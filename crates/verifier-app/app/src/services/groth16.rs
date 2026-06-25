//! Groth16 verification with ALL heavy math offloaded to the BLS12-381 builtin.
//!
//! DESIGN / SECURITY (this is the "offload to the built-in actor" arrow):
//! * The actor never runs trusted setup nor synthesises the circuit. It only
//!   checks a proof against a PREPARED verifying key — proving *knowledge of a
//!   preimage*, nothing more.
//! * Three builtin calls do the work: one G1 multi-scalar-multiplication (to
//!   fold the public inputs), one multi-Miller-loop, one final exponentiation.
//! * Acceptance is the arkworks Groth16 equation in prepared form:
//!       e(A, B) · e(L, -γ) · e(C, -δ) == e(α, β)
//!   where L = ic[0] + Σ publicᵢ·ic[i+1], and `e(α,β)` is precomputed off-chain
//!   and shipped as `alpha_g1_beta_g2`.
//!
//! All arkworks types come from `gbuiltin_bls381`'s re-exports so versions match
//! the builtin exactly. Pattern adapted from gear-foundation/zk-mental-poker.

use core::ops::AddAssign;

use gbuiltin_bls381::{
    ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective as G1, G2Affine},
    ark_ec::{pairing::Pairing, AffineRepr, Group},
    ark_ff::Field,
    ark_scale,
    ark_scale::hazmat::ArkScaleProjective,
    ark_serialize::CanonicalDeserialize,
    Request, Response,
};
use sails_rs::{gstd::msg, prelude::*, ActorId, Encode};
use sha2::{Digest, Sha256};

use super::types::VerifyingKeyBytes;

/// ArkScale usage for builtin calls: neither compresses nor validates.
type ArkScale<T> = ark_scale::ArkScale<T, { ark_scale::HOST_CALL }>;
/// GT element type (Fq12).
type Gt = <Bls12_381 as Pairing>::TargetField;

/// SHA-256 fingerprint (hex) of the prepared vk's component bytes, in a fixed
/// order. The off-chain `zk-keys` tool computes the identical hash so the
/// deployer can pin vk identity.
pub fn fingerprint(vk: &VerifyingKeyBytes) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&vk.alpha_g1_beta_g2);
    hasher.update(&vk.gamma_g2_neg_pc);
    hasher.update(&vk.delta_g2_neg_pc);
    for point in &vk.ic {
        hasher.update(point);
    }
    hex::encode(hasher.finalize())
}

/// Verifying key with deserialized curve points, parsed once at init.
#[derive(Clone)]
pub struct VerifyingKey {
    pub alpha_g1_beta_g2: Gt,
    pub gamma_g2_neg_pc: G2Affine,
    pub delta_g2_neg_pc: G2Affine,
    pub ic: Vec<G1Affine>,
}

impl VerifyingKey {
    /// Parse the prepared vk bytes. PANICS on malformed bytes — this runs at
    /// deploy time and a bad vk is the deployer's error (fail fast).
    pub fn from_bytes(vk: &VerifyingKeyBytes) -> Self {
        let alpha_g1_beta_g2 = ArkScale::<Gt>::decode(&mut &*vk.alpha_g1_beta_g2)
            .expect("malformed alpha_g1_beta_g2")
            .0;
        let gamma_g2_neg_pc = G2Affine::deserialize_uncompressed_unchecked(&*vk.gamma_g2_neg_pc)
            .expect("malformed gamma_g2_neg_pc");
        let delta_g2_neg_pc = G2Affine::deserialize_uncompressed_unchecked(&*vk.delta_g2_neg_pc)
            .expect("malformed delta_g2_neg_pc");
        let ic = vk
            .ic
            .iter()
            .map(|b| {
                G1Affine::deserialize_uncompressed_unchecked(&**b).expect("malformed ic point")
            })
            .collect();
        Self {
            alpha_g1_beta_g2,
            gamma_g2_neg_pc,
            delta_g2_neg_pc,
            ic,
        }
    }
}

/// Verify a Groth16 proof. Returns `Ok(true/false)` for a well-formed proof
/// (valid/invalid), or `Err(reason)` if any input failed to decode.
///
/// `proof` is `(a, b, c)` uncompressed; `public_input` is each public field
/// element uncompressed. Pairings/MSM go to `builtin`.
pub async fn verify_groth16(
    builtin: ActorId,
    vk: VerifyingKey,
    proof_a: &[u8],
    proof_b: &[u8],
    proof_c: &[u8],
    public_input: &[Vec<u8>],
) -> Result<bool, &'static str> {
    let a = G1Affine::deserialize_uncompressed_unchecked(proof_a).map_err(|_| "malformed proof.a")?;
    let b = G2Affine::deserialize_uncompressed_unchecked(proof_b).map_err(|_| "malformed proof.b")?;
    let c = G1Affine::deserialize_uncompressed_unchecked(proof_c).map_err(|_| "malformed proof.c")?;

    let public_inputs: Result<Vec<Fr>, _> = public_input
        .iter()
        .map(|bytes| Fr::deserialize_uncompressed_unchecked(&**bytes).map_err(|_| "malformed public input"))
        .collect();
    let public_inputs = public_inputs?;

    if public_inputs.len() + 1 != vk.ic.len() {
        return Err("public input arity mismatch");
    }

    // L = ic[0] + Σ publicᵢ·ic[i+1]  (the Σ part offloaded as one G1 MSM).
    let l = prepare_inputs(builtin, &vk.ic, &public_inputs).await?;

    // e(A,B)·e(L,-γ)·e(C,-δ) == e(α,β)
    let a_points: ArkScale<Vec<G1Affine>> = vec![a, l, c].into();
    let b_points: ArkScale<Vec<G2Affine>> =
        vec![b, vk.gamma_g2_neg_pc, vk.delta_g2_neg_pc].into();

    let miller = multi_miller_loop(builtin, a_points.encode(), b_points.encode()).await?;
    let exp = final_exponentiation(builtin, miller).await?;

    Ok(exp == vk.alpha_g1_beta_g2)
}

/// L = ic[0] + MSM(ic[1..], public_inputs), MSM offloaded to the builtin.
async fn prepare_inputs(
    builtin: ActorId,
    ic: &[G1Affine],
    public_inputs: &[Fr],
) -> Result<G1Affine, &'static str> {
    let mut g_ic = ic[0].into_group();

    let bases: ArkScale<Vec<G1Affine>> = ic[1..].to_vec().into();
    let scalars: ArkScale<Vec<<G1 as Group>::ScalarField>> = public_inputs.to_vec().into();

    let msm_bytes = match send(builtin, Request::MultiScalarMultiplicationG1 {
        bases: bases.encode(),
        scalars: scalars.encode(),
    })
    .await?
    {
        Response::MultiScalarMultiplicationG1(v) => v,
        _ => return Err("unexpected response (expected MSM G1)"),
    };

    let msm = ArkScaleProjective::<G1>::decode(&mut msm_bytes.as_slice())
        .map_err(|_| "decode MSM result")?
        .0;
    g_ic.add_assign(msm);
    Ok(g_ic.into())
}

async fn multi_miller_loop(
    builtin: ActorId,
    a: Vec<u8>,
    b: Vec<u8>,
) -> Result<Vec<u8>, &'static str> {
    match send(builtin, Request::MultiMillerLoop { a, b }).await? {
        Response::MultiMillerLoop(v) => Ok(v),
        _ => Err("unexpected response (expected MultiMillerLoop)"),
    }
}

async fn final_exponentiation(builtin: ActorId, f: Vec<u8>) -> Result<Gt, &'static str> {
    match send(builtin, Request::FinalExponentiation { f }).await? {
        Response::FinalExponentiation(v) => Ok(ArkScale::<Gt>::decode(&mut v.as_slice())
            .map_err(|_| "decode GT element")?
            .0),
        _ => Err("unexpected response (expected FinalExponentiation)"),
    }
}

/// Send one request to the builtin and decode its `Response`.
async fn send(builtin: ActorId, request: Request) -> Result<Response, &'static str> {
    let reply = msg::send_bytes_for_reply(builtin, request.encode(), 0, 0)
        .map_err(|_| "failed to send builtin request")?
        .await
        .map_err(|_| "builtin returned an error reply")?;
    Response::decode(&mut reply.as_slice()).map_err(|_| "failed to decode builtin response")
}

// Keep `Field` in scope (used for the Gt identity in tests / future batch pow).
const _: fn() = || {
    let _ = <Gt as Field>::ONE;
};
