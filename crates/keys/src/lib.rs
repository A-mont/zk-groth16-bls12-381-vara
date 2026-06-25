//! Step 2 — Groth16 trusted setup.
//!
//! Runs the Groth16 `circuit_specific_setup` once for the `Poseidon(w) == h`
//! relation and produces:
//!   * `pk.bin` — the proving key (stays off-chain, used by the prover),
//!   * `vk.bin` — the verifying key (embedded on-chain in the Sails actor),
//!   * `vk.fingerprint` — SHA-256 of the serialized vk; the *identity* the
//!     on-chain verifier must hold and check against.
//!
//! ⚠️ SECURITY: Groth16 setup is **per-circuit** and **trust-sensitive**. The
//! setup randomness ("toxic waste") must be discarded; whoever holds it can
//! forge proofs. This example uses a *fixed seed* purely for reproducibility in
//! a tutorial — that is explicitly NOT secure for production. A real deployment
//! needs a multi-party ceremony. We warn loudly at the CLI.

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};

use zk_circuit::PreimageCircuit;

/// Output of a setup run, ready to persist + report on.
pub struct SetupArtifacts {
    /// Proving key, serialized **uncompressed** (larger but faster to load).
    pub pk_bytes: Vec<u8>,
    /// Verifying key, serialized **compressed** (small; embedded on-chain).
    pub vk_bytes: Vec<u8>,
    /// SHA-256 of `vk_bytes`, hex-encoded.
    pub vk_fingerprint: String,
    /// The RNG seed used (recorded for reproducibility / observability).
    pub rng_seed: u64,
}

/// SHA-256 fingerprint of arbitrary bytes, hex-encoded. Used to pin the vk
/// identity across off-chain setup and the on-chain verifier.
pub fn fingerprint(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Run Groth16 keygen for the preimage relation with a deterministic seed.
pub fn generate_keys(seed: u64) -> anyhow::Result<SetupArtifacts> {
    let cfg = zk_circuit::hash::default_config();
    // Setup only inspects circuit *structure*; witness is absent.
    let circuit = PreimageCircuit::for_setup(cfg);

    let mut rng = StdRng::seed_from_u64(seed);
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("groth16 setup failed: {e}"))?;

    let mut pk_bytes = Vec::new();
    pk.serialize_uncompressed(&mut pk_bytes)
        .map_err(|e| anyhow::anyhow!("serialize pk: {e}"))?;

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| anyhow::anyhow!("serialize vk: {e}"))?;

    let vk_fingerprint = fingerprint(&vk_bytes);

    Ok(SetupArtifacts {
        pk_bytes,
        vk_bytes,
        vk_fingerprint,
        rng_seed: seed,
    })
}

/// Deserialize a compressed verifying key (used by tests and the prover/client
/// when they need the typed vk).
pub fn deserialize_vk(
    vk_bytes: &[u8],
) -> anyhow::Result<ark_groth16::VerifyingKey<Bls12_381>> {
    ark_groth16::VerifyingKey::<Bls12_381>::deserialize_compressed(vk_bytes)
        .map_err(|e| anyhow::anyhow!("deserialize vk: {e}"))
}

/// The PREPARED verifying key in the EXACT on-chain wire format the Sails actor
/// expects (`VerifyingKeyBytes`). Hex-encoded for a portable JSON artifact.
///
/// * `alpha_g1_beta_g2` — `ArkScale<Gt>` (Compact(len) ++ uncompressed `e(α,β)`).
/// * `gamma_g2_neg_pc` / `delta_g2_neg_pc` — raw uncompressed `-γ` / `-δ` (G2).
/// * `ic` — raw uncompressed `gamma_abc_g1` points (G1).
/// * `fingerprint` — SHA-256 over the concatenation, matching the actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedVk {
    pub alpha_g1_beta_g2: String,
    pub gamma_g2_neg_pc: String,
    pub delta_g2_neg_pc: String,
    pub ic: Vec<String>,
    pub fingerprint: String,
}

/// `ArkScale<T, HOST_CALL>::encode` writes the RAW uncompressed canonical bytes
/// with NO SCALE length prefix (its `encode_to` calls `serialize_with_mode`
/// straight into the output). So for the on-chain wire format every field —
/// including `alpha_g1_beta_g2`, which the actor decodes via `ArkScale::<Gt>` —
/// is just the uncompressed bytes. The Vec<u8> length prefix is added by the
/// surrounding struct's SCALE encoding, not by us.
fn uncompressed<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value
        .serialize_uncompressed(&mut out)
        .expect("uncompressed serialization is infallible");
    out
}

/// SHA-256 over the prepared vk fields in the fixed order the actor hashes them.
fn prepared_fingerprint(
    alpha_g1_beta_g2: &[u8],
    gamma_g2_neg_pc: &[u8],
    delta_g2_neg_pc: &[u8],
    ic: &[Vec<u8>],
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(alpha_g1_beta_g2);
    hasher.update(gamma_g2_neg_pc);
    hasher.update(delta_g2_neg_pc);
    for point in ic {
        hasher.update(point);
    }
    hex::encode(hasher.finalize())
}

/// Produce the prepared verifying key (the on-chain wire format) from a
/// compressed Groth16 vk. Computes `e(α,β)` and the `-γ`/`-δ` negations here so
/// the actor never has to.
pub fn prepare_vk(vk_bytes: &[u8]) -> anyhow::Result<PreparedVk> {
    let vk = deserialize_vk(vk_bytes)?;

    // e(α,β) as the raw uncompressed GT element (what ArkScale<Gt> decodes).
    let alpha_g1_beta_g2 = uncompressed(&Bls12_381::pairing(vk.alpha_g1, vk.beta_g2).0);
    let gamma_g2_neg_pc = uncompressed(&(-vk.gamma_g2));
    let delta_g2_neg_pc = uncompressed(&(-vk.delta_g2));
    let ic: Vec<Vec<u8>> = vk.gamma_abc_g1.iter().map(uncompressed).collect();

    let fingerprint =
        prepared_fingerprint(&alpha_g1_beta_g2, &gamma_g2_neg_pc, &delta_g2_neg_pc, &ic);

    Ok(PreparedVk {
        alpha_g1_beta_g2: hex::encode(alpha_g1_beta_g2),
        gamma_g2_neg_pc: hex::encode(gamma_g2_neg_pc),
        delta_g2_neg_pc: hex::encode(delta_g2_neg_pc),
        ic: ic.iter().map(hex::encode).collect(),
        fingerprint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_is_deterministic_for_fixed_seed() {
        let a = generate_keys(42).unwrap();
        let b = generate_keys(42).unwrap();
        assert_eq!(a.vk_bytes, b.vk_bytes, "vk must be reproducible from seed");
        assert_eq!(a.pk_bytes, b.pk_bytes, "pk must be reproducible from seed");
        assert_eq!(a.vk_fingerprint, b.vk_fingerprint);
    }

    #[test]
    fn different_seeds_give_different_keys() {
        let a = generate_keys(1).unwrap();
        let b = generate_keys(2).unwrap();
        assert_ne!(a.vk_fingerprint, b.vk_fingerprint);
    }

    #[test]
    fn vk_round_trips_through_serialization() {
        let s = generate_keys(7).unwrap();
        let vk = deserialize_vk(&s.vk_bytes).unwrap();
        let mut reser = Vec::new();
        vk.serialize_compressed(&mut reser).unwrap();
        assert_eq!(reser, s.vk_bytes, "vk must round-trip byte-for-byte");
        assert_eq!(fingerprint(&reser), s.vk_fingerprint);
    }
}
