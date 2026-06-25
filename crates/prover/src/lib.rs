//! Step 3 — off-chain prover.
//!
//! Given the secret `w` and the proving key, builds a Groth16 proof `π` for
//! `Poseidon(w) == h` and emits ONLY the public pair `(h, π)`. The witness `w`
//! never appears in any output artifact, log line, or on-chain payload — a
//! property the tests assert directly.

use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};

use zk_circuit::{Fr, PreimageCircuit};

/// The public side of a proof, ready to persist and ship to the chain.
pub struct ProofArtifacts {
    /// Groth16 proof, serialized compressed (~200 bytes) — for OFF-CHAIN verify.
    pub proof_bytes: Vec<u8>,
    /// Proof component A (G1) UNCOMPRESSED — the on-chain wire format.
    pub a_uncompressed: Vec<u8>,
    /// Proof component B (G2) UNCOMPRESSED.
    pub b_uncompressed: Vec<u8>,
    /// Proof component C (G1) UNCOMPRESSED.
    pub c_uncompressed: Vec<u8>,
    /// The public input `h = Poseidon(w)`.
    pub public_h: Fr,
    /// Correlation id minted for this proof; travels with `(h, π)` everywhere.
    pub trace_id: String,
}

/// Contents of `public.json` — everything PUBLIC about a proof. Note the
/// conspicuous absence of `w`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    pub trace_id: String,
    /// Canonical compressed bytes of `h`, hex-encoded.
    pub h_hex: String,
    /// Fingerprint of the vk this proof is meant to be checked against.
    pub vk_fingerprint: String,
    pub curve: String,
    pub hash: String,
}

/// Build a proof for secret `w`. `seed = Some(_)` makes proving deterministic
/// (used by tests); `None` draws fresh randomness (the real ZK path).
pub fn prove(
    pk_bytes: &[u8],
    w: Fr,
    trace_id: String,
    seed: Option<u64>,
) -> anyhow::Result<ProofArtifacts> {
    let pk = ProvingKey::<Bls12_381>::deserialize_uncompressed(pk_bytes)
        .map_err(|e| anyhow::anyhow!("deserialize pk: {e}"))?;

    let cfg = zk_circuit::hash::default_config();
    let circuit = PreimageCircuit::for_witness(cfg, w);
    let public_h = circuit.h;

    let mut rng = match seed {
        Some(s) => StdRng::seed_from_u64(s),
        None => StdRng::from_entropy(),
    };
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng)
        .map_err(|e| anyhow::anyhow!("groth16 prove: {e}"))?;

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| anyhow::anyhow!("serialize proof: {e}"))?;

    // Uncompressed components for the on-chain verifier (which uses
    // `deserialize_uncompressed_unchecked`).
    let a_uncompressed = serialize_uncompressed(&proof.a)?;
    let b_uncompressed = serialize_uncompressed(&proof.b)?;
    let c_uncompressed = serialize_uncompressed(&proof.c)?;

    Ok(ProofArtifacts {
        proof_bytes,
        a_uncompressed,
        b_uncompressed,
        c_uncompressed,
        public_h,
        trace_id,
    })
}

fn serialize_uncompressed<T: CanonicalSerialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    value
        .serialize_uncompressed(&mut out)
        .map_err(|e| anyhow::anyhow!("uncompressed serialization: {e}"))?;
    Ok(out)
}

/// Off-chain verification (sanity check; the authoritative check is on-chain).
/// Returns `Ok(false)` for a well-formed-but-invalid proof and `Err` only on
/// malformed bytes.
pub fn verify(vk_bytes: &[u8], public_h: Fr, proof_bytes: &[u8]) -> anyhow::Result<bool> {
    let vk = zk_keys::deserialize_vk(vk_bytes)?;
    let proof = Proof::<Bls12_381>::deserialize_compressed(proof_bytes)
        .map_err(|e| anyhow::anyhow!("deserialize proof: {e}"))?;
    Groth16::<Bls12_381>::verify(&vk, &[public_h], &proof)
        .map_err(|e| anyhow::anyhow!("groth16 verify: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_circuit::ser::fr_to_bytes;

    fn keys() -> (Vec<u8>, Vec<u8>) {
        let s = zk_keys::generate_keys(1).unwrap();
        (s.pk_bytes, s.vk_bytes)
    }

    #[test]
    fn proof_verifies_offchain() {
        let (pk, vk) = keys();
        let w = Fr::from(42u64);
        let art = prove(&pk, w, "t".into(), Some(2)).unwrap();
        assert!(verify(&vk, art.public_h, &art.proof_bytes).unwrap());
    }

    #[test]
    fn tampered_proof_fails() {
        let (pk, vk) = keys();
        let w = Fr::from(42u64);
        let mut art = prove(&pk, w, "t".into(), Some(2)).unwrap();
        // Flip a byte; verification must not succeed (either invalid or malformed).
        let last = art.proof_bytes.len() - 1;
        art.proof_bytes[last] ^= 0x01;
        let ok = verify(&vk, art.public_h, &art.proof_bytes).unwrap_or(false);
        assert!(!ok, "tampered proof must not verify");
    }

    #[test]
    fn tampered_public_input_fails() {
        let (pk, vk) = keys();
        let w = Fr::from(42u64);
        let art = prove(&pk, w, "t".into(), Some(2)).unwrap();
        let wrong_h = art.public_h + Fr::from(1u64);
        assert!(!verify(&vk, wrong_h, &art.proof_bytes).unwrap());
    }

    #[test]
    fn witness_never_appears_in_outputs() {
        let (pk, _vk) = keys();
        let w = Fr::from(0xDEAD_BEEFu64);
        let art = prove(&pk, w, "trace-xyz".into(), Some(2)).unwrap();
        let w_bytes = fr_to_bytes(&w);
        // The secret's canonical bytes must not be embedded in the proof…
        assert!(
            !contains_subslice(&art.proof_bytes, &w_bytes),
            "secret w leaked into proof bytes"
        );
        // …nor in the public.json payload.
        let public = PublicInputs {
            trace_id: art.trace_id.clone(),
            h_hex: hex::encode(fr_to_bytes(&art.public_h)),
            vk_fingerprint: "fp".into(),
            curve: zk_circuit::CURVE.into(),
            hash: zk_circuit::hash::HASH_NAME.into(),
        };
        let json = serde_json::to_string(&public).unwrap();
        assert!(!json.contains(&hex::encode(&w_bytes)), "secret w leaked into public.json");
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || haystack.len() < needle.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
