//! Step 1 — the relation `R(x, w): hash(w) == h`.
//!
//! * Public input `x = h` (a BLS12-381 `Fr` field element, the hash digest).
//! * Private witness `w` (the secret preimage; never leaves the prover).
//!
//! We use **Poseidon** as the in-circuit hash. Rationale (per brief):
//! Poseidon is SNARK-friendly — a single-element hash is a few hundred R1CS
//! constraints. SHA-256 in-circuit would be tens of thousands of constraints,
//! so we deliberately do NOT use it for v1. The hash lives behind the
//! [`hash`] module so it can be swapped (e.g. for a Merkle/commitment scheme
//! when this generalises to a private payment) without touching the circuit
//! wiring or the prover/verifier.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod hash;

use alloc::vec::Vec;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Canonical (de)serialization of the public input `h` as a field element.
///
/// Shared by the prover (writes `public.json`), the client (encodes the verify
/// message), and any verifier so all sides agree on the byte layout of `h`.
pub mod ser {
    use super::{Fr, Vec};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

    /// Serialize a field element to its canonical compressed bytes.
    pub fn fr_to_bytes(f: &Fr) -> Vec<u8> {
        let mut out = Vec::new();
        f.serialize_compressed(&mut out)
            .expect("Fr serialization is infallible");
        out
    }

    /// Parse a field element from canonical compressed bytes.
    pub fn fr_from_bytes(bytes: &[u8]) -> Option<Fr> {
        Fr::deserialize_compressed(bytes).ok()
    }
}

// Re-export the field/curve types so downstream crates (keys, prover) share the
// exact same definitions — preventing accidental cross-version mismatches.
pub use ark_bls12_381::{Bls12_381, Fr};

/// Human-readable curve identity, surfaced as the `curve` observability metric.
pub const CURVE: &str = "BLS12-381";
/// The scalar field the relation is defined over.
pub const FIELD: &str = "BLS12-381::Fr";

/// The Groth16 relation `Poseidon(w) == h`.
///
/// `h` is allocated as the (sole) public input, `w` as a private witness. When
/// used for **setup** the witness is `None` (only the shape matters); for
/// **proving** it carries the real secret.
#[derive(Clone)]
pub struct PreimageCircuit {
    /// Poseidon parameters (round constants + MDS). Allocated as circuit
    /// constants, so they are baked into the proving/verifying keys.
    pub cfg: hash::PoseidonCfg,
    /// Private witness — the secret preimage. `None` during setup.
    pub w: Option<Fr>,
    /// Public input — the claimed digest `h`.
    pub h: Fr,
}

impl PreimageCircuit {
    /// Build a setup-time instance (no witness). `h` may be any value; setup
    /// only inspects the constraint structure, not the assignment.
    pub fn for_setup(cfg: hash::PoseidonCfg) -> Self {
        Self {
            cfg,
            w: None,
            h: Fr::from(0u64),
        }
    }

    /// Build a proving-time instance from a known secret `w`, deriving the
    /// public input `h = Poseidon(w)` natively.
    pub fn for_witness(cfg: hash::PoseidonCfg, w: Fr) -> Self {
        let h = hash::poseidon_hash(&cfg, &[w]);
        Self {
            cfg,
            w: Some(w),
            h,
        }
    }
}

impl ConstraintSynthesizer<Fr> for PreimageCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<Fr>,
    ) -> Result<(), SynthesisError> {
        use ark_r1cs_std::alloc::AllocVar;
        use ark_r1cs_std::eq::EqGadget;
        use ark_r1cs_std::fields::fp::FpVar;

        // Public input first → its position is fixed at index 0 of the public
        // input vector, so the verifier passes exactly `[h]`.
        let h_var = FpVar::<Fr>::new_input(cs.clone(), || Ok(self.h))?;

        // Private witness.
        let w_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.w.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // hash(w) in-circuit, then assert equality with the public digest.
        let computed = hash::poseidon_hash_gadget(cs, &self.cfg, &[w_var])?;
        computed.enforce_equal(&h_var)?;
        Ok(())
    }
}

/// Static facts about the synthesised relation, used for the Step 1
/// observability signals and as a regression guard in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitStats {
    pub num_constraints: usize,
    /// Public ("instance") variables, INCLUDING the implicit constant `1`.
    pub num_instance_variables: usize,
    pub num_witness_variables: usize,
    /// Public-input arity exposed to the verifier (instance vars minus the
    /// implicit `1`). For this relation that is exactly 1 (just `h`).
    pub public_inputs: usize,
}

/// Synthesise the relation once (with a dummy assignment) and count its R1CS
/// dimensions. Cheap; safe to call from binaries to emit Step 1 signals.
pub fn circuit_stats() -> CircuitStats {
    use ark_relations::r1cs::ConstraintSystem;

    let cfg = hash::default_config();
    // A concrete satisfying assignment so counting matches the proving path.
    let w = Fr::from(7u64);
    let circuit = PreimageCircuit::for_witness(cfg, w);

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .expect("relation must synthesise");
    cs.finalize();

    let num_instance_variables = cs.num_instance_variables();
    CircuitStats {
        num_constraints: cs.num_constraints(),
        num_instance_variables,
        num_witness_variables: cs.num_witness_variables(),
        public_inputs: num_instance_variables.saturating_sub(1),
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    fn is_satisfied(w: Fr, h: Fr) -> bool {
        let cfg = hash::default_config();
        let circuit = PreimageCircuit {
            cfg,
            w: Some(w),
            h,
        };
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }

    #[test]
    fn satisfying_assignment_passes() {
        let cfg = hash::default_config();
        let w = Fr::from(42u64);
        let h = hash::poseidon_hash(&cfg, &[w]);
        assert!(is_satisfied(w, h), "correct preimage must satisfy R");
    }

    #[test]
    fn wrong_witness_fails() {
        let cfg = hash::default_config();
        let w = Fr::from(42u64);
        let h = hash::poseidon_hash(&cfg, &[w]);
        // Claim the same h but feed a different preimage.
        assert!(!is_satisfied(Fr::from(43u64), h));
    }

    #[test]
    fn wrong_public_input_fails() {
        let w = Fr::from(42u64);
        // h that does not correspond to w.
        assert!(!is_satisfied(w, Fr::from(123456u64)));
    }

    /// Regression guard: the constraint count must not silently change. If
    /// Poseidon params change this will trip and force a conscious update
    /// (and a re-run of the trusted setup, since vk would change).
    #[test]
    fn constraint_count_is_stable() {
        let stats = circuit_stats();
        assert_eq!(
            stats.public_inputs, 1,
            "relation must expose exactly one public input (h)"
        );
        // Poseidon width-3 (rate 2, capacity 1), 8 full + 57 partial rounds.
        // The exact count is asserted to catch unintended parameter drift.
        assert_eq!(
            stats.num_constraints, hash::EXPECTED_CONSTRAINTS,
            "constraint count drifted — Poseidon params likely changed; \
             re-run trusted setup and update EXPECTED_CONSTRAINTS"
        );
    }
}
