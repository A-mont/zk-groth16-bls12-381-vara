//! The in-circuit hash, isolated behind one module so it can be swapped.
//!
//! v1 uses Poseidon over BLS12-381 `Fr` (width 3 = rate 2 + capacity 1,
//! `alpha = 5`, 8 full + 57 partial rounds — a standard 128-bit-secure
//! parameterisation). Both the **native** hash (used by setup/prover to derive
//! `h`) and the **gadget** (used inside the R1CS) MUST use identical parameters,
//! so they share [`default_config`].
//!
//! ⚠️ Security note: the round constants here are generated with arkworks'
//! `find_poseidon_ark_and_mds`, a dev/test generator. For production you'd pin
//! an audited parameter set. The constants only need to be internally
//! consistent between this native hash and this gadget — which they are, since
//! both call [`default_config`].

use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::Fr;

/// Poseidon parameters specialised to BLS12-381 `Fr`.
pub type PoseidonCfg = PoseidonConfig<Fr>;

/// Name of the active in-circuit hash (observability metric `hash`).
pub const HASH_NAME: &str = "Poseidon(BLS12-381::Fr, w=3, alpha=5, RF=8, RP=57)";

// Poseidon parameters. Width 3 (rate 2, capacity 1).
const FULL_ROUNDS: u64 = 8;
const PARTIAL_ROUNDS: u64 = 57;
const ALPHA: u64 = 5;
const RATE: usize = 2;
const CAPACITY: usize = 1;
/// Bit length of the BLS12-381 scalar field modulus.
const PRIME_BITS: u64 = 255;

/// Expected R1CS constraint count of `Poseidon(w) == h`. Measured from an
/// actual synthesis run (arkworks 0.5, width-3 Poseidon, RF=8/RP=57); the
/// `constraint_count_is_stable` test enforces it as a regression guard. A
/// single-element Poseidon preimage proof is ~238 constraints — three orders of
/// magnitude cheaper than an in-circuit SHA-256, which is why we chose it.
pub const EXPECTED_CONSTRAINTS: usize = 238;

/// Build the canonical Poseidon configuration shared by the native hash and the
/// in-circuit gadget.
pub fn default_config() -> PoseidonCfg {
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        PRIME_BITS,
        RATE,
        FULL_ROUNDS,
        PARTIAL_ROUNDS,
        /* skip_matrices = */ 0,
    );
    PoseidonConfig::new(
        FULL_ROUNDS as usize,
        PARTIAL_ROUNDS as usize,
        ALPHA,
        mds,
        ark,
        RATE,
        CAPACITY,
    )
}

/// Native Poseidon hash of a slice of field elements → one field element.
/// Used off-chain by setup (dummy) and the prover (to derive the public `h`).
pub fn poseidon_hash(cfg: &PoseidonCfg, input: &[Fr]) -> Fr {
    use ark_crypto_primitives::crh::{poseidon::CRH, CRHScheme};
    CRH::<Fr>::evaluate(cfg, input).expect("poseidon native evaluation is infallible for valid input")
}

/// In-circuit Poseidon hash. Allocates the parameters as constants in `cs` and
/// returns the digest variable to be constrained against the public input.
pub fn poseidon_hash_gadget(
    cs: ConstraintSystemRef<Fr>,
    cfg: &PoseidonCfg,
    input: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    use ark_crypto_primitives::crh::{
        poseidon::constraints::{CRHGadget, CRHParametersVar},
        CRHSchemeGadget,
    };
    use ark_r1cs_std::alloc::AllocVar;

    let params = CRHParametersVar::<Fr>::new_constant(cs, cfg.clone())?;
    <CRHGadget<Fr> as CRHSchemeGadget<_, Fr>>::evaluate(&params, input)
}
