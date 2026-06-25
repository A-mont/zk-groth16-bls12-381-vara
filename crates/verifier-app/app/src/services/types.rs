use sails_rs::prelude::*;

/// PREPARED verifying key in the on-chain wire format (mirrors arkworks'
/// `PreparedVerifyingKey` and the gear zk-verification contract):
/// * `alpha_g1_beta_g2` — the GT element `e(α, β)`, ArkScale<Gt>-encoded.
/// * `gamma_g2_neg_pc` / `delta_g2_neg_pc` — the NEGATED γ / δ in G2,
///   uncompressed-serialized.
/// * `ic` — the `gamma_abc_g1` points (one per public input + 1), uncompressed.
///
/// All preparation (the pairing `e(α,β)`, the negations) happens OFF-CHAIN in
/// the `zk-keys` tool, so the actor never computes them.
#[derive(Debug, Default, Clone, Encode, Decode, TypeInfo)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct VerifyingKeyBytes {
    pub alpha_g1_beta_g2: Vec<u8>,
    pub gamma_g2_neg_pc: Vec<u8>,
    pub delta_g2_neg_pc: Vec<u8>,
    pub ic: Vec<Vec<u8>>,
}

/// A Groth16 proof, components uncompressed-serialized.
#[derive(Debug, Clone, Encode, Decode, TypeInfo)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct ProofBytes {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub c: Vec<u8>,
}

/// The rich reply payload of `verify`: verdict + echoed `trace_id` + the vk
/// fingerprint checked against. The client adds gas/block/latency itself.
#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct VerifyReport {
    pub trace_id: String,
    pub ok: bool,
    pub vk_fingerprint: String,
}
