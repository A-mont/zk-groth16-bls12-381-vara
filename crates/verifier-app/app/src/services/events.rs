use sails_rs::prelude::*;

/// Typed events emitted for EVERY handled verify message (success and rejection).
/// The `trace_id` echoes the off-chain correlation id so a single id stitches
/// prover → client → message → reply → event together.
#[event]
#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub enum VerifyEvent {
    /// A well-formed proof was checked. `ok` is the verdict.
    Verified {
        trace_id: String,
        ok: bool,
        vk_fingerprint: String,
    },
    /// The proof was rejected (invalid, or malformed input). `reason` explains.
    Rejected { trace_id: String, reason: String },
}
