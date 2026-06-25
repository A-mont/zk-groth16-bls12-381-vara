use sails_rs::prelude::*;

/// Typed error reply. A method marked `#[export(unwrap_result)]` turns `Err(_)`
/// into an on-chain error reply, so the client never sees a silent failure.
#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub enum VerifyError {
    /// vk/proof/public-input bytes could not be decoded into valid curve points
    /// or field elements. Carries a human-readable reason.
    Malformed(String),
}
