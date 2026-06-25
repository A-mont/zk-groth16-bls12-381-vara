use sails_rs::prelude::*;

use super::groth16::{fingerprint, VerifyingKey};
use super::types::VerifyingKeyBytes;

/// On-chain state. Holds NO secrets — only the (parsed) verifying key, its
/// fingerprint, and the builtin address.
pub struct VerifierState {
    pub vk: VerifyingKey,
    pub vk_fingerprint: String,
    pub builtin_id: ActorId,
}

impl VerifierState {
    pub fn new(
        vk_bytes: VerifyingKeyBytes,
        builtin_id: ActorId,
        expected_fingerprint: String,
    ) -> Self {
        let fp = fingerprint(&vk_bytes);
        assert!(
            fp == expected_fingerprint,
            "vk integrity check failed: fingerprint mismatch"
        );
        let vk = VerifyingKey::from_bytes(&vk_bytes);
        Self {
            vk,
            vk_fingerprint: fp,
            builtin_id,
        }
    }
}
