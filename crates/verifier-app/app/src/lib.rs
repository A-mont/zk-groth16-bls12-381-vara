// On-chain verifier program (compiled to Wasm, no_std).
#![no_std]

use sails_rs::{cell::RefCell, prelude::*};

pub mod services;

use services::service::Service;
use services::state::VerifierState;
use services::types::VerifyingKeyBytes;

/// Top-level program. Holds the verifying key + the BLS12-381 builtin address,
/// and exposes the `verifier` service.
pub struct Program {
    state: RefCell<VerifierState>,
}

#[program]
impl Program {
    /// Deploy the verifier.
    ///
    /// * `vk` — the PREPARED verifying key (see `VerifyingKeyBytes`).
    /// * `builtin_id` — address of the BLS12-381 builtin actor. On Vara mainnet/
    ///   testnet this is `0x6b6e29…dc37`; in gtest it is the in-memory builtin
    ///   address. Making it a parameter keeps the program testable AND
    ///   deployable without code changes.
    /// * `expected_fingerprint` — SHA-256 hex the deployer asserts `vk` hashes
    ///   to. The constructor PANICS on mismatch (fail-fast vk integrity check).
    pub fn new(
        vk: VerifyingKeyBytes,
        builtin_id: ActorId,
        expected_fingerprint: String,
    ) -> Self {
        let state = VerifierState::new(vk, builtin_id, expected_fingerprint);
        Self {
            state: RefCell::new(state),
        }
    }

    pub fn verifier(&self) -> Service<'_> {
        Service::new(&self.state)
    }
}
