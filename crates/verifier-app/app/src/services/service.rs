use sails_rs::{cell::RefCell, prelude::*};

use super::errors::VerifyError;
use super::events::VerifyEvent;
use super::groth16;
use super::state::VerifierState;
use super::types::{ProofBytes, VerifyReport};

/// The verifier service. Borrows the program state; holds no secrets.
pub struct Service<'a> {
    state: &'a RefCell<VerifierState>,
}

impl<'a> Service<'a> {
    pub fn new(state: &'a RefCell<VerifierState>) -> Self {
        Self { state }
    }
}

#[sails_rs::service(events = VerifyEvent)]
impl<'a> Service<'a> {
    /// Verify a proof. `h` and `proof` are the public pair `(h, π)` produced
    /// off-chain; `trace_id` is the correlation id minted at proof generation.
    ///
    /// Emits `Verified`/`Rejected` for every call. A well-formed-but-invalid
    /// proof returns `Ok(VerifyReport{ ok: false })`; only undecodable input
    /// yields a typed `Err`.
    #[export(unwrap_result)]
    pub async fn verify(
        &mut self,
        h: Vec<u8>,
        proof: ProofBytes,
        trace_id: String,
    ) -> Result<VerifyReport, VerifyError> {
        // Snapshot what we need and drop the borrow before any `.await`.
        let (vk, vk_fingerprint, builtin) = {
            let s = self.state.borrow();
            (s.vk.clone(), s.vk_fingerprint.clone(), s.builtin_id)
        };

        // This relation has exactly one public input (h).
        let public_input = vec![h];

        match groth16::verify_groth16(builtin, vk, &proof.a, &proof.b, &proof.c, &public_input).await
        {
            Ok(true) => {
                self.emit_event(VerifyEvent::Verified {
                    trace_id: trace_id.clone(),
                    ok: true,
                    vk_fingerprint: vk_fingerprint.clone(),
                })
                .expect("failed to emit event");
                Ok(VerifyReport {
                    trace_id,
                    ok: true,
                    vk_fingerprint,
                })
            }
            Ok(false) => {
                self.emit_event(VerifyEvent::Rejected {
                    trace_id: trace_id.clone(),
                    reason: "proof invalid".into(),
                })
                .expect("failed to emit event");
                Ok(VerifyReport {
                    trace_id,
                    ok: false,
                    vk_fingerprint,
                })
            }
            Err(reason) => {
                self.emit_event(VerifyEvent::Rejected {
                    trace_id: trace_id.clone(),
                    reason: reason.into(),
                })
                .expect("failed to emit event");
                Err(VerifyError::Malformed(reason.into()))
            }
        }
    }

    /// The fingerprint of the verifying key this actor holds. Free query.
    #[export]
    pub fn vk_fingerprint(&self) -> String {
        self.state.borrow().vk_fingerprint.clone()
    }

    /// The BLS12-381 builtin address this actor offloads pairings to. Free query.
    #[export]
    pub fn builtin(&self) -> ActorId {
        self.state.borrow().builtin_id
    }
}
