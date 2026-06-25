// The deployed verifier's Sails IDL (generated from the on-chain program).
// Drives sails-js encoding/decoding in the browser.
export const IDL = `
type VerifyingKeyBytes = struct {
  alpha_g1_beta_g2: vec u8,
  gamma_g2_neg_pc: vec u8,
  delta_g2_neg_pc: vec u8,
  ic: vec vec u8,
};

type ProofBytes = struct {
  a: vec u8,
  b: vec u8,
  c: vec u8,
};

type VerifyReport = struct {
  trace_id: str,
  ok: bool,
  vk_fingerprint: str,
};

constructor {
  New : (vk: VerifyingKeyBytes, builtin_id: actor_id, expected_fingerprint: str);
};

service Verifier {
  Verify : (h: vec u8, proof: ProofBytes, trace_id: str) -> VerifyReport;
  query Builtin : () -> actor_id;
  query VkFingerprint : () -> str;

  events {
    Verified: struct { trace_id: str, ok: bool, vk_fingerprint: str };
    Rejected: struct { trace_id: str, reason: str };
  }
};
`;
