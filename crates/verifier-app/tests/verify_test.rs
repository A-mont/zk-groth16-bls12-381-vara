//! gtest integration tests for the on-chain verifier (Step 4).
//!
//! These run inside gtest — an in-memory Gear VM that INCLUDES the BLS12-381
//! builtin actor — so the full pairing path executes without a real node. The
//! test consumes the REAL artifacts produced off-chain by `zk-keys` + `zk-prove`
//! (`artifacts/vk_prepared.json`, `proof.json`, `public.json`). Because those
//! are serialized with arkworks 0.5 and the actor deserializes with arkworks 0.4
//! (via the builtin), a green happy-path here also proves cross-version
//! byte-compatibility.
//!
//! Prerequisite: run `zk-keys setup` and `zk-prove prove` first to populate
//! `artifacts/`. Run with: `cargo test`.

use std::path::PathBuf;

use sails_rs::{
    client::{Actor, GtestEnv},
    gtest::System,
    prelude::*,
};
use zk_verifier::{
    client::{
        verifier::Verifier as _, ProofBytes, VerifyingKeyBytes, ZkVerifier as _,
        ZkVerifierCtors as _, ZkVerifierProgram,
    },
    WASM_BINARY,
};

const ADMIN: u64 = 1;

/// gtest's in-memory BLS12-381 builtin address (gear `sdk/gtest/src/builtins/
/// bls12_381.rs`: `BLS12_381_ID`). DIFFERENT from the runtime `0x6b6e…dc37`,
/// which is why the actor takes the builtin id as a constructor parameter.
const GTEST_BLS_BUILTIN: [u8; 32] = *b"modl/bia/bls12-381/v-\x01\0/\0\0\0\0\0\0\0\0";

fn actor(id: u64) -> ActorId {
    id.into()
}

fn artifacts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../artifacts")
}

fn read_json(name: &str) -> serde_json::Value {
    let path = artifacts_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing artifact {path:?} ({e}); run zk-keys + zk-prove first"));
    serde_json::from_str(&text).expect("artifact is valid JSON")
}

fn hexd(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

/// Load the prepared vk + its fingerprint from `vk_prepared.json`.
fn load_vk() -> (VerifyingKeyBytes, String) {
    let v = read_json("vk_prepared.json");
    let vk = VerifyingKeyBytes {
        alpha_g1_beta_g2: hexd(v["alpha_g1_beta_g2"].as_str().unwrap()),
        gamma_g2_neg_pc: hexd(v["gamma_g2_neg_pc"].as_str().unwrap()),
        delta_g2_neg_pc: hexd(v["delta_g2_neg_pc"].as_str().unwrap()),
        ic: v["ic"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| hexd(x.as_str().unwrap()))
            .collect(),
    };
    (vk, v["fingerprint"].as_str().unwrap().to_string())
}

/// Load `(h, proof)` from `public.json` + `proof.json`.
fn load_proof() -> (Vec<u8>, ProofBytes) {
    let public = read_json("public.json");
    let h = hexd(public["h_hex"].as_str().unwrap());
    let p = read_json("proof.json");
    let proof = ProofBytes {
        a: hexd(p["a"].as_str().unwrap()),
        b: hexd(p["b"].as_str().unwrap()),
        c: hexd(p["c"].as_str().unwrap()),
    };
    (h, proof)
}

/// Deploy a fresh verifier wired to the gtest builtin.
async fn deploy() -> (GtestEnv, Actor<ZkVerifierProgram, GtestEnv>, String) {
    let (vk, fingerprint) = load_vk();

    let system = System::new();
    system.init_logger();
    system.mint_to(ADMIN, 1_000_000_000_000_000);

    let code_id = system.submit_code(WASM_BINARY);
    let env = GtestEnv::new(system, actor(ADMIN));
    let program = env
        .deploy::<ZkVerifierProgram>(code_id, b"zk-verifier".to_vec())
        .new(vk, ActorId::new(GTEST_BLS_BUILTIN), fingerprint.clone())
        .await
        .expect("deploy failed");
    (env, program, fingerprint)
}

#[tokio::test]
async fn valid_proof_verifies_on_chain() {
    let (_env, program, fingerprint) = deploy().await;
    let (h, proof) = load_proof();
    let trace_id = "gtest-trace-valid".to_string();

    let report = program
        .verifier()
        .verify(h, proof, trace_id.clone())
        .await
        .expect("verify call should succeed");

    assert!(report.ok, "a valid proof must verify on-chain");
    assert_eq!(report.trace_id, trace_id, "trace_id must be echoed back");
    assert_eq!(
        report.vk_fingerprint, fingerprint,
        "reply must carry the vk fingerprint the actor checked against"
    );
}

#[tokio::test]
async fn vk_fingerprint_query_matches() {
    let (_env, program, fingerprint) = deploy().await;
    let got = program.verifier().vk_fingerprint().await.expect("query");
    assert_eq!(got, fingerprint);
}

#[tokio::test]
async fn tampered_proof_is_rejected() {
    let (_env, program, _fp) = deploy().await;
    let (h, mut proof) = load_proof();

    // Corrupt one byte of component A. With unchecked deserialization the bytes
    // still decode to *a* point, so the pairing simply won't satisfy → ok=false.
    let last = proof.a.len() - 1;
    proof.a[last] ^= 0x01;

    let result = program
        .verifier()
        .verify(h, proof, "gtest-trace-bad".to_string())
        .await;

    // Either a typed error (malformed) or a verdict of ok=false — never accepted.
    let accepted = result.map(|r| r.ok).unwrap_or(false);
    assert!(!accepted, "a tampered proof must never verify");
}

#[tokio::test]
async fn wrong_public_input_is_rejected() {
    let (_env, program, _fp) = deploy().await;
    let (mut h, proof) = load_proof();

    // Flip a byte of the public input h → proof no longer corresponds to it.
    h[0] ^= 0x01;

    let result = program
        .verifier()
        .verify(h, proof, "gtest-trace-wrong-h".to_string())
        .await;
    let accepted = result.map(|r| r.ok).unwrap_or(false);
    assert!(!accepted, "a proof against the wrong public input must be rejected");
}
