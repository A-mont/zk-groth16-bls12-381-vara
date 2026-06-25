//! `zk-prove` — off-chain prover CLI (Step 3).
//!
//! Example:
//!   zk-prove prove --secret 42 --pk artifacts/pk.bin --vk artifacts/vk.bin
//!
//! Writes `proof.bin` + `public.json` and prints the `trace_id` that MUST
//! travel with the proof to the chain. The secret `w` is never written or
//! logged.

use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};

use zk_circuit::ser::fr_to_bytes;
use zk_circuit::Fr;
use zk_prover::PublicInputs;
use zk_telemetry::{banner, init_tracing, new_trace_id, Step, StepReport};

#[derive(Parser)]
#[command(name = "zk-prove", about = "Off-chain Groth16 prover for hash(w)==h")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Prove knowledge of a secret preimage `w`.
    Prove {
        /// The secret preimage as an unsigned integer (never logged/persisted).
        #[arg(long)]
        secret: u64,
        /// Proving key file.
        #[arg(long, default_value = "artifacts/pk.bin")]
        pk: PathBuf,
        /// Verifying key file (read only to record its fingerprint).
        #[arg(long, default_value = "artifacts/vk.bin")]
        vk: PathBuf,
        /// Output directory for proof.bin and public.json.
        #[arg(long, default_value = "artifacts")]
        out_dir: PathBuf,
        /// Optional deterministic proving seed (omit for real ZK randomness).
        #[arg(long)]
        seed: Option<u64>,
    },
}

fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Prove {
            secret,
            pk,
            vk,
            out_dir,
            seed,
        } => run_prove(secret, pk, vk, out_dir, seed),
    }
}

fn run_prove(
    secret: u64,
    pk: PathBuf,
    vk: PathBuf,
    out_dir: PathBuf,
    seed: Option<u64>,
) -> anyhow::Result<()> {
    banner(3, 5, "PROVER - generate (h, proof) off-chain; secret w stays local");

    let trace_id = new_trace_id();
    let mut report = StepReport::start(Step::Prover, &trace_id);

    let pk_bytes = fs::read(&pk).with_context(|| format!("read {pk:?}"))?;
    let vk_bytes = fs::read(&vk).with_context(|| format!("read {vk:?}"))?;
    let vk_fingerprint = zk_keys::fingerprint(&vk_bytes);

    let w = Fr::from(secret);
    let prove_start = std::time::Instant::now();
    let art = match zk_prover::prove(&pk_bytes, w, trace_id.clone(), seed) {
        Ok(a) => a,
        Err(e) => {
            report.fail().note(format!("{e}"));
            report.finish();
            return Err(e);
        }
    };
    let prove_ms = prove_start.elapsed().as_millis() as u64;

    let h_hex = hex::encode(fr_to_bytes(&art.public_h));
    let public = PublicInputs {
        trace_id: trace_id.clone(),
        h_hex: h_hex.clone(),
        vk_fingerprint: vk_fingerprint.clone(),
        curve: zk_circuit::CURVE.into(),
        hash: zk_circuit::hash::HASH_NAME.into(),
    };

    fs::create_dir_all(&out_dir).with_context(|| format!("create {out_dir:?}"))?;
    let proof_path = out_dir.join("proof.bin");
    let public_path = out_dir.join("public.json");
    let proof_json_path = out_dir.join("proof.json");
    let h_path = out_dir.join("h.bin");
    fs::write(&proof_path, &art.proof_bytes).context("write proof.bin")?;
    // Raw canonical bytes of the public input h, for consumers (gtest, client)
    // that want h without parsing JSON/hex. For a field element, uncompressed ==
    // compressed (both 32 bytes), which is exactly what the actor expects.
    fs::write(&h_path, fr_to_bytes(&art.public_h)).context("write h.bin")?;
    // The on-chain wire-format proof: uncompressed (a, b, c), hex-encoded.
    let proof_json = serde_json::json!({
        "a": hex::encode(&art.a_uncompressed),
        "b": hex::encode(&art.b_uncompressed),
        "c": hex::encode(&art.c_uncompressed),
    });
    fs::write(
        &proof_json_path,
        serde_json::to_string_pretty(&proof_json).context("serialize proof.json")?,
    )
    .context("write proof.json")?;
    fs::write(
        &public_path,
        serde_json::to_string_pretty(&public).context("serialize public.json")?,
    )
    .context("write public.json")?;

    // Defensive observability: assert the secret never leaked into outputs.
    let w_bytes = fr_to_bytes(&w);
    let leaked = contains(&art.proof_bytes, &w_bytes)
        || fs::read(&public_path)?
            .windows(w_bytes.len().max(1))
            .any(|win| win == w_bytes.as_slice());
    if leaked {
        report.fail().note("SECURITY: witness bytes detected in output");
        report.finish();
        anyhow::bail!("aborting: witness leaked into an output artifact");
    }

    report
        .metric("prove_ms", prove_ms)
        .metric("proof_bytes", art.proof_bytes.len() as u64)
        .metric("public_input_h", h_hex.clone())
        .metric("vk_fingerprint", vk_fingerprint)
        .metric("witness_leaked", false)
        .note("only (h, proof) emitted; secret w stays local");
    report.finish();

    println!("trace_id: {trace_id}");
    println!("public h: 0x{h_hex}");
    println!("wrote {proof_path:?}, {proof_json_path:?}, {public_path:?}");
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}
