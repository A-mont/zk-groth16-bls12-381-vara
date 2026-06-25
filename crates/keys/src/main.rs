//! `zk-keys` — CLI for the Groth16 trusted setup (Step 2).
//!
//! Example:
//!   zk-keys setup --seed 42 --out-dir artifacts
//!
//! Emits a `setup` StepReport (keygen_ms, pk_bytes, vk_bytes, vk_fingerprint,
//! rng_seed) to stdout and the run log.

use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};

use zk_telemetry::{banner, init_tracing, new_trace_id, Step, StepReport};

#[derive(Parser)]
#[command(name = "zk-keys", about = "Groth16 trusted setup for hash(w)==h")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate (pk, vk) and the vk fingerprint.
    Setup {
        /// Deterministic RNG seed (tutorial reproducibility only — NOT secure).
        #[arg(long, default_value_t = 42)]
        seed: u64,
        /// Directory to write pk.bin, vk.bin, vk.fingerprint.
        #[arg(long, default_value = "artifacts")]
        out_dir: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Setup { seed, out_dir } => run_setup(seed, out_dir),
    }
}

fn run_setup(seed: u64, out_dir: PathBuf) -> anyhow::Result<()> {
    banner(2, 5, "SETUP - Groth16 trusted setup (pk, vk, prepared vk)");

    let trace_id = new_trace_id();
    let mut report = StepReport::start(Step::Setup, &trace_id);

    tracing::warn!(
        "TRUSTED SETUP: this run uses a FIXED seed for reproducibility. The \
         setup randomness ('toxic waste') is trust-sensitive; anyone who holds \
         it can forge proofs. This is fine for a tutorial, NOT for production \
         (use a multi-party ceremony)."
    );

    let keygen_start = std::time::Instant::now();
    let artifacts = match zk_keys::generate_keys(seed) {
        Ok(a) => a,
        Err(e) => {
            report.fail().note(format!("{e}"));
            report.finish();
            return Err(e);
        }
    };
    let keygen_ms = keygen_start.elapsed().as_millis() as u64;

    fs::create_dir_all(&out_dir).with_context(|| format!("create {out_dir:?}"))?;
    let pk_path = out_dir.join("pk.bin");
    let vk_path = out_dir.join("vk.bin");
    let fp_path = out_dir.join("vk.fingerprint");
    fs::write(&pk_path, &artifacts.pk_bytes).context("write pk.bin")?;
    fs::write(&vk_path, &artifacts.vk_bytes).context("write vk.bin")?;
    fs::write(&fp_path, format!("{}\n", artifacts.vk_fingerprint)).context("write fingerprint")?;

    // The PREPARED vk (on-chain wire format): e(α,β), -γ, -δ, IC. The actor is
    // deployed with THIS (and its own fingerprint), not the raw vk.bin.
    let prepared = zk_keys::prepare_vk(&artifacts.vk_bytes)?;
    let prepared_path = out_dir.join("vk_prepared.json");
    fs::write(
        &prepared_path,
        serde_json::to_string_pretty(&prepared).context("serialize vk_prepared.json")?,
    )
    .context("write vk_prepared.json")?;

    report
        .metric("keygen_ms", keygen_ms)
        .metric("pk_bytes", artifacts.pk_bytes.len() as u64)
        .metric("vk_bytes", artifacts.vk_bytes.len() as u64)
        .metric("vk_fingerprint", artifacts.vk_fingerprint.clone())
        .metric("prepared_vk_fingerprint", prepared.fingerprint.clone())
        .metric("rng_seed", seed)
        .note("trusted setup is per-circuit and trust-sensitive");
    report.finish();
    tracing::info!(keygen_ms, "keygen complete");

    println!("vk fingerprint (raw):      {}", artifacts.vk_fingerprint);
    println!("vk fingerprint (prepared): {}  <- the actor checks THIS", prepared.fingerprint);
    println!("wrote {pk_path:?}, {vk_path:?}, {fp_path:?}, {prepared_path:?}");
    Ok(())
}
