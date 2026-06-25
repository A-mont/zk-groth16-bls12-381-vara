//! `zk-circuit` — CLI for the Step 1 relation `Poseidon(w) == h`.
//!
//! Example:
//!   zk-circuit stats
//!
//! Synthesises the R1CS relation once and emits a `circuit` StepReport
//! (num_constraints, num_instance_variables, num_witness_variables,
//! public_inputs, curve) to stdout and the run log. It runs no setup and no
//! proof — it only inspects the *shape* of the relation, which is the Step 1
//! observability signal the rest of the pipeline (setup/prover) builds on.

use anyhow::Result;
use clap::{Parser, Subcommand};

use zk_circuit::{circuit_stats, CURVE, FIELD};
use zk_telemetry::{banner, init_tracing, new_trace_id, Step, StepReport};

#[derive(Parser)]
#[command(name = "zk-circuit", about = "Inspect the hash(w)==h R1CS relation (Step 1)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Synthesise the relation and report its R1CS dimensions.
    Stats,
}

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Stats => run_stats(),
    }
}

fn run_stats() -> Result<()> {
    banner(1, 5, "CIRCUIT - Poseidon(w) == h as R1CS constraints");

    let trace_id = new_trace_id();
    let mut report = StepReport::start(Step::Circuit, &trace_id);

    let stats = circuit_stats();

    report
        .metric("num_constraints", stats.num_constraints as u64)
        .metric("num_instance_variables", stats.num_instance_variables as u64)
        .metric("num_witness_variables", stats.num_witness_variables as u64)
        .metric("public_inputs", stats.public_inputs as u64)
        .metric("curve", CURVE)
        .metric("field", FIELD)
        .note("counts the shape only — no setup, no proof, no witness");
    report.finish();

    println!("relation:   Poseidon(w) == h  over {CURVE}");
    println!("constraints: {}", stats.num_constraints);
    println!(
        "variables:   {} instance (incl. const 1), {} witness",
        stats.num_instance_variables, stats.num_witness_variables
    );
    println!("public inputs: {}  (just h)", stats.public_inputs);
    Ok(())
}
