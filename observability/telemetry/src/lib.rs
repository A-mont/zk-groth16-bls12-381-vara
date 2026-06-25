//! Shared observability layer for the ZK-on-Vara example.
//!
//! This crate is the *spine* of the project's observability contract
//! (see `OBSERVABILITY.md`). Every off-chain step (circuit, setup, prover,
//! client) uses it to:
//!   * initialise `tracing` with an env-selectable format,
//!   * mint and carry a `trace_id` that correlates off-chain ↔ on-chain,
//!   * emit a uniform [`StepReport`] to stdout AND append it as one JSONL line
//!     to `runs/<timestamp>.jsonl`.
//!
//! The on-chain Sails program cannot depend on this crate (it is `no_std` and
//! has no filesystem); it emits the *same conceptual signals* via typed events
//! and `gstd::debug!`. The `trace_id` is what stitches the two worlds together.

use std::collections::BTreeMap;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
pub use serde_json::Value as MetricValue;

/// The five components of the system, used as the `step` discriminant on every
/// [`StepReport`]. Mirrors the architecture diagram in the brief.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// Step 1 — the R1CS relation `hash(w) == h`.
    Circuit,
    /// Step 2 — Groth16 trusted setup producing `(pk, vk)`.
    Setup,
    /// Step 3 — off-chain proof generation.
    Prover,
    /// Step 4 — on-chain Sails verifier actor (reports surfaced by the client).
    Verifier,
    /// Step 5 — the gclient e2e driver.
    Client,
}

impl Step {
    pub fn as_str(&self) -> &'static str {
        match self {
            Step::Circuit => "circuit",
            Step::Setup => "setup",
            Step::Prover => "prover",
            Step::Verifier => "verifier",
            Step::Client => "client",
        }
    }
}

/// Pass/fail outcome of a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Fail,
}

/// One structured, machine-readable record per meaningful operation.
///
/// This is the single shape every step conforms to (the brief's "one
/// `StepReport` type" requirement). Build it with [`StepReport::start`], attach
/// metrics with [`StepReport::metric`], then [`StepReport::finish`] it — which
/// stamps `duration_ms`, logs it, and appends it to the run log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepReport {
    pub trace_id: String,
    pub step: Step,
    pub status: Status,
    /// Epoch milliseconds when the step started.
    pub started_at: u64,
    pub duration_ms: u64,
    /// Free-form numeric/string metrics (the per-step minimums live in
    /// `OBSERVABILITY.md`). Ordered for stable JSONL output.
    pub metrics: BTreeMap<String, MetricValue>,
    pub notes: Vec<String>,
    #[serde(skip)]
    start_instant: Option<std::time::Instant>,
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl StepReport {
    /// Begin a report for `step` correlated by `trace_id`. Status defaults to
    /// `Ok`; call [`StepReport::fail`] to flip it on the error path.
    pub fn start(step: Step, trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            step,
            status: Status::Ok,
            started_at: epoch_millis(),
            duration_ms: 0,
            metrics: BTreeMap::new(),
            notes: Vec::new(),
            start_instant: Some(std::time::Instant::now()),
        }
    }

    /// Attach a metric. Accepts anything serde can turn into a JSON value, so
    /// numbers and strings both work (`report.metric("prove_ms", 12)` /
    /// `report.metric("curve", "BLS12-381")`).
    pub fn metric(&mut self, key: impl Into<String>, value: impl Into<MetricValue>) -> &mut Self {
        self.metrics.insert(key.into(), value.into());
        self
    }

    /// Attach a free-text note (e.g. a security caveat).
    pub fn note(&mut self, note: impl Into<String>) -> &mut Self {
        self.notes.push(note.into());
        self
    }

    /// Mark the step as failed.
    pub fn fail(&mut self) -> &mut Self {
        self.status = Status::Fail;
        self
    }

    /// Stamp `duration_ms`, emit the report to the tracing log, and append it
    /// as one line to the active run log. Returns the finished value so callers
    /// can keep inspecting it.
    pub fn finish(mut self) -> Self {
        if let Some(start) = self.start_instant.take() {
            self.duration_ms = start.elapsed().as_millis() as u64;
        }
        // Structured tracing event (honours LOG_FORMAT=json|pretty).
        match self.status {
            Status::Ok => tracing::info!(
                trace_id = %self.trace_id,
                step = self.step.as_str(),
                status = "ok",
                duration_ms = self.duration_ms,
                metrics = %serde_json::to_string(&self.metrics).unwrap_or_default(),
                "step_report",
            ),
            Status::Fail => tracing::error!(
                trace_id = %self.trace_id,
                step = self.step.as_str(),
                status = "fail",
                duration_ms = self.duration_ms,
                metrics = %serde_json::to_string(&self.metrics).unwrap_or_default(),
                notes = %self.notes.join("; "),
                "step_report",
            ),
        }
        if let Err(e) = append_to_run_log(&self) {
            tracing::warn!("could not append StepReport to run log: {e}");
        }
        self
    }
}

/// Mint a fresh correlation id (UUID v4). Called once at proof generation; the
/// returned string then travels prover → public.json → client → verify message
/// → actor reply/events.
pub fn new_trace_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Print a human-facing stage banner to stdout.
///
/// Purely for human viewers (tutorials / screen recordings) so each script
/// announces *which* pipeline step it is before the structured [`StepReport`]
/// output scrolls by. NOT part of the machine-readable observability contract —
/// the run log carries the canonical signals. `n`/`total` are the step's
/// position among the five components (see [`Step`]).
pub fn banner(n: usize, total: usize, title: &str) {
    let bar = "=".repeat(70);
    println!("\n{bar}");
    println!("  STEP {n}/{total} - {title}");
    println!("{bar}");
}

/// Initialise `tracing` for an off-chain binary.
///
/// * `RUST_LOG` controls levels (defaults to `info`).
/// * `LOG_FORMAT=pretty` (default) or `LOG_FORMAT=json` selects the formatter.
///
/// Safe to call multiple times; only the first call installs a subscriber.
pub fn init_tracing() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false);

    let registry = tracing_subscriber::registry().with(filter);
    let installed = if json {
        registry
            .with(fmt::layer().json().with_current_span(true))
            .try_init()
    } else {
        registry.with(fmt::layer().pretty()).try_init()
    };
    let _ = installed; // ignore "already initialised" on repeated calls
}

// --- Run log (`runs/<timestamp>.jsonl`) -------------------------------------

/// The run-log file path is fixed per-process so every report from one run
/// lands in the same JSONL file. Overridable with `ZK_RUN_LOG`; otherwise a new
/// file `runs/run-<epoch_ms>.jsonl` is chosen on first use.
fn run_log_path() -> PathBuf {
    use std::sync::OnceLock;
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        if let Ok(p) = std::env::var("ZK_RUN_LOG") {
            return PathBuf::from(p);
        }
        let dir = std::env::var("ZK_RUNS_DIR").unwrap_or_else(|_| "runs".to_string());
        PathBuf::from(dir).join(format!("run-{}.jsonl", epoch_millis()))
    })
    .clone()
}

/// Append one [`StepReport`] as a single JSON line to the active run log.
pub fn append_to_run_log(report: &StepReport) -> std::io::Result<()> {
    let path = run_log_path();
    append_report_to(&path, report)
}

/// Append a report to an explicit path (used by tests).
pub fn append_report_to(path: &Path, report: &StepReport) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut line = serde_json::to_string(report).map_err(std::io::Error::other)?;
    line.push('\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(line.as_bytes())
}

/// Read every [`StepReport`] from a JSONL run log (used by the `report` tool).
pub fn read_run_log(path: &Path) -> std::io::Result<Vec<StepReport>> {
    let content = std::fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<StepReport>(line) {
            Ok(r) => out.push(r),
            Err(e) => tracing::warn!("skipping malformed run-log line: {e}"),
        }
    }
    Ok(out)
}

/// Return the most recent `runs/*.jsonl` file (by filename, which embeds the
/// epoch ms), if any.
pub fn latest_run_log(runs_dir: &Path) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(runs_dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "jsonl").unwrap_or(false))
        .collect();
    candidates.sort();
    candidates.pop()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_id_is_unique_and_uuid_shaped() {
        let a = new_trace_id();
        let b = new_trace_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36, "uuid v4 canonical form is 36 chars");
        assert_eq!(a.matches('-').count(), 4);
    }

    #[test]
    fn report_roundtrips_through_jsonl() {
        let dir = std::env::temp_dir().join(format!("zk-telemetry-test-{}", epoch_millis()));
        let path = dir.join("run.jsonl");

        let tid = new_trace_id();
        let mut r = StepReport::start(Step::Prover, &tid);
        r.metric("prove_ms", 12).metric("curve", "BLS12-381").note("hi");
        let finished = r.finish_to(&path);

        let back = read_run_log(&path).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].trace_id, tid);
        assert_eq!(back[0].step, Step::Prover);
        assert_eq!(back[0].metrics["prove_ms"], MetricValue::from(12));
        assert_eq!(back[0].metrics["curve"], MetricValue::from("BLS12-381"));
        assert!(finished.duration_ms < 60_000);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn latest_run_log_picks_highest_timestamp() {
        let dir = std::env::temp_dir().join(format!("zk-telemetry-latest-{}", epoch_millis()));
        create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("run-100.jsonl"), b"").unwrap();
        std::fs::write(dir.join("run-200.jsonl"), b"").unwrap();
        let latest = latest_run_log(&dir).unwrap();
        assert!(latest.ends_with("run-200.jsonl"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

impl StepReport {
    /// Test/utility variant of [`StepReport::finish`] that appends to an
    /// explicit path instead of the process-wide run log.
    pub fn finish_to(mut self, path: &Path) -> Self {
        if let Some(start) = self.start_instant.take() {
            self.duration_ms = start.elapsed().as_millis() as u64;
        }
        if let Err(e) = append_report_to(path, &self) {
            tracing::warn!("could not append StepReport to {path:?}: {e}");
        }
        self
    }
}
