# Observability catalog

Every off-chain step emits a uniform `StepReport` (see
`observability/telemetry`): `trace_id`, `step`, `status`, `started_at`,
`duration_ms`, `metrics{}`, `notes[]`. Each report is printed via `tracing`
(`LOG_FORMAT=pretty|json`, `RUST_LOG` for levels) **and** appended as one JSONL
line to `runs/run-<ts>.jsonl`.

The **`trace_id`** is the spine: minted at proof generation, it flows
prover → `public.json` → client/UI → the `Verify` message → the actor reply and
its `Verified`/`Rejected` event.

## Signals per step

Run a single step's signals on demand: `cargo run -p zk-circuit -- stats`
(Step 1), `… -p zk-keys -- setup` (Step 2), `… -p zk-prover -- prove` (Step 3).
Each prints a stage banner + its `StepReport`. Set `ZK_RUN_LOG=runs/<name>.jsonl`
to make them all append to one log for a combined `make report` table.

| Step | Where | Signal | Type / unit |
|---|---|---|---|
| Circuit | `zk-circuit stats` (`circuit::circuit_stats`) | `num_constraints` | count (238) |
| | | `num_instance_variables`, `num_witness_variables` | count |
| | | `public_inputs` | count (1) |
| | | `curve` | `BLS12-381` |
| Setup | `zk-keys setup` | `keygen_ms` | ms |
| | | `pk_bytes`, `vk_bytes` | bytes |
| | | `vk_fingerprint` | sha256 hex (raw vk) |
| | | `prepared_vk_fingerprint` | sha256 hex (on-chain wire) |
| | | `rng_seed` | u64 |
| Prover | `zk-prove prove` | `prove_ms` | ms |
| | | `proof_bytes` | bytes (192) |
| | | `public_input_h` | hex |
| | | `vk_fingerprint` | hex |
| | | `witness_leaked` | bool (asserted `false`) |
| | | `trace_id` | uuid |
| Verifier (on-chain) | actor reply + event | `verdict` (`ok`) | bool |
| | | `trace_id` | echoed |
| | | `vk_fingerprint` | hex |
| | | event `Verified{trace_id,ok,vk_fingerprint}` / `Rejected{trace_id,reason}` | typed Sails event |
| Client / UI | frontend / `vara-wallet` | `message_id`, `block`, `submit_to_reply_ms`, `verdict` | from the tx receipt |

## On-chain signals

- The actor emits a typed event for **every** handled message:
  `Verified { trace_id, ok, vk_fingerprint }` on a well-formed proof,
  `Rejected { trace_id, reason }` on an invalid/malformed one.
- The `Verify` reply payload carries `{ trace_id, ok, vk_fingerprint }`; the
  caller adds gas / block / latency from the transaction.
- In gtest, builtin interactions are visible via the in-memory BLS12-381 mock.
  Read them with `--verbose` on `vara-wallet`, or `vara-wallet watch <pid>
  --idl <idl>` against the live program.

## Negative-path observability

Each failure is distinct and logged, never silent:

| Cause | Surface |
|---|---|
| Invalid (well-formed) proof | reply `ok:false` + `Rejected{reason:"proof invalid"}` |
| Malformed proof / h / vk bytes | typed `Err(Malformed(reason))` error reply + `Rejected` |
| Wrong public input `h` | `ok:false` (proof no longer satisfies the relation) |
| vk fingerprint mismatch | constructor **panics** at deploy (fail-fast integrity check) |

## Reading the run log

```bash
# every report of the latest run, pretty
cat runs/run-*.jsonl | tail -n +1 | jq .
# just the metrics, per step
jq '{step, status, duration_ms, metrics}' runs/run-*.jsonl
```
