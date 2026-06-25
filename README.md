# Prove You Know a Secret: ZK on Vara

A complete, end-to-end **Groth16 zk-SNARK over BLS12-381**, verified **on-chain on
Vara Network**. The system proves knowledge of a secret preimage without ever
revealing it, and settles that proof inside a Wasm `sails-rs` actor.

**The relation.** For a fixed public input `x = h`, the prover demonstrates
knowledge of a private witness `w` satisfying `R(x, w) : Poseidon(w) == h` —
*"I know a `w` that hashes to this `h`"* — disclosing nothing about `w` beyond the
truth of that statement. Poseidon is the hash of choice because it is
arithmetisation-friendly: the full preimage relation compiles to ~**238** R1CS
constraints over the BLS12-381 scalar field `Fr` (a SHA-256 preimage would be tens
of thousands).

**Off-chain.** An [arkworks](https://arkworks.rs) 0.5 prover runs the Groth16
trusted setup (producing the proving/verifying keys) and emits a constant-size
proof `π = (A, B, C)` — ~**192** bytes regardless of circuit size. The witness `w`
is consumed entirely inside the prover process and is absent from every emitted
artifact, log, and payload.

**On-chain.** The verifier is a `no_std` `sails-rs` actor compiled to
`wasm32v1-none`. It carries an embedded **prepared verifying key** — the precomputed
`e(α, β)`, the negated `-γ` and `-δ` in G2, and the `IC` bases — and checks the
Groth16 pairing identity

```
e(A, B) · e(L, −γ) · e(C, −δ) == e(α, β),    L = ic₀ + h·ic₁
```

It runs **no trusted setup, no circuit re-synthesis, and never sees `w`**; it only
evaluates the equation above against the public `h`. The three expensive
elliptic-curve operations — the multi-scalar multiplication that folds the public
inputs into `L`, the multi-Miller loop, and the final exponentiation — are **not
implemented in Wasm**. They are **offloaded to the Vara runtime's BLS12-381 builtin
actor** through `gbuiltin-bls381`, so verification reuses the node's native, audited
pairing code instead of shipping a curve implementation in the contract. The on-chain
arkworks line is 0.4 (the builtin's); the wire format uses raw
`serialize_uncompressed` encodings, which are byte-identical across the 0.4/0.5
boundary — proven on testnet.

> **Live on Vara testnet** — program
> `0x8d84679b79b6eae0f76f18cd8e1045b7c3482725c47f27b73ecd8f5f32d502eb`.
> A `Verify` call returned `{ ok: true }` at block 28449815.

## Table of contents

- [Layout](#layout)
- [Pinned versions](#pinned-versions)
- [The five components](#the-five-components)
- [Quick start — see it working (no Rust)](#quick-start--see-it-working-no-rust)
- [Walkthrough — build it end to end](#walkthrough--build-it-end-to-end)
  - [Step 1 — Environment & goal](#step-1--environment--goal)
  - [Step 2 — The circuit: `Poseidon(w) == h`](#step-2--the-circuit-poseidonw--h)
  - [Step 3 — Trusted setup: pk, vk and the prepared vk](#step-3--trusted-setup-pk-vk-and-the-prepared-vk)
  - [Step 4 — Generate the proof off-chain: `(h, π)`](#step-4--generate-the-proof-off-chain-h-π)
  - [Step 5 — The Sails verifier (Wasm) + gtest against the builtin mock](#step-5--the-sails-verifier-wasm--gtest-against-the-builtin-mock)
  - [Step 6 — Deploy to Vara testnet](#step-6--deploy-to-vara-testnet)
  - [Step 7 — Real on-chain verification](#step-7--real-on-chain-verification)
  - [Step 8 — Live frontend](#step-8--live-frontend)
- [Command cheat-sheet](#command-cheat-sheet)
- [Security notes](#security-notes)

## Layout

```
zk-groth16-bls12-381-vara/
├─ observability/telemetry/   shared tracing + StepReport + JSONL run-log writer
├─ crates/
│  ├─ circuit/                Step 2 — Poseidon(w)==h as R1CS (arkworks 0.5)
│  ├─ keys/                   Step 3 — Groth16 setup; emits pk/vk + PREPARED vk
│  ├─ prover/                 Step 4 — off-chain prover; emits (h, π) only
│  └─ verifier-app/           Step 5 — Sails verifier (ISOLATED workspace, Wasm)
├─ frontend/                  educational React UI + live on-chain verify
├─ artifacts/                 generated pk/vk/proof + deploy/verify scripts
└─ runs/                      JSONL run logs
```

### Why two workspaces (deviation from the brief)

The brief asked for a single Cargo workspace. The on-chain Sails program lives in
its **own** workspace (`crates/verifier-app`, `exclude`d from the outer one)
because a shared workspace makes Cargo unify features and enable `gstd` + `gtest`
on `sails-rs` simultaneously, breaking the Wasm build (vara-skills `sails-new-app`
guardrail).

## Pinned versions

| Area | Crate / tool | Version | Notes |
|---|---|---|---|
| Off-chain proofs | `ark-groth16`, `ark-bls12-381`, `ark-ec/ff/serialize`, `ark-relations`, `ark-r1cs-std`, `ark-crypto-primitives` | **0.5** | Poseidon + Groth16 |
| On-chain verify | `gbuiltin-bls381` | **1.10.0** | `default-features = false` (keeps `ark-scale/std` → serde out of the no_std Wasm graph) |
| On-chain ark | via `gbuiltin-bls381` re-exports | **0.4** | uncompressed encodings are byte-compatible with 0.5 |
| Program framework | `sails-rs`, `gstd` | **0.10.x / 1.10** | async service, events, generated client |
| Toolchain | rustc | **1.91**, target `wasm32v1-none` | build in WSL |

## The five components

| # | Crate | Does | Key signal |
|---|---|---|---|
| 1 | `circuit` | `Poseidon(w)==h` as ~**238** R1CS constraints | `num_constraints` |
| 2 | `keys` | Groth16 keygen → `pk.bin`, `vk.bin`, **prepared** `vk_prepared.json` + fingerprint | `vk_fingerprint` |
| 3 | `prover` | secret `w` → `(h, π)` (~**192** bytes); `w` never leaves | `prove_ms`, `proof_bytes` |
| 4 | `verifier-app` | Sails actor: checks π via the **BLS12-381 builtin**; emits `Verified`/`Rejected` | `verdict`, `vk_fingerprint` |
| 5 | frontend / vara-wallet | drives `(h, π)` → actor, reads verdict + correlation | `trace_id`, `block`, `latency` |

The on-chain check is the Groth16 equation in prepared form, with MSM + Miller
loop + final exponentiation all offloaded to the builtin:

```
e(A, B) · e(L, −γ) · e(C, −δ) == e(α, β),   L = ic₀ + h·ic₁
```

## Quick start — see it working (no Rust)

The contract is **already deployed** to testnet, so you do **not** need Rust or a
redeploy to see the whole thing work — the frontend talks straight to the live
program.

**Prerequisites:** Node 18+ and a Substrate wallet browser extension
(Polkadot.js / Talisman / SubWallet) with a **testnet account holding some
TVARA** (free from the faucet).

```bash
cd frontend
npm install --legacy-peer-deps     # gear-js peer ranges; .npmrc already sets this
cp .env.example .env               # already points at the deployed program
npm run dev                        # → http://localhost:3000
```

Open `http://localhost:3000`, connect your wallet (top-right), scroll to
**“Verify live”**, and click **Verify on Vara**. You’ll see the real on-chain
verdict (`ok: true`), the echoed `trace_id`, message id, block, and latency.
Toggle *“Corrupt one byte”* to watch it get rejected.

> No TVARA? Get testnet tokens: `vara-wallet --network testnet faucet <address>`.

## Walkthrough — build it end to end

This is the full pipeline reproduced from scratch: circuit → setup → proof →
on-chain verifier → deploy → live verify → UI. Each step lists its **goal**, the
**commands**, and the **success signal** (what you should see on screen). Steps
6–7 are optional reproduction — the contract is already deployed.

> All commands run in **WSL** (never PowerShell directly for `cargo`). To rebuild
> the off-chain artifacts you need Rust **1.91** with the `wasm32v1-none` target
> (`rustup target add wasm32v1-none`); to redeploy you also need
> [`vara-wallet`](https://github.com/gear-foundation/vara-wallet)
> (`npm i -g vara-wallet`) and a funded account.

### One-time setup (before anything else)

Export these in your WSL shell so **every** stage writes to the **same** run-log;
the closing `make report` then prints the whole pipeline as a single table.

```bash
cd /mnt/c/path/to/zk-groth16-bls12-381-vara   # the repo checkout, as seen from WSL
source ~/.cargo/env
export LOG_FORMAT=pretty                 # human-readable output (this is the default)
export RUST_LOG=info
export ZK_RUN_LOG=runs/tutorial.jsonl    # circuit + setup + prover in a single log
```

Each script first prints a `STEP n/5 — …` banner, then its structured
`StepReport` (`trace_id`, `step`, `status`, `duration_ms`, `metrics{}`). The
`trace_id` is the backbone: the one minted by the prover reappears in the
on-chain reply.

> **Speed:** in *debug* builds the arkworks operations are slow (e.g.
> `zk-circuit stats` ~20 s). Add `--release` to the `cargo run` calls (or
> pre-compile with `cargo build --release`) to make them near-instant.

### Step 1 — Environment & goal

**Goal:** confirm the goal and that the toolchain is ready. We prove knowledge of
a secret `w` such that `Poseidon(w) == h`, without revealing `w`, and verify it
on-chain on Vara. The proof is Groth16 over BLS12-381: generated off-chain with
arkworks, verified inside a Sails actor that delegates the pairings to the runtime
BLS12-381 builtin.

```bash
rustc --version                                   # must read 1.91.x
rustup target list --installed | grep wasm32v1-none
ls crates                                         # circuit  keys  prover  verifier-app
```

**Success signal:** `rustc 1.91.x`, `wasm32v1-none` is listed, and `crates/`
shows `circuit  keys  prover  verifier-app`.

### Step 2 — The circuit: `Poseidon(w) == h`

**Goal:** express the relation as an R1CS constraint system and inspect its
shape. Poseidon is SNARK-friendly: the whole hash is ~238 constraints (SHA-256
would be tens of thousands). This step generates no keys and no proof — it only
inspects the relation.

```bash
make circuit          # = cargo run -p zk-circuit -- stats
```

**Success signal:** `STEP 1/5 — CIRCUIT` banner + the `circuit` `StepReport` with
`num_constraints = 238`, `public_inputs = 1` (just `h`), `curve = BLS12-381`.

```
constraints: 238
public inputs: 1  (just h)
```

### Step 3 — Trusted setup: pk, vk and the prepared vk

**Goal:** generate the keys and, above all, the **prepared vk** (the format the
on-chain actor verifies) plus its integrity fingerprint. Groth16 setup produces
the proving key and the verifying key; here we additionally emit the prepared vk
— `e(α,β)`, `-γ`, `-δ`, IC — which is what the actor carries embedded.

```bash
make setup            # = cargo run -p zk-keys -- setup --seed 42 --out-dir artifacts
```

**Success signal:** `STEP 2/5 — SETUP` banner, the trusted-setup WARNING (we use a
**fixed seed** for reproducibility — in production this would be a multi-party
ceremony), the `setup` `StepReport` (`keygen_ms`, `pk_bytes`, `vk_bytes`,
`vk_fingerprint`, `prepared_vk_fingerprint`, `rng_seed`), and:

- `vk fingerprint (prepared): … ← the actor checks THIS`
- files written: `pk.bin`, `vk.bin`, `vk.fingerprint`, `vk_prepared.json`

### Step 4 — Generate the proof off-chain: `(h, π)`

**Goal:** produce the proof from the secret, showing that `w` **never** appears in
any artifact. The prover generates `(h, π)` (~192 bytes) and mints the `trace_id`
that travels with the proof all the way to the chain. The secret `w` is never
written or logged; the script asserts it (`witness_leaked = false`).

```bash
make prove            # = cargo run -p zk-prover -- prove --secret 42 --seed 7
```

**Success signal:** `STEP 3/5 — PROVER` banner, the `prover` `StepReport`
(`prove_ms`, `proof_bytes = 192`, `public_input_h`, `vk_fingerprint`,
`witness_leaked = false`, `trace_id`), and:

- `trace_id: <uuid>` ← **note this value**, it reappears in Step 7
- files: `proof.bin`, `proof.json`, `public.json`

> Optional (reinforces the security claim): `bash artifacts/check-no-leak.sh`
> asserts the secret left no trace in any output.

### Step 5 — The Sails verifier (Wasm) + gtest against the builtin mock

**Goal:** compile the on-chain actor to Wasm and run the gtest suite (happy path +
rejections) using the in-memory BLS12-381 builtin mock. The verifier is a Sails
actor that checks the Groth16 equation by delegating MSM + Miller loop + final
exponentiation to the runtime builtin. It lives in its own isolated workspace
(otherwise Cargo unifies features and breaks the Wasm build).

```bash
cd crates/verifier-app
cargo build --release     # → target/wasm32-gear/release/zk_verifier.opt.wasm + .idl
cargo test --release      # gtest: happy-path + invalid proof + malformed bytes
cd ../..
```

(equivalent to `make verify-app` + `make gtest`)

**Success signal:**

- `zk_verifier.opt.wasm` (~118 KB) and `zk_verifier.idl` are generated
- `test result: ok` in the gtest suite (valid verification → `ok:true`;
  rejections → `Rejected`)

### Step 6 — Deploy to Vara testnet

**Goal:** upload the actor to testnet with the prepared vk + fingerprint.
*(Optional: the contract is already deployed; skip to Step 7 if you’re only
demonstrating.)* The constructor receives the prepared vk, the builtin ActorId,
and the expected fingerprint — and `panic!`s if the fingerprint doesn’t match:
fail-fast integrity at deploy time.

```bash
make deploy           # = bash artifacts/deploy.sh  (chupachups account, testnet)
```

**Success signal:** `STEP 4/5 — VERIFIER` banner, the wasm/args byte sizes, and
`vara-wallet` prints the **new programId**.

> No TVARA on the account? `vara-wallet --network testnet faucet <address>`.
> If you redeploy, update the programId in `frontend/.env` for Step 8.

### Step 7 — Real on-chain verification

**Goal:** send `(h, π)` to the deployed actor and read the real verdict. We first
query `VkFingerprint` (confirms init succeeded), then call `Verify`. The reply
carries the same `trace_id` the prover minted — off-chain ↔ on-chain correlation —
plus the verdict.

```bash
make verify           # = bash artifacts/verify.sh
```

**Success signal:** `STEP 5/5 — CLIENT` banner and the `Verify` reply:

- `ok: true`
- the `vk_fingerprint` matching Step 3
- the `trace_id` you noted in Step 4

> Live program (reference):
> `0x8d84679b79b6eae0f76f18cd8e1045b7c3482725c47f27b73ecd8f5f32d502eb`.

**Observability closeout — the summary table**

```bash
make report
```

Reads `runs/tutorial.jsonl` and shows **one table** with every stage
(`circuit → setup → prover`) — `step`, `status`, `duration_ms`, `metrics`: the
whole pipeline on a single screen.

### Step 8 — Live frontend

**Goal:** see the complete system from the browser, talking directly to the
deployed program and the wallet — no backend. The page talks straight to the
testnet node, the deployed program, and the wallet extension. Connect the wallet,
click **Verify on Vara**, and watch the real verdict, the `trace_id`, the message
id, the block, and the latency. The *“Corrupt one byte”* toggle makes it fail
live.

```bash
cd frontend
npm install --legacy-peer-deps    # gear-js peer ranges (.npmrc already sets this)
cp .env.example .env              # already points at the deployed program
npm run dev                       # → http://localhost:3000
```

**Success signal:**

- Vite serves at `http://localhost:3000`
- connect wallet → **“Verify live”** section → **Verify on Vara** → `ok: true`
  with `trace_id`, message id, block, and latency
- the *“Corrupt one byte”* toggle → the actor **rejects** it

## Command cheat-sheet

A `Makefile` wraps the whole pipeline:

```bash
# setup
export LOG_FORMAT=pretty RUST_LOG=info ZK_RUN_LOG=runs/tutorial.jsonl

make test        # circuit/keys/prover unit + property tests
make circuit     # Step 2  — R1CS (238 constraints)
make setup       # Step 3  — pk/vk + prepared vk
make prove       # Step 4  — (h, π), trace_id
make verify-app  # Step 5a — build the actor Wasm
make gtest       # Step 5b — tests against the builtin mock
make deploy      # Step 6  — deploy to testnet (optional)
make verify      # Step 7  — on-chain Verify → ok:true
make report      # closeout — run-log summary table
make frontend    # Step 8  — UI at localhost:3000
```

The full signal catalog lives in `OBSERVABILITY.md`; the UI in
`frontend/README.md`.

## Security notes

- **Trusted setup**: Groth16 keygen is per-circuit and trust-sensitive. This repo
  uses a *fixed seed* for reproducibility — **not** secure for production (use a
  ceremony).
- This proves **knowledge of a preimage only**, not a full application.
- The witness `w` never appears in any artifact, log, or on-chain payload.
