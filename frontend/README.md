# ZK on Vara: frontend

An educational, single-page explainer for the *"prove you know a secret"* demo,
with a **live on-chain verification** against the deployed Sails verifier on Vara
testnet.

## What it shows

- The statement `Poseidon(w) == h` with the witness `w` visibly **redacted** — it
  never leaves your machine.
- The five-component flow (Circuit → Setup → Prover → Verifier → Client) and how
  only `(h, π)` crosses to the chain.
- A **Verify on Vara** button that submits the precomputed `(h, π)` to the
  deployed program and shows the verdict, echoed `trace_id`, message id, block,
  and latency. A toggle corrupts one byte to demonstrate rejection.

## Run

```bash
npm install        # .npmrc sets legacy-peer-deps (gear-js peer ranges)
cp .env.example .env
npm run dev        # http://localhost:3000
```

`.env`:

```
VITE_NODE_ADDRESS=wss://testnet.vara.network
VITE_PROGRAM_ID=0x8d84679b79b6eae0f76f18cd8e1045b7c3482725c47f27b73ecd8f5f32d502eb
```

To verify you need a Substrate wallet (e.g. Polkadot.js / Talisman / SubWallet)
with a testnet account that has some TVARA for gas.

## How the live call works

`src/hooks/useVerifier.ts` initializes `sails-js` with the program IDL
(`src/idl.ts`) + program id, then calls `Verifier.Verify(h, proof, trace_id)`.
The sample `(h, π)` lives in `src/data/` and was produced off-chain by the
`zk-keys` + `zk-prove` CLIs. The secret `w` is **not** in this app.
