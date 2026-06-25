import { useApi, useAccount } from '@gear-js/react-hooks';
import { Wallet } from '@gear-js/wallet-connect';
import { useMemo, useState, type ReactNode } from 'react';

import { withProviders } from '@/hocs';
import { ADDRESS, BLS_BUILTIN, RELATION } from '@/consts';
import { useVerifier, type VerifyOutcome } from '@/hooks/useVerifier';
import proofData from '@/data/proof.json';
import publicData from '@/data/public.json';
import './App.scss';

// ── helpers ──────────────────────────────────────────────────────────────────

const short = (hex: string, head = 8, tail = 6) => {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  return `0x${h.slice(0, head)}…${h.slice(-tail)}`;
};

/** XOR the last byte of a hex string — used to demo a tampered proof. */
const flipLastByte = (hex: string) => {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const n = parseInt(h.slice(-2), 16) ^ 0x01;
  return h.slice(0, -2) + n.toString(16).padStart(2, '0');
};

// ── small presentational pieces ──────────────────────────────────────────────

function Redacted({ label }: { label: string }) {
  return (
    <span className="redacted" title="The witness never leaves your machine">
      <span className="redacted__bar" aria-hidden />
      <span className="redacted__sr">{label}</span>
    </span>
  );
}

function Eyebrow({ children }: { children: ReactNode }) {
  return <p className="eyebrow">{children}</p>;
}

function Field({ k, v, tone }: { k: string; v: ReactNode; tone?: 'witness' | 'public' }) {
  return (
    <div className={`field ${tone ? `field--${tone}` : ''}`}>
      <span className="field__k">{k}</span>
      <span className="field__v">{v}</span>
    </div>
  );
}

// ── sections ─────────────────────────────────────────────────────────────────

function TopBar() {
  return (
    <header className="topbar">
      <a className="brand" href="#top">
        <span className="brand__mark">ZK</span>
        <span className="brand__dot" />
        <span className="brand__net">VARA</span>
      </a>
      <nav className="topbar__nav">
        <a href="#how">How it works</a>
        <a href="#components">Components</a>
        <a href="#verify">Verify live</a>
      </nav>
      <div className="topbar__wallet">
        <Wallet theme="vara" />
      </div>
    </header>
  );
}

function Hero({ onVerify }: { onVerify: () => void }) {
  return (
    <section className="hero" id="top">
      <div className="hero__grid">
        <div className="hero__lead">
          <Eyebrow>Zero-knowledge · Groth16 · BLS12-381</Eyebrow>
          <h1 className="hero__title">
            Prove you know a secret.
            <br />
            <span className="hero__title-em">Reveal nothing.</span>
          </h1>
          <p className="hero__sub">
            You hold a secret <code>w</code>. You publish only its hash <code>h = Poseidon(w)</code>.
            A ~200-byte proof convinces anyone you know a <code>w</code> that hashes to{' '}
            <code>h</code> — without disclosing <code>w</code>. Here it is verified live, on Vara.
          </p>
          <div className="hero__cta">
            <button className="btn btn--primary" onClick={onVerify}>
              Verify a proof on Vara →
            </button>
            <a className="btn btn--ghost" href="#how">
              See the flow
            </a>
          </div>
        </div>

        <aside className="dossier" aria-label="The statement">
          <div className="dossier__head">
            <span>STATEMENT</span>
            <span className="stamp stamp--secret">CLASSIFIED</span>
          </div>
          <div className="dossier__body">
            <Field
              k="witness  w"
              tone="witness"
              v={
                <>
                  <Redacted label="the secret preimage — hidden" /> <em>stays local</em>
                </>
              }
            />
            <div className="dossier__op">Poseidon(w)</div>
            <Field k="public  h" tone="public" v={<code>{short(publicData.h_hex, 10, 8)}</code>} />
            <Field k="proof  π" tone="public" v={<code>{RELATION.proofBytes} bytes · Groth16</code>} />
          </div>
          <div className="dossier__foot">
            <span>relation</span>
            <code>Poseidon(w) == h</code>
          </div>
        </aside>
      </div>
    </section>
  );
}

const STAGES = [
  { id: 'circuit', t: 'Circuit', d: 'The relation hash(w)=h as ~238 R1CS constraints.', side: 'private' },
  { id: 'setup', t: 'Setup', d: 'One-time keygen → proving key (pk) and verifying key (vk).', side: 'private' },
  { id: 'prover', t: 'Prover', d: 'Off-chain: takes w, outputs only (h, π). w never leaves.', side: 'private' },
  { id: 'verifier', t: 'Verifier on Vara', d: 'A Sails actor checks π against vk via the BLS12-381 builtin.', side: 'public' },
  { id: 'result', t: 'Valid ✓', d: 'Anyone holding (h, π) is convinced — learning nothing about w.', side: 'public' },
] as const;

function Pipeline() {
  return (
    <section className="how" id="how">
      <Eyebrow>The flow</Eyebrow>
      <h2 className="h2">
        The secret stays on your machine. Only <span className="hl">(h, π)</span> crosses to the chain.
      </h2>

      <div className="pipeline">
        <div className="pipeline__boundary">
          <span>your machine — nothing here is published</span>
        </div>
        {STAGES.map((s, i) => (
          <div className={`stage stage--${s.side}`} key={s.id}>
            <span className="stage__n">{String(i + 1).padStart(2, '0')}</span>
            <h3 className="stage__t">{s.t}</h3>
            <p className="stage__d">{s.d}</p>
            {i < STAGES.length - 1 && <span className="stage__arrow" aria-hidden />}
          </div>
        ))}
        <div className="pipeline__wire" aria-hidden>
          <span className="pipeline__packet">(h, π)</span>
        </div>
      </div>
    </section>
  );
}

const COMPONENTS = [
  {
    n: '01',
    t: 'Circuit',
    d: 'Expresses Poseidon(w) == h as an arithmetic circuit. Poseidon is SNARK-friendly — a single-element hash is only ~238 constraints (an in-circuit SHA-256 would be tens of thousands).',
    tag: 'arkworks · R1CS',
  },
  {
    n: '02',
    t: 'Setup',
    d: 'Runs Groth16 keygen once. The proving key stays off-chain; the verifying key is embedded in the on-chain actor. A SHA-256 fingerprint pins its identity.',
    tag: 'Groth16 · trusted setup',
  },
  {
    n: '03',
    t: 'Prover',
    d: 'Off-chain CLI. Takes the secret w, computes h, and emits a ~200-byte proof. Submits exactly (h, π) — never the witness. A trace id is minted here and travels everywhere.',
    tag: 'off-chain',
  },
  {
    n: '04',
    t: 'Verifier actor',
    d: 'A Sails program on Vara. Holds the vk, checks the proof, and offloads the BLS12-381 pairings to the runtime builtin actor. Emits a typed Verified / Rejected event.',
    tag: 'Sails · on-chain',
  },
  {
    n: '05',
    t: 'Client',
    d: 'Drives the flow: sends (h, π) to the actor, reads the verdict, and correlates the trace id with the on-chain message, block, gas, and latency.',
    tag: 'gclient · this page',
  },
] as const;

function Components() {
  return (
    <section className="components" id="components">
      <Eyebrow>Five parts</Eyebrow>
      <h2 className="h2">The system, file by file.</h2>
      <div className="files">
        {COMPONENTS.map((c) => (
          <article className="file" key={c.n}>
            <div className="file__n">{c.n}</div>
            <div className="file__main">
              <h3 className="file__t">{c.t}</h3>
              <p className="file__d">{c.d}</p>
              <span className="file__tag">{c.tag}</span>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

type Phase = 'idle' | 'running' | 'valid' | 'invalid' | 'error';

function LiveVerify() {
  const { isApiReady } = useApi();
  const { account } = useAccount();
  const { ready, verify } = useVerifier();

  const [tamper, setTamper] = useState(false);
  const [phase, setPhase] = useState<Phase>('idle');
  const [outcome, setOutcome] = useState<VerifyOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);

  const proof = useMemo(
    () => ({ a: tamper ? flipLastByte(proofData.a) : proofData.a, b: proofData.b, c: proofData.c }),
    [tamper],
  );

  const traceId = useMemo(
    () => `web-${Math.random().toString(16).slice(2, 10)}`,
    // new id per mount; the on-chain reply echoes it back
    [],
  );

  const run = async () => {
    setError(null);
    setOutcome(null);
    setPhase('running');
    try {
      const res = await verify(publicData.h_hex, proof, traceId);
      setOutcome(res);
      setPhase(res.ok ? 'valid' : 'invalid');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPhase('error');
    }
  };

  const canRun = isApiReady && ready && !!account && phase !== 'running';

  return (
    <section className="verify" id="verify">
      <Eyebrow>Live, on testnet</Eyebrow>
      <h2 className="h2">Send a real proof to the contract.</h2>
      <p className="verify__intro">
        This page submits the precomputed pair <code>(h, π)</code> to the verifier deployed at{' '}
        <a href={`https://idea.gear-tech.io/programs/${ADDRESS.PROGRAM_ID}?node=${ADDRESS.NODE}`} target="_blank" rel="noreferrer">
          {short(ADDRESS.PROGRAM_ID, 8, 6)}
        </a>
        . The secret <code>w</code> is never sent — it isn’t even in this page.
      </p>

      <div className="verify__grid">
        <div className="panel">
          <div className="panel__head">
            <span>OUTGOING MESSAGE → verifier.Verify</span>
          </div>
          <div className="panel__body">
            <Field k="witness w" tone="witness" v={<Redacted label="not transmitted" />} />
            <Field k="h" tone="public" v={<code>{short(publicData.h_hex, 12, 10)}</code>} />
            <Field k="proof.a" tone="public" v={<code>{short(proof.a, 12, 10)}</code>} />
            <Field k="proof.b" tone="public" v={<code>{short(proof.b, 12, 10)}</code>} />
            <Field k="proof.c" tone="public" v={<code>{short(proof.c, 12, 10)}</code>} />
            <Field k="trace_id" v={<code>{traceId}</code>} />

            <label className="toggle">
              <input type="checkbox" checked={tamper} onChange={(e) => setTamper(e.target.checked)} />
              <span>Corrupt one byte of the proof (expect rejection)</span>
            </label>

            {!account && <p className="hint">Connect a wallet (top-right) to sign the verify message.</p>}

            <button className="btn btn--primary btn--full" disabled={!canRun} onClick={run}>
              {phase === 'running' ? 'Verifying on Vara…' : 'Verify on Vara'}
            </button>
          </div>
        </div>

        <div className={`panel panel--result panel--${phase}`}>
          <div className="panel__head">
            <span>ON-CHAIN VERDICT</span>
            {phase === 'valid' && <span className="stamp stamp--valid">VALID</span>}
            {phase === 'invalid' && <span className="stamp stamp--reject">REJECTED</span>}
          </div>
          <div className="panel__body">
            {phase === 'idle' && <p className="muted">Awaiting a verify call. The actor will check π against its embedded vk.</p>}
            {phase === 'running' && (
              <div className="working">
                <div className="working__row">→ MultiScalarMultiplicationG1 (fold public input)</div>
                <div className="working__row">→ MultiMillerLoop (pairing)</div>
                <div className="working__row">→ FinalExponentiation</div>
                <p className="muted">offloaded to the BLS12-381 builtin · awaiting reply…</p>
              </div>
            )}
            {outcome && (phase === 'valid' || phase === 'invalid') && (
              <>
                <Field k="verdict" v={<strong>{outcome.ok ? 'ok = true' : 'ok = false'}</strong>} />
                <Field k="trace_id" v={<code>{outcome.traceId}</code>} />
                <Field k="vk fingerprint" v={<code>{short(outcome.vkFingerprint, 8, 6)}</code>} />
                {outcome.messageId && <Field k="message id" v={<code>{short(outcome.messageId, 8, 6)}</code>} />}
                {outcome.blockHash && <Field k="block" v={<code>{short(outcome.blockHash, 8, 6)}</code>} />}
                <Field k="latency" v={<code>{outcome.elapsedMs} ms</code>} />
                <p className="muted">
                  {outcome.ok
                    ? 'The actor confirmed knowledge of a preimage — and learned nothing about it.'
                    : 'The proof did not satisfy the relation. Nothing was revealed either way.'}
                </p>
              </>
            )}
            {phase === 'error' && <p className="error">Couldn’t complete: {error}</p>}
          </div>
        </div>
      </div>
    </section>
  );
}

function UnderTheHood() {
  return (
    <section className="hood">
      <Eyebrow>Under the hood</Eyebrow>
      <h2 className="h2">One equation, checked by a pairing.</h2>
      <div className="hood__grid">
        <div className="hood__eq">
          <code className="eq">
            e(A, B) · e(L, −γ) · e(C, −δ) <span className="eq__eq">=</span> e(α, β)
          </code>
          <p className="muted">
            Groth16 acceptance in prepared form, where <code>L = ic₀ + h·ic₁</code>. The actor never
            runs trusted setup and never re-builds the circuit — it only checks this product.
          </p>
        </div>
        <div className="hood__notes">
          <Field k="curve" v={<code>{RELATION.curve}</code>} />
          <Field k="proof system" v={<code>{RELATION.proofSystem}</code>} />
          <Field k="in-circuit hash" v={<code>{RELATION.hash}</code>} />
          <Field k="pairings" v={<code>offloaded → builtin</code>} />
          <Field k="BLS12-381 builtin" v={<code>{short(BLS_BUILTIN, 8, 6)}</code>} />
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="footer">
      <div className="footer__row">
        <span className="footer__brand">ZK · VARA</span>
        <span className="muted">
          Prove knowledge of a Poseidon preimage, verified on-chain. The witness <code>w</code> never
          appears in any artifact, log, or payload.
        </span>
      </div>
      <div className="footer__meta">
        <span>program {short(ADDRESS.PROGRAM_ID, 8, 6)}</span>
        <span>testnet</span>
        <span>arkworks · Sails · Groth16 · BLS12-381</span>
      </div>
    </footer>
  );
}

// ── app ──────────────────────────────────────────────────────────────────────

function Component() {
  const { isApiReady } = useApi();
  const { isAccountReady } = useAccount();
  const ready = isApiReady && isAccountReady;

  const scrollToVerify = () => document.getElementById('verify')?.scrollIntoView({ behavior: 'smooth' });

  return (
    <div className="app">
      <TopBar />
      {ready ? (
        <main>
          <Hero onVerify={scrollToVerify} />
          <Pipeline />
          <Components />
          <LiveVerify />
          <UnderTheHood />
          <Footer />
        </main>
      ) : (
        <div className="boot">
          <span className="boot__dot" /> connecting to Vara…
        </div>
      )}
    </div>
  );
}

export const App = withProviders(Component);
