import { useApi, useAccount } from '@gear-js/react-hooks';
import { web3Enable, web3FromSource } from '@polkadot/extension-dapp';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Sails } from 'sails-js';
import { SailsIdlParser } from 'sails-js-parser';

import { ADDRESS } from '@/consts';
import { IDL } from '@/idl';

export type ProofHex = { a: string; b: string; c: string };

export type VerifyOutcome = {
  ok: boolean;
  traceId: string;
  vkFingerprint: string;
  blockHash?: string;
  messageId?: string;
  elapsedMs: number;
};

const hx = (s: string) => (s.startsWith('0x') ? s : `0x${s}`);

/**
 * Wraps the deployed Sails verifier with a typed client. Exposes the on-chain
 * `Verify` command and the free `VkFingerprint` query.
 */
export function useVerifier() {
  const { api, isApiReady } = useApi();
  const { account } = useAccount();
  const sailsRef = useRef<Sails | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!isApiReady || !api) return;
      const parser = await SailsIdlParser.new();
      const sails = new Sails(parser);
      sails.parseIdl(IDL);
      sails.setProgramId(ADDRESS.PROGRAM_ID as `0x${string}`);
      sails.setApi(api);
      if (!cancelled) {
        sailsRef.current = sails;
        setReady(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api, isApiReady]);

  const queryFingerprint = useCallback(async (): Promise<string | null> => {
    const sails = sailsRef.current;
    if (!sails) return null;
    const from = account?.decodedAddress ?? ADDRESS.PROGRAM_ID;
    const q = sails.services.Verifier.queries.VkFingerprint() as any;
    return q.withAddress(from).call() as Promise<string>;
  }, [account]);

  const verify = useCallback(
    async (h: string, proof: ProofHex, traceId: string): Promise<VerifyOutcome> => {
      const sails = sailsRef.current;
      if (!sails) throw new Error('verifier client not ready');
      if (!account) throw new Error('connect a wallet first');

      await web3Enable('ZK on Vara');
      const injector = await web3FromSource(account.meta.source as string);

      const started = performance.now();
      // `as any`: @polkadot/extension-dapp bundles its own @polkadot/types, so
      // the injector's Signer is structurally-but-not-nominally the same type
      // sails-js expects. Casting avoids the duplicate-package type clash.
      const builder = await (
        sails.services.Verifier.functions.Verify(
          hx(h),
          { a: hx(proof.a), b: hx(proof.b), c: hx(proof.c) },
          traceId,
        ) as any
      )
        .withAccount(account.address, { signer: injector.signer })
        .calculateGas();

      const { response, blockHash, msgId } = await builder.signAndSend();
      const reply = (await response()) as { trace_id: string; ok: boolean; vk_fingerprint: string };
      const elapsedMs = Math.round(performance.now() - started);

      return {
        ok: reply.ok,
        traceId: reply.trace_id,
        vkFingerprint: reply.vk_fingerprint,
        blockHash: blockHash?.toString(),
        messageId: msgId?.toString(),
        elapsedMs,
      };
    },
    [account],
  );

  return { ready, verify, queryFingerprint };
}
