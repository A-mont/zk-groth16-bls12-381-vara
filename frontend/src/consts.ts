// Network + deployed-program configuration.
//
// The verifier program was deployed to Vara testnet; the id below is the
// default, overridable via `.env` (VITE_PROGRAM_ID / VITE_NODE_ADDRESS).
const ADDRESS = {
  NODE: (import.meta.env.VITE_NODE_ADDRESS as string) || 'wss://testnet.vara.network',
  PROGRAM_ID:
    (import.meta.env.VITE_PROGRAM_ID as string) ||
    '0x8d84679b79b6eae0f76f18cd8e1045b7c3482725c47f27b73ecd8f5f32d502eb',
};

// The BLS12-381 builtin actor the program offloads pairings to (Vara runtime).
const BLS_BUILTIN = '0x6b6e292c382945e80bf51af2ba7fe9f458dcff81ae6075c46f9095e1bbecdc37';

// Facts about the relation, surfaced in the UI copy.
const RELATION = {
  curve: 'BLS12-381',
  hash: 'Poseidon',
  proofSystem: 'Groth16',
  constraints: 238,
  proofBytes: 192,
};

export { ADDRESS, BLS_BUILTIN, RELATION };
