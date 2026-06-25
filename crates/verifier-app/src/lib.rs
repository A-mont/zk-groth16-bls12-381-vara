// Crate entrypoint. Compiled two ways:
//   * wasm32 (on-chain): re-export the program's wasm entrypoints from `app`.
//   * host (tests/std): embed the compiled wasm as WASM_BINARY and re-export the
//     generated typed client, so e2e/gtest can deploy and call the program.
#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(all(not(target_arch = "wasm32"), any(feature = "wasm-binary", test)))]
mod code {
    include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));
}

#[cfg(all(not(target_arch = "wasm32"), any(feature = "wasm-binary", test)))]
pub use code::WASM_BINARY_OPT as WASM_BINARY;

#[cfg(any(test, feature = "zk-verifier-client"))]
pub use zk_verifier_client as client;

#[cfg(target_arch = "wasm32")]
pub use zk_verifier_app::wasm::*;
