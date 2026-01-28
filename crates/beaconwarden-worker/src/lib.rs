#[cfg(target_arch = "wasm32")]
mod worker_wasm;

#[cfg(target_arch = "wasm32")]
pub use worker_wasm::*;

/// This crate is intended to be built for Cloudflare Workers (wasm32-unknown-unknown).
///
/// Keeping a tiny non-wasm surface helps `cargo check` on typical dev machines.
#[cfg(not(target_arch = "wasm32"))]
pub fn build_target_hint() -> &'static str {
    "beaconwarden-worker is intended for wasm32-unknown-unknown (Cloudflare Workers)"
}
