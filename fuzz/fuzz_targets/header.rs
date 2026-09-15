//! Fuzz target for the `.cbv` header/layout parser — the vault's entire
//! attack surface for untrusted input.
//!
//! Run:
//! ```bash
//! rustup toolchain install nightly
//! cargo install cargo-fuzz
//! cargo +nightly fuzz run header -- -max_total_time=600
//! ```
//!
//! Any crash, panic, or hang is a real defect: the core forbids `unsafe`, so a
//! panic is only a denial of service, but opening a file must never be able to
//! take the process down.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    cerberus_core::container::fuzz_parse(data);
});
