//! Properties that are cheap to assert and expensive to notice by hand.
//!
//! These are less about cryptographic correctness — `security.rs` covers that —
//! and more about invariants a refactor could silently break: statistical
//! quality of the ciphertext, absence of a network stack, cost of a guess.

use cerberus_core::container;
use cerberus_core::factors::{Factor, FactorSet};
use cerberus_core::kdf::KdfParams;
use cerberus_core::vault::{Entry, Vault};
use cerberus_core::Cascade;
use zeroize::Zeroizing;

const FAST: KdfParams = KdfParams {
    memory_kib: 19 * 1024,
    time_cost: 2,
    parallelism: 1,
};

fn factors() -> FactorSet {
    FactorSet::new().with(Factor::Password(Zeroizing::new(
        "correct horse battery staple".into(),
    )))
}

/// A vault holding very compressible data must still produce incompressible
/// ciphertext.
///
/// Any structure surviving encryption — a repeated block, a plaintext run —
/// shows up as a file that compresses. This catches an ECB-like mistake or a
/// layer accidentally becoming a no-op.
#[test]
fn the_ciphertext_shows_no_exploitable_structure() {
    let mut vault = Vault::new("compressible");
    let root = vault.root;
    for i in 0..50 {
        let mut e = Entry::new(root, format!("entry-{i}"));
        // Maximally repetitive: if any of it survives, entropy will collapse.
        e.password = "A".repeat(200);
        e.notes = "AAAA".repeat(200);
        vault.add_entry(e).unwrap();
    }

    let bytes = container::seal(&vault, &factors(), Cascade::recommended(), FAST).unwrap();
    // Skip the header, which is cleartext by design.
    let payload = &bytes[80..bytes.len() - 64];

    let entropy = shannon_entropy(payload);
    assert!(
        entropy > 7.9,
        "payload entropy is only {entropy:.3} bits/byte; ciphertext should be ~8.0"
    );

    // No 16-byte block should ever repeat in a well-formed ciphertext of this
    // size; a repeat is the classic signature of a broken mode.
    let mut blocks = std::collections::HashSet::new();
    for block in payload.chunks_exact(16) {
        assert!(blocks.insert(block), "a 16-byte ciphertext block repeats");
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Byte values must be uniformly distributed across the payload.
///
/// A chi-squared test over 256 buckets. The critical value at p=0.001 with 255
/// degrees of freedom is ~330; a healthy ciphertext lands near 255.
#[test]
fn ciphertext_bytes_are_uniformly_distributed() {
    let mut vault = Vault::new("x");
    let root = vault.root;
    for i in 0..200 {
        let mut e = Entry::new(root, format!("e{i}"));
        e.password = "Z".repeat(100);
        vault.add_entry(e).unwrap();
    }
    let bytes = container::seal(&vault, &factors(), Cascade::paranoid(), FAST).unwrap();
    let payload = &bytes[80..bytes.len() - 64];

    let mut counts = [0usize; 256];
    for &b in payload {
        counts[b as usize] += 1;
    }
    let expected = payload.len() as f64 / 256.0;
    let chi2: f64 = counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum();

    assert!(
        chi2 < 330.0,
        "chi-squared is {chi2:.1} over 255 degrees of freedom; the payload is not uniform"
    );
}

/// The vault core must not depend on any network stack.
///
/// Cerberus makes no network calls, and that is a property worth enforcing
/// mechanically. A dependency added in passing would otherwise turn "it never
/// phones home" from a fact into a hope.
#[test]
fn the_core_pulls_in_no_networking_crate() {
    let lock = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("Cargo.lock");
    let Ok(contents) = std::fs::read_to_string(&lock) else {
        // Not an error: a packaged crate has no lockfile beside it.
        eprintln!("Cargo.lock not found, skipping");
        return;
    };

    // Present in the tree via Tauri's desktop stack, which the core never
    // touches. This test guards `cerberus-core`'s own dependency list, checked
    // separately below.
    let core_manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("core manifest");

    for banned in [
        "reqwest",
        "hyper",
        "ureq",
        "curl",
        "isahc",
        "surf",
        "attohttpc",
        "tokio",
        "async-std",
        "rustls",
        "native-tls",
        "openssl",
        "socket2",
    ] {
        assert!(
            !core_manifest.contains(banned),
            "cerberus-core declares the networking crate `{banned}`"
        );
    }

    // Sanity check that the lockfile was actually read.
    assert!(contents.contains("cerberus-core"));
}

/// Guessing must be expensive, and the cost must scale with the chosen profile.
///
/// This is the only defence that survives an attacker holding the file: they
/// can bypass every in-app delay by writing their own reader, but not Argon2id.
#[test]
#[ignore = "measures wall-clock cost; run explicitly with --ignored"]
fn a_single_guess_costs_real_time() {
    let vault = Vault::new("x");

    for (name, params, floor_ms) in [
        ("interactive", KdfParams::INTERACTIVE, 100u128),
        ("hardened", KdfParams::HARDENED, 500),
    ] {
        let bytes = container::seal(&vault, &factors(), Cascade::recommended(), params).unwrap();
        let wrong =
            FactorSet::new().with(Factor::Password(Zeroizing::new("wrong password".into())));

        let start = std::time::Instant::now();
        assert!(container::open(&bytes, &wrong).is_err());
        let elapsed = start.elapsed().as_millis();

        println!("{name}: one wrong guess costs {elapsed} ms");
        assert!(
            elapsed >= floor_ms,
            "{name}: a guess cost only {elapsed} ms, well under the {floor_ms} ms floor"
        );
    }
}

/// Failed unlocks must not become cheaper as they repeat.
///
/// A cache keyed on the salt, or a short-circuit on a repeated wrong password,
/// would hand an attacker a free speed-up.
#[test]
fn repeated_wrong_guesses_do_not_get_faster() {
    let bytes =
        container::seal(&Vault::new("x"), &factors(), Cascade::recommended(), FAST).unwrap();
    let wrong = FactorSet::new().with(Factor::Password(Zeroizing::new("wrong password".into())));

    let mut timings = Vec::new();
    for _ in 0..5 {
        let start = std::time::Instant::now();
        assert!(container::open(&bytes, &wrong).is_err());
        timings.push(start.elapsed().as_secs_f64());
    }

    let first = timings[0];
    let last = timings[timings.len() - 1];
    assert!(
        last > first * 0.5,
        "the fifth guess took {last:.3}s against {first:.3}s for the first: results are being cached"
    );
}
