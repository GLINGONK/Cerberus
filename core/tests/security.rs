//! Security tests that treat the crate as a black box.
//!
//! These are the checks that matter to an attacker rather than to a developer:
//! can a malformed file crash the parser, does a wrong factor ever succeed, and
//! do secrets survive anywhere they should not.

use cerberus_core::cipher::{Cascade, CipherAlgo};
use cerberus_core::container;
use cerberus_core::factors::{Factor, FactorSet, Pattern};
use cerberus_core::kdf::KdfParams;
use cerberus_core::vault::{Entry, Vault};
use zeroize::Zeroizing;

/// Cheap Argon2 settings. Real vaults use `KdfParams::HARDENED`.
const FAST: KdfParams = KdfParams {
    memory_kib: 19 * 1024,
    time_cost: 2,
    parallelism: 1,
};

fn password(s: &str) -> FactorSet {
    FactorSet::new().with(Factor::Password(Zeroizing::new(s.to_string())))
}

fn vault_with_secret(secret: &str) -> Vault {
    let mut v = Vault::new("test");
    let root = v.root;
    let mut e = Entry::new(root, "Bank");
    e.username = "victim".into();
    e.password = secret.into();
    e.notes = format!("recovery phrase: {secret}");
    v.add_entry(e).unwrap();
    v
}

/// A sealed vault must not contain its own plaintext anywhere.
#[test]
fn no_plaintext_survives_encryption() {
    let secret = "SUPER-SECRET-CANARY-9f3a2b";
    let bytes = container::seal(
        &vault_with_secret(secret),
        &password("correct horse battery staple"),
        Cascade::recommended(),
        FAST,
    )
    .unwrap();

    for needle in [
        secret.as_bytes(),
        b"victim".as_slice(),
        b"Bank".as_slice(),
        b"recovery",
    ] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle),
            "found plaintext {:?} in the sealed file",
            String::from_utf8_lossy(needle)
        );
    }
}

/// A v2 file must not reveal, to someone holding only the file, which factors it
/// needs or which ciphers protect it.
///
/// This is the exact leak an independent attacker used against an early build:
/// the cleartext header announced "pattern only" and the full cascade, which
/// told them precisely what to attack. v2 encrypts all of it.
#[test]
fn a_stolen_file_reveals_no_factors_or_cascade() {
    let factors = FactorSet::new()
        .with(Factor::Password(Zeroizing::new(
            "correct horse battery".into(),
        )))
        .with(Factor::Pattern(
            Pattern::new(5, vec![0, 6, 12, 18, 24, 20]).unwrap(),
        ));

    // A distinctive cascade whose ordered ids must not appear in the clear.
    let cascade = Cascade::new(vec![
        CipherAlgo::Camellia256,
        CipherAlgo::Twofish256,
        CipherAlgo::Serpent256,
    ])
    .unwrap();
    let ids: Vec<u8> = cascade.ids();

    // Seal the SAME vault, factors and cascade twice. If the factor flags and
    // cascade were stored in cleartext (as in v1), the region describing them
    // would be byte-identical between the two files. Because they are encrypted
    // under a fresh nonce each time, that region must differ. This is the
    // robust, non-probabilistic way to prove the metadata is encrypted — unlike
    // searching random-looking bytes for a short id sequence.
    let a = container::seal(&Vault::new("x"), &factors, cascade.clone(), FAST).unwrap();
    let b = container::seal(&Vault::new("x"), &factors, cascade, FAST).unwrap();

    // The metadata block sits just after the clear header (67) + length (2).
    const META_START: usize = 67 + 2;
    let meta_a = &a[META_START..META_START + 40];
    let meta_b = &b[META_START..META_START + 40];
    assert_ne!(
        meta_a, meta_b,
        "the metadata block is not encrypted (identical across seals)"
    );

    // Only opening with the correct factors recovers them.
    let (_, header) = container::open(&a, &factors).unwrap();
    assert_eq!(header.cascade.ids(), ids);
    assert!(header.factors_known());
}

/// Nothing derived from the password may appear in the file either.
#[test]
fn no_password_derivative_leaks_into_the_header() {
    let pw = "correct horse battery staple";
    let bytes = container::seal(
        &Vault::new("x"),
        &password(pw),
        Cascade::recommended(),
        FAST,
    )
    .unwrap();

    let digest = blake3::hash(pw.as_bytes());
    assert!(
        !bytes.windows(32).any(|w| w == digest.as_bytes()),
        "a hash of the password is stored in the file"
    );
}

/// Every single-byte corruption must be rejected, across every cascade shape.
#[test]
fn corruption_is_always_detected() {
    for cascade in [
        Cascade::new(vec![CipherAlgo::Aes256Gcm]).unwrap(),
        Cascade::new(vec![CipherAlgo::Serpent256]).unwrap(),
        Cascade::recommended(),
        Cascade::paranoid(),
    ] {
        let factors = password("correct horse battery staple");
        let bytes = container::seal(&Vault::new("x"), &factors, cascade, FAST).unwrap();

        // Sampled: each attempt costs a full Argon2 derivation. The exhaustive
        // per-byte version lives in the cipher unit tests, where no KDF runs.
        for offset in (0..bytes.len()).step_by(997) {
            for bit in [0x01u8, 0x80] {
                let mut tampered = bytes.clone();
                tampered[offset] ^= bit;
                assert!(
                    container::open(&tampered, &factors).is_err(),
                    "corruption at byte {offset} bit {bit:#04x} was accepted"
                );
            }
        }
    }
}

/// Truncation at any length must fail cleanly rather than panic.
///
/// Exhaustive over the first 300 bytes — that is where the header lives and
/// where every off-by-one boundary is — then sampled across the payload. Once
/// past the header, `open` runs a full Argon2 derivation per call, so testing
/// every one of the remaining thousands of lengths would cost minutes in a
/// debug build for no extra coverage.
#[test]
fn truncation_never_panics() {
    let factors = password("correct horse battery staple");
    let bytes = container::seal(&Vault::new("x"), &factors, Cascade::recommended(), FAST).unwrap();

    let boundary = bytes.len().min(300);
    for len in 0..boundary {
        assert!(container::open(&bytes[..len], &factors).is_err());
    }
    for len in (boundary..bytes.len()).step_by(499) {
        assert!(container::open(&bytes[..len], &factors).is_err());
    }
}

/// Structured garbage aimed at the header parser must never panic.
///
/// A cheap stand-in for `cargo-fuzz`, run on every `cargo test` so regressions
/// surface without a nightly toolchain.
#[test]
fn hostile_headers_never_panic() {
    let factors = password("correct horse battery staple");
    let mut seed: u64 = 0x5eed_1234;
    let mut next = || {
        // xorshift64: deterministic, so a failure is reproducible.
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };

    for _ in 0..20_000 {
        let mut buf = b"CERBERUS".to_vec();
        let len = (next() % 200) as usize;
        for _ in 0..len {
            buf.push((next() & 0xFF) as u8);
        }
        let _ = container::open(&buf, &factors);
        let _ = container::open(&buf[..buf.len() / 2], &factors);
    }
}

/// Absurd KDF parameters in a header must be refused before Argon2 allocates.
///
/// Without the bounds check this test would try to allocate terabytes.
#[test]
fn hostile_kdf_parameters_cannot_exhaust_memory() {
    let factors = password("correct horse battery staple");
    let bytes = container::seal(&Vault::new("x"), &factors, Cascade::recommended(), FAST).unwrap();

    let mut hostile = bytes.clone();
    hostile[10..14].copy_from_slice(&u32::MAX.to_le_bytes()); // memory_kib
    let start = std::time::Instant::now();
    assert!(container::open(&hostile, &factors).is_err());
    assert!(
        start.elapsed() < std::time::Duration::from_secs(2),
        "the parser tried to honour an absurd memory cost"
    );

    let mut slow = bytes;
    slow[14..18].copy_from_slice(&u32::MAX.to_le_bytes()); // time_cost
    let start = std::time::Instant::now();
    assert!(container::open(&slow, &factors).is_err());
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
}

/// Every wrong factor combination must fail, and the right one must succeed.
#[test]
fn only_the_exact_factor_set_opens_the_vault() {
    let keyfile = vec![0xABu8; 256];
    let pattern = Pattern::new(5, vec![0, 6, 12, 18, 24, 20]).unwrap();

    let correct = FactorSet::new()
        .with(Factor::Password(Zeroizing::new(
            "correct horse battery".into(),
        )))
        .with(Factor::Keyfile(Zeroizing::new(keyfile.clone())))
        .with(Factor::Pattern(pattern.clone()));

    let bytes = container::seal(&Vault::new("x"), &correct, Cascade::recommended(), FAST).unwrap();
    assert!(container::open(&bytes, &correct).is_ok());

    let wrong_sets = [
        // Missing the pattern.
        FactorSet::new()
            .with(Factor::Password(Zeroizing::new(
                "correct horse battery".into(),
            )))
            .with(Factor::Keyfile(Zeroizing::new(keyfile.clone()))),
        // Missing the key file.
        FactorSet::new()
            .with(Factor::Password(Zeroizing::new(
                "correct horse battery".into(),
            )))
            .with(Factor::Pattern(pattern.clone())),
        // One byte off in the key file.
        FactorSet::new()
            .with(Factor::Password(Zeroizing::new(
                "correct horse battery".into(),
            )))
            .with(Factor::Keyfile(Zeroizing::new({
                let mut k = keyfile.clone();
                k[0] ^= 1;
                k
            })))
            .with(Factor::Pattern(pattern.clone())),
        // Pattern traced in reverse.
        FactorSet::new()
            .with(Factor::Password(Zeroizing::new(
                "correct horse battery".into(),
            )))
            .with(Factor::Keyfile(Zeroizing::new(keyfile.clone())))
            .with(Factor::Pattern(
                Pattern::new(5, vec![20, 24, 18, 12, 6, 0]).unwrap(),
            )),
        // Same pattern on a different grid size.
        FactorSet::new()
            .with(Factor::Password(Zeroizing::new(
                "correct horse battery".into(),
            )))
            .with(Factor::Keyfile(Zeroizing::new(keyfile)))
            .with(Factor::Pattern(
                Pattern::new(6, vec![0, 6, 12, 18, 24, 20]).unwrap(),
            )),
    ];

    for (i, wrong) in wrong_sets.iter().enumerate() {
        assert!(
            container::open(&bytes, wrong).is_err(),
            "wrong factor set #{i} opened the vault"
        );
    }
}

/// Two vaults sharing a password must not share any key material.
#[test]
fn identical_passwords_produce_unrelated_files() {
    let factors = password("the same password everywhere");
    let a = container::seal(&Vault::new("a"), &factors, Cascade::recommended(), FAST).unwrap();
    let b = container::seal(&Vault::new("a"), &factors, Cascade::recommended(), FAST).unwrap();

    assert_ne!(a, b);

    // The header's fixed prefix is legitimately identical: magic (8), version (2)
    // and the three KDF cost fields (9) are the same because both vaults were
    // sealed with the same parameters. Compare the complete salts: requiring
    // their very first byte to differ made this test fail randomly 1/256 times.
    const FIXED_PREFIX: usize = 8 + 2 + 4 + 4 + 1;
    let salt_a = &a[FIXED_PREFIX..FIXED_PREFIX + 32];
    let salt_b = &b[FIXED_PREFIX..FIXED_PREFIX + 32];
    assert_ne!(salt_a, salt_b, "two vaults were sealed with the same salt");
}

/// MAC verification must not leak the position of the first wrong byte.
///
/// Wall-clock timing is noisy, so this asserts only that no gross,
/// data-dependent early exit exists — a byte-by-byte `==` would show a clear
/// gradient here.
#[test]
fn mac_comparison_shows_no_timing_gradient() {
    let factors = password("correct horse battery staple");
    let bytes = container::seal(&Vault::new("x"), &factors, Cascade::recommended(), FAST).unwrap();
    let mac_start = bytes.len() - 64;

    let mut timings = Vec::new();
    for offset in [0usize, 16, 32, 48, 63] {
        let mut tampered = bytes.clone();
        tampered[mac_start + offset] ^= 0xFF;

        let start = std::time::Instant::now();
        for _ in 0..20 {
            let _ = container::open(&tampered, &factors);
        }
        timings.push(start.elapsed().as_secs_f64());
    }

    let mean = timings.iter().sum::<f64>() / timings.len() as f64;
    let spread = (timings.iter().cloned().fold(f64::MIN, f64::max)
        - timings.iter().cloned().fold(f64::MAX, f64::min))
        / mean;
    assert!(
        spread < 0.5,
        "MAC verification time varies with the corrupted position ({spread:.2} relative spread)"
    );
}

/// A vault written by an older cascade choice must still open unchanged.
#[test]
fn every_persisted_cascade_can_be_reopened() {
    let factors = password("correct horse battery staple");
    for algo in CipherAlgo::ALL {
        let cascade = Cascade::new(vec![algo]).unwrap();
        let bytes = container::seal(&vault_with_secret("canary"), &factors, cascade, FAST).unwrap();
        let (vault, header) = container::open(&bytes, &factors).unwrap();
        assert_eq!(vault.entries[0].password, "canary");
        assert_eq!(header.cascade.layers(), &[algo]);
    }
}
