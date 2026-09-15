//! End-to-end test of the Shamir-protected vault flow, mirroring exactly what
//! the application does: a random secret is split into shares, used as a key-file
//! factor to seal a vault, and any K shares reconstruct it to open the vault.

use cerberus_core::container;
use cerberus_core::factors::{Factor, FactorSet};
use cerberus_core::kdf::KdfParams;
use cerberus_core::shamir::{self, Share};
use cerberus_core::vault::{Entry, Vault};
use cerberus_core::Cascade;
use zeroize::Zeroizing;

const FAST: KdfParams = KdfParams {
    memory_kib: 19 * 1024,
    time_cost: 2,
    parallelism: 1,
};

/// Rebuild the key-file factor from a set of shares, the way the app does.
fn factor_from_shares(shares: &[Share], password: &str) -> FactorSet {
    let secret = shamir::combine(shares).unwrap();
    FactorSet::new()
        .with(Factor::Password(Zeroizing::new(password.into())))
        .with(Factor::Keyfile(secret))
}

fn sample_vault() -> Vault {
    let mut v = Vault::new("shamir");
    let root = v.root;
    let mut e = Entry::new(root, "Bank");
    e.password = "the-actual-secret".into();
    v.add_entry(e).unwrap();
    v
}

#[test]
fn a_two_of_three_vault_opens_with_any_two_shares() {
    // Create: random secret → shares → seal with password + secret-as-keyfile.
    let secret = cerberus_core::random::vec(32).unwrap();
    let shares = shamir::split(&secret, 2, 3).unwrap();

    let create_factors = FactorSet::new()
        .with(Factor::Password(Zeroizing::new("master password".into())))
        .with(Factor::Keyfile(Zeroizing::new(secret)));
    let bytes = container::seal(
        &sample_vault(),
        &create_factors,
        Cascade::recommended(),
        FAST,
    )
    .unwrap();

    // Any 2 of the 3 shares must open it.
    for combo in [[0, 1], [0, 2], [1, 2]] {
        let subset: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
        let factors = factor_from_shares(&subset, "master password");
        let (vault, _) = container::open(&bytes, &factors).unwrap();
        assert_eq!(vault.entries[0].password, "the-actual-secret");
    }
}

#[test]
fn the_password_is_still_required_even_with_enough_shares() {
    let secret = cerberus_core::random::vec(32).unwrap();
    let shares = shamir::split(&secret, 2, 3).unwrap();

    let create_factors = FactorSet::new()
        .with(Factor::Password(Zeroizing::new("master password".into())))
        .with(Factor::Keyfile(Zeroizing::new(secret)));
    let bytes = container::seal(
        &Vault::new("x"),
        &create_factors,
        Cascade::recommended(),
        FAST,
    )
    .unwrap();

    // Correct shares, wrong password → still refused.
    let wrong = factor_from_shares(&shares[..2], "WRONG password");
    assert!(container::open(&bytes, &wrong).is_err());

    // Correct shares, correct password → opens.
    let right = factor_from_shares(&shares[..2], "master password");
    assert!(container::open(&bytes, &right).is_ok());
}

#[test]
fn shares_below_the_threshold_cannot_open_the_vault() {
    let secret = cerberus_core::random::vec(32).unwrap();
    // 3-of-5: fewer than 3 must fail.
    let shares = shamir::split(&secret, 3, 5).unwrap();

    let create_factors = FactorSet::new()
        .with(Factor::Password(Zeroizing::new("master password".into())))
        .with(Factor::Keyfile(Zeroizing::new(secret)));
    let bytes = container::seal(
        &Vault::new("x"),
        &create_factors,
        Cascade::recommended(),
        FAST,
    )
    .unwrap();

    // Two shares (below threshold) reconstruct the WRONG secret → open fails.
    let two = factor_from_shares(&shares[..2], "master password");
    assert!(
        container::open(&bytes, &two).is_err(),
        "a below-threshold subset opened the vault"
    );

    // Three shares (at threshold) → opens.
    let three = factor_from_shares(&shares[..3], "master password");
    assert!(container::open(&bytes, &three).is_ok());
}

#[test]
fn shares_survive_files_and_hex_before_opening() {
    // Simulate: shares saved to files / printed as hex, then reloaded to unlock.
    let secret = cerberus_core::random::vec(32).unwrap();
    let shares = shamir::split(&secret, 2, 3).unwrap();

    let create_factors = FactorSet::new()
        .with(Factor::Password(Zeroizing::new("master password".into())))
        .with(Factor::Keyfile(Zeroizing::new(secret)));
    let bytes =
        container::seal(&sample_vault(), &create_factors, Cascade::paranoid(), FAST).unwrap();

    // Share 0 goes through the binary file format, share 1 through paper hex.
    let file_bytes = shares[0].to_bytes(2, 3);
    let (from_file, _, _) = Share::from_bytes(&file_bytes).unwrap();

    let hex = shares[1].to_hex(2, 3);
    let (from_hex, _, _) = Share::from_hex(&hex).unwrap();

    let factors = factor_from_shares(&[from_file, from_hex], "master password");
    let (vault, _) = container::open(&bytes, &factors).unwrap();
    assert_eq!(vault.entries[0].password, "the-actual-secret");
}
