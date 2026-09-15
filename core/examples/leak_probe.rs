//! Writes a real vault to disk and inspects the bytes for anything readable.
//!
//! The unit tests already assert this, but they do it on an in-memory buffer.
//! This example goes through the actual file-writing path — including the
//! backup copy and the temporary file — so it also catches a plaintext leak
//! that only happens on disk.
//!
//! ```bash
//! cargo run --release -p cerberus-core --example leak_probe -- <dossier>
//! ```

use cerberus_core::container;
use cerberus_core::factors::{Factor, FactorSet};
use cerberus_core::kdf::KdfParams;
use cerberus_core::vault::{CustomField, Entry, Vault};
use cerberus_core::Cascade;
use zeroize::Zeroizing;

/// Distinctive strings planted in the vault. If any survives to disk, the
/// encryption did not cover that field.
const CANARIES: [&str; 6] = [
    "CANARY-PASSWORD-7f3a91",
    "CANARY-USERNAME-b28e04",
    "CANARY-NOTES-5c1d77",
    "CANARY-TOTP-LABEL-e90f22",
    "CANARY-CUSTOM-a44b16",
    "CANARY-TITLE-19d3fe",
];

fn main() {
    let dir = std::env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&dir).expect("cannot create the probe directory");
    let path = dir.join("probe.cbv");

    let mut vault = Vault::new("probe");
    let root = vault.root;
    let mut entry = Entry::new(root, CANARIES[5]);
    entry.username = CANARIES[1].into();
    entry.password = CANARIES[0].into();
    entry.notes = CANARIES[2].into();
    entry.url = format!("https://{}.example", CANARIES[3]);
    entry.custom_fields = vec![CustomField {
        name: "secret".into(),
        value: CANARIES[4].into(),
        secret: true,
    }];
    vault.add_entry(entry).expect("cannot add the entry");

    let factors = FactorSet::new().with(Factor::Password(Zeroizing::new(
        "probe password for the audit".into(),
    )));

    // Two writes, so the backup path and the temp file are exercised too.
    for _ in 0..2 {
        container::write_to_file(
            &path,
            &vault,
            &factors,
            Cascade::paranoid(),
            KdfParams::INTERACTIVE,
        )
        .expect("cannot write the vault");
    }

    let mut leaks = Vec::new();
    let mut inspected = 0usize;

    for file in std::fs::read_dir(&dir)
        .expect("cannot list the directory")
        .flatten()
    {
        let bytes = match std::fs::read(file.path()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        inspected += 1;
        for canary in CANARIES {
            if bytes.windows(canary.len()).any(|w| w == canary.as_bytes()) {
                leaks.push(format!(
                    "{} contient {canary}",
                    file.file_name().to_string_lossy()
                ));
            }
        }
    }

    let sealed = std::fs::read(&path).expect("cannot read back the vault");
    let entropy = shannon_entropy(&sealed[80..sealed.len() - 64]);

    println!("  fields inspected : {inspected}");
    println!("  vault size       : {} bytes", sealed.len());
    println!("  payload entropy  : {entropy:.3} bits/byte (expected > 7.9)");

    if leaks.is_empty() && entropy > 7.9 {
        println!("  no leak detected");
    } else {
        for leak in &leaks {
            eprintln!("  LEAK: {leak}");
        }
        if entropy <= 7.9 {
            eprintln!("  LEAK: insufficient entropy, the ciphertext has structure");
        }
        std::process::exit(1);
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
