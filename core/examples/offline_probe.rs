//! Bounded offline audit probe for an existing vault.
//!
//! It deliberately reports no candidate and no vault content: only whether
//! one of the bounded candidate sets succeeded, its ordinal and elapsed time.

use std::time::Instant;

use cerberus_core::container;
use cerberus_core::factors::{Factor, FactorSet, Pattern};
use zeroize::Zeroizing;

fn try_set(file: &[u8], set: FactorSet) -> bool {
    container::open(file, &set).is_ok()
}

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: offline_probe <vault> <passwords|patterns> [limit]");
        std::process::exit(2);
    };
    let mode = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "passwords".into());
    let limit = std::env::args()
        .nth(3)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(usize::MAX);
    let skip = std::env::args()
        .nth(4)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let file = std::fs::read(path).expect("cannot read vault");
    let start = Instant::now();
    let mut attempts = 0usize;

    let success = if mode == "passwords" {
        // Bounded, generic high-frequency candidates. Values are intentionally
        // never printed, including on success.
        let candidates = [
            "password",
            "password1",
            "password123",
            "12345678",
            "123456789",
            "1234567890",
            "qwerty123",
            "qwertyuiop",
            "azertyuiop",
            "azerty123",
            "iloveyou",
            "sunshine",
            "princess",
            "football",
            "monkey123",
            "dragon123",
            "admin123",
            "welcome1",
            "letmein1",
            "trustno1",
            "Password1",
            "Password123",
            "P@ssw0rd",
            "P@ssw0rd123",
        ];
        let mut found = false;
        for candidate in candidates.into_iter().skip(skip).take(limit) {
            attempts += 1;
            let set = FactorSet::new().with(Factor::Password(Zeroizing::new(candidate.into())));
            if try_set(&file, set) {
                found = true;
                break;
            }
        }
        found
    } else if mode == "patterns" {
        let mut candidates: Vec<(u8, Vec<u8>)> = Vec::new();
        for size in [6u8, 7, 8] {
            let n = size as usize;
            // Rows and columns in both directions, with enough points to clear
            // the backend's theoretical 55-bit threshold.
            let take = 12usize.min(n * n);
            candidates.push((size, (0..take as u8).collect()));
            candidates.push((size, (0..take as u8).rev().collect()));
            let col: Vec<u8> = (0..take).map(|i| ((i % n) * n + i / n) as u8).collect();
            candidates.push((size, col.clone()));
            candidates.push((size, col.into_iter().rev().collect()));
            let snake: Vec<u8> = (0..n * n)
                .flat_map(|r| {
                    let row: Vec<u8> = if r % 2 == 0 {
                        (0..n).map(|c| (r * n + c) as u8).collect()
                    } else {
                        (0..n).rev().map(|c| (r * n + c) as u8).collect()
                    };
                    row
                })
                .take(take)
                .collect();
            candidates.push((size, snake));
        }
        // Common human-drawn families not covered by straight/raster/snake
        // filters: a Z, an outer spiral, a cross-like stroke and a heart-like
        // symmetric outline. They are deliberately generic and never printed.
        candidates.extend([
            (8, vec![0, 1, 2, 3, 4, 5, 6, 7, 14, 21, 28, 35]),
            (8, vec![0, 1, 2, 3, 4, 5, 6, 7, 15, 23, 31, 39]),
            (8, vec![3, 11, 19, 27, 35, 34, 33, 32, 40, 48, 56, 57]),
            (8, vec![17, 10, 3, 12, 21, 30, 23, 16, 24, 33, 42, 51]),
        ]);
        let mut found = false;
        for (size, points) in candidates.into_iter().skip(skip).take(limit) {
            let Ok(pattern) = Pattern::new(size, points) else {
                continue;
            };
            let set = FactorSet::new().with(Factor::Pattern(pattern));
            if set.validate().is_err() {
                continue;
            }
            attempts += 1;
            if try_set(&file, set) {
                found = true;
                break;
            }
        }
        found
    } else {
        eprintln!("unknown mode");
        std::process::exit(2);
    };

    println!(
        "success={success} attempts={attempts} elapsed_ms={}",
        start.elapsed().as_millis()
    );
}
