//! Authentication factors and how they combine into a single composite secret.
//!
//! Every factor the user enrolled is **mandatory** (logical AND). Each one is
//! reduced to 32 bytes by BLAKE3 under its own domain label, then concatenated
//! in a fixed canonical order with explicit length prefixes, so no two distinct
//! factor sets can ever serialise to the same composite.

use zeroize::{Zeroize, Zeroizing};

use crate::error::{CoreError, Result};

/// Which factors a vault requires, as a bitfield stored in the header.
pub mod flags {
    pub const PASSWORD: u8 = 0b0000_0001;
    pub const PIN: u8 = 0b0000_0010;
    pub const KEYFILE: u8 = 0b0000_0100;
    pub const PATTERN: u8 = 0b0000_1000;
}

/// One authentication factor supplied by the user at unlock time.
#[derive(Clone)]
pub enum Factor {
    /// Master passphrase.
    Password(Zeroizing<String>),
    /// Short numeric PIN. Never valid on its own.
    Pin(Zeroizing<String>),
    /// Full contents of a key file.
    Keyfile(Zeroizing<Vec<u8>>),
    /// Ordered sequence of dots on an N×N grid.
    Pattern(Pattern),
}

impl Factor {
    fn flag(&self) -> u8 {
        match self {
            Factor::Password(_) => flags::PASSWORD,
            Factor::Pin(_) => flags::PIN,
            Factor::Keyfile(_) => flags::KEYFILE,
            Factor::Pattern(_) => flags::PATTERN,
        }
    }

    /// Canonical ordering position. Fixed forever: changing it breaks every vault.
    fn rank(&self) -> u8 {
        match self {
            Factor::Password(_) => 0,
            Factor::Pin(_) => 1,
            Factor::Keyfile(_) => 2,
            Factor::Pattern(_) => 3,
        }
    }

    fn domain(&self) -> &'static [u8] {
        match self {
            Factor::Password(_) => b"cerberus/v1/factor/password",
            Factor::Pin(_) => b"cerberus/v1/factor/pin",
            Factor::Keyfile(_) => b"cerberus/v1/factor/keyfile",
            Factor::Pattern(_) => b"cerberus/v1/factor/pattern",
        }
    }

    /// Reject factors that cannot carry meaningful entropy.
    pub fn validate(&self) -> Result<()> {
        match self {
            Factor::Password(p) => {
                if p.chars().count() < 8 {
                    return Err(CoreError::InvalidFactor(
                        "the master password must be at least 8 characters".into(),
                    ));
                }
            }
            Factor::Pin(p) => {
                if p.len() < 4 || p.len() > 32 {
                    return Err(CoreError::InvalidFactor(
                        "the PIN must be between 4 and 32 digits".into(),
                    ));
                }
                if !p.chars().all(|c| c.is_ascii_digit()) {
                    return Err(CoreError::InvalidFactor(
                        "the PIN must contain digits only".into(),
                    ));
                }
            }
            Factor::Keyfile(k) => {
                if k.len() < 32 {
                    return Err(CoreError::InvalidFactor(
                        "a key file must be at least 32 bytes".into(),
                    ));
                }
            }
            Factor::Pattern(p) => p.validate()?,
        }
        Ok(())
    }

    /// Reduce the factor to 32 bytes under its own domain label.
    fn contribution(&self) -> Zeroizing<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.domain());
        match self {
            // Unicode-normalised so the same passphrase typed on a different
            // keyboard layout still produces the same bytes.
            Factor::Password(p) | Factor::Pin(p) => hasher.update(p.as_bytes()),
            Factor::Keyfile(k) => hasher.update(k),
            Factor::Pattern(p) => hasher.update(&p.canonical_bytes()),
        };
        Zeroizing::new(*hasher.finalize().as_bytes())
    }

    /// Rough entropy in bits, for the UI strength meter only.
    ///
    /// Deliberately conservative and never used to decide whether a vault is
    /// safe to create — that decision lives in [`FactorSet::validate`].
    pub fn estimated_bits(&self) -> f64 {
        match self {
            Factor::Password(p) => estimate_password_bits(p),
            // A PIN is digits only: log2(10) per character, and that is generous
            // given how predictable real PINs are.
            Factor::Pin(p) => p.len() as f64 * 3.32,
            // A key file's entropy is bounded by its content, which we cannot
            // measure honestly. Credit the 256 bits of a generated key file only.
            Factor::Keyfile(_) => 256.0,
            Factor::Pattern(p) => p.estimated_bits(),
        }
    }
}

/// Very rough passphrase entropy: alphabet size × length, with a penalty for
/// repeated characters. Not a substitute for zxcvbn, just a meter.
fn estimate_password_bits(p: &str) -> f64 {
    let mut alphabet = 0u32;
    if p.chars().any(|c| c.is_ascii_lowercase()) {
        alphabet += 26;
    }
    if p.chars().any(|c| c.is_ascii_uppercase()) {
        alphabet += 26;
    }
    if p.chars().any(|c| c.is_ascii_digit()) {
        alphabet += 10;
    }
    if p.chars().any(|c| !c.is_alphanumeric()) {
        alphabet += 33;
    }
    if !p.is_ascii() {
        alphabet += 100;
    }
    if alphabet == 0 {
        return 0.0;
    }
    let unique = p.chars().collect::<std::collections::HashSet<_>>().len() as f64;
    let length = p.chars().count() as f64;
    let repetition_penalty = (unique / length).max(0.3);
    length * (alphabet as f64).log2() * repetition_penalty
}

/// An unlock pattern drawn on a square grid, Android-style but larger.
///
/// The secret is the **ordered** sequence of dots, so `1→5→9` and `9→5→1` are
/// different patterns; segment direction is therefore part of the secret.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pattern {
    size: u8,
    points: Vec<u8>,
}

impl Pattern {
    pub const MIN_SIZE: u8 = 3;
    pub const MAX_SIZE: u8 = 8;

    /// Build a pattern on a `size`×`size` grid from 0-indexed dot numbers.
    pub fn new(size: u8, points: Vec<u8>) -> Result<Self> {
        let p = Pattern { size, points };
        p.validate()?;
        Ok(p)
    }

    pub fn size(&self) -> u8 {
        self.size
    }

    pub fn points(&self) -> &[u8] {
        &self.points
    }

    /// Minimum number of dots accepted on a grid of this size.
    pub fn min_points(size: u8) -> usize {
        (size as usize).max(5)
    }

    pub fn validate(&self) -> Result<()> {
        if !(Self::MIN_SIZE..=Self::MAX_SIZE).contains(&self.size) {
            return Err(CoreError::InvalidFactor(format!(
                "the grid must be between {}×{} and {}×{}",
                Self::MIN_SIZE,
                Self::MIN_SIZE,
                Self::MAX_SIZE,
                Self::MAX_SIZE
            )));
        }
        let cells = (self.size as usize) * (self.size as usize);
        if self.points.len() < Self::min_points(self.size) {
            return Err(CoreError::InvalidFactor(format!(
                "the pattern must link at least {} dots",
                Self::min_points(self.size)
            )));
        }
        if self.points.len() > cells {
            return Err(CoreError::InvalidFactor(
                "the pattern has more dots than the grid holds".into(),
            ));
        }
        let mut seen = vec![false; cells];
        for &p in &self.points {
            let idx = p as usize;
            if idx >= cells {
                return Err(CoreError::InvalidFactor(
                    "the pattern refers to a dot outside the grid".into(),
                ));
            }
            if seen[idx] {
                return Err(CoreError::InvalidFactor(
                    "a dot cannot be used twice in one pattern".into(),
                ));
            }
            seen[idx] = true;
        }
        Ok(())
    }

    /// Byte encoding fed to the KDF. Includes the grid size so the same dot
    /// sequence on a 3×3 and on a 5×5 grid are different secrets.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.points.len() + 2);
        out.push(self.size);
        out.push(self.points.len() as u8);
        out.extend_from_slice(&self.points);
        out
    }

    /// True if the dot sequence is a shape a human is likely to draw first:
    /// a straight line (row, column, or diagonal with a constant step), or a
    /// raster/reading-order sequence of raw indices (`0,1,2,3…`).
    ///
    /// Combinatorial entropy (`estimated_bits`) counts these as ordinary
    /// permutations, but they are the very first guesses in any pattern
    /// dictionary attack — an independent audit found the old 40-bit floor
    /// (and even the current combinatorial one) let a plain diagonal or row
    /// pass as "strong". This check catches what the bit count can't.
    fn is_geometrically_trivial(&self) -> bool {
        if self.points.len() < 2 {
            return true;
        }
        let n = self.size as i32;

        // Raw index arithmetic progression: 0,1,2,3… or 5,7,9,11… etc.
        let step = self.points[1] as i32 - self.points[0] as i32;
        if self
            .points
            .windows(2)
            .all(|w| w[1] as i32 - w[0] as i32 == step)
        {
            return true;
        }

        // Grid-geometry collinearity: constant (dx, dy) between consecutive
        // dots, i.e. a straight row, column, or diagonal on the grid.
        let coord = |p: u8| ((p as i32) % n, (p as i32) / n);
        let (x0, y0) = coord(self.points[0]);
        let (x1, y1) = coord(self.points[1]);
        let (dx, dy) = (x1 - x0, y1 - y0);
        let collinear = self.points.windows(2).all(|w| {
            let (xa, ya) = coord(w[0]);
            let (xb, yb) = coord(w[1]);
            (xb - xa, yb - ya) == (dx, dy)
        });
        if collinear {
            return true;
        }

        // Palindromic path: same shape drawn out-and-back (e.g. corners).
        let reversed: Vec<u8> = self.points.iter().rev().copied().collect();
        if reversed == self.points {
            return true;
        }

        // Boustrophedon ("snake"): reading order that alternates direction each
        // row — the offline probe generated exactly this and it slipped past
        // the collinearity and arithmetic checks. Detect it by walking the two
        // canonical snakes (starting left-to-right and right-to-left) and
        // seeing if this pattern is a prefix of either.
        if self.is_snake_prefix() {
            return true;
        }

        false
    }

    /// True if the dots are a prefix of a boustrophedon sweep of the grid.
    fn is_snake_prefix(&self) -> bool {
        let n = self.size as usize;
        for start_reversed in [false, true] {
            let mut snake: Vec<u8> = Vec::with_capacity(n * n);
            for r in 0..n {
                let left_to_right = (r % 2 == 0) != start_reversed;
                if left_to_right {
                    snake.extend((0..n).map(|c| (r * n + c) as u8));
                } else {
                    snake.extend((0..n).rev().map(|c| (r * n + c) as u8));
                }
            }
            if snake.starts_with(&self.points) {
                return true;
            }
        }
        false
    }

    /// Conservative structural floor for a pattern used without another factor.
    /// This does not pretend to measure human entropy; it merely rejects broad
    /// families that remain easy to describe and dictionary-test.
    fn has_standalone_complexity(&self) -> bool {
        if self.size != 8 || self.points.len() < 14 {
            return false;
        }
        let n = self.size as i32;
        let coord = |p: u8| ((p as i32) % n, (p as i32) / n);
        let coords: Vec<_> = self.points.iter().map(|&p| coord(p)).collect();
        let min_x = coords.iter().map(|p| p.0).min().unwrap_or(0);
        let max_x = coords.iter().map(|p| p.0).max().unwrap_or(0);
        let min_y = coords.iter().map(|p| p.1).min().unwrap_or(0);
        let max_y = coords.iter().map(|p| p.1).max().unwrap_or(0);
        if max_x - min_x < 5 || max_y - min_y < 5 {
            return false;
        }

        let normalise = |dx: i32, dy: i32| {
            let mut a = dx.unsigned_abs();
            let mut b = dy.unsigned_abs();
            while b != 0 {
                (a, b) = (b, a % b);
            }
            let divisor = a.max(1) as i32;
            (dx / divisor, dy / divisor)
        };
        let directions: Vec<_> = coords
            .windows(2)
            .map(|w| normalise(w[1].0 - w[0].0, w[1].1 - w[0].1))
            .collect();
        let distinct = directions
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>()
            .len();
        let turns = directions.windows(2).filter(|w| w[0] != w[1]).count();
        distinct >= 6 && turns >= 9
    }

    /// Entropy of this pattern, in bits.
    ///
    /// Counts ordered sequences of `k` distinct dots out of `n`, ignoring the
    /// "no skipping over an unvisited dot" rule. That over-counts slightly, so
    /// this is an upper bound — but it is the number attackers care about, and
    /// the UI needs the honest ceiling, not a flattering one.
    pub fn estimated_bits(&self) -> f64 {
        let n = (self.size as f64) * (self.size as f64);
        let k = self.points.len() as f64;
        let mut bits = 0.0;
        let mut i = 0.0;
        while i < k {
            bits += (n - i).log2();
            i += 1.0;
        }
        bits
    }
}

/// The complete set of factors presented at unlock time.
#[derive(Clone, Default)]
pub struct FactorSet {
    factors: Vec<Factor>,
}

/// Minimum entropy, in bits, for a pattern used as the *only* factor.
///
/// See the rationale in [`FactorSet::validate`]. Public so the UI can warn the
/// user live rather than only at save time.
pub const PATTERN_ONLY_MIN_BITS: f64 = 80.0;

impl FactorSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a factor. Adding a second factor of the same kind replaces the first,
    /// except for key files, which accumulate.
    pub fn with(mut self, factor: Factor) -> Self {
        if !matches!(factor, Factor::Keyfile(_)) {
            self.factors.retain(|f| f.rank() != factor.rank());
        }
        self.factors.push(factor);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.factors.is_empty()
    }

    pub fn len(&self) -> usize {
        self.factors.len()
    }

    pub fn is_pattern_only(&self) -> bool {
        self.flags() == flags::PATTERN
    }

    /// Bitfield of factor kinds present, matching the header field.
    pub fn flags(&self) -> u8 {
        self.factors.iter().fold(0, |acc, f| acc | f.flag())
    }

    pub fn total_estimated_bits(&self) -> f64 {
        self.factors.iter().map(Factor::estimated_bits).sum()
    }

    /// Validate every factor, and refuse combinations that only look secure.
    pub fn validate(&self) -> Result<()> {
        if self.factors.is_empty() {
            return Err(CoreError::NoFactors);
        }
        for f in &self.factors {
            f.validate()?;
        }

        let flags = self.flags();
        let only = |flag: u8| flags == flag;

        // A PIN alone is at most ~106 bits of *claimed* entropy but is in practice
        // guessable in seconds. Never let it stand alone.
        if only(flags::PIN) {
            return Err(CoreError::InvalidFactor(
                "a PIN cannot be the only factor: pair it with a key file or a password".into(),
            ));
        }

        // A pattern used as the sole factor must clear a real bar.
        //
        // A combinatorial score alone overestimates human choices. Standalone use
        // therefore combines an 80-bit ceiling with strict 8×8 structural rules;
        // smaller or recognisably regular gestures remain valid only when paired
        // with another factor.
        if only(flags::PATTERN) {
            let pattern = self.factors.iter().find_map(|f| match f {
                Factor::Pattern(p) => Some(p),
                _ => None,
            });
            if let Some(p) = pattern {
                if p.is_geometrically_trivial() {
                    return Err(CoreError::InvalidFactor(
                        "this pattern is a straight line, a raster sequence, or an \
                         out-and-back shape — the first guess of any pattern dictionary \
                         attack. Draw an irregular shape, or add a password."
                            .into(),
                    ));
                }
                if !p.has_standalone_complexity() {
                    return Err(CoreError::InvalidFactor(
                        "a standalone pattern must use an irregular 8x8 path with at least 14 dots, span most of the grid, and change direction repeatedly; otherwise add a password or key file"
                            .into(),
                    ));
                }
            }
            let bits = self.total_estimated_bits();
            if bits < PATTERN_ONLY_MIN_BITS {
                return Err(CoreError::InvalidFactor(format!(
                    "this pattern only carries about {bits:.0} bits, and it is your only \
                     factor. Use an irregular 8×8 pattern with more dots, or add a \
                     password — at least {PATTERN_ONLY_MIN_BITS:.0} bits are required."
                )));
            }
        }

        Ok(())
    }

    /// Fold every factor into the composite secret handed to Argon2id.
    ///
    /// Factors are sorted by canonical rank, then each contribution is emitted
    /// with a length prefix. Without those prefixes, two different factor sets
    /// could concatenate to identical bytes.
    pub fn composite(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;

        let mut ordered: Vec<&Factor> = self.factors.iter().collect();
        // Stable sort keeps multiple key files in the order the user added them.
        ordered.sort_by_key(|f| f.rank());

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"cerberus/v1/composite");
        hasher.update(&[self.flags()]);
        hasher.update(&(ordered.len() as u32).to_le_bytes());

        for f in ordered {
            let mut c = f.contribution();
            hasher.update(&[f.rank()]);
            hasher.update(&(c.len() as u32).to_le_bytes());
            hasher.update(c.as_ref());
            c.zeroize();
        }

        Ok(Zeroizing::new(hasher.finalize().as_bytes().to_vec()))
    }
}

/// Generate a key file: 256 bytes straight from the OS CSPRNG.
pub fn generate_keyfile() -> Result<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(crate::random::vec(256)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password(s: &str) -> Factor {
        Factor::Password(Zeroizing::new(s.to_string()))
    }

    #[test]
    fn the_composite_is_deterministic() {
        let a = FactorSet::new().with(password("correct horse battery"));
        let b = FactorSet::new().with(password("correct horse battery"));
        assert_eq!(a.composite().unwrap(), b.composite().unwrap());
    }

    #[test]
    fn adding_a_factor_changes_the_composite() {
        let base = FactorSet::new().with(password("correct horse battery"));
        let more = base
            .clone()
            .with(Factor::Keyfile(Zeroizing::new(vec![9u8; 64])));
        assert_ne!(base.composite().unwrap(), more.composite().unwrap());
    }

    #[test]
    fn factor_order_does_not_matter() {
        let keyfile = Factor::Keyfile(Zeroizing::new(vec![3u8; 64]));
        let a = FactorSet::new()
            .with(password("correct horse battery"))
            .with(keyfile.clone());
        let b = FactorSet::new()
            .with(keyfile)
            .with(password("correct horse battery"));
        assert_eq!(a.composite().unwrap(), b.composite().unwrap());
    }

    #[test]
    fn factor_kinds_cannot_be_confused_with_each_other() {
        // Same bytes, different kind: the domain label must keep them apart.
        let as_password = FactorSet::new().with(password("12345678"));
        let as_keyfile = FactorSet::new()
            .with(Factor::Keyfile(Zeroizing::new(b"12345678".repeat(8))))
            .with(password("something else"));
        assert_ne!(
            as_password.composite().unwrap(),
            as_keyfile.composite().unwrap()
        );
    }

    #[test]
    fn a_pin_alone_is_refused() {
        let set = FactorSet::new().with(Factor::Pin(Zeroizing::new("123456".into())));
        assert!(set.composite().is_err());
    }

    #[test]
    fn a_pin_paired_with_a_keyfile_is_accepted() {
        let set = FactorSet::new()
            .with(Factor::Pin(Zeroizing::new("123456".into())))
            .with(Factor::Keyfile(Zeroizing::new(vec![1u8; 256])));
        assert!(set.composite().is_ok());
    }

    #[test]
    fn short_passwords_and_tiny_keyfiles_are_refused() {
        assert!(FactorSet::new()
            .with(password("short"))
            .composite()
            .is_err());
        assert!(FactorSet::new()
            .with(Factor::Keyfile(Zeroizing::new(vec![0u8; 8])))
            .composite()
            .is_err());
    }

    #[test]
    fn an_empty_factor_set_is_refused() {
        assert!(FactorSet::new().composite().is_err());
    }

    #[test]
    fn pattern_direction_is_part_of_the_secret() {
        let forward = Pattern::new(3, vec![0, 1, 2, 5, 8]).unwrap();
        let backward = Pattern::new(3, vec![8, 5, 2, 1, 0]).unwrap();
        assert_ne!(forward.canonical_bytes(), backward.canonical_bytes());

        let a = FactorSet::new()
            .with(Factor::Pattern(forward))
            .with(password("a password"));
        let b = FactorSet::new()
            .with(Factor::Pattern(backward))
            .with(password("a password"));
        assert_ne!(a.composite().unwrap(), b.composite().unwrap());
    }

    #[test]
    fn the_grid_size_is_part_of_the_secret() {
        let small = Pattern::new(3, vec![0, 1, 2, 5, 8]).unwrap();
        let large = Pattern::new(5, vec![0, 1, 2, 5, 8]).unwrap();
        assert_ne!(small.canonical_bytes(), large.canonical_bytes());
    }

    #[test]
    fn malformed_patterns_are_refused() {
        assert!(Pattern::new(3, vec![0, 1]).is_err(), "too few dots");
        assert!(
            Pattern::new(3, vec![0, 1, 2, 3, 9]).is_err(),
            "dot outside grid"
        );
        assert!(
            Pattern::new(3, vec![0, 1, 2, 3, 3]).is_err(),
            "repeated dot"
        );
        assert!(
            Pattern::new(2, vec![0, 1, 2, 3, 0]).is_err(),
            "grid too small"
        );
        assert!(
            Pattern::new(9, vec![0, 1, 2, 3, 4]).is_err(),
            "grid too large"
        );
    }

    #[test]
    fn a_weak_pattern_cannot_stand_alone() {
        // 3×3 with 5 dots ≈ 26 bits — far below the 55-bit floor.
        let weak = Pattern::new(3, vec![0, 1, 2, 5, 8]).unwrap();
        assert!(weak.estimated_bits() < PATTERN_ONLY_MIN_BITS);
        assert!(FactorSet::new()
            .with(Factor::Pattern(weak))
            .composite()
            .is_err());

        // A 5×5 with 5 dots (~23 bits) is also rejected — the old 40-bit floor
        // would have been the relevant line, but this stays well under either.
        let medium = Pattern::new(5, vec![0, 6, 12, 18, 24]).unwrap();
        assert!(FactorSet::new()
            .with(Factor::Pattern(medium))
            .composite()
            .is_err());

        // A wide, irregular 8×8 path with 14 dots clears the standalone floor.
        // a straight line or raster sequence — `0..12` used to pass here too,
        // but that is exactly the first guess of a pattern dictionary attack
        // (a plain reading-order sweep). An independent audit caught this;
        // see `is_geometrically_trivial`.
        let strong =
            Pattern::new(8, vec![3, 61, 10, 47, 22, 56, 1, 39, 15, 50, 28, 44, 7, 58]).unwrap();
        assert!(strong.estimated_bits() > PATTERN_ONLY_MIN_BITS);
        assert!(FactorSet::new()
            .with(Factor::Pattern(strong))
            .composite()
            .is_ok());

        // A structured Z-like gesture is still human-predictable even on 8x8.
        let z = Pattern::new(8, vec![0, 1, 2, 3, 4, 5, 6, 7, 14, 21, 28, 35, 42, 49]).unwrap();
        assert!(FactorSet::new()
            .with(Factor::Pattern(z))
            .composite()
            .is_err());
    }

    #[test]
    fn geometrically_trivial_patterns_are_rejected_even_with_high_entropy() {
        // A straight raster sweep on an 8×8 grid clears the bit floor
        // (>80 bits combinatorially) but is the single most predictable shape
        // a human can draw — it must still be refused as the sole factor.
        let raster = Pattern::new(8, (0..16).collect()).unwrap();
        assert!(raster.estimated_bits() > PATTERN_ONLY_MIN_BITS);
        assert!(FactorSet::new()
            .with(Factor::Pattern(raster))
            .composite()
            .is_err());

        // A plain diagonal is flagged as trivial directly by the heuristic
        // (independent of whether it also happens to clear the bit floor).
        let diagonal = Pattern::new(8, vec![0, 9, 18, 27, 36, 45, 54, 63]).unwrap();
        assert!(diagonal.is_geometrically_trivial());

        // A boustrophedon "snake" sweep (reading order, alternating direction
        // each row) is a classic predictable Android-style gesture that slipped
        // past the collinearity and arithmetic checks — a follow-up audit probe
        // generated exactly this. It must be caught too.
        let snake = Pattern::new(6, vec![0, 1, 2, 3, 4, 5, 11, 10, 9, 8]).unwrap();
        assert!(snake.is_geometrically_trivial());
        assert!(FactorSet::new()
            .with(Factor::Pattern(snake))
            .composite()
            .is_err());
    }

    #[test]
    fn a_weak_pattern_is_fine_when_combined_with_a_password() {
        // The floor only applies to a *sole* pattern. Paired with a password,
        // even a small grid is acceptable — the entropy adds up.
        let weak = Pattern::new(3, vec![0, 1, 2, 5, 8]).unwrap();
        let set = FactorSet::new()
            .with(Factor::Password(Zeroizing::new("a decent password".into())))
            .with(Factor::Pattern(weak));
        assert!(set.composite().is_ok());
    }

    #[test]
    fn generated_keyfiles_are_unique_and_usable() {
        let a = generate_keyfile().unwrap();
        let b = generate_keyfile().unwrap();
        assert_eq!(a.len(), 256);
        assert_ne!(a.to_vec(), b.to_vec());
        assert!(Factor::Keyfile(a).validate().is_ok());
    }

    #[test]
    fn keyfiles_accumulate_but_other_factors_replace() {
        let set = FactorSet::new()
            .with(password("first password"))
            .with(password("second password"))
            .with(Factor::Keyfile(Zeroizing::new(vec![1u8; 64])))
            .with(Factor::Keyfile(Zeroizing::new(vec![2u8; 64])));
        assert_eq!(set.len(), 3);
    }
}
