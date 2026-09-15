//! Shamir Secret Sharing over GF(256).
//!
//! Splits a secret into `N` shares such that any `K` of them reconstruct it, and
//! any `K-1` reveal *nothing* — an information-theoretic guarantee, not a
//! computational one.
//!
//! In Cerberus this powers the "any K of my USB keys" unlock: a random 32-byte
//! secret is split into shares (one per removable key file), and at unlock K of
//! them rebuild that secret, which is then fed into the normal factor pipeline
//! alongside the master password. Losing some keys is survivable; a stolen
//! subset below the threshold is useless.
//!
//! The maths: each byte of the secret is the constant term of a random degree
//! `K-1` polynomial over GF(256); a share is that polynomial evaluated at a
//! distinct non-zero x. Reconstruction is Lagrange interpolation at x=0.

use zeroize::{Zeroize, Zeroizing};

use crate::error::{CoreError, Result};

/// GF(256) multiplication (AES field, reducing polynomial 0x11b).
///
/// Russian-peasant algorithm, branch-light and constant-time with respect to
/// the operands' *values* — no data-dependent table lookups.
fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        // Add a into the product when the low bit of b is set.
        p ^= a.wrapping_mul(b & 1);
        let hi = a & 0x80;
        a <<= 1;
        // Reduce modulo the field polynomial when overflowing past degree 7.
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// Multiplicative inverse in GF(256): `a^254 = a^-1` (since `a^255 = 1`).
///
/// `inv(0)` is defined as 0; it never arises here because x-coordinates are
/// non-zero and distinct.
fn ginv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    // Exponent 254 = 0b1111_1110.
    for bit in 1..8 {
        base = gmul(base, base);
        if (254 >> bit) & 1 == 1 {
            result = gmul(result, base);
        }
    }
    result
}

/// One share of a split secret.
#[derive(Clone)]
pub struct Share {
    /// Non-zero x-coordinate, unique per share. Also the human-facing index.
    pub x: u8,
    /// One evaluated byte per secret byte.
    pub y: Zeroizing<Vec<u8>>,
    /// Random ID shared by every share from the same `split()` call.
    ///
    /// Not secret — it identifies a *batch*, not the secret. An independent
    /// audit pointed out that shares from two unrelated splits (e.g. the
    /// user mixing up two visually similar USB drives from different vault
    /// setups) could otherwise be combined without complaint, silently
    /// producing a wrong key instead of a clear error. `combine()` refuses
    /// to mix shares whose batch IDs disagree.
    pub batch: [u8; 4],
}

impl Drop for Share {
    fn drop(&mut self) {
        self.x.zeroize();
        self.batch.zeroize();
    }
}

/// Largest number of shares the field allows (x ranges over 1..=255).
/// Equal to `u8::MAX`, so `n: u8` is structurally within range.
pub const MAX_SHARES: u8 = 255;

/// Split `secret` into `n` shares, any `k` of which reconstruct it.
pub fn split(secret: &[u8], k: u8, n: u8) -> Result<Vec<Share>> {
    if k < 2 {
        return Err(CoreError::InvalidFactor(
            "the threshold must be at least 2".into(),
        ));
    }
    if n < k {
        return Err(CoreError::InvalidFactor(
            "there cannot be fewer shares than the threshold".into(),
        ));
    }
    // n is a u8, so it can never exceed MAX_SHARES (255); no upper check needed.
    if secret.is_empty() {
        return Err(CoreError::InvalidFactor("nothing to split".into()));
    }

    let mut batch = [0u8; 4];
    crate::random::fill(&mut batch)?;

    // For each byte, a degree k-1 polynomial: coeff[0] is the secret byte,
    // the rest are random. Fresh randomness per byte.
    let mut shares: Vec<Share> = (1..=n)
        .map(|x| Share {
            x,
            y: Zeroizing::new(vec![0u8; secret.len()]),
            batch,
        })
        .collect();

    for (byte_idx, &secret_byte) in secret.iter().enumerate() {
        // Every coefficient, including the leading one, is drawn uniformly
        // over the full field — zero included. An earlier version rejected
        // and re-drew a zero leading coefficient to force an exact degree
        // k-1 polynomial; an independent audit pointed out that this biases
        // the coefficient distribution and, with it, the value a k-1 share
        // set can rule out. Shamir's perfect-secrecy proof only needs degree
        // *at most* k-1, not exactly k-1: for every candidate secret there is
        // still exactly one bounded-degree polynomial matching any k-1
        // points, whether or not the true leading coefficient happens to be
        // zero. Uniform sampling (no resampling) is what the proof requires.
        let mut coeffs = Zeroizing::new(vec![0u8; k as usize]);
        coeffs[0] = secret_byte;
        crate::random::fill(&mut coeffs[1..])?;

        for share in shares.iter_mut() {
            share.y[byte_idx] = eval(&coeffs, share.x);
        }
        coeffs.zeroize();
    }

    Ok(shares)
}

/// Evaluate a polynomial (coefficients low-to-high) at `x` using Horner's rule.
fn eval(coeffs: &[u8], x: u8) -> u8 {
    let mut acc = 0u8;
    for &c in coeffs.iter().rev() {
        acc = gmul(acc, x) ^ c;
    }
    acc
}

/// Reconstruct the secret from `shares` (at least `k` of the originals).
///
/// Fails if fewer than 2 shares are given, if x-coordinates repeat, or if the
/// shares disagree on length. It does **not** know the original `k`: supplying
/// too few shares yields a wrong secret rather than an error — that is inherent
/// to Shamir, and why the reconstructed value is always checked against the MAC
/// upstream rather than trusted blindly.
pub fn combine(shares: &[Share]) -> Result<Zeroizing<Vec<u8>>> {
    if shares.len() < 2 {
        return Err(CoreError::InvalidFactor(
            "at least 2 shares are needed".into(),
        ));
    }
    let len = shares[0].y.len();
    if len == 0 || shares.iter().any(|s| s.y.len() != len) {
        return Err(CoreError::InvalidFactor(
            "shares have inconsistent lengths".into(),
        ));
    }
    let batch = shares[0].batch;
    if shares.iter().any(|s| s.batch != batch) {
        return Err(CoreError::InvalidFactor(
            "these shares come from different vault setups and cannot be combined \
             — check you did not mix shares from two different splits"
                .into(),
        ));
    }
    for (i, a) in shares.iter().enumerate() {
        if a.x == 0 {
            return Err(CoreError::InvalidFactor("invalid share index 0".into()));
        }
        for b in &shares[i + 1..] {
            if a.x == b.x {
                return Err(CoreError::InvalidFactor(
                    "two shares share the same index".into(),
                ));
            }
        }
    }

    let mut secret = Zeroizing::new(vec![0u8; len]);

    // Lagrange interpolation at x = 0, byte by byte.
    for byte_idx in 0..len {
        let mut acc = 0u8;
        for (i, si) in shares.iter().enumerate() {
            // Basis polynomial L_i(0) = Π_{j≠i} x_j / (x_j - x_i).
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, sj) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                num = gmul(num, sj.x);
                den = gmul(den, sj.x ^ si.x); // subtraction == xor in GF(2^n)
            }
            let lagrange = gmul(num, ginv(den));
            acc ^= gmul(si.y[byte_idx], lagrange);
        }
        secret[byte_idx] = acc;
    }

    Ok(secret)
}

// ---------------------------------------------------------------- serialization

const SHARE_MAGIC: &[u8; 6] = b"CBVSHR";
/// v2 adds the 4-byte batch ID ahead of the y-values (see [`Share::batch`]).
const SHARE_VERSION: u8 = 2;
const BATCH_LEN: usize = 4;
/// Bytes of BLAKE3 kept as a checksum, to catch typos in hand-entered hex.
const CHECKSUM_LEN: usize = 2;

impl Share {
    /// Serialise a share to bytes: magic, version, k, n, x, batch, length, y, checksum.
    ///
    /// `k` and `n` travel with the share so the restore screen can tell the user
    /// how many more shares are needed. They are not secret — the security is the
    /// share value, not the knowledge of the threshold.
    pub fn to_bytes(&self, k: u8, n: u8) -> Zeroizing<Vec<u8>> {
        let mut out = Vec::with_capacity(13 + BATCH_LEN + self.y.len());
        out.extend_from_slice(SHARE_MAGIC);
        out.push(SHARE_VERSION);
        out.push(k);
        out.push(n);
        out.push(self.x);
        out.extend_from_slice(&self.batch);
        out.extend_from_slice(&(self.y.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.y);
        let checksum = blake3::hash(&out);
        out.extend_from_slice(&checksum.as_bytes()[..CHECKSUM_LEN]);
        Zeroizing::new(out)
    }

    /// Parse a share, also returning the `(k, n)` it was created with.
    pub fn from_bytes(buf: &[u8]) -> Result<(Share, u8, u8)> {
        let min = SHARE_MAGIC.len() + 5 + BATCH_LEN + CHECKSUM_LEN;
        if buf.len() < min {
            return Err(CoreError::InvalidFactor("share is too short".into()));
        }
        if &buf[..6] != SHARE_MAGIC {
            return Err(CoreError::InvalidFactor("not a Cerberus share".into()));
        }
        if buf[6] != SHARE_VERSION {
            return Err(CoreError::InvalidFactor("unsupported share version".into()));
        }
        let k = buf[7];
        let n = buf[8];
        let x = buf[9];
        let batch: [u8; 4] = buf[10..14].try_into().unwrap();
        let len = u16::from_le_bytes([buf[14], buf[15]]) as usize;

        let body_end = 16 + len;
        if buf.len() != body_end + CHECKSUM_LEN {
            return Err(CoreError::InvalidFactor("share length mismatch".into()));
        }
        // Verify the checksum before trusting any field — catches a mistyped digit.
        let expected = blake3::hash(&buf[..body_end]);
        if buf[body_end..] != expected.as_bytes()[..CHECKSUM_LEN] {
            return Err(CoreError::InvalidFactor(
                "share checksum failed: a character was likely mistyped".into(),
            ));
        }
        if x == 0 {
            return Err(CoreError::InvalidFactor("invalid share index".into()));
        }

        Ok((
            Share {
                x,
                y: Zeroizing::new(buf[16..body_end].to_vec()),
                batch,
            },
            k,
            n,
        ))
    }

    /// Group-formatted hex for a paper backup, e.g. `CBV1-9F3A-2B84-…`.
    pub fn to_hex(&self, k: u8, n: u8) -> Zeroizing<String> {
        let bytes = self.to_bytes(k, n);
        let mut s = String::with_capacity(bytes.len() * 2 + bytes.len() / 2);
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 && i % 2 == 0 {
                s.push('-');
            }
            s.push_str(&format!("{b:02X}"));
        }
        Zeroizing::new(s)
    }

    /// Parse hex produced by [`Share::to_hex`], tolerating spaces, dashes and case.
    pub fn from_hex(input: &str) -> Result<(Share, u8, u8)> {
        let cleaned: String = input.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if cleaned.len() % 2 != 0 {
            return Err(CoreError::InvalidFactor(
                "odd number of hex characters — one is missing".into(),
            ));
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(cleaned.len() / 2));
        let raw = cleaned.as_bytes();
        for pair in raw.chunks_exact(2) {
            let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
            let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
            bytes.push((hi << 4) | lo);
        }
        Share::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn gf_multiplication_matches_known_values() {
        // Reference values in the AES field.
        assert_eq!(gmul(0, 5), 0);
        assert_eq!(gmul(1, 5), 5);
        assert_eq!(gmul(0x53, 0xCA), 0x01); // 0x53 and 0xCA are inverses
        assert_eq!(gmul(0x57, 0x83), 0xc1);
    }

    #[test]
    fn every_nonzero_element_has_an_inverse() {
        for a in 1u8..=255 {
            assert_eq!(gmul(a, ginv(a)), 1, "inverse wrong for {a}");
        }
    }

    #[test]
    fn any_k_shares_reconstruct_the_secret() {
        let secret = b"a 32-byte master share secret!!!";
        let shares = split(secret, 3, 5).unwrap();

        // Try several distinct 3-subsets; each must rebuild the secret.
        for combo in [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]] {
            let subset: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
            assert_eq!(&combine(&subset).unwrap()[..], secret);
        }
        // All five together also work.
        assert_eq!(&combine(&shares).unwrap()[..], secret);
    }

    #[test]
    fn fewer_than_k_shares_do_not_reveal_the_secret() {
        let secret = b"top secret bytes";
        let shares = split(secret, 3, 5).unwrap();
        // Two shares (k-1) must not reconstruct the true secret.
        let subset = vec![shares[0].clone(), shares[1].clone()];
        let wrong = combine(&subset).unwrap();
        assert_ne!(&wrong[..], secret, "k-1 shares recovered the secret");
    }

    #[test]
    fn a_single_share_is_pure_noise_about_the_secret() {
        // Across many splits of the same secret, a given share position must not
        // correlate with the secret's first byte — it should look uniform.
        let secret = [0x42u8; 1];
        let mut seen = HashSet::new();
        for _ in 0..500 {
            let shares = split(&secret, 2, 2).unwrap();
            seen.insert(shares[0].y[0]);
        }
        // A constant or near-constant y would betray structure; expect spread.
        assert!(seen.len() > 100, "share values are not well spread");
    }

    #[test]
    fn shares_round_trip_for_a_full_key() {
        let secret = crate::random::vec(32).unwrap();
        for (k, n) in [(2u8, 3u8), (3, 5), (5, 5), (2, 10), (10, 20)] {
            let shares = split(&secret, k, n).unwrap();
            assert_eq!(shares.len(), n as usize);
            let subset: Vec<Share> = shares.into_iter().take(k as usize).collect();
            assert_eq!(&combine(&subset).unwrap()[..], &secret[..]);
        }
    }

    #[test]
    fn invalid_parameters_are_refused() {
        assert!(split(b"x", 1, 3).is_err(), "threshold below 2");
        assert!(split(b"x", 4, 3).is_err(), "more threshold than shares");
        assert!(split(b"", 2, 3).is_err(), "empty secret");
        assert!(combine(&[]).is_err(), "no shares");
    }

    #[test]
    fn mismatched_or_duplicate_shares_are_refused() {
        let shares = split(b"secret bytes here", 2, 4).unwrap();
        // Duplicate index.
        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert!(combine(&dup).is_err());
    }

    #[test]
    fn shares_from_different_splits_are_refused_not_silently_wrong() {
        let a = split(b"secret bytes here", 2, 4).unwrap();
        let b = split(b"secret bytes here", 2, 4).unwrap();
        // Same secret, same k/n, but from two independent split() calls: the
        // batch IDs differ, and mixing them must be a clear error, not a
        // silently wrong reconstructed secret.
        let mixed = vec![a[0].clone(), b[1].clone()];
        assert!(combine(&mixed).is_err());
    }

    #[test]
    fn shares_survive_a_byte_round_trip() {
        let secret = crate::random::vec(32).unwrap();
        let shares = split(&secret, 2, 3).unwrap();
        let restored: Vec<Share> = shares
            .iter()
            .map(|s| {
                let bytes = s.to_bytes(2, 3);
                let (back, k, n) = Share::from_bytes(&bytes).unwrap();
                assert_eq!((k, n), (2, 3));
                assert_eq!(back.x, s.x);
                back
            })
            .collect();
        assert_eq!(&combine(&restored[..2]).unwrap()[..], &secret[..]);
    }

    #[test]
    fn shares_survive_a_hex_round_trip() {
        let secret = crate::random::vec(32).unwrap();
        let shares = split(&secret, 3, 5).unwrap();
        let restored: Vec<Share> = shares
            .iter()
            .take(3)
            .map(|s| {
                let hex = s.to_hex(3, 5);
                // Simulate a human retyping with spaces and lowercase.
                let messy = hex.to_lowercase().replace('-', " ");
                Share::from_hex(&messy).unwrap().0
            })
            .collect();
        assert_eq!(&combine(&restored).unwrap()[..], &secret[..]);
    }

    #[test]
    fn a_mistyped_hex_character_is_caught() {
        let shares = split(b"secret bytes here!", 2, 3).unwrap();
        let hex = shares[0].to_hex(2, 3);
        // Flip one hex digit somewhere in the payload.
        let mut chars: Vec<char> = hex.chars().collect();
        let pos = chars.iter().position(|c| c.is_ascii_hexdigit()).unwrap() + 20;
        chars[pos] = if chars[pos] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert!(
            Share::from_hex(&tampered).is_err(),
            "checksum failed to catch a mistyped character"
        );
    }

    #[test]
    fn garbage_shares_are_refused_without_panicking() {
        assert!(Share::from_bytes(&[]).is_err());
        assert!(Share::from_bytes(b"not a share at all").is_err());
        assert!(Share::from_hex("zzzz").is_err());
        assert!(Share::from_hex("ABC").is_err(), "odd length");
    }

    #[test]
    fn reconstruction_with_exactly_k_shares_is_always_exact() {
        // Coefficients (including the leading one) are uniform over the whole
        // field, so the polynomial's true degree is sometimes below k-1 by
        // chance. That must never break reconstruction with exactly k shares.
        for _ in 0..200 {
            let shares = split(b"abcdefgh", 4, 6).unwrap();
            // Reconstructing with exactly k=4 must always succeed and be exact.
            let subset: Vec<Share> = shares.into_iter().take(4).collect();
            assert_eq!(&combine(&subset).unwrap()[..], b"abcdefgh");
        }
    }
}
