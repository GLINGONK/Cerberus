//! Randomness.
//!
//! Every random byte in Cerberus originates from the operating system CSPRNG
//! (`BCryptGenRandom` on Windows). User-supplied entropy is only ever *mixed in*,
//! never substituted: the output is at least as strong as the OS source even if
//! the extra entropy is empty or attacker-controlled.

use crate::error::{CoreError, Result};
use zeroize::Zeroize;

/// Fill `buf` with cryptographically secure random bytes from the OS.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| CoreError::Random(e.to_string()))
}

/// Return `N` cryptographically secure random bytes.
pub fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

/// Return a `Vec` of `n` cryptographically secure random bytes.
pub fn vec(n: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    fill(&mut out)?;
    Ok(out)
}

/// Accumulates optional user entropy (mouse movement, timing jitter) that is
/// folded into the OS CSPRNG output.
///
/// This can only ever *add* uncertainty. `BLAKE3(os_random ‖ pool)` is at least
/// as unpredictable as `os_random` alone, so a hostile or empty pool is harmless.
#[derive(Default)]
pub struct EntropyPool {
    pool: Vec<u8>,
}

impl EntropyPool {
    pub fn new() -> Self {
        Self::default()
    }

    /// Absorb an arbitrary observation (cursor coordinates, nanosecond timestamps…).
    ///
    /// The pool is compressed once it grows past 4 KiB so it cannot grow without bound.
    pub fn absorb(&mut self, sample: &[u8]) {
        self.pool.extend_from_slice(sample);
        if self.pool.len() > 4096 {
            let digest = blake3::hash(&self.pool);
            self.pool.zeroize();
            self.pool.clear();
            self.pool.extend_from_slice(digest.as_bytes());
        }
    }

    /// Bits of entropy conservatively credited to the pool, for UI display only.
    ///
    /// Deliberately pessimistic (2 bits per sampled byte) and never used to decide
    /// whether output is safe — that guarantee comes from the OS CSPRNG.
    pub fn estimated_bits(&self) -> usize {
        (self.pool.len() * 2).min(256)
    }

    /// Produce `n` random bytes from the OS CSPRNG, hardened with the pool.
    pub fn random(&self, n: usize) -> Result<Vec<u8>> {
        let mut seed = [0u8; 64];
        fill(&mut seed)?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"cerberus/v1/rng");
        hasher.update(&seed);
        hasher.update(&self.pool);
        seed.zeroize();

        let mut out = vec![0u8; n];
        hasher.finalize_xof().fill(&mut out);
        Ok(out)
    }
}

impl Drop for EntropyPool {
    fn drop(&mut self) {
        self.pool.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_random_is_not_constant() {
        let a = bytes::<32>().unwrap();
        let b = bytes::<32>().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_pool_still_yields_fresh_bytes() {
        let pool = EntropyPool::new();
        assert_ne!(pool.random(32).unwrap(), pool.random(32).unwrap());
    }

    #[test]
    fn hostile_pool_cannot_fix_the_output() {
        let mut pool = EntropyPool::new();
        pool.absorb(&[0u8; 512]);
        assert_ne!(pool.random(32).unwrap(), pool.random(32).unwrap());
    }

    #[test]
    fn pool_stays_bounded() {
        let mut pool = EntropyPool::new();
        for _ in 0..1000 {
            pool.absorb(&[7u8; 64]);
        }
        assert!(pool.pool.len() <= 4096);
    }
}
