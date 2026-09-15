//! Key derivation: Argon2id for the expensive step, HKDF-SHA512 for the cheap
//! expansion into per-layer keys.
//!
//! Only Argon2id touches the user's secrets. Everything downstream expands the
//! resulting master key, so a single slow derivation covers the whole cascade
//! no matter how many layers it has.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CoreError, Result};

/// Length of the derived master key, in bytes.
pub const MASTER_KEY_LEN: usize = 64;

/// Length of the per-vault Argon2 salt, in bytes.
pub const SALT_LEN: usize = 32;

/// Argon2id cost parameters, stored in the vault header so the file stays openable.
///
/// These are public by necessity — an attacker learns how expensive the
/// derivation is, which tells them nothing useful about the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub time_cost: u32,
    /// Degree of parallelism.
    pub parallelism: u8,
}

impl KdfParams {
    /// ~0.5 s on a modern desktop. For contexts where the vault unlocks often.
    pub const INTERACTIVE: KdfParams = KdfParams {
        memory_kib: 256 * 1024,
        time_cost: 3,
        parallelism: 4,
    };

    /// ~2 s. The default: 1 GiB of memory makes GPU and ASIC attacks expensive.
    pub const HARDENED: KdfParams = KdfParams {
        memory_kib: 1024 * 1024,
        time_cost: 4,
        parallelism: 4,
    };

    /// ~15 s and 4 GiB. For vaults that are opened rarely and matter a lot.
    pub const PARANOID: KdfParams = KdfParams {
        memory_kib: 4 * 1024 * 1024,
        time_cost: 8,
        parallelism: 8,
    };

    /// Reject parameters weaker than the OWASP minimum, or large enough to be a
    /// denial-of-service vector when read from an untrusted file.
    ///
    /// A tampered header could otherwise ask for a 1 GiB-per-thread allocation
    /// or drive the cost down to something brute-forceable.
    ///
    /// The ceilings track [`Self::PARANOID`] with a small margin, not a
    /// theoretical Argon2 maximum: an independent audit pointed out that the
    /// previous 8 GiB / 64-pass / 64-way ceiling let a hostile file rename
    /// itself to `.cbv` and stall the app on a huge, unauthenticated
    /// derivation (memory exhaustion, paging, or an OOM kill) before the MAC
    /// check ever gets a chance to reject it. Nothing legitimate needs more
    /// than paranoid-plus-headroom.
    pub fn validate(&self) -> Result<()> {
        if self.memory_kib < 19 * 1024 {
            return Err(CoreError::InvalidFactor(
                "Argon2 memory cost below the 19 MiB minimum".into(),
            ));
        }
        if self.memory_kib > Self::PARANOID.memory_kib {
            return Err(CoreError::InvalidFactor(
                "Argon2 memory cost above the 4 GiB ceiling".into(),
            ));
        }
        if self.time_cost < 2 || self.time_cost > Self::PARANOID.time_cost * 2 {
            return Err(CoreError::InvalidFactor(
                "Argon2 time cost outside the 2..=16 range".into(),
            ));
        }
        if self.parallelism == 0 || self.parallelism > Self::PARANOID.parallelism * 2 {
            return Err(CoreError::InvalidFactor(
                "Argon2 parallelism outside the 1..=16 range".into(),
            ));
        }
        Ok(())
    }

    fn to_argon2(self) -> Result<Argon2<'static>> {
        self.validate()?;
        let params = Params::new(
            self.memory_kib,
            self.time_cost,
            self.parallelism as u32,
            Some(MASTER_KEY_LEN),
        )
        .map_err(|_| CoreError::Kdf)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams::HARDENED
    }
}

/// Number of times `region::lock` has failed since process start.
///
/// An independent audit noted that lock failures were silently swallowed —
/// the key still worked, but with no anti-swap guarantee and no way for
/// anyone to notice. This makes that condition observable instead of mute.
static LOCK_FAILURES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many times a `MasterKey` allocation failed to lock into physical
/// memory since the process started. Non-zero means some key material may
/// have been eligible for paging. Exposed so the app layer can warn instead
/// of failing in complete silence.
pub fn memory_lock_failures() -> u64 {
    LOCK_FAILURES.load(std::sync::atomic::Ordering::Relaxed)
}

/// A derived master key.
///
/// The 64 key bytes live in a heap box whose pages Cerberus *asks* the OS to
/// lock into physical memory (`VirtualLock` on Windows, `mlock` elsewhere,
/// via the `region` crate), so they are less likely to be written to the
/// page file, and the bytes are zeroized when dropped.
///
/// This is a **best-effort mitigation, not a guarantee**: an independent
/// audit correctly flagged the earlier wording as overclaiming. It does not
/// protect against hibernation (the whole RAM image is written to disk),
/// against a debugger or crash dump of this process, or against a page the
/// OS refuses to lock (working-set quota exhausted after many allocations).
/// It also only covers this 64-byte key buffer — the decrypted vault itself,
/// cloned passwords, and IPC payloads live in ordinary, unlocked allocations.
/// See `memory_lock_failures()` to detect when even this narrow guarantee
/// silently stopped holding.
///
/// `region` performs the platform `unsafe` internally, so this crate keeps its
/// `#![forbid(unsafe_code)]` guarantee.
pub struct MasterKey {
    key: Box<KeyPage>,
    /// The live page-lock. Held (not leaked) so it unlocks exactly this key's
    /// page when the key drops, instead of staying locked until the process
    /// exits. `None` if the OS refused the lock.
    guard: Option<region::LockGuard>,
}

/// The key bytes, forced onto their own dedicated OS page.
///
/// An independent audit flagged that the old design leaked the lock guard with
/// `mem::forget` — pages stayed locked for the whole process lifetime and could
/// slowly exhaust the lockable-page quota across many key clones. The reason for
/// the leak was that two 64-byte `Box`ed keys often landed on the same page, so
/// dropping one guard would unlock a page another key still relied on (and
/// `region` panics on a double unlock).
///
/// Aligning each key to a full page (`repr(align(4096))`, which also rounds the
/// size up to a page) guarantees no two keys ever share a page. With sharing
/// gone, each key can hold its guard and unlock its own page on drop — the
/// explicit lifecycle the audit asked for. 4096 is the standard page size on
/// the supported platforms; a larger OS page only means the lock rounds out to
/// it harmlessly, never a shared-page double unlock.
#[repr(align(4096))]
struct KeyPage([u8; MASTER_KEY_LEN]);

impl MasterKey {
    /// Wrap raw key bytes, locking their dedicated page into RAM.
    fn wrap(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        let key = Box::new(KeyPage(bytes));
        let guard = match region::lock(key.as_ref() as *const KeyPage, MASTER_KEY_LEN) {
            Ok(guard) => Some(guard),
            Err(_) => {
                LOCK_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                None
            }
        };
        MasterKey { key, guard }
    }

    /// A fresh, purely random key — never derived from a password.
    ///
    /// Used for the in-RAM re-sealing of an unlocked vault: it exists only to
    /// keep decrypted secrets out of continuously-resident plaintext, and dies
    /// with the process. It must never touch disk.
    pub fn random() -> Result<Self> {
        Ok(Self::wrap(crate::random::bytes::<MASTER_KEY_LEN>()?))
    }

    /// Run Argon2id over the composite of every authentication factor.
    pub fn derive(composite: &[u8], salt: &[u8], params: KdfParams) -> Result<Self> {
        if salt.len() != SALT_LEN {
            return Err(CoreError::Kdf);
        }
        let argon = params.to_argon2()?;
        let mut out = [0u8; MASTER_KEY_LEN];
        argon
            .hash_password_into(composite, salt, &mut out)
            .map_err(|_| CoreError::Kdf)?;
        let key = Self::wrap(out);
        out.zeroize();
        Ok(key)
    }

    /// Expand the master key into `len` bytes bound to `info`.
    ///
    /// Distinct `info` values yield computationally unrelated outputs, which is
    /// what keeps each cascade layer's key independent from the others.
    pub fn expand(&self, info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>> {
        let hk = Hkdf::<Sha512>::new(None, &self.key.0);
        let mut out = Zeroizing::new(vec![0u8; len]);
        hk.expand(info, &mut out).map_err(|_| CoreError::Kdf)?;
        Ok(out)
    }

    /// Key material for every layer of `cascade`, concatenated.
    ///
    /// Each layer gets its own HKDF invocation labelled with its index *and* its
    /// algorithm id, so reordering a cascade also changes every key.
    pub fn cascade_keys(
        &self,
        cascade: &crate::cipher::Cascade,
        context: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut keys = Zeroizing::new(Vec::with_capacity(cascade.key_material_len()));
        for (i, algo) in cascade.layers().iter().enumerate() {
            let mut info = Vec::new();
            info.extend_from_slice(b"cerberus/v1/layer/");
            info.extend_from_slice(&(i as u32).to_le_bytes());
            info.push(algo.id());
            info.push(b'/');
            info.extend_from_slice(context);
            let layer = self.expand(&info, crate::cipher::LAYER_KEY_LEN)?;
            keys.extend_from_slice(&layer);
        }
        Ok(keys)
    }

    /// Key used for the HMAC-SHA512 that authenticates the whole file.
    pub fn file_mac_key(&self, context: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let mut info = b"cerberus/v1/file-mac/".to_vec();
        info.extend_from_slice(context);
        self.expand(&info, 64)
    }

    /// Constant-time equality of the raw key material.
    ///
    /// Used to re-authenticate an action against the *currently open* vault's
    /// key (e.g. the cleartext export) without paying a second Argon2 pass and,
    /// crucially, without trusting an on-disk file that an attacker could have
    /// swapped between the check and the use. Constant time so it leaks nothing
    /// about how close a wrong guess was.
    pub fn same_key(&self, other: &MasterKey) -> bool {
        use subtle::ConstantTimeEq;
        self.key.0.ct_eq(&other.key.0).unwrap_u8() == 1
    }
}

impl Clone for MasterKey {
    /// Cloning re-locks a fresh page, so every copy keeps the anti-swap
    /// guarantee and its own lock guard.
    fn clone(&self) -> Self {
        Self::wrap(self.key.0)
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        // Wipe first, then let `guard` drop and explicitly unlock this key's
        // page. Order matters: the bytes must be gone before the page is
        // eligible for swapping again.
        self.key.0.zeroize();
        drop(self.guard.take());
    }
}

impl std::fmt::Debug for MasterKey {
    /// Never print key material, not even by accident through a `{:?}` in a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

/// Measure how long `params` takes on this machine, for UI calibration.
pub fn benchmark(params: KdfParams) -> Result<std::time::Duration> {
    let salt = [0u8; SALT_LEN];
    let start = std::time::Instant::now();
    MasterKey::derive(b"benchmark", &salt, params)?;
    Ok(start.elapsed())
}

/// Pick the heaviest profile that still unlocks within `target`.
///
/// Falls back to `INTERACTIVE` on slow machines rather than making the vault
/// unusable.
pub fn calibrate(target: std::time::Duration) -> Result<KdfParams> {
    for params in [
        KdfParams::PARANOID,
        KdfParams::HARDENED,
        KdfParams::INTERACTIVE,
    ] {
        if benchmark(params)? <= target {
            return Ok(params);
        }
    }
    Ok(KdfParams::INTERACTIVE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::Cascade;

    /// Cheap parameters so the test suite stays fast. Never use these for real vaults.
    const TEST: KdfParams = KdfParams {
        memory_kib: 19 * 1024,
        time_cost: 2,
        parallelism: 1,
    };

    #[test]
    fn derivation_is_deterministic() {
        let salt = [7u8; SALT_LEN];
        let a = MasterKey::derive(b"secret", &salt, TEST).unwrap();
        let b = MasterKey::derive(b"secret", &salt, TEST).unwrap();
        // Compare via a derived output rather than the private buffer.
        assert_eq!(
            a.expand(b"t", 32).unwrap().to_vec(),
            b.expand(b"t", 32).unwrap().to_vec()
        );
    }

    #[test]
    fn a_different_salt_gives_a_different_key() {
        let a = MasterKey::derive(b"secret", &[1u8; SALT_LEN], TEST).unwrap();
        let b = MasterKey::derive(b"secret", &[2u8; SALT_LEN], TEST).unwrap();
        assert_ne!(
            a.expand(b"t", 32).unwrap().to_vec(),
            b.expand(b"t", 32).unwrap().to_vec()
        );
    }

    #[test]
    fn each_layer_gets_an_independent_key() {
        let key = MasterKey::derive(b"secret", &[0u8; SALT_LEN], TEST).unwrap();
        let cascade = Cascade::paranoid();
        let keys = key.cascade_keys(&cascade, b"ctx").unwrap();
        assert_eq!(keys.len(), cascade.key_material_len());

        let chunks: Vec<&[u8]> = keys.chunks(crate::cipher::LAYER_KEY_LEN).collect();
        for i in 0..chunks.len() {
            for j in (i + 1)..chunks.len() {
                assert_ne!(
                    chunks[i], chunks[j],
                    "layers {i} and {j} share key material"
                );
            }
        }
    }

    #[test]
    fn reordering_a_cascade_changes_every_key() {
        use crate::cipher::CipherAlgo;
        let key = MasterKey::derive(b"secret", &[0u8; SALT_LEN], TEST).unwrap();
        let a = Cascade::new(vec![CipherAlgo::Aes256Gcm, CipherAlgo::Serpent256]).unwrap();
        let b = Cascade::new(vec![CipherAlgo::Serpent256, CipherAlgo::Aes256Gcm]).unwrap();
        assert_ne!(
            key.cascade_keys(&a, b"ctx").unwrap().to_vec(),
            key.cascade_keys(&b, b"ctx").unwrap().to_vec()
        );
    }

    #[test]
    fn the_file_mac_key_is_not_a_layer_key() {
        let key = MasterKey::derive(b"secret", &[0u8; SALT_LEN], TEST).unwrap();
        let mac = key.file_mac_key(b"ctx").unwrap();
        let layers = key.cascade_keys(&Cascade::recommended(), b"ctx").unwrap();
        assert!(!layers.windows(mac.len()).any(|w| w == &mac[..]));
    }

    #[test]
    fn weak_or_absurd_parameters_are_refused() {
        assert!(KdfParams {
            memory_kib: 1024,
            time_cost: 3,
            parallelism: 4
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            memory_kib: 64 * 1024 * 1024,
            time_cost: 3,
            parallelism: 4
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            memory_kib: 256 * 1024,
            time_cost: 1,
            parallelism: 4
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            memory_kib: 256 * 1024,
            time_cost: 3,
            parallelism: 0
        }
        .validate()
        .is_err());
        assert!(KdfParams::HARDENED.validate().is_ok());
    }

    #[test]
    fn the_master_key_never_leaks_through_debug() {
        let key = MasterKey::derive(b"secret", &[0u8; SALT_LEN], TEST).unwrap();
        assert_eq!(format!("{key:?}"), "MasterKey(<redacted>)");
    }
}
