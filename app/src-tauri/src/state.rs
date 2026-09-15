//! Application state.
//!
//! While unlocked, the vault is **not** held as continuously-resident plaintext.
//! It lives sealed in memory under a random per-session key, and is decrypted
//! into a short-lived [`OpenVault`] only for the duration of a single command,
//! then re-sealed. This shortens how long decrypted passwords sit in RAM.
//!
//! Honest limitation: the session key lives in the same process as the sealed
//! blob, so an attacker who can dump the whole running process defeats this. It
//! is defence-in-depth — it shrinks the exposure window and keeps secrets out of
//! long-lived allocations and swapped pages — not protection against a live
//! process dump. The web frontend still only ever receives one secret at a time,
//! on explicit user action.

use std::path::PathBuf;
use std::sync::Mutex;

use cerberus_core::container::{self, Header};
use cerberus_core::session::{
    AutoLockPolicy, ClipboardGuard, ClipboardPolicy, IdleTracker, UnlockThrottle,
};
use cerberus_core::{MasterKey, Vault};

/// The decrypted view of the vault, alive only inside a single [`AppState::with_vault`]
/// call. Its `Vault` (and every secret in it) is zeroized when this drops.
pub struct OpenVault {
    pub path: PathBuf,
    pub vault: Vault,
    /// Master key derived once at unlock and reused for every save.
    ///
    /// Re-running Argon2id per save costs seconds at the higher cost profiles
    /// and buys nothing: the salt is per-vault, and freshness across writes
    /// comes from the nonces. Holding the key also means the user's factors do
    /// not have to stay in memory at all.
    pub key: MasterKey,
    /// Salt, cascade and KDF settings of the file on disk.
    pub header: Header,
    pub idle: IdleTracker,
    /// Set when the in-memory vault differs from what is on disk.
    pub dirty: bool,
    /// BLAKE3 of the exact file bytes this session last read or wrote. Used for
    /// optimistic concurrency: if the file on disk no longer hashes to this, a
    /// second instance changed it, and saving would silently clobber their work.
    pub fingerprint: [u8; 32],
}

/// The resident form of an unlocked vault: sealed, never plaintext.
struct SealedVault {
    path: PathBuf,
    /// The vault, encrypted with `session_key`. Re-created on every mutation.
    sealed: Vec<u8>,
    /// Random key, in-RAM only, that never touches disk.
    session_key: MasterKey,
    /// The real on-disk master key, for saving.
    key: MasterKey,
    /// The real on-disk header.
    header: Header,
    idle: IdleTracker,
    dirty: bool,
    fingerprint: [u8; 32],
}

impl SealedVault {
    /// Seal a freshly opened vault for resident storage.
    fn from_open(open: OpenVault) -> Result<Self, String> {
        let session_key = MasterKey::random().map_err(|e| e.to_string())?;
        let sealed =
            container::seal_ephemeral(&open.vault, &session_key).map_err(|e| e.to_string())?;
        Ok(SealedVault {
            path: open.path,
            sealed,
            session_key,
            key: open.key,
            header: open.header,
            idle: open.idle,
            dirty: open.dirty,
            fingerprint: open.fingerprint,
        })
    }

    /// Decrypt into a transient [`OpenVault`] for one operation.
    fn unseal(&self) -> Result<OpenVault, String> {
        let vault = container::open_ephemeral(&self.sealed, &self.session_key)
            .map_err(|e| e.to_string())?;
        Ok(OpenVault {
            path: self.path.clone(),
            vault,
            key: self.key.clone(),
            header: self.header.clone(),
            idle: self.idle.clone(),
            dirty: self.dirty,
            fingerprint: self.fingerprint,
        })
    }

    /// Re-seal after an operation, absorbing any changes the command made.
    fn reseal(&mut self, open: OpenVault) -> Result<(), String> {
        self.sealed =
            container::seal_ephemeral(&open.vault, &self.session_key).map_err(|e| e.to_string())?;
        self.path = open.path;
        self.key = open.key;
        self.header = open.header;
        self.idle = open.idle;
        self.dirty = open.dirty;
        self.fingerprint = open.fingerprint;
        Ok(())
    }
}

#[derive(Default)]
pub struct AppState {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    open: Option<SealedVault>,
    throttle: UnlockThrottle,
    clipboard: Option<ClipboardGuard>,
    clipboard_policy: ClipboardPolicy,
    autolock_policy: AutoLockPolicy,
    /// Header of the last vault pointed at, readable before unlocking.
    peeked: Option<(PathBuf, Header)>,
    /// Local app config (recent vaults, prefs), loaded after the gate (if any).
    config: crate::appconfig::AppConfig,
    /// Active gate phrase for this session, so config re-saves stay encrypted.
    gate_phrase: Option<zeroize::Zeroizing<String>>,
    /// Inter-process lock for the open vault; dropped (released) on close.
    vault_lock: Option<crate::vaultlock::VaultLock>,
}

impl AppState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `f` against the open vault, or fail if the vault is locked.
    ///
    /// Every command that touches vault contents goes through here, so "is it
    /// unlocked?" is checked in exactly one place.
    pub fn with_vault<T>(
        &self,
        f: impl FnOnce(&mut OpenVault) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut inner = self.lock();
        let sealed = inner.open.as_mut().ok_or("the vault is locked")?;
        // Decrypt for this one operation only; `transient` (and its secrets)
        // zeroize when it drops at the end of this function.
        let mut transient = sealed.unseal()?;
        let result = f(&mut transient);
        // Re-seal even on error: the command may have mutated the vault before
        // failing, and the resident copy must reflect reality.
        sealed.reseal(transient)?;
        result
    }

    pub fn is_unlocked(&self) -> bool {
        self.lock().open.is_some()
    }

    pub fn set_open(&self, open: OpenVault) -> Result<(), String> {
        let mut inner = self.lock();
        // Release any previously-held lock first (it removes its own file), so
        // re-opening the same vault in this instance does not have the old
        // guard delete the freshly-acquired lock file (same path).
        inner.vault_lock = None;
        // Take the inter-process lock before sealing: if another instance holds
        // this vault, refuse now rather than let two writers race.
        let lock = crate::vaultlock::acquire(&open.path)?;
        // Seal immediately: the plaintext `OpenVault` handed in here drops (and
        // zeroizes) as this returns, leaving only the sealed form resident.
        let sealed = SealedVault::from_open(open)?;
        inner.open = Some(sealed);
        inner.vault_lock = lock;
        Ok(())
    }

    /// Drop the decrypted vault. `Vault` and its entries zeroize on drop.
    pub fn close(&self) {
        let mut inner = self.lock();
        inner.open = None;
        inner.clipboard = None;
        // Release the inter-process lock (the file is removed on drop).
        inner.vault_lock = None;
    }

    /// Enforce the idle timeout independent of the frontend.
    ///
    /// Reads and writes only the resident [`SealedVault`]'s idle tracker —
    /// never decrypts — so this is cheap enough to poll from a native
    /// background thread every second. That thread is what makes the idle
    /// timeout real even if the webview is frozen, suspended, or otherwise
    /// stops calling `session_tick`: a previous version relied solely on the
    /// frontend's poll, so a stalled or compromised webview never expired
    /// the session.
    ///
    /// Returns `true` if it just locked the vault (caller may want to notify
    /// the frontend).
    pub fn enforce_idle(&self, now_ms: u64) -> bool {
        let mut inner = self.lock();
        let Some(sealed) = inner.open.as_ref() else {
            return false;
        };
        if sealed.idle.should_lock(now_ms).is_none() {
            return false;
        }
        inner.open = None;
        inner.clipboard = None;
        inner.vault_lock = None;
        true
    }

    pub fn throttle_remaining_ms(&self, now_ms: u64) -> u64 {
        self.lock().throttle.remaining(now_ms).as_millis() as u64
    }

    /// Carry a penalty recorded by a previous run of the application into this
    /// one, so restarting Cerberus does not reset the delay.
    ///
    /// Only ever raises the penalty: a stale on-disk record cannot be used to
    /// *shorten* a delay accumulated in this session.
    pub fn adopt_persisted_attempts(&self, vault: &std::path::Path) {
        let (failures, last_ms) = crate::attempts::read(vault);
        if failures == 0 {
            return;
        }
        let mut inner = self.lock();
        if failures > inner.throttle.failures() {
            inner.throttle = UnlockThrottle::restored(failures, last_ms);
        }
    }

    pub fn record_unlock_failure(&self, now_ms: u64) {
        self.lock().throttle.record_failure(now_ms);
    }

    pub fn record_unlock_success(&self) {
        self.lock().throttle.record_success();
    }

    pub fn failure_count(&self) -> u32 {
        self.lock().throttle.failures()
    }

    pub fn clipboard_policy(&self) -> ClipboardPolicy {
        self.lock().clipboard_policy.clone()
    }

    pub fn set_clipboard_policy(&self, policy: ClipboardPolicy) {
        self.lock().clipboard_policy = policy;
    }

    pub fn arm_clipboard(&self, secret: &str, now_ms: u64) {
        let policy = self.clipboard_policy();
        self.lock().clipboard = Some(ClipboardGuard::new(policy, secret, now_ms));
    }

    /// Should the clipboard be wiped now, given what it currently holds?
    ///
    /// Returns false when the user has since copied something else, so the app
    /// never destroys clipboard content it did not put there.
    pub fn clipboard_due(&self, current: &str, now_ms: u64) -> bool {
        let mut inner = self.lock();
        let Some(guard) = inner.clipboard.as_ref() else {
            return false;
        };
        if !guard.owns(current) {
            inner.clipboard = None;
            return false;
        }
        if guard.should_clear(now_ms) {
            inner.clipboard = None;
            return true;
        }
        false
    }

    pub fn autolock_policy(&self) -> AutoLockPolicy {
        self.lock().autolock_policy.clone()
    }

    pub fn set_autolock_policy(&self, policy: AutoLockPolicy) {
        let mut inner = self.lock();
        if let Some(sealed) = inner.open.as_mut() {
            sealed.idle = IdleTracker::new(policy.clone(), now_ms());
        }
        inner.autolock_policy = policy;
    }

    // ── app config + gate phrase ──────────────────────────────────────────

    /// Adopt a loaded config and the phrase (if any) that unlocked it.
    pub fn set_config(&self, config: crate::appconfig::AppConfig, phrase: Option<String>) {
        let mut inner = self.lock();
        inner.config = config;
        inner.gate_phrase = phrase.map(zeroize::Zeroizing::new);
    }

    pub fn config(&self) -> crate::appconfig::AppConfig {
        self.lock().config.clone()
    }

    /// Mutate the config and persist it under the current gate phrase.
    pub fn update_config(
        &self,
        f: impl FnOnce(&mut crate::appconfig::AppConfig),
    ) -> Result<(), String> {
        let mut inner = self.lock();
        f(&mut inner.config);
        let phrase = inner.gate_phrase.as_ref().map(|p| p.to_string());
        crate::appconfig::save(&inner.config, phrase.as_deref()).map_err(|e| e.to_string())
    }

    /// Change the active gate phrase (or clear it), re-saving the config.
    pub fn set_gate_phrase(&self, phrase: Option<String>) -> Result<(), String> {
        let mut inner = self.lock();
        crate::appconfig::save(&inner.config, phrase.as_deref()).map_err(|e| e.to_string())?;
        inner.gate_phrase = phrase.map(zeroize::Zeroizing::new);
        Ok(())
    }

    pub fn set_peeked(&self, path: PathBuf, header: Header) {
        self.lock().peeked = Some((path, header));
    }

    pub fn peeked(&self) -> Option<(PathBuf, Header)> {
        self.lock().peeked.clone()
    }

    /// A poisoned mutex means another thread panicked while holding vault state.
    /// Recovering the guard is correct here: the alternative is a permanently
    /// unusable app, and the data behind it is plain state, not an invariant
    /// that a panic could have half-broken.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Monotonic-ish milliseconds since the Unix epoch.
///
/// Used only for throttling and timers, where a clock step is an annoyance
/// rather than a security failure — the KDF is what makes guessing expensive.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
