//! Local application configuration, with an optional "gate phrase".
//!
//! Holds non-vault state: recently opened vault paths and a few preferences.
//! When a gate phrase is set, this file is encrypted, so someone who merely
//! opens Cerberus on an unlocked machine sees nothing — not even where the
//! user's vaults live.
//!
//! Honesty (as documented to the user): this protects the *application's* view,
//! not the vault files. An attacker with a `.cbv` opens it with another tool
//! regardless. The gate is a deterrent against casual snooping, and it withholds
//! real information (the vault list), not a bypassable `if`.

use std::path::PathBuf;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use cerberus_core::kdf::{KdfParams, MasterKey};

const MAGIC: &[u8; 6] = b"CBVCFG";
const VERSION: u8 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// User-facing configuration, persisted between runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    /// Most-recent-first list of vault paths, capped.
    #[serde(default)]
    pub recent_vaults: Vec<String>,
    #[serde(default)]
    pub clipboard_seconds: Option<u64>,
    #[serde(default)]
    pub autolock_minutes: Option<u64>,
    #[serde(default)]
    pub language: Option<String>,
}

impl AppConfig {
    const RECENT_LIMIT: usize = 10;

    pub fn push_recent(&mut self, path: &str) {
        self.recent_vaults.retain(|p| p != path);
        self.recent_vaults.insert(0, path.to_string());
        self.recent_vaults.truncate(Self::RECENT_LIMIT);
    }
}

fn config_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("Cerberus").join("config.dat"))
}

/// Is a gate phrase currently protecting the config?
pub fn gate_is_set() -> bool {
    matches!(config_state(), ConfigState::Gated)
}

/// The four distinguishable states of the on-disk config file.
///
/// `gate_is_set()` alone conflated "no gate" with "corrupt/unreadable", so a
/// tampered or truncated `config.dat` was treated as absent and could be
/// silently overwritten without the current phrase. Callers that change the
/// gate must tell these apart (a cross-audit finding).
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigState {
    /// No file at all: a first-time gate can be set freely.
    Absent,
    /// A valid cleartext config (no gate).
    Plain,
    /// A valid gated (encrypted) config.
    Gated,
    /// The file exists but is unreadable or malformed — refuse to reconfigure.
    Corrupt,
}

pub fn config_state() -> ConfigState {
    let Some(path) = config_path() else {
        return ConfigState::Absent;
    };
    if !path.exists() {
        return ConfigState::Absent;
    }
    let Ok(bytes) = std::fs::read(&path) else {
        return ConfigState::Corrupt; // exists but cannot be read
    };
    if bytes.len() < 8 || &bytes[..6] != MAGIC {
        return ConfigState::Corrupt;
    }
    match bytes[7] {
        0 => ConfigState::Plain,
        1 => ConfigState::Gated,
        _ => ConfigState::Corrupt,
    }
}

/// Does any config file exist at all?
pub fn exists() -> bool {
    config_path().map(|p| p.exists()).unwrap_or(false)
}

/// Load the config. Requires the gate phrase iff one is set.
///
/// A wrong phrase yields [`GateError::WrongPhrase`], distinct from "no gate", so
/// the UI can tell the difference. It never returns partial data on failure.
pub fn load(phrase: Option<&str>) -> Result<AppConfig, GateError> {
    let Some(path) = config_path() else {
        return Ok(AppConfig::default());
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(AppConfig::default());
    };
    if bytes.len() < 8 || &bytes[..6] != MAGIC {
        return Ok(AppConfig::default());
    }
    let encrypted = bytes[7] == 1;

    if !encrypted {
        let json = &bytes[8..];
        return serde_json::from_slice(json).map_err(|_| GateError::Corrupt);
    }

    let phrase = phrase.ok_or(GateError::PhraseRequired)?;
    // Layout after header: salt(32) ‖ nonce(12) ‖ ciphertext.
    if bytes.len() < 8 + SALT_LEN + NONCE_LEN {
        return Err(GateError::Corrupt);
    }
    let salt = &bytes[8..8 + SALT_LEN];
    let nonce = &bytes[8 + SALT_LEN..8 + SALT_LEN + NONCE_LEN];
    let ct = &bytes[8 + SALT_LEN + NONCE_LEN..];

    let key = derive_key(phrase, salt).map_err(|_| GateError::Corrupt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| GateError::Corrupt)?;
    let plain = cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: ct,
                aad: MAGIC,
            },
        )
        .map_err(|_| GateError::WrongPhrase)?;
    let plain = Zeroizing::new(plain);
    serde_json::from_slice(&plain).map_err(|_| GateError::Corrupt)
}

/// Save the config. If `phrase` is `Some`, the file is encrypted (gate enabled);
/// if `None`, it is written in clear (no gate).
pub fn save(config: &AppConfig, phrase: Option<&str>) -> Result<(), GateError> {
    let Some(path) = config_path() else {
        return Err(GateError::Corrupt);
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let json = Zeroizing::new(serde_json::to_vec(config).map_err(|_| GateError::Corrupt)?);
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);

    match phrase {
        None => {
            out.push(0); // not encrypted
            out.extend_from_slice(&json);
        }
        Some(phrase) => {
            out.push(1); // encrypted
            let salt =
                cerberus_core::random::bytes::<SALT_LEN>().map_err(|_| GateError::Corrupt)?;
            let nonce = cerberus_core::random::vec(NONCE_LEN).map_err(|_| GateError::Corrupt)?;
            let key = derive_key(phrase, &salt).map_err(|_| GateError::Corrupt)?;
            let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| GateError::Corrupt)?;
            let ct = cipher
                .encrypt(
                    nonce.as_slice().into(),
                    Payload {
                        msg: &json,
                        aad: MAGIC,
                    },
                )
                .map_err(|_| GateError::Corrupt)?;
            out.extend_from_slice(&salt);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ct);
        }
    }

    // Serialise writes across instances so two processes saving config at once
    // cannot tear each other's file or lose the Windows rename race.
    crate::vaultlock::with_lock(&path, || atomic_write(&path, &out)).map_err(|_| GateError::Corrupt)
}

/// Write `bytes` to `path`, replacing any existing file, durably.
///
/// The previous version used a fixed `config.tmp` name plus a bare
/// `std::fs::rename`. On Windows `rename` does not replace an existing
/// destination, so every save *after* the first silently failed: preferences,
/// language, and the gate phrase could never be changed a second time, and a
/// stale `config.tmp` was left behind. An independent audit caught this. This
/// mirrors the vault's Windows-safe replacement.
fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    let write_tmp = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_tmp {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = replace_existing(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_existing(tmp: &std::path::Path, path: &std::path::Path) -> std::io::Result<()> {
    std::fs::rename(tmp, path)
}

#[cfg(windows)]
fn replace_existing(tmp: &std::path::Path, path: &std::path::Path) -> std::io::Result<()> {
    if !path.exists() {
        return std::fs::rename(tmp, path);
    }
    // `rename` will not overwrite on Windows: stage the old file aside, install
    // the new one, and restore the original name if installing fails.
    let rollback = path.with_extension(format!("old.{}", uuid::Uuid::new_v4()));
    std::fs::rename(path, &rollback)?;
    if let Err(install) = std::fs::rename(tmp, path) {
        let _ = std::fs::rename(&rollback, path);
        return Err(install);
    }
    let _ = std::fs::remove_file(&rollback);
    Ok(())
}

/// Derive a 32-byte AES key from the gate phrase.
///
/// Uses the interactive Argon2 profile: the gate is a convenience deterrent, not
/// the vault's protection, so a ~0.5 s derivation is the right trade-off.
fn derive_key(phrase: &str, salt: &[u8]) -> Result<Zeroizing<Vec<u8>>, ()> {
    let master =
        MasterKey::derive(phrase.as_bytes(), salt, KdfParams::INTERACTIVE).map_err(|_| ())?;
    master.expand(b"cerberus/gate/v1", 32).map_err(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateError {
    /// A gate phrase is set but none was provided.
    PhraseRequired,
    /// The provided phrase did not decrypt the config.
    WrongPhrase,
    /// The file is unreadable or malformed.
    Corrupt,
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::PhraseRequired => write!(f, "a gate phrase is required"),
            GateError::WrongPhrase => write!(f, "wrong gate phrase"),
            GateError::Corrupt => write!(f, "the configuration is unreadable"),
        }
    }
}
