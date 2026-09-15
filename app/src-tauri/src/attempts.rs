//! Persistent record of failed unlock attempts.
//!
//! The in-memory throttle resets when the process does, so a user — or an
//! attacker sitting at an unlocked desktop — could clear a growing penalty just
//! by restarting Cerberus. Keeping the counter on disk closes that.
//!
//! **This is a speed bump, not a defence.** Anyone holding the `.cbv` file can
//! ignore the application entirely and grind at the file with their own reader.
//! The only thing that actually costs them is Argon2id. What this stops is
//! casual repeated guessing at a machine the owner walked away from.
//!
//! The file is deliberately not authenticated: there is no key to authenticate
//! it with before the vault is open, and pretending otherwise would be theatre.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
struct Record {
    failures: u32,
    /// Unix milliseconds of the most recent failure.
    last_failure_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Store {
    /// Keyed by a hash of the vault path, so the file never lists where a
    /// user's vaults live.
    vaults: HashMap<String, Record>,
}

/// `%LOCALAPPDATA%\Cerberus\attempts.json`, or the OS equivalent.
fn store_path() -> Option<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(dirs_fallback)?;
    Some(base.join("Cerberus").join("attempts.json"))
}

fn dirs_fallback() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"))
}

fn key_for(vault: &Path) -> String {
    // Canonicalise first: on Windows the *same* file can be named
    // `C:\a\v.cbv`, `C:/a/v.cbv`, or `c:\A\V.cbv`, which hash differently.
    // Without this, an attacker resets the persisted penalty simply by varying
    // the spelling of the path between attempts. `canonicalize` collapses
    // separators, relative components, and drive-letter/component case to one
    // stable form. Fall back to the raw string only if the file cannot be
    // resolved (it normally exists — we are unlocking it).
    let canonical = std::fs::canonicalize(vault)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| vault.to_string_lossy().into_owned());
    blake3::hash(canonical.as_bytes()).to_hex().to_string()
}

fn load() -> Store {
    store_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save(store: &Store) {
    let Some(path) = store_path() else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string(store) {
        // Best effort: failing to record an attempt must never block a
        // legitimate unlock. But the write is atomic (temp + fsync + replace):
        // a crash mid-`std::fs::write` used to truncate the file, so `load()`
        // fell back to default and every vault's accumulated penalty was wiped.
        let _ = atomic_write(&path, json.as_bytes());
    }
}

/// Durable replace: write to a unique temp, flush and fsync, then swap it in.
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let tmp = path.with_extension(format!("json.{}.tmp", uuid::Uuid::new_v4()));
    let write = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // `rename` will not overwrite an existing file on Windows.
    #[cfg(windows)]
    if path.exists() {
        let rollback = path.with_extension(format!("json.{}.old", uuid::Uuid::new_v4()));
        std::fs::rename(path, &rollback)?;
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::rename(&rollback, path);
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        let _ = std::fs::remove_file(&rollback);
        return Ok(());
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Failures recorded for a vault, and when the last one happened.
pub fn read(vault: &Path) -> (u32, u64) {
    load()
        .vaults
        .get(&key_for(vault))
        .map(|r| (r.failures, r.last_failure_ms))
        .unwrap_or((0, 0))
}

pub fn record_failure(vault: &Path, now_ms: u64) {
    let key = key_for(vault);
    with_store_lock(|| {
        let mut store = load();
        let entry = store.vaults.entry(key).or_default();
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure_ms = now_ms;
        save(&store);
    });
}

pub fn clear(vault: &Path) {
    let key = key_for(vault);
    with_store_lock(|| {
        let mut store = load();
        if store.vaults.remove(&key).is_some() {
            save(&store);
        }
    });
}

/// Serialise the read-modify-write of the shared store across instances, so two
/// processes recording a failure at once cannot lose one another's increment.
fn with_store_lock<T>(f: impl FnOnce() -> T) -> T {
    match store_path() {
        // Strict, not best-effort: a lost failure-count increment weakens the
        // anti-bruteforce throttle (cross-audit, Gemini C-02).
        Some(p) => crate::vaultlock::with_lock_strict(&p, f),
        None => f(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The path is hashed, so the store never reveals where vaults are kept.
    #[test]
    fn the_store_key_does_not_contain_the_path() {
        let key = key_for(Path::new("C:/Users/someone/Documents/private.cbv"));
        assert!(!key.contains("someone"));
        assert!(!key.contains("private"));
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn different_vaults_get_different_keys() {
        assert_ne!(key_for(Path::new("a.cbv")), key_for(Path::new("b.cbv")));
        assert_eq!(key_for(Path::new("a.cbv")), key_for(Path::new("a.cbv")));
    }

    #[test]
    fn equivalent_spellings_of_the_same_file_share_a_key() {
        // Canonicalisation must collapse different spellings of one real file to
        // one key, or the persistent throttle is bypassed by varying the path.
        let dir = std::env::temp_dir().join(format!("cerberus-attempts-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("v.cbv");
        std::fs::write(&file, b"x").unwrap();

        // Same file reached via a redundant `.` component.
        let dotted = dir.join(".").join("v.cbv");
        assert_eq!(key_for(&file), key_for(&dotted));

        std::fs::remove_dir_all(&dir).ok();
    }
}
