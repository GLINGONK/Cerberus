//! Inter-process exclusive lock for an open vault.
//!
//! A cross-audit found that two Cerberus instances could open the same vault,
//! both pass the optimistic fingerprint check, then commit in turn — the second
//! silently discarding the first's changes, or (after a concurrent rekey)
//! bringing the old factors back to life. The fingerprint detects a change
//! already committed; it cannot prevent two writers racing.
//!
//! This closes it with a plain lock file next to the vault (`<vault>.cbvlock`),
//! created with `create_new` so exactly one process can hold it. It is held for
//! the whole unlocked session and removed on lock/close (and on drop). To avoid
//! a crash leaving a permanent stale lock, the file records the owning process
//! id; a lock whose owner is no longer alive is reclaimed.
//!
//! Deliberately dependency-free: the exclusion is the OS's atomic `create_new`,
//! and liveness uses the `windows` crate already pulled in for the app.

use std::io::Write;
use std::path::{Path, PathBuf};

/// A held vault lock. Dropping it releases (deletes) the lock file.
#[derive(Debug)]
pub struct VaultLock {
    path: PathBuf,
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn lock_path(vault: &Path) -> PathBuf {
    let name = vault
        .file_name()
        .map(|n| format!("{}.cbvlock", n.to_string_lossy()))
        .unwrap_or_else(|| "vault.cbvlock".to_string());
    match vault.parent() {
        Some(dir) => dir.join(name),
        None => PathBuf::from(name),
    }
}

/// Try to take the exclusive lock for `vault`.
///
/// Fails if another *live* process already holds it. A lock left behind by a
/// dead process is reclaimed. Best-effort by design: if the directory is not
/// writable we return `Ok(None)` rather than blocking the user out of their own
/// vault — the fingerprint check remains as a second line.
pub fn acquire(vault: &Path) -> Result<Option<VaultLock>, String> {
    let path = lock_path(vault);

    for _ in 0..2 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", std::process::id());
                let _ = f.flush();
                return Ok(Some(VaultLock { path }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if holder_is_alive(&path) {
                    return Err("this vault is already open in another Cerberus instance. \
                         Close it there first."
                        .into());
                }
                // Stale lock from a crashed process: remove and retry once.
                let _ = std::fs::remove_file(&path);
                continue;
            }
            // Directory not writable, etc. Don't lock the user out of their vault.
            Err(_) => return Ok(None),
        }
    }
    // Lost the reclaim race to yet another instance.
    Err("this vault is already open in another Cerberus instance.".into())
}

/// Is the process recorded in the lock file still running?
///
/// A missing/garbled file, or our own pid, counts as "not a live foreign
/// holder" so a leftover is reclaimable.
fn holder_is_alive(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(pid) = content.trim().parse::<u32>() else {
        return false;
    };
    if pid == std::process::id() {
        return false;
    }
    pid_alive(pid)
}

#[cfg(windows)]
fn pid_alive(pid: u32) -> bool {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // A live PID alone is NOT enough: after a crash the OS can recycle our old
    // PID onto an unrelated program (Chrome, Slack, …). Treating that as the
    // live holder would lock the user out of their own vault permanently
    // (cross-audit, Gemini C-03). So we also confirm the process image is
    // Cerberus itself — only then is it a genuine second instance.
    //
    // SAFETY: OpenProcess with a query-only right; the handle, if valid, is
    // closed before returning. A fully-exited PID yields an error here.
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        if handle.is_invalid() {
            return false;
        }
        let mut buf = [0u16; 260]; // MAX_PATH
        let mut len = buf.len() as u32;
        let queried = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(handle);
        if !queried {
            // Cannot read the image name (e.g. a higher-integrity process):
            // fall back to "alive" so we never risk two concurrent writers.
            return true;
        }
        let image = String::from_utf16_lossy(&buf[..len as usize]);
        image_is_cerberus(&image)
    }
}

/// Does this executable path belong to a Cerberus instance?
///
/// Compared against our own running image's file name (case-insensitively),
/// so it holds under any install location and for the dev binary.
#[cfg(windows)]
fn image_is_cerberus(image_path: &str) -> bool {
    let own = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));
    let Some(own) = own else {
        return true; // cannot identify ourselves: be conservative, assume alive
    };
    let their = std::path::Path::new(image_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    their.eq_ignore_ascii_case(&own)
}

#[cfg(not(windows))]
fn pid_alive(_pid: u32) -> bool {
    // On non-Windows (not a shipping target) assume a lock is live rather than
    // risk two writers. The user can delete a stale `.cbvlock` by hand.
    true
}

/// Run `f` while holding a short-lived exclusive lock beside `target`.
///
/// For the small shared files (`attempts.json`, `config.dat`) that any instance
/// may rewrite: it makes a read-modify-write critical section so two instances
/// do not lose each other's update. Best-effort — if the lock cannot be taken
/// after a brief spin (another instance is mid-write, or a stale lock lingers),
/// `f` still runs, because blocking a best-effort save is worse than a rare
/// lost increment. The lock file is removed when the guard drops.
pub fn with_lock<T>(target: &Path, f: impl FnOnce() -> T) -> T {
    let name = target
        .file_name()
        .map(|n| format!("{}.lock", n.to_string_lossy()))
        .unwrap_or_else(|| "shared.lock".to_string());
    let path = match target.parent() {
        Some(dir) => dir.join(name),
        None => PathBuf::from(name),
    };

    let mut guard = None;
    for attempt in 0..20 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                let _ = writeln!(file, "{}", std::process::id());
                guard = Some(VaultLock { path: path.clone() });
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if !holder_is_alive(&path) {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                if attempt == 19 {
                    break; // give up waiting; proceed best-effort
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(_) => break, // directory not writable: proceed best-effort
        }
    }
    let result = f();
    drop(guard);
    result
}

/// Like [`with_lock`], but for security counters that must not lose an update.
///
/// `attempts.json` (the persisted anti-bruteforce penalty) is different from a
/// preference file: a dropped increment weakens the throttle. A cross-audit
/// (Gemini C-02) flagged that the best-effort `with_lock` could let two
/// instances clobber each other's failure count. This variant does not bail out
/// to best-effort on contention — it keeps waiting, reclaiming any dead holder
/// each round, so it only ever blocks on a genuinely-live Cerberus doing its own
/// sub-millisecond write. A generous absolute cap (~5 s) is kept purely so a
/// pathological lock leak can never hang the UI forever; reaching it is not
/// expected and it then proceeds best-effort as a last resort.
pub fn with_lock_strict<T>(target: &Path, f: impl FnOnce() -> T) -> T {
    let name = target
        .file_name()
        .map(|n| format!("{}.lock", n.to_string_lossy()))
        .unwrap_or_else(|| "shared.lock".to_string());
    let path = match target.parent() {
        Some(dir) => dir.join(name),
        None => PathBuf::from(name),
    };

    let mut guard = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                let _ = writeln!(file, "{}", std::process::id());
                guard = Some(VaultLock { path: path.clone() });
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if !holder_is_alive(&path) {
                    let _ = std::fs::remove_file(&path);
                    continue;
                }
                if std::time::Instant::now() >= deadline {
                    break; // pathological leak: proceed best-effort rather than hang
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(_) => break, // directory not writable: proceed best-effort
        }
    }
    let result = f();
    drop(guard);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_vault() -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("cerberus-lock-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let vault = dir.join("v.cbv");
        std::fs::write(&vault, b"x").unwrap();
        (dir, vault)
    }

    #[test]
    fn acquire_creates_then_releases_the_lock_file() {
        let (dir, vault) = temp_vault();
        let lp = lock_path(&vault);
        {
            let guard = acquire(&vault).unwrap();
            assert!(guard.is_some());
            assert!(lp.exists(), "lock file should exist while held");
        }
        assert!(!lp.exists(), "lock file should be gone after drop");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_dead_holders_lock_is_reclaimed() {
        let (dir, vault) = temp_vault();
        let lp = lock_path(&vault);
        // A leftover lock naming a definitely-dead pid (0 is never a real
        // user process; OpenProcess fails for it) must be reclaimable.
        std::fs::write(&lp, b"0\n").unwrap();
        let guard = acquire(&vault).unwrap();
        assert!(guard.is_some(), "a stale lock should be reclaimed");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn with_lock_runs_and_returns_its_value() {
        let (dir, vault) = temp_vault();
        let out = with_lock(&vault, || 42);
        assert_eq!(out, 42);
        std::fs::remove_dir_all(&dir).ok();
    }
}
