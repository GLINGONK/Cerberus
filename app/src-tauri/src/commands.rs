//! IPC commands exposed to the frontend.
//!
//! Two rules hold throughout:
//! 1. Listings never carry passwords, TOTP seeds or notes. Secrets cross the
//!    boundary only through [`entry_reveal`] and [`entry_copy`], one at a time.
//! 2. Every unlock failure returns the same opaque error, so the frontend
//!    cannot tell which factor was wrong.

use std::path::PathBuf;

use cerberus_core::container;
use cerberus_core::factors::{self, Factor, FactorSet, Pattern};
use cerberus_core::generator::{self, PasswordPolicy};
use cerberus_core::random::EntropyPool;
use cerberus_core::totp::Totp;
use cerberus_core::vault::{CustomField, Entry};
use cerberus_core::{Cascade, CipherAlgo, KdfParams, Vault};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::state::{now_ms, AppState, OpenVault};

/// Factors as the unlock screen collects them.
///
/// Key files travel as paths, never as bytes: the frontend has no reason to
/// hold key material, and this keeps it out of the webview's heap entirely.
#[derive(Debug, Deserialize)]
pub struct FactorInput {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(default)]
    pub keyfiles: Vec<PathBuf>,
    #[serde(default)]
    pub pattern: Option<PatternInput>,
    /// Shamir share files to reconstruct into a single key-file factor.
    #[serde(default)]
    pub share_files: Vec<PathBuf>,
    /// Shamir shares typed by hand (paper backup), same purpose as `share_files`.
    #[serde(default)]
    pub share_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PatternInput {
    pub size: u8,
    pub points: Vec<u8>,
}

impl FactorInput {
    fn build(self) -> Result<FactorSet, String> {
        let mut set = FactorSet::new();
        if let Some(p) = self.password.filter(|p| !p.is_empty()) {
            set = set.with(Factor::Password(Zeroizing::new(p)));
        }
        if let Some(p) = self.pin.filter(|p| !p.is_empty()) {
            set = set.with(Factor::Pin(Zeroizing::new(p)));
        }
        for path in self.keyfiles {
            let bytes = std::fs::read(&path)
                .map_err(|e| format!("cannot read the key file {}: {e}", path.display()))?;
            set = set.with(Factor::Keyfile(Zeroizing::new(bytes)));
        }
        if let Some(p) = self.pattern {
            let pattern = Pattern::new(p.size, p.points).map_err(|e| e.to_string())?;
            set = set.with(Factor::Pattern(pattern));
        }
        // Shamir shares (from files and/or hand-typed hex) reconstruct one secret,
        // which is presented as a key-file factor — the same factor the vault was
        // created with. Below the threshold, reconstruction yields the wrong
        // secret and unlocking simply fails, revealing nothing.
        if !self.share_files.is_empty() || !self.share_hex.is_empty() {
            let secret = reconstruct_shares(&self.share_files, &self.share_hex)?;
            set = set.with(Factor::Keyfile(secret));
        }
        if set.is_empty() {
            return Err("supply at least one authentication factor".into());
        }
        Ok(set)
    }

    /// Build only the base factors (password / PIN / pattern), ignoring key files
    /// and shares. Used when creating a Shamir vault: the split secret is added
    /// by the caller as the key-file factor.
    fn build_base_only(self) -> Result<FactorSet, String> {
        let mut set = FactorSet::new();
        if let Some(p) = self.password.filter(|p| !p.is_empty()) {
            set = set.with(Factor::Password(Zeroizing::new(p)));
        }
        if let Some(p) = self.pin.filter(|p| !p.is_empty()) {
            set = set.with(Factor::Pin(Zeroizing::new(p)));
        }
        if let Some(p) = self.pattern {
            let pattern = Pattern::new(p.size, p.points).map_err(|e| e.to_string())?;
            set = set.with(Factor::Pattern(pattern));
        }
        Ok(set)
    }
}

/// BLAKE3 of a vault file's exact bytes, for optimistic concurrency control.
fn fingerprint_bytes(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// Re-read the vault file and hash it. `None` if it cannot be read (e.g. moved).
fn fingerprint_on_disk(path: &std::path::Path) -> Option<[u8; 32]> {
    std::fs::read(path).ok().map(|b| fingerprint_bytes(&b))
}

/// Refuse to write if the file on disk no longer matches what this session last
/// read or wrote — a second instance changed it, and saving would clobber their
/// work (or, after a concurrent rekey, silently revive the old factors).
fn guard_against_concurrent_change(open: &OpenVault) -> Result<(), String> {
    match fingerprint_on_disk(&open.path) {
        // File changed under us since we opened or last saved it.
        Some(current) if current != open.fingerprint => Err(
            "the vault file changed on disk (another Cerberus instance?). \
             Lock and reopen it before saving so you do not overwrite those changes."
                .into(),
        ),
        // Unreadable *and* gone: the file we were editing has vanished (deleted,
        // moved, or its permissions changed). Surface it rather than silently
        // writing a fresh orphan file elsewhere.
        None if !open.path.exists() => {
            Err("the vault file is no longer accessible at its path".into())
        }
        // Unchanged, or momentarily unreadable but still present.
        _ => Ok(()),
    }
}

/// Combine Shamir shares from files and hex into the reconstructed secret.
fn reconstruct_shares(files: &[PathBuf], hex: &[String]) -> Result<Zeroizing<Vec<u8>>, String> {
    use cerberus_core::shamir::Share;

    let mut shares = Vec::new();
    for path in files {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("cannot read the share {}: {e}", path.display()))?;
        let (share, _, _) = Share::from_bytes(&bytes).map_err(|e| e.to_string())?;
        shares.push(share);
    }
    for h in hex.iter().filter(|h| !h.trim().is_empty()) {
        let (share, _, _) = Share::from_hex(h).map_err(|e| e.to_string())?;
        shares.push(share);
    }
    if shares.len() < 2 {
        return Err("at least 2 shares are needed to reconstruct".into());
    }
    cerberus_core::shamir::combine(&shares).map_err(|e| e.to_string())
}

/// An entry as the list and detail panes see it. Deliberately secret-free.
#[derive(Debug, Serialize)]
pub struct EntryView {
    pub id: Uuid,
    pub folder: Uuid,
    pub title: String,
    pub username: String,
    pub url: String,
    pub tags: Vec<String>,
    pub has_password: bool,
    pub has_totp: bool,
    pub has_notes: bool,
    pub password_length: usize,
    pub created_at: i64,
    pub modified_at: i64,
    pub expires_at: Option<i64>,
    pub expired: bool,
    pub history_count: usize,
    pub autotype_window: Option<String>,
    pub autotype_sequence: Option<String>,
    pub custom_fields: Vec<CustomFieldView>,
    pub trashed: bool,
    pub deleted_at: Option<i64>,
}

/// A custom field as the UI sees it.
///
/// Fields flagged secret arrive with `value: None` and are fetched one at a
/// time through [`entry_reveal_custom`], like a password.
#[derive(Debug, Serialize)]
pub struct CustomFieldView {
    pub name: String,
    pub value: Option<String>,
    pub secret: bool,
}

impl From<&Entry> for EntryView {
    fn from(e: &Entry) -> Self {
        EntryView {
            id: e.id,
            folder: e.folder,
            title: e.title.clone(),
            username: e.username.clone(),
            url: e.url.clone(),
            tags: e.tags.clone(),
            has_password: !e.password.is_empty(),
            has_totp: e.totp_secret.is_some(),
            has_notes: !e.notes.is_empty(),
            // The length is metadata the UI needs for its strength meter; it is
            // a far weaker disclosure than the password itself.
            password_length: e.password.chars().count(),
            created_at: e.created_at,
            modified_at: e.modified_at,
            expires_at: e.expires_at,
            expired: e.is_expired(),
            history_count: e.history.len(),
            autotype_window: e.autotype_window.clone(),
            autotype_sequence: e.autotype_sequence.clone(),
            custom_fields: e
                .custom_fields
                .iter()
                .map(|f| CustomFieldView {
                    name: f.name.clone(),
                    value: (!f.secret).then(|| f.value.clone()),
                    secret: f.secret,
                })
                .collect(),
            trashed: e.is_trashed(),
            deleted_at: e.deleted_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FolderView {
    pub id: Uuid,
    pub parent: Option<Uuid>,
    pub name: String,
    pub icon: String,
    pub entry_count: usize,
}

#[derive(Debug, Serialize)]
pub struct VaultInfo {
    pub name: String,
    pub path: String,
    pub root: Uuid,
    pub entry_count: usize,
    pub folder_count: usize,
    pub cascade: Vec<String>,
    pub dirty: bool,
}

/// What the unlock screen can learn about a vault before any factor is entered.
///
/// For a v2 vault the factors and cascade are encrypted, so `factors_known` is
/// false and the `needs_*` / `cascade` fields are meaningless — the UI must show
/// all factor options rather than pretend it knows.
#[derive(Debug, Serialize)]
pub struct VaultPeek {
    pub path: String,
    pub factors_known: bool,
    pub needs_password: bool,
    pub needs_pin: bool,
    pub needs_keyfile: bool,
    pub needs_pattern: bool,
    pub cascade: Vec<String>,
    pub kdf_memory_mib: u32,
    pub kdf_time_cost: u32,
}

// ---------------------------------------------------------------- app gate & config

#[derive(Debug, Serialize)]
pub struct GateStatus {
    /// A gate phrase protects the config.
    pub gate_set: bool,
    /// A config file exists at all.
    pub config_exists: bool,
}

#[tauri::command]
pub fn gate_status() -> GateStatus {
    GateStatus {
        gate_set: crate::appconfig::gate_is_set(),
        config_exists: crate::appconfig::exists(),
    }
}

/// Load the config, supplying the gate phrase if one is set. Called at startup.
///
/// Returns the config (recent vaults, prefs). A wrong phrase is reported so the
/// gate screen can ask again.
#[tauri::command]
pub fn gate_open(
    phrase: Option<String>,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let config = crate::appconfig::load(phrase.as_deref()).map_err(|e| e.to_string())?;
    let recent = config.recent_vaults.clone();
    let language = config.language.clone();
    state.set_config(config, phrase);
    Ok(serde_json::json!({ "recent_vaults": recent, "language": language }))
}

/// Persisted UI language code (e.g. "fr", "en"), or `None` to follow the system.
#[tauri::command]
pub fn get_language(state: State<'_, AppState>) -> Option<String> {
    state.config().language
}

/// Persist the chosen UI language. Saved with the gate phrase if one is set.
#[tauri::command]
pub fn set_language(code: Option<String>, state: State<'_, AppState>) -> Result<(), String> {
    state.update_config(|c| c.language = code)
}

/// Enable, change, or disable the gate phrase.
///
/// `new_phrase = None` disables it. When a gate is already set, `current` must
/// be the phrase in force and is verified by decrypting the config with it —
/// otherwise any IPC caller (a compromised webview, a malicious extension)
/// could disable the gate or overwrite the config without knowing the phrase,
/// as an independent audit found. Setting a gate for the first time needs no
/// `current`.
#[tauri::command]
pub fn gate_configure(
    current: Option<String>,
    new_phrase: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if let Some(p) = &new_phrase {
        if p.chars().count() < 6 {
            return Err("the gate phrase must be at least 6 characters".into());
        }
    }
    // Distinguish absent / cleartext / gated / corrupt so a tampered config
    // cannot be reconfigured as if no gate existed.
    match crate::appconfig::config_state() {
        crate::appconfig::ConfigState::Gated => {
            // Prove knowledge of the current phrase before changing/removing it.
            let current = current.ok_or("the current gate phrase is required")?;
            crate::appconfig::load(Some(&current))
                .map_err(|_| "the current gate phrase is incorrect".to_string())?;
        }
        crate::appconfig::ConfigState::Corrupt => {
            return Err("the configuration file is unreadable or corrupt; \
                        the gate cannot be reconfigured until it is restored or removed"
                .into());
        }
        // Absent or Plain: no gate in force, so a first-time set needs no proof.
        _ => {}
    }
    state.set_gate_phrase(new_phrase)
}

/// Recent vault paths, for the unlock screen's quick-open list.
#[tauri::command]
pub fn recent_vaults(state: State<'_, AppState>) -> Vec<String> {
    state.config().recent_vaults
}

// ---------------------------------------------------------------- vault lifecycle

#[tauri::command]
pub fn vault_peek(path: PathBuf, state: State<'_, AppState>) -> Result<VaultPeek, String> {
    let header = container::peek_header(&path).map_err(|e| e.to_string())?;
    let known = header.factors_known();
    let peek = VaultPeek {
        path: path.display().to_string(),
        factors_known: known,
        // Only meaningful for a v1 vault; a v2 peek cannot see the factors.
        needs_password: known && header.factor_flags & factors::flags::PASSWORD != 0,
        needs_pin: known && header.factor_flags & factors::flags::PIN != 0,
        needs_keyfile: known && header.factor_flags & factors::flags::KEYFILE != 0,
        needs_pattern: known && header.factor_flags & factors::flags::PATTERN != 0,
        cascade: if known {
            header
                .cascade
                .layers()
                .iter()
                .map(|a| a.display_name().to_string())
                .collect()
        } else {
            Vec::new()
        },
        kdf_memory_mib: header.kdf.memory_kib / 1024,
        kdf_time_cost: header.kdf.time_cost,
    };
    state.set_peeked(path, header);
    Ok(peek)
}

#[tauri::command]
pub fn vault_create(
    path: PathBuf,
    name: String,
    input: FactorInput,
    cascade: Vec<String>,
    kdf_profile: String,
    state: State<'_, AppState>,
) -> Result<VaultInfo, String> {
    if path.exists() {
        return Err("a file already exists at that location".into());
    }
    let path_str = path.display().to_string();
    let factors = input.build()?;
    let cascade = parse_cascade(&cascade)?;
    let kdf = parse_kdf_profile(&kdf_profile)?;

    let vault = Vault::new(name);
    let (key, header) =
        container::create_file(&path, &vault, &factors, cascade, kdf).map_err(|e| e.to_string())?;

    let info = describe(&vault, &path, &header.cascade, false);
    let fingerprint = fingerprint_on_disk(&path).unwrap_or_default();
    state.set_open(OpenVault {
        path,
        vault,
        key,
        header,
        idle: cerberus_core::session::IdleTracker::new(state.autolock_policy(), now_ms()),
        dirty: false,
        fingerprint,
    })?;
    let _ = state.update_config(|c| c.push_recent(&path_str));
    Ok(info)
}

/// One Shamir share, handed back to the UI so the user can store it.
///
/// All N shares cross to the frontend once, at creation, so the user can save
/// and distribute them. Below the threshold they reveal nothing; at creation the
/// secret is being made anyway, so this is not a new exposure.
#[derive(Debug, Serialize)]
pub struct ShareExport {
    pub index: u8,
    pub k: u8,
    pub n: u8,
    /// Suggested file name, e.g. `cerberus-part-2-sur-3.cbvshare`.
    pub filename: String,
    /// Group-formatted hex for the paper backup.
    pub hex: String,
    /// Raw share bytes, base64, so the UI can write the share file.
    pub file_b64: String,
}

/// Create a vault whose key-file factor is split into `n` Shamir shares, of which
/// `k` are needed to unlock. The base factors (password/PIN/pattern) still apply
/// on top. Returns the shares for the user to save and print.
#[tauri::command]
#[allow(clippy::too_many_arguments)] // Tauri command: parameters map to IPC args.
pub fn vault_create_shamir(
    path: PathBuf,
    name: String,
    input: FactorInput,
    k: u8,
    n: u8,
    cascade: Vec<String>,
    kdf_profile: String,
    state: State<'_, AppState>,
) -> Result<Vec<ShareExport>, String> {
    use base64::Engine;

    if path.exists() {
        return Err("a file already exists at that location".into());
    }
    let cascade_parsed = parse_cascade(&cascade)?;
    let kdf = parse_kdf_profile(&kdf_profile)?;

    // The Shamir secret is a fresh 32-byte key. It becomes the vault's key-file
    // factor; the user never sees it, only its shares.
    let secret = cerberus_core::random::vec(32).map_err(|e| e.to_string())?;
    let shares = cerberus_core::shamir::split(&secret, k, n).map_err(|e| e.to_string())?;

    // Build the factor set: the base factors, plus the reconstructed-secret as a
    // key file. Here we already hold the secret, so add it directly.
    let mut factors = input.build_base_only()?;
    factors = factors.with(Factor::Keyfile(Zeroizing::new(secret.clone())));

    let vault = Vault::new(name);
    let (key, header) = container::create_file(&path, &vault, &factors, cascade_parsed, kdf)
        .map_err(|e| e.to_string())?;

    let info_cascade = header.cascade.clone();
    let fingerprint = fingerprint_on_disk(&path).unwrap_or_default();
    state.set_open(OpenVault {
        path: path.clone(),
        vault,
        key,
        header,
        idle: cerberus_core::session::IdleTracker::new(state.autolock_policy(), now_ms()),
        dirty: false,
        fingerprint,
    })?;
    let _ = info_cascade;

    let b64 = base64::engine::general_purpose::STANDARD;
    let exports = shares
        .iter()
        .map(|s| ShareExport {
            index: s.x,
            k,
            n,
            filename: format!("cerberus-part-{}-sur-{}.cbvshare", s.x, n),
            hex: s.to_hex(k, n).to_string(),
            file_b64: b64.encode(&*s.to_bytes(k, n)),
        })
        .collect();

    Ok(exports)
}

/// Render a Shamir share's paper QR from its hex.
#[tauri::command]
pub fn share_qr(hex: String) -> Result<String, String> {
    crate::qr::svg(&hex)
}

/// Write a share file to disk from its base64 bytes (chosen by the user).
#[tauri::command]
pub fn share_save(path: PathBuf, file_b64: String) -> Result<(), String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(file_b64.as_bytes())
        .map_err(|e| format!("invalid share data: {e}"))?;
    std::fs::write(&path, &bytes).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn vault_unlock(
    path: PathBuf,
    input: FactorInput,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<VaultInfo, String> {
    // Adopt whatever penalty survived a previous run of the application, so
    // restarting Cerberus no longer wipes the delay.
    state.adopt_persisted_attempts(&path);

    // Refuse early while the throttle is still counting down.
    let waiting = state.throttle_remaining_ms(now_ms());
    if waiting > 0 {
        return Err(format!(
            "too many failed attempts: wait {} s",
            waiting.div_ceil(1000)
        ));
    }

    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    // Inspect the exact bytes that will be opened: peeking the path a second
    // time would permit a file-replacement race between approval and KDF.
    let header = container::peek_bytes(&bytes).map_err(|e| e.to_string())?;
    if header.kdf.memory_kib > KdfParams::HARDENED.memory_kib {
        let accepted = app
            .dialog()
            .message(format!(
                "This vault requests {} MiB of memory for key derivation. Continue only if you intended to use this high-cost profile.",
                header.kdf.memory_kib / 1024
            ))
            .title("High key-derivation cost")
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancel)
            .blocking_show();
        if !accepted {
            return Err("unlock cancelled before expensive key derivation".into());
        }
    }
    let factors = input.build()?;
    let fingerprint = fingerprint_bytes(&bytes);
    match container::open_keyed(&bytes, &factors) {
        Ok(opened) => {
            state.record_unlock_success();
            crate::attempts::clear(&path);
            let p = path.display().to_string();
            let _ = state.update_config(|c| c.push_recent(&p));
            let info = describe(&opened.vault, &path, &opened.header.cascade, false);
            state.set_open(OpenVault {
                path,
                vault: opened.vault,
                key: opened.key,
                header: opened.header,
                idle: cerberus_core::session::IdleTracker::new(state.autolock_policy(), now_ms()),
                dirty: false,
                fingerprint,
            })?;
            Ok(info)
        }
        Err(e) => {
            state.record_unlock_failure(now_ms());
            crate::attempts::record_failure(&path, now_ms());
            // Distinguish "this file is broken" from "these factors are wrong",
            // but never reveal *which* factor was wrong.
            Err(match e {
                cerberus_core::CoreError::Io(_)
                | cerberus_core::CoreError::BadMagic
                | cerberus_core::CoreError::UnsupportedVersion(_) => e.to_string(),
                _ => "unable to unlock: check your factors".to_string(),
            })
        }
    }
}

#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>) -> Result<(), String> {
    state.close();
    Ok(())
}

#[tauri::command]
pub fn vault_is_unlocked(state: State<'_, AppState>) -> bool {
    state.is_unlocked()
}

#[tauri::command]
pub fn vault_save(state: State<'_, AppState>) -> Result<(), String> {
    state.with_vault(|open| {
        guard_against_concurrent_change(open)?;
        // Uses the cached master key: no Argon2 pass, so this stays in the
        // millisecond range regardless of the vault's cost profile.
        container::write_to_file_with_key(&open.path, &open.vault, &open.key, &open.header)
            .map_err(|e| e.to_string())?;
        open.fingerprint = fingerprint_on_disk(&open.path).unwrap_or(open.fingerprint);
        open.dirty = false;
        Ok(())
    })
}

#[tauri::command]
pub fn vault_info(state: State<'_, AppState>) -> Result<VaultInfo, String> {
    state.with_vault(|open| {
        Ok(describe(
            &open.vault,
            &open.path,
            &open.header.cascade,
            open.dirty,
        ))
    })
}

/// Re-encrypt the vault under new factors, a new cascade, or new KDF settings.
///
/// A fresh salt and HKDF context are generated as a side effect of writing, so
/// the old factors stop working the moment this succeeds.
#[tauri::command]
pub fn vault_rekey(
    input: FactorInput,
    cascade: Vec<String>,
    kdf_profile: String,
    state: State<'_, AppState>,
) -> Result<VaultInfo, String> {
    let new_factors = input.build()?;
    let new_cascade = parse_cascade(&cascade)?;
    let new_kdf = parse_kdf_profile(&kdf_profile)?;

    state.with_vault(|open| {
        guard_against_concurrent_change(open)?;
        // Factors changed, so a fresh salt and a full derivation are required.
        let (key, header) =
            container::create_file(&open.path, &open.vault, &new_factors, new_cascade, new_kdf)
                .map_err(|e| e.to_string())?;
        open.key = key;
        open.header = header;
        open.fingerprint = fingerprint_on_disk(&open.path).unwrap_or(open.fingerprint);
        open.dirty = false;
        Ok(describe(
            &open.vault,
            &open.path,
            &open.header.cascade,
            false,
        ))
    })
}

// ---------------------------------------------------------------- browsing

#[tauri::command]
pub fn folders_list(state: State<'_, AppState>) -> Result<Vec<FolderView>, String> {
    state.with_vault(|open| {
        Ok(open
            .vault
            .folders
            .iter()
            .map(|f| FolderView {
                id: f.id,
                parent: f.parent,
                name: f.name.clone(),
                icon: f.icon.clone(),
                entry_count: open.vault.entries_in(f.id).len(),
            })
            .collect())
    })
}

#[tauri::command]
pub fn folder_create(
    parent: Uuid,
    name: String,
    state: State<'_, AppState>,
) -> Result<Uuid, String> {
    state.with_vault(|open| {
        let id = open
            .vault
            .add_folder(parent, name)
            .map_err(|e| e.to_string())?;
        open.dirty = true;
        Ok(id)
    })
}

#[tauri::command]
pub fn folder_delete(id: Uuid, state: State<'_, AppState>) -> Result<usize, String> {
    state.with_vault(|open| {
        let removed = open.vault.remove_folder(id).map_err(|e| e.to_string())?;
        open.dirty = true;
        Ok(removed)
    })
}

/// List entries, optionally filtered by folder and by a search query.
#[tauri::command]
pub fn entries_list(
    folder: Option<Uuid>,
    query: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<EntryView>, String> {
    state.with_vault(|open| {
        open.idle.touch(now_ms());
        let query = query.unwrap_or_default();
        let mut out: Vec<EntryView> = open
            .vault
            .search(&query)
            .into_iter()
            .filter(|e| folder.is_none_or(|f| e.folder == f))
            .map(EntryView::from)
            .collect();
        out.sort_by_key(|e| e.title.to_lowercase());
        Ok(out)
    })
}

// ---------------------------------------------------------------- entry editing

#[derive(Debug, Deserialize)]
pub struct EntryInput {
    pub folder: Uuid,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub totp: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub autotype_window: Option<String>,
    #[serde(default)]
    pub autotype_sequence: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomFieldInput>,
}

#[derive(Debug, Deserialize)]
pub struct CustomFieldInput {
    pub name: String,
    /// `None` means "keep whatever is stored", so the UI can submit a secret
    /// field it never received the value of.
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub secret: bool,
}

impl EntryInput {
    /// Validate the TOTP field before storing it, so a bad seed is rejected at
    /// entry time rather than discovered when a code is needed.
    fn totp_secret(&self) -> Result<Option<String>, String> {
        let Some(raw) = self.totp.as_ref().filter(|s| !s.trim().is_empty()) else {
            return Ok(None);
        };
        let raw = raw.trim();
        if raw.starts_with("otpauth://") {
            Totp::from_uri(raw).map_err(|e| e.to_string())?;
        } else {
            Totp::from_base32(raw).map_err(|e| e.to_string())?;
        }
        Ok(Some(raw.to_string()))
    }
}

/// Resolve submitted custom fields against what is already stored.
///
/// A field whose value is `None` keeps its existing value: that is how a secret
/// field survives an edit without ever being sent to the webview.
///
/// A free function rather than a method so the caller can take the submitted
/// fields out of `EntryInput` before consuming the rest of it.
fn resolve_custom_fields(
    submitted: &[CustomFieldInput],
    existing: &[CustomField],
) -> Vec<CustomField> {
    submitted
        .iter()
        .filter(|f| !f.name.trim().is_empty())
        .map(|f| CustomField {
            name: f.name.trim().to_string(),
            value: f.value.clone().unwrap_or_else(|| {
                existing
                    .iter()
                    .find(|e| e.name == f.name.trim())
                    .map(|e| e.value.clone())
                    .unwrap_or_default()
            }),
            secret: f.secret,
        })
        .collect()
}

#[tauri::command]
pub fn entry_create(input: EntryInput, state: State<'_, AppState>) -> Result<Uuid, String> {
    let totp = input.totp_secret()?;
    let custom = resolve_custom_fields(&input.custom_fields, &[]);
    state.with_vault(|open| {
        let mut e = Entry::new(input.folder, input.title);
        e.username = input.username;
        e.password = input.password;
        e.url = input.url;
        e.notes = input.notes;
        e.totp_secret = totp;
        e.tags = input.tags;
        e.expires_at = input.expires_at;
        e.autotype_window = input.autotype_window;
        e.autotype_sequence = input.autotype_sequence;
        e.custom_fields = custom;
        let id = open.vault.add_entry(e).map_err(|e| e.to_string())?;
        open.dirty = true;
        Ok(id)
    })
}

#[tauri::command]
pub fn entry_update(
    id: Uuid,
    mut input: EntryInput,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let totp = input.totp_secret()?;
    let submitted_fields = std::mem::take(&mut input.custom_fields);
    state.with_vault(|open| {
        let entry = open.vault.entry_mut(id).ok_or("unknown entry")?;
        entry.title = input.title;
        entry.username = input.username;
        entry.url = input.url;
        entry.notes = input.notes;
        entry.totp_secret = totp;
        entry.tags = input.tags;
        entry.folder = input.folder;
        entry.expires_at = input.expires_at;
        entry.autotype_window = input.autotype_window;
        entry.autotype_sequence = input.autotype_sequence;
        entry.custom_fields = resolve_custom_fields(&submitted_fields, &entry.custom_fields);
        // Route through set_password so the previous value lands in history.
        if entry.password != input.password {
            entry.set_password(input.password);
        }
        open.dirty = true;
        Ok(())
    })
}

/// Move an entry to the trash. Reversible.
#[tauri::command]
pub fn entry_delete(id: Uuid, state: State<'_, AppState>) -> Result<(), String> {
    state.with_vault(|open| {
        if !open.vault.trash_entry(id) {
            return Err("unknown entry".into());
        }
        open.dirty = true;
        Ok(())
    })
}

#[tauri::command]
pub fn entry_restore(id: Uuid, state: State<'_, AppState>) -> Result<(), String> {
    state.with_vault(|open| {
        if !open.vault.restore_entry(id) {
            return Err("this entry is not in the trash".into());
        }
        open.dirty = true;
        Ok(())
    })
}

/// Destroy a trashed entry for good.
#[tauri::command]
pub fn entry_purge(id: Uuid, state: State<'_, AppState>) -> Result<(), String> {
    state.with_vault(|open| {
        if !open.vault.purge_entry(id) {
            return Err("this entry is not in the trash".into());
        }
        open.dirty = true;
        Ok(())
    })
}

#[tauri::command]
pub fn trash_list(state: State<'_, AppState>) -> Result<Vec<EntryView>, String> {
    state.with_vault(|open| {
        Ok(open
            .vault
            .trashed()
            .into_iter()
            .map(EntryView::from)
            .collect())
    })
}

/// Empty the trash. Returns how many entries were destroyed.
#[tauri::command]
pub fn trash_empty(state: State<'_, AppState>) -> Result<usize, String> {
    state.with_vault(|open| {
        let purged = open.vault.purge_trash();
        open.dirty = purged > 0;
        Ok(purged)
    })
}

/// Which secret field a reveal or copy is asking for.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretField {
    Password,
    Username,
    Notes,
    Totp,
}

/// Hand a single secret to the frontend, on explicit user action only.
#[tauri::command]
pub fn entry_reveal(
    id: Uuid,
    field: SecretField,
    state: State<'_, AppState>,
) -> Result<String, String> {
    reveal(id, field, &state)
}

/// Shared by [`entry_reveal`] and [`entry_copy`] so both go through the same
/// single-secret path.
fn reveal(id: Uuid, field: SecretField, state: &AppState) -> Result<String, String> {
    state.with_vault(|open| {
        open.idle.touch(now_ms());
        let entry = open.vault.entry(id).ok_or("unknown entry")?;
        Ok(match field {
            SecretField::Password => entry.password.clone(),
            SecretField::Username => entry.username.clone(),
            SecretField::Notes => entry.notes.clone(),
            SecretField::Totp => current_totp(entry)?.to_string(),
        })
    })
}

/// Reveal one secret custom field, by name.
#[tauri::command]
pub fn entry_reveal_custom(
    id: Uuid,
    name: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    state.with_vault(|open| {
        open.idle.touch(now_ms());
        let entry = open.vault.entry(id).ok_or("unknown entry")?;
        entry
            .custom_fields
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.value.clone())
            .ok_or_else(|| "unknown field".to_string())
    })
}

/// Copy a custom field to the clipboard, with the same auto-wipe as a password.
#[tauri::command]
pub fn entry_copy_custom(
    id: Uuid,
    name: String,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<u64, String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;

    let secret = entry_reveal_custom(id, name, state.clone())?;
    app.clipboard()
        .write_text(secret.clone())
        .map_err(|e| e.to_string())?;
    state.arm_clipboard(&secret, now_ms());
    Ok(state.clipboard_policy().clear_after.as_secs())
}

/// Copy a secret to the clipboard and arm the auto-wipe timer.
#[tauri::command]
pub fn entry_copy(
    id: Uuid,
    field: SecretField,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<u64, String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;

    let secret = reveal(id, field, &state)?;
    app.clipboard()
        .write_text(secret.clone())
        .map_err(|e| e.to_string())?;
    state.arm_clipboard(&secret, now_ms());
    Ok(state.clipboard_policy().clear_after.as_secs())
}

/// Wipe the clipboard if it still holds the secret we put there.
///
/// Called on a timer by the frontend. The ownership check means a value the
/// user copied afterwards survives.
#[tauri::command]
pub fn clipboard_tick(app: tauri::AppHandle, state: State<'_, AppState>) -> Result<bool, String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;

    let current = app.clipboard().read_text().unwrap_or_default();
    if state.clipboard_due(&current, now_ms()) {
        app.clipboard()
            .write_text(String::new())
            .map_err(|e| e.to_string())?;
        return Ok(true);
    }
    Ok(false)
}

fn current_totp(entry: &Entry) -> Result<Zeroizing<String>, String> {
    let raw = entry.totp_secret.as_ref().ok_or("this entry has no TOTP")?;
    let totp = if raw.starts_with("otpauth://") {
        Totp::from_uri(raw)
    } else {
        Totp::from_base32(raw)
    }
    .map_err(|e| e.to_string())?;
    totp.code().map_err(|e| e.to_string())
}

#[derive(Debug, Serialize)]
pub struct TotpView {
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
}

#[tauri::command]
pub fn entry_totp(id: Uuid, state: State<'_, AppState>) -> Result<TotpView, String> {
    state.with_vault(|open| {
        let entry = open.vault.entry(id).ok_or("unknown entry")?;
        let raw = entry.totp_secret.as_ref().ok_or("this entry has no TOTP")?;
        let totp = if raw.starts_with("otpauth://") {
            Totp::from_uri(raw)
        } else {
            Totp::from_base32(raw)
        }
        .map_err(|e| e.to_string())?;
        Ok(TotpView {
            code: totp.code().map_err(|e| e.to_string())?.to_string(),
            seconds_remaining: totp.seconds_remaining(),
            period: totp.period,
        })
    })
}

/// Password history for one entry, newest first.
#[tauri::command]
pub fn entry_history(id: Uuid, state: State<'_, AppState>) -> Result<Vec<(String, i64)>, String> {
    state.with_vault(|open| {
        let entry = open.vault.entry(id).ok_or("unknown entry")?;
        Ok(entry
            .history
            .iter()
            .map(|h| (h.password.clone(), h.replaced_at))
            .collect())
    })
}

// ---------------------------------------------------------------- generation & audit

#[tauri::command]
pub fn generate_password(policy: PasswordPolicy) -> Result<serde_json::Value, String> {
    let pool = EntropyPool::new();
    let password = generator::password(&policy, &pool).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "password": password.to_string(),
        "bits": policy.entropy_bits(),
    }))
}

#[tauri::command]
pub fn generate_passphrase(
    words: usize,
    separator: String,
    capitalize: bool,
) -> Result<serde_json::Value, String> {
    let sep = separator.chars().next().unwrap_or('-');
    let pool = EntropyPool::new();
    let phrase = generator::passphrase(words, sep, capitalize, &pool).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "password": phrase.to_string(),
        "bits": generator::passphrase_bits(words),
    }))
}

#[tauri::command]
pub fn generate_keyfile(path: PathBuf) -> Result<(), String> {
    let bytes = factors::generate_keyfile().map_err(|e| e.to_string())?;
    std::fs::write(&path, &*bytes).map_err(|e| e.to_string())
}

#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub reused: Vec<EntryView>,
    pub expired: Vec<EntryView>,
    pub weak: Vec<EntryView>,
    pub without_totp: usize,
    pub total: usize,
}

/// Vault-wide hygiene report: reuse, expiry and short passwords.
#[tauri::command]
pub fn vault_audit(state: State<'_, AppState>) -> Result<AuditReport, String> {
    state.with_vault(|open| {
        Ok(AuditReport {
            reused: open
                .vault
                .reused_passwords()
                .into_iter()
                .map(EntryView::from)
                .collect(),
            expired: open
                .vault
                .expired_entries()
                .into_iter()
                .map(EntryView::from)
                .collect(),
            weak: open
                .vault
                .entries
                .iter()
                .filter(|e| !e.password.is_empty() && e.password.chars().count() < 12)
                .map(EntryView::from)
                .collect(),
            without_totp: open
                .vault
                .entries
                .iter()
                .filter(|e| e.totp_secret.is_none())
                .count(),
            total: open.vault.entries.len(),
        })
    })
}

/// Render arbitrary text as an SVG QR code.
///
/// Rendering happens in Rust and returns finished markup, so a secret never
/// passes through a JavaScript QR library.
#[tauri::command]
pub fn qr_svg(text: String) -> Result<String, String> {
    crate::qr::svg(&text)
}

/// QR code for an entry's TOTP, for enrolling another authenticator.
#[tauri::command]
pub fn entry_totp_qr(id: Uuid, state: State<'_, AppState>) -> Result<String, String> {
    let uri = state.with_vault(|open| {
        let entry = open.vault.entry(id).ok_or("unknown entry")?;
        let raw = entry.totp_secret.as_ref().ok_or("this entry has no TOTP")?;
        let mut totp = if raw.starts_with("otpauth://") {
            Totp::from_uri(raw)
        } else {
            Totp::from_base32(raw)
        }
        .map_err(|e| e.to_string())?;
        if totp.account.is_none() {
            totp.account = Some(entry.username.clone());
        }
        if totp.issuer.is_none() {
            totp.issuer = Some(entry.title.clone());
        }
        Ok(totp.to_uri())
    })?;
    crate::qr::svg(&uri)
}

// ---------------------------------------------------------------- import / export

/// Import a CSV export from another password manager.
#[tauri::command]
pub fn vault_import_csv(
    path: PathBuf,
    folder: Option<Uuid>,
    state: State<'_, AppState>,
) -> Result<cerberus_core::porting::ImportReport, String> {
    // Read raw bytes and decode ourselves: a Windows KeePass export is often
    // UTF-16 (with a BOM), which `read_to_string` rejects outright ("stream did
    // not contain valid UTF-8") — the import then just failed with a cryptic
    // error. Decode UTF-16 LE/BE by BOM, otherwise treat it as UTF-8.
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let csv = decode_text(&bytes);
    state.with_vault(|open| {
        let target = folder.unwrap_or(open.vault.root);
        let report = cerberus_core::porting::import_csv(&mut open.vault, &csv, target)
            .map_err(|e| e.to_string())?;
        open.dirty = report.imported > 0 || report.folders_created > 0;
        Ok(report)
    })
}

/// Decode a text file whose encoding we do not control (foreign CSV exports).
///
/// Handles the three encodings password managers actually emit on Windows:
/// UTF-16 little-endian and big-endian (detected by BOM), and UTF-8 (with or
/// without BOM). Anything else is read as UTF-8 lossily rather than refused —
/// losing one odd byte beats failing a whole migration.
fn decode_text(bytes: &[u8]) -> String {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => decode_utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => decode_utf16(rest, u16::from_be_bytes),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

fn decode_utf16(bytes: &[u8], to_u16: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| to_u16([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Export the vault as plaintext CSV, **after re-verifying the factors**.
///
/// The result is completely unprotected, so dumping it must take more than a
/// merely-unlocked session: the user re-supplies the vault's factors, which are
/// re-derived against the on-disk file before anything is written. An unlocked
/// session ridden by a compromised webview therefore cannot silently exfiltrate
/// every password in the clear — this mirrors the master-password re-prompt
/// that Bitwarden (same webview architecture) requires for export. The UI must
/// still warn that the output is unprotected, and the file destroyed after use.
#[tauri::command]
pub fn vault_export_csv(
    path: PathBuf,
    input: FactorInput,
    state: State<'_, AppState>,
) -> Result<usize, String> {
    // The re-authentication itself must obey the anti-bruteforce throttle, and a
    // wrong guess here must count exactly like a failed unlock. Otherwise this
    // command is an unthrottled oracle: an attacker riding an unlocked session
    // could loop `vault_export_csv` with candidate factors, at full Argon2 speed
    // but with no penalty, to recover the real factors. (Found in cross-audit.)
    // The throttle/attempt calls take the state lock, so they must stay *outside*
    // `with_vault`, which holds that same lock across its closure.
    let waiting = state.throttle_remaining_ms(now_ms());
    if waiting > 0 {
        return Err(format!(
            "too many failed attempts: wait {} s",
            waiting.div_ceil(1000)
        ));
    }
    let verify = input.build()?;

    // Re-authenticate against the *in-memory* vault, never a fresh disk read.
    //
    // A cross-audit (Gemini 3.1 Pro, C-01) found the previous version verified
    // the factors against `std::fs::read(vault_path)` and then exported
    // `open.vault` from RAM. Those are two different objects: an attacker on an
    // unlocked session could swap the `.cbv` on disk for one they own, pass
    // their own factors (which open the swapped file), and still receive a
    // cleartext dump of the victim's in-memory vault — bypassing the re-auth
    // entirely. We now re-derive the key from the supplied factors with the
    // header that belongs to the open vault and compare it, in constant time, to
    // the key actually protecting `open.vault`. The check and the exported data
    // are then the same object; there is no disk file to swap. The Argon2 pass
    // is still paid on purpose — proving knowledge of the factors is the gate.
    let vault_path = state.with_vault(|open| Ok(open.path.clone()))?;
    let exported = state.with_vault(|open| {
        let composite = verify.composite().map_err(|e| e.to_string())?;
        let candidate =
            cerberus_core::kdf::MasterKey::derive(&composite, &open.header.salt, open.header.kdf)
                .map_err(|e| e.to_string())?;
        if !candidate.same_key(&open.key) {
            return Ok(None);
        }
        let csv = cerberus_core::porting::export_csv(&open.vault);
        std::fs::write(&path, csv.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        Ok(Some(open.vault.live().count()))
    })?;

    match exported {
        Some(count) => {
            state.record_unlock_success();
            crate::attempts::clear(&vault_path);
            Ok(count)
        }
        None => {
            state.record_unlock_failure(now_ms());
            crate::attempts::record_failure(&vault_path, now_ms());
            Err("export refused: the factors do not match this vault".to_string())
        }
    }
}

/// Save an encrypted copy of the vault under its current factors.
///
/// A plain byte-for-byte copy: it opens with exactly the same factors as the
/// original, which is what makes it a usable backup.
#[tauri::command]
pub fn vault_backup(path: PathBuf, state: State<'_, AppState>) -> Result<(), String> {
    state.with_vault(|open| {
        container::write_to_file_with_key(&path, &open.vault, &open.key, &open.header)
            .map_err(|e| e.to_string())
    })
}

// ---------------------------------------------------------------- settings & session

#[tauri::command]
pub fn kdf_benchmark(profile: String) -> Result<u64, String> {
    let params = parse_kdf_profile(&profile)?;
    cerberus_core::kdf::benchmark(params)
        .map(|d| d.as_millis() as u64)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn cipher_catalogue() -> Vec<serde_json::Value> {
    CipherAlgo::ALL
        .iter()
        .map(|a| {
            serde_json::json!({
                "id": format!("{a:?}"),
                "name": a.display_name(),
            })
        })
        .collect()
}

#[tauri::command]
pub fn set_clipboard_seconds(seconds: u64, state: State<'_, AppState>) {
    let mut policy = state.clipboard_policy();
    policy.clear_after = std::time::Duration::from_secs(seconds.clamp(1, 600));
    state.set_clipboard_policy(policy);
}

#[tauri::command]
pub fn set_autolock_minutes(minutes: Option<u64>, state: State<'_, AppState>) {
    let mut policy = state.autolock_policy();
    policy.idle_timeout = minutes
        .filter(|m| *m > 0)
        .map(|m| std::time::Duration::from_secs(m * 60));
    state.set_autolock_policy(policy);
}

/// Report activity and ask whether the idle timer has expired.
///
/// The frontend polls this; the decision itself stays in Rust so a compromised
/// or stalled webview cannot keep the vault open indefinitely.
#[tauri::command]
pub fn session_tick(active: bool, state: State<'_, AppState>) -> Result<Option<u64>, String> {
    let now = now_ms();
    let mut should_lock = false;
    let remaining = state.with_vault(|open| {
        if active {
            open.idle.touch(now);
        }
        if open.idle.should_lock(now).is_some() {
            should_lock = true;
        }
        Ok(open.idle.seconds_until_lock(now))
    })?;

    if should_lock {
        state.close();
        return Err("locked after inactivity".into());
    }
    Ok(remaining)
}

#[tauri::command]
pub fn unlock_delay_remaining(state: State<'_, AppState>) -> serde_json::Value {
    serde_json::json!({
        "milliseconds": state.throttle_remaining_ms(now_ms()),
        "failures": state.failure_count(),
    })
}

/// Security self-check surfaced in Settings.
///
/// `memory_lock_failures` is non-zero when the OS refused to lock some key
/// pages into RAM (working-set quota exhausted), meaning that key material may
/// have become eligible for the page file. Previously this was measured but
/// never shown to anyone.
#[tauri::command]
pub fn security_status() -> serde_json::Value {
    serde_json::json!({
        "memory_lock_failures": cerberus_core::kdf::memory_lock_failures(),
    })
}

// ---------------------------------------------------------------- auto-type

/// Type an entry's credentials into whichever window has focus.
///
/// `sequence` overrides the entry's own sequence, so the UI can offer "username
/// only" or "password only" without storing a second sequence per entry.
///
/// The Cerberus window is minimised first: auto-type goes to the *focused*
/// window, and while the user is clicking a button in Cerberus, that window is
/// Cerberus. Minimising hands focus back to whatever was underneath.
#[tauri::command]
pub fn autotype(
    id: Uuid,
    sequence: Option<String>,
    window: tauri::Window,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let (entry_sequence, username, password, totp) = collect_autotype(id, &state)?;
    let chosen = sequence.unwrap_or(entry_sequence);

    let _ = window.minimize();
    // Let the compositor actually transfer focus before synthesising input.
    std::thread::sleep(std::time::Duration::from_millis(350));
    let target = crate::autotype::foreground_window()?;
    crate::autotype::run(&chosen, &username, &password, totp.as_deref(), &target)
}

/// Auto-type the entry whose window pattern matches the focused window.
///
/// This is the path the global hotkey takes: the user is already in the target
/// application, so nothing is minimised and nothing steals focus.
#[tauri::command]
pub fn autotype_focused(state: State<'_, AppState>) -> Result<String, String> {
    if !state.is_unlocked() {
        return Err("the vault is locked".into());
    }
    let target = crate::autotype::foreground_window()?;
    let title = target.title.clone();
    let matched = state.with_vault(|open| {
        Ok(open
            .vault
            .entries
            .iter()
            .find(|e| {
                e.autotype_window
                    .as_deref()
                    .is_some_and(|pattern| crate::autotype::window_matches(pattern, &title))
            })
            .map(|e| (e.id, e.title.clone())))
    })?;

    let Some((id, entry_title)) = matched else {
        return Err(format!(
            "no entry matches the active window (\"{}\")",
            title.chars().take(60).collect::<String>()
        ));
    };

    let (sequence, username, password, totp) = collect_autotype(id, &state)?;
    crate::autotype::run(&sequence, &username, &password, totp.as_deref(), &target)?;
    Ok(entry_title)
}

/// Gather everything auto-type needs, then release the vault lock before typing.
///
/// Typing takes hundreds of milliseconds; holding the state mutex across it
/// would stall every other command.
fn collect_autotype(
    id: Uuid,
    state: &AppState,
) -> Result<(String, String, String, Option<String>), String> {
    state.with_vault(|open| {
        let entry = open.vault.entry(id).ok_or("unknown entry")?;
        let totp = entry
            .totp_secret
            .as_ref()
            .and_then(|_| current_totp(entry).ok())
            .map(|c| c.to_string());
        Ok((
            entry
                .autotype_sequence
                .clone()
                .unwrap_or_else(|| crate::autotype::DEFAULT_SEQUENCE.to_string()),
            entry.username.clone(),
            entry.password.clone(),
            totp,
        ))
    })
}

/// The entry whose auto-type window pattern matches the focused window.
#[tauri::command]
pub fn autotype_match(state: State<'_, AppState>) -> Result<Option<EntryView>, String> {
    let title = crate::autotype::foreground_window()?.title;
    state.with_vault(|open| {
        Ok(open
            .vault
            .entries
            .iter()
            .find(|e| {
                e.autotype_window
                    .as_deref()
                    .is_some_and(|pattern| crate::autotype::window_matches(pattern, &title))
            })
            .map(EntryView::from))
    })
}

// ---------------------------------------------------------------- helpers

fn describe(vault: &Vault, path: &std::path::Path, cascade: &Cascade, dirty: bool) -> VaultInfo {
    VaultInfo {
        name: vault.name.clone(),
        path: path.display().to_string(),
        root: vault.root,
        entry_count: vault.entries.len(),
        folder_count: vault.folders.len(),
        cascade: cascade
            .layers()
            .iter()
            .map(|a| a.display_name().to_string())
            .collect(),
        dirty,
    }
}

fn parse_cascade(names: &[String]) -> Result<Cascade, String> {
    let layers = names
        .iter()
        .map(|n| {
            CipherAlgo::ALL
                .iter()
                .copied()
                .find(|a| format!("{a:?}").eq_ignore_ascii_case(n))
                .ok_or_else(|| format!("unknown cipher: {n}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Cascade::new(layers).map_err(|e| e.to_string())
}

fn parse_kdf_profile(profile: &str) -> Result<KdfParams, String> {
    match profile.to_ascii_lowercase().as_str() {
        "interactive" => Ok(KdfParams::INTERACTIVE),
        "hardened" => Ok(KdfParams::HARDENED),
        "paranoid" => Ok(KdfParams::PARANOID),
        other => Err(format!("unknown KDF profile: {other}")),
    }
}
