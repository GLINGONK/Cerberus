//! The in-memory vault: folders, entries, search.
//!
//! This is the plaintext structure. It only ever exists between a successful
//! unlock and the next lock, and it wipes its secret fields on drop.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CoreError, Result};

/// A single credential.
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Entry {
    #[zeroize(skip)]
    pub id: Uuid,
    #[zeroize(skip)]
    pub folder: Uuid,
    pub title: String,
    pub username: String,
    pub password: String,
    #[zeroize(skip)]
    pub url: String,
    pub notes: String,
    /// Base32 TOTP seed, when the entry carries a second factor of its own.
    pub totp_secret: Option<String>,
    #[zeroize(skip)]
    pub tags: Vec<String>,
    /// Window title pattern that auto-type matches against, e.g. `*GitHub*`.
    #[zeroize(skip)]
    pub autotype_window: Option<String>,
    /// Auto-type key sequence. Defaults to `{USERNAME}{TAB}{PASSWORD}{ENTER}`.
    #[zeroize(skip)]
    pub autotype_sequence: Option<String>,
    #[zeroize(skip)]
    pub created_at: i64,
    #[zeroize(skip)]
    pub modified_at: i64,
    /// Unix timestamp after which the UI nags the user to rotate this password.
    #[zeroize(skip)]
    pub expires_at: Option<i64>,
    /// Previous passwords, newest first. Capped by [`Entry::HISTORY_LIMIT`].
    pub history: Vec<PastPassword>,

    // Fields below were added after the first vaults were written. Every one is
    // `#[serde(default)]` so an older `.cbv` still deserialises unchanged.
    /// Arbitrary extra fields: licence keys, security answers, account numbers.
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    /// Set when the entry is in the trash. `None` means it is live.
    #[serde(default)]
    #[zeroize(skip)]
    pub deleted_at: Option<i64>,
}

/// A user-defined field on an entry.
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct CustomField {
    #[zeroize(skip)]
    pub name: String,
    pub value: String,
    /// Masked in the UI and excluded from search, like a password.
    #[serde(default)]
    #[zeroize(skip)]
    pub secret: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct PastPassword {
    pub password: String,
    #[zeroize(skip)]
    pub replaced_at: i64,
}

impl Entry {
    /// How many superseded passwords an entry keeps.
    ///
    /// Bounded on purpose: unbounded history is a slowly growing pile of
    /// plaintext secrets the user has forgotten about.
    pub const HISTORY_LIMIT: usize = 20;

    pub fn new(folder: Uuid, title: impl Into<String>) -> Self {
        let now = now_unix();
        Entry {
            id: Uuid::new_v4(),
            folder,
            title: title.into(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            totp_secret: None,
            tags: Vec::new(),
            autotype_window: None,
            autotype_sequence: None,
            created_at: now,
            modified_at: now,
            expires_at: None,
            history: Vec::new(),
            custom_fields: Vec::new(),
            deleted_at: None,
        }
    }

    pub fn is_trashed(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Replace the password, pushing the old one into history.
    pub fn set_password(&mut self, new_password: impl Into<String>) {
        let old = std::mem::replace(&mut self.password, new_password.into());
        if !old.is_empty() {
            self.history.insert(
                0,
                PastPassword {
                    password: old,
                    replaced_at: now_unix(),
                },
            );
            self.history.truncate(Self::HISTORY_LIMIT);
        }
        self.modified_at = now_unix();
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|t| t <= now_unix())
    }

    /// Does this entry match a free-text query?
    ///
    /// Passwords, notes and secret custom fields are deliberately excluded:
    /// typing a few characters should not silently confirm a guess about a
    /// stored secret.
    pub fn matches(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        self.title.to_lowercase().contains(&q)
            || self.username.to_lowercase().contains(&q)
            || self.url.to_lowercase().contains(&q)
            || self.tags.iter().any(|t| t.to_lowercase().contains(&q))
            || self.custom_fields.iter().any(|f| {
                f.name.to_lowercase().contains(&q)
                    || (!f.secret && f.value.to_lowercase().contains(&q))
            })
    }
}

/// A folder in the tree. `parent == None` marks the root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: Uuid,
    pub parent: Option<Uuid>,
    pub name: String,
    /// Icon identifier resolved by the UI.
    pub icon: String,
}

impl Folder {
    pub fn new(parent: Option<Uuid>, name: impl Into<String>) -> Self {
        Folder {
            id: Uuid::new_v4(),
            parent,
            name: name.into(),
            icon: "folder".into(),
        }
    }
}

/// The decrypted vault contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub name: String,
    pub folders: Vec<Folder>,
    pub entries: Vec<Entry>,
    pub root: Uuid,
}

impl Vault {
    pub fn new(name: impl Into<String>) -> Self {
        let root = Folder::new(None, "All entries");
        let root_id = root.id;
        Vault {
            name: name.into(),
            folders: vec![root],
            entries: Vec::new(),
            root: root_id,
        }
    }

    pub fn folder(&self, id: Uuid) -> Option<&Folder> {
        self.folders.iter().find(|f| f.id == id)
    }

    pub fn entry(&self, id: Uuid) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Live entries — everything not in the trash.
    pub fn live(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|e| !e.is_trashed())
    }

    /// Entries currently in the trash, most recently deleted first.
    pub fn trashed(&self) -> Vec<&Entry> {
        let mut out: Vec<&Entry> = self.entries.iter().filter(|e| e.is_trashed()).collect();
        out.sort_by_key(|e| std::cmp::Reverse(e.deleted_at.unwrap_or(0)));
        out
    }

    pub fn entry_mut(&mut self, id: Uuid) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    /// Direct children of a folder.
    pub fn children(&self, parent: Uuid) -> Vec<&Folder> {
        self.folders
            .iter()
            .filter(|f| f.parent == Some(parent))
            .collect()
    }

    /// Live entries filed directly under a folder.
    pub fn entries_in(&self, folder: Uuid) -> Vec<&Entry> {
        self.live().filter(|e| e.folder == folder).collect()
    }

    /// Search live entries. Trashed ones are never returned here.
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        if query.trim().is_empty() {
            return self.live().collect();
        }
        self.live().filter(|e| e.matches(query)).collect()
    }

    pub fn add_folder(&mut self, parent: Uuid, name: impl Into<String>) -> Result<Uuid> {
        if self.folder(parent).is_none() {
            return Err(CoreError::InvalidFactor("unknown parent folder".into()));
        }
        let folder = Folder::new(Some(parent), name);
        let id = folder.id;
        self.folders.push(folder);
        Ok(id)
    }

    /// Delete a folder, its subtree, and every entry inside it.
    ///
    /// Returns the number of entries removed so the UI can warn before committing.
    pub fn remove_folder(&mut self, id: Uuid) -> Result<usize> {
        if id == self.root {
            return Err(CoreError::InvalidFactor(
                "the root folder cannot be deleted".into(),
            ));
        }
        let mut doomed = vec![id];
        let mut i = 0;
        while i < doomed.len() {
            let current = doomed[i];
            for child in self.folders.iter().filter(|f| f.parent == Some(current)) {
                doomed.push(child.id);
            }
            i += 1;
        }
        // Entries go to the trash rather than vanishing: deleting a folder is
        // far too easy to do by accident to take its contents with it for good.
        let mut moved = 0;
        let now = now_unix();
        for entry in self.entries.iter_mut() {
            if doomed.contains(&entry.folder) && !entry.is_trashed() {
                entry.deleted_at = Some(now);
                moved += 1;
            }
        }
        self.folders.retain(|f| !doomed.contains(&f.id));
        Ok(moved)
    }

    pub fn add_entry(&mut self, entry: Entry) -> Result<Uuid> {
        if self.folder(entry.folder).is_none() {
            return Err(CoreError::InvalidFactor("unknown folder".into()));
        }
        let id = entry.id;
        self.entries.push(entry);
        Ok(id)
    }

    /// Move an entry to the trash. Reversible until it is purged.
    ///
    /// A password manager is exactly the wrong place for an irreversible
    /// one-click delete: the data it holds usually cannot be recreated.
    pub fn trash_entry(&mut self, id: Uuid) -> bool {
        match self.entry_mut(id) {
            Some(e) if !e.is_trashed() => {
                e.deleted_at = Some(now_unix());
                true
            }
            _ => false,
        }
    }

    /// Take an entry back out of the trash.
    ///
    /// If its folder was deleted meanwhile, it lands back in the root rather
    /// than becoming unreachable.
    pub fn restore_entry(&mut self, id: Uuid) -> bool {
        let root = self.root;
        let folder_exists = self
            .entry(id)
            .map(|e| e.folder)
            .is_some_and(|f| self.folder(f).is_some());
        match self.entry_mut(id) {
            Some(e) if e.is_trashed() => {
                e.deleted_at = None;
                if !folder_exists {
                    e.folder = root;
                }
                true
            }
            _ => false,
        }
    }

    /// Permanently delete a trashed entry. Not reversible.
    pub fn purge_entry(&mut self, id: Uuid) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| !(e.id == id && e.is_trashed()));
        before != self.entries.len()
    }

    /// Empty the trash. Returns how many entries were destroyed.
    pub fn purge_trash(&mut self) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| !e.is_trashed());
        before - self.entries.len()
    }

    /// Purge trashed entries deleted more than `max_age_days` ago.
    pub fn purge_trash_older_than(&mut self, max_age_days: i64) -> usize {
        let cutoff = now_unix() - max_age_days * 86_400;
        let before = self.entries.len();
        self.entries
            .retain(|e| !e.deleted_at.is_some_and(|t| t < cutoff));
        before - self.entries.len()
    }

    /// Entries whose password is shared with at least one other entry.
    ///
    /// Comparison runs over BLAKE3 digests so the audit never builds a list of
    /// plaintext passwords in memory.
    ///
    /// The digests are **keyed** with a fresh random key drawn per call: equal
    /// passwords still collide (so counting works), but the digests cannot be
    /// matched against a precomputed dictionary if one ever escaped the process.
    /// A plain unsalted hash of a password is trivially reversible for common
    /// choices (a cross-audit finding).
    pub fn reused_passwords(&self) -> Vec<&Entry> {
        use std::collections::HashMap;
        // The per-call key salts the digests so equal passwords collide only
        // within this one audit, never across calls. If the OS CSPRNG fails we
        // must NOT fall back to a fixed key ([0u8; 32] made the digests an
        // unsalted, dictionary-invertible hash — a cross-audit, Gemini C-04).
        // Fail closed: report nothing rather than offer a degraded audit.
        let Ok(key) = crate::random::bytes::<32>() else {
            return Vec::new();
        };
        let digest = |p: &str| *blake3::keyed_hash(&key, p.as_bytes()).as_bytes();
        let mut counts: HashMap<[u8; 32], usize> = HashMap::new();
        for e in self.live() {
            if e.password.is_empty() {
                continue;
            }
            *counts.entry(digest(&e.password)).or_default() += 1;
        }
        self.live()
            .filter(|e| {
                !e.password.is_empty() && counts.get(&digest(&e.password)).is_some_and(|&c| c > 1)
            })
            .collect()
    }

    pub fn expired_entries(&self) -> Vec<&Entry> {
        self.live().filter(|e| e.is_expired()).collect()
    }
}

/// Wipe every secret field when the vault is dropped (i.e. on lock).
impl Drop for Vault {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_with_entries() -> Vault {
        let mut v = Vault::new("test");
        let root = v.root;
        for (title, user, pass) in [
            ("GitHub", "octocat", "aaa"),
            ("GitLab", "fox", "bbb"),
            ("Bank", "me", "aaa"),
        ] {
            let mut e = Entry::new(root, title);
            e.username = user.into();
            e.password = pass.into();
            v.add_entry(e).unwrap();
        }
        v
    }

    /// A vault serialised before `custom_fields` and `deleted_at` existed must
    /// still deserialise. Every field added after v1 carries `#[serde(default)]`
    /// precisely so an older `.cbv` keeps opening.
    #[test]
    fn vaults_written_before_the_new_fields_still_load() {
        let legacy = r#"{
            "name": "ancien",
            "root": "11111111-1111-4111-8111-111111111111",
            "folders": [{
                "id": "11111111-1111-4111-8111-111111111111",
                "parent": null, "name": "All entries", "icon": "folder"
            }],
            "entries": [{
                "id": "22222222-2222-4222-8222-222222222222",
                "folder": "11111111-1111-4111-8111-111111111111",
                "title": "GitHub", "username": "octocat", "password": "hunter2",
                "url": "https://github.com", "notes": "", "totp_secret": null,
                "tags": [], "autotype_window": null, "autotype_sequence": null,
                "created_at": 1, "modified_at": 1, "expires_at": null, "history": []
            }]
        }"#;

        let vault: Vault = serde_json::from_str(legacy).expect("legacy vault failed to load");
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(vault.entries[0].password, "hunter2");
        assert!(vault.entries[0].custom_fields.is_empty());
        assert!(!vault.entries[0].is_trashed());
        assert_eq!(
            vault.search("").len(),
            1,
            "a legacy entry must count as live"
        );
    }

    #[test]
    fn a_new_vault_has_exactly_one_root() {
        let v = Vault::new("test");
        assert_eq!(v.folders.len(), 1);
        assert!(v.folder(v.root).unwrap().parent.is_none());
    }

    #[test]
    fn search_matches_titles_usernames_and_tags() {
        let v = vault_with_entries();
        assert_eq!(v.search("git").len(), 2);
        assert_eq!(v.search("octocat").len(), 1);
        assert_eq!(v.search("").len(), 3);
        assert_eq!(v.search("nothing here").len(), 0);
    }

    #[test]
    fn search_never_matches_on_the_password() {
        let v = vault_with_entries();
        assert_eq!(v.search("aaa").len(), 0, "search leaked a password match");
    }

    #[test]
    fn changing_a_password_records_history() {
        let mut v = vault_with_entries();
        let id = v.entries[0].id;
        v.entry_mut(id).unwrap().set_password("new secret");
        let e = v.entry(id).unwrap();
        assert_eq!(e.password, "new secret");
        assert_eq!(e.history.len(), 1);
        assert_eq!(e.history[0].password, "aaa");
    }

    #[test]
    fn history_stays_bounded() {
        let mut e = Entry::new(Uuid::new_v4(), "x");
        for i in 0..100 {
            e.set_password(format!("password-{i}"));
        }
        assert_eq!(e.history.len(), Entry::HISTORY_LIMIT);
        // Newest first: the most recently replaced password heads the list.
        assert_eq!(e.history[0].password, "password-98");
    }

    #[test]
    fn deleting_an_entry_only_trashes_it() {
        let mut v = vault_with_entries();
        let id = v.entries[0].id;

        assert!(v.trash_entry(id));
        assert_eq!(
            v.search("").len(),
            2,
            "trashed entries must not appear in listings"
        );
        assert_eq!(v.trashed().len(), 1);
        assert_eq!(v.entries.len(), 3, "the entry itself is still stored");

        assert!(v.restore_entry(id));
        assert_eq!(v.search("").len(), 3);
        assert!(v.trashed().is_empty());
    }

    #[test]
    fn purging_is_the_only_irreversible_delete() {
        let mut v = vault_with_entries();
        let id = v.entries[0].id;

        // A live entry cannot be purged: it has to be trashed first.
        assert!(!v.purge_entry(id));
        assert_eq!(v.entries.len(), 3);

        v.trash_entry(id);
        assert!(v.purge_entry(id));
        assert_eq!(v.entries.len(), 2);
        assert!(v.entry(id).is_none());
    }

    #[test]
    fn emptying_the_trash_leaves_live_entries_alone() {
        let mut v = vault_with_entries();
        v.trash_entry(v.entries[0].id);
        v.trash_entry(v.entries[1].id);
        assert_eq!(v.purge_trash(), 2);
        assert_eq!(v.entries.len(), 1);
    }

    #[test]
    fn old_trash_can_be_purged_by_age() {
        let mut v = vault_with_entries();
        let recent = v.entries[0].id;
        let ancient = v.entries[1].id;
        v.trash_entry(recent);
        v.trash_entry(ancient);
        // Backdate one deletion by 60 days.
        v.entry_mut(ancient).unwrap().deleted_at = Some(now_unix() - 60 * 86_400);

        assert_eq!(v.purge_trash_older_than(30), 1);
        assert!(v.entry(ancient).is_none());
        assert!(v.entry(recent).is_some());
    }

    #[test]
    fn restoring_into_a_deleted_folder_falls_back_to_the_root() {
        let mut v = Vault::new("test");
        let root = v.root;
        let folder = v.add_folder(root, "Work").unwrap();
        let id = v.add_entry(Entry::new(folder, "ssh")).unwrap();

        v.remove_folder(folder).unwrap();
        assert!(v.restore_entry(id));
        assert_eq!(
            v.entry(id).unwrap().folder,
            root,
            "restored entry became unreachable"
        );
        assert_eq!(v.entries_in(root).len(), 1);
    }

    #[test]
    fn audits_ignore_the_trash() {
        let mut v = vault_with_entries();
        // "aaa" is shared by entries 0 and 2; trashing one ends the reuse.
        v.trash_entry(v.entries[0].id);
        assert!(v.reused_passwords().is_empty());
    }

    #[test]
    fn custom_fields_are_searchable_unless_marked_secret() {
        let mut v = Vault::new("test");
        let root = v.root;
        let mut e = Entry::new(root, "Router");
        e.custom_fields = vec![
            CustomField {
                name: "Serial number".into(),
                value: "SN-4471".into(),
                secret: false,
            },
            CustomField {
                name: "Code PUK".into(),
                value: "998877".into(),
                secret: true,
            },
        ];
        v.add_entry(e).unwrap();

        assert_eq!(
            v.search("SN-4471").len(),
            1,
            "public custom values should be searchable"
        );
        assert_eq!(
            v.search("Serial").len(),
            1,
            "field names should be searchable"
        );
        assert_eq!(
            v.search("PUK").len(),
            1,
            "secret field names are not the secret"
        );
        assert_eq!(
            v.search("998877").len(),
            0,
            "a secret value leaked through search"
        );
    }

    #[test]
    fn deleting_a_folder_takes_its_subtree_with_it() {
        let mut v = Vault::new("test");
        let root = v.root;
        let parent = v.add_folder(root, "Work").unwrap();
        let child = v.add_folder(parent, "Servers").unwrap();
        v.add_entry(Entry::new(child, "ssh")).unwrap();
        v.add_entry(Entry::new(root, "kept")).unwrap();

        assert_eq!(v.remove_folder(parent).unwrap(), 1);
        assert_eq!(v.folders.len(), 1);
        // The folder is gone, but its entry went to the trash rather than away.
        assert_eq!(v.search("").len(), 1);
        assert_eq!(v.search("")[0].title, "kept");
        assert_eq!(v.trashed().len(), 1);
        assert_eq!(v.trashed()[0].title, "ssh");
    }

    #[test]
    fn the_root_folder_cannot_be_deleted() {
        let mut v = Vault::new("test");
        let root = v.root;
        assert!(v.remove_folder(root).is_err());
    }

    #[test]
    fn entries_cannot_be_filed_in_a_folder_that_does_not_exist() {
        let mut v = Vault::new("test");
        assert!(v.add_entry(Entry::new(Uuid::new_v4(), "orphan")).is_err());
    }

    #[test]
    fn reuse_audit_flags_shared_passwords_only() {
        let v = vault_with_entries();
        let reused = v.reused_passwords();
        assert_eq!(reused.len(), 2);
        assert!(reused.iter().all(|e| e.password == "aaa"));
    }

    #[test]
    fn expiry_is_reported() {
        let mut v = Vault::new("test");
        let root = v.root;
        let mut old = Entry::new(root, "old");
        old.expires_at = Some(0);
        let mut fresh = Entry::new(root, "fresh");
        fresh.expires_at = Some(i64::MAX);
        v.add_entry(old).unwrap();
        v.add_entry(fresh).unwrap();
        assert_eq!(v.expired_entries().len(), 1);
        assert_eq!(v.expired_entries()[0].title, "old");
    }
}
