//! CSV import and export.
//!
//! CSV is the one format every password manager can produce: KeePass, Bitwarden,
//! 1Password, Chrome, Firefox and Edge all export it. Parsing KDBX directly
//! would cover only KeePass, for far more work.
//!
//! **Exported CSV is plaintext.** Nothing here pretends otherwise; the caller is
//! expected to warn the user and the file should be destroyed after use.

use std::collections::HashMap;

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::vault::{Entry, Vault};

/// Columns Cerberus writes, and the ones it looks for on import.
const COLUMNS: [&str; 7] = [
    "folder", "title", "username", "password", "url", "notes", "totp",
];
const ESCAPE_MARKER: &str = "cerberus_csv_escape_v1";

/// Header spellings used by other password managers, mapped to our column names.
///
/// Matching is case-insensitive and ignores spaces and underscores, so
/// `"Login Name"`, `"login_name"` and `"loginname"` all resolve identically.
fn alias(header: &str) -> Option<&'static str> {
    let normalised: String = header
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '_' && *c != '-')
        .collect::<String>()
        .to_lowercase();

    Some(match normalised.as_str() {
        "folder" | "group" | "grouping" | "category" | "path" => "folder",
        "title" | "name" | "account" | "accountname" | "item" | "itemname" => "title",
        "username" | "user" | "login" | "loginname" | "email" | "usernamefield" => "username",
        "password" | "pass" | "loginpassword" | "passwordfield" => "password",
        "url" | "uri" | "website" | "site" | "loginuri" | "weblogin" => "url",
        "notes" | "note" | "comment" | "comments" | "extra" => "notes",
        "totp" | "otp" | "otpauth" | "logintotp" | "twofactor" | "authkey" => "totp",
        _ => return None,
    })
}

/// Serialise a vault to CSV.
///
/// Trashed entries are skipped: exporting the bin would quietly resurrect
/// things the user deleted.
pub fn export_csv(vault: &Vault) -> Zeroizing<String> {
    let folder_names: HashMap<Uuid, String> = vault
        .folders
        .iter()
        .map(|f| (f.id, folder_path(vault, f.id)))
        .collect();

    let mut out = String::new();
    out.push_str(&COLUMNS.join(","));
    out.push(',');
    out.push_str(ESCAPE_MARKER);
    out.push('\n');

    for entry in vault.live() {
        let row = [
            folder_names.get(&entry.folder).cloned().unwrap_or_default(),
            entry.title.clone(),
            entry.username.clone(),
            entry.password.clone(),
            entry.url.clone(),
            entry.notes.clone(),
            entry.totp_secret.clone().unwrap_or_default(),
        ];
        out.push_str(
            &row.iter()
                .map(|f| quote(&spreadsheet_safe(f)))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str(",1");
        out.push('\n');
    }

    Zeroizing::new(out)
}

/// Slash-separated path of a folder, root excluded.
fn folder_path(vault: &Vault, id: Uuid) -> String {
    let mut parts = Vec::new();
    let mut current = Some(id);
    // Bounded by the folder count: a corrupted parent cycle cannot hang this.
    for _ in 0..vault.folders.len() {
        let Some(folder) = current.and_then(|c| vault.folder(c)) else {
            break;
        };
        if folder.parent.is_none() {
            break;
        }
        parts.push(folder.name.clone());
        current = folder.parent;
    }
    parts.reverse();
    parts.join("/")
}

/// Wrap a field in quotes when it contains a delimiter, quote or newline.
fn quote(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Prevent CSV consumers such as Excel from treating vault data as a formula.
/// Two apostrophes make the encoding reversible without confusing a legitimate
/// value that already starts with one apostrophe. Values already starting with
/// the escape prefix are escaped too, keeping the mapping one-to-one.
fn spreadsheet_safe(field: &str) -> String {
    let dangerous = field
        .chars()
        .next()
        .is_some_and(|c| matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r'));
    if dangerous || field.starts_with("''") {
        format!("''{field}")
    } else {
        field.to_string()
    }
}

fn spreadsheet_unescape(field: String) -> String {
    field
        .strip_prefix("''")
        .map_or_else(|| field.clone(), str::to_string)
}

/// What an import did, so the UI can report it honestly.
#[derive(Debug, Default, serde::Serialize)]
pub struct ImportReport {
    pub imported: usize,
    pub skipped: usize,
    pub folders_created: usize,
    /// Human-readable reasons rows were skipped, capped so a bad file cannot
    /// produce an unbounded error list.
    pub problems: Vec<String>,
}

/// Parse CSV and add its rows to `vault`.
///
/// Unknown columns are ignored, missing ones are treated as empty. A row is
/// skipped only when it has no title *and* no username — anything else is
/// imported, because losing a row silently during a migration is worse than
/// importing an imperfect one.
pub fn import_csv(vault: &mut Vault, csv: &str, into: Uuid) -> Result<ImportReport> {
    let rows = parse_csv(csv)?;
    let mut rows = rows.into_iter();

    let header = rows
        .next()
        .ok_or_else(|| CoreError::InvalidFactor("the file is empty".into()))?;
    let cerberus_escaped = header.iter().any(|name| name == ESCAPE_MARKER);

    // Map each of our column names to its index in this particular file.
    let mut index: HashMap<&str, usize> = HashMap::new();
    for (i, name) in header.iter().enumerate() {
        if let Some(column) = alias(name) {
            index.entry(column).or_insert(i);
        }
    }
    if !index.contains_key("title") && !index.contains_key("username") {
        return Err(CoreError::InvalidFactor(
            "no recognisable column: the file needs at least a title or a username".into(),
        ));
    }

    let mut report = ImportReport::default();
    let mut folder_cache: HashMap<String, Uuid> = HashMap::new();

    for (line, row) in rows.enumerate() {
        let get = |column: &str| -> String {
            index
                .get(column)
                .and_then(|i| row.get(*i))
                .cloned()
                .map(|field| {
                    if cerberus_escaped {
                        spreadsheet_unescape(field)
                    } else {
                        field
                    }
                })
                .unwrap_or_default()
        };

        let title = get("title");
        let username = get("username");
        if title.trim().is_empty() && username.trim().is_empty() {
            report.skipped += 1;
            continue;
        }

        let folder = match get("folder").trim() {
            "" => into,
            path => match ensure_folder(vault, into, path, &mut folder_cache, &mut report) {
                Ok(id) => id,
                Err(_) => into,
            },
        };

        let mut entry = Entry::new(
            folder,
            if title.trim().is_empty() {
                username.clone()
            } else {
                title
            },
        );
        entry.username = username;
        entry.password = get("password");
        entry.url = get("url");
        entry.notes = get("notes");

        let totp = get("totp");
        if !totp.trim().is_empty() {
            // Validate before storing: a bad seed imported silently only shows
            // up later, when a code is actually needed.
            let parsed = if totp.starts_with("otpauth://") {
                crate::totp::Totp::from_uri(&totp)
            } else {
                crate::totp::Totp::from_base32(&totp)
            };
            match parsed {
                Ok(_) => entry.totp_secret = Some(totp),
                Err(_) if report.problems.len() < 20 => report.problems.push(format!(
                    "line {}: unreadable TOTP secret, imported without it",
                    line + 2
                )),
                Err(_) => {}
            }
        }

        vault.add_entry(entry)?;
        report.imported += 1;
    }

    Ok(report)
}

/// Find or create the folder chain described by a slash-separated path.
fn ensure_folder(
    vault: &mut Vault,
    root: Uuid,
    path: &str,
    cache: &mut HashMap<String, Uuid>,
    report: &mut ImportReport,
) -> Result<Uuid> {
    if let Some(id) = cache.get(path) {
        return Ok(*id);
    }

    let mut current = root;
    let mut walked = String::new();
    for part in path.split(['/', '\\']).filter(|p| !p.trim().is_empty()) {
        if !walked.is_empty() {
            walked.push('/');
        }
        walked.push_str(part);

        if let Some(id) = cache.get(&walked) {
            current = *id;
            continue;
        }
        let existing = vault
            .children(current)
            .into_iter()
            .find(|f| f.name.eq_ignore_ascii_case(part.trim()))
            .map(|f| f.id);

        current = match existing {
            Some(id) => id,
            None => {
                report.folders_created += 1;
                vault.add_folder(current, part.trim())?
            }
        };
        cache.insert(walked.clone(), current);
    }

    cache.insert(path.to_string(), current);
    Ok(current)
}

/// Minimal RFC 4180 parser: quoted fields, doubled quotes, embedded newlines.
///
/// Written here rather than pulled in as a dependency: it is sixty lines, and
/// every crate added to this project gets access to decrypted secrets.
fn parse_csv(input: &str) -> Result<Vec<Vec<String>>> {
    // Strip a UTF-8 BOM: Excel puts one in front of every file it writes.
    let input = input.trim_start_matches('\u{feff}');
    let delim = detect_delimiter(input);

    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            c if c == delim && !in_quotes => row.push(std::mem::take(&mut field)),
            '\r' if !in_quotes => {
                // Swallow CRLF as a single terminator.
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            '\n' if !in_quotes => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            other => field.push(other),
        }
    }

    if in_quotes {
        return Err(CoreError::InvalidFactor(
            "malformed CSV: a quoted field is never closed".into(),
        ));
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }

    // Drop trailing blank lines.
    rows.retain(|r| !(r.len() == 1 && r[0].trim().is_empty()));
    Ok(rows)
}

/// Sniff the field delimiter from the header line.
///
/// Cerberus writes commas, but real-world exports don't always. KeePass on a
/// European Windows locale exports **semicolon**-separated CSV, and some tools
/// emit tabs. Parsing such a file with a hard-coded comma yields a single giant
/// column, so no header matches and the import fails outright. We pick, among
/// `,` `;` and tab, whichever appears most on the first line *outside* quotes —
/// falling back to comma when there's nothing to go on.
fn detect_delimiter(input: &str) -> char {
    let header: String = {
        let mut in_quotes = false;
        let mut out = String::new();
        for c in input.chars() {
            match c {
                '"' => in_quotes = !in_quotes,
                '\n' | '\r' if !in_quotes => break,
                _ if !in_quotes => out.push(c),
                _ => {}
            }
        }
        out
    };
    [',', ';', '\t']
        .into_iter()
        .max_by_key(|&d| header.matches(d).count())
        .filter(|&d| header.contains(d))
        .unwrap_or(',')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vault {
        let mut v = Vault::new("test");
        let root = v.root;
        let work = v.add_folder(root, "Travail").unwrap();
        let servers = v.add_folder(work, "Serveurs").unwrap();

        let mut a = Entry::new(root, "GitHub");
        a.username = "octocat".into();
        a.password = "hunter2".into();
        a.url = "https://github.com".into();
        v.add_entry(a).unwrap();

        let mut b = Entry::new(servers, "SSH prod");
        b.username = "root".into();
        b.password = "p@ss,\"word\"\nsecond line".into();
        b.notes = "attention".into();
        v.add_entry(b).unwrap();
        v
    }

    #[test]
    fn export_then_import_preserves_everything() {
        let original = sample();
        let csv = export_csv(&original);

        let mut restored = Vault::new("restored");
        let root = restored.root;
        let report = import_csv(&mut restored, &csv, root).unwrap();

        assert_eq!(report.imported, 2);
        assert_eq!(report.skipped, 0);

        let ssh = restored.search("SSH prod");
        assert_eq!(ssh.len(), 1);
        // The nastiest field: commas, quotes and a newline all at once.
        assert_eq!(ssh[0].password, "p@ss,\"word\"\nsecond line");
        assert_eq!(ssh[0].notes, "attention");

        // The folder hierarchy came back from the path column.
        assert_eq!(folder_path(&restored, ssh[0].folder), "Travail/Serveurs");
    }

    #[test]
    fn spreadsheet_formulas_are_neutralised_and_round_trip_losslessly() {
        let mut original = Vault::new("test");
        let root = original.root;
        let mut entry = Entry::new(root, "=HYPERLINK(\"https://invalid\")");
        entry.username = "+cmd".into();
        entry.password = "-1+2".into();
        entry.url = "@SUM(A1:A2)".into();
        entry.notes = "''already escaped".into();
        original.add_entry(entry).unwrap();

        let csv = export_csv(&original);
        for dangerous in ["''=HYPERLINK", "''+cmd", "''-1+2", "''@SUM"] {
            assert!(csv.contains(dangerous));
        }

        let mut restored = Vault::new("restored");
        let restored_root = restored.root;
        import_csv(&mut restored, &csv, restored_root).unwrap();
        let entry = &restored.entries[0];
        assert_eq!(entry.title, "=HYPERLINK(\"https://invalid\")");
        assert_eq!(entry.username, "+cmd");
        assert_eq!(entry.password, "-1+2");
        assert_eq!(entry.url, "@SUM(A1:A2)");
        assert_eq!(entry.notes, "''already escaped");
    }

    #[test]
    fn foreign_csv_values_are_not_mistaken_for_our_escape_format() {
        let csv = "title,username\n''literal,user\n";
        let mut vault = Vault::new("import");
        let root = vault.root;
        import_csv(&mut vault, csv, root).unwrap();
        assert_eq!(vault.entries[0].title, "''literal");
    }

    #[test]
    fn foreign_header_names_are_recognised() {
        let csv = "\"Group\",\"Name\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\
                   \"Perso\",\"Banque\",\"jean\",\"secret123\",\"https://banque.fr\",\"note\"\n";
        let mut v = Vault::new("x");
        let root = v.root;
        let report = import_csv(&mut v, csv, root).unwrap();

        assert_eq!(report.imported, 1);
        let e = &v.search("Banque")[0];
        assert_eq!(e.username, "jean");
        assert_eq!(e.password, "secret123");
        assert_eq!(e.url, "https://banque.fr");
        assert_eq!(e.notes, "note");
        assert_eq!(folder_path(&v, e.folder), "Perso");
    }

    #[test]
    fn semicolon_delimited_export_is_recognised() {
        // KeePass on a European Windows locale writes ';'-separated CSV.
        let csv = "Group;Title;Username;Password;URL;Notes\n\
                   Perso;Banque;jean;secret123;https://banque.fr;note\n";
        let mut v = Vault::new("x");
        let root = v.root;
        let report = import_csv(&mut v, csv, root).unwrap();
        assert_eq!(report.imported, 1);
        let e = &v.search("Banque")[0];
        assert_eq!(e.username, "jean");
        assert_eq!(e.password, "secret123");
    }

    #[test]
    fn tab_delimited_export_is_recognised() {
        let csv = "Title\tUsername\tPassword\nBanque\tjean\tsecret123\n";
        let mut v = Vault::new("x");
        let root = v.root;
        let report = import_csv(&mut v, csv, root).unwrap();
        assert_eq!(report.imported, 1);
        assert_eq!(v.search("Banque")[0].password, "secret123");
    }

    #[test]
    fn a_comma_in_a_quoted_field_does_not_pick_the_wrong_delimiter() {
        // Comma-delimited file whose values contain semicolons must still parse
        // as comma-delimited (the header has no semicolons to mislead us).
        let csv = "title,notes\nSite,\"a; b; c\"\n";
        let mut v = Vault::new("x");
        let root = v.root;
        let report = import_csv(&mut v, csv, root).unwrap();
        assert_eq!(report.imported, 1);
        assert_eq!(v.search("Site")[0].notes, "a; b; c");
    }

    #[test]
    fn chrome_style_export_is_recognised() {
        // Chrome writes exactly these headers.
        let csv = "name,url,username,password,note\n\
                   example.com,https://example.com,me@example.com,pw123,\n";
        let mut v = Vault::new("x");
        let root = v.root;
        assert_eq!(import_csv(&mut v, csv, root).unwrap().imported, 1);
        assert_eq!(v.search("example.com")[0].username, "me@example.com");
    }

    #[test]
    fn rows_without_a_title_or_username_are_skipped() {
        let csv = "title,username,password\n,,orphan\nReal,user,pw\n";
        let mut v = Vault::new("x");
        let root = v.root;
        let report = import_csv(&mut v, csv, root).unwrap();
        assert_eq!(report.imported, 1);
        assert_eq!(report.skipped, 1);
    }

    #[test]
    fn a_bad_totp_is_reported_not_swallowed() {
        let csv = "title,totp\nA,not-base32!!\nB,GEZDGNBVGY3TQOJQ\n";
        let mut v = Vault::new("x");
        let root = v.root;
        let report = import_csv(&mut v, csv, root).unwrap();

        assert_eq!(report.imported, 2);
        assert_eq!(report.problems.len(), 1);
        assert!(report.problems[0].contains("line 2"));
        assert!(v.search("A")[0].totp_secret.is_none());
        assert!(v.search("B")[0].totp_secret.is_some());
    }

    #[test]
    fn folders_are_reused_not_duplicated() {
        let csv = "folder,title\nA/B,one\nA/B,two\nA/C,three\n";
        let mut v = Vault::new("x");
        let root = v.root;
        let report = import_csv(&mut v, csv, root).unwrap();
        assert_eq!(report.imported, 3);
        // root + A + B + C
        assert_eq!(v.folders.len(), 4);
        assert_eq!(report.folders_created, 3);
    }

    #[test]
    fn the_trash_is_not_exported() {
        let mut v = sample();
        let id = v.search("GitHub")[0].id;
        v.trash_entry(id);
        let csv = export_csv(&v);
        assert!(!csv.contains("GitHub"), "a trashed entry was exported");
        assert!(csv.contains("SSH prod"));
    }

    #[test]
    fn malformed_input_is_refused_rather_than_guessed() {
        let mut v = Vault::new("x");
        let root = v.root;
        assert!(import_csv(&mut v, "", root).is_err(), "empty file");
        assert!(
            import_csv(&mut v, "a,b,c\n1,2,3\n", root).is_err(),
            "no known column"
        );
        assert!(
            import_csv(&mut v, "title\n\"unterminated\n", root).is_err(),
            "unclosed quote"
        );
    }

    #[test]
    fn crlf_and_a_bom_are_handled() {
        let csv = "\u{feff}title,username\r\nSite,user\r\n";
        let mut v = Vault::new("x");
        let root = v.root;
        assert_eq!(import_csv(&mut v, csv, root).unwrap().imported, 1);
        assert_eq!(v.search("Site").len(), 1);
    }
}
