//! Global auto-type for Windows.
//!
//! Synthesises keystrokes into the focused window with `SendInput`, using
//! `KEYEVENTF_UNICODE` so the typed text does not depend on the active keyboard
//! layout — a layout-dependent implementation silently mangles passwords
//! containing symbols.
//!
//! Threat note: auto-type hands a password to whatever window happens to be in
//! front. The window-title match is a convenience for the user, not a security
//! boundary — malware can name its window anything it likes.

/// Typed when an entry defines no sequence of its own.
pub const DEFAULT_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";

/// One step of an expanded auto-type sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Text(String),
    Tab,
    Enter,
    Delay(u64),
}

/// Snapshot of the exact window that was in front when auto-type was armed.
#[derive(Debug, Clone)]
pub struct ForegroundWindow {
    id: isize,
    /// Owning process id, captured alongside the handle. Windows recycles HWND
    /// values, so a destroyed target's handle can be reassigned to another
    /// window mid-sequence; requiring the *same process* as well makes a bare
    /// handle collision no longer enough to redirect keystrokes.
    pid: u32,
    pub title: String,
}

/// Expand a sequence into concrete actions.
///
/// Placeholders are substituted here rather than by string replacement so a
/// password that happens to contain `{TAB}` is typed literally instead of being
/// re-interpreted as a keystroke.
pub fn parse(
    sequence: &str,
    username: &str,
    password: &str,
    totp: Option<&str>,
) -> Result<Vec<Action>, String> {
    let mut actions = Vec::new();
    let mut literal = String::new();
    let mut rest = sequence;

    while let Some(start) = rest.find('{') {
        literal.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after
            .find('}')
            .ok_or_else(|| "unterminated placeholder in the auto-type sequence".to_string())?;
        let token = &after[..end];
        rest = &after[end + 1..];

        let upper = token.to_ascii_uppercase();
        match upper.as_str() {
            "USERNAME" => literal.push_str(username),
            "PASSWORD" => literal.push_str(password),
            "TOTP" => literal.push_str(totp.ok_or("this entry has no TOTP to type")?),
            "TAB" | "ENTER" => {
                if !literal.is_empty() {
                    actions.push(Action::Text(std::mem::take(&mut literal)));
                }
                actions.push(if upper == "TAB" {
                    Action::Tab
                } else {
                    Action::Enter
                });
            }
            _ if upper.starts_with("DELAY ") => {
                let ms: u64 = upper[6..]
                    .trim()
                    .parse()
                    .map_err(|_| "the delay placeholder needs a number of milliseconds")?;
                if !literal.is_empty() {
                    actions.push(Action::Text(std::mem::take(&mut literal)));
                }
                actions.push(Action::Delay(ms.min(10_000)));
            }
            _ => return Err(format!("unknown placeholder: {{{token}}}")),
        }
    }

    literal.push_str(rest);
    if !literal.is_empty() {
        actions.push(Action::Text(literal));
    }
    Ok(actions)
}

/// Does a KeePass-style window pattern match a window title?
///
/// `*` matches any run of characters; matching is case-insensitive.
pub fn window_matches(pattern: &str, title: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let title = title.to_lowercase();
    if !pattern.contains('*') {
        return pattern == title;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;

    // A pattern not starting with '*' must match at the very beginning.
    if let Some(first) = parts.first() {
        if !first.is_empty() {
            if !title.starts_with(first) {
                return false;
            }
            pos = first.len();
        }
    }
    // Likewise, a pattern not ending with '*' must reach the end.
    if let Some(last) = parts.last() {
        if !last.is_empty() && !title.ends_with(last) {
            return false;
        }
    }

    for part in &parts[1..parts.len().saturating_sub(1).max(1)] {
        if part.is_empty() {
            continue;
        }
        match title[pos..].find(part) {
            Some(found) => pos += found + part.len(),
            None => return false,
        }
    }
    true
}

#[cfg(windows)]
mod platform {
    use super::Action;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
        VIRTUAL_KEY, VK_RETURN, VK_TAB,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId,
    };

    fn window_pid(hwnd: windows::Win32::Foundation::HWND) -> u32 {
        let mut pid = 0u32;
        // SAFETY: writes the owning process id into our own local `pid`.
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        pid
    }

    pub fn foreground_window() -> Result<super::ForegroundWindow, String> {
        // SAFETY: GetForegroundWindow takes no arguments and returns a handle we
        // only pass back to GetWindowTextW, which writes at most `buf.len()`
        // UTF-16 units into our own stack buffer.
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() {
                return Err("no foreground window is available".into());
            }
            let pid = window_pid(hwnd);
            if pid == 0 {
                // Without a process id the recycling guard degrades to the bare
                // handle comparison; refuse rather than arm a weaker check.
                return Err("could not identify the target window's process".into());
            }
            let mut buf = [0u16; 512];
            let len = GetWindowTextW(hwnd, &mut buf);
            Ok(super::ForegroundWindow {
                id: hwnd.0 as isize,
                pid,
                title: String::from_utf16_lossy(&buf[..len as usize]),
            })
        }
    }

    fn ensure_target(expected: &super::ForegroundWindow) -> Result<(), String> {
        let current = unsafe { GetForegroundWindow() };
        // Both the handle and its owning process must still match. The handle
        // alone can be recycled to a different window after the target closes;
        // requiring the same process too defeats that.
        if current.0 as isize != expected.id || window_pid(current) != expected.pid {
            return Err("auto-type cancelled because the foreground window changed".into());
        }
        Ok(())
    }

    pub fn run(actions: &[Action], expected: &super::ForegroundWindow) -> Result<(), String> {
        for action in actions {
            ensure_target(expected)?;
            match action {
                Action::Text(s) => {
                    for ch in s.encode_utf16() {
                        ensure_target(expected)?;
                        send_unicode(ch)?;
                    }
                }
                Action::Tab => send_vk(VK_TAB)?,
                Action::Enter => send_vk(VK_RETURN)?,
                Action::Delay(ms) => std::thread::sleep(std::time::Duration::from_millis(*ms)),
            }
            // A short gap between events: applications that debounce input drop
            // keystrokes delivered faster than a human could produce them.
            std::thread::sleep(std::time::Duration::from_millis(6));
        }
        Ok(())
    }

    fn send_unicode(unit: u16) -> Result<(), String> {
        let mut down = INPUT {
            r#type: INPUT_KEYBOARD,
            ..Default::default()
        };
        down.Anonymous.ki = KEYBDINPUT {
            wVk: VIRTUAL_KEY(0),
            wScan: unit,
            dwFlags: KEYEVENTF_UNICODE,
            time: 0,
            dwExtraInfo: 0,
        };
        let mut up = down;
        up.Anonymous.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        dispatch(&[down, up])
    }

    fn send_vk(key: VIRTUAL_KEY) -> Result<(), String> {
        let mut down = INPUT {
            r#type: INPUT_KEYBOARD,
            ..Default::default()
        };
        down.Anonymous.ki = KEYBDINPUT {
            wVk: key,
            wScan: 0,
            dwFlags: Default::default(),
            time: 0,
            dwExtraInfo: 0,
        };
        let mut up = down;
        up.Anonymous.ki.dwFlags = KEYEVENTF_KEYUP;
        dispatch(&[down, up])
    }

    fn dispatch(inputs: &[INPUT]) -> Result<(), String> {
        // SAFETY: `inputs` is a live slice of correctly-initialised INPUT values
        // and the size argument matches the type exactly.
        let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
        if sent as usize != inputs.len() {
            return Err("Windows refused the synthetic keystroke: another \
                        application may be blocking input injection"
                .into());
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod platform {
    use super::Action;

    pub fn foreground_window() -> Result<super::ForegroundWindow, String> {
        Err("auto-type is only implemented on Windows".into())
    }

    pub fn run(_actions: &[Action], _expected: &super::ForegroundWindow) -> Result<(), String> {
        Err("auto-type is only implemented on Windows".into())
    }
}

pub fn foreground_window() -> Result<ForegroundWindow, String> {
    platform::foreground_window()
}

/// Expand and type a sequence into the focused window.
pub fn run(
    sequence: &str,
    username: &str,
    password: &str,
    totp: Option<&str>,
    target: &ForegroundWindow,
) -> Result<(), String> {
    let actions = parse(sequence, username, password, totp)?;
    platform::run(&actions, target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_sequence_expands_as_expected() {
        let actions = parse(DEFAULT_SEQUENCE, "octocat", "hunter2", None).unwrap();
        assert_eq!(
            actions,
            vec![
                Action::Text("octocat".into()),
                Action::Tab,
                Action::Text("hunter2".into()),
                Action::Enter,
            ]
        );
    }

    #[test]
    fn a_password_containing_a_placeholder_is_typed_literally() {
        let actions = parse("{PASSWORD}", "u", "abc{TAB}def", None).unwrap();
        assert_eq!(actions, vec![Action::Text("abc{TAB}def".into())]);
    }

    #[test]
    fn totp_and_delays_are_supported() {
        let actions = parse("{USERNAME}{TAB}{DELAY 200}{TOTP}", "u", "p", Some("123456")).unwrap();
        assert_eq!(
            actions,
            vec![
                Action::Text("u".into()),
                Action::Tab,
                Action::Delay(200),
                Action::Text("123456".into()),
            ]
        );
    }

    #[test]
    fn a_missing_totp_is_an_error_rather_than_an_empty_field() {
        assert!(parse("{TOTP}", "u", "p", None).is_err());
    }

    #[test]
    fn malformed_sequences_are_refused() {
        assert!(parse("{PASSWORD", "u", "p", None).is_err());
        assert!(parse("{NOPE}", "u", "p", None).is_err());
        assert!(parse("{DELAY abc}", "u", "p", None).is_err());
    }

    #[test]
    fn delays_are_capped() {
        assert_eq!(
            parse("{DELAY 999999}", "u", "p", None).unwrap(),
            vec![Action::Delay(10_000)]
        );
    }

    #[test]
    fn window_patterns_match_the_way_users_expect() {
        assert!(window_matches("*GitHub*", "GitHub - Mozilla Firefox"));
        assert!(window_matches("*github*", "GitHub - Mozilla Firefox"));
        assert!(window_matches("GitHub*", "GitHub - Mozilla Firefox"));
        assert!(window_matches("*Firefox", "GitHub - Mozilla Firefox"));
        assert!(window_matches(
            "GitHub - Mozilla Firefox",
            "GitHub - Mozilla Firefox"
        ));

        assert!(!window_matches("*GitLab*", "GitHub - Mozilla Firefox"));
        assert!(!window_matches("Firefox*", "GitHub - Mozilla Firefox"));
        assert!(!window_matches("GitHub", "GitHub - Mozilla Firefox"));
    }

    #[test]
    fn multi_wildcard_patterns_match_in_order() {
        assert!(window_matches("*Git*Firefox*", "GitHub - Mozilla Firefox"));
        assert!(!window_matches("*Firefox*Git*", "GitHub - Mozilla Firefox"));
    }
}
