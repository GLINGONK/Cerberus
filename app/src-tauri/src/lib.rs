//! Cerberus desktop application.
//!
//! The webview renders the interface and nothing else: every cryptographic
//! operation, and the decrypted vault itself, stay in this native layer. The
//! frontend can ask for one secret at a time and never sees a key.

pub mod appconfig;
pub mod attempts;
pub mod autotype;
pub mod commands;
pub mod qr;
#[cfg(target_os = "windows")]
pub mod session_watch;
pub mod state;
pub mod vaultlock;

use tauri::{Emitter, Manager};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

/// Hotkey that types the entry matching the focused window.
///
/// This is the workflow auto-type is built for: the user is already in the
/// target application, so nothing has to steal or hand back focus.
fn autotype_hotkey() -> Shortcut {
    Shortcut::new(Some(Modifiers::CONTROL | Modifiers::ALT), Code::KeyA)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, shortcut, event| {
                    // Fire on press only; the release event would type twice.
                    if event.state() != ShortcutState::Pressed || shortcut != &autotype_hotkey() {
                        return;
                    }
                    let Some(state) = app.try_state::<state::AppState>() else {
                        return;
                    };
                    let outcome = commands::autotype_focused(state);
                    // The window may be hidden behind the target application,
                    // so report through an event the UI turns into a toast.
                    let _ = app.emit(
                        "autotype-result",
                        match outcome {
                            Ok(title) => serde_json::json!({ "ok": true, "entry": title }),
                            Err(message) => serde_json::json!({ "ok": false, "error": message }),
                        },
                    );
                })
                .build(),
        )
        .manage(state::AppState::new())
        .setup(|app| {
            // A registration failure means another application already owns the
            // hotkey. Not fatal: everything else still works.
            if let Err(e) = app.global_shortcut().register(autotype_hotkey()) {
                eprintln!("global auto-type hotkey unavailable: {e}");
            }
            // Lock the vault whenever the window is hidden from the user. The
            // in-memory vault zeroizes on drop, so this genuinely shortens the
            // window during which secrets sit in RAM.
            let handle = app.handle().clone();
            if let Some(window) = app.get_webview_window("main") {
                window.on_window_event(move |event| {
                    if let tauri::WindowEvent::Destroyed = event {
                        if let Some(state) = handle.try_state::<state::AppState>() {
                            state.close();
                        }
                    }
                });
            }

            // Native idle enforcement, independent of the webview. A stalled,
            // suspended, or compromised frontend used to mean no auto-lock at
            // all — this thread checks the same idle policy every second from
            // outside the webview's control.
            let tick_handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if let Some(state) = tick_handle.try_state::<state::AppState>() {
                    let now = state::now_ms();
                    if state.enforce_idle(now) {
                        let _ = tick_handle.emit("vault-locked", "idle");
                    }
                }
            });

            // Session lock (Win+L / screen lock) and system suspend must lock
            // the vault immediately, not after the idle timeout — the user is
            // stepping away *now*, not gradually going idle.
            #[cfg(target_os = "windows")]
            {
                let lock_handle = app.handle().clone();
                session_watch::start(move || {
                    if let Some(state) = lock_handle.try_state::<state::AppState>() {
                        state.close();
                    }
                    let _ = lock_handle.emit("vault-locked", "session");
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::gate_status,
            commands::gate_open,
            commands::gate_configure,
            commands::recent_vaults,
            commands::get_language,
            commands::set_language,
            commands::vault_peek,
            commands::vault_create,
            commands::vault_create_shamir,
            commands::share_qr,
            commands::share_save,
            commands::vault_unlock,
            commands::vault_lock,
            commands::vault_is_unlocked,
            commands::vault_save,
            commands::vault_info,
            commands::vault_rekey,
            commands::vault_audit,
            commands::vault_import_csv,
            commands::vault_export_csv,
            commands::vault_backup,
            commands::folders_list,
            commands::folder_create,
            commands::folder_delete,
            commands::entries_list,
            commands::entry_create,
            commands::entry_update,
            commands::entry_delete,
            commands::entry_restore,
            commands::entry_purge,
            commands::trash_list,
            commands::trash_empty,
            commands::entry_reveal,
            commands::entry_reveal_custom,
            commands::entry_copy_custom,
            commands::entry_copy,
            commands::entry_totp,
            commands::entry_totp_qr,
            commands::entry_history,
            commands::clipboard_tick,
            commands::generate_password,
            commands::generate_passphrase,
            commands::generate_keyfile,
            commands::qr_svg,
            commands::kdf_benchmark,
            commands::cipher_catalogue,
            commands::set_clipboard_seconds,
            commands::set_autolock_minutes,
            commands::session_tick,
            commands::unlock_delay_remaining,
            commands::security_status,
            commands::autotype,
            commands::autotype_focused,
            commands::autotype_match,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start Cerberus");
}
