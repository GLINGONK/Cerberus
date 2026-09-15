//! Native detection of Windows session lock and system suspend.
//!
//! An independent audit found that the previous auto-lock relied entirely on
//! the frontend polling `session_tick` every five seconds. If WebView2 froze,
//! was suspended, or the OS put the machine to sleep, nothing enforced the
//! idle timeout and the decrypted vault could sit in memory indefinitely.
//!
//! This module runs a message-only window on its own thread, independent of
//! the Tauri webview, and asks Windows to notify it directly of two events
//! that must lock the vault immediately: the user locking their session
//! (Win+L or automatic screen lock) and the system suspending (sleep or
//! hibernate). It is unsafe Win32 FFI by necessity — there is no safe
//! wrapper for session/power notifications — kept in its own small module
//! and nowhere near the cryptographic core.

use std::sync::OnceLock;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Power::RegisterSuspendResumeNotification;
use windows::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
    TranslateMessage, CW_USEDEFAULT, DEVICE_NOTIFY_WINDOW_HANDLE, HWND_MESSAGE, MSG,
    PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND, PBT_APMSUSPEND, WM_POWERBROADCAST,
    WM_WTSSESSION_CHANGE, WNDCLASSW, WTS_SESSION_LOCK,
};

/// Called from the window procedure when the session locks or the system
/// suspends. Set once at startup; never cleared.
static ON_LOCK_EVENT: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

/// Start watching for session-lock and suspend events. `on_lock_event` runs
/// on a dedicated background thread — keep it fast and non-blocking (it
/// should just flip the in-memory vault state and let the frontend catch up
/// on its next poll).
///
/// Safe to call once per process. A second call is a no-op.
pub fn start(on_lock_event: impl Fn() + Send + Sync + 'static) {
    if ON_LOCK_EVENT.set(Box::new(on_lock_event)).is_err() {
        return; // already started
    }
    std::thread::spawn(|| {
        // Errors here are not fatal to the app: worst case, this defence
        // layer is silently absent and the JS-polling fallback still runs.
        if let Err(e) = run_message_loop() {
            eprintln!("session watcher unavailable: {e}");
        }
    });
}

fn run_message_loop() -> windows::core::Result<()> {
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let class_name = windows::core::w!("CerberusSessionWatch");

        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: instance.into(),
            lpszClassName: class_name,
            ..Default::default()
        };
        RegisterClassW(&wc);

        let hwnd = CreateWindowExW(
            Default::default(),
            class_name,
            PCWSTR::null(),
            Default::default(),
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            HWND_MESSAGE, // message-only window: no UI, no taskbar presence
            None,
            instance,
            None,
        )?;

        // Ask for this session's lock/unlock notifications specifically —
        // not every session on the machine. This can fail transiently at
        // startup if the Remote Desktop services are not ready yet
        // (RPC_S_INVALID_BINDING), so retry a few times before giving up rather
        // than leaving Win+L unobserved for the whole session. The 1 s idle-tick
        // thread still runs as a fallback either way.
        let mut wts_ok = false;
        for attempt in 0..5 {
            match WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) {
                Ok(()) => {
                    wts_ok = true;
                    break;
                }
                Err(e) => {
                    eprintln!(
                        "session-lock notifications attempt {} failed: {e}",
                        attempt + 1
                    );
                    std::thread::sleep(std::time::Duration::from_secs(2));
                }
            }
        }
        if !wts_ok {
            eprintln!("session-lock notifications unavailable after retries");
        }

        // Power (suspend/resume) broadcasts do NOT reach a message-only window:
        // Windows only broadcasts them to top-level windows. Registering the
        // window explicitly with RegisterSuspendResumeNotification delivers
        // WM_POWERBROADCAST to it directly, which is what makes suspend
        // detection actually work here. An independent audit found the previous
        // reliance on the broadcast was inoperative.
        if let Err(e) =
            RegisterSuspendResumeNotification(HANDLE(hwnd.0), DEVICE_NOTIFY_WINDOW_HANDLE)
        {
            eprintln!("suspend/resume notifications unavailable: {e}");
        }

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).into() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    Ok(())
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let locking_event = match msg {
        WM_WTSSESSION_CHANGE => wparam.0 as u32 == WTS_SESSION_LOCK,
        // Lock on suspend *and* resume: suspend gets secrets out of RAM before
        // the machine sleeps; resume is defence in depth in case the suspend
        // notification was missed. PBT_APMRESUMESUSPEND/AUTOMATIC cover the two
        // resume flavours Windows sends.
        WM_POWERBROADCAST => matches!(
            wparam.0 as u32,
            PBT_APMSUSPEND | PBT_APMRESUMESUSPEND | PBT_APMRESUMEAUTOMATIC
        ),
        _ => false,
    };
    if locking_event {
        if let Some(cb) = ON_LOCK_EVENT.get() {
            cb();
        }
    }
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}
