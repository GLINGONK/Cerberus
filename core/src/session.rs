//! Session policy: unlock throttling, auto-lock and clipboard lifetime.
//!
//! Kept as pure logic driven by an injected clock so every rule is testable
//! without sleeping. The platform glue (timers, clipboard, session events)
//! lives in the application crate.

use std::time::Duration;

/// How long to wait before a further unlock attempt is accepted.
///
/// The delay doubles per failure. It exists to make online guessing tedious;
/// the real defence against an attacker holding the file is Argon2id, since
/// they can always bypass this by writing their own reader.
#[derive(Debug, Clone)]
pub struct UnlockThrottle {
    failures: u32,
    /// Monotonic milliseconds at which the last failure was recorded.
    last_failure_ms: Option<u64>,
    max_delay: Duration,
}

impl Default for UnlockThrottle {
    fn default() -> Self {
        UnlockThrottle {
            failures: 0,
            last_failure_ms: None,
            max_delay: Duration::from_secs(60),
        }
    }
}

impl UnlockThrottle {
    pub fn new(max_delay: Duration) -> Self {
        UnlockThrottle {
            max_delay,
            ..Default::default()
        }
    }

    /// Rebuild a throttle from a persisted count, so restarting the application
    /// does not clear an accumulated penalty.
    pub fn restored(failures: u32, last_failure_ms: u64) -> Self {
        UnlockThrottle {
            failures,
            last_failure_ms: (failures > 0).then_some(last_failure_ms),
            ..Default::default()
        }
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Delay required after `failures` consecutive failures: 0, 1, 2, 4, 8… seconds.
    pub fn required_delay(&self) -> Duration {
        if self.failures == 0 {
            return Duration::ZERO;
        }
        let secs = 1u64.checked_shl(self.failures - 1).unwrap_or(u64::MAX);
        Duration::from_secs(secs).min(self.max_delay)
    }

    /// Record a failed attempt at monotonic time `now_ms`.
    pub fn record_failure(&mut self, now_ms: u64) {
        self.failures = self.failures.saturating_add(1);
        self.last_failure_ms = Some(now_ms);
    }

    /// Clear the penalty after a successful unlock.
    pub fn record_success(&mut self) {
        self.failures = 0;
        self.last_failure_ms = None;
    }

    /// Time still to wait at `now_ms`, or zero if an attempt is allowed.
    pub fn remaining(&self, now_ms: u64) -> Duration {
        let Some(last) = self.last_failure_ms else {
            return Duration::ZERO;
        };
        let required = self.required_delay();
        let elapsed = Duration::from_millis(now_ms.saturating_sub(last));
        required.saturating_sub(elapsed)
    }

    pub fn may_attempt(&self, now_ms: u64) -> bool {
        self.remaining(now_ms).is_zero()
    }
}

/// When the vault should lock itself.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AutoLockPolicy {
    /// Lock after this much user inactivity. `None` disables the timer.
    pub idle_timeout: Option<Duration>,
    /// Lock when the OS session locks or the machine suspends.
    pub on_session_lock: bool,
    /// Lock when the window loses focus. Aggressive, off by default.
    pub on_focus_loss: bool,
    /// Lock when the window is minimised.
    pub on_minimise: bool,
}

impl Default for AutoLockPolicy {
    fn default() -> Self {
        AutoLockPolicy {
            idle_timeout: Some(Duration::from_secs(5 * 60)),
            on_session_lock: true,
            on_focus_loss: false,
            on_minimise: false,
        }
    }
}

/// Why the vault locked, so the UI can explain itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Manual,
    Idle,
    SessionLock,
    FocusLoss,
    Minimised,
}

/// Tracks activity and decides when to lock.
#[derive(Debug, Clone)]
pub struct IdleTracker {
    policy: AutoLockPolicy,
    last_activity_ms: u64,
}

impl IdleTracker {
    pub fn new(policy: AutoLockPolicy, now_ms: u64) -> Self {
        IdleTracker {
            policy,
            last_activity_ms: now_ms,
        }
    }

    pub fn touch(&mut self, now_ms: u64) {
        self.last_activity_ms = now_ms;
    }

    pub fn should_lock(&self, now_ms: u64) -> Option<LockReason> {
        let timeout = self.policy.idle_timeout?;
        let idle = Duration::from_millis(now_ms.saturating_sub(self.last_activity_ms));
        (idle >= timeout).then_some(LockReason::Idle)
    }

    /// Translate an OS event into a lock decision under the current policy.
    pub fn on_event(&self, event: SystemEvent) -> Option<LockReason> {
        match event {
            SystemEvent::SessionLocked | SystemEvent::Suspend if self.policy.on_session_lock => {
                Some(LockReason::SessionLock)
            }
            SystemEvent::FocusLost if self.policy.on_focus_loss => Some(LockReason::FocusLoss),
            SystemEvent::Minimised if self.policy.on_minimise => Some(LockReason::Minimised),
            _ => None,
        }
    }

    pub fn seconds_until_lock(&self, now_ms: u64) -> Option<u64> {
        let timeout = self.policy.idle_timeout?;
        let idle = Duration::from_millis(now_ms.saturating_sub(self.last_activity_ms));
        Some(timeout.saturating_sub(idle).as_secs())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemEvent {
    SessionLocked,
    Suspend,
    FocusLost,
    Minimised,
}

/// Clipboard hygiene for copied secrets.
#[derive(Debug, Clone)]
pub struct ClipboardPolicy {
    /// Wipe the clipboard this long after a copy.
    pub clear_after: Duration,
    /// Wipe as soon as one paste is observed, without waiting for the timer.
    pub clear_on_first_paste: bool,
    /// Ask Windows not to sync the entry to Cloud Clipboard or clipboard history.
    pub exclude_from_history: bool,
}

impl Default for ClipboardPolicy {
    fn default() -> Self {
        ClipboardPolicy {
            clear_after: Duration::from_secs(12),
            clear_on_first_paste: true,
            exclude_from_history: true,
        }
    }
}

/// Tracks one copied secret and decides when it must be wiped.
///
/// Wiping is conditional on the clipboard still holding *our* value: clearing
/// unconditionally would destroy whatever the user copied in the meantime.
#[derive(Debug, Clone)]
pub struct ClipboardGuard {
    policy: ClipboardPolicy,
    copied_at_ms: u64,
    /// BLAKE3 of the copied value, so the guard never retains the secret itself.
    fingerprint: [u8; 32],
    pastes_seen: u32,
}

impl ClipboardGuard {
    pub fn new(policy: ClipboardPolicy, secret: &str, now_ms: u64) -> Self {
        ClipboardGuard {
            policy,
            copied_at_ms: now_ms,
            fingerprint: *blake3::hash(secret.as_bytes()).as_bytes(),
            pastes_seen: 0,
        }
    }

    pub fn note_paste(&mut self) {
        self.pastes_seen = self.pastes_seen.saturating_add(1);
    }

    /// Does the clipboard still hold the value this guard is responsible for?
    pub fn owns(&self, current: &str) -> bool {
        *blake3::hash(current.as_bytes()).as_bytes() == self.fingerprint
    }

    pub fn should_clear(&self, now_ms: u64) -> bool {
        if self.policy.clear_on_first_paste && self.pastes_seen > 0 {
            return true;
        }
        Duration::from_millis(now_ms.saturating_sub(self.copied_at_ms)) >= self.policy.clear_after
    }

    pub fn seconds_remaining(&self, now_ms: u64) -> u64 {
        self.policy
            .clear_after
            .saturating_sub(Duration::from_millis(
                now_ms.saturating_sub(self.copied_at_ms),
            ))
            .as_secs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_attempt_is_never_delayed() {
        let t = UnlockThrottle::default();
        assert!(t.may_attempt(0));
        assert_eq!(t.required_delay(), Duration::ZERO);
    }

    #[test]
    fn the_delay_doubles_per_failure() {
        let mut t = UnlockThrottle::default();
        for (failures, expected_secs) in [(1u32, 1u64), (2, 2), (3, 4), (4, 8), (5, 16), (6, 32)] {
            while t.failures() < failures {
                t.record_failure(0);
            }
            assert_eq!(t.required_delay(), Duration::from_secs(expected_secs));
        }
    }

    #[test]
    fn the_delay_is_capped_and_never_overflows() {
        let mut t = UnlockThrottle::new(Duration::from_secs(60));
        for _ in 0..200 {
            t.record_failure(0);
        }
        assert_eq!(t.required_delay(), Duration::from_secs(60));
    }

    #[test]
    fn waiting_out_the_delay_permits_a_retry() {
        let mut t = UnlockThrottle::default();
        t.record_failure(1_000);
        t.record_failure(1_000);
        assert!(!t.may_attempt(1_000));
        assert_eq!(t.remaining(1_000), Duration::from_secs(2));
        assert!(!t.may_attempt(2_500));
        assert!(t.may_attempt(3_000));
    }

    #[test]
    fn a_restored_throttle_keeps_its_penalty() {
        let t = UnlockThrottle::restored(4, 1_000);
        assert_eq!(t.failures(), 4);
        assert_eq!(t.required_delay(), Duration::from_secs(8));
        assert!(!t.may_attempt(1_000), "a restored penalty must still apply");
        assert!(t.may_attempt(9_000));
    }

    #[test]
    fn restoring_zero_failures_imposes_nothing() {
        let t = UnlockThrottle::restored(0, 12_345);
        assert!(t.may_attempt(0));
        assert_eq!(t.required_delay(), Duration::ZERO);
    }

    #[test]
    fn a_success_clears_the_penalty() {
        let mut t = UnlockThrottle::default();
        t.record_failure(0);
        t.record_failure(0);
        t.record_success();
        assert_eq!(t.failures(), 0);
        assert!(t.may_attempt(0));
    }

    #[test]
    fn idle_locking_respects_the_timeout() {
        let policy = AutoLockPolicy {
            idle_timeout: Some(Duration::from_secs(300)),
            ..Default::default()
        };
        let mut tracker = IdleTracker::new(policy, 0);
        assert!(tracker.should_lock(299_000).is_none());
        assert_eq!(tracker.should_lock(300_000), Some(LockReason::Idle));

        tracker.touch(299_000);
        assert!(tracker.should_lock(300_000).is_none());
        assert_eq!(tracker.should_lock(599_000), Some(LockReason::Idle));
    }

    #[test]
    fn a_disabled_timeout_never_locks_on_idle() {
        let policy = AutoLockPolicy {
            idle_timeout: None,
            ..Default::default()
        };
        let tracker = IdleTracker::new(policy, 0);
        assert!(tracker.should_lock(u64::MAX).is_none());
        assert!(tracker.seconds_until_lock(0).is_none());
    }

    #[test]
    fn system_events_follow_the_policy() {
        let strict = IdleTracker::new(
            AutoLockPolicy {
                on_focus_loss: true,
                on_minimise: true,
                ..Default::default()
            },
            0,
        );
        assert_eq!(
            strict.on_event(SystemEvent::SessionLocked),
            Some(LockReason::SessionLock)
        );
        assert_eq!(
            strict.on_event(SystemEvent::Suspend),
            Some(LockReason::SessionLock)
        );
        assert_eq!(
            strict.on_event(SystemEvent::FocusLost),
            Some(LockReason::FocusLoss)
        );

        let relaxed = IdleTracker::new(AutoLockPolicy::default(), 0);
        assert!(relaxed.on_event(SystemEvent::FocusLost).is_none());
        assert!(relaxed.on_event(SystemEvent::Minimised).is_none());
        assert_eq!(
            relaxed.on_event(SystemEvent::SessionLocked),
            Some(LockReason::SessionLock)
        );
    }

    #[test]
    fn the_clipboard_clears_on_the_timer() {
        let g = ClipboardGuard::new(ClipboardPolicy::default(), "hunter2", 0);
        assert!(!g.should_clear(11_000));
        assert!(g.should_clear(12_000));
    }

    #[test]
    fn the_clipboard_clears_early_on_the_first_paste() {
        let mut g = ClipboardGuard::new(ClipboardPolicy::default(), "hunter2", 0);
        assert!(!g.should_clear(1_000));
        g.note_paste();
        assert!(g.should_clear(1_000));
    }

    #[test]
    fn the_guard_only_claims_its_own_value() {
        let g = ClipboardGuard::new(ClipboardPolicy::default(), "hunter2", 0);
        assert!(g.owns("hunter2"));
        assert!(
            !g.owns("something the user copied afterwards"),
            "clearing here would destroy unrelated clipboard content"
        );
    }

    #[test]
    fn the_guard_does_not_retain_the_secret() {
        let g = ClipboardGuard::new(ClipboardPolicy::default(), "hunter2", 0);
        let dumped = format!("{g:?}");
        assert!(
            !dumped.contains("hunter2"),
            "the secret leaked through Debug"
        );
    }
}
