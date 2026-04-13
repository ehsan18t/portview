//! # Platform-specific process termination
//!
//! Wraps `sysinfo`'s kill API so the rest of the crate can stay platform-free.
//!
//! - Unix: default sends `SIGTERM`; `force = true` sends `SIGKILL`.
//! - Windows: always calls `TerminateProcess` (equivalent to `taskkill /F`).
//!   There is no reliable graceful equivalent for arbitrary processes, so
//!   `force` is accepted but has no behavioral effect.

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

/// Outcome of a single kill attempt.
///
/// The `Failed` variant is Unix-only: on Windows, `TerminateProcess` failures
/// that are not "process already exited" map to `PermissionDenied` (the
/// overwhelmingly common cause — access denied, protected processes), so no
/// generic-failure variant is needed. On Unix, `kill(2)` can return errors
/// beyond `ESRCH` / `EPERM` (for example `EINVAL`), hence the extra case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillOutcome {
    /// Signal/terminate request succeeded.
    Signaled,
    /// Process was already gone at signal time (idempotent success).
    AlreadyGone,
    /// Operating system refused the request (permissions, protected process).
    PermissionDenied,
    /// `kill(2)` returned an error that is neither `ESRCH` nor `EPERM`.
    #[cfg(unix)]
    Failed,
}

impl KillOutcome {
    /// Whether this outcome counts as overall success for exit-code purposes.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Signaled | Self::AlreadyGone)
    }
}

/// Attempt to terminate `pid`. See module docs for platform behavior.
#[must_use]
pub fn kill_pid(pid: u32, force: bool) -> KillOutcome {
    let mut sys = System::new();
    let target = Pid::from_u32(pid);
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        false,
        ProcessRefreshKind::nothing(),
    );

    let Some(process) = sys.process(target) else {
        return KillOutcome::AlreadyGone;
    };

    #[cfg(unix)]
    {
        let signal = if force {
            sysinfo::Signal::Kill
        } else {
            sysinfo::Signal::Term
        };
        match process.kill_with(signal) {
            Some(true) => KillOutcome::Signaled,
            Some(false) => classify_unix_failure(pid),
            None => KillOutcome::Failed,
        }
    }

    #[cfg(windows)]
    {
        let _ = force;
        if process.kill() {
            KillOutcome::Signaled
        } else {
            classify_windows_failure(pid)
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        // Unsupported target: no platform kill primitive is wired up.
        // Treat as permission-denied so the caller surfaces a clear status
        // without requiring a Unix-only `Failed` variant on this target.
        let _ = (process, force);
        KillOutcome::PermissionDenied
    }
}

#[cfg(unix)]
fn classify_unix_failure(pid: u32) -> KillOutcome {
    // SAFETY: `kill(pid, 0)` never delivers a signal; it only probes whether
    // the process exists and whether we have permission to signal it.
    let rc = unsafe { libc::kill(pid.cast_signed(), 0) };
    if rc == 0 {
        KillOutcome::Failed
    } else {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => KillOutcome::AlreadyGone,
            Some(libc::EPERM) => KillOutcome::PermissionDenied,
            _ => KillOutcome::Failed,
        }
    }
}

#[cfg(windows)]
fn classify_windows_failure(pid: u32) -> KillOutcome {
    // Re-probe: if the PID is no longer present, treat as AlreadyGone.
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[Pid::from_u32(pid)]),
        false,
        ProcessRefreshKind::nothing(),
    );
    if sys.process(Pid::from_u32(pid)).is_none() {
        KillOutcome::AlreadyGone
    } else {
        // Most common remaining cause on Windows is ERROR_ACCESS_DENIED.
        KillOutcome::PermissionDenied
    }
}
