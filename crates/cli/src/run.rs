//! `runtime run <app|file> [--debug] [-- args...]`.
//!
//! **Ctrl-C.** The terminal delivers SIGINT to the whole foreground process group, so the program gets it and
//! decides what to do. This process ignores SIGINT from the moment the child is started until it has been
//! reaped, so it survives to report the child's exit status (a shell that says "Interrupted" while the app
//! saves its state is worse). The ignore starts right AFTER the spawn on purpose: a disposition of `SIG_IGN` is
//! inherited across `exec`, so ignoring first would make the app itself deaf to Ctrl-C. The price is a window of
//! microseconds in which Ctrl-C also kills this process. The previous disposition is restored afterwards.
use crate::CmdError;
use crate::SANDBOX_NOTE;
use crate::install::report_on_stderr;
use crate::safe::warn;
use rt_core::{Launcher, RunOptions};
use std::ffi::OsString;

/// Returns the program's exit code (128+N for a signal N), truncated to a byte like a shell does.
pub fn run(target: &str, args: &[OsString], debug: bool) -> Result<u8, CmdError> {
    let launcher = Launcher::new();
    let store = crate::store()?;
    let backend = crate::backend(&launcher)?;
    eprintln!("{SANDBOX_NOTE}");
    let started = rt_core::start(&store, &backend, &launcher, target, args, &RunOptions { debug })?;
    if let Some(installed) = &started.installed {
        report_on_stderr(installed);
    }
    let outcome = {
        let _sigint = IgnoreSigint::new();
        started.wait()
    }?;
    if outcome.log_write_failed {
        warn(&format!(
            "the log file {} is incomplete (a write failed)",
            outcome.log_path.display()
        ));
    }
    if outcome.terminal_write_failed {
        warn("the program's stderr could not be written to the terminal");
    }
    Ok(u8::try_from(outcome.exit_code & 0xff).unwrap_or(1))
}

/// Ignores SIGINT until dropped, then restores what was there before (see the module docs).
struct IgnoreSigint(libc::sighandler_t);

impl IgnoreSigint {
    fn new() -> IgnoreSigint {
        // SAFETY: `signal` with SIG_IGN installs no handler code, so nothing can run in signal context; the
        // disposition is process-wide and is put back by `Drop`. No other thread of this program changes it.
        IgnoreSigint(unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) })
    }
}

impl Drop for IgnoreSigint {
    fn drop(&mut self) {
        if self.0 != libc::SIG_ERR {
            // SAFETY: `self.0` is the disposition `signal` returned for SIGINT: a valid argument to give back.
            unsafe { libc::signal(libc::SIGINT, self.0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The current SIGINT handler (`SIG_DFL`, `SIG_IGN` or a function address).
    fn sigint_disposition() -> libc::sighandler_t {
        // SAFETY: `sigaction` with a null new action only reads the current one into the zeroed struct.
        unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            assert_eq!(libc::sigaction(libc::SIGINT, std::ptr::null(), &mut old), 0);
            old.sa_sigaction
        }
    }

    #[test]
    fn sigint_is_ignored_while_the_guard_lives_and_restored_afterwards() {
        // A shell can start a background job with SIGINT ignored: begin from a known state, put it back at the end.
        // SAFETY: as in `IgnoreSigint`; this is the only test that touches SIGINT.
        let original = unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
        assert_eq!(sigint_disposition(), libc::SIG_DFL);
        {
            let _g = IgnoreSigint::new();
            assert_eq!(sigint_disposition(), libc::SIG_IGN);
        }
        assert_eq!(
            sigint_disposition(),
            libc::SIG_DFL,
            "the previous disposition is restored"
        );
        // A previous non-default handler is restored too, not reset to the default.
        extern "C" fn handler(_: libc::c_int) {}
        // SAFETY: an async-signal-safe no-op handler.
        unsafe { libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t) };
        {
            let _g = IgnoreSigint::new();
            assert_eq!(sigint_disposition(), libc::SIG_IGN);
        }
        assert_eq!(sigint_disposition(), handler as *const () as libc::sighandler_t);
        // SAFETY: puts back what the harness had.
        unsafe { libc::signal(libc::SIGINT, original) };
    }
}
