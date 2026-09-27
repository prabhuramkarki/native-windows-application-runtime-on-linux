//! `runtime run <app|file> [--debug] [--unsandboxed] [-- args...]`.
//!
//! **Sandbox.** The program runs in the app's sandbox (`crate::sandbox`): bwrap missing or unable to create a
//! sandbox stops the run before anything starts, with an install hint. `--unsandboxed` runs it without one (this
//! run only) and says so on stderr. A sandboxed run prints what its profile cannot enforce (`note: ...`).
//!
//! **Out of memory.** With a memory limit, the scope's OOM kill ends the run as systemd stops the scope (SIGTERM to
//! bwrap: 143); a 143 under a memory limit therefore prints a `note:` pointing at the scope's journal.
//!
//! **Ctrl-C, unsandboxed.** The terminal delivers SIGINT to the whole foreground process group, so the program
//! gets it and decides what to do. This process ignores SIGINT from the moment the child is started until it has
//! been reaped, so it survives to report the child's exit status (a shell that says "Interrupted" while the app
//! saves its state is worse). The ignore starts right AFTER the spawn on purpose: a disposition of `SIG_IGN` is
//! inherited across `exec`, so ignoring first would make the app itself deaf to Ctrl-C. The price is a window of
//! microseconds in which Ctrl-C also kills this process. The previous disposition is restored afterwards. The
//! guard is created BEFORE the "installed as ..." report (`report_and_wait`), so a Ctrl-C while that is written
//! cannot kill the CLI either.
//!
//! **App lock.** The app's `deps.lock` is held SHARED from before the start until the program has ended, for
//! sandboxed and `--unsandboxed` runs alike (a file target's from right after its install), so every exclusive
//! holder (`deps --install`, `display`/`permissions` changes, `remove`, `uninstall`) refuses with "the app is running
//! (started by `runtime run`)" for as long as the run lives, whatever the program does inside (a program need not
//! keep a `wineserver`). The fd is close-on-exec: the program never holds it. Residual: when `bwrap` dies of a
//! signal (Ctrl-C) this process is woken as it dies and drops the lock while the kernel is still tearing down the
//! sandbox's PID namespace (`--die-with-parent` SIGKILLs its PID 1); when THIS process is SIGKILLed the kernel
//! releases the lock as it exits and the sandbox dies right after. Both windows are below a millisecond: the Ctrl-C
//! e2e test polls every millisecond and never saw a sandbox process after `runtime` had exited (docs/SECURITY.md).
//!
//! **Ctrl-C and SIGTERM, sandboxed** (measured with bubblewrap 0.11.1). The program is in a new session
//! (`--new-session`), so the terminal's SIGINT never reaches it; it reaches `bwrap` itself (still in this process
//! group), which does not handle or forward it and dies, and with it the sandbox: `--die-with-parent` kills the
//! sandbox's PID 1 and the kernel kills every process of the PID namespace (the program and its `wineserver`)
//! with SIGKILL. A SIGINT or SIGTERM sent to THIS process only (`kill <pid>`, a supervisor) is forwarded to `bwrap`
//! by a `sigaction` handler (SA_RESTART, errno kept) for as long as the child runs, with the same result. So the program is killed, not asked (no
//! Windows Ctrl-C event), and this process reports 130 (143 for SIGTERM). A signal this process was started with
//! ignored (a shell's background job ignores SIGINT, and so does its `bwrap`) stays ignored.
use crate::CmdError;
use crate::install::report_on_stderr;
use crate::safe::warn;
use rt_core::{InstallOutcome, Launcher, RunAppError, RunOptions, RunOutcome, Started, Target};
use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

/// Returns the program's exit code (128+N for a signal N), truncated to a byte like a shell does.
pub fn run(target: &str, args: &[OsString], debug: bool, unsandboxed: bool) -> Result<u8, CmdError> {
    let launcher = Launcher::new();
    let store = crate::store()?;
    // An unknown id or a missing file is reported as that, not as a missing Wine: look for Wine only when the
    // target needs it.
    let found = rt_core::find_target(&store, target, Path::new("."))?;
    let backend = match &found {
        Target::Installed(id) => crate::backend_of(&store, &store.get(id)?, &launcher)?,
        Target::File(_) => crate::backend(&launcher)?,
    };
    // The app runs under a SHARED hold of its lock (module docs, "App lock"): refused while a dependency install,
    // a removal or a settings change holds it exclusively, and those refuse for as long as this run lives. No
    // missing-dependency hint here: it would read the whole executable on every start (`install` and `doctor`
    // show it).
    let deps_lock = match &found {
        Target::Installed(id) => crate::deps::lock_or_refuse(&store.get(id)?, true, "start")?,
        Target::File(_) => None,
    };
    // Under that lock: `runtime permissions --set` takes it exclusively, so the profile cannot change meanwhile.
    let (sandbox, memory_limited) = if unsandboxed {
        eprintln!("warning: running WITHOUT a sandbox (--unsandboxed)");
        (None, false)
    } else {
        let (sb, memory) = crate::sandbox::for_run(&store, &found, &*backend)?;
        (Some(sb), memory)
    };
    let sandboxed = sandbox.is_some();
    let started = rt_core::start(
        &store,
        &*backend,
        &launcher,
        target,
        args,
        &RunOptions { debug, sandbox },
    )?;
    // A file target is a new app: its lock exists only now. The program already runs, so a refusal (another
    // command took the lock within these microseconds) can only be reported.
    let deps_lock = match deps_lock {
        None if started.installed.is_some() => store
            .get(&started.id)
            .map_err(CmdError::from)
            .and_then(|env| crate::deps::lock_or_refuse(&env, true, "hold the lock of"))
            .unwrap_or_else(|e| {
                warn(&format!("the app runs without its lock: {e}"));
                None
            }),
        held => held,
    };
    let outcome = report_and_wait(started, report_on_stderr, sandboxed);
    drop(deps_lock);
    let outcome = outcome?;
    if outcome.log_write_failed {
        warn(&format!(
            "the log file {} is incomplete (a write failed)",
            outcome.log_path.display()
        ));
    }
    if outcome.terminal_write_failed {
        warn("the program's stderr could not be written to the terminal");
    }
    // An OOM kill in the scope ends it with systemd's SIGTERM, which looks like any other SIGTERM here.
    if memory_limited && outcome.exit_code == 143 {
        eprintln!(
            "note: the program was terminated (exit 143); if it exceeded its memory limit see `journalctl --user -u \
             'run-p*.scope'`"
        );
    }
    Ok(u8::try_from(outcome.exit_code & 0xff).unwrap_or(1))
}

/// Reports a first-time install with `report`, then waits for the program, with SIGINT ignored (`sandboxed`:
/// SIGINT and SIGTERM forwarded to the child) throughout: the guard exists BEFORE the report, so a Ctrl-C while
/// the report is being written cannot kill this process either (see the module docs).
fn report_and_wait(
    started: Started,
    report: impl FnOnce(&InstallOutcome),
    sandboxed: bool,
) -> Result<RunOutcome, RunAppError> {
    let _ignore = (!sandboxed).then(IgnoreSigint::new);
    let _forward = sandboxed.then(|| Forward::to(started.pid()));
    if let Some(installed) = &started.installed {
        report(installed);
    }
    started.wait()
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

/// The process [`forward`] signals; 0: none.
static FORWARD_TO: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward(sig: libc::c_int) {
    // SAFETY: `__errno_location` is this thread's errno; the handler must not change what the interrupted code sees.
    let errno = unsafe { *libc::__errno_location() };
    let pid = FORWARD_TO.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: `kill` is async-signal-safe and touches no memory of this process.
        unsafe { libc::kill(pid, sig) };
    }
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = errno };
}

/// Forwards SIGINT and SIGTERM to one child until dropped, then restores the previous actions (module docs). The
/// handler is installed with `sigaction(SA_RESTART)`, so the `waitpid` this process is blocked in is restarted, not
/// failed with EINTR.
// ponytail: a signal that lands after the child was reaped but before the drop goes to its pid, which the kernel
// does not reuse within microseconds; closing that gap needs our own waitid(WNOWAIT) loop.
struct Forward(Vec<(libc::c_int, libc::sigaction)>);

impl Forward {
    fn to(pid: u32) -> Forward {
        FORWARD_TO.store(i32::try_from(pid).unwrap_or(0), Ordering::SeqCst);
        let mut saved = Vec::new();
        for sig in [libc::SIGINT, libc::SIGTERM] {
            // SAFETY: plain `sigaction` calls on zeroed/filled structs; `forward` is async-signal-safe (an atomic
            // load, `kill`, errno kept). The previous actions are put back by `Drop`; no other thread of this
            // program changes them.
            unsafe {
                let mut old: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, std::ptr::null(), &mut old) != 0 {
                    continue;
                }
                // Started with it ignored (a shell's background job): stay deaf to it, like the child is.
                if old.sa_sigaction == libc::SIG_IGN {
                    continue;
                }
                let mut new: libc::sigaction = std::mem::zeroed();
                new.sa_sigaction = forward as extern "C" fn(libc::c_int) as libc::sighandler_t;
                new.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut new.sa_mask);
                if libc::sigaction(sig, &new, std::ptr::null_mut()) == 0 {
                    saved.push((sig, old));
                }
            }
        }
        Forward(saved)
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        for (sig, old) in &self.0 {
            // SAFETY: `old` is the action `sigaction` reported for `sig`: a valid one to give back.
            unsafe { libc::sigaction(*sig, old, std::ptr::null_mut()) };
        }
        FORWARD_TO.store(0, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// SIGINT is process-wide: the tests that change it take turns.
    static SIGINT: Mutex<()> = Mutex::new(());

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
        let _turn = SIGINT.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: as in `IgnoreSigint`; the tests that touch SIGINT hold `SIGINT`.
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

    #[test]
    fn sigint_is_ignored_before_the_install_report_is_written() {
        let _turn = SIGINT.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: as above.
        let original = unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
        let tmp = tempfile::tempdir().unwrap();
        let store = rt_core::Store::new(tmp.path().join("apps")).unwrap();
        let backend = rt_core::FakeBackend::with_script("exit 4");
        let launcher = Launcher::with_host_env([("PATH", "/usr/bin:/bin")]);
        let hello = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/build/hello64.exe");
        let started = rt_core::start(
            &store,
            &backend,
            &launcher,
            hello.to_str().unwrap(),
            &[],
            &RunOptions::default(),
        )
        .unwrap();
        assert!(started.installed.is_some());
        let mut during_report = None;
        let outcome = report_and_wait(started, |_| during_report = Some(sigint_disposition()), false).unwrap();
        assert_eq!(outcome.exit_code, 4);
        assert_eq!(
            during_report,
            Some(libc::SIG_IGN),
            "a Ctrl-C during the report must not kill the CLI"
        );
        assert_eq!(sigint_disposition(), libc::SIG_DFL, "restored afterwards");
        // SAFETY: puts back what the harness had.
        unsafe { libc::signal(libc::SIGINT, original) };
    }

    #[test]
    fn sigint_and_sigterm_are_forwarded_to_the_child_and_restored_afterwards() {
        let _turn = SIGINT.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: as above.
        let original = unsafe { libc::signal(libc::SIGINT, libc::SIG_DFL) };
        // SAFETY: as above; SIGTERM is only raised while the forwarding handler is installed.
        let original_term = unsafe { libc::signal(libc::SIGTERM, libc::SIG_DFL) };
        for sig in [libc::SIGINT, libc::SIGTERM] {
            let mut child = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();
            {
                let _g = Forward::to(child.id());
                assert_ne!(sigint_disposition(), libc::SIG_DFL);
                // SAFETY: the forwarding handler is installed: this process survives and the child gets `sig`.
                assert_eq!(unsafe { libc::raise(sig) }, 0);
            }
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(child.wait().unwrap().signal(), Some(sig), "the child got the signal");
        }
        assert_eq!(sigint_disposition(), libc::SIG_DFL, "restored afterwards");
        assert_eq!(FORWARD_TO.load(Ordering::SeqCst), 0);
        // The handler leaves errno alone even when its `kill` fails (ESRCH: a child that is gone).
        let mut gone = std::process::Command::new("/bin/true").spawn().unwrap();
        gone.wait().unwrap();
        {
            let _g = Forward::to(gone.id());
            // SAFETY: this thread's errno; SIGINT goes to the forwarding handler.
            unsafe {
                *libc::__errno_location() = 42;
                libc::raise(libc::SIGINT);
                assert_eq!(*libc::__errno_location(), 42, "the handler changed errno");
            }
        }
        // An ignored SIGINT (a background job) stays ignored.
        // SAFETY: as above.
        unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
        {
            let _g = Forward::to(1);
            assert_eq!(sigint_disposition(), libc::SIG_IGN);
        }
        assert_eq!(sigint_disposition(), libc::SIG_IGN);
        // SAFETY: puts back what the harness had.
        unsafe {
            libc::signal(libc::SIGINT, original);
            libc::signal(libc::SIGTERM, original_term);
        }
    }
}
