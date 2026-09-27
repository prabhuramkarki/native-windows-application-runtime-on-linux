//! `runtimed [--socket PATH] [--write]`: serves the runtime API in the foreground until SIGTERM or SIGINT (exit 0).
//! Read-only by default; `--write` adds the mutating methods (jobs that run the sibling `runtime`), after the checks
//! of `rt_daemon::write` (the socket inside `$XDG_RUNTIME_DIR`, the job directory, the `runtime` binary and its
//! version). The startup log says `mode: write` or `mode: read-only`.
//!
//! The socket is the one systemd hands over (`LISTEN_PID`/`LISTEN_FDS`, see `rt_daemon::server`), else `--socket
//! PATH`, else `$XDG_RUNTIME_DIR/runtime/runtimed.sock`. A handed-over socket that is not usable is an error, never
//! a reason to bind somewhere else. The activation variables are removed from the environment either way, so no
//! probe this process starts inherits them.
//!
//! `sandbox.info` names the `runtime` binary next to this one (same directory) as the sandbox's `sandbox-init`
//! shim, never `runtimed` itself: `runtimed` has no `sandbox-init`. When that file is missing the answer says the
//! runtime executable cannot be resolved.
//!
//! Exit codes: 0 stopped by a signal, 1 cannot start or serve (the reason on stderr), 2 bad arguments. Logs go to
//! stderr, one line per event, never a request's content.
use rt_api::Runtime;
use rt_daemon::server::{self, ServeError, ServerConfig};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const USAGE: &str = "usage: runtimed [--socket PATH] [--write]";

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    // An atomic store: async-signal-safe, and errno is untouched.
    STOP.store(true, Ordering::SeqCst);
}

/// SIGTERM and SIGINT set [`STOP`]. No `SA_RESTART`: the accept loop's `poll` wakes with EINTR.
fn on_stop_signals() {
    for sig in [libc::SIGTERM, libc::SIGINT] {
        // SAFETY: a plain `sigaction` on a zeroed struct with an empty mask; `on_signal` only stores an atomic.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut sa.sa_mask);
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

fn fail(e: &ServeError) -> i32 {
    eprintln!("runtimed: {e}");
    1
}

fn main() {
    std::process::exit(run())
}

fn run() -> i32 {
    let mut socket = None;
    let mut write = false;
    let mut args = std::env::args_os().skip(1);
    while let Some(a) = args.next() {
        match (a.to_str(), args.len()) {
            (Some("--socket"), 1..) if socket.is_none() => socket = args.next().map(PathBuf::from),
            (Some("--write"), _) if !write => write = true,
            (Some("-h" | "--help"), _) => {
                println!("{USAGE}");
                return 0;
            }
            _ => {
                eprintln!("{USAGE}");
                return 2;
            }
        }
    }
    // A panic is caught per request (-32603 on the wire); its text may quote untrusted data, so only where.
    std::panic::set_hook(Box::new(|info| match info.location() {
        Some(l) => eprintln!("runtimed: a request handler panicked at {}:{}", l.file(), l.line()),
        None => eprintln!("runtimed: a request handler panicked"),
    }));
    let inherited = server::listener_from_env(&|k| std::env::var_os(k));
    for k in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        // SAFETY: no thread has been started yet, so nothing reads the environment concurrently.
        unsafe { std::env::remove_var(k) };
    }
    let inherited = match inherited {
        Ok(l) => l,
        Err(e) => return fail(&e),
    };
    let socket = match (&inherited, socket) {
        (Some(_), _) => PathBuf::new(),
        (None, Some(p)) => p,
        (None, None) => match server::default_socket_path() {
            Ok(p) => p,
            Err(e) => return fail(&e),
        },
    };
    // `/usr/bin/runtimed` -> `/usr/bin/runtime`; after an upgrade `current_exe` reads `runtimed (deleted)`, and the
    // sibling is still the installed `runtime`.
    let shim_path = match std::env::current_exe() {
        Ok(me) => me.with_file_name("runtime"),
        Err(_) => {
            eprintln!("runtimed: cannot find its own executable");
            return 1;
        }
    };
    let rt = match Runtime::open() {
        Ok(rt) => rt.with_runtime_exe(shim_path.clone()),
        Err(e) => {
            eprintln!("runtimed: {}", e.message);
            return 1;
        }
    };
    on_stop_signals();
    let jobs = if write {
        let at = match &inherited {
            Some(l) => rt_daemon::write::listener_path(l),
            None => Some(socket.clone()),
        };
        let xdg = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        let runtime_exe = shim_path.clone();
        match at
            .ok_or_else(|| "--write: the inherited socket has no path".to_owned())
            .and_then(|at| rt_daemon::write::prepare(&at, xdg.as_deref(), &runtime_exe))
        {
            Ok(cfg) => Some(rt_daemon::jobs::Jobs::new(cfg)),
            Err(e) => {
                eprintln!("runtimed: {e}");
                return 1;
            }
        }
    } else {
        None
    };
    eprintln!("runtimed: mode: {}", if write { "write" } else { "read-only" });
    let ctx = Arc::new(rt_daemon::dispatch::Ctx::new(Arc::new(rt), jobs, &STOP));
    match server::serve(ctx, ServerConfig::new(socket), inherited) {
        Ok(()) => 0,
        Err(e) => fail(&e),
    }
}
