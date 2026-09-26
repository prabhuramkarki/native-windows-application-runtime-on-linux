//! The `sandbox-init` shim: the first program bubblewrap starts inside the sandbox (`runtime sandbox-init
//! <block>`, a hidden subcommand). It hardens ITSELF and then `execve`s the real program, so everything the
//! program starts (the Wine loader, wineserver, every Windows process) inherits the hardening:
//!
//! 1. `RLIMIT_CORE = 0` (no core dumps of Windows program memory into the prefix or the cwd);
//! 2. the [`landlock`] ruleset of its argument block ([`Applied::Unavailable`](landlock::Applied) goes on
//!    silently: the host-side probe in `runtime sandbox` / `doctor` reports it; any other failure refuses);
//! 3. the [`seccomp`] deny-list (mandatory: if it cannot be built or installed, nothing runs), with `ptrace` let
//!    through for Wine's requests only when step 2 enforced a Landlock domain (see [`seccomp`]);
//! 4. `execve(program, [program, args...], environ)`: the environment and `argv[0]` as given, the pid unchanged
//!    (bwrap's signal forwarding and `--die-with-parent` still reach the program).
//!
//! Every refusal exits **126** with one `runtime: sandbox-init: ...` line on stderr, including an `execve` that
//! fails (not 127: the program never started, and 126 is what the sandbox's other refusals use).
//!
//! **Input.** The argument block is the ONLY input the shim trusts: no config file, no environment variable. It is
//! [`encode`]d by the renderer and [`parse`]d strictly: exactly `--v1` first, then at most [`MAX_RULES`] pairs
//! `--rule ro:<path>` / `--rule rw:<path>` (absolute, `.`/`..`-free paths), then `--`, then an absolute program and
//! its arguments (passed on byte for byte). No argument may contain a NUL byte.
//!
//! **Safe for anyone to run.** The subcommand is hidden, not secret: it only ever takes rights away from ITSELF and
//! then runs a program the caller named, which the caller could have run directly. It never touches another
//! process or a file.
use crate::{landlock, seccomp};
use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
#[cfg(test)]
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

/// The version marker every argument block starts with.
pub const VERSION: &str = "--v1";
/// The most Landlock rules one block may carry.
pub const MAX_RULES: usize = 256;
/// The exit status of every refusal.
pub const REFUSED: i32 = 126;

/// The shim's parsed argument block. `argv` are the program's arguments after `argv[0]` (which is `program`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitArgs {
    pub landlock: Vec<landlock::Rule>,
    pub program: PathBuf,
    pub argv: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InitError {
    #[error("the argument block does not start with {VERSION}")]
    Version,
    #[error("argument {0}: expected --rule or --")]
    Unexpected(usize),
    #[error("--rule has no value")]
    MissingRule,
    #[error("rule {0:?} is not ro:<path> or rw:<path>")]
    RuleAccess(String),
    #[error("{0:?} is not an absolute path free of `.` and `..`")]
    NotAbsolute(String),
    #[error("an argument contains a NUL byte")]
    Nul,
    #[error("more than {MAX_RULES} rules")]
    TooManyRules,
    #[error("no `--` before the program")]
    NoSeparator,
    #[error("no program after `--`")]
    NoProgram,
}

/// The block for `args`: `--v1`, `--rule ro:<path>`/`rw:<path>` per rule, `--`, the program, its arguments.
pub fn encode(args: &InitArgs) -> Vec<OsString> {
    let mut out = vec![OsString::from(VERSION)];
    for r in &args.landlock {
        let mut v = OsString::from(match r.access {
            landlock::Access::ReadExec => "ro:",
            landlock::Access::ReadWrite => "rw:",
        });
        v.push(&r.path);
        out.extend([OsString::from("--rule"), v]);
    }
    out.push(OsString::from("--"));
    out.push(args.program.clone().into_os_string());
    out.extend(args.argv.iter().cloned());
    out
}

/// Absolute, `.`/`..`-free (judged on the bytes, like the renderer) and not just `/`-less text.
fn plain_abs(p: &[u8]) -> bool {
    p.first() == Some(&b'/') && !p.split(|b| *b == b'/').any(|c| c == b"." || c == b"..")
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).chars().take(200).collect()
}

/// The strict inverse of [`encode`] (module docs).
pub fn parse(args: &[OsString]) -> Result<InitArgs, InitError> {
    if args.iter().any(|a| a.as_bytes().contains(&0)) {
        return Err(InitError::Nul);
    }
    if args.first().map(OsString::as_os_str) != Some(OsStr::new(VERSION)) {
        return Err(InitError::Version);
    }
    let mut landlock = Vec::new();
    let mut i = 1;
    loop {
        match args.get(i).map(|a| a.as_bytes()) {
            None => return Err(InitError::NoSeparator),
            Some(b"--") => break,
            Some(b"--rule") => {
                let v = args.get(i + 1).ok_or(InitError::MissingRule)?.as_bytes();
                let access = match v.get(..3) {
                    Some(b"ro:") => landlock::Access::ReadExec,
                    Some(b"rw:") => landlock::Access::ReadWrite,
                    _ => return Err(InitError::RuleAccess(lossy(v))),
                };
                let path = &v[3..];
                if !plain_abs(path) {
                    return Err(InitError::NotAbsolute(lossy(path)));
                }
                if landlock.len() == MAX_RULES {
                    return Err(InitError::TooManyRules);
                }
                landlock.push(landlock::Rule {
                    path: PathBuf::from(OsStr::from_bytes(path)),
                    access,
                });
                i += 2;
            }
            Some(_) => return Err(InitError::Unexpected(i)),
        }
    }
    let program = args.get(i + 1).ok_or(InitError::NoProgram)?;
    if program.is_empty() {
        return Err(InitError::NoProgram);
    }
    if !plain_abs(program.as_bytes()) {
        return Err(InitError::NotAbsolute(lossy(program.as_bytes())));
    }
    Ok(InitArgs {
        landlock,
        program: PathBuf::from(program),
        argv: args[i + 2..].to_vec(),
    })
}

/// Prints the refusal and exits [`REFUSED`].
fn refuse(why: &str) -> ! {
    eprintln!("runtime: sandbox-init: {why}");
    std::process::exit(REFUSED)
}

/// [`parse`], then [`run`]; a block that does not parse is refused (126). What `runtime sandbox-init` does.
pub fn main(args: &[OsString]) -> ! {
    match parse(args) {
        Ok(a) => run(a),
        Err(e) => refuse(&format!("refused its arguments: {e}")),
    }
}

/// The seccomp filter for what Landlock did: ptrace (Wine's requests only) inside an enforced Landlock domain,
/// which confines it to the program's own processes; the strict filter otherwise (see [`seccomp`]).
pub fn filter_for(
    applied: &landlock::Applied,
    arch: seccomp::Arch,
) -> Result<Vec<seccomp::SockFilter>, seccomp::SeccompError> {
    match applied {
        landlock::Applied::Enforced { .. } => seccomp::build_filter_confined_ptrace(arch),
        landlock::Applied::Unavailable(_) => seccomp::build_filter(arch),
    }
}

/// Hardens this process and becomes the program (module docs). Never returns: the program, or exit 126.
pub fn run(args: InitArgs) -> ! {
    // The argv first (`parse` already refused NUL bytes, so these cannot fail); the filter is built after Landlock
    // (`filter_for` depends on its outcome), still before anything is installed.
    let c = |s: &OsStr| CString::new(s.as_bytes()).unwrap_or_else(|_| refuse("an argument contains a NUL byte"));
    let program = c(args.program.as_os_str());
    let argv: Vec<CString> = std::iter::once(program.clone())
        .chain(args.argv.iter().map(|a| c(a)))
        .collect();
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    let arch = seccomp::host_arch().unwrap_or_else(|e| refuse(&e.to_string()));

    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `no_core` is a live rlimit the kernel only reads.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } != 0 {
        refuse(&format!("setrlimit(RLIMIT_CORE): {}", std::io::Error::last_os_error()));
    }
    // Unavailable: the host-side probe reports it (`runtime sandbox`, `doctor`); a missing rule path is expected
    // (a `--ro-bind-try` source the host lacks).
    // A Landlock error refuses before any filter is chosen: `filter_for` only ever sees an applied state.
    let applied = landlock::apply(&args.landlock).unwrap_or_else(|e| refuse(&format!("landlock: {e}")));
    let filter = filter_for(&applied, arch).unwrap_or_else(|e| refuse(&e.to_string()));
    if let Err(e) = seccomp::install(&filter) {
        refuse(&e.to_string());
    }
    // SAFETY: `program` and every `ptrs` entry are live NUL-terminated strings and `ptrs` ends with NULL; execv
    // keeps the current environment. It only returns on failure.
    unsafe { libc::execv(program.as_ptr(), ptrs.as_ptr()) };
    let e = std::io::Error::last_os_error();
    refuse(&format!(
        "cannot run {:?}: {e}",
        lossy(args.program.as_os_str().as_bytes())
    ))
}

/// In this crate's TEST binary only: `<test binary> sandbox-init <block>` behaves like `runtime sandbox-init`, so
/// the real-bwrap tests run the real shim code (the renderer names the running executable as the shim). glibc
/// calls `.init_array` entries before `main` with `(argc, argv, envp)`; for any other argv this returns and the
/// test harness starts as usual.
#[cfg(test)]
#[used]
#[unsafe(link_section = ".init_array")]
static TEST_SHIM: extern "C" fn(libc::c_int, *const *const libc::c_char, *const *const libc::c_char) = test_shim;

#[cfg(test)]
extern "C" fn test_shim(argc: libc::c_int, argv: *const *const libc::c_char, _envp: *const *const libc::c_char) {
    let argc = usize::try_from(argc).unwrap_or(0);
    // SAFETY: glibc passes the process's own argc and argv: `argc` live NUL-terminated strings.
    let arg = |i: usize| unsafe { std::ffi::CStr::from_ptr(*argv.add(i)) }.to_bytes();
    if argc < 2 || arg(1) != b"sandbox-init" {
        return;
    }
    let args: Vec<OsString> = (2..argc).map(|i| OsString::from_vec(arg(i).to_vec())).collect();
    main(&args)
}

#[cfg(test)]
mod tests;
