//! The compatibility-backend seam: what a backend (Wine in Phase 2, others later) must provide, the typed errors,
//! and the host-environment allowlist the [`Launcher`](crate::Launcher) applies to every child.
//!
//! A backend only *describes* a process: [`CompatBackend::command`] returns a [`Command`] with its backend
//! variables (`WINEPREFIX`, ...) set through `.env()`, its working directory and its arguments. It must not call
//! `env_clear()` itself and must not spawn. The one place a `Command` is finalised (environment cleared, allowlist
//! applied, backend variables re-applied, sandbox hook) and started is the `Launcher`.
//!
//! **Helper processes** (`wineboot`, `wineserver -k`, `wine --version`) must be run with
//! [`Launcher::run_helper`](crate::Launcher::run_helper) on a `Launcher` the backend owns (it is `Clone`).
//! Never `Command::status()/output()/spawn()` directly: that would hand the helper the FULL host environment
//! (secrets, `LD_PRELOAD`). Convert its error with [`BackendError::from_run`].
//!
//! POSIX only: the crate is Linux-first and uses `OsStrExt` for byte-level name checks.
use crate::{AppEnv, RunError};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The most text an error keeps from a child's output or any other untrusted source.
pub const MAX_DETAIL_BYTES: usize = 4096;

/// Untrusted text embedded in an error, cut to [`MAX_DETAIL_BYTES`] (on a char boundary, lossy UTF-8). It may
/// still hold terminal escapes: print it through the CLI's `safe()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail(String);

impl Detail {
    pub fn from_bytes(raw: &[u8]) -> Detail {
        // Decode only the head: invalid bytes grow to 3 bytes (U+FFFD), so cut again afterwards.
        let mut s = String::from_utf8_lossy(&raw[..raw.len().min(MAX_DETAIL_BYTES)]).into_owned();
        let mut cut = s.len().min(MAX_DETAIL_BYTES);
        while !s.is_char_boundary(cut) {
            cut -= 1; // index 0 is always a boundary, so this ends
        }
        s.truncate(cut);
        Detail(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Detail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// The backend itself is missing (e.g. Wine is not installed); the text tells the user what to do.
    #[error("compatibility backend not available: {0}")]
    Unavailable(Detail),
    /// A path handed to the backend is not under the app's `drive_c`.
    #[error("{what} is not inside the app's drive_c")]
    OutsideDriveC { what: &'static str },
    /// A backend step ran and failed; `detail` is (capped) output of the step.
    #[error("{what} failed: {detail}")]
    Failed { what: &'static str, detail: Detail },
    /// The step was killed at its deadline; `output` is what it had printed (capped at 4 KiB).
    #[error("{what} did not finish within {secs} s; output: {output}")]
    TimedOut {
        what: &'static str,
        secs: u64,
        output: Detail,
    },
    #[error("{what}: {source}")]
    Io {
        what: &'static str,
        #[source]
        source: io::Error,
    },
}

impl BackendError {
    /// `Failed` from a step's raw output (capped here).
    pub fn failed(what: &'static str, output: &[u8]) -> BackendError {
        BackendError::Failed {
            what,
            detail: Detail::from_bytes(output),
        }
    }

    /// Converts the error of a helper run (`Launcher::run_helper`) for the step called `what`. A timeout keeps
    /// its (already capped) partial output.
    pub fn from_run(what: &'static str, e: RunError) -> BackendError {
        match e {
            RunError::TimedOut { after, output } => BackendError::TimedOut {
                what,
                secs: after.as_secs(),
                output,
            },
            RunError::Capture(source) | RunError::Spawn(source) | RunError::Wait(source) => {
                BackendError::Io { what, source }
            }
        }
    }
}

/// Per-run options. `debug`: verbose backend logging and the child's stderr also shown on the terminal.
/// `dotnet`: the app has Wine Mono recorded, so the backend enables `mscoree` for this program (only the
/// program: helpers never get it).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunOpts {
    pub debug: bool,
    pub dotnet: bool,
}

pub trait CompatBackend: Send + Sync {
    fn id(&self) -> &'static str;
    /// The backend's version string (what `doctor` and metadata record).
    fn version(&self) -> Result<String, BackendError>;
    /// Creates and hardens the prefix under `env.prefix()`. Idempotent; a failure may leave a partial prefix
    /// (the caller removes the whole environment). Helper processes go through `Launcher::run_helper`.
    fn prepare(&self, env: &AppEnv) -> Result<(), BackendError>;
    /// Describes the process for `exe_unix` (in `cwd_unix`, with `args` verbatim). The paths come from
    /// `winpath::resolve_under`; a backend rejects ones outside `env.drive_c()`. Does not spawn.
    fn command(
        &self,
        env: &AppEnv,
        exe_unix: &Path,
        cwd_unix: &Path,
        args: &[OsString],
        opts: &RunOpts,
    ) -> Result<Command, BackendError>;
    /// Stops whatever the backend runs for this app (Wine: `wineserver -k`, via `Launcher::run_helper`).
    /// "Nothing running" is success.
    fn stop(&self, env: &AppEnv) -> Result<(), BackendError>;
    /// Directories with the backend's built-in DLLs (for `doctor`).
    fn dll_dirs(&self) -> Vec<PathBuf>;
    /// Wraps `cmd` so it does not report done until whatever background process it started (if any) has also
    /// finished — e.g. Wine's `wineserver`, which keeps running after its client exits and flushes the registry
    /// to disk a few seconds later. This matters because a caller that tears down the whole process tree the
    /// instant the direct child exits (a `--unshare-pid` sandbox: see `rt_installer::InstallerSandbox`, which
    /// makes `bwrap` PID 1 of a fresh PID namespace) kills that background process before it gets to finish, and
    /// there is no way to fix this with a follow-up call afterwards — by the time such a call could run, the
    /// process is already dead. The wrapping has to happen INSIDE the same spawn `cmd` becomes, before the
    /// sandbox (or anything else) ever sees it. Identity by default: most backends spawn nothing persistent.
    fn settle(&self, cmd: Command) -> Command {
        cmd
    }
}

/// The variable names a child may inherit from the host, besides anything starting with `LC_`.
const ALLOWED: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LANGUAGE",
    "TERM",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "DBUS_SESSION_BUS_ADDRESS",
    "PULSE_SERVER",
];
const ALLOWED_PREFIX: &[u8] = b"LC_";

/// The part of `host` a child may see: names in the allowlist (`PATH HOME USER LOGNAME LANG LANGUAGE LC_* TERM
/// DISPLAY WAYLAND_DISPLAY XAUTHORITY XDG_RUNTIME_DIR XDG_SESSION_TYPE DBUS_SESSION_BUS_ADDRESS PULSE_SERVER`;
/// `LC_*` means "starts with `LC_`", so `LC_` alone matches and `LCX` does not). Everything else is dropped:
/// secrets, `SSH_AUTH_SOCK`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, any `WINE*`. A name must be non-empty printable
/// ASCII without `=`; a value must not contain NUL. Order of `host` is kept. Pass `std::env::vars_os()` for the
/// real environment or any list in tests (no process-environment mutation needed).
pub fn allowed_env<I, K, V>(host: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    host.into_iter()
        .filter(|(k, v)| {
            let (k, v) = (k.as_ref().as_bytes(), v.as_ref().as_bytes());
            name_is_well_formed(k) && is_allowed(k) && !v.contains(&0)
        })
        .map(|(k, v)| (k.as_ref().to_owned(), v.as_ref().to_owned()))
        .collect()
}

fn name_is_well_formed(name: &[u8]) -> bool {
    !name.is_empty() && name.iter().all(|b| b.is_ascii_graphic() && *b != b'=')
}

fn is_allowed(name: &[u8]) -> bool {
    name.starts_with(ALLOWED_PREFIX) || ALLOWED.iter().any(|a| a.as_bytes() == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(v: &[(OsString, OsString)]) -> Vec<String> {
        v.iter().map(|(k, _)| k.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn keeps_exactly_the_allowlisted_names() {
        let allowed = [
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "LANG",
            "LANGUAGE",
            "LC_ALL",
            "LC_CTYPE",
            "LC_",
            "TERM",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
            "XDG_RUNTIME_DIR",
            "XDG_SESSION_TYPE",
            "DBUS_SESSION_BUS_ADDRESS",
            "PULSE_SERVER",
        ];
        let denied = [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "SSH_AUTH_SOCK",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "WINEPREFIX",
            "WINEDEBUG",
            "WINEDLLOVERRIDES",
            "SECRET",
            "LCX",
            "LC",
            "XLC_ALL",
            "lc_all",
            "path",
            "Path",
            "HOME2",
            "XDG_DATA_HOME",
            "XDG_CONFIG_HOME",
            "XDG_SESSION_ID",
            "SHELL",
            "PWD",
            "EDITOR",
            "http_proxy",
            "DISPLAY_",
        ];
        let host: Vec<(&str, &str)> = allowed.iter().chain(denied.iter()).map(|n| (*n, "v")).collect();
        let got = names(&allowed_env(host));
        assert_eq!(got, allowed, "kept set differs (order of host is preserved)");
    }

    #[test]
    fn values_are_passed_through_unchanged() {
        let got = allowed_env([("PATH", "/usr/bin:/bin"), ("LC_ALL", "C.UTF-8")]);
        assert_eq!(
            got,
            vec![
                (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
                (OsString::from("LC_ALL"), OsString::from("C.UTF-8"))
            ]
        );
        // A non-UTF-8 value is fine.
        let raw = OsStr::from_bytes(b"/tmp/\xff\xfe");
        assert_eq!(allowed_env([(OsStr::new("HOME"), raw)])[0].1, raw);
    }

    #[test]
    fn a_value_with_nul_is_dropped() {
        let bad = OsStr::from_bytes(b"a\0b");
        let got = allowed_env([
            (OsStr::new("PATH"), bad),
            (OsStr::new("HOME"), OsStr::new("/home/u")),
            (OsStr::new("LC_ALL"), OsStr::from_bytes(b"\0")),
        ]);
        assert_eq!(names(&got), ["HOME"]);
    }

    #[test]
    fn malformed_names_are_dropped() {
        let got = allowed_env([
            (OsStr::new(""), OsStr::new("v")),
            (OsStr::new("LC_A=B"), OsStr::new("v")),
            (OsStr::new("LC_A B"), OsStr::new("v")),
            (OsStr::from_bytes(b"LC_\xc3\xa9"), OsStr::new("v")),
            (OsStr::from_bytes(b"LC_\0"), OsStr::new("v")),
            (OsStr::from_bytes(b"LC_\n"), OsStr::new("v")),
            (OsStr::new("LC_OK"), OsStr::new("v")),
        ]);
        assert_eq!(names(&got), ["LC_OK"]);
    }

    #[test]
    fn empty_host_gives_empty_env() {
        assert!(allowed_env(Vec::<(&str, &str)>::new()).is_empty());
    }

    #[test]
    fn detail_is_capped_on_a_char_boundary() {
        let d = Detail::from_bytes(&vec![b'a'; 1_000_000]);
        assert_eq!(d.as_str().len(), MAX_DETAIL_BYTES);
        // 3-byte chars: 4096 is not a multiple of 3, the cut must back up to a boundary.
        let d = Detail::from_bytes("€".repeat(10_000).as_bytes());
        assert!(d.as_str().len() <= MAX_DETAIL_BYTES);
        assert_eq!(d.as_str().len(), 4095);
        // Invalid bytes become U+FFFD (3 bytes each): the cap still holds after decoding.
        let d = Detail::from_bytes(&vec![0xffu8; 100_000]);
        assert!(d.as_str().len() <= MAX_DETAIL_BYTES, "{}", d.as_str().len());
    }

    #[test]
    fn from_run_keeps_the_timeout_output_and_maps_io_errors() {
        let out = Detail::from_bytes(b"partial output");
        let e = BackendError::from_run(
            "wineboot",
            RunError::TimedOut {
                after: std::time::Duration::from_millis(2500),
                output: out.clone(),
            },
        );
        match &e {
            BackendError::TimedOut { what, secs, output } => {
                assert_eq!((*what, *secs), ("wineboot", 2));
                assert_eq!(output, &out);
            }
            other => panic!("{other:?}"),
        }
        assert!(e.to_string().contains("partial output"), "{e}");
        let e = BackendError::from_run("wineboot", RunError::Spawn(io::Error::from(io::ErrorKind::NotFound)));
        assert!(matches!(e, BackendError::Io { what: "wineboot", .. }), "{e:?}");
        let e = BackendError::from_run("x", RunError::Wait(io::Error::from(io::ErrorKind::Other)));
        assert!(matches!(e, BackendError::Io { .. }));
        let e = BackendError::from_run("x", RunError::Capture(io::Error::from(io::ErrorKind::Other)));
        assert!(matches!(e, BackendError::Io { .. }));
    }

    #[test]
    fn failed_error_text_is_bounded() {
        let e = BackendError::failed("wineboot", &vec![b'x'; 5_000_000]);
        assert!(e.to_string().len() < MAX_DETAIL_BYTES + 100);
        assert!(e.to_string().starts_with("wineboot failed: xxx"));
    }
}
