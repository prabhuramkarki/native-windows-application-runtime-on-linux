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
//!
//! # The contract (version [`BACKEND_API_VERSION`])
//!
//! [`CompatBackend`] is the only execution seam. Backends are Rust types compiled into the workspace and chosen by
//! id (`rt_api::backends::select`); there are no plugins and no dynamic loading of code (the source scan in
//! `tests/conformance.rs` and the `cargo deny` bans enforce it; `docs/SECURITY.md` says why). The contract, method
//! by method:
//!
//! * `id`: a constant `[a-z0-9-]{1,32}` word, recorded as the app's `backend.id`.
//! * `version`: spawns nothing outside `Launcher::run_helper`.
//! * `capabilities`: constant ([`Capabilities`]). The platform refuses what they exclude before it creates
//!   anything: `rt_core::install` (architecture, subsystem), `rt_installer::install_via_installer` (`installers`),
//!   `rt_deps::install_plan` (`dependency_packages`), `rt_core::run` (`dotnet`, for an app with Wine Mono recorded).
//! * `prepare`: creates the prefix so that `env.drive_c()` exists and is the guest's `C:`; idempotent; helpers
//!   only through the backend's `Launcher`.
//! * `command`: describes and never spawns; never calls `env_clear`; refuses an exe or cwd outside `env.drive_c()`
//!   ([`BackendError::OutsideDriveC`], see [`inside_drive_c`]); passes `args` verbatim; sets only its own
//!   variables (never `LD_PRELOAD`/`LD_LIBRARY_PATH`); the program is an absolute path.
//! * `stop`: with nothing running, succeeds. `dll_dirs`: absolute. `settle`: keeps the program and arguments of
//!   the command it wraps.
//! * A backend never reads the app's `permissions.toml`, never decides sandboxing (the `Launcher` and
//!   `rt_sandbox` do), never downloads, never writes outside `env.root()`.
//!
//! `rt_core::backend::conformance` checks what of this is observable; never spawning in `command` and the
//! prohibitions are reviewed, not proven.
//!
//! **What the platform assumes of every backend** (audit of Phase 6D): the prefix layout (`drive_c` is `C:`; the
//! install services copy programs below it and `resolve_under` maps metadata paths into it); the program
//! command carries `WINEPREFIX = env.prefix()` when it is to run in the app sandbox (`rt_sandbox` derives the app
//! from it and refuses a command without it: a backend that does not set it can run only `--unsandboxed`).
//! Gated by a capability because they read or write Wine's own layout: the installer pipeline (`system.reg`,
//! `user.reg`, `.lnk` files, `msiexec.exe` in `system32`: `installers`); dependency packages (DLL overrides and
//! Wine configuration in `user.reg`, `reg.exe`, the `wineserver`-in-`/proc` busy check: `dependency_packages`);
//! Wine Mono (`dotnet`).
//!
//! **Wine-specific, stays concrete** (Decision B5; a second backend brings its own): `doctor`'s Wine checks
//! (`backend_wine::harden::audit_prefix`, `check_app_home`, Wine's driver modules), the Wine-shaped fallback
//! command of `runtime sandbox` when Wine is missing (`rt_api::host::sandbox`), `backend_wine::harden_cause`,
//! `runtime display` (Wine's graphics driver in `user.reg`), and the `wineserver` checks of `remove`,
//! `uninstall` and `permissions --set` (they find no `wineserver` for another backend, so they refuse nothing).
use crate::{AppEnv, RunError};
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[cfg(any(test, feature = "testing"))]
pub mod conformance;

/// The version of the contract above; bumped on any change a backend must react to. `runtime doctor` prints it.
pub const BACKEND_API_VERSION: u32 = 1;

/// What a backend can run and take (see the module docs for where each is enforced).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Guest architectures it runs.
    pub arches: &'static [pe::Arch],
    /// Subsystems it runs.
    pub subsystems: &'static [pe::Subsystem],
    /// Honours [`RunOpts::dotnet`].
    pub dotnet: bool,
    /// Its prefix is what `rt_installer` reads (`drive_c`, `system.reg`/`user.reg`, `.lnk` files).
    pub installers: bool,
    /// `rt_deps` may install packages into its prefix (DLL overrides, Wine configuration).
    pub dependency_packages: bool,
}

impl Capabilities {
    /// `Ok` when `backend` (whose capabilities these are) runs programs of `arch` and `subsystem`.
    pub fn check(&self, backend: &'static str, arch: pe::Arch, subsystem: pe::Subsystem) -> Result<(), Unsupported> {
        if !self.arches.contains(&arch) {
            return Err(Unsupported::Arch {
                backend,
                arch: format!("{arch:?}").to_lowercase(),
            });
        }
        if !self.subsystems.contains(&subsystem) {
            return Err(Unsupported::Subsystem {
                backend,
                subsystem: format!("{subsystem:?}").to_lowercase(),
            });
        }
        Ok(())
    }
}

/// A refusal by capability: nothing was created.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unsupported {
    #[error("the {backend} backend does not run {arch} programs")]
    Arch { backend: &'static str, arch: String },
    #[error("the {backend} backend does not run programs of the {subsystem} subsystem")]
    Subsystem { backend: &'static str, subsystem: String },
    #[error("the {backend} backend does not support {feature}")]
    Feature {
        backend: &'static str,
        feature: &'static str,
    },
}

/// Whether [`inside_drive_c`] wants a regular file or a directory at the end of the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    File,
    Dir,
}

/// The containment check of `command`, for every backend: `p` is absolute, has no `..`, is component-wise below
/// `env.drive_c()` (else [`BackendError::OutsideDriveC`]), has no symlink on the way (`drive_c` itself included)
/// and is a regular file or a directory as `want` says (all by `lstat`; else `Failed` naming `what`). Returns the
/// normalised path: `drive_c` plus the verified components.
pub fn inside_drive_c(env: &AppEnv, p: &Path, what: &'static str, want: Want) -> Result<PathBuf, BackendError> {
    let root = env.drive_c();
    let outside = || BackendError::OutsideDriveC { what };
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(outside());
    }
    // `root` is absolute (`AppEnv` guarantees it), so a relative `p` fails here; whole components are compared.
    let rel = p.strip_prefix(&root).map_err(|_| outside())?;
    let io = |source| BackendError::Io { what, source };
    let not = |text: &[u8]| BackendError::failed(what, text);
    let mut cur = root.clone();
    let mut meta = std::fs::symlink_metadata(&cur).map_err(io)?;
    for comp in rel.components() {
        if meta.file_type().is_symlink() {
            return Err(not(b"the path goes through a symbolic link"));
        }
        cur.push(comp);
        meta = std::fs::symlink_metadata(&cur).map_err(io)?;
    }
    // A final symlink is neither a regular file nor a directory by lstat, so `want` refuses it too.
    let file_type = meta.file_type();
    match want {
        Want::File if !file_type.is_file() => Err(not(b"not a regular file")),
        Want::Dir if !file_type.is_dir() => Err(not(b"not a directory")),
        _ => Ok(cur),
    }
}

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

/// The execution seam; see the module docs for the contract every implementation keeps.
pub trait CompatBackend: Send + Sync {
    fn id(&self) -> &'static str;
    /// The backend's version string (what `doctor` and metadata record).
    fn version(&self) -> Result<String, BackendError>;
    /// What it can run and take. Constant; required (no default), so every backend states them.
    fn capabilities(&self) -> Capabilities;
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
    fn capabilities_check_each_arch_and_subsystem() {
        use pe::{Arch, Subsystem};
        let caps = Capabilities {
            arches: &[Arch::X86_64],
            subsystems: &[Subsystem::Gui, Subsystem::Console],
            dotnet: false,
            installers: false,
            dependency_packages: false,
        };
        assert_eq!(caps.check("t", Arch::X86_64, Subsystem::Gui), Ok(()));
        assert_eq!(caps.check("t", Arch::X86_64, Subsystem::Console), Ok(()));
        for arch in [Arch::X86, Arch::Arm64, Arch::Arm64Ec, Arch::Other(0x1c2)] {
            let e = caps.check("t", arch, Subsystem::Gui).unwrap_err();
            assert!(matches!(e, Unsupported::Arch { backend: "t", .. }), "{e:?}");
        }
        assert_eq!(
            caps.check("t", Arch::X86, Subsystem::Gui).unwrap_err().to_string(),
            "the t backend does not run x86 programs"
        );
        for sub in [Subsystem::Native, Subsystem::Efi, Subsystem::Other(9)] {
            let e = caps.check("t", Arch::X86_64, sub).unwrap_err();
            assert!(matches!(e, Unsupported::Subsystem { backend: "t", .. }), "{e:?}");
        }
        // The architecture is checked first.
        assert!(matches!(
            caps.check("t", Arch::X86, Subsystem::Efi),
            Err(Unsupported::Arch { .. })
        ));
    }

    #[test]
    fn failed_error_text_is_bounded() {
        let e = BackendError::failed("wineboot", &vec![b'x'; 5_000_000]);
        assert!(e.to_string().len() < MAX_DETAIL_BYTES + 100);
        assert!(e.to_string().starts_with("wineboot failed: xxx"));
    }
}
