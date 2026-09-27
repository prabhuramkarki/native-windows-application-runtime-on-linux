//! The system-Wine [`CompatBackend`]: `wine`/`wineserver` found by [`discover`], prefixes created and hardened
//! by [`harden`].
//!
//! Every helper process (`wine --version`, `wineboot -u`, `wineserver -k`) runs through
//! `Launcher::run_helper`: cleared environment, allowlist, then the backend's own variables. The process that
//! runs the app is only *described* by [`WineBackend::command`]; `Launcher::spawn` starts it.
//!
//! **`HOME` is the app's own directory.** Wine derives the Windows environment (`WINEHOMEDIR`, the shell
//! folders, its caches) from `HOME`, so a host `HOME` would hand the real home to every app. The backend
//! therefore sets `HOME` itself, to [`app_home`] (`<app>/runtime/home`, created 0700 by `prepare`), for `wineboot`,
//! `command()` and `wineserver -k` alike (backend variables win over the host allowlist in the `Launcher`).
//! `command()` refuses to run when that directory is not a real directory. `wine --version` has no app and keeps
//! the allowlisted host `HOME` (it prints the version and exits). This is hygiene, not a boundary: the app is
//! still the same uid and Wine's `\\?\unix\` paths still reach the real home.
//!
//! **Not a sandbox.** Wine can still reach the host (`\\?\unix\...` NT paths, the `com*` device links Wine
//! recreates on every start); see `harden` and Phase 5.
//!
//! # SIGPIPE and a lingering `wineserver` (verified on real Wine 10.0, see `tests/e2e_wine.rs`)
//! The first Wine process of a prefix starts the `wineserver` daemon, which inherits that process's STDERR (its
//! stdin and stdout are `/dev/null`) and outlives the process by ~3 s, or for as long as any other process
//! uses the prefix. In `--debug` mode stderr is the tee socket of `Launcher::spawn`; once `wait()` has joined
//! the tee, the socket has no reader, and a `wineserver` that later writes to it would get `EPIPE`. The
//! experiment `e2e_debug_run_survives_a_lingering_wineserver` shows that the server ignores `SIGPIPE`, survives
//! the end of the debug run and serves the next run. Nothing in this crate depends on that being true for
//! other Wine versions; the e2e test is the tripwire.
use rt_core::backend::Capabilities;
use rt_core::pe::{Arch, Subsystem};
use rt_core::{AppEnv, BackendError, CompatBackend, Detail, Launcher, RunOpts};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub mod discover;
pub mod harden;

/// [`CompatBackend::id`] of [`WineBackend`]: what `metadata.json` records as `backend.id`.
pub const BACKEND_ID: &str = "wine";

/// Wine's own `WINEDLLOVERRIDES` for every process but a managed app's program: no menu spam, no Mono/Gecko
/// download dialogs. `mscoree=d` also keeps Wine's own Mono prompt (and any Mono) off installers, helpers,
/// `prepare` and native programs.
pub const WINEDLLOVERRIDES: &str = "winemenubuilder.exe=d;mscoree=d;mshtml=d";

/// [`WINEDLLOVERRIDES`] without `mscoree=d`: only for the program of an app with Wine Mono recorded
/// ([`RunOpts::dotnet`], used by `command()` alone), so its `mscoree` loads the installed Mono.
pub const WINEDLLOVERRIDES_DOTNET: &str = "winemenubuilder.exe=d;mshtml=d";

/// [`CompatBackend::settle`]'s shell wrapper: a FIXED script text, never built with `format!` or any other
/// string-interpolation of caller-supplied data — the same "untrusted data only ever arrives as argv, never
/// substituted into program text" discipline this codebase already uses everywhere a shell is involved (e.g.
/// `InstallerSandbox::wrap` itself, `crate::uninstall`'s `split_command_line`/`resolve_uninstaller`). The
/// wineserver path, the real program and its arguments are all separate `Command::arg()` calls (separate argv
/// elements handed to `sh`), never spliced into this string.
///
/// `WS="$1"; shift` peels the wineserver path off the front of argv, so `"$@"` becomes exactly the original
/// program plus its own arguments; `"$@"` runs it, `rc=$?` captures its real exit status BEFORE anything else
/// can change `$?`. `"$WS" -w` then blocks until wineserver has no more clients for this prefix — Wine's own
/// `wineserver -w` semantics, and the same daemon this command's own client process would otherwise leave
/// running unsupervised — which is when it has flushed `system.reg`/`user.reg` to disk (verified empirically,
/// both standalone against real `sh` — this file's `settle_*` tests — and end-to-end with real Wine and bwrap,
/// `crates/cli/tests/e2e_installers.rs`'s registry-derived metadata assertions). Only then does `exit $rc`
/// return the original command's own status, not wineserver's.
///
/// This must run inside the SAME process tree as the original command, never as a separate follow-up call: a
/// `--unshare-pid` sandbox (`rt_installer::InstallerSandbox`) makes `bwrap` PID 1 of a fresh PID namespace, and
/// `bwrap` tears that namespace down (killing every process still in it, `wineserver` included) the instant its
/// own direct child — this whole `sh -c` invocation — exits. A follow-up command run after `wait()` returns
/// would be waiting on an already-dead process; wrapping the ORIGINAL invocation is the only place this can
/// work.
///
/// Residual risk (M7 of the Phase 3 final review; accepted, not actively bounded): if `wineserver -w` never
/// returns (a stuck Wine process still holding the prefix open), this step now blocks with no internal timeout,
/// where none existed before either (`pipeline::run_installer_process` already runs the installer itself with
/// no internal deadline, by design: a non-silent GUI install may need unbounded wall-clock time for a human).
/// In practice `wineserver -w` returns promptly once the direct child has exited and holds no other prefix
/// clients open.
const SETTLE_SCRIPT: &str = r#"WS="$1"; shift; "$@"; rc=$?; "$WS" -w >/dev/null 2>&1; exit $rc"#;

/// The per-app `HOME` (see the module docs): `<app>/runtime/home`.
pub fn app_home(env: &AppEnv) -> PathBuf {
    env.root().join("runtime").join("home")
}

/// Requires a real directory (by `lstat`: a link, even to a directory, is refused) at `path`.
fn require_real_dir(path: &Path, what: &'static str) -> Result<(), BackendError> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_dir() => Ok(()),
        Ok(_) => Err(BackendError::failed(
            what,
            b"not a real directory (a link or another kind of file)",
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(BackendError::failed(
            what,
            b"missing: this app was not prepared by this version, reinstall it",
        )),
        Err(source) => Err(BackendError::Io { what, source }),
    }
}

/// `prepare`: creates `<app>/runtime/home` (0700) if it is missing; `runtime/` and `home` must be real
/// directories (Wine is about to write below `home`; a link there would send it elsewhere).
fn ensure_app_home(env: &AppEnv) -> Result<(), BackendError> {
    let runtime = env.root().join("runtime");
    require_real_dir(&runtime, "app runtime directory")?;
    let mut builder = std::fs::DirBuilder::new();
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    match builder.create(app_home(env)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            require_real_dir(&app_home(env), "app home directory")
        }
        Err(source) => Err(BackendError::Io {
            what: "app home directory",
            source,
        }),
    }
}

/// `command`: `runtime/` and `home` are real directories (nothing is created here). `doctor` makes the same
/// check, so it and `run` agree on which apps are usable.
pub fn check_app_home(env: &AppEnv) -> Result<(), BackendError> {
    require_real_dir(&env.root().join("runtime"), "app runtime directory")?;
    require_real_dir(&app_home(env), "app home directory")
}

/// Deadlines of the helper steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub prepare: Duration,
    pub stop: Duration,
    pub version: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            prepare: Duration::from_secs(120),
            stop: Duration::from_secs(20),
            version: Duration::from_secs(20),
        }
    }
}

#[derive(Clone)]
pub struct WineBackend {
    wine: PathBuf,
    wineserver: PathBuf,
    dll_dirs: Vec<PathBuf>,
    launcher: Launcher,
    timeouts: Timeouts,
}

impl std::fmt::Debug for WineBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WineBackend")
            .field("wine", &self.wine)
            .field("wineserver", &self.wineserver)
            .field("dll_dirs", &self.dll_dirs)
            .field("timeouts", &self.timeouts)
            .finish_non_exhaustive()
    }
}

/// The version line of `wine --version` (`wine-10.0 (Ubuntu 10.0~repack-12)`), or `None` for anything else.
///
/// Only the FIRST line counts. It must be `wine-X.Y[.Z][-rcN]`, optionally followed by ` (...)`, valid UTF-8 and
/// without control characters; the result is cut to 128 characters.
pub fn parse_version(output: &[u8]) -> Option<String> {
    let line = output.split(|b| *b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end();
    if line.chars().any(char::is_control) {
        return None;
    }
    let (token, rest) = line.split_once(' ').unwrap_or((line, ""));
    let rest_ok = rest.is_empty() || (rest.starts_with('(') && rest.ends_with(')'));
    (valid_version_token(token) && rest_ok).then(|| line.chars().take(MAX_VERSION_CHARS).collect())
}

const MAX_VERSION_CHARS: usize = 128;

fn valid_version_token(token: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.len() <= 6 && s.bytes().all(|b| b.is_ascii_digit());
    let Some(v) = token.strip_prefix("wine-") else {
        return false;
    };
    let (numbers, rc) = match v.split_once("-rc") {
        Some((n, rc)) => (n, Some(rc)),
        None => (v, None),
    };
    let parts: Vec<&str> = numbers.split('.').collect();
    (2..=3).contains(&parts.len()) && parts.iter().all(|p| digits(p)) && rc.is_none_or(digits)
}

/// A hardening failure as `BackendError::Io` whose source wraps the typed [`harden::HardenError`]
/// (retrievable with [`harden_cause`]; `TooDeep`, `TooManyEntries` and `Symlink` stay distinguishable).
fn harden_error(what: &'static str, e: harden::HardenError) -> BackendError {
    BackendError::Io {
        what,
        source: std::io::Error::other(e),
    }
}

/// The typed hardening failure behind an error of [`WineBackend::prepare`], if it was one (a refused prefix
/// before `wineboot`, or a failed/incomplete hardening after it).
pub fn harden_cause(e: &BackendError) -> Option<&harden::HardenError> {
    match e {
        BackendError::Io { source, .. } => source.get_ref()?.downcast_ref(),
        _ => None,
    }
}

/// `err` (the failure of `wineboot`) with the failure of the `stop` that followed, if any: the caller must learn
/// that a wineserver may still be running in the prefix (Task 6 deletes the environment on a failed `prepare`).
/// Both parts are capped, the result stays within one `Detail`.
fn with_stop_note(err: BackendError, stopped: Result<(), BackendError>) -> BackendError {
    let Err(stop) = stopped else {
        return err;
    };
    let stop_text = stop.to_string();
    let note = format!(
        "; ALSO `wineserver -k` failed ({}): a wineserver may still be running in this prefix",
        Detail::from_bytes(&stop_text.as_bytes()[..stop_text.len().min(1200)])
    );
    let join = |head: &Detail| {
        let head = &head.as_str().as_bytes()[..head.as_str().len().min(2000)];
        Detail::from_bytes(&[head, note.as_bytes()].concat())
    };
    match err {
        BackendError::Failed { what, detail } => BackendError::Failed {
            what,
            detail: join(&detail),
        },
        BackendError::TimedOut { what, secs, output } => BackendError::TimedOut {
            what,
            secs,
            output: join(&output),
        },
        other => BackendError::Failed {
            what: "wineboot",
            detail: join(&Detail::from_bytes(other.to_string().as_bytes())),
        },
    }
}

impl WineBackend {
    /// Finds the system Wine (see [`discover`]); the error tells the user how to install it.
    pub fn discover() -> Result<WineBackend, BackendError> {
        WineBackend::discover_with(Launcher::new())
    }

    /// Like [`discover`](Self::discover), with the `Launcher` the services also use for `spawn`.
    pub fn discover_with(launcher: Launcher) -> Result<WineBackend, BackendError> {
        WineBackend::discover_using(
            launcher,
            &|k| std::env::var_os(k),
            &discover::is_executable_file,
            &discover::is_dir,
            &discover::canonicalize,
        )
    }

    pub(crate) fn discover_using(
        launcher: Launcher,
        env: &impl Fn(&str) -> Option<OsString>,
        is_file: &impl Fn(&Path) -> bool,
        is_dir: &impl Fn(&Path) -> bool,
        canonicalize: &impl Fn(&Path) -> Option<PathBuf>,
    ) -> Result<WineBackend, BackendError> {
        let found = discover::discover(env, is_file, is_dir, canonicalize)
            .map_err(|e| BackendError::Unavailable(Detail::from_bytes(e.to_string().as_bytes())))?;
        Ok(WineBackend::from_found(found, launcher))
    }

    /// The launcher this backend runs its helpers with; services use the same one to `spawn` (one place for the
    /// Phase 5 sandbox `wrap` hook).
    pub fn launcher(&self) -> &Launcher {
        &self.launcher
    }

    pub fn from_found(found: discover::Found, launcher: Launcher) -> WineBackend {
        WineBackend {
            wine: found.wine,
            wineserver: found.wineserver,
            dll_dirs: found.dll_dirs,
            launcher,
            timeouts: Timeouts::default(),
        }
    }

    pub fn with_timeouts(mut self, timeouts: Timeouts) -> WineBackend {
        self.timeouts = timeouts;
        self
    }

    pub fn wine_path(&self) -> &Path {
        &self.wine
    }

    pub fn wineserver_path(&self) -> &Path {
        &self.wineserver
    }

    /// `<wine>` with the variables every Wine process of this app gets. `Launcher::finalize` re-applies them
    /// after clearing the environment.
    /// `dotnet` selects [`WINEDLLOVERRIDES_DOTNET`]: `true` only in `command()`, from [`RunOpts::dotnet`]; every
    /// helper passes `false`.
    fn wine_command(&self, env: &AppEnv, winedebug: &str, dotnet: bool) -> Command {
        let mut cmd = Command::new(&self.wine);
        cmd.env("WINEPREFIX", env.prefix())
            .env("HOME", app_home(env))
            .env("WINEARCH", "win64")
            .env("WINEDEBUG", winedebug)
            .env(
                "WINEDLLOVERRIDES",
                if dotnet {
                    WINEDLLOVERRIDES_DOTNET
                } else {
                    WINEDLLOVERRIDES
                },
            )
            .env("WINESERVER", &self.wineserver);
        cmd
    }
}

impl CompatBackend for WineBackend {
    fn id(&self) -> &'static str {
        BACKEND_ID
    }

    fn version(&self) -> Result<String, BackendError> {
        let mut cmd = Command::new(&self.wine);
        cmd.arg("--version").env("WINEDEBUG", "-all");
        let out = self
            .launcher
            .run_helper(cmd, self.timeouts.version)
            .map_err(|e| BackendError::from_run("wine --version", e))?;
        if !out.status.success() {
            return Err(BackendError::failed("wine --version", &out.output));
        }
        parse_version(&out.output).ok_or_else(|| BackendError::failed("wine --version", &out.output))
    }

    /// 32- and 64-bit GUI and console programs (a `win64` prefix with WoW64); Wine Mono, the installer pipeline
    /// and dependency packages all work on its prefix layout.
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            arches: &[Arch::X86, Arch::X86_64],
            subsystems: &[Subsystem::Gui, Subsystem::Console],
            dotnet: true,
            installers: true,
            dependency_packages: true,
        }
    }

    /// `wineboot -u` (deadline 120 s, `WINEDEBUG=-all`), then ALWAYS `wineserver -k` (also after a failure or
    /// a timeout: killing `wineboot` does not kill the server it started), then, if `wineboot` succeeded, the
    /// hardening. The server is stopped first so no Wine process races the hardening.
    fn prepare(&self, env: &AppEnv) -> Result<(), BackendError> {
        let prefix = env.prefix();
        // Wine follows links: refuse before it writes anything through one.
        harden::precheck(&prefix).map_err(|e| harden_error("prefix", e))?;
        ensure_app_home(env)?;
        let mut cmd = self.wine_command(env, "-all", false);
        cmd.args(["wineboot", "-u"]);
        let booted = self.launcher.run_helper(cmd, self.timeouts.prepare);
        let stopped = self.stop(env);
        let out = match booted {
            Ok(out) => out,
            Err(e) => return Err(with_stop_note(BackendError::from_run("wineboot", e), stopped)),
        };
        if !out.status.success() {
            let mut detail = format!("{}: ", out.status).into_bytes();
            detail.extend_from_slice(&out.output);
            return Err(with_stop_note(BackendError::failed("wineboot", &detail), stopped));
        }
        stopped?;
        let report = harden::harden_prefix(&prefix).map_err(|e| harden_error("prefix hardening", e))?;
        tracing::debug!(?report, "prefix hardened");
        Ok(())
    }

    /// `<wine> <exe> <args...>` with the backend variables (`HOME` is [`app_home`], which must be a real
    /// directory) and `current_dir(cwd)`. `exe_unix` and `cwd_unix`
    /// are the RESOLVED host paths the caller got from `winpath::resolve_under` (never Windows text: Wine would
    /// expand `PROGRA~1` and follow links). They are re-checked here because the fake backend does not:
    /// absolute, no `..`, component-wise under `env.drive_c()`, no symlink on the way, the exe a regular file
    /// and the cwd a directory (all by `lstat`).
    fn command(
        &self,
        env: &AppEnv,
        exe_unix: &Path,
        cwd_unix: &Path,
        args: &[OsString],
        opts: &RunOpts,
    ) -> Result<Command, BackendError> {
        check_app_home(env)?;
        let root = env.drive_c();
        // Wine gets the NORMALISED paths (`drive_c` + the verified components), not the caller's spelling.
        let exe_unix = check_inside(&root, exe_unix, "executable", Want::File)?;
        let cwd_unix = check_inside(&root, cwd_unix, "working directory", Want::Dir)?;
        let mut cmd = self.wine_command(env, if opts.debug { "err+all,fixme-all" } else { "-all" }, opts.dotnet);
        cmd.arg(&exe_unix).args(args).current_dir(&cwd_unix);
        Ok(cmd)
    }

    /// `wineserver -k` for this prefix (deadline 20 s). Exit 0, and 1 (no server running), are success.
    fn stop(&self, env: &AppEnv) -> Result<(), BackendError> {
        let mut cmd = Command::new(&self.wineserver);
        cmd.arg("-k").env("WINEPREFIX", env.prefix()).env("HOME", app_home(env));
        let out = self
            .launcher
            .run_helper(cmd, self.timeouts.stop)
            .map_err(|e| BackendError::from_run("wineserver -k", e))?;
        match out.status.code() {
            Some(0 | 1) => Ok(()),
            _ => Err(BackendError::failed("wineserver -k", &out.output)),
        }
    }

    fn dll_dirs(&self) -> Vec<PathBuf> {
        self.dll_dirs.clone()
    }

    /// Wraps `cmd` in [`SETTLE_SCRIPT`] (see its own docs for exactly why and how): `/bin/sh -c <script> sh
    /// <wineserver> <program> <args...>`, with `cmd`'s env and cwd carried over unchanged. `cmd`'s own program
    /// and args are read back with `get_program`/`get_args` (the same introspection this crate's tests already
    /// use), never re-derived, so this is a pure wrap of whatever `command()` built — it does not know or care
    /// whether that was a real installer, `msiexec`, or anything else.
    fn settle(&self, cmd: Command) -> Command {
        let mut out = Command::new("/bin/sh");
        out.arg("-c").arg(SETTLE_SCRIPT).arg("sh").arg(&self.wineserver);
        out.arg(cmd.get_program());
        out.args(cmd.get_args());
        for (k, v) in cmd.get_envs() {
            match v {
                Some(v) => {
                    out.env(k, v);
                }
                None => {
                    out.env_remove(k);
                }
            }
        }
        if let Some(dir) = cmd.get_current_dir() {
            out.current_dir(dir);
        }
        out
    }
}

enum Want {
    File,
    Dir,
}

/// See [`WineBackend::command`]. `root` is absolute (`AppEnv` guarantees it), so a relative `p` fails the
/// `strip_prefix`. Returns the normalised path: `root` plus the verified components.
fn check_inside(root: &Path, p: &Path, what: &'static str, want: Want) -> Result<PathBuf, BackendError> {
    let outside = || BackendError::OutsideDriveC { what };
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(outside());
    }
    let rel = p.strip_prefix(root).map_err(|_| outside())?; // compares whole components
    let io = |source| BackendError::Io { what, source };
    let not = |text: &[u8]| BackendError::failed(what, text);
    // Every step by lstat: a link anywhere on the way (drive_c itself included) is refused.
    let mut cur = root.to_path_buf();
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

#[cfg(test)]
mod tests {
    use super::*;
    use rt_core::{AppId, Store};
    use std::collections::BTreeSet;
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::Instant;

    // ---- version parser ----

    #[test]
    fn parse_version_table() {
        let ok = |input: &str, want: &str| {
            assert_eq!(parse_version(input.as_bytes()).as_deref(), Some(want), "{input:?}");
        };
        ok(
            "wine-10.0 (Ubuntu 10.0~repack-12ubuntu1)\n",
            "wine-10.0 (Ubuntu 10.0~repack-12ubuntu1)",
        );
        ok("wine-10.0\n", "wine-10.0");
        ok("wine-9.0.1 (Debian)", "wine-9.0.1 (Debian)");
        ok("wine-10.0-rc3 (Staging)\r\n", "wine-10.0-rc3 (Staging)");
        ok("wine-9.22-rc1\n", "wine-9.22-rc1");
        ok("wine-10.0\nsecond line is ignored\n", "wine-10.0");
        ok("wine-10.0   \n", "wine-10.0");
        ok("wine-8.21 (Staging)\nwine: something else\n", "wine-8.21 (Staging)");
        for bad in [
            "",
            "\n",
            " ",
            "wine",
            "wine-",
            "wine-x.y",
            "wine-10",
            "wine-10.",
            "wine-10.0.",
            "wine-10.0.1.2",
            "wine-10.0-beta",
            "wine-10.0-rc",
            "wine-10.0 Ubuntu",
            "wine-10.0(Ubuntu)",
            "wine-10.0x",
            "Wine-10.0",
            "wine 10.0",
            "wine-10.0 (Ubuntu\u{1b}[31m)",
            "wine-10.0 (a\0b)",
            "wine: cannot find '/usr/lib/wine/wine64'\n",
            "bash: wine: command not found\nwine-10.0\n",
            "\u{feff}wine-10.0",
        ] {
            assert_eq!(parse_version(bad.as_bytes()), None, "{bad:?}");
        }
        assert_eq!(parse_version(b"\xff\xfe\xfd"), None);
        assert_eq!(
            parse_version(b"wine-10.0 (\xff\xfe)"),
            None,
            "invalid UTF-8 is garbage, not lossy-accepted"
        );
    }

    #[test]
    fn parse_version_caps_length_and_survives_huge_input() {
        let huge = format!("wine-10.0 ({})\n", "a".repeat(1_000_000));
        let v = parse_version(huge.as_bytes()).unwrap();
        assert_eq!(v.chars().count(), 128);
        assert!(v.starts_with("wine-10.0 (aaa"));
        // Multi-byte text is cut on a char boundary.
        let multi = format!("wine-10.0 ({})", "é".repeat(500));
        assert_eq!(parse_version(multi.as_bytes()).unwrap().chars().count(), 128);
        // No newline, no space: still no panic, still garbage.
        assert_eq!(parse_version(&vec![b'a'; 5_000_000]), None);
        assert_eq!(
            parse_version(format!("wine-10.0{}", "0".repeat(1_000_000)).as_bytes()),
            None
        );
        assert_eq!(parse_version(&vec![0u8; 100_000]), None);
    }

    // ---- fake wine / wineserver: shell scripts that record how they were run ----

    struct Rig {
        _t: tempfile::TempDir,
        root: PathBuf,
        bin: PathBuf,
        log: PathBuf,
        outside: PathBuf,
        env: AppEnv,
    }

    const WINE_DEFAULT: &str = r#"
case "$1" in
  --version) echo 'wine-10.0 (Fake 1)' ;;
  wineboot)
    P="$WINEPREFIX"
    mkdir -p "$P/dosdevices" "$P/drive_c/users/u/AppData/Roaming/Microsoft/Windows" "$P/drive_c/windows"
    ln -s ../drive_c "$P/dosdevices/c:"; ln -s / "$P/dosdevices/z:"; ln -s /dev/ttyS0 "$P/dosdevices/com1"
    ln -s @OUTSIDE@/Desktop "$P/drive_c/users/u/Desktop"
    ln -s @OUTSIDE@/Desktop "$P/drive_c/users/u/AppData/Roaming/Microsoft/Windows/Templates"
    : > "$P/system.reg" ;;
  *) printf '%s\0' "$@" > @LOG@/argv.bin ;;
esac
"#;

    fn script(path: &Path, body: &str) {
        fs::write(path, format!("#!/bin/sh\n[ \"$1\" = --rig-probe ] && exit 0\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        // Another test thread may have forked while the file was open for writing; that child holds the write
        // fd until its exec, and executing the script meanwhile fails with ETXTBSY ("Text file busy"). Probe
        // until the script can be executed, so the test proper never sees it.
        for _ in 0..500 {
            let probe = Command::new(path)
                .arg("--rig-probe")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            match probe {
                Err(e) if e.raw_os_error() == Some(26) => std::thread::sleep(Duration::from_millis(4)),
                _ => break,
            }
        }
    }

    fn rig_with(wine_body: &str, wineserver_body: &str) -> Rig {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().canonicalize().unwrap();
        let (bin, log, outside) = (root.join("bin"), root.join("log"), root.join("outside"));
        for d in [&bin, &log, &outside.join("Desktop")] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(outside.join("Desktop/canary.txt"), b"canary").unwrap();
        let fill = |s: &str| {
            s.replace("@OUTSIDE@", outside.to_str().unwrap())
                .replace("@LOG@", log.to_str().unwrap())
        };
        script(
            &bin.join("wine"),
            &fill(&format!(
                "echo \"wine $*\" >> @LOG@/calls.txt\nenv | sort > @LOG@/env-wine.txt\n{wine_body}"
            )),
        );
        script(
            &bin.join("wineserver"),
            &fill(&format!(
                "echo \"wineserver $* [WINEPREFIX=$WINEPREFIX]\" >> @LOG@/calls.txt\nenv | sort > @LOG@/env-wineserver.txt\n{wineserver_body}"
            )),
        );
        let store = Store::new(root.join("apps")).unwrap();
        let env = store.create(&AppId::parse("t").unwrap()).unwrap();
        // Like an app that `prepare` has already been run for.
        fs::create_dir(app_home(&env)).unwrap();
        Rig {
            _t: t,
            root,
            bin,
            log,
            outside,
            env,
        }
    }

    fn rig() -> Rig {
        rig_with(WINE_DEFAULT, "exit 0")
    }

    impl Rig {
        fn backend(&self) -> WineBackend {
            let launcher = Launcher::with_host_env([
                ("PATH", "/usr/bin:/bin"),
                ("HOME", "/injected-home"),
                ("SECRET", "hunter2"),
                ("LD_PRELOAD", "/evil.so"),
                ("WINEPREFIX", "/host/prefix"),
                ("AWS_SECRET_ACCESS_KEY", "aws"),
            ]);
            WineBackend::from_found(
                discover::Found {
                    wine: self.bin.join("wine"),
                    wineserver: self.bin.join("wineserver"),
                    dll_dirs: vec![],
                },
                launcher,
            )
        }
        fn calls(&self) -> Vec<String> {
            fs::read_to_string(self.log.join("calls.txt"))
                .unwrap_or_default()
                .lines()
                .map(String::from)
                .collect()
        }
        fn env_of(&self, file: &str) -> Vec<(String, String)> {
            fs::read_to_string(self.log.join(file))
                .unwrap_or_else(|e| panic!("{file}: {e} (the helper did not run)"))
                .lines()
                .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
                .collect()
        }
        /// A regular exe file under drive_c (creating the directories) and its directory.
        fn exe(&self, rel: &str) -> (PathBuf, PathBuf) {
            let exe = self.env.drive_c().join(rel);
            let dir = exe.parent().unwrap().to_path_buf();
            fs::create_dir_all(&dir).unwrap();
            fs::write(&exe, b"MZ").unwrap();
            (exe, dir)
        }
    }

    /// The helper saw exactly the allowlisted host variables plus the backend's own ones, nothing else.
    fn assert_only_allowlist_and_backend_vars(got: &[(String, String)], backend_vars: &[(&str, &str)]) {
        let get = |k: &str| got.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        // HOME is the host's (injected) one unless the backend sets it: then the backend's value must win.
        let want_home = backend_vars
            .iter()
            .find(|(k, _)| *k == "HOME")
            .map_or("/injected-home", |(_, v)| *v);
        assert_eq!(get("HOME"), Some(want_home), "{got:?}");
        assert_eq!(got.iter().filter(|(k, _)| k == "HOME").count(), 1, "{got:?}");
        assert_eq!(get("PATH"), Some("/usr/bin:/bin"), "{got:?}");
        let shell_added = ["PWD", "SHLVL", "_", "OLDPWD"];
        let expected: BTreeSet<&str> = ["HOME", "PATH"]
            .into_iter()
            .chain(backend_vars.iter().map(|(k, _)| *k))
            .chain(shell_added)
            .collect();
        let names: BTreeSet<&str> = got.iter().map(|(k, _)| k.as_str()).collect();
        let extra: Vec<_> = names.difference(&expected).collect();
        assert!(extra.is_empty(), "the helper saw host variables it must not: {extra:?}");
        for (k, v) in backend_vars {
            assert_eq!(get(k), Some(*v), "backend var {k}");
        }
        assert_eq!(
            got.iter().filter(|(k, _)| k == "WINEPREFIX").count(),
            backend_vars.iter().filter(|(k, _)| *k == "WINEPREFIX").count()
        );
    }

    // ---- helpers run through Launcher::run_helper ----

    #[test]
    fn version_runs_through_run_helper() {
        let r = rig();
        assert_eq!(r.backend().version().unwrap(), "wine-10.0 (Fake 1)");
        // The host WINEPREFIX from the injected env must not reach the helper either.
        assert_only_allowlist_and_backend_vars(&r.env_of("env-wine.txt"), &[("WINEDEBUG", "-all")]);
        assert_eq!(r.calls(), ["wine --version"]);
    }

    #[test]
    fn prepare_runs_through_run_helper() {
        let r = rig();
        let ws = r.bin.join("wineserver");
        r.backend().prepare(&r.env).unwrap();
        let prefix = r.env.prefix();
        let home = app_home(&r.env);
        assert_only_allowlist_and_backend_vars(
            &r.env_of("env-wine.txt"),
            &[
                ("HOME", home.to_str().unwrap()),
                ("WINEPREFIX", prefix.to_str().unwrap()),
                ("WINEARCH", "win64"),
                ("WINEDEBUG", "-all"),
                ("WINEDLLOVERRIDES", "winemenubuilder.exe=d;mscoree=d;mshtml=d"),
                ("WINESERVER", ws.to_str().unwrap()),
            ],
        );
    }

    #[test]
    fn stop_runs_through_run_helper() {
        let r = rig();
        r.backend().stop(&r.env).unwrap();
        assert_only_allowlist_and_backend_vars(
            &r.env_of("env-wineserver.txt"),
            &[
                ("HOME", app_home(&r.env).to_str().unwrap()),
                ("WINEPREFIX", r.env.prefix().to_str().unwrap()),
            ],
        );
    }

    // ---- version ----

    #[test]
    fn version_rejects_garbage_a_failing_exit_and_a_hang() {
        let r = rig_with("echo 'bash: wine: command not found'", "exit 0");
        assert!(matches!(
            r.backend().version(),
            Err(BackendError::Failed {
                what: "wine --version",
                ..
            })
        ));
        let r = rig_with("echo 'wine-10.0 (Fake)'; exit 3", "exit 0");
        assert!(
            matches!(r.backend().version(), Err(BackendError::Failed { .. })),
            "a failing exit is an error"
        );
        let r = rig_with("exec sleep 30", "exit 0");
        let t = Timeouts {
            version: Duration::from_secs(1),
            ..Timeouts::default()
        };
        let started = Instant::now();
        let e = r.backend().with_timeouts(t).version().unwrap_err();
        assert!(
            matches!(
                e,
                BackendError::TimedOut {
                    what: "wine --version",
                    secs: 1,
                    ..
                }
            ),
            "{e:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        let mut b = r.backend();
        b.wine = r.root.join("missing/wine");
        assert!(matches!(b.version(), Err(BackendError::Io { .. })));
    }

    // ---- prepare ----

    #[test]
    fn prepare_creates_then_stops_then_hardens_the_prefix() {
        let r = rig();
        r.backend().prepare(&r.env).unwrap();
        let prefix = r.env.prefix();
        assert_eq!(
            r.calls(),
            [
                "wine wineboot -u".to_string(),
                format!("wineserver -k [WINEPREFIX={}]", prefix.display())
            ]
        );
        let dd: Vec<_> = fs::read_dir(prefix.join("dosdevices"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(dd, [OsString::from("c:")]);
        for link in ["Desktop", "AppData/Roaming/Microsoft/Windows/Templates"] {
            let p = r.env.drive_c().join("users/u").join(link);
            let m = fs::symlink_metadata(&p).unwrap();
            assert!(m.is_dir(), "{link}");
            assert_eq!(fs::read_dir(&p).unwrap().count(), 0, "{link}");
        }
        assert!(prefix.join("system.reg").is_file());
        assert_eq!(fs::read(r.outside.join("Desktop/canary.txt")).unwrap(), b"canary");
    }

    #[test]
    fn prepare_is_idempotent_on_an_existing_prefix() {
        let r = rig();
        let b = r.backend();
        b.prepare(&r.env).unwrap();
        b.prepare(&r.env).unwrap();
        assert_eq!(r.calls().len(), 4);
    }

    #[test]
    fn prepare_stops_the_server_even_when_wineboot_fails() {
        let r = rig_with(
            "case \"$1\" in wineboot) echo 'wine: boom' >&2; exit 3;; esac",
            "exit 0",
        );
        let e = r.backend().prepare(&r.env).unwrap_err();
        match &e {
            BackendError::Failed {
                what: "wineboot",
                detail,
            } => {
                assert!(detail.as_str().contains("boom"), "{detail}");
                assert!(
                    detail.as_str().contains('3'),
                    "the exit status is part of the message: {detail}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(r.calls().len(), 2, "{:?}", r.calls());
        assert!(r.calls()[1].starts_with("wineserver -k"), "{:?}", r.calls());
    }

    #[test]
    fn prepare_stops_the_server_even_when_wineboot_times_out() {
        let r = rig_with("case \"$1\" in wineboot) exec sleep 30;; esac", "exit 0");
        let t = Timeouts {
            prepare: Duration::from_secs(1),
            ..Timeouts::default()
        };
        let started = Instant::now();
        let e = r.backend().with_timeouts(t).prepare(&r.env).unwrap_err();
        assert!(
            matches!(
                e,
                BackendError::TimedOut {
                    what: "wineboot",
                    secs: 1,
                    ..
                }
            ),
            "{e:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(
            r.calls().iter().any(|c| c.starts_with("wineserver -k")),
            "{:?}",
            r.calls()
        );
    }

    #[test]
    fn prepare_does_not_harden_a_prefix_whose_wineboot_failed() {
        let r = rig_with(
            "case \"$1\" in wineboot) mkdir -p \"$WINEPREFIX/dosdevices\"; ln -s / \"$WINEPREFIX/dosdevices/z:\"; exit 1;; esac",
            "exit 0",
        );
        r.backend().prepare(&r.env).unwrap_err();
        // The caller removes the whole environment on failure; nothing was "half repaired".
        assert!(fs::symlink_metadata(r.env.prefix().join("dosdevices/z:")).is_ok());
    }

    #[test]
    fn prepare_reports_a_failing_stop() {
        let r = rig_with(WINE_DEFAULT, "echo 'wineserver: cannot kill' >&2; exit 5");
        let e = r.backend().prepare(&r.env).unwrap_err();
        assert!(
            matches!(
                e,
                BackendError::Failed {
                    what: "wineserver -k",
                    ..
                }
            ),
            "{e:?}"
        );
    }

    #[test]
    fn prepare_reports_a_wineboot_that_cannot_be_started() {
        let r = rig();
        let mut b = r.backend();
        b.wine = r.root.join("missing/wine");
        assert!(matches!(
            b.prepare(&r.env),
            Err(BackendError::Io { what: "wineboot", .. })
        ));
        assert!(
            r.calls().iter().any(|c| c.starts_with("wineserver -k")),
            "stop still ran"
        );
    }

    #[test]
    fn prepare_refuses_a_symlinked_prefix_before_running_wine() {
        let r = rig();
        let victim = r.root.join("victim");
        fs::create_dir(&victim).unwrap();
        symlink(&victim, r.env.prefix()).unwrap();
        let e = r.backend().prepare(&r.env).unwrap_err();
        assert!(matches!(e, BackendError::Io { what: "prefix", .. }), "{e:?}");
        assert!(
            matches!(harden_cause(&e), Some(harden::HardenError::Symlink { what: "prefix" })),
            "{e:?}"
        );
        assert!(r.calls().is_empty(), "wine must not have run: {:?}", r.calls());
        assert_eq!(fs::read_dir(&victim).unwrap().count(), 0);
    }

    #[test]
    fn prepare_refuses_a_symlinked_drive_c_before_running_wine() {
        let r = rig();
        let victim = r.root.join("victim");
        fs::create_dir(&victim).unwrap();
        fs::create_dir(r.env.prefix()).unwrap();
        symlink(&victim, r.env.drive_c()).unwrap();
        let e = r.backend().prepare(&r.env).unwrap_err();
        assert!(matches!(e, BackendError::Io { what: "prefix", .. }), "{e:?}");
        assert!(
            matches!(harden_cause(&e), Some(harden::HardenError::Symlink { what: "drive_c" })),
            "{e:?}"
        );
        assert!(r.calls().is_empty(), "{:?}", r.calls());
    }

    // ---- the per-app HOME ----

    #[test]
    fn prepare_creates_the_app_home_private_and_wineboot_runs_with_it() {
        let r = rig();
        let home = r.env.root().join("runtime/home");
        fs::remove_dir(&home).unwrap();
        r.backend().prepare(&r.env).unwrap();
        let m = fs::symlink_metadata(&home).unwrap();
        assert!(m.is_dir(), "the app home is a real directory");
        assert_eq!(m.permissions().mode() & 0o777, 0o700);
        let seen = r.env_of("env-wine.txt");
        assert_eq!(
            seen.iter().find(|(k, _)| k == "HOME").map(|(_, v)| v.as_str()),
            home.to_str(),
            "wineboot must not see the host HOME (/injected-home)"
        );
        // A second prepare accepts the existing directory.
        r.backend().prepare(&r.env).unwrap();
    }

    #[test]
    fn prepare_refuses_an_app_home_that_is_a_link_or_a_file_before_running_wine() {
        for kind in ["symlink", "file"] {
            let r = rig();
            let home = r.env.root().join("runtime/home");
            fs::remove_dir(&home).unwrap();
            if kind == "symlink" {
                let victim = r.root.join("victim");
                fs::create_dir(&victim).unwrap();
                symlink(&victim, &home).unwrap();
            } else {
                fs::write(&home, b"x").unwrap();
            }
            let e = r.backend().prepare(&r.env).unwrap_err();
            assert!(
                matches!(
                    &e,
                    BackendError::Failed {
                        what: "app home directory",
                        ..
                    }
                ),
                "{kind}: {e:?}"
            );
            assert!(r.calls().is_empty(), "{kind}: wine must not have run: {:?}", r.calls());
        }
        // `runtime/` itself a link: refused as well (creating `home` would go through it).
        let r = rig();
        let victim = r.root.join("victim");
        fs::create_dir(&victim).unwrap();
        fs::remove_dir(app_home(&r.env)).unwrap();
        fs::remove_dir(r.env.root().join("runtime")).unwrap();
        symlink(&victim, r.env.root().join("runtime")).unwrap();
        let e = r.backend().prepare(&r.env).unwrap_err();
        assert!(
            matches!(
                &e,
                BackendError::Failed {
                    what: "app runtime directory",
                    ..
                }
            ),
            "{e:?}"
        );
        assert_eq!(
            fs::read_dir(&victim).unwrap().count(),
            0,
            "nothing was created through the link"
        );
        assert!(r.calls().is_empty());
    }

    #[test]
    fn command_refuses_a_missing_or_linked_app_home() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/a.exe");
        let b = r.backend();
        let go = || b.command(&r.env, &exe, &dir, &[], &RunOpts::default());
        assert!(go().is_ok());
        let home = app_home(&r.env);
        fs::remove_dir(&home).unwrap();
        assert!(
            matches!(
                go(),
                Err(BackendError::Failed {
                    what: "app home directory",
                    ..
                })
            ),
            "missing"
        );
        let victim = r.root.join("victim");
        fs::create_dir(&victim).unwrap();
        symlink(&victim, &home).unwrap();
        assert!(
            matches!(
                go(),
                Err(BackendError::Failed {
                    what: "app home directory",
                    ..
                })
            ),
            "a link to a directory"
        );
        fs::remove_file(&home).unwrap();
        fs::write(&home, b"x").unwrap();
        assert!(matches!(go(), Err(BackendError::Failed { .. })), "a file");
        fs::remove_file(&home).unwrap();
        fs::create_dir(&home).unwrap();
        // `runtime/` replaced by a link to a directory that has a `home` inside: refused too.
        fs::create_dir(victim.join("home")).unwrap();
        fs::remove_dir(&home).unwrap();
        fs::remove_dir(r.env.root().join("runtime")).unwrap();
        symlink(&victim, r.env.root().join("runtime")).unwrap();
        assert!(
            matches!(
                go(),
                Err(BackendError::Failed {
                    what: "app runtime directory",
                    ..
                })
            ),
            "runtime/ is a link"
        );
    }

    #[test]
    fn the_program_runs_with_the_app_home_whatever_the_host_home_is() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/a.exe");
        let cmd = r
            .backend()
            .command(&r.env, &exe, &dir, &[], &RunOpts::default())
            .unwrap();
        // The launcher's host environment says HOME=/injected-home (and other secrets): the backend wins.
        let out = r.backend().launcher().run_helper(cmd, Duration::from_secs(10)).unwrap();
        assert!(out.status.success());
        let seen = r.env_of("env-wine.txt");
        let home = app_home(&r.env);
        assert_eq!(
            seen.iter().find(|(k, _)| k == "HOME").map(|(_, v)| v.as_str()),
            home.to_str(),
            "{seen:?}"
        );
        assert!(!seen.iter().any(|(_, v)| v.contains("/injected-home")), "{seen:?}");
    }

    // ---- stop ----

    #[test]
    fn stop_treats_exit_0_and_1_as_success_and_anything_else_as_an_error() {
        for (code, ok) in [(0, true), (1, true), (2, false), (127, false), (255, false)] {
            let r = rig_with(WINE_DEFAULT, &format!("exit {code}"));
            let res = r.backend().stop(&r.env);
            assert_eq!(res.is_ok(), ok, "exit {code}: {res:?}");
            if !ok {
                assert!(matches!(
                    res,
                    Err(BackendError::Failed {
                        what: "wineserver -k",
                        ..
                    })
                ));
            }
        }
        // Killed by a signal: no exit code, an error.
        let r = rig_with(WINE_DEFAULT, "kill -9 $$");
        assert!(r.backend().stop(&r.env).is_err());
    }

    #[test]
    fn stop_passes_wineprefix_and_dash_k() {
        let r = rig();
        r.backend().stop(&r.env).unwrap();
        assert_eq!(
            r.calls(),
            [format!("wineserver -k [WINEPREFIX={}]", r.env.prefix().display())]
        );
    }

    #[test]
    fn stop_times_out_and_reports_spawn_errors() {
        let r = rig_with(WINE_DEFAULT, "exec sleep 30");
        let t = Timeouts {
            stop: Duration::from_secs(1),
            ..Timeouts::default()
        };
        let started = Instant::now();
        let e = r.backend().with_timeouts(t).stop(&r.env).unwrap_err();
        assert!(
            matches!(
                e,
                BackendError::TimedOut {
                    what: "wineserver -k",
                    secs: 1,
                    ..
                }
            ),
            "{e:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(10));
        let mut b = r.backend();
        b.wineserver = r.root.join("missing/wineserver");
        assert!(matches!(b.stop(&r.env), Err(BackendError::Io { .. })));
    }

    #[test]
    fn the_default_deadlines() {
        let t = Timeouts::default();
        assert_eq!(
            (t.prepare.as_secs(), t.stop.as_secs(), t.version.as_secs()),
            (120, 20, 20)
        );
    }

    // ---- command ----

    fn envs(cmd: &Command) -> Vec<(String, String)> {
        let mut v: Vec<_> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.unwrap().to_string_lossy().into_owned(),
                )
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn command_builds_the_exact_wine_invocation() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/hello64.exe");
        let b = r.backend();
        let args = [OsString::from("--flag"), OsString::from("value")];
        let cmd = b
            .command(
                &r.env,
                &exe,
                &dir,
                &args,
                &RunOpts {
                    debug: false,
                    dotnet: false,
                },
            )
            .unwrap();
        assert_eq!(cmd.get_program(), r.bin.join("wine").as_os_str());
        assert_eq!(
            cmd.get_args().collect::<Vec<_>>(),
            [exe.as_os_str(), "--flag".as_ref(), "value".as_ref()]
        );
        assert_eq!(cmd.get_current_dir(), Some(dir.as_path()));
        let mut want = vec![
            (
                "HOME".to_string(),
                r.env.root().join("runtime/home").display().to_string(),
            ),
            ("WINEARCH".to_string(), "win64".to_string()),
            ("WINEDEBUG".to_string(), "-all".to_string()),
            (
                "WINEDLLOVERRIDES".to_string(),
                "winemenubuilder.exe=d;mscoree=d;mshtml=d".to_string(),
            ),
            ("WINEPREFIX".to_string(), r.env.prefix().display().to_string()),
            ("WINESERVER".to_string(), r.bin.join("wineserver").display().to_string()),
        ];
        want.sort();
        assert_eq!(envs(&cmd), want);

        let cmd = b
            .command(
                &r.env,
                &exe,
                &dir,
                &[],
                &RunOpts {
                    debug: true,
                    dotnet: false,
                },
            )
            .unwrap();
        let debug = envs(&cmd).into_iter().find(|(k, _)| k == "WINEDEBUG").unwrap().1;
        assert_eq!(debug, "err+all,fixme-all");
        assert_eq!(cmd.get_args().count(), 1);
    }

    fn overrides(cmd: &Command) -> String {
        envs(cmd).into_iter().find(|(k, _)| k == "WINEDLLOVERRIDES").unwrap().1
    }

    #[test]
    fn dotnet_enables_mscoree_for_the_program_only() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/hello64.exe");
        let b = r.backend();
        let on = b
            .command(
                &r.env,
                &exe,
                &dir,
                &[],
                &RunOpts {
                    debug: false,
                    dotnet: true,
                },
            )
            .unwrap();
        assert_eq!(overrides(&on), "winemenubuilder.exe=d;mshtml=d");
        assert_eq!(WINEDLLOVERRIDES_DOTNET, "winemenubuilder.exe=d;mshtml=d");
        let off = b.command(&r.env, &exe, &dir, &[], &RunOpts::default()).unwrap();
        assert_eq!(overrides(&off), "winemenubuilder.exe=d;mscoree=d;mshtml=d");
        assert_eq!(WINEDLLOVERRIDES, "winemenubuilder.exe=d;mscoree=d;mshtml=d");
        // Only the flag differs, and settle carries it over unchanged.
        let mut a = envs(&on);
        a.retain(|(k, _)| k != "WINEDLLOVERRIDES");
        let mut c = envs(&off);
        c.retain(|(k, _)| k != "WINEDLLOVERRIDES");
        assert_eq!(a, c);
        assert_eq!(overrides(&b.settle(on)), "winemenubuilder.exe=d;mshtml=d");
    }

    /// Every Wine command constructor: `prepare` (helper) and `command` (the program) are the only
    /// `wine_command` users, and only `command` passes anything but a literal `false`. Installers, `settle`,
    /// `stop` and `version` build their commands through them or bypass `wine_command` entirely.
    #[test]
    fn only_command_can_pass_dotnet_to_wine_command() {
        let lib = include_str!("lib.rs");
        let prod = &lib[..lib.find("#[cfg(test)]").unwrap()];
        // Whitespace-normalised, so a rustfmt line split cannot hide a call; every source file of the crate.
        let all = [prod, include_str!("harden.rs"), include_str!("discover.rs")].join("\n");
        let flat = all.split_whitespace().collect::<Vec<_>>().join(" ");
        let calls: Vec<&str> = flat.split("self.wine_command(").skip(1).collect();
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert!(
            calls.iter().any(|l| l.starts_with("env, \"-all\", false)")),
            "{calls:?}"
        );
        assert!(calls.iter().any(|l| l.contains("opts.dotnet);")), "{calls:?}");
    }

    // ---- settle ----

    #[test]
    fn settle_wraps_the_command_in_the_settle_script_with_wineserver_program_and_args_as_argv() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/hello64.exe");
        let b = r.backend();
        let args = [OsString::from("--flag"), OsString::from("value")];
        let cmd = b.command(&r.env, &exe, &dir, &args, &RunOpts::default()).unwrap();
        let cmd_envs = envs(&cmd);
        let cmd_cwd = cmd.get_current_dir().map(Path::to_path_buf);

        let out = b.settle(cmd);

        assert_eq!(out.get_program(), OsStr::new("/bin/sh"));
        let got_args: Vec<_> = out.get_args().collect();
        assert_eq!(
            got_args,
            [
                OsStr::new("-c"),
                OsStr::new(SETTLE_SCRIPT),
                OsStr::new("sh"),
                r.bin.join("wineserver").as_os_str(),
                r.bin.join("wine").as_os_str(),
                OsStr::new(exe.as_os_str()),
                OsStr::new("--flag"),
                OsStr::new("value"),
            ]
        );
        // The env and cwd of the ORIGINAL command are carried over unchanged (same discipline as
        // `InstallerSandbox::wrap`'s own env-replay loop).
        assert_eq!(envs(&out), cmd_envs);
        assert_eq!(out.get_current_dir().map(Path::to_path_buf), cmd_cwd);
    }

    #[test]
    fn settle_preserves_an_explicit_env_removal() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/a.exe");
        let b = r.backend();
        let mut cmd = b.command(&r.env, &exe, &dir, &[], &RunOpts::default()).unwrap();
        cmd.env_remove("WINEARCH");
        let out = b.settle(cmd);
        assert_eq!(
            out.get_envs()
                .find(|(k, _)| *k == OsStr::new("WINEARCH"))
                .map(|(_, v)| v),
            Some(None),
            "an explicit removal must be kept, not just absent"
        );
    }

    /// The script itself, run standalone against a real `sh`: proves it (a) runs the wrapped command with the
    /// right argv, (b) captures ITS exit code even though a second command (the "wineserver -w" stand-in) runs
    /// after it, (c) genuinely waits for that second command before the shell itself exits. This is the one
    /// mechanism the whole C1 fix depends on; the real Wine + bwrap proof is in
    /// `crates/cli/tests/e2e_installers.rs`.
    #[test]
    fn settle_script_runs_for_real_captures_the_real_exit_code_and_waits_for_the_second_command() {
        let tmp = tempfile::tempdir().unwrap();
        let waiter = tmp.path().join("waiter.sh");
        let marker = tmp.path().join("marker");
        // Stands in for `wineserver -w`: blocks until the marker exists, proving it actually ran and was waited
        // for (not just launched and abandoned).
        fs::write(
            &waiter,
            format!(
                "#!/bin/sh\n[ \"$1\" = -w ] || exit 9\nwhile [ ! -f {} ]; do sleep 0.05; done\n",
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&waiter, fs::Permissions::from_mode(0o755)).unwrap();

        let program = tmp.path().join("prog.sh");
        fs::write(
            &program,
            format!(
                "#!/bin/sh\necho \"argv:$*\"\n(sleep 0.2; touch {}) &\nexit 42\n",
                marker.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();

        let start = Instant::now();
        let out = Command::new("/bin/sh")
            .arg("-c")
            .arg(SETTLE_SCRIPT)
            .arg("sh")
            .arg(&waiter)
            .arg(&program)
            .arg("a")
            .arg("b")
            .output()
            .unwrap();
        let elapsed = start.elapsed();

        assert_eq!(out.status.code(), Some(42), "the original command's exit code");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "argv:a b\n");
        assert!(marker.exists(), "the background write must have completed");
        assert!(
            elapsed >= Duration::from_millis(150),
            "the shell must have blocked on the waiter, not returned immediately: {elapsed:?}"
        );
    }

    #[test]
    fn hostile_arguments_stay_single_argv_entries_and_no_shell_is_involved() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/hello64.exe");
        let hostile: Vec<OsString> = [
            "a b",
            "\"quoted\"",
            "'single'",
            "x;y",
            "$(touch PWNED)",
            "`touch PWNED`",
            "line1\nline2",
            "",
            "-k",
            "--",
            "&& touch PWNED",
            "*",
            "~",
            "\\",
        ]
        .iter()
        .map(OsString::from)
        .chain([OsString::from_vec_bytes(b"non-utf8-\xff")])
        .collect();
        let b = r.backend();
        let cmd = b.command(&r.env, &exe, &dir, &hostile, &RunOpts::default()).unwrap();
        let mut expected_args = vec![exe.as_os_str().to_owned()];
        expected_args.extend(hostile.iter().cloned());
        assert_eq!(cmd.get_args().map(OsString::from).collect::<Vec<_>>(), expected_args);
        // Really run it (the fake `wine` prints its argv NUL-separated): every entry arrives intact.
        let launcher = Launcher::with_host_env([("PATH", "/usr/bin:/bin")]);
        let out = launcher.run_helper(cmd, Duration::from_secs(10)).unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.output));
        let raw = fs::read(r.log.join("argv.bin")).unwrap();
        let got: Vec<&[u8]> = raw.split(|b| *b == 0).collect();
        let got = &got[..got.len() - 1]; // the trailing NUL leaves one empty tail
        let want: Vec<&[u8]> = expected_args.iter().map(|a| a.as_bytes()).collect();
        assert_eq!(got, want.as_slice());
        assert!(!dir.join("PWNED").exists());
    }

    trait FromVecBytes {
        fn from_vec_bytes(b: &[u8]) -> OsString;
    }
    impl FromVecBytes for OsString {
        fn from_vec_bytes(b: &[u8]) -> OsString {
            std::os::unix::ffi::OsStringExt::from_vec(b.to_vec())
        }
    }

    #[test]
    fn command_passes_the_resolved_host_path_verbatim() {
        let r = rig();
        // Names Wine would treat specially if it saw them as Windows text stay literal host paths.
        let (exe, dir) = r.exe("Program Files/PROGRA~1/héllo wörld/a.exe");
        let cmd = r
            .backend()
            .command(&r.env, &exe, &dir, &[], &RunOpts::default())
            .unwrap();
        assert_eq!(cmd.get_args().next().unwrap(), exe.as_os_str());
        assert!(exe.to_str().unwrap().contains("PROGRA~1"));
    }

    fn outside_error(res: Result<Command, BackendError>, what: &str) {
        match res {
            Err(BackendError::OutsideDriveC { .. }) => {}
            other => panic!("{what}: expected OutsideDriveC, got {other:?}"),
        }
    }

    #[test]
    fn command_rejects_an_exe_or_cwd_outside_drive_c() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/a.exe");
        let b = r.backend();
        let go = |exe: &Path, cwd: &Path| b.command(&r.env, exe, cwd, &[], &RunOpts::default());
        // A real executable outside, in the prefix but not in drive_c, a sibling whose name starts like drive_c.
        fs::write(r.env.prefix().join("evil.exe"), b"MZ").unwrap();
        let sibling = r.env.prefix().join("drive_c-evil");
        fs::create_dir_all(&sibling).unwrap();
        fs::write(sibling.join("x.exe"), b"MZ").unwrap();
        for bad in [
            Path::new("/bin/sh").to_path_buf(),
            r.env.prefix().join("evil.exe"),
            sibling.join("x.exe"),
            r.outside.join("Desktop/canary.txt"),
            PathBuf::from("/"),
            r.env.drive_c(), // drive_c itself is not an exe
        ] {
            let res = go(&bad, &dir);
            if bad == r.env.drive_c() {
                assert!(res.is_err(), "{bad:?}");
            } else {
                outside_error(res, &format!("exe {bad:?}"));
            }
        }
        for bad in [
            Path::new("/tmp"),
            Path::new("/"),
            sibling.as_path(),
            r.env.prefix().as_path(),
        ] {
            outside_error(go(&exe, bad), &format!("cwd {bad:?}"));
        }
        assert!(go(&exe, &dir).is_ok(), "the happy path still works");
    }

    #[test]
    fn command_rejects_dotdot_even_when_it_stays_inside() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/a.exe");
        fs::write(r.env.prefix().join("evil.exe"), b"MZ").unwrap();
        let b = r.backend();
        let go = |exe: &Path, cwd: &Path| b.command(&r.env, exe, cwd, &[], &RunOpts::default());
        // Lexically these start with drive_c: only the `..` rejection catches them.
        let escaping = r.env.drive_c().join("../evil.exe");
        assert!(escaping.starts_with(r.env.drive_c()));
        outside_error(go(&escaping, &dir), "escaping exe");
        let inside = r.env.drive_c().join("Program Files/../Program Files/t/a.exe");
        outside_error(go(&inside, &dir), "exe with `..` that stays inside");
        let cwd = r.env.drive_c().join("Program Files/t/..");
        outside_error(go(&exe, &cwd), "cwd with ..");
        let cwd = r.env.drive_c().join("../..");
        outside_error(go(&exe, &cwd), "cwd escaping");
    }

    #[test]
    fn command_rejects_relative_paths() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/a.exe");
        let b = r.backend();
        let go = |exe: &Path, cwd: &Path| b.command(&r.env, exe, cwd, &[], &RunOpts::default());
        outside_error(go(Path::new("a.exe"), &dir), "bare name");
        outside_error(
            go(Path::new("drive_c/Program Files/t/a.exe"), &dir),
            "relative drive_c path",
        );
        outside_error(go(&exe, Path::new("t")), "relative cwd");
        outside_error(go(&exe, Path::new("")), "empty cwd");
        outside_error(go(Path::new(""), &dir), "empty exe");
    }

    #[test]
    fn command_rejects_a_directory_a_symlink_and_a_missing_exe() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/a.exe");
        let b = r.backend();
        let go = |exe: &Path, cwd: &Path| b.command(&r.env, exe, cwd, &[], &RunOpts::default());
        // a directory (named like an exe)
        let d = dir.join("dir.exe");
        fs::create_dir(&d).unwrap();
        assert!(matches!(
            go(&d, &dir),
            Err(BackendError::Failed { what: "executable", .. })
        ));
        // a symlink to a regular file INSIDE drive_c, and to one outside
        let l1 = dir.join("link-in.exe");
        symlink(&exe, &l1).unwrap();
        assert!(matches!(
            go(&l1, &dir),
            Err(BackendError::Failed { what: "executable", .. })
        ));
        let l2 = dir.join("link-out.exe");
        symlink(r.outside.join("Desktop/canary.txt"), &l2).unwrap();
        assert!(matches!(
            go(&l2, &dir),
            Err(BackendError::Failed { what: "executable", .. })
        ));
        // dangling and missing
        let l3 = dir.join("dangling.exe");
        symlink(r.root.join("nowhere"), &l3).unwrap();
        assert!(go(&l3, &dir).is_err());
        assert!(go(&dir.join("missing.exe"), &dir).is_err());
    }

    #[test]
    fn command_rejects_a_symlinked_directory_component() {
        let r = rig();
        let (_exe, dir) = r.exe("Program Files/t/a.exe");
        // drive_c/link -> outside directory that holds a regular exe: lexically inside, physically not.
        fs::write(r.outside.join("Desktop/real.exe"), b"MZ").unwrap();
        let link = r.env.drive_c().join("link");
        symlink(r.outside.join("Desktop"), &link).unwrap();
        let b = r.backend();
        let res = b.command(&r.env, &link.join("real.exe"), &dir, &[], &RunOpts::default());
        assert!(
            matches!(res, Err(BackendError::Failed { what: "executable", .. })),
            "{res:?}"
        );
        let (exe, _) = r.exe("Program Files/t/b.exe");
        let res = b.command(&r.env, &exe, &link, &[], &RunOpts::default());
        assert!(
            matches!(
                res,
                Err(BackendError::Failed {
                    what: "working directory",
                    ..
                })
            ),
            "{res:?}"
        );
    }

    #[test]
    fn command_rejects_a_symlinked_drive_c() {
        let r = rig();
        let (_exe, _dir) = r.exe("Program Files/t/a.exe");
        // The whole drive_c moved elsewhere and replaced by a link to it: lexically everything is inside.
        let real = r.root.join("elsewhere");
        fs::rename(r.env.drive_c(), &real).unwrap();
        symlink(&real, r.env.drive_c()).unwrap();
        let exe = r.env.drive_c().join("Program Files/t/a.exe");
        let b = r.backend();
        let res = b.command(&r.env, &exe, &r.env.drive_c(), &[], &RunOpts::default());
        assert!(
            matches!(res, Err(BackendError::Failed { what: "executable", .. })),
            "{res:?}"
        );
        let res = b.command(
            &r.env,
            &real.join("Program Files/t/a.exe"),
            &real,
            &[],
            &RunOpts::default(),
        );
        assert!(matches!(res, Err(BackendError::OutsideDriveC { .. })), "{res:?}");
    }

    #[test]
    fn command_rejects_a_cwd_that_is_not_a_real_directory() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/a.exe");
        let b = r.backend();
        let go = |cwd: &Path| b.command(&r.env, &exe, cwd, &[], &RunOpts::default());
        assert!(matches!(
            go(&exe),
            Err(BackendError::Failed {
                what: "working directory",
                ..
            })
        ));
        let l = dir.join("l");
        symlink(&dir, &l).unwrap();
        assert!(go(&l).is_err());
        assert!(go(&dir.join("missing")).is_err());
        // drive_c itself is a fine cwd.
        assert!(go(&r.env.drive_c()).is_ok());
    }

    // ---- a failing stop is never swallowed (Task 5 review, Important 2) ----

    const STOP_FAILS: &str = "echo 'STOP-OUT: cannot kill the server' >&2; exit 5";

    #[test]
    fn a_failed_wineboot_and_a_failed_stop_are_both_reported() {
        let r = rig_with(
            "case \"$1\" in wineboot) echo 'BOOT-OUT: boom' >&2; exit 3;; esac",
            STOP_FAILS,
        );
        let e = r.backend().prepare(&r.env).unwrap_err();
        let text = e.to_string();
        assert!(matches!(e, BackendError::Failed { what: "wineboot", .. }), "{e:?}");
        for needle in ["BOOT-OUT: boom", "wineserver -k", "STOP-OUT", "may still be running"] {
            assert!(text.contains(needle), "{needle:?} missing from: {text}");
        }
    }

    #[test]
    fn a_wineboot_timeout_and_a_failed_stop_are_both_reported() {
        let r = rig_with(
            "case \"$1\" in wineboot) echo 'BOOT-OUT: slow'; exec sleep 30;; esac",
            STOP_FAILS,
        );
        let t = Timeouts {
            prepare: Duration::from_secs(1),
            ..Timeouts::default()
        };
        let e = r.backend().with_timeouts(t).prepare(&r.env).unwrap_err();
        let text = e.to_string();
        assert!(
            matches!(
                e,
                BackendError::TimedOut {
                    what: "wineboot",
                    secs: 1,
                    ..
                }
            ),
            "{e:?}"
        );
        for needle in ["BOOT-OUT: slow", "wineserver -k", "STOP-OUT", "may still be running"] {
            assert!(text.contains(needle), "{needle:?} missing from: {text}");
        }
    }

    #[test]
    fn a_wineboot_that_cannot_start_and_a_failed_stop_are_both_reported() {
        let r = rig_with(WINE_DEFAULT, STOP_FAILS);
        let mut b = r.backend();
        b.wine = r.root.join("missing/wine");
        let e = b.prepare(&r.env).unwrap_err();
        let text = e.to_string();
        assert!(text.contains("wineboot") && text.contains("STOP-OUT"), "{text}");
        assert!(text.contains("may still be running"), "{text}");
    }

    #[test]
    fn the_merged_failure_text_stays_bounded() {
        let big = "yes 'BOOT-OUT xxxxxxxxxxxxxxxx' | head -c 200000 >&2; exit 3";
        let r = rig_with(
            &format!("case \"$1\" in wineboot) {big};; esac"),
            "yes 'STOP-OUT yyyyyyyyyyyyyyyy' | head -c 200000 >&2; exit 5",
        );
        let e = r.backend().prepare(&r.env).unwrap_err();
        match &e {
            BackendError::Failed { detail, .. } => {
                assert!(detail.as_str().len() <= 4096, "{}", detail.as_str().len());
                let text = detail.as_str();
                assert!(text.contains("BOOT-OUT") && text.contains("STOP-OUT"), "{text}");
                assert!(
                    text.contains("may still be running"),
                    "the warning must survive the cap"
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(e.to_string().len() < 4200);
    }

    #[test]
    fn a_failed_wineboot_with_a_working_stop_is_reported_as_before() {
        let r = rig_with(
            "case \"$1\" in wineboot) echo 'BOOT-OUT: boom' >&2; exit 3;; esac",
            "exit 0",
        );
        let text = r.backend().prepare(&r.env).unwrap_err().to_string();
        assert!(
            text.contains("BOOT-OUT") && !text.contains("may still be running"),
            "{text}"
        );
    }

    // ---- typed hardening failures (Task 5 review, Minor 10) ----

    #[test]
    fn a_hardening_failure_after_wineboot_is_matchable() {
        // wineboot "creates" a tree deeper than the walk examines: harden refuses, and the cause is typed.
        let r = rig_with(
            "case \"$1\" in wineboot) mkdir -p \"$WINEPREFIX/dosdevices\" \"$WINEPREFIX/drive_c/a/b/c/d/e/f/g/h/i/j/k/l/m\"; ln -s ../drive_c \"$WINEPREFIX/dosdevices/c:\";; esac",
            "exit 0",
        );
        let e = r.backend().prepare(&r.env).unwrap_err();
        assert!(
            matches!(
                e,
                BackendError::Io {
                    what: "prefix hardening",
                    ..
                }
            ),
            "{e:?}"
        );
        assert!(
            matches!(harden_cause(&e), Some(harden::HardenError::TooDeep { max: 12 })),
            "{e:?}"
        );
        assert!(e.to_string().contains("directory levels"), "{e}");
        // Other errors carry no hardening cause.
        let other = BackendError::failed("x", b"y");
        assert!(harden_cause(&other).is_none());
        let io = BackendError::Io {
            what: "x",
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        };
        assert!(harden_cause(&io).is_none());
    }

    // ---- API for the services ----

    #[test]
    fn launcher_is_the_one_the_backend_runs_with() {
        let r = rig();
        let b = r.backend();
        let mut cmd = Command::new("/usr/bin/env");
        cmd.env("FROM_BACKEND", "1");
        let out = b.launcher().run_helper(cmd, Duration::from_secs(10)).unwrap();
        let text = String::from_utf8_lossy(&out.output).into_owned();
        assert!(
            text.contains("HOME=/injected-home"),
            "the injected host env of the backend's launcher: {text}"
        );
        assert!(text.contains("FROM_BACKEND=1"));
        assert!(!text.contains("SECRET"), "{text}");
    }

    #[test]
    fn discover_using_reports_a_missing_wine_with_a_hint_and_keeps_the_launcher() {
        let none = |_: &str| None::<OsString>;
        let no_file = |_: &Path| false;
        let no_canon = |_: &Path| None::<PathBuf>;
        let launcher = Launcher::with_host_env([("HOME", "/injected-home"), ("PATH", "/usr/bin:/bin")]);
        let e = WineBackend::discover_using(launcher, &none, &no_file, &no_file, &no_canon).unwrap_err();
        assert!(matches!(e, BackendError::Unavailable(_)), "{e:?}");
        assert!(e.to_string().contains("apt install wine"), "{e}");

        let launcher = Launcher::with_host_env([("HOME", "/injected-home"), ("PATH", "/usr/bin:/bin")]);
        let env = |k: &str| (k == "PATH").then(|| OsString::from("/opt/x/bin"));
        let files = |p: &Path| p == Path::new("/opt/x/bin/wine64") || p == Path::new("/opt/x/bin/wineserver");
        let dirs = |p: &Path| p == Path::new("/opt/x/lib/wine/x86_64-windows");
        let b = WineBackend::discover_using(launcher, &env, &files, &dirs, &no_canon).unwrap();
        assert_eq!(b.wine_path(), Path::new("/opt/x/bin/wine64"));
        assert_eq!(b.dll_dirs(), [PathBuf::from("/opt/x/lib/wine/x86_64-windows")]);
        let out = b
            .launcher()
            .run_helper(Command::new("/usr/bin/env"), Duration::from_secs(10))
            .unwrap();
        assert!(String::from_utf8_lossy(&out.output).contains("HOME=/injected-home"));
    }

    // ---- the path Wine gets is normalised (Task 5 review, Minor 6) ----

    #[test]
    fn wine_gets_the_normalised_path_not_the_callers_spelling() {
        let r = rig();
        let (exe, dir) = r.exe("Program Files/t/a.exe");
        let dc = r.env.drive_c();
        let dc = dc.to_str().unwrap();
        let spelled_exe = PathBuf::from(format!("{dc}/./Program Files//t/./a.exe"));
        let spelled_dir = PathBuf::from(format!("{dc}//Program Files/t/"));
        assert_ne!(spelled_exe.as_os_str(), exe.as_os_str());
        assert_ne!(spelled_dir.as_os_str(), dir.as_os_str());
        let cmd = r
            .backend()
            .command(
                &r.env,
                &spelled_exe,
                &spelled_dir,
                &[OsString::from("x")],
                &RunOpts::default(),
            )
            .unwrap();
        assert_eq!(cmd.get_args().next().unwrap(), exe.as_os_str());
        // `Path` equality ignores `.` and `//`: compare the raw bytes.
        assert_eq!(cmd.get_current_dir().map(Path::as_os_str), Some(dir.as_os_str()));
        // ... and it really runs that path.
        let launcher = Launcher::with_host_env([("PATH", "/usr/bin:/bin")]);
        assert!(
            launcher
                .run_helper(cmd, Duration::from_secs(10))
                .unwrap()
                .status
                .success()
        );
        let raw = fs::read(r.log.join("argv.bin")).unwrap();
        assert_eq!(raw.split(|b| *b == 0).next().unwrap(), exe.as_os_str().as_bytes());
    }

    // ---- small things ----

    #[test]
    fn id_and_dll_dirs() {
        let r = rig();
        let b = r.backend();
        assert_eq!(b.id(), "wine");
        assert!(b.dll_dirs().is_empty());
        let found = discover::Found {
            wine: "/w".into(),
            wineserver: "/ws".into(),
            dll_dirs: vec!["/d1".into(), "/d2".into()],
        };
        let b = WineBackend::from_found(found, Launcher::with_host_env(Vec::<(&str, &str)>::new()));
        assert_eq!(b.dll_dirs(), [PathBuf::from("/d1"), PathBuf::from("/d2")]);
        assert_eq!(
            (b.wine_path(), b.wineserver_path()),
            (Path::new("/w"), Path::new("/ws"))
        );
    }

    #[test]
    fn the_backend_is_send_sync_and_clone() {
        fn is<T: Send + Sync + Clone>() {}
        is::<WineBackend>();
        let _: &dyn CompatBackend = &rig().backend();
    }
}
