//! The [`Launcher`]: the ONE place a backend's [`Command`] is finalised and started.
//!
//! ```text
//! backend.command(..) --> Launcher::finalize --> Launcher::spawn --> Running::wait
//!   (WINEPREFIX=... set     env_clear + allowlist     log file, stderr routing,
//!    through .env())        + backend vars again      tee thread
//!                           + sandbox hook (`wrap`)
//! ```
//!
//! **Sandbox hook.** [`Launcher::wrap`] is identity unless a [`Sandbox`] was attached with
//! [`Launcher::with_sandbox`], in which case it delegates to it. `rt_installer`'s `InstallerSandbox` is the
//! first (Phase 3 Task 5, installer helpers only); a later phase may attach one to every app run.
//!
//! **Environment.** `Command::env_clear()` also forgets variables set earlier with `.env()`, so `finalize`
//! first snapshots what the backend set, clears, applies the allowlisted host variables and only then re-applies
//! the snapshot: backend variables always win over a host variable of the same name (a host `WINEPREFIX` can
//! never redirect a prefix, and the Wine backend's `HOME` replaces the host's) and everything not allowlisted (`LD_PRELOAD`, secrets, ...) is gone.
//!
//! **X11 cookie.** The Wine backend replaces `HOME`, which hides `~/.Xauthority`; when `DISPLAY` is kept and
//! `XAUTHORITY` is not, [`Launcher::with_host_env`] adds the host's `<HOME>/.Xauthority` (path only) if it is a
//! regular file, so X authentication keeps working. A host `XAUTHORITY` is never overridden.
//!
//! **Helper processes.** `run_helper` finalises a helper command (`wineboot`, `wineserver -k`, ...) the same way and
//! runs it under a deadline with capped output; it is the only supported way for a backend to run one.
//!
//! **Streams.** stdout AND stdin are inherited by `spawn` (interactive console programs need both), so the program
//! can write terminal escape sequences to the terminal and read what the user types; `run_helper` closes stdin.
//! stdout is inherited raw. stderr goes to a fresh `logs/run-<secs>-<nanos>-<pid>.log`; with
//! [`LogSink::Tee`] it is copied to that file and to a terminal writer by a thread that [`Running::wait`] joins.
//!
//! **Log files** are created with `O_CREAT|O_EXCL` (never through a symlink) and mode 0600 after `symlink_metadata`
//! has shown that `logs/` is a real directory; at most [`MAX_LOGS`] `run-*.log` regular files are kept per app.
//! Residual race (documented, not closable without `openat2`): a process of the same uid that can write to the
//! app directory can swap `logs/` for a symlink between the check and the create; `O_EXCL` still guarantees the
//! *file* is new, and Phase 5's sandbox is the real boundary.
use crate::proc::{Drain, capture_pair, run_with_timeout, stdio};
use crate::{AppEnv, HelperOutput, RunError, allowed_env};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// At most this many `run-*.log` files are kept per app.
pub const MAX_LOGS: usize = 20;
/// Pruning looks at no more than this many directory entries (bounded work).
const MAX_SCAN: usize = 10_000;
/// Name collisions (same nanosecond, same pid) are retried with `-1`..`-N` up to this many times.
const NAME_RETRIES: u32 = 8;

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("the app's logs directory is missing, a symbolic link or not a directory")]
    LogsDir,
    #[error("cannot create the log file: {0}")]
    Log(#[source] io::Error),
    #[error("cannot start the process: {0}")]
    Spawn(#[source] io::Error),
}

/// Where the child's stderr goes. It always goes to the log file; `Tee` also copies it to a terminal writer.
pub enum LogSink {
    LogOnly,
    Tee(Box<dyn Write + Send>),
}

impl LogSink {
    /// Tee to this process's stderr.
    pub fn tee_stderr() -> LogSink {
        LogSink::Tee(Box::new(io::stderr()))
    }
}

/// A sandbox hook attachable to a [`Launcher`] (see [`Launcher::with_sandbox`]). Called by [`Launcher::wrap`] on
/// the fully-finalized command (final argv, env and cwd already set): a real implementation rebuilds the
/// program and args (e.g. `bwrap <profile> -- <program> <args>`) and carries the env/cwd over unchanged.
pub trait Sandbox: Send + Sync {
    fn wrap(&self, cmd: Command) -> Command;
}

/// See the module docs. Cheap to clone (the filtered host environment and the sandbox are shared), so a backend
/// can own one.
#[derive(Clone)]
pub struct Launcher {
    /// The host variables a child may inherit (already filtered by [`allowed_env`]).
    host: Arc<Vec<(OsString, OsString)>>,
    /// See [`Sandbox`]. `None` (the default): [`Launcher::wrap`] is identity.
    sandbox: Option<Arc<dyn Sandbox>>,
}

impl Default for Launcher {
    fn default() -> Self {
        Launcher::new()
    }
}

impl Launcher {
    /// A launcher over this process's real environment (read once, now).
    pub fn new() -> Launcher {
        Launcher::with_host_env(std::env::vars_os())
    }

    /// A launcher over an explicit host environment (tests; no process-environment mutation needed).
    pub fn with_host_env<I, K, V>(host: I) -> Launcher
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let mut kept = allowed_env(host); // a later duplicate wins in `finalize`, so pushing shadows an empty XAUTHORITY
        let value = |name: &str| kept.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v.clone());
        let xauth = default_xauthority(
            &value("HOME").unwrap_or_default(),
            value("DISPLAY").is_some(),
            value("XAUTHORITY").is_some_and(|v| !v.is_empty()),
            is_regular_file_nofollow,
        );
        if let Some(path) = xauth {
            kept.push((OsString::from("XAUTHORITY"), path.into_os_string()));
        }
        Launcher {
            host: Arc::new(kept),
            sandbox: None,
        }
    }

    /// Attaches a sandbox hook (see [`Sandbox`]); a builder call, so a backend can do
    /// `Launcher::new().with_sandbox(...)`. Replaces any sandbox attached earlier.
    pub fn with_sandbox(mut self, sandbox: Arc<dyn Sandbox>) -> Launcher {
        self.sandbox = Some(sandbox);
        self
    }

    /// The sandbox hook: identity unless a [`Sandbox`] is attached ([`Launcher::with_sandbox`]); it runs last, on
    /// the finished command, so a sandbox sees the final environment.
    pub fn wrap(&self, cmd: Command) -> Command {
        match &self.sandbox {
            Some(sandbox) => sandbox.wrap(cmd),
            None => cmd,
        }
    }

    /// Applies the environment rules (module docs) and the sandbox hook. `spawn` and `run_helper` use it.
    pub fn finalize(&self, mut cmd: Command) -> Command {
        // 1. Snapshot what the backend set: `env_clear` would discard it. `None` = an explicit removal.
        let explicit: Vec<(OsString, Option<OsString>)> = cmd
            .get_envs()
            .map(|(k, v)| (k.to_owned(), v.map(OsStr::to_owned)))
            .collect();
        // 2. Drop everything inherited from this process, 3. add the allowlisted host variables,
        cmd.env_clear();
        for (k, v) in self.host.iter() {
            cmd.env(k, v);
        }
        // 4. and re-apply the backend's own last, so they win.
        for (k, v) in explicit {
            match v {
                Some(v) => cmd.env(k, v),
                None => cmd.env_remove(k),
            };
        }
        self.wrap(cmd)
    }

    /// Finalises `cmd`, creates the log file and starts the child. The returned [`Running`] must be waited for.
    pub fn spawn(&self, cmd: Command, env: &AppEnv, sink: LogSink) -> Result<Running, LaunchError> {
        let cmd = self.finalize(cmd);
        let (log, log_path) = create_log_with(&env.logs_dir(), log_names())?;
        let running = start_child(cmd, log, log_path, sink)?;
        // Best effort: a failed prune must not fail the launch.
        if let Some(name) = running.log_path.file_name() {
            let _ = prune_logs(&env.logs_dir(), MAX_LOGS, name, MAX_SCAN);
        }
        Ok(running)
    }

    /// Runs a helper process (`wineboot`, `wineserver -k`, `wine --version`, ...) to completion: finalises `cmd`
    /// like [`spawn`](Self::spawn) (cleared environment + allowlist + the command's own variables), closes its
    /// stdin, waits at most `timeout` and returns its status and combined stdout+stderr (at most 64 KiB). On
    /// timeout the child is killed and reaped and the error carries the partial output. This is the ONLY way a
    /// backend should run a helper: a plain `Command::output()` would pass the full host environment.
    pub fn run_helper(&self, cmd: Command, timeout: Duration) -> Result<HelperOutput, RunError> {
        let (status, output) = run_with_timeout(self.finalize(cmd), timeout)?;
        Ok(HelperOutput { status, output })
    }
}

/// The X11 cookie file to pass when the host did not name one. The Wine backend redirects `HOME`, which hides
/// `~/.Xauthority` from clients that fall back to it (`startx`, `ssh -X`, `xdm`; GDM/SDDM/KDE export
/// `XAUTHORITY`). Returns `<home>/.Xauthority` only if `DISPLAY` is set, `XAUTHORITY` is unset or empty, `home` is
/// absolute and `is_regular_file` says it is a regular file (the caller's probe must not follow symlinks). Only
/// the PATH is handed over, never the contents.
fn default_xauthority(
    home: &OsStr,
    has_display: bool,
    has_xauthority: bool,
    is_regular_file: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let home = Path::new(home);
    if !has_display || has_xauthority || !home.is_absolute() {
        return None;
    }
    let path = home.join(".Xauthority");
    is_regular_file(&path).then_some(path)
}

/// `symlink_metadata`: a symlink (even to a regular file) or a directory is refused.
fn is_regular_file_nofollow(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// Routes the child's stderr per `sink` (stdout is inherited) and starts it. On failure the log is removed.
fn start_child(mut cmd: Command, log: File, log_path: PathBuf, sink: LogSink) -> Result<Running, LaunchError> {
    cmd.stdout(Stdio::inherit());
    let mut tee = None;
    match sink {
        LogSink::LogOnly => {
            cmd.stderr(Stdio::from(log));
        }
        LogSink::Tee(terminal) => {
            let started = capture_pair().and_then(|(rd, wr)| {
                cmd.stderr(stdio(wr));
                tee_to(rd, log, terminal)
            });
            match started {
                Ok(t) => tee = Some(t),
                Err(e) => return Err(discard(&log_path, LaunchError::Log(e))),
            }
        }
    }
    let spawned = cmd.spawn();
    // `cmd` holds the write end of the tee socket (and the log): release them so EOF can arrive.
    drop(cmd);
    match spawned {
        Ok(child) => Ok(Running { child, tee, log_path }),
        Err(e) => Err(discard(&log_path, LaunchError::Spawn(e))),
    }
}

/// A started child plus its log. Dropping it without `wait` neither kills nor waits for the child.
#[must_use = "a Running child must be waited for (or killed and waited for)"]
pub struct Running {
    child: Child,
    tee: Option<Drain<TeeReport>>,
    log_path: PathBuf,
}

/// What the tee thread saw go wrong. A sink that fails is dropped (the other keeps working, the child is never
/// blocked or failed by logging).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct TeeReport {
    log_write_failed: bool,
    terminal_write_failed: bool,
}

/// The outcome of [`Running::wait_report`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finished {
    pub status: ExitStatus,
    /// The log file stopped accepting writes (disk full, ...), so the log is incomplete. Only observable with
    /// [`LogSink::Tee`]; with `LogOnly` the child writes the file itself and this is always `false`.
    pub log_write_failed: bool,
    /// The terminal writer of [`LogSink::Tee`] failed (closed terminal, ...); always `false` otherwise.
    pub terminal_write_failed: bool,
}

impl std::fmt::Debug for Running {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Running")
            .field("pid", &self.child.id())
            .field("log_path", &self.log_path)
            .finish()
    }
}

impl Running {
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Kills the child (SIGKILL; only the direct child, not what it started). Still call `wait` afterwards to
    /// reap it and join the tee thread. Task 7's Ctrl-C forwarding uses this.
    pub fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }

    /// `Some(status)` once the child has exited, without blocking. `wait`/`wait_report` still work afterwards.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Waits for the child, then joins the tee thread (which has drained the child's stderr by then). Use
    /// [`wait_report`](Self::wait_report) to learn whether the log or the terminal lost writes.
    pub fn wait(self) -> io::Result<ExitStatus> {
        self.wait_report().map(|f| f.status)
    }

    /// Like [`wait`](Self::wait), also reporting sink write failures.
    pub fn wait_report(mut self) -> io::Result<Finished> {
        let status = self.child.wait();
        let report = self.tee.take().map(Drain::finish).unwrap_or_default();
        status.map(|status| Finished {
            status,
            log_write_failed: report.log_write_failed,
            terminal_write_failed: report.terminal_write_failed,
        })
    }
}

/// `run-<secs>-<nanos, 9 digits>-<pid>` then the retry suffixes: names sort oldest-first by plain string order.
fn log_names() -> impl Iterator<Item = String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let base = format!("run-{}-{:09}-{}", now.as_secs(), now.subsec_nanos(), std::process::id());
    std::iter::once(format!("{base}.log")).chain((1..=NAME_RETRIES).map(move |n| format!("{base}-{n}.log")))
}

/// Requires a real directory (a symlink, even to a directory, is refused).
fn require_real_dir(dir: &Path) -> Result<(), LaunchError> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_dir() => Ok(()),
        Ok(_) => Err(LaunchError::LogsDir),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(LaunchError::LogsDir),
        Err(e) => Err(LaunchError::Log(e)),
    }
}

/// Removes the log of a launch that never started; returns `err` for `?`-style use.
fn discard(log_path: &Path, err: LaunchError) -> LaunchError {
    let _ = fs::remove_file(log_path);
    err
}

/// Creates the first name in `names` that is free, in `dir`, mode 0600, `O_EXCL`.
fn create_log_with(dir: &Path, names: impl Iterator<Item = String>) -> Result<(File, PathBuf), LaunchError> {
    require_real_dir(dir)?;
    for name in names {
        let path = dir.join(name);
        // `create_new` = O_CREAT|O_EXCL: fails on ANY existing entry, a symlink (even dangling) included, and
        // never follows one at the final component.
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(f) => return Ok((f, path)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(LaunchError::Log(e)),
        }
    }
    Err(LaunchError::Log(io::Error::from(io::ErrorKind::AlreadyExists)))
}

/// Copies `rd` (the child's stderr) to `log` and `terminal` in `CHUNK`-sized pieces. A failing sink is dropped
/// and recorded in the [`TeeReport`]; the other keeps working and the child is never blocked.
fn tee_to(
    rd: UnixStream,
    mut log: impl Write + Send + 'static,
    mut terminal: Box<dyn Write + Send>,
) -> io::Result<Drain<TeeReport>> {
    Drain::start(rd, TeeReport::default(), move |report: &mut TeeReport, chunk| {
        if !report.log_write_failed && log.write_all(chunk).is_err() {
            report.log_write_failed = true;
        }
        if !report.terminal_write_failed && terminal.write_all(chunk).and_then(|()| terminal.flush()).is_err() {
            report.terminal_write_failed = true;
        }
    })
}

fn is_log_name(name: &OsStr) -> bool {
    let n = name.as_encoded_bytes();
    n.starts_with(b"run-") && n.ends_with(b".log")
}

/// Deletes the oldest `run-*.log` regular files in `dir` so at most `keep` remain, counting `current` (never
/// deleted). Symlinks, directories and other names are neither counted nor touched (`DirEntry::file_type` does not
/// follow links, and `remove_file` on a link removes the link only). At most `max_scan` directory entries are
/// examined. Returns the number deleted.
fn prune_logs(dir: &Path, keep: usize, current: &OsStr, max_scan: usize) -> io::Result<usize> {
    require_real_dir(dir).map_err(|e| match e {
        LaunchError::Log(e) => e,
        _ => io::Error::new(io::ErrorKind::InvalidInput, "logs directory is not a real directory"),
    })?;
    // `(name, is_regular_file)`; an entry whose type cannot be read is an `Err`, skipped by `prune_entries`.
    let entries = fs::read_dir(dir)?.map(|entry| {
        let entry = entry?;
        let file_type = entry.file_type()?;
        Ok((entry.file_name(), file_type.is_file()))
    });
    Ok(prune_entries(dir, keep, current, entries, max_scan))
}

/// The selection and deletion part of [`prune_logs`] over already-listed entries. A bad entry (`Err`) is skipped,
/// never aborts the prune; it still counts against `max_scan`.
fn prune_entries(
    dir: &Path,
    keep: usize,
    current: &OsStr,
    entries: impl Iterator<Item = io::Result<(OsString, bool)>>,
    max_scan: usize,
) -> usize {
    let mut old: Vec<OsString> = Vec::new();
    for entry in entries.take(max_scan) {
        let Ok((name, is_regular_file)) = entry else { continue };
        if name != current && is_log_name(&name) && is_regular_file {
            old.push(name);
        }
    }
    // Names are `run-<secs>-<nanos>-...`: string order is age order.
    old.sort();
    let excess = old.len().saturating_sub(keep.saturating_sub(1));
    let mut deleted = 0;
    for name in old.into_iter().take(excess) {
        if fs::remove_file(dir.join(name)).is_ok() {
            deleted += 1;
        }
    }
    deleted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AppId, CompatBackend, FakeBackend, RunOpts, Store};
    use std::collections::BTreeMap;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    struct Fx {
        _tmp: tempfile::TempDir,
        env: AppEnv,
        outside: PathBuf,
    }

    /// App `t` with logs/, plus `outside/canary.txt`.
    fn fx() -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().join("apps")).unwrap();
        let env = store.create(&AppId::parse("t").unwrap()).unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("canary.txt"), "canary").unwrap();
        Fx {
            _tmp: tmp,
            env,
            outside,
        }
    }

    fn poisoned() -> Launcher {
        Launcher::with_host_env([
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/home/u"),
            ("LC_ALL", "C"),
            ("LANG", "fr_FR.UTF-8"),
            ("SECRET", "x"),
            ("LD_PRELOAD", "/nonexistent.so"),
            ("WINEPREFIX", "/host/prefix"),
            ("AWS_SECRET_ACCESS_KEY", "k"),
            ("SSH_AUTH_SOCK", "/s"),
        ])
    }

    fn fake_cmd(fx: &Fx, script: &str, debug: bool) -> Command {
        let b = FakeBackend::with_script(script);
        b.prepare(&fx.env).unwrap();
        b.command(
            &fx.env,
            Path::new("/app.exe"),
            &fx.env.drive_c(),
            &[],
            &RunOpts { debug },
        )
        .unwrap()
    }

    /// stderr of `env` as lines.
    fn child_env(fx: &Fx, l: &Launcher) -> Vec<String> {
        let r = l
            .spawn(fake_cmd(fx, "/usr/bin/env >&2", false), &fx.env, LogSink::LogOnly)
            .unwrap();
        let path = r.log_path().to_path_buf();
        assert!(r.wait().unwrap().success());
        fs::read_to_string(path).unwrap().lines().map(str::to_owned).collect()
    }

    fn has_var(lines: &[String], name: &str) -> bool {
        lines.iter().any(|l| l.starts_with(&format!("{name}=")))
    }

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<(Vec<u8>, Vec<usize>)>>);

    impl SharedBuf {
        fn bytes(&self) -> Vec<u8> {
            self.0.lock().unwrap().0.clone()
        }
        fn max_write(&self) -> usize {
            self.0.lock().unwrap().1.iter().copied().max().unwrap_or(0)
        }
    }

    impl Write for SharedBuf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            let mut g = self.0.lock().unwrap();
            g.1.push(b.len());
            g.0.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BrokenTerminal;
    impl Write for BrokenTerminal {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    /// The explicit environment of a command as `name -> Some(value) | None (removed)`.
    fn envs(c: &Command) -> BTreeMap<String, Option<String>> {
        c.get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    fn some(v: &str) -> Option<String> {
        Some(v.to_owned())
    }

    fn regular_logs(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.file_type().unwrap().is_file() && is_log_name(&e.file_name()))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    fn old_name(i: u32) -> String {
        format!("run-{i:010}-000000000-1.log")
    }

    // ------------------------------------------------------------------------------ finalize (env rules)

    #[test]
    fn finalize_reapplies_the_backend_vars_that_env_clear_discards() {
        let l = Launcher::with_host_env([("PATH", "/usr/bin")]);
        let mut c = Command::new("/bin/true");
        c.env("WINEPREFIX", "/apps/t/prefix").env("WINEARCH", "win64");
        let e = envs(&l.finalize(c));
        assert_eq!(e["WINEPREFIX"], some("/apps/t/prefix"));
        assert_eq!(e["WINEARCH"], some("win64"));
        assert_eq!(e["PATH"], some("/usr/bin"));
    }

    #[test]
    fn finalize_never_lets_a_host_wineprefix_or_ld_preload_through() {
        let l = poisoned();
        // Backend set a prefix: it wins.
        let mut c = Command::new("/bin/true");
        c.env("WINEPREFIX", "/apps/t/prefix");
        let e = envs(&l.finalize(c));
        assert_eq!(e["WINEPREFIX"], some("/apps/t/prefix"));
        assert!(!e.contains_key("LD_PRELOAD"));
        // Backend set none: the host's must not appear either.
        let e = envs(&l.finalize(Command::new("/bin/true")));
        assert!(!e.contains_key("WINEPREFIX"), "{e:?}");
        for bad in ["SECRET", "LD_PRELOAD", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK"] {
            assert!(!e.contains_key(bad), "{bad} leaked: {e:?}");
        }
    }

    #[test]
    fn finalize_gives_the_host_exactly_the_allowlist() {
        let e = envs(&poisoned().finalize(Command::new("/bin/true")));
        let names: Vec<&str> = e.keys().map(String::as_str).collect();
        assert_eq!(names, ["HOME", "LANG", "LC_ALL", "PATH"]);
    }

    #[test]
    fn a_backend_var_wins_over_an_allowlisted_host_var_of_the_same_name() {
        let l = poisoned(); // host LANG=fr_FR.UTF-8
        let mut c = Command::new("/bin/true");
        c.env("LANG", "C");
        assert_eq!(envs(&l.finalize(c))["LANG"], some("C"));
    }

    #[test]
    fn a_backend_env_remove_is_kept() {
        let l = poisoned();
        let mut c = Command::new("/bin/true");
        c.env_remove("LANG");
        // After env_clear std drops the entry, so the child has no LANG at all (the host's was removed again).
        assert!(!envs(&l.finalize(c)).contains_key("LANG"));
    }

    #[test]
    fn wrap_is_the_identity_and_finalize_keeps_program_args_and_cwd() {
        let l = Launcher::with_host_env(Vec::<(&str, &str)>::new());
        let mut c = Command::new("/bin/echo");
        c.arg("a b").arg("$(x)").current_dir("/tmp").env("K", "v");
        let w = l.wrap(c);
        assert_eq!(w.get_program(), "/bin/echo");
        assert_eq!(w.get_args().collect::<Vec<_>>(), ["a b", "$(x)"]);
        assert_eq!(w.get_current_dir(), Some(Path::new("/tmp")));
        assert_eq!(envs(&w)["K"], some("v"));
        let mut c = Command::new("/bin/echo");
        c.arg("x").current_dir("/tmp");
        let f = l.finalize(c);
        assert_eq!(f.get_program(), "/bin/echo");
        assert_eq!(f.get_args().collect::<Vec<_>>(), ["x"]);
        assert_eq!(f.get_current_dir(), Some(Path::new("/tmp")));
    }

    struct PrefixSandbox;
    impl Sandbox for PrefixSandbox {
        fn wrap(&self, cmd: Command) -> Command {
            let mut wrapped = Command::new("/usr/bin/env");
            wrapped.arg("--").arg(cmd.get_program()).args(cmd.get_args());
            for (k, v) in cmd.get_envs() {
                match v {
                    Some(v) => {
                        wrapped.env(k, v);
                    }
                    None => {
                        wrapped.env_remove(k);
                    }
                }
            }
            wrapped
        }
    }

    #[test]
    fn wrap_delegates_to_an_attached_sandbox_and_is_identity_without_one() {
        let mut c = Command::new("/bin/echo");
        c.arg("hi").env("K", "v");
        let plain = Launcher::with_host_env(Vec::<(&str, &str)>::new()).wrap(c);
        assert_eq!(plain.get_program(), "/bin/echo");

        let mut c = Command::new("/bin/echo");
        c.arg("hi").env("K", "v");
        let sandboxed = Launcher::with_host_env(Vec::<(&str, &str)>::new())
            .with_sandbox(Arc::new(PrefixSandbox))
            .wrap(c);
        assert_eq!(sandboxed.get_program(), "/usr/bin/env");
        assert_eq!(sandboxed.get_args().collect::<Vec<_>>(), ["--", "/bin/echo", "hi"]);
        assert_eq!(envs(&sandboxed)["K"], some("v"));
    }

    #[test]
    fn finalize_applies_the_sandbox_after_the_env_rules() {
        // The sandbox sees the FINAL env (host allowlist + backend vars), not the raw backend command.
        let l = Launcher::with_host_env([("PATH", "/usr/bin")]).with_sandbox(Arc::new(PrefixSandbox));
        let mut c = Command::new("/bin/true");
        c.env("WINEPREFIX", "/apps/t/prefix");
        let out = l.finalize(c);
        assert_eq!(out.get_program(), "/usr/bin/env");
        assert_eq!(out.get_args().collect::<Vec<_>>(), ["--", "/bin/true"]);
        assert_eq!(envs(&out)["WINEPREFIX"], some("/apps/t/prefix"));
        assert_eq!(envs(&out)["PATH"], some("/usr/bin"));
    }

    // ------------------------------------------------------------------------------ real spawns

    #[test]
    fn the_child_of_a_real_spawn_sees_only_allowlist_plus_backend_vars() {
        let fx = fx();
        let lines = child_env(&fx, &poisoned());
        assert!(lines.contains(&"PATH=/usr/bin:/bin".to_string()), "{lines:?}");
        assert!(lines.contains(&"HOME=/home/u".to_string()));
        assert!(lines.contains(&"LC_ALL=C".to_string()));
        // The backend's own variable, not the host's `WINEPREFIX=/host/prefix`.
        let wp: Vec<_> = lines.iter().filter(|l| l.starts_with("WINEPREFIX=")).collect();
        assert_eq!(wp, [&format!("WINEPREFIX={}", fx.env.prefix().display())]);
        for bad in ["SECRET", "LD_PRELOAD", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK"] {
            assert!(!has_var(&lines, bad), "{bad} reached the child: {lines:?}");
        }
    }

    #[test]
    fn the_real_process_environment_is_stripped_too() {
        // `cargo test` sets CARGO_MANIFEST_DIR in this process; env_clear() must keep it from the child.
        assert!(
            std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
            "run under `cargo test`"
        );
        let fx = fx();
        let lines = child_env(&fx, &Launcher::new());
        assert!(!has_var(&lines, "CARGO_MANIFEST_DIR"), "{lines:?}");
        assert!(!has_var(&lines, "CARGO"), "{lines:?}");
        assert!(has_var(&lines, "WINEPREFIX"));
        if std::env::var_os("PATH").is_some() {
            assert!(has_var(&lines, "PATH"), "{lines:?}");
        }
    }

    #[test]
    fn stderr_goes_to_a_0600_log_and_stdout_is_not_captured() {
        let fx = fx();
        let r = poisoned()
            .spawn(
                fake_cmd(&fx, "echo to-stdout; echo to-stderr >&2", false),
                &fx.env,
                LogSink::LogOnly,
            )
            .unwrap();
        let path = r.log_path().to_path_buf();
        assert_eq!(path.parent().unwrap(), fx.env.logs_dir());
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        assert!(name.starts_with("run-") && name.ends_with(".log"), "{name}");
        assert!(r.wait().unwrap().success());
        assert_eq!(fs::read_to_string(&path).unwrap(), "to-stderr\n");
        let m = fs::symlink_metadata(&path).unwrap();
        assert!(m.file_type().is_file());
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn stdout_is_inherited_from_the_parent() {
        let fx = fx();
        let r = poisoned()
            .spawn(
                fake_cmd(&fx, r#"p=$(readlink /proc/$$/fd/1); echo "$p" >&2"#, false),
                &fx.env,
                LogSink::LogOnly,
            )
            .unwrap();
        let path = r.log_path().to_path_buf();
        assert!(r.wait().unwrap().success());
        // Same open file as this process's stdout (`pipe:[N]`, a file, ...), not /dev/null and not the log.
        let mine = fs::read_link("/proc/self/fd/1").unwrap();
        assert_eq!(fs::read_to_string(path).unwrap().trim_end(), mine.to_str().unwrap());
    }

    #[test]
    fn the_exit_status_is_passed_through() {
        let fx = fx();
        for code in [0, 7, 255] {
            let r = poisoned()
                .spawn(fake_cmd(&fx, &format!("exit {code}"), false), &fx.env, LogSink::LogOnly)
                .unwrap();
            assert_eq!(r.wait().unwrap().code(), Some(code));
        }
    }

    #[test]
    fn debug_tee_writes_to_the_log_and_the_terminal() {
        let fx = fx();
        let term = SharedBuf::default();
        let r = poisoned()
            .spawn(
                fake_cmd(&fx, "echo out; echo err1 >&2; echo err2 >&2", true),
                &fx.env,
                LogSink::Tee(Box::new(term.clone())),
            )
            .unwrap();
        let path = r.log_path().to_path_buf();
        assert!(r.wait().unwrap().success());
        assert_eq!(fs::read_to_string(&path).unwrap(), "err1\nerr2\n");
        assert_eq!(term.bytes(), b"err1\nerr2\n");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn a_large_tee_stream_neither_deadlocks_nor_loses_data_and_is_copied_in_small_chunks() {
        let fx = fx();
        let term = SharedBuf::default();
        let total = 1024 * 1024; // 16x a pipe buffer
        let r = poisoned()
            .spawn(
                fake_cmd(&fx, &format!("head -c {total} /dev/zero >&2"), true),
                &fx.env,
                LogSink::Tee(Box::new(term.clone())),
            )
            .unwrap();
        let path = r.log_path().to_path_buf();
        assert!(r.wait().unwrap().success());
        assert_eq!(fs::metadata(&path).unwrap().len(), total as u64);
        assert_eq!(term.bytes().len(), total);
        assert!(term.max_write() <= 8 * 1024, "chunk of {} bytes", term.max_write());
    }

    #[test]
    fn a_broken_terminal_does_not_stop_the_log() {
        let fx = fx();
        let r = poisoned()
            .spawn(
                fake_cmd(&fx, "head -c 300000 /dev/zero >&2; exit 4", true),
                &fx.env,
                LogSink::Tee(Box::new(BrokenTerminal)),
            )
            .unwrap();
        let path = r.log_path().to_path_buf();
        assert_eq!(r.wait().unwrap().code(), Some(4));
        assert_eq!(fs::metadata(&path).unwrap().len(), 300_000);
    }

    #[test]
    fn wait_returns_although_a_daemon_keeps_stderr_open() {
        // Like wineserver after wineboot: the direct child is gone, a grandchild still holds stderr.
        let fx = fx();
        let term = SharedBuf::default();
        let r = poisoned()
            .spawn(
                fake_cmd(&fx, "sleep 3 & echo hi >&2", true),
                &fx.env,
                LogSink::Tee(Box::new(term.clone())),
            )
            .unwrap();
        let path = r.log_path().to_path_buf();
        let t0 = Instant::now();
        assert!(r.wait().unwrap().success());
        assert!(t0.elapsed() < Duration::from_secs(2), "took {:?}", t0.elapsed());
        assert_eq!(fs::read_to_string(&path).unwrap(), "hi\n");
        assert_eq!(term.bytes(), b"hi\n");
    }

    #[test]
    fn a_spawn_failure_is_typed_and_leaves_no_log_behind() {
        let fx = fx();
        let err = poisoned()
            .spawn(Command::new("/nonexistent/prog"), &fx.env, LogSink::LogOnly)
            .unwrap_err();
        assert!(matches!(err, LaunchError::Spawn(_)), "{err:?}");
        assert_eq!(fs::read_dir(fx.env.logs_dir()).unwrap().count(), 0);
    }

    // ------------------------------------------------------------------------------ logs dir and log file

    #[test]
    fn a_symlinked_logs_dir_is_refused_before_anything_runs() {
        let fx = fx();
        fs::remove_dir(fx.env.logs_dir()).unwrap();
        symlink(&fx.outside, fx.env.logs_dir()).unwrap();
        let ran = fx.outside.join("ran");
        let script = format!("echo x > '{}'", ran.display());
        let err = poisoned()
            .spawn(fake_cmd(&fx, &script, false), &fx.env, LogSink::LogOnly)
            .unwrap_err();
        assert!(matches!(err, LaunchError::LogsDir), "{err:?}");
        assert!(!ran.exists(), "the command ran");
        let mut left: Vec<_> = fs::read_dir(&fx.outside)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(left, ["canary.txt"], "a log was created through the symlink");
    }

    #[test]
    fn a_logs_dir_that_is_a_file_or_missing_is_refused() {
        let fx = fx();
        fs::remove_dir(fx.env.logs_dir()).unwrap();
        let cmd = |fx: &Fx| fake_cmd(fx, "exit 0", false);
        assert!(matches!(
            poisoned().spawn(cmd(&fx), &fx.env, LogSink::LogOnly),
            Err(LaunchError::LogsDir)
        ));
        fs::write(fx.env.logs_dir(), "x").unwrap();
        assert!(matches!(
            poisoned().spawn(cmd(&fx), &fx.env, LogSink::LogOnly),
            Err(LaunchError::LogsDir)
        ));
    }

    #[test]
    fn a_log_is_created_with_create_new_and_never_through_a_symlink() {
        let fx = fx();
        let logs = fx.env.logs_dir();
        symlink(fx.outside.join("canary.txt"), logs.join("run-1.log")).unwrap();
        symlink(fx.outside.join("missing"), logs.join("run-2.log")).unwrap(); // dangling
        fs::write(logs.join("run-3.log"), "keep me").unwrap();
        let names = ["run-1.log", "run-2.log", "run-3.log", "run-4.log"]
            .into_iter()
            .map(String::from);
        let (mut f, path) = create_log_with(&logs, names).unwrap();
        assert_eq!(path, logs.join("run-4.log"));
        f.write_all(b"new").unwrap();
        assert_eq!(fs::read_to_string(fx.outside.join("canary.txt")).unwrap(), "canary");
        assert!(!fx.outside.join("missing").exists(), "a dangling link was followed");
        assert_eq!(fs::read_to_string(logs.join("run-3.log")).unwrap(), "keep me");
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn when_every_name_is_taken_creation_fails() {
        let fx = fx();
        let logs = fx.env.logs_dir();
        fs::write(logs.join("run-1.log"), "").unwrap();
        let r = create_log_with(&logs, ["run-1.log".to_string()].into_iter());
        assert!(matches!(r, Err(LaunchError::Log(e)) if e.kind() == io::ErrorKind::AlreadyExists));
    }

    #[test]
    fn generated_log_names_are_distinct_and_match_the_pattern() {
        let v: Vec<String> = log_names().collect();
        assert_eq!(v.len(), 1 + NAME_RETRIES as usize);
        let set: std::collections::BTreeSet<_> = v.iter().collect();
        assert_eq!(set.len(), v.len());
        assert!(v.iter().all(|n| is_log_name(OsStr::new(n))), "{v:?}");
    }

    // ------------------------------------------------------------------------------ pruning

    #[test]
    fn pruning_keeps_the_newest_20_and_touches_nothing_else() {
        let fx = fx();
        let logs = fx.env.logs_dir();
        for i in 1..=30 {
            fs::write(logs.join(old_name(i)), format!("log {i}")).unwrap();
        }
        // Things that look log-ish but are not regular `run-*.log` files, and unrelated files.
        for n in ["notes.txt", "run-1.txt", "xrun-1.log", "keep.log", "run-x.log.bak"] {
            fs::write(logs.join(n), "other").unwrap();
        }
        fs::create_dir(logs.join("run-dir.log")).unwrap();
        fs::write(logs.join("run-dir.log/inner"), "inner").unwrap();
        // Symlinks that match the pattern and sort OLDEST: must be neither counted nor followed nor deleted.
        symlink(fx.outside.join("canary.txt"), logs.join("run-0000000000-a.log")).unwrap();
        symlink(&fx.outside, logs.join("run-0000000000-b.log")).unwrap();
        symlink(fx.outside.join("missing"), logs.join("run-0000000000-c.log")).unwrap();

        let deleted = prune_logs(&logs, MAX_LOGS, OsStr::new(&old_name(30)), MAX_SCAN).unwrap();
        assert_eq!(deleted, 10);
        let want: Vec<String> = (11..=30).map(old_name).collect();
        assert_eq!(regular_logs(&logs), want);
        for n in ["notes.txt", "run-1.txt", "xrun-1.log", "keep.log", "run-x.log.bak"] {
            assert!(logs.join(n).is_file(), "{n} was deleted");
        }
        assert_eq!(fs::read_to_string(logs.join("run-dir.log/inner")).unwrap(), "inner");
        for l in ["a", "b", "c"] {
            let p = logs.join(format!("run-0000000000-{l}.log"));
            assert!(fs::symlink_metadata(&p).unwrap().file_type().is_symlink(), "{l}");
        }
        assert_eq!(fs::read_to_string(fx.outside.join("canary.txt")).unwrap(), "canary");
    }

    #[test]
    fn pruning_never_deletes_the_current_log_even_if_it_sorts_oldest() {
        let fx = fx();
        let logs = fx.env.logs_dir();
        for i in 1..=25 {
            fs::write(logs.join(old_name(i)), "x").unwrap();
        }
        let deleted = prune_logs(&logs, MAX_LOGS, OsStr::new(&old_name(1)), MAX_SCAN).unwrap();
        assert_eq!(deleted, 5);
        let left = regular_logs(&logs);
        assert_eq!(left.len(), 20);
        assert!(left.contains(&old_name(1)));
        assert!(left.contains(&old_name(25)));
        assert!(!left.contains(&old_name(2)) && !left.contains(&old_name(6)));
        assert!(left.contains(&old_name(7)));
    }

    #[test]
    fn pruning_refuses_a_logs_dir_that_is_a_symlink() {
        let fx = fx();
        for i in 1..=30 {
            fs::write(fx.outside.join(old_name(i)), "x").unwrap();
        }
        fs::remove_dir(fx.env.logs_dir()).unwrap();
        symlink(&fx.outside, fx.env.logs_dir()).unwrap();
        assert!(prune_logs(&fx.env.logs_dir(), MAX_LOGS, OsStr::new("run-none.log"), MAX_SCAN).is_err());
        assert_eq!(regular_logs(&fx.outside).len(), 30);
    }

    #[test]
    fn spawning_keeps_at_most_20_logs() {
        let fx = fx();
        let logs = fx.env.logs_dir();
        for i in 1..=25 {
            fs::write(logs.join(old_name(i)), "old").unwrap();
        }
        let r = poisoned()
            .spawn(fake_cmd(&fx, "echo new >&2", false), &fx.env, LogSink::LogOnly)
            .unwrap();
        let new = r.log_path().file_name().unwrap().to_string_lossy().into_owned();
        assert!(r.wait().unwrap().success());
        let left = regular_logs(&logs);
        assert_eq!(left.len(), MAX_LOGS, "{left:?}");
        assert!(left.contains(&new));
        assert_eq!(fs::read_to_string(logs.join(&new)).unwrap(), "new\n");
    }

    // ------------------------------------------------------------------------------ run_helper

    fn env_helper(l: &Launcher, backend_var: Option<(&str, &str)>) -> Vec<String> {
        let mut c = Command::new("/usr/bin/env");
        if let Some((k, v)) = backend_var {
            c.env(k, v);
        }
        let out = l.run_helper(c, Duration::from_secs(20)).unwrap();
        assert!(out.status.success());
        String::from_utf8(out.output)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn launcher_is_clone_send_sync_and_a_clone_keeps_the_host_env() {
        fn assert_traits<T: Clone + Send + Sync>() {}
        assert_traits::<Launcher>();
        let l = poisoned().clone();
        let e = envs(&l.finalize(Command::new("/bin/true")));
        assert_eq!(e["HOME"], some("/home/u"));
        assert!(!e.contains_key("SECRET"));
    }

    #[test]
    fn a_helper_run_through_run_helper_sees_no_host_secret_and_the_backend_vars() {
        let lines = env_helper(&poisoned(), Some(("WINEPREFIX", "/apps/t/prefix")));
        // Injected host vars that are allowlisted arrive; the process's real environment does not.
        assert!(lines.contains(&"HOME=/home/u".to_string()), "{lines:?}");
        assert!(lines.contains(&"LC_ALL=C".to_string()));
        assert!(lines.contains(&"WINEPREFIX=/apps/t/prefix".to_string()));
        assert_eq!(lines.iter().filter(|l| l.starts_with("WINEPREFIX=")).count(), 1);
        for bad in [
            "SECRET",
            "LD_PRELOAD",
            "AWS_SECRET_ACCESS_KEY",
            "SSH_AUTH_SOCK",
            "CARGO_MANIFEST_DIR",
        ] {
            assert!(!has_var(&lines, bad), "{bad} reached the helper: {lines:?}");
        }
        // A host WINEPREFIX never reaches a helper that did not set one.
        let lines = env_helper(&poisoned(), None);
        assert!(!has_var(&lines, "WINEPREFIX"), "{lines:?}");
    }

    #[test]
    fn run_helper_over_the_real_environment_strips_it_too() {
        assert!(
            std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
            "run under `cargo test`"
        );
        let lines = env_helper(&Launcher::new(), Some(("WINEPREFIX", "/p")));
        assert!(!has_var(&lines, "CARGO_MANIFEST_DIR"), "{lines:?}");
        assert!(lines.contains(&"WINEPREFIX=/p".to_string()));
    }

    #[test]
    fn run_helper_returns_status_and_capped_output() {
        let l = poisoned();
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg("echo out; echo err >&2; exit 3");
        let out = l.run_helper(c, Duration::from_secs(20)).unwrap();
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(out.output, b"out\nerr\n");
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg("head -c 200000 /dev/zero");
        assert_eq!(
            l.run_helper(c, Duration::from_secs(20)).unwrap().output.len(),
            crate::proc::MAX_CAPTURE
        );
    }

    #[test]
    fn run_helper_timeout_still_kills_and_reports_the_partial_output() {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg("echo hello; exec sleep 30");
        let t0 = Instant::now();
        let err = poisoned().run_helper(c, Duration::from_secs(1)).unwrap_err();
        assert!(t0.elapsed() < Duration::from_secs(3), "took {:?}", t0.elapsed());
        match err {
            crate::RunError::TimedOut { output, .. } => assert!(output.as_str().contains("hello"), "{output}"),
            other => panic!("{other:?}"),
        }
    }

    // ------------------------------------------------------------------------------ default XAUTHORITY

    fn xauth(home: &str, display: bool, xauthority: bool, regular: bool) -> Option<PathBuf> {
        default_xauthority(OsStr::new(home), display, xauthority, |_| regular)
    }

    #[test]
    fn a_regular_home_xauthority_is_passed_when_xauthority_is_unset() {
        assert_eq!(
            xauth("/home/u", true, false, true),
            Some(PathBuf::from("/home/u/.Xauthority"))
        );
    }

    #[test]
    fn no_default_xauthority_when_the_file_is_not_a_regular_file() {
        // missing, a directory and a symlink all answer `false` from the no-follow probe
        assert_eq!(xauth("/home/u", true, false, false), None);
    }

    #[test]
    fn no_default_xauthority_for_a_relative_or_empty_home() {
        assert_eq!(xauth("home/u", true, false, true), None);
        assert_eq!(xauth("", true, false, true), None);
        assert_eq!(xauth(".", true, false, true), None);
    }

    #[test]
    fn no_default_xauthority_without_display_or_when_the_host_names_one() {
        assert_eq!(xauth("/home/u", false, false, true), None, "no DISPLAY");
        assert_eq!(xauth("/home/u", true, true, true), None, "host XAUTHORITY wins");
    }

    #[test]
    fn the_default_xauthority_probe_gets_the_exact_path_and_is_not_asked_when_pointless() {
        let seen = std::cell::RefCell::new(Vec::new());
        let probe = |p: &Path| {
            seen.borrow_mut().push(p.to_owned());
            true
        };
        assert!(default_xauthority(OsStr::new("/h"), true, false, probe).is_some());
        assert_eq!(*seen.borrow(), [PathBuf::from("/h/.Xauthority")]);
        let never = |_: &Path| -> bool { panic!("probed although nothing can be returned") };
        assert_eq!(default_xauthority(OsStr::new("/h"), false, false, never), None);
        assert_eq!(default_xauthority(OsStr::new("rel"), true, false, never), None);
        assert_eq!(default_xauthority(OsStr::new("/h"), true, true, never), None);
    }

    #[test]
    fn the_real_probe_accepts_a_file_and_refuses_missing_directory_symlink_and_dangling_link() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        fs::write(d.join("file"), "cookie").unwrap();
        fs::create_dir(d.join("dir")).unwrap();
        symlink(d.join("file"), d.join("link")).unwrap();
        symlink(d.join("nothing"), d.join("dangling")).unwrap();
        assert!(is_regular_file_nofollow(&d.join("file")));
        for no in ["dir", "link", "dangling", "missing"] {
            assert!(!is_regular_file_nofollow(&d.join(no)), "{no}");
        }
        // and end to end through the real probe: HOME=<d> has no .Xauthority yet, then a file, then a symlink
        let host = |home: &Path| {
            let l = Launcher::with_host_env([
                (OsString::from("DISPLAY"), OsString::from(":0")),
                (OsString::from("HOME"), home.as_os_str().to_owned()),
            ]);
            envs(&l.finalize(Command::new("/bin/true"))).remove("XAUTHORITY")
        };
        assert_eq!(host(d), None);
        fs::write(d.join(".Xauthority"), "cookie").unwrap();
        assert_eq!(host(d), Some(Some(format!("{}/.Xauthority", d.display()))));
        fs::remove_file(d.join(".Xauthority")).unwrap();
        symlink(d.join("file"), d.join(".Xauthority")).unwrap();
        assert_eq!(host(d), None, "a symlinked .Xauthority is refused");
    }

    #[test]
    fn launcher_passes_the_default_xauthority_to_a_real_child_and_an_empty_one_is_replaced() {
        let fx = fx();
        let home = tempfile::tempdir().unwrap();
        fs::write(home.path().join(".Xauthority"), "cookie").unwrap();
        let want = format!("XAUTHORITY={}/.Xauthority", home.path().display());
        for empty in [None, Some("")] {
            let mut host = vec![
                ("PATH", home.path().to_str().unwrap().to_owned()),
                ("HOME", home.path().to_str().unwrap().to_owned()),
                ("DISPLAY", ":1".to_owned()),
            ];
            host.extend(empty.map(|e| ("XAUTHORITY", e.to_owned())));
            let lines = child_env(&fx, &Launcher::with_host_env(host));
            let got: Vec<_> = lines.iter().filter(|l| l.starts_with("XAUTHORITY=")).collect();
            assert_eq!(got, [&want], "{lines:?}");
        }
        // a host XAUTHORITY is untouched although the default file exists; without DISPLAY nothing is added
        let h = home.path().to_str().unwrap();
        let named = Launcher::with_host_env([
            ("HOME", h),
            ("DISPLAY", ":1"),
            ("XAUTHORITY", "/run/user/1/xauth"),
            ("PATH", "/usr/bin"),
        ]);
        let got: Vec<_> = child_env(&fx, &named);
        let got: Vec<_> = got.iter().filter(|l| l.starts_with("XAUTHORITY=")).collect();
        assert_eq!(got, [&"XAUTHORITY=/run/user/1/xauth".to_string()]);
        let headless = Launcher::with_host_env([("HOME", h), ("PATH", "/usr/bin")]);
        assert!(!has_var(&child_env(&fx, &headless), "XAUTHORITY"));
    }

    // ------------------------------------------------------------------------------ bounded and tolerant pruning

    #[test]
    fn pruning_looks_at_no_more_than_max_scan_entries() {
        let fx = fx();
        let logs = fx.env.logs_dir();
        for i in 1..=60 {
            fs::write(logs.join(old_name(i)), "x").unwrap();
        }
        // Only 10 of the 60 entries are examined (whichever the filesystem lists first); of those, keep-1 = 4
        // survive, so exactly 6 go and 54 remain. An unbounded scan would delete 56.
        let deleted = prune_logs(&logs, 5, OsStr::new("run-none.log"), 10).unwrap();
        assert_eq!(deleted, 6);
        assert_eq!(regular_logs(&logs).len(), 54);
        // A limit of zero examines nothing.
        assert_eq!(prune_logs(&logs, 5, OsStr::new("run-none.log"), 0).unwrap(), 0);
        assert_eq!(regular_logs(&logs).len(), 54);
    }

    #[test]
    fn pruning_skips_entries_it_cannot_read_and_carries_on() {
        let fx = fx();
        let logs = fx.env.logs_dir();
        for i in 1..=25 {
            fs::write(logs.join(old_name(i)), "x").unwrap();
        }
        let bad = || Err(io::Error::from(io::ErrorKind::PermissionDenied));
        let mut entries: Vec<io::Result<(OsString, bool)>> = vec![bad()];
        for i in 1..=25 {
            entries.push(Ok((OsString::from(old_name(i)), true)));
            if i % 5 == 0 {
                entries.push(bad());
            }
        }
        let deleted = prune_entries(
            &logs,
            MAX_LOGS,
            OsStr::new(&old_name(25)),
            entries.into_iter(),
            MAX_SCAN,
        );
        assert_eq!(deleted, 5);
        let want: Vec<String> = (6..=25).map(old_name).collect();
        assert_eq!(regular_logs(&logs), want);
    }

    // ------------------------------------------------------------------------------ Running: kill, try_wait, sink failures

    #[test]
    fn kill_stops_the_child_promptly_and_wait_reports_the_signal() {
        use std::os::unix::process::ExitStatusExt;
        let fx = fx();
        let mut r = poisoned()
            .spawn(fake_cmd(&fx, "exec sleep 30", false), &fx.env, LogSink::LogOnly)
            .unwrap();
        assert!(r.id() > 0);
        assert!(r.try_wait().unwrap().is_none(), "still running");
        let t0 = Instant::now();
        r.kill().unwrap();
        let st = r.wait().unwrap();
        assert!(t0.elapsed() < Duration::from_secs(2), "took {:?}", t0.elapsed());
        assert_eq!(st.signal(), Some(9));
        assert_eq!(st.code(), None);
    }

    #[test]
    fn kill_also_works_in_tee_mode_and_try_wait_sees_the_exit() {
        let fx = fx();
        let mut r = poisoned()
            .spawn(
                fake_cmd(&fx, "exec sleep 30", true),
                &fx.env,
                LogSink::Tee(Box::new(SharedBuf::default())),
            )
            .unwrap();
        r.kill().unwrap();
        let t0 = Instant::now();
        let st = loop {
            if let Some(st) = r.try_wait().unwrap() {
                break st;
            }
            assert!(t0.elapsed() < Duration::from_secs(5), "never exited");
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(!st.success());
        assert!(r.wait().is_ok(), "wait after try_wait still works");
    }

    #[test]
    fn healthy_sinks_report_no_failure() {
        let fx = fx();
        let r = poisoned()
            .spawn(
                fake_cmd(&fx, "echo e >&2; exit 2", true),
                &fx.env,
                LogSink::Tee(Box::new(SharedBuf::default())),
            )
            .unwrap();
        let f = r.wait_report().unwrap();
        assert_eq!(f.status.code(), Some(2));
        assert!(!f.log_write_failed && !f.terminal_write_failed, "{f:?}");
    }

    #[test]
    fn a_full_log_sink_is_reported_and_the_child_is_not_blocked() {
        // /dev/full accepts open() and fails every write with ENOSPC. The path given is a scratch name: it is
        // only what `Running::log_path` says (and what would be removed if the start failed).
        let fx = fx();
        let full = OpenOptions::new().write(true).open("/dev/full").unwrap();
        let term = SharedBuf::default();
        let cmd = poisoned().finalize(fake_cmd(&fx, "head -c 300000 /dev/zero >&2; exit 5", true));
        let scratch = fx.env.logs_dir().join("not-created.log");
        let r = start_child(cmd, full, scratch, LogSink::Tee(Box::new(term.clone()))).unwrap();
        let f = r.wait_report().unwrap();
        assert_eq!(f.status.code(), Some(5));
        assert!(f.log_write_failed);
        assert!(!f.terminal_write_failed);
        assert_eq!(term.bytes().len(), 300_000, "the terminal side kept working");
    }

    #[test]
    fn a_broken_terminal_is_reported_and_the_log_is_complete() {
        let fx = fx();
        let r = poisoned()
            .spawn(
                fake_cmd(&fx, "head -c 100000 /dev/zero >&2", true),
                &fx.env,
                LogSink::Tee(Box::new(BrokenTerminal)),
            )
            .unwrap();
        let path = r.log_path().to_path_buf();
        let f = r.wait_report().unwrap();
        assert!(f.terminal_write_failed && !f.log_write_failed, "{f:?}");
        assert_eq!(fs::metadata(path).unwrap().len(), 100_000);
    }

    #[test]
    fn a_grandchild_that_never_stops_writing_cannot_keep_the_tee_alive() {
        // The direct child exits at once; a background loop keeps writing 16 MB to stderr. Once the child has
        // exited the reader takes at most MAX_AFTER_STOP more and closes (the writer then gets EPIPE and dies).
        let fx = fx();
        let term = SharedBuf::default();
        let script =
            "( i=0; while [ $i -lt 500000 ]; do echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx >&2; i=$((i+1)); done ) & exit 0";
        let r = poisoned()
            .spawn(
                fake_cmd(&fx, script, true),
                &fx.env,
                LogSink::Tee(Box::new(term.clone())),
            )
            .unwrap();
        let path = r.log_path().to_path_buf();
        let t0 = Instant::now();
        assert!(r.wait().unwrap().success());
        assert!(t0.elapsed() < Duration::from_secs(10), "took {:?}", t0.elapsed());
        // Cap (1 MiB) plus generous room for what was read before the child exited; an uncapped reader takes 16 MB.
        let teed = term.bytes().len();
        assert!(teed <= 8 * 1024 * 1024, "teed {teed} bytes");
        assert_eq!(fs::metadata(path).unwrap().len(), teed as u64);
    }
}
