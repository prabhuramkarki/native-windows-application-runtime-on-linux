//! The [`Launcher`]: the ONE place a backend's [`Command`] is finalised and started.
//!
//! ```text
//! backend.command(..) --> Launcher::finalize --> Launcher::spawn --> Running::wait
//!   (WINEPREFIX=... set     env_clear + allowlist     log file, stderr routing,
//!    through .env())        + backend vars again      tee thread
//!                           + sandbox hook (`wrap`)
//! ```
//!
//! **Environment.** `Command::env_clear()` also forgets variables set earlier with `.env()`, so `finalize`
//! first snapshots what the backend set, clears, applies the allowlisted host variables and only then re-applies
//! the snapshot: backend variables always win over a host variable of the same name (a host `WINEPREFIX` can
//! never redirect a prefix) and everything not allowlisted (`LD_PRELOAD`, secrets, ...) is gone.
//!
//! **Streams.** stdout is inherited. stderr goes to a fresh `logs/run-<secs>-<nanos>-<pid>.log`; with
//! [`LogSink::Tee`] it is copied to that file and to a terminal writer by a thread that [`Running::wait`] joins.
//!
//! **Log files** are created with `O_CREAT|O_EXCL` (never through a symlink) and mode 0600 after `symlink_metadata`
//! has shown that `logs/` is a real directory; at most [`MAX_LOGS`] `run-*.log` regular files are kept per app.
//! Residual race (documented, not closable without `openat2`): a process of the same uid that can write to the
//! app directory can swap `logs/` for a symlink between the check and the create; `O_EXCL` still guarantees the
//! *file* is new, and Phase 5's sandbox is the real boundary.
use crate::proc::{Drain, capture_pair, stdio};
use crate::{AppEnv, allowed_env};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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

/// See the module docs.
pub struct Launcher {
    /// The host variables a child may inherit (already filtered by [`allowed_env`]).
    host: Vec<(OsString, OsString)>,
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
        Launcher {
            host: allowed_env(host),
        }
    }

    /// The sandbox hook. Identity in Phase 2 (Phase 5 wraps the command here); it runs last, on the finished
    /// command, so a sandbox sees the final environment.
    pub fn wrap(&self, cmd: Command) -> Command {
        cmd
    }

    /// Applies the environment rules (module docs) and the sandbox hook. `spawn` uses it; backends that run helper
    /// processes (`wineboot`, `wineserver -k`) call it too before [`run_with_timeout`](crate::run_with_timeout).
    pub fn finalize(&self, mut cmd: Command) -> Command {
        // 1. Snapshot what the backend set: `env_clear` would discard it. `None` = an explicit removal.
        let explicit: Vec<(OsString, Option<OsString>)> = cmd
            .get_envs()
            .map(|(k, v)| (k.to_owned(), v.map(OsStr::to_owned)))
            .collect();
        // 2. Drop everything inherited from this process, 3. add the allowlisted host variables,
        cmd.env_clear();
        for (k, v) in &self.host {
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
        let mut cmd = self.finalize(cmd);
        let (log, log_path) = create_log_with(&env.logs_dir(), log_names())?;
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
        let child = match spawned {
            Ok(c) => c,
            Err(e) => return Err(discard(&log_path, LaunchError::Spawn(e))),
        };
        // Best effort: a failed prune must not fail the launch.
        if let Some(name) = log_path.file_name() {
            let _ = prune_logs(&env.logs_dir(), MAX_LOGS, name);
        }
        Ok(Running { child, tee, log_path })
    }
}

/// A started child plus its log. Dropping it without `wait` neither kills nor waits for the child.
pub struct Running {
    child: Child,
    tee: Option<Drain<()>>,
    log_path: PathBuf,
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

    /// Waits for the child, then joins the tee thread (which has drained the child's stderr by then).
    pub fn wait(mut self) -> io::Result<ExitStatus> {
        let status = self.child.wait();
        if let Some(tee) = self.tee.take() {
            tee.finish();
        }
        status
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
/// (the other keeps working; the child is never blocked or failed by logging).
fn tee_to(rd: UnixStream, log: File, terminal: Box<dyn Write + Send>) -> io::Result<Drain<()>> {
    let mut sinks: (Option<File>, Option<Box<dyn Write + Send>>) = (Some(log), Some(terminal));
    Drain::start(rd, (), move |(), chunk| {
        if let Some(f) = &mut sinks.0
            && f.write_all(chunk).is_err()
        {
            sinks.0 = None;
        }
        if let Some(t) = &mut sinks.1
            && t.write_all(chunk).and_then(|()| t.flush()).is_err()
        {
            sinks.1 = None;
        }
    })
}

fn is_log_name(name: &OsStr) -> bool {
    let n = name.as_encoded_bytes();
    n.starts_with(b"run-") && n.ends_with(b".log")
}

/// Deletes the oldest `run-*.log` regular files in `dir` so at most `keep` remain, counting `current` (never
/// deleted). Symlinks, directories and other names are neither counted nor touched (`DirEntry::file_type` does not
/// follow links, and `remove_file` on a link removes the link only). Returns the number deleted.
fn prune_logs(dir: &Path, keep: usize, current: &OsStr) -> io::Result<usize> {
    require_real_dir(dir).map_err(|e| match e {
        LaunchError::Log(e) => e,
        _ => io::Error::new(io::ErrorKind::InvalidInput, "logs directory is not a real directory"),
    })?;
    let mut old: Vec<OsString> = Vec::new();
    for entry in fs::read_dir(dir)?.take(MAX_SCAN) {
        let entry = entry?;
        let name = entry.file_name();
        if name != current && is_log_name(&name) && entry.file_type()?.is_file() {
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
    Ok(deleted)
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

        let deleted = prune_logs(&logs, MAX_LOGS, OsStr::new(&old_name(30))).unwrap();
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
        let deleted = prune_logs(&logs, MAX_LOGS, OsStr::new(&old_name(1))).unwrap();
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
        assert!(prune_logs(&fx.env.logs_dir(), MAX_LOGS, OsStr::new("run-none.log")).is_err());
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
}
