//! `runtimed --write`: what must hold before a daemon may run mutations, checked once at startup.
//!
//! * The socket is inside `$XDG_RUNTIME_DIR` (spec D11): every sandbox profile mounts an empty tmpfs over that
//!   directory and no grant may name it, so no sandboxed program can reach a write-capable socket. A `--socket` in
//!   any other directory could sit inside one a grant exposes. The check resolves symlinks in the existing part of
//!   the path and refuses any `..`.
//!   `$XDG_RUNTIME_DIR` itself must be a 0700 directory of this user and not `/` (what systemd makes
//!   `/run/user/<uid>`), or "inside" would mean nothing.
//! * `$XDG_RUNTIME_DIR/runtime/job-cwd` exists as a 0700 directory of ours (spec D8), created if missing. Each
//!   daemon takes a directory of its own in it, `d-<32 hex>/`, guarded by an exclusive `flock` on `d-<32 hex>.lock`
//!   held for the daemon's life ([`DaemonDir`]); each job runs in a fresh subdirectory of that. At startup a daemon
//!   removes only the `d-*` directories whose lock it can take (their daemon is gone): never a live daemon's, whether
//!   that daemon serves the same socket (and this one is about to be refused by the socket lock) or another one.
//!   Anything else there is left alone.
//! * The sibling `runtime` passes `check_runtime_exe` and `runtime --version` prints this daemon's own version
//!   within [`VERSION_TIMEOUT`] (its output read on a thread against the same deadline, at most 4 KiB) (spec D10).
//!   The CLI's `--plan-digest` check still guards consent if the binary is replaced later.
use crate::jobs::{JobsConfig, check_job_cwd, check_runtime_exe, child_env};
use std::fs;
use std::io::{BufRead, Read};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long `runtime --version` may take.
pub const VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// What `--write` needs: the job configuration, and this daemon's own job directory (keep it for the daemon's life;
/// dropping it releases the lock and removes the directory).
#[derive(Debug)]
pub struct Prepared {
    pub jobs: JobsConfig,
    pub dir: DaemonDir,
}

/// This daemon's job directory and the `flock` that marks it live. Dropped: the directory is removed.
#[derive(Debug)]
pub struct DaemonDir {
    path: PathBuf,
    lock_path: PathBuf,
    _lock: fs::File,
}

impl Drop for DaemonDir {
    fn drop(&mut self) {
        remove_logged(&self.path);
        let _ = fs::remove_file(&self.lock_path);
    }
}

/// `remove_dir_all` (it never follows a symlink), saying so on stderr when it fails (the disk space stays used).
pub(crate) fn remove_logged(p: &Path) {
    if let Err(e) = fs::remove_dir_all(p)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!("runtimed: cannot remove the job directory {}: {e}", shown(p));
    }
}

/// Opens (creating if `create`) and `flock`s `p` without blocking: `Ok(None)` when another process holds it.
fn try_lock(p: &Path, create: bool) -> std::io::Result<Option<fs::File>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    // SAFETY: `flock` on an fd we own; no memory is passed.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(f));
    }
    let e = std::io::Error::last_os_error();
    if e.kind() == std::io::ErrorKind::WouldBlock {
        Ok(None)
    } else {
        Err(e)
    }
}

fn random_hex() -> Result<String, String> {
    let mut b = [0u8; 16];
    let mut got = 0;
    while got < b.len() {
        // SAFETY: the pointer and length name the unfilled tail of `b`.
        let r = unsafe { libc::getrandom(b[got..].as_mut_ptr().cast(), b.len() - got, 0) };
        if r > 0 {
            got += r as usize;
        } else if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            return Err("--write: getrandom failed".into());
        }
    }
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Takes a fresh `d-<hex>` directory in `job_cwd`, locked. The lock file is created and locked first, and still
/// being the file at its path is checked after the lock (a cleaner of another daemon may have removed an unlocked
/// one in between); only then the directory is created, so a `d-*` directory without its lock file is never live.
fn take_daemon_dir(job_cwd: &Path) -> Result<DaemonDir, String> {
    for _ in 0..8 {
        let name = format!("d-{}", random_hex()?);
        let lock_path = job_cwd.join(format!("{name}.lock"));
        let lock = match try_lock(&lock_path, true) {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("--write: cannot create {}: {e}", shown(&lock_path))),
        };
        let held = lock.metadata().ok();
        let there = fs::symlink_metadata(&lock_path).ok();
        if held
            .zip(there)
            .is_none_or(|(h, t)| h.ino() != t.ino() || h.dev() != t.dev())
        {
            continue;
        }
        let path = job_cwd.join(&name);
        if let Err(e) = fs::DirBuilder::new().mode(0o700).create(&path) {
            let _ = fs::remove_file(&lock_path);
            return Err(format!("--write: cannot create {}: {e}", shown(&path)));
        }
        return Ok(DaemonDir {
            path,
            lock_path,
            _lock: lock,
        });
    }
    Err("--write: cannot take a job directory".into())
}

/// Removes the job directories of daemons that are gone: `d-<32 hex>` whose lock can be taken (or has no lock
/// file), and lock files whose lock can be taken. Held locks and anything else are left alone.
fn remove_dead_daemon_dirs(job_cwd: &Path) {
    let is_hex = |n: &str| n.len() == 32 && n.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let Ok(entries) = fs::read_dir(job_cwd) else { return };
    for e in entries.flatten() {
        let Some(name) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(id) = name.strip_prefix("d-") else { continue };
        let (id, is_lock) = match id.strip_suffix(".lock") {
            Some(id) => (id, true),
            None => (id, false),
        };
        // `DirEntry::file_type` does not follow a symlink.
        let Ok(ft) = e.file_type() else { continue };
        if !is_hex(id) || (is_lock && !ft.is_file()) || (!is_lock && !ft.is_dir()) {
            continue;
        }
        let lock_path = job_cwd.join(format!("d-{id}.lock"));
        let dir = job_cwd.join(format!("d-{id}"));
        match try_lock(&lock_path, false) {
            // Its daemon is gone: the directory first, the lock file last (while held).
            Ok(Some(_held)) => {
                remove_logged(&dir);
                let _ = fs::remove_file(&lock_path);
            }
            // No lock file: never live (a daemon creates and locks it before the directory).
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && !is_lock => remove_logged(&dir),
            _ => {}
        }
    }
}

/// The job configuration for a write-mode daemon on `socket`, or why it may not have one (a message for stderr).
pub fn prepare(socket: &Path, xdg: Option<&Path>, runtime_exe: &Path) -> Result<Prepared, String> {
    prepare_with(socket, xdg, runtime_exe, VERSION_TIMEOUT)
}

fn shown(p: &Path) -> String {
    rt_core::clean_text(&p.to_string_lossy(), 512)
}

fn euid() -> u32 {
    crate::server::euid()
}

pub(crate) fn prepare_with(
    socket: &Path,
    xdg: Option<&Path>,
    runtime_exe: &Path,
    version_timeout: Duration,
) -> Result<Prepared, String> {
    let xdg = xdg
        .filter(|p| p.is_absolute())
        .ok_or("--write needs XDG_RUNTIME_DIR (an absolute path)")?;
    let root = fs::canonicalize(xdg).map_err(|e| format!("--write: cannot resolve XDG_RUNTIME_DIR: {e}"))?;
    let m = fs::metadata(&root).map_err(|e| format!("--write: cannot inspect XDG_RUNTIME_DIR: {e}"))?;
    if root == Path::new("/") || !m.is_dir() || m.uid() != euid() || m.mode() & 0o077 != 0 {
        return Err(format!(
            "--write needs XDG_RUNTIME_DIR ({}) to be a 0700 directory of this user (like /run/user/<uid>)",
            shown(&root)
        ));
    }
    if !inside(socket, &root) {
        return Err(format!(
            "--write needs the socket inside XDG_RUNTIME_DIR ({}), which no sandbox can see; {} is not",
            shown(&root),
            shown(socket)
        ));
    }
    let dir = root.join("runtime");
    private_dir(&dir)?;
    let cwd = dir.join("job-cwd");
    private_dir(&cwd)?;
    check_job_cwd(&cwd, euid()).map_err(|e| format!("--write: {}", e.message))?;
    remove_dead_daemon_dirs(&cwd);
    check_runtime_exe(runtime_exe, euid()).map_err(|e| format!("--write: {}", e.message))?;
    let want = format!("runtime {}", env!("CARGO_PKG_VERSION"));
    let got = version_of(runtime_exe, &cwd, version_timeout)?;
    if got != want {
        return Err(format!(
            "--write: {} says {:?}; this runtimed is {}: install matching versions",
            shown(runtime_exe),
            rt_core::clean_text(&got, 128),
            env!("CARGO_PKG_VERSION")
        ));
    }
    let dir = take_daemon_dir(&cwd)?;
    Ok(Prepared {
        jobs: JobsConfig::new(runtime_exe.to_owned(), dir.path.clone()),
        dir,
    })
}

/// Whether `p` resolves to a path at or below `root` (canonical): `..` is refused outright, symlinks in the part
/// of `p`'s directory that exists are resolved.
pub(crate) fn inside(p: &Path, root: &Path) -> bool {
    if !p.is_absolute() || p.components().any(|c| matches!(c, Component::ParentDir)) {
        return false;
    }
    let Some(mut dir) = p.parent() else { return false };
    let mut rest: Vec<&std::ffi::OsStr> = vec![];
    loop {
        if let Ok(mut full) = fs::canonicalize(dir) {
            full.extend(rest.iter().rev());
            return full.starts_with(root);
        }
        let (Some(name), Some(up)) = (dir.file_name(), dir.parent()) else {
            return false;
        };
        rest.push(name);
        dir = up;
    }
}

/// `d`: created 0700 if missing; otherwise a real directory of ours closed to group and others.
fn private_dir(d: &Path) -> Result<(), String> {
    match fs::DirBuilder::new().mode(0o700).create(d) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            return Err(format!("--write: cannot create {}: {e}", shown(d)));
        }
        _ => {}
    }
    let m = fs::symlink_metadata(d).map_err(|e| format!("--write: cannot inspect {}: {e}", shown(d)))?;
    if !m.file_type().is_dir() || m.uid() != euid() || m.mode() & 0o077 != 0 {
        return Err(format!(
            "--write: {} is not a 0700 directory of this user (a symlink?)",
            shown(d)
        ));
    }
    Ok(())
}

/// `exe --version`'s first line, with the job environment. Everything is bounded by `timeout`: the output is read
/// on a thread (at most 4 KiB, up to the first newline), so a process it leaves holding stdout cannot hang startup;
/// a child still running at the deadline is killed.
fn version_of(exe: &Path, cwd: &Path, timeout: Duration) -> Result<String, String> {
    let fail = |why: String| format!("--write: cannot check {}'s version: {why}", shown(exe));
    let mut child = Command::new(exe)
        .arg("--version")
        .env_clear()
        .envs(child_env(&|| std::env::vars_os().collect()))
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| fail(e.to_string()))?;
    let until = Instant::now() + timeout;
    let no_answer = || fail(format!("no answer within {} s", timeout.as_secs_f32()));
    let (tx, rx) = std::sync::mpsc::channel();
    if let Some(out) = child.stdout.take() {
        // Left blocked (and leaked) only if something keeps the pipe open past the deadline: startup fails then.
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::BufReader::new(out.take(4096)).read_line(&mut line);
            let _ = tx.send(line);
        });
    }
    let line = rx.recv_timeout(until.saturating_duration_since(Instant::now()));
    loop {
        match child.try_wait() {
            Ok(Some(_)) if line.is_ok() => break,
            Ok(None) if Instant::now() < until && line.is_ok() => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(no_answer());
            }
        }
    }
    Ok(line.unwrap_or_default().trim().to_owned())
}

/// The path an inherited listener is bound to (`None`: unnamed or abstract, which `--write` refuses).
pub fn listener_path(l: &std::os::unix::net::UnixListener) -> Option<PathBuf> {
    l.local_addr().ok()?.as_pathname().map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::tests::write_script;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct W {
        _t: tempfile::TempDir,
        xdg: PathBuf,
        exe: PathBuf,
    }

    fn w(version_line: &str) -> W {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().canonicalize().unwrap();
        let xdg = root.join("xdg");
        fs::create_dir(&xdg).unwrap();
        fs::set_permissions(&xdg, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        fs::set_permissions(root.join("bin"), fs::Permissions::from_mode(0o755)).unwrap();
        let exe = root.join("bin/runtime");
        write_script(
            &exe,
            &format!("#!/bin/sh\n[ \"$1\" = --probe ] && exit 0\n{version_line}\n"),
        );
        W { _t: t, xdg, exe }
    }

    fn ours() -> String {
        format!("echo 'runtime {}'", env!("CARGO_PKG_VERSION"))
    }

    fn prep(w: &W, sock: &Path) -> Result<Prepared, String> {
        prepare_with(sock, Some(&w.xdg), &w.exe, Duration::from_millis(500))
    }

    #[test]
    fn a_socket_inside_xdg_runtime_dir_with_a_matching_runtime_is_accepted() {
        let w = w(&ours());
        for sock in [
            w.xdg.join("runtime/runtimed.sock"),
            w.xdg.join("other/deeper/s.sock"),
            w.xdg.join("s.sock"),
        ] {
            let p = prep(&w, &sock).unwrap_or_else(|e| panic!("{sock:?}: {e}"));
            let cfg = &p.jobs;
            // This daemon's own job directory under the shared one: `d-<32 hex>`, 0700.
            assert_eq!(cfg.cwd.parent().unwrap(), w.xdg.join("runtime/job-cwd"));
            let name = cfg.cwd.file_name().unwrap().to_str().unwrap();
            assert!(name.starts_with("d-") && name.len() == 34, "{name}");
            assert_eq!(fs::symlink_metadata(&cfg.cwd).unwrap().mode() & 0o7777, 0o700);
            assert_eq!(cfg.runtime_exe, w.exe);
            assert_eq!(cfg.max_running, 4);
        }
        let m = fs::symlink_metadata(w.xdg.join("runtime/job-cwd")).unwrap();
        assert_eq!(m.mode() & 0o7777, 0o700);
        assert_eq!(
            fs::symlink_metadata(w.xdg.join("runtime")).unwrap().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn a_socket_outside_xdg_runtime_dir_is_refused() {
        let w = w(&ours());
        let outside = w.xdg.parent().unwrap().join("elsewhere");
        fs::create_dir(&outside).unwrap();
        let link = w.xdg.join("link");
        symlink(&outside, &link).unwrap();
        for sock in [
            outside.join("s.sock"),
            link.join("s.sock"),
            w.xdg.join("runtime/../../elsewhere/s.sock"),
            PathBuf::from("/tmp/s.sock"),
            PathBuf::from("relative/s.sock"),
        ] {
            let e = prep(&w, &sock).unwrap_err();
            assert!(e.contains("inside XDG_RUNTIME_DIR"), "{sock:?}: {e}");
        }
        assert!(prepare_with(&w.xdg.join("s.sock"), None, &w.exe, Duration::from_millis(500)).is_err());
        assert!(
            prepare_with(
                &w.xdg.join("s.sock"),
                Some(Path::new("rel")),
                &w.exe,
                Duration::from_millis(500)
            )
            .is_err()
        );
        assert!(
            !w.xdg.join("runtime").exists(),
            "nothing created before the socket check"
        );
    }

    #[test]
    fn another_runtime_version_or_a_silent_one_is_refused() {
        let w = w("echo 'runtime 9.9.9'");
        let e = prep(&w, &w.xdg.join("s.sock")).unwrap_err();
        assert!(e.contains("9.9.9") && e.contains("matching versions"), "{e}");
        let w = self::w("sleep 10");
        let t = Instant::now();
        let e = prep(&w, &w.xdg.join("s.sock")).unwrap_err();
        assert!(e.contains("no answer") && t.elapsed() < Duration::from_secs(3), "{e}");
        let w = self::w(&ours());
        fs::set_permissions(&w.exe, fs::Permissions::from_mode(0o775)).unwrap();
        let e = prep(&w, &w.xdg.join("s.sock")).unwrap_err();
        assert!(e.contains(&format!("run: chmod g-w,o-w {}", w.exe.display())), "{e}");
        // A process left holding stdout (with or without a first line) cannot hang startup.
        let w = self::w(&format!("sleep 10 & {}", ours()));
        prep(&w, &w.xdg.join("s.sock")).unwrap();
        let w = self::w("sleep 10 &");
        let t = Instant::now();
        let e = prep(&w, &w.xdg.join("s.sock")).unwrap_err();
        assert!(e.contains("no answer") && t.elapsed() < Duration::from_secs(3), "{e}");
    }

    #[test]
    fn an_unsafe_runtime_dir_or_job_cwd_is_refused() {
        let w = w(&ours());
        fs::create_dir(w.xdg.join("runtime")).unwrap();
        fs::set_permissions(w.xdg.join("runtime"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(prep(&w, &w.xdg.join("s.sock")).unwrap_err().contains("0700"));
        fs::set_permissions(w.xdg.join("runtime"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(w.xdg.join("runtime/job-cwd")).unwrap();
        fs::set_permissions(w.xdg.join("runtime/job-cwd"), fs::Permissions::from_mode(0o700)).unwrap();
        // Anything that is not a daemon's job directory is left alone and blocks nothing.
        fs::write(w.xdg.join("runtime/job-cwd/notepad"), b"planted").unwrap();
        let odd = w.xdg.join(format!("runtime/job-cwd/{}", "ab".repeat(16)));
        fs::create_dir(&odd).unwrap();
        prep(&w, &w.xdg.join("s.sock")).unwrap();
        assert!(odd.exists() && w.xdg.join("runtime/job-cwd/notepad").exists());
        fs::set_permissions(w.xdg.join("runtime/job-cwd"), fs::Permissions::from_mode(0o750)).unwrap();
        assert!(prep(&w, &w.xdg.join("s.sock")).unwrap_err().contains("0700"));
        // XDG_RUNTIME_DIR itself: ours and 0700, never `/`.
        fs::set_permissions(w.xdg.join("runtime/job-cwd"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&w.xdg, fs::Permissions::from_mode(0o755)).unwrap();
        let like = "to be a 0700 directory of this user (like /run/user/<uid>)";
        let e = prep(&w, &w.xdg.join("s.sock")).unwrap_err();
        assert!(e.contains(like), "{e}");
        let e = prepare_with(
            Path::new("/s.sock"),
            Some(Path::new("/")),
            &w.exe,
            Duration::from_millis(500),
        )
        .unwrap_err();
        assert!(e.contains(like), "{e}");
    }

    /// The final review's I1: a second `runtimed --write` (the same socket, refused later by the socket lock, or
    /// another socket) must never remove a running daemon's job directories; only a dead daemon's go.
    #[test]
    fn two_write_daemons_never_remove_each_others_job_directories() {
        let w = w(&ours());
        let a = prep(&w, &w.xdg.join("runtime/runtimed.sock")).unwrap();
        let live = a.jobs.cwd.join("0".repeat(32));
        fs::create_dir(&live).unwrap();
        fs::write(live.join("setup.log"), b"a running job's file").unwrap();
        let b = prep(&w, &w.xdg.join("runtime/runtimed.sock")).unwrap();
        let c = prep(&w, &w.xdg.join("other.sock")).unwrap();
        assert!(
            live.join("setup.log").exists(),
            "a second daemon removed a live job's directory"
        );
        assert!(b.jobs.cwd != a.jobs.cwd && c.jobs.cwd != a.jobs.cwd && b.jobs.cwd != c.jobs.cwd);
        drop(b);
        drop(c);
        assert!(live.exists());
        // A dead daemon's directory (its lock free, or its lock file gone) is removed with what is in it.
        let job_cwd = w.xdg.join("runtime/job-cwd");
        let dead = job_cwd.join(format!("d-{}", "1".repeat(32)));
        fs::create_dir_all(dead.join("2".repeat(32))).unwrap();
        fs::write(job_cwd.join(format!("d-{}.lock", "1".repeat(32))), b"").unwrap();
        let orphan = job_cwd.join(format!("d-{}", "3".repeat(32)));
        fs::create_dir(&orphan).unwrap();
        let d = prep(&w, &w.xdg.join("s.sock")).unwrap();
        assert!(!dead.exists() && !job_cwd.join(format!("d-{}.lock", "1".repeat(32))).exists());
        assert!(!orphan.exists());
        assert!(live.exists(), "a's lock is still held");
        // A daemon's own directory goes when it stops.
        let a_dir = a.jobs.cwd.clone();
        drop(a);
        assert!(!a_dir.exists());
        drop(d);
    }

    #[test]
    fn an_inherited_listeners_path_is_known() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("s.sock");
        let l = std::os::unix::net::UnixListener::bind(&p).unwrap();
        assert_eq!(listener_path(&l), Some(p));
    }
}
