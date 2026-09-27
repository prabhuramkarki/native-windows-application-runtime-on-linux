//! `runtimed --write`: what must hold before a daemon may run mutations, checked once at startup.
//!
//! * The socket is inside `$XDG_RUNTIME_DIR` (spec D11): every sandbox profile mounts an empty tmpfs over that
//!   directory and no grant may name it, so no sandboxed program can reach a write-capable socket. A `--socket` in
//!   any other directory could sit inside one a grant exposes. The check resolves symlinks in the existing part of
//!   the path and refuses any `..`.
//! * `$XDG_RUNTIME_DIR/runtime/job-cwd` exists as an empty 0700 directory of ours (spec D8), created if missing.
//! * The sibling `runtime` passes `check_runtime_exe` and `runtime --version` (bounded) prints this daemon's own
//!   version (spec D10). The CLI's `--plan-digest` check still guards consent if the binary is replaced later.
use crate::jobs::{JobsConfig, check_job_cwd, check_runtime_exe, child_env};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long `runtime --version` may take.
pub const VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// The job configuration for a write-mode daemon on `socket`, or why it may not have one (a message for stderr).
pub fn prepare(socket: &Path, xdg: Option<&Path>, runtime_exe: &Path) -> Result<JobsConfig, String> {
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
) -> Result<JobsConfig, String> {
    let xdg = xdg
        .filter(|p| p.is_absolute())
        .ok_or("--write needs XDG_RUNTIME_DIR (an absolute path)")?;
    let root = fs::canonicalize(xdg).map_err(|e| format!("--write: cannot resolve XDG_RUNTIME_DIR: {e}"))?;
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
    check_job_cwd(&cwd, euid()).map_err(|e| format!("--write: {} ({})", e.message, shown(&cwd)))?;
    check_runtime_exe(runtime_exe, euid()).map_err(|e| format!("--write: {} ({})", e.message, shown(runtime_exe)))?;
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
    Ok(JobsConfig::new(runtime_exe.to_owned(), cwd))
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

/// `exe --version`'s first line, with the job environment, within `timeout` (killed after it).
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
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail(format!("no answer within {} s", timeout.as_secs_f32())));
            }
        }
    }
    let mut out = String::new();
    if let Some(o) = child.stdout.take() {
        let _ = o.take(4096).read_to_string(&mut out);
    }
    Ok(out.lines().next().unwrap_or("").trim().to_owned())
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

    fn prep(w: &W, sock: &Path) -> Result<JobsConfig, String> {
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
            let cfg = prep(&w, &sock).unwrap_or_else(|e| panic!("{sock:?}: {e}"));
            assert_eq!(cfg.cwd, w.xdg.join("runtime/job-cwd"));
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
        fs::set_permissions(&w.exe, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(prep(&w, &w.xdg.join("s.sock")).unwrap_err().contains("runtime binary"));
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
        fs::write(w.xdg.join("runtime/job-cwd/notepad"), b"planted").unwrap();
        assert!(prep(&w, &w.xdg.join("s.sock")).unwrap_err().contains("job directory"));
    }

    #[test]
    fn an_inherited_listeners_path_is_known() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("s.sock");
        let l = std::os::unix::net::UnixListener::bind(&p).unwrap();
        assert_eq!(listener_path(&l), Some(p));
    }
}
