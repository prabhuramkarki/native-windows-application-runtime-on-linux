//! The real `runtimed` binary: arguments, signals, socket activation and the shim it names. Every run has a
//! scratch environment (no `XDG_RUNTIME_DIR` unless a test sets one, a scratch data directory, never the user's).
use rt_core::{AppId, BackendInfo, Metadata, Store, WinPath};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_runtimed");

struct Scratch {
    dir: tempfile::TempDir,
}

impl Scratch {
    fn new() -> Scratch {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("home")).unwrap();
        Scratch { dir }
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }

    /// `runtimed` (or `program`) with a cleared environment pointing into the scratch dir.
    fn cmd(&self, program: &str) -> Command {
        let mut c = Command::new(program);
        c.env_clear()
            .env("HOME", self.path("home"))
            .env("RUNTIME_DATA_DIR", self.path("data"))
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        c
    }

    fn plant(&self, id: &str) {
        let store = Store::new(self.path("data/apps")).unwrap();
        let id = AppId::parse(id).unwrap();
        let env = store.create(&id).unwrap();
        std::fs::create_dir_all(env.drive_c().join("app")).unwrap();
        // The per-app HOME `runtime run` prepares (the sandbox command binds it).
        std::fs::create_dir_all(env.root().join("runtime/home")).unwrap();
        std::fs::write(env.drive_c().join("app/a.exe"), b"MZ").unwrap();
        let exe = WinPath::parse(r"C:\app\a.exe").unwrap();
        let backend = BackendInfo {
            id: "wine".into(),
            version: "10.0".into(),
        };
        let md = Metadata::new(id, "App".into(), None, "x86_64", &exe, backend, "gui");
        store.write_metadata(&env, &md).unwrap();
    }
}

/// Waits until `sock` is a listening 0600 socket (set after bind+listen), or panics.
fn wait_for(sock: &Path, child: &mut Child) {
    let until = Instant::now() + Duration::from_secs(10);
    while std::fs::symlink_metadata(sock).map(|m| m.mode() & 0o777).ok() != Some(0o600) {
        if let Some(st) = child.try_wait().unwrap() {
            panic!("runtimed exited early: {st}: {}", stderr(child));
        }
        assert!(Instant::now() < until, "no socket at {sock:?}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn stderr(child: &mut Child) -> String {
    let mut s = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = std::io::Read::read_to_string(&mut e, &mut s);
    }
    s
}

/// The exit status within 10 s, or kills it and panics.
fn wait_exit(child: &mut Child) -> ExitStatus {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return st;
        }
        if Instant::now() > until {
            let _ = child.kill();
            panic!("runtimed did not exit");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn call(sock: &Path, method: &str, params: Value) -> Value {
    let mut s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let line = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
    s.write_all(format!("{line}\n").as_bytes()).unwrap();
    let mut out = String::new();
    BufReader::new(s).read_line(&mut out).unwrap();
    serde_json::from_str(&out).unwrap()
}

fn signal(child: &Child, sig: libc::c_int) {
    // SAFETY: a signal to our own child, which has not been reaped yet.
    assert_eq!(unsafe { libc::kill(child.id() as libc::pid_t, sig) }, 0);
}

#[test]
fn sigterm_and_sigint_stop_it_cleanly_and_remove_its_socket() {
    for sig in [libc::SIGTERM, libc::SIGINT] {
        let s = Scratch::new();
        let sock = s.path("run/d.sock");
        let mut child = s.cmd(BIN).arg("--socket").arg(&sock).spawn().unwrap();
        wait_for(&sock, &mut child);
        assert_eq!(
            call(&sock, "rpc.version", json!({}))["result"]["api"],
            rt_api::API_VERSION
        );
        signal(&child, sig);
        let st = wait_exit(&mut child);
        let err = stderr(&mut child);
        assert!(st.success(), "{sig}: {st}: {err}");
        assert!(!sock.exists(), "the socket was left behind");
        assert!(err.contains("runtimed: stopped"), "{err}");
    }
}

#[test]
fn sandbox_info_names_the_sibling_runtime_never_runtimed() {
    let s = Scratch::new();
    s.plant("game");
    let sock = s.path("run/d.sock");
    let mut child = s.cmd(BIN).arg("--socket").arg(&sock).spawn().unwrap();
    wait_for(&sock, &mut child);
    let v = call(&sock, "sandbox.info", json!({"id": "game"}));
    signal(&child, libc::SIGTERM);
    wait_exit(&mut child);
    let r = &v["result"];
    assert!(r.is_object(), "{v}");
    let text = r.to_string();
    let me = std::fs::canonicalize(BIN).unwrap();
    assert!(
        !text.contains(me.to_str().unwrap()),
        "runtimed named as the shim: {text}"
    );
    let sibling = Path::new(BIN).with_file_name("runtime");
    match std::fs::canonicalize(&sibling) {
        // `cargo test -p runtime-daemon` alone does not build `runtime`: then it cannot be resolved, as designed.
        Err(_) => assert!(r["refused"].as_str().unwrap().contains("cannot be resolved"), "{r}"),
        Ok(rt) if !r["command"].as_array().unwrap().is_empty() && r["refused"].is_null() => {
            assert!(text.contains(rt.to_str().unwrap()), "{text}")
        }
        // Refused for another reason (no bwrap, ...): still never because the launcher is unknown.
        Ok(_) => assert!(
            !r["refused"].as_str().unwrap_or("").contains("cannot be resolved"),
            "{r}"
        ),
    }
}

/// `runtimed` started through `sh`, whose pid it inherits by `exec`, with `fd` as its fd 3 and `env` exported.
fn activated(s: &Scratch, fd: i32, env: &str) -> Child {
    let mut c = s.cmd("/bin/sh");
    c.arg("-c").arg(format!("{env}; exec \"$0\"")).arg(BIN);
    // SAFETY: `dup2` and `fcntl` are async-signal-safe; `fd` is open in the parent and so in the forked child.
    // When `fd` already is 3, `dup2` does nothing and leaves its FD_CLOEXEC set: cleared explicitly.
    unsafe {
        c.pre_exec(move || {
            if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    c.spawn().unwrap()
}

#[test]
fn socket_activation_serves_the_inherited_socket_and_leaves_it() {
    let s = Scratch::new();
    let sock = s.path("act.sock");
    let l = UnixListener::bind(&sock).unwrap();
    let mut child = activated(&s, l.as_raw_fd(), "export LISTEN_PID=$$ LISTEN_FDS=1");
    drop(l);
    // No XDG_RUNTIME_DIR and no --socket: only the inherited socket can be served.
    assert_eq!(
        call(&sock, "rpc.version", json!({}))["result"]["api"],
        rt_api::API_VERSION
    );
    signal(&child, libc::SIGTERM);
    let st = wait_exit(&mut child);
    let err = stderr(&mut child);
    assert!(st.success(), "{st}: {err}");
    assert!(err.contains("serving the inherited socket"), "{err}");
    assert!(sock.exists(), "systemd's socket was removed");
}

#[test]
fn activation_meant_for_another_pid_is_ignored() {
    let s = Scratch::new();
    let sock = s.path("run/d.sock");
    let mut child = s
        .cmd(BIN)
        .env("LISTEN_PID", "1")
        .env("LISTEN_FDS", "1")
        .arg("--socket")
        .arg(&sock)
        .spawn()
        .unwrap();
    wait_for(&sock, &mut child);
    assert!(call(&sock, "apps.list", json!({}))["result"].is_object());
    signal(&child, libc::SIGTERM);
    assert!(wait_exit(&mut child).success());
}

#[test]
fn bad_activation_is_an_error_not_a_fallback() {
    let s = Scratch::new();
    let file = std::fs::File::create(s.path("f")).unwrap();
    let l = UnixListener::bind(s.path("l.sock")).unwrap();
    for (fd, env) in [
        (file.as_raw_fd(), "export LISTEN_PID=$$ LISTEN_FDS=1"),
        (l.as_raw_fd(), "export LISTEN_PID=$$ LISTEN_FDS=2"),
    ] {
        let mut child = activated(&s, fd, &format!("{env} XDG_RUNTIME_DIR={}", s.path("xdg").display()));
        let st = wait_exit(&mut child);
        let err = stderr(&mut child);
        assert_eq!(st.code(), Some(1), "{env}: {err}");
        assert!(err.contains("socket activation"), "{err}");
        assert!(!s.path("xdg/runtime").exists(), "fell back to the default socket");
    }
}

#[test]
fn it_refuses_without_a_place_or_with_bad_arguments_or_a_live_twin() {
    let s = Scratch::new();
    let o = s.cmd(BIN).output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("XDG_RUNTIME_DIR"));
    for args in [&["--bogus"][..], &["--socket"], &["x", "y"]] {
        let o = s.cmd(BIN).args(args).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}");
    }
    // The default place, under a scratch XDG_RUNTIME_DIR.
    let xdg = s.path("xdg");
    std::fs::create_dir(&xdg).unwrap();
    let sock = xdg.join("runtime/runtimed.sock");
    let mut first = s.cmd(BIN).env("XDG_RUNTIME_DIR", &xdg).spawn().unwrap();
    wait_for(&sock, &mut first);
    let o = s.cmd(BIN).env("XDG_RUNTIME_DIR", &xdg).output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("already serving"));
    assert!(
        call(&sock, "rpc.version", json!({}))["result"].is_object(),
        "the first one was disturbed"
    );
    signal(&first, libc::SIGTERM);
    assert!(wait_exit(&mut first).success());
    assert!(!sock.exists());
}
