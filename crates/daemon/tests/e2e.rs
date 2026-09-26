//! End to end: the real `runtimed` driven by the real `runtime` (`rpc`, `daemon-status`), the CLI's standalone
//! commands as the oracle, and a hostile fake daemon the CLI must survive without letting anything reach the
//! terminal. Every run has a scratch environment (a scratch data directory and socket, never the user's).
//!
//! `runtime` is another crate's binary: it is taken from next to `runtimed` (`cargo test --workspace` builds
//! both; `cargo test -p runtime-daemon` alone does not, and then these tests fail saying so).
use rt_core::{AppId, BackendInfo, Metadata, Store, WinPath};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DAEMON: &str = env!("CARGO_BIN_EXE_runtimed");

fn runtime_bin() -> PathBuf {
    let p = Path::new(DAEMON).with_file_name("runtime");
    assert!(
        p.is_file(),
        "{} is missing: build it first (`cargo build -p runtime-cli`, or run `cargo test --workspace`)",
        p.display()
    );
    p
}

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

    /// `program` with a cleared environment pointing into the scratch dir (the same for daemon and CLI).
    fn cmd(&self, program: &Path) -> Command {
        let mut c = Command::new(program);
        c.env_clear()
            .env("HOME", self.path("home"))
            .env("RUNTIME_DATA_DIR", self.path("data"))
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(Stdio::null());
        c
    }

    fn rt(&self, args: &[&str]) -> Output {
        self.cmd(&runtime_bin()).args(args).output().unwrap()
    }

    /// `runtime rpc <args> --socket <sock>`.
    fn rpc(&self, sock: &Path, args: &[&str]) -> Output {
        self.cmd(&runtime_bin())
            .arg("rpc")
            .args(args)
            .arg("--socket")
            .arg(sock)
            .output()
            .unwrap()
    }

    fn status(&self, sock: &Path) -> Output {
        self.cmd(&runtime_bin())
            .args(["daemon-status", "--socket"])
            .arg(sock)
            .output()
            .unwrap()
    }

    fn plant(&self, id: &str, name: &str) {
        let store = Store::new(self.path("data/apps")).unwrap();
        let id = AppId::parse(id).unwrap();
        let env = store.create(&id).unwrap();
        std::fs::create_dir_all(env.drive_c().join("app")).unwrap();
        std::fs::write(env.drive_c().join("app/a.exe"), b"MZ").unwrap();
        let exe = WinPath::parse(r"C:\app\a.exe").unwrap();
        let backend = BackendInfo {
            id: "wine".into(),
            version: "10.0".into(),
        };
        let md = Metadata::new(id, name.into(), Some("1.0".into()), "x86_64", &exe, backend, "gui");
        store.write_metadata(&env, &md).unwrap();
    }

    /// A real `runtimed` on `<scratch>/run/d.sock`, up and serving.
    fn daemon(&self) -> (Daemon, PathBuf) {
        let sock = self.path("run/d.sock");
        let mut child = self
            .cmd(Path::new(DAEMON))
            .arg("--socket")
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wait_for(&sock, &mut child);
        (Daemon(child), sock)
    }
}

/// Stops (SIGTERM) and reaps the daemon, whatever the test did.
struct Daemon(Child);

impl Daemon {
    /// SIGTERM, then the exit status.
    fn stop(&mut self) -> std::process::ExitStatus {
        // SAFETY: a signal to our own child, not reaped yet.
        unsafe { libc::kill(self.0.id() as libc::pid_t, libc::SIGTERM) };
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(st) = self.0.try_wait().unwrap() {
                return st;
            }
            assert!(Instant::now() < until, "runtimed did not stop");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for(sock: &Path, child: &mut Child) {
    let until = Instant::now() + Duration::from_secs(10);
    while std::fs::symlink_metadata(sock).map(|m| m.mode() & 0o777).ok() != Some(0o600) {
        if let Some(st) = child.try_wait().unwrap() {
            panic!("runtimed exited early: {st}");
        }
        assert!(Instant::now() < until, "no socket at {sock:?}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn json_out(o: &Output) -> Value {
    assert!(o.status.success(), "{}: {}", o.status, text(&o.stderr));
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&o.stdout)))
}

/// What could drive a terminal: a control (other than the line break) or format character.
fn assert_terminal_safe(what: &str, bytes: &[u8]) {
    let s = std::str::from_utf8(bytes).unwrap_or_else(|_| panic!("{what}: not UTF-8"));
    if let Some(c) = s
        .chars()
        .find(|&c| (c.is_control() && c != '\n') || rt_core::is_format(c))
    {
        panic!("{what}: raw U+{:04X} in {s:?}", c as u32);
    }
}

#[test]
fn rpc_and_daemon_status_against_the_real_daemon() {
    let s = Scratch::new();
    s.plant("game", "Game");
    let (mut d, sock) = s.daemon();
    let sock_s = sock.to_str().unwrap();

    let o = s.status(&sock);
    let out = text(&o.stdout);
    assert_eq!(o.status.code(), Some(0), "{out}{}", text(&o.stderr));
    assert!(out.contains(&format!("socket: {sock_s}\n")), "{out}");
    assert!(
        out.contains("reachable: yes") && out.contains(&format!("api: {}", rt_api::API_VERSION)),
        "{out}"
    );

    let v = json_out(&s.rpc(&sock, &["rpc.version"]));
    assert_eq!(v["api"], rt_api::API_VERSION);
    assert_eq!(v["protocol"], rt_api::PROTOCOL);
    let v = json_out(&s.rpc(&sock, &["apps.list"]));
    assert_eq!(v["apps"][0]["id"], "game");
    let v = json_out(&s.rpc(&sock, &["apps.get", r#"{"id": "game"}"#]));
    assert_eq!(v["name"], "Game");
    for m in ["permissions.get", "deps.plan"] {
        assert!(json_out(&s.rpc(&sock, &[m, r#"{"id": "game"}"#])).is_object(), "{m}");
    }
    assert!(json_out(&s.rpc(&sock, &["compat.list", "{}"]))["records"].is_array());

    // Errors: exit 1, the code and kind on stderr, nothing on stdout.
    for (args, want) in [
        (&["apps.get", r#"{"id": "nope"}"#][..], "code -32000, kind not_found"),
        (&["apps.get", r#"{"id": "../x"}"#], "kind invalid_argument"),
        (&["no.such"], "code -32601"),
        (&["apps.get", r#"{"id": 1}"#], "code -32602"),
        (&["apps.get", "[1]"], "params must be one JSON object"),
        (&["apps.get", "not json"], "params must be one JSON object"),
        (&["apps.get", r#""id""#], "params must be one JSON object"),
    ] {
        let o = s.rpc(&sock, args);
        assert_eq!(o.status.code(), Some(1), "{args:?}");
        assert!(o.stdout.is_empty(), "{args:?}");
        assert!(text(&o.stderr).contains(want), "{args:?}: {}", text(&o.stderr));
    }

    assert!(d.stop().success());
    assert!(!sock.exists());
    let o = s.status(&sock);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o.stdout).contains("reachable: no (no daemon at"),
        "{}",
        text(&o.stdout)
    );
    let o = s.rpc(&sock, &["rpc.version"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(text(&o.stderr).contains("no daemon at"), "{}", text(&o.stderr));
}

#[test]
fn the_default_socket_is_the_daemons_and_needs_xdg_runtime_dir() {
    let s = Scratch::new();
    let xdg = s.path("xdg");
    std::fs::DirBuilder::new().mode(0o700).create(&xdg).unwrap();
    let sock = xdg.join("runtime/runtimed.sock");
    let child = s
        .cmd(Path::new(DAEMON))
        .env("XDG_RUNTIME_DIR", &xdg)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut d = Daemon(child);
    wait_for(&sock, &mut d.0);
    let o = s
        .cmd(&runtime_bin())
        .env("XDG_RUNTIME_DIR", &xdg)
        .arg("daemon-status")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stdout));
    let o = s
        .cmd(&runtime_bin())
        .env("XDG_RUNTIME_DIR", &xdg)
        .args(["rpc", "rpc.version"])
        .output()
        .unwrap();
    assert_eq!(json_out(&o)["api"], rt_api::API_VERSION);
    assert!(d.stop().success());
    // Without XDG_RUNTIME_DIR and without --socket there is no place to look.
    for args in [&["daemon-status"][..], &["rpc", "rpc.version"]] {
        let o = s.rt(args);
        assert_eq!(o.status.code(), Some(1), "{args:?}");
        assert!(
            text(&o.stderr).contains("XDG_RUNTIME_DIR"),
            "{args:?}: {}",
            text(&o.stderr)
        );
    }
}

#[test]
fn rpc_answers_equal_the_standalone_commands() {
    let s = Scratch::new();
    s.plant("game", "Game");
    s.plant("tool", "Tool");
    let (mut d, sock) = s.daemon();
    // apps.list vs `runtime list --json`: the same rows.
    let api = json_out(&s.rpc(&sock, &["apps.list"]));
    assert_eq!(api["skipped"], 0);
    assert_eq!(api["apps"], json_out(&s.rt(&["list", "--json"])));
    // compat.list vs `runtime compat --json`.
    assert_eq!(
        json_out(&s.rpc(&sock, &["compat.list"]))["records"],
        json_out(&s.rt(&["compat", "--json"]))
    );
    // doctor.system vs `runtime doctor --json`: both probe the host, so one mismatch (a probe that timed out under
    // load) is retried once; a real difference fails twice.
    let doctor = || {
        let api = json_out(&s.rpc(&sock, &["doctor.system"]));
        let o = s.rt(&["doctor", "--json"]);
        let cli: Value = serde_json::from_slice(&o.stdout).unwrap();
        let pick = |v: &Value| json!([v["subject"], v["verdict"], v["checks"]]);
        (pick(&api), pick(&cli))
    };
    let (a, c) = doctor();
    if a != c {
        let (a, c) = doctor();
        assert_eq!(a, c);
    }
    assert!(d.stop().success());
}

#[test]
fn unsafe_sockets_never_receive_a_request_from_the_cli() {
    let s = Scratch::new();
    let run = s.path("run");
    std::fs::DirBuilder::new().mode(0o700).create(&run).unwrap();
    let sock = run.join("s.sock");
    let l = UnixListener::bind(&sock).unwrap();
    l.set_nonblocking(true).unwrap();
    let link = s.path("link");
    symlink(&run, &link).unwrap();
    let setups: [(&str, &dyn Fn() -> PathBuf); 3] = [
        ("a socket open to others", &|| {
            std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).unwrap();
            sock.clone()
        }),
        ("a directory open to others", &|| {
            std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o755)).unwrap();
            sock.clone()
        }),
        ("a symlinked directory", &|| {
            std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
            link.join("s.sock")
        }),
    ];
    for (what, setup) in setups {
        let p = setup();
        for o in [s.rpc(&p, &["rpc.version"]), s.status(&p)] {
            assert_eq!(o.status.code(), Some(1), "{what}");
            let all = text(&o.stdout) + &text(&o.stderr);
            assert!(all.contains("refusing"), "{what}: {all}");
        }
        assert!(l.accept().is_err(), "{what}: the CLI connected");
    }
}

/// A fake daemon at `<scratch>/run/f.sock` serving `n` connections: each request line (parsed) is handed to
/// `answer`, which writes what it likes.
/// What a fake daemon does with one request.
type Answer = fn(&mut UnixStream, Value);

fn fake(s: &Scratch, n: usize, answer: Answer) -> PathBuf {
    let run = s.path("run");
    let _ = std::fs::DirBuilder::new().mode(0o700).create(&run);
    let sock = run.join("f.sock");
    let _ = std::fs::remove_file(&sock);
    let l = UnixListener::bind(&sock).unwrap();
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600)).unwrap();
    thread::spawn(move || {
        for _ in 0..n {
            let Ok((mut c, _)) = l.accept() else { return };
            let mut line = String::new();
            let _ = BufReader::new(&c).read_line(&mut line);
            answer(&mut c, serde_json::from_str(&line).unwrap_or(Value::Null));
        }
    });
    sock
}

/// The hostile strings: terminal escapes, C1 CSI, bidi, zero-width, DEL, BEL.
const NASTY: &str = "a\u{1b}]0;pwned\u{7}\u{1b}[2J\u{9b}31m\u{202e}txt.exe\u{200b}\u{7f}\r\nb";

#[test]
fn a_hostile_daemon_never_crashes_the_cli_or_reaches_the_terminal() {
    let s = Scratch::new();
    // A result full of escapes, in keys and values: printed lossless and terminal-safe.
    let sock = fake(&s, 1, |c, req| {
        let v = json!({"jsonrpc": "2.0", "id": req["id"], "result": {NASTY: [NASTY, {"k": NASTY}]}});
        let _ = c.write_all(format!("{v}\n").as_bytes());
    });
    let o = s.rpc(&sock, &["rpc.version"]);
    assert_terminal_safe("result", &o.stdout);
    assert_eq!(
        json_out(&o),
        json!({NASTY: [NASTY, {"k": NASTY}]}),
        "escaping is lossless"
    );

    // Error replies and broken replies: exit 1 (never a panic's 101 or a signal), stderr terminal-safe.
    let cases: [(&str, Answer); 7] = [
        ("error with escapes", |c, req| {
            let e = json!({"code": -32000, "message": NASTY, "data": {"kind": NASTY}});
            let _ = c.write_all(format!("{}\n", json!({"jsonrpc": "2.0", "id": req["id"], "error": e})).as_bytes());
        }),
        ("raw control bytes", |c, _| {
            let _ = c.write_all(b"\x1b]0;pwned\x07\x1b[2J\x9b\xff\n");
        }),
        ("another id", |c, _| {
            let _ = c.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":424242,\"result\":\"\\u001b[2J\"}\n");
        }),
        ("oversize", |c, _| {
            let chunk = vec![b'\x1b'; 1 << 20];
            for _ in 0..20 {
                if c.write_all(&chunk).is_err() {
                    return;
                }
            }
        }),
        ("deep nesting", |c, _| {
            let _ = c.write_all(format!("{}\n", "[".repeat(200_000)).as_bytes());
        }),
        ("closed without a reply", |_, _| {}),
        ("cut short", |c, _| {
            let _ = c.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"\x1b[2J");
        }),
    ];
    for (what, answer) in cases {
        let sock = fake(&s, 1, answer);
        let o = s.rpc(&sock, &["rpc.version"]);
        assert_eq!(o.status.code(), Some(1), "{what}: {}", text(&o.stderr));
        assert!(o.stdout.is_empty(), "{what}");
        assert_terminal_safe(what, &o.stderr);
        assert!(text(&o.stderr).starts_with("error: "), "{what}: {}", text(&o.stderr));
    }

    // daemon-status: a hostile version is shown safely; a daemon that never answers is cut at its timeout.
    let sock = fake(&s, 1, |c, req| {
        let r = json!({"api": NASTY, "runtime": NASTY, "protocol": NASTY});
        let _ = c.write_all(format!("{}\n", json!({"jsonrpc": "2.0", "id": req["id"], "result": r})).as_bytes());
    });
    let o = s.status(&sock);
    assert_eq!(o.status.code(), Some(0));
    assert_terminal_safe("status", &o.stdout);
    let sock = fake(&s, 1, |_, _| thread::sleep(Duration::from_secs(30)));
    let t = Instant::now();
    let o = s.status(&sock);
    assert_eq!(o.status.code(), Some(1));
    assert!(t.elapsed() < Duration::from_secs(15), "{:?}", t.elapsed());
    assert!(text(&o.stdout).contains("reachable: no"), "{}", text(&o.stdout));
}
