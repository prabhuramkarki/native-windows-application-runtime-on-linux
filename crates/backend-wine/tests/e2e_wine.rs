//! End-to-end tests against REAL Wine (system Wine 10.x, `wine`/`wineserver` found by `WineBackend::discover`).
//!
//! **`#[ignore]`d**: they need Wine installed and the mingw fixtures (`tools/build-fixtures.sh` builds
//! `tests/fixtures/build/hello64.exe` and `hello32.exe`, which print `hello from windows` and exit with 7).
//! Run them with
//!
//! ```text
//! cargo test -p runtime-backend-wine -- --ignored --test-threads=1
//! ```
//!
//! Each test uses a temporary data directory and a [`Sandbox`] guard that ALWAYS stops the prefix's `wineserver`
//! (and kills it if it will not stop), so no Wine process survives a test, even a failed one. The GUI fixture
//! (`gui64.exe`, a modal message box) is never run here.
use backend_wine::WineBackend;
use rt_core::{AppEnv, AppId, CompatBackend, Launcher, LogSink, RunOpts, Store};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn fixture(name: &str) -> PathBuf {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    assert!(
        p.is_file(),
        "fixture {} is missing: run tools/build-fixtures.sh",
        p.display()
    );
    p
}

fn wait_until(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < limit, "timed out after {limit:?} waiting for: {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The `wineserver` processes of `prefix`: their executable is `wineserver` and their working directory is
/// Wine's server directory `.../server-<st_dev hex>-<st_ino hex of the prefix>` (verified on Wine 10.0); the
/// environment check is a second, independent way to recognise one.
fn wineservers_for(prefix: &Path) -> Vec<u32> {
    let meta = fs::metadata(prefix).expect("the prefix exists");
    let server_dir = format!("server-{:x}-{:x}", meta.dev(), meta.ino());
    let wanted_env = format!("WINEPREFIX={}", prefix.display()).into_bytes();
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let proc = entry.path();
        let is_wineserver = fs::read_link(proc.join("exe"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n == "wineserver"))
            == Some(true);
        if !is_wineserver {
            continue;
        }
        let by_cwd = fs::read_link(proc.join("cwd"))
            .ok()
            .and_then(|p| p.file_name().map(|n| *n == *server_dir))
            == Some(true);
        let by_env = fs::read(proc.join("environ")).is_ok_and(|e| e.split(|b| *b == 0).any(|v| v == wanted_env));
        if by_cwd || by_env {
            found.push(pid);
        }
    }
    found
}

/// A temporary app environment with real Wine, and the guard that leaves no wineserver behind.
struct Sandbox {
    backend: WineBackend,
    launcher: Launcher,
    env: AppEnv,
    _tmp: tempfile::TempDir, // dropped after `Drop::drop` below has stopped the server
}

impl Sandbox {
    fn new() -> Sandbox {
        let backend = WineBackend::discover().expect("Wine must be installed for the e2e tests (apt install wine)");
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().join("apps")).unwrap();
        let env = store.create(&AppId::parse("e2e").unwrap()).unwrap();
        Sandbox {
            backend,
            launcher: Launcher::new(),
            env,
            _tmp: tmp,
        }
    }

    fn prefix(&self) -> PathBuf {
        self.env.prefix()
    }

    /// Copies a fixture to `drive_c/Program Files/t/<name>` and returns the path and its directory.
    fn install(&self, name: &str) -> (PathBuf, PathBuf) {
        let dir = self.env.drive_c().join("Program Files/t");
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join(name);
        fs::copy(fixture(name), &exe).unwrap();
        (exe, dir)
    }

    /// Runs `exe` through `command()` + `finalize()` and captures stdout (stderr goes to /dev/null so a lingering
    /// wineserver cannot hold the capture pipe open). Returns the output and the wall time.
    fn run_captured(&self, exe: &Path, dir: &Path, args: &[OsString]) -> (Output, Duration) {
        let cmd = self
            .backend
            .command(&self.env, exe, dir, args, &RunOpts::default())
            .unwrap();
        let mut cmd = self.launcher.finalize(cmd);
        cmd.stderr(Stdio::null());
        let started = Instant::now();
        let out = cmd.output().expect("wine could not be started");
        (out, started.elapsed())
    }

    fn assert_no_wineserver(&self) {
        wait_until("the wineserver of the prefix to exit", Duration::from_secs(10), || {
            wineservers_for(&self.prefix()).is_empty()
        });
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if !self.prefix().exists() {
            return;
        }
        let _ = self.backend.stop(&self.env);
        let start = Instant::now();
        while !wineservers_for(&self.prefix()).is_empty() && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(100));
        }
        for pid in wineservers_for(&self.prefix()) {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
        }
        let start = Instant::now();
        while !wineservers_for(&self.prefix()).is_empty() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// Independent of `harden`: every symlink below `drive_c` (never followed while walking) that does not resolve
/// to a place inside `drive_c`, dangling ones included.
fn outward_links(drive_c: &Path) -> Vec<(PathBuf, PathBuf)> {
    fn walk(dir: &Path, real_root: &Path, out: &mut Vec<(PathBuf, PathBuf)>) {
        for e in fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let ft = fs::symlink_metadata(e.path()).unwrap().file_type();
            if ft.is_symlink() {
                match fs::canonicalize(e.path()) {
                    Ok(real) if real.starts_with(real_root) => {}
                    _ => out.push((e.path(), fs::read_link(e.path()).unwrap())),
                }
            } else if ft.is_dir() {
                walk(&e.path(), real_root, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(drive_c, &fs::canonicalize(drive_c).unwrap(), &mut out);
    out
}

fn dosdevices(prefix: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(prefix.join("dosdevices"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

const HELLO: &str = "hello from windows";

#[test]
#[ignore = "needs Wine and the mingw fixtures; run with --ignored --test-threads=1"]
fn e2e_prepare_hardens_and_both_fixtures_run() {
    let sb = Sandbox::new();

    // ---- prepare: a real prefix, hardened ----
    let started = Instant::now();
    sb.backend.prepare(&sb.env).expect("prepare");
    eprintln!("prepare took {:?}", started.elapsed());
    assert_eq!(
        dosdevices(&sb.prefix()),
        ["c:"],
        "right after prepare dosdevices holds only c:"
    );
    assert_eq!(
        fs::read_link(sb.prefix().join("dosdevices/c:")).unwrap(),
        Path::new("../drive_c")
    );
    assert_eq!(
        outward_links(&sb.env.drive_c()),
        vec![],
        "no link below drive_c may leave drive_c"
    );
    assert!(sb.prefix().join("system.reg").is_file());
    let users = sb.env.drive_c().join("users");
    assert!(
        users.is_dir(),
        "the profile directories exist (as real directories now)"
    );
    sb.assert_no_wineserver(); // prepare stops the server it started

    // ---- run both fixtures (32-bit runs in the win64 prefix through WoW64) ----
    let (exe64, dir) = sb.install("hello64.exe");
    let (exe32, _) = sb.install("hello32.exe");
    let (out, t64) = sb.run_captured(&exe64, &dir, &[]);
    eprintln!("hello64 first run took {t64:?}");
    assert_eq!(out.status.code(), Some(7), "hello64 exit code");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(HELLO),
        "hello64 stdout: {:?}",
        out.stdout
    );

    let (out, t32) = sb.run_captured(&exe32, &dir, &[]);
    eprintln!("hello32 (second run, reuses the prefix) took {t32:?}");
    assert_eq!(out.status.code(), Some(7), "hello32 exit code");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(HELLO),
        "hello32 stdout: {:?}",
        out.stdout
    );
    assert!(
        t32 < Duration::from_secs(15),
        "a second run must reuse the prefix, took {t32:?}"
    );

    // ---- the real launcher path: stderr to the 0600 log file, exit code through Running::wait ----
    let cmd = sb
        .backend
        .command(&sb.env, &exe64, &dir, &[], &RunOpts::default())
        .unwrap();
    let running = sb.launcher.spawn(cmd, &sb.env, LogSink::LogOnly).expect("spawn");
    let log = running.log_path().to_path_buf();
    assert_eq!(running.wait().unwrap().code(), Some(7));
    assert!(log.is_file());

    // ---- what Wine did to the prefix while running ----
    assert!(
        fs::symlink_metadata(sb.prefix().join("dosdevices/z:")).is_err(),
        "Wine does not recreate z:"
    );
    // Wine DOES recreate the com* links on every start (documented; not a failure): only c: and com* may exist.
    for name in dosdevices(&sb.prefix()) {
        assert!(
            name == "c:" || name.starts_with("com"),
            "unexpected dosdevices entry {name:?}"
        );
    }
    assert_eq!(
        outward_links(&sb.env.drive_c()),
        vec![],
        "a run must not bring the home links back"
    );

    // ---- prepare again on the existing prefix: idempotent, still hardened, still runs ----
    let started = Instant::now();
    sb.backend.prepare(&sb.env).expect("second prepare");
    eprintln!("second prepare took {:?}", started.elapsed());
    assert_eq!(dosdevices(&sb.prefix()), ["c:"]);
    assert_eq!(outward_links(&sb.env.drive_c()), vec![]);
    sb.assert_no_wineserver();
    let (out, _) = sb.run_captured(&exe64, &dir, &[]);
    assert_eq!(out.status.code(), Some(7));

    // ---- stop with nothing left to stop, and with a server running ----
    sb.backend.stop(&sb.env).expect("stop");
    sb.assert_no_wineserver();
    sb.backend.stop(&sb.env).expect("stop with no server is fine");
    assert!(sb.backend.version().unwrap().starts_with("wine-"));
}

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `SigIgn` of a process as a bit mask (bit n-1 = signal n).
fn ignored_signals(pid: u32) -> u64 {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let line = status.lines().find(|l| l.starts_with("SigIgn:")).unwrap();
    u64::from_str_radix(line["SigIgn:".len()..].trim(), 16).unwrap()
}

fn fd_target(pid: u32, fd: u32) -> String {
    fs::read_link(format!("/proc/{pid}/fd/{fd}")).map_or_else(|e| format!("<{e}>"), |p| p.display().to_string())
}

/// The SIGPIPE experiment (Task 4 review, item 4). The wineserver is STARTED by a debug-mode run (its stderr is
/// the tee socket of `Launcher::spawn`), a second process keeps it alive, the debug run ends (its tee reader is
/// joined and gone), and the server must survive that and still serve a later run.
#[test]
#[ignore = "needs Wine and the mingw fixtures; run with --ignored --test-threads=1"]
fn e2e_debug_run_survives_a_lingering_wineserver() {
    let sb = Sandbox::new();
    sb.backend.prepare(&sb.env).expect("prepare");
    sb.assert_no_wineserver();
    let (exe64, dir) = sb.install("hello64.exe");
    let cmd_exe = sb.env.drive_c().join("windows/system32/cmd.exe");
    let drive_c = sb.env.drive_c();
    let pause: Vec<OsString> = vec!["/c".into(), "pause".into()];

    // R: `cmd /c pause` in DEBUG mode (tee), stdin an open pipe so it stays alive. It starts the wineserver.
    let (r_stdin, r_keep) = io::pipe().unwrap();
    let mut r_cmd = sb
        .backend
        .command(&sb.env, &cmd_exe, &drive_c, &pause, &RunOpts { debug: true })
        .unwrap();
    r_cmd.stdin(Stdio::from(r_stdin));
    let tee = SharedBuf::default();
    let mut r = sb
        .launcher
        .spawn(r_cmd, &sb.env, LogSink::Tee(Box::new(tee.clone())))
        .expect("spawn R");
    wait_until("R to start a wineserver", Duration::from_secs(30), || {
        !wineservers_for(&sb.prefix()).is_empty()
    });
    let servers = wineservers_for(&sb.prefix());
    assert_eq!(servers.len(), 1, "{servers:?}");
    let server = servers[0];
    let (fd0, fd1, fd2) = (fd_target(server, 0), fd_target(server, 1), fd_target(server, 2));
    eprintln!("wineserver {server}: fd0={fd0} fd1={fd1} fd2={fd2}");

    // K: a second process that keeps the server alive after R is gone (not a debug run: log file only).
    let (k_stdin, k_keep) = io::pipe().unwrap();
    let mut k_cmd = sb
        .backend
        .command(&sb.env, &cmd_exe, &drive_c, &pause, &RunOpts::default())
        .unwrap();
    k_cmd.stdin(Stdio::from(k_stdin));
    let mut k = sb.launcher.spawn(k_cmd, &sb.env, LogSink::LogOnly).expect("spawn K");
    std::thread::sleep(Duration::from_secs(5)); // K has connected to the server by now

    // End R: EOF on its stdin. Wait for the process, then join its tee (this is what the run service does).
    drop(r_keep);
    wait_until("R to exit after EOF on stdin", Duration::from_secs(30), || {
        r.try_wait().unwrap().is_some()
    });
    let finished = r.wait_report().expect("wait R");
    eprintln!(
        "R exited: {:?}; tee bytes: {}",
        finished.status,
        tee.0.lock().unwrap().len()
    );
    assert!(!finished.terminal_write_failed && !finished.log_write_failed);

    // The tee reader is gone; the server outlives the linger timeout (~3 s) only because K uses the prefix.
    std::thread::sleep(Duration::from_secs(6));
    assert_eq!(
        wineservers_for(&sb.prefix()),
        [server],
        "the wineserver must survive the end of the debug run"
    );
    let ign = ignored_signals(server);
    eprintln!("wineserver SigIgn={ign:#x}; SIGPIPE ignored: {}", ign & (1 << 12) != 0);
    eprintln!("wineserver fd2 after R ended: {}", fd_target(server, 2));

    // A later run is served by the very same server.
    let (out, t) = sb.run_captured(&exe64, &dir, &[]);
    eprintln!("run after the debug run took {t:?}");
    assert_eq!(out.status.code(), Some(7));
    assert!(String::from_utf8_lossy(&out.stdout).contains(HELLO));
    assert_eq!(
        wineservers_for(&sb.prefix()),
        [server],
        "the same server served the later run"
    );

    // Let K finish, then everything must be stoppable.
    drop(k_keep);
    wait_until("K to exit after EOF on stdin", Duration::from_secs(30), || {
        k.try_wait().unwrap().is_some()
    });
    k.wait().unwrap();
    sb.backend.stop(&sb.env).expect("stop");
    sb.assert_no_wineserver();
}
