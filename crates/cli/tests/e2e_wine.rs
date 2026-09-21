//! End-to-end tests of the REAL `runtime` binary against REAL Wine (system Wine 10.x): no `RUNTIME_WINE` or
//! `RUNTIME_WINESERVER` override, so `WineBackend::discover` runs exactly as it does for a user.
//!
//! **`#[ignore]`d**: they need Wine and the mingw fixtures (`tools/build-fixtures.sh`: `hello64.exe`,
//! `hello32.exe` and the isolation probe `fs64.exe`). Run them with
//!
//! ```text
//! cargo test -p runtime-cli --test e2e_wine -- --ignored --test-threads=1
//! ```
//!
//! Every test works in a temporary `RUNTIME_DATA_DIR` and owns a [`Rig`]. Each test removes its apps with
//! [`Rig::remove_app`], which first starts a PERSISTENT `wineserver -p` for the app (a server that never idles
//! out) and then requires that `runtime remove` alone got rid of it: a `remove` that does not stop the app's Wine
//! processes fails the test. Only after that assertion does the guard run: the `Drop` of the rig runs
//! `runtime remove` for any app left over and then `kill -9`s any `wineserver` of that data directory, so no Wine
//! process survives a failed test either. Console fixtures only: the GUI fixture `gui64.exe` (a modal message
//! box) is never run here.
//!
//! Wine older than 10 has no new WoW64 mode, so the 32-bit steps are skipped (loudly, with `SKIPPED 32-bit` on
//! stderr) there.
//!
//! What the tests do NOT claim: Wine's own `\\?\unix\...` NT paths still reach host files (Phase 2 is not a
//! sandbox, see `docs/SECURITY.md`), so there is deliberately no test asserting isolation from them.
//!
//! The CLI's stdout/stderr go to files, not pipes: the `wineserver` a run starts inherits stdout and would keep
//! a pipe open (and `Command::output` waiting) until it exits, seconds after the CLI has finished. Reading a
//! file after the CLI exited is the same observation without that wait, and lets every call have a deadline.
use backend_wine::WineBackend;
use rt_core::CompatBackend;
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const HELLO: &str = "hello from windows";
/// The longest any single `runtime` invocation may take (a prefix is created in ~15-30 s; wineboot alone is
/// killed by the backend after 120 s).
const DEADLINE: Duration = Duration::from_secs(240);

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

/// `Some(version text)` when the installed Wine is older than 10 and so cannot run 32-bit programs in a 64-bit
/// prefix (no new WoW64); the caller skips its 32-bit steps and says so. Unknown versions are not skipped.
/// Wine is found exactly as the CLI rig lets the CLI find it: the same search over the same environment, with
/// `RUNTIME_WINE` and `RUNTIME_WINESERVER` removed (see [`Rig::exec`]), so this decision cannot disagree with the
/// Wine the CLI runs.
fn wine_without_wow64() -> Option<String> {
    let env = |k: &str| match k {
        "RUNTIME_WINE" | "RUNTIME_WINESERVER" => None,
        _ => std::env::var_os(k),
    };
    let found = backend_wine::discover::discover(
        &env,
        &backend_wine::discover::is_executable_file,
        &backend_wine::discover::is_dir,
        &backend_wine::discover::canonicalize,
    )
    .ok()?;
    let version = WineBackend::from_found(found, rt_core::Launcher::new())
        .version()
        .ok()?;
    let major: u32 = version.strip_prefix("wine-")?.split('.').next()?.parse().ok()?;
    (major < 10).then_some(version)
}

/// What one `runtime` invocation did.
struct Ran {
    cmdline: String,
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    elapsed: Duration,
}

impl Ran {
    fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    fn report(&self) -> String {
        format!(
            "`{}` exited with {:?} after {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.cmdline,
            self.code,
            self.elapsed,
            self.out(),
            self.err()
        )
    }

    /// Asserts the exit code and returns stdout with surrounding whitespace removed (Windows console programs
    /// may end lines with CR LF).
    fn expect(&self, code: i32) -> String {
        assert_eq!(self.code, Some(code), "unexpected exit code: {}", self.report());
        self.out().trim().to_owned()
    }

    fn expect_ok(&self) -> String {
        self.expect(0)
    }
}

/// A temporary data directory, the way to run `runtime` against it, and the guard that leaves nothing behind.
struct Rig {
    root: tempfile::TempDir,
    data: PathBuf,
    /// The `wineserver` the CLI will find too (used only to start the persistent servers of `remove_app`).
    wineserver: PathBuf,
    calls: Cell<u32>,
    /// `server-<dev>-<ino>` directory names of every prefix seen (Wine names a server's directory that way).
    server_dirs: RefCell<HashSet<String>>,
}

impl Rig {
    fn new() -> Rig {
        let backend = WineBackend::discover().expect("Wine must be installed for the e2e tests (apt install wine)");
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir(&data).unwrap();
        Rig {
            root,
            data,
            wineserver: backend.wineserver_path().to_path_buf(),
            calls: Cell::new(0),
            server_dirs: RefCell::default(),
        }
    }

    fn apps(&self) -> PathBuf {
        self.data.join("apps")
    }

    fn drive_c(&self, id: &str) -> PathBuf {
        self.apps().join(id).join("prefix/drive_c")
    }

    /// Runs `runtime <args>` with the data dir of this rig (`extra_env` is set on that process only) and kills it
    /// after `deadline`. Returns what it did and whether the deadline was hit. Never panics for a bad exit.
    fn exec(&self, args: &[&str], extra_env: &[(&str, &str)], deadline: Duration) -> (Ran, bool) {
        let n = self.calls.get() + 1;
        self.calls.set(n);
        let (out_path, err_path) = (
            self.root.path().join(format!("stdout-{n}")),
            self.root.path().join(format!("stderr-{n}")),
        );
        let cmdline = format!("runtime {}", args.join(" "));
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_runtime"));
        cmd.args(args)
            .env("RUNTIME_DATA_DIR", &self.data)
            .env_remove("RUNTIME_WINE")
            .env_remove("RUNTIME_WINESERVER")
            .stdin(Stdio::null())
            .stdout(File::create(&out_path).unwrap())
            .stderr(File::create(&err_path).unwrap());
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let started = Instant::now();
        let mut child = cmd.spawn().unwrap_or_else(|e| panic!("cannot start {cmdline}: {e}"));
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if started.elapsed() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let ran = Ran {
            cmdline,
            code: status.and_then(|s| s.code()),
            stdout: fs::read(&out_path).unwrap_or_default(),
            stderr: fs::read(&err_path).unwrap_or_default(),
            elapsed: started.elapsed(),
        };
        self.remember_servers();
        (ran, status.is_none())
    }

    fn rt_env(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Ran {
        let (ran, timed_out) = self.exec(args, extra_env, DEADLINE);
        assert!(!timed_out, "timed out after {DEADLINE:?}: {}", ran.report());
        ran
    }

    fn rt(&self, args: &[&str]) -> Ran {
        self.rt_env(args, &[])
    }

    /// `runtime install <fixture> --name <name>`; returns the app id (which is the slug of the name).
    fn install_fixture(&self, fixture_name: &str, name: &str) -> String {
        let path = fixture(fixture_name);
        let ran = self.rt(&["install", path.to_str().unwrap(), "--name", name]);
        ran.expect_ok();
        let id = installed_id(&ran);
        assert!(
            self.apps().join(&id).is_dir(),
            "app {id} is not under the data dir: {}",
            ran.report()
        );
        id
    }

    /// `runtime run <id> -- <args>`.
    fn run_app(&self, id: &str, args: &[&str]) -> Ran {
        let mut v = vec!["run", id, "--"];
        v.extend_from_slice(args);
        self.rt(&v)
    }

    /// `runtime list --json` as parsed JSON (an array).
    fn list_json(&self) -> Vec<Value> {
        let ran = self.rt(&["list", "--json"]);
        let text = ran.expect_ok();
        match serde_json::from_str::<Value>(&text) {
            Ok(Value::Array(rows)) => rows,
            other => panic!("`list --json` is not a JSON array ({other:?}): {}", ran.report()),
        }
    }

    fn installed_ids(&self) -> Vec<String> {
        match fs::read_dir(self.apps()) {
            Ok(rd) => rd.flatten().filter_map(|e| e.file_name().into_string().ok()).collect(),
            Err(_) => vec![],
        }
    }

    fn remember_servers(&self) {
        for id in self.installed_ids() {
            if let Ok(m) = fs::metadata(self.apps().join(&id).join("prefix")) {
                self.server_dirs
                    .borrow_mut()
                    .insert(format!("server-{:x}-{:x}", m.dev(), m.ino()));
            }
        }
    }

    /// The `wineserver` processes that belong to this data dir (the executable's name starts with `wineserver`:
    /// `wineserver64` on Ubuntu's Wine 9): recognised by `WINEPREFIX` in their environment (a prefix below the
    /// data dir) or by their working directory (Wine's `server-<dev>-<ino>` of a prefix that existed; the prefix
    /// itself may be gone by now).
    fn wineservers(&self) -> Vec<u32> {
        let mut roots = vec![self.data.clone()];
        roots.extend(fs::canonicalize(&self.data));
        let wanted: Vec<Vec<u8>> = roots
            .iter()
            .map(|r| format!("WINEPREFIX={}/", r.display()).into_bytes())
            .collect();
        let dirs = self.server_dirs.borrow();
        let mut found = Vec::new();
        for entry in fs::read_dir("/proc").into_iter().flatten().flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            let proc = entry.path();
            let is_wineserver = fs::read_link(proc.join("exe"))
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().starts_with("wineserver")))
                == Some(true);
            if !is_wineserver {
                continue;
            }
            let by_cwd = fs::read_link(proc.join("cwd"))
                .ok()
                .and_then(|p| p.file_name().map(|n| dirs.contains(&*n.to_string_lossy())))
                == Some(true);
            let by_env = fs::read(proc.join("environ"))
                .is_ok_and(|e| e.split(|b| *b == 0).any(|v| wanted.iter().any(|w| v.starts_with(w))));
            if by_cwd || by_env {
                found.push(pid);
            }
        }
        found
    }

    fn wait_for_no_wineserver(&self, limit: Duration) -> bool {
        let start = Instant::now();
        while !self.wineservers().is_empty() {
            if start.elapsed() > limit {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        true
    }

    /// Starts `wineserver -p` (persistent: it does NOT exit when idle, unlike the ~3 s linger of a normal one) for
    /// the app's prefix, and checks that this test's detector sees it.
    fn start_persistent_server(&self, id: &str) {
        let prefix = self.apps().join(id).join("prefix");
        // A normal server lingers ~3 s after the last run and `wineserver -p` fails (exit 2) while one runs.
        assert!(
            self.wait_for_no_wineserver(Duration::from_secs(15)),
            "a lingering wineserver of {} did not exit before the persistent one was started",
            self.data.display()
        );
        let status = Command::new(&self.wineserver)
            .arg("-p")
            .env("WINEPREFIX", &prefix)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap_or_else(|e| panic!("cannot start {} -p: {e}", self.wineserver.display()));
        assert!(
            status.success(),
            "`wineserver -p` failed for {}: {status:?}",
            prefix.display()
        );
        self.remember_servers();
        let start = Instant::now();
        while self.wineservers().is_empty() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "control failed: the persistent wineserver of {} is not seen by the leak detector",
                prefix.display()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `runtime remove <id>` while a persistent wineserver runs for the app. `remove` must stop it by itself:
    /// the wait below happens BEFORE any guard can kill anything.
    fn remove_app(&self, id: &str) {
        self.start_persistent_server(id);
        let ran = self.rt(&["remove", id]);
        ran.expect_ok();
        assert!(
            self.wait_for_no_wineserver(Duration::from_secs(10)),
            "`runtime remove {id}` returned but a wineserver of {} is still running (pids {:?}): remove must \
             stop the app's Wine processes\n{}",
            self.data.display(),
            self.wineservers(),
            ran.report()
        );
        assert!(
            !self.apps().join(id).exists(),
            "app dir {id} still exists after remove: {}",
            ran.report()
        );
    }

    /// Best effort and never panics (it runs from `Drop`, possibly while unwinding): `runtime remove` (60 s
    /// deadline each) for every app still in the data dir, then `kill -9` for any wineserver of this data dir
    /// that is still there.
    fn cleanup(&self) {
        self.remember_servers();
        for id in self.installed_ids() {
            let _ = self.exec(&["remove", &id], &[], Duration::from_secs(60));
        }
        if !self.wait_for_no_wineserver(Duration::from_secs(5)) {
            for pid in self.wineservers() {
                let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            }
            self.wait_for_no_wineserver(Duration::from_secs(5));
        }
    }

    /// The last step of every test: the apps were removed by the test (`remove_app`), so no wineserver of the
    /// data dir may be left. This asserts FIRST; the guard's kill path only runs afterwards, to clean up.
    fn finish(&self) {
        let stopped = self.wait_for_no_wineserver(Duration::from_secs(10));
        let left = self.wineservers();
        let apps_left = self.installed_ids();
        self.cleanup();
        assert!(
            stopped,
            "a wineserver of {} was still running after the test removed its apps: pids {left:?}",
            self.data.display()
        );
        assert!(
            apps_left.is_empty(),
            "apps left in the data dir at the end of the test: {apps_left:?}"
        );
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn installed_id(ran: &Ran) -> String {
    ran.out()
        .lines()
        .find_map(|l| l.strip_prefix("Installed: "))
        .unwrap_or_else(|| panic!("no `Installed: <id>` line: {}", ran.report()))
        .trim()
        .to_owned()
}

fn dosdevices(prefix: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(prefix.join("dosdevices"))
        .unwrap_or_else(|e| panic!("cannot list {}/dosdevices: {e}", prefix.display()))
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Every symlink below `drive_c` (never followed while walking) that does not resolve to a place inside
/// `drive_c`, dangling ones included.
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

#[test]
#[ignore = "needs Wine and fixtures; run with --ignored --test-threads=1"]
fn e2e_mvp_loop_install_list_run_logs_doctor_remove() {
    let rig = Rig::new();
    let skip32 = wine_without_wow64();

    // install hello64.exe
    let hello64 = fixture("hello64.exe");
    let ran = rig.rt(&["install", hello64.to_str().unwrap()]);
    ran.expect_ok();
    eprintln!("install took {:?}", ran.elapsed);
    let id = installed_id(&ran);

    // list --json: one app with the expected fields
    let rows = rig.list_json();
    assert_eq!(rows.len(), 1, "expected exactly one app, got {rows:#?}");
    let app = &rows[0];
    assert_eq!(app["id"], id.as_str(), "{app:#}");
    assert!(app["name"].as_str().is_some_and(|n| !n.is_empty()), "name: {app:#}");
    assert_eq!(app["architecture"], "x86_64", "{app:#}");
    let exe = app["executable"].as_str().unwrap_or_default();
    assert!(
        exe.starts_with("C:\\Program Files\\") && exe.to_ascii_lowercase().ends_with("\\hello64.exe"),
        "executable should be a C:\\Program Files\\...\\hello64.exe path: {app:#}"
    );
    assert!(
        app["created"].as_u64().is_some_and(|t| t > 1_600_000_000),
        "created: {app:#}"
    );
    assert!(
        app.get("version").is_some(),
        "the version field must exist (null is fine): {app:#}"
    );

    // run <id>: stdout and the exit code of the Windows program
    let ran = rig.rt(&["run", &id]);
    assert!(ran.out().contains(HELLO), "hello64 stdout: {}", ran.report());
    assert_eq!(ran.code, Some(7), "hello64 exit code: {}", ran.report());

    // run <path to hello32.exe>: installs a second app (32-bit, WoW64) and runs it
    let mut expected_apps = 1;
    if let Some(version) = &skip32 {
        eprintln!("SKIPPED 32-bit: needs Wine >= 10 (found {version})");
    } else {
        let hello32 = fixture("hello32.exe");
        let ran = rig.rt(&["run", hello32.to_str().unwrap()]);
        assert!(ran.out().contains(HELLO), "hello32 stdout: {}", ran.report());
        assert_eq!(ran.code, Some(7), "hello32 exit code: {}", ran.report());
        expected_apps = 2;
        let rows = rig.list_json();
        assert_eq!(rows.len(), 2, "run-by-path installs one more app: {rows:#?}");
        assert!(
            rows.iter().any(|r| r["architecture"] == "x86"),
            "the second app should be 32-bit: {rows:#?}"
        );
    }

    // logs <id>: a debug run puts Wine's stderr into the log; `logs` shows only what is in a log file, and never
    // a raw escape byte
    let ran = rig.rt(&["run", &id, "--debug"]);
    assert!(ran.out().contains(HELLO), "hello64 --debug stdout: {}", ran.report());
    assert_eq!(ran.code, Some(7), "hello64 --debug exit code: {}", ran.report());
    let logs_dir = rig.apps().join(&id).join("logs");
    let log_files: Vec<PathBuf> = fs::read_dir(&logs_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .collect();
    assert!(
        log_files.len() >= 2,
        "one log per run expected in {}: {log_files:?}",
        logs_dir.display()
    );
    let all_logs: String = log_files
        .iter()
        .map(|p| String::from_utf8_lossy(&fs::read(p).unwrap()).into_owned())
        .collect();
    let ran = rig.rt(&["logs", &id]);
    let shown = ran.expect_ok();
    assert!(
        !ran.stdout.contains(&0x1b) && !ran.stderr.contains(&0x1b),
        "raw ESC in `logs` output: {}",
        ran.report()
    );
    for line in shown.lines() {
        assert!(
            all_logs.contains(line.trim_end()),
            "`logs` printed a line that is in no log file of the app: {line:?}\n{}",
            ran.report()
        );
    }
    eprintln!("`logs` printed {} line(s)", shown.lines().count());

    // doctor <id>: exits 0 and never writes a raw terminal escape
    let ran = rig.rt(&["doctor", &id]);
    assert_eq!(ran.code, Some(0), "doctor: {}", ran.report());
    assert!(
        !ran.stdout.contains(&0x1b) && !ran.stderr.contains(&0x1b),
        "raw ESC byte in doctor output: {}",
        ran.report()
    );

    // remove every app (each with a persistent wineserver that only `remove` can stop): nothing is left
    let ids: Vec<String> = rig
        .list_json()
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), expected_apps, "{ids:?}");
    for id in &ids {
        rig.remove_app(id);
    }
    assert!(
        rig.installed_ids().is_empty(),
        "apps left in the data dir after remove: {:?}",
        rig.installed_ids()
    );
    assert_eq!(rig.list_json().len(), 0, "list --json after remove");
    let ran = rig.rt(&["list"]);
    assert!(ran.expect_ok().contains("No apps installed"), "list: {}", ran.report());

    rig.finish();
}

#[test]
#[ignore = "needs Wine and fixtures; run with --ignored --test-threads=1"]
fn e2e_a_second_app_cannot_see_the_first_apps_files() {
    let rig = Rig::new();
    let alpha = rig.install_fixture("fs64.exe", "alpha");
    let beta = rig.install_fixture("fs64.exe", "beta");
    assert_ne!(alpha, beta);
    assert_eq!(rig.list_json().len(), 2);

    // alpha writes a file and reads it back
    let ran = rig.run_app(&alpha, &["write", "SECRET-A"]);
    ran.expect_ok();
    let ran = rig.run_app(&alpha, &["read"]);
    assert_eq!(ran.expect_ok(), "SECRET-A", "{}", ran.report());
    // These are runs of an app whose prefix exists: no prefix creation, so they are quick.
    eprintln!("alpha read (a later run) took {:?}", ran.elapsed);
    assert!(
        ran.elapsed < Duration::from_secs(15),
        "a later run must reuse the prefix: {}",
        ran.report()
    );

    // beta, another prefix, does not have it
    let ran = rig.run_app(&beta, &["read"]);
    assert_eq!(
        ran.expect(3),
        "MISSING",
        "beta must not see alpha's file: {}",
        ran.report()
    );

    // The same observation from the host side.
    assert_eq!(
        fs::read_to_string(rig.drive_c(&alpha).join("runtime-test.txt")).unwrap_or_default(),
        "SECRET-A",
        "alpha's file is in alpha's drive_c"
    );
    assert!(
        !rig.drive_c(&beta).join("runtime-test.txt").exists(),
        "beta's drive_c must not contain the file"
    );

    for id in [&alpha, &beta] {
        rig.remove_app(id);
    }
    rig.finish();
}

#[test]
#[ignore = "needs Wine and fixtures; run with --ignored --test-threads=1"]
fn e2e_hardening_is_visible_from_inside_the_app() {
    let rig = Rig::new();
    let alpha = rig.install_fixture("fs64.exe", "alpha");
    let secret = [("RUNTIME_E2E_SECRET", "leak")];
    let run = |args: &[&str]| {
        let mut v = vec!["run", alpha.as_str(), "--"];
        v.extend_from_slice(args);
        rig.rt_env(&v, &secret)
    };
    let env_of = |name: &str| run(&["env", name]).expect_ok();

    // Positive control: the probe works and sees the prefix's own C: drive.
    let ran = run(&["stat", "C:\\windows\\system32"]);
    assert_eq!(
        ran.expect_ok(),
        "EXISTS",
        "control: C:\\windows\\system32 must exist: {}",
        ran.report()
    );

    // No z: drive: the host root is not mapped as a drive letter. (Control: the host file exists, so MISSING
    // means "not reachable", not "not there".)
    assert!(
        Path::new("/etc/hostname").exists(),
        "control: this test needs /etc/hostname on the host"
    );
    let ran = run(&["stat", "Z:\\etc\\hostname"]);
    assert_eq!(
        ran.expect(3),
        "MISSING",
        "Z:\\etc\\hostname must not be reachable through a drive letter: {}",
        ran.report()
    );

    // The environment allowlist works end to end: a host variable does not reach the Windows program.
    assert_eq!(
        env_of("RUNTIME_E2E_SECRET"),
        "UNSET",
        "a host variable leaked into the Windows program"
    );

    // HOME: the program does not see the host's real home. `HOME` itself is not shown by Wine's Windows
    // environment, but Wine exports the home it was started with as WINEHOMEDIR (`\??\unix<path>`): that must be
    // the app's own directory, never the host's.
    eprintln!("RECORDED: `env HOME` inside the app prints {:?}", env_of("HOME"));
    let app_home = rig.apps().join(&alpha).join("runtime/home");
    let winehomedir = env_of("WINEHOMEDIR");
    eprintln!("RECORDED: `env WINEHOMEDIR` inside the app prints {winehomedir:?}");
    let unix_path = winehomedir
        .strip_prefix("\\??\\unix")
        .unwrap_or_else(|| panic!("WINEHOMEDIR is not a `\\??\\unix...` path: {winehomedir:?}"))
        .replace('\\', "/");
    assert_eq!(
        fs::canonicalize(&unix_path).unwrap_or_else(|e| panic!("WINEHOMEDIR {unix_path:?} does not exist: {e}")),
        fs::canonicalize(&app_home).unwrap(),
        "WINEHOMEDIR must be the app's own home directory"
    );
    let userprofile = env_of("USERPROFILE");
    eprintln!("RECORDED: `env USERPROFILE` inside the app prints {userprofile:?}");
    let host_home = std::env::var("HOME").unwrap_or_default();
    if host_home.len() > 1 && !app_home.starts_with(&host_home) {
        for (name, value) in [("WINEHOMEDIR", &winehomedir), ("USERPROFILE", &userprofile)] {
            assert!(
                !value.replace('\\', "/").contains(&host_home),
                "{name} = {value:?} contains the host home {host_home:?}"
            );
        }
    } else {
        eprintln!(
            "NOTE: the host HOME {host_home:?} is a prefix of the data dir (or too short to check): the \
             `does not contain the host home` assertion is skipped, the equality above still holds"
        );
    }
    assert!(app_home.is_dir(), "{} must exist", app_home.display());

    // What the program can learn about the user and the machine (recorded for docs/SECURITY.md).
    let user = env_of("USERNAME");
    assert!(
        !user.is_empty() && user != "UNSET",
        "control: USERNAME must be set inside the app (got {user:?})"
    );
    eprintln!("RECORDED: `env USERNAME` inside the app prints {user:?}");
    eprintln!(
        "RECORDED: `env WINEUSERNAME` inside the app prints {:?}",
        env_of("WINEUSERNAME")
    );
    eprintln!(
        "RECORDED: `env COMPUTERNAME` inside the app prints {:?}",
        env_of("COMPUTERNAME")
    );

    // The working directory is inside the prefix's C: drive.
    let ran = run(&["cwd"]);
    let cwd = ran.expect_ok();
    assert!(
        cwd.to_ascii_uppercase().starts_with("C:\\"),
        "the working directory must be below C:\\, got {cwd:?}: {}",
        ran.report()
    );
    eprintln!("RECORDED: `cwd` inside the app prints {cwd:?}");

    // The home links are gone: Documents (or `My Documents`) is a real, empty directory inside the prefix.
    let profile = rig.drive_c(&alpha).join("users").join(&user);
    let present: Vec<&str> = ["Documents", "My Documents"]
        .into_iter()
        .filter(|d| fs::symlink_metadata(profile.join(d)).is_ok())
        .collect();
    assert!(
        !present.is_empty(),
        "neither Documents nor My Documents exists in {}: {:?}",
        profile.display(),
        fs::read_dir(&profile).map(|rd| rd.flatten().map(|e| e.file_name()).collect::<Vec<_>>())
    );
    eprintln!("RECORDED: the profile has {present:?}");
    for name in &present {
        let host_side = profile.join(name);
        let meta = fs::symlink_metadata(&host_side).unwrap();
        assert!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "{} must be a real directory, not a link into the real home",
            host_side.display()
        );
        assert_eq!(
            fs::read_dir(&host_side).unwrap().count(),
            0,
            "{} must be empty",
            host_side.display()
        );
        let documents = format!("C:\\users\\{user}\\{name}");
        let ran = run(&["stat", &documents]);
        assert_eq!(ran.expect_ok(), "EXISTS", "{documents} should exist: {}", ran.report());
    }

    // After all these runs the prefix still maps C: (and only C: plus Wine's own com* links), has no z:, and no
    // symlink below drive_c leaves it: with the app's own HOME Wine creates no home links at all.
    let prefix = rig.apps().join(&alpha).join("prefix");
    let devices = dosdevices(&prefix);
    assert!(devices.iter().any(|d| d == "c:"), "c: must be mapped: {devices:?}");
    for name in &devices {
        assert!(
            name == "c:" || name.starts_with("com"),
            "unexpected dosdevices entry {name:?} in {devices:?}"
        );
    }
    assert!(
        fs::symlink_metadata(prefix.join("dosdevices/z:")).is_err(),
        "z: must not exist after runs"
    );
    assert_eq!(
        outward_links(&rig.drive_c(&alpha)),
        vec![],
        "no link below drive_c may leave drive_c"
    );

    rig.remove_app(&alpha);
    rig.finish();
}
