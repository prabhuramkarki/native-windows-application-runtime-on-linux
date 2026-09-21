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
//! Every test works in a temporary `RUNTIME_DATA_DIR` and owns a [`Rig`] whose `Drop` runs `runtime remove` for
//! every app left in it and then kills any `wineserver` that belongs to that data directory, so no Wine process
//! survives a test, even a failed one. Each test then asserts (polling up to 10 s) that none is left. Console
//! fixtures only: the GUI fixture `gui64.exe` (a modal message box) is never run here.
//!
//! What the tests do NOT claim: Wine's own `\\?\unix\...` NT paths still reach host files (Phase 2 is not a
//! sandbox, see `docs/SECURITY.md`), so there is deliberately no test asserting isolation from them.
//!
//! The CLI's stdout/stderr go to files, not pipes: the `wineserver` a run starts inherits stdout and would keep
//! a pipe open (and `Command::output` waiting) until it exits, seconds after the CLI has finished. Reading a
//! file after the CLI exited is the same observation without that wait, and lets every call have a deadline.
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
    calls: Cell<u32>,
    /// `server-<dev>-<ino>` directory names of every prefix seen (Wine names a server's directory that way).
    server_dirs: RefCell<HashSet<String>>,
}

impl Rig {
    fn new() -> Rig {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir(&data).unwrap();
        Rig {
            root,
            data,
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

    /// Runs `runtime <args>` with the data dir of this rig; `extra_env` is set on that process only.
    fn rt_env(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Ran {
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
            if started.elapsed() > DEADLINE {
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
        assert!(status.is_some(), "timed out after {DEADLINE:?}: {}", ran.report());
        self.remember_servers();
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
        let id = ran
            .out()
            .lines()
            .find_map(|l| l.strip_prefix("Installed: "))
            .unwrap_or_else(|| panic!("no `Installed: <id>` line: {}", ran.report()))
            .trim()
            .to_owned();
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

    /// The `wineserver` processes that belong to this data dir: recognised by `WINEPREFIX` in their environment
    /// (a prefix below the data dir) or by their working directory (Wine's `server-<dev>-<ino>` of a prefix that
    /// existed; the prefix itself may be gone by now).
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
                .and_then(|p| p.file_name().map(|n| n == "wineserver"))
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

    /// Best effort and never panics (it runs from `Drop`, possibly while unwinding): `runtime remove` for every
    /// app still in the data dir, then `kill -9` for any wineserver of this data dir that is still there.
    fn cleanup(&self) {
        self.remember_servers();
        for id in self.installed_ids() {
            let _ = Command::new(env!("CARGO_BIN_EXE_runtime"))
                .args(["remove", &id])
                .env("RUNTIME_DATA_DIR", &self.data)
                .env_remove("RUNTIME_WINE")
                .env_remove("RUNTIME_WINESERVER")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if !self.wait_for_no_wineserver(Duration::from_secs(5)) {
            for pid in self.wineservers() {
                let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
            }
            self.wait_for_no_wineserver(Duration::from_secs(5));
        }
    }

    /// The last step of every test: runs the guard now, then requires that no wineserver of this data dir is left.
    fn finish(&self) {
        self.cleanup();
        assert!(
            self.wait_for_no_wineserver(Duration::from_secs(10)),
            "a wineserver of {} is still running after cleanup: pids {:?}",
            self.data.display(),
            self.wineservers()
        );
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn dosdevices(prefix: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(prefix.join("dosdevices"))
        .unwrap_or_else(|e| panic!("cannot list {}/dosdevices: {e}", prefix.display()))
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
#[ignore = "needs Wine and fixtures; run with --ignored --test-threads=1"]
fn e2e_mvp_loop_install_list_run_logs_doctor_remove() {
    let rig = Rig::new();

    // install hello64.exe
    let hello64 = fixture("hello64.exe");
    let ran = rig.rt(&["install", hello64.to_str().unwrap()]);
    ran.expect_ok();
    eprintln!("install took {:?}", ran.elapsed);
    let id = ran
        .out()
        .lines()
        .find_map(|l| l.strip_prefix("Installed: "))
        .unwrap_or_else(|| panic!("no `Installed: <id>` line: {}", ran.report()))
        .trim()
        .to_owned();

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
    let hello32 = fixture("hello32.exe");
    let ran = rig.rt(&["run", hello32.to_str().unwrap()]);
    assert!(ran.out().contains(HELLO), "hello32 stdout: {}", ran.report());
    assert_eq!(ran.code, Some(7), "hello32 exit code: {}", ran.report());
    let rows = rig.list_json();
    assert_eq!(rows.len(), 2, "run-by-path installs one more app: {rows:#?}");
    assert!(
        rows.iter().any(|r| r["architecture"] == "x86"),
        "the second app should be 32-bit: {rows:#?}"
    );

    // logs <id>
    rig.rt(&["logs", &id]).expect_ok();

    // doctor <id>: exits 0 and never writes a raw terminal escape
    let ran = rig.rt(&["doctor", &id]);
    assert_eq!(ran.code, Some(0), "doctor: {}", ran.report());
    assert!(
        !ran.stdout.contains(&0x1b) && !ran.stderr.contains(&0x1b),
        "raw ESC byte in doctor output: {}",
        ran.report()
    );

    // remove every app: nothing is left
    let ids: Vec<String> = rig
        .list_json()
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_owned())
        .collect();
    for id in &ids {
        rig.rt(&["remove", id]).expect_ok();
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

    // Positive control: the probe works and sees the prefix's own C: drive.
    let ran = run(&["stat", "C:\\windows\\system32"]);
    assert_eq!(
        ran.expect_ok(),
        "EXISTS",
        "control: C:\\windows\\system32 must exist: {}",
        ran.report()
    );

    // No z: drive: the host root is not mapped as a drive letter.
    let ran = run(&["stat", "Z:\\etc\\hostname"]);
    assert_eq!(
        ran.expect(3),
        "MISSING",
        "Z:\\etc\\hostname must not be reachable through a drive letter: {}",
        ran.report()
    );

    // The environment allowlist works end to end: a host variable does not reach the Windows program.
    let ran = run(&["env", "RUNTIME_E2E_SECRET"]);
    assert_eq!(
        ran.expect_ok(),
        "UNSET",
        "a host variable leaked into the Windows program: {}",
        ran.report()
    );
    // Recorded, not asserted (see docs/SECURITY.md): HOME is on the allowlist, so the program learns it.
    let home = run(&["env", "HOME"]);
    eprintln!("RECORDED: `env HOME` inside the app prints {:?}", home.out().trim());
    home.expect_ok();
    let user = run(&["env", "USERNAME"]);
    let user = user.expect_ok();
    assert!(
        !user.is_empty() && user != "UNSET",
        "control: USERNAME must be set inside the app (got {user:?})"
    );
    eprintln!("RECORDED: `env USERNAME` inside the app prints {user:?}");

    // The working directory is inside the prefix's C: drive.
    let ran = run(&["cwd"]);
    let cwd = ran.expect_ok();
    assert!(
        cwd.to_ascii_uppercase().starts_with("C:\\"),
        "the working directory must be below C:\\, got {cwd:?}: {}",
        ran.report()
    );
    eprintln!("RECORDED: `cwd` inside the app prints {cwd:?}");

    // The home links are gone: Documents is a real, empty directory inside the prefix.
    let documents = format!("C:\\users\\{user}\\Documents");
    let ran = run(&["stat", &documents]);
    assert_eq!(ran.expect_ok(), "EXISTS", "{documents} should exist: {}", ran.report());
    let host_side = rig.drive_c(&alpha).join("users").join(&user).join("Documents");
    let meta = fs::symlink_metadata(&host_side)
        .unwrap_or_else(|e| panic!("{} should exist on the host: {e}", host_side.display()));
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

    // After all these runs the prefix still maps only C: (Wine recreates com* links on every start: known, allowed).
    let prefix = rig.apps().join(&alpha).join("prefix");
    for name in dosdevices(&prefix) {
        assert!(
            name == "c:" || name.starts_with("com"),
            "unexpected dosdevices entry {name:?} in {:?}",
            dosdevices(&prefix)
        );
    }
    assert!(
        fs::symlink_metadata(prefix.join("dosdevices/z:")).is_err(),
        "z: must not exist after runs"
    );

    rig.finish();
}
