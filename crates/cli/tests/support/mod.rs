//! Shared real-Wine e2e test harness (extracted from `e2e_wine.rs`, Task 8): the [`Rig`] "no stray
//! wineserver" drop-guard, the `runtime` invocation helpers and the fixture lookup, used by both
//! `e2e_wine.rs` (Phase 2 behaviour) and `e2e_installers.rs` (Phase 3's installer pipeline). This is a
//! plain module file under `tests/support/`, not its own test binary (Cargo only turns a file directly
//! under `tests/` into one; a subdirectory like this one is never scanned on its own), included with
//! `mod support;` from each test's own crate root exactly the way a `src/` submodule would be.
//!
//! **Mechanical extraction, not a rewrite.** Every method here behaves exactly as it did inlined in
//! `e2e_wine.rs`; the only addition is [`Rig::xdg_data_home`], a scratch `XDG_DATA_HOME` for the
//! installer pipeline's `.desktop`/icon writes (Task 6/7), which `e2e_wine.rs`'s own tests never
//! exercise (they install plain `.exe`/`.zip` files, never a `.msi`/installer `.exe`) and so never call.
//!
//! This module is compiled once PER test binary that includes it (`e2e_wine.rs` and `e2e_installers.rs`
//! are separate crates, each with its own copy), and no single one of them uses every method here (e.g.
//! `e2e_installers.rs` never needs the persistent-`wineserver`-survives-`remove` dance, `e2e_wine.rs`
//! never needs the `XDG_DATA_HOME` scratch dir) — `dead_code` is allowed for exactly that reason, not to
//! hide a real unused-code smell.
#![allow(dead_code)]
use backend_wine::WineBackend;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The longest any single `runtime` invocation may take (a prefix is created in ~15-30 s; wineboot alone is
/// killed by the backend after 120 s).
pub const DEADLINE: Duration = Duration::from_secs(240);

pub fn fixture(name: &str) -> PathBuf {
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
pub struct Ran {
    pub cmdline: String,
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed: Duration,
}

impl Ran {
    pub fn out(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn err(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    pub fn report(&self) -> String {
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
    pub fn expect(&self, code: i32) -> String {
        assert_eq!(self.code, Some(code), "unexpected exit code: {}", self.report());
        self.out().trim().to_owned()
    }

    pub fn expect_ok(&self) -> String {
        self.expect(0)
    }
}

/// A temporary data directory, the way to run `runtime` against it, and the guard that leaves nothing behind.
pub struct Rig {
    root: tempfile::TempDir,
    data: PathBuf,
    /// The `wineserver` the CLI will find too (used only to start the persistent servers of `remove_app`).
    wineserver: PathBuf,
    calls: Cell<u32>,
    /// `server-<dev>-<ino>` directory names of every prefix seen (Wine names a server's directory that way).
    server_dirs: RefCell<HashSet<String>>,
}

impl Rig {
    pub fn new() -> Rig {
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

    /// The data directory (`RUNTIME_DATA_DIR` of every `runtime` this rig runs).
    pub fn data(&self) -> &Path {
        &self.data
    }

    pub fn apps(&self) -> PathBuf {
        self.data.join("apps")
    }

    pub fn drive_c(&self, id: &str) -> PathBuf {
        self.apps().join(id).join("prefix/drive_c")
    }

    /// A fresh, empty `XDG_DATA_HOME` scratch directory under this rig's own tempdir (mirrors
    /// `apps.rs`'s `plant_desktop_entry` convention): never the real one. Pass its `str` form as
    /// `("XDG_DATA_HOME", ...)` in `extra_env` to exactly the commands that read or write `.desktop`
    /// state (an installer-pipeline install, `remove`, `uninstall`) — never on every command, and
    /// never the process's own real `$XDG_DATA_HOME`.
    pub fn xdg_data_home(&self) -> PathBuf {
        let dir = self.root.path().join("xdg");
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Runs `runtime <args>` with the data dir of this rig (`extra_env` is set on that process only) and kills it
    /// after `deadline`. Returns what it did and whether the deadline was hit. Never panics for a bad exit.
    pub fn exec(&self, args: &[&str], extra_env: &[(&str, &str)], deadline: Duration) -> (Ran, bool) {
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

    pub fn rt_env(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Ran {
        let (ran, timed_out) = self.exec(args, extra_env, DEADLINE);
        assert!(!timed_out, "timed out after {DEADLINE:?}: {}", ran.report());
        ran
    }

    pub fn rt(&self, args: &[&str]) -> Ran {
        self.rt_env(args, &[])
    }

    /// `runtime install <fixture> --name <name>`; returns the app id (which is the slug of the name).
    pub fn install_fixture(&self, fixture_name: &str, name: &str) -> String {
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
    pub fn run_app(&self, id: &str, args: &[&str]) -> Ran {
        let mut v = vec!["run", id, "--"];
        v.extend_from_slice(args);
        self.rt(&v)
    }

    /// `runtime list --json` as parsed JSON (an array).
    pub fn list_json(&self) -> Vec<serde_json::Value> {
        let ran = self.rt(&["list", "--json"]);
        let text = ran.expect_ok();
        match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(serde_json::Value::Array(rows)) => rows,
            other => panic!("`list --json` is not a JSON array ({other:?}): {}", ran.report()),
        }
    }

    pub fn installed_ids(&self) -> Vec<String> {
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
    pub fn wineservers(&self) -> Vec<u32> {
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

    pub fn wait_for_no_wineserver(&self, limit: Duration) -> bool {
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
    pub fn start_persistent_server(&self, id: &str) {
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
    pub fn remove_app(&self, id: &str) {
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
    pub fn cleanup(&self) {
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

    /// The last step of every test: the apps were removed by the test (`remove_app`, or a plain `rt`
    /// call for `uninstall`/`remove` in the installer e2e tests), so no wineserver of the data dir may
    /// be left. This asserts FIRST; the guard's kill path only runs afterwards, to clean up.
    pub fn finish(&self) {
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

pub fn installed_id(ran: &Ran) -> String {
    ran.out()
        .lines()
        .find_map(|l| l.strip_prefix("Installed: "))
        .unwrap_or_else(|| panic!("no `Installed: <id>` line: {}", ran.report()))
        .trim()
        .to_owned()
}
