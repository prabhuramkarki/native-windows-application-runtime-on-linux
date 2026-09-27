//! The `runtimed` end-to-end rig, shared by the daemon's `e2e_jobs.rs` and the GUI's `e2e.rs` (through `#[path]`):
//! a scratch HOME, data dir and `XDG_RUNTIME_DIR` (never the user's) with a copy of the `runtimed` under test and a
//! fake or real `runtime` next to it (the production sibling mechanism), the fake `runtime` and fake Wine scripts.
#![allow(dead_code)] // each test crate uses part of it

use rt_daemon::client::Client;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// The fake `runtime` of A: answers `--version`, else records its argv (NUL separated) and pid keyed by its last
/// argument, then acts on `$RUNTIME_DATA_DIR/fake/mode.<key>` (default: print one line).
pub const FAKE_RUNTIME: &str = r#"#!/bin/sh
[ "$1" = --version ] && { echo "runtime @VERSION@"; exit 0; }
F="$RUNTIME_DATA_DIR/fake"
for a in "$@"; do last="$a"; done
key=$(printf %s "$last" | tr -c 'a-z0-9.-' _)
printf '%s\0' "$@" > "$F/argv.$key"
echo $$ > "$F/pid.$key"
pwd > "$F/cwd.$key"
case "$(cat "$F/mode.$key" 2>/dev/null)" in
  wait) echo ready; sleep 60 ;;
  pdeath) trap 'echo term > "$F/pdeath.$key"; exit 0' TERM; echo ready; while :; do sleep 0.05; done ;;
  *) echo done ;;
esac
"#;

/// The CLI rig's fake Wine (`crates/cli/tests/apps.rs`), trimmed: `wineboot` makes a minimal prefix, anything else
/// is "the app", which prints a line.
pub const FAKE_WINE: &str = r#"#!/bin/sh
case "$1" in
  --version) echo 'wine-10.0 (Fake 1)' ;;
  wineboot)
    P="$WINEPREFIX"
    mkdir -p "$P/dosdevices" "$P/drive_c/Program Files" "$P/drive_c/users/tester/AppData/Roaming/Microsoft/Windows" "$P/drive_c/windows"
    ln -s ../drive_c "$P/dosdevices/c:"
    : > "$P/system.reg" ;;
  *reg.exe)
    case "$2" in
      add) printf 'WINE REGISTRY Version 2\n\n[Software\\\\Wine\\\\Drivers] 1\n"Graphics"="%s"\n\n' "$7" > "$WINEPREFIX/user.reg" ;;
      delete) rm -f "$WINEPREFIX/user.reg" ;;
    esac ;;
  *) echo "app-stdout" ;;
esac
"#;

pub fn fixture(name: &str) -> PathBuf {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    assert!(p.exists(), "missing fixture {name}: run tools/build-fixtures.sh");
    p
}

/// Writes (or copies) an executable, then waits until it can be executed: another test thread may have forked while
/// it was open for writing, and that child holds the write fd until its exec (ETXTBSY meanwhile).
pub fn install_exe(dst: &Path, from: Result<&Path, &str>) {
    match from {
        Ok(src) => {
            fs::copy(src, dst).unwrap();
        }
        Err(body) => fs::write(dst, body).unwrap(),
    }
    fs::set_permissions(dst, fs::Permissions::from_mode(0o755)).unwrap();
    for _ in 0..500 {
        match Command::new(dst)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => thread::sleep(Duration::from_millis(4)),
            _ => break,
        }
    }
}

pub struct Scratch {
    _t: tempfile::TempDir,
    pub root: PathBuf,
    pub bin: PathBuf,
    pub xdg: PathBuf,
    pub data: PathBuf,
    pub home: PathBuf,
}

impl Scratch {
    /// A scratch with a copy of `daemon` (the `runtimed` under test) and, next to it, `runtime`: `Err(script)` for a
    /// fake, `Ok(path)` to copy a real binary.
    pub fn new(daemon: &Path, runtime: Result<&Path, &str>) -> Scratch {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().canonicalize().unwrap();
        let (bin, xdg, data, home) = (root.join("bin"), root.join("xdg"), root.join("data"), root.join("home"));
        for d in [&bin, &xdg, &data.join("fake"), &home] {
            fs::create_dir_all(d).unwrap();
        }
        fs::set_permissions(&xdg, fs::Permissions::from_mode(0o700)).unwrap();
        // A umask of 002 would leave it group-writable, which `runtimed --write` refuses (with a chmod hint).
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        install_exe(&bin.join("runtimed"), Ok(daemon));
        install_exe(&bin.join("runtime"), runtime);
        Scratch {
            _t: t,
            root,
            bin,
            xdg,
            data,
            home,
        }
    }

    pub fn sock(&self) -> PathBuf {
        self.xdg.join("runtime/runtimed.sock")
    }

    pub fn cmd(&self, extra: &[(&str, &Path)]) -> Command {
        let mut c = Command::new(self.bin.join("runtimed"));
        c.env_clear()
            .env("HOME", &self.home)
            .env("PATH", format!("{}:/usr/bin:/bin", self.root.join("fakes").display()))
            .env("RUNTIME_DATA_DIR", &self.data)
            .env("XDG_RUNTIME_DIR", &self.xdg)
            .env("SECRET", "hunter2")
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        for (k, v) in extra {
            c.env(k, v);
        }
        c
    }

    /// `runtimed --write` on the default-style socket, up and serving; its stderr goes to `daemon.log`.
    pub fn daemon(&self, extra: &[(&str, &Path)]) -> Daemon {
        self.start(true, extra)
    }

    /// `runtimed` (with `--write` if `write`) on the default-style socket, up and serving.
    pub fn start(&self, write: bool, extra: &[(&str, &Path)]) -> Daemon {
        let log = fs::File::create(self.root.join("daemon.log")).unwrap();
        let child = self
            .cmd(extra)
            .args(write.then_some("--write"))
            .arg("--socket")
            .arg(self.sock())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut d = Daemon(child);
        let until = Instant::now() + Duration::from_secs(10);
        while fs::symlink_metadata(self.sock()).map(|m| m.mode() & 0o777).ok() != Some(0o600) {
            if let Some(st) = d.0.try_wait().unwrap() {
                panic!("runtimed exited early ({st}): {}", self.log());
            }
            assert!(Instant::now() < until, "no socket: {}", self.log());
            thread::sleep(Duration::from_millis(10));
        }
        d
    }

    pub fn log(&self) -> String {
        fs::read_to_string(self.root.join("daemon.log")).unwrap_or_default()
    }

    pub fn client(&self) -> Client {
        Client::connect(&self.sock()).unwrap()
    }

    pub fn fake(&self, what: &str, key: &str) -> String {
        fs::read_to_string(self.data.join(format!("fake/{what}.{key}"))).unwrap_or_default()
    }

    pub fn mode(&self, key: &str, m: &str) {
        fs::write(self.data.join(format!("fake/mode.{key}")), m).unwrap();
    }

    /// Installs app `id` named `name` straight into the scratch data dir (no job: for a fake `runtime`).
    pub fn plant(&self, id: &str, name: &str) {
        use rt_core::{AppId, BackendInfo, Metadata, Store, WinPath};
        let store = Store::new(self.data.join("apps")).unwrap();
        let id = AppId::parse(id).unwrap();
        let env = store.create(&id).unwrap();
        let exe = WinPath::parse(r"C:\app\a.exe").unwrap();
        let backend = BackendInfo {
            id: "wine".into(),
            version: "10.0".into(),
        };
        let md = Metadata::new(id, name.into(), None, "x86_64", &exe, backend, "gui");
        store.write_metadata(&env, &md).unwrap();
    }
}

pub struct Daemon(pub Child);

impl Daemon {
    pub fn signal(&self, sig: i32) {
        // SAFETY: a signal to our own child, not reaped yet.
        unsafe { libc::kill(self.0.id() as libc::pid_t, sig) };
    }

    pub fn wait(&mut self, within: Duration) -> std::process::ExitStatus {
        let until = Instant::now() + within;
        loop {
            if let Some(st) = self.0.try_wait().unwrap() {
                return st;
            }
            assert!(Instant::now() < until, "runtimed did not exit");
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

pub fn alive(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
        && !fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| s.contains(") Z "))
}

/// The real `runtime` built next to `daemon`.
pub fn real_runtime(daemon: &Path) -> PathBuf {
    let p = daemon.with_file_name("runtime");
    assert!(
        p.is_file(),
        "{} is missing: run `cargo build -p runtime-cli`",
        p.display()
    );
    p
}

/// A scratch with the real `runtime`, a fake Wine and a fake vulkaninfo on PATH.
pub fn real(daemon: &Path) -> (Scratch, Vec<(&'static str, PathBuf)>) {
    let s = Scratch::new(daemon, Ok(&real_runtime(daemon)));
    let fakes = s.root.join("fakes");
    fs::create_dir(&fakes).unwrap();
    install_exe(&fakes.join("wine"), Err(FAKE_WINE));
    install_exe(&fakes.join("wineserver"), Err("#!/bin/sh\nexit 0\n"));
    let env = vec![
        ("RUNTIME_WINE", fakes.join("wine")),
        ("RUNTIME_WINESERVER", fakes.join("wineserver")),
        ("RUNTIME_VULKAN_LOADER", PathBuf::from("present")),
    ];
    (s, env)
}

pub fn refs<'a>(env: &'a [(&'static str, PathBuf)]) -> Vec<(&'static str, &'a Path)> {
    env.iter().map(|(k, v)| (*k, v.as_path())).collect()
}

/// [`FAKE_RUNTIME`] answering `--version` with this workspace's version (what `runtimed --write` requires).
pub fn fake_runtime() -> String {
    FAKE_RUNTIME.replace("@VERSION@", env!("CARGO_PKG_VERSION"))
}
