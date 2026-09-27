//! End to end for `runtimed --write` (Phase 6B): the real `runtimed` binary, copied into a scratch `bin/` next to a
//! `runtime` (the production sibling mechanism; there is no environment override), driven through the real client.
//!
//! * A: a fake `runtime` script: the exact argv, cancel, SIGTERM and SIGKILL of the daemon at process level.
//! * B: the real `runtime` (copied from next to `runtimed`) with a fake Wine (`RUNTIME_WINE`/`RUNTIME_WINESERVER` in
//!   the daemon's environment, which jobs inherit as `RUNTIME_*`): install, permissions, display, deps, run, remove,
//!   and what the app sandbox would expose of `$XDG_RUNTIME_DIR` (spec D11).
//! * C (`#[ignore]`, real Wine and bwrap): a sandboxed `apps.run` of `hello64.exe` whose output arrives as events.
//!
//! Every run has its own scratch HOME, data dir and `XDG_RUNTIME_DIR` (never the user's).
use rt_api::jobs::{EventKind, JobEvent, JobInfo, JobState};
use rt_daemon::client::{Client, InstallParams};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DAEMON: &str = env!("CARGO_BIN_EXE_runtimed");
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The fake `runtime` of A: answers `--version`, else records its argv (NUL separated) and pid keyed by its last
/// argument, then acts on `$RUNTIME_DATA_DIR/fake/mode.<key>` (default: print one line).
const FAKE_RUNTIME: &str = r#"#!/bin/sh
[ "$1" = --version ] && { echo "runtime @VERSION@"; exit 0; }
F="$RUNTIME_DATA_DIR/fake"
for a in "$@"; do last="$a"; done
key=$(printf %s "$last" | tr -c 'a-z0-9.-' _)
printf '%s\0' "$@" > "$F/argv.$key"
echo $$ > "$F/pid.$key"
case "$(cat "$F/mode.$key" 2>/dev/null)" in
  wait) echo ready; sleep 60 ;;
  pdeath) trap 'echo term > "$F/pdeath.$key"; exit 0' TERM; echo ready; while :; do sleep 0.05; done ;;
  *) echo done ;;
esac
"#;

/// The CLI rig's fake Wine (`crates/cli/tests/apps.rs`), trimmed: `wineboot` makes a minimal prefix, anything else
/// is "the app", which prints a line.
const FAKE_WINE: &str = r#"#!/bin/sh
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

fn fixture(name: &str) -> PathBuf {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    assert!(p.exists(), "missing fixture {name}: run tools/build-fixtures.sh");
    p
}

/// Writes (or copies) an executable, then waits until it can be executed: another test thread may have forked while
/// it was open for writing, and that child holds the write fd until its exec (ETXTBSY meanwhile).
fn install_exe(dst: &Path, from: Result<&Path, &str>) {
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

struct Scratch {
    _t: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
    xdg: PathBuf,
    data: PathBuf,
    home: PathBuf,
}

impl Scratch {
    /// `runtime`: `Err(script)` for a fake, `Ok(path)` to copy a real binary.
    fn new(runtime: Result<&Path, &str>) -> Scratch {
        let t = tempfile::tempdir().unwrap();
        let root = t.path().canonicalize().unwrap();
        let (bin, xdg, data, home) = (root.join("bin"), root.join("xdg"), root.join("data"), root.join("home"));
        for d in [&bin, &xdg, &data.join("fake"), &home] {
            fs::create_dir_all(d).unwrap();
        }
        fs::set_permissions(&xdg, fs::Permissions::from_mode(0o700)).unwrap();
        // A umask of 002 would leave it group-writable, which `runtimed --write` refuses (with a chmod hint).
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        install_exe(&bin.join("runtimed"), Ok(Path::new(DAEMON)));
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

    fn sock(&self) -> PathBuf {
        self.xdg.join("runtime/runtimed.sock")
    }

    fn cmd(&self, extra: &[(&str, &Path)]) -> Command {
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
    fn daemon(&self, extra: &[(&str, &Path)]) -> Daemon {
        let log = fs::File::create(self.root.join("daemon.log")).unwrap();
        let child = self
            .cmd(extra)
            .args(["--write", "--socket"])
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

    fn log(&self) -> String {
        fs::read_to_string(self.root.join("daemon.log")).unwrap_or_default()
    }

    fn client(&self) -> Client {
        Client::connect(&self.sock()).unwrap()
    }

    fn fake(&self, what: &str, key: &str) -> String {
        fs::read_to_string(self.data.join(format!("fake/{what}.{key}"))).unwrap_or_default()
    }

    fn mode(&self, key: &str, m: &str) {
        fs::write(self.data.join(format!("fake/mode.{key}")), m).unwrap();
    }
}

struct Daemon(Child);

impl Daemon {
    fn signal(&self, sig: i32) {
        // SAFETY: a signal to our own child, not reaped yet.
        unsafe { libc::kill(self.0.id() as libc::pid_t, sig) };
    }

    fn wait(&mut self, within: Duration) -> std::process::ExitStatus {
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

fn alive(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
        && !fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| s.contains(") Z "))
}

/// Follows job `id` to its end: its final info and every event.
fn follow(c: &mut Client, id: &str) -> (JobInfo, Vec<JobEvent>) {
    let until = Instant::now() + Duration::from_secs(120);
    let (mut after, mut all) = (0, vec![]);
    loop {
        let e = c.job_poll(id, after, 2000).unwrap();
        after = e.next_seq;
        all.extend(e.events);
        if !matches!(e.job.state, JobState::Queued | JobState::Running)
            && all
                .last()
                .is_some_and(|l| l.kind == EventKind::State && !["queued", "running"].contains(&l.text.as_str()))
        {
            return (e.job, all);
        }
        assert!(Instant::now() < until, "job {id} did not end: {all:?}");
    }
}

fn wait_for_event(c: &mut Client, id: &str, text: &str) {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if c.job_poll(id, 0, 200).unwrap().events.iter().any(|e| e.text == text) {
            return;
        }
        assert!(Instant::now() < until, "no {text:?} from {id}");
    }
}

fn fake_runtime() -> String {
    FAKE_RUNTIME.replace("@VERSION@", VERSION)
}

// ------------------------------------------------------------------------------------------------ A: fake runtime

#[test]
fn write_mode_refuses_a_socket_outside_xdg_runtime_dir_or_another_runtime_version() {
    let s = Scratch::new(Err(&fake_runtime()));
    let o = s
        .cmd(&[])
        .args(["--write", "--socket"])
        .arg(s.root.join("run/s.sock"))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("inside XDG_RUNTIME_DIR"),
        "{o:?}"
    );
    let other = Scratch::new(Err("#!/bin/sh\necho 'runtime 0.0.0-other'\n"));
    let o = other
        .cmd(&[])
        .args(["--write", "--socket"])
        .arg(other.sock())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("0.0.0-other"), "{o:?}");
    assert!(!other.sock().exists());
}

#[test]
fn jobs_run_the_sibling_runtime_with_the_exact_argv_and_die_with_the_daemon() {
    let s = Scratch::new(Err(&fake_runtime()));
    let mut d = s.daemon(&[]);
    assert!(s.log().contains("mode: write"), "{}", s.log());
    let mut c = s.client();
    assert!(c.version().unwrap().write);
    // An option-looking id never reaches a child.
    let e = c.remove("-rf").unwrap_err();
    assert_eq!(e.api_error().unwrap().kind, rt_api::ErrorKind::InvalidArgument);
    assert!(
        fs::read_dir(s.data.join("fake")).unwrap().next().is_none(),
        "a child was started"
    );
    // The argv, exactly.
    let id = c.remove("notepad").unwrap().job_id;
    let (info, ev) = follow(&mut c, &id);
    assert_eq!((info.state, info.exit_code), (JobState::Succeeded, Some(0)), "{ev:?}");
    assert_eq!(s.fake("argv", "notepad"), "remove\0--\0notepad\0");
    assert!(ev.iter().any(|e| e.kind == EventKind::Stdout && e.text == "done"));
    // Cancel.
    s.mode("a", "wait");
    let id = c.remove("a").unwrap().job_id;
    wait_for_event(&mut c, &id, "ready");
    c.job_cancel(&id).unwrap();
    let (info, _) = follow(&mut c, &id);
    assert_eq!((info.state, info.signal), (JobState::Cancelled, Some(libc::SIGTERM)));
    // SIGTERM to the daemon with two live jobs: both children gone, exit 0.
    s.mode("b", "wait");
    s.mode("c", "wait");
    let ids: Vec<String> = ["b", "c"].iter().map(|a| c.remove(a).unwrap().job_id).collect();
    for id in &ids {
        wait_for_event(&mut c, id, "ready");
    }
    let pids: Vec<i32> = ["b", "c"]
        .iter()
        .map(|a| s.fake("pid", a).trim().parse().unwrap())
        .collect();
    assert!(pids.iter().all(|p| alive(*p)));
    d.signal(libc::SIGTERM);
    assert!(d.wait(Duration::from_secs(7)).success(), "{}", s.log());
    assert!(pids.iter().all(|p| !alive(*p)), "a job outlived the daemon");
    assert!(!s.sock().exists());
}

#[test]
fn a_killed_daemon_takes_its_jobs_with_it() {
    let s = Scratch::new(Err(&fake_runtime()));
    let mut d = s.daemon(&[]);
    let mut c = s.client();
    s.mode("p", "pdeath");
    let id = c.remove("p").unwrap().job_id;
    wait_for_event(&mut c, &id, "ready");
    let pid: i32 = s.fake("pid", "p").trim().parse().unwrap();
    d.signal(libc::SIGKILL);
    d.wait(Duration::from_secs(5));
    let until = Instant::now() + Duration::from_secs(1);
    while s.fake("pdeath", "p").trim() != "term" {
        assert!(
            Instant::now() < until,
            "the job's runtime got no SIGTERM when the daemon died"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let until = Instant::now() + Duration::from_secs(2);
    while alive(pid) {
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(10));
    }
}

// ------------------------------------------------------------------------------------------------ B: real runtime

fn real_runtime() -> PathBuf {
    let p = Path::new(DAEMON).with_file_name("runtime");
    assert!(p.is_file(), "{} is missing: run `cargo test --workspace`", p.display());
    p
}

/// A scratch with the real `runtime`, a fake Wine and a fake vulkaninfo on PATH.
fn real() -> (Scratch, Vec<(&'static str, PathBuf)>) {
    let s = Scratch::new(Ok(&real_runtime()));
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

fn refs<'a>(env: &'a [(&'static str, PathBuf)]) -> Vec<(&'static str, &'a Path)> {
    env.iter().map(|(k, v)| (*k, v.as_path())).collect()
}

#[test]
fn the_real_runtime_as_jobs_install_permissions_display_deps_run_remove() {
    let (s, env) = real();
    let _d = s.daemon(&refs(&env));
    let mut c = s.client();
    let exe = s.root.join("hello64.exe");
    fs::copy(fixture("hello64.exe"), &exe).unwrap();
    let id = c
        .install(&InstallParams {
            path: exe.to_str().unwrap().into(),
            name: Some("Hello".into()),
            ..Default::default()
        })
        .unwrap()
        .job_id;
    let (info, ev) = follow(&mut c, &id);
    assert_eq!(info.state, JobState::Succeeded, "{ev:?}");
    let app = ev
        .iter()
        .find_map(|e| e.text.strip_prefix("Installed: "))
        .unwrap()
        .to_owned();
    assert!(c.apps().unwrap().apps.iter().any(|a| a.id == app));

    let id = c.permissions_set(&app, &["network=allow".into()]).unwrap().job_id;
    assert_eq!(follow(&mut c, &id).0.state, JobState::Succeeded);
    assert_eq!(c.permissions(&app).unwrap().network, rt_api::NetworkView::Allow);
    let grant = format!("fs+={}:rw", s.home.display());
    let id = c.permissions_set(&app, &[grant]).unwrap().job_id;
    let (info, ev) = follow(&mut c, &id);
    assert_eq!(info.state, JobState::Failed);
    assert!(
        ev.iter()
            .any(|e| e.kind == EventKind::Stderr && e.text.contains("home directory")),
        "{ev:?}"
    );

    // The fake prefix has no reg.exe of its own (a real wineboot makes one); the fake Wine plays it.
    let sys32 = s.data.join("apps").join(&app).join("prefix/drive_c/windows/system32");
    fs::create_dir_all(&sys32).unwrap();
    fs::write(sys32.join("reg.exe"), b"MZ").unwrap();
    let id = c.display_set(&app, rt_api::jobs::Driver::X11).unwrap().job_id;
    let (info, ev) = follow(&mut c, &id);
    assert_eq!(info.state, JobState::Succeeded, "{ev:?}");
    let reg = fs::read_to_string(s.data.join("apps").join(&app).join("prefix/user.reg")).unwrap();
    assert!(reg.contains("\"Graphics\"=\"x11\""), "{reg}");

    let plan = c.deps_plan(&app).unwrap();
    assert!(plan.entries.is_empty());
    let id = c.deps_install(&app, &plan.digest, &[]).unwrap().job_id;
    let (info, ev) = follow(&mut c, &id);
    assert_eq!(info.state, JobState::Succeeded, "{ev:?}");
    assert!(ev.iter().any(|e| e.text == "Nothing to install."), "{ev:?}");

    // run: the fake Wine cannot run inside the sandbox; whatever happens, it never runs unsandboxed.
    let id = c.run_app(&app, &["--unsandboxed".into()]).unwrap().job_id;
    let (info, ev) = follow(&mut c, &id);
    assert!(!ev.iter().any(|e| e.text.contains("WITHOUT a sandbox")), "{ev:?}");
    assert!(
        !ev.iter().any(|e| e.text == "app-stdout"),
        "the fake Wine ran outside a sandbox: {ev:?}"
    );
    assert_eq!(info.state, JobState::Failed, "{ev:?}");

    let id = c.remove(&app).unwrap().job_id;
    assert_eq!(follow(&mut c, &id).0.state, JobState::Succeeded);
    assert!(c.apps().unwrap().apps.is_empty());
}

/// Spec D11: what an app's sandbox would bind never includes the write-capable socket, its directory or an ancestor
/// of it; the runtime directory itself is an empty tmpfs, even for a profile with everything on and live Wayland and
/// PulseAudio sockets in `$XDG_RUNTIME_DIR`.
#[test]
fn no_sandbox_profile_can_see_the_write_socket() {
    use std::os::unix::net::UnixListener;
    let (s, mut env) = real();
    let _wl = UnixListener::bind(s.xdg.join("wayland-0")).unwrap();
    fs::create_dir(s.xdg.join("pulse")).unwrap();
    let _pa = UnixListener::bind(s.xdg.join("pulse/native")).unwrap();
    env.push(("WAYLAND_DISPLAY", PathBuf::from("wayland-0")));
    env.push(("DISPLAY", PathBuf::from(":0")));
    let _d = s.daemon(&refs(&env));
    let mut c = s.client();
    let exe = s.root.join("hello64.exe");
    fs::copy(fixture("hello64.exe"), &exe).unwrap();
    let id = c
        .install(&InstallParams {
            path: exe.to_str().unwrap().into(),
            ..Default::default()
        })
        .unwrap()
        .job_id;
    let (_, ev) = follow(&mut c, &id);
    let app = ev
        .iter()
        .find_map(|e| e.text.strip_prefix("Installed: "))
        .unwrap()
        .to_owned();
    // Nothing at or below /tmp can be granted: the grant lives under the target dir.
    let grants = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let grant = grants.path().canonicalize().unwrap();
    let set: Vec<String> = ["network=allow", "display=on", "audio=on", "gpu=on"]
        .iter()
        .map(|x| x.to_string())
        .chain([format!("fs+={}:rw", grant.display())])
        .collect();
    let id = c.permissions_set(&app, &set).unwrap().job_id;
    let (info, ev) = follow(&mut c, &id);
    assert_eq!(info.state, JobState::Succeeded, "{ev:?}");
    let sock = s.sock();
    for profile in ["maximal", "default"] {
        let view = c.sandbox_info(&app).unwrap();
        let argv = &view.command;
        if profile == "maximal" {
            // The test is not vacuous: the session sockets in XDG_RUNTIME_DIR ARE bound, the grant too.
            for p in [s.xdg.join("wayland-0"), s.xdg.join("pulse/native"), grant.clone()] {
                assert!(argv.iter().any(|a| Path::new(a) == p), "{p:?} not bound: {argv:?}");
            }
        }
        assert!(
            argv.windows(2).any(|w| w[0] == "--tmpfs" && Path::new(&w[1]) == s.xdg),
            "{profile}: {argv:?}"
        );
        for (i, a) in argv.iter().enumerate() {
            if !matches!(
                a.as_str(),
                "--bind" | "--ro-bind" | "--bind-try" | "--ro-bind-try" | "--dev-bind" | "--dev-bind-try"
            ) {
                continue;
            }
            let (src, dst) = (Path::new(&argv[i + 1]), Path::new(&argv[i + 2]));
            for p in [src, dst] {
                assert!(
                    !sock.starts_with(p),
                    "{profile}: {a} {p:?} exposes the socket: {argv:?}"
                );
                assert!(!p.starts_with(s.xdg.join("runtime")), "{profile}: {a} {p:?}: {argv:?}");
            }
        }
        let id = c.permissions_reset(&app).unwrap().job_id;
        follow(&mut c, &id);
    }
}

// ------------------------------------------------------------------------------------------------ C: real Wine

/// A real sandboxed run through the daemon: `hello64.exe`'s output arrives as `stdout` events. Needs Wine and a
/// working bwrap (`RUNTIME_REQUIRE_BWRAP=1` makes a missing bwrap a failure, as in `e2e_sandbox.rs`).
#[test]
#[ignore]
fn a_real_sandboxed_run_streams_its_output() {
    if !Path::new("/usr/bin/bwrap").exists() && std::env::var_os("RUNTIME_REQUIRE_BWRAP").is_none() {
        eprintln!("SKIPPED: no bwrap");
        return;
    }
    let s = Scratch::new(Ok(&real_runtime()));
    let _d = s.daemon(&[]);
    let mut c = s.client();
    let exe = s.root.join("hello64.exe");
    fs::copy(fixture("hello64.exe"), &exe).unwrap();
    let id = c
        .install(&InstallParams {
            path: exe.to_str().unwrap().into(),
            ..Default::default()
        })
        .unwrap()
        .job_id;
    let (info, ev) = follow(&mut c, &id);
    assert_eq!(info.state, JobState::Succeeded, "{ev:?}");
    let app = ev
        .iter()
        .find_map(|e| e.text.strip_prefix("Installed: "))
        .unwrap()
        .to_owned();
    let id = c.run_app(&app, &[]).unwrap().job_id;
    let (info, ev) = follow(&mut c, &id);
    // hello64 exits 7 on purpose (as in e2e_wine.rs): the job is `failed` with the program's own code.
    assert_eq!((info.state, info.exit_code), (JobState::Failed, Some(7)), "{ev:?}");
    assert!(
        ev.iter()
            .any(|e| e.kind == EventKind::Stdout && e.text.contains("hello from windows")),
        "{ev:?}"
    );
    assert!(!ev.iter().any(|e| e.text.contains("WITHOUT a sandbox")));
}
