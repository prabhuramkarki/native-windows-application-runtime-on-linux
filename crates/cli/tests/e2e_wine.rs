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
//! Every test works in a temporary `RUNTIME_DATA_DIR` and owns a [`support::Rig`]. Each test removes its apps
//! with [`support::Rig::remove_app`], which first starts a PERSISTENT `wineserver -p` for the app (a server that
//! never idles out) and then requires that `runtime remove` alone got rid of it: a `remove` that does not stop
//! the app's Wine processes fails the test. Only after that assertion does the guard run: the `Drop` of the rig
//! runs `runtime remove` for any app left over and then `kill -9`s any `wineserver` of that data directory, so
//! no Wine process survives a failed test either. Console fixtures only: the GUI fixture `gui64.exe` (a modal
//! message box) is never run here.
//!
//! `Rig` itself (and the other shared harness pieces: `Ran`, `fixture`, `installed_id`) lives in
//! `tests/support/mod.rs` (Task 8): `e2e_installers.rs` needs the identical "no stray wineserver" drop-guard,
//! so it is shared rather than duplicated.
//!
//! Wine older than 10 has no new WoW64 mode, so the 32-bit steps are skipped (loudly, with `SKIPPED 32-bit` on
//! stderr) there.
//!
//! `runtime run` starts programs in the app sandbox, so every test here needs a working `bwrap` too (the ones
//! named `e2e_real_wine_*` check for it first and skip visibly without it, or fail with `RUNTIME_REQUIRE_BWRAP=1`).
//!
//! What the tests do NOT claim: Wine's own `\\?\unix\...` NT paths reach whatever the sandbox shows (and every
//! host file in an `--unsandboxed` run, see `docs/SECURITY.md`); the sandbox's escape tests are separate.
//!
//! The CLI's stdout/stderr go to files, not pipes: the `wineserver` a run starts inherits stdout and would keep
//! a pipe open (and `Command::output` waiting) until it exits, seconds after the CLI has finished. Reading a
//! file after the CLI exited is the same observation without that wait, and lets every call have a deadline.
mod support;

use backend_wine::WineBackend;
use rt_core::CompatBackend;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use support::{Rig, bwrap_works, fixture, installed_id};

const HELLO: &str = "hello from windows";

/// `Some(version text)` when the installed Wine is older than 10 and so cannot run 32-bit programs in a 64-bit
/// prefix (no new WoW64); the caller skips its 32-bit steps and says so. Unknown versions are not skipped.
/// Wine is found exactly as the CLI rig lets the CLI find it: the same search over the same environment, with
/// `RUNTIME_WINE` and `RUNTIME_WINESERVER` removed (see `Rig::exec`), so this decision cannot disagree with the
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

#[test]
#[ignore = "needs Wine, bwrap and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_run_under_sandbox() {
    if !bwrap_works("e2e_real_wine_run_under_sandbox") {
        return;
    }
    let rig = Rig::new();
    let id = rig.install_fixture("hello64.exe", "boxed");
    let ran = rig.rt(&["run", &id]);
    eprintln!("{}", ran.report());
    assert!(ran.out().contains(HELLO), "hello64 stdout: {}", ran.report());
    assert_eq!(ran.code, Some(7), "hello64 exit code: {}", ran.report());
    assert!(!ran.err().contains("WITHOUT a sandbox"), "{}", ran.report());
    assert!(
        rig.apps().join(&id).join("ran-sandboxed").is_file(),
        "the app is marked"
    );

    // `runtime sandbox` describes that same profile.
    let ran = rig.rt(&["sandbox", &id]);
    let out = ran.expect_ok();
    let prefix = rig.apps().join(&id).join("prefix");
    assert!(
        out.contains("' '--unshare-net' '") && out.contains(&format!("'--bind' '{0}' '{0}'", prefix.display())),
        "{}",
        ran.report()
    );

    // Now that it ran sandboxed, `display` runs reg.exe in the same sandbox, and the value is flushed to disk.
    rig.rt(&["display", &id, "x11"]).expect_ok();
    let ran = rig.rt(&["display", &id]);
    assert!(ran.expect_ok().contains("graphics driver: x11"), "{}", ran.report());

    rig.remove_app(&id);
    rig.finish();
}

/// Every pid whose command line starts with `needle` (Wine shows a program as its host path and arguments).
fn pids_with(needle: &str) -> Vec<u32> {
    fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let pid = e.file_name().to_str()?.parse::<u32>().ok()?;
            let cmdline = fs::read(e.path().join("cmdline")).ok()?;
            cmdline.starts_with(needle.as_bytes()).then_some(pid)
        })
        .collect()
}

#[test]
#[ignore = "needs Wine, bwrap and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_ctrl_c_ends_a_sandboxed_console_program() {
    if !bwrap_works("e2e_real_wine_ctrl_c_ends_a_sandboxed_console_program") {
        return;
    }
    let rig = Rig::new();
    let id = rig.install_fixture("fs64.exe", "spinner");
    let exe = rig.drive_c(&id).join("Program Files").join(&id).join("fs64.exe");
    let exe = exe.to_str().unwrap();
    let logs = tempfile::tempdir().unwrap();
    for (sig, code) in [(libc::SIGINT, 130), (libc::SIGTERM, 143)] {
        let (out, err) = (
            logs.path().join(format!("out-{sig}")),
            logs.path().join(format!("err-{sig}")),
        );
        // Its own process group, like a shell job: the signal reaches ONLY the runtime process.
        let mut child = Command::new(env!("CARGO_BIN_EXE_runtime"))
            .args(["run", &id, "--", "spin"])
            .env("RUNTIME_DATA_DIR", rig.data())
            .env_remove("RUNTIME_WINE")
            .env_remove("RUNTIME_WINESERVER")
            .stdin(Stdio::null())
            .stdout(fs::File::create(&out).unwrap())
            .stderr(fs::File::create(&err).unwrap())
            .process_group(0)
            .spawn()
            .unwrap();
        let report = || {
            format!(
                "stdout: {}\nstderr: {}",
                fs::read_to_string(&out).unwrap_or_default(),
                fs::read_to_string(&err).unwrap_or_default()
            )
        };
        let start = Instant::now();
        while !fs::read_to_string(&out).unwrap_or_default().contains("SPINNING") {
            assert!(child.try_wait().unwrap().is_none(), "ended by itself: {}", report());
            assert!(start.elapsed() < Duration::from_secs(60), "never started: {}", report());
            std::thread::sleep(Duration::from_millis(100));
        }
        if pids_with(exe).is_empty() {
            let _ = child.kill();
            panic!("control: no process {exe:?}: {}", report());
        }
        if sig == libc::SIGINT {
            // The run holds the app lock until the program has ended: `remove` and a permissions change refuse.
            for args in [
                &["remove", id.as_str()][..],
                &["permissions", &id, "--set", "network=allow"],
            ] {
                let ran = rig.rt(args);
                assert_eq!(ran.code, Some(1), "{args:?} while it runs: {}", ran.report());
                assert!(
                    ran.err()
                        .contains("the app is running (started by `runtime run`); quit it first"),
                    "{}",
                    ran.report()
                );
            }
            assert!(rig.drive_c(&id).is_dir(), "the running app's prefix was removed");
            assert!(
                !rig.apps().join(&id).join("permissions.toml").exists(),
                "the profile was changed"
            );
            assert!(
                !pids_with(exe).is_empty(),
                "remove must leave the running program alone"
            );
        }
        // SAFETY: `kill` of our own child's pid.
        assert_eq!(unsafe { libc::kill(child.id() as i32, sig) }, 0);
        let sent = Instant::now();
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if sent.elapsed() > Duration::from_secs(10) {
                let _ = child.kill();
                panic!("signal {sig}: the runtime did not end within 10 s: {}", report());
            }
            // Short, so what is left right after the exit is seen.
            std::thread::sleep(Duration::from_millis(1));
        };
        eprintln!("signal {sig}: runtime ended after {:?} with {status:?}", sent.elapsed());
        assert_eq!(status.code(), Some(code), "signal {sig}: {}", report());
        // The app lock is dropped as `runtime` exits: nothing of the sandbox may be left by then (seen within the
        // millisecond polling above; the kernel's PID-namespace teardown is faster).
        assert!(
            pids_with(exe).is_empty() && rig.wineservers().is_empty(),
            "signal {sig}: the program or its wineserver outlived the run: {:?} {:?}",
            pids_with(exe),
            rig.wineservers()
        );
    }
    rig.remove_app(&id);
    rig.finish();
}
