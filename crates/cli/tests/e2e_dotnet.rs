//! Phase 4F: a managed (.NET) program through Wine Mono, end to end, under the DEFAULT sandbox (bubblewrap +
//! the seccomp deny-list + Landlock + the limits). The fixture `hello-managed.exe` is built by
//! `tools/build-managed-fixture.sh` (Wine Mono's own C# compiler, in a scratch prefix) from
//! `tools/fixtures/hello-managed.cs`.
//!
//! Needs the internet by nature (`runtime deps --install` downloads the pinned ~85 MB Wine Mono MSI through the
//! real fetcher, on the host side; the MSI then runs in the installer sandbox, offline), so the test is
//! `#[ignore]`d and named `real_net_wine_*`: CI's `--skip real_net_` never runs it. It skips visibly without Wine,
//! the fixture or the network, and without bwrap unless `RUNTIME_REQUIRE_BWRAP=1` (then that is a failure):
//!
//! ```text
//! tools/build-managed-fixture.sh
//! RUNTIME_REQUIRE_BWRAP=1 cargo test -p runtime-cli --test e2e_dotnet -- --ignored --test-threads=1 --nocapture
//! ```
mod support;

use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;
use support::{Rig, bwrap_works};

const TEST: &str = "real_net_wine_dotnet_runs_under_the_default_sandbox";
const GREETING: &str = "hello from .NET ";
/// The frozen override strings (crates/backend-wine): native apps and every helper keep `mscoree=d`.
const NATIVE_OVERRIDES: &str = "winemenubuilder.exe=d;mscoree=d;mshtml=d";
const DOTNET_OVERRIDES: &str = "winemenubuilder.exe=d;mshtml=d";

/// `false` after saying SKIPPED why (no Wine, no fixture, no route to the MSI's host).
fn prerequisites() -> bool {
    let skip = |why: &str| {
        eprintln!("SKIPPED {TEST}: {why}");
        false
    };
    if backend_wine::WineBackend::discover().is_err() {
        return skip("Wine is not installed (apt install wine)");
    }
    let exe = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/build/hello-managed.exe");
    if !exe.is_file() {
        return skip("tests/fixtures/build/hello-managed.exe is missing: run tools/build-managed-fixture.sh");
    }
    let online = ("dl.winehq.org", 443)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .is_some_and(|a| TcpStream::connect_timeout(&a, Duration::from_secs(10)).is_ok());
    online || skip("no network (dl.winehq.org:443 is unreachable)")
}

/// No scope of this data dir and no fixture process is left (10 s grace).
fn nothing_left(rig: &Rig) {
    let data = rig.data().display().to_string();
    let start = std::time::Instant::now();
    loop {
        let out = std::process::Command::new("systemctl")
            .args([
                "--user",
                "list-units",
                "--type=scope",
                "--all",
                "--full",
                "--no-legend",
                "--plain",
            ])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let scopes: Vec<&str> = text.lines().filter(|l| l.contains(&data)).collect();
        let procs: Vec<String> = std::fs::read_dir("/proc")
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| {
                std::fs::read(e.path().join("cmdline"))
                    .is_ok_and(|c| String::from_utf8_lossy(&c).contains("hello-managed.exe"))
            })
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        if scopes.is_empty() && procs.is_empty() {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "left behind: scopes {scopes:?}, processes {procs:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "needs the internet, Wine, bwrap and tools/build-managed-fixture.sh"]
fn real_net_wine_dotnet_runs_under_the_default_sandbox() {
    if !bwrap_works(TEST) || !prerequisites() {
        return;
    }
    let rig = Rig::new_in(Path::new(env!("CARGO_TARGET_TMPDIR")));
    let id = rig.install_fixture("hello-managed.exe", "managed");

    // This host enforces both in-kernel layers, so every sandboxed run below is under seccomp AND Landlock.
    let ran = rig.rt(&["sandbox", &id]);
    let out = ran.expect_ok();
    assert!(
        out.contains("seccomp: enforced") && out.contains("landlock: ABI"),
        "seccomp and Landlock must both be enforced on this host for this test to mean anything: {}",
        ran.report()
    );
    // ... and from inside a sandboxed run: the Wine process's own /proc/self/status (native probe, same profile).
    let probe = rig.install_fixture("probe64.exe", "probe");
    let ran = rig.run_app(&probe, &["status"]);
    let status = ran.expect_ok();
    assert!(
        status.contains("Seccomp:\t2") && status.contains("NoNewPrivs:\t1"),
        "{}",
        ran.report()
    );
    rig.rt(&["remove", &probe]).expect_ok();

    // Before: Wine Mono is needed, planned, and the program cannot run (mscoree is disabled).
    let ran = rig.rt(&["doctor", &id]);
    assert!(
        ran.out()
            .lines()
            .any(|l| l.contains("[warn]") && l.contains("Wine Mono is not installed for this app")),
        "{}",
        ran.report()
    );
    let ran = rig.rt(&["deps", &id]);
    assert!(ran.expect_ok().contains("wine-mono"), "{}", ran.report());
    let ran = rig.run_app(&id, &["a", "b"]);
    eprintln!("before Wine Mono: {}", ran.report());
    assert!(!ran.out().contains(GREETING), "ran without Wine Mono: {}", ran.report());
    // The loader refuses the IL-only binary: STATUS_DLL_NOT_FOUND (0xC0000135), whose low byte 53 was the exit code
    // measured on Wine 10.0; the exact code depends on the Wine version, so Wine's own message counts too (it
    // reaches the run log or stderr when the Wine debug channels allow it). Any other failure is not this one.
    let logs = rig.apps().join(&id).join("logs");
    let log: String = std::fs::read_dir(&logs)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| String::from_utf8_lossy(&std::fs::read(e.path()).unwrap_or_default()).into_owned())
        .collect();
    let said = |t: &str| log.contains(t) || ran.err().contains(t);
    assert!(
        ran.code == Some(53) || said("c0000135") || said("mscoree.dll not found"),
        "not the missing-mscoree failure: {}\nrun log:\n{log}",
        ran.report()
    );

    // Install through the engine: the real download (host side), then the MSI in the installer sandbox.
    let (ran, timed_out) = rig.exec(&["deps", &id, "--install"], &[], Duration::from_secs(900));
    eprintln!("deps --install: {}", ran.report());
    assert!(!timed_out, "deps --install timed out");
    assert!(ran.expect_ok().contains("installed: wine-mono"), "{}", ran.report());
    let store = rt_core::Store::new(rig.apps()).unwrap();
    let env = store.get(&rt_core::AppId::parse(&id).unwrap()).unwrap();
    let md = store.read_metadata(&env).unwrap();
    let record = md
        .dependencies
        .iter()
        .find(|d| d.id == rt_core::DOTNET_PACKAGE_ID)
        .expect("wine-mono is recorded")
        .clone();
    assert_eq!(record.version, "9.4.0");
    assert!(
        rig.drive_c(&id)
            .join("windows/mono/mono-2.0/bin/libmono-2.0-x86_64.dll")
            .is_file()
    );
    let ran = rig.rt(&["doctor", &id]);
    assert!(
        ran.out()
            .lines()
            .any(|l| l.contains("[ok]") && l.contains("Wine Mono 9.4.0 is recorded as installed for this app")),
        "{}",
        ran.report()
    );

    // After: the program runs sandboxed, with its arguments and its exit code.
    let ran = rig.run_app(&id, &["a", "b"]);
    eprintln!("{}", ran.report());
    assert!(!ran.err().contains("WITHOUT a sandbox"), "{}", ran.report());
    let lines: Vec<String> = ran.expect(7).lines().map(|l| l.trim().to_owned()).collect();
    assert!(
        lines.len() == 3 && lines[0].starts_with(GREETING) && lines[0].ends_with(" args=2"),
        "{}",
        ran.report()
    );
    assert_eq!(lines[1..], ["a", "b"], "{}", ran.report());
    // JIT + threads, then the GC, under the same filter and rules.
    let ran = rig.run_app(&id, &["threads"]);
    eprintln!("{}", ran.report());
    assert_eq!(ran.expect_ok(), "threads total=400000", "{}", ran.report());
    let ran = rig.run_app(&id, &["alloc"]);
    eprintln!("{}", ran.report());
    assert_eq!(ran.expect_ok(), "alloc ok 64 MiB", "{}", ran.report());

    // The override string of a SANDBOXED run, printed by a native probe: with the same Wine Mono record the
    // managed app got, mscoree is enabled; without it (a plain native app) it stays `mscoree=d`, byte for byte.
    let recorded = rig.install_fixture("fs64.exe", "recorded");
    let renv = store.get(&rt_core::AppId::parse(&recorded).unwrap()).unwrap();
    let mut rmd = store.read_metadata(&renv).unwrap();
    rt_deps::record(&mut rmd, record).unwrap();
    store.write_metadata(&renv, &rmd).unwrap();
    let native = rig.install_fixture("fs64.exe", "native");
    for (app, want) in [(&recorded, DOTNET_OVERRIDES), (&native, NATIVE_OVERRIDES)] {
        let ran = rig.run_app(app, &["env", "WINEDLLOVERRIDES"]);
        assert!(!ran.err().contains("WITHOUT a sandbox"), "{}", ran.report());
        assert_eq!(ran.expect_ok(), want, "{app}: {}", ran.report());
    }

    for app in [&id, &recorded, &native] {
        rig.rt(&["remove", app]).expect_ok();
    }
    nothing_left(&rig);
    rig.finish();
}
