//! The escape suite (Phase 5A): a REAL Windows program (`probe64.exe`, `tools/fixtures/probe.c`) inside the REAL
//! app sandbox (bubblewrap) on REAL Wine tries to reach what the sandbox exists to hide.
//!
//! **The oracle.** Every attempted action is run twice against the SAME target: under the default sandbox it must
//! FAIL (the probe exits 1 and prints `<MODE>-FAILED <why>`), and with `runtime run --unsandboxed` it must
//! SUCCEED (exit 0, `<MODE>-OK`). A control that fails too fails the test: then Wine, a missing file or file
//! permissions made the difference, not the sandbox. Exit code 1 exactly, never "not 0", so a usage error (2) or
//! a crashed Wine cannot pass for a blocked action.
//!
//! **Targets.** The probe reaches host files through Wine's NT unix paths (`\\?\unix\<absolute host path>`), the
//! escape hatch that stays after `Z:` and the home links are gone (docs/SECURITY.md). The "real home" is a fake one
//! in `CARGO_TARGET_TMPDIR` (`<tmp>/home/.ssh/id_test`), set as the CLI's own `HOME`, so the grant checks judge
//! against it too; the developer's real `~/.ssh` is never read. The data dir is also below `CARGO_TARGET_TMPDIR`,
//! like the real `~/.local/share/runtime`, not in `/tmp` (the sandbox's `/tmp` is a writable tmpfs).
//!
//! `#[ignore]`d (Wine, bwrap and the fixtures are needed; CI's `-p runtime-cli -- --ignored` step runs them); each
//! test skips visibly without a working bwrap and fails with `RUNTIME_REQUIRE_BWRAP=1`:
//!
//! ```text
//! RUNTIME_REQUIRE_BWRAP=1 cargo test -p runtime-cli --test e2e_sandbox -- --ignored --test-threads=1
//! ```
mod support;

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;
use support::{Ran, Rig, bwrap_works};

const WARNING: &str = "warning: running WITHOUT a sandbox (--unsandboxed)";

/// One test's world: a rig with its data dir below `CARGO_TARGET_TMPDIR`, a fake home with a canary secret, and
/// one installed probe app.
struct Suite {
    rig: Rig,
    base: tempfile::TempDir,
    home: PathBuf,
    id: String,
}

impl Suite {
    /// `None` (after SKIPPED) without a working bwrap.
    fn new(test: &str) -> Option<Suite> {
        if !bwrap_works(test) {
            return None;
        }
        let tmp = Path::new(env!("CARGO_TARGET_TMPDIR"));
        let base = tempfile::tempdir_in(tmp).unwrap();
        let home = base.path().join("home");
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::write(home.join(".ssh/id_test"), "secret").unwrap();
        let rig = Rig::new_in(tmp);
        let mut s = Suite {
            rig,
            base,
            home,
            id: String::new(),
        };
        s.id = s.install("probe");
        Some(s)
    }

    fn env(&self) -> [(&str, &str); 1] {
        [("HOME", self.home.to_str().unwrap())]
    }

    fn rt(&self, args: &[&str]) -> Ran {
        self.rig.rt_env(args, &self.env())
    }

    fn install(&self, name: &str) -> String {
        let exe = support::fixture("probe64.exe");
        let ran = self.rt(&["install", exe.to_str().unwrap(), "--name", name]);
        ran.expect_ok();
        support::installed_id(&ran)
    }

    fn probe(&self, id: &str, unsandboxed: bool, args: &[&str]) -> Ran {
        let mut v = vec!["run"];
        if unsandboxed {
            v.push("--unsandboxed");
        }
        v.extend([id, "--"]);
        v.extend_from_slice(args);
        let ran = self.rt(&v);
        eprintln!("{}", ran.report());
        ran
    }

    /// The action FAILS in the sandbox: exit 1 and the probe's own `-FAILED` line (so it ran and tried).
    fn fails_boxed(&self, id: &str, args: &[&str]) -> Ran {
        let ran = self.probe(id, false, args);
        assert!(
            ran.code == Some(1) && ran.out().contains("-FAILED"),
            "SANDBOX HOLE: `{}` was not blocked in the sandbox: {}",
            args.join(" "),
            ran.report()
        );
        assert!(!ran.err().contains(WARNING), "{}", ran.report());
        ran
    }

    fn works_boxed(&self, id: &str, args: &[&str]) -> Ran {
        let ran = self.probe(id, false, args);
        assert!(
            ran.code == Some(0) && ran.out().contains("-OK"),
            "`{}` must work in the sandbox: {}",
            args.join(" "),
            ran.report()
        );
        ran
    }

    /// The control: the same action SUCCEEDS without the sandbox. If not, the blocked result proves nothing.
    fn works_unboxed(&self, id: &str, args: &[&str]) -> Ran {
        let ran = self.probe(id, true, args);
        assert!(
            ran.code == Some(0) && ran.out().contains("-OK"),
            "VACUOUS: the unsandboxed control of `{}` failed too, so the sandbox is not what blocked it: {}",
            args.join(" "),
            ran.report()
        );
        assert!(ran.err().contains(WARNING), "{}", ran.report());
        ran
    }

    /// `runtime permissions` refuses while a wineserver of the app runs (an unsandboxed run's lingers ~3 s).
    fn set(&self, sets: &[&str]) -> Ran {
        assert!(
            self.rig.wait_for_no_wineserver(Duration::from_secs(15)),
            "wineserver lingers"
        );
        let mut v = vec!["permissions", self.id.as_str()];
        for s in sets {
            v.extend(["--set", s]);
        }
        self.rt(&v)
    }

    fn permissions_toml(&self) -> PathBuf {
        self.rig.apps().join(&self.id).join("permissions.toml")
    }

    /// Removes this suite's app and `others`, then the rig's no-leftovers check.
    fn finish(&self, others: &[&str]) {
        for id in others.iter().copied().chain([self.id.as_str()]) {
            assert!(
                self.rig.wait_for_no_wineserver(Duration::from_secs(15)),
                "wineserver lingers"
            );
            self.rt(&["remove", id]).expect_ok();
        }
        self.rig.finish();
    }
}

/// Wine's NT path for a host path: `\\?\unix\home\...`.
fn unix(p: &Path) -> String {
    format!("\\\\?\\unix{}", p.display().to_string().replace('/', "\\"))
}

#[test]
#[ignore = "needs Wine, bwrap and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_1_cannot_read_a_secret_in_the_real_home() {
    let Some(s) = Suite::new("e2e_real_wine_sandbox_1_cannot_read_a_secret_in_the_real_home") else {
        return;
    };
    let target = unix(&s.home.join(".ssh/id_test"));
    s.fails_boxed(&s.id, &["read", &target]);
    let ran = s.works_unboxed(&s.id, &["read", &target]);
    assert!(ran.out().contains(&format!("first byte {}", b's')), "{}", ran.report());
    s.finish(&[]);
}

#[test]
#[ignore = "needs Wine, bwrap and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_2_cannot_write_to_the_real_home() {
    let Some(s) = Suite::new("e2e_real_wine_sandbox_2_cannot_write_to_the_real_home") else {
        return;
    };
    let file = s.home.join("escape.txt");
    let target = unix(&file);
    s.fails_boxed(&s.id, &["write", &target]);
    assert!(!file.exists(), "{} exists after a sandboxed write", file.display());
    s.works_unboxed(&s.id, &["write", &target]);
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "escape",
        "the control wrote the host file"
    );
    fs::remove_file(&file).unwrap();
    s.finish(&[]);
}

#[test]
#[ignore = "needs Wine, bwrap and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_3_cannot_see_another_apps_prefix() {
    let Some(s) = Suite::new("e2e_real_wine_sandbox_3_cannot_see_another_apps_prefix") else {
        return;
    };
    let other = s.install("other");
    let canary = s.rig.drive_c(&other).join("canary.txt");
    fs::write(&canary, "other app's data").unwrap();
    s.fails_boxed(&s.id, &["read", &unix(&canary)]);
    s.works_unboxed(&s.id, &["read", &unix(&canary)]);

    // The apps directory lists only this app from inside (bwrap's skeleton for the bound prefix), both from outside.
    let apps = unix(&s.rig.apps());
    let inside = s.works_boxed(&s.id, &["list", &apps]).out();
    assert!(inside.contains(&s.id) && !inside.contains(&other), "{inside}");
    let outside = s.works_unboxed(&s.id, &["list", &apps]).out();
    assert!(outside.contains(&s.id) && outside.contains(&other), "{outside}");
    s.finish(&[&other]);
}

#[test]
#[ignore = "needs Wine, bwrap and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_4_cannot_read_or_write_its_own_permissions_toml() {
    let Some(s) = Suite::new("e2e_real_wine_sandbox_4_cannot_read_or_write_its_own_permissions_toml") else {
        return;
    };
    s.set(&["network=deny"]).expect_ok();
    let file = s.permissions_toml();
    let before = fs::read(&file).expect("`permissions --set` writes permissions.toml");
    let target = unix(&file);
    s.fails_boxed(&s.id, &["read", &target]);
    s.fails_boxed(&s.id, &["write", &target]);
    assert_eq!(fs::read(&file).unwrap(), before, "permissions.toml changed");

    s.works_unboxed(&s.id, &["read", &target]);
    s.works_unboxed(&s.id, &["write", &target]);
    assert_eq!(
        fs::read(&file).unwrap(),
        b"escape",
        "the control rewrote permissions.toml"
    );
    fs::write(&file, &before).unwrap();
    s.finish(&[]);
}

#[test]
#[ignore = "needs Wine, bwrap and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_5_network_is_denied_by_default_and_allowed_by_the_profile() {
    let Some(s) = Suite::new("e2e_real_wine_sandbox_5_network_is_denied_by_default_and_allowed_by_the_profile") else {
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let args = ["connect", "127.0.0.1", port.as_str()];
    s.fails_boxed(&s.id, &args);
    s.works_unboxed(&s.id, &args);
    s.set(&["network=allow"]).expect_ok();
    s.works_boxed(&s.id, &args);
    drop(listener);
    s.finish(&[]);
}

#[test]
#[ignore = "needs Wine, bwrap and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_6_a_granted_directory_is_exactly_what_is_shared() {
    let Some(s) = Suite::new("e2e_real_wine_sandbox_6_a_granted_directory_is_exactly_what_is_shared") else {
        return;
    };
    let parent = s.base.path().join("shared");
    let dir = parent.join("granted");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("in.txt"), "granted").unwrap();
    let sibling = parent.join("sibling.txt");
    fs::write(&sibling, "not granted").unwrap();
    let (inside, new) = (unix(&dir.join("in.txt")), dir.join("new.txt"));

    // Not granted yet: the oracle.
    s.fails_boxed(&s.id, &["read", &inside]);
    s.works_unboxed(&s.id, &["read", &inside]);

    let grant = dir.to_str().unwrap();
    s.set(&[&format!("fs+={grant}:ro")]).expect_ok();
    s.works_boxed(&s.id, &["read", &inside]);
    s.fails_boxed(&s.id, &["write", &unix(&new)]);
    assert!(!new.exists(), "a write through a read-only grant reached the host");
    // The parent is not shared: its other entries stay invisible.
    s.fails_boxed(&s.id, &["read", &unix(&sibling)]);
    let listed = s.works_boxed(&s.id, &["list", &unix(&parent)]).out();
    assert!(listed.contains("granted") && !listed.contains("sibling"), "{listed}");
    s.works_unboxed(&s.id, &["read", &unix(&sibling)]);

    s.set(&[&format!("fs+={grant}:rw")]).expect_ok();
    s.works_boxed(&s.id, &["write", &unix(&new)]);
    assert_eq!(
        fs::read_to_string(&new).unwrap(),
        "escape",
        "the rw grant is the host directory"
    );
    s.finish(&[]);
}

#[test]
#[ignore = "needs Wine, bwrap and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_7_a_grant_of_the_homes_ssh_is_refused() {
    let Some(s) = Suite::new("e2e_real_wine_sandbox_7_a_grant_of_the_homes_ssh_is_refused") else {
        return;
    };
    let ssh = s.home.join(".ssh");
    let ran = s.set(&[&format!("fs+={}:ro", ssh.display())]);
    assert_ne!(ran.code, Some(0), "{}", ran.report());
    assert!(
        ran.err().contains(".ssh"),
        "the refusal names the reason: {}",
        ran.report()
    );
    assert!(!s.permissions_toml().exists(), "nothing may be written");
    // Control: the same command with a harmless grant is accepted, so the refusal is about `.ssh`.
    let ok = s.base.path().join("ok");
    fs::create_dir(&ok).unwrap();
    s.set(&[&format!("fs+={}:ro", ok.display())]).expect_ok();
    s.finish(&[]);
}

#[test]
#[ignore = "needs Wine, bwrap and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_8_unsandboxed_really_is_unsandboxed_and_says_so() {
    let Some(s) = Suite::new("e2e_real_wine_sandbox_8_unsandboxed_really_is_unsandboxed_and_says_so") else {
        return;
    };
    // Reaches the fake home, a host path the sandbox never binds, and warns (asserted in `works_unboxed`).
    s.works_unboxed(&s.id, &["read", &unix(&s.home.join(".ssh/id_test"))]);
    let ran = s.works_unboxed(&s.id, &["list", &unix(s.base.path())]);
    assert!(ran.out().contains("home"), "{}", ran.report());
    // The sandboxed run of the same listing does not warn and does not see it.
    let ran = s.fails_boxed(&s.id, &["list", &unix(s.base.path())]);
    assert!(!ran.err().contains(WARNING), "{}", ran.report());
    s.finish(&[]);
}

/// Phase 4's DXVK D3D11 fixture through `runtime run` under the DEFAULT sandbox: display and GPU passthrough.
/// Needs the internet (`runtime deps --install` downloads DXVK on the host side, outside any sandbox; the program
/// itself runs with network denied), a display session and a Vulkan device, so CI skips it (`--skip real_net_`).
/// Run by hand once per device of `vulkaninfo --summary`:
///
/// ```text
/// DXVK_FILTER_DEVICE_NAME=<device> RUNTIME_REQUIRE_BWRAP=1 cargo test -p runtime-cli --test e2e_sandbox -- \
///     --ignored real_net_wine_d3d11 --nocapture
/// ```
///
/// The runtime's environment allowlist drops `DXVK_*` on purpose, so the filter reaches DXVK the Windows way: the
/// test writes it into the prefix's `HKCU\Environment` (host-side `wine reg add`, before the first run).
#[test]
#[ignore = "needs the internet, Wine, bwrap, a display and a Vulkan device"]
fn real_net_wine_d3d11_renders_under_the_default_sandbox() {
    if !bwrap_works("real_net_wine_d3d11_renders_under_the_default_sandbox") {
        return;
    }
    let rig = Rig::new_in(Path::new(env!("CARGO_TARGET_TMPDIR")));
    let id = rig.install_fixture("d3d11_64.exe", "d3d11");
    let ran = rig.rt(&["deps", &id, "--install"]);
    assert!(ran.expect_ok().contains("installed: dxvk"), "{}", ran.report());

    let filter = std::env::var("DXVK_FILTER_DEVICE_NAME").unwrap_or_default();
    if !filter.is_empty() {
        let wine = backend_wine::WineBackend::discover().unwrap();
        let prefix = rig.apps().join(&id).join("prefix");
        let with_prefix = |program: &Path| {
            let mut c = std::process::Command::new(program);
            c.env("WINEPREFIX", &prefix)
                .env("HOME", rig.apps().join(&id).join("runtime/home"))
                .env("WINEDEBUG", "-all")
                .current_dir(prefix.join("drive_c"));
            c
        };
        let st = with_prefix(wine.wine_path())
            .args([
                "reg",
                "add",
                "HKCU\\Environment",
                "/v",
                "DXVK_FILTER_DEVICE_NAME",
                "/d",
                &filter,
                "/f",
            ])
            .status()
            .unwrap();
        assert!(st.success(), "wine reg add: {st:?}");
        // Flushes the registry to disk before the sandboxed run starts its own wineserver.
        assert!(
            with_prefix(wine.wineserver_path())
                .arg("-w")
                .status()
                .unwrap()
                .success()
        );
    }

    let ran = rig.rt(&["run", &id]);
    eprintln!("{}", ran.report());
    assert!(!ran.err().contains(WARNING), "{}", ran.report());
    let logs = rig.apps().join(&id).join("logs");
    let log: String = fs::read_dir(&logs)
        .unwrap()
        .flatten()
        .map(|e| String::from_utf8_lossy(&fs::read(e.path()).unwrap()).into_owned())
        .collect();
    let short: Vec<&str> = log.lines().filter(|l| !l.starts_with("info:    ")).collect();
    eprintln!("run log (DXVK's stderr):\n{}", short.join("\n"));
    assert!(
        ran.code == Some(0) && ran.out().contains("pixel ok"),
        "the fixture did not render in the sandbox"
    );
    assert!(log.contains("DXVK: v3.1.1"), "DXVK did not load");
    let adapter = ran
        .out()
        .lines()
        .find_map(|l| l.strip_prefix("adapter: ").map(|a| a.trim().to_owned()))
        .unwrap_or_default();
    assert!(
        log.contains(&format!("info:  {adapter}:")),
        "DXVK did not create a device on {adapter:?}"
    );
    assert!(
        adapter.contains(&filter),
        "rendered on {adapter:?}, not the filtered {filter:?}"
    );
    eprintln!("RECORDED: pixel ok on {adapter:?} under the default sandbox");
    rig.rt(&["remove", &id]).expect_ok();
    rig.finish();
}
