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
        // Grants below /tmp are refused and the sandbox's /tmp is a private tmpfs: the suite would prove nothing.
        assert!(
            !tmp.canonicalize().unwrap().starts_with("/tmp"),
            "CARGO_TARGET_TMPDIR {} is under /tmp: run with a target directory outside /tmp (CARGO_TARGET_DIR)",
            tmp.display()
        );
        let base = tempfile::tempdir_in(tmp).unwrap();
        let home = base.path().join("home");
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::write(home.join(".ssh/id_test"), "secret").unwrap();
        let rig = Rig::new_in(tmp);
        rig.set_cleanup_env(&[("HOME", home.to_str().unwrap())]);
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

/// Whether the shim enforces Landlock on this host (it then also refuses to list bwrap's skeleton directories: the
/// parents of a bound directory, which have no rule).
fn landlock() -> bool {
    rt_sandbox::landlock::abi_version().is_ok()
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

    // The apps directory is bwrap's skeleton for the bound prefix: it lists only this app from inside, or (with
    // Landlock, which has no rule for the skeleton) cannot be listed at all; both from outside.
    let apps = unix(&s.rig.apps());
    if landlock() {
        s.fails_boxed(&s.id, &["list", &apps]);
    } else {
        let inside = s.works_boxed(&s.id, &["list", &apps]).out();
        assert!(inside.contains(&s.id) && !inside.contains(&other), "{inside}");
    }
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
    // The parent is not shared: its other entries stay invisible (with Landlock it cannot even be listed).
    s.fails_boxed(&s.id, &["read", &unix(&sibling)]);
    if landlock() {
        s.fails_boxed(&s.id, &["list", &unix(&parent)]);
    } else {
        let listed = s.works_boxed(&s.id, &["list", &unix(&parent)]).out();
        assert!(listed.contains("granted") && !listed.contains("sibling"), "{listed}");
    }
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

/// Phase 5B: the Windows program (a Wine process) runs under the `sandbox-init` shim's seccomp filter with no new
/// privileges; unsandboxed it does not.
#[test]
#[ignore = "needs Wine, bwrap and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_9_the_program_runs_under_the_seccomp_filter() {
    let Some(s) = Suite::new("e2e_real_wine_sandbox_9_the_program_runs_under_the_seccomp_filter") else {
        return;
    };
    let boxed = s.works_boxed(&s.id, &["status"]).out();
    assert!(
        boxed.contains("Seccomp:\t2") && boxed.contains("NoNewPrivs:\t1"),
        "{boxed}"
    );
    let unboxed = s.works_unboxed(&s.id, &["status"]).out();
    assert!(unboxed.contains("Seccomp:\t0"), "{unboxed}");
    s.finish(&[]);
}

/// Phase 5B: what wineserver does with `ptrace` (another process's memory; a suspended thread's registers and
/// hardware breakpoints) still works under the filter, because Landlock confines `ptrace` to the app's own
/// processes (see `rt_sandbox::seccomp`). Without Landlock `ptrace` stays denied and the memory modes fail.
#[test]
#[ignore = "needs Wine, bwrap and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_10_cross_process_memory_and_thread_contexts_work() {
    let Some(s) = Suite::new("e2e_real_wine_sandbox_10_cross_process_memory_and_thread_contexts_work") else {
        return;
    };
    let landlock = landlock();
    for mode in ["readmem", "writemem", "threadctx", "dbgregs"] {
        s.works_unboxed(&s.id, &[mode]);
        assert!(
            s.rig.wait_for_no_wineserver(Duration::from_secs(15)),
            "wineserver lingers"
        );
        if landlock || !mode.ends_with("mem") {
            s.works_boxed(&s.id, &[mode]);
        } else {
            s.fails_boxed(&s.id, &[mode]);
        }
    }
    s.finish(&[]);
}

/// Whether `systemd-run --user` scopes work here (the limits tests need them); `false` after saying SKIPPED, a
/// failure with `RUNTIME_REQUIRE_BWRAP=1` (a host without a user manager cannot pass for protected).
fn scopes_work(test: &str) -> bool {
    let got = rt_sandbox::find_systemd_run_on_path()
        .ok_or_else(|| "systemd-run is not on PATH".to_owned())
        .and_then(|s| rt_sandbox::probe_limits(&s, std::env::var_os("XDG_RUNTIME_DIR").as_deref()));
    match got {
        Ok(s)
            if ["cpu", "memory", "pids"]
                .iter()
                .all(|c| s.controllers.iter().any(|h| h == c)) =>
        {
            true
        }
        other => {
            assert!(
                std::env::var_os("RUNTIME_REQUIRE_BWRAP").is_none_or(|v| v != "1"),
                "RUNTIME_REQUIRE_BWRAP=1 but systemd-run --user scopes cannot limit here: {other:?}"
            );
            eprintln!("SKIPPED {test}: systemd-run --user scopes cannot limit here: {other:?}");
            false
        }
    }
}

/// The desktop is fine: the user manager answers (`running`, or `degraded` for an unrelated failed unit) and a
/// new process starts, right after the app hit its limit.
fn host_is_responsive() {
    let out = std::process::Command::new("systemctl")
        .args(["--user", "is-system-running"])
        .output()
        .unwrap();
    let state = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    assert!(
        state == "running" || state == "degraded",
        "the user manager is {state:?}"
    );
    assert!(std::process::Command::new("true").status().unwrap().success());
}

/// Nothing of this suite outlives the runs: no probe process, and no scope whose command names its data dir
/// (`--collect` removes a finished scope, even a failed one, within a moment).
fn no_leftover_scopes(s: &Suite) {
    let data = s.rig.data().display().to_string();
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
        let ours: Vec<&str> = text.lines().filter(|l| l.contains(&data)).collect();
        let probes = support_pids_with("probe64.exe");
        if ours.is_empty() && probes.is_empty() {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "left behind: scopes {ours:?}, probe processes {probes:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Every pid whose command line mentions `needle`.
fn support_pids_with(needle: &str) -> Vec<u32> {
    fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let pid = e.file_name().to_str()?.parse::<u32>().ok()?;
            let cmdline = fs::read(e.path().join("cmdline")).ok()?;
            (pid != std::process::id() && cmdline.windows(needle.len()).any(|w| w == needle.as_bytes())).then_some(pid)
        })
        .collect()
}

/// Phase 5B: `tasks = 64` stops a Windows fork bomb (CreateProcess in a loop) inside the app's scope: the pids
/// controller refuses the fork (EAGAIN), CreateProcess fails, and the host never notices. The same bounded bomb
/// runs to the end under the default limit and unsandboxed (40 copies, well above what 64 tasks allow), so it is
/// the limit that stopped it. Never an unbounded bomb: the probe stops at its cap and ends every copy.
#[test]
#[ignore = "needs Wine, bwrap, systemd-run --user and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_11_a_fork_bomb_hits_the_task_limit_and_the_host_is_unharmed() {
    let test = "e2e_real_wine_sandbox_11_a_fork_bomb_hits_the_task_limit_and_the_host_is_unharmed";
    let Some(s) = Suite::new(test) else {
        return;
    };
    if !scopes_work(test) {
        return;
    }
    s.set(&["tasks=64"]).expect_ok();
    let ran = s.fails_boxed(&s.id, &["forkbomb", "200"]);
    let out = ran.out();
    let n: u32 = out
        .split("CreateProcess after ")
        .nth(1)
        .and_then(|t| t.split(' ').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no copy count: {}", ran.report()));
    eprintln!(
        "MEASURED: tasks=64 stopped the fork bomb after {n} copies in {:?}",
        ran.elapsed
    );
    assert!((1..40).contains(&n), "{n} copies under tasks=64: {}", ran.report());
    host_is_responsive();
    no_leftover_scopes(&s);
    s.set(&["tasks=default"]).expect_ok();
    let ran = s.works_boxed(&s.id, &["forkbomb", "40"]);
    assert!(ran.out().contains("FORKBOMB-OK 40 copies"), "{}", ran.report());
    s.works_unboxed(&s.id, &["forkbomb", "40"]);
    host_is_responsive();
    no_leftover_scopes(&s);
    s.finish(&[]);
}

/// Phase 5B: `memory = 128` (no swap) ends a program that touches 512 MiB: the kernel's OOM killer acts inside the
/// scope (systemd then stops the scope), the program never finishes, and the test process and the desktop go on.
/// Under the same limit a 32 MiB hog finishes, and unsandboxed a 64 MiB one does (never an unlimited 512 MiB).
#[test]
#[ignore = "needs Wine, bwrap, systemd-run --user and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_12_a_memory_hog_is_killed_at_the_memory_limit_and_the_host_is_unharmed() {
    let test = "e2e_real_wine_sandbox_12_a_memory_hog_is_killed_at_the_memory_limit_and_the_host_is_unharmed";
    let Some(s) = Suite::new(test) else {
        return;
    };
    if !scopes_work(test) {
        return;
    }
    s.set(&["memory=128"]).expect_ok();
    let ran = s.probe(&s.id, false, &["memhog", "512"]);
    eprintln!(
        "MEASURED: memory=128 ended the 512 MiB hog with {:?} after {:?}",
        ran.code, ran.elapsed
    );
    assert!(
        ran.code != Some(0) && !ran.out().contains("MEMHOG-OK"),
        "the hog finished under memory=128: {}",
        ran.report()
    );
    host_is_responsive();
    no_leftover_scopes(&s);
    let ran = s.works_boxed(&s.id, &["memhog", "32"]);
    assert!(ran.out().contains("MEMHOG-OK 32"), "{}", ran.report());
    s.works_unboxed(&s.id, &["memhog", "64"]);
    host_is_responsive();
    no_leftover_scopes(&s);
    s.finish(&[]);
}

/// Phase 5B: `systemd-run --scope` execs bwrap in place, so the process `runtime` started (and forwards Ctrl-C and
/// SIGTERM to) IS bwrap, in its own `run-p<that pid>-*.scope`; two runs of one app at once get two scopes; the
/// program's exit status comes through the scope unchanged.
#[test]
#[ignore = "needs Wine, bwrap, systemd-run --user and fixtures; run with --ignored --test-threads=1"]
fn e2e_real_wine_sandbox_13_each_run_is_its_own_scope_around_the_same_pid() {
    let test = "e2e_real_wine_sandbox_13_each_run_is_its_own_scope_around_the_same_pid";
    let Some(s) = Suite::new(test) else {
        return;
    };
    if !scopes_work(test) {
        return;
    }
    let logs = tempfile::tempdir().unwrap();
    let start = |n: usize| {
        let out = logs.path().join(format!("out-{n}"));
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_runtime"))
            .args(["run", &s.id, "--", "cgroup", "4000"])
            .env("RUNTIME_DATA_DIR", s.rig.data())
            .env("HOME", &s.home)
            .env_remove("RUNTIME_WINE")
            .env_remove("RUNTIME_WINESERVER")
            .stdin(std::process::Stdio::null())
            .stdout(fs::File::create(&out).unwrap())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        (child, out)
    };
    let runs = [start(0), start(1)];
    // The direct child of each `runtime` that runs the program (not its bwrap and systemd-run probes): bwrap
    // itself (systemd-run became it), in a scope named after its pid.
    let mut scopes = Vec::new();
    for (child, out) in &runs {
        let t0 = std::time::Instant::now();
        let kid = loop {
            let kids = fs::read_to_string(format!("/proc/{0}/task/{0}/children", child.id())).unwrap_or_default();
            // argv[0] is bwrap (after systemd-run's exec) and it runs the shim (not the bwrap probe)
            let running = |k: &u32| {
                let cmdline = fs::read(format!("/proc/{k}/cmdline")).unwrap_or_default();
                let argv0 = cmdline.split(|b| *b == 0).next().unwrap_or_default();
                argv0.ends_with(b"/bwrap") && cmdline.windows(12).any(|w| w == b"sandbox-init")
            };
            if let Some(k) = kids
                .split_whitespace()
                .filter_map(|k| k.parse::<u32>().ok())
                .find(running)
            {
                break k;
            }
            assert!(
                t0.elapsed() < Duration::from_secs(30),
                "no bwrap child of runtime: {kids:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        let cgroup = fs::read_to_string(format!("/proc/{kid}/cgroup")).unwrap_or_default();
        assert!(
            cgroup.contains(&format!("/run-p{kid}-")),
            "bwrap {kid} is not in its scope: {cgroup}"
        );
        let t0 = std::time::Instant::now();
        while !fs::read_to_string(out).unwrap_or_default().contains("CGROUP-OK") {
            assert!(t0.elapsed() < Duration::from_secs(60), "the program never started");
            std::thread::sleep(Duration::from_millis(50));
        }
        let program = fs::read_to_string(out).unwrap();
        assert!(
            program.contains(&format!("/run-p{kid}-")),
            "the program is not in bwrap's scope: {program}"
        );
        scopes.push(format!("run-p{kid}-"));
    }
    assert_ne!(scopes[0], scopes[1], "two runs, one scope");
    for (mut child, _) in runs {
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(0));
    }
    // exit statuses through the scope: a usage error is 2, a failed action 1
    assert_eq!(s.probe(&s.id, false, &["nonsense"]).code, Some(2));
    s.fails_boxed(&s.id, &["read", "C:\\no-such-file"]);
    no_leftover_scopes(&s);
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
        let mut reg = with_prefix(wine.wine_path());
        reg.args([
            "reg",
            "add",
            "HKCU\\Environment",
            "/v",
            "DXVK_FILTER_DEVICE_NAME",
            "/d",
            &filter,
            "/f",
        ]);
        let st = status_within(reg, Duration::from_secs(120));
        assert!(st.success(), "wine reg add: {st:?}");
        // Flushes the registry to disk before the sandboxed run starts its own wineserver.
        let mut wait = with_prefix(wine.wineserver_path());
        wait.arg("-w");
        assert!(status_within(wait, Duration::from_secs(60)).success());
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

/// `cmd`'s exit status, killing it (and failing the test) after `limit`.
fn status_within(mut cmd: std::process::Command, limit: Duration) -> std::process::ExitStatus {
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("cannot start {cmd:?}: {e}"));
    let start = std::time::Instant::now();
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return st;
        }
        if start.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{cmd:?} did not finish within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
