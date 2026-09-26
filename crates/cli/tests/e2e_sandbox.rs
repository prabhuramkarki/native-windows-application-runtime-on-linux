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
//!
//! The `syscall_escape_*` tests (Phase 5B, at the end) need no Wine: they run a Linux helper (this test binary)
//! through the real shim and are NOT ignored (glibc hosts only). They skip visibly without bwrap, seccomp, Landlock
//! (the Landlock half of `syscall_escape_2`) or IA32 emulation (the `int 0x80` rows); with `RUNTIME_REQUIRE_BWRAP=1`
//! (which CI's `test` job sets) each of those is a failure instead, so that setting now also requires seccomp,
//! Landlock and IA32 emulation. One skip stays a skip even then: Yama `ptrace_scope` 2 or 3, where no unprivileged
//! attach can succeed and `syscall_escape_2` has nothing to observe.
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

/// The run itself was not refused (the sandbox's or the limits' refusal, a systemd-run failure), so what ended the
/// program was the limit under test.
fn limits_applied(stderr: &str) -> bool {
    !["refused", "cannot be applied", "Failed to"]
        .iter()
        .any(|t| stderr.contains(t))
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
/// the limit that stopped it. Never an unbounded bomb: the probe stops at its cap (100 here, 5000 in the fixture) and
/// ends every copy, so if the limit silently failed the bomb would run 100 copies, print `FORKBOMB-OK` and exit 0,
/// which fails `fails_boxed` below.
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
    let ran = s.fails_boxed(&s.id, &["forkbomb", "100"]);
    assert!(
        limits_applied(&ran.err()),
        "the run itself failed, the limit was not tested: {}",
        ran.report()
    );
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
    // 143: systemd stopped the scope after the kernel's OOM kill inside it. Not "any failure": a refused run (126)
    // or a systemd-run failure (1) would not test the limit at all.
    assert!(
        ran.code == Some(143) && !ran.out().contains("MEMHOG-OK"),
        "the hog was not OOM-killed under memory=128: {}",
        ran.report()
    );
    assert!(limits_applied(&ran.err()), "{}", ran.report());
    assert!(
        ran.err()
            .contains("note: the program was terminated (exit 143); if it exceeded its memory limit"),
        "{}",
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

// ---------------------------------------------------------------------------------------------------------------
// Phase 5B: syscall-level escape tests. A Windows program cannot make raw Linux syscalls, so a Linux-side helper
// does: THIS test binary, re-executed inside the sandbox (`--rt-syscall-probe <mode>`, dispatched from
// `.init_array` before the test harness starts, so the helper is single-threaded and never runs a test). It is
// bound read-only through the renderer's ordinary `ro_binds` (which also gives it a read-only Landlock rule), and
// the shim is the REAL `runtime` binary (`CARGO_BIN_EXE_runtime`, through a `Host` whose `runtime_exe` names it):
// systemd-run scope + bwrap + `runtime sandbox-init` (Landlock, seccomp) exactly as `runtime run` renders them.
//
// The oracle: the same helper, the same bwrap command with the shim's words removed (bwrap only: same binds and
// namespaces, no Landlock, no seccomp). A row whose unfiltered answer is also EPERM has no oracle here; the table
// says so and that row rests on `rt_sandbox`'s interpreter and real-kernel tests.
// ---------------------------------------------------------------------------------------------------------------

/// The syscall-level tests and their helper. The helper is dispatched from `.init_array`, which relies on glibc
/// passing `(argc, argv, envp)` to its entries; on other C libraries the tests are not compiled (and so not run).
#[cfg(all(target_os = "linux", target_env = "gnu"))]
mod syscall_escape {
    use super::*;

    const PROBE_FLAG: &[u8] = b"--rt-syscall-probe";

    /// glibc calls `.init_array` entries before `main` with `(argc, argv, envp)`; for any other argv this returns and
    /// the test harness starts as usual.
    #[used]
    #[unsafe(link_section = ".init_array")]
    static SYSCALL_PROBE: extern "C" fn(libc::c_int, *const *const libc::c_char, *const *const libc::c_char) =
        syscall_probe_entry;

    extern "C" fn syscall_probe_entry(
        argc: libc::c_int,
        argv: *const *const libc::c_char,
        _: *const *const libc::c_char,
    ) {
        let argc = usize::try_from(argc).unwrap_or(0);
        // SAFETY: glibc passes the process's own argc and argv: `argc` live NUL-terminated strings.
        let arg = |i: usize| unsafe { std::ffi::CStr::from_ptr(*argv.add(i)) }.to_bytes();
        if argc < 3 || arg(1) != PROBE_FLAG {
            return;
        }
        let args: Vec<String> = (2..argc)
            .map(|i| String::from_utf8_lossy(arg(i)).into_owned())
            .collect();
        probe::main(&args)
    }

    /// The helper's side. Every call is made in a forked child that reports 0 (success) or the errno through its exit
    /// status, so a call that succeeds (a new user namespace, a tracer) changes nothing for the next one.
    mod probe {
        use std::io::Write;

        pub type Call = fn() -> i32;

        fn errno() -> i32 {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(255)
        }
        fn check(r: libc::c_long) -> i32 {
            if r < 0 { errno() } else { 0 }
        }
        fn check_fd(r: libc::c_long) -> i32 {
            if r >= 0 {
                // SAFETY: a descriptor the probe just created and nothing else uses.
                unsafe { libc::close(r as i32) };
            }
            check(r)
        }

        const THREAD_FLAGS: libc::c_long = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as libc::c_long;
        const UFFD_USER_MODE_ONLY: libc::c_long = 1; // <linux/userfaultfd.h>
        const X32_SYSCALL_BIT: libc::c_long = 0x4000_0000;

        // SAFETY (every call below): one raw syscall with integer arguments, NULL, a deliberately invalid pointer the
        // kernel only validates, or pointers to live locals of the size the kernel reads or writes.
        fn getpid() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_getpid) })
        }
        /// A real thread: glibc tries `clone3` (ENOSYS under the filter) and falls back to `clone` with thread flags.
        fn thread() -> i32 {
            match std::thread::Builder::new().spawn(|| 7).map(|h| h.join()) {
                Ok(Ok(7)) => 0,
                Ok(_) => 254,
                Err(e) => e.raw_os_error().unwrap_or(253),
            }
        }
        fn mmap_exec() -> i32 {
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p == libc::MAP_FAILED {
                return errno();
            }
            unsafe { libc::munmap(p, 4096) };
            0
        }
        fn socket(domain: libc::c_int, ty: libc::c_int) -> i32 {
            check_fd(unsafe { libc::syscall(libc::SYS_socket, domain, ty | libc::SOCK_CLOEXEC, 0) })
        }
        fn socket_unix() -> i32 {
            socket(libc::AF_UNIX, libc::SOCK_STREAM)
        }
        fn socket_vsock() -> i32 {
            socket(libc::AF_VSOCK, libc::SOCK_STREAM)
        }
        fn socket_alg() -> i32 {
            socket(libc::AF_ALG, libc::SOCK_SEQPACKET)
        }
        /// A new pty pair, (master, slave).
        fn pty() -> Result<(i32, i32), i32> {
            let (mut m, mut s) = (-1, -1);
            let r = unsafe { libc::openpty(&mut m, &mut s, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()) };
            if r != 0 { Err(errno()) } else { Ok((m, s)) }
        }
        fn tcgets() -> i32 {
            let (_m, s) = match pty() {
                Ok(p) => p,
                Err(e) => return e,
            };
            // SAFETY: an all-zero termios is a valid value.
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            check(unsafe { libc::syscall(libc::SYS_ioctl, s, libc::TCGETS, &mut t) })
        }
        /// Terminal injection in its strongest form: a new session whose controlling terminal is the pty, then
        /// `TIOCSTI` into it (without the filter: allowed where `dev.tty.legacy_tiocsti` is 1, `EIO` where it is 0).
        fn tiocsti() -> i32 {
            if unsafe { libc::setsid() } < 0 {
                return 250;
            }
            let (_m, s) = match pty() {
                Ok(p) => p,
                Err(_) => return 251,
            };
            if unsafe { libc::ioctl(s, libc::TIOCSCTTY, 0) } != 0 {
                return 252;
            }
            let c: u8 = b'x';
            check(unsafe { libc::syscall(libc::SYS_ioctl, s, libc::TIOCSTI, &c) })
        }
        fn ptrace_traceme() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) })
        }
        fn ptrace_seize_pid0() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_SEIZE, 0, 0, 0) })
        }
        fn unshare_newuser() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER) })
        }
        /// `CLONE_PARENT` is not an unshare flag: the kernel answers EINVAL before any permission check.
        fn unshare_newuser_invalid() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER | libc::CLONE_PARENT) })
        }
        /// A fork into a new user namespace; the child `_exit`s at once.
        fn clone_newuser() -> i32 {
            let flags = (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_long;
            let r = unsafe { libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) };
            if r == 0 {
                unsafe { libc::_exit(0) };
            }
            if r > 0 {
                unsafe { libc::waitpid(r as libc::pid_t, std::ptr::null_mut(), 0) };
            }
            check(r)
        }
        /// Thread flags plus `CLONE_PIDFD` are refused by the kernel with EINVAL before anything is created.
        fn clone_newuser_invalid() -> i32 {
            let flags = THREAD_FLAGS | (libc::CLONE_PIDFD | libc::CLONE_NEWUSER) as libc::c_long;
            check(unsafe { libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) })
        }
        fn clone3_null() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_clone3, 0, 0) })
        }
        /// A bad `type` pointer: the kernel copies it (EFAULT) before it checks privileges.
        fn mount_bad_type() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_mount, c"none".as_ptr(), c"/".as_ptr(), 1usize, 0, 0) })
        }
        fn keyctl_unknown() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_keyctl, 9999, 0, 0, 0, 0) })
        }
        fn bpf_unknown() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_bpf, 9999, 0, 0) })
        }
        fn perf_event_open_null() -> i32 {
            check_fd(unsafe { libc::syscall(libc::SYS_perf_event_open, 0, 0, -1, -1, 0) })
        }
        fn userfaultfd_user_mode() -> i32 {
            check_fd(unsafe {
                libc::syscall(
                    libc::SYS_userfaultfd,
                    UFFD_USER_MODE_ONLY | libc::O_CLOEXEC as libc::c_long,
                )
            })
        }
        fn open_by_handle_null() -> i32 {
            check_fd(unsafe { libc::syscall(libc::SYS_open_by_handle_at, libc::AT_FDCWD, 0, libc::O_RDONLY) })
        }
        fn io_uring_setup_null() -> i32 {
            check_fd(unsafe { libc::syscall(libc::SYS_io_uring_setup, 1, 0) })
        }
        // The rest of spec criterion 1's classes. Arguments are chosen so the call does nothing even if the filter let
        // it through (and even as root): NULL or bad pointers, fd -1, invalid flags or magic numbers.
        fn pivot_root_null() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_pivot_root, 0, 0) })
        }
        fn chroot_null() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_chroot, 0) })
        }
        fn setns_bad_fd() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_setns, -1, 0) })
        }
        /// 0x100 is no umount flag: EINVAL before anything else.
        fn umount2_bad_flags() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_umount2, 0, 0x100) })
        }
        /// 1000 segments (the limit is 16) and an unknown flag.
        fn kexec_load_invalid() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_kexec_load, 0, 1000, 0, 0x10) })
        }
        /// SYSLOG_ACTION_SIZE_BUFFER: at most reads the log's size.
        fn syslog_size() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_syslog, 10, 0, 0) })
        }
        /// A bad pointer (acct(NULL) would switch accounting off).
        fn acct_bad_pointer() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_acct, 1usize) })
        }
        /// Quota type 0xff is out of range: EINVAL.
        fn quotactl_bad_type() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_quotactl, 0xff, 0, 0, 0) })
        }
        /// Flag bit 31 is no swap flag: EINVAL.
        fn swapon_bad_flags() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_swapon, 0, 0x8000_0000u32) })
        }
        fn swapoff_bad_pointer() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_swapoff, 1usize) })
        }
        /// Magic numbers 0: never a reboot.
        fn reboot_bad_magic() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_reboot, 0, 0, 0, 0) })
        }
        fn init_module_null() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_init_module, 0, 0, 0) })
        }
        fn finit_module_bad_fd() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_finit_module, -1, c"".as_ptr(), 0) })
        }
        fn delete_module_null() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_delete_module, 0, 0) })
        }
        fn add_key_null() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_add_key, 0, 0, 0, 0, 0) })
        }
        fn request_key_null() -> i32 {
            check(unsafe { libc::syscall(libc::SYS_request_key, 0, 0, 0, 0) })
        }
        fn tioclinux() -> i32 {
            let (_m, s) = match pty() {
                Ok(p) => p,
                Err(e) => return e,
            };
            let sub: u8 = 0;
            check(unsafe { libc::syscall(libc::SYS_ioctl, s, libc::TIOCLINUX, &sub) })
        }
        fn x32_getpid() -> i32 {
            check(unsafe { libc::syscall(X32_SYSCALL_BIT | libc::SYS_getpid) })
        }
        /// An i386 syscall through `int 0x80` with its first argument (`ebx`) 0; 0 or the errno.
        #[cfg(target_arch = "x86_64")]
        fn int80(nr: i64) -> i32 {
            let mut rax = nr;
            // SAFETY: `int 0x80` enters the i386 ABI; getpid touches no memory and set_thread_area with a NULL
            // descriptor only makes the kernel fail its copy. rbx (reserved by LLVM) is saved in a scratch register
            // and restored; the 32-bit entry may not preserve r8-r11, so they are clobbered; no stack is used.
            unsafe {
                std::arch::asm!("mov {save}, rbx", "xor ebx, ebx", "int 0x80", "mov rbx, {save}", save = out(reg) _,
                inout("rax") rax, out("r8") _, out("r9") _, out("r10") _, out("r11") _, options(nostack));
            }
            let r = rax as i32;
            if (-4095..0).contains(&r) { -r } else { 0 }
        }
        #[cfg(target_arch = "x86_64")]
        fn int80_getpid() -> i32 {
            int80(20)
        }
        /// The one i386 call the filter lets through (Wine's 32-bit `%fs`); NULL makes the kernel answer EFAULT.
        #[cfg(target_arch = "x86_64")]
        fn int80_set_thread_area_null() -> i32 {
            int80(243)
        }

        /// Every row: its name and the call. The expectations live in the test (`ROWS`).
        pub const CALLS: &[(&str, Call)] = &[
            ("getpid", getpid),
            ("thread (clone3 -> clone fallback)", thread),
            ("mmap(PROT_EXEC)", mmap_exec),
            ("socket(AF_UNIX)", socket_unix),
            ("ioctl(TCGETS) on a pty", tcgets),
            #[cfg(target_arch = "x86_64")]
            ("int 0x80 set_thread_area(NULL)", int80_set_thread_area_null),
            ("ptrace(TRACEME)", ptrace_traceme),
            ("ptrace(SEIZE, 0)", ptrace_seize_pid0),
            ("unshare(NEWUSER)", unshare_newuser),
            ("unshare(NEWUSER|PARENT)", unshare_newuser_invalid),
            ("clone(NEWUSER|SIGCHLD)", clone_newuser),
            ("clone(thread flags|PIDFD|NEWUSER)", clone_newuser_invalid),
            ("clone3(NULL, 0)", clone3_null),
            ("mount(bad type)", mount_bad_type),
            ("keyctl(9999)", keyctl_unknown),
            ("bpf(9999)", bpf_unknown),
            ("perf_event_open(NULL)", perf_event_open_null),
            ("userfaultfd(USER_MODE_ONLY)", userfaultfd_user_mode),
            ("open_by_handle_at(NULL)", open_by_handle_null),
            ("io_uring_setup(1, NULL)", io_uring_setup_null),
            ("ioctl(TIOCSTI) into its own terminal", tiocsti),
            ("pivot_root(NULL, NULL)", pivot_root_null),
            ("chroot(NULL)", chroot_null),
            ("setns(-1, 0)", setns_bad_fd),
            ("umount2(NULL, bad flags)", umount2_bad_flags),
            ("kexec_load(1000 segments, bad flag)", kexec_load_invalid),
            ("syslog(SIZE_BUFFER)", syslog_size),
            ("acct(bad pointer)", acct_bad_pointer),
            ("quotactl(bad type)", quotactl_bad_type),
            ("swapon(NULL, bad flags)", swapon_bad_flags),
            ("swapoff(bad pointer)", swapoff_bad_pointer),
            ("reboot(bad magic)", reboot_bad_magic),
            ("init_module(NULL)", init_module_null),
            ("finit_module(-1)", finit_module_bad_fd),
            ("delete_module(NULL)", delete_module_null),
            ("add_key(NULL)", add_key_null),
            ("request_key(NULL)", request_key_null),
            ("ioctl(TIOCLINUX) on a pty", tioclinux),
            ("socket(AF_VSOCK)", socket_vsock),
            ("socket(AF_ALG)", socket_alg),
            #[cfg(target_arch = "x86_64")]
            ("int 0x80 getpid", int80_getpid),
            ("x32 getpid", x32_getpid),
        ];

        /// `f` in a forked child: its 0/errno, or `1000 + signal` when the child was killed.
        fn in_child(f: Call) -> i32 {
            // SAFETY: the helper is single-threaded (it runs before the harness starts any thread).
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                let e = f();
                unsafe { libc::_exit(e.clamp(0, 255)) };
            }
            if pid < 0 {
                return 2000 + errno();
            }
            let mut st = 0;
            unsafe { libc::waitpid(pid, &mut st, 0) };
            if libc::WIFEXITED(st) {
                libc::WEXITSTATUS(st)
            } else {
                1000 + libc::WTERMSIG(st)
            }
        }

        /// `PTRACE_ATTACH` of `pid` and an open of its `/proc/<pid>/mem`, one line each; then `pid` is killed.
        fn attach(pid: libc::pid_t) -> ! {
            let r = check(unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_ATTACH, pid, 0, 0) });
            if r == 0 {
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_DETACH, pid, 0, 0) };
            }
            let mem = std::ffi::CString::new(format!("/proc/{pid}/mem")).unwrap();
            let m = check_fd(unsafe { libc::open(mem.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) } as _);
            println!("attach\t{r}\nprocmem\t{m}");
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            std::io::stdout().flush().unwrap();
            std::process::exit(0)
        }

        pub fn main(args: &[String]) -> ! {
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            match a.as_slice() {
                ["calls"] => {
                    for (name, f) in CALLS {
                        println!("{name}\t{}", in_child(*f));
                    }
                }
                // A child that lives at most 30 s, then either ptrace it from here (the same Landlock domain) or run
                // `attach` through a SECOND shim first (a new, nested domain the child is outside of).
                ["domain", shim, how] => {
                    let child = unsafe { libc::fork() };
                    if child == 0 {
                        unsafe {
                            libc::sleep(30);
                            libc::_exit(0)
                        };
                    }
                    std::io::stdout().flush().unwrap();
                    if *how == "same" {
                        attach(child);
                    }
                    let me = std::env::current_exe().unwrap();
                    let err = std::os::unix::process::CommandExt::exec(
                        std::process::Command::new(shim)
                            .args(["sandbox-init", "--v1", "--rule", "ro:/", "--"])
                            .arg(me)
                            .args([std::str::from_utf8(super::PROBE_FLAG).unwrap(), "attach"])
                            .arg(child.to_string()),
                    );
                    eprintln!("exec {shim}: {err}");
                    std::process::exit(3)
                }
                ["attach", pid] => attach(pid.parse().unwrap()),
                _ => {
                    eprintln!("unknown probe mode {a:?}");
                    std::process::exit(2)
                }
            }
            std::io::stdout().flush().unwrap();
            std::process::exit(0)
        }
    }

    /// The real host, except that the sandbox's shim is the `runtime` binary under test (not this test binary).
    struct ShimHost(PathBuf);

    impl rt_sandbox::Host for ShimHost {
        fn env(&self, name: &str) -> Option<std::ffi::OsString> {
            rt_sandbox::RealHost.env(name)
        }
        fn exists(&self, p: &Path) -> bool {
            rt_sandbox::RealHost.exists(p)
        }
        fn is_socket(&self, p: &Path) -> bool {
            rt_sandbox::RealHost.is_socket(p)
        }
        fn is_file(&self, p: &Path) -> bool {
            rt_sandbox::RealHost.is_file(p)
        }
        fn resolve(&self, p: &Path) -> Option<PathBuf> {
            rt_sandbox::RealHost.resolve(p)
        }
        fn uid(&self) -> u32 {
            rt_sandbox::RealHost.uid()
        }
        fn runtime_exe(&self) -> Option<PathBuf> {
            Some(self.0.clone())
        }
        fn scopes(&self) -> Result<rt_sandbox::ScopeSupport, String> {
            rt_sandbox::RealHost.scopes()
        }
    }

    fn required() -> bool {
        std::env::var_os("RUNTIME_REQUIRE_BWRAP").is_some_and(|v| v == "1")
    }

    /// Which sandbox renders the helper's command.
    #[derive(Clone, Copy, PartialEq)]
    enum Profile {
        /// The app sandbox's default profile, as `runtime run` renders it (scope, bwrap, the real shim).
        App,
        /// The installer sandbox (`rt_installer::InstallerSandbox`, through its production constructor and `wrap`),
        /// as `runtime install`/`uninstall`/`deps --install` render it: bwrap and the real shim, no scope.
        Installer,
    }

    /// Runs the helper with `args` under the default profile exactly as `runtime run` renders it (scope, bwrap, the
    /// real shim), or with `bwrap_only` the same command line with the shim's words cut out. Returns its stdout,
    /// checked to have exited 0.
    fn in_sandbox(args: &[&str], bwrap_only: bool) -> String {
        in_profile(Profile::App, args, bwrap_only)
    }

    /// [`in_sandbox`] under `profile`.
    fn in_profile(profile: Profile, args: &[&str], bwrap_only: bool) -> String {
        let bwrap = rt_sandbox::find_bwrap_on_path().unwrap();
        let shim = PathBuf::from(env!("CARGO_BIN_EXE_runtime")).canonicalize().unwrap();
        let helper = std::env::current_exe().unwrap().canonicalize().unwrap();
        let td = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let app = td.path().canonicalize().unwrap().join("apps/a");
        let (prefix, home) = (app.join("prefix"), app.join("runtime/home"));
        fs::create_dir_all(prefix.join("drive_c")).unwrap();
        fs::create_dir_all(&home).unwrap();
        let mut cmd = std::process::Command::new(&helper);
        cmd.arg(std::str::from_utf8(PROBE_FLAG).unwrap())
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("WINEPREFIX", &prefix)
            .env("HOME", &home)
            .current_dir(prefix.join("drive_c"));
        if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
            cmd.env("XDG_RUNTIME_DIR", rt); // systemd-run --user needs it
        }
        let boxed = if profile == Profile::Installer {
            // The app's environment as the store makes it (the installer sandbox binds its prefix); the helper is
            // bound like the backend's dll dirs (read-only, with a read-only Landlock rule).
            let env = rt_core::Store::new(app.parent().unwrap())
                .unwrap()
                .get(&rt_core::AppId::parse("a").unwrap())
                .unwrap();
            let opts = rt_installer::SandboxOpts {
                allow_network: false,
                extra_ro_binds: vec![helper],
            };
            let boxed = rt_installer::InstallerSandbox::new(bwrap, &shim).wrap(cmd, &env, &opts);
            assert!(
                boxed.get_program() != "/bin/sh",
                "the installer sandbox refused: {boxed:?}"
            );
            boxed
        } else {
            let sb = rt_sandbox::AppSandbox::new(
                bwrap,
                rt_sandbox::Permissions::default(),
                vec![helper],
                std::sync::Arc::new(ShimHost(shim.clone())),
            );
            sb.render(&cmd).expect("the default profile renders")
        };
        eprintln!(
            "launched by {:?} (systemd-run: the task limit's scope; the installer sandbox has none)",
            boxed.get_program()
        );
        let all: Vec<&std::ffi::OsStr> = boxed.get_args().collect();
        let at = all
            .iter()
            .position(|a| *a == "sandbox-init")
            .expect("the shim is in the command");
        assert_eq!(Path::new(all[at - 1]), shim, "the shim is the runtime binary");
        let end = at + all[at..].iter().position(|a| *a == "--").expect("the shim's `--`");
        let mut bare = std::process::Command::new(boxed.get_program());
        bare.args(&all[..at - 1]).args(&all[end + 1..]).env_clear();
        for (k, v) in boxed.get_envs() {
            if let Some(v) = v {
                bare.env(k, v);
            }
        }
        if let Some(d) = boxed.get_current_dir() {
            bare.current_dir(d);
        }
        let run = |mut c: std::process::Command, what: &str| {
            let out = c.output().unwrap();
            let (so, se) = (
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            );
            assert!(out.status.success(), "{what}: {:?}\n{so}\n{se}", out.status);
            so
        };
        if bwrap_only {
            run(bare, "bwrap only")
        } else {
            run(boxed, "through the shim")
        }
    }

    fn rows(out: &str) -> std::collections::BTreeMap<String, i32> {
        out.lines()
            .filter_map(|l| l.rsplit_once('\t'))
            .map(|(k, v)| (k.to_owned(), v.parse().unwrap()))
            .collect()
    }

    /// Whether the shim can install a seccomp filter here (it refuses every run otherwise); `false` after SKIPPED,
    /// a failure under `RUNTIME_REQUIRE_BWRAP=1`.
    fn seccomp_works(test: &str) -> bool {
        // SAFETY: PR_GET_SECCOMP only reads this process's mode.
        if unsafe { libc::prctl(libc::PR_GET_SECCOMP) } >= 0 {
            return true;
        }
        assert!(!required(), "RUNTIME_REQUIRE_BWRAP=1 but this kernel has no seccomp");
        eprintln!("SKIPPED {test}: this kernel has no seccomp");
        false
    }

    /// What a row's call must return.
    #[derive(Clone, Copy, Debug)]
    enum Want {
        Ok,
        Errno(i32),
        /// One of these (0 = success).
        OneOf(&'static [i32]),
        /// Not EPERM: the kernel answered, whatever it said.
        NotEperm,
        /// Host policy decides (Yama, AppArmor's user-namespace restriction, sysctls, loaded modules): anything. The
        /// row has an oracle only where this differs from the filtered answer, and the test says which.
        Host,
    }

    impl Want {
        fn allows(self, got: i32) -> bool {
            match self {
                Want::Ok => got == 0,
                Want::Errno(e) => got == e,
                Want::OneOf(v) => v.contains(&got),
                Want::NotEperm => got != libc::EPERM && got < 1000,
                Want::Host => got < 1000,
            }
        }
    }

    const EPERM: Want = Want::Errno(libc::EPERM);

    /// (row, through the shim, bwrap only). The allowed rows come first; a denied row is EPERM through the shim and
    /// something else without it (the distinguishing arguments make the kernel's own answer deterministic).
    const ROWS: &[(&str, Want, Want)] = &[
        ("getpid", Want::Ok, Want::Ok),
        ("thread (clone3 -> clone fallback)", Want::Ok, Want::Ok),
        ("mmap(PROT_EXEC)", Want::Ok, Want::Ok),
        ("socket(AF_UNIX)", Want::Ok, Want::Ok),
        ("ioctl(TCGETS) on a pty", Want::Ok, Want::Ok),
        #[cfg(target_arch = "x86_64")]
        (
            "int 0x80 set_thread_area(NULL)",
            Want::Errno(libc::EFAULT),
            Want::Errno(libc::EFAULT),
        ),
        ("ptrace(TRACEME)", EPERM, Want::Host),
        ("ptrace(SEIZE, 0)", EPERM, Want::Errno(libc::ESRCH)),
        ("unshare(NEWUSER)", EPERM, Want::Host),
        ("unshare(NEWUSER|PARENT)", EPERM, Want::Errno(libc::EINVAL)),
        ("clone(NEWUSER|SIGCHLD)", EPERM, Want::Host),
        ("clone(thread flags|PIDFD|NEWUSER)", EPERM, Want::Errno(libc::EINVAL)),
        ("clone3(NULL, 0)", Want::Errno(libc::ENOSYS), Want::Host),
        ("mount(bad type)", EPERM, Want::Errno(libc::EFAULT)),
        ("keyctl(9999)", EPERM, Want::NotEperm),
        ("bpf(9999)", EPERM, Want::Host),
        ("perf_event_open(NULL)", EPERM, Want::NotEperm),
        ("userfaultfd(USER_MODE_ONLY)", EPERM, Want::Host),
        ("open_by_handle_at(NULL)", EPERM, Want::Host),
        ("io_uring_setup(1, NULL)", EPERM, Want::Host),
        // allowed where `dev.tty.legacy_tiocsti` is 1, EIO where it is 0
        (
            "ioctl(TIOCSTI) into its own terminal",
            EPERM,
            Want::OneOf(&[0, libc::EIO]),
        ),
        // EFAULT on Linux 7.0; older kernels check the capability first (EPERM)
        ("pivot_root(NULL, NULL)", EPERM, Want::Host),
        ("chroot(NULL)", EPERM, Want::Errno(libc::EFAULT)),
        ("setns(-1, 0)", EPERM, Want::Errno(libc::EBADF)),
        ("umount2(NULL, bad flags)", EPERM, Want::Errno(libc::EINVAL)),
        // Capability checks come first in these: EPERM without the filter too for an unprivileged user (no oracle)
        ("kexec_load(1000 segments, bad flag)", EPERM, Want::Host),
        ("syslog(SIZE_BUFFER)", EPERM, Want::Host),
        ("acct(bad pointer)", EPERM, Want::Host),
        ("quotactl(bad type)", EPERM, Want::Errno(libc::EINVAL)),
        ("swapon(NULL, bad flags)", EPERM, Want::Errno(libc::EINVAL)),
        ("swapoff(bad pointer)", EPERM, Want::Host),
        ("reboot(bad magic)", EPERM, Want::Host),
        ("init_module(NULL)", EPERM, Want::Host),
        ("finit_module(-1)", EPERM, Want::Host),
        ("delete_module(NULL)", EPERM, Want::Host),
        ("add_key(NULL)", EPERM, Want::Errno(libc::EFAULT)),
        ("request_key(NULL)", EPERM, Want::Errno(libc::EFAULT)),
        ("ioctl(TIOCLINUX) on a pty", EPERM, Want::NotEperm),
        ("socket(AF_VSOCK)", EPERM, Want::Host),
        ("socket(AF_ALG)", EPERM, Want::Host),
        #[cfg(target_arch = "x86_64")]
        ("int 0x80 getpid", EPERM, Want::Ok),
        // ENOSYS, or success on a kernel built with the x32 ABI
        ("x32 getpid", EPERM, Want::OneOf(&[0, libc::ENOSYS])),
    ];

    /// Phase 5B, spec criterion 1 at the syscall level: a Linux program in the REAL pipeline (the systemd-run scope
    /// when available, bwrap, the real `runtime sandbox-init` with Landlock and seccomp) gets EPERM for each denied
    /// call, and the same command with the shim cut out (bwrap alone) does not: so the filter is what refused, not
    /// bubblewrap's namespaces or host policy. The allowed rows (what Wine needs: threads through the clone3 fallback,
    /// executable memory, unix sockets, terminal ioctls, the i386 `set_thread_area`) behave the same both ways.
    #[test]
    fn syscall_escape_1_denied_calls_fail_with_eperm_through_the_shim_and_not_without_it() {
        let test = "syscall_escape_1_denied_calls_fail_with_eperm_through_the_shim_and_not_without_it";
        if !bwrap_works(test) || !seccomp_works(test) {
            return;
        }
        check_rows(Profile::App);
    }

    /// Every [`ROWS`] row through `profile` with the shim and with bwrap alone (the oracle); fails on any mismatch.
    fn check_rows(profile: Profile) {
        let (f, u) = (
            in_profile(profile, &["calls"], false),
            in_profile(profile, &["calls"], true),
        );
        let (f, u) = (rows(&f), rows(&u));
        assert_eq!(f.len(), ROWS.len(), "{f:?}");
        assert_eq!(u.len(), ROWS.len(), "{u:?}");
        let mut bad = Vec::new();
        for (name, want_f, want_u) in ROWS {
            let (got_f, got_u) = (f[*name], u[*name]);
            // IA32 emulation off: `int 0x80` faults (a signal) before seccomp sees it, with or without the filter.
            if name.starts_with("int 0x80") && got_u >= 1000 {
                assert!(
                    !required(),
                    "RUNTIME_REQUIRE_BWRAP=1 but int 0x80 kills the process ({got_u})"
                );
                eprintln!("SKIPPED {name}: the kernel has no IA32 emulation");
                continue;
            }
            let denied = matches!(want_f, Want::Errno(e) if *e == libc::EPERM || *e == libc::ENOSYS);
            let oracle = if !denied {
                "allowed"
            } else if got_u != got_f {
                "oracle"
            } else {
                "NO ORACLE here (bwrap alone answers the same): rests on rt_sandbox's seccomp tests"
            };
            eprintln!("{name:40} shim {got_f:4}  bwrap only {got_u:4}  {oracle}");
            // Every strict bwrap-only expectation of a denied row excludes EPERM, so passing it IS the oracle.
            if !want_f.allows(got_f) || !want_u.allows(got_u) {
                bad.push(format!(
                    "{name}: through the shim {got_f} (want {want_f:?}), bwrap only {got_u} (want {want_u:?})"
                ));
            }
        }
        assert!(bad.is_empty(), "SECCOMP HOLE or broken control:\n{}", bad.join("\n"));
    }

    /// Phase 5B Task 6: the installer sandbox (vendor installers, uninstallers, `deps --install` installer packages and
    /// their `reg.exe` steps) runs behind the same shim: every row, with the same oracle. Before Task 6 the installer
    /// sandbox was bubblewrap alone, which is this test's control column (`unshare(NEWUSER)` succeeded there).
    #[test]
    fn syscall_escape_4_the_installer_sandbox_denies_the_same_calls_through_the_shim() {
        let test = "syscall_escape_4_the_installer_sandbox_denies_the_same_calls_through_the_shim";
        if !bwrap_works(test) || !seccomp_works(test) {
            return;
        }
        check_rows(Profile::Installer);
    }

    /// Phase 5B: the Landlock half of the ptrace decision (`ptrace` is allowed for Wine's requests only inside an
    /// enforced Landlock domain). In the real pipeline the helper forks a child and then attaches it (PTRACE_ATTACH, one
    /// of Wine's requests) and opens its `/proc/<pid>/mem`: from the same domain both work (what wineserver does); after
    /// the helper enters a NEW, nested domain (a second `runtime sandbox-init`) the child is outside it and both are
    /// refused. Yama is not what refuses: the tracer is the child's parent in both runs, and the same-domain run
    /// succeeds. This is the only visible process outside the program's domain in production too: bwrap's pid 1.
    #[test]
    fn syscall_escape_2_ptrace_reaches_only_the_apps_own_landlock_domain() {
        let test = "syscall_escape_2_ptrace_reaches_only_the_apps_own_landlock_domain";
        if !bwrap_works(test) || !seccomp_works(test) {
            return;
        }
        // Yama 2 (admin-only attach) or 3 (no attach) refuses even the parent's attach, so neither half can succeed and
        // the property cannot be observed: a visible skip, also under RUNTIME_REQUIRE_BWRAP=1 (not a failure).
        let yama = fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope").unwrap_or_default();
        if matches!(yama.trim(), "2" | "3") {
            eprintln!(
                "SKIPPED {test}: Yama ptrace_scope is {}, which refuses every unprivileged attach",
                yama.trim()
            );
            return;
        }
        let shim = PathBuf::from(env!("CARGO_BIN_EXE_runtime")).canonicalize().unwrap();
        let shim = shim.to_str().unwrap();
        let same = in_sandbox(&["domain", shim, "same"], false);
        let same = rows(&same);
        eprintln!("same domain: {same:?}");
        if let Err(e) = rt_sandbox::landlock::abi_version() {
            // No Landlock: the strict filter, ptrace refused outright.
            assert_eq!(same["attach"], libc::EPERM, "ptrace without Landlock");
            assert!(!required(), "RUNTIME_REQUIRE_BWRAP=1 but Landlock is unavailable: {e}");
            eprintln!("SKIPPED the Landlock half of {test}: {e:?}");
            return;
        }
        assert_eq!((same["attach"], same["procmem"]), (0, 0), "Wine's own-process ptrace");
        let nested = in_sandbox(&["domain", shim, "nested"], false);
        let nested = rows(&nested);
        eprintln!("nested domain: {nested:?}");
        assert_eq!(
            (nested["attach"], nested["procmem"]),
            (libc::EPERM, libc::EACCES),
            "LANDLOCK HOLE: a process outside the tracer's domain was reachable"
        );
    }

    /// docs/SECURITY.md's pipeline table lists exactly [`ROWS`], in order, each with its class: `allowed` (not refused
    /// through the shim), `strict` (a specific non-EPERM answer from bwrap alone is required) or `host` (host policy
    /// decides bwrap alone's answer, so the row may have no oracle).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn syscall_escape_3_the_security_table_is_the_test_list() {
        let doc = include_str!("../../../docs/SECURITY.md");
        let start = doc.find("<!-- pipeline-rows:").expect("the start marker");
        let end = doc.find("<!-- /pipeline-rows -->").expect("the end marker");
        let got: Vec<(String, String)> = doc[start..end]
            .lines()
            .filter(|l| l.starts_with("| `"))
            .map(|l| {
                let cells: Vec<&str> = l.split(" | ").collect();
                (
                    cells[0]
                        .trim_start_matches("| `")
                        .trim_end_matches('`')
                        .replace("\\|", "|"),
                    cells[1].to_owned(),
                )
            })
            .collect();
        let want: Vec<(String, String)> = ROWS
            .iter()
            .map(|(name, f, u)| {
                let class = match (f, u) {
                    (Want::Errno(e), _) if *e != libc::EPERM && *e != libc::ENOSYS => "allowed",
                    (Want::Ok, _) => "allowed",
                    (_, Want::Host) => "host",
                    _ => "strict",
                };
                (name.to_string(), class.to_owned())
            })
            .collect();
        assert_eq!(got, want, "update the pipeline table in docs/SECURITY.md");
    }
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
