use super::*;
use rt_core::{AppId, Launcher, Store};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::time::Duration;

/// The explicit environment of a command as `name -> Some(value) | None (removed)` (mirrors `rt_core::launch`'s
/// own test helper of the same name).
fn envs(c: &Command) -> BTreeMap<String, Option<String>> {
    c.get_envs()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.map(|v| v.to_string_lossy().into_owned()),
            )
        })
        .collect()
}

fn some(v: &str) -> Option<String> {
    Some(v.to_owned())
}

fn fx() -> (tempfile::TempDir, AppEnv) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::new(tmp.path().join("apps")).unwrap();
    let env = store.create(&AppId::parse("t").unwrap()).unwrap();
    fs::create_dir_all(env.prefix()).unwrap();
    (tmp, env)
}

fn finalized(program: &str) -> Command {
    let mut c = Command::new(program);
    c.env_clear();
    c
}

fn network_opts(allow_network: bool) -> SandboxOpts {
    SandboxOpts {
        allow_network,
        ..Default::default()
    }
}

// ------------------------------------------------------------------------------ argv-builder (no bwrap run)

#[test]
fn the_exact_argv_for_a_typical_command() {
    let (_tmp, env) = fx();
    let mut cmd = finalized("/opt/wine/bin/wine64");
    cmd.arg("C:\\installer.exe").arg("/S");
    cmd.env("HOME", env.root().join("runtime/home"));
    cmd.env("WINEPREFIX", env.prefix());
    cmd.current_dir(env.drive_c());

    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &network_opts(false));

    assert_eq!(out.get_program(), "/usr/bin/bwrap");
    let prefix = env.prefix();
    let home = env.root().join("runtime/home");
    let want: Vec<OsString> = [
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--unshare-net",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--ro-bind-try",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/bin",
        "/bin",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind-try",
        "/etc/alternatives",
        "/etc/alternatives",
    ]
    .into_iter()
    .map(OsString::from)
    .chain([
        OsString::from("--bind"),
        prefix.clone().into_os_string(),
        prefix.into_os_string(),
        OsString::from("--tmpfs"),
        home.into_os_string(),
        OsString::from("--"),
        OsString::from("/opt/wine/bin/wine64"),
        OsString::from("C:\\installer.exe"),
        OsString::from("/S"),
    ])
    .collect();
    assert_eq!(out.get_args().collect::<Vec<_>>(), want);
    assert_eq!(out.get_current_dir(), Some(env.drive_c().as_path()));
    assert_eq!(
        envs(&out)["HOME"],
        some(env.root().join("runtime/home").to_str().unwrap())
    );
    assert_eq!(envs(&out)["WINEPREFIX"], some(env.prefix().to_str().unwrap()));
}

#[test]
fn allow_network_true_omits_unshare_net_and_false_includes_it() {
    let (_tmp, env) = fx();
    for (allow, expect_present) in [(false, true), (true, false)] {
        let cmd = finalized("/bin/true");
        let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &network_opts(allow));
        let has_flag = out.get_args().any(|a| a == OsStr::new("--unshare-net"));
        assert_eq!(has_flag, expect_present, "allow_network={allow}");
    }
}

#[test]
fn new_session_is_always_present() {
    let (_tmp, env) = fx();
    let cmd = finalized("/bin/true");
    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &SandboxOpts::default());
    assert!(out.get_args().any(|a| a == OsStr::new("--new-session")));
}

#[test]
fn extra_ro_binds_are_emitted_after_the_fixed_set_with_ro_bind_try() {
    let (_tmp, env) = fx();
    let cmd = finalized("/bin/true");
    let opts = SandboxOpts {
        extra_ro_binds: vec![PathBuf::from("/opt/wine-stable")],
        ..Default::default()
    };
    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &opts);
    let args: Vec<String> = out.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    let extra = args
        .windows(3)
        .position(|w| w == ["--ro-bind-try", "/opt/wine-stable", "/opt/wine-stable"])
        .unwrap_or_else(|| panic!("extra RO bind not found: {args:?}"));
    let last_fixed = args
        .windows(3)
        .position(|w| w == ["--ro-bind-try", "/etc/alternatives", "/etc/alternatives"])
        .unwrap();
    let prefix_bind = args.iter().position(|a| a == "--bind").unwrap();
    assert!(extra > last_fixed, "{args:?}");
    assert!(extra < prefix_bind, "{args:?}");
}

#[test]
fn no_dev_bind_flag_is_ever_emitted() {
    let (_tmp, env) = fx();
    let cmd = finalized("/bin/true");
    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &SandboxOpts::default());
    assert!(
        !out.get_args().any(|a| {
            let a = a.to_string_lossy();
            a.contains("dev-bind")
        }),
        "{:?}",
        out.get_args().collect::<Vec<_>>()
    );
}

#[test]
fn a_missing_home_falls_back_to_the_fixed_scratch_path() {
    let (_tmp, env) = fx();
    let cmd = finalized("/bin/true"); // env_clear(): no HOME at all
    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &SandboxOpts::default());
    let args: Vec<String> = out.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    let i = args.iter().rposition(|a| a == "--tmpfs").unwrap();
    assert_eq!(args[i + 1], FALLBACK_HOME);
}

#[test]
fn the_wrapped_commands_own_home_is_used_for_the_scratch_tmpfs_not_the_fallback() {
    let (_tmp, env) = fx();
    let mut cmd = finalized("/bin/true");
    cmd.env("HOME", "/apps/t/runtime/home");
    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &SandboxOpts::default());
    let args: Vec<String> = out.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    let i = args.iter().rposition(|a| a == "--tmpfs").unwrap();
    assert_eq!(args[i + 1], "/apps/t/runtime/home");
    assert_ne!(args[i + 1], FALLBACK_HOME);
}

#[test]
fn hostile_arguments_stay_single_argv_entries_and_no_shell_is_involved() {
    let (_tmp, env) = fx();
    let mut cmd = finalized("/bin/true");
    let hostile = ["a b", "$(rm -rf /)", "`whoami`", "; echo x", "\n--unshare-net\n"];
    for a in hostile {
        cmd.arg(a);
    }
    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &SandboxOpts::default());
    let args: Vec<String> = out.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    // Each hostile string is exactly one argv entry, in order, at the tail (after `--`).
    let tail = &args[args.len() - hostile.len()..];
    assert_eq!(tail, &hostile);
}

#[test]
fn an_explicit_env_removal_on_the_wrapped_command_is_kept() {
    let (_tmp, env) = fx();
    let mut cmd = finalized("/bin/true");
    cmd.env("KEPT", "1");
    cmd.env_remove("GONE");
    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &SandboxOpts::default());
    let e = envs(&out);
    assert_eq!(e["KEPT"], some("1"));
    // `env_remove` records an explicit removal (`None`), distinct from "never mentioned": either way the
    // spawned child would not see it, which is what matters.
    assert_eq!(e.get("GONE").cloned().flatten(), None);
}

#[test]
fn wrap_never_touches_the_current_processs_real_environment() {
    // A brand new `Command::new` otherwise inherits this process's real env (cargo's CARGO_* vars, ...); wrap()
    // must env_clear() and only re-apply what the wrapped command explicitly had.
    assert!(
        std::env::var_os("CARGO_MANIFEST_DIR").is_some(),
        "run under `cargo test`"
    );
    let (_tmp, env) = fx();
    let cmd = finalized("/bin/true");
    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &SandboxOpts::default());
    assert!(!envs(&out).contains_key("CARGO_MANIFEST_DIR"));
}

#[test]
fn with_no_current_dir_set_the_wrapped_command_also_sets_none() {
    let (_tmp, env) = fx();
    let cmd = finalized("/bin/true");
    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &SandboxOpts::default());
    assert_eq!(out.get_current_dir(), None);
}

#[test]
fn when_home_is_an_ancestor_of_the_prefix_the_home_tmpfs_is_mounted_first() {
    // Regression test for a real, reproduced bug: if the two binds were always emitted in a fixed order (prefix
    // bind, then $HOME tmpfs), and a caller's HOME happened to be `prefix` itself or a directory above it, the
    // later, broader tmpfs mount would silently swallow the earlier, narrower prefix bind (verified against
    // real bwrap 0.11.1 before writing this test).
    let (_tmp, env) = fx();
    let ancestor = env.root(); // a strict ancestor of env.prefix() == env.root().join("prefix")
    let mut cmd = finalized("/bin/true");
    cmd.env("HOME", ancestor);
    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &SandboxOpts::default());
    let args: Vec<String> = out.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    let tmpfs_home = args
        .windows(2)
        .position(|w| w[0] == "--tmpfs" && w[1] == ancestor.to_str().unwrap())
        .unwrap_or_else(|| panic!("{args:?}"));
    let prefix_bind = args.iter().position(|a| a == "--bind").unwrap();
    assert!(
        tmpfs_home < prefix_bind,
        "tmpfs(home) must precede bind(prefix): {args:?}"
    );
}

#[test]
fn when_home_equals_the_prefix_exactly_the_prefix_bind_still_wins() {
    let (_tmp, env) = fx();
    let mut cmd = finalized("/bin/true");
    cmd.env("HOME", env.prefix());
    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &SandboxOpts::default());
    let args: Vec<String> = out.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    let tmpfs_home = args
        .windows(2)
        .position(|w| w[0] == "--tmpfs" && w[1] == env.prefix().to_str().unwrap())
        .unwrap();
    let prefix_bind = args.iter().position(|a| a == "--bind").unwrap();
    assert!(tmpfs_home < prefix_bind, "{args:?}");
}

#[test]
fn real_sandbox_prefix_is_not_shadowed_when_home_is_an_ancestor_of_it() {
    // The end-to-end version of the two ordering tests above, against real bwrap: even in the previously-buggy
    // configuration (HOME set to a directory above the prefix), the prefix's own real content stays visible
    // and writable.
    let Some(bwrap) = require_real_bwrap() else { return };
    let (_tmp, env) = fx();
    fs::write(env.prefix().join("f.txt"), "prefix-data").unwrap();

    let launcher = sandboxed_launcher(&bwrap, &env, SandboxOpts::default());
    let mut cmd = Command::new("/usr/bin/sh");
    cmd.arg("-c").arg(format!("cat {}/f.txt", env.prefix().display()));
    cmd.env("HOME", env.root()); // a strict ancestor of env.prefix()
    let out = launcher.run_helper(cmd, Duration::from_secs(10)).unwrap();

    assert!(out.status.success(), "{:?}", out.output);
    assert_eq!(String::from_utf8_lossy(&out.output), "prefix-data");
}

// ------------------------------------------------------------------------------ bwrap discovery (no filesystem)

#[test]
fn find_bwrap_searches_path_in_order_and_skips_relative_entries() {
    let files = ["/usr/bin/bwrap", "/opt/bin/bwrap"];
    let is_file = |p: &Path| files.contains(&p.to_str().unwrap());
    let env = |k: &str| (k == "PATH").then(|| OsString::from(":.:rel:/opt/bin:/usr/bin"));
    assert_eq!(find_bwrap(&env, &is_file), Some(PathBuf::from("/opt/bin/bwrap")));

    let is_file = |p: &Path| p == Path::new("/usr/bin/bwrap");
    assert_eq!(find_bwrap(&env, &is_file), Some(PathBuf::from("/usr/bin/bwrap")));
}

#[test]
fn find_bwrap_is_none_without_a_match_or_without_path() {
    let is_file = |_: &Path| false;
    let env = |k: &str| (k == "PATH").then(|| OsString::from("/usr/bin"));
    assert_eq!(find_bwrap(&env, &is_file), None);
    let no_path = |_: &str| None;
    assert_eq!(find_bwrap(&no_path, &is_file), None);
}

// ------------------------------------------------------------------------------ real bwrap execution

/// `Some(path)` if a real `bwrap` is on `$PATH`; otherwise prints why the real-sandbox tests are skipped
/// (loudly, per the plan: never a silent `#[ignore]`) and returns `None` so the caller does an early `return`
/// (the test then still reports as passed — `cargo test` has no "skipped" outcome for a plain `#[test]`).
///
/// `cargo test` swallows the stderr of a passing test, so on a machine without `bwrap` the "loud" skip above is
/// actually invisible, and these tests report green while testing nothing. Setting `RUNTIME_REQUIRE_BWRAP=1`
/// (same `RUNTIME_*` naming as `RUNTIME_WINE`/`RUNTIME_DATA_DIR` elsewhere in this codebase) turns that into a
/// hard failure instead, so CI can opt into "these tests MUST really run"; local dev machines that may lack
/// `bwrap` keep today's default (unset: skip and pass). All the decision logic lives in [`check_bwrap`], a plain
/// function over already-resolved values (not the real `$PATH`/env lookups), so the panic branch itself is
/// directly unit-testable (below) without manipulating the real environment or `catch_unwind`-wrapping a test
/// that also does real filesystem/process work.
fn require_real_bwrap() -> Option<PathBuf> {
    let require = std::env::var_os("RUNTIME_REQUIRE_BWRAP").is_some_and(|v| !v.is_empty());
    check_bwrap(find_bwrap_on_path(), require)
}

/// The pure decision behind [`require_real_bwrap`]: `found` is what a real lookup returned, `require` is whether
/// `$RUNTIME_REQUIRE_BWRAP` was set (non-empty). Kept separate so a test can drive the panic branch directly.
fn check_bwrap(found: Option<PathBuf>, require: bool) -> Option<PathBuf> {
    match found {
        Some(p) => Some(p),
        None if require => {
            panic!(
                "bwrap not found on $PATH and RUNTIME_REQUIRE_BWRAP is set: the real-sandbox tests must run for real"
            );
        }
        None => {
            eprintln!("SKIP: bwrap not found on $PATH; the real-sandbox tests need bubblewrap installed");
            None
        }
    }
}

#[test]
fn check_bwrap_panics_with_a_clear_message_when_missing_and_required() {
    let result = std::panic::catch_unwind(|| check_bwrap(None, true));
    let payload = result.expect_err("expected a panic when bwrap is missing and RUNTIME_REQUIRE_BWRAP is set");
    let msg = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or_default();
    assert!(msg.contains("RUNTIME_REQUIRE_BWRAP"), "{msg:?}");
}

#[test]
fn check_bwrap_skips_quietly_without_panicking_when_missing_and_not_required() {
    let result = std::panic::catch_unwind(|| check_bwrap(None, false));
    assert_eq!(
        result.expect("must not panic when RUNTIME_REQUIRE_BWRAP is unset"),
        None
    );
}

#[test]
fn check_bwrap_returns_the_path_when_found_regardless_of_require() {
    for require in [false, true] {
        let found = Some(PathBuf::from("/x/bwrap"));
        assert_eq!(check_bwrap(found.clone(), require), found);
    }
}

fn sandboxed_launcher(bwrap: &Path, env: &AppEnv, opts: SandboxOpts) -> Launcher {
    Launcher::with_host_env(Vec::<(&str, &str)>::new())
        .with_sandbox(InstallerSandbox::new(bwrap).for_launcher(env.clone(), opts))
}

#[test]
fn real_sandbox_cannot_read_a_canary_placed_at_home() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let (_tmp, env) = fx();
    let fake_home = tempfile::tempdir().unwrap();
    fs::write(fake_home.path().join("canary.txt"), "top secret").unwrap();

    let launcher = sandboxed_launcher(&bwrap, &env, SandboxOpts::default());
    let mut cmd = Command::new("/usr/bin/sh");
    cmd.arg("-c").arg(r#"cat "$HOME/canary.txt""#);
    cmd.env("HOME", fake_home.path());
    let out = launcher.run_helper(cmd, Duration::from_secs(10)).unwrap();

    assert!(!out.status.success(), "canary was readable: {:?}", out.output);
    assert!(
        !String::from_utf8_lossy(&out.output).contains("top secret"),
        "canary content leaked: {:?}",
        out.output
    );
}

#[test]
fn real_sandbox_home_is_an_empty_directory_not_missing_and_not_the_real_one() {
    // Distinguishes "an empty scratch dir stands in for $HOME" from "nothing is bound there at all": both make
    // the canary unreadable (the test above), but a program that needs SOME writable $HOME to exist (creating
    // a cache dir, a lock file, ...) would fail differently if the directory itself were simply missing.
    let Some(bwrap) = require_real_bwrap() else { return };
    let (_tmp, env) = fx();
    let fake_home = tempfile::tempdir().unwrap();
    fs::write(fake_home.path().join("canary.txt"), "x").unwrap();

    let launcher = sandboxed_launcher(&bwrap, &env, SandboxOpts::default());
    let mut cmd = Command::new("/usr/bin/sh");
    cmd.arg("-c")
        .arg(r#"test -d "$HOME" && [ -z "$(ls -A "$HOME")" ] && echo EMPTY_DIR"#);
    cmd.env("HOME", fake_home.path());
    let out = launcher.run_helper(cmd, Duration::from_secs(10)).unwrap();

    assert!(out.status.success(), "{:?}", out.output);
    assert!(
        String::from_utf8_lossy(&out.output).contains("EMPTY_DIR"),
        "{:?}",
        out.output
    );
}

#[test]
fn real_sandbox_cannot_write_outside_its_own_prefix() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let (_tmp, env) = fx();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("planted");

    let launcher = sandboxed_launcher(&bwrap, &env, SandboxOpts::default());
    let mut cmd = Command::new("/usr/bin/sh");
    cmd.arg("-c").arg(format!("echo hostile > {}", target.display()));
    let out = launcher.run_helper(cmd, Duration::from_secs(10)).unwrap();

    assert!(!out.status.success(), "write outside the prefix succeeded");
    assert!(!target.exists(), "the file was created on the real host filesystem");
}

#[test]
fn real_sandbox_can_read_and_write_inside_its_own_prefix() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let (_tmp, env) = fx();
    let launcher = sandboxed_launcher(&bwrap, &env, SandboxOpts::default());
    let mut cmd = Command::new("/usr/bin/sh");
    cmd.arg("-c").arg(format!(
        "echo hi > {p}/f.txt && cat {p}/f.txt",
        p = env.prefix().display()
    ));
    let out = launcher.run_helper(cmd, Duration::from_secs(10)).unwrap();

    assert!(out.status.success(), "{:?}", out.output);
    assert_eq!(String::from_utf8_lossy(&out.output), "hi\n");
    assert_eq!(fs::read_to_string(env.prefix().join("f.txt")).unwrap(), "hi\n");
}

/// A loopback TCP listener on the host; used to test network-namespace isolation without DNS (this sandbox
/// binds neither `/etc/resolv.conf` nor `/etc/nsswitch.conf`, so a getaddrinfo-based probe would fail for a
/// reason unrelated to `--unshare-net`) and without a real internet call.
fn loopback_listener() -> (std::net::TcpListener, u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

#[test]
fn real_sandbox_network_is_unshared_by_default_and_shared_when_allowed() {
    let Some(bwrap) = require_real_bwrap() else { return };
    let (_tmp, env) = fx();
    let (listener, port) = loopback_listener();
    let accepted = std::thread::spawn(move || {
        // At most 2 accepts: the disallowed run never connects (its accept must time out from the caller's
        // side, which is bounded by run_helper's own timeout below), the allowed run does.
        listener.set_nonblocking(false).unwrap();
        listener.accept()
    });

    // bash's `/dev/tcp/HOST/PORT` pseudo-device does a plain TCP connect with no external tool and no shell
    // metacharacter risk (the host/port are literal, not interpolated from untrusted input).
    let probe = format!(r#"exec 3<>/dev/tcp/127.0.0.1/{port} && echo CONNECTED || echo FAILED"#);

    let denied = sandboxed_launcher(&bwrap, &env, network_opts(false));
    let mut cmd = Command::new("/usr/bin/bash");
    cmd.arg("-c").arg(&probe);
    let out = denied.run_helper(cmd, Duration::from_secs(10)).unwrap();
    assert!(
        String::from_utf8_lossy(&out.output).contains("FAILED"),
        "connected although allow_network=false: {:?}",
        out.output
    );

    let allowed = sandboxed_launcher(&bwrap, &env, network_opts(true));
    let mut cmd = Command::new("/usr/bin/bash");
    cmd.arg("-c").arg(&probe);
    let out = allowed.run_helper(cmd, Duration::from_secs(10)).unwrap();
    assert!(
        String::from_utf8_lossy(&out.output).contains("CONNECTED"),
        "did not connect although allow_network=true: {:?}",
        out.output
    );
    accepted.join().unwrap().unwrap();
}
