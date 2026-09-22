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

// ------------------------------------------------------------------------------ argv-builder (no bwrap run)

#[test]
fn the_exact_argv_for_a_typical_command() {
    let (_tmp, env) = fx();
    let mut cmd = finalized("/opt/wine/bin/wine64");
    cmd.arg("C:\\installer.exe").arg("/S");
    cmd.env("HOME", env.root().join("runtime/home"));
    cmd.env("WINEPREFIX", env.prefix());
    cmd.current_dir(env.drive_c());

    let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &SandboxOpts { allow_network: false });

    assert_eq!(out.get_program(), "/usr/bin/bwrap");
    let prefix = env.prefix();
    let home = env.root().join("runtime/home");
    let want: Vec<OsString> = [
        "--die-with-parent",
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
        let out = InstallerSandbox::new("/usr/bin/bwrap").wrap(cmd, &env, &SandboxOpts { allow_network: allow });
        let has_flag = out.get_args().any(|a| a == OsStr::new("--unshare-net"));
        assert_eq!(has_flag, expect_present, "allow_network={allow}");
    }
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
/// (loudly, per the plan: never a silent `#[ignore]`).
fn require_real_bwrap() -> Option<PathBuf> {
    match find_bwrap_on_path() {
        Some(p) => Some(p),
        None => {
            eprintln!("SKIP: bwrap not found on $PATH; the real-sandbox tests need bubblewrap installed");
            None
        }
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

    let denied = sandboxed_launcher(&bwrap, &env, SandboxOpts { allow_network: false });
    let mut cmd = Command::new("/usr/bin/bash");
    cmd.arg("-c").arg(&probe);
    let out = denied.run_helper(cmd, Duration::from_secs(10)).unwrap();
    assert!(
        String::from_utf8_lossy(&out.output).contains("FAILED"),
        "connected although allow_network=false: {:?}",
        out.output
    );

    let allowed = sandboxed_launcher(&bwrap, &env, SandboxOpts { allow_network: true });
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
