use super::*;
use crate::permissions::{Access, FsGrant, Network, Refusal};
use rt_core::Sandbox;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

/// A host made of an env map and a set of existing paths (`sockets` and `files` say which of them are sockets
/// or regular files); `links` maps a path to its resolved form.
#[derive(Clone, Default)]
struct FakeHost {
    env: HashMap<String, OsString>,
    exists: BTreeSet<PathBuf>,
    sockets: BTreeSet<PathBuf>,
    files: BTreeSet<PathBuf>,
    links: HashMap<PathBuf, PathBuf>,
    uid: u32,
    /// `runtime_exe` is `None` (default: [`EXE`]).
    no_exe: bool,
    /// `runtime_exe` is this instead of [`EXE`].
    exe_at: Option<PathBuf>,
    /// `scopes` fails with this (default: [`SYSTEMD_RUN`] works).
    no_scopes: Option<String>,
    /// `scopes` offers only these controllers (default: cpu, memory, pids).
    controllers: Option<Vec<&'static str>>,
}

impl Host for FakeHost {
    fn env(&self, name: &str) -> Option<OsString> {
        self.env.get(name).cloned()
    }
    fn exists(&self, p: &Path) -> bool {
        self.exists.contains(p)
    }
    fn is_socket(&self, p: &Path) -> bool {
        self.sockets.contains(p)
    }
    fn is_file(&self, p: &Path) -> bool {
        self.files.contains(p)
    }
    fn resolve(&self, p: &Path) -> Option<PathBuf> {
        self.links
            .get(p)
            .cloned()
            .or_else(|| self.exists(p).then(|| p.to_path_buf()))
    }
    fn uid(&self) -> u32 {
        self.uid
    }
    fn runtime_exe(&self) -> Option<PathBuf> {
        (!self.no_exe).then(|| self.exe_at.clone().unwrap_or_else(|| EXE.into()))
    }
    fn scopes(&self) -> Result<crate::ScopeSupport, String> {
        if let Some(why) = &self.no_scopes {
            return Err(why.clone());
        }
        Ok(crate::ScopeSupport {
            systemd_run: SYSTEMD_RUN.into(),
            controllers: self
                .controllers
                .clone()
                .unwrap_or_else(|| vec!["cpu", "memory", "pids"])
                .into_iter()
                .map(str::to_owned)
                .collect(),
        })
    }
}

impl FakeHost {
    fn with(mut self, p: impl Into<PathBuf>) -> Self {
        self.exists.insert(p.into());
        self
    }
    fn without(mut self, p: &str) -> Self {
        for set in [&mut self.exists, &mut self.sockets, &mut self.files] {
            set.remove(Path::new(p));
        }
        self
    }
    fn socket(mut self, p: &str) -> Self {
        self.sockets.insert(p.into());
        self.with(p)
    }
    fn file(mut self, p: &str) -> Self {
        self.files.insert(p.into());
        self.with(p)
    }
    /// An app's real directories: `<apps>`, `<apps>/<id>`, its prefix, `runtime` and `runtime/home`.
    fn app(self, prefix: &str) -> Self {
        let root = Path::new(prefix).parent().unwrap().to_path_buf();
        self.with(root.parent().unwrap())
            .with(root.join("runtime"))
            .with(root.join("runtime/home"))
            .with(root)
            .with(prefix)
    }
    fn set(mut self, k: &str, v: impl Into<OsString>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }
}

const PREFIX: &str = "/data/apps/a/prefix";
const APP_HOME: &str = "/data/apps/a/runtime/home";
const APP_ROOT: &str = "/data/apps/a";
const RT: &str = "/run/user/1000";
/// The fake host's runtime executable (the shim).
const EXE: &str = "/opt/runtime/bin/runtime";
const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
/// What every scope-wrapped command starts with, before its `-p` properties.
const SCOPE: [&str; 5] = ["--user", "--scope", "--collect", "--quiet", "--expand-environment=no"];

/// This dev machine's shape: Wayland + Xwayland, a Pulse-compatible socket, AMD + NVIDIA nodes.
fn host() -> FakeHost {
    let mut h = FakeHost {
        uid: 1000,
        ..FakeHost::default()
    }
    .set("HOME", "/home/me")
    .set("XDG_RUNTIME_DIR", RT)
    .app(PREFIX)
    .socket("/run/user/1000/wayland-1")
    .socket("/run/user/1000/pulse/native")
    .file("/home/me/.Xauthority");
    for p in ["/tmp/.X11-unix", "/dev/dri", "/dev/nvidiactl", "/dev/nvidia0"] {
        h = h.with(p);
    }
    h
}

/// What `Launcher::finalize` hands the sandbox for a Wine run: allowlisted host variables plus the backend's.
fn app_cmd_at(prefix: &str, home: &str) -> Command {
    let mut c = Command::new("/usr/bin/wine");
    c.args(["C:\\x.exe", "--flag"]).env_clear();
    for (k, v) in [
        ("PATH", "/usr/bin:/bin"),
        ("LANG", "C.UTF-8"),
        ("DISPLAY", ":0"),
        ("WAYLAND_DISPLAY", "wayland-1"),
        ("XAUTHORITY", "/home/me/.Xauthority"),
        ("XDG_RUNTIME_DIR", RT),
        ("XDG_SESSION_TYPE", "wayland"),
        ("WINEARCH", "win64"),
        ("WINEDEBUG", "-all"),
        ("WINEDLLOVERRIDES", "winemenubuilder.exe=d"),
        ("WINESERVER", "/usr/bin/wineserver"),
    ] {
        c.env(k, v);
    }
    c.env("WINEPREFIX", prefix).env("HOME", home);
    c.current_dir(format!("{prefix}/drive_c"));
    c
}

fn app_cmd() -> Command {
    app_cmd_at(PREFIX, APP_HOME)
}

fn sb(p: Permissions, h: FakeHost) -> AppSandbox {
    AppSandbox::new("/usr/bin/bwrap".into(), p, vec!["/opt/wine/lib".into()], Arc::new(h))
}

/// bwrap's own arguments: a `systemd-run` scope in front (see `limits_*`) is cut off.
fn argv(c: &Command) -> Vec<String> {
    let a = all_args(c);
    match a.iter().position(|x| x == "/usr/bin/bwrap") {
        Some(i) if c.get_program() == SYSTEMD_RUN => a[i + 1..].to_vec(),
        _ => a,
    }
}

fn all_args(c: &Command) -> Vec<String> {
    c.get_args().map(|a| a.to_string_lossy().into_owned()).collect()
}

fn envs(c: &Command) -> BTreeMap<String, String> {
    c.get_envs()
        .filter_map(|(k, v)| Some((k.to_string_lossy().into_owned(), v?.to_string_lossy().into_owned())))
        .collect()
}

/// Index of the first contiguous occurrence of `seq` in `a`.
fn pos(a: &[String], seq: &[&str]) -> Option<usize> {
    a.windows(seq.len())
        .position(|w| w.iter().zip(seq).all(|(x, y)| x == y))
}

/// The Landlock rules of the default profile on [`host`], mirroring its binds (gpu on or off).
fn default_rules(gpu: bool) -> Vec<&'static str> {
    let mut r = vec![
        "rw:/proc",
        "rw:/dev/null",
        "rw:/dev/zero",
        "rw:/dev/full",
        "rw:/dev/random",
        "rw:/dev/urandom",
        "rw:/dev/tty",
        "rw:/dev/pts",
        "rw:/dev/shm",
        "rw:/tmp",
        "ro:/usr",
        "ro:/bin",
        "ro:/lib",
        "ro:/lib64",
        "ro:/etc/alternatives",
        "ro:/etc/passwd",
        "ro:/etc/group",
        "ro:/etc/nsswitch.conf",
        "ro:/etc/ld.so.cache",
        "ro:/etc/localtime",
        "ro:/etc/fonts",
        "ro:/etc/ssl",
        "ro:/etc/pki",
        "ro:/etc/ca-certificates",
        "ro:/etc/vulkan",
        "ro:/etc/glvnd",
        "ro:/opt/wine/lib",
        "rw:/run/user/1000",
    ];
    if gpu {
        r.extend([
            "rw:/dev/dri",
            "rw:/dev/nvidiactl",
            "rw:/dev/nvidia0",
            "ro:/sys/dev/char",
            "ro:/sys/devices",
            "ro:/sys/class/drm",
            "ro:/run/opengl-driver",
        ]);
    }
    r.extend([
        "ro:/opt/runtime/bin/runtime",
        "rw:/data/apps/a/prefix",
        "rw:/data/apps/a/runtime/home",
    ]);
    r
}

/// The shim invocation after bwrap's `--`: (the shim's rules, the program and its arguments).
fn shim_part(a: &[String]) -> (Vec<String>, Vec<String>) {
    let dd = a.iter().position(|x| x == "--").unwrap();
    assert_eq!(a[dd + 1..dd + 4], [EXE, "sandbox-init", "--v1"], "{a:?}");
    let block = &a[dd + 3..];
    let end = block.iter().position(|x| x == "--").unwrap();
    let rules = block[1..end]
        .chunks(2)
        .map(|c| {
            assert_eq!(c[0], "--rule");
            c[1].clone()
        })
        .collect();
    (rules, block[end + 1..].to_vec())
}

fn rendered(p: Permissions, h: FakeHost) -> Command {
    sb(p, h).render(&app_cmd()).unwrap()
}

fn perms(f: impl FnOnce(&mut Permissions)) -> Permissions {
    let mut p = Permissions::default();
    f(&mut p);
    p
}

#[test]
fn the_default_profile_is_exactly_this() {
    let c = rendered(Permissions::default(), host());
    // the default task limit, in a scope of the user manager, around bwrap
    assert_eq!(c.get_program(), SYSTEMD_RUN);
    let mut scope: Vec<&str> = SCOPE.to_vec();
    scope.extend(["-p", "TasksMax=4096", "--", "/usr/bin/bwrap"]);
    assert_eq!(all_args(&c)[..scope.len()], scope[..]);
    let mut want: Vec<&str> = vec![
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
    ];
    for d in [
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
        "/etc/alternatives",
        "/etc/passwd",
        "/etc/group",
        "/etc/nsswitch.conf",
        "/etc/ld.so.cache",
        "/etc/localtime",
        "/etc/fonts",
        "/etc/ssl",
        "/etc/pki",
        "/etc/ca-certificates",
        "/etc/vulkan",
        "/etc/glvnd",
        "/opt/wine/lib",
    ] {
        want.extend(["--ro-bind-try", d, d]);
    }
    want.extend(["--perms", "0700", "--tmpfs", RT]);
    for s in ["/run/user/1000/wayland-1", "/tmp/.X11-unix"] {
        want.extend(["--ro-bind-try", s, s]);
    }
    want.extend(["--ro-bind", "/home/me/.Xauthority", "/run/user/1000/Xauthority"]);
    want.extend([
        "--ro-bind-try",
        "/run/user/1000/pulse/native",
        "/run/user/1000/pulse/native",
    ]);
    for d in ["/dev/dri", "/dev/nvidiactl", "/dev/nvidia0"] {
        want.extend(["--dev-bind-try", d, d]);
    }
    for d in ["/sys/dev/char", "/sys/devices", "/sys/class/drm", "/run/opengl-driver"] {
        want.extend(["--ro-bind-try", d, d]);
    }
    want.extend(["--ro-bind", EXE, EXE]);
    want.extend(["--bind", PREFIX, PREFIX, "--bind", APP_HOME, APP_HOME]);
    want.extend(["--remount-ro", "/"]);
    want.extend(["--", EXE, "sandbox-init", "--v1"]);
    for r in default_rules(true) {
        want.extend(["--rule", r]);
    }
    want.extend(["--", "/usr/bin/wine", "C:\\x.exe", "--flag"]);
    assert_eq!(argv(&c), want);
    let e = envs(&c);
    let want_env: BTreeMap<String, String> = [
        ("PATH", "/usr/bin:/bin"),
        ("LANG", "C.UTF-8"),
        ("DISPLAY", ":0"),
        ("WAYLAND_DISPLAY", "wayland-1"),
        ("XAUTHORITY", "/run/user/1000/Xauthority"),
        ("XDG_RUNTIME_DIR", RT),
        ("XDG_SESSION_TYPE", "wayland"),
        ("PULSE_SERVER", "unix:/run/user/1000/pulse/native"),
        ("WINEARCH", "win64"),
        ("WINEDEBUG", "-all"),
        ("WINEDLLOVERRIDES", "winemenubuilder.exe=d"),
        ("WINESERVER", "/usr/bin/wineserver"),
        ("WINEPREFIX", PREFIX),
        ("HOME", APP_HOME),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    assert_eq!(e, want_env);
    assert_eq!(c.get_current_dir(), Some(Path::new("/data/apps/a/prefix/drive_c")));
    let s = sb(Permissions::default(), host());
    assert!(s.skipped(&app_cmd()).is_empty(), "{:?}", s.skipped(&app_cmd()));
    // the only caveat of the default profile on an X11-capable host: X11 itself
    assert_eq!(s.caveats(&app_cmd()), [X11_CAVEAT]);
    // the preview is the wrapped command line, program first
    let preview = s.argv_preview(&app_cmd());
    assert_eq!(preview[0], SYSTEMD_RUN);
    assert_eq!(preview[1..], c.get_args().map(OsString::from).collect::<Vec<_>>()[..]);
    // and `Sandbox::wrap` is `render`
    assert_eq!(all_args(&s.wrap(app_cmd())), all_args(&c));
}

/// The scope part of a rendered command: everything before bwrap (program first).
fn scope_of(c: &Command) -> Vec<String> {
    let a = all_args(c);
    let end = a.iter().position(|x| x == "/usr/bin/bwrap").unwrap_or(0);
    std::iter::once(c.get_program().to_string_lossy().into_owned())
        .chain(a[..end].iter().cloned())
        .collect()
}

fn limited(sets: &[&str]) -> Permissions {
    let mut p = Permissions::default();
    let ctx = GrantCtx {
        home: "/home/me".into(),
        extra_homes: vec![],
        data_root: "/data".into(),
        runtime_dir: None,
    };
    for s in sets {
        p.apply_set(s, &ctx).unwrap();
    }
    p
}

fn want_scope(props: &[&str]) -> Vec<String> {
    let mut w = vec![SYSTEMD_RUN.to_owned()];
    w.extend(SCOPE.iter().map(|s| s.to_string()));
    for p in props {
        w.extend(["-p".to_owned(), p.to_string()]);
    }
    w.push("--".into());
    w
}

#[test]
fn limits_become_the_scope_properties_exactly() {
    let c = rendered(limited(&["memory=2048", "cpu=150", "tasks=512"]), host());
    assert_eq!(
        scope_of(&c),
        want_scope(&["TasksMax=512", "MemoryMax=2048M", "MemorySwapMax=0", "CPUQuota=150%"])
    );
    // bwrap follows unchanged, env and cwd too
    let plain = rendered(Permissions::default(), host());
    assert_eq!(argv(&c), argv(&plain));
    assert_eq!(envs(&c), envs(&plain));
    assert_eq!(c.get_current_dir(), plain.get_current_dir());
    // memory alone keeps the default task limit
    let m = rendered(limited(&["memory=100"]), host());
    assert_eq!(
        scope_of(&m),
        want_scope(&["TasksMax=4096", "MemoryMax=100M", "MemorySwapMax=0"])
    );
    // an explicit 4096 renders like the default (it only changes what a failure does)
    assert_eq!(
        scope_of(&rendered(limited(&["tasks=4096"]), host())),
        want_scope(&["TasksMax=4096"])
    );
    // no task limit and nothing else: no scope at all, and no probe needed
    let h = FakeHost {
        no_scopes: Some("never asked".into()),
        ..host()
    };
    let s = sb(limited(&["tasks=unlimited"]), h.clone());
    let u = s.render(&app_cmd()).unwrap();
    assert_eq!(u.get_program(), "/usr/bin/bwrap");
    assert_eq!(all_args(&u), argv(&plain));
    assert_eq!(s.caveats(&app_cmd()), [X11_CAVEAT]);
    // ...but unlimited tasks with a CPU limit is a scope without TasksMax
    let cpu = rendered(limited(&["tasks=unlimited", "cpu=50"]), host());
    assert_eq!(scope_of(&cpu), want_scope(&["CPUQuota=50%"]));
}

#[test]
fn explicit_limits_fail_closed_and_the_default_degrades_with_a_caveat() {
    let down = FakeHost {
        no_scopes: Some("systemd-run --user --scope failed (Failed to connect to bus)".into()),
        ..host()
    };
    // default only: bwrap without a scope, and a caveat that says why
    let s = sb(Permissions::default(), down.clone());
    let c = s.render(&app_cmd()).unwrap();
    assert_eq!(c.get_program(), "/usr/bin/bwrap");
    assert_eq!(
        s.caveats(&app_cmd()),
        [
            "resource limits unavailable: systemd-run --user --scope failed (Failed to connect to bus); the \
             default task limit (4096) is not applied"
                .to_owned(),
            X11_CAVEAT.to_owned(),
        ]
    );
    // anything explicit: refused, naming the reason and the way out
    for sets in [
        &["tasks=4096"][..],
        &["memory=128"],
        &["cpu=50"],
        &["tasks=unlimited", "memory=64"],
    ] {
        let s = sb(limited(sets), down.clone());
        let e = s.render(&app_cmd()).unwrap_err();
        assert!(matches!(e, RenderError::Limits { .. }), "{sets:?}: {e:?}");
        let text = e.to_string();
        assert!(text.contains("Failed to connect to bus"), "{text}");
        assert!(
            text.contains("runtime permissions a --set memory=off --set cpu=off --set tasks=default"),
            "{text}"
        );
        assert_eq!(s.wrap(app_cmd()).get_program(), "/bin/sh", "{sets:?}: fail closed");
        assert!(s.caveats(&app_cmd()).is_empty());
    }
    // a controller the user manager does not delegate counts as unavailable, for what needs it
    let no_mem = FakeHost {
        controllers: Some(vec!["cpu", "pids"]),
        ..host()
    };
    let e = sb(limited(&["memory=128"]), no_mem.clone())
        .render(&app_cmd())
        .unwrap_err();
    assert!(e.to_string().contains("`memory` controller"), "{e}");
    assert_eq!(
        scope_of(&sb(limited(&["cpu=50"]), no_mem).render(&app_cmd()).unwrap()),
        want_scope(&["TasksMax=4096", "CPUQuota=50%"])
    );
    let no_pids = FakeHost {
        controllers: Some(vec![]),
        ..host()
    };
    let s = sb(Permissions::default(), no_pids);
    assert_eq!(s.render(&app_cmd()).unwrap().get_program(), "/usr/bin/bwrap");
    assert!(
        s.caveats(&app_cmd())[0].contains("`pids` controller"),
        "{:?}",
        s.caveats(&app_cmd())
    );
}

#[test]
fn network_allow_shares_the_net_namespace_binds_dns_and_says_what_that_exposes() {
    let p = perms(|p| p.network = Network::Allow);
    let a = argv(&rendered(p.clone(), host()));
    assert!(!a.contains(&"--unshare-net".to_owned()));
    for f in ["/etc/hosts", "/etc/resolv.conf"] {
        assert!(pos(&a, &["--ro-bind-try", f, f]).is_some(), "{f}: {a:?}");
    }
    // bwrap follows the resolv.conf symlink on the source side: the resolver's whole directory is not bound
    assert!(!a.iter().any(|x| x.starts_with("/run/systemd")), "{a:?}");
    // the network namespace never changes the environment
    assert_eq!(
        envs(&rendered(p.clone(), host())),
        envs(&rendered(Permissions::default(), host()))
    );
    let cav = sb(p, host()).caveats(&app_cmd());
    assert!(cav.iter().any(|c| c.contains("abstract")), "{cav:?}");
    assert!(
        cav.iter().any(|c| c.contains("loopback") && c.contains("CUPS")),
        "{cav:?}"
    );
    // DNS files are not there without network
    let d = argv(&rendered(Permissions::default(), host()));
    assert!(
        !d.iter()
            .any(|x| x == "/etc/resolv.conf" || x == "/etc/hosts" || x == "/run/systemd/resolve")
    );
}

#[test]
fn display_off_binds_no_display_socket_and_drops_its_variables() {
    let c = rendered(perms(|p| p.display = false), host());
    let a = argv(&c);
    for s in ["/run/user/1000/wayland-1", "/tmp/.X11-unix", "/home/me/.Xauthority"] {
        assert!(!a.iter().any(|x| x == s), "{s}: {a:?}");
    }
    assert!(!a.iter().any(|x| x.contains("Xauthority")), "{a:?}");
    let e = envs(&c);
    for k in ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"] {
        assert!(!e.contains_key(k), "{k}");
    }
    assert!(e.contains_key("PULSE_SERVER") && e.contains_key("XDG_RUNTIME_DIR"));
    // no caveat without network; with network the X11 abstract socket stays reachable and says so
    assert!(sb(perms(|p| p.display = false), host()).caveats(&app_cmd()).is_empty());
    let cav = sb(
        perms(|p| {
            p.display = false;
            p.network = Network::Allow;
        }),
        host(),
    )
    .caveats(&app_cmd());
    assert!(
        cav.iter()
            .any(|c| c.contains("display=off") && c.contains("@/tmp/.X11-unix/X")),
        "{cav:?}"
    );
}

#[test]
fn audio_off_binds_no_pulse_socket_and_drops_pulse_server() {
    let mut cmd = app_cmd();
    cmd.env("PULSE_SERVER", "unix:/run/user/1000/pulse/native");
    let c = sb(perms(|p| p.audio = false), host()).render(&cmd).unwrap();
    assert!(!argv(&c).iter().any(|x| x.contains("pulse")));
    assert!(!envs(&c).contains_key("PULSE_SERVER"));
}

#[test]
fn pulse_server_is_kept_only_when_it_names_the_bound_socket() {
    let run = |v: &str| {
        let mut cmd = app_cmd();
        cmd.env("PULSE_SERVER", v);
        envs(&sb(Permissions::default(), host()).render(&cmd).unwrap())["PULSE_SERVER"].clone()
    };
    assert_eq!(
        run("unix:/run/user/1000/pulse/native"),
        "unix:/run/user/1000/pulse/native"
    );
    assert_eq!(run("/run/user/1000/pulse/native"), "/run/user/1000/pulse/native");
    for outside in [
        "tcp:192.168.1.2:4713",
        "unix:/tmp/pulse-sock",
        "unix:/run/user/1000/../1001/pulse/native",
        "unix:/run/user/10000/pulse/native",
        "unix:/run/user/1000/pulse/native tcp:1.2.3.4",
        "unix:/run/user/1000/bus",
    ] {
        assert_eq!(run(outside), "unix:/run/user/1000/pulse/native", "{outside}");
    }
    // no socket to bind: no PULSE_SERVER at all
    let mut cmd = app_cmd();
    cmd.env("PULSE_SERVER", "tcp:1.2.3.4");
    let c = sb(Permissions::default(), host().without("/run/user/1000/pulse/native"))
        .render(&cmd)
        .unwrap();
    assert!(!envs(&c).contains_key("PULSE_SERVER"));
}

#[test]
fn the_shim_runs_the_original_program_under_rules_that_mirror_the_binds() {
    for gpu in [true, false] {
        let a = argv(&rendered(perms(|p| p.gpu = gpu), host()));
        let (rules, program) = shim_part(&a);
        assert_eq!(rules, default_rules(gpu), "gpu {gpu}");
        assert_eq!(program, ["/usr/bin/wine", "C:\\x.exe", "--flag"]);
        // the shim itself is bound read-only at its own path, after every other mount but the app's own dirs
        let exe = pos(&a, &["--ro-bind", EXE, EXE]).expect("the runtime executable is bound");
        assert_eq!(pos(&a, &["--bind", PREFIX, PREFIX]), Some(exe + 3));
        // the parsed block is exactly these rules and this program
        let dd = a.iter().position(|x| x == "--").unwrap();
        let block: Vec<OsString> = a[dd + 3..].iter().map(OsString::from).collect();
        let parsed = crate::init::parse(&block).unwrap();
        assert_eq!(parsed.program, Path::new("/usr/bin/wine"));
        assert_eq!(parsed.landlock.len(), default_rules(gpu).len());
    }
    // network=allow: its /etc files are rules too
    let a = argv(&rendered(perms(|p| p.network = Network::Allow), host()));
    let (rules, _) = shim_part(&a);
    let glvnd = rules.iter().position(|r| r == "ro:/etc/glvnd").unwrap();
    assert_eq!(rules[glvnd + 1..glvnd + 3], ["ro:/etc/hosts", "ro:/etc/resolv.conf"]);
}

#[test]
fn awkward_program_arguments_reach_the_shim_unchanged() {
    let mut cmd = app_cmd();
    let odd = [
        OsString::from("--"),
        OsString::from("--rule"),
        OsString::from("rw:/"),
        OsString::from(""),
        OsString::from("a\nb"),
        OsString::from(std::ffi::OsStr::from_bytes(b"\xff")),
    ];
    cmd.args(&odd);
    let c = sb(Permissions::default(), host()).render(&cmd).unwrap();
    let a: Vec<OsString> = c.get_args().map(OsString::from).collect();
    // bwrap's `--` (the scope's own comes first)
    let dd = a.iter().rposition(|x| x == EXE).unwrap() - 1;
    assert_eq!(a[dd], "--");
    let parsed = crate::init::parse(&a[dd + 3..]).unwrap();
    let mut want: Vec<OsString> = ["C:\\x.exe", "--flag"].iter().map(OsString::from).collect();
    want.extend(odd);
    assert_eq!(parsed.argv, want);
    assert_eq!(parsed.landlock.len(), default_rules(true).len());
}

#[test]
fn grants_become_landlock_rules_with_their_access() {
    let td = crate::grant_tempdir();
    let root = td.path().canonicalize().unwrap();
    let (ro, rw) = (root.join("ro"), root.join("rw"));
    std::fs::create_dir_all(&ro).unwrap();
    std::fs::create_dir_all(&rw).unwrap();
    let p = perms(|p| {
        p.filesystem = vec![
            FsGrant {
                path: ro.clone(),
                access: Access::Ro,
            },
            FsGrant {
                path: rw.clone(),
                access: Access::Rw,
            },
        ]
    });
    let (rules, _) = shim_part(&argv(&rendered(p, host())));
    let exe = rules.iter().position(|r| r == &format!("ro:{EXE}")).unwrap();
    assert_eq!(
        rules[exe - 2..exe],
        [format!("ro:{}", ro.display()), format!("rw:{}", rw.display())]
    );
}

#[test]
fn a_runtime_executable_that_cannot_be_resolved_refuses_the_run() {
    let h = FakeHost { no_exe: true, ..host() };
    let s = sb(Permissions::default(), h);
    assert_eq!(s.render(&app_cmd()).unwrap_err(), RenderError::RuntimeExe);
    let w = s.wrap(app_cmd());
    assert_eq!(w.get_program(), "/bin/sh", "the fail-closed stub");
    assert!(
        argv(&w).iter().any(|a| a.contains("runtime executable")),
        "{:?}",
        argv(&w)
    );
    // a runtime inside the data directory is refused (by the written and the resolved data root)
    let h = FakeHost {
        exe_at: Some("/data/bin/runtime".into()),
        ..host()
    };
    let e = sb(Permissions::default(), h).render(&app_cmd()).unwrap_err();
    assert_eq!(e, RenderError::RuntimeExeInData("/data/bin/runtime".into()));
    // a block the shim would refuse (here: a Wine dll directory with `..`) is refused at render
    let s = AppSandbox::new(
        "/usr/bin/bwrap".into(),
        Permissions::default(),
        vec!["/opt/wine/../lib".into()],
        Arc::new(host()),
    );
    let e = s.render(&app_cmd()).unwrap_err();
    assert!(
        matches!(e, RenderError::Shim(crate::init::InitError::NotAbsolute(_))),
        "{e:?}"
    );
    // a program that is not an absolute path is refused before the shim would refuse it
    let mut rel = Command::new("wine");
    for (k, v) in app_cmd().get_envs() {
        rel.env(k, v.unwrap());
    }
    let e = sb(Permissions::default(), host()).render(&rel).unwrap_err();
    assert_eq!(e, RenderError::Program("wine".into()));
}

#[test]
fn gpu_off_binds_no_device_and_no_sys_tree() {
    let a = argv(&rendered(perms(|p| p.gpu = false), host()));
    assert!(!a.iter().any(|x| x.starts_with("--dev-bind")), "{a:?}");
    assert!(
        !a.iter().any(|x| x.starts_with("/sys") || x == "/run/opengl-driver"),
        "{a:?}"
    );
}

#[test]
fn dev_bind_is_only_ever_used_for_existing_gpu_nodes() {
    let mut h = host();
    for n in [
        "/dev/nvidia-uvm",
        "/dev/nvidia-uvm-tools",
        "/dev/nvidia-modeset",
        "/dev/nvidia3",
        "/dev/nvidia63",
    ] {
        h = h.with(n);
    }
    let a = argv(&rendered(Permissions::default(), h));
    assert!(!a.contains(&"--dev-bind".to_owned()));
    let bound: Vec<&str> = a
        .iter()
        .enumerate()
        .filter(|(_, x)| *x == "--dev-bind-try")
        .map(|(i, _)| a[i + 1].as_str())
        .collect();
    assert_eq!(
        bound,
        [
            "/dev/dri",
            "/dev/nvidiactl",
            "/dev/nvidia-uvm",
            "/dev/nvidia-uvm-tools",
            "/dev/nvidia-modeset",
            "/dev/nvidia0",
            "/dev/nvidia3",
            "/dev/nvidia63"
        ]
    );
}

#[test]
fn missing_sockets_and_nodes_are_skipped_and_reported() {
    let h = FakeHost {
        uid: 1000,
        ..FakeHost::default()
    }
    .set("HOME", "/home/me")
    .app(PREFIX);
    let s = sb(Permissions::default(), h);
    let c = s.render(&app_cmd()).unwrap();
    let a = argv(&c);
    for x in [
        "/run/user/1000/wayland-1",
        "/tmp/.X11-unix",
        "/home/me/.Xauthority",
        "/run/user/1000/pulse/native",
    ] {
        assert!(!a.iter().any(|y| y == x), "{x}");
    }
    assert!(!a.iter().any(|x| x.starts_with("--dev-bind")));
    assert!(!envs(&c).contains_key("PULSE_SERVER"));
    let sk = s.skipped(&app_cmd()).join("\n");
    for want in [
        "display: Wayland socket path /run/user/1000/wayland-1 is not a socket",
        "display: X11 socket directory /tmp/.X11-unix",
        "display: XAUTHORITY /home/me/.Xauthority is not a regular file",
        "audio: PulseAudio socket path /run/user/1000/pulse/native is not a socket",
        "gpu: no GPU device nodes",
    ] {
        assert!(sk.contains(want), "{want}: {sk}");
    }
    // a switch that is off is not "skipped"
    let off = sb(
        perms(|p| {
            p.display = false;
            p.audio = false;
            p.gpu = false;
        }),
        host().without("/dev/dri").without("/run/user/1000/pulse/native"),
    );
    assert!(off.skipped(&app_cmd()).is_empty());
}

#[test]
fn no_display_variable_means_no_display_bind_and_a_note() {
    let mut cmd = app_cmd();
    cmd.env_remove("DISPLAY").env_remove("WAYLAND_DISPLAY");
    let s = sb(Permissions::default(), host());
    let a = argv(&s.render(&cmd).unwrap());
    assert!(!a.iter().any(|x| x == "/tmp/.X11-unix" || x.contains("wayland")));
    assert!(
        s.skipped(&cmd)
            .join("\n")
            .contains("neither DISPLAY nor WAYLAND_DISPLAY")
    );
    // a WAYLAND_DISPLAY with a path in it is refused as a socket name
    let mut cmd = app_cmd();
    cmd.env("WAYLAND_DISPLAY", "../../../home/me/.ssh");
    let a = argv(&s.render(&cmd).unwrap());
    assert!(!a.iter().any(|x| x.contains(".ssh")), "{a:?}");
    assert!(s.skipped(&cmd).join("\n").contains("WAYLAND_DISPLAY"));
}

#[test]
fn an_unset_or_relative_runtime_dir_gets_the_uid_fallback_tmpfs_and_no_sockets() {
    for rt in [None, Some("run/user/1000"), Some("/run/user/1000/../0")] {
        let mut cmd = app_cmd();
        match rt {
            None => cmd.env_remove("XDG_RUNTIME_DIR"),
            Some(v) => cmd.env("XDG_RUNTIME_DIR", v),
        };
        let s = sb(Permissions::default(), host());
        let c = s.render(&cmd).unwrap();
        let a = argv(&c);
        assert!(pos(&a, &["--tmpfs", "/run/user/1000"]).is_some(), "{rt:?}: {a:?}");
        assert!(
            !a.iter().any(|x| x.contains("wayland-1") || x.contains("pulse")),
            "{rt:?}: {a:?}"
        );
        assert!(!envs(&c).contains_key("PULSE_SERVER"));
        // X11 does not live in the runtime dir: still bound
        assert!(pos(&a, &["--ro-bind-try", "/tmp/.X11-unix"]).is_some());
        let sk = s.skipped(&cmd).join("\n");
        assert!(
            sk.contains("XDG_RUNTIME_DIR") && sk.contains("audio") && sk.contains("display"),
            "{sk}"
        );
    }
}

#[test]
fn host_directory_grants_are_bound_ro_or_rw_before_the_apps_own_dirs() {
    let td = crate::grant_tempdir();
    let root = td.path().canonicalize().unwrap();
    let (ro, rw) = (root.join("ro"), root.join("rw"));
    std::fs::create_dir_all(&ro).unwrap();
    std::fs::create_dir_all(&rw).unwrap();
    let p = perms(|p| {
        p.filesystem = vec![
            FsGrant {
                path: ro.clone(),
                access: Access::Ro,
            },
            FsGrant {
                path: rw.clone(),
                access: Access::Rw,
            },
        ]
    });
    let a = argv(&rendered(p, host()));
    let (ro, rw) = (ro.to_str().unwrap(), rw.to_str().unwrap());
    let r = pos(&a, &["--ro-bind", ro, ro]).expect("ro grant");
    let w = pos(&a, &["--bind", rw, rw]).expect("rw grant");
    let prefix = pos(&a, &["--bind", PREFIX, PREFIX]).unwrap();
    assert!(r < prefix && w < prefix);
    // after every tmpfs, so a grant under /tmp is not hidden by the private /tmp
    let tmp = pos(&a, &["--tmpfs", "/tmp"]).unwrap();
    let rtd = pos(&a, &["--tmpfs", RT]).unwrap();
    assert!(r > tmp && r > rtd && w > tmp && w > rtd);
}

#[test]
fn a_stored_grant_that_no_longer_validates_is_a_render_error() {
    let td = crate::grant_tempdir();
    let root = td.path().canonicalize().unwrap();
    let gone = root.join("gone");
    let grant = |path: PathBuf| {
        perms(|p| {
            p.filesystem = vec![FsGrant {
                path,
                access: Access::Rw,
            }]
        })
    };
    // vanished
    let e = sb(grant(gone.clone()), host()).render(&app_cmd()).unwrap_err();
    assert!(
        matches!(
            &e,
            RenderError::Grant(PermError::Grant {
                why: Refusal::Missing,
                ..
            })
        ),
        "{e:?}"
    );
    // a symlink now: its target is judged (here the real home) and the moved grant is refused
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    std::os::unix::fs::symlink(&home, &gone).unwrap();
    let h = host().set("HOME", home.as_os_str());
    let e = sb(grant(gone.clone()), h).render(&app_cmd()).unwrap_err();
    assert!(
        matches!(&e, RenderError::Grant(PermError::Grant { why: Refusal::Home, .. })),
        "{e:?}"
    );
    // a symlink to an acceptable directory is still refused: the stored path must be the resolved one
    std::fs::remove_file(&gone).unwrap();
    let other = root.join("other");
    std::fs::create_dir_all(&other).unwrap();
    std::os::unix::fs::symlink(&other, &gone).unwrap();
    let e = sb(grant(gone.clone()), host()).render(&app_cmd()).unwrap_err();
    assert!(matches!(&e, RenderError::GrantMoved(_)), "{e:?}");
    // no real HOME to judge grants against: refused (with no grants, not needed)
    let mut h = host();
    h.env.remove("HOME");
    let e = sb(grant(other.clone()), h.clone()).render(&app_cmd()).unwrap_err();
    assert_eq!(e, RenderError::NoRealHome);
    assert!(sb(Permissions::default(), h).render(&app_cmd()).is_ok());
    // wrap fails closed: nothing of the app runs
    let w = sb(grant(root.join("nope")), host()).wrap(app_cmd());
    assert_ne!(w.get_program(), "/usr/bin/bwrap");
    assert!(!argv(&w).iter().any(|x| x == "/usr/bin/wine"), "{:?}", argv(&w));
}

#[test]
fn a_grant_equal_to_the_prefix_or_the_app_home_is_refused() {
    let td = crate::grant_tempdir();
    let root = td.path().canonicalize().unwrap();
    let prefix = root.join("apps/a/prefix");
    let home = root.join("apps/a/runtime/home");
    std::fs::create_dir_all(&prefix).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let h = host().app(prefix.to_str().unwrap());
    let cmd = app_cmd_at(prefix.to_str().unwrap(), home.to_str().unwrap());
    for g in [&prefix, &home, &root.join("apps/a"), &root.join("apps")] {
        let p = perms(|p| {
            p.filesystem = vec![FsGrant {
                path: g.clone(),
                access: Access::Rw,
            }]
        });
        let e = sb(p, h.clone()).render(&cmd).unwrap_err();
        assert!(
            matches!(
                &e,
                RenderError::Grant(PermError::Grant {
                    why: Refusal::DataRoot,
                    ..
                })
            ),
            "{g:?}: {e:?}"
        );
    }
}

#[test]
fn the_app_root_and_its_parents_are_never_bound() {
    let a = argv(&rendered(Permissions::default(), host()));
    for x in [APP_ROOT, "/data/apps", "/data", "/data/apps/a/runtime", "/home/me", "/"] {
        // `/` only as the target of the read-only root remount
        let bound = a.iter().enumerate().any(|(i, y)| y == x && a[i - 1] != "--remount-ro");
        assert!(!bound, "{x} appears: {a:?}");
    }
    // the only read-write binds are the prefix and the app home
    let rw: Vec<&str> = a
        .iter()
        .enumerate()
        .filter(|(_, x)| *x == "--bind" || *x == "--bind-try")
        .map(|(i, _)| a[i + 1].as_str())
        .collect();
    assert_eq!(rw, [PREFIX, APP_HOME]);
}

#[test]
fn variables_outside_the_allowlist_are_dropped_again() {
    let mut cmd = app_cmd();
    for (k, v) in [
        ("SSH_AUTH_SOCK", "/run/user/1000/ssh"),
        ("LD_PRELOAD", "/tmp/evil.so"),
        ("LD_LIBRARY_PATH", "/tmp"),
        ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
        ("AWS_SECRET_ACCESS_KEY", "x"),
        ("WINEPRELOADRESERVE", "x"),
    ] {
        cmd.env(k, v);
    }
    let e = envs(&sb(Permissions::default(), host()).render(&cmd).unwrap());
    for k in [
        "SSH_AUTH_SOCK",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DBUS_SESSION_BUS_ADDRESS",
        "AWS_SECRET_ACCESS_KEY",
        "WINEPRELOADRESERVE",
    ] {
        assert!(!e.contains_key(k), "{k} leaked");
    }
    assert_eq!(e["LANG"], "C.UTF-8");
}

#[test]
fn a_command_without_a_usable_prefix_is_refused() {
    let s = sb(Permissions::default(), host());
    let mut none = app_cmd();
    none.env_remove("WINEPREFIX");
    assert_eq!(s.render(&none).unwrap_err(), RenderError::NoPrefix);
    let w = s.wrap(none);
    assert_ne!(w.get_program(), "/usr/bin/bwrap");
    assert!(!argv(&w).iter().any(|x| x == "/usr/bin/wine"));
    assert!(
        s.argv_preview(&app_cmd_at("", APP_HOME))
            .iter()
            .any(|x| x.to_string_lossy().contains("refused"))
    );

    let mut linked = host();
    linked
        .links
        .insert("/data/apps/b/prefix".into(), "/home/me/prefix".into());
    linked = linked
        .with("/data/apps/b")
        .with("/data/apps/b/runtime")
        .with("/data/apps/b/runtime/home");
    for (prefix, why) in [
        ("data/apps/a/prefix", "is not absolute"),
        ("/data/apps/a/../a/prefix", "contains"),
        ("/data/apps/./a/prefix", "contains"),
        ("/data/apps/a/prefix/", "is not"),
        ("/data/apps/a/prefix2", "is not"),
        ("/data/apps/a", "is not"),
        ("/data/other/a/prefix", "is not"),
        ("/apps/prefix", "is not"),
        ("/prefix", "is not"),
        ("/data/apps/zz/prefix", "does not exist"),
        ("/data/apps/b/prefix", "symlink"),
    ] {
        let home = Path::new(prefix)
            .parent()
            .unwrap_or(Path::new("/"))
            .join("runtime/home");
        let c = app_cmd_at(prefix, home.to_str().unwrap());
        let e = sb(Permissions::default(), linked.clone()).render(&c).unwrap_err();
        assert!(
            matches!(&e, RenderError::BadPrefix { why: w, .. } if w.contains(why)),
            "{prefix}: {e:?}"
        );
    }
    // the app home must be the real directory the backend chose
    let mut h = host();
    h.links.insert(APP_HOME.into(), "/home/me".into());
    assert!(matches!(
        sb(Permissions::default(), h).render(&app_cmd()).unwrap_err(),
        RenderError::Home(_)
    ));
    let e = s.render(&app_cmd_at(PREFIX, "/home/me")).unwrap_err();
    assert!(matches!(e, RenderError::Home(_)), "{e:?}");
    let mut nohome = app_cmd();
    nohome.env_remove("HOME");
    assert!(matches!(s.render(&nohome).unwrap_err(), RenderError::Home(_)));
}

#[test]
fn the_prefix_is_bound_after_every_tmpfs_that_contains_it() {
    for (prefix, home) in [
        ("/tmp/x/apps/a/prefix", "/tmp/x/apps/a/runtime/home"),
        (
            "/run/user/1000/rt/apps/a/prefix",
            "/run/user/1000/rt/apps/a/runtime/home",
        ),
    ] {
        let h = host().app(prefix);
        let a = argv(&sb(Permissions::default(), h).render(&app_cmd_at(prefix, home)).unwrap());
        let p = pos(&a, &["--bind", prefix, prefix]).unwrap();
        let hm = pos(&a, &["--bind", home, home]).unwrap();
        for t in ["/tmp", RT] {
            let t = pos(&a, &["--tmpfs", t]).unwrap();
            assert!(p > t && hm > t, "{prefix}: {a:?}");
        }
        // and after every other mount: they are the last two before the read-only root remount and `--`
        let dd = a.iter().position(|x| x == "--").unwrap();
        assert_eq!(a[dd - 2..dd], ["--remount-ro", "/"]);
        assert_eq!(hm + 3, dd - 2);
        assert_eq!(p + 3, hm);
    }
}

#[test]
fn non_socket_display_and_audio_paths_and_a_non_file_xauthority_are_skipped() {
    // `WAYLAND_DISPLAY=bus`-style names pointing at something that is not a socket; the Pulse path a regular file
    let h = host()
        .without("/run/user/1000/wayland-1")
        .with("/run/user/1000/wayland-1")
        .with("/run/user/1000/bus")
        .without("/run/user/1000/pulse/native")
        .file("/run/user/1000/pulse/native");
    for w in ["wayland-1", "bus"] {
        let mut cmd = app_cmd();
        cmd.env("WAYLAND_DISPLAY", w);
        let s = sb(Permissions::default(), h.clone());
        let c = s.render(&cmd).unwrap();
        let a = argv(&c);
        assert!(!a.iter().any(|x| x.ends_with(w) || x.contains("pulse")), "{w}: {a:?}");
        assert!(!envs(&c).contains_key("PULSE_SERVER"));
        let sk = s.skipped(&cmd).join("\n");
        assert!(sk.contains(&format!("/run/user/1000/{w} is not a socket")), "{sk}");
        assert!(sk.contains("/run/user/1000/pulse/native is not a socket"), "{sk}");
    }
    // XAUTHORITY that is a directory, a symlink to the cookie, or relative: not bound, the variable dropped
    for (x, h) in [
        ("/home/me", host().with("/home/me")),
        ("/home/me/link", host().with("/home/me/link")),
        ("rel/.Xauthority", host()),
    ] {
        let mut cmd = app_cmd();
        cmd.env("XAUTHORITY", x);
        let s = sb(Permissions::default(), h);
        let c = s.render(&cmd).unwrap();
        assert!(!argv(&c).iter().any(|a| a.contains("Xauthority") || a == x), "{x}");
        assert!(!envs(&c).contains_key("XAUTHORITY"), "{x}");
        assert!(
            s.skipped(&cmd)
                .join("\n")
                .contains(&format!("XAUTHORITY {x} is not a regular file"))
        );
    }
}

#[test]
fn the_x11_caveat_is_given_exactly_when_the_x11_socket_dir_is_bound() {
    let has = |p: Permissions, cmd: &Command, h: FakeHost| sb(p, h).caveats(cmd).iter().any(|c| c == X11_CAVEAT);
    assert!(has(Permissions::default(), &app_cmd(), host()));
    assert!(!has(perms(|p| p.display = false), &app_cmd(), host()));
    let mut wayland_only = app_cmd();
    wayland_only.env_remove("DISPLAY");
    assert!(!has(Permissions::default(), &wayland_only, host()));
    // no X11 socket directory on the host: nothing bound, no caveat
    assert!(!has(
        Permissions::default(),
        &app_cmd(),
        host().without("/tmp/.X11-unix")
    ));
    assert!(X11_CAVEAT.contains("inject keyboard/mouse input") && X11_CAVEAT.contains("Wayland"));
}

#[test]
fn nested_grants_and_rw_grants_over_the_dll_dirs_are_refused_at_render() {
    let td = crate::grant_tempdir();
    let root = td.path().canonicalize().unwrap();
    let (outer, inner) = (root.join("g"), root.join("g/in"));
    std::fs::create_dir_all(&inner).unwrap();
    let two = |a: &PathBuf, b: &PathBuf| {
        perms(|p| {
            p.filesystem = vec![
                FsGrant {
                    path: a.clone(),
                    access: Access::Ro,
                },
                FsGrant {
                    path: b.clone(),
                    access: Access::Rw,
                },
            ]
        })
    };
    for (a, b) in [(&outer, &inner), (&inner, &outer)] {
        let e = sb(two(a, b), host()).render(&app_cmd()).unwrap_err();
        assert!(matches!(&e, RenderError::GrantOverlap(..)), "{e:?}");
    }
    // a Wine dll dir inside (or equal to, or above) a rw grant: refused; the same grant read-only is fine
    let dll = root.join("wine/lib");
    std::fs::create_dir_all(&dll).unwrap();
    for g in [root.join("wine"), dll.clone()] {
        let grant = |access| {
            perms(|p| {
                p.filesystem = vec![FsGrant {
                    path: g.clone(),
                    access,
                }]
            })
        };
        let s = |p| AppSandbox::new("/usr/bin/bwrap".into(), p, vec![dll.clone()], Arc::new(host()));
        let e = s(grant(Access::Rw)).render(&app_cmd()).unwrap_err();
        assert!(matches!(&e, RenderError::GrantOverlap(..)), "{g:?}: {e:?}");
        assert!(s(grant(Access::Ro)).render(&app_cmd()).is_ok());
    }
}

/// `<base>/real/data/apps/a/{prefix,runtime/home}` and `<base>/data -> real/data`.
fn symlinked_data_root() -> (tempfile::TempDir, PathBuf) {
    let td = crate::grant_tempdir();
    let base = td.path().canonicalize().unwrap();
    std::fs::create_dir_all(base.join("real/data/apps/a/prefix")).unwrap();
    std::fs::create_dir_all(base.join("real/data/apps/a/runtime/home")).unwrap();
    std::os::unix::fs::symlink(base.join("real/data"), base.join("data")).unwrap();
    (td, base)
}

#[test]
fn a_symlink_above_the_apps_dir_is_followed_and_the_resolved_dirs_are_bound_at_the_launchers_paths() {
    let (_td, base) = symlinked_data_root();
    let prefix = base.join("data/apps/a/prefix");
    let home = base.join("data/apps/a/runtime/home");
    let cmd = app_cmd_at(prefix.to_str().unwrap(), home.to_str().unwrap());
    let s = AppSandbox::new(
        "/usr/bin/bwrap".into(),
        Permissions::default(),
        vec![],
        Arc::new(crate::RealHost),
    );
    let c = s.render(&cmd).unwrap();
    let a = argv(&c);
    let real = |p: &str| base.join("real/data/apps/a").join(p).to_str().unwrap().to_owned();
    assert!(
        pos(&a, &["--bind", &real("prefix"), prefix.to_str().unwrap()]).is_some(),
        "{a:?}"
    );
    assert!(
        pos(&a, &["--bind", &real("runtime/home"), home.to_str().unwrap()]).is_some(),
        "{a:?}"
    );
    // inside, the paths stay what the launcher set
    let e = envs(&c);
    assert_eq!(e["WINEPREFIX"], prefix.to_str().unwrap());
    assert_eq!(e["HOME"], home.to_str().unwrap());
}

#[test]
fn a_symlink_at_or_below_the_app_root_is_refused() {
    type Mutate = fn(&Path);
    let cases: [(&str, Mutate); 5] = [
        ("app root", |app| {
            std::fs::rename(app, app.with_file_name("a-real")).unwrap();
            std::os::unix::fs::symlink(app.with_file_name("a-real"), app).unwrap();
        }),
        ("prefix", |app| {
            std::fs::rename(app.join("prefix"), app.join("p2")).unwrap();
            std::os::unix::fs::symlink(app.join("p2"), app.join("prefix")).unwrap();
        }),
        ("prefix elsewhere", |app| {
            std::fs::remove_dir(app.join("prefix")).unwrap();
            let elsewhere = app.parent().unwrap().parent().unwrap().join("elsewhere");
            std::fs::create_dir_all(&elsewhere).unwrap();
            std::os::unix::fs::symlink(&elsewhere, app.join("prefix")).unwrap();
        }),
        ("runtime", |app| {
            std::fs::rename(app.join("runtime"), app.join("rt2")).unwrap();
            std::os::unix::fs::symlink(app.join("rt2"), app.join("runtime")).unwrap();
        }),
        ("runtime/home", |app| {
            std::fs::rename(app.join("runtime/home"), app.join("h2")).unwrap();
            std::os::unix::fs::symlink(app.join("h2"), app.join("runtime/home")).unwrap();
        }),
    ];
    for (what, mutate) in cases {
        let (_td, base) = symlinked_data_root();
        mutate(&base.join("real/data/apps/a"));
        let prefix = base.join("data/apps/a/prefix");
        let home = base.join("data/apps/a/runtime/home");
        let cmd = app_cmd_at(prefix.to_str().unwrap(), home.to_str().unwrap());
        let s = AppSandbox::new(
            "/usr/bin/bwrap".into(),
            Permissions::default(),
            vec![],
            Arc::new(crate::RealHost),
        );
        let e = s.render(&cmd).unwrap_err();
        let ok = match what {
            "runtime" | "runtime/home" => matches!(e, RenderError::Home(_)),
            _ => matches!(&e, RenderError::BadPrefix { why, .. } if why.contains("symlink")),
        };
        assert!(ok, "{what}: {e:?}");
    }
}

/// `bwrap`, or `None` after saying why the real-bwrap tests are skipped (a failure under `RUNTIME_REQUIRE_BWRAP`).
fn real_bwrap(test: &str) -> Option<PathBuf> {
    let required = std::env::var_os("RUNTIME_REQUIRE_BWRAP").is_some_and(|v| !v.is_empty());
    let why = match crate::find_bwrap_on_path() {
        None => "bwrap is not on PATH".to_owned(),
        Some(b) => match crate::probe(&b) {
            Ok(()) => return Some(b),
            Err(e) => e,
        },
    };
    assert!(!required, "RUNTIME_REQUIRE_BWRAP=1 but {why}");
    eprintln!("SKIPPED {test}: {why}");
    None
}

/// A temp data root with app `a` (and a `permissions.toml`, an app-root secret and a data-root secret), `script`
/// run by `/bin/sh -c` inside the sandbox with `$1` = the real `$HOME`, `$2` = the app root, `$3` = the temp root.
/// Returns (stdout, stderr, temp root).
fn run_real(bwrap: PathBuf, p: Permissions, script: &str) -> (String, String, tempfile::TempDir) {
    run_real_with(bwrap, p, script, vec![])
}

/// [`run_real`] with test-only extra read-only binds that get NO Landlock rule (`AppSandbox::hole`).
fn run_real_with(
    bwrap: PathBuf,
    p: Permissions,
    script: &str,
    hole: Vec<PathBuf>,
) -> (String, String, tempfile::TempDir) {
    let td = tempfile::tempdir().unwrap();
    let root = td.path().canonicalize().unwrap();
    let app = root.join("apps/a");
    let (prefix, home) = (app.join("prefix"), app.join("runtime/home"));
    std::fs::create_dir_all(prefix.join("drive_c")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(app.join("permissions.toml"), "version = 1\n").unwrap();
    std::fs::write(app.join("secret"), "s").unwrap();
    std::fs::write(root.join("secret"), "s").unwrap();
    std::fs::write(root.join("cookie"), "cookie").unwrap();
    let real_home = std::env::var_os("HOME").unwrap_or_else(|| "/nonexistent".into());
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", script, "sh"])
        .arg(&real_home)
        .arg(&app)
        .arg(&root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("WINEPREFIX", &prefix)
        .env("HOME", &home)
        .env("XAUTHORITY", root.join("cookie"))
        .current_dir(prefix.join("drive_c"));
    for k in ["WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DISPLAY"] {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    let mut s = AppSandbox::new(bwrap, p, vec![], Arc::new(crate::RealHost));
    s.hole = hole;
    let out = s.wrap(cmd).output().unwrap();
    let (so, se) = (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    );
    assert!(out.status.success(), "{so}\n{se}");
    (so, se, td)
}

/// The real thing: `bwrap` runs a shell inside the default profile. Skips (loudly) without bwrap or user
/// namespaces, unless `RUNTIME_REQUIRE_BWRAP=1`.
#[test]
fn real_bwrap_runs_the_default_profile_and_hides_the_host() {
    let Some(bwrap) = real_bwrap("real_bwrap_runs_the_default_profile_and_hides_the_host") else {
        return;
    };
    let script = r#"
        echo ok
        ls -A "$1" 2>/dev/null | head -3
        echo "--home-end"
        [ -e "$2/permissions.toml" ] && echo "APP-ROOT-VISIBLE"
        echo pwned 2>/dev/null > "$2/permissions.toml"
        for f in "$2/secret" "$3/secret"; do [ -r "$f" ] && echo "SECRET-READ $f"; done
        touch /usr/rt-sandbox-probe 2>/dev/null && echo "USR-WRITABLE"
        touch /rt-sandbox-probe 2>/dev/null && echo "ROOT-WRITABLE"
        # (the path itself may exist: bwrap makes empty parent directories for the runtime executable's bind)
        mkdir -p "$1" 2>/dev/null && touch "$1/.rt-sandbox-probe" 2>/dev/null && echo "HOME-PATH-WRITABLE"
        mkdir "$1/.rt-sandbox-probe-dir" 2>/dev/null && echo "HOME-PATH-WRITABLE"
        touch "$WINEPREFIX/w" && echo prefix-rw
        touch "$HOME/w" && echo home-rw
        touch /dev/shm/w && echo shm-rw
        [ -z "$(ls -A /tmp | grep -v -e "^$(basename "$3")$" -e '^.X11-unix$')" ] && echo tmp-private
        echo "net:$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\n' ,)"
        if [ -n "$WAYLAND_DISPLAY" ]; then [ -S "$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY" ] && echo wayland-ok; fi
        if [ -n "$PULSE_SERVER" ]; then [ -S "${PULSE_SERVER#unix:}" ] && echo pulse-ok; fi
        case "$XAUTHORITY" in */Xauthority) [ "$(cat "$XAUTHORITY")" = cookie ] && echo xauth-ok;; esac
        [ -e "$XDG_RUNTIME_DIR/bus" ] && echo "BUS-VISIBLE"
        [ -e /etc/resolv.conf ] && echo "RESOLV-VISIBLE"
        true
    "#;
    let (so, se, td) = run_real(bwrap, Permissions::default(), script);
    let root = td.path().canonicalize().unwrap();
    let app = root.join("apps/a");
    let lines: Vec<&str> = so.lines().collect();
    assert_eq!(lines[0], "ok", "{so}\n{se}");
    // Nothing of the real home is listed, except (without Landlock, which refuses the listing) the empty directory
    // bwrap makes for the runtime executable's bind when the runtime lives below the home.
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    let skeleton = exe
        .strip_prefix(home.canonicalize().unwrap_or(home))
        .ok()
        .and_then(|rest| rest.iter().next())
        .map(|c| c.to_string_lossy().into_owned());
    let end = lines.iter().position(|l| *l == "--home-end").unwrap();
    assert!(
        lines[1..end].iter().all(|l| Some(*l) == skeleton.as_deref()),
        "the real home is listed inside: {so}"
    );
    for want in ["prefix-rw", "home-rw", "shm-rw", "tmp-private", "net:lo,", "xauth-ok"] {
        assert!(lines.contains(&want), "{want}: {so}\n{se}");
    }
    for bad in [
        "APP-ROOT-VISIBLE",
        "SECRET-READ",
        "USR-WRITABLE",
        "ROOT-WRITABLE",
        "HOME-PATH-WRITABLE",
        "BUS-VISIBLE",
        "RESOLV-VISIBLE",
    ] {
        assert!(!so.contains(bad), "{bad}: {so}");
    }
    assert_eq!(
        std::fs::read_to_string(app.join("permissions.toml")).unwrap(),
        "version = 1\n"
    );
    assert!(!Path::new("/usr/rt-sandbox-probe").exists());
    assert!(app.join("prefix/w").exists() && app.join("runtime/home/w").exists());
    // sockets bound at their own path inside the tmpfs runtime dir are really there (when the host has them)
    let rt = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    match (&rt, std::env::var_os("WAYLAND_DISPLAY")) {
        (Some(rt), Some(w)) if rt.join(&w).exists() => assert!(lines.contains(&"wayland-ok"), "{so}"),
        _ => eprintln!("SKIPPED wayland socket check: no Wayland socket on this host"),
    }
    match &rt {
        Some(rt) if rt.join("pulse/native").exists() => assert!(lines.contains(&"pulse-ok"), "{so}"),
        _ => eprintln!("SKIPPED pulse socket check: no PulseAudio socket on this host"),
    }
}

/// With `network = "allow"` the resolver configuration is readable inside (bwrap follows the `resolv.conf`
/// symlink on the host side) and more than loopback is visible.
#[test]
fn real_bwrap_with_network_allow_reads_the_resolver_config() {
    let Some(bwrap) = real_bwrap("real_bwrap_with_network_allow_reads_the_resolver_config") else {
        return;
    };
    let script = r#"
        grep -q '^nameserver' /etc/resolv.conf && echo dns-ok
        [ -r /etc/hosts ] && echo hosts-ok
        [ -e /run/systemd/resolve ] && echo "RESOLVE-DIR-VISIBLE"
        true
    "#;
    if !std::fs::read_to_string("/etc/resolv.conf").is_ok_and(|t| t.lines().any(|l| l.starts_with("nameserver"))) {
        eprintln!(
            "SKIPPED real_bwrap_with_network_allow_reads_the_resolver_config: no nameserver in the host's resolv.conf"
        );
        return;
    }
    let (so, se, _td) = run_real(bwrap, perms(|p| p.network = Network::Allow), script);
    assert!(so.contains("dns-ok") && so.contains("hosts-ok"), "{so}\n{se}");
    assert!(!so.contains("RESOLVE-DIR-VISIBLE"), "{so}");
}

fn required() -> bool {
    std::env::var_os("RUNTIME_REQUIRE_BWRAP").is_some_and(|v| !v.is_empty())
}

/// Prints `<what> <ptrace result> <errno>` for: PTRACE_ATTACH of its own child, of pid 1 (bwrap's own init,
/// outside the Landlock domain) and PTRACE_TRACEME.
const PTRACE_PY: &str = r#"
import ctypes, os, signal
c = ctypes.CDLL(None, use_errno=True)
c.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
def pt(what, req, pid):
    ctypes.set_errno(0)
    r = c.ptrace(req, pid, None, None)
    print(what, r, ctypes.get_errno())
    return r
child = os.fork()
if child == 0:
    import time
    time.sleep(10)
    os._exit(0)
if pt("attach-child", 16, child) == 0:
    os.waitpid(child, 0)
    c.ptrace(17, child, None, None)
os.kill(child, signal.SIGKILL)
pt("attach-pid1", 16, 1)
pt("traceme", 0, 0)
"#;

/// Through the real shim (this test binary, see `init::TEST_SHIM`) inside real bwrap: the program has the seccomp
/// filter and no new privileges, and Landlock refuses a file the MOUNT layer exposes but no rule covers (a
/// test-only bind punches that hole on purpose).
#[test]
fn real_bwrap_runs_the_program_through_the_shim_and_landlock_backs_the_mounts() {
    let Some(bwrap) = real_bwrap("real_bwrap_runs_the_program_through_the_shim_and_landlock_backs_the_mounts") else {
        return;
    };
    let hole_dir = crate::grant_tempdir();
    let hole = hole_dir.path().canonicalize().unwrap().join("hole.txt");
    std::fs::write(&hole, "exposed").unwrap();
    let script = format!(
        r#"
        grep -E '^(Seccomp|NoNewPrivs):' /proc/self/status | tr -d '\t '
        [ -e '{h}' ] && echo hole-exists
        cat '{h}' 2>/dev/null && echo || echo hole-denied
        cat /etc/passwd >/dev/null && echo etc-ok
        touch "$WINEPREFIX/w2" && echo prefix-rw
        echo x >/dev/null && echo devnull-ok
        [ -x /usr/bin/python3 ] && /usr/bin/python3 -c '{py}'
        true
    "#,
        h = hole.display(),
        py = PTRACE_PY
    );
    let (so, se, _td) = run_real_with(bwrap, Permissions::default(), &script, vec![hole.clone()]);
    let lines: Vec<&str> = so.lines().collect();
    assert_eq!(lines[..2], ["NoNewPrivs:1", "Seccomp:2"], "{so}\n{se}");
    for want in ["hole-exists", "etc-ok", "prefix-rw", "devnull-ok"] {
        assert!(lines.contains(&want), "{want}: {so}\n{se}");
    }
    if !Path::new("/usr/bin/python3").exists() {
        assert!(
            !required(),
            "RUNTIME_REQUIRE_BWRAP=1 but /usr/bin/python3 (the ptrace probe) is missing"
        );
        eprintln!("SKIPPED the ptrace half: no /usr/bin/python3");
    } else if crate::landlock::abi_version().is_ok() {
        // Landlock enforced: Wine's ptrace requests reach the program's own children and nothing outside its
        // domain (bwrap's pid 1); other requests stay refused.
        for want in ["attach-child 0 0", "attach-pid1 -1 1", "traceme -1 1"] {
            assert!(lines.contains(&want), "{want}: {so}\n{se}");
        }
    } else {
        assert!(
            lines.contains(&"attach-child -1 1"),
            "ptrace is refused without Landlock: {so}"
        );
    }
    match crate::landlock::abi_version() {
        Ok(_) => assert!(
            lines.contains(&"hole-denied") && !so.contains("exposed"),
            "LANDLOCK HOLE: {so}\n{se}"
        ),
        Err(e) => {
            assert!(so.contains("exposed"), "without Landlock the mount decides: {so}");
            eprintln!("SKIPPED the Landlock half: {e}");
        }
    }
}
