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

fn argv(c: &Command) -> Vec<String> {
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
    assert_eq!(c.get_program(), "/usr/bin/bwrap");
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
    want.extend(["--bind", PREFIX, PREFIX, "--bind", APP_HOME, APP_HOME]);
    want.extend(["--remount-ro", "/"]);
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
    assert_eq!(preview[0], "/usr/bin/bwrap");
    assert_eq!(preview[1..], c.get_args().map(OsString::from).collect::<Vec<_>>()[..]);
    // and `Sandbox::wrap` is `render`
    assert_eq!(argv(&s.wrap(app_cmd())), argv(&c));
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
    let s = AppSandbox::new(bwrap, p, vec![], Arc::new(crate::RealHost));
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
        mkdir -p "$1" 2>/dev/null && echo "HOME-PATH-WRITABLE"
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
    assert_eq!(lines[1], "--home-end", "the real home is listed inside: {so}");
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
