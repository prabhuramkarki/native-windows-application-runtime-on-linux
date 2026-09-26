//! [`AppSandbox`]: renders an app's [`Permissions`] into a `bwrap` command around the app's finalized Wine
//! command. The app is assumed malicious; Wine is not a boundary, bubblewrap is.
//!
//! **Which app.** The sandbox is attached to a `Launcher`, whose `Sandbox::wrap` gets only the finalized
//! [`Command`], so the app is derived from that command's `WINEPREFIX`: it must be an absolute, `.`/`..`-free
//! path of the exact shape `<apps dir>/<id>/prefix`, with the apps directory named `apps`, and the command's
//! `HOME` must be `<apps dir>/<id>/runtime/home` (the Wine backend's choice). Symlinks ABOVE the apps directory
//! are fine (a symlinked `~/.local/share`, `/home` on another disk, a `RUNTIME_DATA_DIR` on a symlinked mount),
//! but the app root, `prefix`, `runtime` and `runtime/home` must be real directories: each must resolve to the
//! resolved apps directory joined with its own name. The RESOLVED prefix and home are then bound at the paths
//! the launcher set (`--bind <resolved> <WINEPREFIX>`), so the program sees what it was told. Anything else is
//! refused ([`RenderError`]), never bound "as best we can". Only the prefix and that home are bound read-write;
//! the app root itself (which holds `permissions.toml`, the logs and metadata) is NEVER bound, nor is the data
//! root, another app or the real `$HOME`.
//!
//! **The profile** (everything not listed is invisible), in mount order: `--die-with-parent --new-session`
//! (detaches the real controlling terminal: no TIOCSTI injection) `--unshare-pid --unshare-uts --unshare-ipc`
//! and `--unshare-net` unless `network = "allow"`; a fresh `/proc`; a minimal `/dev` (bwrap's own: null, zero,
//! full, random, urandom, tty, pts, and a writable `/dev/shm` Wine needs); a private `/tmp`; read-only
//! [`RO_BINDS`], the `/etc` files in [`ETC_RO`], with network also [`NET_RO`] (`/etc/resolv.conf` is often a
//! symlink into `/run/systemd/resolve`; bwrap follows it on the host side, so only the file itself is bound), and
//! the backend's dll dirs; an EMPTY, `0700` tmpfs at the runtime directory (`$XDG_RUNTIME_DIR` when absolute and
//! `.`/`..`-free, else `/run/user/<uid>`); then per switch and only when the host has it: display = the Wayland
//! socket (which must BE a socket) and `/tmp/.X11-unix` (both read-only at their own paths) and the `XAUTHORITY`
//! cookie (which must be a regular file, not a link), bound read-only at `<runtime dir>/Xauthority` with the
//! variable rewritten to match; audio = `<runtime dir>/pulse/native` (a socket); gpu = `--dev-bind-try` of
//! `/dev/dri` and the NVIDIA nodes in [`GPU_DEV`] plus `/dev/nvidia<N>`, and read-only [`GPU_RO`] (Mesa and the
//! NVIDIA driver read `/sys`); each host directory grant (`--ro-bind` or `--bind`); finally the prefix and the app
//! home; last of all the root itself is remounted read-only, so nothing outside those mounts is writable, not even
//! in memory. A requested socket, cookie or node the host lacks is left out and reported by [`AppSandbox::skipped`].
//! `--dev-bind` is never used for anything but those GPU nodes.
//!
//! **Mount order** (bwrap applies its arguments in order and a LATER mount wins over an EARLIER one at the same
//! or a nested path, as `rt_installer::sandbox` found against real bwrap 0.11.1): every tmpfs (`/tmp`, the
//! runtime dir) comes before anything bound below it, or the tmpfs would swallow it (the X11 directory, the
//! sockets, the cookie, a prefix under `/tmp` in tests); the grants come after the system binds so a grant below
//! `/usr` is what shows there; and the app's own prefix and home come LAST, so nothing bound later can hide or
//! replace them. A grant can never be an ancestor of them anyway: grants at, above or below the data root are
//! refused, grants are re-validated at render time (one that no longer passes, or whose stored path now resolves
//! elsewhere, is a render error, not skipped), two grants may not nest (the later would silently override part
//! of the earlier, e.g. `rw` inside `ro`), and an `rw` grant may not overlap a Wine dll directory.
//!
//! **Environment.** Exactly the finalized command's variables that `rt_core::allowed_env` or the Wine backend
//! ([`BACKEND_ENV`]) may set (the launcher already filtered; re-applied here as defence in depth), minus those of a
//! switch that is off (display: `DISPLAY WAYLAND_DISPLAY XAUTHORITY`; audio: `PULSE_SERVER`) and minus
//! `DBUS_SESSION_BUS_ADDRESS` (no D-Bus socket is ever bound; with a shared network namespace an abstract bus
//! would otherwise be named for the app). With audio on and the socket bound, `PULSE_SERVER` is kept when it
//! names exactly that socket (`unix:<path>` or `<path>`) and is otherwise set to `unix:<runtime dir>/pulse/native`
//! (the only server reachable); without the socket it is dropped. `XAUTHORITY` is the bound copy's path, or
//! dropped when no cookie is bound. The network switch never changes the environment. The cwd is copied.
//!
//! **What the profile cannot enforce** ([`AppSandbox::caveats`]). With the X11 socket directory bound (display on
//! and `DISPLAY` set), the program is an ordinary X11 client of the host's X server: it can read and inject the
//! keyboard and mouse input of every other X11 window (XTEST, XSendEvent), which reaches host code execution. This
//! is the same as Flatpak's `--socket=x11`. The X11 directory is bound whenever display is on and `DISPLAY` is set,
//! whatever graphics driver the app's Wine uses: with Wine's Wayland driver (`runtime display <app> wayland`, which
//! isolates Wine's own windows) a program can still connect to the X11 socket itself (XWayland). With `network = "allow"` the host
//! network namespace is shared: ABSTRACT unix sockets live in the network namespace, not the filesystem, so X11's
//! `@/tmp/.X11-unix/X<n>` and any abstract D-Bus or other session socket are reachable whatever is bound, as are
//! the host's loopback TCP services. So `display = off` with network allowed CANNOT be enforced by bubblewrap (the
//! X server's cookie check is all that is left); the renderer says so instead of pretending.
//!
//! The renderer is pure: host facts come through [`Host`] (env, path existence, file types, symlink
//! resolution), so every switch is unit-tested with `Command` introspection (`get_program`, `get_args`,
//! `get_envs`, `get_current_dir`). [`AppSandbox::skipped`], [`AppSandbox::caveats`] and
//! [`AppSandbox::argv_preview`] each re-render; a launch computes the plan two or three times, which is cheap.
use crate::host::Host;
use crate::permissions::{
    Access, GrantCtx, Network, PermError, Permissions, account_home, related, validate_grant_for,
};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

/// The installer sandbox's fixed read-only system set (a copy of `rt_installer::sandbox::RO_BINDS`: see its docs
/// for why `/bin` is there — Debian's `/usr/bin/wine` is a `#!/bin/sh` wrapper). `rt_sandbox` does not depend on
/// `rt_installer`.
pub const RO_BINDS: [&str; 5] = ["/usr", "/bin", "/lib", "/lib64", "/etc/alternatives"];
/// The small `/etc` set Wine, fontconfig, the dynamic loader, TLS (Debian's `/etc/ssl`, Fedora's `/etc/pki`) and
/// the Vulkan/GLVND loaders read.
pub const ETC_RO: [&str; 11] = [
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
];
/// Name resolution, only with `network = "allow"`.
pub const NET_RO: [&str; 2] = ["/etc/hosts", "/etc/resolv.conf"];
/// GPU device nodes (with `/dev/nvidia<N>`, N < [`MAX_NVIDIA`]), dev-bound only when they exist.
pub const GPU_DEV: [&str; 5] = [
    "/dev/dri",
    "/dev/nvidiactl",
    "/dev/nvidia-uvm",
    "/dev/nvidia-uvm-tools",
    "/dev/nvidia-modeset",
];
const MAX_NVIDIA: u32 = 64;
/// What Mesa and the NVIDIA driver read besides the nodes (`/run/opengl-driver`: NixOS driver libraries).
pub const GPU_RO: [&str; 4] = ["/sys/dev/char", "/sys/devices", "/sys/class/drm", "/run/opengl-driver"];
/// What the Wine backend sets on its command (`backend-wine`'s `wine_command`), besides the host allowlist.
pub const BACKEND_ENV: [&str; 6] = [
    "WINEPREFIX",
    "HOME",
    "WINEARCH",
    "WINEDEBUG",
    "WINEDLLOVERRIDES",
    "WINESERVER",
];
const DISPLAY_ENV: [&str; 3] = ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"];
const X11_DIR: &str = "/tmp/.X11-unix";
/// Where the X11 cookie is bound inside, under the runtime directory.
const XAUTH_NAME: &str = "Xauthority";
/// Always given when the X11 socket directory is bound (module docs, "What the profile cannot enforce").
pub const X11_CAVEAT: &str = "X11 is shared with the host: the program can read and inject keyboard/mouse input of \
                              other X11 windows. Wine's Wayland driver (`runtime display <app> wayland`) keeps Wine \
                              itself off X11, but the X11 socket stays reachable to the program until `runtime \
                              permissions <app> --set display=off`";
const NET_CAVEAT: &str = "network=allow shares the host network namespace: abstract unix sockets (X11's \
                          @/tmp/.X11-unix/X<n>, any abstract D-Bus or other session socket) and the host's loopback \
                          TCP services (CUPS, development servers, a TCP Docker API) are reachable from inside";
const DISPLAY_OFF_CAVEAT: &str = "display=off cannot be enforced with network=allow: the X server's abstract \
                                  socket @/tmp/.X11-unix/X<n> stays reachable (only its cookie check remains)";

/// Why a command cannot be sandboxed. [`AppSandbox::wrap`] turns every one into a command that refuses to run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenderError {
    #[error("the command has no WINEPREFIX: there is no app to sandbox")]
    NoPrefix,
    #[error("WINEPREFIX {path:?} {why}")]
    BadPrefix { path: String, why: &'static str },
    #[error("the command's HOME is not the app's own real home directory {0:?}")]
    Home(String),
    #[error("HOME is not set to an absolute path: cannot check the profile's host directory grants")]
    NoRealHome,
    #[error("the profile's host directory grant is no longer valid: {0}")]
    Grant(PermError),
    #[error(
        "{0:?} and {1:?} overlap (one is inside the other): a grant may not nest in another, and a writable grant may not cover a Wine directory"
    )]
    GrantOverlap(String, String),
    #[error("the host directory grant {0:?} now resolves to another directory; grant it again")]
    GrantMoved(String),
}

/// See the module docs. `ro_binds` are the backend's dll directories (bound read-only).
pub struct AppSandbox {
    bwrap: PathBuf,
    perms: Permissions,
    ro_binds: Vec<PathBuf>,
    host: Arc<dyn Host>,
}

/// One rendering: the command, what was left out and what cannot be enforced.
struct Rendered {
    cmd: Command,
    skipped: Vec<String>,
    caveats: Vec<String>,
}

/// The app's two writable directories: `src` is what is bound (symlinks above the apps dir resolved), `dst`
/// where (the launcher's spelling); and the data root grants are judged against.
struct AppDirs {
    prefix_src: PathBuf,
    prefix_dst: PathBuf,
    home_src: PathBuf,
    home_dst: PathBuf,
    data_root: PathBuf,
}

/// Absolute and free of `.`/`..` components, judged on the text (`Path::components` drops an interior `.`).
fn plain_abs(p: &Path) -> bool {
    p.is_absolute()
        && !p
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .any(|c| c == b"." || c == b"..")
}

fn lossy(p: &Path) -> String {
    p.to_string_lossy().chars().take(200).collect()
}

fn env_of<'a>(cmd: &'a Command, name: &str) -> Option<&'a OsStr> {
    cmd.get_envs()
        .find(|(k, _)| *k == OsStr::new(name))
        .and_then(|(_, v)| v)
}

/// The command's app directories, checked (module docs, "Which app").
fn app_dirs(cmd: &Command, host: &dyn Host) -> Result<AppDirs, RenderError> {
    let prefix = PathBuf::from(env_of(cmd, "WINEPREFIX").ok_or(RenderError::NoPrefix)?);
    let bad = |why| RenderError::BadPrefix {
        path: lossy(&prefix),
        why,
    };
    if !prefix.is_absolute() {
        return Err(bad("is not absolute"));
    }
    if !plain_abs(&prefix) {
        return Err(bad("contains `.` or `..` components"));
    }
    let shape = "is not <data root>/apps/<app>/prefix";
    if prefix.as_os_str().as_bytes().ends_with(b"/") || prefix.file_name() != Some(OsStr::new("prefix")) {
        return Err(bad(shape));
    }
    let root = prefix.parent().ok_or(bad(shape))?;
    let id = root.file_name().ok_or(bad(shape))?;
    let apps = root.parent().ok_or(bad(shape))?;
    if apps.file_name() != Some(OsStr::new("apps")) {
        return Err(bad(shape));
    }
    let data_root = apps.parent().ok_or(bad(shape))?.to_path_buf();
    // Symlinks above `apps` are resolved; at or below the app root every component must be real.
    let real_apps = host.resolve(apps).ok_or(bad("does not exist"))?;
    let real_root = real_apps.join(id);
    let real_prefix = real_root.join("prefix");
    for (p, want) in [(root, &real_root), (prefix.as_path(), &real_prefix)] {
        match host.resolve(p) {
            None => return Err(bad("does not exist")),
            Some(r) if r != *want => return Err(bad("goes through a symlink at or below the app directory")),
            Some(_) => {}
        }
    }
    let home = root.join("runtime/home");
    let real_home = real_root.join("runtime/home");
    let home_ok = env_of(cmd, "HOME").is_some_and(|h| Path::new(h) == home)
        && host.resolve(&root.join("runtime")) == Some(real_root.join("runtime"))
        && host.resolve(&home) == Some(real_home.clone());
    if !home_ok {
        return Err(RenderError::Home(lossy(&home)));
    }
    Ok(AppDirs {
        prefix_src: real_prefix,
        prefix_dst: prefix.clone(),
        home_src: real_home,
        home_dst: home,
        data_root,
    })
}

impl AppSandbox {
    pub fn new(bwrap: PathBuf, perms: Permissions, ro_binds: Vec<PathBuf>, host: Arc<dyn Host>) -> AppSandbox {
        AppSandbox {
            bwrap,
            perms,
            ro_binds,
            host,
        }
    }

    /// The sandboxed command for the finalized `cmd` (module docs), or why there is none.
    pub fn render(&self, cmd: &Command) -> Result<Command, RenderError> {
        self.plan(cmd).map(|r| r.cmd)
    }

    /// The command line [`AppSandbox::wrap`] would run, program first (what `runtime sandbox` prints). When the
    /// command cannot be sandboxed that is the refusal command, which names the reason.
    pub fn argv_preview(&self, cmd: &Command) -> Vec<OsString> {
        let c = self.render(cmd).unwrap_or_else(|e| refusal(&e));
        std::iter::once(c.get_program())
            .chain(c.get_args())
            .map(OsStr::to_owned)
            .collect()
    }

    /// The requested display/audio/gpu pieces the host does not have (left out of the profile), one line each;
    /// empty when the command cannot be rendered at all.
    pub fn skipped(&self, cmd: &Command) -> Vec<String> {
        self.plan(cmd).map(|r| r.skipped).unwrap_or_default()
    }

    /// What this profile, as rendered for `cmd`, cannot enforce; empty when the command cannot be rendered. With
    /// the X11 socket directory bound, always [`X11_CAVEAT`]: X11 is shared with the host, so the program can read
    /// and inject keyboard/mouse input of other X11 windows; Wine's Wayland driver does not change that (the socket
    /// stays bound), only `display = off` does.
    /// With `network = "allow"`: abstract sockets and host loopback services, and that `display = off` cannot be
    /// enforced then.
    pub fn caveats(&self, cmd: &Command) -> Vec<String> {
        self.plan(cmd).map(|r| r.caveats).unwrap_or_default()
    }

    fn ctx(&self, data_root: PathBuf) -> Result<GrantCtx, RenderError> {
        let home = self
            .host
            .env("HOME")
            .map(PathBuf::from)
            .filter(|h| h.is_absolute())
            .ok_or(RenderError::NoRealHome)?;
        Ok(GrantCtx {
            extra_homes: account_home().into_iter().filter(|h| *h != home).collect(),
            home,
            data_root,
            runtime_dir: self
                .host
                .env("XDG_RUNTIME_DIR")
                .map(PathBuf::from)
                .filter(|d| d.is_absolute()),
        })
    }

    /// Every grant re-validated (module docs, "Mount order"): valid, unmoved, not nested in another, and not
    /// writable over a Wine dll directory.
    fn grants(&self, data_root: PathBuf) -> Result<Vec<(PathBuf, Access)>, RenderError> {
        let mut grants: Vec<(PathBuf, Access)> = Vec::new();
        if self.perms.filesystem.is_empty() {
            return Ok(grants);
        }
        let ctx = self.ctx(data_root)?;
        for g in &self.perms.filesystem {
            let real = validate_grant_for(&g.path, g.access, &ctx).map_err(RenderError::Grant)?;
            if real != g.path {
                return Err(RenderError::GrantMoved(lossy(&g.path)));
            }
            if let Some((other, _)) = grants.iter().find(|(o, _)| related(o, &real)) {
                return Err(RenderError::GrantOverlap(lossy(other), lossy(&real)));
            }
            if g.access == Access::Rw
                && let Some(dll) = self
                    .ro_binds
                    .iter()
                    .find(|d| self.host.resolve(d).iter().chain([*d]).any(|d| related(d, &real)))
            {
                return Err(RenderError::GrantOverlap(lossy(&real), lossy(dll)));
            }
            grants.push((real, g.access));
        }
        Ok(grants)
    }

    fn plan(&self, cmd: &Command) -> Result<Rendered, RenderError> {
        let dirs = app_dirs(cmd, &*self.host)?;
        let p = &self.perms;
        // Grants first: a stale one refuses the whole run before anything else is looked at.
        let grants = self.grants(dirs.data_root.clone())?;
        let mut skipped = Vec::new();
        let mut caveats = Vec::new();
        let rt_env = env_of(cmd, "XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|d| plain_abs(d));
        let rt = rt_env
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", self.host.uid())));

        let mut out = Command::new(&self.bwrap);
        out.args([
            "--die-with-parent",
            "--new-session",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-ipc",
        ]);
        if p.network == Network::Deny {
            out.arg("--unshare-net");
        }
        out.args(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]);
        let ro_try = |out: &mut Command, d: &Path| {
            out.arg("--ro-bind-try").arg(d).arg(d);
        };
        for d in RO_BINDS.iter().chain(&ETC_RO) {
            ro_try(&mut out, Path::new(d));
        }
        if p.network == Network::Allow {
            for d in NET_RO {
                ro_try(&mut out, Path::new(d));
            }
        }
        for d in &self.ro_binds {
            ro_try(&mut out, d);
        }
        // Empty and private: only what is bound below appears in it (bwrap creates the parent directories).
        out.args(["--perms", "0700", "--tmpfs"]).arg(&rt);

        // `<what> path <p> is not a socket`, or bound.
        let socket = |out: &mut Command, skipped: &mut Vec<String>, what: &str, s: &Path| {
            if self.host.is_socket(s) {
                ro_try(out, s);
                true
            } else {
                skipped.push(format!(
                    "{what} path {} is not a socket (missing or another file type)",
                    s.display()
                ));
                false
            }
        };
        let mut xauth = None;
        if p.display {
            let wayland = env_of(cmd, "WAYLAND_DISPLAY");
            let display = env_of(cmd, "DISPLAY");
            if wayland.is_none() && display.is_none() {
                skipped.push("display: neither DISPLAY nor WAYLAND_DISPLAY is set".to_owned());
            }
            if let Some(w) = wayland {
                // A socket NAME inside the runtime dir; an absolute or multi-component value is not followed.
                let name_ok = !w.is_empty() && !w.as_bytes().contains(&b'/') && w != ".." && w != ".";
                match &rt_env {
                    _ if !name_ok => skipped.push(format!(
                        "display: WAYLAND_DISPLAY {:?} is not a socket name",
                        w.to_string_lossy()
                    )),
                    None => skipped
                        .push("display: Wayland socket (XDG_RUNTIME_DIR is unset or not an absolute path)".to_owned()),
                    Some(rt) => {
                        socket(&mut out, &mut skipped, "display: Wayland socket", &rt.join(w));
                    }
                }
            }
            if display.is_some() {
                if self.host.exists(Path::new(X11_DIR)) {
                    ro_try(&mut out, Path::new(X11_DIR));
                    caveats.push(X11_CAVEAT.to_owned());
                } else {
                    skipped.push(format!("display: X11 socket directory {X11_DIR} does not exist"));
                }
            }
            if let Some(x) = env_of(cmd, "XAUTHORITY").map(Path::new) {
                // A copy at a fixed path in the private runtime dir: the host path (often under the real home)
                // never appears inside.
                if plain_abs(x) && self.host.is_file(x) {
                    let dst = rt.join(XAUTH_NAME);
                    out.arg("--ro-bind").arg(x).arg(&dst);
                    xauth = Some(dst);
                } else {
                    skipped.push(format!(
                        "display: XAUTHORITY {} is not a regular file (missing, a link or another file type)",
                        x.display()
                    ));
                }
            }
        }
        let mut pulse = None;
        if p.audio {
            match &rt_env {
                None => skipped
                    .push("audio: PulseAudio socket (XDG_RUNTIME_DIR is unset or not an absolute path)".to_owned()),
                Some(rt) => {
                    let s = rt.join("pulse/native");
                    if socket(&mut out, &mut skipped, "audio: PulseAudio socket", &s) {
                        pulse = Some(s);
                    }
                }
            }
        }
        if p.gpu {
            let nodes: Vec<PathBuf> = GPU_DEV
                .iter()
                .map(PathBuf::from)
                .chain((0..MAX_NVIDIA).map(|n| PathBuf::from(format!("/dev/nvidia{n}"))))
                .filter(|n| self.host.exists(n))
                .collect();
            if nodes.is_empty() {
                skipped.push("gpu: no GPU device nodes (/dev/dri, /dev/nvidia*) exist".to_owned());
            }
            for n in &nodes {
                out.arg("--dev-bind-try").arg(n).arg(n);
            }
            for d in GPU_RO {
                ro_try(&mut out, Path::new(d));
            }
        }
        for (g, access) in &grants {
            out.arg(if *access == Access::Rw { "--bind" } else { "--ro-bind" })
                .arg(g)
                .arg(g);
        }
        // Last, so no other mount can hide or replace them (module docs, "Mount order"); the resolved directory at
        // the launcher's path.
        out.arg("--bind").arg(&dirs.prefix_src).arg(&dirs.prefix_dst);
        out.arg("--bind").arg(&dirs.home_src).arg(&dirs.home_dst);
        // bwrap's new root is a writable tmpfs holding the skeleton directories of every mount point (the parents of
        // the prefix, i.e. the app root and data root paths, or the real home's path): without this a write to
        // `<app root>/permissions.toml` or `$HOME/x` "succeeds" in memory (found by the escape suite). Read-only root
        // mount only: the binds, `/tmp`, `/dev` (with `/dev/shm`) and the runtime dir are their own mounts.
        out.args(["--remount-ro", "/"]);
        out.arg("--");
        out.arg(cmd.get_program());
        out.args(cmd.get_args());

        // A new `Command` inherits THIS process's environment: clear it, then replay only what is allowed.
        out.env_clear();
        for (k, v) in cmd.get_envs() {
            let Some(v) = v else { continue };
            let allowed = BACKEND_ENV.iter().any(|b| k == OsStr::new(b)) || !rt_core::allowed_env([(k, v)]).is_empty();
            // A switch that is off, D-Bus (never bound), and PULSE_SERVER/XAUTHORITY (re-decided below).
            let withheld = (!p.display && DISPLAY_ENV.iter().any(|d| k == OsStr::new(d)))
                || ["PULSE_SERVER", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS"]
                    .iter()
                    .any(|d| k == OsStr::new(d));
            if allowed && !withheld {
                out.env(k, v);
            }
        }
        if let Some(x) = xauth {
            out.env("XAUTHORITY", x);
        }
        if let Some(sock) = pulse {
            // Only the one bound socket is reachable, so only a value naming exactly it is kept: a list such as
            // `unix:<sock> tcp:host` or another path is replaced.
            let keep = env_of(cmd, "PULSE_SERVER")
                .filter(|v| Path::new(v.as_bytes().strip_prefix(b"unix:").map_or(*v, OsStr::from_bytes)) == sock);
            match keep {
                Some(v) => out.env("PULSE_SERVER", v),
                None => {
                    let mut v = OsString::from("unix:");
                    v.push(&sock);
                    out.env("PULSE_SERVER", v)
                }
            };
        }
        if let Some(dir) = cmd.get_current_dir() {
            out.current_dir(dir);
        }
        if p.network == Network::Allow {
            caveats.push(NET_CAVEAT.to_owned());
            if !p.display {
                caveats.push(DISPLAY_OFF_CAVEAT.to_owned());
            }
        }
        Ok(Rendered {
            cmd: out,
            skipped,
            caveats,
        })
    }
}

/// What runs instead of an app that cannot be sandboxed: a shell that prints the reason and exits 126, with an
/// empty environment. Nothing of the app's command is in it.
fn refusal(e: &RenderError) -> Command {
    let mut c = Command::new("/bin/sh");
    c.args([
        "-c",
        "printf 'runtime: the sandbox refused to start the program: %s\\n' \"$1\" >&2; exit 126",
    ])
    .arg("sh")
    .arg(e.to_string())
    .env_clear();
    c
}

impl rt_core::Sandbox for AppSandbox {
    /// [`AppSandbox::render`]; fails closed: a command that cannot be sandboxed becomes [`refusal`].
    fn wrap(&self, cmd: Command) -> Command {
        self.render(&cmd).unwrap_or_else(|e| refusal(&e))
    }
}

#[cfg(test)]
mod tests;
