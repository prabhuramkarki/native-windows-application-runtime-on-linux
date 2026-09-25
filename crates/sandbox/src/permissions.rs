//! `permissions.toml`: what one app may reach beyond the GUI baseline. Lives in the app root (NEVER bound into
//! the sandbox), is written only by `runtime permissions`, and is parsed strictly: unknown keys, another
//! `version`, more than [`MAX_BYTES`] bytes or [`MAX_GRANTS`] grants are refused, never narrowed or ignored.
//!
//! ```toml
//! version = 1
//! network = "deny"     # or "allow"
//! display = true
//! audio = true
//! gpu = true
//!
//! [[filesystem]]
//! path = "/home/me/Documents/game-saves"   # absolute, must exist, symlinks resolved when it is added
//! access = "rw"                            # or "ro"
//! ```
//!
//! A host directory grant is judged by [`validate_grant`] on every parse (so a stored profile that no longer
//! passes, e.g. a symlink re-pointed at `$HOME`, is refused at run time): absolute, no `.`/`..`, no control or
//! invisible characters, the symlink-resolved path re-checked, and never `/`, `$HOME`, the runtime data
//! directory (equal, above or below), a fixed list of secret directories under `$HOME` (equal, above or below),
//! or `/proc`, `/sys`, `/dev`, `/run`, `/var/run`, `/tmp` itself, the socket-bearing `/tmp` children in
//! [`RESERVED_TMP_CHILDREN`] (`.X11-unix`, `tmux-*`, `ssh-*`, ...; equal or below), any other `/tmp` directory
//! holding a socket near its top ([`socket_within`]), and `$XDG_RUNTIME_DIR` (devices and runtime sockets belong to
//! the gpu/display/audio switches, and a daemon socket such as docker's would be root on the host). A grant must
//! resolve to a DIRECTORY (never a socket, device node or dotfile), and `rw` is refused on
//! (and below) the system trees in [`RO_ONLY`], where `ro` stays allowed.
use serde::Deserialize;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The profile's file name in the app root.
pub const FILE_NAME: &str = "permissions.toml";
/// Largest profile read or written.
pub const MAX_BYTES: u64 = 64 * 1024;
/// Most filesystem grants in one profile.
pub const MAX_GRANTS: usize = 64;
/// Longest grant path (Linux `PATH_MAX`).
const MAX_PATH_BYTES: usize = 4096;

/// Directories under `$HOME` no grant may equal, contain or sit inside: credentials and keyrings, browser and
/// mail profiles, CLI tokens (`gh`, `rclone`, cloud SDKs, `cargo`'s registry token), and places whose contents
/// the host later EXECUTES (`~/.local/bin` on `$PATH`, systemd user units, autostart entries, git hooks and
/// config, Flatpak app data). An ancestor such as `~/.config` is refused too, naming the child it would expose.
const SENSITIVE: [&str; 24] = [
    ".ssh",
    ".gnupg",
    ".aws",
    ".config/gcloud",
    ".kube",
    ".docker",
    ".password-store",
    ".local/share/keyrings",
    ".pki",
    ".mozilla",
    ".thunderbird",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    ".config/gh",
    ".config/rclone",
    ".azure",
    ".cargo",
    ".terraform.d",
    ".var/app",
    ".config/systemd",
    ".config/autostart",
    ".local/bin",
    ".config/git",
];
/// Host paths governed by the gpu/display/audio switches, never by a grant (equal, above or below). `/run` holds
/// every daemon socket (`docker.sock`, `dbus`, ...); `/var/run` is the same tree on hosts where it is no symlink.
const SYSTEM: [&str; 5] = ["/proc", "/sys", "/dev", "/run", "/var/run"];
/// Shared spots holding other programs' sockets (ssh-agent, the X11 socket that would bypass `display=off`).
const RESERVED_TMP: &str = "/tmp";
/// `/tmp` children that hold (or will hold) other programs' sockets, by name: a grant equal to or below one is
/// refused ([`RESERVED_TMP`] itself, the only thing above them, already is). A trailing `*` matches any rest of
/// the name. Other `/tmp` children are judged by what they hold: see [`socket_within`].
const RESERVED_TMP_CHILDREN: [&str; 12] = [
    "/tmp/.X11-unix",
    "/tmp/.ICE-unix",
    "/tmp/.XIM-unix",
    "/tmp/.font-unix",
    "/tmp/.Test-unix",
    "/tmp/snap-private-tmp",
    "/tmp/tmux-*",
    "/tmp/ssh-*",
    "/tmp/dbus-*",
    "/tmp/pulse-*",
    "/tmp/runtime-*",
    "/tmp/systemd-private-*",
];
/// System trees that may be granted read-only but never read-write (equal or below), except [`RW_OK`].
const RO_ONLY: [&str; 12] = [
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/boot", "/opt", "/var", "/srv", "/root",
];
/// A world-writable scratch directory under `/var`, like `/tmp` children.
const RW_OK: &str = "/var/tmp";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Deny,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Ro,
    Rw,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsGrant {
    pub path: PathBuf,
    pub access: Access,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permissions {
    pub network: Network,
    pub display: bool,
    pub audio: bool,
    pub gpu: bool,
    pub filesystem: Vec<FsGrant>,
}

impl Default for Permissions {
    fn default() -> Self {
        Permissions {
            network: Network::Deny,
            display: true,
            audio: true,
            gpu: true,
            filesystem: Vec::new(),
        }
    }
}

/// What a grant is checked against: the real `$HOME` and the runtime data directory.
#[derive(Debug, Clone)]
pub struct GrantCtx {
    pub home: PathBuf,
    /// Other spellings of a home directory (the account's, from the password database): everything that holds
    /// for `home` holds for these too, so a different `$HOME` cannot sidestep the sensitive list.
    pub extra_homes: Vec<PathBuf>,
    pub data_root: PathBuf,
    /// `$XDG_RUNTIME_DIR` when set (its own sockets are never granted, wherever it is).
    pub runtime_dir: Option<PathBuf>,
}

impl GrantCtx {
    fn homes(&self) -> impl Iterator<Item = &PathBuf> {
        std::iter::once(&self.home).chain(&self.extra_homes)
    }
}

/// The current account's home directory from the password database (`getpwuid_r` of the effective uid), when it
/// is an absolute path. A very long entry (`ERANGE`) is retried with a larger buffer ([`grow_buf`]).
pub fn account_home() -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    grow_buf(|buf| {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call; `pw_dir` points into `buf`, which outlives the copy below.
        let rc = unsafe { libc::getpwuid_r(libc::geteuid(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut res) };
        if rc != 0 {
            return Err(rc);
        }
        if res.is_null() || pwd.pw_dir.is_null() {
            return Ok(None);
        }
        let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
        Ok(Some(PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()))))
    })
    .flatten()
    .filter(|p| p.is_absolute())
}

/// Largest buffer [`grow_buf`] tries.
const MAX_PWD_BUF: usize = 1 << 20;

/// Calls `call` with a 16 KiB buffer, doubling it while `call` fails with `ERANGE` (the `getpwuid_r` protocol), up
/// to [`MAX_PWD_BUF`]; any other error, or `ERANGE` at the cap, is `None`.
fn grow_buf<T>(mut call: impl FnMut(&mut [libc::c_char]) -> Result<T, i32>) -> Option<T> {
    let mut len = 16 * 1024;
    loop {
        let mut buf = vec![0 as libc::c_char; len];
        match call(&mut buf) {
            Ok(t) => return Some(t),
            Err(libc::ERANGE) if len < MAX_PWD_BUF => len *= 2,
            Err(_) => return None,
        }
    }
}

/// The first socket at depth 1 or 2 below `dir` (entries are not followed: a symlink to a socket is not one, and a
/// bind never follows it on the host side). A `/tmp` grant holding one is refused: ssh-agent, nvim, Chromium's
/// singleton and many others put their sockets in arbitrarily named `/tmp` directories.
///
/// ponytail: depth 2 and only at validation time (every load and render re-checks); a socket created deeper, or
/// after the check while the app runs, is not caught. Refusing all of `/tmp/**` would close that, but the test
/// suites' temp directories live under `/tmp` and a deeper test root would overflow `sun_path` for the socket tests.
fn socket_within(dir: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::FileTypeExt;
    for e in fs::read_dir(dir).ok()?.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_socket() {
            return Some(e.path());
        }
        if ft.is_dir()
            && let Ok(rd) = fs::read_dir(e.path())
        {
            for e2 in rd.flatten() {
                if e2.file_type().is_ok_and(|t| t.is_socket()) {
                    return Some(e2.path());
                }
            }
        }
    }
    None
}

/// Why a grant path was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("the path must be absolute")]
    NotAbsolute,
    #[error("the path must not contain `.` or `..` components")]
    DotComponents,
    #[error("the path must be UTF-8 without control or invisible characters")]
    BadChars,
    #[error("the path is longer than {MAX_PATH_BYTES} bytes")]
    TooLong,
    #[error("the path does not exist (a grant must point at something that exists when it is added)")]
    Missing,
    #[error("`/` cannot be granted")]
    Root,
    #[error("the home directory cannot be granted")]
    Home,
    #[error("it contains ~/{0}, which is never shared")]
    Ancestor(&'static str),
    #[error("it is inside ~/{0}, which is never shared")]
    Inside(&'static str),
    #[error("it is, contains or is inside the runtime's data directory")]
    DataRoot,
    #[error("{0} holds device nodes and runtime sockets (the gpu/display/audio switches govern them, never a grant)")]
    System(&'static str),
    #[error("{0} holds other programs' sockets and cannot be granted")]
    Reserved(&'static str),
    #[error("it is, contains or is inside $XDG_RUNTIME_DIR, which holds the session's sockets")]
    RuntimeDir,
    #[error("it is not a directory (only directories can be granted, never a socket, device or plain file)")]
    NotDirectory,
    #[error("{0} is never writable: grant it read-only (ro)")]
    ReadOnlyOnly(&'static str),
    #[error("it is under /tmp and holds a socket ({0}) that would reach another program")]
    TmpSocket(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PermError {
    #[error("{0}")]
    Io(String),
    #[error("{FILE_NAME} is larger than {MAX_BYTES} bytes")]
    TooLarge,
    #[error("{FILE_NAME} is not a plain file (a symlink, FIFO or directory)")]
    NotRegular,
    #[error("{FILE_NAME} is not valid: {0}")]
    Toml(String),
    #[error("{FILE_NAME} has version {0}; only version 1 is understood")]
    Version(i64),
    #[error("more than {MAX_GRANTS} filesystem grants")]
    TooManyGrants,
    #[error("filesystem grant {0:?} appears twice")]
    DuplicateGrant(String),
    #[error("cannot grant {path:?}: {why}")]
    Grant { path: String, why: Refusal },
    #[error(
        "bad permission {0:?}: use network=allow|deny, display|audio|gpu=on|off, fs+=/abs/path:ro|rw or fs-=/abs/path"
    )]
    Expr(String),
    #[error("{0:?} is not granted")]
    NotGranted(String),
}

fn io_err(e: io::Error) -> PermError {
    PermError::Io(e.to_string())
}

fn clip(s: &str) -> String {
    s.chars().take(200).collect()
}

fn lossy(p: &Path) -> String {
    clip(&p.to_string_lossy())
}

/// `p` and, when it exists and differs, its symlink-resolved form: a `$HOME` or `~/.ssh` that is itself a symlink
/// must be judged by both spellings.
fn variants(p: &Path) -> Vec<PathBuf> {
    let mut v = vec![p.to_path_buf()];
    if let Ok(c) = fs::canonicalize(p)
        && c != p
    {
        v.push(c);
    }
    v
}

fn related(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

fn syntax(p: &Path) -> Result<(), Refusal> {
    if !p.is_absolute() {
        return Err(Refusal::NotAbsolute);
    }
    let Some(s) = p.to_str() else {
        return Err(Refusal::BadChars);
    };
    if s.chars().any(|c| c.is_control() || rt_core::is_format(c)) {
        return Err(Refusal::BadChars);
    }
    if s.len() > MAX_PATH_BYTES {
        return Err(Refusal::TooLong);
    }
    // On the text: `Path::components` silently drops an interior `.`.
    if s.split('/').any(|c| c == "." || c == "..") {
        return Err(Refusal::DotComponents);
    }
    Ok(())
}

/// The location rules, run on the path as written and again on its resolved form.
fn locate(p: &Path, ctx: &GrantCtx) -> Result<(), Refusal> {
    if p == Path::new("/") {
        return Err(Refusal::Root);
    }
    if ctx.homes().any(|h| variants(h).iter().any(|h| p == h)) {
        return Err(Refusal::Home);
    }
    if variants(&ctx.data_root).iter().any(|d| related(p, d)) {
        return Err(Refusal::DataRoot);
    }
    for name in SENSITIVE {
        for home in ctx.homes() {
            for s in variants(&home.join(name)) {
                if p.starts_with(&s) {
                    return Err(Refusal::Inside(name));
                }
                if s.starts_with(p) {
                    return Err(Refusal::Ancestor(name));
                }
            }
        }
    }
    for sys in SYSTEM {
        if related(p, Path::new(sys)) {
            return Err(Refusal::System(sys));
        }
    }
    if p == Path::new(RESERVED_TMP) {
        return Err(Refusal::Reserved(RESERVED_TMP));
    }
    if let Ok(rest) = p.strip_prefix(RESERVED_TMP)
        && let Some(first) = rest.components().next()
    {
        let name = first.as_os_str().to_string_lossy();
        let hit = RESERVED_TMP_CHILDREN.iter().find(|r| {
            let r = &r[RESERVED_TMP.len() + 1..];
            match r.strip_suffix('*') {
                Some(stem) => name.starts_with(stem),
                None => name == r,
            }
        });
        if let Some(r) = hit {
            return Err(Refusal::Reserved(r));
        }
    }
    if let Some(rd) = &ctx.runtime_dir
        && variants(rd).iter().any(|d| related(p, d))
    {
        return Err(Refusal::RuntimeDir);
    }
    Ok(())
}

/// `rw` on a system tree is refused (`ro` is fine: programs may read `/usr/share/...`).
fn writable(p: &Path, access: Access) -> Result<(), Refusal> {
    if access == Access::Rw
        && !p.starts_with(RW_OK)
        && let Some(t) = RO_ONLY.iter().find(|t| p.starts_with(t))
    {
        return Err(Refusal::ReadOnlyOnly(t));
    }
    Ok(())
}

/// [`validate_grant`] for a grant with `access`. The fixed lists are checked on the path as written BEFORE it must
/// exist (a refusal never depends on what the host has), then again on the resolved path, which must be a
/// directory.
pub fn validate_grant_for(path: &Path, access: Access, ctx: &GrantCtx) -> Result<PathBuf, PermError> {
    let bad = |why| PermError::Grant { path: lossy(path), why };
    syntax(path).map_err(bad)?;
    locate(path, ctx).map_err(bad)?;
    writable(path, access).map_err(bad)?;
    let real = fs::canonicalize(path).map_err(|_| bad(Refusal::Missing))?;
    syntax(&real).map_err(bad)?;
    locate(&real, ctx).map_err(bad)?;
    writable(&real, access).map_err(bad)?;
    if !fs::metadata(&real).is_ok_and(|m| m.is_dir()) {
        return Err(bad(Refusal::NotDirectory));
    }
    if real.starts_with(RESERVED_TMP)
        && let Some(sock) = socket_within(&real)
    {
        return Err(bad(Refusal::TmpSocket(lossy(&sock))));
    }
    Ok(real)
}

/// Checks one host directory grant (as read-only: see [`validate_grant_for`]) and returns the path to store and
/// bind: `path` with symlinks resolved. The rules run on the path as written (so a refusal names the real reason
/// even for a path that does not exist) and again on the resolved path (a symlink is judged by its target).
pub fn validate_grant(path: &Path, ctx: &GrantCtx) -> Result<PathBuf, PermError> {
    validate_grant_for(path, Access::Ro, ctx)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGrant {
    path: String,
    access: Access,
}

fn on() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    version: i64,
    #[serde(default = "deny")]
    network: Network,
    #[serde(default = "on")]
    display: bool,
    #[serde(default = "on")]
    audio: bool,
    #[serde(default = "on")]
    gpu: bool,
    #[serde(default)]
    filesystem: Vec<RawGrant>,
}

fn deny() -> Network {
    Network::Deny
}

impl Permissions {
    /// Strict parse of a whole profile; every grant goes through [`validate_grant_for`] and is kept resolved.
    pub fn parse(text: &str, ctx: &GrantCtx) -> Result<Permissions, PermError> {
        Permissions::parse_raw(text)?.validated(ctx)
    }

    /// The syntax half of [`Permissions::parse`]: strict TOML, version, sizes and counts, but the grants are kept
    /// as written and NOT checked against the host. Only for editing a profile that may hold a stale grant (see
    /// [`Permissions::validated`]); never bind what this returns.
    pub fn parse_raw(text: &str) -> Result<Permissions, PermError> {
        if text.len() as u64 > MAX_BYTES {
            return Err(PermError::TooLarge);
        }
        let raw: Raw = toml::from_str(text).map_err(|e| PermError::Toml(clip(&e.to_string())))?;
        if raw.version != 1 {
            return Err(PermError::Version(raw.version));
        }
        if raw.filesystem.len() > MAX_GRANTS {
            return Err(PermError::TooManyGrants);
        }
        Ok(Permissions {
            network: raw.network,
            display: raw.display,
            audio: raw.audio,
            gpu: raw.gpu,
            filesystem: raw
                .filesystem
                .into_iter()
                .map(|g| FsGrant {
                    path: PathBuf::from(g.path),
                    access: g.access,
                })
                .collect(),
        })
    }

    /// Every grant checked and resolved ([`validate_grant_for`]); a duplicate after resolution is refused.
    pub fn validated(self, ctx: &GrantCtx) -> Result<Permissions, PermError> {
        let mut filesystem: Vec<FsGrant> = Vec::new();
        for g in self.filesystem {
            let path = validate_grant_for(&g.path, g.access, ctx)?;
            if filesystem.iter().any(|f| f.path == path) {
                return Err(PermError::DuplicateGrant(lossy(&path)));
            }
            filesystem.push(FsGrant { path, access: g.access });
        }
        Ok(Permissions { filesystem, ..self })
    }

    /// The canonical file text: fixed key order, grants in order, strings escaped. `parse(to_toml(p)) == p` for
    /// every profile whose grants are resolved and valid.
    pub fn to_toml(&self) -> String {
        let mut s = format!(
            "version = 1\nnetwork = \"{}\"\ndisplay = {}\naudio = {}\ngpu = {}\n",
            if self.network == Network::Allow {
                "allow"
            } else {
                "deny"
            },
            self.display,
            self.audio,
            self.gpu
        );
        for g in &self.filesystem {
            s.push_str("\n[[filesystem]]\npath = \"");
            for c in g.path.to_string_lossy().chars() {
                match c {
                    '"' => s.push_str("\\\""),
                    '\\' => s.push_str("\\\\"),
                    c if c.is_control() || rt_core::is_format(c) => {
                        let mut units = [0u16; 2];
                        for u in c.encode_utf16(&mut units) {
                            s.push_str(&format!("\\u{u:04x}"));
                        }
                    }
                    c => s.push(c),
                }
            }
            s.push_str(&format!(
                "\"\naccess = \"{}\"\n",
                if g.access == Access::Rw { "rw" } else { "ro" }
            ));
        }
        s
    }

    /// One `--set` expression: `network=allow|deny`, `display|audio|gpu=on|off`, `fs+=<abs>:ro|rw` (an existing
    /// path re-added replaces its access) and `fs-=<abs>`. On error `self` is unchanged.
    pub fn apply_set(&mut self, expr: &str, ctx: &GrantCtx) -> Result<(), PermError> {
        let bad = || PermError::Expr(clip(expr));
        if let Some(rest) = expr.strip_prefix("fs+=") {
            let (path, access) = rest.rsplit_once(':').ok_or_else(bad)?;
            let access = match access {
                "ro" => Access::Ro,
                "rw" => Access::Rw,
                _ => return Err(bad()),
            };
            let path = validate_grant_for(Path::new(path), access, ctx)?;
            if let Some(g) = self.filesystem.iter_mut().find(|g| g.path == path) {
                g.access = access;
            } else if self.filesystem.len() >= MAX_GRANTS {
                return Err(PermError::TooManyGrants);
            } else {
                self.filesystem.push(FsGrant { path, access });
            }
            return Ok(());
        }
        if let Some(path) = expr.strip_prefix("fs-=") {
            // Removal must work for a grant whose directory is gone: no validation, no existence needed (the CLI edits
            // a profile read with `load_opt_raw` and validates what remains).
            let p = Path::new(path);
            let real = fs::canonicalize(p).ok();
            let at = self
                .filesystem
                .iter()
                .position(|g| g.path == p || real.as_deref() == Some(g.path.as_path()))
                .ok_or_else(|| PermError::NotGranted(clip(path)))?;
            self.filesystem.remove(at);
            return Ok(());
        }
        let (key, value) = expr.split_once('=').ok_or_else(bad)?;
        let flag = match value {
            "on" => Some(true),
            "off" => Some(false),
            _ => None,
        };
        match (key, value, flag) {
            ("network", "allow", _) => self.network = Network::Allow,
            ("network", "deny", _) => self.network = Network::Deny,
            ("display", _, Some(f)) => self.display = f,
            ("audio", _, Some(f)) => self.audio = f,
            ("gpu", _, Some(f)) => self.gpu = f,
            _ => return Err(bad()),
        }
        Ok(())
    }
}

/// The text of `permissions.toml` in `app_root`, `None` when there is no file. Opened with `O_NOFOLLOW` (a
/// symlink is refused, never followed), `O_NONBLOCK` (a FIFO cannot hang the open); it must be a regular file and
/// its size is checked on the open handle before anything is read.
fn read_file(app_root: &Path) -> Result<Option<String>, PermError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(app_root.join(FILE_NAME))
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(PermError::NotRegular),
        Err(e) => return Err(io_err(e)),
    };
    let meta = file.metadata().map_err(io_err)?;
    if !meta.file_type().is_file() {
        return Err(PermError::NotRegular);
    }
    if meta.len() > MAX_BYTES {
        return Err(PermError::TooLarge);
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes).map_err(io_err)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(PermError::TooLarge);
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| PermError::Toml("not UTF-8".into()))
}

/// The profile of the app at `app_root` (see [`read_file`]), `None` when there is no file; every grant is
/// validated.
pub fn load_opt(app_root: &Path, ctx: &GrantCtx) -> Result<Option<Permissions>, PermError> {
    read_file(app_root)?.map(|t| Permissions::parse(&t, ctx)).transpose()
}

/// [`load_opt`] without checking the grants against the host ([`Permissions::parse_raw`]): for `--set fs-=` on a
/// profile whose directory has vanished. Its result is validated ([`Permissions::validated`]) before it is stored.
pub fn load_opt_raw(app_root: &Path) -> Result<Option<Permissions>, PermError> {
    read_file(app_root)?.map(|t| Permissions::parse_raw(&t)).transpose()
}

/// [`load_opt`], with the default profile when there is no file.
pub fn load(app_root: &Path, ctx: &GrantCtx) -> Result<Permissions, PermError> {
    Ok(load_opt(app_root, ctx)?.unwrap_or_default())
}

/// How old a leftover temp file must be before `store` deletes it (the runtime holds the app lock while storing,
/// so nothing that recent can be another writer's; the margin only protects a store racing outside the CLI).
const STALE_TEMP: std::time::Duration = std::time::Duration::from_secs(3600);

/// Best-effort removal of `.permissions.toml.tmp-*` regular files in `app_root` older than [`STALE_TEMP`].
fn remove_stale_temps(app_root: &Path) {
    let Ok(rd) = fs::read_dir(app_root) else { return };
    for e in rd.flatten() {
        let name = e.file_name();
        if !name.to_string_lossy().starts_with(&format!(".{FILE_NAME}.tmp-")) {
            continue;
        }
        let old = fs::symlink_metadata(e.path())
            .ok()
            .filter(|m| m.file_type().is_file())
            .and_then(|m| m.modified().ok())
            .and_then(|m| m.elapsed().ok())
            .is_some_and(|age| age > STALE_TEMP);
        if old {
            let _ = fs::remove_file(e.path());
        }
    }
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Writes the profile atomically: a `0600` temp file next to the target (`O_EXCL`), `sync_all`, rename over
/// `permissions.toml`. The file is therefore either the old or the new profile, and a symlink or other non-file
/// at the target is refused. The temp file is removed on every failure; one a crash left behind (older than
/// [`STALE_TEMP`], named like ours) is removed on the next store. Grants are NOT validated here (the caller
/// validates before, and every load validates again).
pub fn store(app_root: &Path, p: &Permissions) -> Result<(), PermError> {
    if p.filesystem.len() > MAX_GRANTS {
        return Err(PermError::TooManyGrants);
    }
    let text = p.to_toml();
    if text.len() as u64 > MAX_BYTES {
        return Err(PermError::TooLarge);
    }
    remove_stale_temps(app_root);
    let target = app_root.join(FILE_NAME);
    match fs::symlink_metadata(&target) {
        Ok(m) if m.file_type().is_file() => {}
        Ok(_) => return Err(PermError::NotRegular),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(e)),
    }
    let (tmp, mut file) = (0..16)
        .find_map(|_| {
            let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let tmp = app_root.join(format!(".{FILE_NAME}.tmp-{}-{n}", std::process::id()));
            match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp) {
                Ok(f) => Some(Ok((tmp, f))),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => None,
                Err(e) => Some(Err(e)),
            }
        })
        .unwrap_or_else(|| Err(io::Error::other("could not create a temporary file")))
        .map_err(io_err)?;
    let written = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            drop(file);
            fs::rename(&tmp, &target)
        });
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(io_err(e));
    }
    if let Ok(d) = fs::File::open(app_root) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Deletes the profile (the app is back to the default); a missing file is fine, a symlink is unlinked, never
/// followed.
pub fn reset(app_root: &Path) -> Result<(), PermError> {
    match fs::remove_file(app_root.join(FILE_NAME)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io_err(e)),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct T {
        _t: tempfile::TempDir,
        root: PathBuf,
        ctx: GrantCtx,
    }

    /// `root/home` (with the runtime's data directory under it, as on a real host) and `root/share`.
    fn t() -> T {
        let td = tempfile::tempdir().unwrap();
        let root = td.path().canonicalize().unwrap();
        let home = root.join("home");
        let data_root = home.join(".local/share/runtime");
        for d in [&data_root, &root.join("share"), &home.join("Documents")] {
            fs::create_dir_all(d).unwrap();
        }
        T {
            _t: td,
            root,
            ctx: GrantCtx {
                home,
                extra_homes: vec![],
                data_root,
                runtime_dir: None,
            },
        }
    }

    impl T {
        fn dir(&self, rel: &str) -> PathBuf {
            let p = self.root.join(rel);
            fs::create_dir_all(&p).unwrap();
            p
        }
        fn why(&self, p: &Path) -> Refusal {
            match validate_grant(p, &self.ctx) {
                Err(PermError::Grant { why, .. }) => why,
                other => panic!("{p:?}: expected a refusal, got {other:?}"),
            }
        }
        fn grant_text(&self, path: &str) -> String {
            format!("version = 1\n[[filesystem]]\npath = \"{path}\"\naccess = \"ro\"\n")
        }
    }

    #[test]
    fn the_default_denies_network_and_files_and_keeps_the_gui_baseline() {
        let p = Permissions::default();
        assert_eq!(p.network, Network::Deny);
        assert!(p.display && p.audio && p.gpu && p.filesystem.is_empty());
        let x = t();
        assert_eq!(Permissions::parse("version = 1\n", &x.ctx).unwrap(), p);
        assert_eq!(Permissions::parse(&p.to_toml(), &x.ctx).unwrap(), p);
    }

    #[test]
    fn a_full_profile_round_trips_and_the_text_is_stable() {
        let x = t();
        let p = Permissions {
            network: Network::Allow,
            display: true,
            audio: false,
            gpu: false,
            filesystem: vec![
                FsGrant {
                    path: x.dir("share"),
                    access: Access::Rw,
                },
                FsGrant {
                    path: x.ctx.home.join("Documents"),
                    access: Access::Ro,
                },
            ],
        };
        let text = p.to_toml();
        assert_eq!(Permissions::parse(&text, &x.ctx).unwrap(), p);
        assert_eq!(Permissions::parse(&text, &x.ctx).unwrap().to_toml(), text);
        assert!(text.starts_with(
            "version = 1\nnetwork = \"allow\"\ndisplay = true\naudio = false\ngpu = false\n\n[[filesystem]]\npath = \""
        ));
    }

    #[test]
    fn parse_refuses_unknown_keys_versions_sizes_and_counts() {
        let x = t();
        let toml = |t: &str| Permissions::parse(t, &x.ctx);
        assert!(matches!(
            toml("version = 1\nnet = \"allow\"\n"),
            Err(PermError::Toml(_))
        ));
        assert!(matches!(
            toml("version = 1\n[[filesystem]]\npath = \"/tmp\"\naccess = \"ro\"\nextra = 1\n"),
            Err(PermError::Toml(_))
        ));
        assert!(matches!(toml("network = \"allow\"\n"), Err(PermError::Toml(_))));
        assert!(matches!(
            toml("version = 1\nnetwork = \"maybe\"\n"),
            Err(PermError::Toml(_))
        ));
        assert!(matches!(toml("version = 1\ngpu = \"yes\"\n"), Err(PermError::Toml(_))));
        assert_eq!(toml("version = 2\n"), Err(PermError::Version(2)));
        assert_eq!(toml("version = 0\n"), Err(PermError::Version(0)));
        assert_eq!(
            toml(&format!("version = 1\n#{}\n", "x".repeat(1 << 20))),
            Err(PermError::TooLarge)
        );
        let many = "[[filesystem]]\npath = \"/nonexistent\"\naccess = \"ro\"\n".repeat(MAX_GRANTS + 1);
        assert_eq!(toml(&format!("version = 1\n{many}")), Err(PermError::TooManyGrants));
    }

    #[test]
    fn parse_refuses_a_duplicate_grant() {
        let x = t();
        let d = x.dir("share");
        let one = format!("[[filesystem]]\npath = {:?}\naccess = \"ro\"\n", d.to_str().unwrap());
        let e = Permissions::parse(&format!("version = 1\n{one}{one}"), &x.ctx);
        assert!(matches!(e, Err(PermError::DuplicateGrant(_))), "{e:?}");
    }

    #[test]
    fn every_hostile_grant_in_a_file_is_refused_with_its_reason() {
        let x = t();
        fs::create_dir_all(x.ctx.home.join(".ssh")).unwrap();
        fs::create_dir_all(x.ctx.data_root.join("apps/other/prefix")).unwrap();
        symlink(&x.ctx.home, x.root.join("link-home")).unwrap();
        let cases: [(String, Refusal); 9] = [
            ("\\u0007/tmp".into(), Refusal::NotAbsolute),
            ("/tmp/\\u0007x".into(), Refusal::BadChars),
            ("/tmp/../etc".into(), Refusal::DotComponents),
            ("relative/dir".into(), Refusal::NotAbsolute),
            ("/".into(), Refusal::Root),
            (x.ctx.home.to_str().unwrap().into(), Refusal::Home),
            (x.root.join("link-home").to_str().unwrap().into(), Refusal::Home),
            (
                x.ctx.data_root.join("apps/other/prefix").to_str().unwrap().into(),
                Refusal::DataRoot,
            ),
            (
                x.ctx.home.join(".ssh").to_str().unwrap().into(),
                Refusal::Inside(".ssh"),
            ),
        ];
        for (path, want) in cases {
            let e = Permissions::parse(&x.grant_text(&path), &x.ctx);
            match e {
                Err(PermError::Grant { why, .. }) => assert_eq!(why, want, "{path}"),
                other => panic!("{path}: {other:?}"),
            }
        }
    }

    #[test]
    fn validate_grant_accepts_ordinary_directories_and_returns_the_resolved_path() {
        let x = t();
        let d = x.dir("share/games");
        assert_eq!(validate_grant(&d, &x.ctx).unwrap(), d);
        assert_eq!(
            validate_grant(&x.ctx.home.join("Documents"), &x.ctx).unwrap(),
            x.ctx.home.join("Documents")
        );
        symlink(&d, x.root.join("alias")).unwrap();
        assert_eq!(validate_grant(&x.root.join("alias"), &x.ctx).unwrap(), d);
    }

    #[test]
    fn only_directories_can_be_granted() {
        use std::os::unix::net::UnixListener;
        let x = t();
        fs::write(x.root.join("share/f.txt"), b"x").unwrap();
        assert_eq!(x.why(&x.root.join("share/f.txt")), Refusal::NotDirectory);
        fs::write(x.ctx.home.join(".bashrc"), b"x").unwrap();
        let mut p = Permissions::default();
        assert!(matches!(
            p.apply_set(&format!("fs+={}:rw", x.ctx.home.join(".bashrc").display()), &x.ctx),
            Err(PermError::Grant {
                why: Refusal::NotDirectory,
                ..
            })
        ));
        let sock = x.root.join("share/agent.sock");
        let _l = UnixListener::bind(&sock).unwrap();
        assert_eq!(x.why(&sock), Refusal::NotDirectory);
        // a symlink to a socket is judged by its target
        symlink(&sock, x.root.join("share/alias.sock")).unwrap();
        assert_eq!(x.why(&x.root.join("share/alias.sock")), Refusal::NotDirectory);
        assert_eq!(x.why(Path::new("/dev/null")), Refusal::System("/dev"));
    }

    #[test]
    fn run_tree_and_var_run_are_refused_by_prefix_without_existing() {
        let x = t();
        for p in [
            "/run",
            "/run/docker.sock",
            "/run/dbus",
            "/run/dbus/system_bus_socket",
            "/run/user/1000",
            "/var/run",
            "/var/run/docker.sock",
            "/var/run/x/y",
        ] {
            let want = if p.starts_with("/var/run") { "/var/run" } else { "/run" };
            assert_eq!(x.why(Path::new(p)), Refusal::System(want), "{p}");
        }
        // a symlink to /run resolves and is refused
        symlink("/run", x.root.join("share/r")).unwrap();
        assert_eq!(x.why(&x.root.join("share/r")), Refusal::System("/run"));
    }

    #[test]
    fn tmp_and_the_x11_socket_dir_are_refused_by_prefix_but_tmp_children_are_fine() {
        let x = t();
        // home and data directory elsewhere: here the temp root is under /tmp, so /tmp is above the data dir
        let ctx = GrantCtx {
            home: "/nonexistent-home".into(),
            extra_homes: vec![],
            data_root: "/nonexistent-data".into(),
            runtime_dir: None,
        };
        let why = |p: &Path| match validate_grant(p, &ctx) {
            Err(PermError::Grant { why, .. }) => why,
            o => panic!("{p:?}: {o:?}"),
        };
        assert_eq!(why(Path::new("/tmp")), Refusal::Reserved("/tmp"));
        assert_eq!(why(Path::new("/tmp/")), Refusal::Reserved("/tmp"));
        assert_eq!(why(Path::new("/tmp/.X11-unix")), Refusal::Reserved("/tmp/.X11-unix"));
        assert_eq!(why(Path::new("/tmp/.X11-unix/X0")), Refusal::Reserved("/tmp/.X11-unix"));
        symlink("/tmp", x.root.join("share/t")).unwrap();
        assert_eq!(why(&x.root.join("share/t")), Refusal::Reserved("/tmp"));
        assert!(validate_grant(&x.dir("share/fine"), &ctx).is_ok()); // the temp dir itself is under /tmp
    }

    #[test]
    fn socket_bearing_tmp_children_are_refused_by_name_equal_or_below() {
        let x = t();
        let ctx = GrantCtx {
            home: "/nonexistent-home".into(),
            extra_homes: vec![],
            data_root: "/nonexistent-data".into(),
            runtime_dir: None,
        };
        let why = |p: &str| match validate_grant(Path::new(p), &ctx) {
            Err(PermError::Grant { why, .. }) => why,
            o => panic!("{p}: {o:?}"),
        };
        // judged by name before existence, so none of these needs to exist on this host
        for (p, rule) in [
            ("/tmp/tmux-1000", "/tmp/tmux-*"),
            ("/tmp/tmux-1000/default", "/tmp/tmux-*"),
            ("/tmp/ssh-XXXXabcd", "/tmp/ssh-*"),
            ("/tmp/ssh-XXXXabcd/agent.1", "/tmp/ssh-*"),
            ("/tmp/.ICE-unix", "/tmp/.ICE-unix"),
            ("/tmp/.ICE-unix/1234", "/tmp/.ICE-unix"),
            ("/tmp/dbus-abc", "/tmp/dbus-*"),
            ("/tmp/.X11-unix", "/tmp/.X11-unix"),
            ("/tmp/.XIM-unix", "/tmp/.XIM-unix"),
            ("/tmp/.font-unix", "/tmp/.font-unix"),
            ("/tmp/.Test-unix", "/tmp/.Test-unix"),
            ("/tmp/pulse-abc", "/tmp/pulse-*"),
            ("/tmp/runtime-me", "/tmp/runtime-*"),
            ("/tmp/snap-private-tmp", "/tmp/snap-private-tmp"),
            ("/tmp/snap-private-tmp/x", "/tmp/snap-private-tmp"),
            ("/tmp/systemd-private-abc-x", "/tmp/systemd-private-*"),
        ] {
            assert_eq!(why(p), Refusal::Reserved(rule), "{p}");
        }
        // a name that merely resembles one is judged normally (here: missing)
        assert_eq!(why("/tmp/tmux"), Refusal::Missing);
        assert_eq!(why("/tmp/my-ssh-notes"), Refusal::Missing);
        drop(x);
    }

    #[test]
    fn each_added_sensitive_home_dir_is_refused_equal_and_below() {
        let x = t();
        let h = &x.ctx.home;
        for name in [
            ".local/share/keyrings",
            ".pki",
            ".mozilla",
            ".thunderbird",
            ".config/google-chrome",
            ".config/chromium",
            ".config/BraveSoftware",
            ".config/gh",
            ".config/rclone",
            ".azure",
            ".cargo",
            ".terraform.d",
            ".var/app",
            ".config/systemd",
            ".config/autostart",
            ".local/bin",
            ".config/git",
        ] {
            // judged before existence: nothing is created
            assert_eq!(x.why(&h.join(name)), Refusal::Inside(name), "{name}");
            assert_eq!(x.why(&h.join(name).join("x/y")), Refusal::Inside(name), "{name}/x/y");
        }
    }

    #[test]
    fn a_tmp_directory_holding_a_socket_is_refused() {
        use std::os::unix::net::UnixListener;
        let x = t();
        let d1 = x.dir("share/one");
        let d2 = x.dir("share/two/sub");
        let clean = x.dir("share/clean/sub");
        let _a = UnixListener::bind(d1.join("s")).unwrap();
        let _b = UnixListener::bind(d2.join("s")).unwrap();
        let deep = x.dir("share/three/a/b");
        let _c = UnixListener::bind(deep.join("s")).unwrap();
        assert_eq!(socket_within(&d1), Some(d1.join("s")));
        assert_eq!(socket_within(&x.root.join("share/two")), Some(d2.join("s")));
        assert_eq!(socket_within(&clean), None);
        assert_eq!(socket_within(&x.root.join("share/clean")), None);
        // ponytail ceiling: depth 3 and deeper is not scanned
        assert_eq!(socket_within(&x.root.join("share/three")), None);
        // a symlink to a socket is not a socket (a bind never follows it on the host side)
        symlink(d1.join("s"), clean.join("link")).unwrap();
        assert_eq!(socket_within(&clean), None);
        // end to end, only under /tmp (where the rule applies)
        if x.root.starts_with("/tmp") {
            assert_eq!(x.why(&d1), Refusal::TmpSocket(lossy(&d1.join("s"))));
            assert!(validate_grant(&clean, &x.ctx).is_ok());
        }
    }

    #[test]
    fn the_account_lookup_buffer_doubles_on_erange_up_to_a_cap() {
        let mut seen = vec![];
        let got = grow_buf(|b| {
            seen.push(b.len());
            if b.len() < 64 * 1024 {
                Err(libc::ERANGE)
            } else {
                Ok(b.len())
            }
        });
        assert_eq!(got, Some(64 * 1024));
        assert_eq!(seen, [16 * 1024, 32 * 1024, 64 * 1024]);
        let mut last = 0;
        assert_eq!(
            grow_buf::<()>(|b| {
                last = b.len();
                Err(libc::ERANGE)
            }),
            None
        );
        assert_eq!(last, MAX_PWD_BUF);
        let mut calls = 0;
        assert_eq!(
            grow_buf::<()>(|_| {
                calls += 1;
                Err(libc::EIO)
            }),
            None
        );
        assert_eq!(calls, 1);
    }

    #[test]
    fn the_session_runtime_dir_is_refused_wherever_it_is() {
        let x = t();
        let rd = x.dir("xdg-run");
        let ctx = GrantCtx {
            runtime_dir: Some(rd.clone()),
            ..x.ctx.clone()
        };
        let why = |p: &Path| match validate_grant(p, &ctx) {
            Err(PermError::Grant { why, .. }) => why,
            o => panic!("{o:?}"),
        };
        assert_eq!(why(&rd), Refusal::RuntimeDir);
        assert_eq!(why(&rd.join("bus")), Refusal::RuntimeDir);
        assert!(validate_grant(&x.dir("share/ok"), &ctx).is_ok());
    }

    #[test]
    fn rw_is_refused_on_system_trees_and_ro_is_allowed_there() {
        let x = t();
        for (p, tree) in [
            ("/etc", "/etc"),
            ("/usr/local", "/usr"),
            ("/usr", "/usr"),
            ("/var/lib/x", "/var"),
            ("/opt/app", "/opt"),
            ("/root", "/root"),
        ] {
            let mut perm = Permissions::default();
            let e = perm.apply_set(&format!("fs+={p}:rw"), &x.ctx);
            assert!(
                matches!(&e, Err(PermError::Grant { why: Refusal::ReadOnlyOnly(t), .. }) if *t == tree),
                "{p}: {e:?}"
            );
            assert!(perm.filesystem.is_empty());
        }
        assert!(validate_grant(Path::new("/usr"), &x.ctx).is_ok());
        let mut perm = Permissions::default();
        perm.apply_set("fs+=/usr:ro", &x.ctx).unwrap();
        // a file that says rw is refused at parse too
        let e = Permissions::parse(
            "version = 1\n[[filesystem]]\npath = \"/etc\"\naccess = \"rw\"\n",
            &x.ctx,
        );
        assert!(
            matches!(
                e,
                Err(PermError::Grant {
                    why: Refusal::ReadOnlyOnly("/etc"),
                    ..
                })
            ),
            "{e:?}"
        );
        // /var/tmp stays writable, like /tmp children
        assert_eq!(writable(Path::new("/var/tmp/x"), Access::Rw), Ok(()));
    }

    #[test]
    fn the_accounts_own_home_counts_even_when_home_says_otherwise() {
        let x = t();
        let real = x.dir("realhome");
        fs::create_dir_all(real.join(".ssh")).unwrap();
        let ctx = GrantCtx {
            home: x.root.join("fakehome"),
            extra_homes: vec![real.clone()],
            ..x.ctx.clone()
        };
        let why = |p: &Path| match validate_grant(p, &ctx) {
            Err(PermError::Grant { why, .. }) => why,
            o => panic!("{o:?}"),
        };
        assert_eq!(why(&real.join(".ssh")), Refusal::Inside(".ssh"));
        assert_eq!(why(&real), Refusal::Home);
        assert_eq!(why(&x.root), Refusal::DataRoot); // above the real home too
        assert!(account_home().is_none_or(|h| h.is_absolute()));
    }

    #[test]
    fn validate_grant_refuses_bad_syntax() {
        let x = t();
        assert_eq!(x.why(Path::new("share")), Refusal::NotAbsolute);
        assert_eq!(x.why(Path::new("")), Refusal::NotAbsolute);
        assert_eq!(x.why(&x.root.join("share/../home")), Refusal::DotComponents);
        assert_eq!(x.why(&x.root.join("share/./x")), Refusal::DotComponents);
        assert_eq!(x.why(&x.root.join("sh\u{1b}[31mare")), Refusal::BadChars);
        assert_eq!(x.why(&x.root.join("sh\u{202e}are")), Refusal::BadChars);
        assert_eq!(x.why(&x.root.join("sh\u{200b}are")), Refusal::BadChars);
        assert_eq!(x.why(&x.root.join("a".repeat(5000))), Refusal::TooLong);
        assert_eq!(x.why(Path::new("/")), Refusal::Root);
        assert_eq!(x.why(&x.root.join("share/nothing-here")), Refusal::Missing);
    }

    #[test]
    fn validate_grant_refuses_home_and_every_sensitive_dir_and_what_is_inside_or_above_them() {
        let x = t();
        let h = &x.ctx.home;
        assert_eq!(x.why(h), Refusal::Home);
        for name in SENSITIVE {
            fs::create_dir_all(h.join(name).join("sub")).unwrap();
            assert_eq!(x.why(&h.join(name)), Refusal::Inside(name), "{name}");
            assert_eq!(x.why(&h.join(name).join("sub")), Refusal::Inside(name), "{name}/sub");
        }
        // an ancestor names the sensitive child it would expose
        assert_eq!(x.why(&h.join(".config")), Refusal::Ancestor(".config/gcloud"));
        assert_eq!(x.why(&h.join(".var")), Refusal::Ancestor(".var/app"));
        // (`.local` and `.local/share` are also above the data directory, which is reported first)
        assert_eq!(x.why(&h.join(".local")), Refusal::DataRoot);
        // the temp root holds both $HOME and the data directory: the data directory is reported first
        assert_eq!(x.why(&x.root), Refusal::DataRoot);
        // ...but a sibling of a sensitive dir is fine
        fs::create_dir_all(h.join(".config/other")).unwrap();
        assert!(validate_grant(&h.join(".config/other"), &x.ctx).is_ok());
        // a nonexistent sensitive path is refused for the real reason, not as missing
        assert_eq!(x.why(&h.join(".ssh/nope")), Refusal::Inside(".ssh"));
    }

    #[test]
    fn validate_grant_refuses_the_data_root_above_below_and_equal() {
        let x = t();
        let d = &x.ctx.data_root;
        fs::create_dir_all(d.join("apps/a/prefix")).unwrap();
        assert_eq!(x.why(d), Refusal::DataRoot);
        assert_eq!(x.why(&d.join("apps/a/prefix")), Refusal::DataRoot);
        assert_eq!(x.why(&x.ctx.home.join(".local/share")), Refusal::DataRoot);
        assert_eq!(x.why(&x.ctx.home.join(".local")), Refusal::DataRoot);
        // outside $HOME the same holds
        let out = GrantCtx {
            data_root: x.dir("elsewhere/rt"),
            ..x.ctx.clone()
        };
        assert_eq!(
            validate_grant(&x.dir("elsewhere"), &out),
            Err(PermError::Grant {
                path: lossy(&x.root.join("elsewhere")),
                why: Refusal::DataRoot
            })
        );
        assert!(validate_grant(&x.dir("elsewhere-2"), &out).is_ok());
    }

    #[test]
    fn a_symlink_grant_is_judged_by_its_target() {
        let x = t();
        fs::create_dir_all(x.ctx.home.join(".gnupg/keys")).unwrap();
        symlink(x.ctx.home.join(".gnupg/keys"), x.root.join("share/innocent")).unwrap();
        assert_eq!(x.why(&x.root.join("share/innocent")), Refusal::Inside(".gnupg"));
        symlink(&x.ctx.home, x.root.join("share/h")).unwrap();
        assert_eq!(x.why(&x.root.join("share/h")), Refusal::Home);
        symlink(&x.ctx.data_root, x.root.join("share/d")).unwrap();
        assert_eq!(x.why(&x.root.join("share/d")), Refusal::DataRoot);
        symlink("/proc", x.root.join("share/p")).unwrap();
        assert_eq!(x.why(&x.root.join("share/p")), Refusal::System("/proc"));
        // a symlinked $HOME is judged by both spellings
        symlink(&x.ctx.home, x.root.join("home-alias")).unwrap();
        let aliased = GrantCtx {
            home: x.root.join("home-alias"),
            ..x.ctx.clone()
        };
        fs::create_dir_all(x.ctx.home.join(".kube")).unwrap();
        assert_eq!(
            validate_grant(&x.ctx.home.join(".kube"), &aliased).unwrap_err(),
            PermError::Grant {
                path: lossy(&x.ctx.home.join(".kube")),
                why: Refusal::Inside(".kube")
            }
        );
    }

    #[test]
    fn validate_grant_refuses_device_and_runtime_socket_trees() {
        let x = t();
        assert_eq!(x.why(Path::new("/proc")), Refusal::System("/proc"));
        assert_eq!(x.why(Path::new("/proc/self")), Refusal::System("/proc"));
        assert_eq!(x.why(Path::new("/sys")), Refusal::System("/sys"));
        assert_eq!(x.why(Path::new("/dev")), Refusal::System("/dev"));
        assert_eq!(x.why(Path::new("/dev/shm")), Refusal::System("/dev"));
        assert_eq!(x.why(Path::new("/run/user")), Refusal::System("/run"));
        assert_eq!(x.why(Path::new("/run/user/1000/bus")), Refusal::System("/run"));
        assert_eq!(x.why(Path::new("/run")), Refusal::System("/run"));
    }

    #[test]
    fn apply_set_handles_every_form() {
        let x = t();
        let mut p = Permissions::default();
        let d = x.dir("share/games");
        let ok = |p: &mut Permissions, e: &str| p.apply_set(e, &x.ctx).unwrap_or_else(|e2| panic!("{e}: {e2}"));
        ok(&mut p, "network=allow");
        assert_eq!(p.network, Network::Allow);
        ok(&mut p, "network=deny");
        assert_eq!(p.network, Network::Deny);
        for (k, get) in [
            ("display", (|p: &Permissions| p.display) as fn(&Permissions) -> bool),
            ("audio", |p| p.audio),
            ("gpu", |p| p.gpu),
        ] {
            ok(&mut p, &format!("{k}=off"));
            assert!(!get(&p), "{k}");
            ok(&mut p, &format!("{k}=on"));
            assert!(get(&p), "{k}");
        }
        ok(&mut p, &format!("fs+={}:ro", d.display()));
        assert_eq!(
            p.filesystem,
            [FsGrant {
                path: d.clone(),
                access: Access::Ro
            }]
        );
        // adding it again is idempotent; a new access replaces the old
        ok(&mut p, &format!("fs+={}:ro", d.display()));
        assert_eq!(p.filesystem.len(), 1);
        ok(&mut p, &format!("fs+={}:rw", d.display()));
        assert_eq!(
            p.filesystem,
            [FsGrant {
                path: d.clone(),
                access: Access::Rw
            }]
        );
        // a symlink spelling is the same grant
        symlink(&d, x.root.join("alias")).unwrap();
        ok(&mut p, &format!("fs+={}:ro", x.root.join("alias").display()));
        assert_eq!(p.filesystem.len(), 1);
        ok(&mut p, &format!("fs-={}", x.root.join("alias").display()));
        assert!(p.filesystem.is_empty());
        // removal works for a directory that is gone
        ok(&mut p, &format!("fs+={}:ro", d.display()));
        fs::remove_dir(&d).unwrap();
        ok(&mut p, &format!("fs-={}", d.display()));
        assert!(p.filesystem.is_empty());
        assert!(matches!(
            p.apply_set("fs-=/never/added", &x.ctx),
            Err(PermError::NotGranted(_))
        ));
    }

    #[test]
    fn apply_set_refuses_bad_syntax_and_bad_grants_and_changes_nothing() {
        let x = t();
        let mut p = Permissions::default();
        for bad in [
            "net=allow",
            "network=maybe",
            "network",
            "",
            "=",
            "display=yes",
            "gpu=",
            "gpu = on",
            "Network=allow",
            "fs+=/x",
            "fs+=",
            "fs+=/x:rx",
            "fs=/x:ro",
            "fs+ =/x:ro",
            "audio=on;network=allow",
        ] {
            assert_eq!(
                p.apply_set(bad, &x.ctx),
                Err(PermError::Expr(bad.to_owned())),
                "{bad:?}"
            );
        }
        for (bad, why) in [
            ("fs+=rel:ro", Refusal::NotAbsolute),
            ("fs+=:ro", Refusal::NotAbsolute),
            ("fs+=/x-does-not-exist:ro", Refusal::Missing),
        ] {
            let e = p.apply_set(bad, &x.ctx);
            assert!(
                matches!(&e, Err(PermError::Grant { why: w, .. }) if *w == why),
                "{bad:?}: {e:?}"
            );
        }
        assert!(matches!(
            p.apply_set("fs+=rel:ro", &x.ctx),
            Err(PermError::Grant {
                why: Refusal::NotAbsolute,
                ..
            })
        ));
        assert!(matches!(p.apply_set("fs+=/x:rx", &x.ctx), Err(PermError::Expr(_))));
        let ssh = x.dir("home/.ssh");
        assert!(matches!(
            p.apply_set(&format!("fs+={}:ro", ssh.display()), &x.ctx),
            Err(PermError::Grant {
                why: Refusal::Inside(".ssh"),
                ..
            })
        ));
        assert_eq!(p, Permissions::default());
        // the 65th grant is refused
        for i in 0..MAX_GRANTS {
            let d = x.dir(&format!("share/d{i}"));
            p.apply_set(&format!("fs+={}:ro", d.display()), &x.ctx).unwrap();
        }
        let d = x.dir("share/one-too-many");
        assert_eq!(
            p.apply_set(&format!("fs+={}:ro", d.display()), &x.ctx),
            Err(PermError::TooManyGrants)
        );
    }

    #[test]
    fn a_path_with_a_colon_keeps_it() {
        let x = t();
        let d = x.dir("share/a:b");
        let mut p = Permissions::default();
        p.apply_set(&format!("fs+={}:rw", d.display()), &x.ctx).unwrap();
        assert_eq!(p.filesystem[0].path, d);
        assert_eq!(Permissions::parse(&p.to_toml(), &x.ctx).unwrap(), p);
    }

    #[test]
    fn a_path_with_quotes_and_backslashes_round_trips() {
        let x = t();
        let d = x.dir("share/we\"ird\\name");
        let p = Permissions {
            filesystem: vec![FsGrant {
                path: d,
                access: Access::Ro,
            }],
            ..Permissions::default()
        };
        assert_eq!(Permissions::parse(&p.to_toml(), &x.ctx).unwrap(), p);
    }

    #[test]
    fn load_of_a_missing_file_is_the_default() {
        let x = t();
        let app = x.dir("app");
        assert_eq!(load(&app, &x.ctx).unwrap(), Permissions::default());
        assert_eq!(load_opt(&app, &x.ctx).unwrap(), None);
    }

    #[test]
    fn load_refuses_a_symlink_a_fifo_a_directory_and_an_oversized_file() {
        let x = t();
        let app = x.dir("app");
        let f = app.join(FILE_NAME);
        fs::write(x.root.join("real.toml"), "version = 1\n").unwrap();
        symlink(x.root.join("real.toml"), &f).unwrap();
        assert_eq!(load(&app, &x.ctx), Err(PermError::NotRegular));
        fs::remove_file(&f).unwrap();
        let fifo = std::ffi::CString::new(f.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_eq!(load(&app, &x.ctx), Err(PermError::NotRegular)); // and it does not block
        fs::remove_file(&f).unwrap();
        fs::create_dir(&f).unwrap();
        assert_eq!(load(&app, &x.ctx), Err(PermError::NotRegular));
        fs::remove_dir(&f).unwrap();
        // huge sparse file: refused on the handle's size, without reading it
        fs::File::create(&f).unwrap().set_len(1 << 40).unwrap();
        assert_eq!(load(&app, &x.ctx), Err(PermError::TooLarge));
        fs::write(&f, format!("version = 1\n#{}\n", "x".repeat(70_000))).unwrap();
        assert_eq!(load(&app, &x.ctx), Err(PermError::TooLarge));
    }

    #[test]
    fn load_survives_hostile_bytes_and_revalidates_grants() {
        let x = t();
        let app = x.dir("app");
        let f = app.join(FILE_NAME);
        fs::write(&f, [0xffu8, 0xfe, 0, b'[', b'\n'].repeat(500)).unwrap();
        assert!(matches!(load(&app, &x.ctx), Err(PermError::Toml(_))));
        fs::write(&f, "version = 1\n\x1b[2J\n").unwrap();
        assert!(matches!(load(&app, &x.ctx), Err(PermError::Toml(_))));
        // a grant that passed once but now points into $HOME is refused at load, never narrowed
        let d = x.dir("share/g");
        let mut p = Permissions::default();
        p.apply_set(&format!("fs+={}:ro", d.display()), &x.ctx).unwrap();
        store(&app, &p).unwrap();
        assert_eq!(load(&app, &x.ctx).unwrap(), p);
        fs::remove_dir(&d).unwrap();
        symlink(&x.ctx.home, &d).unwrap();
        assert!(matches!(
            load(&app, &x.ctx),
            Err(PermError::Grant { why: Refusal::Home, .. })
        ));
    }

    #[test]
    fn store_writes_mode_0600_and_replaces_atomically() {
        let x = t();
        let app = x.dir("app");
        let mut p = Permissions::default();
        store(&app, &p).unwrap();
        let f = app.join(FILE_NAME);
        assert_eq!(fs::metadata(&f).unwrap().permissions().mode() & 0o7777, 0o600);
        let old = fs::read_to_string(&f).unwrap();
        p.network = Network::Allow;
        store(&app, &p).unwrap();
        assert_eq!(load(&app, &x.ctx).unwrap(), p);
        assert_ne!(fs::read_to_string(&f).unwrap(), old);
        assert_eq!(fs::read_dir(&app).unwrap().count(), 1, "no temp file is left behind");
        // a failed store leaves the old file untouched and no temp file: the directory cannot take a new file
        let before = fs::read_to_string(&f).unwrap();
        fs::set_permissions(&app, fs::Permissions::from_mode(0o500)).unwrap();
        let denied = fs::File::create(app.join("probe")).is_err(); // (root would not be stopped)
        let r = store(&app, &Permissions::default());
        fs::set_permissions(&app, fs::Permissions::from_mode(0o700)).unwrap();
        if denied {
            assert!(matches!(r, Err(PermError::Io(_))));
            assert_eq!(fs::read_to_string(&f).unwrap(), before);
            assert_eq!(fs::read_dir(&app).unwrap().count(), 1);
        }
    }

    #[test]
    fn store_refuses_a_symlinked_or_non_file_target_and_writes_nothing() {
        let x = t();
        let app = x.dir("app");
        let victim = x.root.join("victim");
        fs::write(&victim, "keep").unwrap();
        symlink(&victim, app.join(FILE_NAME)).unwrap();
        assert_eq!(store(&app, &Permissions::default()), Err(PermError::NotRegular));
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(fs::read_dir(&app).unwrap().count(), 1);
        fs::remove_file(app.join(FILE_NAME)).unwrap();
        fs::create_dir(app.join(FILE_NAME)).unwrap();
        assert_eq!(store(&app, &Permissions::default()), Err(PermError::NotRegular));
    }

    #[test]
    fn reset_removes_the_file_and_unlinks_a_symlink_without_following_it() {
        let x = t();
        let app = x.dir("app");
        store(&app, &Permissions::default()).unwrap();
        reset(&app).unwrap();
        assert!(!app.join(FILE_NAME).exists());
        reset(&app).unwrap();
        let victim = x.root.join("victim");
        fs::write(&victim, "keep").unwrap();
        symlink(&victim, app.join(FILE_NAME)).unwrap();
        reset(&app).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert!(fs::symlink_metadata(app.join(FILE_NAME)).is_err());
    }

    /// Deterministic byte/char mutation of a valid profile: whatever comes out is Ok or a plain error, never a
    /// panic, and an Ok result always passes the grant rules again.
    #[test]
    fn mutating_a_valid_file_never_panics() {
        let x = t();
        let d = x.dir("share/games");
        let mut p = Permissions::default();
        p.apply_set(&format!("fs+={}:rw", d.display()), &x.ctx).unwrap();
        let base = p.to_toml().into_bytes();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..3000 {
            let mut b = base.clone();
            for _ in 0..(1 + next() % 4) {
                let i = (next() % b.len() as u64) as usize;
                match next() % 4 {
                    0 => b[i] = next() as u8,
                    1 => {
                        b.remove(i);
                    }
                    2 => b.insert(i, b"\"\\[]=\n\0."[(next() % 8) as usize]),
                    _ => b.truncate(i.max(1)),
                }
                if b.is_empty() {
                    b.push(b'x');
                }
            }
            if let Ok(text) = String::from_utf8(b)
                && let Ok(q) = Permissions::parse(&text, &x.ctx)
            {
                for g in &q.filesystem {
                    assert!(validate_grant(&g.path, &x.ctx).is_ok());
                }
            }
        }
    }

    #[test]
    fn store_reports_too_many_grants_as_such() {
        let x = t();
        let app = x.dir("app");
        let p = Permissions {
            filesystem: (0..=MAX_GRANTS)
                .map(|i| FsGrant {
                    path: PathBuf::from(format!("/g{i}")),
                    access: Access::Ro,
                })
                .collect(),
            ..Permissions::default()
        };
        assert_eq!(store(&app, &p), Err(PermError::TooManyGrants));
        assert!(!app.join(FILE_NAME).exists());
    }

    #[test]
    fn store_removes_only_old_temp_files_it_would_have_made() {
        let x = t();
        let app = x.dir("app");
        let old = app.join(format!(".{FILE_NAME}.tmp-1-1"));
        let fresh = app.join(format!(".{FILE_NAME}.tmp-1-2"));
        let other = app.join("other.tmp-1-1");
        for f in [&old, &fresh, &other] {
            fs::write(f, "x").unwrap();
        }
        let ancient = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        for f in [&old, &other] {
            fs::File::options()
                .write(true)
                .open(f)
                .unwrap()
                .set_modified(ancient)
                .unwrap();
        }
        store(&app, &Permissions::default()).unwrap();
        assert!(!old.exists() && fresh.exists() && other.exists());
    }

    #[test]
    fn a_grant_whose_directory_vanished_can_be_removed_from_a_raw_profile() {
        let x = t();
        let app = x.dir("app");
        let d = x.dir("share/gone");
        let mut p = Permissions::default();
        p.apply_set(&format!("fs+={}:rw", d.display()), &x.ctx).unwrap();
        store(&app, &p).unwrap();
        fs::remove_dir(&d).unwrap();
        // the strict load refuses the stale grant, the raw one still reads it
        assert!(matches!(
            load(&app, &x.ctx),
            Err(PermError::Grant {
                why: Refusal::Missing,
                ..
            })
        ));
        let mut raw = load_opt_raw(&app).unwrap().unwrap();
        raw.apply_set(&format!("fs-={}", d.display()), &x.ctx).unwrap();
        let fixed = raw.validated(&x.ctx).unwrap();
        assert!(fixed.filesystem.is_empty());
        store(&app, &fixed).unwrap();
        assert_eq!(load(&app, &x.ctx).unwrap(), fixed);
        // a stale grant that is not removed still blocks the write
        let e = Permissions {
            filesystem: vec![FsGrant {
                path: d,
                access: Access::Ro,
            }],
            ..Permissions::default()
        };
        assert!(matches!(
            e.validated(&x.ctx),
            Err(PermError::Grant {
                why: Refusal::Missing,
                ..
            })
        ));
    }
}
