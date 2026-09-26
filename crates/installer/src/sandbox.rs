//! [`InstallerSandbox`]: a minimal `bwrap` profile for running an installer helper with nothing on the real
//! filesystem but its own app.
//!
//! **Scope.** This is narrower than a general-purpose sandbox: it exists so that Phase 3's installer helpers
//! (unpacking/copying installer payloads, running a silent `.exe`/`.msi` installer) do not get the run of the
//! host the way an unsandboxed Wine run does (`docs/SECURITY.md`, "What is still NOT covered"). It is wired into
//! [`rt_core::Launcher::wrap`] via [`InstallerSandbox::for_launcher`], the ONE existing spawn point, so a caller
//! keeps using `Launcher::spawn`/`run_helper` rather than a second `Command::spawn` path.
//!
//! **The profile** (everything not listed here is invisible): the app's own `prefix` (which contains
//! `drive_c`), read-write, at the same path; [`RO_BINDS`] plus [`SandboxOpts::extra_ro_binds`] read-only (a
//! fixed, documented set — not the real Wine binary's dependency closure, see [`RO_BINDS`]'s docs); a fresh,
//! private `/tmp`; a fresh `/proc` and `/dev`; an empty scratch directory standing in for `$HOME` (never the
//! real one — see [`home_path`]); a fresh PID/UTS/IPC namespace; a new session (`--new-session`, detaches the
//! real controlling terminal); the network namespace unshared unless [`SandboxOpts::allow_network`];
//! `--die-with-parent`; never `--dev-bind`. `docs/SECURITY.md` has the honest "what this does NOT stop" list.
//! The prefix bind and the `$HOME` tmpfs are ordered relative to each other at runtime (never a fixed order):
//! see [`InstallerSandbox::wrap`]'s own comment on why.
//!
//! **The shim (Phase 5B Task 6).** bwrap does not start the program itself: it starts `<runtime exe> sandbox-init
//! --v1 <rules> -- <program> <args>`, the same `rt_sandbox::init` shim as the app sandbox (its encoder, its parser
//! as a render-time check, its Landlock and seccomp code): `RLIMIT_CORE = 0`, the Landlock rules (best effort), the
//! seccomp deny-list (mandatory; `ptrace` only for Wine's requests and only inside an enforced Landlock domain), then
//! `execve` of the ORIGINAL program and arguments. The runtime executable is an explicit input of the only
//! constructor ([`InstallerSandbox::new`]; the CLI passes its `current_exe()`), bound read-only at its resolved path
//! after the system binds and before the prefix. One that is not absolute, was replaced or deleted, does not resolve
//! to a file or lies inside the data directory makes [`InstallerSandbox::wrap`] return `rt_sandbox`'s refusal
//! command (exit 126, the reason on stderr): an installer never runs without the shim.
//!
//! **Landlock rules** mirror the mounts, in mount order, each for its path as it appears INSIDE the sandbox (a bind's
//! destination is a real directory bwrap made even where the host's `/lib` is a symlink to `/usr/lib`; the same
//! inode, so no resolving is needed, exactly as the app renderer): read-write for `/proc` (as bwrap mounts it, like
//! the app sandbox), bwrap's own `/dev` nodes and its `pts`/`shm` directories (`rt_sandbox::render::DEV_RW`; not
//! `/dev` itself, and not `/dev/ptmx`, a symlink to `pts/ptmx` that the `pts` rule covers), `/tmp`, the prefix and
//! the `$HOME` tmpfs; read-execute for [`RO_BINDS`], [`SandboxOpts::extra_ro_binds`] and the runtime executable.
//! Nothing else: no display, audio, GPU, `/sys` or `/etc` beyond `/etc/alternatives`. No systemd scope: installers
//! have no cgroup limits (the callers' deadlines and `--die-with-parent` bound them in time only).
//!
//! [`InstallerSandbox::wrap`] is a pure argv-builder: given the already-finalized [`Command`] (final program,
//! args, env and cwd — see `rt_core::launch`'s module docs), it returns a NEW `Command` that runs `bwrap` with
//! that program/args after `--`, and the exact same env (minus [`SANDBOX_ENV_DENYLIST`]'s display/audio/D-Bus
//! variables) and cwd carried over (a brand-new `Command` otherwise inherits the calling process's own
//! environment, which must never leak into the sandboxed child). It never spawns anything itself (its only
//! filesystem access is resolving the runtime executable), so it is unit-testable with only `Command` introspection (`get_program`, `get_args`,
//! `get_envs`, `get_current_dir`), the same pattern `backend-wine`'s `command()` tests use.
use rt_core::{AppEnv, Sandbox};
use rt_sandbox::init::{self, InitArgs};
use rt_sandbox::landlock::Access::{ReadExec as Ro, ReadWrite as Rw};
use rt_sandbox::landlock::Rule;
use rt_sandbox::render::{DEV_RW, refusal, ro_bind_target};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

/// The fixed, read-only bind set every sandboxed installer command gets, besides its own `prefix`. This is
/// deliberately NOT a walk of the real Wine binary's shared-library dependency closure (`ldd`-style); a fixed,
/// documented set is what the plan asks for and what a system Wine package normally needs (its own binaries and
/// libraries, plus the distro's `/etc/alternatives` symlinks such as `/usr/bin/wine` -> `/etc/alternatives/wine`).
/// A directory that does not exist on this distro is silently skipped (`--ro-bind-try`), never an error.
///
/// **`/bin` (added by Task 8, found by real-Wine e2e testing under this exact sandbox).** Ubuntu's/Debian's
/// `wine`/`wine64` apt packages install `/usr/bin/wine{,64}` as an `update-alternatives` symlink to a small
/// `#!/bin/sh -e` wrapper script (`/usr/bin/wine{,64}-stable`), not a plain ELF binary — confirmed on this exact
/// machine (`wine`, Ubuntu 10.0~repack-12ubuntu1). On a merged-`/usr` system `/bin` is itself a symlink to
/// `/usr/bin`, but the literal path `/bin/sh` from that shebang line still has to resolve INSIDE the sandbox's
/// own mount namespace, and without `/bin` in this fixed set there is no `/bin` at all in there (only `/usr`,
/// `/lib`, `/lib64`, `/etc/alternatives` existed), so the kernel's own shebang resolution failed with ENOENT
/// before Wine ever started — `bwrap` reported it as `execvp /usr/bin/wine: No such file or directory`, which
/// reads exactly like a missing Wine binary and is not: the wrapper script itself was reachable, its
/// interpreter was not. Without this, EVERY installer run through this sandbox failed silently (a `NeedsChoice`
/// with zero candidates, since nothing was ever installed) on a completely stock Ubuntu Wine setup, silent or
/// not, regardless of the display-socket gap documented below. See `docs/SECURITY.md`'s installer-sandbox
/// section for the fuller story.
///
/// ponytail: this only covers a Wine install rooted under one of these five paths (true for a distro package).
/// WineHQ's own official packages commonly install to `/opt/wine-stable/...`, outside all of them; a Wine there
/// would fail to `execvp` inside the sandbox. Fixing that generally means walking the discovered Wine binary's
/// own install root/dependency closure, which is out of THIS task's scope (the plan's own wording reads as
/// "this fixed set is enough" for now) — Task 6, which actually knows the discovered Wine path
/// (`backend_wine::discover::Found`), should pass its install root through [`SandboxOpts::extra_ro_binds`]
/// when it is outside this fixed set, rather than this crate growing a second binary-discovery mechanism.
pub const RO_BINDS: [&str; 5] = ["/usr", "/bin", "/lib", "/lib64", "/etc/alternatives"];

/// Host session variables [`InstallerSandbox::wrap`] never replays into the sandbox, whatever the wrapped
/// command's finalized env holds (`rt_core::backend::ALLOWED` keeps them for ordinary, unsandboxed runs). With
/// `--network` the sandbox shares the host's network namespace, so an abstract X11/Wayland/D-Bus/Pulse socket
/// would otherwise be reachable and these variables say exactly where it is. Denying them means display, audio
/// and D-Bus access are refused in the installer sandbox regardless of `--network`.
pub const SANDBOX_ENV_DENYLIST: [&str; 7] = [
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "DBUS_SESSION_BUS_ADDRESS",
    "PULSE_SERVER",
];

/// The path used as `$HOME` inside the sandbox when the wrapped command's own finalized env has none. Nothing
/// on the host is ever bound there: only an empty `tmpfs`, so a program that insists on some `$HOME` existing
/// gets one, but finds it empty.
const FALLBACK_HOME: &str = "/home/sandbox";

/// Per-run choices [`InstallerSandbox::wrap`] does not hard-code.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SandboxOpts {
    /// `false` (the default): the network namespace is unshared, so the sandboxed process has no network at
    /// all (not even loopback to the host). Installers that need to phone home for a redistributable are out
    /// of scope for Phase 3 (its target is offline-only installers); set this once Phase 4 needs it.
    pub allow_network: bool,
    /// Extra paths bound read-only besides [`RO_BINDS`] (`--ro-bind-try`, so a missing one is skipped, not an
    /// error). For a Wine install outside the fixed set (see [`RO_BINDS`]'s docs), e.g. a WineHQ package under
    /// `/opt/wine-stable`.
    pub extra_ro_binds: Vec<PathBuf>,
}

/// A `bwrap`-backed sandbox for one installer helper invocation. Cheap to clone (`bwrap` is a `PathBuf`).
#[derive(Debug, Clone)]
pub struct InstallerSandbox {
    bwrap: PathBuf,
    runtime_exe: PathBuf,
    #[cfg(test)]
    pub(crate) hole: Vec<PathBuf>,
}

impl InstallerSandbox {
    /// `bwrap` is the path to the `bwrap` binary (see [`find_bwrap`] to locate it); `runtime_exe` is this runtime's
    /// own executable (the CLI's `std::env::current_exe()`), run inside as the `sandbox-init` shim. The only
    /// constructor: there is no sandbox without the shim (module docs, "The shim").
    pub fn new(bwrap: impl Into<PathBuf>, runtime_exe: impl Into<PathBuf>) -> InstallerSandbox {
        InstallerSandbox {
            bwrap: bwrap.into(),
            runtime_exe: runtime_exe.into(),
            #[cfg(test)]
            hole: Vec::new(),
        }
    }

    /// The pre-flight check: whether [`InstallerSandbox::wrap`] can run the shim for `env`'s app, or why not (the same
    /// decision, [`shim_exe`]). Callers check before running anything, so a refusal reaches the user as a sandbox
    /// error instead of the installer's exit 126 in a log.
    pub fn check(&self, env: &AppEnv) -> Result<(), String> {
        shim_exe(&self.runtime_exe, env).map(drop)
    }

    pub fn bwrap_path(&self) -> &Path {
        &self.bwrap
    }

    /// The pure argv-builder (module docs). `cmd` must already be finalized (its env, minus
    /// [`SANDBOX_ENV_DENYLIST`], and cwd are copied over); `env` names the app whose `prefix` is bound read-write.
    /// Fails closed: when the shim cannot run (see [`shim_exe`]) or would refuse its arguments, the result is
    /// `rt_sandbox`'s refusal command (exit 126, the reason on stderr), never the installer without the shim.
    pub fn wrap(&self, cmd: Command, env: &AppEnv, opts: &SandboxOpts) -> Command {
        self.render(&cmd, env, opts).unwrap_or_else(|why| refusal(&why))
    }

    fn render(&self, cmd: &Command, env: &AppEnv, opts: &SandboxOpts) -> Result<Command, String> {
        let exe = shim_exe(&self.runtime_exe, env)?;
        let home = home_path(cmd);
        let prefix = env.prefix();
        // The Landlock rules mirror the mounts, in mount order, each for the path as it appears INSIDE (module docs).
        let mut rules: Vec<Rule> = Vec::new();
        let mut rule = |path: &Path, access| {
            rules.push(Rule {
                path: path.to_path_buf(),
                access,
            })
        };

        let mut out = Command::new(&self.bwrap);
        out.arg("--die-with-parent");
        // Detaches the sandboxed process from the real controlling terminal (a new session/process group), so
        // it cannot use TIOCSTI-style terminal escapes to inject input back into the host's tty. Fine for a
        // non-interactive installer helper (this profile's only target, see the module docs); this is why
        // `Launcher::spawn`'s interactive-console-program path is not something this sandbox is meant for.
        out.arg("--new-session");
        out.arg("--unshare-pid");
        out.arg("--unshare-uts");
        out.arg("--unshare-ipc");
        if !opts.allow_network {
            out.arg("--unshare-net");
        }
        out.arg("--proc").arg("/proc");
        out.arg("--dev").arg("/dev");
        out.arg("--tmpfs").arg("/tmp");
        rule(Path::new("/proc"), Rw);
        for d in DEV_RW {
            rule(Path::new(d), Rw);
        }
        rule(Path::new("/tmp"), Rw);
        // A dll dir that is a symlink under a bound tree is bound and ruled at its resolved path (`ro_bind_target`).
        let mut bound: Vec<PathBuf> = RO_BINDS.iter().map(PathBuf::from).collect();
        for dir in &opts.extra_ro_binds {
            let target = ro_bind_target(dir, std::fs::canonicalize(dir).ok(), &bound);
            bound.push(target);
        }
        for dir in &bound {
            out.arg("--ro-bind-try").arg(dir).arg(dir);
            rule(dir, Ro);
        }
        // The shim at its own (resolved) path, before the prefix: nothing the installer can write replaces it.
        out.arg("--ro-bind").arg(&exe).arg(&exe);
        rule(&exe, Ro);
        #[cfg(test)]
        for h in &self.hole {
            out.arg("--ro-bind").arg(h).arg(h);
        }
        // Order matters: a LATER bwrap mount wins over an EARLIER one at the same or a nested path (verified
        // against real bwrap 0.11.1). `home` is normally unrelated to `prefix` (`backend_wine::app_home` makes
        // it a sibling), but if a caller ever hands `wrap` a `HOME` that is `prefix` itself or an ancestor
        // directory of it, mounting the empty `$HOME` tmpfs AFTER the prefix bind would silently swallow the
        // whole prefix (this was a real, reproduced bug: the two binds were previously always emitted in the
        // same fixed order). So: whichever of the two is the ancestor-or-equal is mounted FIRST, and the
        // more specific one (or, in a plain tie, the prefix bind, since containment of the app's own data
        // matters more than a cosmetic empty `$HOME`) is mounted LAST, so it is what is actually visible.
        if prefix.starts_with(&home) {
            out.arg("--tmpfs").arg(&home);
            out.arg("--bind").arg(&prefix).arg(&prefix);
            rule(&home, Rw);
            rule(&prefix, Rw);
        } else {
            out.arg("--bind").arg(&prefix).arg(&prefix);
            out.arg("--tmpfs").arg(&home);
            rule(&prefix, Rw);
            rule(&home, Rw);
        }
        let block = init::encode(&InitArgs {
            landlock: rules,
            program: PathBuf::from(cmd.get_program()),
            argv: cmd.get_args().map(OsStr::to_owned).collect(),
        });
        // The shim's own check, here: a refusal now rather than a 126 from inside the sandbox.
        init::parse(&block).map_err(|e| format!("the sandbox launcher would refuse its arguments: {e}"))?;
        out.arg("--").arg(&exe).arg("sandbox-init").args(block);

        // A brand-new `Command` otherwise inherits THIS process's real environment (cargo's, the CLI's, ...);
        // it must see exactly what `cmd` was finalized to, nothing more. `get_envs()` is the complete map after
        // `env_clear` + explicit `.env()` calls (see `rt_core::launch`'s own `envs()` test helper).
        out.env_clear();
        for (k, v) in cmd.get_envs() {
            if SANDBOX_ENV_DENYLIST.iter().any(|d| k == OsStr::new(d)) {
                continue;
            }
            match v {
                Some(v) => {
                    out.env(k, v);
                }
                None => {
                    out.env_remove(k);
                }
            }
        }
        if let Some(dir) = cmd.get_current_dir() {
            out.current_dir(dir);
        }
        Ok(out)
    }

    /// Adapts this sandbox to `rt_core`'s [`Sandbox`] hook, bound to one app and one set of options: `Sandbox`'s
    /// own `wrap(cmd)` takes no other parameters, so they are captured here for `Launcher::with_sandbox`.
    pub fn for_launcher(self, env: AppEnv, opts: SandboxOpts) -> Arc<dyn Sandbox> {
        Arc::new(Bound {
            sandbox: self,
            env,
            opts,
        })
    }
}

struct Bound {
    sandbox: InstallerSandbox,
    env: AppEnv,
    opts: SandboxOpts,
}

impl Sandbox for Bound {
    fn wrap(&self, cmd: Command) -> Command {
        self.sandbox.wrap(cmd, &self.env, &self.opts)
    }
}

/// `runtime_exe` as the shim is bound and run, or why it cannot be: absolute, not replaced or deleted since it
/// started (`/proc/self/exe` then reads `<path> (deleted)`), resolved to a regular file, and not inside the runtime's
/// data directory (`<data>/apps/<app>`: the prefix and everything else an installer could write are there). The same
/// checks as the app sandbox (`rt_sandbox::Host::runtime_exe` and its renderer).
fn shim_exe(exe: &Path, env: &AppEnv) -> Result<PathBuf, String> {
    let e = |why: &str| format!("the runtime executable {exe:?} (the sandbox's `sandbox-init` launcher) {why}");
    if !exe.is_absolute() {
        return Err(e("is not an absolute path"));
    }
    if exe.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return Err(e(
            "was replaced or deleted since this `runtime` started: run the command again",
        ));
    }
    let real = std::fs::canonicalize(exe)
        .ok()
        .filter(|r| std::fs::metadata(r).is_ok_and(|m| m.is_file()))
        .ok_or_else(|| e("cannot be resolved to a file"))?;
    let data = env.root().parent().and_then(Path::parent).unwrap_or(env.root());
    let data_real = std::fs::canonicalize(data).unwrap_or_default();
    if [data, data_real.as_path()]
        .iter()
        .any(|d| !d.as_os_str().is_empty() && (real.starts_with(d) || exe.starts_with(d)))
    {
        return Err(e(
            "is inside the runtime's data directory, which holds what the installer may write",
        ));
    }
    Ok(real)
}

/// `cmd`'s own finalized `HOME`, or [`FALLBACK_HOME`] if it set none.
fn home_path(cmd: &Command) -> PathBuf {
    cmd.get_envs()
        .find(|(k, _)| *k == OsStr::new("HOME"))
        .and_then(|(_, v)| v)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(FALLBACK_HOME))
}

/// A regular, executable file (after following symlinks); `false` on any error, the same probe shape as
/// `backend-wine::discover`.
fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Looks for `bwrap` on `$PATH`, the way a shell would (absolute directories only, first match wins). Injected
/// `env`/`is_file` make this unit-testable without touching the real filesystem; [`find_bwrap_on_path`] is the
/// real-filesystem convenience.
pub fn find_bwrap(
    env: &impl Fn(&str) -> Option<std::ffi::OsString>,
    is_file: &impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let path = env("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("bwrap"))
        .find(|candidate| is_file(candidate))
}

/// [`find_bwrap`] over the real environment and filesystem; `None` means `bwrap` is not installed (callers of
/// the real-`bwrap` tests skip loudly rather than failing the suite on a machine without it).
pub fn find_bwrap_on_path() -> Option<PathBuf> {
    find_bwrap(&|k| std::env::var_os(k), &is_executable_file)
}

/// In this crate's TEST binary only: `<test binary> sandbox-init <block>` behaves like `runtime sandbox-init` (the
/// same `rt_sandbox::init::main`), so the real-bwrap tests here, in `crate::pipeline` and in `crate::uninstall` run
/// the real shim with this binary as the runtime executable. The same `.init_array` hook as `rt_sandbox::init`'s
/// (glibc calls it before `main` with `(argc, argv, envp)`; for any other argv it returns).
#[cfg(test)]
#[used]
#[unsafe(link_section = ".init_array")]
static TEST_SHIM: extern "C" fn(libc::c_int, *const *const libc::c_char, *const *const libc::c_char) = test_shim;

#[cfg(test)]
extern "C" fn test_shim(argc: libc::c_int, argv: *const *const libc::c_char, _envp: *const *const libc::c_char) {
    use std::os::unix::ffi::OsStringExt;
    let argc = usize::try_from(argc).unwrap_or(0);
    // SAFETY: glibc passes the process's own argc and argv: `argc` live NUL-terminated strings.
    let arg = |i: usize| unsafe { std::ffi::CStr::from_ptr(*argv.add(i)) }.to_bytes();
    if argc < 2 || arg(1) != b"sandbox-init" {
        return;
    }
    let args: Vec<std::ffi::OsString> = (2..argc)
        .map(|i| std::ffi::OsString::from_vec(arg(i).to_vec()))
        .collect();
    rt_sandbox::init::main(&args)
}

#[cfg(test)]
mod tests;
