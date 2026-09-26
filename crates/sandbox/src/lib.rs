//! The per-app sandbox: the validated permission profile (`permissions.toml`) that decides what a program may
//! reach, and [`AppSandbox`], which renders it into a bubblewrap command around the program. This crate never
//! trusts the file it reads: see [`permissions`]. The rendered profile is described in [`render`]; the seccomp
//! deny-list the program runs under in [`seccomp`]; its Landlock filesystem ruleset in [`landlock`].
#[cfg(test)]
mod bpf_interp;
pub mod host;
pub mod init;
pub mod landlock;
pub mod permissions;
pub mod render;
pub mod seccomp;

pub use host::{Host, RealHost};
pub use permissions::{
    Access, FsGrant, GrantCtx, Network, PermError, Permissions, Refusal, account_home, load, load_opt, load_opt_raw,
    reset, store, validate_grant, validate_grant_for,
};
pub use render::{AppSandbox, RenderError};

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Looks for `bwrap` on `$PATH` the way a shell would (absolute directories only, first match wins), with an
/// injected environment and file probe; the same rules as `rt_installer::sandbox::find_bwrap`.
pub fn find_bwrap(env: &impl Fn(&str) -> Option<OsString>, is_file: &impl Fn(&Path) -> bool) -> Option<PathBuf> {
    let path = env("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("bwrap"))
        .find(|candidate| is_file(candidate))
}

/// [`find_bwrap`] over the real environment and filesystem (a regular, executable file).
pub fn find_bwrap_on_path() -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    find_bwrap(&|k| std::env::var_os(k), &|p: &Path| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    })
}

/// The in-kernel layers the `sandbox-init` shim adds, probed on the host (the shim itself reports nothing): one
/// `seccomp: ...` and one `landlock: ...` line for `runtime sandbox` and `doctor`, whether both are fully there,
/// and [`BYPASS_CAVEAT`] when the filter can be shed on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardening {
    pub seccomp: String,
    pub landlock: String,
    pub complete: bool,
    pub caveat: Option<String>,
}

/// Without Landlock, bwrap's own pid 1 inside the sandbox (dumpable, same uid, no filter) is reachable through
/// `/proc/1/mem`, which seccomp cannot see and only Yama guards (`rt_sandbox::seccomp`, "ptrace and Landlock").
pub const BYPASS_CAVEAT: &str = "seccomp can be bypassed through /proc/1/mem on this host (no Landlock, no Yama)";

pub fn hardening() -> Hardening {
    let seccomp = seccomp::host_arch().and_then(|a| seccomp::build_filter(a).map(|_| a));
    hardening_from(seccomp.map_err(|e| e.to_string()), landlock::host_state(), yama_scope())
}

/// Yama's `ptrace_scope` (0-3), read bounded; `None` when the file is missing or unreadable (Yama not there).
fn yama_scope() -> Option<u32> {
    use std::io::Read;
    let mut buf = [0u8; 16];
    let n = std::fs::File::open("/proc/sys/kernel/yama/ptrace_scope")
        .and_then(|mut f| f.read(&mut buf))
        .ok()?;
    std::str::from_utf8(&buf[..n]).ok()?.trim().parse().ok()
}

/// [`hardening`] from its probes: the filter (its arch, or why it cannot be built), Landlock, and Yama's scope
/// (`None`: no Yama, the same as scope 0).
fn hardening_from(
    seccomp: Result<seccomp::Arch, String>,
    landlock: landlock::HostState,
    yama: Option<u32>,
) -> Hardening {
    let (seccomp, seccomp_ok) = match seccomp {
        Ok(a) => (
            format!("seccomp: enforced ({}, {} rules)", a.name(), seccomp::DENIED.len()),
            true,
        ),
        Err(e) => (
            format!("seccomp: UNAVAILABLE ({e}); `runtime run` refuses to start programs"),
            false,
        ),
    };
    let mut caveat = None;
    let (landlock, landlock_ok) = match landlock {
        landlock::HostState::Abi(abi) => (
            format!("landlock: ABI {abi} (fs); ptrace and /proc/<pid>/mem reach only the app's own processes"),
            true,
        ),
        landlock::HostState::Unavailable(why) => {
            if yama.unwrap_or(0) == 0 {
                caveat = Some(BYPASS_CAVEAT.to_owned());
            }
            (
                format!(
                    "landlock: unavailable: {why}; only the mounts confine files, ptrace stays denied (Windows \
                     programs cannot read or write other processes' memory), and /proc/1/mem is guarded by Yama only"
                ),
                false,
            )
        }
        landlock::HostState::Error(e) => (
            format!("landlock: {e}; `runtime run` refuses to start programs while this fails"),
            false,
        ),
    };
    Hardening {
        seccomp,
        landlock,
        complete: seccomp_ok && landlock_ok,
        caveat,
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    #[test]
    fn the_bypass_caveat_appears_exactly_without_landlock_and_without_yama() {
        let arch = || seccomp::host_arch().map_err(|e| e.to_string());
        let unavailable = || landlock::HostState::Unavailable("gone".into());
        for yama in [None, Some(0)] {
            let h = hardening_from(arch(), unavailable(), yama);
            assert_eq!(h.caveat.as_deref(), Some(BYPASS_CAVEAT), "{yama:?}");
            assert!(!h.complete);
            assert!(h.landlock.starts_with("landlock: unavailable: gone;"), "{}", h.landlock);
            assert!(
                h.landlock.contains("/proc/1/mem is guarded by Yama only"),
                "{}",
                h.landlock
            );
        }
        for yama in [1, 2, 3] {
            let h = hardening_from(arch(), unavailable(), Some(yama));
            assert_eq!(h.caveat, None, "{yama}");
            assert!(!h.complete);
        }
        for yama in [None, Some(0), Some(1)] {
            let h = hardening_from(arch(), landlock::HostState::Abi(8), yama);
            assert_eq!(h.caveat, None);
            assert!(h.complete);
            assert!(h.landlock.starts_with("landlock: ABI 8 (fs)"), "{}", h.landlock);
        }
        let h = hardening_from(Err("no table".into()), landlock::HostState::Abi(8), Some(1));
        assert!(
            !h.complete && h.seccomp.starts_with("seccomp: UNAVAILABLE (no table)"),
            "{}",
            h.seccomp
        );
        let e = landlock::HostState::Error(landlock::LandlockError::BadPath("x".into()));
        let h = hardening_from(arch(), e, None);
        assert_eq!(
            h.caveat, None,
            "a probe error refuses every run: nothing runs to bypass"
        );
        assert!(h.landlock.contains("refuses to start programs"), "{}", h.landlock);
    }

    #[test]
    fn yama_scope_is_read_from_this_host() {
        let want = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .ok()
            .and_then(|t| t.trim().parse().ok());
        assert_eq!(yama_scope(), want);
    }
}

/// How long [`probe`] waits for `bwrap`.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Really creates a throwaway sandbox once (`bwrap --unshare-all --die-with-parent --ro-bind / / true`, at most
/// [`PROBE_TIMEOUT`], output capped by the launcher) so a caller can say why sandboxing is impossible on this host
/// before a run fails on it. `Err` is a one-line reason.
pub fn probe(bwrap: &Path) -> Result<(), String> {
    let mut cmd = Command::new(bwrap);
    cmd.args(["--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "true"]);
    let out = rt_core::Launcher::new()
        .run_helper(cmd, PROBE_TIMEOUT)
        .map_err(|e| format!("bwrap could not be run: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&out.output);
    let first: String = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("no output")
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    Err(probe_reason(&text, &first))
}

/// bwrap's own messages when the kernel refuses an unprivileged user namespace (`kernel.unprivileged_userns_clone`,
/// `user.max_user_namespaces = 0`, AppArmor's `restrict_unprivileged_userns`).
const USERNS_MESSAGES: [&str; 4] = [
    "No permissions to create new namespace",
    "setting up uid map",
    "Creating new namespace failed",
    "unprivileged user namespaces",
];

/// The one-line reason for a failed probe: user namespaces only when bwrap says so, else the excerpt.
fn probe_reason(text: &str, first: &str) -> String {
    if USERNS_MESSAGES.iter().any(|m| text.contains(m)) {
        format!("user namespaces are disabled or restricted on this host ({first})")
    } else {
        format!("the sandbox could not be created ({first})")
    }
}

#[cfg(test)]
pub(crate) fn grant_tempdir() -> tempfile::TempDir {
    let exe = std::env::current_exe().unwrap();
    let base = exe.ancestors().nth(3).unwrap().join("tmp");
    std::fs::create_dir_all(&base).unwrap();
    let td = tempfile::tempdir_in(&base).unwrap();
    assert!(
        !td.path().canonicalize().unwrap().starts_with("/tmp"),
        "the test grant directory {:?} is under /tmp, where every grant is refused: build with a target directory \
         outside /tmp (CARGO_TARGET_DIR)",
        td.path()
    );
    td
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_bwrap_searches_path_in_order_and_skips_relative_entries() {
        let env = |k: &str| (k == "PATH").then(|| OsString::from("rel:/opt/bin:/usr/bin"));
        let is_file = |p: &Path| p == Path::new("/opt/bin/bwrap") || p == Path::new("/usr/bin/bwrap");
        assert_eq!(find_bwrap(&env, &is_file), Some(PathBuf::from("/opt/bin/bwrap")));
        let only_rel = |k: &str| (k == "PATH").then(|| OsString::from("rel"));
        assert_eq!(find_bwrap(&only_rel, &|_: &Path| true), None);
        assert_eq!(find_bwrap(&|_: &str| None, &|_: &Path| true), None);
    }

    #[test]
    fn probe_reports_a_bwrap_that_cannot_run() {
        let e = probe(Path::new("/nonexistent/bwrap")).unwrap_err();
        assert!(e.contains("could not be run"), "{e}");
        // `false` ignores its arguments and fails: a reason, not a panic
        let e = probe(Path::new("/bin/false")).unwrap_err();
        assert_eq!(e, "the sandbox could not be created (no output)");
        let userns = "bwrap: No permissions to create new namespace, likely because the kernel does not allow";
        assert!(probe_reason(userns, "x").starts_with("user namespaces are disabled"));
        // an unrelated EPERM is not blamed on user namespaces
        assert_eq!(
            probe_reason("bwrap: Can't mount proc on /newroot/proc: Operation not permitted", "y"),
            "the sandbox could not be created (y)"
        );
    }
}
