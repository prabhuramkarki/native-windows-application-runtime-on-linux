//! The per-app sandbox: the validated permission profile (`permissions.toml`) that decides what a program may
//! reach, and [`AppSandbox`], which renders it into a bubblewrap command around the program. This crate never
//! trusts the file it reads: see [`permissions`]. The rendered profile is described in [`render`].
pub mod host;
pub mod permissions;
pub mod render;

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
    let userns = ["namespace", "Operation not permitted", "uid map", "Permission denied"];
    if userns.iter().any(|m| text.contains(m)) {
        Err(format!(
            "user namespaces are disabled or restricted on this host: {first}"
        ))
    } else {
        Err(format!("bwrap cannot create a sandbox ({}): {first}", out.status))
    }
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
        assert!(e.contains("cannot create a sandbox"), "{e}");
    }
}
