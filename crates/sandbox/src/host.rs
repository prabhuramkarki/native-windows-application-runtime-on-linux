//! The host facts [`crate::AppSandbox`] reads while rendering: the real process environment (for the real
//! `$HOME` grants are judged against) and which paths exist. Injected so the renderer stays a pure argv builder
//! that tests drive with a fake host; [`RealHost`] is the production view.
use crate::ScopeSupport;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub trait Host: Send + Sync {
    /// A variable of the runtime's own (unfiltered) environment.
    fn env(&self, name: &str) -> Option<OsString>;
    /// `p` exists (symlinks followed: a dangling socket link does not exist).
    fn exists(&self, p: &Path) -> bool;
    /// `p` is a unix socket itself (not followed: a symlink to one is not).
    fn is_socket(&self, p: &Path) -> bool;
    /// `p` is a regular file itself (not followed: a symlink to one is not).
    fn is_file(&self, p: &Path) -> bool;
    /// `p` with every symlink resolved; `None` when it does not exist.
    fn resolve(&self, p: &Path) -> Option<PathBuf>;
    /// The real uid (the fallback runtime directory is `/run/user/<uid>`).
    fn uid(&self) -> u32;
    /// This runtime's own executable, every symlink resolved (the sandbox runs it as its `sandbox-init` shim);
    /// `None` when it cannot be resolved or was deleted or replaced since it started.
    fn runtime_exe(&self) -> Option<PathBuf>;
    /// `systemd-run --user --scope` works here and what its scopes can limit ([`crate::probe_limits`]), or why not.
    fn scopes(&self) -> Result<ScopeSupport, String>;
}

/// `/proc/self/exe` of a binary replaced or deleted since it started reads `<path> (deleted)`.
fn replaced(exe: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    exe.as_os_str().as_bytes().ends_with(b" (deleted)")
}

/// This process's environment and the real filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealHost;

impl Host for RealHost {
    fn env(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
    fn exists(&self, p: &Path) -> bool {
        p.exists()
    }
    fn is_socket(&self, p: &Path) -> bool {
        use std::os::unix::fs::FileTypeExt;
        std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_socket())
    }
    fn is_file(&self, p: &Path) -> bool {
        std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file())
    }
    fn resolve(&self, p: &Path) -> Option<PathBuf> {
        std::fs::canonicalize(p).ok()
    }
    fn uid(&self) -> u32 {
        // SAFETY: getuid cannot fail and touches no memory.
        unsafe { libc::getuid() }
    }
    fn runtime_exe(&self) -> Option<PathBuf> {
        // `/proc/self/exe` of a binary replaced since (a rebuild, a package upgrade) reads `<path> (deleted)`: the
        // file at that path is not this program, so it is refused rather than run as the shim.
        let exe = std::env::current_exe().ok().filter(|e| !replaced(e))?;
        let real = std::fs::canonicalize(exe).ok()?;
        self.is_file(&real).then_some(real)
    }
    fn scopes(&self) -> Result<ScopeSupport, String> {
        // Probed once per 30 s: a launch renders two or three times, and `runtime sandbox` more; a long-lived
        // process (the daemon) still sees a user manager that started or stopped since.
        static PROBED: rt_core::Cached<Result<ScopeSupport, String>> = rt_core::Cached::new(Duration::from_secs(30));
        let probed = PROBED.get_at(Instant::now(), || {
            let sr = crate::find_systemd_run_on_path().ok_or("systemd-run is not on PATH")?;
            // The program gets `$XDG_RUNTIME_DIR` only when it is absolute (`rt_core::allowed_env`).
            let rt = self.env("XDG_RUNTIME_DIR").filter(|d| Path::new(d).is_absolute());
            crate::probe_limits(&sr, rt.as_deref())
        });
        probed.as_ref().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replaced_or_deleted_runtime_executable_is_refused() {
        assert!(replaced(Path::new("/usr/bin/runtime (deleted)")));
        assert!(!replaced(Path::new("/usr/bin/runtime")));
        assert!(!replaced(Path::new("/usr/bin/runtime (deleted)/x")));
        // the running test binary resolves
        assert!(RealHost.runtime_exe().is_some_and(|p| p.is_absolute()));
    }
}
