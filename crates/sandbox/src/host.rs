//! The host facts [`crate::AppSandbox`] reads while rendering: the real process environment (for the real
//! `$HOME` grants are judged against) and which paths exist. Injected so the renderer stays a pure argv builder
//! that tests drive with a fake host; [`RealHost`] is the production view.
use std::ffi::OsString;
use std::path::{Path, PathBuf};

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
        use std::os::unix::ffi::OsStrExt;
        // `/proc/self/exe` of a binary replaced since (a rebuild, a package upgrade) reads `<path> (deleted)`: the
        // file at that path is not this program, so it is refused rather than run as the shim.
        let exe = std::env::current_exe().ok()?;
        if exe.as_os_str().as_bytes().ends_with(b" (deleted)") {
            return None;
        }
        let real = std::fs::canonicalize(exe).ok()?;
        self.is_file(&real).then_some(real)
    }
}
