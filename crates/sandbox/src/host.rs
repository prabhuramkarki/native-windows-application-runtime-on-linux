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
}
