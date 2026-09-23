//! Where this crate's files live under `$XDG_DATA_HOME`, and the small filesystem/process primitives shared by
//! [`crate::entry`] and [`crate::mime`].
//!
//! **Not the same directory `rt_core::dirs` resolves.** `rt_core::dirs::data_root_from` resolves
//! `$XDG_DATA_HOME/runtime` (this project's OWN data directory, for `apps/<id>/...`). A `.desktop` file and its
//! icons are read by the desktop shell itself, which only ever looks in the XDG-standard locations —
//! `$XDG_DATA_HOME/applications` and `$XDG_DATA_HOME/icons/hicolor/...` — directly, with no `/runtime` suffix.
//! [`data_home_from`] mirrors `data_root_from`'s shape (injected closure, `RUNTIME_DATA_DIR`-style precedence
//! minus that one project-specific override, the same absolute/no-dot-components validation) but resolves the
//! plain XDG value.
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XdgError {
    #[error("{var} must be an absolute path, got {value:?}")]
    NotAbsolute { var: &'static str, value: PathBuf },
    #[error("{var} must not contain `.` or `..` components, got {value:?}")]
    NonCanonical { var: &'static str, value: PathBuf },
    #[error("cannot determine the XDG data directory: set XDG_DATA_HOME or HOME")]
    Unresolvable,
}

fn has_dot_components(path: &Path) -> bool {
    path.components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
}

/// A set, non-empty variable (empty counts as unset, per the XDG spec), absolute and free of `.`/`..`
/// components. Mirrors `rt_core::dirs`'s identically named, private helper exactly.
fn abs_var(env: &impl Fn(&str) -> Option<OsString>, var: &'static str) -> Result<Option<PathBuf>, XdgError> {
    match env(var).filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(v) => {
            let value = PathBuf::from(v);
            if !value.is_absolute() {
                Err(XdgError::NotAbsolute { var, value })
            } else if has_dot_components(&value) {
                Err(XdgError::NonCanonical { var, value })
            } else {
                Ok(Some(value))
            }
        }
    }
}

/// `$XDG_DATA_HOME`, else `$HOME/.local/share` (XDG Base Directory Specification). A variable that is set but
/// relative or non-canonical is an error, never a silent fall-through to another location.
pub fn data_home_from(env: &impl Fn(&str) -> Option<OsString>) -> Result<PathBuf, XdgError> {
    if let Some(p) = abs_var(env, "XDG_DATA_HOME")? {
        return Ok(p);
    }
    if let Some(p) = abs_var(env, "HOME")? {
        return Ok(p.join(".local/share"));
    }
    Err(XdgError::Unresolvable)
}

/// `$XDG_DATA_HOME/applications`: where a user's own `.desktop` files live.
pub fn applications_dir_from(env: &impl Fn(&str) -> Option<OsString>) -> Result<PathBuf, XdgError> {
    data_home_from(env).map(|p| p.join("applications"))
}

/// `$XDG_DATA_HOME/icons/hicolor/<size>x<size>/apps`: where a user's own app icons of `size` pixels live
/// (Icon Theme Specification).
pub fn hicolor_apps_dir_from(env: &impl Fn(&str) -> Option<OsString>, size: u32) -> Result<PathBuf, XdgError> {
    data_home_from(env).map(|p| p.join(format!("icons/hicolor/{size}x{size}/apps")))
}

fn is_executable_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Looks for an executable named `name` on `$PATH`, the way a shell would (absolute directories only, first
/// match wins). Mirrors `rt_installer::sandbox::find_bwrap`, generalised over the tool name; injected
/// `env`/`is_exec` make it unit-testable without touching the real filesystem.
pub(crate) fn find_on_path(
    env: &impl Fn(&str) -> Option<OsString>,
    is_exec: &impl Fn(&Path) -> bool,
    name: &str,
) -> Option<PathBuf> {
    let path = env("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|candidate| is_exec(candidate))
}

/// [`find_on_path`] over the real environment and filesystem.
pub(crate) fn find_on_path_real(name: &str) -> Option<PathBuf> {
    find_on_path(&|k| std::env::var_os(k), &is_executable_file, name)
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A private (`0600`-family, caller-chosen `mode`) temp file in `dir`, created with `O_EXCL` so an existing name
/// — even a symlink — is never opened, whose name ends in `tmp_suffix`. Pass `tmp_suffix = ".desktop"` for a
/// file a tool like `desktop-file-validate` will inspect by name (it refuses anything whose name does not
/// literally end that way); `""` for one nothing inspects by name (an icon). Up to 16 attempts with a fresh
/// counter value skip a leftover name from a crashed run rather than reusing it. The caller writes to the
/// returned handle, then either `fs::rename`s the path over the final target (which replaces an existing entry
/// there, symlink included, never that symlink's target — the same discipline `rt_core::Metadata::write_atomic`
/// uses) or removes it on failure.
pub(crate) fn create_temp(dir: &Path, mode: u32, tmp_suffix: &str) -> io::Result<(PathBuf, File)> {
    let mut last = None;
    for _ in 0..16 {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let name = format!(".rt-desktop.tmp-{}-{n}{tmp_suffix}", std::process::id());
        let tmp = dir.join(name);
        match OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp) {
            Ok(f) => return Ok((tmp, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("could not create a temporary file")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let map: HashMap<String, OsString> = pairs.iter().map(|(k, v)| (k.to_string(), OsString::from(v))).collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn xdg_data_home_wins_over_home() {
        let e = env(&[("XDG_DATA_HOME", "/x"), ("HOME", "/h")]);
        assert_eq!(data_home_from(&e), Ok(PathBuf::from("/x")));
    }

    #[test]
    fn home_fallback_gets_the_local_share_suffix() {
        let e = env(&[("HOME", "/h")]);
        assert_eq!(data_home_from(&e), Ok(PathBuf::from("/h/.local/share")));
    }

    #[test]
    fn nothing_set_is_unresolvable() {
        assert_eq!(data_home_from(&env(&[])), Err(XdgError::Unresolvable));
    }

    #[test]
    fn empty_xdg_data_home_counts_as_unset() {
        let e = env(&[("XDG_DATA_HOME", ""), ("HOME", "/h")]);
        assert_eq!(data_home_from(&e), Ok(PathBuf::from("/h/.local/share")));
    }

    #[test]
    fn relative_or_dotted_values_are_rejected_without_falling_through() {
        let e = env(&[("XDG_DATA_HOME", "rel"), ("HOME", "/h")]);
        assert_eq!(
            data_home_from(&e),
            Err(XdgError::NotAbsolute {
                var: "XDG_DATA_HOME",
                value: PathBuf::from("rel")
            })
        );
        let e = env(&[("XDG_DATA_HOME", "/a/../b")]);
        assert_eq!(
            data_home_from(&e),
            Err(XdgError::NonCanonical {
                var: "XDG_DATA_HOME",
                value: PathBuf::from("/a/../b")
            })
        );
    }

    #[test]
    fn applications_and_hicolor_paths_are_joined_correctly() {
        let e = env(&[("XDG_DATA_HOME", "/x")]);
        assert_eq!(applications_dir_from(&e), Ok(PathBuf::from("/x/applications")));
        assert_eq!(
            hicolor_apps_dir_from(&e, 48),
            Ok(PathBuf::from("/x/icons/hicolor/48x48/apps"))
        );
    }

    #[test]
    fn find_on_path_searches_in_order_and_skips_relative_entries() {
        let files = ["/usr/bin/tool", "/opt/bin/tool"];
        let is_exec = |p: &Path| files.contains(&p.to_str().unwrap());
        let env = |k: &str| (k == "PATH").then(|| OsString::from(":.:rel:/opt/bin:/usr/bin"));
        assert_eq!(
            find_on_path(&env, &is_exec, "tool"),
            Some(PathBuf::from("/opt/bin/tool"))
        );
    }

    #[test]
    fn find_on_path_is_none_without_a_match_or_without_path() {
        let is_exec = |_: &Path| false;
        let env = |k: &str| (k == "PATH").then(|| OsString::from("/usr/bin"));
        assert_eq!(find_on_path(&env, &is_exec, "tool"), None);
        assert_eq!(find_on_path(&|_: &str| None, &is_exec, "tool"), None);
    }

    #[test]
    fn create_temp_names_end_in_the_requested_suffix_and_never_collide() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, _) = create_temp(tmp.path(), 0o600, ".desktop").unwrap();
        let (b, _) = create_temp(tmp.path(), 0o600, ".desktop").unwrap();
        assert_ne!(a, b);
        assert!(a.to_str().unwrap().ends_with(".desktop"));
        assert!(b.to_str().unwrap().ends_with(".desktop"));
    }

    #[test]
    fn create_temp_never_opens_an_existing_name() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        fs::write(&victim, "precious").unwrap();
        let dir = tmp.path().join("d");
        fs::create_dir(&dir).unwrap();
        let start = TEMP_COUNTER.load(Ordering::Relaxed);
        for n in start..start + 32 {
            let name = format!(".rt-desktop.tmp-{}-{n}", std::process::id());
            symlink(&victim, dir.join(name)).unwrap();
        }
        assert!(create_temp(&dir, 0o600, "").is_err());
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
    }
}
