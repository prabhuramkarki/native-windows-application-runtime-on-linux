//! Data directory resolution.
use std::{ffi::OsString, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DirsError {
    #[error("{var} must be an absolute path, got {value:?}")]
    NotAbsolute { var: &'static str, value: PathBuf },
    #[error("cannot determine the data directory: set RUNTIME_DATA_DIR, XDG_DATA_HOME or HOME")]
    Unresolvable,
}

/// A set, non-empty variable (empty counts as unset, as the XDG spec says), which must be absolute.
fn abs_var(env: &impl Fn(&str) -> Option<OsString>, var: &'static str) -> Result<Option<PathBuf>, DirsError> {
    match env(var).filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(v) => {
            let value = PathBuf::from(v);
            if value.is_absolute() {
                Ok(Some(value))
            } else {
                Err(DirsError::NotAbsolute { var, value })
            }
        }
    }
}

/// Pure resolution over an injected environment. Precedence: `RUNTIME_DATA_DIR`, then `$XDG_DATA_HOME/runtime`,
/// then `$HOME/.local/share/runtime`. A variable that is set but relative is an error (never a silent fall
/// through to another location). Values are `OsString`: a non-UTF-8 absolute path is a legal Linux path and is
/// kept as is, so nothing here can panic on odd bytes. The result is trusted configuration and is not
/// normalised (a `..` inside an absolute value is the user's business).
pub fn data_root_from(env: &impl Fn(&str) -> Option<OsString>) -> Result<PathBuf, DirsError> {
    if let Some(p) = abs_var(env, "RUNTIME_DATA_DIR")? {
        return Ok(p);
    }
    if let Some(p) = abs_var(env, "XDG_DATA_HOME")? {
        return Ok(p.join("runtime"));
    }
    if let Some(p) = abs_var(env, "HOME")? {
        return Ok(p.join(".local/share/runtime"));
    }
    Err(DirsError::Unresolvable)
}

pub fn apps_dir_from(env: &impl Fn(&str) -> Option<OsString>) -> Result<PathBuf, DirsError> {
    data_root_from(env).map(|r| r.join("apps"))
}

/// [`data_root_from`] over the process environment.
pub fn data_root() -> Result<PathBuf, DirsError> {
    data_root_from(&|k| std::env::var_os(k))
}

/// `data_root()/apps`: one directory per installed app.
pub fn apps_dir() -> Result<PathBuf, DirsError> {
    apps_dir_from(&|k| std::env::var_os(k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::HashMap, os::unix::ffi::OsStrExt, path::Path};

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let map: HashMap<String, OsString> = pairs.iter().map(|(k, v)| (k.to_string(), OsString::from(v))).collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn runtime_data_dir_wins() {
        let e = env(&[("RUNTIME_DATA_DIR", "/r"), ("XDG_DATA_HOME", "/x"), ("HOME", "/h")]);
        assert_eq!(data_root_from(&e), Ok(PathBuf::from("/r")));
    }

    #[test]
    fn xdg_beats_home_and_gets_runtime_suffix() {
        let e = env(&[("XDG_DATA_HOME", "/x"), ("HOME", "/h")]);
        assert_eq!(data_root_from(&e), Ok(PathBuf::from("/x/runtime")));
    }

    #[test]
    fn home_fallback() {
        let e = env(&[("HOME", "/h")]);
        assert_eq!(data_root_from(&e), Ok(PathBuf::from("/h/.local/share/runtime")));
    }

    #[test]
    fn nothing_set_is_an_error() {
        assert_eq!(data_root_from(&env(&[])), Err(DirsError::Unresolvable));
    }

    #[test]
    fn empty_values_count_as_unset() {
        let e = env(&[("RUNTIME_DATA_DIR", ""), ("XDG_DATA_HOME", ""), ("HOME", "/h")]);
        assert_eq!(data_root_from(&e), Ok(PathBuf::from("/h/.local/share/runtime")));
        assert_eq!(data_root_from(&env(&[("HOME", "")])), Err(DirsError::Unresolvable));
    }

    #[test]
    fn relative_values_are_rejected_without_falling_through() {
        // A relative override must not silently fall back to a different directory.
        for (var, val) in [
            ("RUNTIME_DATA_DIR", "data"),
            ("RUNTIME_DATA_DIR", "./x"),
            ("RUNTIME_DATA_DIR", "../x"),
        ] {
            let e = env(&[(var, val), ("XDG_DATA_HOME", "/x"), ("HOME", "/h")]);
            assert_eq!(
                data_root_from(&e),
                Err(DirsError::NotAbsolute {
                    var,
                    value: PathBuf::from(val)
                })
            );
        }
        let e = env(&[("XDG_DATA_HOME", "rel"), ("HOME", "/h")]);
        assert_eq!(
            data_root_from(&e),
            Err(DirsError::NotAbsolute {
                var: "XDG_DATA_HOME",
                value: PathBuf::from("rel")
            })
        );
        let e = env(&[("HOME", "rel")]);
        assert_eq!(
            data_root_from(&e),
            Err(DirsError::NotAbsolute {
                var: "HOME",
                value: PathBuf::from("rel")
            })
        );
    }

    #[test]
    fn non_utf8_absolute_path_is_kept_and_relative_is_rejected() {
        let abs = OsString::from(std::ffi::OsStr::from_bytes(b"/tmp/\xff\xfe"));
        let a = abs.clone();
        let e = move |k: &str| (k == "RUNTIME_DATA_DIR").then(|| a.clone());
        assert_eq!(data_root_from(&e), Ok(PathBuf::from(abs)));

        let rel = OsString::from(std::ffi::OsStr::from_bytes(b"rel\xff"));
        let e = move |k: &str| (k == "RUNTIME_DATA_DIR").then(|| rel.clone());
        let err = data_root_from(&e).unwrap_err();
        assert!(matches!(
            err,
            DirsError::NotAbsolute {
                var: "RUNTIME_DATA_DIR",
                ..
            }
        ));
        // Formatting a non-UTF-8 value must not panic and must not emit it raw.
        assert!(err.to_string().contains("RUNTIME_DATA_DIR"));
    }

    #[test]
    fn error_text_escapes_control_characters() {
        let e = env(&[("RUNTIME_DATA_DIR", "rel\u{1b}[31m")]);
        let msg = data_root_from(&e).unwrap_err().to_string();
        assert!(!msg.contains('\u{1b}'), "raw escape leaked into {msg:?}");
    }

    #[test]
    fn apps_dir_is_root_slash_apps() {
        let e = env(&[("RUNTIME_DATA_DIR", "/r")]);
        assert_eq!(apps_dir_from(&e), Ok(Path::new("/r/apps").to_path_buf()));
        assert_eq!(apps_dir_from(&env(&[])), Err(DirsError::Unresolvable));
        let e = env(&[("RUNTIME_DATA_DIR", "rel")]);
        assert!(apps_dir_from(&e).is_err());
    }

    #[test]
    fn process_env_wrappers_use_the_real_environment() {
        let real = |k: &str| std::env::var_os(k);
        assert_eq!(data_root(), data_root_from(&real));
        assert_eq!(apps_dir(), apps_dir_from(&real));
    }
}
