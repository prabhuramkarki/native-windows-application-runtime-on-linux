//! The permission edit (spec D9) and install form (D10): expressions and params built only from typed choices,
//! refused here with a message before anything is sent (the CLI's own checks stay the real guard).
use rt_api::GrantView;
use rt_daemon::client::{ImportParams, InstallParams};
use std::path::{Path, PathBuf};

/// Longest install name, in bytes (`rt_api::jobs::NAME_MAX`).
const NAME_MAX: usize = rt_api::jobs::NAME_MAX;
/// Longest grant or installer path, in bytes.
const PATH_MAX: usize = rt_api::PATH_MAX;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermChange {
    Network(bool),
    Display(bool),
    Audio(bool),
    Gpu(bool),
    /// A folder from the file chooser.
    Grant {
        path: PathBuf,
        rw: bool,
    },
    /// A grant's path exactly as `permissions.get` showed it.
    Revoke(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstallForm {
    pub path: PathBuf,
    pub name: String,
    pub silent: bool,
    pub network: bool,
}

fn invisible(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || rt_core::is_format(c))
}

/// An absolute UTF-8 path without control or format characters, within `PATH_MAX`.
fn plain_path(p: &std::path::Path) -> Result<&str, &'static str> {
    let s = p.to_str().ok_or("the path is not valid UTF-8")?;
    if !p.is_absolute() {
        Err("the path is not absolute")
    } else if invisible(s) {
        Err("the path contains control or invisible characters")
    } else if s.len() > PATH_MAX {
        Err("the path is too long")
    } else {
        Ok(s)
    }
}

/// The `permissions --set` expression for `c`; `grants` are the app's current grants (for a revoke).
pub(crate) fn perm_expr(c: &PermChange, grants: &[GrantView]) -> Result<String, &'static str> {
    let on = |b: bool| if b { "on" } else { "off" };
    Ok(match c {
        PermChange::Network(b) => format!("network={}", if *b { "allow" } else { "deny" }),
        PermChange::Display(b) => format!("display={}", on(*b)),
        PermChange::Audio(b) => format!("audio={}", on(*b)),
        PermChange::Gpu(b) => format!("gpu={}", on(*b)),
        PermChange::Grant { path, rw } => {
            let p = plain_path(path)?;
            if p.contains(':') {
                return Err("a folder whose path contains ':' cannot be granted");
            }
            format!("fs+={p}:{}", if *rw { "rw" } else { "ro" })
        }
        PermChange::Revoke(p) => {
            if !grants.iter().any(|g| g.path == *p) {
                return Err("that folder is not granted");
            }
            format!("fs-={p}")
        }
    })
}

/// A `.wrun` package (by its extension, any case): the form imports it (`apps.import`) instead of installing it.
/// A package under another name goes to `apps.install`, whose CLI refuses it by its content (W11).
pub fn is_package(path: &Path) -> bool {
    path.extension().is_some_and(|e| e.eq_ignore_ascii_case("wrun"))
}

/// `apps.import`'s params from the form: its name is not used (the package names the app).
pub(crate) fn import_params(f: &InstallForm) -> Result<ImportParams, &'static str> {
    Ok(ImportParams {
        path: plain_path(&f.path)?.to_owned(),
        silent: f.silent,
        network: f.network,
    })
}

/// `apps.install`'s params from the form.
pub(crate) fn install_params(f: &InstallForm) -> Result<InstallParams, &'static str> {
    let path = plain_path(&f.path)?.to_owned();
    let name = f.name.trim();
    if name.len() > NAME_MAX {
        return Err("the name is longer than 256 bytes");
    }
    if invisible(name) {
        return Err("the name contains control or invisible characters");
    }
    Ok(InstallParams {
        path,
        name: (!name.is_empty()).then(|| name.to_owned()),
        exe: None,
        silent: f.silent,
        network: f.network,
    })
}
