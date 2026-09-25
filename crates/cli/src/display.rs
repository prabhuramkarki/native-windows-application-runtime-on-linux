//! `runtime display <app> [auto|x11|wayland]`: shows or sets the Wine graphics driver of an app's prefix
//! (`HKCU\Software\Wine\Drivers` `Graphics`).
//!
//! Reading takes no lock and writes nothing. Setting is validated BEFORE the app lock is taken and before
//! anything is written: `wayland` needs a Wayland session (the socket doctor looks for) and a Wine that has
//! `winewayland` (a Wine whose files cannot be listed, or only partly, is "not verified", which never refuses).
//! `x11` without a `DISPLAY` only warns. The exclusive lock only keeps other runtime commands out (`runtime run`
//! holds the shared lock just while it starts the app); a running app is refused by the wineserver check
//! (`rt_deps::wineservers_for`, the guard `deps` uses), which fails closed when `/proc` cannot be read.
use crate::CmdError;
use crate::safe::{safe, shorten, warn};
use rt_core::doctor::{HostFs, MAX_DLL_DIRS, MAX_LISTING, wayland_socket};
use rt_core::{CompatBackend, GraphicsDriver, Launcher};
use rt_deps::wine_config::{read_graphics_driver_from_prefix, set_graphics_driver};
use std::ffi::OsString;
use std::fs;

fn env_var(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

/// Driver names kept at most.
const MAX_DRIVERS: usize = 200;

/// The `wine*.drv` names (lowercase) among `entries`; `None` when an entry could not be read or there are more
/// than [`MAX_LISTING`] of them (a refusal must never rest on a partly read directory).
fn drivers_in(entries: impl Iterator<Item = std::io::Result<String>>) -> Option<Vec<String>> {
    let mut found = Vec::new();
    for (i, e) in entries.enumerate() {
        let n = e.ok()?.to_ascii_lowercase();
        if i >= MAX_LISTING {
            return None;
        }
        if n.starts_with("wine") && n.ends_with(".drv") && found.len() < MAX_DRIVERS && !found.contains(&n) {
            found.push(n);
        }
    }
    Some(found)
}

/// File names (lowercase) of the Wine driver modules (`wine*.drv`) in the backend's DLL directories: at most
/// [`MAX_DRIVERS`], from at most [`MAX_DLL_DIRS`] directories. `None` when none of the directories could be listed
/// or one was read only in part. `doctor` and `display` both use it.
pub fn wine_drivers(backend: &dyn CompatBackend) -> Option<Vec<String>> {
    let mut found: Vec<String> = Vec::new();
    let mut verified = false;
    for dir in backend.dll_dirs().iter().take(MAX_DLL_DIRS) {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        let names = rd.map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()));
        for n in drivers_in(names)? {
            if found.len() < MAX_DRIVERS && !found.contains(&n) {
                found.push(n);
            }
        }
        verified = true;
    }
    verified.then_some(found)
}

/// `Some(found)` when the backend's DLL directories could be listed, `None` when nothing could be checked.
fn has_winewayland(backend: &dyn CompatBackend) -> Option<bool> {
    wine_drivers(backend).map(|l| l.iter().any(|n| n == "winewayland.drv"))
}

fn session() -> String {
    if wayland_socket(&env_var, &HostFs).is_some() {
        let name = env_var("WAYLAND_DISPLAY").unwrap_or_default();
        return format!("wayland socket {}", shorten(&name.to_string_lossy(), 60));
    }
    match env_var("DISPLAY") {
        Some(d) => format!("x11 DISPLAY {}", shorten(&d.to_string_lossy(), 60)),
        None => "none".into(),
    }
}

fn driver_text(d: &GraphicsDriver) -> String {
    match d {
        GraphicsDriver::Custom(s) => format!("custom: {s}"),
        other => other.as_str().to_owned(),
    }
}

pub fn run(app: &str, choice: Option<&str>) -> Result<(), CmdError> {
    let store = crate::store()?;
    let env = crate::deps::app_env(&store, app)?;
    let launcher = Launcher::new();
    let Some(choice) = choice else {
        let driver =
            read_graphics_driver_from_prefix(&env).map_err(|e| format!("cannot read {}'s user.reg: {e}", env.id()))?;
        let wl = match crate::backend(&launcher).ok().and_then(|b| has_winewayland(&b)) {
            Some(true) => "present",
            Some(false) => "not found",
            None => "not verified",
        };
        return crate::emit(&format!(
            "graphics driver: {}\nsession: {}\nwinewayland: {wl}\n",
            safe(&driver_text(&driver)),
            safe(&session())
        ));
    };
    let want = GraphicsDriver::parse_choice(choice)
        .ok_or_else(|| format!("unknown driver {:?}: choose auto, x11 or wayland", shorten(choice, 40)))?;
    let backend = crate::backend(&launcher)?;
    match want {
        GraphicsDriver::Wayland => {
            if wayland_socket(&env_var, &HostFs).is_none() {
                return Err(
                    "not set: no Wayland session found (WAYLAND_DISPLAY is unset or its socket does not \
                            exist); wayland would leave the program without a display"
                        .into(),
                );
            }
            match has_winewayland(&backend) {
                Some(false) => {
                    return Err(
                        "not set: this Wine has no winewayland driver (Wine built without Wayland \
                                support); nothing was changed"
                            .into(),
                    );
                }
                None => warn("could not verify that this Wine has the winewayland driver; setting it anyway"),
                Some(true) => {}
            }
        }
        GraphicsDriver::X11 if env_var("DISPLAY").is_none() => {
            warn("DISPLAY is not set: x11 needs an X11 or XWayland display when the program runs");
        }
        _ => {}
    }
    let _lock = crate::deps::lock_or_refuse(&env, false, "change the graphics driver of")?;
    // The lock only excludes other runtime commands: a running app is a wineserver for this prefix. Fail closed.
    match rt_deps::wineservers_for(&env.prefix()) {
        Ok(pids) if pids.is_empty() => {}
        Ok(pids) => {
            return Err(format!(
                "not set: {} appears to be running (wineserver pid {}): stop it first; nothing was changed",
                env.id(),
                pids[0]
            )
            .into());
        }
        Err(e) => {
            return Err(format!(
                "not set: cannot check whether {} is running: {e}; nothing was changed",
                env.id()
            )
            .into());
        }
    }
    // Under the lock: the same no-follow, regular-file, size-capped check the read path makes, so Wine's writer
    // never meets a symlinked prefix or `user.reg`. A missing user.reg is fine.
    read_graphics_driver_from_prefix(&env)
        .map_err(|e| format!("not set: cannot use {}'s registry: {e}; nothing was changed", env.id()))?;
    set_graphics_driver(&env, &backend, &launcher, &want).map_err(|e| e.to_string())?;
    crate::emit(&format!("graphics driver of {} set to {}\n", env.id(), want.as_str()))
}

#[cfg(test)]
mod tests {
    use super::drivers_in;
    use std::io;

    fn ok(n: &str) -> io::Result<String> {
        Ok(n.to_owned())
    }

    #[test]
    fn keeps_wine_drivers_only() {
        let l = drivers_in([ok("WinePulse.drv"), ok("kernel32.dll"), ok("winealsa.drv")].into_iter());
        assert_eq!(l.unwrap(), ["winepulse.drv", "winealsa.drv"]);
        assert_eq!(drivers_in(std::iter::empty()), Some(vec![]));
    }

    #[test]
    fn an_unreadable_entry_means_not_verified() {
        let bad = Err(io::Error::other("boom"));
        assert_eq!(drivers_in([ok("winepulse.drv"), bad].into_iter()), None);
    }
}
