//! `runtime display <app> [auto|x11|wayland]`: shows or sets the Wine graphics driver of an app's prefix
//! (`HKCU\Software\Wine\Drivers` `Graphics`).
//!
//! Reading takes no lock and writes nothing. Setting is validated BEFORE the app lock is taken and before
//! anything is written: `wayland` needs a Wayland session (the socket doctor looks for) and a Wine that has
//! `winewayland` (a Wine whose files cannot be listed is "not verified", which never refuses). `x11` without a
//! `DISPLAY` only warns. The lock is exclusive, so a running app refuses it.
use crate::CmdError;
use crate::safe::{safe, shorten, warn};
use rt_core::doctor::{HostFs, wayland_socket};
use rt_core::{CompatBackend, GraphicsDriver, Launcher};
use rt_deps::wine_config::{read_graphics_driver_from_prefix, set_graphics_driver};
use std::ffi::OsString;
use std::fs;

fn env_var(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

/// `Some(found)` when the backend's DLL directories could be listed (or `winewayland` was found anyway),
/// `None` when nothing could be checked.
fn has_winewayland(backend: &dyn CompatBackend) -> Option<bool> {
    let mut verified = false;
    for dir in backend.dll_dirs() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        verified = true;
        for e in rd.flatten() {
            if e.file_name()
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("winewayland")
            {
                return Some(true);
            }
        }
    }
    verified.then_some(false)
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
    // Under the lock: the same no-follow, regular-file, size-capped check the read path makes, so Wine's writer
    // never meets a symlinked prefix or `user.reg`. A missing user.reg is fine.
    read_graphics_driver_from_prefix(&env)
        .map_err(|e| format!("not set: cannot use {}'s registry: {e}; nothing was changed", env.id()))?;
    set_graphics_driver(&env, &backend, &launcher, &want).map_err(|e| e.to_string())?;
    crate::emit(&format!("graphics driver of {} set to {}\n", env.id(), want.as_str()))
}
