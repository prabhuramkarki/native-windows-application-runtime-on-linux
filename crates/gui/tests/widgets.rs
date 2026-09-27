//! Widget smoke tests (spec D13). `harness = false`: GTK must be initialised and used on one thread, and libtest runs
//! tests on worker threads, so this is a plain `main` that runs every scenario in order on the main thread.
//!
//! Without a display (neither `DISPLAY` nor `WAYLAND_DISPLAY`) it skips loudly and passes, unless
//! `RUNTIME_REQUIRE_DISPLAY=1` (the `gui` CI job runs it under `xvfb-run -a` with that set), which makes it fail.
use gtk4::glib;
use gtk4::prelude::*;
use libadwaita as adw;
use std::time::{Duration, Instant};

/// Runs the main context until `done` or panics after `within`.
fn iterate_until(within: Duration, what: &str, mut done: impl FnMut() -> bool) {
    let ctx = glib::MainContext::default();
    let until = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        ctx.iteration(false);
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn the_window_opens_and_closes() {
    let w = rt_gui::ui::window();
    w.present();
    iterate_until(Duration::from_secs(10), "the window to map", || w.is_mapped());
    w.close();
    iterate_until(Duration::from_secs(10), "the window to close", || !w.is_visible());
}

/// Points HOME and every XDG directory at `dir` and keeps GTK off the user's session bus and settings, before GTK
/// starts: the tests never read or write the user's own configuration.
fn isolate(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let run = dir.join("xdg-runtime");
    std::fs::create_dir(&run).unwrap();
    std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A relative WAYLAND_DISPLAY names a socket in the real runtime dir: keep reaching it once that is replaced.
    let wayland = std::env::var_os("WAYLAND_DISPLAY").filter(|w| !w.is_empty()).map(|w| {
        let real = std::env::var_os("XDG_RUNTIME_DIR").unwrap_or_default();
        std::path::Path::new(&real).join(w)
    });
    // SAFETY: called from `main` before GTK (or anything else) has started a thread.
    unsafe {
        if let Some(w) = wayland {
            std::env::set_var("WAYLAND_DISPLAY", w);
        }
        for (k, sub) in [
            ("HOME", "home"),
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_STATE_HOME", "state"),
        ] {
            std::fs::create_dir(dir.join(sub)).unwrap();
            std::env::set_var(k, dir.join(sub));
        }
        std::env::set_var("XDG_RUNTIME_DIR", &run);
        std::env::set_var("GSETTINGS_BACKEND", "memory");
        std::env::set_var("GTK_A11Y", "none");
        std::env::remove_var("DBUS_SESSION_BUS_ADDRESS");
    }
}

fn main() {
    let has_display = ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|s| !s.is_empty()));
    if !has_display {
        if std::env::var_os("RUNTIME_REQUIRE_DISPLAY").is_some_and(|v| v == "1") {
            eprintln!("FAILED: RUNTIME_REQUIRE_DISPLAY=1 but neither DISPLAY nor WAYLAND_DISPLAY is set");
            std::process::exit(1);
        }
        eprintln!(
            "SKIPPED: widget tests need a display (run under `xvfb-run -a`; RUNTIME_REQUIRE_DISPLAY=1 to require one)"
        );
        return;
    }
    let scratch = tempfile::tempdir().expect("scratch dir");
    isolate(scratch.path());
    gtk4::init().expect("gtk init");
    adw::init().expect("adw init");
    let tests: &[(&str, fn())] = &[("the_window_opens_and_closes", the_window_opens_and_closes)];
    for (name, t) in tests {
        eprintln!("test {name} ...");
        t();
        eprintln!("test {name} ... ok");
    }
    eprintln!("widget tests: {} passed", tests.len());
}
