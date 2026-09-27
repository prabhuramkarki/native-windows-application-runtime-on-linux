//! Widget smoke tests (spec D13). `harness = false`: GTK must be initialised and used on one thread, and libtest runs
//! tests on worker threads, so this is a plain `main` that runs every scenario in order on the main thread.
//!
//! Without a display (neither `DISPLAY` nor `WAYLAND_DISPLAY`) it skips loudly and passes, unless
//! `RUNTIME_REQUIRE_DISPLAY=1` (the `gui` CI job runs it under `xvfb-run -a` with that set), which makes it fail.
//! Daemon-backed scenarios run the real `runtimed` from the shared rig (a scratch HOME, data dir and runtime dir).
//! With `RUNTIME_GUI_SHOTS` set, each scenario saves a screenshot to `target/gui-smoke/` (never asserted on).
#[path = "../../daemon/tests/support/mod.rs"]
mod support;

use gtk4 as gtk;
use gtk4::glib;
use gtk4::prelude::*;
use libadwaita as adw;
use rt_gui::ui::{self, Ui};
use rt_gui::vm::{READ_ONLY, START_HINT};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};
use support::{Scratch, fake_runtime};

const WAIT: Duration = Duration::from_secs(20);

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

/// The `runtimed` built next to this test binary.
fn runtimed() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let p = exe.parent().unwrap().parent().unwrap().join("runtimed");
    assert!(
        p.is_file(),
        "{} is missing: run `cargo build -p runtime-daemon -p runtime-cli`",
        p.display()
    );
    p
}

/// The widget named `name` under `root` (depth first).
fn find(root: &gtk::Widget, name: &str) -> Option<gtk::Widget> {
    if root.widget_name() == name {
        return Some(root.clone());
    }
    let mut c = root.first_child();
    while let Some(w) = c {
        if let Some(f) = find(&w, name) {
            return Some(f);
        }
        c = w.next_sibling();
    }
    None
}

fn get(ui: &Ui, name: &str) -> gtk::Widget {
    find(ui.window().upcast_ref(), name).unwrap_or_else(|| panic!("no widget named {name}"))
}

/// Every label under `root`.
fn labels(root: &gtk::Widget) -> Vec<gtk::Label> {
    let mut out: Vec<gtk::Label> = root.clone().downcast::<gtk::Label>().into_iter().collect();
    let mut c = root.first_child();
    while let Some(w) = c {
        out.extend(labels(&w));
        c = w.next_sibling();
    }
    out
}

fn rows(list: &gtk::Widget) -> Vec<gtk::Widget> {
    let mut out = vec![];
    let mut c = list.first_child();
    while let Some(w) = c {
        c = w.next_sibling();
        out.push(w);
    }
    out
}

/// Saves `w` as `target/gui-smoke/<name>.png` when RUNTIME_GUI_SHOTS is set.
fn shot(w: &impl IsA<gtk::Widget>, name: &str) {
    if std::env::var_os("RUNTIME_GUI_SHOTS").is_none() {
        return;
    }
    let w = w.as_ref();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/gui-smoke");
    std::fs::create_dir_all(&dir).unwrap();
    let paintable = gtk::WidgetPaintable::new(Some(w));
    let snap = gtk::Snapshot::new();
    paintable.snapshot(&snap, f64::from(w.width()), f64::from(w.height()));
    let (Some(node), Some(renderer)) = (snap.to_node(), w.native().and_then(|n| n.renderer())) else {
        eprintln!("no screenshot for {name}");
        return;
    };
    let _ = renderer
        .render_texture(&node, None)
        .save_to_png(dir.join(format!("{name}.png")));
}

/// The GUI on `s`'s socket, presented.
fn gui(s: &Scratch) -> Rc<Ui> {
    let ui = ui::start(s.sock());
    ui.window().present();
    ui
}

fn close(ui: Rc<Ui>) {
    ui.window().destroy();
    drop(ui);
    iterate_until(WAIT, "the window to go", || {
        glib::MainContext::default().pending() || true
    });
}

// ------------------------------------------------------------------------------------------------ scenarios

fn no_daemon_shows_how_to_start_it() {
    let s = Scratch::new(&runtimed(), Err(&fake_runtime()));
    let ui = gui(&s);
    let page = get(&ui, "status-unreachable");
    iterate_until(WAIT, "the unreachable page", || page.is_mapped());
    let texts: Vec<String> = labels(&page).iter().map(|l| l.text().to_string()).collect();
    assert!(texts.iter().any(|t| t.contains(START_HINT)), "{texts:?}");
    assert!(
        texts.iter().any(|t| t.contains(&s.sock().display().to_string())),
        "{texts:?}"
    );
    shot(ui.window(), "no-daemon");
    close(ui);
}

fn a_read_only_daemon_disables_writes_with_the_reason() {
    let s = Scratch::new(&runtimed(), Err(&fake_runtime()));
    s.plant("game", "Game");
    let _d = s.start(false, &[]);
    let ui = gui(&s);
    let list = get(&ui, "apps-list");
    iterate_until(WAIT, "the app list", || rows(&list).len() == 1);
    let install = get(&ui, "btn-install");
    assert!(!install.is_sensitive());
    assert_eq!(install.tooltip_text().as_deref(), Some(READ_ONLY));
    let banner = get(&ui, "banner-read-only").downcast::<adw::Banner>().unwrap();
    assert!(banner.is_revealed());
    shot(ui.window(), "read-only");
    close(ui);
}

fn a_write_daemon_enables_install() {
    let s = Scratch::new(&runtimed(), Err(&fake_runtime()));
    let _d = s.daemon(&[]);
    let ui = gui(&s);
    let install = get(&ui, "btn-install");
    iterate_until(WAIT, "install to be possible", || install.is_sensitive());
    assert!(
        !get(&ui, "banner-read-only")
            .downcast::<adw::Banner>()
            .unwrap()
            .is_revealed()
    );
    assert!(
        get(&ui, "btn-install-empty").is_sensitive(),
        "the empty state offers Install"
    );
    close(ui);
}

const HOSTILE: &str = r#"<b>x</b> &amp; <span size="99999">"#;

fn a_hostile_name_is_shown_literally() {
    let s = Scratch::new(&runtimed(), Err(&fake_runtime()));
    s.plant("evil", HOSTILE);
    let _d = s.start(false, &[]);
    let ui = gui(&s);
    let list = get(&ui, "apps-list");
    iterate_until(WAIT, "the app list", || rows(&list).len() == 1);
    let shown: Vec<gtk::Label> = labels(&list).into_iter().filter(|l| l.label() == HOSTILE).collect();
    assert_eq!(shown.len(), 1, "the title label");
    // What is drawn is the string itself: no markup was parsed.
    assert_eq!(shown[0].text(), HOSTILE);
    assert!(!shown[0].uses_markup());
    shot(ui.window(), "hostile-name");
    close(ui);
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
    let tests: &[(&str, fn())] = &[
        ("no_daemon_shows_how_to_start_it", no_daemon_shows_how_to_start_it),
        (
            "a_read_only_daemon_disables_writes_with_the_reason",
            a_read_only_daemon_disables_writes_with_the_reason,
        ),
        ("a_write_daemon_enables_install", a_write_daemon_enables_install),
        ("a_hostile_name_is_shown_literally", a_hostile_name_is_shown_literally),
    ];
    for (name, t) in tests {
        eprintln!("test {name} ...");
        t();
        eprintln!("test {name} ... ok");
    }
    eprintln!("widget tests: {} passed", tests.len());
}
