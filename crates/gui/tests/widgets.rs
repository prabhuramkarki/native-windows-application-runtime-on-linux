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
use libadwaita::prelude::*;
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
    let ctx = glib::MainContext::default();
    let until = Instant::now() + Duration::from_secs(2);
    while ctx.pending() && Instant::now() < until {
        ctx.iteration(false);
    }
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
    // Opened: the page heading, the header's page title and every other place draw it literally too.
    list.downcast_ref::<gtk::ListBox>()
        .unwrap()
        .row_at_index(0)
        .unwrap()
        .emit_activate();
    let win: gtk::Widget = ui.window().clone().upcast();
    iterate_until(WAIT, "the page", || {
        ui.model().page().is_some_and(|p| p.data().is_some())
            && labels(&win).iter().filter(|l| l.label().contains("<b>x")).count() >= 3
    });
    for l in labels(&win).iter().filter(|l| l.label().contains("<b>x")) {
        assert_eq!(l.text(), l.label(), "parsed as markup: {:?}", l.label());
    }
    shot(ui.window(), "hostile-name");
    close(ui);
}

// ------------------------------------------------------------------------------------------------ Task 5: app page

use rt_api::{ConsentView, DepsPlanView, PlanAction, PlanEntryView, VersionInfo};
use rt_gui::vm::{AppData, Cmd, Msg};
use std::cell::RefCell;

/// A UI with no backend: every command it sends is recorded.
fn recorded() -> (Rc<Ui>, Rc<RefCell<Vec<Cmd>>>) {
    let sent = Rc::new(RefCell::new(vec![]));
    let s = sent.clone();
    let ui = Ui::new(
        Box::new(move |c| s.borrow_mut().push(c)),
        std::path::Path::new("/run/x.sock"),
    );
    ui.window().present();
    (ui, sent)
}

fn app_data(id: &str) -> AppData {
    let v = |j: serde_json::Value| j;
    AppData {
        detail: serde_json::from_value(v(serde_json::json!({
            "id": id, "name": "Game", "version": null, "architecture": "x86_64", "executable": "C:\\g.exe",
            "environment": "e", "backend": {"id": "wine", "version": "10"}, "subsystem": "gui", "created": 0,
            "installer": null, "dependencies": [], "prefix": {"exists": true, "hasDriveC": true}
        })))
        .unwrap(),
        permissions: Ok(serde_json::from_value(serde_json::json!({
            "source": "file", "network": "deny", "display": true, "audio": false, "gpu": false,
            "filesystem": [{"path": "/data/music", "access": "ro"}],
            "limits": {"memoryMb": null, "cpuPercent": null, "tasks": 512, "tasksDefault": true, "explicit": false}
        }))
        .unwrap()),
        doctor: Err(rt_daemon::client::ClientError::Unsupported("not in this test")),
        graphics: Err(rt_daemon::client::ClientError::Unsupported("not in this test")),
        sandbox: Err(rt_daemon::client::ClientError::Unsupported("not in this test")),
    }
}

/// `ui` connected (`write` or not) with app `game` open, loaded and planned (`plan`).
fn opened(ui: &Rc<Ui>, write: bool, plan: DepsPlanView) {
    ui.dispatch(Msg::Connected(VersionInfo {
        api: "0.2.0".into(),
        runtime: "0.0.1".into(),
        protocol: "jsonrpc-2.0-ndjson".into(),
        write,
    }));
    ui.dispatch(Msg::Apps(
        serde_json::from_value(
            serde_json::json!({"apps": [{"id": "game", "name": "Game", "version": null,
            "architecture": "x86_64", "executable": "e", "created": 0}], "skipped": 0}),
        )
        .unwrap(),
    ));
    ui.dispatch(Msg::Open("game".into()));
    ui.dispatch(Msg::AppLoaded(Box::new(app_data("game"))));
    ui.dispatch(Msg::PlanLoaded {
        id: "game".into(),
        plan,
    });
}

const DIGEST: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";

fn needed(package: &str, text: &[&str]) -> PlanEntryView {
    PlanEntryView {
        package: package.into(),
        version: Some("14.44".into()),
        action: PlanAction::Install,
        consent: ConsentView::Needed,
        blocked_reason: None,
        sha256: Some(format!("{:0>64}", package.len())),
        consent_text: Some(text.iter().map(|t| t.to_string()).collect()),
    }
}

/// Two needed entries (one with an ESC and markup in its terms) and one denied with a reason.
fn canned_plan() -> DepsPlanView {
    let mut denied = needed("mono", &[]);
    denied.action = PlanAction::Blocked;
    denied.consent = ConsentView::Denied;
    denied.consent_text = None;
    denied.blocked_reason = Some("you said no <b>earlier</b>".into());
    DepsPlanView {
        entries: vec![
            needed(
                "vcrun",
                &[
                    "Licence: proprietary",
                    "Terms \u{1b}[2J <b>bold</b> & more",
                    "Last line",
                ],
            ),
            needed("dx", &["Licence: zlib"]),
            denied,
        ],
        unsatisfied: vec!["d3dcompiler".into()],
        warnings: vec![],
        digest: DIGEST.into(),
    }
}

fn click(ui: &Ui, name: &str) {
    let b = get(ui, name).downcast::<gtk::Button>().unwrap();
    assert!(b.is_sensitive(), "{name} is insensitive: {:?}", b.tooltip_text());
    b.emit_clicked();
}

fn dialog(ui: &Ui, name: &str) -> adw::AlertDialog {
    let mut found = None;
    iterate_until(WAIT, name, || {
        found = find(ui.window().upcast_ref(), name);
        found.is_some()
    });
    found.unwrap().downcast().unwrap()
}

fn the_consent_dialog_shows_every_term_and_sends_only_what_was_accepted() {
    let (ui, sent) = recorded();
    opened(&ui, true, canned_plan());
    click(&ui, "btn-deps");
    let d = dialog(&ui, "consent-dialog");
    let root: gtk::Widget = d.clone().upcast();
    assert_eq!(d.default_response().as_deref(), Some("cancel"));
    assert_eq!(d.close_response(), "cancel");
    assert_eq!(d.response_label("install"), "Install (0 of 2 accepted)");
    let checks: Vec<gtk::CheckButton> = ["vcrun", "dx"]
        .iter()
        .map(|p| find(&root, &format!("consent-check-{p}")).unwrap().downcast().unwrap())
        .collect();
    assert!(checks.iter().all(|c| !c.is_active()), "nothing is pre-checked");
    let text = find(&root, "consent-text-vcrun")
        .unwrap()
        .downcast::<gtk::Label>()
        .unwrap();
    assert!(!text.uses_markup());
    assert_eq!(
        text.text(),
        "Licence: proprietary\nTerms [2J <b>bold</b> & more\nLast line",
        "every line, cleaned, literally"
    );
    let all: Vec<String> = labels(&root).iter().map(|l| l.text().to_string()).collect();
    assert!(
        all.iter().any(|t| t.contains(&format!("{:0>64}", 5))),
        "the sha256: {all:?}"
    );
    assert!(all.iter().any(|t| t.contains("you said no <b>earlier</b>")), "{all:?}");
    assert!(all.iter().any(|t| t.contains("d3dcompiler")), "{all:?}");
    assert!(
        find(&root, "consent-check-mono").is_none(),
        "a denied entry cannot be accepted"
    );
    checks[0].set_active(true);
    assert_eq!(d.response_label("install"), "Install (1 of 2 accepted)");
    assert!(
        !sent.borrow().iter().any(|c| matches!(c, Cmd::DepsInstall { .. })),
        "nothing sent before Install"
    );
    d.emit_by_name::<()>("response", &[&"install"]);
    let deps: Vec<Cmd> = sent
        .borrow()
        .iter()
        .filter(|c| matches!(c, Cmd::DepsInstall { .. }))
        .cloned()
        .collect();
    let v = &canned_plan().entries[0];
    assert_eq!(
        deps,
        [Cmd::DepsInstall {
            id: "game".into(),
            digest: DIGEST.into(),
            consent: vec![rt_api::jobs::ConsentItem {
                package: v.package.clone(),
                version: v.version.clone().unwrap(),
                sha256: v.sha256.clone().unwrap(),
            }],
        }]
    );
    shot(ui.window(), "consent");
    close(ui);
}

fn read_only_disables_the_app_page_writes() {
    let (ui, _) = recorded();
    opened(&ui, false, canned_plan());
    for name in [
        "btn-run",
        "btn-remove",
        "btn-deps",
        "perm-network",
        "perm-display",
        "perm-audio",
        "perm-gpu",
        "perm-grant-ro",
        "perm-reset",
    ] {
        let w = get(&ui, name);
        assert!(!w.is_sensitive(), "{name}");
        assert_eq!(w.tooltip_text().as_deref(), Some(READ_ONLY), "{name}");
    }
    assert!(get(&ui, "btn-plan").is_sensitive(), "planning is a read");
    close(ui);
}

fn remove_asks_first_and_cancel_is_the_default() {
    let (ui, sent) = recorded();
    opened(&ui, true, canned_plan());
    click(&ui, "btn-remove");
    let d = dialog(&ui, "remove-dialog");
    assert_eq!(d.default_response().as_deref(), Some("cancel"));
    assert_eq!(d.close_response(), "cancel");
    assert!(!sent.borrow().iter().any(|c| matches!(c, Cmd::Remove(_))));
    d.emit_by_name::<()>("response", &[&"remove"]);
    assert!(sent.borrow().contains(&Cmd::Remove("game".into())));
    close(ui);
}

fn the_install_dialog_starts_with_everything_off() {
    let (ui, _) = recorded();
    opened(&ui, true, canned_plan());
    click(&ui, "btn-install");
    let d = dialog(&ui, "install-dialog");
    let root: gtk::Widget = d.clone().upcast();
    for name in ["install-silent", "install-network"] {
        let s = find(&root, name).unwrap().downcast::<adw::SwitchRow>().unwrap();
        assert!(!s.is_active(), "{name}");
    }
    assert!(!d.is_response_enabled("install"), "no file chosen yet");
    d.emit_by_name::<()>("response", &[&"cancel"]);
    close(ui);
}

/// A fake `runtime` whose run prints three lines, one with an ESC sequence.
const PRINTER: &str =
    "#!/bin/sh\n[ \"$1\" = --version ] && { echo \"runtime @V@\"; exit 0; }\nprintf 'one\\n\\033[31mtwo\\nthree\\n'\n";

fn a_followed_jobs_output_is_shown_in_order() {
    let script = PRINTER.replace("@V@", env!("CARGO_PKG_VERSION"));
    let s = Scratch::new(&runtimed(), Err(&script));
    s.plant("game", "Game");
    let _d = s.daemon(&[]);
    let ui = gui(&s);
    let list = get(&ui, "apps-list");
    iterate_until(WAIT, "the app list", || rows(&list).len() == 1);
    list.downcast_ref::<gtk::ListBox>()
        .unwrap()
        .row_at_index(0)
        .unwrap()
        .emit_activate();
    let run = get(&ui, "btn-run");
    iterate_until(WAIT, "Run", || get(&ui, "btn-run").is_sensitive());
    drop(run);
    click(&ui, "btn-run");
    let log = get(&ui, "job-log").downcast::<gtk::TextView>().unwrap();
    let text = || {
        let b = log.buffer();
        b.text(&b.start_iter(), &b.end_iter(), false).to_string()
    };
    iterate_until(WAIT, "the job's output", || text().contains("[succeeded"));
    let t = text();
    let at = |l: &str| t.find(l).unwrap_or_else(|| panic!("{l:?} not in {t:?}"));
    assert!(at("one") < at("[31mtwo") && at("[31mtwo") < at("three"), "{t:?}");
    assert!(!t.contains('\u{1b}'), "{t:?}");
    assert!(
        get(&ui, "jobs-panel")
            .downcast::<gtk::Revealer>()
            .unwrap()
            .reveals_child()
    );
    shot(ui.window(), "job-log");
    close(ui);
}

// ------------------------------------------------------------------------------------------------ review fixes

fn checks_of(d: &adw::AlertDialog) -> Vec<gtk::CheckButton> {
    let root: gtk::Widget = d.clone().upcast();
    ["vcrun", "dx"]
        .iter()
        .map(|p| find(&root, &format!("consent-check-{p}")).unwrap().downcast().unwrap())
        .collect()
}

fn deps_sent(sent: &RefCell<Vec<Cmd>>) -> Vec<Cmd> {
    sent.borrow()
        .iter()
        .filter(|c| matches!(c, Cmd::DepsInstall { .. }))
        .cloned()
        .collect()
}

fn a_cancelled_consent_is_forgotten() {
    let (ui, sent) = recorded();
    opened(&ui, true, canned_plan());
    // Tick, then Cancel.
    click(&ui, "btn-deps");
    let d = dialog(&ui, "consent-dialog");
    checks_of(&d)[0].set_active(true);
    assert_eq!(d.response_label("install"), "Install (1 of 2 accepted)");
    d.emit_by_name::<()>("response", &[&"cancel"]);
    assert_eq!(ui.model().consent().unwrap().accepted_count(), 0);
    d.force_close();
    iterate_until(WAIT, "the dialog to go", || {
        find(ui.window().upcast_ref(), "consent-dialog").is_none()
    });
    // Reopen: the box is unticked, the label says so, and Install sends no consent.
    click(&ui, "btn-deps");
    let d = dialog(&ui, "consent-dialog");
    assert!(checks_of(&d).iter().all(|c| !c.is_active()));
    assert_eq!(d.response_label("install"), "Install (0 of 2 accepted)");
    d.emit_by_name::<()>("response", &[&"install"]);
    match &deps_sent(&sent)[..] {
        [Cmd::DepsInstall { consent, digest, .. }] => {
            assert!(consent.is_empty(), "{consent:?}");
            assert_eq!(digest, DIGEST);
        }
        c => panic!("{c:?}"),
    }
    close(ui);
}

fn a_new_plan_closes_an_open_consent_dialog() {
    let (ui, sent) = recorded();
    opened(&ui, true, canned_plan());
    click(&ui, "btn-deps");
    let d = dialog(&ui, "consent-dialog");
    checks_of(&d)[0].set_active(true);
    // A second Plan answer arrives (same digest: the choices are new all the same).
    ui.dispatch(Msg::PlanLoaded {
        id: "game".into(),
        plan: canned_plan(),
    });
    iterate_until(WAIT, "the dialog to close", || {
        find(ui.window().upcast_ref(), "consent-dialog").is_none()
    });
    assert_eq!(ui.model().notice(), Some(rt_gui::vm::PLAN_REPLACED));
    assert_eq!(ui.model().consent().unwrap().accepted_count(), 0);
    // The stale dialog's Install does nothing.
    d.emit_by_name::<()>("response", &[&"install"]);
    assert!(deps_sent(&sent).is_empty());
    close(ui);
}

/// The log view is exactly the model's log after large, trimmed batches (append-only drawing).
fn the_log_view_follows_the_model_through_trimming() {
    use rt_api::jobs::{EventKind, JobEvent, JobEvents, JobInfo, JobKind, JobState};
    let (ui, _) = recorded();
    opened(&ui, true, canned_plan());
    ui.dispatch(Msg::JobStarted {
        what: Cmd::Run("game".into()),
        job_id: "j1".into(),
    });
    let view = get(&ui, "job-log").downcast::<gtk::TextView>().unwrap();
    let mut seq = 1;
    let batch = |seq: &mut u64, n: usize, width: usize| {
        let events = (0..n)
            .map(|i| {
                *seq += 1;
                JobEvent {
                    seq: *seq,
                    ts: 0,
                    kind: EventKind::Stdout,
                    text: format!("{} {}", *seq, "y".repeat(width + i % 7)),
                }
            })
            .collect();
        JobEvents {
            events,
            next_seq: *seq,
            dropped: 0,
            job: JobInfo {
                job_id: "j1".into(),
                kind: JobKind::Run,
                app: Some("game".into()),
                state: JobState::Running,
                exit_code: None,
                signal: None,
                created_at: 0,
                started_at: None,
                ended_at: None,
                dropped: 0,
            },
        }
    };
    for (n, width) in [(10, 5), (2100, 5), (2100, 5), (2100, 5), (300, 4000), (3, 5)] {
        ui.dispatch(Msg::JobEvents(batch(&mut seq, n, width)));
        let b = view.buffer();
        let shown = b.text(&b.start_iter(), &b.end_iter(), false).to_string();
        let m = ui.model();
        let log = m.log("j1").unwrap();
        let mut want = log.lines().collect::<Vec<_>>().join("\n");
        want.push('\n');
        assert!(
            shown == want,
            "after {n}x{width}: {} vs {} lines",
            shown.lines().count(),
            log.len()
        );
        assert!(log.bytes() <= rt_gui::vm::LOG_BYTES);
    }
    close(ui);
}

fn the_remove_dialog_and_about_show_daemon_text_literally() {
    let (ui, _) = recorded();
    ui.dispatch(Msg::Connected(VersionInfo {
        api: "0.2.0".into(),
        runtime: HOSTILE.into(),
        protocol: "jsonrpc-2.0-ndjson".into(),
        write: true,
    }));
    ui.dispatch(Msg::Apps(
        serde_json::from_value(
            serde_json::json!({"apps": [{"id": "evil", "name": HOSTILE, "version": null,
            "architecture": "x86_64", "executable": "e", "created": 0}], "skipped": 0}),
        )
        .unwrap(),
    ));
    ui.dispatch(Msg::Open("evil".into()));
    let mut data = app_data("evil");
    data.detail.name = HOSTILE.into();
    ui.dispatch(Msg::AppLoaded(Box::new(data)));
    click(&ui, "btn-remove");
    let d = dialog(&ui, "remove-dialog");
    let root: gtk::Widget = d.clone().upcast();
    let body: Vec<gtk::Label> = labels(&root)
        .into_iter()
        .filter(|l| l.label().contains(HOSTILE))
        .collect();
    assert_eq!(body.len(), 1, "the body names the app");
    assert_eq!(body[0].text(), body[0].label(), "parsed as markup");
    d.emit_by_name::<()>("response", &[&"cancel"]);
    d.force_close();
    // About: its comments are markup, so the daemon's text is escaped there.
    WidgetExt::activate_action(ui.window(), "win.about", None).unwrap();
    let mut about = None;
    iterate_until(WAIT, "About", || {
        about = find(ui.window().upcast_ref(), "about-dialog");
        about.is_some()
    });
    let about = about.unwrap().downcast::<adw::AboutDialog>().unwrap();
    let escaped = glib::markup_escape_text(HOSTILE).to_string();
    assert!(about.comments().contains(&escaped), "{}", about.comments());
    assert!(!about.comments().contains(HOSTILE));
    about.force_close();
    close(ui);
}

/// A fake `runtime` whose run prints 20 bursts, apart: well over the 8 job-output messages that may be in flight.
const BURSTS: &str = "#!/bin/sh\n[ \"$1\" = --version ] && { echo \"runtime @V@\"; exit 0; }\nfor i in $(seq 1 20); do echo \"burst $i\"; sleep 0.05; done\n";

/// The credits between the followers and the UI are handed back: a job with more poll answers than may be in flight
/// still runs to its end (without the release the follower would wait for good after 8).
fn a_long_chatty_job_runs_to_its_end() {
    let script = BURSTS.replace("@V@", env!("CARGO_PKG_VERSION"));
    let s = Scratch::new(&runtimed(), Err(&script));
    s.plant("game", "Game");
    let _d = s.daemon(&[]);
    let ui = gui(&s);
    let list = get(&ui, "apps-list");
    iterate_until(WAIT, "the app list", || rows(&list).len() == 1);
    list.downcast_ref::<gtk::ListBox>()
        .unwrap()
        .row_at_index(0)
        .unwrap()
        .emit_activate();
    iterate_until(WAIT, "Run", || get(&ui, "btn-run").is_sensitive());
    click(&ui, "btn-run");
    iterate_until(WAIT, "the job's end", || {
        let m = ui.model();
        m.logs()
            .next()
            .and_then(|(_, l)| l.job())
            .is_some_and(|j| rt_gui::vm::is_final(j.state))
    });
    let m = ui.model();
    let (_, log) = m.logs().next().unwrap();
    let lines: Vec<&str> = log.lines().collect();
    let bursts = lines.iter().filter(|l| l.starts_with("burst ")).count();
    assert_eq!(bursts, 20, "{lines:?}");
    drop(m);
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
        // The software renderer: the same drawing path with or without GL (Xvfb has none).
        if std::env::var_os("GSK_RENDERER").is_none() {
            std::env::set_var("GSK_RENDERER", "cairo");
        }
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
        (
            "the_consent_dialog_shows_every_term_and_sends_only_what_was_accepted",
            the_consent_dialog_shows_every_term_and_sends_only_what_was_accepted,
        ),
        (
            "read_only_disables_the_app_page_writes",
            read_only_disables_the_app_page_writes,
        ),
        (
            "remove_asks_first_and_cancel_is_the_default",
            remove_asks_first_and_cancel_is_the_default,
        ),
        (
            "the_install_dialog_starts_with_everything_off",
            the_install_dialog_starts_with_everything_off,
        ),
        (
            "a_followed_jobs_output_is_shown_in_order",
            a_followed_jobs_output_is_shown_in_order,
        ),
        ("a_cancelled_consent_is_forgotten", a_cancelled_consent_is_forgotten),
        ("a_long_chatty_job_runs_to_its_end", a_long_chatty_job_runs_to_its_end),
        (
            "a_new_plan_closes_an_open_consent_dialog",
            a_new_plan_closes_an_open_consent_dialog,
        ),
        (
            "the_log_view_follows_the_model_through_trimming",
            the_log_view_follows_the_model_through_trimming,
        ),
        (
            "the_remove_dialog_and_about_show_daemon_text_literally",
            the_remove_dialog_and_about_show_daemon_text_literally,
        ),
    ];
    for (name, t) in tests {
        eprintln!("test {name} ...");
        t();
        eprintln!("test {name} ... ok");
    }
    eprintln!("widget tests: {} passed", tests.len());
}
