//! The view model and the backend together against the real `runtimed` (spec 6, backend e2e), no display: the
//! sink feeds a channel, each `Msg` goes to `Model::update` and each `Cmd` it returns to `Backend::send`, as the GTK
//! bridge does. The daemon runs from the shared rig (`crates/daemon/tests/support`): a scratch HOME, data dir and
//! `XDG_RUNTIME_DIR`, never the user's; every scenario has a deadline.
#[path = "../../daemon/tests/support/mod.rs"]
mod support;

use rt_api::jobs::JobState;
use rt_gui::backend::Backend;
use rt_gui::vm::{Action, Cmd, Conn, InstallForm, LogBuffer, Model, Msg, PermChange, is_final};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use support::{Scratch, fake_runtime, fixture, refs};

/// The `runtimed` built next to this test binary (`target/<profile>/deps/e2e-*` -> `target/<profile>/runtimed`).
fn runtimed() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let p = exe.parent().unwrap().parent().unwrap().join("runtimed");
    assert!(
        p.is_file() && p.with_file_name("runtime").is_file(),
        "{} or its `runtime` is missing: run `cargo build -p runtime-daemon -p runtime-cli`",
        p.display()
    );
    p
}

/// A model and a backend wired as the GUI wires them.
struct Gui {
    model: Model,
    backend: Backend,
    rx: mpsc::Receiver<Msg>,
    sent: Vec<Cmd>,
    seen: Vec<String>,
    /// The job the last `JobStarted` named.
    job: Option<String>,
    until: Instant,
}

impl Gui {
    fn new(socket: PathBuf) -> Gui {
        let (tx, rx) = mpsc::channel();
        let backend = Backend::spawn(
            socket,
            Arc::new(move |m| {
                let _ = tx.send(m);
            }),
        );
        Gui {
            model: Model::new(),
            backend,
            rx,
            sent: vec![],
            seen: vec![],
            job: None,
            until: Instant::now() + Duration::from_secs(20),
        }
    }

    fn user(&mut self, msg: Msg) {
        let cmds = self.model.update(msg);
        self.send(cmds);
    }

    fn send(&mut self, cmds: Vec<Cmd>) {
        for c in cmds {
            if is_write(&c) && !matches!(c, Cmd::Cancel(_)) {
                // The job it starts is the one to wait for next.
                self.job = None;
            }
            self.sent.push(c.clone());
            self.backend.send(c);
        }
    }

    /// Feeds the backend's messages to the model until `done(msg, model)` holds after one of them.
    /// (`done` is first asked with no message: the model may already be there.)
    fn until(&mut self, what: &str, mut done: impl FnMut(&str, &Model) -> bool) {
        if done("", &self.model) {
            return;
        }
        loop {
            let left = self.until.saturating_duration_since(Instant::now());
            let Ok(msg) = self.rx.recv_timeout(left) else {
                panic!("timed out waiting for {what}; messages: {:#?}", self.seen);
            };
            if let Msg::JobStarted { job_id, .. } = &msg {
                self.job = Some(job_id.clone());
            }
            let text: String = format!("{msg:?}").chars().take(300).collect();
            self.seen.push(text.clone());
            let cmds = self.model.update(msg);
            self.send(cmds);
            if done(&text, &self.model) {
                return;
            }
        }
    }

    fn ready(&mut self) -> bool {
        self.until("the connection", |_, m| !matches!(m.conn(), Conn::Connecting));
        match self.model.conn() {
            Conn::Ready { write, .. } => *write,
            c => panic!("{c:?}"),
        }
    }

    /// Opens app `id` and waits for its page.
    fn open(&mut self, id: &str) {
        self.until("the apps", |_, m| m.visible_apps().iter().any(|a| a.id == id));
        self.user(Msg::Open(id.into()));
        self.until("the app page", |_, m| m.page().is_some_and(|p| p.data().is_some()));
    }

    /// Waits for the last started job to end: its final state and log.
    fn job_ends(&mut self, what: &str) -> (JobState, Vec<String>) {
        fn log(g: &Gui) -> Option<&LogBuffer> {
            g.model.log(g.job.as_ref()?)
        }
        while !log(self).and_then(LogBuffer::job).is_some_and(|j| is_final(j.state)) {
            self.until(what, |text, _| !text.is_empty());
        }
        let log = log(self).unwrap();
        (log.job().unwrap().state, log.lines().map(str::to_owned).collect())
    }
}

fn is_write(c: &Cmd) -> bool {
    !matches!(
        c,
        Cmd::Connect | Cmd::ListApps | Cmd::LoadApp(_) | Cmd::Plan(_) | Cmd::ListJobs | Cmd::Follow(_)
    )
}

#[test]
fn no_daemon_shows_unreachable() {
    let s = Scratch::new(&runtimed(), Err(&fake_runtime()));
    let mut g = Gui::new(s.sock());
    g.until("the connect", |_, m| !matches!(m.conn(), Conn::Connecting));
    let unreachable = Conn::Unreachable {
        socket: s.sock().display().to_string(),
    };
    assert_eq!(*g.model.conn(), unreachable);
    g.user(Msg::Retry);
    g.until("the retry", |text, _| text.starts_with("ConnectFailed"));
    assert_eq!(*g.model.conn(), unreachable);
}

#[test]
fn a_read_only_daemon_gets_no_write_command() {
    let s = Scratch::new(&runtimed(), Err(&fake_runtime()));
    s.plant("game", "Game");
    let _d = s.start(false, &[]);
    let mut g = Gui::new(s.sock());
    assert!(!g.ready());
    g.open("game");
    for msg in [
        Msg::Run,
        Msg::Stop,
        Msg::Remove,
        Msg::Install(InstallForm {
            path: "/in/setup.exe".into(),
            ..Default::default()
        }),
        Msg::Install(InstallForm {
            path: "/in/app.wrun".into(),
            ..Default::default()
        }),
        Msg::Permission(PermChange::Network(true)),
        Msg::ResetPermissions,
        Msg::InstallDeps,
        Msg::Cancel("j".into()),
    ] {
        g.user(msg);
    }
    // Reading still works.
    g.user(Msg::Plan);
    g.until("the plan", |_, m| m.consent().is_some());
    assert!(g.sent.iter().all(|c| !is_write(c)), "{:?}", g.sent);
    assert!(
        std::fs::read_dir(s.data.join("fake")).unwrap().next().is_none(),
        "a runtime ran"
    );
}

#[test]
fn write_jobs_are_followed_cancelled_and_survive_a_daemon_restart() {
    let s = Scratch::new(&runtimed(), Err(&fake_runtime()));
    s.plant("game", "Game");
    let d = s.daemon(&[]);
    let mut g = Gui::new(s.sock());
    assert!(g.ready());
    g.open("game");

    // Remove: the exact argv, its output through the sink in order, then a reload.
    g.user(Msg::Remove);
    let (state, lines) = g.job_ends("the remove job");
    assert_eq!(state, JobState::Succeeded, "{lines:?}");
    assert_eq!(s.fake("argv", "game"), "remove\0--\0game\0");
    let pos = |l: &str| {
        lines
            .iter()
            .position(|x| x == l)
            .unwrap_or_else(|| panic!("{l} not in {lines:?}"))
    };
    assert!(
        pos("[queued]") < pos("[running]")
            && pos("[running]") < pos("done")
            && pos("done") < pos("[succeeded (exit 0)]")
    );
    g.until("the reload", |text, _| text.starts_with("AppLoaded"));

    // Run a job that waits, Stop it through the job list: cancelled.
    s.mode("--", "wait");
    g.user(Msg::Run);
    g.until("Stop to be possible", |_, m| m.can(Action::Stop).is_ok());
    g.user(Msg::Stop);
    let (state, lines) = g.job_ends("the cancelled run");
    assert_eq!(state, JobState::Cancelled, "{lines:?}");

    // A job still running when the daemon restarts: its follower reconnects and ends on not_found.
    s.mode("--", "wait");
    g.user(Msg::Run);
    g.until("the run to be ready", |text, _| text.contains("\"ready\""));
    drop(d);
    let _d = s.daemon(&[]);
    g.until("the follower's end", |text, _| {
        text.starts_with("Failed { what: Follow")
    });
    assert!(
        g.model.notice().unwrap().contains("no longer exists"),
        "{:?}",
        g.model.notice()
    );
}

#[test]
fn the_real_runtime_installs_edits_plans_and_removes() {
    let (s, env) = support::real(&runtimed());
    let _d = s.daemon(&refs(&env));
    let mut g = Gui::new(s.sock());
    assert!(g.ready());
    let exe = s.root.join("hello64.exe");
    std::fs::copy(fixture("hello64.exe"), &exe).unwrap();

    // Install from the form; the app appears once the job ended.
    g.user(Msg::Install(InstallForm {
        path: exe,
        name: "Hello".into(),
        ..Default::default()
    }));
    let (state, lines) = g.job_ends("the install");
    assert_eq!(state, JobState::Succeeded, "{lines:?}");
    let id = lines
        .iter()
        .find_map(|l| l.strip_prefix("Installed: "))
        .unwrap()
        .to_owned();
    g.open(&id);

    // Permissions round trip.
    g.user(Msg::Permission(PermChange::Network(true)));
    let (state, lines) = g.job_ends("the permission change");
    assert_eq!(state, JobState::Succeeded, "{lines:?}");
    g.until("the reloaded permissions", |_, m| {
        m.page()
            .and_then(|p| p.data())
            .and_then(|d| d.permissions.as_ref().ok())
            .is_some_and(|p| p.network == rt_api::NetworkView::Allow)
    });

    // The (empty) plan installs; a tampered digest is refused and planned again, nothing re-sent.
    g.user(Msg::Plan);
    g.until("the plan", |_, m| m.consent().is_some());
    assert!(g.model.consent().unwrap().nothing_to_install());
    g.user(Msg::ConsentOpened);
    g.user(Msg::InstallDeps);
    let (state, lines) = g.job_ends("the deps install");
    assert_eq!(state, JobState::Succeeded, "{lines:?}");
    assert!(lines.iter().any(|l| l == "Nothing to install."), "{lines:?}");
    let tampered = Cmd::DepsInstall {
        id: id.clone(),
        digest: "0".repeat(64),
        consent: vec![],
    };
    g.send(vec![tampered]);
    g.until("the refusal", |text, _| text.starts_with("Failed { what: DepsInstall"));
    assert_eq!(g.model.notice(), Some(rt_gui::vm::PLAN_CHANGED));
    assert_eq!(g.sent.last(), Some(&Cmd::Plan(id.clone())), "a new plan, not a resend");
    g.until("the new plan", |_, m| m.consent().is_some());

    // Remove: the app is gone and its page closed.
    g.user(Msg::Remove);
    let (state, lines) = g.job_ends("the remove");
    assert_eq!(state, JobState::Succeeded, "{lines:?}");
    g.until("the page to close", |_, m| m.page().is_none());
    g.until("the empty list", |_, m| m.visible_apps().is_empty());
}

/// Phase 6D: a `.wrun` chosen in the install form is imported through `apps.import` by the real `runtime` (fake
/// Wine): the app has the manifest's id and its page shows the request, not granted.
#[test]
fn the_install_form_imports_a_package() {
    let (s, env) = support::real(&runtimed());
    let pkg = s.root.join("pkg");
    std::fs::create_dir_all(pkg.join("payload")).unwrap();
    std::fs::copy(fixture("hello64.exe"), pkg.join("payload/hello64.exe")).unwrap();
    std::fs::write(
        pkg.join("wrun.toml"),
        "format = 1\nid = \"demo\"\nname = \"Demo\"\nversion = \"1.0\"\narch = \"x86_64\"\n\n[entry]\n\
         kind = \"portable\"\nexe = \"payload/hello64.exe\"\n\n[permissions]\ngpu = \"off\"\n",
    )
    .unwrap();
    let file = s.root.join("demo.wrun");
    let o = std::process::Command::new(s.bin.join("runtime"))
        .env("RUNTIME_DATA_DIR", &s.data)
        .env("HOME", &s.home)
        .arg("pack")
        .arg(&pkg)
        .arg("-o")
        .arg(&file)
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    let _d = s.daemon(&refs(&env));
    let mut g = Gui::new(s.sock());
    assert!(g.ready());
    g.user(Msg::Install(InstallForm {
        path: file.clone(),
        name: "Not used".into(),
        ..Default::default()
    }));
    assert!(
        matches!(g.sent.last(), Some(Cmd::Import(p)) if p.path == file.to_str().unwrap()),
        "{:?}",
        g.sent
    );
    let (state, lines) = g.job_ends("the import");
    assert_eq!(state, JobState::Succeeded, "{lines:?}");
    assert!(lines.iter().any(|l| l == "Installed: demo"), "{lines:?}");
    g.open("demo");
    let requested = g.model.page_permissions().unwrap().unwrap().requested;
    assert_eq!(
        requested.as_deref(),
        Some("Requested by the package (not granted): gpu=off")
    );
    assert_eq!(g.model.page().unwrap().title(), "Demo");
}
