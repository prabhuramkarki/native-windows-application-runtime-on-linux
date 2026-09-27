//! The view model (spec 5.1): every decision of the GUI, without a toolkit. [`Model::update`] is the only place state
//! changes; it takes a [`Msg`] (a user intent or a backend result) and returns the [`Cmd`]s the backend runs. Widgets
//! read display-ready values (every daemon string passed through [`shown`]) and [`Model::can`] flags; they decide
//! nothing. Pure data: no I/O, no threads, no clock.
mod consent;
mod forms;
mod page;

pub use consent::{ConsentChoice, ConsentState, EntryRow};
pub use forms::{InstallForm, PermChange, is_package};
pub use page::{GrantRow, Line, PermRows};

use rt_api::jobs::{ConsentItem, EventKind, JobEvents, JobInfo, JobKind, JobState};
use rt_api::{
    AppDetail, AppList, DepsPlanView, DoctorView, ErrorKind, GraphicsView, PermissionsView, SandboxView, VersionInfo,
};
use rt_daemon::client::{ClientError, ImportParams, InstallParams};
use std::collections::VecDeque;
use std::path::PathBuf;

/// The command that starts the user's `runtimed` socket unit (shown, never run: spec D6).
pub const START_HINT: &str = "systemctl --user start runtimed.socket";
/// Why every write control is off on a read-only daemon (spec D7).
pub const READ_ONLY: &str = "This runtimed is read-only (started without `--write`). The shipped unit passes `--write`; \
                             see docs/API.md, Running it under systemd.";
/// The notice when a new plan replaced the one an open consent dialog showed.
pub const PLAN_REPLACED: &str = "The dependency plan changed while it was shown. Review it again.";
/// The notice after `consent_mismatch` (spec 5.3).
pub const PLAN_CHANGED: &str = "The dependency plan changed since it was shown. Review it again.";
/// Why a `.wrun` is not sent to a daemon older than API 0.2.1 (it has no `apps.import`).
pub const NO_IMPORT: &str = "This runtimed cannot import .wrun packages (it needs API 0.2.1); update the runtime.";
/// Most lines kept per job log (spec D11).
pub const LOG_MAX: usize = 5000;
/// Most followed job logs kept (the oldest ended one goes first).
pub const MAX_LOGS: usize = 16;
/// Most bytes kept per job log (the daemon itself keeps 512 KiB per job).
pub const LOG_BYTES: usize = 1 << 20;
/// The first line of a log that lost its oldest lines.
pub const EARLIER_DROPPED: &str = "[earlier lines dropped]";
/// Longest message shown (errors, notices, reasons), in characters.
pub const MAX_SHOWN: usize = 1024;
/// Longest name, id or version shown.
pub const TEXT_MAX: usize = 256;
/// Longest log line shown (the daemon's own bound).
const LINE_MAX: usize = 4096;
/// Why nothing can be done before the daemon answered.
const NOT_CONNECTED: &str = "not connected to runtimed";

/// A daemon string made safe to display: control and format characters (bidi, zero-width) removed, at most `max`.
pub fn shown(s: &str, max: usize) -> String {
    rt_core::clean_text(s, max)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conn {
    Connecting,
    /// No daemon at `socket` (or no runtime directory): the "start it" page with [`START_HINT`].
    Unreachable {
        socket: String,
    },
    /// The client refused the socket (wrong owner or mode): the reason.
    Refused(String),
    Ready {
        write: bool,
        api: String,
        runtime: String,
    },
}

/// A failed connect: the socket tried and why.
#[derive(Debug)]
pub struct ConnError {
    pub socket: PathBuf,
    pub error: ClientError,
}

/// What `apps.get` and the per-app probes answered; each probe may fail on its own.
#[derive(Debug)]
pub struct AppData {
    pub detail: AppDetail,
    pub permissions: Result<PermissionsView, ClientError>,
    pub doctor: Result<DoctorView, ClientError>,
    pub graphics: Result<GraphicsView, ClientError>,
    pub sandbox: Result<SandboxView, ClientError>,
}

#[derive(Debug)]
pub enum Msg {
    // User intents.
    Search(String),
    Open(String),
    Run,
    Stop,
    /// After the confirmation dialog.
    Remove,
    Plan,
    Accept(String, bool),
    InstallDeps,
    Install(InstallForm),
    Permission(PermChange),
    ResetPermissions,
    Cancel(String),
    Retry,
    Refresh,
    /// The notice was closed.
    Dismiss,
    /// The consent dialog was opened (every choice starts unaccepted).
    ConsentOpened,
    /// It closed without Install (every choice is reset).
    ConsentClosed,
    /// The UI refused something locally (a file with no local path): the reason, as the notice.
    Refused(&'static str),
    // Backend results.
    Connected(VersionInfo),
    ConnectFailed(ConnError),
    Apps(AppList),
    AppLoaded(Box<AppData>),
    PlanLoaded {
        id: String,
        plan: DepsPlanView,
    },
    JobStarted {
        what: Cmd,
        job_id: String,
    },
    JobEvents(JobEvents),
    JobList(Vec<JobInfo>),
    Failed {
        what: Cmd,
        error: ClientError,
    },
}

/// What the backend runs: one client helper each, plus following a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    Connect,
    ListApps,
    LoadApp(String),
    Plan(String),
    Run(String),
    Cancel(String),
    Remove(String),
    Install(InstallParams),
    /// A `.wrun` package (`apps.import`).
    Import(ImportParams),
    DepsInstall {
        id: String,
        digest: String,
        consent: Vec<ConsentItem>,
    },
    PermSet {
        id: String,
        set: Vec<String>,
    },
    PermReset(String),
    ListJobs,
    Follow(String),
}

/// What a control does, for [`Model::can`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Install,
    Run,
    Stop,
    Remove,
    Plan,
    InstallDeps,
    EditPermissions,
    Cancel,
}

/// One sidebar row (cleaned); `id` is the daemon's own, sent back on open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRow {
    pub id: String,
    pub title: String,
    pub subtitle: String,
}

/// The open app: its id and, once loaded, what the daemon said about it.
#[derive(Debug)]
pub struct AppPage {
    id: String,
    data: Option<AppData>,
}

impl AppPage {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn data(&self) -> Option<&AppData> {
        self.data.as_ref()
    }
    /// The app's name, cleaned (its id until loaded).
    pub fn title(&self) -> String {
        shown(self.data.as_ref().map_or(&self.id, |d| &d.detail.name), TEXT_MAX)
    }
}

/// A followed job's output: at most [`LOG_MAX`] lines and [`LOG_BYTES`] bytes, oldest dropped first behind one
/// [`EARLIER_DROPPED`] line.
#[derive(Debug, Default)]
pub struct LogBuffer {
    lines: VecDeque<String>,
    cut: bool,
    added: u64,
    bytes: usize,
    job: Option<JobInfo>,
}

impl LogBuffer {
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.cut
            .then_some(EARLIER_DROPPED)
            .into_iter()
            .chain(self.lines.iter().map(String::as_str))
    }
    pub fn job(&self) -> Option<&JobInfo> {
        self.job.as_ref()
    }
    /// Grows with every line added: the UI redraws a log only when it changed.
    pub fn version(&self) -> u64 {
        self.added
    }
    /// The lines [`LogBuffer::lines`] yields (the note included).
    pub fn len(&self) -> usize {
        self.lines.len() + usize::from(self.cut)
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Older lines were dropped (the first line is [`EARLIER_DROPPED`]).
    pub fn cut(&self) -> bool {
        self.cut
    }
    /// The kept lines (without the note).
    pub fn kept(&self) -> usize {
        self.lines.len()
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    /// The lines added after `version`, or `None` when some of them were dropped already (redraw everything).
    pub fn since(&self, version: u64) -> Option<impl Iterator<Item = &str>> {
        let new = usize::try_from(self.added.checked_sub(version)?).ok()?;
        (new <= self.lines.len()).then(|| self.lines.iter().skip(self.lines.len() - new).map(String::as_str))
    }
    fn push(&mut self, line: String) {
        self.bytes += line.len();
        self.lines.push_back(line);
        self.added += 1;
        while self.lines.len() > LOG_MAX || (self.bytes > LOG_BYTES && self.lines.len() > 1) {
            let old = self.lines.pop_front().expect("more than one line");
            self.bytes -= old.len();
            self.cut = true;
        }
    }

    /// Adds a poll's events; true when this poll ended the job (the first final state seen).
    fn add(&mut self, ev: JobEvents) -> bool {
        if ev.dropped > 0 {
            self.push(format!("[{} lines were dropped by the daemon]", ev.dropped));
        }
        for e in &ev.events {
            let text = shown(&e.text, LINE_MAX);
            self.push(match e.kind {
                EventKind::State => format!("[{text}]"),
                _ => text,
            });
        }
        let was_final = self.job.as_ref().is_some_and(|j| is_final(j.state));
        let ended = !was_final && is_final(ev.job.state);
        self.job = Some(ev.job);
        ended
    }
}

pub fn is_live(s: JobState) -> bool {
    matches!(s, JobState::Queued | JobState::Running)
}

/// A state no job leaves (a newer daemon's unknown state is not final: its follower keeps polling).
pub fn is_final(s: JobState) -> bool {
    matches!(s, JobState::Succeeded | JobState::Failed | JobState::Cancelled)
}

#[derive(Debug)]
pub struct Model {
    conn: Conn,
    apps: Option<AppList>,
    filter: String,
    page: Option<AppPage>,
    plan: Option<ConsentState>,
    jobs: Vec<JobInfo>,
    /// Followed jobs, oldest first.
    logs: Vec<(String, LogBuffer)>,
    notice: Option<String>,
    /// The consent dialog is open (only then can a choice be accepted or the plan installed).
    consent_open: bool,
    /// A write command was sent for this app and its job is not in the job list yet (`true`: it started).
    pending: Option<(String, bool)>,
}

impl Default for Model {
    fn default() -> Model {
        Model::new()
    }
}

impl Model {
    pub fn new() -> Model {
        Model {
            conn: Conn::Connecting,
            apps: None,
            filter: String::new(),
            page: None,
            plan: None,
            jobs: vec![],
            logs: vec![],
            notice: None,
            consent_open: false,
            pending: None,
        }
    }

    pub fn update(&mut self, msg: Msg) -> Vec<Cmd> {
        let cmds = self.step(msg);
        // A second click before the job shows up in the list must not send a second command.
        for id in cmds.iter().filter_map(write_target) {
            self.pending = Some((id.to_owned(), false));
        }
        cmds
    }

    fn step(&mut self, msg: Msg) -> Vec<Cmd> {
        match msg {
            Msg::Search(s) => {
                self.filter = s.trim().to_lowercase();
                vec![]
            }
            Msg::Open(id) => {
                if !matches!(self.conn, Conn::Ready { .. }) {
                    return vec![];
                }
                self.plan = None;
                self.consent_open = false;
                self.page = Some(AppPage {
                    id: id.clone(),
                    data: None,
                });
                let mut cmds = vec![Cmd::LoadApp(id)];
                cmds.extend(self.writable().then_some(Cmd::ListJobs));
                cmds
            }
            Msg::Run => self.gated(Action::Run, |m| Cmd::Run(m.page_id())),
            Msg::Stop => self.gated(Action::Stop, |m| {
                Cmd::Cancel(m.live_run().map(|j| j.job_id.clone()).unwrap_or_default())
            }),
            Msg::Remove => self.gated(Action::Remove, |m| Cmd::Remove(m.page_id())),
            Msg::Plan => self.gated(Action::Plan, |m| Cmd::Plan(m.page_id())),
            Msg::Accept(package, yes) => {
                // Only a box in the open dialog accepts anything.
                if let Some(p) = self.plan.as_mut().filter(|_| self.consent_open) {
                    p.accept(&package, yes);
                }
                vec![]
            }
            Msg::ConsentOpened | Msg::ConsentClosed => {
                if let Some(p) = &mut self.plan {
                    p.reset();
                }
                self.consent_open = matches!(msg, Msg::ConsentOpened) && self.plan.is_some();
                vec![]
            }
            Msg::Refused(why) => self.refuse(why),
            Msg::InstallDeps => {
                // Any answer closes the model's dialog; a refused one also forgets its choices.
                let was_open = std::mem::take(&mut self.consent_open);
                let refused = self
                    .can(Action::InstallDeps)
                    .err()
                    .or_else(|| (!was_open).then_some("review the plan in the Install dependencies dialog first"));
                if let Some(why) = refused {
                    if let Some(p) = &mut self.plan {
                        p.reset();
                    }
                    return self.refuse(why);
                }
                // The plan is dropped once sent: a second install needs a fresh plan.
                let (id, digest, consent) = self.plan.take().expect("can() checked the plan").into_install();
                vec![Cmd::DepsInstall { id, digest, consent }]
            }
            Msg::Install(form) => {
                let cmd = self.can(Action::Install).and_then(|()| {
                    if !forms::is_package(&form.path) {
                        forms::install_params(&form).map(Cmd::Install)
                    } else if self.imports() {
                        forms::import_params(&form).map(Cmd::Import)
                    } else {
                        Err(NO_IMPORT)
                    }
                });
                match cmd {
                    Ok(c) => vec![c],
                    Err(why) => self.refuse(why),
                }
            }
            Msg::Permission(change) => {
                let grants = self.permissions().map_or(&[][..], |p| &p.filesystem[..]);
                match self
                    .can(Action::EditPermissions)
                    .and_then(|()| forms::perm_expr(&change, grants))
                {
                    Ok(e) => vec![Cmd::PermSet {
                        id: self.page_id(),
                        set: vec![e],
                    }],
                    Err(why) => self.refuse(why),
                }
            }
            Msg::ResetPermissions => self.gated(Action::EditPermissions, |m| Cmd::PermReset(m.page_id())),
            Msg::Cancel(job) => self.gated(Action::Cancel, |_| Cmd::Cancel(job)),
            Msg::Retry => {
                self.conn = Conn::Connecting;
                vec![Cmd::Connect]
            }
            Msg::Refresh => self.reload(),
            Msg::Dismiss => {
                self.notice = None;
                vec![]
            }
            Msg::Connected(v) => {
                self.conn = Conn::Ready {
                    write: v.write && api_at_least(&v.api, [0, 2, 0]),
                    api: shown(&v.api, TEXT_MAX),
                    runtime: shown(&v.runtime, TEXT_MAX),
                };
                self.notice = None;
                self.reload()
            }
            Msg::ConnectFailed(ConnError { socket, error }) => {
                let socket = shown(&socket.to_string_lossy(), rt_api::PATH_MAX);
                self.pending = None;
                self.conn = match error {
                    ClientError::Unsafe { .. } => Conn::Refused(shown(&error.to_string(), MAX_SHOWN)),
                    ClientError::NoRuntimeDir | ClientError::Unreachable { .. } => Conn::Unreachable { socket },
                    // The connection broke (or the daemon cannot serve us): the same page, and why.
                    e => {
                        self.notice = Some(error_text(&e));
                        Conn::Unreachable { socket }
                    }
                };
                vec![]
            }
            Msg::Apps(list) => {
                self.apps = Some(list);
                vec![]
            }
            Msg::AppLoaded(data) => {
                if let Some(page) = self.page.as_mut().filter(|p| p.id == data.detail.id) {
                    page.data = Some(*data);
                }
                vec![]
            }
            Msg::PlanLoaded { id, plan } => {
                if self.page.as_ref().is_some_and(|p| p.id == id) {
                    // A dialog showing the old plan closes: it must not act on one it does not show.
                    if self.consent_open {
                        self.consent_open = false;
                        self.notice = Some(PLAN_REPLACED.to_owned());
                    }
                    self.plan = Some(ConsentState::new(id, plan));
                }
                vec![]
            }
            Msg::JobStarted { what, job_id } => {
                // Only the pending app's own job counts (not an unrelated install's).
                if let Some((app, started)) = &mut self.pending
                    && write_target(&what) == Some(app.as_str())
                {
                    *started = true;
                }
                self.logs.push((job_id.clone(), LogBuffer::default()));
                if self.logs.len() > MAX_LOGS {
                    let ended = |(_, l): &(String, LogBuffer)| l.job.as_ref().is_some_and(|j| is_final(j.state));
                    let oldest = self.logs.iter().position(ended).unwrap_or(0);
                    self.logs.remove(oldest);
                }
                vec![Cmd::Follow(job_id), Cmd::ListJobs]
            }
            Msg::JobEvents(ev) => {
                if self
                    .pending
                    .as_ref()
                    .is_some_and(|p| p.1 && ev.job.app.as_ref() == Some(&p.0))
                {
                    self.pending = None;
                }
                let info = ev.job.clone();
                match self.jobs.iter_mut().find(|j| j.job_id == info.job_id) {
                    Some(j) => *j = info,
                    None => self.jobs.push(info),
                }
                let ended = match self.logs.iter_mut().find(|(id, _)| *id == ev.job.job_id) {
                    Some((_, log)) => log.add(ev),
                    None => false,
                };
                if ended { self.reload() } else { vec![] }
            }
            Msg::JobList(jobs) => {
                if self.pending.as_ref().is_some_and(|p| p.1) {
                    self.pending = None;
                }
                self.jobs = jobs;
                vec![]
            }
            Msg::Failed { what, error } => {
                let kind = error.api_error().map(|e| e.kind);
                if write_target(&what).is_some() {
                    self.pending = None;
                }
                match what {
                    Cmd::DepsInstall { id, .. } if kind == Some(ErrorKind::ConsentMismatch) => {
                        self.notice = Some(PLAN_CHANGED.to_owned());
                        // A fresh plan to review; nothing is re-sent.
                        vec![Cmd::Plan(id)]
                    }
                    // The open app is gone (removed): close its page.
                    Cmd::LoadApp(id)
                        if kind == Some(ErrorKind::NotFound) && self.page.as_ref().is_some_and(|p| p.id == id) =>
                    {
                        self.page = None;
                        self.plan = None;
                        self.consent_open = false;
                        vec![]
                    }
                    what => {
                        self.notice = Some(shown(&format!("{}: {}", label(&what), error_text(&error)), MAX_SHOWN));
                        vec![]
                    }
                }
            }
        }
    }

    /// `cmd` when `action` is possible, else the reason as the notice and nothing.
    fn gated(&mut self, action: Action, cmd: impl FnOnce(&Model) -> Cmd) -> Vec<Cmd> {
        match self.can(action) {
            Ok(()) => vec![cmd(self)],
            Err(why) => self.refuse(why),
        }
    }

    fn refuse(&mut self, why: &str) -> Vec<Cmd> {
        self.notice = Some(why.to_owned());
        vec![]
    }

    /// What to load after connecting, a followed job's end, or Refresh (spec D12: no timer).
    fn reload(&self) -> Vec<Cmd> {
        if !matches!(self.conn, Conn::Ready { .. }) {
            return vec![];
        }
        let mut cmds = vec![Cmd::ListApps];
        cmds.extend(self.writable().then_some(Cmd::ListJobs));
        cmds.extend(self.page.as_ref().map(|p| Cmd::LoadApp(p.id.clone())));
        cmds
    }

    fn writable(&self) -> bool {
        matches!(self.conn, Conn::Ready { write: true, .. })
    }

    /// The daemon has `apps.import` (API 0.2.1).
    fn imports(&self) -> bool {
        matches!(&self.conn, Conn::Ready { api, .. } if api_at_least(api, [0, 2, 1]))
    }

    fn page_id(&self) -> String {
        self.page.as_ref().map(|p| p.id.clone()).unwrap_or_default()
    }

    fn permissions(&self) -> Option<&PermissionsView> {
        self.page.as_ref()?.data.as_ref()?.permissions.as_ref().ok()
    }

    /// The open app's live `run` job (spec D8).
    fn live_run(&self) -> Option<&JobInfo> {
        let id = &self.page.as_ref()?.id;
        self.jobs
            .iter()
            .find(|j| j.kind == JobKind::Run && j.app.as_ref() == Some(id) && is_live(j.state))
    }

    fn app_busy(&self) -> bool {
        let id = self.page.as_ref().map(|p| &p.id);
        self.pending.as_ref().is_some_and(|p| Some(&p.0) == id)
            || self.jobs.iter().any(|j| j.app.as_ref() == id && is_live(j.state))
    }

    /// The consent dialog is open (the UI closes one the model no longer considers open).
    pub fn consent_open(&self) -> bool {
        self.consent_open
    }

    pub fn conn(&self) -> &Conn {
        &self.conn
    }
    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }
    pub fn page(&self) -> Option<&AppPage> {
        self.page.as_ref()
    }
    pub fn jobs(&self) -> &[JobInfo] {
        &self.jobs
    }

    /// The apps matching the search (case-insensitive over name and id), cleaned.
    pub fn visible_apps(&self) -> Vec<AppRow> {
        let Some(list) = &self.apps else { return vec![] };
        list.apps
            .iter()
            .map(|a| AppRow {
                id: a.id.clone(),
                title: shown(&a.name, TEXT_MAX),
                subtitle: match &a.version {
                    Some(v) => format!("{} · {}", shown(&a.id, TEXT_MAX), shown(v, TEXT_MAX)),
                    None => shown(&a.id, TEXT_MAX),
                },
            })
            .filter(|r| {
                self.filter.is_empty()
                    || r.title.to_lowercase().contains(&self.filter)
                    || shown(&r.id, TEXT_MAX).to_lowercase().contains(&self.filter)
            })
            .collect()
    }

    /// "N app entries could not be read", when the daemon skipped some.
    pub fn apps_note(&self) -> Option<String> {
        let n = self.apps.as_ref()?.skipped;
        (n > 0).then(|| format!("{n} app entries could not be read"))
    }

    /// Whether `action` is possible now; `Err` is the reason, shown as the control's tooltip.
    pub fn can(&self, action: Action) -> Result<(), &'static str> {
        let Conn::Ready { write, .. } = self.conn else {
            return Err(NOT_CONNECTED);
        };
        if !write && action != Action::Plan {
            return Err(READ_ONLY);
        }
        let needs_page = !matches!(action, Action::Install | Action::Cancel);
        if needs_page && self.page.is_none() {
            return Err("no app is open");
        }
        match action {
            Action::Install | Action::Cancel | Action::Plan => Ok(()),
            Action::Stop => self
                .live_run()
                .map(|_| ())
                .ok_or("the app is not running as a job of runtimed"),
            Action::InstallDeps => match &self.plan {
                None => Err("plan the dependencies first"),
                Some(p) if p.digest_missing() => {
                    Err("this daemon's deps.plan has no digest (API 0.1): it cannot install dependencies")
                }
                Some(_) if self.app_busy() => Err(APP_BUSY),
                Some(_) => Ok(()),
            },
            Action::Run | Action::Remove | Action::EditPermissions if self.app_busy() => Err(APP_BUSY),
            Action::Run | Action::Remove | Action::EditPermissions => Ok(()),
        }
    }

    pub fn consent(&self) -> Option<&ConsentState> {
        self.plan.as_ref()
    }

    /// The followed jobs' logs, oldest first.
    pub fn logs(&self) -> impl Iterator<Item = (&str, &LogBuffer)> {
        self.logs.iter().map(|(id, l)| (id.as_str(), l))
    }

    pub fn log(&self, job: &str) -> Option<&LogBuffer> {
        self.logs.iter().find(|(id, _)| id == job).map(|(_, l)| l)
    }
}

const APP_BUSY: &str = "A job for this app is still running; try again when it ends.";

/// The app a write command changes (the commands that make an app busy).
fn write_target(c: &Cmd) -> Option<&str> {
    match c {
        Cmd::Run(id) | Cmd::Remove(id) | Cmd::PermReset(id) | Cmd::PermSet { id, .. } | Cmd::DepsInstall { id, .. } => {
            Some(id)
        }
        _ => None,
    }
}

/// `major.minor.patch` of an API version is at least `want` (a missing patch is 0; an unreadable version is not).
fn api_at_least(api: &str, want: [u64; 3]) -> bool {
    let mut parts = api.split('.').map(str::parse::<u64>);
    match (parts.next(), parts.next(), parts.next().unwrap_or(Ok(0))) {
        (Some(Ok(a)), Some(Ok(b)), Ok(c)) => [a, b, c] >= want,
        _ => false,
    }
}

/// A failed command, in a sentence (spec 5.1): fixed ones for the daemon's known kinds, else the cleaned error.
fn error_text(e: &ClientError) -> String {
    let text = match e.api_error() {
        Some(a) => match a.kind {
            ErrorKind::ReadOnly => READ_ONLY.to_owned(),
            ErrorKind::Busy => "4 jobs are already running; try again when one ends.".to_owned(),
            ErrorKind::AppBusy => APP_BUSY.to_owned(),
            ErrorKind::ConsentMismatch => PLAN_CHANGED.to_owned(),
            ErrorKind::NotFound => "It no longer exists (removed, or runtimed restarted).".to_owned(),
            ErrorKind::InvalidArgument => format!("The daemon refused the request: {}", a.message),
            _ => e.to_string(),
        },
        None => e.to_string(),
    };
    shown(&text, MAX_SHOWN)
}

/// What a command was, for its failure notice.
fn label(c: &Cmd) -> &'static str {
    match c {
        Cmd::Connect => "Connect",
        Cmd::ListApps => "Listing apps",
        Cmd::LoadApp(_) => "Loading the app",
        Cmd::Plan(_) => "Planning dependencies",
        Cmd::Run(_) => "Run",
        Cmd::Cancel(_) => "Cancel",
        Cmd::Remove(_) => "Remove",
        Cmd::Install(_) => "Install",
        Cmd::Import(_) => "Import",
        Cmd::DepsInstall { .. } => "Installing dependencies",
        Cmd::PermSet { .. } | Cmd::PermReset(_) => "Changing permissions",
        Cmd::ListJobs => "Listing jobs",
        Cmd::Follow(_) => "Following a job",
    }
}

#[cfg(test)]
mod tests;
