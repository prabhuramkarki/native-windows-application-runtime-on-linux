//! The job table of a write-mode `runtimed` (spec 5.2-5.6): every mutation is the sibling `runtime` binary run with
//! a [`JobSpec`]'s argv, and this module owns those processes.
//!
//! **Spawn.** On the job's own supervisor thread (so `PR_SET_PDEATHSIG`, which fires when the spawning THREAD exits,
//! fires only if the daemon dies): no shell, `env_clear()` plus [`child_env`], cwd the checked empty job directory,
//! stdin `/dev/null`, stdout/stderr piped, `process_group(0)` (pgid = the child's pid), and a `pre_exec` that sets
//! `PR_SET_PDEATHSIG = SIGTERM` and `_exit(127)`s if the daemon already died. Every daemon fd is `CLOEXEC`.
//!
//! **Output.** Two reader threads per job drain the pipes to EOF (a child never blocks on a full pipe). A line ends at
//! `\n`, `\r` or `\r\n`; a longer line than [`LINE_MAX`] is cut (the rest up to its end dropped, the text ending in
//! ` [cut]`); text is decoded lossily and `clean_text`ed. Events live in a ring bounded at [`MAX_EVENTS`] events and
//! [`MAX_EVENT_BYTES`] of text; evictions are counted in `dropped`. After the leader exits the supervisor waits up to
//! 1 s for both pipes to reach EOF; if a process the child started still holds them, a `stderr` note says so, the job
//! ends, and whatever that process writes later is drained and dropped. So the final `state` event is always the
//! job's last event.
//!
//! **Pid reuse.** The supervisor learns of the leader's exit with `waitid(.., WEXITED | WNOWAIT | WNOHANG)`, which
//! leaves the zombie: while it is unreaped its pid, and so the group id, cannot be reused. Group signals are sent only
//! under the job's lock while the leader is unreaped, and the supervisor reaps under the same lock. So a signal can
//! only ever reach the job's own group. (The daemon never ignores SIGCHLD, which would auto-reap.)
//!
//! **Cancel.** SIGTERM to the group, SIGKILL `term_grace` later if the leader has not exited. **Limits.**
//! `max_running` live jobs, one live job per app, finished jobs kept `keep_finished` and `keep_for` (evicted on every
//! start, poll, status, cancel and list). Ids are 128 bits from `getrandom(2)`, held only in memory.
//!
//! Locks: the table's before a job's, never the reverse; a job's lock is never held across a blocking call.
use rt_api::jobs::{EventKind, JobEvent, JobEvents, JobInfo, JobKind, JobSpec, JobStarted, JobState};
use rt_api::{ApiError, ErrorKind};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Most events a job keeps (the oldest are evicted and counted).
pub const MAX_EVENTS: usize = 2000;
/// Most event text a job keeps, in bytes.
pub const MAX_EVENT_BYTES: usize = 512 * 1024;
/// Longest event text, in bytes (a longer line is cut).
pub const LINE_MAX: usize = 4096;
/// Most events one poll returns.
pub const POLL_MAX_EVENTS: usize = 500;
/// How often a waiting poll looks at `stop`, and how often a supervisor looks at its child.
pub const TICK: Duration = Duration::from_millis(100);
const CHILD_TICK: Duration = Duration::from_millis(20);
/// How long the supervisor waits for the pipes to reach EOF after the leader exited (a grandchild may hold them).
const DRAIN: Duration = Duration::from_secs(1);
const CUT: &str = " [cut]";

/// The daemon's environment variables a job's `runtime` gets (spec D9), besides every `RUNTIME_*` one. Nothing comes
/// from the client.
pub const ALLOWED_ENV: &[&str] = &[
    "HOME",
    "PATH",
    "USER",
    "LOGNAME",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "TZ",
    "XDG_RUNTIME_DIR",
    "XDG_DATA_HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_SESSION_TYPE",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
    "PULSE_SERVER",
];

pub struct JobsConfig {
    /// Production: `current_exe().with_file_name("runtime")`; tests: a fake script.
    pub runtime_exe: PathBuf,
    /// `$XDG_RUNTIME_DIR/runtime/job-cwd` (spec D8): checked empty before each spawn.
    pub cwd: PathBuf,
    pub max_running: usize,
    pub keep_finished: usize,
    pub keep_for: Duration,
    /// SIGKILL this long after SIGTERM.
    pub term_grace: Duration,
    pub now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    /// The daemon's environment, filtered by [`child_env`].
    pub env: Arc<dyn Fn() -> Vec<(OsString, OsString)> + Send + Sync>,
}

impl std::fmt::Debug for JobsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobsConfig")
            .field("runtime_exe", &self.runtime_exe)
            .field("cwd", &self.cwd)
            .field("max_running", &self.max_running)
            .field("keep_finished", &self.keep_finished)
            .field("keep_for", &self.keep_for)
            .field("term_grace", &self.term_grace)
            .finish_non_exhaustive()
    }
}

impl JobsConfig {
    /// The production limits (spec 5.4, 5.6) for `runtime_exe` and `cwd`.
    pub fn new(runtime_exe: PathBuf, cwd: PathBuf) -> JobsConfig {
        JobsConfig {
            runtime_exe,
            cwd,
            max_running: 4,
            keep_finished: 100,
            keep_for: Duration::from_secs(3600),
            term_grace: Duration::from_secs(5),
            now: Arc::new(SystemTime::now),
            env: Arc::new(|| std::env::vars_os().collect()),
        }
    }
}

struct Data {
    state: JobState,
    exit_code: Option<i32>,
    signal: Option<i32>,
    created_at: u64,
    started_at: Option<u64>,
    ended_at: Option<u64>,
    events: VecDeque<JobEvent>,
    text_bytes: usize,
    /// The seq of the next event.
    next_seq: u64,
    dropped: u64,
    /// The leader's pid (= pgid) while it is not reaped.
    pid: Option<libc::pid_t>,
    leader_exited: bool,
    cancel_requested: bool,
    term_at: Option<Instant>,
    killed: bool,
    readers_open: u8,
    /// The final state event was pushed: later output (a grandchild's) is drained and dropped.
    closed: bool,
    /// Every signal sent to the group (the tests' pid-reuse guard).
    signals: Vec<i32>,
}

struct Job {
    id: String,
    kind: JobKind,
    app: Option<String>,
    data: Mutex<Data>,
    cv: Condvar,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic elsewhere never makes the table unusable (no invariant spans a panic point).
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn live(s: JobState) -> bool {
    matches!(s, JobState::Queued | JobState::Running)
}

impl Job {
    fn info(&self, d: &Data) -> JobInfo {
        JobInfo {
            job_id: self.id.clone(),
            kind: self.kind,
            app: self.app.clone(),
            state: d.state,
            exit_code: d.exit_code,
            signal: d.signal,
            created_at: d.created_at,
            started_at: d.started_at,
            ended_at: d.ended_at,
            dropped: d.dropped,
        }
    }
}

struct Shared {
    cfg: JobsConfig,
    table: Mutex<Table>,
}

#[derive(Default)]
struct Table {
    jobs: Vec<Arc<Job>>,
    shutting_down: bool,
}

/// The job table. Cloning shares it.
#[derive(Clone)]
pub struct Jobs {
    s: Arc<Shared>,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        (self.cfg.now)()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }

    /// Appends an event (cleaned by the caller) and evicts beyond the bounds.
    fn push(&self, job: &Job, d: &mut Data, kind: EventKind, text: String) {
        d.text_bytes += text.len();
        d.events.push_back(JobEvent {
            seq: d.next_seq,
            ts: self.now_ms(),
            kind,
            text,
        });
        d.next_seq += 1;
        while d.events.len() > MAX_EVENTS || d.text_bytes > MAX_EVENT_BYTES {
            let Some(e) = d.events.pop_front() else { break };
            d.text_bytes -= e.text.len();
            d.dropped += 1;
        }
        job.cv.notify_all();
    }

    fn set_state(&self, job: &Job, d: &mut Data, state: JobState, text: &str) {
        d.state = state;
        self.push(job, d, EventKind::State, text.to_owned());
    }

    /// The job ended: records how, frees its slots, wakes every poll.
    fn finish(&self, job: &Job, d: &mut Data, exit_code: Option<i32>, signal: Option<i32>) {
        let (state, word) = if d.cancel_requested {
            (JobState::Cancelled, "cancelled")
        } else if exit_code == Some(0) {
            (JobState::Succeeded, "succeeded")
        } else {
            (JobState::Failed, "failed")
        };
        let text = match (exit_code, signal) {
            (Some(c), _) => format!("{word} (exit {c})"),
            (_, Some(s)) => format!("{word} (signal {s})"),
            _ => word.to_owned(),
        };
        d.exit_code = exit_code;
        d.signal = signal;
        d.ended_at = Some(self.now_ms());
        d.pid = None;
        self.set_state(job, d, state, &text);
        d.closed = true;
    }

    /// Sends `sig` to the job's group, only while its leader is unreaped (the caller holds the job's lock).
    fn signal(d: &mut Data, sig: i32) {
        if let Some(pid) = d.pid {
            // SAFETY: `pid` is our unreaped child (its zombie at worst), so `-pid` is still its own group.
            unsafe { libc::kill(-pid, sig) };
            d.signals.push(sig);
        }
    }

    fn cancel_locked(d: &mut Data) {
        if !live(d.state) || d.cancel_requested {
            return;
        }
        d.cancel_requested = true;
        if d.pid.is_some() && !d.leader_exited {
            Self::signal(d, libc::SIGTERM);
            d.term_at = Some(Instant::now());
        }
    }

    /// Drops finished jobs older than `keep_for`, then the oldest beyond `keep_finished`.
    fn evict(&self, t: &mut Table) {
        let now = self.now_ms();
        let keep_for = self.cfg.keep_for.as_millis() as u64;
        let ended = |j: &Arc<Job>| lock(&j.data).ended_at;
        t.jobs
            .retain(|j| ended(j).is_none_or(|e| now.saturating_sub(e) <= keep_for));
        let mut finished: Vec<(u64, usize)> = t
            .jobs
            .iter()
            .enumerate()
            .filter_map(|(i, j)| ended(j).map(|e| (e, i)))
            .collect();
        if finished.len() > self.cfg.keep_finished {
            finished.sort();
            let mut gone: Vec<usize> = finished[..finished.len() - self.cfg.keep_finished]
                .iter()
                .map(|(_, i)| *i)
                .collect();
            gone.sort_unstable();
            for i in gone.into_iter().rev() {
                t.jobs.remove(i);
            }
        }
    }

    fn find(&self, id: &str) -> Result<Arc<Job>, ApiError> {
        let mut t = lock(&self.table);
        self.evict(&mut t);
        t.jobs.iter().find(|j| j.id == id).cloned().ok_or_else(|| {
            ApiError::new(
                ErrorKind::NotFound,
                "no such job (unknown, expired, or from an earlier daemon)",
            )
        })
    }
}

impl Jobs {
    pub fn new(cfg: JobsConfig) -> Jobs {
        Jobs {
            s: Arc::new(Shared {
                cfg,
                table: Mutex::default(),
            }),
        }
    }

    /// Starts `spec` (`busy`, `app_busy`, or `unavailable` when the `runtime` binary or the job cwd is unsafe or the
    /// daemon is stopping). A spawn failure is a `failed` job, not an error here.
    pub fn start(&self, spec: JobSpec) -> Result<JobStarted, ApiError> {
        let s = &self.s;
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        check_runtime_exe(&s.cfg.runtime_exe, euid)?;
        check_job_cwd(&s.cfg.cwd, euid)?;
        let app = spec.app().map(|a| a.as_str().to_owned());
        let job = {
            let mut t = lock(&s.table);
            if t.shutting_down {
                return Err(ApiError::new(ErrorKind::Unavailable, "the daemon is stopping"));
            }
            s.evict(&mut t);
            let running: Vec<&Arc<Job>> = t.jobs.iter().filter(|j| live(lock(&j.data).state)).collect();
            if app.is_some() && running.iter().any(|j| j.app == app) {
                return Err(ApiError::new(ErrorKind::AppBusy, "a job for this app is still running"));
            }
            if running.len() >= s.cfg.max_running {
                return Err(ApiError::new(
                    ErrorKind::Busy,
                    format!("{} jobs are already running; try again later", s.cfg.max_running),
                ));
            }
            let now = s.now_ms();
            let job = Arc::new(Job {
                id: new_id()?,
                kind: spec.kind(),
                app,
                data: Mutex::new(Data {
                    state: JobState::Queued,
                    exit_code: None,
                    signal: None,
                    created_at: now,
                    started_at: None,
                    ended_at: None,
                    events: VecDeque::new(),
                    text_bytes: 0,
                    next_seq: 1,
                    dropped: 0,
                    pid: None,
                    leader_exited: false,
                    cancel_requested: false,
                    term_at: None,
                    killed: false,
                    readers_open: 0,
                    closed: false,
                    signals: vec![],
                }),
                cv: Condvar::new(),
            });
            s.set_state(&job, &mut lock(&job.data), JobState::Queued, "queued");
            t.jobs.push(job.clone());
            job
        };
        let (shared, j) = (s.clone(), job.clone());
        let argv = spec.argv();
        if let Err(e) = std::thread::Builder::new()
            .name("job".into())
            .spawn(move || supervise(&shared, &j, argv))
        {
            let mut d = lock(&job.data);
            s.push(
                &job,
                &mut d,
                EventKind::Stderr,
                clean(&format!("cannot start a supervisor: {e}")),
            );
            s.finish(&job, &mut d, None, None);
        }
        Ok(JobStarted { job_id: job.id.clone() })
    }

    /// The events after `after` (at most [`POLL_MAX_EVENTS`]), waiting up to `wait` for one, for the job's end or for
    /// `stop` (looked at every [`TICK`]).
    pub fn poll(&self, id: &str, after: u64, wait: Duration, stop: &AtomicBool) -> Result<JobEvents, ApiError> {
        let job = self.s.find(id)?;
        let until = Instant::now() + wait;
        let mut d = lock(&job.data);
        loop {
            let ready = d.next_seq > after + 1 || !live(d.state);
            let left = until.saturating_duration_since(Instant::now());
            if ready || left.is_zero() || stop.load(Ordering::SeqCst) {
                break;
            }
            d = job
                .cv
                .wait_timeout(d, left.min(TICK))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        let first = d.events.front().map_or(d.next_seq, |e| e.seq);
        let events: Vec<JobEvent> = d
            .events
            .iter()
            .filter(|e| e.seq > after)
            .take(POLL_MAX_EVENTS)
            .cloned()
            .collect();
        Ok(JobEvents {
            next_seq: events.last().map_or(after.max(first - 1), |e| e.seq),
            dropped: (first - 1).saturating_sub(after),
            events,
            job: job.info(&d),
        })
    }

    pub fn status(&self, id: &str) -> Result<JobInfo, ApiError> {
        let job = self.s.find(id)?;
        let d = lock(&job.data);
        Ok(job.info(&d))
    }

    /// Asks the job to stop (SIGTERM to its group, SIGKILL `term_grace` later); a job that ended is left alone.
    pub fn cancel(&self, id: &str) -> Result<JobInfo, ApiError> {
        let job = self.s.find(id)?;
        let mut d = lock(&job.data);
        Shared::cancel_locked(&mut d);
        Ok(job.info(&d))
    }

    /// Live jobs first (oldest first), then finished ones, newest first.
    pub fn list(&self) -> Vec<JobInfo> {
        let mut t = lock(&self.s.table);
        self.s.evict(&mut t);
        let mut v: Vec<JobInfo> = t.jobs.iter().map(|j| j.info(&lock(&j.data))).collect();
        v.sort_by_key(|i| match i.ended_at {
            None => (0, i.created_at),
            Some(e) => (1, u64::MAX - e),
        });
        v
    }

    /// How long a cancel waits before SIGKILL.
    pub fn term_grace(&self) -> Duration {
        self.s.cfg.term_grace
    }

    /// Refuses new jobs, cancels every live one and waits up to `within` for them to be reaped.
    pub fn shutdown(&self, within: Duration) {
        let jobs: Vec<Arc<Job>> = {
            let mut t = lock(&self.s.table);
            t.shutting_down = true;
            t.jobs.clone()
        };
        for j in &jobs {
            Shared::cancel_locked(&mut lock(&j.data));
        }
        let until = Instant::now() + within;
        for j in &jobs {
            let mut d = lock(&j.data);
            while live(d.state) {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return;
                }
                d = j.cv.wait_timeout(d, left).unwrap_or_else(|e| e.into_inner()).0;
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn signals_sent(&self, id: &str) -> Vec<i32> {
        lock(&self.s.find(id).unwrap().data).signals.clone()
    }
}

fn clean(s: &str) -> String {
    rt_core::clean_text(s, LINE_MAX)
}

/// Spawns the child, feeds its readers, escalates a cancel, reaps it and records the end. Runs on the job's own
/// thread, which lives until the child is reaped (PDEATHSIG is tied to it).
fn supervise(s: &Arc<Shared>, job: &Arc<Job>, argv: Vec<OsString>) {
    {
        let mut d = lock(&job.data);
        if d.cancel_requested {
            s.finish(job, &mut d, None, None);
            return;
        }
    }
    // SAFETY: getpid has no preconditions.
    let daemon = unsafe { libc::getpid() };
    let mut cmd = Command::new(&s.cfg.runtime_exe);
    cmd.args(&argv)
        .env_clear()
        .envs(child_env(&*s.cfg.env))
        .current_dir(&s.cfg.cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // SAFETY: the closure runs in the forked child before exec and calls only async-signal-safe functions (prctl,
    // getppid, _exit); it allocates nothing and touches no lock.
    unsafe {
        cmd.pre_exec(move || {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM as libc::c_ulong, 0, 0, 0);
            // The daemon died between fork and prctl: PDEATHSIG will never fire.
            if libc::getppid() != daemon {
                libc::_exit(127);
            }
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let mut d = lock(&job.data);
            s.push(
                job,
                &mut d,
                EventKind::Stderr,
                clean(&format!("cannot start runtime: {e}")),
            );
            s.finish(job, &mut d, None, None);
            return;
        }
    };
    let pid = child.id() as libc::pid_t;
    {
        let mut d = lock(&job.data);
        d.pid = Some(pid);
        d.started_at = Some(s.now_ms());
        d.readers_open = 2;
        s.set_state(job, &mut d, JobState::Running, "running");
        if d.cancel_requested {
            // Cancelled while queued: it never gets to run for long.
            d.cancel_requested = false;
            Shared::cancel_locked(&mut d);
        }
    }
    let pipes: [(Option<Box<dyn Read + Send>>, EventKind); 2] = [
        (child.stdout.take().map(|p| Box::new(p) as _), EventKind::Stdout),
        (child.stderr.take().map(|p| Box::new(p) as _), EventKind::Stderr),
    ];
    for (pipe, kind) in pipes {
        let (s2, j2) = (s.clone(), job.clone());
        let spawned = pipe.map(|p| {
            std::thread::Builder::new()
                .name("job-out".into())
                .spawn(move || read_lines(&s2, &j2, p, kind))
        });
        if !matches!(spawned, Some(Ok(_))) {
            // No reader (the pipe, if any, is closed: the child gets EPIPE instead of blocking).
            lock(&job.data).readers_open -= 1;
        }
    }
    // `child` is never waited on through std: the zombie must stay until reaped below, under the job's lock.
    drop(child);
    while !leader_exited(pid) {
        let mut d = lock(&job.data);
        if let Some(t) = d.term_at
            && !d.killed
            && t.elapsed() >= s.cfg.term_grace
        {
            Shared::signal(&mut d, libc::SIGKILL);
            d.killed = true;
        }
        drop(d);
        std::thread::sleep(CHILD_TICK);
    }
    let mut d = lock(&job.data);
    d.leader_exited = true;
    let until = Instant::now() + DRAIN;
    while d.readers_open > 0 {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        d = job.cv.wait_timeout(d, left).unwrap_or_else(|e| e.into_inner()).0;
    }
    if d.readers_open > 0 {
        s.push(
            job,
            &mut d,
            EventKind::Stderr,
            "output after runtime ended is not shown: a process it started still holds its output".into(),
        );
    }
    let mut status = 0;
    // SAFETY: `pid` is our child, exited and not yet reaped; reaping under the job's lock is what makes every group
    // signal (sent under the same lock while `pid` is set) safe from pid reuse.
    let r = unsafe { libc::waitpid(pid, &mut status, 0) };
    let (code, sig) = if r != pid {
        (None, None)
    } else if libc::WIFEXITED(status) {
        (Some(libc::WEXITSTATUS(status)), None)
    } else if libc::WIFSIGNALED(status) {
        (None, Some(libc::WTERMSIG(status)))
    } else {
        (None, None)
    };
    s.finish(job, &mut d, code, sig);
}

/// Whether the leader exited, leaving it unreaped (`WNOWAIT`). An error (no such child) counts as exited.
fn leader_exited(pid: libc::pid_t) -> bool {
    loop {
        // SAFETY: a zeroed siginfo_t is a valid out-parameter; waitid writes it and reaps nothing (WNOWAIT).
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        if r == -1 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return true;
        }
        // SAFETY: waitid succeeded, so `info` is initialised; si_pid is 0 when no child changed state (WNOHANG).
        return unsafe { info.si_pid() } != 0;
    }
}

/// Reads `pipe` to EOF, one event per line (spec 5.4). Never stops draining early.
fn read_lines(s: &Shared, job: &Job, mut pipe: Box<dyn Read + Send>, kind: EventKind) {
    let mut line: Vec<u8> = Vec::new();
    let mut cut = false;
    let mut after_cr = false;
    let mut buf = [0u8; 8192];
    let emit = |line: &mut Vec<u8>, cut: &mut bool| {
        let mut text = clean(&String::from_utf8_lossy(line));
        if *cut {
            let mut end = LINE_MAX - CUT.len();
            while end > text.len() || !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push_str(CUT);
        }
        line.clear();
        *cut = false;
        let mut d = lock(&job.data);
        if !d.closed {
            s.push(job, &mut d, kind, text);
        }
    };
    loop {
        let n = match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        for &b in &buf[..n] {
            match b {
                b'\n' if after_cr => after_cr = false,
                b'\n' | b'\r' => {
                    after_cr = b == b'\r';
                    emit(&mut line, &mut cut);
                }
                _ => {
                    after_cr = false;
                    if line.len() < LINE_MAX {
                        line.push(b);
                    } else {
                        cut = true;
                    }
                }
            }
        }
    }
    if !line.is_empty() || cut {
        emit(&mut line, &mut cut);
    }
    let mut d = lock(&job.data);
    d.readers_open = d.readers_open.saturating_sub(1);
    job.cv.notify_all();
}

/// The child's environment (spec D9): [`ALLOWED_ENV`] and every `RUNTIME_*` variable of `get()`, in its order.
pub fn child_env(get: &dyn Fn() -> Vec<(OsString, OsString)>) -> Vec<(OsString, OsString)> {
    get()
        .into_iter()
        .filter(|(k, _)| {
            let k = k.as_bytes();
            k.starts_with(b"RUNTIME_") || ALLOWED_ENV.iter().any(|a| a.as_bytes() == k)
        })
        .collect()
}

fn unavailable(what: &str) -> ApiError {
    ApiError::new(ErrorKind::Unavailable, what)
}

/// The `runtime` binary (spec D10): a regular file (a symlink is refused, not followed), owned by `euid` or root,
/// writable by nobody else.
pub fn check_runtime_exe(p: &Path, euid: u32) -> Result<(), ApiError> {
    let m = std::fs::symlink_metadata(p).map_err(|_| unavailable("the runtime binary next to runtimed is missing"))?;
    if !m.file_type().is_file() || (m.uid() != euid && m.uid() != 0) || m.mode() & 0o022 != 0 {
        return Err(unavailable(
            "the runtime binary next to runtimed is not a regular file owned by this user or root and writable only by \
             its owner",
        ));
    }
    Ok(())
}

/// The job cwd (spec D8): a directory (not a symlink) owned by `euid`, mode 0700, empty.
pub fn check_job_cwd(p: &Path, euid: u32) -> Result<(), ApiError> {
    let bad = || unavailable("the job directory is not an empty 0700 directory of this user");
    let m = std::fs::symlink_metadata(p).map_err(|_| bad())?;
    if !m.file_type().is_dir() || m.uid() != euid || m.permissions().mode() & 0o7777 != 0o700 {
        return Err(bad());
    }
    let mut entries = std::fs::read_dir(p).map_err(|_| bad())?;
    if entries.next().is_some() {
        return Err(bad());
    }
    Ok(())
}

/// 128 random bits from `getrandom(2)`, as 32 lowercase hex digits.
fn new_id() -> Result<String, ApiError> {
    let mut b = [0u8; 16];
    let mut got = 0;
    while got < b.len() {
        // SAFETY: the pointer and length name the unfilled tail of `b`.
        let r = unsafe { libc::getrandom(b[got..].as_mut_ptr().cast(), b.len() - got, 0) };
        if r > 0 {
            got += r as usize;
        } else if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            return Err(ApiError::new(ErrorKind::Internal, "cannot make a job id"));
        }
    }
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

#[cfg(test)]
pub(crate) mod tests;
