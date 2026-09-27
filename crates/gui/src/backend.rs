//! The backend (spec 5.2): runs the view model's [`Cmd`]s against `runtimed` and reports [`Msg`]s through a sink,
//! off the UI thread. One request thread (one `Client`, commands in order) and at most [`MAX_FOLLOWERS`] job
//! followers (each with its own `Client`, long-polling `jobs.poll`). [`Backend::send`] never blocks.
//!
//! A `ClientError::Rpc` (and a request the client refused before sending) keeps the connection; any other error drops
//! it and reports `ConnectFailed`; the next command or Retry reconnects. A follower reconnects on its own with
//! backoff ([`BACKOFF_MIN`] doubling to [`BACKOFF_MAX`]) and resumes after the last event it saw; it ends on the
//! job's final state, on `not_found` (the daemon restarted) or when the backend is dropped (after its current poll).
use crate::vm::{AppData, Cmd, ConnError, Msg, is_final};
use rt_daemon::client::{Client, ClientError};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// Most jobs followed at once: the daemon's running-job cap, so the GUI holds at most 4 of its 8 waiting polls.
pub const MAX_FOLLOWERS: usize = 4;
/// How long one `jobs.poll` waits for news.
pub const POLL_WAIT_MS: u32 = 10_000;
/// A follower's first wait after a failed connection or poll, doubled up to [`BACKOFF_MAX`].
pub const BACKOFF_MIN: Duration = Duration::from_millis(500);
pub const BACKOFF_MAX: Duration = Duration::from_secs(8);

/// Where the backend's messages go (the UI forwards them to its main loop).
pub type Sink = Arc<dyn Fn(Msg) + Send + Sync>;
/// How a follower waits: `(how long, stop flag)` (tests record it).
type Sleep = Arc<dyn Fn(Duration, &AtomicBool) + Send + Sync>;

pub struct Backend {
    tx: mpsc::Sender<Cmd>,
    stop: Arc<AtomicBool>,
}

struct Shared {
    socket: PathBuf,
    sink: Sink,
    stop: Arc<AtomicBool>,
    sleep: Sleep,
    slots: Mutex<Slots>,
}

impl Backend {
    /// Starts the request thread, which connects first (`Cmd::Connect`).
    pub fn spawn(socket: PathBuf, sink: Sink) -> Backend {
        Backend::spawn_with(socket, sink, Arc::new(nap))
    }

    fn spawn_with(socket: PathBuf, sink: Sink, sleep: Sleep) -> Backend {
        let stop = Arc::new(AtomicBool::new(false));
        let sh = Arc::new(Shared {
            socket,
            sink,
            stop: stop.clone(),
            sleep,
            slots: Mutex::default(),
        });
        let (tx, rx) = mpsc::channel();
        let _ = tx.send(Cmd::Connect);
        thread::spawn(move || serve(&sh, rx));
        Backend { tx, stop }
    }

    /// Queues `cmd` for the request thread; never blocks (a dead thread drops it).
    pub fn send(&self, cmd: Cmd) {
        let _ = self.tx.send(cmd);
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Sleeps `d` in short steps, returning early once `stop` is set.
fn nap(d: Duration, stop: &AtomicBool) {
    let until = Instant::now() + d;
    while !stop.load(Ordering::SeqCst) {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        thread::sleep(left.min(Duration::from_millis(100)));
    }
}

/// The follower slots: at most [`MAX_FOLLOWERS`] running, the rest wait in order.
#[derive(Default)]
struct Slots {
    running: usize,
    waiting: VecDeque<String>,
}

impl Slots {
    /// `Some(id)` if it may be followed now; else it waits its turn.
    fn start(&mut self, id: String) -> Option<String> {
        if self.running < MAX_FOLLOWERS {
            self.running += 1;
            Some(id)
        } else {
            self.waiting.push_back(id);
            None
        }
    }

    /// A follower ended: the next waiting job, which takes over its slot.
    fn done(&mut self) -> Option<String> {
        let next = self.waiting.pop_front();
        if next.is_none() {
            self.running -= 1;
        }
        next
    }
}

/// The request thread: commands in order on one connection, until the backend is dropped.
fn serve(sh: &Arc<Shared>, rx: mpsc::Receiver<Cmd>) {
    let mut client = None;
    for cmd in rx {
        if sh.stop.load(Ordering::SeqCst) {
            return;
        }
        match cmd {
            Cmd::Connect => client = connect(sh),
            Cmd::Follow(id) => {
                let first = sh.slots.lock().unwrap_or_else(|e| e.into_inner()).start(id);
                if let Some(id) = first {
                    let sh = sh.clone();
                    thread::spawn(move || follow(&sh, id));
                }
            }
            cmd => {
                if client.is_none() {
                    client = connect(sh);
                }
                let Some(c) = client.as_mut() else { continue };
                match request(c, &cmd) {
                    Ok(msg) => (sh.sink)(msg),
                    // The daemon answered (or nothing was sent): the connection is fine.
                    Err(error @ (ClientError::Rpc { .. } | ClientError::Unsupported(_) | ClientError::TooLarge)) => {
                        (sh.sink)(Msg::Failed { what: cmd, error })
                    }
                    Err(error) => {
                        client = None;
                        (sh.sink)(Msg::ConnectFailed(ConnError {
                            socket: sh.socket.clone(),
                            error,
                        }))
                    }
                }
            }
        }
    }
}

/// A new connection and its `rpc.version`, reported either way.
fn connect(sh: &Shared) -> Option<Client> {
    match Client::connect(&sh.socket).and_then(|mut c| c.version().map(|v| (c, v))) {
        Ok((c, v)) => {
            (sh.sink)(Msg::Connected(v));
            Some(c)
        }
        Err(error) => {
            (sh.sink)(Msg::ConnectFailed(ConnError {
                socket: sh.socket.clone(),
                error,
            }));
            None
        }
    }
}

/// A probe's own failure is part of the page; a broken connection fails the whole load.
fn part<T>(r: Result<T, ClientError>) -> Result<Result<T, ClientError>, ClientError> {
    match r {
        Err(e) if !matches!(e, ClientError::Rpc { .. } | ClientError::Unsupported(_)) => Err(e),
        r => Ok(r),
    }
}

/// One command's calls and the message that reports them.
fn request(c: &mut Client, cmd: &Cmd) -> Result<Msg, ClientError> {
    let started = |r: Result<rt_api::jobs::JobStarted, ClientError>| {
        r.map(|j| Msg::JobStarted {
            what: cmd.clone(),
            job_id: j.job_id,
        })
    };
    match cmd {
        Cmd::ListApps => c.apps().map(Msg::Apps),
        Cmd::LoadApp(id) => {
            let detail = c.app(id)?;
            Ok(Msg::AppLoaded(Box::new(AppData {
                detail,
                permissions: part(c.permissions(id))?,
                doctor: part(c.doctor_app(id))?,
                graphics: part(c.graphics_info())?,
                sandbox: part(c.sandbox_info(id))?,
            })))
        }
        Cmd::Plan(id) => c.deps_plan(id).map(|plan| Msg::PlanLoaded { id: id.clone(), plan }),
        Cmd::Run(id) => started(c.run_app(id, &[])),
        Cmd::Remove(id) => started(c.remove(id)),
        Cmd::Install(p) => started(c.install(p)),
        Cmd::DepsInstall { id, digest, consent } => started(c.deps_install(id, digest, consent)),
        Cmd::PermSet { id, set } => started(c.permissions_set(id, set)),
        Cmd::PermReset(id) => started(c.permissions_reset(id)),
        Cmd::Cancel(job) => {
            c.job_cancel(job)?;
            c.jobs().map(Msg::JobList)
        }
        Cmd::ListJobs => c.jobs().map(Msg::JobList),
        Cmd::Connect | Cmd::Follow(_) => Err(ClientError::Unsupported("not a request")),
    }
}

/// A follower thread: follows `id`, then each job that waited for its slot.
fn follow(sh: &Shared, mut id: String) {
    loop {
        follow_one(sh, &id);
        match sh.slots.lock().unwrap_or_else(|e| e.into_inner()).done() {
            Some(next) => id = next,
            None => return,
        }
    }
}

/// Long-polls job `id` until it ended (and nothing is left to read), is gone, or the backend stopped.
fn follow_one(sh: &Shared, id: &str) {
    let (mut client, mut next, mut backoff) = (None::<Client>, 0, BACKOFF_MIN);
    let wait = |backoff: &mut Duration| {
        (sh.sleep)(*backoff, &sh.stop);
        *backoff = (*backoff * 2).min(BACKOFF_MAX);
    };
    while !sh.stop.load(Ordering::SeqCst) {
        let c = match &mut client {
            Some(c) => c,
            None => match Client::connect(&sh.socket) {
                Ok(c) => client.insert(c),
                Err(_) => {
                    wait(&mut backoff);
                    continue;
                }
            },
        };
        match c.job_poll(id, next, POLL_WAIT_MS) {
            Ok(ev) => {
                backoff = BACKOFF_MIN;
                next = ev.next_seq;
                let (ended, empty) = (is_final(ev.job.state), ev.events.is_empty());
                (sh.sink)(Msg::JobEvents(ev));
                if ended && empty {
                    return;
                }
                if empty && !ended {
                    // Answered at once without news (the daemon's waiting polls are all taken): no tight loop.
                    (sh.sleep)(BACKOFF_MIN, &sh.stop);
                }
            }
            Err(e) if matches!(&e, ClientError::Rpc { code, .. } if *code == i64::from(rt_daemon::protocol::BUSY)) => {
                client = None;
                wait(&mut backoff);
            }
            Err(e @ (ClientError::Rpc { .. } | ClientError::Unsupported(_) | ClientError::TooLarge)) => {
                // `not_found`: the daemon restarted (or forgot the job); anything else will not get better.
                (sh.sink)(Msg::Failed {
                    what: Cmd::Follow(id.to_owned()),
                    error: e,
                });
                return;
            }
            Err(_) => {
                client = None;
                wait(&mut backoff);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fifth_follow_waits_until_one_of_four_ends() {
        let mut s = Slots::default();
        for i in 0..MAX_FOLLOWERS {
            assert_eq!(s.start(format!("j{i}")), Some(format!("j{i}")));
        }
        assert_eq!(s.start("j4".into()), None);
        assert_eq!(s.start("j5".into()), None);
        assert_eq!(s.running, MAX_FOLLOWERS);
        // One ends: the oldest waiting job takes its slot.
        assert_eq!(s.done(), Some("j4".into()));
        assert_eq!(s.running, MAX_FOLLOWERS);
        assert_eq!(s.done(), Some("j5".into()));
        for left in (0..MAX_FOLLOWERS).rev() {
            assert_eq!(s.done(), None);
            assert_eq!(s.running, left);
        }
        assert_eq!(s.start("j6".into()), Some("j6".into()));
    }

    fn scratch_socket() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let sock = d.path().join("none/runtimed.sock");
        (d, sock)
    }

    /// Messages into a vector.
    fn collect() -> (Sink, Arc<Mutex<Vec<Msg>>>) {
        let got = Arc::new(Mutex::new(vec![]));
        let g = got.clone();
        (Arc::new(move |m| g.lock().unwrap().push(m)), got)
    }

    fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < until, "timed out: {what}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn no_daemon_is_a_failed_connect_and_retry_tries_again() {
        let (_d, sock) = scratch_socket();
        let (sink, got) = collect();
        let b = Backend::spawn(sock.clone(), sink);
        wait_for("the first connect", || got.lock().unwrap().len() == 1);
        b.send(Cmd::Connect);
        wait_for("the retry", || got.lock().unwrap().len() == 2);
        for m in got.lock().unwrap().iter() {
            match m {
                Msg::ConnectFailed(ConnError {
                    socket,
                    error: ClientError::Unreachable { .. },
                }) => assert_eq!(*socket, sock),
                m => panic!("{m:?}"),
            }
        }
    }

    #[test]
    fn a_follower_backs_off_from_half_a_second_doubling_to_eight() {
        let (_d, sock) = scratch_socket();
        let (sink, _got) = collect();
        let slept = Arc::new(Mutex::new(vec![]));
        let s = slept.clone();
        let b = Backend::spawn_with(
            sock,
            sink,
            Arc::new(move |d, _: &AtomicBool| {
                s.lock().unwrap().push(d);
                thread::sleep(Duration::from_millis(1));
            }),
        );
        b.send(Cmd::Follow("j1".into()));
        wait_for("seven retries", || slept.lock().unwrap().len() >= 7);
        drop(b);
        let ms: Vec<u128> = slept.lock().unwrap()[..7].iter().map(Duration::as_millis).collect();
        assert_eq!(ms, [500, 1000, 2000, 4000, 8000, 8000, 8000]);
        // Stopped: the follower ends and sleeps no more.
        thread::sleep(Duration::from_millis(50));
        let n = slept.lock().unwrap().len();
        thread::sleep(Duration::from_millis(50));
        assert_eq!(slept.lock().unwrap().len(), n);
    }

    #[test]
    fn sending_after_the_request_thread_died_does_not_panic() {
        let (_d, sock) = scratch_socket();
        let b = Backend::spawn(sock, Arc::new(|_| panic!("the sink fails (expected in this test)")));
        wait_for("the request thread to die", || b.tx.send(Cmd::ListApps).is_err());
        for _ in 0..3 {
            b.send(Cmd::ListApps);
            b.send(Cmd::Follow("j".into()));
        }
    }
}
