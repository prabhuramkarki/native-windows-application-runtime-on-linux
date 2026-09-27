use super::*;
use rt_api::jobs::{EventKind, JobSpec, JobState};
use rt_core::AppId;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::Command;
use std::sync::atomic::AtomicU64;

/// The fake `runtime`: records its argv (NUL separated), environment, cwd, stdin and process group under
/// `$RUNTIME_DATA_DIR/fake/`, keyed by its last argument (the app id), then acts on `fake/mode.<key>` (else
/// `fake/mode`, else `ok`).
const FAKE: &str = r#"#!/bin/sh
[ "$1" = --probe ] && exit 0
F="$RUNTIME_DATA_DIR/fake"
for a in "$@"; do last="$a"; done
key=$(printf %s "$last" | tr -c 'a-z0-9.-' _)
printf '%s\0' "$@" > "$F/argv.$key"
env > "$F/env.$key"
pwd > "$F/cwd.$key"
cut -d' ' -f5 "/proc/$$/stat" > "$F/pgid.$key"
echo $$ > "$F/pid.$key"
if read -r line; then echo data > "$F/stdin.$key"; else echo eof > "$F/stdin.$key"; fi
mode=$(cat "$F/mode.$key" 2>/dev/null || cat "$F/mode" 2>/dev/null || echo ok)
case "$mode" in
  ok) echo out-line; echo err-line >&2 ;;
  exit*) exit ${mode#exit } ;;
  flood) seq 100000 ;;
  wide) L=$(printf '%1000s' | tr ' ' b); yes "$L" | head -n 1000 ;;
  longline) head -c 1048576 /dev/zero | tr '\0' a; printf '\nafter\n' ;;
  hostile) printf 'a\033[31mred\342\200\256rev\000nul\rcr\377\376bad\r\nlast\n' ;;
  wait) echo ready; sleep 60 ;;
  sleep) trap '' TERM; echo ready; sleep 60 ;;
  child) sleep 60 & echo $! > "$F/grandchild.$key"; echo ready; wait ;;
  slow) echo first; sleep 0.4; echo late ;;
  orphan) (sleep 2; echo late) & echo ready ;;
  stubborn) (trap '' TERM; exec sleep 60) & echo $! > "$F/grandchild.$key"; echo ready; wait ;;
  graceful) trap 'echo bye; exit 0' TERM; echo ready; while :; do sleep 0.05; done ;;
esac
"#;

pub(crate) struct Fx {
    _t: tempfile::TempDir,
    pub(crate) root: PathBuf,
    pub(crate) fake: PathBuf,
    pub(crate) cwd: PathBuf,
    clock: Arc<AtomicU64>,
    pub(crate) jobs: Jobs,
}

const T0: u64 = 1_800_000_000_000;

pub(crate) fn write_script(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    // Another test thread may have forked while the file was open for writing (ETXTBSY until its exec).
    for _ in 0..500 {
        match Command::new(path).arg("--probe").status() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => std::thread::sleep(Duration::from_millis(4)),
            _ => break,
        }
    }
}

pub(crate) fn fx() -> Fx {
    fx_with(|_| {})
}

pub(crate) fn fx_with(tweak: impl FnOnce(&mut JobsConfig)) -> Fx {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().canonicalize().unwrap();
    let (data, bin, cwd) = (root.join("data"), root.join("bin"), root.join("cwd"));
    let fake = data.join("fake");
    for d in [&fake, &bin, &cwd] {
        fs::create_dir_all(d).unwrap();
    }
    fs::set_permissions(&cwd, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    write_script(&bin.join("runtime"), FAKE);
    let env: Vec<(OsString, OsString)> = [
        ("PATH", "/usr/bin:/bin".into()),
        ("RUNTIME_DATA_DIR", data.to_str().unwrap().to_owned()),
        ("HOME", root.to_str().unwrap().to_owned()),
        ("LANG", "C".into()),
        ("SECRET", "hunter2".into()),
        ("LISTEN_FDS", "3".into()),
        ("LD_PRELOAD", "/evil.so".into()),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let clock = Arc::new(AtomicU64::new(T0));
    let c = clock.clone();
    let mut cfg = JobsConfig {
        runtime_exe: bin.join("runtime"),
        cwd: cwd.clone(),
        max_running: 4,
        keep_finished: 100,
        keep_for: Duration::from_secs(3600),
        term_grace: Duration::from_millis(300),
        now: Arc::new(move || UNIX_EPOCH + Duration::from_millis(c.load(Ordering::SeqCst))),
        env: Arc::new(move || env.clone()),
    };
    tweak(&mut cfg);
    Fx {
        _t: t,
        root,
        fake,
        cwd,
        clock,
        jobs: Jobs::new(cfg),
    }
}

fn app(id: &str) -> AppId {
    AppId::parse(id).unwrap()
}

pub(crate) fn remove(id: &str) -> JobSpec {
    JobSpec::Remove { app: app(id) }
}

impl Fx {
    pub(crate) fn start_job(&self, app_id: &str) -> String {
        self.start(remove(app_id))
    }

    pub(crate) fn mode(&self, key: Option<&str>, m: &str) {
        let f = match key {
            Some(k) => self.fake.join(format!("mode.{k}")),
            None => self.fake.join("mode"),
        };
        fs::write(f, m).unwrap();
    }

    fn start(&self, spec: JobSpec) -> String {
        self.jobs.start(spec).unwrap().job_id
    }

    /// Every retained event after `after`, polling without waiting.
    pub(crate) fn events_after(&self, id: &str, mut after: u64) -> Vec<JobEvent> {
        let mut all = vec![];
        loop {
            let e = self
                .jobs
                .poll(id, after, Duration::ZERO, &AtomicBool::new(false))
                .unwrap();
            if e.events.is_empty() {
                return all;
            }
            after = e.next_seq;
            all.extend(e.events);
        }
    }

    pub(crate) fn events(&self, id: &str) -> Vec<JobEvent> {
        self.events_after(id, 0)
    }

    pub(crate) fn wait_end(&self, id: &str) -> JobInfo {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let i = self.jobs.status(id).unwrap();
            if !matches!(i.state, JobState::Queued | JobState::Running) {
                return i;
            }
            assert!(Instant::now() < until, "job {id} did not end: {i:?}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Waits for a `stdout` event with `text`.
    pub(crate) fn wait_for(&self, id: &str, text: &str) {
        let until = Instant::now() + Duration::from_secs(10);
        while !self.events(id).iter().any(|e| e.text == text) {
            assert!(Instant::now() < until, "no {text:?} from {id}: {:?}", self.events(id));
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub(crate) fn read(&self, what: &str, key: &str) -> String {
        fs::read_to_string(self.fake.join(format!("{what}.{key}"))).unwrap_or_default()
    }
}

fn states(ev: &[JobEvent]) -> Vec<String> {
    ev.iter()
        .filter(|e| e.kind == EventKind::State)
        .map(|e| e.text.clone())
        .collect()
}

fn clean(s: &str) -> bool {
    !s.chars().any(|c| c.is_control() || rt_core::is_format(c))
}

pub(crate) fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks that the pid exists; nothing is delivered.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[test]
fn a_job_runs_runtime_with_the_argv_an_allowlisted_env_the_empty_cwd_no_stdin_and_its_own_group() {
    let f = fx();
    let spec = remove("notepad");
    let id = f.start(spec.clone());
    let info = f.wait_end(&id);
    assert_eq!(
        (info.state, info.exit_code, info.signal, info.kind),
        (JobState::Succeeded, Some(0), None, JobKind::Remove)
    );
    assert_eq!(info.app.as_deref(), Some("notepad"));
    assert!(info.started_at.is_some() && info.ended_at.is_some() && info.created_at == T0);
    let mut want = vec![];
    for a in spec.argv() {
        want.extend_from_slice(a.as_bytes());
        want.push(0);
    }
    assert_eq!(fs::read(f.fake.join("argv.notepad")).unwrap(), want);
    let env = f.read("env", "notepad");
    for bad in ["SECRET", "hunter2", "LISTEN_FDS", "LD_PRELOAD"] {
        assert!(!env.contains(bad), "{bad} leaked: {env}");
    }
    for line in env.lines() {
        let name = line.split('=').next().unwrap();
        assert!(
            ALLOWED_ENV.contains(&name)
                || name.starts_with("RUNTIME_")
                || ["PWD", "SHLVL", "_", "OLDPWD"].contains(&name),
            "{name} in the child's environment"
        );
    }
    assert!(env.contains("RUNTIME_DATA_DIR=") && env.contains("LANG=C"), "{env}");
    // Its own fresh directory under the job cwd, removed when it ended.
    let own = f.cwd.join(&id);
    assert_eq!(f.read("cwd", "notepad").trim(), own.to_str().unwrap());
    assert_eq!(f.read("stdin", "notepad").trim(), "eof");
    let (pgid, pid) = (f.read("pgid", "notepad"), f.read("pid", "notepad"));
    assert_eq!(pgid.trim(), pid.trim(), "the child leads its own group");
    // SAFETY: getpgrp has no preconditions.
    assert_ne!(pgid.trim(), unsafe { libc::getpgrp() }.to_string());
    let ev = f.events(&id);
    assert_eq!(states(&ev), ["queued", "running", "succeeded (exit 0)"]);
    assert!(ev.iter().any(|e| e.kind == EventKind::Stdout && e.text == "out-line"));
    assert!(ev.iter().any(|e| e.kind == EventKind::Stderr && e.text == "err-line"));
    assert_eq!(
        ev.iter().map(|e| e.seq).collect::<Vec<_>>(),
        (1..=ev.len() as u64).collect::<Vec<_>>()
    );
    assert!(ev.iter().all(|e| e.ts == T0));
    assert!(!own.exists());
    assert_eq!(fs::read_dir(&f.cwd).unwrap().count(), 0);
}

#[test]
fn a_nonzero_exit_is_failed_with_its_code() {
    let f = fx();
    f.mode(Some("a"), "exit 3");
    let id = f.start(remove("a"));
    let i = f.wait_end(&id);
    assert_eq!((i.state, i.exit_code, i.signal), (JobState::Failed, Some(3), None));
    assert_eq!(states(&f.events(&id)).last().unwrap(), "failed (exit 3)");
}

#[test]
fn a_flood_keeps_the_newest_2000_events_and_counts_the_rest() {
    let f = fx();
    f.mode(Some("a"), "flood");
    let id = f.start(remove("a"));
    f.wait_end(&id);
    let first = f.jobs.poll(&id, 0, Duration::ZERO, &AtomicBool::new(false)).unwrap();
    assert!(first.events.len() <= POLL_MAX_EVENTS);
    // queued, running, 100000 lines, succeeded
    let total = 100_003;
    assert_eq!(first.dropped, total - MAX_EVENTS as u64);
    assert_eq!(first.job.dropped, total - MAX_EVENTS as u64);
    let ev = f.events(&id);
    assert_eq!(ev.len(), MAX_EVENTS);
    assert_eq!(ev[0].seq, total - MAX_EVENTS as u64 + 1);
    assert_eq!(ev.last().unwrap().seq, total);
    assert!(ev.windows(2).all(|w| w[1].seq == w[0].seq + 1));
    assert_eq!(ev[ev.len() - 2].text, "100000");
    // Asking after the last event: nothing, nothing dropped.
    let tail = f
        .jobs
        .poll(&id, total, Duration::ZERO, &AtomicBool::new(false))
        .unwrap();
    assert!(tail.events.is_empty() && tail.dropped == 0 && tail.next_seq == total);
}

#[test]
fn wide_lines_are_bounded_by_the_text_budget() {
    let f = fx();
    f.mode(Some("a"), "wide");
    let id = f.start(remove("a"));
    f.wait_end(&id);
    let ev = f.events(&id);
    let bytes: usize = ev.iter().map(|e| e.text.len()).sum();
    assert!(bytes <= MAX_EVENT_BYTES, "{bytes}");
    assert!(ev.len() < 1003 && f.jobs.status(&id).unwrap().dropped > 0);
}

#[test]
fn a_huge_line_is_cut_and_the_child_is_never_blocked() {
    let f = fx();
    f.mode(Some("a"), "longline");
    let id = f.start(remove("a"));
    let i = f.wait_end(&id);
    assert_eq!(i.state, JobState::Succeeded);
    let out: Vec<_> = f
        .events(&id)
        .into_iter()
        .filter(|e| e.kind == EventKind::Stdout)
        .collect();
    assert_eq!(
        out.len(),
        2,
        "{:?}",
        out.iter().map(|e| e.text.len()).collect::<Vec<_>>()
    );
    assert!(out[0].text.len() <= LINE_MAX && out[0].text.ends_with(" [cut]"));
    assert!(out[0].text.starts_with("aaaa"));
    assert_eq!(out[1].text, "after");
}

#[test]
fn hostile_output_is_cleaned_and_split_on_cr() {
    let f = fx();
    f.mode(Some("a"), "hostile");
    let id = f.start(remove("a"));
    f.wait_end(&id);
    let out: Vec<String> = f
        .events(&id)
        .into_iter()
        .filter(|e| e.kind == EventKind::Stdout)
        .map(|e| e.text)
        .collect();
    assert!(out.iter().all(|t| clean(t)), "{out:?}");
    assert_eq!(out.len(), 3, "CR and CRLF end lines: {out:?}");
    assert!(out[0].starts_with("a[31mredrevnul"), "{out:?}");
    assert!(out[1].starts_with("cr") && out[1].contains("bad"), "{out:?}");
    assert_eq!(out[2], "last");
}

#[test]
fn caps_one_live_job_per_app_and_four_running() {
    let f = fx();
    f.mode(None, "wait");
    f.start(remove("a"));
    assert_eq!(f.jobs.start(remove("a")).unwrap_err().kind, ErrorKind::AppBusy);
    for a in ["b", "c", "d"] {
        f.start(remove(a));
    }
    assert_eq!(f.jobs.start(remove("e")).unwrap_err().kind, ErrorKind::Busy);
    let install = JobSpec::Install {
        path: "/x/setup.exe".into(),
        name: None,
        exe: None,
        silent: false,
        network: false,
    };
    assert_eq!(f.jobs.start(install).unwrap_err().kind, ErrorKind::Busy);
    assert_eq!(f.jobs.list().len(), 4);
    f.jobs.shutdown(Duration::from_secs(5));
    // All ended: the slots are free again (after shutdown nothing new starts, though).
    assert!(f.jobs.list().iter().all(|j| j.state == JobState::Cancelled));
    assert_eq!(f.jobs.start(remove("e")).unwrap_err().kind, ErrorKind::Unavailable);
}

#[test]
fn an_install_takes_no_app_slot_and_a_finished_job_frees_its_app() {
    let f = fx();
    let id = f.start(remove("a"));
    f.wait_end(&id);
    let again = f.start(remove("a"));
    f.wait_end(&again);
    let install = JobSpec::Install {
        path: "/x/setup.exe".into(),
        name: None,
        exe: None,
        silent: false,
        network: false,
    };
    let i = f.start(install);
    assert_eq!(f.wait_end(&i).app, None);
}

#[test]
fn finished_jobs_are_kept_100_and_one_hour() {
    let f = fx_with(|c| c.max_running = 200);
    let mut ids = vec![];
    for n in 0..101 {
        let id = f.start(remove(&format!("j{n}")));
        f.wait_end(&id);
        ids.push(id);
        f.clock.fetch_add(1, Ordering::SeqCst);
    }
    let list = f.jobs.list();
    assert_eq!(list.len(), 100);
    assert_eq!(f.jobs.status(&ids[0]).unwrap_err().kind, ErrorKind::NotFound);
    assert!(f.jobs.status(&ids[1]).is_ok());
    // newest first
    assert_eq!(list[0].job_id, ids[100]);
    // The newest ended at T0 + 100 ms: exactly one hour later it is kept, 1 ms later it is gone.
    f.clock.store(T0 + 100 + 3_600_000, Ordering::SeqCst);
    assert!(f.jobs.status(&ids[100]).is_ok());
    assert_eq!(f.jobs.list().len(), 1);
    f.clock.fetch_add(1, Ordering::SeqCst);
    assert!(f.jobs.list().is_empty());
    assert_eq!(f.jobs.status(&ids[100]).unwrap_err().kind, ErrorKind::NotFound);
    assert_eq!(
        f.jobs
            .poll(&ids[100], 0, Duration::ZERO, &AtomicBool::new(false))
            .unwrap_err()
            .kind,
        ErrorKind::NotFound
    );
    assert_eq!(f.jobs.cancel("nope").unwrap_err().kind, ErrorKind::NotFound);
}

#[test]
fn cancel_escalates_to_sigkill_after_the_grace() {
    let f = fx();
    f.mode(Some("a"), "sleep");
    let id = f.start(remove("a"));
    f.wait_for(&id, "ready");
    let t = Instant::now();
    let pid: i32 = f.read("pid", "a").trim().parse().unwrap();
    f.jobs.cancel(&id).unwrap();
    let i = f.wait_end(&id);
    assert!(t.elapsed() >= Duration::from_millis(300), "{:?}", t.elapsed());
    assert_eq!((i.state, i.signal, i.exit_code), (JobState::Cancelled, Some(9), None));
    assert_eq!(f.jobs.signals_sent(&id), [libc::SIGTERM, libc::SIGKILL]);
    assert_eq!(states(&f.events(&id)).last().unwrap(), "cancelled (signal 9)");
    assert!(!alive(pid));
    // A second cancel of an ended job sends nothing.
    f.jobs.cancel(&id).unwrap();
    assert_eq!(f.jobs.signals_sent(&id).len(), 2);
}

#[test]
fn cancel_kills_the_whole_group() {
    let f = fx();
    f.mode(Some("a"), "child");
    let id = f.start(remove("a"));
    f.wait_for(&id, "ready");
    let grandchild: i32 = f.read("grandchild", "a").trim().parse().unwrap();
    assert!(alive(grandchild));
    f.jobs.cancel(&id).unwrap();
    let i = f.wait_end(&id);
    assert_eq!((i.state, i.signal), (JobState::Cancelled, Some(libc::SIGTERM)));
    let until = Instant::now() + Duration::from_secs(1);
    while alive(grandchild) {
        assert!(Instant::now() < until, "the grandchild survived");
        std::thread::sleep(Duration::from_millis(10));
    }
    // SIGTERM, then (the leader gone) SIGKILL for whatever is left of the group.
    assert_eq!(f.jobs.signals_sent(&id), [libc::SIGTERM, libc::SIGKILL]);
}

#[test]
fn a_job_that_already_ended_is_never_signalled() {
    let f = fx();
    let id = f.start(remove("a"));
    f.wait_end(&id);
    let i = f.jobs.cancel(&id).unwrap();
    assert_eq!(i.state, JobState::Succeeded);
    assert!(f.jobs.signals_sent(&id).is_empty());
}

#[test]
fn shutdown_cancels_and_reaps_every_live_job() {
    let f = fx();
    f.mode(Some("a"), "wait");
    f.mode(Some("b"), "wait");
    f.mode(Some("c"), "sleep");
    let ids: Vec<String> = ["a", "b", "c"].iter().map(|a| f.start(remove(a))).collect();
    for id in &ids {
        f.wait_for(id, "ready");
    }
    let pids: Vec<i32> = ["a", "b", "c"]
        .iter()
        .map(|a| f.read("pid", a).trim().parse().unwrap())
        .collect();
    let t = Instant::now();
    f.jobs.shutdown(Duration::from_secs(1));
    assert!(t.elapsed() < Duration::from_millis(1500), "{:?}", t.elapsed());
    for id in &ids {
        assert_eq!(f.jobs.status(id).unwrap().state, JobState::Cancelled);
    }
    assert!(pids.iter().all(|p| !alive(*p)));
}

#[test]
fn poll_returns_at_once_on_new_events_at_the_end_after_the_wait_or_on_stop() {
    let f = fx();
    let no = AtomicBool::new(false);
    f.mode(Some("a"), "slow");
    let id = f.start(remove("a"));
    f.wait_for(&id, "first");
    let after = f.events(&id).last().unwrap().seq;
    let t = Instant::now();
    let e = f.jobs.poll(&id, after, Duration::from_secs(10), &no).unwrap();
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_eq!(e.events[0].text, "late");
    // Already there: at once.
    let t = Instant::now();
    assert!(
        !f.jobs
            .poll(&id, 0, Duration::from_secs(10), &no)
            .unwrap()
            .events
            .is_empty()
    );
    assert!(t.elapsed() < Duration::from_millis(50));
    // Ended and nothing new: at once.
    f.wait_end(&id);
    let last = f.events(&id).last().unwrap().seq;
    let t = Instant::now();
    assert!(
        f.jobs
            .poll(&id, last, Duration::from_secs(10), &no)
            .unwrap()
            .events
            .is_empty()
    );
    assert!(t.elapsed() < Duration::from_millis(50));
    // Nothing happens: after the wait.
    f.mode(Some("b"), "wait");
    let id = f.start(remove("b"));
    f.wait_for(&id, "ready");
    let last = f.events(&id).last().unwrap().seq;
    let t = Instant::now();
    let e = f.jobs.poll(&id, last, Duration::from_millis(200), &no).unwrap();
    assert!(e.events.is_empty() && e.next_seq == last);
    assert!(t.elapsed() >= Duration::from_millis(200) && t.elapsed() < Duration::from_millis(600));
    // Stop: within a tick.
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    let setter = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        s.store(true, Ordering::SeqCst);
        Instant::now()
    });
    let e = f.jobs.poll(&id, last, Duration::from_secs(10), &stop).unwrap();
    let set_at = setter.join().unwrap();
    assert!(e.events.is_empty());
    assert!(set_at.elapsed() < Duration::from_millis(150), "{:?}", set_at.elapsed());
    f.jobs.shutdown(Duration::from_secs(2));
}

#[test]
fn job_ids_are_unique_128_bit_hex() {
    let mut ids: Vec<String> = (0..1000).map(|_| new_id().unwrap()).collect();
    assert!(
        ids.iter()
            .all(|i| i.len() == 32 && i.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    );
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 1000);
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[test]
fn the_runtime_binary_must_be_a_regular_file_only_we_can_write() {
    let f = fx();
    let exe = f.root.join("bin/runtime");
    check_runtime_exe(&exe, euid()).unwrap();
    let link = f.root.join("link");
    symlink(&exe, &link).unwrap();
    for (bad, what) in [
        (&link, "symlink"),
        (&f.root.join("bin"), "directory"),
        (&f.root.join("none"), "missing"),
    ] {
        assert_eq!(
            check_runtime_exe(bad, euid()).unwrap_err().kind,
            ErrorKind::Unavailable,
            "{what}"
        );
    }
    let shown = exe.to_str().unwrap().to_owned();
    let msg = |p: &Path, uid| check_runtime_exe(p, uid).unwrap_err().message;
    assert!(msg(&link, euid()).contains("is a symlink"), "{}", msg(&link, euid()));
    assert!(msg(&f.root.join("bin"), euid()).contains("not a regular file"));
    assert!(msg(&f.root.join("none"), euid()).contains("missing"));
    for mode in [0o775, 0o757] {
        fs::set_permissions(&exe, fs::Permissions::from_mode(mode)).unwrap();
        let m = msg(&exe, euid());
        assert!(
            m.contains(&format!("run: chmod g-w,o-w {shown}")) && m.contains(&format!("{mode:o}")),
            "{mode:o}: {m}"
        );
    }
    // Its directory too: whoever may write there may swap the file.
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(f.root.join("bin"), fs::Permissions::from_mode(0o775)).unwrap();
    let m = msg(&exe, euid());
    assert!(
        m.contains(&format!("run: chmod g-w,o-w {}", f.root.join("bin").display())),
        "{m}"
    );
    fs::set_permissions(f.root.join("bin"), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(msg(&exe, euid() + 1).contains("belongs to uid"), "another owner");
    // start refuses before any job exists, and says what to do
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o775)).unwrap();
    let e = f.jobs.start(remove("a")).unwrap_err();
    assert_eq!(e.kind, ErrorKind::Unavailable);
    assert!(e.message.contains("chmod g-w,o-w"), "{}", e.message);
    assert!(f.jobs.list().is_empty());
}

#[test]
fn the_job_cwd_must_be_our_own_0700_directory_and_a_stray_file_blocks_nothing() {
    let f = fx();
    check_job_cwd(&f.cwd, euid()).unwrap();
    let link = f.root.join("cwdlink");
    symlink(&f.cwd, &link).unwrap();
    assert!(check_job_cwd(&link, euid()).is_err(), "symlink");
    assert!(check_job_cwd(&f.cwd, euid() + 1).is_err(), "owner");
    fs::set_permissions(&f.cwd, fs::Permissions::from_mode(0o755)).unwrap();
    let m = check_job_cwd(&f.cwd, euid()).unwrap_err().message;
    assert!(m.contains(f.cwd.to_str().unwrap()), "{m}");
    fs::set_permissions(&f.cwd, fs::Permissions::from_mode(0o700)).unwrap();
    // A stray file (a core dump, say) is in no job's own directory: jobs still start, and see none of it.
    fs::write(f.cwd.join("a"), b"MZ").unwrap();
    check_job_cwd(&f.cwd, euid()).unwrap();
    let id = f.start(remove("a"));
    assert_eq!(f.wait_end(&id).state, JobState::Succeeded);
    assert_eq!(f.read("cwd", "a").trim(), f.cwd.join(&id).to_str().unwrap());
    assert!(f.cwd.join("a").exists(), "not ours to remove");
}

#[test]
fn a_spawn_failure_is_a_failed_job_that_says_why() {
    let f = fx();
    // A regular file we own that cannot be executed: passes the checks, exec fails.
    fs::set_permissions(f.root.join("bin/runtime"), fs::Permissions::from_mode(0o644)).unwrap();
    let id = f.start(remove("a"));
    let i = f.wait_end(&id);
    assert_eq!((i.state, i.exit_code, i.signal), (JobState::Failed, None, None));
    let ev = f.events(&id);
    assert!(
        ev.iter()
            .any(|e| e.kind == EventKind::Stderr && e.text.starts_with("cannot start runtime:")),
        "{ev:?}"
    );
    assert_eq!(states(&ev), ["queued", "failed"]);
}

#[test]
fn child_env_is_the_allowlist_and_runtime_variables() {
    let got = child_env(&|| {
        [
            ("PATH", "p"),
            ("RUNTIME_WINE", "w"),
            ("SECRET", "s"),
            ("LISTEN_PID", "1"),
            ("RUNTIMEX", "x"),
            ("DISPLAY", ":0"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
    });
    let names: Vec<_> = got.iter().map(|(k, _)| k.to_str().unwrap()).collect();
    assert_eq!(names, ["PATH", "RUNTIME_WINE", "DISPLAY"]);
}

/// A process the child left behind still holds the output pipes: the job ends DRAIN after the leader, says that
/// later output is not shown, and its final state event stays the last event.
#[test]
fn the_final_state_event_is_the_last_even_when_a_grandchild_holds_the_output() {
    let f = fx();
    f.mode(Some("a"), "orphan");
    let id = f.start(remove("a"));
    let t = Instant::now();
    let i = f.wait_end(&id);
    assert!(
        t.elapsed() < Duration::from_millis(1900),
        "waited for the grandchild: {:?}",
        t.elapsed()
    );
    assert_eq!(i.state, JobState::Succeeded);
    std::thread::sleep(Duration::from_millis(1500));
    let ev = f.events(&id);
    assert_eq!(ev.last().unwrap().text, "succeeded (exit 0)", "{ev:?}");
    assert!(!ev.iter().any(|e| e.text == "late"), "{ev:?}");
    let note = &ev[ev.len() - 2];
    assert_eq!(note.kind, EventKind::Stderr);
    assert!(note.text.contains("still holds its output"), "{ev:?}");
}

#[test]
fn cancel_kills_what_is_left_of_the_group_after_the_leader_exits() {
    let f = fx();
    f.mode(Some("a"), "stubborn");
    let id = f.start(remove("a"));
    f.wait_for(&id, "ready");
    let gc: i32 = f.read("grandchild", "a").trim().parse().unwrap();
    f.jobs.cancel(&id).unwrap();
    let i = f.wait_end(&id);
    assert_eq!((i.state, i.signal), (JobState::Cancelled, Some(libc::SIGTERM)));
    let until = Instant::now() + Duration::from_secs(1);
    while alive(gc) {
        assert!(
            Instant::now() < until,
            "a group member that ignores SIGTERM survived the cancel"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(f.jobs.signals_sent(&id), [libc::SIGTERM, libc::SIGKILL]);
}

#[test]
fn a_job_that_finished_is_not_reported_cancelled() {
    let f = fx();
    // It handles SIGTERM and exits 0: the work it did stands.
    f.mode(Some("a"), "graceful");
    let id = f.start(remove("a"));
    f.wait_for(&id, "ready");
    f.jobs.cancel(&id).unwrap();
    let i = f.wait_end(&id);
    assert_eq!((i.state, i.exit_code), (JobState::Succeeded, Some(0)));
    // The leader already exited 0; a cancel during the drain kills the process holding the output, and the job
    // still succeeded.
    f.mode(Some("b"), "orphan");
    let id = f.start(remove("b"));
    f.wait_for(&id, "ready");
    std::thread::sleep(Duration::from_millis(300));
    f.jobs.cancel(&id).unwrap();
    let t = Instant::now();
    let i = f.wait_end(&id);
    assert_eq!((i.state, i.exit_code), (JobState::Succeeded, Some(0)));
    assert!(
        t.elapsed() < Duration::from_millis(900),
        "the drain was not cut short: {:?}",
        t.elapsed()
    );
    assert_eq!(f.jobs.signals_sent(&id), [libc::SIGKILL]);
}

#[test]
fn a_poll_after_the_largest_seq_is_empty_not_a_panic() {
    let f = fx();
    let id = f.start(remove("a"));
    f.wait_end(&id);
    let e = f
        .jobs
        .poll(&id, u64::MAX, Duration::from_millis(50), &AtomicBool::new(false))
        .unwrap();
    assert!(e.events.is_empty() && e.dropped == 0 && e.next_seq == u64::MAX);
}
