//! Child-process plumbing shared by the launcher and the backends: draining a child's output without blocking it
//! (`Drain`) and running a helper command under a deadline ([`run_with_timeout`]).
//!
//! **Why a socket pair and not a pipe.** Wine's `wineboot` leaves a `wineserver` daemon behind that inherits the
//! child's stdout/stderr. With a pipe the reader would see EOF only when that daemon exits (seconds later, or
//! never), so "join the reader when the child exits" would hang. A `UnixStream` pair is the std-only way to get a
//! pipe-like fd with a read timeout: the reader polls with a short timeout and, once told the child has exited,
//! drains what is already buffered and stops.
//!
//! Consequences, by design: output a lingering grandchild writes after the direct child exited is dropped, and
//! once the reader is gone such a grandchild gets `EPIPE`/`SIGPIPE` if it writes to the captured stream.
//!
//! [`run_with_timeout`] kills only the direct child (there is no process-group kill without `libc`); a daemon the
//! child started keeps running. It never involves a shell.
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Reads are made in chunks of this size, so memory use does not depend on how much the child writes.
pub const CHUNK: usize = 8 * 1024;
/// [`run_with_timeout`] keeps at most this many bytes of the child's combined stdout+stderr.
pub const MAX_CAPTURE: usize = 64 * 1024;
/// How long the reader waits for data before it looks at the stop flag.
const READ_TIMEOUT: Duration = Duration::from_millis(25);
/// After the child has exited, at most this much more is read (a chatty grandchild cannot keep the reader alive).
const MAX_AFTER_STOP: usize = 1024 * 1024;
const POLL: Duration = Duration::from_millis(10);

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("cannot set up output capture: {0}")]
    Capture(#[source] io::Error),
    #[error("cannot start process: {0}")]
    Spawn(#[source] io::Error),
    #[error("cannot wait for process: {0}")]
    Wait(#[source] io::Error),
    #[error("process did not finish within {0:?} and was killed")]
    TimedOut(Duration),
}

/// The read end has a timeout; the write end goes to the child as an `OwnedFd`.
pub(crate) fn capture_pair() -> io::Result<(UnixStream, UnixStream)> {
    let (rd, wr) = UnixStream::pair()?;
    rd.set_read_timeout(Some(READ_TIMEOUT))?;
    Ok((rd, wr))
}

pub(crate) fn stdio(s: UnixStream) -> Stdio {
    Stdio::from(OwnedFd::from(s))
}

/// A reader thread copying a child's captured output into `T` chunk by chunk.
pub(crate) struct Drain<T> {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<T>>,
}

impl<T: Default + Send + 'static> Drain<T> {
    pub(crate) fn start(
        rd: UnixStream,
        state: T,
        on_chunk: impl FnMut(&mut T, &[u8]) + Send + 'static,
    ) -> io::Result<Drain<T>> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("child-output".into())
            .spawn(move || pump(rd, state, &flag, on_chunk))?;
        Ok(Drain {
            stop,
            handle: Some(handle),
        })
    }

    /// Tells the reader the child is gone, waits for it to drain what is buffered and returns its state.
    pub(crate) fn finish(mut self) -> T {
        self.stop.store(true, Ordering::Release);
        self.handle.take().and_then(|h| h.join().ok()).unwrap_or_default()
    }
}

impl<T> Drop for Drain<T> {
    /// Dropped without `finish`: the (detached) reader still stops by itself.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

fn pump<T>(mut rd: UnixStream, mut state: T, stop: &AtomicBool, mut on_chunk: impl FnMut(&mut T, &[u8])) -> T {
    let mut buf = [0u8; CHUNK];
    let mut after_stop = 0usize;
    loop {
        let stopping = stop.load(Ordering::Acquire);
        match rd.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                on_chunk(&mut state, &buf[..n]);
                if stopping {
                    after_stop += n;
                    if after_stop >= MAX_AFTER_STOP {
                        break;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // Timeout: nothing buffered right now. Stop if the child is gone, else keep waiting.
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                if stopping {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    state
}

/// Runs `cmd` (no shell, stdin closed) and waits at most `timeout`. Returns its exit status and its combined
/// stdout+stderr, capped at [`MAX_CAPTURE`] bytes (the rest is read and discarded, so the child never blocks on
/// a full pipe). On timeout the child is killed and reaped (no zombie) and `RunError::TimedOut` is returned.
pub fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<(ExitStatus, Vec<u8>), RunError> {
    let (rd, wr) = capture_pair().map_err(RunError::Capture)?;
    let wr2 = wr.try_clone().map_err(RunError::Capture)?;
    cmd.stdin(Stdio::null()).stdout(stdio(wr)).stderr(stdio(wr2));
    let drain = Drain::start(rd, Vec::new(), |out: &mut Vec<u8>, chunk| {
        let room = MAX_CAPTURE.saturating_sub(out.len());
        out.extend_from_slice(&chunk[..chunk.len().min(room)]);
    })
    .map_err(RunError::Capture)?;
    let started = cmd.spawn();
    // The parent's copies of the write ends live in `cmd`: close them so EOF can arrive.
    drop(cmd);
    let mut child = started.map_err(RunError::Spawn)?;
    // `None` = a deadline too far away to represent: wait as long as it takes.
    let deadline = Instant::now().checked_add(timeout);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok((status, drain.finish())),
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                drain.finish();
                return Err(RunError::Wait(e));
            }
        }
        let nap = match deadline {
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    // Kill, then reap: a killed child that is never waited for stays a zombie.
                    let _ = child.kill();
                    let _ = child.wait();
                    drain.finish();
                    return Err(RunError::TimedOut(timeout));
                }
                left.min(POLL)
            }
            None => POLL,
        };
        thread::sleep(nap);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(script);
        c
    }

    #[test]
    fn returns_status_and_combined_output() {
        let (st, out) = run_with_timeout(sh("echo out; echo err >&2; exit 3"), Duration::from_secs(10)).unwrap();
        assert_eq!(st.code(), Some(3));
        assert_eq!(String::from_utf8(out).unwrap(), "out\nerr\n");
    }

    #[test]
    fn output_is_capped_and_the_child_is_not_blocked() {
        // 200 kB is far above both the cap and a pipe buffer: a reader that stopped at the cap would deadlock it.
        let (st, out) = run_with_timeout(sh("head -c 200000 /dev/zero"), Duration::from_secs(20)).unwrap();
        assert!(st.success());
        assert_eq!(out.len(), MAX_CAPTURE);
    }

    #[test]
    fn timeout_kills_the_child_promptly_and_leaves_no_zombie() {
        let tmp = tempfile::tempdir().unwrap();
        let pidfile = tmp.path().join("pid");
        let script = format!("echo $$ > '{}'; exec sleep 30", pidfile.display());
        let t0 = Instant::now();
        let err = run_with_timeout(sh(&script), Duration::from_millis(300)).unwrap_err();
        let took = t0.elapsed();
        assert!(matches!(err, RunError::TimedOut(_)), "{err:?}");
        assert!(took < Duration::from_secs(2), "took {took:?}");
        let pid = std::fs::read_to_string(&pidfile).unwrap();
        // A killed but unreaped child would still have a /proc entry (state Z).
        assert!(
            !Path::new("/proc").join(pid.trim()).exists(),
            "child {} still exists",
            pid.trim()
        );
    }

    #[test]
    fn returns_when_a_daemon_keeps_the_output_open() {
        let t0 = Instant::now();
        let (st, out) = run_with_timeout(sh("sleep 3 & echo hi"), Duration::from_secs(20)).unwrap();
        assert!(st.success());
        assert_eq!(out, b"hi\n");
        assert!(t0.elapsed() < Duration::from_secs(2), "took {:?}", t0.elapsed());
    }

    #[test]
    fn a_missing_program_is_a_spawn_error() {
        let err = run_with_timeout(Command::new("/nonexistent/prog"), Duration::from_secs(5)).unwrap_err();
        assert!(matches!(err, RunError::Spawn(_)), "{err:?}");
    }

    #[test]
    fn an_absurd_timeout_does_not_panic() {
        let (st, _) = run_with_timeout(sh("exit 0"), Duration::MAX).unwrap();
        assert!(st.success());
    }
}
