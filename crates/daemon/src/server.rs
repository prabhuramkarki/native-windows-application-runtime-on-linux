//! The socket and everything around it: where it lives, who may connect, how much a connection may cost, and how
//! the daemon stops.
//!
//! **Where.** `$XDG_RUNTIME_DIR/runtime/runtimed.sock` ([`default_socket_path`]) or `--socket PATH`, under the
//! same rules ([`bind_socket`]): the directory is created 0700 if missing, and refused if it is a symlink, not a
//! directory, not ours, or open to group or others. At the socket path, nothing is bound over except a stale
//! socket of ours: a socket nobody accepts on (connect probe: `ECONNREFUSED`) is removed; a live one is
//! [`ServeError::AlreadyRunning`]; anything else (a file, a symlink, a foreign socket) is refused and left alone.
//! The socket is bound under umask 077, set 0600 and checked (type, owner, mode) before the first accept. Only
//! the last component of the directory is checked: its ancestors are the user's own (`XDG_RUNTIME_DIR`) or,
//! for `--socket`, the caller's choice.
//!
//! **Who.** Every accepted connection's `SO_PEERCRED` uid must be this process's effective uid ([`peer_allowed`]);
//! any other is closed without a byte. The 0600 mode already keeps others out: this is defence in depth.
//!
//! **How much.** One thread per connection, at most `max_connections` (another connection gets one [`BUSY`] line
//! and is closed). A request line must arrive whole within `idle_timeout` of the previous reply (so a slow drip
//! of bytes is cut like an idle client) and is capped at [`MAX_FRAME`] (an [`INVALID_REQUEST`] line, then
//! closed). A request runs on a thread of its own: past `request_timeout` the client gets a [`TIMEOUT`] line and
//! is closed, but the connection's slot is only freed when the method returns, so a stuck method can hold at
//! most one thread per slot. A method cannot be cancelled (every one is bounded by its own probe timeouts;
//! `vulkaninfo`'s is 10 s). Replies are written with `idle_timeout` as the write timeout. There is no request
//! semaphore beyond the connection cap: a connection has at most one request in flight.
//!
//! **Stopping.** `stop` (set by SIGTERM/SIGINT in `runtimed`) is polled every [`TICK`]: the listener closes, idle
//! connections end at their next tick, a request being executed gets its reply, and after at most [`GRACE`] the
//! socket file this server bound (checked by device and inode) is removed; an inherited (activated) one is not.
//!
//! **Socket activation** ([`listener_from_env`]): `LISTEN_PID` must be this process (else the variables are not
//! for us and are ignored), `LISTEN_FDS` must be exactly 1, and fd 3 must be a listening `AF_UNIX` stream socket.
use crate::dispatch;
use crate::protocol::{
    BUSY, FrameError, INTERNAL, INVALID_REQUEST, Id, MAX_FRAME, Reply, TIMEOUT, parse_request, read_frame,
};
use rt_api::Runtime;
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

/// How often blocked waits look at the stop flag.
pub const TICK: Duration = Duration::from_millis(100);
/// How long a stopping server waits for its connections.
pub const GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub socket: PathBuf,
    pub max_connections: usize,
    pub request_timeout: Duration,
    pub idle_timeout: Duration,
}

impl ServerConfig {
    /// The defaults: 32 connections, 30 s per request, 30 s to send a request line.
    pub fn new(socket: PathBuf) -> ServerConfig {
        ServerConfig {
            socket,
            max_connections: 32,
            request_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("XDG_RUNTIME_DIR is unset or not an absolute path: pass --socket PATH")]
    NoRuntimeDir,
    #[error("refusing {path}: {why}")]
    Unsafe { path: String, why: &'static str },
    #[error("another runtimed is already serving {0}")]
    AlreadyRunning(String),
    #[error("socket activation: {0}")]
    Activation(&'static str),
    #[error("{what}: {err}")]
    Io { what: &'static str, err: io::Error },
}

fn io(what: &'static str) -> impl FnOnce(io::Error) -> ServeError {
    move |err| ServeError::Io { what, err }
}

/// A path for messages: printable and bounded (it is ours or the caller's, but it ends up on a terminal).
fn shown(p: &Path) -> String {
    rt_core::clean_text(&p.to_string_lossy(), 512)
}

fn log(msg: &str) {
    eprintln!("runtimed: {msg}");
}

fn euid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// `$XDG_RUNTIME_DIR/runtime/runtimed.sock` over an injected environment.
pub fn default_socket_path_from(get: &dyn Fn(&str) -> Option<OsString>) -> Result<PathBuf, ServeError> {
    let dir = PathBuf::from(get("XDG_RUNTIME_DIR").ok_or(ServeError::NoRuntimeDir)?);
    if !dir.is_absolute() {
        return Err(ServeError::NoRuntimeDir);
    }
    Ok(dir.join("runtime").join("runtimed.sock"))
}

pub fn default_socket_path() -> Result<PathBuf, ServeError> {
    default_socket_path_from(&|k| std::env::var_os(k))
}

/// A socket this server created: removed at the end only if the path still names it.
pub struct Bound {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl Bound {
    pub fn remove(&self) {
        match fs::symlink_metadata(&self.path) {
            Ok(m) if m.dev() == self.dev && m.ino() == self.ino => {
                let _ = fs::remove_file(&self.path);
            }
            _ => log("the socket path no longer names our socket: left alone"),
        }
    }
}

/// The directory: created 0700 when missing, then it must be a real directory of ours closed to others.
fn check_dir(dir: &Path) -> Result<(), ServeError> {
    let refuse = |why| ServeError::Unsafe { path: shown(dir), why };
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(io("cannot create the socket directory")(e)),
        _ => {}
    }
    let m = fs::symlink_metadata(dir).map_err(io("cannot inspect the socket directory"))?;
    if m.file_type().is_symlink() {
        Err(refuse("the socket directory is a symlink"))
    } else if !m.is_dir() {
        Err(refuse("not a directory"))
    } else if m.uid() != euid() {
        Err(refuse("the socket directory belongs to another user"))
    } else if m.mode() & 0o077 != 0 {
        Err(refuse("the socket directory is open to group or others (want 0700)"))
    } else {
        Ok(())
    }
}

/// Binds `path` under the rules of the module docs.
pub fn bind_socket(path: &Path) -> Result<(UnixListener, Bound), ServeError> {
    let refuse = |why| ServeError::Unsafe { path: shown(path), why };
    if !path.is_absolute() {
        return Err(refuse("the socket path must be absolute"));
    }
    let dir = path.parent().ok_or_else(|| refuse("no directory"))?;
    check_dir(dir)?;
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(io("cannot inspect the socket path")(e)),
        Ok(m) if !m.file_type().is_socket() => return Err(refuse("something that is not a socket is in the way")),
        Ok(m) if m.uid() != euid() => return Err(refuse("a socket of another user is in the way")),
        Ok(_) => match UnixStream::connect(path) {
            Ok(_) => return Err(ServeError::AlreadyRunning(shown(path))),
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                fs::remove_file(path).map_err(io("cannot remove the stale socket"))?;
                log("removed a stale socket");
            }
            Err(e) => return Err(io("cannot probe the existing socket")(e)),
        },
    }
    // SAFETY: `umask` only swaps the process's file mode mask; the old one is put back right after the bind.
    let old = unsafe { libc::umask(0o077) };
    let bound = UnixListener::bind(path);
    // SAFETY: as above.
    unsafe { libc::umask(old) };
    let listener = bound.map_err(io("cannot bind the socket"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(io("cannot set the socket mode"))?;
    let m = fs::symlink_metadata(path).map_err(io("cannot inspect the bound socket"))?;
    if !m.file_type().is_socket() || m.uid() != euid() || m.mode() & 0o777 != 0o600 {
        return Err(refuse("the bound socket is not a 0600 socket of ours"));
    }
    let bound = Bound {
        path: path.to_owned(),
        dev: m.dev(),
        ino: m.ino(),
    };
    Ok((listener, bound))
}

fn sockopt<T>(fd: RawFd, opt: libc::c_int, val: &mut T) -> io::Result<()> {
    let mut len = std::mem::size_of::<T>() as libc::socklen_t;
    // SAFETY: `val` is a live, writable `T` and `len` its exact size; the kernel writes at most `len` bytes.
    let r = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, opt, (val as *mut T).cast(), &mut len) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<T>() {
        return Err(io::Error::other("unexpected option size"));
    }
    Ok(())
}

/// The connected peer's uid (`SO_PEERCRED`: its credentials when it connected).
fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    sockopt(s.as_raw_fd(), libc::SO_PEERCRED, &mut cred)?;
    Ok(cred.uid)
}

/// Whether the peer of `s` is uid `me`. An unreadable credential is a no.
pub fn peer_allowed(s: &UnixStream, me: u32) -> bool {
    matches!(peer_uid(s), Ok(u) if u == me)
}

/// The inherited listener of systemd socket activation, if the environment hands us one (module docs).
pub fn listener_from_env(get: &dyn Fn(&str) -> Option<OsString>) -> Result<Option<UnixListener>, ServeError> {
    listener_from(get, std::process::id(), 3)
}

/// [`listener_from_env`] with the pid and the fd as parameters (tests use a dup'd fd, never their own fd 3).
pub fn listener_from(
    get: &dyn Fn(&str) -> Option<OsString>,
    pid: u32,
    fd: RawFd,
) -> Result<Option<UnixListener>, ServeError> {
    let Some(p) = get("LISTEN_PID") else {
        return Ok(None);
    };
    if p.to_str().and_then(|s| s.parse::<u32>().ok()) != Some(pid) {
        return Ok(None);
    }
    if get("LISTEN_FDS").as_deref() != Some("1".as_ref()) {
        return Err(ServeError::Activation("LISTEN_FDS must be 1"));
    }
    let bad = || ServeError::Activation("the inherited fd is not a listening Unix stream socket");
    let (mut domain, mut ty, mut listening): (libc::c_int, libc::c_int, libc::c_int) = (0, 0, 0);
    sockopt(fd, libc::SO_DOMAIN, &mut domain).map_err(|_| bad())?;
    sockopt(fd, libc::SO_TYPE, &mut ty).map_err(|_| bad())?;
    sockopt(fd, libc::SO_ACCEPTCONN, &mut listening).map_err(|_| bad())?;
    if domain != libc::AF_UNIX || ty != libc::SOCK_STREAM || listening != 1 {
        return Err(bad());
    }
    // SAFETY: `fd` is an open socket (getsockopt succeeded); FD_CLOEXEC keeps it out of the probes we spawn.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(bad());
    }
    // SAFETY: the activation protocol hands this fd to us alone; nothing else in the process owns or closes it.
    Ok(Some(unsafe { UnixListener::from_raw_fd(fd) }))
}

/// Decrements the connection count when the connection's thread ends, however it ends.
struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Reads from the socket until `until`, looking at `stop` every [`TICK`]: a request line must arrive whole in time.
struct Deadline<'a> {
    s: &'a UnixStream,
    until: Instant,
    stop: &'a AtomicBool,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let left = self.until.saturating_duration_since(Instant::now());
            if left.is_zero() || self.stop.load(Ordering::SeqCst) {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.s.set_read_timeout(Some(left.min(TICK)))?;
            match (&mut &*self.s).read(buf) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                    ) => {}
                r => return r,
            }
        }
    }
}

fn send(s: &UnixStream, r: &Reply) -> io::Result<()> {
    (&mut &*s).write_all(&r.to_line())
}

/// Runs one request on its own thread and waits at most `timeout` for it: the reply (a [`TIMEOUT`] error when it
/// took longer) and the thread, which the caller joins before it frees the connection's slot.
fn run(
    rt: &Arc<Runtime>,
    req: crate::protocol::Request,
    id: Id,
    timeout: Duration,
) -> (Reply, Option<thread::JoinHandle<()>>) {
    let (tx, rx) = mpsc::channel();
    let rt = rt.clone();
    let h = match thread::Builder::new().spawn(move || {
        let _ = tx.send(dispatch::handle(&rt, req));
    }) {
        Ok(h) => h,
        Err(_) => return (Reply::error(id, INTERNAL, "internal error"), None),
    };
    match rx.recv_timeout(timeout) {
        Ok(Some(r)) => (r, Some(h)),
        Ok(None) | Err(mpsc::RecvTimeoutError::Disconnected) => (Reply::error(id, INTERNAL, "internal error"), Some(h)),
        Err(mpsc::RecvTimeoutError::Timeout) => (Reply::error(id, TIMEOUT, "request timed out"), Some(h)),
    }
}

fn connection(s: UnixStream, rt: Arc<Runtime>, cfg: Arc<ServerConfig>, stop: &'static AtomicBool) {
    if s.set_write_timeout(Some(cfg.idle_timeout)).is_err() {
        return;
    }
    let mut r = BufReader::new(Deadline {
        s: &s,
        until: Instant::now(),
        stop,
    });
    loop {
        r.get_mut().until = Instant::now() + cfg.idle_timeout;
        let frame = match read_frame(&mut r) {
            Ok(Some(f)) => f,
            Ok(None) => return,
            Err(FrameError::TooLarge) => {
                log("closed a connection: request line over the cap");
                let why = format!("invalid request: line longer than {MAX_FRAME} bytes");
                let _ = send(&s, &Reply::error(Id::Null, INVALID_REQUEST, why));
                return;
            }
            Err(FrameError::Io(_)) => return,
        };
        let req = match parse_request(&frame) {
            Ok(req) => req,
            Err(reply) => {
                if send(&s, &reply).is_err() {
                    return;
                }
                continue;
            }
        };
        // A notification: nothing to run (every method only reads), nothing to say.
        let Some(id) = req.id.clone() else { continue };
        let (reply, handler) = run(&rt, req, id, cfg.request_timeout);
        let timed_out = matches!(reply, Reply::Err { code: TIMEOUT, .. });
        let sent = send(&s, &reply);
        if timed_out {
            log("a request timed out: connection closed");
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
        // The slot stays taken until the method has returned.
        if let Some(h) = handler {
            let _ = h.join();
        }
        if timed_out || sent.is_err() {
            return;
        }
    }
}

/// Serves `rt` until `stop` is set: on `listener` (inherited; never removed) or on a socket bound at `cfg.socket`
/// (removed at the end).
pub fn serve(
    rt: Arc<Runtime>,
    cfg: ServerConfig,
    listener: Option<UnixListener>,
    stop: &'static AtomicBool,
) -> Result<(), ServeError> {
    let (listener, bound) = match listener {
        Some(l) => {
            log("serving the inherited socket");
            (l, None)
        }
        None => {
            let (l, b) = bind_socket(&cfg.socket)?;
            log(&format!("listening on {}", shown(&cfg.socket)));
            (l, Some(b))
        }
    };
    let result = accept_loop(&listener, rt, Arc::new(cfg), stop);
    drop(listener);
    if let Some(b) = bound {
        b.remove();
    }
    log("stopped");
    result
}

fn accept_loop(
    listener: &UnixListener,
    rt: Arc<Runtime>,
    cfg: Arc<ServerConfig>,
    stop: &'static AtomicBool,
) -> Result<(), ServeError> {
    listener.set_nonblocking(true).map_err(io("cannot use the socket"))?;
    let active = Arc::new(AtomicUsize::new(0));
    let me = euid();
    while !stop.load(Ordering::SeqCst) {
        let mut pfd = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid `pollfd` for the listener, which outlives the call.
        let r = unsafe { libc::poll(&mut pfd, 1, TICK.as_millis() as libc::c_int) };
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io("cannot wait for connections")(e));
        }
        loop {
            let s = match listener.accept() {
                Ok((s, _)) => s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    // Out of fds or memory: back off instead of spinning on the pending connection.
                    log("accept failed; backing off");
                    thread::sleep(TICK);
                    break;
                }
            };
            if !peer_allowed(&s, me) {
                log("refused a connection from another user");
                continue;
            }
            if active.load(Ordering::SeqCst) >= cfg.max_connections {
                // Never block the accept loop on a client: one non-blocking attempt, then close.
                let _ = s.set_nonblocking(true);
                let _ = send(&s, &Reply::error(Id::Null, BUSY, "server busy"));
                log("refused a connection: too many connections");
                continue;
            }
            if s.set_nonblocking(false).is_err() {
                continue;
            }
            active.fetch_add(1, Ordering::SeqCst);
            let slot = Slot(active.clone());
            let (rt, cfg) = (rt.clone(), cfg.clone());
            let spawned = thread::Builder::new().spawn(move || {
                let _slot = slot;
                connection(s, rt, cfg, stop);
            });
            if spawned.is_err() {
                log("cannot start a connection thread");
            }
        }
    }
    let until = Instant::now() + GRACE;
    while active.load(Ordering::SeqCst) > 0 && Instant::now() < until {
        thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{plant, rt};
    use serde_json::{Value, json};
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::symlink;

    fn flag() -> &'static AtomicBool {
        Box::leak(Box::new(AtomicBool::new(false)))
    }

    /// A server over `rt` on `<dir>/run/runtimed.sock`, tuned by `tune`.
    struct Srv {
        sock: PathBuf,
        stop: &'static AtomicBool,
        done: Option<thread::JoinHandle<Result<(), ServeError>>>,
    }

    impl Srv {
        fn start(dir: &Path, rt: Arc<Runtime>, tune: impl FnOnce(&mut ServerConfig)) -> Srv {
            let sock = dir.join("run").join("runtimed.sock");
            let mut cfg = ServerConfig::new(sock.clone());
            tune(&mut cfg);
            let stop = flag();
            let done = Some(thread::spawn(move || serve(rt, cfg, None, stop)));
            let until = Instant::now() + Duration::from_secs(5);
            // Mode 0600 is set after bind+listen; a probe connection would take a slot for a moment.
            while fs::symlink_metadata(&sock).map(|m| m.mode() & 0o777).ok() != Some(0o600) {
                assert!(Instant::now() < until, "the server did not come up");
                thread::sleep(Duration::from_millis(10));
            }
            Srv { sock, stop, done }
        }

        fn conn(&self) -> Conn {
            Conn::new(UnixStream::connect(&self.sock).unwrap())
        }

        /// Stops the server; how long `serve` took to return.
        fn stop(&mut self) -> Duration {
            let t = Instant::now();
            self.stop.store(true, Ordering::SeqCst);
            self.done.take().unwrap().join().unwrap().unwrap();
            t.elapsed()
        }
    }

    impl Drop for Srv {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    struct Conn {
        r: BufReader<UnixStream>,
    }

    impl Conn {
        fn new(s: UnixStream) -> Conn {
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
            Conn { r: BufReader::new(s) }
        }

        fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
            self.r.get_mut().write_all(bytes)
        }

        /// The next reply line, or `None` at EOF (or a reset).
        fn recv(&mut self) -> Option<Value> {
            let mut line = String::new();
            match self.r.read_line(&mut line) {
                Ok(0) | Err(_) => None,
                Ok(_) => Some(serde_json::from_str(&line).unwrap()),
            }
        }

        fn call(&mut self, method: &str, params: Value) -> Value {
            let line = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).to_string();
            self.send(format!("{line}\n").as_bytes()).unwrap();
            self.recv().expect("a reply")
        }
    }

    fn code(v: &Value) -> i64 {
        v["error"]["code"]
            .as_i64()
            .unwrap_or_else(|| panic!("not an error: {v}"))
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().mode() & 0o7777
    }

    /// What the runtime answers for `method`, serialised the way the daemon must send it.
    fn direct(rt: &Runtime, method: &str, id: &str) -> Value {
        fn v<T: serde::Serialize>(r: Result<T, rt_api::ApiError>) -> Value {
            match r {
                Ok(x) => json!({ "result": x }),
                Err(e) => json!({ "error": { "message": e.message, "kind": e.kind } }),
            }
        }
        match method {
            "rpc.version" => v(Ok(rt.version())),
            "apps.list" => v(Ok(rt.apps())),
            "apps.get" => v(rt.app(id)),
            "permissions.get" => v(rt.permissions(id)),
            "compat.list" => v(Ok(rt.compat())),
            "doctor.system" => v(rt.doctor(rt_api::DoctorTarget::System)),
            "doctor.app" => v(rt.doctor(rt_api::DoctorTarget::App(id.into()))),
            "graphics.info" => v(Ok(rt.graphics_info())),
            "sandbox.info" => v(rt.sandbox_info(id)),
            "deps.plan" => v(rt.deps_plan(id)),
            m => panic!("{m}"),
        }
    }

    /// The same shape out of a reply.
    fn wire(reply: &Value) -> Value {
        match reply.get("result") {
            Some(r) => json!({ "result": r }),
            None => {
                assert_eq!(code(reply), -32000, "{reply}");
                json!({ "error": { "message": reply["error"]["message"], "kind": reply["error"]["data"]["kind"] } })
            }
        }
    }

    const ID_METHODS: &[&str] = &["apps.get", "permissions.get", "doctor.app", "sandbox.info", "deps.plan"];

    fn params(method: &str, id: &str) -> Value {
        if ID_METHODS.contains(&method) {
            json!({ "id": id })
        } else {
            json!({})
        }
    }

    #[test]
    fn every_method_over_the_socket_is_exactly_the_runtime_answer() {
        let (d, rt) = rt();
        plant(d.path(), "game", "Game");
        let rt = Arc::new(rt.with_runtime_exe(d.path().join("no-runtime-here")));
        let srv = Srv::start(d.path(), rt.clone(), |_| {});
        let mut c = srv.conn();
        for m in crate::dispatch::METHODS {
            for id in ["game", "nope"] {
                let got = wire(&c.call(m, params(m, id)));
                assert_eq!(got, direct(&rt, m, id), "{m} {id}");
                if !ID_METHODS.contains(m) {
                    break;
                }
            }
        }
    }

    const HOSTILE: &str = "a\x1b[31m\u{202e}b\u{200b}c\nd\u{0085}e\u{7}";

    fn walk(v: &Value, at: &str) {
        let clean = |s: &str| !s.chars().any(|c| c.is_control() || rt_core::is_format(c));
        match v {
            Value::String(s) => assert!(clean(s), "{at}: {s:?}"),
            Value::Array(a) => a.iter().for_each(|x| walk(x, at)),
            Value::Object(o) => o.iter().for_each(|(k, x)| {
                assert!(clean(k), "{at}: key {k:?}");
                walk(x, &format!("{at}.{k}"));
            }),
            _ => {}
        }
    }

    #[test]
    fn hostile_store_content_and_ids_never_reach_the_wire_unclean() {
        let (d, rt) = rt();
        plant(d.path(), "evil", HOSTILE);
        plant(d.path(), "fine", "Fine");
        // A hostile, unreadable metadata file and a hostile permissions file.
        let apps = d.path().join("apps");
        fs::write(
            apps.join("fine/permissions.toml"),
            format!("version = 1\n{HOSTILE:?} = 1\n"),
        )
        .unwrap();
        let broken = apps.join("broken");
        fs::create_dir_all(&broken).unwrap();
        fs::write(broken.join("metadata.json"), HOSTILE).unwrap();
        let srv = Srv::start(d.path(), Arc::new(rt), |_| {});
        let mut c = srv.conn();
        for m in crate::dispatch::METHODS {
            for id in ["evil", "fine", "broken", HOSTILE, "\u{202e}x", &"é".repeat(5000)] {
                let v = c.call(m, params(m, id));
                walk(&v, &format!("{m}({id:?})"));
                if !ID_METHODS.contains(m) {
                    break;
                }
            }
        }
        // Protocol-level errors that quote client input.
        c.send(
            format!(
                "{{\"jsonrpc\":\"2.0\",\"method\":\"apps.get\",\"params\":{{\"id\":\"x\",{HOSTILE:?}:1}},\"id\":2}}\n"
            )
            .as_bytes(),
        )
        .unwrap();
        walk(&c.recv().unwrap(), "unknown param");
        c.send(format!("{{\"jsonrpc\":\"2.0\",\"method\":{HOSTILE:?},\"id\":3}}\n").as_bytes())
            .unwrap();
        walk(&c.recv().unwrap(), "hostile method");
    }

    #[test]
    fn the_socket_is_0600_in_a_0700_dir_and_is_removed_on_stop() {
        let (d, rt) = rt();
        let mut srv = Srv::start(d.path(), Arc::new(rt), |_| {});
        assert_eq!(mode(srv.sock.parent().unwrap()), 0o700);
        assert_eq!(mode(&srv.sock), 0o600);
        assert!(fs::symlink_metadata(&srv.sock).unwrap().file_type().is_socket());
        assert!(srv.stop() < Duration::from_secs(1));
        assert!(!srv.sock.exists());
    }

    #[test]
    fn unsafe_places_are_refused_and_left_alone() {
        let d = tempfile::tempdir().unwrap();
        let refused = |p: &Path| match bind_socket(p) {
            Err(ServeError::Unsafe { .. }) => {}
            r => panic!("{p:?}: {:?}", r.map(|_| ())),
        };
        // Group-writable, world-readable directories.
        for m in [0o770, 0o705, 0o720] {
            let dir = d.path().join(format!("m{m:o}"));
            fs::create_dir(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(m)).unwrap();
            refused(&dir.join("s.sock"));
            assert_eq!(mode(&dir), m, "the mode was changed");
        }
        // A symlinked directory, even to a good one.
        let good = d.path().join("good");
        fs::create_dir(&good).unwrap();
        fs::set_permissions(&good, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&good, d.path().join("link")).unwrap();
        refused(&d.path().join("link/s.sock"));
        // A file, a directory and a symlink at the socket path are not replaced.
        let file = good.join("file.sock");
        fs::write(&file, "keep").unwrap();
        refused(&file);
        assert_eq!(fs::read_to_string(&file).unwrap(), "keep");
        fs::create_dir(good.join("dir.sock")).unwrap();
        refused(&good.join("dir.sock"));
        let real = good.join("real.sock");
        let _live = UnixListener::bind(&real).unwrap();
        symlink(&real, good.join("sym.sock")).unwrap();
        refused(&good.join("sym.sock"));
        assert!(
            fs::symlink_metadata(good.join("sym.sock"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        // A relative path.
        refused(Path::new("rel/s.sock"));
        // A live socket: another daemon.
        assert!(matches!(bind_socket(&real), Err(ServeError::AlreadyRunning(_))));
        assert!(real.exists());
    }

    #[test]
    fn a_stale_socket_is_replaced() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("run");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let sock = dir.join("s.sock");
        drop(UnixListener::bind(&sock).unwrap());
        assert!(sock.exists());
        let (l, b) = bind_socket(&sock).unwrap();
        assert_eq!(mode(&sock), 0o600);
        let _c = UnixStream::connect(&sock).unwrap();
        drop(l);
        b.remove();
        assert!(!sock.exists());
    }

    #[test]
    fn default_path_needs_an_absolute_runtime_dir() {
        let env = |v: Option<&'static str>| {
            move |k: &str| (k == "XDG_RUNTIME_DIR").then_some(v).flatten().map(OsString::from)
        };
        assert_eq!(
            default_socket_path_from(&env(Some("/run/user/1000"))).unwrap(),
            Path::new("/run/user/1000/runtime/runtimed.sock")
        );
        assert!(matches!(
            default_socket_path_from(&env(None)),
            Err(ServeError::NoRuntimeDir)
        ));
        assert!(matches!(
            default_socket_path_from(&env(Some("run"))),
            Err(ServeError::NoRuntimeDir)
        ));
    }

    #[test]
    fn the_peer_check_compares_the_real_peer_uid() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), euid());
        assert!(peer_allowed(&a, euid()));
        assert!(!peer_allowed(&a, euid().wrapping_add(1)));
        assert!(!peer_allowed(&a, 0) || euid() == 0);
    }

    #[test]
    fn the_connection_cap_turns_the_33rd_away_and_frees_slots() {
        let (d, rt) = rt();
        let srv = Srv::start(d.path(), Arc::new(rt), |_| {});
        let mut held: Vec<Conn> = (0..32).map(|_| srv.conn()).collect();
        for c in &mut held {
            assert!(c.call("rpc.version", json!({}))["result"].is_object());
        }
        for _ in 0..3 {
            let mut extra = srv.conn();
            let v = extra.recv().expect("a busy line");
            assert_eq!((code(&v), v["id"].is_null()), (-32001, true));
            assert!(extra.recv().is_none(), "closed after the busy line");
        }
        // The held ones still work; closing one frees a slot.
        assert!(held[5].call("apps.list", json!({}))["result"].is_object());
        drop(held.pop());
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let mut c = srv.conn();
            // Busy until the server has seen the close: the send may meet a closed socket.
            let _ = c.send(b"{\"jsonrpc\":\"2.0\",\"method\":\"rpc.version\",\"id\":9}\n");
            if c.recv().is_some_and(|v| v.get("result").is_some()) {
                break;
            }
            assert!(Instant::now() < until, "no slot freed");
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_line_over_the_cap_is_refused_and_closed_one_at_the_cap_is_served() {
        let (d, rt) = rt();
        let srv = Srv::start(d.path(), Arc::new(rt), |_| {});
        let req = br#"{"jsonrpc":"2.0","method":"rpc.version","id":1}"#;
        let mut at = req.to_vec();
        at.resize(MAX_FRAME, b' ');
        at.push(b'\n');
        let mut c = srv.conn();
        c.send(&at).unwrap();
        assert!(c.recv().unwrap()["result"].is_object());
        // One byte more, and no newline ever: refused as soon as the cap is passed.
        let mut c = srv.conn();
        let s = c.r.get_ref().try_clone().unwrap();
        let w = thread::spawn(move || {
            let mut s = s;
            let _ = s.write_all(&vec![b' '; MAX_FRAME + 1]);
        });
        let v = c.recv().expect("the refusal");
        assert_eq!((code(&v), v["id"].is_null()), (-32600, true));
        assert!(c.recv().is_none());
        w.join().unwrap();
    }

    #[test]
    fn idle_and_slow_clients_are_cut_by_the_line_deadline() {
        let (d, rt) = rt();
        let srv = Srv::start(d.path(), Arc::new(rt), |c| c.idle_timeout = Duration::from_millis(300));
        // Silent.
        let mut c = srv.conn();
        let t = Instant::now();
        assert!(c.recv().is_none());
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        // A partial line, then nothing.
        let mut c = srv.conn();
        c.send(b"{\"jsonrpc\":").unwrap();
        assert!(c.recv().is_none());
        // One byte every 50 ms: each read is quick, the line is not.
        let mut c = srv.conn();
        let t = Instant::now();
        let line = b"{\"jsonrpc\":\"2.0\",\"method\":\"rpc.version\",\"id\":1}\n";
        let mut cut = false;
        for b in line {
            if c.send(&[*b]).is_err() {
                cut = true;
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(cut || c.recv().is_none(), "a slow drip was served");
        assert!(t.elapsed() < Duration::from_secs(5));
        // A prompt client after a reply gets a fresh deadline.
        let mut c = srv.conn();
        for _ in 0..3 {
            thread::sleep(Duration::from_millis(150));
            assert!(c.call("rpc.version", json!({}))["result"].is_object());
        }
    }

    #[test]
    fn a_panic_is_an_internal_error_and_the_daemon_keeps_serving() {
        let (d, rt) = rt();
        let srv = Srv::start(d.path(), Arc::new(rt), |_| {});
        let mut c = srv.conn();
        let v = c.call("test.panic", json!({}));
        assert_eq!(
            (code(&v), v["error"]["message"].as_str()),
            (-32603, Some("internal error"))
        );
        assert!(c.call("rpc.version", json!({}))["result"].is_object());
        assert!(srv.conn().call("apps.list", json!({}))["result"].is_object());
    }

    #[test]
    fn a_slow_request_times_out_and_closes_but_holds_its_slot_until_done() {
        let (d, rt) = rt();
        let srv = Srv::start(d.path(), Arc::new(rt), |c| {
            c.request_timeout = Duration::from_millis(100);
            c.max_connections = 1;
        });
        let mut c = srv.conn();
        let v = c.call("test.sleep", json!({}));
        assert_eq!((code(&v), v["id"].as_i64()), (-32002, Some(1)));
        assert!(c.recv().is_none());
        // The method still runs (600 ms): the single slot is taken until then.
        let v = srv.conn().recv().unwrap();
        assert_eq!(code(&v), -32001);
        thread::sleep(Duration::from_millis(900));
        assert!(srv.conn().call("rpc.version", json!({}))["result"].is_object());
    }

    #[test]
    fn notifications_half_closes_and_pipelining() {
        let (d, rt) = rt();
        let srv = Srv::start(d.path(), Arc::new(rt), |_| {});
        let mut c = srv.conn();
        c.send(
            b"{\"jsonrpc\":\"2.0\",\"method\":\"rpc.version\"}\n\
              [1]\n\
              {\"jsonrpc\":\"2.0\",\"method\":\"rpc.version\",\"id\":\"b\"}\n\
              {\"jsonrpc\":\"2.0\",\"method\":\"rpc.version\",\"id\":null}",
        )
        .unwrap();
        c.r.get_ref().shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(code(&c.recv().unwrap()), -32600);
        assert_eq!(c.recv().unwrap()["id"], "b");
        let last = c.recv().unwrap();
        assert!(last["id"].is_null() && last["result"].is_object());
        assert!(c.recv().is_none());
    }

    #[test]
    fn concurrent_clients_all_get_their_answers() {
        let (d, rt) = rt();
        plant(d.path(), "game", "Game");
        let rt = Arc::new(rt);
        let srv = Srv::start(d.path(), rt.clone(), |_| {});
        let want = serde_json::to_value(rt.app("game").unwrap()).unwrap();
        let workers: Vec<_> = (0..16)
            .map(|i| {
                let mut c = srv.conn();
                let want = want.clone();
                thread::spawn(move || {
                    for n in 0..50 {
                        let id = i * 1000 + n;
                        let line = json!({"jsonrpc":"2.0","method":"apps.get","params":{"id":"game"},"id":id});
                        c.send(format!("{line}\n").as_bytes()).unwrap();
                        let v = c.recv().unwrap();
                        assert_eq!((v["id"].as_i64(), &v["result"]), (Some(id), &want));
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }
    }

    #[test]
    fn stopping_lets_the_request_in_flight_finish() {
        let (d, rt) = rt();
        let mut srv = Srv::start(d.path(), Arc::new(rt), |_| {});
        let mut idle = srv.conn();
        let mut busy = srv.conn();
        busy.send(b"{\"jsonrpc\":\"2.0\",\"method\":\"test.sleep\",\"id\":7}\n")
            .unwrap();
        thread::sleep(Duration::from_millis(100));
        let took = srv.stop();
        assert!(took < GRACE, "{took:?}");
        assert_eq!(busy.recv().unwrap()["result"], "slept");
        assert!(idle.recv().is_none());
        assert!(!srv.sock.exists());
        assert!(UnixStream::connect(&srv.sock).is_err());
    }

    #[test]
    fn an_inherited_listener_is_served_and_not_removed() {
        let (d, rt) = rt();
        let sock = d.path().join("act.sock");
        let l = UnixListener::bind(&sock).unwrap();
        let stop = flag();
        let cfg = ServerConfig::new(d.path().join("unused/never.sock"));
        let h = thread::spawn(move || serve(Arc::new(rt), cfg, Some(l), stop));
        let mut c = Conn::new(UnixStream::connect(&sock).unwrap());
        assert!(c.call("rpc.version", json!({}))["result"].is_object());
        stop.store(true, Ordering::SeqCst);
        h.join().unwrap().unwrap();
        assert!(sock.exists(), "an inherited socket is systemd's to remove");
        assert!(!d.path().join("unused").exists());
    }

    fn env(pairs: &[(&'static str, String)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let pairs = pairs.to_vec();
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| OsString::from(v))
    }

    /// `fd` duplicated to a fresh number the test owns.
    fn dup(fd: RawFd) -> RawFd {
        // SAFETY: `fd` is open; the duplicate is closed by whoever takes it (or leaks in the test).
        let r = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 100) };
        assert!(r >= 0);
        r
    }

    #[test]
    fn activation_checks_pid_count_and_socket_kind() {
        let d = tempfile::tempdir().unwrap();
        let me = std::process::id();
        let ours = |fds: &str| env(&[("LISTEN_PID", me.to_string()), ("LISTEN_FDS", fds.into())]);
        // Not for us: ignored.
        assert!(listener_from(&env(&[]), me, 3).unwrap().is_none());
        let other = env(&[("LISTEN_PID", (me + 1).to_string()), ("LISTEN_FDS", "1".into())]);
        assert!(listener_from(&other, me, 3).unwrap().is_none());
        let junk = env(&[("LISTEN_PID", "x".into()), ("LISTEN_FDS", "1".into())]);
        assert!(listener_from(&junk, me, 3).unwrap().is_none());
        // For us but wrong.
        for n in ["0", "2", "", "1 "] {
            assert!(
                matches!(listener_from(&ours(n), me, 3), Err(ServeError::Activation(_))),
                "{n:?}"
            );
        }
        assert!(matches!(
            listener_from(&env(&[("LISTEN_PID", me.to_string())]), me, 3),
            Err(ServeError::Activation(_))
        ));
        let file = fs::File::create(d.path().join("f")).unwrap();
        let (a, _b) = UnixStream::pair().unwrap();
        let dgram = std::os::unix::net::UnixDatagram::unbound().unwrap();
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        for fd in [file.as_raw_fd(), a.as_raw_fd(), dgram.as_raw_fd(), tcp.as_raw_fd(), 999] {
            assert!(
                matches!(listener_from(&ours("1"), me, fd), Err(ServeError::Activation(_))),
                "fd {fd}"
            );
        }
        // A listening Unix stream socket: taken over.
        let l = UnixListener::bind(d.path().join("l.sock")).unwrap();
        let got = listener_from(&ours("1"), me, dup(l.as_raw_fd())).unwrap().unwrap();
        drop(l);
        let _c = UnixStream::connect(d.path().join("l.sock")).unwrap();
        got.set_nonblocking(true).unwrap();
        assert!(got.accept().is_ok());
    }
}
