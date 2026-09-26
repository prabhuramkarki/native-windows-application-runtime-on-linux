//! A client for `runtimed`: [`Client::connect`], then [`Client::call`] (any method, raw JSON) or a typed helper
//! per method returning the `rt_api` wire type.
//!
//! **Whom it talks to.** Before a byte is sent the socket must pass the daemon's own placement rules, from the
//! client's side: the directory is not a symlink, is ours and is closed to group and others; the socket is a
//! socket, ours, and closed to group and others; and once connected, the peer's `SO_PEERCRED` uid is ours. A
//! socket someone else planted at the path (another user's, or in a directory others can write) never receives
//! a request. The connect itself is non-blocking with a deadline, so a daemon that never accepts cannot hang it.
//!
//! **What it believes.** A reply is untrusted data: it must be one JSON-RPC 2.0 object on one line of at most
//! [`MAX_REPLY`] bytes, arrive whole within the call's timeout, carry our id (or `null` on an error: the daemon's
//! busy and oversize replies cannot know it), and hold exactly one of `result`/`error`. Anything else is a
//! [`ClientError::Protocol`], never a panic, and the connection is not used again. Strings are NOT cleaned here
//! (a raw client shows the daemon's answer as it is); they are only bounded in errors. Whoever puts them on a
//! terminal escapes them (the CLI's `rpc` does).
use crate::protocol::{DOMAIN, FrameError, MAX_FRAME, read_frame_max};
use crate::server;
use rt_api::{
    ApiError, AppDetail, AppList, CompatView, DepsPlanView, DoctorView, ErrorKind, GraphicsView, PermissionsView,
    SandboxView, VersionInfo,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::io::{self, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The longest reply line accepted. Replies may exceed the 1 MiB request cap: `apps.list` over the store's
/// 10,000-entry cap with long executables runs to several MiB.
pub const MAX_REPLY: usize = 16 << 20;
/// How long a call (and the connect) may take by default: longer than the daemon's own 30 s request deadline.
pub const TIMEOUT: Duration = Duration::from_secs(40);
/// The longest error message and `data.kind` kept from a reply, in characters.
const MAX_TEXT: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("XDG_RUNTIME_DIR is unset or not an absolute path: pass --socket PATH")]
    NoRuntimeDir,
    #[error("refusing {path}: {why}")]
    Unsafe { path: String, why: &'static str },
    #[error("no daemon at {path}: {err}")]
    Unreachable { path: String, err: io::Error },
    #[error("the request is longer than {MAX_FRAME} bytes")]
    TooLarge,
    #[error("connection failed: {0}")]
    Io(io::Error),
    #[error("bad reply from the daemon: {0}")]
    Protocol(&'static str),
    /// A JSON-RPC error reply. `message` is the daemon's text (bounded, not cleaned).
    #[error("{message} (code {code})")]
    Rpc {
        code: i64,
        message: String,
        kind: Option<String>,
    },
}

impl ClientError {
    /// A domain error (-32000) as the `rt_api` error it was (an unknown kind is [`ErrorKind::Unknown`]).
    pub fn api_error(&self) -> Option<ApiError> {
        match self {
            ClientError::Rpc { code, message, kind } if *code == i64::from(DOMAIN) => {
                let kind = kind.clone().map_or(Value::Null, Value::String);
                Some(ApiError::new(
                    serde_json::from_value(kind).unwrap_or(ErrorKind::Unknown),
                    message,
                ))
            }
            _ => None,
        }
    }
}

/// `$XDG_RUNTIME_DIR/runtime/runtimed.sock`, where `runtimed` listens by default.
pub fn default_socket_path() -> Result<PathBuf, ClientError> {
    server::default_socket_path().map_err(|_| ClientError::NoRuntimeDir)
}

pub struct Client {
    s: UnixStream,
    timeout: Duration,
    next: i64,
    broken: bool,
}

impl Client {
    /// Connects to `path` with the default [`TIMEOUT`].
    pub fn connect(path: &Path) -> Result<Client, ClientError> {
        Client::connect_with(path, TIMEOUT)
    }

    /// Connects to `path`; `timeout` bounds the connect and then each call.
    pub fn connect_with(path: &Path, timeout: Duration) -> Result<Client, ClientError> {
        connect_as(path, timeout, server::euid())
    }

    /// Calls `method` with `params` (`null` for none, else an object) and returns its `result`.
    /// An error reply leaves the connection usable; any other failure (a timeout, a bad reply) ends it: later
    /// calls fail at once instead of reading a stale reply.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, ClientError> {
        if self.broken {
            return Err(ClientError::Protocol("the connection failed earlier"));
        }
        let id = self.next;
        let mut req = json!({"jsonrpc": "2.0", "method": method, "id": id});
        if !params.is_null() {
            req["params"] = params;
        }
        let mut line = req.to_string().into_bytes();
        if line.len() > MAX_FRAME {
            return Err(ClientError::TooLarge);
        }
        line.push(b'\n');
        self.next = self.next.wrapping_add(1);
        self.broken = true;
        let until = Instant::now() + self.timeout;
        let sent = write_by(&self.s, &line, until);
        // The daemon may have answered and closed (busy, oversize) before our write: its reply says more than
        // the write error does.
        let r = match (self.read_reply(id, until), sent) {
            (Err(ClientError::Protocol(_) | ClientError::Io(_)), Err(e)) => Err(ClientError::Io(e)),
            (r, _) => r,
        };
        if matches!(r, Ok(_) | Err(ClientError::Rpc { .. })) {
            self.broken = false;
        }
        r
    }

    fn read_reply(&mut self, id: i64, until: Instant) -> Result<Value, ClientError> {
        let mut r = BufReader::new(Deadline { s: &self.s, until });
        match read_frame_max(&mut r, MAX_REPLY) {
            Ok(Some(frame)) => parse_reply(&frame, id),
            Ok(None) => Err(ClientError::Protocol(
                "the daemon closed the connection without a reply",
            )),
            Err(FrameError::TooLarge) => Err(ClientError::Protocol("reply longer than 16 MiB")),
            Err(FrameError::Io(e)) => Err(ClientError::Io(e)),
        }
    }

    fn typed<T: DeserializeOwned>(&mut self, method: &str, params: Value) -> Result<T, ClientError> {
        let v = self.call(method, params)?;
        serde_json::from_value(v).map_err(|_| ClientError::Protocol("the result does not have the expected shape"))
    }

    pub fn version(&mut self) -> Result<VersionInfo, ClientError> {
        self.typed("rpc.version", Value::Null)
    }
    pub fn apps(&mut self) -> Result<AppList, ClientError> {
        self.typed("apps.list", Value::Null)
    }
    pub fn app(&mut self, id: &str) -> Result<AppDetail, ClientError> {
        self.typed("apps.get", json!({ "id": id }))
    }
    pub fn permissions(&mut self, id: &str) -> Result<PermissionsView, ClientError> {
        self.typed("permissions.get", json!({ "id": id }))
    }
    pub fn compat(&mut self) -> Result<CompatView, ClientError> {
        self.typed("compat.list", Value::Null)
    }
    pub fn doctor_system(&mut self) -> Result<DoctorView, ClientError> {
        self.typed("doctor.system", Value::Null)
    }
    pub fn doctor_app(&mut self, id: &str) -> Result<DoctorView, ClientError> {
        self.typed("doctor.app", json!({ "id": id }))
    }
    pub fn graphics_info(&mut self) -> Result<GraphicsView, ClientError> {
        self.typed("graphics.info", Value::Null)
    }
    pub fn sandbox_info(&mut self, id: &str) -> Result<SandboxView, ClientError> {
        self.typed("sandbox.info", json!({ "id": id }))
    }
    pub fn deps_plan(&mut self, id: &str) -> Result<DepsPlanView, ClientError> {
        self.typed("deps.plan", json!({ "id": id }))
    }
}

/// [`Client::connect_with`], trusting only uid `me` (tests pass another uid to see a refusal).
fn connect_as(path: &Path, timeout: Duration, me: u32) -> Result<Client, ClientError> {
    check_place(path, me)?;
    let unreachable = |err| ClientError::Unreachable { path: shown(path), err };
    let until = Instant::now() + timeout;
    // Non-blocking, retried while the backlog is full: a daemon that never accepts cannot hang us.
    let s = loop {
        match server::connect_nonblocking(path) {
            Ok(s) => break s,
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) && Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {
                return Err(unreachable(io::ErrorKind::TimedOut.into()));
            }
            Err(e) => return Err(unreachable(e)),
        }
    };
    s.set_nonblocking(false).map_err(ClientError::Io)?;
    if !server::peer_allowed(&s, me) {
        return Err(ClientError::Unsafe {
            path: shown(path),
            why: "the daemon runs as another user",
        });
    }
    Ok(Client {
        s,
        timeout,
        next: 1,
        broken: false,
    })
}

/// A path for messages: printable and bounded.
fn shown(p: &Path) -> String {
    rt_core::clean_text(&p.to_string_lossy(), 512)
}

/// The daemon's placement rules from the client's side (module docs). A missing directory or socket is
/// [`ClientError::Unreachable`]; anything in the way that is not safe is [`ClientError::Unsafe`].
fn check_place(path: &Path, me: u32) -> Result<(), ClientError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let refuse = |why| ClientError::Unsafe { path: shown(path), why };
    if !path.is_absolute() {
        return Err(refuse("the socket path must be absolute"));
    }
    let dir = path.parent().ok_or_else(|| refuse("no directory"))?;
    let lstat =
        |p: &Path| std::fs::symlink_metadata(p).map_err(|err| ClientError::Unreachable { path: shown(path), err });
    let m = lstat(dir)?;
    if m.file_type().is_symlink() {
        return Err(refuse("the socket directory is a symlink"));
    } else if !m.is_dir() {
        return Err(refuse("the socket directory is not a directory"));
    } else if m.uid() != me {
        return Err(refuse("the socket directory belongs to another user"));
    } else if m.mode() & 0o077 != 0 {
        return Err(refuse("the socket directory is open to group or others"));
    }
    let m = lstat(path)?;
    if !m.file_type().is_socket() {
        Err(refuse("not a socket"))
    } else if m.uid() != me {
        Err(refuse("the socket belongs to another user"))
    } else if m.mode() & 0o077 != 0 {
        Err(refuse("the socket is open to group or others"))
    } else {
        Ok(())
    }
}

/// Reads from the socket until `until`, however the bytes trickle in: a reply must arrive whole in time.
struct Deadline<'a> {
    s: &'a UnixStream,
    until: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let left = self.until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.s.set_read_timeout(Some(left))?;
            match (&mut &*self.s).read(buf) {
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
                r => return r,
            }
        }
    }
}

/// Writes `line` whole before `until`.
fn write_by(s: &UnixStream, line: &[u8], until: Instant) -> io::Result<()> {
    let mut at = 0;
    while at < line.len() {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        s.set_write_timeout(Some(left))?;
        match (&mut &*s).write(&line[at..]) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => at += n,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn bounded(s: &str) -> String {
    s.chars().take(MAX_TEXT).collect()
}

/// One reply line: the `result` of request `id`, its error as [`ClientError::Rpc`], or a protocol error.
fn parse_reply(frame: &[u8], id: i64) -> Result<Value, ClientError> {
    let bad = ClientError::Protocol;
    let Ok(Value::Object(mut o)) = serde_json::from_slice::<Value>(frame) else {
        return Err(bad("not a JSON object"));
    };
    if o.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(bad("not JSON-RPC 2.0"));
    }
    let ours = o.get("id").and_then(Value::as_i64) == Some(id);
    match (o.remove("result"), o.remove("error")) {
        (Some(r), None) if ours => Ok(r),
        (Some(_), None) => Err(bad("a reply to another request")),
        (None, Some(Value::Object(e))) if ours || o.get("id") == Some(&Value::Null) => {
            let code = e
                .get("code")
                .and_then(Value::as_i64)
                .ok_or(bad("an error without an integer code"))?;
            let message = e
                .get("message")
                .and_then(Value::as_str)
                .ok_or(bad("an error without a message"))?;
            let kind = e.get("data").and_then(|d| d.get("kind")).and_then(Value::as_str);
            Err(ClientError::Rpc {
                code,
                message: bounded(message),
                kind: kind.map(bounded),
            })
        }
        (None, Some(Value::Object(_))) => Err(bad("a reply to another request")),
        _ => Err(bad("not exactly one of result and error")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{ServerConfig, serve};
    use crate::testutil::{plant, rt};
    use rt_api::Runtime;
    use std::fs;
    use std::io::BufRead;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    const SHORT: Duration = Duration::from_millis(400);

    /// `<dir>/run` created 0700: where every test socket lives.
    fn run_dir(dir: &Path) -> PathBuf {
        let run = dir.join("run");
        fs::DirBuilder::new().mode(0o700).create(&run).unwrap();
        run
    }

    /// A real server over `rt` (cap `max`); the flag stops it.
    fn daemon(dir: &Path, rt: Runtime, max: usize) -> (PathBuf, &'static AtomicBool) {
        let sock = run_dir(dir).join("d.sock");
        let mut cfg = ServerConfig::new(sock.clone());
        cfg.max_connections = max;
        let stop: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
        thread::spawn(move || serve(Arc::new(rt), cfg, None, stop));
        let until = Instant::now() + Duration::from_secs(5);
        use std::os::unix::fs::MetadataExt;
        while fs::symlink_metadata(&sock).map(|m| m.mode() & 0o777).ok() != Some(0o600) {
            assert!(Instant::now() < until, "the server did not come up");
            thread::sleep(Duration::from_millis(10));
        }
        (sock, stop)
    }

    /// A one-connection fake daemon at `<dir>/run/f.sock`: reads one request line, hands it to `answer`, which
    /// writes whatever it likes (and may stall).
    fn fake(dir: &Path, answer: impl FnOnce(&mut UnixStream, Value) + Send + 'static) -> PathBuf {
        let sock = run_dir(dir).join("f.sock");
        let l = UnixListener::bind(&sock).unwrap();
        fs::set_permissions(&sock, fs::Permissions::from_mode(0o600)).unwrap();
        thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&s).read_line(&mut line).unwrap();
            answer(&mut s, serde_json::from_str(&line).unwrap());
        });
        sock
    }

    fn write(s: &mut UnixStream, bytes: &[u8]) {
        let _ = s.write_all(bytes);
    }

    #[test]
    fn every_helper_is_the_runtime_answer() {
        let (d, rt) = rt();
        plant(d.path(), "game", "Game");
        let direct = Runtime::with_store(rt_core::Store::new(d.path().join("apps")).unwrap());
        let (sock, stop) = daemon(d.path(), rt, 4);
        let mut c = Client::connect(&sock).unwrap();
        assert_eq!(c.version().unwrap(), direct.version());
        assert_eq!(c.apps().unwrap(), direct.apps());
        assert_eq!(c.app("game").unwrap(), direct.app("game").unwrap());
        assert_eq!(c.permissions("game").unwrap(), direct.permissions("game").unwrap());
        assert_eq!(c.compat().unwrap(), direct.compat());
        assert_eq!(c.deps_plan("game").unwrap(), direct.deps_plan("game").unwrap());
        // These probe the host: their shape is what is checked here (the daemon tests compare the values).
        assert_eq!(c.doctor_system().unwrap().subject, rt_api::SubjectView::System);
        assert!(matches!(
            c.doctor_app("game").unwrap().subject,
            rt_api::SubjectView::App { .. }
        ));
        c.graphics_info().unwrap();
        c.sandbox_info("game").unwrap();
        // The raw call and the error mapping.
        assert_eq!(c.call("rpc.version", json!({})).unwrap()["api"], rt_api::API_VERSION);
        let e = c.app("nope").unwrap_err();
        match &e {
            ClientError::Rpc { code, kind, .. } => assert_eq!((*code, kind.as_deref()), (-32000, Some("not_found"))),
            e => panic!("{e:?}"),
        }
        assert_eq!(e.api_error().unwrap(), direct.app("nope").unwrap_err());
        let e = c.call("no.such", Value::Null).unwrap_err();
        assert!(
            matches!(
                e,
                ClientError::Rpc {
                    code: -32601,
                    kind: None,
                    ..
                }
            ),
            "{e:?}"
        );
        assert!(e.api_error().is_none());
        // An error reply is not fatal to the connection: the next call is served.
        assert!(c.call("apps.get", json!([1])).is_err());
        assert_eq!(c.version().unwrap(), direct.version());
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn a_busy_daemon_is_an_rpc_error_even_when_the_write_fails() {
        let (d, rt) = rt();
        let (sock, stop) = daemon(d.path(), rt, 0);
        for _ in 0..5 {
            let e = Client::connect_with(&sock, SHORT)
                .and_then(|mut c| c.call("rpc.version", Value::Null))
                .unwrap_err();
            assert!(matches!(e, ClientError::Rpc { code: -32001, .. }), "{e:?}");
        }
        // A request larger than the socket buffer: the write fails (the daemon closed), the busy line is still read.
        let big = json!({ "id": "x".repeat(MAX_FRAME - 100) });
        let e = Client::connect_with(&sock, SHORT)
            .and_then(|mut c| c.call("apps.get", big))
            .unwrap_err();
        assert!(matches!(e, ClientError::Rpc { code: -32001, .. }), "{e:?}");
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn requests_over_the_cap_are_never_sent() {
        let (d, rt) = rt();
        let (sock, stop) = daemon(d.path(), rt, 4);
        let mut c = Client::connect(&sock).unwrap();
        let e = c.call("apps.get", json!({ "id": "x".repeat(MAX_FRAME) })).unwrap_err();
        assert!(matches!(e, ClientError::TooLarge), "{e:?}");
        assert!(c.version().is_ok(), "nothing was sent, the connection is fine");
        stop.store(true, Ordering::SeqCst);
    }

    /// One call through a fake daemon whose answer is `answer`.
    fn against(answer: impl FnOnce(&mut UnixStream, Value) + Send + 'static) -> (Result<Value, ClientError>, Duration) {
        let d = tempfile::tempdir().unwrap();
        let sock = fake(d.path(), answer);
        let mut c = Client::connect_with(&sock, SHORT).unwrap();
        let t = Instant::now();
        let r = c.call("rpc.version", Value::Null);
        let took = t.elapsed();
        if r.is_err() {
            // A connection that failed once is not used again.
            assert!(c.call("rpc.version", Value::Null).is_err());
        }
        (r, took)
    }

    fn reply(v: Value) -> impl FnOnce(&mut UnixStream, Value) + Send + 'static {
        move |s, _| write(s, format!("{v}\n").as_bytes())
    }

    #[test]
    fn hostile_replies_are_errors_never_panics_or_hangs() {
        let protocol = |r: Result<Value, ClientError>, what: &str| {
            assert!(matches!(r, Err(ClientError::Protocol(_))), "{what}: {r:?}");
        };
        protocol(against(|s, _| write(s, b"not json\n")).0, "garbage");
        protocol(against(|s, _| write(s, b"\x1b[2J\xff\xfe\n")).0, "binary");
        protocol(
            against(reply(json!({"jsonrpc":"2.0","id":999,"result":1}))).0,
            "another id",
        );
        protocol(
            against(reply(json!({"jsonrpc":"2.0","id":"1","result":1}))).0,
            "a string id",
        );
        protocol(
            against(reply(json!({"jsonrpc":"2.0","id":null,"result":1}))).0,
            "a null id on a result",
        );
        protocol(against(reply(json!({"jsonrpc":"1.0","id":1,"result":1}))).0, "1.0");
        protocol(against(reply(json!({"id":1,"result":1}))).0, "no jsonrpc");
        protocol(against(reply(json!({"jsonrpc":"2.0","id":1}))).0, "neither");
        protocol(
            against(reply(json!({"jsonrpc":"2.0","id":1,"result":1,"error":{}}))).0,
            "both",
        );
        protocol(
            against(reply(
                json!({"jsonrpc":"2.0","id":1,"error":{"code":"x","message":"m"}}),
            ))
            .0,
            "code",
        );
        protocol(
            against(reply(
                json!({"jsonrpc":"2.0","id":1,"error":{"code":1.5,"message":"m"}}),
            ))
            .0,
            "code",
        );
        protocol(
            against(reply(json!({"jsonrpc":"2.0","id":1,"error":{"code":1}}))).0,
            "no message",
        );
        protocol(
            against(reply(json!({"jsonrpc":"2.0","id":1,"error":"boom"}))).0,
            "error not an object",
        );
        protocol(
            against(reply(json!([{"jsonrpc":"2.0","id":1,"result":1}]))).0,
            "a batch",
        );
        protocol(
            against(|s, _| write(s, format!("{}\n", "[".repeat(100_000)).as_bytes())).0,
            "deep",
        );
        protocol(
            against(|s, _| write(s, b"{\"jsonrpc\":\"2.0\",\"id\":1,\"res")).0,
            "cut short",
        );
        protocol(against(|s, _| write(s, b"\n")).0, "a blank line");
        // Closed without a word.
        let (r, _) = against(|_, _| {});
        assert!(r.is_err(), "{r:?}");
        // Longer than the cap: refused at the cap, not buffered on.
        let (r, _) = against(|s, _| {
            let chunk = vec![b'x'; 1 << 20];
            for _ in 0..(MAX_REPLY >> 20) + 2 {
                if s.write_all(&chunk).is_err() {
                    return;
                }
            }
        });
        protocol(r, "oversize");
        // Silent, and dripping: both cut at the call's deadline.
        let (r, took) = against(|_, _| thread::sleep(Duration::from_secs(3)));
        assert!(
            matches!(r, Err(ClientError::Io(ref e)) if e.kind() == io::ErrorKind::TimedOut),
            "{r:?}"
        );
        assert!(took < Duration::from_secs(2), "{took:?}");
        let (r, took) = against(|s, _| {
            for _ in 0..60 {
                if s.write_all(b" ").is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
        });
        assert!(
            matches!(r, Err(ClientError::Io(ref e)) if e.kind() == io::ErrorKind::TimedOut),
            "{r:?}"
        );
        assert!(took < Duration::from_secs(2), "{took:?}");
        // A huge error message is bounded; a null id is fine on an error; unknown members are ignored.
        let (r, _) = against(reply(json!({"jsonrpc":"2.0","id":null,"extra":1,
            "error":{"code":-32000,"message":"m".repeat(100_000),"data":{"kind":"k".repeat(100_000)}}})));
        match r {
            Err(ClientError::Rpc { code, message, kind }) => {
                assert_eq!(code, -32000);
                assert_eq!(message.chars().count(), MAX_TEXT);
                assert_eq!(kind.unwrap().chars().count(), MAX_TEXT);
            }
            r => panic!("{r:?}"),
        }
        // A result that is valid JSON-RPC but not the helper's type.
        let d = tempfile::tempdir().unwrap();
        let sock = fake(d.path(), |s, req| {
            let id = req["id"].clone();
            write(
                s,
                format!("{}\n", json!({"jsonrpc":"2.0","id":id,"result":"x"})).as_bytes(),
            )
        });
        let e = Client::connect_with(&sock, SHORT).unwrap().apps().unwrap_err();
        assert!(matches!(e, ClientError::Protocol(_)), "{e:?}");
    }

    #[test]
    fn after_a_timeout_nothing_more_is_sent() {
        let d = tempfile::tempdir().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let sock = fake(d.path(), move |s, req| {
            // Answers late, then reports whether another request line arrives.
            thread::sleep(SHORT * 2);
            write(
                s,
                format!("{}\n", json!({"jsonrpc":"2.0","id":req["id"],"result":1})).as_bytes(),
            );
            s.set_read_timeout(Some(SHORT * 2)).unwrap();
            let mut more = [0u8; 1];
            tx.send(matches!(s.read(&mut more), Ok(1))).unwrap();
        });
        let mut c = Client::connect_with(&sock, SHORT).unwrap();
        let r = c.call("rpc.version", Value::Null);
        assert!(
            matches!(r, Err(ClientError::Io(ref e)) if e.kind() == io::ErrorKind::TimedOut),
            "{r:?}"
        );
        let r = c.call("rpc.version", Value::Null);
        assert!(matches!(r, Err(ClientError::Protocol(_))), "{r:?}");
        assert!(!rx.recv().unwrap(), "a request was sent on a failed connection");
    }

    #[test]
    fn what_the_client_sends_is_one_strict_request_line() {
        let d = tempfile::tempdir().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let sock = fake(d.path(), move |s, req| {
            tx.send(req.clone()).unwrap();
            write(
                s,
                format!("{}\n", json!({"jsonrpc":"2.0","id":req["id"],"result":{"ok":true}})).as_bytes(),
            )
        });
        let mut c = Client::connect_with(&sock, SHORT).unwrap();
        assert_eq!(
            c.call("apps.get", json!({"id": "a\u{1b}"})).unwrap(),
            json!({"ok": true})
        );
        let req = rx.recv().unwrap();
        assert_eq!(
            req,
            json!({"jsonrpc":"2.0","method":"apps.get","params":{"id":"a\u{1b}"},"id":1})
        );
    }

    /// Whether anything connected to `l` (non-blocking accept).
    fn contacted(l: &UnixListener) -> bool {
        l.set_nonblocking(true).unwrap();
        l.accept().is_ok()
    }

    #[test]
    fn unsafe_sockets_are_refused_before_a_byte_is_sent() {
        let unsafe_ = |r: Result<Client, ClientError>, what: &str| {
            assert!(matches!(r, Err(ClientError::Unsafe { .. })), "{what}: {:?}", r.err());
        };
        let d = tempfile::tempdir().unwrap();
        let run = run_dir(d.path());
        let sock = run.join("s.sock");
        let l = UnixListener::bind(&sock).unwrap();
        // The socket open to others.
        fs::set_permissions(&sock, fs::Permissions::from_mode(0o666)).unwrap();
        unsafe_(Client::connect_with(&sock, SHORT), "socket 0666");
        fs::set_permissions(&sock, fs::Permissions::from_mode(0o600)).unwrap();
        // The directory open to others.
        for mode in [0o755, 0o770, 0o701] {
            fs::set_permissions(&run, fs::Permissions::from_mode(mode)).unwrap();
            unsafe_(Client::connect_with(&sock, SHORT), &format!("dir {mode:o}"));
        }
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        // A symlinked directory, a symlink at the socket path.
        let link_dir = d.path().join("link");
        symlink(&run, &link_dir).unwrap();
        unsafe_(Client::connect_with(&link_dir.join("s.sock"), SHORT), "symlinked dir");
        symlink(&sock, run.join("l.sock")).unwrap();
        unsafe_(Client::connect_with(&run.join("l.sock"), SHORT), "symlinked socket");
        // Not ours (the owner check against another uid; a second real uid is not available in tests).
        unsafe_(
            connect_as(&sock, SHORT, server::euid().wrapping_add(1)),
            "another owner",
        );
        // Not a socket; not absolute.
        fs::write(run.join("file"), b"").unwrap();
        unsafe_(Client::connect_with(&run.join("file"), SHORT), "a file");
        unsafe_(Client::connect_with(Path::new("run/s.sock"), SHORT), "relative");
        assert!(!contacted(&l), "a refused socket was connected to");
        // And the safe one is fine.
        l.set_nonblocking(false).unwrap();
        assert!(Client::connect_with(&sock, SHORT).is_ok());
        assert!(contacted(&l));
        // Missing: unreachable, not unsafe.
        for p in [run.join("none.sock"), d.path().join("nodir/x.sock")] {
            let r = Client::connect_with(&p, SHORT);
            assert!(
                matches!(r, Err(ClientError::Unreachable { .. })),
                "{p:?}: {:?}",
                r.err()
            );
        }
    }

    #[test]
    fn a_daemon_that_never_accepts_cannot_hang_the_connect() {
        let d = tempfile::tempdir().unwrap();
        let sock = run_dir(d.path()).join("s.sock");
        let l = UnixListener::bind(&sock).unwrap();
        fs::set_permissions(&sock, fs::Permissions::from_mode(0o600)).unwrap();
        // SAFETY: re-`listen` on a listening socket we own only changes its backlog.
        assert_eq!(unsafe { libc::listen(l.as_raw_fd(), 0) }, 0);
        let mut held = vec![];
        while let Ok(s) = server::connect_nonblocking(&sock) {
            held.push(s);
            assert!(held.len() < 64, "the backlog never filled");
        }
        let t = Instant::now();
        let r = Client::connect_with(&sock, SHORT);
        assert!(matches!(r, Err(ClientError::Unreachable { .. })), "{:?}", r.err());
        assert!(t.elapsed() < Duration::from_secs(2));
    }
}
