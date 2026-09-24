//! Hostile in-process HTTPS server for the fetch tests: 127.0.0.1, ephemeral port, self-signed certificate made
//! at test time, one scripted [`Reply`] per request path. Every socket has timeouts and every thread is joined on
//! drop, so a client bug cannot hang the suite or leak a port.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) enum Reply {
    /// `content_length`: `Some(n)` sends `Content-Length: n` (which may lie), `None` sends none (close-delimited).
    Fixed {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        content_length: Option<u64>,
    },
    /// Honest Content-Length, then one byte every `every`.
    Drip { body: Vec<u8>, every: Duration },
    /// Zeros forever, no Content-Length.
    Endless,
    /// 302 to `location`.
    Redirect(String),
    /// Chunked body, optionally with a (lying) Content-Length alongside.
    Chunked { body: Vec<u8>, content_length: Option<u64> },
    /// Honest Content-Length, `sent` bytes of the body, then a TCP reset.
    ResetAfter { body: Vec<u8>, sent: usize },
    /// Waits `delay` before sending anything, then an honest reply.
    SlowHeaders { body: Vec<u8>, delay: Duration },
    /// A 32 KiB header (over our 16 KiB cap, under ureq's 64 KiB default), then an honest body.
    HugeHeaders(Vec<u8>),
}

pub(crate) fn honest(body: &[u8]) -> Reply {
    Reply::Fixed {
        status: 200,
        headers: vec![],
        body: body.to_vec(),
        content_length: Some(body.len() as u64),
    }
}

#[derive(Default)]
pub(crate) struct Stats {
    pub connections: AtomicUsize,
    /// Body bytes the server managed to write (Endless/Drip).
    pub body_bytes: AtomicU64,
    /// A body write failed because the client went away.
    pub client_closed: AtomicBool,
}

pub(crate) struct Server {
    pub port: u16,
    pub cert: Vec<u8>,
    pub stats: Arc<Stats>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl Server {
    pub fn start(routes: Vec<(&str, Reply)>) -> Server {
        let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert = key.cert.der().to_vec();
        let pkcs8 = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
        let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(cert.clone())], pkcs8)
            .unwrap();
        let config = Arc::new(config);
        let routes: Arc<Vec<(String, Reply)>> = Arc::new(routes.into_iter().map(|(p, r)| (p.to_string(), r)).collect());
        let stats = Arc::new(Stats::default());
        let stop = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = {
            let (stats, stop) = (stats.clone(), stop.clone());
            thread::spawn(move || {
                accept_loop(listener, &stop, |tcp| {
                    stats.connections.fetch_add(1, Ordering::SeqCst);
                    let (config, routes, stats, stop) = (config.clone(), routes.clone(), stats.clone(), stop.clone());
                    Some(thread::spawn(move || {
                        let _ = serve(tcp, config, &routes, &stats, &stop);
                    }))
                })
            })
        };
        Server {
            port,
            cert,
            stats,
            stop,
            accept: Some(accept),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
    }
}

/// A plain TCP listener that only counts connections (the target of downgrade redirects and http:// urls).
pub(crate) struct Recorder {
    pub port: u16,
    pub connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl Recorder {
    pub fn start() -> Recorder {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let accept = {
            let (connections, stop) = (connections.clone(), stop.clone());
            thread::spawn(move || {
                accept_loop(listener, &stop, |_tcp| {
                    connections.fetch_add(1, Ordering::SeqCst);
                    None
                })
            })
        };
        Recorder {
            port,
            connections,
            stop,
            accept: Some(accept),
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
    }
}

/// A TCP proxy to `127.0.0.1:upstream` that forwards client bytes at once but server bytes one at a time, `gap`
/// apart: a peer (or on-path attacker) dribbling the TLS handshake and everything after it.
pub(crate) struct Dribble {
    pub port: u16,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl Dribble {
    pub fn start(upstream: u16, gap: Duration) -> Dribble {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let accept = {
            let stop = stop.clone();
            thread::spawn(move || {
                let stop2 = stop.clone();
                accept_loop(listener, &stop, move |client| {
                    let stop = stop2.clone();
                    Some(thread::spawn(move || dribble(client, upstream, gap, &stop)))
                })
            })
        };
        Dribble {
            port,
            stop,
            accept: Some(accept),
        }
    }
}

impl Drop for Dribble {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
    }
}

fn dribble(mut client: TcpStream, upstream: u16, gap: Duration, stop: &Arc<AtomicBool>) {
    let Ok(mut server) = TcpStream::connect(("127.0.0.1", upstream)) else {
        return;
    };
    let poll = Some(Duration::from_millis(50));
    let _ = client.set_read_timeout(poll);
    let _ = server.set_read_timeout(poll);
    let done = Arc::new(AtomicBool::new(false));
    let up = {
        let (mut from, mut to) = (client.try_clone().unwrap(), server.try_clone().unwrap());
        let (stop, done) = (stop.clone(), done.clone());
        thread::spawn(move || {
            let mut b = [0u8; 4096];
            while !stop.load(Ordering::SeqCst) && !done.load(Ordering::SeqCst) {
                match from.read(&mut b) {
                    Ok(0) => break,
                    Ok(n) if to.write_all(&b[..n]).is_err() => break,
                    Ok(_) => {}
                    Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                    Err(_) => break,
                }
            }
        })
    };
    let mut b = [0u8; 1];
    while !stop.load(Ordering::SeqCst) {
        match server.read(&mut b) {
            Ok(0) => break,
            Ok(_) => {
                thread::sleep(gap);
                if client.write_all(&b).is_err() {
                    break;
                }
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
    }
    done.store(true, Ordering::SeqCst);
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = server.shutdown(std::net::Shutdown::Both);
    let _ = up.join();
}

fn accept_loop(listener: TcpListener, stop: &AtomicBool, mut on: impl FnMut(TcpStream) -> Option<JoinHandle<()>>) {
    listener.set_nonblocking(true).unwrap();
    let mut handles = vec![];
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((tcp, _)) => {
                let _ = tcp.set_nonblocking(false);
                let _ = tcp.set_read_timeout(Some(SOCKET_TIMEOUT));
                let _ = tcp.set_write_timeout(Some(SOCKET_TIMEOUT));
                handles.extend(on(tcp));
            }
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
    for h in handles {
        let _ = h.join();
    }
}

type Tls = StreamOwned<ServerConnection, TcpStream>;

fn serve(
    tcp: TcpStream,
    config: Arc<ServerConfig>,
    routes: &[(String, Reply)],
    stats: &Stats,
    stop: &AtomicBool,
) -> io::Result<()> {
    let conn = ServerConnection::new(config).map_err(io::Error::other)?;
    let mut s = StreamOwned::new(conn, tcp);
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut buf)?;
        if n == 0 || head.len() > 16 * 1024 {
            return Ok(());
        }
        head.extend_from_slice(&buf[..n]);
    }
    let line = String::from_utf8_lossy(&head);
    let path = line.split(' ').nth(1).unwrap_or("").to_string();
    let reply = routes
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, r)| r.clone())
        .unwrap_or(Reply::Fixed {
            status: 404,
            headers: vec![],
            body: b"nope".to_vec(),
            content_length: Some(4),
        });
    match reply {
        Reply::Fixed {
            status,
            headers,
            body,
            content_length,
        } => {
            let mut h = headers;
            if let Some(n) = content_length {
                h.push(("Content-Length".into(), n.to_string()));
            }
            write_head(&mut s, status, &h)?;
            s.write_all(&body)?;
            close(s)
        }
        Reply::Drip { body, every } => {
            write_head(&mut s, 200, &[("Content-Length".into(), body.len().to_string())])?;
            for b in body {
                if stop.load(Ordering::SeqCst) {
                    return Ok(());
                }
                thread::sleep(every);
                if s.write_all(&[b]).and_then(|_| s.flush()).is_err() {
                    stats.client_closed.store(true, Ordering::SeqCst);
                    return Ok(());
                }
                stats.body_bytes.fetch_add(1, Ordering::SeqCst);
            }
            close(s)
        }
        Reply::Endless => {
            write_head(&mut s, 200, &[])?;
            let zeros = [0u8; 16 * 1024];
            while !stop.load(Ordering::SeqCst) {
                if s.write_all(&zeros).and_then(|_| s.flush()).is_err() {
                    stats.client_closed.store(true, Ordering::SeqCst);
                    return Ok(());
                }
                stats.body_bytes.fetch_add(zeros.len() as u64, Ordering::SeqCst);
            }
            Ok(())
        }
        Reply::Redirect(location) => {
            write_head(
                &mut s,
                302,
                &[("Location".into(), location), ("Content-Length".into(), "0".into())],
            )?;
            close(s)
        }
        Reply::Chunked { body, content_length } => {
            let mut h = vec![("Transfer-Encoding".to_string(), "chunked".to_string())];
            if let Some(n) = content_length {
                h.push(("Content-Length".into(), n.to_string()));
            }
            write_head(&mut s, 200, &h)?;
            for c in body.chunks(7) {
                write!(s, "{:x}\r\n", c.len())?;
                s.write_all(c)?;
                s.write_all(b"\r\n")?;
            }
            s.write_all(b"0\r\n\r\n")?;
            close(s)
        }
        Reply::ResetAfter { body, sent } => {
            write_head(&mut s, 200, &[("Content-Length".into(), body.len().to_string())])?;
            s.write_all(&body[..sent])?;
            s.flush()?;
            thread::sleep(Duration::from_millis(50));
            let linger = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: valid fd and a correctly sized `linger` struct; SO_LINGER 0 makes close() send a RST.
            unsafe {
                libc::setsockopt(
                    s.sock.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&raw const linger).cast(),
                    size_of::<libc::linger>() as libc::socklen_t,
                );
            }
            Ok(())
        }
        Reply::SlowHeaders { body, delay } => {
            thread::sleep(delay);
            write_head(&mut s, 200, &[("Content-Length".into(), body.len().to_string())])?;
            s.write_all(&body)?;
            close(s)
        }
        Reply::HugeHeaders(body) => {
            let big = "a".repeat(32 * 1024);
            write_head(
                &mut s,
                200,
                &[("X-Big".into(), big), ("Content-Length".into(), body.len().to_string())],
            )?;
            s.write_all(&body)?;
            close(s)
        }
    }
}

fn write_head(s: &mut Tls, status: u16, headers: &[(String, String)]) -> io::Result<()> {
    let mut h = format!("HTTP/1.1 {status} X\r\nConnection: close\r\n");
    for (k, v) in headers {
        h.push_str(&format!("{k}: {v}\r\n"));
    }
    h.push_str("\r\n");
    s.write_all(h.as_bytes())?;
    s.flush()
}

fn close(mut s: Tls) -> io::Result<()> {
    s.conn.send_close_notify();
    s.flush()
}
