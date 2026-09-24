//! Verified download of a package: the only network code in the project.
//!
//! The server, the network and the bytes are all hostile. The pinned SHA-256 and exact size from the bundled
//! manifest are the integrity control; TLS (bundled Mozilla roots, no way to switch verification off) is defence in
//! depth. Bytes stream into a `0600`/`O_EXCL` temp file in the cache directory while being hashed and counted
//! against the declared size; only an exact size and hash match is made read-only and renamed to
//! `cache/<sha256>`. Every other outcome removes the temp file.

use crate::manifest::{MAX_PACKAGE_SIZE, Package, clip, valid_sha256};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use ureq::Timeout as UTimeout;
use ureq::tls::{RootCerts, TlsConfig};
use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, NextTimeout, RustlsConnector, TcpConnector, Transport, time,
};

/// Most redirects ever followed, whatever `FetchOpts::max_redirects` says.
pub const MAX_REDIRECTS: u8 = 3;
/// Response header block cap (ureq's default is 64 KiB).
const MAX_HEADER_BYTES: usize = 16 * 1024;
const CHUNK: usize = 64 * 1024;
const USER_AGENT: &str = concat!("runtime-deps/", env!("CARGO_PKG_VERSION"));
/// Marks a timeout raised by our per-read stall cap. ureq's own `timeout_per_call` is never configured, so it can
/// only come from [`StallTransport`].
const STALL: UTimeout = UTimeout::PerCall;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchOpts {
    /// Per connection: DNS resolution, and TCP connect plus the whole TLS handshake measured from the start of the
    /// connection (an absolute deadline, so a handshake dribbled a byte at a time cannot extend it).
    pub connect_timeout: Duration,
    /// Absolute deadline for the whole fetch from the moment the request starts: every redirect hop, connect, TLS
    /// handshake, headers and body.
    pub total_deadline: Duration,
    /// Longest a single socket read or write may block (reported as `Stalled`).
    pub stall_timeout: Duration,
    /// Clamped to [`MAX_REDIRECTS`].
    pub max_redirects: u8,
}

impl Default for FetchOpts {
    fn default() -> Self {
        FetchOpts {
            connect_timeout: Duration::from_secs(10),
            total_deadline: Duration::from_secs(300),
            stall_timeout: Duration::from_secs(20),
            max_redirects: MAX_REDIRECTS,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// The package's `sha256` is not 64 lowercase hex characters or its `size` is outside 1..=4 GiB (only possible
    /// for a `Package` built without `manifest::parse`); nothing is touched.
    #[error("package has an invalid sha256 or size")]
    BadPackage,
    #[error("package url is not https")]
    NotHttps,
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("redirect to a non-https url refused")]
    RedirectDowngrade,
    #[error("server sent more bytes than the manifest size")]
    TooLarge,
    #[error("server sent fewer bytes than the manifest size")]
    TooShort,
    #[error("download does not match the manifest sha256")]
    HashMismatch,
    #[error("download timed out")]
    Timeout,
    #[error("download stalled (no progress within the stall timeout)")]
    Stalled,
    #[error("TLS failure: {0}")]
    Tls(String),
    #[error("server answered HTTP {0}")]
    Http(u16),
    #[error("response headers too large")]
    HeadersTooLarge,
    #[error("host not found")]
    HostNotFound,
    /// A malformed or unsupported HTTP exchange; the text is ureq's description, clipped.
    #[error("bad HTTP response: {0}")]
    Protocol(String),
    /// The cache directory or entry is a symlink, not a regular file/directory, not ours, or writable by others.
    #[error("unsafe cache path {0:?}")]
    UnsafeCache(PathBuf),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Downloads `pkg` into `cache_dir/<sha256>` (read-only) unless a valid copy is already there.
pub fn fetch(pkg: &Package, cache_dir: &Path, opts: &FetchOpts) -> Result<PathBuf, FetchError> {
    fetch_inner(pkg, cache_dir, opts, RootCerts::WebPki)
}

/// Test seam: trust `roots` ONLY (the local test server's certificate). Not compiled into release code.
#[cfg(test)]
pub(crate) fn fetch_with_roots(
    pkg: &Package,
    cache_dir: &Path,
    opts: &FetchOpts,
    roots: &[Vec<u8>],
) -> Result<PathBuf, FetchError> {
    let certs = roots.iter().map(|d| ureq::tls::Certificate::from_der(d).to_owned());
    fetch_inner(pkg, cache_dir, opts, RootCerts::from(certs.collect::<Vec<_>>()))
}

/// The cached copy of `pkg` if its size and hash still match; a corrupt entry is deleted. Never follows symlinks.
pub fn cached(pkg: &Package, cache_dir: &Path) -> Option<PathBuf> {
    if !valid_pkg(pkg) {
        return None;
    }
    check_cache_dir(cache_dir, false).ok()?;
    let path = cache_dir.join(&pkg.sha256);
    // O_NOFOLLOW: a symlink is never opened (nor deleted); O_NONBLOCK: a FIFO opens without blocking, then fails the
    // regular-file check in `verify`.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .ok()?;
    if verify(file, pkg).unwrap_or(false) {
        Some(path)
    } else {
        let _ = fs::remove_file(&path);
        None
    }
}

/// `sha256` becomes a path component, so it must be exactly what the manifest validator allows.
fn valid_pkg(pkg: &Package) -> bool {
    valid_sha256(&pkg.sha256) && (1..=MAX_PACKAGE_SIZE).contains(&pkg.size)
}

fn fetch_inner(pkg: &Package, cache_dir: &Path, opts: &FetchOpts, roots: RootCerts) -> Result<PathBuf, FetchError> {
    if !valid_pkg(pkg) {
        return Err(FetchError::BadPackage);
    }
    // Checked here so an http url never reaches the network stack at all.
    if !pkg.url.get(..8).is_some_and(|s| s.eq_ignore_ascii_case("https://")) {
        return Err(FetchError::NotHttps);
    }
    check_cache_dir(cache_dir, true)?;
    let dest = cache_dir.join(&pkg.sha256);
    match fs::symlink_metadata(&dest) {
        Ok(m) if !m.file_type().is_file() => return Err(FetchError::UnsafeCache(dest)),
        _ => {}
    }
    if let Some(p) = cached(pkg, cache_dir) {
        return Ok(p);
    }

    let (mut file, guard) = TempFile::create(cache_dir)?;
    download(pkg, opts, roots, &mut file)?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    drop(file);
    fs::rename(&guard.path, &dest)?;
    guard.disarm();
    if let Ok(d) = File::open(cache_dir) {
        let _ = d.sync_all();
    }
    Ok(dest)
}

/// Streams the response body into `out`, counting against `pkg.size` and hashing as it goes.
fn download(pkg: &Package, opts: &FetchOpts, roots: RootCerts, out: &mut File) -> Result<(), FetchError> {
    let agent = agent(opts, roots, Instant::now() + opts.total_deadline);
    let resp = agent.get(&pkg.url).call().map_err(map_err)?;
    let status = resp.status().as_u16();
    if status != 200 {
        return Err(FetchError::Http(status));
    }
    let mut body = resp.into_body().into_reader();
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut got: u64 = 0;
    loop {
        // Never ask for more than one byte past the declared size, whatever Content-Length said.
        let want = (pkg.size - got).saturating_add(1).min(CHUNK as u64) as usize;
        let n = match body.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(FetchError::TooShort),
            Err(e) => return Err(map_err(ureq::Error::from(e))),
        };
        got += n as u64;
        if got > pkg.size {
            return Err(FetchError::TooLarge);
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])?;
    }
    if got < pkg.size {
        return Err(FetchError::TooShort);
    }
    if hex(&hasher.finalize()) != pkg.sha256 {
        return Err(FetchError::HashMismatch);
    }
    Ok(())
}

/// ureq's defaults are unsafe (no https-only, no timeouts, env proxies): every relevant setting is explicit here.
fn agent(opts: &FetchOpts, roots: RootCerts, deadline: Instant) -> ureq::Agent {
    let tls = TlsConfig::builder().root_certs(roots).build();
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(u32::from(opts.max_redirects.min(MAX_REDIRECTS)))
        .max_redirects_will_error(true)
        .http_status_as_error(false)
        .max_response_header_size(MAX_HEADER_BYTES)
        .max_idle_connections(0)
        .user_agent(USER_AGENT)
        .accept("*/*")
        .accept_encoding("")
        .timeout_resolve(Some(opts.connect_timeout))
        .timeout_connect(Some(opts.connect_timeout))
        .timeout_global(Some(opts.total_deadline))
        .tls_config(tls)
        .build();
    // Our own chain: TCP, stall cap, TLS. No SOCKS or CONNECT-proxy connector exists in it at all.
    let connector = FetchConnector {
        stall: opts.stall_timeout,
        connect: opts.connect_timeout,
        deadline,
    };
    ureq::Agent::with_parts(config, connector, DefaultResolver::default())
}

fn map_err(e: ureq::Error) -> FetchError {
    use ureq::Error as E;
    match e {
        E::StatusCode(c) => FetchError::Http(c),
        E::Timeout(STALL) => FetchError::Stalled,
        E::Timeout(_) => FetchError::Timeout,
        E::TooManyRedirects => FetchError::TooManyRedirects,
        // The first url was checked before any request, so this is always a later redirect hop.
        E::RequireHttpsOnly(_) => FetchError::RedirectDowngrade,
        E::LargeResponseHeader(..) => FetchError::HeadersTooLarge,
        E::HostNotFound => FetchError::HostNotFound,
        E::Other(o) => match o.downcast::<TlsFailed>() {
            Ok(t) => FetchError::Tls(t.0),
            Err(o) => FetchError::Protocol(clip(&o.to_string())),
        },
        E::Tls(_) | E::Rustls(_) | E::Pem(_) | E::TlsRequired => FetchError::Tls(clip(&e.to_string())),
        E::Io(io) => FetchError::Io(io::Error::new(io.kind(), clip(&io.to_string()))),
        other => FetchError::Protocol(clip(&other.to_string())),
    }
}

/// Lowercase hex (sha2 0.11 digests have no `LowerHex`).
pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)] as char, HEX[usize::from(b & 15)] as char])
        .collect()
}

/// True if `file` is a regular file of exactly `pkg.size` bytes hashing to `pkg.sha256`. Reads at most size+1.
pub(crate) fn verify(file: File, pkg: &Package) -> io::Result<bool> {
    // Defensive: a FIFO (the only special file we can meet without root) already fails by reading EOF at once.
    if !file.metadata()?.file_type().is_file() {
        return Ok(false);
    }
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut r = file.take(pkg.size + 1);
    let mut got = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        got += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok(got == pkg.size && hex(&hasher.finalize()) == pkg.sha256)
}

/// The cache directory must be a real directory (not a symlink), owned by us and not writable by others.
/// With `create`, a missing one is made `0700`.
fn check_cache_dir(dir: &Path, create: bool) -> Result<(), FetchError> {
    let meta = match fs::symlink_metadata(dir) {
        Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
            fs::symlink_metadata(dir)?
        }
        r => r?,
    };
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if !meta.file_type().is_dir() || meta.uid() != euid || meta.mode() & 0o022 != 0 {
        return Err(FetchError::UnsafeCache(dir.to_path_buf()));
    }
    Ok(())
}

/// A temp file in the cache directory, removed on drop unless disarmed (early return, error or panic).
struct TempFile {
    path: PathBuf,
    armed: bool,
}

impl TempFile {
    fn create(dir: &Path) -> io::Result<(File, TempFile)> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(".tmp-{}-{n}-{nanos:08x}", std::process::id()));
        let file = open_temp(&path)?;
        Ok((file, TempFile { path, armed: true }))
    }

    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// `O_CREAT|O_EXCL` (never reuses, and per POSIX never follows, anything already at `path`), `0600`.
fn open_temp(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)
}

/// TLS failure from the handshake, message clipped.
#[derive(Debug)]
struct TlsFailed(String);

impl std::fmt::Display for TlsFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TlsFailed {}

/// TCP, then [`StallTransport`], then rustls.
#[derive(Debug)]
struct FetchConnector {
    stall: Duration,
    connect: Duration,
    /// Absolute end of the whole fetch, shared by every redirect hop.
    deadline: Instant,
}

impl Connector<()> for FetchConnector {
    type Out = Box<dyn Transport>;

    fn connect(&self, details: &ConnectionDetails, _: Option<()>) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(tcp) = Connector::<()>::connect(&TcpConnector::default(), details, None)? else {
            return Ok(None);
        };
        let established = Arc::new(AtomicBool::new(false));
        let stalled = StallTransport {
            inner: tcp,
            limit: self.stall,
            deadline: self.deadline,
            connect_deadline: Instant::now() + self.connect,
            established: established.clone(),
        };
        match RustlsConnector::default().connect(details, Some(stalled)) {
            Ok(t) => {
                established.store(true, Ordering::SeqCst);
                Ok(t.map(|t| Box::new(t) as Box<dyn Transport>))
            }
            Err(e @ ureq::Error::Timeout(_)) => Err(e),
            Err(e) => Err(ureq::Error::Other(Box::new(TlsFailed(clip(&e.to_string()))))),
        }
    }
}

/// Caps every socket read and write at the tightest of: ureq's own timeout, the stall `limit` ([`STALL`]), the time
/// left before the absolute fetch `deadline` and, until the TLS handshake is done, the connect deadline. ureq hands
/// the TLS handshake one relative timeout reused for every read, so without the absolute deadlines a peer dribbling
/// the handshake a byte at a time could stretch it without bound.
#[derive(Debug)]
struct StallTransport<T> {
    inner: T,
    limit: Duration,
    deadline: Instant,
    connect_deadline: Instant,
    established: Arc<AtomicBool>,
}

impl<T: Transport> StallTransport<T> {
    fn cap(&self, t: NextTimeout) -> Result<NextTimeout, ureq::Error> {
        let now = Instant::now();
        let connect_left = if self.established.load(Ordering::SeqCst) {
            Duration::MAX
        } else {
            self.connect_deadline.saturating_duration_since(now)
        };
        let mut best = (*t.after, t.reason);
        for c in [
            (self.limit, STALL),
            (self.deadline.saturating_duration_since(now), UTimeout::Global),
            (connect_left, UTimeout::Connect),
        ] {
            if c.0 < best.0 {
                best = c;
            }
        }
        if best.0.is_zero() {
            // A zero timeout means "already expired", but ureq would turn it into a 1 s socket timeout.
            return Err(ureq::Error::Timeout(best.1));
        }
        Ok(NextTimeout {
            after: time::Duration::Exact(best.0),
            reason: best.1,
        })
    }
}

impl<T: Transport> Transport for StallTransport<T> {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.inner.buffers()
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        let t = self.cap(timeout)?;
        self.inner.transmit_output(amount, t)
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        let t = self.cap(timeout)?;
        self.inner.await_input(t)
    }

    fn is_open(&mut self) -> bool {
        self.inner.is_open()
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod testserver;
