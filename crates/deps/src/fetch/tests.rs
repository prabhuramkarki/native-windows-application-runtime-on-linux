use super::testserver::{Dribble, Recorder, Reply, Server, honest};
use super::*;
use crate::manifest::{ArchiveFormat, Install, Kind};
use std::os::unix::fs::symlink;
use std::sync::atomic::Ordering;
use std::time::Instant;

fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn body(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

fn pkg_for(url: String, content: &[u8]) -> Package {
    Package {
        id: "p".into(),
        version: "1".into(),
        sha256: sha(content),
        size: content.len() as u64,
        licence: "MIT".into(),
        url,
        kind: Kind::Archive,
        requires_consent: false,
        requires: vec![],
        provides: vec![],
        install: Install::Archive {
            format: ArchiveFormat::Zip,
            extract: vec![],
            dll_overrides: vec![],
        },
    }
}

fn opts() -> FetchOpts {
    FetchOpts {
        connect_timeout: Duration::from_secs(2),
        total_deadline: Duration::from_secs(5),
        stall_timeout: Duration::from_secs(1),
        max_redirects: 3,
    }
}

struct Env {
    _tmp: tempfile::TempDir,
    cache: PathBuf,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("cache");
    Env { _tmp: tmp, cache }
}

fn get(s: &Server, e: &Env, pkg: &Package) -> Result<PathBuf, FetchError> {
    get_with(s, e, pkg, &opts())
}

fn get_with(s: &Server, e: &Env, pkg: &Package, o: &FetchOpts) -> Result<PathBuf, FetchError> {
    fetch_with_roots(pkg, &e.cache, o, std::slice::from_ref(&s.cert))
}

fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => vec![],
    };
    v.sort();
    v
}

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().mode() & 0o777
}

/// RF-3: after a failure the cache dir holds nothing (no partial, no temp file).
#[track_caller]
fn assert_empty(e: &Env) {
    assert_eq!(listing(&e.cache), Vec::<String>::new());
}

#[test]
fn success_path_read_only_file_at_sha256() {
    let data = body(200_000);
    let s = Server::start(vec![("/f", honest(&data))]);
    let e = env();
    let p = pkg_for(s.url("/f"), &data);
    let path = get(&s, &e, &p).unwrap();
    assert_eq!(path, e.cache.join(&p.sha256));
    assert_eq!(fs::read(&path).unwrap(), data);
    assert_eq!(mode(&path), 0o400);
    assert_eq!(mode(&e.cache), 0o700);
    assert_eq!(listing(&e.cache), vec![p.sha256.clone()]);
}

#[test]
fn rf3_wrong_hash_is_hash_mismatch_and_leaves_nothing() {
    let data = body(5000);
    let s = Server::start(vec![("/f", honest(&data))]);
    let e = env();
    let mut p = pkg_for(s.url("/f"), &data);
    p.sha256 = sha(b"something else");
    assert!(matches!(get(&s, &e, &p), Err(FetchError::HashMismatch)));
    assert_empty(&e);
}

#[test]
fn rf1_endless_body_aborts_at_cap_and_closes_connection() {
    let s = Server::start(vec![("/f", Reply::Endless)]);
    let e = env();
    let p = pkg_for(s.url("/f"), &body(100_000));
    assert!(matches!(get(&s, &e, &p), Err(FetchError::TooLarge)));
    assert_empty(&e);
    let t = Instant::now();
    while !s.stats.client_closed.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(5) {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        s.stats.client_closed.load(Ordering::SeqCst),
        "server never saw the client hang up"
    );
    // Bounded by the cap plus socket buffers, not by the (infinite) body.
    assert!(s.stats.body_bytes.load(Ordering::SeqCst) < 64 * 1024 * 1024);
}

#[test]
fn rf1_more_bytes_than_declared_is_too_large() {
    let data = body(2000);
    let s = Server::start(vec![(
        "/f",
        Reply::Fixed {
            status: 200,
            headers: vec![],
            body: data.clone(),
            content_length: None,
        },
    )]);
    let e = env();
    let p = pkg_for(s.url("/f"), &data[..1000]);
    assert!(matches!(get(&s, &e, &p), Err(FetchError::TooLarge)));
    assert_empty(&e);
}

#[test]
fn rf1_fewer_bytes_than_declared_is_too_short() {
    let data = body(1000);
    let s = Server::start(vec![("/f", honest(&data[..500]))]);
    let e = env();
    let p = pkg_for(s.url("/f"), &data);
    assert!(matches!(get(&s, &e, &p), Err(FetchError::TooShort)));
    assert_empty(&e);
}

#[test]
fn rf1_content_length_lying_high() {
    let data = body(1000);
    let fixed = |cl: u64, b: &[u8]| Reply::Fixed {
        status: 200,
        headers: vec![],
        body: b.to_vec(),
        content_length: Some(cl),
    };
    // Claims 2000, sends the 1000 pinned bytes and hangs up: a truncated response, refused.
    // Claims 2000 and sends 2000 against a 1000-byte pin: the cap fires, the header is not believed.
    let s = Server::start(vec![
        ("/short", fixed(2000, &data)),
        ("/long", fixed(2000, &body(2000))),
    ]);
    let e = env();
    assert!(matches!(
        get(&s, &e, &pkg_for(s.url("/short"), &data)),
        Err(FetchError::TooShort)
    ));
    assert_empty(&e);
    assert!(matches!(
        get(&s, &e, &pkg_for(s.url("/long"), &data)),
        Err(FetchError::TooLarge)
    ));
    assert_empty(&e);
}

#[test]
fn rf1_content_length_lying_low() {
    let data = body(1000);
    let s = Server::start(vec![(
        "/f",
        Reply::Fixed {
            status: 200,
            headers: vec![],
            body: data.clone(),
            content_length: Some(500),
        },
    )]);
    let e = env();
    assert!(matches!(
        get(&s, &e, &pkg_for(s.url("/f"), &data)),
        Err(FetchError::TooShort)
    ));
    assert_empty(&e);
}

#[test]
fn rf1_drip_slower_than_stall_timeout_is_stalled() {
    let data = body(10);
    let s = Server::start(vec![(
        "/f",
        Reply::Drip {
            body: data.clone(),
            every: Duration::from_millis(1500),
        },
    )]);
    let e = env();
    let o = FetchOpts {
        stall_timeout: Duration::from_millis(300),
        ..opts()
    };
    let t = Instant::now();
    assert!(matches!(
        get_with(&s, &e, &pkg_for(s.url("/f"), &data), &o),
        Err(FetchError::Stalled)
    ));
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    assert_empty(&e);
}

#[test]
fn rf1_drip_faster_than_stall_hits_total_deadline() {
    let data = body(200);
    let s = Server::start(vec![(
        "/f",
        Reply::Drip {
            body: data.clone(),
            every: Duration::from_millis(50),
        },
    )]);
    let e = env();
    let o = FetchOpts {
        total_deadline: Duration::from_secs(1),
        ..opts()
    };
    let t = Instant::now();
    assert!(matches!(
        get_with(&s, &e, &pkg_for(s.url("/f"), &data), &o),
        Err(FetchError::Timeout)
    ));
    assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    assert_empty(&e);
}

#[test]
fn slow_headers_are_stalled() {
    let data = body(10);
    let s = Server::start(vec![(
        "/f",
        Reply::SlowHeaders {
            body: data.clone(),
            delay: Duration::from_secs(2),
        },
    )]);
    let e = env();
    let o = FetchOpts {
        stall_timeout: Duration::from_millis(300),
        ..opts()
    };
    let t = Instant::now();
    assert!(matches!(
        get_with(&s, &e, &pkg_for(s.url("/f"), &data), &o),
        Err(FetchError::Stalled)
    ));
    assert!(t.elapsed() < Duration::from_millis(1500), "{:?}", t.elapsed());
}

/// I-1: ureq gives the TLS handshake one relative timeout reused per read, so a handshake dribbled a byte at a
/// time (each read well inside the stall timeout) must still end at the absolute total deadline.
#[test]
fn dribbled_handshake_is_bounded_by_total_deadline() {
    let data = body(10);
    let s = Server::start(vec![("/f", honest(&data))]);
    let d = Dribble::start(s.port, Duration::from_millis(20));
    let e = env();
    let o = FetchOpts {
        connect_timeout: Duration::from_secs(10),
        total_deadline: Duration::from_secs(1),
        ..opts()
    };
    let p = pkg_for(format!("https://127.0.0.1:{}/f", d.port), &data);
    let t = Instant::now();
    assert!(matches!(get_with(&s, &e, &p, &o), Err(FetchError::Timeout)));
    assert!(t.elapsed() < Duration::from_millis(1800), "{:?}", t.elapsed());
    assert_empty(&e);
}

/// The total deadline spans redirect hops: a fast first hop, then a dribbled second one.
#[test]
fn dribbled_redirect_hop_is_bounded_by_total_deadline() {
    let data = body(10);
    let target = Server::start(vec![("/f", honest(&data))]);
    let d = Dribble::start(target.port, Duration::from_millis(20));
    let s = Server::start(vec![("/r", Reply::Redirect(format!("https://127.0.0.1:{}/f", d.port)))]);
    let e = env();
    let o = FetchOpts {
        connect_timeout: Duration::from_secs(10),
        total_deadline: Duration::from_secs(1),
        ..opts()
    };
    // Both servers need trusting: pass both certificates.
    let roots = [s.cert.clone(), target.cert.clone()];
    let t = Instant::now();
    let r = fetch_with_roots(&pkg_for(s.url("/r"), &data), &e.cache, &o, &roots);
    assert!(matches!(r, Err(FetchError::Timeout)), "{r:?}");
    assert!(t.elapsed() < Duration::from_millis(1800), "{:?}", t.elapsed());
    assert_empty(&e);
}

/// The connect timeout is absolute from the start of the connection and covers the whole TLS handshake.
#[test]
fn dribbled_handshake_is_bounded_by_connect_timeout() {
    let data = body(10);
    let s = Server::start(vec![("/f", honest(&data))]);
    let d = Dribble::start(s.port, Duration::from_millis(20));
    let e = env();
    let o = FetchOpts {
        connect_timeout: Duration::from_millis(500),
        total_deadline: Duration::from_secs(5),
        ..opts()
    };
    let p = pkg_for(format!("https://127.0.0.1:{}/f", d.port), &data);
    let t = Instant::now();
    assert!(matches!(get_with(&s, &e, &p, &o), Err(FetchError::Timeout)));
    assert!(t.elapsed() < Duration::from_millis(1300), "{:?}", t.elapsed());
    assert_empty(&e);
}

/// The connect deadline stops applying once TLS is up: a body taking longer than `connect_timeout` is fine.
#[test]
fn body_may_outlast_connect_timeout() {
    let data = body(6);
    let s = Server::start(vec![(
        "/f",
        Reply::Drip {
            body: data.clone(),
            every: Duration::from_millis(150),
        },
    )]);
    let e = env();
    let o = FetchOpts {
        connect_timeout: Duration::from_millis(400),
        ..opts()
    };
    get_with(&s, &e, &pkg_for(s.url("/f"), &data), &o).unwrap();
}

#[test]
fn temp_file_is_0600_while_downloading() {
    let data = body(8);
    let s = Server::start(vec![(
        "/f",
        Reply::Drip {
            body: data.clone(),
            every: Duration::from_millis(150),
        },
    )]);
    let e = env();
    let p = pkg_for(s.url("/f"), &data);
    let cert = s.cert.clone();
    let (cache, pp) = (e.cache.clone(), p.clone());
    let h = thread::spawn(move || fetch_with_roots(&pp, &cache, &opts(), &[cert]));
    let t = Instant::now();
    let tmp = loop {
        if let Some(n) = listing(&e.cache).into_iter().find(|n| n.starts_with(".tmp-")) {
            break e.cache.join(n);
        }
        assert!(t.elapsed() < Duration::from_secs(3), "no temp file appeared");
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(mode(&tmp), 0o600);
    h.join().unwrap().unwrap();
    assert_eq!(listing(&e.cache), vec![p.sha256.clone()]);
}

#[test]
fn redirect_loop_is_too_many_redirects() {
    let data = body(10);
    let s = Server::start(vec![("/loop", Reply::Redirect("/loop".into()))]);
    let e = env();
    assert!(matches!(
        get(&s, &e, &pkg_for(s.url("/loop"), &data)),
        Err(FetchError::TooManyRedirects)
    ));
    assert_empty(&e);
}

#[test]
fn redirects_are_followed_up_to_the_clamped_limit() {
    let data = body(10);
    let s = Server::start(vec![
        ("/r4", Reply::Redirect("/r3".into())),
        ("/r3", Reply::Redirect("/r2".into())),
        ("/r2", Reply::Redirect("/r1".into())),
        ("/r1", Reply::Redirect("/f".into())),
        ("/f", honest(&data)),
    ]);
    let e = env();
    let lots = FetchOpts {
        max_redirects: 200,
        ..opts()
    };
    // Three hops is the ceiling even when more are asked for.
    get_with(&s, &e, &pkg_for(s.url("/r3"), &data), &lots).unwrap();
    fs::remove_file(e.cache.join(sha(&data))).unwrap();
    assert!(matches!(
        get_with(&s, &e, &pkg_for(s.url("/r4"), &data), &lots),
        Err(FetchError::TooManyRedirects)
    ));
    let one = FetchOpts {
        max_redirects: 1,
        ..opts()
    };
    assert!(matches!(
        get_with(&s, &e, &pkg_for(s.url("/r2"), &data), &one),
        Err(FetchError::TooManyRedirects)
    ));
    assert_empty(&e);
}

#[test]
fn https_to_http_redirect_is_refused_without_connecting() {
    let rec = Recorder::start();
    let data = body(10);
    let s = Server::start(vec![(
        "/down",
        Reply::Redirect(format!("http://127.0.0.1:{}/x", rec.port)),
    )]);
    let e = env();
    assert!(matches!(
        get(&s, &e, &pkg_for(s.url("/down"), &data)),
        Err(FetchError::RedirectDowngrade)
    ));
    thread::sleep(Duration::from_millis(100));
    assert_eq!(rec.connections.load(Ordering::SeqCst), 0);
    assert_empty(&e);
}

#[test]
fn plain_http_url_is_refused_without_connecting() {
    let rec = Recorder::start();
    let e = env();
    let p = pkg_for(format!("http://127.0.0.1:{}/x", rec.port), b"x");
    assert!(matches!(fetch(&p, &e.cache, &opts()), Err(FetchError::NotHttps)));
    thread::sleep(Duration::from_millis(100));
    assert_eq!(rec.connections.load(Ordering::SeqCst), 0);
}

/// Env proxies are ignored: runs [`env_proxy_child`] in a child process (so no env mutation races other tests) with
/// every proxy variable pointing at a recorder.
#[test]
fn env_proxy_is_ignored() {
    let rec = Recorder::start();
    let proxy = format!("http://127.0.0.1:{}", rec.port);
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "fetch::tests::env_proxy_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("RT_FETCH_PROXY_CHILD", "1")
        .env("ALL_PROXY", &proxy)
        .env("HTTPS_PROXY", &proxy)
        .env("https_proxy", &proxy)
        .env("HTTP_PROXY", &proxy)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(rec.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn env_proxy_child() {
    if std::env::var_os("RT_FETCH_PROXY_CHILD").is_none() {
        return;
    }
    let data = body(100);
    let s = Server::start(vec![("/f", honest(&data))]);
    let e = env();
    get(&s, &e, &pkg_for(s.url("/f"), &data)).unwrap();
}

#[test]
fn http_error_statuses() {
    let data = body(10);
    let err = |status| Reply::Fixed {
        status,
        headers: vec![],
        body: data.clone(),
        content_length: Some(10),
    };
    let s = Server::start(vec![("/500", err(500)), ("/206", err(206))]);
    let e = env();
    assert!(matches!(
        get(&s, &e, &pkg_for(s.url("/missing"), &data)),
        Err(FetchError::Http(404))
    ));
    assert!(matches!(
        get(&s, &e, &pkg_for(s.url("/500"), &data)),
        Err(FetchError::Http(500))
    ));
    assert!(matches!(
        get(&s, &e, &pkg_for(s.url("/206"), &data)),
        Err(FetchError::Http(206))
    ));
    assert_empty(&e);
}

#[test]
fn public_fetch_rejects_self_signed_cert() {
    let data = body(10);
    let s = Server::start(vec![("/f", honest(&data))]);
    let e = env();
    match fetch(&pkg_for(s.url("/f"), &data), &e.cache, &opts()) {
        Err(FetchError::Tls(m)) => assert!(m.len() <= 100, "{m}"),
        other => panic!("{other:?}"),
    }
    assert_empty(&e);
}

#[test]
fn unsolicited_gzip_is_passed_through_raw() {
    use flate2::write::GzEncoder;
    let plain = body(5000);
    let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&plain).unwrap();
    let gz = enc.finish().unwrap();
    let gzip = |b: &[u8]| Reply::Fixed {
        status: 200,
        headers: vec![("Content-Encoding".into(), "gzip".into())],
        body: b.to_vec(),
        content_length: Some(b.len() as u64),
    };
    let s = Server::start(vec![("/f", gzip(&gz))]);
    let e = env();
    // Pinned to the decoded bytes: must fail, the client never decodes.
    let mut p = pkg_for(s.url("/f"), &plain);
    p.size = gz.len() as u64;
    assert!(matches!(get(&s, &e, &p), Err(FetchError::HashMismatch)));
    assert_empty(&e);
    // Pinned to the bytes as served: accepted verbatim.
    let path = get(&s, &e, &pkg_for(s.url("/f"), &gz)).unwrap();
    assert_eq!(fs::read(path).unwrap(), gz);
}

#[test]
fn oversized_headers_are_refused() {
    let data = body(10);
    let s = Server::start(vec![("/f", Reply::HugeHeaders(data.clone()))]);
    let e = env();
    assert!(matches!(
        get(&s, &e, &pkg_for(s.url("/f"), &data)),
        Err(FetchError::HeadersTooLarge)
    ));
    assert_empty(&e);
}

#[test]
fn connection_reset_mid_body_fails() {
    let data = body(100_000);
    let s = Server::start(vec![(
        "/f",
        Reply::ResetAfter {
            body: data.clone(),
            sent: 30_000,
        },
    )]);
    let e = env();
    // The RST surfaces as ECONNRESET or, when rustls sees it first, as an early EOF: both fail closed.
    match get(&s, &e, &pkg_for(s.url("/f"), &data)) {
        Err(FetchError::TooShort) => {}
        Err(FetchError::Io(err)) => assert_eq!(err.kind(), io::ErrorKind::ConnectionReset),
        other => panic!("{other:?}"),
    }
    assert_empty(&e);
}

#[test]
fn chunked_bodies() {
    let data = body(1000);
    let s = Server::start(vec![
        (
            "/ok",
            Reply::Chunked {
                body: data.clone(),
                content_length: None,
            },
        ),
        (
            "/lie",
            Reply::Chunked {
                body: data.clone(),
                content_length: Some(10),
            },
        ),
        (
            "/big",
            Reply::Chunked {
                body: body(3000),
                content_length: None,
            },
        ),
    ]);
    let e = env();
    let path = get(&s, &e, &pkg_for(s.url("/ok"), &data)).unwrap();
    assert_eq!(fs::read(&path).unwrap(), data);
    fs::remove_file(path).unwrap();
    // Chunked with a contradicting Content-Length: chunked framing wins; still hash-checked.
    let path = get(&s, &e, &pkg_for(s.url("/lie"), &data)).unwrap();
    assert_eq!(fs::read(&path).unwrap(), data);
    fs::remove_file(path).unwrap();
    assert!(matches!(
        get(&s, &e, &pkg_for(s.url("/big"), &data)),
        Err(FetchError::TooLarge)
    ));
    assert_empty(&e);
}

#[test]
fn rf3_cache_hit_is_reverified_and_corruption_refetched() {
    let data = body(3000);
    let s = Server::start(vec![("/f", honest(&data))]);
    let e = env();
    let p = pkg_for(s.url("/f"), &data);
    let path = get(&s, &e, &p).unwrap();
    assert_eq!(cached(&p, &e.cache), Some(path.clone()));
    get(&s, &e, &p).unwrap();
    assert_eq!(
        s.stats.connections.load(Ordering::SeqCst),
        1,
        "valid cache hit must not refetch"
    );

    // Same length, different bytes.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut bad = data.clone();
    bad[1234] ^= 1;
    fs::write(&path, &bad).unwrap();
    assert_eq!(cached(&p, &e.cache), None);
    assert!(!path.exists(), "corrupt entry must be deleted");

    fs::write(&path, &data[..10]).unwrap(); // truncated
    let again = get(&s, &e, &p).unwrap();
    assert_eq!(fs::read(&again).unwrap(), data);
    assert_eq!(mode(&again), 0o400);
    assert_eq!(s.stats.connections.load(Ordering::SeqCst), 2);
    assert_eq!(listing(&e.cache), vec![p.sha256.clone()]);
}

#[test]
fn rf3_symlink_at_cache_path_is_refused() {
    let data = body(100);
    let s = Server::start(vec![("/f", honest(&data))]);
    let e = env();
    let p = pkg_for(s.url("/f"), &data);
    fs::DirBuilder::new().mode(0o700).create(&e.cache).unwrap();
    let target = e._tmp.path().join("target");
    fs::write(&target, &data).unwrap(); // even with the right content
    let link = e.cache.join(&p.sha256);
    symlink(&target, &link).unwrap();
    assert_eq!(cached(&p, &e.cache), None);
    assert!(matches!(get(&s, &e, &p), Err(FetchError::UnsafeCache(_))));
    assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    assert_eq!(fs::read(&target).unwrap(), data);
    assert_eq!(listing(&e.cache), vec![p.sha256.clone()]);
    assert_eq!(s.stats.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn rf3_cache_dir_symlink_or_writable_by_others_is_refused() {
    let data = body(100);
    let s = Server::start(vec![("/f", honest(&data))]);
    let e = env();
    let p = pkg_for(s.url("/f"), &data);
    let real = e._tmp.path().join("real");
    fs::DirBuilder::new().mode(0o700).create(&real).unwrap();
    symlink(&real, &e.cache).unwrap();
    assert!(matches!(get(&s, &e, &p), Err(FetchError::UnsafeCache(_))));
    assert_eq!(cached(&p, &e.cache), None);
    assert_eq!(listing(&real), Vec::<String>::new());

    let open = e._tmp.path().join("open");
    fs::create_dir(&open).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(matches!(
        fetch_with_roots(&p, &open, &opts(), std::slice::from_ref(&s.cert)),
        Err(FetchError::UnsafeCache(_))
    ));
    assert_eq!(listing(&open), Vec::<String>::new());
    assert_eq!(s.stats.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn rf3_cache_dir_that_is_a_file_or_not_ours_is_refused() {
    let data = body(100);
    let p = pkg_for("https://127.0.0.1:1/f".into(), &data);
    let e = env();
    fs::write(&e.cache, b"").unwrap();
    fs::set_permissions(&e.cache, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(fetch(&p, &e.cache, &opts()), Err(FetchError::UnsafeCache(_))));
    // `/` is root's and not writable by others, so only the owner check refuses it (as root this proves nothing).
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        assert!(matches!(
            fetch(&p, Path::new("/"), &opts()),
            Err(FetchError::UnsafeCache(_))
        ));
        assert_eq!(cached(&p, Path::new("/")), None);
    }
}

#[test]
fn cached_fifo_does_not_block_and_is_not_used() {
    let data = body(100);
    let p = pkg_for("https://127.0.0.1:1/f".into(), &data);
    let e = env();
    fs::DirBuilder::new().mode(0o700).create(&e.cache).unwrap();
    let fifo = e.cache.join(&p.sha256);
    let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let (tx, rx) = std::sync::mpsc::channel();
    let cache = e.cache.clone();
    thread::spawn(move || tx.send(cached(&p, &cache)).unwrap());
    // Without O_NONBLOCK the open would wait forever for a writer.
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5))
            .expect("cached() blocked on a FIFO"),
        None
    );
}

#[test]
fn rf2_concurrent_fetches_of_one_package_both_succeed() {
    let data = body(1_000_000);
    let s = Server::start(vec![("/f", honest(&data))]);
    let e = env();
    let p = pkg_for(s.url("/f"), &data);
    let hs: Vec<_> = (0..2)
        .map(|_| {
            let (p, cache, cert) = (p.clone(), e.cache.clone(), s.cert.clone());
            thread::spawn(move || fetch_with_roots(&p, &cache, &opts(), &[cert]))
        })
        .collect();
    for h in hs {
        let path = h.join().unwrap().unwrap();
        assert_eq!(fs::read(path).unwrap(), data);
    }
    assert_eq!(listing(&e.cache), vec![p.sha256.clone()]);
}

/// I-2: `sha256` is a path component; a `Package` built by hand must not reach outside the cache dir.
#[test]
fn invalid_package_sha256_or_size_is_refused_and_touches_nothing() {
    let data = body(100);
    let s = Server::start(vec![("/f", honest(&data))]);
    let e = env();
    fs::DirBuilder::new().mode(0o700).create(&e.cache).unwrap();
    let canary = e._tmp.path().join("victim");
    fs::write(&canary, b"keep").unwrap();
    let abs = canary.to_str().unwrap().to_string();
    let good = sha(&data);
    let bad_hashes = [
        "../victim".to_string(),
        abs,
        good.to_uppercase(),
        good[..63].to_string(),
        format!("{good}0"),
        format!("{}\0", &good[..63]),
        String::new(),
    ];
    for h in bad_hashes {
        let mut p = pkg_for(s.url("/f"), &data);
        p.sha256 = h.clone();
        assert_eq!(cached(&p, &e.cache), None, "{h:?}");
        assert!(matches!(get(&s, &e, &p), Err(FetchError::BadPackage)), "{h:?}");
    }
    for size in [0, crate::manifest::MAX_PACKAGE_SIZE + 1] {
        let mut p = pkg_for(s.url("/f"), &data);
        p.size = size;
        assert_eq!(cached(&p, &e.cache), None);
        assert!(matches!(get(&s, &e, &p), Err(FetchError::BadPackage)));
    }
    assert_eq!(fs::read(&canary).unwrap(), b"keep");
    assert_empty(&e);
    assert_eq!(s.stats.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn open_temp_is_exclusive_0600_and_never_follows() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("t");
    drop(open_temp(&path).unwrap());
    assert_eq!(mode(&path), 0o600);
    assert_eq!(open_temp(&path).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    let target = tmp.path().join("victim");
    let link = tmp.path().join("l");
    symlink(&target, &link).unwrap();
    assert!(open_temp(&link).is_err());
    assert!(!target.exists());
}

#[test]
fn temp_guard_removes_unless_disarmed() {
    let tmp = tempfile::tempdir().unwrap();
    let (_f, g) = TempFile::create(tmp.path()).unwrap();
    let path = g.path.clone();
    assert!(path.exists());
    drop(g);
    assert!(!path.exists());
    let (_f, g) = TempFile::create(tmp.path()).unwrap();
    let path = g.path.clone();
    g.disarm();
    assert!(path.exists());
}

#[test]
fn hex_is_lowercase() {
    assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
    assert_eq!(
        sha(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

/// Real network; not run in CI. `cargo test -p runtime-deps real_download_smoke -- --ignored`
#[test]
#[ignore]
fn real_download_smoke() {
    let e = env();
    let mut p = pkg_for(SMOKE_URL.into(), b"");
    p.sha256 = SMOKE_SHA256.into();
    p.size = SMOKE_SIZE;
    let path = fetch(&p, &e.cache, &FetchOpts::default()).unwrap();
    assert_eq!(fs::metadata(path).unwrap().len(), SMOKE_SIZE);
}

/// rust-lang/rust's MIT licence text at the 1.80.0 tag (1023 bytes), pinned 2026-09-24.
const SMOKE_URL: &str = "https://raw.githubusercontent.com/rust-lang/rust/1.80.0/LICENSE-MIT";
const SMOKE_SHA256: &str = "23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3";
const SMOKE_SIZE: u64 = 1023;

use std::thread;

#[test]
fn stall_cap_picks_tightest_bound_and_fails_once_expired() {
    let now = Instant::now();
    let st = |limit_ms, deadline_ms, connect_ms, established| StallTransport {
        inner: (),
        limit: Duration::from_millis(limit_ms),
        deadline: now + Duration::from_millis(deadline_ms),
        connect_deadline: now + Duration::from_millis(connect_ms),
        established: Arc::new(AtomicBool::new(established)),
    };
    let ureq_t = NextTimeout {
        after: time::Duration::Exact(Duration::from_secs(30)),
        reason: UTimeout::RecvBody,
    };
    assert_eq!(st(100, 60_000, 60_000, false).cap(ureq_t).unwrap().reason, STALL);
    assert_eq!(
        st(60_000, 100, 60_000, false).cap(ureq_t).unwrap().reason,
        UTimeout::Global
    );
    assert_eq!(
        st(60_000, 60_000, 100, false).cap(ureq_t).unwrap().reason,
        UTimeout::Connect
    );
    assert_eq!(
        st(60_000, 60_000, 100, true).cap(ureq_t).unwrap().reason,
        UTimeout::RecvBody
    );
    // Already past the deadline: an error at once, never a zero timeout (which ureq would turn into 1 s).
    let expired = StallTransport {
        deadline: now,
        ..st(60_000, 0, 60_000, true)
    };
    thread::sleep(Duration::from_millis(1));
    assert!(matches!(
        expired.cap(ureq_t),
        Err(ureq::Error::Timeout(UTimeout::Global))
    ));
}
