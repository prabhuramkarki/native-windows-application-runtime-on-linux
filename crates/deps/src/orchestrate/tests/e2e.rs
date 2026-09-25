//! Real-Wine end-to-end tests of the whole orchestrator: `install_plan` against a real prefix, the real fetch code
//! over HTTPS from the local test server (trusting only its certificate), real `reg.exe` overrides and a real
//! sandboxed NSIS installer. The manifest is a TEST manifest built here (the CLI cannot take one, on purpose).
//!
//! `tools/build-fixtures.sh` first, then
//! `RUNTIME_REQUIRE_BWRAP=1 cargo test -p runtime-deps --lib -- --ignored e2e_real_wine --test-threads=1`
//! (CI's `wine-e2e` job runs exactly that filter). Every assertion checks an outcome: files, the registry,
//! `metadata.json`, the server's request log, the cache directory, leftover processes.

use super::*;
use crate::fetch::testserver::{Server, honest};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

/// Fetches through the real fetch code, trusting only the local test server's certificate.
struct LocalFetcher(Vec<u8>);

impl Fetcher for LocalFetcher {
    fn fetch(&self, pkg: &Package, cache_dir: &Path) -> Result<PathBuf, FetchError> {
        crate::fetch::fetch_with_roots(pkg, cache_dir, &FetchOpts::default(), std::slice::from_ref(&self.0))
    }
}

/// A zip package `id` putting `exports64.dll` (the real mingw fixture) at `windows/system32/<dll>.dll`, providing
/// and overriding `<dll>`.
fn dll_archive(id: &str, dll: &str, gated: bool, body: &[u8], url: String) -> Package {
    let (mut p, _) = archive(id, gated, &[], &[dll]);
    p.sha256 = sha(body);
    p.size = body.len() as u64;
    p.url = url;
    p.install = Install::Archive {
        format: ArchiveFormat::Zip,
        extract: vec![Extract {
            from: "exports64.dll".into(),
            to: format!("windows/system32/{dll}.dll"),
        }],
        dll_overrides: vec![dll.into()],
    };
    p
}

const DLL: &str = "dllpkg"; // gated archive, d3d11, consented
const INST: &str = "instpkg"; // NSIS installer (dep-installer.exe), vcruntime140
const DENIED: &str = "deniedpkg"; // gated archive, msvcp140, consent refused
const TAMPERED: &str = "tamperpkg"; // archive, dxgi, the server sends other bytes

/// A fresh real Wine prefix in a scratch store (never `~/.local/share` or `~/.wine`), the test manifest's four
/// packages served by the local HTTPS server, and a scratch download cache.
struct WineRig {
    tmp: tempfile::TempDir,
    store: Store,
    env: AppEnv,
    launcher: Launcher,
    backend: backend_wine::WineBackend,
    server: Server,
    manifest: Manifest,
}

impl WineRig {
    fn new() -> WineRig {
        let dll = fixture("exports64.dll");
        let dll_zip = zip_one("exports64.dll", &dll);
        let inst = fixture("dep-installer.exe");
        let denied_zip = zip_one("exports64.dll", b"never downloaded");
        let tampered_zip = zip_one("exports64.dll", b"the pinned bytes");
        let mut evil = tampered_zip.clone();
        let at = evil.len() / 3;
        evil[at] ^= 0x20; // same size, other sha256
        let server = Server::start(vec![
            ("/dllpkg.zip", honest(&dll_zip)),
            ("/instpkg.exe", honest(&inst)),
            ("/deniedpkg.zip", honest(&denied_zip)),
            ("/tamperpkg.zip", honest(&evil)),
        ]);
        let mut installer_pkg = installer(INST, &["vcruntime140"]).0;
        installer_pkg.sha256 = sha(&inst);
        installer_pkg.size = inst.len() as u64;
        installer_pkg.url = server.url("/instpkg.exe");
        installer_pkg.install = Install::Installer {
            silent_args: vec!["/S".into()],
            marker: Marker::File("rt-dep-marker.txt".into()),
            dll_overrides: vec!["vcruntime140".into()],
        };
        let manifest = Manifest {
            packages: vec![
                dll_archive(DLL, "d3d11", true, &dll_zip, server.url("/dllpkg.zip")),
                installer_pkg,
                dll_archive(DENIED, "msvcp140", true, &denied_zip, server.url("/deniedpkg.zip")),
                dll_archive(TAMPERED, "dxgi", false, &tampered_zip, server.url("/tamperpkg.zip")),
            ],
        };
        let launcher = Launcher::new();
        let backend = crate::real_wine_backend(&launcher);
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().join("apps")).unwrap();
        let env = store.create(&AppId::parse("app").unwrap()).unwrap();
        backend.prepare(&env).unwrap();
        backend.stop(&env).unwrap();
        store.write_metadata(&env, &md()).unwrap();
        let rig = WineRig {
            tmp,
            store,
            env,
            launcher,
            backend,
            server,
            manifest,
        };
        rig.assert_no_wineserver("prepare");
        rig
    }

    fn cache(&self) -> PathBuf {
        self.tmp.path().join("deps-cache")
    }

    fn c(&self, rel: &str) -> PathBuf {
        self.env.drive_c().join(rel)
    }

    fn pkg(&self, id: &str) -> &Package {
        self.manifest.get(id).unwrap()
    }

    /// The plan for an app importing `imports`, from the metadata on disk (as `plan_for_app` builds it).
    fn plan(&self, imports: &[&str]) -> AppPlan {
        let facts = Facts {
            imports: imports.iter().map(|s| (*s).to_owned()).collect(),
            extra_capabilities: vec![],
        };
        let md = self.store.read_metadata(&self.env).unwrap();
        let plan = resolve(&facts, &state::installed_set(&md), &[], &self.manifest);
        AppPlan {
            facts,
            plan,
            warnings: vec![],
        }
    }

    fn run(&self, imports: &[&str], answers: &Answers) -> RunReport {
        let fetcher = LocalFetcher(self.server.cert.clone());
        let cache = self.cache();
        let o = Orchestrator {
            manifest: &self.manifest,
            cache_dir: &cache,
            env: &self.env,
            store: &self.store,
            backend: &self.backend,
            launcher: &self.launcher,
            fetcher: &fetcher,
            consent: answers,
            now,
        };
        let t = Instant::now();
        let rep = install_plan(&o, &self.plan(imports)).unwrap();
        eprintln!("run {imports:?}: {rep:?} in {:?}", t.elapsed());
        self.assert_no_wineserver("the run");
        rep
    }

    /// Requests the server saw for `path`.
    fn requests(&self, path: &str) -> usize {
        self.server
            .stats
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|p| *p == path)
            .count()
    }

    fn all_requests(&self) -> usize {
        self.server.stats.requests.lock().unwrap().len()
    }

    /// The prefix's wineserver has exited (it lingers a few seconds after the last Wine program).
    fn assert_no_wineserver(&self, after: &str) {
        let t = Instant::now();
        loop {
            let left = wineservers_for(&self.env.prefix()).unwrap();
            if left.is_empty() {
                return;
            }
            assert!(
                t.elapsed() < Duration::from_secs(20),
                "wineserver {left:?} left after {after}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The `[Software\\Wine\\DllOverrides]` section of `user.reg` (empty if there is none).
    fn overrides(&self) -> String {
        let user = fs::read_to_string(self.env.prefix().join("user.reg")).unwrap();
        user.split("\n\n")
            .find(|s| s.starts_with("[Software\\\\Wine\\\\DllOverrides]"))
            .unwrap_or("")
            .to_owned()
    }

    /// Names in the cache directory, sorted.
    fn cache_listing(&self) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(self.cache())
            .map(|rd| {
                rd.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    /// `metadata.json` as JSON, read raw from disk.
    fn metadata_json(&self) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.env.metadata_path()).unwrap()).unwrap()
    }
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

/// Success criteria 1 to 3 on real Wine: consent-gated archive and sandboxed installer install end to end (files,
/// overrides, marker, consent record in `metadata.json`); a denied package is never requested; a tampered download
/// installs nothing and leaves no cache file; a second run installs and downloads nothing; removing the app leaves
/// nothing of it behind.
#[test]
#[ignore = "needs Wine, bwrap and the mingw/NSIS fixtures"]
fn e2e_real_wine_orchestrator_installs_behind_consent_and_verification() {
    let r = WineRig::new();
    let placeholder = |dll: &str| fs::read(r.c(&format!("windows/system32/{dll}.dll"))).unwrap();
    let (d3d11_before, msvcp_before, dxgi_before) =
        (placeholder("d3d11"), placeholder("msvcp140"), placeholder("dxgi"));

    // A tampered download: nothing installed, nothing recorded, nothing in the cache (not even a temp file).
    let a = Answers::default();
    let rep = r.run(&["dxgi.dll"], &a);
    assert!(rep.completed.is_empty(), "{rep:?}");
    let why = reason(&rep.failed, TAMPERED);
    assert!(why.contains("download failed") && why.contains("sha256"), "{why}");
    assert_eq!(r.requests("/tamperpkg.zip"), 1);
    assert_eq!(placeholder("dxgi"), dxgi_before, "dxgi.dll changed");
    assert!(r.cache_listing().is_empty(), "cache: {:?}", r.cache_listing());
    assert!(!r.overrides().contains("\"dxgi\""), "{}", r.overrides());
    assert!(r.store.read_metadata(&r.env).unwrap().dependencies.is_empty());
    assert!(!r.env.root().join(install_archive::BACKUP_DIR).exists());

    // Consent for dllpkg, none for deniedpkg; instpkg needs none.
    let a = Answers {
        yes: vec![DLL],
        ..Answers::default()
    };
    let rep = r.run(&["d3d11.dll", "vcruntime140.dll", "msvcp140.dll"], &a);
    assert_eq!(sorted(a.asked()), [DENIED, DLL], "prompts");
    let shown = a.asked.borrow().iter().find(|(id, _)| id == DLL).unwrap().1.clone();
    assert_eq!(shown, consent_text(r.pkg(DLL)));
    assert!(rep.failed.is_empty(), "{rep:?}");
    assert_eq!(sorted(rep.completed.clone()), [DLL, INST], "{rep:?}");
    assert_eq!(ids(&rep.skipped), [DENIED], "{rep:?}");
    // Downloads: one each for what installed, NONE for the denied package.
    assert_eq!(r.requests("/dllpkg.zip"), 1);
    assert_eq!(r.requests("/instpkg.exe"), 1);
    assert_eq!(r.requests("/deniedpkg.zip"), 0, "the denied package was requested");
    // The archive: the DLL in place, its original backed up, its override set.
    assert_eq!(placeholder("d3d11"), fixture("exports64.dll"));
    assert_ne!(d3d11_before, fixture("exports64.dll"));
    assert!(r.env.root().join(install_archive::BACKUP_DIR).is_dir());
    let ov = r.overrides();
    assert!(ov.contains("\"d3d11\"=\"native,builtin\""), "{ov}");
    // The installer: ran in the sandbox (its marker is there), staging cleaned, its override set.
    assert!(r.c("rt-dep-marker.txt").is_file(), "installer marker missing");
    assert!(
        fs::read_dir(r.c("windows/temp/rt-deps"))
            .map(|mut d| d.next().is_none())
            .unwrap_or(true),
        "staging not empty"
    );
    assert!(ov.contains("\"vcruntime140\"=\"native,builtin\""), "{ov}");
    // The denied package: nothing of it.
    assert_eq!(placeholder("msvcp140"), msvcp_before);
    assert!(!ov.contains("\"msvcp140\""), "{ov}");
    // metadata.json records exactly the two installs; the consent record hashes the exact text shown.
    let md = r.metadata_json();
    let deps = md["dependencies"].as_array().unwrap();
    let rec = |id: &str| {
        deps.iter()
            .find(|d| d["id"] == id)
            .unwrap_or_else(|| panic!("{id} not in {md}"))
    };
    assert_eq!(deps.len(), 2, "{md}");
    for id in [DLL, INST] {
        assert_eq!(rec(id)["sha256"], r.pkg(id).sha256.as_str());
        assert_eq!(rec(id)["version"], r.pkg(id).version.as_str());
        assert_eq!(rec(id)["installedAt"], NOW);
    }
    assert_eq!(rec(DLL)["consent"]["licenceTextSha256"], sha(shown.as_bytes()).as_str());
    assert_eq!(rec(DLL)["consent"]["givenAt"], NOW);
    assert!(rec(INST)["consent"].is_null(), "{md}");
    // The cache holds exactly the two verified downloads.
    assert_eq!(
        r.cache_listing(),
        sorted(vec![r.pkg(DLL).sha256.clone(), r.pkg(INST).sha256.clone()])
    );

    // A second run: nothing to install, nothing requested, the gated installed package never asked about.
    let before = (
        r.all_requests(),
        r.server.stats.connections.load(std::sync::atomic::Ordering::SeqCst),
    );
    let a = Answers {
        never: vec![DLL],
        ..Answers::default()
    };
    let rep = r.run(&["d3d11.dll", "vcruntime140.dll", "msvcp140.dll"], &a);
    assert!(rep.completed.is_empty() && rep.failed.is_empty(), "{rep:?}");
    assert_eq!(reason(&rep.skipped, DLL), ALREADY_INSTALLED);
    assert_eq!(reason(&rep.skipped, INST), ALREADY_INSTALLED);
    assert_eq!(
        (
            r.all_requests(),
            r.server.stats.connections.load(std::sync::atomic::Ordering::SeqCst)
        ),
        before,
        "the second run touched the network"
    );
    assert_eq!(r.metadata_json()["dependencies"], md["dependencies"]);

    // Removing the app (what `runtime remove` does: stop, delete the app root) leaves nothing of it.
    r.backend.stop(&r.env).unwrap();
    r.store.remove(r.env.id()).unwrap();
    r.assert_no_wineserver("removal");
    assert!(!r.env.root().exists(), "app root left");
    assert_eq!(
        fs::read_dir(r.tmp.path().join("apps")).unwrap().count(),
        0,
        "apps dir not empty"
    );
    let mut top: Vec<_> = fs::read_dir(r.tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    top.sort();
    assert_eq!(top, ["apps", "deps-cache"], "stray files");
    assert_eq!(r.cache_listing().len(), 2, "the shared cache is kept, and only it");
}

/// RF-3 on real Wine: an archive install killed after it wrote into the prefix (the Task 5 crash hook: a panic, so
/// no rollback runs, as with SIGKILL) blocks the package with a journal error until `discard_interrupted_for`
/// restores the prefix byte for byte; then the package installs normally.
#[test]
#[ignore = "needs Wine and the mingw fixtures"]
fn e2e_real_wine_killed_install_is_discarded_and_then_installs() {
    let r = WineRig::new();
    let a = Answers {
        yes: vec![DLL],
        ..Answers::default()
    };
    let path = r.c("windows/system32/d3d11.dll");
    let original = fs::read(&path).unwrap();
    // Crash points: 0 = right after the journal was created, 1 = right after the DLL was written.
    for crash_after in [0u32, 1] {
        install_archive::CRASH_AFTER.with(|c| c.set(Some(crash_after)));
        let got = catch_unwind(AssertUnwindSafe(|| r.run(&["d3d11.dll"], &a)));
        install_archive::CRASH_AFTER.with(|c| c.set(None));
        assert!(got.is_err(), "crash point {crash_after} not reached");
        r.assert_no_wineserver("the crash");
        let journal = r.env.root().join(install_archive::BACKUP_DIR).join(DLL).join("journal");
        assert!(journal.is_file(), "crash {crash_after}: no journal");
        if crash_after == 1 {
            assert_eq!(
                fs::read(&path).unwrap(),
                fixture("exports64.dll"),
                "the DLL was not written"
            );
        }
        assert!(
            r.store.read_metadata(&r.env).unwrap().dependencies.is_empty(),
            "recorded"
        );

        // A plain retry of this same archive adopts the journal (Task 5); a DIFFERENT archive would be refused. Here
        // the user discards instead, as the CLI's journal message tells them to.
        let rep = discard_interrupted_for(&r.store, &r.env, DLL).unwrap();
        eprintln!("crash {crash_after}: discarded {rep:?}");
        assert_eq!(
            fs::read(&path).unwrap(),
            original,
            "crash {crash_after}: original not restored"
        );
        assert!(!journal.exists());
        assert!(
            !r.env.root().join(install_archive::BACKUP_DIR).exists(),
            "backup dir left"
        );
        assert!(!r.overrides().contains("\"d3d11\""));
        assert!(
            !r.env.root().join(LOCK_FILE).exists() || lock_app(&r.env).is_ok(),
            "lock still held"
        );
    }
    let rep = r.run(&["d3d11.dll"], &a);
    assert_eq!(rep.completed, [DLL], "{rep:?}");
    assert_eq!(fs::read(&path).unwrap(), fixture("exports64.dll"));
    assert!(
        r.overrides().contains("\"d3d11\"=\"native,builtin\""),
        "{}",
        r.overrides()
    );
    assert_eq!(r.store.read_metadata(&r.env).unwrap().dependencies.len(), 1);
    // The download was verified once and reused from the cache by every retry.
    assert_eq!(r.requests("/dllpkg.zip"), 1);
}
