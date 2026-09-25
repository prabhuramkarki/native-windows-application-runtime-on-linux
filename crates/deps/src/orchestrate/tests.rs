use super::*;
use crate::manifest::{ArchiveFormat, Extract, Install, Marker};
use crate::resolve::{ConsentState, PlanEntry};
use rt_core::{AppId, BackendInfo, FakeBackend, MAX_DEPENDENCIES};
use std::cell::RefCell;
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command};

const NOW: u64 = 1_900_000_000;
const OLD: u64 = 1_800_000_000;
const OTHER_SHA: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn sha(bytes: &[u8]) -> String {
    crate::fetch::hex(&Sha256::digest(bytes))
}

// ------------------------------------------------------------------------------------------------ fixtures

/// A stored (method 0) zip with one entry.
fn zip_one(name: &str, data: &[u8]) -> Vec<u8> {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    let mut common = Vec::new();
    for v in [0u16, 0, 0, 33] {
        common.extend_from_slice(&v.to_le_bytes());
    }
    common.extend_from_slice(&crc.sum().to_le_bytes());
    common.extend_from_slice(&(data.len() as u32).to_le_bytes());
    common.extend_from_slice(&(data.len() as u32).to_le_bytes());
    common.extend_from_slice(&(name.len() as u16).to_le_bytes());
    common.extend_from_slice(&0u16.to_le_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&common);
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    let mut central = Vec::new();
    central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    central.extend_from_slice(&((3u16 << 8) | 20).to_le_bytes());
    central.extend_from_slice(&20u16.to_le_bytes());
    central.extend_from_slice(&common);
    central.extend_from_slice(&[0u8; 6]);
    central.extend_from_slice(&((0o100_644u32) << 16).to_le_bytes());
    central.extend_from_slice(&0u32.to_le_bytes());
    central.extend_from_slice(name.as_bytes());
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// A zip package installing `windows/system32/<id>.dll`; `gated` makes it consent-gated (proprietary licence).
fn archive(id: &str, gated: bool, requires: &[&str], provides: &[&str]) -> (Package, Vec<u8>) {
    let body = zip_one("f.dll", format!("dll of {id}").as_bytes());
    let pkg = Package {
        id: id.into(),
        version: "1.0".into(),
        sha256: sha(&body),
        size: body.len() as u64,
        licence: if gated {
            manifest::PROPRIETARY.into()
        } else {
            "MIT".into()
        },
        url: format!("https://example.com/{id}.zip"),
        kind: Kind::Archive,
        requires_consent: gated,
        requires: requires.iter().map(|s| (*s).to_owned()).collect(),
        provides: provides.iter().map(|s| (*s).to_owned()).collect(),
        min_vulkan: None,
        install: Install::Archive {
            format: ArchiveFormat::Zip,
            extract: vec![Extract {
                from: "f.dll".into(),
                to: format!("windows/system32/{id}.dll"),
            }],
            dll_overrides: vec![],
        },
    };
    (pkg, body)
}

fn installer(id: &str, provides: &[&str]) -> (Package, Vec<u8>) {
    let body = format!("MZ fake installer {id}").into_bytes();
    let pkg = Package {
        id: id.into(),
        version: "1.0".into(),
        sha256: sha(&body),
        size: body.len() as u64,
        licence: "MIT".into(),
        url: format!("https://example.com/{id}.exe"),
        kind: Kind::Installer,
        requires_consent: false,
        requires: vec![],
        provides: provides.iter().map(|s| (*s).to_owned()).collect(),
        min_vulkan: None,
        install: Install::Installer {
            silent_args: vec!["/S".into()],
            marker: Marker::File(format!("windows/system32/{id}-marker.dll")),
            dll_overrides: vec![],
        },
    };
    (pkg, body)
}

fn md() -> Metadata {
    Metadata::new(
        AppId::parse("app").unwrap(),
        "App".into(),
        None,
        "x86_64",
        &WinPath::parse("C:\\app.exe").unwrap(),
        BackendInfo {
            id: "fake".into(),
            version: "1".into(),
        },
        "gui",
    )
}

struct Rig {
    tmp: tempfile::TempDir,
    store: Store,
    env: AppEnv,
    manifest: Manifest,
}

impl Rig {
    fn new(pkgs: Vec<(Package, Vec<u8>)>) -> Rig {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::new(tmp.path().join("apps")).unwrap();
        let env = store.create(&AppId::parse("app").unwrap()).unwrap();
        fs::create_dir_all(env.drive_c().join("windows/system32")).unwrap();
        // Installer packages are started by the prefix's explorer.exe (the fake backend runs its script instead).
        fs::write(
            env.drive_c().join(crate::install_installer::EXPLORER_RELATIVE),
            b"fake explorer",
        )
        .unwrap();
        store.write_metadata(&env, &md()).unwrap();
        let files = tmp.path().join("files");
        fs::create_dir(&files).unwrap();
        let mut manifest = Manifest::default();
        for (p, body) in pkgs {
            fs::write(files.join(&p.sha256), body).unwrap();
            manifest.packages.push(p);
        }
        Rig {
            tmp,
            store,
            env,
            manifest,
        }
    }
    fn md(&self) -> Metadata {
        self.store.read_metadata(&self.env).unwrap()
    }
    fn set_md(&self, md: &Metadata) {
        self.store.write_metadata(&self.env, md).unwrap();
    }
    fn c(&self, rel: &str) -> PathBuf {
        self.env.drive_c().join(rel)
    }
    fn recorded(&self) -> Vec<String> {
        self.md().dependencies.into_iter().map(|d| d.id).collect()
    }
    /// The plan as `plan_for_app` would give it for an app importing `imports`.
    fn plan(&self, imports: &[&str]) -> AppPlan {
        let facts = Facts {
            imports: imports.iter().map(|s| (*s).to_owned()).collect(),
            extra_capabilities: vec![],
        };
        let plan = resolve(&facts, &state::installed_set(&self.md()), &[], &self.manifest);
        AppPlan {
            facts,
            plan,
            warnings: vec![],
        }
    }
}

type Hook = Box<dyn Fn(&Package)>;

/// Serves prepared files by sha256 and counts every call.
#[derive(Default)]
struct FakeFetcher {
    calls: RefCell<Vec<String>>,
    fail: Vec<&'static str>,
    hook: Option<Hook>,
}

impl Fetcher for FakeFetcher {
    fn fetch(&self, pkg: &Package, cache_dir: &Path) -> Result<PathBuf, FetchError> {
        self.calls.borrow_mut().push(pkg.id.clone());
        if let Some(h) = &self.hook {
            h(pkg);
        }
        if self.fail.contains(&pkg.id.as_str()) {
            return Err(FetchError::HashMismatch);
        }
        Ok(cache_dir.join(&pkg.sha256))
    }
}

impl FakeFetcher {
    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

/// Says yes to `yes`, no to everything else; panics when asked about `never`; records every prompt.
#[derive(Default)]
struct Answers {
    yes: Vec<&'static str>,
    never: Vec<&'static str>,
    asked: RefCell<Vec<(String, String)>>,
}

impl ConsentProvider for Answers {
    fn confirm(&self, pkg: &Package, text: &str) -> bool {
        assert!(!self.never.contains(&pkg.id.as_str()), "prompted for {}", pkg.id);
        self.asked.borrow_mut().push((pkg.id.clone(), text.to_owned()));
        self.yes.contains(&pkg.id.as_str())
    }
}

impl Answers {
    fn asked(&self) -> Vec<String> {
        self.asked.borrow().iter().map(|(id, _)| id.clone()).collect()
    }
}

fn launcher() -> Launcher {
    Launcher::with_host_env([("PATH", "/usr/bin:/bin")])
}

fn now() -> u64 {
    NOW
}

fn run_with(r: &Rig, app: &AppPlan, f: &FakeFetcher, a: &Answers, b: &FakeBackend) -> Result<RunReport, DepsError> {
    let l = launcher();
    let o = Orchestrator {
        manifest: &r.manifest,
        cache_dir: &r.tmp.path().join("files"),
        env: &r.env,
        store: &r.store,
        backend: b,
        launcher: &l,
        fetcher: f,
        consent: a,
        now,
    };
    install_plan(&o, app)
}

fn run(r: &Rig, app: &AppPlan, f: &FakeFetcher, a: &Answers) -> Result<RunReport, DepsError> {
    run_with(r, app, f, a, &FakeBackend::new())
}

fn ids(v: &[(String, String)]) -> Vec<&str> {
    v.iter().map(|(id, _)| id.as_str()).collect()
}

fn reason<'a>(v: &'a [(String, String)], id: &str) -> &'a str {
    &v.iter()
        .find(|(i, _)| i == id)
        .unwrap_or_else(|| panic!("{id} not in {v:?}"))
        .1
}

/// perm (permissive, d3d11), gated (consent, vcruntime140), gdep (permissive, requires gated, msvcp140).
fn three() -> Rig {
    Rig::new(vec![
        archive("perm", false, &[], &["d3d11"]),
        archive("gated", true, &[], &["vcruntime140"]),
        archive("gdep", false, &["gated"], &["msvcp140"]),
    ])
}
const THREE: &[&str] = &["d3d11.dll", "vcruntime140.dll", "msvcp140.dll"];

fn text_hash(p: &Package) -> String {
    sha(consent_text(p).as_bytes())
}

// ------------------------------------------------------------------------------------------------ consent

#[test]
fn without_consent_a_gated_package_is_never_fetched_and_the_rest_still_installs() {
    let r = three();
    let (f, a) = (FakeFetcher::default(), Answers::default());
    let rep = run(&r, &r.plan(THREE), &f, &a).unwrap();
    assert_eq!(a.asked(), ["gated"]);
    assert_eq!(
        f.calls(),
        ["perm"],
        "something consent-gated (or behind it) was downloaded"
    );
    assert_eq!(rep.completed, ["perm"]);
    assert!(rep.failed.is_empty(), "{rep:?}");
    assert!(reason(&rep.skipped, "gated").contains("consent denied"), "{rep:?}");
    assert!(reason(&rep.skipped, "gdep").contains("blocked"), "{rep:?}");
    assert_eq!(r.recorded(), ["perm"]);
    assert_eq!(r.md().dependencies[0].consent, None);
    assert!(r.c("windows/system32/perm.dll").is_file());
    assert!(!r.c("windows/system32/gated.dll").exists());
    assert!(!r.c("windows/system32/gdep.dll").exists());
}

#[test]
fn consent_installs_in_dependency_order_and_records_the_hash_of_the_text_shown() {
    let r = three();
    let (f, a) = (
        FakeFetcher::default(),
        Answers {
            yes: vec!["gated"],
            ..Answers::default()
        },
    );
    let rep = run(&r, &r.plan(THREE), &f, &a).unwrap();
    assert_eq!(rep.completed, ["gated", "gdep", "perm"]);
    assert_eq!(f.calls(), ["gated", "gdep", "perm"]);
    let (_, shown) = &a.asked.borrow()[0];
    assert_eq!(shown, &consent_text(r.manifest.get("gated").unwrap()));
    let md = r.md();
    let gated = md.dependencies.iter().find(|d| d.id == "gated").unwrap();
    assert_eq!(
        gated.consent,
        Some(ConsentRecord {
            given_at: NOW,
            licence_text_sha256: sha(shown.as_bytes()),
        })
    );
    assert_eq!(gated.installed_at, NOW);
    assert_eq!(gated.sha256, r.manifest.get("gated").unwrap().sha256);
    for id in ["perm", "gdep"] {
        assert_eq!(md.dependencies.iter().find(|d| d.id == id).unwrap().consent, None);
    }
}

#[test]
fn a_second_run_prompts_for_nothing_and_installs_nothing_even_with_the_lock_held() {
    let r = three();
    let a = Answers {
        yes: vec!["gated"],
        ..Answers::default()
    };
    run(&r, &r.plan(THREE), &FakeFetcher::default(), &a).unwrap();
    let (f, a) = (FakeFetcher::default(), Answers::default());
    let _held = lock_app(&r.env).unwrap();
    let rep = run(&r, &r.plan(THREE), &f, &a).unwrap();
    assert!(a.asked().is_empty());
    assert!(f.calls().is_empty());
    assert!(rep.completed.is_empty() && rep.failed.is_empty());
    assert_eq!(ids(&rep.skipped), ["gated", "gdep", "perm"]);
    assert!(rep.skipped.iter().all(|(_, why)| why == ALREADY_INSTALLED), "{rep:?}");
}

/// Metadata recording `gated` at `version` with a consent hash of `hash` (a different sha256 than the manifest's).
fn md_with_consent(version: &str, hash: String) -> Metadata {
    let mut m = md();
    state::record(
        &mut m,
        DependencyRecord {
            id: "gated".into(),
            version: version.into(),
            sha256: OTHER_SHA.into(),
            installed_at: OLD,
            consent: Some(ConsentRecord {
                given_at: OLD,
                licence_text_sha256: hash,
            }),
        },
    )
    .unwrap();
    m
}

// `reusable_consent` is unreachable from `install_plan` while upgrades are refused (any record refuses the package),
// so its rule (same version AND same consent text) is tested directly.
#[test]
fn recorded_consent_counts_only_for_the_same_version_and_text() {
    let (p, _) = archive("gated", true, &[], &[]);
    let hash = text_hash(&p);
    let m = md_with_consent("1.0", hash.clone());
    assert_eq!(reusable_consent(&m, &p, &hash).unwrap().given_at, OLD);
    // Same text hash on purpose: only the version differs.
    assert_eq!(reusable_consent(&md_with_consent("0.9", hash.clone()), &p, &hash), None);
    for change in ["licence", "url", "size", "sha256"] {
        let mut old = p.clone();
        match change {
            "licence" => old.licence = "MIT".into(),
            "url" => old.url = "https://example.com/other.zip".into(),
            "size" => old.size += 1,
            _ => old.sha256 = OTHER_SHA.into(),
        }
        assert_eq!(
            reusable_consent(&md_with_consent("1.0", text_hash(&old)), &p, &hash),
            None,
            "{change}"
        );
    }
}

/// `id` bumped to version 2.0 with new bytes (the old file stays in the cache dir too).
fn bump(r: &mut Rig, id: &str) {
    let p = r.manifest.packages.iter_mut().find(|p| p.id == id).unwrap();
    let body = zip_one("f.dll", format!("v2 of {id}").as_bytes());
    p.version = "2.0".into();
    p.sha256 = sha(&body);
    p.size = body.len() as u64;
    fs::write(r.tmp.path().join("files").join(&p.sha256), body).unwrap();
}

const UPGRADE: &str = "version 1.0 is installed; upgrading installed packages is not supported yet: recreate the \
                       environment to get version 2.0";

#[test]
fn an_upgrade_of_an_installed_package_is_refused_before_any_download() {
    let mut r = abc();
    run(&r, &r.plan(&["d3d9"]), &FakeFetcher::default(), &Answers::default()).unwrap();
    let before = r.md();
    let dll = fs::read(r.c("windows/system32/a.dll")).unwrap();
    bump(&mut r, "a");
    let f = FakeFetcher::default();
    let app = r.plan(&["d3d9"]);
    assert_eq!(
        app.plan.entries[0].action,
        Action::Install,
        "the resolver plans the upgrade"
    );
    let rep = run(&r, &app, &f, &Answers::default()).unwrap();
    assert!(f.calls().is_empty());
    assert!(rep.completed.is_empty() && rep.failed.is_empty(), "{rep:?}");
    assert_eq!(reason(&rep.skipped, "a"), UPGRADE);
    assert_eq!(r.md(), before);
    assert_eq!(fs::read(r.c("windows/system32/a.dll")).unwrap(), dll);
}

#[test]
fn an_installer_upgrade_is_refused_before_the_marker_check() {
    let r = Rig::new(vec![installer("vc", &["vcruntime140"])]);
    let mut m = r.md();
    state::record(
        &mut m,
        DependencyRecord {
            id: "vc".into(),
            version: "1.0".into(),
            sha256: OTHER_SHA.into(),
            installed_at: OLD,
            consent: None,
        },
    )
    .unwrap();
    r.set_md(&m);
    fs::write(r.c("windows/system32/vc-marker.dll"), b"from 1.0").unwrap();
    let f = FakeFetcher::default();
    let rep = run(&r, &r.plan(&["vcruntime140"]), &f, &Answers::default()).unwrap();
    assert!(f.calls().is_empty());
    let why = reason(&rep.skipped, "vc");
    assert!(why.contains("upgrading installed packages is not supported"), "{why}");
    assert!(!why.contains("outside the runtime"), "{why}");
    assert_eq!(r.md(), m);
}

#[test]
fn a_refused_upgrade_skips_its_dependents_without_asking_and_unrelated_packages_install() {
    // gated (consent) -> gdep (consent) needs it; perm unrelated. gated 1.0 is recorded, the manifest has 2.0.
    let mut r = Rig::new(vec![
        archive("perm", false, &[], &["d3d11"]),
        archive("gated", true, &[], &["vcruntime140"]),
        archive("gdep", true, &["gated"], &["msvcp140"]),
    ]);
    let hash = text_hash(r.manifest.get("gated").unwrap());
    let mut m = md_with_consent("1.0", hash);
    m.dependencies[0].sha256 = r.manifest.get("gated").unwrap().sha256.clone();
    r.set_md(&m);
    bump(&mut r, "gated");
    let (f, a) = (
        FakeFetcher::default(),
        Answers {
            never: vec!["gated", "gdep"],
            ..Answers::default()
        },
    );
    let rep = run(&r, &r.plan(THREE), &f, &a).unwrap();
    assert_eq!(f.calls(), ["perm"]);
    assert_eq!(rep.completed, ["perm"]);
    assert_eq!(reason(&rep.skipped, "gated"), UPGRADE);
    assert!(reason(&rep.skipped, "gdep").contains("blocked"), "{rep:?}");
    assert!(a.asked().is_empty(), "no prompt for a refused upgrade or behind it");
}

#[test]
fn the_same_version_and_sha256_stays_already_installed() {
    let r = abc();
    run(&r, &r.plan(&["d3d9"]), &FakeFetcher::default(), &Answers::default()).unwrap();
    let f = FakeFetcher::default();
    let app = r.plan(ABC);
    let rep = run(&r, &app, &f, &Answers::default()).unwrap();
    assert_eq!(reason(&rep.skipped, "a"), "already installed");
    assert_eq!(rep.completed, ["b", "c"]);
    assert_eq!(f.calls(), ["b", "c"]);
}

#[test]
fn consent_text_shows_every_field_and_changes_with_each() {
    let (p, _) = archive("gated", true, &[], &[]);
    let t = consent_text(&p);
    assert_eq!(t, consent_text(&p.clone()), "deterministic");
    for field in [&p.id, &p.version, &p.licence, &p.url, &p.sha256, &p.size.to_string()] {
        assert!(t.contains(field.as_str()), "{field} missing from {t}");
    }
    assert!(t.contains("consent"), "{t}");
    let variants: Vec<Package> = vec![
        Package {
            id: "other".into(),
            ..p.clone()
        },
        Package {
            version: "2.0".into(),
            ..p.clone()
        },
        Package {
            licence: "MIT".into(),
            ..p.clone()
        },
        Package {
            url: "https://example.com/x.zip".into(),
            ..p.clone()
        },
        Package {
            size: p.size + 1,
            ..p.clone()
        },
        Package {
            sha256: OTHER_SHA.into(),
            ..p.clone()
        },
    ];
    for v in &variants {
        assert_ne!(consent_text(v), t, "{v:?}");
    }
}

#[test]
fn consent_text_of_an_installer_says_the_vendor_eula_is_accepted_unseen() {
    let (archive_pkg, _) = archive("gated", true, &[], &[]);
    assert!(!consent_text(&archive_pkg).contains("EULA"));
    let (vc, _) = installer("vc", &["vcruntime140"]);
    let t = consent_text(&vc);
    assert!(
        t.contains("accepts the vendor's own licence terms (its EULA) on your behalf")
            && t.contains("not displayed here"),
        "{t}"
    );
}

#[test]
fn consent_text_escapes_what_could_drive_a_terminal() {
    let (mut p, _) = archive("gated", true, &[], &[]);
    p.licence = "MIT\u{202e}\x1b[31m".into();
    let t = consent_text(&p);
    assert!(!t.contains('\u{202e}') && !t.contains('\x1b'), "{t:?}");
    assert!(
        t.lines()
            .all(|l| !l.chars().any(|c| c.is_control() || rt_core::is_format(c)))
    );
}

#[test]
fn a_denied_package_skips_its_dependents_without_asking_and_unrelated_packages_install() {
    let r = Rig::new(vec![
        archive("perm", false, &[], &["d3d11"]),
        archive("gated", true, &[], &["vcruntime140"]),
        archive("gdep", true, &["gated"], &["msvcp140"]),
    ]);
    let (f, a) = (
        FakeFetcher::default(),
        Answers {
            never: vec!["gdep"],
            ..Answers::default()
        },
    );
    let rep = run(&r, &r.plan(THREE), &f, &a).unwrap();
    assert_eq!(a.asked(), ["gated"]);
    assert_eq!(f.calls(), ["perm"]);
    assert_eq!(rep.completed, ["perm"]);
    assert_eq!(ids(&rep.skipped), ["gated", "gdep"]);
}

#[test]
fn blocked_entries_are_never_prompted_and_never_fetched() {
    let r = Rig::new(vec![
        archive("perm", false, &[], &["d3d11"]),
        archive("orphan", true, &["ghost"], &["vcruntime140"]),
    ]);
    let (f, a) = (
        FakeFetcher::default(),
        Answers {
            never: vec!["orphan"],
            ..Answers::default()
        },
    );
    let app = r.plan(&["d3d11", "vcruntime140"]);
    assert!(matches!(
        app.plan.entries.iter().find(|e| e.package == "orphan").unwrap(),
        PlanEntry {
            action: Action::Blocked { .. },
            consent: ConsentState::Needed,
            ..
        }
    ));
    let rep = run(&r, &app, &f, &a).unwrap();
    assert_eq!(f.calls(), ["perm"]);
    assert!(reason(&rep.skipped, "orphan").contains("unknown package"), "{rep:?}");
}

// ------------------------------------------------------------------------------------------------ failures

fn abc() -> Rig {
    Rig::new(vec![
        archive("a", false, &[], &["d3d9"]),
        archive("b", false, &[], &["d3d11"]),
        archive("c", false, &[], &["dxgi"]),
    ])
}
const ABC: &[&str] = &["d3d9", "d3d11", "dxgi"];

#[test]
fn a_failure_stops_the_run_and_metadata_keeps_exactly_the_completed_packages() {
    let r = abc();
    let f = FakeFetcher {
        fail: vec!["b"],
        ..FakeFetcher::default()
    };
    let rep = run(&r, &r.plan(ABC), &f, &Answers::default()).unwrap();
    assert_eq!(rep.completed, ["a"]);
    assert_eq!(ids(&rep.failed), ["b"]);
    assert!(reason(&rep.failed, "b").contains("download failed"), "{rep:?}");
    assert_eq!(
        rep.skipped,
        [("c".to_owned(), "not attempted: an earlier package failed".to_owned())]
    );
    assert_eq!(f.calls(), ["a", "b"]);
    assert_eq!(r.recorded(), ["a"]);
    assert!(!r.c("windows/system32/c.dll").exists());
}

#[test]
fn an_installer_error_is_failed_and_not_recorded() {
    let r = abc();
    // b's archive does not contain what its extract list names.
    fs::write(
        r.tmp.path().join("files").join(&r.manifest.get("b").unwrap().sha256),
        b"not a zip",
    )
    .unwrap();
    let rep = run(&r, &r.plan(ABC), &FakeFetcher::default(), &Answers::default()).unwrap();
    assert_eq!(rep.completed, ["a"]);
    assert_eq!(ids(&rep.failed), ["b"]);
    assert_eq!(r.recorded(), ["a"]);
}

#[test]
fn metadata_unreadable_after_a_successful_install_is_failed_not_recorded() {
    let r = abc();
    let path = r.env.metadata_path();
    let f = FakeFetcher {
        hook: Some(Box::new(move |p: &Package| {
            if p.id == "b" {
                fs::write(&path, b"{ broken").unwrap();
            }
        })),
        ..FakeFetcher::default()
    };
    let rep = run(&r, &r.plan(ABC), &f, &Answers::default()).unwrap();
    assert_eq!(rep.completed, ["a"]);
    let why = reason(&rep.failed, "b");
    assert!(why.contains("installed but not recorded"), "{why}");
    assert!(r.c("windows/system32/b.dll").is_file(), "the install itself succeeded");
    assert_eq!(ids(&rep.skipped), ["c"]);
}

#[test]
fn a_full_dependency_list_is_failed_not_recorded() {
    let r = abc();
    let mut m = r.md();
    for i in 0..MAX_DEPENDENCIES {
        state::record(
            &mut m,
            DependencyRecord {
                id: format!("x{i:03}"),
                version: "1".into(),
                sha256: OTHER_SHA.into(),
                installed_at: OLD,
                consent: None,
            },
        )
        .unwrap();
    }
    r.set_md(&m);
    let rep = run(&r, &r.plan(&["d3d9"]), &FakeFetcher::default(), &Answers::default()).unwrap();
    assert!(rep.completed.is_empty());
    assert!(
        reason(&rep.failed, "a").contains("installed but not recorded"),
        "{rep:?}"
    );
    assert_eq!(r.md().dependencies.len(), MAX_DEPENDENCIES);
}

#[test]
fn a_journal_error_names_the_cli_discard_command_and_discards_nothing() {
    let r = abc();
    let dir = r.env.root().join(install_archive::BACKUP_DIR).join("a");
    fs::create_dir_all(&dir).unwrap();
    let journal = format!("rt-deps-journal 1 {OTHER_SHA}\nF windows/system32/leftover.dll\n");
    fs::write(dir.join("journal"), &journal).unwrap();
    fs::write(r.c("windows/system32/leftover.dll"), b"left by a killed run").unwrap();
    let rep = run(&r, &r.plan(ABC), &FakeFetcher::default(), &Answers::default()).unwrap();
    let why = reason(&rep.failed, "a");
    assert!(
        why.contains("runtime deps app --discard-interrupted a") && why.contains("nothing was installed"),
        "{why}"
    );
    assert!(r.c("windows/system32/leftover.dll").is_file(), "auto-discarded");
    assert_eq!(fs::read_to_string(dir.join("journal")).unwrap(), journal);
    assert!(r.recorded().is_empty());
    // The guarded passthrough does discard, when asked.
    discard_interrupted_for(&r.store, &r.env, "a").unwrap();
    assert!(!r.c("windows/system32/leftover.dll").exists());
}

#[test]
fn a_malformed_sha256_never_reaches_the_fetcher() {
    let mut r = abc();
    r.manifest.packages[0].sha256 = "../../victim".into();
    let f = FakeFetcher::default();
    let rep = run(&r, &r.plan(ABC), &f, &Answers::default()).unwrap();
    assert!(f.calls().is_empty());
    assert!(reason(&rep.failed, "a").contains("sha256"), "{rep:?}");
}

/// Real `bwrap`, or a loud skip (`RUNTIME_REQUIRE_BWRAP=1` makes it a failure).
fn have_bwrap() -> bool {
    let require = std::env::var_os("RUNTIME_REQUIRE_BWRAP").is_some_and(|v| !v.is_empty());
    match rt_installer::find_bwrap_on_path() {
        Some(_) => true,
        None if require => panic!("bwrap not found on $PATH and RUNTIME_REQUIRE_BWRAP is set"),
        None => {
            eprintln!("SKIP: bwrap not found on $PATH");
            false
        }
    }
}

/// A consent-gated installer package `vc` (provides vcruntime140) and an archive `gdep` that requires it.
fn gated_installer_and_dependent() -> Rig {
    let (mut vc, body) = installer("vc", &["vcruntime140"]);
    vc.licence = manifest::PROPRIETARY.into();
    vc.requires_consent = true;
    Rig::new(vec![(vc, body), archive("gdep", false, &["vc"], &["msvcp140"])])
}

#[test]
fn an_installer_whose_marker_is_present_is_skipped_before_any_prompt_or_download() {
    let r = gated_installer_and_dependent();
    fs::write(
        r.c("windows/system32/vc-marker.dll"),
        b"put there by the app's own installer",
    )
    .unwrap();
    let f = FakeFetcher::default();
    let a = Answers {
        never: vec!["vc"],
        ..Answers::default()
    };
    let rep = run(&r, &r.plan(&["vcruntime140.dll", "msvcp140.dll"]), &f, &a).unwrap();
    assert!(a.asked().is_empty(), "prompted: {:?}", a.asked());
    assert_eq!(f.calls(), ["gdep"], "the present installer was downloaded");
    assert_eq!(reason(&rep.skipped, "vc"), MARKER_PRESENT);
    // Ruling 18: says plainly that the runtime set none of its overrides, and how to get the runtime's install.
    assert!(MARKER_PRESENT.contains("did not set its DLL overrides") && MARKER_PRESENT.contains("recreate"));
    // What needs it proceeds: the component is there.
    assert_eq!(rep.completed, ["gdep"]);
    assert!(rep.failed.is_empty(), "{rep:?}");
    assert_eq!(r.recorded(), ["gdep"], "a present installer was recorded as ours");
}

#[test]
fn an_installer_marker_that_appears_before_its_download_skips_it_at_install_time() {
    // `vc` requires `first`; `first`'s download puts vc's marker in place (as a racing app installer could): vc
    // was decided (and consented) while absent, but the check right before its download sees it.
    let (mut vc, body) = installer("vc", &["vcruntime140"]);
    vc.requires = vec!["first".into()];
    let r = Rig::new(vec![(vc, body), archive("first", false, &[], &["d3d11"])]);
    let marker = r.c("windows/system32/vc-marker.dll");
    let f = FakeFetcher {
        hook: Some(Box::new(move |p: &Package| {
            if p.id == "first" {
                fs::write(&marker, b"late").unwrap();
            }
        })),
        ..FakeFetcher::default()
    };
    let rep = run(&r, &r.plan(&["vcruntime140.dll"]), &f, &Answers::default()).unwrap();
    assert_eq!(f.calls(), ["first"]);
    assert_eq!(reason(&rep.skipped, "vc"), MARKER_PRESENT);
    assert_eq!(rep.completed, ["first"]);
    assert_eq!(r.recorded(), ["first"]);
}

/// A consent-gated installer `vc` whose marker is VC++'s `Bld` with `min_dword = 35211`; the prefix's system.reg
/// holds `bld` under that key, when given.
fn vc_bld_rig(bld: Option<u32>) -> Rig {
    let (mut vc, body) = installer("vc", &["vcruntime140"]);
    vc.licence = manifest::PROPRIETARY.into();
    vc.requires_consent = true;
    vc.install = Install::Installer {
        silent_args: vec!["/S".into()],
        marker: Marker::RegistryValue {
            key: r"HKLM\Software\Microsoft\VisualStudio\14.0\VC\Runtimes\X64".into(),
            name: "Bld".into(),
            min_dword: Some(35211),
        },
        dll_overrides: vec![],
    };
    let r = Rig::new(vec![(vc, body)]);
    if let Some(bld) = bld {
        fs::write(
            r.env.prefix().join("system.reg"),
            format!(
                "WINE REGISTRY Version 2\n\n[Software\\\\Microsoft\\\\VisualStudio\\\\14.0\\\\VC\\\\Runtimes\\\\X64] 1\n\
                 \"Installed\"=dword:00000001\n\"Bld\"=dword:{bld:08x}\n\n"
            ),
        )
        .unwrap();
    }
    r
}

#[test]
fn an_older_version_under_the_same_marker_key_is_not_treated_as_present() {
    // VC++ 2015 (Bld 23026) in the prefix: vc is still needed, so it is asked about (here: denied).
    let r = vc_bld_rig(Some(23026));
    let (f, a) = (FakeFetcher::default(), Answers::default());
    let rep = run(&r, &r.plan(&["vcruntime140.dll"]), &f, &a).unwrap();
    assert_eq!(a.asked(), ["vc"]);
    assert!(reason(&rep.skipped, "vc").contains("consent denied"), "{rep:?}");
    let mut app = r.plan(&["vcruntime140.dll"]);
    drop_present_installers(&r.env, &r.manifest, &mut app);
    assert_eq!(
        app.plan.entries.len(),
        1,
        "an older version must not hide the package: {app:?}"
    );
    // This build or newer: present, nothing asked or fetched.
    for bld in [35211, 40000] {
        let r = vc_bld_rig(Some(bld));
        let f = FakeFetcher::default();
        let a = Answers {
            never: vec!["vc"],
            ..Answers::default()
        };
        let rep = run(&r, &r.plan(&["vcruntime140.dll"]), &f, &a).unwrap();
        assert_eq!(reason(&rep.skipped, "vc"), MARKER_PRESENT);
        assert!(f.calls().is_empty());
    }
}

#[test]
fn a_marker_that_cannot_be_read_before_the_download_fails_without_the_vendor_partial_warning() {
    let r = vc_bld_rig(None);
    let outside = r.tmp.path().join("outside.reg");
    fs::write(&outside, "WINE REGISTRY Version 2\n\n").unwrap();
    std::os::unix::fs::symlink(&outside, r.env.prefix().join("system.reg")).unwrap();
    let f = FakeFetcher::default();
    let a = Answers {
        yes: vec!["vc"],
        ..Answers::default()
    };
    let rep = run(&r, &r.plan(&["vcruntime140.dll"]), &f, &a).unwrap();
    let why = reason(&rep.failed, "vc");
    assert!(
        why.contains("nothing was downloaded or run") && !why.contains("partial") && !why.contains("recreate"),
        "{why}"
    );
    assert!(
        f.calls().is_empty(),
        "downloaded although the marker could not be checked"
    );
    assert!(r.recorded().is_empty());
}

#[test]
fn the_plan_drops_an_installer_whose_marker_is_present_with_a_warning() {
    let r = gated_installer_and_dependent();
    let imports = ["vcruntime140.dll", "msvcp140.dll"];
    let mut app = r.plan(&imports);
    drop_present_installers(&r.env, &r.manifest, &mut app);
    assert_eq!(app.plan.entries.len(), 2, "nothing present yet: {app:?}");
    fs::write(r.c("windows/system32/vc-marker.dll"), b"x").unwrap();
    let mut app = r.plan(&imports);
    drop_present_installers(&r.env, &r.manifest, &mut app);
    let left: Vec<&str> = app.plan.entries.iter().map(|e| e.package.as_str()).collect();
    assert_eq!(left, ["gdep"]);
    assert_eq!(app.warnings, [format!("vc: {MARKER_PRESENT}")]);
    // An unreadable marker (a directory where the file marker belongs) keeps the entry: the run reports it.
    fs::remove_file(r.c("windows/system32/vc-marker.dll")).unwrap();
    fs::create_dir(r.c("windows/system32/vc-marker.dll")).unwrap();
    let mut app = r.plan(&imports);
    drop_present_installers(&r.env, &r.manifest, &mut app);
    assert_eq!(app.plan.entries.len(), 2);
}

#[test]
fn a_failing_vendor_installer_warns_about_partial_state() {
    if !have_bwrap() {
        return;
    }
    let r = Rig::new(vec![installer("vc", &["vcruntime140"])]);
    let b = FakeBackend::with_script("exit 3").with_dll_dirs(vec![PathBuf::from("/bin")]);
    let rep = run_with(
        &r,
        &r.plan(&["vcruntime140"]),
        &FakeFetcher::default(),
        &Answers::default(),
        &b,
    )
    .unwrap();
    let why = reason(&rep.failed, "vc");
    assert!(
        why.contains("partial") && why.contains("recreate the environment"),
        "{why}"
    );
    assert!(r.recorded().is_empty());
}

#[test]
fn installer_failure_reasons() {
    let after_run = [
        InstallerPkgError::TimedOut { secs: 5 },
        InstallerPkgError::MarkerMissing,
        InstallerPkgError::NonZeroAndNoMarker { code: Some(1) },
        InstallerPkgError::Sandbox("x".into()),
    ];
    for e in after_run {
        let why = installer_reason(e);
        assert!(why.contains(VENDOR_PARTIAL), "{why}");
    }
    let why = installer_reason(InstallerPkgError::MarkerAlreadyPresent);
    assert!(why.contains(MARKER_PRESENT) && !why.contains(VENDOR_PARTIAL), "{why}");
    let why = installer_reason(InstallerPkgError::BwrapNotFound);
    assert!(!why.contains(VENDOR_PARTIAL), "nothing ran: {why}");
    let why = installer_reason(InstallerPkgError::Registry("\x1b[31mevil\n".repeat(200)));
    assert!(!why.chars().any(|c| c.is_control()) && why.len() < 1000, "{why:?}");
}

// ------------------------------------------------------------------------------------------------ run-level guards

#[test]
fn a_second_run_while_the_first_holds_the_lock_is_refused_before_anything() {
    let r = abc();
    let held = lock_app(&r.env).unwrap();
    let (f, a) = (FakeFetcher::default(), Answers::default());
    let err = run(&r, &r.plan(ABC), &f, &a).unwrap_err();
    assert!(matches!(err, DepsError::LockHeld), "{err:?}");
    assert!(f.calls().is_empty());
    drop(held);
    assert_eq!(run(&r, &r.plan(ABC), &f, &a).unwrap().completed, ["a", "b", "c"]);
    let m = fs::symlink_metadata(r.env.root().join(LOCK_FILE)).unwrap();
    assert_eq!(m.mode() & 0o777, 0o600);
}

#[test]
fn a_symlinked_lock_file_is_refused() {
    let r = abc();
    let target = r.tmp.path().join("elsewhere");
    fs::write(&target, b"").unwrap();
    std::os::unix::fs::symlink(&target, r.env.root().join(LOCK_FILE)).unwrap();
    assert!(matches!(lock_app(&r.env), Err(DepsError::LockFileUnusable(_))));
    assert!(matches!(lock_app_shared(&r.env), Err(DepsError::LockFileUnusable(_))));
    // A directory in its place: unusable too.
    let r = abc();
    fs::create_dir(r.env.root().join(LOCK_FILE)).unwrap();
    assert!(matches!(lock_app(&r.env), Err(DepsError::LockFileUnusable(_))));
    // Any other failure (here: cannot create it) is a plain I/O error.
    let r = abc();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(r.env.root(), fs::Permissions::from_mode(0o500)).unwrap();
    if writable_anyway(r.env.root()) {
        fs::set_permissions(r.env.root(), fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    let got = lock_app(&r.env);
    fs::set_permissions(r.env.root(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(got, Err(DepsError::Io(_))), "{got:?}");
}

/// Whether `dir` (just made read-only) is writable anyway, i.e. the tests run as root: then a read-only directory
/// proves nothing, and the caller skips that part (saying so).
fn writable_anyway(dir: &Path) -> bool {
    let probe = dir.join(".rt-root-probe");
    let root = fs::File::create(&probe).is_ok();
    if root {
        let _ = fs::remove_file(&probe);
        eprintln!("SKIPPED the read-only-directory check: running as root, which writes there anyway");
    }
    root
}

#[test]
fn flock_errors_are_classified_and_only_unlockable_ones_may_be_bypassed() {
    let e = |n| flock_error(io::Error::from_raw_os_error(n));
    assert!(matches!(e(libc::EWOULDBLOCK), DepsError::LockHeld));
    for n in [libc::ENOLCK, libc::EOPNOTSUPP, libc::ENOSYS] {
        let got = e(n);
        assert!(matches!(got, DepsError::LockUnsupported(_)), "{n}: {got:?}");
        assert!(got.nobody_can_lock(), "{n}");
        assert!(got.to_string().contains("does not support locking"), "{got}");
    }
    assert!(matches!(e(libc::EACCES), DepsError::Io(_)));
    assert!(!e(libc::EACCES).nobody_can_lock());
    assert!(!DepsError::LockHeld.nobody_can_lock(), "a held lock must refuse");
    assert!(DepsError::LockFileUnusable("x".into()).nobody_can_lock());
}

/// A shell script named `wineserver` that blocks reading its (never written) stdin; killed on drop. `comm` is the
/// script's name, `exe` the shell: the same name test as a real wineserver's `comm`. (A copy of `/bin/sleep` does
/// not work: multi-call coreutils builds refuse to run under an unknown name.)
struct FakeServer(Child);

impl FakeServer {
    fn start(dir: &Path, prefix: Option<&Path>, cwd: Option<&Path>) -> FakeServer {
        use std::os::unix::fs::PermissionsExt;
        let exe = dir.join("wineserver");
        if !exe.exists() {
            fs::write(&exe, "#!/bin/sh\nread _\n").unwrap();
            fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut cmd = Command::new(&exe);
        cmd.env_clear().stdin(std::process::Stdio::piped());
        if let Some(p) = prefix {
            cmd.env("WINEPREFIX", p);
        }
        if let Some(c) = cwd {
            cmd.current_dir(c);
        }
        // Another test thread may have forked while the script was open for writing; that child holds the write fd
        // until its exec, and executing the script meanwhile fails with ETXTBSY (errno 26). Retry, as the
        // backend-wine rig does.
        for _ in 0..500 {
            match cmd.spawn() {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(std::time::Duration::from_millis(4))
                }
                r => return FakeServer(r.unwrap()),
            }
        }
        panic!("{} stayed busy (ETXTBSY)", exe.display())
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_wineserver_for_this_prefix_makes_the_run_refuse_before_anything() {
    let r = abc();
    let bin = tempfile::tempdir().unwrap();
    let server = FakeServer::start(bin.path(), Some(&r.env.prefix()), None);
    let (f, a) = (FakeFetcher::default(), Answers::default());
    let err = run(&r, &r.plan(ABC), &f, &a).unwrap_err();
    assert!(err.to_string().contains("close the app"), "{err}");
    match err {
        DepsError::PrefixBusy { pids } => assert_eq!(pids, [server.0.id()]),
        other => panic!("{other:?}"),
    }
    assert!(f.calls().is_empty() && a.asked().is_empty());
    drop(server);
    assert_eq!(run(&r, &r.plan(ABC), &f, &a).unwrap().completed, ["a", "b", "c"]);
}

#[test]
fn wineserver_detection_by_env_spelling_and_by_server_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let prefix = tmp.path().join("prefix");
    fs::create_dir(&prefix).unwrap();
    let bin = tempfile::tempdir().unwrap();
    // With a trailing slash, and by the server directory as cwd (no WINEPREFIX: any other spelling of the prefix,
    // e.g. through a symlink, is caught this way, since a real wineserver always runs in its server directory).
    let m = fs::metadata(&prefix).unwrap();
    let server_dir = tmp.path().join(format!("server-{:x}-{:x}", m.dev(), m.ino()));
    fs::create_dir(&server_dir).unwrap();
    let mut slash = prefix.clone().into_os_string();
    slash.push("/");
    let cases: [(Option<PathBuf>, Option<&Path>); 2] = [(Some(PathBuf::from(slash)), None), (None, Some(&server_dir))];
    for (env, cwd) in cases {
        let s = FakeServer::start(bin.path(), env.as_deref(), cwd);
        assert_eq!(wineservers_for(&prefix).unwrap(), [s.0.id()], "{env:?} {cwd:?}");
    }
    let other = tmp.path().join("other");
    fs::create_dir(&other).unwrap();
    let _s = FakeServer::start(bin.path(), Some(&other), None);
    assert!(wineservers_for(&prefix).unwrap().is_empty());
}

#[test]
fn serves_parses_proc_like_inputs() {
    let t = Target {
        spellings: vec![b"/data/apps/x/prefix".to_vec()],
        server_dir: Some("server-803-1f".into()),
    };
    assert!(is_wineserver(Some(Path::new("/usr/lib/wine/wineserver64")), None));
    assert!(is_wineserver(None, Some(b"wineserver\n")));
    assert!(is_wineserver(Some(Path::new("/opt/wineserver (deleted)")), None));
    assert!(!is_wineserver(Some(Path::new("/usr/bin/wine64")), Some(b"wine64\n")));
    assert!(!is_wineserver(None, None), "unreadable is not a match");
    let env = |v: &[u8]| [b"A=1\0".as_slice(), v, b"\0B=2\0"].concat();
    assert!(t.serves(Some(&env(b"WINEPREFIX=/data/apps/x/prefix")), None));
    assert!(t.serves(Some(&env(b"WINEPREFIX=/data/apps/x/prefix//")), None));
    assert!(!t.serves(Some(&env(b"WINEPREFIX=/data/apps/x/prefix2")), None));
    assert!(!t.serves(Some(&env(b"XWINEPREFIX=/data/apps/x/prefix")), None));
    assert!(
        !t.serves(Some(b"WINEPREFIX=/data/apps/x/pre"), None),
        "truncated environ"
    );
    assert!(t.serves(None, Some(Path::new("/tmp/.wine-1000/server-803-1f"))));
    assert!(!t.serves(None, Some(Path::new("/tmp/.wine-1000/server-803-20"))));
    assert!(!t.serves(None, None));
    assert!(!t.serves(Some(&[0xff, 0, 0xfe]), Some(Path::new("/"))));
}

#[test]
fn a_program_started_during_a_download_stops_the_run_before_installing() {
    let r = abc();
    let bin = tempfile::tempdir().unwrap();
    let prefix = r.env.prefix();
    let dir = bin.path().to_path_buf();
    let slot = std::rc::Rc::new(RefCell::new(None::<FakeServer>));
    let s2 = slot.clone();
    let f = FakeFetcher {
        hook: Some(Box::new(move |p: &Package| {
            if p.id == "a" {
                *s2.borrow_mut() = Some(FakeServer::start(&dir, Some(&prefix), None));
            }
        })),
        ..FakeFetcher::default()
    };
    let rep = run(&r, &r.plan(ABC), &f, &Answers::default()).unwrap();
    assert!(rep.completed.is_empty(), "{rep:?}");
    assert!(reason(&rep.failed, "a").contains("close"), "{rep:?}");
    assert_eq!(f.calls(), ["a"]);
    assert_eq!(ids(&rep.skipped), ["b", "c"]);
    assert!(!r.c("windows/system32/a.dll").exists(), "installed under a running app");
    assert!(r.recorded().is_empty());
    slot.borrow_mut().take();
}

// ------------------------------------------------------------------------------------------------ plan_for_app

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    fs::read(&p).unwrap_or_else(|e| panic!("{}: {e} (run tools/build-fixtures.sh)", p.display()))
}

/// `bytes` with the import name `from` renamed to `to` (same length or shorter, NUL-padded).
fn patch_import(mut bytes: Vec<u8>, from: &str, to: &str) -> Vec<u8> {
    assert!(to.len() <= from.len());
    let at = bytes
        .windows(from.len() + 1)
        .position(|w| w[..from.len()].eq_ignore_ascii_case(from.as_bytes()) && w[from.len()] == 0)
        .unwrap_or_else(|| panic!("{from} not in the fixture"));
    let mut new = to.as_bytes().to_vec();
    new.resize(from.len(), 0);
    bytes[at..at + from.len()].copy_from_slice(&new);
    bytes
}

fn dxvk_manifest() -> Manifest {
    let (dxvk, _) = archive("dxvk", false, &[], &["d3d9", "d3d10core", "d3d11", "dxgi"]);
    Manifest { packages: vec![dxvk] }
}

fn app_with_exe(bytes: Option<&[u8]>) -> Rig {
    let r = Rig::new(vec![]);
    if let Some(b) = bytes {
        fs::write(r.c("app.exe"), b).unwrap();
    }
    r
}

#[test]
fn a_d3d11_import_plans_dxvk_without_warnings_for_a_64_bit_app() {
    let exe = patch_import(fixture("hello64.exe"), "msvcrt.dll", "d3d11.dll");
    assert!(
        pe::analyze(&exe)
            .unwrap()
            .imports
            .iter()
            .any(|i| i.dll.eq_ignore_ascii_case("d3d11.dll"))
    );
    let r = app_with_exe(Some(&exe));
    let app = plan_for_app(&r.env, &r.md(), &dxvk_manifest(), &|_| VulkanVerdict::Unknown);
    assert_eq!(app.plan.entries.len(), 1);
    assert_eq!(app.plan.entries[0].package, "dxvk");
    assert_eq!(app.plan.entries[0].action, Action::Install);
    assert!(app.warnings.is_empty(), "{:?}", app.warnings);
}

#[test]
fn a_32_bit_app_gets_the_x64_only_warning() {
    let exe = patch_import(fixture("hello32.exe"), "msvcrt.dll", "d3d11.dll");
    let r = app_with_exe(Some(&exe));
    let app = plan_for_app(&r.env, &r.md(), &dxvk_manifest(), &|_| VulkanVerdict::Unknown);
    assert_eq!(app.plan.entries[0].package, "dxvk");
    assert!(
        app.warnings
            .iter()
            .any(|w| w.contains("64-bit only") && w.contains("builtin")),
        "{:?}",
        app.warnings
    );
}

#[test]
fn a_32_bit_d3d8_app_gets_the_x64_only_warning_too() {
    let exe = patch_import(fixture("hello32.exe"), "msvcrt.dll", "d3d8.dll");
    let r = app_with_exe(Some(&exe));
    let (d8, _) = archive("dxvk8", false, &[], &["d3d8"]);
    let app = plan_for_app(&r.env, &r.md(), &Manifest { packages: vec![d8] }, &|_| {
        VulkanVerdict::Unknown
    });
    assert_eq!(app.plan.entries[0].package, "dxvk8");
    assert!(
        app.warnings
            .iter()
            .any(|w| w.contains("dxvk8") && w.contains("64-bit only")),
        "{:?}",
        app.warnings
    );
}

#[test]
fn an_unsatisfied_capability_is_a_warning() {
    let exe = patch_import(fixture("hello64.exe"), "KERNEL32.dll", "mscoree.dll");
    let r = app_with_exe(Some(&exe));
    let app = plan_for_app(&r.env, &r.md(), &dxvk_manifest(), &|_| VulkanVerdict::Unknown);
    assert!(app.plan.entries.is_empty());
    assert!(app.warnings.iter().any(|w| w.contains("dotnet")), "{:?}", app.warnings);
}

#[test]
fn an_unreadable_executable_is_a_warning_and_an_empty_plan() {
    // Missing, a directory, a FIFO (must not hang), not a PE, a symlink.
    let cases: [&dyn Fn(&Rig); 5] = [
        &|_| {},
        &|r| fs::create_dir(r.c("app.exe")).unwrap(),
        &|r| {
            let c = std::ffi::CString::new(r.c("app.exe").into_os_string().into_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        },
        &|r| fs::write(r.c("app.exe"), b"plain text").unwrap(),
        &|r| {
            let real = r.tmp.path().join("real.exe");
            fs::write(&real, patch_import(fixture("hello64.exe"), "msvcrt.dll", "d3d11.dll")).unwrap();
            std::os::unix::fs::symlink(&real, r.c("app.exe")).unwrap();
        },
    ];
    for (i, setup) in cases.iter().enumerate() {
        let r = app_with_exe(None);
        setup(&r);
        let app = plan_for_app(&r.env, &r.md(), &dxvk_manifest(), &|_| VulkanVerdict::Unknown);
        assert!(app.plan.entries.is_empty(), "case {i}: {:?}", app.plan);
        assert_eq!(app.facts, Facts::default(), "case {i}");
        assert!(
            app.warnings
                .iter()
                .any(|w| w.contains("cannot read the app's executable")),
            "case {i}: {:?}",
            app.warnings
        );
    }
}

#[test]
fn installed_packages_come_from_metadata() {
    let exe = patch_import(fixture("hello64.exe"), "msvcrt.dll", "d3d11.dll");
    let r = app_with_exe(Some(&exe));
    let m = dxvk_manifest();
    let dxvk = &m.packages[0];
    let mut md = r.md();
    state::record(
        &mut md,
        DependencyRecord {
            id: dxvk.id.clone(),
            version: dxvk.version.clone(),
            sha256: dxvk.sha256.clone(),
            installed_at: OLD,
            consent: None,
        },
    )
    .unwrap();
    let app = plan_for_app(&r.env, &md, &m, &|_| VulkanVerdict::Unknown);
    assert_eq!(app.plan.entries[0].action, Action::AlreadyInstalled);
}

// ------------------------------------------------------------------------------------------------ discard

/// A killed-run journal for package `zz` (not recorded) that created `windows/system32/zz.dll`; returns the journal
/// path and its text.
fn killed_journal(r: &Rig) -> (PathBuf, String) {
    let dir = r.env.root().join(install_archive::BACKUP_DIR).join("zz");
    fs::create_dir_all(&dir).unwrap();
    let text = format!("rt-deps-journal 1 {OTHER_SHA}\nF windows/system32/zz.dll\n");
    fs::write(dir.join("journal"), &text).unwrap();
    fs::write(r.c("windows/system32/zz.dll"), b"left by a killed run").unwrap();
    (dir.join("journal"), text)
}

#[test]
fn discard_during_a_running_install_is_lock_held_and_touches_nothing() {
    let r = abc();
    let (journal, text) = killed_journal(&r);
    let (store, env) = (r.store.clone(), r.env.clone());
    let got = std::rc::Rc::new(RefCell::new(None));
    let got2 = got.clone();
    let f = FakeFetcher {
        hook: Some(Box::new(move |p: &Package| {
            if p.id == "a" {
                *got2.borrow_mut() = Some(discard_interrupted_for(&store, &env, "zz"));
            }
        })),
        ..FakeFetcher::default()
    };
    run(&r, &r.plan(&["d3d9"]), &f, &Answers::default()).unwrap();
    let got = got.borrow_mut().take().unwrap();
    assert!(matches!(got, Err(DepsError::LockHeld)), "{got:?}");
    assert_eq!(fs::read_to_string(&journal).unwrap(), text);
    assert!(r.c("windows/system32/zz.dll").is_file());
}

#[test]
fn discard_under_a_running_app_is_prefix_busy() {
    let r = abc();
    let (journal, text) = killed_journal(&r);
    let bin = tempfile::tempdir().unwrap();
    let _server = FakeServer::start(bin.path(), Some(&r.env.prefix()), None);
    let got = discard_interrupted_for(&r.store, &r.env, "zz");
    assert!(matches!(got, Err(DepsError::PrefixBusy { .. })), "{got:?}");
    assert_eq!(fs::read_to_string(&journal).unwrap(), text);
    assert!(r.c("windows/system32/zz.dll").is_file());
}

#[test]
fn discard_of_a_recorded_package_is_refused() {
    let r = abc();
    let (journal, text) = killed_journal(&r);
    let mut m = r.md();
    state::record(
        &mut m,
        DependencyRecord {
            id: "zz".into(),
            version: "1.0".into(),
            sha256: OTHER_SHA.into(),
            installed_at: OLD,
            consent: None,
        },
    )
    .unwrap();
    r.set_md(&m);
    let got = discard_interrupted_for(&r.store, &r.env, "zz");
    assert!(matches!(&got, Err(DepsError::Recorded(id)) if id == "zz"), "{got:?}");
    assert_eq!(fs::read_to_string(&journal).unwrap(), text);
    assert!(r.c("windows/system32/zz.dll").is_file());
}

#[test]
fn discard_of_an_unrecorded_killed_install_restores_the_prefix() {
    let r = abc();
    let (journal, _) = killed_journal(&r);
    let rep = discard_interrupted_for(&r.store, &r.env, "zz").unwrap();
    assert_eq!(rep.removed_files, [PathBuf::from("windows/system32/zz.dll")]);
    assert!(!r.c("windows/system32/zz.dll").exists());
    assert!(!journal.exists());
    // The lock was released: a run can start.
    drop(lock_app(&r.env).unwrap());
}

#[test]
fn dropping_the_lock_releases_it_even_while_the_open_file_is_shared() {
    // What a child forked by another thread holds until it execs: another reference to the same open file.
    let r = abc();
    let lock = lock_app(&r.env).unwrap();
    let dup = lock.0.try_clone().unwrap();
    drop(lock);
    drop(lock_app(&r.env).expect("the lock outlived its AppLock"));
    drop(dup);
}

#[test]
fn shared_locks_coexist_and_exclude_an_exclusive_one_both_ways() {
    let r = abc();
    let (s1, s2) = (lock_app_shared(&r.env).unwrap(), lock_app_shared(&r.env).unwrap());
    assert!(matches!(lock_app(&r.env), Err(DepsError::LockHeld)));
    drop(s1);
    assert!(
        matches!(lock_app(&r.env), Err(DepsError::LockHeld)),
        "one shared holder is enough"
    );
    drop(s2);
    let ex = lock_app(&r.env).unwrap();
    assert!(matches!(lock_app_shared(&r.env), Err(DepsError::LockHeld)));
    drop(ex);
    drop(lock_app_shared(&r.env).unwrap());
}

#[test]
fn a_lock_is_not_inherited_by_a_child_process() {
    let r = abc();
    type Take = fn(&AppEnv) -> Result<AppLock, DepsError>;
    for take in [lock_app_shared as Take, lock_app] {
        let lock = take(&r.env).unwrap();
        let out = Command::new("/bin/sh")
            .args(["-c", "ls -l /proc/$$/fd"])
            .output()
            .unwrap();
        let fds = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success() && fds.contains("->"), "{fds}");
        assert!(!fds.contains(LOCK_FILE), "the lock fd leaked into a child: {fds}");
        drop(lock);
    }
}

/// `install_one`'s own consent check, reached directly: a plan that (wrongly) carries an unconsented gated Install.
#[test]
fn execute_never_fetches_a_gated_install_without_consent() {
    let r = three();
    let (f, a) = (FakeFetcher::default(), Answers::default());
    let (l, b) = (launcher(), FakeBackend::new());
    let o = Orchestrator {
        manifest: &r.manifest,
        cache_dir: &r.tmp.path().join("files"),
        env: &r.env,
        store: &r.store,
        backend: &b,
        launcher: &l,
        fetcher: &f,
        consent: &a,
        now,
    };
    let plan = Plan {
        entries: vec![PlanEntry {
            package: "gated".into(),
            action: Action::Install,
            consent: ConsentState::Needed,
        }],
        unsatisfied: vec![],
    };
    let rep = execute(&o, &plan, &Decisions::default(), &[]);
    assert!(f.calls().is_empty(), "fetched without consent");
    assert!(reason(&rep.failed, "gated").contains("consent missing"), "{rep:?}");
    assert!(r.recorded().is_empty() && a.asked().is_empty());
}

mod e2e;
