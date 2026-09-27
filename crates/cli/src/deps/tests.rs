use super::*;
use clap::Parser;
use rt_core::{BackendInfo, FakeBackend, WinPath};
use rt_deps::manifest::PROPRIETARY;
use rt_deps::{ArchiveFormat, Extract, FetchError, Fetcher, Install, Kind, PlanEntry};
use std::io::Cursor;
use std::os::unix::fs::symlink;
use std::rc::Rc;

// ------------------------------------------------------------------------------------------------ fixtures

fn sha(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn zip_one(name: &str, data: &[u8]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let o = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    w.start_file(name, o).unwrap();
    w.write_all(data).unwrap();
    w.finish().unwrap().into_inner()
}

/// A zip package installing `windows/system32/<id>.dll`.
fn archive(id: &str, gated: bool, requires: &[&str], provides: &[&str]) -> (Package, Vec<u8>) {
    let body = zip_one("f.dll", format!("dll of {id}").as_bytes());
    let pkg = Package {
        id: id.into(),
        version: "1.0".into(),
        sha256: sha(&body),
        size: body.len() as u64,
        licence: if gated { PROPRIETARY.into() } else { "MIT".into() },
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
        let md = Metadata::new(
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
        );
        store.write_metadata(&env, &md).unwrap();
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

    fn recorded(&self) -> Vec<String> {
        let md = self.store.read_metadata(&self.env).unwrap();
        md.dependencies.into_iter().map(|d| d.id).collect()
    }

    /// The plan for an app importing `imports` (what `plan_for_app` gives for such an executable).
    fn plan(&self, imports: &[&str]) -> AppPlan {
        let facts = rt_deps::Facts {
            imports: imports.iter().map(|s| (*s).to_owned()).collect(),
            extra_capabilities: vec![],
            requested: vec![],
        };
        let md = self.store.read_metadata(&self.env).unwrap();
        let plan = rt_deps::resolve(&facts, &rt_deps::installed_set(&md), &[], &self.manifest);
        AppPlan {
            facts,
            plan,
            warnings: vec![],
        }
    }

    /// Installs through the CLI's own consent provider and report, with a counting fake fetcher.
    fn install(&self, app: &AppPlan, f: &FakeFetcher, consent: &CliConsent) -> (String, u8) {
        let (l, b) = (Launcher::with_host_env([("PATH", "/usr/bin:/bin")]), FakeBackend::new());
        let cache = self.tmp.path().join("files");
        let o = Orchestrator {
            manifest: &self.manifest,
            cache_dir: &cache,
            env: &self.env,
            store: &self.store,
            backend: &b,
            launcher: &l,
            fetcher: f,
            consent,
            now: || 1_900_000_000,
            vulkan: &|_| rt_core::VulkanVerdict::Unknown,
            // No installer package runs in these tests.
            runtime_exe: std::path::Path::new("/nonexistent/runtime"),
        };
        install_report(&o, app).unwrap()
    }
}

#[derive(Default)]
struct FakeFetcher {
    calls: RefCell<Vec<String>>,
    fail: Vec<&'static str>,
}

impl Fetcher for FakeFetcher {
    fn fetch(&self, pkg: &Package, cache_dir: &Path) -> Result<PathBuf, FetchError> {
        self.calls.borrow_mut().push(pkg.id.clone());
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

/// A writer the test can read back after the consent provider (which owns a `Box<dyn Write>`) is done.
#[derive(Clone, Default)]
struct Shared(Rc<RefCell<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Shared {
    fn text(&self) -> String {
        String::from_utf8(self.0.borrow().clone()).unwrap()
    }
}

struct Broken;

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn consent<'a>(yes: &'a [String], out: &Shared, answers: Option<&'static str>) -> CliConsent<'a> {
    CliConsent::new(
        yes,
        Box::new(out.clone()),
        answers.map(|a| Box::new(Cursor::new(a.as_bytes())) as Box<dyn BufRead>),
    )
}

/// perm (permissive), gated (consent), gdep (permissive, requires gated).
fn three() -> Rig {
    Rig::new(vec![
        archive("perm", false, &[], &["d3d11"]),
        archive("gated", true, &[], &["vcruntime140"]),
        archive("gdep", false, &["gated"], &["msvcp140"]),
    ])
}
const THREE: &[&str] = &["d3d11.dll", "vcruntime140.dll", "msvcp140.dll"];

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

// ------------------------------------------------------------------------------------------------ plan output

#[test]
fn the_plan_output_for_a_fake_app() {
    let mut r = three();
    r.manifest.packages.push(archive("done", false, &[], &["dxgi"]).0);
    let mut ap = r.plan(&["d3d11.dll", "vcruntime140.dll", "msvcp140.dll"]);
    ap.plan.entries.push(PlanEntry {
        package: "done".into(),
        action: Action::AlreadyInstalled,
        consent: ConsentState::NotNeeded,
    });
    ap.plan.entries.push(PlanEntry {
        package: "ghost".into(),
        action: Action::Blocked {
            reason: "blocked: requires unknown package \"x\"".into(),
        },
        consent: ConsentState::Needed,
    });
    ap.warnings
        .push("the app needs \"dotnet\", which no available package provides".into());
    let want = "Dependencies of app:\n  \
                gated 1.0 (proprietary-redistributable): to install, needs your consent\n  \
                gdep 1.0 (MIT): to install\n  \
                perm 1.0 (MIT): to install\n  \
                done 1.0 (MIT): already installed\n  \
                ghost: blocked: blocked: requires unknown package \"x\"\n\
                warning: the app needs \"dotnet\", which no available package provides\n\
                note: a package you do not consent to is skipped together with everything that needs it; the \
                packages it needs itself still install\n\
                Install with: runtime deps app --install [--yes gated]\n";
    assert_eq!(format_plan("app", &ap, &r.manifest, false), want);
    assert_eq!(format_plan("app", &ap, &r.manifest, false), want, "deterministic");
    // With --install the report follows: no "Install with" line.
    let with = format_plan("app", &ap, &r.manifest, true);
    assert!(
        with.ends_with("still install\n") && !with.contains("Install with"),
        "{with}"
    );
    // Nothing to do.
    let empty = AppPlan {
        facts: rt_deps::Facts::default(),
        plan: Plan::default(),
        warnings: vec![],
    };
    assert_eq!(
        format_plan("app", &empty, &r.manifest, false),
        "Dependencies of app:\n  (none that the runtime can provide)\nNothing to install.\n"
    );
}

#[test]
fn plan_and_report_text_is_sanitised() {
    let r = three();
    let mut ap = r.plan(THREE);
    ap.warnings.push("w\x1b[31m\u{202e}\nx".into());
    ap.plan.entries[0].package = "g\u{9b}2J".into();
    ap.plan.entries.push(PlanEntry {
        package: "b".into(),
        action: Action::Blocked {
            reason: "r\x1b[2J\u{2067}".into(),
        },
        consent: ConsentState::NotNeeded,
    });
    let mut out = format_plan("a\x1bpp", &ap, &r.manifest, false);
    let (rep, _) = format_report(&RunReport {
        completed: vec!["c\x1b".into()],
        failed: vec![("f\u{202e}".into(), "why\r\n\x07".into())],
        skipped: vec![("s".into(), "\u{2066}x".into())],
        warnings: vec![("w".into(), "\x1b]0;t\x07".into())],
    });
    out.push_str(&rep);
    for c in out.chars() {
        assert!(
            !(c.is_control() && c != '\n') && !rt_core::is_format(c),
            "raw U+{:04X} in {out:?}",
            c as u32
        );
    }
    assert_eq!(out.lines().count(), 6 + 1 + 1 + 5, "no injected line breaks: {out}");
}

#[test]
fn the_manifest_listing() {
    let r = three();
    assert_eq!(
        format_manifest(&r.manifest),
        "Bundled packages:\n  perm 1.0 (MIT): provides d3d11\n  gated 1.0 (proprietary-redistributable, needs \
         consent): provides vcruntime140\n  gdep 1.0 (MIT): provides msvcp140; requires gated\n"
    );
    assert!(format_manifest(Manifest::bundled()).contains("dxvk"));
    assert!(format_manifest(Manifest::bundled()).contains("vcrun2022"));
}

// ------------------------------------------------------------------------------------------------ usage

fn parse(args: &[&str]) -> Result<crate::Cli, clap::Error> {
    crate::Cli::try_parse_from(std::iter::once("runtime").chain(args.iter().copied()))
}

fn deps_args(args: &[&str]) -> DepsArgs {
    match parse(args).unwrap().cmd {
        crate::Cmd::Deps(a) => a,
        _ => panic!("not deps"),
    }
}

#[test]
fn a_bare_yes_is_a_usage_error() {
    for bad in [
        &["deps", "app", "--install", "--yes"][..],
        &["deps", "app", "--yes", "--install"],
        &["deps", "app", "--yes", "vc"],
        &["deps", "app", "--install", "--discard-interrupted", "vc"],
        &["deps"],
        &["deps", "app", "--discard-interrupted"],
    ] {
        assert!(parse(bad).is_err(), "{bad:?} parsed");
    }
    let a = deps_args(&["deps", "app", "--install", "--yes", "vc", "--yes", "x"]);
    assert_eq!(
        (a.app.as_deref(), a.install, a.yes.clone()),
        (Some("app"), true, strings(&["vc", "x"]))
    );
    assert!(matches!(deps_args(&["deps", "list"]).sub, Some(DepsSub::List)));
    assert!(matches!(
        deps_args(&["deps", "cache", "--clear"]).sub,
        Some(DepsSub::Cache { clear: true })
    ));
    let a = deps_args(&["deps", "app", "--discard-interrupted", "dxvk"]);
    assert_eq!(a.discard_interrupted.as_deref(), Some("dxvk"));
}

#[test]
fn plan_digest_is_64_lowercase_hex_and_needs_install() {
    let d = "0a".repeat(32);
    let a = deps_args(&["deps", "app", "--install", "--plan-digest", &d]);
    assert_eq!(a.plan_digest.as_deref(), Some(d.as_str()));
    assert_eq!(deps_args(&["deps", "app", "--install"]).plan_digest, None);
    let upper = d.to_uppercase();
    let short = &d[1..];
    let long = format!("{d}0");
    let flag = format!("--plan-digest={d}");
    for bad in [
        &["deps", "app", "--plan-digest", &d][..],
        &["deps", "app", "--install", "--plan-digest", &upper],
        &["deps", "app", "--install", "--plan-digest", short],
        &["deps", "app", "--install", "--plan-digest", &long],
        &["deps", "app", "--install", "--plan-digest", "g".repeat(64).as_str()],
        &["deps", "app", "--install", "--plan-digest"],
        &["deps", "app", "--install", &flag, "--discard-interrupted", "x"],
        &["deps", "list", &flag],
    ] {
        assert!(parse(bad).is_err(), "{bad:?} parsed");
    }
}

#[test]
fn the_plan_digest_guard_refuses_any_other_plan() {
    let r = three();
    let ap = r.plan(THREE);
    let d = rt_api::jobs::plan_digest(r.env.id(), &ap, &r.manifest);
    check_plan_digest(r.env.id(), &ap, &r.manifest, None).unwrap();
    check_plan_digest(r.env.id(), &ap, &r.manifest, Some(&d)).unwrap();
    let stale = "0".repeat(64);
    let e = check_plan_digest(r.env.id(), &ap, &r.manifest, Some(&stale)).unwrap_err();
    assert!(
        e.contains("the dependency plan changed since it was shown") && e.contains("nothing was installed"),
        "{e}"
    );
    let mut other = ap.clone();
    other.plan.entries.pop();
    assert!(check_plan_digest(r.env.id(), &other, &r.manifest, Some(&d)).is_err());
}

#[test]
fn every_yes_must_name_a_gated_package_the_plan_installs() {
    let r = three();
    let ap = r.plan(THREE);
    check_yes(&ap.plan, &strings(&["gated"])).unwrap();
    check_yes(&ap.plan, &[]).unwrap();
    // Not in the plan, needs no consent, or blocked: all refused.
    for bad in ["nope", "perm", "gdep"] {
        let e = check_yes(&ap.plan, &strings(&["gated", bad])).unwrap_err();
        assert!(e.contains(bad) && e.contains("nothing was installed"), "{e}");
    }
    let mut blocked = ap.plan.clone();
    blocked.entries[0].action = Action::Blocked { reason: "x".into() };
    assert_eq!(blocked.entries[0].package, "gated");
    assert!(check_yes(&blocked, &strings(&["gated"])).is_err());
}

// ------------------------------------------------------------------------------------------------ consent

#[test]
fn install_without_consent_never_fetches_the_gated_package() {
    for answers in [None, Some(""), Some("n\n"), Some("yess\n"), Some("no\n")] {
        let r = three();
        let (f, out) = (FakeFetcher::default(), Shared::default());
        let c = consent(&[], &out, answers);
        let (text, code) = r.install(&r.plan(THREE), &f, &c);
        assert_eq!(f.calls(), ["perm"], "{answers:?}");
        assert_eq!(r.recorded(), ["perm"]);
        assert_eq!(code, 1, "a skipped package is not full success: {text}");
        assert!(text.contains("skipped:   gated: consent denied"), "{text}");
        let shown = out.text();
        assert!(
            shown.contains(&rt_deps::consent_text(r.manifest.get("gated").unwrap())),
            "{shown}"
        );
        assert!(shown.contains("No consent: gated is skipped"), "{shown}");
        if answers.is_none() {
            assert!(shown.contains("--yes gated") && !shown.contains("[y/N]"), "{shown}");
        }
    }
}

#[test]
fn the_yes_path_prints_the_consent_text_verbatim_before_consenting() {
    let r = three();
    let (f, out) = (FakeFetcher::default(), Shared::default());
    let yes = strings(&["gated"]);
    let c = consent(&yes, &out, None);
    let (text, code) = r.install(&r.plan(THREE), &f, &c);
    assert_eq!((code, f.calls()), (0, strings(&["gated", "gdep", "perm"])), "{text}");
    let ct = rt_deps::consent_text(r.manifest.get("gated").unwrap());
    assert_eq!(
        out.text(),
        format!("\n{ct}\nConsent given on the command line (--yes gated).\n\n")
    );
    assert_eq!(
        text,
        "installed: gated\ninstalled: gdep\ninstalled: perm\n3 installed, 0 failed, 0 skipped, 0 already installed\n"
    );
}

#[test]
fn interactive_answers() {
    let (p, _) = archive("gated", true, &[], &[]);
    for (answer, want) in [
        ("y\n", true),
        ("Y\n", true),
        (" yes \n", true),
        ("YES", true),
        ("", false),
        ("\n", false),
        ("n\n", false),
        ("yes please\n", false),
    ] {
        let out = Shared::default();
        let c = consent(&[], &out, Some(answer));
        assert_eq!(c.confirm(&p, "TEXT"), want, "{answer:?}");
        assert!(
            out.text()
                .starts_with("\nTEXT\nInstall gated under this licence? [y/N] "),
            "{}",
            out.text()
        );
    }
}

#[test]
fn consent_is_no_when_the_text_cannot_be_shown() {
    let (p, _) = archive("gated", true, &[], &[]);
    let yes = strings(&["gated"]);
    for answers in [None, Some("y\n")] {
        let c = CliConsent::new(
            &yes,
            Box::new(Broken),
            answers.map(|a| Box::new(Cursor::new(a.as_bytes())) as Box<dyn BufRead>),
        );
        assert!(!c.confirm(&p, "TEXT"), "consent recorded for a text nobody saw");
    }
}

// ------------------------------------------------------------------------------------------------ report

#[test]
fn a_partial_failure_reports_all_three_lists_and_records_only_what_completed() {
    let r = Rig::new(vec![
        archive("a", false, &[], &["d3d9"]),
        archive("b", false, &[], &["d3d11"]),
        archive("c", false, &[], &["dxgi"]),
    ]);
    let f = FakeFetcher {
        fail: vec!["b"],
        ..FakeFetcher::default()
    };
    let out = Shared::default();
    let (text, code) = r.install(&r.plan(&["d3d9", "d3d11", "dxgi"]), &f, &consent(&[], &out, None));
    assert_eq!(code, 1);
    assert_eq!(
        text,
        "installed: a\nFAILED:    b: download failed: download does not match the manifest sha256\n\
         skipped:   c: not attempted: an earlier package failed\n1 installed, 1 failed, 1 skipped, 0 already installed\n"
    );
    assert_eq!(r.recorded(), ["a"]);
    assert!(out.text().is_empty(), "nothing asked");
}

#[test]
fn report_exit_codes_and_the_ruling_texts() {
    let ok = |skipped: Vec<(String, String)>| RunReport {
        completed: vec!["a".into()],
        skipped,
        ..RunReport::default()
    };
    assert_eq!(format_report(&ok(vec![])).1, 0);
    assert_eq!(
        format_report(&RunReport::default()),
        ("Nothing to install.\n".into(), 0),
        "nothing to do"
    );
    assert_eq!(
        format_report(&ok(vec![("b".into(), rt_deps::ALREADY_INSTALLED.into())])).1,
        0
    );
    let upgrade = "version 1.0 is installed; upgrading installed packages is not supported yet: recreate the \
                   environment to get version 2.0";
    let (text, code) = format_report(&ok(vec![("b".into(), upgrade.into())]));
    assert_eq!(code, 1);
    assert!(text.contains(&format!("skipped:   b: {upgrade}\n")), "{text}");
    let marker = "the prefix already contains this component from outside the runtime; recreate the environment";
    let (text, code) = format_report(&RunReport {
        failed: vec![("vc".into(), marker.into())],
        warnings: vec![("x".into(), "partial".into())],
        ..RunReport::default()
    });
    assert_eq!(code, 1);
    assert!(
        text.contains(&format!("FAILED:    vc: {marker}\n")) && text.contains("warning:   x: partial"),
        "{text}"
    );
}

#[test]
fn a_journal_error_names_the_discard_command_and_discard_errors_are_clear() {
    let r = Rig::new(vec![archive("a", false, &[], &["d3d9"])]);
    let dir = r.env.root().join(rt_deps::install_archive::BACKUP_DIR).join("a");
    fs::create_dir_all(&dir).unwrap();
    let other = "f".repeat(64);
    fs::write(
        dir.join("journal"),
        format!("rt-deps-journal 1 {other}\nF windows/system32/left.dll\n"),
    )
    .unwrap();
    fs::write(r.env.drive_c().join("windows/system32/left.dll"), b"left").unwrap();
    let (text, code) = r.install(
        &r.plan(&["d3d9"]),
        &FakeFetcher::default(),
        &consent(&[], &Shared::default(), None),
    );
    assert_eq!(code, 1);
    assert!(text.contains("runtime deps app --discard-interrupted a"), "{text}");
    let msg = discard_error(DepsError::Recorded("a".into()), "a");
    assert!(
        msg.contains("recorded as installed") && msg.contains("recreate the environment"),
        "{msg}"
    );
    let rep = rt_deps::discard_interrupted_for(&r.store, &r.env, "a").unwrap();
    assert!(
        format_discard("a", &rep).contains("removed: windows/system32/left.dll"),
        "{rep:?}"
    );
    assert_eq!(format_discard("a", &Default::default()), "Nothing to discard for a.\n");
}

// ------------------------------------------------------------------------------------------------ hint

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    fs::read(&p).unwrap_or_else(|e| panic!("{}: {e} (run tools/build-fixtures.sh)", p.display()))
}

/// `bytes` with the import name `from` renamed to `to` (not longer, NUL padded).
fn patch_import(mut bytes: Vec<u8>, from: &str, to: &str) -> Vec<u8> {
    let at = bytes
        .windows(from.len() + 1)
        .position(|w| w[..from.len()].eq_ignore_ascii_case(from.as_bytes()) && w[from.len()] == 0)
        .unwrap();
    let mut new = to.as_bytes().to_vec();
    new.resize(from.len(), 0);
    bytes[at..at + from.len()].copy_from_slice(&new);
    bytes
}

#[test]
fn a_blocked_entry_is_not_counted_as_missing_in_the_hint() {
    let e = |package: &str, action| rt_deps::PlanEntry {
        package: package.into(),
        action,
        consent: rt_deps::ConsentState::NotNeeded,
    };
    let mut plan = AppPlan {
        facts: rt_deps::Facts::default(),
        plan: rt_deps::Plan {
            entries: vec![
                e(
                    "dxvk",
                    Action::Blocked {
                        reason: "Vulkan is unusable".into(),
                    },
                ),
                e("vcrun2022", Action::Install),
            ],
            unsatisfied: vec![],
        },
        warnings: vec![],
    };
    assert_eq!(
        hint_for("app", &plan).as_deref(),
        Some("hint: 1 dependency missing: run `runtime deps app`")
    );
    plan.plan.entries.remove(1);
    assert_eq!(hint_for("app", &plan), None);
}

#[test]
fn the_hint_is_one_line_and_only_when_something_is_missing() {
    let r = three();
    let md = r.store.read_metadata(&r.env).unwrap();
    // No executable: no plan, no hint.
    assert_eq!(missing_hint(&r.env, &md, &r.manifest), None);
    let exe = patch_import(fixture("hello64.exe"), "msvcrt.dll", "d3d11.dll");
    fs::write(r.env.drive_c().join("app.exe"), exe).unwrap();
    let h = missing_hint(&r.env, &md, &r.manifest).unwrap();
    assert_eq!(h, "hint: 1 dependency missing: run `runtime deps app`");
    let exe = patch_import(fixture("hello64.exe"), "KERNEL32.dll", "msvcp140.dll");
    let exe = patch_import(exe, "msvcrt.dll", "d3d11.dll");
    fs::write(r.env.drive_c().join("app.exe"), exe).unwrap();
    let h = missing_hint(&r.env, &md, &r.manifest).unwrap();
    assert_eq!(h, "hint: 3 dependencies missing: run `runtime deps app`");
    // Installed: no hint.
    let (text, _) = r.install(
        &rt_deps::plan_for_app(&r.env, &md, &r.manifest, &|_| rt_core::VulkanVerdict::Unknown),
        &FakeFetcher::default(),
        &consent(&strings(&["gated"]), &Shared::default(), None),
    );
    assert!(text.starts_with("installed: gated\n"), "{text}");
    let md = r.store.read_metadata(&r.env).unwrap();
    assert_eq!(missing_hint(&r.env, &md, &r.manifest), None);
    // A second --install finds everything there: full success, not "skipped".
    let (text, code) = r.install(
        &rt_deps::plan_for_app(&r.env, &md, &r.manifest, &|_| rt_core::VulkanVerdict::Unknown),
        &FakeFetcher::default(),
        &consent(&[], &Shared::default(), None),
    );
    assert_eq!(code, 0, "{text}");
    assert!(
        text.ends_with("0 installed, 0 failed, 0 skipped, 3 already installed\n"),
        "{text}"
    );
}

// ------------------------------------------------------------------------------------------------ cache

#[test]
fn cache_clear_removes_only_regular_files_named_as_a_sha256() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("cache");
    assert_eq!(cache_entries(&dir).unwrap(), [], "missing is empty");
    fs::create_dir(&dir).unwrap();
    let (a, b) = ("a".repeat(64), "0123456789abcdef".repeat(4));
    fs::write(dir.join(&a), b"12345").unwrap();
    fs::write(dir.join(&b), b"xy").unwrap();
    let outside = t.path().join("victim");
    fs::write(&outside, b"keep").unwrap();
    let keep = [
        ("c".repeat(64), "symlink"),
        ("d".repeat(64), "dir"),
        ("A".repeat(64), "upper"),
        ("e".repeat(63), "short"),
        (".tmp-1-0-00000000".into(), "tmp"),
        (format!("{}.part", "f".repeat(64)), "suffix"),
        ("notes.txt".into(), "stray"),
    ];
    for (name, kind) in &keep {
        match *kind {
            "symlink" => symlink(&outside, dir.join(name)).unwrap(),
            "dir" => fs::create_dir(dir.join(name)).unwrap(),
            _ => fs::write(dir.join(name), b"x").unwrap(),
        }
    }
    let listed = cache_entries(&dir).unwrap();
    let want = [
        CacheEntry {
            name: b.clone(),
            size: 2,
        },
        CacheEntry {
            name: a.clone(),
            size: 5,
        },
    ];
    assert_eq!(listed, want);
    assert_eq!(
        format_cache(&dir, &listed, false),
        format!(
            "Download cache: {}\n  {b}  2 bytes\n  {a}  5 bytes\nTotal: 2 file(s), 7 bytes\n",
            dir.display()
        )
    );
    let gone = clear_cache(&dir).unwrap();
    assert_eq!(gone, want);
    assert!(!dir.join(&a).exists() && !dir.join(&b).exists());
    for (name, kind) in &keep {
        assert!(fs::symlink_metadata(dir.join(name)).is_ok(), "{kind} entry deleted");
    }
    assert_eq!(fs::read(&outside).unwrap(), b"keep");
    assert_eq!(cache_entries(&dir).unwrap(), []);
}

#[test]
fn a_symlinked_cache_dir_is_refused() {
    let t = tempfile::tempdir().unwrap();
    let real = t.path().join("real");
    fs::create_dir(&real).unwrap();
    let name = "a".repeat(64);
    fs::write(real.join(&name), b"x").unwrap();
    symlink(&real, t.path().join("cache")).unwrap();
    assert!(clear_cache(&t.path().join("cache")).is_err());
    assert!(real.join(&name).exists());
}

// ------------------------------------------------------------------------------------------------ locks

#[test]
fn lock_or_refuse_refuses_while_held_and_names_the_command() {
    let r = three();
    let held = rt_deps::lock_app(&r.env).unwrap();
    for (shared, what) in [(true, "start"), (false, "remove")] {
        let e = lock_or_refuse(&r.env, shared, what).unwrap_err().to_string();
        assert!(
            e.starts_with(&format!("cannot {what} app: ")) && e.contains("wait"),
            "{e}"
        );
    }
    drop(held);
    let s = lock_or_refuse(&r.env, true, "start").unwrap();
    assert!(s.is_some());
    let s2 = lock_or_refuse(&r.env, true, "start").unwrap();
    assert!(s2.is_some(), "two apps can start at once");
    drop(s2);
    assert!(
        lock_or_refuse(&r.env, false, "remove").is_err(),
        "a start holds it shared"
    );
    drop(s);
    assert!(lock_or_refuse(&r.env, false, "remove").unwrap().is_some());
    // An unusable lock file (a directory, a symlink) is a warning, not a refusal: nobody can lock it.
    let r = three();
    fs::create_dir(r.env.root().join(rt_deps::LOCK_FILE)).unwrap();
    for shared in [true, false] {
        assert!(lock_or_refuse(&r.env, shared, "x").unwrap().is_none());
    }
    let r = three();
    symlink("/nonexistent", r.env.root().join(rt_deps::LOCK_FILE)).unwrap();
    assert!(lock_or_refuse(&r.env, false, "remove").unwrap().is_none());
    // Any other failure (here: the lock file cannot be created) refuses, for starting and for removing.
    let r = three();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(r.env.root(), fs::Permissions::from_mode(0o500)).unwrap();
    let probe = r.env.root().join(".rt-root-probe");
    if fs::File::create(&probe).is_ok() {
        let _ = fs::remove_file(&probe);
        fs::set_permissions(r.env.root(), fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!("SKIPPED the read-only-directory check: running as root, which writes there anyway");
        return;
    }
    let got: Vec<_> = [true, false]
        .map(|shared| lock_or_refuse(&r.env, shared, "remove").map(|l| l.is_some()))
        .into_iter()
        .collect();
    fs::set_permissions(r.env.root(), fs::Permissions::from_mode(0o700)).unwrap();
    for g in got {
        let e = g.unwrap_err().to_string();
        assert!(e.starts_with("cannot remove app: "), "{e}");
    }
}

#[test]
fn only_a_terminal_on_both_ends_is_asked() {
    assert!(can_ask(true, true));
    assert!(!can_ask(true, false), "a prompt the user cannot see");
    assert!(!can_ask(false, true));
    assert!(!can_ask(false, false));
}

#[test]
fn the_rest_of_an_over_long_answer_is_never_the_next_answer() {
    let (p, _) = archive("gated", true, &[], &[]);
    let out = Shared::default();
    let long: &'static str = Box::leak(format!("{}y\nn\ny\n", "x".repeat(300)).into_boxed_str());
    let c = consent(&[], &out, Some(long));
    assert!(!c.confirm(&p, "T"), "an over-long line is no");
    assert!(!c.confirm(&p, "T"), "its tail \"y\" became the next answer");
    assert!(c.confirm(&p, "T"), "the line after is read as it is");
    // An over-long "yes" is no too, and one without a newline at EOF.
    let long_yes: &'static str = Box::leak(format!("yes{}\n", " ".repeat(300)).into_boxed_str());
    assert!(!consent(&[], &Shared::default(), Some(long_yes)).confirm(&p, "T"));
    assert!(consent(&[], &Shared::default(), Some("y")).confirm(&p, "T"));
}

#[test]
fn doctor_notes_each_installer_already_in_the_prefix_and_nothing_else() {
    let plan = AppPlan {
        facts: rt_deps::Facts::default(),
        plan: rt_deps::Plan::default(),
        warnings: vec![
            format!("vcrun2022: {}", rt_deps::MARKER_PRESENT),
            "the app needs \"dotnet\", which no available package provides".into(),
            format!("x\u{1b}[31m: {}", rt_deps::MARKER_PRESENT),
        ],
    };
    let notes = present_notes(&plan);
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert_eq!(notes[0], format!("note: vcrun2022: {}", rt_deps::MARKER_PRESENT));
    assert!(notes[0].contains("did not set its DLL overrides"));
    assert!(!notes[1].contains('\u{1b}'), "unsanitised: {:?}", notes[1]);
}
