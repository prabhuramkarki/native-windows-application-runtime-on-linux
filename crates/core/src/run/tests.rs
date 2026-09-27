use super::*;
use crate::fake::{Call, FakeBackend};
use crate::testutil::{fixture, write_file};
use crate::{AppEnv, BackendInfo};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::sync::{Arc, Mutex};

const EXE_TEXT: &str = "C:\\Program Files\\app\\app.exe";

/// Collects what the `debug` tee writes to "the terminal".
#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Buf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

/// A terminal that is gone.
struct Broken;

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// `apps/` (the store), `in/` (the directory relative targets are read against) and an `outside/` canary dir.
struct Fx {
    tmp: tempfile::TempDir,
    store: Store,
    backend: FakeBackend,
    launcher: Launcher,
    term: Buf,
}

fn fx(script: &str) -> Fx {
    let tmp = tempfile::tempdir().unwrap();
    fs::create_dir(tmp.path().join("in")).unwrap();
    fs::create_dir(tmp.path().join("outside")).unwrap();
    Fx {
        store: Store::new(tmp.path().join("apps")).unwrap(),
        backend: FakeBackend::with_script(script),
        launcher: Launcher::with_host_env([("PATH", "/usr/bin:/bin")]),
        term: Buf::default(),
        tmp,
    }
}

impl Fx {
    /// An installed app `id` whose program `C:\Program Files\app\app.exe` exists. Built by hand (no `prepare`
    /// call is recorded on the backend).
    fn app(&self, id: &str) -> AppEnv {
        let id = AppId::parse(id).unwrap();
        let env = self.store.create(&id).unwrap();
        let dir = env.drive_c().join("Program Files/app");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("app.exe"), b"MZ").unwrap();
        let md = Metadata::new(
            id,
            "App".into(),
            None,
            "x86_64",
            &WinPath::parse(EXE_TEXT).unwrap(),
            BackendInfo {
                id: "fake".into(),
                version: "fake-1.0".into(),
            },
            "console",
        );
        self.store.write_metadata(&env, &md).unwrap();
        env
    }

    /// Rewrites one field of `metadata.json` behind the store's back (the store would refuse most values).
    fn tamper(&self, env: &AppEnv, edit: impl FnOnce(&mut serde_json::Value)) {
        let mut v: serde_json::Value = serde_json::from_slice(&fs::read(env.metadata_path()).unwrap()).unwrap();
        edit(&mut v);
        fs::write(env.metadata_path(), serde_json::to_vec(&v).unwrap()).unwrap();
    }

    fn start(&self, target: &str, args: &[OsString], debug: bool) -> Result<Started, RunAppError> {
        let term = self.term.clone();
        let terminal = move || -> Box<dyn Write + Send> { Box::new(term.clone()) };
        let base = self.tmp.path().join("in");
        let env = Env {
            base: &base,
            terminal: &terminal,
        };
        start_in(
            &self.store,
            &self.backend,
            &self.launcher,
            target,
            args,
            &RunOptions {
                debug,
                ..RunOptions::default()
            },
            &env,
        )
    }

    fn go(&self, target: &str, args: &[OsString]) -> Result<RunOutcome, RunAppError> {
        self.start(target, args, false)?.wait()
    }

    fn commands(&self) -> Vec<Call> {
        self.backend
            .calls()
            .into_iter()
            .filter(|c| matches!(c, Call::Command { .. }))
            .collect()
    }

    fn prepares(&self) -> usize {
        self.backend
            .calls()
            .iter()
            .filter(|c| matches!(c, Call::Prepare { .. }))
            .count()
    }

    fn input(&self, name: &str, bytes: &[u8]) -> PathBuf {
        write_file(&self.tmp.path().join("in"), name, bytes)
    }

    fn app_dirs(&self) -> Vec<String> {
        match fs::read_dir(self.store.apps_dir()) {
            Ok(rd) => {
                let mut v: Vec<String> = rd
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                v.sort();
                v
            }
            Err(_) => Vec::new(),
        }
    }
}

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn text(e: &RunAppError) -> String {
    e.to_string()
}

// ---------------------------------------------------------------- classification

#[test]
fn classify_table() {
    use TargetKind::{Id, Path};
    for (target, want) in [
        ("../x", Path),
        ("./x", Path),
        ("a/b.exe", Path),
        ("/abs/app", Path),
        ("dir/app", Path),
        ("APP.EXE", Path),
        ("app.Exe", Path),
        ("hello.exe", Path),
        ("hello.zip", Path),
        ("HELLO.ZIP", Path),
        ("hello", Id),
        ("hello-2", Id),
        ("my.app", Id),
        ("exe", Id),
        ("zip", Id),
        ("app.exe.txt", Id),
        ("", Id),
        ("Hello World", Id),
    ] {
        assert_eq!(classify(target), want, "{target:?}");
    }
}

#[test]
fn exit_code_is_the_code_or_128_plus_the_signal() {
    assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
    assert_eq!(exit_code(ExitStatus::from_raw(7 << 8)), 7);
    assert_eq!(exit_code(ExitStatus::from_raw(255 << 8)), 255);
    assert_eq!(exit_code(ExitStatus::from_raw(15)), 143);
    assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
}

// ---------------------------------------------------------------- an installed app

#[test]
fn an_installed_app_runs_and_its_exit_code_passes_through() {
    for code in [0, 7, 255] {
        let f = fx(&format!("exit {code}"));
        let env = f.app("app");
        let out = f.go("app", &[]).unwrap();
        assert_eq!(out.exit_code, code);
        assert_eq!(out.status.code(), Some(code));
        assert!(out.installed.is_none());
        assert_eq!(out.id.as_str(), "app");
        assert!(!out.log_write_failed && !out.terminal_write_failed);
        assert!(out.log_path.starts_with(env.logs_dir()), "{:?}", out.log_path);
        assert!(out.log_path.is_file());
        let exe = env.drive_c().join("Program Files/app/app.exe");
        assert_eq!(
            f.commands(),
            [Call::Command {
                app: env.id().clone(),
                exe: exe.clone(),
                cwd: exe.parent().unwrap().to_owned(),
                args: vec![],
                debug: false,
                dotnet: false
            }]
        );
        assert_eq!(f.prepares(), 0, "an installed app is not prepared again");
    }
}

#[test]
fn a_program_killed_by_a_signal_reports_128_plus_the_signal() {
    let f = fx("kill -TERM $$");
    f.app("app");
    let out = f.go("app", &[]).unwrap();
    assert_eq!(out.status.code(), None);
    assert_eq!(out.status.signal(), Some(15));
    assert_eq!(out.exit_code, 143);
}

#[test]
fn a_started_program_can_be_killed() {
    let f = fx("exec sleep 60");
    f.app("app");
    let mut s = f.start("app", &[], false).unwrap();
    s.kill().unwrap();
    let out = s.wait().unwrap();
    assert_eq!(out.exit_code, 137);
}

#[test]
fn the_executable_is_found_ignoring_case_and_the_child_starts_in_its_directory() {
    let f = fx("pwd >&2");
    let env = f.app("app");
    f.tamper(&env, |v| {
        v["executable"] = "C:\\Program Files\\APP\\App.EXE".into();
    });
    let out = f.go("app", &[]).unwrap();
    let real = env.drive_c().join("Program Files/app/app.exe");
    let Call::Command { exe, cwd, .. } = &f.commands()[0] else {
        unreachable!()
    };
    assert_eq!(exe, &real, "the RESOLVED path is passed, not the metadata spelling");
    assert_eq!(cwd, real.parent().unwrap());
    let log = fs::read_to_string(&out.log_path).unwrap();
    assert_eq!(
        fs::canonicalize(log.trim()).unwrap(),
        fs::canonicalize(cwd).unwrap(),
        "the child ran in the program's directory"
    );
}

#[test]
fn arguments_are_passed_verbatim() {
    let f = fx(r#"printf '<%s>\n' "$@" >&2"#);
    f.app("app");
    let mut args = os(&[
        "a b",
        "\"quoted\"",
        "'single'",
        "x;y",
        "$(touch pwned)",
        "`id`",
        "l1\nl2",
        "-n",
        "--",
        "-",
        "*",
        "",
        "  spaces  ",
        "C:\\path\\with\\backslash",
        "$HOME",
        "a|b&c>d",
    ]);
    args.push(OsString::from_vec(b"non-utf8-\xff\xfe".to_vec()));
    let out = f.go("app", &args).unwrap();
    assert_eq!(out.exit_code, 0);
    let Call::Command { args: got, .. } = &f.commands()[0] else {
        unreachable!()
    };
    assert_eq!(got, &args, "exactly the arguments given");
    let log = fs::read(&out.log_path).unwrap();
    let mut want = b"<a b>\n<\"quoted\">\n<'single'>\n<x;y>\n<$(touch pwned)>\n<`id`>\n<l1\nl2>\n<-n>\n<-->\n<->\n<*>\n<>\n<  spaces  >\n<C:\\path\\with\\backslash>\n<$HOME>\n<a|b&c>d>\n<non-utf8-".to_vec();
    want.extend_from_slice(b"\xff\xfe>\n");
    assert_eq!(log, want);
    let env = f.store.get(&AppId::parse("app").unwrap()).unwrap();
    assert!(!env.drive_c().join("Program Files/app/pwned").exists(), "no shell ran");
}

// ---------------------------------------------------------------- dotnet

fn record(id: &str) -> crate::DependencyRecord {
    crate::DependencyRecord {
        id: id.into(),
        version: "9.4.0".into(),
        sha256: "0".repeat(64),
        installed_at: 1_800_000_000,
        consent: None,
    }
}

/// `RunOpts::dotnet` of the one `command()` call of a run of an app that records `ids` (`start_in`, fake backend).
fn dotnet_of(ids: &[String]) -> bool {
    let f = fx("exit 0");
    let env = f.app("app");
    let mut md = f.store.read_metadata(&env).unwrap();
    md.dependencies = ids.iter().map(|i| record(i)).collect();
    f.store.write_metadata(&env, &md).unwrap();
    f.go("app", &[]).unwrap();
    let Call::Command { dotnet, .. } = &f.commands()[0] else {
        unreachable!()
    };
    *dotnet
}

#[test]
fn dotnet_is_passed_to_the_backend_only_for_a_recorded_wine_mono() {
    assert!(!dotnet_of(&[]));
    assert!(dotnet_of(&["wine-mono".to_owned()]));
    assert!(!dotnet_of(&[
        "dxvk".to_owned(),
        "wine-mono2".to_owned(),
        "Wine-Mono".to_owned()
    ]));
    // The largest list `read` accepts: 127 unrelated records, or those and the Mono one.
    let many: Vec<String> = (0..crate::MAX_DEPENDENCIES - 1).map(|i| format!("pkg{i}")).collect();
    assert!(!dotnet_of(&many));
    let mut with = many.clone();
    with.insert(70, "wine-mono".into());
    assert!(dotnet_of(&with));
}

#[test]
fn an_app_with_wine_mono_is_refused_on_a_backend_without_dotnet() {
    let mut f = fx("exit 0");
    f.backend = FakeBackend::new().with_capabilities(crate::backend::Capabilities {
        dotnet: false,
        ..FakeBackend::new().capabilities()
    });
    let env = f.app("app");
    let mut md = f.store.read_metadata(&env).unwrap();
    md.dependencies = vec![record("wine-mono")];
    f.store.write_metadata(&env, &md).unwrap();
    let e = f.go("app", &[]).unwrap_err();
    assert!(
        matches!(
            e,
            RunAppError::Unsupported {
                source: crate::backend::Unsupported::Feature { backend: "fake", .. },
                ..
            }
        ),
        "{e:?}"
    );
    assert!(f.commands().is_empty(), "not a silent run without Mono");
    // Without Wine Mono recorded the same backend runs the app.
    md.dependencies.clear();
    f.store.write_metadata(&env, &md).unwrap();
    assert_eq!(f.go("app", &[]).unwrap().exit_code, 0);
}

#[test]
fn an_oversized_or_duplicated_record_list_is_refused_before_any_command() {
    // `Metadata::read` refuses both (it is never asked twice), so `dotnet` is never derived from them.
    for ids in [
        vec!["wine-mono".to_owned(); 2],
        (0..10_000).map(|i| format!("p{i}")).collect(),
    ] {
        let f = fx("exit 0");
        let env = f.app("app");
        let mut md = f.store.read_metadata(&env).unwrap();
        md.dependencies = ids.iter().map(|i| record(i)).collect();
        fs::write(env.metadata_path(), serde_json::to_vec(&md).unwrap()).unwrap();
        assert!(f.go("app", &[]).is_err());
        assert!(f.commands().is_empty());
    }
}

// ---------------------------------------------------------------- debug

#[test]
fn debug_is_passed_to_the_backend_and_the_sink_together() {
    let f = fx("echo oops >&2");
    f.app("app");
    let out = f.start("app", &[], true).unwrap().wait().unwrap();
    let Call::Command { debug, .. } = &f.commands()[0] else {
        unreachable!()
    };
    assert!(*debug, "command() got debug=true");
    assert_eq!(f.term.text(), "oops\n", "the sink teed to the terminal");
    assert_eq!(fs::read_to_string(&out.log_path).unwrap(), "oops\n", "and to the log");

    let f = fx("echo oops >&2");
    f.app("app");
    let out = f.start("app", &[], false).unwrap().wait().unwrap();
    let Call::Command { debug, .. } = &f.commands()[0] else {
        unreachable!()
    };
    assert!(!*debug, "command() got debug=false");
    assert_eq!(f.term.text(), "", "without debug nothing reaches the terminal");
    assert_eq!(fs::read_to_string(&out.log_path).unwrap(), "oops\n");
}

#[test]
fn a_failing_terminal_is_reported_and_does_not_fail_the_program() {
    let f = fx("echo oops >&2; exit 3");
    f.app("app");
    let terminal = || -> Box<dyn Write + Send> { Box::new(Broken) };
    let base = f.tmp.path().join("in");
    let env = Env {
        base: &base,
        terminal: &terminal,
    };
    let out = start_in(
        &f.store,
        &f.backend,
        &f.launcher,
        "app",
        &[],
        &RunOptions {
            debug: true,
            ..RunOptions::default()
        },
        &env,
    )
    .unwrap()
    .wait()
    .unwrap();
    assert_eq!(out.exit_code, 3);
    assert!(out.terminal_write_failed);
    assert!(!out.log_write_failed);
    assert_eq!(
        fs::read_to_string(&out.log_path).unwrap(),
        "oops\n",
        "the log kept working"
    );
}

// ---------------------------------------------------------------- a broken or hostile environment

fn ran(env: &AppEnv) -> bool {
    env.prefix().join("ran").exists()
}

#[test]
fn a_missing_program_is_an_actionable_error_and_nothing_runs() {
    let f = fx("touch \"$WINEPREFIX/ran\"");
    let env = f.app("app");
    fs::remove_file(env.drive_c().join("Program Files/app/app.exe")).unwrap();
    let e = f.go("app", &[]).unwrap_err();
    assert!(matches!(e, RunAppError::ExecutableMissing { .. }), "{e:?}");
    let msg = text(&e);
    assert!(
        msg.contains("runtime remove app") && msg.contains("install it again"),
        "{msg}"
    );
    assert!(msg.contains("not implemented yet"), "no fake fix is offered: {msg}");
    assert!(f.commands().is_empty() && !ran(&env));
}

#[test]
fn a_program_that_is_not_a_regular_file_is_refused() {
    // A directory, a symlink to a real file outside, a symlinked parent directory.
    type Tamper = fn(&Fx, &AppEnv);
    let cases: [(&str, Tamper); 3] = [
        ("directory", |_, env| {
            let p = env.drive_c().join("Program Files/app/app.exe");
            fs::remove_file(&p).unwrap();
            fs::create_dir(&p).unwrap();
        }),
        ("symlink to a file", |f, env| {
            let p = env.drive_c().join("Program Files/app/app.exe");
            fs::remove_file(&p).unwrap();
            let outside = f.tmp.path().join("outside/real.exe");
            fs::write(&outside, b"MZ").unwrap();
            symlink(&outside, &p).unwrap();
        }),
        ("symlinked directory", |f, env| {
            let d = env.drive_c().join("Program Files/app");
            let outside = f.tmp.path().join("outside/app");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("app.exe"), b"MZ").unwrap();
            fs::remove_dir_all(&d).unwrap();
            symlink(&outside, &d).unwrap();
        }),
    ];
    for (what, tamper) in cases {
        let f = fx("touch \"$WINEPREFIX/ran\"");
        let env = f.app("app");
        tamper(&f, &env);
        let e = f.go("app", &[]).unwrap_err();
        assert!(matches!(e, RunAppError::ExecutableMissing { .. }), "{what}: {e:?}");
        assert!(f.commands().is_empty() && !ran(&env), "{what}: something ran");
    }
}

#[test]
fn hostile_metadata_fields_are_refused_and_nothing_runs() {
    type Edit = fn(&mut serde_json::Value);
    let cases: [(&str, Edit); 8] = [
        ("architecture with a path", |v| {
            v["architecture"] = "x86_64/../../x".into()
        }),
        ("architecture arm64", |v| v["architecture"] = "arm64".into()),
        ("architecture empty", |v| v["architecture"] = "".into()),
        ("other backend", |v| v["backend"]["id"] = "wine".into()),
        ("backend id with a path", |v| v["backend"]["id"] = "../../bin/sh".into()),
        ("environment evil", |v| v["environment"] = "evil".into()),
        ("environment with a path", |v| v["environment"] = "../../x".into()),
        ("environment empty", |v| v["environment"] = "".into()),
    ];
    for (what, edit) in cases {
        let f = fx("touch \"$WINEPREFIX/ran\"");
        let env = f.app("app");
        f.tamper(&env, edit);
        let e = f.go("app", &[]).unwrap_err();
        assert!(f.commands().is_empty() && !ran(&env), "{what}: something ran ({e})");
        assert!(f.backend.calls().is_empty(), "{what}: the backend was called");
    }
}

#[test]
fn the_known_value_checks_stand_on_their_own() {
    // In-memory metadata: independent of `Metadata::validate`, which `read_metadata` also applies to the
    // architecture, so each guard of `check_known` is pinned here.
    let good = || {
        Metadata::new(
            AppId::parse("app").unwrap(),
            "App".into(),
            None,
            "x86_64",
            &WinPath::parse(EXE_TEXT).unwrap(),
            BackendInfo {
                id: "fake".into(),
                version: "1".into(),
            },
            "console",
        )
    };
    let id = AppId::parse("app").unwrap();
    assert!(check_known(&id, &good(), "fake").is_ok());
    let mut x86 = good();
    x86.architecture = "x86".into();
    assert!(check_known(&id, &x86, "fake").is_ok());
    for arch in ["arm64", "X86_64", "x86_64/../../x", "", "x64", "x86 "] {
        let mut m = good();
        m.architecture = arch.into();
        assert!(
            matches!(
                check_known(&id, &m, "fake"),
                Err(RunAppError::BadMetadata {
                    field: "architecture",
                    ..
                })
            ),
            "{arch:?}"
        );
    }
    assert!(matches!(
        check_known(&id, &good(), "wine"),
        Err(RunAppError::BackendMismatch { .. })
    ));
    let mut m = good();
    m.backend.id = "fake\x1b[31m".into();
    let e = check_known(&id, &m, "fake").unwrap_err();
    assert!(
        !text(&e).contains('\x1b'),
        "untrusted text is escaped in the message: {e}"
    );
    for env in ["evil", "", "Default", "default ", "../x"] {
        let mut m = good();
        m.environment = env.into();
        assert!(
            matches!(
                check_known(&id, &m, "fake"),
                Err(RunAppError::BadMetadata {
                    field: "environment",
                    ..
                })
            ),
            "{env:?}"
        );
    }
}

#[test]
fn corrupt_metadata_and_a_symlinked_app_directory_are_errors() {
    let f = fx("touch \"$WINEPREFIX/ran\"");
    let env = f.app("app");
    fs::write(env.metadata_path(), b"{ not json").unwrap();
    assert!(matches!(f.go("app", &[]), Err(RunAppError::Store(StoreError::Meta(_)))));
    fs::remove_file(env.metadata_path()).unwrap();
    assert!(matches!(f.go("app", &[]), Err(RunAppError::Store(StoreError::Meta(_)))));
    assert!(f.commands().is_empty() && !ran(&env));

    // apps/evil -> outside (which holds a complete app): get() refuses the link.
    let f = fx("touch \"$WINEPREFIX/ran\"");
    let real = f.app("real");
    symlink(real.root(), f.tmp.path().join("apps/evil")).unwrap();
    let e = f.go("evil", &[]).unwrap_err();
    assert!(matches!(e, RunAppError::Store(StoreError::NotADirectory)), "{e:?}");
    assert!(f.commands().is_empty() && !ran(&real));
}

// ---------------------------------------------------------------- targets

#[test]
fn an_unknown_id_is_an_error_with_a_hint_and_creates_nothing() {
    let f = fx("exit 0");
    let e = f.go("hello", &[]).unwrap_err();
    assert!(matches!(e, RunAppError::NotInstalled { .. }), "{e:?}");
    let msg = text(&e);
    assert!(
        msg.contains("runtime list") && msg.contains("runtime install <file>"),
        "{msg}"
    );
    // An id that is not even a valid id, with control characters: escaped in the message.
    let e = f.go("Hello\x1b[31m", &[]).unwrap_err();
    assert!(!text(&e).contains('\x1b'), "{e}");
    assert!(matches!(e, RunAppError::NoSuchFile { .. }), "{e:?}");
    assert!(f.backend.calls().is_empty());
    assert!(f.app_dirs().is_empty());
}

#[test]
fn a_path_that_does_not_exist_is_an_error_and_creates_nothing() {
    let f = fx("exit 0");
    for target in ["nothing.exe", "../x", "sub/nothing.zip", "NOTHING.EXE"] {
        let e = f.go(target, &[]).unwrap_err();
        assert!(matches!(e, RunAppError::NoSuchFile { .. }), "{target}: {e:?}");
        assert!(text(&e).contains("runtime install <file>"), "{e}");
    }
    assert!(f.backend.calls().is_empty());
    assert!(f.app_dirs().is_empty());
}

#[test]
fn a_path_target_is_installed_then_run() {
    let f = fx("exit 7");
    f.input("hello64.exe", &fixture("hello64.exe"));
    let out = f.go("hello64.exe", &os(&["a b", "--x"])).unwrap();
    assert_eq!(out.exit_code, 7);
    let installed = out.installed.as_ref().expect("the outcome reports the install");
    assert_eq!(installed.id, out.id);
    assert_eq!(f.prepares(), 1, "prepare ran exactly once");
    let env = f.store.get(&out.id).unwrap();
    let exe = resolve_under(&env.drive_c(), &installed.executable).unwrap();
    let Call::Command {
        app,
        exe: got,
        cwd,
        args,
        debug,
        ..
    } = &f.commands()[0]
    else {
        unreachable!()
    };
    assert_eq!((app, got, cwd), (&out.id, &exe, &exe.parent().unwrap().to_owned()));
    assert_eq!((args, debug), (&os(&["a b", "--x"]), &false));
    assert_eq!(f.backend.calls().len(), 2, "prepare then command, nothing else");
}

#[test]
fn an_absolute_path_and_an_uppercase_extension_are_paths_too() {
    let f = fx("exit 0");
    let p = f.input("HELLO64.EXE", &fixture("hello64.exe"));
    let out = f.go(p.to_str().unwrap(), &[]).unwrap();
    assert!(out.installed.is_some());
    assert_eq!(f.commands().len(), 1);
}

#[test]
fn a_second_run_by_path_installs_a_second_app() {
    let f = fx("exit 0");
    f.input("hello64.exe", &fixture("hello64.exe"));
    let a = f.go("hello64.exe", &[]).unwrap();
    let b = f.go("hello64.exe", &[]).unwrap();
    assert_ne!(a.id, b.id, "no overwrite, a new id");
    assert_eq!(f.prepares(), 2);
}

#[test]
fn an_installed_id_wins_over_a_file_of_the_same_name() {
    let f = fx("exit 0");
    f.app("hello");
    f.input("hello", &fixture("hello64.exe"));
    let out = f.go("hello", &[]).unwrap();
    assert!(
        out.installed.is_none(),
        "the installed app ran, the file was not installed"
    );
    assert_eq!(f.prepares(), 0);
    assert_eq!(f.app_dirs(), ["hello"]);
}

#[test]
fn an_id_shaped_target_that_is_a_file_and_not_installed_is_installed() {
    let f = fx("exit 0");
    f.input("hello", &fixture("hello64.exe"));
    let out = f.go("hello", &[]).unwrap();
    assert!(out.installed.is_some());
    assert_eq!(f.prepares(), 1);
    // ... also when the name is not a valid id at all.
    let f = fx("exit 0");
    f.input("Hello World", &fixture("hello64.exe"));
    assert!(f.go("Hello World", &[]).unwrap().installed.is_some());
}

#[test]
fn an_install_failure_is_reported_and_leaves_no_app_and_runs_nothing() {
    let f = fx("exit 0");
    f.input("notpe.exe", b"just text");
    let e = f.go("notpe.exe", &[]).unwrap_err();
    assert!(matches!(e, RunAppError::Install(_)), "{e:?}");
    fs::create_dir(f.tmp.path().join("in/dir.exe")).unwrap();
    let e = f.go("dir.exe", &[]).unwrap_err();
    assert!(matches!(e, RunAppError::Install(InstallError::NotRegular)), "{e:?}");
    assert!(f.commands().is_empty());
    assert!(f.app_dirs().is_empty(), "no residue: {:?}", f.app_dirs());
}

// ---------------------------------------------------------------- resolve_program

#[test]
fn resolve_program_returns_the_environment_metadata_program_and_directory() {
    let f = fx("exit 0");
    let env = f.app("app");
    let id = AppId::parse("app").unwrap();
    let p = resolve_program(&f.store, &id, "fake").unwrap();
    assert_eq!(p.env.root(), env.root());
    assert_eq!(p.metadata.name, "App");
    let exe = env.drive_c().join("Program Files/app/app.exe");
    assert_eq!(p.exe, exe);
    assert_eq!(p.cwd, exe.parent().unwrap());
    assert!(f.backend.calls().is_empty(), "resolving spawns and prepares nothing");
    // The RESOLVED spelling, not the metadata's, comes back.
    f.tamper(&env, |v| v["executable"] = "C:\\PROGRAM FILES\\APP\\APP.EXE".into());
    assert_eq!(resolve_program(&f.store, &id, "fake").unwrap().exe, exe);
}

#[test]
fn resolve_program_of_an_unknown_id_is_not_installed() {
    let f = fx("exit 0");
    let e = resolve_program(&f.store, &AppId::parse("nothing").unwrap(), "fake").unwrap_err();
    assert!(matches!(e, RunAppError::NotInstalled { .. }), "{e:?}");
    assert!(text(&e).contains("runtime list"), "{e}");
}

#[test]
fn resolve_program_applies_the_known_value_checks() {
    let f = fx("exit 0");
    let env = f.app("app");
    let id = AppId::parse("app").unwrap();
    let e = resolve_program(&f.store, &id, "wine").unwrap_err();
    assert!(matches!(e, RunAppError::BackendMismatch { .. }), "{e:?}");
    f.tamper(&env, |v| v["environment"] = "evil".into());
    let e = resolve_program(&f.store, &id, "fake").unwrap_err();
    assert!(
        matches!(
            e,
            RunAppError::BadMetadata {
                field: "environment",
                ..
            }
        ),
        "{e:?}"
    );
}

#[test]
fn resolve_program_refuses_a_missing_or_irregular_program_and_hostile_executable_metadata() {
    let id = AppId::parse("app").unwrap();
    // On disk: gone, a directory, a symlink to a file outside, a symlinked parent directory.
    type Tamper = fn(&Fx, &AppEnv);
    let cases: [(&str, Tamper); 4] = [
        ("missing", |_, env| {
            fs::remove_file(env.drive_c().join("Program Files/app/app.exe")).unwrap();
        }),
        ("directory", |_, env| {
            let p = env.drive_c().join("Program Files/app/app.exe");
            fs::remove_file(&p).unwrap();
            fs::create_dir(&p).unwrap();
        }),
        ("symlink to a file", |f, env| {
            let p = env.drive_c().join("Program Files/app/app.exe");
            fs::remove_file(&p).unwrap();
            let outside = f.tmp.path().join("outside/real.exe");
            fs::write(&outside, b"MZ").unwrap();
            symlink(&outside, &p).unwrap();
        }),
        ("symlinked directory", |f, env| {
            let d = env.drive_c().join("Program Files/app");
            let outside = f.tmp.path().join("outside/app");
            fs::create_dir(&outside).unwrap();
            fs::write(outside.join("app.exe"), b"MZ").unwrap();
            fs::remove_dir_all(&d).unwrap();
            symlink(&outside, &d).unwrap();
        }),
    ];
    for (what, tamper) in cases {
        let f = fx("exit 0");
        let env = f.app("app");
        tamper(&f, &env);
        let e = resolve_program(&f.store, &id, "fake").unwrap_err();
        assert!(matches!(e, RunAppError::ExecutableMissing { .. }), "{what}: {e:?}");
    }
    // In metadata.json (a file the Wine app itself could rewrite).
    for exe in [
        "C:\\..\\..\\outside\\real.exe",
        "D:\\Program Files\\app\\app.exe",
        "C:\\",
        "",
        "C:\\Program Files\\app\\",
        "\\\\?\\unix\\etc\\passwd",
        "/etc/passwd",
        "C:\\Program Files\\app\\app.exe\x1b[31m",
    ] {
        let f = fx("exit 0");
        let env = f.app("app");
        fs::write(f.tmp.path().join("outside/real.exe"), b"MZ").unwrap();
        f.tamper(&env, |v| v["executable"] = exe.into());
        let e = resolve_program(&f.store, &id, "fake").expect_err(exe);
        assert!(!text(&e).contains('\x1b'), "{exe:?}: unescaped text: {e}");
    }
}

// ---------------------------------------------------------------- find_target

#[test]
fn find_target_classifies_without_a_backend_and_creates_nothing() {
    let f = fx("exit 0");
    let base = f.tmp.path().join("in");
    let find = |t: &str| find_target(&f.store, t, &base);
    assert!(matches!(find("hello"), Err(RunAppError::NotInstalled { .. })));
    assert!(matches!(find(""), Err(RunAppError::NoSuchFile { .. })));
    assert!(matches!(find("nothing.exe"), Err(RunAppError::NoSuchFile { .. })));
    assert!(matches!(find("Hello World"), Err(RunAppError::NoSuchFile { .. })));
    let e = find("Hello\x1b[31m").unwrap_err();
    assert!(!text(&e).contains('\x1b'), "{e}");
    f.app("app");
    assert!(matches!(find("app"), Ok(Target::Installed(id)) if id.as_str() == "app"));
    let p = f.input("hello64.exe", b"MZ");
    assert!(matches!(find("hello64.exe"), Ok(Target::File(got)) if got == p));
    // An installed id wins over a file of the same name; an id-shaped file that is not installed is a file.
    f.input("app", b"MZ");
    assert!(matches!(find("app"), Ok(Target::Installed(_))));
    f.input("plain", b"MZ");
    assert!(matches!(find("plain"), Ok(Target::File(_))));
    assert!(f.backend.calls().is_empty());
    assert_eq!(f.app_dirs(), ["app"], "nothing was created");
}

// ---------------------------------------------------------------- a failure after an install by path

/// A backend whose `command` fails or describes a program that cannot be started.
struct FailingBackend {
    inner: FakeBackend,
    unstartable: bool,
}

impl CompatBackend for FailingBackend {
    fn capabilities(&self) -> crate::backend::Capabilities {
        self.inner.capabilities()
    }
    fn id(&self) -> &'static str {
        self.inner.id()
    }
    fn version(&self) -> Result<String, BackendError> {
        self.inner.version()
    }
    fn prepare(&self, env: &AppEnv) -> Result<(), BackendError> {
        self.inner.prepare(env)
    }
    fn command(
        &self,
        env: &AppEnv,
        exe: &Path,
        cwd: &Path,
        args: &[OsString],
        opts: &RunOpts,
    ) -> Result<std::process::Command, BackendError> {
        if self.unstartable {
            return Ok(std::process::Command::new("/nonexistent/no-such-program"));
        }
        let _ = (env, exe, cwd, args, opts);
        Err(BackendError::failed("fake command", b"configured to fail"))
    }
    fn stop(&self, env: &AppEnv) -> Result<(), BackendError> {
        self.inner.stop(env)
    }
    fn dll_dirs(&self) -> Vec<PathBuf> {
        vec![]
    }
}

#[test]
fn a_command_or_spawn_failure_after_an_install_by_path_names_the_new_app() {
    for unstartable in [false, true] {
        let f = fx("exit 0");
        let backend = FailingBackend {
            inner: FakeBackend::new(),
            unstartable,
        };
        f.input("hello64.exe", &fixture("hello64.exe"));
        let base = f.tmp.path().join("in");
        let terminal = || -> Box<dyn Write + Send> { Box::new(io::sink()) };
        let env = Env {
            base: &base,
            terminal: &terminal,
        };
        let Err(e) = start_in(
            &f.store,
            &backend,
            &f.launcher,
            "hello64.exe",
            &[],
            &RunOptions::default(),
            &env,
        ) else {
            panic!("expected a failure (unstartable={unstartable})")
        };
        let apps = f.app_dirs();
        assert_eq!(apps.len(), 1, "the install stays: {apps:?}");
        let msg = text(&e);
        assert!(
            msg.contains(&format!("installed as {}", apps[0])) && msg.contains(&format!("runtime remove {}", apps[0])),
            "unstartable={unstartable}: {msg}"
        );
        assert!(matches!(e, RunAppError::AfterInstall { .. }), "{e:?}");
    }
}

#[test]
fn a_failure_for_an_app_that_was_already_installed_is_not_wrapped() {
    let f = fx("exit 0");
    f.app("app");
    let backend = FailingBackend {
        inner: FakeBackend::new(),
        unstartable: false,
    };
    let base = f.tmp.path().join("in");
    let terminal = || -> Box<dyn Write + Send> { Box::new(io::sink()) };
    let env = Env {
        base: &base,
        terminal: &terminal,
    };
    let Err(e) = start_in(
        &f.store,
        &backend,
        &f.launcher,
        "app",
        &[],
        &RunOptions::default(),
        &env,
    ) else {
        panic!("expected a failure")
    };
    assert!(matches!(e, RunAppError::Backend(_)), "{e:?}");
    assert!(!text(&e).contains("installed as"), "{e}");
}

// ------------------------------------------------------------------------------ sandbox

/// A wrapped command's program, `WINEPREFIX` and `SETTLED`.
type Seen = (OsString, Option<OsString>, Option<OsString>);

/// Records the commands it is given (program and `WINEPREFIX`/`SETTLED`), and refuses them all when `refuse`.
#[derive(Default)]
struct RecordingSandbox {
    seen: Mutex<Vec<Seen>>,
    refuse: bool,
}

impl Sandbox for RecordingSandbox {
    fn wrap(&self, cmd: std::process::Command) -> std::process::Command {
        let var = |name: &str| {
            cmd.get_envs()
                .find(|(k, _)| *k == name)
                .and_then(|(_, v)| v.map(OsString::from))
        };
        let seen = (cmd.get_program().to_owned(), var("WINEPREFIX"), var("SETTLED"));
        self.seen.lock().unwrap().push(seen);
        cmd
    }
    fn try_wrap(&self, cmd: std::process::Command) -> Result<std::process::Command, String> {
        let cmd = self.wrap(cmd);
        if self.refuse {
            Err("refused for the test".into())
        } else {
            Ok(cmd)
        }
    }
}

/// [`FakeBackend`] whose `settle` marks the command with `SETTLED=1`.
struct SettlingBackend(FakeBackend);

impl CompatBackend for SettlingBackend {
    fn capabilities(&self) -> crate::backend::Capabilities {
        self.0.capabilities()
    }
    fn id(&self) -> &'static str {
        self.0.id()
    }
    fn version(&self) -> Result<String, BackendError> {
        self.0.version()
    }
    fn prepare(&self, env: &AppEnv) -> Result<(), BackendError> {
        self.0.prepare(env)
    }
    fn command(
        &self,
        env: &AppEnv,
        exe: &Path,
        cwd: &Path,
        args: &[OsString],
        opts: &RunOpts,
    ) -> Result<std::process::Command, BackendError> {
        self.0.command(env, exe, cwd, args, opts)
    }
    fn stop(&self, env: &AppEnv) -> Result<(), BackendError> {
        self.0.stop(env)
    }
    fn dll_dirs(&self) -> Vec<PathBuf> {
        vec![]
    }
    fn settle(&self, mut cmd: std::process::Command) -> std::process::Command {
        cmd.env("SETTLED", "1");
        cmd
    }
}

fn start_with(
    f: &Fx,
    backend: &dyn CompatBackend,
    target: &str,
    sandbox: Option<Arc<dyn Sandbox>>,
) -> Result<Started, RunAppError> {
    let base = f.tmp.path().join("in");
    let terminal = || -> Box<dyn Write + Send> { Box::new(io::sink()) };
    let env = Env {
        base: &base,
        terminal: &terminal,
    };
    let opts = RunOptions { debug: false, sandbox };
    start_in(&f.store, backend, &f.launcher, target, &[], &opts, &env)
}

#[test]
fn the_sandbox_wraps_the_settled_program_only_and_never_the_install() {
    let f = fx("exit 5");
    let backend = SettlingBackend(FakeBackend::with_script("exit 5"));
    f.input("hello64.exe", &fixture("hello64.exe"));
    let sb = Arc::new(RecordingSandbox::default());
    let out = start_with(&f, &backend, "hello64.exe", Some(sb.clone()))
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(out.exit_code, 5);
    // The install prepared the prefix (its helpers run through the backend, never through the sandbox) ...
    assert!(backend.0.calls().iter().any(|c| matches!(c, Call::Prepare { .. })));
    // ... and the sandbox saw exactly one command: the program, settled, in the new app's prefix.
    let env = f.store.get(&out.id).unwrap();
    let seen = sb.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        [(
            OsString::from("/bin/sh"),
            Some(env.prefix().into_os_string()),
            Some(OsString::from("1"))
        )]
    );
}

#[test]
fn without_a_sandbox_the_program_is_not_settled() {
    let f = fx("exit 0");
    f.app("app");
    let backend = SettlingBackend(FakeBackend::with_script("[ -z \"$SETTLED\" ] || exit 9"));
    let out = start_with(&f, &backend, "app", None).unwrap().wait().unwrap();
    assert_eq!(out.exit_code, 0, "settle is only for a sandboxed run");
}

#[test]
fn a_sandbox_that_refuses_starts_nothing() {
    let f = fx("exit 0");
    let env = f.app("app");
    let canary = f.tmp.path().join("outside/ran");
    let backend = FakeBackend::with_script(&format!("touch {}", canary.display()));
    let sb = Arc::new(RecordingSandbox {
        refuse: true,
        ..RecordingSandbox::default()
    });
    let Err(e) = start_with(&f, &backend, "app", Some(sb)) else {
        panic!("a refused command must not start")
    };
    assert!(
        matches!(&e, RunAppError::Launch(LaunchError::Sandbox(m)) if m == "refused for the test"),
        "{e:?}"
    );
    assert_eq!(
        text(&e),
        "the sandbox refused to start the program: refused for the test"
    );
    assert!(!canary.exists(), "the program ran");
    let logs: Vec<_> = fs::read_dir(env.logs_dir()).unwrap().collect();
    assert!(logs.is_empty(), "no log file for a run that never started: {logs:?}");
}
