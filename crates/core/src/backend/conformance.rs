//! The backend conformance suite: what of the contract (module docs of `rt_core::backend`) is observable, as named
//! checks. Each returns [`Failure`]s instead of panicking, so a caller asserts `is_empty()` and sees them all.
//!
//! * [`static_checks`] start no process: id grammar and stability, capabilities, absolute `dll_dirs`, and
//!   `command` (no side effect on the scratch tree, an absolute program, `args` verbatim, `current_dir` the given
//!   cwd, no `LD_PRELOAD`/`LD_LIBRARY_PATH`, `OutsideDriveC` for `..` escapes and absolute paths outside, a refusal
//!   through a symlinked `drive_c` entry), and `settle` keeping the program and arguments.
//! * [`live_checks`] run the backend: `prepare` twice, a program launched through `Launcher::spawn` reports the
//!   expected exit code, `stop` succeeds on the idle environment (twice).
//!
//! Not observable, so reviewed rather than checked: that `command` never spawns, that a backend never reads
//! `permissions.toml`, never downloads, never writes outside `env.root()`.
//!
//! Compiled for tests and the `testing` feature only (dependents enable it through a dev-dependency).
use crate::backend::{BackendError, CompatBackend, RunOpts};
use crate::{AppEnv, AppId, Launcher, LogSink, Store};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

/// One failed check: its name and what was seen (bounded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub check: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.check, self.detail)
    }
}

/// A store with one app environment, below a directory the caller owns (a tempdir), plus an `outside/` directory
/// next to the store. Use a fresh one per tier: the static layout is not a prefix a real backend prepared.
pub struct Scratch {
    root: PathBuf,
    pub store: Store,
    pub env: AppEnv,
}

impl Scratch {
    /// `root` must exist and be empty.
    pub fn new(root: &Path) -> Scratch {
        let store = Store::new(root.join("apps")).expect("the scratch store");
        let env = store
            .create(&AppId::parse("conformance").expect("a valid id"))
            .expect("the scratch app");
        fs::create_dir_all(root.join("outside")).expect("outside/");
        Scratch {
            root: root.to_owned(),
            store,
            env,
        }
    }

    /// The directory beside the store that no command may name.
    pub fn outside(&self) -> PathBuf {
        self.root.join("outside")
    }
}

/// The paths the static checks use, created on first use: a program inside `drive_c`, real files outside it (one
/// in `outside/`, one in the prefix next to `drive_c`) and a link inside `drive_c` to `outside/`.
struct Layout {
    exe: PathBuf,
    dir: PathBuf,
    outside_exe: PathBuf,
    dotdot_exe: PathBuf,
    linked_exe: PathBuf,
}

fn layout(s: &Scratch) -> Layout {
    let drive_c = s.env.drive_c();
    let dir = drive_c.join("Program Files/conformance");
    fs::create_dir_all(&dir).expect("the program directory");
    let exe = dir.join("app.exe");
    fs::write(&exe, b"MZ").expect("the program");
    let outside_exe = s.outside().join("evil.exe");
    fs::write(&outside_exe, b"MZ").expect("outside/evil.exe");
    fs::write(s.env.prefix().join("evil.exe"), b"MZ").expect("prefix/evil.exe");
    let link = drive_c.join("Program Files/link");
    if fs::symlink_metadata(&link).is_err() {
        symlink(s.outside(), &link).expect("the link");
    }
    Layout {
        exe,
        dir,
        outside_exe,
        dotdot_exe: drive_c.join("../evil.exe"),
        linked_exe: link.join("evil.exe"),
    }
}

/// Arguments no backend may touch: non-UTF-8 (NUL-free), a leading `-`, `--`, spaces, a newline, empty.
fn hostile_args() -> Vec<OsString> {
    vec![
        OsString::from_vec(b"\xff\xfe-bytes".to_vec()),
        "-x".into(),
        "--".into(),
        "a b".into(),
        "l1\nl2".into(),
        "".into(),
    ]
}

/// Every entry below `dir` (not following links): path, type, size, mtime.
fn snapshot(dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, out: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(m) = fs::symlink_metadata(&p) else { continue };
            out.push(format!(
                "{} {:?} {} {}.{}",
                p.display(),
                m.file_type(),
                m.len(),
                m.mtime(),
                m.mtime_nsec()
            ));
            if m.file_type().is_dir() {
                walk(&p, out);
            }
        }
    }
    let mut v = Vec::new();
    walk(dir, &mut v);
    v.sort();
    v
}

fn argv(cmd: &Command) -> Vec<OsString> {
    std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(OsStr::to_owned)
        .collect()
}

fn bounded(s: String) -> String {
    let mut s = s;
    if s.len() > 300 {
        let mut cut = 300;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str("...");
    }
    s
}

struct Out(Vec<Failure>);

impl Out {
    fn fail(&mut self, check: &'static str, detail: impl Into<String>) {
        self.0.push(Failure {
            check,
            detail: bounded(detail.into()),
        });
    }

    fn ensure(&mut self, ok: bool, check: &'static str, detail: impl FnOnce() -> String) {
        if !ok {
            self.fail(check, detail());
        }
    }
}

fn id_is_valid(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The checks that start no process (see the module docs). A backend that must find its own layout in the prefix
/// (Wine's `runtime/home`) gets it from the caller before the call.
pub fn static_checks(b: &dyn CompatBackend, scratch: &Scratch) -> Vec<Failure> {
    let mut out = Out(Vec::new());
    let id = b.id();
    out.ensure(id_is_valid(id), "id", || format!("{id:?} is not [a-z0-9-]{{1,32}}"));
    out.ensure(b.id() == id, "id", || "not constant".into());

    let caps = b.capabilities();
    out.ensure(
        !caps.arches.is_empty() && !caps.subsystems.is_empty() && b.capabilities() == caps,
        "capabilities",
        || format!("empty or not constant: {caps:?}"),
    );
    let dirs = b.dll_dirs();
    out.ensure(dirs.iter().all(|d| d.is_absolute()), "dll-dirs-absolute", || {
        format!("{dirs:?}")
    });

    let l = layout(scratch);
    let env = &scratch.env;
    let opts = RunOpts::default();
    let args = hostile_args();
    let before = snapshot(&scratch.root);
    let cmd = match b.command(env, &l.exe, &l.dir, &args, &opts) {
        Ok(cmd) => cmd,
        Err(e) => {
            out.fail("command-ok", format!("the program inside drive_c was refused: {e}"));
            return out.0;
        }
    };
    let after = snapshot(&scratch.root);
    out.ensure(before == after, "command-no-side-effect", || {
        let changed: Vec<&String> = after.iter().filter(|a| !before.contains(a)).collect();
        format!("the scratch tree changed: {changed:?}")
    });
    out.ensure(
        Path::new(cmd.get_program()).is_absolute(),
        "command-program-absolute",
        || format!("{:?}", cmd.get_program()),
    );
    let got: Vec<&OsStr> = cmd.get_args().collect();
    let tail_ok = got.len() >= args.len()
        && got[got.len() - args.len()..] == args.iter().map(|a| a.as_os_str()).collect::<Vec<_>>()[..];
    out.ensure(tail_ok, "command-args-verbatim", || {
        format!("the arguments do not end with {args:?}: {got:?}")
    });
    out.ensure(cmd.get_current_dir() == Some(l.dir.as_path()), "command-cwd", || {
        format!("{:?}, not {:?}", cmd.get_current_dir(), l.dir)
    });
    let loader: Vec<&OsStr> = cmd
        .get_envs()
        .map(|(k, _)| k)
        .filter(|k| {
            let k = k.as_bytes();
            k == b"LD_PRELOAD" || k == b"LD_LIBRARY_PATH"
        })
        .collect();
    out.ensure(loader.is_empty(), "command-no-loader-vars", || {
        format!("sets {loader:?}")
    });

    let outside = |r: Result<Command, BackendError>| matches!(r, Err(BackendError::OutsideDriveC { .. }));
    let dotdot = b.command(env, &l.dotdot_exe, &l.dir, &[], &opts);
    out.ensure(outside(dotdot), "outside-dotdot", || {
        format!("{:?} was not OutsideDriveC", l.dotdot_exe)
    });
    let abs_exe = b.command(env, &l.outside_exe, &l.dir, &[], &opts);
    let abs_cwd = b.command(env, &l.exe, &scratch.outside(), &[], &opts);
    out.ensure(outside(abs_exe) && outside(abs_cwd), "outside-absolute", || {
        format!(
            "{:?} or the cwd {:?} was not OutsideDriveC",
            l.outside_exe,
            scratch.outside()
        )
    });
    out.ensure(
        b.command(env, &l.linked_exe, &l.dir, &[], &opts).is_err(),
        "outside-symlink",
        || format!("{:?} (through a link to outside/) was accepted", l.linked_exe),
    );

    let original = argv(&cmd);
    let cwd = cmd.get_current_dir().map(Path::to_owned);
    let settled = b.settle(cmd);
    let wrapped = argv(&settled);
    out.ensure(
        wrapped.ends_with(&original) && settled.get_current_dir().map(Path::to_owned) == cwd,
        "settle-keeps-argv",
        || format!("{wrapped:?} does not end with {original:?} (or the cwd changed)"),
    );
    out.0
}

/// The checks that run the backend (see the module docs): `program` is written below `drive_c` after `prepare`
/// and must exit with `expect_exit` when launched through `launcher` without arguments.
pub fn live_checks(
    b: &dyn CompatBackend,
    scratch: &Scratch,
    launcher: &Launcher,
    program: &[u8],
    expect_exit: i32,
) -> Vec<Failure> {
    let mut out = Out(Vec::new());
    let env = &scratch.env;
    for round in ["first", "second"] {
        if let Err(e) = b.prepare(env) {
            out.fail("prepare-twice", format!("the {round} prepare failed: {e}"));
            return out.0;
        }
    }
    out.ensure(env.drive_c().is_dir(), "prepare-drive-c", || {
        format!("{:?} is not a directory after prepare", env.drive_c())
    });
    let dir = env.drive_c().join("Program Files/conformance");
    let exe = dir.join("live.exe");
    if let Err(e) = fs::create_dir_all(&dir).and_then(|()| fs::write(&exe, program)) {
        out.fail("prepare-drive-c", format!("cannot write below drive_c: {e}"));
        return out.0;
    }
    match b.command(env, &exe, &dir, &[], &RunOpts::default()) {
        Err(e) => out.fail("command-ok", e.to_string()),
        Ok(cmd) => match launcher.spawn(cmd, env, LogSink::LogOnly).map(|r| r.wait()) {
            Ok(Ok(status)) => out.ensure(status.code() == Some(expect_exit), "exit-code", || {
                format!("{status}, expected exit {expect_exit}")
            }),
            Ok(Err(e)) => out.fail("exit-code", format!("wait: {e}")),
            Err(e) => out.fail("exit-code", format!("spawn: {e}")),
        },
    }
    for round in ["first", "second"] {
        if let Err(e) = b.stop(env) {
            out.fail("stop-idle", format!("the {round} stop failed: {e}"));
        }
    }
    out.0
}
