//! `install`, `run`, `list`, `remove` and `logs` through the real binary and the REAL `WineBackend` code path.
//!
//! No Wine is needed: `RUNTIME_WINE` / `RUNTIME_WINESERVER` (set on the spawned process only) point at shell
//! scripts written by [`Rig`]. The fake `wine wineboot -u` creates a minimal prefix; the fake `wine <exe> args`
//! records its argv (NUL separated), cwd and environment, prints to stdout and stderr and then sources an optional
//! `hook.sh` the test wrote (exit code, signals, sleeping). The spawned `runtime` gets a cleared environment.
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const NOTE: &str = "note: Windows applications run WITHOUT a sandbox until Phase 5 (see docs/SECURITY.md)";
const APP_STDERR: &str = "fake-wine stderr line";

const WINE: &str = r#"
case "$1" in
  --version) echo 'wine-10.0 (Fake 1)' ;;
  wineboot)
    echo "wine wineboot" >> @LOG@/calls.txt
    P="$WINEPREFIX"
    mkdir -p "$P/dosdevices" "$P/drive_c/Program Files" "$P/drive_c/users/tester/AppData/Roaming/Microsoft/Windows" "$P/drive_c/windows"
    ln -s ../drive_c "$P/dosdevices/c:"
    : > "$P/system.reg" ;;
  *)
    echo "wine <app>" >> @LOG@/calls.txt
    printf '%s\0' "$@" > @LOG@/argv.bin
    pwd > @LOG@/cwd.txt
    env | sort > @LOG@/env.txt
    echo "app-stdout"
    echo "fake-wine stderr line" >&2
    if [ -f @LOG@/hook.sh ]; then . @LOG@/hook.sh; fi ;;
esac
"#;

/// A tempdir with `data/` (RUNTIME_DATA_DIR), `bin/{wine,wineserver}` (fakes), `log/` (what they record) and
/// `in/` (input files).
struct Rig {
    _t: tempfile::TempDir,
    root: PathBuf,
    data: PathBuf,
    bin: PathBuf,
    log: PathBuf,
    inputs: PathBuf,
    /// `false`: `RUNTIME_WINE` points at a file that does not exist.
    wine_present: bool,
}

fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n[ \"$1\" = --rig-probe ] && exit 0\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    // Another test thread may have forked while the file was open for writing; that child holds the write fd
    // until its exec and running the script meanwhile fails with ETXTBSY. Probe until it can be executed.
    for _ in 0..500 {
        let probe = Command::new(path)
            .arg("--rig-probe")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        match probe {
            Err(e) if e.raw_os_error() == Some(26) => std::thread::sleep(Duration::from_millis(4)),
            _ => break,
        }
    }
}

fn fixture(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    assert!(p.exists(), "missing fixture {name}: run tools/build-fixtures.sh");
    p
}

fn rig() -> Rig {
    rig_with("exit 0")
}

fn rig_with(wineserver_body: &str) -> Rig {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().canonicalize().unwrap();
    let (data, bin, log, inputs) = (root.join("data"), root.join("bin"), root.join("log"), root.join("in"));
    for d in [&data, &bin, &log, &inputs] {
        fs::create_dir_all(d).unwrap();
    }
    let fill = |s: &str| s.replace("@LOG@", log.to_str().unwrap());
    script(&bin.join("wine"), &fill(WINE));
    script(
        &bin.join("wineserver"),
        &fill(&format!(
            "if [ -d \"$WINEPREFIX\" ]; then E=yes; else E=no; fi\necho \"wineserver $* WINEPREFIX=$WINEPREFIX exists=$E\" >> @LOG@/calls.txt\n{wineserver_body}"
        )),
    );
    Rig {
        _t: t,
        root,
        data,
        bin,
        log,
        inputs,
        wine_present: true,
    }
}

impl Rig {
    fn no_wine(mut self) -> Rig {
        self.wine_present = false;
        self
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_runtime"));
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("RUNTIME_DATA_DIR", &self.data)
            .env(
                "RUNTIME_WINE",
                if self.wine_present {
                    self.bin.join("wine")
                } else {
                    self.root.join("no-such-wine")
                },
            )
            .env("RUNTIME_WINESERVER", self.bin.join("wineserver"))
            .env("SECRET", "hunter2")
            .stdin(Stdio::null());
        c
    }

    fn rt<S: AsRef<std::ffi::OsStr>>(&self, args: &[S]) -> Output {
        self.cmd().args(args).output().unwrap()
    }

    fn apps(&self) -> PathBuf {
        self.data.join("apps")
    }

    fn app_dirs(&self) -> Vec<String> {
        let mut v: Vec<String> = match fs::read_dir(self.apps()) {
            Ok(rd) => rd
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => vec![],
        };
        v.sort();
        v
    }

    fn input(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.inputs.join(name);
        fs::write(&p, bytes).unwrap();
        p
    }

    /// Copies `hello64.exe` to `in/<file_name>` and installs it; returns the app id.
    fn install_as(&self, file_name: &str, extra: &[&str]) -> String {
        let p = self.input(file_name, &fs::read(fixture("hello64.exe")).unwrap());
        let mut args: Vec<&std::ffi::OsStr> = vec!["install".as_ref(), p.as_os_str()];
        args.extend(extra.iter().map(|s| std::ffi::OsStr::new(*s)));
        let out = self.rt(&args);
        assert_ok(&out);
        installed_id(&out)
    }

    fn install(&self) -> String {
        self.install_as("hello64.exe", &[])
    }

    fn hook(&self, body: &str) {
        fs::write(self.log.join("hook.sh"), body).unwrap();
    }

    fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.log.join("calls.txt"))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }

    fn argv(&self) -> Vec<Vec<u8>> {
        let raw = fs::read(self.log.join("argv.bin")).expect("the fake wine did not run an app");
        let mut v: Vec<Vec<u8>> = raw.split(|b| *b == 0).map(<[u8]>::to_vec).collect();
        assert_eq!(v.pop(), Some(vec![]), "argv.bin ends with NUL");
        v
    }

    /// Every entry below the data dir with its type, sorted: what a command may have touched.
    fn tree(&self) -> Vec<String> {
        fn walk(dir: &Path, rel: &str, out: &mut Vec<String>) {
            let Ok(rd) = fs::read_dir(dir) else { return };
            for e in rd {
                let e = e.unwrap();
                let name = format!("{rel}/{}", e.file_name().to_string_lossy());
                let t = e.file_type().unwrap();
                out.push(format!(
                    "{name} {}",
                    if t.is_dir() {
                        "d"
                    } else if t.is_symlink() {
                        "l"
                    } else {
                        "f"
                    }
                ));
                if t.is_dir() {
                    walk(&e.path(), &name, out);
                }
            }
        }
        let mut v = vec![];
        walk(&self.root, "", &mut v);
        v.retain(|l| !l.starts_with("/log") && !l.starts_with("/bin"));
        v.sort();
        v
    }

    /// An app directory with valid metadata but no real program (enough for `list`, `logs`, `remove`).
    fn plant(&self, id: &str, name: &str) -> PathBuf {
        let dir = self.apps().join(id);
        for d in ["logs", "prefix/drive_c"] {
            fs::create_dir_all(dir.join(d)).unwrap();
        }
        let md = serde_json::json!({
            "schemaVersion": 1, "id": id, "name": name, "version": "1.2.3", "architecture": "x86_64",
            "executable": "C:\\Program Files\\x\\x.exe", "environment": "default",
            "backend": {"id": "wine", "version": "wine-10.0"}, "subsystem": "console", "created": 1_700_000_000u64
        });
        fs::write(dir.join("metadata.json"), serde_json::to_vec(&md).unwrap()).unwrap();
        dir
    }
}

fn s(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn assert_ok(o: &Output) {
    assert!(
        o.status.success(),
        "exit {:?}\nstdout: {}\nstderr: {}",
        o.status.code(),
        s(&o.stdout),
        s(&o.stderr)
    );
}

fn assert_fails(o: &Output) -> String {
    assert_eq!(
        o.status.code(),
        Some(1),
        "expected exit 1\nstdout: {}\nstderr: {}",
        s(&o.stdout),
        s(&o.stderr)
    );
    let err = s(&o.stderr);
    assert!(err.contains("error: "), "no `error:` line: {err}");
    err
}

fn installed_id(o: &Output) -> String {
    s(&o.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("Installed: "))
        .unwrap_or_else(|| panic!("no `Installed:` line in {}", s(&o.stdout)))
        .to_owned()
}

/// No raw terminal-control characters anywhere in `text`.
fn assert_tame(text: &str, what: &str) {
    for c in text.chars() {
        let bad = (c.is_control() && c != '\n') || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        assert!(!bad, "{what} contains U+{:04X}: {text:?}", c as u32);
    }
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("bad JSON ({e}): {}", s(&o.stdout)))
}

// ================================================================ list

#[test]
fn list_on_an_empty_data_dir_prints_an_empty_state_and_needs_no_wine() {
    let r = rig().no_wine();
    let o = r.rt(&["list"]);
    assert_ok(&o);
    assert!(s(&o.stdout).contains("No apps installed"), "{}", s(&o.stdout));
    assert!(s(&o.stdout).contains("runtime install"), "{}", s(&o.stdout));
    assert_eq!(s(&o.stderr), "");
    let o = r.rt(&["list", "--json"]);
    assert_ok(&o);
    assert_eq!(json(&o), serde_json::json!([]));
    assert!(r.app_dirs().is_empty(), "list must not create the data dir contents");
}

#[test]
fn list_shows_a_sorted_table_and_stable_json() {
    let r = rig().no_wine();
    r.plant("zeta", "Zeta App");
    r.plant("alpha", "Alpha App");
    r.plant("mid", "Mid App");
    let o = r.rt(&["list"]);
    assert_ok(&o);
    let out = s(&o.stdout);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4, "{out}");
    for h in ["ID", "NAME", "VERSION", "ARCH", "EXECUTABLE"] {
        assert!(lines[0].contains(h), "{}", lines[0]);
    }
    let order: Vec<&str> = lines[1..]
        .iter()
        .map(|l| l.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(order, ["alpha", "mid", "zeta"]);
    for f in ["Alpha App", "1.2.3", "x86_64", "C:\\Program Files\\x\\x.exe"] {
        assert!(lines[1].contains(f), "{f} missing in {}", lines[1]);
    }

    let v = json(&r.rt(&["list", "--json"]));
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 3);
    assert_eq!(
        arr[0],
        serde_json::json!({
            "id": "alpha", "name": "Alpha App", "version": "1.2.3", "architecture": "x86_64",
            "executable": "C:\\Program Files\\x\\x.exe", "created": 1_700_000_000u64
        })
    );
    let ids: Vec<&str> = arr.iter().map(|a| a["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["alpha", "mid", "zeta"]);
}

#[test]
fn list_json_has_a_null_version_when_there_is_none() {
    let r = rig().no_wine();
    let dir = r.plant("nover", "N");
    let md_path = dir.join("metadata.json");
    let mut md: serde_json::Value = serde_json::from_slice(&fs::read(&md_path).unwrap()).unwrap();
    md["version"] = serde_json::Value::Null;
    fs::write(&md_path, serde_json::to_vec(&md).unwrap()).unwrap();
    let v = json(&r.rt(&["list", "--json"]));
    assert_eq!(v[0]["version"], serde_json::Value::Null);
    let o = r.rt(&["list"]);
    assert_ok(&o);
    assert!(s(&o.stdout).contains("nover"));
}

#[test]
fn list_survives_and_sanitises_hostile_entries() {
    let r = rig().no_wine();
    r.plant("good", "Good App");
    // A valid entry whose name is full of terminal controls.
    let hostile = "evil\u{1b}]0;pwned\u{7}\u{9b}[31m\r\n\u{202e}txt\u{2067}";
    let evil = r.plant("evil", hostile);
    // ... and hostile free-text fields (version) and an executable name with bidi/invisible characters.
    let md_path = evil.join("metadata.json");
    let mut md: serde_json::Value = serde_json::from_slice(&fs::read(&md_path).unwrap()).unwrap();
    md["version"] = "9\u{1b}[31m\u{9b}2J\u{202e}".into();
    md["executable"] = "C:\\Program Files\\x\\a\u{202e}b\u{200b}.exe".into();
    fs::write(&md_path, serde_json::to_vec(&md).unwrap()).unwrap();
    // Corrupt metadata, a schema from the future, an oversized name.
    let bad = r.plant("badjson", "x");
    fs::write(bad.join("metadata.json"), "{ not json \u{1b}]0;from-file\u{7}").unwrap();
    let old = r.plant("newschema", "x");
    fs::write(old.join("metadata.json"), r#"{"schemaVersion": 99}"#).unwrap();
    let big = r.plant("huge", &"n".repeat(5000));
    let _ = big;
    // A symlink entry (to a directory holding a real-looking app), a plain file, and a name that is not an id.
    let outside = r.root.join("outside");
    fs::create_dir_all(&outside).unwrap();
    symlink(r.plant("target-app", "T"), r.apps().join("link")).unwrap();
    fs::write(r.apps().join("notadir"), "file").unwrap();
    fs::create_dir(r.apps().join("we\u{1b}]0;ird\u{7}name")).unwrap();

    let o = r.rt(&["list"]);
    assert_ok(&o);
    let (out, err) = (s(&o.stdout), s(&o.stderr));
    assert_tame(&out, "stdout");
    assert_tame(&err, "stderr");
    assert!(out.contains("Good App") && out.contains("evil"), "{out}");
    assert!(
        out.contains("\\u{1b}]0;pwned\\u{7}"),
        "the escape is visible, not executed: {out}"
    );
    assert_eq!(out.lines().count(), 1 + 3, "header + good, evil, target-app: {out}");
    // One warning per bad entry, each on one line.
    let warnings: Vec<&str> = err.lines().collect();
    assert!(warnings.iter().all(|l| l.starts_with("warning: ")), "{err}");
    for what in ["badjson", "newschema", "huge", "link", "notadir", "we\\u{1b}"] {
        assert!(
            warnings.iter().any(|l| l.contains(what)),
            "no warning about {what}: {err}"
        );
    }

    // JSON: the corrupt entries are left out, the array parses, nothing raw reaches the terminal.
    let o = r.rt(&["list", "--json"]);
    assert_ok(&o);
    let text = s(&o.stdout);
    assert_tame(&text, "json stdout");
    assert_tame(&s(&o.stderr), "json stderr");
    let v = json(&o);
    let ids: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["evil", "good", "target-app"]);
    assert_eq!(v[0]["name"], hostile, "the data itself is intact (lossless escaping)");
    assert_eq!(v[0]["executable"], "C:\\Program Files\\x\\a\u{202e}b\u{200b}.exe");
    assert!(s(&o.stderr).lines().count() >= 6);
}

// ================================================================ install

#[test]
fn install_reports_the_app_and_creates_a_prefix_through_the_backend() {
    let r = rig();
    let p = r.input("hello64.exe", &fs::read(fixture("hello64.exe")).unwrap());
    let o = r.rt(&["install".as_ref(), p.as_os_str(), "--name".as_ref(), "My App".as_ref()]);
    assert_ok(&o);
    let (out, err) = (s(&o.stdout), s(&o.stderr));
    assert_eq!(installed_id(&o), "my-app");
    assert!(out.contains("Name:       My App"), "{out}");
    assert!(
        out.contains("Executable: C:\\Program Files\\my-app\\hello64.exe"),
        "{out}"
    );
    assert!(out.contains("runtime run my-app"), "{out}");
    assert_eq!(err.matches(NOTE).count(), 1, "exactly one sandbox note: {err}");
    assert_tame(&err, "stderr");
    assert_eq!(
        r.calls(),
        [
            "wine wineboot",
            &format!(
                "wineserver -k WINEPREFIX={} exists=yes",
                r.apps().join("my-app/prefix").display()
            )
        ]
    );
    assert!(
        r.apps()
            .join("my-app/prefix/drive_c/Program Files/my-app/hello64.exe")
            .is_file()
    );
    // and it is listed
    let v = json(&r.rt(&["list", "--json"]));
    assert_eq!(v[0]["id"], "my-app");
    assert_eq!(v[0]["name"], "My App");
    assert_eq!(v[0]["architecture"], "x86_64");
    assert_eq!(v[0]["executable"], "C:\\Program Files\\my-app\\hello64.exe");
}

#[test]
fn install_of_a_second_app_with_the_same_name_gets_a_new_id() {
    let r = rig();
    assert_eq!(r.install_as("hello64.exe", &["--name", "Twin"]), "twin");
    assert_eq!(r.install_as("hello64.exe", &["--name", "Twin"]), "twin-2");
    assert_eq!(r.app_dirs(), ["twin", "twin-2"]);
}

#[test]
fn install_passes_exe_for_an_archive() {
    use std::io::Write;
    let r = rig();
    let zip_path = r.inputs.join("bundle.zip");
    {
        let mut w = zip::ZipWriter::new(fs::File::create(&zip_path).unwrap());
        let o = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, fx) in [("a/hello64.exe", "hello64.exe"), ("b/hello32.exe", "hello32.exe")] {
            w.start_file(name, o).unwrap();
            w.write_all(&fs::read(fixture(fx)).unwrap()).unwrap();
        }
        w.finish().unwrap();
    }
    let o = r.rt(&["install".as_ref(), zip_path.as_os_str()]);
    let err = assert_fails(&o);
    assert!(err.contains("--exe"), "{err}");
    assert!(r.app_dirs().is_empty(), "no residue after a refused install");

    let o = r.rt(&[
        "install".as_ref(),
        zip_path.as_os_str(),
        "--exe".as_ref(),
        "b/hello32.exe".as_ref(),
    ]);
    assert_ok(&o);
    assert!(s(&o.stdout).contains("hello32.exe"), "{}", s(&o.stdout));
    assert!(
        s(&o.stdout).contains("\\b\\hello32.exe"),
        "the selected program keeps its place in the archive: {}",
        s(&o.stdout)
    );
}

#[test]
fn install_errors_exit_1_leave_nothing_and_print_safe_text() {
    let r = rig();
    // not a Windows program, missing file, a directory, a hostile file name
    let text = r.input("notes.txt", b"just text");
    let dir = r.inputs.join("dir");
    fs::create_dir(&dir).unwrap();
    let hostile = r.inputs.join("no\u{1b}]0;pwned\u{7}.exe");
    for target in [text, r.inputs.join("missing.exe"), dir, hostile] {
        let o = r.rt(&["install".as_ref(), target.as_os_str()]);
        let err = assert_fails(&o);
        assert_tame(&err, "stderr");
        assert_eq!(s(&o.stdout), "", "nothing on stdout for a failed install");
    }
    assert!(r.app_dirs().is_empty());
    assert_eq!(r.calls(), Vec::<String>::new(), "no environment was created");
    // a DLL
    let dll = r.input("lib.dll", &fs::read(fixture("exports64.dll")).unwrap());
    let err = assert_fails(&r.rt(&["install".as_ref(), dll.as_os_str()]));
    assert!(err.contains("DLL"), "{err}");
    assert!(r.app_dirs().is_empty());
}

#[test]
fn install_without_wine_is_an_error_that_says_what_to_do() {
    let r = rig().no_wine();
    let p = r.input("hello64.exe", &fs::read(fixture("hello64.exe")).unwrap());
    let err = assert_fails(&r.rt(&["install".as_ref(), p.as_os_str()]));
    assert!(err.contains("RUNTIME_WINE"), "{err}");
    assert!(r.app_dirs().is_empty());
}

#[test]
fn a_failing_backend_setup_leaves_no_app() {
    let r = rig();
    script(&r.bin.join("wine"), "echo 'boom \u{1b}[31m' >&2; exit 9");
    let p = r.input("hello64.exe", &fs::read(fixture("hello64.exe")).unwrap());
    let o = r.rt(&["install".as_ref(), p.as_os_str()]);
    let err = assert_fails(&o);
    assert!(err.contains("boom"), "{err}");
    assert_tame(&err, "stderr");
    assert!(r.app_dirs().is_empty(), "{:?}", r.app_dirs());
}

// ================================================================ run

#[test]
fn run_of_an_unknown_id_exits_1_with_a_hint() {
    let r = rig();
    let o = r.rt(&["run", "nothing"]);
    let err = assert_fails(&o);
    assert!(err.contains("runtime list") && err.contains("runtime install"), "{err}");
    assert!(r.app_dirs().is_empty());
    assert!(r.calls().is_empty(), "wine was not called: {:?}", r.calls());
    // hostile target: escaped in the message
    let o = r.cmd().args(["run", "Hello\u{1b}]0;x\u{7}"]).output().unwrap();
    assert_tame(&assert_fails(&o), "stderr");
}

#[test]
fn run_an_installed_app_passes_the_exit_code_stdout_and_verbatim_args() {
    let r = rig();
    let id = r.install();
    r.hook("exit 7");
    let mut cmd = r.cmd();
    let odd = OsString::from_vec(b"non-utf8-\xff\xfe".to_vec());
    cmd.args([
        "run",
        &id,
        "--",
        "a b",
        "\"q\"",
        "'s'",
        "x;y",
        "$(touch pwned)",
        "`id`",
        "l1\nl2",
        "-n",
        "--debug",
        "-x",
        "--",
        "",
        "$HOME",
        "*",
    ])
    .arg(&odd);
    let o = cmd.output().unwrap();
    assert_eq!(o.status.code(), Some(7), "stderr: {}", s(&o.stderr));
    assert_eq!(s(&o.stdout), "app-stdout\n", "the app's stdout is the CLI's stdout");
    let err = s(&o.stderr);
    assert_eq!(
        err,
        format!("{NOTE}\n"),
        "only the sandbox note: the app's stderr goes to the log"
    );
    // argv: the resolved exe, then the arguments exactly.
    let argv = r.argv();
    let exe = r
        .apps()
        .join(format!("{id}/prefix/drive_c/Program Files/{id}/hello64.exe"));
    assert_eq!(argv[0], exe.as_os_str().as_encoded_bytes());
    let want: Vec<&[u8]> = vec![
        b"a b",
        b"\"q\"",
        b"'s'",
        b"x;y",
        b"$(touch pwned)",
        b"`id`",
        b"l1\nl2",
        b"-n",
        b"--debug",
        b"-x",
        b"--",
        b"",
        b"$HOME",
        b"*",
        b"non-utf8-\xff\xfe",
    ];
    assert_eq!(argv[1..].iter().map(Vec::as_slice).collect::<Vec<_>>(), want);
    assert!(!exe.parent().unwrap().join("pwned").exists());
    // cwd = the program's directory
    let cwd = fs::read_to_string(r.log.join("cwd.txt")).unwrap();
    assert_eq!(fs::canonicalize(cwd.trim()).unwrap(), exe.parent().unwrap());
    // the child saw the backend variables and no host secret
    let env = fs::read_to_string(r.log.join("env.txt")).unwrap();
    assert!(
        env.contains(&format!("WINEPREFIX={}", r.apps().join(&id).join("prefix").display())),
        "{env}"
    );
    assert!(!env.contains("SECRET") && !env.contains("hunter2"), "{env}");
    // exit code 0 passes through as well
    r.hook("exit 0");
    assert_eq!(r.rt(&["run", &id]).status.code(), Some(0));
}

#[test]
fn run_reports_a_signal_death_as_128_plus_the_signal() {
    let r = rig();
    let id = r.install();
    r.hook("kill -TERM $$");
    assert_eq!(r.rt(&["run", &id]).status.code(), Some(143));
}

#[test]
fn run_debug_also_shows_the_apps_stderr_on_the_terminal() {
    let r = rig();
    let id = r.install();
    let o = r.rt(&["run", &id]);
    assert_ok(&o);
    assert!(
        !s(&o.stderr).contains(APP_STDERR),
        "quiet without --debug: {}",
        s(&o.stderr)
    );
    let o = r.rt(&["run", "--debug", &id]);
    assert_ok(&o);
    let err = s(&o.stderr);
    assert_eq!(err.matches(APP_STDERR).count(), 1, "{err}");
    assert_eq!(err.matches(NOTE).count(), 1, "{err}");
    // Both runs are in the log files: `logs` shows the newest.
    let o = r.rt(&["logs", &id]);
    assert_ok(&o);
    assert_eq!(s(&o.stdout), format!("{APP_STDERR}\n"));
    assert_eq!(fs::read_dir(r.apps().join(&id).join("logs")).unwrap().count(), 2);
}

#[test]
fn run_a_file_installs_it_first_and_then_runs_it() {
    let r = rig();
    let p = r.input("hello64.exe", &fs::read(fixture("hello64.exe")).unwrap());
    r.hook("exit 3");
    let o = r
        .cmd()
        .args(["run".as_ref(), p.as_os_str(), "--".as_ref(), "one".as_ref()])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(3), "stderr: {}", s(&o.stderr));
    let err = s(&o.stderr);
    assert_eq!(err.matches(NOTE).count(), 1, "{err}");
    assert!(
        err.contains("installed") && err.contains("hello64"),
        "the install is reported: {err}"
    );
    assert_tame(&err, "stderr");
    assert_eq!(r.calls().iter().filter(|c| *c == "wine wineboot").count(), 1);
    let argv = r.argv();
    assert_eq!(argv[1], b"one");
    assert_eq!(r.app_dirs().len(), 1);
    let v = json(&r.rt(&["list", "--json"]));
    assert_eq!(v.as_array().unwrap().len(), 1);
}

#[test]
fn run_survives_ctrl_c_and_reports_the_childs_status() {
    let r = rig();
    let id = r.install();
    // SIGINT to the runtime process (the fake's parent) while it waits; the child then exits 5 by itself.
    r.hook("sleep 0.5; kill -INT $PPID; sleep 0.3; exit 5");
    let o = r.rt(&["run", &id]);
    assert_eq!(
        o.status.code(),
        Some(5),
        "the CLI must survive SIGINT while waiting: {:?}",
        o.status
    );
}

#[test]
fn run_without_wine_or_with_a_broken_app_is_an_error() {
    let r = rig();
    let id = r.install();
    // The program vanished from the environment.
    fs::remove_file(
        r.apps()
            .join(format!("{id}/prefix/drive_c/Program Files/{id}/hello64.exe")),
    )
    .unwrap();
    let o = r.rt(&["run", &id]);
    let err = assert_fails(&o);
    assert!(
        err.contains("cannot be found") && err.contains(&format!("runtime remove {id}")),
        "{err}"
    );
    assert!(!err.contains("repair` will"), "no fake fix");
    // Corrupt metadata: an error, nothing executed (the fake's argv file never appears).
    let id2 = r.install_as("second.exe", &[]);
    let md = r.apps().join(&id2).join("metadata.json");
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&md).unwrap()).unwrap();
    v["environment"] = "evil".into();
    fs::write(&md, serde_json::to_vec(&v).unwrap()).unwrap();
    assert_tame(&assert_fails(&r.rt(&["run", &id2])), "stderr");
    assert!(!r.log.join("argv.bin").exists());
    // No Wine at all.
    let r2 = rig().no_wine();
    let err = assert_fails(&r2.rt(&["run", "x"]));
    assert!(err.contains("RUNTIME_WINE"), "{err}");
}

// ================================================================ remove

#[test]
fn remove_stops_the_backend_then_deletes_the_app() {
    let r = rig();
    let id = r.install();
    r.plant("other", "Other");
    let before = r.calls().len();
    let o = r.rt(&["remove", &id]);
    assert_ok(&o);
    assert!(s(&o.stdout).contains(&format!("Removed {id}")), "{}", s(&o.stdout));
    assert_eq!(r.app_dirs(), ["other"]);
    let calls = r.calls();
    assert_eq!(calls.len(), before + 1, "{calls:?}");
    assert!(calls[before].starts_with("wineserver -k WINEPREFIX="), "{calls:?}");
    assert!(
        calls[before].ends_with(&format!("{id}/prefix exists=yes")),
        "the backend is stopped BEFORE the environment is deleted: {calls:?}"
    );
    assert_eq!(json(&r.rt(&["list", "--json"])).as_array().unwrap().len(), 1);
}

#[test]
fn remove_of_a_missing_app_is_an_error_and_needs_no_wine() {
    let r = rig().no_wine();
    let err = assert_fails(&r.rt(&["remove", "nothing"]));
    assert!(err.contains("nothing") && err.contains("runtime list"), "{err}");
    assert!(r.calls().is_empty());
}

#[test]
fn remove_accepts_ids_only_and_touches_nothing_otherwise() {
    let r = rig();
    r.plant("victim", "V");
    fs::write(r.data.join("canary"), "canary").unwrap();
    let outside = r.root.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("canary"), "canary").unwrap();
    symlink(&outside, r.apps().join("link")).unwrap();
    let before = r.tree();
    let victim_abs = r.apps().join("victim");
    let abs_canary = r.data.join("canary");
    let cases: Vec<OsString> = vec![
        "../canary".into(),
        "..".into(),
        ".".into(),
        "".into(),
        "/".into(),
        abs_canary.into(),
        victim_abs.clone().into(),
        "./victim".into(),
        "victim/".into(),
        "victim/..".into(),
        "a/b".into(),
        "VICTIM".into(),
        "-x".into(),
        "no\u{1b}]0;x\u{7}".into(),
    ];
    for arg in cases {
        let o = r.cmd().arg("remove").arg("--").arg(&arg).output().unwrap();
        let err = assert_fails(&o);
        assert_tame(&err, "stderr");
        assert_eq!(r.tree(), before, "nothing may change for {arg:?}");
    }
    // The symlink entry: an id, but refused (not a real directory); the target survives.
    let err = assert_fails(&r.rt(&["remove", "link"]));
    assert!(!err.is_empty());
    assert_eq!(r.tree(), before);
    assert_eq!(fs::read_to_string(outside.join("canary")).unwrap(), "canary");
    assert!(r.calls().is_empty(), "no wine call for refused ids: {:?}", r.calls());
    // ... while the plain id works.
    assert_ok(&r.rt(&["remove", "victim"]));
    assert!(!victim_abs.exists());
    assert_eq!(fs::read_to_string(r.data.join("canary")).unwrap(), "canary");
}

#[test]
fn remove_without_wine_warns_and_still_removes() {
    let r = rig().no_wine();
    r.plant("app", "A");
    let o = r.rt(&["remove", "app"]);
    assert_ok(&o);
    let err = s(&o.stderr);
    assert!(err.contains("warning: ") && err.contains("Wine"), "{err}");
    assert_tame(&err, "stderr");
    assert!(r.app_dirs().is_empty());
    assert!(r.calls().is_empty());
}

#[test]
fn remove_still_removes_when_stopping_the_backend_fails() {
    let r = rig_with("echo 'server \u{1b}[31mstuck' >&2; exit 3");
    r.plant("app", "A");
    let o = r.rt(&["remove", "app"]);
    assert_ok(&o);
    let err = s(&o.stderr);
    assert!(err.contains("warning: ") && err.contains("wineserver -k"), "{err}");
    assert_tame(&err, "stderr");
    assert!(r.app_dirs().is_empty());
}

// ================================================================ logs

fn log_file(r: &Rig, id: &str, name: &str, bytes: &[u8]) -> PathBuf {
    let p = r.apps().join(id).join("logs").join(name);
    fs::write(&p, bytes).unwrap();
    p
}

fn numbered(n: usize) -> Vec<u8> {
    (1..=n).map(|i| format!("line {i}\n")).collect::<String>().into_bytes()
}

#[test]
fn logs_shows_the_newest_regular_run_log_and_needs_no_wine() {
    let r = rig().no_wine();
    r.plant("app", "A");
    log_file(&r, "app", "run-1000000001-000000000-1.log", b"old\n");
    log_file(&r, "app", "run-1000000002-000000000-1.log", b"newest\n");
    log_file(&r, "app", "other.log", b"not a run log\n");
    log_file(&r, "app", "run-1000000009-000000000-1.txt", b"wrong extension\n");
    log_file(&r, "app", "zzz", b"wrong name\n");
    // Newer names that must not be picked: a symlink to a secret, a directory.
    let secret = r.root.join("secret");
    fs::write(&secret, "TOP-SECRET\n").unwrap();
    symlink(&secret, r.apps().join("app/logs/run-1000000003-000000000-1.log")).unwrap();
    fs::create_dir(r.apps().join("app/logs/run-1000000004-000000000-1.log")).unwrap();
    let o = r.rt(&["logs", "app"]);
    assert_ok(&o);
    assert_eq!(s(&o.stdout), "newest\n");
    assert!(!s(&o.stdout).contains("TOP-SECRET"));
}

#[test]
fn logs_of_an_app_without_logs_and_of_bad_ids() {
    let r = rig().no_wine();
    r.plant("app", "A");
    let o = r.rt(&["logs", "app"]);
    assert_ok(&o);
    assert_eq!(s(&o.stdout), "");
    assert!(s(&o.stderr).contains("no logs"), "{}", s(&o.stderr));
    assert_fails(&r.rt(&["logs", "nothing"]));
    for bad in ["../app", "/x", "", "app/", ".."] {
        let o = r.cmd().args(["logs", "--", bad]).output().unwrap();
        assert_fails(&o);
    }
}

#[test]
fn logs_caps_the_number_of_lines() {
    let r = rig().no_wine();
    r.plant("app", "A");
    log_file(&r, "app", "run-1-1-1.log", &numbered(3000));
    let last = |n: usize, total: usize| {
        (total - n + 1..=total)
            .map(|i| format!("line {i}\n"))
            .collect::<String>()
    };
    // default 50
    let o = r.rt(&["logs", "app"]);
    assert_ok(&o);
    assert_eq!(s(&o.stdout), last(50, 3000));
    assert!(
        s(&o.stderr).contains("note: "),
        "truncation is announced: {}",
        s(&o.stderr)
    );
    // explicit
    let o = r.rt(&["logs", "app", "--lines", "5"]);
    assert_eq!(s(&o.stdout), last(5, 3000));
    let o = r.rt(&["logs", "app", "--lines", "1"]);
    assert_eq!(s(&o.stdout), "line 3000\n");
    // above the maximum: clamped to 1000
    let o = r.rt(&["logs", "app", "--lines", "99999"]);
    assert_ok(&o);
    assert_eq!(s(&o.stdout), last(1000, 3000));
    assert!(s(&o.stderr).contains("1000"), "{}", s(&o.stderr));
    // a short log is shown whole and silently
    log_file(&r, "app", "run-2-1-1.log", &numbered(4));
    let o = r.rt(&["logs", "app", "--lines", "100"]);
    assert_eq!(s(&o.stdout), "line 1\nline 2\nline 3\nline 4\n");
    assert_eq!(s(&o.stderr), "");
    // 0 and garbage are errors, not panics
    assert_fails(&r.rt(&["logs", "app", "--lines", "0"]));
    for bad in ["-1", "abc", "", "1.5", "99999999999999999999999"] {
        let o = r.cmd().args(["logs", "app", "--lines", bad]).output().unwrap();
        assert!(!o.status.success() && o.status.code().is_some(), "--lines {bad:?}");
        assert!(o.stdout.is_empty());
    }
}

#[test]
fn logs_caps_the_bytes() {
    let r = rig().no_wine();
    r.plant("app", "A");
    let line = format!("{}\n", "x".repeat(99));
    let big: String = (0..20_000).map(|i| format!("{i:05} {line}")).collect(); // 2 MB
    log_file(&r, "app", "run-1-1-1.log", big.as_bytes());
    let o = r.rt(&["logs", "app", "--lines", "1000"]);
    assert_ok(&o);
    assert!(o.stdout.len() <= 64 * 1024, "{} bytes", o.stdout.len());
    assert!(
        o.stdout.len() > 32 * 1024,
        "the cap is used, not something tiny: {}",
        o.stdout.len()
    );
    assert!(
        s(&o.stdout).ends_with(&format!("19999 {line}")),
        "the end of the log is shown"
    );
    assert!(
        s(&o.stdout)
            .lines()
            .all(|l| l.starts_with(|c: char| c.is_ascii_digit())),
        "no partial first line"
    );
    assert!(s(&o.stderr).contains("note: "), "{}", s(&o.stderr));
}

#[test]
fn logs_sanitises_hostile_bytes_and_bounds_a_huge_single_line() {
    let r = rig().no_wine();
    r.plant("app", "A");
    let mut bytes = b"start \x1b]0;pwned\x07 \x1b[31mred\x00nul\r\xc2\x9b[2J \xe2\x80\xae\xff\xfe end\n".to_vec();
    bytes.extend_from_slice(b"second line\n");
    log_file(&r, "app", "run-1-1-1.log", &bytes);
    let o = r.rt(&["logs", "app"]);
    assert_ok(&o);
    let out = s(&o.stdout);
    assert_tame(&out, "stdout");
    assert!(out.contains("\\u{1b}]0;pwned\\u{7}"), "{out}");
    assert!(out.contains("\\u{0}") && out.contains("\\r"), "{out}");
    assert_eq!(
        out.lines().count(),
        2,
        "newlines are kept, nothing else splits lines: {out:?}"
    );

    // 300 KiB of ESC bytes on one line, no newline at all.
    log_file(&r, "app", "run-2-1-1.log", &vec![0x1b; 300 * 1024]);
    let o = r.rt(&["logs", "app"]);
    assert_ok(&o);
    assert!(o.stdout.len() <= 64 * 1024, "{} bytes", o.stdout.len());
    assert!(!o.stdout.is_empty());
    assert_tame(&s(&o.stdout), "stdout");
    assert!(s(&o.stderr).contains("note: "));
    // same with plain text
    log_file(&r, "app", "run-3-1-1.log", &vec![b'a'; 1 << 20]);
    let o = r.rt(&["logs", "app"]);
    assert_ok(&o);
    assert!(
        o.stdout.len() <= 64 * 1024 && o.stdout.len() > 60 * 1024,
        "{}",
        o.stdout.len()
    );
}

#[test]
fn logs_refuses_a_symlinked_logs_directory() {
    let r = rig().no_wine();
    let dir = r.plant("app", "A");
    let outside = r.root.join("outside-logs");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("run-1-1-1.log"), "TOP-SECRET\n").unwrap();
    fs::remove_dir(dir.join("logs")).unwrap();
    symlink(&outside, dir.join("logs")).unwrap();
    let o = r.rt(&["logs", "app"]);
    let err = assert_fails(&o);
    assert!(!s(&o.stdout).contains("TOP-SECRET") && !err.contains("TOP-SECRET"));
    // ... and a missing logs directory is an error too
    fs::remove_file(dir.join("logs")).unwrap();
    assert_fails(&r.rt(&["logs", "app"]));
}

#[test]
fn logs_does_not_block_on_a_fifo_named_like_a_log() {
    let r = rig().no_wine();
    r.plant("app", "A");
    log_file(&r, "app", "run-1-1-1.log", b"real\n");
    let fifo = r.apps().join("app/logs/run-9-9-9.log");
    match Command::new("mkfifo").arg(&fifo).output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return, // no mkfifo: skip
        Err(e) => panic!("{e}"),
        Ok(o) => assert!(o.status.success()),
    }
    let mut child = r
        .cmd()
        .args(["logs", "app"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("`logs` blocked on a FIFO");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let out = child.wait_with_output().unwrap();
    assert!(status.success());
    assert_eq!(s(&out.stdout), "real\n");
}

#[test]
fn a_usage_error_echoing_hostile_arguments_is_sanitised() {
    let r = rig();
    for args in [
        vec!["bog\u{7}us\u{202e}\u{9b}[2J"],
        vec!["list", "--no\u{7}pe\u{202e}"],
        vec!["run", "x", "--\u{9b}31m", "\u{202e}"],
    ] {
        let o = r.rt(&args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert_tame(&s(&o.stderr), "stderr");
        assert!(o.stdout.is_empty());
    }
}

#[test]
fn a_usage_error_is_reported_without_running_anything() {
    let r = rig();
    for args in [
        &["run"][..],
        &["remove"],
        &["logs"],
        &["install"],
        &["bogus"],
        &["list", "--nope"],
    ] {
        let o = r.rt(args);
        assert!(!o.status.success(), "{args:?}");
        assert!(o.stdout.is_empty(), "{args:?}");
    }
    assert!(r.calls().is_empty());
}
