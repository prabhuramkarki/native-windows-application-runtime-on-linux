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

/// What `run --unsandboxed` says on stderr (the rig's fake Wine cannot run in a real sandbox, so the rig runs apps
/// with `--unsandboxed`; `runtime sandbox`, the refusals and the doctor check are tested below, a real sandboxed
/// run in `e2e_wine.rs`).
const NOTE: &str = "warning: running WITHOUT a sandbox (--unsandboxed)";
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
    /// A second temp directory OUTSIDE `/tmp` (under `CARGO_TARGET_TMPDIR`), for host directories a permission
    /// grant may name: every grant at or below `/tmp` is refused.
    grants: tempfile::TempDir,
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

/// A `vulkaninfo --summary` body that lists one GPU with the given API version.
fn vulkaninfo_body(major: u32, minor: u32) -> String {
    format!(
        "printf 'GPU0:\\n\\tapiVersion = {major}.{minor}.0\\n\\tdriverVersion = 1\\n\\tdeviceType = PHYSICAL_DEVICE_TYPE_DISCRETE_GPU\\n\\tdeviceName = fake\\n\\tdriverName = fake\\n'"
    )
}

fn fixture(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    assert!(p.exists(), "missing fixture {name}: run tools/build-fixtures.sh");
    p
}

/// A `systemd-run` whose scopes work and offer every controller: logs its arguments, answers the probe (the
/// controllers line) and otherwise runs the command after `--` in place, like `--scope` does.
const FAKE_SYSTEMD_RUN: &str = "echo \"$*\" >> @LOG@/systemd-run.txt\n\
    case \" $* \" in *' TasksMax=100 -- /bin/sh -c '*) echo 'cpu io memory pids'; exit 0;; esac\n\
    while [ $# -gt 0 ] && [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"";

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
    // A GPU that meets DXVK's minimum (`cmd` also says the loader is present): plans do not depend on the host.
    script(&bin.join("vulkaninfo"), &vulkaninfo_body(1, 3));
    script(&bin.join("systemd-run"), &fill(FAKE_SYSTEMD_RUN));
    Rig {
        _t: t,
        root,
        data,
        bin,
        log,
        inputs,
        wine_present: true,
        grants: tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap(),
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
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
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
            .env("RUNTIME_VULKAN_LOADER", "present")
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
fn list_says_no_usable_apps_when_every_entry_is_corrupt() {
    let r = rig().no_wine();
    let bad = r.plant("badjson", "x");
    fs::write(bad.join("metadata.json"), "{ not json").unwrap();
    fs::write(r.apps().join("notadir"), "file").unwrap();
    let o = r.rt(&["list"]);
    assert_ok(&o);
    let (out, err) = (s(&o.stdout), s(&o.stderr));
    assert!(out.starts_with("No usable apps"), "{out}");
    assert!(!out.contains("No apps installed"), "{out}");
    assert_eq!(err.lines().count(), 2, "one warning per bad entry: {err}");
    // json stays an empty array; a good app next to a bad one prints the table, not an empty state
    assert_eq!(json(&r.rt(&["list", "--json"])), serde_json::json!([]));
    r.plant("good", "Good App");
    let out = s(&r.rt(&["list"]).stdout);
    assert!(out.contains("Good App") && !out.contains("No "), "{out}");
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
    assert!(
        !err.contains("sandbox"),
        "install runs no program: no sandbox note: {err}"
    );
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
fn install_of_a_wrun_package_is_refused_and_points_at_import() {
    use std::io::Write;
    let r = rig();
    let wrun = r.inputs.join("app.wrun");
    {
        let mut w = zip::ZipWriter::new(fs::File::create(&wrun).unwrap());
        let o = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.start_file("wrun.toml", o).unwrap();
        w.write_all(b"format = 1\n").unwrap();
        w.start_file("payload/hello64.exe", o).unwrap();
        w.write_all(&fs::read(fixture("hello64.exe")).unwrap()).unwrap();
        w.finish().unwrap();
    }
    let err = assert_fails(&r.rt(&["install".as_ref(), wrun.as_os_str()]));
    assert!(err.contains("this is a .wrun package: use `runtime import`"), "{err}");
    assert!(r.app_dirs().is_empty());
    assert_eq!(r.calls(), Vec::<String>::new(), "no environment was created");
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
fn install_of_a_real_msi_is_routed_to_the_installer_pipeline_and_fails_cleanly_without_msiexec() {
    // Dispatch is by content, not extension: the fake `wineboot` (like a real one, minus creating
    // `windows/system32/msiexec.exe`) still runs for real, proving the file was routed to the new installer
    // pipeline (Task 6), not rejected outright the way Phase 2's `rt_core::install` alone would reject an MSI.
    let r = rig();
    let p = r.input("hello.msi", &fs::read(fixture("hello.msi")).unwrap());
    let o = r.rt(&["install".as_ref(), p.as_os_str()]);
    let err = assert_fails(&o);
    assert!(err.contains("msiexec.exe"), "{err}");
    assert_tame(&err, "stderr");
    assert_eq!(s(&o.stdout), "", "nothing on stdout for a failed install");
    assert!(r.app_dirs().is_empty(), "the half-built environment must be cleaned up");
    // `wineboot` really ran (real WineBackend.prepare, not a stub) and the backend was stopped afterwards.
    assert!(r.calls().iter().any(|c| c == "wine wineboot"), "{:?}", r.calls());
    assert!(
        r.calls().iter().any(|c| c.starts_with("wineserver -k")),
        "{:?}",
        r.calls()
    );
}

#[test]
fn install_of_a_msi_without_wine_says_what_to_do() {
    let r = rig().no_wine();
    let p = r.input("hello.msi", &fs::read(fixture("hello.msi")).unwrap());
    let err = assert_fails(&r.rt(&["install".as_ref(), p.as_os_str()]));
    assert!(err.contains("RUNTIME_WINE"), "{err}");
    assert!(r.app_dirs().is_empty());
}

#[test]
fn install_of_an_installer_without_silent_warns_about_no_display_in_the_sandbox() {
    let r = rig();
    let p = r.input("hello.msi", &fs::read(fixture("hello.msi")).unwrap());
    let err = assert_fails(&r.rt(&["install".as_ref(), p.as_os_str()]));
    assert!(err.contains("no display access"), "{err}");
    assert!(err.contains("--silent"), "{err}");

    // The same install with --silent does not get the warning (it explicitly asked to skip the GUI).
    let p2 = r.input("hello2.msi", &fs::read(fixture("hello.msi")).unwrap());
    let err2 = assert_fails(&r.rt(&["install".as_ref(), p2.as_os_str(), "--silent".as_ref()]));
    assert!(!err2.contains("no display access"), "{err2}");
}

#[test]
fn install_of_an_unrecognised_file_still_uses_the_old_pipeline() {
    // Not installer-shaped (no MSI magic, no installer marker): falls through to the unchanged
    // `rt_core::install`, which reports its own `Unknown` error, not the installer pipeline's.
    let r = rig();
    let p = r.input("notes.txt", b"just some text");
    let err = assert_fails(&r.rt(&["install".as_ref(), p.as_os_str()]));
    assert!(err.contains("not recognised") || err.contains("unrecognised"), "{err}");
    assert!(r.app_dirs().is_empty());
}

#[test]
fn silent_and_network_are_ignored_with_a_warning_for_a_non_installer() {
    let r = rig();
    let p = r.input("hello64.exe", &fs::read(fixture("hello64.exe")).unwrap());
    let o = r.rt(&[
        "install".as_ref(),
        p.as_os_str(),
        "--silent".as_ref(),
        "--network".as_ref(),
    ]);
    assert_ok(&o);
    let err = s(&o.stderr);
    assert!(err.contains("warning: ") && err.contains("--silent"), "{err}");
    assert_tame(&err, "stderr");
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
    let o = r.rt(&["run", "--unsandboxed", "nothing"]);
    let err = assert_fails(&o);
    assert!(err.contains("runtime list") && err.contains("runtime install"), "{err}");
    assert!(r.app_dirs().is_empty());
    assert!(r.calls().is_empty(), "wine was not called: {:?}", r.calls());
    // hostile target: escaped in the message
    let o = r
        .cmd()
        .args(["run", "--unsandboxed", "Hello\u{1b}]0;x\u{7}"])
        .output()
        .unwrap();
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
        "--unsandboxed",
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
    assert_eq!(r.rt(&["run", "--unsandboxed", &id]).status.code(), Some(0));
}

#[test]
fn the_program_gets_the_apps_own_home_not_the_hosts() {
    let r = rig();
    let id = r.install();
    let hostile = "/home/hostile-host-user";
    let out = r
        .cmd()
        .env("HOME", hostile)
        .args(["run", "--unsandboxed", id.as_str()])
        .output()
        .unwrap();
    assert_ok(&out);
    let env = fs::read_to_string(r.log.join("env.txt")).unwrap();
    let want = format!("HOME={}", r.apps().join(&id).join("runtime/home").display());
    assert!(env.lines().any(|l| l == want), "want {want}\n{env}");
    assert!(!env.contains(hostile), "the host HOME reached the program:\n{env}");
    assert!(r.apps().join(&id).join("runtime/home").is_dir());
}

#[test]
fn run_reports_a_signal_death_as_128_plus_the_signal() {
    let r = rig();
    let id = r.install();
    r.hook("kill -TERM $$");
    assert_eq!(r.rt(&["run", "--unsandboxed", &id]).status.code(), Some(143));
}

#[test]
fn run_debug_also_shows_the_apps_stderr_on_the_terminal() {
    let r = rig();
    let id = r.install();
    let o = r.rt(&["run", "--unsandboxed", &id]);
    assert_ok(&o);
    assert!(
        !s(&o.stderr).contains(APP_STDERR),
        "quiet without --debug: {}",
        s(&o.stderr)
    );
    let o = r.rt(&["run", "--unsandboxed", "--debug", &id]);
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
        .args([
            "run".as_ref(),
            "--unsandboxed".as_ref(),
            p.as_os_str(),
            "--".as_ref(),
            "one".as_ref(),
        ])
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
    let o = r.rt(&["run", "--unsandboxed", &id]);
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
    let o = r.rt(&["run", "--unsandboxed", &id]);
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
    assert_tame(&assert_fails(&r.rt(&["run", "--unsandboxed", &id2])), "stderr");
    assert!(!r.log.join("argv.bin").exists());
    // No Wine at all, for an installed app.
    let r2 = rig().no_wine();
    r2.plant("x", "X");
    let err = assert_fails(&r2.rt(&["run", "--unsandboxed", "x"]));
    assert!(err.contains("RUNTIME_WINE"), "{err}");
}

#[test]
fn run_of_an_app_recorded_for_an_unknown_backend_is_refused_not_run_with_wine() {
    let r = rig();
    let id = r.install();
    let md = r.apps().join(&id).join("metadata.json");
    let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&md).unwrap()).unwrap();
    for recorded in ["null", "\u{1b}[31mx"] {
        v["backend"]["id"] = recorded.into();
        fs::write(&md, serde_json::to_vec(&v).unwrap()).unwrap();
        let err = assert_fails(&r.rt(&["run", "--unsandboxed", &id]));
        assert!(
            err.contains("unknown compatibility backend") && err.contains("known: wine"),
            "{err}"
        );
        assert_tame(&err, "stderr");
        assert!(!r.log.join("argv.bin").exists(), "Wine ran the app");
    }
    // The same app recorded for Wine runs (the registry selects Wine on the rig's fake).
    v["backend"]["id"] = "wine".into();
    fs::write(&md, serde_json::to_vec(&v).unwrap()).unwrap();
    assert_ok(&r.rt(&["run", "--unsandboxed", &id]));
}

#[test]
fn run_of_an_unknown_id_or_a_missing_file_says_so_even_when_wine_is_missing() {
    let r = rig().no_wine();
    let err = assert_fails(&r.rt(&["run", "--unsandboxed", "nothing"]));
    assert!(
        err.contains("runtime list") && err.contains("runtime install <file>"),
        "{err}"
    );
    assert!(
        !err.contains("RUNTIME_WINE"),
        "the Wine error hides the real one: {err}"
    );
    let err = assert_fails(&r.rt(&["run", "--unsandboxed", "nothing.exe"]));
    assert!(err.contains("no such file"), "{err}");
    assert!(!err.contains("RUNTIME_WINE"), "{err}");
    // What does need Wine still says so: a file to install, and an installed app.
    let p = r.input("hello64.exe", &fs::read(fixture("hello64.exe")).unwrap());
    let err = assert_fails(&r.rt(&["run".as_ref(), "--unsandboxed".as_ref(), p.as_os_str()]));
    assert!(err.contains("RUNTIME_WINE"), "{err}");
    assert!(r.app_dirs().is_empty(), "nothing was installed: {:?}", r.app_dirs());
}

#[test]
fn run_of_a_file_whose_start_fails_names_the_app_it_installed() {
    let r = rig();
    // The fake Wine deletes itself once the prefix exists, so installing works and starting the program cannot.
    let wine = WINE.replace("@LOG@", r.log.to_str().unwrap()).replace(
        ": > \"$P/system.reg\" ;;",
        &format!(": > \"$P/system.reg\"; rm -f {} ;;", r.bin.join("wine").display()),
    );
    assert!(wine.contains("rm -f"), "the rig text changed");
    script(&r.bin.join("wine"), &wine);
    let p = r.input("hello64.exe", &fs::read(fixture("hello64.exe")).unwrap());
    let o = r.rt(&["run".as_ref(), "--unsandboxed".as_ref(), p.as_os_str()]);
    let err = assert_fails(&o);
    let ids = r.app_dirs();
    assert_eq!(ids.len(), 1, "the install stays: {ids:?}");
    assert!(
        err.contains(&format!("installed as {}", ids[0])) && err.contains(&format!("runtime remove {}", ids[0])),
        "{err}"
    );
    assert_tame(&err, "stderr");
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

/// Plants a fake `.desktop` entry + hicolor icon for `id` under a fresh scratch `XDG_DATA_HOME` (never the real
/// one — `Rig::cmd()` normally `env_clear()`s it away entirely; this is added back on top, on the returned
/// `Command`, for exactly the one call that needs it), plus an unrelated survivor `.desktop` file in the same
/// directory. Returns `(xdg_dir, desktop_path, icon_path, survivor_path)`.
fn plant_desktop_entry(r: &Rig, id: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let xdg = r.root.join("xdg");
    let apps_dir = xdg.join("applications");
    let icon_dir = xdg.join("icons/hicolor/48x48/apps");
    fs::create_dir_all(&apps_dir).unwrap();
    fs::create_dir_all(&icon_dir).unwrap();
    let desktop_path = apps_dir.join(format!("runtime-{id}.desktop"));
    let icon_path = icon_dir.join(format!("runtime-{id}.png"));
    fs::write(
        &desktop_path,
        format!("[Desktop Entry]\nType=Application\nName=Desktop App\nExec=runtime run {id}\n"),
    )
    .unwrap();
    fs::write(&icon_path, b"not a real png, contents do not matter for this test").unwrap();
    let survivor_path = apps_dir.join("runtime-other.desktop");
    fs::write(&survivor_path, "survivor").unwrap();
    (xdg, desktop_path, icon_path, survivor_path)
}

#[test]
fn remove_also_deletes_this_apps_desktop_entry_and_icon() {
    let r = rig();
    let id = "desktop-app";
    r.plant(id, "Desktop App");
    let (xdg, desktop_path, icon_path, survivor_path) = plant_desktop_entry(&r, id);

    let mut cmd = r.cmd();
    let o = cmd.env("XDG_DATA_HOME", &xdg).arg("remove").arg(id).output().unwrap();
    assert_ok(&o);

    assert!(!desktop_path.exists(), "the .desktop entry must be removed by `remove`");
    assert!(!icon_path.exists(), "the icon must be removed by `remove`");
    assert!(survivor_path.exists(), "an unrelated .desktop file must survive");
}

// ================================================================ uninstall

#[test]
fn uninstall_of_a_missing_app_is_an_error_and_needs_no_wine() {
    let r = rig().no_wine();
    let err = assert_fails(&r.rt(&["uninstall", "nothing"]));
    assert!(err.contains("nothing") && err.contains("runtime list"), "{err}");
    assert!(r.calls().is_empty());
}

#[test]
fn uninstall_rejects_a_path_not_an_id_and_touches_nothing() {
    let r = rig();
    r.plant("victim", "V");
    for arg in ["../victim", "/abs", ".", "", "victim/"] {
        let o = r.cmd().arg("uninstall").arg("--").arg(arg).output().unwrap();
        let err = assert_fails(&o);
        assert!(err.contains("not a valid app id"), "{arg:?}: {err}");
    }
    assert_eq!(r.app_dirs(), ["victim"]);
    assert!(r.calls().is_empty());
}

#[test]
fn uninstall_of_a_portable_exe_app_falls_back_to_plain_removal_a_documented_limit() {
    // A portable-exe install has no `installer` field at all: no uninstall command exists to run, so
    // `uninstall` behaves exactly like `remove` for it.
    let r = rig();
    let id = r.install();
    let before = r.calls().len();
    let o = r.rt(&["uninstall", &id]);
    assert_ok(&o);
    assert!(s(&o.stdout).contains(&format!("Uninstalled {id}")), "{}", s(&o.stdout));
    assert!(r.app_dirs().is_empty());
    // Only the backend stop, no attempt to run a nonexistent uninstall command.
    let calls = &r.calls()[before..];
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(calls[0].starts_with("wineserver -k"), "{calls:?}");
}

#[test]
fn uninstall_also_deletes_this_apps_desktop_entry_and_icon() {
    let r = rig();
    let id = "desktop-app";
    r.plant(id, "Desktop App");
    let (xdg, desktop_path, icon_path, survivor_path) = plant_desktop_entry(&r, id);

    let mut cmd = r.cmd();
    let o = cmd
        .env("XDG_DATA_HOME", &xdg)
        .arg("uninstall")
        .arg(id)
        .output()
        .unwrap();
    assert_ok(&o);

    assert!(
        !desktop_path.exists(),
        "the .desktop entry must be removed by `uninstall`"
    );
    assert!(!icon_path.exists(), "the icon must be removed by `uninstall`");
    assert!(survivor_path.exists(), "an unrelated .desktop file must survive");
}

#[test]
fn uninstall_without_wine_warns_and_still_removes() {
    let r = rig().no_wine();
    r.plant("app", "A");
    let o = r.rt(&["uninstall", "app"]);
    assert_ok(&o);
    let err = s(&o.stderr);
    assert!(err.contains("warning: ") && err.contains("Wine"), "{err}");
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
fn logs_of_an_empty_newest_log_says_so_on_stderr() {
    let r = rig().no_wine();
    r.plant("app", "A");
    log_file(&r, "app", "run-1-1-1.log", b"older, not shown\n");
    log_file(&r, "app", "run-2-1-1.log", b"");
    let o = r.rt(&["logs", "app"]);
    assert_ok(&o);
    assert!(o.stdout.is_empty(), "{}", s(&o.stdout));
    assert_eq!(
        s(&o.stderr),
        "note: the newest log is empty (use --debug for Wine diagnostics)\n"
    );
    // a log with content stays silent on stderr
    log_file(&r, "app", "run-3-1-1.log", b"x\n");
    let o = r.rt(&["logs", "app"]);
    assert_eq!((s(&o.stdout).as_str(), s(&o.stderr).as_str()), ("x\n", ""));
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

// ================================================================ doctor

/// Every entry below the rig root (the fake Wine's `bin/` and `log/` excluded) with its type, size and mtime:
/// any modification, creation or deletion changes it.
fn snapshot(r: &Rig) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    fn walk(dir: &Path, rel: &str, out: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for e in rd {
            let e = e.unwrap();
            let name = format!("{rel}/{}", e.file_name().to_string_lossy());
            let m = fs::symlink_metadata(e.path()).unwrap();
            out.push(format!(
                "{name} mode={:o} len={} mtime={}.{}",
                m.mode(),
                m.len(),
                m.mtime(),
                m.mtime_nsec()
            ));
            if m.is_dir() {
                walk(&e.path(), &name, out);
            }
        }
    }
    let mut v = vec![];
    walk(&r.root, "", &mut v);
    v.retain(|l| !l.starts_with("/log") && !l.starts_with("/bin"));
    v.sort();
    v
}

/// The lines of `out` that contain `needle`.
fn lines_with<'a>(out: &'a str, needle: &str) -> Vec<&'a str> {
    out.lines().filter(|l| l.contains(needle)).collect()
}

/// The section header lines (not indented) of a doctor report, in order.
fn sections(out: &str) -> Vec<&str> {
    out.lines()
        .filter(|l| {
            [
                "Architecture",
                "PE",
                "Imports",
                "Graphics",
                "Audio",
                "Runtime",
                "Prefix",
                "Program",
            ]
            .contains(l)
        })
        .collect()
}

impl Rig {
    /// A fake Wine DLL directory next to the fake `wineserver` (where `dll_dirs` looks).
    fn wine_dlls(&self, names: &[&str]) {
        let d = self.bin.join("x86_64-windows");
        fs::create_dir_all(&d).unwrap();
        for n in names {
            fs::write(d.join(n), b"").unwrap();
        }
    }

    /// The runtime as a desktop user sees it: display, the PulseAudio-compatible socket (pipewire-pulse).
    fn desktop(&self) -> Command {
        let run = self.root.join("run");
        fs::create_dir_all(run.join("pulse")).unwrap();
        if !run.join("pulse/native").exists() {
            fs::write(run.join("pulse/native"), b"").unwrap();
        }
        let mut c = self.cmd();
        c.env("DISPLAY", ":0").env("XDG_RUNTIME_DIR", &run);
        c
    }
}

#[test]
fn doctor_without_arguments_runs_the_system_checks_only_and_is_read_only() {
    let r = rig();
    r.wine_dlls(&["kernel32.dll", "winepulse.drv"]);
    let _ = r.desktop(); // creates the runtime dir: part of the "before" state
    let before = snapshot(&r);
    let o = r.desktop().arg("doctor").output().unwrap();
    let out = s(&o.stdout);
    assert_eq!(snapshot(&r), before, "doctor modified something");
    assert!(o.stderr.is_empty(), "{}", s(&o.stderr));
    assert!(out.starts_with("Runtime Diagnostics\n"), "{out}");
    assert!(out.contains("System checks"), "{out}");
    assert_eq!(
        sections(&out),
        ["Architecture", "Graphics", "Audio", "Runtime"],
        "{out}"
    );
    let wine = lines_with(&out, "Wine: wine-10.0 (Fake 1)");
    assert_eq!(wine.len(), 1, "{out}");
    assert!(wine[0].trim_start().starts_with("[ok]"), "{}", wine[0]);
    assert!(lines_with(&out, "PulseAudio-compatible")[0].contains("[ok]"), "{out}");
    assert!(lines_with(&out, "X11")[0].contains("[ok]"), "{out}");
    if cfg!(target_arch = "x86_64") {
        assert!(lines_with(&out, "host architecture")[0].contains("[ok]"), "{out}");
        assert_eq!(o.status.code(), Some(0), "{out}");
    }
    let result = out.lines().last().unwrap();
    assert!(
        result == "Result: Looks good." || result == "Result: Application may fail to start.",
        "{result}: only Vulkan (a host library) can differ here"
    );
    assert!(r.calls().is_empty(), "wine was not started: {:?}", r.calls());
}

#[test]
fn doctor_says_may_fail_without_a_display_or_pipewire() {
    let r = rig();
    let o = r.rt(&["doctor"]); // a cleared environment: no display session, no PipeWire
    let out = s(&o.stdout);
    assert_eq!(o.status.code(), Some(0), "warnings are not failures: {out}");
    assert!(lines_with(&out, "no display session")[0].contains("[warn]"), "{out}");
    assert!(lines_with(&out, "no audio path")[0].contains("[warn]"), "{out}");
    assert_eq!(out.lines().last().unwrap(), "Result: Application may fail to start.");
}

#[test]
fn doctor_warns_when_only_the_pipewire_socket_exists_and_reports_the_wine_drivers() {
    let r = rig();
    r.wine_dlls(&["kernel32.dll", "winepulse.drv"]);
    let run = r.root.join("run");
    fs::create_dir_all(&run).unwrap();
    fs::write(run.join("pipewire-0"), b"").unwrap();
    let o = r.cmd().env("XDG_RUNTIME_DIR", &run).arg("doctor").output().unwrap();
    let out = s(&o.stdout);
    let l = lines_with(&out, "pipewire-pulse");
    assert!(l.len() == 1 && l[0].contains("[warn]"), "{out}");
    assert!(!out.contains("not verified"), "the drivers were listed: {out}");
    // With the pulse socket too: ok, and the same listed drivers.
    fs::create_dir_all(run.join("pulse")).unwrap();
    fs::write(run.join("pulse/native"), b"").unwrap();
    let out = s(&r
        .cmd()
        .env("XDG_RUNTIME_DIR", &run)
        .arg("doctor")
        .output()
        .unwrap()
        .stdout);
    assert!(lines_with(&out, "PulseAudio-compatible")[0].contains("[ok]"), "{out}");
    // Without the driver module in the listed directory: reported.
    fs::remove_file(r.bin.join("x86_64-windows/winepulse.drv")).unwrap();
    let out = s(&r
        .cmd()
        .env("XDG_RUNTIME_DIR", &run)
        .arg("doctor")
        .output()
        .unwrap()
        .stdout);
    assert!(lines_with(&out, "no PulseAudio driver")[0].contains("[warn]"), "{out}");
}

#[test]
fn doctor_without_wine_fails_with_the_install_hint_and_still_reports_the_rest() {
    // Neither $RUNTIME_WINE nor a wine on PATH: the discovery error carries the install hint.
    let r = rig();
    let empty = r.root.join("emptybin");
    fs::create_dir_all(&empty).unwrap();
    let o = r
        .cmd()
        .env_remove("RUNTIME_WINE")
        .env_remove("RUNTIME_WINESERVER")
        .env("PATH", &empty)
        .arg("doctor")
        .output()
        .unwrap();
    let out = s(&o.stdout);
    assert_eq!(o.status.code(), Some(1), "{out}");
    let wine = lines_with(&out, "Wine is not usable");
    assert_eq!(wine.len(), 1, "{out}");
    assert!(
        wine[0].contains("[FAIL]") && wine[0].contains("sudo apt install wine"),
        "{}",
        wine[0]
    );
    assert!(
        out.contains("Architecture") && out.contains("Graphics"),
        "the other checks still run: {out}"
    );
    assert!(
        out.lines()
            .last()
            .unwrap()
            .starts_with("Result: Application cannot run"),
        "{out}"
    );
    // A bad override: also a failure, the text says which variable.
    let r = rig().no_wine();
    let o = r.rt(&["doctor"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        lines_with(&s(&o.stdout), "RUNTIME_WINE")[0].contains("[FAIL]"),
        "{}",
        s(&o.stdout)
    );
}

#[test]
fn doctor_of_an_installed_app_runs_every_check_and_reads_only() {
    let r = rig();
    r.wine_dlls(&["kernel32.dll", "msvcrt.dll"]);
    let id = r.install();
    let _ = r.desktop(); // creates the runtime dir: part of the "before" state
    let before = snapshot(&r);
    let o = r.desktop().args(["doctor", &id]).output().unwrap();
    let out = s(&o.stdout);
    assert_eq!(snapshot(&r), before, "doctor modified the app environment");
    assert!(o.stderr.is_empty(), "{}", s(&o.stderr));
    assert_eq!(
        sections(&out),
        [
            "Architecture",
            "PE",
            "Imports",
            "Graphics",
            "Audio",
            "Runtime",
            "Prefix",
            "Program"
        ],
        "{out}"
    );
    assert!(out.contains(&format!("Application: Runtime Fixture ({id})")), "{out}");
    assert!(lines_with(&out, "valid PE")[0].contains("[ok]"), "{out}");
    assert!(lines_with(&out, "program architecture")[0].contains("[ok]"), "{out}");
    assert!(
        lines_with(&out, "imported DLLs")[0].contains("[ok]"),
        "both imports are in Wine's directory: {out}"
    );
    assert!(lines_with(&out, "prefix hardened")[0].contains("[ok]"), "{out}");
    assert!(lines_with(&out, "program found")[0].contains("hello64.exe"), "{out}");
    // Calls to the fake wine: none but `--version`, which does not log.
    assert!(
        r.calls()
            .iter()
            .all(|c| c == "wine wineboot" || c.starts_with("wineserver")),
        "{:?}",
        r.calls()
    );
    assert_eq!(
        r.calls().len(),
        2,
        "install ran wineboot + wineserver -k; doctor started nothing: {:?}",
        r.calls()
    );
    if cfg!(target_arch = "x86_64") {
        assert_ne!(o.status.code(), Some(2));
    }
}

#[test]
fn doctor_lists_missing_dlls_and_never_calls_them_missing_without_a_dll_directory() {
    let r = rig();
    let id = r.install();
    // The fake Wine has no DLL directory: not verified.
    let o = r.desktop().args(["doctor", &id]).output().unwrap();
    let out = s(&o.stdout);
    assert!(
        lines_with(&out, "DLL availability not verified")[0].contains("[warn]"),
        "{out}"
    );
    assert!(!out.contains("KERNEL32") && !out.contains("not found in Wine"), "{out}");
    // An empty DLL directory: everything the program imports is reported.
    r.wine_dlls(&[]);
    let out = s(&r.desktop().args(["doctor", &id]).output().unwrap().stdout);
    let l = lines_with(&out, "not found in Wine");
    assert_eq!(l.len(), 1, "{out}");
    assert!(
        l[0].contains("\"KERNEL32.dll\"") && l[0].contains("\"msvcrt.dll\""),
        "{}",
        l[0]
    );
    assert!(l[0].contains("[warn]"));
}

#[test]
fn doctor_of_a_file_analyses_it_without_installing_anything() {
    let r = rig();
    r.wine_dlls(&["kernel32.dll", "msvcrt.dll"]);
    let exe = fixture("hello64.exe");
    let _ = r.desktop(); // creates the runtime dir: part of the "before" state
    let before = snapshot(&r);
    let o = r.desktop().arg("doctor").arg(&exe).output().unwrap();
    let out = s(&o.stdout);
    assert_eq!(o.status.code(), Some(0), "{out}\n{}", s(&o.stderr));
    assert_eq!(snapshot(&r), before, "doctor installed or changed something");
    assert!(r.app_dirs().is_empty());
    assert!(r.calls().is_empty());
    assert!(out.contains("File: ") && out.contains("hello64.exe"), "{out}");
    assert_eq!(
        sections(&out),
        ["Architecture", "PE", "Imports", "Graphics", "Audio", "Runtime"],
        "{out}"
    );
    assert!(lines_with(&out, "valid PE")[0].contains("[ok]"));
    // A DLL is not launchable: a failure, exit 1.
    let o = r
        .desktop()
        .arg("doctor")
        .arg(fixture("exports64.dll"))
        .output()
        .unwrap();
    let out = s(&o.stdout);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(lines_with(&out, "DLL")[0].contains("[FAIL]"), "{out}");
    assert!(
        out.lines()
            .last()
            .unwrap()
            .starts_with("Result: Application cannot run"),
        "{out}"
    );
    // x86 works too.
    let o = r.desktop().arg("doctor").arg(fixture("hello32.exe")).output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", s(&o.stdout));
    assert!(s(&o.stdout).contains("x86 (32-bit"), "{}", s(&o.stdout));
}

#[test]
fn doctor_of_a_file_that_is_not_a_program_reports_a_failure_and_never_hangs() {
    let r = rig();
    let text = r.input("notes.txt", b"just text");
    let dir = r.inputs.join("adir.exe");
    fs::create_dir(&dir).unwrap();
    let fifo = r.inputs.join("pipe.exe");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    let before = snapshot(&r);
    for (what, target, needle) in [
        ("text", &text, "cannot be analysed"),
        ("directory", &dir, "not a regular file"),
        ("fifo", &fifo, "not a regular file"),
    ] {
        let mut child = r
            .cmd()
            .arg("doctor")
            .arg(target)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        let status = loop {
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            if start.elapsed() > Duration::from_secs(20) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{what}: doctor hangs");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let out = child.wait_with_output().unwrap();
        let text = s(&out.stdout);
        assert_eq!(status.code(), Some(1), "{what}: {text}");
        assert!(lines_with(&text, needle)[0].contains("[FAIL]"), "{what}: {text}");
        assert!(out.stderr.is_empty(), "{what}: {}", s(&out.stderr));
    }
    assert_eq!(snapshot(&r), before);
}

#[test]
fn doctor_of_a_zip_archive_says_to_install_it_first_and_is_not_a_failure() {
    let r = rig();
    let zip = r.input("archive.zip", b"PK\x03\x04rest");
    let before = snapshot(&r);
    let o = r.cmd().arg("doctor").arg(&zip).output().unwrap();
    let text = s(&o.stdout);
    assert_eq!(o.status.code(), Some(0), "nothing is wrong with the file: {text}");
    let line = lines_with(&text, "zip archive")[0];
    assert!(line.contains("[warn]") && line.contains("runtime install"), "{text}");
    assert!(!text.contains("[FAIL]"), "{text}");
    assert!(o.stderr.is_empty(), "{}", s(&o.stderr));
    assert_eq!(snapshot(&r), before);
}

#[test]
fn doctor_of_an_app_without_its_home_fails_and_agrees_with_run() {
    let r = rig();
    let id = r.install();
    let home = r.apps().join(&id).join("runtime/home");
    for (damage, words) in [("missing", "reinstall it"), ("symlink", "not a real directory")] {
        let _ = fs::remove_dir_all(&home);
        if damage == "symlink" {
            symlink(&r.inputs, &home).unwrap();
        }
        let o = r.desktop().args(["doctor", &id]).output().unwrap();
        let out = s(&o.stdout);
        assert_eq!(o.status.code(), Some(1), "{damage}: {out}");
        let line = lines_with(&out, "app home")[0];
        assert!(line.contains("[FAIL]") && line.contains(words), "{damage}: {out}");
        // `run` refuses the same app, with the same words.
        let err = assert_fails(&r.rt(&["run", "--unsandboxed", &id]));
        assert!(err.contains("app home") && err.contains(words), "{damage}: {err}");
    }
    // Also when the program itself cannot be resolved: both failures are reported.
    fs::remove_dir_all(&home).unwrap();
    fs::remove_file(
        r.apps()
            .join(format!("{id}/prefix/drive_c/Program Files/{id}/hello64.exe")),
    )
    .unwrap();
    let o = r.desktop().args(["doctor", &id]).output().unwrap();
    let out = s(&o.stdout);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(lines_with(&out, "app home")[0].contains("[FAIL]"), "{out}");
    assert!(lines_with(&out, "cannot be found")[0].contains("[FAIL]"), "{out}");
    // A restored home is fine again: no such line.
    fs::create_dir(&home).unwrap();
    let out = s(&r.desktop().args(["doctor", &id]).output().unwrap().stdout);
    assert!(lines_with(&out, "app home").is_empty(), "{out}");
}

#[test]
fn doctor_of_an_unknown_id_or_a_missing_file_is_an_error_with_a_hint_and_needs_no_wine() {
    let r = rig().no_wine();
    let o = r.rt(&["doctor", "nothing"]);
    let err = assert_fails(&o);
    assert!(
        err.contains("runtime list") && err.contains("runtime install <file>"),
        "{err}"
    );
    assert!(o.stdout.is_empty(), "no half report: {}", s(&o.stdout));
    let err = assert_fails(&r.rt(&["doctor", "nothing.exe"]));
    assert!(err.contains("no such file"), "{err}");
    let o = r
        .cmd()
        .args(["doctor", "Hello\u{1b}]0;x\u{7}\u{202e}"])
        .output()
        .unwrap();
    assert_tame(&assert_fails(&o), "stderr");
    assert!(r.app_dirs().is_empty());
}

#[test]
fn doctor_never_creates_the_data_dir() {
    let r = rig();
    fs::remove_dir_all(&r.data).unwrap();
    let before = snapshot(&r);
    for args in [
        vec!["doctor".to_string()],
        vec!["doctor".into(), "nothing".into()],
        vec!["doctor".into(), fixture("hello64.exe").to_str().unwrap().into()],
        vec!["doctor".into(), "--json".into()],
    ] {
        let _ = r.rt(&args);
        assert!(!r.data.exists(), "{args:?} created the data dir");
        assert_eq!(snapshot(&r), before, "{args:?}");
    }
}

#[test]
fn doctor_sanitises_a_hostile_app_name_and_reports_a_broken_program() {
    let r = rig();
    // Valid metadata, no program in the prefix; the name is hostile.
    r.plant("evil", "Evil\u{1b}]0;pwned\u{7}\u{202e}\u{9b}[2J name");
    let o = r.desktop().args(["doctor", "evil"]).output().unwrap();
    let out = s(&o.stdout);
    assert_tame(&out, "stdout");
    assert!(out.contains("Application: Evil"), "{out}");
    assert!(out.contains("\\u{1b}"), "escaped, not dropped: {out}");
    let l = lines_with(&out, "cannot be found or used");
    assert!(l[0].contains("[FAIL]") && l[0].contains("runtime remove evil"), "{out}");
    assert_eq!(o.status.code(), Some(1), "{out}");
    // JSON: escapes, the same text.
    let o = r.desktop().args(["doctor", "evil", "--json"]).output().unwrap();
    assert_tame(&s(&o.stdout), "json");
    let v = json(&o);
    assert_eq!(v["subject"]["kind"], "app");
    assert_eq!(
        v["subject"]["name"], "Evil\u{1b}]0;pwned\u{7}\u{202e}\u{9b}[2J name",
        "the JSON is faithful, only escaped"
    );
}

#[test]
fn doctor_flags_an_unhardened_prefix() {
    let r = rig();
    let id = r.install();
    let prefix = r.apps().join(&id).join("prefix");
    // z: back, and a link that leaves drive_c.
    symlink("/", prefix.join("dosdevices/z:")).unwrap();
    symlink("/etc", prefix.join("drive_c/users/tester/Desktop")).unwrap();
    let _ = r.desktop(); // creates the runtime dir: part of the "before" state
    let before = snapshot(&r);
    let o = r.desktop().args(["doctor", &id]).output().unwrap();
    let out = s(&o.stdout);
    assert_eq!(snapshot(&r), before, "doctor repaired something");
    assert!(
        lines_with(&out, "host root drive present")[0].contains("[warn]"),
        "{out}"
    );
    let l = lines_with(&out, "Desktop");
    assert!(l[0].contains("[FAIL]"), "{out}");
    assert_eq!(o.status.code(), Some(1));
    // Wine's com* links alone are tolerated.
    let r = rig();
    let id = r.install();
    let prefix = r.apps().join(&id).join("prefix");
    symlink("/dev/ttyS0", prefix.join("dosdevices/com1")).unwrap();
    let out = s(&r.desktop().args(["doctor", &id]).output().unwrap().stdout);
    let l = lines_with(&out, "prefix hardened");
    assert!(l[0].contains("[ok]") && l[0].contains("com"), "{out}");
}

#[test]
fn doctor_json_has_a_stable_shape() {
    let r = rig();
    r.wine_dlls(&["kernel32.dll", "msvcrt.dll"]);
    let id = r.install();
    let statuses = ["ok", "warn", "fail"];
    let areas = [
        "architecture",
        "pe",
        "imports",
        "graphics",
        "audio",
        "runtime",
        "prefix",
        "program",
    ];
    let verdicts = ["good", "may_fail", "fail"];
    let exe = fixture("hello64.exe");
    for (args, kind, expect_areas) in [
        (
            vec!["doctor".as_ref(), "--json".as_ref()],
            "system",
            vec!["architecture", "graphics", "audio", "runtime"],
        ),
        (
            vec!["doctor".as_ref(), id.as_ref(), "--json".as_ref()],
            "app",
            areas.to_vec(),
        ),
        (
            vec!["doctor".as_ref(), exe.as_os_str(), "--json".as_ref()],
            "file",
            vec!["architecture", "pe", "imports", "graphics", "audio", "runtime"],
        ),
    ] {
        let o = r.desktop().args(&args).output().unwrap();
        assert!(o.stderr.is_empty(), "{}", s(&o.stderr));
        let v = json(&o);
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["checks", "subject", "verdict"]);
        assert_eq!(v["subject"]["kind"], kind);
        assert!(verdicts.contains(&v["verdict"].as_str().unwrap()), "{v}");
        let checks = v["checks"].as_array().unwrap();
        assert!(!checks.is_empty());
        let mut seen: Vec<&str> = vec![];
        for c in checks {
            let mut k: Vec<&str> = c.as_object().unwrap().keys().map(String::as_str).collect();
            k.sort_unstable();
            assert_eq!(k, ["area", "status", "text"], "{c}");
            assert!(areas.contains(&c["area"].as_str().unwrap()), "{c}");
            assert!(statuses.contains(&c["status"].as_str().unwrap()), "{c}");
            assert!(c["text"].is_string());
            if !seen.contains(&c["area"].as_str().unwrap()) {
                seen.push(c["area"].as_str().unwrap());
            }
        }
        let mut want = expect_areas.clone();
        want.sort_unstable();
        seen.sort_unstable();
        assert_eq!(seen, want, "{kind}");
        // The verdict matches the statuses and the exit code.
        let worst = if checks.iter().any(|c| c["status"] == "fail") {
            "fail"
        } else if checks.iter().any(|c| c["status"] == "warn") {
            "may_fail"
        } else {
            "good"
        };
        assert_eq!(v["verdict"], worst);
        assert_eq!(o.status.code(), Some(i32::from(worst == "fail")));
    }
    // A file's subject carries its path.
    let o = r
        .desktop()
        .args(["doctor".as_ref(), exe.as_os_str(), "--json".as_ref()])
        .output()
        .unwrap();
    assert!(json(&o)["subject"]["path"].as_str().unwrap().ends_with("hello64.exe"));
}

#[test]
fn doctor_arguments_are_checked() {
    let r = rig();
    for args in [&["doctor", "a", "b"][..], &["doctor", "--nope"]] {
        let o = r.rt(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(o.stdout.is_empty());
    }
}

#[test]
fn doctor_reports_an_unreadable_program_directory_as_failures_never_as_missing_dlls() {
    use std::os::unix::fs::PermissionsExt;
    let r = rig();
    r.wine_dlls(&[]); // an empty DLL directory: every import would be "missing" if the program were looked at
    let id = r.install();
    let dir = r.apps().join(&id).join("prefix/drive_c/Program Files").join(&id);
    // Searchable but not listable: locating the program (a case-insensitive lookup) and the prefix audit both need
    // to list it, so the failure is reported there. (The import check's own handling of a program directory that
    // cannot be listed is tested in core, where the listing is injected.)
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o111)).unwrap();
    let readable_anyway = fs::read_dir(&dir).is_ok();
    let o = r.desktop().args(["doctor", &id]).output().unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap(); // so the tempdir can be removed
    if readable_anyway {
        eprintln!("SKIPPED: running as root, a mode 111 directory is still listable");
        return;
    }
    let out = s(&o.stdout);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(lines_with(&out, "cannot be examined")[0].contains("[FAIL]"), "{out}");
    assert!(
        lines_with(&out, "cannot be found or used")[0].contains("[FAIL]"),
        "{out}"
    );
    assert!(!out.contains("not found in"), "no DLL is called missing: {out}");
    assert!(!out.contains("Imports"), "{out}");
}

#[test]
fn doctor_calls_a_prefix_without_drive_c_incomplete() {
    let r = rig();
    let id = r.install();
    let prefix = r.apps().join(&id).join("prefix");
    fs::rename(prefix.join("drive_c"), r.root.join("moved-drive_c")).unwrap();
    let o = r.desktop().args(["doctor", &id]).output().unwrap();
    let out = s(&o.stdout);
    let l = lines_with(&out, "incomplete prefix");
    assert_eq!(l.len(), 1, "{out}");
    assert!(l[0].contains("[warn]") && l[0].contains("drive_c missing"), "{}", l[0]);
    assert!(!out.contains("cannot be examined"), "{out}");
}

/// The roadmap's "deliberately broken environment": a symlinked `drive_c` is a failing verdict, in JSON too, and
/// names the checks. (A missing executable and a missing or symlinked home are covered by
/// `doctor_of_an_app_without_its_home_fails_and_agrees_with_run`; a missing `drive_c` is only the warning
/// `doctor_calls_a_prefix_without_drive_c_incomplete` asserts.)
#[test]
fn doctor_of_an_app_whose_drive_c_is_a_symlink_fails_and_names_the_prefix() {
    let r = rig();
    let id = r.install();
    let drive_c = r.apps().join(&id).join("prefix/drive_c");
    fs::rename(&drive_c, r.root.join("elsewhere")).unwrap();
    symlink(r.root.join("elsewhere"), &drive_c).unwrap();
    let o = r.desktop().args(["doctor", &id]).output().unwrap();
    let out = s(&o.stdout);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(lines_with(&out, "cannot be examined")[0].contains("[FAIL]"), "{out}");
    assert!(out.contains("Application cannot run"), "{out}");
    let j: serde_json::Value =
        serde_json::from_slice(&r.desktop().args(["doctor", &id, "--json"]).output().unwrap().stdout).unwrap();
    assert_eq!(j["verdict"], "fail");
    assert!(
        j["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["area"] == "prefix" && c["status"] == "fail")
    );
}

// ================================================================ doctor: .NET and the Direct3D route

/// Records the bundled package `pkg` as installed for `id` (as `deps --install` would), without downloading.
fn record_installed(r: &Rig, id: &str, pkg: &str) {
    let store = rt_core::Store::new(r.apps()).unwrap();
    let env = store.get(&rt_core::AppId::parse(id).unwrap()).unwrap();
    let mut md = store.read_metadata(&env).unwrap();
    let p = rt_deps::Manifest::bundled().get(pkg).unwrap();
    rt_deps::record(
        &mut md,
        rt_core::DependencyRecord {
            id: p.id.clone(),
            version: p.version.clone(),
            sha256: p.sha256.clone(),
            installed_at: 1,
            consent: None,
        },
    )
    .unwrap();
    store.write_metadata(&env, &md).unwrap();
}

fn route_lines(out: &str) -> Vec<&str> {
    lines_with(out, "Direct3D ")
}

#[test]
fn doctor_predicts_the_built_in_route_when_dxvk_is_not_installed() {
    let r = rig();
    let (id, _) = install_d3d11(&r);
    let o = r.desktop().args(["doctor", &id]).output().unwrap();
    let out = s(&o.stdout);
    let l = route_lines(&out);
    assert_eq!(l.len(), 1, "{out}");
    assert!(
        l[0].contains("[warn]")
            && l[0].contains("Direct3D 11")
            && l[0].contains("built-in")
            && l[0].contains("runtime deps"),
        "{out}"
    );
    assert!(!l[0].contains("DXVK is"), "{out}");
}

#[test]
fn doctor_predicts_dxvk_when_it_is_recorded_and_vulkan_is_usable_and_built_in_when_it_is_not() {
    let r = rig();
    let (id, _) = install_d3d11(&r);
    record_installed(&r, &id, "dxvk");
    let out = s(&r.desktop().args(["doctor", &id]).output().unwrap().stdout);
    let l = route_lines(&out);
    assert_eq!(l.len(), 1, "{out}");
    assert!(l[0].contains("[ok]") && l[0].contains("Direct3D 11: DXVK"), "{out}");
    let out = s(&r
        .desktop()
        .env("RUNTIME_VULKAN_LOADER", "absent")
        .args(["doctor", &id])
        .output()
        .unwrap()
        .stdout);
    let l = route_lines(&out);
    assert_eq!(l.len(), 1, "{out}");
    // installed + Vulkan unusable: DXVK's DLLs still win, so the app fails: a failing check, not "built-in"
    assert!(
        l[0].contains("[FAIL]")
            && l[0].contains("DXVK is installed but Vulkan is unusable")
            && l[0].contains("fail to create a Direct3D device"),
        "{out}"
    );
    assert!(out.contains("Application cannot run"), "{out}");
    // JSON: the areas stay `graphics` and `runtime`
    let j: serde_json::Value =
        serde_json::from_slice(&r.desktop().args(["doctor", &id, "--json"]).output().unwrap().stdout).unwrap();
    let d3d: Vec<&serde_json::Value> = j["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["text"].as_str().unwrap().starts_with("Direct3D"))
        .collect();
    assert_eq!(d3d.len(), 1);
    assert_eq!(d3d[0]["area"], "graphics");
}

#[test]
fn doctor_says_vulkan_is_not_verified_when_the_probe_lists_nothing() {
    let r = rig();
    let (id, _) = install_d3d11(&r);
    record_installed(&r, &id, "dxvk");
    script(&r.bin.join("vulkaninfo"), "echo nothing useful");
    let out = s(&r.desktop().args(["doctor", &id]).output().unwrap().stdout);
    let l = route_lines(&out);
    assert!(
        l.len() == 1 && l[0].contains("DXVK") && l[0].contains("Vulkan not verified"),
        "{out}"
    );
}

#[test]
fn doctor_d3d11_and_d3d12_on_an_unusable_vulkan_are_both_built_in() {
    let r = rig();
    // two imports patched to d3d12.dll and d3d11.dll
    let mut bytes = fs::read(fixture("hello64.exe")).unwrap();
    let at = bytes
        .windows(12)
        .position(|w| w.eq_ignore_ascii_case(b"kernel32.dll"))
        .expect("import");
    bytes[at..at + 12].copy_from_slice(b"d3d12.dll\0\0\0");
    let at = bytes
        .windows(11)
        .position(|w| w.eq_ignore_ascii_case(b"msvcrt.dll\0"))
        .expect("import");
    bytes[at..at + 11].copy_from_slice(b"d3d11.dll\0\0");
    let p = r.input("both.exe", &bytes);
    let out2 = r.rt(&[OsString::from("install"), p.into_os_string()]);
    assert_ok(&out2);
    let id2 = installed_id(&out2);
    let out = s(&r
        .desktop()
        .env("RUNTIME_VULKAN_LOADER", "absent")
        .args(["doctor", &id2])
        .output()
        .unwrap()
        .stdout);
    let l = route_lines(&out);
    assert_eq!(l.len(), 2, "{out}");
    assert!(
        l.iter()
            .all(|x| x.contains("built-in") && x.contains("Vulkan") && !x.contains("DXVK")),
        "{out}"
    );
}

#[test]
fn doctor_predicts_the_built_in_route_for_a_32_bit_app_even_with_dxvk_recorded() {
    let r = rig();
    r.wine_dlls(&[
        "kernel32.dll",
        "msvcrt.dll",
        "d3d11.dll",
        "winepulse.drv",
        "winewayland.drv",
    ]);
    let mut bytes = fs::read(fixture("hello64.exe")).unwrap();
    let at = bytes
        .windows(11)
        .position(|w| w.eq_ignore_ascii_case(b"msvcrt.dll\0"))
        .unwrap();
    bytes[at..at + 11].copy_from_slice(b"d3d11.dll\0\0");
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    bytes[pe + 4..pe + 6].copy_from_slice(&0x014Cu16.to_le_bytes()); // machine: i386
    let p = r.input("x86.exe", &bytes);
    let o = r.rt(&[OsString::from("install"), p.into_os_string()]);
    assert_ok(&o);
    let id = installed_id(&o);
    let want = |out: &str, why: &str| {
        let l = route_lines(out);
        assert!(
            l.len() == 1
                && l[0].contains("[ok]")
                && l[0].contains("built-in")
                && l[0].contains(why)
                && !l[0].contains("DXVK:"),
            "{out}"
        );
    };
    let out = s(&r.desktop().args(["doctor", &id]).output().unwrap().stdout);
    want(&out, "64-bit only");
    record_installed(&r, &id, "dxvk");
    let out = s(&r.desktop().args(["doctor", &id]).output().unwrap().stdout);
    want(&out, "DXVK covers 64-bit only");
    // nothing to act on: the whole report is as good as the rest of it (a 32-bit app is not "may fail")
    assert!(out.contains("Looks good."), "{out}");
}

#[test]
fn doctor_reports_one_direct3d_10_line_for_all_d3d10_imports() {
    let r = rig();
    let mut bytes = fs::read(fixture("hello64.exe")).unwrap();
    for (from, to) in [
        (&b"kernel32.dll"[..], &b"d3d10_1.dll\0"[..]),
        (b"msvcrt.dll\0", b"D3D10.DLL\0\0"),
    ] {
        let at = bytes
            .windows(from.len())
            .position(|w| w.eq_ignore_ascii_case(from))
            .unwrap();
        bytes[at..at + to.len()].copy_from_slice(to);
    }
    let p = r.input("d10.exe", &bytes);
    let o = r.rt(&[OsString::from("install"), p.into_os_string()]);
    assert_ok(&o);
    let out = s(&r.desktop().args(["doctor", &installed_id(&o)]).output().unwrap().stdout);
    assert_eq!(route_lines(&out).len(), 1, "{out}");
    assert!(route_lines(&out)[0].contains("Direct3D 10"), "{out}");
}

#[test]
fn doctor_of_a_file_or_the_system_predicts_no_direct3d_route() {
    let r = rig();
    let mut bytes = fs::read(fixture("hello64.exe")).unwrap();
    let at = bytes
        .windows(11)
        .position(|w| w.eq_ignore_ascii_case(b"msvcrt.dll\0"))
        .unwrap();
    bytes[at..at + 11].copy_from_slice(b"d3d11.dll\0\0");
    let f = r.input("g.exe", &bytes);
    let out = s(&r.desktop().arg("doctor").arg(&f).output().unwrap().stdout);
    assert!(route_lines(&out).is_empty(), "{out}");
    let out = s(&r.desktop().arg("doctor").output().unwrap().stdout);
    assert!(route_lines(&out).is_empty(), "{out}");
}

/// `hello64.exe` with a CLR header (data directory 14: a non-zero RVA and size), so the analysis calls it managed.
fn managed_exe() -> Vec<u8> {
    let mut bytes = fs::read(fixture("hello64.exe")).unwrap();
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let dir = pe + 24 + 112 + 14 * 8;
    bytes[dir..dir + 4].copy_from_slice(&0x2008u32.to_le_bytes());
    bytes[dir + 4..dir + 8].copy_from_slice(&72u32.to_le_bytes());
    bytes
}

fn install_managed(r: &Rig) -> String {
    let p = r.input("managed.exe", &managed_exe());
    let o = r.rt(&[OsString::from("install"), p.into_os_string()]);
    assert_ok(&o);
    let id = installed_id(&o);
    let all = format!("{}{}", s(&o.stdout), s(&o.stderr));
    assert!(all.contains(&format!("run `runtime deps {id} --install`")), "{all}");
    id
}

#[test]
fn doctor_judges_a_managed_program_by_the_recorded_wine_mono_and_ignores_a_native_one() {
    let r = rig();
    let id = install_managed(&r);
    let out = s(&r.desktop().args(["doctor", &id]).output().unwrap().stdout);
    let l = lines_with(&out, ".NET");
    assert_eq!(l.len(), 1, "{out}");
    assert!(
        l[0].contains("[warn]")
            && l[0].contains("Wine Mono is not installed for this app")
            && l[0].contains(&format!("runtime deps {id} --install")),
        "{out}"
    );
    assert!(!out.contains("mscoree=d"), "{out}");
    let j: serde_json::Value =
        serde_json::from_slice(&r.desktop().args(["doctor", &id, "--json"]).output().unwrap().stdout).unwrap();
    assert!(
        j["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["area"] == "runtime" && c["status"] == "warn" && c["text"].as_str().unwrap().contains(".NET"))
    );
    // Recorded: Ok, with the recorded version.
    record_installed(&r, &id, "wine-mono");
    let out = s(&r.desktop().args(["doctor", &id]).output().unwrap().stdout);
    let l = lines_with(&out, ".NET");
    assert_eq!(l.len(), 1, "{out}");
    assert!(
        l[0].contains("[ok]") && l[0].contains("Wine Mono 9.4.0 is recorded as installed for this app"),
        "{out}"
    );
    // A file target is not an installed app: told, not warned.
    let f = r.input("m2.exe", &managed_exe());
    let out = s(&r.desktop().arg("doctor").arg(&f).output().unwrap().stdout);
    let l = lines_with(&out, ".NET");
    assert_eq!(l.len(), 1, "{out}");
    assert!(
        l[0].contains("[ok]") && l[0].contains("installed per app by `runtime deps`"),
        "{out}"
    );
    let native = r.install();
    let out = s(&r.desktop().args(["doctor", &native]).output().unwrap().stdout);
    assert!(lines_with(&out, ".NET").is_empty(), "{out}");
}

#[test]
fn run_enables_mscoree_only_for_an_app_with_wine_mono_recorded() {
    let r = rig();
    let managed = install_managed(&r);
    let overrides = |id: &str| {
        assert_eq!(r.rt(&["run", "--unsandboxed", id]).status.code(), Some(0));
        fs::read_to_string(r.log.join("env.txt"))
            .unwrap()
            .lines()
            .find(|l| l.starts_with("WINEDLLOVERRIDES="))
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        overrides(&managed),
        "WINEDLLOVERRIDES=winemenubuilder.exe=d;mscoree=d;mshtml=d"
    );
    record_installed(&r, &managed, "wine-mono");
    assert_eq!(overrides(&managed), "WINEDLLOVERRIDES=winemenubuilder.exe=d;mshtml=d");
    // Another app, without the record, keeps mscoree=d.
    let native = r.install_as("other.exe", &[]);
    assert_eq!(
        overrides(&native),
        "WINEDLLOVERRIDES=winemenubuilder.exe=d;mscoree=d;mshtml=d"
    );
}

// ================================================================ deps

/// Holds `id`'s dependency lock exclusively, as a running `runtime deps <id> --install` does.
fn hold_deps_lock(r: &Rig, id: &str) -> rt_deps::AppLock {
    let store = rt_core::Store::new(r.apps()).unwrap();
    rt_deps::lock_app(&store.get(&rt_core::AppId::parse(id).unwrap()).unwrap()).unwrap()
}

/// Installs `hello64.exe` with its `msvcrt.dll` import renamed to `d3d11.dll`: the bundled manifest plans DXVK.
fn install_d3d11(r: &Rig) -> (String, Output) {
    install_patched(r, b"msvcrt.dll\0", b"d3d11.dll\0\0")
}

/// Installs `hello64.exe` with the import `from` renamed to `to` (same length, NUL terminated).
fn install_patched(r: &Rig, from: &[u8], to: &[u8]) -> (String, Output) {
    assert_eq!(from.len(), to.len());
    let mut bytes = fs::read(fixture("hello64.exe")).unwrap();
    let at = bytes
        .windows(from.len())
        .position(|w| w.eq_ignore_ascii_case(from))
        .expect("import");
    bytes[at..at + to.len()].copy_from_slice(to);
    let p = r.input("game.exe", &bytes);
    let out = r.rt(&[OsString::from("install"), p.into_os_string()]);
    assert_ok(&out);
    (installed_id(&out), out)
}

#[test]
fn deps_prints_the_plan_without_changing_anything_and_install_run_doctor_hint() {
    let r = rig();
    let (id, installed) = install_d3d11(&r);
    let hint = format!("hint: 1 dependency missing: run `runtime deps {id}`\n");
    assert!(s(&installed.stderr).contains(&hint), "{}", s(&installed.stderr));
    let (tree, calls) = (r.tree(), r.calls());
    let o = r.rt(&["deps", &id]);
    assert_ok(&o);
    assert_eq!(
        s(&o.stdout),
        format!("Dependencies of {id}:\n  dxvk 3.1.1 (Zlib): to install\nInstall with: runtime deps {id} --install\n")
    );
    assert_eq!(
        (r.tree(), r.calls()),
        (tree, calls),
        "`deps <app>` wrote something or ran Wine"
    );
    let d = r.rt(&["doctor", &id]);
    assert!(s(&d.stderr).contains(&hint), "{}", s(&d.stderr));
    // `run` stays cheap: no hint, so the executable is never read for one.
    let run = r.rt(&["run", "--unsandboxed", &id]);
    assert_ok(&run);
    assert!(!s(&run.stderr).contains("hint:"), "{}", s(&run.stderr));
    let list = r.rt(&["deps", "list"]);
    assert_ok(&list);
    assert!(
        s(&list.stdout).contains("  dxvk 3.1.1 (Zlib): provides d3d8, d3d9"),
        "{}",
        s(&list.stdout)
    );
    // Nothing interrupted: nothing to discard.
    let o = r.rt(&["deps", &id, "--discard-interrupted", "dxvk"]);
    assert_ok(&o);
    assert_eq!(s(&o.stdout), "Nothing to discard for dxvk.\n");
}

/// `runtime deps <app>` for an app importing d3d11 with the given loader override; asserts nothing was written.
fn deps_output_with_loader(r: &Rig, loader: &str) -> String {
    let (id, _) = install_d3d11(r);
    let (tree, calls) = (r.tree(), r.calls());
    let o = r
        .cmd()
        .env("RUNTIME_VULKAN_LOADER", loader)
        .args(["deps", &id])
        .output()
        .unwrap();
    assert_ok(&o);
    assert_eq!((r.tree(), r.calls()), (tree, calls), "nothing written, no network");
    let out = s(&o.stdout);
    assert!(!out.contains("): to install"), "{out}");
    out
}

#[test]
fn deps_shows_dxvk_blocked_when_the_vulkan_loader_is_absent() {
    let out = deps_output_with_loader(&rig(), "absent");
    assert!(
        out.contains("blocked") && out.contains("loader") && out.contains("Wine's built-in Direct3D"),
        "{out}"
    );
}

#[test]
fn deps_install_does_not_install_a_package_blocked_for_vulkan() {
    let r = rig();
    let (id, _) = install_d3d11(&r);
    let o = r
        .cmd()
        .env("RUNTIME_VULKAN_LOADER", "absent")
        .args(["deps", &id, "--install"])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(1),
        "a skipped package is exit 1: {}",
        s(&o.stdout)
    );
    let out = s(&o.stdout);
    assert!(
        out.contains("skipped:   dxvk: Vulkan is unusable") && out.contains("0 installed"),
        "{out}"
    );
    assert!(
        !r.data
            .join("apps")
            .join(&id)
            .join("prefix/drive_c/windows/system32/d3d11.dll")
            .exists(),
        "dxvk was installed on a host without Vulkan"
    );
    assert!(!r.data.join("deps-cache").exists(), "something was downloaded");
}

#[test]
fn deps_shows_dxvk_blocked_when_the_only_gpu_is_vulkan_1_1() {
    let r = rig();
    script(&r.bin.join("vulkaninfo"), &vulkaninfo_body(1, 1));
    let out = deps_output_with_loader(&r, "present");
    assert!(
        out.contains("no Vulkan device supports API 1.3 (best is 1.1)") && out.contains("Wine's built-in Direct3D"),
        "{out}"
    );
}

#[test]
fn deps_yes_mistakes_are_refused_before_anything_happens() {
    let r = rig();
    let (id, _) = install_d3d11(&r);
    let tree = r.tree();
    let bare = r.rt(&["deps", &id, "--install", "--yes"]);
    assert_eq!(bare.status.code(), Some(2), "{}", s(&bare.stderr));
    // dxvk needs no consent; nope is not in the plan.
    for pkg in ["dxvk", "nope"] {
        let err = assert_fails(&r.rt(&["deps", &id, "--install", "--yes", pkg]));
        assert!(err.contains(pkg) && err.contains("nothing was installed"), "{err}");
    }
    assert_eq!(r.tree(), tree, "no lock file, no cache directory, nothing");
}

#[test]
fn remove_uninstall_run_and_install_refuse_while_a_dependency_install_holds_the_lock() {
    let r = rig();
    let (id, _) = install_d3d11(&r);
    let lock = hold_deps_lock(&r, &id);
    let before = r.calls();
    for (cmd, verb) in [("remove", "remove"), ("uninstall", "uninstall"), ("run", "start")] {
        let err = assert_fails(&r.rt(&[cmd, &id]));
        assert!(
            err.contains(&format!("cannot {verb} {id}")) && err.contains("wait"),
            "{cmd}: {err}"
        );
    }
    let err = assert_fails(&r.rt(&["deps", &id, "--install"]));
    assert!(err.contains("another runtime command"), "{err}");
    assert_eq!(r.app_dirs(), std::slice::from_ref(&id));
    assert_eq!(r.calls(), before, "nothing was stopped, run or removed");
    drop(lock);
    assert_ok(&r.rt(&["run", "--unsandboxed", &id]));
    assert_ok(&r.rt(&["remove", &id]));
    assert!(r.app_dirs().is_empty());
}

#[test]
fn deps_cache_lists_and_clears_only_completed_downloads() {
    let r = rig().no_wine();
    let o = r.rt(&["deps", "cache"]);
    assert_ok(&o);
    assert!(
        s(&o.stdout).ends_with("Total: 0 file(s), 0 bytes\n"),
        "{}",
        s(&o.stdout)
    );
    assert!(!r.data.join("deps-cache").exists(), "listing created the cache");
    let dir = r.data.join("deps-cache");
    fs::create_dir(&dir).unwrap();
    let hex = "ab".repeat(32);
    fs::write(dir.join(&hex), b"123").unwrap();
    fs::write(dir.join(".tmp-1-0-00000000"), b"in progress").unwrap();
    symlink(r.root.join("in"), dir.join("cd".repeat(32))).unwrap();
    let o = r.rt(&["deps", "cache"]);
    assert_ok(&o);
    assert!(
        s(&o.stdout).contains(&format!("  {hex}  3 bytes\nTotal: 1 file(s), 3 bytes\n")),
        "{}",
        s(&o.stdout)
    );
    let o = r.rt(&["deps", "cache", "--clear"]);
    assert_ok(&o);
    assert!(
        s(&o.stdout).ends_with("Deleted 1 file(s), 3 bytes\n"),
        "{}",
        s(&o.stdout)
    );
    assert!(!dir.join(&hex).exists());
    assert!(dir.join(".tmp-1-0-00000000").exists() && dir.join("cd".repeat(32)).is_symlink());
}

/// hello64.exe with `KERNEL32.dll` renamed to `msvcp140.dll`: the bundled manifest plans the consent-gated vcrun2022.
fn install_msvcp140(r: &Rig) -> String {
    install_patched(r, b"KERNEL32.dll\0", b"msvcp140.dll\0").0
}

#[test]
fn deps_install_without_a_terminal_never_consents_even_when_stdin_says_yes() {
    let r = rig();
    let id = install_msvcp140(&r);
    // A file where the download cache belongs: a fetch fails on it before any network access (the fetcher checks
    // the cache directory first), so this test can never download, and the file shows whether one was tried.
    let cache = r.data.join("deps-cache");
    fs::write(&cache, b"not a directory").unwrap();
    let mut child = r
        .cmd()
        .args(["deps", &id, "--install"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(b"y\n").unwrap();
    }
    let o = child.wait_with_output().unwrap();
    let out = s(&o.stdout);
    assert_eq!(o.status.code(), Some(1), "{out}\n{}", s(&o.stderr));
    assert!(
        out.contains("vcrun2022 14.44.35211 (proprietary-redistributable): to install, needs your consent"),
        "{out}"
    );
    assert!(
        out.contains("Package: vcrun2022\nVersion: 14.44.35211\nLicence: proprietary-redistributable\n"),
        "{out}"
    );
    assert!(
        out.contains("No consent: vcrun2022 is skipped (no terminal to ask on"),
        "{out}"
    );
    assert!(!out.contains("[y/N]") && !out.contains("download failed"), "{out}");
    assert!(out.contains("skipped:   vcrun2022: "), "{out}");
    assert_eq!(
        fs::read(&cache).unwrap(),
        b"not a directory",
        "a download was attempted"
    );
}

#[test]
fn deps_discard_of_an_installer_package_does_not_claim_a_clean_prefix() {
    let r = rig();
    let id = install_msvcp140(&r);
    let o = r.rt(&["deps", &id, "--discard-interrupted", "vcrun2022"]);
    assert_ok(&o);
    let out = s(&o.stdout);
    assert!(!out.contains("Nothing to discard"), "{out}");
    assert!(
        out.contains("installer package") && out.contains("no journal") && out.contains("recreate the environment"),
        "{out}"
    );
}

// ================================================================ display

/// The fake `reg.exe` (the fake wine runs it as an app, `$2` is the verb): `add ... /d V` writes a `user.reg`
/// with `Graphics` = V, `delete` removes it. Returns the app's prefix.
fn display_app(r: &Rig) -> PathBuf {
    let dir = r.plant("dapp", "D");
    let prefix = dir.join("prefix");
    fs::create_dir_all(prefix.join("drive_c/windows/system32")).unwrap();
    fs::create_dir_all(dir.join("runtime/home")).unwrap();
    fs::write(prefix.join("drive_c/windows/system32/reg.exe"), b"MZ").unwrap();
    r.hook(
        r#"printf '%s\n' "$*" >> "$(dirname "$0")/../log/reg-argv.txt"
case "$2" in
  add) printf 'WINE REGISTRY Version 2\n\n[Software\\\\Wine\\\\Drivers] 1\n"Graphics"="%s"\n\n' "$7" > "$WINEPREFIX/user.reg" ;;
  delete) rm -f "$WINEPREFIX/user.reg" ;;
esac"#,
    );
    prefix
}

fn user_reg(prefix: &Path, body: &str) {
    fs::write(
        prefix.join("user.reg"),
        format!("WINE REGISTRY Version 2\n\n[Software\\\\Wine\\\\Drivers] 1\n{body}\n\n"),
    )
    .unwrap();
}

/// A Wayland session: a socket `wayland-1` under `run/`.
fn wayland(r: &Rig) -> Command {
    let run = r.root.join("run");
    fs::create_dir_all(&run).unwrap();
    fs::write(run.join("wayland-1"), b"").unwrap();
    let mut c = r.cmd();
    c.env("WAYLAND_DISPLAY", "wayland-1").env("XDG_RUNTIME_DIR", &run);
    c
}

fn display_lines(o: &Output) -> Vec<String> {
    assert_ok(o);
    s(&o.stdout).lines().map(String::from).collect()
}

fn reg_argv(r: &Rig) -> Vec<String> {
    fs::read_to_string(r.log.join("reg-argv.txt"))
        .unwrap_or_default()
        .lines()
        .map(|l| l.split_once(' ').map_or(l, |x| x.1).to_owned())
        .collect()
}

fn reg_ran(r: &Rig) -> bool {
    r.calls().iter().any(|c| c == "wine <app>")
}

#[test]
fn display_reads_auto_on_a_fresh_app() {
    let r = rig();
    display_app(&r);
    assert_eq!(
        display_lines(&r.rt(&["display", "dapp"])),
        ["graphics driver: auto", "session: none", "winewayland: not verified"]
    );
    r.wine_dlls(&["kernel32.dll"]);
    let o = r.cmd().env("DISPLAY", ":0").args(["display", "dapp"]).output().unwrap();
    assert_eq!(
        display_lines(&o),
        [
            "graphics driver: auto",
            "session: x11 DISPLAY :0",
            "winewayland: not found"
        ]
    );
    let o = wayland(&r).args(["display", "dapp"]).output().unwrap();
    assert_eq!(display_lines(&o)[1], "session: wayland socket wayland-1");
    assert!(!reg_ran(&r));
}

#[test]
fn display_wayland_is_refused_without_a_session_and_writes_nothing() {
    let r = rig();
    let prefix = display_app(&r);
    r.wine_dlls(&["winewayland.drv"]);
    user_reg(&prefix, "\"Graphics\"=\"x11,wayland\"");
    let before = fs::read(prefix.join("user.reg")).unwrap();
    let err = assert_fails(&r.rt(&["display", "dapp", "wayland"]));
    assert!(err.contains("no Wayland session"), "{err}");
    assert_eq!(fs::read(prefix.join("user.reg")).unwrap(), before);
    // WAYLAND_DISPLAY set but no socket: still no session
    let o = r
        .cmd()
        .env("WAYLAND_DISPLAY", "wayland-9")
        .env("XDG_RUNTIME_DIR", r.root.join("run"))
        .args(["display", "dapp", "wayland"])
        .output()
        .unwrap();
    assert!(assert_fails(&o).contains("no Wayland session"));
    assert_eq!(fs::read(prefix.join("user.reg")).unwrap(), before);
    assert!(!reg_ran(&r));
}

#[test]
fn display_wayland_is_refused_when_wine_has_no_winewayland() {
    let r = rig();
    let prefix = display_app(&r);
    r.wine_dlls(&["kernel32.dll"]);
    let o = wayland(&r).args(["display", "dapp", "wayland"]).output().unwrap();
    assert!(assert_fails(&o).contains("no winewayland"));
    assert!(!prefix.join("user.reg").exists() && !reg_ran(&r));
}

#[test]
fn display_wayland_sets_and_rereads_and_auto_and_x11_follow() {
    let r = rig();
    let prefix = display_app(&r);
    r.wine_dlls(&["winewayland.drv"]);
    let o = wayland(&r).args(["display", "dapp", "wayland"]).output().unwrap();
    assert_ok(&o);
    let o = wayland(&r).args(["display", "dapp"]).output().unwrap();
    assert_eq!(
        display_lines(&o),
        [
            "graphics driver: wayland",
            "session: wayland socket wayland-1",
            "winewayland: present"
        ]
    );
    assert_ok(&r.rt(&["display", "dapp", "auto"]));
    assert!(!prefix.join("user.reg").exists());
    let k = r"HKCU\Software\Wine\Drivers";
    assert_eq!(
        reg_argv(&r),
        [
            format!("add {k} /v Graphics /d wayland /f"),
            format!("delete {k} /v Graphics /f")
        ]
    );
    // x11 without DISPLAY warns and still sets
    let o = r.rt(&["display", "dapp", "x11"]);
    assert_ok(&o);
    assert!(s(&o.stderr).contains("warning: DISPLAY is not set"), "{}", s(&o.stderr));
    assert_eq!(display_lines(&r.rt(&["display", "dapp"]))[0], "graphics driver: x11");
}

#[test]
fn display_shows_a_custom_value_cleaned_and_setting_overwrites_it() {
    let r = rig();
    let prefix = display_app(&r);
    user_reg(&prefix, "\"Graphics\"=\"x11,wayland\"");
    assert_eq!(
        display_lines(&r.rt(&["display", "dapp"]))[0],
        "graphics driver: custom: x11,wayland"
    );
    user_reg(&prefix, "\"Graphics\"=\"a\\x1b[31m\\x202ez\"");
    let o = r.rt(&["display", "dapp"]);
    assert_tame(&s(&o.stdout), "display output");
    assert_ok(&r.rt(&["display", "dapp", "x11"]));
    assert_eq!(display_lines(&r.rt(&["display", "dapp"]))[0], "graphics driver: x11");
}

#[test]
fn display_with_a_symlinked_or_hostile_user_reg_fails_or_says_auto_without_hanging() {
    let r = rig();
    let prefix = display_app(&r);
    fs::write(prefix.join("real.reg"), b"x").unwrap();
    symlink(prefix.join("real.reg"), prefix.join("user.reg")).unwrap();
    assert!(assert_fails(&r.rt(&["display", "dapp"])).contains("symlink"));
    fs::remove_file(prefix.join("user.reg")).unwrap();
    // a FIFO is not a regular file: Auto, and the open does not block
    let fifo = std::ffi::CString::new(prefix.join("user.reg").to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert_eq!(display_lines(&r.rt(&["display", "dapp"]))[0], "graphics driver: auto");
    fs::remove_file(prefix.join("user.reg")).unwrap();
    fs::write(
        prefix.join("user.reg"),
        [0xffu8, b'[', b'\\', 0, b'\n', b'"'].repeat(2000),
    )
    .unwrap();
    let o = r.rt(&["display", "dapp"]);
    assert!(o.status.code().is_some_and(|c| c <= 1), "{}", s(&o.stderr));
}

#[test]
fn display_set_is_refused_while_a_wineserver_runs_for_the_prefix_and_writes_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let r = rig();
    let prefix = display_app(&r);
    // A process named `wineserver` whose WINEPREFIX is the app's prefix (what `wineservers_for` looks for).
    let exe = r.root.join("fake-ws/wineserver");
    fs::create_dir_all(exe.parent().unwrap()).unwrap();
    fs::write(&exe, "#!/bin/sh\nread _\n").unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    let mut cmd = Command::new(&exe);
    cmd.env_clear()
        .env("WINEPREFIX", &prefix)
        .stdin(std::process::Stdio::piped());
    let mut server = (0..500)
        .find_map(|_| match cmd.spawn() {
            Err(e) if e.raw_os_error() == Some(26) => {
                std::thread::sleep(std::time::Duration::from_millis(4));
                None
            }
            x => Some(x.unwrap()),
        })
        .expect("spawn the fake wineserver");
    let o = r.rt(&["display", "dapp", "x11"]);
    let _ = server.kill();
    let _ = server.wait();
    let err = assert_fails(&o);
    assert!(
        err.contains("appears to be running") && err.contains("nothing was changed"),
        "{err}"
    );
    assert_eq!(o.status.code(), Some(1));
    assert!(!prefix.join("user.reg").exists() && !reg_ran(&r));
    // once it is gone the same command works
    assert_ok(&r.rt(&["display", "dapp", "x11"]));
}

/// The shared lock is what `runtime run` holds only while it starts an app; it keeps another runtime command's
/// exclusive lock out, but a live app is refused by the wineserver check (the test above).
#[test]
fn display_set_is_refused_while_another_runtime_command_holds_the_app_lock() {
    let r = rig();
    let prefix = display_app(&r);
    let store = rt_core::Store::new(r.apps()).unwrap();
    let env = store.get(&rt_core::AppId::parse("dapp").unwrap()).unwrap();
    let _running = rt_deps::lock_app_shared(&env).unwrap();
    let o = r.rt(&["display", "dapp", "x11"]);
    assert!(assert_fails(&o).contains("dapp"));
    assert!(!prefix.join("user.reg").exists() && !reg_ran(&r));
}

#[test]
fn display_rejects_bad_ids_unknown_apps_and_unknown_choices() {
    let r = rig();
    display_app(&r);
    for bad in ["../x", "/etc", "a/b", ".."] {
        let err = assert_fails(&r.rt(&["display", bad]));
        assert!(err.contains("not a valid app id"), "{err}");
        assert_fails(&r.rt(&["display", bad, "x11"]));
    }
    assert!(assert_fails(&r.rt(&["display", "nope"])).contains("no app named"));
    let o = r.rt(&["display", "dapp", "bogus"]);
    assert_eq!(o.status.code(), Some(2));
    let err = s(&o.stderr);
    assert!(
        err.contains("auto") && err.contains("x11") && err.contains("wayland"),
        "{err}"
    );
    assert!(!reg_ran(&r));
}

#[test]
fn display_set_is_refused_for_a_symlinked_user_reg_or_prefix() {
    let r = rig();
    let prefix = display_app(&r);
    let target = prefix.join("real.reg");
    fs::write(&target, b"untouched").unwrap();
    symlink(&target, prefix.join("user.reg")).unwrap();
    let err = assert_fails(&r.rt(&["display", "dapp", "x11"]));
    assert!(err.contains("symlink") && err.contains("nothing was changed"), "{err}");
    assert_eq!(fs::read(&target).unwrap(), b"untouched");
    assert!(!reg_ran(&r));
    // the prefix directory itself a symlink
    fs::remove_file(prefix.join("user.reg")).unwrap();
    let moved = prefix.with_file_name("prefix-real");
    fs::rename(&prefix, &moved).unwrap();
    symlink(&moved, &prefix).unwrap();
    assert_fails(&r.rt(&["display", "dapp", "x11"]));
    assert!(!reg_ran(&r) && !moved.join("user.reg").exists());
}

#[test]
fn doctor_of_an_app_checks_its_graphics_driver_setting_and_keeps_the_areas() {
    let r = rig();
    let prefix = display_app(&r);
    r.wine_dlls(&["kernel32.dll", "winepulse.drv"]);
    user_reg(&prefix, "\"Graphics\"=\"wayland\"");
    // wayland setting, no Wayland session: warned; the sections are unchanged
    let o = r.cmd().args(["doctor", "dapp"]).output().unwrap();
    let out = s(&o.stdout);
    assert!(lines_with(&out, "set to wayland")[0].contains("[warn]"), "{out}");
    let o = r.cmd().args(["doctor", "dapp", "--json"]).output().unwrap();
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let areas: Vec<&str> = j["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["area"].as_str().unwrap())
        .collect();
    assert!(areas.contains(&"graphics") && areas.contains(&"audio"), "{areas:?}");
    // a Wayland session, but this Wine has no winewayland.drv in a listed directory
    let out = s(&wayland(&r).args(["doctor", "dapp"]).output().unwrap().stdout);
    assert!(lines_with(&out, "winewayland")[0].contains("[warn]"), "{out}");
    r.wine_dlls(&["winewayland.drv"]);
    let out = s(&wayland(&r).args(["doctor", "dapp"]).output().unwrap().stdout);
    assert!(
        lines_with(&out, "Wine graphics driver: wayland")[0].contains("[ok]"),
        "{out}"
    );
    // an unreadable user.reg (a symlink) is reported, not dropped
    fs::remove_file(prefix.join("user.reg")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", prefix.join("user.reg")).unwrap();
    let out = s(&r.cmd().args(["doctor", "dapp"]).output().unwrap().stdout);
    assert!(
        lines_with(&out, "graphics driver setting not verified")[0].contains("[warn]"),
        "{out}"
    );
}

// ================================================================ permissions

/// An app `papp` and a `$HOME` (`home/`, with a `.ssh` and an ordinary `share/` directory) for `HOME`.
fn perm_app(r: &Rig) -> (PathBuf, PathBuf) {
    let app = r.plant("papp", "P");
    let home = r.grants.path().canonicalize().unwrap().join("home");
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::create_dir_all(home.join("share")).unwrap();
    (app, home)
}

fn perm(r: &Rig, home: &Path, args: &[&str]) -> Output {
    r.cmd()
        .env("HOME", home)
        .arg("permissions")
        .args(args)
        .output()
        .unwrap()
}

/// A process named `wineserver` for `prefix` (what `wineservers_for` looks for); kill it when done.
fn fake_wineserver(r: &Rig, prefix: &Path) -> std::process::Child {
    use std::os::unix::fs::PermissionsExt;
    let exe = r.root.join("fake-ws/wineserver");
    fs::create_dir_all(exe.parent().unwrap()).unwrap();
    fs::write(&exe, "#!/bin/sh\nread _\n").unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    let mut cmd = Command::new(&exe);
    cmd.env_clear().env("WINEPREFIX", prefix).stdin(Stdio::piped());
    (0..500)
        .find_map(|_| match cmd.spawn() {
            Err(e) if e.raw_os_error() == Some(26) => {
                std::thread::sleep(std::time::Duration::from_millis(4));
                None
            }
            x => Some(x.unwrap()),
        })
        .expect("spawn the fake wineserver")
}

#[test]
fn permissions_shows_the_default_and_where_it_came_from() {
    let r = rig();
    let (app, home) = perm_app(&r);
    let o = perm(&r, &home, &["papp"]);
    assert_ok(&o);
    let out = s(&o.stdout);
    assert!(
        out.starts_with("version = 1\nnetwork = \"deny\"\ndisplay = true\naudio = true\ngpu = true\n"),
        "{out}"
    );
    assert!(out.ends_with("source: default\n"), "{out}");
    assert!(!app.join("permissions.toml").exists());
}

#[test]
fn permissions_set_writes_once_and_shows_the_result() {
    use std::os::unix::fs::PermissionsExt;
    let r = rig();
    let (app, home) = perm_app(&r);
    let share = home.join("share");
    let o = perm(
        &r,
        &home,
        &[
            "papp",
            "--set",
            "network=allow",
            "--set",
            "gpu=off",
            "--set",
            &format!("fs+={}:rw", share.display()),
        ],
    );
    assert_ok(&o);
    let out = s(&o.stdout);
    assert!(
        out.contains("network = \"allow\"") && out.contains("gpu = false") && out.contains("access = \"rw\""),
        "{out}"
    );
    assert!(out.ends_with("source: permissions.toml\n"), "{out}");
    let file = app.join("permissions.toml");
    assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o7777, 0o600);
    let shown = s(&perm(&r, &home, &["papp"]).stdout);
    assert_eq!(shown, out);
    // removal, and only the app root holds the file (no temp file left)
    assert_ok(&perm(
        &r,
        &home,
        &["papp", "--set", &format!("fs-={}", share.display())],
    ));
    assert!(!fs::read_to_string(&file).unwrap().contains("filesystem"));
    assert!(
        fs::read_dir(&app)
            .unwrap()
            .all(|e| !e.unwrap().file_name().to_string_lossy().contains(".tmp-"))
    );
}

#[test]
fn permissions_set_with_a_bad_expression_or_grant_refuses_all_and_writes_nothing() {
    let r = rig();
    let (app, home) = perm_app(&r);
    for bad in ["net=allow", "fs+=rel:ro", "fs+=/x:rx", "network=maybe"] {
        let o = perm(&r, &home, &["papp", "--set", "gpu=off", "--set", bad]);
        let err = assert_fails(&o);
        assert!(err.contains("nothing was changed"), "{bad}: {err}");
        assert!(!app.join("permissions.toml").exists(), "{bad}");
    }
    let err = assert_fails(&perm(&r, &home, &["papp", "--set", "net=allow"]));
    assert!(err.contains("network=allow|deny") && err.contains("fs+="), "{err}");
    // secrets, $HOME, `/`, and the runtime's data directory are never granted
    for (dir, why) in [
        (home.join(".ssh"), "~/.ssh"),
        (home.clone(), "home directory"),
        (PathBuf::from("/"), "`/`"),
        (r.data.clone(), "data directory"),
        (r.data.join("apps/papp/prefix"), "data directory"),
    ] {
        let err = assert_fails(&perm(
            &r,
            &home,
            &["papp", "--set", &format!("fs+={}:ro", dir.display())],
        ));
        assert!(
            err.contains(why) && err.contains("nothing was changed"),
            "{dir:?}: {err}"
        );
        assert!(!app.join("permissions.toml").exists(), "{dir:?}");
    }
    assert!(
        !fs::read_dir(&app)
            .unwrap()
            .any(|e| e.unwrap().file_name().to_string_lossy().contains("permissions"))
    );
}

#[test]
fn permissions_set_is_refused_while_a_wineserver_runs_and_reset_too() {
    let r = rig();
    let (app, home) = perm_app(&r);
    assert_ok(&perm(&r, &home, &["papp", "--set", "gpu=off"]));
    let before = fs::read_to_string(app.join("permissions.toml")).unwrap();
    let mut server = fake_wineserver(&r, &app.join("prefix"));
    let set = perm(&r, &home, &["papp", "--set", "network=allow"]);
    let reset = perm(&r, &home, &["papp", "--reset"]);
    let _ = server.kill();
    let _ = server.wait();
    for o in [&set, &reset] {
        let err = assert_fails(o);
        assert!(
            err.contains("appears to be running") && err.contains("nothing was changed"),
            "{err}"
        );
    }
    assert_eq!(fs::read_to_string(app.join("permissions.toml")).unwrap(), before);
    // reading is fine meanwhile, and once it is gone the change works
    assert_ok(&perm(&r, &home, &["papp", "--set", "network=allow"]));
}

#[test]
fn permissions_set_is_refused_while_another_runtime_command_holds_the_app_lock() {
    let r = rig();
    let (app, home) = perm_app(&r);
    let store = rt_core::Store::new(r.apps()).unwrap();
    let env = store.get(&rt_core::AppId::parse("papp").unwrap()).unwrap();
    let _running = rt_deps::lock_app_shared(&env).unwrap();
    assert!(assert_fails(&perm(&r, &home, &["papp", "--set", "gpu=off"])).contains("papp"));
    assert!(!app.join("permissions.toml").exists());
}

#[test]
fn permissions_reset_deletes_the_file_and_json_parses_back() {
    let r = rig();
    let (app, home) = perm_app(&r);
    let share = home.join("share");
    assert_ok(&perm(
        &r,
        &home,
        &[
            "papp",
            "--set",
            "audio=off",
            "--set",
            &format!("fs+={}:ro", share.display()),
        ],
    ));
    let o = perm(&r, &home, &["papp", "--json"]);
    assert_ok(&o);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["network"], "deny");
    assert_eq!(
        (v["display"].as_bool(), v["audio"].as_bool(), v["gpu"].as_bool()),
        (Some(true), Some(false), Some(true))
    );
    assert_eq!(v["filesystem"][0]["path"], share.to_str().unwrap());
    assert_eq!(v["filesystem"][0]["access"], "ro");
    assert_ok(&perm(&r, &home, &["papp", "--reset"]));
    assert!(!app.join("permissions.toml").exists());
    let v: serde_json::Value = serde_json::from_slice(&perm(&r, &home, &["papp", "--json"]).stdout).unwrap();
    assert_eq!(v["filesystem"], serde_json::json!([]));
    assert_ok(&perm(&r, &home, &["papp", "--reset"])); // no file: fine
    assert!(assert_fails(&perm(&r, &home, &["papp", "--reset", "--set", "gpu=off"])).contains("cannot be combined"));
}

#[test]
fn permissions_refuses_a_symlinked_or_oversized_file_and_writes_nothing() {
    let r = rig();
    let (app, home) = perm_app(&r);
    let victim = r.root.join("victim");
    fs::write(&victim, "keep").unwrap();
    let f = app.join("permissions.toml");
    std::os::unix::fs::symlink(&victim, &f).unwrap();
    for args in [vec!["papp"], vec!["papp", "--set", "gpu=off"]] {
        let err = assert_fails(&perm(&r, &home, &args));
        assert!(err.contains("not a plain file"), "{err}");
    }
    assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
    fs::remove_file(&f).unwrap();
    let big = format!("version = 1\n#{}\n", "x".repeat(1 << 20));
    fs::write(&f, &big).unwrap();
    let err = assert_fails(&perm(&r, &home, &["papp", "--set", "gpu=off"]));
    assert!(err.contains("larger than"), "{err}");
    assert_eq!(fs::read_to_string(&f).unwrap(), big);
    // a hostile file's text is escaped on the way out
    fs::write(&f, "version = 1\nnetwork = \"\\u001b[2J\"\n").unwrap();
    let o = perm(&r, &home, &["papp"]);
    assert!(!o.stderr.contains(&0x1b) && !o.stdout.contains(&0x1b));
    assert_fails(&o);
}

#[test]
fn permissions_rejects_bad_ids_and_unknown_apps() {
    let r = rig();
    let (_, home) = perm_app(&r);
    for bad in ["../x", "/etc", "a/b", ".."] {
        let err = assert_fails(&perm(&r, &home, &[bad]));
        assert!(err.contains("not a valid app id"), "{err}");
        assert_fails(&perm(&r, &home, &[bad, "--set", "gpu=off"]));
    }
    assert!(assert_fails(&perm(&r, &home, &["nope"])).contains("no app named"));
    // without an absolute HOME nothing can be judged
    let o = r
        .cmd()
        .env("HOME", "relative")
        .args(["permissions", "papp"])
        .output()
        .unwrap();
    assert!(assert_fails(&o).contains("HOME"));
}

#[test]
fn permissions_refuses_sockets_files_daemon_dirs_and_rw_system_trees() {
    let r = rig();
    let (app, home) = perm_app(&r);
    // (a socket path must fit `sun_path`; under /tmp it is refused for where it is)
    let short = tempfile::tempdir_in("/tmp").unwrap();
    let sock = short.path().join("agent.sock");
    let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    fs::write(home.join(".bashrc"), "x").unwrap();
    // The refusal's own wording (a grant path is echoed in the message too, so its text alone proves nothing).
    let tmp = "/tmp holds other programs' sockets and cannot be granted";
    let run = "/run holds device nodes and runtime sockets";
    for (grant, why) in [
        (format!("{}:rw", sock.display()), tmp),
        (format!("{}:ro", short.path().display()), tmp),
        (
            format!("{}:rw", home.join(".bashrc").display()),
            "it is not a directory",
        ),
        ("/run/docker.sock:rw".into(), run),
        ("/run/dbus:ro".into(), run),
        // `/tmp` itself contains this rig's data directory (a /tmp tempdir), which is checked first; the
        // `/tmp` rule for `/tmp` itself is unit-tested in `rt_sandbox::permissions`.
        (
            "/tmp:ro".into(),
            "it is, contains or is inside the runtime's data directory",
        ),
        ("/tmp/.X11-unix:ro".into(), tmp),
        ("/etc:rw".into(), "never writable"),
        ("/usr/local:rw".into(), "never writable"),
    ] {
        let err = assert_fails(&perm(&r, &home, &["papp", "--set", &format!("fs+={grant}")]));
        assert!(
            err.contains(why) && err.contains("nothing was changed"),
            "{grant}: {err}"
        );
        assert!(!app.join("permissions.toml").exists(), "{grant}");
    }
    // the account's real home counts even if HOME points elsewhere
    if let Some(real) = rt_sandbox::account_home().filter(|h| h.join(".ssh").is_dir()) {
        let o = perm(
            &r,
            &home,
            &["papp", "--set", &format!("fs+={}:ro", real.join(".ssh").display())],
        );
        assert!(assert_fails(&o).contains("~/.ssh"));
    }
}

#[test]
fn permissions_can_remove_a_grant_whose_directory_is_gone() {
    let r = rig();
    let (app, home) = perm_app(&r);
    let gone = home.join("gone");
    fs::create_dir(&gone).unwrap();
    assert_ok(&perm(
        &r,
        &home,
        &["papp", "--set", &format!("fs+={}:rw", gone.display())],
    ));
    fs::remove_dir(&gone).unwrap();
    // reading refuses, and says how to get out
    let err = assert_fails(&perm(&r, &home, &["papp"]));
    assert!(err.contains("does not exist") && err.contains("--reset"), "{err}");
    assert_ok(&perm(&r, &home, &["papp", "--set", &format!("fs-={}", gone.display())]));
    assert!(
        !fs::read_to_string(app.join("permissions.toml"))
            .unwrap()
            .contains("filesystem")
    );
    assert_ok(&perm(&r, &home, &["papp"]));
}

// ================================================================ sandbox

/// A `bwrap` in the rig's `bin/` that records its arguments (one call per line in `log/bwrap.txt`) and then runs
/// what follows `--` UNSANDBOXED (the fake Wine could not run in a real sandbox), or exits 0 (the probe).
/// Logs its arguments and runs the program after `--` without any sandbox. The `sandbox-init` shim is skipped too
/// (to its own `--`): its Landlock rules name paths as they are INSIDE a real sandbox (`/lib` is a bind there, a
/// symlink on a merged-/usr host), so it cannot run on the host; the real-bwrap tests run it.
fn fake_bwrap(r: &Rig) {
    let body = "echo \"$*\" >> @LOG@/bwrap.txt\nwhile [ $# -gt 0 ] && [ \"$1\" != -- ]; do shift; done\n\
                [ $# -gt 0 ] || exit 0\nshift\n\
                if [ \"$2\" = sandbox-init ]; then while [ $# -gt 0 ] && [ \"$1\" != -- ]; do shift; done; shift; fi\nexec \"$@\""
        .replace("@LOG@", r.log.to_str().unwrap());
    script(&r.bin.join("bwrap"), &body);
}

/// The `runtime` under test, as the sandbox names it (its shim).
fn runtime_exe() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_runtime")).canonicalize().unwrap()
}

fn systemd_run_calls(r: &Rig) -> Vec<String> {
    fs::read_to_string(r.log.join("systemd-run.txt"))
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect()
}

/// `systemd-run` fails like it does without a user manager.
fn no_user_manager(r: &Rig) {
    script(
        &r.bin.join("systemd-run"),
        "echo 'Failed to connect to user scope bus via local transport: No such file or directory' >&2; exit 1",
    );
}

fn bwrap_calls(r: &Rig) -> Vec<String> {
    fs::read_to_string(r.log.join("bwrap.txt"))
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect()
}

/// `r.cmd()` with only the rig's `bin/` on PATH: no real `bwrap` (the fake scripts need nothing else to refuse).
fn no_bwrap(r: &Rig) -> Command {
    let mut c = r.cmd();
    c.env("PATH", &r.bin);
    c
}

const NO_BWRAP: &str = "error: cannot start the sandbox: bwrap is not on PATH. Install bubblewrap (`sudo apt install \
                        bubblewrap`) or rerun with --unsandboxed (NOT sandboxed)";

#[test]
fn run_without_bwrap_refuses_before_anything_starts_or_is_installed() {
    let r = rig();
    let id = r.install();
    let before = r.calls();
    let o = no_bwrap(&r).args(["run", &id]).output().unwrap();
    assert_eq!(assert_fails(&o).trim_end(), NO_BWRAP);
    assert_eq!(r.calls(), before, "nothing ran");
    // A file is not even installed.
    let p = r.input("other.exe", &fs::read(fixture("hello64.exe")).unwrap());
    let o = no_bwrap(&r).args(["run".as_ref(), p.as_os_str()]).output().unwrap();
    assert_eq!(assert_fails(&o).trim_end(), NO_BWRAP);
    assert_eq!(r.app_dirs(), [id]);
}

#[test]
fn permissions_set_limits_writes_them_and_json_shows_default_and_explicit() {
    let r = rig();
    let (app, home) = perm_app(&r);
    let v: serde_json::Value = serde_json::from_slice(&perm(&r, &home, &["papp", "--json"]).stdout).unwrap();
    assert_eq!(
        v["limits"],
        serde_json::json!({"memory_mb": null, "cpu_percent": null, "tasks": 4096, "tasks_default": true})
    );
    let o = perm(
        &r,
        &home,
        &["papp", "--set", "memory=2048", "--set", "cpu=100", "--set", "tasks=512"],
    );
    assert_ok(&o);
    assert!(
        s(&o.stdout).contains("\n[limits]\nmemory_mb = 2048\ncpu_percent = 100\ntasks = 512\n"),
        "{}",
        s(&o.stdout)
    );
    let v: serde_json::Value = serde_json::from_slice(&perm(&r, &home, &["papp", "--json"]).stdout).unwrap();
    assert_eq!(
        v["limits"],
        serde_json::json!({"memory_mb": 2048, "cpu_percent": 100, "tasks": 512, "tasks_default": false})
    );
    assert_ok(&perm(
        &r,
        &home,
        &["papp", "--set", "tasks=unlimited", "--set", "cpu=off"],
    ));
    let v: serde_json::Value = serde_json::from_slice(&perm(&r, &home, &["papp", "--json"]).stdout).unwrap();
    assert_eq!(
        v["limits"],
        serde_json::json!({"memory_mb": 2048, "cpu_percent": null, "tasks": "unlimited", "tasks_default": false})
    );
    // out of range or malformed: refused as a whole, the file untouched
    let file = app.join("permissions.toml");
    let before = fs::read_to_string(&file).unwrap();
    for (bad, why) in [
        ("memory=10", "64..=1048576 MiB"),
        ("tasks=8", "16..=65536"),
        ("cpu=0", "percent"),
        ("tasks=off", "tasks=<n>|unlimited|default"),
    ] {
        let err = assert_fails(&perm(&r, &home, &["papp", "--set", "gpu=off", "--set", bad]));
        assert!(err.contains(why) && err.contains("nothing was changed"), "{bad}: {err}");
        assert_eq!(fs::read_to_string(&file).unwrap(), before, "{bad}");
    }
    assert_ok(&perm(
        &r,
        &home,
        &["papp", "--set", "tasks=default", "--set", "memory=off"],
    ));
    assert!(!fs::read_to_string(&file).unwrap().contains("limits"));
}

#[test]
fn a_sandboxed_run_starts_bwrap_in_a_scope_with_the_apps_limits() {
    let r = rig();
    let id = r.install();
    fake_bwrap(&r);
    r.hook("exit 6");
    let o = r.rt(&["run", &id]);
    assert_eq!(
        o.status.code(),
        Some(6),
        "the program's status through the scope: {}",
        s(&o.stderr)
    );
    assert_eq!(s(&o.stderr), "");
    let bwrap = r.bin.join("bwrap");
    let calls = systemd_run_calls(&r);
    assert_eq!(calls.len(), 2, "the probe, then the run: {calls:?}");
    let scope = "--user --scope --collect --quiet --expand-environment=no";
    assert!(
        calls[0].starts_with(&format!("{scope} -p TasksMax=100 -- /bin/sh -c ")),
        "{calls:?}"
    );
    assert!(
        calls[1].starts_with(&format!(
            "{scope} -p TasksMax=4096 -- {} --die-with-parent ",
            bwrap.display()
        )),
        "{calls:?}"
    );
    let home = r.grants.path().canonicalize().unwrap();
    let set = r
        .cmd()
        .env("HOME", &home)
        .args([
            "permissions",
            &id,
            "--set",
            "memory=128",
            "--set",
            "tasks=64",
            "--set",
            "cpu=50",
        ])
        .output()
        .unwrap();
    assert_ok(&set);
    let o = r.cmd().env("HOME", &home).args(["run", &id]).output().unwrap();
    assert_eq!(o.status.code(), Some(6));
    let calls = systemd_run_calls(&r);
    assert!(
        calls[3].starts_with(&format!(
            "{scope} -p TasksMax=64 -p MemoryMax=128M -p MemorySwapMax=0 -p CPUQuota=50% -- {} ",
            bwrap.display()
        )),
        "{calls:?}"
    );
    assert_eq!(bwrap_calls(&r).len(), 4, "two probes, two runs");
}

#[test]
fn a_143_under_a_memory_limit_points_at_the_journal() {
    let r = rig();
    let id = r.install();
    fake_bwrap(&r);
    r.hook("exit 143");
    let note = "note: the program was terminated (exit 143); if it exceeded its memory limit see `journalctl --user -u \
                'run-p*.scope'`\n";
    let o = r.rt(&["run", &id]);
    assert_eq!(o.status.code(), Some(143));
    assert_eq!(s(&o.stderr), "", "no memory limit: no note");
    let home = r.grants.path().canonicalize().unwrap();
    let run = || r.cmd().env("HOME", &home).args(["run", &id]).output().unwrap();
    let set = |e: &str| {
        let o = r
            .cmd()
            .env("HOME", &home)
            .args(["permissions", &id, "--set", e])
            .output()
            .unwrap();
        assert_ok(&o);
    };
    set("memory=128");
    let o = run();
    assert_eq!(o.status.code(), Some(143));
    assert_eq!(s(&o.stderr), note);
    r.hook("exit 3");
    let o = run();
    assert_eq!(
        (o.status.code(), s(&o.stderr)),
        (Some(3), String::new()),
        "another status: no note"
    );
}

#[test]
fn explicit_limits_refuse_the_run_without_a_user_manager_and_the_default_degrades_with_a_note() {
    let r = rig();
    let id = r.install();
    fake_bwrap(&r);
    no_user_manager(&r);
    let o = r.rt(&["run", &id]);
    assert_ok(&o);
    assert_eq!(
        s(&o.stderr),
        "note: resource limits unavailable: systemd-run --user --scope failed (Failed to connect to user scope bus \
         via local transport: No such file or directory); the default task limit (4096) is not applied\n"
    );
    assert!(bwrap_calls(&r)[1].starts_with("--die-with-parent "), "no scope");
    let home = r.grants.path().canonicalize().unwrap();
    let set = |e: &str| {
        r.cmd()
            .env("HOME", &home)
            .args(["permissions", &id, "--set", e])
            .output()
            .unwrap()
    };
    // an explicit value, even the default one, is a request: no scope, no run
    for e in ["tasks=4096", "memory=512"] {
        assert_ok(&set(e));
        let before = (r.calls(), bwrap_calls(&r).len());
        let o = r.cmd().env("HOME", &home).args(["run", &id]).output().unwrap();
        let err = assert_fails(&o);
        assert!(
            err.contains("sets resource limits, but they cannot be applied: systemd-run --user --scope failed")
                && err.contains(&format!(
                    "runtime permissions {id} --set memory=off --set cpu=off --set tasks=default"
                )),
            "{err}"
        );
        assert_eq!(
            (r.calls(), bwrap_calls(&r).len()),
            (before.0, before.1 + 1),
            "only the bwrap probe ran"
        );
    }
    // no systemd-run at all
    fs::remove_file(r.bin.join("systemd-run")).unwrap();
    let o = r
        .cmd()
        .env("HOME", &home)
        .env("PATH", &r.bin)
        .args(["run", &id])
        .output()
        .unwrap();
    assert!(
        assert_fails(&o).contains("cannot be applied: systemd-run is not on PATH"),
        "{}",
        s(&o.stderr)
    );
}

#[test]
fn sandbox_shows_the_limits_and_the_systemd_run_command_line() {
    let r = rig();
    let id = r.install();
    let out = s(&r.rt(&["sandbox", &id]).stdout);
    let sr = r.bin.join("systemd-run");
    for want in [
        format!(
            "limits: systemd-run --user works ({}; cgroup controllers: cpu io memory pids)\n",
            sr.display()
        ),
        "  tasks: 4096 (default, best effort)\n  memory: no limit\n  cpu: no limit\n".to_owned(),
    ] {
        assert!(out.contains(&want), "{want:?} in {out}");
    }
    let line = lines_with(&out, "command: ")[0];
    assert!(
        line.starts_with(&format!(
            "command: '{}' '--user' '--scope' '--collect' '--quiet' '--expand-environment=no' '-p' 'TasksMax=4096' \
             '--' '",
            sr.display()
        )),
        "{line}"
    );
    let home = r.grants.path().canonicalize().unwrap();
    let set = r
        .cmd()
        .env("HOME", &home)
        .args(["permissions", &id, "--set", "memory=256", "--set", "tasks=unlimited"])
        .output()
        .unwrap();
    assert_ok(&set);
    let out = s(&r
        .cmd()
        .env("HOME", &home)
        .args(["sandbox", &id])
        .output()
        .unwrap()
        .stdout);
    assert!(
        out.contains(
            "  tasks: no limit (permissions.toml)\n  memory: 256 MiB, no swap (permissions.toml, mandatory)\n"
        ),
        "{out}"
    );
    no_user_manager(&r);
    let out = s(&r
        .cmd()
        .env("HOME", &home)
        .args(["sandbox", &id])
        .output()
        .unwrap()
        .stdout);
    assert!(
        out.contains("limits: UNAVAILABLE: systemd-run --user --scope failed (Failed to connect"),
        "{out}"
    );
    assert!(
        out.contains("REFUSED: the app's permissions.toml sets resource limits"),
        "{out}"
    );
    assert_tame(&out, "stdout");
}

#[test]
fn doctor_reports_whether_limits_can_be_applied() {
    let r = rig();
    let id = r.install();
    let out = s(&r.rt(&["doctor", &id]).stdout);
    let line = lines_with(&out, "limits: ")[0];
    assert!(
        line.contains("[ok]")
            && line.contains("limits: systemd-run --user available (cgroup controllers: cpu io memory pids)"),
        "{out}"
    );
    no_user_manager(&r);
    let out = s(&r.rt(&["doctor", &id]).stdout);
    let line = lines_with(&out, "limits: ")[0];
    assert!(
        line.contains("[warn]")
            && line.contains("limits: unavailable: systemd-run --user --scope failed")
            && line.contains("the default task limit (fork-bomb guard) is not applied"),
        "{out}"
    );
    let home = r.grants.path().canonicalize().unwrap();
    fs::write(
        r.apps().join(&id).join("permissions.toml"),
        "version = 1\n[limits]\nmemory_mb = 512\n",
    )
    .unwrap();
    let out = s(&r
        .cmd()
        .env("HOME", &home)
        .args(["doctor", &id])
        .output()
        .unwrap()
        .stdout);
    let line = lines_with(&out, "limits: ")[0];
    assert!(
        line.contains("[warn]") && line.contains(&format!("runs of {id} will be refused")),
        "{out}"
    );
    // scopes work, but not the controller this app's limit needs: not "available"
    script(
        &r.bin.join("systemd-run"),
        &FAKE_SYSTEMD_RUN
            .replace("cpu io memory pids", "cpu io pids")
            .replace("@LOG@", r.log.to_str().unwrap()),
    );
    let out = s(&r
        .cmd()
        .env("HOME", &home)
        .args(["doctor", &id])
        .output()
        .unwrap()
        .stdout);
    let line = lines_with(&out, "limits: ")[0];
    assert!(
        line.contains("[warn]")
            && line.contains(&format!(
                "limits: systemd-run --user available, but runs of {id} will be refused: the memory cgroup \
                 controller is not available to your user session"
            )),
        "{out}"
    );
}

#[test]
fn run_refuses_when_bwrap_cannot_create_a_sandbox() {
    let r = rig();
    let id = r.install();
    script(
        &r.bin.join("bwrap"),
        "echo 'bwrap: No permissions to create new namespace, likely because the kernel does not allow' >&2; exit 1",
    );
    let before = r.calls();
    let err = assert_fails(&r.rt(&["run", &id]));
    assert!(
        err.starts_with("error: cannot start the sandbox: user namespaces are disabled or restricted on this host")
            && err.contains(
                "Install bubblewrap (`sudo apt install bubblewrap`) or rerun with --unsandboxed (NOT sandboxed)"
            ),
        "{err}"
    );
    assert_eq!(r.calls(), before, "nothing ran");
}

#[test]
fn a_sandboxed_run_starts_the_settled_program_in_bwrap_and_marks_the_app() {
    let r = rig();
    let id = r.install();
    fake_bwrap(&r);
    r.hook("exit 6");
    let root = r.apps().join(&id);
    assert!(!root.join("ran-sandboxed").exists());
    let o = r.rt(&["run", &id, "--", "arg one"]);
    assert_eq!(o.status.code(), Some(6), "stderr: {}", s(&o.stderr));
    assert_eq!(s(&o.stdout), "app-stdout\n");
    assert_eq!(
        s(&o.stderr),
        "",
        "no DISPLAY and no network: nothing the profile cannot enforce"
    );
    let calls = bwrap_calls(&r);
    assert_eq!(calls.len(), 2, "the probe, then the program: {calls:?}");
    assert!(calls[0].starts_with("--unshare-all "), "{calls:?}");
    let prefix = root.join("prefix");
    let home = root.join("runtime/home");
    let run = &calls[1];
    for want in [
        "--die-with-parent --new-session --unshare-pid --unshare-uts --unshare-ipc --unshare-net ".to_owned(),
        format!(
            " --bind {0} {0} --bind {1} {1} --remount-ro / -- {2} sandbox-init --v1 --rule ",
            prefix.display(),
            home.display(),
            runtime_exe().display()
        ),
        format!(
            " --rule rw:{} --rule rw:{} -- /bin/sh -c ",
            prefix.display(),
            home.display()
        ),
        format!(
            " {} {} ",
            r.bin.join("wineserver").display(),
            r.bin.join("wine").display()
        ),
    ] {
        assert!(run.contains(&want), "{want:?} in {run}");
    }
    assert!(run.ends_with("hello64.exe arg one"), "{run}");
    // Only the prefix and the app's home are bound: never the app root (permissions.toml, the marker).
    let root_text = root.display().to_string();
    assert!(
        !run.split(' ').any(|a| a == root_text || a == format!("{root_text}/")),
        "{run}"
    );
    // The program's argv is exact, the registry was settled (`wineserver -w`) and the app is marked.
    assert_eq!(r.argv()[1], b"arg one");
    assert!(
        r.calls().iter().any(|c| c.starts_with("wineserver -w ")),
        "{:?}",
        r.calls()
    );
    assert!(root.join("ran-sandboxed").is_file());
}

#[test]
fn a_sandboxed_run_prints_what_the_profile_cannot_enforce() {
    let r = rig();
    let id = r.install();
    fake_bwrap(&r);
    let home = r.grants.path().canonicalize().unwrap();
    let set = r
        .cmd()
        .env("HOME", &home)
        .args(["permissions", &id, "--set", "network=allow", "--set", "display=off"])
        .output()
        .unwrap();
    assert_ok(&set);
    let o = r.cmd().env("HOME", &home).args(["run", &id]).output().unwrap();
    assert_ok(&o);
    let err = s(&o.stderr);
    let notes: Vec<&str> = err.lines().collect();
    assert_eq!(notes.len(), 2, "{err}");
    assert!(
        notes[0].starts_with("note: network=allow shares the host network namespace"),
        "{err}"
    );
    assert!(
        notes[1].starts_with("note: display=off cannot be enforced with network=allow"),
        "{err}"
    );
    assert!(!bwrap_calls(&r)[1].contains("--unshare-net"));
}

#[test]
fn a_profile_that_is_refused_stops_the_run() {
    let r = rig();
    let id = r.install();
    fake_bwrap(&r);
    fs::write(r.apps().join(&id).join("permissions.toml"), "version = 1\nbogus = 1\n").unwrap();
    let before = r.calls();
    let err = assert_fails(&r.rt(&["run", &id]));
    assert!(
        err.starts_with("error: cannot start the sandbox: the app's permissions.toml is refused")
            && err.contains(&format!("runtime permissions {id} --reset")),
        "{err}"
    );
    assert_eq!(r.calls(), before);
    assert_eq!(bwrap_calls(&r).len(), 1, "only the probe ran");
}

#[test]
fn sandbox_prints_the_profile_and_the_bwrap_command_line_without_running_anything() {
    let r = rig();
    let id = r.install();
    let before = r.calls();
    let o = r.rt(&["sandbox", &id]);
    assert_ok(&o);
    let out = s(&o.stdout);
    assert!(
        out.contains("profile (default): network deny, display on, audio on, gpu on, 0 host directories"),
        "{out}"
    );
    assert!(
        out.contains("skipped: display: neither DISPLAY nor WAYLAND_DISPLAY is set"),
        "{out}"
    );
    assert!(
        out.contains(&format!("warning: `runtime run --unsandboxed {id}` would run")),
        "{out}"
    );
    let line = lines_with(&out, "command: ")[0];
    let root = r.apps().join(&id);
    let prefix = root.join("prefix");
    assert!(line.contains(" '--unshare-net' "), "{line}");
    assert!(
        line.contains(&format!(" '--bind' '{0}' '{0}' ", prefix.display())),
        "{line}"
    );
    assert!(
        !line.contains(&format!("'{}'", root.display())),
        "never the app root: {line}"
    );
    assert!(line.ends_with("hello64.exe'"), "{line}");
    assert_eq!(r.calls(), before, "no Wine process");
    assert_tame(&out, "stdout");

    // network=allow: no --unshare-net, and the caveat is shown.
    let home = r.grants.path().canonicalize().unwrap();
    let set = r
        .cmd()
        .env("HOME", &home)
        .args(["permissions", &id, "--set", "network=allow"])
        .output()
        .unwrap();
    assert_ok(&set);
    let out = s(&r
        .cmd()
        .env("HOME", &home)
        .args(["sandbox", &id])
        .output()
        .unwrap()
        .stdout);
    assert!(out.contains("profile (permissions.toml): network allow"), "{out}");
    assert!(
        out.contains("note: network=allow shares the host network namespace"),
        "{out}"
    );
    assert!(!lines_with(&out, "command: ")[0].contains("--unshare-net"), "{out}");
    // No bwrap: still exit 0, and says so.
    let o = no_bwrap(&r).env("HOME", &home).args(["sandbox", &id]).output().unwrap();
    assert_ok(&o);
    assert!(
        s(&o.stdout).starts_with("bubblewrap: UNAVAILABLE: bwrap is not on PATH"),
        "{}",
        s(&o.stdout)
    );
}

#[test]
fn doctor_reports_the_sandbox_for_the_system_and_summarises_an_apps_profile() {
    let r = rig();
    let id = r.install();
    let o = no_bwrap(&r).args(["doctor", &id]).output().unwrap();
    let out = s(&o.stdout);
    let line = lines_with(&out, "sandbox")[0];
    assert!(
        line.contains("[warn]") && line.contains("bwrap is not on PATH"),
        "{out}"
    );
    let v = json(&no_bwrap(&r).args(["doctor", "--json"]).output().unwrap());
    let check = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["text"].as_str().unwrap().contains("sandbox"))
        .unwrap();
    assert_eq!(
        (check["area"].as_str(), check["status"].as_str()),
        (Some("runtime"), Some("warn"))
    );
    assert!(
        check["text"]
            .as_str()
            .unwrap()
            .starts_with("sandbox: unavailable: bwrap is not on PATH"),
        "{check}"
    );
    fake_bwrap(&r);
    // A profile that needs HOME to be checked, without HOME (the rig's environment is cleared): the real reason.
    fs::write(r.apps().join(&id).join("permissions.toml"), "version = 1\n").unwrap();
    let out = s(&r.rt(&["doctor", &id]).stdout);
    let line = lines_with(&out, "sandbox")[0];
    assert!(
        line.contains("[warn]") && line.contains("sandbox: cannot read the profile: HOME is not set"),
        "{out}"
    );
    fs::remove_file(r.apps().join(&id).join("permissions.toml")).unwrap();
    let out = s(&r.rt(&["doctor"]).stdout);
    let line = lines_with(&out, "sandbox")[0];
    assert!(line.contains("[ok]") && line.contains("bubblewrap works"), "{out}");
    let out = s(&r.rt(&["doctor", &id]).stdout);
    let line = lines_with(&out, "sandbox")[0];
    assert!(
        line.contains("[ok]")
            && line.ends_with("profile: network deny, display on, audio on, gpu on, 0 host directories"),
        "{out}"
    );
}

#[test]
fn once_an_app_ran_sandboxed_its_registry_helpers_run_in_its_sandbox() {
    let r = rig();
    let prefix = display_app(&r);
    let id = "dapp";
    // Never sandboxed: `display` runs reg.exe like any Wine helper.
    assert_ok(&r.rt(&["display", id, "x11"]));
    assert!(r.calls().iter().any(|c| c == "wine <app>"), "{:?}", r.calls());
    assert!(prefix.join("user.reg").exists());
    fs::write(prefix.parent().unwrap().join("ran-sandboxed"), "").unwrap();
    // Sandboxed before, and no bwrap: refused, nothing ran.
    let before = r.calls();
    let err = assert_fails(&no_bwrap(&r).args(["display", id, "auto"]).output().unwrap());
    assert!(
        err.contains(&format!("{id} has run in the sandbox"))
            && err.contains("its Wine helpers must run sandboxed too")
            && err.contains("nothing was changed"),
        "{err}"
    );
    assert_eq!(r.calls(), before);
    // With bwrap: reg.exe goes through it (the fake runs it after recording the profile).
    fake_bwrap(&r);
    assert_ok(&r.rt(&["display", id, "auto"]));
    let calls = bwrap_calls(&r);
    let reg = calls
        .iter()
        .find(|c| c.contains("reg.exe"))
        .unwrap_or_else(|| panic!("{calls:?}"));
    assert!(reg.contains("--unshare-net") && reg.contains(" delete "), "{reg}");
    // Something else at the marker's path (the runtime only ever writes a file) still counts as marked.
    let marker = prefix.parent().unwrap().join("ran-sandboxed");
    fs::remove_file(&marker).unwrap();
    fs::create_dir(&marker).unwrap();
    fs::remove_file(r.bin.join("bwrap")).unwrap();
    let err = assert_fails(&no_bwrap(&r).args(["display", id, "x11"]).output().unwrap());
    assert!(err.contains("has run in the sandbox"), "{err}");
}

#[test]
fn remove_and_uninstall_refuse_while_the_app_still_runs_and_work_once_it_is_gone() {
    // A sandboxed app's wineserver survives `wineserver -k` (its socket is in the sandbox's private /tmp); the
    // host's /proc still shows it, like this fake one.
    let r = rig();
    let id = r.install();
    let root = r.apps().join(&id);
    let mut server = fake_wineserver(&r, &root.join("prefix"));
    for cmd in ["remove", "uninstall"] {
        let before = r.calls().len();
        let err = assert_fails(&r.rt(&[cmd, &id]));
        assert!(
            err.contains(&format!("{id} is running (wineserver pid {})", server.id()))
                && err.contains("quit it (Ctrl-C its `runtime run`) first; nothing was removed"),
            "{cmd}: {err}"
        );
        assert!(root.join("metadata.json").is_file(), "{cmd} removed the app");
        let calls = &r.calls()[before..];
        assert_eq!(calls.len(), 1, "{cmd}: only the stop, no uninstaller: {calls:?}");
        assert!(calls[0].starts_with("wineserver -k"), "{calls:?}");
    }
    server.kill().unwrap();
    server.wait().unwrap();
    assert_ok(&r.rt(&["remove", &id]));
    assert!(r.app_dirs().is_empty());
}

#[test]
fn sandbox_output_cannot_be_split_by_a_newline_in_a_path() {
    let r = rig();
    // A data directory whose name holds a newline, an escape sequence and a forged line.
    let data = r.root.join("da\nta\u{1b}[2J\ncommand: 'forged'");
    let run = |args: &[&std::ffi::OsStr]| r.cmd().env("RUNTIME_DATA_DIR", &data).args(args).output().unwrap();
    let p = r.input("hello64.exe", &fs::read(fixture("hello64.exe")).unwrap());
    assert_ok(&run(&["install".as_ref(), p.as_os_str()]));
    let o = run(&["sandbox".as_ref(), "runtime-fixture".as_ref()]);
    assert_ok(&o);
    let out = s(&o.stdout);
    assert_tame(&out, "stdout");
    let known = [
        "bubblewrap: ",
        "seccomp: ",
        "landlock: ",
        "shim: ",
        "profile ",
        "  host directory ",
        "limits: ",
        "  tasks: ",
        "  memory: ",
        "  cpu: ",
        "Wine: ",
        "REFUSED: ",
        "skipped: ",
        "note: ",
        "warning: ",
        "command: ",
    ];
    for line in out.lines() {
        assert!(
            known.iter().any(|k| line.starts_with(k)),
            "a forged line {line:?} in:\n{out}"
        );
    }
    assert_eq!(lines_with(&out, "command: ").len(), 1, "{out}");
    assert!(out.contains("da\\nta\\u{1b}[2J\\ncommand"), "{out}");
}

#[test]
fn every_exclusive_command_is_refused_while_a_runtime_run_of_the_app_lives() {
    // The lock, not /proc, is the signal: the program here is a plain shell (no wineserver process at all).
    let r = rig();
    let (id, _) = install_d3d11(&r);
    let go = r.log.join("go");
    // Bounded (30 s), so a failing test leaves nothing behind.
    r.hook(&format!(
        "i=0; while [ ! -f {} ] && [ $i -lt 600 ]; do sleep 0.05; i=$((i+1)); done; exit 4",
        go.display()
    ));
    let mut run = r
        .cmd()
        .args(["run", "--unsandboxed", &id])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while !r.calls().iter().any(|c| c == "wine <app>") {
        assert!(start.elapsed() < Duration::from_secs(20), "the program never started");
        std::thread::sleep(Duration::from_millis(20));
    }
    let home = r.grants.path().canonicalize().unwrap();
    let before = (r.calls(), r.tree());
    let commands: [&[&str]; 5] = [
        &["deps", &id, "--install"],
        &["display", &id, "x11"],
        &["permissions", &id, "--set", "network=allow"],
        &["remove", &id],
        &["uninstall", &id],
    ];
    for args in commands {
        let err = assert_fails(&r.cmd().env("HOME", &home).args(args).output().unwrap());
        assert!(
            err.contains("the app is running (started by `runtime run`); quit it first"),
            "{args:?}: {err}"
        );
    }
    assert_eq!((r.calls(), r.tree()), before, "nothing ran or changed");
    // Once the run has ended the same commands work.
    fs::write(&go, "").unwrap();
    assert_eq!(run.wait().unwrap().code(), Some(4));
    assert_ok(
        &r.cmd()
            .env("HOME", &home)
            .args(["permissions", &id, "--set", "network=allow"])
            .output()
            .unwrap(),
    );
    assert_ok(&r.rt(&["remove", &id]));
}

/// `runtime sandbox-init` itself (hidden): a program that cannot be executed is a 126 refusal (not 127), and the
/// program's arguments arrive byte for byte, clap's own syntax (`--`, `--help`) included.
#[test]
fn sandbox_init_refuses_with_126_and_passes_arguments_unchanged() {
    let rt = || Command::new(env!("CARGO_BIN_EXE_runtime"));
    let o = rt()
        .args(["sandbox-init", "--v1", "--", "/nonexistent/program"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(126), "{o:?}");
    assert!(
        s(&o.stderr).starts_with("runtime: sandbox-init: cannot run \"/nonexistent/program\": No such file"),
        "{o:?}"
    );
    let o = rt().args(["sandbox-init", "--help"]).output().unwrap();
    assert_eq!(o.status.code(), Some(126), "no help, a refused block: {o:?}");
    assert!(!s(&o.stdout).contains("Usage"), "{o:?}");
    // hidden from the help
    let help = rt().arg("--help").output().unwrap();
    assert!(!s(&help.stdout).contains("sandbox-init"), "{help:?}");

    let odd: Vec<OsString> = vec![
        "--".into(),
        "--help".into(),
        "-h".into(),
        "".into(),
        "a b".into(),
        "line\nbreak".into(),
        OsString::from_vec(b"\xff\xfe".to_vec()),
    ];
    // Landlock rules name canonical host paths (`/usr/bin/sh` and its libraries live below /usr here).
    let o = rt()
        .args(["sandbox-init", "--v1", "--rule", "ro:/usr", "--rule", "ro:/etc", "--"])
        .args(["/usr/bin/sh", "-c", "printf '%s\\0' \"$@\"", "sh"])
        .args(&odd)
        .output()
        .unwrap();
    assert!(o.status.success(), "{o:?}");
    let mut want = Vec::new();
    for a in &odd {
        want.extend_from_slice(a.as_encoded_bytes());
        want.push(0);
    }
    assert_eq!(o.stdout, want);
}

/// Phase 5B final review: `deps --install` picks the helper launcher ONCE for all archive packages of the run, so
/// when the plan may run an installer package (which gets a read-write prefix in the installer sandbox) the app is
/// marked BEFORE that choice: an archive package's `reg.exe` after the installer package is then sandboxed (or,
/// without bwrap, refused) instead of running through a launcher chosen while the app was unmarked. The download
/// cache is a file here, so nothing can ever be downloaded (the fetch fails on it first).
#[test]
fn deps_install_marks_the_app_before_choosing_the_helper_launcher_when_an_installer_package_may_run() {
    let r = rig();
    let id = install_msvcp140(&r); // plan: vcrun2022, an installer package
    let marker = r.apps().join(&id).join("ran-sandboxed");
    assert!(!marker.exists());
    let cache = r.data.join("deps-cache");
    fs::write(&cache, b"not a directory").unwrap();

    // Without bwrap: marked, so the helper launcher refuses before anything is fetched or run.
    let before = r.calls();
    let o = no_bwrap(&r).args(["deps", &id, "--install"]).output().unwrap();
    let err = assert_fails(&o);
    assert!(
        err.contains("has run in the sandbox") && err.contains("must run sandboxed too") && err.contains("bwrap"),
        "{err}"
    );
    assert!(marker.is_file(), "marked before the launcher was chosen");
    assert_eq!(r.calls(), before, "nothing ran");
    assert_eq!(
        fs::read(&cache).unwrap(),
        b"not a directory",
        "a download was attempted"
    );

    // With bwrap: the launcher chosen for the run's archive packages is the app sandbox (the marker is there).
    fake_bwrap(&r);
    let o = r.rt(&["deps", &id, "--install"]);
    assert!(!s(&o.stderr).contains("must run sandboxed too"), "{}", s(&o.stderr));
    assert!(marker.is_file());
    assert_eq!(
        fs::read(&cache).unwrap(),
        b"not a directory",
        "a download was attempted"
    );
}

/// An archive-only plan on a never-sandboxed app writes no marker: its `reg.exe` runs like any Wine helper, the
/// documented residual for apps no sandboxed code has touched.
#[test]
fn deps_install_of_archive_packages_only_does_not_mark_the_app() {
    let r = rig();
    let (id, _) = install_d3d11(&r); // plan: dxvk, an archive package
    fs::write(r.data.join("deps-cache"), b"not a directory").unwrap();
    let _ = r.rt(&["deps", &id, "--install"]);
    assert!(!r.apps().join(&id).join("ran-sandboxed").exists());
}

/// The mark fails closed: when it cannot be written, nothing is fetched or installed.
#[test]
fn deps_install_refuses_when_the_marker_cannot_be_written() {
    let r = rig();
    let id = install_msvcp140(&r);
    let cache = r.data.join("deps-cache");
    fs::write(&cache, b"not a directory").unwrap();
    let root = r.apps().join(&id);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();
    let o = r.rt(&["deps", &id, "--install"]);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let err = assert_fails(&o);
    assert!(
        err.contains("cannot record") && err.contains("nothing was installed"),
        "{err}"
    );
    assert!(!root.join("ran-sandboxed").exists());
    assert_eq!(
        fs::read(&cache).unwrap(),
        b"not a directory",
        "a download was attempted"
    );
}

// ================================================================ golden: the host-fact reports, byte for byte

/// A 32-bit `hello64.exe` whose `msvcrt.dll` import is `d3d11.dll` (DXVK would cover 64-bit only).
fn x86_d3d11_exe() -> Vec<u8> {
    let mut bytes = fs::read(fixture("hello64.exe")).unwrap();
    let at = bytes
        .windows(11)
        .position(|w| w.eq_ignore_ascii_case(b"msvcrt.dll\0"))
        .unwrap();
    bytes[at..at + 11].copy_from_slice(b"d3d11.dll\0\0");
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    bytes[pe + 4..pe + 6].copy_from_slice(&0x014Cu16.to_le_bytes()); // machine: i386
    bytes
}

/// The rig states the host-fact reports are pinned on (installed in this order, so the ids are stable): a native
/// app, one importing d3d11, managed without and with Wine Mono recorded, 32-bit with DXVK recorded, one whose
/// executable is gone, one whose `drive_c` is a symlink, and a hostile name. Returns the ids.
fn golden_rig(r: &Rig) -> Vec<String> {
    r.wine_dlls(&["kernel32.dll", "msvcrt.dll", "d3d11.dll", "winepulse.drv"]);
    let native = r.install();
    let (d3d, _) = install_d3d11(r);
    let managed = install_managed(r);
    let mono = install_managed(r);
    record_installed(r, &mono, "wine-mono");
    let p = r.input("x86.exe", &x86_d3d11_exe());
    let o = r.rt(&[OsString::from("install"), p.into_os_string()]);
    assert_ok(&o);
    let x86 = installed_id(&o);
    record_installed(r, &x86, "dxvk");
    let no_exe = r.install_as("gone.exe", &[]);
    let exe = r
        .apps()
        .join(&no_exe)
        .join("prefix/drive_c/Program Files")
        .join(&no_exe);
    fs::remove_file(exe.join("gone.exe")).unwrap();
    let linked = r.install_as("linked.exe", &[]);
    let drive_c = r.apps().join(&linked).join("prefix/drive_c");
    fs::rename(&drive_c, r.root.join("elsewhere")).unwrap();
    symlink(r.root.join("elsewhere"), &drive_c).unwrap();
    r.plant("evil", "Evil\u{1b}]0;pwned\u{7}\u{202e}\u{9b}[2J name");
    vec![native, d3d, managed, mono, x86, no_exe, linked, "evil".into()]
}

/// One transcript of every report, host-specific text replaced: the rig root, this binary, the kernel's
/// hardening phrases (and the sandbox's `command:`/`skipped:`/`note:` lines, which name host devices and binds;
/// their content is pinned by the sandbox tests above).
fn golden_transcript(r: &Rig, ids: &[String]) -> String {
    let h = rt_sandbox::hardening();
    let exe = runtime_exe();
    let root = r.root.display().to_string();
    let norm = |text: &str| {
        let mut t = text
            .replace(&exe.display().to_string(), "<RUNTIME>")
            .replace(&root, "<ROOT>")
            .replace(&h.seccomp, "<SECCOMP>")
            .replace(&h.landlock, "<LANDLOCK>");
        if let Some(c) = &h.caveat {
            t = t.replace(c, "<CAVEAT>");
        }
        t
    };
    let mut out = String::new();
    let mut add = |name: &str, mut c: Command, sandbox: bool| {
        let o = c.output().unwrap();
        let mut so = norm(&s(&o.stdout));
        if sandbox {
            so = so
                .lines()
                .filter(|l| !["command: ", "skipped: ", "note: "].iter().any(|p| l.starts_with(p)))
                .map(|l| format!("{l}\n"))
                .collect();
        }
        out += &format!(
            "=== {name} (exit {:?})\n{so}--- stderr\n{}",
            o.status.code(),
            norm(&s(&o.stderr))
        );
    };
    let with = |args: &[&str]| {
        let mut c = r.desktop();
        c.args(args);
        c
    };
    // Before the fake bwrap exists: only the rig's bin/ on PATH, so no bwrap at all.
    let mut c = with(&["doctor", "--json"]);
    c.env("PATH", &r.bin);
    add("doctor --json, no bwrap", c, false);
    let mut c = with(&["doctor", &ids[0], "--json"]);
    c.env("PATH", &r.bin);
    add("doctor native --json, no bwrap", c, false);
    let mut c = with(&["sandbox", &ids[0]]);
    c.env("PATH", &r.bin);
    add("sandbox native, no bwrap", c, true);
    fake_bwrap(r);
    add("doctor", with(&["doctor"]), false);
    add("doctor --json", with(&["doctor", "--json"]), false);
    let mut c = with(&["doctor", "--json"]);
    c.env("RUNTIME_WINE", r.root.join("no-such-wine"));
    add("doctor --json, no wine", c, false);
    let mut c = with(&["doctor", "--json"]);
    c.env("RUNTIME_VULKAN_LOADER", "absent");
    add("doctor --json, no vulkan loader", c, false);
    for id in ids {
        add(&format!("doctor {id}"), with(&["doctor", id]), false);
        add(&format!("doctor {id} --json"), with(&["doctor", id, "--json"]), false);
        add(&format!("deps {id}"), with(&["deps", id]), false);
        add(&format!("sandbox {id}"), with(&["sandbox", id]), true);
    }
    let mut c = with(&["deps", &ids[1]]);
    c.env("RUNTIME_VULKAN_LOADER", "absent");
    add("deps d3d11, no vulkan loader", c, false);
    let mut c = with(&["doctor", &ids[1], "--json"]);
    c.env("RUNTIME_VULKAN_LOADER", "absent");
    add("doctor d3d11 --json, no vulkan loader", c, false);
    add("graphics info", with(&["graphics", "info"]), false);
    out
}

/// The host-fact reports (`doctor`, `doctor <app>`, `--json`, `sandbox <app>`, `deps <app>`, `graphics info`) are
/// byte for byte what `tests/golden/host_facts.txt` holds. Moving their gathering code must not change one byte;
/// `RUNTIME_BLESS=1` rewrites the file (only for an intended change of the output).
#[test]
fn host_fact_reports_match_the_golden_transcript() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!("SKIPPED: the golden transcript was taken on x86_64 (the architecture check differs)");
        return;
    }
    let r = rig();
    let ids = golden_rig(&r);
    let got = golden_transcript(&r, &ids);
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/host_facts.txt");
    if std::env::var_os("RUNTIME_BLESS").is_some_and(|v| v == "1") {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &got).unwrap();
    }
    let want = fs::read_to_string(&path).expect("no golden: run with RUNTIME_BLESS=1 once");
    if got != want {
        let (g, w): (Vec<&str>, Vec<&str>) = (got.lines().collect(), want.lines().collect());
        let at = g
            .iter()
            .zip(&w)
            .position(|(a, b)| a != b)
            .unwrap_or(g.len().min(w.len()));
        panic!(
            "the transcript differs from {} at line {}:\n  got:  {:?}\n  want: {:?}",
            path.display(),
            at + 1,
            g.get(at),
            w.get(at)
        );
    }
}

// ================================================================ the API over the same rig: rt_api::Runtime

/// Not a test of its own: the API side of the `api_*` tests. It does nothing unless `RT_API_CALL` is set; the
/// tests below run this test binary again, with the rig's environment and only this test, so `Runtime::open()`
/// sees exactly what the `runtime` process sees. Prints the result (`{"Ok": ...}` or `{"Err": ...}`) as JSON
/// between markers.
#[test]
fn api_child() {
    let Some(call) = std::env::var_os("RT_API_CALL") else {
        return;
    };
    let mut rt = rt_api::Runtime::open().unwrap();
    // A caller that is not `runtime` (this test binary, like a daemon) names the `runtime` binary as the shim.
    if let Some(exe) = std::env::var_os("RT_API_RUNTIME_EXE") {
        rt = rt.with_runtime_exe(exe.into());
    }
    let arg = std::env::var("RT_API_ARG").ok();
    let v = match call.to_str().unwrap() {
        "doctor" => serde_json::to_value(rt.doctor(match arg {
            None => rt_api::DoctorTarget::System,
            Some(a) => rt_api::DoctorTarget::App(a),
        })),
        "graphics" => serde_json::to_value(Ok::<_, ()>(rt.graphics_info())),
        "sandbox" => serde_json::to_value(rt.sandbox_info(&arg.unwrap())),
        "deps" => serde_json::to_value(rt.deps_plan(&arg.unwrap())),
        other => panic!("unknown RT_API_CALL {other}"),
    };
    println!("@@API@@{}@@API@@", v.unwrap());
}

/// Runs `api_child` with the environment `rig_cmd` would give `runtime`: the API's answer to `call` (`arg`).
fn api(rig_cmd: &Command, call: &str, arg: Option<&str>) -> Result<serde_json::Value, serde_json::Value> {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.env_clear()
        .args(["--exact", "api_child", "--nocapture", "--test-threads=1"]);
    for (k, v) in rig_cmd.get_envs() {
        if let Some(v) = v {
            c.env(k, v);
        }
    }
    c.env("RT_API_CALL", call);
    if let Some(a) = arg {
        c.env("RT_API_ARG", a);
    }
    let o = c.stdin(Stdio::null()).output().unwrap();
    let out = s(&o.stdout);
    let json = out
        .split("@@API@@")
        .nth(1)
        .unwrap_or_else(|| panic!("no API answer: {out}\n{}", s(&o.stderr)));
    let mut v: serde_json::Value = serde_json::from_str(json).unwrap();
    if let Some(ok) = v.get_mut("Ok") {
        return Ok(ok.take());
    }
    Err(v
        .get_mut("Err")
        .unwrap_or_else(|| panic!("neither Ok nor Err: {json}"))
        .take())
}

/// No control or format character in any string (keys too): the API's sanitise-everything rule.
fn assert_clean_json(v: &serde_json::Value, at: &str) {
    let clean = |s: &str| !s.chars().any(|c| c.is_control() || rt_core::is_format(c));
    match v {
        serde_json::Value::String(t) => assert!(clean(t), "{at}: {t:?}"),
        serde_json::Value::Array(a) => a.iter().for_each(|x| assert_clean_json(x, at)),
        serde_json::Value::Object(o) => o.iter().for_each(|(k, x)| {
            assert!(clean(k), "{at}: key {k:?}");
            assert_clean_json(x, &format!("{at}.{k}"));
        }),
        _ => {}
    }
}

/// The `(area, status, text)` triples of a doctor JSON (the CLI's or the API's), texts cleaned like the API's.
fn triples(v: &serde_json::Value) -> Vec<(String, String, String)> {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["area"].as_str().unwrap().to_owned(),
                c["status"].as_str().unwrap().to_owned(),
                rt_core::clean_text(c["text"].as_str().unwrap(), rt_api::LONG_MAX),
            )
        })
        .collect()
}

/// `doctor [<id>] --json` through the CLI and `Runtime::doctor` through the API agree: verdict, subject id and
/// every triple; the hint's count too. Nothing is written by the API call.
fn doctor_agrees(r: &Rig, cmd: impl Fn() -> Command, id: Option<&str>) -> serde_json::Value {
    let mut c = cmd();
    c.arg("doctor").args(id).arg("--json");
    let o = c.output().unwrap();
    let cli = json(&o);
    let before = snapshot(r);
    let api = api(&cmd(), "doctor", id).unwrap_or_else(|e| panic!("{id:?}: {e}"));
    assert_eq!(snapshot(r), before, "the API's doctor wrote something");
    assert_clean_json(&api, "doctor");
    assert_eq!(api["verdict"], cli["verdict"], "{id:?}");
    assert_eq!(api["subject"]["kind"], cli["subject"]["kind"]);
    assert_eq!(api["subject"]["id"], cli["subject"]["id"]);
    assert_eq!(triples(&api), triples(&cli), "{id:?}");
    let hint = s(&o.stderr)
        .lines()
        .find_map(|l| l.strip_prefix("hint: ")?.split(' ').next()?.parse::<u64>().ok())
        .unwrap_or(0);
    assert_eq!(api["missingDependencies"], hint, "{id:?}: {}", s(&o.stderr));
    api
}

#[test]
fn api_doctor_equals_the_cli_json_on_every_rig_state() {
    let r = rig();
    // Sandbox unavailable first (no bwrap anywhere on PATH): the check is a warning in both.
    r.wine_dlls(&["kernel32.dll", "msvcrt.dll", "d3d11.dll", "winepulse.drv"]);
    let no_bwrap = || {
        let mut c = r.desktop();
        c.env("PATH", &r.bin);
        c
    };
    let v = doctor_agrees(&r, no_bwrap, None);
    assert!(
        triples(&v)
            .iter()
            .any(|t| t.1 == "warn" && t.2.contains("bwrap is not on PATH")),
        "{v}"
    );
    let ids = golden_rig(&r);
    doctor_agrees(&r, no_bwrap, Some(&ids[0]));
    fake_bwrap(&r);
    let desktop = || r.desktop();
    doctor_agrees(&r, desktop, None);
    // native, d3d11, managed without and with Mono, 32-bit, missing exe, symlinked drive_c, hostile name
    let mut verdicts = vec![];
    for id in &ids {
        let v = doctor_agrees(&r, desktop, Some(id));
        verdicts.push(v["verdict"].as_str().unwrap().to_owned());
    }
    assert_eq!(verdicts[5..], ["fail", "fail", "fail"], "{verdicts:?}");
    let mono = doctor_agrees(&r, desktop, Some(&ids[3]));
    assert!(
        triples(&mono)
            .iter()
            .any(|t| t.2.contains("Wine Mono 9.4.0 is recorded")),
        "{mono}"
    );
    let without = doctor_agrees(&r, desktop, Some(&ids[2]));
    assert!(
        triples(&without).iter().any(|t| t.1 == "warn" && t.2.contains(".NET")),
        "{without}"
    );
    // The d3d11 app's plan has DXVK to install: the CLI's hint, the API's count (compared in `doctor_agrees`).
    assert_eq!(doctor_agrees(&r, desktop, Some(&ids[1]))["missingDependencies"], 1);
    // The hostile name is cleaned, not escaped.
    let evil = doctor_agrees(&r, desktop, Some("evil"));
    assert_eq!(evil["subject"]["name"], "Evil]0;pwned[2J name");
    // Wine missing: a failing check with the install hint, in both.
    let no_wine = || {
        let mut c = r.desktop();
        c.env("RUNTIME_WINE", r.root.join("no-such-wine"));
        c
    };
    let v = doctor_agrees(&r, no_wine, Some(&ids[0]));
    assert!(
        triples(&v)
            .iter()
            .any(|t| t.1 == "fail" && t.2.contains("RUNTIME_WINE")),
        "{v}"
    );
    let empty = r.root.join("emptybin");
    fs::create_dir_all(&empty).unwrap();
    let no_wine_at_all = || {
        let mut c = r.desktop();
        c.env_remove("RUNTIME_WINE")
            .env_remove("RUNTIME_WINESERVER")
            .env("PATH", &empty);
        c
    };
    let v = doctor_agrees(&r, no_wine_at_all, None);
    assert!(
        triples(&v)
            .iter()
            .any(|t| t.1 == "fail" && t.2.contains("sudo apt install wine")),
        "{v}"
    );
    // Vulkan absent through the loader override: the D3D route fails in both.
    let no_vulkan = || {
        let mut c = r.desktop();
        c.env("RUNTIME_VULKAN_LOADER", "absent");
        c
    };
    doctor_agrees(&r, no_vulkan, Some(&ids[1]));
    // An unknown or invalid id: the kinds, where the CLI fails.
    let e = api(&r.desktop(), "doctor", Some("nothing")).unwrap_err();
    assert_eq!(e["kind"], "not_found");
    let e = api(&r.desktop(), "doctor", Some("../x")).unwrap_err();
    assert_eq!(e["kind"], "invalid_argument");
}

#[test]
fn api_doctor_never_passes_a_hostile_import_name_on() {
    let r = rig();
    r.wine_dlls(&["kernel32.dll"]); // the hostile import is then "not found" and named in the check
    let (id, _) = install_patched(&r, b"msvcrt.dll\0", b"\x1b[2Jq\x07.dll\0");
    let v = doctor_agrees(&r, || r.desktop(), Some(&id));
    let line = triples(&v)
        .into_iter()
        .find(|t| t.0 == "imports" && t.1 == "warn")
        .unwrap_or_else(|| panic!("no missing-import check: {v}"));
    assert!(line.2.contains("[2Jq") && line.2.contains(".dll"), "{line:?}");
}

#[test]
fn api_deps_plan_equals_the_cli_plan() {
    let r = rig();
    let ids = golden_rig(&r);
    for (id, loader) in ids
        .iter()
        .map(|i| (i.as_str(), "present"))
        .chain([(ids[1].as_str(), "absent")])
    {
        let mut c = r.cmd();
        c.env("RUNTIME_VULKAN_LOADER", loader);
        let cli = s(&r
            .cmd()
            .env("RUNTIME_VULKAN_LOADER", loader)
            .args(["deps", id])
            .output()
            .unwrap()
            .stdout);
        let before = snapshot(&r);
        let v = api(&c, "deps", Some(id)).unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(snapshot(&r), before, "deps_plan wrote something");
        assert_clean_json(&v, "deps");
        let entries: Vec<&str> = cli
            .lines()
            .filter(|l| l.starts_with("  ") && l.contains("): "))
            .collect();
        let api_entries = v["entries"].as_array().unwrap();
        assert_eq!(entries.len(), api_entries.len(), "{id}: {cli}\n{v}");
        for (line, e) in entries.iter().zip(api_entries) {
            let what = match (e["action"].as_str().unwrap(), e["consent"].as_str().unwrap()) {
                ("install", "needed") => "to install, needs your consent".to_owned(),
                ("install", _) => "to install".to_owned(),
                ("alreadyInstalled", _) => rt_deps::ALREADY_INSTALLED.to_owned(),
                ("blocked", _) => format!("blocked: {}", e["blockedReason"].as_str().unwrap()),
                other => panic!("{other:?}"),
            };
            let head = format!(
                "  {} {} (",
                e["package"].as_str().unwrap(),
                e["version"].as_str().unwrap()
            );
            assert!(
                line.starts_with(&head) && line.ends_with(&format!("): {what}")),
                "{line} vs {e}"
            );
        }
        let warnings: Vec<&str> = cli.lines().filter_map(|l| l.strip_prefix("warning: ")).collect();
        assert_eq!(serde_json::json!(warnings), v["warnings"], "{id}");
    }
    let blocked = api(r.cmd().env("RUNTIME_VULKAN_LOADER", "absent"), "deps", Some(&ids[1])).unwrap();
    assert_eq!(blocked["entries"][0]["action"], "blocked");
}

#[test]
fn api_sandbox_info_equals_runtime_sandbox_and_fails_closed() {
    let r = rig();
    let id = r.install();
    let home = r.grants.path().canonicalize().unwrap();
    // No bwrap on PATH (the rig's bin/ only): unavailable, with the reason `runtime sandbox` prints.
    let mut c = r.cmd();
    c.env("PATH", &r.bin);
    let cli = s(&no_bwrap(&r).args(["sandbox", &id]).output().unwrap().stdout);
    let v = api(&c, "sandbox", Some(&id)).unwrap();
    assert_eq!(
        v["bwrap"],
        serde_json::json!({"state": "unavailable", "reason": "bwrap is not on PATH"})
    );
    assert!(
        cli.starts_with("bubblewrap: UNAVAILABLE: bwrap is not on PATH"),
        "{cli}"
    );
    // With a (fake) bwrap: the view is the CLI's report, line for line.
    fake_bwrap(&r);
    let before = snapshot(&r);
    let mut c = r.cmd();
    c.env("RT_API_RUNTIME_EXE", runtime_exe());
    let v = api(&c, "sandbox", Some(&id)).unwrap();
    assert_eq!(snapshot(&r), before, "sandbox_info wrote something");
    assert_clean_json(&v, "sandbox");
    let cli = s(&r.rt(&["sandbox", &id]).stdout);
    assert_eq!(v["bwrap"]["state"], "available");
    assert_eq!(v["wine"]["state"], "available");
    assert_eq!(v["limits"]["state"], "available");
    assert_eq!(
        v["cgroupControllers"],
        serde_json::json!(["cpu", "io", "memory", "pids"])
    );
    assert_eq!(v["profile"]["source"], "default");
    let lines = |p: &str| -> Vec<String> {
        cli.lines()
            .filter_map(|l| l.strip_prefix(p))
            .map(String::from)
            .collect()
    };
    assert_eq!(serde_json::json!(lines("skipped: ")), v["skipped"]);
    let notes = lines("note: ");
    assert_eq!(serde_json::json!(notes), v["caveats"], "{cli}");
    assert_eq!(lines("seccomp: ").len() + lines("landlock: ").len(), 2);
    // The supplied `runtime` is the shim, not this test binary: the command is exactly `runtime sandbox`'s.
    let me = std::env::current_exe().unwrap().canonicalize().unwrap();
    assert!(!v.to_string().contains(me.to_str().unwrap()), "{v}");
    assert!(v["refused"].is_null(), "{v}");
    let quoted: Vec<String> = v["command"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| format!("'{}'", a.as_str().unwrap().replace('\'', r"'\''")))
        .collect();
    assert_eq!(lines("command: "), [quoted.join(" ")]);
    // A supplied path that is not a file: the sandbox is refused for it (fail closed), never this binary used.
    let mut c = r.cmd();
    c.env("RT_API_RUNTIME_EXE", r.root.join("no-such-runtime"));
    let v = api(&c, "sandbox", Some(&id)).unwrap();
    assert!(
        v["refused"].as_str().unwrap().contains("runtime executable") && !v.to_string().contains(me.to_str().unwrap()),
        "{v}"
    );
    // Wine missing: part of the answer, with the install hint; the command keeps its shape.
    let mut c = r.cmd();
    c.env("RUNTIME_WINE", r.root.join("no-such-wine"));
    let v = api(&c, "sandbox", Some(&id)).unwrap();
    assert_eq!(v["wine"]["state"], "unavailable");
    assert!(v["wine"]["reason"].as_str().unwrap().contains("RUNTIME_WINE"), "{v}");
    // An invalid profile: an error, never the default.
    fs::write(r.apps().join(&id).join("permissions.toml"), "version = 1\nbogus = 1\n").unwrap();
    let mut c = r.cmd();
    c.env("HOME", &home);
    let e = api(&c, "sandbox", Some(&id)).unwrap_err();
    assert_eq!(e["kind"], "unavailable");
    assert!(
        e["message"].as_str().unwrap().contains("permissions.toml is refused"),
        "{e}"
    );
    assert_fails(&r.cmd().env("HOME", &home).args(["sandbox", &id]).output().unwrap());
}

#[test]
fn api_sandbox_info_cleans_a_hostile_data_dir_path_in_the_command() {
    let r = rig();
    fake_bwrap(&r);
    let data = r.root.join("da\nta\u{1b}[2J\u{202e}x");
    let p = r.input("hello64.exe", &fs::read(fixture("hello64.exe")).unwrap());
    assert_ok(
        &r.cmd()
            .env("RUNTIME_DATA_DIR", &data)
            .arg("install")
            .arg(&p)
            .output()
            .unwrap(),
    );
    let mut c = r.cmd();
    c.env("RUNTIME_DATA_DIR", &data);
    let v = api(&c, "sandbox", Some("runtime-fixture")).unwrap();
    assert_clean_json(&v, "sandbox");
    let cmd = v["command"].as_array().unwrap();
    assert!(cmd.iter().any(|a| a.as_str().unwrap().contains("data[2Jx")), "{v}");
}

#[test]
fn api_graphics_info_follows_the_loader_override_like_graphics_info() {
    let r = rig();
    let v = api(&r.cmd(), "graphics", None).unwrap();
    let cli = s(&r.rt(&["graphics", "info"]).stdout);
    assert_eq!(
        (v["verdict"].as_str(), v["loader"].as_bool()),
        (Some("usable"), Some(true))
    );
    assert!(cli.starts_with("Vulkan: usable\n"), "{cli}");
    assert_eq!(v["devices"][0]["api"], "1.3");
    for p in v["perPackage"].as_array().unwrap() {
        let line = format!(
            "  {} {}+: met",
            p["id"].as_str().unwrap(),
            p["minVulkan"].as_str().unwrap()
        );
        assert!(p["ok"] == true && cli.contains(&line), "{line} in {cli}");
    }
    let mut c = r.cmd();
    c.env("RUNTIME_VULKAN_LOADER", "absent");
    let v = api(&c, "graphics", None).unwrap();
    let cli = s(&r
        .cmd()
        .env("RUNTIME_VULKAN_LOADER", "absent")
        .args(["graphics", "info"])
        .output()
        .unwrap()
        .stdout);
    assert_eq!(
        (v["verdict"].as_str(), v["loader"].as_bool(), v["toolFound"].as_bool()),
        (Some("unusable"), Some(false), Some(false))
    );
    assert!(
        cli.starts_with("Vulkan: unusable") && cli.contains(v["reason"].as_str().unwrap()),
        "{cli}\n{v}"
    );
}

/// Hostile metadata (version, executable path) and a hostile grant path reach `doctor` and `sandbox_info` only
/// cleaned: every string of their answers (errors included) is free of control and format characters.
#[test]
fn api_doctor_and_sandbox_info_clean_a_hostile_version_executable_and_grant() {
    let r = rig();
    fake_bwrap(&r);
    let dir = r.plant("vile", "Vile");
    let md_path = dir.join("metadata.json");
    let mut md: serde_json::Value = serde_json::from_slice(&fs::read(&md_path).unwrap()).unwrap();
    md["version"] = "9\n\u{202e}\u{1b}[31m\u{9b}2J".into();
    md["executable"] = "C:\\Program Files\\x\\a\u{202e}b\u{200b}.exe".into();
    fs::write(&md_path, serde_json::to_vec(&md).unwrap()).unwrap();
    let doc = doctor_agrees(&r, || r.desktop(), Some("vile"));
    assert_eq!(doc["subject"]["version"], "9[31m2J");
    // The missing executable is named in the program check, escaped by core (printable) and walked clean above.
    assert!(
        triples(&doc)
            .iter()
            .any(|t| t.0 == "program" && t.2.contains(r"a\u{202e}b")),
        "{doc}"
    );
    // sandbox_info cannot resolve that program: an error, cleaned.
    let e = api(&r.cmd(), "sandbox", Some("vile")).unwrap_err();
    assert_clean_json(&e, "sandbox error");
    assert_eq!(e["kind"], "unavailable");
    // A real app whose permissions.toml grants a directory with a bidi override in its name: refused (the grant
    // validator never accepts such a path), and the refusal that quotes it is walked clean.
    let id = r.install();
    let home = r.grants.path().canonicalize().unwrap();
    let odd = home.join("od\u{202e}d");
    fs::create_dir(&odd).unwrap();
    fs::write(
        r.apps().join(&id).join("permissions.toml"),
        format!(
            "version = 1\n[[filesystem]]\npath = \"{}/od\\u202ed\"\naccess = \"ro\"\n",
            home.display()
        ),
    )
    .unwrap();
    let mut c = r.desktop();
    c.env("HOME", &home);
    let e = api(&c, "sandbox", Some(&id)).unwrap_err();
    assert_clean_json(&e, "grant error");
    assert!(e["message"].as_str().unwrap().contains("invisible characters"), "{e}");
    // doctor: the sandbox check warns with the (cut) refusal, equal to the CLI's and walked clean.
    let doc = doctor_agrees(
        &r,
        || {
            let mut c = r.desktop();
            c.env("HOME", &home);
            c
        },
        Some(&id),
    );
    assert!(
        triples(&doc)
            .iter()
            .any(|t| t.1 == "warn" && t.2.contains("cannot read the profile")),
        "{doc}"
    );
}

// ================================================================ runtimed's argv (Phase 6B)

/// The digest `deps.plan` reports for `id` in this rig (the rig's GPU meets every package's minimum).
fn plan_digest_of(r: &Rig, id: &str) -> String {
    let store = rt_core::Store::new(r.apps()).unwrap();
    let env = store.get(&rt_core::AppId::parse(id).unwrap()).unwrap();
    let md = store.read_metadata(&env).unwrap();
    let m = rt_deps::Manifest::bundled();
    let plan = rt_deps::plan_for_app(&env, &md, m, &|_| rt_core::VulkanVerdict::Usable);
    rt_api::jobs::plan_digest(env.id(), &plan, m)
}

/// `runtime <spec.argv()>` in the rig, exactly as `runtimed` would start it (after argv[0]).
fn rt_spec(r: &Rig, spec: &rt_api::jobs::JobSpec) -> Output {
    r.rt(&spec.argv())
}

fn deps_install_spec(id: &str, digest: &str, yes: &[&str]) -> rt_api::jobs::JobSpec {
    rt_api::jobs::JobSpec::DepsInstall {
        app: rt_core::AppId::parse(id).unwrap(),
        plan_digest: digest.into(),
        yes: yes.iter().map(|y| (*y).to_owned()).collect(),
    }
}

#[test]
fn deps_install_with_a_stale_plan_digest_installs_nothing() {
    let r = rig();
    let id = install_msvcp140(&r);
    // A file where the download cache belongs: any fetch would fail on it and leave it changed or not; nothing may
    // even look at it here.
    let cache = r.data.join("deps-cache");
    fs::write(&cache, b"not a directory").unwrap();
    let right = plan_digest_of(&r, &id);
    let stale = if right.starts_with('0') { "1" } else { "0" }.to_owned() + &right[1..];
    let (tree, calls) = (r.tree(), r.calls());
    for yes in [&[][..], &["vcrun2022"]] {
        let o = rt_spec(&r, &deps_install_spec(&id, &stale, yes));
        let err = assert_fails(&o);
        assert!(
            err.contains("the dependency plan changed since it was shown") && err.contains("nothing was installed"),
            "{err}"
        );
        assert!(
            !s(&o.stdout).contains("Package: vcrun2022"),
            "the licence was offered: {}",
            s(&o.stdout)
        );
        assert_eq!(
            (r.tree(), r.calls()),
            (tree.clone(), calls.clone()),
            "no mark, no lock, no Wine"
        );
        assert_eq!(fs::read(&cache).unwrap(), b"not a directory");
    }
    // A digest that is not 64 lowercase hex, or one without --install, is a usage error.
    for bad in [
        vec![
            "deps".to_owned(),
            id.clone(),
            "--install".into(),
            "--plan-digest".into(),
            right.to_uppercase(),
        ],
        vec![
            "deps".into(),
            id.clone(),
            "--install".into(),
            format!("--plan-digest={}", &right[1..]),
        ],
        vec!["deps".into(), id.clone(), "--install".into(), "--plan-digest=".into()],
        vec!["deps".into(), id.clone(), format!("--plan-digest={right}")],
    ] {
        let o = r.rt(&bad);
        assert_eq!(o.status.code(), Some(2), "{bad:?}: {}", s(&o.stderr));
    }
    assert_eq!(r.tree(), tree);
}

#[test]
fn deps_install_with_the_reported_digest_behaves_exactly_as_without_it() {
    let r = rig();
    let id = install_msvcp140(&r);
    fs::write(r.data.join("deps-cache"), b"not a directory").unwrap();
    let digest = plan_digest_of(&r, &id);
    for yes in [&[][..], &["vcrun2022"]] {
        let with = rt_spec(&r, &deps_install_spec(&id, &digest, yes));
        let mut plain = vec!["deps".to_owned(), id.clone(), "--install".into()];
        plain.extend(yes.iter().map(|y| format!("--yes={y}")));
        let without = r.rt(&plain);
        assert_eq!(
            (with.status.code(), s(&with.stdout), s(&with.stderr)),
            (without.status.code(), s(&without.stdout), s(&without.stderr)),
            "{yes:?}"
        );
        let out = s(&with.stdout);
        assert!(
            out.contains("Package: vcrun2022"),
            "the licence text is shown in full: {out}"
        );
        if yes.is_empty() {
            assert!(out.contains("No consent: vcrun2022 is skipped"), "{out}");
        } else {
            assert!(
                out.contains("Consent given on the command line (--yes vcrun2022)"),
                "{out}"
            );
        }
    }
    // An app whose plan is empty: nothing to install, exit 0.
    let plain = r.install();
    let o = rt_spec(&r, &deps_install_spec(&plain, &plan_digest_of(&r, &plain), &[]));
    assert_ok(&o);
    assert!(s(&o.stdout).ends_with("Nothing to install.\n"), "{}", s(&o.stdout));
}

/// `runtime deps` has `list` and `cache` subcommands: the daemon's argv puts the app id after `--`, and an app
/// really named `list` must reach the app path, never the subcommand (spec 5.1's open question, decided here).
#[test]
fn deps_install_argv_of_an_app_named_list_or_cache_reaches_the_app() {
    let r = rig();
    for name in ["list", "cache"] {
        r.plant(name, "Shadowed");
        let o = rt_spec(&r, &deps_install_spec(name, &plan_digest_of(&r, name), &[]));
        let out = s(&o.stdout);
        assert!(
            out.starts_with(&format!("Dependencies of {name}:\n")),
            "{name}: {out}{}",
            s(&o.stderr)
        );
        assert!(
            !out.contains("Bundled packages") && !out.contains("Download cache"),
            "{out}"
        );
    }
}

#[test]
fn the_daemons_argv_with_hostile_values_has_only_the_intended_effect() {
    use rt_api::jobs::JobSpec;
    let r = rig();
    // An install named `--network`: a name, not the flag.
    let exe = r.input("hello64.exe", &fs::read(fixture("hello64.exe")).unwrap());
    let o = rt_spec(
        &r,
        &JobSpec::Install {
            path: exe,
            name: Some("--network".into()),
            exe: None,
            silent: false,
            network: false,
        },
    );
    assert_ok(&o);
    let id = installed_id(&o);
    assert_eq!(id, "network");
    let md: serde_json::Value =
        serde_json::from_slice(&fs::read(r.apps().join(&id).join("metadata.json")).unwrap()).unwrap();
    assert_eq!(md["name"], "--network");
    // `--set=--reset` is an expression the grammar refuses; nothing changes (no reset, no file).
    let (app, home) = perm_app(&r);
    fs::write(app.join("permissions.toml"), "version = 1\nnetwork = \"allow\"\n").unwrap();
    let spec = JobSpec::PermissionsSet {
        app: rt_core::AppId::parse("papp").unwrap(),
        set: vec!["--reset".into()],
    };
    let o = r.cmd().env("HOME", &home).args(spec.argv()).output().unwrap();
    let err = assert_fails(&o);
    assert!(err.contains("nothing was changed"), "{err}");
    assert_eq!(
        fs::read_to_string(app.join("permissions.toml")).unwrap(),
        "version = 1\nnetwork = \"allow\"\n"
    );
    // `remove -- <id>` removes that app, and only it.
    let o = rt_spec(
        &r,
        &JobSpec::Remove {
            app: rt_core::AppId::parse(&id).unwrap(),
        },
    );
    assert_ok(&o);
    assert_eq!(r.app_dirs(), ["papp"]);
}

/// Spec D11, the installer half (the app sandbox half is `crates/daemon/tests/e2e_jobs.rs`): what the installer
/// sandbox binds, with the network on, never includes `$XDG_RUNTIME_DIR`, the write-capable socket or an ancestor
/// of it (it binds only the system trees, the shim and the prefix, and drops the session variables).
#[test]
fn the_installer_sandbox_never_binds_the_daemons_socket() {
    let r = rig();
    let dir = r.plant("inst", "I");
    let store = rt_core::Store::new(r.apps()).unwrap();
    let env = store.get(&rt_core::AppId::parse("inst").unwrap()).unwrap();
    assert_eq!(env.root(), dir);
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let xdg = PathBuf::from(format!("/run/user/{uid}"));
    let sock = xdg.join("runtime/runtimed.sock");
    let sb = rt_installer::InstallerSandbox::new("/usr/bin/bwrap", env!("CARGO_BIN_EXE_runtime"));
    let mut cmd = Command::new("/bin/true");
    cmd.env_clear()
        .env("HOME", r.root.join("home"))
        .env("XDG_RUNTIME_DIR", &xdg)
        .env("WAYLAND_DISPLAY", "wayland-0");
    let opts = rt_installer::SandboxOpts {
        allow_network: true,
        extra_ro_binds: vec![],
    };
    let wrapped = sb.wrap(cmd, &env, &opts);
    let argv: Vec<String> = wrapped.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    assert!(argv.iter().any(|a| a == "--bind"), "not a real render: {argv:?}");
    let mut seen = 0;
    for (i, a) in argv.iter().enumerate() {
        if a == "--" {
            break;
        }
        if matches!(
            a.as_str(),
            "--bind" | "--ro-bind" | "--bind-try" | "--ro-bind-try" | "--dev-bind" | "--dev-bind-try"
        ) {
            seen += 1;
            for p in [Path::new(&argv[i + 1]), Path::new(&argv[i + 2])] {
                assert!(!sock.starts_with(p) && !p.starts_with(&xdg), "{a} {p:?}: {argv:?}");
            }
        }
    }
    assert!(seen >= 3, "{argv:?}");
    let envs: Vec<_> = wrapped
        .get_envs()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    assert!(
        !envs.iter().any(|k| k == "XDG_RUNTIME_DIR" || k == "WAYLAND_DISPLAY"),
        "{envs:?}"
    );
}
