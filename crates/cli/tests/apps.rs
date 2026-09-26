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

#[test]
fn doctor_warns_about_a_managed_program_and_not_about_a_native_one() {
    let r = rig();
    let mut bytes = fs::read(fixture("hello64.exe")).unwrap();
    // a CLR header: data directory 14 (opt + 112 + 14 * 8 in a PE32+ header) gets a non-zero RVA and size
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let dir = pe + 24 + 112 + 14 * 8;
    bytes[dir..dir + 4].copy_from_slice(&0x2008u32.to_le_bytes());
    bytes[dir + 4..dir + 8].copy_from_slice(&72u32.to_le_bytes());
    let p = r.input("managed.exe", &bytes);
    let o = r.rt(&[OsString::from("install"), p.into_os_string()]);
    assert_ok(&o);
    let id = installed_id(&o);
    let out = s(&r.desktop().args(["doctor", &id]).output().unwrap().stdout);
    let l = lines_with(&out, ".NET");
    assert_eq!(l.len(), 1, "{out}");
    assert!(
        l[0].contains("[warn]") && l[0].contains("no .NET runtime is bundled") && l[0].contains("mscoree=d"),
        "{out}"
    );
    let j: serde_json::Value =
        serde_json::from_slice(&r.desktop().args(["doctor", &id, "--json"]).output().unwrap().stdout).unwrap();
    assert!(
        j["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["area"] == "runtime" && c["text"].as_str().unwrap().contains(".NET"))
    );
    let native = r.install();
    let out = s(&r.desktop().args(["doctor", &native]).output().unwrap().stdout);
    assert!(lines_with(&out, ".NET").is_empty(), "{out}");
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
    for (grant, why) in [
        (format!("{}:rw", sock.display()), "/tmp"),
        (format!("{}:ro", short.path().display()), "/tmp"),
        (format!("{}:rw", home.join(".bashrc").display()), "not a directory"),
        ("/run/docker.sock:rw".into(), "/run"),
        ("/run/dbus:ro".into(), "/run"),
        ("/tmp:ro".into(), "/tmp"),
        ("/tmp/.X11-unix:ro".into(), "/tmp/.X11-unix"),
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
fn fake_bwrap(r: &Rig) {
    let body = "echo \"$*\" >> @LOG@/bwrap.txt\nwhile [ $# -gt 0 ] && [ \"$1\" != -- ]; do shift; done\n\
                [ $# -gt 0 ] || exit 0\nshift\nexec \"$@\""
        .replace("@LOG@", r.log.to_str().unwrap());
    script(&r.bin.join("bwrap"), &body);
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
            " --bind {0} {0} --bind {1} {1} --remount-ro / -- /bin/sh -c ",
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
        err.contains(&format!(
            "{id} has run in the sandbox, so its Wine helpers must run sandboxed too"
        )) && err.contains("nothing was changed"),
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
        "profile ",
        "  host directory ",
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
