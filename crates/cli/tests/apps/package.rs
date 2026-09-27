//! `runtime pack`, `inspect`, `unpack` and `import` (Phase 6D), over the fake-Wine rig of `apps.rs` (included from
//! there as a module so the rig is not copied). A `.wrun` can only request: these tests check that `import` grants
//! nothing, touches no existing app, leaves nothing after a failure, and that `permissions`/`deps` show the requests.
use super::*;
use std::io::{Read, Write};

/// A portable package: `App/hello64.exe` and a data file, two dependencies (one consent-gated), two permissions.
const DEMO: &str = "format = 1\nid = \"demo\"\nname = \"Demo App\"\nversion = \"1.0.0\"\narch = \"x86_64\"\n\
    dependencies = [\"vcrun2022\", \"dxvk\"]\n\n[entry]\nkind = \"portable\"\nexe = \"payload/App/hello64.exe\"\n\n\
    [permissions]\nnetwork = \"allow\"\ngpu = \"off\"\n";

/// `in/<name>/` with `wrun.toml` = `manifest` and `payload/<path>` for each of `files`.
fn pkg_dir(r: &Rig, name: &str, manifest: &str, files: &[(&str, Vec<u8>)]) -> PathBuf {
    let dir = r.inputs.join(name);
    for (path, bytes) in files {
        let p = dir.join("payload").join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, bytes).unwrap();
    }
    fs::write(dir.join("wrun.toml"), manifest).unwrap();
    dir
}

fn hello() -> Vec<u8> {
    fs::read(fixture("hello64.exe")).unwrap()
}

/// `runtime pack in/<name> -o in/<name>.wrun`; returns the package.
fn pack(r: &Rig, name: &str, manifest: &str, files: &[(&str, Vec<u8>)]) -> PathBuf {
    let dir = pkg_dir(r, name, manifest, files);
    let out = r.inputs.join(format!("{name}.wrun"));
    let o = r.rt(&["pack".as_ref(), dir.as_os_str(), "-o".as_ref(), out.as_os_str()]);
    assert_ok(&o);
    out
}

fn demo(r: &Rig) -> PathBuf {
    pack(
        r,
        "demo",
        DEMO,
        &[("App/hello64.exe", hello()), ("App/data.txt", b"some data\n".to_vec())],
    )
}

/// The data dir's entries (what `inspect`/`unpack` must never touch).
fn data_tree(r: &Rig) -> Vec<String> {
    r.tree().into_iter().filter(|l| l.starts_with("/data")).collect()
}

/// Every file below `dir` with its bytes.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = vec![];
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            let m = fs::symlink_metadata(&p).unwrap();
            if m.is_dir() {
                stack.push(p.clone());
                out.push((p, vec![]));
            } else if m.is_file() {
                out.push((p.clone(), fs::read(&p).unwrap()));
            } else {
                out.push((p.clone(), fs::read_link(&p).unwrap().into_os_string().into_vec()));
            }
        }
    }
    out.sort();
    out
}

/// A copy of `src` with `path`'s bytes passed through `edit` (entry order and every other byte kept).
fn rewrite(src: &Path, dst: &Path, path: &str, edit: impl Fn(&mut Vec<u8>)) {
    let mut a = zip::ZipArchive::new(fs::File::open(src).unwrap()).unwrap();
    let mut w = zip::ZipWriter::new(fs::File::create(dst).unwrap());
    let o = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o644);
    for i in 0..a.len() {
        let mut e = a.by_index(i).unwrap();
        let name = e.name().to_owned();
        let mut bytes = vec![];
        e.read_to_end(&mut bytes).unwrap();
        if name == path {
            edit(&mut bytes);
        }
        w.start_file(name, o).unwrap();
        w.write_all(&bytes).unwrap();
    }
    w.finish().unwrap();
}

fn with_home(r: &Rig, args: &[&str]) -> Output {
    let home = r.grants.path().canonicalize().unwrap();
    r.cmd().env("HOME", &home).args(args).output().unwrap()
}

#[test]
fn pack_inspect_and_unpack_round_trip_and_touch_no_app() {
    let r = rig();
    let wrun = demo(&r);
    let before = data_tree(&r);

    let o = r.rt(&["inspect".as_ref(), wrun.as_os_str()]);
    assert_ok(&o);
    let out = s(&o.stdout);
    for want in [
        "Package:   demo 1.0.0\n",
        "Name:      Demo App\n",
        "Arch:      x86_64\n",
        "Kind:      portable (payload/App/hello64.exe)\n",
        "Files:     2 (",
        "unsigned: its origin is not verified\n",
        "Already installed: no\n",
        "It would request:\n",
        "  dependency vcrun2022: needs your consent when you run `runtime deps demo --install`\n",
        "  dependency dxvk: installed by `runtime deps demo --install` (no consent needed)\n",
        "  permission network=allow: not granted; you can grant it with `runtime permissions demo --set=network=allow`\n",
        "  permission gpu=off: not granted; you can grant it with `runtime permissions demo --set=gpu=off`\n",
    ] {
        assert!(out.contains(want), "{want:?} in {out}");
    }
    let j = json(&r.rt(&["inspect".as_ref(), wrun.as_os_str(), "--json".as_ref()]));
    assert_eq!(
        (&j["id"], &j["name"], &j["version"], &j["arch"], &j["kind"], &j["entry"]),
        (
            &"demo".into(),
            &"Demo App".into(),
            &"1.0.0".into(),
            &"x86_64".into(),
            &"portable".into(),
            &"payload/App/hello64.exe".into()
        )
    );
    assert_eq!(
        (&j["files"], &j["signed"], &j["installed"]),
        (&2.into(), &false.into(), &false.into())
    );
    assert_eq!(j["digest"].as_str().unwrap().len(), 64);
    assert!(
        out.contains(&format!("Digest:    {}\n", j["digest"].as_str().unwrap())),
        "{out}"
    );
    assert_eq!(
        j["requests"],
        serde_json::json!({
            "dependencies": [{"id": "vcrun2022", "consent": "needed"}, {"id": "dxvk", "consent": "none"}],
            "permissions": ["network=allow", "gpu=off"],
        })
    );

    let dest = r.inputs.join("unpacked");
    assert_ok(&r.rt(&["unpack".as_ref(), wrun.as_os_str(), "-o".as_ref(), dest.as_os_str()]));
    assert_eq!(fs::read(dest.join("payload/App/hello64.exe")).unwrap(), hello());
    assert_eq!(fs::read(dest.join("payload/App/data.txt")).unwrap(), b"some data\n");
    // Unpacked and packed again: byte-identical (the manifest is the canonical one with [[files]] stripped).
    let manifest = fs::read_to_string(dest.join("wrun.toml")).unwrap();
    let stripped = &manifest[..manifest.find("\n[[files]]").unwrap()];
    fs::write(dest.join("wrun.toml"), format!("{stripped}\n")).unwrap();
    let again = r.inputs.join("again.wrun");
    assert_ok(&r.rt(&["pack".as_ref(), dest.as_os_str(), "-o".as_ref(), again.as_os_str()]));
    assert_eq!(fs::read(&again).unwrap(), fs::read(&wrun).unwrap());

    // An existing destination and an existing output are refused, and left as they were.
    let o = r.rt(&["unpack".as_ref(), wrun.as_os_str(), "-o".as_ref(), dest.as_os_str()]);
    assert_fails(&o);
    assert!(dest.join("payload/App/data.txt").is_file());
    let o = r.rt(&[
        "pack".as_ref(),
        r.inputs.join("demo").as_os_str(),
        "-o".as_ref(),
        again.as_os_str(),
    ]);
    assert_fails(&o);
    assert_eq!(fs::read(&again).unwrap(), fs::read(&wrun).unwrap());

    assert_eq!(data_tree(&r), before, "inspect/unpack/pack touched the data dir");
    assert!(r.app_dirs().is_empty());
    assert_eq!(r.calls(), Vec::<String>::new(), "no Wine was run");
}

#[test]
fn inspect_and_unpack_refuse_a_tampered_package_and_leave_nothing() {
    let r = rig();
    let wrun = demo(&r);
    let bad = r.inputs.join("bad.wrun");
    rewrite(&wrun, &bad, "payload/App/data.txt", |b| b[0] ^= 1);
    let err = assert_fails(&r.rt(&["inspect".as_ref(), bad.as_os_str()]));
    assert!(err.contains("does not match the manifest"), "{err}");
    let dest = r.inputs.join("out");
    let err = assert_fails(&r.rt(&["unpack".as_ref(), bad.as_os_str(), "-o".as_ref(), dest.as_os_str()]));
    assert!(err.contains("does not match the manifest"), "{err}");
    assert!(!dest.exists(), "unpack left its destination behind");
}

#[test]
fn inspect_escapes_a_hostile_name_and_refuses_unknown_dependencies() {
    let r = rig();
    // `pack` refuses such a name, so the package is built by hand.
    let wrun = r.inputs.join("evil.wrun");
    let manifest = DEMO.replace("Demo App", "Evil\\u001b]0;pwned\\u0007\\u202e")
        + "\n[[files]]\npath = \"payload/App/hello64.exe\"\nsize = 1\nsha256 = \"00\"\n";
    {
        let mut w = zip::ZipWriter::new(fs::File::create(&wrun).unwrap());
        let o = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        w.start_file("wrun.toml", o).unwrap();
        w.write_all(manifest.as_bytes()).unwrap();
        w.start_file("payload/App/hello64.exe", o).unwrap();
        w.write_all(b"x").unwrap();
        w.finish().unwrap();
    }
    for cmd in ["inspect", "import"] {
        let o = r.rt(&[cmd.as_ref(), wrun.as_os_str()]);
        let err = assert_fails(&o);
        assert_tame(&err, "stderr");
        assert_tame(&s(&o.stdout), "stdout");
    }

    let unknown = pack(
        &r,
        "unknown",
        &DEMO.replace("\"dxvk\"", "\"no-such-package\""),
        &[("App/hello64.exe", hello())],
    );
    for cmd in ["inspect", "import"] {
        let err = assert_fails(&r.rt(&[cmd.as_ref(), unknown.as_os_str()]));
        assert!(err.contains("no-such-package"), "{err}");
        assert!(err.contains("not in the runtime's dependency manifest"), "{err}");
    }
    assert!(r.app_dirs().is_empty());
}

#[test]
fn import_creates_the_app_records_the_requests_and_grants_nothing() {
    let r = rig();
    let wrun = demo(&r);
    let o = r.rt(&["import".as_ref(), wrun.as_os_str()]);
    assert_ok(&o);
    let out = s(&o.stdout);
    assert_eq!(installed_id(&o), "demo");
    assert!(
        out.contains("It would request:\n"),
        "the inspect summary comes first: {out}"
    );
    assert!(out.contains("unsigned: its origin is not verified\n"), "{out}");
    for want in [
        "Nothing was granted or installed. To grant what the package requested:\n",
        "  runtime permissions demo --set=network=allow\n",
        "  runtime permissions demo --set=gpu=off\n",
        "  runtime deps demo --install\n",
    ] {
        assert!(out.contains(want), "{want:?} in {out}");
    }
    let app = r.apps().join("demo");
    assert!(
        !app.join("permissions.toml").exists(),
        "import wrote a permissions.toml"
    );
    let exe = app.join("prefix/drive_c/Program Files/demo/App/hello64.exe");
    assert_eq!(fs::read(exe).unwrap(), hello());
    let md: serde_json::Value = serde_json::from_slice(&fs::read(app.join("metadata.json")).unwrap()).unwrap();
    assert_eq!(md["schemaVersion"], 4);
    assert_eq!(md["name"], "Demo App");
    let p = &md["package"];
    assert_eq!((&p["id"], &p["version"]), (&"demo".into(), &"1.0.0".into()));
    assert_eq!(p["requestedDependencies"], serde_json::json!(["vcrun2022", "dxvk"]));
    assert_eq!(
        p["requestedPermissions"],
        serde_json::json!(["network=allow", "gpu=off"])
    );
    let j = json(&r.rt(&["inspect".as_ref(), wrun.as_os_str(), "--json".as_ref()]));
    assert_eq!((&p["digest"], &j["installed"]), (&j["digest"], &true.into()));
    // Nothing ran: the prefix was prepared, the program never started.
    assert!(!r.calls().iter().any(|c| c == "wine <app>"), "{:?}", r.calls());

    // `permissions` shows what is requested and not granted, with the grant command; `--set` then satisfies it.
    let o = with_home(&r, &["permissions", "demo"]);
    assert_ok(&o);
    let out = s(&o.stdout);
    for want in [
        "requested by the package (not granted): network=allow; grant it with `runtime permissions demo \
         --set=network=allow`\n",
        "requested by the package (not granted): gpu=off; grant it with `runtime permissions demo --set=gpu=off`\n",
    ] {
        assert!(out.contains(want), "{want:?} in {out}");
    }
    let j = json(&with_home(&r, &["permissions", "demo", "--json"]));
    assert_eq!(j["requested"], serde_json::json!(["network=allow", "gpu=off"]));
    assert_ok(&with_home(&r, &["permissions", "demo", "--set=network=allow"]));
    let out = s(&with_home(&r, &["permissions", "demo"]).stdout);
    assert!(!out.contains("network=allow;"), "{out}");
    assert!(out.contains("(not granted): gpu=off;"), "{out}");
    let j = json(&with_home(&r, &["permissions", "demo", "--json"]));
    assert_eq!(j["requested"], serde_json::json!(["gpu=off"]));

    // `deps` plans the requested packages behind the unchanged consent; showing the plan installs nothing.
    let (tree, calls) = (r.tree(), r.calls());
    let o = r.rt(&["deps", "demo"]);
    assert_ok(&o);
    let out = s(&o.stdout);
    assert!(
        out.contains(": to install, needs your consent (requested by the package)\n") && out.contains("vcrun2022"),
        "{out}"
    );
    assert!(
        out.contains("Install with: runtime deps demo --install [--yes vcrun2022]"),
        "{out}"
    );
    assert_eq!((r.tree(), r.calls()), (tree, calls), "`deps demo` changed something");
}

#[test]
fn import_with_a_taken_id_is_refused_and_the_existing_app_is_untouched() {
    let r = rig();
    let wrun = demo(&r);
    assert_ok(&r.rt(&["import".as_ref(), wrun.as_os_str()]));
    let before = snapshot(&r.apps());
    let calls = r.calls();
    let o = r.rt(&["import".as_ref(), wrun.as_os_str()]);
    let err = assert_fails(&o);
    assert!(err.contains("demo is already installed"), "{err}");
    assert!(err.contains("runtime remove demo"), "{err}");
    assert_eq!(snapshot(&r.apps()), before, "the existing app changed");
    assert_eq!(r.calls(), calls, "no backend call for a taken id");
    assert_eq!(r.app_dirs(), ["demo"]);
}

#[test]
fn a_tampered_payload_or_a_portable_with_installer_flags_leaves_no_app() {
    let r = rig();
    let wrun = demo(&r);
    let bad = r.inputs.join("bad.wrun");
    rewrite(&wrun, &bad, "payload/App/data.txt", |b| b[3] ^= 0x20);
    let err = assert_fails(&r.rt(&["import".as_ref(), bad.as_os_str()]));
    assert!(err.contains("data.txt"), "{err}");
    assert!(r.app_dirs().is_empty(), "the half-built app was left behind");
    assert!(!r.data.join("staging").exists() || fs::read_dir(r.data.join("staging")).unwrap().next().is_none());

    for flag in ["--network", "--silent"] {
        let err = assert_fails(&r.rt(&["import".as_ref(), wrun.as_os_str(), flag.as_ref()]));
        assert!(
            err.contains("--silent/--network only apply to installer packages"),
            "{err}"
        );
    }
    assert!(r.app_dirs().is_empty());
}

#[test]
fn a_failed_installer_import_leaves_no_app_and_no_staged_file() {
    let r = rig();
    let manifest = "format = 1\nid = \"setup\"\nname = \"Setup\"\nversion = \"1\"\narch = \"x86_64\"\n\n[entry]\n\
        kind = \"installer\"\ninstaller = \"payload/hello.msi\"\n";
    let wrun = pack(
        &r,
        "setup",
        manifest,
        &[("hello.msi", fs::read(fixture("hello.msi")).unwrap())],
    );
    // The fake Wine has no msiexec.exe: the pipeline runs and fails after the environment was created.
    let o = r.rt(&["import".as_ref(), wrun.as_os_str(), "--silent".as_ref()]);
    let err = assert_fails(&o);
    assert!(err.contains("msiexec.exe"), "{err}");
    assert!(r.calls().iter().any(|c| c == "wine wineboot"), "{:?}", r.calls());
    assert!(r.app_dirs().is_empty(), "the half-built app was left behind");
    let staging = r.data.join("staging");
    assert!(staging.is_dir(), "the staging directory is made on demand");
    assert_eq!(fs::metadata(&staging).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(
        fs::read_dir(&staging).unwrap().count(),
        0,
        "the staged installer is removed"
    );
}

#[test]
fn an_imported_app_gets_the_same_sandbox_as_an_installed_one() {
    let r = rig();
    let manifest = "format = 1\nid = \"imported-app\"\nname = \"Flat\"\nversion = \"1\"\narch = \"x86_64\"\n\n[entry]\n\
        kind = \"portable\"\nexe = \"payload/hello64.exe\"\n\n[permissions]\nnetwork = \"allow\"\n";
    let wrun = pack(&r, "flat", manifest, &[("hello64.exe", hello())]);
    assert_ok(&r.rt(&["import".as_ref(), wrun.as_os_str()]));
    // Distinct ids that no other part of the command line contains.
    let local = r.install_as("hello64.exe", &["--name", "installed-app"]);
    assert_eq!(local, "installed-app");
    let command = |id: &str| {
        let out = s(&r.rt(&["sandbox", id]).stdout);
        lines_with(&out, "command: ")[0].replace(id, "ID")
    };
    assert_eq!(command("imported-app"), command("installed-app"));
}
