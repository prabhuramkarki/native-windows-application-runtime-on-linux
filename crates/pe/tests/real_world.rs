//! Oracle test against real binaries. Ignored by default: run with
//!   RUNTIME_SAMPLES=/dir1:/dir2 cargo test -p runtime-pe --test real_world -- --ignored --nocapture
//! Compares our analysis with `file(1)` for every .exe/.dll/.sys/.ocx found (extension is only
//! used to *find* candidates here; detection itself never looks at it).
use pe::{Arch, Format, Kind, Subsystem};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        let p = e.path();
        if ft.is_dir() {
            walk(&p, out);
        } else if ft.is_file() {
            let ext = p.extension().and_then(|x| x.to_str()).map(str::to_ascii_lowercase);
            if matches!(ext.as_deref(), Some("exe" | "dll" | "sys" | "ocx")) {
                out.push(p);
            }
        }
    }
}

#[test]
#[ignore]
fn matches_file_command_on_real_binaries() {
    let roots = std::env::var("RUNTIME_SAMPLES").expect("set RUNTIME_SAMPLES=/dir1:/dir2");
    let mut files = vec![];
    for r in roots.split(':') {
        walk(Path::new(r), &mut files);
    }
    let (mut checked, mut failures) = (0, vec![]);
    for f in &files {
        let Ok(bytes) = fs::read(f) else { continue };
        if pe::detect(&bytes) != pe::FileKind::Pe {
            continue;
        }
        let oracle = String::from_utf8(Command::new("file").arg("-b").arg(f).output().unwrap().stdout).unwrap();
        let info = match pe::analyze(&bytes) {
            Ok(i) => i,
            Err(e) => {
                failures.push(format!("{}: analyze failed: {e} (file says: {oracle})", f.display()));
                continue;
            }
        };
        checked += 1;
        let mut bad = vec![];
        if oracle.contains("PE32+") != (info.format == Format::Pe32Plus) {
            bad.push("format");
        }
        let want_arch = if oracle.contains("x86-64") {
            Some(Arch::X86_64)
        } else if oracle.contains("Intel 80386") {
            Some(Arch::X86)
        } else if oracle.contains("ARM64") {
            Some(Arch::Arm64)
        } else {
            None
        };
        if want_arch.is_some_and(|a| a != info.arch) {
            bad.push("arch");
        }
        if oracle.contains("(DLL)") != (info.kind == Kind::Dll) {
            bad.push("kind");
        }
        if oracle.contains("(console)") && info.subsystem != Subsystem::Console
            || oracle.contains("(GUI)") && info.subsystem != Subsystem::Gui
        {
            bad.push("subsystem");
        }
        if !bad.is_empty() {
            failures.push(format!("{}: {bad:?} differ from file(1): {oracle}", f.display()));
        }
        if !info.warnings.is_empty() {
            println!("note {}: {:?}", f.display(), info.warnings);
        }
    }
    println!("checked {checked} PE files");
    assert!(checked > 0, "no PE files found under RUNTIME_SAMPLES");
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
