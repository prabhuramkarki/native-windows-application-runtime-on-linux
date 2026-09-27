//! Spec D4: the GUI talks only to `runtimed`. No file under `src` names the in-process API, starts a process or
//! links the CLI; the view model and the backend import no toolkit.
use std::fs;
use std::path::{Path, PathBuf};

/// Anywhere under `src`.
const NEVER: &[&str] = &["Runtime::", "rt_api::Runtime", "process::Command", "runtime_cli"];
/// Under `src/vm` and in `src/backend.rs` (whole words: `gio` must not match "region").
const NO_TOOLKIT: &[&str] = &["gtk4", "libadwaita", "adw", "glib", "gio", "gdk4", "gsk4"];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn has_word(text: &str, word: &str) -> bool {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    text.match_indices(word)
        .any(|(i, _)| !text[..i].ends_with(ident) && !text[i + word.len()..].starts_with(ident))
}

/// Every violation under `src`, as "file: what".
fn violations(src: &Path) -> Vec<String> {
    let mut files = vec![];
    rust_files(src, &mut files);
    assert!(!files.is_empty(), "no sources under {src:?}");
    let mut found = vec![];
    for f in files {
        let text = fs::read_to_string(&f).unwrap();
        let rel = f.strip_prefix(src).unwrap();
        found.extend(
            NEVER
                .iter()
                .filter(|n| text.contains(*n))
                .map(|n| format!("{}: {n}", rel.display())),
        );
        if rel.starts_with("vm") || rel == Path::new("backend.rs") {
            found.extend(
                NO_TOOLKIT
                    .iter()
                    .filter(|w| has_word(&text, w))
                    .map(|w| format!("{}: {w}", rel.display())),
            );
        }
    }
    found
}

#[test]
fn the_scanner_finds_what_it_looks_for() {
    let d = tempfile::tempdir().unwrap();
    fs::create_dir(d.path().join("vm")).unwrap();
    fs::write(d.path().join("vm/mod.rs"), "use gtk4::glib; // region\n").unwrap();
    fs::write(
        d.path().join("backend.rs"),
        "adw::init(); std::process::Command::new(\"x\");\n",
    )
    .unwrap();
    fs::write(d.path().join("ui.rs"), "use gtk4::glib; rt_api::Runtime::new();\n").unwrap();
    let mut v = violations(d.path());
    v.sort();
    assert_eq!(
        v,
        [
            "backend.rs: adw",
            "backend.rs: process::Command",
            "ui.rs: Runtime::",
            "ui.rs: rt_api::Runtime",
            "vm/mod.rs: glib",
            "vm/mod.rs: gtk4",
        ]
    );
}

#[test]
fn the_gui_talks_only_to_runtimed_and_its_model_has_no_toolkit() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert!(
        src.join("vm/mod.rs").is_file(),
        "the view model moved: update this scan"
    );
    assert_eq!(violations(&src), Vec::<String>::new());
}
