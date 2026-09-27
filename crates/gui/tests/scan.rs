//! Spec D4: the GUI talks only to `runtimed`. No file under `src` names the in-process API, starts a process (std,
//! GLib or GIO), launches a URI or another app, opens a network socket, uses the daemon's server side, or links the
//! CLI; the view model and the backend import no toolkit.
use std::fs;
use std::path::{Path, PathBuf};

/// Anywhere under `src`.
const NEVER: &[&str] = &[
    "Runtime::",
    "rt_api::Runtime",
    "runtime_cli",
    // Processes: std, and GLib/GIO's own spawning.
    "process::Command",
    "Command::new",
    "os::unix::process",
    "Subprocess",
    "spawn_async",
    "spawn_sync",
    "spawn_command_line",
    "spawn_check",
    // Handing a URI or file to another app.
    "UriLauncher",
    "FileLauncher",
    "launch_default_for_uri",
    "AppInfo",
    "show_uri",
    // Network sockets.
    "std::net",
    "SocketClient",
];
/// The only parts of `rt_daemon` the GUI may name: the client and the protocol constants.
const DAEMON_ALLOWED: &[&str] = &["client", "protocol"];
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
        for (i, _) in text.match_indices("rt_daemon::") {
            let rest = &text[i + "rt_daemon::".len()..];
            if !DAEMON_ALLOWED.iter().any(|a| rest.starts_with(a)) {
                let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                found.push(format!("{}: rt_daemon::{name}", rel.display()));
            }
        }
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
    fs::write(
        d.path().join("more.rs"),
        "gio::Subprocess::newv(); glib::spawn_async(); gtk::UriLauncher::new(); std::net::TcpStream; \
         rt_daemon::server::serve(); rt_daemon::client::Client; glib::spawn_future_local(f);\n",
    )
    .unwrap();
    let mut v = violations(d.path());
    v.sort();
    assert_eq!(
        v,
        [
            "backend.rs: Command::new",
            "backend.rs: adw",
            "backend.rs: process::Command",
            "more.rs: Subprocess",
            "more.rs: UriLauncher",
            "more.rs: rt_daemon::server",
            "more.rs: spawn_async",
            "more.rs: std::net",
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
