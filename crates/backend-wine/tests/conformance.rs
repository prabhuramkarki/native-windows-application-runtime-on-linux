//! The static tier of the backend conformance suite over the Wine backend: `WineBackend::from_found` with fake
//! `wine`/`wineserver` paths that are NOT executable, so an accidental spawn fails loudly instead of starting
//! anything. The live tier is in `e2e_wine.rs` (real Wine, `#[ignore]`d).
use backend_wine::WineBackend;
use backend_wine::discover::Found;
use rt_core::Launcher;
use rt_core::backend::conformance::{Scratch, static_checks};
use std::fs;

#[test]
fn the_wine_backend_passes_the_static_checks_without_starting_a_process() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("bin");
    fs::create_dir(&bin).unwrap();
    for f in ["wine", "wineserver"] {
        fs::write(bin.join(f), b"not a program: nothing may run it\n").unwrap();
    }
    let root = tmp.path().join("scratch");
    fs::create_dir(&root).unwrap();
    let scratch = Scratch::new(&root);
    // What `prepare` would have made and `command` requires: the app's own `HOME`.
    fs::create_dir(scratch.env.root().join("runtime/home")).unwrap();
    let found = Found {
        wine: bin.join("wine"),
        wineserver: bin.join("wineserver"),
        dll_dirs: vec![bin.clone()],
    };
    let b = WineBackend::from_found(found, Launcher::with_host_env([("PATH", "/nonexistent")]));
    let failures = static_checks(&b, &scratch);
    let text: Vec<String> = failures.iter().map(ToString::to_string).collect();
    assert!(failures.is_empty(), "wine fails:\n{}", text.join("\n"));
}
