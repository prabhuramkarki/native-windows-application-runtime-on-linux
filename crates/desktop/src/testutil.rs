//! Test-only helper shared by `entry::tests` and `mime::tests`: gating a real-subprocess test on an external
//! tool's presence, matching `rt_installer::sandbox`'s `RUNTIME_REQUIRE_BWRAP` convention (Tasks 5/6) — skip
//! loudly by default (a dev machine may lack the tool), but let `RUNTIME_REQUIRE_<TOOL>` turn that into a hard
//! failure (CI must run these for real).
use crate::xdg::find_on_path_real;
use std::path::PathBuf;

/// `Some(path)` if `name` is really on `$PATH`. Otherwise: `require_var` unset (or empty) prints why the test is
/// skipped and returns `None` (the test still reports as passed — `cargo test` has no "skipped" outcome for a
/// plain `#[test]`, and this crate's stderr is what documents that this coverage was not actually exercised);
/// `require_var` set makes the same situation a hard `panic!`.
pub(crate) fn require_tool(name: &str, require_var: &str) -> Option<PathBuf> {
    match find_on_path_real(name) {
        Some(p) => Some(p),
        None if std::env::var_os(require_var).is_some_and(|v| !v.is_empty()) => {
            panic!("{name} not found on $PATH and {require_var} is set: this test must run for real")
        }
        None => {
            eprintln!("SKIP: {name} not found on $PATH; this test needs it installed");
            None
        }
    }
}
