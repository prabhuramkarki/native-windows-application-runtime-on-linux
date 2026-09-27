//! Dependency engine: manifest, resolver, verified fetch and installers for runtime components.

pub mod capabilities;
pub mod fetch;
pub mod install_archive;
pub mod install_installer;
pub mod manifest;
pub mod orchestrate;
pub mod resolve;
pub mod state;
pub mod tarball;
pub mod wine_config;

pub use capabilities::capability_for;
pub use fetch::{FetchError, FetchOpts, cached, fetch};
pub use manifest::{ArchiveFormat, Extract, Install, Kind, Manifest, ManifestError, Marker, Package};
pub use orchestrate::{
    ALREADY_INSTALLED, AppLock, AppPlan, ConsentProvider, DepsError, Fetcher, LOCK_FILE, MARKER_PRESENT, NetFetcher,
    Orchestrator, REQUESTED_REASON, RunReport, VulkanFor, X64_ONLY_CAPS, check_backend, consent_text,
    discard_interrupted_for, drop_present_installers, install_plan, lock_app, lock_app_shared, plan_for_app,
    plan_for_pe, unix_now, wineservers_for,
};
pub use resolve::{
    Action, ConsentState, Facts, InstalledRef, InstalledSet, Plan, PlanEntry, block_for_vulkan, required_capabilities,
    resolve,
};
pub use state::{StateError, consent_of, forget, installed_set, record};

/// The major version in `wine --version`'s line (`wine-10.0 (Ubuntu ...)` gives 10).
#[cfg(test)]
fn wine_major(version: &str) -> Option<u32> {
    version
        .strip_prefix("wine-")?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// Real Wine for the `e2e_real_wine_*` and `real_net_wine_*` tests, discovered through `launcher`. These tests were
/// verified on Wine 10.0 only (CI's Ubuntu may ship 9.x), so an older Wine fails here, up front, with a clear message
/// instead of somewhere inside a prefix run.
#[cfg(test)]
pub(crate) fn real_wine_backend(launcher: &rt_core::Launcher) -> backend_wine::WineBackend {
    use rt_core::CompatBackend;
    let backend = backend_wine::WineBackend::discover_with(launcher.clone())
        .expect("Wine must be installed for the real-Wine tests (apt install wine)");
    let version = backend.version().expect("`wine --version` failed");
    assert!(
        wine_major(&version).is_some_and(|m| m >= 10),
        "the real-Wine dependency tests need Wine 10 or newer (verified on 10.0 only); found {version:?}. Install \
         Wine 10 (e.g. from WineHQ) to run them"
    );
    backend
}

/// The built `runtime` binary: the installer sandbox's `sandbox-init` shim in this crate's real-bwrap tests. It is
/// looked up next to this test binary (`target/<profile>/deps/<test>` -> `target/<profile>/runtime`), so the profile
/// and any `CARGO_TARGET_DIR` match. `cargo test -p runtime-deps` does not build it: a missing one fails loudly
/// (never a silent skip). Call it only where a real sandbox runs.
#[cfg(test)]
pub(crate) fn test_runtime_exe() -> std::path::PathBuf {
    let exe = test_runtime_path();
    assert!(
        exe.is_file(),
        "{exe:?} is missing: run `cargo build -p runtime-cli` first (the installer sandbox runs it as its \
         `sandbox-init` shim)"
    );
    exe
}

/// Where [`test_runtime_exe`] looks, without the check (for rigs whose tests may not run a sandbox at all).
#[cfg(test)]
pub(crate) fn test_runtime_path() -> std::path::PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the test binary is in target/<profile>/deps")
        .join("runtime")
}

#[cfg(test)]
#[test]
fn wine_major_reads_the_version_line() {
    assert_eq!(wine_major("wine-10.0 (Ubuntu 10.0~repack-12ubuntu1)"), Some(10));
    assert_eq!(wine_major("wine-9.0"), Some(9));
    assert_eq!(wine_major("wine-11.0-rc1"), Some(11));
    assert_eq!(wine_major("10.0"), None);
    assert_eq!(wine_major("wine-"), None);
}
