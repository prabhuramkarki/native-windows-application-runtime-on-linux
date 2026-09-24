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

pub use capabilities::capability_for;
pub use fetch::{FetchError, FetchOpts, cached, fetch};
pub use manifest::{ArchiveFormat, Extract, Install, Kind, Manifest, ManifestError, Marker, Package};
pub use orchestrate::{
    AppLock, AppPlan, ConsentProvider, DepsError, Fetcher, LOCK_FILE, NetFetcher, Orchestrator, RunReport,
    consent_text, discard_interrupted_for, install_plan, lock_app, lock_app_shared, plan_for_app, unix_now,
    wineservers_for,
};
pub use resolve::{
    Action, ConsentState, Facts, InstalledRef, InstalledSet, Plan, PlanEntry, required_capabilities, resolve,
};
pub use state::{StateError, consent_of, forget, installed_set, record};
