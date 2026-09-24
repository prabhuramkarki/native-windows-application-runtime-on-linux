//! Dependency engine: manifest, resolver, verified fetch and installers for runtime components.

pub mod capabilities;
pub mod fetch;
pub mod install_archive;
pub mod manifest;
pub mod resolve;
pub mod state;
pub mod tarball;

pub use capabilities::capability_for;
pub use fetch::{FetchError, FetchOpts, cached, fetch};
pub use manifest::{ArchiveFormat, Extract, Install, Kind, Manifest, ManifestError, Marker, Package};
pub use resolve::{
    Action, ConsentState, Facts, InstalledRef, InstalledSet, Plan, PlanEntry, required_capabilities, resolve,
};
pub use state::{StateError, consent_of, forget, installed_set, record};
