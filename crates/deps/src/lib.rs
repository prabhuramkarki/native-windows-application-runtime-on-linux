//! Dependency engine: manifest, resolver, verified fetch and installers for runtime components.

pub mod capabilities;
pub mod manifest;
pub mod resolve;

pub use capabilities::capability_for;
pub use manifest::{ArchiveFormat, Extract, Install, Kind, Manifest, ManifestError, Marker, Package};
pub use resolve::{
    Action, ConsentState, Facts, InstalledRef, InstalledSet, Plan, PlanEntry, required_capabilities, resolve,
};
