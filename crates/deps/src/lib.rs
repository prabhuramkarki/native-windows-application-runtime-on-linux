//! Dependency engine: manifest, resolver, verified fetch and installers for runtime components.

pub mod manifest;

pub use manifest::{ArchiveFormat, Extract, Install, Kind, Manifest, ManifestError, Marker, Package};
