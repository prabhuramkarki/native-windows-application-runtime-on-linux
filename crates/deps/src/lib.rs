//! Dependency engine: manifest, resolver, verified fetch and installers for runtime components.

pub mod manifest;

pub use manifest::{Extract, Install, Kind, Manifest, ManifestError, Marker, Package};
