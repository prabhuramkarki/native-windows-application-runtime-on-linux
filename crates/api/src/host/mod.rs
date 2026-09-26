//! Host probes: the fact-gathering code behind `doctor`, `runtime sandbox`, `runtime graphics info` and the
//! dependency plan, shared by the CLI (which formats the facts for people) and [`crate::Runtime`] (which returns
//! them as sanitised wire types). NOT part of the stable API contract: these functions return raw, unsanitised
//! host and app data and may change with the CLI; the stable surface is [`crate::Runtime`] and [`crate::types`].
pub mod doctor;
pub mod graphics;
pub mod sandbox;
