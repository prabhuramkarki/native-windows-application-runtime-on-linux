//! The per-app sandbox: the validated permission profile (`permissions.toml`) that decides what a program may
//! reach. This crate never trusts the file it reads: see [`permissions`].
pub mod permissions;

pub use permissions::{
    Access, FsGrant, GrantCtx, Network, PermError, Permissions, Refusal, load, load_opt, reset, store, validate_grant,
};
