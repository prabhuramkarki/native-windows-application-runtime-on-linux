//! The per-app sandbox: the validated permission profile (`permissions.toml`) that decides what a program may
//! reach. This crate never trusts the file it reads: see [`permissions`].
pub mod permissions;

pub use permissions::{
    Access, FsGrant, GrantCtx, Network, PermError, Permissions, Refusal, account_home, load, load_opt, load_opt_raw,
    reset, store, validate_grant, validate_grant_for,
};
