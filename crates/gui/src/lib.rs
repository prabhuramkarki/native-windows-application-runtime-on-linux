//! `runtime-gui`: a GTK 4 + libadwaita client of `runtimed` (docs/superpowers/specs/2026-09-27-gui-client-design.md).
//! It talks only to the daemon, through `rt_daemon::client::Client`.
pub mod ui;
pub mod vm;
