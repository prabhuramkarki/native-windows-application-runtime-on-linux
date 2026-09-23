//! Registers `runtime` as a handler for `.exe`/`.msi` files (Phase 3 Task 7), so a file manager's double-click
//! or "Open With" can hand a Windows installer straight to `runtime install`.
//!
//! **No new MIME type is defined.** `.exe` (`application/x-msdownload`) and `.msi` (`application/x-msi`) are
//! already registered, with their own glob patterns, by every distro's `shared-mime-info` package (verified on
//! this machine's own `/usr/share/mime/packages/freedesktop.org.xml`). Defining a second, competing MIME type
//! for the same extensions would be redundant at best and could shadow the system's own detection at worst,
//! so this module only REFERENCES those two existing types — nothing here calls `update-mime-database`, because
//! nothing here writes anything under a `mime/packages/` directory for it to process; only
//! `update-desktop-database` (which rebuilds `applications/mimeinfo.cache`, the file that actually makes a
//! desktop shell offer `runtime` for "Open With") is called, and it runs through
//! [`crate::entry::refresh_desktop_database`] like every other `.desktop` write in this crate.
//!
//! **One `.desktop` file, not two.** The brief allows either "`MimeType=` + a second `.desktop` for the install
//! action" or "one `.desktop` with both"; this module writes one, `runtime-installer.desktop`, that carries
//! both `MimeType=` and `Exec=runtime install %f`. A second `.desktop` with an `Actions=` group pointing at the
//! very same `Exec=` line would be pure duplication for no behavioural difference — a file manager's "Open
//! With"/double-click path is driven entirely by `MimeType=` on an ordinary entry, no `Actions=` group needed.
//! `NoDisplay=true` is deliberately NOT set: some desktop environments also exclude `NoDisplay` entries from
//! their "Open With" list (not just the main app grid), which would silently defeat the one feature this module
//! exists to add; the accepted cost is that "Install with Runtime" also shows up once, harmlessly, in the
//! ordinary application menu.
use crate::entry::{self, DesktopError};
use crate::xdg;
use std::ffi::OsString;

const FILE_NAME: &str = "runtime-installer.desktop";

fn render() -> String {
    let mut s = String::new();
    s.push_str("[Desktop Entry]\n");
    s.push_str("Type=Application\n");
    s.push_str("Name=Install with Runtime\n");
    s.push_str("Exec=runtime install %f\n");
    s.push_str("Terminal=false\n");
    s.push_str("Categories=System;\n");
    s.push_str("MimeType=application/x-msdownload;application/x-msi;\n");
    s
}

/// Writes/overwrites `~/.local/share/applications/runtime-installer.desktop` (idempotent: same fixed content
/// every time) and refreshes `applications/mimeinfo.cache`. Called once per successful install by
/// `installer::pipeline` — cheap and idempotent, so no "already registered" bookkeeping is needed; a user who
/// deleted the file gets it back on their next install.
pub fn register() -> Result<(), DesktopError> {
    register_with_env(&|k| std::env::var_os(k))
}

pub(crate) fn register_with_env(env: &impl Fn(&str) -> Option<OsString>) -> Result<(), DesktopError> {
    let apps_dir = xdg::applications_dir_from(env)?;
    entry::write_validated_desktop_file(&apps_dir, &apps_dir.join(FILE_NAME), &render())?;
    entry::refresh_desktop_database(&apps_dir);
    Ok(())
}

#[cfg(test)]
mod tests;
