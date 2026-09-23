//! `.desktop` launcher generation for an installed app (Phase 3 Task 7).
//!
//! [`write`] turns an app's [`Metadata`] and already-extracted icon PNGs (see [`crate::icon`]) into a real
//! `~/.local/share/applications/runtime-<id>.desktop` and its `~/.local/share/icons/hicolor/<size>x<size>/apps/
//! runtime-<id>.png` files, so the app shows up in a normal desktop menu/launcher. [`remove`] deletes exactly
//! those files back out again.
//!
//! **Filenames are derived from [`AppId`] alone, nothing is tracked in a manifest** (this crate's own ruling,
//! matching the rest of the codebase's "derive, don't store" philosophy — see `rt_core::store::AppEnv`, every
//! path on which is a derived method, never a stored list). [`remove`] therefore does not need to know which
//! icon sizes a given app actually got; it attempts every path [`HICOLOR_SIZES`] could have produced and treats
//! "was never written" (`NotFound`) as success, not an error.
//!
//! **`.desktop`'s own escaping is not shell-quoting and not `rt_core::text`/the CLI's `crate::safe`.** Every
//! value written here goes through [`escape_value`] (a plain `string`-type Desktop Entry value) or
//! [`escape_exec_arg`] (`Exec=`'s own additional argument-quoting rules), both implemented from the Desktop
//! Entry Specification directly and tested against a REAL `desktop-file-validate` subprocess, never reused from
//! or generalised into this project's terminal-injection sanitiser (a `.desktop` file is parsed by a desktop
//! shell, not printed to a terminal — a different threat model with its own spec).
//!
//! **Validation is a hard error.** [`write`] never leaves an invalid `.desktop` file at its real path: the
//! content is built, written to a private temp file next to the target (same directory, so the final
//! `fs::rename` is on one filesystem), validated with a real `desktop-file-validate` subprocess, and only
//! renamed into place on success; a validation failure — or the tool being missing entirely — removes the temp
//! file and returns [`DesktopError`]. This mirrors `rt_installer::sandbox`'s `BwrapNotFound`: a required
//! external tool being absent is this crate's own hard error, not a silent skip (skipping loudly is a
//! TEST-only convention, see `crate::testutil`).
//!
//! **What a failure here does NOT do:** it does not fail the app's install. `installer::pipeline` calls this
//! module only after the app itself is fully installed and runnable via `runtime run <id>`; a `.desktop` entry
//! is additive desktop-shell integration, not core functionality — exactly the same "cosmetic, never
//! load-bearing" stance Task 6 already took for icon extraction. See `crates/installer/src/pipeline.rs`.
use crate::xdg::{self, XdgError};
use rt_core::{AppEnv, AppId, Metadata};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

/// hicolor sizes this crate writes/removes icons at (also what `installer::pipeline` requests from
/// `crate::icon::extract_icon_png`). Fixed and public so a caller of [`write`] and this module's own [`remove`]
/// always agree on exactly which paths exist.
pub const HICOLOR_SIZES: [u32; 5] = [16, 32, 48, 128, 256];

/// Longest `Name=` value this module emits, in UTF-8 bytes, after escaping. Not a Desktop Entry Specification
/// limit (it does not set one) — this crate's own defensive cap, well under `rt_core::meta::MAX_NAME_LEN` (256,
/// itself already a cap on `Metadata.name`): a menu label this long is never usefully rendered by any desktop
/// shell, so cutting it here (rather than trusting every future caller of `render` to have already capped it)
/// is cheap insurance.
pub const MAX_DISPLAY_NAME_LEN: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum DesktopError {
    #[error("{0}")]
    Xdg(#[from] XdgError),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("desktop-file-validate was not found on $PATH: install desktop-file-utils")]
    ValidatorNotFound,
    #[error("the generated .desktop file failed validation: {0}")]
    Invalid(String),
}

fn desktop_file_name(id: &AppId) -> String {
    format!("runtime-{id}.desktop")
}
fn icon_file_name(id: &AppId) -> String {
    format!("runtime-{id}.png")
}
fn icon_name(id: &AppId) -> String {
    format!("runtime-{id}")
}

/// Cuts `s` to at most `max_bytes` bytes, on a character boundary.
fn truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Escapes `s` for a `.desktop` key of value type `string` (Desktop Entry Specification, "Value Types"): every
/// backslash becomes `\\` (the spec's general escape rule — an unescaped backslash is ambiguous with the escape
/// sequences `\s`/`\n`/`\t`/`\r`/`\\` a reader may apply to a value). Every control character (`char::is_control`
/// — a raw newline, tab, CR, ESC, every other C0/C1 code) and every Unicode bidi/format character
/// (`rt_core::is_format`) is DROPPED, never encoded: turning a hostile embedded newline into the spec's own
/// `\n` escape sequence would still let a parser render its effect (e.g. what looks like a second `Name=`
/// line), even though the literal byte is gone from the file, so nothing here round-trips one back in — a
/// `.desktop` value stays exactly one physical line, full stop.
fn escape_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if c.is_control() || rt_core::is_format(c) {
            continue;
        } else {
            out.push(c);
        }
    }
    out
}

/// Characters that force an `Exec=` argument to be double-quoted (Desktop Entry Specification, "Exec variables"
/// § reserved characters). This is not "characters a shell treats specially" (`runtime` itself never invokes a
/// shell to run `Exec=`) — it is the exact set the SPEC reserves, because a `.desktop`-aware launcher parses
/// `Exec=` itself using these same rules.
const EXEC_RESERVED: [char; 19] = [
    ' ', '\t', '\n', '"', '\'', '\\', '>', '<', '~', '|', '&', ';', '$', '*', '?', '#', '(', ')', '`',
];

/// Escapes one `Exec=` argument per the Desktop Entry Specification's "Exec variables" quoting rules:
/// 1. Control/format characters are dropped (same policy as [`escape_value`]).
/// 2. A literal `%` becomes `%%` — `Exec=`'s own field-code escape (`%f`, `%u`, ...), independent of quoting.
/// 3. The general `string`-type escape applies: a literal backslash becomes `\\`.
/// 4. If the (post-steps-1-3) argument contains any [`EXEC_RESERVED`] character, it is wrapped in double quotes,
///    and each of `"`, `` ` ``, `$`, `\` inside is escaped with one more preceding backslash — applied AFTER
///    step 3's backslash-doubling, per the spec's own worked example ("to unambiguously represent a literal
///    backslash character in a quoted argument ... it must be escaped twice: once following the general
///    escaping rule and once following the quoting rule").
///
/// Every case here (spaces, `%`, double/single quotes, backslashes, `$(...)`-shaped text) was checked against a
/// real `desktop-file-validate` subprocess, not just asserted in-process (`crates/desktop/src/entry/tests.rs`).
fn escape_exec_arg(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .filter(|&c| !(c.is_control() || rt_core::is_format(c)))
        .collect();
    let percent_doubled = filtered.replace('%', "%%");
    let needs_quoting = percent_doubled.chars().any(|c| EXEC_RESERVED.contains(&c));
    let general = percent_doubled.replace('\\', "\\\\");
    if !needs_quoting {
        return general;
    }
    let mut out = String::with_capacity(general.len() + 2);
    out.push('"');
    for c in general.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// The exact `.desktop` content [`write`] places at `applications/runtime-<id>.desktop`. Pure and directly
/// testable for exact-match assertions; `has_icon` controls whether an `Icon=` line is emitted at all (an app
/// with no extractable icon gets none — a missing `Icon=` is valid, `desktop-file-validate` accepts it).
fn render(id: &AppId, name: &str, has_icon: bool) -> String {
    let name = escape_value(truncate(name, MAX_DISPLAY_NAME_LEN));
    let exec_id = escape_exec_arg(id.as_str());
    let mut s = String::new();
    s.push_str("[Desktop Entry]\n");
    s.push_str("Type=Application\n");
    s.push_str(&format!("Name={name}\n"));
    s.push_str(&format!("Exec=runtime run {exec_id}\n"));
    if has_icon {
        s.push_str(&format!("Icon={}\n", icon_name(id)));
    }
    s.push_str("Terminal=false\n");
    s.push_str("Categories=Utility;\n");
    s
}

/// Strips control/format characters from tool output before it can reach an error message (subprocess
/// stdout/stderr is untrusted the moment the input it complains about was attacker-controlled), and caps it.
fn clean_message(s: &str) -> String {
    const MAX: usize = 500;
    let filtered: String = s
        .chars()
        .filter(|&c| !(c.is_control() || rt_core::is_format(c)))
        .collect();
    truncate(filtered.trim(), MAX).to_owned()
}

/// Runs a real `desktop-file-validate` subprocess on `path`. `Ok(())` only on a clean pass; the tool being
/// missing from `$PATH` and a real validation failure are both errors (see the module docs on why this crate
/// treats a required external tool as a hard error, not a skip).
fn validate_desktop_file(path: &Path) -> Result<(), DesktopError> {
    let tool = xdg::find_on_path_real("desktop-file-validate").ok_or(DesktopError::ValidatorNotFound)?;
    let output = Command::new(tool).arg(path).output()?;
    if output.status.success() {
        Ok(())
    } else {
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Err(DesktopError::Invalid(clean_message(&text)))
    }
}

/// Best-effort: refreshes `applications/mimeinfo.cache` (and similar caches) so a desktop shell picks up a
/// freshly written or removed `.desktop` file promptly. `update-desktop-database` missing, or failing, is never
/// an error here — a stale cache self-heals the next time anything else in `dir` changes it, and a fresh
/// `.desktop` file is still found by any lookup that does not rely on the cache at all.
pub(crate) fn refresh_desktop_database(dir: &Path) {
    if let Some(tool) = xdg::find_on_path_real("update-desktop-database") {
        // Best-effort per the doc comment above: its own stdout/stderr (e.g. a complaint about a directory that
        // does not exist yet, or an unrelated malformed `.desktop` file already sitting in `dir`) is noise this
        // crate has already decided not to act on, not something worth passing through to whatever inherited
        // these streams.
        let _ = Command::new(tool)
            .arg(dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Writes `bytes` as `final_path` (whose parent must be `dir`): a private temp file next to it
/// (`xdg::create_temp`, suffix `.desktop` so `desktop-file-validate` will look at it by name), validated with a
/// real subprocess, then renamed into place only on success. The temp file is removed on every failure path.
pub(crate) fn write_validated_desktop_file(dir: &Path, final_path: &Path, content: &str) -> Result<(), DesktopError> {
    fs::create_dir_all(dir)?;
    let (tmp, mut f) = xdg::create_temp(dir, 0o644, ".desktop")?;
    let write_result = {
        use std::io::Write;
        f.write_all(content.as_bytes()).and_then(|()| f.sync_all())
    };
    drop(f);
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    if let Err(e) = validate_desktop_file(&tmp) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, final_path)?;
    Ok(())
}

/// Writes one icon PNG's bytes to `final_path` (whose parent must be `dir`) the same private-temp-then-rename
/// way as [`write_validated_desktop_file`], minus the validation step (nothing inspects an icon file by
/// filename the way `desktop-file-validate` does a `.desktop`).
fn write_icon_file(dir: &Path, final_path: &Path, bytes: &[u8]) -> Result<(), DesktopError> {
    fs::create_dir_all(dir)?;
    let (tmp, mut f) = xdg::create_temp(dir, 0o644, "")?;
    let write_result = {
        use std::io::Write;
        f.write_all(bytes).and_then(|()| f.sync_all())
    };
    drop(f);
    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    fs::rename(&tmp, final_path)?;
    Ok(())
}

/// Writes `~/.local/share/applications/runtime-<id>.desktop` and, for every `(size, png_bytes)` pair in
/// `icon_pngs`, `~/.local/share/icons/hicolor/<size>x<size>/apps/runtime-<id>.png`. `meta.name` becomes `Name=`
/// (already the best available name — see `crates/installer/src/pipeline.rs`'s own resolution — never
/// re-derived here). `meta.id` (== `app.id()`) becomes both the filename stem and the `Exec=runtime run <id>`
/// argument. See the module docs for what a failure here does and does not affect.
pub fn write(app: &AppEnv, meta: &Metadata, icon_pngs: &[(u32, Vec<u8>)]) -> Result<(), DesktopError> {
    write_with_env(app, meta, icon_pngs, &|k| std::env::var_os(k))
}

pub(crate) fn write_with_env(
    app: &AppEnv,
    meta: &Metadata,
    icon_pngs: &[(u32, Vec<u8>)],
    env: &impl Fn(&str) -> Option<OsString>,
) -> Result<(), DesktopError> {
    let id = app.id();
    let content = render(id, &meta.name, !icon_pngs.is_empty());
    let apps_dir = xdg::applications_dir_from(env)?;
    write_validated_desktop_file(&apps_dir, &apps_dir.join(desktop_file_name(id)), &content)?;

    for (size, bytes) in icon_pngs {
        let icon_dir = xdg::hicolor_apps_dir_from(env, *size)?;
        write_icon_file(&icon_dir, &icon_dir.join(icon_file_name(id)), bytes)?;
    }

    refresh_desktop_database(&apps_dir);
    Ok(())
}

fn remove_file_ignore_missing(path: &Path) -> Result<(), DesktopError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Deletes exactly the files [`write`] could have created for `id`: `applications/runtime-<id>.desktop` and
/// `icons/hicolor/<size>x<size>/apps/runtime-<id>.png` for every size in [`HICOLOR_SIZES`] — no glob, no
/// manifest, purely derived from `id` (Ruling 1). A file that was never written (e.g. no icon was ever
/// extracted for this app) is not an error: every deletion here is "remove if present". Every deletion is
/// attempted regardless of an earlier one's outcome; the first genuine I/O error (never a missing-file one) is
/// what is returned, once every path has been tried.
pub fn remove(id: &AppId) -> Result<(), DesktopError> {
    remove_with_env(id, &|k| std::env::var_os(k))
}

pub(crate) fn remove_with_env(id: &AppId, env: &impl Fn(&str) -> Option<OsString>) -> Result<(), DesktopError> {
    let apps_dir = xdg::applications_dir_from(env)?;
    let mut first_err = remove_file_ignore_missing(&apps_dir.join(desktop_file_name(id))).err();
    refresh_desktop_database(&apps_dir);

    for size in HICOLOR_SIZES {
        let icon_dir = xdg::hicolor_apps_dir_from(env, size)?;
        if let Err(e) = remove_file_ignore_missing(&icon_dir.join(icon_file_name(id))) {
            first_err.get_or_insert(e);
        }
    }
    match first_err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
