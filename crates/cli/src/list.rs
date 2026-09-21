//! `runtime list [--json]`.
use crate::CmdError;
use crate::safe::{json_safe, safe, warn};
use serde_json::json;

pub fn run(as_json: bool) -> Result<(), CmdError> {
    let store = crate::store()?;
    let mut apps = Vec::new();
    let mut warned = false;
    for entry in store.list() {
        match entry {
            Ok((_env, md)) => apps.push(md),
            // A bad entry (corrupt metadata, a symlink, a stray file) never stops the listing.
            Err(w) => {
                warned = true;
                warn(&w.to_string());
            }
        }
    }
    if as_json {
        let rows: Vec<_> = apps
            .iter()
            .map(|m| {
                json!({
                    "id": m.id.as_str(), "name": m.name, "version": m.version,
                    "architecture": m.architecture, "executable": m.executable, "created": m.created,
                })
            })
            .collect();
        return crate::emit(&format!("{}\n", json_safe(&serde_json::to_string_pretty(&rows)?)));
    }
    if apps.is_empty() && warned {
        return crate::emit(
            "No usable apps (every entry was skipped, see the warnings above). Install one with: runtime install <file>\n",
        );
    }
    if apps.is_empty() {
        return crate::emit("No apps installed. Install one with: runtime install <file>\n");
    }
    let mut rows = vec![["ID", "NAME", "VERSION", "ARCH", "EXECUTABLE"].map(String::from)];
    for m in &apps {
        rows.push([
            safe(m.id.as_str()),
            safe(&m.name),
            m.version.as_deref().map_or_else(|| "-".into(), safe),
            safe(&m.architecture),
            safe(&m.executable),
        ]);
    }
    let width = |col: usize| rows.iter().map(|r| r[col].chars().count()).max().unwrap_or(0);
    let widths: Vec<usize> = (0..4).map(width).collect();
    let mut out = String::new();
    for r in &rows {
        for (cell, w) in r.iter().zip(&widths) {
            out.push_str(&format!("{cell:<w$}  "));
        }
        out.push_str(&r[4]);
        out.push('\n');
    }
    crate::emit(&out)
}
