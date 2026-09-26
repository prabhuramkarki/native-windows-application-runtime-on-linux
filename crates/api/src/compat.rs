//! The compatibility matrix: `compat.toml` (embedded), strict parsing, and the one table that is both `runtime
//! compat` and `docs/COMPAT.md` (a test fails when the two drift). Every record is something that was really run.
//! Parsing is safe for any text: unknown fields, control characters, oversize input and inconsistent records are
//! errors, never panics.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::OnceLock;

/// Input above this is rejected before parsing (`toml` has no input cap of its own).
pub const MAX_BYTES: usize = 256 * 1024;
pub const MAX_RECORDS: usize = 500;
/// Longest attacker-controlled value echoed in an error message.
const MAX_ECHO: usize = 40;

const HEADER: &str = "\
# Compatibility matrix

<!-- Generated from crates/api/compat.toml; do not edit by hand. Regenerate with:
     cargo run -q -p runtime-cli -- compat > docs/COMPAT.md -->

Each row is something that was really run: `ci:<job>` is a CI job run that passed, `manual:<date>` was run by
hand on that date on the recorded Wine and GPU. A program that is not listed has not been tested.

";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Works,
    Partial,
    Broken,
    Untested,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Works => "works",
            Status::Partial => "partial",
            Status::Broken => "broken",
            Status::Untested => "untested",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub app: String,
    #[serde(default)]
    pub version: Option<String>,
    pub status: Status,
    pub wine: String,
    #[serde(default)]
    pub gpu: Option<String>,
    #[serde(default)]
    pub graphics: bool,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compat {
    #[serde(default, rename = "record")]
    pub records: Vec<Record>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CompatError {
    #[error("compat file is {size} bytes, over the {} byte limit", MAX_BYTES)]
    TooLarge { size: usize },
    #[error("compat file is not valid TOML for the schema: {0}")]
    Toml(String),
    #[error("compat file has an unknown field: {0}")]
    UnknownField(String),
    #[error("{0} records, over the limit of {MAX_RECORDS}")]
    TooManyRecords(usize),
    #[error("record {record:?}: invalid {field} (non-empty, bounded, no control characters)")]
    BadField { record: String, field: &'static str },
    #[error("record {0:?}: works, partial and broken need `evidence`")]
    MissingEvidence(String),
    #[error("record {0:?}: evidence must be ci:<job> or manual:<YYYY-MM-DD>")]
    BadEvidence(String),
    #[error("record {0:?}: graphics = true needs `gpu`")]
    GraphicsNeedsGpu(String),
    #[error("record {0:?} appears twice for the same version, wine and gpu")]
    Duplicate(String),
}

/// Truncate an echoed value so an error never carries unbounded text.
fn clip(s: &str) -> String {
    let mut it = s.chars();
    let head: String = it.by_ref().take(MAX_ECHO).collect();
    if it.next().is_some() {
        format!("{head}...")
    } else {
        head
    }
}

/// Non-empty, at most `max` bytes, no control characters.
fn valid_text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}

/// `ci:<job>` or `manual:<YYYY-MM-DD>` (digits, month 1-12, day 1-31; no calendar, so no date crate).
fn valid_evidence(e: &str) -> bool {
    if let Some(job) = e.strip_prefix("ci:") {
        return !job.is_empty();
    }
    let Some(d) = e.strip_prefix("manual:") else {
        return false;
    };
    let b = d.as_bytes();
    let n = |r: std::ops::Range<usize>| {
        d.get(r)
            .filter(|s| s.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|s| s.parse::<u32>().ok())
    };
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && n(0..4).is_some()
        && matches!(n(5..7), Some(1..=12))
        && matches!(n(8..10), Some(1..=31))
}

impl Compat {
    /// Parse and fully validate compat text.
    pub fn parse(text: &str) -> Result<Compat, CompatError> {
        if text.len() > MAX_BYTES {
            return Err(CompatError::TooLarge { size: text.len() });
        }
        let c: Compat = toml::from_str(text).map_err(|e| {
            let msg = clip(e.message());
            if msg.starts_with("unknown field") {
                CompatError::UnknownField(msg)
            } else {
                CompatError::Toml(msg)
            }
        })?;
        if c.records.len() > MAX_RECORDS {
            return Err(CompatError::TooManyRecords(c.records.len()));
        }
        let mut seen = HashSet::new();
        for r in &c.records {
            r.check()?;
            if !seen.insert((&r.app, &r.version, &r.wine, &r.gpu)) {
                return Err(CompatError::Duplicate(clip(&r.app)));
            }
        }
        Ok(c)
    }
}

impl Record {
    fn check(&self) -> Result<(), CompatError> {
        let record = || clip(&self.app);
        let bad = |field| CompatError::BadField {
            record: record(),
            field,
        };
        let text = |field, v: &Option<String>, max| match v {
            Some(s) if !valid_text(s, max) => Err(bad(field)),
            _ => Ok(()),
        };
        if !valid_text(&self.app, 80) {
            return Err(bad("app"));
        }
        if !valid_text(&self.wine, 40) {
            return Err(bad("wine"));
        }
        text("version", &self.version, 40)?;
        text("gpu", &self.gpu, 120)?;
        text("notes", &self.notes, 300)?;
        match &self.evidence {
            Some(e) if !valid_text(e, 80) || !valid_evidence(e) => return Err(CompatError::BadEvidence(record())),
            None if self.status != Status::Untested => return Err(CompatError::MissingEvidence(record())),
            _ => {}
        }
        if self.graphics && self.gpu.is_none() {
            return Err(CompatError::GraphicsNeedsGpu(record()));
        }
        Ok(())
    }
}

/// The compat file shipped in the binary, parsed once.
pub fn bundled() -> &'static Compat {
    static BUNDLED: OnceLock<Compat> = OnceLock::new();
    // A test parses the same file, so this cannot fail in a released build.
    BUNDLED.get_or_init(|| Compat::parse(include_str!("../compat.toml")).expect("bundled compat.toml is invalid"))
}

/// One markdown table cell: `|` escaped, absent values `-`. (Text is already free of control characters.)
fn cell(s: Option<&str>) -> String {
    s.map_or_else(|| "-".to_owned(), |s| s.replace('|', "\\|"))
}

/// The markdown of `docs/COMPAT.md` and of `runtime compat`.
pub fn render_table(c: &Compat) -> String {
    let mut out = String::from(HEADER);
    out.push_str(
        "| App | Version | Status | Wine | GPU | Evidence | Notes |\n| --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for r in &c.records {
        let gpu = r.gpu.as_deref().map(|g| {
            if r.graphics {
                format!("{g} (graphics)")
            } else {
                g.to_owned()
            }
        });
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} |\n",
            cell(Some(&r.app)),
            cell(r.version.as_deref()),
            r.status.as_str(),
            cell(Some(&r.wine)),
            cell(gpu.as_deref()),
            cell(r.evidence.as_deref()),
            cell(r.notes.as_deref()),
        ));
    }
    out
}

/// `[{app, version, status, wine, gpu, graphics, evidence, notes}]`; absent optional fields are null.
pub fn render_json(c: &Compat) -> String {
    let rows: Vec<_> = c
        .records
        .iter()
        .map(|r| {
            serde_json::json!({
                "app": r.app, "version": r.version, "status": r.status.as_str(), "wine": r.wine,
                "gpu": r.gpu, "graphics": r.graphics, "evidence": r.evidence, "notes": r.notes,
            })
        })
        .collect();
    serde_json::to_string_pretty(&rows).unwrap_or_default() + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
[[record]]
app = "hello64.exe"
status = "works"
wine = "10.0"
evidence = "ci:wine-e2e"
notes = "runs | exits 7"

[[record]]
app = "Some Game"
version = "1.2"
status = "partial"
wine = "10.0"
gpu = "Intel UHD 620"
graphics = true
evidence = "manual:2026-09-26"

[[record]]
app = "Unknown"
status = "untested"
wine = "10.0"
evidence = "ci:x"
"#;

    /// `VALID` with one record swapped in, for the rejection tests.
    fn one(body: &str) -> String {
        format!("[[record]]\napp = \"a\"\nwine = \"10.0\"\n{body}\n")
    }

    #[test]
    fn a_valid_file_renders_a_stable_table() {
        let c = Compat::parse(VALID).unwrap();
        assert_eq!(c.records.len(), 3);
        let want = format!(
            "{HEADER}\
| App | Version | Status | Wine | GPU | Evidence | Notes |\n\
| --- | --- | --- | --- | --- | --- | --- |\n\
| hello64.exe | - | works | 10.0 | - | ci:wine-e2e | runs \\| exits 7 |\n\
| Some Game | 1.2 | partial | 10.0 | Intel UHD 620 (graphics) | manual:2026-09-26 | - |\n\
| Unknown | - | untested | 10.0 | - | ci:x | - |\n"
        );
        assert_eq!(render_table(&c), want);
    }

    #[test]
    fn json_is_valid_and_escapes_strings() {
        let c = Compat::parse(&one(
            "status = \"untested\"\nnotes = \"say \\\"hi\\\" \\\\ \\u2028 </td>\"",
        ))
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&render_json(&c)).unwrap();
        assert_eq!(v[0]["notes"], "say \"hi\" \\ \u{2028} </td>");
        assert_eq!(v[0]["status"], "untested");
        assert!(v[0]["version"].is_null() && v[0]["evidence"].is_null());
        assert_eq!(v[0]["graphics"], false);
    }

    #[test]
    fn rejects_unknown_fields_and_unknown_status() {
        let e = Compat::parse(&one("status = \"untested\"\nextra = 1")).unwrap_err();
        assert!(matches!(e, CompatError::UnknownField(_)), "{e:?}");
        let e = Compat::parse(&one("status = \"fine\"")).unwrap_err();
        assert!(matches!(e, CompatError::Toml(_)), "{e:?}");
        let e = Compat::parse("[[record]]\napp = \"a\"\nstatus = \"untested\"\nwine = \"1\"\n[other]\n").unwrap_err();
        assert!(matches!(e, CompatError::UnknownField(_)), "{e:?}");
    }

    #[test]
    fn evidence_is_required_for_a_result_but_allowed_on_untested() {
        for s in ["works", "partial", "broken"] {
            let e = Compat::parse(&one(&format!("status = \"{s}\""))).unwrap_err();
            assert!(matches!(e, CompatError::MissingEvidence(_)), "{s}: {e:?}");
        }
        Compat::parse(&one("status = \"untested\"")).unwrap();
        Compat::parse(&one("status = \"untested\"\nevidence = \"ci:job\"")).unwrap();
    }

    #[test]
    fn rejects_bad_evidence() {
        for ev in [
            "ci:",
            "manual:31-02-2026",
            "manual:2026-13-01",
            "manual:2026-00-10",
            "manual:2026-01-32",
            "manual:2026-1-01",
            "manual:",
            "other:x",
            "",
            "ci:has\\u0007bell",
        ] {
            let e = Compat::parse(&one(&format!("status = \"works\"\nevidence = \"{ev}\""))).unwrap_err();
            assert!(matches!(e, CompatError::BadEvidence(_)), "{ev:?}: {e:?}");
        }
        Compat::parse(&one("status = \"works\"\nevidence = \"manual:2026-12-31\"")).unwrap();
    }

    #[test]
    fn graphics_needs_a_gpu() {
        let e = Compat::parse(&one("status = \"untested\"\ngraphics = true")).unwrap_err();
        assert!(matches!(e, CompatError::GraphicsNeedsGpu(_)), "{e:?}");
        Compat::parse(&one("status = \"untested\"\ngraphics = true\ngpu = \"x\"")).unwrap();
    }

    #[test]
    fn rejects_control_characters_and_overlong_or_empty_text() {
        for body in [
            "status = \"untested\"\nnotes = \"a\\u001b[2Jb\"",
            "status = \"untested\"\nnotes = \"a\\nb\"",
            "status = \"untested\"\nnotes = \"a\\u0085b\"",
            "status = \"untested\"\nnotes = \"\"",
            "status = \"untested\"\nversion = \"\"",
            "status = \"untested\"\nnotes = \"x\"\nversion = \"1\\u0000\"",
        ] {
            let e = Compat::parse(&one(body)).unwrap_err();
            assert!(matches!(e, CompatError::BadField { .. }), "{body}: {e:?}");
        }
        let e = Compat::parse("[[record]]\napp = \"a\\u0007\"\nstatus = \"untested\"\nwine = \"1\"\n").unwrap_err();
        assert!(matches!(e, CompatError::BadField { field: "app", .. }), "{e:?}");
        for (field, max) in [("notes", 300), ("version", 40), ("gpu", 120)] {
            let ok = "x".repeat(max);
            Compat::parse(&one(&format!("status = \"untested\"\n{field} = {ok:?}"))).unwrap();
            let long = "x".repeat(max + 1);
            let e = Compat::parse(&one(&format!("status = \"untested\"\n{field} = {long:?}"))).unwrap_err();
            assert!(matches!(e, CompatError::BadField { .. }), "{field}: {e:?}");
        }
        let long = "x".repeat(81);
        let e = Compat::parse(&format!(
            "[[record]]\napp = {long:?}\nstatus = \"untested\"\nwine = \"1\"\n"
        ))
        .unwrap_err();
        assert!(matches!(e, CompatError::BadField { field: "app", .. }), "{e:?}");
    }

    #[test]
    fn caps_records_and_bytes() {
        let rec = |i: usize| format!("[[record]]\napp = \"a{i}\"\nstatus = \"untested\"\nwine = \"1\"\n");
        let many = |n: usize| (0..n).map(rec).collect::<String>();
        assert_eq!(Compat::parse(&many(500)).unwrap().records.len(), 500);
        let e = Compat::parse(&many(501)).unwrap_err();
        assert!(matches!(e, CompatError::TooManyRecords(501)), "{e:?}");
        let big = format!("{}\n# {}\n", many(1), "x".repeat(MAX_BYTES));
        let e = Compat::parse(&big).unwrap_err();
        assert!(matches!(e, CompatError::TooLarge { .. }), "{e:?}");
    }

    #[test]
    fn rejects_a_duplicate_tuple_but_not_a_different_one() {
        let rec = |extra: &str| format!("[[record]]\napp = \"a\"\nstatus = \"untested\"\nwine = \"10.0\"\n{extra}\n");
        let e = Compat::parse(&format!("{}{}", rec(""), rec(""))).unwrap_err();
        assert!(matches!(e, CompatError::Duplicate(_)), "{e:?}");
        for other in ["version = \"2\"", "gpu = \"g\""] {
            Compat::parse(&format!("{}{}", rec(""), rec(other))).unwrap();
        }
        let e = Compat::parse(&format!("{}{}", rec("notes = \"n\""), rec(""))).unwrap_err();
        assert!(matches!(e, CompatError::Duplicate(_)), "{e:?}");
    }

    /// Hostile input never panics: every single-byte deletion, replacement and insertion of the valid file.
    #[test]
    fn mutations_of_a_valid_file_never_panic() {
        let base = VALID.as_bytes();
        let parse = |b: &[u8]| {
            let _ = Compat::parse(&String::from_utf8_lossy(b));
        };
        for i in 0..base.len() {
            let mut d = base.to_vec();
            d.remove(i);
            parse(&d);
            for b in [0u8, b'"', b'\n', b'[', b'=', 0xff, 0x1b, b'\\'] {
                let mut r = base.to_vec();
                r[i] = b;
                parse(&r);
                let mut n = base.to_vec();
                n.insert(i, b);
                parse(&n);
            }
        }
        parse(&base[..base.len() / 2]);
    }

    #[test]
    fn the_bundled_file_is_valid_and_every_record_has_evidence() {
        let c = bundled();
        assert!(!c.records.is_empty());
        for r in &c.records {
            assert!(r.evidence.is_some(), "{}", r.app);
        }
    }

    #[test]
    fn compat_md_matches_records() {
        let want = render_table(bundled());
        assert!(
            include_str!("../../../docs/COMPAT.md") == want,
            "docs/COMPAT.md is out of date with crates/api/compat.toml; regenerate it with:\n  \
             cargo run -q -p runtime-cli -- compat > docs/COMPAT.md"
        );
    }
}
