//! `runtime doctor [<app|file>] [--json]`: a read-only health report.
//!
//! * no argument: the system checks (host architecture, Wine, Vulkan, display, audio: the PulseAudio-compatible
//!   socket Wine 10 uses);
//! * an installed app id: those plus the app's program (PE facts, imports against Wine's DLLs, prefix state) and
//!   its Wine graphics driver setting (read from the prefix's `user.reg`, as `runtime display` does);
//! * a file (the target is classified like `run`'s: it contains `/` or ends in `.exe`/`.zip`): the same PE and
//!   import checks on the file, which is NOT installed. Only Wine's own DLLs count for its imports (the file's
//!   directory is not scanned: `runtime run <file>` copies just the file into a prefix).
//!
//! **Read-only.** Nothing is created, changed or removed. The facts are gathered by `rt_api::host::doctor` (see
//! there: the prefix is only audited, the only processes are `wine --version` and the bounded host probes); this
//! module finds the target, formats the report and prints the dependency hint.
//!
//! **Output.** Sections in a fixed order (Architecture, PE, Imports, Graphics, Audio, Runtime, Prefix, Program),
//! one line per check, marked `[ok]`, `[warn]` or `[FAIL]` (plain ASCII on purpose: the same bytes on any
//! terminal and in logs), then `Result:`. `--json` prints `{"subject", "verdict", "checks": [{"area", "status",
//! "text"}]}`; `area`, `status` and `verdict` are stable, `text` is prose and NOT a stable API. Every untrusted
//! string is escaped (`safe`, `json_safe`).
//!
//! **Exit code.** 1 when the verdict is `fail`, and for usage and I/O errors (an unknown app id, a file that does
//! not exist); 0 otherwise (a warning is not a failure).
use crate::CmdError;
use crate::safe::{json_safe, safe};
use rt_api::host::doctor::{Facts, area_id, report, status_id, verdict_id};
use rt_core::Target;
use rt_core::doctor::{Area, Report, Status, Subject, Verdict};
use serde_json::json;
use std::fmt::Write;
use std::path::Path;

pub fn run(target: Option<&str>, as_json: bool) -> Result<u8, CmdError> {
    // The target first, before Wine is looked for: an unknown id is reported as that.
    let found = match target {
        Some(t) => {
            let store = crate::store()?;
            let found = rt_core::find_target(&store, t, Path::new("."))?;
            Some((store, found))
        }
        None => None,
    };
    let vulkan = &rt_api::host::graphics::verdict_for;
    let facts = match &found {
        None => Facts::system(),
        Some((store, Target::Installed(id))) => Facts::app(store, id, vulkan),
        Some((_, Target::File(path))) => Facts::file(path),
    };
    let report = report(&facts, rt_api::host::graphics::host());
    crate::emit(&if as_json {
        render_json(&report)?
    } else {
        render(&report)
    })?;
    if let (Some(plan), Subject::App { id, .. }) = (&facts.plan, &report.subject) {
        if let Some(h) = crate::deps::hint_for(id, plan) {
            eprintln!("{h}");
        }
        for n in crate::deps::present_notes(plan) {
            eprintln!("{n}");
        }
    }
    Ok(u8::from(report.verdict == Verdict::Fail))
}

// ---------------------------------------------------------------- output

/// The order of the sections.
const ORDER: [Area; 8] = [
    Area::Architecture,
    Area::Pe,
    Area::Imports,
    Area::Graphics,
    Area::Audio,
    Area::Runtime,
    Area::Prefix,
    Area::Program,
];

/// The heading of an area.
fn heading(area: Area) -> &'static str {
    match area {
        Area::Architecture => "Architecture",
        Area::Pe => "PE",
        Area::Imports => "Imports",
        Area::Graphics => "Graphics",
        Area::Audio => "Audio",
        Area::Runtime => "Runtime",
        Area::Prefix => "Prefix",
        Area::Program => "Program",
    }
}

fn render(report: &Report) -> String {
    let mut o = String::from("Runtime Diagnostics\n\n");
    let _ = match &report.subject {
        Subject::System => writeln!(o, "System checks (no application given)"),
        Subject::File { path } => writeln!(o, "File: {}", safe(path)),
        Subject::App { id, name, version } => {
            let name = name
                .as_deref()
                .map_or_else(|| safe(id), |n| format!("{} ({})", safe(n), safe(id)));
            match version {
                Some(v) => writeln!(o, "Application: {name}, version {}", safe(v)),
                None => writeln!(o, "Application: {name}"),
            }
        }
    };
    for area in ORDER {
        let label = heading(area);
        let checks: Vec<_> = report.checks.iter().filter(|c| c.area == area).collect();
        if checks.is_empty() {
            continue;
        }
        let _ = writeln!(o, "\n{label}");
        for c in checks {
            let mark = match c.status {
                Status::Ok => "[ok]",
                Status::Warn => "[warn]",
                Status::Fail => "[FAIL]",
            };
            let _ = writeln!(o, "  {mark:<6} {}", safe(&c.text));
        }
    }
    let result = match report.verdict {
        Verdict::Good => "Looks good.",
        Verdict::MayFail => "Application may fail to start.",
        Verdict::Fail => "Application cannot run: fix the items marked [FAIL].",
    };
    let _ = write!(o, "\nResult: {result}\n");
    o
}

fn render_json(report: &Report) -> Result<String, CmdError> {
    let subject = match &report.subject {
        Subject::System => json!({"kind": "system"}),
        Subject::File { path } => json!({"kind": "file", "path": path}),
        Subject::App { id, name, version } => json!({"kind": "app", "id": id, "name": name, "version": version}),
    };
    let checks: Vec<_> = report
        .checks
        .iter()
        .map(|c| json!({"area": area_id(c.area), "status": status_id(c.status), "text": c.text}))
        .collect();
    let doc = json!({"subject": subject, "verdict": verdict_id(report.verdict), "checks": checks});
    Ok(format!("{}\n", json_safe(&serde_json::to_string_pretty(&doc)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_core::doctor::Check;

    fn check(area: Area, status: Status, text: &str) -> Check {
        Check {
            area,
            status,
            text: text.into(),
        }
    }

    #[test]
    fn the_layout_is_sections_in_order_marks_and_a_result_line() {
        let report = Report {
            subject: Subject::App {
                id: "app".into(),
                name: Some("My \u{1b}[31mApp".into()),
                version: Some("1.0".into()),
            },
            checks: vec![
                check(Area::Runtime, Status::Ok, "Wine: wine-10.0"),
                check(Area::Architecture, Status::Ok, "host architecture: x86-64"),
                check(Area::Imports, Status::Warn, "1 imported DLL not found: \"a.dll\""),
                check(Area::Prefix, Status::Fail, "a link leaves drive_c"),
            ],
            verdict: Verdict::Fail,
        };
        let want = "Runtime Diagnostics\n\
                    \n\
                    Application: My \\u{1b}[31mApp (app), version 1.0\n\
                    \n\
                    Architecture\n  [ok]   host architecture: x86-64\n\
                    \n\
                    Imports\n  [warn] 1 imported DLL not found: \"a.dll\"\n\
                    \n\
                    Runtime\n  [ok]   Wine: wine-10.0\n\
                    \n\
                    Prefix\n  [FAIL] a link leaves drive_c\n\
                    \n\
                    Result: Application cannot run: fix the items marked [FAIL].\n";
        assert_eq!(render(&report), want);
        for (verdict, line) in [
            (Verdict::Good, "Result: Looks good.\n"),
            (Verdict::MayFail, "Result: Application may fail to start.\n"),
        ] {
            let r = Report {
                subject: Subject::System,
                checks: vec![],
                verdict,
            };
            let out = render(&r);
            assert!(out.ends_with(line), "{out}");
            assert!(out.contains("System checks (no application given)"));
        }
    }

    #[test]
    fn a_file_subject_and_an_app_without_a_name_are_escaped_too() {
        let r = Report {
            subject: Subject::File {
                path: "a\u{1b}b\u{202e}.exe".into(),
            },
            checks: vec![],
            verdict: Verdict::Good,
        };
        let out = render(&r);
        assert!(out.contains("File: a\\u{1b}b\\u{202e}.exe"), "{out}");
        let r = Report {
            subject: Subject::App {
                id: "x".into(),
                name: None,
                version: None,
            },
            checks: vec![],
            verdict: Verdict::Good,
        };
        assert!(render(&r).contains("Application: x\n"));
        let r = Report {
            subject: Subject::App {
                id: "x".into(),
                name: Some("n\u{202e}".into()),
                version: Some("1\u{1b}[31m\u{9b}".into()),
            },
            checks: vec![],
            verdict: Verdict::Good,
        };
        let out = render(&r);
        assert!(
            out.contains("Application: n\\u{202e} (x), version 1\\u{1b}[31m\\u{9b}\n"),
            "{out}"
        );
    }

    #[test]
    fn a_check_text_is_escaped_even_though_core_already_escapes_it() {
        let r = Report {
            subject: Subject::System,
            checks: vec![check(Area::Runtime, Status::Warn, "x\u{1b}]0;t\u{7}\u{202e}")],
            verdict: Verdict::MayFail,
        };
        let out = render(&r);
        assert!(out.contains("x\\u{1b}]0;t\\u{7}\\u{202e}"), "{out}");
        assert!(!out.chars().any(|c| c.is_control() && c != '\n'));
    }

    #[test]
    fn every_area_has_a_place_in_the_order() {
        let all = [
            Area::Architecture,
            Area::Pe,
            Area::Imports,
            Area::Graphics,
            Area::Audio,
            Area::Runtime,
            Area::Prefix,
            Area::Program,
        ];
        for area in all {
            assert!(ORDER.contains(&area));
        }
        assert_eq!(ORDER.len(), all.len());
    }
}
