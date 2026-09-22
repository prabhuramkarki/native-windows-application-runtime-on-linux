//! The installer family, the per-family silent-flag matrix, and [`plan`], which turns a family
//! plus a silent/not choice into the program to run and the flags to pass it.
//!
//! This module is pure logic: no file I/O, no subprocess spawning. It never inspects a real
//! installer file itself (that is `pe::detect`/`pe::installer::detect` and MSI-magic sniffing,
//! done by the caller); it only maps an already-detected family to a flag list. Every enum here
//! is a closed set, so "hostile input" just means "cover every variant", which the tests do.
use std::ffi::OsString;

/// The installer technology a file was detected as, independent of file extension.
///
/// [`InstallerFamily::Msi`] is NOT one of `pe::InstallerKind`'s variants: MSI is a separate file
/// format (an OLE2/CFB compound file), detected by `pe::detect` returning `FileKind::Msi`, not by
/// a marker inside a PE file. [`InstallerFamily::Unknown`] covers anything else: a bare PE binary
/// with no installer marker, or a family this crate does not (yet) recognise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerFamily {
    Inno,
    Nsis,
    InstallShield,
    WixBurn,
    Msi,
    Unknown,
}

impl From<pe::InstallerKind> for InstallerFamily {
    fn from(kind: pe::InstallerKind) -> Self {
        match kind {
            pe::InstallerKind::InnoSetup => InstallerFamily::Inno,
            pe::InstallerKind::Nsis => InstallerFamily::Nsis,
            pe::InstallerKind::InstallShield => InstallerFamily::InstallShield,
            pe::InstallerKind::WixBurn => InstallerFamily::WixBurn,
        }
    }
}

/// The silent-install command-line switches for one `.exe`-based installer family, and a note on
/// how much to trust them (some are documented, standard flags; InstallShield's is a best effort).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SilentFlags {
    pub args: Vec<OsString>,
    pub note: &'static str,
}

fn os_args(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

/// The silent-flag entry for an `.exe`-based installer family, or `None` for [`InstallerFamily::Msi`]
/// (MSI silence is `msiexec` flags, handled in [`plan`], not flags passed to an exe) and
/// [`InstallerFamily::Unknown`] (never guess a flag for an unrecognised installer).
pub fn silent_flags(family: InstallerFamily) -> Option<SilentFlags> {
    match family {
        InstallerFamily::Inno => Some(SilentFlags {
            args: os_args(&["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"]),
            note: "Inno Setup: standard documented silent switches.",
        }),
        InstallerFamily::Nsis => Some(SilentFlags {
            args: os_args(&["/S"]),
            note: "NSIS: standard documented silent switch.",
        }),
        InstallerFamily::InstallShield => Some(SilentFlags {
            args: os_args(&["/s"]),
            note: "InstallShield: /s is unreliable; many InstallShield installers ignore it or still show UI \
                   unless a generated .iss response file is supplied alongside it.",
        }),
        InstallerFamily::WixBurn => Some(SilentFlags {
            args: os_args(&["/quiet", "/norestart"]),
            note: "WiX Burn: standard documented silent switches.",
        }),
        InstallerFamily::Msi | InstallerFamily::Unknown => None,
    }
}

/// The program a [`RunPlan`] should invoke. MSI files are never run directly: `msiexec` runs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Program {
    Exe,
    MsiExec,
}

/// What to run and which flags to pass it. Paths are deliberately NOT part of this type: the
/// caller (a later task's install pipeline) owns the installer's path and `msiexec`'s `/i <path>`
/// argument, and assembles the full argv from `program`, its own path, and `args`. This keeps a
/// pure flag-decision separate from path/containment handling, which belongs to the pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPlan {
    pub program: Program,
    pub args: Vec<OsString>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("no known silent-install flags for installer family {0:?}; refusing to guess one")]
    NoSilentFlags(InstallerFamily),
}

/// Decides what to run and which flags to pass, for a detected installer family.
///
/// Never applies a flag the caller did not ask for: `silent=false` always means "just run the
/// installer, showing its own UI" (an empty `args` for `Exe`, no extra `msiexec` flags for `Msi`).
/// `silent=true` on [`InstallerFamily::Unknown`] returns [`PlanError::NoSilentFlags`] rather than
/// guessing a flag that might not exist for that installer.
pub fn plan(kind: InstallerFamily, silent: bool) -> Result<RunPlan, PlanError> {
    if kind == InstallerFamily::Msi {
        let args = if silent {
            os_args(&["/qn", "/norestart"])
        } else {
            Vec::new()
        };
        return Ok(RunPlan {
            program: Program::MsiExec,
            args,
        });
    }
    if !silent {
        return Ok(RunPlan {
            program: Program::Exe,
            args: Vec::new(),
        });
    }
    match silent_flags(kind) {
        Some(flags) => Ok(RunPlan {
            program: Program::Exe,
            args: flags.args,
        }),
        None => Err(PlanError::NoSilentFlags(kind)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn os(strs: &[&str]) -> Vec<OsString> {
        strs.iter().map(OsString::from).collect()
    }

    #[test]
    fn table_every_family_and_silent_flag() {
        let cases: Vec<(InstallerFamily, bool, Program, Vec<OsString>)> = vec![
            (
                InstallerFamily::Inno,
                true,
                Program::Exe,
                os(&["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-"]),
            ),
            (InstallerFamily::Inno, false, Program::Exe, os(&[])),
            (InstallerFamily::Nsis, true, Program::Exe, os(&["/S"])),
            (InstallerFamily::Nsis, false, Program::Exe, os(&[])),
            (InstallerFamily::InstallShield, true, Program::Exe, os(&["/s"])),
            (InstallerFamily::InstallShield, false, Program::Exe, os(&[])),
            (
                InstallerFamily::WixBurn,
                true,
                Program::Exe,
                os(&["/quiet", "/norestart"]),
            ),
            (InstallerFamily::WixBurn, false, Program::Exe, os(&[])),
            (InstallerFamily::Msi, true, Program::MsiExec, os(&["/qn", "/norestart"])),
            (InstallerFamily::Msi, false, Program::MsiExec, os(&[])),
        ];
        for (family, silent, want_program, want_args) in cases {
            let plan = plan(family, silent).unwrap_or_else(|e| panic!("{family:?} silent={silent} should plan: {e}"));
            assert_eq!(plan.program, want_program, "{family:?} silent={silent}");
            assert_eq!(plan.args, want_args, "{family:?} silent={silent}");
        }
    }

    #[test]
    fn unknown_silent_true_never_guesses_a_flag() {
        let err = plan(InstallerFamily::Unknown, true).expect_err("Unknown + silent must error, never guess");
        assert!(matches!(err, PlanError::NoSilentFlags(InstallerFamily::Unknown)));
    }

    #[test]
    fn unknown_silent_false_just_runs_the_exe() {
        let plan = plan(InstallerFamily::Unknown, false).expect("Unknown non-silent just runs the installer's own UI");
        assert_eq!(plan.program, Program::Exe);
        assert_eq!(plan.args, Vec::<OsString>::new());
    }

    #[test]
    fn installshield_note_documents_the_unreliability() {
        let flags = silent_flags(InstallerFamily::InstallShield).expect("InstallShield has a silent-flag entry");
        assert!(!flags.note.is_empty());
        let lower = flags.note.to_lowercase();
        assert!(
            lower.contains("unreliable") && lower.contains("iss"),
            "note should document unreliability and the .iss response-file workaround, got: {:?}",
            flags.note
        );
    }

    #[test]
    fn msi_and_unknown_have_no_exe_silent_flags_entry() {
        assert!(silent_flags(InstallerFamily::Msi).is_none());
        assert!(silent_flags(InstallerFamily::Unknown).is_none());
    }

    #[test]
    fn plan_error_is_a_clean_std_error() {
        let err = plan(InstallerFamily::Unknown, true).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.is_empty());
        assert!(
            msg.chars().all(|c| !c.is_control()),
            "control character leaked into {msg:?}"
        );
        fn assert_is_std_error<E: std::error::Error>(_: &E) {}
        assert_is_std_error(&err);
    }

    #[test]
    fn family_from_pe_installer_kind_uses_the_real_variant_names() {
        assert_eq!(
            InstallerFamily::from(pe::InstallerKind::InnoSetup),
            InstallerFamily::Inno
        );
        assert_eq!(InstallerFamily::from(pe::InstallerKind::Nsis), InstallerFamily::Nsis);
        assert_eq!(
            InstallerFamily::from(pe::InstallerKind::InstallShield),
            InstallerFamily::InstallShield
        );
        assert_eq!(
            InstallerFamily::from(pe::InstallerKind::WixBurn),
            InstallerFamily::WixBurn
        );
    }
}
