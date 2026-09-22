//! Ranks which file an installer just wrote is the application's own executable, from Task 2's
//! snapshot diff and any Start Menu shortcuts parsed by Task 3's `lnk` module.
//!
//! **Never guesses on a genuine tie.** Scoring is strict priority order, exactly as the plan
//! states: (1) named by a Start Menu `.lnk`'s target > (2) named in a new `Uninstall` registry
//! entry > (3) GUI subsystem (per `pe::analyze`) > (4) largest file size. Candidates are compared
//! lexicographically on that 4-tuple; [`rank`] returns [`RankResult::Winner`] only when exactly
//! one candidate reaches the highest tuple value. Anything else — several candidates tied at the
//! top, or no candidates at all — is [`RankResult::NeedsManualChoice`], never a silent pick (an
//! empty diff and a genuine tie share this one variant rather than a separate `NoCandidates`: both
//! mean the same thing to a caller, "I cannot tell you, ask the user or take `--exe`", and keeping
//! one variant is less code for the same information — the `Vec` being empty already says which
//! case it was).
//!
//! **Byte access is injected, not read directly** (Phase 2's `doctor`/`FsProbe` style), so ranking
//! is unit-testable without real files on disk: `read` fetches a candidate's whole bytes (used
//! only for the GUI-subsystem check, `pe::analyze`), `size` fetches just its size (used for the
//! file-size tie-break) — kept as two separate closures rather than one, so a caller ranking many
//! large candidates is never forced to read a whole file just to compare sizes; only the winning
//! tier's candidates end up read at all, and only for the subsystem check. Both take the exact
//! `InstallDiff::new_files` path string; a real caller's closures join it onto the app's actual
//! `drive_c` themselves.
//!
//! **Candidates** are the entries of `InstallDiff::new_files` whose extension is `.exe`
//! (case-insensitive) — the only kind of file this ranking is ever asked to choose among (a
//! `.dll`, `.ini`, or data file an installer also wrote is never "the application").
use crate::lnk::ShellLink;
use crate::snapshot::InstallDiff;

/// One installed-file candidate for "the application's own executable" and how it scored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Exactly as it appears in [`InstallDiff::new_files`] (drive_c-relative, `/`-joined).
    pub path: String,
    /// The matching `Uninstall` entry's `DisplayName`, when (2) is how this candidate was
    /// identified. `None` otherwise — a shortcut or the GUI/size tiers carry no name of their own.
    pub name: Option<String>,
    /// Always `None` here: extracting an icon needs `rt_desktop`, decoding PE bytes this function
    /// has no reason to touch for every candidate when only the eventual winner's icon is ever
    /// used. The install pipeline (Task 6/7) fills this in once ranking has picked (or the user
    /// has chosen) a winner.
    pub icon: Option<Vec<(u32, Vec<u8>)>>,
    /// An informational bitmask of which signals matched: bit 3 = Start Menu `.lnk`, bit 2 =
    /// Uninstall entry, bit 1 = GUI subsystem, bit 0 = nonzero file size. This is NOT the value
    /// [`rank`] actually compares candidates on (that would lose the file size's real magnitude to
    /// a single bit) — [`rank`]'s internal tie-break key keeps the real magnitude. Useful for
    /// logging/display only.
    pub score: u32,
}

/// What [`rank`] decided. See the module doc for exactly when each variant is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RankResult {
    Winner(Candidate),
    NeedsManualChoice(Vec<Candidate>),
}

/// The exact, lossless tie-break order: compared as a tuple, greatest wins. `file_size` carries
/// its real magnitude (unlike `Candidate::score`'s single bit for it), so two candidates of
/// different sizes are never mistaken for a tie.
type RankKey = (bool, bool, bool, u64);

fn is_exe(path: &str) -> bool {
    path.rsplit('.')
        .next()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
        && path.contains('.')
}

/// `.lnk` `relative_path` targets, normalised to the same drive_c-relative `/`-joined, lowercased
/// form as `InstallDiff::new_files`, so the two can be compared directly. Only `C:` targets are
/// considered (drive_c is the only drive a Wine prefix has; a shortcut naming another drive letter
/// can never match anything an installer wrote there and is silently excluded, not an error).
fn lnk_targets(shortcuts: &[ShellLink]) -> Vec<String> {
    shortcuts
        .iter()
        .filter_map(|s| s.relative_path.as_ref())
        .filter(|p| p.drive() == 'C')
        .map(|p| p.components().join("/").to_lowercase())
        .collect()
}

/// `(display_name, haystack)` per Uninstall entry: `haystack` is `uninstall_string` and
/// `icon_path` concatenated, backslashes normalised to `/` and lowercased, so a candidate path is
/// found by substring containment however it is quoted or dressed up in the real value (e.g.
/// `"C:\Program Files\App\app.exe" /uninstall` or `C:\Program Files\App\app.exe,0`).
fn uninstall_haystacks(diff: &InstallDiff) -> Vec<(Option<String>, String)> {
    diff.uninstall_entries
        .iter()
        .map(|e| {
            let haystack = [e.uninstall_string.as_deref(), e.icon_path.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ")
                .replace('\\', "/")
                .to_lowercase();
            (e.display_name.clone(), haystack)
        })
        .collect()
}

/// Ranks the `.exe` candidates in `diff.new_files`. See the module doc for the priority order, the
/// injected `read`/`size` closures, and exactly what counts as a candidate.
pub fn rank(
    diff: &InstallDiff,
    shortcuts: &[ShellLink],
    read: impl Fn(&str) -> Option<Vec<u8>>,
    size: impl Fn(&str) -> Option<u64>,
) -> RankResult {
    let lnk_targets = lnk_targets(shortcuts);
    let uninstall = uninstall_haystacks(diff);

    let mut scored: Vec<(Candidate, RankKey)> = diff
        .new_files
        .iter()
        .filter(|p| is_exe(p))
        .map(|path| {
            let lower = path.to_lowercase();
            let has_lnk = lnk_targets.contains(&lower);
            let uninstall_match = uninstall.iter().find(|(_, haystack)| haystack.contains(&lower));
            let has_uninstall = uninstall_match.is_some();
            let is_gui = read(path)
                .and_then(|bytes| pe::analyze(&bytes).ok())
                .is_some_and(|info| info.subsystem == pe::Subsystem::Gui);
            let file_size = size(path).unwrap_or(0);

            let bits = (u32::from(has_lnk) << 3)
                | (u32::from(has_uninstall) << 2)
                | (u32::from(is_gui) << 1)
                | u32::from(file_size > 0);
            let candidate = Candidate {
                path: path.clone(),
                name: uninstall_match.and_then(|(name, _)| name.clone()),
                icon: None,
                score: bits,
            };
            (candidate, (has_lnk, has_uninstall, is_gui, file_size))
        })
        .collect();

    let Some(&(_, top)) = scored.iter().max_by_key(|(_, key)| *key) else {
        return RankResult::NeedsManualChoice(Vec::new());
    };
    scored.retain(|(_, key)| *key == top);
    let mut winners: Vec<Candidate> = scored.into_iter().map(|(c, _)| c).collect();
    if winners.len() == 1 {
        RankResult::Winner(winners.pop().expect("len checked"))
    } else {
        RankResult::NeedsManualChoice(winners)
    }
}

#[cfg(test)]
mod tests;
