//! Ranks which file an installer just wrote is the application's own executable, from Task 2's
//! snapshot diff and any Start Menu shortcuts parsed by Task 3's `lnk` module.
//!
//! **Never guesses on a genuine tie.** Scoring is strict priority order, exactly as the plan
//! states: (1) named by a Start Menu `.lnk`'s target > (2) named in a new `Uninstall` registry
//! entry > (3) GUI subsystem (per `pe::analyze`) > (4) largest file size. This is applied in two
//! narrowing stages rather than one flat 4-tuple comparison (see [`rank`]'s laziness note just
//! below for why): first every candidate is narrowed to the top `(has_lnk, has_uninstall)` pair,
//! then — only if more than one candidate remains — narrowed again to the top `(is_gui,
//! file_size)` pair among THOSE. Either stage narrowing to exactly one candidate is a
//! [`RankResult::Winner`]; anything else — several candidates still tied after both stages, or no
//! candidates at all — is [`RankResult::NeedsManualChoice`], never a silent pick (an empty diff and
//! a genuine tie share this one variant rather than a separate `NoCandidates`: both mean the same
//! thing to a caller, "I cannot tell you, ask the user or take `--exe`", and keeping one variant is
//! less code for the same information — the `Vec` being empty already says which case it was).
//!
//! **Byte access is injected, not read directly** (Phase 2's `doctor`/`FsProbe` style), so ranking
//! is unit-testable without real files on disk: `read` fetches a candidate's whole bytes (used
//! only for the GUI-subsystem check, `pe::analyze`), `size` fetches just its size (used for the
//! file-size tie-break) — kept as two separate closures rather than one, so a caller ranking many
//! large candidates is never forced to read a whole file just to compare sizes. `read` is also
//! evaluated LAZILY, one tier at a time: the (1) `.lnk` and (2) Uninstall-entry signals need no
//! I/O at all, so they are computed for every candidate first; `read`/`pe::analyze` (3) is then
//! called ONLY for the candidates still tied after (1) and (2) — an installer naming its own
//! executable in a `.lnk` or an Uninstall entry, among 50 other `.exe`s it also wrote, costs zero
//! calls to `read` for any of them, not 50. Both closures take the exact `InstallDiff::new_files`
//! path string; a real caller's closures join it onto the app's actual `drive_c` themselves.
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

/// A candidate after the no-I/O tiers (1)/(2) have been scored, before (3)/(4) are even looked at.
struct Partial {
    path: String,
    has_lnk: bool,
    has_uninstall: bool,
    uninstall_name: Option<String>,
}

fn to_candidate(p: Partial, is_gui: bool, file_size: u64) -> Candidate {
    let bits = (u32::from(p.has_lnk) << 3)
        | (u32::from(p.has_uninstall) << 2)
        | (u32::from(is_gui) << 1)
        | u32::from(file_size > 0);
    Candidate {
        path: p.path,
        name: p.uninstall_name,
        icon: None,
        score: bits,
    }
}

/// Ranks the `.exe` candidates in `diff.new_files`. See the module doc for the priority order, the
/// injected `read`/`size` closures (and exactly when `read` is and is not called), and exactly
/// what counts as a candidate.
pub fn rank(
    diff: &InstallDiff,
    shortcuts: &[ShellLink],
    read: impl Fn(&str) -> Option<Vec<u8>>,
    size: impl Fn(&str) -> Option<u64>,
) -> RankResult {
    let lnk_targets = lnk_targets(shortcuts);
    let uninstall = uninstall_haystacks(diff);

    // Tiers (1) and (2): no I/O, computed for every candidate.
    let mut partials: Vec<Partial> = diff
        .new_files
        .iter()
        .filter(|p| is_exe(p))
        .map(|path| {
            let lower = path.to_lowercase();
            let uninstall_match = uninstall.iter().find(|(_, haystack)| haystack.contains(&lower));
            Partial {
                path: path.clone(),
                has_lnk: lnk_targets.contains(&lower),
                has_uninstall: uninstall_match.is_some(),
                uninstall_name: uninstall_match.and_then(|(name, _)| name.clone()),
            }
        })
        .collect();

    if partials.is_empty() {
        return RankResult::NeedsManualChoice(Vec::new());
    }
    let top_pair = partials
        .iter()
        .map(|p| (p.has_lnk, p.has_uninstall))
        .max()
        .expect("partials is non-empty");
    partials.retain(|p| (p.has_lnk, p.has_uninstall) == top_pair);

    // A unique winner from (1)/(2) alone needs no GUI-subsystem check at all: `read` is never
    // called for it, or for any candidate it already beat. `size` is still fetched (a stat, not a
    // full read) so `Candidate.score`'s size bit stays accurate even in this early-exit path.
    if partials.len() == 1 {
        let winner = partials.pop().expect("len checked");
        let file_size = size(&winner.path).unwrap_or(0);
        return RankResult::Winner(to_candidate(winner, false, file_size));
    }

    // A unique winner from (1)/(2) alone needs no GUI-subsystem check at all: `read` is never
    // called for it, or for any candidate it already beat. `size` is still fetched (a stat, not a
    // full read) so `Candidate.score`'s size bit stays accurate even in this early-exit path.
    // Tier (3): only the candidates still tied after (1)/(2) are ever read.
    let scored: Vec<(Partial, bool, u64)> = partials
        .into_iter()
        .map(|p| {
            let is_gui = read(&p.path)
                .and_then(|bytes| pe::analyze(&bytes).ok())
                .is_some_and(|info| info.subsystem == pe::Subsystem::Gui);
            let file_size = size(&p.path).unwrap_or(0);
            (p, is_gui, file_size)
        })
        .collect();

    let top_key: (bool, u64) = scored
        .iter()
        .map(|(_, gui, sz)| (*gui, *sz))
        .max()
        .expect("scored is non-empty");
    let mut winners: Vec<(Partial, bool, u64)> = scored
        .into_iter()
        .filter(|(_, gui, sz)| (*gui, *sz) == top_key)
        .collect();
    if winners.len() == 1 {
        let (p, gui, sz) = winners.pop().expect("len checked");
        RankResult::Winner(to_candidate(p, gui, sz))
    } else {
        RankResult::NeedsManualChoice(
            winners
                .into_iter()
                .map(|(p, gui, sz)| to_candidate(p, gui, sz))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests;
