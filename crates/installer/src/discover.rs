//! Ranks which file an installer just wrote is the application's own executable, from Task 2's
//! snapshot diff and any Start Menu shortcuts parsed by Task 3's `lnk` module.
//!
//! **Never guesses on a genuine tie.** Scoring is strict priority order, exactly as the plan
//! states: (1) named by a Start Menu `.lnk`'s target > (2) named by a new `Uninstall` registry
//! entry's `DisplayIcon` > (3) GUI subsystem (per `pe::analyze`) > (4) largest file size. This is applied in two
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
//! `.dll`, `.ini`, or data file an installer also wrote is never "the application"), minus the
//! uninstallers [`rank`] excludes (see its doc for the exact rule).
//!
//! **Paths are matched structurally, never by substring.** Every registry value (`DisplayIcon`,
//! `UninstallString`) is reduced to the one executable path it names ([`exe_in`]) and every `.lnk`
//! target to its [`WinPath`]; both are then compared for equality against a candidate's
//! drive_c-relative path, component-wise and case-insensitively. So `my-uninstall-helper.exe` is
//! never mistaken for `uninstall.exe`, and `C:\App\a.exe` never matches `C:\App\a.exe.bak`.
use crate::lnk::ShellLink;
use crate::snapshot::InstallDiff;
use crate::uninstall::split_command_line;
use rt_core::WinPath;

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

/// The comparison key for a Windows path: drive_c-relative, `/`-joined, lowercased — the same form
/// as a lowercased `InstallDiff::new_files` entry. `None` for any drive but `C:` (the only drive a
/// Wine prefix has: a path elsewhere can never name anything an installer wrote there).
fn key(p: &WinPath) -> Option<String> {
    (p.drive() == 'C').then(|| p.components().join("/").to_lowercase())
}

/// The executable path a registry command line or icon location names, as a [`key`]. Handles
/// `"C:\A B\app.exe" /S`, `"C:\A B\app.exe",0`, unquoted `C:\A B\app.exe /S` (the program is the
/// shortest prefix ending in `.exe` followed by the end, a space, a tab, `,` or `"` — what Windows
/// itself tries first), and `C:\App\app.exe,0`. Anything else (`%ProgramFiles%\...`, a bare
/// `uninstall.exe`, `MsiExec.exe /X{...}`, not an absolute `C:` path) is `None`: it names nothing
/// this ranking can match. Never panics: the `.exe` search runs on an ASCII-lowercased copy, whose
/// byte offsets equal the original's, and `.` is ASCII, so every slice is on a char boundary.
pub(crate) fn exe_in(value: &str) -> Option<String> {
    let value = value.trim();
    let program = if value.starts_with('"') {
        split_command_line(value).into_iter().next()?
    } else {
        let lower = value.to_ascii_lowercase();
        let end = lower
            .match_indices(".exe")
            .map(|(i, _)| i + 4)
            .find(|&end| matches!(lower.as_bytes().get(end), None | Some(b' ' | b'\t' | b',' | b'"')))?;
        value[..end].to_owned()
    };
    key(&WinPath::parse(&program).ok()?)
}

/// True for a file name an uninstaller conventionally has: `uninstall*`/`uninst*`, `unins<digits>`
/// (Inno's `unins000.exe`), `remove*` — case-insensitive, `.exe` stripped. Matches the whole
/// basename's start, never a substring (`my-uninstall-helper.exe` is not an uninstaller name).
fn looks_like_uninstaller(path: &str) -> bool {
    let base = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    let stem = base.strip_suffix(".exe").unwrap_or(&base);
    stem.starts_with("uninst")
        || stem.starts_with("remove")
        || stem
            .strip_prefix("unins")
            .is_some_and(|d| d.chars().all(|c| c.is_ascii_digit()))
}

/// Words that make a shortcut's own file name an "Uninstall" shortcut: the uninstaller-name family
/// ([`looks_like_uninstaller`]) plus common localized forms (German `Deinstallieren`/`Entfernen`,
/// French `Désinstaller`, Spanish/Portuguese `Desinstalar`).
const UNINSTALL_WORDS: [&str; 6] = ["uninst", "remove", "deinstall", "entfern", "désinstall", "desinstal"];

/// Keys of the `.lnk` targets that count as the app's own shortcuts: every shortcut except one
/// whose own file name contains an [`UNINSTALL_WORDS`] word (NSIS/Inno's "Uninstall My App.lnk",
/// which points at the uninstaller or at `app.exe /uninstall` and is evidence of nothing).
fn lnk_targets(shortcuts: &[(String, ShellLink)]) -> Vec<String> {
    shortcuts
        .iter()
        .filter(|(lnk_path, _)| {
            let name = lnk_path.rsplit('/').next().unwrap_or(lnk_path).to_lowercase();
            !UNINSTALL_WORDS.iter().any(|w| name.contains(w))
        })
        .filter_map(|(_, s)| key(s.relative_path.as_ref()?))
        .collect()
}

/// Per Uninstall entry: `(display_name, DisplayIcon exe, UninstallString exe)`, each exe a [`key`].
fn entries(diff: &InstallDiff) -> Vec<(Option<String>, Option<String>, Option<String>)> {
    diff.uninstall_entries
        .iter()
        .map(|e| {
            (
                e.display_name.clone(),
                e.icon_path.as_deref().and_then(exe_in),
                e.uninstall_string.as_deref().and_then(exe_in),
            )
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
///
/// `shortcuts` pairs each parsed `.lnk` with its own `InstallDiff::new_files` path (its file name
/// decides whether it is an "Uninstall" shortcut, see [`lnk_targets`]).
///
/// **Uninstallers are never auto-picked.** Before any tier is scored, a candidate is removed from
/// the pool when EITHER
/// - (a) its basename looks like an uninstaller ([`looks_like_uninstaller`]: `uninstall*`,
///   `uninst*`, `unins<digits>`, `remove*`) — always, whatever else names it; OR
/// - (b) an Uninstall entry's `UninstallString` names it (the parsed program, [`exe_in`]) AND there
///   is no positive evidence it is the app. Positive evidence = a Start Menu `.lnk` targets it whose
///   own name is not an "Uninstall" one ([`UNINSTALL_WORDS`]), or an entry's `DisplayIcon` names it
///   while that same entry's `UninstallString` does not (NSIS commonly sets both to its
///   uninstaller, so that pair is evidence of nothing).
///
/// So an app whose `UninstallString` is its own main exe (`app.exe /uninstall`) stays eligible
/// when a normal shortcut, or another entry's `DisplayIcon`, names it. If the exclusion leaves no
/// candidates, the result is [`RankResult::NeedsManualChoice`] listing the excluded exe(s).
///
/// **Doubtful exclusions.** An exclusion is doubtful when the exe was dropped by (b) alone (not
/// uninstaller-named: maybe `app.exe /uninstall` with no evidence), or by (a) despite positive
/// evidence (maybe a real app called `Remove Background.exe`). When any exclusion is doubtful and
/// the surviving winner has no tier (1)/(2) signal of its own, the result is
/// [`RankResult::NeedsManualChoice`] listing the survivor(s) plus the doubtful exes: otherwise a
/// bundled `helper.exe`/`vcredist.exe` would win silently by elimination. An uninstaller-named
/// file with no evidence (NSIS's `uninstall.exe`, Inno's `unins000.exe`) is a confident exclusion
/// and never triggers this: the one real app left still auto-picks.
pub fn rank(
    diff: &InstallDiff,
    shortcuts: &[(String, ShellLink)],
    read: impl Fn(&str) -> Option<Vec<u8>>,
    size: impl Fn(&str) -> Option<u64>,
) -> RankResult {
    let lnk_targets = lnk_targets(shortcuts);
    let entries = entries(diff);
    let excluded_candidate = |path: &String| Candidate {
        path: path.clone(),
        name: None,
        icon: None,
        score: 0,
    };

    // `excluded` pairs each dropped exe with whether dropping it is doubtful (see "Doubtful
    // exclusions" in this function's doc).
    let mut candidates = Vec::new();
    let mut excluded = Vec::new();
    for p in diff.new_files.iter().filter(|p| is_exe(p)) {
        let lower = p.to_lowercase();
        let is = |k: &Option<String>| k.as_deref() == Some(lower.as_str());
        let named = entries.iter().any(|(_, _, u)| is(u));
        let evidence = lnk_targets.contains(&lower) || entries.iter().any(|(_, icon, u)| is(icon) && !is(u));
        let by_name = looks_like_uninstaller(&lower);
        if by_name || (named && !evidence) {
            excluded.push((p, evidence || !by_name));
        } else {
            candidates.push(p);
        }
    }
    if candidates.is_empty() {
        return RankResult::NeedsManualChoice(excluded.iter().map(|(p, _)| excluded_candidate(p)).collect());
    }
    let doubtful: Vec<Candidate> = excluded
        .iter()
        .filter(|(_, d)| *d)
        .map(|(p, _)| excluded_candidate(p))
        .collect();

    // Tiers (1) and (2): no I/O, computed for every candidate.
    let mut partials: Vec<Partial> = candidates
        .into_iter()
        .map(|path| {
            let lower = path.to_lowercase();
            let uninstall_match = entries
                .iter()
                .find(|(_, icon, _)| icon.as_deref() == Some(lower.as_str()));
            Partial {
                path: path.clone(),
                has_lnk: lnk_targets.contains(&lower),
                has_uninstall: uninstall_match.is_some(),
                uninstall_name: uninstall_match.and_then(|(name, _, _)| name.clone()),
            }
        })
        .collect();

    let top_pair = partials
        .iter()
        .map(|p| (p.has_lnk, p.has_uninstall))
        .max()
        .unwrap_or_default();
    partials.retain(|p| (p.has_lnk, p.has_uninstall) == top_pair);
    // Doubtful exclusions + a winner with no tier (1)/(2) signal = too uncertain to auto-pick.
    let settle = |result: RankResult| {
        if top_pair != (false, false) || doubtful.is_empty() {
            return result;
        }
        let mut list = match result {
            RankResult::Winner(c) => vec![c],
            RankResult::NeedsManualChoice(v) => v,
        };
        list.extend(doubtful);
        RankResult::NeedsManualChoice(list)
    };

    // A unique winner from (1)/(2) alone needs no GUI-subsystem check at all: `read` is never
    // called for it, or for any candidate it already beat. `size` is still fetched (a stat, not a
    // full read) so `Candidate.score`'s size bit stays accurate even in this early-exit path.
    if partials.len() == 1 {
        let winner = partials.pop().expect("len checked");
        let file_size = size(&winner.path).unwrap_or(0);
        return settle(RankResult::Winner(to_candidate(winner, false, file_size)));
    }

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
    settle(if winners.len() == 1 {
        let (p, gui, sz) = winners.pop().expect("len checked");
        RankResult::Winner(to_candidate(p, gui, sz))
    } else {
        RankResult::NeedsManualChoice(
            winners
                .into_iter()
                .map(|(p, gui, sz)| to_candidate(p, gui, sz))
                .collect(),
        )
    })
}

#[cfg(test)]
mod tests;
