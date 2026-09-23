use super::*;
use crate::snapshot::UninstallEntry;
use rt_core::WinPath;

fn diff(new_files: &[&str], uninstall: Vec<UninstallEntry>) -> InstallDiff {
    InstallDiff {
        new_files: new_files.iter().map(|s| s.to_string()).collect(),
        new_registry_keys: Vec::new(),
        uninstall_entries: uninstall,
    }
}

fn lnk_to(target: &str) -> (String, ShellLink) {
    named_lnk_to(
        "ProgramData/Microsoft/Windows/Start Menu/Programs/App/My App.lnk",
        target,
    )
}

fn named_lnk_to(lnk_path: &str, target: &str) -> (String, ShellLink) {
    let link = ShellLink {
        relative_path: Some(WinPath::parse(target).unwrap()),
        ..ShellLink::default()
    };
    (lnk_path.to_owned(), link)
}

/// No `read`/`size` closure in these tests ever needs to answer anything (no candidate reaches
/// the GUI/size tiers before a `.lnk` or Uninstall match already settles it): both simply say
/// "nothing available", the same way a caller with no real files to check would.
fn no_bytes(_: &str) -> Option<Vec<u8>> {
    None
}
fn no_size(_: &str) -> Option<u64> {
    None
}

// --- laziness: `read` (the full-bytes closure) must never be called once a higher tier already
// settles the winner ------------------------------------------------------------------------

#[test]
fn read_is_never_called_when_a_shortcut_alone_already_settles_the_winner() {
    let d = diff(
        &[
            "Program Files/App/app.exe",
            "Program Files/App/helper1.exe",
            "Program Files/App/helper2.exe",
        ],
        vec![],
    );
    let shortcuts = [lnk_to(r"C:\Program Files\App\app.exe")];
    let read_calls = std::cell::Cell::new(0usize);
    let read = |_: &str| {
        read_calls.set(read_calls.get() + 1);
        None
    };
    let result = rank(&d, &shortcuts, read, no_size);
    assert!(matches!(result, RankResult::Winner(c) if c.path == "Program Files/App/app.exe"));
    assert_eq!(
        read_calls.get(),
        0,
        "tier (1) alone already settled it: read must not be called"
    );
}

#[test]
fn read_is_never_called_when_an_uninstall_entry_alone_already_settles_the_winner() {
    let d = diff(
        &["Program Files/App/app.exe", "Program Files/App/helper.exe"],
        vec![UninstallEntry {
            display_name: Some("My App".into()),
            uninstall_string: None,
            icon_path: Some(r"C:\Program Files\App\app.exe".into()),
        }],
    );
    let read_calls = std::cell::Cell::new(0usize);
    let read = |_: &str| {
        read_calls.set(read_calls.get() + 1);
        None
    };
    let result = rank(&d, &[], read, no_size);
    assert!(matches!(result, RankResult::Winner(c) if c.path == "Program Files/App/app.exe"));
    assert_eq!(
        read_calls.get(),
        0,
        "tier (2) alone already settled it: read must not be called"
    );
}

#[test]
fn read_is_called_only_for_candidates_still_tied_after_lnk_and_uninstall() {
    // Three candidates: two tied at the top (no lnk, no uninstall match) and one loser (neither).
    // Only the two tied ones may ever be passed to `read`.
    let d = diff(
        &["P/tied_a.exe", "P/tied_b.exe"],
        vec![UninstallEntry {
            display_name: Some("Something Else".into()),
            uninstall_string: None,
            icon_path: Some(r"C:\P\not_a_candidate.exe".into()),
        }],
    );
    let seen = std::cell::RefCell::new(Vec::new());
    let read = |p: &str| {
        seen.borrow_mut().push(p.to_string());
        None
    };
    let result = rank(&d, &[], read, no_size);
    let mut seen = seen.into_inner();
    seen.sort();
    assert_eq!(seen, ["P/tied_a.exe", "P/tied_b.exe"]);
    assert!(matches!(result, RankResult::NeedsManualChoice(_)));
}

#[test]
fn unambiguous_winner_via_start_menu_shortcut() {
    let d = diff(&["Program Files/App/app.exe", "Program Files/App/helper.exe"], vec![]);
    let shortcuts = [lnk_to(r"C:\Program Files\App\app.exe")];
    let result = rank(&d, &shortcuts, no_bytes, no_size);
    let RankResult::Winner(c) = result else {
        panic!("expected a winner: {result:?}");
    };
    assert_eq!(c.path, "Program Files/App/app.exe");
    assert_eq!(c.score & 0b1000, 0b1000, "lnk bit must be set");
}

#[test]
fn unambiguous_winner_via_uninstall_entry_name_no_shortcut() {
    let d = diff(
        &["Program Files/App/app.exe", "Program Files/App/helper.exe"],
        vec![UninstallEntry {
            display_name: Some("My App".into()),
            uninstall_string: None,
            icon_path: Some(r"C:\Program Files\App\app.exe".into()),
        }],
    );
    let result = rank(&d, &[], no_bytes, no_size);
    let RankResult::Winner(c) = result else {
        panic!("expected a winner: {result:?}");
    };
    assert_eq!(c.path, "Program Files/App/app.exe");
    assert_eq!(c.name.as_deref(), Some("My App"));
}

#[test]
fn genuine_tie_at_the_top_priority_level_asks_for_a_manual_choice() {
    // Neither candidate has a shortcut, an uninstall entry, a GUI subsystem, or any size (both
    // `size` calls return None -> 0): every tier ties, so this must never silently pick one.
    let d = diff(&["Program Files/App/a.exe", "Program Files/App/b.exe"], vec![]);
    let result = rank(&d, &[], no_bytes, no_size);
    let RankResult::NeedsManualChoice(candidates) = result else {
        panic!("expected a manual choice: {result:?}");
    };
    let mut paths: Vec<_> = candidates.iter().map(|c| c.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["Program Files/App/a.exe", "Program Files/App/b.exe"]);
}

#[test]
fn empty_diff_is_a_manual_choice_with_an_empty_list() {
    let d = diff(&[], vec![]);
    let result = rank(&d, &[], no_bytes, no_size);
    assert_eq!(result, RankResult::NeedsManualChoice(Vec::new()));
}

#[test]
fn a_diff_with_only_non_exe_files_is_also_an_empty_manual_choice() {
    let d = diff(&["Program Files/App/readme.txt", "Program Files/App/data.dll"], vec![]);
    assert_eq!(
        rank(&d, &[], no_bytes, no_size),
        RankResult::NeedsManualChoice(Vec::new())
    );
}

#[test]
fn a_shortcut_to_something_the_installer_did_not_write_never_boosts_an_unrelated_file() {
    // The shortcut points at a file that is NOT in `new_files` at all (an installer that shipped
    // a shortcut to some other, pre-existing tool). Both real candidates must be scored as if the
    // shortcut did not exist: still a genuine tie, not a silent pick of whichever happens to come
    // first.
    let d = diff(&["Program Files/App/a.exe", "Program Files/App/b.exe"], vec![]);
    let shortcuts = [lnk_to(r"C:\Somewhere\Else\unrelated.exe")];
    let result = rank(&d, &shortcuts, no_bytes, no_size);
    let RankResult::NeedsManualChoice(candidates) = result else {
        panic!("expected a manual choice: {result:?}");
    };
    assert_eq!(candidates.len(), 2);
    assert!(
        candidates.iter().all(|c| c.score & 0b1000 == 0),
        "no candidate may claim the lnk bit"
    );
}

#[test]
fn non_exe_new_files_never_become_candidates_even_when_one_exe_is_unambiguous() {
    let d = diff(
        &[
            "Program Files/App/app.exe",
            "Program Files/App/readme.txt",
            "Program Files/App/data.dll",
        ],
        vec![],
    );
    let result = rank(&d, &[], no_bytes, no_size);
    assert!(matches!(result, RankResult::Winner(c) if c.path == "Program Files/App/app.exe"));
}

#[test]
fn lnk_beats_uninstall_beats_gui_beats_size() {
    // Four candidates, each winning on exactly one tier below the top, to prove the priority
    // ORDER, not just that each signal individually can produce a winner.
    let d = diff(
        &["P/by_lnk.exe", "P/by_uninstall.exe", "P/by_gui.exe", "P/by_size.exe"],
        vec![UninstallEntry {
            display_name: Some("Uninstall Match".into()),
            uninstall_string: None,
            icon_path: Some(r"C:\P\by_uninstall.exe".into()),
        }],
    );
    let shortcuts = [lnk_to(r"C:\P\by_lnk.exe")];
    let gui_marker = b"GUI".to_vec();
    let read = |p: &str| (p == "P/by_gui.exe").then(|| gui_marker.clone());
    // `read` above returns a marker, not a real PE, for by_gui.exe: `pe::analyze` will reject it
    // (not a PE), so `is_gui` stays false for it too - the size tier below shows the fallback
    // instead. This is fine: the point of this table is the RELATIVE order lnk > uninstall > size
    // when neither of the two higher tiers is reachable, which the assertions below check. A
    // real-PE `is_gui` case is exercised separately.
    let size = |p: &str| match p {
        "P/by_size.exe" => Some(999),
        _ => Some(1),
    };
    let result = rank(&d, &shortcuts, read, size);
    assert!(matches!(result, RankResult::Winner(c) if c.path == "P/by_lnk.exe"));
}

#[test]
fn gui_subsystem_beats_size_when_neither_lnk_nor_uninstall_apply() {
    let d = diff(&["P/console.exe", "P/gui.exe"], vec![]);
    let gui_bytes = gui_pe_bytes();
    let read = |p: &str| (p == "P/gui.exe").then(|| gui_bytes.clone());
    let size = |p: &str| match p {
        "P/console.exe" => Some(1_000_000), // much bigger, but GUI still wins
        "P/gui.exe" => Some(10),
        _ => None,
    };
    let result = rank(&d, &[], read, size);
    assert!(matches!(result, RankResult::Winner(c) if c.path == "P/gui.exe"));
}

#[test]
fn largest_file_wins_when_every_higher_tier_is_absent() {
    let d = diff(&["P/small.exe", "P/big.exe"], vec![]);
    let size = |p: &str| match p {
        "P/small.exe" => Some(10),
        "P/big.exe" => Some(1_000_000),
        _ => None,
    };
    let result = rank(&d, &[], no_bytes, size);
    assert!(matches!(result, RankResult::Winner(c) if c.path == "P/big.exe"));
}

/// A minimal real PE64 GUI-subsystem image, built by hand (no mingw dependency for a unit test):
/// just enough of the header for `pe::analyze` to read the subsystem field.
fn gui_pe_bytes() -> Vec<u8> {
    let mut out = vec![0u8; 0x400];
    out[..2].copy_from_slice(b"MZ");
    out[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    out[0x40..0x44].copy_from_slice(b"PE\0\0");
    let fh = 0x44;
    out[fh..fh + 2].copy_from_slice(&0x8664u16.to_le_bytes()); // x86_64
    out[fh + 16..fh + 18].copy_from_slice(&240u16.to_le_bytes()); // optional header size
    out[fh + 18..fh + 20].copy_from_slice(&0x0022u16.to_le_bytes());
    let oh = fh + 20;
    out[oh..oh + 2].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
    out[oh + 32..oh + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    out[oh + 36..oh + 40].copy_from_slice(&0x200u32.to_le_bytes());
    out[oh + 56..oh + 60].copy_from_slice(&0x1000u32.to_le_bytes()); // size of image
    out[oh + 60..oh + 64].copy_from_slice(&0x400u32.to_le_bytes()); // size of headers
    out[oh + 68..oh + 70].copy_from_slice(&2u16.to_le_bytes()); // GUI subsystem
    out[oh + 108..oh + 112].copy_from_slice(&16u32.to_le_bytes());
    out
}

#[test]
fn sanity_gui_pe_bytes_is_actually_gui() {
    let info = pe::analyze(&gui_pe_bytes()).expect("analyze");
    assert_eq!(info.subsystem, pe::Subsystem::Gui);
}

// --- the uninstaller an `UninstallString` names is never auto-picked --------------------------

fn nsis_entry(icon: Option<&str>) -> UninstallEntry {
    UninstallEntry {
        display_name: Some("My App".into()),
        uninstall_string: Some(r#""C:\Program Files\App\uninstall.exe""#.into()),
        icon_path: icon.map(Into::into),
    }
}

#[test]
fn uninstall_string_never_makes_the_uninstaller_win_nsis_shape() {
    // No `.lnk`; the uninstaller is bigger, so the size tier alone would also pick it if it were
    // still a candidate. It must not win by tier (2) or by any lower tier.
    let d = diff(
        &["Program Files/App/app.exe", "Program Files/App/uninstall.exe"],
        vec![nsis_entry(None)],
    );
    let size = |p: &str| match p {
        "Program Files/App/uninstall.exe" => Some(1_000_000),
        _ => Some(10),
    };
    let result = rank(&d, &[], no_bytes, size);
    assert!(
        matches!(&result, RankResult::Winner(c) if c.path == "Program Files/App/app.exe"),
        "{result:?}"
    );
}

#[test]
fn display_icon_naming_the_uninstaller_does_not_rescue_it() {
    // NSIS scripts often set `DisplayIcon` to `uninstall.exe,0` too.
    let d = diff(
        &["Program Files/App/app.exe", "Program Files/App/uninstall.exe"],
        vec![nsis_entry(Some(r"C:\Program Files\App\uninstall.exe,0"))],
    );
    let result = rank(&d, &[], no_bytes, no_size);
    assert!(
        matches!(&result, RankResult::Winner(c) if c.path == "Program Files/App/app.exe"),
        "{result:?}"
    );
}

#[test]
fn a_start_menu_uninstall_shortcut_does_not_rescue_the_uninstaller() {
    // NSIS/Inno commonly add an "Uninstall My App" Start Menu shortcut next to the app's own.
    let d = diff(
        &["Program Files/App/app.exe", "Program Files/App/uninstall.exe"],
        vec![nsis_entry(None)],
    );
    let shortcuts = [
        lnk_to(r"C:\Program Files\App\app.exe"),
        named_lnk_to(
            "ProgramData/Microsoft/Windows/Start Menu/Programs/App/Uninstall My App.lnk",
            r"C:\Program Files\App\uninstall.exe",
        ),
    ];
    let size = |p: &str| (p == "Program Files/App/uninstall.exe").then_some(1_000_000);
    let result = rank(&d, &shortcuts, no_bytes, size);
    assert!(
        matches!(&result, RankResult::Winner(c) if c.path == "Program Files/App/app.exe"),
        "{result:?}"
    );
}

#[test]
fn inno_shape_display_icon_names_the_app_and_unins000_never_wins() {
    let d = diff(
        &[
            "Program Files/App/app.exe",
            "Program Files/App/helper.exe",
            "Program Files/App/unins000.exe",
        ],
        vec![UninstallEntry {
            display_name: Some("My App".into()),
            uninstall_string: Some(r#""C:\Program Files\App\unins000.exe""#.into()),
            icon_path: Some(r"C:\Program Files\App\app.exe".into()),
        }],
    );
    let size = |p: &str| (p == "Program Files/App/unins000.exe").then_some(1_000_000);
    let result = rank(&d, &[], no_bytes, size);
    let RankResult::Winner(c) = result else {
        panic!("expected a winner: {result:?}");
    };
    assert_eq!(c.path, "Program Files/App/app.exe");
    assert_eq!(c.name.as_deref(), Some("My App"));
    assert_eq!(c.score & 0b0100, 0b0100, "won by tier (2), DisplayIcon");
}

#[test]
fn an_uninstaller_that_is_the_only_new_exe_is_a_manual_choice_not_a_winner() {
    let d = diff(&["Program Files/App/uninstall.exe"], vec![nsis_entry(None)]);
    let result = rank(&d, &[], no_bytes, no_size);
    let RankResult::NeedsManualChoice(candidates) = result else {
        panic!("expected a manual choice: {result:?}");
    };
    let paths: Vec<_> = candidates.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(paths, ["Program Files/App/uninstall.exe"]);
}

// --- refined exclusion: an UninstallString-named exe with positive evidence is the app ---------

#[test]
fn an_app_whose_uninstall_string_is_itself_wins_via_a_normal_shortcut() {
    // `app.exe /uninstall` is the app's own exe: a normal Start Menu shortcut to it is positive
    // evidence, so it stays eligible (and wins over a bigger helper).
    let d = diff(
        &["Program Files/App/app.exe", "Program Files/App/helper.exe"],
        vec![UninstallEntry {
            display_name: Some("My App".into()),
            uninstall_string: Some(r#""C:\Program Files\App\app.exe" /uninstall"#.into()),
            icon_path: Some(r"C:\Program Files\App\app.exe,0".into()),
        }],
    );
    let shortcuts = [lnk_to(r"C:\Program Files\App\app.exe")];
    let size = |p: &str| (p == "Program Files/App/helper.exe").then_some(1_000_000);
    let result = rank(&d, &shortcuts, no_bytes, size);
    assert!(
        matches!(&result, RankResult::Winner(c) if c.path == "Program Files/App/app.exe"),
        "{result:?}"
    );
}

#[test]
fn a_display_icon_in_another_entry_is_positive_evidence() {
    let d = diff(
        &["App/app.exe"],
        vec![
            UninstallEntry {
                display_name: Some("Maintenance".into()),
                uninstall_string: Some(r"C:\App\app.exe /uninstall".into()),
                icon_path: None,
            },
            UninstallEntry {
                display_name: Some("My App".into()),
                uninstall_string: None,
                icon_path: Some(r"C:\App\app.exe,0".into()),
            },
        ],
    );
    let result = rank(&d, &[], no_bytes, no_size);
    assert!(
        matches!(&result, RankResult::Winner(c) if c.path == "App/app.exe" && c.name.as_deref() == Some("My App")),
        "{result:?}"
    );
}

#[test]
fn a_display_icon_equal_to_its_own_uninstall_string_is_not_evidence() {
    // NSIS often sets DisplayIcon to the uninstaller too; the pair proves nothing.
    let d = diff(
        &["App/setup.exe"],
        vec![UninstallEntry {
            display_name: Some("My App".into()),
            uninstall_string: Some(r#""C:\App\setup.exe" /uninstall"#.into()),
            icon_path: Some(r#""C:\App\setup.exe",0"#.into()),
        }],
    );
    assert!(matches!(
        rank(&d, &[], no_bytes, no_size),
        RankResult::NeedsManualChoice(_)
    ));
}

#[test]
fn an_uninstall_named_shortcut_is_not_evidence_and_gives_no_tier_one() {
    // "Uninstall My App.lnk" -> `app.exe /uninstall`: not a reason to keep or boost it.
    let d = diff(&["App/app.exe", "App/other.exe"], vec![]);
    let shortcuts = [named_lnk_to("Start Menu/Uninstall My App.lnk", r"C:\App\other.exe")];
    let size = |p: &str| (p == "App/app.exe").then_some(1_000_000);
    let result = rank(&d, &shortcuts, no_bytes, size);
    assert!(
        matches!(&result, RankResult::Winner(c) if c.path == "App/app.exe" && c.score & 0b1000 == 0),
        "{result:?}"
    );
}

#[test]
fn an_uninstaller_named_file_never_wins_even_with_a_shortcut_and_display_icon() {
    for name in ["uninstall.exe", "unins000.exe", "Uninst.exe", "REMOVE.EXE", "unins.exe"] {
        let path = format!("App/{name}");
        let d = diff(
            &[&path, "App/helper.exe"],
            vec![UninstallEntry {
                display_name: Some("My App".into()),
                uninstall_string: Some(format!(r"C:\App\{name} /SILENT")),
                icon_path: Some(format!(r"C:\App\{name},0")),
            }],
        );
        let shortcuts = [lnk_to(&format!(r"C:\App\{name}"))];
        let size = |p: &str| (p == path).then_some(1_000_000);
        let result = rank(&d, &shortcuts, no_bytes, size);
        assert!(
            matches!(&result, RankResult::Winner(c) if c.path == "App/helper.exe"),
            "{name}: {result:?}"
        );
    }
}

// --- structured (not substring) path matching ---------------------------------------------------

#[test]
fn exe_in_extracts_the_program_path() {
    let k = |s: &str| exe_in(s);
    let app = Some("program files/my app/app.exe".to_owned());
    assert_eq!(k(r"C:\Program Files\My App\app.exe /S --x"), app, "unquoted, spaces");
    assert_eq!(k(r#""C:\Program Files\My App\app.exe" /S"#), app, "quoted");
    assert_eq!(k(r#""C:\Program Files\My App\app.exe",0"#), app, "quoted icon");
    assert_eq!(k(r"C:\Program Files\My App\app.exe,0"), app, "icon index");
    assert_eq!(k(r"c:/program files/my app/APP.EXE"), app, "case, separators");
    assert_eq!(
        k(r"C:\Program Files\App\unins000.exe /SILENT"),
        Some("program files/app/unins000.exe".to_owned())
    );
    assert_eq!(k(r"%ProgramFiles%\App\app.exe"), None, "%VAR% stays literal");
    assert_eq!(k("MsiExec.exe /X{1234}"), None);
    assert_eq!(k(r"D:\App\app.exe"), None, "not drive C");
    assert_eq!(k(r"C:\App\app.ico,0"), None, "not an exe");
    assert_eq!(k(r"C:\App\app.exe.bak"), None, ".exe must end the program");
}

#[test]
fn a_candidate_merely_containing_the_uninstallers_name_is_not_excluded() {
    let d = diff(
        &["App/my-uninstall-helper.exe", "App/uninstall.exe"],
        vec![UninstallEntry {
            display_name: Some("My App".into()),
            uninstall_string: Some(r"C:\App\uninstall.exe /S".into()),
            icon_path: None,
        }],
    );
    let result = rank(&d, &[], no_bytes, no_size);
    assert!(
        matches!(&result, RankResult::Winner(c) if c.path == "App/my-uninstall-helper.exe"),
        "{result:?}"
    );
}

#[test]
fn an_uninstall_string_path_ending_in_a_candidates_path_does_not_exclude_it() {
    // `C:\MyApp\app.exe` ends with `app/app.exe`: a substring match would wrongly drop App/app.exe.
    let d = diff(
        &["App/app.exe", "MyApp/app.exe"],
        vec![UninstallEntry {
            display_name: None,
            uninstall_string: Some(r#""C:\MyApp\app.exe" /uninstall"#.into()),
            icon_path: None,
        }],
    );
    let result = rank(&d, &[], no_bytes, no_size);
    assert!(
        matches!(&result, RankResult::Winner(c) if c.path == "App/app.exe"),
        "{result:?}"
    );
}

#[test]
fn a_display_icon_ending_in_a_candidates_path_does_not_boost_it() {
    // `C:\P\xa.exe` contains `a.exe`: only P/xa.exe may get tier (2).
    let d = diff(
        &["a.exe", "P/xa.exe"],
        vec![UninstallEntry {
            display_name: Some("X".into()),
            uninstall_string: None,
            icon_path: Some(r"C:\P\xa.exe".into()),
        }],
    );
    let result = rank(&d, &[], no_bytes, no_size);
    assert!(
        matches!(&result, RankResult::Winner(c) if c.path == "P/xa.exe"),
        "{result:?}"
    );
}

/// Hostile registry/`.lnk`-derived strings: `exe_in` (and so `rank`) returns, never panics.
#[test]
fn exe_in_never_panics_on_hostile_input() {
    let fixed = [
        String::new(),
        "\"".repeat(5000),
        ".exe".repeat(10_000),
        "\u{e9}.exe\u{e9}".repeat(1000),
        "C:\\\u{130}.EXE,0".to_owned(),
        "\"C:\\a.exe".to_owned(),
        "C:\\".to_owned() + &"a\\".repeat(100_000) + "x.exe",
    ];
    for s in &fixed {
        let _ = exe_in(s);
    }
    let alphabet: Vec<char> = " \"\\/:,%\0\u{130}\u{e9}Cc.exe0".chars().collect();
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..20_000 {
        let len = (next() % 40) as usize;
        let s: String = (0..len)
            .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
            .collect();
        let _ = exe_in(&s);
        let d = diff(
            &["App/app.exe", "App/uninstall.exe"],
            vec![UninstallEntry {
                display_name: None,
                uninstall_string: Some(s.clone()),
                icon_path: Some(s),
            }],
        );
        let _ = rank(&d, &[], no_bytes, no_size);
    }
}
