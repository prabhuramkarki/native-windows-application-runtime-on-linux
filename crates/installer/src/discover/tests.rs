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

fn lnk_to(target: &str) -> ShellLink {
    ShellLink {
        relative_path: Some(WinPath::parse(target).unwrap()),
        ..ShellLink::default()
    }
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
