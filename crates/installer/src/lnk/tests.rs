use super::*;
use std::panic::catch_unwind;

/// Builds a minimal, spec-valid `[MS-SHLLINK]` file: the fixed 76-byte header, an optional
/// `LinkTargetIDList` (no `LinkInfo`), plus whichever `StringData` fields are given, in the fixed
/// order the format requires (`Name`, `RelativePath`, `WorkingDir`, `Arguments`, `IconLocation`).
/// All Unicode.
#[derive(Default)]
struct Lnk {
    icon_index: i32,
    name: Option<&'static str>,
    relative_path: Option<&'static str>,
    working_dir: Option<&'static str>,
    arguments: Option<&'static str>,
    icon_location: Option<&'static str>,
    /// Raw `SHITEMID` item stream for `LinkTargetIDList` (no `IDListSize` prefix — `build()` adds
    /// that). `None`: no `LinkTargetIDList` at all (`HAS_LINK_TARGET_ID_LIST` unset).
    id_list_items: Option<Vec<u8>>,
}

impl Lnk {
    fn build(&self) -> Vec<u8> {
        let mut flags: u32 = IS_UNICODE;
        if self.id_list_items.is_some() {
            flags |= HAS_LINK_TARGET_ID_LIST;
        }
        if self.name.is_some() {
            flags |= HAS_NAME;
        }
        if self.relative_path.is_some() {
            flags |= HAS_RELATIVE_PATH;
        }
        if self.working_dir.is_some() {
            flags |= HAS_WORKING_DIR;
        }
        if self.arguments.is_some() {
            flags |= HAS_ARGUMENTS;
        }
        if self.icon_location.is_some() {
            flags |= HAS_ICON_LOCATION;
        }

        let mut b = Vec::with_capacity(HEADER_LEN);
        b.extend_from_slice(&HEADER_SIGNATURE.to_le_bytes());
        b.extend_from_slice(&LINK_CLSID);
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes()); // FileAttributes
        b.extend_from_slice(&[0u8; 24]); // Creation/Access/WriteTime
        b.extend_from_slice(&0u32.to_le_bytes()); // FileSize
        b.extend_from_slice(&self.icon_index.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // ShowCommand
        b.extend_from_slice(&0u16.to_le_bytes()); // HotKey
        b.extend_from_slice(&0u16.to_le_bytes()); // Reserved1
        b.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        b.extend_from_slice(&0u32.to_le_bytes()); // Reserved3
        assert_eq!(b.len(), HEADER_LEN);

        if let Some(items) = &self.id_list_items {
            b.extend_from_slice(&(items.len() as u16).to_le_bytes());
            b.extend_from_slice(items);
        }

        let str_data = |s: &str| -> Vec<u8> {
            let units: Vec<u16> = s.encode_utf16().collect();
            let mut out = (units.len() as u16).to_le_bytes().to_vec();
            out.extend(units.iter().flat_map(|u| u.to_le_bytes()));
            out
        };
        for s in [
            self.name,
            self.relative_path,
            self.working_dir,
            self.arguments,
            self.icon_location,
        ]
        .into_iter()
        .flatten()
        {
            b.extend(str_data(s));
        }
        b
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("missing fixture {}: {e}", path.display()))
}

/// Extracts `hello.lnk`'s own real `LinkTargetIDList` item stream (the `SHITEMID` sequence,
/// `IDListSize` prefix excluded) straight from the fixture, for reuse as a real-world IDList in
/// the `Lnk` builder rather than a hand-built one.
fn hello_id_list_items() -> Vec<u8> {
    let bytes = fixture("hello.lnk");
    let size = u16::from_le_bytes([bytes[HEADER_LEN], bytes[HEADER_LEN + 1]]) as usize;
    bytes[HEADER_LEN + 2..HEADER_LEN + 2 + size].to_vec()
}

#[test]
fn real_wine_shortcut_parses_working_dir_and_icon_location() {
    // Captured with `wine cscript` + WScript.Shell's CreateShortcut in a scratch prefix (Wine
    // 10.0), targeting a nonexistent C:\target\hello.exe purely to exercise the format: TargetPath
    // set, WorkingDirectory "C:\target", IconLocation "C:\target\hello.exe, 3". Wine records the
    // target via LinkTargetIDList + LinkInfo, not RelativePath StringData (RELATIVE_PATH's flag
    // bit is unset here) — LinkInfo remains skipped (out of scope, see the module doc), but
    // LinkTargetIDList's items are walked as a fallback and recover the same absolute path here
    // (verified empirically against this fixture's real bytes: a "My Computer" root item, a
    // drive item for "C:\", a folder item "target", and a file item "hello.exe").
    let bytes = fixture("hello.lnk");
    assert!(bytes.len() < 1024, "fixture should be small, was {} bytes", bytes.len());
    let link = ShellLink::parse(&bytes).expect("parses");
    assert_eq!(link.working_dir, Some(WinPath::parse(r"C:\target").unwrap()));
    assert_eq!(
        link.icon_location,
        Some((WinPath::parse(r"C:\target\hello.exe").unwrap(), 3))
    );
    assert_eq!(
        link.relative_path,
        Some(WinPath::parse(r"C:\target\hello.exe").unwrap())
    );
    assert!(link.warnings.is_empty(), "{:?}", link.warnings);
}

/// Same recovery as the fixture-based test above, but built through the `Lnk` test helper (no
/// `RelativePath` StringData at all — `HAS_RELATIVE_PATH` unset) so the fallback is anchored to a
/// synthetic file too, independent of `hello.lnk` staying byte-for-byte the same.
#[test]
fn id_list_fallback_recovers_absolute_path_when_relative_path_flag_unset() {
    let lnk = Lnk {
        id_list_items: Some(hello_id_list_items()),
        working_dir: Some(r"C:\target"),
        ..Lnk::default()
    };
    let link = ShellLink::parse(&lnk.build()).expect("parses");
    assert_eq!(
        link.relative_path,
        Some(WinPath::parse(r"C:\target\hello.exe").unwrap())
    );
    assert!(link.warnings.is_empty(), "{:?}", link.warnings);
}

/// The fallback must never override a `RelativePath` StringData that already parsed — it only
/// fires when `relative_path` would otherwise stay `None`.
#[test]
fn id_list_fallback_does_not_override_present_relative_path() {
    let lnk = Lnk {
        id_list_items: Some(hello_id_list_items()),
        relative_path: Some(r"C:\explicit\other.exe"),
        ..Lnk::default()
    };
    let link = ShellLink::parse(&lnk.build()).expect("parses");
    assert_eq!(
        link.relative_path,
        Some(WinPath::parse(r"C:\explicit\other.exe").unwrap())
    );
    assert!(link.warnings.is_empty(), "{:?}", link.warnings);
}

#[test]
fn minimal_header_with_no_optional_structures_is_a_complete_valid_file() {
    let bytes = Lnk::default().build();
    assert_eq!(bytes.len(), HEADER_LEN);
    let link = ShellLink::parse(&bytes).expect("parses");
    assert_eq!(link, ShellLink::default());
}

#[test]
fn all_three_fields_round_trip_when_present_and_parseable() {
    let lnk = Lnk {
        icon_index: 5,
        working_dir: Some(r"C:\Program Files\Widget"),
        icon_location: Some(r"C:\Program Files\Widget\widget.exe"),
        relative_path: Some(r"C:\Program Files\Widget\widget.exe"),
        ..Lnk::default()
    };
    let link = ShellLink::parse(&lnk.build()).expect("parses");
    assert_eq!(
        link.working_dir,
        Some(WinPath::parse(r"C:\Program Files\Widget").unwrap())
    );
    assert_eq!(
        link.relative_path,
        Some(WinPath::parse(r"C:\Program Files\Widget\widget.exe").unwrap())
    );
    assert_eq!(
        link.icon_location,
        Some((WinPath::parse(r"C:\Program Files\Widget\widget.exe").unwrap(), 5))
    );
    assert!(link.warnings.is_empty());
}

/// A genuinely relative `RELATIVE_PATH` (what real installers actually write there per
/// [MS-SHLLINK]) is not a `WinPath` (which only accepts absolute `X:\...` forms): this is the
/// "one bad field, not a whole failure" path — the rest of the link still parses, `relative_path`
/// is `None`, and exactly one warning names the field.
#[test]
fn unparseable_relative_path_is_none_with_a_warning_not_an_abort() {
    let lnk = Lnk {
        relative_path: Some(r"target\hello.exe"), // no drive letter: WinPath::parse rejects it
        working_dir: Some(r"C:\target"),
        icon_location: Some(r"C:\target\hello.exe"),
        icon_index: 3,
        ..Lnk::default()
    };
    let link = ShellLink::parse(&lnk.build()).expect("parses");
    assert_eq!(link.relative_path, None);
    assert_eq!(link.working_dir, Some(WinPath::parse(r"C:\target").unwrap()));
    assert_eq!(
        link.icon_location,
        Some((WinPath::parse(r"C:\target\hello.exe").unwrap(), 3))
    );
    assert_eq!(link.warnings.len(), 1, "{:?}", link.warnings);
    assert!(link.warnings[0].contains("RelativePath"), "{:?}", link.warnings);
}

#[test]
fn empty_icon_location_string_is_an_unusable_path_not_a_panic() {
    let lnk = Lnk {
        icon_location: Some(""),
        ..Lnk::default()
    };
    let link = ShellLink::parse(&lnk.build()).expect("parses");
    assert_eq!(link.icon_location, None);
    assert_eq!(link.warnings.len(), 1);
}

#[test]
fn a_minimal_link_info_of_only_its_own_size_field_is_skipped_cleanly() {
    let mut bytes = Lnk::default().build();
    bytes[20..24].copy_from_slice(&(HAS_LINK_INFO | IS_UNICODE).to_le_bytes());
    bytes.extend_from_slice(&4u32.to_le_bytes()); // LinkInfoSize == 4: covers only itself
    let link = ShellLink::parse(&bytes).expect("parses");
    assert_eq!(link, ShellLink::default());
}

#[test]
fn link_info_smaller_than_its_own_size_field_is_rejected() {
    let mut bytes = Lnk::default().build();
    bytes[20..24].copy_from_slice(&(HAS_LINK_INFO | IS_UNICODE).to_le_bytes());
    bytes.extend_from_slice(&3u32.to_le_bytes()); // smaller than the 4-byte field itself
    assert!(matches!(ShellLink::parse(&bytes), Err(LnkError::Malformed(_))));
}

#[test]
fn truncated_header_is_rejected_cleanly() {
    let bytes = Lnk::default().build();
    for n in 0..HEADER_LEN {
        assert!(matches!(
            ShellLink::parse(&bytes[..n]),
            Err(LnkError::Truncated { len }) if len == n
        ));
    }
}

#[test]
fn bad_signature_is_rejected() {
    let mut bytes = Lnk::default().build();
    bytes[0] ^= 0xFF;
    assert!(matches!(ShellLink::parse(&bytes), Err(LnkError::BadSignature)));
}

#[test]
fn bad_clsid_is_rejected() {
    let mut bytes = Lnk::default().build();
    bytes[4] ^= 0xFF;
    assert!(matches!(ShellLink::parse(&bytes), Err(LnkError::BadClsid)));
}

#[test]
fn declared_id_list_size_past_end_of_file_is_rejected_not_read_out_of_bounds() {
    let mut bytes = Lnk::default().build();
    bytes[20..24].copy_from_slice(&(HAS_LINK_TARGET_ID_LIST | IS_UNICODE).to_le_bytes());
    bytes.extend_from_slice(&0xFFFFu16.to_le_bytes()); // IDListSize: far past EOF
    assert!(matches!(ShellLink::parse(&bytes), Err(LnkError::Malformed(_))));
}

/// An item whose own `cbSize` claims far more bytes than the outer `LinkTargetIDList` region
/// actually reserves for it. The extra bytes are real, addressable file bytes (deliberately spelling
/// a drive string, `Z:\`) that happen to follow in the buffer — this proves the walker stops at the
/// outer region's `end` rather than trusting the item's own (bogus) `cbSize` and wandering past it.
/// Mutation-checked: removing `id_list_path`'s `e <= end` bound (accepting any
/// `pos.checked_add(cbsize)` that merely avoids overflow) makes this fail — the walker then reads
/// the trailing `Z:\` bytes as this item's drive string and recovers `relative_path == Some("Z:\")`
/// instead of leaving it `None`.
#[test]
fn id_list_item_cbsize_past_region_end_is_not_read_as_a_path_segment() {
    let mut bytes = Lnk::default().build();
    let mut flags = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    flags |= HAS_LINK_TARGET_ID_LIST;
    bytes[20..24].copy_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&4u16.to_le_bytes()); // outer IDListSize: only 4 bytes reserved
    bytes.extend_from_slice(&20u16.to_le_bytes()); // this item's own (bogus) cbSize: far past those 4 bytes
    bytes.push(0x23); // drive-item type byte
    bytes.extend_from_slice(b"Z:\\\0"); // only a buggy walker (past the outer `end`) would read this
    bytes.resize(HEADER_LEN + 2 + 20, 0); // pad so the bogus item_end (20 bytes) is in-bounds
    let link = ShellLink::parse(&bytes).expect("parses");
    assert_eq!(link.relative_path, None);
    assert!(link.warnings.is_empty(), "{:?}", link.warnings);
}

/// A folder/file item whose declared `cbSize` is internally consistent (fits the outer
/// `LinkTargetIDList` region and the file) but far too small to hold the fixed 12-byte
/// file-entry header `read_file_entry_name` expects before the name. Must be skipped gracefully,
/// not read out of bounds. Mutation-checked: replacing `read_file_entry_name`'s
/// `bytes.get(name_start..item_end)?` with raw slicing (`&bytes[name_start..item_end]`) makes this
/// panic (`name_start` is past `item_end`, a backwards range), proving the `.get` bound is load-
/// bearing here, not decorative.
#[test]
fn id_list_item_truncated_before_its_fixed_header_is_skipped_gracefully() {
    let mut bytes = Lnk::default().build();
    let mut flags = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    flags |= HAS_LINK_TARGET_ID_LIST;
    bytes[20..24].copy_from_slice(&flags.to_le_bytes());
    bytes.extend_from_slice(&5u16.to_le_bytes()); // outer IDListSize: 5 bytes total
    bytes.extend_from_slice(&5u16.to_le_bytes()); // this item's own cbSize: also 5 (self-consistent)
    bytes.push(0x31); // folder-item type byte
    bytes.extend_from_slice(&[0u8; 2]); // only 2 bytes of content follow: nowhere near a 12-byte header
    let r = catch_unwind(|| ShellLink::parse(&bytes));
    assert!(r.is_ok(), "panicked: {r:?}");
    let link = r.unwrap().expect("parses");
    assert_eq!(link.relative_path, None);
    assert!(link.warnings.is_empty(), "{:?}", link.warnings);
}

/// A folder/file item with its full fixed 12-byte header present but a zero-length short name
/// (the byte right after the header is already the NUL terminator) and no extension block,
/// sandwiched between a drive item and a real file item. The empty name must contribute no path
/// segment, not a spurious empty one, and must not panic. Mutation-checked: dropping
/// `id_list_path`'s `!s.is_empty()` guard on the returned name (letting an empty segment through)
/// makes this fail — the empty segment joins as a doubled backslash (`C:\\app.exe`), which
/// `WinPath::parse` then rejects as an empty path component, leaving `relative_path` `None` with
/// a warning instead of the expected recovered path.
#[test]
fn id_list_item_with_zero_length_name_contributes_no_segment() {
    let mut bytes = Lnk::default().build();
    let mut flags = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    flags |= HAS_LINK_TARGET_ID_LIST;
    bytes[20..24].copy_from_slice(&flags.to_le_bytes());
    let drive_item: &[u8] = &[0x23, b'C', b':', b'\\', 0]; // type + "C:\" + NUL
    let mut folder_item: Vec<u8> = vec![0x31]; // type byte
    folder_item.extend_from_slice(&[0u8; 11]); // reserved(1) + filesize(4) + date(4) + attributes(2)
    folder_item.push(0); // zero-length short name: NUL right away
    let mut file_item: Vec<u8> = vec![0x32]; // type byte
    file_item.extend_from_slice(&[0u8; 11]); // reserved(1) + filesize(4) + date(4) + attributes(2)
    file_item.extend_from_slice(b"app.exe\0");
    let mut items = Vec::new();
    for item in [drive_item, &folder_item, &file_item] {
        items.extend_from_slice(&((item.len() + 2) as u16).to_le_bytes());
        items.extend_from_slice(item);
    }
    bytes.extend_from_slice(&(items.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&items);
    let r = catch_unwind(|| ShellLink::parse(&bytes));
    assert!(r.is_ok(), "panicked: {r:?}");
    let link = r.unwrap().expect("parses");
    assert_eq!(link.relative_path, Some(WinPath::parse(r"C:\app.exe").unwrap()));
    assert!(link.warnings.is_empty(), "{:?}", link.warnings);
}

/// An item type byte outside every recognized range (root/drive/folder/file) must be skipped
/// entirely — not a general shell-namespace resolver — never panicking and never contributing a
/// segment. Mutation-checked: replacing the catch-all `_ => {}` arm with `_ => unreachable!()`
/// makes this panic, proving the catch-all is doing real work, not dead code.
#[test]
fn id_list_item_with_unrecognized_type_is_skipped_gracefully() {
    let mut bytes = Lnk::default().build();
    let mut flags = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    flags |= HAS_LINK_TARGET_ID_LIST;
    bytes[20..24].copy_from_slice(&flags.to_le_bytes());
    let item: &[u8] = &[0x99, b'X', b':', b'\\', 0]; // an unrecognized type byte, drive-shaped payload
    let cbsize = (item.len() + 2) as u16; // this one item is the whole IDList: outer size == item cbSize
    bytes.extend_from_slice(&cbsize.to_le_bytes()); // outer IDListSize
    bytes.extend_from_slice(&cbsize.to_le_bytes()); // this item's own cbSize
    bytes.extend_from_slice(item);
    let r = catch_unwind(|| ShellLink::parse(&bytes));
    assert!(r.is_ok(), "panicked: {r:?}");
    let link = r.unwrap().expect("parses");
    assert_eq!(link.relative_path, None); // ignored, not misread as a drive item
    assert!(link.warnings.is_empty(), "{:?}", link.warnings);
}

#[test]
fn declared_string_data_length_past_end_of_file_is_rejected() {
    let mut bytes = Lnk::default().build();
    bytes[20..24].copy_from_slice(&(HAS_WORKING_DIR | IS_UNICODE).to_le_bytes());
    bytes.extend_from_slice(&0xFFFFu16.to_le_bytes()); // CountCharacters: far past EOF
    assert!(matches!(ShellLink::parse(&bytes), Err(LnkError::Malformed(_))));
}

#[test]
fn all_present_flags_but_all_fields_truncated_away_never_panics() {
    // Every optional-structure/StringData flag set, but nothing follows the header at all.
    let mut bytes = Lnk::default().build();
    let all = HAS_LINK_TARGET_ID_LIST
        | HAS_LINK_INFO
        | HAS_NAME
        | HAS_RELATIVE_PATH
        | HAS_WORKING_DIR
        | HAS_ARGUMENTS
        | HAS_ICON_LOCATION
        | IS_UNICODE;
    bytes[20..24].copy_from_slice(&all.to_le_bytes());
    let r = catch_unwind(|| ShellLink::parse(&bytes));
    assert!(r.is_ok());
    assert!(r.unwrap().is_err());
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// The whole point of Part A's spike: 10 000 xorshift-mutated variants of a rich, spec-valid
/// `.lnk` (every optional structure and StringData field present, matching the shape the two
/// rejected crates panicked on) must never panic `ShellLink::parse`, however they are corrupted.
/// Includes a real `LinkTargetIDList` (reused from `hello.lnk`) so mutations land on IDList item
/// bytes too, exercising `id_list_path` and its helpers, not just StringData.
#[test]
fn mutated_bytes_never_panic() {
    let template = Lnk {
        icon_index: 3,
        name: Some("Hello Fixture"),
        relative_path: Some(r"C:\target\hello.exe"),
        working_dir: Some(r"C:\target"),
        arguments: Some("--flag value"),
        icon_location: Some(r"C:\target\hello.exe"),
        id_list_items: Some(hello_id_list_items()),
    }
    .build();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for n in 0..10_000u64 {
        let mut m = template.clone();
        if rng.next().is_multiple_of(5) {
            let len = m.len();
            m.truncate((rng.next() as usize) % (len + 1));
        } else {
            for _ in 0..=(rng.next() % 6) {
                let len = m.len();
                if len == 0 {
                    break;
                }
                let at = (rng.next() as usize) % len;
                m[at] = rng.next() as u8;
            }
        }
        let r = catch_unwind(|| ShellLink::parse(&m));
        assert!(r.is_ok(), "panicked on iteration {n}: {m:?}");
    }
}
