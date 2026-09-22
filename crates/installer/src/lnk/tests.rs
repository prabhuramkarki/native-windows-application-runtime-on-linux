use super::*;
use std::panic::catch_unwind;

/// Builds a minimal, spec-valid `[MS-SHLLINK]` file: the fixed 76-byte header (no `LinkTargetIDList`,
/// no `LinkInfo`) plus whichever `StringData` fields are given, in the fixed order the format
/// requires (`Name`, `RelativePath`, `WorkingDir`, `Arguments`, `IconLocation`). All Unicode.
#[derive(Default)]
struct Lnk {
    icon_index: i32,
    name: Option<&'static str>,
    relative_path: Option<&'static str>,
    working_dir: Option<&'static str>,
    arguments: Option<&'static str>,
    icon_location: Option<&'static str>,
}

impl Lnk {
    fn build(&self) -> Vec<u8> {
        let mut flags: u32 = IS_UNICODE;
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

#[test]
fn real_wine_shortcut_parses_working_dir_and_icon_location() {
    // Captured with `wine cscript` + WScript.Shell's CreateShortcut in a scratch prefix (Wine
    // 10.0), targeting a nonexistent C:\target\hello.exe purely to exercise the format: TargetPath
    // set (which Wine records via LinkTargetIDList + LinkInfo, both skipped here, not RelativePath
    // — see the module doc on why that is expected), WorkingDirectory "C:\target", IconLocation
    // "C:\target\hello.exe, 3".
    let bytes = fixture("hello.lnk");
    assert!(bytes.len() < 1024, "fixture should be small, was {} bytes", bytes.len());
    let link = ShellLink::parse(&bytes).expect("parses");
    assert_eq!(link.working_dir, Some(WinPath::parse(r"C:\target").unwrap()));
    assert_eq!(
        link.icon_location,
        Some((WinPath::parse(r"C:\target\hello.exe").unwrap(), 3))
    );
    // Real shortcuts to an absolute target path do not carry RELATIVE_PATH at all: `None` here is
    // "field absent", not "field present but unusable", so it must not produce a warning either.
    assert_eq!(link.relative_path, None);
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
#[test]
fn mutated_bytes_never_panic() {
    let template = Lnk {
        icon_index: 3,
        name: Some("Hello Fixture"),
        relative_path: Some(r"C:\target\hello.exe"),
        working_dir: Some(r"C:\target"),
        arguments: Some("--flag value"),
        icon_location: Some(r"C:\target\hello.exe"),
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
