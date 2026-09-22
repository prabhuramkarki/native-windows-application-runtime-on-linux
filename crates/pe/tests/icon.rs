mod common;
use common::*;

const RT_GROUP_ICON: u16 = 14;
const RT_ICON: u16 = 3;

/// A GRPICONDIR + GRPICONDIRENTRY array (the RT_GROUP_ICON resource body): `entries` is
/// `(width, height, bit_count, bytes_in_resource, id)`.
fn grpicondir(entries: &[(u8, u8, u16, u32, u16)]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0u16.to_le_bytes()); // idReserved
    b.extend_from_slice(&1u16.to_le_bytes()); // idType: 1 = icon
    b.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // idCount
    for &(w, h, bit_count, bytes_in_res, id) in entries {
        b.push(w);
        b.push(h);
        b.push(0); // bColorCount
        b.push(0); // bReserved
        b.extend_from_slice(&1u16.to_le_bytes()); // wPlanes
        b.extend_from_slice(&bit_count.to_le_bytes());
        b.extend_from_slice(&(bytes_in_res as u16).to_le_bytes()); // dwBytesInResLo
        b.extend_from_slice(&((bytes_in_res >> 16) as u16).to_le_bytes()); // dwBytesInResHi
        b.extend_from_slice(&id.to_le_bytes());
    }
    b
}

/// One RT_GROUP_ICON (id 1) naming two RT_ICON members (32x32x32 id 101, 16x16x8 id 102), plus
/// the two RT_ICON resources themselves, in one `.rsrc` section.
fn two_icon_image() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let icon32 = b"FAKE32BITMAPDATA............".to_vec();
    let icon16 = b"FAKE16BITMAPDATA".to_vec();
    let group = grpicondir(&[
        (32, 32, 32, icon32.len() as u32, 101),
        (16, 16, 8, icon16.len() as u32, 102),
    ]);
    let base = Builder::rva(0);
    let rsrc = rsrc_multi(
        base,
        &[
            (RT_GROUP_ICON, 1, 0x409, &group),
            (RT_ICON, 101, 0x409, &icon32),
            (RT_ICON, 102, 0x409, &icon16),
        ],
    );
    let img = Builder::x64()
        .section(".rsrc", DATA_R, rsrc.clone())
        .dir(2, base, rsrc.len() as u32)
        .build();
    (img, icon32, icon16)
}

#[test]
fn finds_group_icon_entries_and_their_data() {
    let (img, icon32, icon16) = two_icon_image();
    let entries = pe::find_group_icon(&img).unwrap().expect("group icon present");
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[0],
        pe::GroupIconEntry {
            id: 101,
            width: 32,
            height: 32,
            bit_count: 32
        }
    );
    assert_eq!(
        entries[1],
        pe::GroupIconEntry {
            id: 102,
            width: 16,
            height: 16,
            bit_count: 8
        }
    );
    assert_eq!(pe::icon_bytes(&img, 101).unwrap(), Some(icon32));
    assert_eq!(pe::icon_bytes(&img, 102).unwrap(), Some(icon16));
    assert_eq!(pe::icon_bytes(&img, 999).unwrap(), None, "no RT_ICON with that id");
}

#[test]
fn zero_width_or_height_means_256() {
    let icon = b"BIGICON".to_vec();
    let group = grpicondir(&[(0, 0, 32, icon.len() as u32, 7)]);
    let base = Builder::rva(0);
    let rsrc = rsrc_multi(base, &[(RT_GROUP_ICON, 1, 0x409, &group), (RT_ICON, 7, 0x409, &icon)]);
    let img = Builder::x64()
        .section(".rsrc", DATA_R, rsrc.clone())
        .dir(2, base, rsrc.len() as u32)
        .build();
    let entries = pe::find_group_icon(&img).unwrap().expect("group icon present");
    assert_eq!((entries[0].width, entries[0].height), (256, 256));
}

#[test]
fn no_resource_directory_is_ok_none_not_an_error() {
    let img = Builder::x64().build(); // no sections, no directories at all
    assert_eq!(pe::find_group_icon(&img).unwrap(), None);
    assert_eq!(pe::icon_bytes(&img, 1).unwrap(), None);
}

#[test]
fn resources_present_but_no_icon_group_is_ok_none() {
    let base = Builder::rva(0);
    let rsrc = rsrc_version_section(base, &version_info_block("1.0.0.0", "NoIcon"));
    let img = Builder::x64()
        .section(".rsrc", DATA_R, rsrc.clone())
        .dir(2, base, rsrc.len() as u32)
        .build();
    assert_eq!(pe::find_group_icon(&img).unwrap(), None);
}

/// A GRPICONDIR whose declared `idCount` claims more entries than the resource actually holds
/// bytes for: pelite's own `GroupResource::new` bounds-checks the total size before touching the
/// entry array (see `crates/pe/src/icon.rs`'s doc comment) and must return `Err`, never panic or
/// read past the buffer.
#[test]
fn absurd_declared_entry_count_is_an_error_not_a_panic() {
    let mut group = grpicondir(&[(16, 16, 32, 4, 1)]);
    group[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes()); // idCount lie
    let base = Builder::rva(0);
    let rsrc = rsrc_multi(base, &[(RT_GROUP_ICON, 1, 0x409, &group), (RT_ICON, 1, 0x409, b"data")]);
    let img = Builder::x64()
        .section(".rsrc", DATA_R, rsrc.clone())
        .dir(2, base, rsrc.len() as u32)
        .build();
    let r = std::panic::catch_unwind(|| pe::find_group_icon(&img));
    assert!(r.is_ok(), "panicked on an absurd idCount");
    assert!(r.unwrap().is_err());
}

#[test]
fn truncated_group_icon_resource_is_an_error_not_a_panic() {
    let mut group = grpicondir(&[(16, 16, 32, 4, 1)]);
    group.truncate(group.len() - 2); // cuts off mid-entry
    let base = Builder::rva(0);
    let rsrc = rsrc_multi(base, &[(RT_GROUP_ICON, 1, 0x409, &group)]);
    let img = Builder::x64()
        .section(".rsrc", DATA_R, rsrc.clone())
        .dir(2, base, rsrc.len() as u32)
        .build();
    let r = std::panic::catch_unwind(|| pe::find_group_icon(&img));
    assert!(r.is_ok(), "panicked on a truncated group icon resource");
    assert!(r.unwrap().is_err());
}

/// Same hazard `version_hostile.rs`'s `misaligned_resource_directory_is_reported_not_dereferenced`
/// guards against, for this module's own call into `resources()`: a resource directory RVA that
/// is not 4-byte aligned makes pelite cast a misaligned pointer to `&IMAGE_RESOURCE_DIRECTORY`,
/// UB caught as a hard abort in debug builds. `icon.rs`'s `with_resources` has its own copy of the
/// `res_rva % 4` guard (see its doc comment); this proves it fires before `resources()` is ever
/// called, not after.
#[test]
fn misaligned_resource_directory_is_reported_not_dereferenced() {
    let base = Builder::rva(0);
    let rsrc = rsrc_multi(base, &[(RT_GROUP_ICON, 1, 0x409, &grpicondir(&[(16, 16, 32, 4, 1)]))]);
    for skew in [1u32, 2, 3] {
        let skewed = Builder::x64()
            .section(".rsrc", DATA_R, rsrc.clone())
            .dir(2, base + skew, rsrc.len() as u32 - skew)
            .build();
        let r = std::panic::catch_unwind(|| pe::find_group_icon(&skewed));
        assert!(r.is_ok(), "panicked at skew {skew}");
        let err = r
            .unwrap()
            .expect_err("misaligned directory must be reported, not silently empty");
        assert!(err.to_string().contains("aligned"), "skew {skew}: {err}");
    }
}

/// xorshift byte-flip mutation, same style as `tests/robust.rs`: a valid two-icon image corrupted
/// thousands of ways must never panic either accessor.
#[test]
fn mutated_icon_resources_never_panic() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }
    let (original, _, _) = two_icon_image();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for n in 0..10_000u64 {
        let mut m = original.clone();
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
        let r = std::panic::catch_unwind(|| {
            let _ = pe::find_group_icon(&m);
            let _ = pe::icon_bytes(&m, 101);
            let _ = pe::icon_bytes(&m, 102);
        });
        assert!(r.is_ok(), "panicked on iteration {n}");
    }
}

#[test]
fn not_a_pe_is_an_error_never_a_panic() {
    for input in [&b""[..], b"garbage", b"MZ", &vec![0u8; 512]] {
        let r = std::panic::catch_unwind(|| (pe::find_group_icon(input), pe::icon_bytes(input, 1)));
        assert!(r.is_ok(), "panicked on {input:?}");
    }
}
