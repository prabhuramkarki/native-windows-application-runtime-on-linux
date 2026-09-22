use super::*;
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("missing fixture {}: run tools/build-fixtures.sh ({e})", path.display()))
}

// --- extract_icon_png against real and minimal-synthetic PE images ---------------------------

#[test]
fn hello64_icon_is_returned_unchanged_at_every_requested_size() {
    let pe_bytes = fixture("hello64.exe");
    let sizes = [16, 32, 48, 128, 256];
    let result = extract_icon_png(&pe_bytes, &sizes).unwrap();
    assert_eq!(result.len(), sizes.len(), "one entry per requested size: {result:?}");
    // hello64.exe carries exactly one 32x32 PNG-in-ICO entry (see pe crate's own fixtures.rs
    // test), so every requested size falls back to that same source and gets the exact same
    // bytes back, unchanged (PNG passthrough, no re-encoding).
    let entries = pe::find_group_icon(&pe_bytes).unwrap().unwrap();
    let raw = pe::icon_bytes(&pe_bytes, entries[0].id).unwrap().unwrap();
    assert!(raw.starts_with(PNG_SIGNATURE));
    for (size, png) in &result {
        assert_eq!(png, &raw, "size {size}");
    }
}

#[test]
fn pe_with_no_icon_resource_at_all_is_ok_empty_not_an_error() {
    // fs.c/fs64.exe carries no .rc-declared resources whatsoever.
    let pe_bytes = fixture("fs64.exe");
    assert_eq!(extract_icon_png(&pe_bytes, &[16, 32]).unwrap(), Vec::new());
}

#[test]
fn not_a_pe_is_an_error() {
    assert!(matches!(extract_icon_png(b"not a pe", &[32]), Err(IconError::NotPe)));
    assert!(matches!(extract_icon_png(&[], &[32]), Err(IconError::NotPe)));
}

#[test]
fn empty_sizes_list_is_ok_empty() {
    let pe_bytes = fixture("hello64.exe");
    assert_eq!(extract_icon_png(&pe_bytes, &[]).unwrap(), Vec::new());
}

// --- a minimal hand-rolled PE + two-member icon group, for the isolation test ------------------
// Deliberately smaller than `pe`'s own test `Builder`/`rsrc_multi` (which are internal to that
// crate and not reusable here): just enough header/section/resource-directory bytes for
// `pe::find_group_icon`/`pe::icon_bytes` to read two RT_ICON members out of one RT_GROUP_ICON.

fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

/// A minimal `.rsrc`-only PE64 image with one RT_GROUP_ICON (id 1) naming the given
/// `(id, width, height, bit_count, data)` RT_ICON members.
fn pe_with_icon_group(members: &[(u16, u16, u16, u16, &[u8])]) -> Vec<u8> {
    // GRPICONDIR + entries.
    let mut group = vec![0u8; 6];
    put16(&mut group, 2, 1); // idType
    put16(&mut group, 4, members.len() as u16);
    for &(id, w, h, bc, data) in members {
        let mut e = vec![0u8; 14];
        e[0] = w as u8;
        e[1] = h as u8;
        put16(&mut e, 4, 1); // wPlanes
        put16(&mut e, 6, bc);
        put32(&mut e, 8, data.len() as u32);
        put16(&mut e, 12, id);
        group.extend(e);
    }

    // Resource directory: root -> {GROUP_ICON(14) -> id1 -> lang -> data, ICON(3) -> id_i -> lang -> data}.
    let rt_group_icon = 14u32;
    let rt_icon = 3u32;
    let dir_hdr = |count: u16| {
        let mut d = vec![0u8; 16];
        put16(&mut d, 14, count);
        d
    };
    let root_size = 16 + 8 * 2; // two top-level types
    let group_type_dir_off = root_size;
    let group_type_dir_size = 16 + 8; // one id (1) under GROUP_ICON
    let icon_type_dir_off = group_type_dir_off + group_type_dir_size;
    let icon_type_dir_size = 16 + 8 * members.len();
    let group_id_lang_off = icon_type_dir_off + icon_type_dir_size;
    let group_id_lang_size = 16 + 8; // one language
    let mut icon_id_lang_off = Vec::new();
    let mut off = group_id_lang_off + group_id_lang_size;
    for _ in members {
        icon_id_lang_off.push(off);
        off += 16 + 8; // one language each
    }
    let dirs_end = off; // end of every directory level, before the data-entry array itself
    let group_data_entry_off = off;
    off += 16;
    let mut icon_data_entry_off = Vec::new();
    for _ in members {
        icon_data_entry_off.push(off);
        off += 16;
    }
    let data_start = off;

    let mut rsrc = dir_hdr(2);
    rsrc.extend(rt_group_icon.to_le_bytes());
    rsrc.extend((0x8000_0000u32 | group_type_dir_off as u32).to_le_bytes());
    rsrc.extend(rt_icon.to_le_bytes());
    rsrc.extend((0x8000_0000u32 | icon_type_dir_off as u32).to_le_bytes());
    assert_eq!(rsrc.len(), root_size);

    rsrc.extend(dir_hdr(1)); // GROUP_ICON's id directory: one id (1)
    rsrc.extend(1u32.to_le_bytes());
    rsrc.extend((0x8000_0000u32 | group_id_lang_off as u32).to_le_bytes());
    assert_eq!(rsrc.len(), icon_type_dir_off);

    rsrc.extend(dir_hdr(members.len() as u16)); // ICON's id directory: one id per member
    for (i, &(id, ..)) in members.iter().enumerate() {
        rsrc.extend(u32::from(id).to_le_bytes());
        rsrc.extend((0x8000_0000u32 | icon_id_lang_off[i] as u32).to_le_bytes());
    }
    assert_eq!(rsrc.len(), group_id_lang_off);

    rsrc.extend(dir_hdr(1)); // group's language directory
    rsrc.extend(0x0409u32.to_le_bytes());
    rsrc.extend((group_data_entry_off as u32).to_le_bytes());
    for (i, off) in icon_id_lang_off.iter().enumerate() {
        assert_eq!(rsrc.len(), *off);
        rsrc.extend(dir_hdr(1));
        rsrc.extend(0x0409u32.to_le_bytes());
        rsrc.extend((icon_data_entry_off[i] as u32).to_le_bytes());
    }
    assert_eq!(rsrc.len(), dirs_end);

    let base = 0x1000u32; // section RVA
    let mut running = data_start as u32;
    rsrc.extend((base + running).to_le_bytes());
    rsrc.extend((group.len() as u32).to_le_bytes());
    rsrc.extend([0u8; 8]);
    running += group.len() as u32;
    for &(_, _, _, _, data) in members {
        rsrc.extend((base + running).to_le_bytes());
        rsrc.extend((data.len() as u32).to_le_bytes());
        rsrc.extend([0u8; 8]);
        running += data.len() as u32;
    }
    assert_eq!(rsrc.len(), data_start);
    rsrc.extend(&group);
    for &(_, _, _, _, data) in members {
        rsrc.extend(data);
    }

    // Minimal PE64 header + one .rsrc section, in the style of pe's own test Builder.
    let mut out = vec![0u8; 0x400];
    out[..2].copy_from_slice(b"MZ");
    put32(&mut out, 0x3C, 0x40);
    out[0x40..0x44].copy_from_slice(b"PE\0\0");
    let fh = 0x44;
    put16(&mut out, fh, 0x8664); // x86_64
    put16(&mut out, fh + 2, 1); // one section
    put16(&mut out, fh + 16, 240); // optional header size
    put16(&mut out, fh + 18, 0x0022); // executable, large-address-aware
    let oh = fh + 20;
    put16(&mut out, oh, 0x20B); // PE32+
    put32(&mut out, oh + 32, 0x1000); // section alignment
    put32(&mut out, oh + 36, 0x200); // file alignment
    put32(&mut out, oh + 56, 0x2000); // size of image
    put32(&mut out, oh + 60, 0x400); // size of headers
    put16(&mut out, oh + 68, 3); // console subsystem
    put32(&mut out, oh + 108, 16); // NumberOfRvaAndSizes
    let dirs = oh + 112;
    put32(&mut out, dirs + 2 * 8, base); // IMAGE_DIRECTORY_ENTRY_RESOURCE = index 2
    put32(&mut out, dirs + 2 * 8 + 4, rsrc.len() as u32);
    let sh = oh + 240;
    out[sh..sh + 6].copy_from_slice(b".rsrc\0");
    put32(&mut out, sh + 8, rsrc.len() as u32); // virtual size
    put32(&mut out, sh + 12, base); // virtual address
    put32(&mut out, sh + 16, rsrc.len().div_ceil(0x200) as u32 * 0x200); // raw size
    let raw_ptr = out.len() as u32;
    put32(&mut out, sh + 20, raw_ptr); // pointer to raw data
    put32(&mut out, sh + 36, 0x4000_0040); // readable initialised data
    out.extend_from_slice(&rsrc);
    out.resize(out.len().next_multiple_of(0x200), 0);
    out
}

#[test]
fn one_hostile_size_never_blocks_the_others() {
    let good_png = {
        // A tiny real 1x1 PNG (the exact bytes do not matter, only that it starts with the magic).
        let mut buf = Vec::new();
        let mut enc = png::Encoder::new(std::io::Cursor::new(&mut buf), 1, 1);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        enc.write_header()
            .unwrap()
            .write_image_data(&[10, 20, 30, 255])
            .unwrap();
        buf
    };
    let mut hostile_dib = vec![0u8; 40];
    put32(&mut hostile_dib, 0, 40);
    put32(&mut hostile_dib, 4, 100_000); // absurd width
    put32(&mut hostile_dib, 8, 200_000); // absurd height
    put16(&mut hostile_dib, 14, 32);

    let pe_bytes = pe_with_icon_group(&[(1, 32, 32, 32, &good_png), (2, 64, 64, 32, &hostile_dib)]);
    assert!(
        pe::find_group_icon(&pe_bytes).unwrap().is_some(),
        "sanity: group icon is readable"
    );

    let result = extract_icon_png(&pe_bytes, &[32, 64]).unwrap();
    let by_size: std::collections::HashMap<_, _> = result.into_iter().collect();
    assert_eq!(
        by_size.get(&32),
        Some(&good_png),
        "the decodable size must still come back"
    );
    assert_eq!(
        by_size.get(&64),
        None,
        "the hostile size must be absent, not an error or a panic"
    );
}

// --- decode_dib / to_png: direct unit tests on the private decoder ----------------------------

/// Builds a minimal uncompressed DIB (`BITMAPINFOHEADER` + XOR data + AND mask), `bit_count` 24 or
/// 32, from a row-major top-to-bottom `(r, g, b, a)` pixel grid (the DIB's own bottom-up storage
/// and BGR(A) channel order are handled here so callers can write pixels in the obvious order).
fn build_dib(width: u32, height: u32, bit_count: u16, pixels: &[(u8, u8, u8, u8)]) -> Vec<u8> {
    assert_eq!(pixels.len(), (width * height) as usize);
    let bpp = match bit_count {
        24 => 3,
        32 => 4,
        _ => panic!("test helper only supports 24/32bpp"),
    };
    let xor_stride = (width * bpp).div_ceil(4) * 4;
    let and_stride = width.div_ceil(32) * 4;
    let mut out = vec![0u8; 40];
    put32(&mut out, 0, 40);
    put32(&mut out, 4, width);
    put32(&mut out, 8, height * 2);
    put16(&mut out, 12, 1);
    put16(&mut out, 14, bit_count);
    // compression (offset 16) stays 0 = BI_RGB

    let mut xor = vec![0u8; (xor_stride * height) as usize];
    let mut and = vec![0u8; (and_stride * height) as usize];
    for y in 0..height {
        let src_row = height - 1 - y; // bottom-up storage
        for x in 0..width {
            let (r, g, b, a) = pixels[(y * width + x) as usize];
            let px_off = (src_row * xor_stride + x * bpp) as usize;
            xor[px_off] = b;
            xor[px_off + 1] = g;
            xor[px_off + 2] = r;
            if bpp == 4 {
                xor[px_off + 3] = a;
            } else if a == 0 {
                let bit_off = (src_row * and_stride * 8 + x) as usize;
                and[bit_off / 8] |= 0x80 >> (bit_off % 8);
            }
        }
    }
    out.extend(xor);
    out.extend(and);
    out
}

#[test]
fn decodes_a_32bpp_dib_with_real_alpha() {
    let px = [(255, 0, 0, 255), (0, 255, 0, 128), (0, 0, 255, 0), (255, 255, 255, 255)];
    let dib = build_dib(2, 2, 32, &px);
    let (w, h, rgba) = decode_dib(&dib).expect("decodes");
    assert_eq!((w, h), (2, 2));
    assert_eq!(&rgba[0..4], &[255, 0, 0, 255]);
    assert_eq!(&rgba[4..8], &[0, 255, 0, 128]);
    assert_eq!(&rgba[8..12], &[0, 0, 255, 0]);
    assert_eq!(&rgba[12..16], &[255, 255, 255, 255]);
}

#[test]
fn decodes_a_24bpp_dib_using_the_and_mask_for_alpha() {
    let px = [(10, 20, 30, 255), (40, 50, 60, 0)]; // second pixel transparent via AND mask
    let dib = build_dib(2, 1, 24, &px);
    let (w, h, rgba) = decode_dib(&dib).expect("decodes");
    assert_eq!((w, h), (2, 1));
    assert_eq!(&rgba[0..4], &[10, 20, 30, 255]);
    assert_eq!(&rgba[4..8], &[40, 50, 60, 0]);
}

fn fake_png(width: u32, height: u32) -> Vec<u8> {
    let mut b = PNG_SIGNATURE.to_vec();
    b.extend_from_slice(&13u32.to_be_bytes()); // IHDR chunk length (not inspected, only the type/dims are)
    b.extend_from_slice(b"IHDR");
    b.extend_from_slice(&width.to_be_bytes());
    b.extend_from_slice(&height.to_be_bytes());
    b.extend_from_slice(b"whatever follows is never inspected here");
    b
}

#[test]
fn well_formed_png_with_valid_dimensions_is_passed_through_unchanged() {
    let png = fake_png(32, 32);
    assert_eq!(to_png(&png), Some(png.clone()));
}

/// The decompression-bomb guard this finding asked for: a PNG's own byte size says nothing about
/// the pixel buffer a real decoder would need for the dimensions it declares, so a PNG-in-ICO
/// entry claiming an absurd width/height must be rejected before being passed through, exactly
/// like an oversized DIB is rejected before being decoded.
#[test]
fn png_declaring_oversized_dimensions_is_rejected_not_passed_through() {
    for (w, h) in [(100_000u32, 32u32), (32, 100_000), (300, 300)] {
        let png = fake_png(w, h);
        assert_eq!(to_png(&png), None, "w={w} h={h}");
    }
}

#[test]
fn png_with_zero_width_or_height_is_rejected() {
    assert_eq!(to_png(&fake_png(0, 32)), None);
    assert_eq!(to_png(&fake_png(32, 0)), None);
}

#[test]
fn png_signature_whose_first_chunk_is_not_ihdr_is_rejected() {
    let mut b = PNG_SIGNATURE.to_vec();
    b.extend_from_slice(&13u32.to_be_bytes());
    b.extend_from_slice(b"IDAT"); // not the mandatory first chunk
    b.extend_from_slice(&32u32.to_be_bytes());
    b.extend_from_slice(&32u32.to_be_bytes());
    assert_eq!(to_png(&b), None);
}

#[test]
fn truncated_png_header_is_rejected_not_a_panic() {
    let full = fake_png(32, 32);
    for n in 0..24 {
        let r = std::panic::catch_unwind(|| to_png(&full[..n]));
        assert!(r.is_ok(), "panicked at prefix {n}");
        assert_eq!(r.unwrap(), None, "prefix {n} is not a complete IHDR");
    }
}

/// 300x300 is over hicolor's 256 maximum, but this DIB carries every byte a real 300x300 32bpp
/// image would need: without the explicit `MAX_EDGE` check, the pixel/mask bounds checks further
/// down would happily accept it (they only reject a size that does NOT fit the bytes given). This
/// isolates the dimension cap itself, rather than incidentally relying on a truncated-file guard
/// that a genuinely large, well-formed, full-size DIB would sail past.
#[test]
fn declared_dimensions_over_the_hicolor_max_are_rejected_even_with_full_backing_data() {
    let (width, height) = (300u32, 300u32);
    let xor_stride = width * 4;
    let and_stride = width.div_ceil(32) * 4;
    let mut dib = vec![0u8; 40];
    put32(&mut dib, 0, 40);
    put32(&mut dib, 4, width);
    put32(&mut dib, 8, height * 2);
    put16(&mut dib, 14, 32);
    dib.extend(vec![0u8; (xor_stride * height) as usize]);
    dib.extend(vec![0u8; (and_stride * height) as usize]);
    assert_eq!(decode_dib(&dib), None);
}

#[test]
fn truncated_dib_header_is_none_not_a_panic() {
    for n in 0..40 {
        assert_eq!(decode_dib(&vec![0u8; n]), None);
    }
}

#[test]
fn absurd_declared_dimensions_are_rejected_before_allocating() {
    for (w, h) in [(100_000i32, 2i32), (2, 100_000), (0, 2), (2, 0), (-1, 2), (2, -1)] {
        let mut dib = vec![0u8; 40];
        put32(&mut dib, 0, 40);
        put32(&mut dib, 4, w as u32);
        put32(&mut dib, 8, (h * 2) as u32);
        put16(&mut dib, 14, 32);
        assert_eq!(decode_dib(&dib), None, "w={w} h={h}");
    }
}

#[test]
fn odd_doubled_height_is_rejected() {
    let mut dib = vec![0u8; 40];
    put32(&mut dib, 0, 40);
    put32(&mut dib, 4, 2);
    put32(&mut dib, 8, 3); // not even: cannot be a valid XOR+AND doubled height
    put16(&mut dib, 14, 32);
    assert_eq!(decode_dib(&dib), None);
}

#[test]
fn unsupported_bit_depth_is_rejected_not_misdecoded() {
    let mut dib = vec![0u8; 40 + 64];
    put32(&mut dib, 0, 40);
    put32(&mut dib, 4, 2);
    put32(&mut dib, 8, 4);
    put16(&mut dib, 14, 8); // palette-based, not decoded (see module doc)
    assert_eq!(decode_dib(&dib), None);
}

#[test]
fn non_bi_rgb_compression_is_rejected() {
    let mut dib = build_dib(2, 2, 32, &[(0, 0, 0, 0); 4]);
    put32(&mut dib, 16, 1); // BI_RLE8 or anything non-zero: unsupported
    assert_eq!(decode_dib(&dib), None);
}

#[test]
fn truncated_pixel_data_is_rejected_not_read_out_of_bounds() {
    let full = build_dib(4, 4, 32, &[(1, 2, 3, 4); 16]);
    for n in 40..full.len() {
        assert_eq!(decode_dib(&full[..n]), None, "prefix {n}");
    }
    assert!(decode_dib(&full).is_some(), "the untruncated version must still decode");
}

/// xorshift byte-flip mutation of a valid 32bpp DIB: `decode_dib` must never panic, however the
/// bytes are corrupted (this is the "hostile icon resource never panics" guarantee this crate is
/// responsible for, one level below `pe`'s own no-panic guarantee on the resource directory).
#[test]
fn mutated_dib_bytes_never_panic() {
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }
    let template = build_dib(4, 4, 32, &[(9, 8, 7, 6); 16]);
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
        let r = std::panic::catch_unwind(|| decode_dib(&m));
        assert!(r.is_ok(), "panicked on iteration {n}: {m:?}");
    }
}
