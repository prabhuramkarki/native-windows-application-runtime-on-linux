//! Extracts a PE's icon (its RT_GROUP_ICON/RT_ICON resources, via `runtime-pe`) as PNG bytes at
//! requested hicolor sizes.
//!
//! **Bytes are untrusted** (the PE is a hostile installer's own `.exe`, and the ICO "image" data
//! inside an icon resource is a further, separately-crafted structure this module must not trust
//! just because `pe::find_group_icon`/`pe::icon_bytes` returned it cleanly). Two kinds of failure
//! are distinguished deliberately:
//!
//! * **The input is not analysable as a PE at all** (`pe::Error::NotPe`): [`extract_icon_png`]
//!   returns `Err`. A caller handed the wrong file entirely, and every requested size would fail
//!   for the same reason, so there is nothing useful to return per-size.
//! * **Everything else** — no resource directory, no RT_GROUP_ICON, a corrupt resource walk, a
//!   missing RT_ICON member, a truncated or hostile DIB, dimensions or a bit depth this module
//!   does not decode — is treated as "no usable icon for this input/size", never a hard error.
//!   `Ok(vec![])` for no icon at all; for a group icon that exists but where some requested sizes
//!   fail to decode, those sizes are simply **absent from the returned `Vec`** — the caller can
//!   tell exactly which sizes came back by checking which `u32` keys are present, and one bad
//!   size never blocks the others.
//!
//! **Decoding.** An ICO "image" entry is either a raw PNG stream (common for a 256x256 entry, and
//! in practice for smaller ones too — real encoders vary) or an uncompressed DIB (a
//! `BITMAPINFOHEADER` followed by XOR color data and a 1bpp AND transparency mask, with NO
//! `BITMAPFILEHEADER`, per the ICO format). PNG is detected by its magic bytes and passed through
//! byte-for-byte, never re-encoded. A DIB is decoded and re-encoded as PNG with the `png` crate
//! (MIT OR Apache-2.0; not hand-rolled, per the project's own stance on vetted format crates —
//! see `docs/THIRD_PARTY.md`).
//!
//! ponytail: only 24bpp and 32bpp uncompressed (`BI_RGB`) DIBs are decoded — real icon resources
//! built by any current toolchain are one of these two (or already PNG); older 1/4/8bpp palette
//! DIBs return `Err` for that one size (never a panic, never silently wrong pixels) rather than
//! adding a palette decoder nothing here has a test fixture for. Add palette support if a real
//! installer's icon needs it.
//!
//! **Bounds.** hicolor's own maximum is 256x256; a DIB declaring anything larger (or non-positive)
//! is rejected before any pixel/mask data is read or any output buffer is allocated — a hostile PE
//! can put an arbitrary `biWidth`/`biHeight` in the header, and 256x256 RGBA (262 144 bytes) is
//! already far under the stated 16 MiB single-icon allocation ceiling, so this one check enforces
//! both. Every subsequent slice access is a checked `.get(..)`, never raw indexing, so a `biSize`,
//! row stride or mask offset that does not fit the actual bytes present is an `Err` for that size,
//! never a panic or an out-of-bounds read.
use std::io::Cursor;

/// hicolor's own maximum edge length; also this module's cap on a DIB's declared dimensions.
const MAX_EDGE: u32 = 256;
/// Never allocate more than this for one icon's decoded RGBA buffer. 256x256x4 = 262 144 bytes,
/// comfortably under this; the check exists so the *reason* a huge declared size is rejected is
/// documented and tested independently of the 256-edge cap happening to imply it.
const MAX_ALLOC_BYTES: usize = 16 * 1024 * 1024;

const PNG_MAGIC: &[u8] = b"\x89PNG";

/// Why the WHOLE call failed (see the module doc for what does, and does not, reach this — most
/// failures instead just leave one requested size absent from the result).
#[derive(Debug, thiserror::Error)]
pub enum IconError {
    #[error("not a PE file")]
    NotPe,
}

/// Extracts the best-matching icon for each of `sizes` (pass hicolor's own sizes, `&[16, 32, 48,
/// 128, 256]`, for a normal install) from a PE image's icon-group resource, as PNG bytes. See the
/// module doc for exactly what is an `Err` versus a size simply missing from the result.
///
/// Picking the "best" RT_ICON member for a requested size: the member whose declared width is
/// closest to it (real icon directories are square in practice, so width alone is used as each
/// member's effective size); a tie in distance is broken toward the LARGER member (upscaling a
/// display is preferable to it looking worse than it has to — never zoomed-in blur from a smaller
/// source when a bigger one was available). The same source member can legitimately end up
/// serving several different requested sizes when the PE only carries one or a few — the returned
/// bytes are that member's actual pixel data at ITS OWN resolution, not resized to the requested
/// size; a consumer that cares about exact pixel dimensions can read them back out of the PNG
/// itself.
pub fn extract_icon_png(pe_bytes: &[u8], sizes: &[u32]) -> Result<Vec<(u32, Vec<u8>)>, IconError> {
    let entries = match pe::find_group_icon(pe_bytes) {
        Ok(Some(entries)) if !entries.is_empty() => entries,
        Ok(_) => return Ok(Vec::new()), // no group icon, or an empty one: nothing to extract
        Err(pe::Error::NotPe) => return Err(IconError::NotPe),
        // A PE-shaped file whose resource directory is corrupt is "no usable icon", not a hard
        // failure of the whole call: every other Task 3 accessor treats a hostile icon resource
        // the same leniently (see the module doc).
        Err(pe::Error::Malformed(_)) => return Ok(Vec::new()),
    };

    let mut out = Vec::with_capacity(sizes.len());
    for &want in sizes {
        let best = entries
            .iter()
            .min_by_key(|e| (u32::from(e.width).abs_diff(want), std::cmp::Reverse(e.width)))
            .expect("entries is non-empty, checked above");
        let Ok(Some(raw)) = pe::icon_bytes(pe_bytes, best.id) else {
            continue; // no RT_ICON data for this id, or the resource walk failed: skip this size
        };
        let Some(png) = to_png(&raw) else { continue };
        out.push((want, png));
    }
    Ok(out)
}

/// Returns `raw` unchanged if it is already a PNG stream, otherwise decodes it as an ICO DIB entry
/// and re-encodes as PNG. `None`: unusable (truncated, hostile dimensions, or an unsupported bit
/// depth) — never a panic.
fn to_png(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.starts_with(PNG_MAGIC) {
        return Some(raw.to_vec());
    }
    let (width, height, rgba) = decode_dib(raw)?;
    encode_png(width, height, &rgba)
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}
fn i32_at(b: &[u8], at: usize) -> Option<i32> {
    u32_at(b, at).map(|v| v as i32)
}
fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

/// Row size in bytes for `width` pixels at `bytes_per_pixel`, padded up to a 4-byte boundary
/// (every DIB row is; see [MS-WMF]/BMP). `None` on overflow (never reachable once `width` is
/// capped at [`MAX_EDGE`], but checked regardless: nothing here trusts its own earlier checks to
/// justify skipping a checked op it can get for free).
fn row_stride(width: u32, bytes_per_pixel: u32) -> Option<u32> {
    width
        .checked_mul(bytes_per_pixel)?
        .checked_add(3)?
        .checked_div(4)?
        .checked_mul(4)
}

/// Decodes an uncompressed 24bpp or 32bpp `BI_RGB` DIB (a `BITMAPINFOHEADER` plus XOR color data
/// and a 1bpp AND mask, no `BITMAPFILEHEADER` — the ICO convention) into `(width, height, rgba)`.
/// `None` for anything else: truncated header, non-positive/odd/oversized declared dimensions,
/// an unsupported bit depth or compression, or pixel/mask data that does not fit the bytes given.
fn decode_dib(raw: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    const HEADER_LEN: usize = 40;
    if raw.len() < HEADER_LEN {
        return None;
    }
    let bi_size = u32_at(raw, 0)?;
    if bi_size < HEADER_LEN as u32 {
        return None;
    }
    let width = i32_at(raw, 4)?;
    let doubled_height = i32_at(raw, 8)?; // ICO stores XOR-mask height + AND-mask height together
    let bit_count = u16_at(raw, 14)?;
    let compression = u32_at(raw, 16)?;
    if compression != 0 {
        return None; // BI_RGB only
    }
    if width <= 0 || doubled_height <= 0 || doubled_height % 2 != 0 {
        return None;
    }
    let (width, height) = (width as u32, (doubled_height / 2) as u32);
    // The whole point of this check: reject before allocating or computing further, on the
    // DIB's OWN declared size, independent of whatever the group-icon directory entry claimed.
    if width == 0 || height == 0 || width > MAX_EDGE || height > MAX_EDGE {
        return None;
    }
    let rgba_len = (width as usize).checked_mul(height as usize)?.checked_mul(4)?;
    if rgba_len > MAX_ALLOC_BYTES {
        return None;
    }

    let bytes_per_pixel = match bit_count {
        24 => 3,
        32 => 4,
        _ => return None, // ponytail: palette (1/4/8bpp) DIBs are not decoded, see the module doc
    };
    let xor_stride = row_stride(width, bytes_per_pixel)?;
    let xor_size = xor_stride.checked_mul(height)?;
    // AND mask: 1 bit per pixel, rows padded to a 4-byte boundary.
    let and_stride = width.checked_add(31)?.checked_div(32)?.checked_mul(4)?;
    let and_size = and_stride.checked_mul(height)?;

    let pixels_start = bi_size as usize;
    let pixels_end = pixels_start.checked_add(xor_size as usize)?;
    let mask_end = pixels_end.checked_add(and_size as usize)?;
    let pixels = raw.get(pixels_start..pixels_end)?;
    let mask = raw.get(pixels_end..mask_end)?;

    let mut rgba = vec![0u8; rgba_len];
    for y in 0..height {
        // DIB rows are stored bottom-up; output row 0 is the top of the image.
        let src_row = height - 1 - y;
        let row = pixels.get((src_row * xor_stride) as usize..)?;
        let mask_row = mask.get((src_row * and_stride) as usize..)?;
        for x in 0..width {
            let px = row.get((x * bytes_per_pixel) as usize..(x * bytes_per_pixel + bytes_per_pixel) as usize)?;
            let (b, g, r) = (px[0], px[1], px[2]);
            let alpha = if bytes_per_pixel == 4 {
                px[3] // 32bpp icons carry real alpha; the AND mask is redundant and ignored for these
            } else {
                let byte = *mask_row.get((x / 8) as usize)?;
                let bit_set = byte & (0x80 >> (x % 8)) != 0;
                if bit_set { 0 } else { 255 } // AND mask: 1 = transparent
            };
            let out = (y * width + x) as usize * 4;
            rgba[out..out + 4].copy_from_slice(&[r, g, b, alpha]);
        }
    }
    Some((width, height, rgba))
}

fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut encoder = png::Encoder::new(Cursor::new(&mut buf), width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().ok()?;
        writer.write_image_data(rgba).ok()?;
    }
    Some(buf)
}

#[cfg(test)]
mod tests;
