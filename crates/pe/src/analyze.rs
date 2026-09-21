use crate::{Error, FileKind, detect, model::*};
use pelite::{PeFile, Wrap};
use std::collections::BTreeMap;

pub fn analyze(bytes: &[u8]) -> Result<PeInfo, Error> {
    if detect(bytes) != FileKind::Pe {
        return Err(Error::NotPe);
    }
    // pelite hands out `&T` straight into the buffer, so the buffer must be 8-aligned.
    let copy;
    let bytes = if bytes.as_ptr().align_offset(8) == 0 {
        bytes
    } else {
        copy = Aligned::new(bytes);
        copy.bytes()
    };
    let file = PeFile::from_bytes(bytes).map_err(|e| Error::Malformed(e.to_string()))?;
    check_layout(&file)?;
    let info = match file {
        Wrap::T32(f) => info32(f),
        Wrap::T64(f) => info64(f),
    };
    Ok(info)
}

/// pelite checks alignment against the RVA, not the real file offset. If a section's raw
/// pointer and RVA disagree mod 8, it would return misaligned references (UB) for tables in
/// that section. Real linkers never produce this; corrupted or hostile files do.
fn check_layout(file: &PeFile<'_>) -> Result<(), Error> {
    let bad = file
        .section_headers()
        .iter()
        .any(|s| s.SizeOfRawData != 0 && s.PointerToRawData.wrapping_sub(s.VirtualAddress) % 8 != 0);
    if bad {
        return Err(Error::Malformed(
            "section file offset and RVA are misaligned relative to each other".into(),
        ));
    }
    Ok(())
}

struct Aligned {
    words: Vec<u64>,
    len: usize,
}

impl Aligned {
    fn new(src: &[u8]) -> Self {
        let mut words = vec![0u64; src.len().div_ceil(8)];
        // SAFETY: `words` owns at least `src.len()` initialised bytes; u8 has no alignment needs.
        unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), src.len()) }.copy_from_slice(src);
        Self { words, len: src.len() }
    }
    fn bytes(&self) -> &[u8] {
        // SAFETY: same buffer as above, shared borrow.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
    }
}

// Export string limits. A forwarder or name is read through at most MAX_STRING_LEN + 1 bytes;
// all kept strings together may not exceed BYTES_BUDGET; each table is read up to
// MAX_EXPORT_ENTRIES entries.
const MAX_STRING_LEN: usize = 1024;
const BYTES_BUDGET: usize = 4 * 1024 * 1024;
const MAX_EXPORT_ENTRIES: usize = 65_536;

enum Str {
    Ok(String),
    /// Longer than MAX_STRING_LEN.
    TooLong,
    /// Mapped data ended before a NUL.
    Unterminated,
    /// RVA not inside any section.
    Unreadable,
}

/// Reads a NUL-terminated string from `bytes` (everything from the string's RVA to the end of its
/// section) touching at most MAX_STRING_LEN + 1 bytes, however long the data is.
fn read_bounded(bytes: &[u8]) -> Str {
    let window = &bytes[..bytes.len().min(MAX_STRING_LEN + 1)];
    match memchr::memchr(0, window) {
        Some(n) => Str::Ok(String::from_utf8_lossy(&window[..n]).into_owned()),
        None if window.len() > MAX_STRING_LEN => Str::TooLong,
        None => Str::Unterminated,
    }
}

/// Counts one kind of problem and remembers where it first happened, for one aggregate warning.
#[derive(Default)]
struct Tally {
    count: usize,
    first: usize,
}

impl Tally {
    fn hit(&mut self, at: usize) {
        if self.count == 0 {
            self.first = at;
        }
        self.count += 1;
    }
    fn warn(&self, warnings: &mut Vec<String>, what: &str, at: &str) {
        if self.count > 0 {
            warnings.push(format!("exports: {} {what} (first at {at} {})", self.count, self.first));
        }
    }
}

const DIR_SECURITY: usize = 4;
const DIR_DELAY_IMPORT: usize = 13;
const DIR_CLR: usize = 14;

// pelite's pe32 and pe64 modules expose identical APIs behind different traits, so the
// extraction body is stamped out once per word size.
macro_rules! extract {
    ($fn_name:ident, $pe:ident, $format:expr, $word:ty, $ord_flag:expr) => {
        fn $fn_name(f: pelite::$pe::PeFile<'_>) -> PeInfo {
            use pelite::$pe::Pe;
            let mut warnings = Vec::new();
            let fh = f.file_header();
            let oh = f.optional_header();
            let dirs = f.data_directory();
            // (rva, size) of a data directory; (0, 0) when absent.
            let dir = |i: usize| dirs.get(i).map_or((0, 0), |d| (d.VirtualAddress, d.Size));

            let sections = f
                .section_headers()
                .iter()
                .map(|s| Section {
                    name: s
                        .name()
                        .map(str::to_owned)
                        .unwrap_or_else(|b| String::from_utf8_lossy(b).into_owned()),
                    virtual_address: s.VirtualAddress,
                    virtual_size: s.VirtualSize,
                    raw_size: s.SizeOfRawData,
                    readable: s.Characteristics & 0x4000_0000 != 0,
                    writable: s.Characteristics & 0x8000_0000 != 0,
                    executable: s.Characteristics & 0x2000_0000 != 0,
                })
                .collect();

            // Walk import thunk arrays by hand. pelite's `int()` demands aligned tables and
            // rejects the 4-byte-aligned ones GNU ld emits for PE32+. Shared budget prevents
            // resource exhaustion (hostile files with unbounded thunk tables).
            let mut budget = 200_000usize;
            let mut thunks = |mut rva: u32, dll: &str, warnings: &mut Vec<String>| {
                let mut functions = Vec::new();
                if rva == 0 {
                    warnings.push(format!("imports: {dll} zero table RVA"));
                    return functions;
                }
                let mut terminated = false;
                for _ in 0..65_536 {
                    if budget == 0 {
                        warnings.push(format!(
                            "imports: {dll} budget exhausted at {} functions",
                            functions.len()
                        ));
                        break;
                    }
                    let Ok(v) = f.derva_copy::<$word>(rva) else {
                        warnings.push(format!("imports: {dll} truncated table at offset {:#x}", rva));
                        break;
                    };
                    if v == 0 {
                        terminated = true;
                        break;
                    }
                    // Compute next_rva FIRST, before handling value
                    let word_size = std::mem::size_of::<$word>() as u32;
                    let Some(next_rva) = rva.checked_add(word_size) else {
                        warnings.push(format!("imports: {dll} RVA overflow"));
                        break;
                    };
                    // Charge budget unconditionally
                    budget -= 1;
                    // Advance rva BEFORE handling value (so all continue paths advance)
                    rva = next_rva;
                    // Handle ordinal or by-name import
                    if v & $ord_flag != 0 {
                        functions.push(ImportedFn::Ordinal((v & 0xFFFF) as u16));
                    } else {
                        // For by-name: check value fits in 31 bits (ordinal flag in bit 31/63)
                        if v > 0x7FFF_FFFF {
                            warnings.push(format!("imports: {dll} thunk value overflows 31 bits ({:#x})", v));
                            continue;
                        }
                        let name_rva = (v as u32).checked_add(2).unwrap_or(0);
                        if name_rva == 0 {
                            warnings.push(format!("imports: {dll} thunk value overflow at {:#x}", v));
                            continue;
                        }
                        match f.derva_c_str(name_rva) {
                            Ok(n) => {
                                if n.len() > 1024 {
                                    warnings.push(format!("imports: {dll} name too long ({} bytes)", n.len()));
                                    continue;
                                }
                                functions.push(ImportedFn::Name(n.to_string()));
                            }
                            Err(_) => {
                                warnings.push(format!(
                                    "imports: {dll} unreadable function name at {:#x}",
                                    name_rva
                                ));
                            }
                        }
                    }
                }
                if !terminated {
                    warnings.push(format!(
                        "imports: {dll} thunk table not terminated within 65536 entries"
                    ));
                }
                functions
            };

            let mut imports = Vec::new();
            match f.imports() {
                Ok(list) => {
                    let mut desc_count = 0;
                    for desc in list {
                        if desc_count >= 4096 {
                            warnings.push("imports: descriptor limit (4096) exceeded".to_owned());
                            break;
                        }
                        desc_count += 1;
                        let Ok(dll) = desc.dll_name() else {
                            warnings.push("imports: unreadable DLL name".to_owned());
                            continue;
                        };
                        let dll_str = dll.to_string();
                        let d = desc.image();
                        // Fall back to the IAT when the lookup table is absent (old linkers).
                        let table = if d.OriginalFirstThunk != 0 {
                            d.OriginalFirstThunk
                        } else {
                            d.FirstThunk
                        };
                        imports.push(Import {
                            dll: dll_str.clone(),
                            delay: false,
                            functions: thunks(table, &dll_str, &mut warnings),
                        });
                    }
                }
                Err(pelite::Error::Null) => {}
                Err(e) => warnings.push(format!("imports: {e}")),
            }

            // pelite has no delay-import support: walk IMAGE_DELAYLOAD_DESCRIPTOR (8 x u32) by hand.
            if dir(DIR_DELAY_IMPORT).0 != 0 {
                let mut rva = dir(DIR_DELAY_IMPORT).0;
                let mut terminated = false;
                for _ in 0..4096 {
                    let Ok(d) = f.derva_copy::<[u32; 8]>(rva) else {
                        warnings.push("delay imports: truncated descriptor".to_owned());
                        break;
                    };
                    if d[1] == 0 {
                        terminated = true;
                        break;
                    }
                    let next_rva = rva.checked_add(32).unwrap_or(0);
                    if next_rva == 0 {
                        warnings.push("delay imports: RVA overflow".to_owned());
                        break;
                    }
                    rva = next_rva;
                    if d[0] & 1 == 0 {
                        warnings.push("delay imports: VA-based descriptor unsupported".to_owned());
                        continue;
                    }
                    let Ok(dll) = f.derva_c_str(d[1]) else {
                        warnings.push("delay imports: unreadable DLL name".to_owned());
                        continue;
                    };
                    let dll_str = dll.to_string();
                    imports.push(Import {
                        dll: dll_str.clone(),
                        delay: true,
                        functions: thunks(d[4], &dll_str, &mut warnings),
                    });
                }
                if !terminated {
                    warnings.push("delay imports: descriptor table not terminated within 4096 entries".to_owned());
                }
            }

            let mut exports = Vec::new();
            match f.exports() {
                Ok(ex) => {
                    let base = ex.ordinal_base() as u32;
                    // Note: pelite's Ordinal is u16; bases above 0xFFFF silently truncate. No panic, wrong ordinals.
                    match ex.by() {
                        Ok(by) => {
                            // pelite's `&str`/`Forward` accessors scan to the NUL with no limit, so
                            // many entries pointing at one huge unterminated string cost a full scan
                            // each. Read every string ourselves through `read_bounded` instead.
                            // `by.index()` is avoided for the same reason and because pelite's
                            // forwarder check adds the directory RVA and size in u32 (overflows).
                            let (dir_rva, dir_size) = dir(0);
                            let in_dir = |rva: u32| {
                                u64::from(rva) >= u64::from(dir_rva) && u64::from(rva) < u64::from(dir_rva) + u64::from(dir_size)
                            };
                            let read = |rva: u32| f.slice_bytes(rva).map_or(Str::Unreadable, read_bounded);
                            let mut bytes_used = 0usize;
                            let mut budget_exhausted = false;
                            // Charges `len` against the shared budget; false (and flagged) if it does not fit.
                            let mut charge = |len: usize| {
                                if bytes_used + len <= BYTES_BUDGET {
                                    bytes_used += len;
                                    true
                                } else {
                                    budget_exhausted = true;
                                    false
                                }
                            };
                            let funcs = by.functions();
                            let funcs_len = funcs.len().min(MAX_EXPORT_ENTRIES);
                            let name_rvas = by.names();
                            let name_len = name_rvas.len().min(MAX_EXPORT_ENTRIES);
                            if name_rvas.len() > name_len {
                                warnings.push(format!(
                                    "exports: name table has {} entries, only the first {MAX_EXPORT_ENTRIES} were read",
                                    name_rvas.len()
                                ));
                            }
                            if funcs.len() > funcs_len {
                                warnings.push(format!(
                                    "exports: function table has {} entries, only the first {MAX_EXPORT_ENTRIES} were read",
                                    funcs.len()
                                ));
                            }

                            let mut names = BTreeMap::new();
                            let (mut oob, mut name_long, mut name_open, mut name_bad) =
                                (Tally::default(), Tally::default(), Tally::default(), Tally::default());
                            let name_idx = by.name_indices();
                            for (hint, (&rva, &idx)) in name_rvas.iter().zip(name_idx).take(name_len).enumerate() {
                                let idx = usize::from(idx);
                                if idx >= funcs_len {
                                    oob.hit(idx);
                                    continue;
                                }
                                match read(rva) {
                                    Str::Ok(n) => {
                                        if charge(n.len()) {
                                            names.insert(idx, n);
                                        }
                                    }
                                    Str::TooLong => name_long.hit(hint),
                                    Str::Unterminated => name_open.hit(hint),
                                    Str::Unreadable => name_bad.hit(hint),
                                }
                            }
                            oob.warn(&mut warnings, "name entries out of range", "index");
                            name_long.warn(&mut warnings, "names too long", "name entry");
                            name_open.warn(&mut warnings, "names unterminated", "name entry");
                            name_bad.warn(&mut warnings, "names unreadable", "name entry");

                            let (mut fwd_long, mut fwd_open, mut fwd_bad) =
                                (Tally::default(), Tally::default(), Tally::default());
                            for (idx, &rva) in funcs.iter().enumerate().take(funcs_len) {
                                if rva == 0 {
                                    continue; // unused slot
                                }
                                let mut forwarder = None;
                                // An RVA inside the export directory is a forwarder string.
                                // A forwarder that cannot be read keeps its export (ordinal and name are
                                // still real) with `forwarder: None`; the aggregate warning below is what
                                // records that it was a forwarder.
                                if in_dir(rva) {
                                    match read(rva) {
                                        Str::Ok(s) => {
                                            if charge(s.len()) {
                                                forwarder = Some(s);
                                            }
                                        }
                                        Str::TooLong => fwd_long.hit(idx),
                                        Str::Unterminated => fwd_open.hit(idx),
                                        Str::Unreadable => fwd_bad.hit(idx),
                                    }
                                }
                                exports.push(Export {
                                    name: names.remove(&idx),
                                    ordinal: base.saturating_add(idx as u32),
                                    forwarder,
                                });
                            }
                            fwd_long.warn(&mut warnings, "forwarders too long", "index");
                            fwd_open.warn(&mut warnings, "forwarders unterminated", "index");
                            fwd_bad.warn(&mut warnings, "forwarders unreadable", "index");
                            if budget_exhausted {
                                warnings.push(format!(
                                    "exports: string budget (~{BYTES_BUDGET} bytes) exhausted at {bytes_used} bytes"
                                ));
                            }
                        }
                        Err(e) => warnings.push(format!("exports: {e}")),
                    }
                }
                Err(pelite::Error::Null) => {}
                Err(e) => warnings.push(format!("exports: {e}")),
            }

            let mut relocation_count = 0;
            match f.base_relocs() {
                Ok(r) => relocation_count = r.fold(0usize, |n, _rva, ty| n + usize::from(ty != 0)),
                Err(pelite::Error::Null) => {}
                Err(e) => warnings.push(format!("relocations: {e}")),
            }

            let mut tls = None;
            match f.tls() {
                Ok(t) => {
                    let callback_count = match t.callbacks() {
                        Ok(c) => c.len(),
                        Err(pelite::Error::Null) => 0, // no callback array
                        Err(e) => {
                            warnings.push(format!("tls callbacks: {e}"));
                            0
                        }
                    };
                    tls = Some(Tls { callback_count })
                }
                Err(pelite::Error::Null) => {}
                Err(e) => warnings.push(format!("tls: {e}")),
            }

            let version = None;

            PeInfo {
                format: $format,
                arch: Arch::from_machine(fh.Machine),
                kind: if fh.Characteristics & 0x2000 != 0 {
                    Kind::Dll
                } else {
                    Kind::Exe
                },
                subsystem: Subsystem::from_raw(oh.Subsystem),
                image_base: oh.ImageBase as u64,
                entry_point_rva: oh.AddressOfEntryPoint,
                size_of_image: oh.SizeOfImage,
                aslr: oh.DllCharacteristics & 0x0040 != 0,
                nx: oh.DllCharacteristics & 0x0100 != 0,
                signed: dir(DIR_SECURITY).1 != 0,
                dotnet: dir(DIR_CLR).0 != 0,
                sections,
                imports,
                exports,
                relocation_count,
                tls,
                version,
                installer: None,
                warnings,
            }
        }
    };
}

extract!(info32, pe32, Format::Pe32, u32, 0x8000_0000u32);
extract!(info64, pe64, Format::Pe32Plus, u64, 0x8000_0000_0000_0000u64);
