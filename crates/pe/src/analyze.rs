use crate::{Error, FileKind, detect, installer, model::*, version};
use pelite::resources::FindError;
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
    let mut info = match file {
        Wrap::T32(f) => info32(f),
        Wrap::T64(f) => info64(f),
    };
    info.installer = installer::detect(bytes, &info);
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
    /// Same, for one import table; the position is an RVA.
    fn warn_rva(&self, warnings: &mut Vec<String>, scope: &str, dll: &str, what: &str, at: &str) {
        if self.count > 0 {
            warnings.push(format!(
                "{scope}: {dll}: {} {what} (first at {at} RVA {:#x})",
                self.count, self.first
            ));
        }
    }
}

/// Reads a DLL name (import or delay-import descriptor): `Err` says what is wrong with it.
fn dll_name(bytes: Option<&[u8]>) -> Result<String, &'static str> {
    match bytes.map_or(Str::Unreadable, read_bounded) {
        Str::Ok(n) => Ok(n),
        Str::TooLong => Err("DLL name too long"),
        Str::Unterminated => Err("unterminated DLL name"),
        Str::Unreadable => Err("unreadable DLL name"),
    }
}

// Import walk limits: thunks per table, thunks over the whole file, descriptors per directory.
const MAX_THUNKS_PER_TABLE: usize = 65_536;
const MAX_IMPORT_THUNKS: usize = 200_000;
const MAX_DESCRIPTORS: usize = 4096;

const DIR_EXPORT: usize = 0;
const DIR_IMPORT: usize = 1;
const DIR_RESOURCE: usize = 2;
const DIR_SECURITY: usize = 4;
const DIR_BASERELOC: usize = 5;
const DIR_TLS: usize = 9;
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
            // rejects the 4-byte-aligned ones GNU ld emits for PE32+. Every string is read through
            // `read_bounded` (pelite's `derva_c_str` scans to the NUL without limit), and two shared
            // budgets bound what a hostile file can make us do: MAX_IMPORT_THUNKS thunks and
            // BYTES_BUDGET bytes of function names, over all tables together.
            let mut budget = MAX_IMPORT_THUNKS;
            let mut name_bytes = BYTES_BUDGET;
            let mut thunks = |mut rva: u32, scope: &str, dll: &str, warnings: &mut Vec<String>| {
                let mut functions = Vec::new();
                if rva == 0 {
                    warnings.push(format!("{scope}: {dll} zero table RVA"));
                    return functions;
                }
                // Per-thunk problems are counted, not listed: a hostile table would otherwise turn
                // each of up to 200_000 thunks into a warning string.
                let (mut wide, mut long, mut open, mut bad, mut no_room) = (
                    Tally::default(),
                    Tally::default(),
                    Tally::default(),
                    Tally::default(),
                    Tally::default(),
                );
                // Why the walk stopped early; None when the table ended with its terminator.
                let mut stop = None;
                let mut n = 0usize;
                loop {
                    let Ok(v) = f.derva_copy::<$word>(rva) else {
                        stop = Some(format!("{scope}: {dll} truncated table at RVA {rva:#x}"));
                        break;
                    };
                    if v == 0 {
                        break;
                    }
                    if n == MAX_THUNKS_PER_TABLE {
                        stop = Some(format!(
                            "{scope}: {dll} thunk table not terminated within {MAX_THUNKS_PER_TABLE} entries"
                        ));
                        break;
                    }
                    if budget == 0 {
                        stop = Some(format!("{scope}: {dll} budget exhausted at {} functions", functions.len()));
                        break;
                    }
                    let Some(next_rva) = rva.checked_add(std::mem::size_of::<$word>() as u32) else {
                        stop = Some(format!("{scope}: {dll} RVA overflow at {rva:#x}"));
                        break;
                    };
                    let thunk_rva = rva;
                    budget -= 1;
                    n += 1;
                    rva = next_rva;
                    if v & $ord_flag != 0 {
                        functions.push(ImportedFn::Ordinal((v & 0xFFFF) as u16));
                    } else if v > 0x7FFF_FFFF {
                        // Only reachable for PE32+: an RVA has 31 bits, the rest must be zero.
                        wide.hit(thunk_rva as usize);
                    } else {
                        let name_rva = v as u32 + 2; // skips the u16 hint; cannot overflow
                        match f.slice_bytes(name_rva).map_or(Str::Unreadable, read_bounded) {
                            Str::Ok(name) if name.len() <= name_bytes => {
                                name_bytes -= name.len();
                                functions.push(ImportedFn::Name(name));
                            }
                            Str::Ok(_) => no_room.hit(name_rva as usize),
                            Str::TooLong => long.hit(name_rva as usize),
                            Str::Unterminated => open.hit(name_rva as usize),
                            Str::Unreadable => bad.hit(name_rva as usize),
                        }
                    }
                }
                wide.warn_rva(warnings, scope, dll, "thunk values overflow 31 bits", "thunk");
                long.warn_rva(warnings, scope, dll, "names too long", "name");
                open.warn_rva(warnings, scope, dll, "names unterminated", "name");
                bad.warn_rva(warnings, scope, dll, "names unreadable", "name");
                no_room.warn_rva(warnings, scope, dll, "names dropped, string budget exhausted", "name");
                warnings.extend(stop);
                functions
            };

            let mut imports = Vec::new();
            match f.imports() {
                Ok(list) => {
                    let dir_rva = dir(DIR_IMPORT).0;
                    let at = |idx: usize| dir_rva.wrapping_add((idx * 20) as u32);
                    let count = list.image().len();
                    for (idx, desc) in list.into_iter().enumerate() {
                        if idx >= MAX_DESCRIPTORS {
                            warnings.push(format!("imports: descriptor limit ({MAX_DESCRIPTORS}) exceeded"));
                            break;
                        }
                        let d = desc.image();
                        let dll = match dll_name(f.slice_bytes(d.Name).ok()) {
                            Ok(n) => n,
                            Err(why) => {
                                warnings.push(format!("imports: {why} (descriptor {idx}, RVA {:#x})", at(idx)));
                                continue;
                            }
                        };
                        // Fall back to the IAT when the lookup table is absent (old linkers).
                        let table = if d.OriginalFirstThunk != 0 {
                            d.OriginalFirstThunk
                        } else {
                            d.FirstThunk
                        };
                        let functions = thunks(table, "imports", &dll, &mut warnings);
                        imports.push(Import {
                            dll,
                            delay: false,
                            functions,
                        });
                    }
                    // pelite ends the list at the first descriptor with FirstThunk == 0 (so a
                    // zero table RVA cannot reach `thunks` from here). Real linkers write an
                    // all-zero terminator; anything else there was cut off, so say so.
                    if let Ok(t) = f.derva_copy::<[u32; 5]>(at(count)) {
                        if t != [0; 5] {
                            warnings.push(format!(
                                "imports: descriptor {count} (RVA {:#x}) has FirstThunk 0 but other fields set; \
                                 list ends there",
                                at(count)
                            ));
                        }
                    }
                }
                Err(pelite::Error::Null) => {}
                Err(pelite::Error::Bounds) if dirs.len() <= DIR_IMPORT => {}
                Err(e) => warnings.push(format!("imports: {e}")),
            }

            // pelite has no delay-import support: walk IMAGE_DELAYLOAD_DESCRIPTOR (8 x u32) by hand.
            if dir(DIR_DELAY_IMPORT).0 != 0 {
                let mut rva = dir(DIR_DELAY_IMPORT).0;
                let mut idx = 0usize;
                loop {
                    let ctx = format!("descriptor {idx}, RVA {rva:#x}");
                    let Ok(d) = f.derva_copy::<[u32; 8]>(rva) else {
                        warnings.push(format!("delay imports: truncated descriptor ({ctx})"));
                        break;
                    };
                    if d[1] == 0 {
                        break;
                    }
                    if idx == MAX_DESCRIPTORS {
                        warnings.push(format!(
                            "delay imports: descriptor table not terminated within {MAX_DESCRIPTORS} entries"
                        ));
                        break;
                    }
                    let Some(next_rva) = rva.checked_add(32) else {
                        warnings.push(format!("delay imports: RVA overflow ({ctx})"));
                        break;
                    };
                    rva = next_rva;
                    idx += 1;
                    if d[0] & 1 == 0 {
                        warnings.push(format!("delay imports: VA-based descriptor unsupported ({ctx})"));
                        continue;
                    }
                    let dll = match dll_name(f.slice_bytes(d[1]).ok()) {
                        Ok(n) => n,
                        Err(why) => {
                            warnings.push(format!("delay imports: {why} ({ctx})"));
                            continue;
                        }
                    };
                    let functions = thunks(d[4], "delay imports", &dll, &mut warnings);
                    imports.push(Import {
                        dll,
                        delay: true,
                        functions,
                    });
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
                            let (dir_rva, dir_size) = dir(DIR_EXPORT);
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
                Err(pelite::Error::Bounds) if dirs.len() <= DIR_EXPORT => {}
                Err(e) => warnings.push(format!("exports: {e}")),
            }

            let mut relocation_count = 0;
            match f.base_relocs() {
                Ok(r) => {
                    // Walk the blocks here instead of using pelite's iterator: it rounds
                    // SizeOfBlock up to 4 with a wrapping add, so a SizeOfBlock of 0xFFFFFFFD..FF
                    // makes it advance by 0 and yield the same block forever (a hang). It also
                    // skips a malformed block (SizeOfBlock < 8, or running past the end of the
                    // directory) without a word. Same advance rule, but every step moves forward,
                    // and anything odd is reported.
                    let data = r.image();
                    let mut off = 0usize;
                    let mut bad = Tally::default();
                    while data.len() - off >= 8 {
                        let left = data.len() - off;
                        let word = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap_or_default());
                        let (page, size) = (word(off), word(off + 4) as usize);
                        // An all-zero header is the "no relocations" idiom (Wine's builtin stubs
                        // carry a directory of exactly one), not damage.
                        if (size < 8 || size > left) && (page, size) != (0, 0) {
                            bad.hit(off);
                        }
                        let words = &data[off + 8..off + size.clamp(8, left)];
                        relocation_count += words.chunks_exact(2).filter(|w| w[1] >> 4 != 0).count();
                        off += size.max(8).next_multiple_of(4).min(left);
                    }
                    if bad.count > 0 {
                        warnings.push(format!(
                            "relocations: {} malformed blocks (SizeOfBlock under 8 or past the end of the directory), \
                             first at directory offset {:#x}",
                            bad.count, bad.first
                        ));
                    }
                    if off < data.len() {
                        warnings.push(format!("relocations: {} trailing bytes ignored", data.len() - off));
                    }
                }
                Err(pelite::Error::Null) => {}
                Err(pelite::Error::Bounds) if dirs.len() <= DIR_BASERELOC => {}
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
                Err(pelite::Error::Bounds) if dirs.len() <= DIR_TLS => {}
                Err(e) => warnings.push(format!("tls: {e}")),
            }

            // RT_VERSION is read as raw bytes and parsed by `version::parse`; pelite's own
            // VersionInfo walker panics on crafted input. No resource directory (or fewer than
            // three data directories) means no version info, silently.
            let mut version = None;
            let (res_rva, res_size) = dir(DIR_RESOURCE);
            if res_rva != 0 && res_size != 0 {
                if res_rva % 4 != 0 {
                    // pelite would read 4-aligned directory structures from misaligned memory.
                    warnings.push(format!("resources: directory RVA {res_rva:#x} is not 4-byte aligned"));
                } else {
                    match f.resources() {
                        Ok(res) => match version::find(&res) {
                            Ok(raw) => match version::parse(raw) {
                                Ok(v) => version = Some(v),
                                Err(e) => warnings.push(format!("version info: {e}")),
                            },
                            Err(FindError::NotFound) => {}
                            Err(e) => warnings.push(format!("version info: {e}")),
                        },
                        Err(pelite::Error::Null) => {}
                        Err(e) => warnings.push(format!("resources: {e}")),
                    }
                }
            }

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
