use crate::{Error, FileKind, detect, model::*};
use pelite::{PeFile, Wrap};

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
                        break;
                    }
                    if v & $ord_flag != 0 {
                        functions.push(ImportedFn::Ordinal((v & 0xFFFF) as u16));
                        budget -= 1;
                    } else {
                        let name_rva = (v as u32).checked_add(2).unwrap_or(0);
                        if name_rva == 0 {
                            warnings.push(format!("imports: {dll} thunk value overflows u32 ({:#x})", v));
                            continue;
                        }
                        match f.derva_c_str(name_rva) {
                            Ok(n) => {
                                if n.len() > 1024 {
                                    warnings.push(format!("imports: {dll} name too long ({} bytes)", n.len()));
                                    continue;
                                }
                                functions.push(ImportedFn::Name(n.to_string()));
                                budget -= 1;
                            }
                            Err(_) => {
                                warnings.push(format!(
                                    "imports: {dll} unreadable function name at {:#x}",
                                    name_rva
                                ));
                            }
                        }
                    }
                    let word_size = std::mem::size_of::<$word>() as u32;
                    let Some(next_rva) = rva.checked_add(word_size) else {
                        warnings.push(format!("imports: {dll} RVA overflow"));
                        break;
                    };
                    rva = next_rva;
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
                let mut delay_count = 0;
                for _ in 0..4096 {
                    if delay_count >= 4096 {
                        warnings.push("delay imports: descriptor limit (4096) exceeded".to_owned());
                        break;
                    }
                    let Ok(d) = f.derva_copy::<[u32; 8]>(rva) else {
                        warnings.push("delay imports: truncated descriptor".to_owned());
                        break;
                    };
                    if d[1] == 0 {
                        break;
                    }
                    delay_count += 1;
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
            }

            let exports = Vec::new();

            let relocation_count = 0;

            let tls = None;

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
