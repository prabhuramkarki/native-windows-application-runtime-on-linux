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
const DIR_CLR: usize = 14;

// pelite's pe32 and pe64 modules expose identical APIs behind different traits, so the
// extraction body is stamped out once per word size.
macro_rules! extract {
    ($fn_name:ident, $pe:ident, $format:expr, $word:ty, $ord_flag:expr) => {
        fn $fn_name(f: pelite::$pe::PeFile<'_>) -> PeInfo {
            use pelite::$pe::Pe;
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

            let imports = Vec::new();

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
                warnings: Vec::new(),
            }
        }
    };
}

extract!(info32, pe32, Format::Pe32, u32, 0x8000_0000u32);
extract!(info64, pe64, Format::Pe32Plus, u64, 0x8000_0000_0000_0000u64);
