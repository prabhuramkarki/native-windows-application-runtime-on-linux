//! Synthetic PE builder: lets unit tests craft exact header/table layouts without a Windows
//! toolchain. Layout: 0x400 bytes of headers, then one 0x1000-aligned section per entry.
#![allow(dead_code)]

pub const DATA_R: u32 = 0x4000_0040; // initialised data, readable
pub const DATA_RW: u32 = 0xC000_0040;
pub const CODE_RX: u32 = 0x6000_0020;

pub struct Builder {
    pub pe32plus: bool,
    pub machine: u16,
    pub dll: bool,
    pub subsystem: u16,
    pub sections: Vec<(&'static str, u32, Vec<u8>)>,
    /// (data directory index, rva, size)
    pub dirs: Vec<(usize, u32, u32)>,
    /// NumberOfRvaAndSizes as written to the header (default 16). Entries in `dirs` at or above
    /// this index are still written to the (always 16-entry) table area but the parser ignores them.
    pub num_dirs: u32,
    pub overlay: Vec<u8>,
}

impl Builder {
    pub fn x64() -> Self {
        Self {
            pe32plus: true,
            machine: 0x8664,
            dll: false,
            subsystem: 3,
            sections: vec![],
            dirs: vec![],
            num_dirs: 16,
            overlay: vec![],
        }
    }
    pub fn x86() -> Self {
        Self {
            pe32plus: false,
            machine: 0x014C,
            ..Self::x64()
        }
    }
    /// RVA of the nth section.
    pub fn rva(index: usize) -> u32 {
        0x1000 * (index as u32 + 1)
    }
    pub fn section(mut self, name: &'static str, chars: u32, data: Vec<u8>) -> Self {
        self.sections.push((name, chars, data));
        self
    }
    pub fn dir(mut self, index: usize, rva: u32, size: u32) -> Self {
        self.dirs.push((index, rva, size));
        self
    }

    pub fn build(&self) -> Vec<u8> {
        let opt_size = if self.pe32plus { 240 } else { 224 };
        let mut out = vec![0u8; 0x400];
        out[..2].copy_from_slice(b"MZ");
        put32(&mut out, 0x3C, 0x40);
        out[0x40..0x44].copy_from_slice(b"PE\0\0");
        let fh = 0x44;
        put16(&mut out, fh, self.machine);
        put16(&mut out, fh + 2, self.sections.len() as u16);
        put16(&mut out, fh + 16, opt_size);
        let mut chars = 0x0002 | if self.pe32plus { 0x0020 } else { 0x0100 };
        if self.dll {
            chars |= 0x2000;
        }
        put16(&mut out, fh + 18, chars);
        let oh = fh + 20;
        put16(&mut out, oh, if self.pe32plus { 0x20B } else { 0x10B });
        if !self.sections.is_empty() {
            put32(&mut out, oh + 16, Self::rva(0)); // entry point
        }
        if self.pe32plus {
            put64(&mut out, oh + 24, 0x1_4000_0000);
        } else {
            put32(&mut out, oh + 28, 0x40_0000);
        }
        put32(&mut out, oh + 32, 0x1000); // section alignment
        put32(&mut out, oh + 36, 0x200); // file alignment
        put32(&mut out, oh + 56, Self::rva(self.sections.len())); // size of image
        put32(&mut out, oh + 60, 0x400); // size of headers
        put16(&mut out, oh + 68, self.subsystem);
        put16(&mut out, oh + 70, 0x0140); // DYNAMIC_BASE | NX_COMPAT
        let (num_dirs, dirs) = if self.pe32plus {
            (oh + 108, oh + 112)
        } else {
            (oh + 92, oh + 96)
        };
        put32(&mut out, num_dirs, self.num_dirs);
        for &(i, rva, size) in &self.dirs {
            put32(&mut out, dirs + i * 8, rva);
            put32(&mut out, dirs + i * 8 + 4, size);
        }
        let mut sh = oh + opt_size as usize;
        for (i, (name, chars, data)) in self.sections.iter().enumerate() {
            let raw_ptr = out.len() as u32;
            out[sh..sh + name.len()].copy_from_slice(name.as_bytes());
            put32(&mut out, sh + 8, data.len() as u32); // virtual size
            put32(&mut out, sh + 12, Self::rva(i));
            put32(&mut out, sh + 16, data.len().div_ceil(0x200) as u32 * 0x200);
            put32(&mut out, sh + 20, raw_ptr);
            put32(&mut out, sh + 36, *chars);
            sh += 40;
            out.extend_from_slice(data);
            out.resize(out.len().next_multiple_of(0x200), 0);
        }
        out.extend_from_slice(&self.overlay);
        out
    }
}

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

/// Little-endian byte assembler for hand-laid table data.
#[derive(Default)]
pub struct Bytes(pub Vec<u8>);
impl Bytes {
    pub fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u16(mut self, v: u16) -> Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn cstr(mut self, s: &str) -> Self {
        self.0.extend_from_slice(s.as_bytes());
        self.0.push(0);
        self
    }
    /// Zero-pad up to absolute offset `at` within the section.
    pub fn pad_to(mut self, at: usize) -> Self {
        assert!(self.0.len() <= at, "layout overlap at {at}");
        self.0.resize(at, 0);
        self
    }
}

pub fn analyze(b: &Builder) -> pe::PeInfo {
    pe::analyze(&b.build()).expect("analyze")
}

#[rustfmt::skip]
pub fn imports_data(base: u32) -> Vec<u8> {
    Bytes::default()
        .u32(base + 68).u32(0).u32(0).u32(base + 48).u32(base + 68) // descriptor: OFT, ts, fwd, name, FT
        .pad_to(20 + 20) // null terminator descriptor
        .pad_to(48)
        .cstr("kernel32.dll")
        .pad_to(68) // 68 % 8 == 4: deliberately misaligned
        .u64(u64::from(base + 96)) // by name
        .u64(0x8000_0000_0000_0005) // by ordinal 5
        .u64(0)
        .pad_to(96)
        .u16(0)
        .cstr("ExitProcess")
        .0
}

/// PE32 (u32 thunk) twin of `imports_data`: kernel32.dll importing ExitProcess by name, then ordinal 5.
#[rustfmt::skip]
pub fn imports_data32(base: u32) -> Vec<u8> {
    Bytes::default()
        .u32(base + 68).u32(0).u32(0).u32(base + 48).u32(base + 68) // descriptor: OFT, ts, fwd, name, FT
        .pad_to(48)
        .cstr("kernel32.dll")
        .pad_to(68)
        .u32(base + 96) // by name
        .u32(0x8000_0005) // by ordinal 5
        .u32(0)
        .pad_to(96)
        .u16(0)
        .cstr("ExitProcess")
        .0
}

/// Import directory at offset 0 built from raw descriptors `(OriginalFirstThunk, Name, FirstThunk)`,
/// followed by a null descriptor, then `tail` at `imports_tail_off`. Descriptor `i` sits at RVA
/// `base + 20 * i`. Nothing is validated.
pub fn imports_raw(descs: &[(u32, u32, u32)], tail: &[u8]) -> Vec<u8> {
    let mut b = Bytes::default();
    for &(oft, name, ft) in descs {
        b = b.u32(oft).u32(0).u32(0).u32(name).u32(ft);
    }
    let mut out = b.pad_to(20 * (descs.len() + 1)).pad_to(imports_tail_off(descs.len())).0;
    out.extend_from_slice(tail);
    out
}

pub fn imports_tail_off(n_descs: usize) -> usize {
    (20 * (n_descs + 1)).next_multiple_of(8)
}

/// Delay-import directory at offset 0 from raw 8-word descriptors, followed by a null descriptor,
/// then `tail` at `delay_tail_off`. Descriptor `i` sits at RVA `base + 32 * i`. Word order:
/// attributes, DllNameRVA, module handle, IAT, INT, ...
pub fn delay_raw(descs: &[[u32; 8]], tail: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for d in descs {
        out.extend(d.iter().flat_map(|w| w.to_le_bytes()));
    }
    out.resize(delay_tail_off(descs.len()), 0); // zero padding includes the null descriptor
    out.extend_from_slice(tail);
    out
}

pub fn delay_tail_off(n_descs: usize) -> usize {
    (32 * (n_descs + 1)).next_multiple_of(8)
}

#[rustfmt::skip]
pub fn delay_data(base: u32) -> Vec<u8> {
    Bytes::default()
        .u32(1).u32(base + 64).u32(0).u32(base + 112).u32(base + 80).u32(0).u32(0).u32(0) // descriptor
        .pad_to(64) // (terminator descriptor is the zeroed 32..64)
        .cstr("dxgi.dll")
        .pad_to(80)
        .u64(u64::from(base + 128))
        .u64(0x8000_0000_0000_0007)
        .u64(0)
        .pad_to(128)
        .u16(0)
        .cstr("CreateDXGIFactory")
        .0
}

/// Ordinal base 10; slot 0 named "Alpha", slot 1 named "Fwd" forwarding to ntdll, slot 2 unused.
#[rustfmt::skip]
pub fn exports_data(base: u32) -> Vec<u8> {
    Bytes::default()
        .u32(0).u32(0).u16(0).u16(0).u32(base + 40).u32(10).u32(3).u32(2).u32(base + 64).u32(base + 80).u32(base + 96)
        .pad_to(40)
        .cstr("mylib.dll")
        .pad_to(64)
        .u32(0x2000).u32(base + 112).u32(0)
        .pad_to(80)
        .u32(base + 144).u32(base + 152)
        .pad_to(96)
        .u16(0).u16(1)
        .pad_to(112)
        .cstr("NTDLL.RtlAllocateHeap")
        .pad_to(144)
        .cstr("Alpha")
        .pad_to(152)
        .cstr("Fwd")
        .0
}

/// Ordinal-only export: slot 0 unnamed with symbol RVA 0x2000 outside export dir, ordinal base 5.
#[rustfmt::skip]
pub fn exports_ordinal_only_data(base: u32) -> Vec<u8> {
    Bytes::default()
        .u32(0).u32(0).u16(0).u16(0).u32(base + 40).u32(5).u32(1).u32(0).u32(base + 64).u32(0).u32(base + 80)
        .pad_to(40)
        .cstr("mylib.dll")
        .pad_to(64)
        .u32(0x2000)  // symbol RVA outside export dir
        .pad_to(80)
        .u16(0)
        .pad_to(96)
        .0
}

/// Offset (within the section) of the free-form `tail` passed to `exports_raw`.
pub fn exports_tail_off(nf: usize, nn: usize) -> usize {
    (64 + 4 * nf + 4 * nn + 2 * nn).next_multiple_of(8)
}

/// Export section from raw parts. Header at 0, DLL name at 40, function table at 64, then the
/// name RVA table, the name-index (u16) table and finally `tail` (strings) at `exports_tail_off`.
/// `names` is (name RVA, function index) per name-table entry. Nothing is validated, so tests
/// can point RVAs anywhere.
#[rustfmt::skip]
pub fn exports_raw(base: u32, ordinal_base: u32, funcs: &[u32], names: &[(u32, u16)], tail: &[u8]) -> Vec<u8> {
    let (nf, nn) = (funcs.len(), names.len());
    let f_off = 64u32;
    let n_off = f_off + 4 * nf as u32;
    let i_off = n_off + 4 * nn as u32;
    let mut b = Bytes::default()
        .u32(0).u32(0).u16(0).u16(0).u32(base + 40).u32(ordinal_base).u32(nf as u32).u32(nn as u32)
        .u32(base + f_off).u32(base + n_off).u32(base + i_off)
        .pad_to(40)
        .cstr("mylib.dll")
        .pad_to(64);
    for &f in funcs {
        b = b.u32(f);
    }
    for &(rva, _) in names {
        b = b.u32(rva);
    }
    for &(_, idx) in names {
        b = b.u16(idx);
    }
    let mut out = b.pad_to(exports_tail_off(nf, nn)).0;
    out.extend_from_slice(tail);
    out
}

/// One block covering page 0x1000: two DIR64 fixups plus one ABSOLUTE padding entry.
#[rustfmt::skip]
pub fn reloc_data() -> Vec<u8> {
    Bytes::default().u32(0x1000).u32(16).u16(0xA010).u16(0xA018).u16(0x0000).u16(0x0000).0
}

/// PE32 relocation block: `page`, SizeOfBlock as given (not derived), then the type/offset words.
pub fn reloc_block(page: u32, size_of_block: u32, words: &[u16]) -> Vec<u8> {
    let mut b = Bytes::default().u32(page).u32(size_of_block);
    for &w in words {
        b = b.u16(w);
    }
    b.0
}

/// PE32 (x86) TLS directory, image base 0x40_0000, with two callbacks (VAs 0x40_1000 and 0x40_1010)
/// and a zero terminator.
#[rustfmt::skip]
pub fn tls_data32(base: u32) -> Vec<u8> {
    let image_base = 0x40_0000u32;
    let va = |off: u32| image_base + base + off;
    Bytes::default()
        .u32(va(32)).u32(va(40)).u32(va(40)).u32(va(48)).u32(0).u32(0)
        .pad_to(48)
        .u32(image_base + 0x1000).u32(image_base + 0x1010).u32(0)
        .0
}

#[rustfmt::skip]
pub fn tls_data(base: u32) -> Vec<u8> {
    let image_base = 0x1_4000_0000u64;
    let va = |off: u32| image_base + u64::from(base + off);
    Bytes::default()
        .u64(va(48)).u64(va(56)).u64(va(56)).u64(va(64)).u32(0).u32(0)
        .pad_to(64)
        .u64(image_base + 0x1000).u64(image_base + 0x1010).u64(0)
        .0
}

/// TLS with AddressOfCallBacks pointing outside the image (image_base + 0x00FF_0000).
#[rustfmt::skip]
pub fn tls_data_oob_callbacks(base: u32) -> Vec<u8> {
    let image_base = 0x1_4000_0000u64;
    let va = |off: u32| image_base + u64::from(base + off);
    Bytes::default()
        .u64(va(48)).u64(va(56)).u64(va(56)).u64(image_base + 0x00FF_0000).u32(0).u32(0)
        .pad_to(64)
        .u64(image_base + 0x1000).u64(image_base + 0x1010).u64(0)
        .0
}

/// TLS with AddressOfCallBacks == 0 (no callbacks, should be silent Null).
#[rustfmt::skip]
pub fn tls_data_no_callbacks(base: u32) -> Vec<u8> {
    let image_base = 0x1_4000_0000u64;
    let va = |off: u32| image_base + u64::from(base + off);
    Bytes::default()
        .u64(va(48)).u64(va(56)).u64(va(56)).u64(0).u32(0).u32(0)
        .pad_to(64)
        .u64(image_base + 0x1000).u64(image_base + 0x1010).u64(0)
        .0
}

/// `.rsrc` section content: a three-level resource directory (type 16 = RT_VERSION, id 1, language
/// 0x409) whose single data entry holds `data` verbatim. `base` is the section's RVA. Wire it with
/// `.dir(2, base, len)`, where `len` is the returned length.
pub fn rsrc_version_section(base: u32, data: &[u8]) -> Vec<u8> {
    rsrc_version_langs(base, &[(0x409, data)])
}

/// Like `rsrc_version_section`, with one language entry per `(language id, data)`, in the order
/// given (real linkers sort ascending; tests may not).
pub fn rsrc_version_langs(base: u32, langs: &[(u32, &[u8])]) -> Vec<u8> {
    let n = langs.len() as u32;
    // IMAGE_RESOURCE_DIRECTORY: characteristics, timestamp, major, minor, named entries, id entries.
    let dir = |count: u16| Bytes::default().u32(0).u32(0).u16(0).u16(0).u16(0).u16(count);
    let mut out = dir(1).u32(16).u32(0x8000_0000 | 24).0; // root: type 16 -> directory at 24
    out.extend(dir(1).u32(1).u32(0x8000_0000 | 48).0); // id 1 -> directory at 48
    let mut lang_dir = dir(langs.len() as u16);
    let entries_at = 48 + 16 + 8 * n;
    for (i, &(lang, _)) in langs.iter().enumerate() {
        lang_dir = lang_dir.u32(lang).u32(entries_at + 16 * i as u32); // language -> data entry
    }
    out.extend(lang_dir.0);
    // IMAGE_RESOURCE_DATA_ENTRY: OffsetToData (an RVA), Size, CodePage, Reserved.
    let mut data_at = entries_at + 16 * n;
    for &(_, data) in langs {
        out.extend(
            Bytes::default()
                .u32(base + data_at)
                .u32(data.len() as u32)
                .u32(0)
                .u32(0)
                .0,
        );
        data_at += data.len() as u32;
    }
    assert_eq!(out.len() as u32, entries_at + 16 * n);
    for &(_, data) in langs {
        out.extend_from_slice(data);
    }
    out
}

/// A general three-level PE resource section (Type -> ID -> Language), built from raw `(type_id,
/// id, lang_id, data)` tuples grouped automatically by type then by id. `rsrc_version_langs`
/// above only ever builds one type (RT_VERSION); this is the same shape generalised to several
/// types/ids at once, which Task 3's RT_GROUP_ICON + RT_ICON tests need together in one section.
/// `base` is the section's RVA (wire with `.dir(2, base, len)`).
pub fn rsrc_multi(base: u32, entries: &[(u16, u16, u16, &[u8])]) -> Vec<u8> {
    let mut types: Vec<u16> = Vec::new();
    for &(t, _, _, _) in entries {
        if !types.contains(&t) {
            types.push(t);
        }
    }
    let ids_of = |t: u16| -> Vec<u16> {
        let mut v = Vec::new();
        for &(et, id, _, _) in entries {
            if et == t && !v.contains(&id) {
                v.push(id);
            }
        }
        v
    };
    let langs_of = |t: u16, id: u16| -> Vec<(u16, &[u8])> {
        entries
            .iter()
            .filter(|&&(et, eid, _, _)| et == t && eid == id)
            .map(|&(_, _, l, d)| (l, d))
            .collect()
    };
    let dir_hdr = |count: u16| Bytes::default().u32(0).u32(0).u16(0).u16(0).u16(0).u16(count);

    let root_size = 16 + 8 * types.len();
    let mut off = root_size;
    let mut type_dir_off = Vec::new();
    for &t in &types {
        type_dir_off.push(off);
        off += 16 + 8 * ids_of(t).len();
    }
    let mut id_dir_off: Vec<Vec<usize>> = Vec::new();
    for &t in &types {
        let mut per_id = Vec::new();
        for &id in &ids_of(t) {
            per_id.push(off);
            off += 16 + 8 * langs_of(t, id).len();
        }
        id_dir_off.push(per_id);
    }
    // `off` here (before the data-entry array itself is laid out) is where the last directory
    // level ends: the checkpoint the emission loops below are asserted against.
    let dirs_end = off;
    let mut data_entry_off: Vec<Vec<Vec<usize>>> = Vec::new();
    for &t in &types {
        let mut per_id = Vec::new();
        for &id in &ids_of(t) {
            let mut per_lang = Vec::new();
            for _ in &langs_of(t, id) {
                per_lang.push(off);
                off += 16;
            }
            per_id.push(per_lang);
        }
        data_entry_off.push(per_id);
    }
    let data_start = off; // where the raw resource bytes begin, after every IMAGE_RESOURCE_DATA_ENTRY

    let mut out = dir_hdr(types.len() as u16).0;
    for (ti, &t) in types.iter().enumerate() {
        out.extend(
            Bytes::default()
                .u32(u32::from(t))
                .u32(0x8000_0000 | type_dir_off[ti] as u32)
                .0,
        );
    }
    for (ti, &t) in types.iter().enumerate() {
        let ids = ids_of(t);
        out.extend(dir_hdr(ids.len() as u16).0);
        for (ii, &id) in ids.iter().enumerate() {
            out.extend(
                Bytes::default()
                    .u32(u32::from(id))
                    .u32(0x8000_0000 | id_dir_off[ti][ii] as u32)
                    .0,
            );
        }
    }
    for (ti, &t) in types.iter().enumerate() {
        for (ii, &id) in ids_of(t).iter().enumerate() {
            let langs = langs_of(t, id);
            out.extend(dir_hdr(langs.len() as u16).0);
            for (li, &(lang, _)) in langs.iter().enumerate() {
                out.extend(
                    Bytes::default()
                        .u32(u32::from(lang))
                        .u32(data_entry_off[ti][ii][li] as u32)
                        .0,
                );
            }
        }
    }
    assert_eq!(out.len(), dirs_end, "directory layout arithmetic is self-consistent");
    let mut running = data_start as u32;
    let mut all_data = Vec::new();
    for &t in &types {
        for &id in &ids_of(t) {
            for &(_, data) in &langs_of(t, id) {
                out.extend(
                    Bytes::default()
                        .u32(base + running)
                        .u32(data.len() as u32)
                        .u32(0)
                        .u32(0)
                        .0,
                );
                all_data.extend_from_slice(data);
                running += data.len() as u32;
            }
        }
    }
    out.extend(all_data);
    out
}

pub fn words(w: &[u16]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

pub fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

/// One VS_VERSIONINFO-style block; wLength is filled in.
pub fn block(key: &str, w_type: u16, value_len: u16, value: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
    let pad4 = |b: &mut Vec<u8>| b.resize(b.len().next_multiple_of(4), 0);
    let mut b = vec![0, 0];
    b.extend(value_len.to_le_bytes());
    b.extend(w_type.to_le_bytes());
    b.extend(utf16z(key));
    pad4(&mut b);
    b.extend(value);
    for c in children {
        pad4(&mut b);
        b.extend(c);
    }
    let len = b.len() as u16;
    b[..2].copy_from_slice(&len.to_le_bytes());
    b
}

pub fn string(k: &str, v: &str) -> Vec<u8> {
    let val = utf16z(v);
    block(k, 1, (val.len() / 2) as u16, &val, &[])
}

/// A well-formed VS_VERSIONINFO: fixed file info plus StringFileInfo/040904B0 holding
/// FileVersion and ProductName.
pub fn version_info_block(file_version: &str, product: &str) -> Vec<u8> {
    let mut fixed = vec![0u8; 52];
    fixed[..4].copy_from_slice(&0xFEEF_04BDu32.to_le_bytes());
    let table = block(
        "040904B0",
        1,
        0,
        &[],
        &[string("FileVersion", file_version), string("ProductName", product)],
    );
    let sfi = block("StringFileInfo", 1, 0, &[], &[table]);
    block("VS_VERSION_INFO", 0, 52, &fixed, &[sfi])
}
