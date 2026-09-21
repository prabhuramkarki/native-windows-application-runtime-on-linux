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
        put32(&mut out, num_dirs, 16);
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
