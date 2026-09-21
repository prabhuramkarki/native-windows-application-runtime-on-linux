use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Pe,
    /// OLE2 compound file: MSI packages (and legacy Office files; refine when needed).
    Msi,
    Zip,
    Unknown,
}

const OLE_MAGIC: &[u8] = &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

pub fn detect(bytes: &[u8]) -> FileKind {
    if is_pe(bytes) {
        FileKind::Pe
    } else if bytes.starts_with(OLE_MAGIC) {
        FileKind::Msi
    } else if bytes.starts_with(b"PK\x03\x04") {
        FileKind::Zip
    } else {
        FileKind::Unknown
    }
}

fn is_pe(b: &[u8]) -> bool {
    if !b.starts_with(b"MZ") {
        return false;
    }
    let Some(off) = b.get(0x3C..0x40).map(|s| u32::from_le_bytes(s.try_into().unwrap())) else {
        return false;
    };
    b.get(off as usize..).is_some_and(|rest| rest.starts_with(b"PE\0\0"))
}
