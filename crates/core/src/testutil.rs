//! Test helpers shared by the install and unzip tests: fixtures, PE patching, a raw zip writer that can produce
//! archives the `zip` crate refuses to write (hostile names, lying sizes, encryption flags), FIFOs, tree listings.
use std::io::Write;
use std::path::{Path, PathBuf};

/// A binary built by `tools/build-fixtures.sh` (needs mingw-w64; the files are not committed).
pub fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {name}: run tools/build-fixtures.sh"))
}

fn u32_at(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize
}

/// Offset of the COFF header (right after `PE\0\0`).
fn coff(pe: &[u8]) -> usize {
    u32_at(pe, 0x3C) + 4
}

pub fn set_machine(mut pe: Vec<u8>, machine: u16) -> Vec<u8> {
    let at = coff(&pe);
    pe[at..at + 2].copy_from_slice(&machine.to_le_bytes());
    pe
}

/// The optional header's `Subsystem` field (offset 68 in both PE32 and PE32+).
pub fn set_subsystem(mut pe: Vec<u8>, subsystem: u16) -> Vec<u8> {
    let at = coff(&pe) + 20 + 68;
    pe[at..at + 2].copy_from_slice(&subsystem.to_le_bytes());
    pe
}

/// Bytes appended after the image (an overlay): changes the size and, for markers, the installer heuristic.
pub fn with_overlay(mut pe: Vec<u8>, extra: &[u8]) -> Vec<u8> {
    pe.extend_from_slice(extra);
    pe
}

/// Every path under `dir` (relative, `/` separated, directories with a trailing `/`), sorted. Symlinks are listed
/// as `name -> target` and never followed.
pub fn tree(dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        let mut names: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
        names.sort_by_key(|e| e.file_name());
        for e in names {
            let name = format!("{prefix}{}", e.file_name().to_string_lossy());
            let ft = e.file_type().unwrap();
            if ft.is_symlink() {
                out.push(format!("{name} -> {}", std::fs::read_link(e.path()).unwrap().display()));
            } else if ft.is_dir() {
                out.push(format!("{name}/"));
                walk(&e.path(), &format!("{name}/"), out);
            } else {
                out.push(name);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, "", &mut out);
    out
}

pub fn mkfifo(path: &Path) {
    let c = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str())).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo failed");
}

/// Runs `f` on a thread and fails (rather than hanging the test run) when it does not finish in 10 s.
pub fn within_10s<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(std::time::Duration::from_secs(10))
        .expect("blocked: the call did not return")
}

pub fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

/// Deflate-compresses `data` (raw deflate, as zip method 8 stores it).
pub fn deflate(data: &[u8], level: flate2::Compression) -> Vec<u8> {
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), level);
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// `n` zero bytes, deflated at the best level (about 1000:1).
pub fn deflated_zeros(n: usize) -> Vec<u8> {
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    let block = vec![0u8; 1 << 20];
    let mut left = n;
    while left > 0 {
        let k = left.min(block.len());
        enc.write_all(&block[..k]).unwrap();
        left -= k;
    }
    enc.finish().unwrap()
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

pub const S_IFREG: u32 = 0o100_000;
pub const S_IFDIR: u32 = 0o040_000;
pub const S_IFLNK: u32 = 0o120_000;
pub const S_IFIFO: u32 = 0o010_000;
pub const S_IFCHR: u32 = 0o020_000;

/// One entry of a raw zip. `data` is what is stored (already compressed for method 8); the declared sizes and
/// the CRC default to the honest values for a stored entry and can be overridden to lie.
#[derive(Clone)]
pub struct Raw {
    pub name: Vec<u8>,
    pub method: u16,
    pub flags: u16,
    pub data: Vec<u8>,
    pub declared_size: u64,
    pub crc: u32,
    pub mode: u32,
}

impl Raw {
    pub fn file(name: &str, data: &[u8]) -> Raw {
        Raw {
            name: name.as_bytes().to_vec(),
            method: 0,
            flags: 0,
            data: data.to_vec(),
            declared_size: data.len() as u64,
            crc: crc32(data),
            mode: S_IFREG | 0o644,
        }
    }

    pub fn dir(name: &str) -> Raw {
        let mut r = Raw::file(name, b"");
        r.mode = S_IFDIR | 0o755;
        r
    }

    /// A symlink-like entry: the mode says so, the content is the target.
    pub fn special(name: &str, mode: u32, content: &[u8]) -> Raw {
        let mut r = Raw::file(name, content);
        r.mode = mode;
        r
    }

    /// Stores `plain` deflated (method 8) with honest sizes.
    pub fn deflated(name: &str, plain: &[u8]) -> Raw {
        let mut r = Raw::file(name, plain);
        r.method = 8;
        r.data = deflate(plain, flate2::Compression::default());
        r
    }

    pub fn declared(mut self, size: u64) -> Raw {
        self.declared_size = size;
        self
    }

    pub fn mode(mut self, mode: u32) -> Raw {
        self.mode = mode;
        self
    }

    pub fn flags(mut self, flags: u16) -> Raw {
        self.flags = flags;
        self
    }

    pub fn method(mut self, method: u16) -> Raw {
        self.method = method;
        self
    }
}

/// Builds a zip (no zip64, no extra fields, no comment) exactly as described: the sizes in BOTH headers are the
/// declared ones.
pub fn raw_zip(entries: &[Raw]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for e in entries {
        let offset = out.len() as u32;
        let csize = e.data.len() as u32;
        let usize_ = e.declared_size as u32;
        // Names that are not ASCII are UTF-8 (general purpose flag bit 11), as every modern archiver writes them;
        // without the flag the crate would decode them as CP437.
        let flags = e.flags | if e.name.is_ascii() { 0 } else { 0x800 };
        let mut common = Vec::new();
        common.extend_from_slice(&flags.to_le_bytes());
        common.extend_from_slice(&e.method.to_le_bytes());
        common.extend_from_slice(&0u16.to_le_bytes()); // time
        common.extend_from_slice(&33u16.to_le_bytes()); // date 1980-01-01
        common.extend_from_slice(&e.crc.to_le_bytes());
        common.extend_from_slice(&csize.to_le_bytes());
        common.extend_from_slice(&usize_.to_le_bytes());
        common.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        common.extend_from_slice(&0u16.to_le_bytes()); // extra len

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&common);
        out.extend_from_slice(&e.name);
        out.extend_from_slice(&e.data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&((3u16 << 8) | 20).to_le_bytes()); // made by: Unix
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&common);
        central.extend_from_slice(&0u16.to_le_bytes()); // comment len
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        central.extend_from_slice(&(e.mode << 16).to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(&e.name);
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Offset of the (last) end-of-central-directory record.
pub fn eocd_at(zip: &[u8]) -> usize {
    zip.windows(4).rposition(|w| w == b"PK\x05\x06").unwrap()
}

pub fn put16(zip: &mut [u8], at: usize, v: u16) {
    zip[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

pub fn put32(zip: &mut [u8], at: usize, v: u32) {
    zip[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// Gives the end record a comment (of `comment.len()` bytes, appended after it).
pub fn with_comment(mut zip: Vec<u8>, comment: &[u8]) -> Vec<u8> {
    let end = eocd_at(&zip);
    put16(&mut zip, end + 20, comment.len() as u16);
    zip.extend_from_slice(comment);
    zip
}

/// The fields of a zip64 end record and which classic end-record fields become `0xFFFF`/`0xFFFFFFFF` sentinels.
#[derive(Clone)]
pub struct Z64 {
    pub disk: u32,
    pub disk_cd: u32,
    pub entries_disk: u64,
    pub total: u64,
    pub cd_size: u64,
    pub cd_offset: u64,
    /// The record's own "size of the remaining record" field (44 when honest).
    pub size_field: u64,
    /// Where the locator says the zip64 record is (`None` = honestly, right before the locator).
    pub locator_target: Option<u64>,
    /// The locator's "disk with the zip64 record" and "total number of disks" fields (0 and 1 when honest).
    pub locator_disk: u32,
    pub locator_disks: u32,
    /// Bytes of "extensible data" after the 56-byte record (`size_field` must account for them).
    pub extensible: Vec<u8>,
    pub sentinel_count: bool,
    pub sentinel_size: bool,
    pub sentinel_offset: bool,
}

impl Z64 {
    /// Honest values for `zip` (a [`raw_zip`] archive), with the entry count as the only sentinel.
    pub fn honest(zip: &[u8]) -> Z64 {
        let end = eocd_at(zip);
        let n = u64::from(u16::from_le_bytes([zip[end + 10], zip[end + 11]]));
        let word = |at: usize| u64::from(u32::from_le_bytes(zip[at..at + 4].try_into().unwrap()));
        Z64 {
            disk: 0,
            disk_cd: 0,
            entries_disk: n,
            total: n,
            cd_size: word(end + 12),
            cd_offset: word(end + 16),
            size_field: 44,
            locator_target: None,
            locator_disk: 0,
            locator_disks: 1,
            extensible: Vec::new(),
            sentinel_count: true,
            sentinel_size: false,
            sentinel_offset: false,
        }
    }
}

/// Rewrites the end of a [`raw_zip`] archive into the zip64 form (a zip64 end record and its locator in front of
/// the classic end record) with exactly the fields `z` says, honest or not.
pub fn to_zip64_with(mut zip: Vec<u8>, z: &Z64) -> Vec<u8> {
    let end = eocd_at(&zip);
    if z.sentinel_count {
        put16(&mut zip, end + 8, 0xFFFF);
        put16(&mut zip, end + 10, 0xFFFF);
    }
    if z.sentinel_size {
        put32(&mut zip, end + 12, 0xFFFF_FFFF);
    }
    if z.sentinel_offset {
        put32(&mut zip, end + 16, 0xFFFF_FFFF);
    }
    let mut rec = Vec::new();
    rec.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
    rec.extend_from_slice(&z.size_field.to_le_bytes());
    rec.extend_from_slice(&45u16.to_le_bytes());
    rec.extend_from_slice(&45u16.to_le_bytes());
    rec.extend_from_slice(&z.disk.to_le_bytes());
    rec.extend_from_slice(&z.disk_cd.to_le_bytes());
    rec.extend_from_slice(&z.entries_disk.to_le_bytes());
    rec.extend_from_slice(&z.total.to_le_bytes());
    rec.extend_from_slice(&z.cd_size.to_le_bytes());
    rec.extend_from_slice(&z.cd_offset.to_le_bytes());
    rec.extend_from_slice(&z.extensible);
    let mut locator = Vec::new();
    locator.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
    locator.extend_from_slice(&z.locator_disk.to_le_bytes());
    locator.extend_from_slice(&z.locator_target.unwrap_or(end as u64).to_le_bytes());
    locator.extend_from_slice(&z.locator_disks.to_le_bytes());
    zip.splice(end..end, rec.into_iter().chain(locator));
    zip
}

/// A zip64 archive whose record states `entries` and is otherwise honest.
pub fn to_zip64(zip: Vec<u8>, entries: u64) -> Vec<u8> {
    let z = Z64 {
        entries_disk: entries,
        total: entries,
        ..Z64::honest(&zip)
    };
    to_zip64_with(zip, &z)
}
