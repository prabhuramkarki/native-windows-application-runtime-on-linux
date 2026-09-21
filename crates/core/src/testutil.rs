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

/// Rewrites the end of a [`raw_zip`] archive into the zip64 form: a zip64 end record and locator in front of the
/// classic end record, whose counts become the `0xFFFF` sentinel. `entries` is what the zip64 record states.
pub fn to_zip64(mut zip: Vec<u8>, entries: u64) -> Vec<u8> {
    let end = zip.windows(4).rposition(|w| w == b"PK\x05\x06").unwrap();
    let cd_size = u32::from_le_bytes(zip[end + 12..end + 16].try_into().unwrap());
    let cd_offset = u32::from_le_bytes(zip[end + 16..end + 20].try_into().unwrap());
    for at in [end + 8, end + 10] {
        zip[at..at + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
    }
    let mut z64 = Vec::new();
    z64.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
    z64.extend_from_slice(&44u64.to_le_bytes());
    z64.extend_from_slice(&45u16.to_le_bytes());
    z64.extend_from_slice(&45u16.to_le_bytes());
    z64.extend_from_slice(&0u32.to_le_bytes());
    z64.extend_from_slice(&0u32.to_le_bytes());
    z64.extend_from_slice(&entries.to_le_bytes()); // on this disk
    z64.extend_from_slice(&entries.to_le_bytes()); // total
    z64.extend_from_slice(&u64::from(cd_size).to_le_bytes());
    z64.extend_from_slice(&u64::from(cd_offset).to_le_bytes());
    let mut locator = Vec::new();
    locator.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
    locator.extend_from_slice(&0u32.to_le_bytes());
    locator.extend_from_slice(&(end as u64).to_le_bytes());
    locator.extend_from_slice(&1u32.to_le_bytes());
    zip.splice(end..end, z64.into_iter().chain(locator));
    zip
}
