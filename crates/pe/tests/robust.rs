mod common;
use common::*;

/// File offset of data directory 0 in an x64 image built by `Builder` (PE header at 0x40, file
/// header 20 bytes, optional header fields up to the directories 112 bytes).
const X64_DIRS: usize = 0x44 + 20 + 112;

/// Every table at once, so mutations hit real structures rather than empty space.
fn rich_sample() -> Vec<u8> {
    let r = Builder::rva;
    let version = version_info_block("2.5.0.1", "Rich");
    let rsrc = rsrc_version_section(r(5), &version);
    let rsrc_len = rsrc.len() as u32;
    Builder::x64()
        .section(".idata", DATA_RW, imports_data(r(0)))
        .section(".didat", DATA_RW, delay_data(r(1)))
        .section(".edata", DATA_R, exports_data(r(2)))
        .section(".reloc", DATA_R, reloc_data())
        .section(".tls", DATA_RW, tls_data(r(4)))
        .section(".rsrc", DATA_R, rsrc)
        .dir(1, r(0), 40)
        .dir(13, r(1), 64)
        .dir(0, r(2), 160)
        .dir(5, r(3), 16)
        .dir(9, r(4), 40)
        .dir(2, r(5), rsrc_len)
        .build()
}

#[test]
fn rich_sample_parses_cleanly() {
    let i = pe::analyze(&rich_sample()).unwrap();
    assert!(i.warnings.is_empty(), "{:?}", i.warnings);
    assert_eq!((i.imports.len(), i.exports.len(), i.relocation_count), (2, 2, 2));
    let v = i.version.expect("version info");
    assert_eq!(v.file_version.as_deref(), Some("2.5.0.1"));
    assert_eq!(v.strings.get("ProductName").map(String::as_str), Some("Rich"));
}

/// The structure-targeted mutator below writes at `X64_DIRS`; make sure that is where the
/// builder puts the directories.
#[test]
fn directory_offset_matches_the_builder_layout() {
    let img = rich_sample();
    let field = |i: usize, half: usize| {
        let at = X64_DIRS + i * 8 + half * 4;
        u32::from_le_bytes(img[at..at + 4].try_into().unwrap())
    };
    assert_eq!((field(1, 0), field(1, 1)), (Builder::rva(0), 40));
    assert_eq!(field(2, 0), Builder::rva(5));
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Env override parsed as decimal or `0x` hex.
fn env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(s) => {
            let s = s.trim();
            match s.strip_prefix("0x") {
                Some(h) => u64::from_str_radix(h, 16),
                None => s.parse(),
            }
            .unwrap_or_else(|e| panic!("{name}={s:?}: {e}"))
        }
        Err(_) => default,
    }
}

/// Structure-targeted damage: overwrite the RVA or size of 1-3 of the 16 data directories with a
/// boundary-biased value. Random byte flips almost never produce a coherent bad directory pointer;
/// this finds pointer bugs (e.g. a misaligned resource directory) directly.
fn corrupt_directories(m: &mut [u8], rng: &mut Rng, image_size: u32) {
    for _ in 0..=rng.next() % 3 {
        let at = X64_DIRS + (rng.next() as usize % 16) * 8 + (rng.next() as usize % 2) * 4;
        let cur = u32::from_le_bytes(m[at..at + 4].try_into().unwrap());
        let v = match rng.next() % 9 {
            0 => 0,
            1 => 1,
            2 => u32::MAX,
            3 => image_size,
            4 => image_size + 1,
            5 => image_size - 1,
            6 => cur.wrapping_add(1 + rng.next() as u32 % 7), // near-miss, e.g. misaligned
            7 => cur ^ (1 << (rng.next() % 32)),
            _ => rng.next() as u32,
        };
        m[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// The parser is a security boundary (it is fed untrusted installers): corrupt or truncate a
/// valid image thousands of ways and require that it never panics. Debug builds also trap
/// integer overflow. (cargo-fuzz needs nightly; add a fuzz target once CI has one.)
///
/// Two mutators run each iteration: the byte-flip/truncate one, and a second that damages the
/// data-directory entries (optionally followed by a byte flip). A hard abort (not a panic) kills
/// the whole test binary, so `RUNTIME_FUZZ_SEED` / `RUNTIME_FUZZ_ITERS` make runs reproducible
/// and let a long run be requested.
#[test]
fn corrupted_input_never_panics() {
    let original = rich_sample();
    let seed = env_u64("RUNTIME_FUZZ_SEED", 0x9E37_79B9_7F4A_7C15);
    let iters = env_u64("RUNTIME_FUZZ_ITERS", 30_000);
    assert_ne!(seed, 0, "xorshift needs a non-zero seed");
    let image_size = Builder::rva(6);
    let mut rng = Rng(seed);
    for n in 0..iters {
        let mut m = original.clone();
        if rng.next().is_multiple_of(5) {
            m.truncate(rng.next() as usize % m.len());
        } else {
            for _ in 0..=rng.next() % 6 {
                // Bias towards the headers and table area, where structure lives.
                let span = if rng.next().is_multiple_of(2) { 0x200 } else { m.len() };
                let at = rng.next() as usize % span.min(m.len());
                m[at] = rng.next() as u8;
            }
        }
        let mut s = original.clone();
        corrupt_directories(&mut s, &mut rng, image_size);
        if rng.next().is_multiple_of(4) {
            let at = rng.next() as usize % s.len();
            s[at] = rng.next() as u8;
        }
        for (mode, input) in [("bytes", &m), ("directories", &s)] {
            let r = std::panic::catch_unwind(|| {
                let _ = pe::analyze(input);
                let _ = pe::detect(input);
            });
            assert!(r.is_ok(), "panicked on iteration {n} ({mode} mutator, seed {seed:#x})");
        }
    }
}
