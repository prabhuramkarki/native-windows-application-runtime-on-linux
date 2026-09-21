mod common;
use common::*;
use std::{
    cell::RefCell,
    panic::{self, PanicHookInfo},
    path::PathBuf,
    sync::Arc,
};

/// File offset of data directory 0 in an x64 (PE32+) image built by `Builder` (PE header at 0x40,
/// file header 20 bytes, optional header fields up to the directories 112 bytes). The structure
/// mutator below only knows this PE32+ layout; PE32 (x86) headers get byte-flip coverage only.
const X64_DIRS: usize = 0x44 + 20 + 112;
/// File offset of SizeOfImage in the same layout (optional header + 56).
const X64_SIZE_OF_IMAGE: usize = 0x44 + 20 + 56;

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
    let size = &img[X64_SIZE_OF_IMAGE..X64_SIZE_OF_IMAGE + 4];
    assert_eq!(u32::from_le_bytes(size.try_into().unwrap()), Builder::rva(6));
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

/// Env override parsed as decimal or `0x` hex. A set-but-unusable value is an error, never a
/// silent fallback to the default.
fn env_u64(name: &str, default: u64) -> u64 {
    let s = match std::env::var(name) {
        Ok(s) => s,
        Err(std::env::VarError::NotPresent) => return default,
        Err(e) => panic!("{name}: {e}"),
    };
    let s = s.trim();
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16),
        None => s.parse(),
    }
    .unwrap_or_else(|e| panic!("{name}={s:?}: {e}"))
}

/// What the fuzz thread is analysing right now, so the panic hook can say which input killed the
/// process even when the panic is followed by a non-unwinding abort (pelite does that).
struct Current {
    seed: u64,
    iteration: u64,
    mode: &'static str,
    input: Vec<u8>,
}

thread_local! {
    static CURRENT: RefCell<Option<Current>> = const { RefCell::new(None) };
}

fn track(seed: u64, iteration: u64, mode: &'static str, input: &[u8]) {
    CURRENT.with_borrow_mut(|c| {
        let cur = c.get_or_insert_with(|| Current {
            seed,
            iteration,
            mode,
            input: vec![],
        });
        (cur.seed, cur.iteration, cur.mode) = (seed, iteration, mode);
        cur.input.clear();
        cur.input.extend_from_slice(input);
    });
}

fn dump_path(seed: u64, iteration: u64) -> PathBuf {
    std::env::temp_dir().join(format!("pe-fuzz-fail-{seed:x}-{iteration}.bin"))
}

type Hook = Box<dyn Fn(&PanicHookInfo<'_>) + Sync + Send + 'static>;

/// While alive, any panic on this thread first prints seed/iteration/mode and saves the failing
/// input, then runs the previous hook. Drop puts the previous hook back (not reached on abort).
struct DiagnoseGuard(Option<Arc<Hook>>);

impl DiagnoseGuard {
    fn install() -> Self {
        let prev = Arc::new(panic::take_hook());
        let chained = Arc::clone(&prev);
        panic::set_hook(Box::new(move |info| {
            CURRENT.with_borrow(|c| {
                if let Some(c) = c {
                    let path = dump_path(c.seed, c.iteration);
                    let saved = std::fs::write(&path, &c.input)
                        .map_or(String::from("unsaved"), |()| path.display().to_string());
                    eprintln!(
                        "corruption test: seed={:#x} iteration={} mode={} input={saved}",
                        c.seed, c.iteration, c.mode
                    );
                }
            });
            chained(info);
        }));
        Self(Some(prev))
    }
}

impl Drop for DiagnoseGuard {
    fn drop(&mut self) {
        CURRENT.with_borrow_mut(|c| *c = None);
        // The hook cannot be swapped while unwinding; our hook is inert once CURRENT is cleared.
        if std::thread::panicking() {
            return;
        }
        drop(panic::take_hook()); // our hook, releasing its clone of the Arc
        if let Some(Ok(prev)) = self.0.take().map(Arc::try_unwrap) {
            panic::set_hook(prev);
        }
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
/// data-directory entries (optionally followed by a byte flip).
///
/// Diagnosing a failure: a panic hook prints `corruption test: seed=<hex> iteration=<n>
/// mode=<bytes|directories> input=<path>` and saves the offending input to
/// `$TMPDIR/pe-fuzz-fail-<seed>-<n>.bin` BEFORE the panic message, which also covers a hard abort
/// (SIGABRT from a non-unwinding panic in a dependency), where `catch_unwind` cannot help. To
/// reproduce: `RUNTIME_FUZZ_SEED=<seed> RUNTIME_FUZZ_ITERS=<n+1> cargo test -p runtime-pe --test
/// robust corrupted -- --nocapture`, or feed the dump `$TMPDIR/pe-fuzz-fail-<seed>-<n>.bin` to
/// `pe::analyze`. Pass `--nocapture`: libtest captures test output, and on an abort the process
/// dies before the captured hook line is flushed, so without it the seed/iteration line is lost
/// (the dump file is still written).
#[test]
fn corrupted_input_never_panics() {
    let original = rich_sample();
    let seed = env_u64("RUNTIME_FUZZ_SEED", 0x9E37_79B9_7F4A_7C15);
    let iters = env_u64("RUNTIME_FUZZ_ITERS", 30_000);
    assert_ne!(seed, 0, "xorshift needs a non-zero seed");
    assert!(iters > 0, "RUNTIME_FUZZ_ITERS must be at least 1");
    let at = X64_SIZE_OF_IMAGE;
    let image_size = u32::from_le_bytes(original[at..at + 4].try_into().unwrap());
    let _hook = DiagnoseGuard::install();
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
            track(seed, n, mode, input);
            let r = panic::catch_unwind(|| {
                let _ = pe::analyze(input);
                let _ = pe::detect(input);
            });
            assert!(
                r.is_ok(),
                "panicked on iteration {n} ({mode} mutator, seed {seed:#x}); input saved to {}",
                dump_path(seed, n).display()
            );
        }
    }
}
