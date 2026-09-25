//! A bounded, streaming reader for hostile `.tar.gz` and `.tar.zst` package archives.
//!
//! The package's sha256 is verified before this runs, but the archive is still treated as hostile: nothing in it
//! is trusted. [`walk`] reads the archive ONCE, front to back, and never writes anything itself: for every entry
//! it asks `select` whether the caller wants it and, for [`Selection::Take`], hands `sink` a reader limited to
//! exactly the entry's size. Everything else is discarded while streaming. Memory is one 512-byte header block,
//! one [`CHUNK`] discard buffer, the decoder's own state (an input buffer of [`CHUNK`], plus gzip's 32 KiB window or
//! zstd's window of at most [`TarLimits::max_zstd_window`]) and at most one extended-header payload (capped, see
//! below). [`walk`] reads gzip; [`walk_codec`] picks the [`Codec`].
//!
//! **Compression layer.** Decompressed bytes are counted as they stream and the walk stops at
//! [`TarLimits::max_total_bytes`] (headers and padding count too), whatever the stream would still produce. Each
//! single read from the decoder is at most [`CHUNK`] bytes, so the work done past the cap is at most one chunk.
//! Compressed bytes are counted on the input side and capped at [`TarLimits::max_compressed_bytes`]. Once more
//! than [`TarLimits::ratio_floor`] bytes have been decompressed, `decompressed > compressed_so_far * max_ratio`
//! is [`TarError::RatioExceeded`] (the floor lets small, highly compressible archives, whose zero padding alone
//! compresses a hundredfold, through). Each gzip member is read by its own `flate2::bufread::GzDecoder`, which
//! checks the CRC and length trailer; bytes after a member start another member only up to
//! [`TarLimits::max_gzip_members`] (default 1): past the cap, a gzip magic byte is [`TarError::TooManyMembers`]
//! and anything else is [`TarError::TrailingGarbage`]. A stream that ends early is [`TarError::Truncated`].
//!
//! **Zstd.** Decoded by `ruzstd`'s `StreamingDecoder` (pure Rust) reading through the same counted input, so the
//! caps and the ratio guard above apply unchanged. `ruzstd` checks the frame header's window size (for a
//! single-segment frame, its content size) against the limit it is given BEFORE allocating the window, so a frame
//! declaring more than [`TarLimits::max_zstd_window`] is [`TarError::Zstd`] without allocating it. The decoder
//! holds back one window of output until the frame ends, so it may decode up to one window plus one 128 KiB block
//! beyond what was counted: bounded by that cap, not by the stream. Exactly one frame is read: after it, no input
//! is the end, a zstd magic first byte is [`TarError::TooManyFrames`] and anything else is
//! [`TarError::TrailingGarbage`]. Skippable frames (and dictionary frames) are refused as [`TarError::Zstd`], an
//! input that ends inside the frame is [`TarError::Truncated`]. The content checksum, when present, is read but not
//! verified (ruzstd never verifies it; the package's sha256 already covers the bytes).
//!
//! **Tar layer.** Only POSIX ustar (`ustar\0` `00`) and GNU (`ustar  \0`) headers are accepted (old v7 headers
//! without magic are refused). Every header's checksum is verified; both the unsigned and the historic signed
//! byte sums are accepted. Numeric fields (size, mode, checksum) are strict octal: optional leading spaces, at
//! least one digit `0-7`, then only NUL/space; GNU base-256 (high bit set, which also covers negative numbers),
//! any other byte and overflow are [`TarError::BadHeader`].
//! * Entries: regular files (`'0'` or NUL) and directories (`'5'`, size must be 0). Everything else is
//!   [`TarError::UnsupportedEntry`]: hard and symbolic links, devices, FIFOs, contiguous files, GNU sparse,
//!   multi-volume, volume label, dump dir, GNU long LINK (`'K'`), PAX global headers (`'g'`, refused rather than
//!   ignored: their records would silently apply to every later entry) and any unknown type flag.
//! * Names: the POSIX `prefix` is joined to `name` with `/` (the GNU header's prefix area holds other data and is
//!   not a name). A GNU long name (`'L'`, payload up to `max_name_len + 1` bytes, cut at the first NUL) or a PAX
//!   extended header (`'x'`, payload up to `max_name_len + 512` bytes) replaces the name of the NEXT entry; only
//!   one of them may precede an entry. PAX records must be well formed (`<len> <key>=<value>\n`); the only key
//!   used is `path` (at most once); `mtime`, `atime` and `ctime` are ignored; every other key is
//!   [`TarError::UnsupportedEntry`]. A payload over its cap is [`TarError::NameTooLong`].
//! * Name rules, in order: longer than `max_name_len` bytes is [`TarError::NameTooLong`]; then
//!   [`TarError::UnsafeName`] for non-UTF-8 and absolute (`/...`) names. ONE leading `./` is stripped (`./a/b`
//!   is `a/b`; `././a` is refused), a directory loses ONE trailing `/`. A directory named exactly `./` or `.` is
//!   the archive root (`tar -C dir .` writes one): it is counted but NOT reported to `select`. After that, every
//!   `/`-separated component must be non-empty, must not end with `.` or space (which also refuses `.` and `..`
//!   and Windows-trimmed names) and must not contain `\`, `:` (drive letters, alternate data streams), control
//!   characters (NUL included) or the invisible/bidi characters of [`rt_core::is_format`]. So a file name with a
//!   trailing `/`, `a//b` and an empty name are refused.
//! * Duplicates: the same path may appear more than once (later entries win in real `tar`). They are reported
//!   each time and never merged: the caller decides (the installer should refuse or pick explicitly).
//! * `mode` is reported as recorded (it may carry setuid bits); callers must not apply it blindly.
//! * The end of the archive is two zero blocks; a single zero block followed by anything else is
//!   [`TarError::BadHeader`], a missing end is [`TarError::Truncated`]. After it, at most
//!   [`TarLimits::trailing_allowance`] bytes of zeros may follow (GNU tar pads to a 10 KiB record, hence the
//!   default of 10240), then the stream must end; anything else is [`TarError::TrailingGarbage`].
//! * [`TarLimits::max_entries`] counts every file and directory entry, skipped ones and the root included.
//!
//! No input panics: arithmetic is checked or saturating and header fields are read through `.get()`.

use flate2::bufread::GzDecoder;
use ruzstd::decoding::errors::FrameDecoderError;
use ruzstd::decoding::{FrameDecoder, StreamingDecoder};
use std::io::{self, BufRead, BufReader, Read};
use std::ops::Range;

const BLOCK: usize = 512;
/// Largest single read from the decompressor, the discard buffer and the decoder's input buffer.
const CHUNK: usize = 32 * 1024;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
/// Room in a PAX payload beyond the path: record lengths, `path=`, newlines and the ignored timestamp records.
const PAX_SLACK: u64 = 512;

/// Every cap of the reader. [`TarLimits::for_package`] holds the production values; tests lower them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarLimits {
    /// Most file and directory entries (skipped ones included).
    pub max_entries: usize,
    /// Longest entry name in bytes (after joining prefix/name or applying a long name).
    pub max_name_len: usize,
    /// Largest file entry.
    pub max_entry_bytes: u64,
    /// Most decompressed bytes in total (tar headers and padding included).
    pub max_total_bytes: u64,
    /// Most compressed input bytes.
    pub max_compressed_bytes: u64,
    /// Highest decompressed / compressed-so-far ratio, checked once `ratio_floor` bytes were decompressed.
    pub max_ratio: u64,
    /// Decompressed bytes before the ratio guard applies.
    pub ratio_floor: u64,
    /// Most gzip members (concatenated gzip streams).
    pub max_gzip_members: usize,
    /// Largest zstd window: the most memory the decoder may hold for back-references.
    pub max_zstd_window: u64,
    /// Most zero bytes accepted after the two end-of-archive blocks.
    pub trailing_allowance: usize,
}

impl TarLimits {
    /// Limits for a package whose (hash-verified) archive is `compressed_size` bytes: the input may not be
    /// longer than that, and it may expand to at most `200 x compressed_size`, clamped to `[1 MiB, 2 GiB]`.
    pub fn for_package(compressed_size: u64) -> TarLimits {
        let max_ratio = 200;
        let ratio_floor = MIB;
        TarLimits {
            max_entries: 4096,
            max_name_len: 512,
            max_entry_bytes: 512 * MIB,
            max_total_bytes: compressed_size.saturating_mul(max_ratio).clamp(ratio_floor, 2 * GIB),
            max_compressed_bytes: compressed_size,
            max_ratio,
            ratio_floor,
            max_gzip_members: 1,
            max_zstd_window: 64 * MIB,
            trailing_allowance: 10240,
        }
    }
}

/// The compression around the tar stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Gzip,
    Zstd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarEntryKind {
    File,
    Dir,
}

/// One accepted entry. `path` is validated (see the module docs), `/`-separated, without a leading or trailing
/// `/`. `size` is 0 for directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarEntry {
    pub path: String,
    pub kind: TarEntryKind,
    pub size: u64,
    pub mode: u32,
}

/// What `select` wants done with an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    /// Discard the entry's data (streamed, within the same caps).
    Skip,
    /// Hand the entry's data to `sink`.
    Take,
}

#[derive(Debug, thiserror::Error)]
pub enum TarError {
    #[error("corrupt gzip data: {0}")]
    Gzip(String),
    #[error("corrupt zstd data: {0}")]
    Zstd(String),
    #[error("the archive is truncated")]
    Truncated,
    #[error("malformed tar header: {0}")]
    BadHeader(&'static str),
    #[error("tar header checksum mismatch")]
    BadChecksum,
    #[error("an entry name is too long")]
    NameTooLong,
    #[error("unsafe entry name \"{0}\"")]
    UnsafeName(String),
    #[error("unsupported tar entry: {0}")]
    UnsupportedEntry(&'static str),
    #[error("the archive has too many entries")]
    TooManyEntries,
    #[error("an archive entry is too large")]
    EntryTooLarge,
    #[error("the archive expands beyond its size limit")]
    TooLarge,
    #[error("the compressed archive is larger than expected")]
    CompressedTooLarge,
    #[error("the archive's compression ratio is implausibly high")]
    RatioExceeded,
    #[error("unexpected data after the end of the archive")]
    TrailingGarbage,
    #[error("the archive has too many gzip members")]
    TooManyMembers,
    #[error("the archive has more than one zstd frame")]
    TooManyFrames,
    #[error(transparent)]
    Io(#[from] io::Error),
    /// For `sink` to report its own failures.
    #[error("{0}")]
    Callback(Box<dyn std::error::Error + Send + Sync>),
}

/// [`walk_codec`] for gzip.
pub fn walk<R: Read>(
    src: R,
    limits: &TarLimits,
    select: impl FnMut(&TarEntry) -> Selection,
    sink: impl FnMut(&TarEntry, &mut dyn Read) -> Result<(), TarError>,
) -> Result<u64, TarError> {
    walk_codec(Codec::Gzip, src, limits, select, sink)
}

/// Streams the archive once. `select` sees every reported entry (see the module docs for what is reported); for
/// [`Selection::Take`] `sink` gets a reader that yields exactly `size` bytes and then EOF. Whatever `sink` leaves
/// unread is discarded. If the archive fails while `sink` reads, `sink` sees an I/O error and the archive's
/// error is returned, whatever `sink` returned. Returns the number of file and directory entries.
pub fn walk_codec<R: Read>(
    codec: Codec,
    src: R,
    limits: &TarLimits,
    mut select: impl FnMut(&TarEntry) -> Selection,
    mut sink: impl FnMut(&TarEntry, &mut dyn Read) -> Result<(), TarError>,
) -> Result<u64, TarError> {
    walk_stream(&mut Stream::new(codec, src, limits), limits, &mut select, &mut sink)
}

fn walk_stream<R: Read>(
    s: &mut Stream<R>,
    l: &TarLimits,
    select: &mut dyn FnMut(&TarEntry) -> Selection,
    sink: &mut dyn FnMut(&TarEntry, &mut dyn Read) -> Result<(), TarError>,
) -> Result<u64, TarError> {
    let mut block = [0u8; BLOCK];
    let mut entries: u64 = 0;
    // `Some` once an extended header was read for the next entry; the inner value is its path, if any.
    let mut ext: Option<Option<Vec<u8>>> = None;
    loop {
        read_block(s, &mut block)?;
        if block.iter().all(|&b| b == 0) {
            if ext.is_some() {
                return Err(TarError::BadHeader("extended header without an entry"));
            }
            read_block(s, &mut block)?;
            if block.iter().any(|&b| b != 0) {
                return Err(TarError::BadHeader("single zero block inside the archive"));
            }
            finish(s, l)?;
            return Ok(entries);
        }
        verify_checksum(&block)?;
        let posix = match (field(&block, 257..263), field(&block, 263..265)) {
            (b"ustar\0", b"00") => true,
            (b"ustar ", b" \0") => false,
            _ => return Err(TarError::BadHeader("not a ustar or GNU header")),
        };
        let size = octal(field(&block, 124..136))?;
        let kind = match block.get(156).copied().unwrap_or(0) {
            b'0' | 0 => TarEntryKind::File,
            b'5' => TarEntryKind::Dir,
            t @ (b'L' | b'x') => {
                if ext.is_some() {
                    return Err(TarError::BadHeader("consecutive extended headers"));
                }
                let cap = if t == b'L' {
                    (l.max_name_len as u64).saturating_add(1)
                } else {
                    (l.max_name_len as u64).saturating_add(PAX_SLACK)
                };
                if size > cap {
                    return Err(TarError::NameTooLong);
                }
                let mut payload = vec![0u8; usize::try_from(size).map_err(|_| TarError::NameTooLong)?];
                if read_full(s, &mut payload)? != payload.len() {
                    return Err(TarError::Truncated);
                }
                discard(s, padding(size))?;
                ext = Some(if t == b'L' {
                    Some(cut_nul(&payload).to_vec())
                } else {
                    pax_path(&payload)?
                });
                continue;
            }
            t => return Err(TarError::UnsupportedEntry(unsupported(t))),
        };
        entries = entries.saturating_add(1);
        if entries > l.max_entries as u64 {
            return Err(TarError::TooManyEntries);
        }
        let mode = u32::try_from(octal(field(&block, 100..108))?).map_err(|_| TarError::BadHeader("mode"))?;
        match kind {
            TarEntryKind::Dir if size != 0 => return Err(TarError::BadHeader("directory with data")),
            TarEntryKind::File if size > l.max_entry_bytes => return Err(TarError::EntryTooLarge),
            _ => {}
        }
        let raw = match ext.take() {
            Some(Some(path)) => path,
            _ => ustar_name(&block, posix),
        };
        let mut left = size;
        if let Some(path) = normalise(&raw, kind, l.max_name_len)? {
            let entry = TarEntry { path, kind, size, mode };
            if select(&entry) == Selection::Take {
                let mut r = EntryReader {
                    s: &mut *s,
                    left,
                    short: false,
                };
                let res = sink(&entry, &mut r);
                let short = r.short;
                left = r.left;
                if let Some(e) = s.failed.take() {
                    return Err(e);
                }
                if short {
                    return Err(TarError::Truncated);
                }
                res?;
            }
        }
        discard(s, left.saturating_add(padding(size)))?;
    }
}

/// The reader `sink` gets: at most `left` more bytes, then EOF.
struct EntryReader<'a, R: Read> {
    s: &'a mut Stream<R>,
    left: u64,
    /// The archive ended before `left` reached 0.
    short: bool,
}

impl<R: Read> Read for EntryReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let cap = usize::try_from(self.left).unwrap_or(usize::MAX).min(buf.len());
        if cap == 0 {
            return Ok(0);
        }
        let got = self.s.read_io(buf.get_mut(..cap).unwrap_or_default())?;
        if got == 0 {
            self.short = true;
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tar entry is truncated"));
        }
        self.left = self.left.saturating_sub(got as u64);
        Ok(got)
    }
}

/// Compressed input, counted and capped.
struct Counted<R> {
    inner: R,
    n: u64,
    max: u64,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let got = self.inner.read(buf)?;
        self.n = self.n.saturating_add(got as u64);
        if self.n > self.max {
            return Err(io::Error::other(OverCap));
        }
        Ok(got)
    }
}

/// [`Counted`]'s error, recognised under the zstd decoder's error chain (which only lends it out by reference).
#[derive(Debug, thiserror::Error)]
#[error("compressed input over its cap")]
struct OverCap;

type Input<R> = BufReader<Counted<R>>;

enum Dec<R: Read> {
    Gz(GzDecoder<Input<R>>),
    /// A zstd frame whose header is read by the first [`Stream::read`], so that its errors are typed there.
    ZstHeader(Input<R>),
    /// Boxed: the frame decoder's state is several hundred bytes.
    Zst(Box<StreamingDecoder<Input<R>, FrameDecoder>>),
    /// The last member or frame ended at the end of the input (or the stream already failed).
    Done,
}

/// The decompressed byte stream across gzip members or in one zstd frame, with the compression-side caps.
struct Stream<R: Read> {
    dec: Dec<R>,
    members: usize,
    /// Decompressed bytes returned so far.
    total: u64,
    max_total: u64,
    max_ratio: u64,
    ratio_floor: u64,
    max_members: usize,
    max_window: u64,
    /// The (first) typed error behind an I/O error handed to `sink`.
    failed: Option<TarError>,
}

impl<R: Read> Stream<R> {
    fn new(codec: Codec, src: R, l: &TarLimits) -> Self {
        let counted = Counted {
            inner: src,
            n: 0,
            max: l.max_compressed_bytes,
        };
        let input = BufReader::with_capacity(CHUNK, counted);
        Stream {
            dec: match codec {
                Codec::Gzip => Dec::Gz(GzDecoder::new(input)),
                Codec::Zstd => Dec::ZstHeader(input),
            },
            members: 1,
            total: 0,
            max_total: l.max_total_bytes,
            max_ratio: l.max_ratio,
            ratio_floor: l.ratio_floor,
            max_members: l.max_gzip_members,
            max_window: l.max_zstd_window,
            failed: None,
        }
    }

    /// At most [`CHUNK`] decompressed bytes; `Ok(0)` only at the real end of the input.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TarError> {
        let want = buf.len().min(CHUNK);
        let buf = buf.get_mut(..want).unwrap_or_default();
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if matches!(self.dec, Dec::ZstHeader(_))
                && let Dec::ZstHeader(input) = std::mem::replace(&mut self.dec, Dec::Done)
            {
                // `ruzstd` refuses a window over the cap before allocating it.
                let dec =
                    StreamingDecoder::new_with_max_window_size(input, self.max_window).map_err(|e| classify_zst(&e))?;
                self.dec = Dec::Zst(Box::new(dec));
            }
            let (got, input) = match &mut self.dec {
                Dec::Gz(dec) => (
                    dec.read(buf).map_err(|e| classify(e, dec.get_ref().get_ref())),
                    dec.get_ref(),
                ),
                Dec::Zst(dec) => (dec.read(buf).map_err(|e| classify_zst(&e)), dec.get_ref()),
                Dec::ZstHeader(_) | Dec::Done => return Ok(0),
            };
            let got = match got {
                Ok(n) => n,
                Err(e) => {
                    // A failed zstd decoder is never polled again (a `sink` may keep reading after an error).
                    if matches!(self.dec, Dec::Zst(_)) {
                        self.dec = Dec::Done;
                    }
                    return Err(e);
                }
            };
            match got {
                0 => {}
                n => {
                    self.total = self.total.saturating_add(n as u64);
                    if self.total > self.max_total {
                        return Err(TarError::TooLarge);
                    }
                    // Compressed bytes the decoder has consumed (read-ahead still in the buffer excluded).
                    let compressed = input.get_ref().n.saturating_sub(input.buffer().len() as u64);
                    if self.total > self.ratio_floor && self.total > compressed.saturating_mul(self.max_ratio) {
                        return Err(TarError::RatioExceeded);
                    }
                    return Ok(n);
                }
            }
            // The member or frame ended (the gzip decoder checked its CRC and length): is there more input?
            let (mut rest, zstd) = match std::mem::replace(&mut self.dec, Dec::Done) {
                Dec::Gz(dec) => (dec.into_inner(), false),
                Dec::Zst(dec) => (dec.into_inner(), true),
                Dec::ZstHeader(_) | Dec::Done => return Ok(0),
            };
            let next = match rest.fill_buf() {
                Ok(b) => b.first().copied(),
                Err(e) if zstd => return Err(classify_zst(&e)),
                Err(e) => return Err(classify(e, rest.get_ref())),
            };
            match next {
                None => return Ok(0),
                Some(first) if zstd => {
                    return Err(if first == 0x28 {
                        TarError::TooManyFrames
                    } else {
                        TarError::TrailingGarbage
                    });
                }
                Some(first) if self.members >= self.max_members => {
                    return Err(if first == 0x1f {
                        TarError::TooManyMembers
                    } else {
                        TarError::TrailingGarbage
                    });
                }
                Some(_) => {
                    self.members = self.members.saturating_add(1);
                    self.dec = Dec::Gz(GzDecoder::new(rest));
                }
            }
        }
    }

    /// [`Stream::read`] for `sink`: the first typed error is kept in `failed` for `walk` to return.
    fn read_io(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read(buf).map_err(|e| {
            self.failed.get_or_insert(e);
            io::Error::other("the archive could not be read")
        })
    }
}

fn classify<R>(e: io::Error, input: &Counted<R>) -> TarError {
    if input.n > input.max {
        return TarError::CompressedTooLarge;
    }
    match e.kind() {
        io::ErrorKind::UnexpectedEof => TarError::Truncated,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => TarError::Gzip(e.to_string()),
        _ => TarError::Io(e),
    }
}

/// A zstd error: the first I/O error in its chain decides (our cap, an early end, or the source's own failure);
/// without one, the data is corrupt. `StreamingDecoder::read` wraps the decoder's error in an `io::Error`, whose
/// `source()` skips the wrapped error itself, so that one is unwrapped with `get_ref`.
fn classify_zst(e: &(dyn std::error::Error + 'static)) -> TarError {
    let mut cur = Some(e);
    while let Some(err) = cur {
        if let Some(io) = err.downcast_ref::<io::Error>() {
            return match io.get_ref() {
                Some(inner) if inner.is::<FrameDecoderError>() => {
                    cur = Some(inner);
                    continue;
                }
                Some(inner) if inner.is::<OverCap>() => TarError::CompressedTooLarge,
                _ if io.kind() == io::ErrorKind::UnexpectedEof => TarError::Truncated,
                _ => TarError::Io(io::Error::new(io.kind(), io.to_string())),
            };
        }
        cur = err.source();
    }
    TarError::Zstd(e.to_string())
}

/// Fills `buf` as far as the stream goes; returns how much was read.
fn read_full<R: Read>(s: &mut Stream<R>, buf: &mut [u8]) -> Result<usize, TarError> {
    let mut got = 0;
    while let Some(rest) = buf.get_mut(got..).filter(|r| !r.is_empty()) {
        match s.read(rest)? {
            0 => break,
            n => got += n,
        }
    }
    Ok(got)
}

fn read_block<R: Read>(s: &mut Stream<R>, block: &mut [u8; BLOCK]) -> Result<(), TarError> {
    if read_full(s, block)? == BLOCK {
        Ok(())
    } else {
        Err(TarError::Truncated)
    }
}

/// Reads and drops exactly `n` bytes.
fn discard<R: Read>(s: &mut Stream<R>, mut n: u64) -> Result<(), TarError> {
    let mut buf = [0u8; CHUNK];
    while n > 0 {
        let want = usize::try_from(n).unwrap_or(CHUNK).min(CHUNK);
        match s.read(buf.get_mut(..want).unwrap_or_default())? {
            0 => return Err(TarError::Truncated),
            got => n = n.saturating_sub(got as u64),
        }
    }
    Ok(())
}

/// After the end blocks: at most `trailing_allowance` zero bytes, then the end of the input.
fn finish<R: Read>(s: &mut Stream<R>, l: &TarLimits) -> Result<(), TarError> {
    let mut buf = [0u8; CHUNK];
    let mut extra: u64 = 0;
    loop {
        let n = s.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        extra = extra.saturating_add(n as u64);
        if extra > l.trailing_allowance as u64 || buf.get(..n).unwrap_or_default().iter().any(|&b| b != 0) {
            return Err(TarError::TrailingGarbage);
        }
    }
}

fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

fn field(block: &[u8], r: Range<usize>) -> &[u8] {
    block.get(r).unwrap_or_default()
}

fn cut_nul(b: &[u8]) -> &[u8] {
    b.split(|&c| c == 0).next().unwrap_or_default()
}

/// Strict octal: leading spaces, 1+ digits `0-7`, then only NUL/space. GNU base-256 (high bit set on the first
/// byte) is not a digit, so it is refused as well. At most 12 digits: overflow is unreachable, still checked.
fn octal(f: &[u8]) -> Result<u64, TarError> {
    let start = f.iter().position(|&b| b != b' ').unwrap_or(f.len());
    let rest = f.get(start..).unwrap_or_default();
    let digits = rest.iter().take_while(|b| (b'0'..=b'7').contains(*b)).count();
    if digits == 0 {
        return Err(TarError::BadHeader("empty number"));
    }
    if rest
        .get(digits..)
        .unwrap_or_default()
        .iter()
        .any(|&b| b != 0 && b != b' ')
    {
        return Err(TarError::BadHeader("bad octal number"));
    }
    rest.get(..digits).unwrap_or_default().iter().try_fold(0u64, |v, &d| {
        v.checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(d - b'0')))
            .ok_or(TarError::BadHeader("number overflows"))
    })
}

/// The stored checksum must equal the unsigned or the signed byte sum, the checksum field counted as spaces.
fn verify_checksum(block: &[u8; BLOCK]) -> Result<(), TarError> {
    let want = octal(field(block, 148..156)).map_err(|_| TarError::BadChecksum)?;
    let (mut unsigned, mut signed) = (0u64, 0i64);
    for (i, &b) in block.iter().enumerate() {
        let b = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += u64::from(b);
        signed += i64::from(b as i8);
    }
    if want == unsigned || i64::try_from(want) == Ok(signed) {
        Ok(())
    } else {
        Err(TarError::BadChecksum)
    }
}

fn ustar_name(block: &[u8], posix: bool) -> Vec<u8> {
    let name = cut_nul(field(block, 0..100));
    let prefix = if posix { cut_nul(field(block, 345..500)) } else { &[] };
    if prefix.is_empty() {
        return name.to_vec();
    }
    [prefix, b"/", name].concat()
}

/// The `path` of a PAX extended header, if it has one. See the module docs for the accepted keys.
fn pax_path(mut p: &[u8]) -> Result<Option<Vec<u8>>, TarError> {
    let bad = TarError::BadHeader;
    let mut path = None;
    while !p.is_empty() {
        let sp = p
            .iter()
            .position(|&b| b == b' ')
            .ok_or(bad("pax record without length"))?;
        let digits = p.get(..sp).unwrap_or_default();
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return Err(bad("pax record length"));
        }
        let len: usize = std::str::from_utf8(digits)
            .ok()
            .and_then(|d| d.parse().ok())
            .ok_or(bad("pax record length"))?;
        let record = p.get(..len).ok_or(bad("pax record past the end"))?;
        let body = record
            .get(sp.saturating_add(1)..)
            .and_then(|b| b.strip_suffix(b"\n"))
            .ok_or(bad("pax record framing"))?;
        let eq = body
            .iter()
            .position(|&b| b == b'=')
            .ok_or(bad("pax record without '='"))?;
        let (key, value) = (
            body.get(..eq).unwrap_or_default(),
            body.get(eq + 1..).unwrap_or_default(),
        );
        match key {
            b"path" if path.is_some() => return Err(bad("duplicate pax path")),
            b"path" => path = Some(value.to_vec()),
            b"mtime" | b"atime" | b"ctime" => {}
            _ => return Err(TarError::UnsupportedEntry("pax key other than path/mtime/atime/ctime")),
        }
        p = p.get(len..).unwrap_or_default();
    }
    Ok(path)
}

/// The validated, reported path; `None` for the archive root directory (`./` or `.`).
fn normalise(raw: &[u8], kind: TarEntryKind, max: usize) -> Result<Option<String>, TarError> {
    if raw.len() > max {
        return Err(TarError::NameTooLong);
    }
    let unsafe_name = || TarError::UnsafeName(clip(raw));
    let name = std::str::from_utf8(raw).map_err(|_| unsafe_name())?;
    if kind == TarEntryKind::Dir && (name == "./" || name == ".") {
        return Ok(None);
    }
    let name = name.strip_prefix("./").unwrap_or(name);
    let name = if kind == TarEntryKind::Dir {
        name.strip_suffix('/').unwrap_or(name)
    } else {
        name
    };
    // An absolute name has an empty first component; `ends_with('.')` also refuses `.` and `..`.
    let bad = |c: &str| {
        c.is_empty()
            || c.ends_with(['.', ' '])
            || c.chars()
                .any(|ch| ch == '\\' || ch == ':' || ch.is_control() || rt_core::is_format(ch))
    };
    if name.split('/').any(bad) {
        return Err(unsafe_name());
    }
    Ok(Some(name.to_owned()))
}

/// At most 64 bytes of a name, escaped, for an error message.
fn clip(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw.get(..raw.len().min(64)).unwrap_or_default())
        .escape_debug()
        .to_string()
}

fn unsupported(t: u8) -> &'static str {
    match t {
        b'1' => "hard link",
        b'2' => "symbolic link",
        b'3' => "character device",
        b'4' => "block device",
        b'6' => "FIFO",
        b'7' => "contiguous file",
        b'g' => "pax global header",
        b'K' => "GNU long link name",
        b'S' => "GNU sparse file",
        b'M' => "GNU multi-volume continuation",
        b'V' => "GNU volume label",
        b'D' => "GNU directory dump",
        _ => "unknown entry type",
    }
}

#[cfg(test)]
mod tests;
