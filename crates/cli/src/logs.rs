//! `runtime logs <id> [--lines N]`: the end of the newest `run-*.log` of an app.
//!
//! The log is written by the app (same uid, and Wine can swap what is inside the app directory), so it is
//! untrusted: the `logs` directory must be a real directory (lstat), only regular files named `run-*.log` count
//! (`DirEntry::file_type` does not follow links), the chosen file is opened with `O_NOFOLLOW|O_NONBLOCK` and
//! re-checked with fstat, at most 64 KiB are read, and every line goes through `safe` (line breaks kept). The
//! OUTPUT is bounded too: at most `--lines` lines (default 50, at most 1000) and 64 KiB after escaping.
use crate::CmdError;
use crate::safe::{safe, warn};
use rt_core::{AppId, StoreError};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub const DEFAULT_LINES: u32 = 50;
const MAX_LINES: usize = 1000;
/// The most that is read from the file and the most that is printed.
const CAP_BYTES: usize = 64 * 1024;
/// At most this many directory entries are looked at.
const MAX_SCAN: usize = 10_000;

pub fn run(arg: &str, lines: u32) -> Result<(), CmdError> {
    if lines == 0 {
        return Err("--lines must be at least 1".into());
    }
    let mut lines = lines as usize;
    if lines > MAX_LINES {
        eprintln!("note: --lines is limited to {MAX_LINES}");
        lines = MAX_LINES;
    }
    let id = AppId::parse(arg).map_err(|e| {
        format!(
            "{:?} is not a valid app id ({e}); `logs` takes an id from `runtime list`",
            crate::safe::shorten(arg, 80)
        )
    })?;
    let store = crate::store()?;
    let env = match store.get(&id) {
        Err(StoreError::NotFound) => return Err(format!("no app named {id} is installed (see `runtime list`)").into()),
        other => other?,
    };
    let dir = env.logs_dir();
    match fs::symlink_metadata(&dir) {
        Ok(m) if m.file_type().is_dir() => {}
        Ok(_) => return Err(format!("the logs directory of {id} is not a real directory: refusing to read it").into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!("{id} has no logs directory").into());
        }
        Err(e) => return Err(e.into()),
    }
    let Some(path) = newest_log(&dir)? else {
        eprintln!("note: {id} has no logs yet (run it first)");
        return Ok(());
    };
    let (chunk, whole_file) = read_tail(&path)?;
    if chunk.is_empty() {
        eprintln!("note: the newest log is empty (use --debug for Wine diagnostics)");
        return Ok(());
    }
    let tail = render_tail(&chunk, !whole_file, lines, CAP_BYTES);
    crate::emit(&tail.text)?;
    if tail.truncated {
        eprintln!("note: only the end of the log is shown (last {lines} lines, at most 64 KiB)");
    }
    Ok(())
}

/// The `run-*.log` regular file with the greatest name (names are `run-<secs>-<nanos>-<pid>.log`, so this is
/// the newest), or `None`.
fn newest_log(dir: &Path) -> Result<Option<std::path::PathBuf>, CmdError> {
    let mut best: Option<std::ffi::OsString> = None;
    for (n, entry) in fs::read_dir(dir)?.enumerate() {
        if n >= MAX_SCAN {
            warn(&format!(
                "the logs directory has more than {MAX_SCAN} entries; only the first were examined"
            ));
            break;
        }
        let entry = entry?;
        let name = entry.file_name();
        let bytes = name.as_encoded_bytes();
        let is_log = bytes.starts_with(b"run-") && bytes.ends_with(b".log");
        // `file_type` does not follow a symlink: a link, directory or FIFO named like a log is skipped.
        if is_log && entry.file_type()?.is_file() && best.as_ref().is_none_or(|b| name > *b) {
            best = Some(name);
        }
    }
    Ok(best.map(|name| dir.join(name)))
}

/// The last (at most [`CAP_BYTES`]) bytes of the file, and whether that is the whole file.
fn read_tail(path: &Path) -> Result<(Vec<u8>, bool), CmdError> {
    // The name was a regular file when listed; it may have been swapped since: never follow a link, never
    // block on a FIFO, and look at what was actually opened.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err("the newest log is not a regular file".into());
    }
    let start = meta.len().saturating_sub(CAP_BYTES as u64);
    file.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    // `take`: the file may grow while it is read.
    file.take(CAP_BYTES as u64).read_to_end(&mut buf)?;
    Ok((buf, start == 0))
}

#[derive(Debug, PartialEq, Eq)]
struct Tail {
    /// Sanitised, every line ended by `\n`; at most `cap` bytes.
    text: String,
    /// Something of the log is not in `text`.
    truncated: bool,
}

/// The last `lines` lines of `chunk` (raw log bytes), escaped with `safe`, in at most `cap` bytes. `cut_start`:
/// `chunk` begins in the middle of the file, so its first line is partial and is dropped when there is a
/// newline to drop it at (a chunk that is one endless line keeps its end). Whole lines only, except when a
/// single line alone is longer than `cap`: then its end is kept.
fn render_tail(chunk: &[u8], cut_start: bool, lines: usize, cap: usize) -> Tail {
    let text = String::from_utf8_lossy(chunk);
    let mut body: &str = &text;
    let mut truncated = cut_start;
    if cut_start && let Some(i) = body.find('\n') {
        body = &body[i + 1..];
    }
    let all: Vec<&str> = body.lines().collect();
    let skip = all.len().saturating_sub(lines);
    truncated |= skip > 0;
    let mut kept: Vec<String> = Vec::new();
    let mut used = 0;
    for line in all[skip..].iter().rev() {
        let mut escaped = safe(line);
        if used + escaped.len() + 1 > cap {
            truncated = true;
            if kept.is_empty() {
                let mut from = escaped.len().saturating_sub(cap.saturating_sub(1));
                while !escaped.is_char_boundary(from) {
                    from += 1;
                }
                escaped = escaped.split_off(from);
                kept.push(escaped);
            }
            break;
        }
        used += escaped.len() + 1;
        kept.push(escaped);
    }
    kept.reverse();
    let text: String = kept.iter().map(|l| format!("{l}\n")).collect();
    Tail { text, truncated }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tail(chunk: &str, cut: bool, lines: usize, cap: usize) -> Tail {
        render_tail(chunk.as_bytes(), cut, lines, cap)
    }

    #[test]
    fn whole_short_input_is_shown_untruncated() {
        assert_eq!(
            tail("a\nb\n", false, 10, 1000),
            Tail {
                text: "a\nb\n".into(),
                truncated: false
            }
        );
        assert_eq!(
            tail("a\nb", false, 10, 1000).text,
            "a\nb\n",
            "a missing final newline is added"
        );
        assert_eq!(
            tail("", false, 10, 1000),
            Tail {
                text: String::new(),
                truncated: false
            }
        );
        assert_eq!(tail("\n\n", false, 10, 1000).text, "\n\n", "empty lines are lines");
    }

    #[test]
    fn the_last_n_lines_are_kept() {
        let t = tail("1\n2\n3\n4\n5\n", false, 2, 1000);
        assert_eq!(
            t,
            Tail {
                text: "4\n5\n".into(),
                truncated: true
            }
        );
        assert!(
            !tail("1\n2\n3\n", false, 3, 1000).truncated,
            "exactly n lines is not truncated"
        );
        assert_eq!(tail("1\n2\n3\n", false, 1, 1000).text, "3\n");
    }

    #[test]
    fn a_partial_first_line_is_dropped_when_the_chunk_starts_mid_file() {
        let t = tail("rtial line\nwhole\nlast\n", true, 10, 1000);
        assert_eq!(
            t,
            Tail {
                text: "whole\nlast\n".into(),
                truncated: true
            }
        );
        // without a newline anywhere the single endless line is kept
        assert_eq!(tail("only-one-huge-line", true, 10, 1000).text, "only-one-huge-line\n");
        assert!(tail("only-one-huge-line", true, 10, 1000).truncated);
    }

    #[test]
    fn the_output_never_exceeds_the_byte_cap_and_keeps_the_newest_whole_lines() {
        let chunk = "aaaa\nbbbb\ncccc\ndddd\n";
        let t = tail(chunk, false, 100, 10); // room for two 5-byte lines
        assert_eq!(
            t,
            Tail {
                text: "cccc\ndddd\n".into(),
                truncated: true
            }
        );
        assert_eq!(tail(chunk, false, 100, 20).text, chunk);
        assert!(!tail(chunk, false, 100, 20).truncated);
        assert_eq!(tail(chunk, false, 100, 19).text, "bbbb\ncccc\ndddd\n");
    }

    #[test]
    fn one_line_longer_than_the_cap_keeps_its_end_within_the_cap() {
        let t = tail(&format!("{}END\n", "x".repeat(500)), false, 5, 20);
        assert_eq!(t.text.len(), 20);
        assert!(t.text.ends_with("xxxEND\n"), "{:?}", t.text);
        assert!(t.truncated);
        // multi-byte characters are not cut in half
        let t = tail(&"é".repeat(100), false, 5, 21);
        assert!(
            t.text.len() <= 21 && t.text.chars().all(|c| c == 'é' || c == '\n'),
            "{:?}",
            t.text
        );
    }

    #[test]
    fn escaping_can_not_push_the_output_over_the_cap() {
        // 1000 ESC bytes escape to 6 bytes each.
        let t = tail(&"\x1b".repeat(1000), false, 5, 100);
        assert!(t.text.len() <= 100, "{}", t.text.len());
        assert!(!t.text.contains('\x1b'));
        let t = tail("a\x1b[31mb\u{0}\r\nnext\n", false, 10, 1000);
        assert_eq!(
            t.text, "a\\u{1b}[31mb\\u{0}\nnext\n",
            "CRLF line ends are line ends, `\\r` inside a line is escaped"
        );
        assert_eq!(tail("a\rb\n", false, 5, 100).text, "a\\rb\n");
    }

    #[test]
    fn invalid_utf8_and_bare_carriage_returns_are_contained() {
        let t = render_tail(b"a\xff\xfeb\rc\nd\n", false, 10, 1000);
        assert_eq!(t.text, "a\u{fffd}\u{fffd}b\\rc\nd\n");
        assert_eq!(t.text.lines().count(), 2);
    }

    #[test]
    fn read_tail_reads_the_end_of_a_regular_file_only() {
        let dir = tempfile::tempdir().unwrap();
        let small = dir.path().join("small");
        fs::write(&small, b"hello\n").unwrap();
        assert_eq!(read_tail(&small).unwrap(), (b"hello\n".to_vec(), true));
        let big = dir.path().join("big");
        let data: Vec<u8> = (0..CAP_BYTES * 2).map(|i| (i % 251) as u8).collect();
        fs::write(&big, &data).unwrap();
        let (tail, whole) = read_tail(&big).unwrap();
        assert!(!whole);
        assert_eq!(tail, data[CAP_BYTES..], "exactly the last CAP_BYTES bytes");
        // Not regular files (the name may have been swapped after the directory was listed): refused, no hang.
        std::os::unix::fs::symlink(&small, dir.path().join("link")).unwrap();
        assert!(
            read_tail(&dir.path().join("link")).is_err(),
            "a symlink is never followed"
        );
        let fifo = dir.path().join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // On its own thread: a `read_tail` that blocks on the FIFO must fail this test, not hang the run.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_tail(&fifo).map_err(|e| e.to_string()));
        });
        let e = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("read_tail blocked on a FIFO")
            .unwrap_err();
        assert!(e.contains("not a regular file"), "{e}");
        assert!(read_tail(dir.path()).is_err(), "a directory is refused");
    }
}
