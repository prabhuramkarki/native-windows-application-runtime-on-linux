use super::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;
use std::process::Command;

// ---------- a tiny tar writer ----------

fn put_octal(field: &mut [u8], v: u64) {
    let w = field.len() - 1;
    let s = format!("{v:0w$o}");
    assert_eq!(s.len(), w, "test value too large for its field");
    field[..w].copy_from_slice(s.as_bytes());
    field[w] = 0;
}

/// Recomputes the (unsigned) checksum of a header block.
fn seal(h: &mut [u8]) {
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

/// A POSIX ustar header for `name` (at most 100 bytes), mode 0644.
fn header(name: &[u8], typ: u8, size: u64) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[..name.len()].copy_from_slice(name);
    put_octal(&mut h[100..108], 0o644);
    put_octal(&mut h[108..116], 0);
    put_octal(&mut h[116..124], 0);
    put_octal(&mut h[124..136], size);
    put_octal(&mut h[136..148], 0);
    h[156] = typ;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    seal(&mut h);
    h
}

/// `header` with one edit applied and the checksum recomputed.
fn edited(name: &[u8], typ: u8, size: u64, edit: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut h = header(name, typ, size);
    edit(&mut h);
    seal(&mut h);
    h
}

fn pad(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(512) {
        v.push(0);
    }
}

#[derive(Default)]
struct Tar(Vec<u8>);

impl Tar {
    fn raw(mut self, bytes: &[u8]) -> Self {
        self.0.extend_from_slice(bytes);
        self
    }
    fn data(mut self, d: &[u8]) -> Self {
        self.0.extend_from_slice(d);
        pad(&mut self.0);
        self
    }
    fn file(self, name: &str, data: &[u8]) -> Self {
        self.raw(&header(name.as_bytes(), b'0', data.len() as u64)).data(data)
    }
    fn dir(self, name: &str) -> Self {
        self.raw(&header(name.as_bytes(), b'5', 0))
    }
    /// A GNU long-name ('L') header carrying `name` + NUL.
    fn long(self, name: &[u8]) -> Self {
        let mut payload = name.to_vec();
        payload.push(0);
        self.raw(&header(b"././@LongLink", b'L', payload.len() as u64))
            .data(&payload)
    }
    /// A PAX extended header ('x') with these records.
    fn pax(self, records: &[(&str, &[u8])]) -> Self {
        let mut payload = Vec::new();
        for (k, v) in records {
            payload.extend(pax_record(k, v));
        }
        self.raw(&header(b"PaxHeaders/x", b'x', payload.len() as u64))
            .data(&payload)
    }
    fn end(mut self) -> Vec<u8> {
        self.0.extend_from_slice(&[0u8; 1024]);
        self.0
    }
}

fn pax_record(k: &str, v: &[u8]) -> Vec<u8> {
    let body = 1 + k.len() + 1 + v.len() + 1; // " k=v\n"
    let mut len = body + 1;
    while len.to_string().len() + body != len {
        len += 1;
    }
    let mut r = format!("{len} {k}=").into_bytes();
    r.extend_from_slice(v);
    r.push(b'\n');
    assert_eq!(r.len(), len);
    r
}

fn gz_level(tar: &[u8], level: u32) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(tar).unwrap();
    e.finish().unwrap()
}

fn gz(tar: &[u8]) -> Vec<u8> {
    gz_level(tar, 6)
}

fn lim() -> TarLimits {
    TarLimits::for_package(1 << 20)
}

type Taken = Vec<(TarEntry, Vec<u8>)>;

/// Takes every entry and reads it to the end.
fn collect(gz: &[u8], limits: &TarLimits) -> Result<Taken, TarError> {
    collect_codec(Codec::Gzip, gz, limits)
}

fn collect_codec(codec: Codec, input: &[u8], limits: &TarLimits) -> Result<Taken, TarError> {
    let mut out = Vec::new();
    walk_codec(
        codec,
        input,
        limits,
        |_| Selection::Take,
        |e, r| {
            let mut data = Vec::new();
            r.read_to_end(&mut data)?;
            out.push((e.clone(), data));
            Ok(())
        },
    )?;
    Ok(out)
}

fn run(tar: Vec<u8>) -> Result<Taken, TarError> {
    collect(&gz(&tar), &lim())
}

fn err(tar: Vec<u8>) -> TarError {
    run(tar).expect_err("must be rejected")
}

fn paths(t: &Taken) -> Vec<&str> {
    t.iter().map(|(e, _)| e.path.as_str()).collect()
}

fn is_unsafe(e: TarError) -> bool {
    matches!(e, TarError::UnsafeName(_))
}

/// Independent of `normalise`: what a path handed to a caller must look like.
fn safe(p: &str, max: usize) -> bool {
    !p.is_empty()
        && p.len() <= max
        && !p.starts_with('/')
        && p.split('/').all(|c| {
            !c.is_empty()
                && c != "."
                && c != ".."
                && !c.ends_with('.')
                && !c.ends_with(' ')
                && !c
                    .chars()
                    .any(|ch| ch.is_control() || ch == '\\' || ch == ':' || rt_core::is_format(ch))
        })
}

// ---------- happy paths ----------

#[test]
fn files_and_dirs_with_modes_and_data() {
    let tar = Tar::default()
        .raw(&edited(b"bin/", b'5', 0, |h| put_octal(&mut h[100..108], 0o755)))
        .raw(&edited(b"bin/tool.dll", b'0', 5, |h| {
            put_octal(&mut h[100..108], 0o4755)
        }))
        .data(b"hello")
        .file("bin/empty", b"")
        .end();
    let got = run(tar).unwrap();
    assert_eq!(paths(&got), ["bin", "bin/tool.dll", "bin/empty"]);
    assert_eq!(got[0].0.kind, TarEntryKind::Dir);
    assert_eq!(got[0].0.mode, 0o755);
    assert_eq!(got[1].0.kind, TarEntryKind::File);
    assert_eq!(got[1].0.mode, 0o4755);
    assert_eq!(got[1].0.size, 5);
    assert_eq!(got[1].1, b"hello");
    assert_eq!(got[2].0.size, 0);
    assert!(got[2].1.is_empty());
}

#[test]
fn nul_typeflag_is_a_regular_file() {
    let tar = Tar::default().raw(&header(b"a", 0, 1)).data(b"x").end();
    let got = run(tar).unwrap();
    assert_eq!(got[0].0.kind, TarEntryKind::File);
    assert_eq!(got[0].1, b"x");
}

#[test]
fn returns_number_of_entries_seen_including_skipped() {
    let tar = Tar::default().dir("d/").file("d/a", b"1").file("d/b", b"22").end();
    let n = walk(
        &gz(&tar)[..],
        &lim(),
        |_| Selection::Skip,
        |_, _| panic!("nothing taken"),
    )
    .unwrap();
    assert_eq!(n, 3);
}

#[test]
fn empty_archive_is_ok() {
    assert!(run(Tar::default().end()).unwrap().is_empty());
}

#[test]
fn ustar_prefix_is_joined_with_slash() {
    let tar = Tar::default()
        .raw(&edited(b"d3d11.dll", b'0', 1, |h| {
            h[345..353].copy_from_slice(b"x64/deep")
        }))
        .data(b"z")
        .end();
    assert_eq!(paths(&run(tar).unwrap()), ["x64/deep/d3d11.dll"]);
}

#[test]
fn gnu_magic_is_accepted_and_its_prefix_area_ignored() {
    let tar = Tar::default()
        .raw(&edited(b"a.dll", b'0', 1, |h| {
            h[257..265].copy_from_slice(b"ustar  \0");
            h[345..350].copy_from_slice(b"junk!"); // GNU atime/ctime area, not a prefix
        }))
        .data(b"z")
        .end();
    assert_eq!(paths(&run(tar).unwrap()), ["a.dll"]);
}

#[test]
fn gnu_long_name_applies_to_next_entry() {
    let long = format!("{}/{}.dll", "d".repeat(150), "f".repeat(80));
    let tar = Tar::default()
        .long(long.as_bytes())
        .file("truncated", b"abc")
        .file("after", b"q")
        .end();
    let got = run(tar).unwrap();
    assert_eq!(paths(&got), [long.as_str(), "after"]);
    assert_eq!(got[0].1, b"abc");
}

#[test]
fn pax_path_overrides_name_and_timestamps_are_ignored() {
    let long = format!("{}/x.dll", "p".repeat(300));
    let tar = Tar::default()
        .pax(&[
            ("mtime", b"1700000000.5"),
            ("path", long.as_bytes()),
            ("atime", b"1"),
            ("ctime", b"2"),
        ])
        .file("short", b"data")
        .file("plain", b"")
        .end();
    let got = run(tar).unwrap();
    assert_eq!(paths(&got), [long.as_str(), "plain"]);
    assert_eq!(got[0].1, b"data");
}

#[test]
fn pax_header_without_path_keeps_ustar_name() {
    let tar = Tar::default().pax(&[("mtime", b"5")]).file("name", b"").end();
    assert_eq!(paths(&run(tar).unwrap()), ["name"]);
}

#[test]
fn one_leading_dot_slash_is_stripped() {
    let tar = Tar::default().dir("./").dir("./a/").file("./a/b", b"1").end();
    let got = run(tar).unwrap();
    // `./` (the archive root, as `tar -C dir .` writes it) is counted but not reported.
    assert_eq!(paths(&got), ["a", "a/b"]);
    let n = walk(
        &gz(&Tar::default().dir("./").dir(".").end())[..],
        &lim(),
        |_| panic!(),
        |_, _| panic!(),
    )
    .unwrap();
    assert_eq!(n, 2);
}

#[test]
fn directory_without_trailing_slash_is_accepted() {
    assert_eq!(paths(&run(Tar::default().dir("a").end()).unwrap()), ["a"]);
}

#[test]
fn signed_checksum_variant_is_accepted() {
    let name = "é/ü.dll"; // bytes >= 0x80 make the signed and unsigned sums differ
    let mut h = header(name.as_bytes(), b'0', 0);
    h[148..156].fill(b' ');
    let signed: i64 = h.iter().map(|&b| i64::from(b as i8)).sum();
    h[148..156].copy_from_slice(format!("{signed:06o}\0 ").as_bytes());
    let tar = Tar::default().raw(&h).end();
    assert_eq!(paths(&run(tar).unwrap()), [name]);
}

#[test]
fn leading_spaces_in_numbers_are_accepted() {
    let tar = Tar::default()
        .raw(&edited(b"a", b'0', 0, |h| {
            h[124..136].copy_from_slice(b"         3 \0")
        }))
        .data(b"abc")
        .end();
    assert_eq!(run(tar).unwrap()[0].1, b"abc");
}

#[test]
fn duplicates_are_reported_each_time() {
    let tar = Tar::default().file("a", b"1").file("a", b"2").end();
    let got = run(tar).unwrap();
    assert_eq!(paths(&got), ["a", "a"]);
    assert_eq!((got[0].1.as_slice(), got[1].1.as_slice()), (&b"1"[..], &b"2"[..]));
}

#[test]
fn trailing_zero_padding_within_allowance_is_ok() {
    let mut tar = Tar::default().file("a", b"1").end();
    tar.extend(vec![0u8; lim().trailing_allowance]);
    assert_eq!(run(tar).unwrap().len(), 1);
}

#[test]
fn multiple_members_are_accepted_up_to_the_cap() {
    let tar = Tar::default().file("a", &[7u8; 700]).file("b", b"x").end();
    let (one, two) = tar.split_at(600); // the split falls inside `a`'s data
    let mut input = gz(one);
    input.extend(gz(two));
    let l = TarLimits {
        max_gzip_members: 2,
        ..lim()
    };
    let got = collect(&input, &l).unwrap();
    assert_eq!(paths(&got), ["a", "b"]);
    assert_eq!(got[0].1, vec![7u8; 700]);
    let (one, rest) = tar.split_at(600);
    let (two, three) = rest.split_at(600);
    let mut input = gz(one);
    input.extend(gz(two));
    input.extend(gz(three));
    assert!(matches!(collect(&input, &l), Err(TarError::TooManyMembers)));
}

// ---------- selection and the sink reader ----------

#[test]
fn only_taken_entries_reach_the_sink() {
    let tar = Tar::default().file("a", b"AAAA").file("b", b"BB").file("c", b"C").end();
    let mut seen = Vec::new();
    let mut taken = Vec::new();
    walk(
        &gz(&tar)[..],
        &lim(),
        |e| {
            seen.push(e.path.clone());
            if e.path == "b" {
                Selection::Take
            } else {
                Selection::Skip
            }
        },
        |e, r| {
            let mut d = Vec::new();
            r.read_to_end(&mut d)?;
            taken.push((e.path.clone(), d));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(seen, ["a", "b", "c"]);
    assert_eq!(taken, [("b".to_string(), b"BB".to_vec())]);
}

#[test]
fn sink_reader_is_limited_to_exactly_size_bytes() {
    let tar = Tar::default().file("a", &[1u8; 1000]).file("b", b"next").end();
    let mut lens = Vec::new();
    walk(
        &gz(&tar)[..],
        &lim(),
        |_| Selection::Take,
        |_, r| {
            let mut big = vec![0u8; 1 << 16];
            let mut got = 0;
            loop {
                let n = r.read(&mut big)?;
                if n == 0 {
                    break;
                }
                got += n;
            }
            assert_eq!(r.read(&mut big)?, 0, "EOF is sticky");
            lens.push(got);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(lens, [1000, 4]);
}

#[test]
fn sink_that_reads_less_leaves_the_stream_positioned() {
    let tar = Tar::default().file("a", &[1u8; 5000]).file("b", b"second").end();
    let mut out = Vec::new();
    walk(
        &gz(&tar)[..],
        &lim(),
        |_| Selection::Take,
        |e, r| {
            let mut one = [0u8; 1];
            if e.path == "a" {
                r.read_exact(&mut one)?;
                out.push(one.to_vec());
            } else {
                let mut d = Vec::new();
                r.read_to_end(&mut d)?;
                out.push(d);
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(out, [vec![1u8], b"second".to_vec()]);
}

#[test]
fn callback_error_propagates_and_stops_the_walk() {
    let tar = Tar::default().file("a", b"1").file("b", b"2").end();
    let mut seen = 0;
    let e = walk(
        &gz(&tar)[..],
        &lim(),
        |_| {
            seen += 1;
            Selection::Take
        },
        |_, _| Err(TarError::Callback("disk full".into())),
    )
    .unwrap_err();
    assert!(
        matches!(e, TarError::Callback(ref m) if m.to_string() == "disk full"),
        "{e:?}"
    );
    assert_eq!(seen, 1);
}

#[test]
fn truncation_under_the_sink_is_reported_as_truncated_not_as_the_sinks_error() {
    let tar = Tar::default().file("a", &[3u8; 4000]).end();
    let input = gz(&tar[..1500]);
    let e = walk(
        &input[..],
        &lim(),
        |_| Selection::Take,
        |_, r| {
            let mut d = Vec::new();
            r.read_to_end(&mut d).map_err(|e| TarError::Callback(e.into()))?;
            Ok(())
        },
    )
    .unwrap_err();
    assert!(matches!(e, TarError::Truncated), "{e:?}");
}

#[test]
fn gzip_error_under_the_sink_wins_over_the_sinks_error() {
    let tar = Tar::default().file("a", &[3u8; 4000]).end();
    let mut input = gz(&tar);
    let n = input.len();
    input[n - 6] ^= 0xff; // CRC
    let e = walk(
        &input[..],
        &lim(),
        |_| Selection::Take,
        |_, r| {
            let mut d = Vec::new();
            r.read_to_end(&mut d).map_err(|e| TarError::Callback(e.into()))?;
            // the entry's own data is intact; the CRC is only checked at the end of the member
            Ok(())
        },
    )
    .unwrap_err();
    assert!(matches!(e, TarError::Gzip(_)), "{e:?}");
}

// ---------- entry type rejections ----------

fn rejects_type(t: u8) {
    let tar = Tar::default().raw(&header(b"x", t, 0)).end();
    let e = err(tar);
    assert!(
        matches!(e, TarError::UnsupportedEntry(_)),
        "type {:?}: {e:?}",
        t as char
    );
}

#[test]
fn hardlink_rejected() {
    rejects_type(b'1');
}
#[test]
fn symlink_rejected() {
    rejects_type(b'2');
}
#[test]
fn char_device_rejected() {
    rejects_type(b'3');
}
#[test]
fn block_device_rejected() {
    rejects_type(b'4');
}
#[test]
fn fifo_rejected() {
    rejects_type(b'6');
}
#[test]
fn contiguous_rejected() {
    rejects_type(b'7');
}
#[test]
fn gnu_sparse_rejected() {
    rejects_type(b'S');
}
#[test]
fn multi_volume_rejected() {
    rejects_type(b'M');
}
#[test]
fn gnu_long_link_rejected() {
    rejects_type(b'K');
}
#[test]
fn pax_global_header_rejected() {
    rejects_type(b'g');
}
#[test]
fn unknown_typeflag_rejected() {
    for t in [b'A', b'Z', b'N', b'D', b'V', 0xff, b'8', b'9'] {
        rejects_type(t);
    }
}

// ---------- extended header rejections ----------

#[test]
fn pax_key_other_than_path_and_timestamps_rejected() {
    for k in [
        "linkpath",
        "size",
        "uname",
        "SCHILY.xattr.x",
        "GNU.sparse.name",
        "hdrcharset",
    ] {
        let e = err(Tar::default().pax(&[(k, b"v")]).file("a", b"").end());
        assert!(matches!(e, TarError::UnsupportedEntry(_)), "{k}: {e:?}");
    }
}

#[test]
fn pax_duplicate_path_rejected() {
    let e = err(Tar::default()
        .pax(&[("path", b"a"), ("path", b"b")])
        .file("x", b"")
        .end());
    assert!(matches!(e, TarError::BadHeader(_)), "{e:?}");
}

#[test]
fn pax_malformed_records_rejected() {
    for payload in [
        &b"99 path=a\n"[..], // length past the end
        b"x path=a\n",       // non-decimal length
        b"9 patha\n\n",      // no '='
        b"10 path=ab",       // no newline
        b"4 a\n",            // length shorter than "len "
        b"12path=abc\n",     // no space
        b"0 ",
        b"+11 path=a\n", // sign in the length
    ] {
        let tar = Tar::default()
            .raw(&header(b"p", b'x', payload.len() as u64))
            .data(payload)
            .file("a", b"")
            .end();
        let e = err(tar);
        assert!(
            matches!(e, TarError::BadHeader(_)),
            "{:?}: {e:?}",
            String::from_utf8_lossy(payload)
        );
    }
}

#[test]
fn pax_header_over_its_cap_is_name_too_long() {
    let l = lim();
    let big = "a".repeat(l.max_name_len + 600);
    let e = err(Tar::default().pax(&[("path", big.as_bytes())]).file("a", b"").end());
    assert!(matches!(e, TarError::NameTooLong), "{e:?}");
}

#[test]
fn pax_path_over_name_cap_is_name_too_long() {
    let big = "a".repeat(lim().max_name_len + 1);
    let e = err(Tar::default().pax(&[("path", big.as_bytes())]).file("a", b"").end());
    assert!(matches!(e, TarError::NameTooLong), "{e:?}");
}

#[test]
fn gnu_long_name_over_cap_is_name_too_long() {
    let big = "a".repeat(lim().max_name_len + 1);
    let e = err(Tar::default().long(big.as_bytes()).file("a", b"").end());
    assert!(matches!(e, TarError::NameTooLong), "{e:?}");
}

#[test]
fn gnu_long_name_payload_over_cap_rejected_even_if_the_name_is_short() {
    // the cap bounds the memory read, not just the name: "a" followed by NUL filler
    let mut payload = b"a".to_vec();
    payload.resize(lim().max_name_len + 2, 0);
    let tar = Tar::default()
        .raw(&header(b"././@LongLink", b'L', payload.len() as u64))
        .data(&payload)
        .file("x", b"")
        .end();
    assert!(matches!(err(tar), TarError::NameTooLong));
}

#[test]
fn pax_payload_over_cap_rejected_even_if_the_path_is_short() {
    let mtime = "1".repeat(lim().max_name_len + 600);
    let tar = Tar::default()
        .pax(&[("path", b"a"), ("mtime", mtime.as_bytes())])
        .file("x", b"")
        .end();
    assert!(matches!(err(tar), TarError::NameTooLong));
}

#[test]
fn truncated_extended_payload_is_truncated() {
    let rec = pax_record("path", b"abc");
    // 400 has padding (whose discard also hits the end); 512 has none, so only the payload check catches it
    for declared in [400, 512] {
        let mut tar = Tar::default().raw(&header(b"p", b'x', declared)).0;
        tar.extend_from_slice(&rec);
        let e = err(tar);
        assert!(matches!(e, TarError::Truncated), "{declared}: {e:?}");
    }
}

#[test]
fn consecutive_extended_headers_rejected() {
    for tar in [
        Tar::default().long(b"a").long(b"b").file("x", b"").end(),
        Tar::default().pax(&[("path", b"a")]).long(b"b").file("x", b"").end(),
        Tar::default()
            .pax(&[("mtime", b"1")])
            .pax(&[("mtime", b"1")])
            .file("x", b"")
            .end(),
    ] {
        assert!(matches!(err(tar), TarError::BadHeader(_)));
    }
}

#[test]
fn extended_header_without_entry_rejected() {
    let e = err(Tar::default().long(b"dangling").end());
    assert!(matches!(e, TarError::BadHeader(_)), "{e:?}");
}

// ---------- name rejections ----------

fn rejects_name(name: &str) {
    for tar in [
        Tar::default().file(name, b"").end(),
        Tar::default().pax(&[("path", name.as_bytes())]).file("ok", b"").end(),
    ] {
        let e = err(tar);
        assert!(is_unsafe(e), "{name:?}");
    }
}

#[test]
fn absolute_name_rejected() {
    rejects_name("/etc/passwd");
    rejects_name("./../a"); // ONE ./ is stripped, then `..`
}
#[test]
fn dotdot_component_rejected() {
    rejects_name("..");
    rejects_name("../a");
    rejects_name("a/../../b");
    rejects_name("a/..");
}
#[test]
fn empty_name_rejected() {
    rejects_name("");
    assert!(is_unsafe(err(Tar::default().dir("").end())));
}
#[test]
fn empty_component_rejected() {
    rejects_name("a//b");
    rejects_name("a/");
    assert!(is_unsafe(err(Tar::default().dir("a//").end())));
}
#[test]
fn dot_component_rejected() {
    rejects_name("a/./b");
    rejects_name("a/.");
    rejects_name(".");
    rejects_name("./");
}
#[test]
fn double_dot_slash_prefix_rejected() {
    rejects_name("././a");
    assert!(is_unsafe(err(Tar::default().dir("././").end())));
}
#[test]
fn backslash_rejected() {
    rejects_name("a\\b");
    rejects_name("..\\x");
}
#[test]
fn control_chars_rejected() {
    rejects_name("a\nb");
    rejects_name("a\u{7f}");
    rejects_name("a\u{85}");
    rejects_name("\u{1b}[31m");
}
#[test]
fn nul_in_pax_path_rejected() {
    let e = err(Tar::default().pax(&[("path", b"a\0b")]).file("ok", b"").end());
    assert!(is_unsafe(e));
}
#[test]
fn format_chars_rejected() {
    rejects_name("evil\u{202e}lld.exe");
    rejects_name("a\u{200b}b");
}
#[test]
fn drive_letter_and_colon_rejected() {
    rejects_name("C:");
    rejects_name("c:/windows/x.dll");
    rejects_name("a/b:stream");
}
#[test]
fn trailing_dot_or_space_component_rejected() {
    rejects_name("a./b");
    rejects_name("a/b.");
    rejects_name("a /b");
    rejects_name("a/b ");
}
#[test]
fn file_with_trailing_slash_rejected() {
    assert!(is_unsafe(err(Tar::default().file("a/", b"").end())));
}
#[test]
fn non_utf8_name_rejected() {
    let tar = Tar::default().raw(&header(b"a\xff\xfe", b'0', 0)).end();
    assert!(is_unsafe(err(tar)));
    let tar = Tar::default().long(b"b\xc3").file("x", b"").end();
    assert!(is_unsafe(err(tar)));
}
#[test]
fn ustar_name_over_cap_is_name_too_long() {
    let l = TarLimits {
        max_name_len: 10,
        ..lim()
    };
    let tar = Tar::default().file("abcdefghijk", b"").end();
    assert!(matches!(collect(&gz(&tar), &l), Err(TarError::NameTooLong)));
    let tar = Tar::default().file("abcdefghij", b"").end();
    assert!(collect(&gz(&tar), &l).is_ok());
}
#[test]
fn unsafe_name_error_is_clipped_and_escaped() {
    let name = format!("/{}\u{1b}", "x".repeat(500));
    let e = err(Tar::default().pax(&[("path", name.as_bytes())]).file("ok", b"").end());
    let TarError::UnsafeName(shown) = e else {
        panic!("{e:?}")
    };
    assert!(shown.len() < 120, "{shown}");
    assert!(!shown.chars().any(char::is_control));
}

// ---------- numeric field and header rejections ----------

#[test]
fn base256_size_rejected() {
    let tar = Tar::default()
        .raw(&edited(b"a", b'0', 0, |h| {
            h[124..136].fill(0);
            h[124] = 0x80;
            h[135] = 1;
        }))
        .data(b"x")
        .end();
    assert!(matches!(err(tar), TarError::BadHeader(_)));
    let neg = Tar::default()
        .raw(&edited(b"a", b'0', 0, |h| h[124..136].fill(0xff)))
        .end();
    assert!(matches!(err(neg), TarError::BadHeader(_)));
}
#[test]
fn non_octal_digit_rejected() {
    let tar = Tar::default()
        .raw(&edited(b"a", b'0', 0, |h| {
            h[124..136].copy_from_slice(b"0000000008\0\0")
        }))
        .end();
    assert!(matches!(err(tar), TarError::BadHeader(_)));
    let tar = Tar::default()
        .raw(&edited(b"a", b'0', 0, |h| {
            h[124..136].copy_from_slice(b"-0000000001\0")
        }))
        .end();
    assert!(matches!(err(tar), TarError::BadHeader(_)));
}
#[test]
fn garbage_after_digits_rejected() {
    let tar = Tar::default()
        .raw(&edited(b"a", b'0', 0, |h| h[124..136].copy_from_slice(b"00000000000x")))
        .end();
    assert!(matches!(err(tar), TarError::BadHeader(_)));
}
#[test]
fn empty_size_field_rejected() {
    let tar = Tar::default()
        .raw(&edited(b"a", b'0', 0, |h| h[124..136].fill(0)))
        .end();
    assert!(matches!(err(tar), TarError::BadHeader(_)));
}
#[test]
fn bad_mode_field_rejected() {
    let tar = Tar::default()
        .raw(&edited(b"a", b'0', 0, |h| h[100..108].copy_from_slice(b"07x5\0\0\0\0")))
        .end();
    assert!(matches!(err(tar), TarError::BadHeader(_)));
}
#[test]
fn twelve_digit_size_without_terminator_is_parsed_and_capped() {
    let tar = Tar::default()
        .raw(&edited(b"a", b'0', 0, |h| h[124..136].copy_from_slice(b"777777777777")))
        .end();
    assert!(matches!(err(tar), TarError::EntryTooLarge));
}
#[test]
fn entry_over_max_entry_bytes_rejected() {
    let l = TarLimits {
        max_entry_bytes: 100,
        ..lim()
    };
    let tar = Tar::default().file("a", &[0u8; 101]).end();
    assert!(matches!(collect(&gz(&tar), &l), Err(TarError::EntryTooLarge)));
    let tar = Tar::default().file("a", &[0u8; 100]).end();
    assert!(collect(&gz(&tar), &l).is_ok());
}
#[test]
fn directory_with_size_rejected() {
    let tar = Tar::default().raw(&header(b"d/", b'5', 1)).data(b"x").end();
    assert!(matches!(err(tar), TarError::BadHeader(_)));
}
#[test]
fn checksum_mismatch_rejected() {
    let mut h = header(b"a", b'0', 0);
    h[0] = b'b'; // not resealed
    assert!(matches!(err(Tar::default().raw(&h).end()), TarError::BadChecksum));
    let mut h = header(b"a", b'0', 0);
    h[148..156].copy_from_slice(b"zzzzzz\0 ");
    assert!(matches!(err(Tar::default().raw(&h).end()), TarError::BadChecksum));
}
#[test]
fn non_ustar_magic_rejected() {
    let v7 = edited(b"a", b'0', 0, |h| h[257..265].fill(0));
    assert!(matches!(err(Tar::default().raw(&v7).end()), TarError::BadHeader(_)));
    let odd = edited(b"a", b'0', 0, |h| h[263..265].copy_from_slice(b"01"));
    assert!(matches!(err(Tar::default().raw(&odd).end()), TarError::BadHeader(_)));
}
#[test]
fn too_many_entries_counts_skipped_ones() {
    let l = TarLimits {
        max_entries: 2,
        ..lim()
    };
    let tar = Tar::default().file("a", b"").file("b", b"").file("c", b"").end();
    let r = walk(&gz(&tar)[..], &l, |_| Selection::Skip, |_, _| Ok(()));
    assert!(matches!(r, Err(TarError::TooManyEntries)), "{r:?}");
    let tar = Tar::default().file("a", b"").file("b", b"").end();
    assert_eq!(walk(&gz(&tar)[..], &l, |_| Selection::Skip, |_, _| Ok(())).unwrap(), 2);
}

// ---------- structure: end blocks, truncation, trailing data ----------

#[test]
fn single_zero_block_only_is_truncated() {
    assert!(matches!(err(vec![0u8; 512]), TarError::Truncated));
}
#[test]
fn empty_input_tar_is_truncated() {
    assert!(matches!(err(Vec::new()), TarError::Truncated));
}
#[test]
fn missing_end_blocks_is_truncated() {
    let mut tar = Tar::default().file("a", b"1").end();
    tar.truncate(tar.len() - 1024);
    assert!(matches!(err(tar), TarError::Truncated));
}
#[test]
fn lone_zero_block_between_headers_rejected() {
    let tar = Tar::default().file("a", b"1").raw(&[0u8; 512]).file("b", b"2").end();
    assert!(matches!(err(tar), TarError::BadHeader(_)));
}
#[test]
fn partial_header_block_is_truncated() {
    let mut tar = Tar::default().file("a", b"1").0;
    tar.extend_from_slice(&header(b"b", b'0', 0)[..100]);
    assert!(matches!(err(tar), TarError::Truncated));
}
#[test]
fn declared_size_past_the_end_is_truncated() {
    let tar = Tar::default().raw(&header(b"a", b'0', 5000)).data(b"short").end();
    assert!(matches!(err(tar), TarError::Truncated));
}
#[test]
fn size_lie_shorter_data_misparses_as_truncated_or_header_error() {
    // header claims 600 bytes, only 5 present before the next header: the next header is eaten as data
    let tar = Tar::default()
        .raw(&header(b"a", b'0', 600))
        .data(b"short")
        .file("b", b"x")
        .end();
    let e = err(tar);
    assert!(
        matches!(e, TarError::Truncated | TarError::BadChecksum | TarError::BadHeader(_)),
        "{e:?}"
    );
}
#[test]
fn size_lie_longer_data_is_a_checksum_error() {
    let tar = Tar::default().raw(&header(b"a", b'0', 5)).data(&[b'A'; 600]).end();
    assert!(matches!(err(tar), TarError::BadChecksum));
}
#[test]
fn trailing_zero_padding_beyond_allowance_rejected() {
    let mut tar = Tar::default().file("a", b"1").end();
    tar.extend(vec![0u8; lim().trailing_allowance + 1]);
    assert!(matches!(err(tar), TarError::TrailingGarbage));
}
#[test]
fn nonzero_data_after_end_rejected() {
    let mut tar = Tar::default().file("a", b"1").end();
    tar.push(1);
    assert!(matches!(err(tar), TarError::TrailingGarbage));
    let tar = Tar::default().file("a", b"1").end();
    let mut tar2 = tar.clone();
    tar2.extend(Tar::default().file("b", b"2").end()); // `tar -A` style concatenation
    assert!(matches!(err(tar2), TarError::TrailingGarbage));
}
#[test]
fn bytes_after_the_gzip_member_rejected() {
    let mut input = gz(&Tar::default().file("a", b"1").end());
    input.extend_from_slice(b"junk");
    assert!(matches!(collect(&input, &lim()), Err(TarError::TrailingGarbage)));
    let mut input = gz(&Tar::default().file("a", b"1").end());
    input.push(0);
    assert!(matches!(collect(&input, &lim()), Err(TarError::TrailingGarbage)));
}
#[test]
fn concatenated_gzip_members_over_cap_rejected() {
    let tar = Tar::default().file("a", b"1").end();
    let (one, two) = tar.split_at(512);
    let mut input = gz(one);
    input.extend(gz(two));
    assert!(matches!(collect(&input, &lim()), Err(TarError::TooManyMembers)));
    // a whole second member after a complete archive, even an empty one
    let mut input = gz(&tar);
    input.extend(gz(b""));
    assert!(matches!(collect(&input, &lim()), Err(TarError::TooManyMembers)));
}
#[test]
fn garbage_in_place_of_a_second_member_is_a_gzip_error() {
    let tar = Tar::default().file("a", b"1").end();
    let (one, _) = tar.split_at(512);
    let mut input = gz(one);
    input.extend_from_slice(b"not gzip at all");
    let l = TarLimits {
        max_gzip_members: 2,
        ..lim()
    };
    assert!(matches!(collect(&input, &l), Err(TarError::Gzip(_))));
}

// ---------- gzip layer ----------

fn small_archive() -> Vec<u8> {
    gz(&Tar::default()
        .dir("d/")
        .file("d/a.dll", b"hello world")
        .file("b", &[9u8; 700])
        .end())
}

#[test]
fn corrupted_crc_is_gzip_error() {
    let mut input = small_archive();
    let n = input.len();
    input[n - 8] ^= 1;
    assert!(matches!(collect(&input, &lim()), Err(TarError::Gzip(_))));
}
#[test]
fn corrupted_isize_is_gzip_error() {
    let mut input = small_archive();
    let n = input.len();
    input[n - 1] ^= 1;
    assert!(matches!(collect(&input, &lim()), Err(TarError::Gzip(_))));
}
#[test]
fn truncated_gzip_trailer_or_body_is_truncated() {
    let input = small_archive();
    for cut in [1, 4, 8, input.len() / 2] {
        let e = collect(&input[..input.len() - cut], &lim()).unwrap_err();
        assert!(matches!(e, TarError::Truncated), "cut {cut}: {e:?}");
    }
}

#[test]
fn not_gzip_is_gzip_error() {
    let tar = Tar::default().file("a", b"1").end();
    let e = collect(&tar, &lim()).unwrap_err();
    assert!(matches!(e, TarError::Gzip(_)), "{e:?}");
}
#[test]
fn truncated_gzip_at_every_prefix_never_panics() {
    let input = small_archive();
    for n in 0..input.len() {
        let r = collect(&input[..n], &lim());
        let e = r.expect_err("a strict prefix must fail");
        assert!(
            matches!(e, TarError::Truncated | TarError::Gzip(_)),
            "prefix {n}/{}: {e:?}",
            input.len()
        );
    }
    assert_eq!(collect(&input, &lim()).unwrap().len(), 3);
}
#[test]
fn source_io_error_is_io() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }
    let e = walk(Broken, &lim(), |_| Selection::Take, |_, _| Ok(())).unwrap_err();
    assert!(
        matches!(e, TarError::Io(ref i) if i.kind() == io::ErrorKind::PermissionDenied),
        "{e:?}"
    );
}
#[test]
fn compressed_input_over_cap_rejected() {
    let input = small_archive();
    let l = TarLimits {
        max_compressed_bytes: input.len() as u64 - 1,
        ..lim()
    };
    assert!(matches!(collect(&input, &l), Err(TarError::CompressedTooLarge)));
    let l = TarLimits {
        max_compressed_bytes: input.len() as u64,
        ..lim()
    };
    assert!(collect(&input, &l).is_ok());
}

/// Streams `n` zero bytes as one tar file entry into a gzip member without holding them in memory.
fn zero_entry_gz(n: u64, name: &str) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::new(1));
    e.write_all(&header(name.as_bytes(), b'0', n)).unwrap();
    let chunk = vec![0u8; 1 << 20];
    let mut left = n;
    while left > 0 {
        let k = left.min(chunk.len() as u64) as usize;
        e.write_all(&chunk[..k]).unwrap();
        left -= k as u64;
    }
    let mut tail = vec![0u8; (512 - (n % 512) as usize) % 512];
    tail.extend_from_slice(&[0u8; 1024]);
    e.write_all(&tail).unwrap();
    e.finish().unwrap()
}

fn walk_counting(codec: Codec, input: &[u8], l: &TarLimits, sel: Selection) -> (Result<u64, TarError>, u64) {
    let mut s = Stream::new(codec, input, l);
    // a sink with a huge buffer: the reader must still hand out at most one chunk per read
    let mut big = vec![0u8; 8 << 20];
    let r = walk_stream(
        &mut s,
        l,
        &mut |_: &TarEntry| sel,
        &mut |_: &TarEntry, r: &mut dyn Read| {
            while r.read(&mut big)? > 0 {}
            Ok(())
        },
    );
    (r, s.total)
}

#[test]
fn gzip_bomb_aborts_at_total_cap_with_bounded_work() {
    let input = zero_entry_gz(64 << 20, "bomb");
    let cap = 1 << 20;
    let l = TarLimits {
        max_total_bytes: cap,
        max_ratio: u64::MAX,
        max_entry_bytes: 1 << 30,
        max_compressed_bytes: 1 << 30,
        ..lim()
    };
    for sel in [Selection::Take, Selection::Skip] {
        let (r, total) = walk_counting(Codec::Gzip, &input, &l, sel);
        assert!(matches!(r, Err(TarError::TooLarge)), "{r:?}");
        assert!(total <= cap + CHUNK as u64, "read {total} decompressed bytes");
    }
}

#[test]
fn ratio_guard_trips_after_the_floor() {
    let input = zero_entry_gz(16 << 20, "bomb");
    let l = TarLimits {
        max_total_bytes: 1 << 30,
        max_entry_bytes: 1 << 30,
        max_compressed_bytes: 1 << 30,
        ..lim()
    };
    let (r, total) = walk_counting(Codec::Gzip, &input, &l, Selection::Skip);
    assert!(matches!(r, Err(TarError::RatioExceeded)), "{r:?}");
    assert!(total > l.ratio_floor);
    assert!(total < 4 << 20, "tripped late: {total}");
    // the same stream passes with the ratio guard relaxed
    let relaxed = TarLimits {
        max_ratio: 100_000,
        ..l
    };
    assert!(walk_counting(Codec::Gzip, &input, &relaxed, Selection::Skip).0.is_ok());
}

#[test]
fn ratio_guard_does_not_apply_below_the_floor() {
    // 900 KiB of zeros compresses ~1000:1 but stays under the 1 MiB floor
    let input = zero_entry_gz(900 << 10, "z");
    assert!(collect(&input, &TarLimits::for_package(input.len() as u64)).is_ok());
}

#[test]
fn skip_streams_a_large_entry_without_buffering() {
    let size: u64 = 48 << 20;
    let input = zero_entry_gz(size, "big");
    let l = TarLimits {
        max_entry_bytes: size,
        max_total_bytes: size + 4096,
        max_ratio: u64::MAX,
        max_compressed_bytes: input.len() as u64,
        ..lim()
    };
    let t = std::time::Instant::now();
    let mut s = Stream::new(Codec::Gzip, &input[..], &l);
    let mut seen = Vec::new();
    let r = walk_stream(
        &mut s,
        &l,
        &mut |e: &TarEntry| {
            seen.push((e.path.clone(), e.size));
            Selection::Skip
        },
        &mut |_: &TarEntry, _: &mut dyn Read| panic!("skipped entries never reach the sink"),
    );
    assert_eq!(r.unwrap(), 1);
    assert_eq!(seen, [("big".to_string(), size)]);
    assert_eq!(s.total, 512 + size + 1024);
    assert!(t.elapsed().as_secs() < 20);
}

// ---------- zstd ----------

fn zst(tar: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(tar, ruzstd::encoding::CompressionLevel::Fastest)
}

fn collect_zst(input: &[u8], limits: &TarLimits) -> Result<Taken, TarError> {
    collect_codec(Codec::Zstd, input, limits)
}

/// A hand-made zstd frame header: no single segment, no checksum, no dictionary, window descriptor `wd`
/// (`window = (1 << (10 + (wd >> 3))) * (8 + (wd & 7)) / 8`).
fn zst_header(wd: u8) -> Vec<u8> {
    vec![0x28, 0xB5, 0x2F, 0xFD, 0x00, wd]
}

/// A zstd block: `typ` 0 is raw (`body` is the data), 1 is RLE (`body` is the one byte repeated `size` times).
fn zst_block(last: bool, typ: u32, size: u32, body: &[u8]) -> Vec<u8> {
    let h = (size << 3) | (typ << 1) | u32::from(last);
    [&h.to_le_bytes()[..3], body].concat()
}

/// A tar holding one `n`-byte file of zeros, as one zstd frame (1 MiB window) of RLE blocks, built without holding
/// the zeros: 512 MiB takes about 16 KiB.
fn zero_entry_zst(n: u64, name: &str) -> Vec<u8> {
    let mut f = zst_header(0x50);
    f.extend(zst_block(false, 0, 512, &header(name.as_bytes(), b'0', n)));
    let mut left = n + padding(n) + 1024;
    while left > 0 {
        let k = left.min(128 << 10);
        left -= k;
        f.extend(zst_block(left == 0, 1, k as u32, &[0]));
    }
    f
}

fn two_files() -> Vec<u8> {
    Tar::default()
        .dir("d/")
        .file("d/a.dll", b"hello")
        .file("b.bin", &(0..3000u32).map(|i| (i * 7) as u8).collect::<Vec<_>>())
        .end()
}

#[test]
fn zstd_archive_is_read_byte_exact() {
    let tar = two_files();
    let got = collect_zst(&zst(&tar), &lim()).unwrap();
    assert_eq!(paths(&got), ["d", "d/a.dll", "b.bin"]);
    assert_eq!(got[1].1, b"hello");
    assert_eq!(got[2].1, (0..3000u32).map(|i| (i * 7) as u8).collect::<Vec<_>>());
    // gzip input is not zstd
    assert!(matches!(collect_zst(&gz(&tar), &lim()), Err(TarError::Zstd(_))));
}

#[test]
fn zstd_bomb_aborts_at_total_cap_with_bounded_work() {
    let input = zero_entry_zst(512 << 20, "bomb");
    assert!(input.len() < 20 << 10, "{}", input.len());
    let cap = 4 << 20;
    let l = TarLimits {
        max_total_bytes: cap,
        max_entry_bytes: 1 << 30,
        ..lim()
    };
    for sel in [Selection::Take, Selection::Skip] {
        let (r, total) = walk_counting(Codec::Zstd, &input, &l, sel);
        assert!(matches!(r, Err(TarError::TooLarge | TarError::RatioExceeded)), "{r:?}");
        assert!(total <= cap + CHUNK as u64, "read {total} decompressed bytes");
    }
    // with the total cap out of the way, the ratio guard trips right after its floor
    let l = TarLimits {
        max_total_bytes: 1 << 30,
        ..l
    };
    let (r, total) = walk_counting(Codec::Zstd, &input, &l, Selection::Skip);
    assert!(matches!(r, Err(TarError::RatioExceeded)), "{r:?}");
    assert!(total < l.ratio_floor + 2 * CHUNK as u64, "tripped late: {total}");
}

#[test]
fn zstd_window_over_the_cap_is_refused_before_allocating() {
    let tar = Tar::default().file("a", b"x").end();
    let frame = |wd: u8| [zst_header(wd), zst_block(true, 0, tar.len() as u32, &tar)].concat();
    let l = TarLimits {
        max_zstd_window: 64 << 20,
        ..lim()
    };
    // exactly the cap (exponent 16) is fine
    assert_eq!(paths(&collect_zst(&frame(16 << 3), &l).unwrap()), ["a"]);
    // 64 MiB + 1/8 and 1 GiB are refused
    let t = std::time::Instant::now();
    for wd in [(16 << 3) | 1, 20 << 3] {
        let r = collect_zst(&frame(wd), &l);
        assert!(matches!(r, Err(TarError::Zstd(_))), "{wd:#x}: {r:?}");
    }
    assert!(t.elapsed().as_secs() < 1);
    // the cap is a TarLimits field, not a constant
    let small = TarLimits {
        max_zstd_window: 1 << 20,
        ..lim()
    };
    assert!(matches!(collect_zst(&frame(16 << 3), &small), Err(TarError::Zstd(_))));
}

#[test]
fn zstd_truncated_anywhere_is_truncated() {
    let input = zst(&two_files());
    for cut in 0..input.len() {
        let r = collect_zst(&input[..cut], &lim());
        assert!(matches!(r, Err(TarError::Truncated)), "cut at {cut}: {r:?}");
    }
}

#[test]
fn zstd_trailing_garbage_rejected() {
    let mut input = zst(&two_files());
    input.extend((0..100u8).map(|i| i.wrapping_mul(37) | 1));
    assert!(matches!(collect_zst(&input, &lim()), Err(TarError::TrailingGarbage)));
}

#[test]
fn zstd_second_frame_rejected() {
    let tar = two_files();
    // split inside the tar and at its very end: the second frame is refused either way
    for at in [1024, tar.len()] {
        let input = [zst(&tar[..at]), zst(&tar[at..])].concat();
        let r = collect_zst(&input, &lim());
        assert!(matches!(r, Err(TarError::TooManyFrames)), "{at}: {r:?}");
    }
}

#[test]
fn zstd_skippable_frame_rejected() {
    let mut input = vec![0x50, 0x2A, 0x4D, 0x18, 4, 0, 0, 0, 1, 2, 3, 4];
    input.extend(zst(&two_files()));
    assert!(matches!(collect_zst(&input, &lim()), Err(TarError::Zstd(_))));
}

#[test]
fn zstd_compressed_input_over_cap_rejected() {
    let input = zst(&two_files());
    let l = TarLimits {
        max_compressed_bytes: input.len() as u64 - 1,
        ..lim()
    };
    assert!(matches!(collect_zst(&input, &l), Err(TarError::CompressedTooLarge)));
    let l = TarLimits {
        max_compressed_bytes: input.len() as u64,
        ..lim()
    };
    assert!(collect_zst(&input, &l).is_ok());
}

#[test]
fn zstd_source_io_error_is_io() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "nope"))
        }
    }
    let r = walk_codec(Codec::Zstd, Failing, &lim(), |_| Selection::Take, |_, _| Ok(()));
    assert!(
        matches!(&r, Err(TarError::Io(e)) if e.kind() == io::ErrorKind::PermissionDenied),
        "{r:?}"
    );
}

#[test]
fn zstd_error_under_the_sink_wins_even_if_the_sink_keeps_reading() {
    // 512-byte raw blocks in a 1 KiB window, cut inside b.bin's data: the decoder fails while the sink reads it
    let mut input = zst_header(0);
    for b in two_files().chunks(512) {
        input.extend(zst_block(false, 0, 512, b));
    }
    let cut = &input[..6 + 8 * 515 + 100];
    let mut sunk = Vec::new();
    let r = walk_codec(
        Codec::Zstd,
        cut,
        &lim(),
        |_| Selection::Take,
        |e, r| {
            sunk.push(e.path.clone());
            let mut buf = [0u8; 4096];
            for _ in 0..3 {
                let _ = r.read(&mut buf);
            }
            Ok(())
        },
    );
    assert!(matches!(r, Err(TarError::Truncated)), "{r:?}");
    assert_eq!(sunk, ["d", "d/a.dll", "b.bin"]);
}

#[test]
fn zstd_mutations_never_panic() {
    let input = zst(&two_files());
    let (mut oks, mut errs) = (0u32, 0u32);
    for step in [13, 7, 3] {
        for at in (0..input.len()).step_by(step) {
            for bit in [0x01, 0x80, 0xff] {
                let mut m = input.clone();
                m[at] ^= bit;
                match collect_zst(&m, &lim()) {
                    Ok(_) => oks += 1,
                    Err(_) => errs += 1,
                }
            }
        }
    }
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    for _ in 0..2000 {
        let mut m = input.clone();
        mutate(&mut m, &mut rng);
        let _ = collect_zst(&m, &lim());
        let noise: Vec<u8> = (0..rng.below(4096)).map(|_| rng.next() as u8).collect();
        let _ = collect_zst(&[&input[..6], &noise].concat(), &lim());
    }
    assert!(errs > 100, "ok {oks} err {errs}");
}

// ---------- limits ----------

#[test]
fn for_package_defaults() {
    let l = TarLimits::for_package(10 << 20);
    assert_eq!(l.max_compressed_bytes, 10 << 20);
    assert_eq!(l.max_total_bytes, 200 * (10 << 20));
    assert_eq!(l.max_entries, 4096);
    assert_eq!(l.max_name_len, 512);
    assert_eq!(l.max_entry_bytes, 512 << 20);
    assert_eq!(l.max_gzip_members, 1);
    assert_eq!(l.max_zstd_window, 64 << 20);
    assert_eq!(TarLimits::for_package(1 << 40).max_total_bytes, 2 << 30);
    assert_eq!(TarLimits::for_package(10).max_total_bytes, l.ratio_floor);
    assert_eq!(TarLimits::for_package(u64::MAX).max_total_bytes, 2 << 30);
}

// ---------- fuzz ----------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

#[test]
fn seeded_mutation_fuzz_never_panics_or_accepts_unsafe_names() {
    let mut tar = Tar::default()
        .dir("./")
        .dir("dir/")
        .file("dir/a.dll", b"hello")
        .raw(&edited(b"f.dll", b'0', 3, |h| h[345..348].copy_from_slice(b"pre")))
        .data(b"abc");
    let header_offsets: Vec<usize> = (0..tar.0.len()).step_by(512).collect();
    tar = tar
        .long(format!("{}/l.dll", "L".repeat(120)).as_bytes())
        .file("x", b"12345678")
        .pax(&[("path", b"pax/p.dll"), ("mtime", b"1")])
        .file("y", b"z");
    let tar = tar.end();
    let base_gz = gz_level(&tar, 1);
    let limits = TarLimits {
        max_name_len: 200,
        ..lim()
    };
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let (mut oks, mut errs) = (0u32, 0u32);
    for i in 0..20_000 {
        let input = if i % 2 == 0 {
            let mut t = tar.clone();
            for _ in 0..1 + rng.below(3) {
                mutate(&mut t, &mut rng);
            }
            if rng.below(2) == 0 {
                for &o in &header_offsets {
                    if let Some(h) = t.get_mut(o..o + 512) {
                        seal(h);
                    }
                }
            }
            gz_level(&t, 1)
        } else {
            let mut g = base_gz.clone();
            mutate(&mut g, &mut rng);
            g
        };
        let r = walk(
            &input[..],
            &limits,
            |e| {
                assert!(safe(&e.path, limits.max_name_len), "unsafe path accepted: {:?}", e.path);
                if e.kind == TarEntryKind::Dir {
                    assert_eq!(e.size, 0);
                }
                assert!(e.size <= limits.max_entry_bytes);
                Selection::Take
            },
            |e, r| {
                let n = io::copy(r, &mut io::sink())?;
                assert!(n <= e.size);
                Ok(())
            },
        );
        if r.is_ok() { oks += 1 } else { errs += 1 }
    }
    assert!(
        oks > 100 && errs > 100,
        "fuzz did not exercise both outcomes: ok {oks} err {errs}"
    );
}

fn mutate(v: &mut Vec<u8>, rng: &mut Rng) {
    let at = rng.below(v.len() + 1);
    match rng.below(4) {
        0 if at < v.len() => v[at] ^= 1 << rng.below(8),
        1 if at < v.len() => v[at] = rng.next() as u8,
        2 => v.truncate(at),
        _ => {
            for _ in 0..1 + rng.below(4) {
                v.insert(at.min(v.len()), rng.next() as u8);
            }
        }
    }
}

// ---------- golden archives from the system tar ----------

#[test]
fn system_tar_golden_archives() {
    if Command::new("tar")
        .arg("--version")
        .output()
        .map(|o| !o.status.success())
        .unwrap_or(true)
    {
        eprintln!("SKIPPED system_tar_golden_archives: no `tar` on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    let deep = format!("dxvk-2.4/{}/x64", "n".repeat(120));
    std::fs::create_dir_all(src.join(&deep)).unwrap();
    std::fs::write(src.join(&deep).join("d3d11.dll"), b"MZ fake dll").unwrap();
    std::fs::write(src.join("dxvk-2.4/README.md"), vec![b'r'; 3000]).unwrap();
    for format in ["gnu", "posix", "ustar"] {
        let out = dir.path().join(format!("{format}.tar.gz"));
        let mut cmd = Command::new("tar");
        cmd.arg(format!("--format={format}"))
            .args(["--owner=0", "--group=0", "--numeric-owner"]);
        if format == "ustar" {
            // ustar cannot hold the 120-byte component; archive only the short file
            cmd.arg("--exclude=nnn*");
        }
        cmd.arg("-czf").arg(&out).arg("-C").arg(&src).arg("dxvk-2.4");
        let st = cmd.output().unwrap();
        assert!(st.status.success(), "{format}: {}", String::from_utf8_lossy(&st.stderr));
        let input = std::fs::read(&out).unwrap();
        let got =
            collect(&input, &TarLimits::for_package(input.len() as u64)).unwrap_or_else(|e| panic!("{format}: {e}"));
        let mut names: Vec<&str> = paths(&got);
        names.sort();
        let dll = format!("{deep}/d3d11.dll");
        assert!(names.contains(&"dxvk-2.4/README.md"), "{format}: {names:?}");
        if format != "ustar" {
            assert!(names.contains(&dll.as_str()), "{format}: {names:?}");
            let (_, data) = got.iter().find(|(e, _)| e.path == dll).unwrap();
            assert_eq!(data, b"MZ fake dll");
        }
    }
    // `tar -C dir .` writes a `./` root entry and `./` prefixes on every name
    let out = dir.path().join("dot.tar.gz");
    let st = Command::new("tar")
        .arg("-czf")
        .arg(&out)
        .arg("-C")
        .arg(src.join("dxvk-2.4"))
        .arg(".")
        .output()
        .unwrap();
    assert!(st.status.success());
    let input = std::fs::read(&out).unwrap();
    let got = collect(&input, &TarLimits::for_package(input.len() as u64)).unwrap();
    assert!(paths(&got).contains(&"README.md"), "{:?}", paths(&got));
    // the same through the host `zstd` (real compressed blocks and a content checksum), when it is installed
    let out = dir.path().join("dot.tar.zst");
    let st = Command::new("tar")
        .args(["--zstd", "-cf"])
        .arg(&out)
        .arg("-C")
        .arg(src.join("dxvk-2.4"))
        .arg(".")
        .output()
        .unwrap();
    if !st.status.success() {
        eprintln!(
            "SKIPPED the tar.zst golden archive: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        return;
    }
    let input = std::fs::read(&out).unwrap();
    let got = collect_zst(&input, &TarLimits::for_package(input.len() as u64)).unwrap();
    let (_, data) = got.iter().find(|(e, _)| e.path == "README.md").unwrap();
    assert_eq!(data, &vec![b'r'; 3000]);
}
