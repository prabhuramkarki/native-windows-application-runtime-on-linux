//! Mutation harness (the style of `deps/src/manifest/tests.rs`): seeded xorshift byte flips, overwrites,
//! truncations, inserts and deletions. No mutant panics, every error text is at most 4 KiB, and nothing is written
//! outside the scratch directory.
use super::*;
use crate::manifest::parse_manifest;
use std::fs;

/// Deterministic xorshift64 so failures reproduce.
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

fn mutate(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(8) {
        match rng.below(5) {
            0 => {
                let at = rng.below(b.len());
                b[at] ^= 1 << rng.below(8);
            }
            1 => {
                let at = rng.below(b.len());
                b[at] = rng.next() as u8;
            }
            2 => b.truncate(rng.below(b.len() + 1)),
            3 => {
                let start = rng.below(b.len());
                let end = (start + rng.below(64)).min(b.len());
                let chunk = b[start..end].to_vec();
                let at = rng.below(b.len() + 1);
                b.splice(at..at, chunk);
            }
            _ => {
                if !b.is_empty() {
                    b.remove(rng.below(b.len()));
                }
            }
        }
        if b.is_empty() {
            break;
        }
    }
    b
}

const MUTANTS: usize = 2_000;
const MAX_ERROR: usize = 4096;

#[test]
fn mutated_manifests_never_panic_and_errors_are_bounded() {
    let seed = valid_manifest().into_bytes();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut accepted = 0;
    for i in 0..MUTANTS {
        let b = mutate(&seed, &mut rng);
        let r = std::panic::catch_unwind(|| parse_manifest(&b));
        match r {
            Err(_) => panic!("mutant {i} panicked: {:?}", String::from_utf8_lossy(&b)),
            Ok(Ok(_)) => accepted += 1,
            Ok(Err(e)) => assert!(
                e.to_string().len() <= MAX_ERROR,
                "mutant {i}: {} bytes",
                e.to_string().len()
            ),
        }
    }
    assert!(accepted < MUTANTS, "every mutant was accepted");
}

#[test]
fn mutated_packages_never_panic_and_write_only_their_destination() {
    let seed = valid_package();
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let t = tempfile::tempdir().unwrap();
    let canary = t.path().join("canary");
    fs::create_dir(&canary).unwrap();
    fs::write(canary.join("keep"), b"keep").unwrap();
    let mut opened = 0;
    for i in 0..MUTANTS {
        let b = mutate(&seed, &mut rng);
        let dir = t.path().to_owned();
        let r = std::panic::catch_unwind(|| -> Result<(), PackageError> {
            let mut p = open_in(&dir, &b, Limits::default())?;
            p.verify()?;
            p.unpack(&dir.join("out"))
        });
        match r {
            Err(_) => panic!("mutant {i} panicked"),
            Ok(Ok(())) => {
                opened += 1;
                fs::remove_dir_all(t.path().join("out")).unwrap();
            }
            Ok(Err(e)) => assert!(
                e.to_string().len() <= MAX_ERROR,
                "mutant {i}: {} bytes",
                e.to_string().len()
            ),
        }
        let mut names: Vec<_> = fs::read_dir(t.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["canary", "in.wrun"], "mutant {i} left something behind");
        assert_eq!(fs::read_dir(&canary).unwrap().count(), 1);
        assert_eq!(fs::read(canary.join("keep")).unwrap(), b"keep");
    }
    assert!(opened < MUTANTS, "every mutant was accepted");
}
