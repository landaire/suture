//! End-to-end tests for the `suture` binary.
//!
//! These spawn the real compiled binary via `assert_cmd` and drive
//! it against temp files. The goal is to lock down the user-facing
//! shape: exit codes, stderr messaging, backup-file naming, and
//! apply round-trip correctness. Snapshot-based assertions cover
//! the human-readable `inspect` output.

#![cfg(feature = "cli")]

use std::path::Path;
use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

fn suture() -> Command {
    Command::cargo_bin("suture").expect("suture binary must build")
}

fn write_file(p: &Path, bytes: &[u8]) {
    std::fs::write(p, bytes).expect("write temp file");
}

fn read_file(p: &Path) -> Vec<u8> {
    std::fs::read(p).expect("read temp file")
}

/// Most tests need a temp dir plus paths for source / target /
/// patch files. Bundling the construction means the test bodies
/// stay focused on the behaviour they're checking.
struct Fixture {
    _dir: tempfile::TempDir,
    pub src: PathBuf,
    pub tgt: PathBuf,
    pub patch: PathBuf,
    pub work: PathBuf,
}

impl Fixture {
    fn new(src_bytes: &[u8], tgt_bytes: &[u8]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.bin");
        let tgt = dir.path().join("target.bin");
        let patch = dir.path().join("changes.suture");
        let work = dir.path().join("workfile.bin");
        write_file(&src, src_bytes);
        write_file(&tgt, tgt_bytes);
        write_file(&work, src_bytes);
        Self {
            _dir: dir,
            src,
            tgt,
            patch,
            work,
        }
    }
}

#[test]
fn help_lists_every_subcommand() {
    suture()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("diff"))
        .stdout(predicate::str::contains("apply"))
        .stdout(predicate::str::contains("inspect"));
}

#[test]
fn diff_then_apply_reproduces_target() {
    let src = b"line one\nline two\nline three\n";
    let tgt = b"line one\nline TWO!\nline three\nline four\n";
    let f = Fixture::new(src, tgt);

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .assert()
        .success();

    suture()
        .args(["apply", f.patch.to_str().unwrap(), f.work.to_str().unwrap()])
        .assert()
        .success();

    assert_eq!(read_file(&f.work), tgt);
}

#[test]
fn diff_then_apply_round_trip_compressed() {
    let src = vec![0u8; 16 * 1024];
    let mut tgt = src.clone();
    tgt[7] = 0xFF;
    tgt.extend_from_slice(&[1, 2, 3, 4]);
    let f = Fixture::new(&src, &tgt);

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .args(["--compression", "always"])
        .assert()
        .success();

    suture()
        .args(["apply", f.patch.to_str().unwrap(), f.work.to_str().unwrap()])
        .assert()
        .success();

    assert_eq!(read_file(&f.work), tgt);
}

#[test]
fn diff_default_picks_compression_for_large_repetitive_payload() {
    // 16 KiB of zeros + a tiny tweak: zstd should win, and the
    // default policy is `auto` -- no flag passed.
    let src = vec![0u8; 16 * 1024];
    let mut tgt = src.clone();
    tgt[1024] = 0xFF;
    let f = Fixture::new(&src, &tgt);

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .assert()
        .success();

    suture()
        .args(["inspect", f.patch.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("compressed:     true"));

    // and the patch round-trips
    suture()
        .args(["apply", f.patch.to_str().unwrap(), f.work.to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(read_file(&f.work), tgt);
}

#[test]
fn diff_compression_never_overrides_default() {
    // `--compression never` must produce a raw patch even when
    // the heuristic would have picked compressed.
    let f = Fixture::new(b"abc", b"abd");

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .args(["--compression", "never"])
        .assert()
        .success();

    suture()
        .args(["inspect", f.patch.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("compressed:     false"));
}

#[test]
fn diff_to_stdout_then_apply_via_file() {
    let src = b"alpha";
    let tgt = b"alphabet";
    let f = Fixture::new(src, tgt);

    let bytes = suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(&bytes[0..6], b"SUTURE");
    write_file(&f.patch, &bytes);

    suture()
        .args(["apply", f.patch.to_str().unwrap(), f.work.to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(read_file(&f.work), tgt);
}

#[test]
fn apply_creates_dot_bak_with_original_bytes() {
    let src = b"keep me safe";
    let tgt = b"keep me edited";
    let f = Fixture::new(src, tgt);

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .assert()
        .success();

    suture()
        .args(["apply", f.patch.to_str().unwrap(), f.work.to_str().unwrap()])
        .assert()
        .success();

    let bak = f.work.with_file_name(format!(
        "{}.bak",
        f.work.file_name().unwrap().to_str().unwrap()
    ));
    assert!(bak.exists(), "expected backup at {}", bak.display());
    assert_eq!(read_file(&bak), src);
    assert_eq!(read_file(&f.work), tgt);
}

#[test]
fn apply_walks_to_indexed_backup_when_dot_bak_exists() {
    let src = b"first";
    let tgt = b"second";
    let f = Fixture::new(src, tgt);

    // Pre-existing backup that apply must not clobber.
    let dot_bak = f.work.with_file_name(format!(
        "{}.bak",
        f.work.file_name().unwrap().to_str().unwrap()
    ));
    write_file(&dot_bak, b"DO NOT OVERWRITE");

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .assert()
        .success();

    suture()
        .args(["apply", f.patch.to_str().unwrap(), f.work.to_str().unwrap()])
        .assert()
        .success();

    assert_eq!(read_file(&dot_bak), b"DO NOT OVERWRITE");
    let indexed = f.work.with_file_name(format!(
        "{}.1.bak",
        f.work.file_name().unwrap().to_str().unwrap()
    ));
    assert!(indexed.exists(), "expected backup at {}", indexed.display());
    assert_eq!(read_file(&indexed), src);
}

#[test]
fn apply_no_backup_skips_bak_creation() {
    let src = b"abc";
    let tgt = b"abd";
    let f = Fixture::new(src, tgt);

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .assert()
        .success();

    suture()
        .args(["apply", f.patch.to_str().unwrap(), f.work.to_str().unwrap()])
        .arg("--no-backup")
        .assert()
        .success();

    let bak = f.work.with_file_name(format!(
        "{}.bak",
        f.work.file_name().unwrap().to_str().unwrap()
    ));
    assert!(
        !bak.exists(),
        "no-backup should not create {}",
        bak.display()
    );
}

#[test]
fn apply_output_writes_to_alternate_path_without_touching_input() {
    let src = b"original";
    let tgt = b"original!";
    let f = Fixture::new(src, tgt);
    let out_path = f.work.with_file_name("out.bin");

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .assert()
        .success();

    suture()
        .args(["apply", f.patch.to_str().unwrap(), f.work.to_str().unwrap()])
        .args(["-o", out_path.to_str().unwrap()])
        .assert()
        .success();

    assert_eq!(read_file(&out_path), tgt);
    // input untouched, no backup created
    assert_eq!(read_file(&f.work), src);
    let bak = f.work.with_file_name(format!(
        "{}.bak",
        f.work.file_name().unwrap().to_str().unwrap()
    ));
    assert!(!bak.exists());
}

#[test]
fn apply_refuses_when_target_doesnt_match_recorded_source() {
    let src = b"hello world";
    let tgt = b"hello WORLD";
    let f = Fixture::new(src, tgt);

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .assert()
        .success();

    // overwrite workfile so it no longer matches the patch's source
    write_file(&f.work, b"completely different bytes");

    // assert_cmd doesn't allocate a TTY, so this exercises the
    // non-interactive branch: warn, mention --force, refuse.
    suture()
        .args(["apply", f.patch.to_str().unwrap(), f.work.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("warning"))
        .stderr(predicate::str::contains("does not match"))
        .stderr(predicate::str::contains("--force"));

    // file untouched
    assert_eq!(read_file(&f.work), b"completely different bytes");
}

#[test]
fn apply_force_overrides_mismatch_but_still_warns() {
    // A length-only patch (digest=none) keeps the source/target
    // length identical, so we can `--force` past the digest-less
    // mismatch and produce a deterministic output.
    let src = b"abcdefgh";
    let tgt = b"ABCDefgh";
    let f = Fixture::new(src, tgt);

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .args(["--digest", "blake3"])
        .assert()
        .success();

    // Same length, different bytes -> length check passes, digest fails.
    write_file(&f.work, b"01234567");

    suture()
        .args(["apply", f.patch.to_str().unwrap(), f.work.to_str().unwrap()])
        .arg("--force")
        .assert()
        .success()
        .stderr(predicate::str::contains("warning"))
        .stderr(predicate::str::contains("digest"));

    // The patch still applied (the first 4 bytes are uppercased).
    assert_eq!(read_file(&f.work), b"ABCD4567");
}

#[test]
fn apply_rejects_garbage_patch() {
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("not-a-patch.bin");
    let target = dir.path().join("file");
    write_file(&bogus, b"this is not a patch");
    write_file(&target, b"hello");

    suture()
        .args(["apply", bogus.to_str().unwrap(), target.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("magic"));
}

#[test]
fn inspect_human_output_is_stable() {
    let src = b"line one\nline two\nline three\n";
    let tgt = b"line one\nline TWO!\nline three\nline four\n";
    let f = Fixture::new(src, tgt);

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .args(["--digest", "crc32"])
        // pin compression off so the snapshot's "compressed: false"
        // line stays deterministic regardless of zstd version.
        .args(["--compression", "never"])
        .assert()
        .success();

    let output = suture()
        .args(["inspect", f.patch.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(output).unwrap();

    // The encoded size depends on rkyv layout details, so redact
    // it; everything else (op shape, digest, version) is stable.
    insta::with_settings!({
        filters => vec![
            (r"encoded size:\s+\d+ bytes", "encoded size:   <SIZE> bytes"),
        ],
    }, {
        insta::assert_snapshot!("inspect_text_diff", stdout);
    });
}

#[test]
fn inspect_reports_compression_flag_with_forced_always() {
    let f = Fixture::new(b"abc", b"abd");

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .args(["--compression", "always"])
        .assert()
        .success();

    suture()
        .args(["inspect", f.patch.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("compressed:     true"));
}

#[test]
fn diff_with_zero_timeout_still_produces_applicable_patch() {
    // similar bails to an approximate diff when the deadline is in
    // the past; the resulting patch must still apply cleanly.
    let src = b"the quick brown fox";
    let tgt = b"the lazy brown fox jumps";
    let f = Fixture::new(src, tgt);

    suture()
        .args(["diff", f.src.to_str().unwrap(), f.tgt.to_str().unwrap()])
        .args(["-o", f.patch.to_str().unwrap()])
        .args(["--timeout", "0"])
        .assert()
        .success();

    suture()
        .args(["apply", f.patch.to_str().unwrap(), f.work.to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(read_file(&f.work), tgt);
}
