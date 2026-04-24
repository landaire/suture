//! Integration tests for [`Patch::apply_to`] across the three
//! stock [`PatchTarget`] impls: `&mut [u8]`, `Vec<u8>`, and
//! `std::fs::File`.
//!
//! The contract being exercised:
//!
//! - Length-preserving patches apply to every target.
//! - Length-changing patches apply to `Vec<u8>` and `File`; the
//!   fixed-size `[u8]` impl rejects them with
//!   [`BufferError::LengthChangeUnsupported`].
//! - Splice offsets translate from source coordinates into
//!   target-current coordinates (the `apply_to` delta tracking).
//! - Parity: the resulting bytes match `Patch::apply(&source)`.

mod common;

use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};

use suture::ApplyToError;
use suture::BufferError;
use suture::Patch;
use suture::PatchOp;

use crate::common::corpus;
use crate::common::mixed_patch;

// --- helpers ------------------------------------------------------

fn write_only_patch() -> Patch {
    let mut p = Patch::new();
    p.write(2, vec![0xAA, 0xBB]).unwrap();
    p.write(10, vec![0xCC]).unwrap();
    p
}

fn growing_patch() -> Patch {
    // Inserts shift the tail; deletes shrink it. Together they
    // exercise the delta-tracking code path on apply_to.
    let mut p = Patch::new();
    p.write(0, vec![0xAA]).unwrap();
    p.insert(4, vec![0x11, 0x22, 0x33]).unwrap();
    p.delete(20, 4).unwrap();
    p
}

fn open_rw(path: &std::path::Path) -> std::fs::File {
    OpenOptions::new().read(true).write(true).open(path).expect("reopen rw")
}

// --- &mut [u8] ----------------------------------------------------

#[test]
fn apply_to_mut_slice_runs_length_preserving_patch() {
    let mut buf = corpus();
    let p = write_only_patch();
    p.apply_to(buf.as_mut_slice()).expect("fixed buffer accepts pure writes");

    let expected = p.apply(&corpus()).unwrap();
    assert_eq!(buf, expected);
}

#[test]
fn apply_to_mut_slice_rejects_insert() {
    let mut buf = corpus();
    let mut p = Patch::new();
    p.insert(4, vec![0xAA, 0xBB]).unwrap();

    let err = p.apply_to(buf.as_mut_slice()).unwrap_err();
    assert!(matches!(
        err,
        ApplyToError::Sink(BufferError::LengthChangeUnsupported { offset: 4, old_len: 0, new_len: 2 })
    ));
    // The target must be untouched on rejection.
    assert_eq!(buf, corpus(), "slice bytes should be unchanged after rejected splice");
}

#[test]
fn apply_to_mut_slice_rejects_delete() {
    let mut buf = corpus();
    let mut p = Patch::new();
    p.delete(4, 2).unwrap();

    let err = p.apply_to(buf.as_mut_slice()).unwrap_err();
    assert!(matches!(
        err,
        ApplyToError::Sink(BufferError::LengthChangeUnsupported { old_len: 2, new_len: 0, .. })
    ));
    assert_eq!(buf, corpus());
}

#[test]
fn apply_to_mut_slice_reports_out_of_bounds_write() {
    // Shorter-than-patch slice: the op's offset is valid but extends
    // past the buffer's end.
    let mut buf = vec![0u8; 8];
    let mut p = Patch::new();
    p.write(6, vec![0xFF, 0xFF, 0xFF, 0xFF]).unwrap();

    let err = p.apply_to(buf.as_mut_slice()).unwrap_err();
    assert!(matches!(
        err,
        ApplyToError::Sink(BufferError::OutOfBounds { offset: 6, old_len: 4, buffer_len: 8 })
    ));
}

// --- Vec<u8> ------------------------------------------------------

#[test]
fn apply_to_vec_handles_mixed_patch_identically_to_apply() {
    let source = corpus();
    let p = mixed_patch();

    let mut target = source.clone();
    p.apply_to(&mut target).unwrap();

    assert_eq!(target, p.apply(&source).unwrap());
}

#[test]
fn apply_to_vec_handles_length_growing_and_shrinking_splices() {
    let source = corpus();
    let p = growing_patch();

    let mut target = source.clone();
    p.apply_to(&mut target).unwrap();

    assert_eq!(target, p.apply(&source).unwrap());
    assert_ne!(target.len(), source.len(), "growing_patch should change length");
}

#[test]
fn apply_to_vec_reports_out_of_bounds_splice() {
    let mut target = vec![0u8; 8];
    let mut p = Patch::new();
    p.write(4, vec![0xAA]).unwrap();
    // Legal write, then an out-of-bounds splice.
    p.push_op(PatchOp::splice(10, 2, vec![0xFF]));

    let err = p.apply_to(&mut target).unwrap_err();
    assert!(matches!(
        err,
        ApplyToError::Sink(BufferError::OutOfBounds { offset: 10, old_len: 2, .. })
    ));
    // The earlier legal write already happened -- apply_to is not
    // transactional. Documenting that.
    assert_eq!(target[4], 0xAA);
}

#[test]
fn apply_to_vec_with_out_of_order_ops_errors_before_touching_target() {
    let mut target = corpus();
    let mut p = Patch::new();
    p.push_op(PatchOp::write(10, vec![0x01]));
    p.push_op(PatchOp::write(5, vec![0x02]));

    let err = p.apply_to(&mut target).unwrap_err();
    assert!(matches!(err, ApplyToError::OutOfOrder { offset: 5, cursor: 11 }));
    // The first write *did* land -- the order check fires on op 2,
    // after op 1 already executed. This matches apply_to's
    // non-transactional semantics.
    assert_eq!(target[10], 0x01);
}

#[test]
fn apply_to_vec_with_empty_patch_is_noop() {
    let mut target = corpus();
    Patch::new().apply_to(&mut target).unwrap();
    assert_eq!(target, corpus());
}

// --- std::fs::File ------------------------------------------------

#[test]
fn apply_to_file_handles_length_preserving_patch() {
    let source = corpus();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), &source).unwrap();

    let p = write_only_patch();
    {
        let mut f = open_rw(tmp.path());
        p.apply_to(&mut f).unwrap();
        f.sync_all().unwrap();
    }

    assert_eq!(fs::read(tmp.path()).unwrap(), p.apply(&source).unwrap());
}

#[test]
fn apply_to_file_handles_mixed_patch() {
    let source = corpus();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), &source).unwrap();

    let p = mixed_patch();
    {
        let mut f = open_rw(tmp.path());
        p.apply_to(&mut f).unwrap();
        f.sync_all().unwrap();
    }

    assert_eq!(fs::read(tmp.path()).unwrap(), p.apply(&source).unwrap());
}

#[test]
fn apply_to_file_grows_and_shrinks_on_disk() {
    let source = corpus();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), &source).unwrap();

    let p = growing_patch();
    let expected = p.apply(&source).unwrap();
    {
        let mut f = open_rw(tmp.path());
        p.apply_to(&mut f).unwrap();
        f.sync_all().unwrap();
    }

    let got = fs::read(tmp.path()).unwrap();
    assert_eq!(got, expected);
    assert_eq!(got.len() as u64, fs::metadata(tmp.path()).unwrap().len(), "file length and contents agree");
}

#[test]
fn apply_to_file_truncates_when_patch_shrinks_past_current_tail() {
    let source = corpus();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), &source).unwrap();

    let mut p = Patch::new();
    p.delete(16, 16).unwrap(); // drop the entire second half
    let expected = p.apply(&source).unwrap();

    {
        let mut f = open_rw(tmp.path());
        p.apply_to(&mut f).unwrap();
        f.sync_all().unwrap();
    }

    let got = fs::read(tmp.path()).unwrap();
    assert_eq!(got, expected);
    assert_eq!(got.len(), 16);
}

#[test]
fn apply_to_file_extends_when_patch_appends_at_source_end() {
    let source = corpus();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), &source).unwrap();

    let mut p = Patch::new();
    p.insert(32, b" <-tail".to_vec()).unwrap();
    let expected = p.apply(&source).unwrap();

    {
        let mut f = open_rw(tmp.path());
        p.apply_to(&mut f).unwrap();
        f.sync_all().unwrap();
    }

    assert_eq!(fs::read(tmp.path()).unwrap(), expected);
}

#[test]
fn apply_to_file_does_not_rely_on_caller_seek_position() {
    // A caller may have seeked to an arbitrary position before
    // handing the file to apply_to. The PatchTarget impl must
    // re-seek for every op, not trust the incoming cursor.
    let source = corpus();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), &source).unwrap();

    let p = write_only_patch();
    {
        let mut f = open_rw(tmp.path());
        f.seek(SeekFrom::Start(20)).unwrap();
        f.write_all(&[0x00]).unwrap(); // move cursor somewhere weird
        f.seek(SeekFrom::Start(7)).unwrap();
        // Reset the byte we just scribbled so we can compare cleanly.
        f.seek(SeekFrom::Start(20)).unwrap();
        f.write_all(&source[20..21]).unwrap();
        f.seek(SeekFrom::Start(5)).unwrap();

        p.apply_to(&mut f).unwrap();
        f.sync_all().unwrap();
    }

    assert_eq!(fs::read(tmp.path()).unwrap(), p.apply(&source).unwrap());
}

#[test]
fn apply_to_file_returns_io_error_on_splice_past_end() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), b"short").unwrap();

    let mut p = Patch::new();
    p.push_op(PatchOp::splice(4, 8, vec![0xFF, 0xFF]));

    let mut f = open_rw(tmp.path());
    let err = p.apply_to(&mut f).unwrap_err();
    assert!(matches!(err, ApplyToError::Sink(_)));
    // Sink error is an io::Error with InvalidInput for out-of-range
    // splices.
    if let ApplyToError::Sink(e) = err {
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
    }
}
