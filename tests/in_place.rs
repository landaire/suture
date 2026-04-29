//! Tests for `Patch::apply_to` across the stock `PatchTarget` impls:
//! `&mut [u8]`, `Vec<u8>`, and `std::fs::File`.

mod common;

use std::fs::OpenOptions;
use std::fs::{
    self,
};
use std::io::Seek;
use std::io::SeekFrom;

use suture::ApplyToError;
use suture::Patch;
use suture::PatchOp;
use suture::target::BufferError;
use suture::target::FileTargetError;

use crate::common::corpus;

fn write_only_patch() -> Patch {
    let mut p = Patch::new();
    p.write(2, vec![0xAA, 0xBB]).unwrap();
    p.write(10, vec![0xCC]).unwrap();
    p
}

fn growing_patch() -> Patch {
    let mut p = Patch::new();
    p.write(0, vec![0xAA]).unwrap();
    p.insert(4, vec![0x11, 0x22, 0x33]).unwrap();
    p.delete(20, 4).unwrap();
    p
}

fn open_rw(path: &std::path::Path) -> std::fs::File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("reopen rw")
}

#[test]
fn apply_to_mut_slice_runs_length_preserving_patch() {
    let mut buf = corpus();
    let p = write_only_patch();
    p.apply_to(buf.as_mut_slice()).unwrap();
    assert_eq!(buf, p.apply(&corpus()).unwrap());
}

#[test]
fn apply_to_mut_slice_rejects_length_changing_op() {
    let mut buf = corpus();
    let mut p = Patch::new();
    p.insert(4, vec![0xAA, 0xBB]).unwrap();

    let err = p.apply_to(buf.as_mut_slice()).unwrap_err();
    assert!(matches!(
        err,
        ApplyToError::Sink(BufferError::LengthChangeUnsupported {
            offset: 4,
            old_len: 0,
            new_len: 2
        })
    ));
    assert_eq!(buf, corpus());
}

#[test]
fn apply_to_mut_slice_reports_out_of_bounds_write() {
    let mut buf = vec![0u8; 8];
    let mut p = Patch::new();
    p.write(6, vec![0xFF, 0xFF, 0xFF, 0xFF]).unwrap();

    let err = p.apply_to(buf.as_mut_slice()).unwrap_err();
    assert!(matches!(
        err,
        ApplyToError::Sink(BufferError::OutOfBounds {
            offset: 6,
            old_len: 4,
            buffer_len: 8
        })
    ));
}

#[test]
fn apply_to_vec_handles_length_growing_and_shrinking_splices() {
    let source = corpus();
    let p = growing_patch();

    let mut target = source.clone();
    p.apply_to(&mut target).unwrap();

    assert_eq!(target, p.apply(&source).unwrap());
    assert_ne!(target.len(), source.len());
}

#[test]
fn apply_to_vec_reports_out_of_bounds_splice() {
    let mut target = vec![0u8; 8];
    let mut p = Patch::new();
    p.write(4, vec![0xAA]).unwrap();
    p.push_op(PatchOp::splice(10, 2, vec![0xFF]));

    let err = p.apply_to(&mut target).unwrap_err();
    assert!(matches!(
        err,
        ApplyToError::Sink(BufferError::OutOfBounds {
            offset: 10,
            old_len: 2,
            ..
        })
    ));
    // apply_to is not transactional: the earlier write already landed.
    assert_eq!(target[4], 0xAA);
}

#[test]
fn apply_to_vec_with_out_of_order_ops_errors_mid_apply() {
    let mut target = corpus();
    let mut p = Patch::new();
    p.push_op(PatchOp::write(10, vec![0x01]));
    p.push_op(PatchOp::write(5, vec![0x02]));

    let err = p.apply_to(&mut target).unwrap_err();
    assert!(matches!(
        err,
        ApplyToError::OutOfOrder {
            offset: 5,
            cursor: 11
        }
    ));
    // Not transactional: op 1 landed before op 2 tripped the check.
    assert_eq!(target[10], 0x01);
}

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
    assert_eq!(got.len() as u64, fs::metadata(tmp.path()).unwrap().len());
}

#[test]
fn apply_to_file_truncates_when_patch_shrinks_past_current_tail() {
    let source = corpus();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), &source).unwrap();

    let mut p = Patch::new();
    p.delete(16, 16).unwrap();
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
    // Each splice_at call must re-seek; the caller's incoming cursor
    // is irrelevant.
    let source = corpus();
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), &source).unwrap();

    let p = write_only_patch();
    {
        let mut f = open_rw(tmp.path());
        f.seek(SeekFrom::Start(5)).unwrap();
        p.apply_to(&mut f).unwrap();
        f.sync_all().unwrap();
    }

    assert_eq!(fs::read(tmp.path()).unwrap(), p.apply(&source).unwrap());
}

#[test]
fn apply_to_file_rejects_splice_past_end() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    fs::write(tmp.path(), b"short").unwrap();

    let mut p = Patch::new();
    p.push_op(PatchOp::splice(4, 8, vec![0xFF, 0xFF]));

    let mut f = open_rw(tmp.path());
    let err = p.apply_to(&mut f).unwrap_err();
    assert!(matches!(
        err,
        ApplyToError::Sink(FileTargetError::OutOfBounds {
            offset: 4,
            old_len: 8,
            file_len: 5
        })
    ));
}
