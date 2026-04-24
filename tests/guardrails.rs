//! Tests for source verification and patch-structure checks.

mod common;

use suture::ApplyError;
use suture::BuildError;
use suture::Patch;
use suture::PatchOp;
use suture::metadata::SourceMetadata;
use suture::metadata::VerifyError;

use crate::common::corpus;
use crate::common::metadata_with_crc32;
use crate::common::mixed_patch;

#[test]
fn length_only_metadata_catches_truncated_buffer() {
    let source = corpus();
    let mut p = Patch::with_metadata(SourceMetadata::new(source.len() as u64));
    p.write(0, vec![0xFF]).unwrap();

    let truncated = &source[..source.len() - 4];
    let err = p.apply(truncated).unwrap_err();
    assert!(matches!(err, ApplyError::Verify(VerifyError::LengthMismatch { expected: 32, actual: 28 })));
}

#[test]
fn length_only_metadata_catches_extended_buffer() {
    let source = corpus();
    let mut p = Patch::with_metadata(SourceMetadata::new(source.len() as u64));
    p.write(0, vec![0xFF]).unwrap();

    let mut extended = source.clone();
    extended.extend_from_slice(b"tail");
    let err = p.apply(&extended).unwrap_err();
    assert!(matches!(err, ApplyError::Verify(VerifyError::LengthMismatch { expected: 32, actual: 36 })));
}

#[test]
fn length_only_metadata_misses_in_place_flip() {
    // Length-only metadata cannot detect same-length tampering. A
    // digest is required for that.
    let mut source = corpus();
    let mut p = Patch::with_metadata(SourceMetadata::new(source.len() as u64));
    p.write(0, vec![0xAA]).unwrap();

    source[10] = 0xEE;
    assert!(p.apply(&source).is_ok());
}

#[test]
fn crc32_digest_catches_in_place_flip() {
    let mut source = corpus();
    let mut p = Patch::with_metadata(metadata_with_crc32(&source));
    p.write(0, vec![0xAA]).unwrap();

    source[10] ^= 0x01;
    let err = p.apply(&source).unwrap_err();
    assert!(matches!(err, ApplyError::Verify(VerifyError::DigestMismatch { .. })));
}

#[cfg(feature = "blake3")]
#[test]
fn blake3_digest_catches_in_place_flip() {
    use crate::common::metadata_with_blake3;
    let mut source = corpus();
    let mut p = Patch::with_metadata(metadata_with_blake3(&source));
    p.write(0, vec![0xAA]).unwrap();

    source[7] ^= 0x40;
    let err = p.apply(&source).unwrap_err();
    assert!(matches!(err, ApplyError::Verify(VerifyError::DigestMismatch { .. })));
}

#[cfg(feature = "sha2")]
#[test]
fn sha256_digest_catches_in_place_flip() {
    use crate::common::metadata_with_sha256;
    let mut source = corpus();
    let mut p = Patch::with_metadata(metadata_with_sha256(&source));
    p.write(0, vec![0xAA]).unwrap();

    source[7] ^= 0x40;
    let err = p.apply(&source).unwrap_err();
    assert!(matches!(err, ApplyError::Verify(VerifyError::DigestMismatch { .. })));
}

#[test]
fn digest_verification_succeeds_on_pristine_source() {
    let source = corpus();
    let mut p = Patch::with_metadata(metadata_with_crc32(&source));
    p.write(0, vec![0xAA]).unwrap();
    assert!(p.apply(&source).is_ok());
}

#[test]
fn file_metadata_is_not_consulted_by_verify() {
    use suture::metadata::FileMetadata;

    // FileMetadata is a caller-driven fast path; verify() must not
    // use it, otherwise a stale mtime would falsely reject an
    // untouched buffer.
    let source = corpus();
    let meta = SourceMetadata::new(source.len() as u64).with_file(FileMetadata {
        size: source.len() as u64,
        mtime_seconds: 0,
        mtime_nanos: 0,
    });
    let mut p = Patch::with_metadata(meta);
    p.write(0, vec![0xAA]).unwrap();
    assert!(p.apply(&source).is_ok());
}

#[test]
fn file_backed_source_is_caught_after_rewrite() {
    use crate::common::overwrite_file;
    use std::fs;
    use suture::metadata::FileMetadata;
    use suture::metadata::HashAlgorithm;
    use suture::metadata::SourceDigest;

    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    overwrite_file(tmp.path(), &corpus());

    let original = fs::read(tmp.path()).unwrap();
    let original_stat = FileMetadata::from_file(&fs::File::open(tmp.path()).unwrap()).unwrap();
    let meta = SourceMetadata::new(original.len() as u64)
        .with_digest(SourceDigest::new(HashAlgorithm::Crc32, HashAlgorithm::Crc32.compute(&original)))
        .with_file(original_stat);
    let mut p = Patch::with_metadata(meta.clone());
    p.write(0, vec![0xAA]).unwrap();

    assert!(p.apply(&original).is_ok());

    let mut tampered = original.clone();
    tampered[4] ^= 0xFF;
    overwrite_file(tmp.path(), &tampered);

    let reread = fs::read(tmp.path()).unwrap();
    let new_stat = FileMetadata::from_file(&fs::File::open(tmp.path()).unwrap()).unwrap();
    assert_ne!(original_stat, new_stat);

    let err = p.apply(&reread).unwrap_err();
    assert!(matches!(err, ApplyError::Verify(VerifyError::DigestMismatch { .. })));
}

#[test]
fn overlap_between_two_writes_is_rejected_at_build_time() {
    let mut p = Patch::new();
    p.write(4, vec![0xAA, 0xBB, 0xCC]).unwrap();
    let err = p.write(6, vec![0xDD]).unwrap_err();
    assert!(matches!(err, BuildError::Overlap { offset: 6, existing_offset: 4, existing_old_len: 3 }));
}

#[test]
fn overlap_between_adjacent_delete_and_insert_is_rejected() {
    let mut p = Patch::new();
    p.delete(4, 4).unwrap();
    let err = p.insert(6, vec![0xAA]).unwrap_err();
    assert!(matches!(err, BuildError::Overlap { .. }));
}

#[test]
fn zero_length_insert_at_existing_offset_is_allowed() {
    // A pure insert at the same offset as an existing op has zero
    // source span, so the overlap check lets it through; the apply
    // loop orders it before the write at the same offset.
    let mut p = Patch::new();
    p.write(4, vec![0xAA]).unwrap();
    p.insert(4, vec![0xBB]).unwrap();

    let out = p.apply(&corpus()).unwrap();
    assert_eq!(out[4], 0xBB);
    assert_eq!(out[5], 0xAA);
}

#[test]
fn out_of_bounds_splice_errors_at_apply_time() {
    let mut p = Patch::new();
    p.write(30, vec![0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
    let err = p.apply(&[0u8; 16]).unwrap_err();
    assert!(matches!(err, ApplyError::OutOfBounds { offset: 30, old_len: 4, source_len: 16 }));
}

#[test]
fn out_of_order_ops_via_push_op_are_rejected_at_apply_time() {
    let mut p = Patch::new();
    p.push_op(PatchOp::write(10, vec![0x01]));
    p.push_op(PatchOp::write(5, vec![0x02]));
    let err = p.apply(&corpus()).unwrap_err();
    assert!(matches!(err, ApplyError::OutOfOrder { offset: 5, cursor: 11 }));
}

#[test]
fn stream_to_enforces_same_guardrails_as_apply() {
    let source = corpus();
    let mut p = Patch::with_metadata(metadata_with_crc32(&source));
    p.write(0, vec![0xAA]).unwrap();

    let mut tampered = source.clone();
    tampered[1] ^= 0x10;

    let mut sink = Vec::new();
    let err = p.stream_to(&tampered, &mut sink).unwrap_err();
    assert!(matches!(err, ApplyError::Verify(VerifyError::DigestMismatch { .. })));
    assert!(sink.is_empty());
}

#[test]
fn stream_to_rejects_out_of_bounds_without_metadata() {
    let mut p = Patch::new();
    p.write(30, vec![0xFF]).unwrap();
    let mut sink = Vec::new();
    let err = p.stream_to(&[0u8; 4], &mut sink).unwrap_err();
    assert!(matches!(err, ApplyError::OutOfBounds { .. }));
}

#[test]
fn apply_unchecked_skips_length_and_digest_checks() {
    let source = corpus();
    let mut p = Patch::with_metadata(metadata_with_crc32(&source));
    p.write(0, vec![0xAA]).unwrap();

    let bogus: Vec<u8> = (100u8..132).collect();
    let out = unsafe { p.apply_unchecked(&bogus) };
    assert_eq!(out[0], 0xAA);
    assert_eq!(&out[1..], &bogus[1..]);
}

#[test]
fn apply_unchecked_panics_on_out_of_bounds_op() {
    // apply_unchecked uses checked slicing internally, so a caller
    // that violates the "op offset in bounds" precondition gets a
    // panic rather than UB.
    let mut p = Patch::new();
    p.push_op(PatchOp::write(100, vec![0xFF]));

    let result = std::panic::catch_unwind(|| {
        let p = p.clone();
        unsafe { p.apply_unchecked(&[0u8; 4]) }
    });
    assert!(result.is_err());
}

#[test]
fn chained_writes_see_original_offsets_not_shifted_by_prior_inserts() {
    // Op offsets are always in the source coordinate system, so a
    // 3-byte insert at 4 shifts a write at 16 to position 19 in the
    // output without changing the op's stored offset.
    let source = corpus();
    let mut p = Patch::new();
    p.insert(4, b"<<<".to_vec()).unwrap();
    p.write(16, vec![0xEE]).unwrap();

    let out = p.apply(&source).unwrap();
    assert_eq!(&out[4..7], b"<<<");
    assert_eq!(out[16 + 3], 0xEE);
}
