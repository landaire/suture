//! End-to-end tests for the guardrails Suture uses to detect that a
//! patch is being applied to a buffer it wasn't built against.
//!
//! The scenarios intentionally cover the full ladder of protection:
//! length-only metadata (cheapest, can miss same-length tampering),
//! digest metadata (catches anything the hash can distinguish), and
//! `FileMetadata` (informational -- a caller fast-path, not enforced
//! by `verify`). The overlap / out-of-bounds / out-of-order cases
//! cover the separate guardrails that protect the patch structure
//! itself regardless of metadata.

mod common;

use suture::ApplyError;
use suture::BuildError;
use suture::Patch;
use suture::PatchOp;
use suture::SourceMetadata;
use suture::VerifyError;

use crate::common::corpus;
use crate::common::metadata_with_crc32;
use crate::common::mixed_patch;

// --- length-based guardrail ---------------------------------------

#[test]
fn length_only_metadata_catches_truncated_buffer() {
    let source = corpus();
    let mut p = Patch::with_metadata(SourceMetadata::new(source.len() as u64));
    p.write(0, vec![0xFF]).unwrap();

    // Buffer was truncated after the patch was built. verify() must
    // refuse to run splices against a shorter source.
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
    // Documenting a *known* blind spot: if the buffer was modified in
    // place without changing length, length-only metadata will happily
    // verify the tampered buffer. Callers that want to catch this
    // must attach a digest.
    let mut source = corpus();
    let mut p = Patch::with_metadata(SourceMetadata::new(source.len() as u64));
    p.write(0, vec![0xAA]).unwrap();

    source[10] = 0xEE; // tamper, same length
    assert!(p.apply(&source).is_ok(), "length-only verify cannot see in-place flips");
}

// --- digest-based guardrail ---------------------------------------

#[test]
fn crc32_digest_catches_in_place_flip() {
    let mut source = corpus();
    let meta = metadata_with_crc32(&source);
    let mut p = Patch::with_metadata(meta);
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

// --- file metadata guardrail --------------------------------------

#[test]
fn file_metadata_is_not_consulted_by_verify() {
    use suture::FileMetadata;

    // FileMetadata documents itself as an *opportunistic* fast path
    // the caller checks separately. Make sure the library really
    // doesn't reach for it implicitly -- a stale `mtime` on an
    // untouched buffer must not trip verify().
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
    // End-to-end: build a patch against a real temp file, rewrite
    // the file, read it back, and confirm verify() refuses it.
    use crate::common::overwrite_file;
    use std::fs;
    use suture::FileMetadata;
    use suture::HashAlgorithm;
    use suture::SourceDigest;

    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    overwrite_file(tmp.path(), &corpus());

    let original = fs::read(tmp.path()).unwrap();
    let original_stat = FileMetadata::from_file(&fs::File::open(tmp.path()).unwrap()).unwrap();
    let meta = SourceMetadata::new(original.len() as u64)
        .with_digest(SourceDigest::new(HashAlgorithm::Crc32, HashAlgorithm::Crc32.compute(&original)))
        .with_file(original_stat);
    let mut p = Patch::with_metadata(meta.clone());
    p.write(0, vec![0xAA]).unwrap();

    // Pristine read verifies.
    assert!(p.apply(&original).is_ok());

    // Tamper: rewrite the file with different bytes.
    let mut tampered = original.clone();
    tampered[4] ^= 0xFF;
    overwrite_file(tmp.path(), &tampered);

    let reread = fs::read(tmp.path()).unwrap();
    let new_stat = FileMetadata::from_file(&fs::File::open(tmp.path()).unwrap()).unwrap();

    // mtime fast-path (a caller convention, not enforced by the
    // library) sees the file has changed.
    assert_ne!(original_stat, new_stat, "mtime should differ after rewrite");

    // verify() catches the content change via digest regardless.
    let err = p.apply(&reread).unwrap_err();
    assert!(matches!(err, ApplyError::Verify(VerifyError::DigestMismatch { .. })));
}

// --- patch-structure guardrails -----------------------------------

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
    // Insert at 6 lies inside the [4, 8) deleted range.
    let err = p.insert(6, vec![0xAA]).unwrap_err();
    assert!(matches!(err, BuildError::Overlap { .. }));
}

#[test]
fn zero_length_insert_at_existing_offset_is_allowed() {
    // A pure insert at the same offset as an existing op occupies
    // no source range and is ordered before the op at that offset,
    // so this is structurally fine. The apply loop proves it: both
    // the insert and the write land at offset 4 without collision.
    let mut p = Patch::new();
    p.write(4, vec![0xAA]).unwrap();
    p.insert(4, vec![0xBB]).unwrap();

    let out = p.apply(&corpus()).unwrap();
    assert_eq!(out[4], 0xBB);
    assert_eq!(out[5], 0xAA);
}

#[test]
fn out_of_bounds_splice_errors_at_apply_time() {
    // No metadata here so the length check doesn't short-circuit.
    let mut p = Patch::new();
    p.write(30, vec![0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
    let err = p.apply(&[0u8; 16]).unwrap_err();
    assert!(matches!(err, ApplyError::OutOfBounds { offset: 30, old_len: 4, source_len: 16 }));
}

#[test]
fn out_of_order_ops_via_push_op_are_rejected_at_apply_time() {
    // push_op bypasses the structural checks that the regular
    // builders enforce, so it's the right way to stage an unsorted
    // patch and confirm apply still catches it.
    let mut p = Patch::new();
    p.push_op(PatchOp::write(10, vec![0x01]));
    p.push_op(PatchOp::write(5, vec![0x02]));
    let err = p.apply(&corpus()).unwrap_err();
    assert!(matches!(err, ApplyError::OutOfOrder { offset: 5, cursor: 11 }));
}

// --- stream_to parity ---------------------------------------------

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
    assert!(sink.is_empty(), "no bytes should be streamed when verification fails");
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
fn stream_to_matches_apply_for_mixed_patch() {
    let source = corpus();
    let p = mixed_patch();
    let via_apply = p.apply(&source).unwrap();
    let mut via_stream = Vec::new();
    p.stream_to(&source, &mut via_stream).unwrap();
    assert_eq!(via_apply, via_stream);
}

// --- apply_unchecked escape hatch ---------------------------------

#[test]
fn apply_unchecked_skips_length_and_digest_checks() {
    let source = corpus();
    let mut p = Patch::with_metadata(metadata_with_crc32(&source));
    p.write(0, vec![0xAA]).unwrap();

    // Completely different buffer but same shape. verify() would
    // reject it; unchecked must not.
    let bogus: Vec<u8> = (100u8..132).collect();
    let out = unsafe { p.apply_unchecked(&bogus) };
    assert_eq!(out[0], 0xAA);
    assert_eq!(&out[1..], &bogus[1..]);
}

#[test]
fn apply_unchecked_still_panics_on_structural_invariant_violations() {
    // The safety contract says the caller must keep offsets in-bounds
    // and ordered; if they don't, apply_unchecked panics rather than
    // doing unsafe-memory things, because the inner loop uses checked
    // slicing. That panic is the observable signal that the caller
    // lied about the preconditions.
    let mut p = Patch::new();
    p.push_op(PatchOp::write(100, vec![0xFF]));

    let result = std::panic::catch_unwind(|| {
        let p = p.clone();
        unsafe { p.apply_unchecked(&[0u8; 4]) }
    });
    assert!(result.is_err(), "expected panic from out-of-bounds unchecked apply");
}

// --- length-preserving writes over a "live" buffer ---------------

#[test]
fn chained_writes_see_original_offsets_not_shifted_by_prior_inserts() {
    // Regression guard: the offset coordinate system is always the
    // *original* source, never the shifting post-splice position.
    // If apply() ever started reinterpreting offsets mid-run, the
    // second write would land on the wrong bytes.
    let source = corpus();
    let mut p = Patch::new();
    p.insert(4, b"<<<".to_vec()).unwrap();
    p.write(16, vec![0xEE]).unwrap();

    let out = p.apply(&source).unwrap();
    assert_eq!(&out[4..7], b"<<<");
    // Original index 16, shifted by the 3-byte insert.
    assert_eq!(out[16 + 3], 0xEE);
}

#[test]
fn metadata_mutators_round_trip_through_clear() {
    let mut p = Patch::new();
    assert!(p.metadata().is_none());
    p.set_metadata(SourceMetadata::new(8));
    assert_eq!(p.metadata().map(|m| m.len), Some(8));
    p.clear_metadata();
    assert!(p.metadata().is_none());
}
