//! Snapshot tests pinning applied output, error Display form, and
//! the serde schema.

mod common;

use std::fmt::Write as _;

use suture::Patch;
use suture::PatchOp;
use suture::metadata::SourceMetadata;

use crate::common::corpus;
use crate::common::metadata_with_crc32;
use crate::common::mixed_patch;

/// 16-column hexdump with an ASCII gutter, for diff-friendly
/// snapshots.
fn hexdump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (row, chunk) in bytes.chunks(16).enumerate() {
        write!(out, "{:04x}:", row * 16).unwrap();
        for b in chunk {
            write!(out, " {b:02x}").unwrap();
        }
        for _ in chunk.len()..16 {
            out.push_str("   ");
        }
        out.push_str("  |");
        for b in chunk {
            out.push(if (0x20..0x7f).contains(b) {
                *b as char
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }
    out
}

#[test]
fn snapshot_in_place_write_on_corpus() {
    let mut p = Patch::new();
    p.write(4, vec![0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
    insta::assert_snapshot!(hexdump(&p.apply(&corpus()).unwrap()));
}

#[test]
fn snapshot_pure_insert_shifts_tail() {
    let mut p = Patch::new();
    p.insert(8, b"<<INSERT>>".to_vec()).unwrap();
    insta::assert_snapshot!(hexdump(&p.apply(&corpus()).unwrap()));
}

#[test]
fn snapshot_pure_delete_shrinks_tail() {
    let mut p = Patch::new();
    p.delete(8, 8).unwrap();
    insta::assert_snapshot!(hexdump(&p.apply(&corpus()).unwrap()));
}

#[test]
fn snapshot_length_changing_splice() {
    let mut p = Patch::new();
    p.splice(4, 8, b"hi".to_vec()).unwrap();
    insta::assert_snapshot!(hexdump(&p.apply(&corpus()).unwrap()));
}

#[test]
fn snapshot_mixed_patch_on_corpus() {
    insta::assert_snapshot!(hexdump(&mixed_patch().apply(&corpus()).unwrap()));
}

#[test]
fn snapshot_truncate_via_trailing_delete() {
    let mut p = Patch::new();
    p.delete(16, 16).unwrap();
    insta::assert_snapshot!(hexdump(&p.apply(&corpus()).unwrap()));
}

#[test]
fn snapshot_extend_via_end_insert() {
    let mut p = Patch::new();
    p.insert(32, b" <-appended".to_vec()).unwrap();
    insta::assert_snapshot!(hexdump(&p.apply(&corpus()).unwrap()));
}

#[test]
fn snapshot_display_length_mismatch_error() {
    let mut p = Patch::with_metadata(SourceMetadata::new(32));
    p.write(0, vec![0xFF]).unwrap();
    let err = p.apply(&[0u8; 8]).unwrap_err();
    insta::assert_snapshot!(err.to_string());
}

#[test]
fn snapshot_display_digest_mismatch_error() {
    let source = corpus();
    let mut p = Patch::with_metadata(metadata_with_crc32(&source));
    p.write(0, vec![0xAA]).unwrap();
    let mut tampered = source.clone();
    tampered[0] = 0xFF;
    let err = p.apply(&tampered).unwrap_err();
    insta::assert_snapshot!(err.to_string());
}

#[test]
fn snapshot_display_out_of_bounds_error() {
    let mut p = Patch::new();
    p.write(30, vec![0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
    let err = p.apply(&[0u8; 16]).unwrap_err();
    insta::assert_snapshot!(err.to_string());
}

#[test]
fn snapshot_display_out_of_order_error() {
    let mut p = Patch::new();
    p.push_op(PatchOp::write(10, vec![0x01]));
    p.push_op(PatchOp::write(5, vec![0x02]));
    let err = p.apply(&corpus()).unwrap_err();
    insta::assert_snapshot!(err.to_string());
}

#[test]
fn snapshot_display_overlap_build_error() {
    // Writes coalesce with neighbours, but mixing a write against
    // a non-length-preserving op (here: delete) still produces an
    // Overlap error, whose Display formatting we pin.
    let mut p = Patch::new();
    p.delete(4, 3).unwrap();
    let err = p.write(5, vec![0xDD]).unwrap_err();
    insta::assert_snapshot!(err.to_string());
}

#[cfg(feature = "serde")]
#[test]
fn snapshot_serde_json_shape_of_mixed_patch_with_metadata() {
    // Pins the wire schema. A diff here means existing serialised
    // patches on disk may not round-trip cleanly.
    let source = corpus();
    let mut p = Patch::with_metadata(metadata_with_crc32(&source));
    p.write(2, vec![0xAA, 0xBB]).unwrap();
    p.insert(16, vec![0xCC, 0xDD]).unwrap();
    p.delete(28, 2).unwrap();

    let json = serde_json::to_string_pretty(&p).unwrap();
    insta::assert_snapshot!(json);
}

#[cfg(feature = "serde")]
#[test]
fn snapshot_serde_json_round_trip_fidelity() {
    let source = corpus();
    let p = mixed_patch();
    let json = serde_json::to_string(&p).unwrap();
    let back: Patch = serde_json::from_str(&json).unwrap();
    insta::assert_snapshot!(hexdump(&back.apply(&source).unwrap()));
}
