//! Helpers shared across integration tests.
//!
//! Each `tests/*.rs` file is compiled as its own binary, so anything
//! that needs to be reused lives here and is pulled in with
//! `mod common;`.

#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::Path;

use suture::HashAlgorithm;
use suture::Patch;
use suture::SourceDigest;
use suture::SourceMetadata;

/// A deterministic 32-byte test corpus with a recognisable pattern so
/// snapshot diffs are easy to eyeball.
pub fn corpus() -> Vec<u8> {
    (0u8..32).collect()
}

/// Build a patch that rewrites a short run at the start, inserts a
/// marker in the middle, and deletes a pair of bytes near the end.
/// The shape is deliberately chosen to exercise all three shrink /
/// grow / in-place transitions in a single apply.
pub fn mixed_patch() -> Patch {
    let mut p = Patch::new();
    p.write(2, vec![0xAA, 0xBB]).unwrap();
    p.insert(16, vec![0xCC, 0xDD]).unwrap();
    p.delete(28, 2).unwrap();
    p
}

/// Attach a [`SourceMetadata`] block that pins `source`'s length and
/// CRC-32 digest.
pub fn metadata_with_crc32(source: &[u8]) -> SourceMetadata {
    let digest = HashAlgorithm::Crc32.compute(source);
    SourceMetadata::new(source.len() as u64).with_digest(SourceDigest::new(HashAlgorithm::Crc32, digest))
}

/// Same but with BLAKE3. Only valid when the feature is compiled in.
#[cfg(feature = "blake3")]
pub fn metadata_with_blake3(source: &[u8]) -> SourceMetadata {
    let digest = HashAlgorithm::Blake3.compute(source);
    SourceMetadata::new(source.len() as u64).with_digest(SourceDigest::new(HashAlgorithm::Blake3, digest))
}

#[cfg(feature = "sha2")]
pub fn metadata_with_sha256(source: &[u8]) -> SourceMetadata {
    let digest = HashAlgorithm::Sha256.compute(source);
    SourceMetadata::new(source.len() as u64).with_digest(SourceDigest::new(HashAlgorithm::Sha256, digest))
}

/// Write `bytes` to `path`, overwriting anything that's there.
/// Sleeps briefly beforehand so that the resulting mtime differs from
/// prior writes at sub-second filesystem resolution.
pub fn overwrite_file(path: &Path, bytes: &[u8]) {
    // APFS and ext4 have sub-second mtime resolution, but CI
    // runners can be fast enough that two back-to-back writes land in
    // the same nanosecond. A short sleep keeps mtime-based fast-path
    // tests meaningful.
    std::thread::sleep(std::time::Duration::from_millis(10));
    let mut f = fs::File::create(path).expect("create temp file");
    f.write_all(bytes).expect("write temp file");
    f.sync_all().expect("sync temp file");
}
