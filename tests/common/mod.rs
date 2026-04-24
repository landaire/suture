//! Helpers shared across integration tests.

#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::Path;

use suture::Patch;
use suture::metadata::HashAlgorithm;
use suture::metadata::SourceMetadata;

pub fn corpus() -> Vec<u8> {
    (0u8..32).collect()
}

/// Mixed patch that exercises write, insert, and delete in one apply.
pub fn mixed_patch() -> Patch {
    let mut p = Patch::new();
    p.write(2, vec![0xAA, 0xBB]).unwrap();
    p.insert(16, vec![0xCC, 0xDD]).unwrap();
    p.delete(28, 2).unwrap();
    p
}

pub fn metadata_with_crc32(source: &[u8]) -> SourceMetadata {
    SourceMetadata::new(source.len() as u64).with_digest(HashAlgorithm::Crc32.digest(source))
}

#[cfg(feature = "blake3")]
pub fn metadata_with_blake3(source: &[u8]) -> SourceMetadata {
    SourceMetadata::new(source.len() as u64).with_digest(HashAlgorithm::Blake3.digest(source))
}

#[cfg(feature = "sha2")]
pub fn metadata_with_sha256(source: &[u8]) -> SourceMetadata {
    SourceMetadata::new(source.len() as u64).with_digest(HashAlgorithm::Sha256.digest(source))
}

/// Overwrite `path` with `bytes`. Sleeps 10ms first so the resulting
/// mtime always advances past the previous write on sub-second-
/// resolution filesystems.
pub fn overwrite_file(path: &Path, bytes: &[u8]) {
    std::thread::sleep(std::time::Duration::from_millis(10));
    let mut f = fs::File::create(path).expect("create temp file");
    f.write_all(bytes).expect("write temp file");
    f.sync_all().expect("sync temp file");
}
