//! Source-material metadata used to verify that a patch is being
//! applied to the buffer it was generated against.

use core::fmt;
use std::io;

/// Description of the source bytes a [`Patch`](crate::Patch) was
/// generated against. None of the fields are required individually:
/// a metadata block with only `len` is still useful for catching the
/// "wrong file entirely" case; add `digest` for tamper-detection and
/// `file` to short-circuit verification when the on-disk timestamp
/// proves the file is untouched.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
pub struct SourceMetadata {
    pub len: u64,
    pub digest: Option<SourceDigest>,
    pub file: Option<FileMetadata>,
}

impl SourceMetadata {
    pub fn new(len: u64) -> Self {
        Self { len, digest: None, file: None }
    }

    pub fn with_digest(mut self, digest: SourceDigest) -> Self {
        self.digest = Some(digest);
        self
    }

    pub fn with_file(mut self, file: FileMetadata) -> Self {
        self.file = Some(file);
        self
    }

    /// Verify that `source` matches the recorded length and digest.
    /// `file` is intentionally not consulted -- it's an opportunistic
    /// fast path callers can check separately to skip a full content
    /// hash.
    pub fn verify(&self, source: &[u8]) -> Result<(), VerifyError> {
        if source.len() as u64 != self.len {
            return Err(VerifyError::LengthMismatch { expected: self.len, actual: source.len() as u64 });
        }
        if let Some(digest) = &self.digest {
            let actual = digest.algorithm.compute(source);
            if actual != digest.bytes {
                return Err(VerifyError::DigestMismatch {
                    algorithm: digest.algorithm,
                    expected: digest.bytes.clone(),
                    actual,
                });
            }
        }
        Ok(())
    }
}

/// `(algorithm, digest)` pair. Stored separately from
/// [`SourceMetadata`] so callers can build digests on a background
/// thread and attach them once ready.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
pub struct SourceDigest {
    pub algorithm: HashAlgorithm,
    pub bytes: Vec<u8>,
}

impl SourceDigest {
    pub fn new(algorithm: HashAlgorithm, bytes: impl Into<Vec<u8>>) -> Self {
        Self { algorithm, bytes: bytes.into() }
    }
}

/// Filesystem stat snapshot. Cheap-to-check optimisation for
/// "did the file change?" without re-reading the whole thing.
/// Populated by callers from `std::fs::Metadata` when the source is
/// file-backed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
pub struct FileMetadata {
    pub size: u64,
    /// Modification time as `(seconds_since_unix_epoch, nanos)`.
    /// Stored split so the type stays platform- and timezone-agnostic.
    pub mtime_seconds: i64,
    pub mtime_nanos: u32,
}

impl FileMetadata {
    /// Snapshot an open file's size and modification time.
    ///
    /// Convenience wrapper around [`FileMetadata::from_metadata`] for
    /// the common "I already have the file open" case.
    pub fn from_file(file: &std::fs::File) -> io::Result<Self> {
        Self::from_metadata(&file.metadata()?)
    }

    /// Snapshot a [`std::fs::Metadata`] into the library's platform-
    /// agnostic form. Errors if the filesystem didn't record an
    /// mtime (rare, typically only on exotic filesystems) or if the
    /// mtime predates the Unix epoch.
    pub fn from_metadata(meta: &std::fs::Metadata) -> io::Result<Self> {
        let mtime = meta.modified()?;
        let duration = mtime.duration_since(std::time::UNIX_EPOCH).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("file mtime predates Unix epoch: {e}"))
        })?;
        Ok(Self {
            size: meta.len(),
            mtime_seconds: duration.as_secs() as i64,
            mtime_nanos: duration.subsec_nanos(),
        })
    }
}

/// Hash function tag. CRC-32 is always available; cryptographic
/// hashes are gated on opt-in features. The bar here is "did the
/// source change", not collision resistance, so CRC-32 is a fine
/// default when the patch only needs cheap tamper-detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
pub enum HashAlgorithm {
    /// IEEE 802.3 CRC-32. 4-byte digest. Built in, no feature gate.
    Crc32,
    #[cfg(feature = "blake3")]
    Blake3,
    #[cfg(feature = "sha2")]
    Sha256,
}

impl HashAlgorithm {
    /// Compute the digest of `bytes`.
    pub fn compute(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Crc32 => crc32_ieee(bytes).to_be_bytes().to_vec(),
            #[cfg(feature = "blake3")]
            HashAlgorithm::Blake3 => blake3::hash(bytes).as_bytes().to_vec(),
            #[cfg(feature = "sha2")]
            HashAlgorithm::Sha256 => {
                use sha2::Digest;
                sha2::Sha256::digest(bytes).to_vec()
            }
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            HashAlgorithm::Crc32 => 4,
            #[cfg(feature = "blake3")]
            HashAlgorithm::Blake3 => 32,
            #[cfg(feature = "sha2")]
            HashAlgorithm::Sha256 => 32,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            HashAlgorithm::Crc32 => "crc32",
            #[cfg(feature = "blake3")]
            HashAlgorithm::Blake3 => "blake3",
            #[cfg(feature = "sha2")]
            HashAlgorithm::Sha256 => "sha256",
        }
    }
}

fn crc32_ieee(bytes: &[u8]) -> u32 {
    const POLY: u32 = 0xEDB8_8320;
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ POLY } else { crc >> 1 };
        }
    }
    !crc
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    LengthMismatch { expected: u64, actual: u64 },
    DigestMismatch { algorithm: HashAlgorithm, expected: Vec<u8>, actual: Vec<u8> },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::LengthMismatch { expected, actual } => {
                write!(f, "source length mismatch: expected {expected}, got {actual}")
            }
            VerifyError::DigestMismatch { algorithm, .. } => {
                write!(f, "source {algorithm} digest mismatch")
            }
        }
    }
}

impl core::error::Error for VerifyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_only_metadata_catches_size_difference() {
        let meta = SourceMetadata::new(8);
        assert!(meta.verify(b"01234567").is_ok());
        assert!(matches!(meta.verify(b"0123"), Err(VerifyError::LengthMismatch { .. })));
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn blake3_digest_round_trip() {
        let bytes = b"hello world";
        let digest = HashAlgorithm::Blake3.compute(bytes);
        let meta = SourceMetadata::new(bytes.len() as u64).with_digest(SourceDigest::new(HashAlgorithm::Blake3, digest));
        assert!(meta.verify(bytes).is_ok());
        assert!(meta.verify(b"hello WORLD").is_err());
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn sha256_digest_round_trip() {
        let bytes = b"hello world";
        let digest = HashAlgorithm::Sha256.compute(bytes);
        let meta = SourceMetadata::new(bytes.len() as u64).with_digest(SourceDigest::new(HashAlgorithm::Sha256, digest));
        assert!(meta.verify(bytes).is_ok());
        assert!(meta.verify(b"hello WORLD").is_err());
    }

    #[test]
    fn file_metadata_from_file_captures_size_and_mtime() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello suture").unwrap();
        tmp.as_file_mut().sync_all().unwrap();

        let fm = FileMetadata::from_file(tmp.as_file()).unwrap();
        assert_eq!(fm.size, b"hello suture".len() as u64);
        // mtime is expected to be post-epoch on any sane host.
        assert!(fm.mtime_seconds > 0);
        assert!(fm.mtime_nanos < 1_000_000_000);
    }

    #[test]
    fn file_metadata_from_metadata_matches_from_file() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"x").unwrap();
        tmp.as_file_mut().sync_all().unwrap();

        let via_file = FileMetadata::from_file(tmp.as_file()).unwrap();
        let via_meta = FileMetadata::from_metadata(&tmp.as_file().metadata().unwrap()).unwrap();
        assert_eq!(via_file, via_meta);
    }
}
