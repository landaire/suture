//! Source-buffer metadata used to verify a patch is being applied
//! to the buffer it was built against.

use core::fmt;
use std::io;

/// Description of the source a [`Patch`](crate::Patch) was built
/// against. `len` alone catches "wrong buffer entirely"; add a
/// [`SourceDigest`] for tamper detection and [`FileMetadata`] for
/// an mtime fast path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct SourceMetadata {
    pub len: u64,
    pub digest: Option<SourceDigest>,
    pub file: Option<FileMetadata>,
}

impl SourceMetadata {
    pub fn new(len: u64) -> Self {
        Self {
            len,
            digest: None,
            file: None,
        }
    }

    pub fn with_digest(mut self, digest: SourceDigest) -> Self {
        self.digest = Some(digest);
        self
    }

    pub fn with_file(mut self, file: FileMetadata) -> Self {
        self.file = Some(file);
        self
    }

    /// Verify `source` against `len` and `digest`. `file` is not
    /// consulted -- it's a separate, caller-driven fast path.
    pub fn verify(&self, source: &[u8]) -> Result<(), VerifyError> {
        if source.len() as u64 != self.len {
            return Err(VerifyError::LengthMismatch {
                expected: self.len,
                actual: source.len() as u64,
            });
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

/// `(algorithm, digest)` pair. Split from [`SourceMetadata`] so
/// callers can compute the digest out of band and attach it later.
///
/// Construct via [`HashAlgorithm::digest`] (correct by construction)
/// or [`SourceDigest::new`] (validates length).
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct SourceDigest {
    pub algorithm: HashAlgorithm,
    pub bytes: Vec<u8>,
}

impl SourceDigest {
    /// Errors if `bytes.len()` doesn't match `algorithm.output_len()`.
    pub fn new(
        algorithm: HashAlgorithm,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, DigestLengthError> {
        let bytes = bytes.into();
        let expected = algorithm.output_len();
        if bytes.len() != expected {
            return Err(DigestLengthError {
                algorithm,
                expected,
                actual: bytes.len(),
            });
        }
        Ok(Self { algorithm, bytes })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestLengthError {
    pub algorithm: HashAlgorithm,
    pub expected: usize,
    pub actual: usize,
}

impl fmt::Display for DigestLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} digest must be {} bytes, got {}",
            self.algorithm, self.expected, self.actual
        )
    }
}

impl core::error::Error for DigestLengthError {}

/// Filesystem stat snapshot for a mtime-based "did this file
/// change?" check without re-reading contents. Populated by
/// callers from [`std::fs::Metadata`] on file-backed sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct FileMetadata {
    pub size: u64,
    /// Unix mtime split into `(seconds, nanos)`.
    pub mtime_seconds: i64,
    pub mtime_nanos: u32,
}

impl FileMetadata {
    pub fn from_file(file: &std::fs::File) -> Result<Self, FileMetadataError> {
        Self::from_metadata(&file.metadata()?)
    }

    pub fn from_metadata(meta: &std::fs::Metadata) -> Result<Self, FileMetadataError> {
        let mtime = meta.modified()?;
        let duration = mtime.duration_since(std::time::UNIX_EPOCH).map_err(|e| {
            FileMetadataError::MtimeBeforeEpoch {
                before_epoch_by: e.duration(),
            }
        })?;
        Ok(Self {
            size: meta.len(),
            mtime_seconds: duration.as_secs() as i64,
            mtime_nanos: duration.subsec_nanos(),
        })
    }
}

#[derive(Debug)]
pub enum FileMetadataError {
    /// The filesystem didn't record an mtime, or metadata lookup
    /// failed.
    Io(io::Error),
    /// The recorded mtime is before [`std::time::UNIX_EPOCH`].
    MtimeBeforeEpoch {
        before_epoch_by: std::time::Duration,
    },
}

impl fmt::Display for FileMetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileMetadataError::Io(e) => write!(f, "file metadata read failed: {e}"),
            FileMetadataError::MtimeBeforeEpoch { before_epoch_by } => {
                write!(f, "file mtime is {before_epoch_by:?} before Unix epoch")
            }
        }
    }
}

impl core::error::Error for FileMetadataError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            FileMetadataError::Io(e) => Some(e),
            FileMetadataError::MtimeBeforeEpoch { .. } => None,
        }
    }
}

impl From<io::Error> for FileMetadataError {
    fn from(e: io::Error) -> Self {
        FileMetadataError::Io(e)
    }
}

/// Hash function tag. CRC-32 is always available; cryptographic
/// hashes require an opt-in feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum HashAlgorithm {
    /// IEEE 802.3 CRC-32, 4-byte digest.
    Crc32,
    #[cfg(feature = "blake3")]
    Blake3,
    #[cfg(feature = "sha2")]
    Sha256,
}

impl HashAlgorithm {
    /// Compute the digest of `bytes` and wrap it in a [`SourceDigest`].
    /// The returned digest matches `self` by construction.
    pub fn digest(self, bytes: &[u8]) -> SourceDigest {
        SourceDigest {
            algorithm: self,
            bytes: self.compute(bytes),
        }
    }

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
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
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
    LengthMismatch {
        expected: u64,
        actual: u64,
    },
    DigestMismatch {
        algorithm: HashAlgorithm,
        expected: Vec<u8>,
        actual: Vec<u8>,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::LengthMismatch { expected, actual } => {
                write!(
                    f,
                    "source length mismatch: expected {expected}, got {actual}"
                )
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
        assert!(matches!(
            meta.verify(b"0123"),
            Err(VerifyError::LengthMismatch { .. })
        ));
    }

    #[cfg(feature = "blake3")]
    #[test]
    fn blake3_digest_round_trip() {
        let bytes = b"hello world";
        let meta = SourceMetadata::new(bytes.len() as u64)
            .with_digest(HashAlgorithm::Blake3.digest(bytes));
        assert!(meta.verify(bytes).is_ok());
        assert!(meta.verify(b"hello WORLD").is_err());
    }

    #[cfg(feature = "sha2")]
    #[test]
    fn sha256_digest_round_trip() {
        let bytes = b"hello world";
        let meta = SourceMetadata::new(bytes.len() as u64)
            .with_digest(HashAlgorithm::Sha256.digest(bytes));
        assert!(meta.verify(bytes).is_ok());
        assert!(meta.verify(b"hello WORLD").is_err());
    }

    #[test]
    fn source_digest_new_rejects_wrong_length() {
        let err = SourceDigest::new(HashAlgorithm::Crc32, vec![0x00; 3]).unwrap_err();
        assert_eq!(
            err,
            DigestLengthError {
                algorithm: HashAlgorithm::Crc32,
                expected: 4,
                actual: 3
            }
        );
    }

    #[test]
    fn file_metadata_from_file_captures_size_and_mtime() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello suture").unwrap();
        tmp.as_file_mut().sync_all().unwrap();

        let fm = FileMetadata::from_file(tmp.as_file()).unwrap();
        assert_eq!(fm.size, b"hello suture".len() as u64);
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
