//! On-disk patch format.
//!
//! A patch file is a small fixed header followed by an
//! [`rkyv`]-archived [`Patch`], optionally compressed with `zstd`:
//!
//! ```text
//!   magic    "SUTURE"  6 bytes
//!   version  u16 LE    2 bytes   format version (currently 1)
//!   flags    u8        1 byte    bit 0 = zstd-compressed body
//!   _rsvd    u8        1 byte    must be 0
//!   body_len u64 LE    8 bytes   length of the body that follows
//!   body     ...                 rkyv archive of [`Patch`]
//! ```
//!
//! The leading magic + version let a future reader recognise an
//! incompatible patch and refuse cleanly instead of feeding garbage
//! to the rkyv archive validator. When we eventually need to break
//! the body layout we bump [`FORMAT_VERSION`] and dispatch on the
//! version field at decode time.

use core::fmt;
use std::io;

use rkyv::rancor::Error as RkyvError;
use rkyv::util::AlignedVec;

use crate::Patch;

const MAGIC: &[u8; 6] = b"SUTURE";

/// Current on-disk format version. Bump when the body layout changes
/// in a way older readers can't handle.
pub const FORMAT_VERSION: u16 = 1;

/// Length of the fixed header that precedes every patch body.
pub const HEADER_LEN: usize = 18;

const FLAG_COMPRESSED: u8 = 0b0000_0001;
const KNOWN_FLAGS: u8 = FLAG_COMPRESSED;

/// Compression level passed to zstd when compression is requested.
/// Level 0 is "library default" (currently 3) -- a balance of size
/// and speed that is fine for interactive use.
const ZSTD_LEVEL: i32 = 0;

/// How [`encode`] should treat compression.
///
/// `Auto` (the default for [`encode`]) tries the body both ways and
/// keeps whichever is smaller. zstd's frame overhead is a handful
/// of bytes, so for tiny patches "raw" wins; large patches over
/// repetitive payloads typically shrink by an order of magnitude.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Compression {
    /// Pick the smaller of `compressed` and `raw`. Ties go to raw
    /// so a reader without zstd support can still decode.
    #[default]
    Auto,
    /// Always wrap the body in a zstd frame, even when it grows.
    Always,
    /// Never compress.
    Never,
}

/// Result of [`decode`]. Carries the decoded [`Patch`] plus the
/// envelope facts that callers (e.g. `suture inspect`) want to
/// surface.
#[derive(Debug, Clone)]
pub struct Decoded {
    pub patch: Patch,
    pub format_version: u16,
    pub compressed: bool,
}

/// Result of [`encode`]. The `compressed` flag tells the caller
/// which branch the heuristic took -- useful for a "wrote a 423-
/// byte compressed patch" success message.
#[derive(Debug, Clone)]
pub struct Encoded {
    pub bytes: Vec<u8>,
    pub compressed: bool,
}

#[derive(Debug)]
pub enum EncodeError {
    /// Failed to archive the patch with rkyv.
    Rkyv(RkyvError),
    /// Failed to compress the archived payload with zstd.
    Compress(io::Error),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::Rkyv(e) => write!(f, "rkyv archive failed: {e}"),
            EncodeError::Compress(e) => write!(f, "zstd compression failed: {e}"),
        }
    }
}

impl core::error::Error for EncodeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            EncodeError::Rkyv(e) => Some(e),
            EncodeError::Compress(e) => Some(e),
        }
    }
}

#[derive(Debug)]
pub enum DecodeError {
    /// Buffer doesn't even contain a complete header.
    ShortHeader { got: usize },
    /// Magic bytes at the start don't match `b"SUTURE"`.
    BadMagic { got: [u8; 6] },
    /// Encoded version isn't one this build can decode.
    UnsupportedVersion { found: u16, supported: u16 },
    /// One or more bits set in the flags byte that this build
    /// doesn't recognise -- the patch was likely written by a
    /// newer suture that introduced extra options.
    UnknownFlags { flags: u8 },
    /// Reserved byte was non-zero.
    NonZeroReserved { byte: u8 },
    /// Body-length field disagrees with the bytes available.
    BodyLengthMismatch { declared: u64, available: u64 },
    /// zstd decompression failed (compressed bit was set).
    Decompress(io::Error),
    /// rkyv validation/deserialisation failed -- the body isn't a
    /// well-formed [`Patch`].
    Rkyv(RkyvError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::ShortHeader { got } => {
                write!(
                    f,
                    "patch is too short: need {HEADER_LEN} bytes for the header, got {got}"
                )
            }
            DecodeError::BadMagic { got } => {
                write!(
                    f,
                    "not a suture patch: expected magic {MAGIC:?}, got {got:?}"
                )
            }
            DecodeError::UnsupportedVersion { found, supported } => {
                write!(
                    f,
                    "unsupported patch format version {found} (this build understands {supported})"
                )
            }
            DecodeError::UnknownFlags { flags } => {
                write!(f, "patch has unknown flag bits set: {flags:#010b}")
            }
            DecodeError::NonZeroReserved { byte } => {
                write!(f, "reserved header byte must be 0, got {byte:#x}")
            }
            DecodeError::BodyLengthMismatch {
                declared,
                available,
            } => {
                write!(
                    f,
                    "body length mismatch: header declares {declared} bytes, found {available}"
                )
            }
            DecodeError::Decompress(e) => write!(f, "zstd decompression failed: {e}"),
            DecodeError::Rkyv(e) => write!(f, "rkyv decode failed: {e}"),
        }
    }
}

impl core::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            DecodeError::Decompress(e) => Some(e),
            DecodeError::Rkyv(e) => Some(e),
            _ => None,
        }
    }
}

/// Encode `patch` into the on-disk format under the requested
/// [`Compression`] policy. The returned [`Encoded`] reports both
/// the bytes and whether compression was actually applied -- in
/// `Auto` mode that depends on the input.
///
/// `Auto` archives the patch with rkyv once and then runs zstd
/// once, comparing body lengths to pick the smaller. The header
/// size is identical either way, so comparing bodies is the same
/// as comparing total file size.
pub fn encode(patch: &Patch, mode: Compression) -> Result<Encoded, EncodeError> {
    let archived = rkyv::to_bytes::<RkyvError>(patch).map_err(EncodeError::Rkyv)?;

    let (body, compressed) = match mode {
        Compression::Never => (archived.to_vec(), false),
        Compression::Always => (
            zstd::encode_all(archived.as_slice(), ZSTD_LEVEL).map_err(EncodeError::Compress)?,
            true,
        ),
        Compression::Auto => {
            let zst =
                zstd::encode_all(archived.as_slice(), ZSTD_LEVEL).map_err(EncodeError::Compress)?;
            // Tie-break in favour of raw: smaller-or-equal compressed
            // payloads aren't worth the extra decode dependency on the
            // reader side.
            if zst.len() < archived.len() {
                (zst, true)
            } else {
                (archived.to_vec(), false)
            }
        }
    };

    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.push(if compressed { FLAG_COMPRESSED } else { 0 });
    out.push(0);
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(Encoded {
        bytes: out,
        compressed,
    })
}

/// Decode a patch file. Validates the header, decompresses if
/// needed, then runs rkyv's `bytecheck` validator before handing
/// back an owned [`Patch`].
pub fn decode(bytes: &[u8]) -> Result<Decoded, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::ShortHeader { got: bytes.len() });
    }
    let magic: [u8; 6] = bytes[0..6].try_into().unwrap();
    if &magic != MAGIC {
        return Err(DecodeError::BadMagic { got: magic });
    }
    let version = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
    if version != FORMAT_VERSION {
        return Err(DecodeError::UnsupportedVersion {
            found: version,
            supported: FORMAT_VERSION,
        });
    }
    let flags = bytes[8];
    if flags & !KNOWN_FLAGS != 0 {
        return Err(DecodeError::UnknownFlags { flags });
    }
    let reserved = bytes[9];
    if reserved != 0 {
        return Err(DecodeError::NonZeroReserved { byte: reserved });
    }
    let body_len = u64::from_le_bytes(bytes[10..18].try_into().unwrap());
    let body_slice = &bytes[HEADER_LEN..];
    if body_len != body_slice.len() as u64 {
        return Err(DecodeError::BodyLengthMismatch {
            declared: body_len,
            available: body_slice.len() as u64,
        });
    }

    let compressed = (flags & FLAG_COMPRESSED) != 0;
    // rkyv's archive validator requires the bytes to be aligned to
    // the archive's max alignment. The body slice is just an offset
    // into a `Vec<u8>` which has u8 alignment, so we re-copy into
    // an `AlignedVec` before validating.
    let aligned: AlignedVec<16> = if compressed {
        let decompressed = zstd::decode_all(body_slice).map_err(DecodeError::Decompress)?;
        let mut a = AlignedVec::with_capacity(decompressed.len());
        a.extend_from_slice(&decompressed);
        a
    } else {
        let mut a = AlignedVec::with_capacity(body_slice.len());
        a.extend_from_slice(body_slice);
        a
    };
    let patch = rkyv::from_bytes::<Patch, RkyvError>(&aligned).map_err(DecodeError::Rkyv)?;
    Ok(Decoded {
        patch,
        format_version: version,
        compressed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_patch() -> Patch {
        let mut p = Patch::new();
        p.write(2, vec![0xAA, 0xBB]).unwrap();
        p.insert(8, vec![0xCC, 0xDD, 0xEE]).unwrap();
        p.delete(16, 4).unwrap();
        p
    }

    fn encode_never(p: &Patch) -> Vec<u8> {
        encode(p, Compression::Never).unwrap().bytes
    }

    #[test]
    fn round_trip_uncompressed() {
        let p = sample_patch();
        let encoded = encode(&p, Compression::Never).unwrap();
        assert!(!encoded.compressed);
        let decoded = decode(&encoded.bytes).unwrap();
        assert!(!decoded.compressed);
        assert_eq!(decoded.format_version, FORMAT_VERSION);
        assert_eq!(decoded.patch, p);
    }

    #[test]
    fn round_trip_compressed() {
        let p = sample_patch();
        let encoded = encode(&p, Compression::Always).unwrap();
        assert!(encoded.compressed);
        let decoded = decode(&encoded.bytes).unwrap();
        assert!(decoded.compressed);
        assert_eq!(decoded.patch, p);
    }

    #[test]
    fn compression_shrinks_repetitive_payloads() {
        // 64 KiB of zeros archives to >= 64 KiB rkyv but compresses
        // to a few hundred bytes -- a sanity check that the
        // compressed bit actually flows through to zstd.
        let mut p = Patch::new();
        p.write(0, vec![0u8; 64 * 1024]).unwrap();
        let raw = encode(&p, Compression::Never).unwrap().bytes;
        let zst = encode(&p, Compression::Always).unwrap().bytes;
        assert!(
            zst.len() * 4 < raw.len(),
            "compressed {} not meaningfully smaller than raw {}",
            zst.len(),
            raw.len()
        );
    }

    #[test]
    fn auto_picks_compressed_for_repetitive_payloads() {
        let mut p = Patch::new();
        p.write(0, vec![0u8; 64 * 1024]).unwrap();
        let auto = encode(&p, Compression::Auto).unwrap();
        assert!(auto.compressed, "auto should compress 64 KiB of zeros");
        // and the resulting bytes round-trip
        assert_eq!(decode(&auto.bytes).unwrap().patch, p);
    }

    #[test]
    fn auto_matches_smaller_of_raw_and_compressed() {
        // The heuristic is "pick the smaller, ties go to raw".
        // We don't pin which one wins for any particular input
        // (rkyv layout + zstd framing make the crossover point
        // version-dependent) -- we just check that Auto's choice
        // and size match whichever Always/Never branch is smaller.
        let cases = [
            Patch::new(),
            {
                let mut p = Patch::new();
                p.write(0, b"hello".to_vec()).unwrap();
                p
            },
            {
                let mut p = Patch::new();
                p.write(0, vec![0u8; 64 * 1024]).unwrap();
                p
            },
        ];
        for p in cases {
            let raw = encode(&p, Compression::Never).unwrap();
            let zst = encode(&p, Compression::Always).unwrap();
            let auto = encode(&p, Compression::Auto).unwrap();
            if zst.bytes.len() < raw.bytes.len() {
                assert!(auto.compressed);
                assert_eq!(auto.bytes.len(), zst.bytes.len());
            } else {
                // ties go to raw
                assert!(!auto.compressed);
                assert_eq!(auto.bytes.len(), raw.bytes.len());
            }
            assert_eq!(decode(&auto.bytes).unwrap().patch, p);
        }
    }

    #[test]
    fn header_layout_is_stable() {
        let p = Patch::new();
        let bytes = encode_never(&p);
        assert_eq!(&bytes[0..6], MAGIC);
        assert_eq!(
            u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
            FORMAT_VERSION
        );
        assert_eq!(bytes[8], 0); // flags
        assert_eq!(bytes[9], 0); // reserved
        let body_len = u64::from_le_bytes(bytes[10..18].try_into().unwrap());
        assert_eq!(body_len as usize, bytes.len() - HEADER_LEN);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = encode_never(&sample_patch());
        bytes[0] = b'X';
        assert!(matches!(decode(&bytes), Err(DecodeError::BadMagic { .. })));
    }

    #[test]
    fn rejects_unknown_version() {
        let mut bytes = encode_never(&sample_patch());
        bytes[6] = 0xFF;
        bytes[7] = 0xFF;
        assert!(matches!(
            decode(&bytes),
            Err(DecodeError::UnsupportedVersion { found: 0xFFFF, .. })
        ));
    }

    #[test]
    fn rejects_unknown_flags() {
        let mut bytes = encode_never(&sample_patch());
        bytes[8] = 0b1000_0000;
        assert!(matches!(
            decode(&bytes),
            Err(DecodeError::UnknownFlags { .. })
        ));
    }

    #[test]
    fn rejects_short_header() {
        assert!(matches!(
            decode(&[1, 2, 3]),
            Err(DecodeError::ShortHeader { got: 3 })
        ));
    }

    #[test]
    fn rejects_body_length_mismatch() {
        let mut bytes = encode_never(&sample_patch());
        // bump declared body length past what's actually present
        let declared = u64::from_le_bytes(bytes[10..18].try_into().unwrap());
        let bumped = declared + 100;
        bytes[10..18].copy_from_slice(&bumped.to_le_bytes());
        assert!(matches!(
            decode(&bytes),
            Err(DecodeError::BodyLengthMismatch { .. })
        ));
    }
}
