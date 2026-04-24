//! Binary patches: an ordered overlay of byte splices over a base
//! buffer.
//!
//! A [`Patch`] is a list of `(offset, old_len, new_bytes)` splices
//! that, applied to a base buffer, produce a modified version. The
//! splice form covers in-place writes, inserts, deletes, replacements
//! that change length, and truncation -- pure writes are just
//! splices where `old_len == new_bytes.len()`.
//!
//! Patches are storage-agnostic: apply them to a `Vec<u8>`, return a
//! freshly-built `Vec<u8>`, or stream them through any
//! [`std::io::Write`] sink alongside the source bytes.
//!
//! A patch can carry [`SourceMetadata`] -- the length, an optional
//! content digest, and / or filesystem metadata describing the base
//! the patch was generated against. [`Patch::apply`] verifies the
//! source against this metadata before splicing;
//! [`Patch::apply_unchecked`] is the `unsafe` escape hatch that
//! skips verification when the caller already knows the source is
//! the expected one.
//!
//! Optional features:
//! - `serde` and `rkyv` add the matching derives on the public types.
//! - `blake3` and `sha2` enable the matching [`HashAlgorithm`]
//!   variants and `SourceMetadata::compute_*` helpers.

#![forbid(unsafe_op_in_unsafe_fn)]

mod metadata;
mod patch;

pub use metadata::FileMetadata;
pub use metadata::HashAlgorithm;
pub use metadata::SourceDigest;
pub use metadata::SourceMetadata;
pub use metadata::VerifyError;
pub use patch::ApplyError;
pub use patch::BuildError;
pub use patch::Patch;
pub use patch::PatchOp;
