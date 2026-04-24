//! In-memory binary patches.
//!
//! A [`Patch`] is an ordered list of `(offset, old_len, new_bytes)`
//! splices over a base buffer. The splice form covers in-place
//! writes, inserts, deletes, and length-changing replacements.
//!
//! [`Patch::apply`] returns a new `Vec<u8>`; [`Patch::apply_to`]
//! mutates any [`PatchTarget`](target::PatchTarget) in place
//! (`Vec<u8>`, `std::fs::File`, or a fixed-size `&mut [u8]`);
//! [`Patch::stream_to`] writes through an [`std::io::Write`] sink.
//!
//! A patch can carry a [`SourceMetadata`](metadata::SourceMetadata)
//! block describing the buffer it was generated against; `apply`
//! and `stream_to` verify the source against it before splicing.
//!
//! Features:
//! - `serde`, `rkyv` — derives on the public types.
//! - `blake3`, `sha2` — matching
//!   [`HashAlgorithm`](metadata::HashAlgorithm) variants.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod metadata;
pub mod target;

mod patch;

pub use patch::ApplyError;
pub use patch::ApplyToError;
pub use patch::BuildError;
pub use patch::Patch;
pub use patch::PatchOp;
