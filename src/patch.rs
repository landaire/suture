//! [`Patch`] and [`PatchOp`].

use core::fmt;
use std::io;

use crate::metadata::SourceMetadata;
use crate::metadata::VerifyError;
use crate::target::PatchTarget;

/// One splice in a [`Patch`].
///
/// `offset` and `old_len` are in the source's coordinate system;
/// applying replaces `source[offset..offset + old_len]` with
/// `new_bytes`. `old_len == 0` is a pure insert, `new_bytes.is_empty()`
/// is a pure delete, `old_len == new_bytes.len()` is an in-place write.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
pub struct PatchOp {
    pub offset: u64,
    pub old_len: u64,
    pub new_bytes: Vec<u8>,
}

impl PatchOp {
    pub fn write(offset: u64, bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        Self { offset, old_len: bytes.len() as u64, new_bytes: bytes }
    }

    pub fn insert(offset: u64, bytes: impl Into<Vec<u8>>) -> Self {
        Self { offset, old_len: 0, new_bytes: bytes.into() }
    }

    pub fn delete(offset: u64, len: u64) -> Self {
        Self { offset, old_len: len, new_bytes: Vec::new() }
    }

    pub fn splice(offset: u64, old_len: u64, new_bytes: impl Into<Vec<u8>>) -> Self {
        Self { offset, old_len, new_bytes: new_bytes.into() }
    }

    fn source_end(&self) -> u64 {
        self.offset + self.old_len
    }
}

/// Ordered list of splices over a base buffer plus optional
/// [`SourceMetadata`] for verification.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
pub struct Patch {
    ops: Vec<PatchOp>,
    metadata: Option<SourceMetadata>,
}

impl Patch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_metadata(metadata: SourceMetadata) -> Self {
        Self { ops: Vec::new(), metadata: Some(metadata) }
    }

    pub fn metadata(&self) -> Option<&SourceMetadata> {
        self.metadata.as_ref()
    }

    pub fn set_metadata(&mut self, metadata: SourceMetadata) {
        self.metadata = Some(metadata);
    }

    pub fn clear_metadata(&mut self) {
        self.metadata = None;
    }

    pub fn ops(&self) -> &[PatchOp] {
        &self.ops
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Output length after splicing into a source of `source_len`
    /// bytes. Does not validate ordering or bounds.
    pub fn output_len(&self, source_len: u64) -> u64 {
        let mut out = source_len as i64;
        for op in &self.ops {
            out += op.new_bytes.len() as i64 - op.old_len as i64;
        }
        out as u64
    }

    /// Append an op without sorting or overlap-checking. Prefer
    /// [`Patch::splice`] / [`write`](Patch::write) /
    /// [`insert`](Patch::insert) / [`delete`](Patch::delete) unless
    /// rebuilding from a known-good source (e.g. a deserialised
    /// patch).
    pub fn push_op(&mut self, op: PatchOp) {
        self.ops.push(op);
    }

    pub fn splice(&mut self, offset: u64, old_len: u64, new_bytes: impl Into<Vec<u8>>) -> Result<(), BuildError> {
        self.insert_op(PatchOp::splice(offset, old_len, new_bytes))
    }

    pub fn write(&mut self, offset: u64, new_bytes: impl Into<Vec<u8>>) -> Result<(), BuildError> {
        self.insert_op(PatchOp::write(offset, new_bytes))
    }

    pub fn insert(&mut self, offset: u64, new_bytes: impl Into<Vec<u8>>) -> Result<(), BuildError> {
        self.insert_op(PatchOp::insert(offset, new_bytes))
    }

    pub fn delete(&mut self, offset: u64, len: u64) -> Result<(), BuildError> {
        self.insert_op(PatchOp::delete(offset, len))
    }

    fn insert_op(&mut self, op: PatchOp) -> Result<(), BuildError> {
        let new_end = op.source_end();
        let pos = self.ops.partition_point(|existing| existing.offset < op.offset);
        if let Some(prev) = pos.checked_sub(1).and_then(|i| self.ops.get(i))
            && prev.source_end() > op.offset
        {
            return Err(BuildError::Overlap {
                offset: op.offset,
                existing_offset: prev.offset,
                existing_old_len: prev.old_len,
            });
        }
        if let Some(next) = self.ops.get(pos)
            && next.offset < new_end
        {
            return Err(BuildError::Overlap {
                offset: op.offset,
                existing_offset: next.offset,
                existing_old_len: next.old_len,
            });
        }
        self.ops.insert(pos, op);
        Ok(())
    }

    /// Apply into a new `Vec<u8>`. Verifies `source` against the
    /// patch's [`SourceMetadata`] (if any) first.
    pub fn apply(&self, source: &[u8]) -> Result<Vec<u8>, ApplyError> {
        if let Some(meta) = &self.metadata {
            meta.verify(source).map_err(ApplyError::Verify)?;
        }
        self.apply_inner(source)
    }

    /// Apply without verifying metadata.
    ///
    /// # Safety
    /// The caller must ensure:
    /// 1. `source` is the buffer the patch was built against.
    /// 2. `op.offset + op.old_len <= source.len()` for every op.
    ///
    /// The implementation uses checked slicing, so violating (2)
    /// panics rather than reading out of bounds. The `unsafe` marker
    /// documents the caller's obligation to have verified (1) and
    /// (2) out of band.
    pub unsafe fn apply_unchecked(&self, source: &[u8]) -> Vec<u8> {
        self.apply_inner(source).expect("apply_unchecked: invariants violated by caller")
    }

    fn apply_inner(&self, source: &[u8]) -> Result<Vec<u8>, ApplyError> {
        let source_len = source.len() as u64;
        let out_len = self.output_len(source_len);
        let mut out = Vec::with_capacity(out_len as usize);
        let mut cursor: u64 = 0;
        for op in &self.ops {
            if op.offset < cursor {
                return Err(ApplyError::OutOfOrder { offset: op.offset, cursor });
            }
            if op.source_end() > source_len {
                return Err(ApplyError::OutOfBounds {
                    offset: op.offset,
                    old_len: op.old_len,
                    source_len,
                });
            }
            out.extend_from_slice(&source[cursor as usize..op.offset as usize]);
            out.extend_from_slice(&op.new_bytes);
            cursor = op.source_end();
        }
        if cursor < source_len {
            out.extend_from_slice(&source[cursor as usize..]);
        }
        Ok(out)
    }

    /// Apply in place to `target`.
    ///
    /// Length-changing ops succeed on growable targets (`Vec<u8>`,
    /// `std::fs::File`) and fail on fixed-size ones (`&mut [u8]`)
    /// with [`BufferError::LengthChangeUnsupported`](crate::target::BufferError::LengthChangeUnsupported).
    ///
    /// Metadata is not verified -- the target isn't read back through
    /// the trait. Verify manually via
    /// [`SourceMetadata::verify`](crate::metadata::SourceMetadata::verify)
    /// if required.
    pub fn apply_to<T: PatchTarget + ?Sized>(&self, target: &mut T) -> Result<(), ApplyToError<T::Error>> {
        let mut cursor: u64 = 0;
        let mut delta: i64 = 0;
        for op in &self.ops {
            if op.offset < cursor {
                return Err(ApplyToError::OutOfOrder { offset: op.offset, cursor });
            }
            let target_offset = (op.offset as i64 + delta) as u64;
            target
                .splice_at(target_offset, op.old_len, &op.new_bytes)
                .map_err(ApplyToError::Sink)?;
            cursor = op.source_end();
            delta += op.new_bytes.len() as i64 - op.old_len as i64;
        }
        Ok(())
    }

    /// Stream the patched output through `sink`. Avoids the
    /// intermediate `Vec<u8>` that [`Patch::apply`] allocates.
    pub fn stream_to<W: io::Write>(&self, source: &[u8], sink: &mut W) -> Result<(), ApplyError> {
        if let Some(meta) = &self.metadata {
            meta.verify(source).map_err(ApplyError::Verify)?;
        }
        let source_len = source.len() as u64;
        let mut cursor: u64 = 0;
        for op in &self.ops {
            if op.offset < cursor {
                return Err(ApplyError::OutOfOrder { offset: op.offset, cursor });
            }
            if op.source_end() > source_len {
                return Err(ApplyError::OutOfBounds {
                    offset: op.offset,
                    old_len: op.old_len,
                    source_len,
                });
            }
            sink.write_all(&source[cursor as usize..op.offset as usize]).map_err(ApplyError::Io)?;
            sink.write_all(&op.new_bytes).map_err(ApplyError::Io)?;
            cursor = op.source_end();
        }
        if cursor < source_len {
            sink.write_all(&source[cursor as usize..]).map_err(ApplyError::Io)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum BuildError {
    /// A new splice overlaps an op already in the patch.
    Overlap { offset: u64, existing_offset: u64, existing_old_len: u64 },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::Overlap { offset, existing_offset, existing_old_len } => write!(
                f,
                "splice at {offset} overlaps existing op at [{existing_offset}, {})",
                existing_offset + existing_old_len
            ),
        }
    }
}

impl core::error::Error for BuildError {}

#[derive(Debug)]
pub enum ApplyError {
    Verify(VerifyError),
    OutOfOrder { offset: u64, cursor: u64 },
    OutOfBounds { offset: u64, old_len: u64, source_len: u64 },
    Io(io::Error),
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplyError::Verify(e) => write!(f, "source verification failed: {e}"),
            ApplyError::OutOfOrder { offset, cursor } => {
                write!(f, "splice at {offset} would re-cross cursor {cursor}; ops must be sorted by offset")
            }
            ApplyError::OutOfBounds { offset, old_len, source_len } => {
                write!(
                    f,
                    "splice [{offset}, {}) extends past source length {source_len}",
                    offset + old_len
                )
            }
            ApplyError::Io(e) => write!(f, "i/o error during stream_to: {e}"),
        }
    }
}

impl core::error::Error for ApplyError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            ApplyError::Verify(e) => Some(e),
            ApplyError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Error returned by [`Patch::apply_to`].
#[derive(Debug)]
pub enum ApplyToError<E> {
    /// Only reachable for patches built with [`Patch::push_op`].
    OutOfOrder { offset: u64, cursor: u64 },
    Sink(E),
}

impl<E: fmt::Display> fmt::Display for ApplyToError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplyToError::OutOfOrder { offset, cursor } => {
                write!(f, "op at {offset} would re-cross cursor {cursor}; ops must be sorted by offset")
            }
            ApplyToError::Sink(e) => write!(f, "target error: {e}"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for ApplyToError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            ApplyToError::Sink(e) => Some(e),
            ApplyToError::OutOfOrder { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_replaces_in_place() {
        let mut p = Patch::new();
        p.write(2, vec![0xAA, 0xBB]).unwrap();
        assert_eq!(p.apply(&[0u8; 8]).unwrap(), vec![0, 0, 0xAA, 0xBB, 0, 0, 0, 0]);
    }

    #[test]
    fn insert_grows_the_buffer() {
        let mut p = Patch::new();
        p.insert(2, vec![0xAA, 0xBB]).unwrap();
        assert_eq!(p.apply(b"01234").unwrap(), b"01\xAA\xBB234");
    }

    #[test]
    fn delete_shrinks_the_buffer() {
        let mut p = Patch::new();
        p.delete(2, 2).unwrap();
        assert_eq!(p.apply(b"012345").unwrap(), b"0145");
    }

    #[test]
    fn splice_replaces_with_different_length() {
        let mut p = Patch::new();
        p.splice(1, 2, vec![0xFF, 0xFE, 0xFD]).unwrap();
        assert_eq!(p.apply(b"01234").unwrap(), b"0\xFF\xFE\xFD34");
    }

    #[test]
    fn truncate_via_trailing_delete() {
        let mut p = Patch::new();
        p.delete(4, 4).unwrap();
        assert_eq!(p.apply(b"01234567").unwrap(), b"0123");
    }

    #[test]
    fn extend_via_insert_at_end() {
        let mut p = Patch::new();
        p.insert(4, vec![0xAA, 0xBB]).unwrap();
        assert_eq!(p.apply(b"0123").unwrap(), b"0123\xAA\xBB");
    }

    #[test]
    fn overlap_is_rejected() {
        let mut p = Patch::new();
        p.write(2, vec![0xAA, 0xBB]).unwrap();
        assert!(matches!(p.write(3, vec![0xCC]), Err(BuildError::Overlap { .. })));
    }

    #[test]
    fn unsorted_input_sorts_into_place() {
        let mut p = Patch::new();
        p.write(4, vec![0xCC]).unwrap();
        p.write(1, vec![0xAA]).unwrap();
        let ops = p.ops();
        assert_eq!(ops[0].offset, 1);
        assert_eq!(ops[1].offset, 4);
    }

    #[test]
    fn stream_to_matches_apply() {
        let source = (0u8..16).collect::<Vec<_>>();
        let mut p = Patch::new();
        p.write(4, vec![0xAA, 0xBB]).unwrap();
        p.insert(10, vec![0xCC]).unwrap();
        p.delete(14, 2).unwrap();
        let via_apply = p.apply(&source).unwrap();
        let mut via_stream = Vec::new();
        p.stream_to(&source, &mut via_stream).unwrap();
        assert_eq!(via_apply, via_stream);
    }

    #[test]
    fn apply_verifies_metadata() {
        let source = b"hello".to_vec();
        let mut p = Patch::with_metadata(SourceMetadata::new(source.len() as u64));
        p.write(0, vec![b'H']).unwrap();
        assert!(p.apply(&source).is_ok());
        assert!(p.apply(b"longer source").is_err());
    }

    #[test]
    fn apply_unchecked_skips_verification() {
        let mut p = Patch::with_metadata(SourceMetadata::new(99));
        p.write(0, vec![b'H']).unwrap();
        let out = unsafe { p.apply_unchecked(b"hello") };
        assert_eq!(out, b"Hello");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_round_trip_preserves_ops_and_metadata() {
        let mut p = Patch::with_metadata(SourceMetadata::new(16));
        p.write(2, vec![0xAA, 0xBB]).unwrap();
        p.insert(8, vec![0xCC]).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let back: Patch = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn output_len_accounts_for_growth_and_shrink() {
        let mut p = Patch::new();
        p.insert(0, vec![1, 2, 3]).unwrap();
        p.delete(5, 2).unwrap();
        assert_eq!(p.output_len(10), 10 + 3 - 2);
    }
}
