//! [`PatchTarget`] -- the trait describing a buffer a
//! [`Patch`](crate::Patch) can be applied to in place.
//!
//! Implementors expose a single operation: replace
//! `self[offset..offset + old_len]` with `new_bytes`. That covers
//! the full splice vocabulary (writes, inserts, deletes,
//! length-changing replacements).
//!
//! Fixed-size targets (`&mut [u8]`) reject length-changing splices
//! at the sink level by returning
//! [`BufferError::LengthChangeUnsupported`]; growable targets
//! (`Vec<u8>`, `std::fs::File`) handle every shape.
//!
//! In-place apply performs *no* metadata verification -- there's no
//! byte-level read-back through this trait. Callers that want
//! digest verification should read the target's bytes and invoke
//! [`SourceMetadata::verify`](crate::SourceMetadata::verify) before
//! calling [`Patch::apply_to`](crate::Patch::apply_to).

use core::fmt;
use std::io;

/// A buffer a [`Patch`](crate::Patch) can be spliced into in place.
pub trait PatchTarget {
    type Error: core::error::Error + 'static;

    /// Replace `self[offset..offset + old_len]` with `new_bytes`.
    ///
    /// `old_len == new_bytes.len()` is a length-preserving write,
    /// `old_len == 0` is a pure insert, `new_bytes.is_empty()` is a
    /// pure delete. Implementors that can't grow or shrink must
    /// return an error when `old_len != new_bytes.len()`.
    fn splice_at(&mut self, offset: u64, old_len: u64, new_bytes: &[u8]) -> Result<(), Self::Error>;
}

/// Error returned by [`Patch::apply_to`](crate::Patch::apply_to).
#[derive(Debug)]
pub enum ApplyToError<E> {
    /// Patch ops are out of source order. Only reachable for patches
    /// built via [`Patch::push_op`](crate::Patch::push_op), which
    /// bypasses the sort-and-overlap check.
    OutOfOrder { offset: u64, cursor: u64 },
    /// The target's own error -- usually bounds or capability
    /// ([`BufferError`]) or I/O ([`std::io::Error`]).
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

/// Error returned by the [`PatchTarget`] impls for `[u8]` and
/// `Vec<u8>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferError {
    /// The splice range extends past the target's current length.
    OutOfBounds { offset: u64, old_len: u64, buffer_len: u64 },
    /// A length-changing splice was submitted to a fixed-size
    /// target. Returned by `<[u8] as PatchTarget>::splice_at`.
    LengthChangeUnsupported { offset: u64, old_len: u64, new_len: u64 },
}

impl fmt::Display for BufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BufferError::OutOfBounds { offset, old_len, buffer_len } => write!(
                f,
                "splice at [{offset}, {}) exceeds buffer length {buffer_len}",
                offset + old_len
            ),
            BufferError::LengthChangeUnsupported { offset, old_len, new_len } => write!(
                f,
                "splice at {offset} changes length ({old_len} -> {new_len}); target is fixed-size"
            ),
        }
    }
}

impl core::error::Error for BufferError {}

// --- impls --------------------------------------------------------

impl PatchTarget for [u8] {
    type Error = BufferError;

    fn splice_at(&mut self, offset: u64, old_len: u64, new_bytes: &[u8]) -> Result<(), Self::Error> {
        let new_len = new_bytes.len() as u64;
        if old_len != new_len {
            return Err(BufferError::LengthChangeUnsupported { offset, old_len, new_len });
        }
        let buffer_len = <[u8]>::len(self) as u64;
        let end = offset.checked_add(old_len).filter(|end| *end <= buffer_len);
        let Some(end) = end else {
            return Err(BufferError::OutOfBounds { offset, old_len, buffer_len });
        };
        self[offset as usize..end as usize].copy_from_slice(new_bytes);
        Ok(())
    }
}

impl PatchTarget for Vec<u8> {
    type Error = BufferError;

    fn splice_at(&mut self, offset: u64, old_len: u64, new_bytes: &[u8]) -> Result<(), Self::Error> {
        let buffer_len = self.len() as u64;
        let end = offset.checked_add(old_len).filter(|end| *end <= buffer_len);
        let Some(end) = end else {
            return Err(BufferError::OutOfBounds { offset, old_len, buffer_len });
        };
        let start = offset as usize;
        let end = end as usize;
        Vec::splice(self, start..end, new_bytes.iter().copied());
        Ok(())
    }
}

impl PatchTarget for std::fs::File {
    type Error = io::Error;

    fn splice_at(&mut self, offset: u64, old_len: u64, new_bytes: &[u8]) -> Result<(), Self::Error> {
        use io::{Read, Seek, SeekFrom, Write};

        // Fast path: length-preserving writes skip the
        // read-tail / rewrite dance entirely.
        if old_len == new_bytes.len() as u64 {
            self.seek(SeekFrom::Start(offset))?;
            return self.write_all(new_bytes);
        }

        let file_len = self.metadata()?.len();
        let tail_start = offset
            .checked_add(old_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "splice range overflows u64"))?;
        if tail_start > file_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("splice range [{offset}, {tail_start}) exceeds file length {file_len}"),
            ));
        }

        let mut tail = Vec::with_capacity((file_len - tail_start) as usize);
        self.seek(SeekFrom::Start(tail_start))?;
        self.read_to_end(&mut tail)?;

        self.seek(SeekFrom::Start(offset))?;
        self.write_all(new_bytes)?;
        self.write_all(&tail)?;

        let new_len = offset + new_bytes.len() as u64 + tail.len() as u64;
        self.set_len(new_len)?;
        Ok(())
    }
}
