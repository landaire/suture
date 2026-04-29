//! In-place application targets.

use core::fmt;
use std::io;

/// A buffer [`Patch::apply_to`](crate::Patch::apply_to) can splice into.
pub trait PatchTarget {
    type Error: core::error::Error + 'static;

    /// Replace `self[offset..offset + old_len]` with `new_bytes`.
    ///
    /// `old_len == 0` is a pure insert; `new_bytes.is_empty()` is a
    /// pure delete; `old_len == new_bytes.len()` is a length-
    /// preserving write. Implementations that can't change length
    /// must return an error when `old_len != new_bytes.len()`.
    fn splice_at(&mut self, offset: u64, old_len: u64, new_bytes: &[u8])
    -> Result<(), Self::Error>;
}

/// Error returned by the stock [`PatchTarget`] impls for `[u8]` and
/// `Vec<u8>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferError {
    OutOfBounds {
        offset: u64,
        old_len: u64,
        buffer_len: u64,
    },
    /// `old_len != new_bytes.len()` on a fixed-size target.
    LengthChangeUnsupported {
        offset: u64,
        old_len: u64,
        new_len: u64,
    },
}

impl fmt::Display for BufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BufferError::OutOfBounds {
                offset,
                old_len,
                buffer_len,
            } => write!(
                f,
                "splice at [{offset}, {}) exceeds buffer length {buffer_len}",
                offset + old_len
            ),
            BufferError::LengthChangeUnsupported {
                offset,
                old_len,
                new_len,
            } => write!(
                f,
                "splice at {offset} changes length ({old_len} -> {new_len}); target is fixed-size"
            ),
        }
    }
}

impl core::error::Error for BufferError {}

impl PatchTarget for [u8] {
    type Error = BufferError;

    fn splice_at(
        &mut self,
        offset: u64,
        old_len: u64,
        new_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let new_len = new_bytes.len() as u64;
        if old_len != new_len {
            return Err(BufferError::LengthChangeUnsupported {
                offset,
                old_len,
                new_len,
            });
        }
        let buffer_len = <[u8]>::len(self) as u64;
        let end = offset.checked_add(old_len).filter(|end| *end <= buffer_len);
        let Some(end) = end else {
            return Err(BufferError::OutOfBounds {
                offset,
                old_len,
                buffer_len,
            });
        };
        self[offset as usize..end as usize].copy_from_slice(new_bytes);
        Ok(())
    }
}

impl PatchTarget for Vec<u8> {
    type Error = BufferError;

    fn splice_at(
        &mut self,
        offset: u64,
        old_len: u64,
        new_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        let buffer_len = self.len() as u64;
        let end = offset.checked_add(old_len).filter(|end| *end <= buffer_len);
        let Some(end) = end else {
            return Err(BufferError::OutOfBounds {
                offset,
                old_len,
                buffer_len,
            });
        };
        let start = offset as usize;
        let end = end as usize;
        Vec::splice(self, start..end, new_bytes.iter().copied());
        Ok(())
    }
}

impl PatchTarget for std::fs::File {
    type Error = FileTargetError;

    /// Length-preserving writes seek + write in place. Length-
    /// changing splices buffer the tail (`offset + old_len .. EOF`)
    /// in memory, rewrite, and `set_len` to the new size.
    fn splice_at(
        &mut self,
        offset: u64,
        old_len: u64,
        new_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        use io::Read;
        use io::Seek;
        use io::SeekFrom;
        use io::Write;

        if old_len == new_bytes.len() as u64 {
            self.seek(SeekFrom::Start(offset))?;
            self.write_all(new_bytes)?;
            return Ok(());
        }

        let file_len = self.metadata()?.len();
        let tail_start = offset
            .checked_add(old_len)
            .ok_or(FileTargetError::SpliceRangeOverflow { offset, old_len })?;
        if tail_start > file_len {
            return Err(FileTargetError::OutOfBounds {
                offset,
                old_len,
                file_len,
            });
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

#[derive(Debug)]
pub enum FileTargetError {
    Io(io::Error),
    /// The splice range extends past the file's current length.
    OutOfBounds {
        offset: u64,
        old_len: u64,
        file_len: u64,
    },
    /// `offset + old_len` overflows `u64`.
    SpliceRangeOverflow {
        offset: u64,
        old_len: u64,
    },
}

impl fmt::Display for FileTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileTargetError::Io(e) => write!(f, "file i/o error: {e}"),
            FileTargetError::OutOfBounds {
                offset,
                old_len,
                file_len,
            } => write!(
                f,
                "splice at [{offset}, {}) exceeds file length {file_len}",
                offset + old_len
            ),
            FileTargetError::SpliceRangeOverflow { offset, old_len } => {
                write!(
                    f,
                    "splice range offset {offset} + old_len {old_len} overflows u64"
                )
            }
        }
    }
}

impl core::error::Error for FileTargetError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            FileTargetError::Io(e) => Some(e),
            FileTargetError::OutOfBounds { .. } | FileTargetError::SpliceRangeOverflow { .. } => {
                None
            }
        }
    }
}

impl From<io::Error> for FileTargetError {
    fn from(e: io::Error) -> Self {
        FileTargetError::Io(e)
    }
}
