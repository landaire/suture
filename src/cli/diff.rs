//! `suture diff` -- build a [`Patch`] from a source/target pair
//! using the `similar` crate's Myers diff.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use clap::Args;
use clap::ValueEnum;
use similar::Algorithm;
use similar::DiffOp;
use similar::capture_diff_slices_deadline;

use super::CliError;
use super::DigestKind;
use super::Stdio;
use super::read_path;
use super::write_path;
use crate::Patch;
use crate::PatchOp;
use crate::format;
use crate::metadata::SourceMetadata;

/// Default diff timeout. The Myers algorithm is O(N*D) and can blow
/// up on large pathological inputs; bailing to an approximate diff
/// after a minute is a sensible default for an interactive CLI.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

#[derive(Args, Debug)]
pub struct DiffArgs {
    /// Original (pre-edit) file.
    pub source: PathBuf,
    /// Modified (post-edit) file.
    pub target: PathBuf,
    /// Where to write the patch. Defaults to stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Compression policy for the patch body.
    ///
    /// `auto` (the default) tries the body both raw and
    /// zstd-compressed and keeps whichever is smaller -- so small
    /// patches stay raw (where zstd framing would only add bytes)
    /// and large repetitive patches shrink dramatically.
    #[arg(long, value_enum, default_value_t = CompressionMode::Auto)]
    pub compression: CompressionMode,
    /// Maximum wall-clock time the diff may spend before falling
    /// back to an approximate result. Filesystem-agnostic source
    /// data (length + digest) is recorded regardless of timeout.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub timeout: u64,
    /// Source-content digest to record alongside the source length.
    /// Used by `apply` to detect being run against the wrong file.
    #[arg(long, value_enum, default_value_t = DigestKind::Blake3)]
    pub digest: DigestKind,
}

/// CLI mirror of [`format::Compression`]. Kept separate so the
/// clap-facing names ("auto" / "always" / "never") are decoupled
/// from internal renames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CompressionMode {
    /// Pick the smaller of compressed and raw.
    Auto,
    /// Always compress the body.
    Always,
    /// Never compress.
    Never,
}

impl CompressionMode {
    fn into_format(self) -> format::Compression {
        match self {
            CompressionMode::Auto => format::Compression::Auto,
            CompressionMode::Always => format::Compression::Always,
            CompressionMode::Never => format::Compression::Never,
        }
    }
}

pub fn run(args: DiffArgs, io: &mut Stdio<'_>) -> Result<(), CliError> {
    let source = read_path(&args.source)?;
    let target = read_path(&args.target)?;

    let timeout = Duration::from_secs(args.timeout);
    let started = Instant::now();
    let patch = build_patch(&source, &target, timeout, args.digest);
    let elapsed = started.elapsed();

    let encoded = format::encode(&patch, args.compression.into_format())
        .map_err(|e| format!("encode: {e}"))?;

    match &args.output {
        Some(path) => {
            write_path(path, &encoded.bytes)?;
            writeln!(
                io.err,
                "wrote {} ({} ops, {} bytes) to {} in {:?}",
                if encoded.compressed {
                    "compressed patch"
                } else {
                    "patch"
                },
                patch.len(),
                encoded.bytes.len(),
                path.display(),
                elapsed,
            )?;
        }
        None => {
            io.out.write_all(&encoded.bytes)?;
        }
    }
    Ok(())
}

/// Compute the diff and assemble it into a [`Patch`] with
/// filesystem-agnostic source metadata (length + optional digest).
///
/// We deliberately do *not* record the source path or filesystem
/// stat -- those are caller-context, not patch content. A patch
/// produced from a file at `/tmp/a` should apply just as cleanly
/// to a copy of those same bytes at any other path.
///
/// `similar`'s Myers/Patience implementations emit raw ops in the
/// algorithm's traversal order, which isn't necessarily monotonic
/// in source position (the `old_index` of an `Insert` can land
/// inside a previously-emitted `Delete` range). [`Patch`] requires
/// strictly source-ordered, non-overlapping splices, so we ignore
/// the raw `Delete`/`Insert`/`Replace` records and rebuild the
/// patch from the `Equal` runs only: those define what stays, and
/// the gaps between them define what changes.
pub fn build_patch(source: &[u8], target: &[u8], timeout: Duration, digest: DigestKind) -> Patch {
    let deadline = Instant::now().checked_add(timeout);
    let raw_ops = capture_diff_slices_deadline(Algorithm::Myers, source, target, deadline);

    let mut metadata = SourceMetadata::new(source.len() as u64);
    if let Some(algo) = digest.into_algorithm() {
        metadata = metadata.with_digest(algo.digest(source));
    }
    let mut patch = Patch::with_metadata(metadata);

    // Equal anchors form the LCS, monotonic in both old and new.
    // We collect them and bracket with virtual zero-length anchors
    // at (0, 0) and (source.len(), target.len()) so a single
    // pass over consecutive pairs covers every gap, including any
    // leading/trailing change region.
    let mut anchors: Vec<Anchor> = vec![Anchor {
        old_start: 0,
        new_start: 0,
        len: 0,
    }];
    for op in &raw_ops {
        if let DiffOp::Equal {
            old_index,
            new_index,
            len,
        } = *op
        {
            anchors.push(Anchor {
                old_start: old_index,
                new_start: new_index,
                len,
            });
        }
    }
    anchors.push(Anchor {
        old_start: source.len(),
        new_start: target.len(),
        len: 0,
    });
    anchors.sort_by_key(|a| (a.old_start, a.new_start));

    for win in anchors.windows(2) {
        let prev = win[0];
        let next = win[1];
        let old_gap_start = prev.old_start + prev.len;
        let new_gap_start = prev.new_start + prev.len;
        // sorted Equals are non-overlapping, so the gap end is at
        // or past its start; identical anchors collapse to a no-op.
        let old_gap_len = next.old_start.saturating_sub(old_gap_start);
        let new_gap_len = next.new_start.saturating_sub(new_gap_start);
        if old_gap_len == 0 && new_gap_len == 0 {
            continue;
        }
        let new_bytes = target[new_gap_start..new_gap_start + new_gap_len].to_vec();
        let old_offset = old_gap_start as u64;
        let old_len = old_gap_len as u64;
        let op = match (old_gap_len, new_gap_len) {
            (0, _) => PatchOp::insert(old_offset, new_bytes),
            (_, 0) => PatchOp::delete(old_offset, old_len),
            _ => PatchOp::splice(old_offset, old_len, new_bytes),
        };
        // Anchors are strictly increasing, so gaps are
        // non-overlapping and source-ordered by construction.
        patch.push_op(op);
    }
    patch
}

#[derive(Clone, Copy)]
struct Anchor {
    old_start: usize,
    new_start: usize,
    len: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_via_apply_reproduces_target() {
        let source = b"hello world\nthis is line two\nthis is line three\n".to_vec();
        let target =
            b"hello WORLD\nthis is line two\nbrand new line\nthis is line three\n".to_vec();
        let patch = build_patch(
            &source,
            &target,
            Duration::from_secs(60),
            DigestKind::Blake3,
        );
        let applied = patch.apply(&source).unwrap();
        assert_eq!(applied, target);
    }

    #[test]
    fn metadata_records_length_and_digest() {
        let source = b"abc".to_vec();
        let target = b"abd".to_vec();
        let patch = build_patch(
            &source,
            &target,
            Duration::from_secs(60),
            DigestKind::Blake3,
        );
        let meta = patch.metadata().expect("metadata recorded");
        assert_eq!(meta.len, source.len() as u64);
        let digest = meta.digest.as_ref().expect("digest recorded");
        assert_eq!(digest.algorithm, crate::metadata::HashAlgorithm::Blake3);
    }

    #[test]
    fn digest_none_omits_digest_but_keeps_length() {
        let source = b"abc".to_vec();
        let target = b"abd".to_vec();
        let patch = build_patch(&source, &target, Duration::from_secs(60), DigestKind::None);
        let meta = patch.metadata().expect("metadata recorded");
        assert_eq!(meta.len, 3);
        assert!(meta.digest.is_none());
    }

    #[test]
    fn round_trip_handles_non_monotonic_myers_ops() {
        // Regression: similar's Myers/Patience emit ops in
        // traversal order, not source order. The "keep me safe"/
        // "keep me edited" pair in particular trips this. We
        // canonicalise via Equal anchors; the resulting patch
        // must apply cleanly.
        let src = b"keep me safe".to_vec();
        let tgt = b"keep me edited".to_vec();
        let patch = build_patch(&src, &tgt, Duration::from_secs(60), DigestKind::None);
        assert_eq!(patch.apply(&src).unwrap(), tgt);
    }

    #[test]
    fn round_trip_when_target_is_completely_different() {
        let src = b"abcdef".to_vec();
        let tgt = b"xyz".to_vec();
        let patch = build_patch(&src, &tgt, Duration::from_secs(60), DigestKind::None);
        assert_eq!(patch.apply(&src).unwrap(), tgt);
    }

    #[test]
    fn round_trip_when_one_side_is_empty() {
        let empty = Vec::<u8>::new();
        let bytes = b"hello".to_vec();
        let p = build_patch(&empty, &bytes, Duration::from_secs(60), DigestKind::None);
        assert_eq!(p.apply(&empty).unwrap(), bytes);
        let p = build_patch(&bytes, &empty, Duration::from_secs(60), DigestKind::None);
        assert_eq!(p.apply(&bytes).unwrap(), empty);
    }

    #[test]
    fn empty_diff_produces_zero_ops() {
        let bytes = b"unchanged".to_vec();
        let patch = build_patch(&bytes, &bytes, Duration::from_secs(60), DigestKind::None);
        assert!(patch.is_empty());
    }
}
