//! `suture apply` -- apply a patch to a file in place.
//!
//! Behaviour:
//!
//! - Decodes the patch envelope and rejects unknown formats.
//! - Verifies the target file matches the patch's
//!   [`SourceMetadata`](crate::metadata::SourceMetadata). On
//!   mismatch, the user gets a warning naming the specific check
//!   that failed. In an interactive session we prompt the user to
//!   confirm; non-interactive sessions refuse and suggest
//!   `--force`. `--force` skips the prompt entirely.
//! - Backs up the target to `<file>.bak` (then `<file>.1.bak`, ...)
//!   before mutating it. `--no-backup` skips the copy.
//! - If `--output` is supplied, writes the result there instead of
//!   over the input. The backup step is then unnecessary and
//!   skipped.

use std::io::Write as _;
use std::path::PathBuf;

use clap::Args;

use super::CliError;
use super::Stdio;
use super::backup;
use super::read_path;
use super::write_path;
use crate::format;
use crate::metadata::SourceMetadata;
use crate::metadata::VerifyError;

#[derive(Args, Debug)]
pub struct ApplyArgs {
    /// Patch file produced by `suture diff`.
    pub patch: PathBuf,
    /// Target file to splice into.
    pub target: PathBuf,
    /// Write the result here instead of overwriting `target`. When
    /// set, no backup is created (the original is untouched).
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Don't create a `.bak` copy of the target before mutating it.
    #[arg(long)]
    pub no_backup: bool,
    /// Apply even if the target's length/digest doesn't match the
    /// patch's recorded source metadata. The mismatch is still
    /// reported on stderr so the operator knows what they overrode.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: ApplyArgs, io: &mut Stdio<'_>) -> Result<(), CliError> {
    let patch_bytes = read_path(&args.patch)?;
    let decoded = format::decode(&patch_bytes)
        .map_err(|e| format!("decode {}: {}", args.patch.display(), e))?;
    let target_bytes = read_path(&args.target)?;

    let mut patch = decoded.patch;
    if let Some(meta) = patch.metadata().cloned()
        && let Err(verify_err) = meta.verify(&target_bytes)
    {
        report_verify_warning(io, &args.target, &meta, &verify_err)?;
        if !args.force && !confirm_override(io)? {
            return Err("refusing to apply incompatible patch".into());
        }
        // The user has accepted the mismatch (via --force or the
        // prompt); clearing the metadata avoids a second rejection
        // inside `Patch::apply`'s built-in verification pass.
        patch.clear_metadata();
    }

    let result = patch
        .apply(&target_bytes)
        .map_err(|e| format!("apply: {e}"))?;

    let destination = args.output.as_ref().unwrap_or(&args.target);
    let writing_in_place = args.output.is_none();

    if writing_in_place && !args.no_backup {
        let bak = backup::make_backup(&args.target).map_err(|e| {
            format!(
                "failed to create backup of {}: {}",
                args.target.display(),
                e
            )
        })?;
        writeln!(io.err, "backed up {} -> {}", args.target.display(), bak.display())?;
    }

    write_path(destination, &result)?;
    writeln!(
        io.err,
        "applied {} ops ({} -> {} bytes) to {}",
        patch.len(),
        target_bytes.len(),
        result.len(),
        destination.display(),
    )?;
    Ok(())
}

/// Decide whether the user is OK with applying despite a metadata
/// mismatch. In a TTY we prompt; outside a TTY we refuse and
/// nudge them at `--force`. Returning `Ok(true)` means proceed.
fn confirm_override(io: &mut Stdio<'_>) -> std::io::Result<bool> {
    if !io.interactive {
        writeln!(
            io.err,
            "refusing to apply incompatible patch (pass --force to override, or run interactively to confirm)"
        )?;
        return Ok(false);
    }
    write!(io.err, "Apply this patch anyway? [y/N]: ")?;
    io.err.flush()?;
    let mut answer = String::new();
    let n = io.input.read_line(&mut answer)?;
    if n == 0 {
        // EOF on stdin -- treat as "no", same as a non-y reply
        writeln!(io.err)?;
        return Ok(false);
    }
    let answer = answer.trim();
    Ok(answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"))
}

/// Emit a structured warning describing how the target failed
/// verification. The message names the specific check (length vs
/// digest) so the operator can tell whether they have the wrong
/// file entirely or "just" a tampered copy.
fn report_verify_warning(
    io: &mut Stdio<'_>,
    target: &std::path::Path,
    meta: &SourceMetadata,
    err: &VerifyError,
) -> std::io::Result<()> {
    writeln!(
        io.err,
        "warning: {} does not match the patch's recorded source",
        target.display()
    )?;
    match err {
        VerifyError::LengthMismatch { expected, actual } => {
            writeln!(
                io.err,
                "  source length: expected {expected}, got {actual}"
            )?;
        }
        VerifyError::DigestMismatch { algorithm, .. } => {
            writeln!(
                io.err,
                "  source {algorithm} digest does not match"
            )?;
        }
    }
    if meta.digest.is_some() {
        writeln!(
            io.err,
            "  applying anyway may produce garbage; the patch was built against different bytes"
        )?;
    } else {
        writeln!(
            io.err,
            "  patch only recorded a length check; mismatch means the file is the wrong size"
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::DigestKind;
    use super::super::diff::build_patch;
    use std::time::Duration;

    /// Build a patch + write a file pair where the file's contents
    /// don't match the patch's source metadata. Returns
    /// `(patch_path, target_path, target_contents)`.
    fn mismatched_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let src = b"original bytes here".to_vec();
        let tgt = b"original BYTES here".to_vec();
        let patch =
            build_patch(&src, &tgt, Duration::from_secs(60), DigestKind::Blake3);
        let bytes = format::encode(&patch, format::Compression::Never).unwrap().bytes;
        let patch_path = dir.path().join("p.suture");
        let target_path = dir.path().join("file.bin");
        std::fs::write(&patch_path, &bytes).unwrap();
        // Same length so the digest -- not the length -- is what
        // trips verify(). That isolates the "file looks plausible
        // but isn't actually the right bytes" case the prompt is
        // designed for.
        let actual_target = b"completely diffrnt!".to_vec();
        assert_eq!(actual_target.len(), src.len());
        std::fs::write(&target_path, &actual_target).unwrap();
        (dir, patch_path, target_path, actual_target)
    }

    fn args(patch: &std::path::Path, target: &std::path::Path, force: bool) -> ApplyArgs {
        ApplyArgs {
            patch: patch.to_path_buf(),
            target: target.to_path_buf(),
            output: None,
            no_backup: true,
            force,
        }
    }

    #[test]
    fn interactive_prompt_yes_proceeds_with_apply() {
        let (_dir, patch, target, original_target) = mismatched_fixture();
        let mut out = Vec::<u8>::new();
        let mut err = Vec::<u8>::new();
        {
            let mut io = Stdio::from_streams(&b"y\n"[..], &mut out, &mut err, true);
            run(args(&patch, &target, false), &mut io).expect("apply succeeds after y");
        }
        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("Apply this patch anyway?"), "{stderr}");
        // file was rewritten -- contents differ from the original
        let written = std::fs::read(&target).unwrap();
        assert_ne!(written, original_target);
    }

    #[test]
    fn interactive_prompt_no_refuses() {
        let (_dir, patch, target, original_target) = mismatched_fixture();
        let mut out = Vec::<u8>::new();
        let mut err = Vec::<u8>::new();
        let result = {
            let mut io = Stdio::from_streams(&b"n\n"[..], &mut out, &mut err, true);
            run(args(&patch, &target, false), &mut io)
        };
        assert!(result.is_err(), "n should refuse");
        // file untouched
        assert_eq!(std::fs::read(&target).unwrap(), original_target);
    }

    #[test]
    fn interactive_empty_reply_treats_as_no() {
        // The prompt is "[y/N]:" -- a bare Enter must default to no.
        let (_dir, patch, target, original_target) = mismatched_fixture();
        let mut out = Vec::<u8>::new();
        let mut err = Vec::<u8>::new();
        let result = {
            let mut io = Stdio::from_streams(&b"\n"[..], &mut out, &mut err, true);
            run(args(&patch, &target, false), &mut io)
        };
        assert!(result.is_err());
        assert_eq!(std::fs::read(&target).unwrap(), original_target);
    }

    #[test]
    fn non_interactive_session_refuses_without_prompting() {
        let (_dir, patch, target, original_target) = mismatched_fixture();
        let mut out = Vec::<u8>::new();
        let mut err = Vec::<u8>::new();
        let result = {
            let mut io = Stdio::from_streams(&b""[..], &mut out, &mut err, false);
            run(args(&patch, &target, false), &mut io)
        };
        assert!(result.is_err());
        let stderr = String::from_utf8(err).unwrap();
        assert!(!stderr.contains("Apply this patch anyway?"), "{stderr}");
        assert!(stderr.contains("--force"), "{stderr}");
        assert_eq!(std::fs::read(&target).unwrap(), original_target);
    }

    #[test]
    fn force_skips_the_prompt_entirely() {
        let (_dir, patch, target, original_target) = mismatched_fixture();
        let mut out = Vec::<u8>::new();
        let mut err = Vec::<u8>::new();
        {
            // Empty stdin would EOF if read; with --force we never
            // touch input, so this proves the prompt is bypassed.
            let mut io = Stdio::from_streams(&b""[..], &mut out, &mut err, true);
            run(args(&patch, &target, true), &mut io).expect("force succeeds");
        }
        let stderr = String::from_utf8(err).unwrap();
        assert!(stderr.contains("warning"), "{stderr}");
        assert!(!stderr.contains("Apply this patch anyway?"), "{stderr}");
        assert_ne!(std::fs::read(&target).unwrap(), original_target);
    }
}
