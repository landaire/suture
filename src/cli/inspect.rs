//! `suture inspect` -- describe a patch without applying it.
//!
//! Output is a human-readable summary on stdout: format version,
//! compression flag, source metadata, op count, and an op-by-op
//! listing. Stable enough to snapshot in tests.

use std::io::Write as _;
use std::path::PathBuf;

use clap::Args;

use super::CliError;
use super::Stdio;
use super::io_helpers::hex;
use super::read_path;
use crate::PatchOp;
use crate::format;
use crate::metadata::SourceMetadata;

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Patch file to describe.
    pub patch: PathBuf,
}

pub fn run(args: InspectArgs, io: &mut Stdio<'_>) -> Result<(), CliError> {
    let bytes = read_path(&args.patch)?;
    let decoded = format::decode(&bytes)
        .map_err(|e| format!("decode {}: {}", args.patch.display(), e))?;

    writeln!(io.out, "format version: {}", decoded.format_version)?;
    writeln!(io.out, "compressed:     {}", decoded.compressed)?;
    writeln!(io.out, "encoded size:   {} bytes", bytes.len())?;
    writeln!(io.out, "ops:            {}", decoded.patch.len())?;

    print_metadata(io, decoded.patch.metadata())?;
    print_ops(io, decoded.patch.ops())?;
    Ok(())
}

fn print_metadata(io: &mut Stdio<'_>, meta: Option<&SourceMetadata>) -> std::io::Result<()> {
    let Some(meta) = meta else {
        writeln!(io.out, "metadata:       (none)")?;
        return Ok(());
    };
    writeln!(io.out, "source length:  {} bytes", meta.len)?;
    if let Some(d) = &meta.digest {
        writeln!(io.out, "source digest:  {} {}", d.algorithm, hex(&d.bytes))?;
    } else {
        writeln!(io.out, "source digest:  (none)")?;
    }
    if let Some(file) = meta.file {
        writeln!(
            io.out,
            "source file:    size={} mtime={}.{:09}",
            file.size, file.mtime_seconds, file.mtime_nanos
        )?;
    }
    Ok(())
}

fn print_ops(io: &mut Stdio<'_>, ops: &[PatchOp]) -> std::io::Result<()> {
    if ops.is_empty() {
        return Ok(());
    }
    writeln!(io.out)?;
    writeln!(io.out, "  # offset      old_len  new_len  kind")?;
    for (i, op) in ops.iter().enumerate() {
        let kind = classify(op);
        writeln!(
            io.out,
            "  {i:>3} {:>10}  {:>7}  {:>7}  {kind}",
            op.offset,
            op.old_len,
            op.new_bytes.len(),
        )?;
    }
    Ok(())
}

fn classify(op: &PatchOp) -> &'static str {
    if op.old_len == 0 {
        "insert"
    } else if op.new_bytes.is_empty() {
        "delete"
    } else if op.old_len == op.new_bytes.len() as u64 {
        "write"
    } else {
        "splice"
    }
}
