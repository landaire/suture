//! `suture` command-line interface.
//!
//! Three subcommands:
//!
//! - `diff <source> <target>`  -- generate a patch from two files
//! - `apply <patch> <file>`    -- apply a patch to a file in place
//! - `inspect <patch>`         -- describe a patch without applying
//!
//! The CLI is split out from the binary so the argument parser and
//! the run functions can be exercised by integration tests without
//! shelling out.

use std::io::BufRead;
use std::io::BufReader;
use std::io::IsTerminal;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;

mod apply;
mod backup;
mod diff;
mod inspect;
mod io_helpers;

pub use apply::ApplyArgs;
pub use diff::DiffArgs;
pub use inspect::InspectArgs;

/// suture: build, inspect, and apply binary patches.
#[derive(Parser, Debug)]
#[command(name = "suture", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Compute a patch from `source` to `target`.
    Diff(DiffArgs),
    /// Apply a patch to a file (in place, with a backup by default).
    Apply(ApplyArgs),
    /// Describe a patch's contents without applying it.
    Inspect(InspectArgs),
}

/// Source-digest algorithm recorded in the patch's
/// [`SourceMetadata`](crate::metadata::SourceMetadata).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum DigestKind {
    /// Don't record a digest. The patch will only check source
    /// length on apply.
    None,
    /// 4-byte CRC-32. Cheap, catches accidental corruption.
    Crc32,
    /// 32-byte BLAKE3. Cryptographic; recommended.
    Blake3,
}

impl DigestKind {
    pub fn into_algorithm(self) -> Option<crate::metadata::HashAlgorithm> {
        match self {
            DigestKind::None => None,
            DigestKind::Crc32 => Some(crate::metadata::HashAlgorithm::Crc32),
            DigestKind::Blake3 => Some(crate::metadata::HashAlgorithm::Blake3),
        }
    }
}

/// Top-level entry point. Parses argv from the process and routes
/// to the matching subcommand. Returns an [`ExitCode`] so the
/// binary can do `std::process::exit(suture::cli::main())`.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    run(cli, &mut Stdio::from_process())
}

/// Run a parsed CLI invocation against an explicit stdio sink.
/// Tests construct a `Stdio` over in-memory buffers to capture
/// output and feed scripted input; the binary uses
/// [`Stdio::from_process`] to bind to the real process streams.
///
/// Subcommands return `Result<(), CliError>`: on `Err`, this
/// function prints the error chain to stderr and exits non-zero.
/// Subcommands have no need to surface their own `ExitCode` -- if
/// they want to fail, they return an error.
pub fn run(cli: Cli, io: &mut Stdio<'_>) -> ExitCode {
    let result = match cli.command {
        Command::Diff(args) => diff::run(args, io),
        Command::Apply(args) => apply::run(args, io),
        Command::Inspect(args) => inspect::run(args, io),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // chain Display through the source list so callers see
            // the full "x: y: z" trail rather than only the top.
            let _ = writeln!(io.err, "error: {e}");
            let mut src = e.source();
            while let Some(s) = src {
                let _ = writeln!(io.err, "  caused by: {s}");
                src = s.source();
            }
            ExitCode::FAILURE
        }
    }
}

/// Bundle of streams a subcommand may interact with: stdin (for
/// confirmation prompts), stdout (machine output / patch bytes),
/// stderr (human messages), plus an `interactive` flag that says
/// whether prompting the user makes sense. Holding this in one
/// struct lets tests swap the real process streams for in-memory
/// buffers in one place, including a scripted stdin.
pub struct Stdio<'a> {
    pub input: Box<dyn BufRead + 'a>,
    pub out: Box<dyn Write + 'a>,
    pub err: Box<dyn Write + 'a>,
    /// True when both stdin and stderr are TTYs. Subcommands use
    /// this to decide whether to prompt or to fall through to a
    /// scripted-default behaviour.
    pub interactive: bool,
}

impl<'a> Stdio<'a> {
    /// Bind to the real process streams. Marks the session as
    /// interactive only when stdin AND stderr are both TTYs --
    /// stderr matters because that's where prompts get written.
    pub fn from_process() -> Self {
        let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
        Self {
            input: Box::new(BufReader::new(std::io::stdin())),
            out: Box::new(std::io::stdout()),
            err: Box::new(std::io::stderr()),
            interactive,
        }
    }

    /// Build a `Stdio` over arbitrary readers/writers. Tests use
    /// this to feed scripted answers and snapshot output.
    pub fn from_streams<I, O, E>(input: I, out: O, err: E, interactive: bool) -> Self
    where
        I: BufRead + 'a,
        O: Write + 'a,
        E: Write + 'a,
    {
        Self {
            input: Box::new(input),
            out: Box::new(out),
            err: Box::new(err),
            interactive,
        }
    }
}

/// Boxed error returned by every subcommand's `run` function. Each
/// subcommand defines its own concrete error and converts on the
/// way out.
pub type CliError = Box<dyn core::error::Error + Send + Sync + 'static>;

/// Helper: read a path argument into a `Vec<u8>`, with an error
/// message that names the path.
pub(crate) fn read_path(p: &PathBuf) -> Result<Vec<u8>, CliError> {
    std::fs::read(p).map_err(|e| format!("failed to read {}: {}", p.display(), e).into())
}

/// Helper: write `bytes` to `path` (truncating).
pub(crate) fn write_path(p: &PathBuf, bytes: &[u8]) -> Result<(), CliError> {
    std::fs::write(p, bytes).map_err(|e| format!("failed to write {}: {}", p.display(), e).into())
}
