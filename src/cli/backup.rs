//! Backup-file naming and creation.
//!
//! On `apply`, we copy the target file aside before mutating it.
//! The first backup is `<orig>.bak`; if that name is taken we try
//! `<orig>.1.bak`, `<orig>.2.bak`, ... until we find a free slot.
//!
//! `create_new` open ensures we never clobber an existing backup
//! even under a (mild) race with another process.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io;
use std::path::Path;
use std::path::PathBuf;

/// Hard ceiling on backup index searches. Hitting this means the
/// user has 100k+ stale `.bak` files in the same directory; we
/// surface the failure rather than spin forever.
const MAX_INDEX: u32 = 100_000;

/// Copy `orig` to a fresh `.bak` slot and return the path used.
///
/// Always reads `orig` byte-for-byte rather than hard-linking, so
/// the subsequent in-place mutation can't reflect into the backup.
pub fn make_backup(orig: &Path) -> io::Result<PathBuf> {
    let bytes = std::fs::read(orig)?;
    let candidate = bak_path(orig, None);
    if let Some(written) = try_create_and_write(&candidate, &bytes)? {
        return Ok(written);
    }
    for n in 1..MAX_INDEX {
        let candidate = bak_path(orig, Some(n));
        if let Some(written) = try_create_and_write(&candidate, &bytes)? {
            return Ok(written);
        }
    }
    Err(io::Error::other(format!(
        "no free .bak slot for {} within {MAX_INDEX} indices",
        orig.display()
    )))
}

/// Try to create `path` exclusively and write `bytes` to it.
/// Returns `Ok(Some(path))` on success, `Ok(None)` if the file
/// already exists (caller advances to the next slot), `Err` on any
/// other I/O failure.
fn try_create_and_write(path: &Path, bytes: &[u8]) -> io::Result<Option<PathBuf>> {
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path);
    match result {
        Ok(mut f) => {
            use io::Write;
            f.write_all(bytes)?;
            f.sync_all()?;
            Ok(Some(path.to_path_buf()))
        }
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(None),
        Err(e) => Err(e),
    }
}

/// Compute the backup path for `orig`. With `n = None` returns
/// `<orig>.bak`; with `Some(k)` returns `<orig>.k.bak`.
///
/// We append rather than replace the existing extension so e.g.
/// `notes.txt` becomes `notes.txt.bak`, matching the convention
/// most editors use.
fn bak_path(orig: &Path, n: Option<u32>) -> PathBuf {
    let mut s: OsString = orig.as_os_str().to_owned();
    if let Some(k) = n {
        s.push(".");
        s.push(k.to_string());
    }
    s.push(".bak");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bak_path_appends_extension() {
        let p = Path::new("/tmp/notes.txt");
        assert_eq!(bak_path(p, None), PathBuf::from("/tmp/notes.txt.bak"));
        assert_eq!(bak_path(p, Some(1)), PathBuf::from("/tmp/notes.txt.1.bak"));
        assert_eq!(bak_path(p, Some(42)), PathBuf::from("/tmp/notes.txt.42.bak"));
    }

    #[test]
    fn bak_path_handles_extensionless_files() {
        let p = Path::new("/tmp/binary");
        assert_eq!(bak_path(p, None), PathBuf::from("/tmp/binary.bak"));
        assert_eq!(bak_path(p, Some(3)), PathBuf::from("/tmp/binary.3.bak"));
    }

    #[test]
    fn make_backup_first_slot_is_dot_bak() {
        let dir = tempfile::tempdir().unwrap();
        let orig = dir.path().join("file.bin");
        std::fs::write(&orig, b"hello").unwrap();

        let bak = make_backup(&orig).unwrap();
        assert_eq!(bak, dir.path().join("file.bin.bak"));
        assert_eq!(std::fs::read(&bak).unwrap(), b"hello");
    }

    #[test]
    fn make_backup_walks_to_next_free_index() {
        let dir = tempfile::tempdir().unwrap();
        let orig = dir.path().join("file.bin");
        std::fs::write(&orig, b"v3").unwrap();
        std::fs::write(dir.path().join("file.bin.bak"), b"v0").unwrap();
        std::fs::write(dir.path().join("file.bin.1.bak"), b"v1").unwrap();
        std::fs::write(dir.path().join("file.bin.2.bak"), b"v2").unwrap();

        let bak = make_backup(&orig).unwrap();
        assert_eq!(bak, dir.path().join("file.bin.3.bak"));
        assert_eq!(std::fs::read(&bak).unwrap(), b"v3");

        // existing slots remain untouched
        assert_eq!(std::fs::read(dir.path().join("file.bin.bak")).unwrap(), b"v0");
        assert_eq!(std::fs::read(dir.path().join("file.bin.1.bak")).unwrap(), b"v1");
        assert_eq!(std::fs::read(dir.path().join("file.bin.2.bak")).unwrap(), b"v2");
    }
}
