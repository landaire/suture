//! Tiny helpers shared by more than one subcommand. Kept separate
//! so the subcommand modules read top-down without scrolling past
//! formatting plumbing.

/// Render `bytes` as a lowercase hex string. Used by `inspect` to
/// surface digests in a familiar form.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble(*b >> 4));
        out.push(nibble(*b & 0x0F));
    }
    out
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}
