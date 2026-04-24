# suture

In-memory binary patches: an ordered list of byte splices over a base
buffer, with optional source-material verification.

A `Patch` is a list of `(offset, old_len, new_bytes)` splices. The
splice form covers in-place writes, inserts, deletes,
length-changing replacements, and truncation -- a pure overwrite is
just a splice where `old_len == new_bytes.len()`.

```rust
use suture::Patch;

let mut patch = Patch::new();
patch.write(2, vec![0xAA, 0xBB])?;          // in-place write
patch.insert(6, vec![0xCC])?;                // pure insert
patch.delete(8, 2)?;                         // pure delete
let result = patch.apply(&original_bytes)?;
```

A patch can carry `SourceMetadata` -- length, content digest, and / or
filesystem stat -- describing the buffer it was generated against.
`Patch::apply` verifies the source matches before splicing;
`Patch::apply_unchecked` is the `unsafe` escape hatch for callers
that have already verified out-of-band.

## Cargo features

| feature | adds |
| --- | --- |
| `serde`  | `Serialize` / `Deserialize` derives on `Patch`, `SourceMetadata`, etc. |
| `rkyv`   | `Archive` / `Serialize` / `Deserialize` derives. |
| `blake3` | `HashAlgorithm::Blake3` and BLAKE3-backed digest computation. |
| `sha2`   | `HashAlgorithm::Sha256` and SHA-256-backed digest computation. |

CRC-32 is always available -- no feature gate required.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
