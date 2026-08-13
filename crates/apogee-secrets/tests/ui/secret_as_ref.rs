//! A secret must not convert to its bytes implicitly. Half the standard library takes
//! `impl AsRef<[u8]>`, so one such impl would let a secret be written to a file, sent down a socket,
//! or hashed into a log line without the call site ever naming `expose`. Reaching the bytes has to
//! stay a deliberate word a reviewer can grep for.

use apogee_secrets::Secret;

/// Stands in for `std::fs::write` and every other sink shaped like it.
///
/// Declared here rather than reached for in the standard library, whose signature rustc renders
/// into the note below only when the toolchain carries `rust-src`. Expecting that would make this
/// case's recorded output a fact about the machine it ran on.
fn writes_bytes(_: impl AsRef<[u8]>) {}

fn main() {
    let secret = Secret::new(b"marker".to_vec());
    writes_bytes(secret);
}
