//! A secret must not convert to its bytes implicitly. Half the standard library takes
//! `impl AsRef<[u8]>`, so one such impl would let a secret be written to a file, sent down a socket,
//! or hashed into a log line without the call site ever naming `expose`. Reaching the bytes has to
//! stay a deliberate word a reviewer can grep for.

use apogee_secrets::Secret;

fn main() {
    let secret = Secret::new(b"marker".to_vec());
    std::fs::write("/dev/null", secret).unwrap();
}
