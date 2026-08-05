//! A secret must not be `Debug`-printable: that is one log line away from disk.

use apogee_secrets::Secret;

fn main() {
    let secret = Secret::new(b"hunter2".to_vec());
    println!("{secret:?}");
}
