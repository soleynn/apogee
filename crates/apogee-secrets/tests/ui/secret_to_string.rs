//! `to_string` rides on `Display`, so it must be unavailable for the same reason.

use apogee_secrets::Secret;

fn main() {
    let secret = Secret::new(b"hunter2".to_vec());
    let _ = secret.to_string();
}
