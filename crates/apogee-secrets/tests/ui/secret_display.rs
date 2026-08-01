//! A secret must not be `Display`-formattable, so it cannot be interpolated into a message.

use apogee_secrets::Secret;

fn main() {
    let secret = Secret::new(b"hunter2".to_vec());
    println!("{secret}");
}
