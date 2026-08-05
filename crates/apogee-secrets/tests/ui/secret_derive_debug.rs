//! A type holding a secret must not be able to derive `Debug`: the derive would print the field.

use apogee_secrets::Secret;

#[derive(Debug)]
struct Credentials {
    password: Secret,
}

fn main() {
    let _ = Credentials {
        password: Secret::new(b"hunter2".to_vec()),
    };
}
