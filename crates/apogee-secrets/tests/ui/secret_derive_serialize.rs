//! A type holding a secret must not be able to derive `Serialize`: the derive would write the field
//! into whatever the struct is persisted as.

use apogee_secrets::Secret;

#[derive(serde::Serialize)]
struct Credentials {
    password: Secret,
}

fn main() {
    let _ = Credentials {
        password: Secret::new(b"hunter2".to_vec()),
    };
}
