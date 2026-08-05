//! A secret must not be cloneable: a clone is a second buffer with its own lifetime, and only one
//! of the two gets dropped where the caller thinks it does.

use apogee_secrets::Secret;

#[derive(Clone)]
struct Credentials {
    password: Secret,
}

fn main() {
    let _ = Credentials {
        password: Secret::new(b"hunter2".to_vec()),
    };
}
