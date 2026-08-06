//! Two secrets must not be comparable. `==` over a password is a variable-time oracle the moment a
//! caller checks a supplied value against a stored one, and the derive is available: the wrapper
//! underneath implements `PartialEq`, so only the absence of it here stands in the way.

use apogee_secrets::Secret;

#[derive(PartialEq)]
struct Credentials {
    password: Secret,
}

fn main() {
    let _ = Credentials {
        password: Secret::new(b"hunter2".to_vec()),
    };
}
