//! A secret must not have a default. `Secret::default()` is an empty secret that satisfies every
//! signature a real one does, so a field nobody filled in reads as a value rather than as a mistake,
//! and it reaches the login call as an empty password.

use apogee_secrets::Secret;

#[derive(Default)]
struct Credentials {
    password: Secret,
}

fn main() {
    let _ = Credentials::default();
}
