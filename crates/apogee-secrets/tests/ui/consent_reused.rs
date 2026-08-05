//! Consent must not be reusable. It is consumed by the call it authorizes, so one grant authorizes
//! one action; a `Clone` or a `Copy` would let a caller ask once and act on it forever.

use apogee_secrets::Consent;

#[derive(Clone)]
struct Authorized {
    consent: Consent,
}

fn main() {
    let _ = Authorized {
        consent: Consent::granted(),
    };
}
