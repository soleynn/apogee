//! Consent must not be constructible except through the one call that says so. A struct literal
//! reaching past the constructor would let a library below the layer that can ask a user create an
//! encrypted store on their behalf, which is the silent fallback the design refuses.

use apogee_secrets::Consent;

fn main() {
    let _ = Consent(());
}
