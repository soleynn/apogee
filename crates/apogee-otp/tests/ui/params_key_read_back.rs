//! The profile answers for its parameters and never for its key. There is no accessor, no field, and
//! no conversion back to the base32 the key arrived as: a code derived from the key is the only
//! thing that comes out.

use apogee_otp::TotpParams;

fn read_the_key(params: &TotpParams) {
    let _ = params.key();
    let _ = params.secret();
    let _ = params.key;
}

fn main() {
    let _ = read_the_key;
}
