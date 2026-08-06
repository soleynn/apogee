//! A live code must not be cloneable: a clone is a second buffer of digits with its own lifetime,
//! and only one of the two is erased where the caller thinks it is.

use apogee_otp::Code;

#[derive(Clone)]
struct Attempt {
    code: Code,
}

fn main() {
    let _ = std::mem::size_of::<Attempt>();
}
