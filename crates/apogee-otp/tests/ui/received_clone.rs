//! What a wait took off the wire holds a live code, so it must not be cloneable either: a clone is a
//! second buffer of digits with its own lifetime, and only one of the two is erased where the caller
//! thinks it is.

use apogee_otp::Received;

#[derive(Clone)]
struct Attempt {
    received: Received,
}

fn main() {
    let _ = std::mem::size_of::<Attempt>();
}
