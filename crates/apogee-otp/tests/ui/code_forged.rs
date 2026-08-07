//! A code in a caller's hands came from a secret this crate holds. Neither the tuple field nor the
//! constructor is reachable from outside, so there is no second way for one to come into being.

use apogee_otp::Code;

fn main() {
    let _ = Code(String::from("123456"));
    let _ = Code::new(String::from("123456"));
}
