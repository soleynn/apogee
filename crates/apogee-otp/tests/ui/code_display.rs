//! Nor may it be formatted into a string. `Debug` renders the digit count on purpose; a `Display`
//! would render the digits, and the one call that needs them asks for them by name.

use apogee_otp::Code;

fn submit(code: &Code) -> String {
    format!("{code}")
}

fn main() {
    let _ = submit;
}
