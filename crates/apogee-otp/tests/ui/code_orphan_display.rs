//! Nor may a consumer supply the missing rendering itself.

use apogee_otp::Code;

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.expose())
    }
}

fn main() {}
