//! Nor may two of them be compared. A caller that could compare codes would keep the previous one to
//! compare against, which is the record this crate keeps behind one handle so it stays in one place.

use apogee_otp::Code;

fn is_a_repeat(sent: &Code, next: &Code) -> bool {
    sent == next
}

fn main() {
    let _ = is_a_repeat;
}
