//! A delivered code must not be formatted into a string. `Debug` renders the peer and the counts on
//! purpose; a `Display` would be the shortest route the digits have to a log line, and the one call
//! that needs them takes the code out by name.

use apogee_otp::Received;

fn announce(received: &Received) -> String {
    format!("{received}")
}

fn main() {
    let _ = announce;
}
