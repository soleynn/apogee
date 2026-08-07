#![no_main]

use libfuzzer_sys::fuzz_target;

// The one-time-password import grammar takes whatever a user pastes: a link from another
// authenticator, a key transcribed off a printed sheet, a file some other program wrote. On any text
// at all it must answer rather than abort, and it must not reserve out of a length it read from that
// text: the input cap and the key cap are checked before anything is decoded, and this is the target
// that says so. Text rather than bytes, because that is the shape the surface actually takes.
fuzz_target!(|data: &str| {
    apogee_otp::fuzz_parse_import(data);
});
