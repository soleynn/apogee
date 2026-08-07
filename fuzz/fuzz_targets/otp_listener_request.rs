#![no_main]

use libfuzzer_sys::fuzz_target;

// The listener's request line is the only parser in this workspace that reads bytes a stranger on the
// network chose, rather than bytes a server we asked answered with. It must answer on any input at
// all, allocate nothing it did not bound before the read, and never take the process down. Bytes
// rather than text, because a socket is not obliged to send anything decodable and the grammar never
// builds a `char`: an implementation that reached for one would accept several non-ASCII spellings of
// a digit, which is a second way to say a code that the fixed length was supposed to have refused.
fuzz_target!(|data: &[u8]| {
    apogee_otp::fuzz_parse_request(data);
});
