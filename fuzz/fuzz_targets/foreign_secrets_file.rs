#![no_main]

use libfuzzer_sys::fuzz_target;

// The plaintext table another launcher writes its passwords into when it is configured to keep one.
// Unlike the two sealed-store targets beside it, nothing authenticates these bytes before the decoder
// is handed them: the file sits at a path this launcher does not own, so what reaches the parser is an
// attacker's reach and not only the decoder's own totality. It must answer on any bytes at all, must
// not reserve out of anything it read, and must not let one unreadable entry hide the account that was
// asked for, since the rest of the file belongs to accounts this was never asked about.
//
// The assertion is a bound rather than an absence: a password that comes back was decoded out of the
// input, and JSON escaping only ever shrinks, so one longer than the input is the decoder amplifying
// what it read.
//
// The account name searched for comes out of the first byte's worth of length, so a corpus entry
// carries the name it is searched with and a minimized crash reproduces from the file alone.
fuzz_target!(|data: &[u8]| {
    let Some((len, rest)) = data.split_first() else {
        return;
    };
    let (name, body) = rest.split_at(usize::from(*len).min(rest.len()));
    let Ok(name) = std::str::from_utf8(name) else {
        return;
    };
    assert!(
        apogee_secrets::fuzz_parse_exported_file(body, name),
        "the decoded password was longer than the bytes it came out of"
    );
});
