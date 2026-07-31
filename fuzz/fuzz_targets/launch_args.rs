#![no_main]

use libfuzzer_sys::fuzz_target;

use sqex_crypto::{ArgKey, ArgumentBuilder, LegacyBlowfish, TickCount, sqex_base64};

/// The wrapper the encrypted form is always packed in.
const PREFIX: &str = "//**sqex0003";
const SUFFIX: &str = "**//";
/// The checksum alphabet, restated so the fuzzer checks the trailing character against a table it did
/// not get from the code under test.
const CHECKSUM: &[u8; 16] = b"fX1pGtdS5CAP4_VL";

/// The plaintext the builder should have produced for `pairs` under `ticks`, serialized here rather
/// than taken from the crate: the leading space on every pair, the `/` before the key, the space
/// before `=`, spaces doubled in both halves, and the tick-derived `T` leading the list, displacing a
/// caller-supplied one.
fn expected_plaintext(ticks: u32, pairs: &[(String, String)]) -> String {
    fn escaped(s: &str) -> String {
        s.replace(' ', "  ")
    }

    let mut out = format!(" /T ={ticks}");
    let skip = usize::from(pairs.first().is_some_and(|(k, _)| k == "T"));
    for (k, v) in pairs.iter().skip(skip) {
        out.push_str(" /");
        out.push_str(&escaped(k));
        out.push_str(" =");
        out.push_str(&escaped(v));
    }
    out
}

// The argument builder is the crate's one transform with a live caller, and everything it is handed
// crosses a trust boundary of its own: the session id and version come off the wire, and the free-form
// extras come from the user. This drives it over arbitrary key/value text, in arbitrary quantity, at
// arbitrary tick values.
//
// Beyond panic-freedom it pins two things the type system does not. The output round-trips: the body
// decodes and decrypts back to exactly the serialization above, so no input can be silently mangled or
// truncated by the codec. And the `T` argument always leads and always carries the tick the key was
// derived from, however many `T`s the caller supplies, since a login whose key and `T` disagree fails
// at the game with nothing to see.
//
// A third invariant rides along without being restated here: the builder's own debug assertion that
// the plaintext fits the buffer it reserved. Checking it from out here would mean copying the
// reservation formula into this file, which would then hold for any input by arithmetic alone and
// prove nothing about the code. Debug assertions are on in a fuzz build, so driving the builder is
// what exercises it.
fuzz_target!(|data: &[u8]| {
    let (head, rest) = match data.split_at_checked(4) {
        Some((head, rest)) => (head, rest),
        None => return,
    };
    let ticks = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);

    // Fields are separated by the unit separator, which the arguments themselves may not contain, so
    // an input maps to exactly one pair list. An odd field count leaves a trailing key with no value,
    // which is dropped rather than paired with an empty one.
    let fields: Vec<String> = rest
        .split(|&b| b == 0x1F)
        .map(|f| String::from_utf8_lossy(f).into_owned())
        .collect();
    let pairs: Vec<(String, String)> = fields
        .chunks_exact(2)
        .map(|kv| (kv[0].clone(), kv[1].clone()))
        .collect();

    let mut builder = ArgumentBuilder::new();
    for (k, v) in &pairs {
        builder = builder.add(k.clone(), v.clone());
    }

    // The plaintext form carries no `T`, no escaping and no key, so it is exactly the pairs joined.
    let plain = builder.build_plain();
    let expected_plain: String = pairs
        .iter()
        .map(|(k, v)| format!(" {k}={v}"))
        .collect::<Vec<_>>()
        .join("");
    assert_eq!(plain, expected_plain, "plain form");

    let key = ArgKey::from_tick(TickCount::from_raw(ticks));
    let encrypted = builder.build_encrypted(&key);

    let body = encrypted
        .strip_prefix(PREFIX)
        .and_then(|s| s.strip_suffix(SUFFIX))
        .expect("not wrapped");
    let (base64, checksum) = body.split_at(body.len() - 1);
    assert!(
        CHECKSUM.contains(&checksum.as_bytes()[0]),
        "checksum char {checksum:?} is not in the table"
    );

    let ciphertext = sqex_base64::decode(base64).expect("body did not decode");
    assert_eq!(ciphertext.len() % 8, 0, "ciphertext is not whole blocks");

    // The key the builder used is the tick's high half; deriving it here from the raw tick rather than
    // from the string proves the two agree.
    let key_bytes = format!("{:08x}", ticks & 0xFFFF_0000);
    let decrypted = LegacyBlowfish::new(key_bytes.as_bytes()).decrypt(&ciphertext);

    let mut padded = expected_plaintext(ticks, &pairs).into_bytes();
    padded.resize(padded.len().next_multiple_of(8), 0);
    assert_eq!(decrypted, padded, "round trip");
});
