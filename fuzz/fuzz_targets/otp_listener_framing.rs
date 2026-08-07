#![no_main]

use libfuzzer_sys::fuzz_target;

// The framing, driven at a chunk size the input picks. The assertion is an equality rather than an
// absence: how a peer split its writes may not change the verdict. That property is what the
// reference gets wrong, and it gets it wrong for legitimate clients rather than hostile ones, since a
// request split across TCP segments fills part of its single unchecked read and the code is dropped
// with nothing reported. A target that only asserted "does not abort" would never see it, because
// both spellings answer cleanly and simply disagree.
//
// The stride comes out of the first byte, so a corpus entry carries its own splitting and a minimized
// crash is reproducible from the file alone.
fuzz_target!(|data: &[u8]| {
    let Some((stride, body)) = data.split_first() else {
        return;
    };
    assert!(
        apogee_otp::fuzz_framing_agrees(body, usize::from(*stride) + 1),
        "the verdict depended on how the input was split"
    );
});
