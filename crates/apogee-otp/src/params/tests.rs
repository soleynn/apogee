//! Known-answer vectors and the import accept/reject table.
//!
//! A sibling file rather than an inline module for the reason the sealed store's frame tests record:
//! a fixed key literal in that position reads to a security scan as a hard-coded credential, and its
//! configuration excludes test files by name. The published vectors are exactly that shape.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apogee_secrets::Secret;
use proptest::prelude::*;
use rstest::rstest;

use super::*;

/// The published seeds, one per hash. The table in the standard was computed with a different seed
/// length for each, and reusing the twenty-byte one for the wider hashes reproduces only the first
/// column. If a vector ever disagrees on SHA-256 or SHA-512 alone, this is the first thing to check.
const SHA1_SEED: &[u8] = b"12345678901234567890";
const SHA256_SEED: &[u8] = b"12345678901234567890123456789012";
const SHA512_SEED: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

/// A base32 secret that decodes to twenty bytes, which clears the minimum key length.
const KEY: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

fn profile(
    seed: &[u8],
    algorithm: Algorithm,
    digits: u8,
    period: u32,
) -> Result<TotpParams, OtpError> {
    TotpParams::assemble(Zeroizing::new(seed.to_vec()), algorithm, digits, period)
        .map_err(|reason| OtpError::Import { reason })
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn uri(tail: &str) -> String {
    format!("otpauth://totp/apogee?secret={KEY}{tail}")
}

/// The code an offered secret produces at a fixed instant, which is how two spellings of the same
/// key are compared without the key ever being exposed.
fn code_at(offered: &str, seconds: u64) -> Result<String, OtpError> {
    let params = TotpParams::parse(offered)?;
    Ok(params
        .code(at(seconds), ClockSkew::NONE)?
        .expose()
        .to_owned())
}

/// The published seed's code at an instant, or `None` if anything at all refused. A property test
/// asserts on the `Option` rather than unwrapping, which a free helper here may not do.
fn code_for(seconds: u64) -> Option<String> {
    code_with_skew(seconds, 0)
}

/// The same, with the clock corrected by `offset` seconds.
fn code_with_skew(seconds: u64, offset: i64) -> Option<String> {
    profile(SHA1_SEED, Algorithm::Sha1, 6, 30)
        .ok()?
        .code(at(seconds), ClockSkew::from_seconds(offset))
        .ok()
        .map(|code| code.expose().to_owned())
}

/// The published seed's code for one counter, reached without going through a clock at all. This is
/// what lets a boundary assertion name the window a code came from instead of comparing two codes,
/// which is the assertion that collides once in a million.
fn code_of_window(counter: u64) -> Option<String> {
    profile(SHA1_SEED, Algorithm::Sha1, 6, 30)
        .ok()?
        .code_for_counter(counter)
        .ok()
        .map(|code| code.expose().to_owned())
}

/// The published table, all six instants across all three hashes, at eight digits.
#[rstest]
#[case(Algorithm::Sha1, SHA1_SEED, 59, "94287082")]
#[case(Algorithm::Sha1, SHA1_SEED, 1_111_111_109, "07081804")]
#[case(Algorithm::Sha1, SHA1_SEED, 1_111_111_111, "14050471")]
#[case(Algorithm::Sha1, SHA1_SEED, 1_234_567_890, "89005924")]
#[case(Algorithm::Sha1, SHA1_SEED, 2_000_000_000, "69279037")]
#[case(Algorithm::Sha1, SHA1_SEED, 20_000_000_000, "65353130")]
#[case(Algorithm::Sha256, SHA256_SEED, 59, "46119246")]
#[case(Algorithm::Sha256, SHA256_SEED, 1_111_111_109, "68084774")]
#[case(Algorithm::Sha256, SHA256_SEED, 1_111_111_111, "67062674")]
#[case(Algorithm::Sha256, SHA256_SEED, 1_234_567_890, "91819424")]
#[case(Algorithm::Sha256, SHA256_SEED, 2_000_000_000, "90698825")]
#[case(Algorithm::Sha256, SHA256_SEED, 20_000_000_000, "77737706")]
#[case(Algorithm::Sha512, SHA512_SEED, 59, "90693936")]
#[case(Algorithm::Sha512, SHA512_SEED, 1_111_111_109, "25091201")]
#[case(Algorithm::Sha512, SHA512_SEED, 1_111_111_111, "99943326")]
#[case(Algorithm::Sha512, SHA512_SEED, 1_234_567_890, "93441116")]
#[case(Algorithm::Sha512, SHA512_SEED, 2_000_000_000, "38618901")]
#[case(Algorithm::Sha512, SHA512_SEED, 20_000_000_000, "47863826")]
fn published_vectors_match_the_table(
    #[case] algorithm: Algorithm,
    #[case] seed: &[u8],
    #[case] seconds: u64,
    #[case] expected: &str,
) -> Result<(), OtpError> {
    let params = profile(seed, algorithm, 8, 30)?;
    assert_eq!(
        params.code(at(seconds), ClockSkew::NONE)?.expose(),
        expected
    );
    Ok(())
}

/// Ten to the sixth divides ten to the eighth, so a six-digit code is the last six characters of the
/// published eight-digit one, leading zeros included. Two of these rows start with a zero, which is
/// exactly what a naive integer format drops.
#[rstest]
#[case(59, "287082")]
#[case(1_111_111_109, "081804")]
#[case(1_111_111_111, "050471")]
#[case(1_234_567_890, "005924")]
#[case(2_000_000_000, "279037")]
#[case(20_000_000_000, "353130")]
fn six_digits_are_the_last_six_of_the_eight_digit_code(
    #[case] seconds: u64,
    #[case] expected: &str,
) -> Result<(), OtpError> {
    let wide = profile(SHA1_SEED, Algorithm::Sha1, 8, 30)?;
    let narrow = profile(SHA1_SEED, Algorithm::Sha1, 6, 30)?;
    let wide = wide.code(at(seconds), ClockSkew::NONE)?;
    let narrow = narrow.code(at(seconds), ClockSkew::NONE)?;
    assert_eq!(narrow.expose(), expected);
    assert!(wide.expose().ends_with(narrow.expose()));
    assert_eq!(narrow.len(), 6);
    Ok(())
}

/// A parameter left out of the URI takes the value the login server accepts, so a bare export
/// imports as something that works.
#[test]
fn an_otpauth_uri_yields_its_parameters() -> Result<(), OtpError> {
    let params = TotpParams::parse(&uri(""))?;
    assert_eq!(params.algorithm(), Algorithm::Sha1);
    assert_eq!(params.digits(), 6);
    assert_eq!(params.period(), 30);
    assert!(params.deviations().is_empty());
    Ok(())
}

#[test]
fn a_raw_base32_secret_is_accepted_without_a_uri() -> Result<(), OtpError> {
    let params = TotpParams::parse(KEY)?;
    assert_eq!(params.digits(), 6);
    assert_eq!(params.period(), 30);
    assert_eq!(
        code_at(KEY, 1_234_567_890)?,
        code_at(&uri(""), 1_234_567_890)?
    );
    Ok(())
}

/// Every spelling a real export or a hand-transcribed key arrives in, all decoding to one key. The
/// decoder underneath refuses all four, so this is the normalization doing the work.
#[rstest]
#[case("jbswy3dpehpk3pxpjbswy3dpehpk3pxp")]
#[case("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP====")]
#[case("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP")]
#[case("JBSW-Y3DP-EHPK-3PXP-JBSW-Y3DP-EHPK-3PXP")]
fn a_transcribed_secret_is_normalized(#[case] offered: &str) -> Result<(), OtpError> {
    assert_eq!(
        code_at(offered, 1_234_567_890)?,
        code_at(KEY, 1_234_567_890)?
    );
    Ok(())
}

/// The authority is compared without regard to case, which a general-purpose parser does not do for
/// a scheme it has no special handling for.
#[rstest]
#[case("otpauth://TOTP/apogee?secret=")]
#[case("OTPAUTH://totp/apogee?secret=")]
fn the_scheme_and_the_type_are_matched_without_regard_to_case(
    #[case] head: &str,
) -> Result<(), OtpError> {
    let offered = format!("{head}{KEY}");
    assert_eq!(
        code_at(&offered, 1_234_567_890)?,
        code_at(KEY, 1_234_567_890)?
    );
    Ok(())
}

/// Everything from the first `#` is data about the link, not part of it. Left on, it would fold into
/// the last parameter's value.
#[test]
fn a_fragment_is_stripped_before_anything_is_parsed() -> Result<(), OtpError> {
    let offered = uri("&period=30#note");
    assert_eq!(
        code_at(&offered, 1_234_567_890)?,
        code_at(KEY, 1_234_567_890)?
    );
    Ok(())
}

/// One case per hostile input the grammar was written against. The assertion is on the reason, not
/// on the message: the message is what a shell renders and is allowed to be reworded.
#[rstest]
#[case::authority_missing(
    "otpauth:totp/a?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    Rejected::Authority
)]
#[case::one_slash(
    "otpauth:/totp/a?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    Rejected::Authority
)]
#[case::userinfo(
    "otpauth://user:pass@totp/a?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    Rejected::Authority
)]
#[case::port(
    "otpauth://totp:8080/a?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    Rejected::Authority
)]
#[case::empty_authority(
    "otpauth:///a?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    Rejected::Authority
)]
#[case::counter_based(
    "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    Rejected::Type
)]
#[case::other_scheme(
    "https://totp/a?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    Rejected::Scheme
)]
#[case::bulk_export(
    "otpauth-migration://offline?data=CjkKCkhlbGxvIXDeAd",
    Rejected::MigrationBundle
)]
#[case::whitespace_only("   \t  ", Rejected::Empty)]
fn each_malformed_link_is_refused_by_its_own_reason(
    #[case] offered: &str,
    #[case] expected: Rejected,
) {
    assert!(
        matches!(TotpParams::parse(offered), Err(OtpError::Import { reason }) if reason == expected),
        "{expected:?}"
    );
}

/// The parameter half of the same table, built onto a URI whose secret is valid, so each case fails
/// for the reason it names and not because something else was wrong too.
#[rstest]
#[case::counter_parameter("&counter=1", Rejected::Type)]
#[case::period_zero("&period=0", Rejected::Period)]
#[case::period_over_the_cap("&period=301", Rejected::Period)]
#[case::period_not_a_number("&period=abc", Rejected::Period)]
#[case::period_negative("&period=-30", Rejected::Period)]
#[case::period_past_the_width("&period=18446744073709551615", Rejected::Period)]
#[case::digits_too_few("&digits=5", Rejected::Digits)]
#[case::digits_too_many("&digits=9", Rejected::Digits)]
#[case::digits_spelled("&digits=six", Rejected::Digits)]
#[case::digits_negative("&digits=-1", Rejected::Digits)]
#[case::digits_fractional("&digits=6.0", Rejected::Digits)]
#[case::digits_past_the_width("&digits=99999999999999999999", Rejected::Digits)]
#[case::algorithm_unknown("&algorithm=MD5", Rejected::Algorithm)]
#[case::algorithm_wrong_family("&algorithm=SHA3", Rejected::Algorithm)]
#[case::algorithm_empty("&algorithm=", Rejected::Algorithm)]
#[case::duplicate_secret(
    "&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    Rejected::DuplicateParameter
)]
#[case::duplicate_digits("&digits=6&digits=6", Rejected::DuplicateParameter)]
#[case::duplicate_unknown_key("&issuer=a&issuer=a", Rejected::DuplicateParameter)]
fn each_malformed_parameter_is_refused_by_its_own_reason(
    #[case] tail: &str,
    #[case] expected: Rejected,
) {
    let offered = uri(tail);
    assert!(
        matches!(TotpParams::parse(&offered), Err(OtpError::Import { reason }) if reason == expected),
        "{expected:?}"
    );
}

/// The secret half of the table. A duplicate key is refused whatever it is, which is why the
/// duplicate cases sit above and not here.
#[rstest]
#[case::absent("otpauth://totp/apogee", Rejected::SecretMissing)]
#[case::present_and_empty("otpauth://totp/apogee?secret=", Rejected::SecretMissing)]
#[case::only_padding("otpauth://totp/apogee?secret=====", Rejected::SecretMissing)]
#[case::outside_the_alphabet(
    "otpauth://totp/apogee?secret=JBSWY3DP0189JBSWY3DPEHPK3PXPJBSW",
    Rejected::SecretAlphabet
)]
#[case::not_text(
    "otpauth://totp/apogee?secret=%FFJBSWY3DPEHPK3PXPJBSWY3DP",
    Rejected::SecretAlphabet
)]
#[case::truncated_escape(
    "otpauth://totp/apogee?secret=JBSWY3DPEHPK3PXPJBSWY3DP%F",
    Rejected::SecretAlphabet
)]
#[case::too_short("otpauth://totp/apogee?secret=JBSWY3DP", Rejected::SecretTooShort)]
#[case::raw_too_short("JBSWY3DP", Rejected::SecretTooShort)]
fn each_unusable_secret_is_refused_by_its_own_reason(
    #[case] offered: &str,
    #[case] expected: Rejected,
) {
    assert!(
        matches!(TotpParams::parse(offered), Err(OtpError::Import { reason }) if reason == expected),
        "{expected:?}"
    );
}

/// A plus sign stays a plus sign. The form decoder a general-purpose parser reaches for turns it
/// into a space, which silently rewrites a secret and is how two readers of one link import
/// different keys. Here it is a character outside the alphabet and the import is refused.
#[test]
fn a_plus_in_a_secret_is_not_a_space() {
    let offered = format!("otpauth://totp/apogee?secret=JBSW+Y3DP{KEY}");
    assert!(matches!(
        TotpParams::parse(&offered),
        Err(OtpError::Import {
            reason: Rejected::SecretAlphabet
        })
    ));
}

/// Parameter names are matched without regard to case, which is what the exports in the wild are
/// spelled with.
#[rstest]
#[case::upper_case("otpauth://totp/apogee?SECRET={key}&DIGITS=8", 8)]
#[case::mixed_case("otpauth://totp/apogee?SeCrEt={key}", 6)]
fn a_parameter_name_is_matched_without_regard_to_case(
    #[case] shape: &str,
    #[case] digits: u8,
) -> Result<(), OtpError> {
    let offered = shape.replace("{key}", KEY);
    assert_eq!(TotpParams::parse(&offered)?.digits(), digits);
    Ok(())
}

/// A name is not percent-decoded, though a value is. Decoding names would let `%73ecret` carry a
/// secret past a reader that looked only for the plain spelling, and past the duplicate rule with
/// it. Here the encoded name is a key this build has no meaning for, so the link carries no secret.
#[test]
fn a_parameter_name_is_not_percent_decoded() {
    let offered = format!("otpauth://totp/apogee?%73ecret={KEY}");
    assert!(matches!(
        TotpParams::parse(&offered),
        Err(OtpError::Import {
            reason: Rejected::SecretMissing
        })
    ));
}

/// A key with no value is still a key: it carries nothing and it counts for the duplicate rule. A
/// reader that skipped it would take the other spelling's value while a reader that did not would
/// refuse the link, which is the disagreement the duplicate rule exists to prevent. Either order is
/// refused, and the two reasons are the two different things wrong with them.
#[rstest]
#[case::bare_key("otpauth://totp/apogee?secret", Rejected::SecretMissing)]
#[case::bare_then_valued(
    "otpauth://totp/apogee?secret&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    Rejected::SecretMissing
)]
#[case::valued_then_bare(
    "otpauth://totp/apogee?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&secret",
    Rejected::DuplicateParameter
)]
#[case::valued_then_bare_unknown_key(
    "otpauth://totp/apogee?issuer=a&issuer&secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    Rejected::DuplicateParameter
)]
fn a_valueless_parameter_is_still_a_parameter(#[case] offered: &str, #[case] expected: Rejected) {
    assert!(
        matches!(TotpParams::parse(offered), Err(OtpError::Import { reason }) if reason == expected),
        "{expected:?}"
    );
}

/// Empty query elements are skipped rather than counted, so a trailing or doubled separator does not
/// read as a repeated nameless key and refuse a link every other reader accepts.
#[test]
fn empty_query_elements_are_skipped() -> Result<(), OtpError> {
    let offered = format!("otpauth://totp/apogee?&secret={KEY}&&period=30&");
    assert_eq!(
        code_at(&offered, 1_234_567_890)?,
        code_at(KEY, 1_234_567_890)?
    );
    Ok(())
}

/// The issuer is not checked against the label prefix, deliberately. Every implementation that has
/// the check compares case-sensitively and so refuses real exports, and it guards a field this crate
/// reads and drops. Both parts are pinned here because the absence is a decision, not an oversight.
#[rstest]
#[case::issuer_disagrees("Github:me?issuer=Gitlab&")]
#[case::issuer_differs_only_in_case("Github:me?issuer=GitHub&")]
#[case::two_colons("a:b:c?")]
fn a_label_that_disagrees_with_its_issuer_is_accepted(#[case] label: &str) -> Result<(), OtpError> {
    let offered = format!("otpauth://totp/{label}secret={KEY}");
    assert_eq!(
        code_at(&offered, 1_234_567_890)?,
        code_at(KEY, 1_234_567_890)?
    );
    Ok(())
}

/// A label written to look like somewhere else is accepted and dropped. There is nothing to sanitize
/// because nothing is kept: the stored form carries a fixed literal, so a right-to-left override or
/// a homoglyph issuer has nowhere to be displayed from.
#[rstest]
#[case::right_to_left_override("%E2%80%AEsuoicilam")]
#[case::homoglyph("%D0%A1quare%20Enix")]
#[case::emoji("%F0%9F%A6%91")]
fn a_label_written_to_deceive_is_accepted_and_dropped(#[case] label: &str) -> Result<(), OtpError> {
    let offered = format!("otpauth://totp/{label}?secret={KEY}");
    let params = TotpParams::parse(&offered)?;
    let stored = params.into_secret();
    let stored = std::str::from_utf8(stored.expose())
        .unwrap_or_default()
        .to_owned();
    assert_eq!(stored.matches('/').count(), 3, "{stored}");
    assert!(stored.contains("/totp/apogee?"), "{stored}");
    Ok(())
}

/// A label is decoded so a malformed one is caught, and then dropped. These are the three shapes a
/// decoder that shrugged would carry into whatever displayed it.
#[rstest]
#[case::not_text("%FF")]
#[case::embedded_nul("%00a")]
#[case::truncated_escape("a%F")]
#[case::non_hexadecimal_escape("a%ZZ")]
fn a_malformed_label_is_refused(#[case] label: &str) {
    let offered = format!("otpauth://totp/{label}?secret={KEY}");
    assert!(matches!(
        TotpParams::parse(&offered),
        Err(OtpError::Import {
            reason: Rejected::Label
        })
    ));
}

/// A label is decoded once. Twice would turn `%2540` into `@`, which is how two readers of one link
/// end up naming different accounts. Nothing here is kept, so the check is that it parses at all.
#[test]
fn a_double_encoded_label_is_decoded_once_and_dropped() -> Result<(), OtpError> {
    let offered = format!("otpauth://totp/%2540home?secret={KEY}");
    assert_eq!(
        code_at(&offered, 1_234_567_890)?,
        code_at(KEY, 1_234_567_890)?
    );
    Ok(())
}

/// Text far longer than a secret is refused before it is looked at, and so is a key that decodes to
/// more bytes than any generator uses.
///
/// The first case is the one that says "before it is decoded": it is a perfectly good secret with a
/// parameter this build has no name for padded out past the cap, so it parses if the cap is not
/// there and is refused only because of its length. Two walls of `A` would prove nothing, since the
/// key cap answers those with the same reason a few thousand decoded bytes later.
#[test]
fn oversized_input_is_refused_before_it_is_decoded() {
    let padded = uri(&format!("&note={}", "n".repeat(2048)));
    assert!(padded.len() > 2048);
    assert!(matches!(
        TotpParams::parse(&padded),
        Err(OtpError::Import {
            reason: Rejected::TooLong
        })
    ));
    // The same text under the cap is a working secret, so length is the only thing refusing it.
    assert!(TotpParams::parse(&uri("&note=nn")).is_ok());

    let wide_key = "A".repeat(1000);
    assert!(matches!(
        TotpParams::parse(&wide_key),
        Err(OtpError::Import {
            reason: Rejected::TooLong
        })
    ));
}

/// The secret is percent-decoded exactly once. Twice, and a key whose escape decodes into a
/// character the base32 alphabet does not hold becomes a different, perfectly valid key: the two
/// readers of one link then import different secrets, which is the differential the hand-written
/// grammar exists to prevent. Asserted on the secret rather than on the label because the label is
/// decoded and thrown away, so both behaviours look identical there.
#[test]
fn a_double_encoded_secret_is_decoded_once_and_refused() {
    let escaped = format!("otpauth://totp/x?secret={}%2550", &KEY[..KEY.len() - 1]);
    assert!(matches!(
        TotpParams::parse(&escaped),
        Err(OtpError::Import {
            reason: Rejected::SecretAlphabet
        })
    ));
    // What a second pass would have turned it into: a key that imports cleanly.
    let once = format!("otpauth://totp/x?secret={}P", &KEY[..KEY.len() - 1]);
    assert!(TotpParams::parse(&once).is_ok());
}

/// An exotic parameter is kept exactly as it was given and reported, never rewritten to the value
/// the login server accepts: a user with a genuinely unusual secret gets wrong codes with an
/// explanation rather than wrong codes without one.
#[test]
fn exotic_parameters_are_stored_and_reported() -> Result<(), OtpError> {
    let params = TotpParams::parse(&uri("&algorithm=SHA512&digits=8&period=60"))?;
    assert_eq!(params.algorithm(), Algorithm::Sha512);
    assert_eq!(params.digits(), 8);
    assert_eq!(params.period(), 60);
    assert_eq!(
        params.deviations(),
        vec![
            Deviation::Algorithm {
                offered: Algorithm::Sha512,
                accepted: Algorithm::Sha1,
            },
            Deviation::Digits {
                offered: 8,
                accepted: USABLE_DIGITS,
            },
            Deviation::Period {
                offered: 60,
                accepted: USABLE_PERIOD,
            },
        ]
    );
    Ok(())
}

/// The stored form goes back through the same grammar, so a change to the parser that broke the
/// round trip would break importing and reading back together rather than one of them silently.
#[test]
fn the_canonical_form_round_trips() -> Result<(), OtpError> {
    let params = TotpParams::parse(&uri("&algorithm=SHA256&digits=8&period=45"))?;
    let before = params.code(at(1_234_567_890), ClockSkew::NONE)?;
    let before = before.expose().to_owned();

    let stored = params.into_secret();
    let after = TotpParams::from_secret(&stored)?;
    assert_eq!(after.algorithm(), Algorithm::Sha256);
    assert_eq!(after.digits(), 8);
    assert_eq!(after.period(), 45);
    assert_eq!(
        after.code(at(1_234_567_890), ClockSkew::NONE)?.expose(),
        before
    );
    Ok(())
}

/// The buffer the canonical form is built in is erased when it drops, and is wide enough for the
/// whole of it before a key byte goes in.
///
/// Both halves are the same defect. A buffer that grows moves what it already holds, and the block
/// it hands back to the allocator keeps the key in it: only the last buffer reaches the store, and
/// only that one is erased. The type is asserted by a helper that would not compile against a plain
/// `String`, and the sizing is asserted at every extreme the type accepts at once.
#[test]
fn the_canonical_buffer_is_erased_and_never_grows() -> Result<(), OtpError> {
    fn erased(_: &Zeroizing<String>) {}

    for key_bytes in [MIN_KEY_BYTES, 32, 100, MAX_KEY_BYTES] {
        let params = TotpParams::assemble(
            Zeroizing::new(vec![0x5a; key_bytes]),
            Algorithm::Sha512,
            MAX_DIGITS,
            MAX_PERIOD,
        )
        .map_err(|reason| OtpError::Import { reason })?;
        let text = params.canonical();
        erased(&text);
        let wanted = canonical_capacity((key_bytes * 8).div_ceil(5));
        assert!(
            text.len() <= wanted,
            "a {key_bytes}-byte key wrote {} bytes into a buffer sized for {wanted}",
            text.len()
        );
        // The buffer is still the one it was created with: a grown buffer carries the capacity a
        // doubling left it at, and the block it grew out of went back to the allocator with the key
        // in it.
        assert_eq!(
            text.capacity(),
            wanted,
            "the canonical buffer was reallocated"
        );
    }
    Ok(())
}

/// The two failure paths are told apart by where the text came from, because a caller answers them
/// differently: one is a paste to correct, the other is a stored value to replace.
#[test]
fn a_stored_value_that_does_not_parse_reports_stored_not_import() {
    let not_text = Secret::new(vec![0xff, 0xfe]);
    assert!(matches!(
        TotpParams::from_secret(&not_text),
        Err(OtpError::Stored { .. })
    ));

    let unusable = Secret::from_string("otpauth://hotp/a?secret=AAAAAAAAAAAAAAAA".to_owned());
    assert!(matches!(
        TotpParams::from_secret(&unusable),
        Err(OtpError::Stored {
            reason: Rejected::Type
        })
    ));
}

/// The profile is the one thing in the crate holding a long-lived shared secret, so its rendering is
/// the shortest route that secret has to a log line.
#[test]
fn a_rendered_profile_never_shows_the_key() -> Result<(), OtpError> {
    let params = TotpParams::parse(&uri(""))?;
    let rendered = format!("{params:?}");
    assert!(!rendered.contains("JBSWY3DP"), "{rendered}");
    assert!(rendered.contains("Sha1"), "{rendered}");
    Ok(())
}

proptest! {
    /// A code is the same everywhere inside its window and changes at the boundary. Asserted as
    /// equality against the window's first second rather than as inequality across the boundary:
    /// two adjacent six-digit codes collide once in a million, and a shrinker finds that.
    #[test]
    fn a_code_is_constant_inside_its_window(seconds in 0u64..2_000_000_000) {
        let here = code_for(seconds);
        prop_assert!(here.is_some());
        prop_assert_eq!(here, code_for(seconds - seconds % 30));
    }

    /// The three seconds every naive implementation gets wrong, asserted as the window a code came
    /// from rather than as two codes differing: the interval is half-open, so the last second of a
    /// window still produces its code and the instant on the boundary already produces the next.
    #[test]
    fn the_boundary_second_belongs_to_the_window_it_opens(k in 0u64..60_000_000) {
        let start = k * 30;
        prop_assert_eq!(code_for(start), code_of_window(k));
        prop_assert_eq!(code_for(start + 29), code_of_window(k));
        prop_assert_eq!(code_for(start + 30), code_of_window(k + 1));
        prop_assert_eq!(code_for(start + 31), code_of_window(k + 1));
    }

    /// A code is a step function of the clock and of nothing else: whatever instant it was asked
    /// for, it is the code of the window that instant falls in. This is the relation the reuse
    /// guard's walk forward and the caller's wait are both built on.
    #[test]
    fn a_code_is_the_code_of_the_window_it_falls_in(seconds in 0u64..2_000_000_000) {
        prop_assert_eq!(code_for(seconds), code_of_window(seconds / 30));
    }

    /// The correction is an offset applied to the clock, with the sign the name carries: a server
    /// that is ahead gets the code its own clock is about to want. A flipped sign generates a code
    /// one window out in exactly the situation the correction exists for, and nothing else here
    /// would notice, because both codes are well formed.
    #[test]
    fn a_skew_offset_moves_the_clock_by_its_own_sign(
        seconds in 100u64..2_000_000_000,
        offset in -90i64..90,
    ) {
        prop_assert_eq!(
            code_with_skew(seconds, offset),
            code_for(seconds.saturating_add_signed(offset))
        );
    }

    /// Across three rollovers the code changes only on a boundary, and it does change. The first
    /// half is the strong claim and is exact; the second is asserted over four windows at once
    /// rather than over one pair, because one pair of six-digit codes matches once in a million and
    /// four in a row match about once in every million million million.
    #[test]
    fn a_code_changes_only_where_a_window_does(k in 0u64..60_000_000, into in 0u64..30) {
        let start = k * 30 + into;
        let mut previous = code_for(start);
        let mut changes = 0;
        for step in 1..=90 {
            let here = code_for(start + step);
            prop_assert!(here.is_some());
            if here != previous {
                prop_assert_eq!((start + step) % 30, 0, "a code changed inside a window");
                changes += 1;
            }
            previous = here;
        }
        prop_assert!(changes > 0, "no code changed across three windows");
    }

    /// Whatever text is accepted, the profile it produced is inside every range this type promises
    /// and derives a code exactly as wide as it says, all digits. The width is the part worth
    /// having: the published table pins six and eight at fixed instants, and a formatter that
    /// dropped a leading zero or ignored the count would be wrong everywhere else.
    #[test]
    fn an_accepted_import_keeps_every_promise_the_type_makes(
        secret in "(JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP|jbswy3dpehpk3pxpjbswy3dpehpk3pxp====|[A-Za-z2-7 =-]{0,40})",
        digits in "(6|6|7|8|[0-9]{1,4}|)",
        period in "(30|30|60|[0-9]{1,4}|)",
        algorithm in "(SHA1|SHA1|sha256|SHA512|[A-Za-z0-9]{1,6}|)",
    ) {
        let offered =
            format!("otpauth://totp/x?secret={secret}&digits={digits}&period={period}&algorithm={algorithm}");
        if let Ok(params) = TotpParams::parse(&offered) {
            prop_assert!((6..=8).contains(&params.digits()));
            prop_assert!((1..=300).contains(&params.period()));
            let code = params.code(at(1_234_567_890), ClockSkew::NONE);
            prop_assert!(code.is_ok());
            if let Ok(code) = code {
                prop_assert_eq!(code.len(), usize::from(params.digits()));
                prop_assert!(code.expose().bytes().all(|b| b.is_ascii_digit()));
            }
        }
    }

    /// Structural fuzz over the characters an import is built from: never takes the process down,
    /// always a clean answer.
    #[test]
    fn parse_never_panics(offered in "[A-Za-z0-9:/?&=%.#@+_~\\- ]{0,300}") {
        let _ = TotpParams::parse(&offered);
    }

    /// The same over arbitrary text, which is what a paste actually is. The grammar slices its input
    /// by byte offset in four places, and every one of them is a character boundary a multi-byte
    /// character can sit across.
    #[test]
    fn parse_never_panics_on_arbitrary_text(offered in "(?s).{0,200}") {
        let _ = TotpParams::parse(&offered);
    }

    /// And over text built to reach the parser's own branches: the scheme, the authority and the
    /// separators, with arbitrary characters between them.
    #[test]
    fn parse_never_panics_on_a_mangled_link(
        head in "(otpauth|otpauth-migration|OTPAUTH|https|)",
        marker in "(://|:/|:|//|)",
        body in "(?s).{0,80}",
    ) {
        let _ = TotpParams::parse(&format!("{head}{marker}{body}"));
    }
}
