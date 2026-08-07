//! The import grammar: the crate's only hostile parser.
//!
//! Everything here runs on text that arrived from a paste, a clipboard or a file some other program
//! wrote, so it is written to a rule rather than delegated. A general-purpose URL parser is not used
//! for three reasons that each show up as a real input below: it accepts userinfo and a port and
//! then drops them, it treats the authority of a non-special scheme as opaque and so refuses a
//! capitalized `TOTP`, and its query decoder turns `+` into a space and replaces bytes that are not
//! text with a replacement character instead of saying so.
//!
//! No rejection carries any of the offered text. An `otpauth` URI is a secret in its entirety.

use zeroize::Zeroizing;

use super::{Algorithm, TotpParams};
use crate::error::Rejected;

/// The longest text accepted before anything is looked at. A shared secret and its parameters are
/// well under a hundred characters; the cap is what bounds the work a paste can ask for.
const MAX_INPUT: usize = 2048;

const SCHEME: &str = "otpauth://";
const MIGRATION: &str = "otpauth-migration://";

/// The type this crate generates for. A counter-based profile is a different algorithm, not a
/// variation on this one.
const TIME_BASED: &str = "totp";
const COUNTER_BASED: &str = "hotp";

/// Parse an `otpauth` URI or a raw base32 secret.
pub(super) fn parse(offered: &str) -> Result<TotpParams, Rejected> {
    let trimmed = offered.trim_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.len() > MAX_INPUT {
        return Err(Rejected::TooLong);
    }
    // A fragment is not part of the data, and leaving it on would fold into the secret on the raw
    // arm and into the last parameter's value on the URI arm.
    let body = trimmed.split_once('#').map_or(trimmed, |(head, _)| head);
    let body = body.trim_matches(|c: char| c.is_ascii_whitespace());
    if body.is_empty() {
        return Err(Rejected::Empty);
    }

    // Checked before the general scheme test so a bulk export from another authenticator gets its
    // own answer rather than a complaint about the scheme. Users paste these.
    if starts_with_ignoring_case(body, MIGRATION) {
        return Err(Rejected::MigrationBundle);
    }
    if let Some(rest) = strip_prefix_ignoring_case(body, SCHEME) {
        return parse_uri(rest);
    }
    // The scheme is there and the authority marker is not. This is the shape that takes a
    // general-purpose parser down, so it is named rather than fed to the base32 arm.
    if starts_with_ignoring_case(body, "otpauth:") {
        return Err(Rejected::Authority);
    }
    if body.contains("://") {
        return Err(Rejected::Scheme);
    }
    parse_raw_secret(body)
}

/// A bare base32 secret, with everything else defaulted to what the login server accepts.
fn parse_raw_secret(body: &str) -> Result<TotpParams, Rejected> {
    let key = decode_secret(body)?;
    TotpParams::assemble(
        key,
        Algorithm::Sha1,
        super::USABLE_DIGITS,
        super::USABLE_PERIOD,
    )
}

/// The grammar after the `otpauth://` literal.
fn parse_uri(rest: &str) -> Result<TotpParams, Rejected> {
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, after) = rest.split_at(split);

    // Userinfo and a port are both accepted-and-ignored by a general-purpose parser, which is a
    // parser-differential surface: two readers of the same text disagree about which host it names.
    if authority.contains('@') || authority.contains(':') {
        return Err(Rejected::Authority);
    }
    if authority.eq_ignore_ascii_case(COUNTER_BASED) {
        return Err(Rejected::Type);
    }
    if !authority.eq_ignore_ascii_case(TIME_BASED) {
        return Err(Rejected::Authority);
    }

    let (label, query) = match after.split_once('?') {
        Some((label, query)) => (label, Some(query)),
        None => (after, None),
    };
    check_label(label.strip_prefix('/').unwrap_or(label))?;
    parse_query(query.unwrap_or(""))
}

/// The label is decoded so a malformed one is refused, and then dropped.
///
/// Nothing here is stored or displayed, so the issuer-agrees-with-the-label-prefix rule is not
/// applied: every implementation that has one compares case-sensitively and so falsely rejects real
/// exports, and it protects a field this crate does not keep.
fn check_label(label: &str) -> Result<(), Rejected> {
    let decoded = percent_decode(label).ok_or(Rejected::Label)?;
    if decoded.chars().any(char::is_control) {
        return Err(Rejected::Label);
    }
    Ok(())
}

fn parse_query(query: &str) -> Result<TotpParams, Rejected> {
    let mut seen: Vec<String> = Vec::new();
    let mut key: Option<Zeroizing<Vec<u8>>> = None;
    let mut algorithm = Algorithm::Sha1;
    let mut digits = super::USABLE_DIGITS;
    let mut period = super::USABLE_PERIOD;

    for element in query.split('&') {
        if element.is_empty() {
            continue;
        }
        let (name, value) = element.split_once('=').unwrap_or((element, ""));
        let name = name.to_ascii_lowercase();
        // Recognized or not. A repeated key is the classic smuggling shape, and "the last one wins"
        // is how two parsers come to disagree about which secret was imported.
        if seen.contains(&name) {
            return Err(Rejected::DuplicateParameter);
        }
        seen.push(name.clone());

        match name.as_str() {
            "secret" => {
                let decoded = percent_decode(value).ok_or(Rejected::SecretAlphabet)?;
                key = Some(decode_secret(&decoded)?);
            }
            "algorithm" => {
                let decoded = percent_decode(value).ok_or(Rejected::Algorithm)?;
                algorithm = match decoded.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    _ => return Err(Rejected::Algorithm),
                };
            }
            "digits" => {
                let decoded = percent_decode(value).ok_or(Rejected::Digits)?;
                digits = decoded.parse::<u8>().map_err(|_| Rejected::Digits)?;
            }
            "period" => {
                let decoded = percent_decode(value).ok_or(Rejected::Period)?;
                period = decoded.parse::<u32>().map_err(|_| Rejected::Period)?;
            }
            // A counter parameter marks a counter-based profile whatever the authority said.
            "counter" => return Err(Rejected::Type),
            // The format is de facto and grows, so an unrecognized key is data this build has no
            // name for rather than a reason to refuse a working secret.
            _ => (),
        }
    }

    TotpParams::assemble(
        key.ok_or(Rejected::SecretMissing)?,
        algorithm,
        digits,
        period,
    )
}

/// Normalize and decode a base32 secret.
///
/// Case, `=` padding, spacing and hyphens are all normalized away first. Real exports and
/// hand-transcribed keys carry all four and the decoder rejects every one of them, so a secret that
/// works everywhere else would otherwise be refused here.
fn decode_secret(raw: &str) -> Result<Zeroizing<Vec<u8>>, Rejected> {
    let mut normalized = Zeroizing::new(String::with_capacity(raw.len()));
    for c in raw.chars() {
        if c.is_ascii_whitespace() || c == '-' {
            continue;
        }
        normalized.push(c.to_ascii_uppercase());
    }
    while normalized.ends_with('=') {
        normalized.pop();
    }
    if normalized.is_empty() {
        return Err(Rejected::SecretMissing);
    }
    base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        normalized.as_str(),
    )
    .map(Zeroizing::new)
    .ok_or(Rejected::SecretAlphabet)
}

/// Decode percent-escapes exactly once, refusing a truncated or non-hexadecimal escape and bytes
/// that are not text.
///
/// Exactly once is the contract: a decoder run twice turns `%2540` into `@`, which is how two
/// readers of the same text end up with different labels.
fn percent_decode(text: &str) -> Option<Zeroizing<String>> {
    let bytes = text.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            out.push((high << 4) | low);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    Some(Zeroizing::new(std::str::from_utf8(&out).ok()?.to_owned()))
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn starts_with_ignoring_case(text: &str, prefix: &str) -> bool {
    strip_prefix_ignoring_case(text, prefix).is_some()
}

fn strip_prefix_ignoring_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        text.get(prefix.len()..)
    } else {
        None
    }
}
