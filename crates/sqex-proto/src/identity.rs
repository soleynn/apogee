// Client identities: the user-agent strings, the machine computer-id, and the frontier referer. SE
// fingerprints these, so each is reproduced exactly. The launcher user agent embeds a computer-id
// whose derivation (SHA1 over the UTF-16LE encoding of caller-supplied facts, with a checksum byte
// prepended) is an easy thing to port wrong, so it is golden-tested (Launcher.cs:657-673). The facts
// are caller-supplied rather than read here on purpose: apogee-core's production caller deliberately
// feeds it a random per-install id instead of the host's real machine name and username, so the value
// carries no link back to the host. Do not wire this to real host facts without re-checking that
// contract in apogee-core.

use std::fmt;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use sha1::{Digest, Sha1};

use crate::time::LauncherTime;

pub const PATCHER_USER_AGENT: &str = "FFXIV PATCH CLIENT";

const COMPUTER_ID_LEN: usize = 5;

const REFERER_LANG: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputerId([u8; COMPUTER_ID_LEN]);

impl ComputerId {
    #[must_use]
    pub fn from_facts(
        machine_name: &str,
        user_name: &str,
        os_version: &str,
        processor_count: u32,
    ) -> Self {
        let concatenated = format!("{machine_name}{user_name}{os_version}{processor_count}");
        let digest = Sha1::digest(encode_utf16le(&concatenated));

        let mut bytes = [0u8; COMPUTER_ID_LEN];
        bytes[1..].copy_from_slice(&digest[..4]);
        let sum = bytes[1]
            .wrapping_add(bytes[2])
            .wrapping_add(bytes[3])
            .wrapping_add(bytes[4]);
        bytes[0] = 0u8.wrapping_sub(sum);
        Self(bytes)
    }
}

impl fmt::Display for ComputerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[must_use]
pub fn launcher_user_agent(computer_id: &ComputerId) -> String {
    format!("SQEXAuthor/2.0.0(Windows 6.2; ja-jp; {computer_id})")
}

#[must_use]
pub fn frontier_referer(template: &str, language: &str, timestamp: &str) -> String {
    let language = language.replace('-', "_");
    // The timestamp needs no escaping: it comes from `LauncherTime`'s renderers, whose output is digits
    // and dashes by construction. Unlike `language` it is not a free-form locale string.
    fill_template(
        template,
        &utf8_percent_encode(&language, REFERER_LANG).to_string(),
        timestamp,
    )
}

fn fill_template(template: &str, language: &str, timestamp: &str) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(brace) = rest.find('{') {
        out.push_str(&rest[..brace]);
        rest = &rest[brace..];
        if let Some(tail) = rest.strip_prefix("{lang}") {
            out.push_str(language);
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("{time}") {
            out.push_str(timestamp);
            rest = tail;
        } else {
            out.push('{');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    out
}

pub struct ClientContext<'a> {
    pub computer_id: &'a ComputerId,
    pub language: &'a str,
    pub accept_language: &'a str,
    pub referer_template: &'a str,
}

impl ClientContext<'_> {
    pub(crate) fn user_agent_and_referer(&self, now: &LauncherTime) -> (String, String) {
        (
            launcher_user_agent(self.computer_id),
            frontier_referer(
                self.referer_template,
                self.language,
                &now.referer_timestamp(),
            ),
        )
    }
}

fn encode_utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use apogee_test_support::golden::assert_golden_bytes;

    #[test]
    fn utf16le_encodes_ascii_as_low_byte_then_zero() {
        assert_eq!(encode_utf16le("AB"), [0x41, 0x00, 0x42, 0x00]);
    }

    #[test]
    fn computer_id_checksum_zeroes_the_byte_sum() {
        let id = ComputerId::from_facts("host", "user", "os", 4);
        let sum: u8 = id.0.iter().copied().fold(0u8, u8::wrapping_add);
        assert_eq!(sum, 0);
    }

    #[test]
    fn computer_id_matches_the_independent_golden() {
        // The expected value comes from an independent implementation of the documented algorithm run
        // over the same fixed synthetic facts; no real machine data and no SE bytes.
        let id = ComputerId::from_facts("APOGEE-TEST", "apogee", "TESTOS-1.0", 8);
        assert_golden_bytes(id.to_string().as_bytes(), b"1588d5721c");
    }

    #[test]
    fn launcher_user_agent_embeds_the_computer_id() {
        let id = ComputerId::from_facts("APOGEE-TEST", "apogee", "TESTOS-1.0", 8);
        assert_eq!(
            launcher_user_agent(&id),
            "SQEXAuthor/2.0.0(Windows 6.2; ja-jp; 1588d5721c)"
        );
    }

    #[test]
    fn frontier_referer_underscores_lang_and_inserts_time() {
        let referer = frontier_referer(
            "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
            "en-us",
            "2024-01-02-03-40",
        );
        assert_eq!(
            referer,
            "https://launcher.finalfantasyxiv.com/v700/?rc_lang=en_us&time=2024-01-02-03-40"
        );
    }

    #[test]
    fn fill_template_does_not_rescan_substituted_text() {
        // One left-to-right pass, matching the oracle's positional `string.Format`: a language whose text
        // is itself the `{time}` placeholder fills the language slot literally. Sequential `.replace()`
        // calls would let the second replacement overwrite the first's output with the timestamp.
        assert_eq!(
            fill_template("?rc_lang={lang}&time={time}", "{time}", "2024-01-02-03-40"),
            "?rc_lang={time}&time=2024-01-02-03-40"
        );
        // The reverse direction too: a timestamp containing `{lang}` is not re-read as a placeholder.
        assert_eq!(
            fill_template("?rc_lang={lang}&time={time}", "en_us", "{lang}"),
            "?rc_lang=en_us&time={lang}"
        );
    }

    #[test]
    fn fill_template_passes_through_an_unknown_placeholder() {
        assert_eq!(
            fill_template("?a={unknown}&b={lang}&c={", "en_us", "t"),
            "?a={unknown}&b=en_us&c={"
        );
    }

    #[test]
    fn frontier_referer_escapes_query_structure_in_the_language() {
        // The sibling `lang` query parameter is percent-encoded by the `url` crate; the referer must not
        // be the one surface where a language code can inject or truncate query structure.
        let escape = |language| {
            frontier_referer(
                "https://launcher.finalfantasyxiv.com/v700/?rc_lang={lang}&time={time}",
                language,
                "2024-01-02-03-40",
            )
        };
        assert_eq!(
            escape("en-us&admin=1"),
            "https://launcher.finalfantasyxiv.com/v700/?rc_lang=en_us%26admin%3D1&time=2024-01-02-03-40"
        );
        assert_eq!(
            escape("en-us#frag&x=1"),
            "https://launcher.finalfantasyxiv.com/v700/?rc_lang=en_us%23frag%26x%3D1&time=2024-01-02-03-40"
        );
        assert_eq!(
            escape("en-us?evil=1"),
            "https://launcher.finalfantasyxiv.com/v700/?rc_lang=en_us%3Fevil%3D1&time=2024-01-02-03-40"
        );
    }

    #[test]
    fn frontier_referer_leaves_every_real_locale_byte_identical() {
        // Encoding must be invisible for the input SE actually serves: the unreserved set covers every
        // locale code, so the emitted referer stays byte-identical to the reference launcher's.
        for language in ["en-us", "ja-jp", "de-de", "fr-fr", "zh-cn"] {
            let referer = frontier_referer("{lang}", language, "t");
            assert_eq!(referer, language.replace('-', "_"));
        }
    }
}
