//! Client identities: the user-agent strings, the machine computer-id, and the frontier referer.
//!
//! SE fingerprints these, so each is reproduced exactly. The launcher user agent embeds a computer-id
//! whose derivation (SHA1 over the UTF-16LE encoding of host facts, with a checksum byte prepended) is
//! an easy thing to port wrong, so it is golden-tested (`Launcher.cs:657-673`).

use std::fmt;

use sha1::{Digest, Sha1};

use crate::time::LauncherTime;

/// The patcher user agent, sent on the boot- and game-version checks. SE also defines a `-MAC` variant
/// for the Mac service; a Linux-first launcher presents as the Windows client.
pub const PATCHER_USER_AGENT: &str = "FFXIV PATCH CLIENT";

/// A computer-id is a checksum byte followed by the first four bytes of the host-facts hash.
const COMPUTER_ID_LEN: usize = 5;

/// A machine identifier SE's launcher sends on frontier and OAuth requests: five bytes rendered as ten
/// lowercase hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComputerId([u8; COMPUTER_ID_LEN]);

impl ComputerId {
    /// Derive a computer-id from fixed host facts: SHA1 over the UTF-16LE encoding of
    /// `machine_name + user_name + os_version + processor_count`, with the digest's first four bytes at
    /// positions 1-4 and a checksum (the two's-complement negation of their sum) at position 0.
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

    /// Derive a computer-id from the running host. The stability-versus-privacy choice (host-derived
    /// like SE, or random per install) is settled with the login surface.
    #[must_use]
    pub fn from_host() -> Self {
        todo!("read host identity facts")
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

/// The launcher user agent for OAuth pages and frontier requests, embedding `computer_id`.
#[must_use]
pub fn launcher_user_agent(computer_id: &ComputerId) -> String {
    format!("SQEXAuthor/2.0.0(Windows 6.2; ja-jp; {computer_id})")
}

/// Fill a caller-supplied frontier referer template: `{lang}` becomes the language code with dashes
/// turned to underscores (`en-us` -> `en_us`); `{time}` becomes the supplied UTC timestamp.
#[must_use]
pub fn frontier_referer(template: &str, language: &str, timestamp: &str) -> String {
    template
        .replace("{lang}", &language.replace('-', "_"))
        .replace("{time}", timestamp)
}

/// The per-install, per-locale client values every launcher request carries: the computer-id, the
/// language code, the `Accept-Language` header, and the frontier referer template. Both the frontier
/// and OAuth contexts embed this so the shared plumbing lives in one place.
pub struct ClientContext<'a> {
    /// The launcher computer-id, embedded in the user agent.
    pub computer_id: &'a ComputerId,
    /// The client language code (e.g. `en-us`), used for the referer and the gate-status query.
    pub language: &'a str,
    /// The `Accept-Language` header value.
    pub accept_language: &'a str,
    /// The referer URL template, with `{lang}` and `{time}` placeholders.
    pub referer_template: &'a str,
}

impl ClientContext<'_> {
    /// The launcher user agent and frontier referer this client sends, derived together since every
    /// request builds both from these fields.
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

/// Encode a string as UTF-16LE bytes (the encoding SE hashes host facts under).
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
}
