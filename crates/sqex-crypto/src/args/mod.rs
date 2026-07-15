//! The `sqex0003` encrypted launch-argument string.
//!
//! An ordered key/value set is serialized with SE's exact quirks (a leading space on every pair, `/`
//! before the key, a space before `=`, and single spaces doubled), encrypted with the little-endian
//! [`LegacyBlowfish`] variant under a tick-derived key, mangled-base64-encoded, tagged with a checksum
//! char, and wrapped in `//**sqex0003…**//`. Byte-identity with the SE launcher is the bar, so every
//! quirk is reproduced deliberately.

use zeroize::Zeroizing;

use crate::{LegacyBlowfish, sqex_base64};

mod key;
#[cfg(test)]
mod tests;

pub use key::{ArgKey, TickCount};

/// The format version embedded in the wrapper (`sqex{version:04}`).
const VERSION: u32 = 3;

/// The 16-entry checksum alphabet, indexed by one nibble of the key.
const CHECKSUM_TABLE: [char; 16] = [
    'f', 'X', '1', 'p', 'G', 't', 'd', 'S', '5', 'C', 'A', 'P', '4', '_', 'V', 'L',
];

/// Builds the launcher's argument string, plain or encrypted.
#[derive(Default)]
pub struct ArgumentBuilder {
    args: Vec<(String, String)>,
}

impl ArgumentBuilder {
    /// A builder with no arguments.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a key/value pair, preserving insertion order.
    #[must_use]
    pub fn add(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args.push((key.into(), value.into()));
        self
    }

    /// The plaintext form used when argument encryption is disabled: `" {key}={value}"` per pair, no
    /// `/`, no space before `=`, no escaping, no `T` (matches the launcher's plain build).
    #[must_use]
    pub fn build_plain(&self) -> String {
        let mut out = String::new();
        for (k, v) in &self.args {
            out.push(' ');
            out.push_str(k);
            out.push('=');
            out.push_str(v);
        }
        out
    }

    /// The `//**sqex0003…**//` encrypted form.
    ///
    /// `T={ticks}` is inserted as the first pair from `key` itself (overwriting a caller-supplied `T`
    /// at index 0 rather than duplicating it), so the key and the `T` value cannot desync.
    #[must_use]
    pub fn build_encrypted(&self, key: &ArgKey) -> String {
        // The serialized plaintext carries the session id and other credential-bearing args in the
        // clear, so build it straight into a zeroizing buffer that is wiped on drop. Pre-size to an
        // upper bound (every space can at most double) so growth never reallocates and strands a
        // cleartext copy in freed heap. `T={ticks}` leads, derived from the key itself; a
        // caller-supplied leading `T` is dropped rather than duplicated, so key and `T` can't desync.
        let cap = self
            .args
            .iter()
            .map(|(k, v)| 4 + 2 * (k.len() + v.len()))
            .sum::<usize>()
            + 20;
        let mut plaintext = Zeroizing::new(String::with_capacity(cap));
        push_pair(&mut plaintext, "T", &key.ticks().to_string());
        let skip_first = self.args.first().is_some_and(|(k, _)| k == "T");
        for (k, v) in self.args.iter().skip(usize::from(skip_first)) {
            push_pair(&mut plaintext, k, v);
        }

        let key_bytes = Zeroizing::new(key.key_bytes());
        let ciphertext = LegacyBlowfish::new(key_bytes.as_slice()).encrypt(plaintext.as_bytes());
        let body = sqex_base64::encode(&ciphertext);
        let checksum = derive_checksum(key.key());
        format!("//**sqex{:04}{}{}**//", VERSION, body, checksum)
    }
}

/// Append one serialized `" /{key} ={value}"` pair, escaping both halves in place.
fn push_pair(out: &mut String, key: &str, value: &str) {
    out.push_str(" /");
    push_escaped(out, key);
    out.push_str(" =");
    push_escaped(out, value);
}

/// Append `s` with every space doubled (SE escapes keys and values this way). Byte-identical to
/// `s.replace(' ', "  ")`, but appends in place instead of allocating a fresh `String` per call.
fn push_escaped(out: &mut String, s: &str) {
    for ch in s.chars() {
        out.push(ch);
        if ch == ' ' {
            out.push(' ');
        }
    }
}

/// The checksum char for `key`: one nibble (bits 16-19) indexes the table. The mask makes the index
/// structurally in-range; `'!'` is the launcher's out-of-range fallback, reproduced for parity.
fn derive_checksum(key: u32) -> char {
    let index = ((key & 0x000F_0000) >> 16) as usize;
    CHECKSUM_TABLE.get(index).copied().unwrap_or('!')
}
