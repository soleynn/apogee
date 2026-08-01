//! The `sqex0003` encrypted launch-argument string.
//!
//! An ordered key/value set is serialized with SE's exact quirks (a leading space on every pair, `/`
//! before the key, a space before `=`, and single spaces doubled), encrypted with the little-endian
//! [`LegacyBlowfish`] variant under a tick-derived key, mangled-base64-encoded, tagged with a checksum
//! char, and wrapped in `//**sqex0003…**//`. Byte-identity with the SE launcher is the bar, so every
//! quirk is reproduced deliberately.

use std::fmt::Write as _;

use zeroize::{ZeroizeOnDrop, Zeroizing};

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
///
/// # Examples
///
/// ```
/// use sqex_crypto::{ArgKey, ArgumentBuilder, TickCount};
///
/// let key = ArgKey::from_tick(TickCount::from_raw(0x1234_5678));
/// let encrypted = ArgumentBuilder::new()
///     .add("DEV.UseSqPack", "1")
///     .build_encrypted(&key);
///
/// assert!(encrypted.starts_with("//**sqex0003"));
/// ```
#[derive(Default, ZeroizeOnDrop)]
pub struct ArgumentBuilder {
    args: Vec<(Zeroizing<String>, Zeroizing<String>)>,
}

impl ArgumentBuilder {
    /// A builder with no arguments.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a key/value pair, preserving insertion order.
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_crypto::ArgumentBuilder;
    ///
    /// let plain = ArgumentBuilder::new()
    ///     .add("language", "1")
    ///     .add("resetConfig", "0")
    ///     .build_plain();
    /// assert_eq!(plain, " language=1 resetConfig=0");
    /// ```
    #[must_use]
    pub fn add(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args
            .push((Zeroizing::new(key.into()), Zeroizing::new(value.into())));
        self
    }

    /// The plaintext form used when argument encryption is disabled: `" {key}={value}"` per pair, no
    /// `/`, no space before `=`, no escaping, no `T` (matches the launcher's plain build).
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_crypto::ArgumentBuilder;
    ///
    /// let plain = ArgumentBuilder::new().add("language", "1").build_plain();
    /// assert_eq!(plain, " language=1");
    /// ```
    #[must_use]
    pub fn build_plain(&self) -> String {
        // Sized exactly (a space and an `=` per pair, nothing escaped) rather than grown. Growing
        // from empty reallocates once per doubling, and on a fragmented heap each move leaves the
        // session id readable in a freed block that nothing can reach to wipe.
        let cap = self
            .args
            .iter()
            .map(|(k, v)| 2 + k.len() + v.len())
            .sum::<usize>();
        let mut out = String::with_capacity(cap);
        for (k, v) in &self.args {
            out.push(' ');
            out.push_str(k);
            out.push('=');
            out.push_str(v);
        }
        // Exact, not a bound: the only witness that the reservation above still matches the loop
        // below it. Debug assertions are on in the fuzzer, which drives this over arbitrary pairs.
        debug_assert_eq!(out.len(), cap, "the plain form outgrew its reservation");
        out
    }

    /// The `//**sqex0003…**//` encrypted form.
    ///
    /// `T={ticks}` is inserted as the first pair from `key` itself (overwriting a caller-supplied `T`
    /// at index 0 rather than duplicating it), so the key and the `T` value cannot desync.
    ///
    /// # Examples
    ///
    /// ```
    /// use sqex_crypto::{ArgKey, ArgumentBuilder, TickCount};
    ///
    /// let key = ArgKey::from_tick(TickCount::from_raw(0x1234_5678));
    /// let encrypted = ArgumentBuilder::new().add("a", "b").build_encrypted(&key);
    ///
    /// assert!(encrypted.starts_with("//**sqex0003"));
    /// assert!(encrypted.ends_with("G**//")); // 'G' is this key's checksum char
    /// ```
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
        // Written directly rather than through `push_pair`: `T`'s value is a plain decimal tick, so
        // it can never contain the space `push_escaped` would double, and writing it in place skips
        // an intermediate heap `String` that would otherwise hold the key's own digits unzeroized.
        let _ = write!(plaintext, " /T ={}", key.ticks());
        let skip_first = self.args.first().is_some_and(|(k, _)| k.as_str() == "T");
        for (k, v) in self.args.iter().skip(usize::from(skip_first)) {
            push_pair(&mut plaintext, k, v);
        }
        // Checked here rather than in a test, because the value it is about is this local buffer and
        // nothing outside can see it. A reservation that came up short would have grown the string
        // above, leaving a cleartext copy of the session id in freed heap that the zeroizing wrapper
        // can no longer reach: the failure is silent, and the only witness is this line. Debug
        // assertions are on in the fuzzer, which is what drives it over adversarial argument sets.
        debug_assert!(
            plaintext.len() <= cap,
            "the argument plaintext outgrew its reservation"
        );

        let key_bytes = Zeroizing::new(key.key_bytes());
        let ciphertext = LegacyBlowfish::new(key_bytes.as_slice()).encrypt(plaintext.as_bytes());
        let body = sqex_base64::encode(&ciphertext);
        let checksum = derive_checksum(key.key());

        // Pre-sized rather than built with `format!`: `body`'s length isn't known to a format
        // string, so `format!` would under-reserve and reallocate-and-copy while writing it. 17 is
        // the fixed literal bytes: `//**sqex` (8) + the 4-digit version + the checksum (1) + `**//` (4).
        let mut out = String::with_capacity(17 + body.len());
        out.push_str("//**sqex");
        let _ = write!(out, "{VERSION:04}");
        out.push_str(&body);
        out.push(checksum);
        out.push_str("**//");
        out
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
