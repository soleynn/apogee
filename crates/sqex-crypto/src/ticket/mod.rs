//! The obfuscated authentication ticket the login query carries.
//!
//! The raw ticket is expanded to lowercase hex and NUL-terminated, prefixed with a 16-bit sum of
//! those bytes, padded to an 8-byte multiple with characters drawn from a 64-entry alphabet by an
//! MSVCRT-style generator, overwritten at its head with the generator's running sum, byte-swapped in
//! its first two bytes, encrypted with textbook big-endian [`Blowfish`] under a key derived from a
//! minute-rounded clock reading, mangled-base64-encoded, and cut into 300-character comma-joined
//! chunks.
//!
//! Byte-identity with the SE launcher is the bar, so every quirk is reproduced deliberately: the
//! clock subtraction wraps, the sum is sign-extended before it seeds the generator, the running sum
//! overwrites bytes that were already written, and the swap lands on top of that overwrite. Each is
//! commented where it happens and pinned by a recorded vector.

use core::fmt;

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{Blowfish, CrtRand, CryptoError, bytes, sqex_base64};

#[cfg(test)]
mod tests;

/// The alphabet the padding characters are drawn from: digits, uppercase, lowercase, `-`, `_`.
///
/// Deliberately *not* the mangled base64 alphabet. The two hold the same 64 characters in a
/// different order, so reusing [`sqex_base64`]'s table here would produce plausible output that the
/// server rejects.
const PAD_ALPHABET: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";

/// Lowercase hex digits, for the ticket expansion and the cipher key.
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// The fixed tail of the cipher key, appended to eight hex digits of the rounded clock.
const KEY_SUFFIX: &[u8; 8] = b"#un@e=x>";

/// The encoded text is cut into chunks of this many characters, joined by commas.
const CHUNK: usize = 300;

/// A server clock reading in whole Unix seconds.
///
/// A newtype so a millisecond value cannot be passed by mistake, and 32-bit because the launcher's
/// clock word is: the value is rendered as exactly eight hex digits into the cipher key, so a wider
/// integer would silently produce a longer key and a different ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerTime(pub u32);

impl ServerTime {
    /// Truncate a signed Unix-seconds reading to the 32-bit clock word.
    ///
    /// Keeps the low 32 bits and discards sign and any high bits, reproducing the narrowing the
    /// launcher performs on its own 64-bit clock. Callers holding a `SystemTime` seconds count go
    /// through here rather than spelling the cast at each call site.
    #[must_use]
    pub fn from_unix_seconds(secs: i64) -> Self {
        Self(secs as u32)
    }
}

/// An obfuscated authentication ticket: the query text and the length reported beside it.
///
/// Both halves are load-bearing on the wire, and the length is *not* the text's length: the text
/// carries the chunk separators and the reported length does not count them. The text goes into the
/// query raw. Percent-encoding it would escape the separator and the padding character, and the
/// server would not see the same value.
///
/// The text is a bearer credential, so it zeroizes on drop, implements no `Display`, `Clone`, or
/// `Serialize`, and its [`Debug`] redacts.
#[derive(ZeroizeOnDrop)]
pub struct ObfuscatedTicket {
    text: String,
    /// A public size rather than a secret, and zeroizing an integer is theatre.
    #[zeroize(skip)]
    length: usize,
}

impl ObfuscatedTicket {
    /// Obfuscate `raw` against `time`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::EmptyTicket`] when `raw` is empty. Every other input, including any
    /// `time` value whatsoever, yields a ticket.
    pub fn from_auth_ticket(raw: &[u8], time: ServerTime) -> Result<Self, CryptoError> {
        // The generator's running sum is seeded by reading the first four bytes back out of the
        // buffer, which exist only once the ticket has contributed at least two hex digits.
        // Splitting the first byte off here both rejects the empty ticket and hands that seed the
        // byte it needs, so the transform below holds no slice index that could be out of range.
        let Some((&first, _)) = raw.split_first() else {
            return Err(CryptoError::EmptyTicket);
        };

        let rounded = round_to_minute(time.0);
        let key = blowfish_key(rounded);
        let buf = Zeroizing::new(build_buffer(raw, first, rounded));

        let ciphertext = Zeroizing::new(Blowfish::new(key.as_slice()).encrypt(&buf));
        let encoded = Zeroizing::new(sqex_base64::encode(&ciphertext));

        Ok(Self {
            length: encoded.len(),
            text: split_join(&encoded),
        })
    }

    /// The query text, chunk separators included.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The reported length: the encoded length *before* chunking, so it excludes the separators.
    #[must_use]
    pub fn length(&self) -> usize {
        self.length
    }
}

impl fmt::Debug for ObfuscatedTicket {
    /// Redacts the text. A formatted ticket must never put a live credential in a log line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfuscatedTicket")
            .field("length", &self.length)
            .field("text", &"<redacted>")
            .finish()
    }
}

/// Round a clock reading down five seconds and then to the minute.
///
/// The launcher subtracts five in an unchecked 32-bit context, so a reading below five wraps to near
/// `u32::MAX` instead of saturating, and every value in `0..=4` lands on the same rounded result as
/// `u32::MAX`. Widening either operation to 64 bits, or to a signed type, changes the answer: signed
/// remainder would make the second step subtract a negative.
fn round_to_minute(time: u32) -> u32 {
    let t = time.wrapping_sub(5);
    // Total rather than wrapping: `t % 60` is never greater than `t`.
    t - t % 60
}

/// The 16-byte cipher key: eight lowercase hex digits of `rounded`, then [`KEY_SUFFIX`].
///
/// Rendered nibble by nibble rather than through `format!` so the digits never occupy an
/// un-zeroized heap `String`, matching how the launch-argument key is built. The result is
/// byte-identical to `{rounded:08x}` for every input, which a test pins rather than a comment.
fn blowfish_key(rounded: u32) -> Zeroizing<[u8; 16]> {
    let mut key = Zeroizing::new([0u8; 16]);
    for (i, slot) in key.iter_mut().take(8).enumerate() {
        *slot = HEX_LOWER[((rounded >> (28 - 4 * i)) & 0xF) as usize];
    }
    key[8..].copy_from_slice(KEY_SUFFIX);
    key
}

/// Seed the padding generator from the rounded clock and the ticket sum.
///
/// The sum is reinterpreted as *signed* before it widens, so a sum with bit 15 set fills the high
/// half with ones and flips the top sixteen bits of the clock. Folding the sum in unsigned instead
/// produces a well-formed ticket with entirely different padding, which only the server would
/// reject, so the cast chain is spelled out and pinned by a vector.
fn rand_seed(rounded: u32, ticket_sum: u16) -> u32 {
    rounded ^ (ticket_sum as i16 as i32 as u32)
}

/// Build the plaintext block: the sum, the hex-expanded ticket, its terminator, and the padding.
///
/// `first` is `raw`'s first byte, already split off by the caller so this function holds no index.
fn build_buffer(raw: &[u8], first: u8, rounded: u32) -> Vec<u8> {
    // Two sum bytes, two hex digits per raw byte, one terminator, then padded up to a block
    // multiple. Exact rather than an estimate, so the buffer never grows: a reallocation would
    // strand a plaintext copy of the credential in freed heap that no wrapper can reach.
    let reserved = (2 * raw.len() + 3).next_multiple_of(8);
    let mut buf = Vec::with_capacity(reserved);

    // The sum's two bytes are written last, once the sum is known; reserve their slots first so the
    // hex lands at the offset the rest of the transform expects.
    buf.extend_from_slice(&[0, 0]);

    let mut ticket_sum: u16 = 0;
    for &b in raw {
        let (hi, lo) = hex_digits(b);
        buf.push(hi);
        buf.push(lo);
        // Accumulated as 16-bit and wrapping: the launcher truncates on every step, and for any
        // real ticket the sum passes the wrap point many times over, so where bit 15 lands is
        // load-bearing for the seed above.
        ticket_sum = ticket_sum
            .wrapping_add(u16::from(hi))
            .wrapping_add(u16::from(lo));
    }
    // The terminator is summed too, and contributes nothing.
    buf.push(0);

    let sum_bytes = bytes::write_u16_le(ticket_sum);
    buf[..2].copy_from_slice(&sum_bytes);

    let mut rng = CrtRand::new(rand_seed(rounded, ticket_sum));
    // The running sum starts as the little-endian word at the buffer head, which is the two sum
    // bytes followed by the two hex digits of the ticket's first byte. Derived from the values in
    // hand rather than read back out of the buffer: identical by construction, and it keeps the
    // read that the launcher performs host-endian from becoming a latent portability bug here.
    let (first_hi, first_lo) = hex_digits(first);
    let mut running = bytes::u32_le([sum_bytes[0], sum_bytes[1], first_hi, first_lo]);

    // The padding count is the distance to the next block boundary, so it is the loop bound itself
    // rather than a separately computed length that could disagree with the buffer.
    let total = buf.len().next_multiple_of(8);
    for _ in buf.len()..total {
        let ch = PAD_ALPHABET[(running.wrapping_add(rng.next()) & 0x3F) as usize];
        buf.push(ch);
        // The *character code* folds back in, not the 0..63 index that selected it. Folding the
        // index instead still yields in-range characters from the same alphabet, so nothing local
        // catches it.
        running = running.wrapping_add(u32::from(ch));
    }

    // The running sum overwrites the head, destroying the ticket sum and the first two hex digits.
    // It never extends the buffer: appending instead produces a correctly shaped, correctly encoded,
    // entirely plausible ticket that is wrong. The sum therefore never reaches the wire; its only
    // effects are the seed and this word's starting value.
    if let Some(slot) = buf.first_chunk_mut::<4>() {
        *slot = bytes::write_u32_le(running);
    }
    // After the overwrite, so this swaps the low two bytes of the running sum, not the ticket sum.
    buf.swap(0, 1);

    // The only witness that the reservation above still matches what the loops below it wrote.
    // Nothing observable in the output changes when it does not, so under-reserving here is silent:
    // the ticket is byte-identical and a plaintext copy of the credential is left in freed heap.
    debug_assert_eq!(
        buf.len(),
        reserved,
        "the ticket buffer outgrew its reservation"
    );
    buf
}

/// Split `b64` into [`CHUNK`]-character pieces joined by commas.
fn split_join(b64: &str) -> String {
    let raw = b64.as_bytes();
    let chunks = raw.len().div_ceil(CHUNK);
    let reserved = raw.len() + chunks.saturating_sub(1);
    let mut text = String::with_capacity(reserved);
    for (i, chunk) in raw.chunks(CHUNK).enumerate() {
        if i > 0 {
            text.push(',');
        }
        // The encoder emits ASCII only, so a byte is a char and there is no slice index here that
        // could split a multi-byte sequence.
        text.extend(chunk.iter().map(|&b| b as char));
    }
    debug_assert_eq!(
        text.len(),
        reserved,
        "the chunked text outgrew its reservation"
    );
    text
}

/// One byte as its two lowercase hex digits, high nibble first.
fn hex_digits(b: u8) -> (u8, u8) {
    (HEX_LOWER[(b >> 4) as usize], HEX_LOWER[(b & 0x0F) as usize])
}
