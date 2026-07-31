//! The launch-argument key and its tick.
//!
//! The key is the high 16 bits of a monotonic tick; the full tick also travels in the `T` argument so
//! the game can re-derive the key.
//!
//! The tick is supplied, never read here: reading it means naming a host clock, and which clock is
//! correct depends on how the game is being launched, which only the composition root knows. That
//! keeps this crate pure, so every transform in it is reproducible from its inputs alone.
//!
//! Neither type renders itself (no `Debug`, `Display`, `Clone`, or `Serialize`) and both zeroize on
//! drop. That is hygiene, not secrecy: the protocol puts the tick in the `T` argument as decimal
//! text, and the checksum character publishes four of its bits, so the key is recoverable from the
//! emitted string by anyone who wants it.

use zeroize::ZeroizeOnDrop;

/// A monotonic millisecond tick, the sole nondeterministic input to argument encryption.
///
/// Whatever produces this must read the same clock the game will read when it re-derives the key, and
/// must do so close enough to the launch that the value still matches. The game masks off the low 16
/// bits and retries exactly one 65536 ms step below its own reading, so a tick more than two of those
/// steps stale cannot be recovered.
#[derive(ZeroizeOnDrop)]
pub struct TickCount(u32);

impl TickCount {
    /// Construct from a raw tick. The only constructor, so the transform is deterministic and the
    /// clock read stays outside this crate.
    #[must_use]
    pub fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
}

/// The launch-argument key, derived from a tick.
///
/// `raw` is the full tick (decimal-serialized into the `T` argument); the Blowfish key is its high 16
/// bits (`raw & 0xFFFF_0000`), rendered as 8 lowercase-hex ASCII bytes.
#[derive(ZeroizeOnDrop)]
pub struct ArgKey {
    raw: u32,
}

impl ArgKey {
    /// Construct from a tick, the sole source of an `ArgKey`.
    #[must_use]
    pub fn from_tick(tick: TickCount) -> Self {
        Self { raw: tick.0 }
    }

    /// The full raw tick, serialized decimal into the `T` argument.
    #[must_use]
    pub(super) fn ticks(&self) -> u32 {
        self.raw
    }

    /// The Blowfish key: the high 16 bits of the tick.
    #[must_use]
    pub(super) fn key(&self) -> u32 {
        self.raw & 0xFFFF_0000
    }

    /// The key rendered as 8 lowercase-hex ASCII bytes (all < 0x80, so the signed-key fold is dormant).
    ///
    /// Rendered nibble by nibble rather than through `format!` so the secret key digits never occupy
    /// an un-zeroized heap `String`; the output is byte-identical to `{:08x}`.
    #[must_use]
    pub(super) fn key_bytes(&self) -> [u8; 8] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let k = self.key();
        let mut out = [0u8; 8];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = HEX[((k >> (28 - 4 * i)) & 0xF) as usize];
        }
        out
    }
}
