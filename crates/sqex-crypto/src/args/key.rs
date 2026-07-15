//! The launch-argument key and its tick source.
//!
//! The key is the high 16 bits of a monotonic tick; the full tick also travels in the `T` argument so
//! the game can re-derive the key. Key material is zeroized on drop and never rendered (no `Debug`,
//! `Display`, `Clone`, or `Serialize`).

use zeroize::ZeroizeOnDrop;

/// A monotonic millisecond tick, the sole nondeterministic input to argument encryption.
#[derive(ZeroizeOnDrop)]
pub struct TickCount(u32);

impl TickCount {
    /// Read the host monotonic tick the game will re-derive its key from.
    #[must_use]
    pub fn now_for_game() -> Self {
        todo!("read the host monotonic tick source")
    }

    /// Construct from a fixed raw tick. Deterministic; the entry point for tests and goldens.
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
    /// Construct from a tick, the sole source of an `ArgKey`. `TickCount::from_raw` is the
    /// deterministic entry point tests and goldens use; `TickCount::now_for_game` is the live source.
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
