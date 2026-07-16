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
    ///
    /// The game runs under Wine, which maps `GetTickCount` onto the host `CLOCK_MONOTONIC_RAW`, so the
    /// launcher must read that same clock or the game can't recover the key. Mirrors XL's Linux
    /// `GetRawTickCount`
    /// (`References/FFXIVQuickLauncher/src/XIVLauncher.Common/Encryption/ArgumentBuilder.cs:122-132`):
    /// `CLOCK_MONOTONIC_RAW`, then `tv_sec * 1000 + tv_nsec / 1_000_000`, truncated to `u32`.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn now_for_game() -> Self {
        use rustix::time::{ClockId, clock_gettime};
        let ts = clock_gettime(ClockId::MonotonicRaw);
        Self(timespec_to_tick(ts.tv_sec, ts.tv_nsec))
    }

    /// Off-Linux there is no game to launch as a native process; the host tick source is unimplemented.
    #[cfg(not(target_os = "linux"))]
    #[must_use]
    pub fn now_for_game() -> Self {
        todo!("host monotonic tick source is Linux-only")
    }

    /// Construct from a fixed raw tick. Deterministic; the entry point for tests and goldens.
    #[must_use]
    pub fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
}

/// The pure fold from a `CLOCK_MONOTONIC_RAW` timespec to SE's 32-bit tick.
///
/// Byte-identical to XL's `(uint)((tv_sec * 1000) + (tv_nsec / 1000000))`: wrapping `i64` arithmetic
/// then a 32-bit truncation reproduce C#'s unchecked `long` math and `(uint)` cast for every input.
#[cfg(target_os = "linux")]
fn timespec_to_tick(sec: i64, nsec: i64) -> u32 {
    sec.wrapping_mul(1000).wrapping_add(nsec / 1_000_000) as u32
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::timespec_to_tick;

    #[test]
    fn fold_matches_xl_oracle() {
        assert_eq!(timespec_to_tick(0, 0), 0);
        assert_eq!(timespec_to_tick(1, 0), 1000);
        assert_eq!(timespec_to_tick(0, 1_000_000), 1);
        assert_eq!(timespec_to_tick(0, 999_999), 0); // sub-ms truncated
        assert_eq!(timespec_to_tick(4_294_967, 301_000_000), 5); // (uint) 32-bit wrap
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
