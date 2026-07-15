//! The MSVCRT `rand()` generator: a linear congruential generator returning a 15-bit value.
//! Reproduced with wrapping 32-bit arithmetic to match C's overflow semantics.

/// Stateful MSVCRT-style pseudo-random generator.
#[derive(Debug, Clone)]
pub struct CrtRand {
    seed: u32,
}

impl CrtRand {
    /// Seed the generator.
    #[must_use]
    pub fn new(seed: u32) -> Self {
        Self { seed }
    }

    /// Advance and return the next 15-bit value.
    #[allow(clippy::should_implement_trait)] // not an Iterator: yields a bare u32, mirrors C rand()
    pub fn next(&mut self) -> u32 {
        self.seed = self
            .seed
            .wrapping_mul(0x0003_43fd)
            .wrapping_add(0x0026_9ec3);
        (self.seed >> 16) & 0x7fff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_documented_msvcrt_sequence() {
        // The canonical `srand(1)` output every MSVC `rand()` produces.
        let mut rng = CrtRand::new(1);
        let got: Vec<u32> = (0..8).map(|_| rng.next()).collect();
        assert_eq!(got, [41, 18467, 6334, 26500, 19169, 15724, 11478, 29358]);
    }

    #[test]
    fn stays_within_15_bits() {
        let mut rng = CrtRand::new(0x1234_5678);
        for _ in 0..1000 {
            assert!(rng.next() <= 0x7fff);
        }
    }
}
