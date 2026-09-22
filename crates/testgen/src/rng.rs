//! A seeded `xorshift64*` generator whose sequence is fixed for all time.
//!
//! The stream is part of this crate's interface: a given seed produces the same
//! values on every platform and every release.

/// A seeded xorshift64\* generator. Period `2^64 - 1`.
#[derive(Debug, Clone)]
pub struct Rng {
    /// Never zero: the constructor guarantees it and no step can reach it.
    state: u64,
}

/// The xorshift64\* output multiplier, and the fallback state when the seed
/// finalises to zero.
const SCRAMBLE: u64 = 0x2545_F491_4F6C_DD1D;

impl Rng {
    /// Seed the generator. Every `u64` is a legal seed, including zero.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        // SplitMix64 finaliser: decorrelates adjacent seeds, which raw
        // xorshift does not.
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        Self {
            state: if z == 0 { SCRAMBLE } else { z },
        }
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(SCRAMBLE)
    }

    /// A uniform value in `0..bound`.
    pub fn below(&mut self, bound: u64) -> u64 {
        assert!(bound > 0, "Rng::below needs a positive bound");
        // Largest multiple of `bound` in the draw space; the tail above it is
        // the biased part and is redrawn.
        let ceiling = (u64::MAX / bound) * bound;
        loop {
            let draw = self.next_u64();
            if draw < ceiling {
                return draw % bound;
            }
        }
    }

    /// A uniform value in `lo..hi`, half-open.
    pub fn range(&mut self, lo: i64, hi: i64) -> i64 {
        assert!(hi > lo, "Rng::range needs lo < hi, got {lo}..{hi}");
        // The span of an `i64` interval can overflow `i64` but never `u64`.
        #[allow(
            clippy::cast_sign_loss,
            reason = "the wrapping difference of two i64 is the exact span as u64"
        )]
        let span = (hi as u64).wrapping_sub(lo as u64);
        #[allow(
            clippy::cast_possible_wrap,
            reason = "offset is below span, so lo + offset is in lo..hi and cannot wrap"
        )]
        let offset = self.below(span) as i64;
        lo.wrapping_add(offset)
    }

    /// A uniform value in `0.0..1.0`, built from the top 53 bits.
    pub fn unit(&mut self) -> f64 {
        // 2^53 exactly.
        const MANTISSA: f64 = 9_007_199_254_740_992.0;
        #[allow(
            clippy::cast_precision_loss,
            reason = "the value is below 2^53, which f64 represents exactly"
        )]
        let numerator = (self.next_u64() >> 11) as f64;
        numerator / MANTISSA
    }

    /// Fisher-Yates, in place.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "below(i + 1) is at most i, which came from a usize"
            )]
            let j = self.below(i as u64 + 1) as usize;
            items.swap(i, j);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Rng;

    /// One seed fixes the stream.
    #[test]
    fn one_seed_gives_one_stream() {
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        let left: Vec<u64> = (0..64).map(|_| a.next_u64()).collect();
        let right: Vec<u64> = (0..64).map(|_| b.next_u64()).collect();
        assert_eq!(left, right);
    }

    /// Adjacent seeds give different streams.
    #[test]
    fn adjacent_seeds_do_not_agree_on_their_first_draws() {
        let first: Vec<u64> = (0..8).map(|_| Rng::new(1).next_u64()).collect();
        let second: Vec<u64> = (0..8).map(|_| Rng::new(2).next_u64()).collect();
        assert_ne!(first, second);
    }

    /// `below(n)` is in `0..n` for every draw and every bound.
    #[test]
    fn below_stays_within_its_bound_for_every_bound() {
        let mut rng = Rng::new(0);
        for bound in 1..64u64 {
            for _ in 0..256 {
                assert!(rng.below(bound) < bound);
            }
        }
    }

    /// `range` is half-open, so `lo` can occur and `hi` cannot.
    #[test]
    fn range_is_half_open() {
        let mut rng = Rng::new(3);
        let mut saw_lo = false;
        for _ in 0..4096 {
            let v = rng.range(-5, 5);
            assert!((-5..5).contains(&v), "{v} escaped -5..5");
            saw_lo |= v == -5;
        }
        assert!(saw_lo, "the lower bound never occurred in 4096 draws");
    }

    /// A shuffle preserves the multiset it permutes.
    #[test]
    fn shuffle_is_a_permutation() {
        let mut rng = Rng::new(11);
        let mut items: Vec<u32> = (0..97).collect();
        rng.shuffle(&mut items);
        let mut sorted = items.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..97).collect::<Vec<u32>>());
        assert_ne!(items, sorted, "97 elements shuffled to sorted order");
    }

    /// `unit` stays in `0.0..1.0` with mean near a half; the 0.02 tolerance is
    /// over four standard errors at 4096 draws.
    #[test]
    fn unit_is_in_the_half_open_unit_interval_with_mean_one_half() {
        let mut rng = Rng::new(5);
        let mut total = 0.0;
        for _ in 0..4096 {
            let v = rng.unit();
            assert!((0.0..1.0).contains(&v), "{v} escaped 0.0..1.0");
            total += v;
        }
        let mean = total / 4096.0;
        assert!((mean - 0.5).abs() < 0.02, "mean {mean} is not near 0.5");
    }
}
