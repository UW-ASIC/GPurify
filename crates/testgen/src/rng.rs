//! A seeded generator whose sequence is fixed for all time.
//!
//! Not `rand`. A test corpus that changes when a dependency bumps its default
//! algorithm is not reproducible, and a failure that cannot be reproduced from
//! a seed printed in a log is a failure nobody fixes. So the algorithm is
//! written out here, in eleven lines, and it is part of this crate's interface:
//! **seed 7 produces the same stream on every platform, in every release, for
//! as long as this file is unchanged.**
//!
//! # The algorithm
//!
//! Marsaglia's xorshift64, output-scrambled by a multiply — `xorshift64*`. The
//! state is 64 bits, the period is `2^64 - 1` (every state except zero occurs
//! exactly once per cycle), and it passes `BigCrush`. It is not cryptographic and
//! nothing here wants it to be: the requirement is a long period, a cheap step
//! and a fixed definition.
//!
//! Zero is the one state xorshift cannot leave, so [`Rng::new`] runs the seed
//! through a `SplitMix64` finaliser first. That also decorrelates adjacent
//! seeds, which matters because tests seed from small integers.

/// A seeded xorshift64\* generator. Period `2^64 - 1`.
#[derive(Debug, Clone)]
pub struct Rng {
    /// Never zero: the constructor guarantees it and no step can reach it.
    state: u64,
}

/// The xorshift64\* output multiplier, from Vigna's paper. Also the fallback
/// state, chosen only because it is a known-good odd constant.
const SCRAMBLE: u64 = 0x2545_F491_4F6C_DD1D;

impl Rng {
    /// Seed the generator. Every `u64` is a legal seed, including zero.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        // SplitMix64's finaliser. Its job here is not randomness but
        // separation: `new(1)` and `new(2)` must not produce streams that
        // agree for their first few values, and raw xorshift seeds do.
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
    ///
    /// Rejection sampling, not `% bound`. The modulo is biased towards small
    /// values whenever `bound` does not divide `2^64`, and a generator that
    /// quietly skews the corpus it builds is a worse problem than the loop:
    /// the expected number of draws is below `1 + 2^-63` for every bound this
    /// crate uses.
    ///
    /// # Panics
    ///
    /// When `bound` is zero — there is no value to return.
    pub fn below(&mut self, bound: u64) -> u64 {
        assert!(bound > 0, "Rng::below needs a positive bound");
        // Largest multiple of `bound` that fits in the draw space. Values at
        // or above it are the biased tail and are redrawn.
        let ceiling = (u64::MAX / bound) * bound;
        loop {
            let draw = self.next_u64();
            if draw < ceiling {
                return draw % bound;
            }
        }
    }

    /// A uniform value in `lo..hi`, half-open.
    ///
    /// # Panics
    ///
    /// When `hi` is not greater than `lo`.
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

    /// A uniform value in `0.0..1.0`.
    ///
    /// Built from the top 53 bits, which is every bit an `f64` mantissa can
    /// hold — so the result is uniform over the representable values rather
    /// than over a coarser grid rescaled to look continuous.
    pub fn unit(&mut self) -> f64 {
        // 2^53 exactly, written as an f64 so no cast is needed at all.
        const MANTISSA: f64 = 9_007_199_254_740_992.0;
        #[allow(
            clippy::cast_precision_loss,
            reason = "the value is below 2^53, which f64 represents exactly"
        )]
        let numerator = (self.next_u64() >> 11) as f64;
        numerator / MANTISSA
    }

    /// Fisher-Yates, in place.
    ///
    /// Each permutation is equally likely because [`Rng::below`] is unbiased.
    /// Used wherever a construct-from-answer builder must prove the code under
    /// test does not depend on input order: the answer is fixed before the
    /// shuffle, and the shuffle is what makes the input arbitrary.
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

    /// Oracle: determinism. The claim in this module's docs is that a seed
    /// fixes the stream, and the only way to state that as a test is to draw
    /// twice from two generators built the same way.
    #[test]
    fn one_seed_gives_one_stream() {
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        let left: Vec<u64> = (0..64).map(|_| a.next_u64()).collect();
        let right: Vec<u64> = (0..64).map(|_| b.next_u64()).collect();
        assert_eq!(left, right);
    }

    /// Oracle: determinism, the other half. Two seeds that differ by one must
    /// not produce streams that agree, which is the property the `SplitMix64`
    /// finaliser in `new` exists to buy.
    #[test]
    fn adjacent_seeds_do_not_agree_on_their_first_draws() {
        let first: Vec<u64> = (0..8).map(|_| Rng::new(1).next_u64()).collect();
        let second: Vec<u64> = (0..8).map(|_| Rng::new(2).next_u64()).collect();
        assert_ne!(first, second);
    }

    /// Oracle: law. `below(n)` is in `0..n` for every draw and every bound,
    /// which is the contract the geometry builders rely on to stay inside the
    /// coordinate domain.
    #[test]
    fn below_stays_within_its_bound_for_every_bound() {
        let mut rng = Rng::new(0);
        for bound in 1..64u64 {
            for _ in 0..256 {
                assert!(rng.below(bound) < bound);
            }
        }
    }

    /// Oracle: law. `range` is half-open, so `lo` can occur and `hi` cannot.
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

    /// Oracle: law. A permutation preserves the multiset it permutes, whatever
    /// the seed. That is the whole correctness claim for a shuffle; that it is
    /// uniform is an argument about `below`, tested above.
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

    /// Oracle: law. The unit draw is confined to `0.0..1.0`, and its mean over
    /// many draws is near a half. The tolerance is stated: 4096 draws of a
    /// uniform have a standard error of `1/sqrt(12 * 4096)` = 0.0045, so 0.02
    /// is over four sigma and fails on a generator with any real skew.
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
