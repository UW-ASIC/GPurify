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
    /// Seeds the generator. Every `u64` is a legal seed, including zero. The
    /// seed passes through the `SplitMix64` finaliser first, so adjacent
    /// seeds start unrelated streams.
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

    /// The next 64 bits of the stream: one step, the unit every other draw
    /// is built from, so a seed's sequence is the sequence of these.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(SCRAMBLE)
    }

    /// A uniform value in `0..bound`, without modulo bias: a draw from the
    /// biased tail is discarded and redrawn, so one call may consume more than
    /// one value of the stream.
    ///
    /// # Panics
    ///
    /// Panics if `bound` is zero.
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

    /// A uniform value in `lo..hi`, half-open. Any span fits, even
    /// `i64::MIN..i64::MAX`.
    ///
    /// # Panics
    ///
    /// Panics unless `lo < hi`.
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

    /// A uniform value in `0.0..1.0`, built from the top 53 bits of one draw;
    /// `1.0` never occurs.
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

    /// Shuffles `items` in place, Fisher-Yates: every permutation equally
    /// likely.
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

    /// Adjacent seeds start unrelated streams, as [`Rng::new`] documents: over
    /// the first 64 draws of seeds `s` and `s + 1`, the two windows share no
    /// value, and each output bit of position-matched draws differs about half
    /// the time.
    ///
    /// Oracle: law, the avalanche property the `SplitMix64` finaliser is built
    /// for (Steele, Lea and Flood, "Fast Splittable Pseudorandom Number
    /// Generators", OOPSLA 2014; its constants are Stafford's Mix13, "Better
    /// Bit Mixing", 2011): a changed input flips each output bit with
    /// probability 1/2. Over 256 adjacent pairs each (draw, bit) cell counts
    /// the pairs that differ there, Binomial(256, 1/2) for unrelated streams:
    /// mean 128, sd 8, and the test allows 6 sd. And `x * SCRAMBLE` is a
    /// bijection (the multiplier is odd), so a value common to both windows is
    /// a common state: one stream the other shifted by under 64 draws.
    #[test]
    fn adjacent_seeds_start_unrelated_streams() {
        const SEEDS: u64 = 256;
        const DRAWS: usize = 64;
        let window = |seed: u64| {
            let mut rng = Rng::new(seed);
            [(); DRAWS].map(|()| rng.next_u64())
        };
        let mut differ = [[0u32; 64]; DRAWS];
        for seed in 0..SEEDS {
            let (a, b) = (window(seed), window(seed + 1));
            assert!(
                !a.iter().any(|x| b.contains(x)),
                "seeds {seed} and {} share a state within {DRAWS} draws",
                seed + 1
            );
            for (cells, (x, y)) in differ.iter_mut().zip(a.iter().zip(&b)) {
                for (bit, count) in cells.iter_mut().enumerate() {
                    *count += u32::from(((x ^ y) >> bit) & 1 == 1);
                }
            }
        }
        for (draw, cells) in differ.iter().enumerate() {
            for (bit, &count) in cells.iter().enumerate() {
                assert!(
                    (80..=176).contains(&count),
                    "draw {draw}, bit {bit}: {count} of {SEEDS} adjacent pairs differ"
                );
            }
        }
    }

    /// `below(n)` is in `0..n` for every draw and every bound.
    ///
    /// Oracle: the documented range of `below(n)`, `0..n`, on every bound from
    /// 1 to 63.
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
    ///
    /// Oracle: the documented half-open range: every draw in `-5..5`, and `-5`
    /// occurs, which 4096 draws miss with probability 0.9^4096.
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
    ///
    /// Oracle: law. A shuffle is a permutation, so sorting it gives back
    /// `0..97`; coming back sorted has odds of 1 in 97!.
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
    ///
    /// Oracle: closed form. A uniform draw on [0, 1) has mean 1/2 and standard
    /// deviation 1/sqrt(12), so the mean of 4096 has standard error 0.0045 and
    /// 0.02 is over four of them.
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
