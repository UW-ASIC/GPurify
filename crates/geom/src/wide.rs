//! Signed 256-bit integers, for the exact distances of edges at any angle.
//!
//! A squared distance from a grid point to a skew line is `cross² / len²`
//! with `cross` up to 2^83 in magnitude, and a point where a skew edge is cut
//! has coordinates `X / W` with `X` near 2^125: their squares need up to 252
//! bits. Two's complement over four little-endian `u64` limbs; every operation
//! here stays in range for the domain (`±2^40` coordinates), and the
//! callers' debug asserts say so.

use core::cmp::Ordering;

/// A signed 256-bit integer, two's complement, little-endian limbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct I256([u64; 4]);

impl I256 {
    pub(crate) const ZERO: Self = Self([0; 4]);

    pub(crate) fn from_i128(v: i128) -> Self {
        let fill = if v < 0 { u64::MAX } else { 0 };
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "splitting into limbs"
        )]
        let (lo, hi) = (v as u64, (v >> 64) as u64);
        Self([lo, hi, fill, fill])
    }

    pub(crate) fn is_negative(self) -> bool {
        self.0[3] >> 63 == 1
    }

    #[must_use]
    pub(crate) fn add(self, o: Self) -> Self {
        let mut out = [0u64; 4];
        let mut carry = false;
        for (k, slot) in out.iter_mut().enumerate() {
            let (s, c1) = self.0[k].overflowing_add(o.0[k]);
            let (s, c2) = s.overflowing_add(u64::from(carry));
            *slot = s;
            carry = c1 || c2;
        }
        Self(out)
    }

    #[must_use]
    pub(crate) fn neg(self) -> Self {
        Self(self.0.map(|l| !l)).add(Self::from_i128(1))
    }

    #[must_use]
    pub(crate) fn sub(self, o: Self) -> Self {
        self.add(o.neg())
    }

    /// The product, modulo 2^256: exact when it fits.
    #[must_use]
    pub(crate) fn mul(self, o: Self) -> Self {
        let mut out = [0u64; 4];
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..4 - i {
                let t = u128::from(self.0[i]) * u128::from(o.0[j]) + u128::from(out[i + j]) + carry;
                #[expect(clippy::cast_possible_truncation, reason = "the low limb")]
                {
                    out[i + j] = t as u64;
                }
                carry = t >> 64;
            }
        }
        Self(out)
    }

    fn bit(self, k: usize) -> bool {
        (self.0[k / 64] >> (k % 64)) & 1 == 1
    }

    fn shl1(self, low: bool) -> Self {
        let mut out = [0u64; 4];
        let mut carry = u64::from(low);
        for (k, slot) in out.iter_mut().enumerate() {
            *slot = (self.0[k] << 1) | carry;
            carry = self.0[k] >> 63;
        }
        Self(out)
    }

    fn ucmp(self, o: Self) -> Ordering {
        self.0.iter().rev().cmp(o.0.iter().rev())
    }

    /// `floor(self / d)` and whether it leaves a remainder, for `self >= 0`,
    /// `d > 0`, by restoring division.
    pub(crate) fn div_floor(self, d: Self) -> (Self, bool) {
        debug_assert!(!self.is_negative() && !d.is_negative() && d != Self::ZERO);
        let (mut q, mut r) = (Self::ZERO, Self::ZERO);
        for k in (0..256).rev() {
            r = r.shl1(self.bit(k));
            let take = r.ucmp(d) != Ordering::Less;
            if take {
                r = r.sub(d);
            }
            q = q.shl1(take);
        }
        (q, r != Self::ZERO)
    }

    /// The value, when it fits an `i128`.
    pub(crate) fn to_i128(self) -> Option<i128> {
        let fill = if self.is_negative() { u64::MAX } else { 0 };
        let fits = self.0[2] == fill && self.0[3] == fill && (self.0[1] >> 63 == fill & 1);
        fits.then(|| (i128::from(self.0[1]) << 64) | i128::from(self.0[0]))
    }
}

impl PartialOrd for I256 {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

impl Ord for I256 {
    fn cmp(&self, o: &Self) -> Ordering {
        match (self.is_negative(), o.is_negative()) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => self.ucmp(*o),
        }
    }
}

/// `a · b` against `c · d`, exactly, for any `i128` operands under 2^126.
pub(crate) fn cmp_products(a: i128, b: i128, c: i128, d: i128) -> Ordering {
    let w = I256::from_i128;
    w(a).mul(w(b)).cmp(&w(c).mul(w(d)))
}

/// `2 · num / den` as its floor and whether that is inexact, for `num >= 0`,
/// `den > 0`: a twice-squared distance at any angle.
///
/// # Panics
///
/// When the quotient does not fit an `i128`, which no distance in the domain
/// reaches.
pub(crate) fn twice_ratio(num: I256, den: I256) -> (i128, bool) {
    let (q, inexact) = num.add(num).div_floor(den);
    (
        q.to_i128()
            .expect("a squared distance in the domain fits an i128"),
        inexact,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: closed form against `i128` arithmetic where it fits, and
    /// `(2^100)^2 / 2^150 = 2^50` beyond it.
    #[test]
    fn wide_arithmetic_matches_i128_and_powers_of_two() {
        let w = I256::from_i128;
        for (a, b) in [(7i128, -3i128), (-5, -9), (1 << 62, -(1 << 60)), (0, 5)] {
            assert_eq!(w(a).mul(w(b)).to_i128(), Some(a * b));
            assert_eq!(w(a).sub(w(b)).to_i128(), Some(a - b));
            assert_eq!(w(a).cmp(&w(b)), a.cmp(&b));
        }
        let big = w(1 << 100).mul(w(1 << 100));
        assert_eq!(big.to_i128(), None);
        assert_eq!(
            big.div_floor(w(1 << 100).mul(w(1 << 50))),
            (w(1 << 50), false)
        );
        assert_eq!(w(7).div_floor(w(2)), (w(3), true));
        assert_eq!(twice_ratio(w(5), w(4)), (2, true));
        assert_eq!(cmp_products(1 << 100, 3, 1 << 101, 1), Ordering::Greater);
        assert_eq!(cmp_products(-(1 << 100), 3, 1 << 101, 1), Ordering::Less);
    }
}
