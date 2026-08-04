//! Cross-dimension arithmetic.
//!
//! Only the combinations this tree actually performs are implemented. That is
//! the whole list, and it is short on purpose: a general dimensional algebra
//! would be several hundred impls to support five call sites.
//!
//! **Operands may carry any prefix; results are canonical.** `mV / µA`
//! compiles, and yields `Qty<Resistance, 0>` — ohms — with the `10^(P-Q)`
//! factor applied at runtime. The alternative, deriving the output prefix from
//! the operands, needs `generic_const_exprs` and is not available on stable.
//! Canonical results also stop prefixes propagating into downstream signatures,
//! which is the larger win: a rule's limit column has one prefix, not one per
//! call path.
//!
//! Call `.to::<MILLI>()` on the result if a different prefix is wanted.

use crate::qty::{Area, Current, CurrentDensity, Length, Qty, Resistance, Voltage};
use std::ops::{Div, Mul};

macro_rules! product {
    ($($lhs:ident * $rhs:ident => $out:ident, $why:literal;)*) => {$(
        #[doc = $why]
        impl<const P: i8, const Q: i8> Mul<Qty<$rhs, Q>> for Qty<$lhs, P> {
            type Output = Qty<$out, 0>;
            fn mul(self, rhs: Qty<$rhs, Q>) -> Qty<$out, 0> {
                debug_assert!(
                    self.is_finite() && rhs.is_finite(),
                    concat!("non-finite operand to ", stringify!($lhs), " * ", stringify!($rhs)),
                );
                // Both operands to base units first: the `10^(P+Q)` factor is
                // then just the two scalings `Qty::base` already performs, and
                // the result is canonical because base units *are* `10^0`.
                Qty::new(self.base() * rhs.base())
            }
        }
    )*};
}

macro_rules! quotient {
    ($($num:ident / $den:ident => $out:ident, $why:literal;)*) => {$(
        #[doc = $why]
        impl<const P: i8, const Q: i8> Div<Qty<$den, Q>> for Qty<$num, P> {
            type Output = Qty<$out, 0>;
            fn div(self, rhs: Qty<$den, Q>) -> Qty<$out, 0> {
                debug_assert!(
                    self.is_finite() && rhs.is_finite(),
                    concat!("non-finite operand to ", stringify!($num), " / ", stringify!($den)),
                );
                // `10^(P-Q)` as the quotient of the two `base` scalings. A zero
                // denominator is left to produce an infinity rather than a
                // typed error: `Div` cannot return one, and a zero resistance
                // is a short — a legal physical input, not an unsupported one.
                // The finiteness net is `Qty::is_finite`, asserted where a
                // quantity enters a report.
                Qty::new(self.base() / rhs.base())
            }
        }
    )*};
}

product! {
    Length * Length => Area, "Physical area. Layout area is `DbuArea`, not this.";
    Current * Resistance => Voltage, "Ohm's law. Branch current to IR drop.";
}

quotient! {
    Voltage / Current => Resistance, "Ohm's law. Point-to-point resistance from a probe solve.";
    Voltage / Resistance => Current, "Ohm's law. Supply drop to branch current.";
    Current / Length => CurrentDensity, "Electromigration: current per unit conductor width.";
}

// `Capacitance` and `Inductance` deliberately carry no operators, and the list
// above is closed rather than pending. Both are terminal quantities here: `pex`
// produces them from a field solve or a closed form, and every consumer
// downstream — `network`, `reduce`, `export` — only sums or writes them. Nor
// does any product or quotient of them land in a dimension this crate has:
// `Ohm * Farad` is a time and `Farad * Volt` a charge, and `qty::dimensions!`
// declares neither. An impl for either would therefore mean a new public marker
// type with no reader, which is a larger interface, not a better one.
