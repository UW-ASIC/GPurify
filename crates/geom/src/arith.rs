//! Cross-dimension arithmetic. Operands may carry any prefix; results are
//! always canonical (`10^0`), so call `.to::<MILLI>()` if another is wanted.

use crate::qty::{Area, Current, CurrentDensity, Length, Qty, Resistance, Voltage};
use std::ops::{Div, Mul};

macro_rules! product {
    ($($lhs:ident * $rhs:ident => $out:ident, $why:literal;)*) => {$(
        #[doc = $why]
        impl<const P: i8, const Q: i8> Mul<Qty<$rhs, Q>> for Qty<$lhs, P> {
            type Output = Qty<$out, 0>;
            fn mul(self, rhs: Qty<$rhs, Q>) -> Qty<$out, 0> {
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
                // Zero denominator gives inf, not an error: a zero resistance is a legal short.
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

// `Capacitance` and `Inductance` are terminal: no product of them lands in a
// dimension this crate declares.
