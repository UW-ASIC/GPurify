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
                todo!()
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
                todo!()
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

// ponytail: no Capacitance or Inductance operators. PEX produces both directly
// from a field solve and never derives them from other quantities, so an
// `Ohm * Farad => Time` impl would have no call site. Add one when a call site
// exists, not before.
