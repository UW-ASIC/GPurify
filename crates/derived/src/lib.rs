//! Derived layers: boolean expressions over the deck's layer table.
//!
//! Every domain needs these. DRC rules run on `poly AND diff`, device
//! recognition needs the gate layer, PEX needs conductor minus via. In the old
//! tree the expression evaluator lived in `drc` and a second, **bounding-box
//! approximate** one lived in `lvs` — the latter claiming bboxes were
//! "sufficient for manhattan geometry", which is false for any non-convex
//! shape. Its `And` over-reported and its `Subtract` over-removed, on the path
//! feeding device recognition.
//!
//! So there is one evaluator and it is exact. The bounding-box work survives as
//! [`prefilter`] — cheap rejection of pairs that provably cannot interact,
//! followed by the exact operation. That is what bboxes are good at, and it is
//! the one place they are allowed near a verdict.

pub mod expr;
pub mod prefilter;

pub use expr::{DerivedError, DerivedExpr, Evaluator, LayerRef};
