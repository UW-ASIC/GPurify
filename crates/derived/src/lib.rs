//! Derived layers: exact boolean expressions over the deck's layer table.

pub mod expr;
pub mod prefilter;

pub use expr::{DerivedError, DerivedExpr, Evaluator, LayerRef};
