//! Integration tests for `engine`, one module each.

/// The corpus splitter, shared with `tests/common`. Included by path rather
/// than through `common`: this binary wants the fixture root and none of the
/// rest of that module.
#[path = "../common/gen_fixtures.rs"]
mod gen_fixtures;

mod checks;
mod pipeline;
mod summary;
