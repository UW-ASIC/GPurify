//! String interning.
//!
//! Names — nets, cells, layers, rule ids, hierarchy path components — are
//! identity, not data. They are compared and hashed millions of times and read
//! as text exactly once, when a report reaches a human. So they become a `u32`
//! at the boundary and stay one.
//!
//! # No hash map
//!
//! The table is a sorted index over the string arena, looked up by binary
//! search. That is not a micro-optimisation, it is the determinism gate: a
//! `HashMap` iterated in seed order is what made 8 of 27 parasitic reports in
//! the old tree differ between runs of the same binary. A sorted table has one
//! iteration order on every machine.
//!
//! Interning is O(log n) per name rather than O(1). It happens once per name at
//! ingest, so that is not a cost worth a nondeterministic data structure.

/// An interned string.
///
/// Comparable and hashable as a `u32`. Two `StrId` from different [`StrTable`]s
/// are not comparable, and nothing checks that — there is one table per run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct StrId(pub u32);

/// The one string table for a run.
///
/// **Five questions.** In: `&str`. Out: [`StrId`]. How many: tens of thousands
/// of distinct names, each interned once and resolved rarely. Access pattern:
/// write-heavy during ingest, read-only afterwards, and the read is by id.
/// Lifetime: the whole run. Parallelisable: no — interning is inherently
/// sequential, which is fine because it is not on a hot path.
#[derive(Debug, Default)]
pub struct StrTable {
    /// All bytes, concatenated. One allocation, not one per string.
    arena: String,
    /// `arena[span[i].0 .. span[i].1]` is string `i`. Indexed by [`StrId`].
    span: Vec<(u32, u32)>,
    /// Ids sorted by their string's bytes. The binary-search index.
    sorted: Vec<StrId>,
}

impl StrTable {
    pub fn with_capacity(names: usize, bytes: usize) -> Self {
        todo!()
    }

    /// Intern a name, returning the existing id if it is already present.
    ///
    /// **Decision** — one string in, one id out, and idempotent: interning the
    /// same name twice returns the same id. That idempotence is what the test
    /// plan checks, along with the sorted index staying sorted.
    pub fn intern(&mut self, name: &str) -> StrId {
        todo!()
    }

    /// Look up without interning. `None` for an unknown name.
    ///
    /// Used by consumers that must not grow the table — a rule referring to a
    /// layer that does not exist is an error, not a new layer.
    pub fn get(&self, name: &str) -> Option<StrId> {
        todo!()
    }

    /// Resolve an id back to text. The only place a `StrId` becomes readable,
    /// and it is called when writing a report.
    pub fn resolve(&self, id: StrId) -> &str {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        todo!()
    }
}
