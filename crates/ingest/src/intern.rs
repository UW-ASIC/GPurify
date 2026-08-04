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
//! # Two runs, not one
//!
//! The index is staged: a large `sorted` run holding everything merged so far,
//! and a small `pending` run holding names interned since the last merge. A
//! lookup binary-searches both. A new name is inserted into `pending`, which
//! memmoves a few hundred bytes; only when `pending` fills does it merge back
//! into `sorted`, which memmoves the table.
//!
//! One sorted vector would be simpler and quadratic — an insert near the front
//! of 50k names moves 200 KB, and a run pays that 50k times. Staging turns the
//! run's total from n² element moves into about n^1.5, and costs one extra
//! binary search over a run small enough to sit in L1.
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
    /// Ids sorted by their string's bytes. The merged half of the index.
    sorted: Vec<StrId>,
    /// Ids interned since the last merge, sorted by their string's bytes among
    /// themselves. Disjoint from `sorted`; the two together are every id.
    /// Bounded by [`merge_threshold`], so an insert memmoves a batch and not
    /// the table.
    pending: Vec<StrId>,
}

impl StrTable {
    pub fn with_capacity(names: usize, bytes: usize) -> Self {
        Self {
            arena: String::with_capacity(bytes),
            span: Vec::with_capacity(names),
            sorted: Vec::with_capacity(names),
            pending: Vec::with_capacity(merge_threshold(names)),
        }
    }

    /// Intern a name, returning the existing id if it is already present.
    ///
    /// **Decision** — one string in, one id out, and idempotent: interning the
    /// same name twice returns the same id. That idempotence is what the test
    /// plan checks, along with the sorted index staying sorted.
    pub fn intern(&mut self, name: &str) -> StrId {
        debug_assert_eq!(self.span.len(), self.sorted.len() + self.pending.len());

        // Each scrutinee is bound first so the immutable borrow of `self` taken
        // by the comparator ends before the `&mut self` work below.
        let merged = self.sorted.binary_search_by(|&id| self.resolve(id).cmp(name));
        if let Ok(pos) = merged {
            return self.sorted[pos];
        }
        let staged = self.pending.binary_search_by(|&id| self.resolve(id).cmp(name));
        let pos = match staged {
            Ok(pos) => return self.pending[pos],
            Err(pos) => pos,
        };

        let start = crate::narrow(self.arena.len());
        let id = StrId(crate::narrow(self.span.len()));
        self.arena.push_str(name);
        let end = crate::narrow(self.arena.len());
        self.span.push((start, end));
        self.pending.insert(pos, id);

        debug_assert_eq!(self.resolve(id), name);
        debug_assert!(pos == 0 || self.resolve(self.pending[pos - 1]) < name);
        debug_assert!(pos + 1 == self.pending.len() || self.resolve(self.pending[pos + 1]) > name);

        // Branches once per name over a run's whole length, so the predictor
        // has it: the taken side runs about sqrt(n) times out of n.
        if self.pending.len() >= merge_threshold(self.sorted.len()) {
            self.merge();
        }

        debug_assert_eq!(self.span.len(), self.sorted.len() + self.pending.len());
        id
    }

    /// Fold `pending` back into `sorted`, leaving one sorted run.
    ///
    /// Both inputs are already sorted, so appending and re-sorting is a single
    /// linear merge — Rust's stable sort detects the two natural runs. That is
    /// why this is `sort_by` and not `sort_unstable_by`: the run detection is
    /// the whole point, and pdqsort has none.
    fn merge(&mut self) {
        let Self { arena, span, sorted, pending } = self;
        sorted.append(pending);
        let (arena, span) = (&*arena, &*span);
        sorted.sort_by(|&a, &b| text(arena, span, a).cmp(text(arena, span, b)));

        debug_assert!(pending.is_empty());
        // Strict `<` asserts the two invariants the binary search rests on:
        // ascending order, and no name interned twice.
        debug_assert!(sorted.is_sorted_by(|&a, &b| text(arena, span, a) < text(arena, span, b)));
    }

    /// Look up without interning. `None` for an unknown name.
    ///
    /// Used by consumers that must not grow the table — a rule referring to a
    /// layer that does not exist is an error, not a new layer.
    pub fn get(&self, name: &str) -> Option<StrId> {
        debug_assert_eq!(self.span.len(), self.sorted.len() + self.pending.len());
        let hit = |run: &[StrId]| {
            run.binary_search_by(|&id| self.resolve(id).cmp(name))
                .ok()
                .map(|pos| run[pos])
        };
        // A name lives in exactly one run, so which one answers is not a
        // choice — `sorted` is searched first only because it is the larger.
        hit(&self.sorted).or_else(|| hit(&self.pending))
    }

    /// Resolve an id back to text. The only place a `StrId` becomes readable,
    /// and it is called when writing a report.
    pub fn resolve(&self, id: StrId) -> &str {
        text(&self.arena, &self.span, id)
    }

    pub fn len(&self) -> usize {
        self.span.len()
    }

    pub fn is_empty(&self) -> bool {
        self.span.is_empty()
    }
}

/// [`StrTable::resolve`] over the raw columns, so a caller holding a `&mut` to
/// a disjoint field can still compare two names.
fn text<'a>(arena: &'a str, span: &[(u32, u32)], id: StrId) -> &'a str {
    // Fail closed: an id from another table, or one never issued, indexes out
    // of bounds and panics rather than resolving to a plausible name.
    let (start, end) = span[id.0 as usize];
    debug_assert!(start <= end);
    &arena[start as usize..end as usize]
}

/// How many staged ids are worth carrying before merging them back.
///
/// Balanced, not guessed. An insert memmoves half of `pending`; a merge touches
/// all of `sorted` and happens once per `pending` filling. Over a run of `n`
/// names those two costs are `n·|pending|` and `n²/|pending|`, which meet at
/// `|pending| = sqrt(|sorted|)` — about `n^1.5` element moves total against the
/// `n²` a single sorted vector pays.
///
/// The floor is where the model stops being the thing that matters: 64 ids is
/// 256 bytes, four cache lines, and a memmove that size is lost in the string
/// comparisons the binary search already did.
fn merge_threshold(sorted: usize) -> usize {
    sorted.isqrt().max(64)
}

/// The staged index only merges above [`merge_threshold`], and the integration
/// suite in `tests/intern.rs` interns a handful of names per table — so every
/// property it states is checked below the merge, on one run. These stay here
/// because the merge is what this module's data structure *is*, and it is
/// unreachable from outside without thousands of names.
#[cfg(test)]
mod tests {
    use super::{merge_threshold, StrTable};

    /// Oracle: law. Interning is idempotent and `resolve` inverts it, however
    /// many merges happened in between. The count is chosen against
    /// `merge_threshold` rather than picked round, so this cannot quietly stop
    /// crossing it if the threshold changes.
    #[test]
    fn a_name_survives_every_merge_its_arrival_order_puts_it_through() {
        // Enough to merge repeatedly: the threshold grows as isqrt, so this is
        // dozens of merges, not one.
        let names = merge_threshold(0) * merge_threshold(0);
        let mut table = StrTable::default();

        // Descending arrival order, so every name inserts at position 0 of the
        // pending run and the merge always has real work to do.
        let issued: Vec<_> = (0..names)
            .map(|n| table.intern(&format!("net_{:06}", names - n)))
            .collect();

        assert_eq!(table.len(), names, "distinct names collapsed onto one id");
        for (n, id) in issued.iter().enumerate() {
            let name = format!("net_{:06}", names - n);
            assert_eq!(table.resolve(*id), name, "resolve stopped inverting intern");
            assert_eq!(table.intern(&name), *id, "a merged name was interned twice");
            assert_eq!(table.get(&name), Some(*id), "a merged name went missing");
        }
        assert_eq!(table.len(), names, "re-interning grew the table");
        assert!(table.get("net_999999").is_none(), "a name never interned was found");
    }
}
