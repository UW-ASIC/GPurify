//! String interning.
//!
//! A sorted index over a string arena, not a hash map: iteration order must be
//! identical on every machine or reports differ between runs of the same binary.

/// An interned string.
///
/// Two `StrId` from different [`StrTable`]s are not comparable, and nothing
/// checks that — there is one table per run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct StrId(pub u32);

/// The one string table for a run.
#[derive(Debug, Default)]
pub struct StrTable {
    /// All bytes, concatenated.
    arena: String,
    /// `arena[span[i].0 .. span[i].1]` is string `i`. Indexed by [`StrId`].
    span: Vec<(u32, u32)>,
    /// Ids sorted by their string's bytes. The merged half of the index.
    sorted: Vec<StrId>,
    /// Ids interned since the last merge, sorted among themselves. Disjoint
    /// from `sorted`; the two together are every id.
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
    pub fn intern(&mut self, name: &str) -> StrId {
        debug_assert_eq!(self.span.len(), self.sorted.len() + self.pending.len());

        // Each scrutinee is bound first so the immutable borrow of `self` taken
        // by the comparator ends before the `&mut self` work below.
        let merged = self
            .sorted
            .binary_search_by(|&id| self.resolve(id).cmp(name));
        if let Ok(pos) = merged {
            return self.sorted[pos];
        }
        let staged = self
            .pending
            .binary_search_by(|&id| self.resolve(id).cmp(name));
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

        if self.pending.len() >= merge_threshold(self.sorted.len()) {
            self.merge();
        }

        debug_assert_eq!(self.span.len(), self.sorted.len() + self.pending.len());
        id
    }

    /// Fold `pending` back into `sorted`, leaving one sorted run.
    ///
    /// `sort_by`, not `sort_unstable_by`: both inputs are already sorted and
    /// the stable sort detects the two natural runs, making this a linear merge.
    fn merge(&mut self) {
        let Self {
            arena,
            span,
            sorted,
            pending,
        } = self;
        sorted.append(pending);
        let (arena, span) = (&*arena, &*span);
        sorted.sort_by(|&a, &b| text(arena, span, a).cmp(text(arena, span, b)));

        debug_assert!(pending.is_empty());
        // Strict `<`: ascending order, and no name interned twice.
        debug_assert!(sorted.is_sorted_by(|&a, &b| text(arena, span, a) < text(arena, span, b)));
    }

    /// Look up without interning. `None` for an unknown name.
    pub fn get(&self, name: &str) -> Option<StrId> {
        debug_assert_eq!(self.span.len(), self.sorted.len() + self.pending.len());
        let hit = |run: &[StrId]| {
            run.binary_search_by(|&id| self.resolve(id).cmp(name))
                .ok()
                .map(|pos| run[pos])
        };
        // A name lives in exactly one run, so the order of these is arbitrary.
        hit(&self.sorted).or_else(|| hit(&self.pending))
    }

    /// Resolve an id back to text.
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
    // Fail closed: an id from another table panics rather than resolving to a
    // plausible name.
    let (start, end) = span[id.0 as usize];
    debug_assert!(start <= end);
    &arena[start as usize..end as usize]
}

/// How many staged ids are worth carrying before merging them back.
///
/// `sqrt` balances the per-insert memmove of `pending` against the per-merge
/// memmove of `sorted`; below the floor neither cost is measurable.
fn merge_threshold(sorted: usize) -> usize {
    sorted.isqrt().max(64)
}

#[cfg(test)]
mod tests {
    use super::{merge_threshold, StrTable};

    /// Interning is idempotent and `resolve` inverts it, however many merges
    /// happened in between.
    #[test]
    fn a_name_survives_every_merge_its_arrival_order_puts_it_through() {
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
        assert!(
            table.get("net_999999").is_none(),
            "a name never interned was found"
        );
    }
}
