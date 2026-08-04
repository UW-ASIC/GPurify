//! Port binding: attaching declared names to extracted nets.
//!
//! A net has a name only if the layout says so, via a TEXT label placed on a
//! conductor shape. Everything else is anonymous, and LVS matches it by
//! structure.
//!
//! # Ambiguity is an error
//!
//! Two different labels on one net, or one label touching two nets, is a
//! contradiction in the layout. It is reported, not resolved: picking one and
//! carrying on produces an LVS result that is confidently wrong about which
//! net is which.

use crate::net::{NetId, NetTable};
use gpurify_ingest::{Provenance, StrId};

/// Named nets.
///
/// Sorted by [`NetId`], so lookup is a binary search and iteration order is the
/// same on every run.
///
/// Both directions are indexed. `net`/`name` is the net-ordered view — what
/// [`name_of`](Self::name_of), reports and `drc` read. `by_name`/`by_name_net`
/// is the same rows re-sorted by name, which is what
/// [`net_of`](Self::net_of) partitions on. The second pair is a derived
/// permutation of the first, so two tables holding the same bindings still
/// compare equal.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PortTable {
    net: Vec<NetId>,
    name: Vec<StrId>,
    /// The `name` column ascending. Ties — one name reaching two nets — stay in
    /// net order, so a partition point lands on the lowest such net.
    by_name: Vec<StrId>,
    /// The net of the row `by_name` holds at the same index.
    by_name_net: Vec<NetId>,
    /// [`bind_ports_into`]'s working column, owned by the table so the
    /// allocation survives from one run to the next. Emptied on every exit path
    /// of that function — including both error paths — so it never contributes
    /// to what `Debug` prints or `PartialEq` compares.
    scratch: Vec<(NetId, StrId)>,
}

/// Why binding failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PortError {
    #[error("net {0:?} carries two different labels")]
    ConflictingLabels(NetId),
    #[error("label is attached to a shape on no extracted net")]
    OrphanLabel,
}

impl PortTable {
    /// The four columns hold the same rows, so their lengths agree.
    ///
    /// `O(1)` deliberately: this runs on every accessor, and `len` is called
    /// once per net by `lvs` and `export`, so an ordering scan here would be
    /// quadratic in a debug build. Ordering is asserted where it is
    /// established — [`build`](Self::build) and [`bind_ports_into`].
    fn debug_columns(&self) {
        debug_assert_eq!(
            self.net.len(),
            self.name.len(),
            "a name lost its net, or a net lost its name"
        );
        debug_assert_eq!(
            self.by_name.len(),
            self.net.len(),
            "the name index and the net-ordered columns are the same rows"
        );
        debug_assert_eq!(
            self.by_name_net.len(),
            self.by_name.len(),
            "a name-index row lost its net"
        );
        debug_assert!(
            self.scratch.is_empty(),
            "binding scratch outlived the call that filled it, so it is about \
             to be compared or printed as if it were a column"
        );
    }

    /// The name of a net, if it has one.
    pub fn name_of(&self, net: NetId) -> Option<StrId> {
        self.debug_columns();
        self.net.binary_search(&net).ok().map(|row| self.name[row])
    }

    /// The net a name refers to, if any.
    ///
    /// A name that reaches two nets answers with the lower of them, which is
    /// what the net-ordered scan this replaced also found first.
    pub fn net_of(&self, name: StrId) -> Option<NetId> {
        self.debug_columns();
        // Partition rather than `binary_search`: on a repeated name the search
        // may land on any of the matching rows, and the first one is the
        // canonical answer.
        let row = self.by_name.partition_point(|candidate| *candidate < name);
        (self.by_name.get(row) == Some(&name)).then(|| self.by_name_net[row])
    }

    pub fn len(&self) -> usize {
        self.debug_columns();
        self.net.len()
    }

    pub fn is_empty(&self) -> bool {
        // Through `len`, so the column-parity assert holds on this path too.
        self.len() == 0
    }

    /// Build directly from name bindings.
    ///
    /// Reopened in the Testing-Phase, for the same reason as
    /// [`crate::NetTable::from_assignment`]: private fields and a single
    /// `todo!()` producer meant no test could hand a named net to anything
    /// downstream. `export`'s SPEF and DSPF writers both require named nets, so
    /// every writer test had to run the full extract-label-bind chain first.
    ///
    /// Entries are sorted by [`NetId`] here, so the binary-search invariant
    /// holds however the caller ordered them.
    ///
    /// # Panics
    ///
    /// Debug builds only, when two entries name the same net. That is
    /// [`PortError::ConflictingLabels`], and a table is the wrong place to
    /// discover it: [`bind_ports_into`] refuses it before one is built.
    #[must_use]
    pub fn build(entries: &[(NetId, StrId)]) -> Self {
        let mut sorted = entries.to_vec();
        sorted.sort_unstable_by_key(|&(net, _)| net);
        debug_assert!(
            sorted.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "two entries name one net, which is a conflict rather than a table"
        );

        // The same two splits `bind_ports_into` ends with, because this is the
        // same transform: one `(net, name)` column split into the two the table
        // stores, then re-sorted and split again into the name index. Both
        // columns of a pair are written by one pass, which is what the two
        // one-column maps this replaced could not do.
        let mut table = Self::default();
        table.net.reserve(sorted.len());
        table.name.reserve(sorted.len());
        for &(net, name) in &sorted {
            table.net.push(net);
            table.name.push(name);
        }

        sorted.sort_unstable_by_key(|&(net, name)| (name, net));
        table.by_name.reserve(sorted.len());
        table.by_name_net.reserve(sorted.len());
        for &(net, name) in &sorted {
            table.by_name.push(name);
            table.by_name_net.push(net);
        }

        debug_assert_eq!(table.net.len(), sorted.len(), "a port went missing in the split");
        debug_assert!(
            table.by_name.windows(2).all(|pair| pair[0] <= pair[1]),
            "the name index must be ascending, which is what `net_of` partitions"
        );
        table.debug_columns();
        table
    }
}

/// Bind every label in the layout to its net.
///
/// **Transform, A-to-B.** Caller owns `out`. Reads `Provenance::labels`, which
/// is already ascending by [`PolyId`](gpurify_core::PolyId), so the result is
/// deterministic without a sort.
///
/// A label whose shape carries [`NetId::NONE`] — a cut, a marker, anything on a
/// layer the deck does not call a conductor — is [`PortError::OrphanLabel`].
/// See [`crate::net::extract_nets_into`] for which polygons those are.
pub fn bind_ports_into(
    nets: &NetTable,
    provenance: &Provenance,
    out: &mut PortTable,
) -> Result<(), PortError> {
    let labels = provenance.labels();
    debug_assert!(
        labels.windows(2).all(|pair| pair[0].0 <= pair[1].0),
        "Provenance::labels is documented ascending by PolyId, which is what \
         lets this bind without sorting the labels first"
    );

    // Split into per-column borrows so the table's own scratch column can be
    // read while the output columns are written.
    let PortTable {
        net: out_net,
        name: out_name,
        by_name,
        by_name_net,
        scratch: bound,
    } = out;

    // Cleared before anything can fail, so an error leaves an empty table and
    // not the previous call's rows. A stale binding is a name pointing at the
    // wrong net, which is the failure this module refuses.
    out_net.clear();
    out_name.clear();
    by_name.clear();
    by_name_net.clear();

    // The working column lives on the table, so binding twice reuses one
    // allocation. It is emptied again on every exit below, which is what keeps
    // it out of `PartialEq` and `Debug`.
    bound.clear();
    bound.reserve(labels.len());
    for &(poly, name) in labels {
        bound.push((nets.net_of(poly), name));
    }
    debug_assert_eq!(
        bound.len(),
        labels.len(),
        "a label went missing between the provenance table and the binder"
    );

    // Orphans first, before the sort: `NetId::NONE` is `u32::MAX`, so two
    // orphan labels would otherwise sort adjacent and read as a conflict on a
    // net that does not exist. Fail closed — an orphan is reported, never
    // skipped, or a conductor layer missing from the deck reads as a layout
    // that simply has fewer pins.
    // `|=`, not `||`: no early exit, so the scan costs the same on every input
    // and carries no data-dependent branch.
    let mut orphaned = false;
    for &(net, _) in bound.iter() {
        orphaned |= net == NetId::NONE;
    }
    if orphaned {
        bound.clear();
        return Err(PortError::OrphanLabel);
    }

    // Sorting by `(net, name)` brings one net's labels adjacent, which turns
    // both remaining questions into a neighbour comparison: the repeated name
    // is `dedup`, and what survives it on one net is the contradiction.
    bound.sort_unstable();
    bound.dedup();

    // Adjacent-pair scan over two offset views of one column. The empty and
    // single-row cases collapse to two empty views rather than to a length
    // guard.
    let left = &bound[..bound.len().saturating_sub(1)];
    let right = &bound[bound.len().min(1)..];
    debug_assert_eq!(
        left.len(),
        right.len(),
        "the two offset views of one column must agree, or a pair is scanned \
         against the wrong neighbour"
    );
    let mut conflict = NetId::NONE;
    for i in 0..left.len() {
        let (net, _) = left[i];
        let (next, _) = right[i];
        // `NetId::NONE` is `u32::MAX`, which is `min`'s identity, so a pair that
        // does not clash contributes nothing and needs no branch. Reporting the
        // lowest clashing net rather than the first one found is the same answer
        // read off a sorted column, and it is canonical.
        let clash = u32::from(net == next).wrapping_sub(1);
        conflict = NetId(conflict.0.min(net.0 | clash));
    }
    if conflict != NetId::NONE {
        bound.clear();
        return Err(PortError::ConflictingLabels(conflict));
    }

    // Both output columns from one pass; the four `clear`s above already left
    // them empty.
    out_net.reserve(bound.len());
    out_name.reserve(bound.len());
    for &(net, name) in bound.iter() {
        out_net.push(net);
        out_name.push(name);
    }

    // Re-sorted by `(name, net)`, the same rows are the name-ordered index
    // `net_of` partitions. The net order it was just read in is what breaks
    // ties, so a name reaching two nets indexes the lower one first.
    bound.sort_unstable_by_key(|&(net, name)| (name, net));
    by_name.reserve(bound.len());
    by_name_net.reserve(bound.len());
    for &(net, name) in bound.iter() {
        by_name.push(name);
        by_name_net.push(net);
    }
    bound.clear();

    debug_assert_eq!(
        out_net.len(),
        out_name.len(),
        "a name lost its net, or a net lost its name"
    );
    debug_assert_eq!(
        by_name.len(),
        out_net.len(),
        "the name index and the net-ordered columns are the same rows"
    );
    debug_assert_eq!(
        by_name_net.len(),
        by_name.len(),
        "a name-index row lost its net"
    );
    debug_assert!(
        out_net.len() <= labels.len(),
        "binding produced a port no label asked for"
    );
    debug_assert!(
        out_net.windows(2).all(|pair| pair[0] < pair[1]),
        "the table must be strictly ascending by net, which is what `name_of` \
         binary-searches and what the conflict check above just established"
    );
    debug_assert!(
        by_name.windows(2).all(|pair| pair[0] <= pair[1]),
        "the name index must be ascending, which is what `net_of` partitions"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{NetId, PortTable, StrId};

    /// Reads the private columns directly, for the reason
    /// `NetTable`'s module test does: `build`'s whole job is the sort, and
    /// checking it through `name_of` — which binary-searches the column the
    /// sort produced — would let an unsorted table and a broken search agree.
    ///
    /// Oracle: construct-from-answer. Entries go in worst-case order — every
    /// one out of place — and the sorted columns are written down beside them.
    #[test]
    fn build_sorts_by_net_however_the_caller_ordered_the_entries() {
        let table = PortTable::build(&[
            (NetId(7), StrId(2)),
            (NetId(0), StrId(9)),
            (NetId(3), StrId(4)),
        ]);

        assert_eq!(table.net, [NetId(0), NetId(3), NetId(7)]);
        assert_eq!(
            table.name,
            [StrId(9), StrId(4), StrId(2)],
            "a name must travel with its net through the sort"
        );

        assert_eq!(PortTable::build(&[]), PortTable::default());
    }
}
