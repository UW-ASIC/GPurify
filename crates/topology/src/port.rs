//! Port binding: attaching declared names to extracted nets.

use crate::net::{NetId, NetTable};
use gpurify_ingest::{Provenance, StrId};

/// Named nets. `net`/`name` is ascending by [`NetId`]; `by_name`/`by_name_net`
/// is the same rows re-sorted by name, a derived permutation, so two tables
/// holding the same bindings compare equal.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PortTable {
    net: Vec<NetId>,
    name: Vec<StrId>,
    /// The `name` column ascending; ties stay in net order, so a partition
    /// point lands on the lowest such net.
    by_name: Vec<StrId>,
    /// The net of the row `by_name` holds at the same index.
    by_name_net: Vec<NetId>,
    /// [`bind_ports_into`]'s working column, emptied on every exit path so it
    /// never reaches `Debug` or `PartialEq`.
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
    /// The four columns hold the same rows, so their lengths agree. `O(1)`,
    /// because this runs on every accessor; ordering is asserted where it is
    /// established instead.
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

    /// The net a name refers to, if any; the lower of them if it reaches two.
    pub fn net_of(&self, name: StrId) -> Option<NetId> {
        self.debug_columns();
        // Partition rather than `binary_search`: on a repeated name the search
        // may land on any matching row, and the first is the canonical answer.
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

    /// Build from name bindings, sorted here however the caller ordered them.
    ///
    /// # Panics
    ///
    /// Debug builds only, when two entries name the same net — that is
    /// [`PortError::ConflictingLabels`], refused before a table is built.
    #[must_use]
    pub fn build(entries: &[(NetId, StrId)]) -> Self {
        let mut sorted = entries.to_vec();
        sorted.sort_unstable_by_key(|&(net, _)| net);
        debug_assert!(
            sorted.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "two entries name one net, which is a conflict rather than a table"
        );

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

        debug_assert_eq!(
            table.net.len(),
            sorted.len(),
            "a port went missing in the split"
        );
        debug_assert!(
            table.by_name.windows(2).all(|pair| pair[0] <= pair[1]),
            "the name index must be ascending, which is what `net_of` partitions"
        );
        table.debug_columns();
        table
    }
}

/// Bind every label in the layout to its net; caller owns `out`. A label whose
/// shape carries [`NetId::NONE`] is [`PortError::OrphanLabel`].
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

    // Per-column borrows, so scratch is readable while the columns are written.
    let PortTable {
        net: out_net,
        name: out_name,
        by_name,
        by_name_net,
        scratch: bound,
    } = out;

    // Cleared before anything can fail: an error must leave an empty table, not
    // the previous call's rows naming the wrong net.
    out_net.clear();
    out_name.clear();
    by_name.clear();
    by_name_net.clear();

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
    // skipped, or a missing conductor layer reads as a layout with fewer pins.
    let mut orphaned = false;
    for &(net, _) in bound.iter() {
        orphaned |= net == NetId::NONE;
    }
    if orphaned {
        bound.clear();
        return Err(PortError::OrphanLabel);
    }

    // Sorting by `(net, name)` brings one net's labels adjacent: `dedup` takes
    // the repeat, and what survives on one net is the contradiction.
    bound.sort_unstable();
    bound.dedup();

    // Two offset views of one column; empty and single-row collapse to two
    // empty views rather than to a length guard.
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
        // `NetId::NONE` is `min`'s identity, so a pair that does not clash
        // contributes nothing.
        let clash = u32::from(net == next).wrapping_sub(1);
        conflict = NetId(conflict.0.min(net.0 | clash));
    }
    if conflict != NetId::NONE {
        bound.clear();
        return Err(PortError::ConflictingLabels(conflict));
    }

    out_net.reserve(bound.len());
    out_name.reserve(bound.len());
    for &(net, name) in bound.iter() {
        out_net.push(net);
        out_name.push(name);
    }

    // Re-sorted by `(name, net)` into the index `net_of` partitions; net order
    // breaks ties, so a name reaching two nets indexes the lower one first.
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

    /// Reads the private columns directly: checking the sort through `name_of`
    /// would let an unsorted table and a broken search agree.
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
