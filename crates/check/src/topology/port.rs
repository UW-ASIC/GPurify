//! Port binding: attaching layout labels to extracted nets.
//!
//! Data in: `NetTable` + `Provenance::labels`. Data out: `PortTable`.

use crate::topology::net::{NetId, NetTable};
use gpurify_geom::PolyId;
use gpurify_ingest::{Provenance, StrId};

/// Named nets: one row per distinct `(net, name)` binding, filled by
/// [`bind_ports_into`].
///
/// LVS, SPEF and the design-intent file refer to nets by these names. Two
/// contradictions a layout can draw are kept as drawn, never resolved by
/// picking a side:
///
/// - **A name on several nets** is one logical net the layout leaves in
///   pieces: an open, which `lvs.label_conflict` reports.
///   [`nets_of`](Self::nets_of) returns every piece and
///   [`net_of`](Self::net_of) none, so a consumer that resolves a name sees
///   all the pieces or refuses.
/// - **A net with several names** is two named nets shorted, which
///   `lvs.net_seed_conflict` reports. [`names_of`](Self::names_of) returns
///   every name, and [`name_of`](Self::name_of) the first in [`StrId`]
///   order.
#[derive(Debug, Default)]
pub struct PortTable {
    /// `net`, `name` and `poly` ascend by `(net, name)`.
    net: Vec<NetId>,
    name: Vec<StrId>,
    /// The lowest polygon carrying the row's name on the row's net.
    poly: Vec<PolyId>,
    /// The same rows ascending by `(name, net)`.
    by_name: Vec<StrId>,
    by_name_net: Vec<NetId>,
}

/// Why binding failed. The [`PortTable`] is left empty, and the `gpurify`
/// pipeline stops there with no report row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PortError {
    /// A label is attached to a shape on no net: one on a layer that is not
    /// a conductor. Which label is not recorded.
    #[error("label is attached to a shape on no extracted net")]
    OrphanLabel,
}

impl PortTable {
    /// The name of a net, if it has one: the first in [`StrId`] order when it
    /// has several (a short, see [`names_of`](Self::names_of)). *O*(log *n*)
    /// in bindings.
    pub fn name_of(&self, net: NetId) -> Option<StrId> {
        self.names_of(net).first().copied()
    }

    /// Every name a net carries, ascending by [`StrId`]. More than one is a
    /// short between named nets.
    pub fn names_of(&self, net: NetId) -> &[StrId] {
        let from = self.net.partition_point(|&candidate| candidate < net);
        let to = self.net.partition_point(|&candidate| candidate <= net);
        &self.name[from..to]
    }

    /// Every net a name is on, ascending. More than one is an open: one
    /// logical net the layout leaves in pieces.
    pub fn nets_of(&self, name: StrId) -> &[NetId] {
        let from = self.by_name.partition_point(|&candidate| candidate < name);
        let to = self.by_name.partition_point(|&candidate| candidate <= name);
        &self.by_name_net[from..to]
    }

    /// The net a name refers to, when exactly one net carries it. `None` for
    /// a name on no net, and for one on several, whose pieces
    /// [`nets_of`](Self::nets_of) lists: no single piece is the net.
    pub fn net_of(&self, name: StrId) -> Option<NetId> {
        match *self.nets_of(name) {
            [net] => Some(net),
            _ => None,
        }
    }

    /// The first name, in [`StrId`] order, that is on several nets: an open.
    pub fn split_name(&self) -> Option<StrId> {
        self.by_name
            .windows(2)
            .find(|pair| pair[0] == pair[1])
            .map(|pair| pair[0])
    }

    /// The lowest net that carries several names: a short.
    pub fn shorted_net(&self) -> Option<NetId> {
        self.net
            .windows(2)
            .find(|pair| pair[0] == pair[1])
            .map(|pair| pair[0])
    }

    /// Every binding as parallel `(nets, names, polygons)` columns, ascending
    /// by `(net, name)`. Each polygon is the lowest carrying that name on that
    /// net.
    pub(crate) fn bindings(&self) -> (&[NetId], &[StrId], &[PolyId]) {
        (&self.net, &self.name, &self.poly)
    }

    /// Every binding as parallel `(names, nets)` columns, ascending by
    /// `(name, net)`.
    pub(crate) fn bindings_by_name(&self) -> (&[StrId], &[NetId]) {
        (&self.by_name, &self.by_name_net)
    }

    /// The number of distinct `(net, name)` bindings: a name on two nets, or
    /// a net with two names, counts twice.
    pub fn len(&self) -> usize {
        self.net.len()
    }

    /// Whether no net is labelled.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Bind every label in the layout to its net; caller owns `out`, left empty on
/// error. The same name twice on one net binds once. Two names on one net,
/// and one name on two nets, bind as drawn (see [`PortTable`]).
///
/// `nets` must have been extracted from the store `provenance` describes.
///
/// # Errors
///
/// [`PortError::OrphanLabel`] when any label sits on a shape with no net.
///
/// # Panics
///
/// Panics if a label names a polygon `nets` never saw.
pub fn bind_ports_into(
    nets: &NetTable,
    provenance: &Provenance,
    out: &mut PortTable,
) -> Result<(), PortError> {
    out.net.clear();
    out.name.clear();
    out.poly.clear();
    out.by_name.clear();
    out.by_name_net.clear();

    let mut bound: Vec<(NetId, StrId, PolyId)> = provenance
        .labels()
        .iter()
        .map(|&(poly, name)| (nets.net_of(poly), name, poly))
        .collect();

    if bound.iter().any(|&(net, ..)| net == NetId::NONE) {
        return Err(PortError::OrphanLabel);
    }

    // Sorted, a binding's lowest polygon leads its run and survives the dedup.
    bound.sort_unstable();
    bound.dedup_by_key(|&mut (net, name, _)| (net, name));

    out.net.extend(bound.iter().map(|&(net, ..)| net));
    out.name.extend(bound.iter().map(|&(_, name, _)| name));
    out.poly.extend(bound.iter().map(|&(.., poly)| poly));

    bound.sort_unstable_by_key(|&(net, name, _)| (name, net));
    out.by_name.extend(bound.iter().map(|&(_, name, _)| name));
    out.by_name_net.extend(bound.iter().map(|&(net, ..)| net));
    Ok(())
}
