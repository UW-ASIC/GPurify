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
#[derive(Debug, Default)]
pub struct PortTable {
    net: Vec<NetId>,
    name: Vec<StrId>,
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
    /// The name of a net, if it has one.
    pub fn name_of(&self, net: NetId) -> Option<StrId> {
        todo!()
    }

    /// The net a name refers to, if any.
    pub fn net_of(&self, name: StrId) -> Option<NetId> {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        todo!()
    }
}

/// Bind every label in the layout to its net.
///
/// **Transform, A-to-B.** Caller owns `out`. Reads `Provenance::labels`, which
/// is already ascending by [`PolyId`], so the result is deterministic without a
/// sort.
pub fn bind_ports_into(
    nets: &NetTable,
    provenance: &Provenance,
    out: &mut PortTable,
) -> Result<(), PortError> {
    todo!()
}
