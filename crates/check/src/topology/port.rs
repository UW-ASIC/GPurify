//! Port binding: attaching layout labels to extracted nets.
//!
//! Data in: `NetTable` + `Provenance::labels`. Data out: `PortTable`.

use crate::topology::net::{NetId, NetTable};
use gpurify_ingest::{Provenance, StrId};

/// Named nets. `net`/`name` ascend by [`NetId`]; `by_name`/`by_name_net` are
/// the same rows ascending by `(name, net)`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PortTable {
    net: Vec<NetId>,
    name: Vec<StrId>,
    by_name: Vec<StrId>,
    by_name_net: Vec<NetId>,
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
        self.net.binary_search(&net).ok().map(|row| self.name[row])
    }

    /// The net a name refers to, if any; the lowest if it reaches several.
    pub fn net_of(&self, name: StrId) -> Option<NetId> {
        let row = self.by_name.partition_point(|candidate| *candidate < name);
        (self.by_name.get(row) == Some(&name)).then(|| self.by_name_net[row])
    }

    pub fn len(&self) -> usize {
        self.net.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Bind every label in the layout to its net; caller owns `out`, left empty on
/// error. A label on [`NetId::NONE`] is [`PortError::OrphanLabel`]; two names
/// on one net are a conflict naming the lowest such net.
pub fn bind_ports_into(
    nets: &NetTable,
    provenance: &Provenance,
    out: &mut PortTable,
) -> Result<(), PortError> {
    out.net.clear();
    out.name.clear();
    out.by_name.clear();
    out.by_name_net.clear();

    let mut bound: Vec<(NetId, StrId)> = provenance
        .labels()
        .iter()
        .map(|&(poly, name)| (nets.net_of(poly), name))
        .collect();

    // Checked before the sort: two orphans would otherwise read as a conflict.
    if bound.iter().any(|&(net, _)| net == NetId::NONE) {
        return Err(PortError::OrphanLabel);
    }

    bound.sort_unstable();
    bound.dedup();
    if let Some(w) = bound.windows(2).find(|w| w[0].0 == w[1].0) {
        return Err(PortError::ConflictingLabels(w[0].0));
    }

    out.net.extend(bound.iter().map(|&(net, _)| net));
    out.name.extend(bound.iter().map(|&(_, name)| name));

    bound.sort_unstable_by_key(|&(net, name)| (name, net));
    out.by_name.extend(bound.iter().map(|&(_, name)| name));
    out.by_name_net.extend(bound.iter().map(|&(net, _)| net));
    Ok(())
}
