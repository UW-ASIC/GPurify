//! Exact query result: one transformed shape with stable hierarchy identity.

use crate::exact::Point;
use crate::geometry::Bbox;

use super::fnv::Fnv64;
use super::instance_path::InstancePathEntry;
use super::layer_identity::GdsLayerIdentity;
use super::shape_kind::IndexedShapeKind;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HierarchyCandidate {
    pub structure: String,
    pub element_index: u32,
    /// PATH elements can produce multiple exact polygon parts.
    pub part_index: u32,
    pub kind: IndexedShapeKind,
    pub layer: GdsLayerIdentity,
    pub instance_path: Vec<InstancePathEntry>,
    pub ring: Vec<Point>,
    pub bbox: Bbox,
}

impl HierarchyCandidate {
    /// Alias for stable_hash — stable identity for cross-run comparison.
    #[doc(alias = "stable_hash")]
    #[must_use]
    pub fn stable_identity(&self) -> u64 {
        self.stable_hash()
    }

    /// Stable non-cryptographic identity for marker/result deduplication.
    #[must_use]
    pub fn stable_hash(&self) -> u64 {
        let mut hash = Fnv64::new();
        hash.string(&self.structure);
        hash.u32(self.element_index);
        hash.u32(self.part_index);
        hash.u8(self.kind as u8);
        hash.i16(self.layer.layer);
        hash.i16(self.layer.datatype);
        for entry in &self.instance_path {
            hash.string(&entry.parent_structure);
            hash.u32(entry.element_index);
            hash.string(&entry.referenced_structure);
            hash.u16(entry.column);
            hash.u16(entry.row);
        }
        for point in &self.ring {
            hash.i32(point.x);
            hash.i32(point.y);
        }
        hash.finish()
    }
}
