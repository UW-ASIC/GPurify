//! Deterministic verification tile. `TileId` lives here with the tile record
//! it identifies (a bare newtype with no impls of its own).

use crate::geometry::Bbox;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TileId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationTile {
    pub id: TileId,
    pub column: u32,
    pub row: u32,
    pub core: Bbox,
    pub query_region: Bbox,
    // ponytail: invalidation_key computed externally via content_hash()
}

impl VerificationTile {
    /// Compute a content fingerprint from the geometry within this tile.
    pub fn content_hash(&self, candidates: &[super::candidate::HierarchyCandidate]) -> u64 {
        use super::fnv::Fnv64;
        let mut hash = Fnv64::new();
        hash.u64(self.id.0);
        for c in candidates {
            hash.u64(c.stable_hash());
        }
        hash.finish()
    }
}
