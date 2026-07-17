//! Per-tile query result bundle.

use super::candidate::HierarchyCandidate;
use super::tile::VerificationTile;

#[derive(Clone, Debug)]
pub struct TileCandidates {
    pub tile: VerificationTile,
    pub candidates: Vec<HierarchyCandidate>,
}
