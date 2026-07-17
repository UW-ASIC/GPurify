//! Deterministic tiling and marker ownership.

use crate::gds::{LayoutError, LayoutErrorKind};
use crate::geometry::Bbox;
use crate::params::{Deck, DrcRuleParam};
use rayon::prelude::*;

use super::index::{validate_bbox, HierarchySpatialIndex};
use super::layer_identity::GdsLayerIdentity;
use super::tile::{TileId, VerificationTile};
use super::tile_candidates::TileCandidates;

/// Compute the halo distance from the maximum reach of any rule in the deck.
/// This ensures tiles overlap enough to avoid seam artifacts.
// ponytail: scans DrcRuleParam values only, not production ScalarExpr
#[must_use]
pub fn halo_from_deck(deck: &Deck) -> i32 {
    let mut max = 0i32;
    for rule in &deck.drc_rules {
        let reach = match rule {
            DrcRuleParam::MinWidth { min, .. } => *min,
            DrcRuleParam::MinSpacing { min, .. } => *min,
            DrcRuleParam::MinSpacingDiff { min, .. } => *min,
            DrcRuleParam::MinEnclosure { min, .. } => *min,
            DrcRuleParam::MinExtension { min, .. } => *min,
            DrcRuleParam::MaxWidth { max, .. } => *max,
            DrcRuleParam::Notch { min, .. } => *min,
            DrcRuleParam::MinEdgeLength { min, .. } => *min,
            DrcRuleParam::OffGrid { grid, .. } => *grid,
            DrcRuleParam::Overlap { min, .. } => *min,
            DrcRuleParam::CornerToCorner { min, .. } => *min,
            DrcRuleParam::EolSpacing { eol_spacing, .. } => *eol_spacing,
            DrcRuleParam::WideDependentSpacing { wide_spacing, .. } => *wide_spacing,
            DrcRuleParam::PrlSpacing { prl_spacing, .. } => *prl_spacing,
            DrcRuleParam::AsymmetricEnclosure { min_one_side, .. } => *min_one_side,
            DrcRuleParam::RedundantVia { within, .. } => *within,
            DrcRuleParam::ViaArraySpacing { array_spacing, .. } => *array_spacing,
            DrcRuleParam::MaxDistanceToTap { max_dist, .. } => *max_dist,
            DrcRuleParam::MultiPatterning { color_spacing, .. } => *color_spacing,
            DrcRuleParam::MinDensity { window, .. } | DrcRuleParam::MaxDensity { window, .. } => {
                *window
            }
            // Rules without a distance reach (area-only, ratio, angle)
            DrcRuleParam::MinArea { .. }
            | DrcRuleParam::Angle { .. }
            | DrcRuleParam::Antenna { .. }
            | DrcRuleParam::AntennaCar { .. }
            | DrcRuleParam::MinEnclosedArea { .. }
            | DrcRuleParam::Cheesing { .. } => 0,
        };
        max = max.max(reach);
    }
    max
}

#[derive(Clone, Debug)]
pub struct TileGrid {
    bounds: Bbox,
    tile_width: i32,
    tile_height: i32,
    halo: i32,
    columns: u32,
    rows: u32,
}

impl TileGrid {
    pub const MAX_TILES: u64 = 10_000_000;

    /// Create a tile grid with halo automatically sized from deck rules.
    pub fn from_deck(
        bounds: Bbox,
        tile_width: i32,
        tile_height: i32,
        deck: &Deck,
    ) -> Result<Self, LayoutError> {
        let halo = halo_from_deck(deck);
        Self::new(bounds, tile_width, tile_height, halo)
    }

    pub fn new(
        bounds: Bbox,
        tile_width: i32,
        tile_height: i32,
        halo: i32,
    ) -> Result<Self, LayoutError> {
        validate_bbox(bounds, "tile bounds")?;
        if tile_width <= 0 || tile_height <= 0 || halo < 0 {
            return Err(LayoutError::layout(
                LayoutErrorKind::Malformed,
                "tile dimensions must be positive and halo non-negative",
            ));
        }
        let width = i64::from(bounds.xmax) - i64::from(bounds.xmin);
        let height = i64::from(bounds.ymax) - i64::from(bounds.ymin);
        if width <= 0 || height <= 0 {
            return Err(LayoutError::layout(
                LayoutErrorKind::Malformed,
                "tile bounds must have positive area",
            ));
        }
        let columns = ceil_div(width, i64::from(tile_width));
        let rows = ceil_div(height, i64::from(tile_height));
        let columns = u32::try_from(columns).map_err(|_| {
            LayoutError::layout(
                LayoutErrorKind::CapacityExceeded,
                "tile column count exceeds u32",
            )
        })?;
        let rows = u32::try_from(rows).map_err(|_| {
            LayoutError::layout(
                LayoutErrorKind::CapacityExceeded,
                "tile row count exceeds u32",
            )
        })?;
        let tile_count = u64::from(columns)
            .checked_mul(u64::from(rows))
            .ok_or_else(|| {
                LayoutError::layout(LayoutErrorKind::CapacityExceeded, "tile count overflow")
            })?;
        if tile_count > Self::MAX_TILES {
            return Err(LayoutError::layout(
                LayoutErrorKind::CapacityExceeded,
                format!(
                    "tile count {tile_count} exceeds capacity {}",
                    Self::MAX_TILES
                ),
            ));
        }
        Ok(Self {
            bounds,
            tile_width,
            tile_height,
            halo,
            columns,
            rows,
        })
    }

    #[must_use]
    pub fn columns(&self) -> u32 {
        self.columns
    }
    #[must_use]
    pub fn rows(&self) -> u32 {
        self.rows
    }

    /// Row-major tiles, clipped at the layout bounds.
    pub fn tiles(&self) -> Result<Vec<VerificationTile>, LayoutError> {
        let capacity =
            usize::try_from(u64::from(self.columns) * u64::from(self.rows)).map_err(|_| {
                LayoutError::layout(
                    LayoutErrorKind::CapacityExceeded,
                    "tile vector exceeds usize",
                )
            })?;
        let mut tiles = Vec::with_capacity(capacity);
        for row in 0..self.rows {
            for column in 0..self.columns {
                tiles.push(self.tile(column, row)?);
            }
        }
        Ok(tiles)
    }

    pub fn owner_of_marker(&self, marker: Bbox) -> Result<TileId, LayoutError> {
        validate_bbox(marker, "marker bbox")?;
        if marker.xmin < self.bounds.xmin
            || marker.xmin > self.bounds.xmax
            || marker.ymin < self.bounds.ymin
            || marker.ymin > self.bounds.ymax
        {
            return Err(LayoutError::layout(
                LayoutErrorKind::Malformed,
                "marker lower-left anchor is outside tile bounds",
            ));
        }
        let dx = i64::from(marker.xmin) - i64::from(self.bounds.xmin);
        let dy = i64::from(marker.ymin) - i64::from(self.bounds.ymin);
        let column = (dx / i64::from(self.tile_width)).min(i64::from(self.columns - 1));
        let row = (dy / i64::from(self.tile_height)).min(i64::from(self.rows - 1));
        Ok(TileId(row as u64 * u64::from(self.columns) + column as u64))
    }

    pub fn tile_owns_marker(
        &self,
        tile: VerificationTile,
        marker: Bbox,
    ) -> Result<bool, LayoutError> {
        Ok(self.owner_of_marker(marker)? == tile.id)
    }

    pub fn query_parallel<'a>(
        &self,
        index: &HierarchySpatialIndex<'a>,
        top: &str,
        layer: Option<GdsLayerIdentity>,
    ) -> Result<Vec<TileCandidates>, LayoutError> {
        let tiles = self.tiles()?;
        let mut results: Vec<Result<TileCandidates, LayoutError>> = tiles
            .par_iter()
            .map(|tile| {
                index
                    .query(top, tile.query_region, layer)
                    .map(|candidates| TileCandidates {
                        tile: *tile,
                        candidates,
                    })
            })
            .collect();
        let mut output = Vec::with_capacity(results.len());
        for result in results.drain(..) {
            output.push(result?);
        }
        output.sort_by_key(|entry| entry.tile.id);
        Ok(output)
    }

    fn tile(&self, column: u32, row: u32) -> Result<VerificationTile, LayoutError> {
        let xmin = i64::from(self.bounds.xmin) + i64::from(column) * i64::from(self.tile_width);
        let ymin = i64::from(self.bounds.ymin) + i64::from(row) * i64::from(self.tile_height);
        let xmax = (xmin + i64::from(self.tile_width)).min(i64::from(self.bounds.xmax));
        let ymax = (ymin + i64::from(self.tile_height)).min(i64::from(self.bounds.ymax));
        let core = Bbox {
            xmin: to_i32(xmin, "tile xmin")?,
            ymin: to_i32(ymin, "tile ymin")?,
            xmax: to_i32(xmax, "tile xmax")?,
            ymax: to_i32(ymax, "tile ymax")?,
        };
        let query_region = Bbox {
            xmin: to_i32(
                (xmin - i64::from(self.halo)).max(i64::from(self.bounds.xmin)),
                "halo xmin",
            )?,
            ymin: to_i32(
                (ymin - i64::from(self.halo)).max(i64::from(self.bounds.ymin)),
                "halo ymin",
            )?,
            xmax: to_i32(
                (xmax + i64::from(self.halo)).min(i64::from(self.bounds.xmax)),
                "halo xmax",
            )?,
            ymax: to_i32(
                (ymax + i64::from(self.halo)).min(i64::from(self.bounds.ymax)),
                "halo ymax",
            )?,
        };
        let id = TileId(u64::from(row) * u64::from(self.columns) + u64::from(column));
        Ok(VerificationTile {
            id,
            column,
            row,
            core,
            query_region,
        })
    }
}

fn ceil_div(value: i64, divisor: i64) -> i64 {
    (value + divisor - 1) / divisor
}

fn to_i32(value: i64, context: &str) -> Result<i32, LayoutError> {
    i32::try_from(value).map_err(|_| {
        LayoutError::layout(
            LayoutErrorKind::ArithmeticOverflow,
            format!("{context} outside i32"),
        )
    })
}
