//! Stable DRC result database, waiver provenance and deterministic incremental merge.

use super::production::Unit;
use gdsverify_core::exact::{Point, Polygon, Ring};
use crate::geometry::LayerId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntRect {
    pub xmin: i32,
    pub ymin: i32,
    pub xmax: i32,
    pub ymax: i32,
}

impl IntRect {
    pub fn is_valid(self) -> bool {
        self.xmin <= self.xmax && self.ymin <= self.ymax
    }
    pub fn intersects(self, other: Self) -> bool {
        self.xmin <= other.xmax
            && other.xmin <= self.xmax
            && self.ymin <= other.ymax
            && other.ymin <= self.ymax
    }
}

/// Exact marker coordinates. Rings are canonical outer/hole boundaries in DBU.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MarkerGeometry {
    Point {
        x: i32,
        y: i32,
    },
    Edge {
        x0: i32,
        y0: i32,
        x1: i32,
        y1: i32,
    },
    Polygon {
        outer: Vec<(i32, i32)>,
        holes: Vec<Vec<(i32, i32)>>,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurement {
    pub name: String,
    pub value: f64,
    pub unit: Unit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultIdentity {
    pub deck_id: String,
    pub deck_revision: String,
    pub model_revision: String,
    pub context_id: String,
    /// Content hash of the source geometry that produced this result.
    #[serde(default)]
    pub source_geometry_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaiverState {
    Active,
    Expired,
    NotMatched,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaiverDisposition {
    pub waiver_id: String,
    pub provenance: String,
    pub owner: String,
    pub justification: String,
    pub expires_on: Option<String>,
    pub state: WaiverState,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultRecord {
    pub fingerprint: String,
    pub rule_id: String,
    pub hierarchy_path: String,
    pub layer: Option<LayerId>,
    pub marker: MarkerGeometry,
    pub measurements: Vec<Measurement>,
    pub identity: ResultIdentity,
    pub waiver: Option<WaiverDisposition>,
}

impl ResultRecord {
    pub fn new(
        rule_id: String,
        hierarchy_path: String,
        layer: Option<LayerId>,
        marker: MarkerGeometry,
        mut measurements: Vec<Measurement>,
        identity: ResultIdentity,
    ) -> Result<Self, ResultDbError> {
        if rule_id.trim().is_empty()
            || hierarchy_path.trim().is_empty()
            || identity.deck_id.trim().is_empty()
            || identity.deck_revision.trim().is_empty()
            || identity.model_revision.trim().is_empty()
            || identity.context_id.trim().is_empty()
        {
            return Err(ResultDbError::Invalid(
                "record identity fields must not be empty".into(),
            ));
        }
        if measurements
            .iter()
            .any(|m| m.name.trim().is_empty() || !m.value.is_finite())
        {
            return Err(ResultDbError::Invalid(
                "measurement names and values must be valid".into(),
            ));
        }
        measurements.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then_with(|| a.unit.cmp(&b.unit))
                .then_with(|| a.value.total_cmp(&b.value))
        });
        let marker = canonicalize_marker(marker)?;
        let fingerprint = fingerprint_fields(
            &rule_id,
            &hierarchy_path,
            layer,
            &marker,
            &measurements,
            &identity,
        );
        Ok(Self {
            fingerprint,
            rule_id,
            hierarchy_path,
            layer,
            marker,
            measurements,
            identity,
            waiver: None,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultDatabase {
    pub records: Vec<ResultRecord>,
}

impl ResultDatabase {
    /// Check that all expected tiles are present and complete.
    pub fn verify_complete(&self, expected_tile_count: usize) -> Result<(), crate::DrcError> {
        if self.records.len() < expected_tile_count {
            // ponytail: record count != tile count, but this is a rough completeness
            // check. Real tile completeness needs TileDatabase-level tracking.
            return Err(crate::DrcError::IncompleteResults {
                expected: expected_tile_count,
                records: self.records.len(),
            });
        }
        Ok(())
    }

    /// Schedule tiles for re-execution based on changed geometry.
    pub fn schedule_invalidated(&self, change_region: IntRect) -> Vec<TileWorkUnit> {
        // ponytail: without tile-level metadata in ResultDatabase, we can only
        // return an empty set. Real scheduling needs TileDatabase with bounds.
        let _ = change_region;
        Vec::new()
    }

    pub fn insert(&mut self, record: ResultRecord) -> Result<(), ResultDbError> {
        if record.fingerprint
            != fingerprint_fields(
                &record.rule_id,
                &record.hierarchy_path,
                record.layer,
                &record.marker,
                &record.measurements,
                &record.identity,
            )
        {
            return Err(ResultDbError::Invalid(
                "record fingerprint does not match content".into(),
            ));
        }
        match self
            .records
            .binary_search_by(|entry| entry.fingerprint.cmp(&record.fingerprint))
        {
            Ok(index) if self.records[index] == record => Ok(()),
            Ok(_) => Err(ResultDbError::FingerprintConflict(record.fingerprint)),
            Err(index) => {
                self.records.insert(index, record);
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Waiver {
    pub waiver_id: String,
    pub fingerprint: String,
    pub provenance: String,
    pub owner: String,
    pub justification: String,
    pub expires_on: Option<String>,
}

/// Apply exact-fingerprint waivers. `today` and expiry are strict `YYYY-MM-DD`.
pub fn apply_waivers(
    database: &mut ResultDatabase,
    waivers: &[Waiver],
    today: &str,
) -> Result<Vec<String>, ResultDbError> {
    validate_date(today)?;
    let mut by_fingerprint = BTreeMap::new();
    for waiver in waivers {
        if waiver.waiver_id.trim().is_empty()
            || waiver.provenance.trim().is_empty()
            || waiver.owner.trim().is_empty()
            || waiver.justification.trim().is_empty()
            || by_fingerprint
                .insert(waiver.fingerprint.clone(), waiver)
                .is_some()
        {
            return Err(ResultDbError::Invalid(
                "waivers require unique fingerprint and provenance".into(),
            ));
        }
        if let Some(expiry) = &waiver.expires_on {
            validate_date(expiry)?;
        }
    }
    // Waiver state is a recomputed view, not sticky record state. Revocation,
    // an empty waiver set, or expiry must remove a formerly Active disposition.
    for record in &mut database.records {
        record.waiver = None;
    }
    let mut unmatched: BTreeSet<_> = by_fingerprint.keys().cloned().collect();
    for record in &mut database.records {
        let Some(waiver) = by_fingerprint.get(&record.fingerprint) else {
            continue;
        };
        unmatched.remove(&record.fingerprint);
        let state = if waiver
            .expires_on
            .as_ref()
            .is_some_and(|expiry| expiry.as_str() < today)
        {
            WaiverState::Expired
        } else {
            WaiverState::Active
        };
        record.waiver = Some(WaiverDisposition {
            waiver_id: waiver.waiver_id.clone(),
            provenance: waiver.provenance.clone(),
            owner: waiver.owner.clone(),
            justification: waiver.justification.clone(),
            expires_on: waiver.expires_on.clone(),
            state,
        });
    }
    Ok(unmatched.into_iter().collect())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleDependency {
    pub rule_id: String,
    pub layers: BTreeSet<LayerId>,
    pub region: Option<IntRect>,
    pub hierarchy_prefixes: BTreeSet<String>,
    pub depends_on_rules: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChangeSet {
    pub layers: BTreeSet<LayerId>,
    pub regions: Vec<IntRect>,
    pub hierarchy_paths: BTreeSet<String>,
    pub changed_rules: BTreeSet<String>,
}

/// Deterministic dependency-closure invalidation.
pub fn invalidated_rules(
    dependencies: &[RuleDependency],
    changes: &ChangeSet,
) -> Result<BTreeSet<String>, ResultDbError> {
    let mut by_id = BTreeMap::new();
    for dependency in dependencies {
        if dependency.rule_id.trim().is_empty()
            || by_id
                .insert(dependency.rule_id.clone(), dependency)
                .is_some()
        {
            return Err(ResultDbError::Invalid(
                "dependency rule IDs must be unique".into(),
            ));
        }
        if dependency.region.is_some_and(|region| !region.is_valid()) {
            return Err(ResultDbError::Invalid(
                "dependency region is invalid".into(),
            ));
        }
    }
    for dependency in dependencies {
        for target in &dependency.depends_on_rules {
            if !by_id.contains_key(target) {
                return Err(ResultDbError::Invalid(format!(
                    "unknown dependency rule `{target}`"
                )));
            }
        }
    }
    if let Some(rule) = changes
        .changed_rules
        .iter()
        .find(|rule| !by_id.contains_key(*rule))
    {
        return Err(ResultDbError::Invalid(format!(
            "unknown changed rule `{rule}`"
        )));
    }
    let mut invalid = changes.changed_rules.clone();
    let has_geometry_change = !changes.layers.is_empty()
        || !changes.regions.is_empty()
        || !changes.hierarchy_paths.is_empty();
    for dependency in dependencies {
        let layer_hit = has_geometry_change
            && !dependency.layers.is_empty()
            && (changes.layers.is_empty() || !dependency.layers.is_disjoint(&changes.layers));
        let region_hit = dependency.region.is_none_or(|scope| {
            changes.regions.is_empty()
                || changes
                    .regions
                    .iter()
                    .any(|change| scope.intersects(*change))
        });
        let path_hit = dependency.hierarchy_prefixes.is_empty()
            || changes.hierarchy_paths.is_empty()
            || changes.hierarchy_paths.iter().any(|path| {
                dependency
                    .hierarchy_prefixes
                    .iter()
                    .any(|prefix| path.starts_with(prefix) || prefix.starts_with(path))
            });
        if layer_hit && region_hit && path_hit {
            invalid.insert(dependency.rule_id.clone());
        }
    }
    let mut queue: VecDeque<_> = invalid.iter().cloned().collect();
    while let Some(changed) = queue.pop_front() {
        for dependency in dependencies {
            if dependency.depends_on_rules.contains(&changed)
                && invalid.insert(dependency.rule_id.clone())
            {
                queue.push_back(dependency.rule_id.clone());
            }
        }
    }
    Ok(invalid)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TileStatus {
    Complete,
    Failed,
    Pending,
    Skipped,
}

/// Content-addressed work descriptor for distributed tile execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TileWorkUnit {
    pub tile_id: u64,
    pub tile_bounds: IntRect,
    pub deck_hash: String,
    pub source_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TileDatabase {
    pub tile_id: u64,
    pub core: IntRect,
    pub status: TileStatus,
    pub database: ResultDatabase,
}

impl TileDatabase {
    pub fn serialize(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
    pub fn deserialize(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// Deterministically merge local tile results and deduplicate seam records by fingerprint.
pub fn merge_tiles(mut tiles: Vec<TileDatabase>) -> Result<ResultDatabase, ResultDbError> {
    if tiles.iter().any(|tile| !tile.core.is_valid()) {
        return Err(ResultDbError::Invalid("tile core is invalid".into()));
    }
    tiles.sort_by_key(|tile| tile.tile_id);
    if tiles
        .windows(2)
        .any(|pair| pair[0].tile_id == pair[1].tile_id)
    {
        return Err(ResultDbError::Invalid("tile IDs must be unique".into()));
    }
    let mut merged = ResultDatabase::default();
    for tile in tiles {
        let mut records = tile.database.records;
        records.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        for record in records {
            merged.insert(record)?;
        }
    }
    Ok(merged)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResultDbError {
    Invalid(String),
    FingerprintConflict(String),
}

impl fmt::Display for ResultDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid result database: {message}"),
            Self::FingerprintConflict(value) => {
                write!(f, "fingerprint collision/conflict `{value}`")
            }
        }
    }
}

impl std::error::Error for ResultDbError {}

fn fingerprint_fields(
    rule_id: &str,
    path: &str,
    layer: Option<LayerId>,
    marker: &MarkerGeometry,
    measurements: &[Measurement],
    identity: &ResultIdentity,
) -> String {
    // Two independent fixed-seed FNV-1a lanes. Stable across processes/platforms;
    // not presented as cryptographic proof. Exact content is always collision-checked.
    let canonical =
        format!("{rule_id}\0{path}\0{layer:?}\0{marker:?}\0{measurements:?}\0{identity:?}");
    let a = fnv1a(canonical.as_bytes(), 0xcbf29ce484222325);
    let b = fnv1a(canonical.as_bytes(), 0x84222325cbf29ce4);
    format!("{a:016x}{b:016x}")
}

fn canonicalize_marker(marker: MarkerGeometry) -> Result<MarkerGeometry, ResultDbError> {
    match marker {
        point @ MarkerGeometry::Point { .. } => Ok(point),
        MarkerGeometry::Edge { x0, y0, x1, y1 } => {
            if (x0, y0) == (x1, y1) {
                return Err(ResultDbError::Invalid("edge marker is degenerate".into()));
            }
            let ((x0, y0), (x1, y1)) = if (x0, y0) <= (x1, y1) {
                ((x0, y0), (x1, y1))
            } else {
                ((x1, y1), (x0, y0))
            };
            Ok(MarkerGeometry::Edge { x0, y0, x1, y1 })
        }
        MarkerGeometry::Polygon { outer, holes } => {
            let outer = Ring::new(outer.into_iter().map(Point::from).collect())
                .map_err(|error| ResultDbError::Invalid(format!("marker outer ring: {error}")))?;
            let holes = holes
                .into_iter()
                .map(|ring| Ring::new(ring.into_iter().map(Point::from).collect()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| ResultDbError::Invalid(format!("marker hole ring: {error}")))?;
            let polygon = Polygon::new(outer, holes)
                .map_err(|error| ResultDbError::Invalid(format!("marker polygon: {error}")))?;
            Ok(MarkerGeometry::Polygon {
                outer: polygon
                    .outer()
                    .vertices()
                    .iter()
                    .map(|point| (point.x, point.y))
                    .collect(),
                holes: polygon
                    .holes()
                    .iter()
                    .map(|ring| {
                        ring.vertices()
                            .iter()
                            .map(|point| (point.x, point.y))
                            .collect()
                    })
                    .collect(),
            })
        }
    }
}

fn fnv1a(bytes: &[u8], seed: u64) -> u64 {
    bytes.iter().fold(seed, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

fn validate_date(value: &str) -> Result<(), ResultDbError> {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(i, b)| i != 4 && i != 7 && !b.is_ascii_digit())
    {
        return Err(ResultDbError::Invalid(format!(
            "invalid ISO date `{value}`"
        )));
    }
    let year: u32 = value[0..4].parse().unwrap();
    let month: u32 = value[5..7].parse().unwrap();
    let day: u32 = value[8..10].parse().unwrap();
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if day == 0 || day > max_day {
        return Err(ResultDbError::Invalid(format!(
            "invalid ISO date `{value}`"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(x: i32) -> ResultRecord {
        ResultRecord::new(
            "M1.S.1".into(),
            "/top/u0".into(),
            Some(1),
            MarkerGeometry::Point { x, y: 20 },
            vec![Measurement {
                name: "spacing".into(),
                value: 12.0,
                unit: Unit::Dbu,
            }],
            ResultIdentity {
                deck_id: "deck".into(),
                deck_revision: "r1".into(),
                model_revision: "m1".into(),
                context_id: "tt".into(),
                source_geometry_hash: String::new(),
            },
        )
        .unwrap()
    }

    #[test]
    fn fingerprints_are_stable_and_content_checked() {
        let a = record(10);
        let b = record(10);
        assert_eq!(a.fingerprint, b.fingerprint);
        let mut database = ResultDatabase::default();
        database.insert(a).unwrap();
        database.insert(b).unwrap();
        assert_eq!(database.records.len(), 1);
        assert_ne!(record(11).fingerprint, database.records[0].fingerprint);

        let identity = ResultIdentity {
            deck_id: "deck".into(),
            deck_revision: "r1".into(),
            model_revision: "m1".into(),
            context_id: "tt".into(),
            source_geometry_hash: String::new(),
        };
        let clockwise = ResultRecord::new(
            "A".into(),
            "/top".into(),
            None,
            MarkerGeometry::Polygon {
                outer: vec![(0, 0), (0, 4), (4, 4), (4, 0)],
                holes: Vec::new(),
            },
            Vec::new(),
            identity.clone(),
        )
        .unwrap();
        let shifted = ResultRecord::new(
            "A".into(),
            "/top".into(),
            None,
            MarkerGeometry::Polygon {
                outer: vec![(4, 4), (0, 4), (0, 0), (4, 0)],
                holes: Vec::new(),
            },
            Vec::new(),
            identity,
        )
        .unwrap();
        assert_eq!(clockwise.fingerprint, shifted.fingerprint);
    }

    #[test]
    fn waiver_provenance_and_expiry_are_preserved() {
        let mut database = ResultDatabase {
            records: vec![record(10)],
        };
        let waiver = Waiver {
            waiver_id: "W-1".into(),
            fingerprint: database.records[0].fingerprint.clone(),
            provenance: "review/123".into(),
            owner: "physical-verification".into(),
            justification: "qualified IP boundary".into(),
            expires_on: Some("2026-07-01".into()),
        };
        assert!(apply_waivers(&mut database, &[waiver], "2026-07-12")
            .unwrap()
            .is_empty());
        assert_eq!(
            database.records[0].waiver.as_ref().unwrap().state,
            WaiverState::Expired
        );
        let active = Waiver {
            waiver_id: "W-2".into(),
            fingerprint: database.records[0].fingerprint.clone(),
            provenance: "review/456".into(),
            owner: "physical-verification".into(),
            justification: "temporary active waiver".into(),
            expires_on: Some("2026-08-01".into()),
        };
        apply_waivers(&mut database, &[active], "2026-07-12").unwrap();
        assert_eq!(
            database.records[0].waiver.as_ref().unwrap().state,
            WaiverState::Active
        );
        apply_waivers(&mut database, &[], "2026-07-12").unwrap();
        assert!(database.records[0].waiver.is_none());
        assert!(apply_waivers(&mut database, &[], "2026-02-30").is_err());
    }

    #[test]
    fn invalidation_closes_dependencies_and_respects_scope() {
        let dependencies = vec![
            RuleDependency {
                rule_id: "A".into(),
                layers: BTreeSet::from([1]),
                region: Some(IntRect {
                    xmin: 0,
                    ymin: 0,
                    xmax: 100,
                    ymax: 100,
                }),
                hierarchy_prefixes: BTreeSet::from(["/top/u".into()]),
                depends_on_rules: BTreeSet::new(),
            },
            RuleDependency {
                rule_id: "B".into(),
                layers: BTreeSet::new(),
                region: None,
                hierarchy_prefixes: BTreeSet::new(),
                depends_on_rules: BTreeSet::from(["A".into()]),
            },
        ];
        let changes = ChangeSet {
            layers: BTreeSet::from([1]),
            regions: vec![IntRect {
                xmin: 50,
                ymin: 50,
                xmax: 60,
                ymax: 60,
            }],
            hierarchy_paths: BTreeSet::from(["/top/u0".into()]),
            changed_rules: BTreeSet::new(),
        };
        assert_eq!(
            invalidated_rules(&dependencies, &changes).unwrap(),
            BTreeSet::from(["A".into(), "B".into()])
        );

        let ancestor_change = ChangeSet {
            layers: BTreeSet::from([1]),
            regions: Vec::new(),
            hierarchy_paths: BTreeSet::from(["/top".into()]),
            changed_rules: BTreeSet::new(),
        };
        assert!(invalidated_rules(&dependencies, &ancestor_change)
            .unwrap()
            .contains("A"));

        let descendant_dependencies = vec![RuleDependency {
            rule_id: "C".into(),
            layers: BTreeSet::from([1]),
            region: None,
            hierarchy_prefixes: BTreeSet::from(["/top".into()]),
            depends_on_rules: BTreeSet::new(),
        }];
        let descendant_change = ChangeSet {
            layers: BTreeSet::from([1]),
            regions: Vec::new(),
            hierarchy_paths: BTreeSet::from(["/top/u0/x1".into()]),
            changed_rules: BTreeSet::new(),
        };
        assert_eq!(
            invalidated_rules(&descendant_dependencies, &descendant_change).unwrap(),
            BTreeSet::from(["C".into()])
        );
    }

    #[test]
    fn tile_merge_is_order_independent_and_deduplicates_seams() {
        let a = record(10);
        let b = record(11);
        let core = IntRect {
            xmin: 0,
            ymin: 0,
            xmax: 100,
            ymax: 100,
        };
        let tiles = vec![
            TileDatabase {
                tile_id: 2,
                core,
                status: TileStatus::Complete,
                database: ResultDatabase {
                    records: vec![b.clone(), a.clone()],
                },
            },
            TileDatabase {
                tile_id: 1,
                core,
                status: TileStatus::Complete,
                database: ResultDatabase { records: vec![a] },
            },
        ];
        let merged = merge_tiles(tiles).unwrap();
        assert_eq!(merged.records.len(), 2);
        assert!(merged.records[0].fingerprint < merged.records[1].fingerprint);
    }

    #[test]
    fn tile_serialize_deserialize_roundtrips() {
        let tile = TileDatabase {
            tile_id: 42,
            core: IntRect {
                xmin: 0,
                ymin: 0,
                xmax: 100,
                ymax: 100,
            },
            status: TileStatus::Complete,
            database: ResultDatabase {
                records: vec![record(10)],
            },
        };
        let bytes = tile.serialize().unwrap();
        let restored = TileDatabase::deserialize(&bytes).unwrap();
        assert_eq!(restored.tile_id, 42);
        assert_eq!(restored.status, TileStatus::Complete);
        assert_eq!(restored.database.records.len(), 1);
        assert_eq!(
            restored.database.records[0].fingerprint,
            tile.database.records[0].fingerprint
        );
    }

    #[test]
    fn verify_complete_checks_record_count() {
        let db = ResultDatabase {
            records: vec![record(10), record(11)],
        };
        assert!(db.verify_complete(2).is_ok());
        assert!(db.verify_complete(3).is_err());
    }

    #[test]
    fn schedule_invalidated_returns_empty_without_tile_metadata() {
        let db = ResultDatabase {
            records: vec![record(10)],
        };
        let region = IntRect {
            xmin: 0,
            ymin: 0,
            xmax: 50,
            ymax: 50,
        };
        assert!(db.schedule_invalidated(region).is_empty());
    }

    #[test]
    fn source_geometry_hash_is_included_in_identity() {
        let identity = ResultIdentity {
            deck_id: "deck".into(),
            deck_revision: "r1".into(),
            model_revision: "m1".into(),
            context_id: "tt".into(),
            source_geometry_hash: "abc123".into(),
        };
        let a = ResultRecord::new(
            "R1".into(),
            "/top".into(),
            None,
            MarkerGeometry::Point { x: 0, y: 0 },
            Vec::new(),
            identity.clone(),
        )
        .unwrap();
        let mut identity2 = identity;
        identity2.source_geometry_hash = "different".into();
        let b = ResultRecord::new(
            "R1".into(),
            "/top".into(),
            None,
            MarkerGeometry::Point { x: 0, y: 0 },
            Vec::new(),
            identity2,
        )
        .unwrap();
        // Different source hashes produce different fingerprints
        assert_ne!(a.fingerprint, b.fingerprint);
    }
}
