//! Hierarchy-preserving spatial queries and deterministic tile ownership.
//!
//! The index retains one local shape table per GDS structure. Queries walk SREF/AREF
//! nodes and use cached cell bboxes only as conservative rejects; every returned
//! candidate includes its exact transformed ring and stable hierarchy identity.
//!
//! One public type per file; `TileId` rides with [`tile::VerificationTile`]
//! (a bare newtype with no impls of its own). Re-exported here so
//! `core::hierarchy_index::X` paths are stable.

pub mod candidate;
mod fnv;
pub mod grid;
pub mod index;
pub mod instance_path;
pub mod layer_identity;
pub mod options;
pub mod shape_kind;
pub mod tile;
pub mod tile_candidates;

pub use candidate::HierarchyCandidate;
pub use grid::{halo_from_deck, TileGrid};
pub use index::HierarchySpatialIndex;
pub use instance_path::{path_depth, path_to_string, InstancePathEntry};
pub use layer_identity::GdsLayerIdentity;
pub use options::HierarchyIndexOptions;
pub use shape_kind::IndexedShapeKind;
pub use tile::{TileId, VerificationTile};
pub use tile_candidates::TileCandidates;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gds::GdsUnits;
    use crate::gds::{
        flatten_gds_library, GdsArrayReference, GdsBoundary, GdsElement, GdsElementMeta,
        GdsEnvelope, GdsFlattenOptions, GdsLibrary, GdsReference, GdsStructure, GdsTransform,
        LayoutErrorKind,
    };
    use crate::exact::Point;
    use crate::geometry::Bbox;
    use crate::params::{DrcRuleParam, LayerDef, LayerTable};

    fn rectangle(x0: i32, y0: i32, x1: i32, y1: i32) -> Vec<Point> {
        vec![
            Point::new(x0, y0),
            Point::new(x1, y0),
            Point::new(x1, y1),
            Point::new(x0, y1),
        ]
    }

    fn boundary(x0: i32, y0: i32, x1: i32, y1: i32) -> GdsElement {
        GdsElement::Boundary(GdsBoundary {
            layer: 7,
            datatype: 0,
            ring: rectangle(x0, y0, x1, y1),
            meta: GdsElementMeta::default(),
        })
    }

    fn structure(name: &str, elements: Vec<GdsElement>) -> GdsStructure {
        GdsStructure {
            timestamps: [0; 12],
            name: name.to_string(),
            elements,
            unhandled_records: Vec::new(),
        }
    }

    fn library(structures: Vec<GdsStructure>) -> GdsLibrary {
        GdsLibrary {
            version: 600,
            timestamps: [0; 12],
            name: "index".to_string(),
            units: GdsUnits {
                user_units_per_database_unit: 1.0e-3,
                meters_per_database_unit: 1.0e-9,
            },
            structures,
            unhandled_records: Vec::new(),
            envelope: GdsEnvelope::complete(),
        }
    }

    fn layers() -> LayerTable {
        LayerTable::from_defs(
            &[(
                "met1".to_string(),
                LayerDef {
                    layer: 7,
                    datatype: 0,
                },
            )]
            .into_iter()
            .collect(),
        )
    }

    fn sref(name: &str, origin: Point, transform: GdsTransform) -> GdsElement {
        GdsElement::Sref(GdsReference {
            structure: name.to_string(),
            origin,
            transform,
            meta: GdsElementMeta::default(),
        })
    }

    #[test]
    fn flat_and_hierarchical_candidates_are_exactly_equivalent() {
        let leaf = structure("leaf", vec![boundary(0, 0, 10, 20)]);
        let middle = structure(
            "middle",
            vec![sref(
                "leaf",
                Point::new(30, 40),
                GdsTransform {
                    angle_degrees: Some(90.0),
                    ..Default::default()
                },
            )],
        );
        let top = structure(
            "top",
            vec![
                sref(
                    "leaf",
                    Point::new(100, 0),
                    GdsTransform {
                        reflected: true,
                        ..Default::default()
                    },
                ),
                sref(
                    "middle",
                    Point::new(0, 100),
                    GdsTransform {
                        angle_degrees: Some(270.0),
                        magnification: Some(2.0),
                        ..Default::default()
                    },
                ),
                GdsElement::Aref(GdsArrayReference {
                    structure: "leaf".to_string(),
                    columns: 3,
                    rows: 2,
                    origin: Point::new(0, 200),
                    column_endpoint: Point::new(90, 200),
                    row_endpoint: Point::new(0, 280),
                    transform: GdsTransform {
                        angle_degrees: Some(180.0),
                        ..Default::default()
                    },
                    meta: GdsElementMeta::default(),
                }),
            ],
        );
        let library = library(vec![leaf, middle, top]);
        let index = HierarchySpatialIndex::build(&library, Default::default()).unwrap();
        let bbox = index.cell_bbox("top").unwrap();
        let candidates = index.query("top", bbox, None).unwrap();
        let flat = flatten_gds_library(
            &library,
            &layers(),
            &GdsFlattenOptions {
                selected_top: Some("top".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        let store = &flat.cells["top"];
        assert_eq!(candidates.len(), store.poly_count());
        for (index, candidate) in candidates.iter().enumerate() {
            assert_eq!(candidate.bbox, store.poly_bbox[index]);
            let (start, end) = store.poly_range(crate::geometry::PolyId(index as u32));
            let flat_ring: Vec<Point> = (start..end)
                .map(|vertex| Point::new(store.verts_x[vertex], store.verts_y[vertex]))
                .collect();
            assert_eq!(candidate.ring, flat_ring);
        }
        assert_eq!(candidates[0].instance_path.len(), 1);
        assert_eq!(candidates[1].instance_path.len(), 2);
        assert_eq!(candidates[2].instance_path[0].column, 0);
        assert_eq!(candidates[7].instance_path[0].column, 2);
        assert_eq!(candidates[7].instance_path[0].row, 1);
    }

    #[test]
    fn query_layer_filter_and_bbox_pruning_are_deterministic() {
        let mut second = match boundary(1_000, 1_000, 1_010, 1_010) {
            GdsElement::Boundary(value) => value,
            _ => unreachable!(),
        };
        second.layer = 8;
        let library = library(vec![structure(
            "top",
            vec![boundary(0, 0, 10, 10), GdsElement::Boundary(second)],
        )]);
        let index = HierarchySpatialIndex::build(&library, Default::default()).unwrap();
        let local = index
            .query(
                "top",
                Bbox {
                    xmin: -1,
                    ymin: -1,
                    xmax: 20,
                    ymax: 20,
                },
                None,
            )
            .unwrap();
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].layer.layer, 7);
        let filtered = index
            .query(
                "top",
                index.cell_bbox("top").unwrap(),
                Some(GdsLayerIdentity {
                    layer: 8,
                    datatype: 0,
                }),
            )
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].element_index, 1);
        assert_eq!(
            index.equivalent_layout_hash("top").unwrap(),
            index.equivalent_layout_hash("top").unwrap()
        );
    }

    #[test]
    fn parallel_tiles_are_row_major_and_seam_markers_have_one_owner() {
        let library = library(vec![structure("top", vec![boundary(95, 20, 105, 40)])]);
        let index = HierarchySpatialIndex::build(&library, Default::default()).unwrap();
        let grid = TileGrid::new(
            Bbox {
                xmin: 0,
                ymin: 0,
                xmax: 200,
                ymax: 200,
            },
            100,
            100,
            10,
        )
        .unwrap();
        let results = grid.query_parallel(&index, "top", None).unwrap();
        assert_eq!(
            results
                .iter()
                .map(|result| result.tile.id)
                .collect::<Vec<_>>(),
            [TileId(0), TileId(1), TileId(2), TileId(3)]
        );
        assert_eq!(results[0].candidates.len(), 1);
        assert_eq!(results[1].candidates.len(), 1);
        let seam_marker = Bbox {
            xmin: 100,
            ymin: 25,
            xmax: 100,
            ymax: 35,
        };
        assert_eq!(grid.owner_of_marker(seam_marker).unwrap(), TileId(1));
        assert_eq!(
            results
                .iter()
                .filter(|result| grid.tile_owns_marker(result.tile, seam_marker).unwrap())
                .count(),
            1
        );
    }

    #[test]
    fn deep_hierarchy_and_expansion_limits_fail_before_overflow() {
        let mut structures = vec![structure("leaf", vec![boundary(0, 0, 10, 10)])];
        for depth in 1..=32 {
            structures.push(structure(
                &format!("d{depth}"),
                vec![sref(
                    if depth == 1 {
                        "leaf".to_string()
                    } else {
                        format!("d{}", depth - 1)
                    }
                    .as_str(),
                    Point::new(1, 1),
                    GdsTransform::default(),
                )],
            ));
        }
        let deep_library = library(structures);
        let index = HierarchySpatialIndex::build(
            &deep_library,
            HierarchyIndexOptions {
                max_depth: 64,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            index.cell_bbox("d32"),
            Some(Bbox {
                xmin: 32,
                ymin: 32,
                xmax: 42,
                ymax: 42,
            })
        );
        assert_eq!(
            index
                .query("d32", index.cell_bbox("d32").unwrap(), None)
                .unwrap()
                .len(),
            1
        );

        let shallow_index = HierarchySpatialIndex::build(
            &deep_library,
            HierarchyIndexOptions {
                max_depth: 8,
                ..Default::default()
            },
        )
        .unwrap();
        let depth_error = shallow_index
            .query("d32", shallow_index.cell_bbox("d32").unwrap(), None)
            .err()
            .unwrap();
        assert_eq!(depth_error.kind, LayoutErrorKind::CapacityExceeded);

        let array = library(vec![
            structure("leaf", vec![boundary(0, 0, 10, 10)]),
            structure(
                "top",
                vec![GdsElement::Aref(GdsArrayReference {
                    structure: "leaf".to_string(),
                    columns: 100,
                    rows: 100,
                    origin: Point::new(0, 0),
                    column_endpoint: Point::new(1_000, 0),
                    row_endpoint: Point::new(0, 1_000),
                    transform: GdsTransform::default(),
                    meta: GdsElementMeta::default(),
                })],
            ),
        ]);
        let array_error = HierarchySpatialIndex::build(
            &array,
            HierarchyIndexOptions {
                max_array_instances: 9_999,
                ..Default::default()
            },
        )
        .err()
        .unwrap();
        assert_eq!(array_error.kind, LayoutErrorKind::CapacityExceeded);
    }

    fn test_deck(rules: Vec<DrcRuleParam>) -> crate::params::Deck {
        use crate::params::{ConnectivityConfig, Deck, DeviceConfig, ErcParams, PropertyTolerance};
        use std::collections::HashMap;
        Deck {
            layers: layers(),
            drc_rules: rules,
            pex: HashMap::new(),
            dbu_nm: 1.0,
            lvs_cut_required: false,
            strict: false,
            connectivity: ConnectivityConfig {
                conductors: vec![],
                vias: vec![],
            },
            devices: DeviceConfig::default(),
            w_tolerance: PropertyTolerance::default(),
            l_tolerance: PropertyTolerance::default(),
            fail_on_floating: false,
            intra_layer_touch: false,
            global_nets: vec![],
            erc: ErcParams::default(),
            device_catalog: HashMap::new(),
            pex_method: Default::default(),
        }
    }

    #[test]
    fn halo_from_deck_returns_max_spacing() {
        let deck = test_deck(vec![
            DrcRuleParam::MinWidth {
                id: "w1".into(),
                layer: 0,
                min: 100,
            },
            DrcRuleParam::MinSpacing {
                id: "s1".into(),
                layer: 0,
                min: 500,
            },
            DrcRuleParam::MinEnclosure {
                id: "e1".into(),
                outer: 0,
                inner: 1,
                min: 200,
            },
        ]);
        assert_eq!(grid::halo_from_deck(&deck), 500);
    }

    #[test]
    fn halo_from_deck_empty_rules_returns_zero() {
        let deck = test_deck(vec![]);
        assert_eq!(grid::halo_from_deck(&deck), 0);
    }

    #[test]
    fn content_hash_is_deterministic() {
        let lib = library(vec![structure("top", vec![boundary(0, 0, 10, 20)])]);
        let index = HierarchySpatialIndex::build(&lib, Default::default()).unwrap();
        let candidates = index
            .query("top", index.cell_bbox("top").unwrap(), None)
            .unwrap();
        let tile = VerificationTile {
            id: TileId(0),
            column: 0,
            row: 0,
            core: Bbox {
                xmin: 0,
                ymin: 0,
                xmax: 100,
                ymax: 100,
            },
            query_region: Bbox {
                xmin: 0,
                ymin: 0,
                xmax: 100,
                ymax: 100,
            },
        };
        let h1 = tile.content_hash(&candidates);
        let h2 = tile.content_hash(&candidates);
        assert_eq!(h1, h2);
    }

    #[test]
    fn query_bounded_returns_error_on_excess() {
        let lib = library(vec![structure(
            "top",
            vec![boundary(0, 0, 10, 10), boundary(20, 20, 30, 30)],
        )]);
        let index = HierarchySpatialIndex::build(&lib, Default::default()).unwrap();
        let bbox = index.cell_bbox("top").unwrap();
        // limit=1 but 2 candidates
        let err = index.query_bounded("top", bbox, None, 1).unwrap_err();
        assert_eq!(err.kind, LayoutErrorKind::CapacityExceeded);
        // limit=2 should succeed
        let ok = index.query_bounded("top", bbox, None, 2).unwrap();
        assert_eq!(ok.len(), 2);
    }

    #[test]
    fn path_to_string_formatting() {
        assert_eq!(instance_path::path_to_string(&[]), "<top>");
        let path = vec![
            InstancePathEntry {
                parent_structure: "top".into(),
                element_index: 0,
                referenced_structure: "leaf".into(),
                column: 0,
                row: 0,
            },
            InstancePathEntry {
                parent_structure: "leaf".into(),
                element_index: 2,
                referenced_structure: "cell".into(),
                column: 3,
                row: 1,
            },
        ];
        assert_eq!(
            instance_path::path_to_string(&path),
            "top[0]/leaf/leaf[2]/cell<3,1>"
        );
        assert_eq!(instance_path::path_depth(&path), 2);
    }

    #[test]
    fn canonical_string_with_and_without_array_indices() {
        let sref_entry = InstancePathEntry {
            parent_structure: "A".into(),
            element_index: 5,
            referenced_structure: "B".into(),
            column: 0,
            row: 0,
        };
        assert_eq!(sref_entry.canonical_string(), "A[5]/B");

        let aref_entry = InstancePathEntry {
            parent_structure: "A".into(),
            element_index: 5,
            referenced_structure: "B".into(),
            column: 2,
            row: 3,
        };
        assert_eq!(aref_entry.canonical_string(), "A[5]/B<2,3>");
    }

    #[test]
    fn transform_and_tile_arithmetic_overflow_is_typed() {
        let fractional = library(vec![
            structure("leaf", vec![boundary(0, 0, 11, 10)]),
            structure(
                "top",
                vec![sref(
                    "leaf",
                    Point::new(0, 0),
                    GdsTransform {
                        magnification: Some(0.5),
                        ..Default::default()
                    },
                )],
            ),
        ]);
        let error = HierarchySpatialIndex::build(&fractional, Default::default())
            .err()
            .unwrap();
        assert_eq!(error.kind, LayoutErrorKind::NonIntegralTransform);

        let library = library(vec![
            structure("leaf", vec![boundary(i32::MAX - 10, 0, i32::MAX, 10)]),
            structure(
                "top",
                vec![sref("leaf", Point::new(100, 0), GdsTransform::default())],
            ),
        ]);
        let error = HierarchySpatialIndex::build(&library, Default::default())
            .err()
            .unwrap();
        assert_eq!(error.kind, LayoutErrorKind::ArithmeticOverflow);

        let error = TileGrid::new(
            Bbox {
                xmin: i32::MIN,
                ymin: 0,
                xmax: i32::MAX,
                ymax: 10,
            },
            1,
            1,
            0,
        )
        .unwrap_err();
        assert_eq!(error.kind, LayoutErrorKind::CapacityExceeded);
    }
}
