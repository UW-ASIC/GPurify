//! Spatial index borrowing the lossless library.

use crate::exact::{Point, Ring};
use crate::gds::{
    checked_array_coordinate, ensure_meta_supported, exact_pitch, stroke_path, validate_hierarchy,
    Affine, GdsElement, GdsLibrary, GdsStructure, LayoutError, LayoutErrorKind,
};
use crate::geometry::Bbox;
use std::collections::{HashMap, HashSet};

use super::candidate::HierarchyCandidate;
use super::fnv::Fnv64;
use super::instance_path::InstancePathEntry;
use super::layer_identity::GdsLayerIdentity;
use super::options::HierarchyIndexOptions;
use super::shape_kind::IndexedShapeKind;

#[derive(Clone, Debug)]
struct LocalShape {
    element_index: u32,
    part_index: u32,
    kind: IndexedShapeKind,
    layer: GdsLayerIdentity,
    ring: Vec<Point>,
    bbox: Bbox,
}

#[derive(Clone, Debug)]
struct IndexedCell {
    parts_by_element: Vec<Vec<LocalShape>>,
    hierarchy_bbox: Option<Bbox>,
}

/// Spatial index borrowing the lossless library. Cell geometry is stored once;
/// instance expansions are produced only by queries.
pub struct HierarchySpatialIndex<'a> {
    library: &'a GdsLibrary,
    by_name: HashMap<&'a str, &'a GdsStructure>,
    cells: HashMap<&'a str, IndexedCell>,
    top_cells: Vec<String>,
    options: HierarchyIndexOptions,
}

impl<'a> HierarchySpatialIndex<'a> {
    pub fn build(
        library: &'a GdsLibrary,
        options: HierarchyIndexOptions,
    ) -> Result<Self, LayoutError> {
        if !library.unhandled_records.is_empty() {
            return Err(LayoutError::layout(
                LayoutErrorKind::Unsupported,
                "library contains unhandled records",
            ));
        }
        let by_name: HashMap<&str, &GdsStructure> = library
            .structures
            .iter()
            .map(|structure| (structure.name.as_str(), structure))
            .collect();
        validate_hierarchy(library, &by_name)?;

        let referenced: HashSet<&str> = library
            .structures
            .iter()
            .flat_map(|structure| structure.elements.iter())
            .filter_map(|element| match element {
                GdsElement::Sref(reference) => Some(reference.structure.as_str()),
                GdsElement::Aref(reference) => Some(reference.structure.as_str()),
                _ => None,
            })
            .collect();
        let top_cells = library
            .structures
            .iter()
            .filter(|structure| !referenced.contains(structure.name.as_str()))
            .map(|structure| structure.name.clone())
            .collect();

        let mut cells = HashMap::new();
        for structure in &library.structures {
            if !structure.unhandled_records.is_empty() {
                return Err(LayoutError::layout(
                    LayoutErrorKind::Unsupported,
                    format!("structure `{}` contains unhandled records", structure.name),
                ));
            }
            let mut parts_by_element = vec![Vec::new(); structure.elements.len()];
            for (element_index, element) in structure.elements.iter().enumerate() {
                let element_index = u32::try_from(element_index).map_err(|_| {
                    LayoutError::layout(
                        LayoutErrorKind::CapacityExceeded,
                        format!(
                            "structure `{}` has more than u32::MAX elements",
                            structure.name
                        ),
                    )
                })?;
                let parts = index_element(element, element_index)?;
                parts_by_element[element_index as usize] = parts;
            }
            cells.insert(
                structure.name.as_str(),
                IndexedCell {
                    parts_by_element,
                    hierarchy_bbox: None,
                },
            );
        }

        let mut index = Self {
            library,
            by_name,
            cells,
            top_cells,
            options,
        };
        let names: Vec<&str> = index
            .library
            .structures
            .iter()
            .map(|structure| structure.name.as_str())
            .collect();
        for name in names {
            let mut stack = Vec::new();
            index.compute_hierarchy_bbox(name, 0, &mut stack)?;
        }
        Ok(index)
    }

    #[must_use]
    pub fn top_cells(&self) -> &[String] {
        &self.top_cells
    }

    #[must_use]
    pub fn cell_bbox(&self, name: &str) -> Option<Bbox> {
        self.cells.get(name).and_then(|cell| cell.hierarchy_bbox)
    }

    /// Return exact candidates whose conservative transformed bboxes intersect
    /// `region`. Optional layer selection happens before polygon transformation.
    pub fn query(
        &self,
        top: &str,
        region: Bbox,
        layer: Option<GdsLayerIdentity>,
    ) -> Result<Vec<HierarchyCandidate>, LayoutError> {
        validate_bbox(region, "query region")?;
        let root = self.by_name.get(top).copied().ok_or_else(|| {
            LayoutError::layout(
                LayoutErrorKind::UndefinedReference,
                format!("query top `{top}` is undefined"),
            )
        })?;
        let mut output = Vec::new();
        let mut path = Vec::new();
        let mut visits = 0usize;
        self.query_structure(
            root,
            Affine::IDENTITY,
            region,
            layer,
            0,
            &mut visits,
            &mut path,
            &mut output,
        )?;
        Ok(output)
    }

    /// Maximum candidates before query aborts with CapacityExceeded.
    pub const MAX_QUERY_CANDIDATES: usize = 10_000_000;

    /// Query with explicit capacity bound. Returns error if candidate count exceeds limit.
    pub fn query_bounded(
        &self,
        top: &str,
        region: Bbox,
        layer: Option<GdsLayerIdentity>,
        max_candidates: usize,
    ) -> Result<Vec<HierarchyCandidate>, LayoutError> {
        let result = self.query(top, region, layer)?;
        if result.len() > max_candidates {
            return Err(LayoutError::layout(
                LayoutErrorKind::CapacityExceeded,
                format!(
                    "query returned {} candidates (limit {})",
                    result.len(),
                    max_candidates
                ),
            ));
        }
        Ok(result)
    }

    /// Hash exact candidate identity and geometry in deterministic traversal order.
    pub fn equivalent_layout_hash(&self, top: &str) -> Result<u64, LayoutError> {
        let bbox = self.cell_bbox(top).ok_or_else(|| {
            LayoutError::layout(
                LayoutErrorKind::Malformed,
                format!("top `{top}` has no area geometry"),
            )
        })?;
        let candidates = self.query(top, bbox, None)?;
        let mut hash = Fnv64::new();
        for candidate in candidates {
            hash.u64(candidate.stable_hash());
        }
        Ok(hash.finish())
    }

    fn compute_hierarchy_bbox(
        &mut self,
        name: &'a str,
        depth: usize,
        stack: &mut Vec<&'a str>,
    ) -> Result<Option<Bbox>, LayoutError> {
        if let Some(bbox) = self.cells[name].hierarchy_bbox {
            return Ok(Some(bbox));
        }
        if depth > self.options.max_depth {
            return Err(LayoutError::layout(
                LayoutErrorKind::CapacityExceeded,
                format!(
                    "hierarchy depth exceeded {} at `{name}`",
                    self.options.max_depth
                ),
            ));
        }
        if stack.contains(&name) {
            return Err(LayoutError::layout(
                LayoutErrorKind::HierarchyCycle,
                format!("cycle through `{name}`"),
            ));
        }
        stack.push(name);
        let structure = self.by_name[name];
        let mut bbox = None;
        for (element_index, element) in structure.elements.iter().enumerate() {
            for part in &self.cells[name].parts_by_element[element_index] {
                include_bbox(&mut bbox, part.bbox);
            }
            match element {
                GdsElement::Sref(reference) => {
                    let child = self.compute_hierarchy_bbox(
                        self.structure_name(&reference.structure)?,
                        depth + 1,
                        stack,
                    )?;
                    if let Some(child) = child {
                        let transform = Affine::instance(reference.transform, reference.origin)?;
                        include_bbox(&mut bbox, transform_bbox(transform, child)?);
                    }
                }
                GdsElement::Aref(reference) => {
                    let count = usize::from(reference.columns)
                        .checked_mul(usize::from(reference.rows))
                        .ok_or_else(|| {
                            LayoutError::layout(
                                LayoutErrorKind::ArithmeticOverflow,
                                "AREF instance count overflow",
                            )
                        })?;
                    if count > self.options.max_array_instances {
                        return Err(LayoutError::layout(
                            LayoutErrorKind::CapacityExceeded,
                            format!(
                                "AREF has {count} instances; limit is {}",
                                self.options.max_array_instances
                            ),
                        ));
                    }
                    let child = self.compute_hierarchy_bbox(
                        self.structure_name(&reference.structure)?,
                        depth + 1,
                        stack,
                    )?;
                    if let Some(child) = child {
                        let pitches = array_pitches(reference)?;
                        // A linear array's extrema are attained at its four corner origins.
                        for column in [0, reference.columns - 1] {
                            for row in [0, reference.rows - 1] {
                                let origin = array_origin(reference.origin, pitches, column, row)?;
                                let transform = Affine::instance(reference.transform, origin)?;
                                include_bbox(&mut bbox, transform_bbox(transform, child)?);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        stack.pop();
        self.cells.get_mut(name).unwrap().hierarchy_bbox = bbox;
        Ok(bbox)
    }

    fn structure_name(&self, name: &str) -> Result<&'a str, LayoutError> {
        self.by_name
            .get_key_value(name)
            .map(|(stored, _)| *stored)
            .ok_or_else(|| {
                LayoutError::layout(
                    LayoutErrorKind::UndefinedReference,
                    format!("reference to undefined `{name}`"),
                )
            })
    }

    #[allow(clippy::too_many_arguments)]
    fn query_structure(
        &self,
        structure: &'a GdsStructure,
        transform: Affine,
        region: Bbox,
        layer: Option<GdsLayerIdentity>,
        depth: usize,
        visits: &mut usize,
        path: &mut Vec<InstancePathEntry>,
        output: &mut Vec<HierarchyCandidate>,
    ) -> Result<(), LayoutError> {
        if depth > self.options.max_depth {
            return Err(LayoutError::layout(
                LayoutErrorKind::CapacityExceeded,
                format!("hierarchy query depth exceeded {}", self.options.max_depth),
            ));
        }
        if let Some(local_bbox) = self.cells[structure.name.as_str()].hierarchy_bbox {
            let world_bbox = transform_bbox(transform, local_bbox)?;
            if !bbox_intersects(world_bbox, region) {
                return Ok(());
            }
        }
        for (element_index, element) in structure.elements.iter().enumerate() {
            *visits = visits.checked_add(1).ok_or_else(|| {
                LayoutError::layout(
                    LayoutErrorKind::ArithmeticOverflow,
                    "query visit counter overflow",
                )
            })?;
            if *visits > self.options.max_expanded_visits_per_query {
                return Err(LayoutError::layout(
                    LayoutErrorKind::CapacityExceeded,
                    format!(
                        "query exceeded {} expanded visits",
                        self.options.max_expanded_visits_per_query
                    ),
                ));
            }
            for part in &self.cells[structure.name.as_str()].parts_by_element[element_index] {
                if layer.is_some_and(|wanted| wanted != part.layer) {
                    continue;
                }
                let conservative = transform_bbox(transform, part.bbox)?;
                if !bbox_intersects(conservative, region) {
                    continue;
                }
                let mut ring = part
                    .ring
                    .iter()
                    .copied()
                    .map(|point| transform.apply(point))
                    .collect::<Result<Vec<_>, _>>()?;
                if signed_area2(&ring) < 0 {
                    ring.reverse();
                }
                Ring::new(ring.clone()).map_err(|error| {
                    LayoutError::layout(
                        LayoutErrorKind::Malformed,
                        format!("indexed transformed ring is invalid: {error}"),
                    )
                })?;
                let bbox = points_bbox(&ring)?;
                if bbox_intersects(bbox, region) {
                    output.push(HierarchyCandidate {
                        structure: structure.name.clone(),
                        element_index: part.element_index,
                        part_index: part.part_index,
                        kind: part.kind,
                        layer: part.layer,
                        instance_path: path.clone(),
                        ring,
                        bbox,
                    });
                }
            }
            match element {
                GdsElement::Sref(reference) => {
                    let child = self.by_name[reference.structure.as_str()];
                    let child_transform = transform
                        .compose(Affine::instance(reference.transform, reference.origin)?)?;
                    path.push(InstancePathEntry {
                        parent_structure: structure.name.clone(),
                        element_index: element_index as u32,
                        referenced_structure: reference.structure.clone(),
                        column: 0,
                        row: 0,
                    });
                    self.query_structure(
                        child,
                        child_transform,
                        region,
                        layer,
                        depth + 1,
                        visits,
                        path,
                        output,
                    )?;
                    path.pop();
                }
                GdsElement::Aref(reference) => {
                    let count = usize::from(reference.columns)
                        .checked_mul(usize::from(reference.rows))
                        .ok_or_else(|| {
                            LayoutError::layout(
                                LayoutErrorKind::ArithmeticOverflow,
                                "AREF instance count overflow",
                            )
                        })?;
                    if count > self.options.max_array_instances {
                        return Err(LayoutError::layout(
                            LayoutErrorKind::CapacityExceeded,
                            format!(
                                "AREF has {count} instances; limit is {}",
                                self.options.max_array_instances
                            ),
                        ));
                    }
                    let pitches = array_pitches(reference)?;
                    let child = self.by_name[reference.structure.as_str()];
                    for column in 0..reference.columns {
                        for row in 0..reference.rows {
                            let origin = array_origin(reference.origin, pitches, column, row)?;
                            let child_transform = transform
                                .compose(Affine::instance(reference.transform, origin)?)?;
                            path.push(InstancePathEntry {
                                parent_structure: structure.name.clone(),
                                element_index: element_index as u32,
                                referenced_structure: reference.structure.clone(),
                                column,
                                row,
                            });
                            self.query_structure(
                                child,
                                child_transform,
                                region,
                                layer,
                                depth + 1,
                                visits,
                                path,
                                output,
                            )?;
                            path.pop();
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn index_element(element: &GdsElement, element_index: u32) -> Result<Vec<LocalShape>, LayoutError> {
    let (kind, layer, rings) = match element {
        GdsElement::Boundary(boundary) => {
            ensure_meta_supported(&boundary.meta, "BOUNDARY")?;
            Ring::new(boundary.ring.clone()).map_err(|error| {
                LayoutError::layout(
                    LayoutErrorKind::Malformed,
                    format!("invalid BOUNDARY: {error}"),
                )
            })?;
            (
                IndexedShapeKind::Boundary,
                GdsLayerIdentity {
                    layer: boundary.layer,
                    datatype: boundary.datatype,
                },
                vec![boundary.ring.clone()],
            )
        }
        GdsElement::Box(box_element) => {
            ensure_meta_supported(&box_element.meta, "BOX")?;
            Ring::new(box_element.ring.clone()).map_err(|error| {
                LayoutError::layout(LayoutErrorKind::Malformed, format!("invalid BOX: {error}"))
            })?;
            (
                IndexedShapeKind::Box,
                GdsLayerIdentity {
                    layer: box_element.layer,
                    datatype: box_element.box_type,
                },
                vec![box_element.ring.clone()],
            )
        }
        GdsElement::Path(path) => (
            IndexedShapeKind::Path,
            GdsLayerIdentity {
                layer: path.layer,
                datatype: path.datatype,
            },
            stroke_path(path)?,
        ),
        GdsElement::Text(text) => {
            ensure_meta_supported(&text.meta, "TEXT")?;
            return Ok(Vec::new());
        }
        GdsElement::Sref(reference) => {
            ensure_meta_supported(&reference.meta, "SREF")?;
            Affine::instance(reference.transform, reference.origin)?;
            return Ok(Vec::new());
        }
        GdsElement::Aref(reference) => {
            ensure_meta_supported(&reference.meta, "AREF")?;
            Affine::instance(reference.transform, reference.origin)?;
            array_pitches(reference)?;
            return Ok(Vec::new());
        }
        GdsElement::Node(_) => {
            return Err(LayoutError::layout(
                LayoutErrorKind::Unsupported,
                "NODE has no polygon spatial-index representation",
            ));
        }
        GdsElement::Unsupported(element) => {
            return Err(LayoutError::layout(
                LayoutErrorKind::Unsupported,
                format!(
                    "element record 0x{:02x} is unsupported",
                    element.start_record.record_type
                ),
            ));
        }
    };
    rings
        .into_iter()
        .enumerate()
        .map(|(part_index, ring)| {
            let bbox = points_bbox(&ring)?;
            Ok(LocalShape {
                element_index,
                part_index: part_index as u32,
                kind,
                layer,
                ring,
                bbox,
            })
        })
        .collect()
}

fn array_pitches(
    reference: &crate::gds::GdsArrayReference,
) -> Result<(i32, i32, i32, i32), LayoutError> {
    Ok((
        exact_pitch(
            reference.column_endpoint.x,
            reference.origin.x,
            reference.columns,
            "column x",
        )?,
        exact_pitch(
            reference.column_endpoint.y,
            reference.origin.y,
            reference.columns,
            "column y",
        )?,
        exact_pitch(
            reference.row_endpoint.x,
            reference.origin.x,
            reference.rows,
            "row x",
        )?,
        exact_pitch(
            reference.row_endpoint.y,
            reference.origin.y,
            reference.rows,
            "row y",
        )?,
    ))
}

fn array_origin(
    origin: Point,
    pitches: (i32, i32, i32, i32),
    column: u16,
    row: u16,
) -> Result<Point, LayoutError> {
    Ok(Point {
        x: checked_array_coordinate(origin.x, pitches.0, column, pitches.2, row)?,
        y: checked_array_coordinate(origin.y, pitches.1, column, pitches.3, row)?,
    })
}

fn points_bbox(points: &[Point]) -> Result<Bbox, LayoutError> {
    let first = points
        .first()
        .ok_or_else(|| LayoutError::layout(LayoutErrorKind::Malformed, "empty polygon ring"))?;
    let mut bbox = Bbox {
        xmin: first.x,
        ymin: first.y,
        xmax: first.x,
        ymax: first.y,
    };
    for point in &points[1..] {
        bbox.xmin = bbox.xmin.min(point.x);
        bbox.ymin = bbox.ymin.min(point.y);
        bbox.xmax = bbox.xmax.max(point.x);
        bbox.ymax = bbox.ymax.max(point.y);
    }
    Ok(bbox)
}

fn transform_bbox(transform: Affine, bbox: Bbox) -> Result<Bbox, LayoutError> {
    points_bbox(&[
        transform.apply(Point::new(bbox.xmin, bbox.ymin))?,
        transform.apply(Point::new(bbox.xmax, bbox.ymin))?,
        transform.apply(Point::new(bbox.xmax, bbox.ymax))?,
        transform.apply(Point::new(bbox.xmin, bbox.ymax))?,
    ])
}

fn include_bbox(target: &mut Option<Bbox>, value: Bbox) {
    if let Some(target) = target {
        target.xmin = target.xmin.min(value.xmin);
        target.ymin = target.ymin.min(value.ymin);
        target.xmax = target.xmax.max(value.xmax);
        target.ymax = target.ymax.max(value.ymax);
    } else {
        *target = Some(value);
    }
}

pub(super) fn validate_bbox(bbox: Bbox, name: &str) -> Result<(), LayoutError> {
    if bbox.xmin > bbox.xmax || bbox.ymin > bbox.ymax {
        Err(LayoutError::layout(
            LayoutErrorKind::Malformed,
            format!("{name} is inverted"),
        ))
    } else {
        Ok(())
    }
}

fn bbox_intersects(a: Bbox, b: Bbox) -> bool {
    i64::from(a.xmin) <= i64::from(b.xmax)
        && i64::from(b.xmin) <= i64::from(a.xmax)
        && i64::from(a.ymin) <= i64::from(b.ymax)
        && i64::from(b.ymin) <= i64::from(a.ymax)
}

fn signed_area2(ring: &[Point]) -> i128 {
    ring.iter()
        .enumerate()
        .map(|(index, point)| {
            let next = ring[(index + 1) % ring.len()];
            point.x as i128 * next.y as i128 - next.x as i128 * point.y as i128
        })
        .sum()
}
