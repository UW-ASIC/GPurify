//! Deterministic legal rectilinear fill generation and exact density/CMP recheck.
//!
//! The generator only emits configured rectangular fill on the configured grid.
//! Region, exclusion, keepout, spacing, width, minimum-density and maximum-density
//! constraints are exact polygon-set operations. Failure to converge is explicit;
//! calibrated CMP predictions are `NotRun` unless the caller supplies a model.

use gdsverify_core::exact::{
    rectilinear_intersection, rectilinear_subtraction, rectilinear_union, ExactGeometryError,
    Point, Polygon, PolygonSet,
};
use crate::geometry::{GeometryStore, LayerId};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillPattern {
    Grid,
    Staggered,
    Chequerboard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillConnectivity {
    Floating,
    GroundConnected,
}

#[derive(Clone, Debug)]
pub struct FillConfig {
    pub shape_width: i32,
    pub shape_height: i32,
    pub min_width: i32,
    pub min_space: i32,
    pub grid: i32,
    pub grid_origin_x: i32,
    pub grid_origin_y: i32,
    pub window: i32,
    pub step: i32,
    pub min_density: f64,
    pub max_density: f64,
    pub max_candidates: usize,
    pub pattern: FillPattern,
    pub connectivity: FillConnectivity,
    /// Maximum density gradient across adjacent windows; None = unchecked.
    pub gradient_limit: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct FillInputs {
    pub region: PolygonSet,
    pub existing_material: PolygonSet,
    pub keepouts: PolygonSet,
    pub exclusions: PolygonSet,
    /// Critical-net regions where fill must not be placed.
    pub critical_net_regions: PolygonSet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillStatus {
    Converged,
    Infeasible,
    CapacityExceeded,
    Error,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DensitySample {
    pub x0: i32,
    pub y0: i32,
    pub x1: i32,
    pub y1: i32,
    pub scoped_area_dbu2: f64,
    pub material_area_dbu2: f64,
    pub density: f64,
}

#[derive(Clone, Debug)]
pub struct FillResult {
    pub status: FillStatus,
    pub fill: PolygonSet,
    pub samples: Vec<DensitySample>,
    pub evaluated_candidates: usize,
    pub accepted_shapes: usize,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CmpPoint {
    pub density: f64,
    pub thickness_nm: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CmpCalibration {
    pub model_revision: String,
    pub points: Vec<CmpPoint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmpStatus {
    Evaluated,
    NotRun,
    Error,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CmpSample {
    pub x: i32,
    pub y: i32,
    pub density: f64,
    pub thickness_nm: f64,
}

#[derive(Clone, Debug)]
pub struct FillRecheck {
    pub density_clean: bool,
    pub density_samples: Vec<DensitySample>,
    pub cmp_status: CmpStatus,
    pub cmp_model_revision: Option<String>,
    pub cmp_samples: Vec<CmpSample>,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum FillError {
    InvalidConfig(String),
    Geometry(ExactGeometryError),
}

impl fmt::Display for FillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(f, "invalid fill configuration: {message}"),
            Self::Geometry(error) => write!(f, "fill exact geometry: {error}"),
        }
    }
}

impl std::error::Error for FillError {}

impl From<ExactGeometryError> for FillError {
    fn from(value: ExactGeometryError) -> Self {
        Self::Geometry(value)
    }
}

/// Generate deterministic legal fill, scanning `(y, x)` grid order.
pub fn generate_fill(inputs: &FillInputs, config: &FillConfig) -> Result<FillResult, FillError> {
    validate_config(config)?;
    let legal = rectilinear_subtraction(&inputs.region, &inputs.exclusions)?;
    let combined_keepouts = rectilinear_union(&inputs.keepouts, &inputs.critical_net_regions)?;
    let obstacles = rectilinear_union(&inputs.existing_material, &combined_keepouts)?;
    let Some((xmin, ymin, xmax, ymax)) = set_bbox(&legal) else {
        return Ok(FillResult {
            status: FillStatus::Error,
            fill: PolygonSet::empty(),
            samples: Vec::new(),
            evaluated_candidates: 0,
            accepted_shapes: 0,
            diagnostics: vec!["legal fill region is empty".into()],
        });
    };

    let mut fill = PolygonSet::empty();
    let mut material = inputs.existing_material.clone();
    let mut samples = density_samples(&material, &legal, config.window, config.step)?;
    if samples
        .iter()
        .any(|sample| sample.density > config.max_density)
    {
        return Ok(FillResult {
            status: FillStatus::Infeasible,
            fill,
            samples,
            evaluated_candidates: 0,
            accepted_shapes: 0,
            diagnostics: vec!["existing material already exceeds maximum density".into()],
        });
    }
    if density_converged(&samples, config) {
        return Ok(FillResult {
            status: FillStatus::Converged,
            fill,
            samples,
            evaluated_candidates: 0,
            accepted_shapes: 0,
            diagnostics: Vec::new(),
        });
    }

    let mut evaluated = 0_usize;
    let mut accepted = 0_usize;
    let mut y = align_up(ymin, config.grid_origin_y, config.grid)?;
    while y
        .checked_add(config.shape_height)
        .is_some_and(|edge| edge <= ymax)
    {
        let mut x = align_up(xmin, config.grid_origin_x, config.grid)?;
        while x
            .checked_add(config.shape_width)
            .is_some_and(|edge| edge <= xmax)
        {
            if evaluated >= config.max_candidates {
                return Ok(FillResult {
                    status: FillStatus::CapacityExceeded,
                    fill,
                    samples,
                    evaluated_candidates: evaluated,
                    accepted_shapes: accepted,
                    diagnostics: vec![format!(
                        "candidate limit {} reached before density convergence",
                        config.max_candidates
                    )],
                });
            }
            evaluated += 1;
            let candidate = rectangle(
                x,
                y,
                x.checked_add(config.shape_width)
                    .ok_or_else(|| FillError::InvalidConfig("fill x overflow".into()))?,
                y.checked_add(config.shape_height)
                    .ok_or_else(|| FillError::InvalidConfig("fill y overflow".into()))?,
            )?;

            let entirely_legal = rectilinear_subtraction(&candidate, &legal)?
                .polygons()
                .is_empty();
            let halo = rectangle(
                x.checked_sub(config.min_space)
                    .ok_or_else(|| FillError::InvalidConfig("fill halo x overflow".into()))?,
                y.checked_sub(config.min_space)
                    .ok_or_else(|| FillError::InvalidConfig("fill halo y overflow".into()))?,
                x.checked_add(config.shape_width)
                    .and_then(|edge| edge.checked_add(config.min_space))
                    .ok_or_else(|| FillError::InvalidConfig("fill halo x overflow".into()))?,
                y.checked_add(config.shape_height)
                    .and_then(|edge| edge.checked_add(config.min_space))
                    .ok_or_else(|| FillError::InvalidConfig("fill halo y overflow".into()))?,
            )?;
            let occupied = rectilinear_union(&obstacles, &fill)?;
            let spacing_legal = rectilinear_intersection(&halo, &occupied)?
                .polygons()
                .is_empty();
            if entirely_legal && spacing_legal {
                let proposed_material = rectilinear_union(&material, &candidate)?;
                let proposed_samples =
                    density_samples(&proposed_material, &legal, config.window, config.step)?;
                let improves = samples
                    .iter()
                    .zip(&proposed_samples)
                    .any(|(before, after)| {
                        before.density < config.min_density && after.density > before.density
                    });
                let below_max = proposed_samples
                    .iter()
                    .all(|sample| sample.density <= config.max_density + 1e-12);
                if improves && below_max {
                    fill = rectilinear_union(&fill, &candidate)?;
                    material = proposed_material;
                    samples = proposed_samples;
                    accepted += 1;
                    if density_converged(&samples, config) {
                        return Ok(FillResult {
                            status: FillStatus::Converged,
                            fill,
                            samples,
                            evaluated_candidates: evaluated,
                            accepted_shapes: accepted,
                            diagnostics: Vec::new(),
                        });
                    }
                }
            }
            x = x
                .checked_add(config.grid)
                .ok_or_else(|| FillError::InvalidConfig("fill x scan overflow".into()))?;
        }
        y = y
            .checked_add(config.grid)
            .ok_or_else(|| FillError::InvalidConfig("fill y scan overflow".into()))?;
    }
    Ok(FillResult {
        status: FillStatus::Infeasible,
        fill,
        samples,
        evaluated_candidates: evaluated,
        accepted_shapes: accepted,
        diagnostics: vec!["legal candidate space exhausted before density convergence".into()],
    })
}

/// Recheck exact density after fill and optionally apply caller-supplied CMP calibration.
pub fn recheck_fill(
    inputs: &FillInputs,
    result: &FillResult,
    config: &FillConfig,
    cmp: Option<&CmpCalibration>,
) -> Result<FillRecheck, FillError> {
    validate_config(config)?;
    let legal = rectilinear_subtraction(&inputs.region, &inputs.exclusions)?;
    let material = rectilinear_union(&inputs.existing_material, &result.fill)?;
    let density_samples = density_samples(&material, &legal, config.window, config.step)?;
    let density_clean = density_converged(&density_samples, config);
    let Some(model) = cmp else {
        return Ok(FillRecheck {
            density_clean,
            density_samples,
            cmp_status: CmpStatus::NotRun,
            cmp_model_revision: None,
            cmp_samples: Vec::new(),
            diagnostics: vec!["CMP not run: no calibrated model supplied".into()],
        });
    };
    if let Err(message) = validate_cmp(model) {
        return Ok(FillRecheck {
            density_clean,
            density_samples,
            cmp_status: CmpStatus::Error,
            cmp_model_revision: Some(model.model_revision.clone()),
            cmp_samples: Vec::new(),
            diagnostics: vec![message],
        });
    }
    let cmp_samples = density_samples
        .iter()
        .map(|sample| CmpSample {
            x: sample.x0,
            y: sample.y0,
            density: sample.density,
            thickness_nm: interpolate_cmp(model, sample.density),
        })
        .collect();
    Ok(FillRecheck {
        density_clean,
        density_samples,
        cmp_status: CmpStatus::Evaluated,
        cmp_model_revision: Some(model.model_revision.clone()),
        cmp_samples,
        diagnostics: Vec::new(),
    })
}

/// Append generated fill to a geometry store without approximating holes.
pub fn append_fill(
    store: &mut GeometryStore,
    layer: LayerId,
    result: &FillResult,
) -> Result<Vec<crate::geometry::PolyId>, FillError> {
    let mut ids = Vec::new();
    for polygon in result.fill.polygons() {
        if !polygon.holes().is_empty() {
            return Err(FillError::InvalidConfig(
                "generated fill unexpectedly contains holes".into(),
            ));
        }
        let points: Vec<_> = polygon
            .outer()
            .vertices()
            .iter()
            .map(|p| (p.x, p.y))
            .collect();
        ids.push(store.add_polygon(layer, &points));
    }
    Ok(ids)
}

fn density_samples(
    material: &PolygonSet,
    region: &PolygonSet,
    window: i32,
    step: i32,
) -> Result<Vec<DensitySample>, FillError> {
    let Some((xmin, ymin, xmax, ymax)) = set_bbox(region) else {
        return Ok(Vec::new());
    };
    super::density_window_work(xmin, ymin, xmax, ymax, window, step)?;
    let mut samples = Vec::new();
    let window = i64::from(window);
    let step = i64::from(step);
    let xmax = i64::from(xmax);
    let ymax = i64::from(ymax);
    let mut y = i64::from(ymin);
    loop {
        let mut x = i64::from(xmin);
        loop {
            let x1 = x
                .checked_add(window)
                .ok_or(ExactGeometryError::ArithmeticOverflow)?
                .min(xmax);
            let y1 = y
                .checked_add(window)
                .ok_or(ExactGeometryError::ArithmeticOverflow)?
                .min(ymax);
            let (x0, y0, x1, y1) = (
                i32::try_from(x)
                    .map_err(|_| FillError::InvalidConfig("window x overflow".into()))?,
                i32::try_from(y)
                    .map_err(|_| FillError::InvalidConfig("window y overflow".into()))?,
                i32::try_from(x1)
                    .map_err(|_| FillError::InvalidConfig("window x overflow".into()))?,
                i32::try_from(y1)
                    .map_err(|_| FillError::InvalidConfig("window y overflow".into()))?,
            );
            let clipped = rectilinear_intersection(region, &rectangle(x0, y0, x1, y1)?)?;
            let scoped_area = clipped.area2() as f64 / 2.0;
            if scoped_area > 0.0 {
                let material_area =
                    rectilinear_intersection(material, &clipped)?.area2() as f64 / 2.0;
                samples.push(DensitySample {
                    x0,
                    y0,
                    x1,
                    y1,
                    scoped_area_dbu2: scoped_area,
                    material_area_dbu2: material_area,
                    density: material_area / scoped_area,
                });
            }
            if i64::from(x1) == xmax {
                break;
            }
            x = x
                .checked_add(step)
                .ok_or_else(|| FillError::InvalidConfig("window step overflow".into()))?;
        }
        if y.checked_add(window)
            .ok_or(ExactGeometryError::ArithmeticOverflow)?
            >= ymax
        {
            break;
        }
        y = y
            .checked_add(step)
            .ok_or_else(|| FillError::InvalidConfig("window step overflow".into()))?;
    }
    Ok(samples)
}

fn density_converged(samples: &[DensitySample], config: &FillConfig) -> bool {
    !samples.is_empty()
        && samples.iter().all(|sample| {
            sample.density + 1e-12 >= config.min_density
                && sample.density <= config.max_density + 1e-12
        })
}

fn validate_config(config: &FillConfig) -> Result<(), FillError> {
    if config.shape_width <= 0
        || config.shape_height <= 0
        || config.min_width <= 0
        || config.min_space < 0
        || config.grid <= 0
        || config.window <= 0
        || config.step <= 0
        || config.step > config.window
        || config.max_candidates == 0
    {
        return Err(FillError::InvalidConfig(
            "dimensions/grid/window/capacity are invalid or step leaves unchecked gaps".into(),
        ));
    }
    if config.shape_width < config.min_width
        || config.shape_height < config.min_width
        || config.shape_width % config.grid != 0
        || config.shape_height % config.grid != 0
    {
        return Err(FillError::InvalidConfig(
            "fill shape violates minimum width or manufacturing grid".into(),
        ));
    }
    if !config.min_density.is_finite()
        || !config.max_density.is_finite()
        || !(0.0..=1.0).contains(&config.min_density)
        || !(0.0..=1.0).contains(&config.max_density)
        || config.min_density > config.max_density
    {
        return Err(FillError::InvalidConfig(
            "density bounds must satisfy 0 <= min <= max <= 1".into(),
        ));
    }
    Ok(())
}

fn validate_cmp(model: &CmpCalibration) -> Result<(), String> {
    if model.model_revision.trim().is_empty() || model.points.is_empty() {
        return Err("CMP model revision and calibration points are required".into());
    }
    let mut previous = f64::NEG_INFINITY;
    for point in &model.points {
        if !point.density.is_finite()
            || !point.thickness_nm.is_finite()
            || !(0.0..=1.0).contains(&point.density)
            || point.thickness_nm <= 0.0
            || point.density <= previous
        {
            return Err(
                "CMP points require increasing density and positive finite thickness".into(),
            );
        }
        previous = point.density;
    }
    Ok(())
}

fn interpolate_cmp(model: &CmpCalibration, density: f64) -> f64 {
    if density <= model.points[0].density {
        return model.points[0].thickness_nm;
    }
    for pair in model.points.windows(2) {
        if density <= pair[1].density {
            let t = (density - pair[0].density) / (pair[1].density - pair[0].density);
            return pair[0].thickness_nm + t * (pair[1].thickness_nm - pair[0].thickness_nm);
        }
    }
    model.points.last().unwrap().thickness_nm
}

fn align_up(value: i32, origin: i32, grid: i32) -> Result<i32, FillError> {
    let delta = i64::from(value) - i64::from(origin);
    let grid = i64::from(grid);
    let remainder = delta.rem_euclid(grid);
    let aligned = if remainder == 0 {
        i64::from(value)
    } else {
        i64::from(value) + grid - remainder
    };
    i32::try_from(aligned).map_err(|_| FillError::InvalidConfig("grid alignment overflow".into()))
}

fn rectangle(x0: i32, y0: i32, x1: i32, y1: i32) -> Result<PolygonSet, FillError> {
    Ok(PolygonSet::from_polygon(Polygon::from_outer(vec![
        Point::new(x0, y0),
        Point::new(x1, y0),
        Point::new(x1, y1),
        Point::new(x0, y1),
    ])?))
}

fn set_bbox(set: &PolygonSet) -> Option<(i32, i32, i32, i32)> {
    let mut bbox = (i32::MAX, i32::MAX, i32::MIN, i32::MIN);
    let mut any = false;
    for polygon in set.polygons() {
        for point in polygon.outer().vertices() {
            any = true;
            bbox.0 = bbox.0.min(point.x);
            bbox.1 = bbox.1.min(point.y);
            bbox.2 = bbox.2.max(point.x);
            bbox.3 = bbox.3.max(point.y);
        }
    }
    any.then_some(bbox)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x0: i32, y0: i32, x1: i32, y1: i32) -> PolygonSet {
        rectangle(x0, y0, x1, y1).unwrap()
    }

    fn config() -> FillConfig {
        FillConfig {
            shape_width: 4,
            shape_height: 10,
            min_width: 4,
            min_space: 2,
            grid: 2,
            grid_origin_x: 0,
            grid_origin_y: 0,
            window: 20,
            step: 20,
            min_density: 0.4,
            max_density: 0.4,
            max_candidates: 100,
            pattern: FillPattern::Grid,
            connectivity: FillConnectivity::Floating,
            gradient_limit: None,
        }
    }

    #[test]
    fn fill_is_grid_space_keepout_and_density_legal() {
        let inputs = FillInputs {
            region: rect(0, 0, 20, 10),
            existing_material: PolygonSet::empty(),
            keepouts: rect(0, 0, 4, 10),
            exclusions: PolygonSet::empty(),
            critical_net_regions: PolygonSet::empty(),
        };
        let result = generate_fill(&inputs, &config()).unwrap();
        assert_eq!(result.status, FillStatus::Converged);
        assert_eq!(result.accepted_shapes, 2);
        assert_eq!(result.samples[0].density, 0.4);
        let xs: Vec<_> = result
            .fill
            .polygons()
            .iter()
            .map(|p| p.outer().vertices()[0].x)
            .collect();
        assert_eq!(xs, vec![6, 12]);
    }

    #[test]
    fn infeasible_and_capacity_are_not_reported_converged() {
        let inputs = FillInputs {
            region: rect(0, 0, 20, 10),
            existing_material: PolygonSet::empty(),
            keepouts: rect(0, 0, 18, 10),
            exclusions: PolygonSet::empty(),
            critical_net_regions: PolygonSet::empty(),
        };
        assert_eq!(
            generate_fill(&inputs, &config()).unwrap().status,
            FillStatus::Infeasible
        );
        let mut limited = config();
        limited.max_candidates = 1;
        assert_eq!(
            generate_fill(
                &FillInputs {
                    keepouts: PolygonSet::empty(),
                    ..inputs
                },
                &limited
            )
            .unwrap()
            .status,
            FillStatus::CapacityExceeded
        );
    }

    #[test]
    fn recheck_needs_supplied_cmp_and_uses_calibration() {
        let inputs = FillInputs {
            region: rect(0, 0, 20, 10),
            existing_material: PolygonSet::empty(),
            keepouts: rect(0, 0, 4, 10),
            exclusions: PolygonSet::empty(),
            critical_net_regions: PolygonSet::empty(),
        };
        let result = generate_fill(&inputs, &config()).unwrap();
        let not_run = recheck_fill(&inputs, &result, &config(), None).unwrap();
        assert_eq!(not_run.cmp_status, CmpStatus::NotRun);
        let model = CmpCalibration {
            model_revision: "foundry-r1".into(),
            points: vec![
                CmpPoint {
                    density: 0.0,
                    thickness_nm: 90.0,
                },
                CmpPoint {
                    density: 0.8,
                    thickness_nm: 110.0,
                },
            ],
        };
        let checked = recheck_fill(&inputs, &result, &config(), Some(&model)).unwrap();
        assert!(checked.density_clean);
        assert_eq!(checked.cmp_status, CmpStatus::Evaluated);
        assert!((checked.cmp_samples[0].thickness_nm - 100.0).abs() < 1e-12);
    }

    #[test]
    fn density_and_cmp_windows_are_translation_safe_and_bounded() {
        let calibration = CmpCalibration {
            model_revision: "foundry-r1".into(),
            points: vec![
                CmpPoint {
                    density: 0.0,
                    thickness_nm: 90.0,
                },
                CmpPoint {
                    density: 1.0,
                    thickness_nm: 110.0,
                },
            ],
        };
        let mut translated_config = config();
        translated_config.window = 10;
        translated_config.step = 10;
        translated_config.min_density = 1.0;
        translated_config.max_density = 1.0;
        let run_at = |origin: i32| {
            let region = rect(origin, origin, origin + 5, origin + 5);
            let inputs = FillInputs {
                region: region.clone(),
                existing_material: region,
                keepouts: PolygonSet::empty(),
                exclusions: PolygonSet::empty(),
                critical_net_regions: PolygonSet::empty(),
            };
            let generated = generate_fill(&inputs, &translated_config).unwrap();
            assert_eq!(generated.status, FillStatus::Converged);
            recheck_fill(&inputs, &generated, &translated_config, Some(&calibration)).unwrap()
        };
        let at_origin = run_at(0);
        let at_max = run_at(i32::MAX - 5);
        assert_eq!(at_origin.density_samples[0].density, 1.0);
        assert_eq!(
            at_max.density_samples[0].density,
            at_origin.density_samples[0].density
        );
        assert_eq!(
            at_max.density_samples[0].scoped_area_dbu2,
            at_origin.density_samples[0].scoped_area_dbu2
        );
        assert_eq!(at_max.cmp_status, CmpStatus::Evaluated);

        let cap = super::super::MAX_DENSITY_WINDOW_WORK as i32;
        let oversized = rect(0, 0, cap + 1, 1);
        let inputs = FillInputs {
            region: oversized.clone(),
            existing_material: oversized,
            keepouts: PolygonSet::empty(),
            exclusions: PolygonSet::empty(),
            critical_net_regions: PolygonSet::empty(),
        };
        let mut unit_windows = translated_config;
        unit_windows.window = 1;
        unit_windows.step = 1;
        let result = FillResult {
            status: FillStatus::Converged,
            fill: PolygonSet::empty(),
            samples: Vec::new(),
            evaluated_candidates: 0,
            accepted_shapes: 0,
            diagnostics: Vec::new(),
        };
        assert!(matches!(
            recheck_fill(&inputs, &result, &unit_windows, None),
            Err(FillError::Geometry(
                ExactGeometryError::CapacityExceeded { .. }
            ))
        ));
    }
}
