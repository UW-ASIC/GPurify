//! CMP (Chemical-Mechanical Polishing) thickness prediction model.
//!
//! Without calibration data, `predict_cmp` returns `CmpStatus::NotRun`.
//! This module is a standalone data model; the fill module's existing
//! `CmpCalibration` covers the integrated density-to-thickness pipeline.

use super::fill::DensitySample;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CmpModel {
    pub revision: String,
    pub base_thickness_nm: f64,
    pub density_coefficient: f64,
    pub pressure_coefficient: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CmpSample {
    pub x: i32,
    pub y: i32,
    pub density: f64,
    pub predicted_thickness_nm: f64,
    pub uniformity_pct: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CmpStatus {
    Clean,
    Violation,
    NotRun,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CmpReport {
    pub status: CmpStatus,
    pub samples: Vec<CmpSample>,
    pub max_variation_nm: f64,
}

/// Predict post-CMP thickness from density samples.
/// Without calibration data, returns `CmpStatus::NotRun`.
pub fn predict_cmp(density_samples: &[DensitySample], model: Option<&CmpModel>) -> CmpReport {
    let Some(model) = model else {
        return CmpReport {
            status: CmpStatus::NotRun,
            samples: Vec::new(),
            max_variation_nm: 0.0,
        };
    };
    if !model.base_thickness_nm.is_finite()
        || !model.density_coefficient.is_finite()
        || !model.pressure_coefficient.is_finite()
        || model.base_thickness_nm <= 0.0
    {
        return CmpReport {
            status: CmpStatus::Error,
            samples: Vec::new(),
            max_variation_nm: 0.0,
        };
    }
    // ponytail: linear model — thickness = base + density_coeff * density.
    // pressure_coefficient reserved for future multi-zone models.
    let samples: Vec<CmpSample> = density_samples
        .iter()
        .map(|ds| {
            let thickness = model.base_thickness_nm + model.density_coefficient * ds.density;
            CmpSample {
                x: ds.x0,
                y: ds.y0,
                density: ds.density,
                predicted_thickness_nm: thickness,
                uniformity_pct: 0.0, // filled in below
            }
        })
        .collect();
    if samples.is_empty() {
        return CmpReport {
            status: CmpStatus::Clean,
            samples,
            max_variation_nm: 0.0,
        };
    }
    let min_t = samples
        .iter()
        .map(|s| s.predicted_thickness_nm)
        .fold(f64::INFINITY, f64::min);
    let max_t = samples
        .iter()
        .map(|s| s.predicted_thickness_nm)
        .fold(f64::NEG_INFINITY, f64::max);
    let max_variation = max_t - min_t;
    let mean_t = samples
        .iter()
        .map(|s| s.predicted_thickness_nm)
        .sum::<f64>()
        / samples.len() as f64;
    let samples: Vec<CmpSample> = samples
        .into_iter()
        .map(|mut s| {
            s.uniformity_pct = if mean_t > 0.0 {
                (s.predicted_thickness_nm - mean_t) / mean_t * 100.0
            } else {
                0.0
            };
            s
        })
        .collect();
    CmpReport {
        status: CmpStatus::Clean,
        samples,
        max_variation_nm: max_variation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predict_cmp_without_model_returns_not_run() {
        let report = predict_cmp(&[], None);
        assert_eq!(report.status, CmpStatus::NotRun);
        assert!(report.samples.is_empty());
    }

    #[test]
    fn predict_cmp_linear_model() {
        let model = CmpModel {
            revision: "test-r1".into(),
            base_thickness_nm: 100.0,
            density_coefficient: 20.0,
            pressure_coefficient: 0.0,
        };
        let samples = vec![
            DensitySample {
                x0: 0,
                y0: 0,
                x1: 10,
                y1: 10,
                scoped_area_dbu2: 100.0,
                material_area_dbu2: 50.0,
                density: 0.5,
            },
            DensitySample {
                x0: 10,
                y0: 0,
                x1: 20,
                y1: 10,
                scoped_area_dbu2: 100.0,
                material_area_dbu2: 80.0,
                density: 0.8,
            },
        ];
        let report = predict_cmp(&samples, Some(&model));
        assert_eq!(report.status, CmpStatus::Clean);
        assert_eq!(report.samples.len(), 2);
        assert!((report.samples[0].predicted_thickness_nm - 110.0).abs() < 1e-12);
        assert!((report.samples[1].predicted_thickness_nm - 116.0).abs() < 1e-12);
        assert!((report.max_variation_nm - 6.0).abs() < 1e-12);
    }

    #[test]
    fn predict_cmp_invalid_model_returns_error() {
        let model = CmpModel {
            revision: "bad".into(),
            base_thickness_nm: -1.0,
            density_coefficient: 0.0,
            pressure_coefficient: 0.0,
        };
        assert_eq!(predict_cmp(&[], Some(&model)).status, CmpStatus::Error);
    }
}
