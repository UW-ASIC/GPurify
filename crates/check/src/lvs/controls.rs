//! What the deck's `lvs` statements change in a comparison
//! ([`LvsControls`]): per-parameter tolerances and ignored parameters.
//!
//! Data in: the controls and the two graphs. Data out: the graphs as the
//! controls leave them, and the bound a paired parameter must meet.

use crate::lvs::graph::{narrow, Graph};
use gpurify_ingest::deck::LvsControls;
use gpurify_ingest::StrId;

/// Drops every parameter `lvs ignore_parameter` names for the device's
/// model, so neither a merge nor the comparison reads it: as if no card
/// stated it and the layout measured none.
pub(crate) fn drop_ignored_params(graph: &mut Graph, controls: &LvsControls) {
    if controls.ignore_parameter.is_empty() {
        return;
    }
    let mut param = Vec::with_capacity(graph.param.len());
    let mut start = Vec::with_capacity(graph.device_count() + 1);
    start.push(0);
    for device in 0..graph.device_count() {
        let model = graph.device_model[device];
        param.extend(
            graph
                .params_of(narrow(device))
                .iter()
                .filter(|&&(name, _)| !controls.ignore_parameter.contains(&(model, name))),
        );
        start.push(narrow(param.len()));
    }
    graph.param = param;
    graph.device_param_start = start;
}

/// How far apart two values of one parameter may be and still agree.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Bound {
    /// A fraction of the larger value.
    relative: f64,
    /// In the parameter's SI unit.
    absolute: f64,
}

impl Bound {
    /// Whether `a` and `b` agree: `|a - b| <= absolute + relative * max(|a|,
    /// |b|)`. `NaN` never does. With no absolute part this is the run's
    /// relative test exactly, since adding `0.0` changes no value.
    pub(crate) fn agree(self, a: f64, b: f64) -> bool {
        (a - b).abs() <= self.absolute + self.relative * a.abs().max(b.abs())
    }
}

/// The bound on `param` of `model`: the deck's `lvs tolerance` row for it,
/// whose parts replace the run's, or the run's relative `default` alone.
///
/// ponytail: a linear scan per parameter; a deck states a handful of rows.
pub(crate) fn bound(controls: &LvsControls, default: f64, model: StrId, param: StrId) -> Bound {
    controls
        .tolerance
        .iter()
        .find(|row| row.model == model && row.param == param)
        .map_or(
            Bound {
                relative: default,
                absolute: 0.0,
            },
            |row| Bound {
                relative: row.relative,
                absolute: row.absolute,
            },
        )
}
