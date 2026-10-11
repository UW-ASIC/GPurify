//! What the deck's `lvs` statements change in a comparison
//! ([`LvsControls`]): per-parameter tolerances, ignored parameters and
//! asymmetric transistors.
//!
//! Data in: the controls and the two graphs. Data out: the graphs as the
//! controls leave them, and the bound a paired parameter must meet.

use crate::lvs::graph::{narrow, transpose_into, Graph};
use crate::lvs::verdict::Discrepancy;
use crate::topology::TerminalRole;
use gpurify_ingest::deck::{DeviceKind, LvsControls};
use gpurify_ingest::StrId;

/// The role an asymmetric transistor's source is compared under: a pin of
/// its own, so it never trades places with the drain.
const FIXED_SOURCE: TerminalRole = TerminalRole::Pin(0);
/// The role an asymmetric transistor's drain is compared under.
const FIXED_DRAIN: TerminalRole = TerminalRole::Pin(1);

/// Whether `device` is a transistor of a model `lvs asymmetric` names.
fn is_asymmetric(graph: &Graph, device: usize, controls: &LvsControls) -> bool {
    graph.device_kind[device] == DeviceKind::Mos
        && controls.asymmetric.contains(&graph.device_model[device])
}

/// Gives an asymmetric transistor's source and drain roles of their own,
/// [`FIXED_SOURCE`] and [`FIXED_DRAIN`], which share no role code (so
/// refinement and the terminal comparison tell them apart) and are no
/// channel (so a parallel merge needs source on source and drain on drain,
/// and no series merge takes them). With no asymmetric model, untouched.
pub(crate) fn fix_channels(graph: &mut Graph, controls: &LvsControls) {
    if controls.asymmetric.is_empty() {
        return;
    }
    let mut changed = false;
    for device in 0..graph.device_count() {
        if !is_asymmetric(graph, device, controls) {
            continue;
        }
        let from = graph.device_terminal_start[device] as usize;
        let to = graph.device_terminal_start[device + 1] as usize;
        for role in &mut graph.terminal_role[from..to] {
            *role = match *role {
                TerminalRole::Source => FIXED_SOURCE,
                TerminalRole::Drain => FIXED_DRAIN,
                other => other,
            };
        }
        changed = true;
    }
    if changed {
        let nets = graph.net_count();
        transpose_into(graph, nets);
    }
}

/// Names an asymmetric transistor's terminal in `found` by the role it was
/// drawn and written with again: [`FIXED_SOURCE`] is its `Source` and
/// [`FIXED_DRAIN`] its `Drain`. `reference` is the reduced reference graph
/// the rows index.
pub(crate) fn unfix_roles(found: &mut [Discrepancy], reference: &Graph, controls: &LvsControls) {
    for discrepancy in found {
        if let Discrepancy::TerminalMismatch {
            ref_device, role, ..
        } = discrepancy
        {
            if is_asymmetric(reference, *ref_device as usize, controls) {
                *role = match *role {
                    FIXED_SOURCE => TerminalRole::Source,
                    FIXED_DRAIN => TerminalRole::Drain,
                    other => other,
                };
            }
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::{fix_channels, unfix_roles, FIXED_DRAIN, FIXED_SOURCE};
    use crate::lvs::graph::{transpose_into, Graph};
    use crate::lvs::verdict::Discrepancy;
    use crate::topology::TerminalRole::{Bulk, Drain, Gate, Source};
    use gpurify_ingest::deck::{DeviceKind, LvsControls};
    use gpurify_ingest::StrId;

    const DMOS: StrId = StrId(1);
    const NMOS: StrId = StrId(2);

    /// A `DMOS` and an `NMOS`, each gate 0, source 1, drain 2, bulk 3.
    fn two_mos() -> Graph {
        let mut graph = Graph {
            device_kind: vec![DeviceKind::Mos; 2],
            device_model: vec![DMOS, NMOS],
            device_terminal_start: vec![0, 4, 8],
            terminal_net: vec![0, 1, 2, 3, 0, 1, 2, 3],
            terminal_role: [Gate, Source, Drain, Bulk].repeat(2),
            device_param_start: vec![0, 0, 0],
            net_name: vec![None; 4],
            ..Graph::default()
        };
        transpose_into(&mut graph, 4);
        graph
    }

    /// Oracle: the definition. Only the asymmetric model's source and drain
    /// take the fixed roles, in both directions of the incidence, and a
    /// terminal mismatch on it is named by its drawn role again; the other
    /// model's is left alone. Breaks if the rewrite reaches another model or
    /// misses the net side, or if a report keeps the internal role.
    #[test]
    fn only_an_asymmetric_transistor_s_ends_are_fixed_and_reported_as_drawn() {
        let controls = LvsControls {
            asymmetric: vec![DMOS],
            ..LvsControls::default()
        };
        let mut graph = two_mos();
        fix_channels(&mut graph, &controls);
        assert_eq!(
            graph.terminals_of(0).1,
            [Gate, FIXED_SOURCE, FIXED_DRAIN, Bulk]
        );
        assert_eq!(graph.terminals_of(1).1, [Gate, Source, Drain, Bulk]);
        assert_eq!(graph.terminals_on(1), [(0, FIXED_SOURCE), (1, Source)]);

        let mismatch = |ref_device, role| Discrepancy::TerminalMismatch {
            layout_device: ref_device,
            ref_device,
            role,
        };
        let mut found = vec![mismatch(0, FIXED_DRAIN), mismatch(1, FIXED_DRAIN)];
        unfix_roles(&mut found, &graph, &controls);
        assert_eq!(found, [mismatch(0, Drain), mismatch(1, FIXED_DRAIN)]);
    }
}
