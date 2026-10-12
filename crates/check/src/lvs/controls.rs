//! What the deck's `lvs` statements change in a comparison
//! ([`LvsControls`]): per-parameter tolerances, ignored parameters,
//! asymmetric transistors, permuted pins and ignored devices.
//!
//! Data in: the controls and the two graphs. Data out: the graphs as the
//! controls leave them, and the bound a paired parameter must meet.

use crate::lvs::graph::{narrow, transpose_into, Graph};
use crate::lvs::reduce::Merge;
use crate::lvs::verdict::Discrepancy;
use crate::topology::device::role_at;
use crate::topology::TerminalRole;
use gpurify_ingest::deck::{DeviceKind, LvsControls};
use gpurify_ingest::layout::glob_matches;
use gpurify_ingest::{StrId, StrTable};

/// The role an asymmetric transistor's source is compared under: a pin of
/// its own, so it never trades places with the drain.
const FIXED_SOURCE: TerminalRole = TerminalRole::Pin(0);
/// The role an asymmetric transistor's drain is compared under.
const FIXED_DRAIN: TerminalRole = TerminalRole::Pin(1);
/// Pins `lvs permute` joins share `Pin(PERMUTED + p)`, `p` the lowest
/// position of the class: past every role a recogniser or card gives a
/// device of four pins, and no channel.
const PERMUTED: u8 = 8;

/// The pins of one device as `lvs asymmetric` and `lvs permute` leave them:
/// `root[p]` is the lowest position interchangeable with position `p`, in
/// `device` statement order (see `gpurify_ingest::deck::DeviceRecognition`).
#[derive(Debug, Clone, Copy)]
struct Classes {
    kind: DeviceKind,
    root: [u8; 4],
    asymmetric: bool,
}

impl Classes {
    /// The classes of a device of `kind` and `model`: the default ones (a
    /// transistor's source and drain, unless asymmetric, and a resistor's
    /// ends) joined with every `lvs permute` pair of the model. `None` when
    /// no control names the model, and the roles stay as built.
    fn of(kind: DeviceKind, model: StrId, controls: &LvsControls) -> Option<Self> {
        let asymmetric = kind == DeviceKind::Mos && controls.asymmetric.contains(&model);
        let permuted = controls.permute.iter().any(|row| row.0 == model);
        if !asymmetric && !permuted {
            return None;
        }
        let mut classes = Self {
            kind,
            root: [0, 1, 2, 3],
            asymmetric,
        };
        match kind {
            DeviceKind::Mos if !asymmetric => classes.join(1, 2),
            DeviceKind::Resistor => classes.join(0, 1),
            _ => {}
        }
        for &(_, a, b) in controls.permute.iter().filter(|row| row.0 == model) {
            classes.join(a, b);
        }
        Some(classes)
    }

    /// Joins the classes of positions `a` and `b`; a position past four is
    /// no pin of any kind and is ignored.
    fn join(&mut self, a: u8, b: u8) {
        let (Some(&ra), Some(&rb)) = (self.root.get(usize::from(a)), self.root.get(usize::from(b)))
        else {
            return;
        };
        let (low, high) = (ra.min(rb), ra.max(rb));
        for root in &mut self.root {
            if *root == high {
                *root = low;
            }
        }
    }

    /// The positions in `position`'s class, as a bit mask.
    fn class(self, position: u8) -> u8 {
        let root = self.root[usize::from(position)];
        (0..4u8)
            .filter(|&p| self.root[usize::from(p)] == root)
            .fold(0, |mask, p| mask | 1 << p)
    }

    /// The role position `position` is compared under. The default classes
    /// keep the builders' roles (a transistor's channel stays `Source` and
    /// `Drain`, a resistor's ends `Pin(0)`), an asymmetric transistor's
    /// lone ends are [`FIXED_SOURCE`] and [`FIXED_DRAIN`], any other lone
    /// pin keeps its role, and every other class is
    /// `Pin(PERMUTED + lowest position)`.
    fn role(self, position: u8) -> TerminalRole {
        let class = self.class(position);
        if self.kind == DeviceKind::Mos && class == 0b0110 {
            return role_at(self.kind, position);
        }
        if self.kind == DeviceKind::Resistor && class == 0b0011 {
            return TerminalRole::Pin(0);
        }
        if class.is_power_of_two() {
            return match (self.asymmetric, position) {
                (true, 1) => FIXED_SOURCE,
                (true, 2) => FIXED_DRAIN,
                _ => role_at(self.kind, position),
            };
        }
        TerminalRole::Pin(PERMUTED + self.root[usize::from(position)])
    }

    /// The role a terminal compared under `role` is reported as: a fixed
    /// end as the end it is, a permuted class as its lowest pin.
    fn reported(self, role: TerminalRole) -> TerminalRole {
        match role {
            FIXED_SOURCE if self.asymmetric => TerminalRole::Source,
            FIXED_DRAIN if self.asymmetric => TerminalRole::Drain,
            TerminalRole::Pin(pin) if pin >= PERMUTED => role_at(self.kind, pin - PERMUTED),
            other => other,
        }
    }
}

/// The position a built role stands at for `kind`, the inverse of
/// [`role_at`]; a resistor's ends, both built `Pin(0)`, read as position 0.
fn position_of(kind: DeviceKind, role: TerminalRole) -> Option<u8> {
    (0..4u8).find(|&position| role_at(kind, position) == role)
}

/// Gives every device of a model `lvs asymmetric` or `lvs permute` names
/// the roles [`Classes::role`] says, so refinement, the terminal comparison
/// and a parallel merge treat the pins of one class as one, and an
/// asymmetric transistor's ends as two. A class other than the default
/// channel is no channel, so no series merge takes it. With neither
/// control, untouched.
pub(crate) fn assign_roles(graph: &mut Graph, controls: &LvsControls) {
    if controls.asymmetric.is_empty() && controls.permute.is_empty() {
        return;
    }
    let mut changed = false;
    for device in 0..graph.device_count() {
        let kind = graph.device_kind[device];
        let Some(classes) = Classes::of(kind, graph.device_model[device], controls) else {
            continue;
        };
        let from = graph.device_terminal_start[device] as usize;
        let to = graph.device_terminal_start[device + 1] as usize;
        for role in &mut graph.terminal_role[from..to] {
            if let Some(position) = position_of(kind, *role) {
                *role = classes.role(position);
            }
        }
        changed = true;
    }
    if changed {
        let nets = graph.net_count();
        transpose_into(graph, nets);
    }
}

/// Names each terminal mismatch in `found` by a role its device was drawn
/// and written with: an asymmetric transistor's end as that end, and a pin
/// of a permuted class as the class's lowest pin. `reference` is the
/// reduced reference graph the rows index.
pub(crate) fn report_roles(found: &mut [Discrepancy], reference: &Graph, controls: &LvsControls) {
    for discrepancy in found {
        if let Discrepancy::TerminalMismatch {
            ref_device, role, ..
        } = discrepancy
        {
            let device = *ref_device as usize;
            let kind = reference.device_kind[device];
            if let Some(classes) = Classes::of(kind, reference.device_model[device], controls) {
                *role = classes.reported(*role);
            }
        }
    }
}

/// Whether `lvs ignore`, `lvs ignore_shorted`, `lvs max_res` or `lvs
/// min_caps` leaves `device` out: its model is ignored, or ignored when
/// shorted and every terminal it has is on one net, or it is a resistor
/// stating an `r` above the deck's `max_res`, or a capacitor stating a `c`
/// below its `min_caps` (`KLayout`'s `max_res` and `min_caps`, "the
/// netlist compare will ignore" such devices). `values` names `r` and `c`;
/// a device stating neither has no value to hold to a threshold and stays.
fn left_out(
    graph: &Graph,
    device: u32,
    controls: &LvsControls,
    values: (Option<StrId>, Option<StrId>),
) -> bool {
    let model = graph.device_model[device as usize];
    if controls.ignore.contains(&model) {
        return true;
    }
    let stated = |name: Option<StrId>| {
        name.and_then(|name| {
            graph
                .params_of(device)
                .iter()
                .find(|&&(stated, _)| stated == name)
                .map(|&(_, value)| value)
        })
    };
    let open = match graph.device_kind[device as usize] {
        DeviceKind::Resistor => controls
            .max_res
            .zip(stated(values.0))
            .is_some_and(|(limit, r)| r > limit),
        // `min_caps` is in aF.
        DeviceKind::Capacitor => controls
            .min_caps
            .zip(stated(values.1))
            .is_some_and(|(limit, c)| c < limit * 1e-18),
        _ => false,
    };
    if open {
        return true;
    }
    let nets = graph.terminals_of(device).0;
    controls.ignore_shorted.contains(&model)
        && nets
            .first()
            .is_some_and(|&first| first != u32::MAX && nets.iter().all(|&net| net == first))
}

/// Drops every device `lvs ignore`, `lvs ignore_shorted`, `lvs max_res` or
/// `lvs min_caps` leaves out ([`left_out`]; `values` names `r` and `c`), as if it were not drawn or written, and every net that
/// lost its last terminal with them and is no port: no netlist could state
/// such a net, while a port must still pair. Surviving nets keep their
/// order. Returns the rows of `graph` the kept devices were, ascending, or
/// `None` when nothing was dropped.
pub(crate) fn drop_ignored_devices(
    graph: &mut Graph,
    controls: &LvsControls,
    values: (Option<StrId>, Option<StrId>),
) -> Option<Vec<u32>> {
    if controls.ignore.is_empty()
        && controls.ignore_shorted.is_empty()
        && controls.max_res.is_none()
        && controls.min_caps.is_none()
    {
        return None;
    }
    let kept: Vec<u32> = (0..narrow(graph.device_count()))
        .filter(|&device| !left_out(graph, device, controls, values))
        .collect();
    if kept.len() == graph.device_count() {
        return None;
    }
    let nets = graph.net_count();
    // A net survives while a kept device or a port holds it, or nothing
    // ever did: only what the dropped devices alone reached goes.
    let mut held = vec![false; nets];
    for &net in &graph.port_net {
        held[net as usize] = true;
    }
    for &device in &kept {
        for &net in graph.terminals_of(device).0 {
            if let Some(slot) = held.get_mut(net as usize) {
                *slot = true;
            }
        }
    }
    let mut new_net = vec![u32::MAX; nets];
    let mut next = 0u32;
    for (net, slot) in new_net.iter_mut().enumerate() {
        if held[net] || graph.terminals_on(narrow(net)).is_empty() {
            *slot = next;
            next += 1;
        }
    }
    let renamed = |net: u32| new_net.get(net as usize).copied().unwrap_or(u32::MAX);
    let mut out = Graph {
        net_name: (0..nets)
            .filter(|&net| new_net[net] != u32::MAX)
            .map(|net| graph.net_name[net])
            .collect(),
        port_net: graph.port_net.iter().map(|&net| renamed(net)).collect(),
        ..Graph::default()
    };
    out.device_terminal_start.push(0);
    out.device_param_start.push(0);
    for &device in &kept {
        out.device_kind.push(graph.device_kind[device as usize]);
        out.device_model.push(graph.device_model[device as usize]);
        let (terminal_nets, roles) = graph.terminals_of(device);
        out.terminal_net
            .extend(terminal_nets.iter().map(|&net| renamed(net)));
        out.terminal_role.extend_from_slice(roles);
        out.device_terminal_start
            .push(narrow(out.terminal_net.len()));
        out.param.extend_from_slice(graph.params_of(device));
        out.device_param_start.push(narrow(out.param.len()));
    }
    transpose_into(&mut out, next as usize);
    *graph = out;
    Some(kept)
}

/// Whether a layout net labelled `name` is a must-connect net: its label
/// matches an `lvs connect_implicit` pattern, or is in an `lvs
/// connect_explicit` group.
pub(crate) fn must_connect(name: StrId, strings: &StrTable, controls: &LvsControls) -> bool {
    let text = strings.resolve(name);
    controls
        .connect_implicit
        .iter()
        .any(|pattern| glob_matches(pattern, text))
        || controls
            .connect_explicit
            .iter()
            .any(|group| group.contains(&name))
}

/// `layout` with its must-connect nets joined, as `KLayout`'s
/// `connect_implicit` and `connect_explicit` join them for LVS ("physically
/// there are multiple nets, logically ... there is only one net"; catalog
/// LVS-002): the nets of one label an `lvs connect_implicit` pattern
/// matches are one net, and so are the nets labelled with the names of one
/// `lvs connect_explicit` group (an explicit group first). The joined net is
/// the lowest of its nets, with that net's label; the other rows go, and
/// surviving nets keep their order. Devices are unchanged. With neither
/// control, a copy. The open stays an open on the layout:
/// [`check_layout`](crate::lvs::check_layout) still reports it, as a
/// warning.
pub fn join_must_connect(layout: &Graph, controls: &LvsControls, strings: &StrTable) -> Graph {
    let mut out = layout.clone();
    if controls.connect_implicit.is_empty() && controls.connect_explicit.is_empty() {
        return out;
    }
    // Each must-connect net's key: `(0, group)` for an explicit group,
    // `(1, label)` for an implicit label; the first net of a key stays.
    let key = |name: StrId| {
        if let Some(group) = controls
            .connect_explicit
            .iter()
            .position(|group| group.contains(&name))
        {
            return Some((0u8, narrow(group)));
        }
        let text = strings.resolve(name);
        controls
            .connect_implicit
            .iter()
            .any(|pattern| glob_matches(pattern, text))
            .then_some((1u8, name.0))
    };
    let mut first: Vec<((u8, u32), u32)> = Vec::new();
    let mut new_net = Vec::with_capacity(layout.net_count());
    let mut kept = 0u32;
    for (net, &name) in layout.net_name.iter().enumerate() {
        let joined = name.and_then(key).and_then(|k| {
            first
                .iter()
                .find(|&&(seen, _)| seen == k)
                .map(|&(_, row)| row)
        });
        if let Some(row) = joined {
            new_net.push(row);
            continue;
        }
        if let Some(k) = name.and_then(key) {
            first.push((k, kept));
        }
        new_net.push(kept);
        out.net_name[kept as usize] = layout.net_name[net];
        kept += 1;
    }
    out.net_name.truncate(kept as usize);
    for net in &mut out.terminal_net {
        if let Some(&renamed) = new_net.get(*net as usize) {
            *net = renamed;
        }
    }
    out.port_net = layout
        .port_net
        .iter()
        .map(|&net| new_net[net as usize])
        .collect();
    out.port_net.sort_unstable();
    out.port_net.dedup();
    transpose_into(&mut out, kept as usize);
    out
}

/// The names of `reference`'s ports, ascending, each once: what `lvs
/// ports_by_name` pairs by.
pub(crate) fn port_names(reference: &Graph) -> Vec<StrId> {
    let mut names: Vec<StrId> = reference
        .port_net
        .iter()
        .filter_map(|&net| reference.net_name[net as usize])
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// The refinement seed of every node of the two reduced graphs, layout
/// nodes first, devices before nets on each side, as refinement numbers
/// them: a layout net whose label is one of the port `names` and the
/// reference port net of that name share the name's rank, so refinement
/// starts them in a class of their own; so do the layout net labelled and
/// the reference net named by one `lvs same_nets` row, ranked after the
/// ports (a port's own rank wins on a net both name). Every other node has
/// none, `u32::MAX`.
pub(crate) fn port_seeds(
    (layout, reference): (&Graph, &Graph),
    names: &[StrId],
    same_nets: &[(StrId, StrId)],
) -> Vec<u32> {
    let rank = |name: Option<StrId>| {
        name.and_then(|name| names.binary_search(&name).ok())
            .map(narrow)
    };
    let paired = |name: Option<StrId>, side: fn(&(StrId, StrId)) -> StrId| {
        name.and_then(|name| same_nets.iter().position(|row| side(row) == name))
            .map(|at| narrow(names.len() + at))
    };
    let split = layout.device_count() + layout.net_count();
    let mut seeds = vec![u32::MAX; split + reference.device_count() + reference.net_count()];
    for (net, &name) in layout.net_name.iter().enumerate() {
        seeds[layout.device_count() + net] = rank(name)
            .or_else(|| paired(name, |row| row.0))
            .unwrap_or(u32::MAX);
    }
    let base = split + reference.device_count();
    for (net, &name) in reference.net_name.iter().enumerate() {
        seeds[base + net] = paired(name, |row| row.1).unwrap_or(u32::MAX);
    }
    for &net in &reference.port_net {
        let net = net as usize;
        if let Some(rank) = rank(reference.net_name[net]) {
            seeds[base + net] = rank;
        }
    }
    seeds
}

/// Rewrites each merge's device rows, rows of a graph [`drop_ignored_devices`]
/// filtered, as rows of the graph it was given (`kept[row]`).
pub(crate) fn restore_rows(merges: &mut [Merge], kept: Option<&[u32]>) {
    let Some(kept) = kept else {
        return;
    };
    for merge in merges {
        for row in &mut merge.devices {
            *row = kept[*row as usize];
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
    use super::{assign_roles, report_roles, Classes, FIXED_DRAIN, FIXED_SOURCE};
    use crate::lvs::graph::{transpose_into, Graph};
    use crate::lvs::verdict::Discrepancy;
    use crate::topology::TerminalRole::{Bulk, Drain, Gate, Pin, Source};
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
        assign_roles(&mut graph, &controls);
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
        report_roles(&mut found, &graph, &controls);
        assert_eq!(found, [mismatch(0, Drain), mismatch(1, FIXED_DRAIN)]);
    }

    /// Oracle: the definition (deck.md: "permutations chain"). Permuting a
    /// transistor's gate with its source joins the default source-drain
    /// class, so gate, source and drain are one class under `Pin(8)` and the
    /// bulk stays; on an asymmetric transistor the same row joins only gate
    /// and source, and the drain stays fixed. A capacitor's permuted plates
    /// are `Pin(8)` and report as `Pin(0)`. Breaks if classes do not chain,
    /// or if asymmetry is lost under a permutation.
    #[test]
    fn permutations_chain_with_the_default_classes() {
        let roles = |kind, controls: &LvsControls| {
            let classes = Classes::of(kind, DMOS, controls).expect("a control names DMOS");
            (0..4).map(|p| classes.role(p)).collect::<Vec<_>>()
        };
        let gate_source = LvsControls {
            permute: vec![(DMOS, 0, 1)],
            ..LvsControls::default()
        };
        assert_eq!(
            roles(DeviceKind::Mos, &gate_source),
            [Pin(8), Pin(8), Pin(8), Bulk]
        );
        let asymmetric = LvsControls {
            asymmetric: vec![DMOS],
            ..gate_source.clone()
        };
        assert_eq!(
            roles(DeviceKind::Mos, &asymmetric),
            [Pin(8), Pin(8), FIXED_DRAIN, Bulk]
        );
        let plates = LvsControls {
            permute: vec![(DMOS, 1, 0)],
            ..LvsControls::default()
        };
        let classes = Classes::of(DeviceKind::Capacitor, DMOS, &plates).expect("named");
        assert_eq!((classes.role(0), classes.role(1)), (Pin(8), Pin(8)));
        assert_eq!(classes.reported(Pin(8)), Pin(0));
        assert!(Classes::of(DeviceKind::Mos, NMOS, &plates).is_none());
    }
}
