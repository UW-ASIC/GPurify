//! Static voltage propagation from the declared supplies, conditional on gate
//! voltage.
//!
//! Model: a net may sit anywhere between the lowest and highest declared
//! supply joined to it through conducting device channels (MOS source to
//! drain, every pin of a resistor, diode or BJT); gates, bulks and capacitors
//! pass nothing, and a supply net is fixed at its domain's nominal (power) or
//! 0 V (ground). Data in: nets, devices, [`IntentMap`]. Data out:
//! [`NetVoltage`].
//!
//! A MOS whose deck row states a gate condition is a switch: `on_gate_min`
//! (an n-channel device) conducts only while its gate can reach that voltage
//! or more, `on_gate_max` (a p-channel device) only while its gate can fall to
//! that voltage or less, judged on the range its gate net reaches. This is
//! the conditional propagation of Calibre PERC as its public white paper
//! states it ("The NMOS is ON when the voltage at gate pin is >= 1 V, and OFF
//! when the voltage at gate pin is < 1 V", Siemens 81822, figure 1). A gate
//! no supply could reach even with every channel conducting is driven from
//! outside the cell, so its switch may conduct; so may a switch whose gate is
//! reached only through switches that never turn on (the gate floats). Every
//! other channel, and a MOS with no condition, conducts whatever its gate.
//!
//! The propagation is the least fixed point of these rules, so a range is
//! the span of every supply that can reach the net through channels that can
//! be on; the voltage rules built on it can still over-report. A channel
//! passes its full range when on: no threshold drop, no body effect. A node
//! pumped or bootstrapped beyond its supplies is outside the model.
//!
//! This is catalog row ERC-F1, defined by Calibre PERC (white paper 81822,
//! public material only), the sky130 hv.X.1 rule and Siemens patents
//! US10796045B2 and US9262574B2. See the [check catalog] and
//! [check-sources.md].
//!
//! [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
//! [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md

use crate::erc::facts::IntentMap;
use crate::topology::{DeviceId, DeviceTable, NetId, NetTable, TerminalRole};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::intent::SupplyRole;

/// What each net can see, indexed by [`NetId`]. Every column has one entry
/// per net of the extraction [`propagate_into`] was given.
#[derive(Debug, Default)]
pub struct NetVoltage {
    /// Lowest voltage the net can reach, mV; `lo > hi` when no supply reaches
    /// the net.
    pub lo: Vec<f64>,
    /// Highest voltage the net can reach, mV; `-inf` when no supply reaches it.
    pub hi: Vec<f64>,
    /// Lowest domain nominal among the reaching supplies, mV.
    /// A ground supply counts as its domain's nominal here, not 0 V.
    pub nominal_lo: Vec<f64>,
    /// Highest domain nominal among the reaching supplies, mV; `-inf` when
    /// none reaches the net.
    pub nominal_hi: Vec<f64>,
    /// Bit `d` set when a power supply of domain `d` reaches the net.
    pub power: Vec<u64>,
}

impl NetVoltage {
    /// True when some supply reaches `net`. `NetId::NONE` is false; any other
    /// id past the table panics.
    pub fn known(&self, net: NetId) -> bool {
        net != NetId::NONE && self.lo[net.idx()] <= self.hi[net.idx()]
    }

    /// The largest `|V(a) - V(b)|` the two nets can reach, mV; `None` unless both are known.
    pub fn worst_delta(&self, a: NetId, b: NetId) -> Option<f64> {
        (self.known(a) && self.known(b))
            .then(|| (self.hi[a.idx()] - self.lo[b.idx()]).max(self.hi[b.idx()] - self.lo[a.idx()]))
    }

    /// The power-domain mask of `net`; zero for `NetId::NONE`. A domain id is a
    /// bit, so at most 64 domains.
    pub fn power_of(&self, net: NetId) -> u64 {
        if net == NetId::NONE {
            0
        } else {
            self.power[net.idx()]
        }
    }

    /// Every column emptied and refilled with `count` unreached nets.
    fn reset(&mut self, count: usize) {
        for column in [&mut self.lo, &mut self.nominal_lo] {
            column.clear();
            column.resize(count, f64::INFINITY);
        }
        for column in [&mut self.hi, &mut self.nominal_hi] {
            column.clear();
            column.resize(count, f64::NEG_INFINITY);
        }
        self.power.clear();
        self.power.resize(count, 0);
    }

    /// Row `net` as one value.
    fn range(&self, net: usize) -> Range {
        Range {
            lo: self.lo[net],
            hi: self.hi[net],
            nominal_lo: self.nominal_lo[net],
            nominal_hi: self.nominal_hi[net],
            power: self.power[net],
        }
    }

    /// Widens row `net` to cover `with`; true when anything grew.
    fn widen(&mut self, net: usize, with: Range) -> bool {
        let old = self.range(net);
        let new = old.union(with);
        if new == old {
            return false;
        }
        self.lo[net] = new.lo;
        self.hi[net] = new.hi;
        self.nominal_lo[net] = new.nominal_lo;
        self.nominal_hi[net] = new.nominal_hi;
        self.power[net] = new.power;
        true
    }
}

/// One net's row of [`NetVoltage`].
#[derive(Debug, Clone, Copy, PartialEq)]
struct Range {
    lo: f64,
    hi: f64,
    nominal_lo: f64,
    nominal_hi: f64,
    power: u64,
}

impl Range {
    /// Nothing reached: the identity of [`Range::union`].
    const EMPTY: Range = Range {
        lo: f64::INFINITY,
        hi: f64::NEG_INFINITY,
        nominal_lo: f64::INFINITY,
        nominal_hi: f64::NEG_INFINITY,
        power: 0,
    };

    fn union(self, other: Range) -> Range {
        Range {
            lo: self.lo.min(other.lo),
            hi: self.hi.max(other.hi),
            nominal_lo: self.nominal_lo.min(other.nominal_lo),
            nominal_hi: self.nominal_hi.max(other.nominal_hi),
            power: self.power | other.power,
        }
    }
}

/// True when a terminal in this role conducts DC through the device.
pub fn is_channel(kind: DeviceKind, role: TerminalRole) -> bool {
    !matches!(role, TerminalRole::Gate | TerminalRole::Bulk) && kind != DeviceKind::Capacitor
}

/// A MOS switch's gate net and when it conducts.
#[derive(Debug, Clone, Copy)]
struct Switch {
    gate: NetId,
    /// `on_gate_min` (`true`, conducts at or above `at`) or `on_gate_max`.
    at_least: bool,
    /// The condition's voltage, mV.
    at: f64,
}

impl Switch {
    /// The switch of `device`, or `None` for a channel that always conducts:
    /// not a MOS, or a MOS whose row states no gate condition.
    fn of(devices: &DeviceTable, device: usize) -> Option<Switch> {
        if devices.kind[device] != DeviceKind::Mos {
            return None;
        }
        let value = devices.value.get(device).copied().unwrap_or_default();
        let (at_least, at) = match (value.on_gate_min_mv, value.on_gate_max_mv) {
            (Some(at), _) => (true, at),
            (None, Some(at)) => (false, at),
            (None, None) => return None,
        };
        let (nets, roles) = devices.terminals_of(device_id(device));
        let gate = roles
            .iter()
            .position(|&role| role == TerminalRole::Gate)
            .map_or(NetId::NONE, |at| nets[at]);
        Some(Switch { gate, at_least, at })
    }

    /// True when the gate's reached range can turn the switch on; false when
    /// no supply reaches the gate yet.
    fn can_turn_on(self, voltage: &NetVoltage) -> bool {
        if !reached(voltage, self.gate) {
            return false;
        }
        let gate = self.gate.idx();
        if self.at_least {
            voltage.hi[gate] >= self.at
        } else {
            voltage.lo[gate] <= self.at
        }
    }
}

fn device_id(index: usize) -> DeviceId {
    DeviceId(u32::try_from(index).expect("a device table indexes with u32"))
}

/// What one propagation reads besides the voltages it writes.
struct Graph<'a> {
    devices: &'a DeviceTable,
    /// Per net: a declared supply, fixed at its own voltage.
    supply: Vec<bool>,
    /// Devices with a terminal on each net, CSR by `start`.
    start: Vec<u32>,
    adjacent: Vec<u32>,
    /// Per device: its gate condition, `None` for a channel that always
    /// conducts.
    switch: Vec<Option<Switch>>,
}

/// `device`'s channel nets that are among the first `count` nets.
fn channel(devices: &DeviceTable, count: usize, device: usize) -> impl Iterator<Item = usize> + '_ {
    let kind = devices.kind[device];
    let (nets, roles) = devices.terminals_of(device_id(device));
    nets.iter()
        .zip(roles)
        .filter(move |&(&net, &role)| {
            net != NetId::NONE && net.idx() < count && is_channel(kind, role)
        })
        .map(|(&net, _)| net.idx())
}

/// True when some supply reaches `net`, a net of `voltage`'s extraction.
fn reached(voltage: &NetVoltage, net: NetId) -> bool {
    net != NetId::NONE && net.idx() < voltage.lo.len() && voltage.known(net)
}

impl Graph<'_> {
    /// Runs the queued devices to a fixed point: a conducting device widens
    /// each of its non-supply channel nets to the union of all of them, and a
    /// net that grows queues every device on it, its gates' included.
    fn relax(
        &self,
        free: &[bool],
        queue: &mut Vec<usize>,
        queued: &mut [bool],
        out: &mut NetVoltage,
    ) {
        while let Some(device) = queue.pop() {
            queued[device] = false;
            let on = match self.switch[device] {
                None => true,
                Some(switch) => free[device] || switch.can_turn_on(out),
            };
            if !on {
                continue;
            }
            let count = self.supply.len();
            let union = channel(self.devices, count, device)
                .fold(Range::EMPTY, |acc, net| acc.union(out.range(net)));
            for net in channel(self.devices, count, device) {
                if self.supply[net] || !out.widen(net, union) {
                    continue;
                }
                let (lo, hi) = (self.start[net] as usize, self.start[net + 1] as usize);
                for &next in &self.adjacent[lo..hi] {
                    let next = next as usize;
                    if !queued[next] {
                        queued[next] = true;
                        queue.push(next);
                    }
                }
            }
        }
    }
}

/// Propagates the declared supplies over conducting device channels; `out` is
/// refilled to `nets.net_count()` rows. Supply nets stop propagation: two
/// domains that share a ground stay apart. A terminal on no net, or on a net
/// past `nets`, is ignored.
///
/// Three passes: every channel conducting, to find the gates no supply can
/// reach at all (their switches are free to conduct); then the switches
/// judged on their gates' ranges, starting from the supplies alone; then, as
/// often as some switch's gate is still unreached (it floats), that switch
/// freed and the propagation resumed. Ranges only grow, so this ends.
///
/// # Panics
///
/// Panics if `devices` holds more than `u32::MAX` devices.
pub fn propagate_into(
    nets: &NetTable,
    devices: &DeviceTable,
    intent: &IntentMap,
    out: &mut NetVoltage,
) {
    let count = nets.net_count();
    let mut supply = vec![false; count];
    for &net in &intent.supply_net {
        if net != NetId::NONE && net.idx() < count {
            supply[net.idx()] = true;
        }
    }
    let mut start = vec![0u32; count + 1];
    for device in 0..devices.len() {
        for &net in devices.terminals_of(device_id(device)).0 {
            if net != NetId::NONE && net.idx() < count {
                start[net.idx() + 1] += 1;
            }
        }
    }
    for at in 1..start.len() {
        start[at] += start[at - 1];
    }
    let mut fill = start.clone();
    let mut adjacent = vec![0u32; start[count] as usize];
    for device in 0..devices.len() {
        for &net in devices.terminals_of(device_id(device)).0 {
            if net != NetId::NONE && net.idx() < count {
                adjacent[fill[net.idx()] as usize] = device_id(device).0;
                fill[net.idx()] += 1;
            }
        }
    }
    let graph = Graph {
        devices,
        supply,
        start,
        adjacent,
        switch: (0..devices.len()).map(|d| Switch::of(devices, d)).collect(),
    };
    let seed = |out: &mut NetVoltage| {
        out.reset(count);
        for (row, &net) in intent.supply_net.iter().enumerate() {
            if net == NetId::NONE || net.idx() >= count {
                continue;
            }
            let nominal = intent.supply_voltage[row].raw();
            let (volts, power) = match intent.supply_role[row] {
                SupplyRole::Power => (nominal, 1u64 << intent.supply_domain[row].0),
                SupplyRole::Ground => (0.0, 0),
            };
            out.widen(
                net.idx(),
                Range {
                    lo: volts,
                    hi: volts,
                    nominal_lo: nominal,
                    nominal_hi: nominal,
                    power,
                },
            );
        }
    };
    let mut queue: Vec<usize> = (0..devices.len()).rev().collect();
    let mut queued = vec![true; devices.len()];

    // Every channel conducting: which gates any supply can reach at all.
    seed(out);
    graph.relax(&vec![true; devices.len()], &mut queue, &mut queued, out);
    let mut free: Vec<bool> = graph
        .switch
        .iter()
        .map(|switch| switch.is_some_and(|switch| !reached(out, switch.gate)))
        .collect();

    seed(out);
    queue.extend((0..devices.len()).rev());
    queued.fill(true);
    loop {
        graph.relax(&free, &mut queue, &mut queued, out);
        for (device, switch) in graph.switch.iter().enumerate() {
            let floating = switch.is_some_and(|switch| !reached(out, switch.gate));
            if floating && !free[device] {
                free[device] = true;
                queued[device] = true;
                queue.push(device);
            }
        }
        if queue.is_empty() {
            return;
        }
    }
}
