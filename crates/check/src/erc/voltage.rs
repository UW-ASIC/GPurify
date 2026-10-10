//! Static voltage propagation from the declared supplies.
//!
//! Model: a net may sit anywhere between the lowest and highest declared
//! supply joined to it through device channels (MOS source to drain, every
//! pin of a resistor, diode or BJT); gates, bulks and capacitors pass nothing,
//! and a supply net is fixed at its domain's nominal (power) or 0 V (ground).
//! Data in: nets, devices, [`IntentMap`]. Data out: [`NetVoltage`].
//!
//! A channel passes whatever its gate is driven to, so a range spans every
//! supply the net could ever be joined to, and the voltage rules built on it
//! can over-report. A node pumped or bootstrapped beyond its supplies is
//! outside the model. This is catalog row ERC-F1, partial because channels
//! pass unconditionally; it is defined by Calibre PERC (white paper 81822,
//! public material only), the sky130 hv.X.1 rule and Siemens patents
//! US10796045B2 and US9262574B2. See the [check catalog] and
//! [check-sources.md].
//!
//! [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
//! [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md

use crate::erc::facts::IntentMap;
use crate::topology::{DeviceTable, NetId, NetTable, TerminalRole};
use gpurify_geom::connectivity::{components_into, ComponentLabel};
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

    fn fold(&mut self, into: usize, from: usize) {
        self.lo[into] = self.lo[into].min(self.lo[from]);
        self.hi[into] = self.hi[into].max(self.hi[from]);
        self.nominal_lo[into] = self.nominal_lo[into].min(self.nominal_lo[from]);
        self.nominal_hi[into] = self.nominal_hi[into].max(self.nominal_hi[from]);
        self.power[into] |= self.power[from];
    }
}

/// True when a terminal in this role conducts DC through the device.
pub fn is_channel(kind: DeviceKind, role: TerminalRole) -> bool {
    !matches!(role, TerminalRole::Gate | TerminalRole::Bulk) && kind != DeviceKind::Capacitor
}

/// Propagates the declared supplies over device channels; `out` is refilled to
/// `nets.net_count()` rows. Supply nets stop propagation: two domains that share
/// a ground stay apart.
pub fn propagate_into(
    nets: &NetTable,
    devices: &DeviceTable,
    intent: &IntentMap,
    out: &mut NetVoltage,
) {
    let count = nets.net_count();
    // Rows `count ..` are one accumulator per component, indexed by its label.
    let rows = count * 2;
    out.lo.clear();
    out.lo.resize(rows, f64::INFINITY);
    out.hi.clear();
    out.hi.resize(rows, f64::NEG_INFINITY);
    out.nominal_lo.clear();
    out.nominal_lo.resize(rows, f64::INFINITY);
    out.nominal_hi.clear();
    out.nominal_hi.resize(rows, f64::NEG_INFINITY);
    out.power.clear();
    out.power.resize(rows, 0);

    for (row, &net) in intent.supply_net.iter().enumerate() {
        let at = net.idx();
        let nominal = intent.supply_voltage[row].raw();
        let (volts, power) = match intent.supply_role[row] {
            SupplyRole::Power => (nominal, 1u64 << intent.supply_domain[row].0),
            SupplyRole::Ground => (0.0, 0),
        };
        out.lo[at] = volts;
        out.hi[at] = volts;
        out.nominal_lo[at] = nominal;
        out.nominal_hi[at] = nominal;
        out.power[at] = power;
    }
    let is_supply = |net: NetId| intent.supply_net.binary_search(&net).is_ok();

    // Join the non-supply channel nets of each device.
    let mut edges: Vec<(u32, u32)> = Vec::new();
    let mut channel: Vec<NetId> = Vec::new();
    let channels = |device: usize, channel: &mut Vec<NetId>| {
        let id = crate::topology::DeviceId(u32::try_from(device).expect("a device id is a u32"));
        let (terminal_nets, roles) = devices.terminals_of(id);
        channel.clear();
        channel.extend(
            terminal_nets
                .iter()
                .zip(roles)
                .filter(|&(&net, &role)| {
                    net != NetId::NONE && is_channel(devices.kind[device], role)
                })
                .map(|(&net, _)| net),
        );
    };
    for device in 0..devices.len() {
        channels(device, &mut channel);
        let mut free = channel.iter().filter(|&&net| !is_supply(net));
        if let Some(&anchor) = free.next() {
            edges.extend(free.map(|&net| (anchor.0, net.0)));
        }
    }
    let mut label: Vec<ComponentLabel> = Vec::new();
    let node_count = u32::try_from(count).expect("a NetId is a u32");
    components_into(node_count, &edges, &mut label);

    // Every supply on a channel reaches the components of the device's other channel nets.
    for device in 0..devices.len() {
        channels(device, &mut channel);
        for &supply in channel.iter().filter(|&&net| is_supply(net)) {
            for &net in channel.iter().filter(|&&net| !is_supply(net)) {
                out.fold(count + label[net.idx()].0 as usize, supply.idx());
            }
        }
    }
    for (net, root) in (0..node_count).zip(&label) {
        if !is_supply(NetId(net)) {
            out.fold(net as usize, count + root.0 as usize);
        }
    }
    out.lo.truncate(count);
    out.hi.truncate(count);
    out.nominal_lo.truncate(count);
    out.nominal_hi.truncate(count);
    out.power.truncate(count);
}
