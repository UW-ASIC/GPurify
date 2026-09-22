//! Two tables computed once per run and read by most rules.
//!
//! Data in: nets, devices, ports, and the optional design intent.
//! Data out: [`NetFacts`] (roles per net) and [`IntentMap`] (intent keyed by
//! [`NetId`]); [`IntentMap::is_usable`] is the one skip decision.

use crate::topology::{DeviceTable, NetId, NetTable, PortTable, TerminalRole};
use gpurify_geom::{prefix, Qty, Voltage};
use gpurify_ingest::intent::{DesignIntent, NetLimits, SupplyRole};

/// Which terminal roles are present on a net, one bit per role. Every
/// `Pin(_)` is one bit: a symmetric device's pin index carries no meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct RoleMask(pub u8);

impl RoleMask {
    pub const GATE: Self = Self(1 << 0);
    pub const SOURCE: Self = Self(1 << 1);
    pub const DRAIN: Self = Self(1 << 2);
    pub const BULK: Self = Self(1 << 3);
    pub const BASE: Self = Self(1 << 4);
    pub const EMITTER: Self = Self(1 << 5);
    pub const COLLECTOR: Self = Self(1 << 6);
    pub const PIN: Self = Self(1 << 7);
    pub const NONE: Self = Self(0);

    pub const fn of(role: TerminalRole) -> Self {
        match role {
            TerminalRole::Gate => Self::GATE,
            TerminalRole::Source => Self::SOURCE,
            TerminalRole::Drain => Self::DRAIN,
            TerminalRole::Bulk => Self::BULK,
            TerminalRole::Base => Self::BASE,
            TerminalRole::Emitter => Self::EMITTER,
            TerminalRole::Collector => Self::COLLECTOR,
            TerminalRole::Pin(_) => Self::PIN,
        }
    }

    /// True when every bit of `other` is set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Roles present on each net, indexed by [`NetId`].
#[derive(Debug, Default)]
pub struct NetFacts {
    pub role: Vec<RoleMask>,
}

impl NetFacts {
    pub fn len(&self) -> usize {
        self.role.len()
    }

    pub fn is_empty(&self) -> bool {
        self.role.is_empty()
    }

    /// True when any device terminal lands on this net. `NetId::NONE` is
    /// false; any other id past the table panics.
    pub fn is_device_connected(&self, net: NetId) -> bool {
        net != NetId::NONE && !self.role[net.idx()].is_empty()
    }
}

/// Fold every device terminal into its net's role mask; `out` is refilled to
/// `nets.net_count()` rows.
pub fn classify_nets_into(nets: &NetTable, devices: &DeviceTable, out: &mut NetFacts) {
    // A scrap row past the end takes `NetId::NONE` (and any id past this
    // extraction) so its roles cannot leak onto a real net.
    let scrap = nets.net_count();
    out.role.clear();
    out.role.resize(scrap + 1, RoleMask::NONE);
    for (&net, &role) in devices.terminal_net.iter().zip(&devices.terminal_role) {
        let row = net.idx().min(scrap);
        out.role[row] = out.role[row].union(RoleMask::of(role));
    }
    out.role.truncate(scrap);
}

/// Design intent re-keyed from names onto extracted nets. A net that is not a
/// declared supply has no supply row.
#[derive(Debug, Default)]
pub struct IntentMap {
    /// False when no design intent was supplied at all.
    pub declared: bool,
    /// Declared supply nets, ascending (the lookups binary-search it).
    pub supply_net: Vec<NetId>,
    pub supply_role: Vec<SupplyRole>,
    /// Nominal voltage of each supply net's domain.
    pub supply_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Nets with declared limits, ascending. Not disjoint from `supply_net`.
    pub limit_net: Vec<NetId>,
    pub limit: Vec<NetLimits>,
}

impl IntentMap {
    /// The nominal voltage of a declared supply net.
    pub fn nominal_voltage(&self, net: NetId) -> Option<Qty<Voltage, { prefix::MILLI }>> {
        let row = self.supply_net.binary_search(&net).ok()?;
        Some(self.supply_voltage[row])
    }

    /// The limits declared for a net. All-`None` means *not checked*, never
    /// *unlimited*.
    pub fn limits_of(&self, net: NetId) -> NetLimits {
        self.limit_net
            .binary_search(&net)
            .map_or_else(|_| NetLimits::default(), |row| self.limit[row])
    }

    /// True means *run*: intent was supplied and names a supply or a limited
    /// net this layout has.
    pub fn is_usable(&self) -> bool {
        self.declared && !(self.supply_net.is_empty() && self.limit_net.is_empty())
    }
}

/// Re-key design intent onto extracted nets; `out` is cleared and refilled.
/// `None` leaves `declared == false`, which is how six rules report skipped.
pub fn resolve_intent_into(
    intent: Option<&DesignIntent>,
    ports: &PortTable,
    nets: &NetTable,
    out: &mut IntentMap,
) {
    *out = IntentMap::default();
    let Some(intent) = intent else {
        return;
    };
    out.declared = !intent.is_empty();

    // ponytail: a declared supply the layout never labelled is silently absent;
    // reporting it needs a way to enumerate `DesignIntent`'s names.
    let net_count = u32::try_from(nets.net_count()).expect("a NetId is a u32, so the count fits");
    for net in (0..net_count).map(NetId) {
        let Some(name) = ports.name_of(net) else {
            continue;
        };
        if let Some((domain, role)) = intent.supply_role(name) {
            out.supply_net.push(net);
            out.supply_role.push(role);
            out.supply_voltage.push(intent.domain_voltage(domain));
        }
        let limits = intent.limits(name);
        if limits.max_drop.is_some()
            || limits.max_drop_fraction.is_some()
            || limits.max_overvoltage.is_some()
            || limits.budget_current_ua.is_some()
        {
            out.limit_net.push(net);
            out.limit.push(limits);
        }
    }
}
