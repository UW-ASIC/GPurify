//! Two tables computed once per run and read by most of the rules.
//!
//! [`IntentMap`] is where the skip decision is made: the `Option<&DesignIntent>`
//! is resolved exactly once, here, into [`IntentMap::declared`], so six rules
//! cannot each get that test wrong.

use gpurify_ingest::intent::{DesignIntent, DomainId, NetLimits, SupplyRole};
use crate::topology::{DeviceTable, NetId, NetTable, PortTable, TerminalRole};
use gpurify_geom::{prefix, Qty, Voltage};

/// Which terminal roles are present on a net, as a bit per role.
///
/// [`TerminalRole::Pin`] collapses to one bit: the pin index of a symmetric
/// two-terminal device carries no electrical meaning.
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

    /// Nothing attached.
    pub const NONE: Self = Self(0);

    /// Every role.
    pub const ANY: Self = Self(0xFF);

    /// The bit for one terminal role.
    pub const fn of(role: TerminalRole) -> Self {
        // `Pin(_)` discards the index: shifting by it would put `Pin(3)` on the
        // drain bit.
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

    /// True when the two masks share at least one bit.
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `self` with every bit of `other` cleared.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == Self::NONE.0
    }
}

/// What is attached to each net, indexed by [`NetId`].
#[derive(Debug, Default)]
pub struct NetFacts {
    /// Roles present on each net, indexed by [`NetId`].
    pub role: Vec<RoleMask>,
    /// Terminals attached to each net, saturating at [`u32::MAX`]. Counts
    /// terminals, not devices: a device with source and drain on one net
    /// contributes two.
    ///
    /// Separate from the mask because `multiple_drivers` needs *how many*.
    pub terminals: Vec<u32>,
}

impl NetFacts {
    pub fn len(&self) -> usize {
        debug_assert_eq!(
            self.role.len(),
            self.terminals.len(),
            "a mask lost its count, or a count lost its mask"
        );
        self.role.len()
    }

    pub fn is_empty(&self) -> bool {
        // Through `len`, so the column-parity assert holds on this path too.
        self.len() == 0
    }

    /// The roles on one net. [`RoleMask::NONE`] for a net no device touches.
    pub fn role_of(&self, net: NetId) -> RoleMask {
        // `NetId::NONE` is an absence rather than a net.
        if net == NetId::NONE {
            return RoleMask::NONE;
        }
        // Fail closed: a net id this table never saw panics rather than reading
        // as unconnected, so "no device touches this net" and "this net is not
        // in this extraction" cannot answer the same.
        debug_assert_eq!(self.role.len(), self.terminals.len());
        self.role[net.idx()]
    }

    /// True when any device terminal at all lands on this net.
    pub fn is_device_connected(&self, net: NetId) -> bool {
        // Every device family, not just MOS: the mask was folded from the flat
        // terminal column.
        !self.role_of(net).is_empty()
    }
}

/// Fold every device terminal into its net's role mask.
///
/// Caller owns `out`, cleared and refilled to `nets.net_count()` rows.
pub fn classify_nets_into(nets: &NetTable, devices: &DeviceTable, out: &mut NetFacts) {
    debug_assert_eq!(
        devices.terminal_net.len(),
        devices.terminal_role.len(),
        "a net column and a role column arrive parallel"
    );

    // One row per net plus a scrap row on the end: a terminal carrying
    // `NetId::NONE`, or any id past this extraction, clamps onto the scrap row
    // and is truncated away, so its roles cannot leak onto a real net.
    let scrap = nets.net_count();
    out.role.clear();
    out.role.resize(scrap + 1, RoleMask::NONE);
    out.terminals.clear();
    out.terminals.resize(scrap + 1, 0);

    for (&net, &role) in devices.terminal_net.iter().zip(&devices.terminal_role) {
        let row = net.idx().min(scrap);
        out.role[row] = out.role[row].union(RoleMask::of(role));
        // Saturating: wrapping to zero would report a broken extraction clean.
        out.terminals[row] = out.terminals[row].saturating_add(1);
    }

    out.role.truncate(scrap);
    out.terminals.truncate(scrap);

    debug_assert_eq!(out.role.len(), scrap, "one mask per extracted net");
    debug_assert_eq!(out.terminals.len(), scrap, "one count per extracted net");
    debug_assert!(
        out.terminals.iter().map(|&n| n as usize).sum::<usize>() <= devices.terminal_net.len(),
        "the fold counted more terminals than the device table holds"
    );
}

/// Design intent, re-keyed from interned names onto extracted nets.
///
/// Existence-based: a net that is not a declared supply has no row here, rather
/// than a row holding `None`.
#[derive(Debug, Default)]
pub struct IntentMap {
    /// False when no design intent was supplied at all.
    ///
    /// Not derived from `supply_net.is_empty()`: an intent file that declares
    /// domains but no supply on this block is a different situation from no
    /// intent file.
    pub declared: bool,

    /// Declared supply nets, ascending — the binary searches below stand on it.
    pub supply_net: Vec<NetId>,
    pub supply_domain: Vec<DomainId>,
    pub supply_role: Vec<SupplyRole>,
    /// Nominal voltage of each supply net's domain.
    pub supply_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,

    /// Nets with declared limits, ascending. Not disjoint from `supply_net`.
    pub limit_net: Vec<NetId>,
    pub limit: Vec<NetLimits>,

    /// Names that intent declared and extraction produced no net for.
    ///
    /// Not an error, but reported: "checked, clean" on a supply that does not
    /// exist in this layout is false confidence.
    pub undeclared: Vec<gpurify_ingest::StrId>,
}

impl IntentMap {
    /// Whether a net is a declared supply, and in which role and domain.
    pub fn supply_of(&self, net: NetId) -> Option<(DomainId, SupplyRole)> {
        let row = self.supply_row(net)?;
        Some((self.supply_domain[row], self.supply_role[row]))
    }

    /// The nominal voltage of a declared supply net.
    pub fn nominal_voltage(&self, net: NetId) -> Option<Qty<Voltage, { prefix::MILLI }>> {
        self.supply_row(net).map(|row| self.supply_voltage[row])
    }

    /// The limits declared for a net. All-`None` when undeclared, which means
    /// *not checked* and never *unlimited*.
    pub fn limits_of(&self, net: NetId) -> NetLimits {
        debug_assert_eq!(
            self.limit_net.len(),
            self.limit.len(),
            "a limit lost its net, or a net lost its limit"
        );
        self.limit_net
            .binary_search(&net)
            .map_or_else(|_| NetLimits::default(), |row| self.limit[row])
    }

    pub fn supply_count(&self) -> usize {
        debug_assert_eq!(self.supply_net.len(), self.supply_domain.len());
        debug_assert_eq!(self.supply_net.len(), self.supply_role.len());
        debug_assert_eq!(self.supply_net.len(), self.supply_voltage.len());
        self.supply_net.len()
    }

    /// True when there is something here for an intent-dependent rule to check
    /// against; false means no intent file, or one that named no net this
    /// layout has.
    ///
    /// True means *run*. Inverting the sense turns six unchecked rules into six
    /// clean ones.
    pub fn is_usable(&self) -> bool {
        // Both columns, not just the supplies: per-net limits with no supply
        // among them are still something to check against.
        self.declared && !(self.supply_net.is_empty() && self.limit_net.is_empty())
    }

    /// The row a declared supply net sits on.
    fn supply_row(&self, net: NetId) -> Option<usize> {
        debug_assert_eq!(self.supply_net.len(), self.supply_domain.len());
        debug_assert_eq!(self.supply_net.len(), self.supply_role.len());
        debug_assert_eq!(self.supply_net.len(), self.supply_voltage.len());
        debug_assert!(
            self.supply_net.windows(2).all(|pair| pair[0] < pair[1]),
            "the supply column is documented ascending, which is what this \
             binary search stands on"
        );
        self.supply_net.binary_search(&net).ok()
    }
}

/// Re-key design intent onto extracted nets.
///
/// Caller owns `out`, cleared and refilled. `intent` of `None` produces an
/// empty map with `declared == false`, which is how six rules report skipped
/// instead of clean.
pub fn resolve_intent_into(
    intent: Option<&DesignIntent>,
    ports: &PortTable,
    nets: &NetTable,
    out: &mut IntentMap,
) {
    debug_assert!(
        ports.len() <= nets.net_count(),
        "the port table names more nets than the extraction produced, so a \
         name would be re-keyed onto a net that is not there"
    );
    debug_assert!(
        u32::try_from(nets.net_count()).is_ok(),
        "a NetId is a u32, so the net count fits one"
    );

    // Cleared first: a stale supply row is a rule checking a net that is not
    // there, which reports clean.
    out.declared = false;
    out.supply_net.clear();
    out.supply_domain.clear();
    out.supply_role.clear();
    out.supply_voltage.clear();
    out.limit_net.clear();
    out.limit.clear();
    out.undeclared.clear();

    let Some(intent) = intent else {
        // `declared` stays false and the map stays empty: the six gated rules
        // read that and record themselves skipped.
        return;
    };

    out.declared = !intent.is_empty();

    // O(nets) to reach the hundreds that carry a name: neither end of the join
    // can be enumerated through `PortTable` or `DesignIntent`.
    let net_count = u32::try_from(nets.net_count()).expect("a NetId is a u32, so the count fits");
    for row in 0..net_count {
        let net = NetId(row);
        let Some(name) = ports.name_of(net) else {
            continue;
        };

        if let Some((domain, role)) = intent.supply_role(name) {
            out.supply_net.push(net);
            out.supply_domain.push(domain);
            out.supply_role.push(role);
            out.supply_voltage.push(intent.domain_voltage(domain));
        }

        let limits = intent.limits(name);
        // All-`None` is what `limits_of` answers for an absent row anyway.
        if limits.max_drop.is_some()
            || limits.max_drop_fraction.is_some()
            || limits.max_overvoltage.is_some()
            || limits.budget_current_ua.is_some()
        {
            out.limit_net.push(net);
            out.limit.push(limits);
        }
    }

    // KNOWN FAIL-OPEN: `undeclared` is left empty, so a declared supply the
    // layout never labelled is silently absent instead of reported. The set
    // difference needs the names `DesignIntent` declared, and it exposes no way
    // to enumerate them; the fix is a `supply_names() -> &[StrId]` accessor on
    // `ingest`.

    debug_assert_eq!(
        out.supply_net.len(),
        out.supply_voltage.len(),
        "a supply lost its voltage"
    );
    debug_assert_eq!(out.limit_net.len(), out.limit.len(), "a limit lost its net");
    debug_assert_eq!(
        out.supply_net.len(),
        out.supply_domain.len(),
        "a supply lost its domain"
    );
    debug_assert_eq!(
        out.supply_net.len(),
        out.supply_role.len(),
        "a supply lost its role"
    );
    debug_assert!(
        out.supply_net.len() <= nets.net_count() && out.limit_net.len() <= nets.net_count(),
        "the re-keying produced more rows than there are nets to key them onto"
    );
    debug_assert!(
        out.supply_net.windows(2).all(|pair| pair[0] < pair[1])
            && out.limit_net.windows(2).all(|pair| pair[0] < pair[1]),
        "both columns are documented ascending, which walking net ids in order \
         is what guarantees"
    );
}
