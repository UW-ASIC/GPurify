//! Two tables computed once per run and read by most rules.
//!
//! Data in: nets, devices, ports, and the optional design intent.
//! Data out: [`NetFacts`] (roles per net), [`IntentMap`] (intent keyed by
//! [`NetId`]) and [`NetTypes`] (the intent's net types per net);
//! [`IntentMap::is_usable`] is the one skip decision.

use crate::topology::{DeviceTable, NetId, NetTable, PortTable, TerminalRole};
use gpurify_geom::{prefix, Qty, Voltage};
use gpurify_ingest::intent::{DesignIntent, DomainId, NetLimits, NetTypeBy, SupplyRole};
use gpurify_ingest::{StrId, StrTable};

/// Which terminal roles are present on a net, one bit per role. Every
/// `Pin(_)` is one bit: a symmetric device's pin index carries no meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct RoleMask(pub u8);

impl RoleMask {
    /// A MOS gate.
    pub const GATE: Self = Self(1 << 0);
    /// A MOS source, as extraction assigns it: by terminal order, not by
    /// circuit function.
    pub const SOURCE: Self = Self(1 << 1);
    /// A MOS drain, as extraction assigns it: by terminal order, not by
    /// circuit function.
    pub const DRAIN: Self = Self(1 << 2);
    /// A MOS bulk (body).
    pub const BULK: Self = Self(1 << 3);
    /// A bipolar base.
    pub const BASE: Self = Self(1 << 4);
    /// A bipolar emitter.
    pub const EMITTER: Self = Self(1 << 5);
    /// A bipolar collector.
    pub const COLLECTOR: Self = Self(1 << 6);
    /// Any pin of a resistor, capacitor or diode, whatever its index.
    pub const PIN: Self = Self(1 << 7);
    /// No terminal: a net no device touches.
    pub const NONE: Self = Self(0);

    /// The one bit for `role`; every `Pin(_)` maps to [`Self::PIN`].
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

    pub(crate) const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// The bits set in either mask.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// True when no bit is set: no device terminal on the net.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Roles present on each net, indexed by [`NetId`].
#[derive(Debug, Default)]
pub struct NetFacts {
    /// One mask per net of the extraction [`classify_nets_into`] was given.
    pub role: Vec<RoleMask>,
}

impl NetFacts {
    /// The number of nets classified.
    pub fn len(&self) -> usize {
        self.role.len()
    }

    /// True when no net was classified, as for a design never extracted.
    pub fn is_empty(&self) -> bool {
        self.role.is_empty()
    }

    /// True when any device terminal lands on this net. `NetId::NONE` is
    /// false; any other id past the table panics.
    pub fn is_device_connected(&self, net: NetId) -> bool {
        net != NetId::NONE && !self.role[net.idx()].is_empty()
    }
}

/// Folds every device terminal into its net's role mask; `out` is refilled to
/// `nets.net_count()` rows. A terminal on no net, or on a net past `nets`, is
/// dropped.
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
    /// Parallel to `supply_net`: power or ground.
    pub supply_role: Vec<SupplyRole>,
    /// The domain each supply net belongs to.
    pub supply_domain: Vec<DomainId>,
    /// Nominal voltage of each supply net's domain.
    pub supply_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Nets with declared limits, ascending. Not disjoint from `supply_net`.
    pub limit_net: Vec<NetId>,
    /// Parallel to `limit_net`: the limits as the intent states them, at
    /// least one of them set.
    pub limit: Vec<NetLimits>,
}

impl IntentMap {
    /// A declared supply net's role and its domain's nominal voltage.
    pub fn supply(&self, net: NetId) -> Option<(SupplyRole, Qty<Voltage, { prefix::MILLI }>)> {
        let row = self.supply_net.binary_search(&net).ok()?;
        Some((self.supply_role[row], self.supply_voltage[row]))
    }

    /// The voltage a declared supply net is held at.
    pub fn nominal_voltage(&self, net: NetId) -> Option<Qty<Voltage, { prefix::MILLI }>> {
        let row = self.supply_net.binary_search(&net).ok()?;
        Some(self.held_at(row))
    }

    /// Supply row `row`'s voltage: its domain's nominal for power, zero for
    /// ground.
    pub fn held_at(&self, row: usize) -> Qty<Voltage, { prefix::MILLI }> {
        match self.supply_role[row] {
            SupplyRole::Power => self.supply_voltage[row],
            SupplyRole::Ground => Qty::new(0.0),
        }
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

/// One declared power state re-keyed onto extracted nets (see
/// [`PowerState`](gpurify_ingest::intent::PowerState)). A name no labelled
/// net carries is dropped, as for [`IntentMap`].
#[derive(Debug, Clone)]
pub struct StateMap {
    /// The state's name.
    pub name: gpurify_geom::StrId,
    /// Supply nets switched off in this state, ascending.
    pub off: Vec<NetId>,
    /// Nets held at a voltage in this state, ascending by net, and the
    /// voltage.
    pub input: Vec<(NetId, Qty<Voltage, { prefix::MILLI }>)>,
}

/// Every power state the intent declares, keyed onto extracted nets, in file
/// order; empty without intent or states.
pub fn resolve_states(
    intent: Option<&DesignIntent>,
    ports: &PortTable,
    nets: &NetTable,
) -> Vec<StateMap> {
    let Some(intent) = intent else {
        return Vec::new();
    };
    let net_count = u32::try_from(nets.net_count()).expect("a NetId is a u32, so the count fits");
    intent
        .states()
        .iter()
        .map(|state| {
            let mut map = StateMap {
                name: state.name,
                off: Vec::new(),
                input: Vec::new(),
            };
            for net in (0..net_count).map(NetId) {
                let Some(name) = ports.name_of(net) else {
                    continue;
                };
                if state.off.contains(&name) {
                    map.off.push(net);
                }
                if let Some(&(_, voltage)) = state.inputs.iter().find(|input| input.0 == name) {
                    map.input.push((net, voltage));
                }
            }
            map
        })
        .collect()
}

impl IntentMap {
    /// The supplies of power state `state`: every declared supply it does not
    /// switch off, and every net it holds, as a supply at that voltage (a
    /// ground at 0 V, otherwise a power supply of domain 0). A held net that
    /// is also a supply is held, not supplied. Limits are not carried.
    #[allow(
        clippy::float_cmp,
        reason = "exactly 0 V is a ground; any other voltage is held as power"
    )]
    pub fn in_state(&self, state: &StateMap) -> IntentMap {
        let held = |net: NetId| state.input.iter().any(|input| input.0 == net);
        let mut rows: Vec<(NetId, SupplyRole, DomainId, Qty<Voltage, { prefix::MILLI }>)> = (0
            ..self.supply_net.len())
            .filter(|&row| {
                let net = self.supply_net[row];
                state.off.binary_search(&net).is_err() && !held(net)
            })
            .map(|row| {
                (
                    self.supply_net[row],
                    self.supply_role[row],
                    self.supply_domain[row],
                    self.supply_voltage[row],
                )
            })
            .collect();
        for &(net, voltage) in &state.input {
            let role = if voltage.raw() == 0.0 {
                SupplyRole::Ground
            } else {
                SupplyRole::Power
            };
            rows.push((net, role, DomainId(0), voltage));
        }
        rows.sort_by_key(|row| row.0);
        IntentMap {
            declared: true,
            supply_net: rows.iter().map(|row| row.0).collect(),
            supply_role: rows.iter().map(|row| row.1).collect(),
            supply_domain: rows.iter().map(|row| row.2).collect(),
            supply_voltage: rows.iter().map(|row| row.3).collect(),
            limit_net: Vec::new(),
            limit: Vec::new(),
        }
    }

    /// This intent with each net's current budget replaced by `pick` of its
    /// limits (its RMS or its peak current), its frequency kept, and no
    /// other limit: the loads
    /// [`extract_into`](crate::erc::power::extract_into) spreads for an AC
    /// current rule. A net `pick` gives nothing carries no load.
    #[must_use]
    pub fn with_budget(&self, pick: impl Fn(&NetLimits) -> Option<f64>) -> IntentMap {
        let (limit_net, limit) = self
            .limit_net
            .iter()
            .zip(&self.limit)
            .filter_map(|(&net, limits)| {
                pick(limits).map(|current| {
                    (
                        net,
                        NetLimits {
                            budget_current_ua: Some(current),
                            frequency_mhz: limits.frequency_mhz,
                            ..NetLimits::default()
                        },
                    )
                })
            })
            .unzip();
        IntentMap {
            declared: self.declared,
            supply_net: self.supply_net.clone(),
            supply_role: self.supply_role.clone(),
            supply_domain: self.supply_domain.clone(),
            supply_voltage: self.supply_voltage.clone(),
            limit_net,
            limit,
        }
    }
}

/// Re-keys design intent onto extracted nets; `out` is cleared and refilled.
/// `None` leaves `declared == false`, which is how the intent rules report skipped.
///
/// A net is matched by its label name in `ports`. A supply or limit the
/// intent names but no labelled net carries is dropped without a report.
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
            out.supply_domain.push(domain);
            out.supply_voltage.push(intent.domain_voltage(domain));
        }
        let limits = intent.limits(name);
        if limits.max_drop.is_some()
            || limits.max_drop_fraction.is_some()
            || limits.max_overvoltage.is_some()
            || limits.budget_current_ua.is_some()
            || limits.rms_current_ua.is_some()
            || limits.peak_current_ua.is_some()
        {
            out.limit_net.push(net);
            out.limit.push(limits);
        }
    }
}

/// The design's net types (US20100306720A1's net types and type sets),
/// resolved onto extracted nets by [`resolve_net_types_into`].
#[derive(Debug, Default, Clone)]
pub struct NetTypes {
    /// Bit `i` of a mask is `name[i]`: the declared types, then the sets, in
    /// the intent's order. At most 64.
    pub name: Vec<StrId>,
    /// Per net, the types and sets it has; empty when the intent declares
    /// none.
    pub mask: Vec<u64>,
}

impl NetTypes {
    /// The bit of the type or set `name`, or `None` for a name the intent
    /// does not declare.
    pub fn bit(&self, name: StrId) -> Option<u64> {
        self.name.iter().position(|&n| n == name).map(|i| 1u64 << i)
    }

    /// The types and sets of `net`; none for a net past the table.
    pub fn of(&self, net: NetId) -> u64 {
        self.mask.get(net.idx()).copied().unwrap_or(0)
    }
}

/// Whether `text` matches `pattern` whole, a `?` in the pattern matching
/// zero or more characters (US20100306720A1 \[0201\]).
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    match pattern.split_first() {
        None => text.is_empty(),
        Some((b'?', rest)) => (0..=text.len()).any(|skip| glob(rest, &text[skip..])),
        Some((&c, rest)) => text.first() == Some(&c) && glob(rest, &text[1..]),
    }
}

/// The pin name a device-assigned net type lists for a terminal role.
fn pin_name(role: TerminalRole) -> &'static str {
    match role {
        TerminalRole::Gate => "g",
        TerminalRole::Source => "s",
        TerminalRole::Drain => "d",
        TerminalRole::Bulk | TerminalRole::Base => "b",
        TerminalRole::Emitter => "e",
        TerminalRole::Collector => "c",
        TerminalRole::Pin(0) => "pos",
        TerminalRole::Pin(1) => "neg",
        TerminalRole::Pin(_) => "",
    }
}

/// Assigns the intent's net types to extracted nets; `out` is cleared and
/// refilled, empty without intent or without a declared type.
///
/// A type by name marks every net whose label (its first, in `ports`)
/// matches one of its names, `lvsPower` and `lvsGround` marking the supplies
/// `supplies` resolved and `lvsOutline` every labelled net; a type by device
/// marks the nets on the listed pins of the listed models' devices. A set is
/// marked on a net with any of its members, in declaration order, so a set
/// may name an earlier set.
pub fn resolve_net_types_into(
    intent: Option<&DesignIntent>,
    ports: &PortTable,
    nets: &NetTable,
    devices: &DeviceTable,
    supplies: &IntentMap,
    strings: &StrTable,
    out: &mut NetTypes,
) {
    out.name.clear();
    out.mask.clear();
    let Some(intent) = intent.filter(|i| !i.net_types().is_empty()) else {
        return;
    };
    for net_type in intent.net_types() {
        if !out.name.contains(&net_type.name) {
            out.name.push(net_type.name);
        }
    }
    out.name
        .extend(intent.type_sets().iter().map(|set| set.name));
    debug_assert!(out.name.len() <= 64, "the intent caps types and sets at 64");
    let count = nets.net_count();
    out.mask.resize(count, 0);
    for net_type in intent.net_types() {
        let bit = out.bit(net_type.name).expect("a declared type has a bit");
        match &net_type.by {
            NetTypeBy::Names(patterns) => {
                for (net, mask) in (0u32..).map(NetId).zip(out.mask.iter_mut()) {
                    let label = ports.name_of(net);
                    let role = supplies.supply(net).map(|(role, _)| role);
                    let hit = patterns.iter().any(|pattern| match pattern.as_str() {
                        "lvsPower" => role == Some(SupplyRole::Power),
                        "lvsGround" => role == Some(SupplyRole::Ground),
                        "lvsOutline" => label.is_some(),
                        _ => label.is_some_and(|name| {
                            glob(pattern.as_bytes(), strings.resolve(name).as_bytes())
                        }),
                    });
                    if hit {
                        *mask |= bit;
                    }
                }
            }
            NetTypeBy::Devices {
                models,
                negate,
                pins,
            } => {
                for device in 0..devices.len() {
                    if models.contains(&devices.model[device]) == *negate {
                        continue;
                    }
                    let id = crate::topology::DeviceId(
                        u32::try_from(device).expect("a device id is a u32"),
                    );
                    let (nets, roles) = devices.terminals_of(id);
                    for (&net, &role) in nets.iter().zip(roles) {
                        let listed = pins.is_empty() || pins.iter().any(|p| p == pin_name(role));
                        if listed && net.idx() < count {
                            out.mask[net.idx()] |= bit;
                        }
                    }
                }
            }
        }
    }
    for set in intent.type_sets() {
        let bit = out.bit(set.name).expect("a declared set has a bit");
        let members = set
            .types
            .iter()
            .filter_map(|&member| out.bit(member))
            .fold(0, |all, b| all | b);
        for mask in &mut out.mask {
            if *mask & members != 0 {
                *mask |= bit;
            }
        }
    }
}
