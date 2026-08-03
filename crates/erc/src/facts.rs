//! Two tables computed once per run and read by most of the rules.
//!
//! Both exist for the same reason `GeometryStore` precomputes a bounding box
//! per polygon: the answer is wanted by many consumers, it is one linear pass
//! to produce, and recomputing it inside each consumer is the mistake that
//! turns a linear rule into a quadratic one.
//!
//! [`NetFacts`] answers *what is attached to this net* without walking the
//! device table again. [`IntentMap`] answers *what did the design owner say
//! about this net*, re-keyed from interned names to [`NetId`] so no rule holds
//! a [`StrId`] in a loop.
//!
//! [`StrId`]: gpurify_ingest::StrId
//!
//! # `IntentMap` is where the skip decision is made
//!
//! Six rules cannot run without design intent. Each of them could test
//! `intent.is_none()` itself; then there would be six places for that test to
//! be wrong, and getting it wrong means an unchecked design reported clean.
//! Instead the `Option` is resolved exactly once, here, into
//! [`IntentMap::declared`] — and a rule reading a `false` there has one thing
//! to do, which is record itself skipped.

use gpurify_ingest::intent::{DesignIntent, DomainId, NetLimits, SupplyRole};
use gpurify_topology::{DeviceTable, NetId, NetTable, PortTable, TerminalRole};
use gpurify_units::{prefix, Qty, Voltage};

/// Which terminal roles are present on a net, as a bit per role.
///
/// Eight roles, eight bits, one byte per net. A `Vec<RoleMask>` over a
/// million-net design is a megabyte scanned linearly, which is what makes
/// "is this net a gate and nothing else" a load and a mask rather than a walk
/// over the device table.
///
/// [`TerminalRole::Pin`] collapses to one bit: the pin index of a symmetric
/// two-terminal device carries no electrical meaning by definition, and a rule
/// that needed to tell pin 0 from pin 1 would be asking the wrong question.
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

    /// Nothing attached. The state of a net no device touches, which is what
    /// `unconnected_pin` looks for.
    pub const NONE: Self = Self(0);

    /// Every role. `mask != NONE` is "device-connected", the question the old
    /// tree got wrong by consulting only the MOS list, so that a block of BJTs
    /// or resistors read as entirely unconnected.
    pub const ANY: Self = Self(0xFF);

    /// The bit for one terminal role.
    ///
    /// **Decision** — one small value in, one out, pure, and the single place
    /// the role-to-bit mapping is written down.
    pub const fn of(role: TerminalRole) -> Self {
        todo!()
    }

    /// True when every bit of `other` is set in `self`.
    pub const fn contains(self, other: Self) -> bool {
        todo!()
    }

    /// True when the two masks share at least one bit.
    pub const fn intersects(self, other: Self) -> bool {
        todo!()
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        todo!()
    }

    /// `self` with every bit of `other` cleared.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        todo!()
    }

    pub const fn is_empty(self) -> bool {
        todo!()
    }
}

/// What is attached to each net.
///
/// **Five questions.** In: a [`DeviceTable`]'s terminal columns. Out: one
/// [`RoleMask`] and one device count per net. How many: one row per net, so
/// hundreds of thousands. Access pattern: written once in terminal order, then
/// read by net id, randomly, by six rules — a dense array indexed by [`NetId`],
/// never a map. Lifetime: whole run, rebuilt per extraction into the caller's
/// buffer. Parallelisable: the fold is a per-net `or`, so it partitions by
/// terminal range with a merge, but at one byte per net it is not worth
/// splitting.
///
/// `device_count` is separate from the mask rather than derived from it because
/// `multiple_drivers` needs *how many*, not *whether* — and a net with two
/// drains and a net with one are the same mask.
#[derive(Debug, Default)]
pub struct NetFacts {
    /// Roles present on each net, indexed by [`NetId`].
    pub role: Vec<RoleMask>,
    /// Terminals attached to each net, saturating at [`u32::MAX`]. Counts
    /// terminals, not devices: a device with source and drain on one net
    /// contributes two.
    pub terminals: Vec<u32>,
}

impl NetFacts {
    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        todo!()
    }

    /// The roles on one net. [`RoleMask::NONE`] for a net no device touches.
    pub fn role_of(&self, net: NetId) -> RoleMask {
        todo!()
    }

    /// True when any device terminal at all lands on this net.
    ///
    /// The question five rules ask, and the one the old tree answered by
    /// scanning the MOS device list alone — which reported every net in a
    /// BJT-only or passive-only block as unconnected.
    pub fn is_device_connected(&self, net: NetId) -> bool {
        todo!()
    }
}

/// Fold every device terminal into its net's role mask.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled to
/// `nets.net_count()` rows. One pass over the flat terminal columns; each
/// terminal contributes an `or` into one row, so row order does not matter and
/// the pass is a scatter-reduce rather than a per-net gather.
///
/// This is the "two passes instead of one" case from the kernel rule read from
/// the other side: six rules each doing their own gather is six passes, and
/// this is the one that replaces them.
pub fn classify_nets_into(nets: &NetTable, devices: &DeviceTable, out: &mut NetFacts) {
    todo!()
}

/// Design intent, re-keyed from interned names onto extracted nets.
///
/// **Five questions.** In: a [`DesignIntent`] and a [`PortTable`]. Out: the
/// same declarations addressed by [`NetId`]. How many: tens of supplies and
/// hundreds of limited nets in a design with hundreds of thousands of nets —
/// two orders of magnitude sparser than the net table, so this is a pair of
/// sorted lists and a binary search, not a dense column. Access pattern:
/// read-only after construction, looked up by net id. Lifetime: whole run.
/// Parallelisable: read-only.
///
/// Existence-based: a net that is not a declared supply has no row here, rather
/// than a row holding `None`. The `declared` flag is the one deliberate
/// exception, and it is a claim about the run, not about a net.
#[derive(Debug, Default)]
pub struct IntentMap {
    /// **False when no design intent was supplied at all.**
    ///
    /// The six intent-dependent rules read this and nothing else before
    /// deciding to record [`Skipped`]. Not derived from `supply_net.is_empty()`
    /// — an intent file that declares domains but no supply on this block is a
    /// different situation from no intent file, and only one of the two is the
    /// user forgetting to pass `--intent`.
    ///
    /// [`Skipped`]: gpurify_report::Outcome::Skipped
    pub declared: bool,

    /// Declared supply nets, ascending. Binary search, so the lookup is
    /// deterministic and needs no hash.
    pub supply_net: Vec<NetId>,
    pub supply_domain: Vec<DomainId>,
    pub supply_role: Vec<SupplyRole>,
    /// Nominal voltage of each supply net's domain, copied here so the power
    /// extraction does not need the [`DesignIntent`] as well.
    pub supply_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,

    /// Nets with declared limits, ascending. Disjoint from nothing — a supply
    /// net usually has limits too.
    pub limit_net: Vec<NetId>,
    pub limit: Vec<NetLimits>,

    /// Names that intent declared and extraction produced no net for.
    ///
    /// Not an error: a block-level run legitimately sees only some of a chip's
    /// supplies. It **is** reported, because "checked, clean" on a supply that
    /// does not exist in this layout is the same false confidence as a skipped
    /// rule pretending to be clean.
    pub undeclared: Vec<gpurify_ingest::StrId>,
}

impl IntentMap {
    /// Whether a net is a declared supply, and in which role and domain.
    pub fn supply_of(&self, net: NetId) -> Option<(DomainId, SupplyRole)> {
        todo!()
    }

    /// The nominal voltage of a declared supply net.
    pub fn nominal_voltage(&self, net: NetId) -> Option<Qty<Voltage, { prefix::MILLI }>> {
        todo!()
    }

    /// The limits declared for a net. All-`None` when undeclared, which means
    /// *not checked* and never *unlimited*.
    pub fn limits_of(&self, net: NetId) -> NetLimits {
        todo!()
    }

    pub fn supply_count(&self) -> usize {
        todo!()
    }

    /// True when there is nothing here for an intent-dependent rule to check
    /// against — no intent file, or one that named no net this layout has.
    ///
    /// The precondition of every intent-gated transform in [`crate::rules`].
    pub fn is_usable(&self) -> bool {
        todo!()
    }
}

/// Re-key design intent onto extracted nets.
///
/// **Transform, A-to-B.** Caller owns `out`, cleared and refilled. `intent` is
/// `None` when the run was given no intent file; that produces an empty map
/// with `declared == false`, which is the whole mechanism by which six rules
/// report skipped instead of clean.
///
/// Every declared name is looked up through `ports`, so a supply that the
/// layout never labelled lands in [`IntentMap::undeclared`] rather than being
/// silently dropped.
pub fn resolve_intent_into(
    intent: Option<&DesignIntent>,
    ports: &PortTable,
    nets: &NetTable,
    out: &mut IntentMap,
) {
    todo!()
}
