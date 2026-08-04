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
        // A closed eight-arm match over a payload enum, every arm a constant:
        // the discriminant *is* the table index, so this lowers to one load
        // rather than a chain of compares. `Pin(_)` discards the index because
        // the two ends of a symmetric device are interchangeable by definition
        // — shifting by the index would put `Pin(3)` on the drain bit.
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
        // The same guard, and the same argument, as `DeviceTable::devices_on`:
        // `NetId::NONE` is an absence rather than a net, so nothing is attached
        // to it. Not a bulk branch — one compare per query, and the taken side
        // would otherwise index at `u32::MAX`.
        if net == NetId::NONE {
            return RoleMask::NONE;
        }
        // Fail closed, as `NetTable::net_of` does: a net id this table never
        // saw panics in every profile rather than reading as unconnected. "No
        // device touches this net" and "this net is not in this extraction"
        // must not answer the same, or a rule exempts a net nobody classified.
        debug_assert_eq!(self.role.len(), self.terminals.len());
        self.role[net.idx()]
    }

    /// True when any device terminal at all lands on this net.
    ///
    /// The question five rules ask, and the one the old tree answered by
    /// scanning the MOS device list alone — which reported every net in a
    /// BJT-only or passive-only block as unconnected.
    pub fn is_device_connected(&self, net: NetId) -> bool {
        // Every family, not just MOS: the mask was folded from the flat
        // terminal column, so a block of resistors reads as connected here
        // where the old tree's MOS-list scan reported all of it floating.
        !self.role_of(net).is_empty()
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
    debug_assert_eq!(
        devices.terminal_net.len(),
        devices.terminal_role.len(),
        "a net column and a role column arrive parallel"
    );

    // One row per net plus a scrap row on the end. A terminal carrying
    // `NetId::NONE` — or any id past this extraction — clamps onto the scrap
    // row instead of taking a branch, and the row is dropped before the caller
    // ever sees it. That is the sentinel-object idiom: the fold body runs
    // unconditionally, and no terminal's roles can leak onto a real net.
    let scrap = nets.net_count();
    out.role.clear();
    out.role.resize(scrap + 1, RoleMask::NONE);
    out.terminals.clear();
    out.terminals.resize(scrap + 1, 0);

    // Scalar by rule, not by omission. The output index is `terminal_net[i]`,
    // so this is a scatter-accumulate: two terminals can land on the same net,
    // which makes it unvectorisable without lane-conflict detection. Access to
    // `out.role` is random rather than contiguous for the same reason. The loop
    // is the intended form and there is nothing to upgrade.
    //
    // The gather reading is worse, not better: a per-net fold would have to
    // walk `devices_on(net)` and re-read every terminal of each device to find
    // the ones landing back on `net` — other rows, nested, for the same answer.
    for (&net, &role) in devices.terminal_net.iter().zip(&devices.terminal_role) {
        let row = net.idx().min(scrap);
        out.role[row] = out.role[row].union(RoleMask::of(role));
        // Saturating, per the column's doc: a net with four billion terminals
        // is a broken extraction, and wrapping to zero would report it clean.
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
        // `binary_search` on an empty column is `Err(0)`, so this is total for
        // any net — including one on a design that declared nothing.
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
        // The default is all-`None`, which every reader treats as *not checked*
        // rather than *unlimited*. That is the whole reason this returns a
        // `NetLimits` and not an `Option<NetLimits>`.
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

    /// True when there **is** something here for an intent-dependent rule to
    /// check against. False means no intent file, or one that named no net this
    /// layout has.
    ///
    /// The precondition of every intent-gated transform in [`crate::rules`]:
    /// each of the six records [`Skipped`]`(`[`NoDesignIntent`]`)` when this is
    /// false, and runs when it is true. The sense is the name's, not its
    /// negation — an implementation that inverts it turns six unchecked rules
    /// into six clean ones.
    ///
    /// [`Skipped`]: gpurify_report::Outcome::Skipped
    /// [`NoDesignIntent`]: gpurify_report::SkipReason::NoDesignIntent
    pub fn is_usable(&self) -> bool {
        // The sense is the name's: true means *run*. Read `declared` first —
        // it is the one fact that distinguishes "no intent file" from "an
        // intent file naming nothing this layout has" — then require that
        // something survived the re-keying, because a rule handed two empty
        // columns examines nothing and would report that as clean.
        //
        // Both columns, not just the supplies: a declaration of per-net limits
        // with no supply among them is still something to check against, the
        // same argument `DesignIntent::is_empty` makes on the other side.
        self.declared && !(self.supply_net.is_empty() && self.limit_net.is_empty())
    }

    /// The row a declared supply net sits on.
    ///
    /// **Decision** — one id in, one row out, and the single place the sorted
    /// supply column is searched, so `supply_of` and `nominal_voltage` cannot
    /// disagree about which row a net is.
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
    debug_assert!(
        ports.len() <= nets.net_count(),
        "the port table names more nets than the extraction produced, so a \
         name would be re-keyed onto a net that is not there"
    );
    debug_assert!(
        u32::try_from(nets.net_count()).is_ok(),
        "a NetId is a u32, so the net count fits one"
    );

    // Cleared before anything else, so a reused map cannot carry the previous
    // extraction's supplies into this one. A stale supply row is a rule
    // checking a net that is not there, which reports clean.
    out.declared = false;
    out.supply_net.clear();
    out.supply_domain.clear();
    out.supply_role.clear();
    out.supply_voltage.clear();
    out.limit_net.clear();
    out.limit.clear();
    out.undeclared.clear();

    let Some(intent) = intent else {
        // No intent file. `declared` stays false and the map stays empty, which
        // is exactly what the six gated rules read before recording themselves
        // skipped.
        return;
    };

    // `is_empty` is ingest's own "nobody wrote one", and its doc states that a
    // file with all three sections empty is the same verdict as no file at all.
    // A file declaring domains but no supply on this block is *not* empty by
    // that definition, so the distinction this flag exists for survives.
    out.declared = !intent.is_empty();

    // This walks every extracted net — hundreds of thousands, each costing a
    // binary search in `name_of` — to reach the hundreds that carry a name.
    // Not a shortcut: `PortTable` exposes `name_of(NetId)`, `net_of(StrId)`,
    // `len` and nothing that iterates its rows, and `DesignIntent` keeps every
    // declared-name column private behind `StrId`-taking accessors. Neither end
    // of the join can be enumerated, so O(nets) is the only shape reachable
    // from this signature. Recorded in `docs/SIGNATURE_DEFECTS.md` under
    // "erc/facts.rs" as the performance entry; resolving it wants either
    // `ports.rows() -> (&[NetId], &[StrId])` on `topology` or `supply_names()`
    // on `ingest`, and both are signature changes rather than Phase-4 ones.
    //
    // Scalar, and doubly so: the output is a compact that keeps a payload the
    // predicate computed (the domain, role and voltage the lookup returned),
    // written across six columns, and the predicate itself is two binary
    // searches. Neither the payload nor the searches survive if-conversion.
    let net_count = u32::try_from(nets.net_count()).expect("a NetId is a u32, so the count fits");
    for row in 0..net_count {
        let net = NetId(row);
        // Escape valve: heavily biased and so predicted — named nets are
        // hundreds out of hundreds of thousands — and the taken side is two
        // binary searches and up to six pushes, which is exactly the expensive
        // work a branch exists to skip.
        let Some(name) = ports.name_of(net) else {
            continue;
        };

        // Same valve: a declared supply is rarer still than a named net.
        if let Some((domain, role)) = intent.supply_role(name) {
            out.supply_net.push(net);
            out.supply_domain.push(domain);
            out.supply_role.push(role);
            // Copied off the domain here so no rule needs the `DesignIntent`
            // as well as the map.
            out.supply_voltage.push(intent.domain_voltage(domain));
        }

        let limits = intent.limits(name);
        // All-`None` is what `limits_of` already answers for an absent row, so
        // storing one would be a row that says nothing. Same valve again.
        if limits.max_drop.is_some()
            || limits.max_drop_fraction.is_some()
            || limits.max_overvoltage.is_some()
            || limits.budget_current_ua.is_some()
        {
            out.limit_net.push(net);
            out.limit.push(limits);
        }
    }

    // FAIL-OPEN, KNOWN, AND UNFIXABLE FROM THIS SIGNATURE. `undeclared` is left
    // empty, so a declared supply the layout never labelled is silently absent
    // instead of reported. Intent naming VDD and VSS against a layout labelling
    // only VDD leaves `is_usable` true, the six gated rules run, and every one
    // of them reports clean about a rail nothing checked — the false-clean this
    // module's header says it exists to prevent, in the one column meant to
    // catch it.
    //
    // It is not a simplification. The set difference needs the names
    // `DesignIntent` declared, and every one of its columns is private behind
    // accessors that take a `StrId` and answer about it; `ports` yields only the
    // names that *did* resolve, which is the wrong side of the difference. There
    // is no source of the missing `StrId`s in `(intent, ports, nets, out)`.
    //
    // Nor is the count reachable as a proxy: `DesignIntent` publishes
    // `domain_count` but no supply count, and while its loader refuses a domain
    // with no supply, a domain that keeps one labelled supply and loses another
    // is invisible to a per-domain count. `docs/NEED_TESTING.md` records that
    // this column has no test at all, for the same reason.
    //
    // Fix is an enumerating accessor on `DesignIntent` — `supply_names() ->
    // &[StrId]` is enough, and this transform would then drive the join off it
    // through the `PortTable::net_of` that already exists, pushing every name
    // that misses into `undeclared`. That is an `ingest` signature change, not a
    // Phase-4 one. Recorded in `docs/SIGNATURE_DEFECTS.md` under "erc/facts.rs"
    // as the correctness entry.

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
