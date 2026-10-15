//! Rules over the voltages each net can reach ([`NetVoltage`]).
//!
//! Data in: devices, design intent, the propagated voltages. Data out:
//! violations at device markers and one run per row. All but `well_sharing`
//! skip without intent.
//! A device whose measured terminals no supply reaches is not examined.

use crate::erc::facts::IntentMap;
use crate::erc::ruleset::RuleHead;
use crate::erc::voltage::{is_channel, NetVoltage};
use crate::erc::{first_vertex, record_run, skip_rows, Design};
use crate::report::{LimitSense, Measurement, Outcome, RuleRun, Severity, Violation, Violations};
use crate::topology::device::{DeviceMeasure, DeviceParam};
use crate::topology::{DeviceId, NetId, TerminalRole};
use gpurify_geom::{prefix, Dbu, LayerId, Qty, Voltage};
use gpurify_ingest::deck::DeviceKind;
use gpurify_ingest::intent::SupplyRole;
use gpurify_ingest::StrId;

/// Device models and one voltage limit per row: `gate_oxide` and `drain_source`.
///
/// Two deck kinds share this table type, one table each in
/// [`RuleSet`](crate::erc::RuleSet): `gate_oxide(; models: models, max:
/// voltage)` and `drain_source(; models: models, max: voltage)`. Both
/// compare, for every device of a listed model, the largest voltage two of
/// its terminals can reach apart with `max`. Each net's reachable range comes
/// from the declared supplies ([`NetVoltage`]), and `|V(a) - V(b)|` is worst
/// case: the top of one range minus the bottom of the other. What each kind
/// measures, and who defines it, is on [`check_gate_oxide`] and
/// [`check_drain_source`].
///
/// # Limits
///
/// A net's range is the span of every supply it reaches through a device
/// channel that can conduct: a transistor whose deck row states a gate
/// condition only while its gate allows it, any other channel always
/// ([`propagate_into`](crate::erc::voltage::propagate_into)). Threshold
/// drops and power-down are ignored, so this can over-report. A net no
/// supply reaches that way, such as a primary input
/// with no ESD diode, is not checked, and neither is a device whose measured
/// terminals sit on such nets. The shipped decks state the operating
/// voltages the PDKs document, not an absolute maximum rating.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ModelLimitTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Models each row applies to, CSR.
    pub model_start: Vec<u32>,
    /// Device model names, CSR by `model_start`; at least one per row.
    pub model: Vec<StrId>,
    /// Per row: the largest allowed terminal-to-terminal voltage, mV.
    /// Positive from a deck.
    pub max_voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
}

/// Well and body bias: deck kind `well_bias`, written
/// `well_bias(; pmos: models | none, nmos: models | none)`.
///
/// Which MOS models sit in an n-well (bulk must be highest) and which on the
/// p-substrate (bulk must be lowest). A row flags a `pmos` device whose
/// source or drain can rise above the lowest voltage its bulk can sit at, and
/// an `nmos` device whose source or drain can fall below the highest voltage
/// its bulk can sit at: a junction that can forward-bias, injecting into the
/// substrate and risking latch-up. Ranges come from the declared supplies
/// ([`NetVoltage`]). A row must name at least one model.
///
/// # Limits
///
/// Only transistors are checked, not guard rings (ERC-D3). A device needs a
/// bulk terminal on a net, and of the shipped decks only sky130 connects
/// wells as nets (ERC-F12). Ranges over-report as [`ModelLimitTable`]'s do.
///
/// Catalog: ERC-D3 (partial), ERC-F12 in the [check catalog]. Defined by
/// [GF180MCU] LU.9 and LU.10. Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct WellBiasTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// `pmos[pmos_start[i] .. pmos_start[i + 1]]` are row `i`'s n-well models.
    pub pmos_start: Vec<u32>,
    /// Models whose bulk must be the highest voltage, CSR by `pmos_start`.
    pub pmos: Vec<StrId>,
    /// `nmos[nmos_start[i] .. nmos_start[i + 1]]` are row `i`'s substrate
    /// models.
    pub nmos_start: Vec<u32>,
    /// Models whose bulk must be the lowest voltage, CSR by `nmos_start`.
    pub nmos: Vec<StrId>,
}

/// A missing level shifter: deck kind `missing_level_shifter`, written
/// `missing_level_shifter(; shifters: models | none)`.
///
/// Models allowed to take a gate from another power domain. A row flags a
/// transistor, not of a `shifters` model, whose gate is reached by a power
/// supply of a domain that reaches neither its source nor its drain: a signal
/// from one power domain driving a gate in another without a level shifter.
/// Reach is through device channels from the declared power supplies
/// ([`NetVoltage::power`]); a ground supply carries no domain here.
///
/// # Limits
///
/// Ranges over-report as [`ModelLimitTable`]'s do, and a gate or channel no
/// power supply reaches is not checked. It reads every supply on: isolation
/// at switchable-domain outputs (ERC-F7) and gates undriven in a power state
/// (ERC-F8) are [`MissingIsolationTable`]'s and [`UndrivenGateTable`]'s. This
/// is a functional check, not ESD protection of a domain crossing (ERC-C4).
///
/// Catalog: ERC-F6 in the [check catalog]. Defined by Calibre PERC (white
/// paper 81822, public material only); [IEEE 1801] (UPF, cited for scope and
/// not read). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [IEEE 1801]: https://standards.ieee.org/ieee/1801/11890/
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MissingLevelShifterTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// `shifter[shifter_start[i] .. shifter_start[i + 1]]` are row `i`'s
    /// exempt models; a row may name none.
    pub shifter_start: Vec<u32>,
    /// Level-shifter models, exempt from the row; CSR by `shifter_start`.
    pub shifter: Vec<StrId>,
}

/// A DC path between power domains: deck kind `domain_crossing`, written
/// `domain_crossing()`.
///
/// A row flags a device whose channel (every terminal but gate and bulk; a
/// capacitor has none) is reached by power supplies of more than one domain:
/// a DC or sneak path that joins two power domains. Reach is through device
/// channels ([`NetVoltage::power`]), so every device touching a group of
/// channel-connected nets that two domains reach is flagged, not only the one
/// that joins them. Every row flags the same devices.
///
/// # Limits
///
/// A transistor whose deck row states no gate condition passes whatever its
/// gate, so it joins domains even when it is off, and this can over-report.
/// This is a functional check, not ESD
/// protection of a domain crossing (ERC-C4).
///
/// Catalog: ERC-F9 in the [check catalog]. Defined by Calibre PERC (datasheet
/// and white paper 81822, public material only). Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
#[derive(Debug, Default, Clone, PartialEq)]
pub struct DomainCrossingTable {
    /// Rule id and severity per row. Rows differ only in id and severity.
    pub head: RuleHead,
}

/// Voltage-dependent spacing: deck kind `voltage_spacing`, written
/// `voltage_space(L; voltage: [v, ..], space: [len, ..])`, or
/// `voltage_space(A, B; ..)` between two layers.
///
/// A row is a table of steps: from each step's `voltage` up, two shapes on
/// different nets need that step's `space`. A pair is held to the step with
/// the largest voltage its nets can reach apart, the worst case
/// [`NetVoltage::worst_delta`]: the top of one net's range minus the bottom
/// of the other's. A pair whose voltage difference is below the first step
/// needs nothing from the row. "From the step up" is inclusive: a difference
/// exactly at a step's voltage needs that step's space, and a gap exactly at
/// the space passes. On one layer the pairs are shapes in different merged
/// figures; across two layers every pair, overlap included (a distance of
/// 0), reported on the first layer. Ranges come from the declared supplies
/// ([`NetVoltage`]).
///
/// # Limits
///
/// Shapes on one net are not judged: they sit at one voltage, and same-net
/// spacing is `space(L; nets: same)`'s. A pair with a net no supply reaches
/// is not judged. Ranges over-report as [`ModelLimitTable`]'s do, so two
/// nets that only ever move together read their full swing apart. The
/// layers must be conductors, so a pair is judged on extracted nets, not on
/// marker or tag layers (sky130 hvnwell.8's HV n-well is the n-well under
/// `hvi`). A cut-to-metal variant (LEF58 `TOCUT ABOVE | BELOW`) is the
/// two-layer form with the cut layer named.
///
/// Catalog: DRC-082, ERC-F11 in the [check catalog]. Defined by
/// [LEF58_VOLTAGESPACING] (`VOLTAGESPACING [TOCUT [ABOVE | BELOW]]
/// {voltage spacing} ... ;`, as `OpenROAD` parses it); voltage-aware DRC in
/// Calibre, IC Validator, Pegasus and Empyrean (public product material
/// only: "different spacings based on ... the difference in voltages
/// between different geometries", Siemens Calibre blog, 2015); [SKY130]
/// hvnwell.8 ("Min space between HV_nwell and any nwell on different nets",
/// whose HV n-well is a tag, not a voltage). Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [LEF58_VOLTAGESPACING]: https://github.com/The-OpenROAD-Project/OpenROAD/blob/master/src/odb/src/lefin/lefTechLayerVoltageSpacing.cpp
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct VoltageSpacingTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer measured, and the one findings are reported on.
    pub layer: Vec<LayerId>,
    /// Per row: the second layer, `None` for spacing within `layer`.
    pub other: Vec<Option<LayerId>>,
    /// `voltage[step_start[i] .. step_start[i + 1]]` and the same range of
    /// `space` are row `i`'s steps; at least one per row.
    pub step_start: Vec<u32>,
    /// Each step's voltage, mV: zero or more, rising strictly within a row.
    pub voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
    /// Each step's spacing, database units: positive, never falling within a
    /// row.
    pub space: Vec<Dbu>,
}

/// The field across the dielectric between two nets: deck kind
/// `dielectric_field`, written `dielectric_field(L; max_field: f)`, or
/// `dielectric_field(A, B; max_field: f)` between two conductor layers.
///
/// Two shapes on different nets hold the dielectric between them at the
/// worst-case voltage their nets can reach apart ([`NetVoltage::worst_delta`]),
/// and the field across it is that voltage over their separation. A pair is
/// flagged when the field exceeds `max_field`: when the separation is below
/// `ΔV / max_field`. On one layer the separation is the lateral gap, between
/// shapes in different merged figures. Between two layers it is
/// `sqrt(gap² + t²)`, with `gap` the lateral gap (0 where the shapes
/// overlap in plan) and `t` the dielectric between the layers from the deck's
/// `pex` stack: the upper layer's height less the lower layer's height and
/// thickness. A finding reports the lateral gap against the least lateral
/// gap the voltage allows, `sqrt((ΔV / max_field)² - t²)` rounded up to the
/// database unit; a pair whose voltage the vertical dielectric alone holds
/// needs no gap.
///
/// # Limits
///
/// A field limit, not a lifetime: the time-dependent breakdown model of
/// JEP159A is not evaluated. Shapes on one net, and a net no supply reaches,
/// are not judged; ranges over-report as [`ModelLimitTable`]'s do. The
/// rounding up of the lateral limit can flag a corner-to-corner pair less than
/// one database unit inside it.
///
/// Catalog: ERC-F13 in the [check catalog]. Defined by JEDEC [JEP159A]
/// (low-k/metal inter- and intra-level dielectric integrity, abstract only);
/// Synopsys IC Validator's voltage-dependent checks (public product material
/// only). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [JEP159A]: https://www.jedec.org/standards-documents/docs/jep159a
#[derive(Debug, Default, Clone, PartialEq)]
pub struct DielectricFieldTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer measured, and the one findings are reported on.
    pub layer: Vec<LayerId>,
    /// Per row: the second layer, `None` for pairs within `layer`.
    pub other: Vec<Option<LayerId>>,
    /// Per row: the largest field the dielectric may carry, V/µm (equal to
    /// mV/nm). Positive from a deck.
    pub max_field: Vec<f64>,
    /// Per row: the dielectric between the two layers, nm, from the deck's
    /// stack; 0 for one layer, `None` when the stack does not state both
    /// layers or they overlap in height (the row is refused).
    pub vertical_nm: Vec<Option<f64>>,
}

/// High-voltage features tagged: deck kind `hv_tag`, written
/// `hv_tag(L, tag; voltage: v)`.
///
/// A merged figure of the conductor layer `L` whose net can reach `voltage`
/// or more ([`NetVoltage::hi`]) is a high-voltage feature, and must lie
/// entirely inside the `tag` layer, touching its edge from inside allowed
/// (as `inside(L, tag)` measures it). Because a net's range spans every
/// supply its channels can join it to, any layout shorted to a high-voltage
/// net, directly or through a conducting device, is a high-voltage feature
/// too. A figure's net is its lowest-numbered drawn polygon's.
///
/// # Limits
///
/// Voltage alone decides what is high-voltage: sky130's text tags
/// (`shv_nwell`, `hv_bb`, `hv_lv`, `lv_net`) are not read, and a net no
/// supply reaches is not judged. Ranges over-report as
/// [`ModelLimitTable`]'s do.
///
/// Catalog: DRC-083 in the [check catalog]. Defined by [SKY130] hv.X.1
/// ("High voltage source/drain regions must be tagged by diff:hv"), hv.X.4
/// ("Any piece of layout that is shorted to hv_source/drain becomes a high
/// voltage feature"), hv.X.6 (an n-well biased at 7.2 V or more is tagged)
/// and hvnwell.11 (an n-well on a high-voltage supply is enclosed by `hvi`).
/// Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct HvTagTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the conductor layer whose figures are judged.
    pub layer: Vec<LayerId>,
    /// Per row: the tag layer a high-voltage figure must lie inside.
    pub tag: Vec<LayerId>,
    /// Per row: the voltage from which a net is high-voltage, mV.
    pub voltage: Vec<Qty<Voltage, { prefix::MILLI }>>,
}

/// Gates left undriven in a power state: deck kind `undriven_gate`, written
/// `undriven_gate()`.
///
/// A row flags every net with a transistor gate on it that some supply
/// reaches with every supply on, but that none reaches in a power state the
/// intent declares (its switched-off supplies holding nothing, its inputs
/// held at their voltages, and gate-conditioned transistors switching on
/// the result, [`propagate_into`](crate::erc::voltage::propagate_into)): the
/// gate floats in that state. As the Calibre PERC white paper states it, "If
/// the EN pin of the tristate buffer is at zero volts, the output pin Y of
/// the tristate buffer has no definitive voltage value and becomes floating.
/// Subsequent gates connected to pin Y become un-driven". Every row flags
/// the same nets.
///
/// # Limits
///
/// Only the declared states are examined, never every combination of
/// inputs. A gate no supply reaches with every supply on (a primary input)
/// is `floating_gate`'s, not this rule's.
///
/// Catalog: ERC-F8 in the [check catalog]. Defined by Calibre PERC (white
/// paper 81822, "Finding un-driven gates", public material only); [IEEE
/// 1801] power states (cited for scope, not read); Siemens Insight Analyzer
/// (public material only). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [IEEE 1801]: https://standards.ieee.org/ieee/1801/11890/
#[derive(Debug, Default, Clone, PartialEq)]
pub struct UndrivenGateTable {
    /// Rule id and severity per row. Rows differ only in id and severity.
    pub head: RuleHead,
}

/// A floating input to a powered transistor in a power state: deck kind
/// `missing_isolation`, written `missing_isolation(; isolation: models |
/// none)`.
///
/// A row flags a transistor, not of an `isolation` model, whose gate some
/// supply reaches with every supply on but none reaches in a declared power
/// state (as [`UndrivenGateTable`] finds it), while a power supply still
/// reaches its source or drain in that state: a powered stage with a
/// floating input, which leaks statically and can switch at random. With a
/// switched-off domain driving the gate, this is the missing isolation cell
/// of IEEE 1801 at a switchable domain's output; an isolation cell's models
/// are exempt, since clamping its own floating input is its job.
///
/// # Limits
///
/// Only the declared states are examined. A stage is powered when a power
/// supply reaches its channel through conducting devices; a channel reached
/// only by grounds is not.
///
/// Catalog: ERC-F7, ERC-H1 in the [check catalog]. Defined by [IEEE 1801]
/// and Si2 CPF isolation (cited for scope, not read); Calibre PERC
/// (white paper 81822) and Siemens Insight Analyzer, static leakage through
/// floating inputs (public material only). Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [IEEE 1801]: https://standards.ieee.org/ieee/1801/11890/
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MissingIsolationTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// `isolation[isolation_start[i] .. isolation_start[i + 1]]` are row
    /// `i`'s exempt models; a row may name none.
    pub isolation_start: Vec<u32>,
    /// Isolation-cell models, exempt from the row; CSR by `isolation_start`.
    pub isolation: Vec<StrId>,
}

/// Row `row` of a CSR column; an empty column (no rows pushed) answers empty.
fn csr<'a>(start: &[u32], column: &'a [StrId], row: usize) -> &'a [StrId] {
    match (start.get(row), start.get(row + 1)) {
        (Some(&lo), Some(&hi)) => &column[lo as usize..hi as usize],
        _ => &[],
    }
}

/// The net on the first terminal with `role`, or `NetId::NONE`.
pub(crate) fn terminal(nets: &[NetId], roles: &[TerminalRole], role: TerminalRole) -> NetId {
    roles
        .iter()
        .position(|&r| r == role)
        .map_or(NetId::NONE, |at| nets[at])
}

pub(crate) fn device_id(index: usize) -> DeviceId {
    DeviceId(u32::try_from(index).expect("a device table indexes with u32"))
}

/// One violation at a device's marker polygon.
pub(crate) fn push_device(
    design: Design<'_>,
    device: usize,
    rule: StrId,
    severity: Severity,
    measured: Measurement,
    limit: Measurement,
    out: &mut Violations,
) {
    let marker = design.devices.marker[device];
    out.push(Violation {
        rule,
        layer: design.store.poly_layer(marker),
        severity,
        at: first_vertex(design.store, marker),
        measured,
        limit,
        shapes: (marker, None),
    });
}

/// Run `measure` over every device of the row's models; flag a result above
/// the row's limit, mV. `None` from `measure` is a device not examined.
fn check_model_limit(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &ModelLimitTable,
    measure: fn(&NetVoltage, &[NetId], &[TerminalRole]) -> Option<f64>,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let devices = design.devices;
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let limit = Measurement::Voltage(table.max_voltage[row]);
        let models = csr(&table.model_start, &table.model, row);
        let mut examined = 0u64;
        for device in 0..devices.len() {
            if !models.contains(&devices.model[device]) {
                continue;
            }
            let (nets, roles) = devices.terminals_of(device_id(device));
            let Some(delta) = measure(voltage, nets, roles) else {
                continue;
            };
            examined += 1;
            let measured = Measurement::Voltage(Qty::new(delta));
            if measured.violates(limit, LimitSense::Maximum) {
                let severity = table.head.severity[row];
                push_device(design, device, rule, severity, measured, limit, out);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Largest gate-to-source, -drain or -bulk voltage a device can see.
fn gate_stress(voltage: &NetVoltage, nets: &[NetId], roles: &[TerminalRole]) -> Option<f64> {
    let gate = terminal(nets, roles, TerminalRole::Gate);
    [
        TerminalRole::Source,
        TerminalRole::Drain,
        TerminalRole::Bulk,
    ]
    .into_iter()
    .filter_map(|role| voltage.worst_delta(gate, terminal(nets, roles, role)))
    .reduce(f64::max)
}

/// Largest drain-to-source voltage a device can see.
fn drain_source_stress(
    voltage: &NetVoltage,
    nets: &[NetId],
    roles: &[TerminalRole],
) -> Option<f64> {
    voltage.worst_delta(
        terminal(nets, roles, TerminalRole::Source),
        terminal(nets, roles, TerminalRole::Drain),
    )
}

/// Runs every `gate_oxide` row: gate-oxide overstress.
///
/// Flags a device of the row's models whose gate can differ from its source,
/// drain or bulk by more than `max`, the oxide stress its rating bounds. The
/// measure is the largest of those three worst-case differences whose two
/// nets some supply reaches.
///
/// `examined` counts devices of the row's models with at least one such
/// pair. A violation sits at the first vertex of the device's marker, on the
/// marker layer, measuring the difference in mV against `max`. Every row is
/// skipped without usable intent.
///
/// Catalog: ERC-F2 in the [check catalog]. Defined by [GF180MCU] §14.1.4.2;
/// [SKY130] hv rules; [ESDA TR22] §4.1; Calibre (public material only).
/// Limits are on [`ModelLimitTable`]; source tags are in [check-sources.md].
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
/// [ESDA TR22]: https://www.esda.org/store/standards/product/72/esd-tr22-0-01-14
pub fn check_gate_oxide(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &ModelLimitTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    check_model_limit(design, intent, voltage, table, gate_stress, out, runs);
}

/// Runs every `drain_source` row: junction and channel overstress.
///
/// Flags a device of the row's models whose drain can differ from its source
/// by more than `max`, the worst-case difference of the two nets' ranges.
///
/// `examined` counts devices of the row's models whose source and drain some
/// supply reaches. Violations report as [`check_gate_oxide`]'s do.
///
/// Catalog: ERC-F3 in the [check catalog]. Defined by [SKY130] hv rules; the
/// [IHP SG13G2] process specification. Limits are on [`ModelLimitTable`];
/// source tags are in [check-sources.md].
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
/// [IHP SG13G2]: https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc
pub fn check_drain_source(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &ModelLimitTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    check_model_limit(
        design,
        intent,
        voltage,
        table,
        drain_source_stress,
        out,
        runs,
    );
}

/// Runs every [`WellBiasTable`] row.
///
/// `examined` counts devices of the row's models whose bulk, and at least
/// one of source and drain, some supply reaches. A violation sits at the
/// first vertex of the device's marker, on the marker layer, measuring the
/// excess in mV against 0 V. Every row is skipped without usable intent.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_well_bias(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &WellBiasTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let devices = design.devices;
    let limit = Measurement::Voltage(Qty::new(0.0));
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let pmos = csr(&table.pmos_start, &table.pmos, row);
        let nmos = csr(&table.nmos_start, &table.nmos, row);
        let mut examined = 0u64;
        for device in 0..devices.len() {
            let model = devices.model[device];
            let high = pmos.contains(&model);
            if !high && !nmos.contains(&model) {
                continue;
            }
            let (nets, roles) = devices.terminals_of(device_id(device));
            let bulk = terminal(nets, roles, TerminalRole::Bulk);
            let ends = [TerminalRole::Source, TerminalRole::Drain]
                .map(|role| terminal(nets, roles, role))
                .into_iter()
                .filter(|&net| voltage.known(net));
            let excess = if high {
                ends.map(|net| voltage.hi[net.idx()])
                    .reduce(f64::max)
                    .filter(|_| voltage.known(bulk))
                    .map(|top| top - voltage.lo[bulk.idx()])
            } else {
                ends.map(|net| voltage.lo[net.idx()])
                    .reduce(f64::min)
                    .filter(|_| voltage.known(bulk))
                    .map(|bottom| voltage.hi[bulk.idx()] - bottom)
            };
            let Some(excess) = excess else {
                continue;
            };
            examined += 1;
            let measured = Measurement::Voltage(Qty::new(excess));
            if measured.violates(limit, LimitSense::Maximum) {
                let severity = table.head.severity[row];
                push_device(design, device, rule, severity, measured, limit, out);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Runs every [`MissingLevelShifterTable`] row over every MOS device.
///
/// `examined` counts transistors, not of a shifter model, whose gate and
/// whose source or drain some power supply reaches. A violation sits at the
/// first vertex of the device's marker, on the marker layer, measuring the
/// count of domains that reach the gate but not the channel against 0. Every
/// row is skipped without usable intent.
pub fn check_missing_level_shifter(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &MissingLevelShifterTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let devices = design.devices;
    let limit = Measurement::Count(0);
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let shifters = csr(&table.shifter_start, &table.shifter, row);
        let mut examined = 0u64;
        for device in 0..devices.len() {
            if devices.kind[device] != DeviceKind::Mos || shifters.contains(&devices.model[device])
            {
                continue;
            }
            let (nets, roles) = devices.terminals_of(device_id(device));
            let gate = voltage.power_of(terminal(nets, roles, TerminalRole::Gate));
            let channel = voltage.power_of(terminal(nets, roles, TerminalRole::Source))
                | voltage.power_of(terminal(nets, roles, TerminalRole::Drain));
            if gate == 0 || channel == 0 {
                continue;
            }
            examined += 1;
            let measured = Measurement::Count((gate & !channel).count_ones());
            if measured.violates(limit, LimitSense::Maximum) {
                let severity = table.head.severity[row];
                push_device(design, device, rule, severity, measured, limit, out);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Runs every [`DomainCrossingTable`] row over every device.
///
/// `examined` counts devices whose channel some power supply reaches. A
/// violation sits at the first vertex of the device's marker, on the marker
/// layer, measuring the count of domains that reach the channel against 1.
/// Every row is skipped without usable intent.
pub fn check_domain_crossing(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &DomainCrossingTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let devices = design.devices;
    let limit = Measurement::Count(1);
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let mut examined = 0u64;
        for device in 0..devices.len() {
            let (nets, roles) = devices.terminals_of(device_id(device));
            let kind = devices.kind[device];
            let mask = nets
                .iter()
                .zip(roles)
                .filter(|&(_, &role)| is_channel(kind, role))
                .fold(0u64, |mask, (&net, _)| mask | voltage.power_of(net));
            if mask == 0 {
                continue;
            }
            examined += 1;
            let measured = Measurement::Count(mask.count_ones());
            if measured.violates(limit, LimitSense::Maximum) {
                let severity = table.head.severity[row];
                push_device(design, device, rule, severity, measured, limit, out);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// The gate net of each MOS device, `NetId::NONE` for another kind or a
/// gate on no net.
fn gate_nets(design: Design<'_>) -> Vec<NetId> {
    let devices = design.devices;
    (0..devices.len())
        .map(|device| {
            if devices.kind[device] != DeviceKind::Mos {
                return NetId::NONE;
            }
            let (nets, roles) = devices.terminals_of(device_id(device));
            terminal(nets, roles, TerminalRole::Gate)
        })
        .collect()
}

/// Runs every [`UndrivenGateTable`] row.
///
/// `examined` counts the gate nets some supply reaches with every supply on.
/// A violation sits at the first vertex of the net's lowest-numbered
/// polygon, on its layer, measuring the count of states the net floats in
/// against 0; a net with no polygon is not reported. Every row is skipped
/// without usable intent, or when the intent declares no power state.
///
/// # Panics
///
/// Panics if `states` holds a propagation over other nets.
pub fn check_undriven_gate(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    states: &[NetVoltage],
    table: &UndrivenGateTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() || states.is_empty() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let mut gates: Vec<NetId> = gate_nets(design)
        .into_iter()
        .filter(|&net| voltage.known(net))
        .collect();
    gates.sort_unstable();
    gates.dedup();
    let floating: Vec<(NetId, u32)> = gates
        .iter()
        .map(|&net| {
            let off = states.iter().filter(|state| !state.known(net)).count();
            (net, u32::try_from(off).expect("a state count fits a u32"))
        })
        .filter(|&(_, off)| off > 0)
        .collect();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        for &(net, off) in &floating {
            let Some(&poly) = design.nets.polys_of(net).first() else {
                continue;
            };
            out.push(Violation {
                rule,
                layer: design.store.poly_layer(poly),
                severity: table.head.severity[row],
                at: first_vertex(design.store, poly),
                measured: Measurement::Count(off),
                limit: Measurement::Count(0),
                shapes: (poly, None),
            });
        }
        record_run(runs, out, before, rule, Outcome::Ran, gates.len() as u64);
    }
}

/// Runs every [`MissingIsolationTable`] row over every MOS device.
///
/// `examined` counts the transistors, not of an isolation model, whose gate
/// some supply reaches with every supply on. A violation sits at the first
/// vertex of the device's marker, on the marker layer, measuring the count
/// of states in which its gate floats while its channel is powered, against
/// 0. Every row is skipped without usable intent, or when the intent
/// declares no power state.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables),
/// or `states` holds a propagation over other nets.
pub fn check_missing_isolation(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    states: &[NetVoltage],
    table: &MissingIsolationTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() || states.is_empty() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let devices = design.devices;
    let gates = gate_nets(design);
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let exempt = csr(&table.isolation_start, &table.isolation, row);
        let mut examined = 0u64;
        for (device, &gate) in gates.iter().enumerate() {
            if !voltage.known(gate) || exempt.contains(&devices.model[device]) {
                continue;
            }
            examined += 1;
            let (nets, roles) = devices.terminals_of(device_id(device));
            let channel =
                [TerminalRole::Source, TerminalRole::Drain].map(|role| terminal(nets, roles, role));
            let leaking = states
                .iter()
                .filter(|state| {
                    !state.known(gate) && channel.iter().any(|&net| state.power_of(net) != 0)
                })
                .count();
            let measured =
                Measurement::Count(u32::try_from(leaking).expect("a state count fits a u32"));
            let limit = Measurement::Count(0);
            if measured.violates(limit, LimitSense::Maximum) {
                let severity = table.head.severity[row];
                push_device(design, device, rule, severity, measured, limit, out);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Runs every [`HvTagTable`] row.
///
/// `examined` counts the high-voltage figures. A violation sits at the
/// centre of the figure's first rectangle, on `L`, measuring the area left
/// outside `tag` against 0, named by the figure's lowest drawn polygon.
/// Every row is skipped without usable intent; a row is refused when a layer
/// will not validate or merge, or `L` holds a shape on no net.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_hv_tag(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &HvTagTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let mut scratch = crate::drc::Scratch::default();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let layer = table.layer[row];
        let unnetted = design
            .store
            .polys_on_layer(layer)
            .any(|poly| design.nets.net_of(gpurify_geom::PolyId(poly)) == NetId::NONE);
        let (outcome, examined) = if unnetted {
            (Outcome::Refused, 0)
        } else {
            let from = table.voltage[row].raw();
            crate::drc::rules::presence::inside_where(
                design.store,
                rule,
                (layer, table.tag[row]),
                &mut scratch,
                out,
                |owner| {
                    let net = design.nets.net_of(owner);
                    voltage.known(net) && voltage.hi[net.idx()] >= from
                },
            )
        };
        let severity = table.head.severity[row];
        for at in &mut out.severity[before..] {
            *at = severity;
        }
        record_run(runs, out, before, rule, outcome, examined);
    }
}

/// Runs every [`DielectricFieldTable`] row.
///
/// `examined` counts the pairs judged: shapes on two different nets that
/// some supply reaches, within the largest lateral limit any two nets of the
/// layout need (on one layer, in different merged figures). A violation sits
/// at the midpoint of the pair's nearest points, on the first layer,
/// measuring the lateral gap against its limit, with both shapes named.
/// Every row is skipped without usable intent; a row is refused when a layer
/// will not validate or holds a shape on no net, or its stack is unstated.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_dielectric_field(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    grid: gpurify_geom::Grid,
    table: &DielectricFieldTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    // The widest voltage any two reached nets can span, mV.
    let (lo, hi) = voltage
        .lo
        .iter()
        .zip(&voltage.hi)
        .filter(|(lo, hi)| lo <= hi)
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(a, b), (&lo, &hi)| {
            (a.min(lo), b.max(hi))
        });
    let widest_delta = (hi - lo).max(0.0);
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        reason = "a grid's units per µm and a lateral limit in units are far below 2^52"
    )]
    let lateral = |delta: f64, field: f64, vertical: f64| -> Option<Dbu> {
        // The separation the voltage needs, nm, then its lateral part.
        let separation = delta / field;
        (separation > vertical).then(|| {
            let nm = (separation * separation - vertical * vertical).sqrt();
            Dbu::new_unchecked((nm * grid.dbu_per_um() as f64 / 1000.0).ceil() as i64)
        })
    };
    let mut scratch = crate::drc::Scratch::default();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let field = table.max_field[row];
        let (outcome, examined) = match table.vertical_nm[row] {
            None => (Outcome::Refused, 0),
            Some(vertical) => {
                let widest = lateral(widest_delta, field, vertical)
                    .unwrap_or(Dbu::new_unchecked(0))
                    .max(Dbu::new_unchecked(1));
                crate::drc::rules::spacing::net_pair_spacing(
                    design.store,
                    design.nets,
                    rule,
                    (table.layer[row], table.other[row]),
                    widest,
                    &mut scratch,
                    out,
                    |a: NetId, b: NetId| {
                        if a == b {
                            return None;
                        }
                        let delta = voltage.worst_delta(a, b)?;
                        Some(lateral(delta, field, vertical))
                    },
                )
            }
        };
        let severity = table.head.severity[row];
        for at in &mut out.severity[before..] {
            *at = severity;
        }
        record_run(runs, out, before, rule, outcome, examined);
    }
}

/// The space a pair needs whose nets can reach `delta` mV apart: the step
/// with the largest voltage at or below `delta`, `None` below the first.
fn step_space(
    voltage: &[Qty<Voltage, { prefix::MILLI }>],
    space: &[Dbu],
    delta: f64,
) -> Option<Dbu> {
    voltage
        .iter()
        .rposition(|step| step.raw() <= delta)
        .map(|step| space[step])
}

/// Runs every [`VoltageSpacingTable`] row.
///
/// `examined` counts the pairs judged: shapes on two different nets that
/// some supply reaches, within the row's largest space of each other (on one
/// layer, in different merged figures). A violation sits at the midpoint of
/// the pair's nearest points, on the first layer, measuring the gap against
/// the step's space, with both shapes named. Every row is skipped without
/// usable intent; a row is refused when a layer will not validate or holds a
/// shape on no net.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_voltage_spacing(
    design: Design<'_>,
    intent: &IntentMap,
    voltage: &NetVoltage,
    table: &VoltageSpacingTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let mut scratch = crate::drc::Scratch::default();
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let steps = table.step_start[row] as usize..table.step_start[row + 1] as usize;
        let (volts, spaces) = (&table.voltage[steps.clone()], &table.space[steps]);
        let widest = *spaces.iter().max().expect("a row has a step");
        let need = |a: NetId, b: NetId| {
            if a == b {
                return None;
            }
            let delta = voltage.worst_delta(a, b)?;
            Some(step_space(volts, spaces, delta))
        };
        let (outcome, examined) = crate::drc::rules::spacing::net_pair_spacing(
            design.store,
            design.nets,
            rule,
            (table.layer[row], table.other[row]),
            widest,
            &mut scratch,
            out,
            need,
        );
        let severity = table.head.severity[row];
        for at in &mut out.severity[before..] {
            *at = severity;
        }
        record_run(runs, out, before, rule, outcome, examined);
    }
}

/// A power switch wired against the power intent: deck kind `power_switch`,
/// written `power_switch(; models: models)`.
///
/// A power switch joins an always-on supply to the supply it gates: IEEE
/// 1801's `create_power_switch` names an `-input_supply_port` and an
/// `-output_supply_port` (ISLPED 2014 UPF tutorial: `-input_supply_port {
/// in_vdd VDDB } -output_supply_port { out_vdd VDD }`, the output the
/// switched domain's primary power), and Liu et al. (Samsung and Synopsys,
/// `DVCon`) require "The PG connection of power switch cells should respect
/// the UPF specification" and "Power switch control signal should come from
/// always on path". Here the power intent is the design intent: a supply
/// some declared power state turns off is switched, every other declared
/// supply is always on. A transistor of a listed model is a switch, and a
/// row flags:
///
/// - a switch whose channel does not join an always-on supply to a
///   switched supply of the same role (a header between powers, a footer
///   between grounds);
/// - a switch whose gate floats in a declared power state: no supply
///   reaches its control net there, as [`UndrivenGateTable`] reads a state,
///   so its control does not come from an always-on path.
///
/// Needs design intent that declares power states.
///
/// # Limits
///
/// Retention cells (their save and restore controls, their retention
/// supply), always-on cells inside a switched domain, and standard cells on
/// the real rather than the switched net are not checked: the intent does
/// not say which cells are which. IEEE 1801 itself was not read; the rules
/// are the cited papers'.
///
/// Catalog: ERC-F14 (partial) in the [check catalog]. Defined by [IEEE
/// 1801] `create_power_switch` (cited for scope, not read); [Liu] (`DVCon`,
/// the power-switch and PG-connectivity checks); the [ISLPED 2014] UPF
/// tutorial (the switch's supply ports). Source tags are in
/// [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [IEEE 1801]: https://standards.ieee.org/ieee/1801/11890/
/// [Liu]: https://dvcon-proceedings.org/wp-content/uploads/low-power-verification-with-upf-principle-and-practice.pdf
/// [ISLPED 2014]: https://islped.org/2014/files/Failing%20to%20fail%20UPF%20tutorial%20.pdf
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PowerSwitchTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Switch models per row, CSR.
    pub model_start: Vec<u32>,
    /// Switch models, CSR by `model_start`; at least one per row.
    pub model: Vec<StrId>,
}

/// Runs every [`PowerSwitchTable`] row over every transistor of its models.
///
/// `examined` counts the switches. A wiring violation sits at the first
/// vertex of the switch's marker, on its layer, measuring the joined
/// always-on and switched pair it lacks, 0, against 1; a control violation
/// there too, measuring the states its gate floats in against 0. Every row
/// is skipped without usable intent, or when the intent declares no power
/// state.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables),
/// or `states` holds a propagation over other nets.
pub fn check_power_switch(
    design: Design<'_>,
    intent: &IntentMap,
    switched: &[NetId],
    states: &[NetVoltage],
    table: &PowerSwitchTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if !intent.is_usable() || states.is_empty() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let devices = design.devices;
    let role = |net: NetId| intent.supply(net).map(|(role, _)| role);
    let on = |net: NetId| switched.binary_search(&net).is_err();
    for row in 0..table.head.len() {
        let before = out.len();
        let models =
            &table.model[table.model_start[row] as usize..table.model_start[row + 1] as usize];
        let mut examined = 0u64;
        for device in 0..devices.len() {
            if devices.kind[device] != DeviceKind::Mos || !models.contains(&devices.model[device]) {
                continue;
            }
            examined += 1;
            let (nets, roles) = devices.terminals_of(device_id(device));
            let (s, d) = (
                terminal(nets, roles, TerminalRole::Source),
                terminal(nets, roles, TerminalRole::Drain),
            );
            let gate = terminal(nets, roles, TerminalRole::Gate);
            let wired = match (role(s), role(d)) {
                (Some(a), Some(b)) if a == b => on(s) != on(d),
                _ => false,
            };
            if !wired {
                push_device(
                    design,
                    device,
                    table.head.rule[row],
                    table.head.severity[row],
                    Measurement::Count(0),
                    Measurement::Count(1),
                    out,
                );
            }
            let floats = states
                .iter()
                .filter(|state| gate == NetId::NONE || !state.known(gate))
                .count();
            if floats > 0 {
                push_device(
                    design,
                    device,
                    table.head.rule[row],
                    table.head.severity[row],
                    Measurement::Count(u32::try_from(floats).expect("a state count fits a u32")),
                    Measurement::Count(0),
                    out,
                );
            }
        }
        record_run(
            runs,
            out,
            before,
            table.head.rule[row],
            Outcome::Ran,
            examined,
        );
    }
}

/// A hot-carrier susceptible transistor: deck kind `hot_carrier`, written
/// `hot_carrier(; models: models, max_length: len)`.
///
/// A transistor of a listed model, drawn at most `max_length` long (a
/// minimum-channel device), used in both directions. [GF180MCU] §14.1.4.1
/// (e): "Longer than minimum channel length should be used in circuits where
/// NMOSFETs are used in bi-directional mode"; its reason, "When source and
/// drain are exchanged, as in a pass gate, the degradation is more severe".
/// A device is used in both directions when neither channel end is a
/// declared supply and each end, cut off from the other through this device
/// and any device joining the same two nets (its partner in a transmission
/// gate), still reaches both a power and a ground supply through MOS
/// channels: each side can be driven high and low by itself, so current can
/// flow through the device either way. A pass gate between two inverter
/// outputs is one; the upper device of a NAND stack is not (its lower node
/// reaches ground only), nor an inverter's (a supply end), nor a pass gate
/// into gates alone. The guideline is advice, so a deck writes the row at
/// `warning` severity. Needs design intent, for which nets are the supplies.
///
/// # Limits
///
/// "Bi-directional" is not defined further by the guideline; reading it as
/// both sides driven both ways is this kind's. The guideline's static voltage
/// bound (Vds within Vddmax) is [`check_drain_source`]'s, and its stress
/// condition in time (the fraction a FET conducts) has no static reading. A
/// device whose length was not measured is not examined.
///
/// Catalog: ERC-F4 in the [check catalog]. Defined by [GF180MCU] §14.1.4.1
/// (a), (b) and (e). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_manual/drm_14_1.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct HotCarrierTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// `model[model_start[i] .. model_start[i + 1]]` are row `i`'s models.
    pub model_start: Vec<u32>,
    /// Device model names, CSR by `model_start`; at least one per row.
    pub model: Vec<StrId>,
    /// Per row: the longest channel still minimum, database units. Positive
    /// from a deck.
    pub max_length: Vec<Dbu>,
}

/// Every MOS's channel ends `[source, drain]`, `NetId::NONE` for another
/// kind or an end on no net.
fn channel_ends(design: Design<'_>) -> Vec<[NetId; 2]> {
    let devices = design.devices;
    (0..devices.len())
        .map(|device| {
            if devices.kind[device] != DeviceKind::Mos {
                return [NetId::NONE; 2];
            }
            let (nets, roles) = devices.terminals_of(device_id(device));
            [TerminalRole::Source, TerminalRole::Drain].map(|role| terminal(nets, roles, role))
        })
        .collect()
}

/// Runs every [`HotCarrierTable`] row.
///
/// `examined` counts devices of the row's models at most `max_length` long.
/// A violation sits at the first vertex of the device's marker, on the
/// marker layer, measuring its length against `max_length`. Every row is
/// skipped when no design intent was given or it declares no supply this
/// layout has.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_hot_carrier(
    design: Design<'_>,
    intent: &IntentMap,
    table: &HotCarrierTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    if intent.supply_net.is_empty() {
        skip_rows(&table.head, out, runs);
        return;
    }
    let devices = design.devices;
    let ends = channel_ends(design);
    let supply = |net: NetId| intent.supply(net).map(|(role, _)| role);
    let mut seen = vec![0u32; design.nets.net_count()];
    let mut stamp = 0u32;
    let mut walk: Vec<NetId> = Vec::new();
    // Whether `from` reaches both a power and a ground supply through MOS
    // channels, never through a device joining `cut`'s two nets.
    // ponytail: one walk per side of every short device; share walks per
    // cut pair if a large design makes this quadratic.
    let mut both_rails = |from: NetId, cut: [NetId; 2]| {
        stamp += 1;
        let mut roles = [false; 2];
        walk.clear();
        walk.push(from);
        while let Some(at) = walk.pop() {
            if at.idx() >= seen.len() || seen[at.idx()] == stamp {
                continue;
            }
            seen[at.idx()] = stamp;
            if let Some(role) = supply(at) {
                roles[usize::from(role == SupplyRole::Ground)] = true;
                continue;
            }
            for &other in devices.devices_on(at) {
                let [a, b] = ends[other.0 as usize];
                if a == NetId::NONE || b == NetId::NONE {
                    continue;
                }
                if (a == cut[0] && b == cut[1]) || (a == cut[1] && b == cut[0]) {
                    continue;
                }
                if a == at || b == at {
                    walk.push(if a == at { b } else { a });
                }
            }
        }
        roles == [true, true]
    };
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let models = csr(&table.model_start, &table.model, row);
        let limit = table.max_length[row];
        let mut examined = 0u64;
        for device in 0..devices.len() {
            if !models.contains(&devices.model[device]) {
                continue;
            }
            let length = devices
                .params_of(device_id(device))
                .iter()
                .find_map(|&(param, value)| match (param, value) {
                    (DeviceParam::Length, DeviceMeasure::Length(l)) => Some(l),
                    _ => None,
                });
            let Some(length) = length.filter(|&l| l <= limit) else {
                continue;
            };
            examined += 1;
            let [s, d] = ends[device];
            if s == NetId::NONE || d == NetId::NONE || s == d {
                continue;
            }
            if supply(s).is_some() || supply(d).is_some() {
                continue;
            }
            if both_rails(s, [s, d]) && both_rails(d, [s, d]) {
                let severity = table.head.severity[row];
                let (measured, limit) = (Measurement::Length(length), Measurement::Length(limit));
                push_device(design, device, rule, severity, measured, limit, out);
            }
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}

/// Transistors sharing a well with another supply: deck kind
/// `well_sharing`, written `well_sharing(; models: models, resistors:
/// bool)`.
///
/// Mitsubishi's latch-up verification ([US 5,638,286], first embodiment)
/// "groups together all of the transistors included in the same well region
/// as the transistors having the same back gate terminal", and of each
/// group "extracts an MOS transistor which does not meet any of the
/// conditions as a latch-up MOS transistor":
///
/// 1. its source "is connected directly to the well region";
/// 2. it "is connected to the latter through a resistance";
/// 3. it "is connected to the latter in series in a drain-source terminal
///    direction through a single or a plurality of transistors included in
///    the same well region".
///
/// Here the well region is a transistor's bulk net, its back gate terminal,
/// so a row checks every transistor of a listed model with a bulk on a net:
/// it passes when a channel end (source or drain alike: a MOS is symmetric)
/// is on the bulk net (1); with `resistors: true`, when a resistor joins a
/// channel end to the bulk net (2); or when a chain of channels of other
/// transistors whose bulk is the same net joins a channel end to it (3).
/// Otherwise it is flagged: a transistor fed from a supply other than its
/// well's, such as the patent's Q5, whose source reaches its well "in
/// relation to the different N- well region". A potential difference
/// between the two supplies "causes a base current to flow in the forward
/// direction to the PNP" (col. 2), whatever their nominal voltages, so this
/// is topological where [`check_well_bias`] compares voltages. The scope,
/// which models sit in a well (the patent's n-well transistors, or an
/// isolated p-well's by the same reasoning) and whether a resistor counts,
/// is the deck's. Needs no design intent.
///
/// # Limits
///
/// A resistor counts only between a channel end and the bulk net, with no
/// limit on its value (the patent states none), and not inside a chain.
/// Calibre PERC's own "PMOS/NMOS devices sharing the same well" check is
/// named in public material (Hogan & Medhat, 2021) but not defined; this is
/// the patent's. A device with no bulk terminal on a net is not examined.
///
/// Catalog: ERC-D9 in the [check catalog]. Defined by [US 5,638,286].
/// Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [US 5,638,286]: https://patents.google.com/patent/US5638286A/en
#[derive(Debug, Default, Clone, PartialEq)]
pub struct WellSharingTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// `model[model_start[i] .. model_start[i + 1]]` are row `i`'s models.
    pub model_start: Vec<u32>,
    /// Device model names, CSR by `model_start`; at least one per row.
    pub model: Vec<StrId>,
    /// Per row: a resistor between a channel end and the well's net
    /// satisfies the check (the patent's condition 2).
    pub resistors: Vec<bool>,
}

/// Runs every [`WellSharingTable`] row.
///
/// `examined` counts devices of the row's models with a bulk on a net. A
/// violation sits at the first vertex of the device's marker, on the marker
/// layer, measuring the conditions met, 0, against 1. Every row runs.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_well_sharing(
    design: Design<'_>,
    table: &WellSharingTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let devices = design.devices;
    let ends = channel_ends(design);
    let bulk: Vec<NetId> = (0..devices.len())
        .map(|device| {
            if devices.kind[device] != DeviceKind::Mos {
                return NetId::NONE;
            }
            let (nets, roles) = devices.terminals_of(device_id(device));
            terminal(nets, roles, TerminalRole::Bulk)
        })
        .collect();
    // Whether a resistor joins `a` and `b`.
    let resistor_between = |a: NetId, b: NetId| {
        devices.devices_on(a).iter().any(|&other| {
            if devices.kind[other.0 as usize] != DeviceKind::Resistor {
                return false;
            }
            let (nets, _) = devices.terminals_of(other);
            nets.len() == 2 && ((nets[0] == a && nets[1] == b) || (nets[0] == b && nets[1] == a))
        })
    };
    let mut seen = vec![0u32; design.nets.net_count()];
    let mut stamp = 0u32;
    let mut walk: Vec<NetId> = Vec::new();
    // Whether a chain of channels of transistors other than `skip` whose bulk
    // is `well` joins one of `from` to `well`.
    let mut chained = |from: [NetId; 2], well: NetId, skip: usize| {
        stamp += 1;
        walk.clear();
        walk.extend(from.into_iter().filter(|&net| net != NetId::NONE));
        while let Some(at) = walk.pop() {
            if at == well {
                return true;
            }
            if at.idx() >= seen.len() || seen[at.idx()] == stamp {
                continue;
            }
            seen[at.idx()] = stamp;
            for &other in devices.devices_on(at) {
                let other = other.0 as usize;
                let [a, b] = ends[other];
                if other == skip || bulk[other] != well || a == NetId::NONE || b == NetId::NONE {
                    continue;
                }
                if a == at || b == at {
                    walk.push(if a == at { b } else { a });
                }
            }
        }
        false
    };
    for row in 0..table.head.len() {
        let before = out.len();
        let rule = table.head.rule[row];
        let models = csr(&table.model_start, &table.model, row);
        let mut examined = 0u64;
        for device in 0..devices.len() {
            let well = bulk[device];
            if well == NetId::NONE || !models.contains(&devices.model[device]) {
                continue;
            }
            examined += 1;
            let channel = ends[device];
            let on = |end: NetId| end != NetId::NONE && end == well;
            let through_resistor = |end: NetId| end != NetId::NONE && resistor_between(end, well);
            if channel.into_iter().any(on)
                || (table.resistors[row] && channel.into_iter().any(through_resistor))
                || chained(channel, well, device)
            {
                continue;
            }
            let severity = table.head.severity[row];
            let (measured, limit) = (Measurement::Count(0), Measurement::Count(1));
            push_device(design, device, rule, severity, measured, limit, out);
        }
        record_run(runs, out, before, rule, Outcome::Ran, examined);
    }
}
