//! The forty-four tables, the deck parser that fills them, and the dispatcher.
//!
//! Data in: a deck's rule table. Data out: a [`RuleSet`]; [`RuleSet::run`]
//! produces violations and exactly one `RuleRun` per configured row.

use crate::erc::facts::{IntentMap, NetFacts};
use crate::erc::power::{NetNetworks, Power, PowerError, Process};
use crate::erc::rules::{antenna, domain, electrical, esd, latchup, reliability, supply, topology};
use crate::erc::voltage::NetVoltage;
use crate::erc::{Design, ErcError, Scratch};
use crate::report::{RuleRun, Severity, Violations};
use crate::topology::PortTable;
use gpurify_geom::{prefix, Dbu, DbuArea, Qty, Temperature, Voltage};
use gpurify_geom::{Bbox, LayerId};
use gpurify_ingest::deck::{Deck, DeviceKind, ParamValue, ProcessStack, RuleSpec, RuleTable};
use gpurify_ingest::{StrId, StrTable};

pub use crate::deck::rules::ERC_KINDS as KINDS;

/// The two columns every rule table has.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RuleHead {
    /// The deck's id for this rule, interned; what a `RuleRun` is attributed to.
    pub rule: Vec<StrId>,
    /// Per row: `Error`, or `Warning` when the deck row is marked `warning`.
    pub severity: Vec<Severity>,
}

impl RuleHead {
    /// The number of rows; every per-row column of the table has this many.
    pub fn len(&self) -> usize {
        self.rule.len()
    }

    /// True when the deck has no row of this kind; its check records nothing.
    pub fn is_empty(&self) -> bool {
        self.rule.is_empty()
    }
}

/// Every configured rule, one table per kind.
///
/// Built by [`RuleSet::from_deck`] and run by [`RuleSet::run`], usually
/// through [`erc::check`](crate::erc::check). Each field holds the rows of
/// the [`KINDS`] entry of the same name; its table type defines the kind.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RuleSet {
    /// `floating_gate` rows: [`topology::FloatingGateTable`].
    pub floating_gate: topology::FloatingGateTable,
    /// `floating_well` rows: [`topology::FloatingWellTable`].
    pub floating_well: topology::FloatingWellTable,
    /// `multiple_drivers` rows: [`topology::MultipleDriversTable`].
    pub multiple_drivers: topology::MultipleDriversTable,
    /// `unconnected_pin` rows: [`topology::UnconnectedPinTable`].
    pub unconnected_pin: topology::UnconnectedPinTable,
    /// `fanout` rows: [`topology::FanoutTable`].
    pub fanout: topology::FanoutTable,

    /// `supply_short` rows: [`supply::SupplyShortTable`].
    pub supply_short: supply::SupplyShortTable,
    /// `soft_connection` rows: [`supply::SoftConnectionTable`].
    pub soft_connection: supply::SoftConnectionTable,
    /// `missing_tie` rows: [`supply::MissingTieTable`].
    pub missing_tie: supply::MissingTieTable,
    /// `tie_high_low` rows: [`supply::TieHighLowTable`].
    pub tie_high_low: supply::TieHighLowTable,
    /// `esd_topological` rows: [`supply::EsdTopologicalTable`].
    pub esd_topological: supply::EsdTopologicalTable,
    /// `mixed_tag` rows: [`supply::MixedTagTable`].
    pub mixed_tag: supply::MixedTagTable,

    /// `antenna` rows: [`antenna::AntennaTable`].
    pub antenna: antenna::AntennaTable,
    /// `antenna_electrical` rows: [`antenna::AntennaElectricalTable`].
    pub antenna_electrical: antenna::AntennaElectricalTable,
    /// `density_cmp` rows: [`antenna::DensityCmpTable`].
    pub density_cmp: antenna::DensityCmpTable,

    /// `p2p_resistance` rows: [`electrical::P2pResistanceTable`].
    pub p2p_resistance: electrical::P2pResistanceTable,
    /// `ir_drop` rows: [`electrical::IrDropTable`].
    pub ir_drop: electrical::IrDropTable,
    /// `em_current_density` rows: [`electrical::EmCurrentDensityTable`].
    pub em_current_density: electrical::EmCurrentDensityTable,
    /// `electromigration` rows: [`electrical::ElectromigrationTable`].
    pub electromigration: electrical::ElectromigrationTable,
    /// `dynamic_ir_drop` rows: [`electrical::DynamicIrDropTable`].
    pub dynamic_ir_drop: electrical::DynamicIrDropTable,
    /// `em_thermal` rows: [`electrical::EmThermalTable`].
    pub em_thermal: electrical::EmThermalTable,

    /// `reliability` rows: [`reliability::ReliabilityTable`].
    pub reliability: reliability::ReliabilityTable,
    /// `hv_domain` rows: [`reliability::HvDomainTable`].
    pub hv_domain: reliability::HvDomainTable,
    /// `esd_latchup` rows: [`reliability::EsdLatchupTable`].
    pub esd_latchup: reliability::EsdLatchupTable,

    /// `esd_path` rows: [`esd::EsdPathTable`].
    pub esd_path: esd::EsdPathTable,
    /// `esd_ground_coupling` rows: [`esd::EsdGroundCouplingTable`].
    pub esd_ground_coupling: esd::EsdGroundCouplingTable,
    /// `esd_cross_domain` rows: [`esd::EsdCrossDomainTable`].
    pub esd_cross_domain: esd::EsdCrossDomainTable,
    /// `esd_parasitic` rows: [`esd::EsdParasiticTable`].
    pub esd_parasitic: esd::EsdParasiticTable,
    /// `esd_exposed` rows: [`esd::EsdExposedTable`].
    pub esd_exposed: esd::EsdExposedTable,

    /// `guard_ring_bias` rows: [`latchup::GuardRingBiasTable`].
    pub guard_ring_bias: latchup::GuardRingBiasTable,
    /// `tie_area` rows: [`latchup::TieAreaTable`].
    pub tie_area: latchup::TieAreaTable,
    /// `guard_ring` rows: [`latchup::GuardRingTable`].
    pub guard_ring: latchup::GuardRingTable,
    /// `forward_diode` rows: [`latchup::ForwardDiodeTable`].
    pub forward_diode: latchup::ForwardDiodeTable,
    /// `conditional_tie` rows: [`latchup::ConditionalTieTable`].
    pub conditional_tie: latchup::ConditionalTieTable,
    /// `latchup_victim` rows: [`latchup::LatchupVictimTable`].
    pub latchup_victim: latchup::LatchupVictimTable,

    /// `gate_oxide` rows: [`domain::ModelLimitTable`], checked by
    /// [`domain::check_gate_oxide`].
    pub gate_oxide: domain::ModelLimitTable,
    /// `drain_source` rows: [`domain::ModelLimitTable`], checked by
    /// [`domain::check_drain_source`].
    pub drain_source: domain::ModelLimitTable,
    /// `well_bias` rows: [`domain::WellBiasTable`].
    pub well_bias: domain::WellBiasTable,
    /// `missing_level_shifter` rows: [`domain::MissingLevelShifterTable`].
    pub missing_level_shifter: domain::MissingLevelShifterTable,
    /// `domain_crossing` rows: [`domain::DomainCrossingTable`].
    pub domain_crossing: domain::DomainCrossingTable,
    /// `voltage_spacing` rows: [`domain::VoltageSpacingTable`].
    pub voltage_spacing: domain::VoltageSpacingTable,
    /// `hv_tag` rows: [`domain::HvTagTable`].
    pub hv_tag: domain::HvTagTable,
    /// `undriven_gate` rows: [`domain::UndrivenGateTable`].
    pub undriven_gate: domain::UndrivenGateTable,
    /// `missing_isolation` rows: [`domain::MissingIsolationTable`].
    pub missing_isolation: domain::MissingIsolationTable,
    /// `dielectric_field` rows: [`domain::DielectricFieldTable`].
    pub dielectric_field: domain::DielectricFieldTable,
}

/// Everything one run reads, borrowed.
#[derive(Debug, Clone, Copy)]
pub struct RunInputs<'a> {
    /// The extracted layout: geometry, nets and devices.
    pub design: Design<'a>,
    /// Terminal roles per net, from
    /// [`classify_nets_into`](crate::erc::facts::classify_nets_into) over the
    /// same nets.
    pub facts: &'a NetFacts,
    /// Labelled nets: driven from outside the cell.
    pub ports: &'a PortTable,
    /// The design intent keyed by net; [`IntentMap::is_usable`] decides which
    /// rows skip.
    pub intent: &'a IntentMap,
    /// What each net can reach from the declared supplies.
    pub voltage: &'a NetVoltage,
    /// What each net can reach in each declared power state, in the intent's
    /// order: that state's supplies off and inputs held
    /// ([`IntentMap::in_state`]). Empty when the intent declares no state.
    pub states: &'a [NetVoltage],
    /// The per-net networks, or why they could not be built.
    pub networks: Result<&'a NetNetworks, PowerError>,
    /// The solved supply grid, or `None` when intent declared no supplies.
    pub power: Power<'a>,
    /// The die boundary: the denominator of every density.
    pub die: Bbox,
    /// The deck's grid, stack and connectivity. The grid turns a width in
    /// database units into metres for a current-density limit, and a diode's
    /// area into the square micrometres an antenna credit is stated per; the
    /// stack and connectivity build the ESD stress networks.
    pub process: Process<'a>,
    /// The applied sign-off temperature, absolute; distinct from each row's
    /// characterisation temperature.
    pub operating_temperature: Qty<Temperature, { prefix::BASE }>,
}

/// The dielectric between two layers of the `pex` stack, nm: the upper
/// layer's height less the lower layer's height and thickness. `None` when
/// the stack does not state both layers (no row, or a thickness of 0) or
/// they overlap in height.
fn vertical_gap(stack: &ProcessStack, a: LayerId, b: LayerId) -> Option<f64> {
    let row = |layer: LayerId| {
        let thickness = *stack.thickness_nm.get(layer.idx())?;
        (thickness > 0.0).then(|| (stack.height_nm[layer.idx()], thickness))
    };
    let (mut lower, mut upper) = (row(a)?, row(b)?);
    if upper.0 < lower.0 {
        std::mem::swap(&mut lower, &mut upper);
    }
    let gap = upper.0 - (lower.0 + lower.1);
    (gap > 0.0).then_some(gap)
}

fn narrow(len: usize) -> u32 {
    u32::try_from(len).expect("a deck's rule columns are far short of four billion entries")
}

/// Close one CSR row: the leading zero on the first row, then the running end.
fn close_csr(start: &mut Vec<u32>, end: usize) {
    if start.is_empty() {
        start.push(0);
    }
    start.push(narrow(end));
}

/// One deck row, and the typed parameter lookups. Physical parameters arrive
/// as [`ParamValue::Ratio`] already in their column's unit. Each lookup checks
/// the value's type only; what values a row can hold is [`RuleSet::validate`]'s.
#[derive(Clone, Copy)]
struct Row<'a> {
    rules: &'a RuleTable,
    strings: &'a StrTable,
    spec: &'a RuleSpec,
}

impl Row<'_> {
    /// The deck's id for this row, as text (error paths only).
    fn name(&self) -> String {
        self.strings.resolve(self.spec.id).to_owned()
    }

    fn wrong_type(&self, param: &'static str) -> ErcError {
        ErcError::WrongParamType {
            rule: self.name(),
            param,
        }
    }

    /// The row's layers, refused unless `fits(count)`; `expected` is what the
    /// error reports.
    fn layers_where(&self, expected: u32, fits: bool) -> Result<&[LayerId], ErcError> {
        let found = self.rules.layers_of(self.spec);
        if fits {
            Ok(found)
        } else {
            Err(ErcError::WrongLayerCount {
                rule: self.name(),
                expected,
                found: narrow(found.len()),
            })
        }
    }

    /// Exactly `expected` layers.
    fn layers(&self, expected: u32) -> Result<&[LayerId], ErcError> {
        let count = narrow(self.rules.layers_of(self.spec).len());
        self.layers_where(expected, count == expected)
    }

    /// At least `least` layers.
    fn layers_from(&self, least: u32) -> Result<&[LayerId], ErcError> {
        let count = narrow(self.rules.layers_of(self.spec).len());
        self.layers_where(least, count >= least)
    }

    fn find(&self, param: &'static str) -> Option<ParamValue> {
        self.rules.param(self.spec, self.strings.get(param)?)
    }

    fn need(&self, param: &'static str) -> Result<ParamValue, ErcError> {
        self.find(param).ok_or_else(|| ErcError::MissingParam {
            rule: self.name(),
            param,
        })
    }

    /// A distance.
    fn length(&self, param: &'static str) -> Result<Dbu, ErcError> {
        match self.need(param)? {
            ParamValue::Length(value) => Ok(value),
            _ => Err(self.wrong_type(param)),
        }
    }

    fn opt_length(&self, param: &'static str) -> Result<Option<Dbu>, ErcError> {
        match self.find(param) {
            None => Ok(None),
            Some(_) => self.length(param).map(Some),
        }
    }

    /// A number in its column's unit.
    fn number(&self, param: &'static str) -> Result<f64, ErcError> {
        match self.need(param)? {
            ParamValue::Ratio(value) => Ok(value),
            _ => Err(self.wrong_type(param)),
        }
    }

    /// A piecewise-linear table, `(area, value)` points in deck order; empty
    /// when absent.
    fn area_table(
        &self,
        area: &'static str,
        value: &'static str,
    ) -> Result<Vec<(DbuArea, f64)>, ErcError> {
        let (Some(area_key), Some(value_key)) = (self.strings.get(area), self.strings.get(value))
        else {
            return Ok(Vec::new());
        };
        let (mut areas, mut values) = (Vec::new(), Vec::new());
        for &(key, param) in self.rules.params_of(self.spec) {
            match param {
                ParamValue::Area(at) if key == area_key => areas.push(at),
                ParamValue::Ratio(of) if key == value_key => values.push(of),
                _ if key == area_key || key == value_key => return Err(self.wrong_type(value)),
                _ => {}
            }
        }
        if areas.len() != values.len() {
            return Err(self.wrong_type(value));
        }
        Ok(areas.into_iter().zip(values).collect())
    }

    fn opt_number(&self, param: &'static str) -> Result<Option<f64>, ErcError> {
        match self.find(param) {
            None => Ok(None),
            Some(_) => self.number(param).map(Some),
        }
    }

    fn count(&self, param: &'static str) -> Result<u32, ErcError> {
        match self.need(param)? {
            ParamValue::Count(value) => Ok(value),
            _ => Err(self.wrong_type(param)),
        }
    }

    fn opt_layer(&self, param: &'static str) -> Result<Option<LayerId>, ErcError> {
        match self.find(param) {
            None => Ok(None),
            Some(ParamValue::Layer(value)) => Ok(Some(value)),
            Some(_) => Err(self.wrong_type(param)),
        }
    }

    /// Every length named by a repeated `param`, in deck order; empty when
    /// absent.
    fn lengths(&self, param: &'static str) -> Result<Vec<Dbu>, ErcError> {
        let Some(name) = self.strings.get(param) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for &(key, value) in self.rules.params_of(self.spec) {
            if key == name {
                match value {
                    ParamValue::Length(length) => out.push(length),
                    _ => return Err(self.wrong_type(param)),
                }
            }
        }
        Ok(out)
    }

    /// Every model named by a repeated `param`, in deck order; empty when absent.
    fn models(&self, param: &'static str) -> Result<Vec<StrId>, ErcError> {
        let Some(name) = self.strings.get(param) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for &(key, value) in self.rules.params_of(self.spec) {
            if key == name {
                match value {
                    ParamValue::Model(model) => out.push(model),
                    _ => return Err(self.wrong_type(param)),
                }
            }
        }
        Ok(out)
    }

    /// An antenna row's one collecting measure: a row states one
    /// `sidewall_thickness`, or none for the drawn area.
    fn antenna_measure(&self) -> Result<antenna::AntennaMeasure, ErcError> {
        Ok(match self.opt_length("sidewall_thickness")? {
            Some(thickness) => antenna::AntennaMeasure::Sidewall { thickness },
            None => antenna::AntennaMeasure::Area,
        })
    }

    fn flag(&self, param: &'static str, absent: bool) -> Result<bool, ErcError> {
        match self.find(param) {
            None => Ok(absent),
            Some(ParamValue::Flag(value)) => Ok(value),
            Some(_) => Err(self.wrong_type(param)),
        }
    }

    /// A voltage-dependent spacing table: the repeated `voltage` (mV) and
    /// `space` parameters, one step each, in deck order. The voltages are
    /// zero or more and rise strictly; the spaces are positive and never
    /// fall; there is one space per voltage.
    #[allow(
        clippy::type_complexity,
        reason = "the two columns of one table, returned together"
    )]
    fn voltage_table(&self) -> Result<(Vec<Qty<Voltage, { prefix::MILLI }>>, Vec<Dbu>), ErcError> {
        let (voltage_key, space_key) = (self.strings.get("voltage"), self.strings.get("space"));
        let (mut voltage, mut space) = (Vec::new(), Vec::new());
        for &(key, value) in self.rules.params_of(self.spec) {
            if Some(key) == voltage_key {
                match value {
                    ParamValue::Ratio(millivolts) if millivolts.is_finite() => {
                        voltage.push(millivolts);
                    }
                    _ => return Err(self.wrong_type("voltage")),
                }
            } else if Some(key) == space_key {
                match value {
                    ParamValue::Length(length) => space.push(length),
                    _ => return Err(self.wrong_type("space")),
                }
            }
        }
        for (empty, param) in [(voltage.is_empty(), "voltage"), (space.is_empty(), "space")] {
            if empty {
                return Err(ErcError::MissingParam {
                    rule: self.name(),
                    param,
                });
            }
        }
        let bad = |why| ErcError::BadTable {
            rule: self.name(),
            why,
        };
        if voltage.len() != space.len() {
            return Err(bad("a voltage table needs one space per voltage"));
        }
        Ok((voltage.into_iter().map(Qty::new).collect(), space))
    }

    /// Push the row's head; `warning = true` demotes it from `Error`. Parsed
    /// before either column is pushed.
    fn head(&self, head: &mut RuleHead) -> Result<(), ErcError> {
        let severity = if self.flag("warning", false)? {
            Severity::Warning
        } else {
            Severity::Error
        };
        head.rule.push(self.spec.id);
        head.severity.push(severity);
        Ok(())
    }
}

/// The value checks of [`RuleSet::validate`], for one rule.
struct Check<'a> {
    /// The rule's id, for the error.
    rule: &'a str,
}

impl Check<'_> {
    /// A finite number: an infinite limit would pass everything.
    fn finite(&self, param: &'static str, value: f64) -> Result<(), ErcError> {
        if value.is_finite() {
            Ok(())
        } else {
            Err(ErcError::WrongParamType {
                rule: self.rule.to_owned(),
                param,
            })
        }
    }

    /// A finite, strictly positive number.
    fn positive(&self, param: &'static str, value: f64) -> Result<(), ErcError> {
        self.finite(param, value)?;
        if value > 0.0 {
            Ok(())
        } else {
            Err(self.non_positive(param))
        }
    }

    /// A finite number of zero or more.
    fn not_negative(&self, param: &'static str, value: f64) -> Result<(), ErcError> {
        self.finite(param, value)?;
        if value >= 0.0 {
            Ok(())
        } else {
            Err(self.non_positive(param))
        }
    }

    /// A strictly positive distance.
    fn length(&self, param: &'static str, value: Dbu) -> Result<(), ErcError> {
        if value.raw() > 0 {
            Ok(())
        } else {
            Err(self.non_positive(param))
        }
    }

    /// A fraction in `0.0 ..= 1.0`.
    fn fraction(&self, param: &'static str, value: f64) -> Result<(), ErcError> {
        self.finite(param, value)?;
        if (0.0..=1.0).contains(&value) {
            Ok(())
        } else {
            Err(ErcError::NotAFraction {
                rule: self.rule.to_owned(),
                param,
            })
        }
    }

    fn non_positive(&self, param: &'static str) -> ErcError {
        ErcError::NonPositiveLimit {
            rule: self.rule.to_owned(),
            limit: param.to_owned(),
        }
    }

    fn missing(&self, param: &'static str) -> ErcError {
        ErcError::MissingParam {
            rule: self.rule.to_owned(),
            param,
        }
    }
}

impl RuleSet {
    /// Builds the tables from a deck, holding each row to [`Self::validate`]'s
    /// checks as it is filed. Fails closed on any row of a kind in [`KINDS`] it
    /// cannot read; rows of other kinds are stepped over. The antenna tables
    /// also take a copy of the deck's connectivity.
    ///
    /// # Errors
    ///
    /// Returns the first [`ErcError`] in deck order: a rule id used twice by
    /// rows of any kind, or, in a row of a kind in [`KINDS`], a missing or
    /// mistyped parameter or a wrong layer count, then what
    /// [`Self::validate`] refuses of it.
    ///
    /// # Panics
    ///
    /// Panics if one table's layer or model column outgrows a `u32` index.
    pub fn from_deck(deck: &Deck, strings: &StrTable) -> Result<Self, ErcError> {
        let mut set = Self::default();
        // Sorted ids already filed; the first duplicate in deck order is refused.
        let mut seen: Vec<StrId> = Vec::with_capacity(deck.rules.spec.len());
        // A cut collects by its area whatever the row's measure: LEF's cut
        // layers "do not use side area modelling".
        let cut_by_area = |layer: LayerId, measure: antenna::AntennaMeasure| {
            if deck.connectivity.via_cut.contains(&layer) {
                antenna::AntennaMeasure::Area
            } else {
                measure
            }
        };

        for spec in &deck.rules.spec {
            let row = Row {
                rules: &deck.rules,
                strings,
                spec,
            };
            match seen.binary_search(&spec.id) {
                Ok(_) => return Err(ErcError::DuplicateRule(row.name())),
                Err(at) => seen.insert(at, spec.id),
            }

            // Every arm reads its parameters before touching a table, so a row
            // of the wrong shape leaves no half-written column; its values are
            // checked once it is filed.
            let kind = strings.resolve(spec.kind);
            match kind {
                "antenna" => {
                    let layers = row.layers_from(2)?;
                    let max_ratio = row.number("max_ratio")?;
                    let measure = row.antenna_measure()?;
                    let diode = row.opt_layer("diode_layer")?;
                    let table = &mut set.antenna;
                    row.head(&mut table.head)?;
                    table.gate.push(layers[0]);
                    table.diode.push(diode);
                    table.collector.extend_from_slice(&layers[1..]);
                    table
                        .collector_measure
                        .extend(layers[1..].iter().map(|&layer| cut_by_area(layer, measure)));
                    table.max_ratio.push(max_ratio);
                    close_csr(&mut table.collector_start, table.collector.len());
                }
                "antenna_electrical" => {
                    let layers = row.layers_from(2)?;
                    let max_ratio = row.number("max_ratio")?;
                    let measure = row.antenna_measure()?;
                    let diode = row.opt_layer("diode_layer")?;
                    let credit = row.opt_number("diode_credit")?.unwrap_or(0.0);
                    let bonus = row.opt_number("diode_bonus")?.unwrap_or(0.0);
                    let minus = row.opt_number("area_minus_diode")?.unwrap_or(0.0);
                    let plus = row.opt_number("gate_plus_diode")?.unwrap_or(0.0);
                    let reduce = row.area_table("diode_reduce_area", "diode_reduce")?;
                    let diode_max = row.area_table("diode_max_ratio_area", "diode_max_ratio")?;
                    let cut_factor = row.number("cut_factor")?;
                    let exempt = row.opt_layer("exempt_layer")?;
                    let table = &mut set.antenna_electrical;
                    row.head(&mut table.head)?;
                    table.gate.push(layers[0]);
                    table.collector.extend_from_slice(&layers[1..]);
                    table
                        .collector_measure
                        .extend(layers[1..].iter().map(|&layer| cut_by_area(layer, measure)));
                    table.cut_factor.push(cut_factor);
                    table.diode.push(diode);
                    table.diode_credit.push(credit);
                    table.diode_bonus.push(bonus);
                    table.area_minus_diode.push(minus);
                    table.gate_plus_diode.push(plus);
                    table.diode_reduce.push(reduce);
                    table.diode_max_ratio.push(diode_max);
                    table.exempt.push(exempt);
                    table.max_ratio.push(max_ratio);
                    close_csr(&mut table.collector_start, table.collector.len());
                }
                "density_cmp" => {
                    let layers = row.layers(1)?;
                    let window = (row.length("window_x")?, row.length("window_y")?);
                    let step = (row.length("step_x")?, row.length("step_y")?);
                    let min_density = row.opt_number("min_density")?;
                    let max_density = row.opt_number("max_density")?;
                    let max_neighbour_delta = row.opt_number("max_neighbour_delta")?;
                    let include_partial_windows = row.flag("include_partial_windows", true)?;
                    // The three coefficients are one model: all or none.
                    let cmp = match row.find("cmp_target_density") {
                        None => None,
                        Some(_) => Some(antenna::CmpModel {
                            target_density: row.number("cmp_target_density")?,
                            thickness_sensitivity: row.length("cmp_thickness_sensitivity")?,
                            max_abs_thickness_delta: row.length("cmp_max_abs_thickness_delta")?,
                        }),
                    };
                    let table = &mut set.density_cmp;
                    row.head(&mut table.head)?;
                    table.layer.push(layers[0]);
                    table.window.push(window);
                    table.step.push(step);
                    table.min_density.push(min_density);
                    table.max_density.push(max_density);
                    table.max_neighbour_delta.push(max_neighbour_delta);
                    table.cmp.push(cmp);
                    table.include_partial_windows.push(include_partial_windows);
                }
                "electromigration" => {
                    let layers = row.layers_from(1)?;
                    let max_density = Qty::new(row.number("max_density")?);
                    let per_cut = Qty::new(row.number("max_current_per_cut")?);
                    let blech = Qty::new(row.number("blech_limit")?);
                    let reference = Qty::new(row.number("reference_temperature")?);
                    let activation = row.number("activation_energy_ev")?;
                    let exponent = row.number("current_exponent")?;
                    let table = &mut set.electromigration;
                    row.head(&mut table.head)?;
                    table.layer.extend_from_slice(layers);
                    table.max_density.extend(layers.iter().map(|_| max_density));
                    table
                        .max_current_per_cut
                        .extend(layers.iter().map(|_| per_cut));
                    table.blech_limit.extend(layers.iter().map(|_| blech));
                    table.reference_temperature.push(reference);
                    table.activation_energy_ev.push(activation);
                    table.current_exponent.push(exponent);
                    close_csr(&mut table.layer_start, table.layer.len());
                }
                "em_current_density" => {
                    let layers = row.layers_from(1)?;
                    let max_density = Qty::new(row.number("max_density")?);
                    let per_cut = Qty::new(row.number("max_current_per_cut")?);
                    // The band's width and current are one statement: both or none.
                    let narrow = match row.opt_length("narrow_width")? {
                        Some(width) => Some((width, Qty::new(row.number("narrow_current")?))),
                        None => None,
                    };
                    let table = &mut set.em_current_density;
                    row.head(&mut table.head)?;
                    table.layer.extend_from_slice(layers);
                    table.max_density.extend(layers.iter().map(|_| max_density));
                    table
                        .max_current_per_cut
                        .extend(layers.iter().map(|_| per_cut));
                    table.narrow.extend(layers.iter().map(|_| narrow));
                    close_csr(&mut table.layer_start, table.layer.len());
                }
                "esd_latchup" => {
                    let layers = row.layers(2)?;
                    let min_guard_ring_width = row.length("min_guard_ring_width")?;
                    let max_tap_distance = row.length("max_tap_distance")?;
                    let clamps = row.models("clamp")?;
                    let table = &mut set.esd_latchup;
                    row.head(&mut table.head)?;
                    table.pad.push(layers[0]);
                    table.clamp.extend(clamps);
                    close_csr(&mut table.clamp_start, table.clamp.len());
                    table.guard_ring.push(layers[1]);
                    table.min_guard_ring_width.push(min_guard_ring_width);
                    table.max_tap_distance.push(max_tap_distance);
                }
                "conditional_tie" => {
                    let layers = row.layers(4)?;
                    let within = row.length("within")?;
                    let spacing = row.lengths("spacing")?;
                    let max_distance = row.lengths("max_distance")?;
                    let table = &mut set.conditional_tie;
                    row.head(&mut table.head)?;
                    table.region.push(layers[0]);
                    table.tap.push(layers[1]);
                    table.well.push(layers[2]);
                    table.other.push(layers[3]);
                    table.within.push(within);
                    table.spacing.extend(spacing);
                    close_csr(&mut table.spacing_start, table.spacing.len());
                    table.max_distance.extend(max_distance);
                    close_csr(&mut table.max_distance_start, table.max_distance.len());
                }
                "esd_cross_domain" => {
                    row.layers(0)?;
                    let diodes = row.models("diode")?;
                    let local = row.models("local")?;
                    let table = &mut set.esd_cross_domain;
                    row.head(&mut table.head)?;
                    table.diode.extend(diodes);
                    close_csr(&mut table.diode_start, table.diode.len());
                    table.local.extend(local);
                    close_csr(&mut table.local_start, table.local.len());
                }
                "esd_exposed" => {
                    let layers = row.layers(1)?;
                    let clamps = row.models("clamp")?;
                    let resistors = row.models("resistor")?;
                    let rated = row.models("rated")?;
                    let table = &mut set.esd_exposed;
                    row.head(&mut table.head)?;
                    table.pad.push(layers[0]);
                    table.clamp.extend(clamps);
                    close_csr(&mut table.clamp_start, table.clamp.len());
                    table.resistor.extend(resistors);
                    close_csr(&mut table.resistor_start, table.resistor.len());
                    table.rated.extend(rated);
                    close_csr(&mut table.rated_start, table.rated.len());
                }
                "esd_ground_coupling" => {
                    row.layers(0)?;
                    let diodes = row.models("diode")?;
                    let table = &mut set.esd_ground_coupling;
                    row.head(&mut table.head)?;
                    table.diode.extend(diodes);
                    close_csr(&mut table.diode_start, table.diode.len());
                }
                "esd_parasitic" => {
                    let layers = row.layers(2)?;
                    let min_spacing = row.length("min_spacing")?;
                    let table = &mut set.esd_parasitic;
                    row.head(&mut table.head)?;
                    table.pad.push(layers[0]);
                    table.diffusion.push(layers[1]);
                    table.min_spacing.push(min_spacing);
                }
                "esd_path" => {
                    let layers = row.layers_from(1)?;
                    if layers.len() > 2 {
                        return Err(ErcError::WrongLayerCount {
                            rule: row.name(),
                            expected: 2,
                            found: narrow(layers.len()),
                        });
                    }
                    let clamps = row.models("clamp")?;
                    let current = Qty::new(row.number("current")?);
                    let clamp_resistance = Qty::new(row.number("clamp_resistance")?);
                    let max_resistance = row.opt_number("max_resistance")?.map(Qty::new);
                    let clamp_it2 = row.opt_number("clamp_it2")?.map(Qty::new);
                    let max_density = row.opt_number("max_density")?.map(Qty::new);
                    let per_cut = row.opt_number("max_current_per_cut")?.map(Qty::new);
                    let max_voltage = row.opt_number("max_voltage")?.map(Qty::new);
                    let table = &mut set.esd_path;
                    row.head(&mut table.head)?;
                    table.pad.push(layers[0]);
                    table
                        .source
                        .push(layers.get(1).copied().unwrap_or(layers[0]));
                    table.clamp.extend(clamps);
                    close_csr(&mut table.clamp_start, table.clamp.len());
                    table.current.push(current);
                    table.clamp_resistance.push(clamp_resistance);
                    table.max_resistance.push(max_resistance);
                    table.clamp_it2.push(clamp_it2);
                    table.max_density.push(max_density);
                    table.max_current_per_cut.push(per_cut);
                    table.max_voltage.push(max_voltage);
                }
                "forward_diode" => {
                    let layers = row.layers(1)?;
                    let models = row.models("model")?;
                    let table = &mut set.forward_diode;
                    row.head(&mut table.head)?;
                    table.marker.push(layers[0]);
                    table.model.extend(models);
                    close_csr(&mut table.model_start, table.model.len());
                }
                "guard_ring" => {
                    let layers = row.layers(2)?;
                    let max_space = row.opt_length("max_space")?;
                    let min_width = row.opt_length("min_width")?;
                    let pad = row.opt_layer("pad")?;
                    // `near` and `within` are one condition: both or neither.
                    let near = match (row.opt_layer("near")?, row.opt_length("within")?) {
                        (Some(layer), Some(within)) => Some((layer, within)),
                        (None, None) => None,
                        (Some(_), None) => {
                            return Err(ErcError::MissingParam {
                                rule: row.name(),
                                param: "within",
                            })
                        }
                        (None, Some(_)) => {
                            return Err(ErcError::MissingParam {
                                rule: row.name(),
                                param: "near",
                            })
                        }
                    };
                    let table = &mut set.guard_ring;
                    row.head(&mut table.head)?;
                    table.target.push(layers[0]);
                    table.ring.push(layers[1]);
                    table.max_space.push(max_space);
                    table.min_width.push(min_width);
                    table.pad.push(pad);
                    table.near.push(near);
                }
                "guard_ring_bias" => {
                    let layers = row.layers(1)?;
                    let power = row.flag("power", true)?;
                    let table = &mut set.guard_ring_bias;
                    row.head(&mut table.head)?;
                    table.ring.push(layers[0]);
                    table.power.push(power);
                }
                "latchup_victim" => {
                    let layers = row.layers(3)?;
                    let within = row.length("within")?;
                    let max_distance = row.length("max_distance")?;
                    let pad = row.opt_layer("pad")?;
                    let table = &mut set.latchup_victim;
                    row.head(&mut table.head)?;
                    table.aggressor.push(layers[0]);
                    table.region.push(layers[1]);
                    table.tap.push(layers[2]);
                    table.within.push(within);
                    table.max_distance.push(max_distance);
                    table.pad.push(pad);
                }
                "tie_area" => {
                    let layers = row.layers(3)?;
                    let min_ratio = row.number("min_ratio")?;
                    let table = &mut set.tie_area;
                    row.head(&mut table.head)?;
                    table.region.push(layers[0]);
                    table.contact.push(layers[1]);
                    table.channel.push(layers[2]);
                    table.min_ratio.push(min_ratio);
                }
                "esd_topological" => {
                    let layers = row.layers(1)?;
                    let clamps = row.models("clamp")?;
                    let table = &mut set.esd_topological;
                    row.head(&mut table.head)?;
                    table.pad.push(layers[0]);
                    table.clamp.extend(clamps);
                    close_csr(&mut table.clamp_start, table.clamp.len());
                }
                "gate_oxide" | "drain_source" => {
                    row.layers(0)?;
                    let models = row.models("model")?;
                    let max_voltage = Qty::new(row.number("max_voltage")?);
                    let table = if kind == "gate_oxide" {
                        &mut set.gate_oxide
                    } else {
                        &mut set.drain_source
                    };
                    row.head(&mut table.head)?;
                    table.model.extend(models);
                    close_csr(&mut table.model_start, table.model.len());
                    table.max_voltage.push(max_voltage);
                }
                "well_bias" => {
                    row.layers(0)?;
                    let pmos = row.models("pmos")?;
                    let nmos = row.models("nmos")?;
                    let table = &mut set.well_bias;
                    row.head(&mut table.head)?;
                    table.pmos.extend(pmos);
                    close_csr(&mut table.pmos_start, table.pmos.len());
                    table.nmos.extend(nmos);
                    close_csr(&mut table.nmos_start, table.nmos.len());
                }
                "missing_level_shifter" => {
                    row.layers(0)?;
                    let shifters = row.models("shifter")?;
                    let table = &mut set.missing_level_shifter;
                    row.head(&mut table.head)?;
                    table.shifter.extend(shifters);
                    close_csr(&mut table.shifter_start, table.shifter.len());
                }
                "domain_crossing" => {
                    row.layers(0)?;
                    row.head(&mut set.domain_crossing.head)?;
                }
                "undriven_gate" => {
                    row.layers(0)?;
                    row.head(&mut set.undriven_gate.head)?;
                }
                "missing_isolation" => {
                    row.layers(0)?;
                    let isolation = row.models("isolation")?;
                    let table = &mut set.missing_isolation;
                    row.head(&mut table.head)?;
                    table.isolation.extend(isolation);
                    close_csr(&mut table.isolation_start, table.isolation.len());
                }
                "hv_tag" => {
                    let layers = row.layers(2)?;
                    let voltage = Qty::new(row.number("voltage")?);
                    let table = &mut set.hv_tag;
                    row.head(&mut table.head)?;
                    table.layer.push(layers[0]);
                    table.tag.push(layers[1]);
                    table.voltage.push(voltage);
                }
                "mixed_tag" => {
                    let layers = row.layers(2)?;
                    let table = &mut set.mixed_tag;
                    row.head(&mut table.head)?;
                    table.layer.push(layers[0]);
                    table.tag.push(layers[1]);
                }
                "dielectric_field" => {
                    let count = narrow(row.rules.layers_of(row.spec).len());
                    let layers = row.layers_where(2, (1..=2).contains(&count))?;
                    let max_field = row.number("max_field")?;
                    let vertical = match layers.get(1) {
                        None => Some(0.0),
                        Some(&b) => vertical_gap(&deck.stack, layers[0], b),
                    };
                    let table = &mut set.dielectric_field;
                    row.head(&mut table.head)?;
                    table.layer.push(layers[0]);
                    table.other.push(layers.get(1).copied());
                    table.max_field.push(max_field);
                    table.vertical_nm.push(vertical);
                }
                "voltage_spacing" => {
                    let count = narrow(row.rules.layers_of(row.spec).len());
                    let layers = row.layers_where(2, (1..=2).contains(&count))?;
                    let (voltage, space) = row.voltage_table()?;
                    let table = &mut set.voltage_spacing;
                    row.head(&mut table.head)?;
                    table.layer.push(layers[0]);
                    table.other.push(layers.get(1).copied());
                    table.voltage.extend(voltage);
                    table.space.extend(space);
                    close_csr(&mut table.step_start, table.space.len());
                }
                "floating_gate" => {
                    row.layers(0)?;
                    let labels_are_ports = row.flag("labels_are_ports", false)?;
                    row.head(&mut set.floating_gate.head)?;
                    set.floating_gate.labels_are_ports.push(labels_are_ports);
                }
                "fanout" => {
                    row.layers(0)?;
                    let max_gates = row.count("max_gates")?;
                    let table = &mut set.fanout;
                    row.head(&mut table.head)?;
                    table.max_gates.push(max_gates);
                }
                "floating_well" => {
                    let layers = row.layers(2)?;
                    let table = &mut set.floating_well;
                    row.head(&mut table.head)?;
                    table.well.push(layers[0]);
                    table.tap.push(layers[1]);
                }
                "hv_domain" => {
                    row.layers(0)?;
                    let max_domain_delta = Qty::new(row.number("max_domain_delta")?);
                    let isolation = row.opt_layer("isolation")?;
                    let table = &mut set.hv_domain;
                    row.head(&mut table.head)?;
                    table.max_domain_delta.push(max_domain_delta);
                    table.isolation.push(isolation);
                }
                "ir_drop" => {
                    row.layers(0)?;
                    row.head(&mut set.ir_drop.head)?;
                }
                "dynamic_ir_drop" => {
                    row.layers(0)?;
                    row.head(&mut set.dynamic_ir_drop.head)?;
                }
                "em_thermal" => {
                    let layers = row.layers_from(1)?;
                    let max_density = Qty::new(row.number("max_density")?);
                    let per_cut = Qty::new(row.number("max_current_per_cut")?);
                    let blech = Qty::new(row.number("blech_limit")?);
                    let reference = Qty::new(row.number("reference_temperature")?);
                    let activation = row.number("activation_energy_ev")?;
                    let exponent = row.number("current_exponent")?;
                    let conductivity = row.number("thermal_conductivity")?;
                    let spreading = row.number("heat_spreading")?;
                    let sigma = row.number("sigma")?;
                    let limit_failure = row.number("limit_failure")?;
                    let max_failure = row.number("max_failure")?;
                    let table = &mut set.em_thermal;
                    row.head(&mut table.head)?;
                    table.layer.extend_from_slice(layers);
                    table.max_density.extend(layers.iter().map(|_| max_density));
                    table
                        .max_current_per_cut
                        .extend(layers.iter().map(|_| per_cut));
                    table.blech_limit.extend(layers.iter().map(|_| blech));
                    table.reference_temperature.push(reference);
                    table.activation_energy_ev.push(activation);
                    table.current_exponent.push(exponent);
                    table.thermal_conductivity.push(conductivity);
                    table.heat_spreading.push(spreading);
                    table.sigma.push(sigma);
                    table.limit_failure.push(limit_failure);
                    table.max_failure.push(max_failure);
                    close_csr(&mut table.layer_start, table.layer.len());
                }
                "missing_tie" => {
                    let layers = row.layers(2)?;
                    let max_distance = row.length("max_distance")?;
                    let table = &mut set.missing_tie;
                    row.head(&mut table.head)?;
                    table.region.push(layers[0]);
                    table.tap.push(layers[1]);
                    table.max_distance.push(max_distance);
                }
                "multiple_drivers" => {
                    row.layers(0)?;
                    let max_drivers = row.count("max_drivers")?;
                    let table = &mut set.multiple_drivers;
                    row.head(&mut table.head)?;
                    table.max_drivers.push(max_drivers);
                }
                "p2p_resistance" => {
                    row.layers(0)?;
                    let max_resistance = Qty::new(row.number("max_resistance")?);
                    let table = &mut set.p2p_resistance;
                    row.head(&mut table.head)?;
                    table.max_resistance.push(max_resistance);
                }
                "reliability" => {
                    row.layers(0)?;
                    let required_lifetime_hours = row.number("required_lifetime_hours")?;
                    let reference_lifetime_hours = row.number("reference_lifetime_hours")?;
                    let reference_stress = Qty::new(row.number("reference_stress")?);
                    let stress_exponent = row.number("stress_exponent")?;
                    let reference_temperature = Qty::new(row.number("reference_temperature")?);
                    let activation_energy_ev = row.number("activation_energy_ev")?;
                    let max_abs_voltage = Qty::new(row.number("max_abs_voltage")?);
                    let duty_cycle = row.number("duty_cycle")?;
                    let table = &mut set.reliability;
                    row.head(&mut table.head)?;
                    table.required_lifetime_hours.push(required_lifetime_hours);
                    table
                        .reference_lifetime_hours
                        .push(reference_lifetime_hours);
                    table.reference_stress.push(reference_stress);
                    table.stress_exponent.push(stress_exponent);
                    table.reference_temperature.push(reference_temperature);
                    table.activation_energy_ev.push(activation_energy_ev);
                    table.duty_cycle.push(duty_cycle);
                    table.max_abs_voltage.push(max_abs_voltage);
                }
                "soft_connection" => {
                    let layers = row.layers_from(1)?;
                    let table = &mut set.soft_connection;
                    row.head(&mut table.head)?;
                    table.soft.extend_from_slice(layers);
                    close_csr(&mut table.soft_start, table.soft.len());
                }
                "supply_short" => {
                    let layers = row.layers_from(2)?;
                    let table = &mut set.supply_short;
                    row.head(&mut table.head)?;
                    table.tap_a.push(layers[0]);
                    table.tap_b.push(layers[1]);
                    table.within.push(layers.get(2).copied());
                }
                "tie_high_low" => {
                    row.layers(0)?;
                    row.head(&mut set.tie_high_low.head)?;
                }
                "unconnected_pin" => {
                    let layers = row.layers_from(1)?;
                    let table = &mut set.unconnected_pin;
                    row.head(&mut table.head)?;
                    table.layer.extend_from_slice(layers);
                    close_csr(&mut table.layer_start, table.layer.len());
                }
                // Another domain's row; a kind no domain knows is refused by
                // `CompiledDeck::from_deck`.
                _ => continue,
            }
            let filed = set.head_of(kind).len() - 1;
            set.check_row(kind, filed, strings)?;
        }
        set.soft_connection.connectivity = deck.connectivity.clone();
        set.em_thermal.height_nm.clone_from(&deck.stack.height_nm);
        for stack in [&mut set.antenna.stack, &mut set.antenna_electrical.stack] {
            let from = &deck.connectivity;
            stack.conductors.clone_from(&from.conductors);
            stack.vias = from
                .via_cut
                .iter()
                .zip(&from.via_connects)
                .map(|(&cut, &(a, b))| (cut, a, b))
                .collect();
            stack.intra_layer_touch = from.intra_layer_touch;
            let devices = &deck.devices;
            stack.gates = (0..devices.kind.len())
                .filter(|&i| devices.kind[i] == DeviceKind::Mos)
                .filter_map(|i| devices.terminal.get(devices.terminal_start[i] as usize))
                .copied()
                .collect();
        }
        Ok(set)
    }

    /// Whether every row's values are ones its kind can hold: every limit,
    /// rating and lifetime finite and positive, every distance positive,
    /// every fraction in `0.0 ..= 1.0` (a duty cycle also above 0), a
    /// `density_cmp` row bounding something, a `well_bias` row naming a
    /// model, the clamp and model lists of the kinds that need one not empty,
    /// and `max_drivers` at least 1. [`Self::from_deck`] holds each row to
    /// this as it is filed; tables built in code are held to the same.
    ///
    /// Rows are checked table by table in [`KINDS`] order, each row's values
    /// in the order its kind reads them.
    ///
    /// # Errors
    ///
    /// The first failing value: [`ErcError::WrongParamType`] for a number that
    /// is not finite, [`ErcError::NonPositiveLimit`],
    /// [`ErcError::NotAFraction`], or [`ErcError::MissingParam`] for a row
    /// that bounds or names nothing.
    ///
    /// # Panics
    ///
    /// When a table's columns break the
    /// [table invariants](crate::erc::rules#tables).
    pub fn validate(&self, strings: &StrTable) -> Result<(), ErcError> {
        for kind in KINDS {
            for row in 0..self.head_of(kind).len() {
                self.check_row(kind, row, strings)?;
            }
        }
        Ok(())
    }

    /// Every row's rule id with its kind, table by table in [`KINDS`] order.
    pub fn rules(&self) -> impl Iterator<Item = (StrId, &'static str)> + '_ {
        KINDS.into_iter().flat_map(move |kind| {
            self.head_of(kind)
                .rule
                .iter()
                .map(move |&rule| (rule, kind))
        })
    }

    /// The head of the table of `kind`, one of [`KINDS`].
    fn head_of(&self, kind: &str) -> &RuleHead {
        match kind {
            "antenna" => &self.antenna.head,
            "antenna_electrical" => &self.antenna_electrical.head,
            "density_cmp" => &self.density_cmp.head,
            "domain_crossing" => &self.domain_crossing.head,
            "drain_source" => &self.drain_source.head,
            "electromigration" => &self.electromigration.head,
            "em_current_density" => &self.em_current_density.head,
            "dynamic_ir_drop" => &self.dynamic_ir_drop.head,
            "em_thermal" => &self.em_thermal.head,
            "esd_latchup" => &self.esd_latchup.head,
            "esd_topological" => &self.esd_topological.head,
            "esd_path" => &self.esd_path.head,
            "esd_ground_coupling" => &self.esd_ground_coupling.head,
            "esd_cross_domain" => &self.esd_cross_domain.head,
            "esd_parasitic" => &self.esd_parasitic.head,
            "esd_exposed" => &self.esd_exposed.head,
            "guard_ring_bias" => &self.guard_ring_bias.head,
            "tie_area" => &self.tie_area.head,
            "guard_ring" => &self.guard_ring.head,
            "forward_diode" => &self.forward_diode.head,
            "conditional_tie" => &self.conditional_tie.head,
            "latchup_victim" => &self.latchup_victim.head,
            "floating_gate" => &self.floating_gate.head,
            "floating_well" => &self.floating_well.head,
            "gate_oxide" => &self.gate_oxide.head,
            "hv_domain" => &self.hv_domain.head,
            "ir_drop" => &self.ir_drop.head,
            "missing_level_shifter" => &self.missing_level_shifter.head,
            "missing_tie" => &self.missing_tie.head,
            "multiple_drivers" => &self.multiple_drivers.head,
            "p2p_resistance" => &self.p2p_resistance.head,
            "reliability" => &self.reliability.head,
            "soft_connection" => &self.soft_connection.head,
            "supply_short" => &self.supply_short.head,
            "tie_high_low" => &self.tie_high_low.head,
            "unconnected_pin" => &self.unconnected_pin.head,
            "well_bias" => &self.well_bias.head,
            "voltage_spacing" => &self.voltage_spacing.head,
            "dielectric_field" => &self.dielectric_field.head,
            "hv_tag" => &self.hv_tag.head,
            "mixed_tag" => &self.mixed_tag.head,
            "fanout" => &self.fanout.head,
            "undriven_gate" => &self.undriven_gate.head,
            "missing_isolation" => &self.missing_isolation.head,
            other => unreachable!("{other} is not an ERC kind"),
        }
    }

    /// [`Self::validate`] for row `r` of the table of `kind`.
    fn check_row(&self, kind: &str, r: usize, strings: &StrTable) -> Result<(), ErcError> {
        let c = Check {
            rule: strings.resolve(self.head_of(kind).rule[r]),
        };
        let span = |start: &[u32]| start[r] as usize..start[r + 1] as usize;
        match kind {
            "antenna" => {
                let t = &self.antenna;
                c.positive("max_ratio", t.max_ratio[r])?;
                for &measure in &t.collector_measure[span(&t.collector_start)] {
                    if let antenna::AntennaMeasure::Sidewall { thickness } = measure {
                        c.length("sidewall_thickness", thickness)?;
                    }
                }
            }
            "antenna_electrical" => {
                let t = &self.antenna_electrical;
                c.positive("max_ratio", t.max_ratio[r])?;
                c.finite("diode_credit", t.diode_credit[r])?;
                c.finite("diode_bonus", t.diode_bonus[r])?;
                c.not_negative("area_minus_diode", t.area_minus_diode[r])?;
                c.not_negative("gate_plus_diode", t.gate_plus_diode[r])?;
                c.positive("cut_factor", t.cut_factor[r])?;
                for &measure in &t.collector_measure[span(&t.collector_start)] {
                    if let antenna::AntennaMeasure::Sidewall { thickness } = measure {
                        c.length("sidewall_thickness", thickness)?;
                    }
                }
                for &(_, factor) in &t.diode_reduce[r] {
                    c.not_negative("diode_reduce", factor)?;
                }
                for &(_, limit) in &t.diode_max_ratio[r] {
                    c.positive("diode_max_ratio", limit)?;
                }
            }
            "density_cmp" => {
                let t = &self.density_cmp;
                c.length("window_x", t.window[r].0)?;
                c.length("window_y", t.window[r].1)?;
                c.length("step_x", t.step[r].0)?;
                c.length("step_y", t.step[r].1)?;
                for (param, bound) in [
                    ("min_density", t.min_density[r]),
                    ("max_density", t.max_density[r]),
                    ("max_neighbour_delta", t.max_neighbour_delta[r]),
                ] {
                    if let Some(value) = bound {
                        c.fraction(param, value)?;
                    }
                }
                if let Some(cmp) = t.cmp[r] {
                    c.fraction("cmp_target_density", cmp.target_density)?;
                    c.length("cmp_max_abs_thickness_delta", cmp.max_abs_thickness_delta)?;
                }
                // A row bounding nothing would report clean forever.
                if t.min_density[r].is_none()
                    && t.max_density[r].is_none()
                    && t.max_neighbour_delta[r].is_none()
                    && t.cmp[r].is_none()
                {
                    return Err(c.missing("max_density"));
                }
            }
            "electromigration" => {
                let t = &self.electromigration;
                for at in span(&t.layer_start) {
                    c.positive("max_density", t.max_density[at].raw())?;
                    c.positive("max_current_per_cut", t.max_current_per_cut[at].raw())?;
                    c.positive("blech_limit", t.blech_limit[at].raw())?;
                }
                c.positive("reference_temperature", t.reference_temperature[r].raw())?;
                c.positive("activation_energy_ev", t.activation_energy_ev[r])?;
                c.positive("current_exponent", t.current_exponent[r])?;
            }
            "em_current_density" => {
                let t = &self.em_current_density;
                for at in span(&t.layer_start) {
                    c.positive("max_density", t.max_density[at].raw())?;
                    c.positive("max_current_per_cut", t.max_current_per_cut[at].raw())?;
                    if let Some((width, current)) = t.narrow[at] {
                        c.length("narrow_width", width)?;
                        c.positive("narrow_current", current.raw())?;
                    }
                }
            }
            "em_thermal" => {
                let t = &self.em_thermal;
                for at in span(&t.layer_start) {
                    c.positive("max_density", t.max_density[at].raw())?;
                    c.positive("max_current_per_cut", t.max_current_per_cut[at].raw())?;
                    c.positive("blech_limit", t.blech_limit[at].raw())?;
                }
                c.positive("reference_temperature", t.reference_temperature[r].raw())?;
                c.positive("activation_energy_ev", t.activation_energy_ev[r])?;
                c.positive("current_exponent", t.current_exponent[r])?;
                c.positive("thermal_conductivity", t.thermal_conductivity[r])?;
                c.positive("sigma", t.sigma[r])?;
                // Zero spreading is a one-dimensional heat path; less is no
                // geometry.
                c.finite("heat_spreading", t.heat_spreading[r])?;
                if t.heat_spreading[r] < 0.0 {
                    return Err(c.non_positive("heat_spreading"));
                }
                // A characterisation at 0 or 1 has no quantile; a budget of 0
                // flags any wire that carries current.
                for (param, value) in [
                    ("limit_failure", t.limit_failure[r]),
                    ("max_failure", t.max_failure[r]),
                ] {
                    c.fraction(param, value)?;
                    if value <= 0.0 {
                        return Err(c.non_positive(param));
                    }
                }
                if t.limit_failure[r] >= 1.0 {
                    return Err(ErcError::NotAFraction {
                        rule: c.rule.to_owned(),
                        param: "limit_failure",
                    });
                }
            }
            "esd_latchup" => {
                let t = &self.esd_latchup;
                c.length("min_guard_ring_width", t.min_guard_ring_width[r])?;
                c.length("max_tap_distance", t.max_tap_distance[r])?;
                if span(&t.clamp_start).is_empty() {
                    return Err(c.missing("clamp"));
                }
            }
            "esd_topological" if span(&self.esd_topological.clamp_start).is_empty() => {
                return Err(c.missing("clamp"));
            }
            "esd_path" => {
                let t = &self.esd_path;
                c.positive("current", t.current[r].raw())?;
                c.positive("clamp_resistance", t.clamp_resistance[r].raw())?;
                let limits = [
                    ("max_resistance", t.max_resistance[r].map(Qty::raw)),
                    ("clamp_it2", t.clamp_it2[r].map(Qty::raw)),
                    ("max_density", t.max_density[r].map(Qty::raw)),
                    (
                        "max_current_per_cut",
                        t.max_current_per_cut[r].map(Qty::raw),
                    ),
                    ("max_voltage", t.max_voltage[r].map(Qty::raw)),
                ];
                for (param, limit) in limits {
                    if let Some(value) = limit {
                        c.positive(param, value)?;
                    }
                }
                // A row bounding nothing would report clean forever.
                if limits.iter().all(|(_, limit)| limit.is_none()) {
                    return Err(c.missing("max_resistance"));
                }
            }
            "esd_ground_coupling" if span(&self.esd_ground_coupling.diode_start).is_empty() => {
                return Err(c.missing("diode"));
            }
            "esd_cross_domain" if span(&self.esd_cross_domain.diode_start).is_empty() => {
                return Err(c.missing("diode"));
            }
            "esd_exposed" if span(&self.esd_exposed.clamp_start).is_empty() => {
                return Err(c.missing("clamp"));
            }
            "esd_parasitic" => c.length("min_spacing", self.esd_parasitic.min_spacing[r])?,
            "forward_diode" if span(&self.forward_diode.model_start).is_empty() => {
                return Err(c.missing("model"));
            }
            "guard_ring" => {
                let t = &self.guard_ring;
                if let Some(space) = t.max_space[r] {
                    c.length("max_space", space)?;
                }
                if let Some(width) = t.min_width[r] {
                    c.length("min_width", width)?;
                }
                if let Some((_, within)) = t.near[r] {
                    c.length("within", within)?;
                }
            }
            "tie_area" => c.fraction("min_ratio", self.tie_area.min_ratio[r])?,
            "conditional_tie" => {
                let t = &self.conditional_tie;
                c.length("within", t.within[r])?;
                let spacing = &t.spacing[span(&t.spacing_start)];
                let limits = &t.max_distance[span(&t.max_distance_start)];
                for &value in spacing {
                    c.length("spacing", value)?;
                }
                for &value in limits {
                    c.length("max_distance", value)?;
                }
                // One more limit than thresholds, thresholds ascending.
                if limits.len() != spacing.len() + 1
                    || spacing.windows(2).any(|pair| pair[0] >= pair[1])
                {
                    return Err(ErcError::WrongParamType {
                        rule: c.rule.to_owned(),
                        param: "max_distance",
                    });
                }
            }
            "latchup_victim" => {
                let t = &self.latchup_victim;
                c.length("within", t.within[r])?;
                c.length("max_distance", t.max_distance[r])?;
            }
            "gate_oxide" | "drain_source" => {
                let t = if kind == "gate_oxide" {
                    &self.gate_oxide
                } else {
                    &self.drain_source
                };
                if span(&t.model_start).is_empty() {
                    return Err(c.missing("model"));
                }
                c.positive("max_voltage", t.max_voltage[r].raw())?;
            }
            // A row naming no model would check nothing.
            "well_bias" => {
                let t = &self.well_bias;
                if span(&t.pmos_start).is_empty() && span(&t.nmos_start).is_empty() {
                    return Err(c.missing("pmos"));
                }
            }
            "hv_domain" => {
                c.positive("max_domain_delta", self.hv_domain.max_domain_delta[r].raw())?;
            }
            "missing_tie" => c.length("max_distance", self.missing_tie.max_distance[r])?,
            // Zero permitted drivers flags every driven net.
            "multiple_drivers" if self.multiple_drivers.max_drivers[r] == 0 => {
                return Err(c.non_positive("max_drivers"));
            }
            "p2p_resistance" => {
                c.positive(
                    "max_resistance",
                    self.p2p_resistance.max_resistance[r].raw(),
                )?;
            }
            "reliability" => {
                let t = &self.reliability;
                c.positive("required_lifetime_hours", t.required_lifetime_hours[r])?;
                c.positive("reference_lifetime_hours", t.reference_lifetime_hours[r])?;
                c.positive("reference_stress", t.reference_stress[r].raw())?;
                c.positive("stress_exponent", t.stress_exponent[r])?;
                c.positive("reference_temperature", t.reference_temperature[r].raw())?;
                c.positive("activation_energy_ev", t.activation_energy_ev[r])?;
                c.positive("max_abs_voltage", t.max_abs_voltage[r].raw())?;
                // A zero duty cycle makes every lifetime infinite.
                c.fraction("duty_cycle", t.duty_cycle[r])?;
                if t.duty_cycle[r] <= 0.0 {
                    return Err(c.non_positive("duty_cycle"));
                }
            }
            "hv_tag" => c.positive("voltage", self.hv_tag.voltage[r].raw())?,
            "dielectric_field" => c.positive("max_field", self.dielectric_field.max_field[r])?,
            // Zero permitted gates flags every gate net.
            "fanout" if self.fanout.max_gates[r] == 0 => {
                return Err(c.non_positive("max_gates"));
            }
            "voltage_spacing" => {
                let t = &self.voltage_spacing;
                let steps = span(&t.step_start);
                let (voltage, space) = (&t.voltage[steps.clone()], &t.space[steps]);
                let bad = |why| ErcError::BadTable {
                    rule: c.rule.to_owned(),
                    why,
                };
                if voltage.is_empty() {
                    return Err(c.missing("voltage"));
                }
                for step in voltage {
                    c.finite("voltage", step.raw())?;
                }
                if voltage[0].raw() < 0.0
                    || voltage
                        .windows(2)
                        .any(|pair| pair[0].raw() >= pair[1].raw())
                {
                    return Err(bad(
                        "a voltage table's voltages start at 0 V or more and rise strictly",
                    ));
                }
                for &step in space {
                    c.length("space", step)?;
                }
                if space.windows(2).any(|pair| pair[1] < pair[0]) {
                    return Err(bad(
                        "a voltage table's spaces never fall as the voltage rises",
                    ));
                }
            }
            // Nothing beyond the layers and models each row names.
            _ => {}
        }
        Ok(())
    }

    /// Configured rule rows across every table: the number of `RuleRun` rows a
    /// run produces.
    pub fn len(&self) -> usize {
        [
            &self.floating_gate.head,
            &self.floating_well.head,
            &self.multiple_drivers.head,
            &self.unconnected_pin.head,
            &self.fanout.head,
            &self.supply_short.head,
            &self.soft_connection.head,
            &self.missing_tie.head,
            &self.tie_high_low.head,
            &self.esd_topological.head,
            &self.mixed_tag.head,
            &self.antenna.head,
            &self.antenna_electrical.head,
            &self.density_cmp.head,
            &self.p2p_resistance.head,
            &self.ir_drop.head,
            &self.em_current_density.head,
            &self.electromigration.head,
            &self.dynamic_ir_drop.head,
            &self.em_thermal.head,
            &self.reliability.head,
            &self.hv_domain.head,
            &self.esd_latchup.head,
            &self.gate_oxide.head,
            &self.drain_source.head,
            &self.well_bias.head,
            &self.missing_level_shifter.head,
            &self.domain_crossing.head,
            &self.voltage_spacing.head,
            &self.hv_tag.head,
            &self.undriven_gate.head,
            &self.missing_isolation.head,
            &self.dielectric_field.head,
            &self.esd_path.head,
            &self.esd_ground_coupling.head,
            &self.esd_cross_domain.head,
            &self.esd_parasitic.head,
            &self.esd_exposed.head,
            &self.guard_ring_bias.head,
            &self.tie_area.head,
            &self.guard_ring.head,
            &self.forward_diode.head,
            &self.conditional_tie.head,
            &self.latchup_victim.head,
        ]
        .iter()
        .map(|head| head.len())
        .sum()
    }

    /// True when the deck configures no ERC row.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Runs every table once, appending to `out` and `runs`: exactly one
    /// `RuleRun` per configured row, and none for an empty table.
    ///
    /// # Panics
    ///
    /// Panics if a table's columns break the
    /// [table invariants](crate::erc::rules#tables), as one assembled by hand
    /// rather than by [`RuleSet::from_deck`] can.
    pub fn run(
        &self,
        inputs: RunInputs<'_>,
        scratch: &mut Scratch,
        out: &mut Violations,
        runs: &mut Vec<RuleRun>,
    ) {
        let RunInputs {
            design,
            facts,
            ports,
            intent,
            voltage,
            states,
            networks,
            power,
            die,
            process,
            operating_temperature,
        } = inputs;
        let grid = process.grid;

        topology::check_floating_gate(design, facts, ports, &self.floating_gate, out, runs);
        topology::check_floating_well(design, &self.floating_well, scratch, out, runs);
        topology::check_multiple_drivers(
            design,
            intent,
            &self.multiple_drivers,
            scratch,
            out,
            runs,
        );
        topology::check_unconnected_pin(design, facts, &self.unconnected_pin, out, runs);
        topology::check_fanout(design, &self.fanout, out, runs);

        supply::check_supply_short(design, &self.supply_short, scratch, out, runs);
        supply::check_soft_connection(design, &self.soft_connection, scratch, out, runs);
        supply::check_missing_tie(design, &self.missing_tie, scratch, out, runs);
        supply::check_tie_high_low(design, facts, intent, &self.tie_high_low, out, runs);
        supply::check_esd_topological(design, intent, &self.esd_topological, out, runs);
        supply::check_mixed_tag(design, &self.mixed_tag, out, runs);

        antenna::check_antenna(design, &self.antenna, scratch, out, runs);
        antenna::check_antenna_electrical(
            design,
            grid,
            &self.antenna_electrical,
            scratch,
            out,
            runs,
        );
        antenna::check_density_cmp(design, die, &self.density_cmp, scratch, out, runs);

        electrical::check_p2p_resistance(
            design,
            networks,
            &self.p2p_resistance,
            scratch,
            out,
            runs,
        );
        electrical::check_ir_drop(power, intent, &self.ir_drop, out, runs);
        electrical::check_em_current_density(
            power,
            intent,
            grid,
            &self.em_current_density,
            out,
            runs,
        );
        electrical::check_electromigration(
            power,
            intent,
            grid,
            operating_temperature,
            &self.electromigration,
            out,
            runs,
        );
        electrical::check_dynamic_ir_drop(power, intent, &self.dynamic_ir_drop, scratch, out, runs);
        electrical::check_em_thermal(
            power,
            intent,
            grid,
            operating_temperature,
            &self.em_thermal,
            out,
            runs,
        );

        reliability::check_reliability(
            power,
            intent,
            operating_temperature,
            &self.reliability,
            out,
            runs,
        );
        reliability::check_hv_domain(design, intent, voltage, &self.hv_domain, out, runs);
        reliability::check_esd_latchup(design, intent, &self.esd_latchup, scratch, out, runs);

        esd::check_esd_path(design, intent, process, &self.esd_path, scratch, out, runs);
        esd::check_esd_ground_coupling(design, intent, &self.esd_ground_coupling, out, runs);
        esd::check_esd_cross_domain(design, intent, voltage, &self.esd_cross_domain, out, runs);
        esd::check_esd_parasitic(design, &self.esd_parasitic, out, runs);
        esd::check_esd_exposed(design, intent, &self.esd_exposed, out, runs);

        latchup::check_guard_ring_bias(design, intent, &self.guard_ring_bias, out, runs);
        latchup::check_tie_area(design, &self.tie_area, scratch, out, runs);
        latchup::check_guard_ring(design, &self.guard_ring, scratch, out, runs);
        latchup::check_forward_diode(design, intent, voltage, &self.forward_diode, out, runs);
        latchup::check_conditional_tie(design, &self.conditional_tie, scratch, out, runs);
        latchup::check_latchup_victim(design, &self.latchup_victim, scratch, out, runs);

        domain::check_gate_oxide(design, intent, voltage, &self.gate_oxide, out, runs);
        domain::check_drain_source(design, intent, voltage, &self.drain_source, out, runs);
        domain::check_well_bias(design, intent, voltage, &self.well_bias, out, runs);
        domain::check_missing_level_shifter(
            design,
            intent,
            voltage,
            &self.missing_level_shifter,
            out,
            runs,
        );
        domain::check_domain_crossing(design, intent, voltage, &self.domain_crossing, out, runs);
        domain::check_voltage_spacing(design, intent, voltage, &self.voltage_spacing, out, runs);
        domain::check_hv_tag(design, intent, voltage, &self.hv_tag, out, runs);
        domain::check_dielectric_field(
            design,
            intent,
            voltage,
            grid,
            &self.dielectric_field,
            out,
            runs,
        );
        domain::check_undriven_gate(
            design,
            intent,
            voltage,
            states,
            &self.undriven_gate,
            out,
            runs,
        );
        domain::check_missing_isolation(
            design,
            intent,
            voltage,
            states,
            &self.missing_isolation,
            out,
            runs,
        );
    }
}
