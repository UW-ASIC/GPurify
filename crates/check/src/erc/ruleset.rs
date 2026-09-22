//! The nineteen tables, the deck parser that fills them, and the dispatcher.
//!
//! Data in: a deck's rule table. Data out: a [`RuleSet`]; [`RuleSet::run`]
//! produces violations and exactly one `RuleRun` per configured row.

use crate::erc::facts::{IntentMap, NetFacts};
use crate::erc::power::{NetNetworks, Solved};
use crate::erc::rules::{antenna, electrical, reliability, supply, topology};
use crate::erc::{Design, ErcError, Scratch};
use crate::report::{RuleRun, Severity, Violations};
use gpurify_geom::{prefix, Dbu, Grid, Qty, Temperature};
use gpurify_geom::{Bbox, LayerId};
use gpurify_ingest::deck::{Deck, ParamValue, RuleSpec, RuleTable};
use gpurify_ingest::{StrId, StrTable};

/// Every rule kind this crate implements, as the deck spells it. Any other
/// kind belongs to another domain and is stepped over.
pub const KINDS: [&str; 19] = [
    "antenna",
    "antenna_electrical",
    "density_cmp",
    "electromigration",
    "em_current_density",
    "esd_latchup",
    "esd_topological",
    "floating_gate",
    "floating_well",
    "hv_domain",
    "ir_drop",
    "missing_tie",
    "multiple_drivers",
    "p2p_resistance",
    "reliability",
    "soft_connection",
    "supply_short",
    "tie_high_low",
    "unconnected_pin",
];

/// The two columns every rule table has.
#[derive(Debug, Default)]
pub struct RuleHead {
    /// The deck's id for this rule, interned; what a `RuleRun` is attributed to.
    pub rule: Vec<StrId>,
    pub severity: Vec<Severity>,
}

impl RuleHead {
    pub fn len(&self) -> usize {
        self.rule.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rule.is_empty()
    }
}

/// Every configured rule, one table per kind.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub floating_gate: topology::FloatingGateTable,
    pub floating_well: topology::FloatingWellTable,
    pub multiple_drivers: topology::MultipleDriversTable,
    pub unconnected_pin: topology::UnconnectedPinTable,

    pub supply_short: supply::SupplyShortTable,
    pub soft_connection: supply::SoftConnectionTable,
    pub missing_tie: supply::MissingTieTable,
    pub tie_high_low: supply::TieHighLowTable,
    pub esd_topological: supply::EsdTopologicalTable,

    pub antenna: antenna::AntennaTable,
    pub antenna_electrical: antenna::AntennaElectricalTable,
    pub density_cmp: antenna::DensityCmpTable,

    pub p2p_resistance: electrical::P2pResistanceTable,
    pub ir_drop: electrical::IrDropTable,
    pub em_current_density: electrical::EmCurrentDensityTable,
    pub electromigration: electrical::ElectromigrationTable,

    pub reliability: reliability::ReliabilityTable,
    pub hv_domain: reliability::HvDomainTable,
    pub esd_latchup: reliability::EsdLatchupTable,
}

/// Everything one run reads, borrowed.
#[derive(Debug, Clone, Copy)]
pub struct RunInputs<'a> {
    pub design: Design<'a>,
    pub facts: &'a NetFacts,
    pub intent: &'a IntentMap,
    pub networks: &'a NetNetworks,
    /// The solved supply grid, or `None` when intent declared no supplies.
    pub power: Option<Solved<'a>>,
    /// The die boundary: the denominator of every density.
    pub die: Bbox,
    pub grid: Grid,
    /// The applied sign-off temperature, absolute; distinct from each row's
    /// characterisation temperature.
    pub operating_temperature: Qty<Temperature, { prefix::BASE }>,
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
/// as [`ParamValue::Ratio`] already in their column's unit.
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

    fn non_positive(&self, param: &'static str) -> ErcError {
        ErcError::NonPositiveLimit {
            rule: self.name(),
            limit: param.to_owned(),
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

    /// A strictly positive distance.
    fn length(&self, param: &'static str) -> Result<Dbu, ErcError> {
        match self.need(param)? {
            ParamValue::Length(value) if value.raw() > 0 => Ok(value),
            ParamValue::Length(_) => Err(self.non_positive(param)),
            _ => Err(self.wrong_type(param)),
        }
    }

    fn opt_length(&self, param: &'static str) -> Result<Option<Dbu>, ErcError> {
        match self.find(param) {
            None => Ok(None),
            Some(_) => self.length(param).map(Some),
        }
    }

    /// A distance of either sign.
    fn signed_length(&self, param: &'static str) -> Result<Dbu, ErcError> {
        match self.need(param)? {
            ParamValue::Length(value) => Ok(value),
            _ => Err(self.wrong_type(param)),
        }
    }

    /// A finite `f64`: an infinite limit would pass everything.
    fn number(&self, param: &'static str) -> Result<f64, ErcError> {
        match self.need(param)? {
            ParamValue::Ratio(value) if value.is_finite() => Ok(value),
            _ => Err(self.wrong_type(param)),
        }
    }

    fn opt_number(&self, param: &'static str, absent: f64) -> Result<f64, ErcError> {
        match self.find(param) {
            None => Ok(absent),
            Some(_) => self.number(param),
        }
    }

    /// A finite, strictly positive `f64`.
    fn positive(&self, param: &'static str) -> Result<f64, ErcError> {
        let value = self.number(param)?;
        if value > 0.0 {
            Ok(value)
        } else {
            Err(self.non_positive(param))
        }
    }

    /// A fraction in `0.0 ..= 1.0`.
    fn fraction(&self, param: &'static str) -> Result<f64, ErcError> {
        let value = self.number(param)?;
        if (0.0..=1.0).contains(&value) {
            Ok(value)
        } else {
            Err(ErcError::NotAFraction {
                rule: self.name(),
                param,
            })
        }
    }

    fn opt_fraction(&self, param: &'static str) -> Result<Option<f64>, ErcError> {
        match self.find(param) {
            None => Ok(None),
            Some(_) => self.fraction(param).map(Some),
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

    fn flag(&self, param: &'static str, absent: bool) -> Result<bool, ErcError> {
        match self.find(param) {
            None => Ok(absent),
            Some(ParamValue::Flag(value)) => Ok(value),
            Some(_) => Err(self.wrong_type(param)),
        }
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

impl RuleSet {
    /// Build the tables from a deck. Fails closed on any row of a kind in
    /// [`KINDS`] it cannot read; rows of other kinds are stepped over.
    pub fn from_deck(deck: &Deck, strings: &StrTable) -> Result<Self, ErcError> {
        let mut set = Self::default();
        // Sorted ids already filed; the first duplicate in deck order is refused.
        let mut seen: Vec<StrId> = Vec::with_capacity(deck.rules.spec.len());

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

            // Every arm reads its parameters before touching a table, so a
            // refused row leaves no half-written column.
            match strings.resolve(spec.kind) {
                "antenna" => {
                    let layers = row.layers_from(2)?;
                    let max_ratio = row.positive("max_ratio")?;
                    // One measure for the whole collecting set: a row states
                    // one `sidewall_thickness`.
                    let measure = match row.opt_length("sidewall_thickness")? {
                        Some(thickness) => antenna::AntennaMeasure::Sidewall { thickness },
                        None => antenna::AntennaMeasure::Area,
                    };
                    let table = &mut set.antenna;
                    row.head(&mut table.head)?;
                    table.gate.push(layers[0]);
                    table.collector.extend_from_slice(&layers[1..]);
                    table
                        .collector_measure
                        .extend(layers[1..].iter().map(|_| measure));
                    table.max_ratio.push(max_ratio);
                    close_csr(&mut table.collector_start, table.collector.len());
                }
                "antenna_electrical" => {
                    let layers = row.layers_from(2)?;
                    let max_ratio = row.positive("max_ratio")?;
                    let diode = row.opt_layer("diode_layer")?;
                    let credit = row.opt_number("diode_credit", 0.0)?;
                    let bonus = row.opt_number("diode_bonus", 0.0)?;
                    let table = &mut set.antenna_electrical;
                    row.head(&mut table.head)?;
                    table.gate.push(layers[0]);
                    table.collector.extend_from_slice(&layers[1..]);
                    table.diode.push(diode);
                    table.diode_credit.push(credit);
                    table.diode_bonus.push(bonus);
                    table.max_ratio.push(max_ratio);
                    close_csr(&mut table.collector_start, table.collector.len());
                }
                "density_cmp" => {
                    let layers = row.layers(1)?;
                    let window = (row.length("window_x")?, row.length("window_y")?);
                    let step = (row.length("step_x")?, row.length("step_y")?);
                    let min_density = row.opt_fraction("min_density")?;
                    let max_density = row.opt_fraction("max_density")?;
                    let max_neighbour_delta = row.opt_fraction("max_neighbour_delta")?;
                    let include_partial_windows = row.flag("include_partial_windows", true)?;
                    // The four coefficients are one model: all or none.
                    let cmp = match row.find("cmp_target_density") {
                        None => None,
                        Some(_) => Some(antenna::CmpModel {
                            target_density: row.fraction("cmp_target_density")?,
                            nominal_thickness: row.length("cmp_nominal_thickness")?,
                            thickness_sensitivity: row
                                .signed_length("cmp_thickness_sensitivity")?,
                            max_abs_thickness_delta: row.length("cmp_max_abs_thickness_delta")?,
                        }),
                    };
                    // A row bounding nothing would report clean forever.
                    if min_density.is_none()
                        && max_density.is_none()
                        && max_neighbour_delta.is_none()
                        && cmp.is_none()
                    {
                        return Err(ErcError::MissingParam {
                            rule: row.name(),
                            param: "max_density",
                        });
                    }
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
                    let max_density = Qty::new(row.positive("max_density")?);
                    let per_cut = Qty::new(row.positive("max_current_per_cut")?);
                    let blech = Qty::new(row.positive("blech_limit")?);
                    let reference = Qty::new(row.positive("reference_temperature")?);
                    let activation = row.positive("activation_energy_ev")?;
                    let exponent = row.positive("current_exponent")?;
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
                    let max_density = Qty::new(row.positive("max_density")?);
                    let per_cut = Qty::new(row.positive("max_current_per_cut")?);
                    let table = &mut set.em_current_density;
                    row.head(&mut table.head)?;
                    table.layer.extend_from_slice(layers);
                    table.max_density.extend(layers.iter().map(|_| max_density));
                    table
                        .max_current_per_cut
                        .extend(layers.iter().map(|_| per_cut));
                    close_csr(&mut table.layer_start, table.layer.len());
                }
                "esd_latchup" => {
                    let layers = row.layers(2)?;
                    // Validated but unused: they qualify clamp devices, and a
                    // deck cannot name a clamp model (`ParamValue` has no
                    // string), so every pad is flagged as unprotected.
                    row.positive("required_current")?;
                    row.positive("max_path_resistance")?;
                    row.positive("max_clamp_voltage")?;
                    let min_guard_ring_width = row.length("min_guard_ring_width")?;
                    let max_tap_distance = row.length("max_tap_distance")?;
                    let table = &mut set.esd_latchup;
                    row.head(&mut table.head)?;
                    table.pad.push(layers[0]);
                    table.guard_ring.push(layers[1]);
                    table.min_guard_ring_width.push(min_guard_ring_width);
                    table.max_tap_distance.push(max_tap_distance);
                }
                "esd_topological" => {
                    let layers = row.layers(1)?;
                    let table = &mut set.esd_topological;
                    row.head(&mut table.head)?;
                    table.pad.push(layers[0]);
                }
                "floating_gate" => {
                    row.layers(0)?;
                    row.head(&mut set.floating_gate.head)?;
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
                    let max_domain_delta = Qty::new(row.positive("max_domain_delta")?);
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
                    // Zero permitted drivers flags every driven net.
                    if max_drivers == 0 {
                        return Err(row.non_positive("max_drivers"));
                    }
                    let table = &mut set.multiple_drivers;
                    row.head(&mut table.head)?;
                    table.max_drivers.push(max_drivers);
                }
                "p2p_resistance" => {
                    row.layers(0)?;
                    let max_resistance = Qty::new(row.positive("max_resistance")?);
                    let table = &mut set.p2p_resistance;
                    row.head(&mut table.head)?;
                    table.max_resistance.push(max_resistance);
                }
                "reliability" => {
                    row.layers(0)?;
                    let required_lifetime_hours = row.positive("required_lifetime_hours")?;
                    let reference_lifetime_hours = row.positive("reference_lifetime_hours")?;
                    let reference_stress = Qty::new(row.positive("reference_stress")?);
                    let stress_exponent = row.positive("stress_exponent")?;
                    let reference_temperature = Qty::new(row.positive("reference_temperature")?);
                    let activation_energy_ev = row.positive("activation_energy_ev")?;
                    let max_abs_voltage = Qty::new(row.positive("max_abs_voltage")?);
                    // A zero duty cycle makes every lifetime infinite.
                    let duty_cycle = row.fraction("duty_cycle")?;
                    if duty_cycle <= 0.0 {
                        return Err(row.non_positive("duty_cycle"));
                    }
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
                    let layers = row.layers(2)?;
                    let table = &mut set.supply_short;
                    row.head(&mut table.head)?;
                    table.tap_a.push(layers[0]);
                    table.tap_b.push(layers[1]);
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
                // Another domain's row; the engine refuses a kind no domain knows.
                _ => {}
            }
        }
        Ok(set)
    }

    /// Configured rule rows across every table: the number of `RuleRun` rows a
    /// run produces.
    pub fn len(&self) -> usize {
        [
            &self.floating_gate.head,
            &self.floating_well.head,
            &self.multiple_drivers.head,
            &self.unconnected_pin.head,
            &self.supply_short.head,
            &self.soft_connection.head,
            &self.missing_tie.head,
            &self.tie_high_low.head,
            &self.esd_topological.head,
            &self.antenna.head,
            &self.antenna_electrical.head,
            &self.density_cmp.head,
            &self.p2p_resistance.head,
            &self.ir_drop.head,
            &self.em_current_density.head,
            &self.electromigration.head,
            &self.reliability.head,
            &self.hv_domain.head,
            &self.esd_latchup.head,
        ]
        .iter()
        .map(|head| head.len())
        .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Run every table once, appending to `out` and `runs`. An empty table
    /// produces no `RuleRun`.
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
            intent,
            networks,
            power,
            die,
            grid,
            operating_temperature,
        } = inputs;

        topology::check_floating_gate(design, facts, &self.floating_gate, out, runs);
        topology::check_floating_well(design, &self.floating_well, scratch, out, runs);
        topology::check_multiple_drivers(design, &self.multiple_drivers, scratch, out, runs);
        topology::check_unconnected_pin(design, facts, &self.unconnected_pin, out, runs);

        supply::check_supply_short(design, &self.supply_short, scratch, out, runs);
        supply::check_soft_connection(design, &self.soft_connection, scratch, out, runs);
        supply::check_missing_tie(design, &self.missing_tie, scratch, out, runs);
        supply::check_tie_high_low(design, facts, &self.tie_high_low, out, runs);
        supply::check_esd_topological(design, &self.esd_topological, out, runs);

        antenna::check_antenna(design, &self.antenna, scratch, out, runs);
        antenna::check_antenna_electrical(design, &self.antenna_electrical, scratch, out, runs);
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

        reliability::check_reliability(
            power,
            intent,
            operating_temperature,
            &self.reliability,
            out,
            runs,
        );
        reliability::check_hv_domain(design, intent, &self.hv_domain, out, runs);
        reliability::check_esd_latchup(design, intent, &self.esd_latchup, scratch, out, runs);
    }
}
