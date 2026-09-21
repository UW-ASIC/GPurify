//! The nineteen tables, and the dispatcher that runs each one once.

use crate::erc::facts::{IntentMap, NetFacts};
use crate::erc::power::{NetNetworks, Solved};
use crate::erc::rules::{antenna, electrical, reliability, supply, topology};
use crate::erc::{Design, ErcError, Scratch};
use gpurify_geom::{Bbox, LayerId};
use gpurify_geom::LayerRef;
use gpurify_ingest::deck::{Deck, ParamValue, RuleSpec, RuleTable};
use gpurify_ingest::{StrId, StrTable};
use crate::report::{RuleRun, Severity, Violations};
use gpurify_geom::{prefix, Dbu, Grid, Qty, Temperature};

/// Every rule kind this crate implements, as the deck spells it.
///
/// A kind absent from this array belongs to another domain and is stepped over
/// by [`RuleSet::from_deck`]; the engine is what refuses a kind that is in
/// neither this array nor `crate::drc::ruleset::KINDS`.
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
    /// The deck's id for this rule, interned; what [`RuleRun`] is attributed to.
    pub rule: Vec<StrId>,
    pub severity: Vec<Severity>,
}

impl RuleHead {
    pub fn len(&self) -> usize {
        debug_assert_eq!(
            self.rule.len(),
            self.severity.len(),
            "a rule row without a severity, or a severity without a row"
        );
        self.rule.len()
    }

    /// True when the deck configured no row of this kind.
    ///
    /// An empty table produces no [`RuleRun`] at all: the deck did not ask for
    /// this rule, so nothing claims it was checked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    /// Per-net role masks from [`crate::erc::classify_nets_into`].
    pub facts: &'a NetFacts,
    /// Design intent re-keyed onto nets.
    pub intent: &'a IntentMap,
    /// Per-net resistor networks from [`crate::erc::power::extract_nets_into`].
    pub networks: &'a NetNetworks,
    /// The solved supply grid, or `None` when intent declared no supplies. Four
    /// rules record themselves skipped on `None`.
    pub power: Option<Solved<'a>>,
    /// The die boundary — the denominator of every density fraction.
    pub die: Bbox,
    /// The run's manufacturing grid.
    pub grid: Grid,
    /// The temperature the design is signed off at, absolute. The *applied*
    /// point, distinct from each rule row's characterisation temperature.
    pub operating_temperature: Qty<Temperature, { prefix::BASE }>,
}

/// Narrow a column length to the `u32` every CSR index in this crate is.
///
/// Panicking rather than erroring: a deck with four billion layer references in
/// one rule is not a deck a typed error would help anyone fix.
fn narrow(len: usize) -> u32 {
    u32::try_from(len).expect("a deck's rule columns are far short of four billion entries")
}

/// Close one CSR row: the leading zero on the first row, the running end after
/// every row. `start.len()` is therefore `rows + 1` for a non-empty table and
/// `0` for an untouched one.
fn close_csr(start: &mut Vec<u32>, end: usize) {
    if start.is_empty() {
        start.push(0);
    }
    start.push(narrow(end));
    debug_assert!(
        start.windows(2).all(|pair| pair[0] <= pair[1]),
        "a CSR row ended before it began"
    );
}

/// One deck row, and the lookups every arm of [`RuleSet::from_deck`] needs.
///
/// A parameter is spelled exactly as the column it fills. Physical parameters
/// arrive as [`ParamValue::Ratio`] and are read in the unit their column
/// already carries — ohms, millivolts, microamps (milliamps for `esd_latchup`),
/// amps per metre, kelvin absolute, hours — so the conversion is the identity
/// and no rounding enters a limit.
#[derive(Clone, Copy)]
struct Row<'a> {
    rules: &'a RuleTable,
    strings: &'a StrTable,
    spec: &'a RuleSpec,
}

impl Row<'_> {
    /// The deck's id for this row, as text. Only ever built on an error path.
    fn name(&self) -> String {
        self.strings.resolve(self.spec.id).to_owned()
    }

    fn wrong_type(&self, param: &'static str) -> ErcError {
        ErcError::WrongParamType {
            rule: self.name(),
            param,
        }
    }

    /// Exactly `expected` layers, or the row is refused.
    fn layers(&self, expected: u32) -> Result<&[LayerId], ErcError> {
        let found = self.rules.layers_of(self.spec);
        let count = narrow(found.len());
        (count == expected)
            .then_some(found)
            .ok_or_else(|| ErcError::WrongLayerCount {
                rule: self.name(),
                expected,
                found: count,
            })
    }

    /// At least `least` layers — the CSR kinds, whose list has no fixed length.
    fn layers_from(&self, least: u32) -> Result<&[LayerId], ErcError> {
        let found = self.rules.layers_of(self.spec);
        let count = narrow(found.len());
        (count >= least)
            .then_some(found)
            .ok_or_else(|| ErcError::WrongLayerCount {
                rule: self.name(),
                expected: least,
                found: count,
            })
    }

    /// A parameter the deck may omit. `None` covers both "the string table has
    /// never seen this name" and "this row does not carry it".
    fn find(&self, param: &'static str) -> Option<ParamValue> {
        self.rules.param(self.spec, self.strings.get(param)?)
    }

    fn need(&self, param: &'static str) -> Result<ParamValue, ErcError> {
        self.find(param).ok_or_else(|| ErcError::MissingParam {
            rule: self.name(),
            param,
        })
    }

    /// A distance, strictly positive: a zero spacing or window limit passes
    /// everything or flags everything, which is not a limit.
    fn length(&self, param: &'static str) -> Result<Dbu, ErcError> {
        match self.need(param)? {
            ParamValue::Length(value) => self.positive_dbu(value, param),
            _ => Err(self.wrong_type(param)),
        }
    }

    fn opt_length(&self, param: &'static str) -> Result<Option<Dbu>, ErcError> {
        match self.find(param) {
            None => Ok(None),
            Some(ParamValue::Length(value)) => self.positive_dbu(value, param).map(Some),
            Some(_) => Err(self.wrong_type(param)),
        }
    }

    /// A distance that may be either sign, such as a CMP thickness sensitivity.
    fn signed_length(&self, param: &'static str) -> Result<Dbu, ErcError> {
        match self.need(param)? {
            ParamValue::Length(value) => Ok(value),
            _ => Err(self.wrong_type(param)),
        }
    }

    fn positive_dbu(&self, value: Dbu, param: &'static str) -> Result<Dbu, ErcError> {
        (value.raw() > 0)
            .then_some(value)
            .ok_or_else(|| ErcError::NonPositiveLimit {
                rule: self.name(),
                limit: param.to_owned(),
            })
    }

    /// A finite `f64`. Infinity and NaN are refused here rather than compared
    /// against later: an infinite limit passes every measurement silently.
    fn number(&self, param: &'static str) -> Result<f64, ErcError> {
        match self.need(param)? {
            ParamValue::Ratio(value) if value.is_finite() => Ok(value),
            _ => Err(self.wrong_type(param)),
        }
    }

    fn opt_number(&self, param: &'static str, absent: f64) -> Result<f64, ErcError> {
        match self.find(param) {
            None => Ok(absent),
            Some(ParamValue::Ratio(value)) if value.is_finite() => Ok(value),
            Some(_) => Err(self.wrong_type(param)),
        }
    }

    /// A finite, strictly positive `f64`.
    fn positive(&self, param: &'static str) -> Result<f64, ErcError> {
        let value = self.number(param)?;
        (value > 0.0)
            .then_some(value)
            .ok_or_else(|| ErcError::NonPositiveLimit {
                rule: self.name(),
                limit: param.to_owned(),
            })
    }

    /// A fraction in `0.0 ..= 1.0`.
    fn fraction(&self, param: &'static str) -> Result<f64, ErcError> {
        let value = self.number(param)?;
        (0.0..=1.0)
            .contains(&value)
            .then_some(value)
            .ok_or_else(|| ErcError::NotAFraction {
                rule: self.name(),
                param,
            })
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

    /// Push the row's head, at the severity the deck asked for.
    ///
    /// `warning = true` demotes the row to [`Severity::Warning`]; absent leaves
    /// it at [`Severity::Error`], which is the safe default. Parsed *before*
    /// either column is pushed, so a bad flag leaves no half-written head.
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
    /// Build the tables from a deck.
    ///
    /// Fails closed on anything it does not understand *in a row it owns*: a
    /// deck with one bad rule is not partially usable, because a caller cannot
    /// tell a rule that was dropped from a rule that found nothing. A row whose
    /// kind is not in [`KINDS`] belongs to another domain and is stepped over.
    #[allow(
        clippy::too_many_lines,
        reason = "nineteen kinds listed once is the deck's parameter schema; splitting it \
                  per kind hides the manifest this function exists to be"
    )]
    pub fn from_deck(deck: &Deck, strings: &StrTable) -> Result<Self, ErcError> {
        let mut set = Self::default();
        // A sorted side copy of the ids already filed, for the duplicate check.
        let mut seen: Vec<StrId> = Vec::with_capacity(deck.rules.spec.len());

        for spec in &deck.rules.spec {
            let row = Row {
                rules: &deck.rules,
                strings,
                spec,
            };

            // The first duplicate *in deck order* is the one refused: `seen`
            // decides whether this row was seen, never which row it collides
            // with.
            match seen.binary_search(&spec.id) {
                Ok(_) => return Err(ErcError::DuplicateRule(row.name())),
                Err(at) => {
                    seen.insert(at, spec.id);
                    debug_assert!(
                        seen[..at].last().is_none_or(|before| *before < spec.id)
                            && seen[at + 1..].first().is_none_or(|after| spec.id < *after),
                        "the side copy the duplicate check binary-searches is out of order"
                    );
                }
            }

            // Every arm reads its parameters *before* touching a table, so a
            // refused row leaves no half-written column behind.
            match strings.resolve(spec.kind) {
                "antenna" => {
                    let layers = row.layers_from(2)?;
                    let max_ratio = row.positive("max_ratio")?;
                    // One measure for the row's whole collecting set: a deck row
                    // can state only one `sidewall_thickness`, so it applies to
                    // every collector. Mixing measures means one row per measure.
                    let measure = match row.opt_length("sidewall_thickness")? {
                        Some(thickness) => antenna::AntennaMeasure::Sidewall { thickness },
                        None => antenna::AntennaMeasure::Area,
                    };
                    let table = &mut set.antenna;
                    row.head(&mut table.head)?;
                    table.gate.push(LayerRef::Base(layers[0]));
                    table
                        .collector
                        .extend(layers[1..].iter().copied().map(LayerRef::Base));
                    table
                        .collector_measure
                        .extend(layers[1..].iter().map(|_| measure));
                    table.max_ratio.push(max_ratio);
                    close_csr(&mut table.collector_start, table.collector.len());
                }
                "antenna_electrical" => {
                    let layers = row.layers_from(2)?;
                    let max_ratio = row.positive("max_ratio")?;
                    let diode = row.opt_layer("diode_layer")?.map(LayerRef::Base);
                    let credit = row.opt_number("diode_credit", 0.0)?;
                    let bonus = row.opt_number("diode_bonus", 0.0)?;
                    let table = &mut set.antenna_electrical;
                    row.head(&mut table.head)?;
                    table.gate.push(LayerRef::Base(layers[0]));
                    table
                        .collector
                        .extend(layers[1..].iter().copied().map(LayerRef::Base));
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
                    let cmp = match row.find("cmp_target_density") {
                        None => None,
                        // The four coefficients are one model: guessing the rest
                        // is a thickness verdict nobody characterised.
                        Some(_) => Some(antenna::CmpModel {
                            target_density: row.fraction("cmp_target_density")?,
                            nominal_thickness: row.length("cmp_nominal_thickness")?,
                            thickness_sensitivity: row
                                .signed_length("cmp_thickness_sensitivity")?,
                            max_abs_thickness_delta: row.length("cmp_max_abs_thickness_delta")?,
                        }),
                    };
                    // Fail closed: a row bounding nothing reports clean over
                    // every window forever.
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
                    table.layer.push(LayerRef::Base(layers[0]));
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
                    table.blech_limit.push(blech);
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
                    let required_current = Qty::new(row.positive("required_current")?);
                    let max_path_resistance = Qty::new(row.positive("max_path_resistance")?);
                    let max_clamp_voltage = Qty::new(row.positive("max_clamp_voltage")?);
                    let min_guard_ring_width = row.length("min_guard_ring_width")?;
                    let max_tap_distance = row.length("max_tap_distance")?;
                    let table = &mut set.esd_latchup;
                    row.head(&mut table.head)?;
                    table.pad.push(layers[0]);
                    table.guard_ring.push(layers[1]);
                    table.required_current.push(required_current);
                    table.max_path_resistance.push(max_path_resistance);
                    table.max_clamp_voltage.push(max_clamp_voltage);
                    table.min_guard_ring_width.push(min_guard_ring_width);
                    table.max_tap_distance.push(max_tap_distance);
                    // The clamp list is empty and cannot be otherwise from a
                    // deck: a clamp is a device model *name* and `ParamValue`
                    // carries no string. The discharge-path half then finds no
                    // path from any pad and flags all of them, so the row is
                    // loud rather than silently clean.
                    close_csr(&mut table.clamp_start, table.clamp_model.len());
                }
                "esd_topological" => {
                    let layers = row.layers(1)?;
                    let table = &mut set.esd_topological;
                    row.head(&mut table.head)?;
                    table.pad.push(layers[0]);
                    // Empty for the same reason as `esd_latchup` above.
                    close_csr(&mut table.clamp_start, table.clamp_model.len());
                }
                "floating_gate" => {
                    row.layers(0)?;
                    row.head(&mut set.floating_gate.head)?;
                }
                "floating_well" => {
                    let layers = row.layers(2)?;
                    let table = &mut set.floating_well;
                    row.head(&mut table.head)?;
                    table.well.push(LayerRef::Base(layers[0]));
                    table.tap.push(LayerRef::Base(layers[1]));
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
                    table.region.push(LayerRef::Base(layers[0]));
                    table.tap.push(LayerRef::Base(layers[1]));
                    table.max_distance.push(max_distance);
                }
                "multiple_drivers" => {
                    row.layers(0)?;
                    let max_drivers = row.count("max_drivers")?;
                    // Zero permitted drivers flags every driven net in the
                    // design, which is a rule nobody can satisfy.
                    if max_drivers == 0 {
                        return Err(ErcError::NonPositiveLimit {
                            rule: row.name(),
                            limit: "max_drivers".to_owned(),
                        });
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
                    // A duty cycle of zero makes the predicted lifetime infinite,
                    // so the rule could never fire.
                    let duty_cycle = row.fraction("duty_cycle")?;
                    if duty_cycle <= 0.0 {
                        return Err(ErcError::NonPositiveLimit {
                            rule: row.name(),
                            limit: "duty_cycle".to_owned(),
                        });
                    }
                    let table = &mut set.reliability;
                    row.head(&mut table.head)?;
                    table.required_lifetime_hours.push(required_lifetime_hours);
                    // The mechanism's name is the rule's own id: `ParamValue`
                    // carries no string to state a separate one.
                    table.mechanism.push(spec.id);
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
                    table
                        .soft
                        .extend(layers.iter().copied().map(LayerRef::Base));
                    close_csr(&mut table.soft_start, table.soft.len());
                }
                "supply_short" => {
                    let layers = row.layers(2)?;
                    let table = &mut set.supply_short;
                    row.head(&mut table.head)?;
                    table.tap_a.push(LayerRef::Base(layers[0]));
                    table.tap_b.push(LayerRef::Base(layers[1]));
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
                // Another domain's row. The other half of fail closed is
                // `engine::run::run_checks`, which refuses a kind in neither
                // [`KINDS`] nor `crate::drc::ruleset::KINDS`.
                _ => {}
            }
        }

        debug_assert_eq!(
            set.len(),
            deck.rules
                .spec
                .iter()
                .filter(|spec| KINDS.contains(&strings.resolve(spec.kind)))
                .count(),
            "a deck row was filed under no kind, or under two"
        );
        set.debug_assert_shape();
        Ok(set)
    }

    /// How many rule rows are configured across every table — the number of
    /// [`RuleRun`] rows a run must produce.
    pub fn len(&self) -> usize {
        self.heads().iter().map(|head| head.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The nineteen heads, in field order.
    fn heads(&self) -> [&RuleHead; KINDS.len()] {
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
    }

    /// Every parallel and CSR column against the head it belongs to.
    ///
    /// A `*_start` column is `rows + 1` long once anything is in it, and a
    /// column parallel to a CSR body is as long as that body. The transforms
    /// index on both without rechecking.
    fn debug_assert_shape(&self) {
        let csr = |head: &RuleHead, start: &[u32], body: usize| {
            debug_assert_eq!(
                start.len(),
                head.len() + usize::from(!head.is_empty()),
                "a CSR start column is not one longer than its rows"
            );
            debug_assert_eq!(
                start.last().copied().unwrap_or(0) as usize,
                body,
                "a CSR start column does not end at its body's length"
            );
        };

        let table = &self.floating_well;
        debug_assert_eq!(table.well.len(), table.head.len());
        debug_assert_eq!(table.tap.len(), table.head.len());

        let table = &self.multiple_drivers;
        debug_assert_eq!(table.max_drivers.len(), table.head.len());

        let table = &self.unconnected_pin;
        csr(&table.head, &table.layer_start, table.layer.len());

        let table = &self.supply_short;
        debug_assert_eq!(table.tap_a.len(), table.head.len());
        debug_assert_eq!(table.tap_b.len(), table.head.len());

        let table = &self.soft_connection;
        csr(&table.head, &table.soft_start, table.soft.len());

        let table = &self.missing_tie;
        debug_assert_eq!(table.region.len(), table.head.len());
        debug_assert_eq!(table.tap.len(), table.head.len());
        debug_assert_eq!(table.max_distance.len(), table.head.len());

        let table = &self.esd_topological;
        debug_assert_eq!(table.pad.len(), table.head.len());
        csr(&table.head, &table.clamp_start, table.clamp_model.len());

        let table = &self.antenna;
        debug_assert_eq!(table.gate.len(), table.head.len());
        debug_assert_eq!(table.max_ratio.len(), table.head.len());
        debug_assert_eq!(table.collector_measure.len(), table.collector.len());
        csr(&table.head, &table.collector_start, table.collector.len());

        let table = &self.antenna_electrical;
        debug_assert_eq!(table.gate.len(), table.head.len());
        debug_assert_eq!(table.diode.len(), table.head.len());
        debug_assert_eq!(table.diode_credit.len(), table.head.len());
        debug_assert_eq!(table.diode_bonus.len(), table.head.len());
        debug_assert_eq!(table.max_ratio.len(), table.head.len());
        csr(&table.head, &table.collector_start, table.collector.len());

        let table = &self.density_cmp;
        debug_assert_eq!(table.layer.len(), table.head.len());
        debug_assert_eq!(table.window.len(), table.head.len());
        debug_assert_eq!(table.step.len(), table.head.len());
        debug_assert_eq!(table.min_density.len(), table.head.len());
        debug_assert_eq!(table.max_density.len(), table.head.len());
        debug_assert_eq!(table.max_neighbour_delta.len(), table.head.len());
        debug_assert_eq!(table.cmp.len(), table.head.len());
        debug_assert_eq!(table.include_partial_windows.len(), table.head.len());

        let table = &self.p2p_resistance;
        debug_assert_eq!(table.max_resistance.len(), table.head.len());

        let table = &self.em_current_density;
        debug_assert_eq!(table.max_density.len(), table.layer.len());
        debug_assert_eq!(table.max_current_per_cut.len(), table.layer.len());
        csr(&table.head, &table.layer_start, table.layer.len());

        let table = &self.electromigration;
        debug_assert_eq!(table.max_density.len(), table.layer.len());
        debug_assert_eq!(table.max_current_per_cut.len(), table.layer.len());
        debug_assert_eq!(table.blech_limit.len(), table.head.len());
        debug_assert_eq!(table.reference_temperature.len(), table.head.len());
        debug_assert_eq!(table.activation_energy_ev.len(), table.head.len());
        debug_assert_eq!(table.current_exponent.len(), table.head.len());
        csr(&table.head, &table.layer_start, table.layer.len());

        let table = &self.reliability;
        debug_assert_eq!(table.required_lifetime_hours.len(), table.head.len());
        debug_assert_eq!(table.mechanism.len(), table.head.len());
        debug_assert_eq!(table.reference_lifetime_hours.len(), table.head.len());
        debug_assert_eq!(table.reference_stress.len(), table.head.len());
        debug_assert_eq!(table.stress_exponent.len(), table.head.len());
        debug_assert_eq!(table.reference_temperature.len(), table.head.len());
        debug_assert_eq!(table.activation_energy_ev.len(), table.head.len());
        debug_assert_eq!(table.duty_cycle.len(), table.head.len());
        debug_assert_eq!(table.max_abs_voltage.len(), table.head.len());

        let table = &self.hv_domain;
        debug_assert_eq!(table.max_domain_delta.len(), table.head.len());
        debug_assert_eq!(table.isolation.len(), table.head.len());

        let table = &self.esd_latchup;
        debug_assert_eq!(table.pad.len(), table.head.len());
        debug_assert_eq!(table.guard_ring.len(), table.head.len());
        debug_assert_eq!(table.required_current.len(), table.head.len());
        debug_assert_eq!(table.max_path_resistance.len(), table.head.len());
        debug_assert_eq!(table.max_clamp_voltage.len(), table.head.len());
        debug_assert_eq!(table.min_guard_ring_width.len(), table.head.len());
        debug_assert_eq!(table.max_tap_distance.len(), table.head.len());
        debug_assert_eq!(table.clamp_resistance.len(), table.clamp_model.len());
        debug_assert_eq!(table.clamp_capacity.len(), table.clamp_model.len());
        debug_assert_eq!(table.clamp_voltage.len(), table.clamp_model.len());
        csr(&table.head, &table.clamp_start, table.clamp_model.len());
    }

    /// Run every non-empty table's transform once.
    ///
    /// `scratch`, `out` and `runs` are appended to, not cleared, so a caller
    /// may accumulate several cells into one report. Order is not load-bearing:
    /// `Violations::sort_canonical` establishes the report order.
    ///
    /// Every configured rule row produces exactly one [`RuleRun`], including
    /// the ones that could not run.
    pub fn run(
        &self,
        inputs: RunInputs<'_>,
        scratch: &mut Scratch,
        out: &mut Violations,
        runs: &mut Vec<RuleRun>,
    ) {
        debug_assert!(
            inputs.facts.len() <= inputs.design.nets.net_count(),
            "the role column names more nets than the extraction produced"
        );
        debug_assert!(
            inputs
                .power
                .is_none_or(|s| s.solution.is_consistent_with(s.grid)),
            "a solution whose columns do not match its grid would be read by four rules"
        );
        debug_assert!(
            inputs.die.xlo.raw() <= inputs.die.xhi.raw()
                && inputs.die.ylo.raw() <= inputs.die.yhi.raw(),
            "the die boundary is the denominator of every density, so it runs low to high"
        );
        debug_assert!(
            inputs.operating_temperature.raw() > 0.0
                && inputs.operating_temperature.raw().is_finite(),
            "the sign-off temperature is absolute, and every derating divides by it"
        );

        let before = runs.len();

        // An unconfigured kind must produce no `RuleRun` at all: that silence
        // is a different claim from a skip.
        if !self.floating_gate.head.is_empty() {
            topology::check_floating_gate(
                inputs.design,
                inputs.facts,
                &self.floating_gate,
                out,
                runs,
            );
        }
        if !self.floating_well.head.is_empty() {
            topology::check_floating_well(inputs.design, &self.floating_well, scratch, out, runs);
        }
        if !self.multiple_drivers.head.is_empty() {
            topology::check_multiple_drivers(
                inputs.design,
                &self.multiple_drivers,
                scratch,
                out,
                runs,
            );
        }
        if !self.unconnected_pin.head.is_empty() {
            topology::check_unconnected_pin(
                inputs.design,
                inputs.facts,
                &self.unconnected_pin,
                out,
                runs,
            );
        }

        if !self.supply_short.head.is_empty() {
            supply::check_supply_short(inputs.design, &self.supply_short, scratch, out, runs);
        }
        if !self.soft_connection.head.is_empty() {
            supply::check_soft_connection(inputs.design, &self.soft_connection, scratch, out, runs);
        }
        if !self.missing_tie.head.is_empty() {
            supply::check_missing_tie(inputs.design, &self.missing_tie, scratch, out, runs);
        }
        if !self.tie_high_low.head.is_empty() {
            supply::check_tie_high_low(inputs.design, inputs.facts, &self.tie_high_low, out, runs);
        }
        if !self.esd_topological.head.is_empty() {
            supply::check_esd_topological(inputs.design, &self.esd_topological, out, runs);
        }

        if !self.antenna.head.is_empty() {
            antenna::check_antenna(inputs.design, &self.antenna, scratch, out, runs);
        }
        if !self.antenna_electrical.head.is_empty() {
            antenna::check_antenna_electrical(
                inputs.design,
                &self.antenna_electrical,
                scratch,
                out,
                runs,
            );
        }
        if !self.density_cmp.head.is_empty() {
            antenna::check_density_cmp(
                inputs.design,
                inputs.die,
                &self.density_cmp,
                scratch,
                out,
                runs,
            );
        }

        if !self.p2p_resistance.head.is_empty() {
            electrical::check_p2p_resistance(
                inputs.design,
                inputs.networks,
                &self.p2p_resistance,
                scratch,
                out,
                runs,
            );
        }
        if !self.ir_drop.head.is_empty() {
            electrical::check_ir_drop(inputs.power, inputs.intent, &self.ir_drop, out, runs);
        }
        if !self.em_current_density.head.is_empty() {
            electrical::check_em_current_density(
                inputs.power,
                inputs.intent,
                inputs.grid,
                &self.em_current_density,
                out,
                runs,
            );
        }
        if !self.electromigration.head.is_empty() {
            electrical::check_electromigration(
                inputs.power,
                inputs.intent,
                inputs.grid,
                inputs.operating_temperature,
                &self.electromigration,
                out,
                runs,
            );
        }

        if !self.reliability.head.is_empty() {
            reliability::check_reliability(
                inputs.power,
                inputs.intent,
                inputs.operating_temperature,
                &self.reliability,
                out,
                runs,
            );
        }
        if !self.hv_domain.head.is_empty() {
            reliability::check_hv_domain(inputs.design, inputs.intent, &self.hv_domain, out, runs);
        }
        if !self.esd_latchup.head.is_empty() {
            reliability::check_esd_latchup(
                inputs.design,
                inputs.intent,
                inputs.networks,
                &self.esd_latchup,
                scratch,
                out,
                runs,
            );
        }

        debug_assert_eq!(
            runs.len(),
            before + self.len(),
            "a configured rule row produced no run row, or produced two"
        );
    }
}
