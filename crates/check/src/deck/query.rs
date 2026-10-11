//! What a compiled deck enforces, read from the typed rules the checks run.
//!
//! A consumer that draws layout (a router, a generator) needs the same limits
//! the checker holds the layout to. Reading them here, from the rule values
//! and through the condition functions the checks call
//! ([`Rule::required_spacing`]), means the two cannot disagree; reading the
//! deck text again would be a second parser.
//!
//! Every length is in database units of [`CompiledDeck::grid`], the grid the
//! deck was compiled on: a deck compiled at 1 nm and a layout checked at
//! 5 nm read different values.

use super::CompiledDeck;
use crate::drc::{Rule, SpacingQuery};
use crate::erc::rules::antenna::AntennaMeasure;
use crate::report::LimitSense;
use gpurify_geom::{prefix, Current, CurrentDensity, Dbu, DbuArea, LayerId, Qty, StrId, Voltage};

/// The enclosure rules between one inner and one outer layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Enclosure {
    /// The enclosure every side needs: the largest [`Rule::MinEnclosure`]
    /// limit, `None` without one.
    pub all_sides: Option<Dbu>,
    /// The enclosure both sides of one axis need: the largest
    /// [`Rule::AsymmetricEnclosure`] limit, `None` without one.
    pub opposite: Option<Dbu>,
}

/// One density rule on a layer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DensityLimit {
    /// The rule's id.
    pub rule: StrId,
    /// The window side and step for [`Rule::Density`]; `None` for
    /// [`Rule::GlobalDensity`], which measures the whole die.
    pub window: Option<(Dbu, Dbu)>,
    /// The limit as a fraction of the window or die.
    pub limit: f64,
    /// Whether `limit` is a minimum or a maximum.
    pub sense: LimitSense,
}

/// One antenna row whose collectors include a layer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AntennaLimit {
    /// The rule's id.
    pub rule: StrId,
    /// The gate layer the ratio is taken against.
    pub gate: LayerId,
    /// The largest collector-to-gate ratio the row allows.
    pub max_ratio: f64,
    /// Whether the collector counts its area or its sidewall.
    pub measure: AntennaMeasure,
    /// The diode layer whose gates the row skips, if any.
    pub diode: Option<LayerId>,
}

/// The current a layer may carry, from its `em_current_density` rows.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EmLimit {
    /// The rule's id.
    pub rule: StrId,
    /// The wire current per unit width, A/m.
    pub max_density: Qty<CurrentDensity, { prefix::BASE }>,
    /// The current one cut may carry, µA.
    pub max_current_per_cut: Qty<Current, { prefix::MICRO }>,
}

/// The voltages a device model may see, from its `gate_oxide` and
/// `drain_source` rows: the smallest of each, `None` without one.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct FetLimits {
    /// The most its gate may differ from its source, drain or bulk.
    pub gate_oxide: Option<Qty<Voltage, { prefix::MILLI }>>,
    /// The most its drain may differ from its source.
    pub drain_source: Option<Qty<Voltage, { prefix::MILLI }>>,
}

impl CompiledDeck {
    /// Every DRC rule reading `layer`, with its id, in deck order.
    pub fn drc_on(&self, layer: LayerId) -> impl Iterator<Item = (StrId, &Rule)> + '_ {
        self.drc
            .rules
            .iter()
            .filter(move |(_, rule)| rule.layers().contains(&Some(layer)))
            .map(|(id, rule)| (*id, rule))
    }

    /// The narrowest legal width of `layer`: the largest [`Rule::MinWidth`]
    /// limit on it, the width its check reports as the `limit` of a shape
    /// too narrow. `None` when no rule bounds it.
    ///
    /// # Examples
    ///
    /// ```
    /// use gpurify_check::deck::compile;
    /// use gpurify_geom::{Dbu, Grid, StrTable};
    ///
    /// let text = "grid 5nm\nlayer met1 = gds(68, 20)\nrule m1.1 width(met1) >= 140nm\n";
    /// let mut strings = StrTable::default();
    /// let deck = compile(text, Grid::new(1000)?, &mut strings)?;
    /// let met1 = deck.layers.id(&strings, "met1").expect("declared");
    /// assert_eq!(deck.min_width(met1), Some(Dbu::new_unchecked(140)));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn min_width(&self, layer: LayerId) -> Option<Dbu> {
        self.drc_on(layer)
            .filter_map(|(_, rule)| match *rule {
                Rule::MinWidth { layer: on, limit } if on == layer => Some(limit),
                _ => None,
            })
            .max()
    }

    /// The smallest legal area of a shape on `layer`: the largest
    /// [`Rule::MinArea`] limit on it.
    pub fn min_area(&self, layer: LayerId) -> Option<DbuArea> {
        self.drc_on(layer)
            .filter_map(|(_, rule)| match *rule {
                Rule::MinArea { layer: on, limit } if on == layer => Some(limit),
                _ => None,
            })
            .max()
    }

    /// The smallest legal hole in `layer`: the largest
    /// [`Rule::MinEnclosedArea`] limit on it.
    pub fn min_enclosed_area(&self, layer: LayerId) -> Option<DbuArea> {
        self.drc_on(layer)
            .filter_map(|(_, rule)| match *rule {
                Rule::MinEnclosedArea { layer: on, limit } if on == layer => Some(limit),
                _ => None,
            })
            .max()
    }

    /// The space two shapes on `layer` described by `query` must keep: the
    /// largest that any of the layer's same-layer spacing rules requires of
    /// them ([`Rule::required_spacing`]), which is the `limit` the checker
    /// reports when they are closer. `None` when no such rule holds them.
    ///
    /// # Examples
    ///
    /// ```
    /// use gpurify_check::deck::compile;
    /// use gpurify_check::drc::SpacingQuery;
    /// use gpurify_geom::{Dbu, Grid, StrTable};
    ///
    /// let text = "grid 5nm
    /// layer met1 = gds(68, 20)
    /// rule m1.2 space(met1) >= 140nm
    /// rule m1.3b wide_space(met1; width: 3um) >= 280nm
    /// ";
    /// let mut strings = StrTable::default();
    /// let deck = compile(text, Grid::new(1000)?, &mut strings)?;
    /// let met1 = deck.layers.id(&strings, "met1").expect("declared");
    /// let nm = Dbu::new_unchecked;
    /// let wires = SpacingQuery { width_a: nm(140), width_b: nm(140), run_length: nm(5000), end_of_line: None };
    /// assert_eq!(deck.required_spacing(met1, &wires), Some(nm(140)));
    /// let plate = SpacingQuery { width_a: nm(3000), ..wires };
    /// assert_eq!(deck.required_spacing(met1, &plate), Some(nm(280)));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn required_spacing(&self, layer: LayerId, query: &SpacingQuery) -> Option<Dbu> {
        self.drc
            .rules
            .iter()
            .filter_map(|(_, rule)| rule.required_spacing(layer, &self.drc.tables, query))
            .max()
    }

    /// The enclosure rules holding `inner` inside `outer`.
    pub fn enclosure(&self, inner: LayerId, outer: LayerId) -> Enclosure {
        let mut found = Enclosure::default();
        for (_, rule) in &self.drc.rules {
            match *rule {
                Rule::MinEnclosure {
                    outer: o,
                    inner: i,
                    limit,
                } if (o, i) == (outer, inner) => found.all_sides = found.all_sides.max(Some(limit)),
                Rule::AsymmetricEnclosure {
                    outer: o,
                    inner: i,
                    min_one_side,
                } if (o, i) == (outer, inner) => {
                    found.opposite = found.opposite.max(Some(min_one_side));
                }
                _ => {}
            }
        }
        found
    }

    /// The space the cuts of an array of `cuts` cuts on `cut` must keep: the
    /// largest [`Rule::ViaArraySpacing`] limit among the rules for which
    /// `cuts` makes an array (more than its threshold). `None` when none does.
    pub fn via_array_spacing(&self, cut: LayerId, cuts: u32) -> Option<Dbu> {
        self.drc_on(cut)
            .filter_map(|(_, rule)| match *rule {
                Rule::ViaArraySpacing {
                    layer,
                    array_threshold,
                    limit,
                } if layer == cut && cuts > u32::from(array_threshold) => Some(limit),
                _ => None,
            })
            .max()
    }

    /// The density rules on `layer`, in deck order.
    pub fn density(&self, layer: LayerId) -> impl Iterator<Item = DensityLimit> + '_ {
        self.drc_on(layer)
            .filter_map(move |(rule, value)| match *value {
                Rule::Density {
                    layer: on,
                    window,
                    step,
                    limit,
                    sense,
                    ..
                } if on == layer => Some(DensityLimit {
                    rule,
                    window: Some((window, step)),
                    limit,
                    sense,
                }),
                Rule::GlobalDensity {
                    layer: on,
                    limit,
                    sense,
                    ..
                } if on == layer => Some(DensityLimit {
                    rule,
                    window: None,
                    limit,
                    sense,
                }),
                _ => None,
            })
    }

    /// The `antenna` rows that count `collector` among their collectors, in
    /// deck order.
    pub fn antenna(&self, collector: LayerId) -> impl Iterator<Item = AntennaLimit> + '_ {
        let table = &self.erc.antenna;
        (0..table.head.len()).filter_map(move |row| {
            let span = table.collector_start[row] as usize..table.collector_start[row + 1] as usize;
            let at = table.collector[span.clone()]
                .iter()
                .position(|&layer| layer == collector)?;
            Some(AntennaLimit {
                rule: table.head.rule[row],
                gate: table.gate[row],
                max_ratio: table.max_ratio[row],
                measure: table.collector_measure[span.start + at],
                diode: table.diode[row],
            })
        })
    }

    /// The `em_current_density` rows naming `layer`, in deck order.
    pub fn em_limit(&self, layer: LayerId) -> impl Iterator<Item = EmLimit> + '_ {
        let table = &self.erc.em_current_density;
        (0..table.head.len()).filter_map(move |row| {
            let span = table.layer_start[row] as usize..table.layer_start[row + 1] as usize;
            let at = span.start + table.layer[span].iter().position(|&on| on == layer)?;
            Some(EmLimit {
                rule: table.head.rule[row],
                max_density: table.max_density[at],
                max_current_per_cut: table.max_current_per_cut[at],
            })
        })
    }

    /// The voltage limits on device model `model` (an interned model name).
    pub fn fet_limits(&self, model: StrId) -> FetLimits {
        let smallest = |table: &crate::erc::rules::domain::ModelLimitTable| {
            (0..table.head.len())
                .filter(|&row| {
                    let span = table.model_start[row] as usize..table.model_start[row + 1] as usize;
                    table.model[span].contains(&model)
                })
                .map(|row| table.max_voltage[row])
                .min_by(|a, b| a.raw().total_cmp(&b.raw()))
        };
        FetLimits {
            gate_oxide: smallest(&self.erc.gate_oxide),
            drain_source: smallest(&self.erc.drain_source),
        }
    }
}
