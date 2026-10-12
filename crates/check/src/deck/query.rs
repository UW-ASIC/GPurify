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
use crate::drc::{CutClassTable, Rule, SpacingQuery};
use crate::erc::rules::antenna::AntennaMeasure;
use crate::report::LimitSense;
use gpurify_geom::{prefix, Current, CurrentDensity, Dbu, DbuArea, LayerId, Qty, StrId, Voltage};

/// The enclosure rules between one inner and one outer layer. A rule with a
/// wire band ([`WireBand`](crate::drc::WireBand)) counts as if it held every
/// wire: the strictest it can be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Enclosure {
    /// The enclosure every side needs: the largest [`Rule::MinEnclosure`]
    /// limit, `None` without one.
    pub all_sides: Option<Dbu>,
    /// The enclosure both sides of one axis need: the largest
    /// [`Rule::AsymmetricEnclosure`] or [`Rule::AdjacentEnclosure`] limit,
    /// `None` without one. For a rectangular cut in a shape whose edges do
    /// not step along its sides the two rules read the same enclosure.
    pub opposite: Option<Dbu>,
    /// The enclosure every side not on the host's boundary needs: the
    /// largest [`Rule::NoncoincidentEnclosure`] limit, `None` without one.
    pub noncoincident: Option<Dbu>,
    /// The most the host may reach past the inner shape on any side: the
    /// smallest [`Rule::MaxEnclosure`] limit, `None` without one.
    pub at_most: Option<Dbu>,
    /// Whether a [`Rule::FullWidth`] holds the inner shape to span the
    /// host's width along one axis.
    pub full_width: bool,
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

/// One antenna or electrical-antenna row whose collectors include a layer.
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
    /// The diode layer: whose gates an `antenna` row skips, whose area an
    /// `antenna_electrical` row credits; `None` without one.
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
    /// The widths `layer`'s shapes must be one of
    /// ([`Rule::AllowedWidth`]), sorted; `None` when no rule lists them.
    pub fn allowed_widths(&self, layer: LayerId) -> Option<&[Dbu]> {
        self.drc_on(layer).find_map(|(_, rule)| match *rule {
            Rule::AllowedWidth { layer: on, widths } if on == layer => {
                self.drc.widths.get(widths as usize).map(Vec::as_slice)
            }
            _ => None,
        })
    }

    /// The cut sizes `layer`'s shapes must be one of ([`Rule::CutClass`]),
    /// each `(short, long)`, sorted; `None` when no rule lists them.
    pub fn cut_classes(&self, layer: LayerId) -> Option<&[(Dbu, Dbu)]> {
        self.drc_on(layer).find_map(|(_, rule)| match *rule {
            Rule::CutClass { layer: on, classes } if on == layer => {
                self.drc.classes.get(classes as usize).map(Vec::as_slice)
            }
            _ => None,
        })
    }

    /// The largest bounding-box aspect ratio a shape on `layer` may have
    /// ([`Rule::AspectRatio`]), the strictest stated.
    pub fn max_aspect_ratio(&self, layer: LayerId) -> Option<f64> {
        self.drc_on(layer)
            .filter_map(|(_, rule)| match *rule {
                Rule::AspectRatio { layer: on, limit } if on == layer => Some(limit),
                _ => None,
            })
            .reduce(f64::min)
    }

    /// The most area `layer` may cover in the whole layout
    /// ([`Rule::TotalArea`]), the strictest stated.
    pub fn max_total_area(&self, layer: LayerId) -> Option<DbuArea> {
        self.drc_on(layer)
            .filter_map(|(_, rule)| match *rule {
                Rule::TotalArea { layer: on, limit } if on == layer => Some(limit),
                _ => None,
            })
            .min()
    }

    /// The shortest edge a `MINSTEP` rule allows on `layer`
    /// ([`Rule::MinStep`]), the strictest stated.
    pub fn min_step(&self, layer: LayerId) -> Option<Dbu> {
        self.drc_on(layer)
            .filter_map(|(_, rule)| match *rule {
                Rule::MinStep {
                    layer: on, limit, ..
                } if on == layer => Some(limit),
                _ => None,
            })
            .max()
    }

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
                    ..
                } if (o, i) == (outer, inner) => found.all_sides = found.all_sides.max(Some(limit)),
                Rule::AsymmetricEnclosure {
                    outer: o,
                    inner: i,
                    min_one_side,
                    ..
                } if (o, i) == (outer, inner) => {
                    found.opposite = found.opposite.max(Some(min_one_side));
                }
                Rule::AdjacentEnclosure {
                    outer: o,
                    inner: i,
                    min_one_side,
                } if (o, i) == (outer, inner) => {
                    found.opposite = found.opposite.max(Some(min_one_side));
                }
                Rule::NoncoincidentEnclosure {
                    outer: o,
                    inner: i,
                    limit,
                } if (o, i) == (outer, inner) => {
                    found.noncoincident = found.noncoincident.max(Some(limit));
                }
                Rule::MaxEnclosure {
                    outer: o,
                    inner: i,
                    limit,
                } if (o, i) == (outer, inner) => {
                    found.at_most = Some(found.at_most.map_or(limit, |most| most.min(limit)));
                }
                Rule::FullWidth { outer: o, inner: i } if (o, i) == (outer, inner) => {
                    found.full_width = true;
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

    /// The space the cuts on `cut` must keep from every other cut, centre to
    /// centre when `center`, else edge to edge: the largest
    /// [`Rule::CutSpacing`] limit that holds every cut (no `adjacent`).
    /// `None` when none does.
    pub fn cut_spacing(&self, cut: LayerId, center: bool) -> Option<Dbu> {
        self.drc_on(cut)
            .filter_map(|(_, rule)| match *rule {
                Rule::CutSpacing {
                    layer,
                    center: c,
                    adjacent: 0,
                    limit,
                    ..
                } if layer == cut && c == center => Some(limit),
                _ => None,
            })
            .max()
    }

    /// The cut-class spacing table on `cut` ([`Rule::CutClassSpacing`]),
    /// the first stated; `None` without one.
    pub fn cut_class_spacing(&self, cut: LayerId) -> Option<&CutClassTable> {
        self.drc_on(cut).find_map(|(_, rule)| match *rule {
            Rule::CutClassSpacing { layer, table } if layer == cut => {
                self.drc.cut_tables.get(table as usize)
            }
            _ => None,
        })
    }

    /// The fewest cuts on `cut` a via needs where it lands on a `wide` wire
    /// `wire_width` wide: the largest [`Rule::MinimumCut`] count among the
    /// rules whose `width` the wire is strictly wider than, whatever their
    /// far-side metal. `None` when none holds it.
    pub fn minimum_cuts(&self, cut: LayerId, wide: LayerId, wire_width: Dbu) -> Option<u16> {
        self.drc_on(cut)
            .filter_map(|(_, rule)| match *rule {
                Rule::MinimumCut {
                    cut: c,
                    wide: w,
                    width,
                    min_count,
                    ..
                } if (c, w) == (cut, wide) && wire_width > width => Some(min_count),
                _ => None,
            })
            .max()
    }

    /// The tallest stack of overlapping cuts through `cut`: the smallest
    /// [`Rule::ViaStack`] `max_height` among the stacks naming it. `None`
    /// when none does.
    pub fn max_via_stack(&self, cut: LayerId) -> Option<u16> {
        self.drc
            .rules
            .iter()
            .filter_map(|(_, rule)| match *rule {
                Rule::ViaStack { stack, max_height }
                    if self
                        .drc
                        .stacks
                        .get(stack as usize)
                        .is_some_and(|layers| layers.contains(&cut)) =>
                {
                    Some(max_height)
                }
                _ => None,
            })
            .min()
    }

    /// The space a shape on `a` must keep from one on `b` in the projection
    /// metric: the largest [`Rule::ProjectionSpacing`] limit between them,
    /// in either order. `None` without one.
    pub fn projection_spacing(&self, a: LayerId, b: LayerId) -> Option<Dbu> {
        self.drc_on(a)
            .filter_map(|(_, rule)| match *rule {
                Rule::ProjectionSpacing { a: x, b: y, limit }
                    if (x, y) == (a, b) || (x, y) == (b, a) =>
                {
                    Some(limit)
                }
                _ => None,
            })
            .max()
    }

    /// How many `inner` shapes an `outer` shape must hold, `(fewest, most)`:
    /// the tightest bounds of the [`Rule::MustContain`] rules between them,
    /// `u32::MAX` for no most. `None` without one.
    pub fn contains(&self, outer: LayerId, inner: LayerId) -> Option<(u32, u32)> {
        self.drc_on(outer)
            .filter_map(|(_, rule)| match *rule {
                Rule::MustContain {
                    outer: o,
                    inner: i,
                    min_count,
                    max_count,
                } if (o, i) == (outer, inner) => Some((min_count, max_count)),
                _ => None,
            })
            .reduce(|(min_a, max_a), (min_b, max_b)| (min_a.max(min_b), max_a.min(max_b)))
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

    /// The `antenna` rows, then the `antenna_electrical` rows, that count
    /// `collector` among their collectors, each in deck order.
    pub fn antenna(&self, collector: LayerId) -> impl Iterator<Item = AntennaLimit> + '_ {
        let plain = &self.erc.antenna;
        let electrical = &self.erc.antenna_electrical;
        let plain = (0..plain.head.len()).map(move |row| {
            (
                &plain.head,
                row,
                &plain.collector_start,
                &plain.collector,
                &plain.collector_measure,
                plain.gate[row],
                plain.max_ratio[row],
                plain.diode[row],
            )
        });
        let electrical = (0..electrical.head.len()).map(move |row| {
            (
                &electrical.head,
                row,
                &electrical.collector_start,
                &electrical.collector,
                &electrical.collector_measure,
                electrical.gate[row],
                electrical.max_ratio[row],
                electrical.diode[row],
            )
        });
        plain.chain(electrical).filter_map(
            move |(head, row, start, collectors, measures, gate, max_ratio, diode)| {
                let span = start[row] as usize..start[row + 1] as usize;
                let at = collectors[span.clone()]
                    .iter()
                    .position(|&layer| layer == collector)?;
                Some(AntennaLimit {
                    rule: head.rule[row],
                    gate,
                    max_ratio,
                    measure: measures[span.start + at],
                    diode,
                })
            },
        )
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
