//! Process-stage rules: antenna ratios and windowed density.
//!
//! A cumulative antenna check is one rule row per fabrication stage, row `k`
//! naming every layer etched up to layer `k`. Nets are built per etch stage
//! from only the conductors that exist at that etch (SVRF `CONNECT` between
//! `NET AREA RATIO` stages), so a diode or a second gate reachable only
//! through a higher metal does not count yet. Areas are doubled [`DbuArea`]s
//! summed in `i128`; each stage's ratio is an `f64`, and a cumulative ratio
//! their sum.
//!
//! Data in: the store, nets, the die box. Data out: violations and one run
//! per row.

use crate::drc::rules::{LayerRects, SortedRects};
use crate::erc::ruleset::RuleHead;
use crate::erc::{centre, record_run, Design, Scratch};
use crate::report::{LimitSense, Measurement, Outcome, RuleRun, Violation, Violations};
use crate::topology::{extract_nets_into, NetId, NetTable};
use gpurify_geom::boolean::union_into;
use gpurify_geom::rects::{clipped_area, decompose_into};
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::{Bbox, LayerId, PolyId};
use gpurify_geom::{Dbu, DbuArea, Grid, MAX_ABS_DBU};
use gpurify_ingest::deck::Connectivity;

/// What an [`AntennaTable`] row counts as collecting area. A deck row states
/// one measure for all of its collectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntennaMeasure {
    /// The merged layer's area: drawn polygons that overlap count their
    /// shared area once. Deck: `sidewall: none`.
    Area,
    /// Etched sidewall: the merged layer's perimeter times `thickness`, an
    /// area like the gate's (sky130 poly/li/met1-3, gf180 `perimeter_only`).
    /// Deck: `sidewall: len`.
    Sidewall {
        /// The conductor's thickness, database units. Positive from a deck.
        thickness: Dbu,
    },
}

/// The deck's connectivity, from which each antenna row's etch-stage nets are
/// cut. [`RuleSet::from_deck`](crate::erc::RuleSet::from_deck) copies it from
/// the deck's `connect` statements; with no conductors, every row measures
/// the finished nets instead.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Stack {
    /// Conductor layers bottom-up, as `connect conductors` lists them. The
    /// order decides which conductors exist at a stage.
    pub conductors: Vec<LayerId>,
    /// `(cut, a, b)`: one `connect via` row, the cut and the two conductors it
    /// joins in deck order. A stage keeps a via when both conductors stand.
    pub vias: Vec<(LayerId, LayerId, LayerId)>,
    /// Whether shapes touching on one layer are one net
    /// (`connect touch_within_layer`).
    pub intra_layer_touch: bool,
    /// The gate terminal layer (the first) of every `device mos` row: a
    /// shape that is not a conductor is on one of these when it overlaps
    /// one, whatever the cuts say ([`AntennaTable`]).
    pub gates: Vec<LayerId>,
}

impl Stack {
    /// The stage at which `layer` is etched, as an index into
    /// [`conductors`](Self::conductors): a conductor's own place, a cut's
    /// lower conductor. `None` for any other layer.
    fn standing(&self, layer: LayerId) -> Option<usize> {
        let pos = |layer: LayerId| self.conductors.iter().position(|&c| c == layer);
        pos(layer).or_else(|| {
            self.vias
                .iter()
                .filter(|v| v.0 == layer)
                .filter_map(|&(_, a, b)| Some(pos(a)?.min(pos(b)?)))
                .max()
        })
    }

    /// The connectivity standing when conductor `top` is etched: conductors
    /// up to it, and the vias joining two of them.
    fn stage(&self, top: usize) -> Connectivity {
        let standing = |layer: LayerId| self.conductors[..=top].contains(&layer);
        let (via_cut, via_connects) = self
            .vias
            .iter()
            .filter(|&&(_, a, b)| standing(a) && standing(b))
            .map(|&(cut, a, b)| (cut, (a, b)))
            .unzip();
        Connectivity {
            conductors: self.conductors[..=top].to_vec(),
            via_cut,
            via_connects,
            intra_layer_touch: self.intra_layer_touch,
            ..Connectivity::default()
        }
    }
}

/// A first-order CMP model: finished thickness linear in local density, off
/// its nominal by `sensitivity * (density - target)`. Only that excursion is
/// limited, so the nominal thickness itself is not stated. Deck:
/// `cmp: (target: frac, sensitivity: len, max_delta: len)`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CmpModel {
    /// The density at which the finished thickness is nominal, `0.0 ..= 1.0`.
    pub target_density: f64,
    /// Thickness change per unit density above target, database units; signed.
    pub thickness_sensitivity: Dbu,
    /// Largest allowed `|sensitivity * (density - target)|`, database units.
    pub max_abs_thickness_delta: Dbu,
}

/// Antenna ratio at one etch stage: deck kind `antenna`, written
/// `antenna(gate, collectors..; max_ratio: n, sidewall: len | none,
/// diode: layer | none)`.
///
/// A conductor being plasma-etched collects charge in proportion to its area
/// (or, for a thick layer, its sidewall) and discharges it through the thin
/// gate oxide it is connected to at that moment. A row flags every gate whose
/// ratio is above `max_ratio`. The ratio is one term per etch stage the row's
/// collectors span, summed: the collecting area on the gate's net at that
/// stage over the gate area on that net at that stage. That is LEF's CAR (the
/// sum of a gate's PARs) and IHP's `AreaRatio`; a row whose collectors are
/// all etched at one stage is that stage's PAR. Where:
///
/// - a collector is etched at its own stage: the deck's conductors up to it
///   ([`Stack::conductors`] order) and the vias between two of them. A cut
///   collector stands on its lower conductor; a layer the stack does not
///   place is etched with the row's highest collector. A gate or diode
///   reachable only through a higher metal is not on the net yet. A deck with
///   no conductors measures the finished nets at every stage.
/// - collecting area is summed over every merged collector figure etched at
///   that stage on the net, by the row's [`AntennaMeasure`].
/// - gate area is summed over the merged figures of the `gate` layer on the
///   net, so overlapping gate polygons are counted once. A figure is on the
///   lowest net among the drawn polygons it covers. A layer that is not a
///   conductor (a derived `poly and diffusion` gate, a cut, a capacitor
///   plate) is on the net of one conductor it overlaps with positive area
///   (touching alone does not join): a cut, one its `connect via` rows name;
///   any other layer, the one it lies on, never metal routed over it. A
///   conductor some `device mos` row names as its gate terminal
///   ([`Stack::gates`]) is taken first, so a derived gate sits on its poly
///   even where a `connect via` row joins poly to the diffusion under it.
///   Without one, of the conductors it overlaps, one that another reaches
///   upward through cuts is over it, and of the rest the topmost is taken,
///   so a gate sits on its poly, not on the diffusion or well under it,
///   unless a cut joins the diffusion to the poly (a deck that writes no MOS
///   device then puts the gate on the diffusion).
/// - gates on one net at every stage have one ratio and are reported once.
/// - with a `diode` layer, a gate whose net at the row's highest stage has
///   area on that layer is not this row's: a foundry that states a separate
///   limit with a protection diode (IHP Ant.b without, Ant.e with) writes it
///   as another row. This is [KLayout] `antenna_check` with a diode layer and
///   no factor: "the respective network is skipped".
///
/// The ratio is dimensionless. No design intent is needed.
///
/// # Limits
///
/// - Every net with gate area is checked: reaching diffusion or a tap
///   exempts nothing (ERC-A13). Any area on the `diode` layer counts as a
///   protection diode; IHP's minimum diode size (Ant.g, ERC-A9) is not
///   checked.
/// - LEF `ANTENNACUMROUTINGPLUSCUT` is missing (ERC-A4); oxide classes are one
///   row per gate layer (ERC-A12); a MIM victim works as a gate layer, but
///   gf180's deck leaves ANT.14/15 out (ERC-A11).
///
/// Catalog: ERC-A1, ERC-A2, ERC-A3, ERC-A4 (partial), ERC-A8, ERC-A11
/// (partial), ERC-A12 (partial) in the [check catalog]. Defined by
/// [LEF/DEF 5.8] Appendix C (PAR, CAR, `ANTENNAMODEL`); [GF180MCU] ANT.1-ANT.15;
/// [IHP SG13G2] Ant.a-Ant.f; [SKY130] antenna rules, licon.1 and via.1;
/// [KLayout] `antenna_check` (diodes). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [KLayout]: https://www.klayout.de/doc-qt5/about/drc_ref_netter.html#antenna_check
/// [LEF/DEF 5.8]: https://coriolis.lip6.fr/doc/lefdef/lefdefref/lefdefref.pdf
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [IHP SG13G2]: https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct AntennaTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the gate (victim) layer, the ratio's denominator.
    pub gate: Vec<LayerId>,
    /// `collector[collector_start[i] .. collector_start[i + 1]]` and the
    /// parallel `collector_measure` are row `i`'s collecting set.
    pub collector_start: Vec<u32>,
    /// Collector layers, CSR by `collector_start`; at least one per row. A
    /// layer listed twice in a row collects once, by its first measure.
    pub collector: Vec<LayerId>,
    /// Parallel to `collector`; equal within a row.
    pub collector_measure: Vec<AntennaMeasure>,
    /// Per row: the largest allowed ratio. Positive and finite from a deck.
    pub max_ratio: Vec<f64>,
    /// Per row: the protection-diode layer whose gates the row leaves to
    /// another, or `None` to hold every gate.
    pub diode: Vec<Option<LayerId>>,
    /// The deck's connectivity, shared by every row.
    pub stack: Stack,
}

/// Antenna ratio with protection-diode credit: deck kind `antenna_electrical`,
/// written `antenna_electrical(gate, collectors..; max_ratio: n,
/// sidewall: len | none, diode: layer | none, diode_credit: n,
/// diode_bonus: n)`.
///
/// Nets, collectors, gates, the [`AntennaMeasure`] and the summed ratio are
/// those of [`AntennaTable`]. The value compared with `max_ratio` is sky130's
/// etch gate area ratio with a diode,
///
/// `EGAR = ratio - diode_credit * diode_area - diode_bonus`,
///
/// where `diode_area` is the `diode` layer's area on the gate's net at the
/// row's highest stage in square micrometres: SKY130's "K x
/// (`AntennaDiode_area` in um2)". Both terms are credit for a diode: a gate
/// with no diode area on its net keeps its ratio, so with `diode: none` the
/// bonus never applies (SKY130: "the `diode_bonus` applies only when at least
/// one diode is used, regardless from it's size"). Three public definitions
/// agree on the unit: SKY130's EGAR; the sky130 technology LEF, whose
/// `ANTENNADIFFSIDEAREARATIO` and `ANTENNADIFFAREARATIO` PWL tables rise by
/// `K` per µm² of diode (met1: 2609 at 0.0225 µm², 11600 at 22.5 µm², a
/// slope of 400, met1's `K`); and [KLayout] `antenna_check`, whose diode
/// factor raises "the ratio threshold by \[the factor\] per square
/// micrometer of diode area".
///
/// # Limits
///
/// gf180's additive model (ERC-A6) and LEF's piecewise-linear diffusion
/// limits (ERC-A7) are missing.
///
/// Catalog: ERC-A5 (partial), ERC-A8 in the [check catalog]. Defined by
/// [SKY130] antenna EGAR and Table Ig; [LEF/DEF 5.8] `ANTENNAAREAMINUSDIFF`;
/// [IHP SG13G2] Ant.b/e and Ant.d/f; [KLayout] `antenna_check` (its diode
/// factor). Source tags are in [check-sources.md].
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [KLayout]: https://www.klayout.de/doc-qt5/about/drc_ref_netter.html#antenna_check
/// [LEF/DEF 5.8]: https://coriolis.lip6.fr/doc/lefdef/lefdefref/lefdefref.pdf
/// [IHP SG13G2]: https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/antenna.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct AntennaElectricalTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the gate (victim) layer.
    pub gate: Vec<LayerId>,
    /// `collector[collector_start[i] .. collector_start[i + 1]]`, CSR.
    pub collector_start: Vec<u32>,
    /// Collector layers, CSR by `collector_start`; at least one per row.
    pub collector: Vec<LayerId>,
    /// Parallel to `collector`; equal within a row.
    pub collector_measure: Vec<AntennaMeasure>,
    /// Per row: the protection-diode layer, or `None` for no credit.
    pub diode: Vec<Option<LayerId>>,
    /// Per row: the credit per square micrometre of diode area on the gate's
    /// net, sky130's `K`.
    pub diode_credit: Vec<f64>,
    /// Per row: a constant subtracted from the ratio of every gate with diode
    /// area on its net.
    pub diode_bonus: Vec<f64>,
    /// Per row: the largest allowed credited ratio. Positive from a deck.
    pub max_ratio: Vec<f64>,
    /// The deck's connectivity, shared by every row.
    pub stack: Stack,
}

/// Windowed metal density and the CMP thickness it implies: deck kind
/// `density_cmp`, written `density_cmp(L; window: len x len, step: len x len,
/// min: frac | none, max: frac | none, max_delta: frac | none,
/// partial_windows: bool, cmp: none | (target, sensitivity, max_delta))`.
///
/// Windows of `window` size start at the die's lower-left corner and step by
/// `step` while their origin is inside the die, so a step under the window
/// overlaps on purpose. A window's density is the merged layer's area inside
/// it over the window's area clipped to the die, in `0.0 ..= 1.0`. A row
/// flags a window below `min`, above `max`, differing from the next window to
/// its right or above by more than `max_delta`, or whose CMP excursion
/// `|sensitivity * (density - target)|` is above the model's `max_delta`. An
/// absent bound is not checked, never unlimited; a deck row must state at
/// least one. A die-clipped (partial) window is held to `min`, `max`, the
/// CMP limit and `max_delta` only when `partial_windows` is true: without it
/// a neighbour pair is compared only when both windows lie wholly inside the
/// die. No design intent is needed.
///
/// Catalog: ERC-B1, DRC-071 in the [check catalog]. Defined by [GF180MCU]
/// §13 (density); [LEF/DEF 5.8] `DENSITYCHECKWINDOW`/`DENSITYCHECKSTEP`;
/// [IHP SG13G2] MFil.h; [SKY130] m1.pd.2a/2b. Source tags are in
/// [check-sources.md].
///
/// Catalog DRC-113 (litho and CMP hotspots), in part: a density step between
/// neighbours and the CMP excursion are the hotspots a public model defines.
/// The excursion is the first-order form of the pattern-density model of
/// Ouma et al., "Characterization and modeling of oxide chemical-mechanical
/// polishing using planarization length and pattern density concepts",
/// IEEE Trans. Semicond. Manuf. 15(2):232–244, 2002, with the window standing
/// for the planarization length. Litho hotspots and a full polish simulation
/// need a foundry's calibrated models and are not checked.
///
/// [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
/// [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
/// [LEF/DEF 5.8]: https://coriolis.lip6.fr/doc/lefdef/lefdefref/lefdefref.pdf
/// [GF180MCU]: https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html
/// [IHP SG13G2]: https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc
/// [SKY130]: https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html
#[derive(Debug, Default, Clone, PartialEq)]
pub struct DensityCmpTable {
    /// Rule id and severity per row.
    pub head: RuleHead,
    /// Per row: the layer whose density is measured, merged first.
    pub layer: Vec<LayerId>,
    /// Window extent and step; a step under the window overlaps on purpose.
    pub window: Vec<(Dbu, Dbu)>,
    /// Per row: the `(x, y)` step between window origins, database units.
    /// Positive from a deck; a non-positive window or step refuses the row.
    pub step: Vec<(Dbu, Dbu)>,
    /// Per row: the smallest allowed density, or `None` for unchecked.
    pub min_density: Vec<Option<f64>>,
    /// Per row: the largest allowed density, or `None` for unchecked.
    pub max_density: Vec<Option<f64>>,
    /// Largest density difference between adjacent windows.
    pub max_neighbour_delta: Vec<Option<f64>>,
    /// Per row: the CMP thickness model, or `None` for no thickness check.
    pub cmp: Vec<Option<CmpModel>>,
    /// Evaluate a die-clipped window against its clipped area, or skip it.
    pub include_partial_windows: Vec<bool>,
}

/// The net of every store row on `layer` that is not a conductor: that of the
/// one conductor among `conductors` (bottom-up) the deck connects it to, the
/// lowest net among that conductor's shapes it overlaps with positive area.
/// Touching alone does not join, so a gate is not put on the diffusion beside
/// it. Of the conductors a shape overlaps:
///
/// - a cut joins only those its `connect via` rows name, so a via1 cut sits on
///   met1, not on the poly under it;
/// - a MOS gate terminal layer ([`Stack::gates`]) is taken first, the rules
///   below choosing among several; only a shape over none of them falls to
///   the rules below among all;
/// - one that another of them reaches upward through cuts (the stack's vias,
///   followed bottom-up) is routed over the shape, joined to it only through
///   those cuts, and is passed over: metal drawn over a gate is not its net;
/// - of the rest the topmost wins, so a derived gate `poly and diff` sits on
///   poly, not on the diffusion or well under it.
///
/// `false` when a layer will not validate.
fn attach(
    design: Design<'_>,
    layer: LayerId,
    stack: &Stack,
    conductors: &[LayerId],
    nets: &NetTable,
    net_of: &mut [NetId],
    scratch: &mut Scratch,
) -> bool {
    let store = design.store;
    if store.polys_on_layer(layer).is_empty() {
        return true;
    }
    if validate_layer_into(store, layer, &mut scratch.layer_a).is_err() {
        return false;
    }
    let mut mine = LayerRects::default();
    mine.build(store, layer, &scratch.layer_a);
    // `hit[poly * width + c]`: the lowest net of `conductors[c]` under `poly`.
    let width = conductors.len();
    let mut hit = vec![NetId::NONE; mine.len() * width];
    let mut theirs = LayerRects::default();
    for (c, &conductor) in conductors.iter().enumerate() {
        if validate_layer_into(store, conductor, &mut scratch.layer_b).is_err() {
            return false;
        }
        theirs.build(store, conductor, &scratch.layer_b);
        let under = SortedRects::new(theirs.labelled());
        for poly in 0..mine.len() {
            let slot = &mut hit[poly * width + c];
            for &r in mine.of(u32::try_from(poly).expect("a layer's polygons fit a u32")) {
                for (_, row) in under.overlapping(r) {
                    *slot = (*slot).min(nets.net_of(row));
                }
            }
        }
    }

    // `over[a * width + b]`: `conductors[b]` is above `conductors[a]`, reached
    // from it through cuts taken bottom-up.
    let place: Vec<Option<usize>> = conductors
        .iter()
        .map(|&c| stack.conductors.iter().position(|&s| s == c))
        .collect();
    let mut over = vec![false; width * width];
    for &(_, a, b) in &stack.vias {
        let ends =
            (conductors.iter().position(|&c| c == a)).zip(conductors.iter().position(|&c| c == b));
        if let Some((a, b)) = ends {
            if let (Some(pa), Some(pb)) = (place[a], place[b]) {
                let (lo, hi) = if pa < pb { (a, b) } else { (b, a) };
                over[lo * width + hi] |= pa != pb;
            }
        }
    }
    for via in 0..width {
        for a in 0..width {
            if over[a * width + via] {
                for b in 0..width {
                    over[a * width + b] |= over[via * width + b];
                }
            }
        }
    }
    let named: Vec<LayerId> = stack
        .vias
        .iter()
        .filter(|v| v.0 == layer)
        .flat_map(|&(_, a, b)| [a, b])
        .collect();
    let joins = |c: usize| named.is_empty() || named.contains(&conductors[c]);

    let gate = |c: usize| stack.gates.contains(&conductors[c]);
    let first = store.polys_on_layer(layer).start;
    for (offset, &poly) in mine.poly_of_row.iter().enumerate() {
        let hit = &hit[poly as usize * width..(poly as usize + 1) * width];
        let lies = |c: usize| hit[c] != NetId::NONE && joins(c);
        // The topmost of `among` that is over no other of them.
        let pick = |among: &dyn Fn(usize) -> bool| {
            (0..width)
                .rev()
                .find(|&c| among(c) && !(0..width).any(|d| among(d) && over[d * width + c]))
        };
        let on = pick(&|c| lies(c) && gate(c)).or_else(|| pick(&lies));
        net_of[first as usize + offset] = on.map_or(NetId::NONE, |c| hit[c]);
    }
    true
}

/// One layer merged: what an antenna row measures, so drawn polygons that
/// overlap count their shared area once.
#[derive(Debug, Default)]
struct Figures {
    /// Per figure: twice its area, holes excluded.
    area2: Vec<i128>,
    /// Per figure: twice its perimeter, holes included.
    perimeter2: Vec<i128>,
    /// `rows[start[f] .. start[f + 1]]`: the drawn store rows figure `f`
    /// covers, ascending.
    start: Vec<u32>,
    rows: Vec<PolyId>,
}

impl Figures {
    fn len(&self) -> usize {
        self.area2.len()
    }

    fn rows(&self, figure: usize) -> &[PolyId] {
        &self.rows[self.start[figure] as usize..self.start[figure + 1] as usize]
    }

    /// The figure's net: the lowest net among the drawn rows it covers.
    fn net(&self, figure: usize, net_of: &[NetId]) -> NetId {
        self.rows(figure)
            .iter()
            .map(|row| net_of[row.idx()])
            .min()
            .unwrap_or(NetId::NONE)
    }
}

/// `layer` merged into [`Figures`]. `None` when the layer will not validate
/// or merge.
fn merged(design: Design<'_>, layer: LayerId, scratch: &mut Scratch) -> Option<Figures> {
    validate_layer_into(design.store, layer, &mut scratch.layer_a).ok()?;
    let mut drawn = LayerRects::default();
    drawn.build(design.store, layer, &scratch.layer_a);
    union_into(
        &scratch.layer_a,
        &ValidatedLayer::default(),
        &mut scratch.layer_b,
    )
    .ok()?;
    let figures = &scratch.layer_b;
    let under = SortedRects::new(drawn.labelled());
    let (mut rects, mut start) = (Vec::new(), Vec::new());
    decompose_into(figures, &mut rects, &mut start);
    let mut out = Figures {
        start: vec![0],
        ..Figures::default()
    };
    for (idx, span) in (0..).zip(start.windows(2)) {
        let mine = &rects[span[0] as usize..span[1] as usize];
        out.area2
            .push(mine.iter().map(|r| 2 * r.area().raw()).sum());
        let poly = figures.get(idx);
        let perimeter: i128 = std::iter::once(poly.outer())
            .chain(poly.holes())
            .map(|ring| {
                let (xs, ys) = ring.coords();
                (0..xs.len())
                    .map(|i| {
                        let j = (i + 1) % xs.len();
                        i128::from((xs[j] - xs[i]).raw().abs() + (ys[j] - ys[i]).raw().abs())
                    })
                    .sum::<i128>()
            })
            .sum();
        out.perimeter2.push(2 * perimeter);
        let mut covered: Vec<PolyId> = mine
            .iter()
            .flat_map(|&r| under.overlapping(r))
            .map(|(_, row)| row)
            .collect();
        covered.sort_unstable();
        covered.dedup();
        out.rows.extend(covered);
        out.start
            .push(u32::try_from(out.rows.len()).expect("a layer's row count fits a u32"));
    }
    Some(out)
}

/// Puts every store row of `layers` on its net as the stack stands at `stage`
/// (`None`: the finished nets), cutting the stage's nets into `staged`. A
/// conductor's rows read the stage's nets; any other layer is [`attach`]ed.
/// The stage's net count, or `None` when a layer will not validate.
fn stage_nets(
    design: Design<'_>,
    stack: &Stack,
    stage: Option<usize>,
    layers: &[LayerId],
    staged: &mut NetTable,
    net_of: &mut [NetId],
    scratch: &mut Scratch,
) -> Option<usize> {
    let store = design.store;
    let connectivity = stage.map(|top| stack.stage(top));
    let nets: &NetTable = match &connectivity {
        Some(connectivity) => {
            extract_nets_into(store, connectivity, staged);
            staged
        }
        None => design.nets,
    };
    if nets.net_count() == 0 {
        for &layer in layers {
            for row in store.polys_on_layer(layer) {
                net_of[row as usize] = NetId::NONE;
            }
        }
        return Some(0);
    }
    // Conductors: the stage's, or (finished nets) every layer carrying a net.
    let conductors: Vec<LayerId> = match &connectivity {
        Some(connectivity) => connectivity.conductors.clone(),
        None => (0..store.layer_count())
            .map(|l| LayerId(u16::try_from(l).expect("a LayerId is a u16")))
            .filter(|&l| {
                store
                    .polys_on_layer(l)
                    .any(|row| nets.net_of(PolyId(row)) != NetId::NONE)
            })
            .collect(),
    };
    for &layer in layers {
        if conductors.contains(&layer) {
            for row in store.polys_on_layer(layer) {
                net_of[row as usize] = nets.net_of(PolyId(row));
            }
        } else if !attach(design, layer, stack, &conductors, nets, net_of, scratch) {
            return None;
        }
    }
    Some(nets.net_count())
}

/// One antenna row. Each gate figure's ratio is summed over the row's etch
/// stages: at each, the doubled collecting area of the collectors etched
/// there on the gate's net over the doubled gate area on that net. `judge`
/// receives the ratio and the diode area on the gate's net at the row's
/// stage, and returns the value compared with `limit`, or `None` for a gate
/// this row does not hold. Gates on one net at every stage share a ratio and
/// are judged once, reported at their lowest gate polygon. `examined` is the
/// number of such groups judged; `None` is `Refused` (a layer that will not
/// validate or merge).
#[allow(
    clippy::cast_precision_loss,
    reason = "a die's area in database units is far below 2^53"
)]
#[allow(clippy::too_many_arguments, reason = "one rule row's parameters")]
fn antenna_row(
    design: Design<'_>,
    head: (&RuleHead, usize),
    (gate_layer, collectors, diode): (LayerId, &[LayerId], Option<LayerId>),
    measures: &[AntennaMeasure],
    stack: &Stack,
    limit: f64,
    judge: impl Fn(f64, DbuArea) -> Option<f64>,
    scratch: &mut Scratch,
    out: &mut Violations,
) -> Option<u64> {
    let store = design.store;
    // With no gate there is nothing to measure, whatever the collectors hold
    // (a collector that cannot merge refuses only a row that would read it).
    let gates = merged(design, gate_layer, scratch)?;
    if gates.len() == 0 {
        return Some(0);
    }
    // A collector named twice collects once, with its first measure.
    let mut read: Vec<(LayerId, AntennaMeasure)> = Vec::new();
    for (&layer, &measure) in collectors.iter().zip(measures) {
        if !read.iter().any(|&(l, _)| l == layer) {
            read.push((layer, measure));
        }
    }
    let collected = read
        .iter()
        .map(|&(layer, _)| merged(design, layer, scratch))
        .collect::<Option<Vec<Figures>>>()?;
    let diodes = match diode {
        Some(layer) => Some(merged(design, layer, scratch)?),
        None => None,
    };

    // Each collector's etch stage. The row's stage is the highest; a layer the
    // stack does not place is etched with it. With no conductors every stage
    // is the finished nets.
    let row_stage = (!stack.conductors.is_empty()).then(|| {
        read.iter()
            .filter_map(|&(layer, _)| stack.standing(layer))
            .max()
            .unwrap_or(stack.conductors.len() - 1)
    });
    let etched: Vec<Option<usize>> = read
        .iter()
        .map(|&(layer, _)| row_stage.map(|top| stack.standing(layer).unwrap_or(top)))
        .collect();
    let mut stages = etched.clone();
    stages.sort_unstable();
    stages.dedup();

    // Per gate figure: the summed ratio, its net at each stage (stage-major),
    // and the doubled diode area on its net at the row's stage.
    let n = gates.len();
    let mut ratio = vec![0.0f64; n];
    let mut key = vec![NetId::NONE; n * stages.len()];
    let mut diode_area = vec![0i128; n];
    let mut net_of = vec![NetId::NONE; store.poly_count()];
    let mut staged = std::mem::take(&mut scratch.staged_nets);
    for (s, &stage) in stages.iter().enumerate() {
        let last = s + 1 == stages.len();
        let here: Vec<usize> = (0..read.len()).filter(|&c| etched[c] == stage).collect();
        let mut layers: Vec<LayerId> = here.iter().map(|&c| read[c].0).collect();
        layers.push(gate_layer);
        layers.extend(diode.filter(|_| last));
        layers.sort_unstable();
        layers.dedup();
        let Some(count) = stage_nets(
            design,
            stack,
            stage,
            &layers,
            &mut staged,
            &mut net_of,
            scratch,
        ) else {
            scratch.staged_nets = staged;
            return None;
        };

        let mut gate_area = vec![0i128; count];
        let mut collect = vec![0i128; count];
        let gate_net = &mut key[s * n..(s + 1) * n];
        for (g, net) in gate_net.iter_mut().enumerate() {
            *net = gates.net(g, &net_of);
            if *net != NetId::NONE {
                gate_area[net.idx()] += gates.area2[g];
            }
        }
        for &c in &here {
            let figures = &collected[c];
            for f in 0..figures.len() {
                let net = figures.net(f, &net_of);
                if net != NetId::NONE {
                    collect[net.idx()] += match read[c].1 {
                        AntennaMeasure::Area => figures.area2[f],
                        AntennaMeasure::Sidewall { thickness } => {
                            figures.perimeter2[f] * i128::from(thickness.raw())
                        }
                    };
                }
            }
        }
        for (g, net) in gate_net.iter().enumerate() {
            if *net != NetId::NONE {
                ratio[g] += collect[net.idx()] as f64 / gate_area[net.idx()] as f64;
            }
        }
        if let (true, Some(figures)) = (last, &diodes) {
            let mut on_net = vec![0i128; count];
            for f in 0..figures.len() {
                let net = figures.net(f, &net_of);
                if net != NetId::NONE {
                    on_net[net.idx()] += figures.area2[f];
                }
            }
            for (g, net) in gate_net.iter().enumerate() {
                if *net != NetId::NONE {
                    diode_area[g] = on_net[net.idx()];
                }
            }
        }
    }
    scratch.staged_nets = staged;

    // Gates on a net at the row's stage, grouped by their net at every stage,
    // the row's stage first.
    let top = stages.len() - 1;
    let net_at = |g: usize, s: usize| key[s * n + g];
    let mut order: Vec<usize> = (0..n).filter(|&g| net_at(g, top) != NetId::NONE).collect();
    let cmp = |a: &usize, b: &usize| {
        (0..=top)
            .rev()
            .map(|s| net_at(*a, s).cmp(&net_at(*b, s)))
            .find(|o| o.is_ne())
            .unwrap_or(std::cmp::Ordering::Equal)
    };
    order.sort_by(cmp);

    let limit = Measurement::Ratio(limit);
    let mut examined = 0u64;
    for group in order.chunk_by(|a, b| cmp(a, b).is_eq()) {
        let first = group[0];
        let Some(value) = judge(ratio[first], DbuArea::new(diode_area[first] / 2)) else {
            continue;
        };
        examined += 1;
        if !Measurement::Ratio(value).violates(limit, LimitSense::Maximum) {
            continue;
        }
        let poly = group
            .iter()
            .map(|&g| gates.rows(g)[0])
            .min()
            .expect("a group has a gate");
        out.push(Violation {
            rule: head.0.rule[head.1],
            layer: gate_layer,
            severity: head.0.severity[head.1],
            at: centre(store.poly_bbox(poly)),
            measured: Measurement::Ratio(value),
            limit,
            shapes: (poly, None),
        });
    }
    Some(examined)
}

/// Runs every [`AntennaTable`] row: one ratio per gate, summed over the
/// row's etch stages.
///
/// `examined` counts the gates on a net at the row's highest stage, those on
/// one net at every stage counted once (for a single-stage row, the gate
/// nets), less those the row's `diode` leaves to another row. A violation sits at the centre of the bounding box of the group's
/// lowest-numbered gate polygon, on the gate layer, measuring the ratio
/// against `max_ratio`. A row with gate shapes is refused when one of its
/// layers will not validate (a non-rectilinear shape) or merge.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_antenna(
    design: Design<'_>,
    table: &AntennaTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    for row in 0..table.head.len() {
        let rule = table.head.rule[row];
        let before = out.len();
        let span = table.collector_start[row] as usize..table.collector_start[row + 1] as usize;
        let examined = antenna_row(
            design,
            (&table.head, row),
            (
                table.gate[row],
                &table.collector[span.clone()],
                table.diode[row],
            ),
            &table.collector_measure[span],
            &table.stack,
            table.max_ratio[row],
            |ratio, diode| (diode.raw() == 0).then_some(ratio),
            scratch,
            out,
        );
        let (outcome, examined) = examined.map_or((Outcome::Refused, 0), |n| (Outcome::Ran, n));
        record_run(runs, out, before, rule, outcome, examined);
    }
}

/// Runs every [`AntennaElectricalTable`] row: the credited ratio per gate.
///
/// Reports as [`check_antenna`] does, the measured value being the credited
/// ratio. `grid` turns the diode's area in square database units into the
/// square micrometres its credit is stated per.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
pub fn check_antenna_electrical(
    design: Design<'_>,
    grid: Grid,
    table: &AntennaElectricalTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a resolution squared is far below 2^53"
    )]
    let per_um2 = (grid.dbu_per_um() * grid.dbu_per_um()) as f64;
    for row in 0..table.head.len() {
        let rule = table.head.rule[row];
        let (credit, bonus) = (table.diode_credit[row], table.diode_bonus[row]);
        let before = out.len();
        let span = table.collector_start[row] as usize..table.collector_start[row + 1] as usize;
        let examined = antenna_row(
            design,
            (&table.head, row),
            (
                table.gate[row],
                &table.collector[span.clone()],
                table.diode[row],
            ),
            &table.collector_measure[span],
            &table.stack,
            table.max_ratio[row],
            #[allow(
                clippy::cast_precision_loss,
                reason = "a diode's area in database units is far below 2^53"
            )]
            |ratio, diode_area| {
                // Both credits are for a diode: no diode on the net, none given.
                let bonus = if diode_area.raw() > 0 { bonus } else { 0.0 };
                Some(ratio - credit * (diode_area.raw() as f64 / per_um2) - bonus)
            },
            scratch,
            out,
        );
        let (outcome, examined) = examined.map_or((Outcome::Refused, 0), |n| (Outcome::Ran, n));
        record_run(runs, out, before, rule, outcome, examined);
    }
}

/// Window positions along a span: every window starts inside the die.
fn positions(span: i64, step: i64) -> usize {
    if span <= 0 {
        return 0;
    }
    usize::try_from((span - 1) / step + 1).expect("a window count fits a usize")
}

/// The half-open range of windows `[origin + i * step, + window]` that the
/// interval `[lo, hi]` contributes area to (an edge-on touch contributes none).
fn window_span(
    lo: i64,
    hi: i64,
    origin: i64,
    window: i64,
    step: i64,
    count: usize,
) -> (usize, usize) {
    let count = i64::try_from(count).expect("a window count fits an i64");

    // `div_euclid` floors a negative numerator; `/` would not.
    let first = (lo - window - origin).div_euclid(step) + 1;
    // `ceil((hi - origin) / step)`, spelled as a negated floor.
    let end = -((origin - hi).div_euclid(step));

    let first = first.clamp(0, count);
    let end = end.clamp(first, count);
    let narrow = |edge: i64| usize::try_from(edge).expect("a clamped window index is not negative");
    (narrow(first), narrow(end))
}

/// Window `(i, j)`, and the same window clipped to the die (the density
/// denominator). Every window from [`positions`] meets the die.
fn window_boxes(
    die: Bbox,
    at: (usize, usize),
    window: (Dbu, Dbu),
    step: (Dbu, Dbu),
) -> (Bbox, Bbox) {
    let index = |at: usize| i64::try_from(at).expect("a window index fits an i64");
    let xlo = die.xlo.raw() + index(at.0) * step.0.raw();
    let ylo = die.ylo.raw() + index(at.1) * step.1.raw();
    let (xhi, yhi) = (xlo + window.0.raw(), ylo + window.1.raw());
    let full = Bbox {
        xlo: Dbu::new_unchecked(xlo),
        ylo: Dbu::new_unchecked(ylo),
        xhi: Dbu::new_unchecked(xhi),
        yhi: Dbu::new_unchecked(yhi),
    };
    let clipped = full
        .intersection(die)
        .expect("a window position inside the grid meets the die");
    (full, clipped)
}

/// The half-open range of windows whose die-clipped box `[lo, hi]` touches,
/// boundary included (unlike [`window_span`]). `far` is the die's far edge: an
/// interval starting past it touches nothing.
fn window_touch_span(
    lo: i64,
    hi: i64,
    origin: i64,
    far: i64,
    window: i64,
    step: i64,
    count: usize,
) -> (usize, usize) {
    let count = i64::try_from(count).expect("a window count fits an i64");

    let first = -((window + origin - lo).div_euclid(step));
    let end = (hi - origin).div_euclid(step) + 1;

    let past = i64::from(lo > far) * count;
    let first = first.clamp(0, count).max(past);
    let end = end.clamp(first, count);
    let narrow = |edge: i64| usize::try_from(edge).expect("a clamped window index is not negative");
    (narrow(first), narrow(end))
}

/// `out[j * nx + i]`: the lowest store row whose box touches die-clipped window
/// `(i, j)`, or `u32::MAX`. `boxes[k]` is store row `first_row + k`.
fn window_owners_into(
    boxes: &[Bbox],
    first_row: u32,
    die: Bbox,
    window: (Dbu, Dbu),
    step: (Dbu, Dbu),
    grid: (usize, usize),
    out: &mut Vec<u32>,
) {
    let (nx, ny) = grid;
    let count = nx * ny;
    out.clear();
    out.resize(count, u32::MAX);

    for (offset, &bbox) in boxes.iter().enumerate() {
        let row = first_row + u32::try_from(offset).expect("a layer's row count fits a u32");
        let (i0, i1) = window_touch_span(
            bbox.xlo.raw(),
            bbox.xhi.raw(),
            die.xlo.raw(),
            die.xhi.raw(),
            window.0.raw(),
            step.0.raw(),
            nx,
        );
        let (j0, j1) = window_touch_span(
            bbox.ylo.raw(),
            bbox.yhi.raw(),
            die.ylo.raw(),
            die.yhi.raw(),
            window.1.raw(),
            step.1.raw(),
            ny,
        );
        for j in j0..j1 {
            for i in i0..i1 {
                let slot = j * nx + i;
                out[slot] = out[slot].min(row);
            }
        }
    }
}

/// The store row a window violation names; `fallback` for an empty window.
fn window_owner(owners: &[u32], slot: usize, fallback: u32) -> PolyId {
    let best = owners[slot];
    let none = u32::from(best == u32::MAX).wrapping_neg();
    PolyId((best & !none) | (fallback & none))
}

/// Runs every [`DensityCmpTable`] row over the window grid laid on `die`.
///
/// `examined` counts the windows held to the density and CMP limits: every
/// window with `partial_windows`, else only those wholly inside the die. A
/// violation sits at the centre of the die-clipped window, on the row's
/// layer, and names the lowest-numbered polygon whose box touches the window
/// (the layer's first polygon for an empty window). Density and neighbour
/// delta report ratios, the CMP check a length in database units. One window
/// can raise several violations. A row is refused when its window or step is
/// not positive or its layer will not validate or merge.
///
/// # Panics
///
/// Panics if `table`'s columns break the [table invariants](super#tables).
#[allow(
    clippy::cast_precision_loss,
    reason = "a die's area in database units is far below 2^53"
)]
pub fn check_density_cmp(
    design: Design<'_>,
    die: Bbox,
    table: &DensityCmpTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    let mut rects: Vec<Bbox> = Vec::new();
    let mut rect_start: Vec<u32> = Vec::new();
    let mut density: Vec<f64> = Vec::new();
    // Per window: whether the row holds it to its limits.
    let mut held: Vec<bool> = Vec::new();
    let mut owners: Vec<u32> = Vec::new();

    for row in 0..table.head.len() {
        let (rule, severity) = (table.head.rule[row], table.head.severity[row]);
        let (window, step) = (table.window[row], table.step[row]);
        let violations_before = out.len();

        // A non-positive window has no density; a non-positive step never advances.
        let layer = table.layer[row];
        if window.0.raw() <= 0 || window.1.raw() <= 0 || step.0.raw() <= 0 || step.1.raw() <= 0 {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }

        let Scratch {
            layer_a,
            layer_b,
            areas,
            ..
        } = &mut *scratch;

        // Self-union merges overlaps, so a density stays inside `0.0 ..= 1.0`.
        if validate_layer_into(design.store, layer, layer_a).is_err() {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }
        let operand: &_ = layer_a;
        if union_into(operand, operand, layer_b).is_err() {
            record_run(runs, out, violations_before, rule, Outcome::Refused, 0);
            continue;
        }
        decompose_into(layer_b, &mut rects, &mut rect_start);

        let nx = positions(die.xhi.raw() - die.xlo.raw(), step.0.raw());
        let ny = positions(die.yhi.raw() - die.ylo.raw(), step.1.raw());
        let count = nx * ny;
        areas.clear();
        areas.resize(count, DbuArea::new(0));

        // Rasterise the merged layer into the window grid.
        for rect in &rects {
            let (i0, i1) = window_span(
                rect.xlo.raw(),
                rect.xhi.raw(),
                die.xlo.raw(),
                window.0.raw(),
                step.0.raw(),
                nx,
            );
            let (j0, j1) = window_span(
                rect.ylo.raw(),
                rect.yhi.raw(),
                die.ylo.raw(),
                window.1.raw(),
                step.1.raw(),
                ny,
            );
            for j in j0..j1 {
                for i in i0..i1 {
                    let (_, clipped) = window_boxes(die, (i, j), window, step);
                    let slot = j * nx + i;
                    areas[slot] = areas[slot] + clipped_area(std::slice::from_ref(rect), clipped);
                }
            }
        }

        // An absent bound is not checked: the flag admits the compare's answer.
        let (min_on, min) = (
            table.min_density[row].is_some(),
            table.min_density[row].unwrap_or(0.0),
        );
        let (max_on, max) = (
            table.max_density[row].is_some(),
            table.max_density[row].unwrap_or(0.0),
        );
        let cmp = table.cmp[row];
        let partial = table.include_partial_windows[row];

        let boxes = design.store.layer_bboxes(layer);
        let store_rows = design.store.polys_on_layer(layer);
        // A window holding no geometry is attributed to the layer's lowest row.
        let fallback = if store_rows.start < store_rows.end {
            store_rows.start
        } else {
            0
        };
        window_owners_into(
            boxes,
            store_rows.start,
            die,
            window,
            step,
            (nx, ny),
            &mut owners,
        );

        // Row-major from the die's lower-left; the delta pass relies on it.
        density.clear();
        density.reserve(count);
        held.clear();
        held.reserve(count);
        let mut examined = 0u64;
        for j in 0..ny {
            for i in 0..nx {
                let (full, clipped) = window_boxes(die, (i, j), window, step);
                let counted = partial | die.contains(full);
                let numerator = areas[j * nx + i].raw();
                let denominator = clipped.area().raw();
                let value = numerator as f64 / denominator.max(1) as f64;
                density.push(value);
                held.push(counted);

                examined += u64::from(counted);
                let measured = Measurement::Ratio(value);
                let under = counted
                    & min_on
                    & measured.violates(Measurement::Ratio(min), LimitSense::Minimum);
                let over = counted
                    & max_on
                    & measured.violates(Measurement::Ratio(max), LimitSense::Maximum);

                if under {
                    out.push(Violation {
                        rule,
                        layer,
                        severity,
                        at: centre(clipped),
                        measured,
                        limit: Measurement::Ratio(min),
                        shapes: (window_owner(&owners, j * nx + i, fallback), None),
                    });
                }
                if over {
                    out.push(Violation {
                        rule,
                        layer,
                        severity,
                        at: centre(clipped),
                        measured,
                        limit: Measurement::Ratio(max),
                        shapes: (window_owner(&owners, j * nx + i, fallback), None),
                    });
                }

                if let Some(model) = cmp {
                    let excursion =
                        model.thickness_sensitivity.raw() as f64 * (value - model.target_density);
                    // Saturated at the coordinate domain: violates every limit.
                    #[allow(clippy::cast_possible_truncation, reason = "saturated first")]
                    let magnitude =
                        Dbu::new_unchecked(excursion.abs().min(MAX_ABS_DBU as f64) as i64);
                    if counted
                        & Measurement::Length(magnitude).violates(
                            Measurement::Length(model.max_abs_thickness_delta),
                            LimitSense::Maximum,
                        )
                    {
                        out.push(Violation {
                            rule,
                            layer,
                            severity,
                            at: centre(clipped),
                            measured: Measurement::Length(magnitude),
                            limit: Measurement::Length(model.max_abs_thickness_delta),
                            shapes: (window_owner(&owners, j * nx + i, fallback), None),
                        });
                    }
                }
            }
        }

        // Gradient to the two windows ahead (`+1`, `+nx`) the row holds; `min`
        // clamps the last column and row onto themselves, a zero difference.
        if let Some(delta) = table.max_neighbour_delta[row] {
            let limit = Measurement::Ratio(delta);
            for j in 0..ny {
                for i in 0..nx {
                    let slot = j * nx + i;
                    let ahead = [j * nx + (i + 1).min(nx - 1), (j + 1).min(ny - 1) * nx + i];
                    for neighbour in ahead.into_iter().filter(|&n| held[slot] & held[n]) {
                        let gap = Measurement::Ratio((density[slot] - density[neighbour]).abs());
                        if gap.violates(limit, LimitSense::Maximum) {
                            let (_, clipped) = window_boxes(die, (i, j), window, step);
                            out.push(Violation {
                                rule,
                                layer,
                                severity,
                                at: centre(clipped),
                                measured: gap,
                                limit,
                                shapes: (window_owner(&owners, j * nx + i, fallback), None),
                            });
                        }
                    }
                }
            }
        }

        record_run(runs, out, violations_before, rule, Outcome::Ran, examined);
    }
}

#[cfg(test)]
mod tests {
    use super::{positions, window_boxes, window_owners_into, Bbox, Dbu, LayerId, Stack};

    /// At an etch step only the conductors up to it exist: metal2's via row is
    /// cut, so a diode or gate reachable only through metal2 is not on the net
    /// yet. A cut collector stands on its lower conductor.
    ///
    /// Oracle: the etch-step model `docs/deck.md` states for `antenna` (each
    /// term counts what is connected when that layer is etched), by hand: at
    /// met1 the conductors through met1 and the licon and mcon rows exist,
    /// via1 does not, and a cut stands on its lower conductor.
    #[test]
    fn a_stage_holds_the_conductors_up_to_its_etch_and_the_vias_between_them() {
        let [diff, poly, li, met1, met2] = [0, 1, 2, 3, 4].map(LayerId);
        let [licon, mcon, via1] = [5, 6, 7].map(LayerId);
        let stack = Stack {
            conductors: vec![diff, poly, li, met1, met2],
            vias: vec![
                (licon, diff, li),
                (licon, poly, li),
                (mcon, li, met1),
                (via1, met1, met2),
            ],
            intra_layer_touch: true,
            gates: Vec::new(),
        };

        let at_met1 = stack.stage(stack.standing(met1).expect("a conductor"));
        assert_eq!(at_met1.conductors, [diff, poly, li, met1]);
        assert_eq!(at_met1.via_cut, [licon, licon, mcon]);

        assert_eq!(stack.standing(via1), stack.standing(met1));
        assert_eq!(stack.standing(licon), stack.standing(poly));

        let at_poly = stack.stage(stack.standing(poly).expect("a conductor"));
        assert_eq!(at_poly.conductors, [diff, poly]);
        assert!(at_poly.via_cut.is_empty());

        assert_eq!(Stack::default().standing(met1), None);
    }

    fn bbox(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Bbox {
        Bbox {
            xlo: Dbu::new_unchecked(xlo),
            ylo: Dbu::new_unchecked(ylo),
            xhi: Dbu::new_unchecked(xhi),
            yhi: Dbu::new_unchecked(yhi),
        }
    }

    /// The linear scan [`window_owners_into`] replaced: the lowest row whose
    /// bounding box overlaps the window clipped to the die.
    fn owner_by_scan(
        boxes: &[Bbox],
        first_row: u32,
        die: Bbox,
        at: (usize, usize),
        window: (Dbu, Dbu),
        step: (Dbu, Dbu),
    ) -> u32 {
        let (_, clipped) = window_boxes(die, at, window, step);
        boxes
            .iter()
            .position(|b| b.overlaps(clipped))
            .map_or(u32::MAX, |k| {
                first_row + u32::try_from(k).expect("a test row count fits a u32")
            })
    }

    /// The owner grid answers exactly what the scan did, window for window.
    ///
    /// The cases that separate this span from the area span are the boundary
    /// ones: a box touching a window edge-on is an owner and contributes no
    /// area, and a box past the die's far edge is clipped away rather than
    /// folded onto the border window. Both are in the table, along with
    /// overlapping and non-overlapping steps.
    ///
    /// Oracle: differential against `owner_by_scan`, the linear scan it
    /// replaced, on every window of five window/step layouts, with edge-on,
    /// clipped and off-die boxes.
    #[test]
    fn the_owner_grid_answers_what_the_linear_scan_did() {
        let die = bbox(0, 0, 300, 200);
        // Lowest row first, deliberately: the grid keeps the minimum, so a box
        // that must claim *no* window only proves it when nothing below it
        // would have claimed the same slot anyway.
        let boxes = [
            // Past the far edge on both axes, but near enough that an
            // *unclipped* window would still reach it. The one case the `far`
            // gate answers and the arithmetic alone does not.
            bbox(320, 250, 340, 260),
            bbox(400, 10, 500, 20),       // wholly past the die's far edge
            bbox(-500, -500, -400, -400), // wholly left of and below the die
            // Touches the edge shared by two windows exactly, on both axes.
            bbox(100, 0, 100, 200),
            bbox(10, 10, 40, 40),
            bbox(250, 150, 400, 400), // hangs off the far corner
            bbox(0, 0, 300, 200),     // the whole die
        ];
        let first_row = 7;

        let mut owners = Vec::new();
        for (wx, wy, sx, sy) in [
            (100, 100, 100, 100), // window == step, no overlap
            (100, 100, 50, 50),   // overlapping windows
            (150, 200, 100, 100), // window wider than the step
            (300, 200, 300, 200), // one window covering the whole die
            (7, 11, 13, 17),      // nothing divides anything
        ] {
            let window = (Dbu::new_unchecked(wx), Dbu::new_unchecked(wy));
            let step = (Dbu::new_unchecked(sx), Dbu::new_unchecked(sy));
            let nx = positions(die.xhi.raw() - die.xlo.raw(), sx);
            let ny = positions(die.yhi.raw() - die.ylo.raw(), sy);

            window_owners_into(&boxes, first_row, die, window, step, (nx, ny), &mut owners);
            assert_eq!(owners.len(), nx * ny, "one owner slot per window");

            for j in 0..ny {
                for i in 0..nx {
                    assert_eq!(
                        owners[j * nx + i],
                        owner_by_scan(&boxes, first_row, die, (i, j), window, step),
                        "window ({i}, {j}) of a {wx}x{wy} window stepped by {sx}x{sy}"
                    );
                }
            }
        }
    }
}
