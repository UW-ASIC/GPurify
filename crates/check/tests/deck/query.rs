//! The query API answers what the checker enforces (deck-library plan P2,
//! ledger D3; testing-plan L9b, "consumers read what the checker enforces").
//!
//! Oracle: differential against the checker, on planted cases. For every rule
//! of every shipped deck that a query answers for, a layout is drawn exactly
//! at the queried value, which the rules of that query must pass, and one grid
//! step under it, which they must flag with the largest violation `limit`
//! equal to the query. Every shape is drawn straight onto the rule's layer,
//! derived or not, and only the rules the query reads run on it.

use gpurify_check::deck::{compile, CompiledDeck};
use gpurify_check::drc::{Rule, RuleSet, SpacingQuery};
use gpurify_check::erc::rules::antenna::AntennaMeasure;
use gpurify_check::report::{Measurement, Outcome, Violations};
use gpurify_geom::{Dbu, DbuArea, Grid, LayerId, StrId, StrTable};
use gpurify_testgen::LayoutBuilder;

/// The shipped decks, as `gpurify::pdks` ships them.
const DECKS: [(&str, &str); 4] = [
    (
        "generic_finfet",
        include_str!("../../../../pdks/generic_finfet.deck"),
    ),
    ("gf180mcu", include_str!("../../../../pdks/gf180mcu.deck")),
    (
        "ihp_sg13g2",
        include_str!("../../../../pdks/ihp_sg13g2.deck"),
    ),
    ("sky130", include_str!("../../../../pdks/sky130.deck")),
];

fn grid() -> Grid {
    Grid::new(1000).expect("a 1 nm grid")
}

fn nm(raw: i64) -> Dbu {
    Dbu::new_unchecked(raw)
}

/// One shipped deck, compiled on the 1 nm grid, with its string table.
fn shipped(text: &str) -> (CompiledDeck, StrTable) {
    let mut strings = StrTable::default();
    let deck = compile(text, grid(), &mut strings).expect("a shipped deck compiles");
    (deck, strings)
}

/// Runs `rules` of `deck` over rectangles `[xlo, ylo, xhi, yhi]` on `layer`,
/// and returns the violations' limits. Every rule must run.
fn limits(
    deck: &CompiledDeck,
    rules: &[(StrId, Rule)],
    rects: &[(LayerId, [i64; 4])],
) -> Vec<Measurement> {
    let mut layout = LayoutBuilder::new(deck.layers.len());
    for &(layer, [xlo, ylo, xhi, yhi]) in rects {
        layout.rect(layer, xlo, ylo, xhi, yhi);
    }
    let (store, _) = layout.finish();
    let set = RuleSet {
        rules: rules.to_vec(),
        tables: deck.drc.tables.clone(),
        first_derived: None,
    };
    let mut out = Violations::default();
    let mut runs = Vec::new();
    set.run(&store, &mut out, &mut runs);
    for run in &runs {
        assert_eq!(run.outcome, Outcome::Ran, "{rects:?}: {run:?}");
    }
    out.limit
}

/// The largest length among `limits`; `None` when there is none.
fn largest_length(limits: &[Measurement]) -> Option<Dbu> {
    limits
        .iter()
        .map(|limit| match *limit {
            Measurement::Length(length) => length,
            other => panic!("a length rule reported {other:?}"),
        })
        .max()
}

/// The largest area among `limits`; `None` when there is none.
fn largest_area(limits: &[Measurement]) -> Option<DbuArea> {
    limits
        .iter()
        .map(|limit| match *limit {
            Measurement::Area(area) => area,
            other => panic!("an area rule reported {other:?}"),
        })
        .max()
}

/// The deck's rules for which `keep` holds.
fn rules_where(deck: &CompiledDeck, keep: impl Fn(&Rule) -> bool) -> Vec<(StrId, Rule)> {
    deck.drc
        .rules
        .iter()
        .copied()
        .filter(|(_, rule)| keep(rule))
        .collect()
}

/// A shape exactly `min_width` wide passes every width rule on its layer;
/// one unit narrower fails at that limit.
fn width_case(deck: &CompiledDeck, layer: LayerId, what: &str) {
    let q = deck
        .min_width(layer)
        .expect("the rule's own layer is bounded")
        .raw();
    assert!(q > 1, "{what}: a width of {q}");
    let rules = rules_where(
        deck,
        |rule| matches!(*rule, Rule::MinWidth { layer: on, .. } if on == layer),
    );
    let long = 10 * q + 1000;
    let at = |width: i64| limits(deck, &rules, &[(layer, [0, 0, width, long])]);
    assert_eq!(largest_length(&at(q)), None, "{what}: {q} wide");
    assert_eq!(
        largest_length(&at(q - 1)),
        Some(nm(q)),
        "{what}: {} wide",
        q - 1
    );
}

/// A shape of exactly `min_area` passes every area rule on its layer; one
/// unit smaller fails at that limit.
fn area_case(deck: &CompiledDeck, layer: LayerId, what: &str) {
    let q = deck
        .min_area(layer)
        .expect("the rule's own layer is bounded")
        .raw();
    let q = i64::try_from(q).expect("a shipped area fits a coordinate");
    let rules = rules_where(
        deck,
        |rule| matches!(*rule, Rule::MinArea { layer: on, .. } if on == layer),
    );
    let at = |area: i64| limits(deck, &rules, &[(layer, [0, 0, 1, area])]);
    assert_eq!(largest_area(&at(q)), None, "{what}: area {q}");
    assert_eq!(
        largest_area(&at(q - 1)),
        Some(DbuArea::new(i128::from(q))),
        "{what}: area {}",
        q - 1
    );
}

/// A hole of exactly `min_enclosed_area`, closed by four touching
/// rectangles, passes every hole rule on its layer; one unit smaller fails at
/// that limit.
fn hole_case(deck: &CompiledDeck, layer: LayerId, what: &str) {
    let q = deck
        .min_enclosed_area(layer)
        .expect("the rule's own layer is bounded")
        .raw();
    let q = i64::try_from(q).expect("a shipped area fits a coordinate");
    let rules = rules_where(
        deck,
        |rule| matches!(*rule, Rule::MinEnclosedArea { layer: on, .. } if on == layer),
    );
    // A 1-wide hole `h` high, framed 10 deep on every side.
    let at = |h: i64| {
        limits(
            deck,
            &rules,
            &[
                (layer, [-10, -10, 0, h + 10]),
                (layer, [1, -10, 11, h + 10]),
                (layer, [0, -10, 1, 0]),
                (layer, [0, h, 1, h + 10]),
            ],
        )
    };
    assert_eq!(largest_area(&at(q)), None, "{what}: hole {q}");
    assert_eq!(
        largest_area(&at(q - 1)),
        Some(DbuArea::new(i128::from(q))),
        "{what}: hole {}",
        q - 1
    );
}

/// Two rectangles side by side, `query.width_a` and `query.width_b` wide and
/// `query.run_length` long (at least as long as wide, so the widths are their
/// narrower sides and their facing edges are the run): the required spacing
/// apart they pass every same-layer spacing rule of the layer; one unit
/// closer they fail at that limit.
fn spacing_case(deck: &CompiledDeck, layer: LayerId, query: SpacingQuery, what: &str) {
    let (wa, wb, run) = (
        query.width_a.raw(),
        query.width_b.raw(),
        query.run_length.raw(),
    );
    assert!(run >= wa.max(wb), "{what}: {query:?} is not side by side");
    assert_eq!(
        query.end_of_line,
        Some(query.run_length),
        "{what}: the facing edges are the run"
    );
    let q = deck
        .required_spacing(layer, &query)
        .unwrap_or_else(|| panic!("{what}: no spacing for {query:?}"))
        .raw();
    let rules = rules_where(deck, |rule| {
        matches!(
            *rule,
            Rule::MinSpacing { layer: on, .. }
                | Rule::WideDependentSpacing { layer: on, .. }
                | Rule::AttachedWideSpacing { layer: on, .. }
                | Rule::PrlSpacing { layer: on, .. }
                | Rule::EolSpacing { layer: on, .. }
                | Rule::SpacingTable { layer: on, .. }
                if on == layer
        )
    });
    let at = |gap: i64| {
        limits(
            deck,
            &rules,
            &[
                (layer, [0, 0, wa, run]),
                (layer, [wa + gap, 0, wa + gap + wb, run]),
            ],
        )
    };
    assert!(q > 1, "{what}: a spacing of {q}");
    assert_eq!(largest_length(&at(q)), None, "{what}: {query:?} {q} apart");
    assert_eq!(
        largest_length(&at(q - 1)),
        Some(nm(q)),
        "{what}: {query:?} {} apart",
        q - 1
    );
}

/// Side by side, `width_a` and `width_b` wide, running `run` (raised to the
/// wider width).
fn side_by_side(width_a: i64, width_b: i64, run: i64) -> SpacingQuery {
    let run = nm(run.max(width_a).max(width_b));
    SpacingQuery {
        width_a: nm(width_a),
        width_b: nm(width_b),
        run_length: run,
        end_of_line: Some(run),
    }
}

/// An inner square enclosed by exactly the queried enclosure passes the
/// layer pair's rules of that kind; one unit less on one side fails at that
/// limit. `opposite` takes the two-sided rules, enclosed on left and right
/// only.
fn enclosure_case(deck: &CompiledDeck, inner: LayerId, outer: LayerId, opposite: bool, what: &str) {
    let enclosure = deck.enclosure(inner, outer);
    let q = if opposite {
        enclosure.opposite
    } else {
        enclosure.all_sides
    }
    .expect("the rule's own pair is bounded")
    .raw();
    let rules = rules_where(deck, |rule| match *rule {
        Rule::MinEnclosure {
            outer: o, inner: i, ..
        } => !opposite && (o, i) == (outer, inner),
        Rule::AsymmetricEnclosure {
            outer: o, inner: i, ..
        } => opposite && (o, i) == (outer, inner),
        _ => false,
    });
    let side = 100;
    let vertical = if opposite { 0 } else { q };
    let at = |left: i64| {
        limits(
            deck,
            &rules,
            &[
                (inner, [0, 0, side, side]),
                (outer, [-left, -vertical, side + q, side + vertical]),
            ],
        )
    };
    assert_eq!(largest_length(&at(q)), None, "{what}: enclosed by {q}");
    assert_eq!(
        largest_length(&at(q - 1)),
        Some(nm(q)),
        "{what}: one side {}",
        q - 1
    );
}

/// A row of one more cut than a rule's threshold, the queried spacing apart,
/// passes the layer's array rules; one unit closer fails at that limit.
fn via_case(deck: &CompiledDeck, layer: LayerId, threshold: u16, what: &str) {
    let cuts = u32::from(threshold) + 1;
    let q = deck
        .via_array_spacing(layer, cuts)
        .expect("the rule's own threshold makes an array")
        .raw();
    let rules = rules_where(
        deck,
        |rule| matches!(*rule, Rule::ViaArraySpacing { layer: on, .. } if on == layer),
    );
    let side = 10;
    let at = |gap: i64| {
        let rects: Vec<(LayerId, [i64; 4])> = (0..i64::from(cuts))
            .map(|i| {
                let x = i * (side + gap);
                (layer, [x, 0, x + side, side])
            })
            .collect();
        limits(deck, &rules, &rects)
    };
    assert_eq!(
        largest_length(&at(q)),
        None,
        "{what}: {cuts} cuts {q} apart"
    );
    assert_eq!(
        largest_length(&at(q - 1)),
        Some(nm(q)),
        "{what}: {cuts} cuts {} apart",
        q - 1
    );
}

/// Every rule of every shipped deck that a geometric query answers for: the
/// query is the limit the checker reports. Rules of other kinds (maximum
/// width, cut size, density, ...) are counted, so the loop is known not to
/// have skipped what it claims to cover.
#[test]
fn every_query_is_the_limit_the_checker_reports() {
    for (name, text) in DECKS {
        let (deck, strings) = shipped(text);
        let mut covered = 0;
        for &(id, rule) in &deck.drc.rules {
            let what = format!("{name} {}", strings.resolve(id));
            let base = |layer| deck.min_width(layer).map_or(100, Dbu::raw);
            match rule {
                Rule::MinWidth { layer, .. } => width_case(&deck, layer, &what),
                Rule::MinArea { layer, .. } => area_case(&deck, layer, &what),
                Rule::MinEnclosedArea { layer, .. } => hole_case(&deck, layer, &what),
                Rule::MinSpacing { layer, .. } => {
                    let w = base(layer);
                    spacing_case(&deck, layer, side_by_side(w, w, w), &what);
                }
                Rule::WideDependentSpacing {
                    layer,
                    width_threshold,
                    ..
                }
                | Rule::AttachedWideSpacing {
                    layer,
                    width_threshold,
                    ..
                } => {
                    let w = base(layer);
                    let query = side_by_side(width_threshold.raw(), w, w);
                    spacing_case(&deck, layer, query, &what);
                }
                Rule::PrlSpacing {
                    layer,
                    prl_threshold,
                    ..
                } => {
                    let w = base(layer);
                    spacing_case(&deck, layer, side_by_side(w, w, prl_threshold.raw()), &what);
                }
                Rule::EolSpacing {
                    layer, eol_width, ..
                } => {
                    let run = eol_width.raw() - 1;
                    let w = base(layer).min(run);
                    spacing_case(&deck, layer, side_by_side(w, w, run), &what);
                }
                Rule::SpacingTable { layer, table } => {
                    let table = &deck.drc.tables[table as usize];
                    let w = base(layer);
                    for row in 0..table.width.len() {
                        for column in 0..table.prl.len() {
                            let wide = if row == 0 {
                                w
                            } else {
                                table.width[row].raw() + 1
                            };
                            let run = table.prl[column].raw() + 1;
                            let what = format!("{what} cell ({row}, {column})");
                            spacing_case(&deck, layer, side_by_side(wide, w, run), &what);
                        }
                    }
                }
                Rule::MinEnclosure { outer, inner, .. } => {
                    enclosure_case(&deck, inner, outer, false, &what);
                }
                Rule::AsymmetricEnclosure { outer, inner, .. } => {
                    enclosure_case(&deck, inner, outer, true, &what);
                }
                Rule::ViaArraySpacing {
                    layer,
                    array_threshold,
                    ..
                } => via_case(&deck, layer, array_threshold, &what),
                _ => continue,
            }
            covered += 1;
        }
        assert!(covered > 0, "{name}: no rule a query answers for");
    }
}

/// The ERC queries read the rows the checks read: each against a value a
/// shipped deck states (oracle: the deck text, `pdks/sky130.deck`'s
/// `ar.met1.1`, `EM.met1_mcon`, `vgs.esd_nfet`, `vds.d10v5`, `vgs.01v8` and
/// `vds.01v8`).
#[test]
fn the_electrical_queries_read_what_the_deck_states() {
    let (deck, strings) = shipped(DECKS[3].1);
    let layer = |name| deck.layers.id(&strings, name).expect("a sky130 layer");
    let id = |name| strings.get(name).expect("interned");

    // rule ar.met1.1 antenna(gate, met1; max_ratio: 400, sidewall: 350nm, diode: none)
    let met1: Vec<_> = deck.antenna(layer("met1")).collect();
    assert_eq!(met1.len(), 1, "{met1:?}");
    assert_eq!(met1[0].rule, id("ar.met1.1"));
    assert_eq!(met1[0].gate, layer("gate"));
    assert_eq!(met1[0].max_ratio.to_bits(), 400f64.to_bits());
    assert_eq!(
        met1[0].measure,
        AntennaMeasure::Sidewall { thickness: nm(350) }
    );
    assert_eq!(met1[0].diode, None);

    // rule EM.met1_mcon em_current_density(met1, mcon; max_density: 2.8mA/um, max_current_per_cut: 0.36mA)
    let em: Vec<_> = deck.em_limit(layer("mcon")).collect();
    assert_eq!(em.len(), 1, "{em:?}");
    assert_eq!(em[0].rule, id("EM.met1_mcon"));
    assert_eq!(
        em[0].max_density.raw().to_bits(),
        2800f64.to_bits(),
        "2.8 mA/um is 2800 A/m"
    );
    assert_eq!(
        em[0].max_current_per_cut.raw().to_bits(),
        360f64.to_bits(),
        "0.36 mA is 360 uA"
    );

    // vgs.esd_nfet gate_oxide 5V; vds.d10v5 drain_source 11V (g5d10_fets).
    let esd = deck.fet_limits(id("sky130_fd_pr__esd_nfet_g5v0d10v5"));
    assert_eq!(
        esd.gate_oxide.map(|v| v.raw().to_bits()),
        Some(5000f64.to_bits())
    );
    assert_eq!(
        esd.drain_source.map(|v| v.raw().to_bits()),
        Some(11_000f64.to_bits())
    );
    // vgs.01v8 and vds.01v8, 1.95 V each (lv_fets).
    let lv = deck.fet_limits(id("sky130_fd_pr__nfet_01v8"));
    assert_eq!(
        lv.gate_oxide.map(|v| v.raw().to_bits()),
        Some(1950f64.to_bits())
    );
    assert_eq!(
        lv.drain_source.map(|v| v.raw().to_bits()),
        Some(1950f64.to_bits())
    );
}
