//! Incremental DRC (catalog FLOW-008): after an edit, check again only the
//! part of the layout the edit can change, and keep the rest of the
//! previous run's findings.
//!
//! Data in: a deck, the previous run ([`DrcState`]) and the edited layout's
//! store, built as the previous one was (drawn layers, then the deck's
//! derived ones, as [`derive_layers`] computes them). Data out: the edited
//! layout's [`DrcState`], whose findings are the ones [`check`] gives it:
//! the same violations, every one naming the edited store's rows.
//!
//! A rule is *local* when each finding it makes depends only on shapes
//! within its reach `H` of the shapes it names, and lies within `H` of
//! them: widths, spacings, enclosures, areas, notches, cuts. `H` is the
//! sum of the rule's lengths, plus twice every `sized` and `extended`
//! length the deck's derived layers apply (a derived shape can reach that
//! far past its sources). The drawn shapes the edit added or removed are
//! the seeds. The edited layout's drawn shapes are joined into clusters,
//! two shapes `H` or less apart (box to box) in one cluster; a cluster `H`
//! or less from a seed is dirty, and so is one whose zone (its shapes'
//! boxes grown by `H`) meets a dirty one's or a removed seed's. A local
//! rule runs again on the dirty clusters alone, and keeps every previous
//! finding outside their zones: a local rule's findings on clusters `H`
//! apart are the union of each one's, and a clean cluster is the same
//! shapes, as far from the rest, as before.
//!
//! The rest run again on the whole layout: the density and whole-design
//! kinds, the net, stack, pattern and colouring kinds, a rule on a layer
//! derived from texts or cell names (which a store built in memory lacks),
//! and a local rule that did not run (or did not run before) on its dirty
//! part. As [`RuleSet::run`]: no nets (a `net_spacing` row refuses), no
//! stages, waivers or custom rules.
//!
//! [`RuleSet::run`]: gpurify_check::drc::RuleSet::run

use super::triage::root;
use gpurify_check::deck::CompiledDeck;
use gpurify_check::drc::RuleSet;
use gpurify_check::report::{Outcome, RuleRun, Violation, Violations};
use gpurify_geom::ops::Point;
use gpurify_geom::{Bbox, Dbu, GeometryStore, GeometryStoreBuilder, LayerId, PolyId};
use gpurify_ingest::deck::{DerivedOp, ParamSource, ParamValue};
use gpurify_ingest::layout::derive_layers;
use gpurify_ingest::{Provenance, StrTable};
use std::collections::HashMap;

/// A DRC run's layout and findings: what [`recheck`] starts from.
#[derive(Debug)]
pub struct DrcState {
    /// The layout: drawn layers, then the deck's derived ones.
    pub store: GeometryStore,
    /// The findings, in rule order.
    pub violations: Violations,
    /// One row per rule, in deck order. After [`recheck`], a local rule's
    /// `examined` counts what it looked at again, not the whole layout.
    pub runs: Vec<RuleRun>,
}

/// The kinds a finding of which can depend on shapes far from it, or that
/// report the design as a whole.
const WHOLE: [&str; 16] = [
    "density",
    "global_density",
    "density_balance",
    "cover_density",
    "count",
    "total_area",
    "critical_area",
    "mean_critical_area",
    "via_redundancy",
    "dfm_score",
    "net_spacing",
    "origin",
    "via_stack",
    "multi_patterning",
    "anchored_patterning",
    "pattern_match",
];

/// Every DRC rule of `deck` on `store`, as [`RuleSet::run`] runs it.
///
/// [`RuleSet::run`]: gpurify_check::drc::RuleSet::run
pub fn check(deck: &CompiledDeck, store: GeometryStore) -> DrcState {
    let (mut violations, mut runs) = (Violations::default(), Vec::new());
    deck.drc.run(&store, &mut violations, &mut runs);
    DrcState {
        store,
        violations,
        runs,
    }
}

/// The local rules of `deck` (by index into `deck.drc.rules`) and their
/// reach `H`, in grid units.
fn local_rules(deck: &CompiledDeck, strings: &StrTable) -> (Vec<bool>, i64) {
    let layers = &deck.layers;
    let count = layers.len();
    // A layer computed from texts or cell names, which a store built in
    // memory does not hold.
    let mut labelled = vec![false; count];
    for at in 0..count {
        let layer = LayerId(u16::try_from(at).expect("a LayerId is a u16"));
        labelled[at] = matches!(
            layers.op(layer),
            Some(DerivedOp::WithText { .. } | DerivedOp::TextsOutside | DerivedOp::InCells { .. })
        ) || layers.operands(layer).iter().any(|o| labelled[o.idx()]);
    }
    let source = deck.source(strings);
    let grown: i64 = source
        .derived
        .iter()
        .map(|row| match row.op {
            DerivedOp::Sized(dx, dy) => dx.raw().abs() + dy.raw().abs(),
            DerivedOp::Extended {
                begin,
                end,
                outside,
                inside,
            } => begin.raw() + end.raw() + outside.raw() + inside.raw(),
            _ => 0,
        })
        .sum();
    let mut reach = 0;
    let local = deck
        .drc
        .rules
        .iter()
        .map(|(id, rule)| {
            let reads = rule.layers().into_iter().flatten();
            let local = !WHOLE.contains(&rule.kind()) && !reads.clone().any(|l| labelled[l.idx()]);
            if local {
                let name = strings.resolve(*id);
                let lengths: i64 = (source.rules.iter())
                    .filter(|row| row.id == name)
                    .flat_map(|row| &row.params)
                    .map(|(_, value)| match value {
                        ParamSource::Value(ParamValue::Length(d)) => d.raw().abs(),
                        _ => 0,
                    })
                    .sum();
                reach = reach.max(lengths);
            }
            local
        })
        .collect();
    (local, reach + 2 * grown)
}

/// How far a local rule of `deck` reaches (module docs), in grid units.
pub(crate) fn reach(deck: &CompiledDeck, strings: &StrTable) -> i64 {
    local_rules(deck, strings).1
}

/// A drawn row's geometry, which identifies it across two stores.
type Key = (LayerId, Vec<Dbu>, Vec<Dbu>);

fn key(store: &GeometryStore, row: u32) -> Key {
    let (xs, ys) = store.poly_verts(PolyId(row));
    (store.poly_layer(PolyId(row)), xs.to_vec(), ys.to_vec())
}

/// Rows of `layers` by geometry, each key's rows ascending.
fn by_key(store: &GeometryStore, layers: std::ops::Range<usize>) -> HashMap<Key, Vec<u32>> {
    let mut rows: HashMap<Key, Vec<u32>> = HashMap::new();
    for layer in layers {
        let layer = LayerId(u16::try_from(layer).expect("a LayerId is a u16"));
        for row in store.polys_on_layer(layer) {
            rows.entry(key(store, row)).or_default().push(row);
        }
    }
    rows
}

/// The Chebyshev gap between two boxes; 0 when they touch or overlap.
fn gap(a: Bbox, b: Bbox) -> i64 {
    let x = (b.xlo - a.xhi).raw().max((a.xlo - b.xhi).raw()).max(0);
    let y = (b.ylo - a.yhi).raw().max((a.ylo - b.yhi).raw()).max(0);
    x.max(y)
}

fn grow(b: Bbox, by: i64) -> Bbox {
    let d = |v: Dbu, by: i64| Dbu::new_unchecked(v.raw() + by);
    Bbox {
        xlo: d(b.xlo, -by),
        ylo: d(b.ylo, -by),
        xhi: d(b.xhi, by),
        yhi: d(b.yhi, by),
    }
}

fn holds(b: Bbox, p: Point) -> bool {
    b.xlo <= p.x && p.x <= b.xhi && b.ylo <= p.y && p.y <= b.yhi
}

/// The DRC findings of `store`, an edit of `previous.store`, as
/// [`check`] gives them, checking again only what the edit can change
/// (module docs). `strings` is the table `deck` was compiled into.
///
/// ponytail: clustering sweeps boxes by x and the zone closure is a
/// quadratic scan over dirty zones; a spatial index if edits on large
/// layouts make either show in a profile.
pub fn recheck(
    deck: &CompiledDeck,
    strings: &StrTable,
    previous: &DrcState,
    store: GeometryStore,
) -> DrcState {
    let drawn = deck
        .drc
        .first_derived
        .map_or(store.layer_count(), |l| l.idx().min(store.layer_count()));
    let (local, reach) = local_rules(deck, strings);
    let old = &previous.store;

    // Seeds: drawn rows added and removed, matched by geometry; and where
    // each previous drawn row is now.
    let mut unmatched = by_key(old, 0..drawn);
    for rows in unmatched.values_mut() {
        rows.reverse();
    }
    let mut moved: HashMap<u32, u32> = HashMap::new();
    let mut added = Vec::new();
    let rows: Vec<u32> = (0..drawn)
        .flat_map(|l| store.polys_on_layer(LayerId(u16::try_from(l).expect("a LayerId"))))
        .collect();
    for &row in &rows {
        match unmatched.get_mut(&key(&store, row)).and_then(Vec::pop) {
            Some(was) => {
                moved.insert(was, row);
            }
            None => added.push(row),
        }
    }
    let removed: Vec<Bbox> = (unmatched.values().flatten())
        .map(|&row| old.poly_bbox(PolyId(row)))
        .collect();

    // Clusters of the edited layout's drawn rows, `reach` apart.
    let boxes: Vec<Bbox> = rows.iter().map(|&r| store.poly_bbox(PolyId(r))).collect();
    let mut parent: Vec<usize> = (0..rows.len()).collect();
    let mut by_x: Vec<usize> = (0..rows.len()).collect();
    by_x.sort_unstable_by_key(|&i| boxes[i].xlo);
    for (k, &i) in by_x.iter().enumerate() {
        for &j in &by_x[k + 1..] {
            if (boxes[j].xlo - boxes[i].xhi).raw() > reach {
                break;
            }
            if gap(boxes[i], boxes[j]) <= reach {
                let (a, b) = (root(&mut parent, i), root(&mut parent, j));
                parent[a] = b;
            }
        }
    }
    let cluster: Vec<usize> = (0..rows.len()).map(|i| root(&mut parent, i)).collect();
    let mut dirty = vec![false; rows.len()];
    let index: HashMap<u32, usize> = rows.iter().enumerate().map(|(i, &r)| (r, i)).collect();
    for row in &added {
        dirty[cluster[index[row]]] = true;
    }
    for (i, &b) in boxes.iter().enumerate() {
        if removed.iter().any(|&seed| gap(b, seed) <= reach) {
            dirty[cluster[i]] = true;
        }
    }
    // Zones: a dirty cluster's, and a removed seed's; a clean cluster whose
    // zone meets one is dirty too, until none does.
    let mut zones: Vec<Bbox> = removed.iter().map(|&b| grow(b, reach)).collect();
    let mut taken = vec![false; rows.len()];
    loop {
        for i in 0..rows.len() {
            if dirty[cluster[i]] && !taken[i] {
                taken[i] = true;
                zones.push(grow(boxes[i], reach));
            }
        }
        let meets = |i: usize| {
            let z = grow(boxes[i], reach);
            zones.iter().any(|&other| gap(z, other) == 0)
        };
        let newly: Vec<usize> = (0..rows.len())
            .filter(|&i| !dirty[cluster[i]] && meets(i))
            .map(|i| cluster[i])
            .collect();
        if newly.is_empty() {
            break;
        }
        for c in newly {
            dirty[c] = true;
        }
    }

    // The dirty part, drawn, with the deck's layers derived from it.
    let mut builder = GeometryStoreBuilder::default();
    let mut pushed = Vec::new();
    for (i, &row) in rows.iter().enumerate() {
        if dirty[cluster[i]] {
            let (xs, ys) = store.poly_verts(PolyId(row));
            builder.push(store.poly_layer(PolyId(row)), xs, ys);
            pushed.push(row);
        }
    }
    let (mut part, order) = builder.finish(store.layer_count());
    derive_layers(&mut part, &deck.layers, &Provenance::default(), strings)
        .expect("deriving layers in memory does not fail");
    let derived_rows = by_key(&store, drawn..store.layer_count());
    let to_new = |from: &GeometryStore, row: PolyId, drawn_map: &dyn Fn(u32) -> Option<u32>| {
        if row.0 == u32::MAX || row.idx() >= from.poly_count() {
            return row;
        }
        let mapped = if from.poly_layer(row).idx() < drawn {
            drawn_map(row.0)
        } else {
            derived_rows.get(&key(from, row.0)).map(|rows| rows[0])
        };
        PolyId(mapped.unwrap_or(u32::MAX))
    };
    let from_part = |row: u32| Some(pushed[order[row as usize] as usize]);
    let from_old = |row: u32| moved.get(&row).copied();

    let any_dirty = dirty.iter().any(|&d| d) || !removed.is_empty();
    let mut part_rules = deck.drc.clone();
    part_rules.rules = (deck.drc.rules.iter().zip(&local))
        .filter(|(_, &local)| local)
        .map(|(rule, _)| *rule)
        .collect();
    let (mut part_out, mut part_runs) = (Violations::default(), Vec::new());
    if any_dirty {
        part_rules.run(&part, &mut part_out, &mut part_runs);
    }
    let old_run = |id| previous.runs.iter().find(|run: &&RuleRun| run.rule == id);
    let part_run = |id| part_runs.iter().find(|run: &&RuleRun| run.rule == id);
    let again: Vec<bool> = (deck.drc.rules.iter().zip(&local))
        .map(|(&(id, _), &local)| {
            !local
                || old_run(id).is_none_or(|run| run.outcome != Outcome::Ran)
                || (any_dirty && part_run(id).is_none_or(|run| run.outcome != Outcome::Ran))
        })
        .collect();
    let mut whole_rules: RuleSet = deck.drc.clone();
    whole_rules.rules = (deck.drc.rules.iter().zip(&again))
        .filter(|(_, &again)| again)
        .map(|(rule, _)| *rule)
        .collect();
    let (mut whole_out, mut whole_runs) = (Violations::default(), Vec::new());
    whole_rules.run(&store, &mut whole_out, &mut whole_runs);

    let mut violations = Violations::default();
    let mut runs = Vec::with_capacity(deck.drc.rules.len());
    let in_zone = |at: Point| zones.iter().any(|&z| holds(z, at));
    for (&(id, _), &again) in deck.drc.rules.iter().zip(&again) {
        let before = violations.len();
        let mut take = |from: &Violations,
                        keep: &dyn Fn(&Violation) -> bool,
                        map: &dyn Fn(PolyId) -> PolyId| {
            for row in (0..from.len()).filter(|&row| from.rule[row] == id) {
                let mut v = from.get(row);
                if keep(&v) {
                    v.shapes = (map(v.shapes.0), v.shapes.1.map(map));
                    violations.push(v);
                }
            }
        };
        let run = if again {
            take(&whole_out, &|_| true, &|row| row);
            *whole_runs
                .iter()
                .find(|run| run.rule == id)
                .expect("a run per rule")
        } else {
            take(&previous.violations, &|v| !in_zone(v.at), &|row| {
                to_new(old, row, &from_old)
            });
            take(&part_out, &|_| true, &|row| to_new(&part, row, &from_part));
            RuleRun {
                rule: id,
                outcome: Outcome::Ran,
                examined: part_run(id).map_or(0, |run| run.examined),
                violations: 0,
            }
        };
        runs.push(RuleRun {
            violations: u32::try_from(violations.len() - before).unwrap_or(u32::MAX),
            ..run
        });
    }
    DrcState {
        store,
        violations,
        runs,
    }
}
