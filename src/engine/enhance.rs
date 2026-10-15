//! Automated DRC-clean layout enhancement (catalog FLOW-009): `gpurify
//! enhance` adds a second cut beside each single-cut via that has room for
//! one, and widens power straps, as the deck configures them, and keeps
//! only the edits that add no DRC finding.
//!
//! Data in: a GDSII layout and its deck. Data out: the layout's GDSII with
//! the kept edits added ([`enhance_gds`]).
//!
//! The candidates: for each `via_redundancy(cut, lower, upper; pitch,
//! space)` rule on a drawn cut layer, the cut its definition finds room
//! for beside each single-cut via ([`redundant_cuts`]), wholly on the two
//! shapes the via joins; and for each `widen <layer> net "<pattern>" by
//! <len>` line, a strip `len` wide along each long side of every
//! rectangle on the layer whose net carries a matching label, where the
//! strip touches no shape of the layer, and no cut joining the layer,
//! that is on another net. Neither joins two nets.
//!
//! All candidates are added and the layout checked as `gpurify drc`
//! checks it. A finding the input did not have, by rule and place (by
//! rule alone for a kind that reports the design as a whole, such as
//! `via_redundancy`, whose place moves as vias are fixed), takes back
//! every candidate within the deck's reach of it ([`super::incremental`]),
//! or every candidate when none is that near; this repeats until no new
//! finding is left. So the output has no finding the input lacked, and
//! each iteration takes back at least one candidate.
//!
//! [`redundant_cuts`]: gpurify_check::drc::rules::via::redundant_cuts

use super::pipeline::{extract, load_bytes, Inputs, Loaded};
use super::run::{run_checks, Checks, EngineError, Outputs, RunOptions};
use gpurify_check::deck::DeckFn;
use gpurify_check::drc::rules::via::redundant_cuts;
use gpurify_check::drc::Rule;
use gpurify_check::report::Measurement;
use gpurify_geom::ops::Point;
use gpurify_geom::{Bbox, Dbu, LayerId, PolyId};
use gpurify_ingest::layout::gds::with_boxes;
use gpurify_ingest::layout::glob_matches;
use gpurify_ingest::StrId;
use std::collections::BTreeMap;

/// What [`enhance_gds`] kept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Enhanced {
    /// Redundant cuts added.
    pub cuts: usize,
    /// Strap sides widened.
    pub sides: usize,
}

/// One edit, kept or taken back whole: boxes on stream pairs (a cut and
/// its metal patches, or a strap's strip), and whether it is a cut.
#[derive(Debug, Clone)]
struct Candidate {
    boxes: Vec<((u16, u16), Bbox)>,
    cut: bool,
}

/// The kinds that report the design as a whole, at a place that moves as
/// the design changes: their findings are told apart by rule alone.
const DESIGN: [&str; 7] = [
    "via_redundancy",
    "dfm_score",
    "critical_area",
    "mean_critical_area",
    "global_density",
    "count",
    "total_area",
];

/// A measurement as a number, for how far past its limit it lies.
fn value(m: Measurement) -> f64 {
    #[expect(clippy::cast_precision_loss, reason = "a comparison, not a report")]
    match m {
        Measurement::Ratio(x) => x,
        Measurement::Length(d) => d.raw() as f64,
        Measurement::Area(a) => a.raw() as f64,
        Measurement::Count(n) => f64::from(n),
        _ => 0.0,
    }
}

/// The findings of a run, counted by rule and place, with how far the
/// worst of them lies past its limit for a design-wide kind (0 for the
/// rest): such a finding getting worse is a new one.
fn findings(loaded: &Loaded, out: &Outputs) -> BTreeMap<(StrId, i64, i64), (usize, f64, Point)> {
    let design = |id: StrId| {
        (loaded.deck.drc.rules.iter())
            .any(|&(rule, kind)| rule == id && DESIGN.contains(&kind.kind()))
    };
    let mut counts = BTreeMap::new();
    for row in 0..out.violations.len() {
        let v = out.violations.get(row);
        let (place, past) = if design(v.rule) {
            ((0, 0), (value(v.measured) - value(v.limit)).abs())
        } else {
            ((v.at.x.raw(), v.at.y.raw()), 0.0)
        };
        let entry = counts
            .entry((v.rule, place.0, place.1))
            .or_insert((0, 0.0_f64, v.at));
        entry.0 += 1;
        entry.1 = entry.1.max(past);
    }
    counts
}

/// The layout as given, checked: its findings and net count.
fn checked(
    inputs: &Inputs,
    gds: &[u8],
    decks: &[(&str, DeckFn)],
) -> Result<(Loaded, super::Extracted, Outputs), EngineError> {
    let loaded = load_bytes(inputs, gds, decks)?;
    let extracted = extract(&loaded)?;
    let drc = RunOptions {
        checks: Checks {
            drc: true,
            ..Checks::default()
        },
        ..RunOptions::default()
    };
    let (outputs, _) = run_checks(&loaded, &extracted, &drc);
    Ok((loaded, extracted, outputs))
}

fn bbox(xlo: Dbu, ylo: Dbu, xhi: Dbu, yhi: Dbu) -> Bbox {
    Bbox { xlo, ylo, xhi, yhi }
}

/// Whether two boxes share a point, edges and corners included.
fn touch(a: Bbox, b: Bbox) -> bool {
    a.xlo <= b.xhi && b.xlo <= a.xhi && a.ylo <= b.yhi && b.ylo <= a.yhi
}

/// The layer and every cut layer that joins it: what metal added on it
/// can touch to join a net.
fn reached(loaded: &Loaded, layer: LayerId) -> Vec<LayerId> {
    let connectivity = &loaded.deck.connectivity;
    std::iter::once(layer)
        .chain(
            (connectivity.via_cut.iter())
                .zip(&connectivity.via_connects)
                .filter(|(_, &(a, b))| a == layer || b == layer)
                .map(|(&cut, _)| cut),
        )
        .collect()
}

/// Whether metal added at `b` on `layer` joins nothing: the shapes it
/// touches there are on one net, and every cut it touches already lands
/// on a shape of that net there (a cut is on no net of its own).
fn one_net(loaded: &Loaded, extracted: &super::Extracted, layer: LayerId, b: Bbox) -> bool {
    let (store, nets) = (&loaded.store, &extracted.nets);
    let touching = |l: LayerId, b: Bbox| {
        store
            .polys_on_layer(l)
            .map(PolyId)
            .filter(move |&poly| touch(store.poly_bbox(poly), b))
    };
    let mut on_layer = touching(layer, b).map(|poly| nets.net_of(poly));
    let Some(net) = on_layer.next() else {
        return true;
    };
    on_layer.all(|other| other == net)
        && reached(loaded, layer).into_iter().skip(1).all(|cut| {
            touching(cut, b).all(|poly| {
                touching(layer, store.poly_bbox(poly)).any(|metal| nets.net_of(metal) == net)
            })
        })
}

/// Every candidate the deck's rules and `widen` lines give (module docs).
fn candidates(loaded: &Loaded, extracted: &super::Extracted) -> Vec<Candidate> {
    let (store, deck) = (&loaded.store, &loaded.deck);
    let mut out = Vec::new();
    for (_, rule) in &deck.drc.rules {
        let Rule::ViaRedundancy {
            cut,
            lower,
            upper,
            pitch,
            space,
            ..
        } = *rule
        else {
            continue;
        };
        if [cut, lower, upper]
            .iter()
            .any(|&l| deck.layers.is_derived(l))
        {
            continue;
        }
        let pair = |layer| deck.layers.stream_of(layer);
        for insertion in
            redundant_cuts(store, (cut, lower, upper), (pitch, space)).unwrap_or_default()
        {
            let patches = [(lower, insertion.lower), (upper, insertion.upper)];
            if !patches
                .iter()
                .all(|&(layer, patch)| patch.is_none_or(|b| one_net(loaded, extracted, layer, b)))
            {
                continue;
            }
            let boxes = std::iter::once((pair(cut), insertion.cut))
                .chain(
                    patches
                        .iter()
                        .filter_map(|&(layer, patch)| Some((pair(layer), patch?))),
                )
                .collect();
            out.push(Candidate { boxes, cut: true });
        }
    }
    let nets = &extracted.nets;
    for widen in &deck.edits.widen {
        let layer = (deck.layers.id(&loaded.strings, &widen.layer))
            .expect("the deck checked its widen layers");
        let pair = deck.layers.stream_of(layer);
        let by = widen.by;
        for row in store.polys_on_layer(layer) {
            let poly = PolyId(row);
            let named = (extracted.ports.names_of(nets.net_of(poly)).iter())
                .any(|&name| glob_matches(&widen.net, loaded.strings.resolve(name)));
            let (xs, ys) = store.poly_verts(poly);
            let b = store.poly_bbox(poly);
            let rectangle = xs.len() == 4
                && xs.iter().all(|&x| x == b.xlo || x == b.xhi)
                && ys.iter().all(|&y| y == b.ylo || y == b.yhi);
            if !named || !rectangle {
                continue;
            }
            let strips = if (b.xhi - b.xlo) <= (b.yhi - b.ylo) {
                [
                    bbox(b.xlo - by, b.ylo, b.xlo, b.yhi),
                    bbox(b.xhi, b.ylo, b.xhi + by, b.yhi),
                ]
            } else {
                [
                    bbox(b.xlo, b.ylo - by, b.xhi, b.ylo),
                    bbox(b.xlo, b.yhi, b.xhi, b.yhi + by),
                ]
            };
            for strip in strips {
                if one_net(loaded, extracted, layer, strip) {
                    out.push(Candidate {
                        boxes: vec![(pair, strip)],
                        cut: false,
                    });
                }
            }
        }
    }
    out
}

/// `inputs.layout`'s GDSII with the deck's enhancements that add no DRC
/// finding (module docs), and how many of each it kept.
///
/// ponytail: each round reloads and rechecks the whole layout; check
/// rounds with [`super::incremental::recheck`] if large layouts need it.
///
/// # Errors
///
/// [`EngineError`] when the layout or deck cannot be read, or its nets
/// extracted.
pub fn enhance_gds(
    inputs: &Inputs,
    decks: &[(&str, DeckFn)],
) -> Result<(Vec<u8>, Enhanced), EngineError> {
    let bytes = gpurify_ingest::layout::read_gds_bytes(&inputs.layout)
        .map_err(super::pipeline::LoadError::from)?;
    let (loaded, extracted, outputs) = checked(inputs, &bytes, decks)?;
    let before = findings(&loaded, &outputs);
    let nets = extracted.nets.net_count();
    let reach = super::incremental::reach(&loaded.deck, &loaded.strings);
    let all = candidates(&loaded, &extracted);
    let mut kept = vec![true; all.len()];
    loop {
        let boxes: Vec<_> = (all.iter().zip(&kept))
            .filter(|(_, &k)| k)
            .flat_map(|(c, _)| c.boxes.iter().copied())
            .collect();
        let edited = with_boxes(&bytes, &boxes).map_err(super::pipeline::LoadError::from)?;
        let (loaded, extracted, outputs) = checked(inputs, &edited, decks)?;
        let after = findings(&loaded, &outputs);
        let mut new: Vec<(i64, i64)> = Vec::new();
        for (key, &(n, past, at)) in &after {
            let (was, was_past) = before.get(key).map_or((0, 0.0), |&(n, past, _)| (n, past));
            if n > was || past > was_past {
                new.push((at.x.raw(), at.y.raw()));
            }
        }
        // Nothing joins two nets by construction; were it to, every strap goes.
        if extracted.nets.net_count() != nets {
            let straps = (kept.iter().zip(&all)).any(|(&k, c)| k && !c.cut);
            for (k, c) in kept.iter_mut().zip(&all) {
                *k &= c.cut && straps;
            }
            continue;
        }
        if new.is_empty() {
            let count = |cut: bool| {
                (all.iter().zip(&kept))
                    .filter(|(c, &k)| k && c.cut == cut)
                    .count()
            };
            return Ok((
                edited,
                Enhanced {
                    cuts: count(true),
                    sides: count(false),
                },
            ));
        }
        let mut dropped = false;
        for (k, c) in kept.iter_mut().zip(&all) {
            let near = new.iter().any(|&(x, y)| {
                c.boxes.iter().any(|&(_, b)| {
                    let gap_x = (b.xlo.raw() - x).max(x - b.xhi.raw()).max(0);
                    let gap_y = (b.ylo.raw() - y).max(y - b.yhi.raw()).max(0);
                    gap_x.max(gap_y) <= reach
                })
            });
            if *k && near {
                *k = false;
                dropped = true;
            }
        }
        if !dropped {
            kept.fill(false);
        }
    }
}
