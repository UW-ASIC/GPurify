//! Metamorphic relations on the corpus: every real corpus cell, turned,
//! mirrored or moved, must report what the cell reports where it was drawn.
//!
//! This is the one place a fixture's expectation comes from a run: the
//! relation is the oracle, so the untransformed run states what every
//! transformed run must say. A rule that measures the same thing in a rotated
//! layout must find the same violations with the same measurements, LVS must
//! reach the same verdict, and a net's resistance and capacitance must not
//! change. The exceptions are stated where they are made: density windows
//! are tiled from the die's lower-left corner, so a rotation or mirror
//! legitimately moves them, and translations are multiples of every grid pitch,
//! so `off_grid` keeps its verdict.
//!
//! Each fixture proves the catalog rows of the rule kind its case exercises:
//! invariance is part of a rule's definition.

use crate::harness::{self, Depth, Expect, Finding, Fixture, Layout, Quantity, Symmetry, Want};
use gpurify::check::report::Outcome;
use gpurify::engine::run::Checks;
use gpurify_ingest::deck::parse_deck;
use gpurify_ingest::layout::{gds, UnknownLayers};
use gpurify_ingest::StrTable;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A translation every grid pitch in the corpus deck divides.
const OFFSET: (i64, i64) = (-370_000, 520_000);

/// The kinds whose result depends on where the die's corner falls.
const ORIENTED: [&str; 3] = ["density", "global_density", "density_cmp"];

fn root() -> PathBuf {
    crate::gen_fixtures::fixtures()
}

/// Rule kind to the catalog rows that name it.
fn catalog_rows() -> BTreeMap<String, Vec<&'static str>> {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/check-catalog.tsv"),
    )
    .expect("the catalog is readable");
    let mut rows: BTreeMap<String, Vec<&'static str>> = BTreeMap::new();
    for line in text.lines().skip(1) {
        let cells: Vec<&str> = line.split('\t').collect();
        let id: &'static str = Box::leak(cells[0].to_owned().into_boxed_str());
        for kind in cells[5].split(',').map(str::trim) {
            rows.entry(kind.to_owned()).or_default().push(id);
        }
    }
    rows
}

/// A corpus cell as a harness layout: base-layer polygons as drawn (holes
/// included, in their own orientation) and every placed label.
fn layout_of(gds_path: &Path, deck_text: &str) -> Layout {
    let mut strings = StrTable::default();
    let grid = gpurify::geom::Grid::new(1000).expect("1 nm");
    let deck = parse_deck(deck_text, grid, &mut strings).expect("the corpus deck parses");
    let bytes = std::fs::read(gds_path).expect("the corpus cell is readable");
    let library = gds::Library::parse(&bytes, &mut strings).expect("the corpus cell parses");
    let (store, provenance) = library
        .flatten(&deck, &strings, UnknownLayers::Reject)
        .expect("the corpus cell flattens");
    let mut layout = Layout::default();
    for row in 0..store.poly_count() {
        let poly = gpurify::geom::PolyId(u32::try_from(row).expect("a corpus cell is small"));
        let layer = store.poly_layer(poly);
        if deck.layers.is_derived(layer) {
            continue;
        }
        let (xs, ys) = store.poly_verts(poly);
        let points = xs.iter().zip(ys).map(|(x, y)| (x.raw(), y.raw())).collect();
        let name = strings.resolve(deck.layers.name(layer)).to_owned();
        layout.shapes.push((name, points));
    }
    for label in provenance.placed() {
        let layer = strings.resolve(deck.layers.name(label.layer)).to_owned();
        let text = strings.resolve(label.name).to_owned();
        layout
            .labels
            .push((layer, label.at.x.raw(), label.at.y.raw(), text));
    }
    layout
}

/// The run's own report, as the claims every transformed run must repeat.
fn claims_of(ran: &harness::Ran, nets: &[String]) -> Vec<(Expect, String)> {
    let kind_of: BTreeMap<String, String> = ran
        .loaded
        .deck
        .rules()
        .map(|(id, kind)| (ran.loaded.strings.resolve(id).to_owned(), kind.to_owned()))
        .collect();
    let mut claims = Vec::new();
    for (rule, outcome, _) in &ran.rows {
        let findings = ran
            .findings
            .iter()
            .filter(|(id, ..)| id == rule)
            .map(|(_, measured, _)| Finding {
                measured: Some(*measured),
                at: None,
            })
            .collect();
        let outcome = match outcome {
            Outcome::Ran => Want::Ran,
            Outcome::Skipped(_) => Want::Skipped,
            Outcome::Refused => Want::Refused,
        };
        let kind = kind_of.get(rule).cloned().unwrap_or_else(|| rule.clone());
        claims.push((
            Expect::Rule {
                id: rule.clone(),
                outcome,
                findings,
                // Not carried over: the corpus case states its own floor,
                // and a count a run reported is not a definition.
                examined: None,
            },
            kind,
        ));
    }
    if let Some(verdict) = &ran.lvs {
        let matched = matches!(verdict, gpurify::check::lvs::Verdict::Match);
        claims.push((Expect::Lvs(matched), "lvs".to_owned()));
    }
    for net in nets {
        for quantity in [Quantity::Resistance, Quantity::GroundCap] {
            if let Some(value) = harness::parasitic_total(ran, net, quantity) {
                claims.push((
                    Expect::Parasitic {
                        net: net.clone(),
                        quantity,
                        value,
                        rel: 1e-9,
                    },
                    "pex".to_owned(),
                ));
            }
        }
    }
    claims
}

/// Every corpus case, each under the seven other symmetries at [`OFFSET`];
/// nightly also at the origin.
pub fn fixtures(depth: Depth) -> Vec<Fixture> {
    let root = root();
    let deck = std::fs::read_to_string(root.join("params.deck")).expect("the corpus deck");
    let expectations: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("expectations.json")).expect("expectations"),
    )
    .expect("JSON");
    let rows = catalog_rows();
    let mut out = Vec::new();
    for (domain, checks) in [
        (
            "drc",
            Checks {
                drc: true,
                ..harness::NONE
            },
        ),
        (
            "erc",
            Checks {
                erc: true,
                ..harness::NONE
            },
        ),
        (
            "lvs",
            Checks {
                lvs: true,
                ..harness::NONE
            },
        ),
        (
            "pex",
            Checks {
                pex: true,
                ..harness::NONE
            },
        ),
    ] {
        for case in expectations[domain]["cases"].as_array().expect("cases") {
            let id = case["id"].as_str().expect("id");
            let mut base =
                Fixture::new(&format!("corpus/{domain}/{id}"), &[], &deck, checks).layout(
                    layout_of(&root.join(domain).join(format!("{id}.gds")), &deck),
                );
            if domain == "lvs" {
                let path = root.join("lvs_refs").join(format!("{id}.spice"));
                base.reference = Some(std::fs::read_to_string(path).expect("the case reference"));
            }
            let Ok(ran) = harness::run(&base) else {
                // A cell the pipeline refuses is refused wherever it is drawn.
                base.expect.push(Expect::Passes(false));
                base.catalog = vec!["DRC-120"];
                out.extend(transforms(&base, depth));
                continue;
            };
            let nets: Vec<String> = base.layout.labels.iter().map(|l| l.3.clone()).collect();
            let claims = claims_of(&ran, &nets);
            let mut catalog: Vec<&'static str> = claims
                .iter()
                .filter_map(|(_, kind)| rows.get(kind))
                .flatten()
                .copied()
                .collect();
            catalog.sort_unstable();
            catalog.dedup();
            if catalog.is_empty() {
                catalog.push(match domain {
                    "lvs" => "LVS-019",
                    "pex" => "PEX-001",
                    _ => "DRC-120",
                });
            }
            base.catalog = catalog;
            for symmetry in Symmetry::ALL.iter().skip(1) {
                let mut moved = base.transformed(*symmetry, OFFSET.0, OFFSET.1);
                moved.expect = claims
                    .iter()
                    .filter(|(_, kind)| !ORIENTED.contains(&kind.as_str()))
                    .map(|(expect, _)| expect.clone())
                    .collect();
                out.push(moved);
            }
            if depth == Depth::Nightly {
                let mut moved = base.transformed(Symmetry::IDENTITY, OFFSET.0, OFFSET.1);
                moved.expect = claims.iter().map(|(expect, _)| expect.clone()).collect();
                out.push(moved);
            }
        }
    }
    out
}

fn transforms(base: &Fixture, _depth: Depth) -> Vec<Fixture> {
    Symmetry::ALL
        .iter()
        .skip(1)
        .map(|&symmetry| base.transformed(symmetry, OFFSET.0, OFFSET.1))
        .collect()
}
