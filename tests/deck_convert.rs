//! Every JSON deck and its converted `.deck` lower to the same deck, and the
//! committed `.deck` is exactly what `deck convert` writes.

use gpurify::geom::{Grid, StrId};
use gpurify::ingest::deck::{parse_deck, parse_deck_dsl, to_deck_text, Deck};
use gpurify::ingest::StrTable;
use std::fmt::Write as _;
use std::path::Path;

/// Debug text with every `StrId(n)` replaced by its string, so two loads that
/// intern in a different order still compare.
fn resolved(text: &str, strings: &StrTable) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("StrId(") {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 6..];
        let close = tail.find(')').expect("StrId(n)");
        let n: u32 = tail[..close].parse().expect("a StrId number");
        let _ = write!(out, "{:?}", strings.resolve(StrId(n)));
        rest = &tail[close + 1..];
    }
    out.push_str(rest);
    out
}

/// Everything a deck means, with strings resolved.
fn meaning(deck: &Deck, strings: &StrTable) -> Vec<String> {
    let drc = gpurify::check::drc::RuleSet::from_deck(deck, strings).expect("drc builds");
    let erc = gpurify::check::erc::RuleSet::from_deck(deck, strings).expect("erc builds");
    let rules: Vec<String> = deck
        .rules
        .spec
        .iter()
        .map(|spec| {
            format!(
                "{} {} {:?}",
                strings.resolve(spec.id),
                strings.resolve(spec.kind),
                deck.rules.layers_of(spec)
            )
        })
        .collect();
    [
        format!("{:?}", deck.layers),
        format!("{:?}", deck.connectivity),
        format!("{:?}", deck.devices),
        format!("{:?}", deck.stack),
        format!("{rules:?}"),
        format!("{:?}", drc.rules),
        format!("{erc:?}"),
    ]
    .iter()
    .map(|text| resolved(text, strings))
    .collect()
}

#[test]
fn every_converted_deck_lowers_to_the_deck_its_json_did() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut jsons: Vec<_> = std::fs::read_dir(root.join("pdks"))
        .expect("pdks/")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    jsons.push(root.join("tests/fixtures/params.json"));
    assert!(jsons.len() >= 5, "found {jsons:?}");
    let grid = Grid::new(1000).expect("1 nm");

    for json in jsons {
        let source = std::fs::read_to_string(&json).expect("readable");
        let text = to_deck_text(&source).expect("converts");
        let committed =
            std::fs::read_to_string(json.with_extension("deck")).expect("a .deck beside it");
        assert_eq!(
            text,
            committed,
            "{}: the committed .deck is stale",
            json.display()
        );

        let mut json_strings = StrTable::default();
        let from_json = parse_deck(&source, grid, &mut json_strings).expect("json parses");
        let mut text_strings = StrTable::default();
        let from_text = parse_deck_dsl(&text, grid, &mut text_strings)
            .unwrap_or_else(|why| panic!("{}: {why}", json.display()));
        let (want, got) = (
            meaning(&from_json, &json_strings),
            meaning(&from_text, &text_strings),
        );
        for (want, got) in want.iter().zip(&got) {
            assert_eq!(want, got, "{}", json.display());
        }
    }
}
