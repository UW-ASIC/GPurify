//! The JSON deck reader, kept until every deck is converted to deck text.

use super::{build, Deck, DeckError, DeckSrc, Pairs};
use gpurify_geom::{Grid, StrTable};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// Parse and validate a JSON deck.
pub fn parse_deck(source: &str, grid: Grid, strings: &mut StrTable) -> Result<Deck, DeckError> {
    let doc: DeckSrc =
        serde_json::from_str(source).map_err(|why| DeckError::Malformed(why.to_string()))?;
    build(&doc, grid, strings)
}

/// `serde_json::Map` collapses a repeated key and would drop a duplicate rule.
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Pairs<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PairVisitor<T>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for PairVisitor<T> {
            type Value = Pairs<T>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Pairs<T>, M::Error> {
                let mut pairs = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some(entry) = map.next_entry::<String, T>()? {
                    pairs.push(entry);
                }
                Ok(Pairs(pairs))
            }
        }

        deserializer.deserialize_map(PairVisitor(std::marker::PhantomData))
    }
}
