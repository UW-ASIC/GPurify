//! A deck compiled for the engine: its layers, connectivity, device
//! recognisers and parasitic stack, and every rule already typed.
//!
//! Data in: deck text and the layout's grid ([`compile`]), or a parsed
//! [`Deck`] ([`CompiledDeck::from_deck`]). Data out: a [`CompiledDeck`], which
//! the engine runs as it is, and which a consumer queries for the limits the
//! checker enforces ([`CompiledDeck::required_spacing`] and the methods
//! beside it). The parser's rule table is an intermediate: once
//! the rules are typed nothing reads it, so a deck that compiled names no rule
//! kind the engine does not run and holds no limit the engine would refuse.
//!
//! # Examples
//!
//! ```
//! use gpurify_check::deck::compile;
//! use gpurify_geom::{Grid, StrTable};
//!
//! let text = "grid 5nm
//! layer met1 = gds(68, 20)
//! rule m1.1 width(met1) >= 140nm
//! rule m1.2 space(met1) >= 140nm
//! ";
//! let mut strings = StrTable::default();
//! let deck = compile(text, Grid::new(1000)?, &mut strings)?;
//! assert_eq!(deck.drc.rule_count(), 2);
//! assert!(deck.erc.is_empty());
//!
//! // A limit the parser reads but no rule can hold is refused here, not at run time.
//! let zero = text.replace("140nm\nrule m1.2", "0nm\nrule m1.2");
//! assert!(compile(&zero, Grid::new(1000)?, &mut StrTable::default()).is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod builder;
mod decompile;
mod query;
pub mod rules;

pub use builder::{Bound, BuildDiagnostic, BuildError, DeckBuilder, LayerExpr, LayerRef};
pub use query::{AntennaLimit, DensityLimit, EmLimit, Enclosure, FetLimits};
pub use rules::RuleRow;

use crate::{drc, erc};
use gpurify_geom::{prefix, Grid, Qty, StrId, StrTable, Temperature};
use gpurify_ingest::deck::{
    parse_deck, Connectivity, Deck, DeckError, DeviceRecognition, LayerTable, PrintError,
    ProcessStack, TemperatureLaw,
};

/// A deck ready to run: what [`compile`] makes of deck text.
///
/// Every [`StrId`] in it is from the [`StrTable`] it was
/// compiled into, and every length is in database units of [`Self::grid`], so
/// it is only meaningful with a layout on that grid and with that table.
///
/// Two compiled decks are equal when every table and every typed rule is,
/// in the same order, with the same provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledDeck {
    /// The layout grid every length was converted onto.
    pub grid: Grid,
    /// Drawn and derived layers, and the stream pairs the deck ignores.
    pub layers: LayerTable,
    /// What carries a net, and how layers join.
    pub connectivity: Connectivity,
    /// The `device` statements.
    pub devices: DeviceRecognition,
    /// The parasitic stack, per layer, its sheet resistances at
    /// [`Self::temperature`].
    pub stack: ProcessStack,
    /// The `temperature` statement's operating temperature, absolute; `None`
    /// when the deck states none.
    pub temperature: Option<Qty<Temperature, { prefix::BASE }>>,
    /// The `temperature` statement and the `pex` coefficients as written
    /// ([`TemperatureLaw`]), so the deck prints exactly.
    pub temperature_law: Option<TemperatureLaw>,
    /// Every DRC rule, typed, in deck order.
    pub drc: drc::RuleSet,
    /// Every ERC rule, typed, one table per kind.
    pub erc: erc::RuleSet,
    /// Every rule's id in deck order, with where it came from: what a report
    /// says a consumer changed in a shipped deck.
    pub provenance: Vec<(StrId, Origin)>,
}

/// Where a rule of a [`CompiledDeck`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// As the deck it was compiled or built from states it: a text deck's
    /// rules, or the rules a [`DeckBuilder`] states with
    /// [`rule`](DeckBuilder::rule).
    Base,
    /// Added over a base deck ([`DeckBuilder::add`]).
    Added,
    /// A base deck's rule, replaced ([`DeckBuilder::replace`]).
    Replaced,
}

/// Writes a compiled deck as deck text, which [`compile`] reads back, in the
/// same `strings` it was compiled into, to an equal deck: the way to share a
/// deck built or overridden in Rust with a tool that reads text.
///
/// # Errors
///
/// [`PrintError`] when a value cannot be stated exactly in the deck language
/// (a grid that is no terminating decimal of a nanometre).
///
/// # Examples
///
/// ```
/// use gpurify_check::deck::{compile, print};
/// use gpurify_geom::{Grid, StrTable};
///
/// let text = "grid 5nm\nlayer met1 = gds(68, 20)\nrule m1.1 width(met1) >= 0.14um\n";
/// let mut strings = StrTable::default();
/// let deck = compile(text, Grid::new(1000)?, &mut strings)?;
/// let printed = print(&deck, &strings)?;
/// assert_eq!(compile(&printed, Grid::new(1000)?, &mut strings)?, deck);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn print(deck: &CompiledDeck, strings: &StrTable) -> Result<String, PrintError> {
    gpurify_ingest::deck::print(&deck.source(strings), deck.grid)
}

/// Why a deck did not compile.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CompileError {
    /// The text did not parse, or its statements contradict each other.
    #[error(transparent)]
    Deck(#[from] DeckError),
    /// A rule names a kind neither domain runs, or a DRC rule's values are
    /// not ones its kind can hold.
    #[error(transparent)]
    Drc(#[from] drc::DrcError),
    /// An ERC rule's values are not ones its kind can hold.
    #[error(transparent)]
    Erc(#[from] erc::ErcError),
}

impl CompileError {
    /// Names the file a parse error's diagnostics point into; other errors
    /// pass through unchanged.
    #[must_use]
    pub fn in_file(self, path: &str) -> Self {
        match self {
            Self::Deck(why) => Self::Deck(why.in_file(path)),
            other => other,
        }
    }
}

/// Parses `source` on the layout grid `grid`, interning every name into
/// `strings`, and types every rule.
///
/// # Errors
///
/// [`CompileError::Deck`] from [`parse_deck`], then whatever
/// [`CompiledDeck::from_deck`] refuses.
pub fn compile(
    source: &str,
    grid: Grid,
    strings: &mut StrTable,
) -> Result<CompiledDeck, CompileError> {
    let deck = parse_deck(source, grid, strings)?;
    CompiledDeck::from_deck(deck, grid, strings)
}

impl CompiledDeck {
    /// Types every rule of a parsed deck. `grid` is the one `deck` was parsed
    /// on, and `strings` the table it was interned into.
    ///
    /// # Errors
    ///
    /// The first problem, in this order:
    /// - [`drc::DrcError::UnknownKind`] for a rule whose kind is in neither
    ///   [`drc::ruleset::KINDS`] nor [`erc::KINDS`]: a rule nobody runs makes a
    ///   report that looks complete;
    /// - what [`drc::RuleSet::from_deck`] refuses;
    /// - what [`erc::RuleSet::from_deck`] refuses.
    pub fn from_deck(deck: Deck, grid: Grid, strings: &StrTable) -> Result<Self, CompileError> {
        for spec in &deck.rules.spec {
            let kind = strings.resolve(spec.kind);
            if !drc::ruleset::KINDS.contains(&kind) && !erc::KINDS.contains(&kind) {
                return Err(drc::DrcError::UnknownKind {
                    rule: strings.resolve(spec.id).to_owned(),
                    kind: kind.to_owned(),
                }
                .into());
            }
        }
        let drc = drc::RuleSet::from_deck(&deck, strings)?;
        let erc = erc::RuleSet::from_deck(&deck, strings)?;
        let provenance = deck
            .rules
            .spec
            .iter()
            .map(|spec| (spec.id, Origin::Base))
            .collect();
        let Deck {
            layers,
            rules: _,
            connectivity,
            devices,
            stack,
            temperature,
            temperature_law,
        } = deck;
        Ok(Self {
            grid,
            layers,
            connectivity,
            devices,
            stack,
            temperature,
            temperature_law,
            drc,
            erc,
            provenance,
        })
    }

    /// The number of rules, both domains: the `RuleRun` rows a run of DRC and
    /// ERC records.
    pub fn rule_count(&self) -> usize {
        self.drc.rule_count() + self.erc.len()
    }

    /// Every rule's id with its kind name: the DRC rules in deck order, then
    /// the ERC rows table by table.
    pub fn rules(&self) -> impl Iterator<Item = (StrId, &'static str)> + '_ {
        self.drc
            .rules
            .iter()
            .map(|&(id, rule)| (id, rule.kind()))
            .chain(self.erc.rules())
    }
}

/// The layer table, for a reader that needs only the layers
/// ([`flatten`](gpurify_ingest::layout::gds::Library::flatten)).
impl AsRef<LayerTable> for CompiledDeck {
    fn as_ref(&self) -> &LayerTable {
        &self.layers
    }
}
