//! A deck built in Rust: [`DeckBuilder`], its layer handles and expressions.
//!
//! The builder holds the deck as names, the form the parser reads text into
//! ([`DeckSource`]), and [`DeckBuilder::finish`] lowers and compiles it as
//! [`compile`](super::compile) does text: the same lowering, the same typed
//! rules, the same validation. What only the builder can get wrong (an id
//! used twice, a layer that does not exist, a range nothing satisfies) is
//! reported with the caller's location; everything is reported at `finish`.
//!
//! A builder started from a compiled deck ([`DeckBuilder::from_deck`])
//! overrides it: [`add`](DeckBuilder::add), [`replace`](DeckBuilder::replace)
//! and [`remove`](DeckBuilder::remove) rules, and the same for layers,
//! devices and parasitic rows. The result does not depend on the order of the
//! overrides: a replaced rule keeps its place and its id, added rules follow
//! the base deck's sorted by id, and removing an id then adding it again is
//! replacing it.

use super::custom::{CustomCheck, CustomRule};
use super::rules::{RowValue, RuleRow};
use super::{CompileError, CompiledDeck, Origin};
use crate::report::Severity;
use gpurify_geom::{Dbu, DbuArea, Grid, Length, Qty, StrTable};
use gpurify_ingest::deck::{
    lower, ConnectivitySource, DeckError, DeckSource, DerivedOp, DerivedSource, DeviceKind,
    DeviceSource, DeviceValue, LabelSource, LvsSrc, ParamSource, ParamValue, RuleSource,
    StackSource, ViaSource,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::panic::Location;

/// A layer of a deck being built, from [`DeckBuilder::layer`],
/// [`DeckBuilder::derived`] or [`DeckBuilder::get`]. Only the builder that
/// made it can read it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LayerRef(u32);

/// A layer expression: a layer, or operations on layers, as a derived layer
/// or a rule argument writes it ([deck.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md#layers)).
///
/// `a.and(b).and(c)` is one fold of three operands, as `a and b and c` is;
/// [`group`](Self::group) closes a fold, as parentheses do. A layer argument
/// that is not a plain layer becomes a layer of its own, named and numbered
/// as the parser names one, so a deck built in Rust and its text twin assign
/// the same ids.
#[derive(Debug, Clone, PartialEq)]
pub struct LayerExpr {
    node: Node,
    /// What the expression's construction refused, with where.
    faults: Vec<BuildDiagnostic>,
}

#[derive(Debug, Clone, PartialEq)]
enum Node {
    Layer(LayerRef),
    Op {
        op: DerivedOp,
        operands: Vec<Node>,
        /// An unparenthesised fold, which a further operation of the same
        /// kind extends.
        chain: bool,
        /// A `with_text` pattern.
        pattern: Option<String>,
    },
}

/// One side of a range, as [`LayerExpr::with_area`],
/// [`LayerExpr::with_width`] and [`LayerExpr::with_length`] take it: the
/// deck's `>=`, `>`, `<=`, `<` and `==`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound<T> {
    /// `>= value`.
    AtLeast(T),
    /// `> value`.
    Above(T),
    /// `<= value`.
    AtMost(T),
    /// `< value`.
    Below(T),
    /// `== value`.
    Exactly(T),
}

/// Something the builder refused, and the call that did it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildDiagnostic {
    /// The caller's location.
    pub at: &'static Location<'static>,
    /// What was wrong, worded as the parser words it for deck text.
    pub message: String,
}

/// Why [`DeckBuilder::finish`] made no deck.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BuildError {
    /// What the builder refused, each where it was called, at most 50.
    #[error("{}", render(.0))]
    Invalid(Vec<BuildDiagnostic>),
    /// What lowering or compiling the deck refused: a contradiction between
    /// statements, or a rule its kind cannot hold.
    #[error(transparent)]
    Compile(#[from] CompileError),
}

fn render(diagnostics: &[BuildDiagnostic]) -> String {
    diagnostics
        .iter()
        .map(|d| {
            format!(
                "{}:{}:{}: {}",
                d.at.file(),
                d.at.line(),
                d.at.column(),
                d.message
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The most diagnostics a builder keeps, as the parser keeps.
const MAX_ERRORS: usize = 50;

impl From<LayerRef> for LayerExpr {
    fn from(layer: LayerRef) -> Self {
        Self {
            node: Node::Layer(layer),
            faults: Vec::new(),
        }
    }
}

impl LayerExpr {
    /// The layer, when the expression is a plain one.
    fn as_layer(&self) -> Option<LayerRef> {
        match self.node {
            Node::Layer(layer) => Some(layer),
            Node::Op { .. } => None,
        }
    }

    /// A fold: extends `self` when it is an open fold of `op`.
    fn fold(mut self, op: DerivedOp, other: impl Into<LayerExpr>) -> Self {
        let other = other.into();
        self.faults.extend(other.faults);
        let node = match self.node {
            Node::Op {
                op: prev,
                mut operands,
                chain: true,
                pattern: None,
            } if prev == op => {
                operands.push(other.node);
                Node::Op {
                    op,
                    operands,
                    chain: true,
                    pattern: None,
                }
            }
            node => Node::Op {
                op,
                operands: vec![node, other.node],
                chain: true,
                pattern: None,
            },
        };
        Self {
            node,
            faults: self.faults,
        }
    }

    /// An operation on `self`, with an optional layer argument.
    fn call(mut self, op: DerivedOp, argument: Option<LayerExpr>, pattern: Option<String>) -> Self {
        let mut operands = vec![self.node];
        if let Some(argument) = argument {
            self.faults.extend(argument.faults);
            operands.push(argument.node);
        }
        Self {
            node: Node::Op {
                op,
                operands,
                chain: false,
                pattern,
            },
            faults: self.faults,
        }
    }

    /// `self and other`: the area both cover; on edge layers, the parts that
    /// coincide.
    #[must_use]
    pub fn and(self, other: impl Into<LayerExpr>) -> Self {
        self.fold(DerivedOp::And, other)
    }

    /// `self or other`: the area either covers.
    #[must_use]
    pub fn or(self, other: impl Into<LayerExpr>) -> Self {
        self.fold(DerivedOp::Or, other)
    }

    /// `self not other`: `self`'s area less `other`'s.
    #[must_use]
    pub fn not(self, other: impl Into<LayerExpr>) -> Self {
        self.fold(DerivedOp::Not, other)
    }

    /// `(self)`: closes a fold, so a further `and`, `or` or `not` takes it
    /// as one operand.
    #[must_use]
    pub fn group(mut self) -> Self {
        if let Node::Op { chain, .. } = &mut self.node {
            *chain = false;
        }
        self
    }

    /// `.sized(by)`: every shape grown by `by` on all sides, shrunk when
    /// negative.
    #[must_use]
    pub fn sized(self, by: Dbu) -> Self {
        self.call(DerivedOp::Sized(by, by), None, None)
    }

    /// `.interacting(other)`.
    #[must_use]
    pub fn interacting(self, other: impl Into<LayerExpr>) -> Self {
        self.call(DerivedOp::Interacting(true), Some(other.into()), None)
    }

    /// `.not_interacting(other)`.
    #[must_use]
    pub fn not_interacting(self, other: impl Into<LayerExpr>) -> Self {
        self.call(DerivedOp::Interacting(false), Some(other.into()), None)
    }

    /// `.inside(other)`.
    #[must_use]
    pub fn inside(self, other: impl Into<LayerExpr>) -> Self {
        self.call(DerivedOp::Inside, Some(other.into()), None)
    }

    /// `.outside(other)`.
    #[must_use]
    pub fn outside(self, other: impl Into<LayerExpr>) -> Self {
        self.call(DerivedOp::Outside, Some(other.into()), None)
    }

    /// `.inside_part(other)`, on edges.
    #[must_use]
    pub fn inside_part(self, other: impl Into<LayerExpr>) -> Self {
        self.call(DerivedOp::Part(true), Some(other.into()), None)
    }

    /// `.outside_part(other)`, on edges.
    #[must_use]
    pub fn outside_part(self, other: impl Into<LayerExpr>) -> Self {
        self.call(DerivedOp::Part(false), Some(other.into()), None)
    }

    /// `.holes()`.
    #[must_use]
    pub fn holes(self) -> Self {
        self.call(DerivedOp::Holes, None, None)
    }

    /// `.extents()`.
    #[must_use]
    pub fn extents(self) -> Self {
        self.call(DerivedOp::Extents, None, None)
    }

    /// `.edges()`.
    #[must_use]
    pub fn edges(self) -> Self {
        self.call(DerivedOp::Edges, None, None)
    }

    /// `.rectangles()`: the shapes that are one axis-aligned box.
    #[must_use]
    pub fn rectangles(self) -> Self {
        self.rects(false, true)
    }

    /// `.non_rectangles()`.
    #[must_use]
    pub fn non_rectangles(self) -> Self {
        self.rects(false, false)
    }

    /// `.squares()`: the shapes that are one square.
    #[must_use]
    pub fn squares(self) -> Self {
        self.rects(true, true)
    }

    /// `.non_squares()`.
    #[must_use]
    pub fn non_squares(self) -> Self {
        self.rects(true, false)
    }

    fn rects(self, square: bool, keep: bool) -> Self {
        self.call(DerivedOp::Rectangles { square, keep }, None, None)
    }

    /// `.horizontal()`, on edges.
    #[must_use]
    pub fn horizontal(self) -> Self {
        self.call(DerivedOp::Oriented(false), None, None)
    }

    /// `.vertical()`, on edges.
    #[must_use]
    pub fn vertical(self) -> Self {
        self.call(DerivedOp::Oriented(true), None, None)
    }

    /// `.with_bbox_max(bounds)`: a bound on the bounding box's longer side.
    #[must_use]
    #[track_caller]
    pub fn with_bbox_max(self, bounds: &[Bound<Dbu>]) -> Self {
        self.bbox(true, bounds, Location::caller())
    }

    /// `.with_bbox_min(bounds)`: a bound on the bounding box's shorter side.
    #[must_use]
    #[track_caller]
    pub fn with_bbox_min(self, bounds: &[Bound<Dbu>]) -> Self {
        self.bbox(false, bounds, Location::caller())
    }

    fn bbox(self, longer: bool, bounds: &[Bound<Dbu>], at: &'static Location<'static>) -> Self {
        let op = if longer {
            "with_bbox_max"
        } else {
            "with_bbox_min"
        };
        let ((lo, hi), fault) = range(op, bounds, |side: Dbu| i128::from(side.raw()), at);
        self.ranged(DerivedOp::WithBbox { longer, lo, hi }, fault)
    }

    /// `.with_text(texts, "pattern")`: the shapes holding a matching text
    /// drawn on `texts`.
    #[must_use]
    pub fn with_text(self, texts: LayerRef, pattern: &str) -> Self {
        let op = DerivedOp::WithText {
            keep: true,
            text: 0,
        };
        self.call(op, Some(texts.into()), Some(pattern.to_owned()))
    }

    /// `.without_text(texts, "pattern")`.
    #[must_use]
    pub fn without_text(self, texts: LayerRef, pattern: &str) -> Self {
        let op = DerivedOp::WithText {
            keep: false,
            text: 0,
        };
        self.call(op, Some(texts.into()), Some(pattern.to_owned()))
    }

    /// `.with_area(bounds)`.
    #[must_use]
    #[track_caller]
    pub fn with_area(self, bounds: &[Bound<DbuArea>]) -> Self {
        let at = Location::caller();
        let (range, fault) = range("with_area", bounds, DbuArea::raw, at);
        self.ranged(DerivedOp::WithArea(range.0, range.1), fault)
    }

    /// `.with_width(bounds)`: a bound on the narrowest width, exact for a
    /// strict bound on an irrational neck as the deck's is.
    #[must_use]
    #[track_caller]
    pub fn with_width(self, bounds: &[Bound<Dbu>]) -> Self {
        let at = Location::caller();
        let squared = |width: Dbu| {
            let n = i128::from(width.raw());
            n * n.abs()
        };
        let (range, fault) = range("with_width", bounds, squared, at);
        self.ranged(DerivedOp::WithWidth(range.0, range.1), fault)
    }

    /// `.with_length(bounds)`, on edges.
    #[must_use]
    #[track_caller]
    pub fn with_length(self, bounds: &[Bound<Dbu>]) -> Self {
        let at = Location::caller();
        let (range, fault) = range(
            "with_length",
            bounds,
            |length: Dbu| i128::from(length.raw()),
            at,
        );
        self.ranged(DerivedOp::WithLength(range.0, range.1), fault)
    }

    fn ranged(self, op: DerivedOp, fault: Option<BuildDiagnostic>) -> Self {
        let mut expr = self.call(op, None, None);
        expr.faults.extend(fault);
        expr
    }
}

/// Inclusive bounds as the parser stores them, `i128::MIN` and `i128::MAX`
/// for an open side, and the fault in them if any.
fn range<T: Copy>(
    op: &str,
    bounds: &[Bound<T>],
    value: impl Fn(T) -> i128,
    at: &'static Location<'static>,
) -> ((i128, i128), Option<BuildDiagnostic>) {
    let fault = |message: String| Some(BuildDiagnostic { at, message });
    let (mut lo, mut hi) = (None, None);
    for &bound in bounds {
        let (low, high) = match bound {
            Bound::AtLeast(v) => (Some(value(v)), None),
            Bound::Above(v) => (Some(value(v) + 1), None),
            Bound::AtMost(v) => (None, Some(value(v))),
            Bound::Below(v) => (None, Some(value(v) - 1)),
            Bound::Exactly(v) => (Some(value(v)), Some(value(v))),
        };
        if (low.is_some() && lo.is_some()) || (high.is_some() && hi.is_some()) {
            return (
                (i128::MIN, i128::MAX),
                fault(format!("`.{op}` takes one bound on each side")),
            );
        }
        lo = lo.or(low);
        hi = hi.or(high);
    }
    let (lo, hi) = (lo.unwrap_or(i128::MIN), hi.unwrap_or(i128::MAX));
    if bounds.is_empty() {
        return (
            (lo, hi),
            fault(format!("`.{op}` needs a bound such as `>= 1um`")),
        );
    }
    if lo > hi {
        return ((lo, hi), fault("the range is empty".to_owned()));
    }
    ((lo, hi), None)
}

/// The operations of [`LayerExpr`], on a plain layer.
macro_rules! forward {
    ($($(#[$meta:meta])* $name:ident($($arg:ident: $ty:ty),*);)*) => {
        impl LayerRef {
            $(
                $(#[$meta])*
                #[must_use]
                #[track_caller]
                pub fn $name(self, $($arg: $ty),*) -> LayerExpr {
                    LayerExpr::from(self).$name($($arg),*)
                }
            )*
        }
    };
}

forward! {
    /// [`LayerExpr::and`].
    and(other: impl Into<LayerExpr>);
    /// [`LayerExpr::or`].
    or(other: impl Into<LayerExpr>);
    /// [`LayerExpr::not`].
    not(other: impl Into<LayerExpr>);
    /// [`LayerExpr::sized`].
    sized(by: Dbu);
    /// [`LayerExpr::interacting`].
    interacting(other: impl Into<LayerExpr>);
    /// [`LayerExpr::not_interacting`].
    not_interacting(other: impl Into<LayerExpr>);
    /// [`LayerExpr::inside`].
    inside(other: impl Into<LayerExpr>);
    /// [`LayerExpr::outside`].
    outside(other: impl Into<LayerExpr>);
    /// [`LayerExpr::inside_part`].
    inside_part(other: impl Into<LayerExpr>);
    /// [`LayerExpr::outside_part`].
    outside_part(other: impl Into<LayerExpr>);
    /// [`LayerExpr::holes`].
    holes();
    /// [`LayerExpr::extents`].
    extents();
    /// [`LayerExpr::edges`].
    edges();
    /// [`LayerExpr::with_text`].
    with_text(texts: LayerRef, pattern: &str);
    /// [`LayerExpr::without_text`].
    without_text(texts: LayerRef, pattern: &str);
    /// [`LayerExpr::with_area`].
    with_area(bounds: &[Bound<DbuArea>]);
    /// [`LayerExpr::with_width`].
    with_width(bounds: &[Bound<Dbu>]);
    /// [`LayerExpr::with_length`].
    with_length(bounds: &[Bound<Dbu>]);
    /// [`LayerExpr::rectangles`].
    rectangles();
    /// [`LayerExpr::non_rectangles`].
    non_rectangles();
    /// [`LayerExpr::squares`].
    squares();
    /// [`LayerExpr::non_squares`].
    non_squares();
    /// [`LayerExpr::horizontal`].
    horizontal();
    /// [`LayerExpr::vertical`].
    vertical();
    /// [`LayerExpr::with_bbox_max`].
    with_bbox_max(bounds: &[Bound<Dbu>]);
    /// [`LayerExpr::with_bbox_min`].
    with_bbox_min(bounds: &[Bound<Dbu>]);
}

/// A custom rule before its layers are ids.
#[derive(Debug, Clone)]
struct PendingCustom {
    id: String,
    inputs: Vec<String>,
    severity: Severity,
    check: CustomCheck,
    origin: Origin,
}

/// One rule slot, in deck order.
#[derive(Debug, Clone)]
enum Slot {
    /// A base rule as it was, or a rule this builder states, lowered where it
    /// was stated so its inline layers sit where the parser would put them.
    Kept(RuleSource),
    /// A rule replaced, lowered when the deck is finished.
    Row {
        id: String,
        row: RuleRow,
        origin: Origin,
    },
    /// A base rule removed: adding its id again replaces it here.
    Removed(String),
}

impl Slot {
    fn id(&self) -> &str {
        match self {
            Slot::Kept(rule) => &rule.id,
            Slot::Row { id, .. } | Slot::Removed(id) => id,
        }
    }
}

/// A deck built in Rust, or a compiled deck overridden.
///
/// # Examples
///
/// ```
/// use gpurify_check::deck::{rules, Bound, DeckBuilder};
/// use gpurify_geom::{Dbu, DbuArea, Grid, StrTable};
///
/// let nm = Dbu::new_unchecked; // a 1 nm grid: one database unit per nanometre
/// let mut strings = StrTable::default();
/// let mut d = DeckBuilder::new(Grid::new(1000)?, &mut strings);
/// let met1 = d.layer("met1", (68, 20));
/// let via1 = d.layer("via1", (68, 44));
/// let huge = d.derived("huge_met1", met1.sized(nm(-1500)).sized(nm(1500)));
/// d.rule("m1.1", rules::min_width(met1, nm(140)));
/// d.rule("m1.6", rules::min_area(met1, DbuArea::new(83_000)));
/// d.rule("via.4a", rules::min_enclosure(via1, met1, nm(55)));
/// d.rule("m1.3b", rules::min_spacing(huge, nm(280)));
/// d.rule("tiny", rules::forbidden(met1.with_area(&[Bound::Below(DbuArea::new(100))])));
/// let deck = d.finish()?;
/// assert_eq!(deck.drc.rule_count(), 5);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct DeckBuilder<'s> {
    strings: &'s mut StrTable,
    grid: Grid,
    /// `LayerRef(i)` is `names[i]`.
    names: Vec<String>,
    drawn: Vec<(String, (u16, u16))>,
    ignored: Vec<(u16, u16)>,
    /// Derived rows in id order, each with its `with_text` pattern.
    derived: Vec<(DerivedSource, Option<String>)>,
    connectivity: ConnectivitySource,
    devices: Vec<DeviceSource>,
    pex: Vec<(String, StackSource)>,
    temperature: Option<(f64, f64)>,
    /// The base deck's `lvs` statements, kept as they are.
    lvs: LvsSrc,
    rules: Vec<Slot>,
    added: BTreeMap<String, RuleRow>,
    /// The base deck's provenance, by id.
    base_origin: HashMap<String, Origin>,
    /// Custom rules, in the order stated.
    custom: Vec<PendingCustom>,
    /// Whether this builder overrides a base deck, so what it states is added.
    based: bool,
    errors: Vec<BuildDiagnostic>,
}

/// Whether `name` can be written as a layer name: a letter or `_`, then
/// letters, digits and `_`.
fn is_layer_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether `id` can be written as a rule id: letters, digits, `_` and `.`.
fn is_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

impl<'s> DeckBuilder<'s> {
    /// An empty deck on the layout grid `grid`, its names to be interned into
    /// `strings` when it is finished.
    pub fn new(grid: Grid, strings: &'s mut StrTable) -> Self {
        Self {
            strings,
            grid,
            names: Vec::new(),
            drawn: Vec::new(),
            ignored: Vec::new(),
            derived: Vec::new(),
            connectivity: ConnectivitySource::default(),
            devices: Vec::new(),
            pex: Vec::new(),
            temperature: None,
            lvs: LvsSrc::default(),
            rules: Vec::new(),
            added: BTreeMap::new(),
            base_origin: HashMap::new(),
            custom: Vec::new(),
            based: false,
            errors: Vec::new(),
        }
    }

    /// A builder that starts as `base` and overrides it. `strings` is the
    /// table `base` was compiled into.
    pub fn from_deck(base: &CompiledDeck, strings: &'s mut StrTable) -> Self {
        let source = base.source(strings);
        let base_origin: HashMap<String, Origin> = base
            .provenance
            .iter()
            .map(|&(id, origin)| (strings.resolve(id).to_owned(), origin))
            .collect();
        let custom = base
            .custom
            .iter()
            .map(|rule| {
                let id = strings.resolve(rule.id).to_owned();
                PendingCustom {
                    origin: base_origin.get(&id).copied().unwrap_or(Origin::Base),
                    id,
                    inputs: (rule.inputs.iter())
                        .map(|&layer| strings.resolve(base.layers.name(layer)).to_owned())
                        .collect(),
                    severity: rule.severity,
                    check: rule.check,
                }
            })
            .collect();
        let mut names: Vec<String> = source.layers.iter().map(|(name, _)| name.clone()).collect();
        names.extend(source.derived.iter().map(|row| row.name.clone()));
        let derived = source
            .derived
            .into_iter()
            .map(|row| {
                let pattern = match row.op {
                    DerivedOp::WithText { text, .. } => source.texts.get(text as usize).cloned(),
                    _ => None,
                };
                (row, pattern)
            })
            .collect();
        Self {
            grid: base.grid,
            names,
            drawn: source.layers,
            ignored: source.ignored,
            derived,
            connectivity: source.connectivity,
            devices: source.devices,
            pex: source.pex,
            temperature: source.temperature,
            lvs: source.lvs,
            rules: source.rules.into_iter().map(Slot::Kept).collect(),
            added: BTreeMap::new(),
            custom,
            base_origin,
            based: true,
            errors: Vec::new(),
            strings,
        }
    }

    /// The layout grid the deck is built on.
    pub fn grid(&self) -> Grid {
        self.grid
    }

    #[track_caller]
    fn refuse(&mut self, message: String) {
        if self.errors.len() < MAX_ERRORS {
            self.errors.push(BuildDiagnostic {
                at: Location::caller(),
                message,
            });
        }
    }

    /// `nm` nanometres on the deck's grid, refused when not a whole number
    /// of grid units (`0` then).
    #[track_caller]
    pub fn length(&mut self, nm: f64) -> Dbu {
        match self
            .grid
            .to_dbu(Qty::<Length, { gpurify_geom::prefix::NANO }>::new(nm))
        {
            Ok(length) => length,
            Err(why) => {
                self.refuse(format!("{nm}nm: {why}"));
                Dbu::new_unchecked(0)
            }
        }
    }

    /// `nm2` square nanometres on the deck's grid, refused when not a whole
    /// number of square grid units (`0` then).
    #[track_caller]
    pub fn area(&mut self, nm2: f64) -> DbuArea {
        #[allow(clippy::cast_precision_loss, reason = "a resolution is a small count")]
        let per_um = self.grid.dbu_per_um() as f64;
        let units = nm2 * per_um * per_um / 1e6;
        if units.is_finite() && units.fract() == 0.0 && units.abs() < 2f64.powi(100) {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "whole and in range, checked"
            )]
            let whole = units as i128;
            return DbuArea::new(whole);
        }
        self.refuse(format!(
            "{nm2}nm2 is not a whole number of square grid units"
        ));
        DbuArea::new(0)
    }

    /// A layer's name.
    pub fn name(&self, layer: LayerRef) -> &str {
        self.names.get(layer.0 as usize).map_or("", String::as_str)
    }

    #[track_caller]
    fn declare(&mut self, name: &str) -> LayerRef {
        if !is_layer_name(name) {
            self.refuse(format!("`{name}` is not a layer name a deck can write"));
        } else if self.names.iter().any(|known| known == name) {
            self.refuse(format!("`{name}` is already bound"));
        }
        self.names.push(name.to_owned());
        LayerRef(u32::try_from(self.names.len() - 1).expect("a deck has few layers"))
    }

    /// `layer name = gds(layer, datatype)`: a drawn layer.
    #[track_caller]
    pub fn layer(&mut self, name: &str, (layer, datatype): (u16, u16)) -> LayerRef {
        let handle = self.declare(name);
        self.drawn.push((name.to_owned(), (layer, datatype)));
        handle
    }

    /// `ignore gds(layer, datatype)`.
    #[track_caller]
    pub fn ignore(&mut self, (layer, datatype): (u16, u16)) {
        if self.ignored.contains(&(layer, datatype)) {
            self.refuse(format!("gds({layer}, {datatype}) is already ignored"));
        }
        self.ignored.push((layer, datatype));
    }

    /// `layer name = expr`: a derived layer.
    #[track_caller]
    pub fn derived(&mut self, name: &str, expr: impl Into<LayerExpr>) -> LayerRef {
        let handle = self.declare(name);
        let rows = self.lower_named(name, expr.into());
        self.derived.extend(rows);
        handle
    }

    /// A declared layer, by name; refused (and a handle no layer answers)
    /// when the deck has none.
    #[track_caller]
    pub fn get(&mut self, name: &str) -> LayerRef {
        if let Some(at) = self.names.iter().position(|known| known == name) {
            return LayerRef(u32::try_from(at).expect("a deck has few layers"));
        }
        self.refuse(format!("unknown layer `{name}`"));
        LayerRef(u32::MAX)
    }

    /// Replaces a derived layer's expression in place: it keeps its name and
    /// its place among the derived layers. Refused when no derived layer has
    /// that name.
    #[track_caller]
    pub fn replace_layer(&mut self, name: &str, expr: impl Into<LayerExpr>) {
        let Some(at) = self.derived.iter().position(|(row, _)| row.name == name) else {
            self.refuse(format!(
                "replace of layer `{name}`, which is not a derived layer"
            ));
            return;
        };
        let hidden = format!("{name}#");
        let first = self.derived[..at]
            .iter()
            .position(|(row, _)| row.name.starts_with(&hidden))
            .unwrap_or(at);
        let rows = self.lower_named(name, expr.into());
        let _replaced: Vec<_> = self.derived.splice(first..=at, rows).collect();
    }

    /// Removes a layer, drawn or derived. Refused when the deck has none of
    /// that name; anything still naming it is refused when the deck is
    /// finished.
    #[track_caller]
    pub fn remove_layer(&mut self, name: &str) {
        let hidden = format!("{name}#");
        let before = self.drawn.len() + self.derived.len();
        self.drawn.retain(|(drawn, _)| drawn != name);
        self.derived
            .retain(|(row, _)| row.name != name && !row.name.starts_with(&hidden));
        if self.drawn.len() + self.derived.len() == before {
            self.refuse(format!(
                "remove of layer `{name}`, which the deck does not have"
            ));
        }
    }

    /// `connect conductors [..]`: layers that carry a net.
    #[track_caller]
    pub fn conductors(&mut self, layers: &[LayerRef]) {
        for &layer in layers {
            let name = self.resolve(layer);
            self.connectivity.conductors.push(name);
        }
    }

    /// `connect touch_within_layer`.
    pub fn touch_within_layer(&mut self) {
        self.connectivity.intra_layer_touch = true;
    }

    /// `connect global layer`.
    #[track_caller]
    pub fn global(&mut self, layer: LayerRef) {
        let name = self.resolve(layer);
        self.connectivity.global.push(name);
    }

    /// `connect via cut [a, b]`.
    #[track_caller]
    pub fn via(&mut self, cut: LayerRef, (a, b): (LayerRef, LayerRef)) {
        let via = ViaSource {
            layer: self.resolve(cut),
            connects: (self.resolve(a), self.resolve(b)),
        };
        self.connectivity.vias.push(via);
    }

    /// `connect label text names conductor`.
    #[track_caller]
    pub fn label(&mut self, text: LayerRef, names: LayerRef) {
        let label = LabelSource {
            layer: self.resolve(text),
            names: self.resolve(names),
        };
        self.connectivity.labels.push(label);
    }

    /// `device kind marker model "model" terminals [..]` with `value`'s
    /// coefficients.
    #[track_caller]
    pub fn device(
        &mut self,
        kind: DeviceKind,
        marker: LayerRef,
        model: &str,
        terminals: &[LayerRef],
        value: DeviceValue,
    ) {
        // A loop, not a closure: `resolve` reports the caller's location.
        let mut names = Vec::with_capacity(terminals.len());
        for &layer in terminals {
            names.push(self.resolve(layer));
        }
        let device = DeviceSource {
            kind,
            marker: self.resolve(marker),
            model: model.to_owned(),
            terminals: names,
            value,
        };
        self.devices.push(device);
    }

    /// Removes every recogniser of `model`. Refused when the deck has none.
    #[track_caller]
    pub fn remove_device(&mut self, model: &str) {
        let before = self.devices.len();
        self.devices.retain(|device| device.model != model);
        if self.devices.len() == before {
            self.refuse(format!(
                "remove of device \"{model}\", which the deck does not have"
            ));
        }
    }

    /// `pex layer ..`: the layer's parasitic row. Refused when it has one.
    #[track_caller]
    pub fn pex(&mut self, layer: LayerRef, row: StackSource) {
        let name = self.resolve(layer);
        if self.pex.iter().any(|(stated, _)| *stated == name) {
            self.refuse(format!("`{name}` already has a pex row"));
            return;
        }
        self.pex.push((name, row));
    }

    /// Replaces a layer's parasitic row. Refused when it has none.
    #[track_caller]
    pub fn replace_pex(&mut self, layer: LayerRef, row: StackSource) {
        let name = self.resolve(layer);
        match self.pex.iter_mut().find(|(stated, _)| *stated == name) {
            Some((_, stated)) => *stated = row,
            None => self.refuse(format!(
                "replace of the pex row of `{name}`, which has none"
            )),
        }
    }

    /// `temperature <operating> nominal <nominal>`, both in kelvin: the run's
    /// temperature, and the one every `pex` row's sheet resistance is stated
    /// at. Every row then gives its coefficients ([`StackSource::tc`]).
    pub fn temperature(&mut self, operating_k: f64, nominal_k: f64) {
        self.temperature = Some((operating_k, nominal_k));
    }

    /// Removes a layer's parasitic row. Refused when it has none.
    #[track_caller]
    pub fn remove_pex(&mut self, layer: LayerRef) {
        let name = self.resolve(layer);
        let before = self.pex.len();
        self.pex.retain(|(stated, _)| *stated != name);
        if self.pex.len() == before {
            self.refuse(format!("remove of the pex row of `{name}`, which has none"));
        }
    }

    /// Whether some rule of the deck has `id`.
    fn has_rule(&self, id: &str) -> bool {
        self.added.contains_key(id)
            || self.custom.iter().any(|rule| rule.id == id)
            || self
                .rules
                .iter()
                .any(|slot| slot.id() == id && !matches!(slot, Slot::Removed(_)))
    }

    #[track_caller]
    fn check_id(&mut self, id: &str) -> bool {
        if !is_rule_id(id) {
            self.refuse(format!("`{id}` is not a rule id a deck can write"));
            return false;
        }
        if self.has_rule(id) {
            self.refuse(format!("duplicate rule id `{id}`"));
            return false;
        }
        true
    }

    /// `rule id ..`: a rule this deck states, after the ones before it. A
    /// layer expression among its arguments becomes a layer here, after the
    /// layers declared so far, as the parser makes one.
    #[track_caller]
    pub fn rule(&mut self, id: &str, row: RuleRow) {
        if self.check_id(id) {
            let mut derived = std::mem::take(&mut self.derived);
            let rule = self.lower_rule(id, row, &mut derived);
            self.derived = derived;
            self.rules.push(Slot::Kept(rule));
        }
    }

    /// A custom rule ([`CustomRule`]): `check`, a Rust function, reads
    /// `inputs` and reports at `severity`, after the DRC rules. In a builder
    /// started from a deck it is [`Origin::Added`]. Refused when the id is
    /// taken or no input is given: a rule that reads nothing never runs.
    #[track_caller]
    pub fn custom(
        &mut self,
        id: &str,
        inputs: &[LayerRef],
        severity: Severity,
        check: CustomCheck,
    ) {
        if !self.check_id(id) {
            return;
        }
        if inputs.is_empty() {
            self.refuse(format!("{id}: a custom rule reads at least one layer"));
            return;
        }
        let mut names = Vec::with_capacity(inputs.len());
        for &layer in inputs {
            names.push(self.resolve(layer));
        }
        let origin = if self.based {
            Origin::Added
        } else {
            Origin::Base
        };
        self.custom.push(PendingCustom {
            id: id.to_owned(),
            inputs: names,
            severity,
            check,
            origin,
        });
    }

    /// Adds a rule over the base deck. Refused when the id is taken; an id
    /// [`remove`](Self::remove)d before is replaced in its place.
    #[track_caller]
    pub fn add(&mut self, id: &str, row: RuleRow) {
        if let Some(slot) = self
            .rules
            .iter_mut()
            .find(|slot| matches!(slot, Slot::Removed(removed) if removed == id))
        {
            *slot = Slot::Row {
                id: id.to_owned(),
                row,
                origin: Origin::Replaced,
            };
            return;
        }
        if self.check_id(id) {
            self.added.insert(id.to_owned(), row);
        }
    }

    /// Replaces the rule `id`, keeping its place; its kind may change.
    /// Refused, never an add, when the deck has no rule `id`, and for a
    /// custom rule, which is [`remove`](Self::remove)d and stated again.
    #[track_caller]
    pub fn replace(&mut self, id: &str, row: RuleRow) {
        if self.custom.iter().any(|rule| rule.id == id) {
            self.refuse(format!(
                "replace of custom rule `{id}`: remove it and state the new one"
            ));
            return;
        }
        if let Some(added) = self.added.get_mut(id) {
            *added = row;
            return;
        }
        match self
            .rules
            .iter_mut()
            .find(|slot| slot.id() == id && !matches!(slot, Slot::Removed(_)))
        {
            Some(slot) => {
                *slot = Slot::Row {
                    id: id.to_owned(),
                    row,
                    origin: Origin::Replaced,
                };
            }
            None => self.refuse(format!(
                "replace of rule `{id}`, which the deck does not have"
            )),
        }
    }

    /// Removes the rule `id`, custom or not. Refused when the deck has none.
    #[track_caller]
    pub fn remove(&mut self, id: &str) {
        if self.added.remove(id).is_some() {
            return;
        }
        if let Some(at) = self.custom.iter().position(|rule| rule.id == id) {
            self.custom.remove(at);
            return;
        }
        match self
            .rules
            .iter_mut()
            .find(|slot| slot.id() == id && !matches!(slot, Slot::Removed(_)))
        {
            Some(slot) => *slot = Slot::Removed(id.to_owned()),
            None => self.refuse(format!(
                "remove of rule `{id}`, which the deck does not have"
            )),
        }
    }

    /// A handle's name; refused when the handle is not this builder's.
    #[track_caller]
    fn resolve(&mut self, layer: LayerRef) -> String {
        if let Some(name) = self.names.get(layer.0 as usize) {
            return name.clone();
        }
        if layer.0 != u32::MAX {
            self.refuse("a layer handle from another deck".to_owned());
        }
        String::new()
    }

    /// The derived rows of a named layer's expression: its inner operations
    /// as `name#k` in post-order, then the layer itself, as the parser lowers
    /// `layer name = expr`.
    #[track_caller]
    fn lower_named(&mut self, name: &str, expr: LayerExpr) -> Vec<(DerivedSource, Option<String>)> {
        for fault in expr.faults {
            if self.errors.len() < MAX_ERRORS {
                self.errors.push(fault);
            }
        }
        let mut rows = Vec::new();
        match expr.node {
            Node::Layer(_) => self.refuse(
                "a derived layer needs an operator (and, or, not) or an operation (`.sized(..)`)"
                    .to_owned(),
            ),
            Node::Op {
                op,
                operands,
                pattern,
                ..
            } => {
                let mut count = 0;
                let layers = self.lower_operands(name, operands, &mut count, &mut rows);
                rows.push((
                    DerivedSource {
                        name: name.to_owned(),
                        op,
                        layers,
                    },
                    pattern,
                ));
            }
        }
        rows
    }

    #[track_caller]
    fn lower_operands(
        &mut self,
        name: &str,
        operands: Vec<Node>,
        count: &mut u32,
        rows: &mut Vec<(DerivedSource, Option<String>)>,
    ) -> Vec<String> {
        let mut names = Vec::with_capacity(operands.len());
        for operand in operands {
            let operand = match operand {
                Node::Layer(layer) => self.resolve(layer),
                Node::Op {
                    op,
                    operands,
                    pattern,
                    ..
                } => {
                    let layers = self.lower_operands(name, operands, count, rows);
                    *count += 1;
                    let hidden = format!("{name}#{count}");
                    rows.push((
                        DerivedSource {
                            name: hidden.clone(),
                            op,
                            layers,
                        },
                        pattern,
                    ));
                    hidden
                }
            };
            names.push(operand);
        }
        names
    }

    /// A rule row to the parser's form: each argument that is not a plain
    /// layer lowered as `id@k` in deck order, then the layers put in the
    /// engine's order.
    #[track_caller]
    fn lower_rule(
        &mut self,
        id: &str,
        row: RuleRow,
        rows: &mut Vec<(DerivedSource, Option<String>)>,
    ) -> RuleSource {
        let mut inline = 0;
        let mut named = Vec::with_capacity(row.args.len());
        for arg in row.args {
            if let Some(layer) = arg.as_layer() {
                named.push(self.resolve(layer));
                continue;
            }
            inline += 1;
            let name = format!("{id}@{inline}");
            rows.extend(self.lower_named(&name, arg));
            named.push(name);
        }
        let layers = if row.slots.is_empty() || named.len() < row.slots.len() {
            named
        } else {
            let fixed = row.slots.len();
            row.slots
                .iter()
                .map(|&slot| named[usize::from(slot)].clone())
                .chain(named[fixed..].iter().cloned())
                .collect()
        };
        let mut params: Vec<(&'static str, ParamSource)> = Vec::with_capacity(row.params.len());
        for (name, value) in row.params {
            let value = match value {
                RowValue::Value(value) => ParamSource::Value(value),
                RowValue::Layer(layer) => ParamSource::Layer(self.resolve(layer)),
                RowValue::Model(model) => ParamSource::Model(model),
            };
            params.push((name, value));
        }
        if row.warning {
            params.push(("warning", ParamSource::Value(ParamValue::Flag(true))));
        }
        RuleSource {
            id: id.to_owned(),
            kind: row.kind,
            layers,
            params,
        }
    }

    /// Lowers and compiles the deck, as [`compile`](super::compile) does deck
    /// text, and records where each rule came from
    /// ([`CompiledDeck::provenance`]).
    ///
    /// # Errors
    ///
    /// [`BuildError::Invalid`] with everything the builder refused (an id
    /// used twice, an unknown layer, a range nothing satisfies, an override
    /// of something absent), each where it was called; else
    /// [`BuildError::Compile`] with what lowering or typing refused.
    pub fn finish(mut self) -> Result<CompiledDeck, BuildError> {
        // A base rule's inline layers go with it when it is replaced or removed.
        let kept: HashSet<String> = self
            .rules
            .iter()
            .filter_map(|slot| match slot {
                Slot::Kept(rule) => Some(rule.id.clone()),
                _ => None,
            })
            .collect();
        let mut derived = std::mem::take(&mut self.derived);
        derived.retain(|(row, _)| {
            row.name
                .split_once('@')
                .is_none_or(|(owner, _)| kept.contains(owner))
        });
        let mut rules = Vec::new();
        let mut origins: HashMap<String, Origin> = HashMap::new();
        for slot in std::mem::take(&mut self.rules) {
            match slot {
                Slot::Kept(rule) => {
                    let origin = self
                        .base_origin
                        .get(&rule.id)
                        .copied()
                        .unwrap_or(Origin::Base);
                    origins.insert(rule.id.clone(), origin);
                    rules.push(rule);
                }
                Slot::Row { id, row, origin } => {
                    let rule = self.lower_rule(&id, row, &mut derived);
                    origins.insert(id, origin);
                    rules.push(rule);
                }
                Slot::Removed(_) => {}
            }
        }
        for (id, row) in std::mem::take(&mut self.added) {
            let rule = self.lower_rule(&id, row, &mut derived);
            origins.insert(id, Origin::Added);
            rules.push(rule);
        }
        if !self.errors.is_empty() {
            return Err(BuildError::Invalid(self.errors));
        }
        // Text patterns are numbered in the order the derived rows name them,
        // as the parser numbers them.
        let mut texts = Vec::new();
        let derived = derived
            .into_iter()
            .map(|(mut row, pattern)| {
                if let DerivedOp::WithText { keep, .. } = row.op {
                    let text = u32::try_from(texts.len()).expect("a deck has few patterns");
                    texts.push(pattern.unwrap_or_default());
                    row.op = DerivedOp::WithText { keep, text };
                }
                row
            })
            .collect();
        let source = DeckSource {
            layers: self.drawn,
            ignored: self.ignored,
            derived,
            texts,
            rules,
            connectivity: self.connectivity,
            devices: self.devices,
            pex: self.pex,
            temperature: self.temperature,
            lvs: self.lvs,
        };
        let deck = lower(&source, self.strings).map_err(CompileError::from)?;
        let mut compiled = CompiledDeck::from_deck(deck, self.grid, self.strings)?;
        for (id, origin) in &mut compiled.provenance {
            if let Some(&stated) = origins.get(self.strings.resolve(*id)) {
                *origin = stated;
            }
        }
        // Custom rules follow every typed rule, their ids interned last.
        for rule in self.custom {
            let mut inputs = Vec::with_capacity(rule.inputs.len());
            for name in &rule.inputs {
                let Some(layer) = compiled.layers.id(self.strings, name) else {
                    let why = format!("{}: unknown layer {name}", rule.id);
                    return Err(CompileError::from(DeckError::Malformed(why)).into());
                };
                inputs.push(layer);
            }
            let id = self.strings.intern(&rule.id);
            compiled.custom.push(CustomRule {
                id,
                inputs,
                severity: rule.severity,
                check: rule.check,
            });
            compiled.provenance.push((id, rule.origin));
        }
        Ok(compiled)
    }
}
