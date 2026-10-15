//! Density fill (catalog FLOW-007): `gpurify fill` draws square fill shapes
//! on the deck's fill layer until the density rules hold, as the deck's
//! `fill` lines state them ([`FillSpec`]).
//!
//! Data in: a loaded layout and its deck. Data out: per `fill` line, the
//! fill layer and its new squares, which [`fill_gds`] writes into the
//! layout's GDSII.
//!
//! Sites are a grid of `size` squares at a pitch of `size + space` from the
//! die's lower-left corner, inside the die, each at least `keep` from every
//! shape of the `avoid` layers (measured square to their merged
//! rectangles, so a corner keeps the distance diagonally as well), `space`
//! from fill already drawn, and on nothing of the density layer. They are
//! taken in rows from the bottom, left to right, each only while a window
//! it lies in is below a `density` or `global_density` minimum on the
//! density layer, and only if no window it lies in then passes that
//! layer's maximum: fill tops each window up to its minimum, never over a
//! maximum. A window it cannot bring up (no room) stays short, and the
//! deck's own rule reports it.

use super::pipeline::{load_bytes, Inputs, LoadError, Loaded};
use gpurify_check::deck::DeckFn;
use gpurify_check::drc::Rule;
use gpurify_check::report::LimitSense;
use gpurify_geom::boolean::union_into;
use gpurify_geom::rects::decompose_into;
use gpurify_geom::view::validate_layer_into;
use gpurify_geom::{Bbox, Dbu, GeometryStore, LayerId, ValidatedLayer};
use gpurify_ingest::deck::FillSpec;
use std::ops::Range;

/// Why fill could not be drawn.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FillError {
    /// A layer a `fill` line reads is not rectilinear, is an edge layer, or
    /// could not be computed: fill places rectangles against rectangles.
    #[error("fill {fill}: layer {layer} cannot be read as rectangles")]
    NotRectilinear {
        /// The fill layer, naming the line.
        fill: String,
        /// The layer that could not be read.
        layer: String,
    },
    /// No `density` or `global_density` rule measures the line's density
    /// layer, so nothing states how much fill it needs.
    #[error("fill {fill}: no density or global_density rule measures {density}")]
    NoDensityRule {
        /// The fill layer, naming the line.
        fill: String,
        /// The density layer it names.
        density: String,
    },
    /// The layout could not be read, or the fill written into it.
    #[error(transparent)]
    Load(#[from] LoadError),
}

/// One density rule's windows over a die: a `side_x` by `side_y` window
/// every `stride`, `cols` by `ways` of them (a whole-die rule is one window,
/// the die), each window's covered area and the rule's limit.
struct Windows {
    x0: i64,
    y0: i64,
    side_x: i64,
    side_y: i64,
    stride: i64,
    cols: i64,
    ways: i64,
    /// A window's area: `side²` for a swept window, which may hang past the
    /// die and counts the outside as empty (as `density` measures it).
    whole: f64,
    limit: f64,
    sense: LimitSense,
    covered: Vec<i128>,
}

impl Windows {
    /// The windows `b` overlaps with positive area, as `(row, columns)`.
    fn under(&self, b: Bbox) -> (Range<i64>, Range<i64>) {
        (
            hit(
                b.ylo.raw(),
                b.yhi.raw(),
                self.y0,
                self.side_y,
                self.stride,
                self.ways,
            ),
            hit(
                b.xlo.raw(),
                b.xhi.raw(),
                self.x0,
                self.side_x,
                self.stride,
                self.cols,
            ),
        )
    }

    fn window(&self, ix: i64, iy: i64) -> Bbox {
        let (x, y) = (self.x0 + ix * self.stride, self.y0 + iy * self.stride);
        bbox(x, y, x + self.side_x, y + self.side_y)
    }

    fn slot(&self, ix: i64, iy: i64) -> usize {
        usize::try_from(iy * self.cols + ix).expect("a window index")
    }

    /// Adds `b`'s area inside each window it overlaps.
    fn add(&mut self, b: Bbox) {
        let (rows, cols) = self.under(b);
        for iy in rows {
            for ix in cols.clone() {
                let area = overlap(b, self.window(ix, iy));
                let slot = self.slot(ix, iy);
                self.covered[slot] += area;
            }
        }
    }

    /// Whether a window `b` overlaps is below this minimum.
    fn wants(&self, b: Bbox) -> bool {
        let (rows, cols) = self.under(b);
        self.sense == LimitSense::Minimum
            && rows.into_iter().any(|iy| {
                cols.clone()
                    .any(|ix| self.fraction(self.covered[self.slot(ix, iy)]) < self.limit)
            })
    }

    /// Whether adding `b` keeps every window it overlaps within this maximum.
    fn allows(&self, b: Bbox) -> bool {
        let (rows, cols) = self.under(b);
        self.sense == LimitSense::Minimum
            || rows.into_iter().all(|iy| {
                cols.clone().all(|ix| {
                    let after = self.covered[self.slot(ix, iy)] + overlap(b, self.window(ix, iy));
                    self.fraction(after) <= self.limit
                })
            })
    }

    /// As `density` computes it, so a fraction this calls legal the rule does.
    #[expect(clippy::cast_precision_loss, reason = "an area, as the rule reads it")]
    fn fraction(&self, covered: i128) -> f64 {
        covered as f64 / self.whole
    }
}

/// The indices `i` in `0..n` whose span `origin + i·stride .. + side`
/// overlaps `lo..hi` with positive length.
fn hit(lo: i64, hi: i64, origin: i64, side: i64, stride: i64, n: i64) -> Range<i64> {
    let first = ((lo - origin - side).div_euclid(stride) + 1).clamp(0, n);
    let last = (hi - origin - 1).div_euclid(stride).min(n - 1);
    first..(last + 1).max(first)
}

fn bbox(xlo: i64, ylo: i64, xhi: i64, yhi: i64) -> Bbox {
    let d = Dbu::new_unchecked;
    Bbox {
        xlo: d(xlo),
        ylo: d(ylo),
        xhi: d(xhi),
        yhi: d(yhi),
    }
}

fn overlap(a: Bbox, b: Bbox) -> i128 {
    let w = (a.xhi.min(b.xhi) - a.xlo.max(b.xlo)).raw().max(0);
    let h = (a.yhi.min(b.yhi) - a.ylo.max(b.ylo)).raw().max(0);
    i128::from(w) * i128::from(h)
}

/// A layer merged and cut into disjoint rectangles; `None` when it cannot
/// be (a 45-degree edge, an edge layer, a layer not computed).
fn rects(store: &GeometryStore, layer: LayerId) -> Option<Vec<Bbox>> {
    if store.is_uncomputed(layer) {
        return None;
    }
    let (mut drawn, mut merged) = (ValidatedLayer::default(), ValidatedLayer::default());
    validate_layer_into(store, layer, &mut drawn).ok()?;
    union_into(&drawn, &drawn, &mut merged).ok()?;
    let (mut out, mut start) = (Vec::new(), Vec::new());
    decompose_into(&merged, &mut out, &mut start);
    Some(out)
}

/// The extent of `layers` in `store`.
fn extent(store: &GeometryStore, layers: impl Iterator<Item = LayerId>) -> Bbox {
    layers
        .flat_map(|layer| store.layer_bboxes(layer).iter().copied())
        .fold(Bbox::EMPTY, Bbox::union)
}

/// The fill each of the deck's `fill` lines draws, in deck order: its
/// layer and its new squares, row by row from the bottom.
///
/// # Errors
///
/// [`FillError::NotRectilinear`] and [`FillError::NoDensityRule`].
pub fn fill(loaded: &Loaded) -> Result<Vec<(LayerId, Vec<Bbox>)>, FillError> {
    loaded
        .deck
        .edits
        .fill
        .iter()
        .map(|spec| fill_one(loaded, spec))
        .collect()
}

fn fill_one(loaded: &Loaded, spec: &FillSpec) -> Result<(LayerId, Vec<Bbox>), FillError> {
    let (store, deck) = (&loaded.store, &loaded.deck);
    let id = |name: &str| {
        deck.layers
            .id(&loaded.strings, name)
            .expect("the deck checked its fill layers")
    };
    let (layer, density) = (id(&spec.layer), id(&spec.density));
    let read = |of: LayerId| {
        rects(store, of).ok_or_else(|| FillError::NotRectilinear {
            fill: spec.layer.clone(),
            layer: loaded.strings.resolve(deck.layers.name(of)).to_owned(),
        })
    };
    let drawn = deck
        .drc
        .first_derived
        .map_or(store.layer_count(), LayerId::idx);
    let drawn_extent = extent(
        store,
        (0..drawn).map(|l| LayerId(u16::try_from(l).expect("a LayerId is a u16"))),
    );
    let die_of = |boundary: Option<LayerId>| {
        boundary.map_or(drawn_extent, |b| extent(store, std::iter::once(b)))
    };

    // Every density rule on the layer, its windows over its own die.
    let covered = read(density)?;
    let mut rules = Vec::new();
    let mut die = Bbox::EMPTY;
    for (_, rule) in &deck.drc.rules {
        let (boundary, swept, limit, sense) = match *rule {
            Rule::Density {
                layer,
                boundary,
                window,
                step,
                limit,
                sense,
            } if layer == density => (boundary, Some((window.raw(), step.raw())), limit, sense),
            Rule::GlobalDensity {
                layer,
                boundary,
                limit,
                sense,
            } if layer == density => (boundary, None, limit, sense),
            _ => continue,
        };
        let own = die_of(boundary);
        if own.is_empty() {
            continue;
        }
        die = if die.is_empty() {
            own
        } else {
            die.intersection(own).unwrap_or(Bbox::EMPTY)
        };
        let (x0, y0) = (own.xlo.raw(), own.ylo.raw());
        let (w, h) = ((own.xhi - own.xlo).raw(), (own.yhi - own.ylo).raw());
        let positions =
            |span: i64, side: i64, step: i64| ((span - side).max(0) + step - 1) / step + 1;
        #[expect(clippy::cast_precision_loss, reason = "an area, as the rule reads it")]
        let mut windows = match swept {
            Some((side, step)) => Windows {
                x0,
                y0,
                side_x: side,
                side_y: side,
                stride: step,
                cols: positions(w, side, step),
                ways: positions(h, side, step),
                whole: (i128::from(side) * i128::from(side)) as f64,
                limit,
                sense,
                covered: Vec::new(),
            },
            None => Windows {
                x0,
                y0,
                side_x: w,
                side_y: h,
                stride: w.max(h).max(1),
                cols: 1,
                ways: 1,
                whole: (i128::from(w) * i128::from(h)) as f64,
                limit,
                sense,
                covered: Vec::new(),
            },
        };
        windows.covered = vec![0; usize::try_from(windows.cols * windows.ways).expect("windows")];
        for &r in &covered {
            if let Some(inside) = r.intersection(own) {
                windows.add(inside);
            }
        }
        rules.push(windows);
    }
    if rules.is_empty() {
        return Err(FillError::NoDensityRule {
            fill: spec.layer.clone(),
            density: spec.density.clone(),
        });
    }
    if die.is_empty() {
        return Ok((layer, Vec::new()));
    }

    // The site grid, and the sites each obstacle blocks.
    let (size, pitch) = (spec.size.raw(), spec.size.raw() + spec.space.raw());
    let (x0, y0) = (die.xlo.raw(), die.ylo.raw());
    let count = |span: i64| {
        if span < size {
            0
        } else {
            (span - size) / pitch + 1
        }
    };
    let (cols, rows) = (
        count((die.xhi - die.xlo).raw()),
        count((die.yhi - die.ylo).raw()),
    );
    let mut blocked = vec![false; usize::try_from(cols * rows).expect("a site count")];
    let mut block = |r: Bbox, clear: i64| {
        let ys = hit(
            r.ylo.raw() - clear,
            r.yhi.raw() + clear,
            y0,
            size,
            pitch,
            rows,
        );
        let xs = hit(
            r.xlo.raw() - clear,
            r.xhi.raw() + clear,
            x0,
            size,
            pitch,
            cols,
        );
        for iy in ys {
            for ix in xs.clone() {
                blocked[usize::try_from(iy * cols + ix).expect("a site")] = true;
            }
        }
    };
    for name in &spec.avoid {
        for r in read(id(name))? {
            block(r, spec.keep.raw());
        }
    }
    for r in read(layer)? {
        block(r, spec.space.raw());
    }
    for &r in &covered {
        block(r, 0);
    }

    let mut placed = Vec::new();
    for iy in 0..rows {
        for ix in 0..cols {
            if blocked[usize::try_from(iy * cols + ix).expect("a site")] {
                continue;
            }
            let (x, y) = (x0 + ix * pitch, y0 + iy * pitch);
            let site = bbox(x, y, x + size, y + size);
            if !rules.iter().any(|w| w.wants(site)) || !rules.iter().all(|w| w.allows(site)) {
                continue;
            }
            for windows in &mut rules {
                windows.add(site);
            }
            placed.push(site);
        }
    }
    Ok((layer, placed))
}

/// `inputs.layout`'s GDSII with every `fill` line's squares added on its
/// layer's stream pair, as `gpurify fill` writes it, and how many squares
/// each line drew.
///
/// # Errors
///
/// [`FillError`] when the layout or deck cannot be read, or a line cannot be
/// filled.
pub fn fill_gds(
    inputs: &Inputs,
    decks: &[(&str, DeckFn)],
) -> Result<(Vec<u8>, Vec<usize>), FillError> {
    let bytes = gpurify_ingest::layout::read_gds_bytes(&inputs.layout).map_err(LoadError::from)?;
    let loaded = load_bytes(inputs, &bytes, decks)?;
    let filled = fill(&loaded)?;
    let boxes: Vec<_> = filled
        .iter()
        .flat_map(|(layer, boxes)| {
            let pair = loaded.deck.layers.stream_of(*layer);
            boxes.iter().map(move |&b| (pair, b))
        })
        .collect();
    let out = gpurify_ingest::layout::gds::with_boxes(&bytes, &boxes).map_err(LoadError::from)?;
    Ok((out, filled.iter().map(|(_, boxes)| boxes.len()).collect()))
}
