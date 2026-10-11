//! A `GPurify` deck as a `KLayout` DRC script: the mirror deck of
//! `docs/klayout-mirror.md`, one emitter per DRC kind.
//!
//! The script runs on the layout magnified by two (a1), so every length the
//! deck implies, halves included, is a whole database unit: a length `l` is
//! written `2l` and an area `a` is written `4a`. Corner contact joins
//! material (the Connected model, ledger B20), which is `KLayout`'s default
//! merge, so no layer is put in minimum coherence.
//!
//! Each rule writes JSON lines tagged with its id (see `PRELUDE`), and a
//! [`Mirror`] says how those lines are compared with `GPurify`'s findings.

use gpurify::check::drc::{Rule, RuleSet, WireBand};
use gpurify::check::report::LimitSense;
use gpurify::geom::LayerId;
use gpurify_ingest::deck::{Deck, DerivedOp};
use gpurify_ingest::StrTable;
use std::fmt::Write as _;

/// What the mirror can say about a kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The recipe reports what `GPurify` must report.
    Exact,
    /// The recipe brackets `GPurify`, or agrees only on a class of layouts.
    Approx,
    /// `KLayout` cannot state the rule; the reason is shown.
    None(&'static str),
}

/// How the two reports of one rule are compared, key by key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compare {
    /// The same keys, and the same measurement on each.
    Exact,
    /// Every `KLayout` key is a `GPurify` key, whose measurement is no larger.
    KlayoutWithin,
    /// Every `GPurify` key is a `KLayout` key, whose measurement is no larger.
    GpurifyWithin,
    /// `<id>#lo` ⊆ `GPurify` ⊆ `<id>#hi`, keys only.
    Bracket,
    /// Exact when the layout is in the class [`Mirror::exact_on`] names,
    /// otherwise not compared.
    OnlyInClass,
    /// Not compared.
    Not,
}

/// What a finding is keyed by, on both sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    /// A figure of the named set; `GPurify`'s by its marker.
    FigAt(String),
    /// A figure of the named set; `GPurify`'s by its first shape, `KLayout`'s by
    /// the given edge of an edge pair.
    FigRow(String, usize),
    /// An ordered pair of figures, one per set; `GPurify`'s by its two shapes.
    /// Unordered when the sets are one. `filter_same` drops a `KLayout` pair
    /// inside one figure.
    Pair(String, String, bool),
    /// A point: `GPurify`'s marker; `KLayout`'s window centre, vertex, or box centre.
    Point,
    /// An axis-parallel edge, by its floored midpoint and its length.
    Edge,
    /// An undirected segment: `GPurify`'s from its shape and marker vertex.
    Segment,
    /// A shape by its bounding box (an edge by [`Key::Edge`]). With sets
    /// `(taps, wells)`, a finding whose marker lies in a tap or in a hole of
    /// the wells may be missing from the upper bound of a bracket (the tap
    /// rule's documented over-report).
    Row(Option<(String, String)>),
    /// A pair of drawn polygons of the named layer (`raw:<name>`).
    RowPair(String),
}

/// What a measurement is, and how a `KLayout` number becomes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// A length, to within one database unit.
    Length,
    /// An area, exactly.
    Area,
    /// A fraction, to within 1e-9.
    Ratio,
    /// A count, exactly.
    Count,
    /// A cut's wrong side, else its area: the sides `(short, long)`.
    CutSize(i64, i64),
    /// Not compared.
    Ignore,
}

/// One rule of the deck and how its mirror is compared.
#[derive(Debug, Clone)]
pub struct Mirror {
    /// The rule id.
    pub id: String,
    /// The engine kind.
    pub kind: &'static str,
    /// The kind's verdict.
    pub verdict: Verdict,
    /// How the reports are compared.
    pub compare: Compare,
    /// The comparison key.
    pub key: Key,
    /// The measurement.
    pub value: Value,
    /// Every polygon layer the rule reads, operands included: a corner
    /// contact on one of them makes a difference the open corner-model
    /// findings explain.
    pub reads: Vec<String>,
    /// Layers on which the comparison becomes exact when each is of class R
    /// (rectangles that neither touch nor overlap).
    pub exact_on: Vec<String>,
}

/// One job's script body and its rules.
pub struct Script {
    /// Ruby, run with `src` bound to the doubled source.
    pub ruby: String,
    /// One per DRC rule, in deck order.
    pub mirrors: Vec<Mirror>,
}

/// Helpers every job uses, emitted once per `KLayout` process.
pub const PRELUDE: &str = r#"require "json"
flat
def pts(it) ; it.map { |p| [p.x, p.y] } ; end
def seg(e) ; [e.x1, e.y1, e.x2, e.y2] ; end
def put(h) ; $out.puts(JSON.generate(h)) ; end
def poly(o) ; { hull: pts(o.each_point_hull), holes: (0...o.holes).map { |h| pts(o.each_point_hole(h)) }, area: o.area } ; end
# Every object of `layer` as one line tagged `rule`; a polygon also carries
# what the block says of it.
def emit(rule, layer, &extra)
  data = layer.is_a?(DRC::DRCLayer) ? layer.data : layer
  data.each do |o|
    rec = case o
          when RBA::EdgePair then { ep: [seg(o.first), seg(o.second)] }
          when RBA::Edge     then { e: seg(o) }
          when RBA::Polygon  then poly(o).merge(extra ? extra.call(o) : {})
          else { other: o.to_s }
          end
    put({ rule: rule }.merge(rec))
  end
end
# The figures of a polygon layer (corner contact joins), and whether it has a
# corner contact (its figures differ at minimum coherence) or is of class R.
def figs(name, layer)
  d = layer.data
  emit("fig:" + name, d.merged)
  m = d.dup ; m.min_coherence = true
  put({ corner: name }) if d.merged.each.map(&:to_s).sort != m.merged.each.map(&:to_s).sort
  put({ rclass: name }) if d.count == d.merged.count && d.merged.each.all?(&:is_box?)
end
def big(layer) ; b = layer.data.bbox ; b.empty? ? 1 : b.width + b.height + 1 ; end
def holes_below(rule, layer, a4)
  layer.data.merged.each do |p|
    p.holes.times do |h|
      q = RBA::Polygon.new(p.each_point_hole(h).to_a)
      put({ rule: rule }.merge(poly(q))) if q.area < a4
    end
  end
end
def positions(span, w, s) ; ([span - w, 0].max + s - 1) / s + 1 ; end
def density(rule, layer, die, w, s, limit, maximum)
  return if die.empty?
  cov = layer.data.merged & RBA::Region.new(die)
  positions(die.width, w, s).times do |i|
    positions(die.height, w, s).times do |j|
      win = RBA::Box.new(die.left + i * s, die.bottom + j * s, die.left + i * s + w, die.bottom + j * s + w)
      r = (cov & RBA::Region.new(win)).area.to_f / (w.to_f * w)
      put({ rule: rule, pt: [win.center.x, win.center.y], v: r }) if (maximum ? r > limit : r < limit)
    end
  end
end
# Per merged figure of `region`, the area of `layer` inside it over its own.
def region_density(rule, layer, region, limit, maximum)
  region.data.merged.each do |p|
    r = (layer.data.merged & RBA::Region.new(p)).area.to_f / p.area
    put({ rule: rule }.merge(poly(p)).merge({ v: r })) if (maximum ? r > limit : r < limit)
  end
end
def global_density(rule, layer, die, limit, maximum)
  return if die.empty?
  r = (layer.data.merged & RBA::Region.new(die)).area.to_f / die.area
  put({ rule: rule, pt: [die.center.x, die.center.y], v: r }) if (maximum ? r > limit : r < limit)
end
# Pairs of polygons of `all` (by index) that are both in `chosen` and touch
# or overlap.
def touching(rule, all, chosen)
  ps = all.data.each.to_a
  keep = chosen.data.each.to_a
  ps.each_with_index do |p, i|
    next unless keep.include?(p)
    ps.each_with_index do |q, j|
      next if j <= i || !keep.include?(q)
      put({ rule: rule, rows: [i, j] }) unless (RBA::Region.new(p).sized(1) & RBA::Region.new(q)).is_empty?
    end
  end
end
# Each gate edge an A figure runs past, measured to that figure's own edges:
# one figure at a time, since a transparent `enclosing` also pairs edges of
# neighbouring figures that merely face the same way.
def extension(rule, a, b, lim)
  bm = b.data.merged
  a.data.merged.each do |p|
    ar = RBA::Region.new(p)
    g = ar & bm
    next if g.is_empty?
    ar.enclosing_check(g, lim, false, RBA::Region::Projection, nil, nil, nil, false,
                       RBA::Region::NoOppositeFilter, RBA::Region::NoRectFilter, false,
                       RBA::Region::IgnoreProperties, RBA::Region::NeverIncludeZeroDistance).each do |ep|
      put({ rule: rule, ep: [seg(ep.first), seg(ep.second)] })
    end
  end
end
def edge_enclosure(rule, edges, outer, depth)
  edges.data.each do |e|
    next if e.length == 0
    put({ rule: rule, e: seg(e) }) unless (RBA::Edges.new(e).extended_out(depth) - outer.data).is_empty?
  end
end
# The squared distance from point p to segment a-b, exact.
def sq_dist(p, a, b)
  dx, dy = b.x - a.x, b.y - a.y
  t, l2 = (p.x - a.x) * dx + (p.y - a.y) * dy, dx * dx + dy * dy
  q = t <= 0 ? a : t >= l2 ? b : nil
  q ? (p.x - q.x)**2 + (p.y - q.y)**2 : Rational(((p.x - a.x) * dy - (p.y - a.y) * dx)**2, l2)
end
# The squared distance between two polygons, boundary to boundary: 0 when they
# touch, overlap or nest, else the least from a vertex of one to an edge of the
# other, exact.
def poly_d2(p, q)
  return 0 unless (RBA::Region.new(p).sized(1) & RBA::Region.new(q)).is_empty?
  ds = []
  p.each_edge { |e| q.each_point_hull { |v| ds << sq_dist(v, e.p1, e.p2) } }
  q.each_edge { |e| p.each_point_hull { |v| ds << sq_dist(v, e.p1, e.p2) } }
  ds.min
end
# LEF cut spacing over the drawn cuts of `layer`, by index into `raw:`: a cut's
# neighbours are the others closer than `within`; a pair closer than `lim`
# fails when either cut has at least `n` neighbours. Centre to centre (box
# centres, whole at x2) or boundary to boundary.
def cut_spacing(rule, layer, lim, n, within, center)
  ps = layer.data.each.to_a
  d2 = lambda do |p, q|
    next poly_d2(p, q) unless center
    a, b = p.bbox.center, q.bbox.center
    (a.x - b.x)**2 + (a.y - b.y)**2
  end
  m = ps.size
  dd = {}
  count = Array.new(m, 0)
  (0...m).each do |i|
    ((i + 1)...m).each do |j|
      dd[[i, j]] = d2.call(ps[i], ps[j])
      if dd[[i, j]] < within * within
        count[i] += 1
        count[j] += 1
      end
    end
  end
  dd.each do |(i, j), d|
    put({ rule: rule, rows: [i, j] }) if d < lim * lim && (count[i] >= n || count[j] >= n)
  end
end
# LEF58 cut-class spacing over the drawn cuts of `layer`, by index into `raw:`:
# a cut's class is the [short, long] pair of `cls` its box matches; `tbl` holds
# two rows and columns per class (END, SIDE). Apart along y, a cut faces with
# its SIDE when wider than tall; along x, when taller than wide; apart along
# both, the larger cell; touching or overlapping, the class pair's largest.
def cut_class_spacing(rule, layer, cls, tbl)
  bs = layer.data.each.to_a.map(&:bbox)
  klass = bs.map { |b| cls.index([b.width, b.height].minmax) }
  bs.each_with_index do |a, i|
    ((i + 1)...bs.size).each do |j|
      b = bs[j]
      next if klass[i].nil? || klass[j].nil?
      cell = lambda { |p, q| tbl[2 * klass[i] + (p ? 1 : 0)][2 * klass[j] + (q ? 1 : 0)] }
      apart_x = b.left > a.right || a.left > b.right
      apart_y = b.bottom > a.top || a.bottom > b.top
      need = if apart_x || apart_y
        [apart_y ? cell.(a.width > a.height, b.width > b.height) : 0,
         apart_x ? cell.(a.height > a.width, b.height > b.width) : 0].max
      else
        [[false, false], [false, true], [true, false], [true, true]].map { |p, q| cell.(p, q) }.max
      end
      dx = [b.left - a.right, a.left - b.right, 0].max
      dy = [b.bottom - a.top, a.bottom - b.top, 0].max
      put({ rule: rule, rows: [i, j] }) if dx * dx + dy * dy < need * need
    end
  end
end
# LEF MINIMUMCUT over the drawn cuts of `cuts`: a via is the cuts joining one
# figure of `wide` to one of `other` (the first each overlaps), split into
# groups closer than `within` (nil: one group); a group with a cut on the part
# of `wide` where a square T + 1 fits (x2) and fewer than `n` cuts reports
# every cut, with the count.
def minimum_cut(rule, cuts, wide, other, t, n, within)
  part = wide.data.merged.sized(-t).sized(t)
  wf = wide.data.merged.each.to_a
  of = other.data.merged.each.to_a
  first = lambda { |figs, c| figs.index { |f| !(RBA::Region.new(f) & RBA::Region.new(c)).is_empty? } }
  vias = Hash.new { |h, k| h[k] = [] }
  cuts.data.each do |c|
    w = first.(wf, c)
    vias[[w, first.(of, c)]] << c unless w.nil?
  end
  vias.each_value do |cs|
    group = (0...cs.size).to_a
    root = lambda { |i| group[i] == i ? i : (group[i] = root.(group[i])) }
    cs.each_index do |i|
      ((i + 1)...cs.size).each do |j|
        a, b = cs[i].bbox, cs[j].bbox
        dx = [b.left - a.right, a.left - b.right, 0].max
        dy = [b.bottom - a.top, a.bottom - b.top, 0].max
        group[root.(j)] = root.(i) if within.nil? || dx * dx + dy * dy < within * within
      end
    end
    cs.each_index.group_by { |i| root.(i) }.each_value do |members|
      held = members.any? { |i| !(part & RBA::Region.new(cs[i])).is_empty? }
      next if !held || members.size >= n
      members.each { |i| put({ rule: rule }.merge(poly(cs[i])).merge({ v: members.size })) }
    end
  end
end
# Each merged `outer` figure holding merged `inner` figures (covering them
# entirely) that reaches past their union sized by `lim` (square corners).
def max_enclosure(rule, outer, inner, lim)
  held = inner.data.merged.each.to_a
  outer.data.merged.each do |o|
    r = RBA::Region.new(o)
    mine = held.select { |p| (RBA::Region.new(p) - r).is_empty? }
    next if mine.empty?
    put({ rule: rule }.merge(poly(o))) unless (r - RBA::Region.new(mine).sized(lim)).is_empty?
  end
end
# LEF MAXVIASTACK over raw cut layers, bottom to top: a cut stacks on a cut
# of the layer before whose box it overlaps with positive area; each cut at
# height `max + 1` of a taller chain, with the tallest chain through it.
def via_stack(rule, layers, max)
  cuts = layers.map { |l| l.data.each.to_a }
  over = lambda { |a, b| a.left < b.right && b.left < a.right && a.bottom < b.top && b.bottom < a.top }
  chain = lambda do |order, step|
    h = cuts.map { |cs| [1] * cs.size }
    order.each do |i|
      p = i - step
      next if p < 0 || p >= cuts.size
      cuts[i].each_with_index do |c, k|
        hs = cuts[p].each_index.select { |j| over.(cuts[p][j].bbox, c.bbox) }.map { |j| h[p][j] }
        h[i][k] = hs.max + 1 unless hs.empty?
      end
    end
    h
  end
  down = chain.((0...cuts.size).to_a, 1)
  up = chain.((0...cuts.size).to_a.reverse, -1)
  cuts.each_with_index do |cs, i|
    cs.each_with_index do |c, k|
      put({ rule: rule }.merge(poly(c)).merge({ v: down[i][k] + up[i][k] - 1 })) if down[i][k] == max + 1
    end
  end
end
# The figures of `layer` whose narrowest Euclidean width, squared, lies in
# [lo, hi) (nil: open). `width` resolves only whole units, and a neck between
# two corners is irrational, so each width pair under the bound is measured
# exactly here.
def with_width2(layer, lo, hi)
  lim = Integer.sqrt([hi || lo, 0].max) + 1
  layer.merged.select do |p|
    w2 = RBA::Region.new(p.to_itype(dbu)).width_check(lim).each.map do |ep|
      e, f = ep.first, ep.second
      [sq_dist(e.p1, f.p1, f.p2), sq_dist(e.p2, f.p1, f.p2), sq_dist(f.p1, e.p1, e.p2), sq_dist(f.p2, e.p1, e.p2)].min
    end.min || Float::INFINITY
    (lo.nil? || w2 >= lo) && (hi.nil? || w2 < hi)
  end
end
# The distance between the lines of two parallel edges.
def line_gap(e, f) ; e.dy == 0 ? (e.y1 - f.y1).abs : (e.x1 - f.x1).abs ; end
# The last class threshold an edge's whole length reaches.
def length_class(e, classes) ; classes.rindex { |t| t <= e.length } ; end
# Each facing pair of whole edges `pairs` holds (an `isolated` check with
# `projection` and `whole_edges`) that is closer than the cell its two edges'
# length classes select.
def tip_table(rule, pairs, classes, space)
  pairs.data.each do |ep|
    e, f = ep.first, ep.second
    need = space[length_class(e, classes)][length_class(f, classes)]
    put({ rule: rule, ep: [seg(e), seg(f)] }) if line_gap(e, f) < need
  end
end
# Each facing pair `pairs` holds whose lines are at least `lo` apart.
def forbidden_gap(rule, pairs, lo)
  pairs.data.each do |ep|
    put({ rule: rule, ep: [seg(ep.first), seg(ep.second)] }) if line_gap(ep.first, ep.second) >= lo
  end
end
"#;

/// A Ruby string literal.
fn rb(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

fn var(layer: LayerId) -> String {
    format!("l{}", layer.0)
}

/// A bound for a `KLayout` `[min, max)` selection, from an inclusive `GPurify`
/// bound scaled by `k`: `nil` when absent.
fn lo_bound(lo: i128, k: i128) -> String {
    if lo == i128::MIN {
        "nil".into()
    } else {
        (lo * k).to_string()
    }
}

fn hi_bound(hi: i128, k: i128) -> String {
    if hi == i128::MAX {
        "nil".into()
    } else {
        (hi * k + 1).to_string()
    }
}

struct Layers<'a> {
    deck: &'a Deck,
    strings: &'a StrTable,
}

impl Layers<'_> {
    fn name(&self, layer: LayerId) -> String {
        self.strings
            .resolve(self.deck.layers.name(layer))
            .to_owned()
    }

    /// `layer` and every layer it is computed from, polygon layers only.
    fn reads(&self, layer: LayerId, into: &mut Vec<String>) {
        if !self.deck.layers.is_edges(layer) {
            into.push(self.name(layer));
        }
        for &operand in self.deck.layers.operands(layer) {
            self.reads(operand, into);
        }
    }

    /// The Ruby for one derived layer, from its operands' variables.
    fn derived(&self, layer: LayerId, op: DerivedOp) -> String {
        let ops: Vec<String> = self
            .deck
            .layers
            .operands(layer)
            .iter()
            .map(|&o| var(o))
            .collect();
        let (a, b) = (&ops[0], ops.get(1));
        let b = || b.expect("a binary layer operation");
        match op {
            DerivedOp::And => ops.join(" & "),
            // KLayout's `|` on edges cancels coincident edges of opposite
            // direction; GPurify keeps a shared part once.
            DerivedOp::Or if self.deck.layers.is_edges(layer) => ops[1..]
                .iter()
                .fold(a.clone(), |acc, e| format!("({acc} + ({e} - {acc}))")),
            DerivedOp::Or => ops.join(" | "),
            DerivedOp::Not => ops.join(" - "),
            DerivedOp::Sized(d) => format!("{a}.sized({})", 2 * d.raw()),
            DerivedOp::Interacting(true) => format!("{a}.interacting({})", b()),
            DerivedOp::Interacting(false) => format!("{a}.not_interacting({})", b()),
            DerivedOp::Inside => format!("{a}.inside({})", b()),
            DerivedOp::Outside => format!("{a}.outside({})", b()),
            DerivedOp::Holes => format!("{a}.holes"),
            DerivedOp::Extents => format!("{a}.extents"),
            DerivedOp::WithArea(lo, hi) => {
                format!("{a}.with_area({}, {})", lo_bound(lo, 4), hi_bound(hi, 4))
            }
            // The bounds are on the squared width, so 4x at x2.
            DerivedOp::WithWidth(i128::MIN, i128::MAX) => a.clone(),
            DerivedOp::WithWidth(lo, hi) => {
                format!("with_width2({a}, {}, {})", lo_bound(lo, 4), hi_bound(hi, 4))
            }
            DerivedOp::WithBbox { longer, lo, hi } => format!(
                "{a}.with_bbox_{}({}, {})",
                if longer { "max" } else { "min" },
                lo_bound(lo, 2),
                hi_bound(hi, 2)
            ),
            DerivedOp::Rectangles { square, keep } => format!(
                "{a}.{}{}",
                if keep { "" } else { "non_" },
                if square { "squares" } else { "rectangles" }
            ),
            DerivedOp::Edges => format!("{a}.edges"),
            DerivedOp::Part(true) => format!("{a}.inside_part({})", b()),
            DerivedOp::Part(false) => format!("({a}.outside_part({b}) - {b}.edges)", b = b()),
            DerivedOp::WithLength(lo, hi) => {
                format!("{a}.with_length({}, {})", lo_bound(lo, 2), hi_bound(hi, 2))
            }
            DerivedOp::Oriented(vertical) => {
                format!("{a}.with_angle({})", if vertical { 90 } else { 0 })
            }
            DerivedOp::WithText { keep, text } => {
                let operand = self.deck.layers.operands(layer)[1];
                let (l, d) = self.deck.layers.stream_of(operand);
                let pattern = self.deck.layers.text(text);
                format!(
                    "{a}.{}(src.labels({l}, {d}).texts(pattern({})))",
                    if keep {
                        "interacting"
                    } else {
                        "not_interacting"
                    },
                    rb(pattern)
                )
            }
        }
    }
}

/// Translates every DRC rule of `deck`.
///
/// # Errors
///
/// The deck's DRC rules do not build (`RuleSet::from_deck`).
pub fn translate(deck: &Deck, strings: &StrTable) -> Result<Script, String> {
    let set = RuleSet::from_deck(deck, strings).map_err(|why| why.to_string())?;
    let layers = Layers { deck, strings };
    let mut ruby = String::new();
    let count = deck.layers.len();
    let all: Vec<LayerId> = (0..count)
        .map(|i| LayerId(u16::try_from(i).expect("a LayerId is a u16")))
        .collect();
    let drawn: Vec<LayerId> = all
        .iter()
        .copied()
        .filter(|&l| !deck.layers.is_derived(l))
        .collect();
    for &layer in &all {
        let line = match deck.layers.op(layer) {
            None => {
                let (l, d) = deck.layers.stream_of(layer);
                format!("src.polygons({l}, {d})")
            }
            // KLayout can split a run where an operand's drawn shapes meet;
            // GPurify's edge layer holds maximal runs.
            Some(op) if deck.layers.is_edges(layer) => {
                format!("({}).merged", layers.derived(layer, op))
            }
            Some(op) => layers.derived(layer, op),
        };
        writeln!(ruby, "{} = {line}  # {}", var(layer), layers.name(layer)).expect("a String");
    }
    // The die every density rule without a boundary uses: the drawn layers' extent.
    let die: Vec<String> = drawn
        .iter()
        .map(|&l| format!("{}.data.bbox", var(l)))
        .collect();
    writeln!(ruby, "die = [RBA::Box.new, {}].inject(:+)", die.join(", ")).expect("a String");

    let mut figs: Vec<LayerId> = Vec::new();
    let mut connected = false;
    let mut mirrors = Vec::new();
    for &(id, rule) in &set.rules {
        let id = strings.resolve(id).to_owned();
        let q = rb(&id);
        let mut body = String::new();
        let mut reads = Vec::new();
        let mut fig = |layer: LayerId, reads: &mut Vec<String>| {
            if !figs.contains(&layer) {
                figs.push(layer);
            }
            layers.reads(layer, reads);
            layers.name(layer)
        };
        let lim = |l: gpurify::geom::Dbu| 2 * l.raw();
        let (kind, verdict, compare, key, value, exact_on): (
            &'static str,
            Verdict,
            Compare,
            Key,
            Value,
            Vec<String>,
        ) = match rule {
            Rule::MinWidth { layer, limit } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {}.width({}, euclidian, shielded))",
                    var(layer),
                    lim(limit)
                )
                .expect("a String");
                exact("min_width", Key::FigAt(name), Value::Length)
            }
            Rule::MaxWidth { layer, limit } => {
                fig(layer, &mut reads);
                writeln!(
                    body,
                    "w = {v}.sized(-{h}).sized({h}) ; figs({q}, w) ; emit({q}, w.width(big(w), projection))",
                    v = var(layer),
                    h = limit.raw()
                )
                .expect("a String");
                exact("max_width", Key::FigAt(id.clone()), Value::Length)
            }
            Rule::CutSize {
                layer,
                width,
                height,
            } => {
                fig(layer, &mut reads);
                let (short, long) = (width.min(height).raw(), width.max(height).raw());
                writeln!(
                    body,
                    "emit({q}, {}.drc(if_any(!rectangles, bbox_min != {}, bbox_max != {})))",
                    var(layer),
                    2 * short,
                    2 * long
                )
                .expect("a String");
                exact("cut_size", Key::Point, Value::CutSize(short, long))
            }
            Rule::MinEdgeLength { layer, limit } => {
                fig(layer, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {}.edges.with_length(nil, {}))",
                    var(layer),
                    lim(limit)
                )
                .expect("a String");
                exact("min_edge_length", Key::Edge, Value::Length)
            }
            Rule::Notch { layer, limit } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {}.notch({}, projection))",
                    var(layer),
                    lim(limit)
                )
                .expect("a String");
                exact("notch", Key::FigRow(name, 0), Value::Length)
            }
            Rule::MinSpacing { layer, limit } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {}.isolated({}, euclidian, transparent))",
                    var(layer),
                    lim(limit)
                )
                .expect("a String");
                exact(
                    "min_spacing",
                    Key::Pair(name.clone(), name, false),
                    Value::Length,
                )
            }
            Rule::MinSpacingDiff { a, b, limit } => {
                let (na, nb) = (fig(a, &mut reads), fig(b, &mut reads));
                writeln!(
                    body,
                    "emit({q}, {a}.separation({b}, {}, euclidian, transparent)) ; emit({q}, {a} & {b})",
                    lim(limit),
                    a = var(a),
                    b = var(b)
                )
                .expect("a String");
                exact("min_spacing_diff", Key::Pair(na, nb, false), Value::Length)
            }
            Rule::EolSpacing {
                layer,
                eol_width,
                limit,
            } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {}.isolated({}, projection, transparent, whole_edges).with_length(nil, {}))",
                    var(layer),
                    lim(limit),
                    lim(eol_width)
                )
                .expect("a String");
                approx(
                    "eol_spacing",
                    Compare::KlayoutWithin,
                    Key::Pair(name.clone(), name, false),
                    Value::Length,
                    vec![],
                )
            }
            Rule::PrlSpacing {
                layer,
                prl_threshold,
                limit,
            } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {}.isolated({}, euclidian, transparent, projection_limits({}, nil)))",
                    var(layer),
                    lim(limit),
                    lim(prl_threshold)
                )
                .expect("a String");
                approx(
                    "prl_spacing",
                    Compare::KlayoutWithin,
                    Key::Pair(name.clone(), name.clone(), false),
                    Value::Length,
                    vec![name],
                )
            }
            Rule::CornerToCorner { layer, limit } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {}.isolated({}, euclidian, transparent, projection_limits(0, 1)))",
                    var(layer),
                    lim(limit)
                )
                .expect("a String");
                approx(
                    "corner_to_corner",
                    Compare::GpurifyWithin,
                    Key::Pair(name.clone(), name.clone(), false),
                    Value::Length,
                    vec![name],
                )
            }
            Rule::WideDependentSpacing {
                layer,
                width_threshold,
                limit,
            } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "w = {v}.sized(-{t}).sized({t}) ; emit({q}, w.separation({v}, {}, euclidian, transparent))",
                    lim(limit),
                    v = var(layer),
                    t = width_threshold.raw() - 1
                )
                .expect("a String");
                exact(
                    "wide_dependent_spacing",
                    Key::Pair(name.clone(), name, true),
                    Value::Length,
                )
            }
            Rule::MinArea { layer, limit } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {}.with_area(nil, {}))",
                    var(layer),
                    4 * limit.raw()
                )
                .expect("a String");
                exact("min_area", Key::FigAt(name), Value::Area)
            }
            Rule::MinEnclosedArea { layer, limit } => {
                fig(layer, &mut reads);
                writeln!(
                    body,
                    "holes_below({q}, {}, {})",
                    var(layer),
                    4 * limit.raw()
                )
                .expect("a String");
                exact("min_enclosed_area", Key::Point, Value::Area)
            }
            Rule::Cheesing {
                layer,
                max_unslotted,
            } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {}.drc(if_all(area > {}, with_holes == 0)))",
                    var(layer),
                    4 * max_unslotted.raw()
                )
                .expect("a String");
                exact("cheesing", Key::FigAt(name), Value::Area)
            }
            Rule::Density {
                layer,
                boundary,
                window,
                step,
                limit,
                sense,
            } => {
                layers.reads(layer, &mut reads);
                writeln!(
                    body,
                    "density({q}, {}, {}, {}, {}, {limit:?}, {})",
                    var(layer),
                    boundary.map_or("die".to_owned(), |b| format!("{}.data.bbox", var(b))),
                    lim(window),
                    lim(step),
                    sense == LimitSense::Maximum
                )
                .expect("a String");
                exact("density", Key::Point, Value::Ratio)
            }
            Rule::GlobalDensity {
                layer,
                boundary,
                limit,
                sense,
            } => {
                layers.reads(layer, &mut reads);
                writeln!(
                    body,
                    "global_density({q}, {}, {}, {limit:?}, {})",
                    var(layer),
                    boundary.map_or("die".to_owned(), |b| format!("{}.data.bbox", var(b))),
                    sense == LimitSense::Maximum
                )
                .expect("a String");
                exact("global_density", Key::Point, Value::Ratio)
            }
            Rule::MinEnclosure {
                outer,
                inner,
                limit,
                wire,
            } => {
                fig(outer, &mut reads);
                let name = fig(inner, &mut reads);
                writeln!(
                    body,
                    "i = {} ; emit({q}, {o}.enclosing(i, {}, euclidian, transparent)) ; emit({q}, i.not_inside({o}))",
                    banded(var(inner), &var(outer), wire),
                    lim(limit),
                    o = var(outer),
                )
                .expect("a String");
                exact("min_enclosure", Key::FigRow(name, 1), Value::Length)
            }
            Rule::NoncoincidentEnclosure {
                outer,
                inner,
                limit,
            } => {
                fig(outer, &mut reads);
                let name = fig(inner, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {o}.enclosing({i}, {}, euclidian, transparent, without_touching_edges)) ; \
                     emit({q}, {i}.not_inside({o}))",
                    lim(limit),
                    o = var(outer),
                    i = var(inner)
                )
                .expect("a String");
                approx(
                    "noncoincident_enclosure",
                    Compare::KlayoutWithin,
                    Key::FigRow(name.clone(), 1),
                    Value::Ignore,
                    vec![],
                )
            }
            Rule::AsymmetricEnclosure {
                outer,
                inner,
                min_one_side,
                wire,
            } => {
                fig(outer, &mut reads);
                let name = fig(inner, &mut reads);
                writeln!(
                    body,
                    "i = {} ; c = enclosed({o}, projection) < {} ; \
                     emit({q}, i.drc(if_all(c.first_edges.angle == 90, c.first_edges.angle == 0))) ; \
                     emit({q}, i.not_inside({o}))",
                    banded(var(inner), &var(outer), wire),
                    lim(min_one_side),
                    o = var(outer),
                )
                .expect("a String");
                approx(
                    "asymmetric_enclosure",
                    Compare::KlayoutWithin,
                    Key::FigRow(name.clone(), 0),
                    Value::Ignore,
                    vec![name],
                )
            }
            Rule::MaxEnclosure {
                outer,
                inner,
                limit,
            } => {
                let name = fig(outer, &mut reads);
                fig(inner, &mut reads);
                writeln!(
                    body,
                    "max_enclosure({q}, {}, {}, {})",
                    var(outer),
                    var(inner),
                    lim(limit)
                )
                .expect("a String");
                exact("max_enclosure", Key::FigAt(name), Value::Ignore)
            }
            Rule::MinExtension {
                layer,
                reference,
                limit,
            } => {
                let (na, nb) = (fig(layer, &mut reads), fig(reference, &mut reads));
                writeln!(
                    body,
                    "extension({q}, {a}, {b}, {}) ; emit({q}, {a}.inside({b}))",
                    lim(limit),
                    a = var(layer),
                    b = var(reference)
                )
                .expect("a String");
                approx(
                    "min_extension",
                    Compare::OnlyInClass,
                    Key::Pair(na, nb, false),
                    Value::Length,
                    vec![],
                )
            }
            Rule::GateCorner {
                layer,
                reference,
                of_reference,
            } => {
                layers.reads(layer, &mut reads);
                layers.reads(reference, &mut reads);
                // `corners(90)` marks each concave corner with a 2 x 2 box
                // around it; two corners' boxes overlap only where they are
                // one point.
                writeln!(
                    body,
                    "emit({q}, ({a} & {b}).corners(90) & {}.corners(90))",
                    var(if of_reference { reference } else { layer }),
                    a = var(layer),
                    b = var(reference)
                )
                .expect("a String");
                exact("gate_corner", Key::Point, Value::Ignore)
            }
            Rule::Overlap { a, b, limit } => {
                fig(a, &mut reads);
                fig(b, &mut reads);
                writeln!(
                    body,
                    "ab = {} & {} ; figs({q}, ab) ; emit({q}, ab.width({}, euclidian, shielded))",
                    var(a),
                    var(b),
                    lim(limit)
                )
                .expect("a String");
                exact("overlap", Key::FigAt(id.clone()), Value::Length)
            }
            Rule::MaxDistanceToTap { well, tap, limit } => {
                let wells = fig(well, &mut reads);
                let taps = fig(tap, &mut reads);
                writeln!(
                    body,
                    // `sized(0)` copies the difference: KLayout never finds a
                    // raw polygon overlapping itself, and `w - t` is `w` when
                    // no tap reaches it.
                    "w = {}.dup.raw ; t = {} ; \
                     emit({lo}, w.overlapping((w - t.sized({l})).sized(0))) ; \
                     emit({hi}, w.overlapping((w - t.sized({l}, diamond_limit)).sized(0)))",
                    var(well),
                    var(tap),
                    lo = rb(&format!("{id}#lo")),
                    hi = rb(&format!("{id}#hi")),
                    l = lim(limit)
                )
                .expect("a String");
                (
                    "max_distance_to_tap",
                    Verdict::Approx,
                    Compare::Bracket,
                    Key::Row(Some((taps, wells))),
                    Value::Ignore,
                    vec![],
                )
            }
            Rule::OffGrid { pitch } => {
                for &layer in &drawn {
                    writeln!(
                        body,
                        "emit({q}, {}.dup.raw.ongrid({}))",
                        var(layer),
                        lim(pitch)
                    )
                    .expect("a String");
                }
                exact("off_grid", Key::Point, Value::Ignore)
            }
            Rule::Angle { layer, allowed } => {
                // With no layer, the drawn layers only (F63).
                let targets = layer.map_or_else(|| drawn.clone(), |layer| vec![layer]);
                let mut drop = String::new();
                for (bit, angle) in [(0, 0), (1, 45), (2, 90), (3, -45)] {
                    if allowed >> bit & 1 == 1 {
                        write!(drop, ".without_angle({angle})").expect("a String");
                    }
                }
                for layer in targets {
                    writeln!(body, "emit({q}, {}.dup.raw.edges{drop})", var(layer))
                        .expect("a String");
                }
                exact("angle", Key::Segment, Value::Ignore)
            }
            Rule::RedundantVia {
                layer,
                min_count,
                within,
            } => {
                layers.reads(layer, &mut reads);
                writeln!(
                    body,
                    "c = {}.dup.raw ; \
                     emit({lo}, c.not_interacting(c.sized({w}).raw, {min_count})) ; \
                     emit({hi}, c.not_interacting(c.sized({w}, diamond_limit).raw, {min_count}))",
                    var(layer),
                    lo = rb(&format!("{id}#lo")),
                    hi = rb(&format!("{id}#hi")),
                    w = lim(within)
                )
                .expect("a String");
                (
                    "redundant_via",
                    Verdict::Approx,
                    Compare::Bracket,
                    Key::Row(None),
                    Value::Ignore,
                    vec![],
                )
            }
            Rule::MinimumCut {
                cut,
                wide,
                other,
                width,
                within,
                min_count,
            } => {
                layers.reads(cut, &mut reads);
                layers.reads(wide, &mut reads);
                layers.reads(other, &mut reads);
                writeln!(
                    body,
                    "minimum_cut({q}, {}.dup.raw, {}, {}, {}, {min_count}, {})",
                    var(cut),
                    var(wide),
                    var(other),
                    // A `width + 1` square fits where sizing by `width`
                    // at x2 leaves material.
                    width.raw(),
                    within.map_or("nil".to_owned(), |w| lim(w).to_string())
                )
                .expect("a String");
                exact("minimum_cut", Key::Row(None), Value::Count)
            }
            Rule::ViaArraySpacing {
                layer,
                array_threshold,
                limit,
            } => {
                layers.reads(layer, &mut reads);
                let name = layers.name(layer);
                writeln!(
                    body,
                    "emit({}, {}.dup.raw)",
                    rb(&format!("raw:{name}")),
                    var(layer)
                )
                .expect("a String");
                // Clusters joined at half the limit from each cut: by square
                // growth (Chebyshev, the most joins) and by diamond growth (L1,
                // the fewest). A raw `isolated` never pairs cuts that overlap,
                // which `GPurify` measures at 0: `touching` adds every pair at 0
                // by index into `raw:`.
                for (tag, mode) in [("hi", ""), ("lo", ", diamond_limit")] {
                    writeln!(
                        body,
                        "c = {v}.dup.raw ; big = c.sized({h}{mode}).merged.interacting(c, {n}) ; \
                         arr = c.interacting(big) ; emit({t}, arr.isolated({l}, euclidian, transparent)) ; \
                         touching({t}, {v}.dup.raw, arr)",
                        v = var(layer),
                        h = limit.raw(),
                        n = u32::from(array_threshold) + 1,
                        t = rb(&format!("{id}#{tag}")),
                        l = lim(limit)
                    )
                    .expect("a String");
                }
                (
                    "via_array_spacing",
                    Verdict::Approx,
                    Compare::Bracket,
                    Key::RowPair(name),
                    Value::Ignore,
                    vec![],
                )
            }
            Rule::CutSpacing {
                layer,
                center,
                adjacent,
                within,
                limit,
            } => {
                layers.reads(layer, &mut reads);
                let name = layers.name(layer);
                writeln!(
                    body,
                    "emit({raw}, {v}.dup.raw) ; cut_spacing({q}, {v}.dup.raw, {}, {adjacent}, {}, {center})",
                    lim(limit),
                    lim(within),
                    raw = rb(&format!("raw:{name}")),
                    v = var(layer)
                )
                .expect("a String");
                exact("cut_spacing", Key::RowPair(name), Value::Ignore)
            }
            Rule::ViaStack { stack, max_height } => {
                let cuts: Vec<String> = set.stacks[stack as usize]
                    .iter()
                    .map(|&layer| {
                        layers.reads(layer, &mut reads);
                        format!("{}.dup.raw", var(layer))
                    })
                    .collect();
                writeln!(body, "via_stack({q}, [{}], {max_height})", cuts.join(", "))
                    .expect("a String");
                exact("via_stack", Key::Row(None), Value::Count)
            }
            Rule::CutClassSpacing { layer, table } => {
                layers.reads(layer, &mut reads);
                let name = layers.name(layer);
                let table = &set.cut_tables[table as usize];
                let classes: Vec<String> = table
                    .short
                    .iter()
                    .zip(&table.long)
                    .map(|(&s, &l)| format!("[{}, {}]", lim(s), lim(l)))
                    .collect();
                let side = 2 * table.short.len();
                let rows: Vec<String> = table
                    .space
                    .chunks(side)
                    .map(|row| {
                        let cells: Vec<String> = row.iter().map(|&c| lim(c).to_string()).collect();
                        format!("[{}]", cells.join(", "))
                    })
                    .collect();
                writeln!(
                    body,
                    "emit({raw}, {v}.dup.raw) ; cut_class_spacing({q}, {v}.dup.raw, [{}], [{}])",
                    classes.join(", "),
                    rows.join(", "),
                    raw = rb(&format!("raw:{name}")),
                    v = var(layer)
                )
                .expect("a String");
                exact("cut_class_spacing", Key::RowPair(name), Value::Ignore)
            }
            Rule::MultiPatterning { .. } => (
                "multi_patterning",
                Verdict::None("KLayout has no mask colouring"),
                Compare::Not,
                Key::Point,
                Value::Ignore,
                vec![],
            ),
            Rule::Forbidden { layer } => {
                layers.reads(layer, &mut reads);
                let what = if deck.layers.is_edges(layer) {
                    var(layer)
                } else if matches!(deck.layers.op(layer), None | Some(DerivedOp::Extents)) {
                    format!("{}.dup.raw", var(layer))
                } else {
                    format!("{}.data.merged", var(layer))
                };
                writeln!(body, "emit({q}, {what})").expect("a String");
                exact("forbidden", Key::Row(None), Value::Area)
            }
            Rule::MustContain {
                outer,
                inner,
                min_count,
                max_count,
            } => {
                let name = fig(outer, &mut reads);
                fig(inner, &mut reads);
                // `covering` drops an outer figure that an inner one
                // straddles, whatever else it holds: count only inners that
                // some outer figure holds. Too few and too many are disjoint.
                let (o, i) = (var(outer), var(inner));
                let held =
                    format!("{{ |p| {{ v: {i}.data.merged.inside(RBA::Region.new(p)).count }} }}");
                if min_count > 0 {
                    writeln!(
                        body,
                        "emit({q}, {o}.not_covering({i}.inside({o}), {min_count})) {held}"
                    )
                    .expect("a String");
                }
                if max_count < u32::MAX {
                    writeln!(
                        body,
                        "emit({q}, {o}.covering({i}.inside({o}), {})) {held}",
                        u64::from(max_count) + 1
                    )
                    .expect("a String");
                }
                exact("must_contain", Key::FigAt(name), Value::Count)
            }
            Rule::MustBeInside { inner, outer } => {
                let name = fig(inner, &mut reads);
                fig(outer, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {i}.not_inside({o})) {{ |p| {{ v: (RBA::Region.new(p) - {o}.data).area }} }}",
                    o = var(outer),
                    i = var(inner)
                )
                .expect("a String");
                exact("must_be_inside", Key::FigAt(name), Value::Area)
            }
            Rule::NetSpacing {
                layer,
                same_net,
                limit,
            } => {
                let name = fig(layer, &mut reads);
                if deck.connectivity.intra_layer_touch {
                    if !connected {
                        connected = true;
                        body.push_str(&connect(deck));
                    }
                    writeln!(
                        body,
                        "emit({q}, {}.nets.isolated({}, euclidian, transparent, {}))",
                        var(layer),
                        lim(limit),
                        if same_net { "props_eq" } else { "props_ne" }
                    )
                    .expect("a String");
                    exact(
                        "net_spacing",
                        Key::Pair(name.clone(), name, false),
                        Value::Length,
                    )
                } else {
                    (
                        "net_spacing",
                        Verdict::None(
                            "no `connect touch_within_layer`: KLayout always joins touching shapes",
                        ),
                        Compare::Not,
                        Key::Point,
                        Value::Ignore,
                        vec![],
                    )
                }
            }
            Rule::SpacingTable { layer, table } => {
                let name = fig(layer, &mut reads);
                let table = &set.tables[table as usize];
                let columns = table.prl.len();
                for (r, width) in table.width.iter().enumerate() {
                    for (c, prl) in table.prl.iter().enumerate() {
                        let s = 2 * table.space[r * columns + c].raw();
                        let run = if c == 0 {
                            String::new()
                        } else {
                            format!(", projection_limits({}, nil)", 2 * prl.raw() + 1)
                        };
                        let v = var(layer);
                        if r == 0 {
                            writeln!(
                                body,
                                "emit({q}, {v}.isolated({s}, euclidian, transparent{run}))"
                            )
                        } else {
                            writeln!(
                                body,
                                "emit({q}, {v}.sized(-{w}).sized({w}).separation({v}, {s}, euclidian, transparent{run}))",
                                w = width.raw()
                            )
                        }
                        .expect("a String");
                    }
                }
                approx(
                    "spacing_table",
                    Compare::KlayoutWithin,
                    Key::Pair(name.clone(), name.clone(), true),
                    Value::Ignore,
                    vec![name],
                )
            }
            Rule::AttachedWideSpacing {
                layer,
                width_threshold,
                attached,
                limit,
            } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "w = {v}.sized(-{t}).sized({t}) ; a = (w.sized({}) & {v}).interacting(w) ; \
                     emit({q}, a.separation({v}, {}, euclidian, transparent))",
                    lim(attached),
                    lim(limit),
                    v = var(layer),
                    t = width_threshold.raw() - 1
                )
                .expect("a String");
                approx(
                    "attached_wide_spacing",
                    Compare::KlayoutWithin,
                    Key::Pair(name.clone(), name, true),
                    Value::Length,
                    vec![],
                )
            }
            Rule::EdgeMinLength { layer, limit } => {
                writeln!(
                    body,
                    "emit({q}, {}.with_length(nil, {}))",
                    var(layer),
                    lim(limit)
                )
                .expect("a String");
                exact("edge_min_length", Key::Edge, Value::Length)
            }
            Rule::EdgeSpacing { a, b, limit } => {
                let l = lim(limit);
                let (e, f) = (var(a), b.map_or_else(|| var(a), var));
                let checks = if b.is_none() {
                    format!(
                        "[{e}.space({l}, euclidian, whole_edges), {e}.width({l}, euclidian, whole_edges), \
                         {e}.enclosing({e}, {l}, euclidian, whole_edges, without_touching_edges)]"
                    )
                } else {
                    format!(
                        "[{e}.separation({f}, {l}, euclidian, whole_edges), {e}.overlap({f}, {l}, euclidian, whole_edges), \
                         {e}.enclosing({f}, {l}, euclidian, whole_edges, without_touching_edges), \
                         {e}.enclosed({f}, {l}, euclidian, whole_edges, without_touching_edges)]"
                    )
                };
                writeln!(body, "{checks}.each {{ |x| emit({q}, x) }}").expect("a String");
                approx(
                    "edge_spacing",
                    Compare::KlayoutWithin,
                    Key::Point,
                    Value::Length,
                    vec![],
                )
            }
            Rule::EdgeEnclosure {
                edges,
                outer,
                limit,
            } => {
                layers.reads(outer, &mut reads);
                writeln!(
                    body,
                    "edge_enclosure({q}, {}, {}, {})",
                    var(edges),
                    var(outer),
                    lim(limit)
                )
                .expect("a String");
                exact("edge_enclosure", Key::Point, Value::Ignore)
            }
            Rule::Count {
                layer,
                limit,
                sense,
            } => {
                layers.reads(layer, &mut reads);
                writeln!(
                    body,
                    "n = {}.data.merged.count ; \
                     put({{ rule: {q}, pt: [die.center.x, die.center.y], v: n }}) if !die.empty? && n {} {limit}",
                    var(layer),
                    if sense == LimitSense::Maximum { ">" } else { "<" }
                )
                .expect("a String");
                exact("count", Key::Point, Value::Count)
            }
            Rule::AspectRatio { layer, limit } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {}.drc(bbox_aspect_ratio > {limit:?})) \
                     {{ |p| {{ v: [p.bbox.width, p.bbox.height].max.to_f / [p.bbox.width, p.bbox.height].min }} }}",
                    var(layer)
                )
                .expect("a String");
                exact("aspect_ratio", Key::FigAt(name), Value::Ratio)
            }
            Rule::TotalArea { layer, limit } => {
                layers.reads(layer, &mut reads);
                writeln!(
                    body,
                    "a = {}.data.merged.area ; \
                     put({{ rule: {q}, pt: [die.center.x, die.center.y], v: a / 4.0 }}) if !die.empty? && a > {}",
                    var(layer),
                    4 * limit.raw()
                )
                .expect("a String");
                exact("total_area", Key::Point, Value::Area)
            }
            Rule::CutClass { layer, classes } => {
                fig(layer, &mut reads);
                let wrong: Vec<String> = set.classes[classes as usize]
                    .iter()
                    .map(|&(short, long)| {
                        format!(
                            "if_any(bbox_min != {}, bbox_max != {})",
                            2 * short.raw(),
                            2 * long.raw()
                        )
                    })
                    .collect();
                // A figure fails when it is no rectangle, or every class
                // rejects it.
                let none = match wrong.as_slice() {
                    [one] => one.clone(),
                    _ => format!("if_all({})", wrong.join(", ")),
                };
                writeln!(
                    body,
                    "emit({q}, {}.drc(if_any(!rectangles, {none})))",
                    var(layer)
                )
                .expect("a String");
                exact("cut_class", Key::Point, Value::Ignore)
            }
            Rule::MinInteriorAngle { layer, limit } => {
                // With no layer, the drawn layers only, as for `angle`.
                let targets = layer.map_or_else(|| drawn.clone(), |layer| vec![layer]);
                // The polygon form of `with_angle` measures the angle inside
                // the shape, 0 to 360, in `[min, max)`, as IHP's deck uses it
                // for 3.1; `corners` measures the turn with an inclusive bound
                // resolved on the rounded rotated edge, so a right angle can
                // fall on either side of a limit of 90.
                for layer in targets {
                    writeln!(
                        body,
                        "emit({q}, {}.dup.raw.with_angle(0.0, {limit:?}))",
                        var(layer)
                    )
                    .expect("a String");
                }
                exact("min_interior_angle", Key::Point, Value::Ignore)
            }
            Rule::MinStep { .. } => (
                "min_step",
                Verdict::None("KLayout has no check on runs of short edges"),
                Compare::Not,
                Key::Point,
                Value::Ignore,
                vec![],
            ),
            Rule::PolygonValidity { .. } => (
                "polygon_validity",
                Verdict::None(
                    "KLayout's odd_polygons reports the parts of a polygon that are not \
                     orientable, not the drawn polygon, and no ring of zero area",
                ),
                Compare::Not,
                Key::Point,
                Value::Ignore,
                vec![],
            ),
            Rule::AllowedWidth { layer, widths } => {
                let name = fig(layer, &mut reads);
                let kept: Vec<String> = set.widths[widths as usize]
                    .iter()
                    .map(|w| {
                        let w2 = 4 * i128::from(w.raw()) * i128::from(w.raw());
                        format!("with_width2({}, {w2}, {})", var(layer), w2 + 1)
                    })
                    .collect();
                writeln!(
                    body,
                    "emit({q}, {}.merged - [{}].inject(:+))",
                    var(layer),
                    kept.join(", ")
                )
                .expect("a String");
                exact("allowed_width", Key::FigAt(name), Value::Ignore)
            }
            Rule::RegionDensity {
                layer,
                region,
                limit,
                sense,
            } => {
                layers.reads(layer, &mut reads);
                let name = fig(region, &mut reads);
                writeln!(
                    body,
                    "region_density({q}, {}, {}, {limit:?}, {})",
                    var(layer),
                    var(region),
                    sense == LimitSense::Maximum
                )
                .expect("a String");
                exact("region_density", Key::FigAt(name), Value::Ratio)
            }
            Rule::EdgeWidth { layer, limit } | Rule::EdgeFacingSpace { layer, limit } => {
                let (kind, check) = if matches!(rule, Rule::EdgeWidth { .. }) {
                    ("edge_width", "width")
                } else {
                    ("edge_facing_space", "space")
                };
                writeln!(
                    body,
                    "emit({q}, {}.{check}({}, projection))",
                    var(layer),
                    lim(limit)
                )
                .expect("a String");
                exact(kind, Key::Point, Value::Length)
            }
            Rule::TipSpacingTable { layer, table } => {
                let name = fig(layer, &mut reads);
                let table = &set.class_tables[table as usize];
                let widest = table.space.iter().map(|cell| cell.raw()).max().unwrap_or(0);
                let rows: Vec<String> = table
                    .space
                    .chunks(table.class.len())
                    .map(|row| format!("[{}]", doubled(row)))
                    .collect();
                writeln!(
                    body,
                    "tip_table({q}, {}.isolated({}, projection, transparent, whole_edges), [{}], [{}])",
                    var(layer),
                    2 * widest,
                    doubled(&table.class),
                    rows.join(", ")
                )
                .expect("a String");
                exact(
                    "tip_spacing_table",
                    Key::Pair(name.clone(), name, false),
                    Value::Length,
                )
            }
            Rule::TwoWidthSpacingTable { layer, table } => {
                let name = fig(layer, &mut reads);
                let table = &set.class_tables[table as usize];
                let n = table.class.len();
                let v = var(layer);
                // The part of the layer wider than width `i` (x2: sizing by
                // the undoubled width removes what is at most that wide).
                let part = |i: usize| {
                    if i == 0 {
                        v.clone()
                    } else {
                        format!("{v}.sized(-{w}).sized({w})", w = table.class[i].raw())
                    }
                };
                for r in 0..n {
                    for c in 0..n {
                        let s = 2 * table.space[r * n + c].raw();
                        let run = [table.prl[r], table.prl[c]]
                            .into_iter()
                            .flatten()
                            .map(|prl| 2 * prl.raw() + 1)
                            .max()
                            .map_or(String::new(), |run| {
                                format!(", projection_limits({run}, nil)")
                            });
                        if r == 0 && c == 0 {
                            writeln!(body, "emit({q}, {v}.isolated({s}, euclidian, transparent{run}))")
                        } else {
                            writeln!(
                                body,
                                "emit({q}, {}.separation({}, {s}, euclidian, transparent{run}))",
                                part(r),
                                part(c)
                            )
                        }
                        .expect("a String");
                    }
                }
                approx(
                    "two_width_spacing_table",
                    Compare::KlayoutWithin,
                    Key::Pair(name.clone(), name.clone(), true),
                    Value::Ignore,
                    vec![name],
                )
            }
            Rule::ConvexCornerSpacing {
                except_eol: Some(_),
                ..
            } => (
                "convex_corner_spacing",
                Verdict::None("KLayout cannot exempt the corners of an end of line"),
                Compare::Not,
                Key::Point,
                Value::Ignore,
                vec![],
            ),
            Rule::ConvexCornerSpacing {
                layer,
                corner_to_corner,
                except_eol: None,
                limit,
            } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "emit({q}, {}.isolated({}, {}, transparent, projection_limits(0, 1)))",
                    var(layer),
                    lim(limit),
                    if corner_to_corner { "euclidian" } else { "square" }
                )
                .expect("a String");
                approx(
                    "convex_corner_spacing",
                    Compare::GpurifyWithin,
                    Key::Pair(name.clone(), name, false),
                    Value::Ignore,
                    vec![],
                )
            }
            Rule::ExactPitch { .. } => (
                "exact_pitch",
                Verdict::None("KLayout has no centre-to-centre pitch between neighbouring shapes"),
                Compare::Not,
                Key::Point,
                Value::Ignore,
                vec![],
            ),
            Rule::SpanLength { .. } => (
                "span_length",
                Verdict::None("KLayout measures widths between edges, not the set of a shape's chords"),
                Compare::Not,
                Key::Point,
                Value::Ignore,
                vec![],
            ),
            Rule::EolKeepOut { .. } => (
                "eol_keep_out",
                Verdict::None("KLayout has no end-of-line keep-out box"),
                Compare::Not,
                Key::Point,
                Value::Ignore,
                vec![],
            ),
            Rule::EolWithinSpacing { .. } => (
                "eol_within_spacing",
                Verdict::None(
                    "KLayout has no end-of-line keep-out widened past the end, parallel-edge trigger or end-to-end space",
                ),
                Compare::Not,
                Key::Point,
                Value::Ignore,
                vec![],
            ),
            Rule::ForbiddenSpacing {
                layer,
                min,
                max,
                prl,
            } => {
                let name = fig(layer, &mut reads);
                writeln!(
                    body,
                    "forbidden_gap({q}, {}.isolated({}, projection, transparent, projection_limits({}, nil)), {})",
                    var(layer),
                    lim(max) + 1,
                    lim(prl) + 1,
                    lim(min)
                )
                .expect("a String");
                exact(
                    "forbidden_spacing",
                    Key::Pair(name.clone(), name, false),
                    Value::Length,
                )
            }
        };
        reads.sort();
        reads.dedup();
        if matches!(verdict, Verdict::None(_)) {
            writeln!(ruby, "# {id}: not mirrored").expect("a String");
        } else {
            write!(
                ruby,
                "begin\n{body}rescue => e\n  put({{ error: {q} + \": \" + e.message }})\nend\n"
            )
            .expect("a String");
        }
        mirrors.push(Mirror {
            id,
            kind,
            verdict,
            compare,
            key,
            value,
            reads,
            exact_on,
        });
    }
    // The figures of every layer a rule keys on, before any rule needs them.
    let mut head = String::new();
    for layer in figs {
        writeln!(head, "figs({}, {})", rb(&layers.name(layer)), var(layer)).expect("a String");
    }
    let split = ruby.find("die = ").expect("the die line is written");
    let end = split + ruby[split..].find('\n').expect("a line") + 1;
    ruby.insert_str(end, &head);
    Ok(Script { ruby, mirrors })
}

type Spec = (&'static str, Verdict, Compare, Key, Value, Vec<String>);

/// Lengths doubled for the ×2 layout, as a Ruby list's items.
fn doubled(lengths: &[gpurify::geom::Dbu]) -> String {
    lengths
        .iter()
        .map(|length| (2 * length.raw()).to_string())
        .collect::<Vec<_>>()
        .join(", ")
/// The inner layer `inner` restricted to an enclosure's wire band: the shapes
/// inside the part of `outer` at least `from` wide (`sized(-(w - 1))` and back
/// at x2, as for wide spacing) and not inside the part `below` wide.
fn banded(inner: String, outer: &str, wire: WireBand) -> String {
    let wide = |w: gpurify::geom::Dbu| {
        let t = w.raw() - 1;
        format!("{outer}.sized(-{t}).sized({t})")
    };
    let mut out = inner;
    if wire.from.raw() > 0 {
        out = format!("{out}.inside({})", wide(wire.from));
    }
    if let Some(below) = wire.below {
        out = format!("{out}.not_inside({})", wide(below));
    }
    out
}

fn exact(kind: &'static str, key: Key, value: Value) -> Spec {
    (kind, Verdict::Exact, Compare::Exact, key, value, vec![])
}

fn approx(
    kind: &'static str,
    compare: Compare,
    key: Key,
    value: Value,
    exact_on: Vec<String>,
) -> Spec {
    (kind, Verdict::Approx, compare, key, value, exact_on)
}

/// The deck's connectivity as `KLayout` `connect` statements (doc (c)): each
/// conductor joins itself, each via its two layers, each global layer one net.
/// Labels only name nets, so they join nothing. Each cut layer with a cut on
/// two shapes of one of its layers, or two cuts that touch, is marked
/// `bridge`: `KLayout`'s cut conducts there and `GPurify`'s does not (F88).
fn connect(deck: &Deck) -> String {
    let c = &deck.connectivity;
    let mut out = String::from("clear_connections\n");
    for &layer in &c.conductors {
        writeln!(out, "connect({v}, {v})", v = var(layer)).expect("a String");
    }
    for (&cut, &(a, b)) in c.via_cut.iter().zip(&c.via_connects) {
        writeln!(
            out,
            "connect({a}, {v}) ; connect({v}, {b})\n\
             put({{ bridge: {n} }}) if !{v}.interacting({a}, 2).is_empty? || \
             !{v}.interacting({b}, 2).is_empty? || {v}.data.count != {v}.data.merged.count",
            a = var(a),
            v = var(cut),
            b = var(b),
            n = rb(&var(cut))
        )
        .expect("a String");
    }
    for &layer in &c.global {
        writeln!(out, "connect_global({}, {})", var(layer), rb(&var(layer))).expect("a String");
    }
    out
}
