//! `KLayout`'s JSON lines against `GPurify`'s findings, rule by rule.
//!
//! Both sides are reduced to a map from a key (a figure, a pair of figures, a
//! point, an edge; `translate::Key`) to the smallest measurement under it,
//! since `GPurify` reports per drawn row or pair and `KLayout` per edge pair.
//! Keys are integers: figure indices into the `fig:` sets `KLayout` wrote, or
//! coordinates in `GPurify`'s database units. `KLayout` ran at ×2 (a1), so a
//! `KLayout` coordinate is halved, floored as `GPurify` floors a midpoint.

use crate::translate::{Compare, Key, Mirror, Value};
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

/// A polygon at ×2: its hull and holes.
#[derive(Debug, Clone)]
pub struct Poly {
    pub hull: Vec<(i64, i64)>,
    pub holes: Vec<Vec<(i64, i64)>>,
}

/// One `KLayout` result object, at ×2.
#[derive(Debug, Clone)]
pub enum Item {
    /// Two edges.
    Pair([i64; 4], [i64; 4]),
    /// One edge.
    Edge([i64; 4]),
    /// A polygon, its area, and the value the script gave it.
    Poly(Poly, i64, Option<f64>),
    /// A point and its value (a density window).
    Point(i64, i64, f64),
    /// Two polygons by index into a `raw:` list.
    Rows(i64, i64),
}

/// Everything one job wrote.
#[derive(Debug, Default)]
pub struct Klayout {
    /// Result objects by rule tag.
    pub items: BTreeMap<String, Vec<Item>>,
    /// Figure sets by name.
    pub figs: BTreeMap<String, Vec<Poly>>,
    /// Layers with a corner contact.
    pub corner: BTreeSet<String>,
    /// Cut layers with a cut on two shapes of one layer, or two cuts that touch.
    pub bridge: BTreeSet<String>,
    /// Layers of class R.
    pub rclass: BTreeSet<String>,
    /// Errors the script caught.
    pub errors: Vec<String>,
}

fn points(v: &Json) -> Vec<(i64, i64)> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|p| (p[0].as_i64().unwrap_or(0), p[1].as_i64().unwrap_or(0)))
                .collect()
        })
        .unwrap_or_default()
}

fn seg(v: &Json) -> [i64; 4] {
    std::array::from_fn(|i| v[i].as_i64().unwrap_or(0))
}

impl Klayout {
    /// Parses one job's JSON lines.
    pub fn parse(text: &str) -> Self {
        let mut out = Klayout::default();
        for line in text.lines() {
            let Ok(j) = serde_json::from_str::<Json>(line) else {
                out.errors.push(format!("not JSON: {line}"));
                continue;
            };
            if let Some(e) = j.get("error") {
                out.errors.push(e.to_string());
                continue;
            }
            if let Some(name) = j.get("corner").and_then(Json::as_str) {
                out.corner.insert(name.to_owned());
                continue;
            }
            if let Some(name) = j.get("bridge").and_then(Json::as_str) {
                out.bridge.insert(name.to_owned());
                continue;
            }
            if let Some(name) = j.get("rclass").and_then(Json::as_str) {
                out.rclass.insert(name.to_owned());
                continue;
            }
            let rule = j["rule"].as_str().unwrap_or_default().to_owned();
            let item = if let Some(ep) = j.get("ep") {
                Item::Pair(seg(&ep[0]), seg(&ep[1]))
            } else if let Some(e) = j.get("e") {
                Item::Edge(seg(e))
            } else if let Some(hull) = j.get("hull") {
                let poly = Poly {
                    hull: points(hull),
                    holes: j["holes"]
                        .as_array()
                        .map(|h| h.iter().map(points).collect())
                        .unwrap_or_default(),
                };
                Item::Poly(
                    poly,
                    j["area"].as_i64().unwrap_or(0),
                    j.get("v").and_then(Json::as_f64),
                )
            } else if let Some(rows) = j.get("rows") {
                Item::Rows(
                    rows[0].as_i64().unwrap_or(NO_FIG),
                    rows[1].as_i64().unwrap_or(NO_FIG),
                )
            } else if let Some(pt) = j.get("pt") {
                Item::Point(
                    pt[0].as_i64().unwrap_or(0),
                    pt[1].as_i64().unwrap_or(0),
                    j["v"].as_f64().unwrap_or(f64::NAN),
                )
            } else {
                out.errors.push(format!("unknown line: {line}"));
                continue;
            };
            if let Some(set) = rule.strip_prefix("fig:") {
                if let Item::Poly(poly, ..) = item {
                    out.figs.entry(set.to_owned()).or_default().push(poly);
                }
            } else {
                out.items.entry(rule).or_default().push(item);
            }
        }
        out
    }
}

/// One `GPurify` finding, in its database units.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The marker.
    pub at: (i64, i64),
    /// The measurement as a number.
    pub measured: f64,
    /// The vertices of the first and second shapes, when named.
    pub a: Option<Vec<(i64, i64)>>,
    pub b: Option<Vec<(i64, i64)>>,
}

/// How a rule compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Agreed, under the rule's comparison; `true` when either side found
    /// something.
    Agree(bool),
    /// Out of the class an `OnlyInClass` comparison needs, or `Not`.
    NotCompared,
    /// Disagreed where a documented implementation difference explains it.
    Known(&'static str, String),
    /// Disagreed.
    Disagree(String),
}

// ------------------------------------------------------------- geometry ---

fn on_segment((ax, ay): (f64, f64), (bx, by): (f64, f64), (px, py): (f64, f64)) -> bool {
    let cross = (bx - ax) * (py - ay) - (by - ay) * (px - ax);
    cross == 0.0 && px >= ax.min(bx) && px <= ax.max(bx) && py >= ay.min(by) && py <= ay.max(by)
}

fn ring_f(ring: &[(i64, i64)]) -> Vec<(f64, f64)> {
    #[allow(clippy::cast_precision_loss, reason = "layout coordinates fit an f64")]
    ring.iter().map(|&(x, y)| (x as f64, y as f64)).collect()
}

fn on_ring(ring: &[(i64, i64)], p: (f64, f64)) -> bool {
    let r = ring_f(ring);
    (0..r.len()).any(|i| on_segment(r[i], r[(i + 1) % r.len()], p))
}

/// Strictly inside, for a point not on the ring.
fn in_ring(ring: &[(i64, i64)], (px, py): (f64, f64)) -> bool {
    let r = ring_f(ring);
    let mut inside = false;
    for i in 0..r.len() {
        let ((ax, ay), (bx, by)) = (r[i], r[(i + 1) % r.len()]);
        if (ay > py) != (by > py) && px < ax + (py - ay) * (bx - ax) / (by - ay) {
            inside = !inside;
        }
    }
    inside
}

/// The closed polygon holds `p` (×2 units).
fn contains(poly: &Poly, p: (f64, f64)) -> bool {
    if on_ring(&poly.hull, p) || poly.holes.iter().any(|h| on_ring(h, p)) {
        return true;
    }
    in_ring(&poly.hull, p) && !poly.holes.iter().any(|h| in_ring(h, p))
}

fn on_boundary(poly: &Poly, p: (f64, f64)) -> bool {
    on_ring(&poly.hull, p) || poly.holes.iter().any(|h| on_ring(h, p))
}

/// The figure of `set` holding `p` (×2 units); then one within `slack`.
#[allow(clippy::cast_precision_loss, reason = "small offsets")]
fn fig_of(set: &[Poly], p: (f64, f64), slack: i64) -> Option<i64> {
    let at = |p| set.iter().position(|f| contains(f, p));
    at(p)
        .or_else(|| {
            (-slack..=slack)
                .flat_map(|dx| (-slack..=slack).map(move |dy| (dx, dy)))
                .find_map(|(dx, dy)| at((p.0 + dx as f64, p.1 + dy as f64)))
        })
        .map(|i| i64::try_from(i).expect("a small set"))
}

#[allow(clippy::cast_precision_loss, reason = "layout coordinates fit an f64")]
fn x2((x, y): (i64, i64)) -> (f64, f64) {
    ((2 * x) as f64, (2 * y) as f64)
}

#[allow(clippy::cast_precision_loss, reason = "layout coordinates fit an f64")]
fn pt(x: i64, y: i64) -> (f64, f64) {
    (x as f64, y as f64)
}

/// The Euclidean distance between two segments that do not cross.
fn seg_dist(e: [i64; 4], f: [i64; 4]) -> f64 {
    let to = |p: (f64, f64), s: [i64; 4]| {
        let (a, b) = (pt(s[0], s[1]), pt(s[2], s[3]));
        let (dx, dy) = (b.0 - a.0, b.1 - a.1);
        let len2 = dx * dx + dy * dy;
        let t = if len2 == 0.0 {
            0.0
        } else {
            (((p.0 - a.0) * dx + (p.1 - a.1) * dy) / len2).clamp(0.0, 1.0)
        };
        (p.0 - a.0 - t * dx).hypot(p.1 - a.1 - t * dy)
    };
    [
        to(pt(e[0], e[1]), f),
        to(pt(e[2], e[3]), f),
        to(pt(f[0], f[1]), e),
        to(pt(f[2], f[3]), e),
    ]
    .into_iter()
    .fold(f64::INFINITY, f64::min)
}

fn bbox(points: &[(i64, i64)]) -> [i64; 4] {
    points.iter().fold(
        [i64::MAX, i64::MAX, i64::MIN, i64::MIN],
        |[a, b, c, d], &(x, y)| [a.min(x), b.min(y), c.max(x), d.max(y)],
    )
}

fn seg_box(e: [i64; 4]) -> [i64; 4] {
    [
        e[0].min(e[2]),
        e[1].min(e[3]),
        e[0].max(e[2]),
        e[1].max(e[3]),
    ]
}

/// A ×2 coordinate as `GPurify`'s, floored.
fn half(v: i64) -> i64 {
    v.div_euclid(2)
}

/// The midpoint of two ×2 coordinates as `GPurify`'s, floored.
fn mid(a: i64, b: i64) -> i64 {
    (a + b).div_euclid(4)
}

/// The edge key: floored midpoint and length, in `GPurify`'s units.
/// An edge (doubled coordinates) by its floored midpoint and its Euclidean
/// length, halved and floored as `GPurify` reports a 45-degree edge's.
fn edge_key(e: [i64; 4]) -> Vec<i64> {
    let (dx, dy) = (e[2] - e[0], e[3] - e[1]);
    vec![
        mid(e[0], e[2]),
        mid(e[1], e[3]),
        ((dx * dx + dy * dy) / 4).isqrt(),
    ]
}

fn segment_key(e: [i64; 4]) -> Vec<i64> {
    let (p, q) = ((e[0], e[1]), (e[2], e[3]));
    let (p, q) = if p <= q { (p, q) } else { (q, p) };
    vec![p.0, p.1, q.0, q.1]
}

/// `GPurify`'s marker for a pair: the middle of the gap between two boxes.
fn gap_mid(a: [i64; 4], b: [i64; 4]) -> Vec<i64> {
    let span = |axis: usize| mid(a[axis].max(b[axis]), a[axis + 2].min(b[axis + 2]));
    vec![span(0), span(1)]
}

// ------------------------------------------------------------------ keys ---

type Side = BTreeMap<Vec<i64>, f64>;

fn put(side: &mut Side, key: Vec<i64>, value: f64) {
    let slot = side.entry(key).or_insert(f64::INFINITY);
    *slot = slot.min(value);
}

const NO_FIG: i64 = -1;

struct Ctx<'a> {
    m: &'a Mirror,
    kl: &'a Klayout,
}

impl Ctx<'_> {
    fn set(&self, name: &str) -> &[Poly] {
        self.kl.figs.get(name).map_or(&[], Vec::as_slice)
    }

    fn row_fig(&self, set: &str, row: Option<&Vec<(i64, i64)>>) -> i64 {
        row.and_then(|r| fig_of(self.set(set), x2(r[0]), 0))
            .unwrap_or(NO_FIG)
    }

    fn raw_index(&self, name: &str, row: Option<&Vec<(i64, i64)>>) -> i64 {
        let Some(row) = row else { return NO_FIG };
        let b = bbox(&row.iter().map(|&(x, y)| (2 * x, 2 * y)).collect::<Vec<_>>());
        self.raw(name)
            .iter()
            .position(|p| bbox(&p.hull) == b)
            .map_or(NO_FIG, |i| i64::try_from(i).expect("small"))
    }

    fn raw(&self, name: &str) -> Vec<Poly> {
        self.kl
            .items
            .get(&format!("raw:{name}"))
            .map(|items| {
                items
                    .iter()
                    .filter_map(|i| match i {
                        Item::Poly(p, ..) => Some(p.clone()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `GPurify`'s key for one finding.
    fn g_key(&self, f: &Finding) -> Vec<i64> {
        match &self.m.key {
            Key::FigAt(set) => vec![fig_of(self.set(set), x2(f.at), 2).unwrap_or(NO_FIG)],
            Key::FigRow(set, _) => vec![self.row_fig(set, f.a.as_ref())],
            Key::Pair(a, b, _) => {
                let (i, j) = (self.row_fig(a, f.a.as_ref()), self.row_fig(b, f.b.as_ref()));
                if a == b {
                    vec![i.min(j), i.max(j)]
                } else {
                    vec![i, j]
                }
            }
            Key::Point => vec![f.at.0, f.at.1],
            #[allow(clippy::cast_possible_truncation, reason = "a whole length")]
            Key::Edge => vec![f.at.0, f.at.1, f.measured as i64],
            Key::Segment => {
                let row = f.a.as_ref().expect("an angle finding names its shape");
                let i = row
                    .iter()
                    .position(|&p| p == f.at)
                    .expect("the marker is a vertex");
                let (p, q) = (row[i], row[(i + 1) % row.len()]);
                segment_key([2 * p.0, 2 * p.1, 2 * q.0, 2 * q.1])
            }
            Key::Row(_) => match &f.a {
                Some(row) => {
                    bbox(&row.iter().map(|&(x, y)| (2 * x, 2 * y)).collect::<Vec<_>>()).to_vec()
                }
                #[allow(clippy::cast_possible_truncation, reason = "a whole length")]
                None => vec![f.at.0, f.at.1, f.measured as i64],
            },
            Key::RowPair(name) => {
                let (i, j) = (
                    self.raw_index(name, f.a.as_ref()),
                    self.raw_index(name, f.b.as_ref()),
                );
                vec![i.min(j), i.max(j)]
            }
        }
    }

    /// `KLayout`'s key for one item, `None` for one the comparison drops.
    fn k_key(&self, item: &Item) -> Option<Vec<i64>> {
        let first_point = |item: &Item, edge: usize| match item {
            Item::Pair(a, b) => {
                let e = if edge == 0 { a } else { b };
                pt(e[0], e[1])
            }
            Item::Edge(e) => pt(e[0], e[1]),
            Item::Poly(p, ..) => pt(p.hull[0].0, p.hull[0].1),
            Item::Point(x, y, _) => pt(*x, *y),
            Item::Rows(..) => (f64::NAN, f64::NAN),
        };
        Some(match &self.m.key {
            Key::FigAt(set) => {
                vec![fig_of(self.set(set), first_point(item, 0), 0).unwrap_or(NO_FIG)]
            }
            Key::FigRow(set, edge) => {
                vec![fig_of(self.set(set), first_point(item, *edge), 0).unwrap_or(NO_FIG)]
            }
            Key::Pair(a, b, filter_same) => {
                let (i, j) = (
                    fig_of(self.set(a), first_point(item, 0), 0).unwrap_or(NO_FIG),
                    fig_of(self.set(b), first_point(item, 1), 0).unwrap_or(NO_FIG),
                );
                if *filter_same && i == j && a == b {
                    return None;
                }
                if matches!(self.m.kind, "corner_to_corner" | "convex_corner_spacing") {
                    if let Item::Pair(e, f) = item {
                        let (p, q) = (seg_box(*e), seg_box(*f));
                        let apart = |lo: usize, hi: usize| p[hi] < q[lo] || q[hi] < p[lo];
                        if !(apart(0, 2) && apart(1, 3)) {
                            return None;
                        }
                    }
                }
                if a == b {
                    vec![i.min(j), i.max(j)]
                } else {
                    vec![i, j]
                }
            }
            Key::Point => match item {
                Item::Pair(e, f)
                    if matches!(
                        self.m.kind,
                        "edge_spacing" | "edge_width" | "edge_facing_space"
                    ) =>
                {
                    gap_mid(seg_box(*e), seg_box(*f))
                }
                // A corner of `with_angle`: the first edge arrives at it.
                Item::Pair(e, ..) if self.m.kind == "min_interior_angle" => {
                    vec![half(e[2]), half(e[3])]
                }
                Item::Pair(e, ..) => vec![half(e[0]), half(e[1])],
                Item::Poly(p, ..) => {
                    let b = bbox(&p.hull);
                    vec![mid(b[0], b[2]), mid(b[1], b[3])]
                }
                Item::Point(x, y, _) => vec![half(*x), half(*y)],
                Item::Edge(e) => edge_key(*e)[..2].to_vec(),
                Item::Rows(..) => return None,
            },
            Key::Edge => match item {
                Item::Edge(e) => edge_key(*e),
                _ => return None,
            },
            Key::Segment => match item {
                Item::Edge(e) => segment_key(*e),
                _ => return None,
            },
            Key::Row(_) => match item {
                Item::Poly(p, ..) => bbox(&p.hull).to_vec(),
                Item::Edge(e) => edge_key(*e),
                _ => return None,
            },
            Key::RowPair(name) => {
                if let Item::Rows(i, j) = item {
                    return Some(vec![*i.min(j), *i.max(j)]);
                }
                let Item::Pair(e, f) = item else {
                    return None;
                };
                let raw = self.raw(name);
                let index = |e: &[i64; 4]| {
                    let mid = (
                        f64::midpoint(pt(e[0], e[1]).0, pt(e[2], e[3]).0),
                        f64::midpoint(pt(e[0], e[1]).1, pt(e[2], e[3]).1),
                    );
                    raw.iter()
                        .position(|p| on_boundary(p, mid))
                        .map_or(NO_FIG, |i| i64::try_from(i).expect("small"))
                };
                let (i, j) = (index(e), index(f));
                vec![i.min(j), i.max(j)]
            }
        })
    }

    /// `KLayout`'s measurement of one item, in `GPurify`'s units.
    #[allow(clippy::cast_precision_loss, reason = "layout numbers fit an f64")]
    fn k_value(&self, item: &Item) -> f64 {
        match (item, self.m.value) {
            // `EdgePair#distance` is 0 for two degenerate edges (a neck's
            // corners), so the distance is measured here.
            (Item::Pair(e, f), _) => seg_dist(*e, *f) / 2.0,
            (Item::Edge(e), _) => edge_key(*e)[2] as f64,
            (Item::Point(.., v), _) => *v,
            (Item::Rows(..), _) | (Item::Poly(..), Value::Length | Value::Ignore) => 0.0,
            (Item::Poly(_, area, v), Value::Area) => v.unwrap_or(*area as f64) / 4.0,
            (Item::Poly(_, _, v), Value::Count | Value::Ratio) => v.unwrap_or(f64::NAN),
            (Item::Poly(p, area, _), Value::CutSize(short, long)) => {
                let b = bbox(&p.hull);
                let (w, h) = ((b[2] - b[0]) / 2, (b[3] - b[1]) / 2);
                let (bs, bl) = (w.min(h), w.max(h));
                if bs != short {
                    bs as f64
                } else if bl != long {
                    bl as f64
                } else {
                    *area as f64 / 4.0
                }
            }
        }
    }

    fn k_side(&self, tag: &str) -> Result<Side, String> {
        let mut side = Side::new();
        for item in self.kl.items.get(tag).map_or(&[][..], Vec::as_slice) {
            if let Some(key) = self.k_key(item) {
                put(&mut side, key, self.k_value(item));
            }
        }
        self.mapped(side, "KLayout")
    }

    /// `side`, unless one of its figure keys found no figure: two such keys
    /// would compare equal whatever they stand for.
    fn mapped(&self, side: Side, who: &str) -> Result<Side, String> {
        let figural = matches!(
            self.m.key,
            Key::FigAt(_) | Key::FigRow(..) | Key::Pair(..) | Key::RowPair(_)
        );
        if figural && side.keys().any(|k| k.contains(&NO_FIG)) {
            Err(format!(
                "{who} has a finding in no figure: {}",
                shown(&side)
            ))
        } else {
            Ok(side)
        }
    }

    /// Exact on R+ for `min_extension`: both layers of class R, and every A
    /// over a B lies inside it or runs strictly past it at both ends.
    fn extension_class(&self) -> bool {
        let Key::Pair(a, b, _) = &self.m.key else {
            return false;
        };
        if !(self.kl.rclass.contains(a) && self.kl.rclass.contains(b)) {
            return false;
        }
        let boxes =
            |set: &str| -> Vec<[i64; 4]> { self.set(set).iter().map(|p| bbox(&p.hull)).collect() };
        let (bs, rs) = (boxes(a), boxes(b));
        bs.iter().all(|p| {
            rs.iter().all(|r| {
                // Shapes that only touch make no gate, but KLayout measures them.
                let overlaps = p[0] <= r[2] && r[0] <= p[2] && p[1] <= r[3] && r[1] <= p[3];
                let inside = r[0] <= p[0] && p[2] <= r[2] && r[1] <= p[1] && p[3] <= r[3];
                let across_x = p[0] < r[0] && r[2] < p[2] && r[1] <= p[1] && p[3] <= r[3];
                let across_y = p[1] < r[1] && r[3] < p[3] && r[0] <= p[0] && p[2] <= r[2];
                !overlaps || inside || across_x || across_y
            })
        })
    }
}

fn tolerance(value: Value, a: f64, b: f64) -> bool {
    match value {
        Value::Ignore => true,
        Value::Length => (a - b).abs() <= 1.0,
        // Whole numbers held as `f64`.
        Value::Area | Value::Count | Value::CutSize(..) => (a - b).abs() < 0.5,
        Value::Ratio => (a - b).abs() <= 1e-9 * a.abs().max(b.abs()).max(1e-30),
    }
}

fn shown(side: &Side) -> String {
    let items: Vec<String> = side
        .iter()
        .take(8)
        .map(|(k, v)| format!("{k:?}={v}"))
        .collect();
    format!(
        "{{{}{}}}",
        items.join(", "),
        if side.len() > 8 { ", .." } else { "" }
    )
}

/// `sub ⊆ sup` by key, with `sup`'s measurement no larger on a shared key
/// (when `values`).
fn within(value: Value, sub: &Side, sup: &Side, values: bool) -> Result<(), String> {
    let missing: Side = sub
        .iter()
        .filter(|(k, _)| !sup.contains_key(*k))
        .map(|(k, v)| (k.clone(), *v))
        .collect();
    if !missing.is_empty() {
        return Err(format!("keys missing: {}", shown(&missing)));
    }
    if values {
        for (k, v) in sub {
            let w = sup[k];
            if !(w <= *v || tolerance(value, w, *v)) {
                return Err(format!("{k:?}: {w} above {v}"));
            }
        }
    }
    Ok(())
}

/// Compares one rule. A disagreement on a layout with a corner contact on a layer the
/// rule reads says so: the corner model (F53, fixed in B20) is the first
/// suspect there.
pub fn compare(m: &Mirror, kl: &Klayout, findings: &[Finding]) -> Outcome {
    let ctx = Ctx { m, kl };
    let mut g = Side::new();
    for f in findings {
        put(&mut g, ctx.g_key(f), f.measured);
    }
    let mut compare = m.compare;
    if !m.exact_on.is_empty() && m.exact_on.iter().all(|l| kl.rclass.contains(l)) {
        compare = Compare::Exact;
    }
    if compare == Compare::OnlyInClass {
        compare = if ctx.extension_class() {
            Compare::Exact
        } else {
            Compare::Not
        };
    }
    let mut found = !g.is_empty();
    let result = ctx.mapped(g, "GPurify").and_then(|g| match compare {
        Compare::Not | Compare::OnlyInClass => Ok(()),
        Compare::Exact => {
            let k = ctx.k_side(&m.id)?;
            found |= !k.is_empty();
            if g.keys().ne(k.keys()) {
                Err(format!("GPurify {} / KLayout {}", shown(&g), shown(&k)))
            } else {
                g.iter()
                    .find(|(key, v)| !tolerance(m.value, **v, k[*key]))
                    .map_or(Ok(()), |(key, v)| {
                        Err(format!("{key:?}: GPurify {v}, KLayout {}", k[key]))
                    })
            }
        }
        Compare::KlayoutWithin => within(m.value, &ctx.k_side(&m.id)?, &g, true),
        Compare::GpurifyWithin => within(m.value, &g, &ctx.k_side(&m.id)?, true),
        Compare::Bracket => {
            let (lo, hi) = (
                ctx.k_side(&format!("{}#lo", m.id))?,
                ctx.k_side(&format!("{}#hi", m.id))?,
            );
            // A tap well's furthest point inside a tap over-reports (fails closed).
            let allowed: Side = match &m.key {
                Key::Row(Some((taps, wells))) => findings
                    .iter()
                    .filter(|f| {
                        fig_of(ctx.set(taps), x2(f.at), 0).is_some()
                            || fig_of(ctx.set(wells), x2(f.at), 0).is_none()
                    })
                    .map(|f| (ctx.g_key(f), 0.0))
                    .collect(),
                _ => Side::new(),
            };
            let g_strict: Side = g
                .iter()
                .filter(|(k, _)| !allowed.contains_key(*k))
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            within(m.value, &lo, &g, false)
                .map_err(|e| format!("lo ⊄ GPurify: {e}"))
                .and_then(|()| {
                    within(m.value, &g_strict, &hi, false).map_err(|e| format!("GPurify ⊄ hi: {e}"))
                })
        }
    });
    if matches!(compare, Compare::Not | Compare::OnlyInClass) {
        return Outcome::NotCompared;
    }
    match result {
        Ok(()) => Outcome::Agree(found),
        // An implementation difference, not a defect on either side
        // (testing-plan F88): a KLayout cut is a net member and joins every
        // shape it touches; a GPurify cut joins one shape of each of its two
        // layers where it lands on both. They differ only on a cut that lands
        // on one of its layers, which no documentation settles.
        Err(why) if m.kind == "net_spacing" && !kl.bridge.is_empty() => {
            Outcome::Known("F88 (difference)", why)
        }
        Err(why) => match m.reads.iter().find(|l| kl.corner.contains(*l)) {
            Some(layer) => Outcome::Disagree(format!("{why} (corner contact on {layer})")),
            None => Outcome::Disagree(why),
        },
    }
}
