//! The extracted layout as a circuit a simulator can run.
//!
//! Data in: [`Loaded`] + [`Extracted`], the spec's pin names, and the wire
//! parasitics. Data out: a [`Circuit`] in SI units, every node numbered, node 0
//! the simulator's ground.
//!
//! Two shapes. [`Wires::Lumped`] is one node per net and no wire elements: the
//! device netlist, for leakage and the static capacitance sweep.
//! [`Wires::Distributed`] is a rectangle graph: every
//! conductor polygon is cut into the slab rectangles [`decompose_into`] gives,
//! each rectangle is a node, two rectangles sharing an edge are joined by the
//! sheet resistance from centre to centre, each via cut is its own resistor, and
//! each device terminal sits on the rectangle that touches its channel. Ground
//! capacitance is taken per rectangle from the stack (area less what lies over
//! a channel, which the device model already counts as gate oxide, plus the
//! perimeter no same-net rectangle covers). Coupling is the analytical
//! extractor's, measured between conductor regions (a net's merged shapes,
//! one per edge-connected piece on a layer), each element placed between the
//! two closest rectangles of its two regions; a field solve, when given,
//! rescales every net's ground and every net pair's coupling to the solved
//! totals without moving them.

use std::collections::BTreeMap;

use crate::engine::{Extracted, Loaded};
use crate::liberty::spec::MacroSpec;
use gpurify_check::topology::device::{DeviceId, DeviceMeasure, DeviceParam};
use gpurify_check::topology::{NetId, TerminalRole};
use gpurify_extract::network::{NodeId, Parasitic};
use gpurify_extract::ParasiticNetwork;
use gpurify_geom::rects::decompose_into;
use gpurify_geom::view::{validate_layer_into, ValidatedLayer};
use gpurify_geom::{Bbox, Grid, LayerId, PolyId};
use gpurify_ingest::deck::DeviceKind;

/// Where wire parasitics come from.
#[derive(Clone, Copy)]
pub enum Wires<'a> {
    /// No wire elements; one node per net. What `analytical` and `field`
    /// simulate, where wire capacitance is added separately.
    Lumped,
    /// The rectangle graph, coupling from `analytical`, rescaled to `field`.
    /// What `spice` and `statistical` simulate.
    Distributed {
        /// The analytical extraction of the same layout and nets. Each of
        /// its couplings joins two regions
        /// ([`node_rects`](gpurify_extract::analytical::node_rects)) and is
        /// placed between their closest rectangles.
        analytical: &'a ParasiticNetwork,
        /// A field solve with one node per net. When given, every net's
        /// ground and every net pair's coupling is rescaled to its totals.
        field: Option<&'a ParasiticNetwork>,
    },
}

/// A device parameter value, SI.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Param {
    /// Metres; written divided by
    /// [`Simulator::scale`](crate::liberty::spec::Simulator::scale).
    Length(f64),
    /// Square metres; written divided by the scale's square.
    Area(f64),
    /// A count, such as fingers; written as is.
    Count(u32),
}

/// One device card.
#[derive(Debug, Clone)]
pub struct Device {
    /// The deck's device family.
    pub kind: DeviceKind,
    /// The deck's model name, written on the card as is.
    pub model: String,
    /// Card order (`d g s b` for a MOS, `c b e` for a bipolar, pins in order
    /// otherwise).
    pub nodes: Vec<u32>,
    /// The layout net of each terminal, in `nodes` order.
    pub nets: Vec<NetId>,
    /// Each terminal's role, in `nodes` order.
    pub roles: Vec<TerminalRole>,
    /// Card parameters, `(name, value)`: the recogniser's `w`, `l`, `nf`,
    /// `area` and `perim` (`pj` on a diode). A MOS has its diffusions' `as`,
    /// `ps`, `ad` and `pd` instead of area and perimeter, topology's measures
    /// ([`DeviceParam::SourceArea`] and the rest, the ones LVS compares): a
    /// shared diffusion split between the fingers that share it, holes out of
    /// the area and in the perimeter, none where the terminal is drawn in
    /// pieces. And BSIM4 `sa` and `sb` when its channel's direction can be
    /// told.
    pub params: Vec<(&'static str, Param)>,
}

/// The circuit, SI units.
#[derive(Debug, Clone, Default)]
pub struct Circuit {
    /// Nodes are `0..node_count`. Node 0 is ground.
    pub node_count: u32,
    /// Every recognised device in the layout, in device-table order.
    pub devices: Vec<Device>,
    /// `(a, b, ohms)`.
    pub resistors: Vec<(u32, u32, f64)>,
    /// `(a, b, farads)`; `b == 0` is to ground.
    pub capacitors: Vec<(u32, u32, f64)>,
    /// Per spec pin, in spec order.
    pub pin_node: Vec<u32>,
    /// Per spec pin, the layout nets it is.
    pub pin_nets: Vec<Vec<NetId>>,
}

/// Why the layout could not be made into a circuit.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CircuitError {
    /// Spec pin `.0` names no layout net: no label carries it and, when it is
    /// the spec's `substrate`, the deck declares no substrate geometry
    /// either (`.1` then says so).
    #[error("pin {0} names no net in the layout: no label carries it{1}")]
    MissingPin(String, &'static str),
    /// Spec pins `.0` and `.1` are labelled on one layout net: the layout
    /// shorts them, so no characterisation can tell them apart.
    #[error("pins {0} and {1} are labelled on one net: the layout shorts them")]
    ShortedPins(String, String),
    /// Conductor layer `.0` is not valid rectilinear geometry (`.1` says
    /// why), so it cannot be cut into rectangles. [`Wires::Distributed`]
    /// only.
    #[error("layer {0} is not valid rectilinear geometry: {1}")]
    Geometry(String, String),
    /// Net `.0`'s rectangles and via resistors fall into `.1` separate
    /// pieces, so a terminal on a detached piece would float in simulation.
    /// [`Wires::Distributed`] only.
    #[error(
        "net {0} falls apart into {1} unconnected pieces in the resistor network, \
         so a simulation of it would leave a terminal floating"
    )]
    Disconnected(String, usize),
}

/// The layout nets each spec pin is, in spec order: every net its label is
/// on, plus every net holding substrate geometry when it is the spec's
/// `substrate`. Each list is ascending and never empty. A label on several
/// disconnected nets (an open) gives all of them, which the circuit joins at
/// the pin.
///
/// # Errors
///
/// - [`CircuitError::MissingPin`] for the first pin that names no net.
/// - [`CircuitError::ShortedPins`] for the first two pins whose labels are on
///   one net: a short between them in the layout.
pub fn pin_nets(
    loaded: &Loaded,
    extracted: &Extracted,
    spec: &MacroSpec,
) -> Result<Vec<Vec<NetId>>, CircuitError> {
    let substrate = substrate_nets(loaded, extracted);
    let mut out = Vec::with_capacity(spec.pins.len());
    // `(label net, pin)`: two pins whose labels share a net are shorted.
    let mut labelled: Vec<(NetId, usize)> = Vec::new();
    for (index, pin) in spec.pins.iter().enumerate() {
        let mut nets: Vec<NetId> = loaded
            .strings
            .get(&pin.name)
            .map_or(&[][..], |id| extracted.ports.nets_of(id))
            .to_vec();
        labelled.extend(nets.iter().map(|&net| (net, index)));
        if spec.substrate.as_deref() == Some(pin.name.as_str()) {
            nets.extend(&substrate);
        }
        nets.sort_unstable();
        nets.dedup();
        if nets.is_empty() {
            let hint = if spec.substrate.as_deref() == Some(pin.name.as_str()) {
                ", and the deck declares no substrate geometry"
            } else {
                ""
            };
            return Err(CircuitError::MissingPin(pin.name.clone(), hint));
        }
        out.push(nets);
    }
    labelled.sort_unstable();
    if let Some(pair) = labelled.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        let (first, second) = (&spec.pins[pair[0].1].name, &spec.pins[pair[1].1].name);
        return Err(CircuitError::ShortedPins(first.clone(), second.clone()));
    }
    Ok(out)
}

/// Every net holding a shape on a global (substrate) layer, ascending.
fn substrate_nets(loaded: &Loaded, extracted: &Extracted) -> Vec<NetId> {
    let mut nets: Vec<NetId> = loaded
        .deck
        .connectivity
        .global
        .iter()
        .filter(|layer| layer.idx() < loaded.store.layer_count())
        .flat_map(|&layer| loaded.store.polys_on_layer(layer))
        .map(|row| extracted.nets.net_of(PolyId(row)))
        .filter(|&net| net != NetId::NONE)
        .collect();
    nets.sort_unstable();
    nets.dedup();
    nets
}

/// Disjoint-set over proto nodes; the smallest member is the root, so the
/// final numbering does not depend on union order.
struct Union(Vec<u32>);

impl Union {
    fn find(&mut self, mut x: u32) -> u32 {
        while self.0[x as usize] != x {
            let parent = self.0[x as usize];
            self.0[x as usize] = self.0[parent as usize];
            x = parent;
        }
        x
    }

    fn join(&mut self, a: u32, b: u32) {
        let (a, b) = (self.find(a), self.find(b));
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        self.0[hi as usize] = lo;
    }
}

/// Rectangles bucketed on a uniform grid; a rectangle over more than
/// [`BIG_CELLS`] cells is kept in a list every query scans instead.
struct RectIndex {
    cell: i64,
    buckets: BTreeMap<(i64, i64), Vec<u32>>,
    big: Vec<u32>,
}

const BIG_CELLS: i64 = 64;

impl RectIndex {
    fn new(cell: i64) -> Self {
        Self {
            cell: cell.max(1),
            buckets: BTreeMap::new(),
            big: Vec::new(),
        }
    }

    fn cells(&self, b: Bbox) -> (i64, i64, i64, i64) {
        (
            b.xlo.raw().div_euclid(self.cell),
            b.ylo.raw().div_euclid(self.cell),
            b.xhi.raw().div_euclid(self.cell),
            b.yhi.raw().div_euclid(self.cell),
        )
    }

    fn insert(&mut self, id: u32, b: Bbox) {
        let (x0, y0, x1, y1) = self.cells(b);
        if (x1 - x0 + 1) * (y1 - y0 + 1) > BIG_CELLS {
            self.big.push(id);
            return;
        }
        for gx in x0..=x1 {
            for gy in y0..=y1 {
                self.buckets.entry((gx, gy)).or_default().push(id);
            }
        }
    }

    /// Every id whose cells meet `b`'s, each once, ascending.
    fn query(&self, b: Bbox, out: &mut Vec<u32>) {
        out.clear();
        let (x0, y0, x1, y1) = self.cells(b);
        for gx in x0..=x1 {
            for gy in y0..=y1 {
                if let Some(ids) = self.buckets.get(&(gx, gy)) {
                    out.extend_from_slice(ids);
                }
            }
        }
        out.extend_from_slice(&self.big);
        out.sort_unstable();
        out.dedup();
    }
}

/// Lengths along x and y two boxes share; negative is a gap.
fn shared(a: Bbox, b: Bbox) -> (i64, i64) {
    (
        a.xhi.raw().min(b.xhi.raw()) - a.xlo.raw().max(b.xlo.raw()),
        a.yhi.raw().min(b.yhi.raw()) - a.ylo.raw().max(b.ylo.raw()),
    )
}

/// How much of `b` a rectangle `a` touches or covers: zero when they are apart
/// or meet at a corner.
fn contact(a: Bbox, b: Bbox) -> i64 {
    let (x, y) = shared(a, b);
    if x < 0 || y < 0 || (x == 0 && y == 0) {
        0
    } else {
        x + y
    }
}

fn gap2(a: Bbox, b: Bbox) -> i128 {
    let (x, y) = shared(a, b);
    let (dx, dy) = (i128::from((-x).max(0)), i128::from((-y).max(0)));
    dx * dx + dy * dy
}

#[expect(clippy::cast_precision_loss, reason = "coordinates are below 2^40")]
fn as_f64(v: i64) -> f64 {
    v as f64
}

/// Builds the circuit for `spec` from the extraction, with wires as
/// `wires` says.
///
/// The result is deterministic: node numbers do not depend on hash or union
/// order.
///
/// # Errors
///
/// [`CircuitError::MissingPin`] for a spec pin with no net, and for
/// [`Wires::Distributed`] also [`CircuitError::Geometry`] and
/// [`CircuitError::Disconnected`].
pub fn build(
    loaded: &Loaded,
    extracted: &Extracted,
    spec: &MacroSpec,
    wires: Wires<'_>,
) -> Result<Circuit, CircuitError> {
    let pin_nets = pin_nets(loaded, extracted, spec)?;
    let mut builder = Builder::new(loaded, extracted);
    if let Wires::Distributed { analytical, field } = wires {
        builder.rectangles()?;
        builder.resistors();
        builder.overlaps();
        builder.vias();
        builder.ground_caps();
        builder.couplings(analytical)?;
        if let Some(field) = field {
            builder.calibrate(field);
        }
    }
    builder.devices();
    if matches!(wires, Wires::Distributed { .. }) {
        builder.connected()?;
    }
    Ok(builder.finish(spec, &pin_nets))
}

struct Builder<'a> {
    loaded: &'a Loaded,
    extracted: &'a Extracted,
    um: f64,
    rect: Vec<Bbox>,
    rect_layer: Vec<LayerId>,
    rect_net: Vec<NetId>,
    /// Same-net perimeter each rectangle shares with a neighbour, dbu.
    rect_shared: Vec<i64>,
    /// Rectangles per net.
    net_rects: Vec<Vec<u32>>,
    index: BTreeMap<LayerId, RectIndex>,
    /// One proto node per net with no rectangle, lazily.
    hub: Vec<u32>,
    union: Union,
    resistors: Vec<(u32, u32, f64)>,
    caps: BTreeMap<(u32, u32), f64>,
    devices: Vec<Device>,
}

const GROUND: u32 = 0;

impl<'a> Builder<'a> {
    fn new(loaded: &'a Loaded, extracted: &'a Extracted) -> Self {
        let nets = extracted.nets.net_count();
        #[expect(clippy::cast_precision_loss, reason = "a resolution is a small count")]
        let um = 1e-6 / loaded.grid.dbu_per_um() as f64;
        Self {
            loaded,
            extracted,
            um,
            rect: Vec::new(),
            rect_layer: Vec::new(),
            rect_net: Vec::new(),
            rect_shared: Vec::new(),
            net_rects: vec![Vec::new(); nets],
            index: BTreeMap::new(),
            hub: vec![u32::MAX; nets],
            union: Union(vec![GROUND]),
            resistors: Vec::new(),
            caps: BTreeMap::new(),
            devices: Vec::new(),
        }
    }

    fn grid(&self) -> Grid {
        self.loaded.grid
    }

    fn proto(&mut self) -> u32 {
        let id = u32::try_from(self.union.0.len()).expect("a node id is a u32");
        self.union.0.push(id);
        id
    }

    /// The proto node of rectangle `r`.
    const fn rect_node(r: u32) -> u32 {
        r + 1
    }

    /// The node a net is represented by when nothing more specific is known:
    /// its largest rectangle, or its hub.
    fn anchor(&mut self, net: NetId) -> u32 {
        let rects = &self.net_rects[net.idx()];
        if let Some(&best) = rects
            .iter()
            .max_by_key(|&&r| (self.rect[r as usize].area().raw(), std::cmp::Reverse(r)))
        {
            return Self::rect_node(best);
        }
        if self.hub[net.idx()] == u32::MAX {
            self.hub[net.idx()] = self.proto();
        }
        self.hub[net.idx()]
    }

    fn stack_row(&self, layer: LayerId) -> Option<usize> {
        (layer.idx() < self.loaded.deck.stack.sheet_res_ohm_sq.len()).then_some(layer.idx())
    }

    /// Cut every conductor polygon into rectangles; one proto node each.
    fn rectangles(&mut self) -> Result<(), CircuitError> {
        let store = &self.loaded.store;
        let mut layer = ValidatedLayer::default();
        let (mut rects, mut start) = (Vec::new(), Vec::new());
        let cell = 4 * self.grid().dbu_per_um();
        for &conductor in &self.loaded.deck.connectivity.conductors {
            if conductor.idx() >= store.layer_count() || store.polys_on_layer(conductor).is_empty()
            {
                continue;
            }
            validate_layer_into(store, conductor, &mut layer).map_err(|why| {
                let name = self.loaded.deck.layers.name(conductor);
                CircuitError::Geometry(
                    self.loaded.strings.resolve(name).to_owned(),
                    why.to_string(),
                )
            })?;
            decompose_into(&layer, &mut rects, &mut start);
            let mut index = RectIndex::new(cell);
            for poly in 0..layer.len() {
                let row = layer
                    .get(u32::try_from(poly).expect("a poly index is a u32"))
                    .provenance();
                let net = self.extracted.nets.net_of(row);
                if net == NetId::NONE {
                    continue;
                }
                for &r in &rects[start[poly] as usize..start[poly + 1] as usize] {
                    let id = u32::try_from(self.rect.len()).expect("a rect id is a u32");
                    let node = self.proto();
                    debug_assert_eq!(node, Self::rect_node(id));
                    self.rect.push(r);
                    self.rect_layer.push(conductor);
                    self.rect_net.push(net);
                    self.rect_shared.push(0);
                    self.net_rects[net.idx()].push(id);
                    index.insert(id, r);
                }
            }
            self.index.insert(conductor, index);
        }
        Ok(())
    }

    /// Sheet resistance across every edge two same-layer rectangles share.
    fn resistors(&mut self) {
        let layers: Vec<LayerId> = self.index.keys().copied().collect();
        for layer in layers {
            let rho = self
                .stack_row(layer)
                .map_or(0.0, |row| self.loaded.deck.stack.sheet_res_ohm_sq[row]);
            let ids: Vec<u32> = (0..self.rect.len())
                .filter(|&r| self.rect_layer[r] == layer)
                .map(|r| u32::try_from(r).expect("a rect id is a u32"))
                .collect();
            for vertical in [true, false] {
                // (coordinate, side, low, high, id): side 0 ends there, 1 starts.
                let mut sides: Vec<(i64, u8, i64, i64, u32)> = Vec::with_capacity(2 * ids.len());
                for &id in &ids {
                    let b = self.rect[id as usize];
                    let (lo_side, hi_side, lo, hi) = if vertical {
                        (b.xlo.raw(), b.xhi.raw(), b.ylo.raw(), b.yhi.raw())
                    } else {
                        (b.ylo.raw(), b.yhi.raw(), b.xlo.raw(), b.xhi.raw())
                    };
                    sides.push((hi_side, 0, lo, hi, id));
                    sides.push((lo_side, 1, lo, hi, id));
                }
                sides.sort_unstable();
                for run in sides.chunk_by(|a, b| a.0 == b.0) {
                    let split = run.partition_point(|s| s.1 == 0);
                    let (ending, starting) = run.split_at(split);
                    let (mut i, mut j) = (0, 0);
                    while i < ending.len() && j < starting.len() {
                        let (a, b) = (ending[i], starting[j]);
                        let overlap = a.3.min(b.3) - a.2.max(b.2);
                        if overlap > 0 {
                            self.join_rects(a.4, b.4, overlap, rho, vertical);
                        }
                        if a.3 < b.3 {
                            i += 1;
                        } else {
                            j += 1;
                        }
                    }
                }
            }
        }
    }

    /// Two same-net rectangles that overlap, from shapes drawn over each
    /// other, are one piece of metal: their nodes are joined. The resistance
    /// across the overlap is dropped, slightly optimistic and never an open.
    fn overlaps(&mut self) {
        let mut found = Vec::new();
        for r in 0..self.rect.len() {
            let Some(index) = self.index.get(&self.rect_layer[r]) else {
                continue;
            };
            index.query(self.rect[r], &mut found);
            for &other in &found {
                let o = other as usize;
                if o <= r || self.rect_net[o] != self.rect_net[r] {
                    continue;
                }
                let (x, y) = shared(self.rect[r], self.rect[o]);
                if x > 0 && y > 0 {
                    let a = Self::rect_node(u32::try_from(r).expect("a rect id is a u32"));
                    self.union.join(a, Self::rect_node(other));
                }
            }
        }
    }

    /// Every net with rectangles must be one piece through its resistors
    /// and joins, or some terminal on it would float in simulation.
    fn connected(&self) -> Result<(), CircuitError> {
        let mut pieces = Union(self.union.0.clone());
        for &(a, b, _) in &self.resistors {
            pieces.join(a, b);
        }
        for (net, rects) in self.net_rects.iter().enumerate() {
            let mut roots: Vec<u32> = rects
                .iter()
                .map(|&r| pieces.find(Self::rect_node(r)))
                .collect();
            roots.sort_unstable();
            roots.dedup();
            if roots.len() > 1 {
                let net = NetId(u32::try_from(net).expect("a net id is a u32"));
                let name = self.extracted.ports.name_of(net).map_or_else(
                    || format!("#{}", net.0),
                    |n| self.loaded.strings.resolve(n).to_owned(),
                );
                return Err(CircuitError::Disconnected(name, roots.len()));
            }
        }
        Ok(())
    }

    fn join_rects(&mut self, a: u32, b: u32, overlap: i64, rho: f64, vertical: bool) {
        if self.rect_net[a as usize] != self.rect_net[b as usize] {
            return;
        }
        self.rect_shared[a as usize] += overlap;
        self.rect_shared[b as usize] += overlap;
        let half_squares = |r: u32| {
            let bb = self.rect[r as usize];
            let (along, across) = if vertical {
                (bb.width().raw(), bb.height().raw())
            } else {
                (bb.height().raw(), bb.width().raw())
            };
            as_f64(along) / (2.0 * as_f64(across))
        };
        let ohms = rho * (half_squares(a) + half_squares(b));
        self.resistor(Self::rect_node(a), Self::rect_node(b), ohms);
    }

    fn resistor(&mut self, a: u32, b: u32, ohms: f64) {
        if ohms > 0.0 && ohms.is_finite() {
            self.resistors.push((a, b, ohms));
        } else {
            self.union.join(a, b);
        }
    }

    /// One resistor per via cut, between the rectangles it lands on.
    fn vias(&mut self) {
        let store = &self.loaded.store;
        let connectivity = &self.loaded.deck.connectivity;
        let mut found = Vec::new();
        for (row, &cut) in connectivity.via_cut.iter().enumerate() {
            if cut.idx() >= store.layer_count() {
                continue;
            }
            let per_cut = self
                .stack_row(cut)
                .map_or(0.0, |r| self.loaded.deck.stack.sheet_res_ohm_sq[r]);
            let (lower, upper) = connectivity.via_connects[row];
            for poly in store.polys_on_layer(cut) {
                let b = store.poly_bbox(PolyId(poly));
                let mut ends = [None, None];
                for (slot, layer) in ends.iter_mut().zip([lower, upper]) {
                    let Some(index) = self.index.get(&layer) else {
                        continue;
                    };
                    index.query(b, &mut found);
                    *slot = found
                        .iter()
                        .copied()
                        .filter(|&r| {
                            let (x, y) = shared(self.rect[r as usize], b);
                            x > 0 && y > 0
                        })
                        .max_by_key(|&r| {
                            let (x, y) = shared(self.rect[r as usize], b);
                            (i128::from(x) * i128::from(y), std::cmp::Reverse(r))
                        });
                }
                let net_of = |slot: Option<u32>| slot.map(|r| self.rect_net[r as usize]);
                match ends {
                    [Some(a), Some(b)] if net_of(Some(a)) == net_of(Some(b)) => {
                        self.resistor(Self::rect_node(a), Self::rect_node(b), per_cut);
                    }
                    // One plate is substrate, which has no rectangles: the cut
                    // lands on the net's hub.
                    [Some(a), None] | [None, Some(a)] => {
                        let net = self.rect_net[a as usize];
                        let hub = self.anchor_hub(net);
                        self.resistor(Self::rect_node(a), hub, per_cut);
                    }
                    _ => {}
                }
            }
        }
    }

    /// A net's hub even when it has rectangles: substrate contacts meet there.
    fn anchor_hub(&mut self, net: NetId) -> u32 {
        if self.hub[net.idx()] == u32::MAX {
            self.hub[net.idx()] = self.proto();
        }
        self.hub[net.idx()]
    }

    /// Per rectangle: area not over a channel, and unshared perimeter.
    fn ground_caps(&mut self) {
        let store = &self.loaded.store;
        let stack = &self.loaded.deck.stack;
        let devices = &self.extracted.devices;
        let mut channels = RectIndex::new(4 * self.grid().dbu_per_um());
        for d in 0..devices.len() {
            if devices.kind[d] == DeviceKind::Mos {
                channels.insert(
                    u32::try_from(d).expect("a device id is a u32"),
                    store.poly_bbox(devices.marker[d]),
                );
            }
        }
        let mut found = Vec::new();
        let um = self.um * 1e6;
        for r in 0..self.rect.len() {
            let Some(row) = self.stack_row(self.rect_layer[r]) else {
                continue;
            };
            let (area_af, fringe_af) = (stack.area_cap_af_um2[row], stack.fringe_cap_af_um[row]);
            if area_af <= 0.0 && fringe_af <= 0.0 {
                continue;
            }
            let b = self.rect[r];
            channels.query(b, &mut found);
            let covered: i128 = found
                .iter()
                .map(|&d| {
                    let (x, y) = shared(b, store.poly_bbox(devices.marker[d as usize]));
                    i128::from(x.max(0)) * i128::from(y.max(0))
                })
                .sum();
            #[expect(clippy::cast_precision_loss, reason = "an area below 2^80 dbu^2")]
            let area = (b.area().raw() - covered).max(0) as f64 * um * um;
            let perimeter =
                as_f64((2 * (b.width().raw() + b.height().raw()) - self.rect_shared[r]).max(0))
                    * um;
            let farads = (area_af * area + fringe_af * perimeter) * 1e-18;
            let node = Self::rect_node(u32::try_from(r).expect("a rect id is a u32"));
            self.cap(node, GROUND, farads);
        }
    }

    fn cap(&mut self, a: u32, b: u32, farads: f64) {
        if farads > 0.0 && farads.is_finite() && a != b {
            let key = if a < b { (a, b) } else { (b, a) };
            *self.caps.entry(key).or_insert(0.0) += farads;
        }
    }

    /// The analytical extractor's coupling, each between the closest pair of
    /// rectangles of the two regions it was measured between.
    fn couplings(&mut self, analytical: &ParasiticNetwork) -> Result<(), CircuitError> {
        let rects_of = self.node_rects(analytical)?;
        for row in 0..analytical.element_count() {
            let (Parasitic::CouplingCap(q), Some(to)) = (analytical.value[row], analytical.to[row])
            else {
                continue;
            };
            let from = analytical.from[row];
            // Diffusions and wells couple through junctions, the models' job.
            let layer = |node: NodeId| analytical.node_layer[node.0 as usize];
            if !self.is_wire(layer(from)) || !self.is_wire(layer(to)) {
                continue;
            }
            let rects = |node: NodeId| &rects_of[node.0 as usize][..];
            if let Some((a, b)) = self.closest(rects(from), rects(to)) {
                self.cap(Self::rect_node(a), Self::rect_node(b), q.raw() * 1e-15);
            }
        }
        Ok(())
    }

    /// This circuit's rectangles in each analytical node's region, by
    /// [`NodeId`]: those of the node's net and layer that share area with one
    /// of the region's rectangles. A drawn rectangle lies in one region, the
    /// edge-connected piece its interior is in.
    fn node_rects(&self, analytical: &ParasiticNetwork) -> Result<Vec<Vec<u32>>, CircuitError> {
        let loaded = self.loaded;
        let regions = gpurify_extract::analytical::node_rects(
            &loaded.store,
            &self.extracted.nets,
            &loaded.deck.connectivity,
        )
        .map_err(|why| {
            let name = loaded.deck.layers.name(why.layer());
            CircuitError::Geometry(loaded.strings.resolve(name).to_owned(), why.to_string())
        })?;
        let mut out = vec![Vec::new(); analytical.node_count()];
        let mut found = Vec::new();
        for (node, region) in regions {
            let node = node.0 as usize;
            let Some(index) = self.index.get(&analytical.node_layer[node]) else {
                continue;
            };
            index.query(region, &mut found);
            let net = analytical.node_net[node];
            out[node].extend(found.iter().copied().filter(|&r| {
                let (x, y) = shared(self.rect[r as usize], region);
                self.rect_net[r as usize] == net && x > 0 && y > 0
            }));
        }
        for rects in &mut out {
            rects.sort_unstable();
            rects.dedup();
        }
        Ok(out)
    }

    /// Whether the stack gives `layer` wire capacitance.
    fn is_wire(&self, layer: LayerId) -> bool {
        let stack = &self.loaded.deck.stack;
        self.stack_row(layer).is_some_and(|row| {
            stack.area_cap_af_um2[row] > 0.0 || stack.fringe_cap_af_um[row] > 0.0
        })
    }

    /// The closest pair, one of `ps` and one of `qs`; the first such pair in
    /// rectangle order on a tie.
    fn closest(&self, ps: &[u32], qs: &[u32]) -> Option<(u32, u32)> {
        let mut best: Option<(i128, u32, u32)> = None;
        for &a in ps {
            for &b in qs {
                let d = gap2(self.rect[a as usize], self.rect[b as usize]);
                if best.is_none_or(|(bd, ..)| d < bd) {
                    best = Some((d, a, b));
                }
            }
        }
        best.map(|(_, a, b)| (a, b))
    }

    /// Rescale each solved net's ground, and each solved pair's coupling, to
    /// the field solve's totals.
    fn calibrate(&mut self, field: &ParasiticNetwork) {
        let rect_net_of_node = |builder: &Self, node: u32| -> Option<NetId> {
            let r = node.checked_sub(1)? as usize;
            builder.rect_net.get(r).copied()
        };
        let solved: Vec<bool> = {
            let mut s = vec![false; self.net_rects.len()];
            for net in &field.node_net {
                if let Some(slot) = s.get_mut(net.idx()) {
                    *slot = true;
                }
            }
            s
        };
        let mut target_ground: BTreeMap<NetId, f64> = BTreeMap::new();
        let mut target_pair: BTreeMap<(NetId, NetId), f64> = BTreeMap::new();
        for row in 0..field.element_count() {
            let from = field.node_net[field.from[row].0 as usize];
            match (field.value[row], field.to[row]) {
                (Parasitic::GroundCap(q), None) => {
                    *target_ground.entry(from).or_insert(0.0) += q.raw().max(0.0) * 1e-15;
                }
                (Parasitic::CouplingCap(q), Some(to)) => {
                    let to = field.node_net[to.0 as usize];
                    let key = if from < to { (from, to) } else { (to, from) };
                    *target_pair.entry(key).or_insert(0.0) += q.raw().max(0.0) * 1e-15;
                }
                _ => {}
            }
        }
        // Current totals, by the same keys.
        let mut have_ground: BTreeMap<NetId, f64> = BTreeMap::new();
        let mut have_pair: BTreeMap<(NetId, NetId), f64> = BTreeMap::new();
        for (&(a, b), &f) in &self.caps {
            let (na, nb) = (rect_net_of_node(self, a), rect_net_of_node(self, b));
            match (na, nb, a == GROUND) {
                (_, Some(n), true) => *have_ground.entry(n).or_insert(0.0) += f,
                (Some(x), Some(y), false) if x != y => {
                    let key = if x < y { (x, y) } else { (y, x) };
                    *have_pair.entry(key).or_insert(0.0) += f;
                }
                _ => {}
            }
        }
        let keys: Vec<(u32, u32)> = self.caps.keys().copied().collect();
        for (a, b) in keys {
            let (na, nb) = (rect_net_of_node(self, a), rect_net_of_node(self, b));
            let scale = match (na, nb, a == GROUND) {
                (_, Some(n), true) if solved[n.idx()] => {
                    Some(target_ground.get(&n).copied().unwrap_or(0.0) / have_ground[&n])
                }
                (Some(x), Some(y), false) if x != y && solved[x.idx()] && solved[y.idx()] => {
                    let key = if x < y { (x, y) } else { (y, x) };
                    Some(target_pair.get(&key).copied().unwrap_or(0.0) / have_pair[&key])
                }
                _ => None,
            };
            if let Some(scale) = scale.filter(|s| s.is_finite()) {
                *self.caps.get_mut(&(a, b)).expect("a key just listed") *= scale;
            }
        }
        // Solved capacitance with nothing analytical to carry it: on anchors.
        for (&net, &f) in &target_ground {
            if !have_ground.contains_key(&net) && net.idx() < self.net_rects.len() {
                let node = self.anchor(net);
                self.cap(node, GROUND, f);
            }
        }
        for (&(x, y), &f) in &target_pair {
            if !have_pair.contains_key(&(x, y))
                && x.idx() < self.net_rects.len()
                && y.idx() < self.net_rects.len()
            {
                let (a, b) = (self.anchor(x), self.anchor(y));
                self.cap(a, b, f);
            }
        }
    }

    /// Cards for every recognised device, terminals on the rectangles that
    /// touch their channel, parameters as topology measured them.
    fn devices(&mut self) {
        let loaded = self.loaded;
        let store = &loaded.store;
        let table = &self.extracted.devices;
        let recognisers = &loaded.deck.devices;
        // Source/drain layers of every MOS recogniser.
        let mut sd_layers: Vec<LayerId> = Vec::new();
        for row in 0..recognisers.kind.len() {
            if recognisers.kind[row] == DeviceKind::Mos {
                let (s, e) = (
                    recognisers.terminal_start[row] as usize,
                    recognisers.terminal_start[row + 1] as usize,
                );
                sd_layers.extend(recognisers.terminal[s..e].iter().skip(1).take(2));
            }
        }
        sd_layers.sort_unstable();
        sd_layers.dedup();
        let mut sd_index = RectIndex::new(4 * self.grid().dbu_per_um());
        let mut sd_polys: Vec<PolyId> = Vec::new();
        for &layer in &sd_layers {
            if layer.idx() < store.layer_count() {
                for row in store.polys_on_layer(layer) {
                    let id = u32::try_from(sd_polys.len()).expect("a poly count is a u32");
                    sd_polys.push(PolyId(row));
                    sd_index.insert(id, store.poly_bbox(PolyId(row)));
                }
            }
        }
        let mut channels = RectIndex::new(4 * self.grid().dbu_per_um());
        let mut markers: Vec<Bbox> = Vec::new();
        for d in 0..table.len() {
            if table.kind[d] == DeviceKind::Mos {
                let id = u32::try_from(markers.len()).expect("a device count is a u32");
                markers.push(store.poly_bbox(table.marker[d]));
                channels.insert(id, store.poly_bbox(table.marker[d]));
            }
        }
        // Per MOS: the diffusion polygons its channel abuts, for `sa` and `sb`.
        let mut found = Vec::new();
        let mut touching: Vec<Vec<u32>> = vec![Vec::new(); table.len()];
        for (d, touches) in touching.iter_mut().enumerate() {
            if table.kind[d] != DeviceKind::Mos {
                continue;
            }
            let m = store.poly_bbox(table.marker[d]);
            sd_index.query(m, &mut found);
            for &p in &found {
                if contact(store.poly_bbox(sd_polys[p as usize]), m) > 0 {
                    touches.push(p);
                }
            }
        }

        for (d, touches) in touching.iter().enumerate() {
            let id = DeviceId(u32::try_from(d).expect("a device id is a u32"));
            let (nets, roles) = table.terminals_of(id);
            let marker = store.poly_bbox(table.marker[d]);
            let mut card: Vec<(u8, NetId, TerminalRole)> = roles
                .iter()
                .zip(nets)
                .map(|(&role, &net)| (card_rank(role), net, role))
                .collect();
            card.sort_by_key(|&(rank, ..)| rank);
            let mut device = Device {
                kind: table.kind[d],
                model: loaded.strings.resolve(table.model[d]).to_owned(),
                nodes: Vec::with_capacity(card.len()),
                nets: card.iter().map(|&(_, net, _)| net).collect(),
                roles: card.iter().map(|&(.., role)| role).collect(),
                params: Vec::new(),
            };
            for &(_, net, role) in &card {
                let node = match role {
                    TerminalRole::Bulk => self.anchor(net),
                    _ => self.touching_node(net, marker),
                };
                device.nodes.push(node);
            }
            for &(param, measure) in table.params_of(id) {
                // A MOS's area and perimeter are its diffusions', which
                // topology measured as LVS compares them (testing-plan F100);
                // a bipolar's emitter measures are no ngspice instance
                // parameter.
                let key = match (device.kind, param) {
                    (DeviceKind::Mos, DeviceParam::Area | DeviceParam::Perimeter)
                    | (_, DeviceParam::EmitterArea | DeviceParam::EmitterPerimeter) => continue,
                    (_, DeviceParam::SourceArea) => "as",
                    (_, DeviceParam::DrainArea) => "ad",
                    (_, DeviceParam::SourcePerimeter) => "ps",
                    (_, DeviceParam::DrainPerimeter) => "pd",
                    (_, DeviceParam::Width) => "w",
                    (_, DeviceParam::Length) => "l",
                    (_, DeviceParam::Fingers) => "nf",
                    (DeviceKind::Diode, DeviceParam::Perimeter) => "pj",
                    (_, DeviceParam::Perimeter) => "perim",
                    (_, DeviceParam::Area) => "area",
                };
                #[expect(clippy::cast_precision_loss, reason = "a device area below 2^80")]
                let value = match measure {
                    DeviceMeasure::Length(v) => Param::Length(as_f64(v.raw()) * self.um),
                    DeviceMeasure::Area(v) => Param::Area(v.raw() as f64 * self.um * self.um),
                    DeviceMeasure::Count(n) => Param::Count(n),
                    DeviceMeasure::LengthShare(v, ways) => {
                        Param::Length(as_f64(v.raw()) * self.um / f64::from(ways))
                    }
                    DeviceMeasure::AreaShare(v, ways) => {
                        Param::Area(v.raw() as f64 * self.um * self.um / f64::from(ways))
                    }
                };
                device.params.push((key, value));
            }
            if device.kind == DeviceKind::Mos {
                let active = Active {
                    store,
                    sd_index: &sd_index,
                    sd_polys: &sd_polys,
                    channels: &channels,
                    markers: &markers,
                };
                if let Some((sa, sb)) = active.lod(marker, touches) {
                    device
                        .params
                        .push(("sa", Param::Length(as_f64(sa) * self.um)));
                    device
                        .params
                        .push(("sb", Param::Length(as_f64(sb) * self.um)));
                }
            }
            self.devices.push(device);
        }
    }

    /// The rectangle of `net` touching `marker` most; the net's anchor if none.
    fn touching_node(&mut self, net: NetId, marker: Bbox) -> u32 {
        let mut found = Vec::new();
        let mut best: Option<(i64, std::cmp::Reverse<u32>)> = None;
        for index in self.index.values() {
            index.query(marker, &mut found);
            for &r in &found {
                if self.rect_net[r as usize] != net {
                    continue;
                }
                let c = contact(self.rect[r as usize], marker);
                let key = (c, std::cmp::Reverse(r));
                if c > 0 && best.is_none_or(|b| key > b) {
                    best = Some(key);
                }
            }
        }
        match best {
            Some((_, std::cmp::Reverse(r))) => Self::rect_node(r),
            None => self.anchor(net),
        }
    }

    /// The pin's node: the rectangle under its label, else its net's anchor.
    fn pin_node(&mut self, pin: &str, nets: &[NetId]) -> u32 {
        let loaded = self.loaded;
        let connectivity = &loaded.deck.connectivity;
        let name = loaded.strings.get(pin);
        let mut best: Option<(bool, std::cmp::Reverse<u32>)> = None;
        for label in loaded
            .provenance
            .placed()
            .iter()
            .filter(|l| Some(l.name) == name)
        {
            let at = Bbox::point(label.at.x, label.at.y);
            let named = connectivity
                .label_layer
                .iter()
                .position(|&l| l == label.layer)
                .map(|row| connectivity.label_names[row]);
            for &net in nets {
                for &r in &self.net_rects[net.idx()] {
                    let (x, y) = shared(self.rect[r as usize], at);
                    if x >= 0 && y >= 0 {
                        let key = (
                            named == Some(self.rect_layer[r as usize]),
                            std::cmp::Reverse(r),
                        );
                        if best.is_none_or(|b| key > b) {
                            best = Some(key);
                        }
                    }
                }
            }
        }
        match best {
            Some((_, std::cmp::Reverse(r))) => Self::rect_node(r),
            None => self.anchor(nets[0]),
        }
    }

    fn finish(mut self, spec: &MacroSpec, pin_nets: &[Vec<NetId>]) -> Circuit {
        // Every net is one node unless distributed; a pin's nets are one node.
        let net_count = self.net_rects.len();
        for net in 0..net_count {
            let net = NetId(u32::try_from(net).expect("a net id is a u32"));
            let rects = self.net_rects[net.idx()].clone();
            if rects.is_empty() {
                continue;
            }
            if self.hub[net.idx()] != u32::MAX {
                // A hub beside rectangles is reached through via resistors only;
                // a hub nothing reached is joined to the anchor.
                let reached = self
                    .resistors
                    .iter()
                    .any(|&(a, b, _)| a == self.hub[net.idx()] || b == self.hub[net.idx()]);
                if !reached {
                    let anchor = self.anchor(net);
                    self.union.join(self.hub[net.idx()], anchor);
                }
            }
        }
        let mut pin_node = Vec::with_capacity(pin_nets.len());
        for (pin, nets) in spec.pins.iter().zip(pin_nets) {
            let node = self.pin_node(&pin.name, nets);
            for &net in &nets[1..] {
                let other = self.anchor(net);
                self.union.join(node, other);
            }
            pin_node.push(node);
        }
        // Renumber roots densely, in proto order, ground first.
        let total = self.union.0.len();
        let mut dense = vec![u32::MAX; total];
        let mut next = 0u32;
        for proto in 0..total {
            let root = self
                .union
                .find(u32::try_from(proto).expect("a proto id is a u32"));
            if dense[root as usize] == u32::MAX {
                dense[root as usize] = next;
                next += 1;
            }
        }
        let map = |union: &mut Union, node: u32| dense[union.find(node) as usize];
        let mut circuit = Circuit {
            node_count: next,
            ..Circuit::default()
        };
        for &(a, b, ohms) in &self.resistors {
            let (a, b) = (map(&mut self.union, a), map(&mut self.union, b));
            if a != b {
                circuit.resistors.push((a, b, ohms));
            }
        }
        let caps: Vec<((u32, u32), f64)> = self.caps.iter().map(|(&k, &v)| (k, v)).collect();
        let mut merged: BTreeMap<(u32, u32), f64> = BTreeMap::new();
        for ((a, b), f) in caps {
            let (a, b) = (map(&mut self.union, a), map(&mut self.union, b));
            if a != b {
                let key = if a < b { (b, a) } else { (a, b) };
                *merged.entry(key).or_insert(0.0) += f;
            }
        }
        circuit.capacitors = merged.into_iter().map(|((a, b), f)| (a, b, f)).collect();
        for mut device in std::mem::take(&mut self.devices) {
            for node in &mut device.nodes {
                *node = map(&mut self.union, *node);
            }
            circuit.devices.push(device);
        }
        circuit.pin_node = pin_node
            .into_iter()
            .map(|n| map(&mut self.union, n))
            .collect();
        circuit.pin_nets = pin_nets.to_vec();
        circuit
    }
}

/// The active region a channel sits in: its source/drain diffusions and the
/// other channels, which tile it between the isolation edges.
struct Active<'a> {
    store: &'a gpurify_geom::GeometryStore,
    sd_index: &'a RectIndex,
    sd_polys: &'a [PolyId],
    channels: &'a RectIndex,
    markers: &'a [Bbox],
}

impl Active<'_> {
    /// BSIM4 length-of-diffusion: the distance from each side of the gate to
    /// the isolation edge along the channel's centre line, walking across any
    /// diffusion and any other finger's channel in the way. `None` when the
    /// channel's direction cannot be told.
    ///
    /// ponytail: one centre line, by bounding boxes; an irregular active
    /// region wants the width-weighted `1/(SA + L/2)` average BSIM4 defines.
    fn lod(&self, gate: Bbox, touching: &[u32]) -> Option<(i64, i64)> {
        // Current flows across the edge a source/drain diffusion abuts.
        let along_x = touching.iter().any(|&p| {
            let b = self.store.poly_bbox(self.sd_polys[p as usize]);
            let (x, y) = shared(b, gate);
            x == 0 && y > 0
        });
        let along_y = touching.iter().any(|&p| {
            let b = self.store.poly_bbox(self.sd_polys[p as usize]);
            let (x, y) = shared(b, gate);
            y == 0 && x > 0
        });
        if along_x == along_y {
            return None;
        }
        // Coordinates along the channel (`a`) and across it (`c`).
        let axis = |b: Bbox| {
            if along_x {
                (b.xlo.raw(), b.xhi.raw(), b.ylo.raw(), b.yhi.raw())
            } else {
                (b.ylo.raw(), b.yhi.raw(), b.xlo.raw(), b.xhi.raw())
            }
        };
        let (lo, hi, c_lo, c_hi) = axis(gate);
        let centre = i64::midpoint(c_lo, c_hi);
        let mut found = Vec::new();
        let mut walk = |mut at: i64, outward: i64| -> i64 {
            // Each step lands on a box that starts where the last one ended.
            for _ in 0..1024 {
                let probe = if along_x {
                    Bbox::point(
                        gpurify_geom::Dbu::new_unchecked(at),
                        gpurify_geom::Dbu::new_unchecked(centre),
                    )
                } else {
                    Bbox::point(
                        gpurify_geom::Dbu::new_unchecked(centre),
                        gpurify_geom::Dbu::new_unchecked(at),
                    )
                };
                let mut next = None;
                self.sd_index.query(probe, &mut found);
                let diffusions = found
                    .iter()
                    .map(|&p| self.store.poly_bbox(self.sd_polys[p as usize]));
                let mut boxes: Vec<Bbox> = diffusions.collect();
                self.channels.query(probe, &mut found);
                boxes.extend(found.iter().map(|&m| self.markers[m as usize]));
                for b in boxes {
                    let (b_lo, b_hi, b_clo, b_chi) = axis(b);
                    if b_clo > centre || b_chi < centre {
                        continue;
                    }
                    if outward > 0 && b_lo == at && b_hi > at {
                        next = Some(next.map_or(b_hi, |n: i64| n.max(b_hi)));
                    }
                    if outward < 0 && b_hi == at && b_lo < at {
                        next = Some(next.map_or(b_lo, |n: i64| n.min(b_lo)));
                    }
                }
                match next {
                    Some(n) => at = n,
                    None => return at,
                }
            }
            at
        };
        let (left, right) = (walk(lo, -1), walk(hi, 1));
        Some((lo - left, right - hi))
    }
}

/// Where a terminal sits on its family's card: `d g s b`, `c b e`, pins in order.
const fn card_rank(role: TerminalRole) -> u8 {
    match role {
        TerminalRole::Drain | TerminalRole::Collector => 0,
        TerminalRole::Gate | TerminalRole::Base => 1,
        TerminalRole::Source | TerminalRole::Emitter => 2,
        TerminalRole::Bulk => 3,
        TerminalRole::Pin(position) => position,
    }
}
