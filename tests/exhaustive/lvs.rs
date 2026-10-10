//! LVS against an independent oracle: every small circuit, every single fault.
//!
//! A [`Circuit`] is devices on numbered nets. The [drawer](draw) turns one into
//! a real layout: a MOS is poly across diffusion under an implant, a passive a
//! marker over its terminal pads, and every terminal is contacted to a met1
//! stub that climbs to its net's met2 track, which carries the net's label when
//! the net is a port. The [SPICE writer](spice) turns one into a reference.
//!
//! The [oracle](equivalent) decides every verdict from the documented semantics
//! alone, never from the tool's code or output: two netlists match iff, after
//! the reductions of `docs/usage.md` ("LVS reduction"), a bijection of devices
//! and nets preserves kind, model and terminal incidence up to the
//! interchangeable roles, with every parameter within the 2 % relative
//! tolerance of `CompareOptions`. Net names never take part (the `lvs` module
//! docs), and neither does card order. It is a brute force over every net
//! bijection, which is affordable because the circuits are small.
//!
//! Where the docs describe a defect rather than the intended semantics, the
//! oracle follows the intended one and the fixture is marked with the finding:
//! parallel passives keep their count (F20); `m` multiplies a passive (F21); a
//! parameter is compared only where the reference declares it (F22); `nf=1` is
//! one drawn finger (F16). A diode's and a capacitor's ends are ordered (F15),
//! a series merge crosses a net that is not a port on either side (F12), and a
//! reference `X` instance is flattened (F1): those fixtures hold since B3, B4
//! and B2.
//!
//! The enumeration is every circuit of one to three `nmos`/`pmos` over one to
//! four nets, every net used, one per class under renaming nets and devices and
//! swapping source with drain: 4223 circuits. Each is compared with its own
//! reference, the same cards in reverse order, and the single faults of its
//! reference (one terminal moved, a model swapped, a device deleted or added,
//! two nets shorted, a net opened, `W` off by 1.9 % and 2.1 %, source and drain
//! swapped), deduplicated up to isomorphism. [`Depth::Merge`] takes a seeded
//! sample of the circuits with every fault; [`Depth::Nightly`] adds every
//! other circuit with every fault that must still match and one per kind that
//! must not (see [`fixtures`]). Curated fixtures cover what the enumeration
//! cannot reach: hierarchy, stacks, passives, polarity, bulk, flavours,
//! parameters and the layout-only rows.

use crate::harness::{Depth, Expect, Finding, Fixture, Layout, NONE};
use gpurify::engine::run::Checks;
use gpurify_testgen::Rng;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::OnceLock;

/// LVS alone.
const LVS: Checks = Checks { lvs: true, ..NONE };

/// The comparator's relative tolerance, `CompareOptions`'s documented default.
const TOLERANCE: f64 = 0.02;

/// `nmos` and `pmos` only: the deck of the enumeration, kept small because
/// every fixture owns a copy. `nmos` excludes the `hvt` implant, so the
/// flavour row of [`EXTRA_DECK`] splits it (catalog LVS-066).
const MOS_DECK: &str = "grid 1nm
layer diff = gds(1, 0)
layer poly = gds(2, 0)
layer nsdm = gds(3, 0)
layer psdm = gds(4, 0)
layer hvt = gds(5, 0)
layer cont = gds(8, 0)
layer met1 = gds(10, 0)
layer via1 = gds(11, 0)
layer met2 = gds(12, 0)
layer met2_label = gds(12, 5)
layer diff_active = diff not poly
layer gate = poly and diff
layer gate_n = gate and nsdm
layer gate_nl = gate_n not hvt
layer gate_p = gate and psdm
connect conductors [diff_active, poly, met1, met2]
connect touch_within_layer
connect via cont [diff_active, met1]
connect via cont [poly, met1]
connect via via1 [met1, met2]
connect label met2_label names met2
device mos gate_nl model \"nmos\" terminals [poly, diff_active, diff_active]
device mos gate_p model \"pmos\" terminals [poly, diff_active, diff_active]
";

/// Every other device: the `hvt` flavour, a MOS with a bulk terminal on
/// `pwell`, and one passive or bipolar per kind, each a marker over pads.
const EXTRA_DECK: &str = "layer bsdm = gds(6, 0)
layer pwell = gds(7, 0)
layer tap = gds(9, 0)
layer pina = gds(13, 0)
layer pinb = gds(14, 0)
layer pinc = gds(15, 0)
layer resm = gds(16, 0)
layer capm = gds(17, 0)
layer diom = gds(18, 0)
layer bjtm = gds(19, 0)
layer gate_nh = gate_n and hvt
layer gate_b = gate and bsdm
connect conductors [pwell, pina, pinb, pinc]
connect via cont [pina, met1]
connect via cont [pinb, met1]
connect via cont [pinc, met1]
connect via tap [pwell, met1]
device mos gate_nh model \"nmos_hvt\" terminals [poly, diff_active, diff_active]
device mos gate_b model \"nmosb\" terminals [poly, diff_active, diff_active, pwell]
device resistor resm model \"rpoly\" terminals [pina, pina]
device capacitor capm model \"cmim\" terminals [pina, pinb]
device diode diom model \"dpn\" terminals [pina, pinb]
device bjt bjtm model \"npn\" terminals [pina, pinb, pinc]
";

/// The deck of the curated fixtures.
fn full_deck() -> String {
    format!("{MOS_DECK}{EXTRA_DECK}")
}

// ---------------------------------------------------------------------------
// Circuits
// ---------------------------------------------------------------------------

/// A device's kind and model in one: the deck has one recogniser per model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Model {
    /// `nmos`: gate, source, drain.
    N,
    /// `pmos`.
    P,
    /// `nmos_hvt`, the `hvt` flavour of `nmos`.
    H,
    /// `nmosb`: gate, source, drain, bulk.
    B,
    /// `rpoly`: two interchangeable ends.
    R,
    /// `cmim`: plate 0, plate 1, ordered.
    C,
    /// `dpn`: anode, cathode, ordered.
    D,
    /// `npn`: base, emitter, collector, ordered.
    Q,
}

impl Model {
    fn is_mos(self) -> bool {
        matches!(self, Model::N | Model::P | Model::H | Model::B)
    }

    fn name(self) -> &'static str {
        match self {
            Model::N => "nmos",
            Model::P => "pmos",
            Model::H => "nmos_hvt",
            Model::B => "nmosb",
            Model::R => "rpoly",
            Model::C => "cmim",
            Model::D => "dpn",
            Model::Q => "npn",
        }
    }

    /// One letter, for fixture names and the cards of two-pin devices.
    fn letter(self) -> char {
        match self {
            Model::N => 'N',
            Model::P => 'P',
            Model::H => 'H',
            Model::B => 'B',
            Model::R => 'R',
            Model::C => 'C',
            Model::D => 'D',
            Model::Q => 'Q',
        }
    }
}

/// The marker area of every two-pin device, 800 x 400 nm, in nm².
const PIN2_AREA: i64 = 800 * 400;
/// The marker area of a bipolar, 1600 x 400 nm, in nm².
const BJT_AREA: i64 = 1600 * 400;

/// One device on numbered nets.
#[derive(Debug, Clone, PartialEq)]
struct Dev {
    model: Model,
    /// MOS: gate, source, drain, and bulk for [`Model::B`]; two-pin: the
    /// card's pin 0, pin 1; bipolar: base, emitter, collector.
    pins: Vec<usize>,
    /// Drawn or declared width and length in nm; MOS only.
    w: i64,
    l: i64,
    /// The card's `m`; 1 writes none.
    m: u32,
    /// An `area=` the card declares, in nm². The layout always has its
    /// marker's, and it is compared only where the reference declares one.
    area: Option<i64>,
}

impl Dev {
    /// A MOS of 1000 / 150 nm.
    fn mos(model: Model, g: usize, s: usize, d: usize) -> Self {
        Dev {
            model,
            pins: vec![g, s, d],
            w: 1000,
            l: 150,
            m: 1,
            area: None,
        }
    }

    /// A resistor, capacitor, diode or bipolar on `pins`.
    fn pins(model: Model, pins: &[usize]) -> Self {
        Dev {
            model,
            pins: pins.to_vec(),
            w: 0,
            l: 0,
            m: 1,
            area: None,
        }
    }

    fn sized(mut self, w: i64, l: i64) -> Self {
        self.w = w;
        self.l = l;
        self
    }

    fn bulk(mut self, net: usize) -> Self {
        self.pins.push(net);
        self
    }

    fn times(mut self, m: u32) -> Self {
        self.m = m;
        self
    }

    fn area(mut self, nm2: i64) -> Self {
        self.area = Some(nm2);
        self
    }
}

/// Devices on nets `0..names.len()`. A port is a labelled net in the layout and
/// a `.subckt` port in the reference.
#[derive(Debug, Clone, PartialEq)]
struct Circuit {
    devs: Vec<Dev>,
    names: Vec<String>,
    ports: Vec<bool>,
}

impl Circuit {
    /// Nets `n0..`, every one a port.
    fn new(nets: usize, devs: Vec<Dev>) -> Self {
        Circuit {
            devs,
            names: (0..nets).map(|i| format!("n{i}")).collect(),
            ports: vec![true; nets],
        }
    }

    /// The same circuit with `net` internal: unlabelled in the layout, not a
    /// port of the reference.
    fn internal(mut self, net: usize) -> Self {
        self.ports[net] = false;
        self
    }

    fn nets(&self) -> usize {
        self.names.len()
    }

    /// Drops every net no device touches, renumbering the rest in order.
    fn compact(mut self) -> Self {
        let mut used = vec![false; self.nets()];
        for dev in &self.devs {
            for &p in &dev.pins {
                used[p] = true;
            }
        }
        let mut map = vec![usize::MAX; used.len()];
        let mut next = 0;
        for (i, &u) in used.iter().enumerate() {
            if u {
                map[i] = next;
                next += 1;
            }
        }
        for p in self.devs.iter_mut().flat_map(|d| &mut d.pins) {
            *p = map[*p];
        }
        let mut k = 0;
        self.names.retain(|_| (used[k], k += 1).0);
        let mut k = 0;
        self.ports.retain(|_| (used[k], k += 1).0);
        self
    }

    /// A short code naming the circuit: `N0.1.2` per MOS (gate, source,
    /// drain), joined by `+`.
    fn code(&self) -> String {
        self.devs
            .iter()
            .map(|d| {
                let pins: Vec<String> = d.pins.iter().map(ToString::to_string).collect();
                format!("{}{}", d.model.letter(), pins.join("."))
            })
            .collect::<Vec<_>>()
            .join("+")
    }
}

// ---------------------------------------------------------------------------
// The drawer
// ---------------------------------------------------------------------------

/// Columns are this far apart; each device sits in its own.
const PITCH: i64 = 3000;
/// The lowest met2 track; every device fits below it.
const TRACK0: i64 = 4000;
/// Track spacing; tracks are 200 nm tall.
const TRACK_PITCH: i64 = 400;
/// Source and drain diffusion length.
const SD: i64 = 500;

fn track(net: usize) -> i64 {
    TRACK0 + TRACK_PITCH * i64::try_from(net).expect("few nets")
}

fn column(i: usize) -> i64 {
    PITCH * i64::try_from(i).expect("few devices")
}

/// A met1 stub from `y0` up to `net`'s track over `x0..x1`, with the via there.
fn stub(layout: Layout, x0: i64, x1: i64, y0: i64, net: usize) -> Layout {
    let t = track(net);
    layout
        .rect("met1", x0, y0, x1, t + 200)
        .rect("via1", x0, t, x1, t + 200)
}

/// The layout of `c`: device `i` in column `i`, net `k` a met2 track,
/// labelled with its name when it is a port.
fn draw(c: &Circuit) -> Layout {
    let mut layout = Layout::default();
    for (i, dev) in c.devs.iter().enumerate() {
        layout = if dev.model.is_mos() {
            draw_mos(layout, column(i), dev)
        } else {
            draw_pins(layout, column(i), dev)
        };
    }
    let right = column(c.devs.len());
    for k in 0..c.nets() {
        let t = track(k);
        layout = layout.rect("met2", -1000, t, right, t + 200);
        if c.ports[k] {
            layout = layout.label("met2_label", -900, t + 100, &c.names[k]);
        }
    }
    layout
}

/// Poly across diffusion: the channel is `l` along x and `w` along y, so the
/// recogniser measures exactly `w` and `l` (`DeviceParam`'s rustdoc). Source
/// left, drain right, each contacted near the bottom; the gate is contacted
/// on the poly above the diffusion.
fn draw_mos(layout: Layout, x0: i64, dev: &Dev) -> Layout {
    let (w, l) = (dev.w, dev.l);
    assert!(
        (500..=TRACK0 - 1000).contains(&w),
        "a width the drawer fits"
    );
    let xd = x0 + SD + l;
    let implant =
        |layout: Layout, layer: &str| layout.rect(layer, x0 - 200, -300, xd + SD + 200, w + 200);
    let mut layout =
        layout
            .rect("diff", x0, 0, xd + SD, w)
            .rect("poly", x0 + SD, -200, xd, w + 500);
    layout = match dev.model {
        Model::N => implant(layout, "nsdm"),
        Model::H => implant(implant(layout, "nsdm"), "hvt"),
        Model::P => implant(layout, "psdm"),
        Model::B => {
            let layout = implant(layout, "bsdm")
                .rect("pwell", x0 - 900, -400, xd + SD + 300, w + 300)
                .rect("tap", x0 - 700, 100, x0 - 400, 400);
            stub(layout, x0 - 700, x0 - 400, 100, dev.pins[3])
        }
        _ => unreachable!("not a MOS"),
    };
    layout = layout
        .rect("cont", x0 + 100, 100, x0 + 400, 400)
        .rect("cont", xd + 100, 100, xd + 400, 400)
        .rect("cont", x0 + SD, w + 250, xd, w + 400);
    layout = stub(layout, x0 + 100, x0 + 400, 100, dev.pins[1]);
    layout = stub(layout, xd + 100, xd + 400, 100, dev.pins[2]);
    stub(layout, x0 + SD, xd, w + 250, dev.pins[0])
}

/// The pad of pin `k` of a device in the column at `x0`.
fn pad(x0: i64, k: usize) -> (i64, i64, i64, i64) {
    let x = x0 + 800 * i64::try_from(k).expect("three pins at most");
    (x, 0, x + 400, 400)
}

/// A marker over one 400 nm pad per pin, 800 nm apart; pad `k` is on `pina`,
/// `pinb`, `pinc` by position, except a resistor's, which are both `pina`.
fn draw_pins(mut layout: Layout, x0: i64, dev: &Dev) -> Layout {
    let (marker, layers): (&str, [&str; 3]) = match dev.model {
        Model::R => ("resm", ["pina", "pina", ""]),
        Model::C => ("capm", ["pina", "pinb", ""]),
        Model::D => ("diom", ["pina", "pinb", ""]),
        Model::Q => ("bjtm", ["pina", "pinb", "pinc"]),
        _ => unreachable!("a MOS"),
    };
    let mut right = x0;
    for (k, &net) in dev.pins.iter().enumerate() {
        let (x, y0, x1, y1) = pad(x0, k);
        layout = layout
            .rect(layers[k], x, y0, x1, y1)
            .rect("cont", x + 100, 100, x + 300, 300);
        layout = stub(layout, x + 100, x + 300, 100, net);
        right = x;
    }
    layout.rect(marker, x0 + 200, 0, right + 200, 400)
}

// ---------------------------------------------------------------------------
// The reference
// ---------------------------------------------------------------------------

/// One card, SPICE or (`spectre`) Spectre, which differ here only in the
/// parentheses round the nets. A three-terminal MOS's bulk is written as its
/// source: the deck extracts no bulk for it, so the comparison drops it (`lvs`
/// module docs).
fn card(out: &mut String, index: usize, dev: &Dev, names: &[String], spectre: bool) {
    let (open, close) = if spectre { ("(", ")") } else { ("", "") };
    let n = |k: usize| names[dev.pins[k]].as_str();
    let _ = match dev.model {
        Model::N | Model::P | Model::H | Model::B => {
            let bulk = if dev.model == Model::B { n(3) } else { n(1) };
            write!(
                out,
                "M{index} {open}{} {} {} {bulk}{close} {} w={}n l={}n",
                n(2),
                n(0),
                n(1),
                dev.model.name(),
                dev.w,
                dev.l
            )
        }
        Model::R | Model::C | Model::D => {
            let letter = dev.model.letter();
            write!(
                out,
                "{letter}{index} {open}{} {}{close} {}",
                n(0),
                n(1),
                dev.model.name()
            )
        }
        Model::Q => write!(out, "Q{index} {open}{} {} {}{close} npn", n(2), n(0), n(1)),
    };
    if dev.m != 1 {
        let _ = write!(out, " m={}", dev.m);
    }
    if let Some(area) = dev.area {
        // nm² as µm², which SPICE writes with `p` (1e-12 m²).
        #[allow(clippy::cast_precision_loss, reason = "nanometre areas are small")]
        let _ = write!(out, " area={}p", area as f64 / 1e6);
    }
    out.push('\n');
}

/// Subcircuit `name`'s `.subckt` line and cards; `c`'s port nets are its
/// ports.
fn subckt(out: &mut String, name: &str, c: &Circuit, order: &[usize]) {
    let _ = write!(out, ".subckt {name}");
    for (net, _) in c.names.iter().zip(&c.ports).filter(|(_, &p)| p) {
        out.push(' ');
        out.push_str(net);
    }
    out.push('\n');
    for &i in order {
        card(out, i, &c.devs[i], &c.names, false);
    }
}

/// `c` as one subcircuit `TOP`.
fn spice(c: &Circuit) -> String {
    spice_ordered(c, &(0..c.devs.len()).collect::<Vec<_>>())
}

/// [`spice`] with the cards in `order`.
fn spice_ordered(c: &Circuit, order: &[usize]) -> String {
    let mut out = String::from("* generated by tests/exhaustive/lvs.rs\n");
    subckt(&mut out, "TOP", c, order);
    out.push_str(".ends\n");
    out
}

/// `c` as one Spectre subcircuit `TOP`: [`spice`] in the reader's other
/// dialect (LVS-071). The models that are not Spectre primitives get a
/// `model` card naming their master.
fn spectre(c: &Circuit) -> String {
    let mut out = String::from(
        "// generated by tests/exhaustive/lvs.rs\n\
         model nmos_hvt bsim4\nmodel nmosb bsim4\nmodel rpoly resistor\n\
         model cmim capacitor\nmodel dpn diode\nsubckt TOP",
    );
    for (net, _) in c.names.iter().zip(&c.ports).filter(|(_, &p)| p) {
        out.push(' ');
        out.push_str(net);
    }
    out.push('\n');
    for (i, dev) in c.devs.iter().enumerate() {
        card(&mut out, i, dev, &c.names, true);
    }
    out.push_str("ends TOP\n");
    out
}

/// `text` with `from` replaced by `to`. A reference edit whose anchor is gone
/// would leave the fixture testing the unedited circuit, so it panics instead.
fn edited(text: &str, from: &str, to: &str) -> String {
    assert!(
        text.contains(from),
        "{from:?} is not in the reference:\n{text}"
    );
    text.replace(from, to)
}

/// `top` with one instance of `block`, whose ports land on `on` in order.
fn spice_hier(top: &Circuit, block: &Circuit, on: &[usize]) -> String {
    let mut out = String::from("* generated by tests/exhaustive/lvs.rs\n");
    subckt(
        &mut out,
        "BLK",
        block,
        &(0..block.devs.len()).collect::<Vec<_>>(),
    );
    out.push_str(".ends\n");
    subckt(
        &mut out,
        "TOP",
        top,
        &(0..top.devs.len()).collect::<Vec<_>>(),
    );
    out.push_str("X0");
    for &net in on {
        out.push(' ');
        out.push_str(&top.names[net]);
    }
    out.push_str(" BLK\n.ends\n");
    out
}

/// What [`spice_hier`] means, flat: `block`'s devices in `top`, its ports on
/// `on`, its other nets new internal nets.
fn flatten(top: &Circuit, block: &Circuit, on: &[usize]) -> Circuit {
    let mut flat = top.clone();
    let mut ports = on.iter();
    let map: Vec<usize> = (0..block.nets())
        .map(|k| {
            if block.ports[k] {
                *ports.next().expect("one net per port")
            } else {
                flat.names.push(format!("x0.{}", block.names[k]));
                flat.ports.push(false);
                flat.nets() - 1
            }
        })
        .collect();
    for dev in &block.devs {
        let mut dev = dev.clone();
        for p in &mut dev.pins {
            *p = map[*p];
        }
        flat.devs.push(dev);
    }
    flat
}

// ---------------------------------------------------------------------------
// The oracle
// ---------------------------------------------------------------------------

/// A device after reduction: `w`, `l` in nm, summed by merges, and how many
/// identical devices in parallel it stands for, which is how a passive with no
/// summed parameter keeps its count (F20, F21).
#[derive(Debug, Clone)]
struct Reduced {
    model: Model,
    pins: Vec<usize>,
    w: f64,
    l: f64,
    mult: u32,
    area: Option<i64>,
}

/// Whether two devices of `model` land on the same nets role for role: a
/// MOS's source and drain either way round, a resistor's ends either way,
/// everything else in order; MOS gates and bulks are fixed. `a`'s nets are
/// read through `map`.
fn same_pins(model: Model, a: &[usize], b: &[usize], map: impl Fn(usize) -> usize) -> bool {
    let a = |k: usize| map(a[k]);
    let fixed = |from: usize| (from..b.len()).all(|k| a(k) == b[k]);
    match model {
        Model::N | Model::P | Model::H | Model::B => {
            a(0) == b[0]
                && fixed(3)
                && ((a(1) == b[1] && a(2) == b[2]) || (a(1) == b[2] && a(2) == b[1]))
        }
        Model::R => (a(0) == b[0] && a(1) == b[1]) || (a(0) == b[1] && a(1) == b[0]),
        Model::C | Model::D | Model::Q => fixed(0),
    }
}

/// The documented reductions to a fixed point, parallel first:
///
/// - **multiplier:** a MOS's `m` multiplies its `W`; any other device's `m` is
///   that many in parallel;
/// - **parallel:** devices of one model on the same nets role for role become
///   one; a MOS needs `L` equal and sums `W`, anything else needs its
///   parameters equal and sums its count;
/// - **series** (MOS only): two devices with gates (and bulks) on one net and
///   equal `W`, whose channels meet at a net that is not a port and that no
///   other terminal touches, become one with `L` summed; the net is consumed.
///
/// `shorted_parallel: false` skips a parallel merge of MOS whose source and
/// drain share a net, which is what the tool does today (finding F57); it
/// is used only to mark the fixtures that finding breaks.
///
/// A net no terminal lands on survives only as a port: a floating shape is
/// not a node, and SPICE cannot even write one.
fn reduce(c: &Circuit, shorted_parallel: bool) -> Reduction {
    #[allow(clippy::cast_precision_loss, reason = "nanometre sizes are small")]
    let mut devs: Vec<Reduced> = c
        .devs
        .iter()
        .map(|d| {
            let (w, mult) = if d.model.is_mos() {
                (d.w as f64 * f64::from(d.m), 1)
            } else {
                (0.0, d.m)
            };
            Reduced {
                model: d.model,
                pins: d.pins.clone(),
                w,
                l: d.l as f64,
                mult,
                area: d.area,
            }
        })
        .collect();
    let mut alive = vec![true; c.nets()];
    let shorted = |d: &Reduced| d.model.is_mos() && d.pins[1] == d.pins[2];
    'pass: loop {
        for i in 0..devs.len() {
            for j in i + 1..devs.len() {
                let (a, b) = (&devs[i], &devs[j]);
                #[allow(clippy::float_cmp, reason = "equal means drawn or written the same")]
                let params = if a.model.is_mos() {
                    a.l == b.l
                } else {
                    a.area == b.area
                };
                if a.model == b.model
                    && params
                    && same_pins(a.model, &a.pins, &b.pins, |n| n)
                    && (shorted_parallel || !shorted(a))
                {
                    let b = devs.remove(j);
                    if b.model.is_mos() {
                        devs[i].w += b.w;
                    } else {
                        devs[i].mult += b.mult;
                    }
                    continue 'pass;
                }
            }
        }
        let touches = |devs: &[Reduced], net: usize| {
            devs.iter()
                .flat_map(|d| &d.pins)
                .filter(|&&p| p == net)
                .count()
        };
        for i in 0..devs.len() {
            for j in 0..devs.len() {
                let (a, b) = (&devs[i], &devs[j]);
                #[allow(clippy::float_cmp, reason = "equal means drawn or written the same")]
                let mergeable = i != j
                    && a.model.is_mos()
                    && a.model == b.model
                    && a.pins[0] == b.pins[0]
                    && a.pins[3..] == b.pins[3..]
                    && a.w == b.w;
                if !mergeable {
                    continue;
                }
                for ea in 1..3 {
                    for eb in 1..3 {
                        let x = a.pins[ea];
                        if x == b.pins[eb] && !c.ports[x] && touches(&devs, x) == 2 {
                            let (far_a, far_b, l) = (a.pins[3 - ea], b.pins[3 - eb], b.l);
                            devs[i].pins[1] = far_a;
                            devs[i].pins[2] = far_b;
                            devs[i].l += l;
                            devs.remove(j);
                            alive[x] = false;
                            continue 'pass;
                        }
                    }
                }
            }
        }
        break;
    }
    let live = (0..c.nets())
        .filter(|&k| alive[k] && (c.ports[k] || devs.iter().any(|d| d.pins.contains(&k))))
        .collect();
    let mut models: Vec<Model> = devs.iter().map(|d| d.model).collect();
    models.sort_unstable();
    Reduction {
        devs,
        live,
        nets: c.nets(),
        models,
    }
}

/// A circuit reduced: its devices, the nets that survive, how many nets it
/// had, and its devices' models sorted, the cheapest test there is.
struct Reduction {
    devs: Vec<Reduced>,
    live: Vec<usize>,
    nets: usize,
    models: Vec<Model>,
}

/// `|a - b| <= tol * max(|a|, |b|)`, the definition in `CompareOptions`.
fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= TOLERANCE * a.abs().max(b.abs())
}

/// Whether layout device `a`, its nets renamed by `map`, is reference device
/// `b`. An area is compared only where the reference declares one (F22).
fn pairs(a: &Reduced, b: &Reduced, map: &[usize]) -> bool {
    if a.model != b.model || a.mult != b.mult {
        return false;
    }
    if !same_pins(a.model, &a.pins, &b.pins, |n| map[n]) {
        return false;
    }
    // The layout side always has its marker's area: what was drawn.
    let drawn = match a.model {
        Model::Q => BJT_AREA,
        _ => PIN2_AREA,
    };
    #[allow(clippy::cast_precision_loss, reason = "nanometre areas are small")]
    let area = match b.area {
        Some(declared) => close(a.area.unwrap_or(drawn) as f64, declared as f64),
        None => true,
    };
    area && (!a.model.is_mos() || (close(a.w, b.w) && close(a.l, b.l)))
}

/// Every permutation of `0..n`, for `n` up to 7, computed once.
fn permutations(n: usize) -> &'static [Vec<usize>] {
    static ALL: OnceLock<Vec<Vec<Vec<usize>>>> = OnceLock::new();
    let all = ALL.get_or_init(|| {
        let mut all = vec![vec![Vec::new()]];
        for k in 1..=7 {
            let mut next = Vec::new();
            for rest in &all[k - 1] {
                for at in 0..k {
                    let mut p = rest.clone();
                    p.insert(at, k - 1);
                    next.push(p);
                }
            }
            all.push(next);
        }
        all
    });
    &all[n]
}

/// Whether some assignment pairs each of `a[from..]` with a distinct unused
/// device of `b`.
fn assign(a: &[Reduced], b: &[Reduced], map: &[usize], used: &mut [bool], from: usize) -> bool {
    let Some(dev) = a.get(from) else {
        return true;
    };
    for j in 0..b.len() {
        if !used[j] && pairs(dev, &b[j], map) {
            used[j] = true;
            if assign(a, b, map, used, from + 1) {
                return true;
            }
            used[j] = false;
        }
    }
    false
}

/// The oracle: whether `layout` and `reference` are one circuit, by brute
/// force over every bijection of their reduced nets.
fn equivalent(layout: &Circuit, reference: &Circuit) -> bool {
    verdict(layout, reference, true)
}

/// [`equivalent`], with [`reduce`]'s `shorted_parallel` switch.
fn verdict(layout: &Circuit, reference: &Circuit, shorted_parallel: bool) -> bool {
    matches(
        &reduce(layout, shorted_parallel),
        &reduce(reference, shorted_parallel),
    )
}

/// Whether some bijection of `a`'s surviving nets onto `b`'s pairs every
/// device.
fn matches(a: &Reduction, b: &Reduction) -> bool {
    if a.live.len() != b.live.len() || a.models != b.models {
        return false;
    }
    let mut map = vec![usize::MAX; a.nets];
    permutations(a.live.len()).iter().any(|perm| {
        for (i, &k) in a.live.iter().enumerate() {
            map[k] = b.live[perm[i]];
        }
        assign(&a.devs, &b.devs, &map, &mut vec![false; b.devs.len()], 0)
    })
}

// ---------------------------------------------------------------------------
// Enumeration and faults
// ---------------------------------------------------------------------------

/// An enumerated circuit (MOS only, every net a port) up to renaming nets and
/// devices and swapping source with drain: the least sorted list of device
/// codes over every renaming of the nets that lists them by how many gates and
/// channel ends each carries. An isomorphism keeps those counts, so it maps
/// the renamings of one circuit onto the other's, and the least is the same.
type Key = [u64; 4];

fn key(c: &Circuit) -> Key {
    let code = |d: &Dev, perm: &[usize]| {
        let (g, s, d2) = (perm[d.pins[0]], perm[d.pins[1]], perm[d.pins[2]]);
        let model = u64::from(d.model == Model::P);
        let size = u64::try_from(d.w << 20 | d.l).expect("positive sizes");
        let net = |n: usize| u64::try_from(n).expect("few nets");
        model << 60 | net(g) << 56 | net(s.min(d2)) << 52 | net(s.max(d2)) << 48 | size
    };
    let n = c.nets();
    let mut count = vec![(0u8, 0u8); n];
    for d in &c.devs {
        count[d.pins[0]].0 += 1;
        count[d.pins[1]].1 += 1;
        count[d.pins[2]].1 += 1;
    }
    let mut sorted = count.clone();
    sorted.sort_unstable();
    let rank: Vec<(usize, usize)> = count
        .iter()
        .map(|c| {
            (
                sorted.partition_point(|x| x < c),
                sorted.partition_point(|x| x <= c),
            )
        })
        .collect();
    permutations(n)
        .iter()
        .filter(|perm| (0..n).all(|k| (rank[k].0..rank[k].1).contains(&perm[k])))
        .map(|perm| {
            let mut k = [u64::MAX; 4];
            for (slot, d) in k.iter_mut().zip(&c.devs) {
                *slot = code(d, perm);
            }
            k.sort_unstable();
            k
        })
        .min()
        .expect("at least one permutation")
}

/// Every circuit of one to three `nmos`/`pmos` over one to four nets, every net
/// used, one per isomorphism class.
fn circuits() -> Vec<Circuit> {
    let mut out = Vec::new();
    for nets in 1..=4 {
        let mut types = Vec::new();
        for model in [Model::N, Model::P] {
            for g in 0..nets {
                for s in 0..nets {
                    for d in s..nets {
                        types.push(Dev::mos(model, g, s, d));
                    }
                }
            }
        }
        let mut seen = BTreeSet::new();
        let mut pick = |devs: &[&Dev]| {
            let used: u32 = devs
                .iter()
                .flat_map(|d| &d.pins)
                .fold(0, |used, &p| used | 1 << p);
            if used.count_ones() as usize != nets {
                return;
            }
            let c = Circuit::new(nets, devs.iter().map(|&d| d.clone()).collect());
            if seen.insert(key(&c)) {
                out.push(c);
            }
        };
        for a in 0..types.len() {
            pick(&[&types[a]]);
            for b in a..types.len() {
                pick(&[&types[a], &types[b]]);
                for t in &types[b..] {
                    pick(&[&types[a], &types[b], t]);
                }
            }
        }
    }
    out
}

/// Every single fault of the module docs applied to `c`'s reference, plus the
/// source/drain swaps, which must keep the verdict: `(label, faulted
/// reference, catalog rows)`.
fn faults(c: &Circuit) -> Vec<(String, Circuit, &'static [&'static str])> {
    let mut out = Vec::new();
    let mut push = |label: String, r: Circuit, catalog: &'static [&'static str]| {
        out.push((label, r.compact(), catalog));
    };
    let n = c.nets();
    for (i, dev) in c.devs.iter().enumerate() {
        if dev.pins[1] != dev.pins[2] {
            let mut r = c.clone();
            r.devs[i].pins.swap(1, 2);
            push(format!("sd/{i}"), r, &["LVS-030"]);
        }
        for (t, terminal) in ["g", "s", "d"].into_iter().enumerate() {
            for k in (0..n).filter(|&k| k != dev.pins[t]) {
                let mut r = c.clone();
                r.devs[i].pins[t] = k;
                push(format!("term/{i}{terminal}-n{k}"), r, &["LVS-015"]);
            }
            let net = dev.pins[t];
            let on_net = c.devs.iter().flat_map(|d| &d.pins).filter(|&&p| p == net);
            if on_net.count() >= 2 {
                let mut r = c.clone();
                r.names.push(format!("n{n}"));
                r.ports.push(true);
                r.devs[i].pins[t] = n;
                push(format!("open/{i}{terminal}"), r, &["LVS-015"]);
            }
        }
        let mut r = c.clone();
        r.devs[i].model = if dev.model == Model::N {
            Model::P
        } else {
            Model::N
        };
        push(format!("model/{i}"), r, &["LVS-011", "LVS-013"]);
        let mut r = c.clone();
        r.devs.remove(i);
        push(format!("delete/{i}"), r, &["LVS-012"]);
        let mut r = c.clone();
        r.devs.push(dev.clone());
        push(format!("add/copy{i}"), r, &["LVS-012", "LVS-040"]);
        for (pct, delta) in [("1.9", 19), ("2.1", 21)] {
            let mut r = c.clone();
            r.devs[i].w += dev.w * delta / 1000;
            push(format!("w+{pct}/{i}"), r, &["LVS-014", "LVS-060"]);
        }
    }
    let mut r = c.clone();
    r.names.push(format!("n{n}"));
    r.ports.push(true);
    r.devs.push(Dev::mos(Model::N, n - 1, 0, n));
    push("add/new".to_owned(), r, &["LVS-012"]);
    for a in 0..n {
        for b in a + 1..n {
            let mut r = c.clone();
            for p in r.devs.iter_mut().flat_map(|d| &mut d.pins) {
                if *p == b {
                    *p = a;
                }
            }
            push(format!("short/n{a}+n{b}"), r, &["LVS-015"]);
        }
    }
    out
}

/// Enumerated fixtures that fail today because the tool's symmetry breaking
/// pairs a device with the wrong member of a class refinement cannot split
/// (finding F58), as `(circuit code, fault label)`. Each was re-derived by
/// hand: the faulted reference is the layout's circuit, within tolerance.
const TIE_BREAK: &[(&str, &str)] = &[
    ("N0.0.0+N1.1.2+N2.1.2", "reversed"),
    ("N0.0.0+N1.1.2+N2.1.2", "w+1.9/0"),
    ("N0.0.0+N1.2.2+N2.1.1", "reversed"),
    ("N0.0.0+N1.2.2+N2.1.1", "w+1.9/0"),
    ("N0.0.1+N1.0.2+N2.1.2", "w+1.9/0"),
    ("N0.0.1+N1.2.2+N2.0.1", "reversed"),
    ("N0.0.1+N1.2.2+N2.0.1", "w+1.9/0"),
    ("N0.1.1+N0.1.2+N0.2.2", "w+1.9/0"),
    ("P0.0.0+P1.1.2+P2.1.2", "reversed"),
    ("P0.0.0+P1.1.2+P2.1.2", "w+1.9/0"),
    ("P0.0.0+P1.2.2+P2.1.1", "reversed"),
    ("P0.0.0+P1.2.2+P2.1.1", "w+1.9/0"),
    ("P0.0.1+P1.0.2+P2.1.2", "w+1.9/0"),
    ("P0.0.1+P1.2.2+P2.0.1", "reversed"),
    ("P0.0.1+P1.2.2+P2.0.1", "w+1.9/0"),
    ("P0.1.1+P0.1.2+P0.2.2", "w+1.9/0"),
    ("N0.0.1+N2.1.3+N3.1.2", "reversed"),
    ("N0.0.1+N2.1.3+N3.1.2", "w+1.9/0"),
    ("P0.0.1+P2.1.3+P3.1.2", "reversed"),
    ("P0.0.1+P2.1.3+P3.1.2", "w+1.9/0"),
];

/// Why an enumerated fixture fails today, if it does.
fn known_enum(
    c: &Circuit,
    code: &str,
    label: &str,
    reference: &Circuit,
    matched: bool,
) -> Option<&'static str> {
    let shorted = |c: &Circuit| c.devs.iter().any(|d| d.pins[1] == d.pins[2]);
    if (shorted(c) || shorted(reference)) && verdict(c, reference, false) != matched {
        return Some("F57");
    }
    TIE_BREAK.contains(&(code, label)).then_some("F58")
}

/// The circuit against its own reference, its cards reversed, and its faults,
/// deduplicated up to isomorphism (the source/drain swaps are kept, since
/// they differ only in text).
///
/// With `pick`, the faults are thinned: every fault whose reference still
/// matches is kept, since that is where a false mismatch hides, and of those
/// that must mismatch, one per kind, drawn from `pick`. Without it, all.
fn enumerated(c: &Circuit, mut pick: Option<Rng>) -> Vec<Fixture> {
    let reduced = reduce(c, true);
    let mut seen = BTreeSet::from([key(c)]);
    // `(label, reference, catalog rows, matches)`; the first two keep `c`.
    let mut kept = vec![(
        "base".to_owned(),
        c.clone(),
        &["LVS-019", "LVS-070"][..],
        true,
    )];
    if c.devs.len() > 1 {
        kept.push(("reversed".to_owned(), c.clone(), &["LVS-019"], true));
    }
    kept.push(("spectre".to_owned(), c.clone(), &["LVS-071"], true));
    let mut mismatched = Vec::new();
    for (label, r, catalog) in faults(c) {
        if !label.starts_with("sd/") && !seen.insert(key(&r)) {
            continue;
        }
        let matched = matches(&reduced, &reduce(&r, true));
        if matched || pick.is_none() {
            kept.push((label, r, catalog, matched));
        } else {
            mismatched.push((label, r, catalog, matched));
        }
    }
    if let Some(rng) = &mut pick {
        let kind = |label: &str| label.split('/').next().unwrap_or_default().to_owned();
        let kinds: BTreeSet<String> = mismatched.iter().map(|f| kind(&f.0)).collect();
        for k in kinds {
            let mut of_kind: Vec<_> = mismatched.iter().filter(|f| kind(&f.0) == k).collect();
            let at = rng.below(u64::try_from(of_kind.len()).expect("few faults"));
            kept.push(
                of_kind
                    .swap_remove(usize::try_from(at).expect("few faults"))
                    .clone(),
            );
        }
    }
    let layout = draw(c);
    let code = c.code();
    kept.into_iter()
        .map(|(label, r, catalog, matched)| {
            let text = match label.as_str() {
                "reversed" => spice_ordered(c, &(0..c.devs.len()).rev().collect::<Vec<_>>()),
                "spectre" => spectre(&r),
                _ => spice(&r),
            };
            let mut catalog = catalog.to_vec();
            if label == "base" && reduced.devs.len() < c.devs.len() {
                catalog.push("LVS-040");
            }
            let name = format!("lvs/enum/n{}:{code}/{label}", c.nets());
            let mut fixture = Fixture::new(&name, &catalog, MOS_DECK, LVS)
                .layout(layout.clone())
                .expect(Expect::Lvs(matched));
            fixture.reference = Some(text);
            match known_enum(c, &code, &label, &r, matched) {
                Some(finding) => fixture.known(finding),
                None => fixture,
            }
        })
        .collect()
}

/// One merge-depth circuit in this many, past the one-device ones.
const SAMPLE: u64 = 40;

/// Every fixture this module generates at `depth`.
///
/// The merge sample is every one-device circuit and a seeded draw of the rest,
/// each with every fault. The nightly run adds every other circuit with its
/// faults thinned as [`enumerated`] describes: the full product, about 186 000
/// fixtures, is more than the harness can hold, since it materialises the
/// nightly set in its merge-time checks.
pub fn fixtures(depth: Depth) -> Vec<Fixture> {
    let mut sample = Rng::new(0x1A5_0005);
    let mut out = Vec::new();
    for (index, c) in circuits().iter().enumerate() {
        let sampled = c.devs.len() == 1 || sample.below(SAMPLE) == 0;
        if sampled {
            out.extend(enumerated(c, None));
        } else if depth == Depth::Nightly {
            out.extend(enumerated(c, Some(Rng::new(index as u64))));
        }
    }
    out.extend(curated());
    out.extend(layout_rows());
    out
}

// ---------------------------------------------------------------------------
// Curated fixtures
// ---------------------------------------------------------------------------

/// `layout` drawn and compared with `reference`, the verdict the oracle's.
fn compared(
    name: &str,
    catalog: &[&'static str],
    layout: &Circuit,
    reference: &Circuit,
) -> Fixture {
    let mut fixture = Fixture::new(&format!("lvs/{name}"), catalog, &full_deck(), LVS)
        .layout(draw(layout))
        .expect(Expect::Lvs(equivalent(layout, reference)));
    fixture.reference = Some(spice(reference));
    fixture
}

/// A fixture whose reference is `text`; the caller states its expectations.
fn with_text(name: &str, catalog: &[&'static str], layout: Layout, text: String) -> Fixture {
    let mut fixture =
        Fixture::new(&format!("lvs/{name}"), catalog, &full_deck(), LVS).layout(layout);
    fixture.reference = Some(text);
    fixture
}

/// The asymmetric context every polarity case sits in: an `nmos` gated by `n0`
/// whose channel joins `n1` and `n2`, so `n0` and `n1` cannot trade places.
fn polar(dev: Dev) -> Circuit {
    Circuit::new(3, vec![Dev::mos(Model::N, 0, 1, 2), dev])
}

/// Hierarchy, stacks, parallel devices, polarity, multipliers, tolerance,
/// declared parameters, flavours, bulk, symmetry, ports and verdict classes.
fn curated() -> Vec<Fixture> {
    use Model::{B, C, D, H, N, P, Q, R};
    let mut out = Vec::new();

    // F1 (fixed in B2): a reference that places a block by `X` instance. Top: an nmos on
    // in = n0, out = n1, vss = n2; the block: a pmos `d g s`, placed on
    // (out, in, vss).
    let top = Circuit::new(3, vec![Dev::mos(N, 0, 2, 1)]);
    let block = Circuit::new(3, vec![Dev::mos(P, 1, 2, 0)]);
    let on = [1, 0, 2];
    let flat = flatten(&top, &block, &on);
    let hier = spice_hier(&top, &block, &on);
    for (name, drawn) in [("hier/block_missing", &top), ("hier/block_drawn", &flat)] {
        out.push(
            with_text(
                name,
                &["LVS-010", "LVS-017", "LVS-072"],
                draw(drawn),
                hier.clone(),
            )
            .expect(Expect::Lvs(equivalent(drawn, &flat))),
        );
    }
    out.push(compared(
        "hier/flat_control",
        &["LVS-019", "LVS-072"],
        &flat,
        &flat,
    ));

    // F12 (fixed in B4), LVS-041: a stack through n3, its gates strapped on n0.
    let stack = Circuit::new(4, vec![Dev::mos(N, 0, 1, 3), Dev::mos(N, 0, 3, 2)]);
    let long = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(1000, 300)]);
    let inner = stack.clone().internal(3);
    let both = &["LVS-041", "LVS-049"];
    out.push(compared("series/stack_vs_stack", both, &inner, &inner));
    out.push(compared(
        "series/stack_vs_long",
        &["LVS-041"],
        &inner,
        &long,
    ));
    out.push(compared(
        "series/labelled_stack_vs_stack",
        &["LVS-041"],
        &stack,
        &stack,
    ));
    out.push(compared(
        "series/labelled_stack_vs_long",
        both,
        &stack,
        &long,
    ));
    let mut uneven = inner.clone();
    uneven.devs[1] = uneven.devs[1].clone().sized(2000, 150);
    out.push(compared(
        "series/widths_differ_vs_long",
        &["LVS-041"],
        &uneven,
        &long,
    ));
    let apart = Circuit::new(5, vec![Dev::mos(N, 0, 1, 3), Dev::mos(N, 4, 3, 2)]).internal(3);
    out.push(compared(
        "series/gates_apart_vs_long",
        &["LVS-041"],
        &apart,
        &long,
    ));

    // LVS-040 and finding F57: parallel MOS.
    let two = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2), Dev::mos(N, 0, 2, 1)]);
    let wide = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(2000, 150)]);
    out.push(compared(
        "parallel/mos_two_vs_wide",
        &["LVS-040"],
        &two,
        &wide,
    ));
    let mut lengths = two.clone();
    lengths.devs[1] = lengths.devs[1].clone().sized(1000, 200);
    out.push(compared(
        "parallel/mos_lengths_differ_vs_wide",
        &["LVS-040"],
        &lengths,
        &wide,
    ));
    let shorted = Circuit::new(2, vec![Dev::mos(N, 0, 1, 1), Dev::mos(N, 0, 1, 1)]);
    let shorted_wide = Circuit::new(2, vec![Dev::mos(N, 0, 1, 1).sized(2000, 150)]);
    out.push(
        compared(
            "parallel/mos_shorted_two_vs_wide",
            &["LVS-040"],
            &shorted,
            &shorted_wide,
        )
        .known("F57"),
    );

    // F20, LVS-043, LVS-044: parallel passives keep their count.
    for (model, row) in [(R, "LVS-043"), (C, "LVS-044"), (D, "LVS-044")] {
        let one = polar(Dev::pins(model, &[0, 1]));
        let mut two = one.clone();
        two.devs.push(Dev::pins(model, &[0, 1]));
        let letter = model.letter();
        let name = format!("parallel/{letter}_two_vs_one");
        out.push(compared(&name, &[row], &one, &two).known("F20"));
        out.push(compared(
            &format!("parallel/{letter}_two_vs_two"),
            &[row],
            &two,
            &two,
        ));
    }
    let forward = polar(Dev::pins(D, &[0, 1]));
    let mut opposed = forward.clone();
    opposed.devs.push(Dev::pins(D, &[1, 0]));
    let rows = &["LVS-044", "LVS-030"];
    // Opposed diodes stay two since F15 was fixed; F20's summing is open.
    out.push(compared(
        "parallel/D_opposed_vs_one",
        rows,
        &forward,
        &opposed,
    ));
    out.push(compared(
        "parallel/D_opposed_vs_opposed",
        rows,
        &opposed,
        &opposed,
    ));

    // F15 (fixed in B3), LVS-030: which ends are interchangeable.
    for (model, row) in [(R, "LVS-030"), (C, "LVS-062"), (D, "LVS-063")] {
        let drawn = polar(Dev::pins(model, &[0, 1]));
        let reversed = polar(Dev::pins(model, &[1, 0]));
        let letter = model.letter();
        let rows = &["LVS-030", row];
        out.push(compared(
            &format!("polarity/{letter}_same"),
            rows,
            &drawn,
            &drawn,
        ));
        let fixture = compared(
            &format!("polarity/{letter}_reversed"),
            rows,
            &drawn,
            &reversed,
        );
        out.push(fixture);
    }
    let bjt = polar(Dev::pins(Q, &[0, 1, 2]));
    let flipped = polar(Dev::pins(Q, &[0, 2, 1]));
    let rows = &["LVS-030", "LVS-064"];
    out.push(compared("polarity/Q_same", rows, &bjt, &bjt));
    out.push(compared(
        "polarity/Q_emitter_collector_swapped",
        rows,
        &bjt,
        &flipped,
    ));

    // LVS-071: every model through the Spectre reader, as drawn and with a
    // fault, so the reader is held to the SPICE reader's verdicts.
    let every_model = [
        polar(Dev::mos(P, 1, 0, 2)),
        polar(Dev::mos(H, 1, 0, 2)),
        Circuit::new(4, vec![Dev::mos(B, 0, 1, 2).sized(2000, 150).bulk(3)]),
        polar(Dev::pins(R, &[0, 1])),
        polar(Dev::pins(C, &[0, 1])),
        polar(Dev::pins(D, &[0, 1])),
        polar(Dev::pins(Q, &[0, 1, 2])),
    ];
    for (index, drawn) in every_model.iter().enumerate() {
        let mut moved = drawn.clone();
        let last = moved.devs.len() - 1;
        moved.devs[last].pins.swap(0, 1);
        for (label, written) in [("same", drawn), ("swapped", &moved)] {
            out.push(
                with_text(
                    &format!("spectre/{index}_{label}"),
                    &["LVS-071"],
                    draw(drawn),
                    spectre(written),
                )
                .expect(Expect::Lvs(equivalent(drawn, written))),
            );
        }
    }

    // F21, LVS-046: the multiplier.
    let cap = polar(Dev::pins(C, &[0, 1]));
    let cap_m2 = polar(Dev::pins(C, &[0, 1]).times(2));
    let mut caps = cap.clone();
    caps.devs.push(Dev::pins(C, &[0, 1]));
    out.push(compared("multiplier/C_m2_vs_one", &["LVS-046"], &cap, &cap_m2).known("F21"));
    out.push(compared(
        "multiplier/C_m2_vs_two",
        &["LVS-046", "LVS-044"],
        &caps,
        &cap_m2,
    ));
    let m2 = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).times(2)]);
    let one = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2)]);
    out.push(compared(
        "multiplier/mos_m2_vs_two",
        &["LVS-046", "LVS-040"],
        &two,
        &m2,
    ));
    out.push(compared(
        "multiplier/mos_m2_vs_wide",
        &["LVS-046"],
        &wide,
        &m2,
    ));
    out.push(compared(
        "multiplier/mos_m2_vs_one",
        &["LVS-046", "LVS-014"],
        &one,
        &m2,
    ));

    // LVS-014, LVS-060: either side of 2 %, on W and on L, both signs.
    let square = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(1000, 1000)]);
    for (name, w, l) in [
        ("w-1.9", 981, 1000),
        ("w-2.1", 979, 1000),
        ("l+1.9", 1000, 1019),
        ("l+2.1", 1000, 1021),
        ("l-1.9", 1000, 981),
        ("l-2.1", 1000, 979),
    ] {
        let r = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(w, l)]);
        let rows = &["LVS-014", "LVS-060"];
        out.push(compared(&format!("tolerance/{name}"), rows, &square, &r));
    }

    // F22, F16, LVS-020, LVS-062..064: declared areas and undeclared names.
    for (model, area, row) in [
        (C, PIN2_AREA, "LVS-062"),
        (D, PIN2_AREA, "LVS-063"),
        (Q, BJT_AREA, "LVS-064"),
    ] {
        let pins: &[usize] = if model == Q { &[0, 1, 2] } else { &[0, 1] };
        let alone = Circuit::new(pins.len(), vec![Dev::pins(model, pins)]);
        let letter = model.letter();
        for (case, declared) in [("exact", area), ("5pct_over", area * 105 / 100)] {
            let r = Circuit::new(pins.len(), vec![Dev::pins(model, pins).area(declared)]);
            let name = format!("params/{letter}_area_{case}");
            out.push(compared(&name, &[row, "LVS-014"], &alone, &r));
        }
    }
    let diode = polar(Dev::pins(D, &[0, 1]));
    let declared = polar(Dev::pins(D, &[0, 1]).area(PIN2_AREA));
    let rows = &["LVS-020", "LVS-063"];
    out.push(compared("params/D_area_beside_mos", rows, &diode, &declared).known("F22"));
    let nf = edited(&spice(&one), "l=150n", "l=150n nf=1");
    out.push(
        with_text(
            "params/nf_1_is_one_finger",
            &["LVS-020", "LVS-060"],
            draw(&one),
            nf,
        )
        .expect(Expect::Lvs(true))
        .known("F16"),
    );
    let unknown = edited(&spice(&one), "l=150n", "l=150n foo=1");
    out.push(
        with_text(
            "params/unmeasurable_param",
            &["LVS-020"],
            draw(&one),
            unknown,
        )
        .expect(Expect::Lvs(false)),
    );

    // LVS-066: a flavour is its own model.
    let hvt = Circuit::new(3, vec![Dev::mos(H, 0, 1, 2)]);
    let rows = &["LVS-066", "LVS-013"];
    out.push(compared("flavour/hvt_vs_hvt", &["LVS-066"], &hvt, &hvt));
    out.push(compared("flavour/hvt_vs_plain", rows, &hvt, &one));
    out.push(compared("flavour/plain_vs_hvt", rows, &one, &hvt));

    // LVS-045: bulks must agree for a merge.
    let bulked = |b0: usize, b1: usize, nets: usize| {
        let devs = vec![Dev::mos(B, 0, 1, 2).bulk(b0), Dev::mos(B, 0, 2, 1).bulk(b1)];
        Circuit::new(nets, devs)
    };
    let wide_b = Circuit::new(4, vec![Dev::mos(B, 0, 1, 2).sized(2000, 150).bulk(3)]);
    let rows = &["LVS-045", "LVS-040"];
    out.push(compared(
        "bulk/parallel_one_bulk_vs_wide",
        rows,
        &bulked(3, 3, 4),
        &wide_b,
    ));
    let (split, joined) = (bulked(3, 4, 5), bulked(3, 3, 4));
    out.push(compared(
        "bulk/parallel_two_bulks_vs_two",
        rows,
        &split,
        &split,
    ));
    out.push(compared(
        "bulk/parallel_two_bulks_vs_one_bulk",
        rows,
        &split,
        &joined,
    ));
    let bstack = |b1: usize| {
        let devs = vec![Dev::mos(B, 0, 1, 3).bulk(4), Dev::mos(B, 0, 3, 2).bulk(b1)];
        Circuit::new(6, devs).internal(3).compact()
    };
    let blong = Circuit::new(5, vec![Dev::mos(B, 0, 1, 2).sized(1000, 300).bulk(4)]).compact();
    let rows = &["LVS-045", "LVS-041"];
    out.push(compared(
        "bulk/stack_one_bulk_vs_long",
        rows,
        &bstack(4),
        &blong,
    ));
    out.push(compared(
        "bulk/stack_two_bulks_vs_long",
        rows,
        &bstack(5),
        &blong,
    ));

    // LVS-018: a symmetry resolved by parameter. Two nmos that trade places
    // under n1 <-> n2, n3 <-> n4, drawn 1000 and 2000 wide; the reference
    // writes the widths the other way round, which is the same circuit.
    let sym = |w0, w1| {
        let devs = vec![
            Dev::mos(N, 1, 0, 3).sized(w0, 150),
            Dev::mos(N, 2, 0, 4).sized(w1, 150),
        ];
        Circuit::new(5, devs)
    };
    let rows = &["LVS-018", "LVS-014"];
    out.push(compared(
        "symmetry/widths_swapped",
        &["LVS-018"],
        &sym(1000, 2000),
        &sym(2000, 1000),
    ));
    out.push(compared(
        "symmetry/widths_differ",
        rows,
        &sym(1000, 2000),
        &sym(1000, 1000),
    ));
    // F58's smallest cases: a class refinement cannot split, broken the
    // wrong way. The layout's own circuit with its cards reversed; and a
    // circuit whose one device is written 1.9 % wide.
    let lone = Circuit::new(
        3,
        vec![
            Dev::mos(N, 0, 0, 0),
            Dev::mos(N, 1, 1, 2),
            Dev::mos(N, 2, 1, 2),
        ],
    );
    let text = spice_ordered(&lone, &[2, 1, 0]);
    out.push(
        with_text(
            "symmetry/refinement_stall_reversed",
            &["LVS-018", "LVS-019"],
            draw(&lone),
            text,
        )
        .expect(Expect::Lvs(true))
        .known("F58"),
    );
    let cycle = Circuit::new(
        3,
        vec![
            Dev::mos(N, 0, 0, 1),
            Dev::mos(N, 1, 0, 2),
            Dev::mos(N, 2, 1, 2),
        ],
    );
    let mut cycle_wide = cycle.clone();
    cycle_wide.devs[0].w = 1019;
    let name = "symmetry/refinement_stall_by_parameter";
    out.push(compared(name, rows, &cycle, &cycle_wide).known("F58"));

    // LVS-016: the port order of the reference does not matter.
    let inv = Circuit::new(4, vec![Dev::mos(N, 0, 2, 1), Dev::mos(P, 0, 3, 1)]);
    let reordered = edited(
        &spice(&inv),
        ".subckt TOP n0 n1 n2 n3",
        ".subckt TOP n3 n1 n0 n2",
    );
    out.push(
        with_text("ports/reordered", &["LVS-016"], draw(&inv), reordered).expect(Expect::Lvs(true)),
    );

    // LVS-019: two cells nothing instantiates is no top to compare, and the
    // comparison refuses rather than guesses.
    let two_tops = format!("{}{}", spice(&inv), edited(&spice(&inv), "TOP", "OTHER"));
    out.push(
        with_text("verdict/ambiguous_top", &["LVS-019"], draw(&inv), two_tops)
            .expect(Expect::Lvs(false))
            .expect(Expect::Passes(false)),
    );
    out
}

/// The rows `check_layout` records from the layout alone (its rustdoc), and
/// device recognition's corner cases.
fn layout_rows() -> Vec<Fixture> {
    use Model::{N, R};
    let mut out = Vec::new();
    let one = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2)]);

    // LVS-006: an unlabelled track no terminal lands on floats; a labelled one
    // is a port and does not.
    let mut floating = one.clone();
    floating.names.push("n3".to_owned());
    floating.ports.push(false);
    out.push(
        compared(
            "checks/floating_net",
            &["LVS-006", "LVS-015"],
            &floating,
            &one,
        )
        .expect(Expect::rule("lvs.floating_net", vec![Finding::any()])),
    );
    let mut port = floating.clone();
    port.ports[3] = true;
    out.push(
        compared(
            "checks/unused_port_is_not_floating",
            &["LVS-006", "LVS-016"],
            &port,
            &port,
        )
        .expect(Expect::clean("lvs.floating_net")),
    );

    // LVS-001, LVS-002: one label on two nets is an open, not a join.
    let mut split = Circuit::new(4, vec![Dev::mos(N, 0, 1, 2), Dev::mos(N, 3, 1, 2)]);
    "n0".clone_into(&mut split.names[3]);
    let joined = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2), Dev::mos(N, 0, 1, 2)]);
    out.push(
        compared(
            "checks/label_on_two_nets",
            &["LVS-001", "LVS-002", "LVS-015"],
            &split,
            &joined,
        )
        .expect(Expect::rule("lvs.label_conflict", vec![Finding::any()])),
    );

    // F13, F14, LVS-001, LVS-005: two labels on one net is a short between
    // named nets, which must be reported, not abort the run.
    let shorted = draw(&one).label("met2_label", -800, track(0) + 100, "other");
    out.push(
        with_text(
            "checks/two_labels_on_one_net",
            &["LVS-001", "LVS-005"],
            shorted,
            spice(&one),
        )
        .expect(Expect::rule("lvs.net_seed_conflict", vec![Finding::any()])),
    );

    // LVS-004: a MOS recogniser with two terminals. Its source and drain
    // share a net, so the second diffusion is the first drawn twice and the
    // device is recognised with two terminals.
    let deck = format!(
        "{}layer tsdm = gds(20, 0)\nlayer gate_t = gate and tsdm\n\
         device mos gate_t model \"nmos2\" terminals [poly, diff_active]\n",
        full_deck()
    );
    let shorted = Circuit::new(2, vec![Dev::mos(N, 0, 1, 1)]);
    let mut layout = draw(&shorted);
    for shape in &mut layout.shapes {
        if shape.0 == "nsdm" {
            "tsdm".clone_into(&mut shape.0);
        }
    }
    let mut fixture = Fixture::new("lvs/checks/two_terminal_mos", &["LVS-004"], &deck, LVS)
        .layout(layout)
        .expect(Expect::rule("lvs.terminal_count", vec![Finding::any()]));
    fixture.reference = Some(spice(&shorted));
    out.push(fixture);

    // F32, LVS-004: a MOS drawn without its drain is malformed, and must be
    // reported rather than silently not be a device.
    let mut layout = draw(&one);
    layout.shapes.retain(|(layer, _)| layer != "diff");
    let layout = layout.rect("diff", 0, 0, SD + 150, 1000);
    out.push(
        with_text(
            "checks/mos_without_drain",
            &["LVS-004", "LVS-012"],
            layout,
            spice(&one),
        )
        .expect(Expect::rule("lvs.terminal_net", vec![Finding::any()]))
        .known("F32"),
    );

    // F33, LVS-004: a resistor pad drawn twice is one pad, whichever copy
    // comes first.
    let res = Circuit::new(2, vec![Dev::pins(R, &[0, 1])]);
    let (x0, y0, x1, y1) = pad(0, 0);
    let twice = (
        "pina".to_owned(),
        vec![(x0, y0), (x1, y0), (x1, y1), (x0, y1)],
    );
    let mut first = draw(&res);
    first.shapes.insert(0, twice.clone());
    let mut last = draw(&res);
    last.shapes.push(twice);
    let rows = &["LVS-004", "LVS-012"];
    out.push(
        with_text("checks/pad_drawn_twice_last", rows, last, spice(&res)).expect(Expect::Lvs(true)),
    );
    out.push(
        with_text("checks/pad_drawn_twice_first", rows, first, spice(&res))
            .expect(Expect::Lvs(true))
            .known("F33"),
    );

    // LVS-003: two unlabelled tracks joined only through `pwell`, a soft
    // layer, are one net held together by it; one tap into the well is not.
    // With `crossing`, the second stub passes under the first track with no
    // via, which is no join (F27).
    let deck = format!("{}rule soft soft_connection(pwell)\n", full_deck());
    let erc = Checks { erc: true, ..NONE };
    for (name, taps, crossing, known) in [
        ("checks/soft_connection", &[0, 1][..], false, None),
        (
            "checks/soft_connection_under_a_track",
            &[0, 1][..],
            true,
            Some("F27"),
        ),
        ("checks/one_tap_is_not_soft", &[0][..], false, None),
    ] {
        let mut layout = Layout::default().rect("pwell", 0, 0, 3000, 1000);
        for &net in taps {
            let x = 100 + 2500 * i64::try_from(net).expect("two taps");
            layout = stub(
                layout.rect("tap", x, 100, x + 300, 400),
                x,
                x + 300,
                100,
                net,
            );
            let (left, right) = if crossing {
                (-1000, 3000)
            } else {
                (x - 200, x + 500)
            };
            layout = layout.rect("met2", left, track(net), right, track(net) + 200);
        }
        let findings = if taps.len() == 2 {
            vec![Finding::any()]
        } else {
            Vec::new()
        };
        let fixture = Fixture::new(&format!("lvs/{name}"), &["LVS-003"], &deck, erc)
            .layout(layout)
            .expect(Expect::rule("soft", findings));
        out.push(match known {
            Some(finding) => fixture.known(finding),
            None => fixture,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The oracle on cases derived by hand from the documented semantics.
    #[test]
    fn the_oracle_agrees_with_hand_derivations() {
        use Model::{C, D, N, P, R};
        let inv = Circuit::new(4, vec![Dev::mos(N, 0, 1, 2), Dev::mos(P, 0, 3, 2)]);
        assert!(equivalent(&inv, &inv));
        let mut swapped = inv.clone();
        swapped.devs[0].pins.swap(1, 2);
        assert!(equivalent(&inv, &swapped), "source and drain swap");
        let mut reversed = inv.clone();
        reversed.devs.reverse();
        assert!(equivalent(&inv, &reversed), "order never matters");
        let mut short = inv.clone();
        short.devs[1].pins[1] = 1;
        assert!(!equivalent(&inv, &short.compact()), "a short");
        let mut wide = inv.clone();
        wide.devs[0].w = 1021;
        assert!(!equivalent(&inv, &wide), "2.1 % over");
        wide.devs[0].w = 1019;
        assert!(equivalent(&inv, &wide), "1.9 % over");
        let two = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2), Dev::mos(N, 0, 2, 1)]);
        let one = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(2000, 150)]);
        assert!(
            equivalent(&two, &one),
            "two in parallel are one twice as wide"
        );
        let stack = Circuit::new(4, vec![Dev::mos(N, 0, 1, 3), Dev::mos(N, 0, 3, 2)]);
        let long = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(1000, 300)]);
        assert!(!equivalent(&stack, &long), "a port is never consumed");
        assert!(
            equivalent(&stack.internal(3), &long),
            "a stack is one twice as long"
        );
        let ctx = |m, a, b| polar(Dev::pins(m, &[a, b]));
        assert!(
            !equivalent(&ctx(D, 0, 1), &ctx(D, 1, 0)),
            "a diode is ordered"
        );
        assert!(
            equivalent(&ctx(R, 0, 1), &ctx(R, 1, 0)),
            "a resistor is not"
        );
        let caps = Circuit::new(2, vec![Dev::pins(C, &[0, 1]), Dev::pins(C, &[0, 1])]);
        let cap = Circuit::new(2, vec![Dev::pins(C, &[0, 1])]);
        assert!(!equivalent(&caps, &cap), "two capacitors are not one");
        let m2 = Circuit::new(2, vec![Dev::pins(C, &[0, 1]).times(2)]);
        assert!(equivalent(&caps, &m2), "but they are one of m = 2");
        let top = Circuit::new(3, vec![Dev::mos(N, 0, 2, 1)]);
        let block = Circuit::new(3, vec![Dev::mos(P, 1, 2, 0)]);
        let flat = flatten(&top, &block, &[1, 0, 2]);
        assert_eq!(
            flat.devs[1].pins,
            vec![0, 2, 1],
            "the block lands on its ports"
        );
    }

    /// Counted independently by a brute force over every labelled circuit
    /// (a canonical form by trying every net renaming, in Python).
    #[test]
    fn the_enumeration_has_every_canonical_circuit() {
        assert_eq!(circuits().len(), 4223);
    }
}
