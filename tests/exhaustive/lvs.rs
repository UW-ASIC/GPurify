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
//! tolerance of `CompareOptions` and every count equal (F99). Net names
//! never take part (the `lvs` module docs), and neither does card order. It
//! is a brute force over every net bijection, which is affordable because the
//! circuits are small.
//!
//! Where the docs describe a defect rather than the intended semantics, the
//! oracle follows the intended one and the fixture is marked with the finding.
//! A diode's and a capacitor's ends are ordered (F15), a series merge crosses
//! a net that is not a port on either side (F12), and a reference `X`
//! instance is flattened (F1): those fixtures hold since B3, B4 and B2.
//! `nf=1` is one drawn finger, and a passive is sized by what the deck lets
//! the layout measure (F16): those hold since B6. Parallel passives keep their count (F20), `m`
//! multiplies a passive (F21), and a parameter is compared only where the
//! reference declares it (F22): those hold since B9; since B21 that is per
//! paired device, a card without a parameter stating nothing about it (F68).
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
/// `pwell`, and one passive or bipolar per kind, each a marker over pads. The
/// resistor states its sheet resistance and the capacitor its area and
/// fringe capacitance, so the layout's `r` and `c` follow ([`measured`]).
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
device resistor resm model \"rpoly\" terminals [pina, pina] sheet 100ohm
device capacitor capm model \"cmim\" terminals [pina, pinb] area_cap 1fF/um2 fringe_cap 100aF/um
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
    /// Whether the card writes `w` and `l`: a MOS card may leave either
    /// out, and is then sized by neither (testing-plan F83, F84).
    writes: (bool, bool),
    /// The card's `m`; 1 writes none.
    m: u32,
    /// An `area=` the card declares, in nm². The layout always has its
    /// marker's, and it is compared only where the reference declares one.
    area: Option<i64>,
    /// A resistor's or capacitor's value, `r` or `c` in SI, written
    /// positionally between the nets and the model.
    value: Option<f64>,
    /// Any other `name=value` the card states, in SI. Each is compared,
    /// with the value, against what the layout measures ([`measured`]).
    params: Vec<(&'static str, f64)>,
}

impl Dev {
    /// A MOS of 1000 / 150 nm.
    fn mos(model: Model, g: usize, s: usize, d: usize) -> Self {
        Dev {
            model,
            pins: vec![g, s, d],
            w: 1000,
            l: 150,
            writes: (true, true),
            m: 1,
            area: None,
            value: None,
            params: Vec::new(),
        }
    }

    /// A resistor, capacitor, diode or bipolar on `pins`.
    fn pins(model: Model, pins: &[usize]) -> Self {
        Dev {
            model,
            pins: pins.to_vec(),
            w: 0,
            l: 0,
            writes: (false, false),
            m: 1,
            area: None,
            value: None,
            params: Vec::new(),
        }
    }

    fn sized(mut self, w: i64, l: i64) -> Self {
        self.w = w;
        self.l = l;
        self
    }

    /// The card writes `w` only where `w`, `l` only where `l`.
    fn writes(mut self, w: bool, l: bool) -> Self {
        self.writes = (w, l);
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

    fn value(mut self, si: f64) -> Self {
        self.value = Some(si);
        self
    }

    fn param(mut self, name: &'static str, si: f64) -> Self {
        self.params.push((name, si));
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
            let w = if dev.writes.0 {
                format!(" w={}n", dev.w)
            } else {
                String::new()
            };
            let l = if dev.writes.1 {
                format!(" l={}n", dev.l)
            } else {
                String::new()
            };
            write!(
                out,
                "M{index} {open}{} {} {} {bulk}{close} {}{w}{l}",
                n(2),
                n(0),
                n(1),
                dev.model.name(),
            )
        }
        Model::R | Model::C | Model::D => {
            let letter = dev.model.letter();
            let value = dev.value.map_or(String::new(), |v| format!(" {v:e}"));
            assert!(
                !spectre || value.is_empty(),
                "Spectre has no positional value"
            );
            write!(
                out,
                "{letter}{index} {open}{} {}{close}{value} {}",
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
    for (name, value) in &dev.params {
        let _ = write!(out, " {name}={value:e}");
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
/// dialect (LVS-071). Every model gets a `model` card naming its master: a
/// primitive master with none is the deck's one recogniser of its kind
/// (F97), and the deck has four MOS.
fn spectre(c: &Circuit) -> String {
    let mut out = String::from(
        "// generated by tests/exhaustive/lvs.rs\n\
         model nmos bsim4\nmodel pmos bsim4\nmodel nmos_hvt bsim4\n\
         model nmosb bsim4\nmodel rpoly resistor\nmodel cmim capacitor\n\
         model dpn diode\nmodel npn bjt\nsubckt TOP",
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

/// A device after reduction: `w`, `l` in nm where it is sized by them,
/// summed by merges, and how many identical devices in parallel it stands
/// for, which is how a device with no width to sum keeps its count (F20,
/// F21, F83).
#[derive(Debug, Clone)]
struct Reduced {
    model: Model,
    pins: Vec<usize>,
    w: Option<f64>,
    l: Option<f64>,
    mult: u32,
    area: Option<i64>,
    value: Option<f64>,
    params: Vec<(&'static str, f64)>,
    /// A MOS's [`DIFFUSIONS`] in SI, where stated: drawn, or written.
    sd: [Option<f64>; 4],
}

/// A MOS's source and drain diffusion area and perimeter, in the order a
/// merge or a swapped card trades `as` with `ad` and `ps` with `pd` (F16).
const DIFFUSIONS: [&str; 4] = ["as", "ad", "ps", "pd"];

/// What the layout measures on a drawn MOS's diffusion [`DIFFUSIONS`]`[i]`,
/// in SI: [`draw_mos`]'s source and drain, each [`SD`] by `w` nm, of area
/// `SD · w` and perimeter `2 (SD + w)`. Each device has a column of its own,
/// so no diffusion is shared.
#[allow(clippy::cast_precision_loss, reason = "nanometre sizes are small")]
fn drawn_diffusion(i: usize, w: i64) -> f64 {
    if i < 2 {
        (SD * w) as f64 * 1e-18
    } else {
        (2 * (SD + w)) as f64 * 1e-9
    }
}

/// Whether `b`'s source is on `a`'s drain net, `a`'s nets read through
/// `map`: `b`'s `as` is then `a`'s `ad`, and so on. A MOS whose source and
/// drain share a net is never crossed.
fn crossed(a: &Reduced, b: &Reduced, map: impl Fn(usize) -> usize) -> bool {
    a.model.is_mos() && a.pins[1] != a.pins[2] && map(a.pins[2]) == b.pins[1]
}

/// The names deck.md gives `lvs permute` a pin of `model`, in [`Dev::pins`]
/// order.
fn pin_names(model: Model) -> &'static [&'static str] {
    match model {
        Model::N | Model::P | Model::H | Model::B => &["gate", "source", "drain", "bulk"],
        Model::R => &["end_a", "end_b"],
        Model::C => &["top", "bottom"],
        Model::D => &["anode", "cathode"],
        Model::Q => &["base", "emitter", "collector"],
    }
}

/// Whether two devices of `model` land on the same nets role for role, up
/// to exchanging the pins of one [`Controls::classes`] class: by default a
/// MOS's source and drain either way round and a resistor's ends either way,
/// everything else in order. `a`'s nets are read through `map`.
fn same_pins(
    model: Model,
    (a, b): (&[usize], &[usize]),
    map: impl Fn(usize) -> usize,
    controls: &Controls,
) -> bool {
    a.len() == b.len()
        && controls.classes(model).iter().all(|class| {
            let on = |pins: &[usize], read: &dyn Fn(usize) -> usize| {
                let mut nets: Vec<usize> = class
                    .iter()
                    .filter(|&&k| k < pins.len())
                    .map(|&k| read(pins[k]))
                    .collect();
                nets.sort_unstable();
                nets
            };
            on(a, &map) == on(b, &|n| n)
        })
}

/// The parameter names a reference's cards state, per model: what the
/// layout is measured on, since a measure no card of the model declares is
/// dropped before reduction (F22).
struct Declared(BTreeSet<(Model, &'static str)>);

impl Declared {
    fn of(reference: &Circuit) -> Self {
        let mut names = BTreeSet::new();
        for d in &reference.devs {
            let primary = match d.model {
                Model::C => "c",
                _ => "r",
            };
            let sizes = [(d.writes.0, "w"), (d.writes.1, "l")];
            let stated = sizes
                .into_iter()
                .filter(|&(written, _)| written && d.model.is_mos())
                .map(|(_, name)| name)
                .chain(d.area.map(|_| "area"))
                .chain(d.value.map(|_| primary))
                .chain(d.params.iter().map(|&(name, _)| name));
            names.extend(stated.map(|name| (d.model, name)));
        }
        Declared(names)
    }

    fn has(&self, model: Model, name: &'static str) -> bool {
        self.0.contains(&(model, name))
    }
}

/// The documented reductions to a fixed point, parallel first. A MOS is
/// sized by `w` and `l` where its card writes them, or, `drawn`, where some
/// reference card of its model does:
///
/// - **multiplier:** a MOS's `m` multiplies its `W`; any other device's `m`,
///   a MOS with no `W` included, is that many in parallel;
/// - **parallel:** devices of one model on the same nets role for role become
///   one; a MOS with `W` needs its other sizes equal and sums `W`, anything
///   else needs its parameters equal and sums its count;
/// - **series** (MOS only): two devices that both state `L`, with gates (and
///   bulks) on one net and equal `W` and count, whose channels meet at a net
///   that is not a port and that no other terminal touches, become one with
///   `L` summed; the net is consumed.
///
/// A net no terminal lands on survives only as a port: a floating shape is
/// not a node, and SPICE cannot even write one. Under `controls`, the pins a
/// parallel merge may exchange are [`Controls::classes`], and an asymmetric
/// transistor never merges in series.
fn reduce(c: &Circuit, declared: &Declared, drawn: bool, controls: &Controls) -> Reduction {
    #[allow(clippy::cast_precision_loss, reason = "nanometre sizes are small")]
    let mut devs: Vec<Reduced> = c
        .devs
        .iter()
        .map(|d| {
            let sized = |written: bool, name, value: i64| {
                let stated = if drawn {
                    declared.has(d.model, name)
                } else {
                    written
                };
                (d.model.is_mos() && stated).then_some(value as f64)
            };
            let (w, l) = (sized(d.writes.0, "w", d.w), sized(d.writes.1, "l", d.l));
            // A drawn device is one device; only a card counts more.
            let m = if drawn { 1 } else { d.m };
            let mut sd = [None; 4];
            let mut params = d.params.clone();
            if d.model.is_mos() {
                for (i, name) in DIFFUSIONS.into_iter().enumerate() {
                    sd[i] = if drawn {
                        declared.has(d.model, name).then(|| drawn_diffusion(i, d.w))
                    } else {
                        params.iter().find(|p| p.0 == name).map(|p| p.1)
                    };
                }
                params.retain(|p| !DIFFUSIONS.contains(&p.0));
            }
            // `m` folds into `W` and the diffusions where there is a `W`.
            let (w, mult) = match w {
                Some(w) => {
                    for v in sd.iter_mut().flatten() {
                        *v *= f64::from(m);
                    }
                    (Some(w * f64::from(m)), 1)
                }
                None => (None, m),
            };
            // Relaxed, a resistor's or capacitor's value is what the layout
            // measures where a card declares it, or what the card writes, and
            // `m` folds into it: `r/m`, `m c`.
            let (value, mult) = match controls.value_law(d.model) {
                Some((name, harmonic)) => {
                    let value = if drawn {
                        declared
                            .has(d.model, name)
                            .then(|| measured(d.model, name))
                            .flatten()
                    } else {
                        d.value
                    };
                    let folded = |v: f64| {
                        if harmonic {
                            v / f64::from(mult)
                        } else {
                            v * f64::from(mult)
                        }
                    };
                    match value {
                        Some(v) => (Some(folded(v)), 1),
                        None => (None, mult),
                    }
                }
                None => (d.value, mult),
            };
            Reduced {
                model: d.model,
                pins: d.pins.clone(),
                w,
                l,
                mult,
                area: d.area,
                value,
                params,
                sd,
            }
        })
        .collect();
    let mut alive = vec![true; c.nets()];
    'pass: loop {
        for i in 0..devs.len() {
            for j in i + 1..devs.len() {
                let (a, b) = (&devs[i], &devs[j]);
                // A `W` sums the diffusions end by end, all four or none
                // stated; without one they must be the same, as any value.
                let stated = a.sd.iter().flatten().count();
                let presence = |r: &Reduced| r.sd.map(|v| v.is_some());
                #[allow(clippy::float_cmp, reason = "equal means drawn or written the same")]
                let diffusions = match a.w {
                    Some(_) => presence(a) == presence(b) && (stated == 0 || stated == 4),
                    None => a.sd == b.sd,
                };
                // Relaxed, two values of one law combine instead of agreeing.
                let law = controls
                    .value_law(a.model)
                    .filter(|_| a.value.is_some() && b.value.is_some());
                #[allow(clippy::float_cmp, reason = "equal means drawn or written the same")]
                let params = a.l == b.l
                    && a.w.is_some() == b.w.is_some()
                    && diffusions
                    && a.area == b.area
                    && (a.value == b.value || law.is_some())
                    && a.params == b.params;
                if a.model == b.model
                    && params
                    && same_pins(a.model, (&a.pins, &b.pins), |n| n, controls)
                {
                    let across = usize::from(crossed(a, b, |n| n));
                    let b = devs.remove(j);
                    let a = &mut devs[i];
                    match (&mut a.w, b.w) {
                        _ if law.is_some() => {
                            let harmonic = law.is_some_and(|(_, harmonic)| harmonic);
                            a.value = a.value.zip(b.value).map(|(x, y)| {
                                if harmonic {
                                    1.0 / (1.0 / x + 1.0 / y)
                                } else {
                                    x + y
                                }
                            });
                        }
                        (Some(w), Some(more)) => {
                            *w += more;
                            for k in 0..4 {
                                a.sd[k] = a.sd[k].zip(b.sd[k ^ across]).map(|(x, y)| x + y);
                            }
                        }
                        _ => a.mult += b.mult,
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
                // Relaxed, deck.md's: two resistors or capacitors stating
                // their value chain through a net only they touch, no port,
                // their far ends two other nets; `r` adds and `c` combines
                // harmonically. Ordered plates chain plate to plate. The
                // fixtures state no other parameter on such a passive, so
                // this oracle refuses one that does.
                let passive = i != j
                    && a.model == b.model
                    && matches!(a.model, Model::R | Model::C)
                    && controls.value_law(a.model).is_some()
                    && a.value.is_some()
                    && b.value.is_some()
                    && a.params.is_empty()
                    && b.params.is_empty()
                    && a.area.is_none()
                    && b.area.is_none();
                if passive {
                    let ordered = controls.classes(a.model).len() == 4;
                    for ea in 0..2 {
                        for eb in 0..2 {
                            let x = a.pins[ea];
                            let (far_a, far_b) = (a.pins[1 - ea], b.pins[1 - eb]);
                            if x != b.pins[eb]
                                || c.ports[x]
                                || touches(&devs, x) != 2
                                || far_a == x
                                || far_b == x
                                || far_a == far_b
                                || (ordered && ea == eb)
                            {
                                continue;
                            }
                            let (va, vb) = (a.value.unwrap_or(0.0), b.value.unwrap_or(0.0));
                            let value = if a.model == Model::R {
                                va + vb
                            } else {
                                1.0 / (1.0 / va + 1.0 / vb)
                            };
                            let mut pins = vec![far_a, far_b];
                            if ordered {
                                pins[1 - ea] = far_a;
                                pins[ea] = far_b;
                            }
                            devs[i].pins = pins;
                            devs[i].value = Some(value);
                            devs.remove(j);
                            alive[x] = false;
                            continue 'pass;
                        }
                    }
                }
                #[allow(clippy::float_cmp, reason = "equal means drawn or written the same")]
                let mergeable = i != j
                    && a.model.is_mos()
                    && controls.series(a.model)
                    && a.model == b.model
                    && a.pins[0] == b.pins[0]
                    && a.pins[3..] == b.pins[3..]
                    && a.l.is_some()
                    && b.l.is_some()
                    && a.sd == [None; 4]
                    && b.sd == [None; 4]
                    && a.w == b.w
                    && a.mult == b.mult;
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
                            devs[i].l = devs[i].l.zip(l).map(|(a, b)| a + b);
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
        names: c.names.clone(),
        ports: c.ports.clone(),
    }
}

/// A circuit reduced: its devices, the nets that survive, how many nets it
/// had, and its devices' models sorted, the cheapest test there is; and its
/// nets' names and which are ports (labelled, in a layout).
struct Reduction {
    devs: Vec<Reduced>,
    live: Vec<usize>,
    nets: usize,
    models: Vec<Model>,
    names: Vec<String>,
    ports: Vec<bool>,
}

/// `|a - b| <= tol * max(|a|, |b|)`, the definition in `CompareOptions`.
fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= TOLERANCE * a.abs().max(b.abs())
}

/// An absolute tolerance as the deck writes it and in SI, when stated.
type Absolute = Option<(&'static str, f64)>;

/// The deck's `lvs` statements a fixture states, as the oracle reads them
/// from deck.md ("LVS controls"), and the deck lines that state them.
#[derive(Debug, Clone, Default)]
struct Controls {
    /// `lvs tolerance`: model, parameter, the relative part, and the
    /// absolute part as the deck writes it and in SI.
    tolerance: Vec<(Model, &'static str, f64, Absolute)>,
    /// `lvs ignore_parameter`: model and parameter.
    ignored: Vec<(Model, &'static str)>,
    /// `lvs asymmetric`: MOS models whose source and drain do not swap.
    asymmetric: Vec<Model>,
    /// `lvs permute`: model and two pin positions in [`Dev::pins`] order.
    permuted: Vec<(Model, usize, usize)>,
    /// `lvs ignore`: models whose devices are left out on both sides.
    left_out: Vec<Model>,
    /// `lvs ignore_shorted`: models whose dummies, every pin on one net,
    /// are left out on both sides.
    dummies_out: Vec<Model>,
    /// `lvs ports_by_name`: each reference port pairs only with the layout
    /// net its name labels.
    ports_by_name: bool,
    /// `lvs topology relaxed`: parallel resistors and capacitors stating
    /// their value combine by its law.
    relaxed: bool,
    /// `lvs max_res`: as the deck writes it, and in ohms.
    max_res: Option<(&'static str, f64)>,
    /// `lvs min_caps`: as the deck writes it, and in farads.
    min_caps: Option<(&'static str, f64)>,
    /// `lvs same_nets`: a layout label and a reference net name.
    same_nets: Vec<(&'static str, &'static str)>,
}

impl Controls {
    /// A tolerance row: `relative` as a fraction, `absolute` as the deck
    /// writes it and in SI.
    fn tolerance(
        mut self,
        model: Model,
        param: &'static str,
        relative: f64,
        absolute: Option<(&'static str, f64)>,
    ) -> Self {
        self.tolerance.push((model, param, relative, absolute));
        self
    }

    /// An `lvs ignore_parameter` row.
    fn ignore(mut self, model: Model, param: &'static str) -> Self {
        self.ignored.push((model, param));
        self
    }

    /// An `lvs asymmetric` row.
    fn asymmetric(mut self, model: Model) -> Self {
        self.asymmetric.push(model);
        self
    }

    /// The value a relaxed parallel merge combines on `model`, and whether
    /// harmonically: a resistor's `r` (`1 / Σ 1/r`), a capacitor's `c`
    /// (added), deck.md's; `None` under the strict policy and for any other
    /// model.
    fn value_law(&self, model: Model) -> Option<(&'static str, bool)> {
        match model {
            Model::R if self.relaxed => Some(("r", true)),
            Model::C if self.relaxed => Some(("c", false)),
            _ => None,
        }
    }

    /// An `lvs ignore` row.
    fn leave_out(mut self, model: Model) -> Self {
        self.left_out.push(model);
        self
    }

    /// An `lvs ignore_shorted` row.
    fn leave_out_dummies(mut self, model: Model) -> Self {
        self.dummies_out.push(model);
        self
    }

    /// `c` without the devices the controls leave out, as if never drawn
    /// or written: every one of an ignored model, each dummy (every pin
    /// on one net, [`Dev::pins`] holding exactly the pins compared) of a
    /// model ignored when shorted, and, deck.md's `max_res` and `min_caps`,
    /// each resistor above the one and capacitor below the other, its
    /// value what was drawn ([`measured`]) or what the card writes. Its
    /// nets stay, and [`reduce`] keeps only those a device or a port holds.
    fn kept(&self, c: &Circuit, drawn: bool) -> Circuit {
        let mut out = c.clone();
        out.devs.retain(|d| {
            let dummy = d.pins.iter().all(|&p| p == d.pins[0]);
            let value = |name| {
                if drawn {
                    measured(d.model, name)
                } else {
                    d.value
                }
            };
            let open = match d.model {
                Model::R => self
                    .max_res
                    .zip(value("r"))
                    .is_some_and(|((_, limit), r)| r > limit),
                Model::C => self
                    .min_caps
                    .zip(value("c"))
                    .is_some_and(|((_, limit), c)| c < limit),
                _ => false,
            };
            !(open
                || self.left_out.contains(&d.model)
                || dummy && self.dummies_out.contains(&d.model))
        });
        out
    }

    /// An `lvs permute` row: pins at positions `a` and `b` of [`Dev::pins`].
    fn permute(mut self, model: Model, a: usize, b: usize) -> Self {
        self.permuted.push((model, a, b));
        self
    }

    /// The pin positions of `model` (in [`Dev::pins`] order) as classes of
    /// interchangeable pins, deck.md's: a MOS's source and drain (1, 2)
    /// unless the model is asymmetric, a resistor's ends (0, 1), joined with
    /// every `lvs permute` pair of the model and closed under chaining.
    fn classes(&self, model: Model) -> Vec<Vec<usize>> {
        let mut class: Vec<usize> = (0..4).collect();
        let mut join = |a: usize, b: usize| {
            let (keep, gone) = (class[a].min(class[b]), class[a].max(class[b]));
            for c in &mut class {
                if *c == gone {
                    *c = keep;
                }
            }
        };
        if model.is_mos() && !self.asymmetric.contains(&model) {
            join(1, 2);
        }
        if model == Model::R {
            join(0, 1);
        }
        for &(m, a, b) in &self.permuted {
            if m == model {
                join(a, b);
            }
        }
        (0..4)
            .filter(|&k| class[k] == k)
            .map(|k| (0..4).filter(|&p| class[p] == k).collect())
            .collect()
    }

    /// Whether transistors of `model` merge in series: only while their
    /// classes are the default ones, the channel the only pair.
    fn series(&self, model: Model) -> bool {
        self.classes(model) == [vec![0], vec![1, 2], vec![3]]
    }

    /// `c` with every parameter `lvs ignore_parameter` names dropped from
    /// its cards. Dropped from both sides is the same thing: the layout is
    /// measured only on what the reference's cards declare.
    fn strip(&self, c: &Circuit) -> Circuit {
        let mut out = c.clone();
        for dev in &mut out.devs {
            let model = dev.model;
            let ignored = |name: &str| self.ignored.iter().any(|&(m, n)| m == model && n == name);
            dev.writes.0 &= !ignored("w");
            dev.writes.1 &= !ignored("l");
            if ignored("area") {
                dev.area = None;
            }
            if ignored(if model == Model::C { "c" } else { "r" }) {
                dev.value = None;
            }
            dev.params.retain(|&(name, _)| !ignored(name));
        }
        out
    }

    /// The deck lines stating these controls.
    fn deck(&self) -> String {
        let mut out = String::new();
        for &(model, param) in &self.ignored {
            let _ = writeln!(out, "lvs ignore_parameter \"{}\" {param}", model.name());
        }
        for &model in &self.asymmetric {
            let _ = writeln!(out, "lvs asymmetric \"{}\"", model.name());
        }
        for &model in &self.left_out {
            let _ = writeln!(out, "lvs ignore \"{}\"", model.name());
        }
        for &model in &self.dummies_out {
            let _ = writeln!(out, "lvs ignore_shorted \"{}\"", model.name());
        }
        if self.ports_by_name {
            out.push_str("lvs ports_by_name\n");
        }
        if self.relaxed {
            out.push_str("lvs topology relaxed\n");
        }
        if let Some((text, _)) = self.max_res {
            let _ = writeln!(out, "lvs max_res {text}");
        }
        if let Some((text, _)) = self.min_caps {
            let _ = writeln!(out, "lvs min_caps {text}");
        }
        for &(layout, reference) in &self.same_nets {
            let _ = writeln!(out, "lvs same_nets \"{layout}\" \"{reference}\"");
        }
        for &(model, a, b) in &self.permuted {
            let names = pin_names(model);
            let _ = writeln!(
                out,
                "lvs permute \"{}\" {} {}",
                model.name(),
                names[a],
                names[b]
            );
        }
        for &(model, param, relative, absolute) in &self.tolerance {
            let _ = write!(out, "lvs tolerance \"{}\" {param}", model.name());
            if relative > 0.0 {
                let _ = write!(out, " relative {relative}");
            }
            if let Some((text, _)) = absolute {
                let _ = write!(out, " absolute {text}");
            }
            out.push('\n');
        }
        out
    }

    /// Whether `a` and `b`, values of `param` on `model` in a unit `si` times
    /// SI's, agree: under the model's row, `|a - b| <= absolute + relative *
    /// max(|a|, |b|)` with the parts adding as deck.md says; with no row,
    /// [`close`].
    fn close(&self, model: Model, param: &str, (a, b): (f64, f64), si: f64) -> bool {
        match self.tolerance.iter().find(|t| t.0 == model && t.1 == param) {
            None => close(a, b),
            Some(&(_, _, relative, absolute)) => {
                let absolute = absolute.map_or(0.0, |(_, value)| value);
                (a - b).abs() * si <= absolute + relative * a.abs().max(b.abs()) * si
            }
        }
    }
}

/// Whether layout device `a`, its nets renamed by `map`, is reference device
/// `b` under `controls`. An area is compared only where the reference
/// declares one (F22).
fn pairs(a: &Reduced, b: &Reduced, map: &[usize], controls: &Controls) -> bool {
    if a.model != b.model || a.mult != b.mult {
        return false;
    }
    if !same_pins(a.model, (&a.pins, &b.pins), |n| map[n], controls) {
        return false;
    }
    // The layout side always has its marker's area: what was drawn.
    let drawn = match a.model {
        Model::Q => BJT_AREA,
        _ => PIN2_AREA,
    };
    let model = b.model;
    #[allow(clippy::cast_precision_loss, reason = "nanometre areas are small")]
    let area = match b.area {
        Some(declared) => controls.close(
            model,
            "area",
            (a.area.unwrap_or(drawn) as f64, declared as f64),
            1e-18,
        ),
        None => true,
    };
    // Every other value the card states, against what was drawn; one the
    // layout cannot measure never agrees.
    let primary = match b.model {
        Model::C => "c",
        _ => "r",
    };
    let stated = b
        .params
        .iter()
        .copied()
        .chain(b.value.map(|v| (primary, v)));
    // Relaxed, the layout's value is the one its merges combined.
    let law_value = controls
        .value_law(model)
        .and_then(|(name, _)| a.value.map(|v| (name, v)));
    let drawn_value = |name: &str| match law_value {
        Some((law, v)) if law == name => Some(v),
        _ => measured(b.model, name),
    };
    let sized = stated.into_iter().all(|(name, v)| {
        drawn_value(name).is_some_and(|d| controls.close(model, name, (d, v), 1.0))
    });
    // A size the card writes, against the layout's, which measures it since
    // the card's model declares it, in nm (`si` 1e-9); a diffusion at its
    // channel end, in SI.
    let size = |name: &str, (a, b): (Option<f64>, Option<f64>), si: f64| {
        b.is_none_or(|b| a.is_some_and(|a| controls.close(model, name, (a, b), si)))
    };
    let across = usize::from(crossed(a, b, |n| map[n]));
    let diffusions = (0..4).all(|k| size(DIFFUSIONS[k], (a.sd[k ^ across], b.sd[k]), 1.0));
    area && sized && size("w", (a.w, b.w), 1e-9) && size("l", (a.l, b.l), 1e-9) && diffusions
}

/// What the layout measures on a drawn passive or bipolar of `model`, in SI,
/// from [`draw_pins`]'s marker, 800 (1600 for a bipolar) by 400 nm, and
/// [`EXTRA_DECK`]'s coefficients: the marker's `area` and `perim`; a
/// resistor's body along its pads, `l` 800 nm, across them `w` 400 nm, and
/// `r` = 100 ohm/sq x 800 / 400 = 200 ohm; a capacitor's `c` = 1 fF/um² x
/// 0.32 um² + 0.1 fF/um x 2.4 um = 0.56 fF; a bipolar's emitter, its middle
/// pad 400 nm square, `ae` 0.16 um² and `pe` 1.6 um. Nothing else.
fn measured(model: Model, name: &str) -> Option<f64> {
    let (along, across) = match model {
        Model::Q => (1600e-9, 400e-9),
        _ => (800e-9, 400e-9),
    };
    let (area, perim) = (along * across, 2.0 * (along + across));
    match (model, name) {
        (_, "area") => Some(area),
        (_, "perim") => Some(perim),
        (Model::R, "l") => Some(along),
        (Model::R, "w") => Some(across),
        (Model::R, "r") => Some(100.0 * along / across),
        (Model::C, "c") => Some(1e-3 * area + 1e-10 * perim),
        // The emitter, the middle pad, 400 nm square.
        (Model::Q, "ae") => Some(400e-9 * 400e-9),
        (Model::Q, "pe") => Some(1600e-9),
        _ => None,
    }
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
fn assign(
    (a, b): (&[Reduced], &[Reduced]),
    (map, controls): (&[usize], &Controls),
    used: &mut [bool],
    from: usize,
) -> bool {
    let Some(dev) = a.get(from) else {
        return true;
    };
    for j in 0..b.len() {
        if !used[j] && pairs(dev, &b[j], map, controls) {
            used[j] = true;
            if assign((a, b), (map, controls), used, from + 1) {
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
    equivalent_under(layout, reference, &Controls::default())
}

/// [`equivalent`] under the deck's `lvs` statements.
fn equivalent_under(layout: &Circuit, reference: &Circuit, controls: &Controls) -> bool {
    let reference = controls.strip(reference);
    let declared = Declared::of(&reference);
    let (layout, reference) = (
        controls.kept(layout, true),
        controls.kept(&reference, false),
    );
    matches(
        &reduce(&layout, &declared, true, controls),
        &reduce(&reference, &declared, false, controls),
        controls,
    )
}

/// Whether some bijection of `a`'s surviving nets onto `b`'s pairs every
/// device.
fn matches(a: &Reduction, b: &Reduction, controls: &Controls) -> bool {
    if a.live.len() != b.live.len() || a.models != b.models {
        return false;
    }
    // Under `lvs ports_by_name`, deck.md's: each reference port pairs with
    // the layout net its name labels, which must exist.
    let port_of = |name: &str| (0..b.nets).find(|&r| b.ports[r] && b.names[r] == name);
    let labelled = |r: usize| (0..a.nets).find(|&k| a.ports[k] && a.names[k] == b.names[r]);
    if controls.ports_by_name && (0..b.nets).any(|r| b.ports[r] && labelled(r).is_none()) {
        return false;
    }
    // Under `lvs same_nets`, deck.md's: the layout net labelled with the
    // row's first name pairs with the reference net of its second, and a
    // row only one side has a net for is unpaired.
    let rows: Vec<(Option<usize>, Option<usize>)> = controls
        .same_nets
        .iter()
        .map(|&(la, rb)| {
            let layout = a
                .live
                .iter()
                .copied()
                .find(|&k| a.ports[k] && a.names[k] == la);
            let reference = b.live.iter().copied().find(|&r| b.names[r] == rb);
            (layout, reference)
        })
        .collect();
    if rows.iter().any(|row| row.0.is_some() != row.1.is_some()) {
        return false;
    }
    let mut map = vec![usize::MAX; a.nets];
    permutations(a.live.len()).iter().any(|perm| {
        for (i, &k) in a.live.iter().enumerate() {
            map[k] = b.live[perm[i]];
        }
        let same = rows
            .iter()
            .all(|&(k, r)| k.zip(r).is_none_or(|(k, r)| map[k] == r));
        let named = same
            && (!controls.ports_by_name
                || a.live
                    .iter()
                    .all(|&k| !a.ports[k] || port_of(&a.names[k]).is_none_or(|r| map[k] == r)));
        let used = &mut vec![false; b.devs.len()];
        named && assign((&a.devs, &b.devs), (&map, controls), used, 0)
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

/// The circuit against its own reference, its cards reversed, and its faults,
/// deduplicated up to isomorphism (the source/drain swaps are kept, since
/// they differ only in text).
///
/// With `pick`, the faults are thinned: every fault whose reference still
/// matches is kept, since that is where a false mismatch hides, and of those
/// that must mismatch, one per kind, drawn from `pick`. Without it, all.
fn enumerated(c: &Circuit, mut pick: Option<Rng>) -> Vec<Fixture> {
    let reduced = reduce(c, &Declared::of(c), true, &Controls::default());
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
        let matched = equivalent(c, &r);
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
            fixture
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
    out.extend(controlled());
    out.extend(layout_rows());
    out.extend(verilog_tops().into_iter().map(|top| top.fixture));
    out
}

/// One structural Verilog reference over a SPICE cell (LVS-075): the
/// fixture, the cell library and the Verilog as `GPurify` reads them, and
/// the flat circuit the drawing and the oracle use.
struct VerilogTop {
    fixture: Fixture,
    library: String,
    /// The Verilog with the top given one more port, `sub`, wired to every
    /// instance's, for Netgen's reading of the library through `for_netgen`
    /// in [`netgen`], which puts every three-terminal bulk there.
    verilog_with_sub: String,
    drawn: Circuit,
    flat: Circuit,
}

/// LVS-075: a drawn chain of two inverters against a Verilog top placing
/// the SPICE cell `BLK` (an inverter, ports `n0` in, `n1` out, `n2` and
/// `n3` its rails) twice, by name and in order, and through a bus and an
/// `assign`; and two faults, the second inverter's input moved to `n0`, and
/// the first's output left open. The oracle compares the drawing with what the
/// Verilog means flat ([`flatten`], each instance in turn), so a
/// hierarchical reference must equal flattening it.
fn verilog_tops() -> Vec<VerilogTop> {
    use Model::{N, P};
    let block = Circuit::new(4, vec![Dev::mos(N, 0, 2, 1), Dev::mos(P, 0, 3, 1)]);
    let mut top = Circuit::new(4, Vec::new());
    top.names.push("m".to_owned());
    top.ports.push(false);
    // The chain, flat: `u0` from n0 to m, `u1` on `second`. Every net of
    // the block is a port, so flattening names no inner net.
    let chain =
        |second: [usize; 4]| flatten(&flatten(&top, &block, &[0, 4, 2, 3]), &block, &second);
    let drawn = chain([4, 1, 2, 3]);
    let mut library = String::from("* generated by tests/exhaustive/lvs.rs\n");
    subckt(&mut library, "BLK", &block, &[0, 1]);
    library.push_str(".ends\n");
    // Netgen reads no connection by position ("Ignoring subcircuit with no
    // pin names", netgen `base/verilog.c`), so its copy names every one:
    // `BLK u1 (a, b, c, d SUB);` becomes `.n0(a), .n1(b), ...`.
    let named = |body: &str| -> String {
        body.lines()
            .map(|line| match line.split_once(" (") {
                Some((head, rest))
                    if head.trim_start().starts_with("BLK") && !rest.contains('.') =>
                {
                    let inside = rest.trim_end_matches(");").replace(" SUB", ", .SUB");
                    let mut pins = Vec::new();
                    for (k, net) in inside.split(", ").enumerate() {
                        pins.push(if net == ".SUB" {
                            net.to_owned()
                        } else {
                            format!(".n{k}({net})")
                        });
                    }
                    format!("{head} ({});\n", pins.join(", "))
                }
                _ => format!("{line}\n"),
            })
            .collect()
    };
    let module = |body: &str, sub: bool| {
        let body = if sub { named(body) } else { body.to_owned() };
        let (port, wire) = if sub {
            (", sub", ", .sub(sub)")
        } else {
            ("", "")
        };
        format!(
            "module TOP (n0, n1, n2, n3{port});\n  inout n0, n1, n2, n3{port};\n{}endmodule\n",
            body.replace(", .SUB", wire)
                .replace(" SUB)", if sub { ", sub)" } else { ")" })
        )
    };
    let cases: [(&str, &str, Circuit); 4] = [
        (
            "by_name_and_in_order",
            "  wire m;\n  BLK u0 (.n1(m), .n0(n0), .n2(n2), .n3(n3), .SUB);\n  BLK u1 (m, n1, n2, n3 SUB);\n",
            chain([4, 1, 2, 3]),
        ),
        (
            "bus_and_assign",
            "  wire [1:0] w;\n  assign w[0] = n0;\n  BLK u0 (.n0(w[0]), .n1(w[1]), .n2(n2), .n3(n3), .SUB);\n  BLK u1 ({w[1]}, n1, n2, n3 SUB);\n",
            chain([4, 1, 2, 3]),
        ),
        (
            "second_input_moved",
            "  wire m;\n  BLK u0 (.n0(n0), .n1(m), .n2(n2), .n3(n3), .SUB);\n  BLK u1 (n0, n1, n2, n3 SUB);\n",
            chain([0, 1, 2, 3]),
        ),
        (
            "first_output_open",
            "  wire m;\n  BLK u0 (.n0(n0), .n1(), .n2(n2), .n3(n3), .SUB);\n  BLK u1 (.n0(m), .n1(n1), .n2(n2), .n3(n3), .SUB);\n",
            {
                let mut open = top.clone();
                open.names.push("u0.n1".to_owned());
                open.ports.push(false);
                flatten(&flatten(&open, &block, &[0, 5, 2, 3]), &block, &[4, 1, 2, 3])
            },
        ),
    ];
    cases
        .into_iter()
        .map(|(name, body, flat)| {
            let mut fixture = Fixture::new(
                &format!("lvs/verilog/{name}"),
                &["LVS-075"],
                &full_deck(),
                LVS,
            )
            .layout(draw(&drawn))
            .expect(Expect::Lvs(equivalent(&drawn, &flat)));
            fixture.reference = Some(library.clone());
            fixture.verilog = vec![module(body, false)];
            VerilogTop {
                fixture,
                library: library.clone(),
                verilog_with_sub: module(body, true),
                drawn: drawn.clone(),
                flat,
            }
        })
        .collect()
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
    compared_under(name, catalog, (layout, reference), &Controls::default())
}

/// [`compared`] with the deck's `controls` stated after the full deck, the
/// verdict the oracle's under them.
fn compared_under(
    name: &str,
    catalog: &[&'static str],
    (layout, reference): (&Circuit, &Circuit),
    controls: &Controls,
) -> Fixture {
    let deck = format!("{}{}", full_deck(), controls.deck());
    let mut fixture = Fixture::new(&format!("lvs/{name}"), catalog, &deck, LVS)
        .layout(draw(layout))
        .expect(Expect::Lvs(equivalent_under(layout, reference, controls)));
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

/// One circuit per model past `nmos`, each with its last device's first two
/// pins swapped beside it: `(drawn, swapped)`.
fn every_model() -> Vec<(Circuit, Circuit)> {
    use Model::{B, C, D, H, P, Q, R};
    [
        polar(Dev::mos(P, 1, 0, 2)),
        polar(Dev::mos(H, 1, 0, 2)),
        Circuit::new(4, vec![Dev::mos(B, 0, 1, 2).sized(2000, 150).bulk(3)]),
        polar(Dev::pins(R, &[0, 1])),
        polar(Dev::pins(C, &[0, 1])),
        polar(Dev::pins(D, &[0, 1])),
        polar(Dev::pins(Q, &[0, 1, 2])),
    ]
    .into_iter()
    .map(|drawn| {
        let mut moved = drawn.clone();
        let last = moved.devs.len() - 1;
        moved.devs[last].pins.swap(0, 1);
        (drawn, moved)
    })
    .collect()
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
    // F67 (fixed in B21): with no `l` written anywhere, the run measures none,
    // and a stack with no length to sum stays two transistors: it does not
    // match one unsized card, and does match its own two unsized cards.
    let bare = |c: &Circuit| edited(&spice(c), " w=1000n l=150n", "");
    let one_unsized = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2)]);
    for (name, reference, matched) in [
        ("series/unsized_stack_vs_one", bare(&one_unsized), false),
        ("series/unsized_stack_vs_stack", bare(&inner), true),
    ] {
        out.push(
            with_text(name, &["LVS-041"], draw(&inner), reference).expect(Expect::Lvs(matched)),
        );
    }
    // F84 (fixed in B27): a series merge needs `l` and nothing else, so the
    // stack is one card writing `l` alone; one writing `w` alone has no
    // length to sum, and the stack stays two.
    let long_only =
        |w, l| Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(1000, 300).writes(w, l)]);
    for (name, reference) in [
        ("series/stack_vs_long_l_only", long_only(false, true)),
        ("series/stack_vs_long_w_only", long_only(true, false)),
    ] {
        out.push(compared(name, &["LVS-041"], &inner, &reference));
    }

    // LVS-040 and F57 (fixed in B17): parallel MOS, source and drain shorted too.
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
    out.push(compared(
        "parallel/mos_shorted_two_vs_wide",
        &["LVS-040"],
        &shorted,
        &shorted_wide,
    ));
    // F83 (fixed in B27): with no `w` written anywhere, two transistors in
    // parallel keep their count, as passives do: they are one card of
    // `m = 2`, and not one bare card.
    let bare = |dev: Dev| Circuit::new(3, vec![dev.writes(false, false)]);
    for (name, reference) in [
        (
            "parallel/mos_unsized_two_vs_one",
            bare(Dev::mos(N, 0, 1, 2)),
        ),
        (
            "parallel/mos_unsized_two_vs_m2",
            bare(Dev::mos(N, 0, 1, 2).times(2)),
        ),
    ] {
        out.push(compared(name, &["LVS-040", "LVS-046"], &two, &reference));
    }
    // F84 (fixed in B27): a parallel merge needs `w` and nothing else, so the
    // pair is one card writing `w` alone; one writing `l` alone has no width
    // to sum, so the pair is counted, two against its one.
    let wide_only =
        |w, l| Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(2000, 150).writes(w, l)]);
    for (name, reference) in [
        ("parallel/mos_two_vs_wide_w_only", wide_only(true, false)),
        ("parallel/mos_two_vs_wide_l_only", wide_only(false, true)),
    ] {
        out.push(compared(name, &["LVS-040"], &two, &reference));
    }

    // F20 (fixed in B9), LVS-043, LVS-044: parallel passives keep their count.
    for (model, row) in [(R, "LVS-043"), (C, "LVS-044"), (D, "LVS-044")] {
        let one = polar(Dev::pins(model, &[0, 1]));
        let mut two = one.clone();
        two.devs.push(Dev::pins(model, &[0, 1]));
        let letter = model.letter();
        let name = format!("parallel/{letter}_two_vs_one");
        out.push(compared(&name, &[row], &one, &two));
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
    // Opposed diodes stay two since F15 was fixed.
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
    for (index, (drawn, moved)) in every_model().iter().enumerate() {
        for (label, written) in [("same", drawn), ("swapped", moved)] {
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
    // F97 (fixed in B31): a Spectre primitive with no `model` card names no
    // model, so it is the deck's one recogniser of its kind. The deck has
    // one resistor, capacitor, diode and bipolar, so each card, its model
    // card dropped and its master the primitive, is the device drawn.
    for (dev, model, master) in [
        (Dev::pins(R, &[0, 1]), "rpoly", "resistor"),
        (Dev::pins(C, &[0, 1]), "cmim", "capacitor"),
        (Dev::pins(D, &[0, 1]), "dpn", "diode"),
        (Dev::pins(Q, &[0, 1, 2]), "npn", "npn"),
    ] {
        let circuit = polar(dev);
        let card = edited(&spectre(&circuit), &format!("\nmodel {model} "), "\n// ");
        let text = edited(&card, &format!(") {model}"), &format!(") {master}"));
        out.push(
            with_text(
                &format!("spectre/{master}_primitive_is_the_decks_one"),
                &["LVS-071"],
                draw(&circuit),
                text,
            )
            .expect(Expect::Lvs(true)),
        );
    }

    // F21 (fixed in B9), LVS-046: the multiplier.
    let cap = polar(Dev::pins(C, &[0, 1]));
    let cap_m2 = polar(Dev::pins(C, &[0, 1]).times(2));
    let mut caps = cap.clone();
    caps.devs.push(Dev::pins(C, &[0, 1]));
    out.push(compared(
        "multiplier/C_m2_vs_one",
        &["LVS-046"],
        &cap,
        &cap_m2,
    ));
    out.push(compared(
        "multiplier/C_m2_vs_two",
        &["LVS-046", "LVS-044"],
        &caps,
        &cap_m2,
    ));
    // A card without `m` is one device, whatever another card states (found
    // in B27): two parallel pairs against one bare card and one of `m = 2`.
    let pairs = Circuit::new(
        4,
        [[0, 1], [0, 1], [2, 3], [2, 3]]
            .iter()
            .map(|pins| Dev::pins(C, pins))
            .collect(),
    );
    let bare_and_m2 = Circuit::new(
        4,
        vec![Dev::pins(C, &[0, 1]), Dev::pins(C, &[2, 3]).times(2)],
    );
    out.push(compared(
        "multiplier/C_two_pairs_vs_bare_and_m2",
        &["LVS-046", "LVS-044"],
        &pairs,
        &bare_and_m2,
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
    out.push(compared(
        "params/D_area_beside_mos",
        rows,
        &diode,
        &declared,
    ));
    // F68 (fixed in B21): presence is per device. Two `dpn` cards, one with
    // `area=` and one without, against two drawn diodes: the card without
    // states nothing about its diode's area, so only the other's is compared.
    let diodes = Circuit::new(4, vec![Dev::pins(D, &[0, 1]), Dev::pins(D, &[2, 3])]);
    for (case, declared) in [("exact", PIN2_AREA), ("5pct_over", PIN2_AREA * 105 / 100)] {
        let mut r = diodes.clone();
        r.devs[0] = r.devs[0].clone().area(declared);
        let name = format!("params/D_area_on_one_card_{case}");
        out.push(compared(&name, &["LVS-020", "LVS-063"], &diodes, &r));
    }
    // F16 (fixed in B6), LVS-061..063: what the deck lets the layout
    // measure on a passive, each value either side of the 2 % tolerance.
    // The resistor's body is 800 by 400 nm along its pads, at 100 ohm/sq;
    // the capacitor's marker 0.32 um² and 2.4 um round, at 1 fF/um² and
    // 0.1 fF/um ([`measured`]). `r` and `c` are written positionally.
    let sized =
        |model: Model, size: fn(Dev) -> Dev| Circuit::new(2, vec![size(Dev::pins(model, &[0, 1]))]);
    let res = sized(R, |d| d);
    let cap = sized(C, |d| d);
    let dio = sized(D, |d| d);
    let passives: [(&str, &str, &Circuit, Circuit); 10] = [
        (
            "R_wl_exact",
            "LVS-061",
            &res,
            sized(R, |d| d.param("w", 400e-9).param("l", 800e-9)),
        ),
        (
            "R_l_10pct_over",
            "LVS-061",
            &res,
            sized(R, |d| d.param("l", 880e-9)),
        ),
        ("R_r_exact", "LVS-061", &res, sized(R, |d| d.value(200.0))),
        (
            "R_r_5pct_over",
            "LVS-061",
            &res,
            sized(R, |d| d.value(210.0)),
        ),
        ("C_c_exact", "LVS-062", &cap, sized(C, |d| d.value(5.6e-16))),
        (
            "C_c_area_term_only",
            "LVS-062",
            &cap,
            sized(C, |d| d.value(3.2e-16)),
        ),
        (
            "C_perim_exact",
            "LVS-062",
            &cap,
            sized(C, |d| d.param("perim", 2.4e-6)),
        ),
        (
            "D_area_perim_exact",
            "LVS-063",
            &dio,
            sized(D, |d| d.param("area", 3.2e-13).param("perim", 2.4e-6)),
        ),
        (
            "D_perim_10pct_over",
            "LVS-063",
            &dio,
            sized(D, |d| d.param("perim", 2.64e-6)),
        ),
        (
            "D_r_unmeasurable",
            "LVS-020",
            &dio,
            sized(D, |d| d.param("r", 200.0)),
        ),
    ];
    for (case, row, drawn, written) in passives {
        let name = format!("params/{case}");
        out.push(compared(&name, &[row, "LVS-014"], drawn, &written));
    }
    // F86 (fixed in B27): a two-pin card with no model is the deck's one
    // recogniser of its kind, here `rpoly`, `cmim` and `dpn`, so each card
    // above with its model cut out matches what it matched: 200 ohm, 0.56 fF
    // and a bare diode.
    for (case, row, drawn, written, model) in [
        (
            "R_r_no_model",
            "LVS-061",
            &res,
            sized(R, |d| d.value(200.0)),
            " rpoly",
        ),
        (
            "C_c_no_model",
            "LVS-062",
            &cap,
            sized(C, |d| d.value(5.6e-16)),
            " cmim",
        ),
        ("D_no_model", "LVS-063", &dio, dio.clone(), " dpn"),
    ] {
        out.push(
            with_text(
                &format!("params/{case}"),
                &[row],
                draw(drawn),
                edited(&spice(&written), model, ""),
            )
            .expect(Expect::Lvs(true)),
        );
    }
    // F87 (fixed in B27): KLayout's `A`/`P` and ngspice's diode `pj` are the
    // `area` and `perim` above: 0.32 um² and 2.4 um match, 2.64 um does not.
    let aliased = |size: fn(Dev) -> Dev, names: &[(&str, &str)]| {
        let mut text = spice(&sized(D, size));
        for &(from, to) in names {
            text = edited(&text, from, to);
        }
        text
    };
    for (case, text, matched) in [
        (
            "D_A_P_exact",
            aliased(
                |d| d.param("area", 3.2e-13).param("perim", 2.4e-6),
                &[(" area=", " A="), (" perim=", " P=")],
            ),
            true,
        ),
        (
            "D_pj_exact",
            aliased(|d| d.param("perim", 2.4e-6), &[(" perim=", " pj=")]),
            true,
        ),
        (
            "D_pj_10pct_over",
            aliased(|d| d.param("perim", 2.64e-6), &[(" perim=", " pj=")]),
            false,
        ),
    ] {
        out.push(
            with_text(&format!("params/{case}"), &["LVS-063"], draw(&dio), text)
                .expect(Expect::Lvs(matched)),
        );
    }
    // A deck that gives no sheet resistance computes no `r`, and a card
    // stating one is never taken as agreement.
    let deck = full_deck().replace(" sheet 100ohm", "");
    let mut fixture = Fixture::new(
        "lvs/params/R_r_without_sheet",
        &["LVS-061", "LVS-020"],
        &deck,
        LVS,
    )
    .layout(draw(&res))
    .expect(Expect::Lvs(false));
    fixture.reference = Some(spice(&sized(R, |d| d.value(200.0))));
    out.push(fixture);

    // F85 (fixed in B27): a diode marker drawn as a ring, 0..2000 square with
    // a 200 wall (its hole a clockwise polygon of its own), a pad on each
    // side wall. Derived by hand: area 2000² − 1600² nm² = 1.44 µm², edge
    // both rings, 8000 + 6400 nm = 14.4 µm. The hole is no second marker, so
    // `lvs.terminal_net` is clean.
    let mut ring = Layout::default()
        .rect("diom", 0, 0, 2000, 2000)
        .polygon(
            "diom",
            &[(200, 200), (200, 1800), (1800, 1800), (1800, 200)],
        )
        .rect("pina", 0, 900, 200, 1100)
        .rect("cont", 50, 950, 150, 1050)
        .rect("pinb", 1800, 900, 2000, 1100)
        .rect("cont", 1850, 950, 1950, 1050);
    ring = stub(stub(ring, 50, 150, 950, 0), 1850, 1950, 950, 1);
    for (net, name) in ["n0", "n1"].into_iter().enumerate() {
        let t = track(net);
        ring = ring
            .rect("met2", -1000, t, 3000, t + 200)
            .label("met2_label", -900, t + 100, name);
    }
    let ring_card = Circuit::new(
        2,
        vec![Dev::pins(D, &[0, 1])
            .param("area", 1.44e-12)
            .param("perim", 1.44e-5)],
    );
    out.push(
        with_text(
            "params/D_ring_area_perim",
            &["LVS-063", "LVS-004"],
            ring,
            spice(&ring_card),
        )
        .expect(Expect::Lvs(true))
        .expect(Expect::clean("lvs.terminal_net")),
    );

    // F16 (fixed in B27): a MOS's diffusions, each drawn 500 by 1000 nm:
    // `as` = `ad` = 0.5 um² and `ps` = `pd` = 3 um. Two in parallel sum them,
    // a card's `m` multiplies them, a stack stating them does not merge (the
    // diffusion between would be lost), and 10 % over is a mismatch. A
    // bipolar's emitter, its middle pad 400 nm square: `ae` 0.16 um², `pe`
    // 1.6 um.
    let diffused = |dev: Dev, area: f64, perim: f64| {
        dev.param("as", area)
            .param("ad", area)
            .param("ps", perim)
            .param("pd", perim)
    };
    let mos = |dev: Dev| Circuit::new(3, vec![dev]);
    let diffusion_cases = [
        (
            "params/mos_diffusion_exact",
            &one,
            mos(diffused(Dev::mos(N, 0, 1, 2), 5e-13, 3e-6)),
        ),
        (
            "params/mos_diffusion_10pct_over",
            &one,
            mos(diffused(Dev::mos(N, 0, 1, 2), 5.5e-13, 3e-6)),
        ),
        (
            "parallel/mos_two_diffused_vs_wide",
            &two,
            mos(diffused(Dev::mos(N, 0, 1, 2).sized(2000, 150), 1e-12, 6e-6)),
        ),
        (
            "multiplier/mos_m2_diffused_vs_two",
            &two,
            mos(diffused(Dev::mos(N, 0, 1, 2).times(2), 5e-13, 3e-6)),
        ),
        (
            "series/stack_diffused_vs_long",
            &inner,
            mos(diffused(Dev::mos(N, 0, 1, 2).sized(1000, 300), 5e-13, 3e-6)),
        ),
    ];
    for (name, drawn, written) in diffusion_cases {
        out.push(compared(name, &["LVS-060"], drawn, &written));
    }
    let bjt_alone = Circuit::new(3, vec![Dev::pins(Q, &[0, 1, 2])]);
    for (case, ae) in [("exact", 1.6e-13), ("10pct_over", 1.76e-13)] {
        let written = Circuit::new(
            3,
            vec![Dev::pins(Q, &[0, 1, 2]).param("ae", ae).param("pe", 1.6e-6)],
        );
        let name = format!("params/Q_ae_pe_{case}");
        out.push(compared(&name, &["LVS-064"], &bjt_alone, &written));
    }
    // Two fingers sharing their middle diffusion, both gated by n0, the outer
    // diffusions on n1 and the middle on n2, and an nmos gated by n1 that
    // tells n1 from n2. Derived by hand: each diffusion is 500 by 1000 nm,
    // the middle one shared two ways, so merged the fingers have 1 um² and
    // 6 um on n1 and 0.5 um² and 3 um on n2. A card with those at its source
    // (n1) and drain (n2) matches; one with them the other way round does
    // not. F98 (fixed in B31): without the sensor nothing tells n1 from n2,
    // so the card the other way round is the same circuit with n1 and n2
    // renamed, and names do not take part: both cards match.
    let mut shared = Layout::default()
        .rect("diff", 0, 0, 1800, 1000)
        .rect("poly", 500, -200, 650, 1500)
        .rect("poly", 1150, -200, 1300, 1500)
        .rect("nsdm", -200, -300, 2000, 1200);
    for (x, net) in [(100, 1), (750, 2), (1400, 1)] {
        shared = stub(
            shared.rect("cont", x, 100, x + 300, 400),
            x,
            x + 300,
            100,
            net,
        );
    }
    for x in [500, 1150] {
        shared = stub(
            shared.rect("cont", x, 1250, x + 150, 1400),
            x,
            x + 150,
            1250,
            0,
        );
    }
    // LVS-032: the fingers alone, their nets labelled. Labels break a tie
    // only after the diffusions (KLayout's `consider_net_names`): the
    // channel nets pair the way the diffusions agree (testing-plan F98), so
    // the card that puts 1 um² at its source n1 matches, and so does the
    // one that puts it at n2, the same transistor the other way round.
    let mut fingers = shared.clone();
    for net in 0..3 {
        let t = track(net);
        fingers = fingers.rect("met2", -1000, t, column(1), t + 200).label(
            "met2_label",
            -900,
            t + 100,
            &format!("n{net}"),
        );
    }
    for (case, ends, matched) in [
        ("as_labelled", [1e-12, 5e-13, 6e-6, 3e-6], true),
        ("against_the_labels", [5e-13, 1e-12, 3e-6, 6e-6], true),
    ] {
        let card = DIFFUSIONS
            .into_iter()
            .zip(ends)
            .fold(Dev::mos(N, 0, 1, 2).sized(2000, 150), |dev, (name, v)| {
                dev.param(name, v)
            });
        out.push(
            with_text(
                &format!("names/shared_diffusion_{case}"),
                &["LVS-032", "LVS-060"],
                fingers.clone(),
                spice(&Circuit::new(3, vec![card])),
            )
            .expect(Expect::Lvs(matched)),
        );
    }
    let sensor = Dev::mos(N, 1, 0, 0);
    let tracked = |mut layout: Layout| {
        for net in 0..3 {
            let t = track(net);
            layout = layout.rect("met2", -1000, t, column(2), t + 200).label(
                "met2_label",
                -900,
                t + 100,
                &format!("n{net}"),
            );
        }
        layout
    };
    let symmetric = tracked(shared.clone());
    let shared = tracked(draw_mos(shared, column(1), &sensor));
    for (case, ends, sensed) in [
        ("source_and_drain", [1e-12, 5e-13, 6e-6, 3e-6], true),
        ("the_other_way_round", [5e-13, 1e-12, 3e-6, 6e-6], false),
    ] {
        let card = DIFFUSIONS
            .into_iter()
            .zip(ends)
            .fold(Dev::mos(N, 0, 1, 2).sized(2000, 150), |dev, (name, v)| {
                dev.param(name, v)
            });
        let variants = [
            ("", &shared, vec![card.clone(), sensor.clone()], sensed),
            ("symmetric_", &symmetric, vec![card], true),
        ];
        for (variant, layout, devs, matched) in variants {
            out.push(
                with_text(
                    &format!("parallel/shared_diffusion_{variant}{case}"),
                    &["LVS-060", "LVS-040"],
                    layout.clone(),
                    spice(&Circuit::new(3, devs)),
                )
                .expect(Expect::Lvs(matched)),
            );
        }
    }

    let nf = edited(&spice(&one), "l=150n", "l=150n nf=1");
    out.push(
        with_text(
            "params/nf_1_is_one_finger",
            &["LVS-020", "LVS-060"],
            draw(&one),
            nf,
        )
        .expect(Expect::Lvs(true)),
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
    // F58 (fixed in B17), its smallest cases: a class refinement cannot
    // split, which the closest-parameter pairing alone broke the wrong way.
    // The layout's own circuit with its cards reversed; and a circuit whose
    // one device is written 1.9 % wide.
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
        .expect(Expect::Lvs(true)),
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
    out.push(compared(name, rows, &cycle, &cycle_wide));

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

/// The deck's `lvs` statements (deck.md, "LVS controls"), each verdict the
/// oracle's under the statements the fixture's deck adds.
fn controlled() -> Vec<Fixture> {
    use Model::{B, C, D, N, P, Q, R};
    let mut out = Vec::new();
    let row = |model, param, relative, absolute| {
        Controls::default().tolerance(model, param, relative, absolute)
    };

    // LVS-014: a row bounds one parameter of one model in place of the 2 %,
    // its relative and absolute parts adding. `w` 1000 against 1040 nm is
    // 3.85 % of the larger: past 2 %, within a 5 % row and not a 3 % one,
    // within 50 nm and not 30 nm, within 2 % plus 20 nm (40.8 nm). 1.5 %
    // matches by default and not under a 1 % row. A row on `l`, or on
    // `pmos`, leaves this `w` at 2 %.
    let w_of = |w| Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(w, 1000)]);
    let nm = |text, value: f64| Some((text, value * 1e-9));
    for (name, written, controls) in [
        ("w+3.85_default", 1040, Controls::default()),
        ("w+3.85_relative_5pct", 1040, row(N, "w", 0.05, None)),
        ("w+3.85_relative_3pct", 1040, row(N, "w", 0.03, None)),
        (
            "w+3.85_absolute_50nm",
            1040,
            row(N, "w", 0.0, nm("50nm", 50.0)),
        ),
        (
            "w+3.85_absolute_30nm",
            1040,
            row(N, "w", 0.0, nm("30nm", 30.0)),
        ),
        (
            "w+3.85_2pct_plus_20nm",
            1040,
            row(N, "w", 0.02, nm("20nm", 20.0)),
        ),
        ("w+1.5_default", 1015, Controls::default()),
        ("w+1.5_relative_1pct", 1015, row(N, "w", 0.01, None)),
        ("w+3.85_row_on_l", 1040, row(N, "l", 0.05, None)),
        ("w+3.85_row_on_pmos", 1040, row(P, "w", 0.05, None)),
    ] {
        out.push(compared_under(
            &format!("tolerance/deck/{name}"),
            &["LVS-014", "LVS-060"],
            (&w_of(1000), &w_of(written)),
            &controls,
        ));
    }
    // An ignored parameter is neither compared nor merged on: `w` 1000
    // against 1500 nm matches once `nmos` `w` is ignored, and two
    // transistors of `l` 150 and 200 nm are one of twice the width once `l`
    // is.
    let two = Circuit::new(
        3,
        vec![Dev::mos(N, 0, 1, 2), Dev::mos(N, 0, 2, 1).sized(1000, 200)],
    );
    let wide = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(2000, 150)]);
    let ignore = |param| Controls::default().ignore(N, param);
    for (name, layout, reference, controls) in [
        ("w+50pct", &w_of(1000), &w_of(1500), Controls::default()),
        ("w+50pct_w_ignored", &w_of(1000), &w_of(1500), ignore("w")),
        ("w+50pct_l_ignored", &w_of(1000), &w_of(1500), ignore("l")),
        ("lengths_differ_vs_wide", &two, &wide, Controls::default()),
        ("lengths_differ_vs_wide_l_ignored", &two, &wide, ignore("l")),
    ] {
        out.push(compared_under(
            &format!("ignore_parameter/{name}"),
            &["LVS-014", "LVS-040"],
            (layout, reference),
            &controls,
        ));
    }
    // LVS-031: an asymmetric `nmos`, whose source pairs only with a source.
    // A `pmos` gated by n1 tells n1 from n2, so a card with source and drain
    // swapped is another circuit once `nmos` is asymmetric, and the same one
    // otherwise. Two in parallel merge source on source and not opposed; a
    // stack of them stays two.
    let anchored = |dev: Dev| Circuit::new(3, vec![dev, Dev::mos(P, 1, 0, 0)]);
    let same = anchored(Dev::mos(N, 0, 1, 2));
    let swapped = anchored(Dev::mos(N, 0, 2, 1));
    let aligned = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2), Dev::mos(N, 0, 1, 2)]);
    let opposed = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2), Dev::mos(N, 0, 2, 1)]);
    let stack = Circuit::new(4, vec![Dev::mos(N, 0, 1, 3), Dev::mos(N, 0, 3, 2)]).internal(3);
    let long = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(1000, 300)]);
    for (name, layout, reference) in [
        ("sd_same", &same, &same),
        ("sd_swapped", &same, &swapped),
        ("parallel_aligned_vs_wide", &aligned, &wide),
        ("parallel_opposed_vs_wide", &opposed, &wide),
        ("stack_vs_long", &stack, &long),
        ("stack_vs_stack", &stack, &stack),
    ] {
        for (label, controls) in [
            ("symmetric", Controls::default()),
            ("asymmetric", Controls::default().asymmetric(N)),
        ] {
            out.push(compared_under(
                &format!("asymmetric/{name}/{label}"),
                &["LVS-031", "LVS-030"],
                (layout, reference),
                &controls,
            ));
        }
    }
    // LVS-030: pins the deck permutes. A capacitor or diode reversed, and a
    // bipolar with emitter and collector exchanged, are other circuits by
    // default (F15) and the same once those pins permute; base with emitter
    // is not emitter with collector. The bipolar's base is on n1 and its
    // emitter on n0, which the `nmos` gate fixes, since the `nmos` channel
    // alone would let n1 and n2 trade places. Two capacitors in opposite directions
    // merge into one of m = 2 once the plates permute. A `pmos` with gate
    // and source exchanged is the same once gate permutes with source,
    // which chains with source-drain; a stack of such `nmos` no longer
    // merges in series.
    let two_pin = |model, pins: &[usize]| polar(Dev::pins(model, pins));
    let bjt = |pins: &[usize]| polar(Dev::pins(Q, pins));
    let mut caps_opposed = polar(Dev::pins(C, &[0, 1]));
    caps_opposed.devs.push(Dev::pins(C, &[1, 0]));
    let cap_m2 = polar(Dev::pins(C, &[0, 1]).times(2));
    let p_of = |g, s| polar(Dev::mos(P, g, s, 2));
    let permuted: [(&str, Circuit, Circuit, Controls); 10] = [
        (
            "C_reversed",
            two_pin(C, &[0, 1]),
            two_pin(C, &[1, 0]),
            Controls::default().permute(C, 0, 1),
        ),
        (
            "D_reversed",
            two_pin(D, &[0, 1]),
            two_pin(D, &[1, 0]),
            Controls::default().permute(D, 0, 1),
        ),
        (
            "Q_emitter_collector_swapped",
            bjt(&[1, 0, 2]),
            bjt(&[1, 2, 0]),
            Controls::default().permute(Q, 1, 2),
        ),
        (
            "Q_emitter_collector_swapped_base_permuted",
            bjt(&[1, 0, 2]),
            bjt(&[1, 2, 0]),
            Controls::default().permute(Q, 0, 1),
        ),
        (
            "C_opposed_vs_m2",
            caps_opposed.clone(),
            cap_m2.clone(),
            Controls::default().permute(C, 0, 1),
        ),
        (
            "C_opposed_vs_m2_unpermuted",
            caps_opposed,
            cap_m2,
            Controls::default(),
        ),
        (
            "P_gate_source_swapped",
            p_of(0, 1),
            p_of(1, 0),
            Controls::default().permute(P, 0, 1),
        ),
        (
            "P_gate_source_swapped_unpermuted",
            p_of(0, 1),
            p_of(1, 0),
            Controls::default(),
        ),
        (
            "stack_vs_long_gate_permuted",
            stack.clone(),
            long.clone(),
            Controls::default().permute(N, 0, 1),
        ),
        (
            "C_same",
            two_pin(C, &[0, 1]),
            two_pin(C, &[0, 1]),
            Controls::default().permute(C, 0, 1),
        ),
    ];
    for (name, layout, reference, controls) in permuted {
        out.push(compared_under(
            &format!("permute/{name}"),
            &["LVS-030"],
            (&layout, &reference),
            &controls,
        ));
    }
    // LVS-034: an ignored model's devices are left out on both sides. A
    // capacitor from n0 to n1 beside the `nmos`, drawn and not written or
    // written and not drawn, matches once `cmim` is ignored; ignoring
    // `nmos` instead leaves it unpaired. A capacitor to an internal net
    // n3 takes that net with it; one to a port n3 leaves the port, which
    // must still pair.
    let bare = polar(Dev::mos(P, 1, 0, 2));
    let mut capped = bare.clone();
    capped.devs.push(Dev::pins(C, &[0, 1]));
    let mut to_internal = bare.clone();
    to_internal.names.push("n3".to_owned());
    to_internal.ports.push(false);
    to_internal.devs.push(Dev::pins(C, &[1, 3]));
    let mut to_port = to_internal.clone();
    to_port.ports[3] = true;
    let ignore_c = Controls::default().leave_out(C);
    let ignored: [(&str, &Circuit, &Circuit, Controls); 7] = [
        ("drawn_only", &capped, &bare, ignore_c.clone()),
        ("written_only", &bare, &capped, ignore_c.clone()),
        ("drawn_only_default", &capped, &bare, Controls::default()),
        (
            "drawn_only_nmos_ignored",
            &capped,
            &bare,
            Controls::default().leave_out(N),
        ),
        (
            "internal_net_written_only",
            &bare,
            &to_internal,
            ignore_c.clone(),
        ),
        ("port_written_only", &bare, &to_port, ignore_c.clone()),
        ("both", &capped, &capped, ignore_c),
    ];
    for (name, layout, reference, controls) in ignored {
        out.push(compared_under(
            &format!("ignore/{name}"),
            &["LVS-034"],
            (layout, reference),
            &controls,
        ));
    }
    // LVS-035: dummies, every pin on one net, are left out once their model
    // ignores shorted devices: an `nmos` with gate, source and drain on n0
    // (its bulk, which the deck does not extract, written on its source),
    // and an `nmosb` with all four on n3. One with its gate elsewhere is no
    // dummy.
    let real = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2)]);
    let with_dummy = |gate| {
        let mut c = real.clone();
        c.devs.push(Dev::mos(N, gate, 0, 0));
        c
    };
    let real_b = Circuit::new(4, vec![Dev::mos(B, 0, 1, 2).bulk(3)]);
    let mut dummy_b = real_b.clone();
    dummy_b.devs.push(Dev::mos(B, 3, 3, 3).bulk(3));
    let skip_n = Controls::default().leave_out_dummies(N);
    let skip_b = Controls::default().leave_out_dummies(B);
    let shorted: [(&str, Circuit, Circuit, Controls); 7] = [
        ("N_drawn", with_dummy(0), real.clone(), skip_n.clone()),
        ("N_written", real.clone(), with_dummy(0), skip_n.clone()),
        (
            "N_drawn_default",
            with_dummy(0),
            real.clone(),
            Controls::default(),
        ),
        ("N_gate_elsewhere", with_dummy(1), real.clone(), skip_n),
        ("B_drawn", dummy_b.clone(), real_b.clone(), skip_b.clone()),
        ("B_written", real_b.clone(), dummy_b.clone(), skip_b),
        ("B_drawn_default", dummy_b, real_b, Controls::default()),
    ];
    for (name, layout, reference, controls) in shorted {
        out.push(compared_under(
            &format!("ignore_shorted/{name}"),
            &["LVS-035"],
            (&layout, &reference),
            &controls,
        ));
    }
    // LVS-016, LVS-001: ports by name. Two transistors, each its own gate
    // and drain port, against a reference that wires gate n0 to the drain
    // it names n3: the same circuit up to renaming, a mismatch once ports go
    // by name. The same names match either way, and a layout with no labels
    // matches only by structure.
    let pair = Circuit::new(5, vec![Dev::mos(N, 0, 4, 2), Dev::mos(N, 1, 4, 3)]);
    let mut crossed = pair.clone();
    crossed.names.swap(2, 3);
    let mut unlabelled = pair.clone();
    unlabelled.ports = vec![false; 5];
    let by_name = Controls {
        ports_by_name: true,
        ..Controls::default()
    };
    let named: [(&str, &Circuit, &Circuit, Controls); 6] = [
        ("crossed", &pair, &crossed, Controls::default()),
        ("crossed_by_name", &pair, &crossed, by_name.clone()),
        ("same_by_name", &pair, &pair, by_name.clone()),
        ("reordered_by_name", &pair, &pair, by_name.clone()),
        ("unlabelled", &unlabelled, &pair, Controls::default()),
        ("unlabelled_by_name", &unlabelled, &pair, by_name),
    ];
    for (name, layout, reference, controls) in named {
        let mut fixture = compared_under(
            &format!("ports/{name}"),
            &["LVS-016", "LVS-001"],
            (layout, reference),
            &controls,
        );
        if name.starts_with("reordered") {
            let text = fixture.reference.take().expect("a reference");
            fixture.reference = Some(edited(
                &text,
                ".subckt TOP n0 n1 n2 n3 n4",
                ".subckt TOP n4 n3 n2 n1 n0",
            ));
        }
        out.push(fixture);
    }
    // LVS-043, LVS-044, LVS-049: relaxed topology. Two resistors drawn in
    // parallel, 200 ohm each ([`measured`]), are one of 100 ohm, and two
    // capacitors of 0.56 fF one of 1.12 fF, three one of 1.68 fF; a card's
    // `m` folds in first, so `r=200 m=2` is 100 ohm. Strict, the default,
    // they are two that match only a count of two. A card with no value
    // keeps the count either way.
    let relaxed = Controls {
        relaxed: true,
        ..Controls::default()
    };
    let parallel =
        |model, count| Circuit::new(2, (0..count).map(|_| Dev::pins(model, &[0, 1])).collect());
    let card = |dev: Dev| Circuit::new(2, vec![dev]);
    let combined: [(&str, Circuit, Circuit); 8] = [
        (
            "R_two_vs_half",
            parallel(R, 2),
            card(Dev::pins(R, &[0, 1]).value(100.0)),
        ),
        (
            "R_two_vs_m2",
            parallel(R, 2),
            card(Dev::pins(R, &[0, 1]).value(200.0).times(2)),
        ),
        (
            "R_two_vs_one",
            parallel(R, 2),
            card(Dev::pins(R, &[0, 1]).value(200.0)),
        ),
        (
            "R_two_vs_unvalued_one",
            parallel(R, 2),
            card(Dev::pins(R, &[0, 1])),
        ),
        (
            "C_two_vs_double",
            parallel(C, 2),
            card(Dev::pins(C, &[0, 1]).value(1.12e-15)),
        ),
        (
            "C_two_vs_m2",
            parallel(C, 2),
            card(Dev::pins(C, &[0, 1]).value(5.6e-16).times(2)),
        ),
        (
            "C_three_vs_triple",
            parallel(C, 3),
            card(Dev::pins(C, &[0, 1]).value(1.68e-15)),
        ),
        (
            "C_two_vs_one",
            parallel(C, 2),
            card(Dev::pins(C, &[0, 1]).value(5.6e-16)),
        ),
    ];
    for (name, layout, reference) in combined {
        for (label, controls) in [("relaxed", &relaxed), ("strict", &Controls::default())] {
            out.push(compared_under(
                &format!("topology/{name}/{label}"),
                &["LVS-049", "LVS-043", "LVS-044"],
                (&layout, &reference),
                controls,
            ));
        }
    }
    // LVS-043, LVS-044, LVS-049: relaxed series. Two resistors drawn in
    // series through an internal net, 200 ohm each, are one of 400 ohm, and
    // two capacitors of 0.56 fF chained plate to plate one of 0.28 fF;
    // two written resistors of 100 ohm in series are the 200 ohm drawn.
    // Strict, nothing merges in series. A net that is a port stops the
    // chain, and capacitors meeting tail to tail do not chain.
    let chain = |model, second: [usize; 2]| {
        Circuit::new(
            3,
            vec![Dev::pins(model, &[0, 1]), Dev::pins(model, &second)],
        )
        .internal(1)
    };
    let written_chain = Circuit::new(
        3,
        vec![
            Dev::pins(R, &[0, 2]).value(100.0),
            Dev::pins(R, &[2, 1]).value(100.0),
        ],
    )
    // Not `n1`, which the layout labels: a labelled node stops a merge
    // on both sides (`lvs::compare`).
    .internal(2);
    let series: [(&str, Circuit, Circuit); 6] = [
        (
            "R_chain_vs_sum",
            chain(R, [1, 2]),
            card(Dev::pins(R, &[0, 1]).value(400.0)),
        ),
        (
            "R_chain_through_port_vs_sum",
            Circuit::new(3, vec![Dev::pins(R, &[0, 1]), Dev::pins(R, &[1, 2])]),
            card(Dev::pins(R, &[0, 1]).value(400.0)),
        ),
        (
            "R_one_vs_written_chain",
            card(Dev::pins(R, &[0, 1])),
            written_chain,
        ),
        (
            "C_chain_vs_series",
            chain(C, [1, 2]),
            card(Dev::pins(C, &[0, 1]).value(2.8e-16)),
        ),
        (
            "C_tail_to_tail_vs_series",
            chain(C, [2, 1]),
            card(Dev::pins(C, &[0, 1]).value(2.8e-16)),
        ),
        (
            "D_chain_vs_one",
            chain(D, [1, 2]),
            card(Dev::pins(D, &[0, 1])),
        ),
    ];
    for (name, layout, reference) in series {
        for (label, controls) in [("relaxed", &relaxed), ("strict", &Controls::default())] {
            out.push(compared_under(
                &format!("topology/series/{name}/{label}"),
                &["LVS-049", "LVS-043", "LVS-044"],
                (&layout, &reference),
                controls,
            ));
        }
    }
    // A diode's value is its area: two drawn in parallel, 0.32 um² each,
    // are one of 0.64 um² relaxed, and two strict (derived by hand from
    // [`draw_pins`]).
    let diodes = Circuit::new(2, vec![Dev::pins(D, &[0, 1]), Dev::pins(D, &[0, 1])]);
    let written = spice(&Circuit::new(2, vec![Dev::pins(D, &[0, 1]).area(640_000)]));
    for (label, policy, matched) in [("relaxed", "relaxed", true), ("strict", "strict", false)] {
        let deck = format!("{}lvs topology {policy}\n", full_deck());
        let mut fixture = Fixture::new(
            &format!("lvs/topology/D_two_vs_double_area/{label}"),
            &["LVS-049", "LVS-044"],
            &deck,
            LVS,
        )
        .layout(draw(&diodes))
        .expect(Expect::Lvs(matched));
        fixture.reference = Some(written.clone());
        out.push(fixture);
    }
    // LVS-034: `max_res` and `min_caps` leave out a resistor above and a
    // capacitor below the threshold, on either side, as opens. A drawn
    // resistor of 200 ohm ([`measured`]) across a transistor's channel,
    // against the transistor alone, matches under `max_res 100ohm` and not
    // `300ohm`; a written 1 Mohm the layout does not draw matches under
    // `100kohm` and not `2Mohm`; a drawn capacitor of 0.56 fF matches under
    // `min_caps 1fF` and not `100aF`.
    let alone = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2)]);
    let with = |dev: Dev| Circuit::new(3, vec![Dev::mos(N, 0, 1, 2), dev]);
    let drawn_r = with(Dev::pins(R, &[1, 2]));
    let written_r = with(Dev::pins(R, &[1, 2]).value(1e6));
    let drawn_c = with(Dev::pins(C, &[1, 2]));
    let res = |text, ohm| Controls {
        max_res: Some((text, ohm)),
        ..Controls::default()
    };
    let caps = |text, farad| Controls {
        min_caps: Some((text, farad)),
        ..Controls::default()
    };
    let thresholds: [(&str, &Circuit, &Circuit, Controls); 7] = [
        ("drawn_R_default", &drawn_r, &alone, Controls::default()),
        ("drawn_R_max_100ohm", &drawn_r, &alone, res("100ohm", 100.0)),
        ("drawn_R_max_300ohm", &drawn_r, &alone, res("300ohm", 300.0)),
        (
            "written_R_max_100kohm",
            &alone,
            &written_r,
            res("100kohm", 1e5),
        ),
        ("written_R_max_2Mohm", &alone, &written_r, res("2Mohm", 2e6)),
        ("drawn_C_min_1fF", &drawn_c, &alone, caps("1fF", 1e-15)),
        ("drawn_C_min_100aF", &drawn_c, &alone, caps("100aF", 1e-16)),
    ];
    for (name, layout, reference, controls) in thresholds {
        out.push(compared_under(
            &format!("thresholds/{name}"),
            &["LVS-034"],
            (layout, reference),
            &controls,
        ));
    }
    // LVS-032: `same_nets`. Two transistors, each its own gate and drain,
    // against a reference naming the drains the other way round: one
    // circuit up to renaming. Holding layout `n0` to reference `n0` and
    // `n2` to `n2` contradicts that reference's wiring, a mismatch; `n2` to
    // `n3` follows it, a match; a row naming no net changes nothing, and a
    // row with a layout label and no reference net is unpaired.
    let pair = Circuit::new(5, vec![Dev::mos(N, 0, 4, 2), Dev::mos(N, 1, 4, 3)]);
    let mut crossed = pair.clone();
    crossed.names.swap(2, 3);
    let same = |rows: &[(&'static str, &'static str)]| Controls {
        same_nets: rows.to_vec(),
        ..Controls::default()
    };
    for (name, controls) in [
        ("none", Controls::default()),
        ("against_wiring", same(&[("n0", "n0"), ("n2", "n2")])),
        ("with_wiring", same(&[("n0", "n0"), ("n2", "n3")])),
        ("no_such_nets", same(&[("q", "q")])),
        ("no_reference_net", same(&[("n0", "q")])),
    ] {
        out.push(compared_under(
            &format!("same_nets/{name}"),
            &["LVS-032"],
            (&pair, &crossed),
            &controls,
        ));
    }
    // A passive's value, drawn 200 ohm and 0.56 fF ([`measured`]), against
    // 210 ohm and 0.6 fF: 10 ohm and 40 aF apart, so within 15 ohm and
    // 50 aF and not 5 ohm or 30 aF.
    let one = |dev: Dev| Circuit::new(2, vec![dev]);
    for (name, model, written, absolute, row_name) in [
        ("R_r_absolute_15ohm", R, 210.0, ("15ohm", 15.0), "LVS-061"),
        ("R_r_absolute_5ohm", R, 210.0, ("5ohm", 5.0), "LVS-061"),
        ("C_c_absolute_50aF", C, 6e-16, ("50aF", 5e-17), "LVS-062"),
        ("C_c_absolute_30aF", C, 6e-16, ("30aF", 3e-17), "LVS-062"),
    ] {
        let param = if model == R { "r" } else { "c" };
        out.push(compared_under(
            &format!("tolerance/deck/{name}"),
            &["LVS-014", row_name],
            (
                &one(Dev::pins(model, &[0, 1])),
                &one(Dev::pins(model, &[0, 1]).value(written)),
            ),
            &row(model, param, 0.0, Some(absolute)),
        ));
    }
    out
}

/// An `lvs.short_path` row measuring step `k` of its path (the harness
/// compares the measure, not the limit).
fn step(k: u32) -> Finding {
    Finding {
        measured: Some(gpurify::check::report::Measurement::Count(k)),
        at: None,
    }
}

/// The rows `check_layout` records from the layout alone (its rustdoc), and
/// device recognition's corner cases.
fn layout_rows() -> Vec<Fixture> {
    use Model::{N, R};
    let mut out = Vec::new();
    let one = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2)]);

    // LVS-068: a deck's `lvs range` holds every device of the model to the
    // bounds on what is drawn: the `nmos` 1000 by 150 nm, the capacitor's
    // marker 0.32 um² ([`draw_mos`], [`draw_pins`]). A value at its bound is
    // legal, a model with no device is examined zero times, and another
    // model is not held.
    let cap = Circuit::new(2, vec![Dev::pins(Model::C, &[0, 1])]);
    let ranged: [(&str, &Circuit, &str, Vec<Finding>); 7] = [
        (
            "w_below_min",
            &one,
            "\"nmos\" w >= 1100nm",
            vec![Finding::length(1000)],
        ),
        (
            "w_at_both_bounds",
            &one,
            "\"nmos\" w >= 1000nm <= 1000nm",
            Vec::new(),
        ),
        (
            "l_above_max",
            &one,
            "\"nmos\" l <= 100nm",
            vec![Finding::length(150)],
        ),
        (
            "nf_below_min",
            &one,
            "\"nmos\" nf >= 2",
            vec![Finding::any()],
        ),
        ("other_model", &one, "\"pmos\" w >= 1100nm", Vec::new()),
        (
            "C_area_below_min",
            &cap,
            "\"cmim\" area >= 0.4um2",
            vec![Finding::area(320_000)],
        ),
        (
            "C_area_within",
            &cap,
            "\"cmim\" area <= 0.32um2",
            Vec::new(),
        ),
    ];
    for (name, c, bounds, findings) in ranged {
        let deck = format!("{}lvs range {bounds}\n", full_deck());
        let mut fixture = Fixture::new(&format!("lvs/range/{name}"), &["LVS-068"], &deck, LVS)
            .layout(draw(c))
            .expect(Expect::rule("lvs.param_range", findings));
        fixture.reference = Some(spice(c));
        out.push(fixture);
    }

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
        // `lvs.floating_net` examines every net: the four tracks drawn.
        .expect(
            Expect::rule("lvs.floating_net", vec![Finding::any()]).examined(floating.nets() as u64),
        ),
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
        .expect(Expect::clean("lvs.floating_net").examined(port.nets() as u64)),
    );

    // LVS-001, LVS-002: one label on two nets is an open, not a join. DRC-084:
    // a pin's ports (its label on disjoint shapes) left unjoined, what LEF58
    // MUSTJOINALLPORTS forbids at the top.
    let mut split = Circuit::new(4, vec![Dev::mos(N, 0, 1, 2), Dev::mos(N, 3, 1, 2)]);
    "n0".clone_into(&mut split.names[3]);
    let joined = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2), Dev::mos(N, 0, 1, 2)]);
    out.push(
        compared(
            "checks/label_on_two_nets",
            &["LVS-001", "LVS-002", "LVS-015", "DRC-084"],
            &split,
            &joined,
        )
        .expect(Expect::rule("lvs.label_conflict", vec![Finding::any()])),
    );

    // LVS-002: the same open with n0 a must-connect label (KLayout's
    // `connect_implicit`): the two nets are one to compare, so the verdict
    // is a match, and the open is still reported, as a warning, so the run
    // passes.
    let deck = format!("{}lvs connect_implicit \"n*\"\n", full_deck());
    let mut fixture = Fixture::new(
        "lvs/checks/label_on_two_nets_must_connect",
        &["LVS-002", "LVS-001"],
        &deck,
        LVS,
    )
    .layout(draw(&split))
    .expect(Expect::Lvs(true))
    .expect(Expect::rule("lvs.label_conflict", vec![Finding::any()]))
    .expect(Expect::Passes(true));
    fixture.reference = Some(spice(&joined));
    out.push(fixture);

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
        .expect(Expect::rule("lvs.net_seed_conflict", vec![Finding::any()]))
        .expect(Expect::rule("lvs.short_path", vec![step(1)])),
    );
    // LVS-005: where the short runs. A met1 bridge, a via1 at each end,
    // joins track n0 to track n1, so labels n0 and n1 are on one net, and
    // the fewest polygons between their tracks are the track, the bridge
    // and the other track: two steps, each reported (derived by hand; the
    // transistor joins n0 to no other track).
    let x = -600;
    let bridged = draw(&one)
        .rect("met1", x, track(0), x + 200, track(1) + 200)
        .rect("via1", x, track(0), x + 200, track(0) + 200)
        .rect("via1", x, track(1), x + 200, track(1) + 200);
    out.push(
        with_text(
            "checks/short_path_through_a_bridge",
            &["LVS-005"],
            bridged,
            spice(&one),
        )
        .expect(Expect::rule("lvs.net_seed_conflict", vec![Finding::any()]))
        .expect(Expect::rule("lvs.short_path", vec![step(1), step(2)])),
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
        // `lvs.terminal_count` examines every device: the one transistor drawn.
        .expect(
            Expect::rule("lvs.terminal_count", vec![Finding::any()])
                .examined(shorted.devs.len() as u64),
        );
    fixture.reference = Some(spice(&shorted));
    out.push(fixture);

    // F32 (fixed in B9), LVS-004: a MOS drawn without its drain is malformed,
    // and is reported rather than silently not a device.
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
        .expect(Expect::rule("lvs.terminal_net", vec![Finding::any()])),
    );

    // F33 (fixed in B9), LVS-004: a resistor pad drawn twice is one pad,
    // whichever copy comes first.
    let res = Circuit::new(2, vec![Dev::pins(R, &[0, 1])]);
    let (x0, y0, x1, y1) = pad(0, 0);
    let twice = (
        "pina".to_owned(),
        vec![(x0, y0), (x1, y0), (x1, y1), (x0, y1)],
    );
    let mut first = draw(&res);
    first.shapes.insert(0, twice.clone());
    let mut last = draw(&res);
    last.shapes.push(twice.clone());
    // F69 (fixed in B21), LVS-004: the first pad drawn twice and the second
    // missing is one shape for two ends. The resistor is no device and is
    // reported, where it used to bind with both ends on the first pad's net.
    let (x0, y0, x1, y1) = pad(0, 1);
    let second = vec![(x0, y0), (x1, y0), (x1, y1), (x0, y1)];
    let mut lonely = draw(&res);
    lonely
        .shapes
        .retain(|(layer, points)| !(layer == "pina" && *points == second));
    lonely.shapes.push(twice);
    out.push(
        with_text(
            "checks/pad_drawn_twice_other_missing",
            &["LVS-004", "LVS-012"],
            lonely,
            spice(&res),
        )
        .expect(Expect::rule("lvs.terminal_net", vec![Finding::any()])),
    );
    let rows = &["LVS-004", "LVS-012"];
    out.push(
        with_text("checks/pad_drawn_twice_last", rows, last, spice(&res)).expect(Expect::Lvs(true)),
    );
    out.push(
        with_text("checks/pad_drawn_twice_first", rows, first, spice(&res))
            .expect(Expect::Lvs(true)),
    );

    // LVS-003: two unlabelled tracks joined only through `pwell`, a soft
    // layer, are one net held together by it; one tap into the well is not.
    // With `crossing`, the second stub passes under the first track with no
    // via, which is no join (F27, fixed).
    let deck = format!("{}rule soft soft_connection(pwell)\n", full_deck());
    let erc = Checks { erc: true, ..NONE };
    for (name, taps, crossing, known) in [
        ("checks/soft_connection", &[0, 1][..], false, None),
        (
            "checks/soft_connection_under_a_track",
            &[0, 1][..],
            true,
            None,
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

mod netgen;
mod system;

#[cfg(test)]
mod tests {
    use super::*;

    /// LVS-017: the reference instances a mismatch leaves whole and
    /// unpaired are named, outermost first, and only those.
    ///
    /// Oracle: construct-from-answer. `TOP` holds an `nmos` and places
    /// `BLK` (one `pmos`) as `X0` and `OUTER` as `X1`, which places `BLKH`
    /// (one `nmos_hvt`) as `X2`, `X1` on nets of its own; three models, so
    /// no device can stand in for another, and a block left out leaves the
    /// rest to pair (refinement cannot pair what a missing neighbour
    /// perturbs, which is why `X1` has nets of its own). Drawn whole, the run matches and
    /// names no instance. With `X1`'s block not drawn, the one row is
    /// `X1`, measured its one device, not `X1.X2` inside it; with `X0`'s
    /// not drawn, the one row is `X0`. Breaks if an instance is named whose
    /// devices paired, an inner one is named again, or a missing one is not
    /// named.
    #[test]
    fn a_missing_instance_is_named_once_at_its_outermost() {
        use Model::{H, N, P};
        let reference = "\
.subckt BLK a b c
M0 b a c c pmos
.ends
.subckt BLKH a b c
M0 b a c c nmos_hvt
.ends
.subckt OUTER a b c
X2 a b c BLKH
.ends
.subckt TOP n0 n1 n2 n3 n4 n5
M0 n1 n0 n2 n2 nmos
X0 n1 n0 n2 BLK
X1 n3 n4 n5 OUTER
.ends
";
        let (top, x0, x1) = (
            Dev::mos(N, 0, 2, 1),
            Dev::mos(P, 1, 2, 0),
            Dev::mos(H, 3, 5, 4),
        );
        let instances = |devs: Vec<Dev>| -> Vec<String> {
            report(&draw(&Circuit::new(6, devs)), reference.to_owned())
                .into_iter()
                .filter(|line| {
                    line.starts_with("lvs.unpaired_instance") || line.starts_with("matched")
                })
                .collect()
        };
        assert_eq!(
            instances(vec![top.clone(), x0.clone(), x1.clone()]),
            ["matched Some(true)"]
        );
        let one = "lvs.unpaired_instance Count(1) (0, 0)";
        assert_eq!(
            instances(vec![top.clone(), x0]),
            [one, "matched Some(false)"]
        );
        assert_eq!(instances(vec![top, x1]), [one, "matched Some(false)"]);
    }

    /// The oracle on cases derived by hand from the documented semantics.
    ///
    /// Oracle: hand-derived from the documented semantics, case by case: source
    /// and drain swap and device order are free, a short is not, W within 2 %
    /// matches, parallel devices add width and series ones length.
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
        let mut pairs = caps.clone();
        pairs.names.extend(["n2".to_owned(), "n3".to_owned()]);
        pairs.ports.extend([true, true]);
        pairs
            .devs
            .extend([Dev::pins(C, &[2, 3]), Dev::pins(C, &[2, 3])]);
        let mut bare_and_m2 = cap.clone();
        bare_and_m2.names = pairs.names.clone();
        bare_and_m2.ports = pairs.ports.clone();
        bare_and_m2.devs.push(Dev::pins(C, &[2, 3]).times(2));
        assert!(!equivalent(&pairs, &bare_and_m2), "four are not three");
        let bare = |dev: Dev| Circuit::new(3, vec![dev.writes(false, false)]);
        assert!(
            !equivalent(&two, &bare(Dev::mos(N, 0, 1, 2))),
            "two unsized transistors are not one"
        );
        assert!(
            equivalent(&two, &bare(Dev::mos(N, 0, 1, 2).times(2))),
            "but they are one of m = 2"
        );
        let sized_only = |w, l, size: (i64, i64)| {
            Circuit::new(
                3,
                vec![Dev::mos(N, 0, 1, 2).sized(size.0, size.1).writes(w, l)],
            )
        };
        assert!(
            equivalent(&two, &sized_only(true, false, (2000, 150))),
            "W alone sums"
        );
        assert!(
            !equivalent(&two, &sized_only(false, true, (2000, 150))),
            "L alone counts two"
        );
        let inner = Circuit::new(4, vec![Dev::mos(N, 0, 1, 3), Dev::mos(N, 0, 3, 2)]).internal(3);
        assert!(
            equivalent(&inner, &sized_only(false, true, (1000, 300))),
            "L alone stacks"
        );
        assert!(
            !equivalent(&inner, &sized_only(true, false, (1000, 300))),
            "W alone does not"
        );
        let one = |dev: Dev| Circuit::new(2, vec![dev]);
        let res = one(Dev::pins(R, &[0, 1]));
        let r = |ohms| one(Dev::pins(R, &[0, 1]).value(ohms));
        assert!(equivalent(&res, &r(200.0)), "100 ohm/sq over 800 / 400");
        assert!(!equivalent(&res, &r(210.0)), "5 % over");
        let c = |farads| one(Dev::pins(C, &[0, 1]).value(farads));
        assert!(
            equivalent(&cap, &c(5.6e-16)),
            "0.32 fF of plate and 0.24 fF of fringe"
        );
        assert!(!equivalent(&cap, &c(3.2e-16)), "the plate alone");
        let diode = one(Dev::pins(D, &[0, 1]));
        let perim = |metres| one(Dev::pins(D, &[0, 1]).param("perim", metres));
        assert!(equivalent(&diode, &perim(2.4e-6)), "2 (800 + 400) nm");
        assert!(!equivalent(&diode, &perim(2.64e-6)), "10 % over");
        let top = Circuit::new(3, vec![Dev::mos(N, 0, 2, 1)]);
        let block = Circuit::new(3, vec![Dev::mos(P, 1, 2, 0)]);
        let flat = flatten(&top, &block, &[1, 0, 2]);
        assert_eq!(
            flat.devs[1].pins,
            vec![0, 2, 1],
            "the block lands on its ports"
        );
    }

    /// The classes of one to three `nmos`/`pmos` on nets `0..nets`, not every
    /// net used, under renaming nets and devices and swapping source with
    /// drain, by Burnside's lemma: the mean, over the renamings of the nets,
    /// of the circuits each one fixes. A circuit is a multiset of device types
    /// (model, gate, unordered channel ends), and the multisets of `m` types a
    /// renaming fixes are the `x^m` coefficient of the product, over its
    /// cycles on the types, of `1 / (1 - x^length)` (Pólya). No canonical form
    /// and none of [`key`], [`circuits`] or [`permutations`].
    fn orbits(nets: usize) -> usize {
        let mut types = Vec::new();
        for model in 0..2 {
            for g in 0..nets {
                for s in 0..nets {
                    for d in s..nets {
                        types.push([model, g, s, d]);
                    }
                }
            }
        }
        let (mut group, mut fixed) = (0, 0);
        for code in 0..nets.pow(u32::try_from(nets).expect("few nets")) {
            // Net k goes to digit k of `code` in base `nets`: every map of
            // the nets, and a renaming where the digits are distinct.
            let mut rest = code;
            let rename: Vec<usize> = (0..nets)
                .map(|_| {
                    let digit = rest % nets;
                    rest /= nets;
                    digit
                })
                .collect();
            if (0..nets).any(|k| rename[k + 1..].contains(&rename[k])) {
                continue;
            }
            group += 1;
            let image = |&[model, g, s, d]: &[usize; 4]| {
                let (s, d) = (rename[s], rename[d]);
                [model, rename[g], s.min(d), s.max(d)]
            };
            let mut seen = vec![false; types.len()];
            let mut series = [1, 0, 0, 0];
            for start in 0..types.len() {
                let (mut at, mut length) = (start, 0);
                while !seen[at] {
                    seen[at] = true;
                    length += 1;
                    let next = image(&types[at]);
                    at = types
                        .iter()
                        .position(|t| *t == next)
                        .expect("a renaming permutes the types");
                }
                if length > 0 {
                    for degree in length..series.len() {
                        series[degree] += series[degree - length];
                    }
                }
            }
            fixed += series[1..].iter().sum::<usize>();
        }
        assert_eq!(fixed % group, 0, "Burnside: a whole number of orbits");
        fixed / group
    }

    /// The enumeration has one circuit per class, for each count of nets.
    ///
    /// Oracle: differential against an independent count, [`orbits`], by
    /// Burnside's lemma rather than a canonical form. A class on nets `0..n`
    /// uses some `k <= n` of them and is, renumbered, a class on `0..k` using
    /// every net, which is what [`circuits`] lists for `k`: so it lists
    /// `orbits(n) - orbits(n - 1)` for `n` nets, and `orbits(4)`, the 4223 the
    /// module docs state, in all. A canonical form that splits a class or
    /// merges two, or an enumeration that misses a circuit, changes a count.
    #[test]
    fn the_enumeration_has_every_canonical_circuit() {
        let all = circuits();
        for nets in 1..=4 {
            assert_eq!(
                all.iter().filter(|c| c.nets() == nets).count(),
                orbits(nets) - orbits(nets - 1),
                "{nets} nets"
            );
        }
        assert_eq!((all.len(), orbits(4)), (4223, 4223));
    }

    // Metamorphic relations (P1): each compares two runs of the tool, so it
    // takes no expected value from the brute-force oracle above, and is a
    // second, independent oracle for the rows the fixtures prove with it.

    /// A run of `layout` on [`full_deck`] against `reference`, as sorted text
    /// with names resolved: every rule row and every finding, then whether
    /// LVS matched.
    fn report(layout: &Layout, reference: String) -> Vec<String> {
        let mut fixture =
            Fixture::new("lvs/relation", &["LVS-019"], &full_deck(), LVS).layout(layout.clone());
        fixture.reference = Some(reference);
        let ran = crate::harness::run(&fixture).unwrap_or_else(|why| panic!("{why}"));
        let mut lines: Vec<String> = ran
            .rows
            .iter()
            .map(|(rule, outcome, _)| format!("{rule} {outcome:?}"))
            .chain(
                ran.findings
                    .iter()
                    .map(|(rule, measured, at)| format!("{rule} {measured:?} {at:?}")),
            )
            .collect();
        lines.sort();
        lines.push(format!(
            "matched {:?}",
            ran.lvs
                .map(|verdict| matches!(verdict, gpurify::check::lvs::Verdict::Match))
        ));
        lines
    }

    /// Every one-device circuit of the enumeration and every 211th other
    /// (ponytail: a fixed stride, not a seeded draw; the fixtures sample
    /// the rest).
    fn sample() -> Vec<Circuit> {
        circuits()
            .into_iter()
            .enumerate()
            .filter(|(index, c)| c.devs.len() == 1 || index % 211 == 0)
            .map(|(_, c)| c)
            .collect()
    }

    /// LVS-071: one circuit gets one report whichever dialect states it.
    ///
    /// Oracle: metamorphic relation. [`spice`] and [`spectre`] write the
    /// same circuit in the reader's two documented dialects (the `netlist`
    /// module docs), so every rule row, every finding and the verdict must be
    /// the same for both: on every circuit of [`sample`] against itself and
    /// each of its single [`faults`], and on [`every_model`] as drawn and with
    /// two pins swapped. A Spectre card read as another device, terminal
    /// order or parameter breaks it.
    #[test]
    fn a_reference_reads_the_same_in_spice_and_spectre() {
        let mut pairs = Vec::new();
        for (drawn, moved) in every_model() {
            pairs.push((drawn.clone(), drawn.clone()));
            pairs.push((drawn, moved));
        }
        for c in sample() {
            pairs.push((c.clone(), c.clone()));
            for (_, written, _) in faults(&c) {
                pairs.push((c.clone(), written));
            }
        }
        for (drawn, written) in &pairs {
            let layout = draw(drawn);
            assert_eq!(
                report(&layout, spice(written)),
                report(&layout, spectre(written)),
                "{} drawn, {} written",
                drawn.code(),
                written.code()
            );
        }
    }

    /// LVS-020: a parameter the layout cannot measure, stated on one card, is
    /// one `lvs.undeclared_param` row and changes nothing else, whatever its
    /// value.
    ///
    /// Oracle: metamorphic relation. From a reference that matches its
    /// layout, adding `nrd` (BSIM's drain squares, which no recogniser
    /// measures: `DeviceParam` lists what one does) to any one card keeps
    /// every other row and finding, and adds exactly one
    /// `lvs.undeclared_param` finding and the mismatch; `nrd=1` and
    /// `nrd=1000` give the same report. On every device of every circuit of
    /// [`sample`] and [`every_model`] that reduces nothing, so the added
    /// parameter cannot stop a merge. A stated value taken as agreement with
    /// the layout's silence, or one compared by value, breaks it.
    #[test]
    fn an_unmeasured_parameter_is_one_undeclared_row_whatever_its_value() {
        let drawn = every_model().into_iter().map(|(drawn, _)| drawn);
        let mut checked = 0;
        for c in sample().into_iter().chain(drawn) {
            if reduce(&c, &Declared::of(&c), false, &Controls::default())
                .devs
                .len()
                < c.devs.len()
            {
                continue;
            }
            let layout = draw(&c);
            let base = report(&layout, spice(&c));
            let (verdict, rows) = base.split_last().expect("a verdict line");
            assert_eq!(verdict, "matched Some(true)", "{}", c.code());
            for i in 0..c.devs.len() {
                let stated = |value| {
                    let mut written = c.clone();
                    written.devs[i] = written.devs[i].clone().param("nrd", value);
                    report(&layout, spice(&written))
                };
                let mut added = stated(1.0);
                assert_eq!(added, stated(1000.0), "{}: device {i}", c.code());
                for line in rows {
                    let at = added
                        .iter()
                        .position(|have| have == line)
                        .unwrap_or_else(|| panic!("{}: device {i} lost {line}", c.code()));
                    added.remove(at);
                }
                assert!(
                    added.len() == 2
                        && added[0].starts_with("lvs.undeclared_param ")
                        && added[1] == "matched Some(false)",
                    "{}: device {i} added {added:?}",
                    c.code()
                );
                checked += 1;
            }
        }
        assert!(checked >= 30, "only {checked} cards checked");
    }

    /// LVS-066: the `hvt` implant over an `nmos` gate, and only over its
    /// gate, makes it the deck's `nmos_hvt` flavour (`gate_nh = gate_n and
    /// hvt`, `gate_nl = gate_n not hvt`).
    ///
    /// Oracle: metamorphic relation. Adding `hvt` over exactly one `nmos`
    /// gate gives, against any reference, the report of the same circuit
    /// drawn with that device an `nmos_hvt` (the implant over its whole
    /// device), and so flips the verdict against both the plain reference
    /// and the flavoured one; adding it over that device's source diffusion,
    /// beside the gate, changes nothing. On every `nmos` of every circuit of
    /// [`sample`]. A flavour read from anything but the gate's implant
    /// breaks it.
    #[test]
    fn an_implant_marker_on_a_gate_flips_its_flavour() {
        let mut checked = 0;
        for c in sample() {
            for (i, dev) in c.devs.iter().enumerate() {
                if dev.model != Model::N {
                    continue;
                }
                // [`draw_mos`]'s channel, and its source diffusion short of it.
                let x0 = column(i);
                let gate = (x0 + SD, 0, x0 + SD + dev.l, dev.w);
                let beside = (x0, 0, x0 + SD - 100, dev.w);
                let marked = |(xlo, ylo, xhi, yhi): (i64, i64, i64, i64)| {
                    draw(&c).rect("hvt", xlo, ylo, xhi, yhi)
                };
                let mut flavoured = c.clone();
                flavoured.devs[i].model = Model::H;
                for reference in [&c, &flavoured] {
                    let text = spice(reference);
                    let plain = report(&draw(&c), text.clone());
                    let on_gate = report(&marked(gate), text.clone());
                    let what = format!("{} device {i} against {}", c.code(), reference.code());
                    assert_eq!(
                        on_gate,
                        report(&draw(&flavoured), text.clone()),
                        "{what}: on the gate"
                    );
                    assert_ne!(on_gate.last(), plain.last(), "{what}: the verdict flips");
                    assert_eq!(
                        report(&marked(beside), text),
                        plain,
                        "{what}: beside the gate"
                    );
                }
                checked += 1;
            }
        }
        assert!(checked >= 20, "only {checked} nmos checked");
    }

    /// Oracle: hand-derived from the drawing, testing-plan F100. Liberty's
    /// circuit gives a MOS the diffusions LVS compares, topology's, not a
    /// measure of its own. [`draw`]'s nmos, 1000 by 150 nm, its diffusion
    /// redrawn round a 200 nm square hole at (150, 400) in its source: the
    /// source, 500 by 1000 nm, has `as` = 500 · 1000 − 200 · 200 = 460 000
    /// nm² and `ps` = 2 (500 + 1000) + 4 · 200 = 3800 nm, the hole's edge an
    /// edge of the diffusion; the drain, whole, `ad` = 500 000 nm² and `pd`
    /// = 3000 nm. Liberty used to measure the outer ring alone, 500 000 nm²
    /// and 3000 nm at the source.
    #[test]
    fn liberty_reads_the_diffusions_lvs_compares() {
        use gpurify::liberty::circuit::{build, Param, Wires};
        let mut layout = draw(&Circuit::new(3, vec![Dev::mos(Model::N, 0, 1, 2)]));
        layout.shapes.retain(|(layer, _)| layer.as_str() != "diff");
        let layout = layout
            .rect("diff", 0, 0, 1150, 400)
            .rect("diff", 0, 600, 1150, 1000)
            .rect("diff", 0, 400, 150, 600)
            .rect("diff", 350, 400, 1150, 600);
        let fixture =
            Fixture::new("lvs/liberty_diffusions", &[], &full_deck(), NONE).layout(layout);
        let ran = crate::harness::run(&fixture).expect("the drawing runs");
        let spec = gpurify::liberty::spec::parse(
            r#"{"cell": "TOP", "pins": [
                {"name": "n0", "role": "input", "power": "n1", "ground": "n2"},
                {"name": "n1", "role": "power"}, {"name": "n2", "role": "ground"}],
                "corners": [{"name": "tt", "temperature": 25,
                             "supplies": {"n1": 1.8, "n2": 0}, "models": []}]}"#,
        )
        .expect("a valid spec");
        let built =
            build(&ran.loaded, &ran.extracted, &spec, Wires::Lumped).expect("pins labelled");
        let [mos] = &built.devices[..] else {
            panic!("one transistor: {:?}", built.devices);
        };
        for (name, want) in [
            ("as", Param::Area(4.6e-13)),
            ("ps", Param::Length(3.8e-6)),
            ("ad", Param::Area(5e-13)),
            ("pd", Param::Length(3e-6)),
        ] {
            let got = mos.params.iter().find(|p| p.0 == name).map(|p| p.1);
            let close = match (got, want) {
                (Some(Param::Area(a)), Param::Area(b))
                | (Some(Param::Length(a)), Param::Length(b)) => (a - b).abs() <= 1e-9 * b,
                _ => false,
            };
            assert!(close, "{name}: {got:?}, want {want:?}");
        }
    }
}
