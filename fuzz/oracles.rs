//! One entry point per fuzz target (docs/testing-plan.md L4), each with the
//! oracle the plan gives it beyond "no panic".
//!
//! Shared by the `cargo fuzz` targets in `fuzz_targets/` (nightly) and by
//! `tests/fuzz_regressions.rs`, which replays every committed crasher and
//! seed through the same functions on stable. Every input is raw bytes, so a
//! crasher file replays identically in both; the structured targets decode
//! their bytes with [`Bytes`], never with a crate the main workspace lacks.
//! A crate root including this module also includes
//! `tests/exhaustive/harness.rs` and `tests/exhaustive/bitmap.rs` as
//! `harness` and `bitmap`, which [`drc_e2e`] reads.

use gpurify::check::lvs::CompareOptions;
use gpurify::engine::pipeline::{extract, intern_report_ids, Loaded};
use gpurify::engine::run::{run_checks, Checks, RunOptions};
use gpurify::geom::{GeometryStore, Grid, LayerId, PolyId};
use gpurify_ingest::deck::{parse_deck, Deck, DeckError, DeviceRecognition};
use gpurify_ingest::layout::{derive_layers, gds, LayoutError, UnknownLayers};
use gpurify_ingest::netlist::{Netlist, NetlistError, SubcktId};
use gpurify_ingest::{Provenance, StrTable};
use gpurify_testgen::gds::{write_library, write_store, Array, Placement, Structure};
use gpurify_testgen::LayoutBuilder;

/// Raw fuzz bytes read front to back; past the end every read is zero, so
/// any input decodes.
pub struct Bytes<'a>(pub &'a [u8]);

impl Bytes<'_> {
    /// The next byte, or 0.
    pub fn u8(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&first, rest)) => {
                self.0 = rest;
                first
            }
            None => 0,
        }
    }

    /// The next two bytes, big-endian.
    pub fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.u8(), self.u8()])
    }

    /// The next two bytes as a signed value.
    pub fn i16(&mut self) -> i16 {
        i16::from_be_bytes([self.u8(), self.u8()])
    }

    /// The next four bytes, big-endian.
    pub fn u32(&mut self) -> u32 {
        u32::from_be_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
}

/// The 1 nm grid every deck here is parsed on, the GDS writer's.
fn nm_grid() -> Grid {
    Grid::new(1000).expect("1000 database units per micrometre is a grid")
}

/// Whether two stores hold the same rows, in the same order, on the same layers.
fn same_store(a: &GeometryStore, b: &GeometryStore) -> bool {
    a.layer_count() == b.layer_count()
        && a.poly_count() == b.poly_count()
        && (0..a.layer_count()).all(|layer| {
            let layer = LayerId(u16::try_from(layer).expect("a layer id is a u16"));
            a.polys_on_layer(layer) == b.polys_on_layer(layer)
        })
        && (0..a.poly_count()).all(|row| {
            let row = PolyId(u32::try_from(row).expect("a polygon id is a u32"));
            a.poly_verts(row) == b.poly_verts(row)
        })
}

// ------------------------------------------------------------------- gds ---

/// Layers 0/0 to 15/0, plus three derived layers so booleans and sizing meet
/// whatever geometry the fuzzer draws.
const GDS_DECK: &str = "grid 1nm
layer l0 = gds(0, 0)
layer l1 = gds(1, 0)
layer l2 = gds(2, 0)
layer l3 = gds(3, 0)
layer l4 = gds(4, 0)
layer l5 = gds(5, 0)
layer l6 = gds(6, 0)
layer l7 = gds(7, 0)
layer l8 = gds(8, 0)
layer l9 = gds(9, 0)
layer l10 = gds(10, 0)
layer l11 = gds(11, 0)
layer l12 = gds(12, 0)
layer l13 = gds(13, 0)
layer l14 = gds(14, 0)
layer l15 = gds(15, 0)
layer joined = l1 or l2
layer cut = l1 not l2
layer grown = l3.sized(10nm)
";

fn gds_deck(strings: &mut StrTable) -> Deck {
    parse_deck(GDS_DECK, nm_grid(), strings).expect("the fixed deck parses")
}

/// The most polygons a fuzz input may flatten to: 64 per input byte. A small
/// file can legally place 2^28 polygons ([`gpurify_ingest::layout::MAX_FLAT_POLYGONS`]),
/// which no fuzz run has memory for; the count is taken before expanding.
fn flat_budget(input: usize) -> u64 {
    64 * u64::try_from(input).expect("an input length fits a u64") + 4096
}

/// `gds::Library::parse` on arbitrary bytes.
///
/// Oracle: a typed error, never a panic; flattening within [`flat_budget`];
/// and a layout that flattens and can be written back (every coordinate in
/// 32 bits, every ring, holes slit in, in one record) reads back to the same
/// store, holes and derived layers included.
pub fn gds(data: &[u8]) {
    let mut strings = StrTable::default();
    let Ok(library) = gds::Library::parse(data, &mut strings) else {
        return;
    };
    let _ = library.grid();
    let deck = gds_deck(&mut strings);
    match library.flat_polygons(&strings) {
        Ok(polygons) if polygons <= flat_budget(data.len()) => {}
        _ => return,
    }
    let Ok((store, _labels)) = library.flatten(&deck, &strings, UnknownLayers::Drop) else {
        return;
    };

    let mut bytes = Vec::new();
    if write_store(&store, &deck.layers, "TOP", &mut bytes).is_err() {
        return;
    }
    let mut again = StrTable::default();
    let reread = gds::Library::parse(&bytes, &mut again).expect("a written store parses");
    let deck = gds_deck(&mut again);
    let (round_tripped, _) = reread
        .flatten(&deck, &again, UnknownLayers::Reject)
        .expect("a written store flattens");
    assert!(
        same_store(&store, &round_tripped),
        "parse -> write -> parse changed the store"
    );
}

// -------------------------------------------------------- gds_structured ---

/// The deepest placement chain the reader accepts, root included.
const MAX_DEPTH: usize = gpurify_ingest::layout::MAX_HIERARCHY_DEPTH as usize;

/// A hierarchy decoded from the input, with what flattening it must give,
/// computed from the decoded structures alone.
struct Hierarchy {
    cells: Vec<Structure>,
    /// Each cell's children, one entry per placement, with its copy count.
    children: Vec<Vec<(usize, u128)>>,
    /// Each cell's magnification per placement, parallel to `children`.
    mags: Vec<Vec<u128>>,
    /// Each cell's own rectangle count and area.
    own: Vec<(u128, u128)>,
    /// The extra chain's length: cells that only place the next, the last
    /// placing cell 0.
    chain: usize,
}

/// Up to 8 cells of up to 3 rectangles and 3 placements each (any cell,
/// itself included; up to 256 × 256 arrays; mirror, quarter turns, mag 1 or
/// 2), plus a chain of up to 1199 cells above cell 0. Every coordinate stays
/// far inside the reader's range: offsets and steps are 16-bit, and at most
/// eight levels magnify.
fn hierarchy(b: &mut Bytes<'_>) -> Hierarchy {
    let n = 1 + usize::from(b.u8() % 8);
    let chain = usize::from(b.u16() % 1200);
    let mut h = Hierarchy {
        cells: Vec::new(),
        children: Vec::new(),
        mags: Vec::new(),
        own: Vec::new(),
        chain,
    };
    for i in 0..n {
        let mut cell = Structure {
            name: format!("C{i}"),
            ..Structure::default()
        };
        let mut area = 0u128;
        for _ in 0..b.u8() % 4 {
            let layer = 1 + u16::from(b.u8() % 3);
            let (x, y) = (i32::from(b.i16()), i32::from(b.i16()));
            let (w, tall) = (1 + i32::from(b.u8()), 1 + i32::from(b.u8()));
            area += u128::try_from(w * tall).expect("positive");
            cell.rects.push((layer, 0, [x, y, x + w, y + tall]));
        }
        let (mut children, mut mags) = (Vec::new(), Vec::new());
        for _ in 0..b.u8() % 4 {
            let child = usize::from(b.u8()) % n;
            let flags = b.u8();
            let mag = 1 + u32::from(flags >> 2 & 1);
            let at = (i32::from(b.i16()), i32::from(b.i16()));
            let array = (flags & 8 != 0).then(|| Array {
                cols: 1 + u16::from(b.u8()),
                rows: 1 + u16::from(b.u8()),
                col_step: (i32::from(b.i16()), i32::from(b.i16())),
                row_step: (i32::from(b.i16()), i32::from(b.i16())),
            });
            let copies = array.map_or(1, |a| u128::from(a.cols) * u128::from(a.rows));
            children.push((child, copies));
            mags.push(u128::from(mag));
            cell.refs.push(Placement {
                cell: format!("C{child}"),
                reflect: flags & 1 != 0,
                quarter_turns: flags >> 4 & 3,
                mag,
                at,
                array,
            });
        }
        h.own.push((
            u128::from(u8::try_from(cell.rects.len()).expect("< 4")),
            area,
        ));
        h.cells.push(cell);
        h.children.push(children);
        h.mags.push(mags);
    }
    for j in 0..chain {
        let (next, child) = if j + 1 == chain {
            ("C0".to_owned(), 0)
        } else {
            (format!("D{}", j + 1), n + j + 1)
        };
        h.cells.push(Structure {
            name: format!("D{j}"),
            rects: Vec::new(),
            refs: vec![Placement {
                cell: next,
                reflect: false,
                quarter_turns: 0,
                mag: 1,
                at: (0, 0),
                array: None,
            }],
        });
        h.children.push(vec![(child, 1)]);
        h.mags.push(vec![1]);
        h.own.push((0, 0));
    }
    h
}

impl Hierarchy {
    /// Whether any cell reaches itself.
    fn has_cycle(&self) -> bool {
        // 0 unvisited, 1 on the path, 2 done; iterative so a deep chain cannot
        // overflow the oracle's own stack.
        let mut state = vec![0u8; self.cells.len()];
        for start in 0..self.cells.len() {
            if state[start] != 0 {
                continue;
            }
            let mut stack = vec![(start, 0usize)];
            state[start] = 1;
            while let Some(&mut (cell, ref mut next)) = stack.last_mut() {
                if let Some(&(child, _)) = self.children[cell].get(*next) {
                    *next += 1;
                    match state[child] {
                        1 => return true,
                        0 => {
                            state[child] = 1;
                            stack.push((child, 0));
                        }
                        _ => {}
                    }
                } else {
                    state[cell] = 2;
                    stack.pop();
                }
            }
        }
        false
    }

    /// For an acyclic hierarchy, what each cell flattens to.
    fn totals(&self) -> Vec<Flat> {
        let mut out: Vec<Option<Flat>> = vec![None; self.cells.len()];
        // Chain cells only place later chain cells or cell 0, and general
        // cells only general ones, so a post-order over every cell works.
        let mut order = Vec::new();
        let mut seen = vec![false; self.cells.len()];
        for start in 0..self.cells.len() {
            let mut stack = vec![(start, false)];
            while let Some((cell, expanded)) = stack.pop() {
                if expanded {
                    order.push(cell);
                } else if !seen[cell] {
                    seen[cell] = true;
                    stack.push((cell, true));
                    stack.extend(self.children[cell].iter().map(|&(c, _)| (c, false)));
                }
            }
        }
        for cell in order {
            let (count, area) = self.own[cell];
            let mut flat = Flat {
                depth: 1,
                count,
                area,
                visits: 1,
            };
            for (&(child, copies), &mag) in self.children[cell].iter().zip(&self.mags[cell]) {
                let below = out[child].expect("children come first");
                flat.depth = flat.depth.max(below.depth + 1);
                flat.count = flat
                    .count
                    .saturating_add(copies.saturating_mul(below.count));
                flat.area = flat
                    .area
                    .saturating_add(copies.saturating_mul(mag * mag).saturating_mul(below.area));
                // Flattening does not walk a subtree with no polygon in it.
                if below.count > 0 {
                    flat.visits = flat
                        .visits
                        .saturating_add(copies.saturating_mul(below.visits));
                }
            }
            out[cell] = Some(flat);
        }
        out.into_iter().map(|t| t.expect("every cell")).collect()
    }
}

/// What one cell of an acyclic [`Hierarchy`] flattens to.
#[derive(Debug, Clone, Copy)]
struct Flat {
    /// Levels from the cell down, itself included.
    depth: usize,
    /// Polygons.
    count: u128,
    /// Total area, in square database units.
    area: u128,
    /// Placements walked, the cell's own included, none into a subtree
    /// holding no polygon.
    visits: u128,
}

/// An arbitrary hierarchy written with the test GDS writer and read back.
///
/// Oracle: no stack overflow (F3); any cycle, reached from a root or not, is
/// `CyclicHierarchy` (`HierarchyTooDeep` only where a chain past the cap
/// precedes it); a chain past the cap is `HierarchyTooDeep`; more than
/// `MAX_FLAT_POLYGONS` is `TooManyPolygons`; otherwise the flat count is Σ
/// instances × shapes and the flat area Σ instances × mag² × area, both
/// computed from the decoded structures, and every flat ring is
/// counter-clockwise. An array of a cell holding nothing costs nothing to
/// flatten, however large: the walk is bounded by the placements that reach
/// a polygon.
pub fn gds_structured(data: &[u8]) {
    let h = hierarchy(&mut Bytes(data));
    let mut bytes = Vec::new();
    write_library(&h.cells, &mut bytes).expect("the decoded hierarchy is writable");
    let mut strings = StrTable::default();
    let library = gds::Library::parse(&bytes, &mut strings).expect("a written library parses");
    let deck = parse_deck(
        "grid 1nm\nlayer a = gds(1, 0)\nlayer b = gds(2, 0)\nlayer c = gds(3, 0)\n",
        nm_grid(),
        &mut strings,
    )
    .expect("the fixed deck parses");
    let counted = library.flat_polygons(&strings);

    if h.has_cycle() {
        let deep = h.chain + h.cells.len() > MAX_DEPTH;
        assert!(
            matches!(counted, Err(LayoutError::CyclicHierarchy(_)))
                || (deep && matches!(counted, Err(LayoutError::HierarchyTooDeep(_)))),
            "a cycle read as {counted:?}"
        );
        return;
    }
    let totals = h.totals();
    let roots: Vec<usize> = {
        let mut placed = vec![false; h.cells.len()];
        for children in &h.children {
            for &(child, _) in children {
                placed[child] = true;
            }
        }
        (0..h.cells.len()).filter(|&c| !placed[c]).collect()
    };
    let depth = roots.iter().map(|&r| totals[r].depth).max().unwrap_or(0);
    if depth > MAX_DEPTH {
        assert!(
            matches!(counted, Err(LayoutError::HierarchyTooDeep(_))),
            "a chain {depth} deep read as {counted:?}"
        );
        return;
    }
    let count = roots
        .iter()
        .map(|&r| totals[r].count)
        .fold(0u128, u128::saturating_add);
    let saturated = u64::try_from(count).unwrap_or(u64::MAX);
    assert_eq!(counted.ok(), Some(saturated), "the flat count");
    if count > u128::from(gpurify_ingest::layout::MAX_FLAT_POLYGONS) {
        let refused = library.flatten(&deck, &strings, UnknownLayers::Reject);
        assert!(
            matches!(refused, Err(LayoutError::TooManyPolygons(n)) if n == saturated),
            "{count} polygons read as {refused:?}"
        );
        return;
    }
    // Legal, but more than a fuzz run should expand: the polygons, or the
    // placements walked to reach them (depth times polygons at most).
    let visits = roots
        .iter()
        .map(|&r| totals[r].visits)
        .fold(0u128, u128::saturating_add);
    if count > 1 << 16 || visits > 1 << 20 {
        return;
    }
    let (store, _) = library
        .flatten(&deck, &strings, UnknownLayers::Reject)
        .expect("an acyclic hierarchy in range flattens");
    assert_eq!(u128::try_from(store.poly_count()).ok(), Some(count));
    let mut twice_area = 0i128;
    for row in 0..store.poly_count() {
        let (xs, ys) = store.poly_verts(PolyId(u32::try_from(row).expect("a u32 row")));
        let a2 = gpurify::geom::ops::area2(xs, ys).raw();
        assert!(a2 > 0, "row {row} is not counter-clockwise");
        twice_area += a2;
    }
    let area = roots.iter().map(|&r| totals[r].area).sum::<u128>();
    assert_eq!(
        u128::try_from(twice_area).ok(),
        Some(2 * area),
        "the flat area"
    );
}

// ------------------------------------------------------------------ deck ---

/// `deck::parse_deck` on arbitrary text, then DRC and ERC over one square on
/// every drawn layer.
///
/// Oracle (B15): every error diagnostic's span lies inside the input on
/// character boundaries, and every `rule` an accepted deck holds gets a row
/// in the run table.
pub fn deck(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut strings = StrTable::default();
    let deck = match parse_deck(text, nm_grid(), &mut strings) {
        Ok(deck) => deck,
        Err(DeckError::Invalid { diagnostics, .. }) => {
            assert!(!diagnostics.is_empty(), "a refusal with no diagnostic");
            for d in &diagnostics {
                let (start, end) = (d.start as usize, d.end as usize);
                assert!(
                    start <= end
                        && end <= text.len()
                        && text.is_char_boundary(start)
                        && text.is_char_boundary(end),
                    "span {start}..{end} of a {}-byte deck: {}",
                    text.len(),
                    d.message
                );
            }
            return;
        }
        Err(_) => return,
    };

    let mut layout = LayoutBuilder::new(deck.layers.len());
    for layer in 0..deck.layers.len() {
        let layer = LayerId(u16::try_from(layer).expect("a layer id is a u16"));
        if !deck.layers.is_derived(layer) {
            layout.rect(layer, 0, 0, 1000, 1000);
        }
    }
    let (mut store, _) = layout.finish();
    let provenance = Provenance::default();
    if derive_layers(&mut store, &deck, &provenance, &strings).is_err() {
        return;
    }
    intern_report_ids(&mut strings);
    let rules: Vec<_> = deck.rules.spec.iter().map(|rule| rule.id).collect();
    let loaded = Loaded {
        strings,
        grid: nm_grid(),
        deck,
        store,
        provenance,
        reference: None,
        intent: None,
    };
    let Ok(extracted) = extract(&loaded) else {
        return;
    };
    let options = RunOptions {
        checks: Checks {
            drc: true,
            erc: true,
            lvs: false,
            pex: false,
        },
        lvs: CompareOptions::default(),
        quasistatic_nets: Vec::new(),
    };
    let Ok((outputs, _)) = run_checks(&loaded, &extracted, &options) else {
        return;
    };
    for id in rules {
        assert!(
            outputs.runs.iter().any(|run| run.rule == id),
            "rule {} has no row in the run table",
            loaded.strings.resolve(id)
        );
    }
}

// --------------------------------------------------------------- netlists ---

/// SPICE cards counted without the reader: `(device cards, X cards)`. A card
/// is a line's first token after `*` comment lines and `$`/`;` tails are
/// dropped, unless the line continues the last card with `+`.
fn spice_cards(text: &str) -> (usize, usize) {
    let (mut devices, mut instances, mut cards) = (0, 0, 0);
    for raw in text.lines() {
        let line = if raw.trim_start().starts_with('*') {
            ""
        } else {
            raw.split(['$', ';']).next().unwrap_or("")
        };
        let (line, continues) = match line.trim_start().strip_prefix('+') {
            Some(rest) => (rest, true),
            None => (line, false),
        };
        let Some(head) = line.split_whitespace().next() else {
            continue;
        };
        if continues && cards > 0 {
            continue;
        }
        cards += 1;
        match head.chars().next().map(|c| c.to_ascii_uppercase()) {
            Some('M' | 'Q' | 'R' | 'C' | 'D') => devices += 1,
            Some('X') => instances += 1,
            _ => {}
        }
    }
    (devices, instances)
}

/// The most devices, nets and instances a fuzz input's reference is expanded
/// to. `Netlist::flatten_top` refuses past `MAX_FLAT_ELEMENTS` (2^28) itself,
/// counted before expanding (F89), but a reference just under that is more
/// than a fuzz run has memory for: inputs between the two are not expanded.
const FLAT_ELEMENTS: u128 = 1 << 20;

/// Flattens `netlist` below its top, as LVS loads a reference, when it has
/// one top and at most 1000 subcircuits (the oracle's own walk recurses).
///
/// Oracle, counted from the tables: a cycle the top reaches is
/// `CyclicHierarchy`; a top whose devices, nets and instances number more
/// than `MAX_FLAT_ELEMENTS` is `TooLarge` with that number, saturated to a
/// `u64`; otherwise, within [`FLAT_ELEMENTS`], the flat netlist holds each
/// subcircuit's devices once per instance path, and the top's nets plus,
/// per instance, its callee's nets that are not on a port.
fn flatten_checked(netlist: &Netlist, strings: &mut StrTable) {
    /// `(devices, nets, instances)` below one placement of `cell`, each
    /// instance with the nets it adds; `None` on a cycle.
    fn flat(
        cell: usize,
        calls: &[Vec<usize>],
        own: &[(u128, u128)],
        memo: &mut [Option<[u128; 3]>],
        on_path: &mut [bool],
    ) -> Option<[u128; 3]> {
        if let Some(count) = memo[cell] {
            return Some(count);
        }
        if on_path[cell] {
            return None;
        }
        on_path[cell] = true;
        let mut count = [own[cell].0, 0, 0];
        for &callee in &calls[cell] {
            let [devices, nets, instances] = flat(callee, calls, own, memo, on_path)?;
            count = [
                count[0].saturating_add(devices),
                count[1].saturating_add(own[callee].1).saturating_add(nets),
                count[2].saturating_add(1).saturating_add(instances),
            ];
        }
        on_path[cell] = false;
        memo[cell] = Some(count);
        Some(count)
    }

    let Some(top) = netlist.top() else {
        return;
    };
    let n = netlist.subckt_count();
    if n > 1000 {
        return;
    }
    let mut calls = vec![Vec::new(); n];
    for (&caller, &callee) in netlist.instance_subckt.iter().zip(&netlist.instance_of) {
        calls[caller.0 as usize].push(callee.0 as usize);
    }
    // Per subcircuit: its devices, and its nets that are not on its ports.
    let mut own: Vec<(u128, u128)> = (0..n)
        .map(|c| {
            let rows = netlist.devices_of(SubcktId(u32::try_from(c).expect("under 1000")));
            (u128::from(rows.end - rows.start), 0)
        })
        .collect();
    for (net, cell) in netlist.net_subckt.iter().enumerate() {
        let on_port = netlist.port_net.iter().any(|port| port.0 as usize == net);
        own[cell.0 as usize].1 += u128::from(!on_port);
    }
    let top_nets = netlist
        .net_subckt
        .iter()
        .filter(|&&cell| cell == top)
        .count() as u128;
    let expected = flat(
        top.0 as usize,
        &calls,
        &own,
        &mut vec![None; n],
        &mut vec![false; n],
    );
    let Some([devices, nets, instances]) = expected else {
        assert!(
            matches!(
                netlist.flatten_top(top, strings),
                Err(NetlistError::CyclicHierarchy(_))
            ),
            "a cycle under the top flattened"
        );
        return;
    };
    let nets = top_nets.saturating_add(nets);
    let total = devices.saturating_add(nets).saturating_add(instances);
    if total > u128::from(gpurify_ingest::netlist::MAX_FLAT_ELEMENTS) {
        let saturated = u64::try_from(total).unwrap_or(u64::MAX);
        let refused = netlist.flatten_top(top, strings);
        assert!(
            matches!(refused, Err(NetlistError::TooLarge(count)) if count == saturated),
            "{total} elements read as {:?}",
            refused.map(|flat| flat.device_model.len())
        );
    } else if total <= FLAT_ELEMENTS {
        let flat = netlist
            .flatten_top(top, strings)
            .expect("an acyclic reference within the cap flattens");
        assert_eq!(flat.device_model.len() as u128, devices, "flat devices");
        assert_eq!(flat.net_name.len() as u128, nets, "flat nets");
    }
}

/// `netlist::spice::read` on arbitrary text, with no deck device models, then
/// the flattening below the top LVS does.
///
/// Oracle: a typed error, never a panic; an accepted netlist has one device
/// per `M`/`Q`/`R`/`C`/`D` card and one instance per `X` card, counted from
/// the text by [`spice_cards`]; and [`flatten_checked`].
pub fn netlist_spice(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut strings = StrTable::default();
    let devices = DeviceRecognition::default();
    if let Ok(netlist) = gpurify_ingest::netlist::spice::read(text, &mut strings, &devices) {
        let (cards, calls) = spice_cards(text);
        assert_eq!(netlist.device_model.len(), cards, "device cards");
        assert_eq!(netlist.instance_of.len(), calls, "X cards");
        flatten_checked(&netlist, &mut strings);
    }
}

/// Spectre statements counted without the reader: every statement but
/// `subckt`, `ends`, `endsubckt` and `model` is a device or an instance. A
/// statement starts a line once `//` comments and `*` comment lines are
/// dropped, unless the line before ended in `\`.
fn spectre_statements(text: &str) -> usize {
    let (mut statements, mut cards, mut folded) = (0, 0, false);
    for raw in text.lines() {
        let lead = raw.trim_start();
        let line = if lead.starts_with('*') || lead.starts_with("//") {
            ""
        } else {
            raw.split("//").next().unwrap_or("")
        };
        let trimmed = line.trim_end();
        let (line, folds) = match trimmed.strip_suffix('\\') {
            Some(head) => (head, true),
            None => (trimmed, false),
        };
        let continues = folded;
        folded = folds;
        let head = line
            .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
            .find(|t| !t.is_empty());
        let Some(head) = head else {
            continue;
        };
        if continues && cards > 0 {
            continue;
        }
        cards += 1;
        if !matches!(head, "subckt" | "ends" | "endsubckt" | "model") {
            statements += 1;
        }
    }
    statements
}

/// `netlist::spectre::read` on arbitrary text, then the flattening below the
/// top LVS does.
///
/// Oracle: a typed error, never a panic; an accepted netlist's devices and
/// instances together number its statements, counted from the text by
/// [`spectre_statements`]; and [`flatten_checked`].
pub fn netlist_spectre(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut strings = StrTable::default();
    let devices = DeviceRecognition::default();
    if let Ok(netlist) = gpurify_ingest::netlist::spectre::read(text, &mut strings, &devices) {
        assert_eq!(
            netlist.device_model.len() + netlist.instance_of.len(),
            spectre_statements(text),
            "device and instance statements"
        );
        flatten_checked(&netlist, &mut strings);
    }
}

// ------------------------------------------------------- intent, Liberty ---

/// `intent::parse_intent` on arbitrary text. Oracle: a typed error, never a
/// panic.
pub fn intent(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = gpurify_ingest::intent::parse_intent(text, &mut StrTable::default());
    }
}

/// `liberty::spec::parse` on arbitrary text. Oracle: a typed error, never a
/// panic.
pub fn liberty_spec(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = gpurify::liberty::spec::parse(text);
    }
}

// --------------------------------------------------------------- drc_e2e ---

/// The farthest a bitmap case is moved: its cells span at most 500 nm, so
/// every vertex stays inside a 32-bit GDSII coordinate.
const REACH: i64 = i32::MAX as i64 - 1000;

/// One case of the bitmap reference DRC (X3, `tests/exhaustive/bitmap.rs`)
/// under any of the eight symmetries and any translation in the GDSII range,
/// through the real reader and engine.
///
/// Oracle: the bitmap reference, written from each rule's rustdoc; a case
/// marked with an open finding is skipped.
pub fn drc_e2e(data: &[u8]) {
    let mut b = Bytes(data);
    let Some(fixture) = crate::bitmap::case(b.u32()) else {
        return;
    };
    if fixture.known.is_some() {
        return;
    }
    let symmetry = crate::harness::Symmetry::ALL[usize::from(b.u8() % 8)];
    let mut offset = || {
        let raw = i32::from_be_bytes([b.u8(), b.u8(), b.u8(), b.u8()]);
        i64::from(raw).clamp(-REACH, REACH)
    };
    let (dx, dy) = (offset(), offset());
    let fixture = fixture.transformed(symmetry, dx, dy);
    let broken = crate::harness::violations_of(&fixture, &crate::harness::run(&fixture));
    assert!(broken.is_empty(), "{}: {}", fixture.name, broken.join("; "));
}
