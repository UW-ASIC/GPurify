//! The field-solved capacitance matrix against `FastCap` 2.0 (testing-plan
//! §4 L6, ledger F3), on X6's field-solved geometries: the cube, the plate
//! over the substrate, the bars, the coupled pairs and the three- and
//! four-conductor sets.
//!
//! **What `FastCap` is given.** Each conductor's box (a drawn rectangle
//! extruded through its layer's `pex` row), every face cut into panels
//! graded toward its edges ([`cuts`]), where a conductor's charge piles up,
//! so its answer is close to converged. `FasterCap`, the plan's first choice,
//! is not packaged in nixpkgs.
//!
//! **The substrate** is `GPurify`'s grounded plane at height 0. `FastCap` has
//! no ground plane, so each conductor gets an image conductor, its mirror in
//! the plane, and the grounded matrix is read off the full one exactly: with
//! every image at minus its conductor's potential, `C[i][j] − C[i][j']`
//! where `j'` is `j`'s image. That is the method of images `GPurify` itself
//! uses, so no plane of finite size is approximated.
//!
//! **The dielectric.** Every row of X6's stacks states one permittivity, so
//! the field is homogeneous: `FastCap` solves in vacuum and the matrix is
//! scaled by `εr` (its `-p` factor scales by `εr²` in this build).
//! [`fastcap_differential_stratified_dielectrics`] gives `FastCap` a
//! stratified stack instead (PEX-003) through a list file: each conductor's
//! faces grouped by the permittivity outside them, and each interface between
//! two dielectrics, with its mirror in the substrate, a dielectric surface
//! over the window `GPurify` meshes it on.
//!
//! **Tolerances**, against `FastCap`'s near-converged answer, so they are
//! `GPurify`'s documented discretisation error (`gpurify_extract`,
//! "Accuracy and known gaps": a coarse mesh reads low) with `FastCap`'s
//! own, [`FASTCAP_OWN`], beside it:
//!
//! - [`FASTCAP_OWN`], 0.3 %: this module's mesh reads the cube that much
//!   under its known capacitance at most
//!   ([`fastcap_differential_reference_is_converged_on_the_cube`]);
//! - [`CUBE_FINE`], 0.5 %: the cube at 32 panels a side, which the crate
//!   docs put 0.014 % under the limit;
//! - [`DEFAULT_MESH`], 2.5 %: every entry, total and coupling, at the
//!   default mesh, whose panel edge is the stack's finest length (500 nm
//!   here). The docs put the cube at 2 panels a side 1.8 % low and small
//!   wires 0.2–1 % low; a coupling is resolved by the same panels. And
//!   since a coarse mesh reads low, no total may read above `FastCap`'s by
//!   more than [`FASTCAP_OWN`].
//!
//! `FastCap` prints four significant digits, 5e-4 of each entry, inside all
//! of these.

use super::{
    deck, four_conductors, net, parallel, relative, run, three_conductors, Metal, Row, Stack,
    COARSE,
};
use crate::harness::{Layout, NONE};
use gpurify::extract::field::mesh::MeshOptions;
use gpurify::extract::field::CapMatrix;
use gpurify::extract::ParasiticNetwork;
use gpurify::geom::Dbu;
use gpurify_testgen::oracle;
use std::f64::consts::PI;
use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

/// How far under the converged capacitance `FastCap` reads with this mesh.
const FASTCAP_OWN: f64 = 3e-3;
/// The cube at 32 panels a side against `FastCap`.
const CUBE_FINE: f64 = 5e-3;
/// Any entry at the default mesh against `FastCap`.
const DEFAULT_MESH: f64 = 2.5e-2;

/// `FastCap`'s largest interior panel edge, µm: a tenth of the finest length
/// of these stacks (500 nm) at the centre of a face, finer toward its edges.
const PANEL_UM: f64 = 0.25;

/// One conductor as `FastCap` reads it: a named box, corners in µm.
struct Conductor {
    name: String,
    lo: [f64; 3],
    hi: [f64; 3],
}

/// The boxes of `layout` on `stack`: each `m1` or `m2` rectangle extruded
/// through its row, named by the label inside it.
fn conductors(stack: Stack, layout: &Layout) -> Vec<Conductor> {
    layout
        .shapes
        .iter()
        .map(|(layer, points)| {
            let row: Row = match layer.as_str() {
                "m1" => Metal::M1.row(stack),
                "m2" => Metal::M2.row(stack),
                other => panic!("{other}: not a conductor here"),
            };
            assert_eq!(points.len(), 4, "a rectangle");
            let um = |v: i64| v as f64 / 1e3;
            let (x0, y0) = points[0];
            let (x1, y1) = points[2];
            let name = layout
                .labels
                .iter()
                .find(|(l, x, y, _)| {
                    *l == format!("{layer}_label") && (x0..=x1).contains(x) && (y0..=y1).contains(y)
                })
                .map_or_else(
                    || panic!("no label on the {layer} rectangle at ({x0}, {y0})"),
                    |(.., text)| text.clone(),
                );
            Conductor {
                name,
                lo: [um(x0), um(y0), row.height / 1e3],
                hi: [um(x1), um(y1), (row.height + row.thickness) / 1e3],
            }
        })
        .collect()
}

/// `lo..hi` cut at Chebyshev–Lobatto points: panels about
/// [`PANEL_UM`] in the middle, quadratically finer toward both ends, where a
/// conductor's surface charge is singular. At least four.
fn cuts(lo: f64, hi: f64) -> Vec<f64> {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a few hundred cuts"
    )]
    let n = ((PI * (hi - lo) / (2.0 * PANEL_UM)).ceil() as usize).max(4);
    (0..=n)
        .map(|k| lo + (hi - lo) * (1.0 - (PI * k as f64 / n as f64).cos()) / 2.0)
        .collect()
}

/// Appends `c`'s six faces as quadrilateral panels named `name`, with every
/// `z` multiplied by `mirror` (`-1` for the image in the substrate).
fn panels(out: &mut String, c: &Conductor, name: &str, mirror: f64) {
    for axis in 0..3 {
        for at in [c.lo[axis], c.hi[axis]] {
            face(out, c.lo, c.hi, axis, at, name, mirror);
        }
    }
}

/// Appends the face of the box `lo..hi` normal to `axis` at `at`, cut at
/// [`cuts`] on both of its axes, as panels named `name`, every `z` times
/// `mirror`.
fn face(
    out: &mut String,
    lo: [f64; 3],
    hi: [f64; 3],
    axis: usize,
    at: f64,
    name: &str,
    mirror: f64,
) {
    let (u, v) = ((axis + 1) % 3, (axis + 2) % 3);
    let (us, vs) = (cuts(lo[u], hi[u]), cuts(lo[v], hi[v]));
    for i in 0..us.len() - 1 {
        for j in 0..vs.len() - 1 {
            let _ = write!(out, "Q {name}");
            for (a, b) in [(i, j), (i + 1, j), (i + 1, j + 1), (i, j + 1)] {
                let mut p = [0.0; 3];
                p[axis] = at;
                p[u] = us[a];
                p[v] = vs[b];
                let _ = write!(out, " {} {} {}", p[0], p[1], p[2] * mirror);
            }
            out.push('\n');
        }
    }
}

/// `FastCap`'s grounded Maxwell matrix of `conductors` in a dielectric of
/// `k`, in fF, rows in `conductors` order.
fn fastcap(fastcap: &Path, conductors: &[Conductor], k: f64) -> Vec<Vec<f64>> {
    let mut input = String::from("0 GPurify F3 differential\n");
    for c in conductors {
        panels(&mut input, c, &c.name, 1.0);
        panels(&mut input, c, &format!("{}img", c.name), -1.0);
    }
    let dir = oracle::scratch("fastcap");
    std::fs::write(dir.join("in.qui"), input).expect("the scratch directory is writable");
    let out = oracle::run(
        fastcap,
        &["-o4", "-t0.0001", "in.qui"],
        &dir,
        Duration::from_mins(10),
    );
    let _ = std::fs::remove_dir_all(&dir);
    grounded_matrix(&out, conductors, k)
}

/// The grounded Maxwell matrix of `conductors` from `FastCap`'s output `out`,
/// each conductor with its image `<name>img`, in fF: `C[i][j] − C[i][j']`.
/// `k` multiplies every entry (a uniform dielectric `FastCap` solved in
/// vacuum); 1 when the list file states every permittivity.
fn grounded_matrix(out: &str, conductors: &[Conductor], k: f64) -> Vec<Vec<f64>> {
    let unit = out
        .lines()
        .find_map(|l| l.strip_prefix("CAPACITANCE MATRIX, "))
        .unwrap_or_else(|| panic!("no matrix in FastCap's output:\n{out}"));
    let farads = match unit.trim() {
        "farads" => 1.0,
        "millifarads" => 1e-3,
        "microfarads" => 1e-6,
        "nanofarads" => 1e-9,
        "picofarads" => 1e-12,
        "femtofarads" => 1e-15,
        "attofarads" => 1e-18,
        other => panic!("FastCap unit {other:?}"),
    };
    // Coordinates in µm read as metres: C scales with length, so 1e-6 of it.
    let to_ff = farads * 1e-6 * 1e15 * k;
    let mut rows: Vec<(String, Vec<f64>)> = Vec::new();
    for line in out.lines() {
        let mut words = line.split_whitespace();
        let Some(label) = words.next().and_then(|w| w.strip_suffix("%GROUP1")) else {
            continue;
        };
        let values = words
            .skip(1)
            .map(|w| w.parse::<f64>().expect("a number") * to_ff);
        match rows.iter_mut().find(|(name, _)| name == label) {
            Some((_, row)) => row.extend(values),
            None => rows.push((label.to_owned(), values.collect())),
        }
    }
    let index = |name: &str| {
        rows.iter()
            .position(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("no row {name} in FastCap's output:\n{out}"))
    };
    conductors
        .iter()
        .map(|a| {
            let row = &rows[index(&a.name)].1;
            conductors
                .iter()
                .map(|b| row[index(&b.name)] - row[index(&format!("{}img", b.name))])
                .collect()
        })
        .collect()
}

/// `GPurify`'s Maxwell matrix of the labelled nets of `layout` on `stack`, in
/// fF, rows in `labels` order: at the default mesh, or at `edge` nm panels.
fn gpurify(stack: Stack, layout: Layout, labels: &[&str], edge: Option<i64>) -> Vec<Vec<f64>> {
    let ran = run(&deck(stack, &[], ""), layout, NONE, &[]);
    let nets: Vec<_> = labels.iter().map(|label| net(&ran, label)).collect();
    let mut matrix = CapMatrix::default();
    let (store, all, connectivity, deck_stack, grid) = (
        &ran.loaded.store,
        &ran.extracted.nets,
        &ran.loaded.deck.connectivity,
        &ran.loaded.deck.stack,
        ran.loaded.grid,
    );
    match edge {
        None => gpurify::extract::quasistatic::extract_into(
            store,
            all,
            connectivity,
            &nets,
            deck_stack,
            grid,
            &mut matrix,
            &mut ParasiticNetwork::default(),
        ),
        Some(edge) => gpurify::extract::field::extract_meshed_into(
            store,
            all,
            connectivity,
            &nets,
            deck_stack,
            grid,
            MeshOptions {
                max_edge: Dbu::new_unchecked(edge),
                proximity_refine: Dbu::new_unchecked(0),
                max_panels: 1 << 20,
            },
            &mut matrix,
        ),
    }
    .expect("the field solve converges");
    let n = nets.len();
    let row_of = |net| {
        matrix
            .net
            .iter()
            .position(|&m| m == net)
            .expect("a selected net")
    };
    nets.iter()
        .map(|&i| {
            nets.iter()
                .map(|&j| matrix.value[row_of(i) * n + row_of(j)] * 1e15)
                .collect()
        })
        .collect()
}

/// One geometry: its stack, layout and nets, and the tolerance of every
/// entry for the mesh `GPurify` solves it at.
struct Geometry {
    name: String,
    stack: Stack,
    layout: Layout,
    labels: Vec<&'static str>,
    edge: Option<i64>,
    tolerance: f64,
}

/// X6's field-solved geometries.
fn geometries() -> Vec<Geometry> {
    let at = |name: String, stack: Stack, layout: Layout, labels: &[&'static str]| Geometry {
        name,
        stack,
        layout,
        labels: labels.to_vec(),
        edge: None,
        tolerance: DEFAULT_MESH,
    };
    let mut out = Vec::new();
    // The C6 cube: 1 um, in vacuum, its centre 50 um over the substrate.
    let vacuum = |row: Row| Row { k: 1.0, ..row };
    let cube = Stack {
        m1: Row {
            thickness: 1_000.0,
            height: 49_500.0,
            ..vacuum(COARSE.m1)
        },
        v1: vacuum(COARSE.v1),
        m2: vacuum(COARSE.m2),
    };
    let block = Layout::default()
        .rect("m1", 0, 0, 1_000, 1_000)
        .label("m1_label", 500, 500, "A");
    out.push(at("cube/default_mesh".into(), cube, block.clone(), &["A"]));
    out.push(Geometry {
        edge: Some(32),
        tolerance: CUBE_FINE,
        ..at("cube/32_a_side".into(), cube, block, &["A"])
    });
    // The 8 um plate at 250, 500 and 1000 nm.
    for h in [250.0, 500.0, 1_000.0] {
        let stack = Stack {
            m1: Row {
                height: h,
                ..COARSE.m1
            },
            ..COARSE
        };
        let plate = Layout::default()
            .rect("m1", 0, 0, 8_000, 8_000)
            .label("m1_label", 500, 500, "A");
        out.push(at(format!("plate/h{h}"), stack, plate, &["A"]));
    }
    // The field bars, both metals, at the nightly sizes.
    for metal in [Metal::M1, Metal::M2] {
        for (l, w) in [
            (10_000, 500),
            (20_000, 1_000),
            (40_000, 2_000),
            (40_000, 500),
        ] {
            let bar = Layout::default().rect(metal.name(), 0, 0, l, w).label(
                metal.label(),
                w / 2,
                w / 2,
                "A",
            );
            out.push(at(
                format!("bar/{}/{l}x{w}", metal.name()),
                COARSE,
                bar,
                &["A"],
            ));
        }
    }
    // Coupled pairs: side by side on m1, and m1 under m2.
    for gap in [250, 500, 1_000, 2_000, 4_000] {
        let pair = parallel(Metal::M1, 6_000, 1_000, gap, 0);
        out.push(at(format!("pair/gap{gap}"), COARSE, pair, &["A", "B"]));
    }
    for overlap in [1_000, 2_000, 4_000, 8_000] {
        let pair = Layout::default()
            .rect("m1", 0, 0, 8_000, 1_000)
            .rect("m2", 8_000 - overlap, 0, 16_000 - overlap, 1_000)
            .label("m1_label", 100, 500, "A")
            .label("m2_label", 15_900 - overlap, 500, "B");
        out.push(at(format!("overlap/{overlap}"), COARSE, pair, &["A", "B"]));
    }
    out.push(at(
        "three_conductors".into(),
        COARSE,
        three_conductors(),
        &["A", "B", "C"],
    ));
    out.push(at(
        "four_conductors".into(),
        COARSE,
        four_conductors(),
        &["A", "B", "C", "D"],
    ));
    out
}

/// Every entry of every geometry's matrix within its tolerance of
/// `FastCap`'s.
///
/// Oracle: differential against `FastCap`, an independent field solver, entry by
/// entry within each geometry's tolerance.
#[test]
#[ignore = "release tier: needs fastcap (nix develop .#oracles)"]
fn fastcap_differential_every_field_solved_geometry() {
    let tool = oracle::tool("fastcap");
    let mut broken = Vec::new();
    let mut compared = 0;
    for g in geometries() {
        let k = g.stack.m1.k;
        assert!(
            [g.stack.v1.k, g.stack.m2.k]
                .iter()
                .all(|&other| other.to_bits() == k.to_bits()),
            "{}: a homogeneous stack",
            g.name
        );
        let reference = fastcap(&tool, &conductors(g.stack, &g.layout), k);
        let ours = gpurify(g.stack, g.layout, &g.labels, g.edge);
        for (i, (row, want)) in ours.iter().zip(&reference).enumerate() {
            for (j, (&got, &want)) in row.iter().zip(want).enumerate() {
                let off = relative(got, want);
                println!(
                    "{}: C[{i}][{j}] {got:.6} fF, FastCap {want:.6} fF, {:+.2} %",
                    g.name,
                    (got - want) / want * 100.0
                );
                compared += 1;
                // A coarse mesh reads low, so a total above FastCap's by
                // more than FastCap's own shortfall is wrong at any size.
                let high = i == j && g.edge.is_none() && got > want * (1.0 + FASTCAP_OWN);
                if off > g.tolerance || high {
                    broken.push(format!(
                        "{}: C[{i}][{j}] = {got} fF, FastCap {want} fF ({:.2} %, \
                         tolerance {} %{})",
                        g.name,
                        off * 100.0,
                        g.tolerance * 100.0,
                        if high {
                            ", and a coarse mesh must read low"
                        } else {
                            ""
                        }
                    ));
                }
            }
        }
    }
    assert!(compared > 40, "only {compared} entries compared");
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

/// `FastCap` with this module's mesh and images, on the cube alone, is
/// within 0.3 % of the cube's known capacitance: the reference is converged
/// well inside the tolerances it is used with.
///
/// Oracle: published value: the cube's capacitance, 0.66068 · 4πε₀a with its
/// image in the plane, which `FastCap` must reach within 0.3 %.
#[test]
#[ignore = "release tier: needs fastcap (nix develop .#oracles)"]
fn fastcap_differential_reference_is_converged_on_the_cube() {
    let tool = oracle::tool("fastcap");
    let (side, centre) = (1.0, 50.0);
    let cube = Conductor {
        name: "A".into(),
        lo: [0.0, 0.0, centre - side / 2.0],
        hi: [side, side, centre + side / 2.0],
    };
    let c = fastcap(&tool, &[cube], 1.0)[0][0];
    // As `a_field_solved_capacitance_converges_as_the_mesh_is_refined`.
    let four_pi_eps0 = 4.0 * PI * super::EPSILON0_AF_PER_UM / 1e3;
    let free = 0.660_68 * four_pi_eps0 * side;
    let limit = free / (1.0 - free / (2.0 * four_pi_eps0 * centre));
    assert!(
        relative(c, limit) <= FASTCAP_OWN,
        "FastCap {c} fF, the cube's {limit} fF"
    );
}

/// A stratified stack against `FastCap`, every entry: the plate, the coupled
/// pair and a crossing, `GPurify` at its default mesh, `FastCap` at this
/// module's. Both mesh the same interfaces over the same windows (the
/// footprint grown by [`WINDOW`] times the interface's or the highest
/// conductor's height, metal cut out), so the window is no part of the
/// difference; what is, is `GPurify`'s coarser panels on the interfaces and
/// its centroid collocation there, against `FastCap`'s graded ones.
const STRATIFIED: f64 = 5e-2;

/// `GPurify`'s interface window, in multiples of a height (`gpurify_extract`
/// crate docs, "Dielectric interfaces are windowed").
const WINDOW: f64 = 8.0;

/// The stack's dielectric as `GPurify` reads it: each row's from its height
/// (µm) up to the next row's, the lowest reaching down; bands ascending,
/// the first from minus infinity, neighbours different.
fn bands(stack: Stack) -> Vec<(f64, f64)> {
    let mut rows: Vec<(f64, f64)> = [stack.m1, stack.v1, stack.m2]
        .iter()
        .map(|row| (row.height / 1e3, row.k))
        .collect();
    rows.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut out: Vec<(f64, f64)> = Vec::new();
    for (height, k) in rows {
        match out.last() {
            None => out.push((f64::NEG_INFINITY, k)),
            Some(&(_, last)) if last.to_bits() == k.to_bits() => {}
            Some(_) => out.push((height, k)),
        }
    }
    out
}

/// The permittivity just above (`above`) or below height `z` (µm).
fn permittivity(bands: &[(f64, f64)], z: f64, above: bool) -> f64 {
    let band = bands
        .iter()
        .rposition(|&(from, _)| {
            if above {
                from <= z + 1e-9
            } else {
                from < z - 1e-9
            }
        })
        .unwrap_or(0);
    bands[band].1
}

/// Grid lines through every edge, [`cuts`] between neighbouring edges and
/// growing by half again out to `lo` and `hi`.
fn window_lines(mut edges: Vec<f64>, lo: f64, hi: f64) -> Vec<f64> {
    edges.sort_by(f64::total_cmp);
    edges.dedup_by(|a, b| (*a - *b).abs() < 1e-9);
    let mut out = vec![lo];
    let (first, last) = (edges[0], edges[edges.len() - 1]);
    let mut outside = Vec::new();
    let (mut at, mut gap) = (first, PANEL_UM);
    while at - gap > lo + 1e-9 {
        at -= gap;
        outside.push(at);
        gap *= 1.5;
    }
    outside.reverse();
    out.extend(outside);
    for pair in edges.windows(2) {
        let lines = cuts(pair[0], pair[1]);
        out.extend(&lines[..lines.len() - 1]);
    }
    out.push(last);
    let (mut at, mut gap) = (last, PANEL_UM);
    while at + gap < hi - 1e-9 {
        at += gap;
        out.push(at);
        gap *= 1.5;
    }
    out.push(hi);
    out
}

/// `FastCap`'s grounded Maxwell matrix of `conductors` in the stratified
/// `stack`, in fF, through a list file: each conductor's faces (and its
/// image's) in one file per permittivity outside them, all linked into one
/// group; each interface (and its mirror in the substrate, between the same
/// permittivities upside down) a dielectric surface over [`WINDOW`], metal
/// cut out.
fn fastcap_stratified(tool: &Path, stack: Stack, conductors: &[Conductor]) -> Vec<Vec<f64>> {
    let bands = bands(stack);
    let interfaces: Vec<(f64, f64, f64)> = bands
        .windows(2)
        .map(|pair| (pair[1].0, pair[0].1, pair[1].1))
        .collect();
    let mut files: Vec<(String, f64)> = Vec::new();
    for c in conductors {
        for (name, mirror) in [(c.name.clone(), 1.0), (format!("{}img", c.name), -1.0)] {
            // One file per permittivity outside the faces it holds.
            let mut by_k: Vec<(f64, String)> = Vec::new();
            let mut put = |k: f64, text: String| match by_k
                .iter_mut()
                .find(|(have, _)| have.to_bits() == k.to_bits())
            {
                Some((_, body)) => body.push_str(&text),
                None => by_k.push((k, text)),
            };
            let mut text = String::new();
            face(&mut text, c.lo, c.hi, 2, c.lo[2], &name, mirror);
            put(
                permittivity(&bands, c.lo[2], false),
                std::mem::take(&mut text),
            );
            face(&mut text, c.lo, c.hi, 2, c.hi[2], &name, mirror);
            put(
                permittivity(&bands, c.hi[2], true),
                std::mem::take(&mut text),
            );
            let mut slabs: Vec<f64> = interfaces
                .iter()
                .map(|i| i.0)
                .filter(|&z| z > c.lo[2] + 1e-9 && z < c.hi[2] - 1e-9)
                .collect();
            slabs.insert(0, c.lo[2]);
            slabs.push(c.hi[2]);
            for slab in slabs.windows(2) {
                let (mut lo, mut hi) = (c.lo, c.hi);
                lo[2] = slab[0];
                hi[2] = slab[1];
                for axis in 0..2 {
                    for at in [c.lo[axis], c.hi[axis]] {
                        face(&mut text, lo, hi, axis, at, &name, mirror);
                    }
                }
                put(
                    permittivity(&bands, slab[0], true),
                    std::mem::take(&mut text),
                );
            }
            for (k, body) in by_k {
                files.push((format!("0 {name} at {k}\n{body}"), k));
            }
        }
    }
    let dir = oracle::scratch("fastcap");
    let mut list = String::from("* GPurify PEX-003 differential\n");
    for (index, (body, k)) in files.iter().enumerate() {
        let file = format!("c{index}.qui");
        std::fs::write(dir.join(&file), body).expect("the scratch directory is writable");
        let link = if index + 1 < files.len() { " +" } else { "" };
        let _ = writeln!(list, "C {file} {k} 0 0 0{link}");
    }
    let top = conductors.iter().map(|c| c.hi[2]).fold(0.0_f64, f64::max);
    let reach = |axis: usize| {
        (
            conductors
                .iter()
                .map(|c| c.lo[axis])
                .fold(f64::INFINITY, f64::min),
            conductors
                .iter()
                .map(|c| c.hi[axis])
                .fold(f64::NEG_INFINITY, f64::max),
        )
    };
    for (index, &(z, below, above)) in interfaces.iter().enumerate() {
        let margin = WINDOW * z.max(top);
        let ((xlo, xhi), (ylo, yhi)) = (reach(0), reach(1));
        let edges = |axis: usize| {
            conductors
                .iter()
                .flat_map(|c| [c.lo[axis], c.hi[axis]])
                .collect::<Vec<f64>>()
        };
        let xs = window_lines(edges(0), xlo - margin, xhi + margin);
        let ys = window_lines(edges(1), ylo - margin, yhi + margin);
        for (mirror, outer, inner) in [(1.0, above, below), (-1.0, below, above)] {
            let mut body = format!("0 interface {index} {mirror}\n");
            for x in xs.windows(2) {
                for y in ys.windows(2) {
                    let (cx, cy) = ((x[0] + x[1]) / 2.0, (y[0] + y[1]) / 2.0);
                    let metal = conductors.iter().any(|c| {
                        c.lo[2] <= z + 1e-9
                            && c.hi[2] >= z - 1e-9
                            && c.lo[0] < cx
                            && cx < c.hi[0]
                            && c.lo[1] < cy
                            && cy < c.hi[1]
                    });
                    if metal {
                        continue;
                    }
                    let _ = writeln!(
                        body,
                        "Q d {} {} {z3} {} {} {z3} {} {} {z3} {} {} {z3}",
                        x[0],
                        y[0],
                        x[1],
                        y[0],
                        x[1],
                        y[1],
                        x[0],
                        y[1],
                        z3 = z * mirror
                    );
                }
            }
            let file = format!("d{index}_{}.qui", if mirror > 0.0 { "up" } else { "image" });
            std::fs::write(dir.join(&file), body).expect("the scratch directory is writable");
            // The reference point lies on the outer side: above the plane,
            // between the image plane and the substrate for the image.
            let reference = if mirror > 0.0 { z + 0.5 } else { -z / 2.0 };
            let _ = writeln!(
                list,
                "D {file} {outer} {inner} 0 0 0 {} {} {reference}",
                (xlo + xhi) / 2.0,
                (ylo + yhi) / 2.0
            );
        }
    }
    std::fs::write(dir.join("in.lst"), list).expect("the scratch directory is writable");
    let out = oracle::run(
        tool,
        &["-o4", "-t0.0001", "-lin.lst"],
        &dir,
        Duration::from_mins(20),
    );
    let _ = std::fs::remove_dir_all(&dir);
    grounded_matrix(&out, conductors, 1.0)
}

/// PEX-003: every entry of three stratified geometries within
/// [`STRATIFIED`] of `FastCap`'s multi-dielectric solve: an 8 um `m1`
/// plate and two coupled `m1` bars, the stack 7 up to `m1`'s top and 3.9
/// over it, and an `m1` bar under a crossing `m2` bar, 7 up to `m1`'s top,
/// 3.9 to `m2`'s bottom and 5 over it (two interfaces).
#[test]
#[ignore = "release tier: needs fastcap (nix develop .#oracles)"]
fn fastcap_differential_stratified_dielectrics() {
    let tool = oracle::tool("fastcap");
    let with = |m1: f64, v1: f64, m2: f64| Stack {
        m1: Row { k: m1, ..COARSE.m1 },
        v1: Row { k: v1, ..COARSE.v1 },
        m2: Row { k: m2, ..COARSE.m2 },
    };
    let cases: Vec<(&str, Stack, Layout, Vec<&str>)> = vec![
        (
            "plate",
            with(7.0, 3.9, 3.9),
            Layout::default()
                .rect("m1", 0, 0, 8_000, 8_000)
                .label("m1_label", 500, 500, "A"),
            vec!["A"],
        ),
        (
            "pair",
            with(7.0, 3.9, 3.9),
            parallel(Metal::M1, 3_000, 500, 500, 0),
            vec!["A", "B"],
        ),
        (
            "crossing",
            with(7.0, 3.9, 5.0),
            Layout::default()
                .rect("m1", 0, 0, 4_000, 500)
                .rect("m2", 1_750, -1_500, 2_250, 2_000)
                .label("m1_label", 250, 250, "A")
                .label("m2_label", 2_000, 1_900, "B"),
            vec!["A", "B"],
        ),
    ];
    let mut broken = Vec::new();
    let mut compared = 0;
    for (name, stack, layout, labels) in cases {
        let reference = fastcap_stratified(&tool, stack, &conductors(stack, &layout));
        let ours = gpurify(stack, layout, &labels, None);
        for (i, (row, want)) in ours.iter().zip(&reference).enumerate() {
            for (j, (&got, &want)) in row.iter().zip(want).enumerate() {
                compared += 1;
                println!(
                    "{name}: C[{i}][{j}] {got:.6} fF, FastCap {want:.6} fF, {:+.2} %",
                    (got - want) / want * 100.0
                );
                if relative(got, want) > STRATIFIED {
                    broken.push(format!(
                        "{name}: C[{i}][{j}] = {got} fF, FastCap {want} fF ({:.2} %)",
                        relative(got, want) * 100.0
                    ));
                }
            }
        }
    }
    assert_eq!(compared, 9, "every entry compared");
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}
