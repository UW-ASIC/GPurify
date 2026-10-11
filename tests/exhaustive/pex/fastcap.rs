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
//! **The dielectric.** Every row of these stacks states one permittivity, so
//! the field is homogeneous and `GPurify`'s dielectric model (no dielectric
//! images, each panel pair at the mean of its two permittivities, PEX-003)
//! is exact here. `FastCap` solves in vacuum and the matrix is scaled by
//! `εr`: its `-p` factor scales by `εr²` in this build.
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
        let (u, v) = ((axis + 1) % 3, (axis + 2) % 3);
        let (us, vs) = (cuts(c.lo[u], c.hi[u]), cuts(c.lo[v], c.hi[v]));
        for at in [c.lo[axis], c.hi[axis]] {
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
    let grounded = conductors
        .iter()
        .map(|a| {
            let row = &rows[index(&a.name)].1;
            conductors
                .iter()
                .map(|b| row[index(&b.name)] - row[index(&format!("{}img", b.name))])
                .collect()
        })
        .collect();
    let _ = std::fs::remove_dir_all(&dir);
    grounded
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
