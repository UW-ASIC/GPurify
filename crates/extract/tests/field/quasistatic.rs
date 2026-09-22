//! The field solve: the capacitance matrix and the mesh it is built from.
//!
//! Reciprocity makes the Maxwell matrix symmetric for *any* geometry, so that
//! law holds on generated corpora; a mesh's panels tile the conductor, so their
//! areas sum to a surface area computable on paper.

use crate::common;

use common::{extracted, grid, uniform_stack};
use gpurify_check::topology::NetId;
use gpurify_extract::field::mesh::{build_into, Mesh, MeshError, MeshOptions};
use gpurify_extract::field::CapMatrix;
use gpurify_ingest::deck::ProcessStack;
use gpurify_testgen::{assert_bytes_identical, assert_close, assert_close_relative, dbu, Rng};

/// A matrix from its rows, with one net per row.
fn matrix(rows: &[&[f64]]) -> CapMatrix {
    let n = rows.len();
    let mut value = Vec::with_capacity(n * n);
    for row in rows {
        assert_eq!(row.len(), n, "a capacitance matrix is square");
        value.extend_from_slice(row);
    }
    CapMatrix {
        net: (0..n)
            .map(|i| NetId(u32::try_from(i).expect("row counts here are small")))
            .collect(),
        value,
    }
}

/// A symmetric, strictly diagonally dominant matrix with non-positive
/// off-diagonals — the shape a physical Maxwell matrix has.
///
/// Built rather than solved for, so the laws below are asserted over arbitrary
/// numbers.
fn random_maxwell(rng: &mut Rng, n: usize) -> CapMatrix {
    let mut value = vec![0.0_f64; n * n];
    for i in 0..n {
        for j in (i + 1)..n {
            let coupling = -(0.05 + rng.unit());
            value[i * n + j] = coupling;
            value[j * n + i] = coupling;
        }
    }
    for i in 0..n {
        let off_diagonal: f64 = (0..n)
            .filter(|&j| j != i)
            .map(|j| value[i * n + j].abs())
            .sum();
        value[i * n + i] = off_diagonal + 0.25 + rng.unit();
    }
    CapMatrix {
        net: (0..n)
            .map(|i| NetId(u32::try_from(i).expect("row counts here are small")))
            .collect(),
        value,
    }
}

/// A mesh's panels as bytes, floats by their bit pattern. The determinism gate
/// for meshing, and written out here rather than reached for through `Debug`
/// for the same reason `common::serialise` is.
fn serialise_mesh(mesh: &Mesh) -> Vec<u8> {
    let mut out = Vec::with_capacity(mesh.panel.len() * 60);
    for panel in &mesh.panel {
        for value in &panel.centre {
            out.extend_from_slice(&value.to_bits().to_le_bytes());
        }
        out.extend_from_slice(&panel.area.to_bits().to_le_bytes());
        out.extend_from_slice(&panel.conductor.to_le_bytes());
    }
    for start in &mesh.conductor_start {
        out.extend_from_slice(&start.to_le_bytes());
    }
    for net in &mesh.conductor_net {
        out.extend_from_slice(&net.0.to_le_bytes());
    }
    for epsilon in &mesh.epsilon {
        out.extend_from_slice(&epsilon.to_bits().to_le_bytes());
    }
    out
}

/// Mesh options that mesh, with the proximity knob off.
///
/// Proximity refinement is set to zero throughout: it refines against a
/// distance the tests here are not controlling, and every law below is about
/// what `max_edge` alone does.
fn mesh_options(max_edge: i64, max_panels: u32) -> MeshOptions {
    MeshOptions {
        max_edge: dbu(max_edge),
        proximity_refine: dbu(0),
        max_panels,
    }
}

/// The process stack every mesh below is built against.
///
/// `build_into` gained it in the Testing-Phase: a [`GeometryStore`] is
/// two-dimensional, so the z extent a panel needs comes from `thickness_nm` and
/// `height_nm`, and `Mesh::epsilon` comes from `dielectric_k`. Uniform across
/// its three rows, so no law below can depend on which layer a conductor landed
/// on — the corpora place them freely.
///
/// [`GeometryStore`]: gpurify_geom::GeometryStore
fn stack() -> ProcessStack {
    uniform_stack(3, 1.0, 0.25)
}

/// Oracle: law. A conductor's surface area is a property of the conductor, not
/// of how finely it was cut up, so halving `max_edge` must leave every
/// conductor's area exactly where it was while producing at least as many
/// panels. This is the one meshing law that needs no unit convention at all —
/// it compares a mesh against another mesh of the same solid — and it is the
/// failure this module fears most: a mesh that loses area loses charge, and a
/// solve on it is wrong in a way no residual reveals.
#[test]
fn refining_a_mesh_subdivides_it_without_changing_any_conductors_area() {
    let case = extracted(151, 24, 2);

    let mut coarse = Mesh::default();
    build_into(
        case.store(),
        &case.nets,
        &case.selected,
        &stack(),
        mesh_options(500, 1 << 20),
        grid(),
        &mut coarse,
    )
    .expect("a two-conductor corpus meshes below a million panels");
    let mut fine = Mesh::default();
    build_into(
        case.store(),
        &case.nets,
        &case.selected,
        &stack(),
        mesh_options(250, 1 << 20),
        grid(),
        &mut fine,
    )
    .expect("halving the panel edge stays below a million panels");

    assert!(
        !coarse.panel.is_empty(),
        "a corpus of real geometry meshed into no panels"
    );
    assert!(
        fine.panel.len() >= coarse.panel.len(),
        "a finer edge limit produced {} panels against {} at twice the edge",
        fine.panel.len(),
        coarse.panel.len()
    );

    for conductor in 0..u32::try_from(case.selected.len()).expect("two conductors") {
        let area = conductor_area(&coarse, conductor);
        assert!(
            area > 0.0 && area.is_finite(),
            "conductor {conductor} has a surface area of {area}"
        );
        assert_close_relative(
            &format!("conductor {conductor} across a refinement"),
            conductor_area(&fine, conductor),
            area,
            1e-9,
        );
    }
}

/// Oracle: construct-from-answer. The doc comment states the CSR:
/// `panel[conductor_start[c] .. conductor_start[c + 1]]` belongs to conductor
/// `c`, one conductor per selected net in the order they were selected. So the
/// bands partition the panel column exactly, every panel's own `conductor`
/// field agrees with the band it lies in, and the parallel `epsilon` column is
/// the length of the panel column. A mesh whose CSR disagrees with its panels
/// gives `conductor_area` one answer and the matvec another.
#[test]
fn a_built_mesh_partitions_its_panels_across_the_nets_it_was_given() {
    let case = extracted(157, 24, 3);
    let mut mesh = Mesh::default();
    build_into(
        case.store(),
        &case.nets,
        &case.selected,
        &stack(),
        mesh_options(400, 1 << 20),
        grid(),
        &mut mesh,
    )
    .expect("a three-conductor corpus meshes below a million panels");

    assert_eq!(
        mesh.conductor_net, case.selected,
        "one conductor per selected net, in the order they were selected"
    );
    assert_eq!(
        mesh.conductor_start.len(),
        case.selected.len() + 1,
        "a CSR over {} conductors has {} boundaries",
        case.selected.len(),
        case.selected.len() + 1
    );
    assert_eq!(mesh.conductor_start[0], 0, "the first band starts at zero");
    assert_eq!(
        usize::try_from(*mesh.conductor_start.last().expect("a CSR is never empty"))
            .expect("a panel count is a usize"),
        mesh.panel.len(),
        "the last boundary is the end of the panel column"
    );
    assert_eq!(
        mesh.epsilon.len(),
        mesh.panel.len(),
        "epsilon travels with the mesh, one entry per panel"
    );

    for conductor in 0..case.selected.len() {
        let start = node(mesh.conductor_start[conductor]);
        let end = node(mesh.conductor_start[conductor + 1]);
        assert!(
            start < end,
            "conductor {conductor} owns panels {start}..{end}, which is none"
        );
        let owner = u32::try_from(conductor).expect("conductor counts here are small");
        let mut summed = 0.0;
        for index in start..end {
            let panel = mesh.panel[index];
            assert_eq!(
                panel.conductor, owner,
                "panel {index} sits in conductor {conductor}'s band but names {}",
                panel.conductor
            );
            assert!(
                panel.area > 0.0 && panel.area.is_finite(),
                "panel {index} has an area of {}",
                panel.area
            );
            summed += panel.area;
        }
        assert!(summed > 0.0, "conductor {conductor} has no surface");
    }
}

/// Oracle: law, and the fail-closed rule. `max_panels` is there so a solve that
/// would take a week says so rather than starting, so a corpus that cannot be
/// expressed in one panel must be refused by name — a conductor is a closed
/// surface and has at least six faces, so one panel is not a mesh of anything.
/// A refusal that came back as an empty clean mesh instead is the fail-open
/// mode this workspace treats as the defect.
#[test]
fn a_mesh_that_would_exceed_the_panel_limit_is_refused_rather_than_truncated() {
    let case = extracted(163, 24, 2);
    let mut mesh = Mesh::default();
    assert_eq!(
        build_into(
            case.store(),
            &case.nets,
            &case.selected,
            &stack(),
            mesh_options(400, 1),
            grid(),
            &mut mesh,
        ),
        Err(MeshError::TooManyPanels),
        "two conductors cannot be meshed into a single panel"
    );

    // The same geometry with room to work, so the refusal above is the limit
    // and not the corpus.
    let mut roomy = Mesh::default();
    build_into(
        case.store(),
        &case.nets,
        &case.selected,
        &stack(),
        mesh_options(400, 1 << 20),
        grid(),
        &mut roomy,
    )
    .expect("the same corpus meshes when the limit allows it");
    assert!(
        roomy.panel.len() > 1,
        "the corpus meshed into {} panels, so the limit of one refused nothing",
        roomy.panel.len()
    );
}

/// Oracle: determinism. Panels are sorted into spatial tree order by a key
/// derived only from position, so meshing is a function of the geometry alone.
/// Two builds must give the same bytes, and a build into a buffer that already
/// holds a mesh must give the same bytes as one into a fresh buffer — the
/// "caller owns `out`" half of the interface, which an append satisfies neither
/// of.
#[test]
fn meshing_is_byte_identical_across_runs_and_across_a_reused_buffer() {
    let case = extracted(167, 24, 2);
    let options = mesh_options(400, 1 << 20);

    let mut fresh = Mesh::default();
    build_into(
        case.store(),
        &case.nets,
        &case.selected,
        &stack(),
        options,
        grid(),
        &mut fresh,
    )
    .expect("the corpus meshes");
    let first = serialise_mesh(&fresh);
    assert!(!first.is_empty(), "an empty mesh serialises to no bytes");

    let mut again = Mesh::default();
    build_into(
        case.store(),
        &case.nets,
        &case.selected,
        &stack(),
        options,
        grid(),
        &mut again,
    )
    .expect("the corpus meshes");
    assert_bytes_identical(
        "two meshings of one corpus",
        &first,
        &serialise_mesh(&again),
    );

    build_into(
        case.store(),
        &case.nets,
        &case.selected,
        &stack(),
        options,
        grid(),
        &mut again,
    )
    .expect("the corpus meshes");
    assert_bytes_identical(
        "a meshing into a reused buffer",
        &first,
        &serialise_mesh(&again),
    );
}

/// Surface area of one conductor, summed from its band of panels.
fn conductor_area(mesh: &Mesh, conductor: u32) -> f64 {
    let c = conductor as usize;
    let (from, to) = (
        mesh.conductor_start[c] as usize,
        mesh.conductor_start[c + 1] as usize,
    );
    mesh.panel[from..to].iter().map(|p| p.area).sum()
}

/// A CSR boundary as a subscript, refusing anything that is not one.
fn node(index: u32) -> usize {
    usize::try_from(index).expect("a panel index is a u32 and usize is at least that wide")
}

/// Oracle: construct-from-answer. The matrix is stored row-major as the full
/// square, so `get(i, j)` is `value[i * n + j]` and `dim` is the side. Storing
/// a triangle would make the symmetry law below vacuous, which is why the
/// layout is worth pinning down first.
#[test]
fn a_capacitance_matrix_reads_back_row_major_at_the_dimension_it_reports() {
    let rows: [[f64; 3]; 3] = [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0], [7.0, 8.0, 9.0]];
    let m = matrix(&[&rows[0], &rows[1], &rows[2]]);
    assert_eq!(m.dim(), 3);
    for (i, row) in rows.iter().enumerate() {
        for (j, &expected) in row.iter().enumerate() {
            assert_close(
                &format!("entry ({i}, {j})"),
                m.value[i * m.dim() + j],
                expected,
                1e-12,
            );
        }
    }
    assert_eq!(CapMatrix::default().dim(), 0, "an empty matrix has no rows");
}

/// Oracle: closed form. Asymmetry is the largest relative difference between an
/// entry and its transpose. A symmetric matrix has none; a matrix whose `(0,1)`
/// entry is one and whose `(1,0)` entry is 1.1 is off by a tenth, relative to
/// the smaller of the two, which is a number computed here and not read off a
/// run.
#[test]
fn asymmetry_is_zero_on_a_symmetric_matrix_and_the_relative_gap_otherwise() {
    let symmetric = matrix(&[&[4.0, -1.0, -0.5], &[-1.0, 3.0, -2.0], &[-0.5, -2.0, 5.0]]);
    assert_close("a symmetric matrix", symmetric.asymmetry(), 0.0, 1e-15);

    let skewed = matrix(&[&[4.0, 1.0], &[1.1, 3.0]]);
    assert_close_relative(
        "one tenth out of reciprocity",
        skewed.asymmetry(),
        0.1,
        1e-9,
    );
}

/// Oracle: law. Reciprocity makes the Maxwell matrix symmetric for any geometry
/// whatsoever, so a symmetric matrix must report no asymmetry however it was
/// built. Stated over generated matrices rather than the one written out above,
/// because the useful failure is the one that only shows up off the diagonal of
/// a matrix nobody chose by hand.
#[test]
fn any_symmetric_matrix_reports_no_asymmetry() {
    let mut rng = Rng::new(61);
    for n in 1..=8 {
        let m = random_maxwell(&mut rng, n);
        assert_close(
            &format!("a generated {n} by {n} matrix"),
            m.asymmetry(),
            0.0,
            1e-15,
        );
    }
}
