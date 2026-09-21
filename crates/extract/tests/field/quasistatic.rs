//! The field solve: the capacitance matrix, the mesh it is built from, and the
//! adapter that does the multiplying.
//!
//! Electrostatics is where the oracles are strongest. Reciprocity makes the
//! Maxwell matrix symmetric for *any* geometry, so that law holds on the
//! generated corpus where no closed form exists; a positive-definite matrix
//! makes the electrostatic energy non-negative for every potential vector,
//! including generated ones; and a mesh's panels have to tile the conductor, so
//! their areas sum to a surface area anyone can compute on paper.
//!
//! The GPU is tested here too, and it is tested by running. `docs/GPU.md`
//! contract item 5: where no device exists the test asserts the fallback was
//! taken. Nearly every GPU test in the old tree was `#[ignore]`d, so nothing
//! proved the two paths agreed, and an ignored test is a test that does not
//! exist.

use crate::common;

use common::{extracted, grid, uniform_stack};
use gpurify_check::topology::NetId;
#[cfg(feature = "gpu")]
use gpurify_extract::field::gpu::Device;
#[cfg(feature = "gpu")]
use gpurify_extract::field::matvec::select;
use gpurify_extract::field::matvec::{Backend, CpuMatVec, MatVec};
use gpurify_extract::field::mesh::{
    build_into, conductor_area, Mesh, MeshError, MeshOptions, Panel,
};
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
/// numbers. Gershgorin puts every eigenvalue of such a matrix in the positive
/// half-line, so it is positive definite and its energy is positive for every
/// nonzero potential vector. That is the fact under the energy test, and it is
/// a fact about the matrix rather than about the code.
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

/// A cube of side `s` as six panels, one per face.
///
/// The oracle for `conductor_area`: a cube's surface area is `6 s²` and every
/// panel is exactly one face, so the panels tile it with nothing lost and
/// nothing counted twice.
fn cube(conductor: u32, side: f64) -> Vec<Panel> {
    let half = side / 2.0;
    let faces = [
        ([half, 0.0, 0.0], [1.0, 0.0, 0.0]),
        ([-half, 0.0, 0.0], [-1.0, 0.0, 0.0]),
        ([0.0, half, 0.0], [0.0, 1.0, 0.0]),
        ([0.0, -half, 0.0], [0.0, -1.0, 0.0]),
        ([0.0, 0.0, half], [0.0, 0.0, 1.0]),
        ([0.0, 0.0, -half], [0.0, 0.0, -1.0]),
    ];
    faces
        .into_iter()
        .map(|(centre, normal)| Panel {
            centre,
            normal,
            area: side * side,
            conductor,
        })
        .collect()
}

/// A mesh's panels as bytes, floats by their bit pattern. The determinism gate
/// for meshing, and written out here rather than reached for through `Debug`
/// for the same reason `common::serialise` is.
fn serialise_mesh(mesh: &Mesh) -> Vec<u8> {
    let mut out = Vec::with_capacity(mesh.panel.len() * 60);
    for panel in &mesh.panel {
        for value in panel.centre.iter().chain(&panel.normal) {
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
            let norm = panel
                .normal
                .iter()
                .map(|component| component * component)
                .sum::<f64>()
                .sqrt();
            assert_close(&format!("the normal of panel {index}"), norm, 1.0, 1e-12);
            summed += panel.area;
        }
        assert_close_relative(
            &format!("conductor {conductor} against its own band"),
            conductor_area(&mesh, owner),
            summed,
            1e-12,
        );
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
            assert_close(&format!("entry ({i}, {j})"), m.get(i, j), expected, 1e-12);
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

/// Oracle: closed form. Electrostatic energy is half `V` transpose `C` `V`. For
/// `C = [[2, -1], [-1, 2]]` and `V = [1, 0]` that is one; for `V = [1, 1]` the
/// two off-diagonal terms cancel one unit of each diagonal and it is one again.
/// Both are worked here on paper.
#[test]
fn electrostatic_energy_is_half_v_transpose_c_v() {
    let m = matrix(&[&[2.0, -1.0], &[-1.0, 2.0]]);
    assert_close(
        "a single charged conductor",
        m.energy(&[1.0, 0.0]),
        1.0,
        1e-12,
    );
    assert_close("both at one volt", m.energy(&[1.0, 1.0]), 1.0, 1e-12);
    assert_close("opposed", m.energy(&[1.0, -1.0]), 3.0, 1e-12);
    assert_close("no potential, no energy", m.energy(&[0.0, 0.0]), 0.0, 1e-15);
}

/// Oracle: law. Energy is a quadratic form, so scaling every potential by `k`
/// scales the energy by `k` squared. True for any matrix and any vector, and it
/// catches the two errors a hand-checked example does not: a missing half, and
/// a linear term that should not be there.
#[test]
fn energy_scales_with_the_square_of_the_potentials() {
    let mut rng = Rng::new(67);
    let m = random_maxwell(&mut rng, 6);
    let v: Vec<f64> = (0..6).map(|_| rng.unit() * 4.0 - 2.0).collect();
    let base = m.energy(&v);
    assert!(base > 0.0, "a positive definite matrix stores {base} J");

    for k in [0.5, 2.0, -3.0] {
        let scaled: Vec<f64> = v.iter().map(|value| value * k).collect();
        assert_close_relative(
            "energy under a scaled potential",
            m.energy(&scaled),
            k * k * base,
            1e-12,
        );
    }
}

/// Oracle: law. A physical capacitance matrix is diagonally dominant with
/// non-positive off-diagonals, and such a matrix is positive semi-definite, so
/// its energy is non-negative for *every* potential vector. Asserted over
/// generated matrices and generated potentials: a negative energy means the
/// result is not a capacitance matrix, whatever the residual said.
#[test]
fn energy_is_never_negative_for_any_potential_vector() {
    let mut rng = Rng::new(71);
    for n in 1..=7 {
        let m = random_maxwell(&mut rng, n);
        for round in 0..32 {
            let v: Vec<f64> = (0..n).map(|_| rng.unit() * 20.0 - 10.0).collect();
            let energy = m.energy(&v);
            assert!(
                energy >= 0.0,
                "round {round} of a {n} by {n} matrix stored {energy} J at {v:?}"
            );
        }
    }
}

/// Oracle: closed form. A cube of side two has a surface area of twenty-four,
/// and its mesh is six panels of four. The panels must tile the conductor
/// exactly: a mesh that loses area loses charge, and a solve on it is wrong in
/// a way no residual reveals.
#[test]
fn the_panels_of_a_cube_sum_to_its_analytic_surface_area() {
    let mut mesh = Mesh {
        panel: cube(0, 2.0),
        conductor_start: vec![0, 6],
        conductor_net: vec![NetId(0)],
        epsilon: vec![1.0; 6],
    };
    assert_close("a cube of side two", conductor_area(&mesh, 0), 24.0, 1e-12);

    // Refining a face into four quarters changes the panel count and nothing
    // else. Area is what survives refinement, which is the whole claim.
    let face = mesh.panel.pop().expect("the cube has six faces");
    for _ in 0..4 {
        mesh.panel.push(Panel {
            area: face.area / 4.0,
            ..face
        });
    }
    mesh.conductor_start = vec![0, 9];
    mesh.epsilon = vec![1.0; 9];
    assert_close(
        "the same cube, one face refined",
        conductor_area(&mesh, 0),
        24.0,
        1e-12,
    );
}

/// Oracle: closed form. One conductor's area is its own panels and nobody
/// else's. Two cubes of different sides in one mesh, and each must report its
/// own surface area — an implementation summing the whole panel column passes
/// the single-conductor case above and fails here.
#[test]
fn conductor_area_reads_only_the_panels_of_the_conductor_it_was_asked_about() {
    let mut panel = cube(0, 2.0);
    panel.extend(cube(1, 5.0));
    let mesh = Mesh {
        conductor_start: vec![0, 6, 12],
        conductor_net: vec![NetId(0), NetId(1)],
        epsilon: vec![1.0; panel.len()],
        panel,
    };

    assert_close("the small cube", conductor_area(&mesh, 0), 24.0, 1e-12);
    assert_close("the large cube", conductor_area(&mesh, 1), 150.0, 1e-12);
    assert_close_relative(
        "both conductors against the whole panel column",
        conductor_area(&mesh, 0) + conductor_area(&mesh, 1),
        mesh.panel.iter().map(|p| p.area).sum::<f64>(),
        1e-12,
    );
}

/// Oracle: law. With no device there is nothing to select, so the answer is the
/// host at every problem size — including sizes far above any crossover. This
/// is the fallback contract stated where it can be checked without a device,
/// and it is why `select` takes an `Option` rather than a flag.
#[cfg(feature = "gpu")]
#[test]
fn no_device_means_the_host_at_every_problem_size() {
    for panels in [0_usize, 1, 64, 10_000, 1 << 24] {
        assert_eq!(
            select(panels, None),
            Backend::Cpu,
            "{panels} panels with no device"
        );
    }
}

/// Oracle: law. `CpuMatVec` reports the host, because `Accuracy::backend` is
/// how a run's numbers are attributed and an adapter that misnames itself makes
/// every attribution downstream a lie.
#[test]
fn the_host_adapter_reports_the_host() {
    assert_eq!(CpuMatVec::default().backend(), Backend::Cpu);
}

/// Oracle: law, and `docs/GPU.md` contract item 6. Selection is automatic and
/// measured: below the device's own crossover the host wins and is chosen, at
/// or above it the device is. Where CI has no device the branch taken instead
/// asserts the fallback, which is contract item 5 — this test runs either way
/// and is never `#[ignore]`d.
#[cfg(feature = "gpu")]
#[test]
fn the_device_is_selected_only_above_its_own_measured_crossover() {
    let device = Device::find().expect("probing for a device is not itself a failure");
    let Some(device) = device else {
        assert_eq!(
            select(1 << 24, None),
            Backend::Cpu,
            "no device is present, so every size falls back to the host"
        );
        return;
    };

    let crossover = device.crossover();
    assert!(
        crossover > 0,
        "a crossover of zero is not a measured number"
    );
    assert_eq!(
        select(crossover - 1, Some(&device)),
        Backend::Cpu,
        "below the crossover the host was measured to win"
    );
    assert_eq!(
        select(crossover, Some(&device)),
        Backend::GpuF32,
        "at the crossover the device was measured to win"
    );
}
