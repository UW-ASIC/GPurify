//! Inductance/resistance validation against analytic references and physics.

use quasiss::integrals::filament::self_inductance_bar;

fn wire_deck(nh: usize, nw: usize, f: f64) -> String {
    format!(
        "* straight copper wire\n\
         .units m\n\
         N1 x=0 y=0 z=0\n\
         N2 x=0.1 y=0 z=0\n\
         E1 N1 N2 w=0.001 h=0.001 sigma=5.8e7 nhinc={nh} nwinc={nw}\n\
         .external N1 N2\n\
         .freq fmin={f} fmax={f} ndec=1\n\
         .end\n"
    )
}

#[test]
fn dc_resistance_is_exact() {
    // R = length / (σ · w · h). One filament, low frequency.
    let deck = wire_deck(1, 1, 1.0);
    let res = quasiss::henry::run(&deck).unwrap();
    let r = res.z[0][(0, 0)].re;
    let expected = 0.1 / (5.8e7 * 0.001 * 0.001);
    let rel = (r - expected).abs() / expected;
    println!("R = {r:.6e} Ω, expected {expected:.6e} Ω, rel {:.2e}", rel);
    assert!(rel < 1e-9, "DC resistance off: {rel}");
}

#[test]
fn single_filament_self_inductance_matches_bar_formula() {
    // With nhinc=nwinc=1 the port inductance is exactly the partial self
    // inductance of the rectangular bar (Grover/Rosa formula) — validates the
    // full parse → assemble → nodal-solve plumbing.
    let f = 1.0e6;
    let deck = wire_deck(1, 1, f);
    let res = quasiss::henry::run(&deck).unwrap();
    let w = 2.0 * std::f64::consts::PI * f;
    let l = res.z[0][(0, 0)].im / w;
    let expected = self_inductance_bar(0.1, 0.001, 0.001);
    let rel = (l - expected).abs() / expected;
    println!("L = {l:.6e} H, bar formula {expected:.6e} H, rel {:.2e}", rel);
    assert!(rel < 1e-9, "self inductance off: {rel}");
}

#[test]
fn subdivided_inductance_close_to_single_bar() {
    // Subdividing the cross-section into a filament bundle must give an
    // inductance close to (within a few percent of) the single-bar value at low
    // frequency, where current is ~uniform.
    let f = 1.0e3;
    let single = {
        let res = quasiss::henry::run(&wire_deck(1, 1, f)).unwrap();
        let w = 2.0 * std::f64::consts::PI * f;
        res.z[0][(0, 0)].im / w
    };
    let sub = {
        let res = quasiss::henry::run(&wire_deck(4, 4, f)).unwrap();
        let w = 2.0 * std::f64::consts::PI * f;
        res.z[0][(0, 0)].im / w
    };
    let rel = (single - sub).abs() / single;
    println!("L single = {single:.6e} H, L subdivided = {sub:.6e} H, rel {:.3}%", rel * 100.0);
    assert!(rel < 0.05, "subdivided inductance drifted {:.2}% from single bar", rel * 100.0);
}

#[test]
fn skin_effect_raises_ac_resistance() {
    // With a filament bundle, the AC resistance at high frequency must exceed
    // the DC resistance as current crowds toward the outer filaments.
    let r_dc = quasiss::henry::run(&wire_deck(6, 6, 1.0)).unwrap().z[0][(0, 0)].re;
    let r_ac = quasiss::henry::run(&wire_deck(6, 6, 1.0e9)).unwrap().z[0][(0, 0)].re;
    println!("R_dc = {r_dc:.6e} Ω, R_ac(1GHz) = {r_ac:.6e} Ω, ratio {:.3}", r_ac / r_dc);
    assert!(r_ac > r_dc * 1.05, "no skin-effect rise: {r_ac} vs {r_dc}");
}

#[test]
fn impedance_matrix_is_symmetric() {
    // Two-port with two conductors; the extracted Z must be symmetric.
    let deck = "\
        .units m\n\
        N1 x=0 y=0 z=0\n\
        N2 x=0.05 y=0 z=0\n\
        N3 x=0 y=0.002 z=0\n\
        N4 x=0.05 y=0.002 z=0\n\
        E1 N1 N2 w=0.0002 h=0.0002 sigma=5.8e7\n\
        E2 N3 N4 w=0.0002 h=0.0002 sigma=5.8e7\n\
        .external N1 N2 porta\n\
        .external N3 N4 portb\n\
        .freq fmin=1e8 fmax=1e8 ndec=1\n\
        .end\n";
    let res = quasiss::henry::run(deck).unwrap();
    let z = &res.z[0];
    let asym = (z[(0, 1)] - z[(1, 0)]).norm() / z[(0, 1)].norm().max(1e-30);
    println!("Z01 = {}, Z10 = {}, asym {:.2e}", z[(0, 1)], z[(1, 0)], asym);
    assert!(asym < 1e-9, "impedance matrix not symmetric: {asym}");
    // Mutual coupling between the two nearby wires must be nonzero and positive
    // (parallel currents, positive mutual inductance).
    assert!(z[(0, 1)].im > 0.0);
}

#[test]
fn inductance_is_frequency_independent_at_low_freq() {
    // L = Im(Z)/ω should be ~constant across low frequencies (no skin effect yet).
    let l = |f: f64| {
        let res = quasiss::henry::run(&wire_deck(1, 1, f)).unwrap();
        res.z[0][(0, 0)].im / (2.0 * std::f64::consts::PI * f)
    };
    let l1 = l(1.0e2);
    let l2 = l(1.0e4);
    let rel = (l1 - l2).abs() / l1;
    assert!(rel < 1e-9, "L not frequency independent: {rel}");
}

#[test]
fn iterative_matches_direct() {
    // The complex-GMRES iterative path must reproduce the dense-LU impedance.
    let deck = "\
        .units m\n\
        N1 x=0 y=0 z=0\n\
        N2 x=0.05 y=0 z=0\n\
        N3 x=0 y=0.002 z=0\n\
        N4 x=0.05 y=0.002 z=0\n\
        E1 N1 N2 w=0.0002 h=0.0002 sigma=5.8e7 nhinc=2 nwinc=2\n\
        E2 N3 N4 w=0.0002 h=0.0002 sigma=5.8e7 nhinc=2 nwinc=2\n\
        .external N1 N2 porta\n\
        .external N3 N4 portb\n\
        .freq fmin=1e8 fmax=1e8 ndec=1\n\
        .end\n";
    let nl = quasiss::henry::parse(deck).unwrap();
    let zd = quasiss::henry::solve_with(&nl, quasiss::henry::Method::Direct).unwrap();
    let zi = quasiss::henry::solve_with(&nl, quasiss::henry::Method::Iterative).unwrap();
    let mut maxrel = 0.0f64;
    for i in 0..2 {
        for j in 0..2 {
            let a = zd.z[0][(i, j)];
            let b = zi.z[0][(i, j)];
            maxrel = maxrel.max((a - b).norm() / a.norm().max(1e-30));
        }
    }
    println!("iterative vs direct max rel err = {maxrel:.2e}");
    assert!(maxrel < 1e-7, "iterative disagrees with direct: {maxrel}");
}

#[test]
fn equiv_merges_nodes() {
    // A wire split into two segments joined at N2, vs. the same split where the
    // join is expressed with .equiv N2 N2b — must give identical inductance.
    let joined = "\
        .units m\n\
        N1 x=0 y=0 z=0\n\
        N2 x=0.05 y=0 z=0\n\
        N3 x=0.1 y=0 z=0\n\
        E1 N1 N2 w=0.001 h=0.001 sigma=5.8e7\n\
        E2 N2 N3 w=0.001 h=0.001 sigma=5.8e7\n\
        .external N1 N3\n\
        .freq fmin=1e3 fmax=1e3 ndec=1\n\
        .end\n";
    let equiv = "\
        .units m\n\
        N1 x=0 y=0 z=0\n\
        N2 x=0.05 y=0 z=0\n\
        N2b x=0.05 y=0 z=0\n\
        N3 x=0.1 y=0 z=0\n\
        E1 N1 N2 w=0.001 h=0.001 sigma=5.8e7\n\
        E2 N2b N3 w=0.001 h=0.001 sigma=5.8e7\n\
        .equiv N2 N2b\n\
        .external N1 N3\n\
        .freq fmin=1e3 fmax=1e3 ndec=1\n\
        .end\n";
    let za = quasiss::henry::run(joined).unwrap().z[0][(0, 0)];
    let zb = quasiss::henry::run(equiv).unwrap().z[0][(0, 0)];
    let rel = (za - zb).norm() / za.norm();
    println!("equiv: Z joined {za}, Z equiv {zb}, rel {rel:.2e}");
    assert!(rel < 1e-12, ".equiv did not merge nodes: {rel}");
}

#[test]
fn ground_plane_reduces_inductance_and_matches_image_loop() {
    let l = 0.1;
    let h = 0.003;
    let w = 0.0002;
    let freq = 1.0e3;
    let ind = |deck: &str| {
        let r = quasiss::henry::run(deck).unwrap();
        r.z[0][(0, 0)].im / (2.0 * std::f64::consts::PI * freq)
    };

    // Wire alone (no plane).
    let alone = format!(
        ".units m\nN1 x=0 y=0 z={h}\nN2 x={l} y=0 z={h}\n\
         E1 N1 N2 w={w} h={w} sigma=5.8e7\n.external N1 N2\n.freq fmin={freq} fmax={freq} ndec=1\n.end\n"
    );
    // Wire over an ideal ground plane at z=0.
    let over_plane = format!(
        ".units m\nN1 x=0 y=0 z={h}\nN2 x={l} y=0 z={h}\n\
         E1 N1 N2 w={w} h={w} sigma=5.8e7\n.gplane z=0\n.external N1 N2\n.freq fmin={freq} fmax={freq} ndec=1\n.end\n"
    );
    // Explicit image loop: wire at +h and anti-parallel return at -h (no plane).
    // By image symmetry, its loop inductance = 2 × (wire-over-plane inductance).
    let loop_deck = format!(
        ".units m\n\
         N1 x=0 y=0 z={h}\nN2 x={l} y=0 z={h}\nN3 x={l} y=0 z={mh}\nN4 x=0 y=0 z={mh}\n\
         E1 N1 N2 w={w} h={w} sigma=5.8e7\n\
         E2 N2 N3 w={w} h={w} sigma=5.8e7\n\
         E3 N3 N4 w={w} h={w} sigma=5.8e7\n\
         .external N1 N4\n.freq fmin={freq} fmax={freq} ndec=1\n.end\n",
        mh = -h
    );

    let l_alone = ind(&alone);
    let l_plane = ind(&over_plane);
    let l_loop = ind(&loop_deck);
    println!(
        "L_alone={:.4e} H, L_over_plane={:.4e} H, L_loop={:.4e} H, L_loop/2={:.4e}",
        l_alone, l_plane, l_loop, l_loop / 2.0
    );
    // Ground plane reduces inductance.
    assert!(l_plane < l_alone, "ground plane did not reduce L");
    // Image method matches the explicit loop to a few percent (the loop's short
    // vertical end segments add a small extra inductance).
    let rel = (l_plane - l_loop / 2.0).abs() / (l_loop / 2.0);
    println!("image vs explicit-loop rel = {:.3}", rel);
    assert!(rel < 0.10, "image ground plane disagrees with explicit loop: {rel}");
}

#[test]
fn mesh_formulation_matches_nodal() {
    // FastHenry's MZMᵀ mesh analysis must reproduce the nodal admittance result.
    let decks = [
        // single wire
        "* w\n.units m\nN1 x=0 y=0 z=0\nN2 x=0.1 y=0 z=0\n\
         E1 N1 N2 w=0.001 h=0.001 sigma=5.8e7 nhinc=2 nwinc=2\n.external N1 N2\n\
         .freq fmin=1e6 fmax=1e6 ndec=1\n.end\n",
        // two-port coupled wires (has multiple meshes)
        "* two\n.units m\nN1 x=0 y=0 z=0\nN2 x=0.05 y=0 z=0\nN3 x=0 y=0.002 z=0\nN4 x=0.05 y=0.002 z=0\n\
         E1 N1 N2 w=0.0002 h=0.0002 sigma=5.8e7\nE2 N3 N4 w=0.0002 h=0.0002 sigma=5.8e7\n\
         .external N1 N2 pa\n.external N3 N4 pb\n.freq fmin=1e8 fmax=1e8 ndec=1\n.end\n",
        // a loop (spiral-ish) with many meshes
        "* mesh\n.units m\nN1 x=0 y=0 z=0\nN2 x=0.02 y=0 z=0\nN3 x=0.02 y=0.02 z=0\nN4 x=0 y=0.02 z=0\n\
         E1 N1 N2 w=0.0005 h=0.0005 sigma=5.8e7 nhinc=2 nwinc=2\n\
         E2 N2 N3 w=0.0005 h=0.0005 sigma=5.8e7 nhinc=2 nwinc=2\n\
         E3 N3 N4 w=0.0005 h=0.0005 sigma=5.8e7 nhinc=2 nwinc=2\n\
         .external N1 N4\n.freq fmin=1e7 fmax=1e7 ndec=1\n.end\n",
    ];
    for (di, deck) in decks.iter().enumerate() {
        let nl = quasiss::henry::parse(deck).unwrap();
        let zn = quasiss::henry::solve_full(&nl, quasiss::henry::Method::Direct, quasiss::henry::Formulation::Nodal).unwrap();
        let zm = quasiss::henry::solve_full(&nl, quasiss::henry::Method::Direct, quasiss::henry::Formulation::Mesh).unwrap();
        let np = zn.port_names.len();
        let mut maxrel = 0.0f64;
        for i in 0..np {
            for j in 0..np {
                let a = zn.z[0][(i, j)];
                let b = zm.z[0][(i, j)];
                maxrel = maxrel.max((a - b).norm() / a.norm().max(1e-30));
            }
        }
        println!("deck {di}: mesh vs nodal max rel = {maxrel:.2e}");
        assert!(maxrel < 1e-9, "mesh formulation disagrees with nodal (deck {di}): {maxrel}");
    }
}
