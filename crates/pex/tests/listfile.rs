//! List-file end-to-end: two conductor plates referenced from a .lst produce the
//! same capacitance as building the panels directly.

use std::io::Write;

#[test]
fn list_file_two_plate_capacitor() {
    let dir = std::env::temp_dir().join(format!("fclst_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // Write two single-panel plate .qui files (conductor 1 each).
    let bottom = "0 bottom\nQ 1 -0.1 -0.1 0 0.1 -0.1 0 0.1 0.1 0 -0.1 0.1 0\n";
    let top = "0 top\nQ 1 -0.1 -0.1 0 0.1 -0.1 0 0.1 0.1 0 -0.1 0.1 0\n";
    std::fs::File::create(dir.join("bot.qui")).unwrap().write_all(bottom.as_bytes()).unwrap();
    std::fs::File::create(dir.join("top.qui")).unwrap().write_all(top.as_bytes()).unwrap();

    // List file: bottom at z=0, top at z=0.02, both conductors in vacuum.
    let lst = "* two plates\n\
               C bot.qui 1.0 0 0 0\n\
               C top.qui 1.0 0 0 0.02\n";
    let problem = gdsverify_pex::quasistatic::cap::parse_list_str(lst, &dir).unwrap();
    assert_eq!(problem.num_conductors(), 2, "expected 2 conductors");
    assert_eq!(problem.panels.len(), 2, "expected 2 panels");

    // Solve; expect a sensible mutual capacitance (negative off-diagonal).
    let cap = gdsverify_pex::quasistatic::cap::solve_dielectric(&problem).unwrap();
    println!("list-file 2-plate C matrix (pF): [[{:.3},{:.3}],[{:.3},{:.3}]]",
        cap.c[(0,0)]*1e12, cap.c[(0,1)]*1e12, cap.c[(1,0)]*1e12, cap.c[(1,1)]*1e12);
    assert!(cap.c[(0,1)] < 0.0 && cap.c[(0,0)] > 0.0);
    // Symmetry.
    assert!((cap.c[(0,1)]-cap.c[(1,0)]).abs()/cap.c[(0,1)].abs() < 1e-6);

    let _ = std::fs::remove_dir_all(&dir);
}
