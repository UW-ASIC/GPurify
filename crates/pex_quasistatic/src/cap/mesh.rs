//! Simple panel-mesh generators for examples and the analytic validation suite:
//! flat rectangular plates and a subdivided icosphere. These let the validation
//! tests build canonical geometries (parallel-plate capacitor, isolated sphere)
//! without external mesh files.

use crate::geometry::Vec3;
use crate::integrals::panel::Panel;

/// A flat rectangular plate in the z = `z0` plane, spanning
/// [cx−lx/2, cx+lx/2] × [cy−ly/2, cy+ly/2], subdivided into `nx × ny` quad
/// panels, all assigned to `conductor`.
pub fn plate(
    cx: f64,
    cy: f64,
    z0: f64,
    lx: f64,
    ly: f64,
    nx: usize,
    ny: usize,
    conductor: usize,
) -> Vec<Panel> {
    let mut panels = Vec::with_capacity(nx * ny);
    let x0 = cx - lx / 2.0;
    let y0 = cy - ly / 2.0;
    let dx = lx / nx as f64;
    let dy = ly / ny as f64;
    for i in 0..nx {
        for j in 0..ny {
            let xa = x0 + i as f64 * dx;
            let xb = xa + dx;
            let ya = y0 + j as f64 * dy;
            let yb = ya + dy;
            let verts = vec![
                Vec3::new(xa, ya, z0),
                Vec3::new(xb, ya, z0),
                Vec3::new(xb, yb, z0),
                Vec3::new(xa, yb, z0),
            ];
            panels.push(Panel::new(verts, conductor));
        }
    }
    panels
}

/// A triangulated sphere of radius `r` centred at `center`, produced by
/// `subdivisions` levels of icosahedron refinement, all panels on `conductor`.
/// `subdivisions = 0` gives the 20-face icosahedron; each level ×4 the faces.
pub fn icosphere(center: Vec3, r: f64, subdivisions: usize, conductor: usize) -> Vec<Panel> {
    // Golden-ratio icosahedron vertices.
    let t = (1.0 + 5f64.sqrt()) / 2.0;
    let mut verts: Vec<Vec3> = vec![
        Vec3::new(-1.0, t, 0.0),
        Vec3::new(1.0, t, 0.0),
        Vec3::new(-1.0, -t, 0.0),
        Vec3::new(1.0, -t, 0.0),
        Vec3::new(0.0, -1.0, t),
        Vec3::new(0.0, 1.0, t),
        Vec3::new(0.0, -1.0, -t),
        Vec3::new(0.0, 1.0, -t),
        Vec3::new(t, 0.0, -1.0),
        Vec3::new(t, 0.0, 1.0),
        Vec3::new(-t, 0.0, -1.0),
        Vec3::new(-t, 0.0, 1.0),
    ]
    .into_iter()
    .map(|v| v.normalized())
    .collect();

    let mut faces: Vec<[usize; 3]> = vec![
        [0, 11, 5], [0, 5, 1], [0, 1, 7], [0, 7, 10], [0, 10, 11],
        [1, 5, 9], [5, 11, 4], [11, 10, 2], [10, 7, 6], [7, 1, 8],
        [3, 9, 4], [3, 4, 2], [3, 2, 6], [3, 6, 8], [3, 8, 9],
        [4, 9, 5], [2, 4, 11], [6, 2, 10], [8, 6, 7], [9, 8, 1],
    ];

    for _ in 0..subdivisions {
        let mut new_faces = Vec::with_capacity(faces.len() * 4);
        // Midpoint cache keyed by ordered vertex-index pair.
        let mut cache: std::collections::HashMap<(usize, usize), usize> = std::collections::HashMap::new();
        let mut midpoint = |a: usize, b: usize, verts: &mut Vec<Vec3>| -> usize {
            let key = if a < b { (a, b) } else { (b, a) };
            if let Some(&m) = cache.get(&key) {
                return m;
            }
            let mid = ((verts[a] + verts[b]) * 0.5).normalized();
            let idx = verts.len();
            verts.push(mid);
            cache.insert(key, idx);
            idx
        };
        for f in &faces {
            let a = midpoint(f[0], f[1], &mut verts);
            let b = midpoint(f[1], f[2], &mut verts);
            let c = midpoint(f[2], f[0], &mut verts);
            new_faces.push([f[0], a, c]);
            new_faces.push([f[1], b, a]);
            new_faces.push([f[2], c, b]);
            new_faces.push([a, b, c]);
        }
        faces = new_faces;
    }

    faces
        .iter()
        .map(|f| {
            let vs = vec![
                center + verts[f[0]] * r,
                center + verts[f[1]] * r,
                center + verts[f[2]] * r,
            ];
            Panel::new(vs, conductor)
        })
        .collect()
}
