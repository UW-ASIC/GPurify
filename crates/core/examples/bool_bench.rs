//! Microbenchmark for `rectilinear_boolean` — the hot kernel in DRC derived-layer
//! evaluation (64% of a full Philis signoff run, leaf `classify_point_scaled2`).
//!
//!   cargo run --release -p gdsverify-core --example bool_bench [k]
//!
//! Builds two k×k grids of axis-aligned rectangles (the shape routing/diffusion
//! geometry actually has), offset so they partially overlap, and times the three
//! boolean ops. Prints a checksum (`area2` + component count) so an optimization
//! can be proven output-identical, not just faster.

use gdsverify_core::exact::{Point, Polygon, PolygonSet, Ring};
use std::time::Instant;

fn rect(x0: i32, y0: i32, x1: i32, y1: i32) -> Polygon {
    let ring = Ring::new(vec![
        Point { x: x0, y: y0 },
        Point { x: x1, y: y0 },
        Point { x: x1, y: y1 },
        Point { x: x0, y: y1 },
    ])
    .expect("rect ring");
    Polygon::new(ring, Vec::new()).expect("rect polygon")
}

/// k×k grid of 100×100 rects on a 300 pitch, translated by (dx, dy).
fn grid(k: i32, dx: i32, dy: i32) -> PolygonSet {
    let mut polys = Vec::new();
    for i in 0..k {
        for j in 0..k {
            let x = i * 300 + dx;
            let y = j * 300 + dy;
            polys.push(rect(x, y, x + 100, y + 100));
        }
    }
    PolygonSet::new(polys).expect("grid set")
}

fn main() {
    let k: i32 = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(8);

    let lhs = grid(k, 0, 0);
    let rhs = grid(k, 50, 50);
    let verts = 4 * (k * k) as usize;
    println!("k={k}  {verts} verts/side  (grid cells ~ {}²)", 2 * verts);

    for (name, f) in [
        ("union", PolygonSet::union as fn(&PolygonSet, &PolygonSet) -> _),
        ("intersection", PolygonSet::intersection),
        ("subtraction", PolygonSet::subtraction),
    ] {
        let t = Instant::now();
        let out = f(&lhs, &rhs).expect("boolean");
        let ms = t.elapsed().as_secs_f64() * 1e3;
        println!(
            "  {name:<13} {ms:9.2} ms   area2={:<14} components={}",
            out.area2(),
            out.component_count()
        );
    }
}
