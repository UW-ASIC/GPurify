fn main() {
    use gpurify::engine::pipeline::{extract_into, load_into, Inputs};
    use gpurify::ingest::layout::UnknownLayers;
    use gpurify::units::Grid;
    use std::path::Path;

    let proj_dir = Path::new(".");
    let fixtures = proj_dir.join("tests/fixtures");
    let inputs = Inputs {
        layout: fixtures.join("_source/conformance.gds"),
        deck: fixtures.join("params.json"),
        grid: Some(Grid::new(1000).expect("1000 dbu/um")),
        reference: None,
        intent: None,
        unknown_layers: UnknownLayers::Drop,
    };

    let mut loaded = gpurify::engine::pipeline::Loaded::default();
    load_into(&inputs, &mut loaded).expect("load");

    let mut extracted = gpurify::engine::pipeline::Extracted::default();
    extract_into(&loaded, &mut extracted).expect("extract");

    let store = &loaded.store;
    let nets = &extracted.nets;

    println!("Total polygons: {}", store.poly_count());
    println!("Total nets: {}", nets.net_count());

    let mut poly_counts = vec![0u32; nets.net_count()];
    for poly_idx in 0..store.poly_count() {
        let poly = gpurify::core::PolyId(poly_idx as u32);
        let net = nets.net_of(poly);
        if (net.idx() as usize) < nets.net_count() {
            poly_counts[net.idx() as usize] += 1;
        }
    }

    let max_net_size = *poly_counts.iter().max().unwrap_or(&0) as usize;
    println!("Largest net: {} polygons", max_net_size);
    let sum_polys: u32 = poly_counts.iter().sum();
    println!("Sum of poly_counts: {} (should equal {})", sum_polys, store.poly_count());

    let mut size_freq = std::collections::BTreeMap::new();
    for &size in &poly_counts {
        *size_freq.entry(size).or_insert(0u32) += 1;
    }

    println!("\nNet size distribution:");
    for (size, count) in &size_freq {
        println!("  size {}: {} nets", size, count);
    }

    let huge = poly_counts.iter().filter(|&&s| s > 1000).count();
    let large = poly_counts.iter().filter(|&&s| 100 < s && s <= 1000).count();
    let small = poly_counts.iter().filter(|&&s| s <= 100).count();
    println!("\nNets > 1000 polys: {}", huge);
    println!("Nets 100..1000 polys: {}", large);
    println!("Nets <= 100 polys: {}", small);

    if let Some((biggest_idx, &biggest_size)) = poly_counts
        .iter()
        .enumerate()
        .max_by_key(|(_, &s)| s)
    {
        println!("\nBiggest net: index {} with {} polygons ({:.1}%)", 
            biggest_idx, biggest_size, 
            (biggest_size as f64 / store.poly_count() as f64) * 100.0);
    }
}
