//! Length-unit handling for the `.units` directive.

/// Multiplicative factor converting a value in the given unit to metres.
pub fn units_to_meters(unit: &str) -> Option<f64> {
    let f = match unit.to_ascii_lowercase().as_str() {
        "m" | "meter" | "meters" => 1.0,
        "cm" => 1e-2,
        "mm" => 1e-3,
        "um" | "micron" | "microns" => 1e-6,
        "in" | "inch" | "inches" => 0.0254,
        "mil" | "mils" => 0.0254e-3, // 1 mil = 1/1000 inch
        "km" => 1e3,
        _ => return None,
    };
    Some(f)
}
