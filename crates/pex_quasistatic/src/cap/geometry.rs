//! FastCap surface-geometry parser (the "quickif" / `.qui` list format).
//!
//! Supported line kinds:
//!   * `0 ...`            — title / comment (ignored)
//!   * `* ...`            — comment (ignored)
//!   * `Q c x1 y1 z1 x2 y2 z2 x3 y3 z3 x4 y4 z4`  — quadrilateral panel
//!   * `T c x1 y1 z1 x2 y2 z2 x3 y3 z3`           — triangular panel
//!   * `N c name`         — assign a display name to conductor number `c`
//! `c` is the (1-based, as in FastCap) conductor number.
//!
//! `C subfile ...` include lines are not yet supported and are reported as an error.

use crate::geometry::Vec3;
use crate::integrals::panel::Panel;
use std::collections::BTreeMap;

/// A parsed capacitance problem: panels plus conductor names.
#[derive(Debug, Clone, Default)]
pub struct Geometry {
    pub panels: Vec<Panel>,
    /// Map from 0-based conductor index -> display name.
    pub conductor_names: Vec<String>,
    /// Original FastCap conductor numbers in first-seen order.
    cond_numbers: Vec<i64>,
    names_by_number: BTreeMap<i64, String>,
}

impl Geometry {
    pub fn num_conductors(&self) -> usize {
        self.conductor_names.len()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("line {0}: {1}")]
    At(usize, String),
}

fn parse_floats(tokens: &[&str], n: usize, lineno: usize) -> Result<Vec<f64>, ParseError> {
    if tokens.len() < n {
        return Err(ParseError::At(lineno, format!("expected {n} numbers, got {}", tokens.len())));
    }
    let mut v = Vec::with_capacity(n);
    for t in &tokens[..n] {
        v.push(
            t.parse::<f64>()
                .map_err(|_| ParseError::At(lineno, format!("bad number '{t}'")))?,
        );
    }
    Ok(v)
}

/// Parse a FastCap geometry deck. `scale` multiplies all coordinates (use it to
/// convert to metres if the file is in other units).
pub fn parse(input: &str, scale: f64) -> Result<Geometry, ParseError> {
    let mut geo = Geometry::default();
    // Temporary: conductor number -> 0-based index.
    let mut idx_of: BTreeMap<i64, usize> = BTreeMap::new();

    let intern = |num: i64, geo: &mut Geometry, idx_of: &mut BTreeMap<i64, usize>| -> usize {
        if let Some(&i) = idx_of.get(&num) {
            i
        } else {
            let i = geo.conductor_names.len();
            idx_of.insert(num, i);
            geo.cond_numbers.push(num);
            let name = geo
                .names_by_number
                .get(&num)
                .cloned()
                .unwrap_or_else(|| format!("cond{num}"));
            geo.conductor_names.push(name);
            i
        }
    };

    for (lineno0, raw) in input.lines().enumerate() {
        let lineno = lineno0 + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let first = line.chars().next().unwrap();
        let tokens: Vec<&str> = line.split_whitespace().collect();
        match first {
            '0' | '*' | '%' => continue,
            'Q' | 'q' => {
                let c: i64 = tokens
                    .get(1)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| ParseError::At(lineno, "Q: missing conductor number".into()))?;
                let f = parse_floats(&tokens[2..], 12, lineno)?;
                let verts = vec![
                    Vec3::new(f[0], f[1], f[2]) * scale,
                    Vec3::new(f[3], f[4], f[5]) * scale,
                    Vec3::new(f[6], f[7], f[8]) * scale,
                    Vec3::new(f[9], f[10], f[11]) * scale,
                ];
                let ci = intern(c, &mut geo, &mut idx_of);
                geo.panels.push(Panel::new(verts, ci));
            }
            'T' | 't' => {
                let c: i64 = tokens
                    .get(1)
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| ParseError::At(lineno, "T: missing conductor number".into()))?;
                let f = parse_floats(&tokens[2..], 9, lineno)?;
                let verts = vec![
                    Vec3::new(f[0], f[1], f[2]) * scale,
                    Vec3::new(f[3], f[4], f[5]) * scale,
                    Vec3::new(f[6], f[7], f[8]) * scale,
                ];
                let ci = intern(c, &mut geo, &mut idx_of);
                geo.panels.push(Panel::new(verts, ci));
            }
            'N' | 'n' => {
                if let (Some(cs), Some(name)) = (tokens.get(1), tokens.get(2)) {
                    if let Ok(c) = cs.parse::<i64>() {
                        geo.names_by_number.insert(c, name.to_string());
                        if let Some(&i) = idx_of.get(&c) {
                            geo.conductor_names[i] = name.to_string();
                        }
                    }
                }
            }
            'C' | 'c' => {
                return Err(ParseError::At(lineno, "C (sub-file include) not yet supported".into()));
            }
            _ => return Err(ParseError::At(lineno, format!("unrecognized line: {line}"))),
        }
    }

    Ok(geo)
}
