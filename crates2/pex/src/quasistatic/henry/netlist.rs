//! FastHenry `.inp` data model and parser.
//!
//! Supports the common subset of the FastHenry input language:
//!   * `.units <unit>`
//!   * node lines:   `N<name> x=.. y=.. z=..`
//!   * segment lines:`E<name> <n1> <n2> w=.. h=.. sigma=..|rho=.. nhinc=.. nwinc=.. [wx=.. wy=.. wz=..]`
//!   * `.default <key=val ...>` (segment defaults)
//!   * `.external <n1> <n2> [portname]`
//!   * `.freq fmin=.. fmax=.. ndec=..`
//!   * `.end`
//! Comments start with `*` or `#`. Directives are case-insensitive.

use crate::quasistatic::henry::units::units_to_meters;
use std::collections::HashMap;

/// A named circuit node with 3-D position (metres, after unit scaling).
#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub pos: [f64; 3],
}

/// A conductor segment (later discretized into a filament bundle).
#[derive(Debug, Clone)]
pub struct Segment {
    pub name: String,
    pub n1: String,
    pub n2: String,
    pub w: f64,
    pub h: f64,
    /// Conductivity σ [S/m].
    pub sigma: f64,
    pub nhinc: usize,
    pub nwinc: usize,
    /// Ratio of adjacent filament widths across the width (FastHenry `rw`,
    /// default 2.0): filaments get finer toward the edges to resolve skin/
    /// proximity effects.
    pub rw: f64,
    /// Ratio of adjacent filament heights (FastHenry `rh`, default 2.0).
    pub rh: f64,
    /// Optional explicit width-direction vector; if `None` it is derived.
    pub wdir: Option<[f64; 3]>,
}

/// An external port (pair of terminal nodes).
#[derive(Debug, Clone)]
pub struct Port {
    pub name: String,
    pub n1: String,
    pub n2: String,
}

/// Logarithmic frequency sweep specification.
#[derive(Debug, Clone, Copy)]
pub struct FreqSweep {
    pub fmin: f64,
    pub fmax: f64,
    /// Points per decade.
    pub ndec: f64,
}

impl FreqSweep {
    /// Expand into the list of frequencies [Hz].
    pub fn frequencies(&self) -> Vec<f64> {
        if self.fmin <= 0.0 {
            // A single DC-ish point.
            return vec![self.fmin.max(0.0)];
        }
        if (self.fmax - self.fmin).abs() < f64::EPSILON {
            return vec![self.fmin];
        }
        let decades = (self.fmax / self.fmin).log10();
        let n = (decades * self.ndec).round().max(1.0) as usize;
        (0..=n)
            .map(|i| self.fmin * 10f64.powf(i as f64 / self.ndec))
            .collect()
    }
}

/// An ideal (flux-excluding / high-frequency) perfect ground plane, modelled by
/// image filaments. Defined by a point on the plane and its unit normal.
#[derive(Debug, Clone, Copy)]
pub struct GroundPlane {
    pub point: [f64; 3],
    pub normal: [f64; 3],
}

/// A fully-parsed input deck.
#[derive(Debug, Clone, Default)]
pub struct Netlist {
    pub nodes: Vec<Node>,
    pub segments: Vec<Segment>,
    pub ports: Vec<Port>,
    pub freq: Option<FreqSweep>,
    pub node_index: HashMap<String, usize>,
    /// Groups of node names declared electrically identical via `.equiv`.
    pub equivs: Vec<Vec<String>>,
    /// Optional ideal ground plane (`.gplane`).
    pub ground_plane: Option<GroundPlane>,
}

impl Netlist {
    pub fn node_idx(&self, name: &str) -> Option<usize> {
        self.node_index.get(&name.to_ascii_lowercase()).copied()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("line {0}: {1}")]
    At(usize, String),
}

/// Parse key=value tokens into a map (lowercased keys).
fn kv(tokens: &[&str]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for t in tokens {
        if let Some((k, v)) = t.split_once('=') {
            m.insert(k.to_ascii_lowercase(), v.to_string());
        }
    }
    m
}

fn getf(m: &HashMap<String, String>, k: &str) -> Option<f64> {
    m.get(k).and_then(|s| s.parse::<f64>().ok())
}

/// Parse a FastHenry `.inp` deck from text.
pub fn parse(input: &str) -> Result<Netlist, ParseError> {
    let mut scale = 1.0f64; // metres per input unit
    let mut nl = Netlist::default();

    // Segment defaults from `.default`.
    let mut def_sigma = 5.8e7; // copper-ish default
    let mut def_nhinc = 1usize;
    let mut def_nwinc = 1usize;
    let mut def_w: Option<f64> = None;
    let mut def_h: Option<f64> = None;

    for (lineno0, raw) in input.lines().enumerate() {
        let lineno = lineno0 + 1;
        // Strip comments and whitespace.
        let line = raw.trim();
        if line.is_empty() || line.starts_with('*') || line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let tokens: Vec<&str> = line.split_whitespace().collect();

        if lower.starts_with(".units") {
            let u = tokens.get(1).ok_or_else(|| ParseError::At(lineno, "missing unit".into()))?;
            scale = units_to_meters(u)
                .ok_or_else(|| ParseError::At(lineno, format!("unknown unit '{u}'")))?;
        } else if lower.starts_with(".default") {
            let m = kv(&tokens[1..]);
            // FastHenry sigma is per *input unit*: 1/(Ω·unit). Convert to SI
            // 1/(Ω·m) here (rho likewise is Ω·unit).
            if let Some(s) = getf(&m, "sigma") {
                def_sigma = s / scale;
            }
            if let Some(r) = getf(&m, "rho") {
                def_sigma = 1.0 / (r * scale);
            }
            if let Some(n) = getf(&m, "nhinc") {
                def_nhinc = n as usize;
            }
            if let Some(n) = getf(&m, "nwinc") {
                def_nwinc = n as usize;
            }
            if let Some(v) = getf(&m, "w") {
                def_w = Some(v);
            }
            if let Some(v) = getf(&m, "h") {
                def_h = Some(v);
            }
        } else if lower.starts_with(".external") {
            let n1 = tokens.get(1).ok_or_else(|| ParseError::At(lineno, "external: missing node1".into()))?;
            let n2 = tokens.get(2).ok_or_else(|| ParseError::At(lineno, "external: missing node2".into()))?;
            let name = tokens.get(3).map(|s| s.to_string()).unwrap_or_else(|| format!("port{}", nl.ports.len() + 1));
            nl.ports.push(Port { name, n1: n1.to_string(), n2: n2.to_string() });
        } else if lower.starts_with(".equiv") {
            // .equiv N1 N2 N3 ...  — declare nodes electrically identical.
            let group: Vec<String> = tokens[1..].iter().map(|s| s.to_string()).collect();
            if group.len() >= 2 {
                nl.equivs.push(group);
            }
        } else if lower.starts_with(".gplane") {
            // .gplane z=<val> [nx=.. ny=.. nz=..]  — ideal ground plane.
            let m = kv(&tokens[1..]);
            let px = getf(&m, "x").unwrap_or(0.0) * scale;
            let py = getf(&m, "y").unwrap_or(0.0) * scale;
            let pz = getf(&m, "z").unwrap_or(0.0) * scale;
            let nx = getf(&m, "nx").unwrap_or(0.0);
            let ny = getf(&m, "ny").unwrap_or(0.0);
            let nz = getf(&m, "nz").unwrap_or(1.0);
            nl.ground_plane = Some(GroundPlane { point: [px, py, pz], normal: [nx, ny, nz] });
        } else if lower.starts_with(".freq") {
            let m = kv(&tokens[1..]);
            let fmin = getf(&m, "fmin").ok_or_else(|| ParseError::At(lineno, "freq: missing fmin".into()))?;
            let fmax = getf(&m, "fmax").unwrap_or(fmin);
            let ndec = getf(&m, "ndec").unwrap_or(1.0);
            nl.freq = Some(FreqSweep { fmin, fmax, ndec });
        } else if lower.starts_with(".end") {
            break;
        } else if lower.starts_with('n') && line.contains('=') {
            // Node line: N<name> x=.. y=.. z=..
            let name = tokens[0].to_string();
            let m = kv(&tokens[1..]);
            let x = getf(&m, "x").unwrap_or(0.0) * scale;
            let y = getf(&m, "y").unwrap_or(0.0) * scale;
            let z = getf(&m, "z").unwrap_or(0.0) * scale;
            let key = name.to_ascii_lowercase();
            nl.node_index.insert(key, nl.nodes.len());
            nl.nodes.push(Node { name, pos: [x, y, z] });
        } else if lower.starts_with('e') {
            // Segment line: E<name> n1 n2 key=val...
            if tokens.len() < 3 {
                return Err(ParseError::At(lineno, "segment: need name n1 n2".into()));
            }
            let name = tokens[0].to_string();
            let n1 = tokens[1].to_string();
            let n2 = tokens[2].to_string();
            let m = kv(&tokens[3..]);
            let w = getf(&m, "w").or(def_w)
                .ok_or_else(|| ParseError::At(lineno, "segment: missing w".into()))? * scale;
            let h = getf(&m, "h").or(def_h)
                .ok_or_else(|| ParseError::At(lineno, "segment: missing h".into()))? * scale;
            // Per-unit -> SI, as in `.default` above.
            let sigma = if let Some(s) = getf(&m, "sigma") {
                s / scale
            } else if let Some(r) = getf(&m, "rho") {
                1.0 / (r * scale)
            } else {
                def_sigma
            };
            let nhinc = getf(&m, "nhinc").map(|x| x as usize).unwrap_or(def_nhinc).max(1);
            let nwinc = getf(&m, "nwinc").map(|x| x as usize).unwrap_or(def_nwinc).max(1);
            // FastHenry default ratio 2.0 (readGeom.c): filaments finer at the
            // edges, so nhinc/nwinc > 1 actually resolves skin effect. Our
            // partition matches C's ±delh scheme exactly (both symmetric r^i
            // from each edge).
            let rw = getf(&m, "rw").unwrap_or(2.0);
            let rh = getf(&m, "rh").unwrap_or(2.0);
            let wdir = match (getf(&m, "wx"), getf(&m, "wy"), getf(&m, "wz")) {
                (Some(a), Some(b), Some(c)) => Some([a, b, c]),
                _ => None,
            };
            nl.segments.push(Segment { name, n1, n2, w, h, sigma, nhinc, nwinc, rw, rh, wdir });
        } else {
            return Err(ParseError::At(lineno, format!("unrecognized line: {line}")));
        }
    }

    // Apply .equiv: point every equivalent node name at a single representative
    // index so branches/ports referencing any name in the group share the node.
    for group in nl.equivs.clone() {
        // Representative = the smallest existing index among the group's names.
        let mut rep: Option<usize> = None;
        for name in &group {
            if let Some(&idx) = nl.node_index.get(&name.to_ascii_lowercase()) {
                rep = Some(match rep {
                    Some(r) => r.min(idx),
                    None => idx,
                });
            }
        }
        if let Some(rep) = rep {
            for name in &group {
                nl.node_index.insert(name.to_ascii_lowercase(), rep);
            }
        }
    }

    Ok(nl)
}
