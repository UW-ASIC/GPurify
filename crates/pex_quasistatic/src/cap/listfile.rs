//! FastCap list-file (`.lst`) parser with `C` (conductor) and `D` (dielectric)
//! sub-file includes and per-file permittivity + translation.
//!
//! Grammar (comment lines start with `*`):
//!   `C <geomfile> <outerperm> <xtrans> <ytrans> <ztrans> [+|-]`
//!   `D <geomfile> <outerperm> <innerperm> <xref> <yref> <zref> <xtrans> <ytrans> <ztrans> [+|-]`
//! `C` panels become conductors sitting in a medium of `outerperm`; `D` panels
//! become dielectric interfaces with the given outer/inner permittivities and an
//! inner reference point. Geometry files are the quickif (`.qui`) Q/T format
//! read by [`crate::cap::geometry::parse`]. A trailing `-` flag flips the stored panel
//! orientation (rarely needed for closed surfaces).

use crate::cap::dielectric::{PanelRole, Problem};
use crate::cap::geometry::parse as parse_qui;
use crate::geometry::Vec3;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ListError {
    #[error("line {0}: {1}")]
    At(usize, String),
    #[error("cannot read '{0}': {1}")]
    Io(String, String),
    #[error("geometry parse error in '{0}': {1}")]
    Geo(String, String),
}

fn getf(tok: Option<&&str>, lineno: usize, what: &str) -> Result<f64, ListError> {
    tok.and_then(|s| s.parse::<f64>().ok())
        .ok_or_else(|| ListError::At(lineno, format!("expected number for {what}")))
}

/// Parse a list file at `path` into a dielectric [`Problem`]. Sub-file paths are
/// resolved relative to the list file's directory.
pub fn parse_file(path: &str) -> Result<Problem, ListError> {
    let text = std::fs::read_to_string(path).map_err(|e| ListError::Io(path.into(), e.to_string()))?;
    let base = Path::new(path).parent().map(PathBuf::from).unwrap_or_default();
    parse_str(&text, &base)
}

/// Parse list-file text; `base_dir` resolves relative sub-file paths.
pub fn parse_str(text: &str, base_dir: &Path) -> Result<Problem, ListError> {
    let mut problem = Problem::default();
    // Map original (file-local) conductor number -> global conductor index.
    let mut cond_map: std::collections::BTreeMap<(usize, i64), usize> = std::collections::BTreeMap::new();
    let mut file_counter = 0usize;

    for (lineno0, raw) in text.lines().enumerate() {
        let lineno = lineno0 + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('*') || line.starts_with('%') {
            continue;
        }
        let tok: Vec<&str> = line.split_whitespace().collect();
        let kind = tok[0];
        match kind {
            "C" | "c" => {
                let file = tok.get(1).ok_or_else(|| ListError::At(lineno, "C: missing file".into()))?;
                let outer = getf(tok.get(2), lineno, "outer permittivity")?;
                let tr = Vec3::new(
                    getf(tok.get(3), lineno, "xtrans")?,
                    getf(tok.get(4), lineno, "ytrans")?,
                    getf(tok.get(5), lineno, "ztrans")?,
                );
                let geo = load_geo(base_dir, file, lineno)?;
                file_counter += 1;
                for panel in geo.panels {
                    let local = panel.conductor as i64;
                    let gid = *cond_map.entry((file_counter, local)).or_insert_with(|| {
                        let id = problem.conductor_names.len();
                        problem.conductor_names.push(format!("{file}:{local}"));
                        id
                    });
                    let verts = panel.vertices.iter().map(|v| *v + tr).collect();
                    problem.panels.push(crate::integrals::panel::Panel::new(verts, gid));
                    problem.roles.push(PanelRole::Conductor { id: gid, eps_surrounding: outer });
                }
            }
            "D" | "d" => {
                let file = tok.get(1).ok_or_else(|| ListError::At(lineno, "D: missing file".into()))?;
                let outer = getf(tok.get(2), lineno, "outer permittivity")?;
                let inner = getf(tok.get(3), lineno, "inner permittivity")?;
                let reference = Vec3::new(
                    getf(tok.get(4), lineno, "xref")?,
                    getf(tok.get(5), lineno, "yref")?,
                    getf(tok.get(6), lineno, "zref")?,
                );
                let tr = Vec3::new(
                    getf(tok.get(7), lineno, "xtrans")?,
                    getf(tok.get(8), lineno, "ytrans")?,
                    getf(tok.get(9), lineno, "ztrans")?,
                );
                let geo = load_geo(base_dir, file, lineno)?;
                for panel in geo.panels {
                    let verts = panel.vertices.iter().map(|v| *v + tr).collect();
                    problem.panels.push(crate::integrals::panel::Panel::new(verts, 0));
                    problem.roles.push(PanelRole::Dielectric {
                        eps_out: outer,
                        eps_in: inner,
                        reference: reference + tr,
                    });
                }
            }
            _ => return Err(ListError::At(lineno, format!("unrecognized list line: {line}"))),
        }
    }
    Ok(problem)
}

fn load_geo(base_dir: &Path, file: &str, lineno: usize) -> Result<crate::cap::geometry::Geometry, ListError> {
    let path = base_dir.join(file);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| ListError::Io(path.display().to_string(), e.to_string()))?;
    parse_qui(&text, 1.0).map_err(|e| ListError::Geo(file.into(), format!("{e} (line {lineno} of list)")))
}
