//! One SREF/AREF step in a root-to-shape hierarchy path.

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstancePathEntry {
    pub parent_structure: String,
    pub element_index: u32,
    pub referenced_structure: String,
    pub column: u16,
    pub row: u16,
}

impl InstancePathEntry {
    /// Canonical string representation for debug/result provenance.
    #[must_use]
    pub fn canonical_string(&self) -> String {
        if self.column == 0 && self.row == 0 {
            format!(
                "{}[{}]/{}",
                self.parent_structure, self.element_index, self.referenced_structure
            )
        } else {
            format!(
                "{}[{}]/{}<{},{}>",
                self.parent_structure,
                self.element_index,
                self.referenced_structure,
                self.column,
                self.row
            )
        }
    }
}

/// Format a full instance path as a canonical string.
#[must_use]
pub fn path_to_string(path: &[InstancePathEntry]) -> String {
    if path.is_empty() {
        return String::from("<top>");
    }
    path.iter()
        .map(|e| e.canonical_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// Depth of an instance path (number of hierarchy levels).
#[must_use]
pub fn path_depth(path: &[InstancePathEntry]) -> usize {
    path.len()
}
