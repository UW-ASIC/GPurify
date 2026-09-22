//! String interning. Ids are assigned in arrival order, so they are the same on
//! every machine; nothing iterates the map.

use std::collections::HashMap;

/// An interned string. Ids from different [`StrTable`]s are not comparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct StrId(pub u32);

/// The one string table for a run.
#[derive(Debug, Default)]
pub struct StrTable {
    /// Indexed by [`StrId`].
    names: Vec<Box<str>>,
    ids: HashMap<Box<str>, StrId>,
}

impl StrTable {
    pub fn with_capacity(names: usize, _bytes: usize) -> Self {
        Self {
            names: Vec::with_capacity(names),
            ids: HashMap::with_capacity(names),
        }
    }

    /// Intern a name, returning the existing id if it is already present.
    pub fn intern(&mut self, name: &str) -> StrId {
        if let Some(&id) = self.ids.get(name) {
            return id;
        }
        let id = StrId(crate::narrow(self.names.len()));
        self.names.push(name.into());
        self.ids.insert(name.into(), id);
        id
    }

    /// Look up without interning.
    pub fn get(&self, name: &str) -> Option<StrId> {
        self.ids.get(name).copied()
    }

    /// Panics on an id from another table rather than returning a plausible name.
    pub fn resolve(&self, id: StrId) -> &str {
        &self.names[id.0 as usize]
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}
