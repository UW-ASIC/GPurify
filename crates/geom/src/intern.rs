//! String interning. Ids are assigned in arrival order, so they are the same on
//! every machine; nothing iterates the map.

use std::collections::HashMap;

/// An interned string. Ids from different [`StrTable`]s are not comparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct StrId(pub u32);

/// The one string table for a run: cell, net, layer, model and rule names.
///
/// Ids follow interning order, so a caller that interns in a fixed order gets
/// the same [`StrId`]s on every machine.
#[derive(Debug, Default)]
pub struct StrTable {
    /// Indexed by [`StrId`].
    names: Vec<Box<str>>,
    ids: HashMap<Box<str>, StrId>,
}

impl StrTable {
    /// Interns a name, returning the existing id if it is already present.
    /// A new id is the next integer, so interning order fixes every id.
    pub fn intern(&mut self, name: &str) -> StrId {
        if let Some(&id) = self.ids.get(name) {
            return id;
        }
        let id = StrId(crate::narrow(self.names.len()));
        self.names.push(name.into());
        self.ids.insert(name.into(), id);
        id
    }

    /// Looks a name up without interning it; `None` if it was never interned.
    pub fn get(&self, name: &str) -> Option<StrId> {
        self.ids.get(name).copied()
    }

    /// Returns the string an id was interned from.
    ///
    /// # Panics
    ///
    /// On an id past [`Self::len`], as from another table, rather than
    /// returning a plausible name.
    pub fn resolve(&self, id: StrId) -> &str {
        &self.names[id.0 as usize]
    }

    /// Returns how many distinct strings are interned; ids run `0..len`.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Returns whether nothing has been interned.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}
