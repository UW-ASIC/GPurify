//! The shared stages: load, then extract. Everything the four checks read.

use gpurify_core::GeometryStore;
use gpurify_derived::Evaluator;
use gpurify_ingest::netlist::Netlist;
use gpurify_ingest::{Deck, DesignIntent, Provenance, StrTable};
use gpurify_topology::{DeviceTable, Extraction, NetTable, PortTable};
use gpurify_units::Grid;
use std::path::PathBuf;

/// What a run was asked to work on.
///
/// Paths, not opened files, so a caller can be told what a run will read before
/// it reads anything. `reference` and `intent` are optional and their absence
/// is meaningful: it disables specific checks, loudly.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    pub layout: PathBuf,
    pub deck: PathBuf,
    /// Reference netlist. Absent means LVS is skipped.
    pub reference: Option<PathBuf>,
    /// Design intent. Absent means the intent-dependent ERC rules are skipped
    /// and say so — never that they passed.
    pub intent: Option<PathBuf>,
}

/// Everything read from disk.
///
/// One [`StrTable`] for the whole run, so a net name from the layout and the
/// same name from the reference netlist are the same `StrId` and compare as an
/// integer. Two tables would mean string comparison at the one place it matters
/// most.
#[derive(Debug, Default)]
pub struct Loaded {
    pub strings: StrTable,
    pub grid: Option<Grid>,
    pub deck: Deck,
    pub store: GeometryStore,
    pub provenance: Provenance,
    pub reference: Option<Netlist>,
    pub intent: Option<DesignIntent>,
}

/// Everything derived from what was loaded.
///
/// Built once and shared read-only by all four checks. Owned here rather than
/// by each check, which is what lets them run concurrently without any of them
/// holding a mutable borrow.
#[derive(Debug, Default)]
pub struct Extracted {
    pub derived: Evaluator,
    pub nets: NetTable,
    pub devices: DeviceTable,
    pub ports: PortTable,
}

impl Extracted {
    /// Borrow the three topology tables together.
    pub fn as_extraction(&self) -> Extraction<'_> {
        todo!()
    }
}

/// Read every input.
///
/// **Transform, generative.** Caller owns `out`, so a caller running several
/// layouts against one deck reuses the allocation.
///
/// Order matters and is not incidental: the deck's grid must be established
/// before rule limits can be converted, and before the layout can be read,
/// because layer mapping happens during the read rather than after it.
pub fn load_into(inputs: &Inputs, out: &mut Loaded) -> Result<(), LoadError> {
    todo!()
}

/// Evaluate derived layers, extract nets, recognise devices, bind ports.
///
/// **Transform.** Caller owns `out`. Strictly ordered — devices are recognised
/// on derived layers, and terminals are bound to nets, so neither stage can
/// move.
pub fn extract_into(loaded: &Loaded, out: &mut Extracted) -> Result<(), ExtractError> {
    todo!()
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum LoadError {
    #[error(transparent)]
    Layout(#[from] gpurify_ingest::layout::LayoutError),
    #[error(transparent)]
    Deck(#[from] gpurify_ingest::DeckError),
    #[error(transparent)]
    Intent(#[from] gpurify_ingest::IntentError),
    #[error(transparent)]
    Netlist(#[from] gpurify_ingest::netlist::NetlistError),
    #[error("deck declares no grid resolution")]
    NoGrid,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ExtractError {
    #[error(transparent)]
    Derived(#[from] gpurify_derived::DerivedError),
    #[error(transparent)]
    Port(#[from] gpurify_topology::port::PortError),
}
