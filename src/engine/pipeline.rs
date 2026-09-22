//! The shared stages: load, then extract.
//!
//! Data in: [`Inputs`] (paths plus the grid). Data out: [`Loaded`] (everything read
//! from disk, in one string table) and [`Extracted`] (nets, devices, ports).

use gpurify_check::topology::{DeviceTable, Extraction, NetTable, PortTable};
use gpurify_geom::{Evaluator, GeometryStore, Grid};
use gpurify_ingest::layout::UnknownLayers;
use gpurify_ingest::netlist::Netlist;
use gpurify_ingest::{Deck, DesignIntent, Provenance, StrTable};
use std::path::PathBuf;

/// What a run was asked to work on.
#[derive(Debug, Clone)]
pub struct Inputs {
    pub layout: PathBuf,
    pub deck: PathBuf,
    /// Absent is [`LoadError::NoGrid`]: a guessed grid reinterprets every deck limit.
    pub grid: Option<Grid>,
    /// Absent means LVS is skipped.
    pub reference: Option<PathBuf>,
    /// Absent means the intent-gated ERC rules are skipped.
    pub intent: Option<PathBuf>,
    pub unknown_layers: UnknownLayers,
}

/// Hand-written so `unknown_layers` defaults to `Reject`, the fail-closed choice.
impl Default for Inputs {
    fn default() -> Self {
        Self {
            layout: PathBuf::new(),
            deck: PathBuf::new(),
            grid: None,
            reference: None,
            intent: None,
            unknown_layers: UnknownLayers::Reject,
        }
    }
}

/// Everything read from disk. One [`StrTable`], so a name from the layout and the
/// same name from the reference netlist are one `StrId`.
#[derive(Debug)]
pub struct Loaded {
    pub strings: StrTable,
    pub grid: Grid,
    pub deck: Deck,
    pub store: GeometryStore,
    pub provenance: Provenance,
    pub reference: Option<Netlist>,
    pub intent: Option<DesignIntent>,
}

/// Everything derived from what was loaded, shared read-only by all four checks.
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
        Extraction {
            nets: &self.nets,
            devices: &self.devices,
            ports: &self.ports,
        }
    }
}

/// Read every input. The grid is checked before any file is opened, and the deck
/// is read before the layout because layers are mapped during the layout read.
pub fn load(inputs: &Inputs) -> Result<Loaded, LoadError> {
    let grid = inputs.grid.ok_or(LoadError::NoGrid)?;

    let source = std::fs::read_to_string(&inputs.deck).map_err(|why| {
        gpurify_ingest::DeckError::Io(format!("{}: {why}", inputs.deck.display()))
    })?;

    // Parsed twice: `read_layout` owns the table it interns into, so the first
    // parse only maps layers. `LayerId`s come from sorted names, so both agree.
    let staging = gpurify_ingest::deck::parse_deck(&source, grid, &mut StrTable::default())?;
    let layout =
        gpurify_ingest::layout::read_layout(&inputs.layout, &staging, inputs.unknown_layers)?;

    let mut strings = layout.strings;
    let deck = gpurify_ingest::deck::parse_deck(&source, grid, &mut strings)?;
    let store = layout.store;
    let mut provenance = layout.provenance;
    provenance.resolve_labels(&store, &deck.connectivity)?;

    let reference = match &inputs.reference {
        None => None,
        Some(path) => Some(read_reference(path, &mut strings)?),
    };
    let intent = match &inputs.intent {
        None => None,
        Some(path) => Some(gpurify_ingest::intent::read_intent(path, &mut strings)?),
    };

    intern_report_ids(&mut strings);

    Ok(Loaded {
        strings,
        grid,
        deck,
        store,
        provenance,
        reference,
        intent,
    })
}

/// Intern every LVS report rule id, so `run_checks` (which borrows `Loaded`
/// shared) can find them.
pub fn intern_report_ids(strings: &mut StrTable) {
    for id in crate::engine::run::LVS_RULE_IDS
        .iter()
        .chain(crate::engine::run::LVS_CHECK_RULE_IDS.iter())
    {
        strings.intern(id);
    }
}

/// Read a reference netlist. The first subcircuit opener picks the dialect
/// (`subckt` Spectre, `.subckt` SPICE); the extension decides only without one.
fn read_reference(
    path: &std::path::Path,
    strings: &mut StrTable,
) -> Result<Netlist, gpurify_ingest::netlist::NetlistError> {
    let source = std::fs::read_to_string(path).map_err(|why| {
        gpurify_ingest::netlist::NetlistError::Io(format!("{}: {why}", path.display()))
    })?;
    let spectre = spectre_by_opener(&source).unwrap_or_else(|| {
        matches!(
            path.extension().and_then(std::ffi::OsStr::to_str),
            Some("scs" | "spectre")
        )
    });
    if spectre {
        gpurify_ingest::netlist::spectre::read(&source, strings)
    } else {
        gpurify_ingest::netlist::spice::read(&source, strings)
    }
}

/// Is this netlist Spectre? `None` when no subcircuit opener says.
fn spectre_by_opener(source: &str) -> Option<bool> {
    source.lines().find_map(|raw| {
        let line = raw.trim_start();
        if line.starts_with('*') || line.starts_with("//") {
            return None;
        }
        let head = line
            .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
            .find(|token| !token.is_empty())?;
        match head {
            "subckt" => Some(true),
            _ => head.eq_ignore_ascii_case(".subckt").then_some(false),
        }
    })
}

/// Extract nets, recognise devices, bind ports — in that order, since devices
/// read nets and ports bind to them.
pub fn extract(loaded: &Loaded) -> Result<Extracted, ExtractError> {
    let mut out = Extracted::default();
    out.derived.evaluate(&loaded.store)?;

    // A MOS channel marker over live conductor would fuse source and drain into
    // one net and report the short as clean, so it is refused before nets exist.
    gpurify_check::topology::device::refuse_conducting_channels(
        &loaded.store,
        &loaded.deck.connectivity,
        &loaded.deck.devices,
    )?;
    gpurify_check::topology::net::extract_nets_into(
        &loaded.store,
        &loaded.deck.connectivity,
        &mut out.nets,
    );
    gpurify_check::topology::device::recognise_into(
        &loaded.store,
        &out.derived,
        &out.nets,
        &loaded.deck.devices,
        &mut out.devices,
    );
    gpurify_check::topology::port::bind_ports_into(&out.nets, &loaded.provenance, &mut out.ports)?;
    Ok(out)
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
    #[error(transparent)]
    Label(#[from] gpurify_ingest::LabelError),
    #[error("no grid resolution: Inputs::grid is absent and nothing else establishes one")]
    NoGrid,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ExtractError {
    #[error(transparent)]
    Derived(#[from] gpurify_geom::DerivedError),
    #[error(transparent)]
    Port(#[from] gpurify_check::topology::port::PortError),
    #[error(transparent)]
    Channel(#[from] gpurify_check::topology::ChannelError),
}
