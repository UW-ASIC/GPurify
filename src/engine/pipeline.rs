//! The shared stages: load, then extract.
//!
//! Data in: [`Inputs`] (paths). Data out: [`Loaded`] (everything read from disk,
//! in one string table, on the grid the layout's `UNITS` record states) and
//! [`Extracted`] (nets, devices, ports).

use gpurify_check::topology::{DeviceTable, Extraction, NetTable, PortTable};
use gpurify_geom::{GeometryStore, Grid};
use gpurify_ingest::layout::UnknownLayers;
use gpurify_ingest::netlist::Netlist;
use gpurify_ingest::{Deck, DesignIntent, Provenance, StrTable};
use std::path::PathBuf;

/// What a run was asked to work on: files only. The grid is the layout's own
/// (its `UNITS` record), and geometry on a stream pair the deck neither declares
/// nor ignores refuses the layout.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    /// The GDSII layout. Its `UNITS` record sets the grid of the whole run.
    pub layout: PathBuf,
    /// The process deck, see
    /// [deck.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md).
    pub deck: PathBuf,
    /// The reference netlist, SPICE or Spectre. Absent means LVS is skipped.
    pub reference: Option<PathBuf>,
    /// The design-intent JSON. Absent means the intent-gated ERC rules are skipped.
    pub intent: Option<PathBuf>,
}

/// Everything read from disk. One [`StrTable`], so a name from the layout and the
/// same name from the reference netlist are one `StrId`.
#[derive(Debug)]
pub struct Loaded {
    /// Every name the run knows: layout first, then the deck, the reference,
    /// the intent and the LVS report ids, so the same inputs give the same ids.
    pub strings: StrTable,
    /// The layout's database unit. Every deck length was converted onto it
    /// exactly, or the deck was refused.
    pub grid: Grid,
    /// The parsed deck: layers, rules, connectivity, devices and the
    /// parasitic stack.
    pub deck: Deck,
    /// The flattened layout geometry, on the deck's layer ids.
    pub store: GeometryStore,
    /// The layout's text labels, placed and bound to the polygons they name.
    pub provenance: Provenance,
    /// The reference netlist; `Some` exactly when [`Inputs::reference`] is.
    pub reference: Option<Netlist>,
    /// The design intent; `Some` exactly when [`Inputs::intent`] is.
    pub intent: Option<DesignIntent>,
}

/// Everything derived from what was loaded, shared read-only by all four checks.
#[derive(Debug, Default)]
pub struct Extracted {
    /// Nets traced through the deck's conductors and vias.
    pub nets: NetTable,
    /// Devices recognised from the deck's marker layers, with terminals on `nets`.
    pub devices: DeviceTable,
    /// Net names from text labels. A name on several disconnected nets
    /// resolves to the lowest of them through [`PortTable::net_of`].
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

/// Reads every input.
///
/// The layout's grid is read before the deck is parsed, because every deck
/// length is converted onto it. The reference netlist's dialect is chosen by
/// its first subcircuit opener (`subckt` for Spectre, `.subckt` for SPICE),
/// and by the extension `.scs` or `.spectre` only when it has none.
///
/// # Errors
///
/// - [`LoadError::Deck`]: the deck cannot be read or parsed, or a limit is
///   not a whole number of the layout's database units.
/// - [`LoadError::Layout`]: the layout cannot be read or parsed, has no
///   usable `UNITS` record, or has a shape on a stream pair the deck neither
///   declares nor ignores.
/// - [`LoadError::Label`]: a label the deck claims lands on no shape.
/// - [`LoadError::Netlist`], [`LoadError::Intent`]: the reference or intent
///   file cannot be read or parsed.
pub fn load(inputs: &Inputs) -> Result<Loaded, LoadError> {
    let source = std::fs::read_to_string(&inputs.deck).map_err(|why| {
        gpurify_ingest::DeckError::Io(format!("{}: {why}", inputs.deck.display()))
    })?;
    let bytes = gpurify_ingest::layout::read_gds_bytes(&inputs.layout)?;

    // Layout strings are interned before the deck's, which fixes every StrId.
    let mut strings = StrTable::default();
    let library = gpurify_ingest::layout::gds::Library::parse(&bytes, &mut strings)?;
    // The deck's lengths are converted on the layout's grid, so the layout states it.
    let grid = library.grid()?;
    let deck = gpurify_ingest::deck::parse_deck(&source, grid, &mut strings)
        .map_err(|why| why.in_file(&inputs.deck.display().to_string()))?;
    let (store, mut provenance) = library.flatten(&deck, &strings, UnknownLayers::Reject)?;
    provenance.resolve_labels(&store, &deck.connectivity)?;

    let reference = match &inputs.reference {
        None => None,
        Some(path) => {
            let netlist = read_reference(path, &deck.devices, &mut strings)?;
            // LVS compares leaf devices, so a block the schematic places by
            // instance must be in the comparison: flatten below the top. With
            // no unique top, LVS reports that instead of guessing.
            Some(match netlist.top() {
                Some(top) => netlist.flatten_top(top, &mut strings)?,
                None => netlist,
            })
        }
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
///
/// [`load`] calls it. A caller that builds a [`Loaded`] another way must
/// call it before [`run_checks`](crate::engine::run::run_checks).
pub fn intern_report_ids(strings: &mut StrTable) {
    gpurify_check::lvs::intern_rule_ids(strings);
}

/// Read a reference netlist. The first subcircuit opener picks the dialect
/// (`subckt` Spectre, `.subckt` SPICE); the extension decides only without one.
fn read_reference(
    path: &std::path::Path,
    devices: &gpurify_ingest::deck::DeviceRecognition,
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
        gpurify_ingest::netlist::spice::read(&source, strings, devices)
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
///
/// # Errors
///
/// - [`ExtractError::Channel`]: a transistor's channel marker overlaps
///   conductor on its source/drain layer, which would fuse source and drain
///   into one net, or one of those layers fails geometry validation.
/// - [`ExtractError::Port`]: one net carries two different labels (a short
///   between two named nets), or a label sits on a shape that is on no net.
///   The run stops with no report row for either.
pub fn extract(loaded: &Loaded) -> Result<Extracted, ExtractError> {
    let mut out = Extracted::default();

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
        &out.nets,
        &loaded.deck.devices,
        &mut out.devices,
    );
    gpurify_check::topology::port::bind_ports_into(&out.nets, &loaded.provenance, &mut out.ports)?;
    Ok(out)
}

/// Why [`load`] read nothing usable. Each wraps its reader's error unchanged.
#[derive(Debug, Clone, thiserror::Error)]
pub enum LoadError {
    /// The GDSII layout: unreadable, malformed, no usable `UNITS`, or a shape
    /// on an undeclared layer.
    #[error(transparent)]
    Layout(#[from] gpurify_ingest::layout::LayoutError),
    /// The deck: unreadable, malformed, or a length off the layout's grid.
    #[error(transparent)]
    Deck(#[from] gpurify_ingest::DeckError),
    /// The design-intent file.
    #[error(transparent)]
    Intent(#[from] gpurify_ingest::IntentError),
    /// The reference netlist.
    #[error(transparent)]
    Netlist(#[from] gpurify_ingest::netlist::NetlistError),
    /// A label the deck claims that lands on no shape.
    #[error(transparent)]
    Label(#[from] gpurify_ingest::LabelError),
}

/// Why [`extract`] refused the layout.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExtractError {
    /// Labels could not be bound to nets: two names on one net, or a label
    /// on no net.
    #[error(transparent)]
    Port(#[from] gpurify_check::topology::port::PortError),
    /// A transistor channel marker over live conductor, or geometry that
    /// could not be checked for one.
    #[error(transparent)]
    Channel(#[from] gpurify_check::topology::ChannelError),
}
