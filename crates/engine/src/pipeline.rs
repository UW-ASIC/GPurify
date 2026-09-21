//! The shared stages: load, then extract. Everything the four checks read.

use gpurify_core::GeometryStore;
use gpurify_derived::Evaluator;
use gpurify_ingest::layout::UnknownLayers;
use gpurify_ingest::netlist::Netlist;
use gpurify_ingest::{Deck, DesignIntent, Provenance, StrTable};
use gpurify_topology::{DeviceTable, Extraction, NetTable, PortTable};
use gpurify_units::Grid;
use std::path::PathBuf;

/// What a run was asked to work on: paths, plus the grid they are read against.
#[derive(Debug, Clone)]
pub struct Inputs {
    pub layout: PathBuf,
    pub deck: PathBuf,
    /// The grid every length in this run is expressed against. Absent is
    /// [`LoadError::NoGrid`] — defaulting one silently reinterprets every
    /// limit in the deck.
    pub grid: Option<Grid>,
    /// Reference netlist. Absent means LVS is skipped.
    pub reference: Option<PathBuf>,
    /// Design intent. Absent means the intent-dependent ERC rules are skipped
    /// and say so — never that they passed.
    pub intent: Option<PathBuf>,
    /// What to do with geometry on a layer the deck does not describe.
    pub unknown_layers: UnknownLayers,
}

/// Hand-written for one field: `unknown_layers` must default to
/// [`UnknownLayers::Reject`], where a derive would take whichever variant
/// `ingest` declares first and may silently drop undescribed geometry.
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

/// Everything read from disk.
///
/// One [`StrTable`] for the whole run, so a net name from the layout and the
/// same name from the reference netlist are one `StrId` and compare as integers.
#[derive(Debug, Default)]
pub struct Loaded {
    pub strings: StrTable,
    /// The grid everything here was read against. `Some` after any successful
    /// [`load_into`]; `None` only on a `Loaded` that has not been filled.
    pub grid: Option<Grid>,
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
        // A port names a net of *this* extraction, so tables assembled from
        // two runs are caught here and not inside a rule reading past the end.
        debug_assert!(
            self.ports.len() <= self.nets.net_count(),
            "the port table names more nets than this extraction produced"
        );
        Extraction {
            nets: &self.nets,
            devices: &self.devices,
            ports: &self.ports,
        }
    }
}

/// Read every input into `out`.
///
/// Ordered, observably: the grid is established before either file is opened, so
/// a run without one is [`LoadError::NoGrid`] rather than a path error, and the
/// deck is read first because layer mapping happens during the layout read.
pub fn load_into(inputs: &Inputs, out: &mut Loaded) -> Result<(), LoadError> {
    // A failed load must not leave the previous run's grid behind for a caller
    // that read the error and kept the buffer; set again only on the way out.
    out.grid = None;

    let grid = inputs.grid.ok_or(LoadError::NoGrid)?;

    let source = std::fs::read_to_string(&inputs.deck).map_err(|why| {
        // A run opens four files and "No such file or directory" names none.
        gpurify_ingest::DeckError::Io(format!("{}: {why}", inputs.deck.display()))
    })?;

    // Parsed twice, into two string tables: `read_layout` owns the table it
    // interns into, so the run's one id space can only be the layout's and this
    // first parse exists only to map layers during the read. Safe to do twice
    // because `LayerId`s are assigned by sorted layer *name bytes*
    // (`ingest::deck::build_layers`), not by the order a parse interned in.
    let staging = gpurify_ingest::deck::parse_deck(&source, grid, &mut StrTable::default())?;
    let layout =
        gpurify_ingest::layout::read_layout(&inputs.layout, &staging, inputs.unknown_layers)?;

    out.strings = layout.strings;
    out.deck = gpurify_ingest::deck::parse_deck(&source, grid, &mut out.strings)?;
    out.store = layout.store;
    out.provenance = layout.provenance;
    debug_assert_eq!(
        out.deck.layers.len(),
        staging.layers.len(),
        "two parses of one deck disagree on the layer table the layout was mapped against"
    );

    // Not inside `read_layout`: a label's point is in the root frame only after
    // flattening and its `PolyId` is a store row only after
    // `GeometryStoreBuilder::finish` sorted by layer. Before `bind_ports_into`.
    out.provenance
        .resolve_labels(&out.store, &out.deck.connectivity)?;

    // Both optional readers intern into the same table, after it became the
    // layout's: that is what makes one name from either side one `StrId`.
    out.reference = match &inputs.reference {
        None => None,
        Some(path) => Some(read_reference(path, &mut out.strings)?),
    };
    out.intent = match &inputs.intent {
        None => None,
        Some(path) => Some(gpurify_ingest::intent::read_intent(path, &mut out.strings)?),
    };

    // The one-table invariant: every label names a polygon this store holds and
    // a name this table can resolve.
    let polys = out.store.poly_count();
    let names = out.strings.len();
    debug_assert!(
        {
            let labels = out.provenance.labels();
            let mut ok = true;
            for &(poly, name) in labels {
                ok &= ((poly.0 as usize) < polys) & ((name.0 as usize) < names);
            }
            ok
        },
        "a label names a polygon or a string outside the run's tables"
    );

    intern_report_ids(&mut out.strings);

    out.grid = Some(grid);
    Ok(())
}

/// Intern every LVS report rule id into `strings`.
///
/// Interned before checking because `run_checks` borrows `Loaded` shared and
/// cannot; an unresolvable `StrId` is a panic in the report. Public and apart
/// from [`load_into`] because an embedder building a [`Loaded`] by hand (every
/// field is `pub`) never runs the loader, and would otherwise reach that panic
/// on its first LVS finding.
pub fn intern_report_ids(strings: &mut StrTable) {
    for id in crate::run::LVS_RULE_IDS
        .iter()
        .chain(crate::run::LVS_CHECK_RULE_IDS.iter())
    {
        strings.intern(id);
    }
    debug_assert!(
        crate::run::LVS_RULE_IDS
            .iter()
            .chain(crate::run::LVS_CHECK_RULE_IDS.iter())
            .all(|id| strings.get(id).is_some()),
        "an lvs rule id did not survive interning, so a finding has no name to be reported under"
    );
}

/// Read a reference netlist, picking the dialect from the file's own text.
///
/// Exact rather than heuristic: every netlist either reader accepts declares a
/// subcircuit, and the dialects spell the opener differently. The extension
/// decides only when neither opener appears.
fn read_reference(
    path: &std::path::Path,
    strings: &mut StrTable,
) -> Result<Netlist, gpurify_ingest::netlist::NetlistError> {
    let source = std::fs::read_to_string(path).map_err(|why| {
        gpurify_ingest::netlist::NetlistError::Io(format!("{}: {why}", path.display()))
    })?;
    let declared = spectre_by_opener(&source);
    let spectre = declared.unwrap_or_else(|| {
        matches!(
            path.extension().and_then(std::ffi::OsStr::to_str),
            Some("scs" | "spectre")
        )
    });

    let netlist = if spectre {
        gpurify_ingest::netlist::spectre::read(&source, strings)?
    } else {
        gpurify_ingest::netlist::spice::read(&source, strings)?
    };
    // The opener this read was chosen by is a subcircuit the reader must have
    // produced a row for.
    debug_assert!(
        declared.is_none() || netlist.subckt_count() > 0,
        "the text declared a subcircuit opener and the netlist read from it has no subcircuits"
    );
    Ok(netlist)
}

/// Is this netlist Spectre? `None` when its text does not say.
///
/// Decided by the first subcircuit opener: `subckt` is Spectre, `.subckt` is
/// SPICE. Case follows each reader's rule — SPICE ignores it, Spectre does not.
fn spectre_by_opener(source: &str) -> Option<bool> {
    source.lines().find_map(|raw| {
        let line = raw.trim_start();
        // Both dialects' comment leaders, before the token: reading `* subckt`
        // as an opener picks the dialect out of a sentence a human wrote.
        if line.starts_with('*') || line.starts_with("//") {
            return None;
        }
        // Parens separate in Spectre; harmless for SPICE, where no card begins
        // `.subckt(`.
        let head = line
            .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
            .find(|token| !token.is_empty())?;
        match head {
            "subckt" => Some(true),
            _ => head.eq_ignore_ascii_case(".subckt").then_some(false),
        }
    })
}

/// Evaluate derived layers, extract nets, recognise devices, bind ports.
///
/// Strictly ordered: devices are recognised on derived layers, and terminals are
/// bound to nets, so neither stage can move.
pub fn extract_into(loaded: &Loaded, out: &mut Extracted) -> Result<(), ExtractError> {
    debug_assert_eq!(
        loaded.deck.connectivity.via_cut.len(),
        loaded.deck.connectivity.via_connects.len(),
        "a via layer is a cut and the two layers it joins, in step"
    );

    // Whatever the caller planned into `out.derived` — `Deck` carries no named
    // derived expressions, so nothing here can plan it.
    out.derived.evaluate(&loaded.store)?;

    // Before nets exist: a MOS channel marker over live conductor area means
    // extraction would fuse source and drain into one net and report the short
    // as clean, so that deck-and-layout configuration is refused instead.
    gpurify_topology::device::refuse_conducting_channels(
        &loaded.store,
        &loaded.deck.connectivity,
        &loaded.deck.devices,
    )?;

    // Each of the three clears the table it fills, so a reused `Extracted` is
    // refilled rather than appended to.
    gpurify_topology::net::extract_nets_into(
        &loaded.store,
        &loaded.deck.connectivity,
        &mut out.nets,
    );
    debug_assert!(
        out.nets.net_count() <= loaded.store.poly_count(),
        "more nets than there are polygons to put in them"
    );

    gpurify_topology::device::recognise_into(
        &loaded.store,
        &out.derived,
        &out.nets,
        &loaded.deck.devices,
        &mut out.devices,
    );
    debug_assert!(
        out.devices.len() <= loaded.store.poly_count(),
        "a device is recognised on a marker polygon, so there cannot be more of them than polygons"
    );

    gpurify_topology::port::bind_ports_into(&out.nets, &loaded.provenance, &mut out.ports)?;
    debug_assert!(
        out.ports.len() <= loaded.provenance.labels().len(),
        "ports are deduplicated labels, so there cannot be more of them than labels"
    );
    Ok(())
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
    /// A net label the deck claims could not be placed on any shape.
    #[error(transparent)]
    Label(#[from] gpurify_ingest::LabelError),
    /// No grid was supplied, so no length in the deck has a meaning.
    ///
    /// Fail closed rather than defaulting: a guessed `dbu_per_um` reinterprets
    /// every limit in the deck.
    #[error("no grid resolution: Inputs::grid is absent and nothing else establishes one")]
    NoGrid,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ExtractError {
    #[error(transparent)]
    Derived(#[from] gpurify_derived::DerivedError),
    #[error(transparent)]
    Port(#[from] gpurify_topology::port::PortError),
    /// A MOS channel marker overlaps conductor area on its source/drain layer,
    /// so extraction would report source and drain as one net.
    #[error(transparent)]
    Channel(#[from] gpurify_topology::ChannelError),
}
