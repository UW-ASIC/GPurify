//! The shared stages: load, then extract.
//!
//! Data in: [`Inputs`] (paths). Data out: [`Loaded`] (everything read from disk,
//! in one string table, on the grid the layout's `UNITS` record states) and
//! [`Extracted`] (nets, devices, ports).

use gpurify_check::deck::{BuildError, CompileError, CompiledDeck, DeckFn};
use gpurify_check::topology::{DeviceTable, Extraction, NetTable, PortTable};
use gpurify_geom::{GeometryStore, Grid};
use gpurify_ingest::layout::UnknownLayers;
use gpurify_ingest::lefdef::{self, LefDefError};
use gpurify_ingest::netlist::Netlist;
use gpurify_ingest::{DesignIntent, Provenance, StrTable};
use std::path::{Path, PathBuf};

/// What a run was asked to work on: files only. The grid is the layout's own
/// (its `UNITS` record), and geometry on a stream pair the deck neither declares
/// nor ignores refuses the layout.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    /// The layout: GDSII, whose `UNITS` record sets the grid of the whole
    /// run, or a DEF (`*.def`), whose `UNITS DISTANCE MICRONS` does, drawn
    /// with [`Self::lef`] on the deck's layers of the LEF's layer names
    /// ([`gpurify_ingest::lefdef`]).
    pub layout: PathBuf,
    /// The LEF files a DEF layout reads, technology first; empty for GDSII.
    pub lef: Vec<PathBuf>,
    /// The process deck, see
    /// [deck.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md);
    /// or, for [`load_with`], the name of a deck the binary carries.
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
    /// The compiled deck: layers, connectivity, devices, the parasitic
    /// stack, and every rule typed.
    pub deck: CompiledDeck,
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
    /// Net names from text labels, bound as drawn: a name on several
    /// disconnected nets (an open) names every piece, and a net with several
    /// names (a short) carries them all. See [`PortTable`].
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
/// - [`LoadError::Deck`]: the deck cannot be read or compiled: it does not
///   parse, a limit is not a whole number of the layout's database units, or
///   a rule's values are not ones its kind can hold.
/// - [`LoadError::Layout`]: the layout cannot be read or parsed, has no
///   usable `UNITS` record, or has a shape on a stream pair the deck neither
///   declares nor ignores.
/// - [`LoadError::Label`]: a label the deck claims lands on no shape.
/// - [`LoadError::Netlist`], [`LoadError::Intent`]: the reference or intent
///   file cannot be read or parsed.
///
/// With more than one input at fault, one of their errors is reported; which
/// one is not part of this contract. Nothing orders an unreadable deck before
/// an unreadable layout, and a malformed deck is parsed only after the layout,
/// on its grid.
pub fn load(inputs: &Inputs) -> Result<Loaded, LoadError> {
    load_with(inputs, &[])
}

/// [`load`], with the decks a binary carries by name
/// ([`cli::main_with`](crate::cli::main_with)): when [`Inputs::deck`] is
/// one of the names, that deck is built on the layout's grid, at the point
/// [`load`] would compile the file, so its names take the same ids; any
/// other value is a deck file.
///
/// # Errors
///
/// As [`load`], and [`LoadError::Built`] when the named deck does not build.
pub fn load_with(inputs: &Inputs, decks: &[(&str, DeckFn)]) -> Result<Loaded, LoadError> {
    let builtin = decks
        .iter()
        .find(|(name, _)| inputs.deck.as_path() == std::path::Path::new(name))
        .map(|&(_, build)| build);
    let source = match builtin {
        Some(_) => String::new(),
        None => std::fs::read_to_string(&inputs.deck).map_err(|why| {
            CompileError::from(gpurify_ingest::DeckError::Io(format!(
                "{}: {why}",
                inputs.deck.display()
            )))
        })?,
    };
    let mut strings = StrTable::default();
    let compile = |grid, strings: &mut StrTable| -> Result<CompiledDeck, LoadError> {
        Ok(match builtin {
            Some(build) => build(grid, strings)?,
            None => gpurify_check::deck::compile(&source, grid, strings)
                .map_err(|why| why.in_file(&inputs.deck.display().to_string()))?,
        })
    };
    let (library, grid, deck) = if is_def(&inputs.layout) {
        // A DEF states its grid in its UNITS; its LEFs are read on it, and
        // the deck too, whose layers the design is then drawn on.
        let read = |path: &std::path::Path, file| {
            std::fs::read_to_string(path).map_err(|why| LefDefError {
                file,
                line: 0,
                message: format!("{}: {why}", path.display()),
            })
        };
        let text = read(&inputs.layout, "DEF")?;
        let dbu = lefdef::def_units(&text)?;
        let mut lef = lefdef::Lef::default();
        for path in &inputs.lef {
            lefdef::read_lef_into(&read(path, "LEF")?, dbu, &mut lef)
                .map_err(|why| in_file(why, path))?;
        }
        let def = lefdef::read_def(&text, &lef).map_err(|why| in_file(why, &inputs.layout))?;
        let grid = Grid::new(dbu).map_err(|_| LefDefError {
            file: "DEF",
            line: 0,
            message: format!("UNITS DISTANCE MICRONS {dbu} is not a grid"),
        })?;
        let deck = compile(grid, &mut strings)?;
        let flat = lefdef::flatten(&def, &lef)?;
        let bytes = lefdef::to_gds(
            &flat,
            dbu,
            &def.design,
            &deck.layers,
            &deck.connectivity,
            &strings,
        )?;
        let library = gpurify_ingest::layout::gds::Library::parse(&bytes, &mut strings)?;
        (library, grid, deck)
    } else {
        let bytes = gpurify_ingest::layout::read_gds_bytes(&inputs.layout)?;
        // Layout strings are interned before the deck's, which fixes every StrId.
        let library = gpurify_ingest::layout::gds::Library::parse(&bytes, &mut strings)?;
        // The deck's lengths are converted on the layout's grid, so the layout states it.
        let grid = library.grid()?;
        let deck = compile(grid, &mut strings)?;
        (library, grid, deck)
    };
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

/// One layout read with its deck: what [`load`] reads besides the reference
/// and the intent, and what a multi-die system ([`system`](crate::engine::system))
/// reads for each of its dies. Its names are in the string table it was read
/// into.
#[derive(Debug)]
pub struct Die {
    /// The layout's database unit; the deck's lengths are on it.
    pub grid: Grid,
    /// The compiled deck.
    pub deck: CompiledDeck,
    /// The flattened layout geometry, on the deck's layer ids.
    pub store: GeometryStore,
    /// The layout's text labels, placed and bound to the polygons they name.
    pub provenance: Provenance,
}

/// Reads one layout and its deck file into `strings`, as [`load`] does: the
/// deck file, then the layout's bytes, then [`read_die`].
///
/// # Errors
///
/// As [`load`], but for the reference and the intent.
pub fn load_die(layout: &Path, deck: &Path, strings: &mut StrTable) -> Result<Die, LoadError> {
    let source = std::fs::read_to_string(deck).map_err(|why| {
        CompileError::from(gpurify_ingest::DeckError::Io(format!(
            "{}: {why}",
            deck.display()
        )))
    })?;
    let bytes = gpurify_ingest::layout::read_gds_bytes(layout)?;
    read_die(&bytes, &source, &deck.display().to_string(), strings)
}

/// Reads one GDSII layout and the deck text `deck` (named `deck_file` in its
/// errors) into `strings`, as [`load`] does: the layout's names first, then
/// the deck's, so the same inputs give the same ids. The layout is flattened
/// through the deck and its labels bound to shapes.
///
/// # Errors
///
/// [`LoadError::Layout`], [`LoadError::Deck`] and [`LoadError::Label`], as
/// [`load`] documents them.
pub fn read_die(
    gds: &[u8],
    deck: &str,
    deck_file: &str,
    strings: &mut StrTable,
) -> Result<Die, LoadError> {
    let library = gpurify_ingest::layout::gds::Library::parse(gds, strings)?;
    let grid = library.grid()?;
    let deck =
        gpurify_check::deck::compile(deck, grid, strings).map_err(|why| why.in_file(deck_file))?;
    let (store, mut provenance) = library.flatten(&deck, strings, UnknownLayers::Reject)?;
    provenance.resolve_labels(&store, &deck.connectivity)?;
    Ok(Die {
        grid,
        deck,
        store,
        provenance,
    })
}

/// Is this layout a DEF (named `*.def`), read with [`Inputs::lef`]?
pub fn is_def(layout: &std::path::Path) -> bool {
    layout
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("def"))
}

/// The error with the file it is in named in its message.
fn in_file(mut why: LefDefError, path: &std::path::Path) -> LefDefError {
    why.message = format!("{}: {}", path.display(), why.message);
    why
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
pub(crate) fn read_reference(
    path: &std::path::Path,
    devices: &gpurify_ingest::deck::DeviceRecognition,
    strings: &mut StrTable,
) -> Result<Netlist, gpurify_ingest::netlist::NetlistError> {
    let source = std::fs::read_to_string(path).map_err(|why| {
        gpurify_ingest::netlist::NetlistError::Io(format!("{}: {why}", path.display()))
    })?;
    let spectre_by_name = matches!(
        path.extension().and_then(std::ffi::OsStr::to_str),
        Some("scs" | "spectre")
    );
    read_reference_text(&source, spectre_by_name, devices, strings)
}

/// Reads reference netlist text in the dialect its first subcircuit opener
/// names (`subckt` Spectre, `.subckt` SPICE), or Spectre when it has none and
/// `spectre_by_name` says the file was named so.
///
/// # Errors
///
/// The reader's [`NetlistError`](gpurify_ingest::netlist::NetlistError).
pub fn read_reference_text(
    source: &str,
    spectre_by_name: bool,
    devices: &gpurify_ingest::deck::DeviceRecognition,
    strings: &mut StrTable,
) -> Result<Netlist, gpurify_ingest::netlist::NetlistError> {
    if spectre_by_opener(source).unwrap_or(spectre_by_name) {
        gpurify_ingest::netlist::spectre::read(source, strings, devices)
    } else {
        gpurify_ingest::netlist::spice::read(source, strings, devices)
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
/// - [`ExtractError::Port`]: a label sits on a shape that is on no net. The
///   run stops with no report row. A short between two labelled nets is not
///   an error here: LVS reports it as `lvs.net_seed_conflict`.
pub fn extract(loaded: &Loaded) -> Result<Extracted, ExtractError> {
    extract_layout(&loaded.store, &loaded.deck, &loaded.provenance)
}

/// [`extract`] on a layout's parts: a [`Die`]'s, or a [`Loaded`]'s.
///
/// # Errors
///
/// As [`extract`].
pub fn extract_layout(
    store: &GeometryStore,
    deck: &CompiledDeck,
    provenance: &Provenance,
) -> Result<Extracted, ExtractError> {
    let mut out = Extracted::default();

    // A MOS channel marker over live conductor would fuse source and drain into
    // one net and report the short as clean, so it is refused before nets exist.
    gpurify_check::topology::device::refuse_conducting_channels(
        store,
        &deck.connectivity,
        &deck.devices,
    )?;
    gpurify_check::topology::net::extract_nets_into(store, &deck.connectivity, &mut out.nets);
    gpurify_check::topology::device::recognise_into(
        store,
        &out.nets,
        &deck.devices,
        &mut out.devices,
    );
    gpurify_check::topology::port::bind_ports_into(&out.nets, provenance, &mut out.ports)?;
    Ok(out)
}

/// Why [`load`] read nothing usable. Each wraps its reader's error unchanged.
#[derive(Debug, Clone, thiserror::Error)]
pub enum LoadError {
    /// The GDSII layout: unreadable, malformed, no usable `UNITS`, or a shape
    /// on an undeclared layer.
    #[error(transparent)]
    Layout(#[from] gpurify_ingest::layout::LayoutError),
    /// The deck: unreadable, malformed, a length off the layout's grid, or
    /// a rule its kind cannot hold.
    #[error(transparent)]
    Deck(#[from] CompileError),
    /// The design-intent file.
    #[error(transparent)]
    Intent(#[from] gpurify_ingest::IntentError),
    /// The reference netlist.
    #[error(transparent)]
    Netlist(#[from] gpurify_ingest::netlist::NetlistError),
    /// A label the deck claims that lands on no shape.
    #[error(transparent)]
    Label(#[from] gpurify_ingest::LabelError),
    /// A deck the binary carries by name did not build.
    #[error(transparent)]
    Built(#[from] BuildError),
    /// A DEF layout or one of its LEFs: unreadable, malformed, or a
    /// design that cannot be drawn on the deck's layers.
    #[error(transparent)]
    LefDef(#[from] LefDefError),
}

/// Why [`extract`] refused the layout.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExtractError {
    /// A label could not be bound: it sits on no net.
    #[error(transparent)]
    Port(#[from] gpurify_check::topology::port::PortError),
    /// A transistor channel marker over live conductor, or geometry that
    /// could not be checked for one.
    #[error(transparent)]
    Channel(#[from] gpurify_check::topology::ChannelError),
}
