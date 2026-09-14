//! The shared stages: load, then extract. Everything the four checks read.

use gpurify_core::GeometryStore;
use gpurify_derived::Evaluator;
use gpurify_ingest::layout::UnknownLayers;
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
#[derive(Debug, Clone)]
pub struct Inputs {
    pub layout: PathBuf,
    pub deck: PathBuf,
    /// The grid every length in this run is expressed against.
    ///
    /// Reopened in the Testing-Phase. It is drawn as a pipeline input in this
    /// crate's module diagram and it has to be: [`gpurify_ingest::deck::read_deck`]
    /// takes a [`Grid`] by value, and no `ingest` interface yields one before a
    /// [`Deck`] exists, so nothing downstream can establish it. Absent is
    /// [`LoadError::NoGrid`] — the variant had no observable condition until
    /// this field carried it, and defaulting a grid silently reinterprets
    /// every limit in the deck.
    pub grid: Option<Grid>,
    /// Reference netlist. Absent means LVS is skipped.
    pub reference: Option<PathBuf>,
    /// Design intent. Absent means the intent-dependent ERC rules are skipped
    /// and say so — never that they passed.
    pub intent: Option<PathBuf>,
    /// What to do with geometry on a layer the deck does not describe.
    ///
    /// Reopened in the Testing-Phase: the CLI's `--strict-layers` parsed to a
    /// flag with nowhere to land, which is the fail-open shape the flag exists
    /// to prevent one layer up. This is a load-time decision, so it lives here
    /// rather than on [`crate::run::RunOptions`], and it is
    /// [`UnknownLayers`] rather than a `bool` because that is the value
    /// [`gpurify_ingest::layout::read_layout`] takes — `--strict-layers` is
    /// [`UnknownLayers::Reject`], `--no-strict-layers` is
    /// [`UnknownLayers::Drop`].
    pub unknown_layers: UnknownLayers,
}

/// Written out rather than derived, for one field: `unknown_layers` defaults to
/// [`UnknownLayers::Reject`]. A derived `Default` would have to pick whichever
/// variant `ingest` declared first, and getting it wrong drops geometry from an
/// undescribed layer without saying so.
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
/// same name from the reference netlist are the same `StrId` and compare as an
/// integer. Two tables would mean string comparison at the one place it matters
/// most.
#[derive(Debug, Default)]
pub struct Loaded {
    pub strings: StrTable,
    /// The grid the deck's limits and the layout's coordinates were read
    /// against, copied from [`Inputs::grid`]. `Some` after any successful
    /// [`load_into`] — `None` only on a `Loaded` that has not been filled, which
    /// is what [`Default`] leaves and what [`LoadError::NoGrid`] refuses to turn
    /// into a run.
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
        // The one invariant that spans the three tables: a port names a net of
        // *this* extraction, so an `Extracted` assembled from two different runs
        // is caught here rather than inside a rule reading past the net table.
        debug_assert!(
            self.ports.len() <= self.nets.net_count(),
            "the port table names more nets than this extraction produced"
        );
        // The three fields of *this* extraction, named in the order the struct
        // declares them: the transposition the view exists to prevent is a
        // borrow of somebody else's tables, and it type-checks.
        Extraction {
            nets: &self.nets,
            devices: &self.devices,
            ports: &self.ports,
        }
    }
}

/// Read every input.
///
/// **Transform, generative.** Caller owns `out`, so a caller running several
/// layouts against one deck reuses the allocation.
///
/// Order matters and is not incidental: the grid must be established before
/// rule limits can be converted, and before the layout can be read, because
/// layer mapping happens during the read rather than after it.
///
/// So the first thing this does is read [`Inputs::grid`], and a run without one
/// stops at [`LoadError::NoGrid`] before either file is opened. That is what
/// makes the ordering observable: with an absent grid and two unreadable paths,
/// the error is `NoGrid`, and with a grid and two unreadable paths it is
/// [`LoadError::Deck`] — never [`LoadError::Layout`].
pub fn load_into(inputs: &Inputs, out: &mut Loaded) -> Result<(), LoadError> {
    // Cleared before anything is opened, and set again only on the way out:
    // `Loaded::grid` is documented as `Some` after a successful load, so a
    // failed one must not leave the previous run's grid behind for a caller
    // that read the error and kept the buffer.
    out.grid = None;

    // The grid first, before either path is touched. Every limit in the deck is
    // physical nanometres converted against it, so a run without one has
    // nothing to convert — and guessing a resolution reinterprets every limit.
    let grid = inputs.grid.ok_or(LoadError::NoGrid)?;

    // The deck before the layout, and the deck's own bytes before either parse:
    // `read_layout` takes the deck by reference because layer mapping happens
    // during the read, so an unreadable pair fails as a deck error.
    let source = std::fs::read_to_string(&inputs.deck).map_err(|why| {
        // The path is in the message for the same reason `read_deck` puts it
        // there: a run opens four files and "No such file or directory" names
        // none of them.
        gpurify_ingest::DeckError::Io(format!("{}: {why}", inputs.deck.display()))
    })?;

    // The deck is parsed twice, into two string tables. Not a shortcut and not
    // fixable here: `read_layout` owns the table it interns cell, property and
    // label names into and takes no `&mut StrTable`, so the run's one id space
    // can only be the layout's, and a deck parsed before it is a table behind.
    // The first parse therefore exists to map layers during the read and is
    // thrown away; the kept deck is parsed against the layout's table. The
    // alternative — remapping one side's ids afterwards — is not reachable
    // either: `Provenance` and `PathTable` keep their `StrId` columns private
    // and expose no remap. Filed against the signature in
    // `docs/SIGNATURE_DEFECTS.md`; it costs one extra parse of a small JSON per
    // run.
    //
    // Safe to do twice because `LayerId`s are assigned by sorted layer *name
    // bytes* (`ingest::deck::build_layers`), not by the order the parse
    // happened to intern in — so both parses agree on every id the layout was
    // mapped against.
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

    // The label pass, and it is here rather than inside `read_layout` for two
    // reasons that are both about what exists when. A label's point is in the
    // root frame only after flattening, and the `PolyId` it resolves to is a
    // store row only after `GeometryStoreBuilder::finish` has sorted by layer —
    // so binding cannot happen while records are being read. And *which* text
    // names *which* conductor is the deck's answer, not the file's: GDSII
    // defines no relationship between a `TEXT` and a shape at all, so the
    // pairing comes from `connectivity.labels` and the reader has no business
    // deciding it.
    //
    // Before `bind_ports_into`, which is what turns the bound labels into the
    // `PortTable` every net name downstream comes from.
    out.provenance
        .resolve_labels(&out.store, &out.deck.connectivity)?;

    // Both optional readers intern into the same table, after it became the
    // layout's: that is what makes a net name from the layout and the same name
    // from the reference netlist one `StrId` and an integer compare.
    out.reference = match &inputs.reference {
        None => None,
        Some(path) => Some(read_reference(path, &mut out.strings)?),
    };
    out.intent = match &inputs.intent {
        None => None,
        Some(path) => Some(gpurify_ingest::intent::read_intent(path, &mut out.strings)?),
    };

    // The one-table invariant the double parse above buys, asserted over the
    // one column that carries layout-interned ids across a crate: every label
    // names a polygon this store holds and a name this table can resolve.
    // Hoisted uniforms, and `&` rather than `&&` — no branch per label.
    let polys = out.store.poly_count();
    let names = out.strings.len();
    debug_assert!(
        {
            // One column of `(PolyId, StrId)` pairs, so there is no second
            // length to agree with; the trip count is the slice's own.
            let labels = out.provenance.labels();
            let mut ok = true;
            for &(poly, name) in labels {
                ok &= ((poly.0 as usize) < polys) & ((name.0 as usize) < names);
            }
            ok
        },
        "a label names a polygon or a string outside the run's tables"
    );

    // Every LVS rule id, interned here because `run_checks` borrows `Loaded`
    // shared and cannot. A mismatch it maps into the violation table names one
    // of the first seven, and one of `lvs::checks`'s eight run rows names one of
    // the rest; a `StrId` a writer cannot resolve is a panic in the report
    // rather than a line in it. Fifteen names in a table of tens of thousands.
    for id in crate::run::LVS_RULE_IDS
        .iter()
        .chain(crate::run::LVS_CHECK_RULE_IDS.iter())
    {
        out.strings.intern(id);
    }
    debug_assert!(
        crate::run::LVS_RULE_IDS
            .iter()
            .chain(crate::run::LVS_CHECK_RULE_IDS.iter())
            .all(|id| out.strings.get(id).is_some()),
        "an lvs rule id did not survive interning, so a finding has no name to be reported under"
    );

    out.grid = Some(grid);
    Ok(())
}

/// Read a reference netlist, picking the dialect from the file's own text.
///
/// The dialect is read off the subcircuit opener rather than guessed from the
/// extension, and that is exact rather than heuristic: every netlist either
/// reader accepts declares at least one subcircuit — a device card outside one
/// is refused, because there is no subcircuit for its nets to be scoped to — and
/// the two dialects spell the opener differently, `.subckt` in SPICE and
/// `subckt` in Spectre. So the first opener in the file names the dialect, and a
/// Spectre netlist under a `.cdl` name now reads instead of erroring at its
/// first card.
///
/// The extension decides only when neither opener appears, which is a file that
/// parses as neither dialect; there it picks which reader gets to name the line.
fn read_reference(
    path: &std::path::Path,
    strings: &mut StrTable,
) -> Result<Netlist, gpurify_ingest::netlist::NetlistError> {
    let source = std::fs::read_to_string(path).map_err(|why| {
        gpurify_ingest::netlist::NetlistError::Io(format!("{}: {why}", path.display()))
    })?;
    let declared = spectre_by_opener(&source);
    let spectre = declared.unwrap_or_else(|| {
        // Nothing in the text discriminates. `.scs` and `.spectre` are Spectre,
        // everything else — `.sp`, `.spi`, `.cdl`, `.net` — is SPICE.
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
    // The postcondition that ties the decision to the result: the opener this
    // read was chosen by is a subcircuit the reader must have produced a row
    // for. A decisive sniff followed by an empty subcircuit table would mean
    // the two disagree about what an opener is.
    debug_assert!(
        declared.is_none() || netlist.subckt_count() > 0,
        "the text declared a subcircuit opener and the netlist read from it has no subcircuits"
    );
    Ok(netlist)
}

/// Is this netlist Spectre? `None` when its text does not say. **Decision.**
///
/// In: the whole source. Out: one tri-state, decided by the first subcircuit
/// opener — `subckt` is Spectre, `.subckt` is SPICE. Case follows each reader's
/// own rule rather than a convenience taken here: SPICE compares its cards
/// ignoring ASCII case and Spectre's keywords are exact.
///
/// The scan stops at the first opener instead of running to the end — it is the
/// same `source.lines()` walk the reader is about to do, truncated.
fn spectre_by_opener(source: &str) -> Option<bool> {
    source.lines().find_map(|raw| {
        let line = raw.trim_start();
        // Comment leaders in both dialects, checked before the token: `* subckt
        // ...` in a SPICE header and `// subckt ...` in a Spectre one are prose,
        // and reading either as an opener picks the dialect out of a sentence a
        // human wrote.
        if line.starts_with('*') || line.starts_with("//") {
            return None;
        }
        // Parens are separators in Spectre and ordinary characters in SPICE, so
        // splitting on them is right for the dialect that uses them and harmless
        // for the one that does not: no SPICE card begins `.subckt(`.
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
/// **Transform.** Caller owns `out`. Strictly ordered — devices are recognised
/// on derived layers, and terminals are bound to nets, so neither stage can
/// move.
pub fn extract_into(loaded: &Loaded, out: &mut Extracted) -> Result<(), ExtractError> {
    debug_assert_eq!(
        loaded.deck.connectivity.via_cut.len(),
        loaded.deck.connectivity.via_connects.len(),
        "a via layer is a cut and the two layers it joins, in step"
    );

    // Derived layers first: devices are recognised on them.
    //
    // Whatever the caller planned into `out.derived` is what gets evaluated,
    // which for a `Extracted::default()` is nothing. Nothing here can plan it:
    // `Deck` carries no named derived expressions, so there is no column to
    // hand `Evaluator::plan`. Reported rather than worked around — inventing
    // the deck section would be a Definition decision. `evaluate` re-runs
    // against this store and keeps the buffers a previous call grew, which is
    // what makes a second extraction into one buffer correct.
    out.derived.evaluate(&loaded.store)?;

    // Then nets, then devices on those nets, then labels bound to those nets.
    // Each of the three clears the table it fills, so a reused `Extracted`
    // is refilled rather than appended to.
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
    /// Fail closed rather than defaulting to a common resolution: a deck's
    /// limits are physical nanometres and a guessed `dbu_per_um` reinterprets
    /// every one of them, which passes or fails shapes for a reason nobody
    /// stated.
    #[error("no grid resolution: Inputs::grid is absent and nothing else establishes one")]
    NoGrid,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ExtractError {
    #[error(transparent)]
    Derived(#[from] gpurify_derived::DerivedError),
    #[error(transparent)]
    Port(#[from] gpurify_topology::port::PortError),
}
