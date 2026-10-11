# What GPurify cannot check yet

GPurify has not been proven against foundry signoff on production silicon. Do
not tape out on its verdict alone. This page lists what it misses, so a clean
report can be read for what it is.

## Geometry

A layout with 45° edges loads, and the `angle` rule checks every edge of it.
Every other rule that measures geometry validates its layer first and records
`Refused` for a layer with a non-rectilinear edge, so diagonal routing is
checked for its angles and nothing else.

## Rules that can pass a layout signoff would flag

These rule kinds exist but measure less than a foundry deck does. A clean
result from them is weaker than it looks.

| Check | What it misses |
|---|---|
| `enclosure(inner, outer, opposite)` | An inner shape that is not a rectangle is held to the every-side limit instead. |
| `enclosure(E, L)` on an edge layer | Measures straight out from each edge, so a gap in `L` diagonally off a corner of the shape is not seen. Pair it with the shape `enclosure` where the corner matters. |
| `antenna_electrical` | A row with a diode and a non-zero `diode_credit` is refused: the unit of the credit is not settled. |
| `esd_topological`, `esd_latchup` | Only checks that a clamp path exists. The resistance and current capacity of the path are not checked, and a clamp is any device of a listed model, however it is wired. |
| `gate_oxide`, `drain_source`, `well_bias`, `missing_level_shifter`, `domain_crossing` | A net's voltage range is the span of every supply it connects to through a device channel, ignoring threshold drops, switching and power-down, so these rules can over-report. A net that reaches no supply that way, such as a primary input with no ESD diode, is not checked, and neither is a device whose terminals sit on such nets. |

## Checks that do not exist yet

- Derived layers have no selection by net or angle, no
  `covering`/`overlapping`, and `sized` grows both axes by the same amount.
  Shape class (`.rectangles()`, `.squares()`), direction (`.horizontal()`,
  `.vertical()`) and bounding-box size (`.with_bbox_max()`) are selectable.
- Edge layers cannot be extended, so sky130 difftap.6 "diff and tap are not
  allowed to extend beyond their abutting edge" cannot be written.
- Spacing that depends on the voltage between two nets.
- A way to state the voltage or domain of an input signal in the intent file,
  and checks for inputs driven from a powered-down domain.
- Lithography hotspots (aerial-image or process-window simulation) and a full
  CMP topography simulation: both need a foundry's calibrated optical, resist
  or polish model, which no open PDK publishes. The CMP hotspots a public
  model defines, a density step between neighbouring windows and a
  first-order thickness excursion, are `density_cmp`'s.

## Power grid

- Each supply net is fed from one point: the centre of its highest, then
  widest, shape. A rail fed from several pads reads more drop and more current
  near that point than it really has.
- A net's current budget is shared equally among the devices on it, so one
  device that draws more than its share reads cooler than it is.
- `electromigration` and `reliability` use one temperature for the whole run,
  the deck's `temperature` (85 °C when it states none), with no self-heating.

## Parasitics

- Resistance moves with the deck's `temperature` by each layer's `tc1` and
  `tc2`. Nothing else does: metal thickness does not follow CMP (pattern
  density), via resistance does not depend on current, and mask shifts
  between colours are not modelled. The models exist (density-step CMP,
  Ouma et al., IEEE TSM 15(2), 2002), but their parameters are foundry
  calibration data no open PDK publishes.
- `lib` extracts once, at the deck's temperature, whatever temperatures its
  corners name.

## Shipped decks

Each deck in `pdks/` names, in its header, the rule manual and open decks its
numbers come from, pinned to a release or commit. Rule ids are the foundry's.
None has been compared against foundry signoff results.

- Rules that need a check the language does not have yet are written out,
  commented, near the end of each deck with the reason: net spacing between
  two layers or on wells (no deck connects wells as nets) and maximum
  areas. Each deck also lists the manual rules it leaves out, and why.
- Only sky130 connects wells as nets: the p-substrate (`connect global
  psub`), each n-well through its n-taps, and each isolated p-well in deep
  n-well, so its transistors have a bulk terminal and it carries
  `well_bias`. Its pd2nw diodes and bipolars still have no recogniser. The
  other decks' transistors have no bulk terminal and no `well_bias`. The
  substrate carries no modelled current: a supply reached only through it is
  an island to the power grid, and a field solve leaves it out of a net that holds it, and refuses a net whose pieces join only through it.
- No deck carries `esd_latchup`: none of the manuals states a pad guard-ring
  width and tap distance in the form the rule takes.
- `gate_oxide` and `drain_source` use the operating voltages the PDK
  documents (sky130's model limits, the nominal supplies for gf180mcu and
  IHP), not an absolute maximum rating.
- sky130: maximum metal density (met1-met4, 70% in 700um windows) is the
  standard-cell tech LEF's router limit, not a manual rule, so it is an ERC
  warning over whole windows, not a DRC error.
- sky130: the periphery rules also apply inside SRAM cores (`areaid.ce`).
  The implant-enclosure rules nsd/psd.5a and 5b on diffusion and taps that
  butt each other are measured straight out from each edge (see
  `enclosure(E, L)` above); nsd/psd.7 is checked only on shapes that butt
  nothing. poly.4 measures corner to corner
  where the manual measures parallel edges only, so it can over-report, and
  covers only poly that touches no diffusion.
- IHP: parasitic area capacitance other than Metal1 is computed from the
  documented layer heights and dielectric constants, and fringe capacitance
  is zero. Its antenna rows say `diode: none` (no antenna-diode layer is
  chosen), so a gate with a diode is held to the no-diode limit.
- `generic_finfet` is ASAP7, a predictive process no fab builds. It
  recognises no transistors and extracts no capacitance: the manual gives no
  resistance for the gate and local-interconnect layers and no capacitance at
  all. Its metal heights are stacked from the manual's widths and the 2:1
  aspect ratio, not from a published cross-section.

## Liberty generation

[liberty.md](liberty.md#what-it-does-not-do-yet) lists what `lib` does not
characterize. Against sky130_fd_sc_hd's shipped libraries, the residual
difference is mostly the models: the same devices simulated with today's
ngspice sky130 models differ from the shipped tables by about as much as a
`spice`-accuracy run does.

## Test coverage

`ir_drop`, `electromigration` and `reliability` are checked against numbers
worked out by hand from Ohm's law, Black's equation with the Blech exemption,
and the power-law and Arrhenius lifetime model, including values exactly at
the limit. `esd_latchup` is checked against the closed form on its corpus
cell, guard-ring width and tap distance alike. Many other rules have limits
that are foundry conventions rather than physics, so their tests prove the
rule runs and measures, not that the limit is right for your process.

## Every check that is missing or partial

The sections above explain the gaps that most often matter. This is the
complete list: every check kind a signoff verifier is expected to handle that
GPurify does not have (`missing`), or has without some variant the sources
define (`partial`). It comes from [check-catalog.tsv](check-catalog.tsv), which
also lists what GPurify does cover, and [check-sources.md](check-sources.md)
says which foundry manual, standard or tool defines each one.

<!-- generated from docs/check-catalog.tsv by tests/catalog.rs; edit the catalog, not this block -->

### Design rules (DRC)

| Id | Check | Status | What is missing |
|---|---|---|---|
| DRC-002 | Allowed edge angles | partial | 45-degree and acute edges load and angle checks them; every other geometric rule records Refused on a non-rectilinear layer; with no layer, drawn layers only (F63, fixed) |
| DRC-007 | Label / pin / text rules | partial | Pin-in-drawing is expressible. A label on no net aborts extraction (PortError::OrphanLabel in topology::port::bind_ports_into): caught, but fatal, not a rule. Pin centre spacing is not expressible |
| DRC-015 | Discrete / allowed width set | partial | width(L; allowed: [..]) holds each merged figure's narrowest width to a list (sky130 rpm.1b-1f). Missing: LEF58 WIDTHTABLE's fracture into rectangles and its open-ended last width, and ASAP7 M4.W.3/W.4 (no even multiple of the minimum width) |
| DRC-016 | Wrong-direction width or spacing | partial | width(E) and facing_space(E) on L.edges().horizontal() or .vertical() measure in one direction (ASAP7 M4.W.1, W.5, S.1, S.2); the PRL and NONEOL qualifiers of LEF58 WRONGDIRECTION spacing are missing |
| DRC-020 | Minimum step / edge length / jog | partial | min_step(L; ..) is LEF 5.8 MINSTEP's MAXEDGES, OUTSIDECORNER, INSIDECORNER, STEP and LENGTHSUM; LEF58_MINSTEP's MINADJACENTLENGTH, MINBETWEENLENGTH, NOADJACENTEOL and NOBETWEENEOL are missing |
| DRC-021 | Feature length min/max | partial | Edge length is length(E) (ASAP7 type L); a straight feature's length is its box's longer side, forbidden(L.with_bbox_max(< len)) (sky130 mf.2, IHP Rsil.f); a bent feature's length along its path is not measured |
| DRC-027 | Two-widths spacing table | partial | The table is keyed on the wider shape only; TWOWIDTHS keys on both widths |
| DRC-028 | Influence / stub spacing near wide metal | partial | Implements the sky130 m1.3a form; equivalence with LEF INFLUENCE is unverified |
| DRC-029 | End-of-line spacing | partial | Basic EOL only; PARALLELEDGE, TWOEDGES, ENCLOSECUT and ENDTOEND are missing |
| DRC-030 | EOL extension / keep-out | missing | — |
| DRC-031 | Tip-to-tip / tip-to-side by width class | partial | One end-of-line width per rule, so each width class is its own rule; tip-to-side is not told apart from tip-to-tip |
| DRC-032 | Corner spacing (convex/concave, corner-to-corner) | partial | Measures facing convex corners of the merged layer; CONCAVECORNER, EXCEPTEOL and LEF58 CONVEXCORNER variants are missing; sky130 poly.4 over-reports (limitations.md, "Shipped decks") |
| DRC-033 | Forbidden spacing ranges | missing | — |
| DRC-034 | Maximum spacing | missing | — |
| DRC-035 | Pitch / exact pitch / on-track | missing | Also covers gridded-design rules (Liebmann 2003; Jhaveri 2010) |
| DRC-036 | Span-length table | missing | — |
| DRC-037 | Bent / 45-degree features | partial | angle checks the edges; spacing and width rules record Refused on a non-rectilinear layer |
| DRC-038 | Diagonal width / spacing | missing | In scope since 2026-10-11 (was: Needs non-rectilinear geometry) |
| DRC-041 | Enclosure on two opposite sides | partial | A non-rectangular inner shape is held to the every-side limit (limitations.md, "Rules that can pass a layout signoff would flag") |
| DRC-042 | End-cap / one-of-two-adjacent-sides enclosure | partial | Only the two-opposite-sides form; one-of-two-adjacent-sides and end-cap-only enclosures cannot be written |
| DRC-043 | Width-dependent enclosure | missing | — |
| DRC-044 | Maximum enclosure / min-and-max window | missing | sky130.deck "npc.5 (maximum enclosure)" |
| DRC-045 | Extension / end-cap / overhang | partial | Each gate of merged A ∩ B measured per crossed axis; a gate that bends or carries a stub inside B measures 0 (fails closed) |
| DRC-049 | Exact or maximum count | partial | Minimum count only (sky130.deck "an exact count") |
| DRC-051 | Abutment / butting edges | partial | Edge layers cannot be extended (difftap.6; limitations.md, "Checks that do not exist yet"); edge enclosure misses diagonal gaps (limitations.md, "Rules that can pass a layout signoff would flag") |
| DRC-052 | Gate-shape rules (no bends, no poly on inner diff corners) | missing | Needs corner/turn selection (sky130.deck) |
| DRC-053 | Exact alignment / width match across layers | missing | — |
| DRC-054 | Enclosure excluding coincident edges | missing | — |
| DRC-055 | Direction-dependent (S/D-direction) spacing | missing | — |
| DRC-061 | Centre-to-centre cut spacing | missing | — |
| DRC-062 | Array / adjacent-cut spacing | partial | ADJACENTCUTS WITHIN variants are unverified |
| DRC-063 | Cut-class spacing tables | missing | — |
| DRC-064 | Slotted / bar cut spacing by edge length | missing | sky130.deck left out |
| DRC-065 | Via stacking / cross-layer cut spacing | partial | Cross-layer spacing works; the stack-count limit is missing |
| DRC-066 | Minimum cut count / redundant via | partial | Width-triggered MINIMUMCUT (FROMABOVE/BELOW, LENGTH WITHIN) is missing |
| DRC-067 | Metal-width-dependent via choice | missing | — |
| DRC-068 | Cut-area conservation between two databases | partial | gpurify xor compares two layouts layer by layer, as KLayout's xor does: every region where a drawn layer differs, with its area, so a cut layer's lost or added area is found. Not checked: the irdrop rules' tolerance per connector by cut count, whose text leaves unsettled what a connector is and the unit of its limit (um) |
| DRC-075 | Wide-metal slotting | partial | Slot required is a kind (cheesing); slot geometry uses the generic kinds; slit density over a plate is region_density (IHP Slt.i). Missing: a maximum slot spacing (GF180 MSLOT.4) and staggered slots (MSLOT.6) |
| DRC-076 | Waffle-window density | missing | sky130's waffle rule (m1.- for met1 to met4, RC) holds a 700 um window's metal density to a floor set by how much of it cmm waffle-drop covers (70% when all of it, then 65/60/50/40/30% by band); the public text states neither the window step nor whether the band edges are inclusive, so it is not written |
| DRC-081 | Net spacing between two layers / on wells | missing | Net spacing takes one layer; only sky130 connects wells as nets |
| DRC-082 | Voltage-dependent spacing (VA-DRC) | missing | Top cross-source gap; needs ERC-F1 voltage propagation |
| DRC-083 | HV tag propagation (shorted to HV becomes HV) | partial | hv_domain flags devices whose terminals span supply domains; layout shorted to an HV net is not tagged HV |
| DRC-084 | Floating interconnect / must-join ports | partial | Flags conductor shapes that reach no device; LEF58 must-join-all-ports is not modelled |
| DRC-086 | Shorts between labelled nets | partial | Reported in every run as lvs.net_seed_conflict, naming both labelled shapes, located at the first; no abort |
| DRC-090 | Device-family rules (R, MIM, BJT, varactor, inductor, fuse, Schottky, LDMOS, photodiode, SRAM) | partial | Geometry is expressible through markers; exact resistor widths are width(L; allowed: [..]) (sky130 rpm.1b-1f) and channel length and width width(E) (DRC-011). Missing: licon counts per resistor terminal (rpm.1g-1k) and varactor taps (varac.2, varac.6) |
| DRC-092 | Exemptions (areaid regions, cell-name, rule flags) | partial | Region exemptions work via `not areaid`; cell-name exemptions are missing (layout is flattened) |
| DRC-095 | Seal ring | partial | Geometry through the generic kinds; one seal ring per chip (IHP Seal.m) is count(seal) <= 1 with >= 1, nothing outside it (Seal.l) forbidden(L not (seal or seal.holes())). Missing: the seal ring at the origin (sky130 x.19) and a partnum beside it (x.27) |
| DRC-097 | Frame / die / cell-name rules | partial | Frame, scribe and LBE geometry is expressible with the generic kinds (sky130 x.16, x.21, x.23a-d, x.28; IHP LBE.*), e.g. forbidden(sl and diff), forbidden(lbe.holes()). Missing: cell-name and pcell rules (x.12 exemptions, x.25-x.27) and the seal ring's corner at the origin (x.19) |
| DRC-101 | MP error taxonomy (anchor path, anchor self-conflict, same-mask self-conflict, min opposite-mask spacing) | partial | Reports a colouring failure, not its class |
| DRC-102 | Pre-coloured (MASK) same-/different-mask spacing | missing | — |
| DRC-103 | Stitch legality | missing | — |
| DRC-104 | Per-colour density and colour ratio | missing | — |
| DRC-105 | Trim / cut-metal layers | missing | — |
| DRC-110 | Recommended rules reported as warnings | partial | `warning` severity exists for ERC rows only (deck.md); a recommended DRC rule cannot be reported as a warning |
| DRC-111 | DFM scoring of recommended rules | missing | — |
| DRC-112 | Critical area analysis | missing | — |
| DRC-113 | Litho / CMP simulation hotspots | partial | CMP hotspots a public model defines: a density step between neighbouring windows (max_delta) and a first-order thickness excursion, sensitivity x (density - target), over a window standing for the planarization length (density_cmp, Ouma2002). Litho hotspots (aerial-image, process-window simulation) and a full CMP topography simulation need a foundry's calibrated optical, resist and polish models, which no open PDK publishes; foundry hotspot pattern libraries are not public |
| DRC-114 | Pattern-matching DRC | missing | — |
| DRC-115 | Equation-based DRC | missing | First candidate for Rust custom rules (testing-plan.md L9b) |
| DRC-116 | Curvilinear / all-angle tolerance DRC | missing | In scope since 2026-10-11 (was: Rectilinear only) |
| DRC-117 | Via redundancy scoring / via doubling | partial | Counts cuts within a distance; no DFM scoring and no via doubling |
| DRC-121 | Selection by shape class, net or angle; covering/overlapping; anisotropic size | partial | limitations.md, "Checks that do not exist yet" |
| DRC-122 | Edge-layer ops incl. extension | partial | limitations.md, "Checks that do not exist yet" |
| DRC-123 | Hierarchical processing | partial | Flattened at load (gds::Library::flatten); a scale issue, not correctness |

### Layout against schematic (LVS)

| Id | Check | Status | What is missing |
|---|---|---|---|
| LVS-001 | Port / label consistency | partial | label_conflict flags one label on several nets (an open); net_seed_conflict flags several labels on one net (a short), one row per pair at the first label's shape |
| LVS-002 | Implicit joins (same-label disjoint shapes, must-connect) | partial | Same-label disjoint shapes are not joined; they are reported as label_conflict, and only with --reference (lvs::check_layout); located on the labelled shapes (F70) |
| LVS-005 | Short isolation / localisation | partial | Reported in every run, DRC-only included, naming both labelled shapes, located at the first; no path traced; no abort |
| LVS-010 | Circuit without partner / hierarchical compare | partial | The reference is flattened below its top (Netlist::flatten_top) and compared device by device, so a missing block is a mismatch; there is no per-cell matching and no circuit-mismatch report naming the cell; a reference flattening to more than 2²⁸ devices, nets and instances is refused (NetlistError::TooLarge) |
| LVS-013 | Paired device with a different class/model | partial | Pairing requires the same kind and model, so it shows as unpaired |
| LVS-014 | Parameter mismatch with tolerance | partial | One relative tolerance, 0.02 (lvs::CompareOptions); per-parameter and absolute tolerances are missing |
| LVS-016 | Pin / port mismatch | partial | Net and port names are never compared, so a misnamed or reordered port passes; an unconnected reference port shows as unpaired_net (test net_names_do_not_have_to_agree) |
| LVS-017 | Subcircuit instance unpaired | partial | Instances are flattened, not paired as units: a missing instance shows as its devices unpaired |
| LVS-030 | Swappable pins (S/D, resistor ends, user-declared) | partial | MOS source/drain and resistor ends are interchangeable; diode anode/cathode and capacitor plates are not, as in Netgen. User-declared equivalent pins are missing |
| LVS-031 | Asymmetric devices (S/D not swappable) | missing | — |
| LVS-032 | Net-name seeding (same_nets) | missing | Names neither seed refinement nor are compared (test net_names_do_not_have_to_agree) |
| LVS-033 | Black boxes | missing | — |
| LVS-034 | Ignore device class (fill, decap, tap cells), parasitic filters | missing | sky130 netgen setup ignores fill/tap/fakediode classes |
| LVS-035 | Dummy / shorted device removal | missing | — |
| LVS-042 | Semi-series MOS | missing | — |
| LVS-043 | Resistor series/parallel | partial | Parallel resistors merge keeping R and counting m (match one card with m=2, not one card of R/2). Series merging is MOS only |
| LVS-044 | Capacitor / diode / BJT parallel | partial | Parallel capacitors, diodes and bipolars keep their value and count m; values are not added. Diodes wired in opposite directions do not merge |
| LVS-047 | Logic-gate recognition | missing | — |
| LVS-048 | Filter unused devices | missing | — |
| LVS-049 | Topology vs property policy (strict/relaxed) | partial | Fixed strict policy: structural differences after reduction are reported as unpaired devices. |
| LVS-060 | MOS W, L, nf, m, AS/AD/PS/PD, bulk | partial | w and l from the marker bounding box; nf = 1 per channel, summed by parallel merges; marker area and perim. Compared per paired device, only where its card states the parameter (F68). as/ad/ps/pd from the source/drain polygon (gate edge included, BSIM4 perMod=1), a shared diffusion split evenly, compared at the channel end, summed in parallel merges, refused in series; not measured where drawn in pieces; bulk is dropped when the layout has none |
| LVS-061 | Resistor R/L/W | partial | w/l from the resistor body's bounding box; r = sheet·l/w when the device statement gives sheet; positional R1 a b 1k rpoly is read as r. A bent body reads its bounding box; a card with no model is the deck's one resistor (F86); resistors never merge in series |
| LVS-062 | Capacitor C/A/P | partial | area and perim measured; c = area_cap·area + fringe_cap·perim when the deck gives them; a positional C value is read. No w/l; KLayout A/P read as area/perim (F87); a C card with no model is the deck's one capacitor (F86) |
| LVS-064 | BJT AE/PE/NE, multi-emitter | partial | ae/pe from the emitter terminal's polygon (B27); marker area and perim; no NE or multi-emitter. sky130 bipolars have no recogniser (limitations.md, "Shipped decks") |
| LVS-065 | Inductor | missing | — |
| LVS-067 | Subcircuit-modelled devices (rsubcircuit, fixed cells: VPP, ESD) | missing | sky130 VPP caps have no marker (limitations.md) |
| LVS-068 | Device-count and parameter-range limits (devices per model, W/L inside the model's valid range) | missing | No check exists: the deck has no syntax for per-model counts or parameter ranges |
| LVS-073 | 3D / system LVS across dies | missing | In scope since 2026-10-11 (was: Single-die only) |

### Electrical rules (ERC)

| Id | Check | Status | What is missing |
|---|---|---|---|
| ERC-A4 | Cut/via ratio, routing-plus-cut accumulation | partial | ROUTINGPLUSCUT is missing |
| ERC-A5 | Subtractive diode credit (K x area + bonus) | partial | A row with a diode and non-zero diode_credit is refused (limitations.md, "Rules that can pass a layout signoff would flag"); diode_bonus applies only to gates with diode area on their net |
| ERC-A6 | Additive diode credit (gate += MF x diode) | missing | — |
| ERC-A7 | PWL diffusion-dependent limit | missing | — |
| ERC-A9 | Minimum protection-diode size | missing | — |
| ERC-A11 | MIM capacitor as victim | partial | The gate argument takes any layer; a non-conductor gate joins the layer a device mos row names as its gate terminal, else the conductor it lies on, never metal routed over it (F72, F81 fixed). gf180 leaves ANT.14/15 out, and the FuseTop/Via5 connectivity needs care |
| ERC-A12 | Oxide-class-specific limits | partial | One row per gate layer |
| ERC-A13 | Exemption for substrate-shorted nets | missing | No exemption: every net with gate area > 0 is checked; reaching diffusion or a tap protects nothing (erc::rules::antenna::check_antenna) |
| ERC-A14 | Hierarchical / macro-pin antenna | missing | — |
| ERC-A15 | Fix hint: required diode area | missing | Report feature |
| ERC-C2 | ESD device sizing (perimeter, clamp width) | missing | — |
| ERC-C3 | Protected device (pad-exposed gates and drains) | missing | — |
| ERC-C4 | Cross-domain signal ESD protection | missing | domain_crossing and missing_level_shifter are functional checks, not ESD |
| ERC-C5 | Ground-domain coupling (anti-parallel diodes) | missing | — |
| ERC-C6 | P2P resistance on the discharge path, per pin pair | partial | Measures within one net; the pad-device-bus-clamp path is missing |
| ERC-C7 | ESD-pulse current density | partial | No ESD stimulus and no It2 limits |
| ERC-C8 | Path voltage vs device failure (ESD window) | missing | — |
| ERC-C9 | CDM checks (bus inductance, local clamps, driver/receiver ground R) | missing | — |
| ERC-C10 | Layout parasitic ESD paths | missing | Spacing values are NDA |
| ERC-C12 | Package / 2.5D / 3D ESD | missing | In scope since 2026-10-11 (was: On-chip only: package and multi-die ESD models are outside a layout verifier) |
| ERC-C13 | System-level ESD | missing | In scope since 2026-10-11 (was: A board and system concern, outside a layout verifier) |
| ERC-D1a | Tap distance conditional on neighbouring well spacing | missing | — |
| ERC-D1b | Minimum well-tie area | missing | — |
| ERC-D2 | Pad-diffusion guard ring (spacing, width) | partial | No deck carries it (limitations.md, "Shipped decks"); width is the merged ring's narrowest band, tap distance a bounding-box gap |
| ERC-D3 | Guard ring / well tied to the correct rail | partial | Devices only, not guard rings |
| ERC-D4 | Guard-ring resistance / current under injection | partial | Resistance and current density are computed within one net; a guard ring's path to the supply pins under an injection stimulus is not modelled |
| ERC-D5 | Voltage-aware aggressor/victim | missing | — |
| ERC-D6 | HV latch-up between isolated pockets | missing | — |
| ERC-D7 | Native-device guard ring | missing | — |
| ERC-D8 | Forward-biased diode marked and ringed | missing | — |
| ERC-E3 | Width-banded absolute current for narrow lines | partial | Limit is max_density x width only, with no width band or absolute cap (erc::rules::electrical::check_em_current_density). The IHP deck states JMAX only: it may over-report, but it cannot under-report |
| ERC-E7 | RMS / Joule heating / peak limits | missing | No open source |
| ERC-E9 | PDN integrity (floating stripes, unconnected instances) | partial | Flags unconnected conductors; PDN-specific checks (floating stripes, instance supply terminals) are missing |
| ERC-E11 | Dynamic / vectorless IR | missing | In scope since 2026-10-11 (was: Static analysis only: dynamic IR needs switching activity) |
| ERC-E12 | Stress voiding / slotting | partial | cheesing requires a slot in wide shapes; stress-voiding rules beyond slotting are missing |
| ERC-E13 | Thermal-aware / statistical EM, self-heating | missing | In scope since 2026-10-11 (was: One temperature, 85 C (limitations.md, "Power grid")) |
| ERC-F1 | Static voltage propagation, conditional on gate voltage | partial | Channels pass unconditionally |
| ERC-F4 | HCI susceptibility flag | missing | — |
| ERC-F7 | Missing isolation at switchable-domain outputs | missing | Needs power states |
| ERC-F8 | Power-state-dependent undriven gates | missing | — |
| ERC-F10 | HV tag consistency | partial | The domain span across a device is checked; tag consistency (LV and HV n-wells on one net) is not |
| ERC-F11 | Voltage-dependent spacing | missing | Same row as DRC-082 |
| ERC-F13 | Inter-metal dielectric breakdown | missing | — |
| ERC-G8 | Combinational loops | missing | Digital only, optional |
| ERC-H1 | Static leakage / HiZ / floating in power-down | missing | — |
| ERC-H2 | Analog constraints (symmetry, common centroid, matching, orientation, dummies, WPE, STI) | missing | Overlaps Philis's own properties |
| ERC-H3 | Netlist path checks (gate to ground within N devices; net types) | missing | — |
| ERC-H4 | Fanout limits | missing | — |

### Parasitic extraction (PEX)

| Id | Check | Status | What is missing |
|---|---|---|---|
| PEX-003 | Coupling C (same-layer and cross-layer) | partial | No dielectric images: each panel pair sees the mean of their two permittivities and interfaces reflect nothing, so same-layer coupling is under-predicted 14-159% (extract::field). The substrate is a grounded plane at height 0 (testing-plan F24); a shape at height 0 (well, diffusion) is a junction, out of the field and in closed form, so the field reads metal over another net's junction as coupling to ground (F73); a junction layer needs no dielectric (F94) |
| PEX-004 | Partial self / mutual inductance | partial | Each field-solved net gets its self L and R; mutual inductance between nets is never computed. Current is uniform across each rectangle of the merged conductor, so crowding at corners and width steps is not modelled; a net whose pieces meet only at a corner, or join only through a global layer, is refused (testing-plan F23, F45, F79) |
| PEX-006 | Multi-corner extraction | missing | — |
| PEX-007 | Process effects (CMP thickness, temp-dependent R, nonlinear via R, colour-aware) | partial | Temperature-dependent R: the deck's temperature T nominal T0 and each pex row's tc1/tc2 give R(T) = R(T0)(1 + tc1(T - T0) + tc2(T - T0)^2), the ngspice resistor law with the coefficients PDKs publish; extraction, the power grid and lib read it. Not modelled: CMP thickness from pattern density, current-dependent via R, colour (mask-shift) effects: their models need foundry calibration data no open PDK publishes |
| PEX-008 | Reduction modes (C-only, RC, RCC, thresholds) | missing | One fixed output (R, ground C, coupling C, via R); --quasistatic <net> field-solves R, C and L for that net; --format spef\|dspf. No C-only or RC modes and no thresholds |
| PEX-009 | PEX netlist diff / qualification | missing | Worth building as an internal test tool |

### Flow

| Id | Check | Status | What is missing |
|---|---|---|---|
| FLOW-001 | Geometric / hierarchy-invariant waivers | missing | — |
| FLOW-002 | Early / dirty-design staged runs | missing | — |
| FLOW-003 | SoC integration (macro sync, ports off grid, fill outside boundary, block/pad-ring overlap) | missing | Cheap from LEF/DEF + GDS |
| FLOW-004 | Interface DRC top vs blocks | missing | — |
| FLOW-005 | In-design / live DRC | partial | Shared-deck library (Philis) is the first step |
| FLOW-006 | User-programmable rules | missing | Rust decks + Rule::Custom (testing-plan.md L9b) |

<!-- end of generated block -->
