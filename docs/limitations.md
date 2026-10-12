# What GPurify cannot check yet

GPurify has not been proven against foundry signoff on production silicon. Do
not tape out on its verdict alone. This page lists what it misses, so a clean
report can be read for what it is.

## Geometry

A layout with 45° edges loads, its derived layers are computed (booleans,
`sized`, the selections and the edge operations all take 45° edges), and the
`angle` rule checks every edge of it. A vertex a boolean would place between
grid points, where two diagonals cross, is snapped onto the grid
(`docs/deck.md`, "45-degree geometry"). `width`, `notch`, `space` (one layer
or two), `area`, `hole_area` and `edge_length` measure 45° shapes exactly.
Every other rule that measures geometry records `Refused` for a layer with a
non-rectilinear edge. Edges at angles other than multiples of 45° (curved
shapes written as polygons) are refused by every rule and derived layer, and
the KLayout mirror differential has not yet been run on 45° layouts.

## Rules that can pass a layout signoff would flag

These rule kinds exist but measure less than a foundry deck does. A clean
result from them is weaker than it looks.

| Check | What it misses |
|---|---|
| `enclosure(E, L)` on an edge layer | Measures straight out from each edge, so a gap in `L` diagonally off a corner of the shape is not seen. Pair it with the shape `enclosure` where the corner matters. |
| `esd_topological`, `esd_latchup` | Only checks that a clamp path exists. The resistance and current capacity of the path are not checked, and a clamp is any device of a listed model, however it is wired. |
| `gate_oxide`, `drain_source`, `well_bias`, `missing_level_shifter`, `domain_crossing` | A net's voltage range is the span of every supply it connects to through a device channel that can conduct. Only a transistor whose `device` row states `on_gate_min` or `on_gate_max` is switched by its gate; every other channel always conducts, and threshold drops and power-down are ignored, so these rules can over-report. No shipped deck states a gate condition. A net that reaches no supply that way, such as a primary input with no ESD diode, is not checked, and neither is a device whose terminals sit on such nets. |
| `hv_tag`, `mixed_tag` | High voltage is decided by the intent's supplies (`hv_tag`) or by a tag layer (`mixed_tag`); sky130's text tags (`shv_nwell`, `hv_bb`, `hv_lv`, and the `lv_net` exemption of hvnwell.10) are not read. No shipped deck carries either yet: sky130's hvnwell.10 can be written `mixed_tag(nwell, hvi)`, but `hv_tag` needs a voltage the manual does not name for "high voltage". |
| `dielectric_field` | A field limit, not a dielectric lifetime: JEP159A's time-dependent breakdown model is not evaluated. Voltages and unreached nets are as for `voltage_space`; the lateral limit is rounded up to the grid, so a corner-to-corner pair less than one grid unit inside it is flagged. |
| `voltage_space` | A pair of shapes with a net no supply reaches is not checked, and ranges are as above, so two nets that always move together read their whole swing apart. Its layers must be conductors, so a rule on a tag layer (sky130's HV n-well, the n-well under `hvi`) cannot be written. No shipped deck carries it: no open manual states a voltage table. |

## Checks that do not exist yet

- Derived layers have no selection by net. Shape class
  (`.rectangles()`, `.squares()`), direction (`.horizontal()`,
  `.vertical()`), bounding-box size (`.with_bbox_max()`), `.covering()`,
  `.overlapping()` and per-axis sizing (`.sized(dx, dy)`) are written in
  the deck.
- A way to state the voltage or domain of an input signal for the whole run:
  an input is held only within a power state (`states`), and the power-state
  rules examine only the declared states, never every combination.
- Checks no public source defines, so none is guessed (X2 settled each,
  with what it checked, in the catalog's notes): GF180's maximum slot
  spacing and staggered slots (MSLOT.4b, MSLOT.6; DRC-075); LEF58
  `PARALLELSAMEMASK` (DRC-102); spacing by standard-cell edge type, a LEF
  attribute a layout does not carry (DRC-127); self-aligned multiple
  patterning legality, mandrel and cut-mask rules (DRC-128); the length
  that exempts a long protrusion under LEF `PROTRUSIONWIDTH` (DRC-125); and
  the `EXTENSION`, `SPIRALEXTENSION` and `EXCEPTEXACTALIGNED` forms of LEF58
  `KEEPOUTZONE` (DRC-126). Values a foundry keeps private (a pattern
  library, a defect-size distribution, DFM and via-yield weights, a waffle
  window's step, a cut-area tolerance, die-to-die alignment) are the deck's
  to state: those checks exist and take them as required values.
- Lithography hotspots (aerial-image or process-window simulation) and a full
  CMP topography simulation: both need a foundry's calibrated optical, resist
  or polish model, which no open PDK publishes. The CMP hotspots a public
  model defines, a density step between neighbouring windows and a
  first-order thickness excursion, are `density_cmp`'s.

## Hierarchical comparison

LVS compares flat (catalog LVS-010, LVS-017): the reference is flattened
below its top and the layout is flattened when it is read, so a block is
compared device by device. A mismatch names each reference instance none
of whose devices paired (`lvs.unpaired_instance`), but no cell is matched
as a unit, a partly wrong instance is not named, and the layout's own
instances are gone by then. Where a missing block perturbs its
neighbours' nets, refinement cannot pair them either, so an instance beside
the missing one may be named with it.

Cell-by-cell matching, as KLayout and Netgen do it, needs the layout
extracted per cell: each cell's nets once, a net crossing the cell's
boundary a pin of it, and each placement's pins joined in its parent
(KLayout's hierarchical net extraction). The design that keeps the flat
comparison the oracle:

1. extract each layout cell once, its boundary nets as pins, and pair its
   cells with the reference's subcircuits by name, or by a deck list where
   names differ (KLayout `same_circuits`, Netgen `equate classes`);
2. compare paired cells bottom up, each with its paired children replaced by
   one device per placement whose pins are the child's (the comparison
   already handles devices of many pins); a child that does not match, or
   has no partner, is flattened into its parent instead (KLayout `align`,
   Netgen's flattening of unmatched cells);
3. hold every hierarchical verdict to the flat one: a match must equal the
   flat comparison of both sides flattened, which the X5 harness checks
   over generated hierarchies (`tests/exhaustive/lvs.rs` already decides
   hierarchical references through `flatten`).

Step 1 is the whole of the work and is not written: extraction, every
check that reads nets, and the 2²⁸ flat cap all assume the flattened
store.

## Power grid

- Each supply net is fed from one point: the centre of its highest, then
  widest, shape. A rail fed from several pads reads more drop and more current
  near that point than it really has.
- A net's current budget is shared equally among the devices on it, so one
  device that draws more than its share reads cooler than it is.
- `electromigration` and `reliability` use one temperature for the whole run:
  the intent's `temperature_c`, else the deck's `temperature`, else 85 °C,
  with no self-heating.
  `em_thermal` adds each wire's own Joule heating to it, but a wire heats
  only itself: heat from neighbouring wires, heat carried along a line to
  cooler vias, and resistance rising with temperature are not modelled, so a
  dense bundle of wires reads cooler than it is. Its current is the static
  budget's. `em_rms` and `em_peak` take each net's RMS and peak current from
  the intent, every load in phase, so out-of-phase loads read strict, and
  signal lines carry no current (ERC-E7).
- `dynamic_ir_drop` is vectorless: every load on a net switches at once in
  one worst cycle, with no timing windows (which errs high). The grid is
  resistors and decap only, with no package, bump or wire inductance, and
  only that cycle is followed from the static drop: when decap holds charge
  longer than a clock period, the cycles before count only as their average.
  Backward Euler reads a pulse's peak up to 0.61 % low on an RC node.

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
  commented, near the end of each deck with the reason: net spacing on
  layers that are not conductors (wells in every deck but sky130, and
  sky130's deep n-well and HV n-well) and maximum
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
- sky130: the waffle-drop window density rules (m1.- to m4.-, the DRC
  messages m1.x.1 to m4.x.1: met1-met4 density in a 700x700 window must be
  at least 70% when cmm waffle-drop covers all of it, then 65/60/50/40/30%
  by coverage band) are not checked, and nothing public says how they
  should be. The rule text (google/skywater-pdk 7198cf6,
  docs/rules/periphery-rules.rst lines 2017-2028 and the m2-m4 tables;
  docs/rules/errors.csv lines 1196-1219) gives no window step, and its bands
  share endpoints (80-100% and 60-80%). The 700 um window and 70 um step of
  m1.pd.2a/2b are stated for m1.pd.1 only. No open deck codes the rule:
  open_pdks sky130.lydrc and sky130.tech (0ec4fa6), mpw_precheck
  sky130A_mr.drc (0941bdc) and efabless sky130_klayout_pdk (dace518) have
  no waffle-drop density check. Cadence's SKY130 Pegasus deck (a no-NDA
  release under the Cadence Public License, v0.0_2.12) leaves it commented
  out in Include/m1.drc.pvl, with the note "Unclear if a step should be
  used; maybe 350um ?" and with bands chosen as [low, high). Its DRM of
  2025-07-22, which says it uses information from SkyWater, says
  m1-m4.RC.pd1-6 "are obsolete and removed". It also says cmm*/waffleDrop is
  not supported and should be replaced by metX/fill_block (warning
  mX.oldfill.2). Writing the rule would mean guessing a step, so GPurify
  leaves it out. The sky130 deck does carry that DRM's "Rules for Obsolete
  Fill Layers" (diff/poly/li/m1-m5 .oldfill.1 and .2) as warnings on the
  retired fill and waffle-drop layers. The manual and the rule's caption
  give cmm3's waffle drop as 107:52; the layer map the Pegasus rule reads
  (Include/layer_def.drc.pvl line 538) and google/skywater-pdk
  gds_layers.csv give 107:24, which the deck reads.
- sky130: the IR-drop rules (ct.irdrop.1-3 and via.irdrop to
  via4.irdrop.1-4: "for n contacts on the same connector, mcon area pre-
  and post- Cu conversion must differ by no more than" 0.0-0.9) are not
  checked. `gpurify xor` finds every region where a cut layer differs
  between two layouts. The rules are flagged CU (Cu back end only) and IR
  (compare the Al database with the slotted Cu database). sky130 offers no
  Cu back end: Cadence's DRM says "CU option is not currently offered for
  this PDK" and lists mcon.IR.1-3 as "Rule not implemented", and
  google/skywater-pdk issue 28 is still open on removing the Cu rules. The
  text does not say what a connector is. Its descriptions are cut short
  ("…"), and the via rules say "mcon area". The unit column's "µm" was
  added by a script in google/skywater-pdk 9039be3 (2020-11-06, "Unit
  column generated"), not by SkyWater, and the June 2020 import has no unit.
  The only public code for any of these rules is open_pdks sky130.lydrc
  lines 464-467. It reads ct.irdrop.1-2 as a single-layout li enclosure of
  1-10 or 11-100 mcons (0.2/0.3 um), runs that only under its CU switch,
  and leaves via*.irdrop "not coded because not understandable". That
  reading uses only one layout, which does not match the IR flag.
- sky130: the periphery rules also apply inside SRAM cores (`areaid.ce`).
  The implant-enclosure rules nsd/psd.5a and 5b on diffusion and taps that
  butt each other are measured straight out from each edge (see
  `enclosure(E, L)` above); nsd/psd.7 is checked only on shapes that butt
  nothing. poly.4 measures corner to corner
  where the manual measures parallel edges only, so it can over-report, and
  covers only poly that touches no diffusion.
- IHP: parasitic area capacitance other than Metal1 is computed from the
  documented layer heights and dielectric constants, and fringe capacitance
  is zero. Its antenna rows count a source/drain or tap Activ piece of at
  least 0.16 µm² as a protection diode (Ant.e/f), where IHP's own KLayout
  deck sums a net's diode area and counts it above 0.16 µm², so a net
  protected only by several small pieces is held to the no-diode limit here.
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
| DRC-002 | Allowed edge angles | partial | 45-degree and acute edges load and angle checks them; with no layer, drawn layers only (F63, fixed). Since H12 derived layers compute on 45-degree edges and min_width, notch, min_spacing, min_spacing_diff, min_area, min_enclosed_area, min_edge_length, forbidden, must_be_inside, must_contain, min_enclosure, noncoincident_enclosure, asymmetric_enclosure and adjacent_enclosure measure them (the last two on rectangular inner shapes) (hand-derived and under all 8 grid symmetries, tests/drc_octilinear.rs; against the KLayout mirror on random 45-degree layouts, docs/klayout-mirror.md a8, and against gf180mcu's foundry deck on its fd_pv unit structures, tests/foundry). Every other geometric kind still records Refused on a 45-degree layer (max_width, cut_size, the end-of-line, run-length, corner, wide and table spacings, net_spacing, cheesing, density, full_width, max_enclosure, an enclosure with a wire band, extension, overlap, tap distance, multi-patterning and edge kinds among them); an angle other than a multiple of 45 degrees is Refused by every kind |
| DRC-007 | Label / pin / text rules | partial | Pin-in-drawing is expressible. A label on no net aborts extraction (PortError::OrphanLabel in topology::port::bind_ports_into): caught, but fatal, not a rule. Pin centre spacing is not expressible |
| DRC-015 | Discrete / allowed width set | partial | width(L; allowed: [..]) holds each merged figure's narrowest width to a list (sky130 rpm.1b-1f), and open_last: true leaves the last width open, as LEF58 WIDTHTABLE does. Missing: WIDTHTABLE's fracture into rectangles, which neither LEF 5.8 (no method named; its Figure 1-32 only shows an L's two arms) nor OpenROAD (TritonRoute reads only an ORTHOGONAL table's first width) defines, so WRONGDIRECTION (a list by wire direction) is missing too; ORTHOGONAL; ASAP7 M4.W.3/W.4 (no even multiple of the minimum width) |
| DRC-016 | Wrong-direction width or spacing | partial | width(E) and facing_space(E) on L.edges().horizontal() or .vertical() measure in one direction (ASAP7 M4.W.1, W.5, S.1, S.2); LEF58_SPACING WRONGDIRECTION with NONEOL and PRL is facing_space(L.edges().vertical().with_length(>= w); prl: p) on a horizontal layer, as TritonRoute's checkMetalSpacing_wrongDir reads it. Missing: its LENGTH qualifier, which no public text defines and TritonRoute drops (DRT-333), and a negative PRL (dropped too, DRT-334) |
| DRC-020 | Minimum step / edge length / jog | partial | min_step(L; ..) is LEF 5.8 MINSTEP's MAXEDGES, OUTSIDECORNER, INSIDECORNER, STEP and LENGTHSUM; min_step(L; adjacent \| between_eol ..) is LEF58_MINSTEP's MINADJACENTLENGTH (with NOADJACENTEOL and EXCEPTRECTANGLE) and NOBETWEENEOL as OpenROAD's TritonRoute checks them (no public LEF text defines LEF58_MINSTEP). Missing, because OpenROAD parses them but TritonRoute never checks them and no public text defines them: MINADJACENTLENGTH's CONVEXCORNER, CONCAVECORNER and second length, MINBETWEENLENGTH with EXCEPTSAMECORNERS, and NOADJACENTEOL without MINADJACENTLENGTH |
| DRC-021 | Feature length min/max | partial | Edge length is length(E) (ASAP7 type L); a straight feature's length is its box's longer side, forbidden(L.with_bbox_max(< len)) (sky130 mf.2, IHP Rsil.f). A bent feature's length along its path has no public definition: IHP's own deck checks Rsil.f and Rppd.e as a width in every direction (sg13g2_maximal.drc ext_width 0.5), open_pdks sky130.lydrc flags mf.2 only on a fuse whose every edge is 7.2, and Magic has no fuse rule |
| DRC-027 | Two-widths spacing table | partial | TWOWIDTHS is two_width_spacing_table (both widths, a run per width). Missing, with no public definition: a negative PRL (LEF 5.8 says to read it as in PARALLELRUNLENGTH, whose text never defines a negative run; TritonRoute clamps it to 0 and compares the run with >= where LEF says >, a documented implementation difference), and LEF58_SPACINGTABLE's WRONGDIRECTION, SAMEMASK, EXCEPTEOL and EXCEPTWITHIN (absent from the public LEF text; OpenROAD parses them, TritonRoute never reads them) |
| DRC-028 | Influence / stub spacing near wide metal | partial | attached_wide_spacing holds LEF SPACING RANGE INFLUENCE (a stub within influenceLength of the wide wire inherits its spacing; LEF example tested); its stub-width RANGE and SPACINGTABLE INFLUENCE (two stubs near a wide wire) are missing, and the square growth holds a little more near a wide corner (fails closed) |
| DRC-029 | End-of-line spacing | partial | eol_within_spacing adds LEF WITHIN, PARALLELEDGE, TWOEDGES and LEF58 ENDTOEND; ENCLOSECUT, the LEF58 MINLENGTH/MAXLENGTH, ENDPRLSPACING and WRONGDIRSPACING qualifiers, and the ENDTOEND extensions are missing |
| DRC-030 | EOL extension / keep-out | partial | eol_keep_out checks the LEF58_EOLKEEPOUT box (backward, side, forward); its EXCEPTWITHIN, CORNERONLY and CLASS qualifiers, and LEF58_EOLEXTENSIONSPACING, are missing |
| DRC-031 | Tip-to-tip / tip-to-side by width class | partial | tip_spacing_table classes both facing edges by length (A7 M1.S.1-S.5); M4.S.3 (tip to tip between lines on adjacent tracks with no common run) is corner_space(met4; corner_to_corner: false, except_eol: none) >= 40nm, since lines on adjacent tracks are 24 apart (M4.W.1 on the 48 track pitch of M4.AUX.2) and the larger axis gap is the tip gap. Missing: M4.S.4, tip to tip between lines on adjacent tracks that share a run, which the DRM's text and figure leave undefined (lines sharing a run have no tips facing each other) |
| DRC-032 | Corner spacing (convex/concave, corner-to-corner) | partial | convex_corner_spacing adds LEF58 CONVEXCORNER (the larger axis gap, CORNERTOCORNER Euclidean) and EXCEPTEOL; CONCAVECORNER, the WIDTH table and the SAMEMASK, CORNERONLY, EXCEPTJOGLENGTH and EXCEPTSAMENET/SAMEMETAL qualifiers are missing; sky130 poly.4 over-reports (limitations.md, "Shipped decks") |
| DRC-033 | Forbidden spacing ranges | partial | forbidden_spacing holds a closed gap range between facing edges running longer than a PRL (LEF58_TWOWIRESFORBIDDENSPACING as drt reads it); its MINSPANLENGTH/MAXSPANLENGTH, LEF58_FORBIDDENSPACING's WIDTH/WITHIN/TWOEDGES, and a preferred direction are missing |
| DRC-034 | Maximum spacing | partial | max_space(C[, A]) <= len flags a cut with no other cut whose centre is within the limit, as OpenROAD reads LEF58_MAXSPACING maxSpacing CUTCLASS (FlexDR::fixMaxSpacing and getLonelyVias: a via of the class with no other via cut of any class or net within the spacing, centre to centre, inclusive). No public LEF text defines LEF58_MAXSPACING; OpenROAD reads it only in its router's repair pass (TritonRoute's checker never reports it), so this reading is the only public one. A maximum spacing between wires on a routing layer has no public source |
| DRC-035 | Pitch / exact pitch / on-track | partial | exact_pitch holds neighbouring rectangles to an exact centre-to-centre pitch (A7 FIN.S.1, GATE.S.1); track grids (LEF PITCH, LEF58_PITCH, LEF58_RIGHTWAYONGRIDONLY) are missing. Also covers gridded-design rules (Liebmann 2003; Jhaveri 2010) |
| DRC-036 | Span-length table | partial | span_length checks every chord against the x and y span lists (LEF58_SPANLENGTHTABLE with and without WRONGDIRECTION); ORTHOGONAL and EXCEPTOTHERSPAN are missing |
| DRC-037 | Bent / 45-degree features | partial | angle checks the edges; width, notch, space, area, hole area and edge length measure 45-degree shapes (H12); every other geometric kind records Refused on a non-rectilinear layer |
| DRC-038 | Diagonal width / spacing | partial | Width, notch, space and edge length measured exactly on 45-degree edges (Euclidean; facing edges, necks, acute tips 0, and an axis edge against a 45-degree one at 135 degrees as KLayout's Euclidean width pairs them), H12, against the KLayout mirror on random 45-degree layouts (docs/klayout-mirror.md a8); LEF DIAGWIDTH/DIAGSPACING as separate limits for diagonal edges are not a kind |
| DRC-042 | End-cap / one-of-two-adjacent-sides enclosure | partial | One of two adjacent sides is adjacent_enclosure, each edge read at the corner as sky130A_mr.drc does (F2); IHP M1.c1's end cap is the opposite form; LEF58_ENCLOSURE EOL (an overhang only toward a metal end of line) is not modelled: no public source defines it beyond its syntax |
| DRC-043 | Width-dependent enclosure | partial | WIDTH bands only: LEF EXCEPTEXTRACUT and LENGTH, and LEF58_ENCLOSURETABLE, are missing |
| DRC-051 | Abutment / butting edges | partial | Butting edges are A.edges() and B.edges(): sky130 difftap.4 is length(E), difftap.5 and .7 space(E, F) (Euclidean, so diagonal), and difftap.6 the butting edge lengthened 1 grid past each end with .extended(), checked for diff or tap there, as open_pdks sky130.lydrc codes it. Edge enclosure misses diagonal gaps (limitations.md, Rules that can pass a layout signoff would flag) |
| DRC-053 | Exact alignment / width match across layers | partial | ASAP7 V1.M2.AUX.2 only. LEF58_SPACING EXACTALIGNED (the spacing of exactly aligned line ends) has no public definition: it is absent from the LEF 5.8 text, OpenROAD has no parser for the metal form, and TritonRoute skips the cut form (io.cpp) |
| DRC-055 | Direction-dependent (S/D-direction) spacing | partial | Facing edges in both axes, as sky130's open_pdks KLayout deck (sky130.lydrc) reads lvtn.3b. Magic's sky130.tech derives the S/D direction from the gate (edge4way from the FET edges, 0.415 into the source and drain). The two public decks differ in direction and distance and the manual does not say which is meant: a documented implementation difference |
| DRC-063 | Cut-class spacing tables | partial | Class-pair SIDE/END cells only: the PRL second value, CENTERTOCENTER and CENTERANDEDGE cells, SAMENET/SAMEMETAL and LAYER tables, EXACTALIGNEDSPACING and LEF SPACINGTABLE ORTHOGONAL are missing |
| DRC-065 | Via stacking / cross-layer cut spacing | partial | via_stack counts every cut as a single-cut via, so a double-cut via does not interrupt a stack (fails closed); LEF SPACING LAYER STACK (aligned same-net cuts exempt) is not modelled |
| DRC-066 | Minimum cut count / redundant via | partial | LEF MINIMUMCUT's LENGTH ... WITHIN form (thin wires beside a wide one) and LEF58_MINIMUMCUT's cut classes and AREA are missing |
| DRC-067 | Metal-width-dependent via choice | missing | — |
| DRC-075 | Wide-metal slotting | partial | Slot required is a kind (cheesing); slot geometry uses the generic kinds; slit density over a plate is region_density (IHP Slt.i). Not definable from public sources: GF180 MSLOT.4b (slot space, maximum 30 um) does not say which slots a maximum spacing holds, and GF's own KLayout deck (fd_pv mslot.rb) codes MSLOT.4 as a minimum only; MSLOT.6 (slots across the metal width should be staggered) is in the manual's Appendix B, rules not coded, and states no geometry |
| DRC-081 | Net spacing between two layers / on wells | partial | space(A, B; nets: different) spaces two layers, overlap included; a layer derived from a conductor carries the net of the conductor shapes under each of its shapes (one net, or the rule refuses), so sky130 hvnwell.8 (HV n-well, nwell under hvi, to any nwell) and hv.nwell.1 can be written (the shipped sky130 deck does not yet carry them). Missing: nwell.7 and vhvi.8 need deep n-well and the vhvi-tagged well as nets, which no shipped deck connects, and hv.nwell.1's text tags (shv_nwell) are not read |
| DRC-084 | Floating interconnect / must-join ports | partial | Flags conductor shapes that reach no device (sky130 x.22's floating metal; its exemption labels poly_float .. m5_tie and the areaid.stdcell exclusion are not read). Must-join ports (LEF58_MUSTJOINALLPORTS): a pin's label on disjoint shapes the layout does not join is lvs.label_conflict, an error, unless the deck makes the name must-connect (lvs connect_implicit, joined later: a warning); LEF itself is not read |
| DRC-095 | Seal ring | partial | Geometry through the generic kinds; one seal ring per chip (IHP Seal.m) is count(seal) <= 1 with >= 1, nothing outside it (Seal.l) forbidden(L not (seal or seal.holes())), the seal ring at the origin (sky130 x.19) origin(seal). Missing: a partnum beside it (x.27: if a seal ring is present, a partnum*block pcell is required unless a text says partnum_not_necessary), a condition on one layer's presence that no kind states, and the partnum is a pcell no public deck marks |
| DRC-097 | Frame / die / cell-name rules | partial | Frame, scribe and LBE geometry is expressible with the generic kinds (sky130 x.16, x.21, x.23a-d, x.28; IHP LBE.*), e.g. forbidden(sl and diff), forbidden(lbe.holes()). Cell-name rules are written with `in_cells`/`not_in_cells`: sky130 x.25 (pnp.dg only within named cells) is written, and x.12's *_buildspace exemption is expressible; a maximum cell-name length (CAL:DRC MAXIMUM CELL NAME LENGTH) is forbidden(L.in_cells("?...?*")) with n+1 `?`, which flags only a long-named cell that holds or places a shape on a listed layer. The seal ring's corner at the origin (x.19) is origin(seal). Missing: the pcell rules x.26-x.27 (per placement, not per shape) |
| DRC-102 | Pre-coloured (MASK) same-/different-mask spacing | partial | Mask shapes as layers: same-mask spacing is space(L and mask), different-mask space(L and m1, L and m2), mixed coloured and uncoloured shapes patterning with anchors. Not definable from public sources: PARALLELSAMEMASK is a keyword OpenROAD's odb parses (lefTechLayerSpacingEolParser) and no checker reads; the public LEF/DEF 5.8 reference does not define it, nor which shape the parallel edge must share a mask with |
| DRC-111 | DFM scoring of recommended rules | partial | dfm_score(L[, outer]; check: space\|width\|enclosure, required, recommended, rate) >= sign-off: each finding of the check at the recommended value scores 0 at the required value and 1 at the recommended one, and the design scores their product with the rule's failure rate, as GlobalFoundries scores DFM rules with ICV (arXiv:1805.10016, Equation 2). Values deck-supplied; no public deck states them. The paper prints neither the curve between the margins nor its per-finding function f(score, FR): the line and 1 - FR (1 - score) are GPurify's reading. Missing: checks other than space, width and enclosure, and cell-level scores |
| DRC-112 | Critical area analysis | partial | Shorts between merged figures of one layer, for one square-defect size (critical_area) or averaged over a defect-size distribution the deck samples (critical_area(L; radii, weights): sum of weight x A(r), Stapper's average critical area). Values deck-supplied; no public deck states them. Missing: opens (a defect cutting a wire), and nets rather than figures |
| DRC-113 | Litho / CMP simulation hotspots | partial | CMP hotspots a public model defines: a density step between neighbouring windows (max_delta) and a first-order thickness excursion, sensitivity x (density - target), over a window standing for the planarization length (density_cmp, Ouma2002). Litho hotspots (aerial-image, process-window simulation) and a full CMP topography simulation need a foundry's calibrated optical, resist and polish models, which no open PDK publishes; foundry hotspot pattern libraries are not public |
| DRC-114 | Pattern-matching DRC | partial | pattern(L; window, shapes, ignore): every window placement, in the eight orientations, where L inside the window equals a deck-supplied pattern outside its don't-care boxes (US7757190B2's pattern and anchor, matched exactly). Values deck-supplied; no public deck states them: foundry hotspot libraries are not public. Missing: ranged (fuzzy) edges and multi-layer patterns (US11487930B2, US9171126B1) |
| DRC-115 | Equation-based DRC | partial | Calibre eqDRC: a limit or condition as an expression over measured values (fact sheet 82854-F). Written as a Rust custom rule (DeckBuilder::custom, FLOW-006), which reads the layout and measures as it likes and is run and accounted as any rule; the text deck has no expression language, so a text deck cannot state one |
| DRC-116 | Curvilinear / all-angle tolerance DRC | missing | In scope since 2026-10-11 (was: Rectilinear only) |
| DRC-117 | Via redundancy scoring / via doubling | partial | Counts cuts within a distance; single cuts are the via term of the CAA yield model (Siemens WP 81850). The redundant-via rate (Xu et al., ASP-DAC 2005: 1 - dead/total vias) is via_redundancy(cut, lower, upper; pitch, space): a single-cut via is dead when no second cut fits at pitch on both its shapes, space from every cut. Values deck-supplied; no public deck states them. Missing: via doubling itself, a layout edit |
| DRC-121 | Selection by shape class, net or angle; covering/overlapping; anisotropic size | partial | No selection by net: derived layers are computed before nets are extracted, and connectivity may read derived layers, so a layer selected by net needs a second derivation after extraction (a design is in the X2 report). A derived layer does carry its conductors' nets for net spacing (DRC-081) |
| DRC-123 | Hierarchical processing | partial | Flattened at load (gds::Library::flatten); a scale issue, not correctness. Hierarchical processing (KLayout deep mode) needs per-cell rule evaluation with context-dependent interactions; a design is in the X2 report |
| DRC-124 | Layout input exceptions (missing cell reference, duplicate cell, magnified or angled placement, odd or zero path width, spike, vertex count) | partial | Each case has one answer in the GDS reader: a reference to no structure (MissingCell), two structures of one name (DuplicateCell, refused since X2; before, a reference resolved to either), a placement off a quarter turn, a fractional magnification, a PATH of odd or zero width (refused); an integral magnification read as the scaling it states, a spike read as the region its ring encloses, any vertex count read whole. Missing: Calibre's grading, each case an error or a warning by the deck's choice: a refusal stops the run with no report, and a spike or a magnified placement is read without a note |
| DRC-125 | Protrusion width (narrow protrusion from wide metal) | partial | protrusion_width(L; wide: w2) >= w1: a part narrower than w1 (no w1 square covers it) attached to the part where a w2 square fits, LEF PROTRUSIONWIDTH w1 LENGTH 0 WIDTH w2. Missing: a positive LENGTH, which exempts a long protrusion: LEF/DEF 5.8 measures it 'by the shortest possible path among all of the protrusion wires ... by the shortest outside edges' and settles the reading only by figure; OpenROAD parses and stores the statement and checks nothing, and no open foundry rule states one |
| DRC-126 | Cut keep-out zone by cut class (end, side and spiral extensions) | partial | keep_out_zone(L; class, to, end_side, end_forward, side_side, side_forward): another cut, of class `to` when given, overlapping the side or end zone of a cut of `class`, the zones as OpenROAD's detailed router bloats a via (checKeepOutZone_main; strict overlap). Missing: the EXTENSION form without ENDEXTENSION, SPIRALEXTENSION and EXCEPTEXACTALIGNED, which OpenROAD parses but never checks and no public text defines; a square class (the router skips square vias) is refused |
| DRC-127 | Cell edge-type spacing between placed cells | missing | Not definable from a layout: an edge type is a LEF macro attribute (LEF58_EDGETYPE) that a GDS does not carry and no public convention draws; OpenROAD's detailed placer reads it from LEF. Spacing by type between facing cell edges, with EXCEPTNONFILLERINBETWEEN and the other options, needs the LEF read |
| DRC-128 | Self-aligned multiple patterning (SADP/SAQP mandrel, spacer, cut) legality | missing | Distinct from LELE colouring (DRC-100). Not definable from public sources: the ASAP7 DRM names its SADP and SAQP layers (FIN SAQP, GATE and M4-M7 SADP) but states their rules as widths, spaces and pitches; the mandrel/non-mandrel assignment and cut-mask legality of Yu and Pan (2016) were not obtained, and no open deck checks them |

### Layout against schematic (LVS)

| Id | Check | Status | What is missing |
|---|---|---|---|
| LVS-002 | Implicit joins (same-label disjoint shapes, must-connect) | partial | Same-label disjoint shapes are not joined by default: reported as label_conflict, only with --reference (lvs::check_layout), located on the labelled shapes (F70). The deck's `lvs connect_implicit "pattern"` (glob) and `lvs connect_explicit "a" "b"` declare must-connect nets, joined for the comparison (lvs::join_must_connect, KLayout connect_implicit/connect_explicit), their open still reported as a label_conflict warning, as KLayout warns for a top cell. LEF58_MUSTJOINALLPORTS is not read |
| LVS-005 | Short isolation / localisation | partial | Reported in every run, DRC-only included, naming both labelled shapes, located at the first; no abort. The short's path follows as lvs.short_path: the fewest polygons joining the two labelled shapes through the extraction's joins (NetTable::path, breadth first, deterministic), one row per step between consecutive polygons (Calibre LVS ISOLATE SHORTS, ICV ShortFinder); a cut is no step, and the path is the shortest, not every route. Opens are not isolated: one reference net split over several layout nets shows only as label_conflict where labelled, never as an open path (CAL:LVS ISOLATE OPENS) |
| LVS-010 | Circuit without partner / hierarchical compare | partial | The reference is flattened below its top (Netlist::flatten_top) and compared device by device, so a missing block is a mismatch, and a reference instance none of whose devices paired is named (lvs.unpaired_instance, LVS-017); there is no per-cell matching and no circuit-mismatch report naming a cell; a reference flattening to more than 2²⁸ devices, nets and instances is refused (NetlistError::TooLarge), and one nesting deeper than the layout's 1024 levels (NetlistError::TooDeep, F96); flattening is linear in what it places (F95); no cell-correspondence list naming which layout cell matches which reference subcircuit (KL:same_circuits, NG:equate classes). Cell-by-cell matching needs the layout extracted per cell, its nets crossing cell boundaries as pins (KLayout's hierarchical net extraction), where the layout is flattened on reading; limitations.md, "Hierarchical comparison", gives the design that keeps the flat comparison its oracle |
| LVS-017 | Subcircuit instance unpaired | partial | The comparison is flat, and decides the verdict. Flattening records each placement it expands (Netlist::placements, its path, cell and the run of flat device rows it holds), the comparison traces each reduced reference device back to its rows (compare_traced), and a mismatch names, as lvs.unpaired_instance with the path and cell in the report, each reference instance none of whose kept devices paired, the outermost such (KLayout's subcircuit with no partner). Instances are not paired as units: a partly unpaired instance is not named, the layout has no instances to name (it is flattened on reading), and where a missing block perturbs its neighbours' nets refinement leaves them unpaired too, so an instance beside the missing one may be named with it |
| LVS-033 | Black boxes | missing | — |
| LVS-042 | Semi-series MOS | missing | — |
| LVS-047 | Logic-gate recognition | partial | `lvs recognize_gates` (off by default): plain transistors of one model and identical parameters, each on a gate of its own, stacked in series through nets only the two touch that are no port (or labelled), or in parallel on one source/drain pair, become one device with interchangeable gates, Silvaco Guardian LVS's series and parallel reduction with different gate terminals, on which its INV/NAND_N/NOR_N recognition rests, so a NAND or NOR wired in another input order matches. A merged device is not merged again, so AOI/OAI groups in another order still mismatch (Guardian recognises them; the public note gives their swap rules only by figure); transistors of different sizes never merge. Calibre's LVS RECOGNIZE GATES (ALL/SIMPLE/NONE) is named publicly but not defined; its manual is not public. Proved against a brute force over every reassignment of a group's gates, and by the relation that a reassignment keeps a match; neither Netgen nor KLayout recognises gates, so no differential |
| LVS-048 | Filter unused devices | missing | — |
| LVS-060 | MOS W, L, nf, m, AS/AD/PS/PD, bulk | partial | w and l from the marker bounding box; nf = 1 per channel, summed by parallel merges; marker area and perim. Compared per paired device, only where its card states the parameter (F68). as/ad/ps/pd from the source/drain polygon (gate edge included, BSIM4 perMod=1), a shared diffusion split evenly, compared at the channel end, symmetric channel nets paired the way the diffusions agree (F98), summed in parallel merges, refused in series; not measured where drawn in pieces; bulk is dropped when the layout has none |
| LVS-061 | Resistor R/L/W | partial | w/l from the resistor body's bounding box; r = sheet·l/w when the device statement gives sheet; positional R1 a b 1k rpoly is read as r. A bent body reads its bounding box; a card with no model is the deck's one resistor (F86); resistors merge in series only under `lvs topology relaxed` (LVS-043) |
| LVS-062 | Capacitor C/A/P | partial | area and perim measured; c = area_cap·area + fringe_cap·perim when the deck gives them; a positional C value is read. No w/l; KLayout A/P read as area/perim (F87); a C card with no model is the deck's one capacitor (F86) |
| LVS-064 | BJT AE/PE/NE, multi-emitter | partial | ae/pe from the emitter terminal's polygon (B27); marker area and perim; no NE or multi-emitter. sky130 bipolars have no recogniser (limitations.md, "Shipped decks") |
| LVS-065 | Inductor | partial | `device inductor <marker> model "m" terminals [a, b] inductance 2nH`: a two-pin device whose ends are interchangeable (KLayout DeviceClassInductor), its inductance the deck's value for every device of the recogniser (a foundry's fixed inductor cell; values deck-supplied, no public deck states them), compared as `ind`; SPICE `L` cards (positional value or l=, read as ind, never a length) and Spectre's inductor primitive read; strict, parallel inductors count m; under `lvs topology relaxed` they combine harmonically in parallel and add in series (KLayout InductorDeviceCombiner), as Netgen does under `parallel {value par}` and `series {value add}`. Not extracted: a spiral's own geometry (turns, track width, spacing, diameter, as IHP's inductor2 LVS compares) and an inductance computed from it |
| LVS-067 | Subcircuit-modelled devices (rsubcircuit, fixed cells: VPP, ESD) | missing | sky130 VPP caps have no marker (limitations.md) |
| LVS-073 | 3D / system LVS across dies | partial | gpurify system: dies placed by a system description (origin, quarter turns, mirror), bonded where rectangular bumps of facing faces overlap; system.unbonded_bump, then system.open and system.short pin by pin against the system netlist's die instances and top ports, then the flat device comparison. Bumps must be rectangles and every die on one grid; cross-die bump alignment, size and spacing (DRC-129) and 3D extraction (PEX-015) are not checked |
| LVS-074 | Layout-dependent-effect parameters (LOD SA/SB/SD, WPE SCA/SCB/SCC) | partial | `lvs lde "model" od <layer> max <length> [well <layer> scref <length>]` measures on the model's transistors BSIM4's sa and sb (gate ends to active-area edges, BSIM4's effective 1/(SA+L/2) average over a non-straight edge, compared as a pair smaller first since the stress model reads only their inverse sum) and, with a well, sca, scb and scc from the median distances SC1..SC4 between the gate edges and the first well edge in Silvaco's public closed forms (its worked example reproduced); a distance past max reads as max. Layers, max and SCREF deck-supplied; no open PDK deck states them. Missing: SD (finger spacing within one instance; a device here is one channel), a gate that is no rectangle, OD or well holes (read solid) |

### Electrical rules (ERC)

| Id | Check | Status | What is missing |
|---|---|---|---|
| ERC-A14 | Hierarchical / macro-pin antenna | missing | Not implemented: LEF/DEF 5.8 Appendix C defines the hierarchical calculation (a pin metal area plus ANTENNAPARTIALMETALAREA per layer, ANTENNAGATEAREA and ANTENNADIFFAREA per pin and oxide model, the CAR seeded at the pin layer with ANTENNAMAXAREACAR or ANTENNAMAXCUTCAR), but it needs a LEF macro reader in the ERC flow, which takes GDS only. On full GDS the macro own geometry is flattened and checked by antenna and antenna_electrical, so the pin model matters for abstract views. OpenROAD 26Q2 reads none of ANTENNAPARTIAL* or ANTENNAMAX*CAR, so it is no reference for them |
| ERC-A15 | Fix hint: required diode area | missing | Not implemented: no public source defines a required diode area. Checked: LEF/DEF 5.8 Appendix C (ANTENNADIFFAREARATIO, ANTENNAAREADIFFREDUCEPWL, ANTENNAGATEPLUSDIFF, ANTENNAAREAMINUSDIFF) defines the ratio a diode changes, not the fix; OpenROAD repair_antennas adds diode cells one at a time until the ratio passes (at most 10 per gate) and treats CAR violations with one diode per net; KLayout antenna_check raises the threshold by a factor per um2. Inverting these is a derivation, and a LEF PWL table may fall, so the least area needs a scan; where the inserted diode joins the net (which etch stages see it) is a router choice no source fixes. A finding also carries one measured value and one limit, so a hint needs a second number per finding |
| ERC-C8 | Path voltage vs device failure (ESD window) | partial | The pin voltage under a forced current, with clamp_voltage each conducting clamp holding a turn-on or holding voltage besides its on-resistance (WP2 2.9.3: Vpad = Vdiode_on + Rdiode_on I + Rbus I + Vclamp_on + Rclamp_on I); values deck-supplied, no public deck states them. Not modelled: each protected device own terminal voltages (the pin voltage is checked), a snapback clamp trigger (Vt1) before it conducts, one voltage per row for every clamp |
| ERC-C9 | CDM checks (bus inductance, local clamps, driver/receiver ground R) | partial | Local clamps at a domain-crossing receiver, and with max_ground_resistance the driver/receiver ground resistance (Etherton2015: a unit current between the driver and receiver ground attach points through both grounds and their coupling diodes at a deck on-resistance); values deck-supplied, no public deck states them (Etherton 2 ohm is an example). The bus inductance a CDM discharge sees is not checked: no public source states a static check or a limit (TR18-01 Rule 6.4.2 is a title; Industry Council WP2 describes it as a transient effect) |
| ERC-C12 | Package / 2.5D / 3D ESD | partial | gpurify system: system.esd_package holds each package pin to clamps reaching a power and a ground rail through the assembled system (any die); system.esd_d2d holds each die-to-die bump to its own die alone (JEP196). Path existence only: no resistance, current, clamp size or CDM level; no wafer-on-wafer exemption; package R, L and C not modelled |
| ERC-C13 | System-level ESD | partial | gpurify system: system.esd_iec holds each package pin the system names as exposed to both rails through clamps of the models it names as system-rated. System robustness itself (board TVS, residual pulse, soft failures, powered latch-up) needs simulation, not a layout (WP3 Part I 6.3.1; TR18-01:7) |
| ERC-D5 | Voltage-aware aggressor/victim | partial | Aggressors by pad connection or layer, and with bias and forward by voltage: a junction the intent voltages can forward-bias against the well or tie it lies in (GF 14.3.2: P+ COMP above Vdd, N+ COMP below Ground; CVC: minimum source below maximum bulk). Off-chip over- and undershoot at a pad stays the pad selection. The whole victim polygon is held to the limit, not only its part within within: IO.1 (b) does not say which |
| ERC-D9 | PMOS/NMOS devices sharing one well | missing | Not implemented: no public source says which PMOS/NMOS sharing of a well is illegal. Checked: HoganMedhat2021 names the Calibre PERC check only; the Siemens latch-up and well-connectivity articles; the free ToC of ESDA TR18.0-02; the open DRMs: GF180MCU LU.9/LU.10 (well and substrate taps at the highest and lowest potential: guard_ring_bias, ERC-D3), NW.2a/NW.2b (well spacing by potential), sky130 nwell.5b, hvnwell.8 and hvnwell.10 (LV and HV wells apart: mixed_tag, ERC-F10), IHP NW.b1 (wells on different nets apart); a bulk below its source in a shared well is well_bias (ERC-F12). Each of these is checked; which further sharing the PERC check forbids is not public |
| ERC-E11 | Dynamic / vectorless IR | partial | Vectorless worst cycle: every load on a net switches in phase once, a triangular pulse from its budget, toggle rate and rise time, against the net's decap; an RC grid with no package, bump or wire inductance (L di/dt), and one feed point per supply (limitations.md, "Power grid") |
| ERC-E12 | Stress voiding / slotting | partial | cheesing requires a slot in wide shapes, and the slot geometry (IHP Slt.*, gf180 MSLOT.*) is DRC width, enclosure and spacing; JEP139 and JESD214 are stress-migration test methods that state no layout rule. Checked for stress-voiding rules beyond slotting: sky130 m1.12-m3.12 and m4.12 (slot and remove vias over 3.2 and 10 um) apply only to the copper back end the open sky130 does not offer; GF180 MSLOT.7/MSLOT.8 (vias 0.2 um from a slot) and its via-array spacing are DRC enclosure and spacing; IHP Slt.h1-h4 (via to slit) likewise. No public rule limits vias landing on wide metal, so that part has no definition |
| ERC-F4 | HCI susceptibility flag | missing | Not implemented: no public source defines a hot-carrier stress condition that a static voltage range can test. Checked: Siemens WP 81822 Eq. 1 (Vsg,max >= Vsd,min, after Renn et al. 1996: PMOS ageing peaks at Vg = Vd) holds for every switching PMOS (an inverter: Vsg,max = VDD, Vsd,min = 0), so over static ranges it flags all of them; GF:14.1.4.1 bounds Vds by Vddmax (1.1 x Vdd), which is drain_source (ERC-F3), and ties degradation to the fraction of time a FET conducts, which no static range gives; JESD28 and JESD60 (stress at peak substrate or gate current) are behind a login; sky130 states no hot-carrier rule; the open CVC checker tests Vds overvoltage only. A threshold separating stress from switching would be a guess |
| ERC-F14 | Power-intent supply connectivity (power switches, always-on and retention cells on the supplies the UPF declares) | partial | The power intent is the design intent: a supply some declared power state turns off is switched, the rest always on. power_switch flags a switch (a listed transistor model) not joining an always-on supply to a switched one of the same role (Liu-DVCon PG rule 3; ISLPED2014 input and output supply ports), and one whose control floats in a declared state (Liu-DVCon: control from an always-on path). Not checked: retention cells (save/restore from always-on logic, the retention supply), always-on cells in a switched domain, standard cells on the virtual rather than the real net: the intent does not say which cells are which. UPF itself is not read; IEEE 1801 is free through IEEE GET but was not read (check-sources.md 5) |
| ERC-H2 | Analog constraints (symmetry, common centroid, matching, orientation, dummies, WPE, STI) | partial | matching checks a designer-marked group (a group layer polygon): identical units (model, W, L: GF MP.1, MP.2a; P14), parallel channels (MP.7, perpendicular only) and a common centroid within a deck tolerance (Karmokar2022, Sarhan2019). Not checked: MP.7 anti-parallel current (source and drain are in extraction order and fingers alternate them), dummies (MP.4), identical surroundings and STI context (MP.5, MP.10), well-proximity distance, axis symmetry. The GF guidelines are not coded in its own deck |
| ERC-H3 | Netlist path checks (gate to ground within N devices; net types) | partial | gate_path: a MOS gate whose shortest path to ground (or power) through MOS source/drain and resistor pins passes more than max_devices devices, or none (P12: every transistor gate must have an electrical path to ground that passes through no more than three other devices). P12 states the rule as an example and does not define how devices are counted; one per device passed is its plain reading. Net types beyond the intent power and ground (P12 by name pattern, attached device, type sets) are not modelled |

### Parasitic extraction (PEX)

| Id | Check | Status | What is missing |
|---|---|---|---|
| PEX-003 | Coupling C (same-layer and cross-layer) | partial | The field solve meshes each horizontal interface of the stratified stack (each pex row's dielectric fills up to the next row's height) over a window around the solved nets, FastCap's multi-dielectric formulation; the polarisation beyond the window is left out, and the collocated interface rows make the matrix reciprocal only to the discretisation (refused past 5 %, reported symmetrised). No conformal dielectrics, no per-layer dielectric beside a wire; the closed forms see one permittivity per layer. The substrate is a grounded plane at height 0 (testing-plan F24); a shape at height 0 (well, diffusion) is a junction, out of the field and in closed form, so the field reads metal over another net's junction as coupling to ground (F73); a junction layer needs no dielectric (F94) |
| PEX-007 | Process effects (CMP thickness, temp-dependent R, nonlinear via R, colour-aware) | partial | Temperature-dependent R: the deck's temperature T nominal T0 and each pex row's tc1/tc2 give R(T) = R(T0)(1 + tc1(T - T0) + tc2(T - T0)^2), the ngspice resistor law with the coefficients PDKs publish; extraction, the power grid and lib read it. Not modelled: CMP thickness from pattern density, current-dependent via R, colour (mask-shift) effects: their models need foundry calibration data no open PDK publishes; width- and spacing-dependent thickness and sheet R, layer etch, via-coverage R (SRC:datasheet) |
| PEX-011 | Device-region (MEOL/FEOL) parasitics: gate-to-contact and gate-to-diffusion C, trench contact, via-location gate R | partial | Deck `pex_device "<model>" gate_contact_cap <c> gate_diffusion_cap <c>` (gpurify_extract::device_region): every MOS of that model gets (gate_contact + gate_diffusion)·W from its gate net to its source net and to its drain net. Values deck-supplied; no public deck states them (they come from the foundry's device cross-section). Not done: trench-contact resistance and the gate resistance a gate contact's position sets, which need a node inside the device; the exported netlists attach a device at its net's first node |
| PEX-012 | Metal-fill treatment (floating or grounded fill, virtual fill) | partial | Deck `pex_fill <layer> floating\|grounded\|ignored` (gpurify_extract::fill): a net drawn only on that conductor is a fill piece; floating pieces are eliminated from the capacitive network by Kron reduction (series couplings, coupled pieces together), grounded ones turn couplings to ground, ignored ones are dropped; the fill nets leave the output. The treatment is deck-supplied; no public deck states one. Not done: virtual fill (fill a tool would insert), and fill in the field solve (a solved net's coupling to fill is the closed form's) |
| PEX-013 | Substrate network extraction (substrate and well resistance and coupling) | missing | — |
| PEX-015 | 3D-IC extraction (TSV, micro-bump, interposer, TSV-TSV coupling) | partial | Deck `pex_tsv <cut layer> length <l> liner <t> liner_k <k>` (gpurify_extract::tsv): each cut a copper cylinder of its drawn area's radius in an oxide liner, its liner capacitance 2π ε0 k l / ln((r+t)/r) (Katti et al., IEEE TED 57(1) 2010) to ground on its net, its resistance the pex row's per cut. Values deck-supplied; no public deck states them (no open PDK has a TSV). Not done: the depletion capacitance in series with the liner, TSV-to-TSV coupling through the silicon, micro-bumps, interposer wiring |
| PEX-016 | Point-to-point resistance and net-to-net coupling report between arbitrary points | partial | `pex --p2p NET:X,Y:X,Y…` reports the effective resistance between every two points on a net (gpurify::engine::p2p over erc::power::extract_points_into: each conducting shape a chain along its long axis, sheet × squares, each cut its layer's resistance, Kron reduction to the points), and `--coupling A:B` the total coupling between two nets. Not done: current spreading across a wide shape (the chain model's), and coupling between points rather than nets |

### Flow

| Id | Check | Status | What is missing |
|---|---|---|---|
| FLOW-003 | SoC integration (macro sync, ports off grid, fill outside boundary, block/pad-ring overlap) | partial | With a DEF layout, DRC runs six integration checks (gpurify::engine::integration), each from LEF/DEF 5.8: a FILLS shape outside the DIEAREA, a component outside it, two placed components overlapping (CLASS COVER aside), a CORE cell off its ROW's sites, a DEF pin whose centre is on no TRACKS of its layer, a vertex off the LEF MANUFACTURINGGRID. Not checked: macro synchronisation (a macro's own GDS against its LEF abstract) |
| FLOW-004 | Interface DRC top vs blocks | partial | A DEF layout draws every placed block's LEF abstract (pins and obstructions, checked against KLayout's LEF/DEF reader) with the top-level routing, and DRC checks them together: top-level shapes against the blocks' boundaries. Not done: a block's own layout is not read (no hierarchical DRC; its abstract stands in), and a finding between two shapes of one abstract is not told from one at the interface |
| FLOW-005 | In-design / live DRC | partial | Shared-deck library (Philis) is the first step |
| FLOW-006 | User-programmable rules | partial | DRC custom rules as Rust fn pointers (deck::CustomRule via DeckBuilder::custom; runner owns accounting) and gpurify::cli::main_with for a binary with its own decks; ERC custom rules and a KLayout snippet per rule not yet (deck-library plan P5) |
| FLOW-007 | Fill insertion (density-driven, timing-aware) | missing | DRC-073 checks fill; this generates it |
| FLOW-008 | Incremental / ECO re-verification (changed regions or nets only) | missing | Metamorphic: an incremental run equals a full run |
| FLOW-009 | Automated DRC-clean layout enhancement (via and power-grid insertion) | missing | — |
| FLOW-010 | Clustering and triage of very large result sets | partial | `--cluster <µm>` (gpurify::engine::triage): single-linkage clusters (Sibson 1973) of each rule's violation markers at a reach, listed largest first with count and bounding box. Not done: Vision AI's other signatures (shape, context, root cause), whose definitions are not public |

<!-- end of generated block -->
