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
- `electromigration` and `reliability` use one temperature for the whole run:
  the intent's `temperature_c`, else the deck's `temperature`, else 85 °C,
  with no self-heating.
  `em_thermal` adds each wire's own Joule heating to it, but a wire heats
  only itself: heat from neighbouring wires, heat carried along a line to
  cooler vias, and resistance rising with temperature are not modelled, so a
  dense bundle of wires reads cooler than it is. Its current is the static
  budget's, so AC signal-line RMS and peak limits stay missing (ERC-E7).
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
  leaves it out.
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
| DRC-002 | Allowed edge angles | partial | 45-degree and acute edges load and angle checks them; with no layer, drawn layers only (F63, fixed). Since H12 derived layers compute on 45-degree edges and min_width, notch, min_spacing, min_spacing_diff, min_area, min_enclosed_area, min_edge_length and forbidden measure them (hand-derived and under all 8 grid symmetries, tests/drc_octilinear.rs; against the KLayout mirror on random 45-degree layouts, docs/klayout-mirror.md a8, and against gf180mcu's foundry deck on its fd_pv unit structures, tests/foundry). Every other geometric kind still records Refused on a 45-degree layer (max_width, cut_size, the end-of-line, run-length, corner, wide and table spacings, net_spacing, cheesing, density, enclosure, extension, overlap, tap distance, multi-patterning, must_contain, must_be_inside and edge kinds among them); an angle other than a multiple of 45 degrees is Refused by every kind |
| DRC-007 | Label / pin / text rules | partial | Pin-in-drawing is expressible. A label on no net aborts extraction (PortError::OrphanLabel in topology::port::bind_ports_into): caught, but fatal, not a rule. Pin centre spacing is not expressible |
| DRC-015 | Discrete / allowed width set | partial | width(L; allowed: [..]) holds each merged figure's narrowest width to a list (sky130 rpm.1b-1f). Missing: LEF58 WIDTHTABLE's fracture into rectangles and its open-ended last width, and ASAP7 M4.W.3/W.4 (no even multiple of the minimum width) |
| DRC-016 | Wrong-direction width or spacing | partial | width(E) and facing_space(E) on L.edges().horizontal() or .vertical() measure in one direction (ASAP7 M4.W.1, W.5, S.1, S.2); the PRL and NONEOL qualifiers of LEF58 WRONGDIRECTION spacing are missing |
| DRC-020 | Minimum step / edge length / jog | partial | min_step(L; ..) is LEF 5.8 MINSTEP's MAXEDGES, OUTSIDECORNER, INSIDECORNER, STEP and LENGTHSUM; LEF58_MINSTEP's MINADJACENTLENGTH, MINBETWEENLENGTH, NOADJACENTEOL and NOBETWEENEOL are missing |
| DRC-021 | Feature length min/max | partial | Edge length is length(E) (ASAP7 type L); a straight feature's length is its box's longer side, forbidden(L.with_bbox_max(< len)) (sky130 mf.2, IHP Rsil.f); a bent feature's length along its path is not measured |
| DRC-027 | Two-widths spacing table | partial | TWOWIDTHS is two_width_spacing_table (both widths, a run per width); a negative PRL and the LEF58_SPACINGTABLE qualifiers (WRONGDIRECTION, SAMEMASK, EXCEPTEOL, EXCEPTWITHIN) are missing |
| DRC-028 | Influence / stub spacing near wide metal | partial | attached_wide_spacing holds LEF SPACING RANGE INFLUENCE (a stub within influenceLength of the wide wire inherits its spacing; LEF example tested); its stub-width RANGE and SPACINGTABLE INFLUENCE (two stubs near a wide wire) are missing, and the square growth holds a little more near a wide corner (fails closed) |
| DRC-029 | End-of-line spacing | partial | eol_within_spacing adds LEF WITHIN, PARALLELEDGE, TWOEDGES and LEF58 ENDTOEND; ENCLOSECUT, the LEF58 MINLENGTH/MAXLENGTH, ENDPRLSPACING and WRONGDIRSPACING qualifiers, and the ENDTOEND extensions are missing |
| DRC-030 | EOL extension / keep-out | partial | eol_keep_out checks the LEF58_EOLKEEPOUT box (backward, side, forward); its EXCEPTWITHIN, CORNERONLY and CLASS qualifiers, and LEF58_EOLEXTENSIONSPACING, are missing |
| DRC-031 | Tip-to-tip / tip-to-side by width class | partial | tip_spacing_table classes both facing edges by length (A7 M1.S.1-S.5); M4.S.3 and M4.S.4, tip to tip between lines on adjacent tracks, are missing |
| DRC-032 | Corner spacing (convex/concave, corner-to-corner) | partial | convex_corner_spacing adds LEF58 CONVEXCORNER (the larger axis gap, CORNERTOCORNER Euclidean) and EXCEPTEOL; CONCAVECORNER, the WIDTH table and the SAMEMASK, CORNERONLY, EXCEPTJOGLENGTH and EXCEPTSAMENET/SAMEMETAL qualifiers are missing; sky130 poly.4 over-reports (limitations.md, "Shipped decks") |
| DRC-033 | Forbidden spacing ranges | partial | forbidden_spacing holds a closed gap range between facing edges running longer than a PRL (LEF58_TWOWIRESFORBIDDENSPACING as drt reads it); its MINSPANLENGTH/MAXSPANLENGTH, LEF58_FORBIDDENSPACING's WIDTH/WITHIN/TWOEDGES, and a preferred direction are missing |
| DRC-034 | Maximum spacing | missing | — |
| DRC-035 | Pitch / exact pitch / on-track | partial | exact_pitch holds neighbouring rectangles to an exact centre-to-centre pitch (A7 FIN.S.1, GATE.S.1); track grids (LEF PITCH, LEF58_PITCH, LEF58_RIGHTWAYONGRIDONLY) are missing. Also covers gridded-design rules (Liebmann 2003; Jhaveri 2010) |
| DRC-036 | Span-length table | partial | span_length checks every chord against the x and y span lists (LEF58_SPANLENGTHTABLE with and without WRONGDIRECTION); ORTHOGONAL and EXCEPTOTHERSPAN are missing |
| DRC-037 | Bent / 45-degree features | partial | angle checks the edges; width, notch, space, area, hole area and edge length measure 45-degree shapes (H12); every other geometric kind records Refused on a non-rectilinear layer |
| DRC-038 | Diagonal width / spacing | partial | Width, notch, space and edge length measured exactly on 45-degree edges (Euclidean; facing edges, necks, acute tips 0, and an axis edge against a 45-degree one at 135 degrees as KLayout's Euclidean width pairs them), H12, against the KLayout mirror on random 45-degree layouts (docs/klayout-mirror.md a8); LEF DIAGWIDTH/DIAGSPACING as separate limits for diagonal edges are not a kind |
| DRC-042 | End-cap / one-of-two-adjacent-sides enclosure | partial | One of two adjacent sides is adjacent_enclosure, each edge read at the corner as sky130A_mr.drc does (F2); IHP M1.c1's end cap is the opposite form; LEF58_ENCLOSURE EOL (an overhang only toward a metal end of line) is not modelled: no public source defines it beyond its syntax |
| DRC-043 | Width-dependent enclosure | partial | WIDTH bands only: LEF EXCEPTEXTRACUT and LENGTH, and LEF58_ENCLOSURETABLE, are missing |
| DRC-044 | Maximum enclosure / min-and-max window | partial | A maximum space (IHP Rppd.c, GF180 NP.3d "min/max space") is not written |
| DRC-045 | Extension / end-cap / overhang | partial | Each gate of merged A ∩ B measured per crossed axis; a gate that bends or carries a stub inside B measures 0 (fails closed), and bend (gate_corner, DRC-052) reports the bend itself |
| DRC-051 | Abutment / butting edges | partial | Edge layers cannot be extended (difftap.6; limitations.md, "Checks that do not exist yet"); edge enclosure misses diagonal gaps (limitations.md, "Rules that can pass a layout signoff would flag") |
| DRC-053 | Exact alignment / width match across layers | partial | ASAP7 V1.M2.AUX.2 only: LEF58_SPACING EXACTALIGNED (the spacing of exactly aligned line ends) is not modelled |
| DRC-055 | Direction-dependent (S/D-direction) spacing | partial | Facing edges in both axes, as sky130's own KLayout deck reads lvtn.3b; the S/D direction is not derived from the gate |
| DRC-063 | Cut-class spacing tables | partial | Class-pair SIDE/END cells only: the PRL second value, CENTERTOCENTER and CENTERANDEDGE cells, SAMENET/SAMEMETAL and LAYER tables, EXACTALIGNEDSPACING and LEF SPACINGTABLE ORTHOGONAL are missing |
| DRC-064 | Slotted / bar cut spacing by edge length | partial | sky130 licon.2b-2d are a cut-class table; IHP CntB bars of free length have no class (classes are exact sizes, as LEF58_CUTCLASS) |
| DRC-065 | Via stacking / cross-layer cut spacing | partial | via_stack counts every cut as a single-cut via, so a double-cut via does not interrupt a stack (fails closed); LEF SPACING LAYER STACK (aligned same-net cuts exempt) is not modelled |
| DRC-066 | Minimum cut count / redundant via | partial | LEF MINIMUMCUT's LENGTH ... WITHIN form (thin wires beside a wide one) and LEF58_MINIMUMCUT's cut classes and AREA are missing |
| DRC-067 | Metal-width-dependent via choice | missing | — |
| DRC-068 | Cut-area conservation between two databases | partial | gpurify xor compares two layouts layer by layer, as KLayout's xor does: every region where a drawn layer differs, with its area, so a cut layer's lost or added area is found. Not checked, and not checkable from public sources: the irdrop tolerance per connector by cut count (ct.irdrop.1-3, via.irdrop.1-4 to via4.irdrop.1-4). Its flags are CU (Cu back end only, which sky130 does not offer) and IR (an Al layout against its slotted Cu twin); no public source defines a connector, and the unit (um) was added by a script (skywater-pdk 9039be3), not by SkyWater. No public deck implements it; see docs/limitations.md |
| DRC-075 | Wide-metal slotting | partial | Slot required is a kind (cheesing); slot geometry uses the generic kinds; slit density over a plate is region_density (IHP Slt.i). Missing: a maximum slot spacing (GF180 MSLOT.4) and staggered slots (MSLOT.6) |
| DRC-076 | Waffle-window density | missing | Not implemented, by decision: the rule text (SKY m1.- to m4.-, flag RC) gives a 700 um window and coverage bands but no window step, and no public deck codes it. Cadence's public SKY130 DRM (2025-07-22) lists it as obsolete and removed and cmm*/waffleDrop as unsupported; see docs/limitations.md |
| DRC-081 | Net spacing between two layers / on wells | partial | space(A, B; nets: different) spaces two conductor layers, overlap included; a derived or tag layer carries no nets, so sky130 nwell.7 (dnwell), hvnwell.8 and hv.nwell.1 (HV n-well by hvi or text tag) and vhvi.8 cannot be written, and no shipped deck carries one |
| DRC-084 | Floating interconnect / must-join ports | partial | Flags conductor shapes that reach no device; LEF58 must-join-all-ports is not modelled |
| DRC-086 | Shorts between labelled nets | partial | Reported in every run as lvs.net_seed_conflict, naming both labelled shapes, located at the first; no abort |
| DRC-090 | Device-family rules (R, MIM, BJT, varactor, inductor, fuse, Schottky, LDMOS, photodiode, SRAM) | partial | Geometry is expressible through markers; exact resistor widths are width(L; allowed: [..]) (sky130 rpm.1b-1f) and channel length and width width(E) (DRC-011). Missing: licon counts per resistor terminal (rpm.1g-1k) and varactor taps (varac.2, varac.6) |
| DRC-092 | Exemptions (areaid regions, cell-name, rule flags) | partial | Region exemptions work via `not areaid`; cell-name scoping and exemptions via `L.in_cells("p", ...)` / `L.not_in_cells(...)` on a drawn layer: a shape is in when a cell on its placement path (root included) matches a `*`/`?` glob, as KLayout's `select("-", "+p")` (sky130 m1.4/m1.4a, li.1/li.1a, poly.12 written); rule flags (deck switches such as sky130's floating_labels) are missing |
| DRC-095 | Seal ring | partial | Geometry through the generic kinds; one seal ring per chip (IHP Seal.m) is count(seal) <= 1 with >= 1, nothing outside it (Seal.l) forbidden(L not (seal or seal.holes())). Missing: the seal ring at the origin (sky130 x.19) and a partnum beside it (x.27) |
| DRC-097 | Frame / die / cell-name rules | partial | Frame, scribe and LBE geometry is expressible with the generic kinds (sky130 x.16, x.21, x.23a-d, x.28; IHP LBE.*), e.g. forbidden(sl and diff), forbidden(lbe.holes()). Cell-name rules are written with `in_cells`/`not_in_cells`: sky130 x.25 (pnp.dg only within named cells) is written, and x.12's *_buildspace exemption is expressible; a maximum cell-name length (CAL:DRC MAXIMUM CELL NAME LENGTH) is forbidden(L.in_cells("?...?*")) with n+1 `?`, which flags only a long-named cell that holds or places a shape on a listed layer. Missing: the pcell rules x.26-x.27 (per placement, not per shape) and the seal ring's corner at the origin (x.19) |
| DRC-102 | Pre-coloured (MASK) same-/different-mask spacing | partial | Mask shapes as layers: same-mask spacing is space(L and mask), different-mask space(L and m1, L and m2), mixed coloured and uncoloured shapes patterning with anchors; PARALLELSAMEMASK needs EOL PARALLELEDGE (DRC-029) |
| DRC-111 | DFM scoring of recommended rules | missing | Public form (GlobalFoundries with ICV, arXiv:1805.10016): a recommended-rule finding scores 0 at the required value and 1 at the recommended one, and a chip score is their product; recommended rules are reported as warnings (DRC-110) but not scored |
| DRC-112 | Critical area analysis | partial | Shorts only, for one square-defect size, between merged figures of one layer rather than nets; opens and the average over a defect-size distribution are not computed |
| DRC-113 | Litho / CMP simulation hotspots | partial | CMP hotspots a public model defines: a density step between neighbouring windows (max_delta) and a first-order thickness excursion, sensitivity x (density - target), over a window standing for the planarization length (density_cmp, Ouma2002). Litho hotspots (aerial-image, process-window simulation) and a full CMP topography simulation need a foundry's calibrated optical, resist and polish models, which no open PDK publishes; foundry hotspot pattern libraries are not public |
| DRC-114 | Pattern-matching DRC | missing | A pattern is a window of shapes about an anchor, matched exactly or within ranges in the eight orientations (US7757190B2, US11487930B2, US9171126B1); no pattern input or matcher |
| DRC-115 | Equation-based DRC | missing | Calibre eqDRC: a limit or condition as an expression over measured values (fact sheet 82854-F); left to Rust custom rules (testing-plan L9b, ledger D5) |
| DRC-116 | Curvilinear / all-angle tolerance DRC | missing | In scope since 2026-10-11 (was: Rectilinear only) |
| DRC-117 | Via redundancy scoring / via doubling | partial | Counts cuts within a distance; single cuts are the via term of the CAA yield model (Siemens WP 81850). No redundancy rate (Xu et al., ASP-DAC 2005: 1 - dead/total vias), which needs room to insert, and no via doubling, a layout edit |
| DRC-121 | Selection by shape class, net or angle; covering/overlapping; anisotropic size | partial | No selection by net (limitations.md, "Checks that do not exist yet") |
| DRC-123 | Hierarchical processing | partial | Flattened at load (gds::Library::flatten); a scale issue, not correctness |
| DRC-124 | Layout input exceptions (missing cell reference, duplicate cell, magnified or angled placement, odd or zero path width, spike, vertex count) | missing | Calibre grades each malformed-database case as an error or warning; whether the GDS reader refuses each case is unverified, and none is reported as a rule |
| DRC-125 | Protrusion width (narrow protrusion from wide metal) | missing | A protrusion narrower than width1 and shorter than length from metal wider than width2 |
| DRC-126 | Cut keep-out zone by cut class (end, side and spiral extensions) | missing | — |
| DRC-127 | Cell edge-type spacing between placed cells | missing | Spacing by the edge types of neighbouring standard cells (EXCEPTNONFILLERINBETWEEN and other options); needs cell placement, which a flattened layout loses |
| DRC-128 | Self-aligned multiple patterning (SADP/SAQP mandrel, spacer, cut) legality | missing | Distinct from LELE colouring (DRC-100): legality is a mandrel/non-mandrel assignment plus cut-mask rules |
| DRC-129 | Inter-die alignment and overlap (bump and pad alignment, rotation, cross-die spacing) | missing | Companion to LVS-073; needs a stack description placing each die |
| DRC-130 | Shape must contain a rectangle of a given size | missing | No open foundry rule found that states it; the operation is public only as an SVRF statement name |

### Layout against schematic (LVS)

| Id | Check | Status | What is missing |
|---|---|---|---|
| LVS-002 | Implicit joins (same-label disjoint shapes, must-connect) | partial | Same-label disjoint shapes are not joined by default: reported as label_conflict, only with --reference (lvs::check_layout), located on the labelled shapes (F70). The deck's `lvs connect_implicit "pattern"` (glob) and `lvs connect_explicit "a" "b"` declare must-connect nets, joined for the comparison (lvs::join_must_connect, KLayout connect_implicit/connect_explicit), their open still reported as a label_conflict warning, as KLayout warns for a top cell. LEF58_MUSTJOINALLPORTS is not read |
| LVS-005 | Short isolation / localisation | partial | Reported in every run, DRC-only included, naming both labelled shapes, located at the first; no abort. The short's path follows as lvs.short_path: the fewest polygons joining the two labelled shapes through the extraction's joins (NetTable::path, breadth first, deterministic), one row per step between consecutive polygons (Calibre LVS ISOLATE SHORTS, ICV ShortFinder); a cut is no step, and the path is the shortest, not every route. Opens are not isolated: one reference net split over several layout nets shows only as label_conflict where labelled, never as an open path (CAL:LVS ISOLATE OPENS) |
| LVS-010 | Circuit without partner / hierarchical compare | partial | The reference is flattened below its top (Netlist::flatten_top) and compared device by device, so a missing block is a mismatch; there is no per-cell matching and no circuit-mismatch report naming the cell; a reference flattening to more than 2²⁸ devices, nets and instances is refused (NetlistError::TooLarge), and one nesting deeper than the layout's 1024 levels (NetlistError::TooDeep, F96); flattening is linear in what it places (F95); no cell-correspondence list naming which layout cell matches which reference subcircuit (KL:same_circuits, NG:equate classes) |
| LVS-017 | Subcircuit instance unpaired | partial | Instances are flattened, not paired as units: a missing instance shows as its devices unpaired |
| LVS-033 | Black boxes | missing | — |
| LVS-042 | Semi-series MOS | missing | — |
| LVS-043 | Resistor series/parallel | partial | Parallel resistors merge keeping r and counting m (match one card with m=2, not one card of r/2) under the default strict topology; under the deck's `lvs topology relaxed` they combine harmonically, 1/Σ1/r, w, area and perim adding, l agreeing, m folded in first. Series resistor merging is missing (series merges are MOS only) |
| LVS-044 | Capacitor / diode / BJT parallel | partial | Under the default strict topology parallel capacitors, diodes and bipolars keep their value and count m; under the deck's `lvs topology relaxed` one stating its value combines by adding it (c, a diode's area, a bipolar's ae), with area, perim and pe adding along and m folded in first. Diodes wired in opposite directions do not merge. Series capacitors never merge (CAL:LVS REDUCE SERIES CAPACITORS) |
| LVS-047 | Logic-gate recognition | missing | — |
| LVS-048 | Filter unused devices | missing | — |
| LVS-049 | Topology vs property policy (strict/relaxed) | partial | The deck's `lvs topology strict\|relaxed` (Netgen property topology). Strict, the default: structural differences after reduction are unpaired devices, and parallel passives keep their value and count m. Relaxed: a resistor, capacitor, diode or bipolar stating its value (r, c, area, ae) merges in parallel by the value's law, r harmonically and the rest by adding, m folded in first; one stating no value keeps its count. Netgen's relaxed policy also combines in series, which is not made here (passives never merge in series) |
| LVS-060 | MOS W, L, nf, m, AS/AD/PS/PD, bulk | partial | w and l from the marker bounding box; nf = 1 per channel, summed by parallel merges; marker area and perim. Compared per paired device, only where its card states the parameter (F68). as/ad/ps/pd from the source/drain polygon (gate edge included, BSIM4 perMod=1), a shared diffusion split evenly, compared at the channel end, symmetric channel nets paired the way the diffusions agree (F98), summed in parallel merges, refused in series; not measured where drawn in pieces; bulk is dropped when the layout has none |
| LVS-061 | Resistor R/L/W | partial | w/l from the resistor body's bounding box; r = sheet·l/w when the device statement gives sheet; positional R1 a b 1k rpoly is read as r. A bent body reads its bounding box; a card with no model is the deck's one resistor (F86); resistors never merge in series |
| LVS-062 | Capacitor C/A/P | partial | area and perim measured; c = area_cap·area + fringe_cap·perim when the deck gives them; a positional C value is read. No w/l; KLayout A/P read as area/perim (F87); a C card with no model is the deck's one capacitor (F86) |
| LVS-064 | BJT AE/PE/NE, multi-emitter | partial | ae/pe from the emitter terminal's polygon (B27); marker area and perim; no NE or multi-emitter. sky130 bipolars have no recogniser (limitations.md, "Shipped decks") |
| LVS-065 | Inductor | missing | — |
| LVS-067 | Subcircuit-modelled devices (rsubcircuit, fixed cells: VPP, ESD) | missing | sky130 VPP caps have no marker (limitations.md) |
| LVS-068 | Device-count and parameter-range limits (devices per model, W/L inside the model's valid range) | partial | The deck's `lvs range "model" param >= min <= max` holds every layout device of the model to bounds on a measured parameter (w, l, perim, ps, pd, pe, area, as, ad, ae, nf; a bound is legal), reported as lvs.param_range on the marker; a device whose parameter was not measured refuses the row. Recorded only when the deck states a range, with LVS. Per-model device counts are missing |
| LVS-073 | 3D / system LVS across dies | partial | gpurify system: dies placed by a system description (origin, quarter turns, mirror), bonded where rectangular bumps of facing faces overlap; system.unbonded_bump, then system.open and system.short pin by pin against the system netlist's die instances and top ports, then the flat device comparison. Bumps must be rectangles and every die on one grid; cross-die bump alignment, size and spacing (DRC-129) and 3D extraction (PEX-015) are not checked |
| LVS-074 | Layout-dependent-effect parameters (LOD SA/SB/SD, WPE SCA/SCB/SCC) | missing | BSIM4 defines the instance parameters and their geometry; no open PDK deck extracts them |
| LVS-075 | Structural Verilog reference netlist | missing | Digital top levels arrive as gate-level Verilog |

### Electrical rules (ERC)

| Id | Check | Status | What is missing |
|---|---|---|---|
| ERC-A11 | MIM capacitor as victim | partial | The gate argument takes any layer; a non-conductor gate joins the layer a device mos row names as its gate terminal, else the conductor it lies on, never metal routed over it (F72, F81 fixed). gf180 leaves ANT.14/15 out, and the FuseTop/Via5 connectivity needs care |
| ERC-A14 | Hierarchical / macro-pin antenna | missing | — |
| ERC-A15 | Fix hint: required diode area | missing | Report feature |
| ERC-C3 | Protected device (pad-exposed gates and drains) | partial | A gate on the pad net counts as protected by the primary clamps (no CDM secondary stage is required); clamps are as esd_topological takes them |
| ERC-C4 | Cross-domain signal ESD protection | partial | The grounds' anti-parallel coupling of check 5.1.3, and with `local` a local clamp; no series resistor at the receiver |
| ERC-C6 | P2P resistance on the discharge path, per pin pair | partial | Pin-to-supply pairs only: two signal pins meet only through the supplies between them; a clamp is its on-resistance, with no turn-on or holding voltage |
| ERC-C8 | Path voltage vs device failure (ESD window) | partial | The pin's voltage under a forced current through linear clamps: a clamp's turn-on or holding voltage is folded into the limit, and each protected device's own terminal voltages are not read |
| ERC-C9 | CDM checks (bus inductance, local clamps, driver/receiver ground R) | partial | Local clamps at a domain-crossing receiver only: the driver/receiver ground resistance and the bus inductance are not checked |
| ERC-C12 | Package / 2.5D / 3D ESD | partial | gpurify system: system.esd_package holds each package pin to clamps reaching a power and a ground rail through the assembled system (any die); system.esd_d2d holds each die-to-die bump to its own die alone (JEP196). Path existence only: no resistance, current, clamp size or CDM level; no wafer-on-wafer exemption; package R, L and C not modelled |
| ERC-C13 | System-level ESD | partial | gpurify system: system.esd_iec holds each package pin the system names as exposed to both rails through clamps of the models it names as system-rated. System robustness itself (board TVS, residual pulse, soft failures, powered latch-up) needs simulation, not a layout (WP3 Part I 6.3.1; TR18-01:7) |
| ERC-C14 | ESD layout rules on recognised devices (clamp distance to pad, minimum ESD-path metal width) | missing | Numeric limits are NDA |
| ERC-D5 | Voltage-aware aggressor/victim | partial | Aggressors are chosen by pad connection or layer, not by the voltage the intent propagates; the whole victim polygon is held to the limit |
| ERC-D7 | Native-device guard ring | partial | LU.5's "no other NCOMP, NWELL in between" the device and its ring is not checked |
| ERC-D9 | PMOS/NMOS devices sharing one well | missing | Named as a Calibre PERC layout check without a public definition of which sharing is illegal |
| ERC-E7 | RMS / Joule heating / peak limits | missing | Public limits exist: LEF 5.8's ACCURRENTDENSITY tables by frequency and width, and the sky130 tech LEF's RMS limits (6.1 mA/um met1-met2, 14.9 met3-met4, 22.34 met5, Tj 90 C). The intent states only a DC current budget per net, so no RMS or peak current reaches a check |
| ERC-E9 | PDN integrity (floating stripes, unconnected instances) | partial | Flags unconnected conductors; PDN-specific checks (floating stripes, instance supply terminals) are missing |
| ERC-E11 | Dynamic / vectorless IR | partial | Vectorless worst cycle: every load on a net switches in phase once, a triangular pulse from its budget, toggle rate and rise time, against the net's decap; an RC grid with no package, bump or wire inductance (L di/dt), and one feed point per supply (limitations.md, "Power grid") |
| ERC-E12 | Stress voiding / slotting | partial | cheesing requires a slot in wide shapes, and the slot geometry (IHP Slt.*, gf180 MSLOT.*) is DRC width, enclosure and spacing; JEP139 and JESD214 are stress-migration test methods that state no layout rule, so the stress-voiding rules beyond slotting (vias landing on wide metal) have no public limit |
| ERC-F4 | HCI susceptibility flag | missing | — |
| ERC-F14 | Power-intent supply connectivity (power switches, always-on and retention cells on the supplies the UPF declares) | missing | Needs UPF input; IEEE 1801 not read (check-sources.md §5) |
| ERC-G8 | Combinational loops | missing | Digital only, optional |
| ERC-G9 | Path check: nets with no path to power or ground | missing | — |
| ERC-H2 | Analog constraints (symmetry, common centroid, matching, orientation, dummies, WPE, STI) | missing | Overlaps Philis's own properties |
| ERC-H3 | Netlist path checks (gate to ground within N devices; net types) | missing | — |

### Parasitic extraction (PEX)

| Id | Check | Status | What is missing |
|---|---|---|---|
| PEX-003 | Coupling C (same-layer and cross-layer) | partial | The field solve meshes each horizontal interface of the stratified stack (each pex row's dielectric fills up to the next row's height) over a window around the solved nets, FastCap's multi-dielectric formulation; the polarisation beyond the window is left out, and the collocated interface rows make the matrix reciprocal only to the discretisation (refused past 5 %, reported symmetrised). No conformal dielectrics, no per-layer dielectric beside a wire; the closed forms see one permittivity per layer. The substrate is a grounded plane at height 0 (testing-plan F24); a shape at height 0 (well, diffusion) is a junction, out of the field and in closed form, so the field reads metal over another net's junction as coupling to ground (F73); a junction layer needs no dielectric (F94) |
| PEX-007 | Process effects (CMP thickness, temp-dependent R, nonlinear via R, colour-aware) | partial | Temperature-dependent R: the deck's temperature T nominal T0 and each pex row's tc1/tc2 give R(T) = R(T0)(1 + tc1(T - T0) + tc2(T - T0)^2), the ngspice resistor law with the coefficients PDKs publish; extraction, the power grid and lib read it. Not modelled: CMP thickness from pattern density, current-dependent via R, colour (mask-shift) effects: their models need foundry calibration data no open PDK publishes; width- and spacing-dependent thickness and sheet R, layer etch, via-coverage R (SRC:datasheet) |
| PEX-009 | PEX netlist diff / qualification | partial | Library only (gpurify_extract::compare): two extractions of one layout compared net by net in PEX Certify's metrics (total and ground C, net-to-net C, pin-to-pin R, Elmore delay) with the error statistics a qualification reports (worst, mean, RMS, share within a tolerance above a floor). No reader for another tool's SPEF or DSPF, and no linking of nets by name across two layouts (PEX Link); no CLI |
| PEX-011 | Device-region (MEOL/FEOL) parasitics: gate-to-contact and gate-to-diffusion C, trench contact, via-location gate R | missing | Needs the foundry's device cross-section; no open PDK publishes one |
| PEX-012 | Metal-fill treatment (floating or grounded fill, virtual fill) | missing | — |
| PEX-013 | Substrate network extraction (substrate and well resistance and coupling) | missing | — |
| PEX-014 | Route-level (gate-level) extraction from LEF/DEF | missing | Needs a DEF reader |
| PEX-015 | 3D-IC extraction (TSV, micro-bump, interposer, TSV-TSV coupling) | missing | — |
| PEX-016 | Point-to-point resistance and net-to-net coupling report between arbitrary points | missing | ERC-C6 measures P2P on an ESD path only |

### Flow

| Id | Check | Status | What is missing |
|---|---|---|---|
| FLOW-003 | SoC integration (macro sync, ports off grid, fill outside boundary, block/pad-ring overlap) | missing | Cheap from LEF/DEF + GDS |
| FLOW-004 | Interface DRC top vs blocks | missing | — |
| FLOW-005 | In-design / live DRC | partial | Shared-deck library (Philis) is the first step |
| FLOW-006 | User-programmable rules | partial | DRC custom rules as Rust fn pointers (deck::CustomRule via DeckBuilder::custom; runner owns accounting) and gpurify::cli::main_with for a binary with its own decks; ERC custom rules and a KLayout snippet per rule not yet (deck-library plan P5) |
| FLOW-007 | Fill insertion (density-driven, timing-aware) | missing | DRC-073 checks fill; this generates it |
| FLOW-008 | Incremental / ECO re-verification (changed regions or nets only) | missing | Metamorphic: an incremental run equals a full run |
| FLOW-009 | Automated DRC-clean layout enhancement (via and power-grid insertion) | missing | — |
| FLOW-010 | Clustering and triage of very large result sets | missing | — |

<!-- end of generated block -->
