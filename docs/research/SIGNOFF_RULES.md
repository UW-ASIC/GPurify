# Sign-off rule catalogue and GPurify gap analysis

Researched 2026-09-23 against the open PDK decks listed under Sources and GPurify
at `1764294`. The goal is "0 issues past signoff": a GPurify clean result should
agree with foundry signoff (Calibre, Pegasus or ICV), and with silicon.

GPurify status codes: **have** means the kind exists and its semantics match the decks. **partial** means the kind exists but misses a variant; the gap is named. **mismatch** means the kind exists but measures something different from the foundry decks, and the doc says which direction it fails. **missing** means the kind does not exist. **expr** means it can already be expressed with a derived layer (`and`/`or`/`not`) and an existing kind, but no shipped deck does so.

Everything under "GPurify" comes from reading `crates/check/src/drc/ruleset.rs`,
`crates/check/src/drc/rules/*.rs`, `crates/check/src/erc/**`,
`crates/ingest/src/deck.rs` (`DerivedOp` is `And | Or | Not` only), `pdks/*.json`
and `pdks/README.md`.

---

## 0. Findings that matter first (existing kinds that fail open)

These come before the missing-kind list. A missing kind at least shows up as
"not configured". These rules configure, run and report clean on layouts that
real signoff rejects.

| # | Kind | What GPurify computes | What sky130/gf180/IHP/FreePDK decks compute | Direction |
|---|---|---|---|---|
| F1 | `asymmetric_enclosure` | `min(max(L,R), max(B,T))`: each axis has *one* side ≥ limit (`overlay.rs:59-68`) | Both sides of *one* axis ≥ limit, i.e. `max(min(L,R), min(B,T))`. Magic calls this `surround … directional` ("overlaps by a larger amount on the orthogonal sides"). The sky130 KLayout deck spells it "enclosure … of 2 opposite edges" (li.5, m1.5, licon.7, licon.8a). The FreePDK45 SVRF deck uses `RECTANGLE ENCLOSURE … GOOD 0 0.035 OPPOSITE 0 0.035 OPPOSITE` | **Fails open.** A via with 85 nm margin on left and bottom and 55 nm on right and top passes GPurify, but it fails m1.5/via.5a. All 6 sky130 rows and all 9 IHP rows are affected. |
| F2 | `wide_dependent_spacing` | A shape counts as "wide" when its *narrowest* width ≥ threshold | sky130 defines `huge_mX = mX.sized(-1.5).sized(1.5)`, the part of a shape wider than 3 µm, and checks spacing *from that part*. m1.3a also covers features "attached to or extending from huge_met1 for a distance of up to 0.28 µm" | **Fails open.** A 10×10 µm plate with a 0.14 µm tab has a narrowest width of 0.14, so the plate is never treated as wide. |
| F3 | `max_width` on cuts | Narrowest width ≤ limit | licon.1, ct.1, via.1a, V1.a and Cnt.a are "min **and max** L **and** W", an exact square. licon.3/ct.3/via.3 say "only min square". | **Fails open.** A 0.17×0.34 licon slot passes `min_width` and `max_width`. |
| F4 | `density` | The window is swept over the **layer's own extent** (`area.rs:154`) | Windows tile the **chip/die boundary**. IHP `with_density(…, tile_boundary = chip)` and gf180 `tiles(1000)` both do this, and both have *global* whole-die rules (IHP M1.j/k, gf180 M1.4 ">30 % over the entire die") | **Fails open** for min-density: empty regions of the die are never windowed. There is no global-density form at all. |
| F5 | `min_enclosure` / `min_extension` / `overlap` | Margins are taken on bounding boxes, and the host's holes are ignored (documented at `overlay.rs:5-7`, `:159`) | Edge-exact | **Fails open** for concave hosts: L-shaped metal around a via, or a well with a hole. |
| F6 | `angle` | One global rule; `layers: []` | sky130 x.2 allows 90° only on diff, tap, poly, licon, li, mcon and via–via4, and 45° elsewhere. gf180 checks angles per layer ("ACUTE : non 45 degree angle comp"). | `sky130.json` allows 0/45/90/135 everywhere, so 45° diff/poly/via **pass**. |
| F7 | `max_distance_to_tap` | Distance from each **well vertex** to the nearest tap box | IHP LU.a/LU.b say "any portion of N+Activ … to a tie ≤ 20 µm" and are implemented as `nact.not(ptap.sized(20))`. gf180 DF.13/14 do the same with `sized(20.um)`. | **Fails open.** The farthest point from a set of taps is usually interior, for example midway between two taps, not a vertex. The ERC kind `missing_tie` already has the exact furthest-point semantics. |
| F8 | `antenna` / `antenna_electrical` | (a) `Sidewall` collectors are **refused**. (b) Nets are the final, fully connected nets (`antenna.rs:96`). (c) Gate area is the area of the gate-layer polygons on the net. | (a) sky130 counts *perimeter* areas for poly/li/met1-3 and bottom area for contacts. gf180 uses `perimeter_only(metalN, t)` on every metal. (b) SVRF and KLayout build connectivity **incrementally per etch step** (`CONNECT metal2 metal1 BY via1` between `NET AREA RATIO` stages). (c) The gate is `poly AND diff`. | (a) All **12 gf180 antenna rows are refused**, so the run cannot pass, and sky130 cannot be expressed. (b) **Fails open**: a diode reachable only through upper metal is credited at the lower stage. It also produces false errors, because M1 pieces joined only through M2 are summed. (c) gf180 `ANT.1` names `["poly2","poly2"]`, which makes the gate area the whole poly area, so the ratio comes out too low and the rule **fails open**. |
| F9 | IHP density rows | `metal1_*_local_density` counts `metal1` only | M1Fil.h/k count "Metal1 **and** Metal1:filler" | Max density **fails open** once fill is present. The fix is an `or` derived layer. |

Recommendation: fix F1–F4 and F7–F8 before adding new kinds. Each has a
cheap regression: the sky130 `test_violators.gds` in open_pdks, and IHP's
`testing/testcases` GDS with golden KLayout reports. Diff GPurify's markers
against KLayout's per rule.

---

## 1. DRC rule-kind catalogue

Deck columns: **S** = sky130 (periphery table [S1] and the KLayout deck [S2, S3]), **G** = gf180mcu (KLayout decks [G1]), **I** = IHP SG13G2 (layout-rule tables and KLayout deck [I1, I2]), **A** = ASAP7 DRM [A1], **F** = FreePDK45 SVRF deck [F1].

### 1.1 Width family

| Kind | Definition | Decks | GPurify |
|---|---|---|---|
| Min width | Interior facing edges ≥ w | S G I A F | have (`min_width`, exact on rectilinear) |
| Max width | Width ≤ w (gf180 DF.2b COMP, IHP AFil.a/M1Fil.a2 filler ≤ 5 µm, IHP Slt.c metal ≤ 30 µm without slit, sky130 m1.11 Cu ≤ 4 µm) | S G I A | have (`max_width`, narrowest width; see F3) |
| Exact size / square-only cut | Cut must be exactly w×w; "only min square" | S (licon.1/3, ct.1/3, via.1a/3…) G (V1.1) I (Cnt.a, V1.a) | **missing** (F3) |
| Discrete allowed sizes | "Three sizes of square vias allowed inside areaid.mt: 0.15/0.23/0.28" | S (via.1b, via2.1b-f) | missing |
| Exact size of a device feature (min = max) | rpm.1b-f resistor widths, pwres.2, photo.2, mf.1 | S I (npn13G2.a emitter) | missing (expressible as a min/max pair only if the max is edge-exact) |
| Directional width | Different vertical and horizontal width, e.g. ASAP7 M4.W.1 vs M4.W.5 | A | missing |
| Width by forbidden multiple / track grid | ASAP7 M4.W.3/W.4: width may not span an even number of tracks | A | missing |
| Width by condition | Gate length by device type: sky130 poly.1b pfet in lvtn 0.35, IHP Gat.a3 3.3 V NFET 0.45, gf180 PL.2 by voltage | S G I | expr (derived layer + `min_width`) |
| Channel width (gate W) | sky130 difftap.2 "Diff AND Poly" W ≥ 0.42, gf180 DF.2a | S G | partial: needs the gate's extent *along* poly, not the polygon's narrowest width |
| 45°-bent width | IHP Gat.g, M1.g; gf180 PL.7 | G I | missing (rectilinear only) |
| Min edge length / step | Every edge ≥ l (IHP CntB.a1 length, gf180 DF.11 butting edge ≥ 0.3) | G I A | have (`min_edge_length`); no edge-selection conditions |
| Max length | sky130 pwres.4, IHP npn13G2L.b, LBE.b | S I | missing |
| Aspect ratio | sky130 li.2 L/W ≤ 10 without contact (NC), capm.6 | S | missing |

### 1.2 Spacing family

| Kind | Definition | Decks | GPurify |
|---|---|---|---|
| Min space, same layer (inter-polygon) | `isolated` / SVRF `EXT` | all | have (`min_spacing`; touching shapes merged) |
| Notch (intra-polygon) | sky130 x.6: "all intra-layer separation checks include notch" | all | have (`notch`) |
| Two-layer separation, overlap forbidden | "spacing, no overlap" (licon.9, rpm.6, lvtn.9) | all | have (`min_spacing_diff`; overlap is a violation) |
| Two-layer separation, overlap allowed | Plain `separation`, where overlapping shapes are exempt (poly.4 poly-on-field to diff) | S G I | **missing**: the only two-layer kind forbids overlap. A workaround is `not` on the operand. |
| Metric: euclidean / projection / square | KLayout `projection` (only facing edges), `euclidian`, `square`; sky130 uses projection for poly.4/6/7/8, lvtn.3b and licon.7 | S I | partial: fixed metric (euclidean with corner rule). Projection rules become too strict (false errors, not fail-open) |
| Wide-metal (width-dependent) spacing | Spacing grows when either shape exceeds a width | S (m1.3ab "huge") G (M1.2b width & length > 10 µm) I (M1.f) | mismatch (F2) |
| PRL (parallel-run-length) spacing | Spacing grows with the run length the pair shares | I (M1.e run > 1 µm) A (M4.S.4) | have (`prl_spacing`, one threshold) |
| Width × PRL combined / spacing table | Spacing applies when width ≥ W **and** PRL ≥ L (IHP M1.e: w>0.3 & prl>1 → 0.22; M1.f: w>10 & prl>10 → 0.6). A LEF `SPACINGTABLE PARALLELRUNLENGTH` generalises this | I A | **missing**: `prl_spacing` and `wide_dependent_spacing` are separate and cannot be ANDed; there is no multi-row table |
| End-of-line spacing | Line end narrower than `eolWidth` needs extra space | G (V1.3c eol enclosure) A | have (`eol_spacing`: width + space only) |
| EOL with conditions | `within`, parallel-edge presence and EOL-to-EOL vs EOL-to-side (ASAP7 M1.S.2-S.5 tip-to-side / tip-to-tip by edge-length class; M4.S.3/S.4 tip-to-tip with/without PRL) | A | missing |
| Corner-to-corner | Diagonal spacing | A (M1.S.6, V0.S.2-4) | have (`corner_to_corner`) |
| Voltage-dependent spacing (by marker) | Different value inside a voltage marker: gf180 `_3.3V`/`_5V` via DUALGATE/V5_XTOR on almost every rule; sky130 HV (hvi) rules | S G | expr (derived-layer split) |
| Voltage-dependent spacing (by net voltage, VA-DRC) | Spacing depends on the voltage difference between nets (sky130 hv.nwell.1 "shv_nwell … different nets" 2.5 µm, vhvi.8 11.24 µm; Calibre PERC VA-DRC [C1]) | S | missing |
| Same-net vs different-net spacing | gf180 NW.2a (equipotential, 0.6) vs NW.2b (different potential, 1.4), coded as `conn_space`; sky130 nwell.7/8 and dnwell.3a/3d; IHP NW.b vs NW.b1, NBL.b/c | S G I | **missing**: DRC is geometry-only; no net-aware spacing |
| Spacing to "related" vs "unrelated" shape | gf180 PL.5a/5b (poly to related/unrelated COMP); IHP NBL.e "unrelated N+Activ" | G I | missing (needs net or interaction selection) |
| Pitch / exact spacing | ASAP7 FIN.S.1, GATE.S.1 "exact pitch == 27 nm" | A | missing |
| Center-to-center spacing | sky130 mf.3 fuse centres, x.20 pin centres | S | missing |
| Spacing across marker boundary | sky130 x.13 across areaid.ce | S | missing |
| Cut spacing by array size | gf180 V1.2b (4×4 or larger array → 0.36) | G I | have (`via_array_spacing`, cluster-count threshold; gf180 uses 15 as a stand-in) |
| Cut row spacing | sky130 via2.13, via3.14 (Cu) | S | missing |
| Cut spacing by alignment | ASAP7 V0.S.1 "not aligned on parallel tracks" | A | missing |

### 1.3 Enclosure, extension and overlap family

| Kind | Definition | Decks | GPurify |
|---|---|---|---|
| Min enclosure (all sides) | `enclosing` / SVRF `ENC` | all | have, with bbox caveat (F5) |
| Two opposite sides ("directional", "end-of-line enclosure") | See F1 | S (li.5, m1.5, via.5a, licon.5c/7/8a) G (V1.3d) F | **mismatch** (F1) |
| Conditional enclosure | "If overlap < 0.04 on one side, adjacent edges ≥ 0.06" (gf180 V1.3d/V1.4c); EOL overlap when metal < 0.34 (V1.3c) | G | missing |
| Enclosure by edge class | sky130 via.14 "parallel edges" vs via.14a "45° edges" | S | missing |
| Enclosure except butting edge | n/psd.5a/5b "enclosure of diff … except for butting edge"; n/psd.6 butting edge = 0 | S | missing (needs edge ops) |
| Max enclosure / min–max enclosure | npc.5 max 0.095; IHP Sdiod.b/c "min and max"; sky130 photo.9 | S I | missing |
| Must enclose (presence) | "licon must overlap li and (poly or diff or tap)" (licon.4); "npc must enclose poly_licon" (licon.18); nwell.4 "every nwell contains a contacted tap"; licon.16 "every tap encloses ≥ 1 licon" | S G I | partial: `min_enclosure` measures zero for an unhosted inner shape (catches "inner outside outer"). It cannot express "outer must contain ≥ 1 inner". |
| Min extension (overhang) | poly endcap (poly.8), S/D extension (poly.7), gf180 DF.6, IHP GFil.j | all | have (`min_extension`, bbox; F5) |
| Min/max extension | depmos.5, denmos.5; IHP LU.c "max extension of tie beyond Cont ≤ 6 µm" | S I | missing |
| Overlap amount | IHP pSD.e "overlap at one position ≥ 0.3"; Cnt.g2 | I | have (`overlap`, bbox) |
| Must not overlap / forbidden intersection | licon.17, n/psd.8, tunm.5, x.10, x.23a/c, "Nplus can't overlap Pplus" (gf180 FATAL), IHP forbidden layers | S G I | **missing**: there is no "non-empty derived layer is an error" kind |
| Must not straddle | "poly must not straddle rpm" (rpm.8), difftap.21, vpp.4, dnwell.7 | S G I | missing |
| Coincident edges required | photo.5 "edges coincident with areaid.po", rfdiode.2, extd.2 "2 or 3 coincident edges", pwres.10/11 "abut on opposite edges" | S | missing |

### 1.4 Area, hole and density family

| Kind | Definition | Decks | GPurify |
|---|---|---|---|
| Min area | per merged figure | all | have. The limit is stated as the side of the equivalent square and floored, which fails open by < 0.4 % (pdks/README). |
| Max area | sky130 capm.12, pad.3 "hugePad ≤ 30000 µm²"; IHP MIM.g, LBE.b1 | S I | missing |
| Min hole (enclosed) area | m1.7, n/psd.11, hvtp.6 | S G I | have (`min_enclosed_area`) |
| Min field area | gf180 DF.10 "min field area 0.26" | G | expr (`not` + holes) |
| Max total area per chip / device count per chip | IHP MIM.gR total MIM area, npn13G2.bR ≤ 4000 emitters | I | missing |
| Local (windowed) density min/max | window + step | S (m*.pd, Cu m1.13-14a 50/25 µm) G I (800/400 µm) | have, but mismatched on windows (F4) |
| Global (whole-die) density | IHP AFil.g/g1, M1.j/k, TM1.c/d, LBE.i; gf180 PL.8, M1.4; efabless precheck `met_min_ca_density` (chip-level li1/m1/m2 "ca" density ≥ 0.4) | S G I | **missing** |
| Density gradient (neighbour-window delta) | Foundry CMP rules; not in the open decks | — | have in ERC (`density_cmp.max_neighbour_delta`, untested per NEED_TESTING) |
| Density inside a marker | sky130 vpp.5a-c "max m3 density over capacitor ≤ 0.25", vpp.11 min | S | missing (window = marker polygon) |
| Waffle/fill-coverage-conditioned density | sky130 m1.X.1 "700×700 window covered by waffleDrop and PD < 70 %" | S | missing |
| Slot / cheesing | Wide metal must be slotted: IHP Slt.c (> 30 µm) and Slt.i (slit density ≥ 6 % in plates > 35×35); sky130 m1.12 (Cu > 3.2 µm) | S I | partial (`cheesing` = area above a threshold must carry a hole; no slit-density or slit-width rules) |

### 1.5 Via / cut family

| Kind | Decks | GPurify |
|---|---|---|
| Min cut spacing | all | have |
| Exact square cut | S G I | missing (F3) |
| Array spacing (N×N) | G I | have (`via_array_spacing`, cluster-size proxy) |
| Redundant via required (recommended) | S x.18 RR "use redundant mcon/via…"; I | have (`redundant_via`) |
| Max vias within distance | S via.13 (Cu) "max 5 vias within 0.35 µm" | missing |
| Slotted/bar contact rules | S licon.1b/c, licon.2b-d; I CntB.* (ContBar length, spacing with common run > 5 µm) | missing |
| Cut must be covered by both metals | I Cnt.h, CntB.h; S licon.4 | partial (enclosure 0) |
| Contact on gate forbidden | I Cnt.j "Cont on GatPoly over Activ not allowed"; S licon.17 | missing (forbidden-overlap kind) |
| Licon count per resistor terminal | S rpm.1g-k "only N licons", pwres.7a "12 licons" | missing |
| Self-aligned via alignment | A (V1.AUX, fully/partially aligned) | missing |

### 1.6 Well, tap and latch-up geometry

| Kind | Decks | GPurify |
|---|---|---|
| Tap-to-device max distance (LU) | I LU.a/LU.b 20 µm; G DF.13/14 20 µm; A ACTIVE.LUP.1 30 µm | mismatch (F7) for the DRC kind; the ERC kind `missing_tie` is exact |
| Well must contain contacted tap | S nwell.4 (licon on tap); G/I | partial (ERC `floating_well` tests tap-in-well, not licon-on-tap-to-metal) |
| Tap must carry a contact | S licon.16 | missing |
| Well-to-opposite-diffusion spacing / enclosure | S difftap.8-11; G DF.4c/d, DF.16/17; I NW.f1 | expr (derived `diff and psdm` etc.; **not configured in sky130.json**) |
| Deep-well / isolated-well rules | S dnwell.*, nwell.5-7; G DF.4a/b/e, NW.3/5; I NBL.*, PWB.* | expr, except the net-aware parts (missing) |
| Guard-ring width/continuity | S photo.7 "enclosed by p+ tap ring"; S pwres.9 "full ring of contacted tap strapped with metal"; ESD/LU guard rings in foundry decks | partial (ERC `esd_latchup` guard ring width and distance only) |
| Butted-tap geometry | S difftap.4-7; G DF.3b/DF.11; I pSD.e-g | missing (needs butting-edge ops) |

### 1.7 Grid, angle and shape-class

| Kind | Decks | GPurify |
|---|---|---|
| Off-grid vertices | all (S x.1a 1 nm vs x.1b 5 nm by layer) | have (`off_grid`, one global pitch; no per-layer pitch) |
| Allowed angles | all | partial (F6: global only) |
| Rectangles only (no L/T) | S x.2a (areaid.analog diff/tap), capm.7; Magic `rect_only` | missing |
| No bend / no 90° turn | S poly.11 "no 90° turns of poly on diff", denmos.8; A M4.AUX.3 "may not bend"; G PL.6 | missing |
| Inner-corner rule | S poly.10 "poly can't overlap inner corners of diff" | missing |
| Track / routing-grid alignment | A M4.AUX.1/2, GATE/FIN on grid | missing |
| Zero-area / degenerate shapes | efabless precheck `zeroarea.rb.drc` | check the ingest behaviour: if zero-area shapes are dropped silently, that is fail-open |
| Acute angles | G "ACUTE : non 45 degree angle" | partial (implied by `angle`) |

### 1.8 Multi-patterning

| Kind | Decks | GPurify |
|---|---|---|
| k-colourability at colour spacing | A (LELELE, SADP/SAQP layers per Table 2.3.1) | have (`multi_patterning`: 2-colour bipartite, ≥3 DSATUR with budget → Refused) |
| Pre-coloured checks (same-mask spacing, colour balance, stitch rules) | A | missing |
| SADP-specific (mandrel/spacer, cut-mask, tip-to-tip by colour) | A (M4.S.1 "regardless of mask colors") | missing |

### 1.9 Markers, exemptions, IDs and hierarchy

| Kind | Decks | GPurify |
|---|---|---|
| Marker-conditioned rules (areaid.sc/ce/analog/mt, DUALGATE, V5_XTOR, ThickGateOx) | S G I (pervasive) | expr (derived `and`/`not`) |
| Text-label-conditioned layers | I `ext_interacting_with_text("npn13*")`; S "shv_nwell", "lv_net", "hv_lv", "vhv_block" text tags | **missing** |
| Cell-name-conditioned rules | S licon.11c/d, difftap.2a, li.1a ("inside cells named s8rf2_xcmvpp_hd5_*"); KLayout `layout.select("-cell")` | missing. Worth having only for sky130 foundry-cell exemptions. |
| Rule applicability flags | sky130 P/NE/NC/TC/RC/RR/DE/F/Cu/Al; IHP "R" suffix = recommended | partial: severity exists in ERC; DRC has no deck-level severity, switch or flow variant (Al vs Cu backend) |
| Pin/label rules | S x.5 "pin polygons within drawing", x.17 floating labels; I Pin.a-h "enclosure of X:pin by X ≥ 0" | missing |
| Forbidden layers | I forbidden.* (BiWind, NoDRC, …) | missing (non-empty-layer kind) |
| Seal ring | I Seal.b/k/l/m/n (one seal ring, unbroken passivation ring, nothing outside); S x.19 "seal ring lower-left at origin", nsm.* | missing |
| Pad / bump / passivation / RDL | S pad.2/3, rdl.1-6; I Pad.*, Padb.*, Padc.*, Pas.* | expr for width/space/enclosure; missing for "exit length", counts and max area |
| Fuse / MIM / varactor / photodiode / resistor device-geometry rules | S mf.*, capm.*, varac.*, photo.*, rpm.*, pwres.*; I MIM.*, Rsil/Rppd/Rhi.*; G efuse/mim/resistor decks | expr for most; exact size, count and coincident-edge parts missing |
| ESD-structure geometry | G ESD.1-10 (implant width/space/extension, "ESD implant overlapped by Dualgate"); S hvntm.7 ESD_nwell_tap | expr |
| HV-net propagation ("any layout shorted to hv source/drain becomes HV") | S hv.X.4, vhvi.vhv.3/4, nwell.10/11 | **missing**: needs "shapes on nets that touch marker X" as a derived layer |
| Frame / etest rules (areaid.mt/ft) | S x.12, x.15, nsm.3 | not needed for block signoff |

### 1.10 Derived-layer operations the three decks rely on

Counts come from `sky130.lydrc` [S2] (918 lines). IHP and gf180 use the same set, plus `ext_interacting_with_text` and `conn_space`.

| Operation | sky130 uses | GPurify `DerivedOp` |
|---|---:|---|
| `and` / `not` / `or` | 188 / 123 / 32 | have |
| `interacting` / `not_interacting` | 80 / 65 | **missing** |
| `edges` + edge booleans (butting edges, `second_edges`) | 142 | **missing** |
| `sized` (grow/shrink, open/close) | 30 | **missing** (needed for huge metal, LU, "attached to" rules) |
| `with_area` / `without_area` / `with_length` / `with_angle` | 20 / 19 / 9 / 50 | missing (selection by measure) |
| `inside` / `outside` / `overlapping` / `covering` | a few each | missing |
| `holes` / `with_holes` | 7 / 2 | missing |
| `extents`, `rectangles`, `squares` | IHP/gf180 | missing |
| Net selection (`nets`, `conn_space`, antenna `connect`) | gf180/IHP | missing |

Without `interacting`, `sized` and edge ops, about a third of sky130's coded rules cannot be expressed. That covers licon.7/8a, licon.16/18, n/psd.5a/5b/6, difftap.5/7, m*.3ab, x.22-style selections and every LU distance rule.

---

## 2. ERC catalogue

| Check | Definition / source | GPurify | Gap |
|---|---|---|---|
| Floating gate | Gate net with no driver | have (`floating_gate`) | — |
| Floating interconnect | sky130 x.22 RC: poly/li/met with no path to poly, difftap or a pin | have (`unconnected_pin`) | "Path to a metal pin" exemption and the `*_float` text exemptions are not modelled |
| Floating well / substrate | Well with no tap | partial (`floating_well`: tap inside the well ring) | Needs a *contacted* tap reaching a supply net (sky130 nwell.4 "metal-contacted tap"). Configured by 0 of IHP's rows. |
| Well/substrate bias correctness | nwell tied to highest potential, p-sub/p-well to lowest; forward-biased junction. CVC "forward bias diode", "source vs bulk" [E1] | **missing** | Needs voltage propagation |
| Soft connection | A net joined only through a resistive layer (well, poly-res) is a soft connect; efabless `run_scheck` | have (`soft_connection`) | — |
| Supply short (pre-LVS) | Different supply labels on one net | partial (`supply_short` = n-tie and p-tie on one conductor; configured by **no** deck) | Label-vs-label short and open (same label, split net) belong in LVS. Confirm the LVS crate reports both before signoff. |
| Multiple drivers / contention | Net driven from more than N gate nets | have (`multiple_drivers`, heuristic) | Tristate/transmission-gate awareness |
| Tie-high/low | Gate tied directly to a rail | have (`tie_high_low`) | — |
| Missing tie / LU tap distance | Every point of a region within d of a tap | have (`missing_tie`, exact furthest point) | Use it for IHP LU.a/b and gf180 DF.13/14 in place of the DRC kind (F7) |
| Latch-up guard rings | I/O and HV diffusion guard-ringed; ring width, continuity and tap distance. JESD78 is the qualification test [E3]; foundry LUP rules implement it | partial (`esd_latchup`: ring width + distance to supply) | Ring continuity; "within X µm of a pad/IO diffusion"; sky130 nwell.11 "Power_Net_Hv" |
| Gate-oxide overstress | \|Vgs\|, \|Vgd\| > Vmax(oxide) by device class. CVC "gate vs source", "EOS" [E1]; Calibre PERC | partial (`hv_domain`: max nominal spread across all terminals of a device, from intent) | No per-terminal-pair limits; no propagation through pass gates or level shifters; thin vs thick oxide not distinguished |
| Drain-source / bulk overvoltage | \|Vds\|, \|Vbs\| > rating; LDD/drain-extended orientation (CVC "LDD with incorrect source") | missing | — |
| Level shifter missing / domain crossing | A signal from domain A drives a gate in domain B without a shifter; HiZ inputs from powered-down domains (CVC "Hi-Z inputs", "power cut-off") | **missing** | Needs power-intent-aware net voltage propagation |
| HV propagation / tagging | sky130 hv.X.4, vhvi.vhv.3-5, nwell.10 (LV and HV nwell on one net) | missing | Net-connected-to-marker selection |
| Antenna, per layer | Collecting area over gate area, by layer | partial (F8) | Sidewall/perimeter, staged connectivity, gate definition |
| Antenna, cumulative with diode | sky130 EGAR = EA/A_gate − K·A_diode − bonus [S4]; gf180 `antenna_check(…,[diode,800])`; IHP Ant.e/f (with diode 20000/500) | partial (`antenna_electrical`: the formula matches sky130's form, but rows whose verdict depends on `credit·diode_area` are refused because the unit is unstated) | State the unit (µm²) and un-refuse; separate thin/thick-oxide rows (gf180 ANT.16) |
| ESD path existence | Every pad reaches a clamp to each rail; Calibre PERC topology [C1] | **not functional** (`esd_topological` flags every pad net because a deck cannot name a clamp model) | Clamp device recognition; path search pad→clamp→rail |
| ESD P2P resistance | Pad→clamp→rail effective resistance ≤ R [C1, C2] | partial (`p2p_resistance`: worst pair *within one net*) | Paths through the clamp device (across nets) |
| ESD current density | Wire and via width along the ESD path under pulse current [C2] | partial (`em_current_density` with DC solve) | Pulse-current source model on the ESD path |
| CDM / cross-domain ESD | Cross-domain gate protection (secondary clamp, series R) | missing | — |
| EM, average/DC | Black's equation (MTTF ∝ J⁻ⁿ·e^{Ea/kT}) [E4]; Blech immortality (jL < (jL)c) [E5] | have (`em_current_density`, `electromigration` with Blech + T derating) | NEED_TESTING lists four independent fail-opens |
| EM, RMS / peak | Joule-heating RMS limit and peak limit per layer (signal nets) | missing | Needs activity/waveform input |
| Self-heating | FinFET device SHE raising local T for EM | missing | Only relevant for ASAP7-class nodes |
| IR drop static | Node V vs budget | have (`ir_drop`) | — |
| IR drop dynamic | Transient/vectorless | missing | Nice-to-have for these PDKs |
| TDDB / voltage lifetime | Lifetime under voltage stress | have (`reliability`) | — |
| CMP thickness | Density → thickness | have (`density_cmp`) | untested |
| Floating labels / pins (LVS hygiene) | sky130 x.17 | missing | — |

Net-aware DRC (same-net vs different-net spacing, VA-DRC) sits between the DRC and ERC tables. It needs the extracted `NetTable` fed into DRC, and possibly a voltage per net.

---

## 3. Prioritised gap list for "0 issues past signoff"

### P0: wrong answers today (fix before adding anything)
1. F1: fix `asymmetric_enclosure` to "both sides of one axis" (`max(min(L,R), min(B,T))`), or rename it and add the correct kind.
2. F8: antenna. Support perimeter × thickness collectors, use staged connectivity per etch step (the SVRF `CONNECT … ACCUMULATE` model), require the gate to be a derived `poly and diff` layer, and state the diode-credit unit. Until then, gf180 ERC cannot pass and sky130 has no antenna check.
3. F4: tile density windows over the die/chip box, not the layer extent. Add a global-density form.
4. F3: exact-size / square-cut kind (`width == w` on both axes).
5. F2: define "wide" by opening (`sized(-w/2).sized(+w/2)`) and add the "attached within d" variant.
6. F7: retire vertex-based `max_distance_to_tap` in favour of `missing_tie` semantics, or make it point-exact.
7. F5: edge-exact enclosure, extension and overlap for non-rectangular hosts, holes included.
8. F6: per-layer `angle`.

### P1: needed for sky130 / gf180 / IHP sign-off parity (derived ops + kinds)
1. **Derived ops:** `interacting`/`not_interacting`, `inside`/`outside`/`covering`/`overlapping`, `sized` (grow/shrink), `holes`, and selection by area, width and length. Edge layers (butting and coincident edges) are needed for n/psd.5a/5b/6 and difftap.4-7.
2. **Presence kinds:** "non-empty is an error" (forbidden overlap, straddle, forbidden layers), "outer must contain ≥ N inner" (licon.16, licon.18, nwell.4, rpm.1g-k counts), "must be rectangle".
3. **Net-aware spacing** (same net vs different net): gf180 NW.2a/2b, sky130 nwell.7/8, IHP NW.b/b1, NBL.b/c.
4. **Width × PRL spacing tables** (IHP M1.e/f through TM2).
5. **Min/max enclosure and extension** (npc.5, IHP Sdiod, LU.c/d max tie extension).
6. **Text-label-conditioned derived layers** (IHP device recognition via text; sky130 HV tags).
7. **Max area and per-chip totals** (pad.3, MIM.gR, npn counts).
8. **Pin/label hygiene** (x.5, Pin.*).
9. Deck-level **severity and switches** (recommended vs required; Al vs Cu backend; RC/RR).

### P1: concrete sky130.json omissions (all from the periphery table [S1])

Layers missing from the deck: `npc` 95/20, `dnwell`, `hvi`, `hvntm`, `poly_rs` (poly res purpose), `diff_rs`, `areaid.sc`/`ce`/`analog`, `capm`, `pad`, `nsm`, and the pin/label purposes. GDS numbers are in `docs/rules/gds_layers.csv` [S1].

| Rule | Text (value) | Expressible now? |
|---|---|---|
| licon.1 / ct.1 / via.1a / via2.1a… | exact square 0.17 / 0.17 / 0.15 / 0.20 | no (P0-4) |
| licon.5a | diff encloses licon 0.04 | yes: `min_enclosure(diff, licon_diff)`, with `licon_diff = licon and diff` |
| licon.5b | tap-licon to diff-abutting tap edge 0.06 | no (edge ops) |
| licon.5c | diff encloses licon on 2 opposite sides 0.06 | after F1 fix |
| licon.6 | licon cannot straddle tap | no (straddle kind) |
| licon.7 | tap encloses licon on 2 opposite edges 0.12 | after F1 fix |
| licon.8 / 8a | poly encloses poly_licon 0.05 / opposite sides 0.08 | yes / after F1 |
| licon.9 | poly_licon to psdm, no overlap, 0.11 | yes: `min_spacing_diff(licon and poly, psdm)` |
| licon.10 | licon on (tap and nwell not hvi) to Var_channel 0.25 | yes, once the layers are declared |
| licon.11 / 11a | licon on diff/tap to gate 0.055 (0.05 inside areaid.sc) | yes: `min_spacing_diff((licon and (diff or tap)) not areaid_sc, poly and diff)` |
| licon.13 | npc to licon on diff/tap, no overlap, 0.09 | yes (declare npc) |
| licon.14 | poly_licon to diff/tap 0.19 | yes |
| licon.15 | npc encloses poly_licon 0.10 | yes |
| licon.16 | every tap (and source diff) contains a licon | no (presence kind) |
| licon.17 | licon may not overlap poly and (diff or tap) together | no (forbidden kind) |
| licon.18 | npc must enclose poly_licon | partial (enclosure 0) |
| difftap.3 | non-abutting diff to tap 0.27 | partial (needs "not abutting" edges) |
| difftap.8 / .10 | nwell encloses p+diff / n+tap 0.18 | yes (derived `diff and psdm`, `tap and nsdm`) |
| difftap.9 / .11 | n+diff to nwell 0.34 / p+tap to nwell 0.13 | yes |
| poly.1b | pfet-in-lvtn gate length 0.35 | yes |
| poly.3 / poly.9 | poly resistor width 0.33 / resistor to poly-diff-tap 0.48 | yes (declare poly_rs) |
| poly.4 / .6 | poly on field to diff 0.075 (projection) / gate to abutting tap 0.30 | euclidean approximation only |
| poly.10 / .11 / .12 | inner corners / no 90° on diff / poly-not-nwell over tap | no |
| npc.1 / .2 / .4 | npc width 0.27, space 0.27, npc to gate 0.09 | yes (declare npc) |
| n/psd.5a/5b/6/7/8/9 | implant enclosures and butting-edge rules | 7, 8 and 9 yes; 5a, 5b and 6 need edge ops |
| hvtp.3/4, lvtn.3a/3b/4b/10/12, ncm.* | Vt-implant to gate | yes |
| rpm.3/4/5/7/8/9 | precision resistor enclosures (rbody = `poly and poly_rs and rpm`) | 3, 4, 5, 7 and 9 yes; 8 needs straddle |
| m1.3ab–m4.5ab | huge-metal spacing | mismatch (P0-5) |
| m1.5, via.5a, li.5 … | opposite-side enclosure | mismatch (P0-1) |
| x.2 | 90°-only layers | P0-8 |
| nwell.4 | contacted tap in every nwell | partial (ERC) |
| nwell.5/6/7, dnwell.2/3 | deep-nwell rules | yes except the nwell.7 separate-net part |
| hvi.*, difftap.14-26, poly.13/14, hvntm.*, hv.* | 5 V device rules | mostly yes via the `hvi` marker; hv.* needs net propagation |
| Antenna (all of antenna.rst) | EGAR with perimeter areas and diode credit | no (P0-2) |
| Density | m*.pd (RR), plus efabless chip-level ca-density | no (P0-3) |

The Magic names the downstream user used map onto this deck as `polyc` (Magic `polycont`) = `licon and poly` and `rbody` = `poly and poly_rs` (and `rpm` for p+ precision). `and`/`not`/`or` can derive both, but the source layers (`poly_rs` 66/13, `npc`) are absent from `sky130.json`.

### P1: gf180mcu.json and ihp_sg13g2.json
- gf180: fix the antenna rows (P0-2; `ANT.1` names `poly2` twice). Split every rule into `_3.3V` / `_5V` with DUALGATE/V5_XTOR derived layers. Add NW.2a/2b same/different net, DF.13/14 LU distance through `missing_tie`, and the global density M1.4 ">30 % over die". Add the per-layer offgrid/angle rows.
- IHP: add `floating_well` and LU.a/b (`missing_tie`). Replace the metal density rows with `metalN or metalN_filler`, and add the global AFil.g/M*.j/k. Add M*.e/f (width × PRL), Seal.*, Pin.* and Cnt.g/h/j. `hv_domain` needs 1.2 V vs 3.3 V (ThickGateOx).

### P2: nice-to-have for these PDKs
EOL variants with `within`/parallel-edge conditions, pitch/track rules, SAV alignment,
pre-coloured MP (ASAP7-class only). Also dynamic IR, RMS/peak EM, self-heating,
cell-name exemptions, frame/etest rules, and 45° geometry (sky130 allows 45° on metals;
the tool is rectilinear-only, which *refuses* rather than passes, so the direction is correct).

---

## 4. Part B: deck-language prior art

### 4.1 How existing languages handle the five needs

| Language | Derived layers | Rule tables | Conditions | Reuse / variables | Validation / strictness | Code execution |
|---|---|---|---|---|---|---|
| **SVRF** (Calibre) [F1] | Assignments `x = poly AND diff`, plus selection ops (`INTERACT`, `ENCLOSE`, `INSIDE`, `SIZE`) | Constraint expressions on ops (`EXT m1 < 0.065`); `RECTANGLE ENCLOSURE … GOOD … OPPOSITE` | Layer selection, preprocessor `#IFDEF`, `VARIABLE` switches | Named layers and variables; no functions | Tool-checked syntax; proprietary spec | None (declarative) |
| **KLayout DRC** [K1] | Ruby method chains (`licon.and(poly)`, `.sized`, `.interacting`, `.edges`) | Written by hand (IHP expands M1.e/M1.f into separate chains) | Ruby `if`, `layout.select` by cell, `with_*` selectors | Full Ruby: functions, loops, JSON-loaded values (IHP `sg13g2_tech_default.json`) | Runtime errors only | **Full Ruby: arbitrary code, file and network I/O** |
| **Magic techfile** [M1] | `cifinput`/`cifoutput` templayers: `and`, `and-not`, `grow`, `shrink`, `bloat-or`, `interacting` | `widespacing types wwidth runlength types2 dist` (one width × PRL row per line) | `variants`, per-rule flags (`directional`, `absence_ok`, `touching_ok`) | `alias`, macros | Parse-time positional checking; terse errors | None |
| **gf180/IHP KLayout decks** [G1, I1] | As KLayout, plus custom helpers (`conn_space`, `ext_interacting_with_text`) | Values moved to a JSON table (IHP) | Ruby switches (`FEOL`, `PRECHECK_DRC`, `CONNECTIVITY_RULES`) | Ruby methods | None beyond Ruby | Full Ruby |
| **GPurify JSON** (today) | `{name, op: and/or/not, layers}` | One row per rule; no tables | None | None (a metal stack is written out by hand) | Strict: unknown keys refused, units required (`{"nm": 140}`), typed params | None |
| **TOML** (`toml` 1.1) | Must be strings or nested inline tables | Arrays of tables | None | None | serde `deny_unknown_fields`, spans via `toml_edit` | None |
| **RON** (`ron` 0.12) | Native enums: `And(Layer("poly"), Or([…]))`, typed via serde | Arrays of structs | None | None | Strongest serde typing; decent positions | None |
| **KDL v2** (`kdl` 6.7, `knus` 3.4 derive) | Node trees, or a string sub-grammar | Child nodes as rows | None | None | Type annotations on values, e.g. `(nm)140`, can carry units. `miette` span diagnostics. `knus` derive gives typed decode with spans. | None |
| **Dhall** (`serde_dhall` 0.13) | Unions + functions | Lists of records | `if` | Functions, let | Static types, total (always terminates) | Imports may fetch URLs; disable them |
| **CUE** | Unification | Lists | Disjunctions and constraints | Definitions | Best-in-class constraint validation | Go-only; Rust through `cue-rs` wraps the Go runtime (cgo) [B1] |
| **Starlark** (`starlark` 0.14, Meta) | Builtins return typed values | Python lists/dicts | `if` | Functions and `for` loops; no `while`, no recursion, so evaluation terminates | Optional type annotations; builtins validate eagerly | Hermetic: no I/O unless the host exposes it |
| **Nickel** (`nickel-lang-core` 0.19) | Records, functions | Arrays | `if` | Functions, merging | Contracts (runtime-checked types), good blame messages | Pure; no I/O |

### 4.2 Recommendation

1. **Primary: a small declarative deck DSL of our own, parsed in Rust, that lowers into the same typed rule IR as the JSON.** SVRF and Magic show that a declarative statement language, with no general computation, covers every rule in sections 1–2. It needs:
   - `layer`/`derive` statements with an infix layer algebra (`and or not`, `sized`, `interacting`, `inside`, `edges`, `holes`, `with_width`);
   - one statement per rule, with keyword parameters that are all required and carry units (`space m1 >= 140nm`);
   - `table` literals for width × PRL spacing;
   - `when <marker>` blocks for voltage and marker variants;
   - bounded `for m in [met1..met5]` expansion over declared lists for reuse. Nothing else, so every deck terminates.

   Parse it with a hand-written or `chumsky`/`winnow` parser and report errors with `miette`/`ariadne` spans. Because the grammar is ours, strictness can be total: a missing parameter, a bare number, an unknown layer or a unit mismatch is a parse error with a caret. There is no code execution. KDL v2 can serve as the *surface syntax* to skip writing the outer parser: its `(nm)140` type annotations already give unit-typed literals and `knus` gives spanned typed decode. The layer-expression grammar is still ours, since it lives inside KDL strings or argument lists.

2. **Secondary: Starlark as an optional generator front-end** for foundries or users who want functions and loops (gf180 duplicates every rule for 3.3 V and 5 V; IHP repeats M2–M5). Starlark is hermetic, has no `while` or recursion so evaluation terminates, has a maintained Rust crate, and its builtins can build the same typed IR and validate on construction. This keeps the canonical deck strict and data-only while allowing reuse.

Not recommended: CUE (Go runtime), because the tool is Rust. KLayout-style embedded Ruby or Lua, because it gives arbitrary code execution. TOML, because nested layer expressions and tables become unreadable. Dhall and Nickel work, but PDK engineers are unlikely to know them, and their error messages are about the config language rather than about DRC.

---

## Sources

- [S1] SkyWater SKY130 periphery rules (generated from `periphery.csv`): https://github.com/google/skywater-pdk/blob/main/docs/rules/periphery-rules.rst and https://github.com/google/skywater-pdk/blob/main/docs/rules/periphery/periphery.csv; rendered at https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html; GDS layers at https://github.com/google/skywater-pdk/blob/main/docs/rules/gds_layers.csv
- [S2] open_pdks sky130 KLayout DRC deck: https://github.com/RTimothyEdwards/open_pdks/blob/master/sky130/klayout/sky130.lydrc
- [S3] efabless mpw_precheck decks (sky130A_mr.drc, met_min_ca_density.lydrc, zeroarea.rb.drc, run_scheck, run_cvc): https://github.com/efabless/mpw_precheck/tree/main/checks
- [S4] sky130 antenna rules: https://github.com/google/skywater-pdk/blob/main/docs/rules/antenna.rst
- [G1] GF180MCU KLayout DRC decks (comp, nwell, metal1, via1, esd, poly2, geometry_rules, gf180mcu_antenna, gf180mcu_density): https://github.com/google/globalfoundries-pdk-libs-gf180mcu_fd_pr/tree/main/rules/klayout/drc
- [I1] IHP SG13G2 KLayout DRC (rule_decks/*, sg13g2_maximal.drc, antenna.drc, density.drc, 7_2_latchup.drc): https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.tech/klayout/tech/drc
- [I2] IHP rule tables: https://github.com/IHP-GmbH/IHP-Open-PDK/blob/main/ihp-sg13g2/libs.tech/klayout/tech/drc/docs/main_rules.md and `docs/extra_rules.md`
- [A1] ASAP7 DRM (asap7_drm_201207a.pdf): https://github.com/The-OpenROAD-Project/asap7_pdk_r1p7/tree/main/docs
- [F1] FreePDK45 Calibre DRC deck (SVRF): https://github.com/mflowgen/freepdk-45nm/blob/master/calibre-drc-block.rule
- [K1] KLayout DRC layer reference: https://www.klayout.de/doc/about/drc_ref_layer.html
- [M1] Magic technology file manual (DRC, `surround … directional`, `widespacing … runlength`): http://opencircuitdesign.com/magic/techref/maint2.html
- [C1] Siemens Calibre PERC (ESD, P2P, CD, latch-up, VA-DRC): https://www.siemens.com/en-us/products/ic/calibre-design/reliability-verification/perc/ and https://resources.sw.siemens.com/en-US/technical-paper-calibre-perc-advanced-voltage-aware-drc-delivers-exacting-accuracy-for/
- [C2] Synopsys, "What is PERC": https://www.synopsys.com/glossary/what-is-programmable-electrical-rules-checking.html
- [E1] CVC Circuit Validity Checker (error classes: forward-bias diode, gate vs source, source vs bulk, Hi-Z input, EOS, LDD orientation): https://github.com/d-m-bailey/cvc and https://woset-workshop.github.io/PDFs/2020/a05.pdf
- [E3] JEDEC JESD78, IC Latch-Up Test: https://www.jedec.org/standards-documents/docs/jesd-78e
- [E4] J. R. Black, "Electromigration — A brief survey and some recent results", IEEE Trans. Electron Devices 16(4), 1969, doi:10.1109/T-ED.1969.16754
- [E5] I. A. Blech, "Electromigration in thin aluminum films on titanium nitride", J. Appl. Phys. 47, 1203 (1976), doi:10.1063/1.322842
- [B1] CUE from Rust (`cue-rs` wraps libcue / Go runtime): https://github.com/cue-lang/cue/issues/3102 ; crate versions from crates.io API (kdl 6.7.1, knus 3.4.0, ron 0.12.2, toml 1.1.6, starlark 0.14.2, nickel-lang-core 0.19.0, serde_dhall 0.13.0), 2026-09-23.

[E3], [E4] and [E5] are cited by reference and were not re-fetched.
