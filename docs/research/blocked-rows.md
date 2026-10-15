# Blocked rows: public definitions found (R4)

Earlier rounds marked these catalog rows (`docs/check-catalog.tsv`) "not
definable from public sources". R4 searched again, starting from what each
row's notes say was already checked. This file is research only: it changes
no product code and no catalog row. Where it disagrees with a catalog note, it
says so under [Catalog corrections](#catalog-corrections).

Each row section below gives a **verdict** (found / partial / not found /
needs fetch), the **definition** quoted with an exact citation, whether it is
**implementable** (a sketch, deck parameters and an oracle), and what was
**checked** with no result.

The sections use three words with fixed meanings:

- **definition**: a public text states the rule;
- **reading**: an open implementation does something, which is evidence of
  what the rule means but not a statement of it;
- **derivation**: R4's inference from a text, a figure or a name. A check
  built on a derivation must say so in its doc comment.

## Sources and abbreviations

| Tag | Source |
|---|---|
| [LEF58] | Cadence, *LEF/DEF 5.8 Language Reference*, May 2017: the edition `crates/ingest/src/lefdef` cites. `ref.txt:N` is line N of a `pdftotext -layout` extraction; the printed page is authoritative. |
| [LEF57] | Cadence, *LEF/DEF Language Reference, Product Version 5.7*, November 2009, posted by the ISPD 2018 and 2019 contest organisers: <https://www.ispd.cc/contests/18/lefdefref.pdf> (byte-identical copy at `/contests/19/`; md5 `bfd45c93f73a907ef336ac6cbb47f864`). Despite the 5.7 label, it documents 32/45 nm LEF58_ properties that [LEF58] omits: LEF58_MINSTEP, LEF58_SPACING (cut), LEF58_MINIMUMCUT AREA and others. Earlier rounds had not used it. Every footer reads "November 2009", and the PDF metadata shows only a 2014 re-save. `ref57.txt:N` is a line of its extraction; the printed page equals the PDF page. |
| [OR] | OpenROAD master @ `3549d60529517dc82deb7f0ff769345e9a424911` (2026-10-15). `path:line` links resolve as `https://github.com/The-OpenROAD-Project/OpenROAD/blob/3549d60529517dc82deb7f0ff769345e9a424911/<path>#L<line>`. |
| KLayout | `KLayout/klayout` @ `4d927b797d7e2fc9ab2d8ec29781fa6559851663` |
| Netgen | `RTimothyEdwards/netgen` @ `e5a185dcfa16ee6317883f02bfdc8cf10feabd0e` |
| Magic | `RTimothyEdwards/magic` @ `bed8d4ff84333767aa923d469d339cd05c56a00a` |
| [iEDA] | `OSCC-Project/iEDA` @ `65c39fd28aa0dc0cdd56325df07f6e440069061b`: a second open LEF58 reading (parser and iDRC). |
| [WXL] | Kahng, Wang, Xu, "TritonRoute-WXL: The Open Source Router with Integrated DRC Engine", IEEE TCAD, doi:10.1109/TCAD.2021.3079268; author copy <https://vlsicad.ucsd.edu/Publications/Journals/j136.pdf> |
| [DRM] | ASAP7 DRM, `docs/asap7_drm_201207a.pdf` in `The-OpenROAD-Project/asap7_pdk_r1p7` @ `58d72c9d291e186a77468586ab0c43d8a21eda6a` |
| P12 | US 2010/0306720 A1 (Pikus, Lu, Brooks; Mentor Graphics), "Programmable Electrical Rule Checking", 41 pp. Abandoned; no granted family member found. Cited by paragraph [NNNN]. |
| [GF] | US 9,613,175 B2 (GLOBALFOUNDRIES, Hensel et al., 2017) |

Patents are cited by column:line or paragraph. Google Patents, Justia and
FreePatentsOnline block scripted access. The USPTO image server does not:
`https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/<number>`
(e.g. `20100306720`, `9087174`). That is how P12 and the other patents here
were read.

**Sources deliberately not used.** The brief forbids leaked or pirated
proprietary manuals, so these were seen in search results and not opened, or
opened and not cited:
- Calibre SVRF/PERC manuals reposted on Scribd, docplayer and iczhiku, and
  Chinese blog paraphrases of them (mweda, jianshu);
- a third-party mirror of Cadence Encounter 14.17 documentation
  (`free-online-ebooks.appspot.com`), which appears to define LEF58_MAXSPACING;
- a pdfcoffee.com copy of a Cadence document;
- two foundry tech LEFs reposted in student GitHub repos without a licence (an
  STMicro 28FDSOI kit LEF and an educational `cadence_cap_tech/tech.lef`);
- foundry Calibre decks reposted in student repos.

All the two LEFs show is that MINIMUMCUT AREA, ADJACENTCUTS EXACTALIGNED and
PROTRUSIONWIDTH with a positive LENGTH occur in real kits.

## Summary

| Row | Verdict | What changes |
|---|---|---|
| DRC-127 cell edge-type spacing | **partial**, implementable on LEF+DEF | **Public text:** ISPD 2014 contest Suite A slides and the ICCAD 2017 Problem C FAQ state the core rule. **Readings:** OpenROAD dpl and Ripple. **Still undefined:** OPTIONAL, SOFT and EXCEPTNONFILLERINBETWEEN; EXCEPTABUTTED is defined by name only. **Needed in GPurify:** the LEF reader must keep two PROPERTY strings. |
| DRC-128 SADP/SAQP legality | **found** (SADP), partial (SAQP) | US 2015/0286764 A1 (GF): different/same/free colour spacing bands, a cycle with an odd number of different-colour edges is illegal, and wide lines span an odd number of tracks. Xu et al. TCAD 2015 gives the 1-D line-end rules. |
| ERC-A15 required diode area | **found** | IHP SG13G2 Ant.g Note 4, `PDarea = 0.02 x Vn_area/gate_area`. The sky130 DRM's linear model and US 9,142,556 solve for the area; inverting the LEF PWL matches the DRM. |
| ERC-D9 PMOS/NMOS well sharing | **partial**, implementable | US 5,638,286, a topological well-sharing latch-up check. What Calibre PERC's own check forbids is still not public. |
| ERC-F4 HCI flag | **partial** | No static stress condition is public. GF180 §14.1.4.1(e) gives a structural flag, min-L NMOS used bidirectionally, at warning severity. |
| ERC-H3 netlist path checks | **partial** | P12 full text: net types, type sets, paths, -break/-exclude, path types (all implementable). P12 has no device counting; HP US 6,367,062 gives a one-per-device convention. |
| ERC-G3 multiple drivers | **partial** | The pieces are public: the driver predicate (US 6,077,717), the exact conflict test (Afonso and Monteiro, DATE 2017), and CVC as a dynamic differential. No source states the check itself. |
| ERC-G7 gate tied to rail | **partial** | The P12 device-check mechanism, the TSMC rationale, and a decap exemption (US 6,077,717). |
| ERC-G9 path check | **partial** | P12 semantics are confirmed with paragraph numbers. A path also stops "at a port in the top cell" ([0262]). PATHCHK's LABELED and NOFLOAT are still not public. |
| LVS-042 semi-series MOS | **not found** | Calibre lists SEMI SERIES MOS separately from SERIES MOS and SPLIT GATES (public sky130 report), but no public text defines it. |
| LVS-048 filter unused | **partial** | US 8,751,985 col. 7 (not col. 9) quotes options AE, AF, AG, C, K, P, Q and U. **C becomes definable** via P12 [0162]. K, P and Q still need "path" and "pad". |
| DRC-015 WIDTHTABLE | **partial** | **Found:** ASAP7 M4.W.3/W.4 text (legal widths 24·(4k+1)); WIDTHTABLE ORTHOGONAL text and Fig. 1-33, with TritonRoute as a reading. **Undefined:** the fracture; a distinguishing test shape is given. |
| DRC-016 WRONGDIRECTION | **partial** | **Reading:** negative PRL, from WXL Fig. 7b and TritonRoute's signed PRL. **Undefined:** LENGTH. |
| DRC-021 bent-feature length | **partial** | **Definition:** the Magic tech manual's centerline length with a corner `chop`, matched by the Magic and KLayout extractors. **Missing:** no foundry says its length rules use it. |
| DRC-031 ASAP7 M4.S.4 | **found** | DRM Fig. 3.14.2(d): the same-facing line-end offset on adjacent tracks must be 0 or ≥ 40 nm. Confirmed by Xu et al. Rule 4, Cadence rule 708B and the ASU KLayout deck. |
| DRC-036 SPANLENGTH ORTHOGONAL | **partial** | A derivation from [LEF58] Fig. 1-31: opposite-quadrant concave corners, Euclidean distance. |
| DRC-053 EXACTALIGNED | **found** (cut form) | [LEF57] pp. 55-57 and 61-62, with Fig. 1-21 a-d. The catalog's metal form exists in no public grammar. |
| DRC-066 MINIMUMCUT | **partial** | AREA [WITHIN] is **found** ([LEF57] pp. 157-160, Fig. 1-65). SAMEMETALOVERLAP and FULLYENCLOSED are not found. |
| DRC-125 PROTRUSIONWIDTH LENGTH | **partial** | A derivation from the [LEF58] pp. 76-77 text and Fig. 1-16 a-c, with hand oracles. No implementation exists. |
| DRC-126 KEEPOUTZONE options | **not found** | **New evidence:** a BSD-licensed ASAP7 LEF uses a HORIZONTAL/VERTICALEXTENSION form that OpenROAD drops. **Correction:** OpenROAD drops the whole rule rather than "never checks" it. |
| DRC-130 enclose rectangle | **not found** beyond the current definition | GF's own deck codes MSLOT.1 by the same opening, which gives a second oracle. |
| DRC-020 LEF58_MINSTEP | **mostly found** | **Found:** [LEF57] pp. 161-166 defines CONVEXCORNER, the second MINADJACENTLENGTH and MINBETWEENLENGTH/EXCEPTSAMECORNERS, with figure oracles. **Reading only:** NOADJACENTEOL. **Not found:** CONCAVECORNER. |
| DRC-027 negative PRL | **partial** | **Reading:** from WXL and TritonRoute. **Correction:** "clamps to 0" is iEDA's behaviour, not TritonRoute's. |
| DRC-034 LEF58_MAXSPACING | **needs fetch** | The only defining text found is in a vendor-doc mirror, which was not used; the Si2 download is the legitimate route. |
| DRC-042 LEF58_ENCLOSURE EOL | **partial** | Readings only: TritonRoute via generation and iEDA's LEF58_EOLENCLOSURE. |
| DRC-075 GF180 MSLOT.4 maximum | **partial** | The DRM figure shows across-width pairs; gdscheck gives a test. End-to-end and diagonal pairs are undefined. |
| DRC-102 PARALLELSAMEMASK | **partial** | Grammar position plus the [GF] same-mask EOL concept; the check would be a derivation. |
| DRC-103 stitch legality | **partial** | The Abercrombie (Mentor) Fig. 4 allowed-stitch regions, plus Kahng 2008. The via-landing ban is not public. |
| DRC-105 TRIMMETAL | **partial** | Generic trim-mask rules are found in US 9,087,174 (Cadence) and two IBM patents. LEF58 `LAYER trim OVERLAP n` is undefined. |
| LVS-047 gate recognition | **partial** | **Found:** P12 gives SIMPLE vs ALL and the dependence on power names; HP US 6,077,717 gives NAND/NOR predicates. **Not public:** the gate catalogue. |
| ERC-C9 CDM bus inductance | **partial** | The Russ et al. 2021 public slides give a quasi-static R+jωL method. No limit is public, so it is deck-supplied. |

The rows outside the brief's list (DRC-020, 027, 034, 042, 075, 102, 103,
105, LVS-047 and ERC-C9) came from grepping the catalog notes for "no public",
"not public", "undefined" and "not defined". Rows whose notes say only that
no public deck states a *value* (DRC-007, 068, 076, 090, 111-114, 117, 129,
ERC-C3, C4, C6, C8, C10, C14, E7, PEX-011/012/015) were left out, because the
rule is defined and only its number is deck-supplied. Also left out: DRC-095
(the partnum is a pcell), ERC-E12 (no rule exists), LVS-065, and FLOW-010
(Vision AI signatures, a product feature).

**N2.** N2 is also looking at LVS-042 and LVS-048. Its working notes
had independently found US 8,751,985 and implemented `filter_unused ae af ag
u`. The LVS-048 section below corrects its column citation and adds option C.

## Catalog corrections

This is text for the coordinator; the catalog is not edited here.

- **DRC-053:** the "metal form (spacing of exactly aligned line ends)"
  appears in no public grammar ([LEF57], [LEF58], [OR], Open-EDI, iEDA).
  Drop it, or point it at EOL EXACTWIDTH, which is a different rule. The cut
  form is defined in [LEF57]. Separately, `LEF58_SPACINGTABLE …
  EXACTALIGNEDSPACING` is implementable from [OR]
  `src/drt/src/gc/FlexGC_cut.cpp:112-124`; that belongs to DRC-063.
- **DRC-066:** AREA [WITHIN] is defined ([LEF57] pp. 157-160), so the note's
  "no public definition" now holds only for SAMEMETALOVERLAP and
  FULLYENCLOSED.
- **DRC-126:** the note says OpenROAD "parses but never checks"
  EXTENSION/SPIRALEXTENSION. In fact [OR] `src/drt/src/io/io.cpp:2169-2214`
  drops the whole rule (DRT-327/328) and ignores EXCEPTEXACTALIGNED. A fourth
  form, HORIZONTALEXTENSION/VERTICALEXTENSION, occurs in
  `The-OpenROAD-Project/asap7sc6t_26` `techlef_misc/asap7sc6t_tech_4x_210831.lef`.
- **DRC-027 / DRC-016:** TritonRoute does carry a negative PRL through
  (signed `getPrl`, [OR] `FlexGC_main.cpp:843-893`), except for exactly −1
  dbu, which collides with odb's "no PRL" sentinel. Clamping to 0 is iEDA's
  behaviour. For the wrong-direction rule, DRT-334 and the query box are what
  drop it.
- **DRC-015:** TritonRoute reads WIDTHTABLE ORTHOGONAL ([OR]
  `FlexGC_main.cpp:1481-1551`), so ORTHOGONAL is defined and read. TritonRoute
  deviates from [LEF58] Fig. 1-33 on the wrong-way width.
- **DRC-020:** [LEF57] pp. 161-166 defines CONVEXCORNER, minAdjLength2 and
  MINBETWEENLENGTH/EXCEPTSAMECORNERS, so the note's "no public text defines
  LEF58_MINSTEP" is out of date.
- **LVS-048:** US 8,751,985 lists the options at **col. 7 ll. 44-62**, not
  col. 9. Option C becomes definable: P12 [0162] says the LVS power and
  ground names are what "filtering of unused MOS" uses.
- **ERC-G9:** P12 [0262] also stops a path at "a port in the top cell".
  Check whether `supply_path` does.
- **ERC-H3:** cite P12 [0029] for the "three other devices" example and
  [0247]-[0267] for paths. P12 has no hop-count primitive; its paths are
  equivalence classes ([0265]).

# Rows

## DRC-127: Cell edge-type spacing between placed cells

**Verdict:** partial. The core rule is found: a public contest text defines it, and OpenROAD
and Ripple read it. The options OPTIONAL, SOFT and EXCEPTNONFILLERINBETWEEN are still undefined,
and EXCEPTABUTTED is defined by name only.

**Definition (public text):**
- ISPD 2014 Detailed Routing-Driven Placement Contest, Benchmark Suite A (Mentor), slide 16
  (http://www.ispd.cc/contests/14/web/benchmarks/A/Benchmark_Suite_A.pdf, PDF p.16) says:
  "Each **vertical edge** of a cell may have specified minimum spacings from any other
  vertical cell edge that can be placed right or left of it." Its examples are: "The **left** edge of every
  ao22s01 cell must be placed at least 0.400um away from the **left** edge of every other
  ao22s01 cell". This applies left-to-left, so it covers more than facing edges. A second example
  reads "...at least 0.800um away from the **right** edge of every other a022s01 cell adjacent to it."
  Slide 27 shows the LEF form: `LIBRARY LEF58_CELLEDGESPACINGTABLE STRING "CELLEDGESPACINGTABLE
  EDGETYPE 1 2 0.400 EDGETYPE 1 1 0.400 EDGETYPE 2 2 0.000;"` and `MACRO LEF58_EDGETYPE STRING`.
  Slide 17 has four pictured violations.
- ICCAD 2017 CAD Contest Problem C, FAQ (http://iccad-contest.org/2017/Problem_C/default.html):
  - Q: is "EDGETYPE 1 2 0.400" applied to a right edge of type 2 facing a left edge of type 1? A: "Yes,
    because for a pair of edge types, the edge spacing rules are symmetric."
  - Cells carry `PROPERTY LEF58_EDGETYPE " EDGETYPE LEFT 2 ; EDGETYPE RIGHT 2 ; "`, and "if a
    cell c1 with EDGETYPE 1 for its left edge is place just on the right side of cell c2,
    there must be a gap equal to 0.400 between two cells c1 and c2."
  - Edge spacing is a soft constraint. The contest counts `S_v = min(0.2, N_v/N_cells)` violations, with
    cell flipping allowed.
- OpenROAD issue #3899 (https://github.com/The-OpenROAD-Project/OpenROAD/issues/3899) gives an
  abstracted real-PDK example. It has `EDGETYPE TYPE1 TYPE1 EXCEPTABUTTED 0.XXX`, and TOP/BOTTOM
  edges typed by `RANGE` (`EDGETYPE TOP TYPE4 RANGE 0 0.VVV ; EDGETYPE TOP TYPE3 RANGE 0.VVV 0.QQQ ;`).
  So horizontal-edge spacing across rows occurs in practice.
- LEF/DEF 5.8 (ref.txt) has neither property. That is confirmed: grep finds no EDGETYPE or CELLEDGE.

**Grammar (reading: OR parser):**
- Library: `CELLEDGESPACINGTABLE [NODEFAULT] { EDGETYPE t1 t2 [EXCEPTABUTTED]
  [EXCEPTNONFILLERINBETWEEN] [OPTIONAL] [SOFT] [EXACT] spacing }... ;`. The options must come in that
  order. A type name is any non-blank token, including numerals and `DEFAULT`. `NODEFAULT` is accepted
  and discarded. Sources: OR src/odb/src/lefin/CellEdgeSpacingTableParser.cpp:52-94; fields in
  src/odb/src/codeGenerator/schema/tech/dbCellEdgeSpacing.json.
- Macro: `EDGETYPE {RIGHT|LEFT|TOP|BOTTOM} type [CELLROW n | HALFROW n | RANGE begin end] ;`,
  with one statement per edge segment (OR src/odb/src/lefin/lefMacroEdgeTypeParser.cpp:39-70).
- Tests: OR src/odb/test/data/gscl45nm.lef:12-17 has all four flag combinations, checked at
  src/odb/test/cpp/TestLef58Properties.cpp:515-551. lef58_celledgespacing_numeric.lef and
  lef58_macro_edgetype_numeric.lef cover numeric names and `TOP G2 RANGE 0.5 1.5`
  (TestLef58Properties.cpp:666-735).

**What dpl does (reading):**
- Table: symmetric `[t1][t2] = [t2][t1]`. Unlisted pairs get 0. A later statement for the same pair
  overwrites an earlier one. dpl keeps only `spacing`, `EXACT` and `EXCEPTABUTTED`
  (src/dpl/src/PlacementDRC.cpp:462-493).
- **EXCEPTABUTTED is stored but never consulted.** Grep finds `except_abutted` only in the constructor
  (PlacementDRC.h:21-33, PlacementDRC.cpp:486-487). Abutment, which is distance 0, therefore violates
  any positive spacing. **OPTIONAL, SOFT, EXCEPTNONFILLERINBETWEEN and NODEFAULT are ignored.**
- Edge geometry (src/dpl/src/infrastructure/network.cxx:239-257, 375-437):
  - The cell box is the master placement boundary (SIZE, shifted by -ORIGIN; src/odb/src/db/dbMaster.cpp:668-674).
  - A LEFT/RIGHT/TOP/BOTTOM edge is that side of the box, as a zero-thickness segment.
  - TOP/BOTTOM with RANGE b e becomes x ∈ [xlo+b, xlo+e].
  - LEFT/RIGHT with CELLROW k becomes y ∈ [ylo+(k-1)·h, min(yhi, ylo+k·h)], where h = cell height / its row count.
  - HALFROW k is the same with h/2.
  - A RANGE on a vertical edge, or a CELLROW on a horizontal edge, is silently ignored.
  - An edge whose type is not in the table is dropped.
  - If the table names `DEFAULT`, the untyped remainder of every side becomes a DEFAULT edge.
  - CORE_SPACER (filler) masters get no edges, so a filler between two cells is transparent.
- Check (PlacementDRC.cpp:78-160):
  - Each edge is placed by the instance orientation (`dbTransform(orient)`, lines 25-40). Mirroring
    moves a LEFT-typed edge to the right side.
  - For edge1 of a cell, the query box is edge1 bloated perpendicular by max(row of table)+1.
  - edge2 is any parallel edge of another cell that *strictly* overlaps the query box
    (odb `Rect::overlaps` is strict, geom.h:737-741). That means a positive parallel run and a
    perpendicular distance ≤ max.
  - `dist` is the perpendicular distance between the two lines.
  - Violation if `EXACT ? dist == spc : dist < spc`.
  - **Facing is not required.** Any parallel pair counts, for example cell A's right edge against
    cell B's right edge. This matches the ISPD 2014 "left edge ... from the left edge" wording.
  - Corner-only contact (zero run) is not checked.
- Reporting: `check_placement` lists every offending *cell* under "LEF58_CELLEDGESPACINGTABLE"
  (src/dpl/src/CheckPlacement.cpp:78-81, 259-264).

**A second reading, Ripple** (cuhk-eda/ripple, the ICCAD 2017 Problem C legalizer; src/io/file_lefdef_db.cpp:540-595,
src/db/db.h:210-212):
- It checks facing edges only: `space(L.right, R.left)`, with the gap = R.left − L.right.
- It warns "ignore EXCEPTABUTTED" and drops the flag.
- Reserved type `default` (index 0) is forced to spacing 0.
- It reads only LEFT/RIGHT (TOP/BOTTOM are warned about).

So the two open readings differ on two points: non-facing pairs, and whether `DEFAULT` can carry spacing.

**Implementable?** Yes, on LEF+DEF. It is impossible from GDS alone, because no public convention draws edge types.
- Inputs:
  - the library property `LEF58_CELLEDGESPACINGTABLE`, from PROPERTYDEFINITIONS, LIBRARY;
  - per-MACRO `LEF58_EDGETYPE`;
  - MACRO SIZE/ORIGIN/CLASS;
  - DEF COMPONENTS with location and orientation.

  GPurify's crates/ingest/src/lefdef currently skips PROPERTY and PROPERTYDEFINITIONS, so it would
  need to keep these two strings.
- Operation:
  - Build typed edge segments per master (as above) and transform them per instance.
  - For every pair of parallel segments from different instances with a positive parallel run and
    perpendicular distance d: flag if d < spc(t1,t2), or d == spc for EXACT.
  - Skip CORE_SPACER masters.
- Deck parameters: a switch "facing edges only" (Ripple/ICCAD FAQ) versus "any parallel pair"
  (dpl/ISPD 2014 slide), defaulting to dpl's reading, and a switch for whether EXCEPTABUTTED exempts d == 0.
  EXCEPTABUTTED's meaning by name ("except when abutted") is a derivation that no public text spells out.
- Refuse, or warn on, OPTIONAL/SOFT/EXCEPTNONFILLERINBETWEEN (undefined).
- Oracle. All of these are from OR tests; DBU 2000/µm, site 380, row 2800.
  1. dpl/test/mirror_edge_spacing (.lef/.def/.ok/.defok).
     - Table: `VERTICAL_EDGE_2 VERTICAL_EDGE_2 0.5` (1000 DBU).
     - MOCK_ASYM is 1520 wide: LEFT=VERTICAL_EDGE_1 (not in the table, so dropped), RIGHT=VERTICAL_EDGE_2.
     - Row 0, all N: u1 at x 3800..5320 and u2 at 5320..6840. Their E2 edges are at 5320 and 6840,
       so d = 1520 ≥ 1000: clean.
     - Mirroring u2 to FN moves its E2 to x = 5320, on top of u1's E2: d = 0 < 1000, a **violation**.
       OR skips that mirror ("Skipped 1 instances...", DPL-0024).
     - u3 at (3800,5600) FN puts its E2 at 3800. The only other cell in the row, anchor3, has E2 at
       12920, so d = 9120: **clean**. The .defok has u3 FN.
  2. dpl/test/edge_spacing.defok (Nangate45/fake_macros.lef:168-211).
     - Table: `VERTICAL_EDGE_1 VERTICAL_EDGE_1 0.1 ; VERTICAL_EDGE_2 VERTICAL_EDGE_2 0.5`.
     - MOCK_DOUBLE has CELLROW 1 typed E1 and CELLROW 2 typed E2, on both sides.
     - u2 (7220..8740, y 11200..16800, N) and r3 (9880..11400, same rows): the gap is 1140.
       E1/E1 needs ≥ 200 and E2/E2 needs ≥ 1000: **clean**. At gap 760 (two sites), the CELLROW 2
       pair 760 < 1000 is a **violation**.
     - r2 (5700..7220, y 14000..16800, single row, E1) abuts u2 at x = 7220. u2's edge there in row 2
       is E2, and the pair (E1,E2) has spacing 0: **clean**. Abutment against u2's row-1 E1 edge
       (y 11200..14000) touches only at y = 14000, a zero run: **not checked**.
  3. Differential: run OpenROAD `read_lef ...; read_def ...; check_placement -verbose` and compare
     the set of flagged instances (OR reports cells, not pairs).

**Checked, nothing found:**
- LEF/DEF 5.8 ref.txt, and the ISPD-hosted 5.7 ref of Nov 2009 (ref57.txt): no EDGETYPE, CELLEDGE, EXCEPTABUTTED or NONFILLER.
- Web: exact-phrase searches for EXCEPTNONFILLERINBETWEEN / CELLEDGESPACINGTABLE (no Cadence or
  Si2 public page).
- The ISPD 2014 checker (bin/ispd2014_placement_checker, a Perl script by D. Chinnery). It checks
  only syntax, connectivity and instances, not edge types.
- ISPD 2014 rippledp.tgz is a binary library only.
- ICCAD 2017 03D_4_Karimpour_Darav.pdf link is dead (404 HTML).
- The Problem C slides (Bustany, p.16) only say "Two cells are too close to each other".
- iEDA (no EDGETYPE).
- A Google Patents query for edge-type spacing tables returned only DPT edge-label patents (US20130036397A1), not LEF58.

## DRC-128: SADP/SAQP (mandrel, spacer, cut) legality

**Verdict:** found for SADP, partial for SAQP. This was "partial" before the
patent pass.
- SADP decomposability now has a public, foundry-sourced definition (the
  GlobalFoundries patent below). It is a colour-constraint graph with
  must-be-different and must-be-same spacing bands; a loop with an odd
  number of different-colour edges is not decomposable. Wide lines must
  span an odd number of tracks.
- The trim/cut-mask rules are public in a Cadence patent (see DRC-105).
- Still missing: SAQP rules (only Toshiba's grid colouring is public) and
  real foundry rule values. No open deck checks any of this, and ASAP7
  states its SADP layers only as width, space and grid rules.

**Definition (added by the patent pass):** US 2015/0286764 A1
(GLOBALFOUNDRIES; Lei Yuan, Li Yang, Jongwook Kye; filed 2014-04-04), "Methods
of generating circuit layouts using self-aligned double patterning (SADP)
techniques".
- [0011]: mandrel-metal (MM) and non-mandrel-metal (NMM) features "are
  referred to as being different 'colors'".
- [0015]: "The SADP odd cycle check is generally more complicated than the
  LELE odd cycle check … when two features are spaced between 72 nm and
  120 nm, they must be on same color … This 'must-on-same-color' spacing
  rule is SADP specific … a SADP polygon loop for odd cycle check will
  compose same color edge (SC)", and the loop of FIG. 1N "consists of three
  different color (DC) edge and two same color (SC) edges and is not
  decomposable due to the odd number of DC edges".
- FIG. 1M ("SADP Spacing Rule", front page) gives three spacing bands:
  - S_MIN (e.g. 24 nm) ≤ s < S_INT (e.g. 72 nm): must be different colour.
  - S_INT ≤ s < S_LRG (e.g. 120 nm): must be same colour.
  - s ≥ S_LRG: colour insensitive.
- [0019]: "minimum different color (DC) pitch be 48 nm … minimum DC
  spacing … 24 nm. The minimum same color (SC) pitch … 96 nm, thus the same
  color spacing would be 72 nm … metal widths are generally required to be
  integer times the minimum width".
- [0020]–[0021]: "metal wires that occupy even number of tracks (2, 4,
  6, …) will cause violations of decomposition rules … a metal line must
  occupy an odd number of M2 tracks … 24 nm, 120 nm, 216 nm". This is the
  public reason behind ASAP7 M4.W.3/M4.W.4 (vertical width must be an odd
  multiple of the minimum width).

**Implementable (added):**
1. Build a graph over same-layer features. Add a DC edge when S_MIN ≤ s <
   S_INT and an SC edge when S_INT ≤ s < S_LRG.
2. Flag every cycle with an odd number of DC edges. Equivalently, the
   parity-labelled graph is not 2-colourable: union-find with parity, where
   DC edges have parity 1 and SC edges parity 0.
3. Separately, flag s < S_MIN, and flag wide lines whose width is not
   (2k+1)·w_min + 2k·s_min. On the 24/24 grid that is 24, 120, 216 … nm;
   ASAP7 M4.W.3 is the drawn form of this.

Deck parameters: `s_min, s_int, s_lrg, w_min`.

Oracle:
- FIG. 1L: five features in a loop, every gap < S_INT (five DC edges) → 1
  violation.
- FIG. 1N: a loop of three DC and two SC edges → 1 violation.
- Four features in a loop, all gaps 24 → clean (even DC count).
- Two features 100 nm apart (SC) with a third feature 24 nm from both (two
  DC edges) → clean, because 2 is even.
- FIG. 1R ([0020]): 53A (24, NMM), a 72 gap, 53B (72 wide), a 24 gap, 53C
  (24, NMM). 53A and 53C are both NMM by track parity ([0018]). SC to 53A
  and DC to 53C conflict, so → 1 violation. The root cause is the
  even-track-count width of 53B, so the width check flags 53B (72 is not in
  {24, 120, 216 …}). With 53B 120 wide → clean.

**Earlier findings (still valid):**

**Definition:**
- **1-D line-space SID SADP** (Xu et al. TCAD 2015, as above, pp. 700–702).
  - Track coloring: "Observation 2: A single color is assigned to metal
    patterns on even routing tracks. The alternate color is then assigned to
    metal patterns on odd routing tracks."
  - Stitches: "SADP technique does not allow stitches during the layout
    decomposition stage, which means odd-cycle conflicts must be strictly
    forbidden".
  - Trim process: "In the spacer is dielectric process, the final layout
    patterns are defined as trim mask NOT spacer."
  - Legality is then Table II, p. 701, in terms of these parameters:
    - w: metal width.
    - A_min: min metal area.
    - w_r, s_r: trim minResistWidth and minResistSpace.
    - w_e: etch bias.
    - w_sp: spacer deposit width.
  - The rules are:
    - Rule 0, min length: l0 ≥ A_min/w.
    - Rule 1, OnTrackSpace (line-end gap on the same track): l1 ≥ w_r − 2·w_e.
    - Rule 2, OffTrackOverlap (anti-parallel ends on adjacent tracks that
      overlap): l2 ≥ s_r + 2·w_e.
    - Rule 3, OffTrackSpace (anti-parallel ends with no overlap):
      l3 ≥ √((w_r − 2·w_e)² − w_sp²).
    - Rule 4, OffTrackOffset (same-facing ends): l4 ≥ w_r or l4 = 0.
  - Example values (p. 703): w = s = 24, w_sp = 24, w_r = 44, s_r = 46,
    w_e = 6 nm. These give l1 ≥ 32, l2 ≥ 58, l3 ≥ 21.2, l4 ≥ 44 or 0.
- **2-D SADP** (open author copies). Gao, Yu, Pan, "Self-aligned Double
  Patterning Layout Decomposition with Complementary E-Beam Lithography",
  ASP-DAC 2014, pp. 143–148, https://www.cse.cuhk.edu.hk/~byu/papers/C21-ASPDAC2014-SADPEBL.pdf
  (§II, p. 144) says:
  - "Any two patterns with distance less than Sdp must not be fabricated on
    the same masks".
  - "To achieve a valid layout decomposition, all patterns on the mandrel
    mask and the trim mask must satisfy the minimum spacing Sdp".
  - "a conflict occurs only when there is an odd cycle in the conflict
    graph".
  - Merge-and-cut: conflicting patterns are merged on one mask and the
    unwanted part is trimmed, with "cutting patterns cannot violate the
    minimum spacing Sdp".

  Ban, Lucas, Pan, "Flexible 2D Layout Decomposition Framework for
  Spacer-Type Double Pattering Lithography", DAC 2011, pp. 789–794,
  https://www.cerc.utexas.edu/utda/publications/C117.pdf, gives these
  additional constraints:
  - "SADP mask decomposition does not allow 'stitch' points. Every polygon
    should have a single color".
  - Trim width ≥ "the minimum target layout width or slightly larger".
  - The trim self-conflict: "three or more consecutive polygons have the
    same color where the width of middle polygon is less than the trim mask
    space constraint".

  SID vs SIM is defined in Gao et al., SPIE 8684, 868408 (2013),
  https://www.cerc.utexas.edu/utda/publications/C143.pdf §2.1: "Depending on
  the design specification … Spacer-is-Dielectric (SID) or Spacer-Is-Metal
  (SIM) process can be applied". SIM grid rules for SADP and SAQP (only
  slides are open) are in Kodama et al. (Toshiba), ASP-DAC 2013 3C-4,
  https://www.aspdac.com/aspdac2013/archive/pdf/3C-4.pdf: a chessboard grid
  with 3 grid colours for SADP and 6 for SAQP; "Path only goes through the
  grids of the same color as pins".
- **ASAP7.** DRM Table 2.1.1 and 2.3 (printed pp. 11–12): FIN SAQP, GATE SADP
  "(assuming coloring is done later)", M4–M7 SADP. The SADP-relevant rules
  are M4.W.1–W.5, M4.S.1–S.5, M4.AUX.1–AUX.4 (pp. 53–54): on-track
  placement, no bends, and odd multiples of the min width for wide lines.
  M4.S.2/S.3/S.4/S.5 are Xu Rules 1/3/4/2 in shape (see DRC-031). MEJ 2016
  p. 111 adds "We assume a single patterned block mask layer". There is no
  block-mask layer or rule in the DRM.
- **LEF/DEF.** TRACKS MASK (DEF 5.8 ref pp. 336–337): "By default, the tracks
  cycle through all the masks … 1, 2, 1, 2". This is the track-parity
  colouring of Observation 2. For TRIMMETAL and `_SADP_FILLS_RESERVED`, see
  DRC-105.

**Implementable?** Partly.
- Gridded 1-D SADP (the ASAP7 M4–M7 style) can be implemented as:
  1. on-track check (M4.AUX.2);
  2. no bend (M4.AUX.3);
  3. Rules 0–4 above as edge checks, deck parameters `w_r, s_r, w_e, w_sp`,
     or direct values.

  Colour is implied by track parity, so no colouring step is needed. Oracle:
  the DRC-031 table, plus OnTrackSpace (same track, end gap 31 vs 32 with the
  example parameters) and OffTrackOverlap (57 vs 58).
- 2-D SADP decomposability can be implemented as:
  1. build the conflict graph (edge between two features when distance < Sdp);
  2. flag odd cycles, since stitches are not allowed;
  3. optionally, flag trim self-conflicts (a middle polygon narrower than the
     trim space between two same-coloured neighbours).

  This is the LELE odd-cycle check (DRC-100) with stitching disabled, plus
  the trim conditions. Merge-and-cut repair is an optimization, not a check.

**LEF/DEF 5.7 (pass 2):**
- LEF/DEF 5.7 (Nov 2009, ISPD-hosted, [LEF57]). Grepped for TRIMMETAL, TRIMMEDMETAL, TRIMPOLY, MANDREL, SADP, self-aligned, SAMEMASK, MASK, stitch, patterning and color: 0 hits, apart from two unrelated "mask creation/generation" lines (:4430, :11284). It predates the multi-patterning constructs. Its LEF58_TYPE is only TSV/PASSIVATION and NWELL/PWELL, and its LEF58_AREA has no LAYER/OVERLAP clause.

**Still undefined:**
- SIM-process rules beyond the Toshiba grid scheme.
- SAQP rules other than grid colouring.
- Any foundry's actual mandrel and cut-mask rule numbers. ASAP7 gives none.

**Checked, nothing found:**
- ASAP7 DRM (whole text, grepped for SADP, SAQP, mandrel, spacer, cut,
  color).
- laurentc2 and DAC26 ASAP7 KLayout decks: no mandrel or cut checks.
- LEF/DEF 5.8 ref (no MANDREL type exists; only TRIMMETAL and TRIMPOLY).
- OpenROAD@3549d605 src (no SADP or mandrel code).
- Patents: Google Patents was rate-limited, so the full text was read from
  USPTO image PDFs instead (pass 2). These are US 2015/0286764 A1,
  US 9,087,174 B1, US 11,829,697 B2, US 11,983,476 B2 and US 10,726,187 B2.
  None states SAQP rules.

## ERC-A15: Fix hint: required diode area

**Verdict:** found. Three public sources state the diode-area model in closed form, and two of them
also state the required area. GPurify's existing LEF PWL model inverts directly to that area. The
inversion is a derivation, but the sources below cross-check it exactly.

**Definition:**

1. **IHP SG13G2 Layout Rules Rev. 0.4 (2024-12-19), §7.1 Antenna Rules, p. 65**
   (`IHP-Open-PDK@e261c6d5 ihp-sg13g2/libs.doc/doc/SG13G2_os_layout_rules.pdf`). This source states the required diode area.
   - "Ant.g Size of protection diode (µm²) (Note 4) 0.16"
   - "Note 4. PDarea (µm²) = 0.02 x (Vn_area / (GatPoly over Activ)_area)"
   - "Note 2. Vn_area = cumulative area Cont, Via1 to TopVia2"

   The model is a step function. Without a diode, the limits are Ant.b (metal/gate ≤ 200) and
   Ant.d (via/gate ≤ 20). With a diode, they are Ant.e (≤ 20000) and Ant.f (≤ 500). The required
   area is therefore PDarea = 0.02 × (cumulative contact+via area / gate area), and the table value
   0.16 µm² reads as a floor.

   Reading: the IHP KLayout deck (`IHP-Open-PDK@40c306f5 ihp-sg13g2/libs.tech/klayout/tech/drc/rule_decks/antenna.drc`)
   implements Ant.g only as the floor: "Minimum Size of protection diode (µm²): 0.16". For the
   e/f limits it treats "has_diode = area(d) > 0.16". It does not implement Note 4. So a deck that
   uses Note 4 is a reading of the DRM, not something this deck does. Whether 0.16 is a floor under
   the Note 4 value or a fixed size is ambiguous in the DRM text.

2. **US 9,142,556 B2** (Kito, Rohm, 2015), col 5:57-62. This patent solves for the area explicitly.
   - "antenna ratio=(area of a wiring)/(gate area), maximum ratio=(diode area×α+β), and α and β are parameters determined based on manufacturing conditions."
   - Worked solve, col 6:24-31: "in order to obtain antenna ratio<maximum allowable ratio, 25478.59873<(c)×400+2200 (c)>(25478.59873−2200)/400 (c)>58.196", where (c) is the diode area.
   - It also solves the alternative fix, added gate area, at col 6:37-41: "4000.14/(b)<2348.4 (b)>1.7".
   - The constants are α = 400 and β = 2200, the same as sky130 met1 (see item 3).
   - Typo in the patent: it uses 0.317 at col 6:16 and 0.371 at col 6:19 for the same diode.

3. **SkyWater sky130 DRM, antenna rules** (`google/skywater-pdk@f3d86a69 docs/rules/antenna.rst`, lines 38-54).
   - "Etch Gate Area Ratio = (EA / A_gate) - K x (AntennaDiode_area in um2) - diode_bonus"
   - "The layout should satisfy the condition: EGAR <= MAX_EGAR. The diode_bonus applies only when at least one diode is used, regardless from it's size."
   - Values are in `docs/rules/antenna/table-Ia-antenna-rules-s8d.csv`. For example, met1.1/met2.1/met3: MAX_EGAR 400, K 400, bonus 2200. For mcon.1: 3, K 18, no bonus. For li.1: 75, K 450, no bonus.
   - The released sky130 tech LEF encodes the same rule as a LEF PWL
     (`google/skywater-pdk-libs-sky130_fd_sc_hd main tech/sky130_fd_sc_hd.tlef:112`):
     `ANTENNADIFFSIDEAREARATIO PWL ( ( 0 400 ) ( 0.0125 400 ) ( 0.0225 2609 ) ( 22.5 11600 ) )`.
     - The PWL equals MAX_EGAR + bonus + K·d for d ≥ 0.0225: 400 + 2200 + 400·0.0225 = 2609, and 400 + 2200 + 400·22.5 = 11600.
     - Between 0.0125 and 0.0225 the PWL ramps the bonus in.

4. **LEF 5.8** (ref.txt pp. after line 2415, ANTENNADIFFAREARATIO / ANTENNADIFFSIDEAREARATIO): "the ratio value is calculated using linear interpolation of the diffusion area and ratio input values. The diffusion input values must be specified in ascending order."
   - Reading: OpenROAD extrapolates past the last breakpoint with the last segment's slope (`OpenROAD@3549d605 src/ant/src/AntennaRules.cc:97-124`).
   - Below the first breakpoint, that code finds no segment and also falls through to the extrapolation.

**Derivation (closed form):** for a layer whose limit is a function of diode area, r_lim(d), the
required diode area is d* = min{ d ≥ 0 : r_lim(d) ≥ PAR }, where PAR is the measured ratio.
- **Linear model** (sky130 DRM, US 9,142,556): d* = (PAR − MAX − bonus)/K. If PAR ≤ MAX, d* = 0. If MAX < PAR ≤ MAX + bonus, any diode is enough (sky130), so d* = the smallest legal diode.
- **IHP model:** d* = max(0.16, 0.02·Vn_area/A_gate) whenever the no-diode limit fails, provided the with-diode limit (Ant.e/f) holds. If it does not hold, no diode fixes the net.
- **LEF PWL model:** walk the segments in ascending d and return the first d where r_lim reaches PAR, interpolating inside that segment. If the PWL is non-monotone, take the first crossing. If PAR is beyond the last breakpoint, the result depends on the extrapolation rule: OpenROAD extends the last slope; another reading clamps to the last ratio and reports "not fixable".
- **Caveats** (derivation, as the catalog notes):
  - The hint holds per layer and assumes the diode is connected at or below the layer being etched.
  - With CAR (cumulative ratios), the diff area also enters lower layers.
  - The finding needs a second number (d*) alongside the measured ratio and limit.

**Implementable?** Yes. This is a post-processing step on each antenna finding.
- **Inputs:** PAR, the layer's diff-ratio rule (a value or PWL), and the existing iterm_diff_area.
- **Output:** d_required − d_present, as an area in µm².
- **Deck parameters:** none beyond the existing LEF/deck antenna rules. Optionally a floor (IHP 0.16) and the extrapolation mode.
- **Oracle** (sky130 met1 PWL above; DRM and PWL agree, which cross-checks them):
  - PAR 300 → d* = 0 (no violation).
  - PAR 2500 → PWL d* = 0.0125 + 2100/220900 = 0.022007 µm². DRM: any diode (bonus). This is where the LEF and DRM forms differ.
  - PAR 2650 → d* = 0.125 µm² (PWL: 0.0225 + 41/400; DRM: (2650−2600)/400).
  - PAR 3000 → d* = 1.000 µm² (both forms).
  - PAR 11600 → d* = 22.5 µm².
  - PAR 12000 → 23.5 µm² under OpenROAD extrapolation, or "not fixable" under clamping.
  - Cross-check against the DRM's own table (table-Ia, "with 1um2 diode"): max met1 length 4280 vs 570 without a diode. The ratio 4280/570 ≈ (400+2200+400)/400 = 7.5.
  - US 9,142,556 example: AR 25478.6, α = 400, β = 2200 → d* = 58.196 µm².
  - IHP: Vn_area 50 µm², gate 0.5 µm² → PDarea = 0.02·100 = 2.0 µm². Vn_area 2 µm², gate 1 µm² → 0.04, floored to 0.16 µm².
  - Differential: OpenROAD `repair_antennas` adds whole diode cells until the check passes. For a sky130 diode cell of diff area a, expect ceil(d*/a) cells per gate, up to its cap of 10 per gate.

**Checked, nothing found:**
- OpenROAD `src/grt/src/RepairAntennas.cpp`, `src/ant/src/AntennaChecker.cc:747-818`: the iterative loop (already in the catalog).
- US 11,922,109 B2 (IBM, predictive diode insertion): wire-length threshold only, no area formula.
- US 7,174,527 B2 (Matsushita): seen only in search snippets as K1 = A_gate/(K2·A_diode + A_gate), a damage-reduction coefficient. Not read in full.
- Google Patents, Justia and FreePatentsOnline all blocked automated fetches. The USPTO image PDFs worked.

## ERC-D9: PMOS/NMOS devices sharing one well

**Verdict:** partial. A public patent defines a concrete, connectivity-based well-sharing latch-up
check for transistors in one well. What Calibre PERC's own "PMOS/NMOS devices sharing the same well"
check forbids is still not public.

**Definition:** **US 5,638,286** (Fujimoto, Mitsubishi, 1997), "Latch-up verification device", first embodiment.
- Col 6:45-53: "groups together all of the transistors included in the same well region as the transistors having the same back gate terminal."
- Col 6:56-67 and col 7:1-3: "Three conditions are established:
  (1) A source terminal of the respective transistors having the same back gate terminal information is connected directly to the well region including the transistors.
  (2) The former is connected to the latter through a resistance.
  (3) The former is connected to the latter in series in a drain-source terminal direction through a single or a plurality of transistors included in the same well region.
  The latch-up verifying portion 3 extracts an MOS transistor which does not meet any of the conditions as a latch-up MOS transistor".
- Rationale, col 7:15-28: Q5 "satisfies the condition (3) in relation to the different N- well region 125 although it is formed in the N- well region 111 … the MOS transistor having a plurality of power supply voltage sources is recognized as the latch-up MOS transistor."
- Background, col 2:31-35: VDD1 and VDD2 on different wells; "a potential difference between the power supply voltages VDD1 and VDD2, if generated, causes a base current to flow in the forward direction to the PNP".

This is distinct from well_bias (ERC-F12):
- F12 compares voltages (bulk below source).
- This check is topological. It flags a PMOS whose source supply reaches it through a different well's devices, or from a different supply net, even when the nominal voltages are equal. That is exactly the multi-supply sharing case.
- The patent claims the in-well (n-well) devices. Applying it to NMOS in an isolated p-well (deep n-well) is a derivation by symmetry.

Context (already in the catalog): Hogan & Medhat, Semiconductor Engineering, 2021-05-06, list "detecting PMOS/NMOS devices sharing the same well" among ESD *layout* rules, next to "pad-to-ESD-device P2P resistance". That placement suggests the PERC check is about ESD devices, but no public text says so.

**Implementable?** Yes, as the Fujimoto rule.
- **Inputs:** well regions (n-well polygons; optionally isolated p-wells) and the MOS devices inside each, giving a per-device well id and the well's tap net (the bulk net). Also the netlist of channel and resistor connections.
- **Operation:** for each device M in well W with tap net T(W), M passes if any of these hold:
  - (1) source(M) == T(W). For a symmetric device, either S/D terminal counts.
  - (2) source(M) reaches T(W) through one resistor device.
  - (3) source(M) reaches T(W) through a chain of S-D channel edges whose devices all lie in W.
- Otherwise flag M and report W, T(W) and source(M).
- **Deck parameters:**
  - which well layers are included;
  - whether condition (2) is allowed, and its maximum resistance (the patent gives no value);
  - whether chains may pass through devices of either type.
- **Oracle:**
  - (a) Two PMOS in one n-well tapped to VDD1. P1 has its source on VDD1, so it passes (1). P2 is a series stack whose source is P1's drain, so it passes (3). Expect 0 findings.
  - (b) Same well, plus P3 with its source on VDD2, where VDD2 ties to a second n-well's tap. Expect 1 finding (P3). This is the patent's Q5, FIG. 31/32.
  - (c) As (b), but VDD2 reaches the well through a 10 Ω resistor to VDD1. Expect 0 findings with (2) allowed, and 1 with it disallowed.
  - (d) A PMOS source fed through a PMOS in another well. Expect 1 finding, because condition (3) requires the same well.
  - There is no open-tool differential. CVC (d-m-bailey/cvc) checks voltages (forward bias), not this topology.

**Checked, nothing found:**
- Siemens blog "Searching for Latch-up in All the Right Places" (2017-07-17): no sharing condition.
- GF180MCU DRM §14.3.1-14.3.4, 14.4.x and 14.5.x (`google/gf180mcu-pdk main docs/physical_verification/design_manual/drm_14_*.rst`): no well-sharing rule beyond those the catalog lists.
- IHP SG13G2 Layout Rules §7.2 (p. 67-68): output-buffer guard rings and LU.a-d tap distances only.
- TI SCAA124 and US 11,876,088 / 12,288,786 ("shared well structure"): seen in search results only, not read.
- Skipped on purpose: a Scribd "Calibre PERC Test Cases Catalog" (a proprietary mirror, not read).
- Not reached: the Mentor webinar slides "Programmable Electrical Rule Checking (PERC)" at site.eet-china.com/webinar/pdf/Mentor0523_... The server reset or timed out on both HTTP/2 and HTTP/1.1. The next agent could retry; it may list PERC check names.

## ERC-F4: HCI susceptibility flag

**Verdict:** partial. No public source defines a hot-carrier stress condition testable on static
voltage ranges, so that part is still undefined. A public foundry guideline does give a structural,
static flag that is separate from the Vds bound in ERC-F3.

**Definition:** GF180MCU DRM §14.1.4.1 (`google/gf180mcu-pdk main docs/physical_verification/design_manual/drm_14_1.rst:29-45`).
The catalog quoted only the Vds and time-fraction sentences. The lines it did not quote are these:
- :31 "When source and drain are exchanged, as in a pass gate, the degradation is more severe and occurs in the saturation region as well."
- :35 "In case of multiple power supplies on same chip, special attention must be paid to FETs connected to higher power supply so that voltage across them does not exceed Vddmax for any significant amount of time."
- :37 (a) "Use minimum-channel FETs only when necessary. Hot carrier effect is more pronounced for FETs with shorter channel lengths."
- :39 (b) "For applications where stability of linear region drive current or Tran conductance of an NMOSFET is critical and the very same NMOSFET is subjected to high drain-to-source voltage during circuit operation, longer than minimum channel FETs must be used."
- :41 (c) "In the event of high fanout (>10), speed-critical circuits should preferably be partitioned".
- :45 (e) "Longer than minimum channel length should be used in circuits where NMOSFETs are used in bi-directional mode."
- :7 points to "R-QR-MI-008 APPLICATION NOTE: Guidelines … to Guard Against Hot-Carrier-Induced Degradation", which is not public.

**Implementable?** Partly, as a guideline flag (warning severity), not as a stress-condition rule.
- **Flag (e):**
  - Condition: an NMOS (optionally PMOS) with L ≤ L_min(model) + tolerance that is used bidirectionally.
  - "Bidirectional" is a derivation: neither S nor D is on a supply or ground net, and both S/D nets have a driver other than M. For example, a transmission gate or pass transistor between two driven nets.
- **Flag (b), static part:** a min-L NMOS whose Vds,max from propagated ranges exceeds a deck threshold V_HCI.
  - With V_HCI = Vddmax, this reduces to drain_source (ERC-F3).
  - It adds something only if a deck supplies V_HCI < Vddmax, and no public source gives such a value.
- **Flag (c):** a driver with fanout > 10. The DRM conditions this on "voltages over Vddmax" and "speed-critical", and neither is static. Fanout > 10 alone is a lint.
- **Deck parameters:** L_min per model, length tolerance, device types, the fanout limit (10), and V_HCI.
- **Oracle:**
  - Min-L NMOS pass gate between two inverter outputs: 1 finding.
  - Same device at 2×L_min: 0.
  - Min-L NMOS in an inverter (source on VSS): 0.
  - Min-L transmission gate (N+P), N only: 1.
  - An inverter driving 11 gates: 1 lint (c). Driving 10 gates: 0.

**Checked, nothing found:**
- US 7,219,045 B1 (Cadence, "Hot-carrier reliability design rule checker", 2007): the rules are applied during aged circuit *simulation*, per the abstract on p. 1. It is not a static check.
- Siemens resources and blogs on PERC (2015-2025 titles): no HCI rule text.
- arXiv 2503.21165 (a review of reliability design techniques): no static HCI screen.
- IHP SG13G2 Layout Rules and Process Spec (`IHP-Open-PDK main libs.doc/doc/*.pdf`): no hot-carrier rule.
- Web literature on worst-case stress (Vg ≈ Vd/2 for long channels, Vg = Vd for short channels): bias conditions for device test, not a static circuit rule. Any threshold drawn from it would be a guess.
- US 6,856,160 ("Maximum VCC calculation for hot carrier qualification"): seen only as a title in search results.

## ERC-H3: Netlist path checks (gate to ground within N devices; net types)

**Verdict:** partial. Net types, type sets, paths, breaking and path types are now **found**
(fully defined in P12). Counting devices along a path is **not** defined by P12. A public
counting convention exists in another patent (HP US 6,367,062, one count per series device
traversed).

**Definition:**

*The "three other devices" rule.* It appears only once, in the background, as an example of a
designer rule. It is not a PERC command:
> "every transistor gate in the design must have an electrical path to ground that passes
> through no more than three other devices" (P12 [0029])

P12 has **no path-length or hop-count primitive**. Its paths are equivalence classes, not
walks: "Each net in the netlist belongs to one and only one path. If this command is not called
at all, then each net belongs to a trivial path" ([0265]). The counting commands it has are
these:
- the number of devices on a net, `perc::commandi` "returns the number of devices in the list"
  ([0447], [0541]-[0542]);
- the number of different nets or paths on an instance's pins, the "flat net count" and "flat
  path count" ([0383]-[0391]);
- the adjacent-net or adjacent-path count, which returns only 0, 1 or 2 ("2—more than one
  unique adjacent nets are found", [0545]-[0557]).

None of these is a distance. So the catalog's "P12 ... does not define how devices are
counted" is confirmed against the full text.

*Counting convention, from a public source:* HP US 6,367,062 B1 (McBride, "System and method
for detecting an excessive number of series-connected pass FETs", 2002), col. 11 l. 55 to
col. 13 l. 25. Its method "initialize[s] a count (a count of serial pass FET devices) to zero";
for each pass FET whose output node is the current node it "increments a serial pass FET
counter (step 314) and sets the new 'current node' to be the input node of that pass FET". "If
the count exceeds a predetermined maximum count number, then the system ... reports an
appropriate error message." In FIG. 11, three pass FETs in series between two inverters give
"a count of three". The walk is directed: step 312 is "No" when the direction flags are "unset"
or "bidirectional". This supports GPurify's "one per device passed" reading as a public
precedent, though for a different rule (series pass FETs, not gate-to-ground).

*Net types by name* (`perc::commanda <net_type> <net_name_list> [-cell|-cellName <cells>]`,
[0198]-[0214]):
- "Each net name can contain one or more question mark(?) characters. The ? is a wildcard
  character that matches zero or more characters" ([0201]).
- Without `-cell`, the type is assigned only to top-cell nets that match, then propagated
  *down* through ports. With `-cell`, it is assigned in all cells and propagated up and down,
  "Upward propagation occurs first" ([0202]).
- `-cellName` takes a list that may start with `!` to negate it; the top cell must be named
  (`lvsTop`) ([0203]-[0204]).
- "A net can have multiple net types" ([0206]). At most 64 unique types ([0200]).
- "No net types are assumed by default ... the power/ground nets declared in LVS do not
  automatically have any net types". The reserved names `lvsPower`, `lvsGround` and
  `lvsOutline` ("the list of external nets in the top cell") expand in the name list
  ([0207]-[0211]).
- Worked examples: init_1 to init_4 in [0213]-[0214].

*Net types by device* (`perc::commanda+ <net_type> -type <dev types> [-subtype <models, ! allowed>] [-property <constraint>] [-pin <pins>] [-cell|-cellName]`, [0215]-[0239]):
- "assigns the net type to nets connected to devices selected according to conditions" ([0216]).
- `-pin`: "only assigns <net type> to nets connected to the selected pins of the selected
  devices", with all pins as the default ([0230]).
- Constraint grammar: `P<a P>a P<=a P>=a P==a P!=a P>a<b P>=a<b P>a<=b P>=a<=b` ([0219]-[0229]).
- Example: [0238]-[0239].

*Type sets* (`perc::commandb <set> <types>`, [0240]-[0246]): "A net is said to have the type
named <type_set> if the net has at least one net type contained in <net_type_list>. In other
words, a type set represents the logical OR relation". Sets can nest, as in the example
`supply {generic_power ground}`.

*Conditions* (used everywhere): a net "meet[s] the condition if the net has all of the net
types before the exclamation symbol, and the net does not have any of the net types after the
exclamation symbol" ([0262], [0395], [0407]). So `{power ground}` is AND, and OR needs a type
set ([0267], last sentence).

*Paths* (`perc::commandc -type <dev types> [-subtype] [-property] [-pin <pins>] [-break <cond> [-exclude <types>]]`, [0247]-[0267]):
- "establishes net paths that lead through pins of devices" ([0248]).
- `-pin` takes "two or more pin names"; all pins are the default ([0261]).
- [0262]: "If -break is not specified, which is the default, a path continues until it reaches
  an unqualified device or a port in the top cell. If -break is specified, then a path also
  stops when it reaches a net that meets the criteria of <net_type_condition_list>."
- [0263]: "Even though a break net is not part of a path, its net types contribute to the
  combined net types of the path. By default, a path has the combined net types from all of the
  nets in the path, plus the net types of its break nets. ... If -exclude is specified, then a
  path does not receive the net types listed in <net_type_list> from its break nets. However, a
  path can still carry the net types listed ... if any net of the path has those net types."
- [0264]: calls accumulate ("create paths using the combined path definition"), but
  `-break`/`-exclude` may be given at most once.
- [0267]: "init_1 creates paths that lead through source/drain pins of MOS, and
  positive/negative pins of resistor devices. This is usually the default path definition in
  LVS." The same paragraph covers init_5 (MOS s/d, `-break {power ground} -exclude power`: "A
  net having both types power and ground breaks a path") and init_6 (type set `supply`, so
  either type breaks).
- MOS types are listed in [0172]-[0179]: M, MD, ME, MN, MP, LDD, LDDE, LDDD, LDDN, LDDP, with
  pins g, s, d, b.

*Checks over types:*
- Net check `-netType`/`-pathType`/`-condition`, flat by default and per-cell with `-cell`
  ([0450]-[0462]).
- Device check `-pinNetType {{pins} {cond} ...}`: "A device is said to meet the criteria if
  perc::commandu returns the value of 1 when applied to the device and each pair". commandu
  returns 1 "If there is at least one net [on the listed pins] that meets the criteria"
  ([0394], [0463]-[0485]).

*Corroboration (Xilinx US 7,934,187 B1, Roberts, col. 5):* "Nets are 'effectively shorted' ...
if they are connected (actually shorted) or if one net is coupled to the source of a transistor
and the other net is coupled to the drain ... ERC nets do not include any ground nets." This is
the same object as a P12 MOS-s/d path broken at ground.

**Implementable?** Yes for net types, type sets, paths, path types and the net, device and
adjacent checks. A sketch:
1. Inputs: a flat netlist (hierarchy optional), net names, device type/model/properties and pin
   names.
2. Net types: a bitset of at most 64 per net. Name rules use `?`, which matches zero or more
   characters. Device rules use type, subtype (with `!`), a property constraint and pins.
   Type sets are OR-closures.
3. Paths: union-find over nets. For every qualifying device (type, subtype, property), union
   the nets on its selected pins, i.e. every pin pair of the `-pin` list, all pins by default.
   Never union through a break net: a break net stays out of every non-trivial path and is
   treated as its own trivial path (derivation; P12 says only that it "is not part of a path"
   and that every net is in exactly one path).
4. Path types = the OR of the member nets' types, plus the types of the adjacent break nets
   minus `-exclude`.
5. Checks evaluate `{a b ! c}` conditions on net types or path types.

The "≤ N devices" check stays a GPurify extension. P12 states it as a goal, and US 6,367,062
gives the one-per-device count convention for a series walk.

Oracle (hand-worked, from P12's own examples). Inverter: VDD–MP–out–MN–VSS, with nets VDD
and VSS named.
- init_1 or init_2 with no break: one path {VDD, out, VSS}.
- init_5 (types power={VDD?}, ground={VSS?}; MOS s/d; `-break {power ground}` is AND,
  `-exclude power`). No net has both types, so nothing breaks: one path {VDD, out, VSS} with
  path types {power, ground}. The `-exclude` does not remove power because VDD is in the path
  ([0263]).
- init_6 shape with MOS s/d (`supply={power ground}`, `-break supply -exclude {power ground}`).
  VDD and VSS break, so the path is {out} with path types {}. P12 check_1 (`-netType
  {! Power Ground} -pathType {! Power Ground}`) then reports `out`. The same check under init_5
  does not.
- [0485] check_1 (`-pinNetType {{S D} {Power} {S D} {Ground}}`) reports an MOS whose s/d touch
  both a Power and a Ground net. The inverter's MP fails it (its s/d nets are VDD and out).
- [0239]: R(model ar) between n1 and n2 gives `label_a` on both n1 and n2 (top cell only,
  because there is no `-cell`).

No open reference tool implements PERC semantics, so oracles are construct-from-answer.

**Checked, nothing found:**
- P12 full text for "count", "depth", "within", "path length" (only the [0029] example);
  "PATHCHK", "NOFLOAT", "LABELED" (absent).
- The granted P12 family: none, the application was abandoned.
- Mentor US 7,716,611 (Logic injection, Pikus/Kresh), full OCR: no path counting.
- Google Patents (blocked for scripts: HTTP 503/"Sorry"), Justia (Cloudflare), FPO (403).
  Use image-ppubs.uspto.gov `/dirsearch-public/print/downloadPdf/<number>` instead.

## ERC-G3: Multiple drivers (transistor level)

**Verdict:** partial. No public source defines "multiple drivers" on a transistor netlist as
a check. Public texts do define its parts: what a driver is (a static gate output node), the
fault it guards against (two gates' pull-up and pull-down networks on one node), and a
dynamic short detector (CVC).

**Definition / readings:**
- Afonso and Monteiro, "Analysis of Short-Circuit Conditions in Logic Circuits", DATE 2017,
  pp. 824-829; open copy https://past.date-conference.com/proceedings-archive/2017/pdf/0219.pdf.
  §I, Fig. 1: "short-circuits can arise with a wrong interconnection of gates ... If ... the
  inputs of gate A activate its pull-up network and the inputs of gate B ... activate its
  pull-down network, a direct path from Vdd to Ground is established." Its exact semantics
  (§III, a QBF over the switch graph): flag when some consistent input assignment closes a
  Vdd–Gnd path. That is the precise "multiple drivers conflict", stronger than a structural
  count.
- HP US 6,077,717 (McBride, 2000), col. 7 l. 55 to col. 8 l. 5, gives a public definition of a
  driver node: "a static gate is not a dynamic gate; it is not a latch, it is not a RAM cell,
  it is not a ROM cell, it does not have a clock signal input, it is not driven by a pass FET,
  it is not a FET capacitor ... [and] there is at least one PFET channel-connected to the node,
  and at least one NFET channel-connected to the node". It also defines a FET capacitor: "a FET
  having by the source and drain nodes tied to Ground, and the gate node is driven by a signal
  or by VDD".
- HP US 6,484,295 (McBride and Kok, 2002, "Electrical rules checker ... quality assurance of
  tri-state logic"), col. 2-3, defines the driver configurations an ERC classifies at a node:
  complementary pass FET (PFET‖NFET with inverse gate signals), special complementary pass
  gate, gate output ("a signal where the gate driving the signal is known"), feedback FET,
  RAM pass FET, single pass FET. It appraises them; it does not define a multiple-driver error.
- CVC (open source, https://github.com/d-m-bailey/cvc @23c3867b), `src/CCvcDb.cc:65-110`
  (`ReportShort`): after a mode-driven logic simulation from declared powers, a device whose
  source and drain resolve to different known voltages is reported as "! Short Detected",
  subject to a threshold, Vth and leak-current filters; leaks between unrelated powers are
  always reported. `src/CCvcDb_init.cc:270-315`: "Switch shorts" when a forced-on switch joins
  two powers. This is a dynamic, design-intent check, not a structural driver count.
- Xilinx US 7,934,187 col. 6: hierarchical net checks include "output pins driven by a supply,
  or source and drain connections between two different power supplies or a power supply and
  ground".
- P12 [0485] check_1: an "MOS connected to power and ground" (s/d touching both). This is a
  crowbar device check, not multiple drivers.

**Implementable?** Partly. GPurify's structural reading (rail-oriented channel groups,
complementary networks sharing gate nets count as one driver) remains a derivation. Two
publicly grounded tightenings:
1. The driver predicate from US 6,077,717: a node with ≥1 PFET and ≥1 NFET channel-connected,
   not pass-FET-driven.
2. An exact conflict test on small netlists, following Afonso and Monteiro: enumerate the gate
   input assignments of the two driver groups and flag if some assignment turns on a
   rail-to-rail path through the shared node.

Oracle:
- Two inverters, inputs A and B, outputs tied: conflict (A=0, B=1 gives a VDD–out–VSS path).
- Two inverters on the same input with outputs tied: no conflict (parallel inverter; Afonso's
  test says no satisfying assignment).
- A tri-state buffer plus an inverter, with the enable at a free input: conflict exists
  (enable=1).

For a differential, CVC can be run on a SPICE/CDL netlist with a power file declaring the
rails and inputs; its "Short Detected" count is the dynamic reading.

**Checked, nothing found:**
- Yosys check (cell-level only, as before).
- Netgen and Magic: no ERC of this kind.
- KLayout: no driver checks.
- The survey (no "multiple driver" term; it defines short circuits as "connected to two (or
  more) different supplies", §2.1).
- The DATE 2023/2024 SMT papers (short circuits only).
- HP US 6,367,062, US 6,249,899 and US 6,321,365 (titles only for the last two).

## ERC-G7: Gate tied directly to a rail

**Verdict:** partial. The rationale and the net-level predicate are public; no public tool or
spec states the check with its exemptions.

**Definition / readings:**
- P12 [0478]: the device check `-pinNetType {{pins} {cond} ...}`. Its own example list
  `{{S D} {Power} {G} {Ground}}` shows a gate-pin condition on a net type. So
  `perc::commandp -type {MP MN} -pinNetType {{G} {power}}` is the PERC way to write "gate on a
  power net". [0207] says LVS power and ground carry no net type unless assigned (by
  `lvsPower`/`lvsGround`). This is a definition of the mechanism, not of the rule.
- Rationale: TSMC US 7,663,851 B2 (Huang and Lee, "Tie-off circuit with ESD protection
  features", 2010), col. 1-2: "a conventional inverter 102 whose input node is directly tied to
  ground ... may not provide proper protection for the gate-oxide of the PMOS transistor 104
  during an ESD event. ... the source-to-gate voltage may reach a level higher than VDD".
- Exemption precedent: HP US 6,077,717 col. 7 defines the FET capacitor, "source and drain
  nodes tied to Ground, and the gate node is driven by a signal or by VDD". A decap's gate on a
  rail is legitimate, and the patent's static-gate test excludes it.
- CVC does not flag direct ties: `CheckInverterIO` skips them ("input is tied to matching
  power", `src/CCvcDb_error.cc:1280`). Its "Gate vs Source" errors (`:360-395`) are about
  insufficient gate drive, not ties.
- Calibre FILTER UNUSED option C (US 8,751,985, see LVS-048), "with gate tied to power or
  ground, and either the source or drain floating", uses the same predicate, gate net ∈
  {power, ground} names.
- Flow practice: OpenROAD `repair_tie_fanout` "connects each tie high/low load to a copy of
  the tie high/low cell" (OpenROAD@3549d605 src/rsz/README.md:189). It shows that tie cells
  replace direct ties, but defines no check.

**Implementable?** Yes, as GPurify has it: flag an MOS whose gate net is a declared rail (net
type power or ground, by name or by `lvsPower`/`lvsGround`). A publicly motivated refinement is
to exempt MOS capacitors (s=d=rail, after US 6,077,717) and to report per gate pin, as P12's
device check does.

Oracle:
- INV with input on VSS: flagged (TSMC FIG. 1).
- NMOS with s=d=VSS and gate=VDD: decap; flagged by the plain rule, exempt under the
  US 6,077,717 refinement.
- Gate driven through a tie cell (diode-connected device): not flagged.

**Checked, nothing found:** Netgen, Magic and KLayout (no such ERC); the survey and the SMT
papers; CVC (as above); public Siemens pages.

## ERC-G9: Path check: nets with no path to power or ground

**Verdict:** partial. The P12 semantics, which GPurify already follows, are now verified
against the full text with paragraph numbers. Calibre PATHCHK's own LABELED and NOFLOAT
semantics remain not public.

**Definition:**
- P12 [0460]-[0462]: check_1 (`-netType {! Power Ground} -pathType {! Power Ground}`) "selects
  nets that have no path to Power and no path to Ground. The Power and Ground nets themselves
  are excluded". check_2, through a condition proc, selects "no path to Power or no path to
  Ground (or both)". "OR ... is not supported by the -pathType switch."
- Path extent: [0262], [0263], [0267], quoted under ERC-H3. Default LVS path = MOS s/d +
  resistor pos/neg (init_1).
- [0262] adds a rule GPurify may not model: without `-break` a path also "continues until it
  reaches an unqualified device **or a port in the top cell**". Read with [0456] (flat by
  default), this reads as the path not leaving the top cell's ports. That is a reading; the
  phrase is not elaborated.
- Ferres et al., "A Survey on Transistor-Level Electrical Rule Checking of Integrated
  Circuits", ACM TODAES 2025, doi:10.1145/3748327; open copy
  https://hal.science/hal-05185119/file/article.pdf (curl's default User-Agent passes HAL's
  bot wall; a browser UA does not). §2.1: "a net connecting only the gates of two transistors —
  no voltage can be forced on it, as voltages are only propagated from source to drain or drain
  to source in transistors ... can be considered a static floating net. Static floating nets in
  the design can straightforwardly be found with a reachability analysis of the netlist."
- Oulkaid et al., DATE 2024, https://hal.science/hal-04527225/file/date2024.pdf, §III-A: "we
  build the set of inputs I as the circuit nets that can reach no supply", with
  I ≜ {i ∈ N | REACHS(i) = ∅} from static voltage propagation.
- Xilinx US 7,934,187 col. 5: effectively shorted nets across s/d, with ground excluded (see
  ERC-H3).
- PATHCHK itself: the only public hits are the scribd "ERC Path Check" and docplayer copies of
  the Calibre manual. Both are manual reposts and **were not read**, per the brief.

**Implementable?** Already implemented; the semantics match P12 check_1 and check_2. A possible
addition is P12's net-type machinery, which would supply a LABELED-like "path to a net of type
X" by giving labelled nets a type (P12 net type by name). This would be a P12-based extension,
not Calibre's LABELED. Oracle: the init_5 and init_6 inverter cases under ERC-H3, plus a net on
gates only (static floating, survey §2.1), which must be reported.

**Checked, nothing found:** P12 for PATHCHK, NOFLOAT, LABELED (absent); public Siemens pages;
the survey and the DATE 2023/2024 papers (no PATHCHK flags).

## LVS-042: Semi-series MOS reduction

**Verdict:** not found.

**Definition:** none public. New negative evidence and constraints:
- P12's LVS statements list device reduction, "SPLIT GATES" ([0140]), unused-device filtering,
  logic injection and gate recognition ([0115]-[0165]). There is no semi-series.
- The public Calibre LVS report for sky130 lists `LVS REDUCE SERIES MOS NO`,
  `LVS REDUCE PARALLEL MOS NO`, `LVS REDUCE SEMI SERIES MOS NO` and
  `LVS REDUCE SPLIT GATES YES` as **four separate statements**. Source:
  https://foss-eda-tools.googlesource.com/skywater-pdk/libs/sky130_fd_sc_ms/+/refs/heads/new-spice/cells/inv/sky130_fd_sc_ms__inv_1.lvs.report,
  lines 125-128. So semi-series is neither series nor split gates.
- KLayout's `split_gates` ("Multi-fingered, multi-gate MOS transistors can be built without
  connecting the source/drain internal nets between the fingers ... joins the internal
  source/drain nodes", KLayout@4d927b79 src/lvs/lvs/built-in-macros/_lvs_netter.rb:389-405) is
  the open reading of SPLIT GATES, not of semi-series.
- KLayout combines MOS in parallel only (`MOS3DeviceCombiner`, "parallel transistors can be
  combined into one", src/db/db/dbNetlistDeviceClasses.cc:301-320).
- Netgen: "Series connections are only allowed for resistors and inductors" (netgen@e5a185dc
  base/netgen.c:2984).

N2 (its draft LVS-042 catalog note) had already searched the Siemens pages,
EDA Solutions TN061, FreePDK45, the sky130 reports, the UVA wiki, Silvaco, ICV/Pegasus/Assura
material, Google Patents and the KLayout forum, all with no result. This pass adds P12 (full
text), Mentor US 7,716,611, KLayout and Netgen source, and web searches for "semi-series",
"semiseries" and "semi series" with LVS/MOS/patent. All came back empty. Any definition offered
would be a guess, so none is given.

**Implementable?** No, not as Calibre's statement.

**Checked, nothing found:** as above, plus `site:patents.google.com "semi-series" MOS LVS` and
Mentor patents found by inventor search (Pikus). The Chinese forum and blog posts that paraphrase
the SVRF manual (mweda, jianshu) and the iczhiku manual PDF were deliberately not read.

## LVS-048: Filter unused devices

**Verdict:** partial (8 options defined publicly; others not).

**Definition:**
- GlobalFoundries US 8,751,985 B1 (Puri et al., 2014), **col. 7 ll. 44-62**, checked on the
  page image (sheet with col. 7). N2's catalog note cites "col. 9", which is wrong; the list
  is in col. 7:
  > "The Calibre® package, for instance, provides a control file option (LVS FILTER UNUSED
  > OPTION [option] LAYOUT) to filter out other devices. The Calibre® documentation provides a
  > finite set of possibilities for [option] ... These include, but are not limited to:
  > AE—with source, drain, and gate pins all floating / AF—with source and drain pins tied
  > together / AG—with all pins tied together, including bulk and optional pins / C—with gate
  > tied to power or ground, and either the source or drain floating / K—with neither source nor
  > drain having any path to any pad / P—with no general paths to any pad / Q—with no general
  > paths to any non-power/ground pads / U—with both the source and drain floating"
- P12 [0148]-[0150] ("COMMAND7 ... controls the process of filtering out unused devices during
  a layout-versus-schematic operation"), with [0139]/[0144] ("COMMAND7 MOS yes ... unused MOS
  devices are filtered out"). The surface form is `LVS FILTER UNUSED MOS YES|NO`; FreePDK45's
  public deck has `LVS FILTER UNUSED MOS no`
  (https://raw.githubusercontent.com/mflowgen/freepdk-45nm/master/calibre-lvs.rule line 8).
- P12 [0162]: "Power net names can be used by a layout-versus-schematic operation in, for
  example, logic gate recognition, filtering of unused MOS transistors". So option C's "power
  or ground" are the LVS POWER NAME / GROUND NAME nets.
- P12 [0119]: filtering runs together with reduction ("If the choice is DEVICE REDUCTION ...
  performs device reduction and unused device filtering").
- Open readings of AG ("all pins tied together"):
  - KLayout `Circuit::purge_devices`: `can_purge_device` is true when every terminal of the
    device class, bulk included for MOS4, is on one net (KLayout@4d927b79
    src/db/db/dbCircuit.cc:831-863; doc "devices ... whose terminals are all connected to a
    single net", gsiDeclDbNetlist.cc:1872-1876).
  - Netgen `ignore shorted <class>`: an instance is removed when all pins share one node
    (netgen@e5a185dc base/objlist.c:429-493, tcltk/tclnetgen.c:2875-2905, base/spice.c:1802-1813).

**Implementable?** AE/AF/AG/U are already implemented by N2 (`lvs filter_unused ae af ag u`).
- **C** is now definable: gate net is an LVS power or ground name (P12 [0162]) **and** (source
  floats **or** drain floats). "Floating" uses the same predicate N2 uses for AE/U.
- **K/P/Q** remain derivations. "Path" plausibly means P12's default LVS path (MOS s/d +
  resistor pins, [0267] init_1), and "pad" plausibly means a top-level port (P12 `lvsOutline`,
  [0210]). Neither "general path" nor "pad" is defined in any public source.

Differentials:
- AG: KLayout `netlist.purge_devices` and Netgen `ignore shorted`, run on netlists with a
  device having all four pins on one net.
- C, hand oracle:
  - NMOS with g=VSS, d=n1, and s on a net with no other connection: filtered.
  - The same device with s=VSS: not filtered (neither s nor d floats).
  - g on a signal net: not filtered.

**Checked, nothing found:** the meanings of options other than the eight above (including
whatever "but are not limited to" hides). The sky130 Calibre reports have the statement
commented out (`// LVS FILTER UNUSED OPTION`, report line 102). EDA Solutions TN061, per N2.

## DRC-015: Discrete / allowed width set

**Verdict:** partial. The ASAP7 M4.W.3/W.4 text is found. WIDTHTABLE ORTHOGONAL is found, both as text and figure and in a checker that reads it. The polygon fracture is still undefined; the three candidate methods agree on every LEF example, and a test case below separates them.

**Definition:**

- **ASAP7 M4.W.3/W.4** ([DRM] Table 3.14.1, printed p. 53; Fig. 3.14.1, printed p. 55, PDF p. 63).
  - M4.W.1: "Minimum vertical width of M4 ≥ 24 nm".
  - M4.W.2: "Maximum vertical width of M4 ≤ 480 nm".
  - M4.W.3: "M4 vertical width may not be an even integer multiple of its minimum width". The figure states it as "M4 Vertical Width ≠ 2N × M4.W.1, N ∈ Z+".
  - M4.W.4: "M4 vertical width, resulting in the polygon spanning an even number of minimum width routing tracks vertically, is not allowed". The figure states it as "M4 Vertical Width = (2N+1) × M4.W.1, N ∈ 2Z+".
  - M4.AUX.1: horizontal edges lie on a 24 nm grid.
  - M4.AUX.4: "Outside edge of a wide M4 layer polygon may not touch a routing track edge".
  - "the rules listed in this section for M4 apply to M5 as well" (p. 52), with directions swapped. M6/M7 use the same pattern (M6.W.3, PDF text line 2506).
  - So the legal vertical widths of a horizontal M4 wire are 24·(4k+1) nm: 24, 120, 216, 312, 408 (≤ 480).
  - The ASAP7 tech LEF encodes exactly this: `WIDTHTABLE 0.024 0.12 0.216 0.312 0.408` on M4 ([OR] test/asap7/asap7_tech_1x_201209.lef:294-295). Its comment says "to make the special route widths integer values of the tracks, i.e., 1, 5, 9, 13... min widths" (line 228).
- **WIDTHTABLE ORTHOGONAL** ([LEF58] p. 104 and Fig. 1-33, p. 107): "one of the right or wrong direction width between two inside corners of a rectilinear object must be greater than or equal to the first width value in the WIDTHTABLE in the corresponding direction, if WIDTHTABLE WRONGDIRECTION is specified. Otherwise … the first width value … (for both directions) either vertically or horizontally."
  - Fig. 1-33 c (vertical layer, `WIDTHTABLE 0.05 … ORTHOGONAL; WIDTHTABLE 0.1 0.15 WRONGDIRECTION`): two overlapping rectangles whose inside corners are 0.05 apart horizontally and 0.03 vertically. "OK, the right direction width of 0.05 (>= 0.05) is met although the wrong way direction width fails."
  - Fig. 1-33 d: abutting rectangles sharing a 0.04 edge. "Violation, touching wires still subjects to the rule, and right direction width of 0.04 (< 0.05) fails."
- **Fracture** ([LEF58] p. 105): "A polygon will be fractured into rectangles, and only the shorter dimension of the rectangles will be checked". Fig. 1-32 a (an L with arms 0.1 and 0.2) checks only 0.1 and 0.2.
  - Fig. 1-33 a (a vertical layer, with an L made of a 0.07-tall horizontal arm and a 0.05-wide vertical arm) is flagged: "0.07 is not a legal width of a horizontal wire". So a fractured rectangle's direction is its long axis, and its width is checked against the WRONGDIRECTION table when that axis is the wrong way.

**Reading (implementation):**

- [OR] src/drt/src/gc/FlexGC_main.cpp:1481-1551 (`checkWidthTableOrth_main`, `checkWidthTableOrth`). For each concave corner of a polygon, it looks at concave corners that are endpoints of same-polygon edges inside a box of ±(horz, vert) around it. It flags the pair when `dx < horz_spc && dy < vert_spc`.
- [OR] src/drt/src/io/io.cpp:1799-1823: `horz_spc`/`vert_spc` are the first widths of the ORTHOGONAL tables. On a horizontal layer, horz = wrong-way width and vert = right-way width.
- Deviation from the LEF text: TritonRoute reads the wrong-way first width only from a table that is itself ORTHOGONAL. Fig. 1-33 puts ORTHOGONAL only on the right-way table, so TritonRoute falls back to the right-way width (0.05) for both directions where the LEF says 0.1 for the wrong-way one.
- KLayout (dbLEFImporter.cc:728-759 @4d927b79) keeps only the smallest WIDTHTABLE value as the DEF wire width and ignores ORTHOGONAL ("nothing yet").
- iEDA has no width-table check.

**Implementable?** Yes for ASAP7 and ORTHOGONAL. The fracture needs a chosen convention.

- **ASAP7 deck:** on M4/M5, measure each wire's cross-direction width with `allowed: [24,120,216,312,408]`, closed set. Equivalently, flag `w/24` not an integer or `w/24 mod 4 != 1`.
  - Oracle: horizontal M4 rectangles 1000 × w nm.
    - w = 24, 120: OK.
    - w = 48: W.3.
    - w = 72: W.4 only (W.3 allows odd multiples).
    - w = 168: W.4.
    - w = 30: off-grid (AUX.1).
    - w = 504: W.2.
- **ORTHOGONAL:**
  - Inputs: the first width of the right-way table, R, and of the WRONGDIRECTION table, W. W defaults to R.
  - For every pair of concave corners of one merged polygon, set dx = |x1-x2| and dy = |y1-y2|.
  - The across-wire distance of a right-way wire is dx on a vertical layer and dy on a horizontal one. Flag if `right_dist < R && wrong_dist < W`.
  - Oracle: Fig. 1-33 c (dx 0.05, dy 0.03 on a vertical layer, R 0.05, W 0.1) gives OK; Fig. 1-33 d (dx 0.04, dy 0) gives a violation.
  - Differential: TritonRoute `detailed_route` DRC report on a LEF that carries ORTHOGONAL on both tables (both readings agree there).
- **Fracture (derivation):** the LEF text, Fig. 1-32 and Fig. 1-33 a are all satisfied by any of three methods: (i) maximal rectangles (TritonRoute's min-width and spacing objects), (ii) slicing along the wire direction, (iii) slicing in both directions as WXL does for MINWIDTH ([WXL] p. 5, "After slicing a polygon into rectangles (in both directions), the length along the slicing direction of any sliced rectangle must be ≥ minWidth").
  - Distinguishing test: `WIDTHTABLE 0.1 0.2 0.4`, polygon = (0,0)-(1,0.4) ∪ (0,0.4)-(0.3,0.5).
    - Horizontal slicing gives slabs 1.0×0.4 and 0.3×0.1, both legal: OK.
    - Vertical slicing gives 0.3×0.5, which has width 0.3: violation.
    - Maximal rectangles give 1.0×0.4 and 0.3×0.5: violation.
  - Recommend maximal rectangles, with each rectangle's direction given by its long side. That matches Fig. 1-33 a and TritonRoute's object model. Mark it a derivation.

**Checked, nothing found:**

- [LEF57] has no WIDTHTABLE.
- [OR] has no non-ORTHOGONAL width-table checker (grep "WidthTable" in drt).
- iEDA iDRC has no width table.
- KLayout only takes the smallest width.
- The coriolis HTML LEF/DEF 5.8 (http://coriolis.lip6.fr/doc/lefdef/lefdefref/LEFSyntax.html) is identical to ref.txt for LEF58 properties.
- libresilicon/lefdef_parser lef.md gives syntax only.
- ISPD19 problem intro has no WIDTHTABLE.

## DRC-016: Wrong-direction width or spacing

**Verdict:** partial. Negative PRL now has a public reading and implementation path. LENGTH is still undefined.

**Definition:**

- LEF58_WIDTH WRONGDIRECTION is defined ([LEF58] pp. 107-108, plus the wrong-way width table on pp. 269-272). It was already used.
- LEF58_SPACING `SPACING s WRONGDIRECTION [NONEOL w] [PRL p] [LENGTH l]` is absent from [LEF58] and from [LEF57] (grep "WRONGDIR" finds nothing in [LEF57]). The grammar is only in [OR] src/odb/src/lefin/lefTechLayerWrongDirSpacingParser.cpp:60-72 and the iEDA EOL grammar (`WRONGDIRSPACING`, ieda/routinglayer_property_parser.h:179).
- Meaning of a negative PRL. [WXL] p. 5, Fig. 7 (b) draws "PRL (<0)" as the gap between the two shapes' projections along the run direction, with "spacing" drawn as the corner-to-corner Euclidean distance. Its text: "If … the parallel run length is greater than length, then the spacing … must be greater than or equal to spacing … Figure 7 illustrates the spacing for both positive and negative PRLs."

**Reading:**

- [OR] src/drt/src/gc/FlexGC_main.cpp:1044-1058 `getPrl` already returns a signed overlap, `min(max1,max2) - max(min1,min2)`, which is negative when the edges' projections do not overlap.
- `checkMetalSpacing_wrongDir` (1078-1148):
  - It takes wrong-way edges, skipping those shorter than NONEOL w.
  - It skips the pair if `prl <= prlLength`, i.e. it requires prl > p.
  - It also requires the other edge to be at least w long (NONEOL).
  - It flags if the Euclidean distance between the edges is less than s.
- The query box (1010-1042) spans only the edge's own extent, so neighbours offset beyond the edge end are never found. That is why io.cpp:1630-1636 drops negative PRL (DRT-334), and io.cpp:1625-1628 drops LENGTH (DRT-333).
- The test LEF uses both: `SPACING 0.12 WRONGDIRECTION NONEOL 0.15 PRL -0.05 LENGTH 0.2` ([OR] src/odb/test/data/gscl45nm.lef:47).

**Implementable?** Negative PRL: yes, as a derivation (WXL's figure plus TritonRoute's signed `getPrl` and its strict `prl > p`). LENGTH: no.

- Sketch for negative PRL:
  - Take facing wrong-way edge pairs.
  - Extend the search window by |p| along the edge direction when p < 0.
  - prl = signed projection overlap. Require prl > p, then flag if the Euclidean edge-to-edge distance is less than s.
- Oracle (vertical layer, `SPACING 0.12 WRONGDIRECTION PRL -0.05`): two horizontal wires 1.0 long, facing edges 0.10 apart in y.
  - x-gap 0.03: prl = -0.03 > -0.05, distance √(0.10²+0.03²) = 0.104 < 0.12, so a violation.
  - x-gap 0.06: prl = -0.06, so the rule does not apply.
  - x-overlap 0.5: prl = 0.5, distance 0.10, so a violation.
- Differential: TritonRoute after deleting its DRT-334 guard and widening the query box. As shipped it gives no oracle for p < 0.

**Checked, nothing found** for LENGTH:

- [LEF57], [LEF58], the coriolis HTML.
- [OR] odb parser (LENGTH is parsed and stored with no comment) and drt (DRT-333).
- iEDA (its EOL grammar has no wrong-direction LENGTH).
- [WXL].
- ISPD19 intro (http://www.ispd.cc/contests/19/Introduction_of_ISPD19_Contest_Problem.pdf).
- GitHub code search `"WRONGDIRECTION NONEOL"`: only OpenROAD forks.

## DRC-021: Length of a bent feature along its path (sky130 mf.2, IHP Rsil.f, Rppd.e)

**Verdict:** partial. There is a public definition of a bent resistor's
length, from EDA documentation plus two implementations, and they agree: the
centerline length, with corner squares weighted by a factor. No foundry text
says that its length rules use that definition.

**Definition:**
- Magic Technology File Format 35 manual, Extract section
  (http://opencircuitdesign.com/magic/techref/maint2.html): "resist types R
  [chop] … The optional value 'chop' indicates the factor to apply to
  corners for the adjustment of resistance where devices bend at a 90 degree
  angle. The resistance through the corner as computed by the material
  resistance in ohms per square multiplied by the length of the path
  centerline will be multiplied by chop. The default value of chop if
  unspecified is 1.0. Typical values are 0.7 … or 0.5".
- The Magic reading (magic@bed8d4ff) matches:
  - `extract/ExtBasic.c:2989-3047`: for a multi-tile `device resistor`, the
    side boundaries are paired and `extComputeEffectiveLW(&width, &length…)`
    is called with L and W swapped (the comment is at :1240).
  - Length is accumulated from opposite-side overlaps (:1457, :1483).
  - Corner extensions are added times `chop` (:1507).
  - The default is `exts_cornerChop = 1.0` (`extract/ExtTech.c:857`); `chop`
    is the 4th argument of `resist` (:3415).
- KLayout@4d927b79 `src/db/db/dbNetlistDeviceExtractorClasses.cc:451-466`
  (the resistor extractor): the length is half the length of the resistor
  edges not shared with the two contacts (`eparallel.length()`, then
  `L = 0.5·length2`). For Manhattan bends this equals the centerline length
  (a derivation: an L of width w with outer arms a, b has sides a + b and
  (a − w) + (b − w), whose mean is a + b − w).
- IHP's own LVS reading, IHP-Open-PDK@5e6d592e
  `ihp-sg13g2/libs.tech/klayout/tech/lvs/rule_decks/custom_extractor.lvs:169-195`
  (`calc_res_params`), is a pcell-parameter recovery, not a geometric
  length:
  - L is the shortest non-port edge adjacent to a port edge, plus the width
    if there are bends;
  - bends = corners/4.
- The IHP layout rules (SG13G2_os_layout_rules.pdf Rev 0.4, §6.2 p. 50, §6.3
  p. 51) say only "Rsil.f Min. RES length 0.50" and "Rppd.e Min. SalBlock
  length 0.50", and the §4.1 terminology has no definition of length.

**Implementable?** Yes, as a deck option, `length_mode: centerline(chop)`.
- Inputs: the body polygon and its two terminal edges (the RES/SalBlock or
  fuse markers bounding it).
- Length = (sum of side-overlap lengths of opposite parallel side edges) +
  chop × (centerline through each 90° corner square). For Manhattan
  geometry with chop = 1 this equals half the non-terminal perimeter, the
  KLayout formula.
- Flag the feature if length < min (or > max).
- Oracle, for a 1 µm wide L with arms 0..10 × 0..1 and 9..10 × 0..10, with
  terminals at x=0 and y=10:

  | Method | Length |
  | --- | --- |
  | KLayout (sides 10 + 10 + 9 + 9) / 2 | 19 |
  | Magic, chop = 1 | 19 |
  | Magic, chop = 0.5 | 18.5 (derivation from the manual text) |
  | Straight 1 × 10 bar, any method | 10 |

  Differential: KLayout `extract_devices(resistor("RES", sheet_rho), {"R"=>…,"C"=>…})`
  and read L; Magic `extract` plus `ext2spice` with a `device resistor` and
  `resist … chop`.

**Checked, nothing found:** a foundry statement (sky130, IHP, GF) that the min
or max length of a bent resistor or fuse is measured along the centerline.

## DRC-031: Tip-to-tip / tip-to-side by width class (ASAP7 M4.S.4)

**Verdict:** found. M4.S.4 is the line-end offset (stagger) rule between
same-facing ends of two lines on adjacent tracks that share a run: the offset
must be 0 (aligned) or at least 40 nm.

**Definition:**
- ASAP7 DRM (asap7_drm_201207a.pdf in The-OpenROAD-Project/asap7_pdk_r1p7,
  `docs/asap7_drm_201207a.pdf`, Table 3.14.1, printed p. 53): "M4.S.4 Spacing
  Minimum tip-to-tip spacing between two M4 layer polygons—that share a
  parallel run length—on adjacent tracks ≥ 40 nm". M4.S.3 is the same with
  "that do not share a parallel run length", and M4.S.5 is "Minimum parallel
  run length of two M4 layer polygons on adjacent tracks ≥ 44 nm". The rules
  apply to M5 rotated 90° (§3.14 intro).
- The figure settles which tips are meant. In Fig. 3.14.2(d) (printed p. 56,
  PDF page 64), the top track has lines A and B and the bottom track has C
  and D:
  - M4.S.3 runs from the right end of C to the left end of B. These are
    facing tips on adjacent tracks with no common run.
  - M4.S.4 runs from the left end of B to the left end of D. These are
    same-facing ends of two lines on adjacent tracks that overlap in x.
  - M4.S.5 runs from the left end of D to the right end of B, which is their
    common run.

  The same figure also draws A and C with both ends aligned (offset 0) as
  legal geometry. That is the "= 0" exception (a derivation from the figure:
  the DRM text gives no exception).
- The SADP origin of the rule is public. Xu, Cline, Yeric, Yu, Pan, "Self-Aligned
  Double Patterning Aware Pin Access and Standard Cell Layout Co-Optimization",
  IEEE TCAD 34(5):699–712, May 2015 (author copy:
  https://www.cse.cuhk.edu.hk/~byu/papers/J09-TCAD2015-SADPCell.pdf), p. 702
  Fig. 5(d): "OffTrackOffset ≥ l4 or OffTrackOffset = l4 = 0". Table II,
  p. 701: "Rule 4: l4 ≥ w_r or l4 = 0", where w_r is the trim mask's
  minResistWidth. The paper's Fig. 5(b) OffTrackOverlap and 5(c)
  OffTrackSpace are the shapes of M4.S.5 and M4.S.3, on the same 48 nm pitch
  with 24 nm lines as ASAP7 M4.
- The aligned-ends exception is also stated in public patent text, not only
  derived from the figure. Patents are read from USPTO image PDFs at
  `image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/<no>`.
  - US 9,087,174 B1 (Cadence; Zhang, Gerousis; filed 2013), col. 15
    l. 39–42: "708B represents the trim mask minimum step rule that
    requires two neighboring interconnects running in the same direction
    to have a step having a minimum step of 712B". l. 54–56: "if the design
    rule (e.g., rule 708B) requires that two interconnects running in the
    same direction to have a minimum spacing of zero or greater 100-nm". It
    is drawn in FIG. 7B (sheet 10). So this is a trim-mask rule with the
    shape of M4.S.4: offset 0, or offset ≥ value.
  - US 11,983,476 B2 (IBM; Pandey, Tellez; filed 2021), col. 5 l. 36–52,
    gives a generalised form of the same rule: "an exclusion (dead) zone
    for a line end (where the distance Dt between line ends of neighboring
    nets in the same direction must be greater than Dn+Dz or less than
    Dn)", where "the same direction refers to a scenario where … both of the
    metal shapes have line ends on the same edge". ASAP7 M4.S.4 is the case
    Dn → 0 (only an aligned end is below Dn) and Dn + Dz = 40.
- Clark et al., "ASAP7: A 7-nm finFET predictive process design kit",
  Microelectronics Journal 53 (2016) 105–115 (open copy in the same repo,
  `docs/mej_paper_asap7.pdf`, p. 111, Table 2) says "M4–M7 may not jog —
  1-D lines only" and "We assume a single patterned block mask layer".

**Reading:**
- ASU-VDA-Lab/DAC26_DRC_Benchmark@2b859f96 `testcase/asap7/asap7.lydrc:853-860`
  (BSD-3) does the following:
  - It takes each M4 vertical (line-end) edge and extends it 30 nm along
    itself.
  - It subtracts M4 and keeps the extension edge collinear with the tip
    (`m4_tip_ext_ve_clean`).
  - It codes M4.S.3 as `separation(m4_ve, 40.nm, projection)`, which pairs
    opposite-facing ends.
  - It codes M4.S.4 as `enclosing(m4_ve, 40.nm, projection)`, which pairs
    same-facing ends.

  So the M4.S.4 check is "same-facing line ends on adjacent tracks closer
  than 40 nm and not coincident". This matches the figure.
- A different reading is in laurentc2/ASAP7_for_KLayout@ef77f080
  `drc/drc_ASAP7.lydrc:365`: `m4.sized(0,48.nm).notch(40.nm, projection)…`.
  It catches facing-tip gaps that become notches inside a vertically merged
  cluster. That is in effect a variant of M4.S.3, so do not use it as the
  oracle for M4.S.4.

**Implementable?** Yes.
- Inputs: the M4 layer (M5 rotated), the track direction, and the 40 nm value.
- Operation: for every pair of lines L1, L2 that meet all of the following:
  - they are on adjacent tracks (the facing long edges are 24 nm apart, which
    is M4.S.1);
  - their x-projections overlap by more than 0;
  - for each side (left ends, right ends), with offset = |x1 − x2|:

  flag the pair if 0 < offset < 40 nm. This is an `enclosing`-type,
  same-orientation edge check, with projection, between the line-end edges
  of lines on adjacent tracks.
- Deck parameters: `tip_offset_min` (40 nm), `aligned_ok: true`, adjacent
  tracks only. Generic forms are Xu et al. Rule 4 (`l4 ≥ w_r or l4 = 0`),
  Cadence 708B ("zero or greater [than] 100-nm"), and the IBM dead zone
  `Dt < Dn or Dt > Dn + Dz`. The general kind would be a forbidden-interval
  stagger, `[Dn, Dn+Dz]`.
- Oracle: tracks [0,24] and [48,72] in y, all in nm. Each case gives the top
  line, the bottom line, and the expected result.

  | Top line | Bottom line | Expected |
  | --- | --- | --- |
  | x [0,200] | x [20,300] | 1 M4.S.4 (left ends 20 apart; right ends 100 apart, which is fine) |
  | x [0,200] | x [0,300] | clean (aligned) |
  | x [0,200] | x [40,300] | clean (exactly 40) |
  | x [0,200] | x [39,300] | 1 M4.S.4 |
  | x [0,200] | x [220,400] | no S.4; 1 M4.S.3 (facing tips 20 apart, no common run) |
  | x [0,200] | x [160,400] | no S.4 (offsets 160 and 200); 1 M4.S.5 (run 40 < 44) |

  Differential: `klayout -b -r asap7.lydrc -rd in_gds=t.gds -rd report_file=t.lyrdb`
  with the DAC26 deck. KLayout is not installed here, so this was not run.

**Checked, nothing found:** the ASAP7 Calibre deck. It is not in the GitHub
repo: `calibre/ruledirs/drc/README.txt` says it must be downloaded from
asap.asu.edu.

## DRC-036: Span-length table (ORTHOGONAL)

**Verdict:** partial. The figure defines which corners pair up and supports Euclidean measurement; no checker reads it.

**Definition:**

- [LEF58] p. 102: "ORTHOGONAL length — Specifies that the length between two inside facing corners of a rectilinear object must be greater than or equal to the length."
- Fig. 1-31 (p. 104):
  - The shape is a cross: a horizontal bar with one block above it and one block below it, offset sideways.
  - The concave corners are where the blocks meet the bar: two on the bar's top edge and two on its bottom edge.
  - "the length of the blue arrows should be checked against length". The two blue arrows are straight diagonals from the top-left concave corner to the bottom-right one, and from the top-right to the bottom-left. The vertically aligned pairs are not drawn.

**Derivation from the figure:**

- "Inside facing" pairs two concave corners whose exterior quadrants are opposite (up-left with down-right, up-right with down-left), where each corner lies inside the other's interior quadrant.
- The measure is the Euclidean distance; the arrows are drawn as true diagonals, not as dx/dy legs.
- This is a derivation from a figure. No public text or code confirms it. OpenROAD does not parse ORTHOGONAL for SPANLENGTHTABLE (grep "SPANLENGTHTABLE" in odb lefin finds nothing). Contrast WIDTHTABLE ORTHOGONAL (DRC-015), where TritonRoute uses dx and dy separately and the text says "either vertically or horizontally".

**Implementable?** As a derivation.

- Sketch: for each merged polygon, list its concave corners with their exterior-quadrant direction (sx, sy). For each pair with opposite (sx, sy), where corner2 lies strictly in corner1's interior quadrant and vice versa, flag if the Euclidean distance is less than `length`.
- Oracle (ORTHOGONAL 0.3): bar (0,0)-(1,0.2), top block (0.1,0.2)-(0.6,0.5), bottom block (0.4,-0.3)-(0.9,0).
  - Corners: (0.1,0.2) up-left, (0.6,0.2) up-right, (0.4,0) down-left, (0.9,0) down-right.
  - The facing pairs are (0.1,0.2)-(0.9,0) at 0.825, which is OK, and (0.6,0.2)-(0.4,0) at 0.283, which is a **violation**.
  - Non-facing pairs such as (0.1,0.2)-(0.4,0) are not measured.

**Checked, nothing found:**

- [LEF57] has no SPANLENGTHTABLE.
- [OR] odb/drt.
- iEDA (no span-length rule).
- KLayout LEF importer.
- GitHub code search `"SPANLENGTHTABLE" ORTHOGONAL`: no hits outside the reference text.
- [WXL], ISPD19 intro.

## DRC-053: LEF58_SPACING EXACTALIGNED (metal and cut forms)

**Verdict (revised):** the cut form is **found** (2009 ref text and Figure 1-21) and implementable.
The metal form still **does not exist** in any public grammar, the 2009 ref included.

**Definition (public text):** *LEF/DEF Language Reference 5.7, Nov 2009* (ISPD-hosted, see DRC-066).
- Grammar (pp.55-56, ref57.txt:2388-2410), on a cut layer:
  `PROPERTY LEF58_SPACING "SPACING cutSpacing [MAXXY | [CENTERTOCENTER] [SAMENET|SAMEMETAL|SAMEVIA]
  [LAYER secondLayerName [STACK] | ADJACENTCUTS {2|3|4} [EXACTALIGNED exactAlignedCut] WITHIN cutWithin
  [EXCEPTSAMEPGNET] [CUTCLASS className] [SIDEPARALLELOVERLAP] | PARALLELOVERLAP ... | ...]] ;"`.
- Semantics (p.57, ref57.txt:2449-2456): "The EXACTALIGNED keyword specifies that the adjacent cut
  spacing rule applies when the cut has exactAlignedCut via cuts that are perfectly aligned
  horizontally and/or vertically and are less than cutWithin distance from each other. Otherwise,
  the adjacent cut spacing rule applies when non-perfectly aligned cuts are equal to the specified
  number of cuts after the ADJACENTCUTS keyword, which must be smaller than exactAlignedCut."
- Example (p.61, ref57.txt:2639-2644): "a cut can have at the most two perfectly aligned neighbor cuts
  horizontally and/or vertically or at the most one non-perfectly aligned neighbor cut within 0.2 µm
  distance: `SPACING 0.2 CENTERTOCENTER ADJACENTCUTS 2 EXACTALIGNED 3 WITHIN 0.2 ;`".
- Figure 1-21 (p.62, rendered from PDF page 62). All dimensions are 0.19 centre-to-centre between
  equal square cuts:
  - (a) "Okay. Only 1 neighbor cut within 0.2". It is diagonal, so not aligned.
  - (b) "Violation. When there is 1 non-perfectly aligned neighbor cut (on the left), any other neighbor
    cut, perfectly aligned or not (on the right) would trigger the rule spacing of 0.2".
  - (c) "Okay. Two perfectly aligned neighbor cuts in 'L' or a straight line are fine".
  - (d) "Violation. Three perfectly aligned neighbor cuts would trigger the rule spacing of 0.2".
- Base ADJACENTCUTS meaning (5.8 ref p.33, ref.txt:1377-1383 and 1471-1473): "Applies the spacing rule
  only when the cut has two, three, or four via cuts that are less than cutWithin distance", and "A
  cut is considered adjacent if it is within distance of another cut in any direction (including a
  45-degree angle)."
- Consumers: OR drt skips the rule (io.cpp:1858-1866, DRT-045), and TritonRoute-WXL warns. There is
  no reference tool.
- Metal form: the metal-layer LEF58_SPACING forms in ref57.txt and Open-EDI's full metal grammar contain
  no EXACTALIGNED. The catalog's "exactly aligned line ends" metal form should be dropped.

**Implementable? Yes, cut form.** Sketch, for `SPACING s [CENTERTOCENTER] ADJACENTCUTS k EXACTALIGNED e
WITHIN cw [CUTCLASS c]` on cut layer V:
1. For each cut x (of class c if given), N(x) is the set of other cuts y on V with dist(x,y) < cw.
   dist is centre-to-centre with CENTERTOCENTER, otherwise edge-to-edge. Both are Euclidean ("any
   direction, including a 45-degree angle").
2. Alignment: y is perfectly aligned with x if y's x-extent equals x's (vertically aligned) or y's
   y-extent equals x's (horizontally aligned). For equal cuts, that means the same centre x or the same
   centre y. Extent equality for unequal cuts is a derivation; it matches OR's EXACTALIGNEDSPACING test
   `prl == cut extent`.
3. Trigger: if every y in N(x) is aligned, |N(x)| ≥ e; if any y is not aligned, |N(x)| ≥ k.
   Fig b settles that the second count is the **total** number of neighbours, not just the
   non-aligned ones: one non-aligned plus one aligned triggers with k = 2.
4. When x triggers, flag each (x,y) with dist(x,y) < s, using the same metric.
5. Parameters: s, k, e, cw, centre/edge, class. Other ADJACENTCUTS options (EXCEPTSAMEPGNET,
   SIDEPARALLELOVERLAP) follow the plain adjacent-cuts check.

**Oracle: Figure 1-21 with numbers.** 0.1 × 0.1 cuts, `SPACING 0.2 CENTERTOCENTER ADJACENTCUTS 2
EXACTALIGNED 3 WITHIN 0.2`, x at (0,0):

| Case | Neighbours of x (centres) | Count, alignment | Expected |
|---|---|---|---|
| a | (0.134,0.134), dist 0.1895 | 1, not aligned; 1 < 2 | **Okay** (the neighbour also sees only x) |
| b | (0.134,0.134) and (0.19,0) | 2, one not aligned; 2 ≥ 2 | **Violation**: x with both neighbours (0.1895 and 0.19 < 0.2). (0.134,0.134) also triggers: it sees x and (0.19,0) at 0.145. |
| c-L | (0,0.19) and (0.19,0) | 2, all aligned; 2 < 3 | **Okay**. The two neighbours are 0.269 apart, so each sees 1. |
| c-line | (−0.19,0) and (0.19,0) | 2, all aligned; 2 < 3 | **Okay** |
| d | (−0.19,0), (0.19,0) and (0,0.19) | 3, all aligned; 3 ≥ 3 | **Violation**: 3 pairs |

Boundary cases:
- Case c-L with a neighbour at (0.2,0): c2c = 0.2 is not < 0.2, so it is not counted. Count 1, **Okay**.
- Case a with the diagonal at (0.15,0.15): 0.212 ≥ 0.2, count 0, **Okay**.

**Other "exact aligned" forms (unchanged):**
- `LEF58_SPACINGTABLE ... EXACTALIGNEDSPACING` is implemented by OR drt (FlexGC_cut.cpp:112-124:
  class1 == class2, no LAYER, aligned when `prl == deltaH1/deltaV1`). It belongs to DRC-063.
- KEEPOUTZONE EXCEPTEXACTALIGNED is covered under DRC-126.
- ASAP7 V1.M2.AUX.2 is already `full_width`.

**Checked:**
- ref.txt and ref57.txt (the cut form is found; there is no metal form).
- OR odb/drt.
- Open-EDI.
- iEDA.
- GitHub code search "EXACTALIGNED".
- ISPD 2019 LEFs.

## DRC-066: LEF58_MINIMUMCUT AREA, SAMEMETALOVERLAP, FULLYENCLOSED

**Verdict (revised):** AREA [WITHIN] is **found**: the 2009 ref defines it with two figures, and it is
implementable. SAMEMETALOVERLAP and FULLYENCLOSED are still **not found**.

**Definition: AREA (public text).**
Source: Cadence *LEF/DEF Language Reference, Product Version 5.7, November 2009*, hosted by ISPD
(https://www.ispd.cc/contests/18/lefdefref.pdf; also /contests/19/lefdefref.pdf, which is byte-identical).
ref57.txt:7008-7135; printed pp.157-160.
- About the edition: every page footer reads "November 2009 ... Product Version 5.7", and the
  copyright line is "© 1990-2008". The text carries no later date: the only "2010" in it is a number
  inside a PWL table, ref57.txt:18448. The PDF metadata is just a 2014 re-save:
  `CreationDate Fri Jan 17 16:52:16 2014 EST`, `xmp:CreatorTool Preview`,
  `Producer Mac OS X 10.9.1 Quartz PDFContext`. This is not an edition date.
  The text introduces the properties as "cut layer properties in your LEF file to create 32nm and 45nm
  rules that currently are not supported by existing LEF syntax ... The property names used for
  these rules all start with LEF58_" (ref57.txt:1795-1805).
- Grammar (p.157): `PROPERTY LEF58_MINIMUMCUT "MINIMUMCUT numCuts WIDTH width [WITHIN cutDistance]
  [FROMABOVE | FROMBELOW] [LENGTH length WITHIN distance | AREA area [WITHIN distance]] ;..."`.
  It has no CUTCLASS, SAMEMETALOVERLAP or FULLYENCLOSED; those come from a later LEF58 edition.
- Semantics (p.158): "Applies the minimum cut rule when the wide object has a width that is greater
  than width, and an area that is greater than area."
  - The area is measured on a modified polygon: "The area of a polygon is determined by a process in
    which the polygon is shrunk by an amount equal to width/2, then grown by an amount equal to width/2.
    The resulting polygon at the connection location is used for area comparison."
  - Thin connections: "If the connection is made at a thin wire (width less than and equal to width)
    that connects to the wide object, the biggest remaining neighbor should be checked individually
    with their own areas."
  - Within distance: "If it is followed by a WITHIN distance syntax, the within distance is measured
    from the edges of the remaining neighbors."
  - Cut grouping: "If WITHIN cutDistance is absent, only cuts belonging to the same via are considered
    as multiple cuts."
  - Scope: "If AREA and WITHIN are defined, this rule only checks the thin wire connected to a wide
    wire; it does not check the wide wire itself. A separate MINIMUMCUT numCuts WIDTH width statement
    without AREA and WITHIN is required for any wide wire minimum cut rule."
  - Exclusivity: "You can specify either AREA WITHIN or LENGTH WITHIN in a routing layer."
- The 5.8 May 2017 text (ref.txt p.64) has no AREA. OR parses AREA, and drt drops it (DRT-317).

**Implementable? Yes, for AREA.** Sketch, for `MINIMUMCUT n WIDTH w [WITHIN c] [FROMABOVE|FROMBELOW]
AREA a [WITHIN d]` on metal layer M:
1. Opening: Q = grow(shrink(M, w/2), w/2), using Manhattan sizing (a square structuring element).
   - Parts of M of width ≤ w vanish, which matches "thin wire (width less than and equal to width)".
   - Each connected component R of Q is a "remaining" wide object with area(R).
   - Rectangles wider than w come back whole.
2. For each via, take its cuts between M and the adjacent cut layer, respecting FROMABOVE/FROMBELOW.
   Group the cuts as the existing `minimum_cut` does: with `WITHIN c`, cuts less than c apart count
   together; otherwise, cuts of the same via.
3. If the cuts lie on a component R of Q (a direct via) and a `WITHIN d` is given, the AREA rule does
   **not** apply (Fig 1-65 d). Only plain-width MINIMUMCUT rules apply there.
4. Otherwise the via sits on thin metal of the same polygon. For every component R of Q in that polygon
   with area(R) > a and dist(cut group, edge of R) < d (any R if there is no d), require ≥ n cuts.
   - Each R is checked individually.
   - The requirement is the maximum over all applicable rules.
   - Flag the via if it has fewer cuts.
5. Deck parameters: n, w, c, a, d, and above/below.

The ambiguous points, to be handled as switches:
- "biggest remaining neighbor": Fig 1-65 c checks C and A individually, so I read it as "each
  remaining neighbour".
- The distance metric: the figure dimensions it orthogonally, from R's edge to the via.

**Oracle: Figure 1-65** (p.160, rendered from PDF page 160). The rules are `MINIMUMCUT 2 WIDTH 0.24 ;
MINIMUMCUT 3 WIDTH 0.40 ; MINIMUMCUT 2 WIDTH 0.24 AREA 0.3 WITHIN 10.0 ; MINIMUMCUT 3 WIDTH 0.24 AREA 1.6
WITHIN 3.0`. The thin wire is narrower than 0.24 and carries a 2-cut via.

| Case | Layout | Opened components and areas | Required | Expected (figure) |
|---|---|---|---|---|
| a | A 5×0.3, B 0.2 wide × 0.3 tall, C 2×0.25. Via on a thin wire 1 from A. | B (0.2 ≤ 0.24) vanishes, so A (1.5) and C (0.5) are separate. A at distance 1: 1.5 > 0.3 needs 2; 1.5 < 1.6 does not need 3. | 2 | **Okay** |
| b | Same as a, but B is 0.3 wide. | One component of 1.5 + 0.09 + 0.5 = **2.09** > 1.6, at distance 1 < 3. | 3 | **Violation** |
| c | A 6×0.3, B 0.2 wide (thin), C 2×0.25. Thin wire leaves B; via 2 from C and 4 from A. | C: 0.5 > 0.3 at distance 2 < 10, needs 2. A: 1.8 > 1.6 but distance 4 ≥ 3, so 3 not required; 1.8 > 0.3 at 4 < 10 needs 2. | 2 | **Okay** |
| d | A lone 6×0.3 wire with a 2-cut via directly on it. | AREA…WITHIN rules do not apply (direct via). MINIMUMCUT 2 WIDTH 0.24 applies. | 2 | **Okay** (1 cut would violate) |

Extra edge cases, derived:
- Case b with B exactly 0.24 wide: B vanishes (≤ w), as in case a, **Okay**.
- Case a with the via 10.0 from A: d is not < 10, so no AREA rule applies, **Okay** even with 1 cut.

Figure 1-64 (`MINIMUMCUT 2 WIDTH 0.09 WITHIN 0.05 AREA 2.0`; "Sum of area of all m3 wires > 2.0 ...
all three vias should have two cuts") is internally inconsistent. A wire is dimensioned 0.07 while the
rule needs width > 0.09, and opening by 0.045 would erase a 0.07 wire. Do not use it as an oracle.

There is no reference tool: OR drops the rule (io.cpp:2648-2654), and iEDA's iDRC has no field for it.

**SAMEMETALOVERLAP and FULLYENCLOSED: not found.**
- Neither the 2009 ref nor the 2017 5.8 ref has them. A grep of ref57.txt for SAMEMETALOVERLAP,
  FULLYENCLOSED and ENCLOSED finds only unrelated hits.
- Grammar only, in later parsers: OR MinCutParser.cpp:97-101, Open-EDI routing_layer_rule.h:575-583,
  and iEDA. OR drt drops them (DRT-318/319).
- The nearest public phrases are SAMEVIA in the 2009 ref, "cuts that share the same metal shapes
  above and below that cover the overlap area between the cuts" (ref57.txt:2427-2431, p.56), and
  PARALLELOVERLAP in the 5.8 ref (p.33). Both concern cut spacing, so applying them to MINIMUMCUT
  would be a derivation only. Keep refusing.

**Checked, nothing found (SAMEMETALOVERLAP/FULLYENCLOSED):**
- ref.txt and ref57.txt.
- OR odb/drt.
- iEDA parser and iDRC.
- Open-EDI.
- TritonRoute-WXL.
- ISPD 2014 and 2019 LEFs.
- Web search.

## DRC-125: LEF PROTRUSIONWIDTH with positive LENGTH

**Verdict:** partial. The public definition is the LEF 5.8 text plus three figures, and it is precise enough to
derive an algorithm. No open implementation and no open foundry rule exist.

**Definition:** LEF/DEF 5.8 ref, p.76-77 (ref.txt:3247-3335; PDF pages 76-77, Figure 1-16):
"Specifies that the width of a protrusion must be greater than or equal to width1 if it is
shorter than length, and it connects to a wire that has a width greater than or equal to width2
... Length is determined by the shortest possible path among all of the protrusion wires with
width smaller width1, and is measured by the shortest outside edges of the wires." Example
`PROTRUSIONWIDTH 0.28 LENGTH 0.60 WIDTH 1.20`. The figures, as I read them from the rendered PDF:
- (a) **Okay.** A narrow stub rises from the wide wire, turns along a narrow horizontal piece, then
  follows a narrow vertical piece (also < 0.28) to its open end. The path from the wide wire to that end,
  along the outer edges, is ≥ 0.60.
- (b) **Violation.** Same shape, but the last vertical piece is *wider* than 0.28, so it is not a
  protrusion wire. The path stops where the narrow wires meet it, and that length is < 0.60:
  "length < 0.60 is measured among all protrusion wires with width < 0.28".
- (c) **Violation.** A narrow stub feeds a narrow T-bar: one arm < 0.60, the other arm ≥ 0.60. The
  rule takes the minimum: "length < 0.60 for shortest possible path".
- p.77: LENGTH 0 means "the length of the protrusion wire is irrelevant", which is what GPurify already does.

**Implementable?** Yes, as a derivation from the text and figures:
1. On layer L, take W = the open-by-width2 part (where a w2 square fits), and the narrow part N =
   L − (open-by-width1 of L).
2. Each connected component C of N that touches W is one protrusion.
3. Its root is C ∩ boundary(W). Its far ends are (i) open ends, meaning C's boundary not shared with
   other material, and (ii) contacts with L's non-narrow, non-W material (fig. b).
4. len(C) = min over far ends of the shortest path from the root to that end inside C, measured
   along C's boundary edges and taking the shorter side ("shortest outside edges"). For Manhattan
   wires a geodesic inside C hugging the inner corners gives the same value. Make this a deck switch
   (`boundary` vs `centerline`), because "outside edges" is ambiguous at bends.
5. Flag C if len(C) < LENGTH. With LENGTH 0, flag every C (the current rule).

A C with no far end, a closed loop between two W parts, is undefined in the text and should be
reported, not guessed.

- Parameters: w1, length, w2, and the path mode.
- Oracle: hand cases from Figure 1-16 with w1 = 0.28, L = 0.60, w2 = 1.20, and wire widths 0.20 for narrow, 2.0 for wide.
  - (c'): stub 0.20 × 0.20 above the wide wire, bar 0.20 thick, left arm 0.30, right arm 0.80.
    Paths: 0.20 + 0.30 = 0.50 and 0.20 + 0.80 = 1.00. min = 0.50 < 0.60: **violation**.
    Make the left arm 0.45 and min = 0.65: **clean**.
  - (b'): stub 0.20 tall, then a narrow horizontal 0.30, then a 0.40-wide block. Path
    0.50 < 0.60: **violation**. Make the block 0.20 wide and 0.30 tall with an open end, giving a path of
    0.80: **clean** (fig. a).
  - Straight stub of length 0.59: **violation**; 0.60: **clean** ("shorter than length").
- No reference tool exists: OR stores the rule (src/odb/src/lefin/lefin.cpp:1202-1203) and nothing
  reads it. A newer extended form `LEF58_PROTRUSIONWIDTH width1 {LENGTH length WIDTH width2 | WIDTH
  width2 {MINSIZE ... | MINLENGTH minLength [EXCEPTCUT ...]}...}` exists in Open-EDI's grammar comment
  (routing_layer_rule.h:1006-1021), also with no semantics.

**Checked, nothing found:**
- LEF/DEF 5.7 ref of Nov 2009 (ref57.txt:4666-4735, Example 1-10, pp.103-104): the same text and the same three cases as 5.8, numbered Figure 1-36 there; nothing more on LENGTH.
- Magic and Netgen sources (no "protrusion").
- OR odb/drt (store only).
- KLayout: no LEF rule checks.
- Coriolis, Limbo, OpenDP and Si2 parsers (parse only).
- GitHub code search "PROTRUSIONWIDTH" in *.lef (only Si2 complete.5.8.lef test copies plus the excluded kit LEF).
- IHP/GF180 repos via code search (no hits).
- Web searches (patents on wide-wire identification are unrelated).

## DRC-126: LEF58_KEEPOUTZONE: EXTENSION without ENDEXTENSION, SPIRALEXTENSION, EXCEPTEXACTALIGNED

**Verdict:** not found, with one new piece of public evidence: a BSD-licensed ASAP7 LEF using a fourth zone form.

**Definition / evidence:**
- Grammar (reading): `KEEPOUTZONE CUTCLASS c [TO c2] [EXCEPTEXACTALIGNED [SIDE|END] s]
  {EXTENSION side fwd | ENDEXTENSION es ef SIDEEXTENSION ss sf} SPIRALEXTENSION sp ;`.
  - SPIRALEXTENSION is mandatory in OR's parser (src/odb/src/lefin/KeepOutZoneParser.cpp:33-98).
  - The odb object also has SAMEMASK/SAMEMETAL/DIFFMETAL bits (schema
    tech/dbTechLayerKeepOutZoneRule.json) that the parser never sets.
- Consumer:
  - OR drt **skips** a rule with EXTENSION > 0 (DRT-327) or SPIRALEXTENSION > 0 (DRT-328), and
    ignores EXCEPTEXACTALIGNED (src/drt/src/io/io.cpp:2169-2214).
  - checKeepOutZone_main (src/drt/src/gc/FlexGC_cut.cpp:455-540) skips square cuts.
  - So OR checks only the END/SIDE form with spiral 0. The catalog wording "parses but never checks"
    should read "parses, then drops the whole rule".
  - PR #3168 (https://github.com/The-OpenROAD-Project/OpenROAD/pull/3168) says it was "needed in intel16".
    The only test is drt gcTest.cpp:1535-1564, END/SIDE 51, marker (150,150,200,200).
- **New:** The-OpenROAD-Project/asap7sc6t_26 `techlef_misc/asap7sc6t_tech_4x_210831.lef`
  (BSD-3, ASU, 4× scaled) has three keep-out rules:
  - V1, lines 163-169: `KEEPOUTZONE CUTCLASS V1A TO V1A EXCEPTEXACTALIGNED 0.072 HORIZONTALEXTENSION 0.092 0.092
    VERTICALEXTENSION 0.102 0.102 SPIRALEXTENSION 0.112`. V1A is a square class, 0.072.
  - V2, lines 268-274: `EXCEPTEXACTALIGNED SIDE 0.072 ENDEXTENSION 0.112 0.072 SIDEEXTENSION 0.072 0.112
    SPIRALEXTENSION 0.071`.
  - V3, lines 358-364: `CUTCLASS V3 EXCEPTEXACTALIGNED SIDE 0.071 HORIZONTALEXTENSION 0.071 0.071
    VERTICALEXTENSION 0.071 0.071 SPIRALEXTENSION 0.071`.
  - The HORIZONTALEXTENSION/VERTICALEXTENSION form is **not in OR's grammar**, so OR warns ODB-0388
    and drops those rules.
  - Derivation: it is the absolute-direction variant used for square (or near-square) cuts, where
    "end" and "side" are undefined. That fits OR refusing square vias.
  - Comparing values with the ASAP7 DRM (public, asap7_drm_201207a.pdf §3.13, Table 3.13.1):
    0.072/4 = 18 nm equals V1.S.1's aligned-case spacing ("[18 | 27 | 18]"), and 0.092/4 = 23 nm
    equals V1.S.2 corner-to-corner. That suggests EXCEPTEXACTALIGNED s means "exactly aligned cuts
    are exempt from the zone, down to spacing s", and the extensions encode corner-to-corner keep-outs.
  - 0.102 (25.5 nm) and the spiral 0.112 (28 nm) match no DRM value, so the mapping is only partial.
    This is a derivation, not a definition.
- "SPIRALEXTENSION": no public text. Derivation from the name: a pinwheel-shaped zone, each side's
  extension rotated around the cut. It cannot be pinned down.

**Implementable?**
- EXCEPTEXACTALIGNED, as a derivation: exempt a pair whose facing cut edges are exactly aligned
  (same span on the parallel axis), and whose spacing is ≥ s, measured on the SIDE or END direction
  when given. This can be tested only by hand. No reference tool implements it.
- EXTENSION (single pair) and HORIZONTAL/VERTICALEXTENSION: a plausible reading is the END/SIDE zones
  with equal values, or absolute x/y bloats, but no text says so.
- SPIRALEXTENSION: no.

Keep the current refusal. If anything, add a parser for the HORIZONTALEXTENSION/VERTICALEXTENSION
form so that it is refused explicitly rather than misparsed.

**Checked, nothing found:**
- ref.txt, and the ISPD-hosted LEF/DEF 5.7 ref of Nov 2009 (ref57.txt): no KEEPOUTZONE, SPIRAL, HORIZONTALEXTENSION or EXCEPTEXACTALIGNED.
- OR odb/drt/tests and PR #3168; issue #3140.
- Open-EDI (KeepOutZone class commented out, cut_layer_rule.h:82).
- iEDA (no KEEPOUTZONE).
- GitHub code search "KEEPOUTZONE"/"SPIRALEXTENSION"/"HORIZONTALEXTENSION" (only OR forks and the ASAP7 6T LEF).
- Web and patent searches ("keep-out zone" via spiral; only TSV KOZ and cut-mask patents US9418196/US9754073, unrelated).

## DRC-130: Shape must contain a rectangle of a given size (ENCLOSE RECTANGLE)

**Verdict:** not found beyond the existing definition. One addition: a
foundry-authored open deck codes a "contains a square" check by the same
under/oversize emulation.

**Definition / reading:**
- The KLayout DRC built-ins (KLayout@4d927b79
  `src/drc/drc/built-in-macros/_drc_layer.rb`, `@name` list at :348–1008,
  :3205–3248) have no native "fits a rectangle" op. They have only
  `with_bbox_*`, `rectangles`, `squares`, `non_rectangles` and similar.
- GF180 is new evidence. The foundry deck
  fossi-foundation/globalfoundries-pdk-libs-gf180mcu_fd_pv@b390a163
  `klayout/drc/rule_decks/mslot.rb:51,66` codes MSLOT.1 ("Maximum metal width
  without slotting: 30µm") as
  `sized(0,-15.um).sized(-15.um,0).sized(0,15.um).sized(15.um,0)`. That is a
  morphological opening by a 30 × 30 square, which means "a 30 × 30 square
  fits". It is the forum-2141 emulation in a GF-authored (Apache-2.0) deck.
- aesc-silicon/gdscheck@dee4df85 `hardening/reports/gf180mcuD/mslot.md`,
  "Notes", confirms this reading by test: 30 × 30 clean, 30.005 × 30.005
  fires, 40 × 20 clean, an L of two 40 × 20 arms clean.

**Implementable?** Already implemented. The GF MSLOT.1 cases above are a
second oracle for the square case. Boundary behaviour is "exactly w × h
fits, so the shape is selected": 30 × 30 does not fire.

**Checked, nothing found:**
- Siemens public pages (training course pages only).
- A web search for the "ENCLOSE RECTANGLE" SVRF syntax. It returned only
  Scribd-hosted Calibre manuals, which were not used.
- GitHub code search for "ENCLOSE RECTANGLE". The hits are foundry Calibre
  decks posted in student repos, of unclear licence, so they were not read
  or cited.
- Patents: none of the USPTO PDFs read in pass 2 (listed under DRC-128)
  concern ENCLOSE RECTANGLE.

## DRC-020: LEF58_MINSTEP qualifiers

**Verdict:** found for MINADJACENTLENGTH CONVEXCORNER, for MINADJACENTLENGTH with a second length, and for MINBETWEENLENGTH with EXCEPTSAMECORNERS. Partial for NOADJACENTEOL alone (a reading). Not found for CONCAVECORNER.

**Definition** ([LEF57] pp. 161-166, "Minimum Step Rules"; syntax also on p. 80):

- Syntax:
  ```
  PROPERTY LEF58_MINSTEP "MINSTEP minStepLength [MAXEDGES maxEdges]
    [ MINADJACENTLENGTH minAdjLength [CONVEXCORNER | minAdjLength2]
    | MINBETWEENLENGTH minBetweenLength [EXCEPTSAMECORNERS] ] ;..."
  ```
- MINADJACENTLENGTH (p. 161): "the edges adjacent to min-step edges that are less than minStepLength must be greater than or equal to minAdjLength … If minAdjLength2 is specified, then one adjacent edge must be ≥ minAdjLength and the other adjacent edge must be ≥ minAdjLength2."
- CONVEXCORNER (p. 161): "if a convex corner is between two concave corners, and if one of the length of the edges to form the convex corner is less than minAdjLength, then the other length must be greater than or equal to minStepLength."
- MINBETWEENLENGTH (p. 161): "one of the edges between min-step edges that are less than MinStepLength must be greater than or equal to minBetweenLength."
- EXCEPTSAMECORNERS (p. 162): "a minBetweenLength length is not required for an edge that has the same type of 90-degree corner at each end (that is, both corners are convex, or both are concave)." Fig. 1-66 shows thick same-corner edges and thin "stair-step" edges.
- Worked figures:
  - Fig. 1-68 (`MINSTEP 0.6 MAXEDGES 1 MINADJACENTLENGTH 1.0`).
  - Fig. 1-69 (`… MINADJACENTLENGTH 1.0 1.2`): a 0.5 step with adjacent edges 1.2 and 0.8 violates; 1.2 and 1.0 is OK; 1.1 and 1.0 violates.
  - Fig. 1-70 (CONVEXCORNER).
  - Fig. 1-71 (MINBETWEENLENGTH 1.0).
- The Si2 parser [OR] src/odb/src/lef/lef/lefiLayer.cpp:5883-5960 (`parseMinstep`) validates the same syntax for the LEF57_MINSTEP property.

**Readings:**

- iEDA RV MinStep.cpp ("case 2", ieda/MinStep.cpp:107-125) checks exactly the CONVEXCORNER text.
  - Condition: a vertex is convex, both neighbouring vertices are concave, and `(e_in < minStep && e_out < minAdj) || (e_in < minAdj && e_out < minStep)`.
  - Caveat: iEDA applies it whenever LEF58_MINSTEP has MINADJACENTLENGTH, regardless of the CONVEXCORNER keyword (DRCInterface.cpp:561-576 copies only min_step and min_adj_length).
- TritonRoute ([OR] FlexGC_main.cpp:1808-1897; io.cpp:1660-1678):
  - Plain MINADJACENTLENGTH: a min-step edge is flagged if either adjacent edge is shorter than minAdj.
  - NOADJACENTEOL: a min-step edge is also flagged if an adjacent edge has both corners convex and is shorter than eolWidth. This is only evaluated when MINADJACENTLENGTH is present (1891).
  - Not checked: CONVEXCORNER, minAdjLength2 and MINBETWEENLENGTH. MAXEDGES > 1 is dropped (DRT-335).

**Implementable?** Yes, for CONVEXCORNER, the second length and MINBETWEENLENGTH/EXCEPTSAMECORNERS. The sketches walk the boundary of each merged polygon.

- **Plain MINADJACENTLENGTH:** for every edge e shorter than minStep, flag if either neighbour is shorter than minAdj.
- **With minAdjLength2:** flag unless `max(adj) >= max(L1,L2) && min(adj) >= min(L1,L2)`.
- **CONVEXCORNER:** it *replaces* the plain check. Fig. 1-70 c, a 0.5-wide tab with 0.8 shoulders, is "OK" although the plain rule would flag it.
  - For every convex vertex whose two neighbouring vertices are concave, take its two edges a and b.
  - Flag if `(a < minAdj && b < minStep) || (b < minAdj && a < minStep)`.
- **MINBETWEENLENGTH:**
  - For each pair of successive short edges (< minStep) along the boundary, look at the edges strictly between them.
  - Flag if none is ≥ minBetween. Two adjacent short edges, with nothing between, are flagged (Fig. 1-71 f).
  - With EXCEPTSAMECORNERS, between-edges with the same corner type at both ends are exempt. My reading: no violation if every between-edge that is shorter than minBetween is same-cornered. The text is unambiguous only for a single between-edge.
- Oracle, from [LEF57] figures with the stated verdicts:
  - Fig. 1-70: (a) edges 0.4 and 0.8 at a convex corner between two concave corners violate; (b) 0.5 and 0.9 with the corner not between two concave corners is OK; (c) the tab is OK.
  - Fig. 1-71 (MINBETWEENLENGTH 1.0): (a), (b) and (e) are OK; (c) two 0.5 edges separated by a 0.8 same-corner edge violate; (d) the same shape is OK with EXCEPTSAMECORNERS; (f) violates.
  - Fig. 1-69 as quoted above.
  - Differential: iEDA iDRC for CONVEXCORNER (`run_iDRC.tcl` flow in iEDA scripts/design/*/script/iDRC_script). Add a plain MINSTEP to the LEF, because iEDA needs both rules.
- **NOADJACENTEOL without MINADJACENTLENGTH (a reading):** use TritonRoute's NOADJACENTEOL branch alone. Flag an edge shorter than minStep that is adjacent to an edge with both corners convex and shorter than eolWidth.

**Checked, nothing found** for CONCAVECORNER, and for the other keywords in iEDA's grammar (THREECONCAVECORNERS, CENTERWIDTH, EXCEPTWITHIN, EXCEPTADJACENTLENGTH, CONCAVECORNERS, ieda/routinglayer_property_parser.h:100-115). That grammar shows a newer LEF58_MINSTEP syntax than [LEF57], but no public text defines it.

- Searched: [LEF57], [LEF58], coriolis HTML.
- iEDA: parsed, but only case 1/case 2 are checked.
- [OR]: parsed, never checked.
- GitHub code search `"MINADJACENTLENGTH" "CONCAVECORNER"`: no tech LEFs; only OpenROAD test LEFs (gscl45nm.lef:160-163).
- "NOADJACENTEOL": only odb parser forks.

## DRC-027: Negative PRL in a two-widths / PARALLELRUNLENGTH table

**Verdict:** partial. There is a public reading (figure plus code), but no defining text.

**Definition:**

- [LEF58] p. 94: "The PRL values in SPACINGTABLE TWOWIDTHS statement can be negative, which should be interpreted in the same way as in SPACINGTABLE PARLLELRUNLENGTH rules." The PARALLELRUNLENGTH text never mentions negative values.
- The [LEF57] TWOWIDTHS text (p. 80 syntax) adds nothing.
- ISPD19 intro (p. 2) explicitly restricts its contest to "non-negative values".
- The meaning of a negative PRL comes from [WXL] Fig. 7 (b), p. 5: PRL < 0 is the projection gap, and spacing is measured corner to corner.

**Reading:**

- TritonRoute computes a signed PRL ([OR] src/drt/src/gc/FlexGC_main.cpp:843-893): `prlX`/`prlY` = intersection extent, negated on an axis where the rectangles are separated; prl = `max(prlX, prlY)`.
  - Rectangles side by side get the positive overlap.
  - Rectangles diagonal to each other get −(the smaller of the two gaps).
- The PARALLELRUNLENGTH lookup (src/drt/src/db/tech/frLookupTbl.h:191-202) picks the last column whose length is strictly below the PRL, i.e. "prl > length", as the LEF text has it.
- TWOWIDTHS (src/drt/src/db/tech/frConstraint.h:1290-1301) picks row i when width > row width and prl > row PRL.
- Storage of negative values in odb:
  - V55 lengths are `uint32_t` (src/odb/src/db/dbTechLayer.h:162). A negative length wraps and comes back as the same int in drt's `frCoord` table.
  - TWOWIDTHS PRLs are `int` (dbTechLayer.h:167), but -1 dbu is the "no PRL" sentinel (src/odb/src/lefin/lefin.cpp:998-1002; dbTechLayer.cpp:1632-1636). So PRL = -1 dbu is mis-read, and `getTwoWidthsSpacingTableHasPRL` reports false for every negative PRL.
  - So TritonRoute does carry negative PRLs, with those two caveats. "Clamps to 0" applies to iEDA (getParallelLength uses max(0, …), ieda/Utility.hpp:59-64). Please re-check the catalog note against this.
- Also note: TritonRoute's comparison is strict (>), like LEF's.
  - iEDA's `getSpacing` (ieda/ParallelRunLengthSpacingRule.hpp:30-46) uses `length <= prl`, i.e. ≥, with the PRL clamped to 0.
  - iEDA measures Euclidean distance between maximal rectangles of different nets.

**Implementable?** Yes, as a reading: signed PRL as in TritonRoute or WXL, columns chosen by strict >, Euclidean spacing.

- Ambiguity to record: for a diagonal pair, TritonRoute's |prl| is the *smaller* gap. WXL's figure measures the gap along the run direction. They differ only when the cross-run gap is the smaller one.
- Oracle: `SPACINGTABLE PARALLELRUNLENGTH -0.2 -0.05 0.5 WIDTH 0 0.10 0.12 0.15`. Note that a negative *first* column changes nothing, because the first column always applies.
  - Two min-width horizontal wires, corner to corner, run gap 0.10 and cross gap 0.06. The signed PRL is -0.06 (TritonRoute) or -0.10 (WXL); either is ≤ -0.05, so the column is 0.10. The distance √(0.1²+0.06²) = 0.117 passes.
  - The clamp-to-0 reading (iEDA) gives column 0.12, which is a **violation**. This is the distinguishing case.
  - With run gap 0.03 and cross gap 0.10: prl = -0.03 > -0.05, so 0.12 applies; the distance is 0.104, so a violation in every reading.
- Differential: OpenROAD `detailed_route` / `check_drc` on these two shapes; avoid exactly -1 dbu.

**Checked, nothing found:**

- [LEF57], [LEF58], coriolis HTML, ISPD19 intro.
- Cadence patent US 10,685,164 B1 (PRL-based routing blockages). Columns 3-4 read, nothing about negative PRL. The rest is image-only and Google Patents was rate-limited (HTTP 503), so the remaining columns are unread.
- GitHub code search `"PARALLELRUNLENGTH -0"`: no hits.

## DRC-034: Maximum spacing (LEF58_MAXSPACING)

**Verdict:** needs fetch. No new public definition, and the only text I found is in a vendor-doc mirror I did not use.

**Definition:**

- [LEF58] and [LEF57] do not contain MAXSPACING.
- The syntax `MAXSPACING spacing [CUTCLASS className]` appears in an OpenROAD test LEF ([OR] src/odb/test/data/gscl45nm.lef:121-122, `MAXSPACING 2 CUTCLASS VA`) and in the odb schema (src/odb/src/codeGenerator/schema/tech/dbTechLayerMaxSpacingRule.json: `cut_class_`, `max_spacing_`, no descriptions).
- A related public concept: US 6,804,808 B2 (Sun Microsystems), redundant-via check, claim 25 (col. 13, ll. 1-3): vias "within the given wi connection area are located no farther apart than a respective maximum distance". That is a per-wide-wire redundant-via rule, not LEF58_MAXSPACING.

**Reading:** unchanged from the catalog ([OR] src/drt/src/dr/FlexDR.cpp:1954 `fixMaxSpacing` / `getLonelyVias`).

- Without CUTCLASS, the rule is dropped (io.cpp:2311-2318, DRT-350).
- io_parser_helper.cpp:256-268 uses it to choose secondary vias.
- iEDA has no max-spacing rule.

**Implementable?** As already in the catalog (OpenROAD reading only).

**Checked, nothing found:**

- [LEF57], [LEF58], coriolis HTML, libresilicon lef.md.
- iEDA (parser and iDRC).
- GitHub code search `"LEF58_MAXSPACING"`: only OpenROAD forks.
- WebSearch for MAXSPACING definitions: the only hit was the appspot mirror, not used.
- WebSearch for "isolated via" / "maximum spacing" patents: Sun US6804808, tangential.

## DRC-042: End-cap enclosure (LEF58_ENCLOSURE EOL)

**Verdict:** partial. There are two public readings, but no defining text.

**Definition:**

- [LEF57] p. 47 gives LEF58_ENCLOSURE without EOL (`ENCLOSURE [CUTCLASS c][ABOVE|BELOW] {o1 o2 | END o1 SIDE o2} [WIDTH … | LENGTH …] | EXTRACUT | REDUNDANTCUT …`). It does define END/SIDE ("overhang1 applies to the end edges, and overhang2 applies to the side edges" of rectangular cuts), but not EOL.
- EOL grammar: [OR] src/odb/src/lefin/lefTechLayerCutEnclosureParser.cpp:62-150: `EOL eolWidth [MINLENGTH l] [EOLONLY] [SHORTEDGEONEOL] eolOverhang otherOverhang [SIDESPACING s EXTENSION b f | ENDSPACING s EXTENSION e]`.
- GF patent [GF] col. 22, ll. 8-38 describes a "complex multicut enclosure rule" whose enclosures "depend on their location in relation to the end 1807 of the metal line". This is a concept, with no measures.

**Readings:**

- TritonRoute via generation ([OR] src/drt/src/io/io_parser_helper.cpp:217-251, `getBloatingDist`):
  - It applies only to EOLONLY rules.
  - If the metal's narrow dimension is ≤ eolWidth, then eolOverhang applies toward the line ends (along the metal's long axis) and otherOverhang toward the sides.
  - The checker never queries EOL rules: `getLef58EnclosureConstraints(..., eol=false)` is the default (src/drt/src/db/tech/frLayer.h:820-860; FlexGC_cut.cpp:700-705).
  - SIDESPACING and ENDSPACING are dropped (io.cpp:2217-2224, DRT-340).
- iEDA reads the sibling property **LEF58_EOLENCLOSURE** (`EOLENCLOSURE eolWidth [MINEOLWIDTH] [HORIZONTAL|VERTICAL] [EQUALRECTWIDTH] [CUTCLASS c] [ABOVE|BELOW] {LONGEDGEONLY|SHORTEDGEONLY ov | ov [ov2] [PARALLELEDGE s] [EXTENSION b [f]] [MINLENGTH l] [ALLSIDES]}`, ieda/cutlayer_property_parser.h:118-129) and checks it in ieda/EnclosureParallel.cpp:17-267:
  - It finds cut sides whose metal overhang is less than `overhang`, and requires that side to lie on an EOL edge: both corners convex and length < eolWidth.
  - With MINLENGTH, it skips the edge if both adjacent edges are shorter than minLength.
  - It flags if another metal shape lies inside a PARALLELEDGE window beside the EOL (width = parSpace − eolLength, along = backward/forward EXTENSION).
  - Note that iEDA's `verifyEnclosure` (plain enclosure) is empty (ieda/Enclosure.cpp).

**Implementable?** Partly, as a reading.

- Sketch (TritonRoute convention, EOLONLY):
  - For each cut and its enclosing metal rectangle on the ABOVE/BELOW layer, find the metal's long axis.
  - If the metal width ≤ eolWidth, require overhang ≥ eolOverhang toward both line ends and ≥ otherOverhang toward both sides.
  - Without EOLONLY, the semantics are unknown. A derivation would be: the EOL pair applies when the cut's side lies on an EOL edge (iEDA's EOL-edge test).
- Oracle: cut 0.05×0.05 in a vertical wire 0.05 wide, rule `EOL 0.06 EOLONLY 0.03 0.0`.
  - Overhang toward the wire end 0.02: violation.
  - 0.03: OK.
  - A wire 0.08 wide (> eolWidth): rule not applied.
  - No reference tool reports it. TritonRoute only bloats generated vias, so a differential is possible only indirectly, by inspecting via shapes after `detailed_route`.

**Checked, nothing found:**

- [LEF57], [LEF58], coriolis HTML.
- [OR] GC.
- iEDA LEF58_ENCLOSURE handling (EnclosureEdge only, convex-corner variant skipped, DRCInterface.cpp:678-698).
- WebSearch for EOLONLY / SHORTEDGEONEOL: no definitions.
- GitHub code search `"LEF58_ENCLOSURE" "EOL"`: only OpenROAD test data (gt2_tech.lef, asap7: `ENCLOSURE CUTCLASS Vx EOL 0.0 0.011 0.011`).

## DRC-075: GF180 MSLOT.4b (slot space, maximum 30 µm)

**Verdict:** partial. The figure shows which spacing is meant: between slots
side by side across the metal width. "Which slots" is still not stated in
words.

**Definition:**
- GF180MCU DRM §14.6.3 "Metal Slotting rules",
  https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_manual/drm_14_6_3.html:
  - "These layers will be used to create the slots automatically (by logic
    operation) and there is no need to create physical holes".
  - "MSLOT.4 Slot space (slot mark layers) Minimum 10 Maximum 30".
  - "MSLOT.6 For multiple slots that spans the metal width, slots should be
    staggered".
- The figure `_images/Metal_Slotting.png` draws the MSLOT.4 arrow vertically
  between two slots stacked across the plate's width: facing long edges,
  with full projection overlap. MSLOT.3 is the slot length and MSLOT.2 the
  slot width.

**Readings:**
- The GF deck (fd_pv@b390a163 `mslot.rb:84-87`) has the minimum only:
  `metal_slot_rectangles.drc(space < 10.um)`.
- GF's own slot generator,
  fossi-foundation/globalfoundries-pdk-libs-gf180mcu_fd_pr@4e132a23
  `cells/klayout/scripts/slots.drc:78,92`, is commented "MSLOT.4: Slot space:
  10um to 30um". It places 2 × 10 slots at 10 µm space with rows offset by half a
  slot (`hstep(slot_width + slot_space, slot_height/2)`), which is the
  stagger of MSLOT.6, at the 10 µm margin. It is a construction, not a check.
- aesc-silicon/gdscheck@dee4df85 `hardening/reports/gf180mcuD/mslot.md`,
  Finding 1, reads the maximum pairwise:
  - "two 54 x 30 µm plates, each with two legal 2 x 10 µm marks: 30.0 µm
    apart in the first and 30.005 in the second … The case expects one
    MSLOT1.4".
  - It argues that MSLOT.1 cannot stand in, because the plate is only 30
    tall.
- Magic (open_pdks `gf180mcu/magic/gf180mcu.tech`) has no MSLOT rules, only
  fill `slots`.

**Implementable?** Yes, under a stated reading (derivation from the figure and
the gdscheck reading): on the same metal polygon, for each slot rectangle and
each of its long edges, take the nearest other slot whose facing edge has
positive projection overlap (no third slot between them). Flag the pair if
the gap is greater than 30 µm.
- Optional: also check the short-edge (end-to-end) direction. Leave it off by
  default, since the figure shows only the across-width spacing.
- Slots without a facing neighbour are not checked. MSLOT.1 on (metal −
  slots), which GF's deck already does at `mslot.rb:52,66`, covers unrelieved
  plate area.

Oracle (gdscheck MSLOT.space.h3): plate 54 × 30, two 2 × 10 marks,
- 30.0 apart → clean;
- 30.005 apart → 1 violation;
- a single slot on a plate → no MSLOT.4.

**Still undefined:**
- Whether the maximum also binds end to end (along the slot length).
- Whether it binds diagonally between staggered rows.
- How it interacts with MSLOT.6.

**Checked, nothing found:**
- The DRM rst and figure.
- The GF fd_pv and fd_pr decks and scripts.
- The magic gf180mcu tech file.
- GitHub code search for "MSLOT.4". Every other hit copies fd_pv's
  min-only coding.

## DRC-102: PARALLELSAMEMASK and same/different-mask spacing

**Verdict:** partial. The grammar position is known and there is a patent concept, but no definition. The SAMEMASK spacing options remain undefined.

**Definition:**

- PARALLELSAMEMASK is the last keyword of the PARALLELEDGE clause of LEF58_SPACING ENDOFLINE: `PARALLELEDGE [SUBTRACTEOLWIDTH] parSpace WITHIN parWithin [PRL p] [MINLENGTH l] [TWOEDGES] [SAMEMETAL] [NONEOLCORNERONLY] [PARALLELSAMEMASK]`.
  - Sources: [OR] src/odb/src/lefin/lefTechLayerSpacingEolParser.cpp:369-374; the same in iEDA ieda/routinglayer_property_parser.h:160-166; `SAMEMASK` is a separate rule-level flag (ibid. 182).
- [LEF57] p. 80 has the older PARALLELEDGE (`[SUBTRACTEOLWIDTH] parSpace WITHIN parWithin [MINLENGTH] [TWOEDGES]`) without mask options.
- The PARALLELEDGE window is defined publicly in the ISPD19 intro, p. 2: "the EOL rule is applied only if there is a parallel-edge less than parSpace away that is also less than parWithin from the end of the wire … The PARALLELEDGE search window is constructed by extending from the corner with EOL edge sideward by parSpace, extending forward by eolWithin, and extending backward by parWithin."
- Patent concept, [GF] col. 22, l. 56 – col. 23, l. 10: a "dense end of line same mask spacing rule". The spacing 1917 from the end 1919 of line 1902 to the perpendicular line 1904 must exceed a minimum. It "may need to be applied only if metal lines 1901, 1902, 1903, 1904 are formed using the same photomask, and only if … the spacings between the edges 1908, 1909 of the metal lines 1901, 1903 and the metal line 1902 is within a range … and on whether widths 1916, 1918 … are smaller than a threshold … [and] an extension of the edges 1908, 1909 is within a range". In other words, an EOL rule triggered by parallel neighbours, gated on those neighbours sharing the EOL line's mask.

**Reading:**

- TritonRoute stores the flag (io.cpp:1595-1596 → frConstraint.h:568, 589) and no GC code reads it.
- No drt GC file mentions a mask at all (grep "mask" in src/drt/src/gc: empty).
- iEDA parses it and never uses it.

**Implementable?** As a derivation only.

- Sketch: run the PARALLELEDGE trigger as in the ISPD19 window, but count a parallel edge only if its shape's MASK equals the EOL shape's MASK. Uncoloured shapes need a convention.
- Oracle (derived): rule `SPACING 0.07 ENDOFLINE 0.05 WITHIN 0.02 PARALLELEDGE 0.06 WITHIN 0.1 PARALLELSAMEMASK`; EOL wire on mask 1, with a neighbour 0.04 to the side of the EOL and a facing wire 0.06 beyond the end.
  - Neighbour on mask 1: the rule is triggered, and 0.06 < 0.07 is a violation.
  - Neighbour on mask 2: not triggered, OK.
  - No reference tool.

**Checked, nothing found** for PARALLELSAMEMASK or for SAMEMASK in LEF58_SPACING, LEF58_SPACINGTABLE and LEF58_CORNERSPACING:

- [LEF57] and [LEF58]: no "SAMEMASK" outside DEF TRACKS, ref.txt:13662-13716.
- Coriolis HTML, Si2 lefiLayer.cpp (no mask spacing).
- [OR] drt GC, iEDA iDRC, KLayout LEF importer.
- GitHub code search "PARALLELSAMEMASK": only OpenROAD/TritonRoute forks, iEDA/ecc-tools and lbz007/rectanglequery (a parser).
- Patents beyond [GF]: US20130080980A1 / US9594866B2 (TSMC double-patterning check) were listed by search but not read, because Google Patents was rate-limited.

## DRC-103: Stitch legality

**Verdict:** partial, close to found. The line-end and corner bans are public
(a vendor article with a figure). The via ban is public only in the sense
"no stitches on via or contact layers", not "no stitch on a metal over a via".

**Definition:**
- D. Abercrombie (Mentor), "To Cut or Not To Cut? That is the Double
  Patterning Question", Semiconductor Engineering, Dec 2011.
  https://semiengineering.com/cut-cut-double-patterning-question/ (the live
  site returned 522; the archived copy is at
  `web.archive.org/web/2016id_/https://semiengineering.com/cut-cut-double-patterning-question/`).
  - Stitch definition: "the two pieces of the polygon must be overlapped at
    the cut location to allow for lithographic rounding and misalignment …
    This overlap of each color at a cut location is called a 'stitch.'"
  - Legality: "The added stitch cannot introduce new DRC violations. In other
    words, the two polygons that are created from the original single
    polygon must both meet all DRC requirements."
  - Fig. 4 (`wp-content/uploads/2011/12/4.gif`) builds "Allowed Cut Regions"
    by removing three kinds of region from the polygon:
    - **Spacing Constraints**: the parts of a polygon facing a neighbour
      within the DP distance, shown as red end/side pieces and blue
      wedge-shaped corner regions.
    - **Min Area Constraints**: orange pieces at every line end. A cut there
      would leave a piece below min area. This is the line-end ban.
    - **Corner Constraints**: a red square at an L bend. This is the corner
      ban.

    It then applies **Minimum Stitch Length Constraints**: an allowed region
    too short to hold the stitch is dropped, which gives "Final Stitch
    Candidates".
- Kahng, Park, Xu, Yao, "Layout Decomposition for Double Patterning
  Lithography", ICCAD 2008, pp. 465–472, open copy
  https://vlsicad.ucsd.edu/Publications/Conferences/250/c250.pdf, §3.4
  (rule-based node splitting). A node may be split if:
  - "(i) the horizontal (vertical) merged projections … are separable";
  - "(ii) the resulting overlap lengths … are not less than the given
    overlap margin";
  - "(iii) there are no design rule violations after splitting".

  The rule adds: "The dividing point may be chosen in between the merged
  projections such that no merged projections are cut", and "two features of
  the same color cannot be extended such that the distance between them is
  less than the minimum coloring spacing t". In other words, a stitch may not
  lie inside the projection of a conflicting neighbour.
- Yu, Yuan, Ding, Pan, "Layout Decomposition for Triple Patterning
  Lithography", IEEE TCAD 34(3), 2015, open copy
  https://www.cse.cuhk.edu.hk/~byu/papers/J07-TCAD2015-TPLD.pdf, §III.A:
  "In DPL, the stitch candidate has one precondition: it cannot intersect
  with any projection" (citing Kahng 2008). It also gives a projection-
  sequence rule for TPL "lost" and redundant stitches.
- Yuan, Yang, Pan, IEEE TCAD 29(2), 2010, open copy
  https://www.cerc.utexas.edu/utda/publications/tcad_kun_dpl.pdf, §II.A: "there
  is a minimum overlap length, minol, requirement for stitch insertion … we do
  not want to have any minimum width, minwi, rule violation during
  splitting".
- Via and contact layers: Ban et al. DAC 2011 (above) and Xu et al. 2015
  state that SADP allows no stitch at all. Several MPL papers state that
  stitching is forbidden on contact and via layers. No public text bans a
  metal stitch over a via landing.

**Implementable?** Yes, as a candidate-region construction. For a feature F
on a DP layer, the allowed stitch region is built as follows:
1. Take F.
2. Remove the projections onto F of every same-layer feature within the
   colouring distance (Kahng's (i)).
3. Remove line-end zones of length ℓ_end = A_min/w, so that each piece keeps
   the min area (Abercrombie's Min Area). Also remove any zone that would
   leave a piece narrower than min width.
4. Remove the corner squares at bends (w × w at each convex/concave vertex
   pair of an L or T).

The allowed regions must also be at least `stitch_overlap_min` long
(Min Stitch Length).

Check: every drawn stitch (the overlap of the c1 and c2 pieces of one
original polygon) must lie inside an allowed region, must have overlap ≥
`minol`, and both pieces must pass all single-mask rules. That last part is
the existing `space(...)` and overlap checks in the catalog note.

On cut layers (via, contact), any stitch is illegal: a feature split across
masks is flagged.

Deck parameters: `min_coloring_space`, `stitch_overlap_min`, `min_area`,
`min_width`, `corner_ban: true`, `stitch_layers` (metal only).

Oracle (derived from Fig. 4): a straight wire with a neighbour projecting
onto its middle. Allowed regions are the two segments between the
projection and the line-end zones. A stitch inside the projection is
flagged, a stitch at the line end is flagged, a stitch at an L corner is
flagged, and a stitch in an allowed region shorter than the overlap is
flagged.

**LEF/DEF 5.7 (pass 2):**
- LEF/DEF 5.7 (Nov 2009, ISPD-hosted, [LEF57]). Grepped for TRIMMETAL, TRIMMEDMETAL, TRIMPOLY, MANDREL, SADP, self-aligned, SAMEMASK, MASK, stitch, patterning and color: 0 hits, apart from two unrelated "mask creation/generation" lines (:4430, :11284). It predates the multi-patterning constructs. Its LEF58_TYPE is only TSV/PASSIVATION and NWELL/PWELL, and its LEF58_AREA has no LAYER/OVERLAP clause.

**Checked, nothing found:** a public rule banning a stitch on metal over a
via. Searched Google, the semiengineering series, and the Kahng 2008 and
2008-SPIE ("Revisiting…", c248.pdf) papers, which mention only line-end
count and jog minimisation.

## DRC-105: Trim / cut-metal layers (LEF58_TYPE TRIMMETAL, LEF58_TRIMMEDMETAL)

**Verdict:** partial, but the generic trim-mask rule set is now found. A
Cadence patent states four trim-mask rules with figures. Only the vendor
LEF58 `LAYER <trim> OVERLAP n` clauses remain undefined.

**Definition (added by the patent pass):**
- US 9,087,174 B1 (Cadence; filed 2013-03-15), col. 15 l. 29–42, FIG. 7B
  (sheet 10), "exemplary multi-exposure trim mask rules":
  - "702B illustrates the trim mask minimum width rule where 710B
    represents the minimum spacing between two interconnects". That is the
    on-track end-to-end gap, whose bound is the trim minimum width.
  - "704B illustrates the minimum area rule that requires a minimum length
    716B".
  - "706B represents the trim mask spacing rule that requires two
    neighboring interconnects running in opposite direction to have a
    minimum overlapping distance 714B".
  - "708B represents the trim mask minimum step rule that requires two
    neighboring interconnects running in the same direction to have a step
    having a minimum step of 712B".

  Worked values at l. 43–56:
  - 714B "to be greater than +130-nm or smaller than −60-nm", which is a
    forbidden interval: either an overlap ≥ 130 or a gap ≥ 60.
  - 708B "minimum spacing of zero or greater 100-nm".

  Col. 1 l. 37–40 (Background) adds: "the traditional gridded physical
  implementation … fails to accommodate the trim mask rules".
- US 11,829,697 B2 (IBM; filed 2021-08-06), col. 4 l. 3–7 and l. 22–34:
  - "set a minimum trim spacing to be the larger of the minimum same-track
    spacing for the track that includes the selected extent and the minimum
    trim spacing across different tracks".
  - "In SADP fabrication technologies, the min_trim_spacing may be the
    minimum trim distance … exemplary values being between about 20 nm and
    about 500 nm".
  - It names `min_trim_spacing` (along the track) and
    `min_difftrack_spacing` (across tracks).
- US 11,983,476 B2 (IBM), col. 5 l. 36–52, lists the line-end constraints
  as five items:
  1. "a minimal length Dl";
  2. "a minimal area Da";
  3. "a minimal distance (separation) Ds between line ends";
  4. "a minimal spacing Do between opposite direction neighboring track
     shapes";
  5. "an exclusion (dead) zone … Dt … greater than Dn+Dz or less than Dn"
     for same-direction ends.

  These are the same four rule shapes as Cadence 702B–708B and Xu Rules
  0–4.

**Implementable (updated):** Yes, as a line-end rule set on SADP metal, or
as trim width and space where TRIMMETAL shapes are drawn.
- `on_track_end_gap ≥ a`.
- `min_length ≥ A_min/w`.
- Opposite-facing ends on adjacent tracks: forbid an overlap in
  `(−gap_min, overlap_min)`.
- Same-facing ends on adjacent tracks: forbid a step in `(0, step_min)`.

Oracle, from the Cadence values on adjacent tracks:
- Opposite-facing ends overlapping 100 → violation; 130 → clean.
- Opposite-facing ends 50 apart → violation; 60 apart → clean.
- Same-facing step 0 → clean; 40 → violation; 100 → clean.

**Earlier findings (still valid):**

**Definition:**
- LEF/DEF 5.8 Language Reference (May 2017).
  - p. 47, TRIMMETAL: "used to 'trim' or 'cut' or 'block' the self-aligned
    metal lines … These shapes could be pre-defined in macros/cells or added
    at the line-end of a wires during routing. There are additional rules in
    cut and metal layers to define constraints to those shapes on a
    TRIMMETAL layer."
  - p. 48: the TRIMMEDMETAL mask pairing ("MASK 1 of TM1 trims MASK 1 of
    M1…").
  - pp. 248–249: trim shapes are written in DEF FILLS with `+ MASK`.
  - pp. 320–321: "Signoff DRC tools may require metal shapes under the trim
    metal shapes to fill up the gaps between the line-end of wires
    sandwiched by the trim metal shape" (`_TRIMMETAL_FILLS_RESERVED`).
  - pp. 320–321: "As trim metal shapes need to be aligned and merged, dummy
    patches are often added even on OBS and unconnected pins"
    (`_SADP_FILLS_RESERVED`).
- US 10,726,187 B2 (IBM; Pandey, Tellez, Gao; priority 2018-09-27),
  "Self-aligned double patterning-aware routing in chip manufacturing".
  - [0013]: "The placement of these trim shapes must consider design rules
    such as, for example, the minimum distance between adjacent trim shapes
    on the same track or on adjacent tracks".
  - [0014]: extents are "metal extensions between the active metal and trim
    shapes".
  - [0025]: two trims "can be merged into a single node … if the minimum
    distance between their lateral positions … is not feasible". So two
    trim shapes must be either at least the minimum distance apart or merged.
- Xu et al. TCAD 2015 (DRC-128): the trim mask's minResistWidth w_r,
  minResistSpace s_r and etch bias w_e map to metal line-end rules 1–4.

**Reading (OpenROAD@3549d605):**
- `src/odb/src/lefin/lefTechLayerTypeParser.cpp:62` parses TRIMMETAL.
- `src/odb/src/lefin/lefTechLayerAreaRuleParser.cpp:108` gives the grammar
  `AREA value … [LAYER name OVERLAP overlap]`. Test data
  `src/odb/test/data/gscl45nm.lef:149` has `AREA 0.10100 LAYER metal1 OVERLAP 1 ;`.
- `src/drt/src/io/io.cpp:1744` warns "Unsupported branch LAYER in PROPERTY
  LEF58_AREA … skipping rule".
- `src/odb/src/lefin/lefTechLayerCutEnclosureTableParser.cpp:57-61`:
  "Trim-metal-aware overhang row (references a TRIMMETAL layer such as CM1).
  Trim layers are not modeled in OpenROAD yet, so the clause is recognized
  and discarded".

So the syntax exists in vendor LEF58 (LEF58_AREA and LEF58_ENCLOSURETABLE
with `LAYER trimLayer OVERLAP n`), but no public text says what OVERLAP 1/2
measures.

**Implementable?** Partly, as plain checks on the TRIMMETAL layer, per mask
pair from TRIMMEDMETAL:
- (a) Trim width ≥ w_r and trim space ≥ s_r, with abutting or overlapping
  trims merged first. On the same track and on adjacent tracks this matches
  IBM's "min distance or merged".
- (b) Every SADP-metal line end of mask k must be bounded by a trim shape of
  mask k. This is a derivation from "added at the line-end of a wires".
  Flag a line end not touched by a trim, and flag a trim lying inside a
  metal line (it would cut it).
- (c) The metal line-end rules derived from (a) are Xu Rules 1–4.

Oracle: TM1 mask 1 trims 20 apart with s_r = 46 → 1 violation; the same
trims abutting → clean (merged).

**LEF/DEF 5.7 (pass 2):**
- LEF/DEF 5.7 (Nov 2009, ISPD-hosted, [LEF57]). Grepped for TRIMMETAL, TRIMMEDMETAL, TRIMPOLY, MANDREL, SADP, self-aligned, SAMEMASK, MASK, stitch, patterning and color: 0 hits, apart from two unrelated "mask creation/generation" lines (:4430, :11284). It predates the multi-patterning constructs. Its LEF58_TYPE is only TSV/PASSIVATION and NWELL/PWELL, and its LEF58_AREA has no LAYER/OVERLAP clause.

**Still undefined:** the semantics of LEF58_AREA `LAYER … OVERLAP n` and
LEF58_ENCLOSURETABLE `LAYER … OVERLAP`, and any trim-to-cut (via) rule.

**Checked, nothing found:**
- ref.txt (all "trim" hits listed above).
- The coriolis.lip6.fr HTML mirror of LEF/DEF 5.8, which is identical.
- OpenROAD src and tests (no CM1 test LEF).
- A pdfcoffee.com mirror of a Cadence document. Not used, because it is a
  file-sharing mirror.

## LVS-047: Logic-gate recognition (RECOGNIZE GATES ALL/SIMPLE/NONE)

**Verdict:** partial. The ALL vs SIMPLE split and the dependence on power names are now
public via P12. The exact gate catalogue for "simple" vs "complex" is not public. A public
transistor-level NAND/NOR recognition definition exists (HP).

**Definition:**
- P12 [0154]-[0156]: "This command instructs a layout-versus-schematic operation to recognize
  the representation of logic gates from transistor-level data ... recognize an inverter from a
  particular arrangement of transistors."
- [0142]-[0144]: with `COMMAND9 simple` and XFORM ALL, "simple gates are formed while complex
  gates are not". The surface form is `LVS RECOGNIZE GATES SIMPLE`; sky130's report shows
  `LVS RECOGNIZE GATES ALL`, line 61.
- [0119]: gate recognition runs only after reduction, unused filtering and injection
  (ALL = "device reduction, unused device filtering, logic injection, and gate recognition").
- [0162]: power names are used "in, for example, logic gate recognition". Empirical
  consistency: sky130_fd_sc_ms__inv_1.lvs.report runs `LVS RECOGNIZE GATES ALL` with
  `// LVS POWER NAME` and `// LVS GROUND NAME` unset (lines 58-61). The "NUMBERS OF OBJECTS
  AFTER TRANSFORMATION" still show one MN and one MP, so no INV was formed (lines ~405-415).
  This fits "no rails, no gates", but it is a single observation.
- [0180]-[0191], the recognised gates as built-in devices: "INV—output input",
  "NAND2—output input input", "NOR3—output input input input". `lvsGate`, `lvsIn` and `lvsOut`
  are generic names for all gates and their input and output pins.
- HP US 6,077,717 B1 (McBride, "System and method for detecting NOR gates and NAND gates"),
  abstract and col. 7:
  - NAND (any input count): at a static gate output node, "each and every PFET device that is
    channel connected to the output node is directly connected to VDD. It further verifies that
    no NFET device that is channel connected to the output node is directly connected to
    ground."
  - NOR: the dual. "(i) no PFET ... channel connected to the ... output node is directly
    connected to VDD, (ii) all NFETs ... channel connected to drive the ... output node are
    directly connected to ground, and (iii) at least one PFET and at least one NFET are
    channel connected".
  - The static-gate-output predicate is quoted under ERC-G3. An INV meets neither NAND nor NOR
    by these tests, since its PFET is on VDD and its NFET on ground.
- SubGemini and Gemini II (Ohlrich, Ebeling et al., DAC 1993, doi:10.1145/157485.164556) are
  subgraph-isomorphism recognisers: the general mechanism, not Calibre's catalogue. No open
  copy was found (ACM DL bot-walled).

**Implementable?** Partly (GPurify already has series/parallel group recognition). Public
refinements:
1. Require declared power and ground for recognition (P12 [0162]).
2. Gate the mode: NONE does none, SIMPLE does INV/NANDn/NORn, ALL also does complex (AOI/OAI)
   gates. That INV/NAND/NOR are the "simple" ones is a reading of [0144] and [0181]-[0183];
   the patent does not list them as such.
3. Add the HP NAND/NOR predicate as a cross-check on recognised groups.

Oracle:
- 2-input NAND, PMOS ‖ on VDD and NMOS series to GND: NAND under HP and under GPurify.
- The same NAND with the input order swapped in the layout: must match the source.
- Without power names declared: no gate is formed (the sky130 observation).
- Calibre is the only reference; Netgen and KLayout have no gate recognition.

**Checked, nothing found:**
- An explicit Calibre simple/complex list.
- Mentor US 7,716,611 (logic injection; no gate catalogue).
- Oracle/Sun US 7,958,468 (generic subcircuit recognition, not LVS gates).
- Silvaco Guardian example 4 (`/examples/guardianlvs/section1/example4/` now 404).

## ERC-C9: CDM checks (the bus-inductance part)

**Verdict:** partial. A public quasi-static method gives the inductance a CDM discharge sees on a bus
and how to combine it with resistance. No public source gives a limit; the limit is a deck voltage,
as with the resistance part already implemented.

**Definition:** Russ, Esmark, Huff, Schneider, Langguth (Infineon), Zeitlhöfler (TU Munich), Cadjan,
Feinberg (Silicon Frontline), "Enablement, Evaluation and Extension of a CDM ESD Verification Tool for
IC Level", EOS/ESD Symposium 2021 (Best Paper, Methods). The public slides are at
https://www.synopsys.com/content/dam/synopsys/implementation&signoff/electrical-layout-verification-documents/esd-symposium-2021-pres.pdf
- Slide 10: "CDM center frequency around 1 GHz".
- Slide 11: HFSS of a VSS bus, "ZR=0.24Ω/mm, ZL=2πfL=3Ω/mm, L=0.48nH/mm … CDM frequency range: ZL > ZR".
- Slide 12: a 2 mm bus at 7 A and 600 ps rise time gives an "Inductive voltage peak ∆Vpeak=10V much larger than resistive voltage drop of 3V".
- Slide 14: "Inductance of straight conductor [Kalantarov]: L = μ0·l/2π · (ln(2l/(d+w)) + 1/2) for l ≫ d,w", and "V = sqrt(V_ind² + V_res²) with V_ind = 2πfL·I_path and V_res = R·I_path … Quasi-static approach".
- Slide 21: "Metal reinforcements: reduce inductance prevailing over efforts to reduce Ohmic resistances".
- Slide 23: "Inductance of busses matters because of excessive CDM voltage drops".

The voltage limit compared against is the oxide limit. Etherton et al. use example limits of 8 V and 5 V; that paper is in the same Synopsys folder, `cdm-esd-paper.pdf`, and is already in the catalog as Etherton2015.

**Implementable?** Yes, as an extension of the existing max_ground_resistance (Etherton) check. This
is a reading of public slides plus a derivation for paths.
1. For each straight wire segment on the driver-to-receiver ground path, compute R as today and L from the Kalantarov/Rosa formula. Inputs are l = segment length, w = width, and d = layer thickness from the deck/LEF.
2. Sum R and L along the series path, then compute |Z| = sqrt(R² + (2πfL)²) and V = |Z|·I.
   - The 2πf factor comes from the slides; summing R and L in series is a derivation.
   - Mutual inductance and return paths are ignored (the slides' quasi-static scope). This understates L relative to the HFSS value.
3. Flag when V exceeds the deck's V_limit, or when |Z| exceeds the deck's Z_max.
- **Deck parameters:** f (default 1 GHz per slide 10), I (CDM peak current, deck), layer thickness d, and V_limit or Z_max. None of these values is public as a rule; all are deck-supplied.
- **Oracle:**
  - One segment with l = 1000 µm, w = 10 µm, d = 1 µm: L = 2e-7·1e-3·(ln(2000/11) + 0.5) = 1.1406 nH. At f = 1 GHz, X_L = 7.1666 Ω.
  - Add R = 0.24 Ω and I = 5 A: V_ind = 35.833 V, V_res = 1.200 V, V = 35.853 V. Flag with V_limit = 8 V.
  - The same segment at 100 µm: L = 2e-7·1e-4·(ln(200/11) + 0.5) = 0.06802 nH, X_L = 0.4274 Ω, V_ind = 2.137 V. No flag at 8 V if R·I is small.
  - Units check from slide 11: 2π·1e9·0.48e-9 = 3.016 Ω/mm, which matches "ZL=3Ω/mm".

**Checked, nothing found:**
- Industry Council White Paper 2 Rev 3.0 (May 2021). §2.3.1 says to "minimize parasitic Rvddx and Rgnd bus resistances", and §2.4.2 gives "current density limit of 0.5 A/um requires a 20 um wide bus to carry 10 amperes of CDM current" at 65 nm. Every inductance mention concerns the package, the tester or the discharge path (Appendix D/E), and no on-chip inductance limit is given.
- JEP157A CDM tutorial (Industry Council, 2023-04-04): no bus-inductance rule.
- Etherton2015 (Synopsys PDF): resistance only, with 5-8 V limits.

# Please fetch

These sources look decisive but are paywalled, sit behind a login or form, or
are not distributed publicly. Their content was not guessed. They are ordered
by how many rows each would settle.

1. **Si2 LEF/DEF reference, latest v5.8 and v6.0 "API Format Spec Ref Doc"**,
   <https://si2.org/lef-def-downloads/>.
   - Access: free and Apache-2.0, but the form asks for a name and email and
     mails the link, which an agent cannot complete.
   - Would settle: DRC-034 (LEF58_MAXSPACING); DRC-042 (ENCLOSURE EOL,
     EOLONLY, SHORTEDGEONEOL); DRC-016 (WRONGDIRECTION LENGTH); DRC-102
     (PARALLELSAMEMASK, SAMEMASK); DRC-020 (CONCAVECORNER, NOADJACENTEOL,
     THREECONCAVECORNERS); DRC-036 (SPANLENGTHTABLE ORTHOGONAL); DRC-027
     (negative PRL); DRC-066 (SAMEMETALOVERLAP, FULLYENCLOSED); DRC-126
     (KEEPOUTZONE options); possibly DRC-127 (EDGETYPE options).
   - Why: [LEF57] (2009) already defines 32/45 nm LEF58 rules that the 2017
     text omits. A third-party mirror of a 14.17-era Cadence reference defines
     LEF58_MAXSPACING (not opened, see above), and iEDA's grammar carries
     keywords absent from every public edition. So newer defining text
     exists, and Si2's is the legitimate copy.
2. **Russ, Esmark, Huff, Schneider, Langguth, Zeitlhöfler, Cadjan, Feinberg,
   "Enablement, Evaluation and Extension of a CDM ESD Verification Tool for IC
   Level"**, Proc. EOS/ESD Symposium 2021 (ESDA/IEEE; DOI not located).
   - Would settle: ERC-C9. It should give the current-path model and whether
     a pass/fail limit is applied to V or |Z|.
   - Why: the public slides give the formula but not the method details.
3. **ESDA TR18.0-01**, *ESD Electronic Design Automation Checks*: Rule 6.4.2
   and §§5.6.3 and 6.6.
   - Would settle: ERC-C9 (bus inductance). Possibly ERC-D9.
   - Why: the free table of contents names Rule 6.4.2; only its title is
     public.
4. **Ohlrich, Ebeling, Ginting, Sather, "SubGemini: Identifying SubCircuits
   using a Fast Subgraph Isomorphism Algorithm"**, DAC 1993, pp. 31-37,
   doi:10.1145/157485.164556.
   - Would settle: LVS-047, giving a citable basis for matching complex
     gates (AOI/OAI).
   - Access: the ACM DL blocks scripts; it may be open in a browser.
5. **Gibson, Lu, Pikus, Srinivasan, "A Framework for Logic-Aware Layout
   Analysis"**, ISQED 2010 (IEEE).
   - Would settle: ERC-H3 (how PERC counts devices on a path) and LVS-047
     (which reductions and recognitions PERC applies).
   - Why: its co-authors overlap P12's, and it describes PERC in use.
6. **Zwerger, Graeb, "Short-Circuit-Path and Floating-Node Verification of
   Analog Circuits in Power-Down Mode"** (IEEE; cited as [14] in Oulkaid et
   al., DATE 2024).
   - Would settle: ERC-G3 and ERC-G9, with formal static definitions of
     short-circuit paths and floating nodes.
7. **N. K. Darav, I. S. Bustany, A. Kennings, R. Mamidi, "ICCAD-2017 CAD
   Contest in Multi-Deck Standard Cell Legalization and Benchmarks"**, ICCAD
   2017, <https://dl.acm.org/doi/10.5555/3199700.3199818>.
   - Would settle: DRC-127. It should say whether the contest scored facing
     edges only, scored TOP/BOTTOM edges, and how it treated EXCEPTABUTTED.
   - Why: the contest page says the penalty definitions "are presented
     later", and the contest site's PDF link is dead. Low priority, since the
     FAQ fixes the core rule.
8. **G. Luk-Pat et al., "Design compliance for spacer is dielectric (SID)
   patterning"**, Proc. SPIE 8326, 83260D (2012).
   - Would settle: DRC-128 and DRC-105 (the foundry-style SID rule list and
     the trim-to-metal derivation).
   - Why: it is ref. [26] of Xu et al. 2015, the source of its trim rules.
     Lower priority now that the patents state the rules.
9. **Y. Ma et al., "Self-aligned double patterning (SADP) compliant design
   flow"**, Proc. SPIE 8327, 832706 (2012).
   - Would settle: DRC-128 and DRC-105.
   - Why: it is a Mentor/GF paper on SADP DRC checks, and ref. [17] of Xu et
     al.
10. **H. Zhang, Y. Du, M. D. F. Wong, R. Topaloglu, "Self-aligned double
    patterning decomposition for overlay minimization and hot spot
    detection"**, DAC 2011, pp. 71-76. Also **Z. Xiao, H. Zhang, Y. Du,
    M. D. F. Wong**, ISPD 2012, pp. 17-24.
    - Would settle: DRC-128, the SIM-process (spacer-is-metal) legality
      conditions. No open copy was found.
11. **B. Yu, D. Z. Pan, *Design for Manufacturability with Advanced
    Lithography***, Springer 2016, doi:10.1007/978-3-319-20385-0, chapter on
    pp. 53-82.
    - Would settle: DRC-128. This is the catalog's "Yu and Pan 2016".
    - Low priority: it likely consolidates the open ASP-DAC 2014 and TCAD
      2015 papers used here.
12. **JEDEC JEP122H**, *Failure Mechanisms and Models for Semiconductor
    Devices*, the hot-carrier section.
    - Access: free with a JEDEC login.
    - Would settle: ERC-F4, only if it gives a design-level screen. It likely
      gives lifetime models only, so this is low priority.
13. **GlobalFoundries application note R-QR-MI-008**, "Guidelines for Circuit
    Design … to Guard Against Hot-Carrier-Induced Degradation", cited at
    GF180MCU DRM §14.1.1.
    - Would settle: ERC-F4.
    - Access: not public. GF distributes it under NDA, so list it only if
      someone has legitimate access.

**Public but unread, a follow-up for the next agent:** these were
rate-limited or only partly read, and are not paywalled.
- US 10,685,164 B1 (Cadence, routing based on parallel run length rules),
  columns 5-16: possibly negative PRL, for DRC-027.
- US 2013/0080980 A1 and US 9,594,866 B2 (TSMC, double-patterning checks):
  possibly for DRC-102 and DRC-103.
- US 7,174,527 B2 (Matsushita, antenna damage coefficient): ERC-A15, already
  found.
- The Mentor webinar "Programmable Electrical Rule Checking (PERC)" slides on
  site.eet-china.com, which timed out: possibly PERC check names, for ERC-D9.
