# What a verifier must check, and who says so

*Researched 2026-10-10. This is the requirements side of the
[testing plan](testing-plan.md). One row per check kind, with sources, the
GPurify kind that covers it, status and test oracle, is in
[check-catalog.tsv](check-catalog.tsv). `tests/catalog.rs` (planned, plan
§4 L9) keeps that file and the code from drifting apart.*

## The short answer

**No single authoritative list exists** for DRC, LVS or ERC. No IEEE, JEDEC
or ESDA document enumerates "every DRC rule". The cumulative list has to be
assembled from four kinds of source, each authoritative for a different part:

| Part | Authority | Why it counts |
|---|---|---|
| What rule *kinds* exist at the router/signoff level | Cadence **LEF/DEF 5.8 Language Reference**, plus the full `LEF58_*` grammar as implemented in **OpenROAD** (OpenDB parser, TritonRoute checker) | The de facto interchange grammar every P&R and signoff flow reads. Each keyword is a check kind. |
| What a real process requires, with numbers | The **open foundry design-rule manuals**: SkyWater SKY130, GlobalFoundries GF180MCU, IHP SG13G2, plus ASAP7 (predictive 7 nm FinFET) | Foundry rule ids and limits. They cover 180 nm to 7 nm, including latch-up, antenna, EM and ESD sections. |
| ESD, latch-up and reliability checks | **ESDA TR18.0-01-25** (ESD EDA checks), **ESDA TR18.0-02-20** (latch-up EDA), **ESDA TR22** (foundry ESD parameters); JEDEC **JESD78F.02**, **JEP122H**, **JESD63/202/263/241**; **IEEE 1801-2024** (UPF) for power-domain intent | Standards bodies. ESDA's are the only documents written as lists of *EDA checks*; JEDEC and IEEE supply the stress models and intent semantics the checks rest on. |
| How each check is *measured* (metrics, options, LVS semantics) | **KLayout** DRC/LVS reference, **Netgen** and **Magic** manuals; LVS algorithm papers (**GeminiII**, **SubGemini**) | Executable, open definitions. They are also the differential oracles of the testing plan (§4 L6). |

The commercial tools (Calibre, IC Validator, Pegasus, and the IR/EM tools)
define more check kinds than the open sources do. Their reference manuals and
packaged rule sets are customer-only. What is public (datasheets, white
papers, vendor blogs, granted patents, open-licensed decks and converters)
was mined for check *kinds*, and each such row says so (§4).

## 1. How to read the catalog

Columns: `id`, `domain`, `category`, `check`, `sources`, `gpurify`, `status`,
`oracle`, `notes`.

**status:**

| Value | Meaning |
|---|---|
| `implemented` | A GPurify kind or feature covers it. |
| `expressible` | No dedicated kind, but the deck language writes it, typically `forbidden(<derived layer>)`. |
| `partial` | A kind exists but misses a variant named in `notes`. A clean result from it is weaker than a foundry's. |
| `missing` | Nothing covers it. Each one belongs in `docs/limitations.md`. |
| `verify` | Coverage is unknown and needs a test before it can be classified. |
| `out_of_scope` | Deliberately not covered, with the reason in `notes`. |

**gpurify:** the kind names exactly as in `drc/ruleset.rs` `KINDS` and
`erc/ruleset.rs` `KINDS`, the LVS report ids (`lvs.*`, `checks.rs:21`), or a
feature tag (`deck:`, `erc:`, `lvs:`, `pex:`, `ingest:`, `lib:`).

**oracle** (the test-plan oracle that checks the row):

| Code | Oracle |
|---|---|
| `BM` | Bitmap reference DRC (plan L3) |
| `CF` | Closed-form physics or geometry |
| `SE` | The standard's or manual's own worked example or formula |
| `FR` | The foundry rule value, tested at the limit and at limit − 1 grid step |
| `TX:<tool>` | Cross-check against an open tool: KL (KLayout), NG (Netgen), MAG (Magic), OR (OpenROAD), drt (TritonRoute), YOSYS, ngspice, FasterCap, FastHenry |
| `SY` | A synthetic layout or netlist built from the source's definition, with a known answer |
| `MR` | Metamorphic relation (plan L5) |
| `NV` | Naive reference implementation (dense nodal solve, BFS, brute-force colouring) |

**Snapshot, 2026-10-10** (238 rows):

| Domain | implemented | expressible | partial | missing | verify | out of scope |
|---|---:|---:|---:|---:|---:|---:|
| DRC | 23 | 4 | 34 | 34 | 0 | 4 |
| LVS | 17 | 1 | 16 | 11 | 0 | 1 |
| ERC | 27 | 2 | 14 | 30 | 0 | 4 |
| PEX | 4 | 0 | 2 | 3 | 0 | 1 |
| Flow | 0 | 0 | 1 | 5 | 0 | 0 |

These numbers come from the TSV. Once `tests/catalog.rs` exists, it computes
them, so this table cannot go stale unnoticed (the plan's F5 problem).

## 2. Sources

Tags used in the `sources` column, grouped by part.

### 2.1 Rule grammar and router-level kinds

| Tag | Source | Version | Access | URL |
|---|---|---|---|---|
| `LEF` | Cadence, *LEF/DEF 5.8 Language Reference*, incl. App. C (antenna) | 5.8, May 2017 | Public third-party mirror of a Cadence-copyrighted document; Si2 distributes the parsers (Apache-2.0) after free registration. Newer references with the full LEF58 set are customer-only. | https://coriolis.lip6.fr/doc/lefdef/lefdefref/lefdefref.pdf ; https://si2.org/lef-def-downloads/ |
| `LEF58_*`, `odb` | OpenROAD OpenDB `lefin`: 32 LEF58 properties and all their sub-keywords | master `8a05d8549b`, 2026-10-10 | Open (BSD-3) | https://github.com/The-OpenROAD-Project/OpenROAD/tree/master/src/odb/src/lefin |
| `drt` | OpenROAD TritonRoute `frConstraintTypeEnum` / FlexGC checks | same | Open | https://github.com/The-OpenROAD-Project/OpenROAD/tree/master/src/drt/src/gc |
| `ISPD19` | ISPD 2019 detailed-routing contest rules (with worked examples) | 2019 | Open | http://www.ispd.cc/contests/19/Introduction_of_ISPD19_Contest_Problem.pdf |
| `OpenDFM` | Si2 OpenDFM, a vendor-neutral DRC/DFM language | v2.3.0.4, archived 2012 | Free registration. **Not obtained**, so its operator set is unverified. | https://si2.org/si2-openstandards/ |

Only 7 `LEF58_*` properties appear in the public 2017 reference. Every other
LEF58 row is sourced from OpenROAD's implementation, which is faithful but
not official.

### 2.2 Foundry design-rule manuals

| Tag | Source | Version | Rule ids (approx.) | URL |
|---|---|---|---|---|
| `IHP` | IHP SG13G2 Open Source Layout Rules; SG13G2 Process Specification | Rules Rev 0.4 (2024-12-19); Spec Rev 1.2 (2023-12-20) | ~330 | https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.doc/doc |
| `GF` | GF180MCU Design Rule Manual, incl. App. A (LVS devices), App. B (rules not coded), §14 (latch-up, ESD, EM) | readthedocs "latest", © 2022, no revision printed | ~610 | https://gf180mcu-pdk.readthedocs.io/en/latest/physical_verification/design_man.html |
| `SKY` | SkyWater SKY130 periphery rules, plus the antenna, hv, errors and summary pages | `docs/rules` last changed 2022-10-31, no version string | 523 unique | https://skywater-pdk.readthedocs.io/en/main/rules/periphery.html |
| `A7` | ASAP7 DRM (predictive 7 nm FinFET); Clark et al., *Microelectronics J.* 53 (2016), doi:10.1016/j.mejo.2016.04.006 | r1p7, `asap7_drm_201207a.pdf` | 197 | https://github.com/The-OpenROAD-Project/asap7_pdk_r1p7/blob/main/docs/asap7_drm_201207a.pdf |

All four are open (Apache-2.0 or BSD-3). These are the same manuals the
shipped `pdks/*.deck` cite, so a row's foundry ids double as the deck's rule
ids.

### 2.3 Open decks with pass/fail test layouts (differential-test inputs)

These are the inputs for the testing plan's foundry cross-check (§4 L6). Each
pairs a KLayout deck written by or for the foundry with GDS test cases and
golden results.

| PDK | Deck | Test cases | Last commit | URL |
|---|---|---|---|---|
| IHP SG13G2 | KLayout DRC: `rule_decks/{feol,beol,geometry,forbidden,pin}`, `antenna.drc`, `density.drc` | `testing/testcases/unit/<table>.gds` + `unit_golden`, one per rule table. LVS: per-device-family decks, ~316 GDS/CDL test files. | 2026-08-11 | https://github.com/IHP-GmbH/IHP-Open-PDK/tree/main/ihp-sg13g2/libs.tech/klayout/tech |
| GF180MCU | `fd_pv` KLayout DRC `rule_decks/*.rb`, LVS | 59 unit GDS with golden `.lyrdb` (e.g. `density-M1_4_pass/fail`), ~132 LVS test files | 2026-10-06 | https://github.com/fossi-foundation/globalfoundries-pdk-libs-gf180mcu_fd_pv |
| SKY130 | open_pdks `sky130.lydrc`; efabless `sky130A_mr.drc` + LVS | `test_violators.gds`; `lvs/testing` | 2022-06-16 / 2025-01-29 | https://github.com/RTimothyEdwards/open_pdks/tree/master/sky130/klayout ; https://github.com/efabless/sky130_klayout_pdk |
| SKY130 | Netgen setup: the real PDK reduction and tolerance policy | — | — | `open_pdks/sky130/netgen/sky130_setup.tcl` |

None of the open PDKs ships a Calibre, ICV or PVS deck. sky130's Calibre
pages are TODO stubs. FreePDK45 has open SVRF decks
(https://github.com/mflowgen/freepdk-45nm), but FreePDK45 is a teaching PDK.

### 2.4 Check semantics and LVS

| Tag | Source | Version | URL |
|---|---|---|---|
| `KL` | KLayout DRC reference (175 layer methods, 135 globals, 49 universal-DRC ops; metrics, `whole_edges`, `shielded`, `props_eq/ne`), LVS reference and manual (compare, align, `same_*`, `equivalent_pins`, `tolerance`, `blank_circuit`, `join_symmetric_nets`, `split_gates`), `GenericNetlistCompareLogger` (discrepancy events) | v0.30.12 (2026-08-26) | https://www.klayout.de/doc-qt5/about/drc_ref.html ; https://www.klayout.de/doc-qt5/about/lvs_ref_netter.html ; https://www.klayout.de/doc-qt5/code/class_GenericNetlistCompareLogger.html |
| `NG` | Netgen reference: `permute`, `property` (tolerance, series/parallel combine, `topology strict/relaxed`), `ignore class`, `ignore shorted`, `equate`, `flatten`, `model blackbox`; result strings in `base/netcmp.c` | 1.5.324 | https://opencircuitdesign.com/netgen/reference.html |
| `MAG` | Magic tech-file manual (DRC rule kinds, device extraction kinds), `ext2spice merge` | format 35 | https://opencircuitdesign.com/magic/techref/maint2.html |
| `Gemini` | Ebeling, "GeminiII", ICCAD 1988, doi:10.1109/ICCAD.1988.122520; Ohlrich et al., "SubGemini", DAC 1993, doi:10.1145/157485.164556. Ebeling & Zajicek, ICCAD 1983, pp. 172–173 (confirmed only through secondary citations) | — | paywalled |
| `ngspice` | ngspice manual: SPICE element syntax | 43–47 | https://ngspice.sourceforge.io/docs/ngspice-manual.pdf |

No open, authoritative **CDL** specification exists. CDL is a SPICE subset
with vendor extensions, and the Calibre/Cadence CDL documents are behind
customer logins. GPurify's reader can only be tested against ngspice syntax
plus the dialect real PDK netlists use.

### 2.5 ESD, latch-up, reliability, power intent

| Tag | Source | Version | Access | URL |
|---|---|---|---|---|
| `TR18-01` | ESDA TR18.0-01-25, *ESD Electronic Design Automation Checks* | 2025 (supersedes -11, -14) | Members free; otherwise sold. Only the TOC was read. | https://www.esda.org/store/standards/product/457/esd-tr18-0-01-25/ |
| `TR18-02` | ESDA TR18.0-02-20, *Latch-up EDA* | 2020 (revision due 2027) | Same. TOC read; Annex A reference rules not read. | https://www.esda.org/store/standards/product/307/esd-tr18-0-02-20/ |
| `TR22` | ESDA TR22.0-01-14 / -02-18, foundry and IP ESD parameters | 2014 / 2018 | Members free | https://www.esda.org/store/standards/product/72/esd-tr22-0-01-14 |
| `Khazhinsky2012`, `Hogan2012` | ESDA / In Compliance, "ESD EDA Checks" Parts I and II | 2012 (against TR18-11) | Open, read in full | https://www.esda.org/assets/News/8df611267c/ESDEDA-InCompliance-part1.pdf ; https://www.esda.org/assets/News/ESDEDA-InCompliance-part2.pdf |
| `JESD78` | JEDEC JESD78F.02, IC latch-up test | Nov 2023 | Free with JEDEC registration. Table 1 was read from a third-party copy, so **obtain the JEDEC original** before citing numbers. | https://www.jedec.org/standards-documents/docs/jesd-78b |
| `JS001`, `JS002` | ANSI/ESDA/JEDEC JS-001-2024 (HBM), JS-002-2025 (CDM); JTR001-01-12 user guide | 2024 / 2025 | Registration or purchase; bodies not read. JS-001's pin-combination tables set which pin pairs a P2P check must cover. | https://www.jedec.org/sites/default/files/JTR001-01-12%20Final.pdf |
| `JEP122` | JEDEC JEP122H, failure mechanisms and models (EM, TDDB, HCI, NBTI) | Sep 2016 | Registration; abstract only | https://www.jedec.org/standards-documents/docs/jep-122e |
| `JESD63`, `JESD202`, `JESD263`, `JESD241`, `JESD28`, `JESD60`, `JEP139`, `JESD214`, `JEP159A` | JEDEC EM, dielectric and transistor reliability test methods. JESD263 replaced JESD35A/JESD92 in Jun 2024; JESD241 replaced JESD90. | various | Registration | jedec.org |
| `WP1`–`WP5` | Industry Council on ESD Target Levels white papers (JEP155B, JEP157A, JEP196) | 2016–2023 | Open | https://www.esdindustrycouncil.org/ic/en/documents |
| `Black1969`, `Blech1976` | Black, IEEE TED 16(4), doi:10.1109/T-ED.1969.16754; Blech, J. Appl. Phys. 47(4), doi:10.1063/1.322842 | — | Paywalled | — |
| `IEEE1801` | IEEE 1801-2024 (UPF 4.0) | 2025-03-04 | Free through IEEE GET; **not read**, so no clause numbers are cited | https://standards.ieee.org/ieee/1801/11890/ |
| `CPF` | Si2 Common Power Format 2.1 | archived 2014 | Not read | https://si2.org/si2-openstandards/ |
| `OR` | OpenROAD `psm` (IR, EM, `check_power_grid`) and `ant` (PAR/CAR per LEF/DEF) | latest | Open | https://openroad.readthedocs.io/en/latest/main/src/psm/README.html |
| `YOSYS` | Yosys `check` (loops, conflicting drivers, undriven wires) | latest | Open | https://yosyshq.readthedocs.io/projects/yosys/en/latest/cmd/index_passes_status.html |
| `WH` | Weste & Harris, *CMOS VLSI Design* 4e (§3.3 rules, §3.6.1 antenna, §7.3 reliability, §13.3.2 IR, §13.6.2 ESD) | 2011 | Paywalled; TOC verified | https://pages.hmc.edu/harris/cmosvlsi/4e/cmosvlsidesign_4e_fm.pdf |

No JEDEC or IEEE standard covers antenna (plasma) damage. Its authority is
the foundry manuals plus LEF/DEF Appendix C. No standards body defines static
IR drop either: OpenROAD's behaviour, the foundry EM tables and Weste & Harris
are what exist.

### 2.6 Multi-patterning and restricted design rules

Kahng, Park, Xu, Yao, ICCAD 2008, doi:10.1109/ICCAD.2008.4681616 (double
patterning). Yu et al., ICCAD 2011, doi:10.1109/ICCAD.2011.6105297 (triple
patterning). Yu & Pan, *DFM with Advanced Lithography*, Springer 2016,
doi:10.1007/978-3-319-20385-0. Liebmann, ISPD 2003, doi:10.1145/640000.640026
(restricted design rules). Jhaveri et al., IEEE TCAD 29(4), 2010,
doi:10.1109/TCAD.2010.2042882 (gridded design). The open foundry manuals here
are single-patterning, apart from ASAP7's patterning-driven rules.

## 3. Proprietary tools: public evidence only

Tags: `CAL` Siemens Calibre (nmDRC, nmLVS, PERC, DFM, xACT, RealTime, Recon,
Auto-Waivers, 3DStack); `IA` Siemens Insight Analyzer; `MP` Siemens mPower;
`ICV` Synopsys IC Validator; `SRC` StarRC; `RH` RedHawk-SC; `TOT` Totem; `PF`
PathFinder-SC; `PEG` Cadence Pegasus/PVS/Assura; `VOL` Voltus; `QNT` Quantus;
`SIL` Silvaco; `EMP` Empyrean.

**What was used:**
- vendor product pages and datasheets;
- white papers and vendor engineering blogs;
- the open FreePDK45 SVRF decks;
- PVconverter, a BSD-licensed SVRF→PVS translator whose keyword table shows real SVRF statement names (https://github.com/kiwa3927/PVconverter);
- granted and published patents.

The key patents cited in the catalog:

| Id | Patent | Topic |
|---|---|---|
| P1 | US7757190B2 (AMD) | DRC augmented with pattern matching ("DRC-Plus") |
| P2 | US9904755B2 (Synopsys) | Legalising a multi-patterning layout |
| P3 | US11487930B2 (Synopsys) | Pattern matching with anchors |
| P4 | US10885258B1 (Synopsys) | Fixing ESD path-resistance errors |
| P5 | US10796045B2 (Siemens) | Property-based path tracing (voltage propagation) |
| P6 | US10360331B2 (Siemens) | Scoped simulation for ESD verification |
| P8 | US10546082B1 (Siemens) | Resistor-network reduction for full-chip current density |
| P9 | US9262574B2 (Siemens) | Voltage-related analysis of layout data (voltage-aware DRC) |
| P10, P11 | US20080115097A1 (granted US10643015B2); US20090106715A1 (abandoned) | Properties in EDA; programmable DRC (equation-based DRC lineage) |
| P12 | US20100306720A1 (abandoned) | Programmable electrical rule checking |

**What was not used:** customer-only manuals and packaged rule sets: the SVRF,
TVF and PERC references; PERC packaged-check XML; the full LVS discrepancy
taxonomy; the PXL and PVL references. Leaked copies of Calibre manuals and a
Calibre PERC test-case catalog turned up in search results on
document-sharing sites. They were deliberately not opened, and nothing here
derives from them.

**Check kinds the public evidence shows only in proprietary tools.** Each is a
catalog row:
- multi-patterning error taxonomy, stitches and colour density (DRC-101–104);
- equation-based DRC (DRC-115);
- voltage-aware DRC with automatic propagation (DRC-082, ERC-F1);
- ESD discharge-path P2P resistance and current density (ERC-C6, C7);
- CDM checks (ERC-C9);
- electrical guard-ring checks (ERC-D4);
- static leakage / HiZ (ERC-H1);
- analog constraint checks: symmetry, matching, common centroid (ERC-H2);
- critical area and DFM scoring (DRC-111, 112);
- pattern matching (DRC-114);
- short isolation (LVS-005);
- logic-gate recognition (LVS-047);
- SoC-integration sanity checks (FLOW-003);
- waivers (FLOW-001);
- PEX qualification diff (PEX-009).

**Not gaps after all:** soft-connect checking (KLayout `soft_connect`) and
basic antenna ratios (KLayout `antenna_check`) exist in open tools.

## 4. Where GPurify stands: the gaps that matter

Ordered by how many independent sources define the check, then by severity.
All are `missing` or `partial` in the catalog.

1. **Voltage-dependent spacing** (DRC-082 / ERC-F11). Defined by Calibre,
   ICV, Pegasus, Empyrean, LEF58_VOLTAGESPACING, sky130 hvnwell.8 and gf180
   DV.9. It needs conditional voltage propagation first (ERC-F1).
2. **LVS hierarchy, polarity and parameters** (LVS-010, 017, 030,
   060–064, 072). Reference `X` instances are dropped (testing-plan F1), a
   reversed diode matches (F15), and passives are compared by marker area only
   (F16). The first two are false-clean risks. Every LVS source treats all
   three as basic.
3. **Bounding-box `extension`/`overlap`** (DRC-045/046). Every foundry has
   extension rules; an L-shape passes today.
4. **ESD discharge-path checks** (ERC-C2–C8). TR18, Calibre, ICV, Voltus and
   PathFinder all define them; today only clamp-path existence is checked.
5. **LEF58 router-rule variants**: EOL variants, MINSTEP variants,
   TWOWIDTHS, cut classes, width-dependent enclosure, forbidden/max spacing
   (DRC-020, 027, 029–034, 043, 061, 063). These matter for the shared-deck
   library: a router (Philis) needs these rules to be the ones signoff
   checks.
6. **Shape-class and count selection**: rectangles and squares, exact or
   maximum count, aspect ratio, channel W/L (DRC-005, 011, 022, 049). sky130,
   gf180 and IHP each leave rules out of the shipped decks for lack of these.
7. **Antenna credit models**: gf180's additive model, LEF PWL, IHP minimum
   diode size, hierarchical pins (ERC-A5–A7, A9, A14). Today a diode row with
   credit is refused.
8. **LVS equivalence controls**: black boxes, ignore class, shorted dummies,
   per-parameter tolerance, asymmetric devices, R/C/D/BJT reduction
   (LVS-031–035, 043, 044, 014).
9. **Latch-up beyond tap distance**: conditional tap distance, tie area,
   aggressor/victim (ERC-D1a, D1b, D5).
10. **Custom and equation-based rules** (DRC-115, FLOW-006). This is the
    planned Rust-deck escape hatch (testing-plan §4 L9b).

## 5. What could not be verified

- **ESDA TR18/TR22 bodies.** Only the tables of contents were read. TR18-25's
  individual check numbering is unknown; "check 5.1.3" is from the 2011
  edition and has probably changed. TR18-02 Annex A rule values were not
  read.
- **JEDEC standards.** Only the abstract pages were read, plus JESD78 Table 1
  from a third-party copy. Use the JEDEC original.
- **IEEE 1801 and Si2 CPF** were not read. The power-intent rows (ERC-F6–F8)
  cite them for scope only.
- **Si2 OpenDFM** was not obtained.
- **The full LEF58 grammar** is only in customer-only Cadence references;
  OpenROAD stands in. No public LEF/DEF 6.0 language reference was found.
- **Commercial manuals.** All of the commercial reference material listed in
  §3 is customer-only. Commercial series-MOS and dummy-device reduction
  behaviour is unknown.
- **Version strings.** GF180's DRM revision and sky130's rules version are not
  printed. The sky130 pages were read on 2026-10-10; GF180 is the "latest"
  build.
- **Rule counts** are table-parse approximations.
- **NDA-only values** with no open equivalent: RMS/peak EM limits, numeric
  ESD spacing rules. Only gf180 §14.3–14.5 and IHP §7.2 publish any ESD or
  latch-up numbers.

## 6. Keeping it current

- A new check kind in the code gets a row, or the catalog test fails.
- A missing row that gets implemented flips to `implemented` and gains the
  test-plan §6 matrix cells.
- A new foundry manual or deck release changes the cited version.
- A finding from users, an LLM review or the KLayout/foundry cross-check that
  no row anticipated gets a new row. That is a missing requirement, the gap
  the plan's L9 layer exists to catch.
