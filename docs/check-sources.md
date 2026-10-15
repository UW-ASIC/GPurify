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
feature tag (`deck:`, `drc:`, `erc:`, `lvs:`, `pex:`, `ingest:`, `lib:`).

**oracle** (the test-plan oracle that checks the row):

| Code | Oracle |
|---|---|
| `BM` | Bitmap reference DRC (plan L3) |
| `CF` | Closed-form physics or geometry |
| `SE` | The standard's or manual's own worked example or formula |
| `FR` | The foundry rule value, tested at the limit and at limit − 1 grid step |
| `TX:<tool>` | Cross-check against an open tool: KL (KLayout), NG (Netgen), MAG (Magic), OR (OpenROAD), drt (TritonRoute), YOSYS, ngspice, FastCap, FasterCap, FastHenry |
| `SY` | A synthetic layout or netlist built from the source's definition, with a known answer |
| `MR` | Metamorphic relation (plan L5) |
| `NV` | Naive reference implementation (dense nodal solve, BFS, brute-force colouring) |

**Snapshot, 2026-10-10** (261 rows):

| Domain | implemented | expressible | partial | missing | verify | out of scope |
|---|---:|---:|---:|---:|---:|---:|
| DRC | 56 | 6 | 44 | 0 | 0 | 0 |
| LVS | 31 | 1 | 15 | 1 | 0 | 0 |
| ERC | 64 | 4 | 13 | 0 | 0 | 0 |
| PEX | 9 | 0 | 7 | 0 | 0 | 0 |
| Flow | 2 | 0 | 8 | 0 | 0 | 0 |

These numbers come from the TSV. Once `tests/catalog.rs` exists, it computes
them, so this table cannot go stale unnoticed (the plan's F5 problem).

## 2. Sources

Tags used in the `sources` column, grouped by part.

### 2.1 Rule grammar and router-level kinds

| Tag | Source | Version | Access | URL |
|---|---|---|---|---|
| `LEF` | Cadence, *LEF/DEF 5.8 Language Reference*, incl. App. C (antenna) | 5.8, May 2017 | Public third-party mirror of a Cadence-copyrighted document; Si2 distributes the parsers (Apache-2.0) after free registration. Newer references with the full LEF58 set are customer-only. | https://coriolis.lip6.fr/doc/lefdef/lefdefref/lefdefref.pdf ; https://si2.org/lef-def-downloads/ |
| `LEF57` | Cadence, *LEF/DEF Language Reference, Product Version 5.7*, November 2009, posted by the ISPD 2018 and 2019 contest organisers; defines LEF58_ properties the 5.8 text omits (LEF58_SPACING ENDOFLINE, LEF58_MINSTEP, LEF58_EOLEXTENSIONSPACING, LEF58_SPACINGTABLE cut, LEF58_ENCLOSURE, LEF58_MINIMUMCUT AREA) | 5.7, Nov 2009 | Public posting of a Cadence-copyrighted document (`docs/research/blocked-rows.md`, [LEF57]) | https://www.ispd.cc/contests/18/lefdefref.pdf |
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
| `BSIM4` | BSIM4 MOSFET model manual (UC Berkeley): the layout-dependent instance parameters SA, SB, SD (stress, LOD) and SCA, SCB, SCC, SC (well proximity) and their geometric definitions | 4.8 | https://bsim.berkeley.edu/models/bsim4/ |

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
| `HoganMedhat2021` | Hogan, Medhat (Siemens), "Circuit Reliability Verification For Automotive Electronics", Semiconductor Engineering: the Calibre PERC layout checks it names (P2P and current density pad to ESD device, PMOS/NMOS sharing one well, field-oxide parasitics, latch-up) | 2021-05-06 | Open | https://semiengineering.com/circuit-reliability-verification-for-automotive-electronics/ |
| `Bakhali2020` | Bakhali (Siemens), "ESD P2P And CD Verification Doesn't Have To Be Hard", Semiconductor Engineering: the pin-to-clamp, clamp-to-clamp and pin-to-pin resistance checks and an example rule ESD.CDM.SEC.1 (bus from a ggNMOS to the closest power clamp under 1 Ω) | 2020-11-24 | Open | https://semiengineering.com/esd-p2p-and-cd-verification-doesnt-have-to-be-hard/ |
| `Bryant1991` | R. E. Bryant, "Extraction of Gate Level Models from Transistor Circuits by Four-Valued Symbolic Analysis", ICCAD '91: channel-connected components ("a set of storage nodes connected by the source-drain terminals of transistors") and their rank order | 1991 | Open (author's copy) | https://www.cs.cmu.edu/~bryant/pubdir/iccad91.pdf |
| `Karmokar2022` | Karmokar, Madhusudan, Sharma, Harjani, Lin, Sapatnekar, "Common-Centroid Layout for Active and Passive Devices: A Review and the Road Ahead", ASP-DAC 2022: the centroids of each device's units coincide (Eq. 2-3) | 2022 | Open (author's copy) | http://people.ece.umn.edu/~sachin/conf/aspdac22.pdf |
| `Sarhan2019` | Sarhan, Arriordaz (Siemens), "Automated Analog Design Constraint Checking", Semiconductor Engineering: common centroid, orientation, symmetry, dummies, WPE and STI checks on designer-declared groups | 2019-02-14 | Open | https://semiengineering.com/automated-analog-design-constraint-checking/ |
| `Liu-DVCon` | Liu, Hong, Lee, Choi, Won, Choi (Samsung), Vardhan, Kher (Synopsys), "Low Power Verification with UPF: Principle and Practice", DVCon: power-switch, retention and PG-connectivity checks ("Power switch control signal should come from always on path") | — | Open | https://dvcon-proceedings.org/wp-content/uploads/low-power-verification-with-upf-principle-and-practice.pdf |
| `ISLPED2014` | "Failing to Fail" UPF tutorial, ISLPED 2014: `create_power_switch` with its `-input_supply_port` and `-output_supply_port` | 2014 | Open | https://islped.org/2014/files/Failing%20to%20fail%20UPF%20tutorial%20.pdf |
| `Etherton2015` | Etherton et al. (Freescale, Silicon Frontline, Apache-ANSYS), "A New Full-Chip Verification Methodology to Prevent CDM Oxide Failures", EOS/ESD Symposium, hosted by Synopsys: the driver/receiver ground resistance check ("The user defines the maximum resistance (Rmax) allowed between D/R ground pins") | 2015 | Open | https://www.synopsys.com/content/dam/synopsys/implementation&signoff/electrical-layout-verification-documents/cdm-esd-paper.pdf |
| `CVC` | Bailey, "CVC: Circuit Validity Checker", WOSET 2020: an open (GPL-3) voltage-aware transistor-level ERC; forward-biased junctions and overvoltage from propagated minimum and maximum voltages | 2020 | Open | https://woset-workshop.github.io/PDFs/2020/a05.pdf |
| `JESD78` | JEDEC JESD78F.02, IC latch-up test | Nov 2023 | Free with JEDEC registration. Table 1 was read from a third-party copy, so **obtain the JEDEC original** before citing numbers. | https://www.jedec.org/standards-documents/docs/jesd-78b |
| `JS001`, `JS002` | ANSI/ESDA/JEDEC JS-001-2024 (HBM), JS-002-2025 (CDM); JTR001-01-12 user guide | 2024 / 2025 | Registration or purchase; bodies not read. JS-001's pin-combination tables set which pin pairs a P2P check must cover. | https://www.jedec.org/sites/default/files/JTR001-01-12%20Final.pdf |
| `JEP122` | JEDEC JEP122H, failure mechanisms and models (EM, TDDB, HCI, NBTI) | Sep 2016 | Registration; abstract only | https://www.jedec.org/standards-documents/docs/jep-122e |
| `JESD63`, `JESD202`, `JESD263`, `JESD241`, `JESD28`, `JESD60`, `JEP139`, `JESD214`, `JEP159A` | JEDEC EM, dielectric and transistor reliability test methods. JESD263 replaced JESD35A/JESD92 in Jun 2024; JESD241 replaced JESD90. | various | Registration | jedec.org |
| `WP1`–`WP5` | Industry Council on ESD Target Levels white papers (JEP155B, JEP157A, JEP196) | 2016–2023 | Open | https://www.esdindustrycouncil.org/ic/en/documents |
| `Black1969`, `Blech1976` | Black, IEEE TED 16(4), doi:10.1109/T-ED.1969.16754; Blech, J. Appl. Phys. 47(4), doi:10.1063/1.322842 | — | Paywalled | — |
| `Banerjee1999` | Banerjee, Mehrotra, Sangiovanni-Vincentelli, Hu, "On thermal effects in deep sub-micron VLSI interconnects", DAC 1999, pp. 885–891, doi:10.1145/309847.310093: self-heating `ΔT = I²rms R θ`, `θ = t / (K L W_eff)`, `W_eff = W + φ t` (eqs. 7, 8, 10, 14) | — | Open copy, read | https://www.cecs.uci.edu/~papers/compendium94-03/papers/1999/dac99/pdffiles/49_2.pdf |
| `Kitchin1995` | Kitchin, "Statistical electromigration budgeting for reliable design and verification in a 300-MHz microprocessor", Symp. VLSI Circuits Dig. Tech. Papers 1995, pp. 115–116: chip EM risk as the weakest link of every wire's | — | Paywalled; known through citing papers | — |
| `Najm2003` | Kouroussis and Najm, "A static pattern-independent technique for power grid voltage integrity verification", DAC 2003, pp. 99–104, doi:10.1145/775832.775861: vectorless verification of an RC grid stepped by backward Euler | — | Paywalled; abstract read | https://dl.acm.org/doi/10.1145/775832.775861 |
| `IEEE1801` | IEEE 1801-2024 (UPF 4.0) | 2025-03-04 | Free through IEEE GET; **not read**, so no clause numbers are cited | https://standards.ieee.org/ieee/1801/11890/ |
| `CPF` | Si2 Common Power Format 2.1 | archived 2014 | Not read | https://si2.org/si2-openstandards/ |
| `OR` | OpenROAD `psm` (IR, EM, `check_power_grid`), `ant` (PAR/CAR per LEF/DEF), `rcx` (OpenRCX, extraction from DEF), `fin` (`density_fill`) and `dpl` (placement legality, cell edge spacing) | latest | Open | https://openroad.readthedocs.io/en/latest/main/src/psm/README.html ; https://openroad.readthedocs.io/en/latest/main/src/rcx/README.html |
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

CMP (`Ouma2002`): Ouma, Boning, Chung, Easter, Saxena, Misra, Crevasse,
"Characterization and modeling of oxide chemical-mechanical polishing using
planarization length and pattern density concepts", IEEE Trans. Semicond.
Manuf. 15(2):232–244, 2002: post-polish thickness from pattern density
averaged over the planarization length. Its parameters are process
calibration; no open PDK publishes them.

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
- `ICsprout55`: the Apache-2.0 ICsprout 55 nm open PDK's Calibre LVS deck, whose `ERC PATHCHK` statements carry their meaning in comments ("Nodes with a path to ground but not power", "Nodes without a path to both power and ground") (https://github.com/openecos-projects/icsprout55-pdk/blob/main/pv/LVS/ICsprout_CalLVS_55LLULP1233_REV1_0_OS.lvs);
- PVconverter, a BSD-licensed SVRF→PVS translator whose keyword table shows real SVRF statement names (https://github.com/kiwa3927/PVconverter); a `CAL:<STATEMENT>` source in capitals (e.g. `CAL:ERC PATHCHK`, `CAL:LVS ISOLATE OPENS`) is a statement name from its token table `src/public/token/rcsTokenTypes.h`, which shows the check exists, not its semantics;
- `SRC:datasheet`: the Synopsys StarRC datasheet (CS1038890626, 04/2023), its process-modelling and productivity lists (https://www.synopsys.com/content/dam/synopsys/implementation&signoff/datasheets/starrc-ds.pdf);
- `QNT:RFIC`: Cadence's RFIC design page on Quantus substrate modelling (https://www.cadence.com/en_US/home/explore/rfic-design.html);
- the Siemens product pages and fact sheets for Calibre 3DSTACK, DesignEnhancer, Vision AI and PERC (https://www.siemens.com/en-us/products/ic/calibre-design/);
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
| P13 | US11714117B2 (Synopsys) | ESD path resistance as the pin voltage over a unit forced current |
| P14 | US10216888B2 (Cadence) | Constraint validation: matched devices of one model, finger count, width and length |
| P15 | US12021077B2 | Local CDM protection: a series resistor between a block's output and the input it drives, with clamps |
| P16 | US9035393B2 (TSMC) | A cross-domain CDM cell: series resistor (50, 100 or 200 Ω) and ggNMOS |

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
- PEX qualification diff (PEX-009);
- device-region (MEOL) parasitics, fill treatment, substrate and 3D-IC extraction (PEX-011–013, 015);
- inter-die alignment (DRC-129), path checks (ERC-G9), ESD layout rules on recognised devices (ERC-C14);
- layout enhancement and result clustering (FLOW-009, 010).

**Not gaps after all:** soft-connect checking (KLayout `soft_connect`) and
basic antenna ratios (KLayout `antenna_check`) exist in open tools.

## 4. Where GPurify stands: the gaps that matter

Ordered by how many independent sources define the check, then by severity.
All are `missing` or `partial` in the catalog.

1. **Voltage-dependent spacing** (DRC-082 / ERC-F11). Defined by Calibre,
   ICV, Pegasus, Empyrean, LEF58_VOLTAGESPACING and sky130 hvnwell.8.
   Implemented in H6 as `voltage_space` over gate-conditional voltage
   propagation (ERC-F1); sky130's well rules wait on wells as conductors
   (DRC-081).
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
7. **Antenna hierarchy**: LEF's macro-pin antenna values (ERC-A14) are read
   with a DEF's LEFs, the default oxide model's; DEF's top-down
   `ANTENNAPIN*` budgets and the other oxide models are left. The credit
   models (sky130's EGAR per µm²,
   gf180's additive model, LEF's PWL and minus/plus factors, IHP's minimum
   diode, ERC-A5–A7, A9) are in `antenna_electrical`.
8. **LVS equivalence controls**: black boxes, ignore class, shorted dummies,
   per-parameter tolerance, asymmetric devices, R/C/D/BJT reduction
   (LVS-031–035, 043, 044, 014).
9. **Latch-up beyond tap distance**: conditional tap distance, tie area,
   aggressor/victim (ERC-D1a, D1b, D5).
10. **Custom and equation-based rules** (DRC-115, FLOW-006). This is the
    planned Rust-deck escape hatch (testing-plan §4 L9b).

## 4a. Checks no open-source tool performs

These rows are supported and no open tool defines them, so no open tool can be
the oracle: each is proved on GPurify's own evidence (oracle codes, section 1),
and each must rest on at least two independent oracles. `tests/catalog.rs`
generates this list from the catalog and enforces the rule; a row below with a
single oracle is a named gap that ledger P1 closes.

<!-- generated from docs/check-catalog.tsv by tests/catalog.rs; edit the catalog, not this block -->

| Id | Check | Status | Defined by (public) | Evidence |
|---|---|---|---|---|
| DRC-036 | Span-length table | partial | LEF58_SPANLENGTHTABLE | SE; MR; SY |
| DRC-037 | Bent / 45-degree features | partial | IHP:M1.g,Mn.g,Gat.g; GF:PL.7,MT30.4; SKY:via.14a | FR; MR; SY |
| DRC-038 | Diagonal width / spacing | partial | LEF:DIAGWIDTH,DIAGSPACING,DIAGMINEDGELENGTH; IHP:M1.g,M1.i,Mn.g,Mn.i | SY; MR |
| DRC-081 | Net spacing between two layers / on wells | partial | SKY:nwell.7,hvnwell.8,hv.nwell.1,vhvi.8; IHP:NW.b1,NBL.c | SY; MR |
| DRC-082 | Voltage-dependent spacing (VA-DRC) | implemented | SKY:hvnwell.8,hv.*; LEF58_VOLTAGESPACING; CAL; ICV; PEG; EMP | SY; MR |
| DRC-083 | HV tag propagation (shorted to HV becomes HV) | implemented | SKY:hv.X.1-hv.X.6 | FR; SY; MR |
| DRC-084 | Floating interconnect / must-join ports | partial | SKY:x.22; LEF58_MUSTJOINALLPORTS | SY; MR |
| DRC-085 | Tap presence per well | implemented | SKY:nwell.4; GF:DN.3; IHP:nmosi.d | FR; SY; MR |
| DRC-100 | Colouring legality (odd cycle) | implemented | Kahng2008; Yu2011; YuPan2016; CAL; ICV; PEG | NV:brute-force k-colouring; MR; SY |
| DRC-101 | MP error taxonomy (anchor path, anchor self-conflict, same-mask self-conflict, min opposite-mask spacing) | implemented | CAL | NV; MR; SY |
| DRC-102 | Pre-coloured (MASK) same-/different-mask spacing | partial | LEF:MASK; LEF58 SAMEMASK,PARALLELSAMEMASK; A7:M4.S.1 | NV; MR; SY |
| DRC-103 | Stitch legality | expressible | CAL; ICV | MR; SY |
| DRC-105 | Trim / cut-metal layers | expressible | LEF58_TYPE TRIMMETAL; LEF58_TRIMMEDMETAL; A7:GCUT | FR; MR; SY |
| DRC-110 | Recommended rules reported as warnings | implemented | IHP:R suffix,4.1; SKY:RR,RC; A7:type R; LEF:PREFERENCLOSURE | FR; SY; MR |
| DRC-111 | DFM scoring of recommended rules | partial | CAL:YieldAnalyzer | SY; MR |
| DRC-113 | Litho / CMP simulation hotspots | partial | CAL:LFD,CMPAnalyzer; PEG; Ouma2002 | CF; MR; SY |
| DRC-115 | Equation-based DRC | partial | CAL:eqDRC; patents P10,P11 | CF; SY |
| DRC-124 | Layout input exceptions (missing cell reference, duplicate cell, magnified or angled placement, odd or zero path width, spike, vertex count) | partial | CAL:LAYOUT INPUT EXCEPTION SEVERITY,DRC MAXIMUM VERTEX | SY; MR |
| DRC-128 | Self-aligned multiple patterning (SADP/SAQP mandrel, spacer, cut) legality | partial | US20150286764A1; Xu2015 (TCAD 34(5) Table II); Xiao ISPD 2012 slides; YuPan2016; A7:fin SAQP,M4-M7 SADP (Clark2016) | SE; SY; MR |
| DRC-129 | Inter-die alignment and overlap (bump and pad alignment, rotation, cross-die spacing) | implemented | CAL:3DSTACK | SY; MR |
| LVS-005 | Short isolation / localisation | partial | CAL:LVS ISOLATE SHORT,LVS ISOLATE OPENS; ICV:ShortFinder; PEG | SY; MR |
| LVS-020 | Undeclared parameter | implemented | - | SY; MR |
| LVS-047 | Logic-gate recognition | partial | CAL:LVS RECOGNIZE GATES; SubGemini; Silvaco Guardian LVS app note Logic Gate Recognition (2020) and example 4 | SY; MR |
| LVS-048 | Filter unused devices | partial | CAL:LVS FILTER UNUSED; US8751985B1 (col. 7 ll. 44-62, Calibre's options quoted); US20100306720A1 [0162] | SY; NV |
| LVS-066 | Device flavour (HVT/LVT) by implant marker | expressible | GF:App.A; IHP LVS decks | SY; MR |
| LVS-071 | Spectre reader | implemented | - | SY; MR; fuzz |
| LVS-074 | Layout-dependent-effect parameters (LOD SA/SB/SD, WPE SCA/SCB/SCC) | partial | BSIM4; SRC:datasheet; Silvaco SmartDRC/LVS app note Well Proximity and STI Stress Effect Parameters Extraction (2022) | CF; SE; SY |
| ERC-A9 | Minimum protection-diode size | expressible | IHP:Ant.g | SE:IHP Ant.g; MR; SY |
| ERC-A10 | Diode well legality | expressible | IHP:Ant.h,Ant.i | FR; SY |
| ERC-A13 | Exemption for substrate-shorted nets | implemented | SKY:.ar.1 | SE:SKY .ar.1; MR; SY |
| ERC-A15 | Fix hint: required diode area | partial | IHP:Ant.g Note 4; SKY:antenna EGAR; US9142556; LEF:ANTENNADIFFAREARATIO PWL | SE; CF |
| ERC-B1 | Windowed density + CMP thickness | implemented | GF:13 | CF; MR; SY |
| ERC-C1 | Pad ESD path to power and ground | implemented | TR18-01:4.5.2-4.5.4; Khazhinsky2012 | SY; NV; MR |
| ERC-C2 | ESD device sizing (perimeter, clamp width) | implemented | TR18-01:Fig23,Fig24; Hogan2012:III; GF:14.5 | CF; SY; MR |
| ERC-C3 | Protected device (pad-exposed gates and drains) | implemented | TR18-01:4.5.1,6.1.11; Khazhinsky2012; GF:14.4; WP2:2.3 | SY; MR |
| ERC-C4 | Cross-domain signal ESD protection | implemented | TR18-01(2011):5.1.3; TR18-01:5.6.2; Hogan2012; Khazhinsky2012:Fig5; P15; P16 | SE:Part II pseudocode; SY; NV; MR |
| ERC-C5 | Ground-domain coupling (anti-parallel diodes) | implemented | TR18-01:Fig5; Hogan2012:Fig1,IV; Khazhinsky2012:Fig2 | SY; NV; MR |
| ERC-C7 | ESD-pulse current density | implemented | TR18-01:Fig58; TR22:4.4; Khazhinsky2012; CAL; ICV; PF | CF; MR; SY |
| ERC-C8 | Path voltage vs device failure (ESD window) | partial | TR18-01:2.1; TR22:4.1,8; Khazhinsky2012:Fig4; GF:14.4; WP2:2.9.3 | CF; SY; MR; NV |
| ERC-C9 | CDM checks (bus inductance, local clamps, driver/receiver ground R) | partial | TR18-01:5.6.3,6.6; JEP157A; Khazhinsky2012; PF; Etherton2015 | SY; MR |
| ERC-C10 | Layout parasitic ESD paths | implemented | TR18-01:5.6.1; Khazhinsky2012; GF:14.4 | SY; MR |
| ERC-C11 | ESD device geometry (DCGS, SCGS, fingers) | expressible | GF:LVESD.1-13; IHP:6.8 | FR; MR; SY |
| ERC-C12 | Package / 2.5D / 3D ESD | partial | TR18-01:6.3-6.7; JEP196; CAL:3DPERC | SY; NV |
| ERC-C13 | System-level ESD | partial | TR18-01:7; WP3 | SY; NV |
| ERC-C14 | ESD layout rules on recognised devices (clamp distance to pad, minimum ESD-path metal width) | implemented | Khazhinsky2012; HoganMedhat2021; Bakhali2020; P13; CAL:PERC LDL | CF; SY; MR |
| ERC-D1a | Tap distance conditional on neighbouring well spacing | implemented | GF:LU.1-4 | FR; CF; SY; MR |
| ERC-D1b | Minimum well-tie area | implemented | TR18-02:Annex A; GF:LU.7,IO.2,IO.4 | FR; CF; SY; MR |
| ERC-D2 | Pad-diffusion guard ring (spacing, width) | implemented | GF:IO.1-4; IHP:7.2.1; TR18-02:3.1.2 | FR; MR; SY |
| ERC-D3 | Guard ring / well tied to the correct rail | implemented | GF:LU.9,LU.10,IO.1,IO.3 | SY; MR; NV |
| ERC-D4 | Guard-ring resistance / current under injection | implemented | TR18-02:2.3; JESD78:Table 1; CAL | CF; MR; SY |
| ERC-D5 | Voltage-aware aggressor/victim | partial | TR18-02:2.2.3; GF:14.3.2,IO.1,IO.3; CAL; CVC | FR; CF; SY; MR |
| ERC-D6 | HV latch-up between isolated pockets | expressible | TR18-02:3.3; GF:14.3.4 | SY; MR |
| ERC-D7 | Native-device guard ring | implemented | GF:LU.5 | FR; SY; MR |
| ERC-D8 | Forward-biased diode marked and ringed | implemented | GF:14.3.2,14.3.3 | SY; MR |
| ERC-D9 | PMOS/NMOS devices sharing one well | implemented | US5638286; HoganMedhat2021 | SY; NV; MR |
| ERC-E3 | Width-banded absolute current for narrow lines | implemented | IHP:2.15 | SE:IHP 2.15; FR; MR; SY |
| ERC-E4 | Temperature derating (Black / Arrhenius) | implemented | GF:14.2.2; Black1969; JEP122; JESD63 | SE:GF formula vs table (1.6% rounding); MR; SY |
| ERC-E5 | Lifetime target and percentile | implemented | GF:14.2; IHP:2.15; JESD202 | SE; MR; SY |
| ERC-E6 | Blech short-length immortality | implemented | Blech1976 | CF; MR; SY |
| ERC-E7 | RMS / Joule heating / peak limits | implemented | LEF:ACCURRENTDENSITY PEAK,AVERAGE,RMS; SKY:tech LEF ACCURRENTDENSITY RMS | CF; SY |
| ERC-E11 | Dynamic / vectorless IR | partial | RH; VOL; MP; TOT; Najm2003; WH | CF; NV; MR; SY |
| ERC-E12 | Stress voiding / slotting | partial | JEP139; JESD214; GF:14.6,MSLOT.1-10; IHP:Slt.a-i | FR; MR; SY |
| ERC-E13 | Thermal-aware / statistical EM, self-heating | implemented | RH; TOT; VOL; Banerjee1999; Black1969; JEP122; JESD63; Kitchin1995 | CF; SE; MR; SY |
| ERC-F1 | Static voltage propagation, conditional on gate voltage | implemented | CAL:WP 81822; SKY:hv.X.1; patents P5,P9 | SE:Siemens WP; SY; NV |
| ERC-F2 | Gate-oxide overstress | implemented | GF:14.1.4.2; SKY:hv; TR22:4.1; CAL | FR; CF; SY |
| ERC-F3 | Junction / drain-source overstress | implemented | SKY:hv; IHP:process spec | FR; SY |
| ERC-F4 | HCI susceptibility flag | partial | GF:14.1.4.1; CAL:WP 81822 Eq.1 | SY; NV; MR |
| ERC-F5 | TDDB/BTI/HCI lifetime | implemented | JEP122; JESD263; JESD241; JESD28; JESD60 | CF; MR; SY |
| ERC-F6 | Missing level shifter | implemented | CAL:WP 81822; IEEE1801 | SY; NV |
| ERC-F7 | Missing isolation at switchable-domain outputs | implemented | IEEE1801; CPF | SY; NV |
| ERC-F8 | Power-state-dependent undriven gates | implemented | CAL:WP 81822; IEEE1801; IA | SE:Siemens WP; SY; NV |
| ERC-F9 | DC / sneak path between domains | implemented | CAL:datasheet; CAL:WP 81822 | SE:WP Fig2; SY |
| ERC-F10 | HV tag consistency | implemented | SKY:hv.X.1,hvnwell.9,hvnwell.10; GF:DV.9 | FR; SY; MR |
| ERC-F11 | Voltage-dependent spacing | implemented | (see DRC-082) | SY; MR |
| ERC-F12 | Well / body bias | implemented | GF:LU.9,LU.10 | SY; NV |
| ERC-F13 | Inter-metal dielectric breakdown | implemented | ICV; JEP159A | CF; SY; MR |
| ERC-F14 | Power-intent supply connectivity (power switches, always-on and retention cells on the supplies the UPF declares) | partial | IEEE1801; Liu-DVCon; ISLPED2014 | SY; MR |
| ERC-G2 | Floating well | implemented | SKY:nwell.4 | FR; SY; MR |
| ERC-G4 | Supply short (n-tie + p-tie, VDD-GND) | implemented | CAL | SY; MR |
| ERC-G7 | Gate tied directly to a rail | implemented | CAL (weak sourcing) | SY; NV; MR |
| ERC-G9 | Path check: nets with no path to power or ground | implemented | CAL:ERC PATHCHK,LVS PATHCHK; ICsprout55; P12 | SY; NV; MR |
| ERC-H1 | Static leakage / HiZ / floating in power-down | implemented | IA | SY; NV |
| ERC-H2 | Analog constraints (symmetry, common centroid, matching, orientation, dummies, WPE, STI) | partial | CAL:PERC packaged; ICV:NDL; PEG:Constraint Validator; GF:10.6.2 MP.1-MP.13; Karmokar2022; Sarhan2019; P14 | SY; MR |
| ERC-H3 | Netlist path checks (gate to ground within N devices; net types) | partial | CAL:patent P12; P9; US6367062 | SE; SY; NV; MR |
| ERC-H4 | Fanout limits | implemented | ICV; GF:14.1.4.1 | SY; NV |
| PEX-009 | PEX netlist diff / qualification | implemented | SIL:PEX Certify | CF; MR; SY |
| PEX-010 | SPEF output | implemented | IEEE1481 | CF; SE; MR; golden |
| PEX-011 | Device-region (MEOL/FEOL) parasitics: gate-to-contact and gate-to-diffusion C, trench contact, via-location gate R | partial | SRC:datasheet | SY; MR |
| PEX-012 | Metal-fill treatment (floating or grounded fill, virtual fill) | partial | SRC:datasheet | CF; SY |
| PEX-013 | Substrate network extraction (substrate and well resistance and coupling) | partial | QNT:RFIC; SRC:datasheet | CF; MR; SY |
| PEX-015 | 3D-IC extraction (TSV, micro-bump, interposer, TSV-TSV coupling) | partial | SRC:datasheet; CAL:3DSTACK | CF; SY |
| PEX-016 | Point-to-point resistance and net-to-net coupling report between arbitrary points | partial | SRC:datasheet; CAL:PERC P2P | CF; NV |
| FLOW-001 | Geometric / hierarchy-invariant waivers | implemented | CAL:Auto-Waivers; PEG | SY; MR |
| FLOW-002 | Early / dirty-design staged runs | implemented | CAL:Recon; ICV:Explorer | SY; MR |
| FLOW-003 | SoC integration (macro sync, ports off grid, fill outside boundary, block/pad-ring overlap) | partial | ICV | SY; CF |
| FLOW-005 | In-design / live DRC | partial | CAL:RealTime; ICV:Live; PEG | FR; MR |
| FLOW-008 | Incremental / ECO re-verification (changed regions or nets only) | partial | PEG; SRC:datasheet | MR; SY |
| FLOW-009 | Automated DRC-clean layout enhancement (via and power-grid insertion) | partial | CAL:DesignEnhancer | SY; MR |
| FLOW-010 | Clustering and triage of very large result sets | partial | CAL:Vision AI | SY; NV |

<!-- end of generated block -->

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
