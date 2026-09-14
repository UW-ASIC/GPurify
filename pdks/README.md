# `pdks/` — the shipped rule decks

Four decks in the `DeckJson` schema that `gpurify_ingest::deck::parse_deck`
reads. Each file has exactly five top-level keys, in this order:

```
layers  rules  connectivity  device_recognition  pex
```

`tests/pdk_decks.rs` is the guard. It globs `pdks/*.json`, so a fifth deck is
picked up with no edit, and it asserts the glob is non-empty so a vacuous pass
is not available. Six properties per deck: both rule sets build; the deck files
at least one rule and every rule lands in exactly one domain; every layer a rule
names resolves; every conductor and via cut carries a sheet resistance; the
`pex` stack (when present) has one row per declared layer; both ends of every
via are declared conductors.

**None of these decks is sign-off quality, and none should be used as one.**
They exist to exercise the pipeline end to end against numbers of roughly the
right magnitude. What is missing is enumerated below; that list, not the rule
counts, is the useful part of this file.

---

## What is missing from every deck

Read this before the per-PDK sections. These four apply to all four files.

**No revision is pinned.** Not one deck records which PDK release, document
revision or DRM version its numbers were transcribed from. The schema has no
field for it, so provenance was not dropped — it was never representable. Any
number here is unverifiable against its source without re-deriving it. Treat
every limit as *approximately right, unattributed*.

**`supply_short` is configured by zero of the four.** `gpurify_erc` has the
table and the dispatch arm; no shipped deck files a row into it, so the rule is
dead in practice across the whole tree. A cross-domain short between two supply
nets goes unreported by every deck here.

**Area limits are floored and therefore fail open.** `min_area`,
`min_enclosed_area` and `cheesing` state their limit as the *side of the
equivalent square*, squared by `crates/drc/src/ruleset.rs:228`. Real PDK areas
have no integer square root, so each transcription floors one, and the enforced
limit sits up to `2·side − 1` nm² below the real one. Worst case in this
directory is `sky130.nsdm_min_area` at 514 nm: 1027 nm² of area (0.39 %) that
the rule will pass and the foundry will not. Documented at `ruleset.rs:166-176`
as a known encoding cost; recorded here as what it is, a fail-open direction.

**`DeviceKind::Diode` recognises with the wrong terminal names.**
`role_at` in `crates/topology/src/device.rs` holds a role table for `Mos` and
`Bjt` only; `Resistor`, `Capacitor` and `Diode` fall through to
`TerminalRole::Pin(position)`. For the first two that is the right answer rather
than a gap — `Pin` is documented as either end of a *symmetric* two-terminal
device, interchangeable by definition, and both `crates/topology/tests/devices.rs`
and `crates/lvs/tests/graph.rs` assert the variant while deliberately leaving the
index open, so a layout resistor and a netlist resistor compare.

A diode is not symmetric, so `Pin` is genuinely wrong there: fixing it needs
`Anode`/`Cathode` on `TerminalRole` and a third row in the table. `gf180mcu` and
`ihp_sg13g2` are the decks that carry a diode recogniser.

---

## `sky130.json`

**Source.** SkyWater SKY130 open PDK, transcribed from its public design-rule
documentation. No revision pinned.

**Grid.** Requires a **1 nm** grid (`Grid::new(1000)`). Not a preference —
fourteen limits are not multiples of 5 nm, and `parse_deck` refuses a limit that
is not an exact multiple of the grid. At 5 nm it fails on `li_min_area: limit
236 nm is not an exact multiple of the grid`. All fourteen are floored area
sides (236, 288, 374, 489, 504, 514); the periphery limits alone would tolerate
5 nm.

**Shape.** 21 layers · 9 conductors · 8 via cuts · 15 `pex` rows · 2 device
recognisers (nfet\_01v8, pfet\_01v8).

**Rules: 114 total — 107 DRC, 7 ERC.**

| domain | kinds configured |
|---|---|
| DRC (14 of 24) | min\_width 21, min\_spacing 21, notch 15, min\_area 10, min\_enclosure 9, max\_width 6, min\_enclosed\_area 6, asymmetric\_enclosure 6, wide\_dependent\_spacing 4, min\_spacing\_diff 3, min\_extension 2, overlap 2, off\_grid 1, angle 1 |
| ERC (7 of 19) | floating\_gate 1, floating\_well 1, ir\_drop 1, multiple\_drivers 1, soft\_connection 1, tie\_high\_low 1, unconnected\_pin 1 |

**Deliberately not applicable.** `multi_patterning` — 130 nm single-exposure,
there is no colouring to check.

**Unsourced gaps** (21). DRC: `min_edge_length`, `eol_spacing`, `prl_spacing`,
`corner_to_corner`, `cheesing`, `density`, `max_distance_to_tap`,
`redundant_via`, `via_array_spacing`. ERC: `antenna`, `antenna_electrical`,
`density_cmp`, `electromigration`, `em_current_density`, `esd_latchup`,
`esd_topological`, `hv_domain`, `missing_tie`, `p2p_resistance`, `reliability`,
`supply_short`.

Two of those matter more than the rest. **`antenna` is absent**, and sky130 has
a published antenna rule set — this deck runs zero antenna checks and reports
clean, which is the fail-open shape this project is built to avoid. **`density`
is absent** for every metal, so CMP density is unchecked. `hv_domain` is a gap
rather than N/A: sky130 ships 5 V devices and this deck declares none of them.

---

## `gf180mcu.json`

**Source.** GlobalFoundries GF180MCU open PDK, transcribed from its public
design-rule manual. No revision pinned.

**Grid.** No resolution declared, and every `nm` value is a multiple of **5**,
so it loads against any grid dividing 5 nm — verified identical at 200, 1000 and
2000 dbu/µm. The refusal is live: at 100 dbu/µm (10 nm) it fails on `DF.10:
limit 505 nm is not an exact multiple of the grid`, which is the file's tightest
single constraint.

**Shape.** 38 layers · 8 conductors · 7 via cuts · 14 `pex` rows · 6 device
recognisers (nmos/pmos\_3p3, nmos\_6p0\_nat, one capacitor, one resistor, one
diode).

**Rules: 136 total — 112 DRC, 24 ERC.**

| domain | kinds configured |
|---|---|
| DRC (16 of 24) | min\_width 22, min\_spacing 22, min\_enclosure 13, min\_area 11, notch 8, max\_width 7, wide\_dependent\_spacing 6, density 6, via\_array\_spacing 6, min\_enclosed\_area 4, min\_extension 2, min\_spacing\_diff 1, overlap 1, max\_distance\_to\_tap 1, off\_grid 1, angle 1 |
| ERC (10 of 19) | antenna 12, em\_current\_density 4, esd\_topological 1, floating\_gate 1, floating\_well 1, hv\_domain 1, ir\_drop 1, multiple\_drivers 1, tie\_high\_low 1, unconnected\_pin 1 |

**Deliberately not applicable.** `multi_patterning` (180 nm, single exposure);
`asymmetric_enclosure` (this deck's via enclosures are all symmetric — a real
absence rather than a missing transcription, but unverified against the DRM).

**Unsourced gaps** (15). DRC: `min_edge_length`, `eol_spacing`, `prl_spacing`,
`corner_to_corner`, `cheesing`, `redundant_via`. ERC: `antenna_electrical`,
`density_cmp`, `electromigration`, `esd_latchup`, `missing_tie`,
`p2p_resistance`, `reliability`, `soft_connection`, `supply_short`.

Three transcription compromises carried in from the drafts, all still present:

- `ANT.1` names `poly2` twice. `layers_from(2)` accepts duplicates
  (`crates/erc/src/ruleset.rs:483`), so it parses, but the second slot is not
  the layer the real rule names.
- The six `via_array_spacing` rows use `array_threshold: 15` as a stand-in for
  "4×4 or larger". Fail-closed direction, wrong number.
- `hv_domain_3p3`'s 3630 mV is arithmetic (3.3 V × 1.1), **not a quoted foundry
  limit**.

---

## `ihp_sg13g2.json`

**Source.** IHP SG13G2 130 nm SiGe BiCMOS open PDK, transcribed from its public
design rules. No revision pinned.

**Grid.** Requires a **1 nm** grid (`Grid::new(1000)`). Six limits are not
multiples of 5 nm — all floored area sides (349, 379, 387). At 5 nm it fails on
`activ_min_area: limit 349 nm is not an exact multiple of the grid`. The
periphery limits alone (`manufacturing_grid.pitch = 5`,
`metal2_enclosure_of_via1 = 5`) would tolerate 5 nm.

**Shape.** 49 layers · 9 conductors · 8 via cuts · 16 `pex` rows · 5 device
recognisers (sg13\_lv\_nmos/pmos, npn13G2, res\_rsil, one capacitor).
`connectivity.vias` lists `cont` twice; nothing dedups the cut layer, and that
is the intended split of the old three-way entry into two `(a, b)` pairs.

**Rules: 177 total — 152 DRC, 25 ERC.**

| domain | kinds configured |
|---|---|
| DRC (15 of 24) | min\_width 26, min\_spacing 23, min\_enclosure 17, notch 15, max\_width 14, density 12, wide\_dependent\_spacing 10, min\_area 9, asymmetric\_enclosure 9, min\_spacing\_diff 5, via\_array\_spacing 5, min\_extension 3, min\_enclosed\_area 2, off\_grid 1, angle 1 |
| ERC (9 of 19) | antenna 14, em\_current\_density 4, esd\_topological 1, floating\_gate 1, ir\_drop 1, multiple\_drivers 1, soft\_connection 1, tie\_high\_low 1, unconnected\_pin 1 |

**Deliberately not applicable.** `multi_patterning` (130 nm, single exposure).

**Unsourced gaps** (18). DRC: `min_edge_length`, `eol_spacing`, `prl_spacing`,
`corner_to_corner`, `cheesing`, `overlap`, `max_distance_to_tap`,
`redundant_via`. ERC: `antenna_electrical`, `density_cmp`, `electromigration`,
`esd_latchup`, `floating_well`, `hv_domain`, `missing_tie`, `p2p_resistance`,
`reliability`, `supply_short`.

`floating_well` and `max_distance_to_tap` are the two worth flagging: this deck
declares `nwell` and declares no well-tap rule and no floating-well check, so a
well left unconnected is silent. `hv_domain` is a gap too — SG13G2 has a 3.3 V
domain alongside the 1.5 V core and this deck models neither boundary. It is
also the only deck with a BJT recogniser and it configures no bipolar-specific
rule of any kind.

---

## `generic_finfet.json`

**Source. None. Every value in this file is illustrative.** It is not a
transcription of any foundry PDK and must never be read as one. It exists for a
single purpose: to be the one deck that files at least one rule into *every*
kind, so the dispatcher, the rule tables and the report path are all exercised.
Its numbers are plausible-looking, not correct.

**Grid.** No resolution declared; every `nm` value is a multiple of **5**, so it
loads on any grid dividing 5 nm. The smallest value in the file is 5
(`manufacturing_grid.pitch`).

**Shape.** 17 layers · 8 conductors · 7 via cuts · 14 `pex` rows · 2 device
recognisers (nfet, pfet).

**Rules: 105 total — 69 DRC, 36 ERC.**

| domain | kinds configured |
|---|---|
| DRC | **all 24**: min\_width 17, min\_spacing 17, min\_area 7, min\_enclosure 4, and 2 each for max\_width, min\_spacing\_diff, notch, density, 1 each for the other sixteen |
| ERC (18 of 19) | antenna 8, electromigration 5, em\_current\_density 5, reliability 3, soft\_connection 2, and 1 each for antenna\_electrical, density\_cmp, esd\_latchup, esd\_topological, floating\_gate, floating\_well, hv\_domain, ir\_drop, missing\_tie, multiple\_drivers, p2p\_resistance, tie\_high\_low, unconnected\_pin |

**Deliberately not applicable.** Nothing — the file's whole job is total kind
coverage.

**Unsourced gaps.** `supply_short` is the one kind it does not reach, which is
why no deck in the tree does. And, restating the header: **all 105 rules are
unsourced.** Coverage here is coverage of the dispatcher, not of any process.

Structural gaps this file exposes that the schema cannot express:

- `nwell` is not a conductor, so no well is in the resistance network.
- No diode, isolation or p-tap marker exists, so the ESD and latchup rules run
  against a topology that cannot contain the structures they look for.
- Via cut `sheet_res_ohm_sq` is ohms *per cut*, not ohms per square, reusing a
  field whose name says otherwise.
- The `pex` per-layer caps and the via stack are not reconciled against each
  other; nothing checks that they describe the same stack.

---

## Cross-deck coverage

`·` = configured, `—` = not configured. 43 kinds; `supply_short` is the only row
empty across the board.

| kind | finfet | gf180 | ihp | sky130 |
|---|:-:|:-:|:-:|:-:|
| **DRC** | | | | |
| min\_width, min\_spacing, min\_area, min\_enclosure, min\_enclosed\_area, min\_extension, max\_width, notch, min\_spacing\_diff, wide\_dependent\_spacing, off\_grid, angle | · | · | · | · |
| density | · | · | · | — |
| via\_array\_spacing | · | · | · | — |
| asymmetric\_enclosure | · | — | · | · |
| overlap | · | · | — | · |
| max\_distance\_to\_tap | · | · | — | — |
| min\_edge\_length, eol\_spacing, prl\_spacing, corner\_to\_corner, cheesing, redundant\_via, multi\_patterning | · | — | — | — |
| **ERC** | | | | |
| floating\_gate, ir\_drop, multiple\_drivers, tie\_high\_low, unconnected\_pin | · | · | · | · |
| antenna | · | · | · | — |
| em\_current\_density | · | · | · | — |
| esd\_topological | · | · | · | — |
| soft\_connection | · | — | · | · |
| floating\_well | · | · | — | · |
| hv\_domain | · | · | — | — |
| antenna\_electrical, density\_cmp, electromigration, esd\_latchup, missing\_tie, p2p\_resistance, reliability | · | — | — | — |
| supply\_short | — | — | — | — |

Seven DRC kinds and seven ERC kinds are configured *only* by the illustrative
deck. Whatever those fourteen rules do, no real process has ever exercised them
here.
