# The fixture corpus

161 GDSII files, one deck, and two files of expectations.

```
_source/conformance.gds   every cell, in one file
drc/  erc/  lvs/  pex/    94 + 23 + 16 + 27 single-cell extracts of the same cells
params.json               the deck: layers, rules, limits, connectivity, process stack
klayout/drc_oracle.rb     a KLayout script from the old tree; not used by this suite
manifest.json             the OLD tree's answers. Historical record. Do not edit.
expectations.json         the re-derived answers. What the harness reads.
```

## Where it came from

The corpus was built for the implementation that was deleted at the start of
this rewrite. The old tree is **not an oracle** —
the new tree is validated against physics. Routing the old answers back in
through a manifest would defeat that quietly, which is why the corpus is split
in two and the halves are kept apart.

**The GDS files are data.** Real layout. Cells drawn with deliberate defects:
`DRC_MW_FAIL` is a narrow wire because someone drew it narrow, and geometry
cannot be wrong about itself. Reuse them freely.

**`manifest.json`'s expectations are the old implementation's output.** Every
number in it is a *claim to be checked*, never the answer.

## How `expectations.json` was produced

Every case was derived twice over and only then compared:

1. Read the cell's geometry directly out of the GDS.
2. Apply the rule's **frozen doc comment** — its reporting point, its
   measurement, its `examined` population, its `Outcome` on bad input.
3. Compute what the result must be.
4. Compare with `manifest.json`, and record the comparison in
   `corroboration` — never fold it into the value.

A case that agrees with the manifest now rests on physics and has two
independent routes to the same number. A case that disagrees keeps the derived
value and names, in `dispute`, which side is wrong and why. Nothing was quietly
adopted from either side.

**Every case is kept.** A case nobody could derive is marked
`"provenance": "underivable"`, and its `assert` list names the only claims the
harness is entitled to check. Silently dropping the hard cases would be the
same failure as trusting them.

### The 45 vacuous DRC cases

`docs/TESTING.md` records the corpus's known weakness: of the 94 DRC cases, 45
expect zero violations, and in the old suite an empty violation table was also
what a rule that never ran produced. `report::RuleRun` can finally tell the
difference, so every case here carries `expect_outcome` and `examined_min`
alongside the count.

That fixes most of them. It does not fix all of them, and the file says so
rather than pretending. `strength` grades each case:

| `strength` | meaning | count |
|---|---|---:|
| `strong` | rule ran, jurisdiction non-empty, measurement approaches the limit | 109 |
| `weak` | rule ran with a legitimately empty jurisdiction, or right for an unrelated reason | 9 |
| `vacuous` | rule ran but never approached the limit | 11 |
| `blocked` | derivation sound, corpus or frozen interface prevents reaching it | 13 |
| `refused` | rule fails closed on this input; assert `Refused`, never a clean `Ran` | 11 |
| `skipped` | rule recorded `Skipped`; a clean count here is a false clean | 2 |
| `underivable` | nothing determines the answer | 5 |

Nine cases (`DRC_WDS_PASS`, `DRC_VAS_PASS`, `DRC_EOL_SIDE`, `DRC_EOL_WIDE`,
and five like them) have `examined = 0` for a *correct* reason: the rule
defines `examined` as the population it had jurisdiction over — pairs with a
wide member, pairs in a qualifying cluster, pairs with an end of line — and the
fixture was built so that population is empty. `examined_min > 0` cannot be
asserted on them. Their non-vacuity evidence is the candidate count, which no
frozen signature exposes.

## What the corpus proves

160 cases. 114 of them are corroborated by physics — the manifest and the
derivation agree. 33 disagree or could not be checked, and each one is a
finding rather than a number to pick.

| domain | cases | manifest agrees | count only | disagrees | uncheckable | underivable |
|---|---:|---:|---:|---:|---:|---:|
| drc | 94 | 66 | 13 | 15 | — | 0 |
| erc | 23 | 12 | 2 | 9 | — | 2 |
| lvs | 16 | 16 | — | 0 | — | 0 |
| pex | 27 | 20 | — | 3 | 3 (+1 partial) | 3 |
| **total** | **160** | **114** | **15** | **27** | **3** | **5** |

"count only" means the manifest carried a violation count but no measurement,
so only the count could be compared; the measurement in `expectations.json` is
new.

Disagreement on the *number* and disagreement on the *meaning* are not the same
thing, so `dispute` is tracked separately from `corroboration`. Four cases
agree with the manifest's count while disagreeing with what it means — a
refusal and a clean check both report zero. 38 cases carry a `dispute`, and the
split is the point:

- **13 where the old implementation is superseded.** 7 it simply got wrong
  (`manifest_wrong`), 2 reported per-side where the frozen doc says per-pair
  (`convention`), 2 state a claim that is not a rule kind at all
  (`not_a_rule`), and 2 draw geometry outside what this rectilinear-only tree
  represents, where it fails closed (`fixture_out_of_domain`). The derivation
  stands.
- **9 where the manifest is physically right and the frozen implementation
  cannot reach it** (`code_wrong`) — four named defects, listed under
  `known_defects`. The expectation is the physics, and those cases are expected
  to fail until the defect is fixed. Weakening them to match the code would
  erase the finding.
- **6 the fixture cannot express** (`fixture_incomplete`). Almost all of these
  are one missing layer: **no cell in the corpus draws a `licon`**, so `li`
  never contacts `poly` or `diff`, and every case whose premise is "a strap
  ties X to Y" extracts two separate nets instead.
- **10 blocked by the deck or the frozen interface** — 4 intent-gated rules
  with no design-intent file, 4 coupling values with no coefficient column in
  the process stack, one tap that cannot be spelled as a derived layer, one
  condition a frozen signature makes unsatisfiable. All under
  `blocking_findings`.

LVS is the one domain where every claim held: all 16 `expect_match` booleans
are corroborated by the geometry. Five of them still cannot be reached, because
series/parallel reduction and device flavour have no representation in the
frozen interface.

## Using it

`expectations.json` is table-driven. Per case: `id`, `cell`, `domain`, the rule
or check, `expect_violations`, `expect_outcome`, `examined_min`, and for
positive cases the `measured` value and the `at` coordinate in dbu.

**Read `assert` before asserting anything.** It lists the only claims derivable
for that case. A field absent from it was not derivable and must not be
checked. `known_defects` and `blocking_findings` at the top of the file explain
every case that is expected to fail, and name the file and function to fix.

`manifest.json` stays exactly as it is. It is the historical record and the
thing `expectations.json` is checked against; overwriting it would destroy the
ability to see what changed.
