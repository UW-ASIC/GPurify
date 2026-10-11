# The fixture corpus

One GDSII library, one deck, and two files of expectations.

```
_source/conformance.gds   every cell, in one file
drc/  erc/  lvs/  pex/    94 + 30 + 16 + 27 single-case extracts, generated at test time
params.deck               the deck: layers, rules, limits, connectivity, process stack
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

The corpus's known weakness: of the 94 DRC cases, 45
expect zero violations, and in the old suite an empty violation table was also
what a rule that never ran produced. `report::RuleRun` can finally tell the
difference, so every case here carries `expect_outcome` and `examined_min`
alongside the count.

That fixes most of them. It does not fix all of them, and the file says so
rather than pretending. `strength` grades each case:

| `strength` | meaning | count |
|---|---|---:|
| `strong` | rule ran, jurisdiction non-empty, measurement approaches the limit | 122 |
| `underivable` | nothing determines the answer | 11 |
| `blocked` | derivation sound, corpus or frozen interface prevents reaching it | 9 |
| `vacuous` | rule ran but never approached the limit | 7 |
| `skipped` | rule recorded `Skipped`; a clean count here is a false clean | 7 |
| `weak` | rule ran with a legitimately empty jurisdiction, or right for an unrelated reason | 6 |
| `refused` | rule fails closed on this input; assert `Refused`, never a clean `Ran` | 5 |

Nine cases (`DRC_WDS_PASS`, `DRC_VAS_PASS`, `DRC_EOL_SIDE`, `DRC_EOL_WIDE`,
and five like them) have `examined = 0` for a *correct* reason: the rule
defines `examined` as the population it had jurisdiction over — pairs with a
wide member, pairs in a qualifying cluster, pairs with an end of line — and the
fixture was built so that population is empty. `examined_min > 0` cannot be
asserted on them. Their non-vacuity evidence is the candidate count, which no
frozen signature exposes.

## What the corpus proves

`tests/doc_counts.rs` recomputes every number in this section from
`expectations.json` and fails when one goes stale.

How each case's derived answer compares with the old implementation's
(`corroboration`):

| domain | cases | manifest agrees | count only | disagrees | partial | uncheckable | no manifest entry |
|---|---:|---:|---:|---:|---:|---:|---:|
| drc | 94 | 71 | 11 | 12 | 0 | 0 | 0 |
| erc | 30 | 11 | 6 | 11 | 0 | 0 | 2 |
| lvs | 16 | 14 | 0 | 2 | 0 | 0 | 0 |
| pex | 27 | 19 | 0 | 3 | 2 | 3 | 0 |
| **total** | **167** | **115** | **17** | **28** | **2** | **3** | **2** |

"count only" means the manifest carried a violation count but no measurement,
so only the count could be compared; the measurement in `expectations.json` is
new.

Disagreement on the *number* and disagreement on the *meaning* are not the same
thing, so `dispute` is tracked separately from `corroboration`. A refusal and a
clean check both report zero, so a case can agree with the manifest's count
while disagreeing with what it means. The split is the point:

| `dispute` | meaning | cases |
|---|---|---:|
| `manifest_wrong` | the old implementation got it wrong; the derivation stands | 10 |
| `convention` | the old tree reported per side where the frozen doc says per pair | 2 |
| `not_a_rule` | the manifest states a claim that is not a rule kind | 2 |
| `fixture_out_of_domain` | geometry outside what a rectilinear-only tree represents; it fails closed | 2 |
| `code_wrong` | the manifest is physically right and the implementation cannot reach it (`known_defects`) | 3 |
| `fixture_incomplete` | the fixture cannot express the premise (no cell draws a `licon`) | 5 |
| `no_intent_fixture` | an intent-gated rule with no design-intent file | 14 |
| `no_deck_coefficient` | a coupling value with no coefficient column in the process stack | 4 |
| `deck_gap` | a tap that cannot be spelled as a derived layer | 1 |
| `signature_defect` | a condition a frozen signature makes unsatisfiable | 1 |
| **total** | | **43** |

Cases expected to fail are explained under `known_defects` and
`blocking_findings` at the top of `expectations.json`. Weakening them to match
the code would erase the finding.

LVS cases assert device and net counts, and their verdict against their own
reference netlist in `lvs_refs/<id>.spice`. Each reference was transcribed once
from the manifest's `reference_netlist` for that case, the schematic the case was
designed around (an input, not an answer), and is reviewed like any fixture. The
three HVT/LVT cases are expected to fail until device flavour is recognised
(blocking finding F6), and the harness reports it if one starts to hold.

## Using it

`expectations.json` is table-driven. Per case: `id`, `cell`, `domain`, the rule
or check, `expect_violations`, `expect_outcome`, `examined_min`, and for
positive cases the `measured` value and the `at` coordinate in dbu.

**Read `assert` before asserting anything.** It lists the only claims derivable
for that case. A field absent from it was not derivable and must not be
checked. `known_defects` and `blocking_findings` at the top of the file explain
every case that is expected to fail, and name the file and function to fix.

In the release tier, `tests/klayout` also runs every DRC cell through the
KLayout mirror deck ([klayout-mirror.md](../../docs/klayout-mirror.md)) and
compares rule by rule.

`manifest.json` stays exactly as it is. It is the historical record and the
thing `expectations.json` is checked against; overwriting it would destroy the
ability to see what changed.
