# Mutation baseline

Per-file scores, recorded as each module is rewritten. Referenced by
`docs/TESTING.md`. A full-workspace run is not viable (12,830 mutants, 20+ h
even at `-j16`), so this is built up file by file instead.

Mutation testing is a **post-processing cleanup pass per crate**, never inside
the edit loop. Run it after a module's tests are otherwise complete:

```sh
nix develop -c bash -c 'cd crates_clean && cargo mutants --package gdsverify-core -j 8 --timeout 120 -f <file>'
```

A survivor is a missing test **or** an equivalent mutant. Decide which, every
time — a contrived test against an equivalent mutant inflates the score without
adding safety, and recording an equivalent one as a survivor makes the number
lie. Equivalent mutants are documented **at the site in the source**, so they
are not re-litigated on the next run.

---

## crates_clean/core — 2026-08-01

`407 mutants tested in 38s: 367 caught, 36 missed, 4 unviable`

| file | caught | missed | unviable | status |
|---|---|---|---|---|
| `src/units.rs` | 46 | **0** | 0 | done |
| `src/geometry/bbox.rs` | 34 | 4 | 3 | done — all 4 misses are documented equivalents |
| `src/geometry/ops.rs` | 287 | 32 | 1 | **32 open**, see below |

Not yet run: `geometry/{store,rects,sweep,edge,ids,cold}.rs`, and everything
under `exact/`, `connectivity`, `hierarchy_index`, `sort_scan`, `io`.

### Documented equivalents

- `bbox.rs:92-95`, `+` → `*` (×4). Sentinel becomes `MAX_ABS_DBU * 1 ==
  MAX_ABS_DBU`. The ingest guard bounds every legal coordinate by
  `|c| <= MAX_ABS_DBU`, so the sentinel already dominates the whole domain with
  equality and every `include`/`union` fold is bit-identical. The `+ 1` is
  margin, not correctness. Proof recorded at `bbox.rs:91-107`.
  Note the asymmetry: `+` → `-` is **not** equivalent — the sentinel would stop
  dominating and a point at exactly `±MAX_ABS_DBU` folds wrong. Pinned by
  `folding_a_point_at_the_domain_edge_is_exact`.

### Open: 32 survivors in `geometry/ops.rs`

These are real gaps in genuine geometric predicates, not equivalents. Surfaced
by widening the run's file scope; they were never in the earlier 12.

| function | survivors | why it matters |
|---|---|---|
| `segments_intersect` | ~11 | intersection classification feeds polygon validity and boolean topology |
| `poly_self_intersects_into` | ~9 | the simplicity guarantee `Ring`/`Polygon` are built on |
| `point_in_poly` | ~6 | containment; used for hole-to-outer assignment |
| `clipped_area_into` | 1 | `+=` → `-=`; density rules |
| `isqrt` | 1 | `<` → `<=`; an off-by-one here already broke 3 tests in the original tree |
| boundary comparators | few | — |

`point_seg_dist2` is now 100% caught.

---

## crates/ (original tree) — hand-probed, 2026-08-01

Not a `cargo mutants` run; 6 hand-written mutations, 5 caught.

Inverting `Ring::winding` broke 31 tests; flipping `MinWidth`'s comparison broke
1; an `isqrt` off-by-one broke 3. The core geometry and DRC paths are better
covered than the fixture manifest suggests.

**The one survivor:** `Bbox::within`/`overlaps` (`geometry/bbox.rs:71`).
Making the closed-interval proximity test strict on one axis — "touch or
overlap" becoming "strictly overlap", shifting every spacing prune by one DBU —
produced **zero failures across all 403 tests**. Invisible because every
consumer re-verifies exactly afterwards, so a wrong prune costs correctness
margin silently instead of failing. This is why `bbox.rs` was the first file
rewritten and the first mutation-tested.

One mutation was discarded as **provably equivalent** rather than recorded as a
survivor: in `rectilinear_occupancy`, `ylo*2 < cy2` → `<=` is unreachable
because `cy2 = ys[y] + ys[y+1]` falls strictly between two grid lines.

**ERC, LVS and PEX were never probed.** Their coverage is unmeasured and should
not be assumed to resemble DRC's — they assert counts and aggregate sums only.
