# KLayout mirror deck: per-kind translation of GPurify DRC into KLayout 0.30.8

Research for `docs/testing-plan.md` §4 L6, "Mirror deck", and the record of what the
translator settled (ledger F1).

- **The translator** is `tests/klayout/translate.rs`: a parsed deck becomes a KLayout DRC script,
  one emitter per DRC kind (an exhaustive `match` on `drc::Rule`, so a new kind does not build
  until it has one).
- **The differential** is `tests/klayout/main.rs`. It runs GPurify and the mirror on the same GDS
  and deck and compares rule by rule (`tests/klayout/compare.rs`) on every corpus DRC cell, on
  every DRC fixture of `tests/exhaustive` at the merge depth (dimension, overlay, bitmap), and on
  3000 seeded random layouts over a deck with a rule of every mirrored kind. It is the release
  tier: `nix develop .#oracles --command cargo test --test klayout -- --ignored`. The merge tier
  runs only `every_shipped_deck_translates`.

GPurify semantics come from the code at HEAD: `crates/check/src/drc/{ruleset.rs,rules/*.rs}`,
`crates/geom/src/{boolean.rs,derive.rs,width.rs}`, `crates/ingest/src/layout.rs`, `docs/deck.md`.
Function names are cited rather than line numbers, because the files are being edited concurrently.

The markers mean:
- **(v)**: verified by running KLayout 0.30.8 in batch mode (`nix develop .#oracles`). The
  scripts are in `tools/klayout/experiments/t1.drc … t18.drc`, with the test id in brackets.
- **(x)**: held by the differential on the corpus, the fixtures and the random layouts.
- **(d)**: taken from the KLayout documentation only.

KLayout pages cited:
[L] = `https://www.klayout.de/doc-qt5/about/drc_ref_layer.html` (Layer methods),
[G] = `…/drc_ref_global.html`, [X] = `…/drc_ref_drc.html` (DRC expressions),
[N] = `…/drc_ref_netter.html`, [S] = `…/drc_ref_source.html`,
[R] = `https://www.klayout.de/doc-qt5/code/class_Region.html`.

---

## (a) Global conventions

### a1. Units, and running at ×2

- **GPurify.** Deck lengths in nm are converted exactly to layout DBU when the deck loads
  (`deck/parse.rs` `length`, `area`), so every limit is an integer number of DBU and every area
  an integer number of DBU². The translator emits integers only.
- **KLayout.** An Integer argument is in DBU and a Float is in µm ([L] "width": "Distance values
  can be given as floating-point values (in micron) or integer values (in database units)").
  - (v T1) `width(100)` on a 100-DBU line gives no error; `width(101)` gives one.
  - (v T15) `with_area(nil, 100000)` excludes a box of 120000 DBU², so integer areas are DBU².
- **Run the whole mirror on a ×2 copy:** `src = source(gds).global_transform(magnify(2))`
  ([S] "global_transform", spec `magnify(m)`; (v T12) the doubling is exact).
  - Emit every length as 2·L and every area as 4·A.
  - Every half-length that GPurify implies then becomes an integer: `sized(-limit/2)` for
    `max_width`, `(t-1)/2` for wide parts, `limit/2` for cluster growth.
  - Distances compare the same way (`d < L ⇔ 2d < 2L`), and density ratios are unchanged.
  - The harness halves every output coordinate, flooring as GPurify floors a midpoint.
- **Put `flat` first** ([G] "flat"). With no tiling and no deep mode, flat `Region` semantics
  apply.

### a2. Loading layers

- **Drawn polygon layers:** `src.polygons(L, D)`. Do not use `input`: it also fetches texts,
  which become 2×2 DBU dummy boxes ([L] "texts").
- **Text layers:** `src.labels(L, D)`. Both come back doubled on the ×2 source (x).
- **`ignore gds(L, D)` pairs:** never loaded. GPurify refuses a GDS with undeclared pairs, so the
  harness only feeds layouts GPurify accepted.
- **Derived layers:** translated as in (c), one variable per layer (`l<id>`), hidden layers
  included. GPurify stores each derived layer merged (`ingest/src/layout.rs`, derived loop),
  except `.extents()`, whose boxes are stored one row each and may overlap.
- **Derived edge layers are emitted `.merged`.** KLayout can split a run where the other
  operand's drawn shapes meet (v t18 Z6: `inside_part` splits an edge at the boundary between two
  overlapping shapes of the other layer), and GPurify's edge layer holds maximal runs.
- **`.raw` mutates the layer object** ([L] "raw": "this method will set the state of the layer").
  The translator calls it only on a `.dup`.

### a3. The corner model

- **Decided: Connected (ledger B20).** Corner contact joins material: two shapes that touch only
  at a corner are one figure, a ring closed only at a corner encloses a hole, and the touch point
  is a 0-width neck. That is KLayout's default merge, maximum coherence ([R] "min_coherence=":
  "The default setting is maximum coherence").
  - (v T2) Two squares touching at a corner merge into one polygon.
  - (v t18 Z1) The ring `###|#.#|.##` is one polygon *with* a hole at maximum coherence and one
    without at minimum coherence. F53 says KLayout's default leaves no hole; it leaves one.
  - (v t18 Z1) Euclidean `width` reports the touch point at 0, and a chain of squares joined at
    corners is one polygon whose gap `notch` reports (N1).
- **Mirror rule:** every layer at the default coherence, and no `without_touching_corners` on
  `width`. `min_coherence` is used only to detect a corner contact: the prelude's `figs` marks a
  layer whose figures differ between the two coherences (`{corner: layer}`).
- **GPurify since B20.** Booleans, merges, derived layers, spacing components and nets all
  join material at a corner (`boolean.rs` `successors_into` takes the right turn where four
  boundary edges meet). While F53 was open the differential attributed a disagreement on a
  layout with a corner contact to it (`compare::KNOWN`); F53 is fixed, so those layouts are
  compared like any other.
- **Trap:** a layer object is shared, so `min_coherence` is set on a `dup` (v t15, t17), and the
  DSL `merged` ignores it; `Region#merged` honours it.

### a4. Comparison unit: keys

GPurify reports `shapes: (row, row?)`, `at` and `measured`; KLayout reports polygons, edges and
edge pairs. Each side becomes a map from a key to the smallest measurement under it (GPurify
reports per drawn row or pair, KLayout per edge pair), and the maps are compared per rule. For
every layer a figure or pair rule reads, the script also writes that layer's figures
(`fig:<layer>`), so no GPurify code keys a KLayout result.

| Key | Kinds | From a GPurify finding | From a KLayout result |
|---|---|---|---|
| FIG by marker | min_width, max_width (the wide regions), min_area, cheesing, overlap (the figures of `A & B`), must_contain, must_be_inside | the figure holding `at` (closed, to within one grid step) | the figure holding the polygon's first vertex or the first edge's first point |
| FIG by shape | notch (`at` lies in the void), min_enclosure and asymmetric_enclosure (`at` lies in the strip outside the inner) | the figure holding the first vertex of `shapes.0` | the figure holding the inner layer's edge |
| PAIR | the spacing kinds, min_spacing_diff, min_extension, net_spacing | both shapes' figures | each edge's figure; an overlap polygon's vertex in both layers' figures |
| POINT | cut_size, min_enclosed_area (box centre), density (window centre), global_density (die centre), off_grid (vertex), edge_spacing (gap midpoint), edge_enclosure (edge midpoint) | `at` | the point, halved and floored |
| EDGE | min_edge_length, edge_min_length, forbidden on an edge layer | `at` and `measured` | the edge's floored midpoint and length |
| SEGMENT | angle | the edge from the marker vertex to the next vertex of `shapes.0` | the undirected edge |
| ROW | max_distance_to_tap, redundant_via, forbidden on a polygon layer | the bounding box of `shapes.0` | the polygon's bounding box |
| ROW PAIR | via_array_spacing | both shapes, by bounding box among the drawn cuts | each edge's drawn cut (whose boundary holds the edge's midpoint), or a pair the script names by index |

- A finding that maps to no figure fails the rule: two such keys would compare equal whatever
  they stand for.
- **Measured.** A distance is measured here from the edge pair's geometry, halved, and compared
  with GPurify's floored value to within 1 DBU. `EdgePair#distance` is not used: it is 0 for
  two degenerate edges, which a Euclidean neck between two corners gives at a limit just above
  the neck (v t18 Z2). Areas, counts and cut sides compare exactly, densities to 1e-9.
- **Comparisons.** EXACT: the same keys, the same measurement on each. An APPROX kind is
  compared by the bracket its section states: KLayout ⊆ GPurify (with GPurify's measurement no
  larger on a shared key), GPurify ⊆ KLayout, `lo ⊆ GPurify ⊆ hi`, or exact on a class of
  layouts and not compared off it.
- **Marker of the spacing kinds and via_array_spacing.** GPurify's `at` is the midpoint of the
  two nearest points the pair measured, the middle of their stretch where they run alongside
  (`nearest`; F66, fixed in B24, and for via_array_spacing F82, fixed in B26). Collinear pieces
  of one stretch that touch are merged first, so a side split by a vertex or by the rectangles a
  wide part is cut into is marked at the middle of the whole stretch (F92, fixed in B29). Equally
  long nearest stretches give the middle of the box bounding their midpoints (F82, fixed in B26).

The classes, detected by the script (`{rclass: layer}`) or by the harness from the figures:
- **R:** every shape on the layer is a rectangle, and no two touch or overlap, so rows = figures
  = boxes.
- **R+** (`min_extension`): both layers R, and every A that overlaps or touches a B lies inside
  it or runs strictly past it at both ends along one axis.

### a5. Limit equality

- **GPurify is strict everywhere** (`report/measure.rs` `Measurement::violates`: "a value exactly
  at its limit is legal under both senses").
- **KLayout classic checks flag `d < value` and never equality.** (v T1 `width`, T3 `isolated`
  40/41, T6 `separation` 50/51, T7 `enclosing` 30/31, T8 `overlap` 20/21.) The universal
  `drc(width <= v)` does include equality (v T1).
- **Selection ranges:**
  - `with_area`, `with_length` and `with_bbox_*` take [min, max) ([L] "with_area": "larger or
    equal to min and less (but not equal to) max").
  - `with_density` and `without_density` take a closed [min, max] (v t8, t9 D1/D2).
- **Bound translation** at ×2 (integers):

  | GPurify bound | KLayout length bound | KLayout area bound |
  |---|---|---|
  | `>= a` | min 2a | min 4a |
  | `> a` | min 2a+1 | min 4a+1 |
  | `< b` | max 2b | max 4b |
  | `<= b` | max 2b+1 | max 4b+1 |
  | `== a` | the single-value form | the single-value form |

  The deck stores every bound inclusive (`DerivedOp`), so the translator writes `[2lo, 2hi+1)`
  and `[4lo, 4hi+1)`.

### a6. Options pinned on every check

- **Metric.** Always explicit: `euclidian` or `projection`. Never rely on the default.
- **Shielding.**
  - `transparent` on every check between two figures. GPurify measures each pair on its own, so a
    thin shape between two others does not hide them. (v T3: `isolated(150)` finds 2 pairs
    shielded and 3 transparent.)
  - `shielded` on width (see kind 1).
  - Edge layers reject both options (v t16: "Shielding can only be used for polygon layers").
- **Touching shapes.** `separation`, `enclosing` and `overlap` report zero distance by default,
  for both abutting edges and touching corners ([L] "separation"; (v T6, T7, T8)). Keep that
  wherever GPurify counts d = 0 as a violation; add `without_touching_*` only where noted below.

### a7. Output

**JSON lines**, written by the prelude of `tests/klayout/translate.rs` (`PRELUDE`), one per
result object, integers in DBU of the ×2 layout:
- `{rule, ep: [e1, e2]}` an edge pair, `{rule, e}` an edge;
- `{rule, hull, holes, area[, v]}` a polygon, `v` being what the rule's block says of it (a
  count held, an area outside);
- `{rule, pt, v}` a density window or die; `{rule, rows: [i, j]}` two drawn cuts by index;
- the markers `{corner: layer}`, `{rclass: layer}`, `{bridge: cut layer}`, and `{error}`.

The test writes one script per batch of layouts: the prelude once, then per layout a
`begin … rescue … ensure … end` block that opens its output, binds `src`, defines every deck
layer, writes the figure sets, and runs one `begin … rescue … end` block per rule, so an error is
reported against its rule. `klayout -b -r <batch>.drc`; a few processes at a time, a round of
1000 layouts at a time.

**lyrdb, for people triaging** (not written by the translator). Call `report("mirror", $lyrdb)`
once, then `result.output(rule_id, description)` for each rule ([G] "report", [L] "output"). The
format (v t6 `out.lyrdb`):
- The file is `<report-database>`. Under `<categories>`, each `<category>` holds `<name>m1.1</name>`
  and `<description>`.
- Each result is an `<items><item>` with `<category>'m1.1'</category>`, `<cell>TOP</cell>` and
  `<values><value>…</value></values>`. A category name containing `.` is single-quoted, because
  `.` separates sub-categories.
- Values are text in µm (DBU × dbu), doubled under ×2: `polygon: (x,y;…/hx,hy;…)`,
  `edge: (x1,y1;x2,y2)`, `edge-pair: (e1)|(e2)` (`|` a symmetric pair, `/` a two-layer pair),
  `box: (l,b;r,t)`. The file does not store the dbu.

---

### a8. 45-degree layouts (H12)

`random_octilinear_layouts_agree_with_the_klayout_mirror` runs 1500 random layouts of
chamfered rectangles, octagons and 45-degree bars through the kinds that measure 45-degree
shapes (`width`, `notch`, `space` one layer and two, `area`, `hole_area`, `edge_length`,
`forbidden`, `angle`, and booleans feeding them), compared as each kind's verdict below states.
Three differences are documented, not defects, and the deck and lattice keep them out:

- **Snapping.** A boolean result vertex where a rising and a falling 45-degree edge cross between
  grid points is snapped by cutting the tip of its right angle (`boolean::union_into`);
  KLayout rounds the point to the nearest grid point. The layouts lie on a 10 nm lattice, so
  every crossing is on a 5 nm point of the 1 nm grid and nothing is snapped.
- **`sized` on a 45-degree edge.** GPurify's is the Minkowski sum with the square
  (`docs/deck.md`), which moves a diagonal edge `d·√2`; KLayout moves it `d`. The deck has no
  `sized` layer.
- **A chamfer's end and the far side.** KLayout's Euclidean `width` at its default
  `ignore_angle` pairs two edges at 135 degrees, such as a chamfer and the opposite side;
  GPurify's width is facing edges, necks and acute tips only (`width::narrowest_pair2`). The
  mirror passes `shielded`, under which the material between them shields such a pair; a
  remaining difference would show here as a disagreement.

## (b) Per kind

Notation in the snippets:
- `L`, `A`, `B`, `I` (inner), `O` (outer), `T` (tap), `C` (cut) and `E`, `F` (edge layers) are
  layers built per (a2) and (c).
- Uppercase literals are already doubled: `LIM` = 2·limit DBU, `AREA4` = 4·limit DBU².
- Any other scaling is stated next to the literal. Helpers (`figs`, `holes_below`, `density`,
  `extension`, `touching`, `edge_enclosure`, `with_width2`) are the prelude's.

The **found** column counts the comparisons, over the corpus, the fixtures and the random
layouts, where either side reported something (x); **known** counts those an open finding
explains (kind 30).

| # | Kind | Deck form | Key | Verdict | Compared as | Found / known |
|---|---|---|---|---|---|---|
| 1 | min_width | `width(L) >= l` | FIG by marker | EXACT | exact | 5764 |
| 2 | max_width | `width(L) <= l` | FIG by marker (wide regions) | EXACT | exact | 1202 |
| 3 | cut_size | `size(L) == w x h` | POINT | EXACT | exact | 3197 |
| 4 | min_edge_length | `edge_length(L) >= l` | EDGE | EXACT | exact | 1885 |
| 5 | notch | `notch(L) >= l` | FIG by shape | EXACT | exact | 900 |
| 6 | min_spacing | `space(L) >= l` | PAIR | EXACT | exact | 2329 |
| 7 | min_spacing_diff | `space(A, B) >= l` | PAIR | EXACT | exact | 2852 |
| 8 | eol_spacing | `eol_space(L; eol_width)` | PAIR | APPROX | KLayout ⊆ GPurify | 459 |
| 9 | prl_spacing | `prl_space(L; prl)` | PAIR | APPROX | exact on R, else KLayout ⊆ GPurify | 273 |
| 10 | corner_to_corner | `corner_space(L)` | PAIR | APPROX | exact on R, else GPurify ⊆ KLayout | 369 |
| 11 | wide_dependent_spacing | `wide_space(L; width)` | PAIR | EXACT | exact, same-figure pairs dropped | 1055 |
| 12 | min_area | `area(L) >= a` | FIG by marker | EXACT | exact | 2808 |
| 13 | min_enclosed_area | `hole_area(L) >= a` | POINT | EXACT | exact | 192 |
| 14 | cheesing | `cheesing(L) <= a` | FIG by marker | EXACT | exact | 1430 |
| 15 | density | `density(L[, bnd]; window, step)` | POINT | EXACT | exact | 3453 |
| 16 | global_density | `global_density(L[, bnd])` | POINT | EXACT | exact | 228 |
| 17 | min_enclosure | `enclosure(i, o) >= l` | FIG by shape (inner) | EXACT | exact | 4414 |
| 18 | asymmetric_enclosure | `enclosure(i, o, opposite) >= l` | FIG by shape (inner) | APPROX | exact when the inner layer is R, else KLayout ⊆ GPurify | 3085 |
| 19 | min_extension | `extension(A, B) >= l` | PAIR | APPROX | exact on R+, else not compared | 151 |
| 20 | overlap | `overlap(A, B) >= l` | FIG by marker (`A & B`) | EXACT | exact | 795 |
| 21 | max_distance_to_tap | `tap_distance(w, t) <= l` | ROW | APPROX | lo ⊆ GPurify ⊆ hi | 3083 |
| 22 | off_grid | `off_grid(; pitch)` | POINT | EXACT | exact (as sets) | 3164 |
| 23 | angle | `angle([L]; allowed)` | SEGMENT | EXACT | exact | 102 |
| 24 | redundant_via | `redundant_via(L; within) >= n` | ROW | APPROX | lo ⊆ GPurify ⊆ hi | 3153 |
| 25 | via_array_spacing | `via_array_space(L; array) >= l` | ROW PAIR | APPROX | lo ⊆ GPurify ⊆ hi | 67 |
| 26 | multi_patterning | `patterning(L; colors) >= l` | — | NONE | reported as not mirrored | — |
| 27 | forbidden | `forbidden(L)` | ROW / EDGE | EXACT | exact | 3964 |
| 28 | must_contain | `contains(o, i) >= n` (`<=`, `==`) | FIG by marker (outer) | EXACT | exact | 3236 |
| 29 | must_be_inside | `inside(i, o)` | FIG by marker (inner) | EXACT | exact | 3107 |
| 30 | net_spacing | `space(L; nets: same\|different)` | PAIR | EXACT on one layer with `touch_within_layer`, else NONE | exact | 1141 / 10 (F88) |
| 31 | spacing_table | `space_table(L; …)` | PAIR | APPROX | exact on R, else KLayout ⊆ GPurify | 1209 |
| 32 | attached_wide_spacing | `wide_space(L; width, attached)` | PAIR | APPROX | KLayout ⊆ GPurify | 986 |
| 33 | edge_min_length | `length(E) >= l` | EDGE | EXACT | exact | 2162 |
| 34 | edge_spacing | `space(E[, F]) >= l` | POINT | APPROX | KLayout ⊆ GPurify | 1835 |
| 35 | edge_enclosure | `enclosure(E, L) >= l` | POINT | EXACT | exact | 3112 |
| 36 | count | `count(L) <= n` / `>= n` | POINT | EXACT | exact | new in H |
| 37 | aspect_ratio | `aspect_ratio(L) <= r` | FIG by marker | EXACT | exact | new in H |
| 38 | total_area | `total_area(L) <= a` | POINT | EXACT | exact | new in H |
| 39 | cut_class | `size(L; allowed: [..])` | POINT | EXACT | exact | new in H |
| 40 | edge_width | `width(E) >= l` | POINT | EXACT | exact | new in H |
| 41 | edge_facing_space | `facing_space(E) >= l` | POINT | EXACT | exact | new in H |
| 42 | region_density | `region_density(L, R) <= f` | FIG by marker (`R`) | EXACT | exact | new in H |
| 43 | allowed_width | `width(L; allowed: [..])` | FIG by marker | EXACT | exact (keys) | new in H |
| 44 | min_interior_angle | `interior_angle([L]) >= deg` | POINT | EXACT | exact (keys) | new in H |
| 45 | polygon_validity | `valid([L])` | — | NONE | reported as not mirrored | — |
| 46 | min_step | `min_step(L; ..) >= l` | — | NONE | reported as not mirrored | — |
| 47 | tip_spacing_table | `tip_space_table(L; length, space)` | PAIR | EXACT | exact | — |
| 48 | forbidden_spacing | `forbidden_space(L; min, max, prl)` | PAIR | EXACT | exact | — |
| 49 | eol_within_spacing | `eol_space(L; eol_width, within, parallel, end_to_end)` | — | NONE | reported as not mirrored | — |
| 50 | eol_keep_out | `eol_keep_out(L; eol_width, backward, side, forward)` | — | NONE | reported as not mirrored | — |
| 51 | two_width_spacing_table | `two_width_table(L; width, prl, space)` | PAIR | APPROX | exact on R, else KLayout ⊆ GPurify | — |
| 52 | span_length | `span_length(L; x, y)` | — | NONE | reported as not mirrored | — |
| 53 | convex_corner_spacing | `corner_space(L; corner_to_corner, except_eol)` | PAIR | APPROX without `except_eol`, else NONE | GPurify ⊆ KLayout | — |
| 54 | exact_pitch | `pitch(L, vertical \| horizontal) == l` | — | NONE | reported as not mirrored | — |
| 55 | cut_spacing | `space(L, center) >= l`, `adjacent_space(L[, center]; cuts, within) >= l` | ROW PAIR | EXACT (scripted) | exact | new |
| 56 | cut_class_spacing | `cut_class_space(L; short, long, space)` | ROW PAIR | EXACT (scripted) | exact | new |
| 57 | minimum_cut | `min_cuts(C, W, O; width[, within]) >= n` | ROW | EXACT (scripted) | exact | new |
| 58 | gate_corner | `bend(A, B)`, `covers_corner(A, B)` | POINT | EXACT | exact | new |
| 59 | max_enclosure | `enclosure(i, o) <= l` | FIG by marker (outer) | EXACT | exact | new |
| 60 | noncoincident_enclosure | `enclosure(i, o, noncoincident) >= l` | FIG by shape (inner) | APPROX | KLayout ⊆ GPurify | new |
| 61 | via_stack | `via_stack(C1, C2, ..) <= n` | ROW | EXACT (scripted) | exact | new |
| 62 | full_width | `full_width(i, o)` | FIG by shape (inner) | EXACT (scripted) | exact | new |
| 63 | projection_spacing | `space(A, B, projection) >= l` | PAIR | APPROX | KLayout ⊆ GPurify | new |
| 64 | adjacent_enclosure | `enclosure(i, o, adjacent) >= l` | FIG by shape (inner) | APPROX | exact when the inner layer is R, else KLayout ⊆ GPurify | new |
| 65 | anchored_patterning | `patterning(L, A1, ..; colors) >= l` | — | NONE | reported as not mirrored | — |
| 66 | density_balance | `density_balance(A, B[, d]; window, step) >= f` | POINT | EXACT | exact | — |
| 67 | critical_area | `critical_area(L; radius) <= a` | POINT | EXACT | exact | — |

43 kinds are EXACT (five scripted over KLayout's polygons), 16 APPROX and eight NONE; `convex_corner_spacing` is NONE on a deck with
`except_eol`, and `net_spacing` on a deck without
`connect touch_within_layer`, and between two layers (`space(A, B; nets: ..)`), which is not mirrored. `examined` is GPurify-only; KLayout has no equivalent.

The counts were measured on 990376b (after B20 and B24), with the translator reconciled to B24.

### 1. min_width — EXACT

**GPurify** (`width.rs` `facing`, `material_between = true`)
- Merges the layer with `union_into`. For each figure it takes the minimum of two measures:
  - Parallel edges facing each other across material, with projections that overlap by a positive
    length; the distance is perpendicular (`geom/width.rs` `narrowest_facing`).
  - The Euclidean gap between two concave corners whose voids point at each other
    (`narrowest_neck`, rounded down to whole DBU).
- Holes count. At most one violation per figure, when the minimum is < limit, at the midpoint of
  the narrowest pair; the shape is the lowest drawn row under the figure (`owners_of`).

**KLayout**

```ruby
emit(id, L.width(LIM, euclidian, shielded))
```

- Euclidean width covers both GPurify measures. (v T4: two 100-DBU squares offset by 70 give a
  neck of √1800 = 42.4; `width(43)` flags it, `width(42)` does not, and `projection` does not.)
- No `without_touching_corners`: under the Connected model a corner contact is a 0-width neck
  (v t18 Z1).
- Euclidean width across a void between convex-ended edges (the earlier Q1) does not occur: no
  KLayout pair outside GPurify's measures on any fixture or random layout (x).

### 2. max_width — EXACT

**GPurify** (`width.rs` `max_width`)
- Regions are the union of every (limit+1)-square that fits in the merged layer
  (`wide_rects_into`), merged.
- One violation per region, at its narrowest facing pair, which is the value reported (> limit).

**KLayout**

```ruby
w = L.sized(-H).sized(H) ; figs(id, w)          # H = limit in original DBU, i.e. LIM/2 at x2
emit(id, w.width(big(w), projection))           # big: above any width in the layout
```

- An opening by H keeps exactly the parts wider than 2H (v T10), the same set as GPurify's:
  `wide_rects_into` itself cites `KLayout sized(-w/2).sized(w/2)`.
- The regions are their own figure set; each region's narrowest facing pair is the projection
  width check with a limit above any width. Key FIG by marker, measured that gap.

### 3. cut_size — EXACT

**GPurify** (`width.rs` `cut_size`): per merged figure; it fails when its short side is wrong,
its long side is wrong, or it is not a rectangle. `at` is the bbox centre; `measured` is the
wrong side, else the area.

**KLayout**

```ruby
emit(id, L.drc(if_any(!rectangles, bbox_min != SHORT, bbox_max != LONG)))
```

- Key POINT, the box centre. The measurement is computed from the polygon the way GPurify does.
- Two correct cuts touching at a corner are one figure under Connected, and fail (v t15 K1/K2).

### 4. min_edge_length — EXACT

**GPurify** (`width.rs` `min_edge_length`): every edge of every merged figure, holes included,
shorter than the limit; `at` the edge midpoint.

**KLayout**

```ruby
emit(id, L.edges.with_length(nil, LIM))
```

- A merged figure has no keyhole slit edges in either tool. Collinear edges of opposite direction
  that meet at a corner contact are not joined (x).

### 5. notch — EXACT

**GPurify** (`facing`, `material_between = false`): facing edges across a void inside one merged
figure, holes included, by projection only. One violation per figure, at the middle of the
narrowest notch.

**KLayout**

```ruby
emit(id, L.notch(LIM, projection))
```

- Key FIG by shape: the marker lies in the void, so it is in no figure.
- Under Connected, the gap in a chain joined at corners is a notch (N1; v t18 Z1).

### 6. min_spacing — EXACT

**GPurify** (`spacing.rs` `min_spacing`)
- Works on drawn rows. Components are rows at distance 0 (touching, including at a corner), plus
  nesting (`join_nested`).
- Every candidate pair from two different components closer than the limit is one violation,
  keyed by the row pair. An island inside a hole is measured to the hole ring.

**KLayout**

```ruby
emit(id, L.isolated(LIM, euclidian, transparent))
```

- `isolated` checks between different polygons only ([L] "isolated"), which at the default
  coherence are GPurify's components (v T2). Key PAIR.

### 7. min_spacing_diff — EXACT

**GPurify** (`spacing.rs` `min_spacing_diff`): no component exemption; every cross-layer pair
closer than the limit is a violation, overlap and nesting at 0. Reported on layer `a`.

**KLayout**

```ruby
emit(id, A.separation(B, LIM, euclidian, transparent)) ; emit(id, A & B)
```

- `separation` reports abutting edges and touching corners, but not overlapping or nested shapes
  (v T6), hence the `A & B`. Key PAIR.

### 8. eol_spacing — APPROX (KLayout ⊆ GPurify)

**GPurify** (`spacing.rs` `eol_spacing`, `eol_hit`)
- An end of line is an edge of the merged layer strictly shorter than `eol_width`. Its keep-out
  is the edge's span pushed `limit` straight out of the material, as a closed box.
- Two rows in different figures are a pair when an edge of one meets the keep-out of an end the
  other lies on; the pair measures the Euclidean segment distance from the part of the end that
  row draws.

**KLayout**

```ruby
emit(id, L.isolated(LIM, projection, transparent, whole_edges).with_length(nil, EOLW))
```

- `with_length` on edge pairs keeps a pair when either whole edge is shorter than `eol_width`
  (v t16 Q3/Q3b). A facing pair with such an edge is an end of line with the other figure in its
  keep-out, so every KLayout pair is a GPurify pair, at no smaller distance.
- GPurify also measures far edges that meet the keep-out only at its side or span end (a zero
  projection) and edges that approach the end without facing it (x).

### 9. prl_spacing — APPROX (exact on R, else KLayout ⊆ GPurify)

**GPurify** (`spacing.rs` `prl_spacing`, `facing_runs`, `run_within`)
- The run of two merged figures is facing-edge projection: the longest overlap of the
  projections of two parallel edges of the merged layer, one of each figure, facing each other
  across a gap ≤ limit (F49, fixed in B24; before, the figures' bbox overlap).
- A row pair is judged when its figures' run ≥ prl; it fails when its whole-pair Euclidean
  distance is < limit.

**KLayout**

```ruby
emit(id, L.isolated(LIM, euclidian, transparent, projection_limits(PRL, nil)))   # PRL = 2·prl
```

- (v t11 P3/P4: `projection_limits(100, nil)` behaves exactly like `projecting >= 100`.)
- On R the bounding-box run is the facing projection. Off R the box over-reports the run, so
  GPurify holds more pairs (x). The decided facing-edge run (B24) makes it exact.

Off R the two can still differ. KLayout filters each edge pair of the merged figures by its own
projection; GPurify takes the longest run per figure pair and then judges every row pair of the two
figures by its whole distance, which may come from a corner the run does not include (GPurify
reports more there). GPurify's run also counts edges exactly the limit apart, which `isolated`
never pairs; that changes only which pairs are examined, unless such a pair also comes closer
elsewhere. KLayout's projection of trimmed edge pairs is not verified against GPurify's
whole-edge overlap.

### 10. corner_to_corner — APPROX (exact on R, else GPurify ⊆ KLayout)

**GPurify** (`spacing.rs` `corner_to_corner`, `corner_gap`): convex corners of the merged layer
that face each other, each strictly beyond the other on both axes and out along opposite
diagonals; a pair fails when its nearest such corners are closer than the limit.

**KLayout**

```ruby
emit(id, L.isolated(LIM, euclidian, transparent, projection_limits(0, 1)))
```

- This keeps edge pairs with zero projection (v t11 P1 ≡ P2). The harness drops a pair whose two
  edges overlap or touch on either axis: GPurify needs each corner strictly beyond the other.
- The two edges at a pair of facing convex corners face each other with zero projection, so
  every GPurify pair is a KLayout pair. Off R, KLayout also pairs an edge that ends at a concave
  corner (x).

### 11. wide_dependent_spacing — EXACT, with a same-figure filter

**GPurify** (`spacing.rs` `wide_dependent`, `wide_parts`): wide parts are the union of every
square of side `width_threshold` that fits; each pair of rows in different figures where either
has wide parts measures from those parts to the other row.

**KLayout**

```ruby
w = L.sized(-(T - 1)).sized(T - 1)   # T = width_threshold in original DBU; at x2 this keeps width >= T
emit(id, w.separation(L, LIM, euclidian, transparent))
```

- A wide edge that coincides with an edge of its own figure faces the same way and is not
  paired; the figure's own edges can face its wide part across a notch, so the harness drops
  pairs whose two edges lie on one figure.

### 12. min_area — EXACT

**GPurify** (`area.rs` `min_area`): per merged figure, area without holes, below the limit; `at`
the centre of one of its rectangles.

**KLayout**

```ruby
emit(id, L.with_area(nil, AREA4))
```

### 13. min_enclosed_area — EXACT

**GPurify:** each hole ring of each merged figure below the limit; `at` the centre of the hole's
box.

**KLayout**

```ruby
holes_below(id, L, AREA4)   # each hole ring of each figure of L.data.merged, as a polygon
```

- Not `L.holes.with_area`: the selection would merge two holes that touch at a corner, which
  are two holes under Connected. Key POINT.

### 14. cheesing — EXACT

**GPurify:** a figure fails when its area is > `max_unslotted` and it has no hole.

**KLayout**

```ruby
emit(id, L.drc(if_all(area > AREA4, with_holes == 0)))
```

(v t16 Q1.)

### 15. density — EXACT

**GPurify** (`area.rs` `density`, `die_of`, `positions`)
- **The die** is the extent of the boundary layer, or else the union of the bboxes of every drawn
  layer (derived layers do not count).
- **The windows** are squares of side W at origins die.lo + i·S, NX = ⌈(span − W)/S⌉ + 1 per
  axis. **Each window's value** is the merged layer's area inside the die and the window over W².

**KLayout**

```ruby
die = [RBA::Box.new, l0.data.bbox, l1.data.bbox, …].inject(:+)   # or the boundary layer's bbox
density(id, L, die, W, S, LIMIT, maximum)                       # W, S doubled
```

- The prelude lays the windows out as GPurify defines them and measures each window's coverage
  with KLayout's booleans: `(L ∩ die ∩ window).area / W²`. At ×2 both areas are 4× GPurify's
  integers, so the ratio is the same double and no near-tie needs dropping.
- `with_density` tiles are not used: they need a centring offset and a 2×1 workaround for a
  single tile (the earlier Q2), and the explicit windows state the definition directly.

### 16. global_density — EXACT

**GPurify:** the merged area clipped to the die over the die area, compared strictly; at most one
violation, at the die centre.

**KLayout**

```ruby
global_density(id, L, die, LIMIT, maximum)   # Region#area is an integer in DBU², so the ratio is exact
```

### 17. min_enclosure — EXACT

**GPurify** (`overlay.rs` `enclosure`, `boundary_dist2`): each drawn inner polygon, hosted by a
merged outer figure that covers it; the Euclidean distance to the host's boundary, holes
included; 0 with no host.

**KLayout**

```ruby
emit(id, O.enclosing(I, LIM, euclidian, transparent)) ; emit(id, I.not_inside(O))
```

- `enclosing` ignores inner shapes that are partly or fully outside (v T7), hence the
  `not_inside`. Coincident edges are reported at 0, and corner-to-corner distances count.
- A wire band restricts `I` first, for this kind and the next: `I.inside(O.sized(-T).sized(T))`
  with `T = W - 1` at x2 (the wide part of kind 11) for `width: W`, and `.not_inside(...)` the
  same way for `below:`.
- Key FIG by shape: per inner figure, the least over its drawn rows (the marker is in the strip
  outside the inner).

### 18. asymmetric_enclosure — APPROX (exact when the inner layer is R, else KLayout ⊆ GPurify)

**GPurify** (`overlay.rs` `strips`, `enclosure_of`): each edge of an inner row, holes included,
is read straight out to the nearest host edge facing it; the measure is the better axis,
`max(min over vertical edges, min over horizontal edges)`, which is `max(min(l, r), min(b, t))`
for a rectangle. An unhosted inner is 0.

**KLayout**

```ruby
c = enclosed(O, projection) < LIM
emit(id, I.drc(if_all(c.first_edges.angle == 90, c.first_edges.angle == 0)))   # fails on both axes
emit(id, I.not_inside(O))
```

- (v t4 T17.) Do not use the classic rectangle filter: it stops waiving when an error covers only
  part of a side (v t3 T9e).
- The recipe is the same definition edge by edge: an inner fails when it has a short vertical
  edge and a short horizontal one. Off R, KLayout's projection pairs an inner edge only with
  outer edges whose projection overlaps it by a positive length, as `strips` does, but a
  shielded outer edge and a partly unhosted inner can still differ, so off R KLayout ⊆ GPurify
  (fixtures `asymmetric_enclosure/l_via_*`). The measurement is not compared.

### 19. min_extension — APPROX (exact on R+, else not compared)

**GPurify** (`overlay.rs` `min_extension`, `gate_extension`): each figure of merged `A & B` is a
gate (shapes that only touch make none). A crosses B along an axis when every gate edge facing
along it lies on B's boundary; each such edge measures how far A runs past it, by projection. The
gate measures the least over its crossed axes, and 0 when crossed along neither.

**KLayout**

```ruby
extension(id, A, B, LIM)   # per A figure p: Region(p).enclosing_check(p & B, LIM, projection, transparent, never zero distance)
emit(id, A.inside(B))      # A inside B: GPurify measures 0
```

- One A figure at a time, against its own gates. A layer-wide transparent `A.enclosing(B)` also
  pairs edges of neighbouring figures that merely face the same way: a B beside a thin A, not
  touching it, is "enclosed" by A's far edge (v t18 Z5; random layout 353), and `shielded` would
  hide a gate behind a second B under the same A.
- **R+** (a4). Off it: an A ending inside B or flush at one end (GPurify 0, the recipe sees only
  the far end), a B edge inside a gate along an axis A does not cross, a bent gate. The other
  oracles are the bitmap rectangle pairs and the `min_extension` fixtures of `drc_overlay.rs`.

### 20. overlap — EXACT

**GPurify** (`overlay.rs` `overlap`): each figure of merged `A & B` measured as `min_width`
measures a figure, one violation per figure below the limit, at the midpoint of its narrowest
pair. Shapes that only touch share no area.

**KLayout**

```ruby
ab = A & B ; figs(id, ab) ; emit(id, ab.width(LIM, euclidian, shielded))
```

- The native `overlap` never sees a full cross, where both bounding edges belong to B, so it is
  not used. Key FIG by marker over the figures of `A & B`.

### 21. max_distance_to_tap — APPROX (bracket)

**GPurify** (`overlay.rs` `max_distance_to_tap` → `supply.rs` `untied_points`): for each outer
well row, the furthest point by branch and bound, measured to the tap edges; fails when > limit.
A point inside a tap is measured to the tap's edge, and a well's hole is measured as if filled;
both over-report.

**KLayout**

```ruby
w = W.dup.raw
lo = w.overlapping((w - T.sized(LIM)).sized(0))                  # square ball, Chebyshev: under-reports
hi = w.overlapping((w - T.sized(LIM, diamond_limit)).sized(0))   # L1 ball: over-reports
```

- **lo ⊆ GPurify ⊆ hi**, except that GPurify may be outside hi where its `at` lies in a tap or in
  a hole of the well (the two over-reports).
- `sized(0)` copies the difference: when no tap reaches a well, `w - t` is the well itself, and a
  raw polygon never overlaps itself (v t18 Z3).
- (v t13 S1: `diamond_limit` cuts each convex corner to the L1 ball.) No Euclidean sizing exists
  in KLayout, so this stays a bracket.

### 22. off_grid — EXACT

**GPurify** (`grid.rs` `off_grid`): every vertex of every store row on every drawn layer, hole
rows included, off the lattice. `at` is the vertex.

**KLayout**

```ruby
DRAWN.each { |x| emit(id, x.dup.raw.ongrid(PITCH)) }   # PITCH = 2·pitch
```

- A merged `ongrid` hides vertices inside material; `.raw` reports them (v T16). Collinear
  vertices are kept (v col.rb). Compared as a set of points; the keyhole cell agrees (x).

### 23. angle — EXACT

**GPurify** (`grid.rs` `angle`)
- Checks every non-zero edge of every row on the layer (or, with no layer, on every drawn layer:
  derived layers are not checked, F63, fixed in B24) against the allowed lines 0, 45, 90 and 135.
- `at` is the start vertex in counter-clockwise order.

**KLayout**

```ruby
bad = x.dup.raw.edges         # x: the named layer, or with none each drawn polygon layer
ALLOWED.each { |a| bad = bad.without_angle(a) }   # deck 135deg → -45
emit(id, bad)
```

- 45 and −45 are distinct angles (v T16). Compared as undirected segments.
- With no layer, a derived layer is not emitted, as GPurify does not check it (F63, B24); the
  fixture `angle/derived` holds that (x).

### 24. redundant_via — APPROX (bracket)

**GPurify** (`via.rs` `redundant_via`): on drawn cut rows, a cut's count is itself plus every
other cut within `within` (inclusive); it fails below `min_count`. `at` its centre.

**KLayout**

```ruby
c  = C.dup.raw
lo = c.not_interacting(c.sized(WITHIN).raw, MIN_COUNT)                   # Chebyshev: fewest violations
hi = c.not_interacting(c.sized(WITHIN, diamond_limit).raw, MIN_COUNT)    # L1: most violations
```

- Raw growth plus a counted `interacting` counts each grown cut, itself included (v t10 R1/R2).
  **lo ⊆ GPurify ⊆ hi**, lo = hi when no near pair is diagonal.

### 25. via_array_spacing — APPROX (bracket)

**GPurify** (`via.rs` `via_array_spacing`): clusters are components of "distance ≤ limit" among
cut rows; in each with more than `array_threshold` cuts, every pair closer than the limit fails,
overlapping cuts included (d = 0).

**KLayout**

```ruby
c = C.dup.raw ; big = c.sized(H).merged.interacting(c, THR + 1) ; arr = c.interacting(big)   # H = LIM/2
emit(id + "#hi", arr.isolated(LIM, euclidian, transparent)) ; touching(id + "#hi", C.dup.raw, arr)
# and "#lo" with c.sized(H, diamond_limit)
```

- Square growth joins the most clusters (hi), diamond growth the fewest (lo).
- A raw `isolated` pairs abutting cuts (at 0) but not overlapping ones (v t18 Z7, the earlier Q8);
  `touching` names every pair of array cuts that touch or overlap, by index into `raw:<layer>`.

### 26. multi_patterning — NONE: KLayout has no colouring

**GPurify** (`patterning.rs` `multi_patterning`): figures closer than the spacing conflict; two
colours are a bipartiteness test, three or more a budgeted search (`Refused` when it runs out).

The differential reports every `multi_patterning` rule as not mirrored. The hybrid oracle (a
KLayout conflict graph, `isolated(SPACING2, euclidian, transparent)` between figures, coloured by
brute force in the harness) is not built.

`anchored_patterning` (`patterning(L, A1, ..; colors)`, the same graph with pre-coloured figures)
is not mirrored either. Its graph decision, `anchor_conflict`, is checked against every colouring
of small random graphs (`crates/check/tests/drc/patterning_rules.rs`), and its geometry by the
exhaustive fixtures `anchored_patterning/*`.

### 27. forbidden — EXACT

**GPurify** (`presence.rs` `forbidden`): every polygon as the store holds it, with its area, and
every edge of an edge layer with its length.

**KLayout**

```ruby
emit(id, L.dup.raw)       # drawn layer, or .extents() boxes
emit(id, L.data.merged)   # any other derived layer
emit(id, E)               # edge layer: maximal runs (a2)
```

### 28. must_contain — EXACT

**GPurify** (`presence.rs` `must_contain`): merged inner and outer figures; an inner figure is
held by the outer figure that covers all of it (straddling the boundary, by none); each outer
figure holding fewer than `min_count` or more than `max_count` fails, `measured` the count it
holds. `>=` sets the minimum, `<=` the maximum, `==` both.

**KLayout**

```ruby
emit(id, O.not_covering(I.inside(O), MIN_COUNT)) { |p| { v: I.data.merged.inside(RBA::Region.new(p)).count } }   # a minimum
emit(id, O.covering(I.inside(O), MAX_COUNT + 1)) { |p| { v: … } }                                                # a maximum
```

- Too few and too many are disjoint, so a `==` row emits both lines and no figure twice. The
  maximum reuses the counted `covering` the minimum is verified on ([L] "covering": "only
  selected when covering a given number of shapes").

- `covering` drops an outer figure that any inner shape straddles, whatever else it holds (v t18
  Z4; random layout 133). Counting only inners that some outer holds restores the definition.
  (v t9 C1–C3 for the rest.)

### 29. must_be_inside — EXACT

**GPurify:** a merged inner figure not wholly covered by one merged outer figure; `measured` the
area left outside.

**KLayout**

```ruby
emit(id, I.not_inside(O)) { |p| { v: (RBA::Region.new(p) - O.data).area } }
```

(v t9 C4, T11.)

### 30. net_spacing — EXACT on one layer with `touch_within_layer`, otherwise NONE

**GPurify:** as `min_spacing` (rule 6), restricted to pairs on the same net, or on different
nets. `Refused` when a shape has no net.

**KLayout**

```ruby
# the deck's connectivity, (c), once per layout
emit(id, L.nets.isolated(LIM, euclidian, transparent, props_eq))   # nets: same (props_ne: different)
```

- `props_eq` and `props_ne` work on `isolated` (v t5 T19). `isolated`, not `space`, which would
  add notches inside one polygon.
- **Implementation difference, F88.** A KLayout cut is a net member: one cut on two shapes of
  one layer, or two touching cuts, joins what they touch (v t18 Z8). A GPurify cut joins one
  shape on each of its two layers where it lands on both and belongs to no net (`deck.md`: "a
  cut joins the two layers it overlaps"; `topology/net.rs`: "a cut over only one layer is no
  edge"). Each tool follows its own documented model. They differ only on a cut that lands on
  one of its two layers, an ill-formed via the via-enclosure rule flags, and no documentation
  settles which reading is right, so this is recorded as a difference, not a defect. The script
  marks a cut layer where it occurs (`{bridge: layer}`) and the differential reports a
  `net_spacing` disagreement there as the difference (x: 5 random layouts).

### 31. spacing_table — APPROX (exact on R, else KLayout ⊆ GPurify)

**GPurify** (`spacing.rs` `spacing_table`)
- Per row r, the column is the last c whose `prl` is strictly exceeded by the facing-edge run of
  the two figures over edges at most S[r][c] apart (`run_within`; F49, fixed in B24).
- The pair fails if some row r ≥ 1 has d_r < S[r][col], where d_r is measured from the parts wider
  than `width[r]`, clipped to their row. Otherwise it fails if d_0 < S[0][col].
- Cells never fall along a row (`SpacingTable::is_valid`). So this equals "there is an (r, c ≤ col)
  with d_r < S[r][c]", which is a union of independent checks.

**KLayout**

```ruby
SPACE.each_with_index do |row, r|        # one check per cell, s = 2·space[r][c]
  row.each_with_index do |s, c|
    lim = c == 0 ? "" : ", projection_limits(#{2 * PRL[c] + 1}, nil)"   # run > prl[c]
    r == 0 ? L.isolated(s, euclidian, transparent, lim)
           : L.sized(-WIDTH[r]).sized(WIDTH[r]).separation(L, s, euclidian, transparent, lim)
  end
end
```

- For r ≥ 1, apply the same-figure filter as in rule 11.
- Both take the run as the projection of facing edges within the cell. On R the two agree.
- Off R: for r ≥ 1 KLayout's run is between the wide parts and the figure, GPurify's between the
  whole figures; and GPurify judges a pair by its distance per row once its run selects a column,
  as in rule 9. Neither difference is shown one-sided; compare off R as APPROX.

### 32. attached_wide_spacing — APPROX (KLayout ⊆ GPurify)

**GPurify** (`wide_parts`): the wide parts grown by `attached` with square corners, clipped to
the shape's own figure, including parts of it not connected to the wide part inside the box.

**KLayout**

```ruby
w = L.sized(-(T - 1)).sized(T - 1) ; att = (w.sized(A2) & L).interacting(w)   # A2 = 2·attached
emit(id, att.separation(L, LIM, euclidian, transparent))
```

- `.interacting(w)` drops neighbouring figures within `attached`, and also parts of the own
  figure reached only across a notch, so KLayout's attached part is within GPurify's.

### 33. edge_min_length — EXACT

```ruby
emit(id, E.with_length(nil, LIM))
```

### 34. edge_spacing — APPROX (KLayout ⊆ GPurify)

**GPurify** (`edge.rs` `spacing`): every pair of parallel edges, collinear end-to-end gaps
included, failing when 0 < Euclidean distance < limit; `at` the gap midpoint of the two edges'
boxes.

**KLayout**

```ruby
[E.space(LIM, euclidian, whole_edges), E.width(LIM, euclidian, whole_edges),
 E.enclosing(E, LIM, euclidian, whole_edges, without_touching_edges)]          # one layer
[E.separation(F, …), E.overlap(F, …), E.enclosing(F, …), E.enclosed(F, …)]     # two layers, same options
```

- KLayout checks on edge layers depend on orientation, so the recipe takes the union of every
  relation (v t16). `whole_edges` is accepted on edge layers and makes the marker GPurify's
  (the earlier Q5), and the one-layer `E.enclosing(E)` pairs no edge with itself (the earlier
  Q10) (x).
- No KLayout relation sees collinear end-to-end gaps (v Q11–Q13): those are GPurify's only.

### 35. edge_enclosure — EXACT

**GPurify** (`edge.rs` `enclosure`, `covered_depth`): for each non-zero edge, a strip `limit`
deep on the side away from its shape; the edge fails when the merged outer layer leaves part of
it uncovered. `at` the edge midpoint.

**KLayout**

```ruby
edge_enclosure(id, E, O, LIM)   # each edge whose RBA::Edges.new(e).extended_out(LIM) - O is not empty
```

- (v t16 Q4/Q5.) Key POINT, the edge midpoint; GPurify's `measured` (the covered depth) is not
  compared.

### 36. count — EXACT

**GPurify** (`area.rs` `count`): the merged figures of the layer in the whole layout, one finding
when their number is above a maximum or below a minimum, at the centre of the die (the drawn
layers' extent, as for `global_density`), `measured` the count. Nothing drawn is `Skipped`.

**KLayout**

```ruby
n = L.data.merged.count
put({ rule: id, pt: [die.center.x, die.center.y], v: n }) if !die.empty? && n > MAX   # or n < MIN
```

- `merged` at the default coherence joins shapes meeting at a corner, as the Connected model does
  (a3), so both count the same figures. Key POINT, the die centre; the count compared exactly.

### 37. aspect_ratio — EXACT

**GPurify** (`area.rs` `aspect_ratio`): per merged figure, its bounding box's longer side over its
shorter, as an `f64`; one finding per figure above the limit, at the centre of its first
rectangle, `measured` the ratio.

**KLayout**

```ruby
emit(id, L.drc(bbox_aspect_ratio > R)) { |p| { v: [p.bbox.width, p.bbox.height].max.to_f / [p.bbox.width, p.bbox.height].min } }
```

- `bbox_aspect_ratio` is "the larger dimension divided by the smaller one" of the bounding box
  ([X]; the layer form is `with_bbox_aspect_ratio`, [L]), on merged figures. At ×2 both sides
  double, so the quotient, and its comparison with the unscaled limit, is the same double. Key FIG
  by marker; the ratio compared to 1e-9.

### 38. total_area — EXACT

**GPurify** (`area.rs` `total_area`): the area of the merged layer in the whole layout, holes
excluded; one finding above the limit, at the die's centre (as `count`), `measured` the area.

**KLayout**

```ruby
a = L.data.merged.area
put({ rule: id, pt: [die.center.x, die.center.y], v: a / 4.0 }) if !die.empty? && a > AREA4
```

- `area` on a layer is "the total area of all polygons", merged, so overlaps count once ([L]);
  IHP's own deck checks MIM.gR as `mim_drw.area > value`. At ×2 the area is four times GPurify's.

### 39. cut_class — EXACT

**GPurify** (`width.rs` `cut_class`): per merged figure, a rectangle with no hole whose short and
long sides are one listed class's passes; any other figure is one finding at its bounding box's
centre, `measured` `Count(0)`.

**KLayout**

```ruby
emit(id, C.drc(if_any(!rectangles, if_all(if_any(bbox_min != S1, bbox_max != L1), if_any(bbox_min != S2, bbox_max != L2)))))
```

- The cut_size recipe (rule 3) once per class: a figure fails when it is no rectangle or every
  class rejects it. Key POINT, the box centre; the measurement is not compared.

### 40. edge_width — EXACT

**GPurify** (`edge.rs` `facing`, `inside = true`): two parallel edges of the edge layer whose
shapes lie toward each other (back to back), projections overlapping by a positive length,
measured straight across; every pair, nothing shields one. `at` the middle of the gap between
their boxes.

**KLayout**

```ruby
emit(id, E.width(LIM, projection))
```

- On an edge layer `width` reports pairs in a "back to back" relation, "their inner sides face
  each other", the inside being the right of an edge (KLayout's hulls run clockwise; GPurify's
  edges carry their shape on the left, so both mean the shape's side) ([L]). `projection` measures
  straight across overlapping parts and drops a pair whose projections only touch, as GPurify
  does (`var_near_part_of_edge`). Shielding is a polygon-layer option KLayout refuses on edges,
  so every pair counts, as in GPurify. Key POINT, the gap's middle (as rule 34); the length
  compared.

### 41. edge_facing_space — EXACT

**GPurify** (`edge.rs` `facing`, `inside = false`): as rule 40 with the shapes turned away from
each other (face to face).

**KLayout**

```ruby
emit(id, E.space(LIM, projection))
```

- On an edge layer `space` reports pairs in a "face to face" relation, "their outer sides face
  each other" ([L]). Key POINT, the gap's middle; the length compared.

### 42. region_density — EXACT

**GPurify** (`area.rs` `region_density`): per merged figure of the region layer, the area of the
merged measured layer inside it over its own area, holes excluded; one finding per figure outside
the limit, on the region layer, at the centre of its first rectangle.

**KLayout**

```ruby
region_density(id, L, R, LIMIT, maximum)   # per p in R.data.merged: (L.data.merged & Region(p)).area / p.area
```

- `Polygon#area` leaves holes out, as GPurify does; both ratios are the quotient of two whole
  areas at ×2, so the same double. Key FIG by marker on the region's figures; compared to 1e-9.

### 43. allowed_width — EXACT

**GPurify** (`width.rs` `allowed_width`): per merged figure, its narrowest width squared
(`narrowest_width2`, facing edges and Euclidean necks, as rule 1 and `with_width`) against each
listed width squared; a figure matching none is one finding at the centre of its first rectangle.

**KLayout**

```ruby
emit(id, L.merged - [with_width2(L, W1², W1² + 1), with_width2(L, W2², W2² + 1)].inject(:+))
```

- `with_width2` (c) keeps the figures whose narrowest width squared is in the range, measured
  exactly; the figures in no range are the findings. Key FIG by marker; the width is not compared.

### 44. min_interior_angle — EXACT

**GPurify** (`grid.rs` `min_interior_angle`): every corner of every drawn row (one layer's, or
every drawn layer's), its angle on the shape's side (rows carry their shape on the left, holes
included) 180 less the signed turn, rounded to 1e-9 degree; a corner under the limit is one
finding at the vertex.

**KLayout**

```ruby
emit(id, L.dup.raw.with_angle(0.0, LIMIT))
```

- The polygon form of `with_angle` (deprecated, still in 0.30) measures the angle inside the
  shape, 0 to 360, keeping `min <= a < max`, as IHP's own deck checks 3.1 with `with_angle(0,
  87)`; each corner is an edge pair whose first edge ends at the vertex. On a raw layer it reads
  the polygons as drawn, as GPurify does; a GDS keyhole's cut line adds only 90 and 180 degree
  corners. `corners` measures the turn instead, with an inclusive bound resolved on the rounded
  rotated edge, so a right angle could fall on either side of a limit of 90. Key POINT, the
  vertex; the angle is not compared.

### 45. polygon_validity — NONE: KLayout reports parts, not polygons

**GPurify** (`grid.rs` `polygon_validity`, `geom/view.rs` `ring_defect`): each drawn row that
layer validation refuses as degenerate or self-intersecting is one finding at its first vertex.

KLayout's `odd_polygons` returns "the parts of the polygons which are not orientable … or
self-overlapping", not the drawn polygon, and a ring of zero area has no such part, so the two
answer different questions. The fixtures (hand-drawn defects) and a differential against the
layer validator (`ring_defect_names_what_layer_validation_refuses`) are the oracles.

### 46. min_step — NONE: KLayout has no runs of short edges

**GPurify** (`width.rs` `min_step`): runs of consecutive edges shorter than the limit along each
ring of the merged layer, classified by the long edges either side (left turn: outside corner;
right turn: inside corner; same way: step), rejected per LEF 5.8 `MINSTEP`'s keyword.

KLayout states edge lengths (`with_length`) but not runs of them or the corner they make. The
oracle is LEF 5.8's own Example 1-16 and Figures 1-14 and 1-15, drawn as fixtures, with the
staircase swept at the limit. OpenROAD's TritonRoute implements base `MINSTEP` runs, but its
typed `INSIDECORNER`/`OUTSIDECORNER` branch never sets its corner flags (read from
`FlexGC_main.cpp`), so it is not an oracle for them.
### 47. tip_spacing_table — EXACT

**GPurify** (`facing.rs` `tip_spacing_table`, `each_facing`): whole edges of the merged layer, in
different figures, parallel and facing each other across empty space with a positive overlap of
their spans; the gap is the distance between their lines. Each edge is classed by its own length
(the last threshold it reaches) and the pair needs the cell of the two classes. One finding per
pair of figures, its smallest offending gap.

**KLayout**

```ruby
tip_table(id, L.isolated(REACH, projection, transparent, whole_edges), CLASSES, SPACE)
# REACH = 2·(largest cell); CLASSES and SPACE doubled. The prelude's tip_table keeps an edge pair
# when the distance between its lines is under SPACE[class(e)][class(f)], class(e) the last
# threshold e.length reaches.
```

- `isolated` with `projection` pairs edges of different merged polygons that project onto each
  other with a positive overlap, closer than REACH, which is GPurify's facing pair (d).
  `whole_edges` returns each edge whole, so its length is the merged edge's, the class GPurify
  reads.
- Key PAIR; the smallest distance per pair of figures is compared exactly. The oracles besides
  the mirror: the ASAP7 M1.S.1 to M1.S.5 values at the limit and one step either side (FR), the
  hand-derived fixtures under the square's symmetries (SY, MR).

### 48. forbidden_spacing — EXACT

**GPurify** (`facing.rs` `forbidden_spacing`): facing edges as in rule 47 whose run (the overlap
of their spans) is longer than `prl` and whose gap lies in `[min, max]`. One finding per pair of
figures, its smallest forbidden gap.

**KLayout**

```ruby
forbidden_gap(id, L.isolated(MAX + 1, projection, transparent, projection_limits(PRL + 1, nil)), MIN)
# MAX = 2·max, PRL = 2·prl, MIN = 2·min: isolated keeps gaps under 2·max + 1 (at most max),
# projection_limits runs of at least 2·prl + 1 (longer than prl), and the prelude's
# forbidden_gap the pairs whose lines are at least MIN apart.
```

- (d) `projection_limits` filters an edge pair by its projected length, the overlap of the two
  edges (rule 9's run, v t11 P3/P4).
- Key PAIR, the smallest gap per pair of figures, compared exactly. Besides the mirror: both ends
  of the range and the run swept one step either side (SY, MR); `TritonRoute`'s
  `isForbiddenSpacing` and `isValidPrl` give the closed range and the strict run.

### 49. eol_within_spacing — NONE: KLayout has no end-of-line keep-out

**GPurify** (`facing.rs` `eol_within_spacing`, `beside`): an end of line is an edge of the merged
layer shorter than `eol_width` with both corners convex. Its keep-out is the end widened by
`within` on each side (open) and reaching straight out to the limit (open); a facing edge of
another figure in it, at depth 0 or more and overlapping the widened span, fails below the limit,
or below `end_to_end` when it is an end of line too. With `parallel`, an end is checked only where
an edge faces the line's side less than `space` away, overlapping the stretch from `within` behind
the end's line to the end's `within` past it (both sides with `two_edges`).

**KLayout.** Not mirrored. KLayout's checks pair edges or polygons by distance and projection; none
widens a keep-out past an edge's ends, gates a check on a parallel edge beside the line, or swaps
the space when the facing edge is an end of line too. `TritonRoute` defines the rule
(`FlexGC_eol.cpp`), but it is not run as a differential. The oracles: the LEF 5.8 worked example
(Example 1-18, Figures 1-23 and 1-24; SE), the keep-out's depth, sideways reach, parallel space and
parallel reach each swept one step either side, and both-sides and end-to-end cases, hand-derived
under the square's symmetries (SY, MR).

### 50. eol_keep_out — NONE: KLayout has no end-of-line keep-out box

**GPurify** (`facing.rs` `eol_keep_out`): each end of line (as rule 49) owns a box, the end widened
by `side` each way, from `backward` behind its line to `forward` past it; each other figure whose
material overlaps the box with positive area is a finding, measuring that area.

**KLayout.** Not mirrored: picking the edges whose two corners are convex and testing each one's
box against the other figures is a loop over polygons, not a KLayout check. `TritonRoute` defines
the rule (`checkMetalEOLkeepout_main`), but it is not run as a differential. The oracles: the
box's forward, side and backward reaches each swept one step either side, with the area inside
derived by hand as a rectangle's, under the square's symmetries (SY, MR).

### 51. two_width_spacing_table — APPROX (exact on R, else KLayout ⊆ GPurify)

**GPurify** (`spacing.rs` `two_width_table`): each cell (r, c) holds a pair whose one shape has a
part wider than `width[r]` and the other a part wider than `width[c]` (the whole shape for the
first width), when the figures' run within the cell exceeds both widths' stated runs; it fails
when those two parts are closer than the cell. One finding per pair, at its highest failing cell.

**KLayout**

```ruby
# One check per cell, s = 2·space[r][c]; W(i) = L.sized(-width[i]).sized(width[i]), W(0) = L
# (x2: sizing by the undoubled width removes what is at most that wide); the run is the larger
# of the two widths' stated runs, as projection_limits(2·run + 1, nil).
L.isolated(s, euclidian, transparent)                                     # r = c = 0
W(r).separation(W(c), s, euclidian, transparent[, projection_limits(...)])  # otherwise
```

- The same-figure filter of rule 11 drops a wide part paired with its own figure.
- On R a wide part is the whole rectangle and the projection between two rectangles is their
  facing run, so the two agree. Off R, as rule 31: KLayout's run is between the parts, GPurify's
  between the whole figures. Besides the mirror: LEF's own worked example (the four width and
  run cases it prints; SE), the widths and a run swept one step either side, a thin tab of a wide
  plate, hand-derived under the square's symmetries (SY, MR).

### 52. span_length — NONE: KLayout has no span measure

**GPurify** (`facing.rs` `span_length`, `chords`): the chords horizontal and vertical lines cut
from each merged figure, read slab by slab between the figure's vertex coordinates; one finding per
maximal region of an unchanged illegal chord.

**KLayout.** Not mirrored: `width` with `projection` reports edge pairs closer than a limit, not
the set of chord lengths a span list judges, and a legal set of exact values with an open last one
has no KLayout check. The oracles: LEF 5.8's own span tables (`SPANLENGTHTABLE 0.06 0.08 0.12 0.16
0.20` and `WRONGDIRECTION 0.12 0.16 0.20`), every listed value one step either side (SE), an L, a
ring and a shape drawn in pieces, hand-derived under the square's symmetries (SY, MR).

### 53. convex_corner_spacing — APPROX (GPurify ⊆ KLayout) without `except_eol`, else NONE

**GPurify** (`facing.rs` `convex_corner_spacing`): facing convex corners of different figures, as
rule 10, measured by the larger axis gap (`TritonRoute`'s `maxXY`) or, with `corner_to_corner`,
Euclidean; with `except_eol`, the corners of an end of line on either shape are exempt.

**KLayout**

```ruby
emit(id, L.isolated(LIM, square, transparent, projection_limits(0, 1)))      # the larger axis gap
emit(id, L.isolated(LIM, euclidian, transparent, projection_limits(0, 1)))   # corner_to_corner
```

- `square` is the larger of the two axis distances ([L] "metrics"). As rule 10, the harness drops
  a pair whose edges overlap or touch on an axis, and every GPurify pair is a KLayout pair; KLayout
  also pairs an edge ending at a concave corner, so the comparison is one-sided, keys only.
- `except_eol` cannot be stated: NONE. Its oracles are the hand-derived fixtures: a line end's
  corner exempt on either shape, a wide shape's not (SY, MR).

### 54. exact_pitch — NONE: KLayout has no pitch between neighbours

**GPurify** (`facing.rs` `exact_pitch`): every merged figure a rectangle (else refused); each
rectangle's neighbours along the axis are the nearest rectangles past it that overlap it across;
their centre lines must be exactly the pitch apart.

**KLayout.** Not mirrored: KLayout's checks compare distances between edges against a limit, and
none relates the centre lines of neighbouring shapes or flags a distance that is too large as well
as too small. The oracles: ASAP7's own values (FIN.S.1 27 nm on 7 nm fins, GATE.S.1 54 nm on 20 nm
gates) at the pitch and one step either side (FR), a missing line, rows that do not overlap, and a
bent shape refused, hand-derived under the four symmetries that keep the axes (SY, MR).
---

### 55. cut_spacing — EXACT (scripted)

**GPurify** (`via.rs` `cut_spacing`): LEF cut-layer `SPACING` with `CENTERTOCENTER` and
`ADJACENTCUTS n WITHIN w`. On drawn cut rows, distances are between bounding-box centres or
boundary to boundary (0 for cuts that touch, overlap or nest). A cut is held when at least `n`
other cuts lie strictly closer than `w` (every cut when `n` is 0); a pair closer than the limit
fails when either cut is held.

**KLayout** has no centre-to-centre metric and no per-cut neighbour count, so the prelude's
`cut_spacing` computes the definition over KLayout's raw polygons, independently of GPurify's
code:

```ruby
emit("raw:" + C, C.dup.raw) ; cut_spacing(id, C.dup.raw, LIM, N, WITHIN, CENTER)
# per pair: box centres (whole at x2) or poly_d2 (0 when Region(p).sized(1) & q is not empty,
# else the least vertex-to-edge distance, exact); counts by `< WITHIN²`, failures by `< LIM²`
```

- Key ROW PAIR, both cuts by index into `raw:<layer>`; the measurement is not compared.
- (d) `Polygon#each_edge`, `#each_point_hull`, `#bbox`, `Box#center` ([R]).

### 56. cut_class_spacing — EXACT (scripted)

**GPurify** (`via.rs` `cut_class_spacing`): a `LEF58_SPACINGTABLE` of `CUTCLASS` SIDE/END
cells. A drawn cut's class is the `short` x `long` its bounding box matches. Apart along y, a cut
faces with its SIDE when wider than tall; along x, when taller than wide; apart along both, the
larger cell; touching or overlapping, the class pair's largest cell. Edge-to-edge distance.

**KLayout** has no cut classes, so the prelude's `cut_class_spacing` reads the same table over
KLayout's raw boxes:

```ruby
emit("raw:" + C, C.dup.raw) ; cut_class_spacing(id, C.dup.raw, [[S0, L0], ..], [[cells x2], ..])
```

- Key ROW PAIR; the measurement is not compared.

### 57. minimum_cut — EXACT (scripted)

**GPurify** (`via.rs` `minimum_cut`): LEF `MINIMUMCUT n WIDTH w [WITHIN d]`. A via is the drawn
cuts (by box) joining one merged figure of the wide layer to one of the far layer, split into
groups closer than `d`; a group with a cut on the part of the wide layer where a `w + 1` square
fits and fewer than `n` cuts reports each cut, `measured` the group's count.

**KLayout** has no via or cut count by connection, so the prelude's `minimum_cut` groups KLayout's
raw cuts by the merged figures they overlap, with the wide part `W.merged.sized(-w).sized(w)` at x2
(kind 11's wide part for `w + 1`):

```ruby
minimum_cut(id, C.dup.raw, W, O, w, N, D2 or nil)   # one polygon per reported cut, v = its count
```

- Key ROW, the cut's box; the count is compared exactly. A cut that bridges two figures of one
  layer is grouped by a figure each tool picks in its own order, so the random deck carries no
  `min_cuts` row.

### 58. gate_corner — EXACT

**GPurify** (`overlay.rs` `gate_corner`, `concave_corners`): each concave corner (a right turn
with the material on the left) of a figure of merged `A & B` that is also a concave corner of
merged A (`bend`) or of merged B (`covers_corner`). `at` the corner.

**KLayout**

```ruby
emit(id, (A & B).corners(90) & A.corners(90))   # bend; B.corners(90) for covers_corner
```

- (d) [L] "corners": "Since polygons are oriented clockwise, positive angles indicate concave
  (inner) corners", marked by "small 2x2 DBU boxes". Boxes of two corners overlap only when the
  corners are one point (one unit apart is two DBU at x2, so their boxes only touch), and the
  overlap's centre, halved and floored, is the corner. Key POINT.

### 59. max_enclosure — EXACT

**GPurify** (`overlay.rs` `max_enclosure`, `beyond`): each merged outer figure holding inner
figures (covering them entirely) fails when it reaches past their union grown by the limit with
square corners; `at` a point of that excess, `measured` the least whole growth that covers it.

**KLayout**

```ruby
max_enclosure(id, O, I, LIM)   # per merged O figure: held = merged I figures inside it;
                               # fails when Region(o) - Region(held).sized(LIM) is not empty
```

- Key FIG by marker over the outer figures; the measurement is not compared. `sized` grows a
  rectilinear region with square corners, as `.sized()` in a derived layer (c).

### 60. noncoincident_enclosure — APPROX (KLayout ⊆ GPurify)

**GPurify** (`overlay.rs` `apart_enclosure`): each inner edge against each host edge parallel to
it, facing the same way at or beyond it, Euclidean; pairs that touch are not measured; the least
of the rest is the enclosure, 0 when unhosted.

**KLayout**

```ruby
emit(id, O.enclosing(I, LIM, euclidian, transparent, without_touching_edges)) ; emit(id, I.not_inside(O))
```

- (d) [L] "without_touching_edges": "coincident edges will not yield errors"; it also drops
  touching corners, as GPurify's touching pairs. `enclosing` pairs edges by its own angle and
  orientation filter, which this repository has not run against the per-edge definition, so the
  comparison is the safe bracket until a run settles it. Key FIG by shape (inner); the
  measurement is not compared.

### 61. via_stack — EXACT (scripted)

**GPurify** (`via.rs` `via_stack`): LEF `MAXVIASTACK` over the cut layers listed, bottom to top.
A drawn cut stacks on a cut of the layer before whose box it overlaps with positive area; the
tallest chain from below (`down`) and from above (`up`) through each cut; each cut with
`down == max + 1` is reported, `measured` `down + up - 1`.

**KLayout** has no stack count, so the prelude's `via_stack` runs the same chains over raw boxes:

```ruby
via_stack(id, [C1.dup.raw, C2.dup.raw, ..], MAX)   # one polygon per reported cut, v = its stack
```

- Key ROW, the cut's box; the count is compared exactly.

### 62. full_width — EXACT (scripted)

**GPurify** (`overlay.rs` `enclosure_of`, `Mode::FullWidth`): each inner edge read straight out
to the nearest host edge facing it (`strips`); the inner fails when neither axis reads 0 on every
edge. Unhosted inners are not measured.

**KLayout** has no per-axis span test, so the prelude's `full_width` reads the same straight-out
distances from KLayout's merged polygons (projection: host edges whose span overlaps the inner
edge's, at or beyond it):

```ruby
full_width(id, O, I)   # each merged I figure covered by an O figure, failing on both axes
```

- Key FIG by shape (inner); the measurement is not compared.

### 63. projection_spacing — APPROX (KLayout ⊆ GPurify)

**GPurify** (`spacing.rs` `projection_spacing`, `facing_gap`): drawn shapes of A and B; a pair
measures the least gap between parallel edges facing each other across it with a positive
projection overlap, 0 when the shapes touch, overlap or nest.

**KLayout**

```ruby
emit(id, A.separation(B, LIM, projection, transparent)) ; emit(id, A & B)
```

- (d) [L] "separation" with the `projection` metric. Key PAIR as `min_spacing_diff`; the
  measurement is not compared, and the comparison is the safe bracket until a run settles how
  KLayout pairs edges that meet only at a projection's end.

### 64. adjacent_enclosure — APPROX (exact when the inner layer is R, else KLayout ⊆ GPurify)

**GPurify** (`overlay.rs` `strip_ends`, `adjacent_enclosure`): each inner edge is read straight
out at each of its two ends; the measure is the least, over the inner's convex corners, of the
better edge meeting there, read at that corner. For a rectangle in a host that does not step along
it, that is `max(min(l, r), min(b, t))`, the asymmetric value. An unhosted inner is 0.

**KLayout** (sky130A_mr.drc's own idiom for m1.5 and li.5)

```ruby
c = O.enclosing(I, LIM, projection).second_edges
emit(id, I.interacting(c.width(angle_limit(100.0), 1.dbu).polygons(1.dbu)))   # a corner of short edges
emit(id, I.not_inside(O))
```

- An inner edge enclosed by less (projected) is short; a corner where two short edges meet fails.
- A non-rectangular inner that KLayout passes, GPurify may fail, so off R KLayout ⊆ GPurify. The
  measurement is not compared.

## (c) Derived layers, connectivity, antenna

### Derived-layer operations

Each operation runs on merged operands at the default coherence (a3).

| Deck | GPurify (`geom/src/derive.rs`, `ingest/src/layout.rs`) | KLayout | Difference to pin |
|---|---|---|---|
| `A and B`, `or`, `not` | Exact booleans of the validated operands; the result is merged | `A & B`, `A \| B`, `A - B` ([L] "and"/"or"/"not") | Only the corner model (a3) |
| `.sized(len)` | Minkowski sum with a square; erosion is the complement of growing the complement (`sized_into`) | `.sized(len)` (default `square_limit`, [L] "sized") | Identical on rectilinear shapes (v T10) |
| `.sized(dx, dy)` | Minkowski sum with the box `[-dx, dx] x [-dy, dy]`, or erosion by it; one axis grown and the other shrunk is refused | `.sized(dx, dy)` | Fixtures `derived/sized_xy/*` |
| `.covering(L)` / `.not_covering(L)` | Holds a whole figure of L, touching from inside allowed (`covering_into`) | `.covering(L)` / `.not_covering(L)` | Fixture `derived/covering_overlapping` |
| `.overlapping(L)` | Shares area with L; touching is not overlapping (`overlapping_into`) | `.overlapping(L)` | `.not_overlapping(L)` is `.outside(L)` |
| `.interacting(L)` / `.not_interacting(L)` | Touch or overlap; a shared corner counts (`polys_meet`) | `.interacting(L)` / `.not_interacting(L)` | Same (v T11) |
| `.inside(L)` | No part of the shape lies outside L; touching the boundary from inside is fine | `.inside(L)` | Same (v T11) |
| `.outside(L)` | No shared area; touching only is outside | `.outside(L)` | Same (v T11) |
| `.holes()` | Each hole filled, island included, merged | `.holes` | Same (v T12) |
| `.extents()` | The bbox of each figure, one row per box, unmerged (`extents_into`) | `.extents` | Same: "The boxes will not be merged" ([R]) |
| `.with_area(b)` | Area without holes, inclusive bounds | `.with_area(4lo, 4hi + 1)` | (v T12, T15) |
| `.with_width(b)` | `narrowest_width2`: facing edges and diagonal necks, as `width` (rule 1), squared and exact, against bounds squared at parse time (`> n` is `>= n² + 1`; `geom/width.rs`, `deck/parse.rs` `bounds`) | `with_width2(L, 4lo, 4hi + 1)` (prelude): the merged figures whose narrowest width, squared, lies in [4lo, 4hi + 1); the pairs `width_check` finds under the bound are measured exactly, endpoint to segment as a `Rational` | A threshold recipe, `L.drc(if_all(!(width(euclidian) < LO), width(euclidian) < HI))`, resolves only half units at ×2: `width` compares the true distance with a whole limit, and `width <= v` is `width < v + 1` (v t18 Z9: √19604 = 140.01 is under 141, not 140, and `<= 140` flags it). It is exact on whole widths, which every rectilinear facing width is, and for `>=` and `<` bounds, but a neck between n and n + ½ (n² < w² ≤ n² + n) would count as within `<= n` and `== n` and not `> n`; the fixture `derived/with_width_neck_band` (√4901 under `<= 70nm` and `> 70nm`) disagrees under it. Measured exactly, EXACT for every bound (x; N2, fixed in B16; F65, fixed in B24) |
| `.with_bbox_max(b)`, `.with_bbox_min(b)` | The bounding box's longer or shorter side within the bounds (`with_bbox_into`) | `.with_bbox_max(2lo, 2hi + 1)`, `.with_bbox_min(…)` | "The maximum (minimum) dimension of the bounding box" ([L]), merged (x; fixture `derived/feature_length`) |
| `.rectangles()`, `.squares()` and their `non_` forms | One box with no hole (`rectangles_into`); a square has equal sides | `.rectangles`, `.squares`, `.non_rectangles`, `.non_squares` ([L]) | Both read merged figures at the default coherence, so corner-joined boxes are one non-rectangle (x; fixture `derived/shape_class`) |
| `.with_text(T, "p")` | A text point on the material or its edge; glob `*` and `?` only; case-sensitive | `.interacting(src.labels(T).texts(pattern("p")))` | Text on an edge and on a corner count (v T14, T18). KLayout globs also have `[…]`, `{a,b}` and `\` escapes (Q3) |
| `.without_text(…)` | | `.not_interacting(…)` | |
| `.in_cells("p", …)` | The drawn rows whose placement path (root included) holds a cell matching a pattern; glob `*` and `?` only, case-sensitive; `[`, `]`, `{`, `}` and `\` refused at parse | `src.select("-", "+p", …).global_transform(magnify(2)).polygons(L)` ([S] `Source#select`: a filter enables or disables a cell with its subtree; a cell no filter names inherits its parent's state; `"-"` is the top cell) | Same set by the select rule; the hierarchical fixtures `derived/in_cells/*` run through the mirror |
| `.not_in_cells("p", …)` | The other rows | `src.select("-p", …).global_transform(magnify(2)).polygons(L)` | The selected source drops `src`'s ×2 magnification (a1), so it is applied again (x: every shape came back at half size) |
| `.edges()` | Merged boundary, kept as directed runs, material on the left | `.edges` | KLayout edges are clockwise: same side, opposite direction. Compare edges undirected. |
| `E and F`, `not` | Coincidence ignores direction; each piece keeps its own direction | `E & F`, `E - F` | Same (v T13) |
| `E or F` | Every operand's edges, a shared part once | `E + (F - E)` | `E \| F` cancels coincident edges of opposite direction (v t18 Z6; fixture `derived/edge_booleans`) |
| any edge result | Maximal runs | `( … ).merged` | KLayout can split a run where the other operand's drawn shapes meet (v t18 Z6) |
| `.inside_part(L)` | Strictly inside; parts on L's boundary are in neither result | `.inside_part(L)` | Same (v t13 B1) |
| `.outside_part(L)` | Strictly outside | `E.outside_part(L) - L.edges` | KLayout keeps parts on L's boundary (v t13 B2) |
| `.interacting(L)` on edges | Whole edges that touch, cross or lie inside | `.interacting(L)` | Same (v T13) |
| `.with_length(b)` | Length within the bounds | `.with_length(2lo, 2hi + 1)` | |
| `.horizontal()`, `.vertical()` | The edges along that axis | `.with_angle(0)`, `.with_angle(90)` | An edge layer is axis-aligned, so the two split it (x; fixture `directional`) |
| `.extended(begin, end, out, in)` | One box per edge, unmerged: lengthened before the start and past the end, widened away from and into the shape (`extended_into`) | `.extended(2end, 2begin, 2out, 2in)`, read raw | KLayout's edges run the other way round, so its begin is GPurify's end. Fixtures `derived/extended/*` (the `ends` cases under rotations only) |

### Connectivity, for net_spacing

| Deck | KLayout | Notes |
|---|---|---|
| `connect conductors [c…]` with `connect touch_within_layer` | `connect(c, c)` for each conductor ([N] "connect") | (v t9 N1: touching shapes on one layer join a net.) |
| `connect conductors` without `touch_within_layer` | Cannot be mirrored | KLayout always joins touching shapes on a connected layer ([N]). Such decks are **NONE**. |
| `connect via V [a, b]` | `connect(a, V); connect(V, b)` | GPurify: the cut is no net member and joins one shape of a to one of b where it lands on both. KLayout: the cut belongs to the net, so a cut on two shapes of one layer, or two touching cuts, joins them (v t18 Z8; F88). Marked `{bridge}` per layout. |
| `connect global G` | `connect_global(G, "G")` ([N] "connect_global") | |
| `connect label T names C` | nothing | Labels only name nets; neither tool joins nets by label without `connect_implicit`. |
| Net identity | `L.nets` → property, then `props_eq` / `props_ne` | (v t5 T19) |

### Antenna

`antenna` is an ERC kind, not one of the 54, but `antenna_check` mirrors it. Not translated yet.

**GPurify** (`erc/rules/antenna.rs`)
- For each rule row, the nets are those standing at that etch step: conductors up to the highest
  collector, and the vias between conductors that already stand (`Stack::stage`).
- The ratio is Σ collector area (or perimeter × sidewall) over Σ gate area, per gate net; the net
  fails when it is > `max_ratio`. A gate or cut joins the topmost conductor it overlaps with
  positive area. Collector areas are summed per drawn polygon (F29).

**KLayout**
- For each row, call `clear_connections`, connect the stage's layers, then `connect(gate, poly)`.
- One collector: `antenna_check(gate, coll, max_ratio)`, or with sidewall
  `antenna_check(gate, perimeter_only(coll, t_um), max_ratio)` ([N] "antenna_check").
- Several collectors: `evaluate_nets(gate, {"C1"=>c1, "C2"=>c2}, "var r=(area(C1)+area(C2))/area; skip(r<=thr)", {"thr"=>max})`
  ([N] "evaluate_nets").
- `antenna_electrical`: KLayout's diode spec `[diode, f]` raises the threshold by f × diode area
  in µm², which equals GPurify's `ratio − credit·A − bonus ≤ max` with threshold `max + bonus` and
  f = credit. Compare only rows that ran. A row with `area_minus_diode`, `gate_plus_diode`,
  `cut_factor` other than 1, a `diode_reduce` or `diode_max_ratio` table, or an `exempt` layer
  has no `antenna_check` form; OpenROAD's antenna checker reads the LEF keywords they state
  (`ANTENNAAREAMINUSDIFF`, `ANTENNAGATEPLUSDIFF`, `ANTENNAAREAFACTOR`, the `PWL` tables).

**Verdict: APPROX.** KLayout merges areas per net (F29); a gate joins poly by touching in
KLayout, but only by positive overlap in GPurify.

---

## (d) NONE and APPROX kinds, and their oracles

**NONE**
- **multi_patterning.** Reported as not mirrored. The oracle stays brute-force colouring of small
  conflict graphs (testing-plan L6 skip list); a KLayout conflict graph could feed it.
- **eol_within_spacing.** Reported as not mirrored. The oracles are the LEF 5.8 worked example and
  hand-derived fixtures (rule 49).
- **eol_keep_out.** Reported as not mirrored. The oracle is hand-derived fixtures (rule 50).
- **span_length.** Reported as not mirrored. The oracles are LEF's own span tables and hand-derived
  fixtures (rule 52).
- **exact_pitch.** Reported as not mirrored. The oracles are ASAP7's pitch values and hand-derived
  fixtures (rule 54).
- **net_spacing on a deck without `touch_within_layer`.** The oracle is construct-from-answer
  tests with planted nets.

**APPROX**, and how each is compared:

| Kind | How it is compared |
|---|---|
| eol_spacing | KLayout ⊆ GPurify, GPurify's distance no larger. GPurify's extra pairs: zero-projection keep-out contacts and non-facing approaches. |
| prl_spacing, spacing_table | Exact on R; off R KLayout ⊆ GPurify, because a bounding-box run over-reports. |
| corner_to_corner | Exact on R after dropping pairs whose edges overlap or touch on an axis; off R GPurify ⊆ KLayout. |
| attached_wide_spacing | KLayout ⊆ GPurify. |
| asymmetric_enclosure | Exact when the inner layer is R; off R KLayout ⊆ GPurify. |
| adjacent_enclosure | Exact when the inner layer is R; off R KLayout ⊆ GPurify. |
| min_extension | Exact on R+; not compared off it (bitmap rectangle pairs and the exhaustive fixtures are its oracle). |
| max_distance_to_tap, redundant_via, via_array_spacing | lo ⊆ GPurify ⊆ hi (square and diamond growth), the tap kind with its tap-interior and well-hole allowance. |
| edge_spacing | KLayout ⊆ GPurify; collinear end-to-end pairs are GPurify's only. |
| antenna (ERC) | Not translated yet: compare non-refused rows; F29 differences are expected until F29 is fixed. |

---

## (e) Open questions, and what this turned up in GPurify

### Settled by the translator (F1)

- **The corner model (formerly "pending Q1" on min_width and overlap).** Connected, as KLayout's
  default (a3). Euclidean width across a void between convex-ended edges (the old Q1) does not
  arise: no extra KLayout pair on any fixture or random layout (x).
- **Q2 `tile_count(1, 1)`.** Moot: density windows are laid out explicitly (rule 15).
- **Q5 `whole_edges` on edge layers** is accepted, and **Q10 `E.enclosing(E, …)`** is valid with
  no self-pairs (rule 34, x).
- **Q7 keyholes.** The keyhole corpus cell agrees under `off_grid` (x).
- **Q8 overlapping cuts.** A raw `isolated` pairs abutting cuts but not overlapping ones (v t18
  Z7); rule 25 adds them.
- **Q9 `EdgePair#distance`.** 0 for two degenerate edges (v t18 Z2); the harness measures the
  edges itself.
- **Recipe corrections** the differential forced: `covering` and straddling inners (rule 28),
  layer-wide `enclosing` artifacts (rule 19), a raw polygon never overlapping itself (rule 21),
  `|` on edges and split runs (c), touching cuts (rule 25), the notch and enclosure markers lying
  outside the figure (a4), and `with_width`'s squared bounds, measured exactly (c): after B24
  squared them, the threshold recipe read `< 150nm` as a limit of 45000 and kept every figure,
  so `notch` over the selection reported figures GPurify had not selected.

### Not resolved

1. **Glob escapes (Q3).** KLayout's syntax for escaping `*`, `?`, `[`, `{` and `\` in
   `texts(pattern(...))` is not verified; the translator passes the pattern as written.
2. **Edge merging (Q4).** Collinear edges of opposite direction that touch at a point are not
   joined (x); `|` cancels opposite edges that overlap (v t18 Z6). Other configurations are
   unverified.
3. **`foreign` (Q6).** The universal `drc()` with `foreign` might replace the same-figure filter
   of rules 11, 31 and 32; not explored.

### Found in GPurify

These are not in testing-plan F1–F35. F18, F19, F29 and F34 were confirmed independently.

**N1. A gap in a chain joined at corners was reported by neither rule.** Fixed in B20 (F38, F51):
one corner model, MAX, for booleans and spacing alike (a3).
- Booleans used MIN coherence (`boolean.rs` `successors_into`), but spacing components used MAX
  (`spacing.rs` `prepare`).
- Take squares R1 = (0,0)–(10,10), R2 = (10,10)–(20,20), R3 = (20,0)–(30,10). The 10-wide gap
  between R1 and R3 is:
  - not a notch, because the three squares are separate figures;
  - not a space, because they form one component.
- It is never reported, at any limit. That is a false clean (B1).
- KLayout's default (MAX) `notch` and `space` flag it (v T5).
- Fix: one coherence for both. MAX matches KLayout and foundry decks.

**N2. `with_width` was projection-only.** Fixed in B16 (F39/F55).

**N3. The density die grew with derived layers.** Fixed in B16 (F40).

**N4. `min_extension` judged pairs that only touch.** Recorded as F41; fixed in B15.

**N5. `eol_spacing` read ends of line from drawn rows.** Fixed in B14: ends are read off the
merged layer.

**N6. The `drc_oracle.rb` families.** Retired in F1, with the experiments the translator
superseded (`header.drc`, `mirror_t.drc`, `p.drc`, `lib.rb`, `mk*.rb`).

**N7. `corner_to_corner` could miss an L-shaped row** whose bounding box overlaps its neighbour on
one axis. Fixed in B14 (convex corners of the merged layer).

**F88. An implementation difference: a via cut that lands on one of its two layers.** Not a
defect in either tool. GPurify's `extract_nets_into` joins one shape of a cut's first layer to one
of its second where the cut lands on both, and the cut is no net member, as `deck.md` and
`topology/net.rs` document. KLayout's cut is a net member, so a cut on two met1 shapes with
nothing above, or two touching cuts that each land on one, joins them. Both follow their own
documentation, and nothing documents what such an ill-formed via (one the via-enclosure rule
flags) should connect.
- Repro: `grid 1nm`, `met1 = gds(68, 20)`, `via1 = gds(68, 44)`, `met2 = gds(69, 20)`,
  `connect conductors [met1, met2]`, `connect touch_within_layer`, `connect via via1 [met1, met2]`,
  `rule dn space(met1; nets: different) >= 100nm`; met1 (0,0)–(500,500) and (550,0)–(1050,500),
  via1 (450,200)–(600,300). GPurify reports `dn` at 50 nm, (525, 250); KLayout finds the two
  shapes on one net (v t18 Z8). Two touching cuts (450,200)–(520,300) and (520,200)–(600,300)
  give the same.
- Effect: a false open in LVS and in every net-aware check; `net_spacing` swaps same and
  different. A cut on no upper shape is itself an enclosure error, which limits the reach.
