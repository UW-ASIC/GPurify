# KLayout mirror deck: per-kind translation of GPurify DRC into KLayout 0.30.8

Research for `docs/testing-plan.md` §4 L6, "Mirror deck". The repo was only read.
GPurify semantics come from the code at HEAD: `crates/check/src/drc/{ruleset.rs,rules/*.rs}`,
`crates/geom/src/{boolean.rs,derive.rs,width.rs}`, `crates/ingest/src/layout.rs`, `docs/deck.md`.
Function names are cited rather than line numbers, because the files are being edited concurrently.

The markers mean:
- **(v)**: verified by running KLayout 0.30.8 in batch mode (`nix develop .#oracles`). The
  scripts are in `tools/klayout/experiments/t1.drc … t17.drc`, `header.drc` and `mirror_t.drc`, with the
  test id in brackets.
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
- **Run the whole mirror on a ×2 copy:** `SRC = source($gds).global_transform(magnify(2))`
  ([S] "global_transform", spec `magnify(m)`; (v T12) the doubling is exact).
  - Emit every length as 2·L and every area as 4·A.
  - Every half-length that GPurify implies then becomes an integer: `sized(-limit/2)` for
    `max_width`, `(t-1)/2` for wide parts, `limit/2` for cluster growth, and `(window-step)/2`
    for the density tile offset.
  - Distances compare the same way (`d < L ⇔ 2d < 2L`), and density ratios are unchanged.
  - The harness divides every output coordinate by 2.
- **Put `flat` first** ([G] "flat"). With no tiling and no deep mode, flat `Region` semantics
  apply, including `Region#min_coherence`.

### a2. Loading layers

- **Drawn polygon layers:** `SRC.polygons(L, D)`. Do not use `input`: it also fetches texts,
  which become 2×2 DBU dummy boxes ([L] "texts").
- **Text layers:** `SRC.labels(L, D)`. (v p.drc: on the ×2 source, both `polygons` and `labels`
  come back doubled.)
- **`ignore gds(L, D)` pairs:** never loaded. GPurify refuses a GDS with undeclared pairs, so the
  harness only feeds layouts GPurify accepted.
- **Derived layers:** translated as in (c), then wrapped in `mc(...)`. GPurify stores each derived
  layer as merged, minimum-coherence figures (`ingest/src/layout.rs`, derived loop:
  `store.append_layer` of the boolean or selection result).
- **`.raw` mutates the layer object** ([L] "raw": "this method will set the state of the layer").
  Call it only on a fresh `SRC.polygons(...)` or on a `.dup`.

### a3. Merge coherence: the one semantic every kind has to pin

- **KLayout default: maximum coherence.** Two shapes that touch only at a corner merge into one
  polygon ([R] "min_coherence=": "The default setting is maximum coherence").
  - (v T2) Two such squares merge into one polygon.
  - `width`, `space` and `notch` then flag the touching corner at distance 0, unless the check
    has `without_touching_corners`.
- **GPurify uses two different notions.**
  - **MIN (minimum coherence).** Booleans and merges keep two cells that meet at a corner as two
    rings (`boolean.rs` `successors_into`: "At a degree-four pinch the left turn is taken, keeping
    two cells meeting at a corner as two simple rings"). Used by `min_width`, `notch`, `max_width`,
    `cut_size`, `min_area`, `min_enclosed_area`, `cheesing`, `must_contain`, `must_be_inside`,
    enclosure hosts, the `edge_enclosure` outer layer, and every derived layer.
  - **MAX (maximum coherence).** "Components" are drawn rows at distance 0 (`spacing.rs`
    `prepare` → `label_pairs_into(|d2| d2 == 0)`, and `patterning.rs`); a shared corner joins.
    Used by `min_spacing`, `eol_spacing`, `prl_spacing`, `corner_to_corner`, the wide kinds,
    `net_spacing`, `spacing_table` and `multi_patterning`.
- **Mirror rule:** `def mc(l); c = l.dup; c.data.min_coherence = true; c; end` for MIN kinds,
  and the plain layer for MAX kinds.
  - (v T2, t15 K1/K3, t17) `with_area` and universal `drc(...)` honour the flag, and the `dup`
    leaves the original layer at MAX.
- **Two traps** (v T2, t15):
  - The DSL `merged` method ignores the flag.
  - Chaining selections re-merges each new layer at MAX.
  - So use one universal `drc(...)` pass, or wrap every intermediate in `mc`. To output figures,
    use `layer.data.merged`, which honours the flag (`Region#merged`, [R]; (v header.drc)).

### a4. Comparison unit: drawn rows or merged figures

GPurify reports `shapes: (row, row?)` and `at`. A row is a store polygon: a drawn GDS polygon, or
the outer ring or a hole ring of a keyhole, which ingest splits into an outer row plus hole rows.
- Some kinds work on drawn rows and others on merged figures.
- On a derived layer, rows already are figures.
- KLayout works on merged polygons (clean mode) unless `.raw` is used.

So compare at the coarsest unit both tools share. For every layer that a FIG or PAIR rule reads,
the script also emits `fig:min:<layer>` and `fig:max:<layer>` (that layer's `data.merged` at each
coherence), so the harness never needs GPurify code to key a result.

| Key | Meaning | From a GPurify violation | From a KLayout result |
|---|---|---|---|
| FIG | One merged figure of the rule's layer, at the kind's coherence | `shapes.0` (owner row) → the `fig:` polygon it overlaps with positive area | Polygon → itself. Edge pair → the figure that contains the midpoint of its first edge (closed). |
| PAIR | An unordered pair of figures | Both rows → figures. A hole row maps to the figure it bounds. | Edge pair → (figure of edge 1, figure of edge 2). An overlap polygon → (A-figure, B-figure) containing it. |
| ROW | One drawn polygon | `shapes.0` | A `.raw` polygon, matched by (bbox, area) |
| HOLE | One hole of a figure | `at` = centre of the hole's bbox | Hole polygon → centre of its bbox |
| EDGE | An undirected edge, or an edge pair | `at` + `measured` (midpoint floored, length) | Edge → (floored midpoint, length). Edge pair → (midpoint of the gap between the two edges' bboxes, floor of the distance). |
| VTX | A vertex | `at` | The point marker from `ongrid` |
| WIN | One density window | `at` = window centre | Centre of the tile box |
| DIE | The whole-die verdict | 0 or 1 violation | 0 or 1 marker |

How keys are compared:
- Keys compare per rule id, as sets. GPurify emits one violation per drawn-row pair and KLayout
  one per edge pair, so both sides dedupe first.
- **Secondary check 1, marker.** GPurify's `at` lies in the closed KLayout figure of its key, to
  within one grid step. This does not apply to spacing: there `at` is the midpoint of the gap
  between the two rows' bboxes (`gap_midpoint`), which is not a geometric point of the violation.
- **Secondary check 2, measured value.** For distance kinds, GPurify's `measured` (rounded down
  to whole DBU, `isqrt`) equals the minimum `EdgePair#distance / 2` over the key, to within 1 DBU.

Some kinds are APPROX in general but EXACT on two restricted layout classes. L6 generators should
tag each layout with the classes it satisfies:
- **R:** every shape on the rule's layers is a rectangle, and no two shapes on one layer touch or
  overlap, so rows = figures = boxes.
- **X:** no two shapes of interest are diagonal neighbours within the limit (every near pair shares
  an x or a y projection), so Euclidean = Chebyshev = L1 distance.

### a5. Limit equality

- **GPurify is strict everywhere** (`report/measure.rs` `Measurement::violates`: "a value exactly
  at its limit is legal under both senses").
- **KLayout classic checks flag `d < value` and never equality.** (v T1 `width`, T3 `isolated`
  40/41, T6 `separation` 50/51, T7 `enclosing` 30/31, T8 `overlap` 20/21.) The universal
  `drc(width <= v)` does include equality (v T1).
- **Selection ranges:**
  - `with_area`, `with_length` and `with_bbox_*` take [min, max) ([L] "with_area": "larger or
    equal to min and less (but not equal to) max").
  - `with_density` and `without_density` take a closed [min, max]. (v t8, t9 D1/D2: a tile at
    density 0.5 is inside both `nil..0.5` and `0.5..nil`.)
- **Bound translation** at ×2 (integers):

  | GPurify bound | KLayout length bound | KLayout area bound |
  |---|---|---|
  | `>= a` | min 2a | min 4a |
  | `> a` | min 2a+1 | min 4a+1 |
  | `< b` | max 2b | max 4b |
  | `<= b` | max 2b+1 | max 4b+1 |
  | `== a` | the single-value form | the single-value form |

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

**JSON lines.** This is the harness format, the same pattern the existing `drc_oracle.rb` prints.
(v `header.drc` on edges, edge pairs and polygons with holes):

```ruby
# generated by tools/klayout/translate.rs — KLayout 0.30.8
require "json"
flat
SRC  = source($gds).global_transform(magnify(2))   # every half-DBU becomes an integer
$out = File.open($jsonl, "w")
def pts(it) ; it.map { |p| [p.x, p.y] } ; end
def seg(e)  ; [e.x1, e.y1, e.x2, e.y2] ; end
def emit(rule, layer)                               # one line per object, integer DBU of the x2 layout
  data = layer.is_a?(DRC::DRCLayer) ? layer.data : layer
  data.each do |o|
    rec = case o
          when RBA::EdgePair then { ep: [seg(o.first), seg(o.second)], d: o.distance }
          when RBA::Edge     then { e: seg(o) }
          when RBA::Polygon  then { hull: pts(o.each_point_hull),
                                    holes: (0...o.holes).map { |h| pts(o.each_point_hole(h)) } }
          else { other: o.to_s }
          end
    $out.puts JSON.generate({ rule: rule }.merge(rec))
  end
end
def mc(l) ; c = l.dup ; c.data.min_coherence = true ; c ; end   # GPurify's boolean coherence
# ... layers (c), then one block per rule (b), then:
$out.close
```

Run it as `klayout -b -rd gds=<file> -rd jsonl=<out> -r mirror.drc` (v).

**lyrdb, for people triaging.** Call `report("mirror", $lyrdb)` once, then
`result.output(rule_id, description)` for each rule ([G] "report", [L] "output"). The format
(v t6 `out.lyrdb`):
- The file is `<report-database>`. Under `<categories>`, each `<category>` holds `<name>m1.1</name>`
  and `<description>`.
- Each result is an `<items><item>` with `<category>'m1.1'</category>`, `<cell>TOP</cell>` and
  `<values><value>…</value></values>`. A category name containing `.` is single-quoted, because
  `.` separates sub-categories.
- Values are text in µm (DBU × dbu), doubled under ×2:
  - `polygon: (x,y;…/hx,hy;…)`, with each hole after a `/`;
  - `edge: (x1,y1;x2,y2)`;
  - `edge-pair: (e1)|(e2)`, where `|` marks a symmetric pair (from `width` or `space`) and `/` a
    two-layer pair;
  - `box: (l,b;r,t)`.
- The file does not store the dbu, so pass it to the parser.
- To parse: read the XML, take each item, strip the quotes from the category, match the value
  with a regex per prefix, convert µm to DBU with `round(v/dbu)`, then divide by 2.

JSON lines avoid both the float round-trip and the XML; keep the lyrdb only for viewing in KLayout.

---

## (b) Per kind

Notation in the snippets:
- `L`, `A`, `B`, `I` (inner), `O` (outer), `T` (tap), `C` (cut) and `E`, `F` (edge layers) are
  layers built per (a2) and (c).
- Uppercase literals are already doubled: `LIM` = 2·limit DBU, `AREA4` = 4·limit DBU².
- Any other scaling is stated next to the literal.

**Coherence column:** MIN = wrap the layer in `mc()`; MAX = the default; raw = `.raw`.

| # | Kind | Deck form | Coherence | Key | Verdict |
|---|---|---|---|---|---|
| 1 | min_width | `width(L) >= l` | MIN | FIG | EXACT (pending Q1) |
| 2 | max_width | `width(L) <= l` | MIN | FIG (region geometry) | EXACT |
| 3 | cut_size | `size(L) == w x h` | MIN | FIG | EXACT |
| 4 | min_edge_length | `edge_length(L) >= l` | raw | EDGE | EXACT (no keyholes) |
| 5 | notch | `notch(L) >= l` | MIN | FIG | EXACT |
| 6 | min_spacing | `space(L) >= l` | MAX | PAIR | EXACT |
| 7 | min_spacing_diff | `space(A, B) >= l` | MAX | PAIR | EXACT |
| 8 | eol_spacing | `eol_space(L; eol_width)` | MAX | PAIR | APPROX (EXACT on R, minus one boundary case) |
| 9 | prl_spacing | `prl_space(L; prl)` | MAX | PAIR | APPROX (EXACT on R) |
| 10 | corner_to_corner | `corner_space(L)` | MAX | PAIR | APPROX (EXACT on R, with a filter) |
| 11 | wide_dependent_spacing | `wide_space(L; width)` | MAX | PAIR | EXACT (with a same-figure filter) |
| 12 | min_area | `area(L) >= a` | MIN | FIG | EXACT |
| 13 | min_enclosed_area | `hole_area(L) >= a` | MIN | HOLE | EXACT |
| 14 | cheesing | `cheesing(L) <= a` | MIN | FIG | EXACT |
| 15 | density | `density(L[, bnd]; window, step)` | n/a | WIN | EXACT, except near-ties |
| 16 | global_density | `global_density(L[, bnd])` | n/a | DIE | EXACT, except near-ties |
| 17 | min_enclosure | `enclosure(i, o) >= l` | rows / MIN host | FIG (inner) | EXACT |
| 18 | asymmetric_enclosure | `enclosure(i, o, opposite) >= l` | rows | FIG (inner) | APPROX (EXACT for rectangular inners) |
| 19 | min_extension | `extension(A, B) >= l` | rows (bbox) | PAIR | APPROX (EXACT on R with overlap) |
| 20 | overlap | `overlap(A, B) >= l` | rows (bbox) | PAIR | APPROX (EXACT on R, disjoint intersections) |
| 21 | max_distance_to_tap | `tap_distance(w, t) <= l` | rows | ROW | APPROX (bracket) |
| 22 | off_grid | `off_grid(; pitch)` | raw, every layer | VTX | EXACT |
| 23 | angle | `angle([L]; allowed)` | raw | EDGE (coverage) | EXACT |
| 24 | redundant_via | `redundant_via(L; within) >= n` | raw | ROW | APPROX (bracket; EXACT on X) |
| 25 | via_array_spacing | `via_array_space(L; array) >= l` | raw | PAIR (rows) | APPROX (bracket; EXACT on X) |
| 26 | multi_patterning | `patterning(L; colors) >= l` | MAX | DIE (feasible?) | NONE (hybrid oracle) |
| 27 | forbidden | `forbidden(L)` | raw / derived | ROW / EDGE | EXACT |
| 28 | must_contain | `contains(o, i) >= n` | MIN | FIG (outer) | EXACT |
| 29 | must_be_inside | `inside(i, o)` | MIN | FIG (inner) | EXACT |
| 30 | net_spacing | `space(L; nets: same\|different)` | MAX | PAIR | EXACT if connectivity can be mirrored, else NONE |
| 31 | spacing_table | `space_table(L; …)` | MAX | PAIR | APPROX (EXACT on R) |
| 32 | attached_wide_spacing | `wide_space(L; width, attached)` | MAX | PAIR | APPROX |
| 33 | edge_min_length | `length(E) >= l` | edge layer | EDGE | EXACT |
| 34 | edge_spacing | `space(E[, F]) >= l` | edge layer | EDGE (pair) | APPROX (collinear pairs) |
| 35 | edge_enclosure | `enclosure(E, L) >= l` | edge layer | EDGE | EXACT |

`examined` is GPurify-only; KLayout has no equivalent. Where GPurify's examined is a figure count,
`mc(L).data.merged.count` cross-checks it.

### 1. min_width — EXACT, pending Q1

**GPurify** (`width.rs` `facing`, `material_between = true`)
- Merges the layer with `union_into` (MIN). For each figure it takes the minimum of two measures:
  - Parallel edges facing each other across material, with projections that overlap by a positive
    length; the distance is perpendicular (`geom/width.rs` `narrowest_facing`).
  - The Euclidean gap between two concave corners whose voids point at each other
    (`narrowest_neck`, rounded down to whole DBU).
- Holes count.
- At most one violation per figure, when the minimum is < limit.
- `at` is the midpoint of the narrowest pair; the shape is the lowest drawn row under the figure
  (`owners_of`).
- `examined` is the number of drawn polygons.

**KLayout**

```ruby
emit(id, mc(L).width(LIM, euclidian, shielded, without_touching_corners))
```

- Euclidean width covers both GPurify measures. (v T4: two 100-DBU squares offset by 70 give a
  neck of √1800 = 42.4; `width(43)` flags it, `width(42)` does not, and `projection` does not.)
- Under `mc`, two squares touching at a corner are separate polygons, so
  `without_touching_corners` is only a safeguard (v T2: without it, the touching corner is
  flagged).

### 2. max_width — EXACT

**GPurify** (`width.rs` `max_width`)
- Regions are the union of every (limit+1)-square that fits in the merged layer
  (`wide_rects_into`), merged at MIN.
- One violation per region, at its narrowest facing pair, which is the value reported (> limit).
- `examined` is the number of drawn polygons.

**KLayout**

```ruby
wide = mc(L).sized(-H).sized(H)      # H = limit in original DBU, i.e. LIM/2 at x2
emit(id, mc(wide).data.merged)
```

- An opening by H keeps exactly the parts wider than 2H. (v T10: for a 100-wide L-shape,
  `sized(-50)` leaves nothing and `sized(-49)` leaves a 2-wide sliver.)
- That is the same set as GPurify's: `wide_rects_into` itself cites
  `KLayout sized(-w/2).sized(w/2)`.
- Compare the region polygons exactly, after dividing by 2. This is stronger than FIG.

### 3. cut_size — EXACT

**GPurify** (`width.rs` `cut_size`)
- Works per merged figure (MIN). A figure fails when its short side is wrong, its long side is
  wrong, or it is not a rectangle (a ring of 4 vertices with no hole).
- `at` is the bbox centre; `examined` is the number of figures.

**KLayout**

```ruby
emit(id, mc(L).drc(if_any(! rectangles, bbox_min != SHORT, bbox_max != LONG)))
```

- One universal pass keeps MIN, so two correct cuts touching at a corner pass. (v t15 K1/K2:
  without `mc`, those two cuts fail as one non-rectangle.)

### 4. min_edge_length — EXACT if the layout has no keyholes

**GPurify** (`width.rs` `min_edge_length`)
- Checks every edge of every validated drawn polygon (holes included) without merging (F18), and
  flags edges shorter than the limit.
- `at` is the edge midpoint; `examined` is the number of edges.

**KLayout**

```ruby
emit(id, SRC.polygons(l, d).raw.edges.with_length(nil, LIM))   # a drawn layer
emit(id, DERIVED.edges.with_length(nil, LIM))                  # a derived layer: rows are already figures
```

**Caveat.** GPurify splits a GDS keyhole into an outer row and hole rows (`ingest/src/layout.rs`
→ `canonical_rings_into`). KLayout's raw polygon keeps the slit edges, so generators must not
write keyholes. The mirror encodes the implementation, F18 included.

### 5. notch — EXACT

**GPurify** (`facing`, `material_between = false`)
- Measures facing edges across a void inside one merged figure (MIN), holes included, by
  projection only (no corner-to-corner distance).
- One violation per figure, at the midpoint; `examined` is the number of drawn polygons.

**KLayout**

```ruby
emit(id, mc(L).notch(LIM, projection))
```

- `notch` is the space check within one polygon ([L] "notch"); the `projection` metric gives
  facing edges only.
- Shielding cannot change the minimum.
- See finding N1.

### 6. min_spacing — EXACT

**GPurify** (`spacing.rs` `min_spacing`)
- Works on drawn rows. Components are rows at distance 0 (touching, including at a corner), plus
  nesting (`join_nested`).
- Every candidate pair from two different components whose exact Euclidean boundary distance is
  < limit is one violation, keyed by the row pair.
- An island inside a hole is measured to the hole ring.
- `at` is the gap midpoint of the two rows' bboxes; `examined` counts every candidate pair.

**KLayout**

```ruby
emit(id, SRC.polygons(l, d).isolated(LIM, euclidian, transparent))
```

- `isolated` checks between different polygons only ([L] "isolated"). At MAX coherence it merges
  the same components (v T2: `isolated` finds nothing between corner-touching squares). Notches
  belong to rule 5.
- Key: PAIR, plus the measured-value check.

### 7. min_spacing_diff — EXACT

**GPurify** (`spacing.rs` `min_spacing_diff`)
- No component exemption: every cross-layer pair with distance < limit is a violation. Overlap and
  nesting have distance 0 (`join_nested`).
- Reported on layer `a`.

**KLayout**

```ruby
emit(id, A.separation(B, LIM, euclidian, transparent))   # gaps, plus abutting and corner-touching (d = 0)
emit(id, A & B)                                          # overlap and nesting
```

- `separation` reports abutting edges and touching corners, but not overlapping or nested shapes
  (v T6: nested → 0, partial overlap → 0, abutting → 1, touching corner → 2). Hence the `A & B`.
- Key: PAIR.

### 8. eol_spacing — APPROX (EXACT on R, minus one boundary case)

**GPurify** (`spacing.rs` `eol_spacing`, `eol_hit`)
- For each pair of rows in separate components, each axis-aligned edge of a drawn row that is
  shorter than `eol_width` is an end of line.
- Its keep-out zone is the edge's span pushed `limit` outward, as a closed box.
- Every edge of the other row that meets the zone is measured by Euclidean segment distance. The
  pair fails when the minimum is < limit. Both directions are checked.

**KLayout**

```ruby
emit(id, SRC.polygons(l, d).isolated(LIM, projection, transparent, whole_edges).with_length(nil, EOLW))
```

`with_length` on edge pairs keeps a pair when either whole edge is shorter than `eol_width`
([L] "with_length"). (v t16 Q3/Q3b: the end of a 50-wide line, 30 below a neighbour, is kept;
the side-by-side pair is dropped.)

**Differences**
1. GPurify takes ends of line from drawn rows, so an edge shared by two abutting rows is an end of
   line whose keep-out passes through its own figure (N5).
2. A far edge that touches the zone only at the end of the span (a zero-length projection) is
   measured by GPurify (`Bbox::overlaps` is closed) but not by KLayout's `projection`. The harness
   drops such pairs; they can be recomputed from the two rows.
3. Rows that are not rectangles.

### 9. prl_spacing — APPROX (EXACT on R)

**GPurify**
- The run length is the larger of the two row bboxes' projection overlaps
  (`parallel_run_length`). The bbox over-reports for non-convex rows, which fails closed.
- A pair is judged when run ≥ prl; it fails when its whole-pair Euclidean distance is < limit.

**KLayout**

```ruby
emit(id, SRC.polygons(l, d).isolated(LIM, euclidian, transparent, projection_limits(PRL, nil)))   # PRL = 2·prl
```

(v t11 P3/P4: `projection_limits(100, nil)` behaves exactly like `projecting >= 100`.)

Off R the check is one-sided: KLayout ⊆ GPurify.

### 10. corner_to_corner — APPROX (EXACT on R, with a filter)

**GPurify**
- Judges only pairs whose row bboxes overlap on neither axis (overlap strictly negative on both).
- Fails when the Euclidean distance is < limit.

**KLayout**

```ruby
emit(id, SRC.polygons(l, d).isolated(LIM, euclidian, transparent, projection_limits(0, 1)))
```

- This keeps edge pairs with zero projection (v t11 P1 ≡ P2 `projecting < 1`).
- **Boundary case.** When two bboxes touch on one axis (`A.xhi == B.xlo`), GPurify does not treat
  the pair as diagonal (the overlap is 0, not < 0), but KLayout still reports a pair whose
  projection has zero length (v P1, third pair). The harness drops KLayout pairs whose figure
  bboxes touch on an axis.
- Off R, GPurify's bbox test and the real corners disagree for L-shaped rows (N7).

### 11. wide_dependent_spacing — EXACT, with a same-figure filter

**GPurify** (`spacing.rs` `wide_dependent`, `wide_parts`)
- Wide parts are the union of every square of side `width_threshold` that fits ("a shape exactly
  w wide counts as wide", `wide_rects_into`).
- For each pair of rows in separate components where either row has wide parts, it takes the
  minimum distance from the wide parts (clipped to their own row) to the other row's ring. The
  pair fails when that is < limit.

**KLayout**

```ruby
m    = SRC.polygons(l, d)
wide = m.sized(-(T - 1)).sized(T - 1)   # T = width_threshold in original DBU; at x2 this keeps width >= T
emit(id, wide.separation(m, LIM, euclidian, transparent))
```

- Where a wide edge coincides with an edge of its own figure, both face the same way, so the pair
  is not reported (v `mirror_t.drc`).
- The figure's own edges can still face its wide part across a notch. The harness drops pairs
  whose two edges lie on one MAX figure.
- Key: PAIR.

### 12. min_area — EXACT

**GPurify** (`area.rs` `min_area`)
- Works per merged figure (MIN). The area excludes holes (`covered_area`); the figure fails when
  that area is < limit.
- `at` is the centre of the figure's first rectangle; `examined` is the number of figures.

**KLayout**

```ruby
emit(id, mc(L).drc(area < AREA4))
```

(v t15 K3: two squares touching at a corner are counted separately, as GPurify does.)

### 13. min_enclosed_area — EXACT

**GPurify**
- Checks each hole ring of each merged figure (MIN) against the limit (fails when < limit).
- `at` is the centre of the hole's bbox; `examined` is the number of holes.

**KLayout**

```ruby
emit(id, mc(mc(L).holes).drc(area < AREA4))
```

(v t16 Q2.)

### 14. cheesing — EXACT

**GPurify:** a figure fails when its area is > `max_unslotted` and it has no hole.

**KLayout**

```ruby
emit(id, mc(L).drc(if_all(area > AREA4, with_holes == 0)))
```

(v t16 Q1.)

### 15. density — EXACT, except near-ties

**GPurify** (`area.rs` `density`, `die_of`, `positions`)
- **The die** is the extent of the boundary layer. Without one, it is the union of the bboxes of
  every store layer, including derived ones (N3).
- **The layer** is merged, then clipped to the die.
- **The windows** are squares of side W at origins die.lo + i·S, with
  NX = ⌈(span − W)/S⌉ + 1 (at least 1).
- **Each window's value** is (covered area inside the die) / W², so the part of a window outside
  the die counts as empty.
- A window fails when its value is < limit (minimum rule) or > limit (maximum rule).
- `at` is the window centre; `examined` is the number of windows.

**KLayout**

```ruby
die = polygon_layer ; die.insert(RBA::Box.new(DX1, DY1, DX2, DY2))   # x2 DBU
cov = L & die
off = (W - S) / 2                                                   # an integer at x2
args = [tile_size(W.dbu), tile_step(S.dbu), tile_origin((DX1 + off).dbu, (DY1 + off).dbu), tile_count(NX, NY)]
emit(id, minimum ? cov.without_density(LIMIT .. nil, *args) : cov.without_density(nil .. LIMIT, *args))
```

- **The die.** Compute it in the script, as the union of `bbox` over every drawn and every derived
  polygon layer (`Layer#bbox` returns a DBox in µm (v t14)), or pass it in with `-rd`.
- **Tile placement.** When the step is smaller than the size, tiles are centred on the step cells.
  So `tile_origin` = corner + (W − S)/2. (v t6 T21b: an origin of 0.125 µm with size 0.5 and
  step 0.25 gives tiles at 0, 250 and 500 DBU.)
- **Range bounds** are closed (v D1/D2).
- **Padding.** `padding_zero`, the default, matches GPurify's "outside counts as empty" once the
  layer is clipped to the die.
- **Quirk.** `tile_count(1, 1)` returns no tiles at all in 0.30.8 (v t7/t8, A–H). When NX·NY = 1,
  request (2, 1) and drop the extra window.
- **Ties.** Both tools compute the ratio as a double. Drop windows within 1e-9 of the limit.
- Key: WIN.

### 16. global_density — EXACT, except near-ties

**GPurify:** the merged area clipped to the die, over the die area, compared strictly. At most one
violation, at the die centre; `examined` = 1.

**KLayout**

```ruby
r = (L & die).data.area.to_f / die.data.area           # Region#area is an integer in DBU², so the ratio is exact
emit(id, die) if (minimum ? r < LIMIT : r > LIMIT)
```

Use `data.area`, not `Layer#area`, which returns µm² (v t14).

### 17. min_enclosure — EXACT

**GPurify** (`overlay.rs` `enclosure`, `boundary_dist2`)
- For each drawn inner polygon, the best host is a merged outer figure (MIN) that covers all of the
  inner polygon's area.
- The enclosure is the Euclidean distance from the inner region to the host's boundary, holes
  included.
- With no host, the measure is 0, which is a violation.
- `examined` is the number of inner polygons.

**KLayout**

```ruby
ep = O.enclosing(I, LIM, euclidian, transparent)
emit(id, I.not_inside(O))                 # no host, or straddling a host's edge: GPurify measures 0
emit(id, I.interacting(ep.second_edges))  # inner figures whose margin is too small
```

- `enclosing` ignores inner shapes that are partly or fully outside ([L]; (v T7: both cases give
  0)), hence the `not_inside`.
- Coincident edges are reported at distance 0 (v T7, touching case).
- Corner-to-corner distances count, as in GPurify (v T7, notched host).
- The figure-level verdicts agree: the distance from a figure is the minimum over its rows, and a
  figure is "not inside" exactly when some row has no host.

### 18. asymmetric_enclosure — APPROX (EXACT for rectangular inner rows on R)

**GPurify** (`overlay.rs` `strips`, `enclosure_of`)
- For a rectangular inner row, each side's margin is the distance to the nearest host edge across
  that side's open span (projection).
- The measure is `max(min(l, r), min(b, t))`, which fails when < limit.
- A non-rectangular inner falls back to Euclidean distance on all sides (fails closed). An inner
  with no host measures 0.

**KLayout**

```ruby
c = enclosed(O, projection) < LIM
emit(id, I.drc(if_all(c.first_edges.angle == 90, c.first_edges.angle == 0)))   # fails on both axes
emit(id, I.not_inside(O))
```

- (v t4 T17: a host with one notch that leaves one side short passes; an L-shaped short margin
  fails.)
- **Do not use the classic rectangle filter** (`one_side_allowed, two_opposite_sides_allowed`). It
  stops waiving when an error covers only part of a side, even with `whole_edges` (v t3 T9e).
- **Where it diverges:** for a non-rectangular inner, GPurify uses Euclidean distance on all sides
  and KLayout projection per side; for abutting inner rows, GPurify judges each row's side through
  its neighbour.

### 19. min_extension — APPROX (EXACT on R when every judged pair overlaps)

**GPurify** (`overlay.rs` `min_extension`, `smallest_protrusion`)
- Judges every (a, b) row pair whose bboxes touch or overlap. The index prune at distance 0
  includes boxes that only touch (`index.rs`: "touching at 0").
- The measure is the smallest positive protrusion of a's bbox past b's bbox, or 0 when a
  protrudes nowhere; it fails when < limit.

**KLayout**

```ruby
emit(id, A.enclosing(B, LIM, projection, transparent, without_touching_edges))   # each side where A protrudes
emit(id, A.inside(B))                                                            # A protrudes nowhere: GPurify measures 0
```

- For rectangles that overlap with positive area, every side where A protrudes has a B edge
  facing the same way inside A, with a positive projection.
- Sides with zero protrusion are excluded by both tools: by "positive" in GPurify and by
  `without_touching_edges` in KLayout.
- **Where it diverges:**
  - Pairs that only touch: GPurify measures the far protrusion and can report a false violation
    (N4). KLayout ignores them.
  - Bounding boxes against real shapes (`limitations.md:20`, F19).
- The alternative oracle is the bitmap DRC (testing-plan C5).

### 20. overlap — APPROX (EXACT on R with disjoint intersections)

**GPurify:** for every (a, b) row pair whose bboxes touch or overlap, the measure is the smaller
side of the bbox intersection, 0 when they only touch. `at` is the intersection centre.

**KLayout**

```ruby
emit(id, mc(A & B).width(LIM, projection))   # an intersection narrower than the limit
emit(id, A.separation(B, 1))                 # pairs that only touch (d = 0; 1 DBU at x2 is half a DBU)
```

- The native `overlap` is a two-layer width check ([L] "overlap"). It never sees a full cross,
  where both bounding edges belong to B, so it is not used.
- The recipe diverges when the intersections of different pairs touch (`A & B` merges them), and
  for shapes that are not rectangles (F19).

### 21. max_distance_to_tap — APPROX (bracket)

**GPurify** (`overlay.rs` `max_distance_to_tap` → `supply.rs` `untied_points`)
- For each well row, including hole rows (F34), it finds the furthest point by branch and bound and
  measures its distance to the tap *edges*, holes included.
- A well fails when that distance is > limit (strict). `at` is that point.
- A point inside a tap is measured to the tap's edge, which over-reports.

**KLayout**

```ruby
w  = SRC.polygons(lw, dw).raw ; t = SRC.polygons(lt, dt)
lo = w.overlapping(w - t.sized(LIM))                  # square ball, Chebyshev distance: under-reports
hi = w.overlapping(w - t.sized(LIM, diamond_limit))   # L1 ball: over-reports
```

- (v t13 S1: `diamond_limit` cuts each convex corner to the L1 ball.)
- **Oracle:** lo ⊆ GPurify ⊆ hi.
- GPurify may go beyond hi only where its `at` lies inside a tap (the documented over-report).
- No Euclidean sizing exists in KLayout, so this stays a bracket.

### 22. off_grid — EXACT

**GPurify** (`grid.rs` `off_grid`): every vertex of every store row on every layer, derived and
hole rows included, whose Chebyshev offset from the lattice is non-zero. `at` is the vertex.

**KLayout**

```ruby
ALL.each { |x| emit(id, x.raw.ongrid(PITCH)) }   # every drawn and every derived polygon layer; PITCH = 2·pitch
```

- A merged `ongrid` hides vertices that end up inside material; `.raw` reports them (v T16).
- Collinear vertices are kept (v col.rb).
- Compare as a set of points.

### 23. angle — EXACT

**GPurify** (`grid.rs` `angle`)
- Checks every non-zero edge of every row on the layer (or on every layer) against the allowed
  lines 0, 45, 90 and 135.
- `at` is the start vertex in counter-clockwise order.

**KLayout**

```ruby
bad = x.raw.edges
ALLOWED.each { |a| bad = bad.without_angle(a) }   # deck 135deg → -45
emit(id, bad)
```

- 45 and −45 are distinct angles (v T16).
- KLayout edges run clockwise. So the harness turns each GPurify `(row, at)` into an undirected
  segment, and compares the per-layer union of offending segments.

### 24. redundant_via — APPROX (bracket; EXACT on X)

**GPurify** (`via.rs` `redundant_via`)
- Works on unvalidated cut rows. A cut's count is 1 (itself) plus every other cut whose boundary
  distance is ≤ within (inclusive).
- The cut fails when the count is < min_count. `at` is its centre.

**KLayout**

```ruby
c  = SRC.polygons(lc, dc).raw
lo = c.not_interacting(c.sized(WITHIN).raw, MIN_COUNT)                   # Chebyshev: fewest violations
hi = c.not_interacting(c.sized(WITHIN, diamond_limit).raw, MIN_COUNT)    # L1: most violations
```

- Raw growth plus a counted `interacting` counts each grown cut, the cut itself included (v t10
  R1/R2).
- Without `.raw`, the grown cuts merge and the count breaks (v t9 R1).
- **Oracle:** lo ⊆ GPurify ⊆ hi, and lo = hi on X.

### 25. via_array_spacing — APPROX (bracket; EXACT on X)

**GPurify** (`via.rs` `via_array_spacing`)
- Clusters are components of "boundary distance ≤ limit" among cut rows.
- In each cluster with more than `array_threshold` cuts, every pair at distance < limit fails,
  including overlapping cuts (d = 0).

**KLayout**

```ruby
c   = SRC.polygons(lc, dc).raw
big = c.sized(H).merged.interacting(c, THR + 1)   # H = limit in original DBU (half of LIM); a diamond_limit copy gives the other bound
emit(id, c.interacting(big).isolated(LIM, euclidian, transparent))
```

Open question Q8: whether a raw `isolated` reports overlapping cuts.

### 26. multi_patterning — NONE: KLayout has no colouring

**GPurify** (`patterning.rs` `multi_patterning`)
- Nodes are rows merged at distance 0 (MAX). Two figures conflict when they are closer than the
  spacing.
- Colouring: two colours are a bipartiteness test; three or more use DSATUR with backtracking under
  a budget, and running out of budget is `Refused`.
- When colouring is impossible, one violation is reported at a canonical node.

**Hybrid oracle.** KLayout supplies the conflict graph; the harness supplies the colouring.

```ruby
emit(id + "#conflicts", SRC.polygons(l, d).isolated(SPACING2, euclidian, transparent))
```

- Nodes are the `fig:max` figures and edges are these pairs.
- k = 2: BFS. k ≥ 3: brute-force kⁿ on components of ≤ 20 nodes.
- Compare colourability with GPurify: `Ran` + 0 violations means colourable; 1 violation means
  not, and the node it names must lie in an uncolourable component; `Refused` is skipped.

### 27. forbidden — EXACT

**GPurify** (`presence.rs` `forbidden`): every validated polygon (drawn rows, a keyhole as an outer
plus holes) with its area, and every edge of an edge layer with its length.

**KLayout**

```ruby
emit(id, SRC.polygons(l, d).raw)   # drawn layer
emit(id, DERIVED)                  # derived layer: merged figures
emit(id, E)                        # edge layer
```

Compare the multiset of (bbox, area) for polygons, and the edge set for edges.

### 28. must_contain — EXACT

**GPurify** (`presence.rs` `must_contain`)
- Merges inner and outer figures (MIN). An inner figure is held by the outer figure that covers all
  of its area: touching the boundary from inside is fine, straddling it is not.
- Each outer figure that holds fewer than min_count fails.

**KLayout**

```ruby
emit(id, mc(O).not_covering(mc(I), MIN_COUNT))
```

(v t9 C1–C3.)

### 29. must_be_inside — EXACT

**GPurify:** a merged inner figure (MIN) that is not wholly covered by one merged outer figure.

**KLayout**

```ruby
emit(id, mc(I).not_inside(mc(O)))
```

(v t9 C4, T11.)

### 30. net_spacing — EXACT if the connectivity can be mirrored, otherwise NONE

**GPurify:** as `min_spacing` (rule 6), restricted to pairs whose rows are on the same net, or on
different nets. The rule is `Refused` when any row has no net.

**KLayout**

```ruby
# connectivity block from (c) first
n = L.nets                                                      # net identity as property 0 ([L] "nets")
emit(id, n.isolated(LIM, euclidian, transparent, props_eq))     # nets: same
emit(id, n.isolated(LIM, euclidian, transparent, props_ne))     # nets: different
```

- `props_eq` and `props_ne` work on `isolated` and `space` in 0.30.8 (v t5 T19). They are not
  available on `width` or `notch` ([L] "width", "Properties constraints").
- Use `isolated`, not `space`: `space` adds notches inside one polygon, while GPurify skips pairs
  from the same component.
- The mirroring conditions are in (c).

### 31. spacing_table — APPROX (EXACT on R)

**GPurify** (`spacing.rs` `spacing_table`)
- The column is the last `prl` strictly exceeded by the bbox run.
- The pair fails if some row r ≥ 1 has d_r < S[r][col], where d_r is measured from the parts wider
  than `width[r]`, clipped to their row. Otherwise it fails if d_0 < S[0][col].
- Cells never fall along a row (`SpacingTable::is_valid`). So this equals "there is an (r, c ≤ col)
  with d_r < S[r][c]", which is a union of independent checks.

**KLayout**

```ruby
m = SRC.polygons(l, d)
SPACE.each_with_index do |row, r|
  src = r == 0 ? m : m.sized(-WIDTH[r]).sized(WIDTH[r])     # WIDTH[r] = width[r] in original DBU: keeps parts wider than width[r]
  row.each_with_index do |s, c|                              # s = 2·space[r][c]
    lim = c == 0 ? [] : [projection_limits(2 * PRL[c] + 1, nil)]   # run > prl[c]
    emit(id, r == 0 ? m.isolated(s, euclidian, transparent, *lim)
                    : src.separation(m, s, euclidian, transparent, *lim))
  end
end
```

- For r ≥ 1, apply the same-figure filter as in rule 11.
- On R, the run is the projection of the facing edges, so the two definitions agree.
- Off R, GPurify's run is the bbox overlap; the check is one-sided there (KLayout ⊆ GPurify).

### 32. attached_wide_spacing — APPROX

**GPurify** (`wide_parts`): the wide parts, grown by `attached` with square corners, then clipped
to the figure's *own* rows. That includes parts of the own figure that are not connected to the
wide part inside the grown box.

**KLayout**

```ruby
att = (wide.sized(A2) & m).interacting(wide)    # A2 = 2·attached
emit(id, att.separation(m, LIM, euclidian, transparent))
```

- `& m` alone would also keep neighbouring figures that lie within `attached`.
- `.interacting(wide)` removes those, but also drops parts of the own figure that are reached only
  across a notch.
- So generators avoid notches within `attached` of a wide part, and the same-figure filter applies.

### 33. edge_min_length — EXACT

**GPurify** (`edge.rs` `min_length`): every edge of the edge layer (merged runs) shorter than the
limit. `at` is the midpoint.

**KLayout**

```ruby
emit(id, E.with_length(nil, LIM))
```

### 34. edge_spacing — APPROX (collinear pairs differ)

**GPurify** (`edge.rs` `spacing`)
- Measures every pair of parallel edges in any orientation, collinear end-to-end gaps included.
- A pair fails when 0 < Euclidean distance < limit.
- `at` is the gap midpoint; no shape is named.

**KLayout**

```ruby
one = [E.space(LIM, euclidian), E.width(LIM, euclidian), E.enclosing(E, LIM, euclidian, without_touching_edges)]
two = [E.separation(F, LIM, euclidian), E.overlap(F, LIM, euclidian),
       E.enclosing(F, LIM, euclidian, without_touching_edges), E.enclosed(F, LIM, euclidian, without_touching_edges)]
```

KLayout checks on edge layers depend on orientation, so the recipe takes the union of every
relation (v t16):

| Relation of the two edges | KLayout check |
|---|---|
| Outer sides face each other | `space` / `separation` |
| Inner sides face each other | `width` / `overlap` |
| Same orientation | `enclosing` / `enclosed`; coincident edges report 0 unless `without_touching_edges` |

- No KLayout relation sees collinear end-to-end gaps (v Q11–Q13). The harness drops collinear
  GPurify pairs, or adds a Ruby check over `E.data`.
- The single-layer `E.enclosing(E)` form and `whole_edges` on edge layers are not verified (Q5,
  Q10).

### 35. edge_enclosure — EXACT

**GPurify** (`edge.rs` `enclosure`, `covered_depth`)
- For each non-zero edge, a strip `limit` deep on the side away from its shape.
- The edge fails when the outer layer (merged) leaves an uncovered slice nearer than `limit`.
- `at` is the edge midpoint.

**KLayout**

```ruby
strips = E.extended_out(LIM)                     # one strip per edge, on its outer side
emit(id, strips.raw.not_inside(mc(O)))           # a strip not fully covered means its edge fails
```

- (v t16 Q4/Q5.) The harness maps each strip back to its base edge: the strip side that is
  collinear with an E edge.

---

## (c) Derived layers, connectivity, antenna

### Derived-layer operations

Each operation runs on merged operands. Every polygon result is wrapped in `mc()` (see a3).

| Deck | GPurify (`geom/src/derive.rs`, `ingest/src/layout.rs`) | KLayout | Difference to pin |
|---|---|---|---|
| `A and B`, `or`, `not` | Exact booleans of the validated operands; the result is merged at MIN | `A & B`, `A \| B`, `A - B` ([L] "and"/"or"/"not") | Only the corner-touch coherence |
| `.sized(len)` | Minkowski sum with a square; erosion is the complement of growing the complement (`sized_into`) | `.sized(len)` (default `square_limit`, [L] "sized") | Identical on rectilinear shapes (v T10: square corners, parts no wider than 2\|d\| vanish) |
| `.interacting(L)` / `.not_interacting(L)` | Touch or overlap; a shared corner counts (`polys_meet`) | `.interacting(L)` / `.not_interacting(L)` | Same (v T11: corner and abutment count) |
| `.inside(L)` | No part of the shape lies outside L; touching the boundary from inside is fine | `.inside(L)` | Same (v T11) |
| `.outside(L)` | No shared area; touching only is outside | `.outside(L)` | Same (v T11) |
| `.holes()` | Each hole filled, island included, merged | `.holes` | Same (v T12) |
| `.extents()` | The bbox of each figure, merged at once | `.extents` | KLayout merges at the next use; same under clean semantics |
| `.with_area(b)` | Area without holes, inclusive bounds | `.with_area(min, max)` on [min, max), bounds mapped per (a5) | (v T12, T15) |
| `.with_width(b)` | `narrowest_width` = facing edges by projection only (`geom/width.rs`) | `L.drc(if_all(!(width(projection) < LO), width(projection) < HI))`, with LO and HI mapped per (a5) | (v t13 W1). deck.md says "as width measures it", but `width` also counts Euclidean necks (N2) |
| `.with_text(T, "p")` | A text point on the material or its edge (`on_material`); glob `*` and `?` only; case-sensitive | `.interacting(SRC.labels(T).texts(pattern("p")))`, or `texts(text("p"))` when there is no wildcard | Text on an edge and on a corner count (v T14, T18). KLayout globs also have `[…]`, `{a,b}` and `\` escapes, so those characters must be escaped (Q3) |
| `.without_text(…)` | | `.not_interacting(…)` | |
| `.edges()` | Merged boundary, kept as directed runs, material on the left (CCW) | `.edges` | KLayout edges are clockwise (material on the right): same side, opposite direction. Compare edges undirected. |
| `E and F`, `not`, `or` | Coincidence ignores direction; each piece keeps its own direction | `E & F`, `E - F`, `E \| F` | Same (v T13) |
| `.inside_part(L)` | Strictly inside; parts on L's boundary are in neither result | `.inside_part(L)` | Same (v t13 B1) |
| `.outside_part(L)` | Strictly outside | `E.outside_part(L) - L.edges` | KLayout keeps parts on L's boundary ([L] "does not remove edges that are exactly on the boundaries"; (v t13 B2)), so they must be subtracted |
| `.interacting(L)` on edges | Whole edges that touch, cross or lie inside | `.interacting(L)` | Same (v T13) |
| `.with_length(b)` | Length within the bounds | `.with_length(min, max)` on [min, max), bounds mapped per (a5) | |

### Connectivity, for net_spacing

| Deck | KLayout | Notes |
|---|---|---|
| `connect conductors [c…]` with `connect touch_within_layer` | `connect(c, c)` for each conductor ([N] "connect") | (v t9 N1: touching shapes on one layer join a net.) |
| `connect conductors` without `touch_within_layer` | Cannot be mirrored | KLayout always joins touching shapes on a connected layer ([N]: "This also implies intra-layer connections"). Such decks are **NONE**. |
| `connect via V [a, b]` | `connect(a, V); connect(V, b)` | GPurify: the cut is not a net member, and it joins a to b only if that one cut lands on both. A cut that only touches a shape counts (`polys_intersect`), and so does a corner touch in KLayout (v t6 T20b). KLayout: the cut belongs to the net, so two touching cuts, one landing only on a and one only on b, join a and b, which GPurify does not. Generators must avoid that, or the harness flags it. |
| `connect global G` | `connect_global(G, "G")` ([N] "connect_global") | |
| `connect label T names C` | `connect(C, SRC.labels(lt, dt))` | Labels only name nets. GPurify's `extract_nets_into` never joins nets by label, and KLayout does not either without `connect_implicit`. |
| Net identity | `L.nets` → property 0, then `props_eq` / `props_ne` | (v t5 T19) |

### Antenna

`antenna` is an ERC kind, not one of the 35, but `antenna_check` mirrors it.

**GPurify** (`erc/rules/antenna.rs`)
- For each rule row, the nets are those standing at that etch step: conductors up to the highest
  collector, and the vias between conductors that already stand (`Stack::stage`).
- The ratio is Σ collector area (or perimeter × sidewall) over Σ gate area, per gate net; the net
  fails when it is > `max_ratio`.
- A gate or cut joins the topmost conductor it overlaps with positive area.
- Collector areas are summed per drawn polygon (F29).

**KLayout**
- For each row, call `clear_connections`, connect the stage's layers, then `connect(gate, poly)`.
- One collector:
  - area: `antenna_check(gate, coll, max_ratio)`;
  - sidewall: `antenna_check(gate, perimeter_only(coll, t_um), max_ratio)` ([N] "antenna_check").
- Several collectors (cumulative ratio):
  `evaluate_nets(gate, {"C1"=>c1, "C2"=>c2}, "var r=(area(C1)+area(C2))/area; skip(r<=thr)", {"thr"=>max})`
  ([N] "evaluate_nets").
- `antenna_electrical`: KLayout's diode spec `[diode, f]` raises the threshold by f × diode area
  in µm². That equals GPurify's `ratio − credit·A − bonus ≤ max` with threshold `max + bonus` and
  f = credit. GPurify refuses rows where the credit term decides the verdict, so compare only rows
  that ran.

**Verdict: APPROX.**
- KLayout merges areas per net (F29).
- A gate joins poly by touching in KLayout, but only by positive overlap in GPurify.

---

## (d) NONE and APPROX kinds, and their oracles

**NONE**
- **multi_patterning.** The conflict graph comes from KLayout and brute-force colouring from the
  harness (rule 26). The skip list in testing-plan L6 stays, with this hybrid replacing it.
- **net_spacing on decks whose connectivity cannot be mirrored** (no `touch_within_layer`, or
  touching cuts that land on different layers). The oracle is construct-from-answer tests with
  planted nets.

**APPROX**, with the tolerance or alternative oracle:

| Kind | How to compare |
|---|---|
| eol_spacing | EXACT on R. Drop GPurify pairs that touch the zone only at a span end. Off R, the oracle is the bitmap DRC (C5) plus finding N5. |
| prl_spacing, spacing_table | EXACT on R. Off R, one-sided: KLayout ⊆ GPurify, because a bbox run over-reports. |
| corner_to_corner | EXACT on R after dropping pairs whose bboxes touch on an axis. Off R, no ordering. |
| attached_wide_spacing | EXACT on layouts without notches within `attached` of a wide part. |
| asymmetric_enclosure | Compare rectangular inner rows only. |
| min_extension, overlap | EXACT on R with positive-area overlaps and disjoint intersections. Otherwise the bitmap oracle (C5). |
| max_distance_to_tap, redundant_via, via_array_spacing | Bracket: square ⊆ GPurify ⊆ diamond (the tap kind with its tap-interior allowance). EXACT on X for the via kinds. |
| edge_spacing | Collinear pairs excluded, or a Ruby check added for them. |
| density, global_density | Drop windows and dies within 1e-9 of the limit, and pad 1×1 sweeps. |
| antenna (ERC) | Compare non-refused rows. F29 differences are expected until F29 is fixed. |

---

## (e) Open questions, and what this turned up in GPurify

### Not resolved

1. **Euclidean width and convex-ended pairs (Q1).** A pair of opposite, parallel edges with no
   overlapping projection and a convex endpoint could be reported by KLayout's Euclidean width
   across a void. `shielded` should hide it; this is unverified. If L3 layouts show extra KLayout
   pairs, filter to pairs whose endpoints are concave.
2. **`tile_count(1, 1)` (Q2).** It returns nothing in 0.30.8. This could be a KLayout bug or a
   misuse; the 2×1 workaround is in place.
3. **Glob escapes (Q3).** KLayout's syntax for escaping `*`, `?`, `[`, `{` and `\` in `texts(pattern(...))`
   is not verified.
4. **Edge merging (Q4).** How KLayout merges collinear edges of opposite direction that touch
   (this arises only from figures touching at a corner) is not verified.
5. **`whole_edges` on edge layers (Q5)**, needed for the edge-pair key in rule 34, is not verified.
6. **`foreign` (Q6).** The universal `drc()` with `foreign` might replace the harness's
   same-figure filter for rules 11, 31 and 32; not explored.
7. **Keyholes (Q7).** The GDS reader keeps the keyhole slit in raw polygons; the vertex sets under
   `off_grid` are believed equal but not verified.
8. **Overlapping cuts (Q8).** Whether a raw `isolated` reports overlapping cuts (d = 0) matters for
   rule 25; GPurify reports them.
9. **`EdgePair#distance` (Q9).** Its rounding for non-integer Euclidean distances (the header saw
   only integers) is unknown, so keep the ±1 DBU tolerance.
10. **`E.enclosing(E, …)` (Q10)** on a single edge layer: validity and self-pairs are not verified.
    The two-layer forms are (v t16).

### Found in GPurify

These are not in testing-plan F1–F35. F18, F19, F29 and F34 were confirmed independently.

**N1. A gap in a chain joined at corners is reported by neither rule.**
- Booleans use MIN coherence (`boolean.rs` `successors_into`), but spacing components use MAX
  (`spacing.rs` `prepare`).
- Take squares R1 = (0,0)–(10,10), R2 = (10,10)–(20,20), R3 = (20,0)–(30,10). The 10-wide gap
  between R1 and R3 is:
  - not a notch, because the three squares are separate figures;
  - not a space, because they form one component.
- It is never reported, at any limit. That is a false clean (B1).
- KLayout's default (MAX) `notch` and `space` flag it (v T5).
- Fix: one coherence for both. MAX matches KLayout and foundry decks.

**N2. `with_width` is projection-only.**
- It uses `narrowest_width` → `narrowest_facing`. `docs/deck.md` says "narrowest width, as `width`
  measures it", but `width` also counts Euclidean necks (`narrowest_neck`).
- Two overlapping squares offset by 70 have a neck of 42 that `width` sees, but their `with_width`
  is 100.

**N3. The density die grows with derived layers.**
- With no boundary layer, the die is the union of every store layer's bbox, derived layers
  included (`area.rs` `die_of`).
- So `layer x = met1.sized(1um)` enlarges the die and adds empty windows. deck.md says "the whole
  layout".

**N4. `min_extension` judges pairs that only touch.**
- The prune at distance 0 keeps boxes that only touch, yet `overlay.rs` says "The prune at distance
  zero is exactly the overlapping pairs".
- A line abutting the side of its reference is measured by its far protrusion, which can be a false
  violation. F19 covers this for `overlap` only.

**N5. `eol_spacing` reads ends of line from drawn rows.** An edge that two abutting rows share is an
end of line whose keep-out runs through its own figure. This is the same pattern as F18.

**N6. The `drc_oracle.rb` families to retire:**
- `max_width` as `with_bbox_min(5001)` — the engine now uses wide regions;
- `min_area` without MIN coherence;
- `min_spacing` shielded (it needs `transparent`);
- `min_width` flagging corner-touching shapes.

**N7. `corner_to_corner` can miss an L-shaped row** whose bbox overlaps its neighbour on one axis
but whose real corner is diagonal to it. Corner limits are usually larger than space limits, so
this can be a false clean.
