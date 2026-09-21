# GPurify

Physical verification for integrated circuits — DRC, LVS, ERC and PEX — written
in Rust, data-oriented, and built around one idea: **a clean result has to mean
something.**

The failure this exists to prevent is the false clean. An empty violation table
is also what a run that never executed produces, and a tool that cannot tell
those apart will eventually sign off a chip it did not check. Every rule here
records whether it ran and what it examined, and says why if it stopped. A run
that could not check everything it was asked to check does not pass, and the exit
code says so.

## Status

The implementation is complete — every function has a body, and the suite is
green (714 tests as of 2026-08-04, plus one `#[ignore]`d doctest).

It has **not** been run against production silicon data, and it should not be
used to sign off a tapeout. Specifically:

- The PDKs in `pdks/` are mid-migration to the current deck schema.
  `pdks/README.md` is the authority on what each one actually configures and
  which rules are unsourced gaps.
- Performance is *recorded, not gated*. `tests/bench_all.rs` prints a table; no
  duration fails a build.
- Some rules ship without a definitive test, because the right answer is a
  foundry convention rather than something derivable from physics. Those are
  named, with reasons, in `docs/NEED_TESTING.md`.
- `cargo-mutants` is the intended acceptance gate for the suite and has not been
  run at scale yet.

There is no licence file. Add one before publishing.

## Getting started

The dev shell is the supported environment — it pins the toolchain and supplies
`clippy`, `cargo-mutants` and the Vulkan libraries the PEX GPU path links
against:

```sh
nix develop
cargo build --release
cargo test --workspace
```

A plain stable toolchain builds and tests the CPU paths fine, but `cargo clippy`
will not exist outside the shell, and the workspace lints are part of the
definition of correct here.

## Usage

```
gpurify <check> --deck <deck.json> <layout.gds> [options]
```

| Subcommand | Purpose | Extra input |
|---|---|---|
| `drc` | Design rule check | — |
| `erc` | Electrical rule check | `--intent <file>` for the intent-gated rules |
| `lvs` | Layout versus schematic | reference netlist, required |
| `pex` | Parasitic extraction | `--quasistatic <net>…` selects field-solved nets |
| `all` | Everything | both optional; an absent input marks its check *skipped*, never *passed* |

Shared flags: `--format text|json|gds`, `--output <path>` (default stdout),
`--threads <n>`, `--check-determinism`, `--strict-layers`.

`--format gds` writes violation markers as a layout you can open in a viewer.
`--strict-layers` rejects geometry on layers the deck does not describe instead
of silently dropping it; it defaults on, because a signoff run wants it.

## Determinism is a guarantee, not an aspiration

`--threads` affects speed only. The same inputs must serialise to
**byte-identical output** at any thread count, and `--check-determinism` runs the
job twice and fails if they differ.

This is not a nicety. A signoff report that differs from itself between runs
cannot be diffed against yesterday's, so a reviewer cannot tell a fixed violation
from a vanished one. The gate exists because the previous implementation had
exactly this defect: 8 of 27 parasitic reports differed between runs of the same
binary on the same input. The numbers were right and the file was not
reproducible, which made it useless anyway.

## The deck

One JSON file describes the process. Exactly five sections, and an unknown key is
a hard error — a misspelled `"conectivity"` would otherwise be a deck with no
connectivity at all, which extracts every shape as its own net and reports a
clean LVS for a chip that is not connected.

```json
{
  "layers": { "met1": [68, 20] },
  "rules": {
    "met1_min_width": {
      "kind": "min_width",
      "layers": ["met1"],
      "params": { "limit": { "nm": 140 } }
    }
  },
  "connectivity": { "conductors": ["met1"], "intra_layer_touch": true, "vias": [] },
  "device_recognition": [
    { "kind": "mos", "marker": "poly", "model": "nfet", "terminals": ["diff", "poly"] }
  ],
  "pex": {
    "met1": { "thickness_nm": 360, "height_nm": 936, "sheet_res_ohm_sq": 0.125,
              "area_cap_af_um2": 25.6, "fringe_cap_af_um": 40.9, "dielectric_k": 4.1 }
  }
}
```

Three things catch people out, all deliberate:

- The JSON key is the **rule id**; the kind is a field. Two rules of one kind on
  different layers need distinct ids, and violations are reported by id.
- `layers` is always an **array**, even at length one.
- Parameter values are **tagged** — `{"nm": 140}`, never a bare `140`. The shapes
  a limit can take are a closed set, and a bare `45` cannot be told from a ratio
  of `45`.

The vocabulary is 24 DRC kinds and 19 ERC kinds, in `drc::ruleset::KINDS` and
`erc::ruleset::KINDS`. The two lists are disjoint, and a kind in neither is
refused by the engine rather than skipped.

An absent section leaves its table empty, which has consequences worth knowing: a
deck with no `pex` stack gives current-carrying layers no sheet resistance, and
ERC then refuses its whole stage rather than reporting rules it never ran.

## Architecture

```
geom ─→ ingest ─→ check ─→ extract ─→ gpurify
                                      └─ engine, export, bin/gpurify
```

| Crate | What lives there |
|---|---|
| `gpurify-geom` | `Dbu`, `Grid`, `Qty` — the newtypes that stop a coordinate being a bare integer — and the geometry over them: the store, exact predicates, exact rectilinear booleans, the spatial index, derived-layer expressions and the candidate-pair prefilter. |
| `gpurify-ingest` | Every reader — GDS, OASIS, SPICE/CDL, Spectre, deck, design intent. |
| `gpurify-check` | `topology`, nets, devices and ports recovered from geometry; `report`, violations, measurements and run records; `drc`, geometry rules, 24 kinds; `erc`, electrical rules including antenna and the power-grid solve, 19 kinds; `lvs`, graph matching and nothing else. |
| `gpurify-extract` | Parasitic extraction, with the field solver under `field`. The only place a GPU appears. |
| `gpurify` | `engine`, orchestration: load, extract, check, summarise; `export`, every writer — GDS, SPICE, SPEF, DSPF, JSON; and the `gpurify` binary, argument parsing and rendering. |
| `gpurify-testgen` | Fixture generation. Test infrastructure, not the system under test. |

Every reader lives in `ingest` and every writer in `export`, so determinism is
enforced in one place instead of argued about in eleven.

These are separate crates because the compiler then *enforces* that graph:
nothing in `geom` can import `check`. Inside a crate the modules are peers and
the compiler says nothing, so a merge is only made where the parts are one
shape — `drc`, `erc` and `lvs` are one transform over the same borrowed tables,
appending to the same violation columns. A consumer who wants the whole tool
depends on `gpurify` and gets `gpurify::check`, `gpurify::geom` and the rest as
re-exports.

## Conventions worth knowing before reading the code

- **Coordinates are `Dbu`, an `i64` newtype — never `i32`.** `MAX_ABS_DBU = 1 << 40`
  bounds them so `i128` area products cannot overflow.
- **Fail closed.** An unsupported or unrepresentable input is a typed error. A
  saturating distance sentinel is *fail-open* for a spacing rule, and that is a
  bug rather than an optimisation.
- **The caller owns the memory.** Transforms write into caller-supplied buffers,
  so a loop over rules allocates nothing per rule and behaviour is a
  deterministic function of what appears in the signature.
- **Bulk loops carry their discipline at the call site.** No data-dependent `if`
  in the body without a comment saying why it survives — the branch predicts
  well, the taken side is expensive enough to skip, or the array is large enough
  that speculation was doing the prefetching.
- **`debug_assert` liberally**: preconditions on entry, and the expected shape of
  intermediate and final results.

`docs/VOCABULARY.md` defines these terms. Read it before writing code; the words
are load-bearing and double as skill triggers.

## Testing

Tests are written **against signatures, before implementations exist**. That
ordering is the point: a test written after the code, by the same author, proves
only self-consistency. Most of this suite was authored while every function body
was still `todo!()`, so it could not have been shaped to fit an implementation.

The oracle is **construct-from-answer**. A fixture places a deliberate violation
at a coordinate the test chose, with a measurement the test computed by hand, and
asserts *that* rule on *that* layer at *that* point — never "one violation was
found", because a rule flagging the wrong shape passes a count.

### The fixture corpus

`tests/fixtures/` holds 160 real GDSII cells drawn for a real PDK, each with a
deliberate defect: 94 DRC, 23 ERC, 16 LVS, 27 PEX. `tests/corpus/` drives every
one through the ordinary pipeline. Geometry cannot be wrong about itself, so the
cells are data and are reused freely.

The expectations are not. Two files sit beside the cells and are deliberately
kept apart:

- **`manifest.json`** — the deleted implementation's own answers. A historical
  record. Nothing in the suite reads it.
- **`expectations.json`** — every case re-derived from the geometry and from the
  rule's frozen doc comment, then *compared* with the manifest, with the
  comparison recorded in a field rather than folded into the value. Where the two
  disagree the derived value stands and a `dispute` field names which side is
  wrong and why.

Each case asserts the count, **that the rule ran and examined a non-empty
jurisdiction**, and for a positive case the measurement and the report
coordinate. The middle one is why the corpus was revived: an empty violation
table is also what a rule that never executed produces, and 45 of the old 94 DRC
cases passed on exactly that ambiguity. `report::RuleRun` tells the two apart.
Five cases nobody could derive are marked `underivable` and assert only what does
follow — dropping the hard ones would be the same failure as trusting them.
`tests/fixtures/README.md` is the full account.

122 of the 160 pass today. The 38 that do not are implementation defects with
names, not expectations waiting to be relaxed; `docs/TESTING.md` lists them.

```sh
cargo test --workspace                    # everything
cargo test -p gpurify --test test_all     # end to end, and the 160-case corpus
cargo test --release --test bench_all     # the timing record — needs --release
cargo mutants                             # the acceptance gate (slow)
```

`bench_all` sweeps three sizes rather than one, because a single size cannot
distinguish an algorithm that got slower from one that is quadratic. It is a
test target, so without `--release` you are timing a debug build and the numbers
mean nothing.

## Documentation

| File | Contents |
|---|---|
| `docs/VOCABULARY.md` | Shared terms, used exactly. |
| `docs/CONVENTIONS.md` | The code rubric. |
| `docs/TESTING.md` | Oracles, test adapters, the three gates. |
| `docs/NEED_TESTING.md` | What ships without a definitive test, and why. |
| `docs/CORRECTNESS_MAP.md` | Where correctness is established, and where it is not. |
| `docs/GPU.md` | Why GPU survives only in quasi-static PEX. |
| `pdks/README.md` | Per-PDK source, coverage and gaps. |
| `tests/fixtures/README.md` | The 160-case corpus: where it came from, how each expectation was derived, and every case that disputes the old tree's answer. |

## GPU

There is one GPU path, behind `extract`'s quasi-static `MatVec` seam, built
ahead of time to SPIR-V from GLSL with no JIT. Everything else is CPU and
deliberately so: the rest of this workload is branchy pointer-chasing over
irregular geometry, which is not what a GPU is good at. `docs/GPU.md` makes the
argument in full. A machine with no Vulkan device takes the CPU path and says
which it took.
