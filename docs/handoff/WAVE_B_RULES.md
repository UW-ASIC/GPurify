# Wave B — cross-crate API simplification (sequential, in the main checkout)

Repo: /home/omare/Documents/Projects/Rust/GPurify, branch `simplify` (already checked out; commit on it).
Wave A already cut ~32k lines inside each crate. Now the seams between crates.
Same style rules as /tmp/claude-1000/-home-omare-Documents-Projects-Rust-GPurify/35498cb0-197f-47ef-9353-f5a68560d8eb/scratchpad/WAVE_A_RULES.md
(short doc comments, no debug_assert noise, no history narration, keep arithmetic/order/interning exact),
but you may now change ANY file in the workspace (src, crates, tests, testgen). Not docs/README (Wave D).

## Target shape (api-design: caller owns I/O, data in → data out, plain functions, no retained state,
## coarse call = 2-4 granular calls, no test-only seams in src)

- ingest: parsers take `&str`/`&[u8]` + `&mut StrTable`; the caller reads files.
  `deck::parse_deck(&str, Grid, &mut StrTable) -> Deck`, `gds::Library::parse(&[u8], &mut StrTable)`,
  `Library::flatten(&Deck, ..) -> (GeometryStore, labels)`, netlist `spice::read`/`spectre::read`, `intent::parse_intent`.
- check::topology: `extract_nets(store, &Connectivity) -> NetTable`, `recognise(store, &NetTable, &Devices) -> DeviceTable`,
  `bind_ports(..) -> PortTable` (return by value unless a reused buffer is actually exploited in production).
- check::drc: `RuleSet::run(&GeometryStore) -> (Violations, Vec<RuleRun>)` (or appends into caller vecs); no Design/Scratch in the public API.
- check::erc: one `erc::check(..)` entry taking the tables it reads; everything else pub(crate).
- check::lvs: `Graph::from_layout`, `Graph::from_reference`, one `compare(&Graph, &Graph, &CompareOptions) -> Verdict`
  doing drop-bulk + reduce + refine + interpret inside; `check_layout(.., ids)` taking the interned rule ids.
- extract: `analytical::extract(..) -> ParasiticNetwork`, quasistatic solve entry, network merge helper living in extract.
- root: `load(&Inputs) -> Loaded`, `extract(&Loaded) -> Extracted`, one fn per check, `run_checks`, `run`.
Only move toward this where it deletes code or removes a real coupling; do not add layers.

## Gates
1. `cargo build --workspace --all-targets` warning-free; `cargo test --workspace --release` all ok.
2. `/tmp/claude-1000/-home-omare-Documents-Projects-Rust-GPurify/35498cb0-197f-47ef-9353-f5a68560d8eb/scratchpad/gate.sh`
   → `GATE PASS` (byte-identical corpus output incl. field-solved + inductance SPEF). ~6 min.
   An intentional behaviour fix (listed in your prompt) may change output ONLY if the gate diff is exactly that fix;
   then say so explicitly in the commit message and your report.
3. `cargo fmt --all` before committing.
Commit per logical step, message `<area>: <what>`, trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
Final message ≤25 lines: commits, line counts before→after, anything left undone and why.
