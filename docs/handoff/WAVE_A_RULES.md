# Wave A — internal simplification, one scope per agent

Repo: GPurify (Rust IC physical verification: DRC, ERC, LVS, PEX). Owner wants it
simplified hard: dead code, useless defensive handling, comment walls, duplicate paths.
Results must NOT change.

You work in your own git worktree (your cwd). Other agents work other scopes in parallel,
in other worktrees. Your changes get merged afterwards, so stay inside your scope's files.

## Scope rules
- Edit ONLY files in your scope (listed in your prompt) plus that scope's own tests.
- Do NOT change any pub item that code OUTSIDE your scope uses in non-test code
  (grep crates/*/src and src/). Such changes are Wave B; list them in your report instead.
- Pub items used only by tests (anywhere) or nothing: delete them, delete/adjust the tests
  that only exercised them. If a root `tests/` file or `crates/testgen` uses it, keep it and
  list it for Wave B.
- No new dependencies. No fearless_simd yet (Wave C).

## What to cut
- Dead code (see your audit report — it has file:line lists; re-verify with grep).
- `debug_assert!`s that restate the line above, a push just made, or an invariant the
  constructor guarantees. Default: delete. Keep release `assert!`/`expect` that stop
  silently-wrong output.
- Comment walls. Doc comments: one or two lines stating a fact the signature cannot
  (units, ordering contract, what a refusal means). Keep numeric accuracy caveats
  (e.g. measured error bounds) in one short line. Module `//!` header: 2-6 lines,
  including `Data in:` / `Data out:` for the module's main transform.
  Delete history narration ("used to", "the old tree", "Phase 4", finding numbers).
- Hand-written `unsafe` filter loops → `retain` / `filter().collect()` (same order).
- Duplicate implementations of one thing inside your scope → one.
- Abstractions with one user, observer/hook traits existing only for tests,
  "shrink()"/capacity-tuning APIs nobody calls, options only ever at default.
- Rewrite straight-line where the code is convoluted, but keep the arithmetic, iteration
  order, tie-breaks, float summation order, and interning order EXACTLY (they drive output
  bytes). If unsure whether something affects output, keep its semantics.

## Gates (both must pass before you commit)
1. `cargo test --workspace --no-default-features 2>&1 | grep -E '^test result|FAILED|panicked|^error' `
   → all ok. (Use `--release` if debug is too slow.) Also `cargo build --workspace --all-targets`
   must be warning-free for your scope (`cargo clippy` optional).
2. Golden corpus: `/tmp/claude-1000/-home-omare-Documents-Projects-Rust-GPurify/35498cb0-197f-47ef-9353-f5a68560d8eb/scratchpad/gate.sh $(pwd)`
   → must print `GATE PASS`. Takes ~5 min. Run it at the end (and midway if you make risky changes).

## Finish
- `git add -A && git commit` in your worktree with a message `<scope>: <what>` and the trailer
  line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Several commits fine.
- Final message (≤25 lines): worktree path + branch name, src/test line counts before→after
  (`find <dirs> -name '*.rs' | xargs cat | wc -l`), what was cut, and a "WAVE B" list of
  cross-scope changes you recommend but did not make (item, file:line, why).
