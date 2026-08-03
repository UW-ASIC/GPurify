# Rules without a definitive test

A **definitive test** is one backed by an oracle from `docs/TESTING.md` — a
closed form, a law, or a generator that built the answer it expects.

Some rules have none. They ship anyway, and they are listed here.

That is a deliberate choice over the two alternatives. Deleting them loses real
checks a foundry asks for. Marking them `experimental` in a manifest hides them
behind a flag nobody reads, which is the false-clean failure mode wearing a
different hat. A ledger is the honest option: the rule runs, and anyone
depending on it can see exactly what is and is not established about it.

**A rule stays here until it has an oracle, or until someone argues it needs
none.** Moving one off this list requires naming the oracle.

---

## Format

Each entry states what the rule checks, why no oracle applies yet, and what
*is* verified about it — usually construct-from-answer on the simple cases,
with the hard cases unverified.

```
### <rule id> — <crate>

**Checks.** What it looks for.
**Missing.** Why no closed form or law applies.
**Verified.** What testing does exist.
**Would need.** What an oracle for this would have to look like.
```

---

## Entries

*Populated during the Testing-Phase, as each rule is written and its oracle
either found or not. Empty here does not mean every rule is covered — it means
the Testing-Phase has not reached them yet.*

The rules expected to land here are the combinatorial ones, where correctness
is a matter of design-methodology convention rather than physics and there is
nothing to derive an answer from:

- `multi_patterning` — mask colouring; the constraint is a graph property, and
  whether a given colouring is *the* right one is a convention
- `cheesing` — metal slotting for planarity; the pattern is a foundry
  prescription, not a derivable optimum
- `redundant_via` — a reliability policy, not a physical limit
- `via_array_spacing` — likewise, where the limit is not derivable from the
  spacing rules already checked

Their construct-from-answer coverage is straightforward for simple layouts —
place a known violation, assert it is found — so what is missing is confidence
on the configurations where the convention itself is ambiguous.
