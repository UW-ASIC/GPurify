# Shared vocabulary

One word per concept, used exactly, by humans and agents alike. The words
double as skill triggers, so a synonym costs you the skill.

Structural terms come from the `codebase-design` skill and are **not**
re-invented here. Data terms come from `docs/CONVENTIONS.md`. This file is the
index; those are the long form.

---

## 1. Process

**Plan-Phase** — goals, coarse modules, seams, interfaces, test plan. Prose.

**Definition-Phase** — data movement frozen: structs, signatures, doc
comments. Bodies are `todo!()`. No tests.

**Testing-Phase** — the inherited test plan implemented against the frozen
signatures. Its green state is the completion criterion for the next phase.

**Implementation-Phase** — bodies only.

**Freeze** — the point at which a phase's artefact becomes read-only to later
phases. Unfreezing is allowed but is an event with a stated reason.

**Information barrier** — why the phases exist: a decision is made where it is
cheapest to change, and frozen before the phase that would otherwise make it
implicitly.

---

## 2. Structure — from `codebase-design`

**Module** — anything with an interface and an implementation. In Plan-Phase
this means a *coarse* module: above function and struct level, a cluster of
behaviour behind one interface. _Avoid_: component, service, unit.

**Interface** — everything a caller must know to use the module correctly:
signatures, invariants, ordering constraints, error modes, allocation
behaviour, complexity. _Avoid_: API (signature-only, too narrow).

**Implementation** — what is inside a module.

**Seam** — the place where a module's interface lives; where behaviour can be
altered without editing in that place. _Avoid_: boundary, layer.

**Adapter** — a concrete thing satisfying an interface at a seam. Names a
role, not a substance.

**Depth** — behaviour exercised per unit of interface learned. Design modules
deep. Shallow (interface nearly as large as the implementation) is the defect.

**Leverage** — what callers get from depth. **Locality** — what maintainers
get: change and verification concentrate in one place.

**Deletion test** — imagine the module gone. Complexity vanishes → it was a
pass-through. Complexity reappears across N callers → it earned its keep.

**Two-adapter rule** — one adapter is a hypothetical seam, two is a real one.
No seam without something that actually varies across it.

---

## 3. Data — from `CONVENTIONS.md`

The workspace is a pipeline turning layout geometry into verification
verdicts. Its nouns are tables, its verbs are transforms.

**Table** — parallel `Vec`s (SoA), one row per element. Not a collection of
objects. `GeometryStore` is the exemplar.

**Row** — one element of a table, addressed by index, never by pointer.

**Id** — a newtyped `u32` index into a named table (`PolyId`, `NetId`,
`LayerId`). Two id spaces must not be confusable. _Avoid_: handle, reference.

**Side table** — cold data keyed by the same index as a hot table. Where
strings, paths and per-run metadata live.

**Intern** — replace text with a `u32` at the boundary. Names are identity,
not data: compared and hashed as `u32`, resolved to text only when a human
reads a report.

**Transform** — a function from tables to tables, named by pattern in its doc
comment: *A-to-B*, *in-place*, *generative*, *dispatcher*, *tasker*,
*gatherer*, *sorted table* (CONVENTIONS §2).

**Decision vs transform** — a *decision* computes what to do: small data in,
value out, pure, table-testable. A *transform* applies it across bulk data:
in-place, caller-owned memory, all data flow visible in the signature.
Decide pure, apply in place.

**Kernel rule** — a transform must compile as a compute kernel: uniforms
hoisted, each output row a function of its own input, any row order legal,
each output row written once. The moment row N reads what row N−1 wrote it is
serial, and must be split into two passes.

**Uniform** — a value constant across a whole transform, hoisted above the
loop.

**Combinator** — the utility-library entry point every bulk loop goes through
(map-over-batch, reduce, filter-compact, transform-in-place). SIMD, alignment
and tail handling live inside it. Raw loops over bulk data exist only inside
that library.

**Data-dependent branch** — an `if` on a value inside a combinator body. It is
what stops vectorisation. Removed mechanically: `if p { out[n]=x; n+=1 }`
becomes `out[n]=x; n+=p`. A surviving one carries a comment naming why.

**Dbu** — database unit, `i64`, the only coordinate type. `MAX_ABS_DBU` bounds
it so `i128` products cannot overflow.

**Fail closed** — an unsupported or unrepresentable input is a typed error. An
empty clean result never means "we could not check this". Its opposite,
**fail open**, is the defect class this project fears: a saturating distance
sentinel that silently passes a spacing rule.

---

## 4. Verification

`crates/` is **not** an oracle. The new tree is self-tested against physics.

**Oracle** — anything that can state the correct answer independently of the
code under test. This project has exactly three, all self-contained:

  1. **Closed form** — an analytic solution: parallel-plate and coaxial
     capacitance, sheet resistance of a known rectangle, series/parallel
     networks.
  2. **Law** — a conservation or symmetry property that must hold for any
     input: Maxwell capacitance matrix symmetric, energy non-negative,
     effective resistance obeying the triangle inequality and Rayleigh
     monotonicity, boolean area conservation, `(a−b) ∪ (a∩b) == a`.
  3. **Construct-from-answer** — the generator builds an input whose correct
     output it already knows: a layout emitted from a netlist must extract
     back to that netlist; a violation placed deliberately must be found at
     that coordinate with that measurement.

**Definitive test** — a test backed by one of the three oracles. A rule with
no definitive test still ships, but is listed in `docs/NEED_TESTING.md` with
what is missing. The ledger is the point: an unverified rule is recorded, not
hidden behind a status flag and not deleted.

**Test adapter** — an adapter installed at a seam so a test can observe what
crossing that seam actually did (rows produced, pairs pruned, branch taken)
without the production build paying for it.

**Gate constant** — the compile-time constant that switches a test adapter
off. A test adapter is only acceptable if the gate is a `const` the compiler
folds away. *"It is cheap" is not the standard; "it is absent" is.*

**Null adapter** — the zero-sized default at a test-adapter seam. Production
builds use only this one.

**Optimised-out check** — the evidence that a null adapter cost nothing:
disassembly, binary-size comparison, or a codegen test. A test adapter without
this evidence is unproven and does not merge.

**Mutant / survivor** — `cargo mutants` rewrites a piece of logic; a survivor
is a mutation no test noticed, i.e. a missing test. An **equivalent mutant** is
provably unobservable and is excluded with a written argument at the site, not
counted as a survivor.

**Gate** — a condition a module must meet before it is called done. Distinct
from a test: tests can pass while a gate is unmet.

---

## 5. Rejected terms

- **Depth as a line-count ratio** — rewards padding. Depth is leverage.
- **"Boundary"** — say seam or interface.
- **"Mock"** — say adapter, and say which kind.
- **"Object", "node", "pointer graph"** — this workspace has tables and ids.
- **"Helper", "util", "manager"** — a module nameable only this way has no
  interface worth having.
- **"Golden"** — retired. It named a snapshot of `crates/` output, which is no
  longer authoritative.
