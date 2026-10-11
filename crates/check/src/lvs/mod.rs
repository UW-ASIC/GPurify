//! Layout versus schematic: graph matching between an extracted and a
//! reference netlist.
//!
//! Every path that could not complete returns [`Verdict::Inconclusive`] with a
//! reason; there is no code path from "gave up" to "matched".
//!
//! # What is compared
//!
//! Both sides become a [`Graph`]: devices and nets are two sets of nodes, and
//! each device terminal is an edge labelled with its
//! [`TerminalRole`](crate::topology::TerminalRole). The layout comes from
//! [`graph::from_layout`], the reference from one subcircuit by
//! [`graph::from_reference`]. [`compare`] then:
//!
//! 1. drops every reference `Bulk` terminal when the layout has none (the
//!    deck's MOS recogniser lists three layers), and every layout parameter
//!    that no reference device of the same kind and model declares, so it
//!    cannot block a merge;
//! 2. reduces both sides by parallel and series merges ([`reduce`]);
//! 3. partitions the nodes of both sides together by iterative refinement, the
//!    graph-labelling algorithm of C. Ebeling, "`GeminiII`: a second generation
//!    layout validation program", ICCAD 1988,
//!    [doi:10.1109/ICCAD.1988.122520](https://doi.org/10.1109/ICCAD.1988.122520).
//!    Devices start in one class per `(kind, model)` and nets in one class.
//!    Each pass gives every node a signature from the `(role, class)` of each
//!    of its terminals, and a class splits wherever its members' signatures
//!    differ, until no class splits;
//! 4. breaks a symmetry, a class still holding the same number `k >= 2` of
//!    nodes on each side, by pairing its lowest layout node with the
//!    reference node of the class whose parameters are closest (the lowest on
//!    a tie, and always for nets), then refines again. This is how Netgen
//!    resolves symmetries by property value (catalog LVS-018). Refinement
//!    cannot always tell apart nodes no relabelling exchanges, so while a
//!    match is still possible the pairing is a trial: kept when no class is
//!    left with more reference nodes than layout nodes and every device pair
//!    it forms agrees on parameters, otherwise taken back and the next closest
//!    tried, up to eight per stall (testing-plan F58);
//! 5. reads the final partition: a class with exactly one node per side pairs
//!    them, and every paired device must also agree on kind, model, terminals
//!    and parameters. Parameter presence is per device: each parameter the
//!    reference card states must be measured and agree, and a measure the
//!    card omits is not compared, whatever other cards of the model state
//!    (testing-plan F68). Everything else is a [`Discrepancy`].
//!
//! Roles decide which terminals are interchangeable. Positions never matter.
//!
//! | Role | Interchangeable with |
//! |---|---|
//! | MOS `Source`, `Drain` | each other: which end is the source is a matter of bias |
//! | A resistor's two ends | each other: a resistor has no direction |
//! | A diode's anode and cathode, a capacitor's plates | nothing: a reversed diode is another circuit, and Netgen does not permute capacitor plates either |
//! | `Gate`, `Bulk`, `Base`, `Emitter`, `Collector` | nothing |
//!
//! That is catalog LVS-030. User-declared equivalent pins, and devices whose
//! source and drain must not swap (LVS-031), are not supported.
//!
//! Net names do not take part: they neither seed refinement nor are compared,
//! so a misnamed or reordered port passes (catalog LVS-016, LVS-032).
//!
//! # Report
//!
//! [`check_layout`] adds checks on the layout's own graph, which need no
//! reference. [`record_discrepancies`] turns a [`Verdict::Mismatch`] into
//! error rows. Every id either can write is in [`RULE_IDS`]; the crate's
//! [rule reference](crate#layout-against-schematic) lists them with the
//! [check catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv)
//! rows each covers. The tools those rows cite are in
//! [check-sources.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md).
//!
//! # Limits
//!
//! Known defects, tracked as findings in the
//! [testing plan](https://github.com/UW-ASIC/GPurify/blob/main/docs/testing-plan.md):
//!
//! - **Flat comparison.** [`graph::from_reference`] reads only the subcircuit's
//!   own device cards, so the load step flattens a reference with a unique top
//!   first ([`Netlist::flatten_top`](gpurify_ingest::netlist::Netlist::flatten_top)):
//!   a block placed by instance is compared device by device, never cell by
//!   cell (catalog LVS-010, LVS-017).
//! - **F16, weak parameters.** The layout measures only MOS `w` and `l` and
//!   each device's marker `area`, so passives are not sized.
//! - **Bounded symmetry search.** A tie-break takes back only a pairing whose
//!   own refinement shows it wrong, and tries at most eight candidates; a
//!   wrong pairing exposed only after a later tie-break, or a right one past
//!   the eighth, is kept, and the verdict is then a false mismatch, never a
//!   false match.
//! - **Passive values are counted, not combined.** Parallel resistors,
//!   capacitors and diodes merge into one device of the same value with a
//!   count `m`, so two capacitors of `c` do not match one card of `2c`,
//!   which `KLayout`, adding the capacitance, would pass ([`reduce`]). The
//!   conservative side: a false mismatch, never a false match.

pub mod checks;
mod compare;
pub mod graph;
pub mod reduce;
mod refine;
pub mod verdict;

pub use checks::{
    check_layout, check_net_seed_conflicts, intern_rule_ids, record_discrepancies, RULE_IDS,
};
pub use compare::{compare, compare_logged, CompareOptions};
pub use graph::Graph;
pub use reduce::{Merge, MergeKind, ParamNames};
pub use verdict::{Discrepancy, Verdict};
