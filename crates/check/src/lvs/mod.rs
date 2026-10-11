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
//! 2. reduces both sides by parallel and series merges ([`reduce`]), then
//!    states `m = 1` on every device that states no count;
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
//!    reference node of the class whose parameters are closest, for a net
//!    the one whose pairing puts the diffusions of the transistors already
//!    paired closest at each channel end (testing-plan F98); on a tie the
//!    net named as the layout net's label, then the lowest; then refines
//!    again. This is how Netgen resolves symmetries by property value
//!    (catalog LVS-018). Refinement
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
//!    (testing-plan F68). The count `m` is no measure: a card without one
//!    counts one device, and is compared so. Counts, `m` and `nf`, are
//!    whole numbers and compared exactly, every other parameter within
//!    [`CompareOptions::param_tolerance`] (testing-plan F99), unless the
//!    deck's `lvs tolerance` says otherwise. Everything else is a
//!    [`Discrepancy`];
//! 6. when that leaves a device unpaired on each side, refines again with
//!    every device of one kind in one class, models aside: if that pairs
//!    every node and only models differ, the report is those pairs, each a
//!    [`Discrepancy::ModelMismatch`] (catalog LVS-013, `KLayout`'s devices
//!    "identified but [with] different device classes"); otherwise the
//!    first report stands. The verdict is a mismatch either way.
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
//! That is catalog LVS-030; the deck's `lvs asymmetric` and `lvs permute`
//! change it per model (below).
//!
//! Net names break ties and nothing more (catalog LVS-032): where refinement
//! leaves nets interchangeable, a layout net pairs first with the reference
//! net its label names, as `KLayout`'s `consider_net_names` (on by default)
//! resolves ambiguities, so a transistor whose two diffusions differ on
//! otherwise symmetric nets is compared the way its labels say. Names are
//! not compared, so a misnamed or reordered port passes (catalog LVS-016),
//! unless the deck asks for ports by name (below).
//!
//! # Deck controls
//!
//! The deck's `lvs` statements ([`LvsControls`](gpurify_ingest::deck::LvsControls),
//! [deck.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md#lvs-controls))
//! change the comparison per device model; [`compare_with`] applies them:
//!
//! - `lvs tolerance "model" param relative r absolute a`: the bound a paired
//!   parameter must meet, `|a - b| <= absolute + relative * max(|a|, |b|)`,
//!   in place of the run's relative tolerance (catalog LVS-014; `KLayout`'s
//!   `tolerance`, whose two parts add the same way, and Netgen's `property
//!   ... tolerance`, a relative one).
//! - `lvs ignore_parameter "model" param`: the parameter is dropped on both
//!   sides before reduction, never compared nor read by a merge (catalog
//!   LVS-014; `KLayout`'s `ignore_parameter`, Netgen's `property ...
//!   remove`).
//! - `lvs asymmetric "model"`: the transistor's source and drain are not
//!   interchangeable (catalog LVS-031; `KLayout`'s DMOS device classes, and
//!   a Netgen setup with no `permute` of the model's source and drain);
//!   such transistors merge in parallel source on source, never in series.
//! - `lvs permute "model" pin pin`: the two pins are interchangeable, joined
//!   with the model's default classes (catalog LVS-030; Netgen's `permute`,
//!   `KLayout`'s `equivalent_pins`); a class other than a transistor's
//!   channel is no channel, so it merges in parallel either way round and
//!   never in series.
//! - `lvs ignore "model"`: the model's devices are dropped from both sides
//!   before reduction (catalog LVS-034; Netgen's `ignore class`, `KLayout`'s
//!   `same_device_classes` with `nil`), and a net only they reached is no
//!   node unless it is a port.
//! - `lvs ports_by_name`: each reference port pairs only with the layout
//!   net its name labels (catalog LVS-016, LVS-001; `KLayout`'s
//!   `flag_missing_ports`), seeded as a class of its own.
//! - `lvs range "model" param >= min <= max`: every layout device of the
//!   model is held to the bounds on a measured parameter, a layout check of
//!   its own ([`check_param_ranges`], catalog LVS-068).
//! - `lvs topology relaxed`: a passive or bipolar stating its value merges
//!   in parallel by the value's law, `r` harmonically and `c`, `area`, `ae`
//!   by adding (catalog LVS-043, LVS-044, LVS-049; Netgen's `property
//!   topology relaxed`); strict, the default, keeps a count.
//! - `lvs ignore_shorted "model"`: the same for each device of the model
//!   whose every terminal is on one net, a dummy (catalog LVS-035; Netgen's
//!   `ignore shorted`).
//!
//! # Against Netgen
//!
//! The Netgen differential (`tests/exhaustive/lvs/netgen.rs`, testing-plan
//! F3) states these rules in a Netgen setup and holds every verdict of the
//! LVS enumeration to Netgen's. What no setup can state is encoded there as
//! a documented difference:
//!
//! - **Series MOS:** [`reduce`] merges a stack through a net that is no port;
//!   Netgen 1.5.323 does not merge MOS in series at all.
//! - **Parallel MOS of near-equal `L`:** Netgen's `l critical` merges them
//!   within its tolerance; [`reduce`] needs `L` bit-identical.
//!
//! And what the setup must say to agree: the parameter tolerance as Netgen
//! measures it (see [`CompareOptions::param_tolerance`]), every bulk on one
//! net on both sides when the layout extracts none (this module drops the
//! reference's), a layout size only where a reference card of its model
//! states it (this module keeps no other measure, and Netgen counts a
//! property one side lacks as an error), and no reading of Netgen's pin
//! matching, since names do not take part here. Unsized transistors in
//! parallel counted in `m`, and a merge told only `W` or only `L`, agree
//! with Netgen (B27).
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
//! - **F16, parameters the deck cannot define.** The layout measures MOS and
//!   resistor `w` and `l`, MOS `nf`, every marker's `area` and `perim`, a
//!   MOS's `as`, `ad`, `ps` and `pd` and a bipolar's `ae` and `pe` where
//!   the terminal is one polygon, and a resistor's `r` and a capacitor's `c`
//!   where the deck gives their coefficients. A capacitor's `w` and `l` are
//!   not measured, so a card stating one is `lvs.undeclared_param`.
//! - **Diffusions on symmetric nets.** A diffusion is compared at the
//!   channel end the net pairing puts it on. Where nothing tells two
//!   channel nets apart, the tie-break pairs them the way the diffusions of
//!   the transistors already paired agree, all of a net's transistors
//!   weighed together (testing-plan F98), then by label where the nets
//!   carry one; where no one pairing suits them all, the closest is kept
//!   and the verdict is a false mismatch, never a false match. A parallel
//!   merge sums diffusions end by end; a series merge of transistors
//!   stating them is refused, so such a stack never matches one long card.
//! - **Bounded symmetry search.** A tie-break takes back only a pairing whose
//!   own refinement shows it wrong, and tries at most eight candidates; a
//!   wrong pairing exposed only after a later tie-break, or a right one past
//!   the eighth, is kept, and the verdict is then a false mismatch, never a
//!   false match.
//! - **Passive values are counted, not combined,** under the strict
//!   policy, the default. Parallel resistors, capacitors and diodes merge
//!   into one device of the same value with a count `m`, so two capacitors
//!   of `c` do not match one card of `2c`, which `KLayout`, adding the
//!   capacitance, would pass ([`reduce`]). The deck's `lvs topology
//!   relaxed` combines them. Passives never merge in series.

pub mod checks;
mod compare;
mod controls;
pub mod graph;
pub mod reduce;
mod refine;
pub mod verdict;

pub use checks::{
    check_layout, check_net_seed_conflicts, check_param_ranges, intern_rule_ids,
    record_discrepancies, RULE_IDS,
};
pub use compare::{compare, compare_logged, compare_with, CompareOptions};
pub use graph::Graph;
pub use reduce::{Merge, MergeKind, ParamNames};
pub use verdict::{Discrepancy, Verdict};
