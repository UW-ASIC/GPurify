//! The two sides list a device's terminals in different orders, on purpose.
//!
//! **Implementation-Phase regression test**, and the one file in this suite not
//! inherited from the Plan-Phase test plan. It is here because the inherited
//! suite has a blind spot with a name: every fixture in `tests/common` builds
//! both sides through one `GraphBuilder`, so both sides always list a device's
//! terminals in the *same* order, and the one thing the two projections in
//! `graph.rs` are documented to disagree about is never exercised.
//!
//! What they disagree about is resolved and stated here.
//! `topology::role_at` names the gate at position 0
//! because a recogniser's terminal layers are listed geometry-first;
//! `graph::card_role` names the drain at position 0 because that is SPICE's `M`
//! card order. The two orders *meet in `lvs`* — so a comparison matching
//! terminals slot by slot reported a
//! `TerminalMismatch` on every MOS and every BJT the refiner had just paired
//! correctly, and the whole inherited suite stayed green through it.
//!
//! Oracle: construct-from-answer. One device, written out twice in the two
//! documented orders. Same roles on the same nets, so the answer is a match
//! before anything runs.

use crate::common;

use gpurify_check::lvs::compare::{compare, CompareOptions};
use gpurify_check::lvs::refine::Partition;
use gpurify_check::lvs::{LayoutGraph, RefGraph, Verdict};
use gpurify_check::topology::TerminalRole::{Base, Bulk, Collector, Drain, Emitter, Gate, Source};
use gpurify_ingest::deck::DeviceKind;

/// A MOS in recogniser order against the same MOS in SPICE `M` card order.
#[test]
fn a_mos_in_the_two_documented_terminal_orders_is_one_device() {
    let mut layout = common::GraphBuilder::new(4);
    layout.device(
        DeviceKind::Mos,
        common::NCH,
        // `topology::role_at`: gate, source, drain, bulk.
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
    );

    let mut reference = common::GraphBuilder::new(4);
    reference.device(
        DeviceKind::Mos,
        common::NCH,
        // `graph::card_role`: drain, gate, source, bulk. Every role still lands
        // on the net it landed on above; only the slot moved.
        &[(Drain, 2), (Gate, 0), (Source, 1), (Bulk, 3)],
    );

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(layout.finish()),
        &RefGraph(reference.finish()),
        CompareOptions::default(),
        &mut scratch,
    );
    assert_eq!(verdict, Verdict::Match, "one MOS, two terminal orders");
}

/// The bipolar row of the same table: base/emitter/collector against the card's
/// collector/base/emitter.
#[test]
fn a_bjt_in_the_two_documented_terminal_orders_is_one_device() {
    let mut layout = common::GraphBuilder::new(3);
    layout.device(
        DeviceKind::Bjt,
        common::NCH,
        &[(Base, 0), (Emitter, 1), (Collector, 2)],
    );

    let mut reference = common::GraphBuilder::new(3);
    reference.device(
        DeviceKind::Bjt,
        common::NCH,
        &[(Collector, 2), (Base, 0), (Emitter, 1)],
    );

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(layout.finish()),
        &RefGraph(reference.finish()),
        CompareOptions::default(),
        &mut scratch,
    );
    assert_eq!(verdict, Verdict::Match, "one BJT, two terminal orders");
}

/// Matching by role must not make the check blind. A `Match` here would be the
/// false match the crate's second doc section forbids.
///
/// Two transistors sharing net 2, so the nets are no longer interchangeable —
/// with a single isolated device any permutation of its nets is an isomorphism,
/// and exchanging two of them is a relabelling rather than a difference. Here
/// the reference's gate and drain are exchanged on the lower device, which puts
/// a gate on the shared net and leaves the layout with no net of that shape.
#[test]
fn reordering_the_slots_does_not_excuse_a_terminal_on_the_wrong_net() {
    let mut layout = common::GraphBuilder::new(6);
    layout.device(
        DeviceKind::Mos,
        common::NCH,
        &[(Gate, 0), (Source, 1), (Drain, 2), (Bulk, 3)],
    );
    layout.device(
        DeviceKind::Mos,
        common::NCH,
        &[(Gate, 4), (Source, 2), (Drain, 5), (Bulk, 3)],
    );

    let mut reference = common::GraphBuilder::new(6);
    reference.device(
        DeviceKind::Mos,
        common::NCH,
        // Card order, with the gate and the drain exchanged against the layout.
        &[(Drain, 0), (Gate, 2), (Source, 1), (Bulk, 3)],
    );
    reference.device(
        DeviceKind::Mos,
        common::NCH,
        // Card order, untouched.
        &[(Drain, 5), (Gate, 4), (Source, 2), (Bulk, 3)],
    );

    let mut scratch = Partition::default();
    let verdict = compare(
        &LayoutGraph(layout.finish()),
        &RefGraph(reference.finish()),
        CompareOptions::default(),
        &mut scratch,
    );
    assert_ne!(verdict, Verdict::Match, "a gate on the wrong net matched");
}
