//! LVS against Netgen (testing-plan §4 L6, ledger F3): every circuit of the
//! enumeration against its own reference and every single fault of it, and a
//! few curated cases for what the enumeration cannot reach, compared by
//! `GPurify` and by `netgen -batch lvs`, verdict for verdict.
//!
//! **What each side reads.** `GPurify` runs the fixture as the enumeration
//! does: the circuit drawn as GDS, extracted, and compared with the
//! reference. Netgen reads the drawn circuit's own SPICE ([`spice`]) as its
//! layout side, never a netlist `GPurify` extracted, so nothing it sees comes
//! from the tool under test; a disagreement is in `GPurify`'s extraction or
//! its comparison. That SPICE states a MOS's `w` and `l` only where a
//! reference card of its model does ([`as_declared`]): `GPurify` measures
//! every drawn size but keeps one only where the reference declares it, and
//! Netgen counts a property one side states and the other lacks as an error.
//! Its reference is the fixture's own text. Both go through
//! [`for_netgen`], which puts the bulk of every three-terminal MOS on one
//! extra port: the deck extracts no bulk for those, so `GPurify` drops the
//! reference's, and Netgen must see the same thing on both sides.
//!
//! **The setup** ([`SETUP`]) states `GPurify`'s documented semantics (the
//! `lvs` module docs and `lvs::reduce`) in Netgen's terms:
//!
//! - MOS source and drain permute, and so do a resistor's ends; capacitor
//!   plates and diode and bipolar pins do not (catalog LVS-030);
//! - parallel devices merge: a MOS sums `w`, with `m` folded in and `l`
//!   critical; a passive keeps its value and counts `m`, which is Netgen's
//!   default for a device with no value (LVS-040, LVS-043, LVS-044, LVS-046);
//! - passives never merge in series, as in `GPurify`; MOS do in `GPurify`
//!   and cannot in Netgen (below);
//! - MOS `w` and `l` agree within 2 %. Netgen measures a difference against
//!   the mean of the two values and `GPurify` against the larger
//!   (`CompareOptions::param_tolerance`), so Netgen is given `2t/(2 − t)` for
//!   `GPurify`'s `t`, which puts the boundary in the same place exactly
//!   (LVS-014).
//!
//! A case whose deck states `lvs` controls (deck.md, "LVS controls") adds
//! their Netgen form after the setup ([`netgen_controls`]), and the setup
//! leaves out the `permute` of an asymmetric model's source and drain
//! (LVS-031), which Netgen then keeps apart.
//!
//! **Netgen's verdict** is read from its log: "Netlists do not match" is a
//! mismatch, and "Netlists match" a match unless property errors were found.
//! Its pin matching is not read: `GPurify` compares port names only under
//! the deck's `lvs ports_by_name` (LVS-016, LVS-032), which no case here
//! states, so it is left out on purpose.
//!
//! **Documented differences** ([`SERIES`], [`CRITICAL`]) are encoded per case
//! ([`Case::differs`]): there the two verdicts must differ, and agreeing is
//! reported as loudly as an undocumented disagreement. The enumeration makes
//! every net a port, which no series merge crosses, and draws every length
//! alike, so neither occurs there; the curated cases hold one of each.
//!
//! **Not compared:** a reference with no device left (a one-device circuit
//! with its device deleted), which Netgen declines to check ("has no
//! elements"). They are counted, and `GPurify` must call each a mismatch.

use super::{
    circuits, compared, compared_under, enumerated, pin_names, polar, spice, Circuit, Controls,
    Dev, Model, TOLERANCE,
};
use crate::harness::{self, Expect, Fixture};
use gpurify::check::lvs::Verdict;
use gpurify_testgen::{oracle, Rng};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// `GPurify` merges a MOS stack through a net that is no port into one device
/// of the summed `L` (catalog LVS-041, on by default); Netgen does not merge
/// MOS in series at all, `property ... series enable` notwithstanding.
const SERIES: &str = "series MOS merge (LVS-041)";

/// Netgen merges parallel MOS whose `l` agree within the tolerance (its
/// `critical` property); `GPurify` merges only bit-identical ones
/// (`lvs::reduce`), the conservative side.
const CRITICAL: &str = "parallel MOS of near-equal L (LVS-040)";

/// The MOS models whose recogniser lists three layers ([`super::MOS_DECK`],
/// [`super::EXTRA_DECK`]), so that no bulk is extracted for them.
const THREE_TERMINAL: [&str; 3] = ["nmos", "pmos", "nmos_hvt"];

/// How long one Netgen batch, one circuit and its faults, may run; it takes
/// well under a second.
const LIMIT: Duration = Duration::from_mins(2);

/// The Netgen setup, every class guarded because a netlist may lack it;
/// `TOL` is replaced by Netgen's tolerance. `$asymmetric`, which each case's
/// setup file sets first, lists the MOS models whose source and drain do not
/// permute.
const SETUP: &str = "\
foreach side {-circuit1 -circuit2} {
    set present [cells list -all $side]
    foreach mos {nmos pmos nmos_hvt nmosb} {
        if {[lsearch $present $mos] < 0} continue
        if {[lsearch $asymmetric $mos] < 0} {
            permute \"$side $mos\" source drain
        }
        property \"$side $mos\" parallel enable
        property \"$side $mos\" parallel {l critical}
        property \"$side $mos\" parallel {w add}
        property \"$side $mos\" tolerance {w TOL} {l TOL}
    }
    if {[lsearch $present rpoly] >= 0} {
        permute \"$side rpoly\" end_a end_b
    }
    foreach passive {rpoly cmim dpn npn} {
        if {[lsearch $present $passive] < 0} continue
        property \"$side $passive\" parallel enable
        property \"$side $passive\" series disable
    }
}
";

/// One comparison: the fixture `GPurify` runs, and the two netlists Netgen
/// reads.
struct Case {
    fixture: Fixture,
    /// The drawn circuit, through [`for_netgen`].
    layout: String,
    /// The fixture's reference, through [`for_netgen`].
    reference: String,
    /// The documented difference that makes the verdicts differ here.
    differs: Option<&'static str>,
    /// The fixture's deck controls, which Netgen reads as [`netgen_setup`]
    /// writes them.
    controls: Controls,
}

/// `text` as Netgen reads it: the bulk of every [`THREE_TERMINAL`] MOS on one
/// extra port, `sub`.
fn for_netgen(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let mut words: Vec<&str> = line.split_whitespace().collect();
        if words.first() == Some(&".subckt") {
            words.push("sub");
        } else if line.starts_with('M') && THREE_TERMINAL.contains(&words[5]) {
            words[4] = "sub";
        }
        out.push_str(&words.join(" "));
        out.push('\n');
    }
    out
}

/// `layout` with each MOS card writing `w` and `l` only where a card of its
/// model in `reference` does, as `GPurify` keeps a layout measure only where
/// the reference declares it (testing-plan F22).
fn as_declared(layout: &Circuit, reference: &Circuit) -> Circuit {
    let declared = super::Declared::of(reference);
    let mut out = layout.clone();
    for dev in &mut out.devs {
        dev.writes = (declared.has(dev.model, "w"), declared.has(dev.model, "l"));
    }
    out
}

/// A card's nets: every word but the first and the model, up to the first
/// parameter.
fn card_nets(line: &str) -> Vec<&str> {
    let words: Vec<&str> = line
        .split_whitespace()
        .take_while(|w| !w.contains('='))
        .collect();
    words[1..words.len() - 1].to_vec()
}

/// Whether every net a card of `text` lands on is a port: then no series
/// merge applies.
fn every_net_is_a_port(text: &str) -> bool {
    let ports: Vec<&str> = text
        .lines()
        .find(|l| l.starts_with(".subckt"))
        .map(|l| l.split_whitespace().skip(2).collect())
        .unwrap_or_default();
    text.lines()
        .filter(|l| l.starts_with(['M', 'R', 'C', 'D', 'Q']))
        .all(|l| card_nets(l).iter().all(|n| ports.contains(n)))
}

fn has_device(text: &str) -> bool {
    text.lines()
        .any(|l| l.starts_with(['M', 'R', 'C', 'D', 'Q']))
}

/// Circuit `c` against its own reference and every single fault of it, as
/// the enumeration generates them, but every fault (the full product, not
/// the nightly's thinning). The Spectre copy is left out: Netgen reads no
/// Spectre, and its circuit is the base case's.
fn enumeration(c: &Circuit) -> Vec<Case> {
    let layout = for_netgen(&spice(c));
    enumerated(c, None)
        .into_iter()
        .filter(|f| !f.name.ends_with("/spectre"))
        .map(|fixture| {
            let reference = for_netgen(fixture.reference.as_deref().expect("an LVS fixture"));
            assert!(
                every_net_is_a_port(&layout) && every_net_is_a_port(&reference),
                "{}: a net that is no port could merge in series, which Netgen does not; \
                 mark the case with SERIES",
                fixture.name
            );
            Case {
                fixture,
                layout: layout.clone(),
                reference,
                differs: None,
                controls: Controls::default(),
            }
        })
        .collect()
}

/// What the enumeration cannot reach: the documented differences, and each
/// setup line the enumeration's MOS-only circuits do not exercise.
fn curated() -> Vec<Case> {
    use Model::{C, D, N, Q, R};
    let case = |name: &str,
                catalog: &[&'static str],
                layout: &Circuit,
                reference: &Circuit,
                differs: Option<&'static str>| Case {
        fixture: compared(&format!("netgen/{name}"), catalog, layout, reference),
        layout: for_netgen(&spice(&as_declared(layout, reference))),
        reference: for_netgen(&spice(reference)),
        differs,
        controls: Controls::default(),
    };
    let stack = Circuit::new(4, vec![Dev::mos(N, 0, 1, 3), Dev::mos(N, 0, 3, 2)]).internal(3);
    let long = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(1000, 300)]);
    let two = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2), Dev::mos(N, 0, 2, 1)]);
    let wide = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(2000, 150)]);
    let mut near = two.clone();
    near.devs[1] = near.devs[1].clone().sized(1000, 151);
    let m2 = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).times(2)]);
    // 61 nm on 3000 is 1.99 % of the larger and 2.01 % of the mean: a match
    // for GPurify's 2 %, and for Netgen only at the matching 2.02 %.
    let sized = |w| Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(w, 150)]);
    let mut out = vec![
        case("series/stack_vs_stack", &["LVS-041"], &stack, &stack, None),
        case(
            "series/stack_vs_long",
            &["LVS-041"],
            &stack,
            &long,
            Some(SERIES),
        ),
        case("parallel/mos_two_vs_wide", &["LVS-040"], &two, &wide, None),
        case(
            "parallel/mos_near_lengths_vs_wide",
            &["LVS-040"],
            &near,
            &wide,
            Some(CRITICAL),
        ),
        case("multiplier/mos_m2_vs_two", &["LVS-046"], &two, &m2, None),
        case(
            "tolerance/w+2.03_of_3000",
            &["LVS-014"],
            &sized(3000),
            &sized(3061),
            None,
        ),
        case(
            "tolerance/w+2.07_of_3000",
            &["LVS-014"],
            &sized(3000),
            &sized(3062),
            None,
        ),
    ];
    // B27: unsized parallel MOS keep their count (F83), each merge needs only
    // the size it sums (F84), and a card with no `m` counts one device.
    let only = |dev: Dev, w, l| Circuit::new(3, vec![dev.writes(w, l)]);
    let pairs = Circuit::new(
        4,
        [[0, 1], [0, 1], [2, 3], [2, 3]]
            .iter()
            .map(|pins| Dev::pins(C, pins))
            .collect(),
    );
    let bare_and_m2 = Circuit::new(
        4,
        vec![Dev::pins(C, &[0, 1]), Dev::pins(C, &[2, 3]).times(2)],
    );
    out.extend([
        case(
            "parallel/mos_unsized_two_vs_one",
            &["LVS-040"],
            &two,
            &only(Dev::mos(N, 0, 1, 2), false, false),
            None,
        ),
        case(
            "parallel/mos_unsized_two_vs_m2",
            &["LVS-046"],
            &two,
            &only(Dev::mos(N, 0, 1, 2).times(2), false, false),
            None,
        ),
        case(
            "parallel/mos_two_vs_wide_w_only",
            &["LVS-040"],
            &two,
            &only(Dev::mos(N, 0, 1, 2).sized(2000, 150), true, false),
            None,
        ),
        case(
            "parallel/mos_two_vs_wide_l_only",
            &["LVS-040"],
            &two,
            &only(Dev::mos(N, 0, 1, 2).sized(2000, 150), false, true),
            None,
        ),
        case(
            "series/stack_vs_long_l_only",
            &["LVS-041"],
            &stack,
            &only(Dev::mos(N, 0, 1, 2).sized(1000, 300), false, true),
            Some(SERIES),
        ),
        case(
            "multiplier/C_two_pairs_vs_bare_and_m2",
            &["LVS-046"],
            &pairs,
            &bare_and_m2,
            None,
        ),
    ]);
    for model in [R, C, D] {
        let letter = model.letter();
        let one = polar(Dev::pins(model, &[0, 1]));
        let mut two = one.clone();
        two.devs.push(Dev::pins(model, &[0, 1]));
        let counted = polar(Dev::pins(model, &[0, 1]).times(2));
        let reversed = polar(Dev::pins(model, &[1, 0]));
        out.extend([
            case(
                &format!("parallel/{letter}_two_vs_one"),
                &["LVS-044"],
                &two,
                &one,
                None,
            ),
            case(
                &format!("parallel/{letter}_two_vs_m2"),
                &["LVS-046"],
                &two,
                &counted,
                None,
            ),
            case(
                &format!("polarity/{letter}_reversed"),
                &["LVS-030"],
                &one,
                &reversed,
                None,
            ),
        ]);
    }
    let bjt = polar(Dev::pins(Q, &[0, 1, 2]));
    let flipped = polar(Dev::pins(Q, &[0, 2, 1]));
    out.push(case(
        "polarity/Q_emitter_collector_swapped",
        &["LVS-030"],
        &bjt,
        &flipped,
        None,
    ));
    out.extend(controlled());
    out
}

/// A case under the deck's `controls`, which Netgen reads as the setup lines
/// [`netgen_controls`] writes for them.
fn controlled_case(
    name: &str,
    catalog: &[&'static str],
    (layout, reference): (&Circuit, &Circuit),
    controls: &Controls,
) -> Case {
    Case {
        fixture: compared_under(
            &format!("netgen/{name}"),
            catalog,
            (layout, reference),
            controls,
        ),
        layout: for_netgen(&spice(&as_declared(layout, reference))),
        reference: for_netgen(&spice(reference)),
        differs: None,
        controls: controls.clone(),
    }
}

/// `body`, a Tcl line naming `$side`, for each circuit that has `model`.
fn on_each_side(model: &str, body: &str) -> String {
    format!(
        "foreach side {{-circuit1 -circuit2}} {{\n    \
         if {{[lsearch [cells list -all $side] {model}] >= 0}} {{\n        \
         {body}\n    }}\n}}\n"
    )
}

/// One case's setup file: its asymmetric models, which [`SETUP`] reads, the
/// setup, then its other controls ([`netgen_controls`]). Every file sets
/// `$asymmetric`, since one Netgen process runs a whole batch and a Tcl
/// global would carry over from the case before.
fn netgen_setup(setup: &str, controls: &Controls) -> String {
    let asymmetric: Vec<&str> = controls.asymmetric.iter().map(|m| m.name()).collect();
    format!(
        "set asymmetric {{{}}}\n{setup}{}",
        asymmetric.join(" "),
        netgen_controls(controls)
    )
}

/// The deck's `lvs` statements in Netgen's terms, for each circuit that has
/// the model: a relative `lvs tolerance` is `property ... tolerance`, given
/// as `2t/(2 - t)` since Netgen measures against the mean (as [`SETUP`]
/// does for the default), and `lvs ignore_parameter` is `property ...
/// remove`, `lvs permute` is `permute` with Netgen's pin names, which are
/// the deck's, `lvs ignore` is `ignore class` and `lvs ignore_shorted` is
/// `ignore shorted`. An absolute part has no Netgen counterpart for a
/// real-valued property, so no case states one.
fn netgen_controls(controls: &Controls) -> String {
    let mut out = String::new();
    for &model in &controls.dummies_out {
        let model = model.name();
        out.push_str(&on_each_side(
            model,
            &format!("ignore shorted \"$side {model}\""),
        ));
    }
    for &model in &controls.left_out {
        let model = model.name();
        out.push_str(&on_each_side(
            model,
            &format!("ignore class \"$side {model}\""),
        ));
    }
    for &(model, a, b) in &controls.permuted {
        let names = pin_names(model);
        let model = model.name();
        out.push_str(&on_each_side(
            model,
            &format!("permute \"$side {model}\" {} {}", names[a], names[b]),
        ));
    }
    for &(model, param) in &controls.ignored {
        let model = model.name();
        out.push_str(&on_each_side(
            model,
            &format!("property \"$side {model}\" remove {param}"),
        ));
    }
    for &(model, param, relative, absolute) in &controls.tolerance {
        assert!(absolute.is_none(), "Netgen has no absolute tolerance");
        let netgen = 2.0 * relative / (2.0 - relative);
        let model = model.name();
        out.push_str(&on_each_side(
            model,
            &format!("property \"$side {model}\" tolerance {{{param} {netgen}}}"),
        ));
    }
    out
}

/// The deck controls Netgen states too: each a case either side of what the
/// control changes.
fn controlled() -> Vec<Case> {
    use Model::{N, P};
    let mut out = asymmetric();
    out.extend(permuted());
    out.extend(ignored());
    out.extend(dummies());
    let row = |model, param, relative| Controls::default().tolerance(model, param, relative, None);
    // LVS-014: `w` 3000 against 3120 nm, 3.85 % of the larger: within a 5 %
    // row on `nmos` `w`, not a 3 % one, and not a 5 % row on `pmos`.
    let w_of = |w| Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(w, 150)]);
    for (name, controls) in [
        ("tolerance/deck/w+3.85_relative_5pct", row(N, "w", 0.05)),
        ("tolerance/deck/w+3.85_relative_3pct", row(N, "w", 0.03)),
        ("tolerance/deck/w+3.85_row_on_pmos", row(P, "w", 0.05)),
        // LVS-014: an ignored `w` is not compared.
        (
            "ignore_parameter/w+3.85_w_ignored",
            Controls::default().ignore(N, "w"),
        ),
        (
            "ignore_parameter/w+3.85_l_ignored",
            Controls::default().ignore(N, "l"),
        ),
    ] {
        out.push(controlled_case(
            name,
            &["LVS-014"],
            (&w_of(3000), &w_of(3120)),
            &controls,
        ));
    }
    out
}

/// LVS-031: an asymmetric `nmos` against Netgen with no `permute` of its
/// source and drain. A `pmos` gated by n1 tells n1 from n2, so swapping the
/// ends is another circuit; two in parallel merge only aligned. Each with
/// and without the control.
fn asymmetric() -> Vec<Case> {
    use Model::{N, P};
    let anchored = |dev: Dev| Circuit::new(3, vec![dev, Dev::mos(P, 1, 0, 0)]);
    let same = anchored(Dev::mos(N, 0, 1, 2));
    let swapped = anchored(Dev::mos(N, 0, 2, 1));
    let aligned = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2), Dev::mos(N, 0, 1, 2)]);
    let opposed = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2), Dev::mos(N, 0, 2, 1)]);
    let wide = Circuit::new(3, vec![Dev::mos(N, 0, 1, 2).sized(2000, 150)]);
    let mut out = Vec::new();
    for (name, layout, reference) in [
        ("sd_same", &same, &same),
        ("sd_swapped", &same, &swapped),
        ("parallel_aligned_vs_wide", &aligned, &wide),
        ("parallel_opposed_vs_wide", &opposed, &wide),
    ] {
        for (label, controls) in [
            ("symmetric", Controls::default()),
            ("asymmetric", Controls::default().asymmetric(N)),
        ] {
            out.push(controlled_case(
                &format!("asymmetric/{name}/{label}"),
                &["LVS-031"],
                (layout, reference),
                &controls,
            ));
        }
    }
    out
}

/// LVS-030: pins the deck permutes, against Netgen's `permute`. A capacitor
/// or diode reversed, a bipolar with emitter and collector exchanged (its
/// base on n1, its emitter on n0, which the `nmos` gate fixes), and two
/// capacitors in opposite directions against one of `m = 2`, each with and
/// without the permutation.
fn permuted() -> Vec<Case> {
    use Model::{C, D, Q};
    let mut opposed = polar(Dev::pins(C, &[0, 1]));
    opposed.devs.push(Dev::pins(C, &[1, 0]));
    let pairs = [
        (
            "C_reversed",
            polar(Dev::pins(C, &[0, 1])),
            polar(Dev::pins(C, &[1, 0])),
            Controls::default().permute(C, 0, 1),
        ),
        (
            "D_reversed",
            polar(Dev::pins(D, &[0, 1])),
            polar(Dev::pins(D, &[1, 0])),
            Controls::default().permute(D, 0, 1),
        ),
        (
            "Q_emitter_collector_swapped",
            polar(Dev::pins(Q, &[1, 0, 2])),
            polar(Dev::pins(Q, &[1, 2, 0])),
            Controls::default().permute(Q, 1, 2),
        ),
        (
            "C_opposed_vs_m2",
            opposed,
            polar(Dev::pins(C, &[0, 1]).times(2)),
            Controls::default().permute(C, 0, 1),
        ),
    ];
    let mut out = Vec::new();
    for (name, layout, reference, controls) in pairs {
        for (label, controls) in [("permuted", controls), ("default", Controls::default())] {
            out.push(controlled_case(
                &format!("permute/{name}/{label}"),
                &["LVS-030"],
                (&layout, &reference),
                &controls,
            ));
        }
    }
    out
}

/// LVS-034: a capacitor drawn and not written, written and not drawn, and
/// written to an internal net nothing else touches, against Netgen's
/// `ignore class`, each with and without the control.
fn ignored() -> Vec<Case> {
    use Model::{C, P};
    let bare = polar(Dev::mos(P, 1, 0, 2));
    let mut capped = bare.clone();
    capped.devs.push(Dev::pins(C, &[0, 1]));
    let mut to_internal = bare.clone();
    to_internal.names.push("n3".to_owned());
    to_internal.ports.push(false);
    to_internal.devs.push(Dev::pins(C, &[1, 3]));
    let mut out = Vec::new();
    for (name, layout, reference) in [
        ("drawn_only", &capped, &bare),
        ("written_only", &bare, &capped),
        ("internal_net_written_only", &bare, &to_internal),
    ] {
        for (label, controls) in [
            ("ignored", Controls::default().leave_out(C)),
            ("default", Controls::default()),
        ] {
            out.push(controlled_case(
                &format!("ignore/{name}/{label}"),
                &["LVS-034"],
                (layout, reference),
                &controls,
            ));
        }
    }
    out
}

/// LVS-035: an `nmosb` dummy with all four pins on n3, drawn and not
/// written and the other way round, against Netgen's `ignore shorted`, with
/// and without the control. The four-terminal model, because Netgen reads a
/// three-terminal one's bulk on the extra port ([`for_netgen`]), where no
/// dummy is shorted.
fn dummies() -> Vec<Case> {
    use Model::B;
    let real = Circuit::new(4, vec![Dev::mos(B, 0, 1, 2).bulk(3)]);
    let mut dummy = real.clone();
    dummy.devs.push(Dev::mos(B, 3, 3, 3).bulk(3));
    let mut out = Vec::new();
    for (name, layout, reference) in [("drawn", &dummy, &real), ("written", &real, &dummy)] {
        for (label, controls) in [
            ("ignored", Controls::default().leave_out_dummies(B)),
            ("default", Controls::default()),
        ] {
            out.push(controlled_case(
                &format!("ignore_shorted/{name}/{label}"),
                &["LVS-035"],
                (layout, reference),
                &controls,
            ));
        }
    }
    out
}

/// Netgen's verdict from its comparison log; `None` when it gave none.
/// "Networks match locally but not globally" is its report of swapped
/// connections, a mismatch, and so is "parallel/series network does not
/// match", its report of merged devices that differ. A match with property
/// errors is a mismatch however Netgen words it: "Property errors were
/// found." after a unique match, but only "Netlists match with N
/// symmetries and property errors." after one it resolved by symmetry,
/// which this used to read as a clean match (B31).
fn netgen_verdict(log: &str) -> Option<bool> {
    let refused = ["Netlists do not match", "match locally but not globally"];
    if refused.iter().any(|why| log.contains(why)) {
        Some(false)
    } else if log.contains("Netlists match") {
        Some(
            !log.contains("roperty errors")
                && !log.contains("parallel/series network does not match"),
        )
    } else {
        None
    }
}

/// The lines of a Netgen log that say what it found, for a broken case's
/// report: its verdicts, property and merge complaints, symmetries.
fn netgen_summary(log: &str) -> String {
    let telling = ["atch", "roperty", "ymmetr", "network", "shorted"];
    log.lines()
        .filter(|line| telling.iter().any(|word| line.contains(word)))
        .take(12)
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(" | ")
}

/// `GPurify`'s verdict, or why it gave none.
fn gpurify_verdict(fixture: &Fixture) -> Result<bool, String> {
    match harness::run(fixture)?.lvs {
        Some(Verdict::Match) => Ok(true),
        Some(Verdict::Mismatch(_)) => Ok(false),
        other => Err(format!("no verdict ({other:?})")),
    }
}

/// The enumeration oracle's verdict, for the report.
fn x5_verdict(fixture: &Fixture) -> Option<bool> {
    fixture.expect.iter().find_map(|e| match e {
        Expect::Lvs(matched) => Some(*matched),
        _ => None,
    })
}

/// What a batch of comparisons found.
#[derive(Default)]
struct Tally {
    /// Every case of the batch.
    cases: usize,
    /// Both verdicts the same, where no difference is documented.
    agreed: usize,
    /// Of those, both a match.
    matched: usize,
    /// Verdicts that differ as documented, per difference.
    differs: BTreeMap<&'static str, usize>,
    /// References with no device, which Netgen does not check.
    unchecked: usize,
    /// Everything else, one line each.
    broken: Vec<String>,
}

impl Tally {
    fn add(&mut self, other: Tally) {
        self.cases += other.cases;
        self.agreed += other.agreed;
        self.matched += other.matched;
        for (why, n) in other.differs {
            *self.differs.entry(why).or_default() += n;
        }
        self.unchecked += other.unchecked;
        self.broken.extend(other.broken);
    }
}

/// Compares every case with one Netgen process, in a scratch directory that
/// is removed when nothing broke. Netgen keeps about 6 MB of every comparison
/// until it exits, so a batch is one circuit's cases, a few dozen.
fn differential(netgen: &Path, cases: &[Case]) -> Tally {
    let dir = oracle::scratch("netgen");
    let write = |name: &str, text: &str| {
        std::fs::write(dir.join(name), text).expect("the scratch directory is writable");
    };
    let tolerance = 2.0 * TOLERANCE / (2.0 - TOLERANCE);
    let setup = SETUP.replace("TOL", &tolerance.to_string());
    let mut tally = Tally {
        cases: cases.len(),
        ..Tally::default()
    };
    let mut batch = String::new();
    for (i, case) in cases.iter().enumerate() {
        if has_device(&case.reference) {
            write(&format!("l{i}.spice"), &case.layout);
            write(&format!("r{i}.spice"), &case.reference);
            write(&format!("s{i}.tcl"), &netgen_setup(&setup, &case.controls));
            let _ = writeln!(
                batch,
                "lvs {{l{i}.spice TOP}} {{r{i}.spice TOP}} s{i}.tcl o{i}.log"
            );
        }
    }
    write("batch.tcl", &batch);
    oracle::run(netgen, &["-batch", "source", "batch.tcl"], &dir, LIMIT);
    for (i, case) in cases.iter().enumerate() {
        let name = &case.fixture.name;
        let ours = gpurify_verdict(&case.fixture);
        if !has_device(&case.reference) {
            tally.unchecked += 1;
            if ours != Ok(false) {
                tally.broken.push(format!(
                    "{name}: an empty reference, GPurify {ours:?}, want a mismatch"
                ));
            }
            continue;
        }
        let path = dir.join(format!("o{i}.log"));
        let log = std::fs::read_to_string(&path).unwrap_or_default();
        let theirs = netgen_verdict(&log);
        match (&ours, theirs, case.differs) {
            (Ok(a), Some(b), None) if *a == b => {
                tally.agreed += 1;
                tally.matched += usize::from(b);
            }
            (Ok(a), Some(b), Some(why)) if *a != b => {
                *tally.differs.entry(why).or_default() += 1;
            }
            _ => tally.broken.push(format!(
                "{name}: GPurify {ours:?}, Netgen {theirs:?}, enumeration oracle {:?}{}; {}\n    \
                 netgen: {}",
                x5_verdict(&case.fixture),
                case.differs
                    .map(|why| format!(", documented to differ ({why})"))
                    .unwrap_or_default(),
                path.display(),
                netgen_summary(&log)
            )),
        }
    }
    if tally.broken.is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    tally
}

/// Compares batch `batch(i)` for every `i < count`, each with one Netgen
/// process, on [`oracle::MAX_RUNNING`] threads, and fails listing every case
/// that broke. Returns the tally.
fn compare_all(count: usize, batch: impl Fn(usize) -> Vec<Case> + Sync) -> Tally {
    let netgen = oracle::tool("netgen");
    let next = AtomicUsize::new(0);
    let total = Mutex::new(Tally::default());
    std::thread::scope(|scope| {
        for _ in 0..oracle::MAX_RUNNING {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= count {
                    break;
                }
                let found = differential(&netgen, &batch(i));
                total.lock().expect("not poisoned").add(found);
            });
        }
    });
    let total = total.into_inner().expect("not poisoned");
    println!(
        "netgen: {} cases, {} verdicts agree ({} both a match), documented \
         differences {:?}, {} empty references not checked, {} broken",
        total.cases,
        total.agreed,
        total.matched,
        total.differs,
        total.unchecked,
        total.broken.len()
    );
    let mut broken = total.broken.clone();
    broken.sort();
    assert!(
        broken.is_empty(),
        "{} cases broken (first 200):\n{}",
        broken.len(),
        broken[..broken.len().min(200)].join("\n")
    );
    for why in [SERIES, CRITICAL] {
        assert!(
            total.differs.contains_key(why),
            "{why}: no case exercised it"
        );
    }
    total
}

/// The curated cases and one circuit of the enumeration, drawn by seed, with
/// every single fault of it: a few dozen comparisons, to run by hand.
///
/// Oracle: differential against Netgen, an independent LVS, on the curated
/// cases and one enumerated circuit with every single fault.
#[test]
#[ignore = "release tier: needs netgen (nix develop .#oracles)"]
fn netgen_differential_sample() {
    let circuits = circuits();
    let mut rng = Rng::new(0xF3);
    let pick = usize::try_from(rng.below(circuits.len() as u64)).expect("few circuits");
    println!("netgen: the sample circuit is {}", circuits[pick].code());
    let total = compare_all(2, |i| match i {
        0 => curated(),
        _ => enumeration(&circuits[pick]),
    });
    assert!(total.agreed >= 20 && total.matched >= 5, "too few ran");
}

/// The full enumeration, 4223 circuits each with every single fault, and the
/// curated cases: `GPurify` and Netgen agree on every verdict but the
/// documented differences. The nightly `oracles` job runs it.
///
/// Oracle: differential against Netgen, an independent LVS, on all
/// 4223 circuits with every single fault and the curated cases; the documented
/// differences aside, every verdict agrees.
#[test]
#[ignore = "release tier: needs netgen (nix develop .#oracles)"]
fn netgen_differential_every_small_circuit_and_single_fault() {
    let circuits = circuits();
    let total = compare_all(circuits.len() + 1, |i| match circuits.get(i) {
        Some(c) => enumeration(c),
        None => curated(),
    });
    assert_eq!(
        total.agreed + total.differs.values().sum::<usize>() + total.unchecked,
        total.cases,
        "every case was compared"
    );
    assert!(total.agreed > 100_000, "the full enumeration ran");
}

/// Multi-die stacks (catalog LVS-073): the tool reads two drawn dies and a
/// hierarchical system netlist; Netgen reads the two circuits the test
/// flattened, the dies joined through the bumps drawn and the netlist's cells
/// through the bonds written (`super::system`). Every net is a port, so
/// neither documented difference can arise, and every verdict must agree.
///
/// Oracle: differential against Netgen, an independent LVS, on the flattened
/// system of every merge-depth stack with every die fault and every missing
/// and swapped bump.
#[test]
#[ignore = "release tier: needs netgen (nix develop .#oracles)"]
fn netgen_differential_system_stacks() {
    let netgen = oracle::tool("netgen");
    let cases = super::system::netgen_cases();
    let dir = oracle::scratch("netgen-system");
    let write = |name: &str, text: &str| {
        std::fs::write(dir.join(name), text).expect("the scratch directory is writable");
    };
    let tolerance = 2.0 * TOLERANCE / (2.0 - TOLERANCE);
    let setup = SETUP.replace("TOL", &tolerance.to_string());
    write("setup.tcl", &netgen_setup(&setup, &Controls::default()));
    let mut batch = String::new();
    for (i, (_, _, layout, reference)) in cases.iter().enumerate() {
        write(&format!("l{i}.spice"), &for_netgen(&spice(layout)));
        write(&format!("r{i}.spice"), &for_netgen(&spice(reference)));
        let _ = writeln!(
            batch,
            "lvs {{l{i}.spice TOP}} {{r{i}.spice TOP}} setup.tcl o{i}.log"
        );
    }
    write("batch.tcl", &batch);
    oracle::run(&netgen, &["-batch", "source", "batch.tcl"], &dir, LIMIT);
    let mut broken = Vec::new();
    let mut agreed = 0;
    for (i, (name, ours, _, _)) in cases.iter().enumerate() {
        let path = dir.join(format!("o{i}.log"));
        let theirs = netgen_verdict(&std::fs::read_to_string(&path).unwrap_or_default());
        match (ours, theirs) {
            (Ok(a), Some(b)) if *a == b => agreed += 1,
            _ => broken.push(format!(
                "{name}: GPurify {ours:?}, Netgen {theirs:?}; {}",
                path.display()
            )),
        }
    }
    println!("netgen system: {} cases, {agreed} agree", cases.len());
    assert!(
        broken.is_empty(),
        "{} cases broken (first 60):\n{}",
        broken.len(),
        broken[..broken.len().min(60)].join("\n")
    );
    if broken.is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(agreed > 100, "the stacks ran");
}
