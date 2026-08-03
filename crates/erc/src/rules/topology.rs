//! Rules that ask only what is connected to what.
//!
//! Four kinds, no design intent, no solve. Each reduces to a question about a
//! net's [`RoleMask`] or its device list, which is why they cost one linear
//! pass over [`NetFacts`] between them and why they always run.
//!
//! # These are only as good as the extraction
//!
//! Nothing here re-derives connectivity. A gate is floating because
//! `topology` says the only terminal on its net is a gate — so an extraction
//! that missed a via reports a floating gate that is not floating, and one that
//! merged two nets reports nothing at all. That is the correct dependency
//! (`topology` is where connectivity is decided and tested), and it is stated
//! because these four rules are the ones a reader is tempted to make
//! independently clever.
//!
//! [`RoleMask`]: crate::RoleMask

use crate::facts::NetFacts;
use crate::ruleset::RuleHead;
use crate::{Design, Scratch};
use gpurify_core::LayerId;
use gpurify_derived::LayerRef;
use gpurify_report::{RuleRun, Violations};

/// A gate net with nothing driving it.
///
/// **Five questions.** In: rule rows from the deck. Out: nothing — the table is
/// the configuration. How many: normally exactly one row; a deck may configure
/// two at different severities. Access pattern: read once per row. Lifetime:
/// whole run. Parallelisable: read-only.
///
/// No parameters beyond the head, and that is the finding rather than an
/// omission. The old implementation carried a list of layers to treat as an
/// "external connection", because its net extraction stopped at the device and
/// it had to guess at the rest. Connectivity is `topology`'s job now, so the
/// whole rule is: the net's role mask is exactly [`RoleMask::GATE`].
///
/// [`RoleMask::GATE`]: crate::RoleMask::GATE
#[derive(Debug, Default)]
pub struct FloatingGateTable {
    pub head: RuleHead,
}

/// A well with no tap tying it to a supply.
///
/// The tap is a [`LayerRef`] because it is almost always derived — `nsdm AND
/// diff` inside `nwell` on a standard CMOS deck — and naming the derived layer
/// in the deck keeps the boolean in `derived`, where it is exact, rather than
/// re-approximating it here with bounding boxes as the old implementation did.
#[derive(Debug, Default)]
pub struct FloatingWellTable {
    pub head: RuleHead,
    /// The region that must be tied: `nwell`, a deep n-well, an isolated
    /// p-well.
    pub well: Vec<LayerRef>,
    /// What counts as a tie inside it.
    pub tap: Vec<LayerRef>,
}

/// A net driven by more than one output.
///
/// Two drains on one net is contention only when the drains belong to devices
/// with *different* gate nets — a parallel pair sharing a gate is one driver
/// built wide, and flagging it would make every multi-finger output a
/// violation. So the count is over distinct gate nets, not over drains.
#[derive(Debug, Default)]
pub struct MultipleDriversTable {
    pub head: RuleHead,
    /// Distinct driving gate nets permitted on one net. `1` for ordinary
    /// logic; a deck raises it for a net a design intends to share, such as a
    /// bus with a documented arbitration.
    pub max_drivers: Vec<u32>,
}

/// A conductor on a net no device terminal touches.
///
/// The layers are listed because the answer differs by layer: a top-metal
/// shape reaching no device is a routing stub, and a fill shape reaching no
/// device is fill. A deck that named no layers would flag both.
#[derive(Debug, Default)]
pub struct UnconnectedPinTable {
    pub head: RuleHead,
    /// `layer[layer_start[i] .. layer_start[i + 1]]` are row `i`'s layers.
    /// CSR, not a `Vec<Vec<LayerId>>`.
    pub layer_start: Vec<u32>,
    pub layer: Vec<LayerId>,
}

/// Flag every net whose only terminals are gates.
///
/// **Transform.** One pass over [`NetFacts::role`], per rule row. Each net's
/// verdict is a function of its own mask and the row's uniforms, so any net
/// order is legal and the pass parallelises by net range.
///
/// A gate net with no source, no drain and no passive terminal has no path to
/// a supply through anything: it charges to whatever the process left on it and
/// stays there. The violation is reported at the net's lowest-numbered polygon,
/// which is canonical because `NetTable::polys_of` is ascending.
///
/// `examined` is the number of nets carrying at least one gate terminal — the
/// nets this rule could have flagged. Counting every net instead would make a
/// design with one transistor look thoroughly checked.
pub fn check_floating_gate(
    design: Design<'_>,
    facts: &NetFacts,
    table: &FloatingGateTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Flag every well polygon containing no tap.
///
/// **Transform.** Per rule row: evaluate `well` and `tap` into the scratch
/// layers, index the taps, and test containment of each tap against each well
/// through the proximity prune. Exact containment, not bounding-box overlap —
/// a tap whose box overlaps an L-shaped well but sits in the notch is not
/// inside it, and the old implementation counted it.
///
/// A floating well is a latch-up path and a threshold shift at once, so it is
/// an error rather than a warning wherever a deck does not say otherwise.
///
/// `examined` is the number of well polygons.
pub fn check_floating_well(
    design: Design<'_>,
    table: &FloatingWellTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Flag every net driven from more than `max_drivers` distinct gate nets.
///
/// **Transform.** Two passes, because the kernel rule forbids one: the first
/// walks devices and writes each drain net's driving gate into a per-net slot
/// in `scratch`, the second scans nets and counts distinct slots. Fusing them
/// would have row N reading what row N−1 wrote.
///
/// The distinct count is over gate [`NetId`], so a four-finger output counts
/// once and two independent drivers count twice.
///
/// `examined` is the number of nets carrying at least one drain terminal.
///
/// [`NetId`]: gpurify_topology::NetId
pub fn check_multiple_drivers(
    design: Design<'_>,
    table: &MultipleDriversTable,
    scratch: &mut Scratch,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}

/// Flag every polygon on a listed layer whose net reaches no device.
///
/// **Transform.** One pass over the listed layers' polygon ranges; each
/// polygon's verdict is a load from [`NetFacts`] and a compare, with no
/// data-dependent branch beyond the push.
///
/// The test is [`NetFacts::is_device_connected`], which counts every terminal
/// of every device family. The old implementation consulted the MOS list alone,
/// so a block of BJTs or of resistors reported every one of its nets
/// unconnected — a whole-block false positive that trains a user to ignore the
/// rule, which is the same damage as a false negative.
///
/// `examined` is the number of polygons on the listed layers.
pub fn check_unconnected_pin(
    design: Design<'_>,
    facts: &NetFacts,
    table: &UnconnectedPinTable,
    out: &mut Violations,
    runs: &mut Vec<RuleRun>,
) {
    todo!()
}
