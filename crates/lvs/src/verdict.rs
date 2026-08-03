//! What a comparison concluded, and why.

use gpurify_ingest::StrId;
use gpurify_topology::TerminalRole;

/// The result of comparing one cell.
///
/// Three outcomes, not two. [`Verdict::Inconclusive`] exists because a checker
/// that cannot distinguish "these differ" from "I could not tell" will
/// eventually report the second as the first, and a tapeout will go out on it.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Every device and net paired.
    Match,
    /// The netlists differ, and here is where.
    Mismatch(Vec<Discrepancy>),
    /// The comparison did not complete. Never treated as either of the above.
    Inconclusive(Inconclusive),
}

/// Why a comparison could not conclude.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inconclusive {
    /// Refinement hit its round limit.
    RoundLimit,
    /// A genuine symmetry remained and the run was configured to refuse rather
    /// than break it.
    UnresolvedSymmetry,
    /// The reference netlist has no unique top-level subcircuit, so there is
    /// nothing to compare against without guessing.
    AmbiguousTop,
    /// A subcircuit the layout needs is absent from the reference.
    MissingSubcircuit(StrId),
}

/// One concrete difference, phrased as something a human can act on.
#[derive(Debug, Clone, PartialEq)]
pub enum Discrepancy {
    /// A device exists on one side with no counterpart.
    UnpairedDevice { side: Side, device: u32, model: StrId },
    /// A net exists on one side with no counterpart.
    UnpairedNet { side: Side, net: u32, name: Option<StrId> },
    /// Both sides have the device, but a terminal lands on a different net.
    TerminalMismatch {
        layout_device: u32,
        ref_device: u32,
        role: TerminalRole,
    },
    /// Both sides have the device, but a parameter differs beyond tolerance.
    ParameterMismatch {
        layout_device: u32,
        ref_device: u32,
        param: StrId,
        layout_value: f64,
        ref_value: f64,
    },
    /// Two nets carry the same declared name.
    DuplicateName { name: StrId, nets: (u32, u32) },
    /// The counts in one refinement class differ, which is the general form
    /// the more specific variants above are extracted from.
    ClassImbalance {
        layout_nodes: u32,
        ref_nodes: u32,
    },
}

/// Which netlist a discrepancy is about.
///
/// Named rather than a `bool`, because "which side is missing the device" is
/// the first thing a reader needs and `false` does not say it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Layout,
    Reference,
}
