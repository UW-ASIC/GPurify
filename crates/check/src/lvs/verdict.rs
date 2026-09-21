//! What a comparison concluded, and why.

use crate::topology::TerminalRole;
use gpurify_ingest::StrId;

/// The result of comparing one cell.
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
    /// This cell of a hierarchical plan was never compared; the `StrId` is the
    /// layout cell.
    UncomparedCell(StrId),
}

/// One concrete difference, phrased as something a human can act on.
#[derive(Debug, Clone, PartialEq)]
pub enum Discrepancy {
    /// A device exists on one side with no counterpart.
    UnpairedDevice {
        side: Side,
        device: u32,
        model: StrId,
    },
    /// A net exists on one side with no counterpart.
    UnpairedNet {
        side: Side,
        net: u32,
        name: Option<StrId>,
    },
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
    /// Both sides have the device, but only `side` declares this parameter, so it
    /// was never compared. The name-keyed join must visit the symmetric
    /// difference: skipping it would compare zero parameters and report
    /// [`Verdict::Match`].
    UndeclaredParam {
        side: Side,
        layout_device: u32,
        ref_device: u32,
        param: StrId,
    },
    /// Two nets on one side carry the same declared name; `side` says which
    /// netlist the two indices are in.
    DuplicateName {
        side: Side,
        name: StrId,
        nets: (u32, u32),
    },
    /// The counts in one refinement class differ. Emitted only when the class
    /// holds more than one node per side; a smaller one is reported as
    /// `UnpairedDevice` or `UnpairedNet` instead.
    ClassImbalance { layout_nodes: u32, ref_nodes: u32 },
}

/// Which netlist a discrepancy is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Layout,
    Reference,
}
