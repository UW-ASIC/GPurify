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
    /// This cell of a hierarchical plan was never compared, so nothing is known
    /// about it either way.
    ///
    /// [`hierarchical::run`](crate::hierarchical::run) is handed **one** pair of
    /// graphs and a plan of any length, and its signature gives it no way to
    /// fetch a second pair — the gap is filed under `## lvs` in
    /// `docs/SIGNATURE_DEFECTS.md`. A single-cell plan is the one shape where
    /// the pair it holds unambiguously belongs to the cell the plan names; for
    /// any longer plan, attributing that one comparison to a row would be a
    /// guess, and `Match` reached by guessing is the path from "gave up" to
    /// "matched" that this crate does not have.
    ///
    /// The `StrId` is the layout cell, so a reader is told *which* cells went
    /// unchecked rather than only that some did.
    UncomparedCell(StrId),
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
    /// Both sides have the device, but only one of them declares this
    /// parameter, so it was never compared.
    ///
    /// `side` is the side that *declared* it, which is
    /// [`Discrepancy::UnpairedDevice`]'s reading of the same field: the side the
    /// thing exists on. There is no value pair, which is the point —
    /// [`Discrepancy::ParameterMismatch`] needs two and there is only one.
    ///
    /// Separate from `ParameterMismatch` rather than folded into it behind a
    /// sentinel. A missing declaration is not a value that disagreed, and a
    /// report spelling it `ref_value: NaN` would be read as a measurement.
    ///
    /// This variant is why the name-keyed join may not pass over the symmetric
    /// difference. It used to: a card declaring `W L` against an extraction
    /// declaring nothing compared zero parameters, and the empty discrepancy
    /// list read as [`Verdict::Match`] — a clean result for a comparison that
    /// never happened, on the one outcome this crate's documentation forbids.
    UndeclaredParam {
        side: Side,
        layout_device: u32,
        ref_device: u32,
        param: StrId,
    },
    /// Two nets on one side carry the same declared name.
    ///
    /// `side` says which netlist the two indices are in. Without it `nets` is
    /// a pair of numbers in an unstated index space, and a duplicate in the
    /// schematic reads exactly like one in the layout — which is the fault
    /// this variant exists to distinguish.
    DuplicateName {
        side: Side,
        name: StrId,
        nets: (u32, u32),
    },
    /// The counts in one refinement class differ, which is the general form
    /// the more specific variants above are extracted from.
    ///
    /// Emitted only when the class holds more than one node on each side, so
    /// no individual node can be blamed. A class whose members *can* be
    /// attributed — anything holding at most one node per side — is reported
    /// as [`Discrepancy::UnpairedDevice`] or [`Discrepancy::UnpairedNet`]
    /// instead, and reporting both forms for one class is a double count.
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
