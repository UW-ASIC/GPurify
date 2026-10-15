//! What a comparison concluded, and why.
//!
//! Every row index a [`Discrepancy`] carries is a row of that side's graph
//! **after reduction**: a device row of the reduced graph, or a net row of it.
//! With nothing merged the reduced graph is the input graph row for row; when
//! something merged, [`compare_logged`](crate::lvs::compare_logged) lists which
//! input rows each merged device stands for.

use crate::topology::TerminalRole;
use gpurify_ingest::StrId;

/// The result of comparing one cell.
///
/// Only [`Verdict::Match`] passes. The `gpurify` binary records a
/// [`Verdict::Inconclusive`] as a refused LVS stage, so that run fails too.
///
/// Catalog: LVS-019. `KLayout`'s counterpart is the `NetlistCrossReference`
/// status of the circuit pair; Netgen's is its final "Netlists match uniquely"
/// or "Netlists do not match" line.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// After reduction, every device and every net that carries a terminal or
    /// a name paired one to one, and each device pair agrees on kind, model,
    /// terminals and parameters.
    ///
    /// A net with neither a terminal nor a name is not required to pair: no
    /// netlist can state one (`lvs.floating_net` reports it on the layout).
    Match,
    /// The netlists differ. Never empty. In order: every
    /// [`Discrepancy::ClassImbalance`]; then, for each paired device in
    /// ascending layout row, its identity, terminal and parameter rows; then
    /// unpaired layout devices and nets; then unpaired reference devices and
    /// nets.
    Mismatch(Vec<Discrepancy>),
    /// The comparison did not complete. Never treated as either of the above:
    /// there is no path from "gave up" to "matched".
    Inconclusive(Inconclusive),
}

/// Why a comparison could not conclude.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inconclusive {
    /// More than [`CompareOptions::max_rounds`](crate::lvs::CompareOptions::max_rounds)
    /// refinement passes in a row split a class without reaching a stable
    /// partition. Says nothing about whether the netlists match; a larger
    /// limit may conclude.
    RoundLimit,
    /// The reference netlist has no unique top-level subcircuit (zero, or
    /// several, that nothing instantiates), so there is nothing to compare
    /// against without guessing.
    ///
    /// [`compare`](crate::lvs::compare) never returns it, since it is handed
    /// one subcircuit. The caller that picks the subcircuit does, when
    /// [`Netlist::top`](gpurify_ingest::netlist::Netlist::top) is `None`.
    AmbiguousTop,
}

/// One concrete difference, phrased as something a human can act on.
///
/// Each variant reports under one id of [`RULE_IDS`](crate::lvs::RULE_IDS),
/// written by [`record_discrepancies`](crate::lvs::record_discrepancies) as an
/// error row with no layer, location or shape. Row indices are rows of the
/// reduced graphs (see the [module docs](self)). Catalog rows are in
/// [check-catalog.tsv](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv),
/// and the tools they cite in
/// [check-sources.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md).
///
/// One fault usually shows as several rows. Refinement tells nodes apart by
/// their neighbours, so a moved terminal also separates the devices on the
/// net it moved from, and those are reported too.
#[derive(Debug, Clone, PartialEq)]
pub enum Discrepancy {
    /// A device that no other-side device could be paired with: after
    /// refinement its class does not hold exactly one device per side. Also
    /// raised once per side for a pair whose kinds differ, which refinement,
    /// seeding classes by kind, does not make. A device whose model alone
    /// differs is reported as one [`Discrepancy::ModelMismatch`] instead,
    /// where that explains every difference.
    ///
    /// Report id `lvs.unpaired_device`. Catalog: LVS-012, LVS-013, LVS-049.
    /// `KLayout`: `device_mismatch`. Netgen: listed under "DEVICE mismatches".
    UnpairedDevice {
        /// Which netlist holds the device.
        side: Side,
        /// The device's row in that side's reduced graph.
        device: u32,
        /// The device's model name.
        model: StrId,
    },
    /// A net that carries a terminal or a name and that no other-side net
    /// could be paired with. A reference port with nothing attached shows here
    /// too, and so, under the deck's `lvs ports_by_name`, does a port whose
    /// name labels no layout net, or labels one wired otherwise (catalog
    /// LVS-016, LVS-001); without it, port names are not compared.
    ///
    /// Report id `lvs.unpaired_net`. Catalog: LVS-001, LVS-015, LVS-016. `KLayout`:
    /// `net_mismatch`. Netgen: listed under "NET mismatches".
    UnpairedNet {
        /// Which netlist holds the net.
        side: Side,
        /// The net's row in that side's reduced graph.
        net: u32,
        /// The reference net's name, or the layout net's port label; `None`
        /// for an unlabelled layout net.
        name: Option<StrId>,
    },
    /// A paired device whose terminal does not land on the counterpart of the
    /// net its partner's terminal of the same role lands on.
    ///
    /// Terminals are matched by role, never by position, and interchangeable
    /// roles count as one: MOS `Source` and `Drain`, a resistor's ends, and
    /// pins the deck's `lvs permute` joins, whose row names the class's first
    /// pin; an `lvs asymmetric` transistor's source and drain are two. A
    /// terminal on no net, or on a net that did not pair, never matches. One
    /// moved terminal usually gives a row from each side.
    ///
    /// Report id `lvs.terminal_mismatch`. Catalog: LVS-015. `KLayout` and Netgen
    /// have no separate class for it: they pair a device only when its nets
    /// pair, so the same fault shows there as device and net mismatches.
    TerminalMismatch {
        /// The device's row in the reduced layout graph.
        layout_device: u32,
        /// Its partner's row in the reduced reference graph.
        ref_device: u32,
        /// The role of the terminal that did not land, as written on the side
        /// it came from.
        role: TerminalRole,
    },
    /// A parameter both paired devices declare, whose values differ by more
    /// than [`CompareOptions::param_tolerance`](crate::lvs::CompareOptions::param_tolerance)
    /// `tol`: `|a - b| > tol * max(|a|, |b|)`, or, where the deck has an `lvs
    /// tolerance` row for that parameter of that model, by more than
    /// `absolute + relative * max(|a|, |b|)` ([`compare_with`](crate::lvs::compare_with)).
    /// A `NaN` on either side always differs. A parameter the deck ignores
    /// (`lvs ignore_parameter`) is never compared.
    ///
    /// Values are in SI base units (metres, square metres) and are compared
    /// after reduction, so a merged MOS carries its summed `W`, `nf` or `L`,
    /// and `W` already multiplied by `m`; any other merged device carries
    /// its count of parallel devices as `m`.
    ///
    /// Report id `lvs.parameter_mismatch`. Catalog: LVS-014. `KLayout`:
    /// `match_devices_with_different_parameters`. Netgen: a property error.
    ///
    /// # Limits
    ///
    /// A resistor's `r` and a capacitor's `c` are compared only where the
    /// deck gives their coefficients
    /// ([`from_layout`](crate::lvs::graph::from_layout)).
    ParameterMismatch {
        /// The device's row in the reduced layout graph.
        layout_device: u32,
        /// Its partner's row in the reduced reference graph.
        ref_device: u32,
        /// The parameter's SPICE name.
        param: StrId,
        /// The layout's value.
        layout_value: f64,
        /// The reference's value.
        ref_value: f64,
    },
    /// A parameter a paired device's reference card states that the layout
    /// does not measure. A value stated on one side is never taken as
    /// agreement with silence on the other.
    ///
    /// Every reference parameter the layout does not measure (a capacitor's
    /// `w` and `l`, a diffusion or emitter drawn in pieces, a resistor's `r`
    /// or a capacitor's `c` the deck gives no coefficients for) lands here
    /// (testing-plan F16). Presence is per
    /// device: a layout measure the partner's card omits is not compared,
    /// even when another card of the same model states it (testing-plan
    /// F68), so a layout measure never lands here.
    ///
    /// Report id `lvs.undeclared_param`. Catalog: LVS-020, which is
    /// GPurify-specific and cites no tool.
    UndeclaredParam {
        /// The side that declares it: always [`Side::Reference`], since a
        /// card that omits a parameter states nothing about it.
        side: Side,
        /// The device's row in the reduced layout graph.
        layout_device: u32,
        /// Its partner's row in the reduced reference graph.
        ref_device: u32,
        /// The parameter's SPICE name.
        param: StrId,
    },
    /// Two devices of one kind that refinement pairs by wiring once models
    /// are set aside, and whose models differ: a device drawn with the wrong
    /// flavour, or written with the wrong model. Reported only when the
    /// comparison by model fails and the one with models aside pairs every
    /// node, so the models are all that differ; otherwise the devices are
    /// [`Discrepancy::UnpairedDevice`]s. The pair's parameters are not
    /// compared, two models' parameters not being one model's.
    ///
    /// Report id `lvs.model_mismatch`. Catalog: LVS-013. `KLayout`:
    /// `match_devices_with_different_device_classes`.
    ModelMismatch {
        /// The device's row in the reduced layout graph.
        layout_device: u32,
        /// Its partner's row in the reduced reference graph.
        ref_device: u32,
        /// The layout device's model.
        layout_model: StrId,
        /// The reference device's model.
        ref_model: StrId,
    },
    /// A refinement class, a set of nodes no structural test could tell
    /// apart, holding at least two nodes on each side but a different number
    /// on each. No single node can be blamed, so the class is reported whole.
    /// Its members are also reported as [`Discrepancy::UnpairedDevice`] or
    /// [`Discrepancy::UnpairedNet`]; the double report is deliberate.
    ///
    /// Report id `lvs.class_imbalance`. Catalog: LVS-011, LVS-049. Netgen
    /// prints the same thing as the class fragments under "DEVICE mismatches"
    /// and "NET mismatches".
    ClassImbalance {
        /// Layout nodes in the class.
        layout_nodes: u32,
        /// Reference nodes in the class.
        ref_nodes: u32,
    },
}

/// Which netlist a discrepancy is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The extracted layout: the `layout` argument of
    /// [`compare`](crate::lvs::compare).
    Layout,
    /// The reference netlist's subcircuit: the `reference` argument.
    Reference,
}
