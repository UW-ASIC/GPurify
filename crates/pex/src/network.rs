//! The extracted parasitic network.
//!
//! Not a violation table — PEX does not have verdicts, it has values — so this
//! is its own type rather than a variant of `report`'s.

use gpurify_core::LayerId;
use gpurify_topology::NetId;
use gpurify_units::{prefix, Capacitance, Inductance, Qty, Resistance};

/// One parasitic element.
///
/// Fixed prefixes per kind, chosen so the numbers a report prints are readable
/// without a scale column: ohms, femtofarads, picohenries. Fixing them here
/// also means a whole column shares one scale, so two rows compare directly.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Parasitic {
    /// Series resistance between two nodes of one net.
    Resistance(Qty<Resistance, { prefix::BASE }>),
    /// Capacitance from a net to ground.
    GroundCap(Qty<Capacitance, { prefix::FEMTO }>),
    /// Capacitance between two different nets.
    CouplingCap(Qty<Capacitance, { prefix::FEMTO }>),
    /// Loop or partial inductance. Only the quasi-static path produces these.
    Inductance(Qty<Inductance, { prefix::PICO }>),
}

/// A node in the parasitic network.
///
/// A net is not one node: extraction splits it at every branch point, because a
/// long wire's resistance is not a single number. So a node is a net plus a
/// position along it, and the net's terminals are the nodes a simulator sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct NodeId(pub u32);

/// The extracted network.
///
/// **Five questions.** In: geometry, nets, and the deck's process stack. Out:
/// `SoA` node and element columns. How many: a few nodes per net for a
/// analytical run, thousands for a quasi-static one on a critical net. Access
/// pattern: written once by extraction, then walked in order by reduction and
/// by the writers — so element order is canonical and stated. Lifetime: whole
/// run. Parallelisable: per-net extraction is independent, and results are
/// concatenated in net order to keep the output deterministic.
///
/// # The node-order invariant
///
/// Stated in the Testing-Phase, which found the columns public and the
/// convention unwritten, so a fixture laying nodes out net by net was guessing.
/// It is not a guess: **every node of one net occupies one contiguous range of
/// `node_net`, and the ranges run in ascending [`NetId`]**. That is what
/// "concatenated in net order" above already implies, and it is what lets a
/// writer emit a net's nodes by scanning a range instead of filtering the
/// column.
///
/// Established by [`crate::analytical::extract_into`] and
/// [`crate::quasistatic::extract_into`], and preserved by
/// [`reduce_into`](crate::reduce::reduce_into). [`Self::push`] does not enforce
/// it and [`Self::sort_canonical`] does not restore it — `sort_canonical` orders
/// *elements*, and a caller assembling a network row by row owns the invariant.
#[derive(Debug, Default, PartialEq)]
pub struct ParasiticNetwork {
    /// Which net each node belongs to. Grouped and ascending — see the type's
    /// doc comment.
    pub node_net: Vec<NetId>,
    /// Which layer each node sits on. Needed by the writers and by coupling.
    pub node_layer: Vec<LayerId>,

    /// One row per element. `to` is `None` for a ground capacitance, which is
    /// the common case and does not deserve a sentinel node.
    pub from: Vec<NodeId>,
    pub to: Vec<Option<NodeId>>,
    pub value: Vec<Parasitic>,
}

/// Femtofarads on a capacitive element, zero on any other kind.
///
/// The branchless form of "skip the resistors": a select over a closed enum, so
/// a resistive row contributes `0.0` to a capacitance sum rather than being
/// branched around. That is what lets [`ParasiticNetwork::net_capacitance`]
/// fold every element unconditionally.
///
/// **Decision** — pure, one value in, one out.
///
/// `pub(crate)` because [`crate::reduce`] folds the same column for the same
/// reason — it had its own byte-identical copy until the crate was reviewed
/// whole. One copy, beside the enum it matches on, so a fifth [`Parasitic`]
/// variant cannot be capacitive in one module and not in the other.
#[inline]
pub(crate) fn cap_ff(value: Parasitic) -> f64 {
    match value {
        Parasitic::GroundCap(q) | Parasitic::CouplingCap(q) => q.raw(),
        Parasitic::Resistance(_) | Parasitic::Inductance(_) => 0.0,
    }
}

/// The canonical sort key of one element row, in comparison order: `from`, the
/// far node with ground first, the element kind, the value's bits.
///
/// Named because it is carried in a column — [`ParasiticNetwork::sort_canonical`]
/// computes one per row up front and sorts on it, so the key's width is a cost
/// paid `element_count()` times rather than a shape internal to one function.
type CanonicalKey = (u32, u64, u8, u64);

/// One element row with its key already computed, the row type
/// [`ParasiticNetwork::sort_canonical`] sorts.
type KeyedRow = (CanonicalKey, NodeId, Option<NodeId>, Parasitic);

/// The canonical sort key of one element row: `from`, then `to` with ground
/// first, then element kind, then the value's bits.
///
/// **Decision** — pure, one row in, one key out; the whole of what
/// [`ParasiticNetwork::sort_canonical`] means.
///
/// The value bits are the tie-break that makes the key *total*. Canonical order
/// has to be a function of the rows alone, and without the last field two
/// permutations of the same multiset of rows — two resistors between one pair,
/// say — could sort to different bytes, leaving the determinism gate decided by
/// the very input order it exists to erase. Bits rather than a float compare
/// because `NaN` has no ordering and `to_bits` still gives a total one.
fn canonical_key(from: NodeId, to: Option<NodeId>, value: Parasitic) -> CanonicalKey {
    // The tag orders the kinds by declaration: resistance, ground, coupling,
    // inductance.
    let (tag, raw) = match value {
        Parasitic::Resistance(q) => (0u8, q.raw()),
        Parasitic::GroundCap(q) => (1u8, q.raw()),
        Parasitic::CouplingCap(q) => (2u8, q.raw()),
        Parasitic::Inductance(q) => (3u8, q.raw()),
    };
    // `None` is ground and sorts first, so a present node is shifted up by one.
    // Widened to `u64` because `NodeId(u32::MAX).0 + 1` does not fit a `u32`.
    let far = to.map_or(0, |node| u64::from(node.0) + 1);
    (from.0, far, tag, raw.to_bits())
}

impl ParasiticNetwork {
    pub fn node_count(&self) -> usize {
        debug_assert_eq!(
            self.node_net.len(),
            self.node_layer.len(),
            "the node columns must stay parallel"
        );
        self.node_net.len()
    }

    pub fn element_count(&self) -> usize {
        debug_assert_eq!(
            self.from.len(),
            self.to.len(),
            "the element columns must stay parallel"
        );
        debug_assert_eq!(
            self.from.len(),
            self.value.len(),
            "the element columns must stay parallel"
        );
        self.from.len()
    }

    /// Empty every column, keeping the capacity.
    ///
    /// **Transform, in-place.** The five-column form of "caller owns `out`,
    /// cleared and refilled": `clear` keeps the allocation, so a caller
    /// extracting corner after corner reuses one buffer, and a reused buffer
    /// gives the same bytes as a fresh one — half of what the determinism gate
    /// checks.
    ///
    /// `pub(crate)` because both [`crate::analytical::extract_into`] and
    /// [`crate::quasistatic::extract_into`] open with it — each had its own
    /// byte-identical copy of the five lines until the crate was reviewed whole.
    /// One copy, beside the columns it names, so a sixth column cannot be
    /// cleared by one entry point and left stale by the other.
    pub(crate) fn clear(&mut self) {
        self.node_net.clear();
        self.node_layer.clear();
        self.from.clear();
        self.to.clear();
        self.value.clear();

        debug_assert_eq!(self.node_count(), 0, "a cleared network declares no node");
        debug_assert_eq!(self.element_count(), 0, "a cleared network holds no element");
    }

    pub fn push(&mut self, from: NodeId, to: Option<NodeId>, value: Parasitic) {
        let before = self.element_count();
        let nodes = self.node_count();

        self.from.push(from);
        self.to.push(to);
        self.value.push(value);

        debug_assert_eq!(self.element_count(), before + 1);
        // Nodes and elements are separate columns: an element joins nodes that
        // already exist, and a push that grew the node columns too would
        // misreport every count downstream of it.
        debug_assert_eq!(self.node_count(), nodes, "a push does not create a node");
    }

    /// Total capacitance on one net, ground plus coupling.
    ///
    /// **Decision** — pure, and the number every timing tool asks for first.
    /// Summed in element order, which is canonical, so the result is
    /// bit-identical across runs. Summing in any other order would be a
    /// different `f64`.
    pub fn net_capacitance(&self, net: NetId) -> Qty<Capacitance, { prefix::FEMTO }> {
        let elements = self.element_count();
        // Hoisted above the fold as a uniform: the node column is read as a
        // gather, and a data-dependent *address* is not a branch.
        let nodes = &self.node_net[..];

        // Fail closed on columns that drifted apart. `element_count` above
        // already compares all three, but the trip count below is taken from
        // `from` alone, so the check that licenses it says so here.
        debug_assert_eq!(self.from.len(), self.to.len(), "SoA columns must agree");
        debug_assert_eq!(self.from.len(), self.value.len(), "SoA columns must agree");
        let n = self.from.len();
        // Re-sliced to the trip count so LLVM carries `len == n` into the loop
        // and drops the per-row bounds check on the two trailing columns.
        let (froms, tos, values) = (&self.from[..n], &self.to[..n], &self.value[..n]);

        // A strict left fold in ascending index order. That order is interface,
        // not implementation: it is what makes this sum bit-identical across
        // runs, so it must not be reassociated into lane accumulators however
        // wide the machine is.
        let mut total = 0.0f64;
        for i in 0..n {
            let (from, to, value) = (froms[i], tos[i], values[i]);
            // A ground capacitance has no far node. Folding `from` in twice
            // leaves the `|` below unchanged, which is what makes the far
            // end unconditional instead of a `match` on the `Option`.
            let far = to.unwrap_or(from);
            // Fail closed on a node id past the end of the column: an
            // element whose net cannot be resolved is counted onto no net
            // rather than onto every one. `|` and not `||` — both sides are
            // a compare against a loaded `u32`, so short-circuiting would
            // only buy a branch.
            let touches = (nodes.get(from.0 as usize) == Some(&net))
                | (nodes.get(far.0 as usize) == Some(&net));
            // `if touches { total + c }` with the predicate as a multiplier,
            // and `cap_ff` already zeroes the resistive rows — so every element
            // folds unconditionally, in the canonical order the type's doc
            // comment fixes.
            total += cap_ff(value) * f64::from(u8::from(touches));
        }

        debug_assert_eq!(self.element_count(), elements, "a decision mutates nothing");
        debug_assert!(
            total.is_finite(),
            "net {} summed to {total} fF, which no report can carry",
            net.0
        );
        Qty::new(total)
    }

    /// Establish canonical element order: by `from`, then `to` (`None` first),
    /// then element kind.
    ///
    /// Part of the interface. The determinism gate compares serialised output,
    /// and this is where that comparability is created.
    pub fn sort_canonical(&mut self) {
        let elements = self.element_count();
        let nodes = self.node_count();

        // Three parallel columns cannot be sorted in place without a
        // permutation buffer, and the frozen signature takes no scratch, so one
        // `Vec` of rows is the smallest temporary that does it. Zipping to
        // `AoS`, sorting, and scattering back is also what keeps the three
        // columns provably in step: a permutation applied three times is three
        // chances to apply it differently.
        //
        // Decorate-sort-undecorate: the key is computed once per row here, in
        // one linear pass, rather than once per side of every comparison the
        // sort makes. The buffer widens from 32 bytes a row to 56; that is the
        // decoration's price, it is linear in `element_count()`, and the
        // re-derivation it removes was not.
        //
        // Surviving branch, read off the release asm at `-C
        // target-cpu=x86-64-v3`: every variant of `Parasitic` carries exactly
        // one `Qty` at the same offset, so LLVM hoists the payload load above
        // the match and leaves a four-way jump table that materialises nothing
        // but the kind tag. `to.map_or` is already a `cmovne`. The escape valve
        // is that it predicts: `analytical::extract_into` emits one resistance
        // and one ground capacitance per node, so the kind column is a period-2
        // pattern, which is the case a history-indexed indirect predictor gets
        // right. Removing it outright wants `#[repr(u8)]` on `Parasitic` so the
        // tag is the discriminant — a layout change to a frozen type, not a
        // body.
        // `element_count` above is the length check: it compares all three
        // element columns and is what makes `elements` a legal trip count for
        // indexing every one of them.
        debug_assert_eq!(self.from.len(), self.to.len(), "SoA columns must agree");
        debug_assert_eq!(self.from.len(), self.value.len(), "SoA columns must agree");
        let mut rows: Vec<KeyedRow> = Vec::with_capacity(elements);
        for i in 0..elements {
            let (from, to, value) = (self.from[i], self.to[i], self.value[i]);
            rows.push((canonical_key(from, to, value), from, to, value));
        }
        debug_assert_eq!(rows.len(), elements, "zipping the columns dropped a row");

        // Compared by reference, not by `sort_unstable_by_key`: the latter is
        // defined to call its extractor on every comparison, which would hand
        // back the 24-byte key copy the decoration exists to stop making.
        //
        // Unstable is safe *because* `canonical_key` is total: two rows with
        // equal keys are equal in every field, so their relative order is
        // unobservable and the sort stays a function of the rows alone.
        #[expect(
            clippy::unnecessary_sort_by,
            reason = "`sort_unstable_by_key(|r| r.0)` yields the identical total order — \
                      tuple `Ord` is the same lexicographic compare — but its extractor is \
                      called on every side of every comparison, so it copies the 32-byte \
                      `CanonicalKey` O(n log n) times. Not making that copy is the only \
                      reason the decoration above exists"
        )]
        rows.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        // The adjacent-pair scan as a fold carrying the previous key, the form
        // `analytical::extract_into` states its two order invariants in. `&=`
        // and not an early `break`: a data-dependent exit is the one branch
        // this scan could have, and running the full length costs one compare a
        // row. `(0, 0, 0, 0)` is the least `CanonicalKey` under lexicographic
        // tuple order, so seeding with it never fails a row the sort placed
        // correctly.
        #[cfg(debug_assertions)]
        {
            let mut previous = CanonicalKey::default();
            let mut ascending = true;
            for row in &rows {
                ascending &= previous <= row.0;
                previous = row.0;
            }
            debug_assert!(
                ascending,
                "the keyed rows must come out of the sort ascending"
            );
        }

        // Scattered back in one pass rather than three: the three columns are
        // written from the same row at the same index, so they cannot fall out
        // of step. `clear` keeps the capacity each column already had for
        // `elements` rows, so no push here reallocates.
        self.from.clear();
        self.to.clear();
        self.value.clear();
        self.from.reserve(rows.len());
        self.to.reserve(rows.len());
        self.value.reserve(rows.len());
        for &(_, from, to, value) in &rows {
            self.from.push(from);
            self.to.push(to);
            self.value.push(value);
        }

        debug_assert_eq!(
            self.element_count(),
            elements,
            "a sort neither invents nor drops a row"
        );
        // `sort_canonical` orders elements. The node columns, and with them the
        // node-order invariant in this type's doc comment, are not its business.
        debug_assert_eq!(self.node_count(), nodes, "a sort does not touch the nodes");
    }
}
