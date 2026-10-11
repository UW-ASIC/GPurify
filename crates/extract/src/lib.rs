//! Parasitic extraction: the resistance, capacitance and inductance a layout
//! adds to the circuit it draws.
//!
//! Two methods, both writing one [`ParasiticNetwork`]:
//!
//! - [`analytical`]: closed forms over every net of the design. Fast and
//!   coarse; this is what `gpurify pex` always runs.
//! - [`quasistatic`]: a field solve for the nets a caller names
//!   (`gpurify pex --quasistatic <net>`). Capacitance comes from a
//!   boundary-element solve ([`field`]), inductance and resistance from a
//!   partial-inductance solve ([`field::henry`]), and
//!   [`quasistatic::overlay`] puts the result over the analytical network.
//!
//! Data in: the layout ([`GeometryStore`](gpurify_geom::GeometryStore)), its
//! nets ([`NetTable`](gpurify_check::topology::NetTable)), and the deck's
//! `pex` lines ([`ProcessStack`](gpurify_ingest::deck::ProcessStack), one row
//! per layer id, see
//! [deck.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md#parasitic-stack)).
//! A row holds thickness and height above the substrate in nm, sheet
//! resistance in Ω/□ (Ω per cut on a via layer), relative permittivity, area
//! capacitance in aF/µm² and fringe capacitance in aF/µm. The output is in Ω,
//! fF and pH ([`Parasitic`]). The field solver works in SI units: metres,
//! farads, henries.
//!
//! A conductor layer that holds a net's shapes, or a via layer whose cuts
//! join two conductors, with no row stating a positive sheet resistance has
//! unknown parasitics, not zero ones: both methods refuse it
//! ([`analytical::AnalyticalError`], and the field solves' own errors).
//! Shapes on a global layer (the substrate) carry no parasitics and need no
//! row.
//!
//! # The closed forms
//!
//! From Weste & Harris, *CMOS VLSI Design* 4e (2011), ch. 6. They are applied
//! to conductor regions, not drawn polygons: a region is one piece of the union
//! of a net's shapes on one layer, its parts joined by edges, so a wire drawn
//! as abutting or overlapping polygons is one region with its outline's area
//! and perimeter (testing-plan F44). Two pieces that meet only at a corner are
//! two regions: a neck of zero width carries no current (F76). A layer whose
//! shapes are not valid rectilinear rings cannot be merged exactly and is
//! refused.
//!
//! | Element | Formula | Applied to |
//! |---|---|---|
//! | Wire resistance | `R = Rs · L / W` (sheet resistance × squares) | each region, as the rectangle with the same area and perimeter |
//! | Via resistance | `R = Rcut / n` | the `n` cuts joining one pair of regions, in parallel |
//! | Ground capacitance | `C = Ca · A + Cf · P` | each region: plate area to the substrate plus perimeter fringe |
//! | Lateral coupling | `C = ε₀ εr t · L / S` | facing sidewalls of two nets on one layer, within 10 thicknesses |
//! | Interlayer coupling | `C = ε₀ εr · A / d` | overlapping plates of two nets on two conductor layers |
//!
//! # The field solve
//!
//! [`field`] cuts each selected net's surface into flat rectangular panels,
//! each carrying a uniform charge, and puts one net at a time at 1 V with the
//! others at 0 V. It solves for the panel charges with restarted GMRES (Saad &
//! Schultz, 1986) and iterative refinement. This is the formulation of
//! `FastCap` (Nabors & White, 1991) without its multipole acceleration, so each
//! iteration costs a dense O(panels²) product. Each solve's charge per net is
//! one column of the Maxwell capacitance matrix ([`field::CapMatrix`]).
//! [`quasistatic::extract_into`] reports a net's row sum as its ground
//! capacitance and `−C_ij` as the coupling between nets `i` and `j`. The
//! engine refuses a matrix that is not symmetric to the solve's tolerance.
//!
//! [`field::henry`] merges each selected net's shapes per layer, as the
//! closed forms do, cuts them into rectangles, and makes each rectangle a
//! straight filament along its centre line; rectangles that share an edge
//! are joined through the middle of it, so a bend reads its centre line,
//! and each via cut joins the two layers it lands on.
//! It builds their partial-inductance matrix (Ruehli, 1972). Self
//! terms use Grover's closed form ([`field::filament::self_inductance_bar`]),
//! close parallel pairs the exact brick formula of Hoer & Love (1965), far
//! parallel pairs the centre-line closed form, and every other pair
//! Gauss–Legendre quadrature. The filament network is then solved at 1 MHz,
//! the way `FastHenry` does (Kamon, Tsuk & White, 1994), and each net's port
//! impedance gives its series `L = Im(Z)/ω` and `R = Re(Z)`.
//!
//! # The network
//!
//! A [`ParasiticNetwork`] is node columns (net and layer per [`network::NodeId`])
//! plus element columns (near node, far node or ground, value). Every net's
//! nodes form one contiguous run, in ascending net order. Elements are in
//! canonical order ([`ParasiticNetwork::sort_canonical`]): a total order, so
//! the network is a function of the inputs alone. Nothing iterates a hash map,
//! every float sum is a strict left fold in a fixed order, and the parallel
//! kernels reduce row by row, so a field solve gives the same bits on any
//! thread count.
//!
//! # Accuracy and known gaps
//!
//! What is known to be wrong or missing, so a number can be read for what it is:
//!
//! - **Analytical R** chains a net's regions in layer order, not along the
//!   current path. The net's total is the sum of its region resistances, but
//!   the node a resistor sits between is not the drawn topology: a comb's
//!   fingers come out in series, and a region that is not a constant-width
//!   path reads as the rectangle of its area and perimeter. Two regions that
//!   meet only at a corner are chained like any others, so the corner itself
//!   reads as no resistance where, a neck of zero width, it carries no
//!   current.
//! - **Analytical coupling** is parallel-plate between the regions'
//!   rectangles: no fringing field, so lateral coupling is a lower bound. No
//!   shielding either: a third shape or layer between two plates does not
//!   reduce their coupling, and a plate's ground capacitance ignores the
//!   plates beneath it.
//! - **No dielectric images**: the field solve images each panel in the
//!   substrate, a grounded plane at height 0, so a net's ground capacitance
//!   is to the substrate; but each panel pair sees the mean of their two
//!   permittivities and dielectric interfaces reflect nothing, so same-layer
//!   coupling is under-predicted by 14–159%. The panel edge is set by the
//!   stack's thicknesses and gaps, not by a layer's height, so a panel much
//!   wider than twice its height reads its own image coarsely.
//! - **Junctions are closed form**: a shape on a layer at height 0 (a well,
//!   a diffusion) sits in the substrate plane, and its capacitance to it is
//!   a depletion capacitance, so the field solve leaves it out and adds
//!   `Ca·A + Cf·P` from its `pex` row to its net's ground capacitance. The
//!   field then reads a junction as part of the grounded plane: metal over
//!   another selected net's diffusion couples to ground, not to that net,
//!   and metal over its own net's diffusion counts that field as ground
//!   capacitance too.
//! - **A coarse mesh reads low.** Each panel with itself and with its near
//!   neighbours is integrated over both rectangles (any aspect ratio); far
//!   pairs see each other centroid to centroid. Refining raises C
//!   monotonically toward the limit: a 1 µm cube reads 1.8% under its
//!   capacitance at 2 panels a side and 0.014% under at 32. The stack sets
//!   the panel edge, at which small wires read 0.2–1% low.
//! - **Only selected nets are in the field.** Coupling from a solved net to an
//!   unselected one is the analytical estimate, which `overlay` keeps.
//! - **Inductance** models each rectangle of a net's merged shapes as one
//!   filament, uniform across its width, so current crowding at a corner or
//!   a step in width is not modelled: a junction between two rectangles is a
//!   filament as wide as their shared edge. A via cut is one filament
//!   between the two centre lines it lands on, carrying the stack's
//!   resistance per cut. A net whose pieces do not join into one circuit
//!   (two pieces meeting only at a corner, or joined only through a global
//!   layer, which carries no modelled current) is refused
//!   (see [`field::henry::extract_inductance_into`]).
//!   Only each net's own port impedance is computed, so mutual inductance
//!   between nets never reaches the output. A single frequency (1 MHz) means
//!   there is no skin effect.
//!
//! # Catalog rows
//!
//! The [check catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv)
//! rows for parasitic extraction, and what covers each:
//!
//! | Row | Check | Status | Covered by |
//! |---|---|---|---|
//! | PEX-001 | Sheet R × squares, via R | implemented | [`analytical`] |
//! | PEX-002 | Area + fringe C to substrate | implemented | [`analytical`] |
//! | PEX-003 | Coupling C, same-layer and cross-layer | partial | [`analytical`]; [`quasistatic`] for selected nets, over the substrate plane but without dielectric images |
//! | PEX-004 | Partial self and mutual inductance | partial | [`field::henry`]: one series L per selected net |
//! | PEX-005 | Field-solver reference for selected nets | implemented | [`quasistatic`] |
//! | PEX-006 | Multi-corner extraction | missing | — |
//! | PEX-007 | Process effects (CMP thickness, temperature-dependent R, nonlinear via R) | out of scope | needs foundry models |
//! | PEX-008 | Reduction modes (C-only, RC, RCC, thresholds) | missing | one fixed output |
//! | PEX-009 | PEX netlist diff and qualification | missing | — |
//! | PEX-010 | SPEF output | implemented | `gpurify::export::parasitic::write_spef` |
//!
//! [limitations.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/limitations.md)
//! says what each partial row lacks.

pub mod analytical;
mod conductor;
pub mod field;
pub mod network;
pub mod quasistatic;

pub use network::{Parasitic, ParasiticNetwork};
