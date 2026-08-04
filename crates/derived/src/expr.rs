//! The derived-layer expression tree and its evaluator.

use gpurify_core::boolean::{
    intersection_into, offset_into, subtraction_into, union_into, BooleanError,
};
use gpurify_core::view::validate_layer_into;
use gpurify_core::{GeometryStore, LayerId, ValidatedLayer};
use gpurify_ingest::StrId;
use gpurify_units::{Dbu, MAX_ABS_DBU};

/// A reference to either a base layer or a named derived layer.
///
/// Two variants rather than one id space, because resolving a name to a base
/// layer must fail loudly when the deck does not define it, and a derived name
/// must be resolvable to its expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerRef {
    Base(LayerId),
    Named(StrId),
}

/// A derived-layer expression.
///
/// A closed enum matched exhaustively, not a trait object: the operator set is
/// fixed by the deck schema, and adding one should break every match until it
/// is handled.
///
/// Boxed children, unusually for this tree — an expression is a handful of
/// nodes evaluated once per layer per run, not bulk data, so an arena would be
/// machinery for nothing.
#[derive(Debug, Clone, PartialEq)]
pub enum DerivedExpr {
    Layer(LayerRef),
    Union(Box<DerivedExpr>, Box<DerivedExpr>),
    Intersection(Box<DerivedExpr>, Box<DerivedExpr>),
    /// `lhs` minus `rhs`. Non-commutative; the only operator where swapping
    /// operands is a silent wrong answer.
    Subtraction(Box<DerivedExpr>, Box<DerivedExpr>),
    /// Grow (positive) or shrink (negative) by an exact L-infinity kernel.
    Offset(Box<DerivedExpr>, Dbu),
    /// The area of `operand` that lies inside `region`.
    ///
    /// Area, not whole shapes: a shape straddling the region boundary is cut,
    /// and only the part within `region` survives. The deck spells this
    /// operator, so it stays, but it is `Intersection` under another name and a
    /// body may evaluate it as one. Whole-shape selection is a different
    /// operator and this is not it — `core::boolean` exposes no primitive for
    /// one.
    Inside {
        operand: Box<DerivedExpr>,
        region: Box<DerivedExpr>,
    },
    /// The area of `operand` that lies inside `universe` and **not** inside
    /// `region`.
    ///
    /// Area, not whole shapes, the same cut [`DerivedExpr::Inside`] makes, so
    /// the two partition the operand exactly whenever `universe` contains it.
    ///
    /// Requires an explicit finite universe: "not inside" over an unbounded
    /// plane is not a set of polygons, and the old implementation's implicit
    /// universe was where several of its surprises lived.
    ///
    /// A universe that does not contain the operand truncates the result rather
    /// than raising an error. The universe is the extent the deck declared, and
    /// returning geometry from outside it would be an answer about area the
    /// deck never claimed. Documented here because an undocumented truncation
    /// is exactly the surprise the explicit universe was introduced to remove.
    Outside {
        operand: Box<DerivedExpr>,
        region: Box<DerivedExpr>,
        universe: Box<DerivedExpr>,
    },
}

/// Why a set of derived-layer definitions could not be ordered or evaluated.
///
/// The two naming variants carry a [`StrId`] rather than a `String`, because
/// [`Evaluator::plan`] is handed names and expressions and never a `StrTable`.
/// A name is a `u32` until a report reaches a human, and the caller holding the
/// table is what spells it.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DerivedError {
    #[error("derived layer {:?} is defined in terms of itself", .0)]
    Recursive(StrId),
    #[error("derived layer {:?} is referenced but not defined", .0)]
    Undefined(StrId),
    #[error("layer reference does not resolve to a layer in the deck")]
    UnknownLayer,
    #[error(transparent)]
    Boolean(#[from] gpurify_core::boolean::BooleanError),
    #[error(transparent)]
    Validity(#[from] gpurify_core::view::ValidityError),
}

/// Evaluates named derived layers once each and caches the results.
///
/// **Five questions.** In: the deck's named expressions and a store. Out: one
/// [`ValidatedLayer`] per name. How many: tens of derived layers per deck, each
/// referenced by many rules — which is exactly why the result is cached and not
/// recomputed. Lifetime: the whole run, built once after the layout is read.
/// Parallelisable: independent expressions are, but the dependency graph must
/// be honoured, so it is evaluated in topological order.
///
/// Recursion is detected during that ordering, not by a depth counter: a cycle
/// is a deck error to report, not a stack to blow.
#[derive(Debug, Default)]
pub struct Evaluator {
    /// Names in evaluation order: every definition sits after the definitions
    /// it references, so evaluation is one forward scan. Not sorted — a
    /// topological order and an ascending-`StrId` order coincide only by
    /// accident — which is what `lookup` is for.
    name: Vec<StrId>,
    expr: Vec<DerivedExpr>,
    /// Indices into `name`, ordered by the `StrId` each one points at, so
    /// [`get`](Evaluator::get) is a binary search here and an indexed read
    /// there. A second column rather than a second sort, because `name` has to
    /// stay in evaluation order. Tens of derived layers per deck, so `u32`.
    lookup: Vec<u32>,
    /// Evaluated results, parallel to `name`.
    ///
    /// Kept and refilled rather than dropped between calls, so a second
    /// `evaluate` reuses every buffer the first one grew.
    result: Vec<ValidatedLayer>,
    /// Operand buffers, indexed by depth in the expression rather than by node:
    /// a node takes the slots it needs off the front and hands the rest to its
    /// children, so the live count is the height of the tree and the siblings
    /// of a finished subtree get its slots back.
    ///
    /// Sized in [`evaluate`](Evaluator::evaluate) to the deepest definition the
    /// deck holds — [`scratch_slots`] counts it exactly — and kept afterwards,
    /// so a second `evaluate` allocates nothing and no node allocates at all.
    scratch: Vec<ValidatedLayer>,
}

impl Evaluator {
    /// Order the deck's named expressions and reject cycles.
    ///
    /// **Decision** — the ordering is pure and table-testable: a list of
    /// definitions in, either an order or the [`StrId`] of a cycle out.
    ///
    /// `names[i]` names `exprs[i]`, and the two are reordered together. Fills
    /// both orders: the evaluation order `evaluate` scans, and the sorted
    /// `lookup` column `get` binary-searches.
    pub fn plan(names: &[StrId], exprs: &[DerivedExpr]) -> Result<Self, DerivedError> {
        debug_assert_eq!(
            names.len(),
            exprs.len(),
            "a name column and an expression column arrive parallel"
        );
        let count = u32::try_from(names.len()).expect("a deck's derived layers fit a u32");

        // None of the loops below is a bulk loop: a deck names tens of derived
        // layers, and every loop here is a graph walk whose output index is
        // data-dependent, so none of them is a vector shape either.

        // The input order sorted by name, so a reference resolves to the
        // definition providing it while the evaluation order is still being
        // built.
        let mut by_name: Vec<u32> = (0..count).collect();
        by_name.sort_unstable_by_key(|&row| names[row as usize]);
        debug_assert!(
            by_name
                .windows(2)
                .all(|pair| names[pair[0] as usize] != names[pair[1] as usize]),
            "a deck names each derived layer once; two definitions under one name \
             leave `index_of` free to resolve a reference to either of them"
        );

        // Edges dependency -> dependent, and the count each definition is
        // waiting on. A reference no definition provides is refused here rather
        // than dropped: an unordered definition that evaluated to an empty layer
        // would read downstream as "nothing to check here".
        let mut waiting_on = vec![0u32; names.len()];
        let mut edges: Vec<(u32, u32)> = Vec::new();
        let mut referenced: Vec<StrId> = Vec::new();
        for (row, expr) in exprs.iter().enumerate() {
            referenced.clear();
            referenced_names(expr, &mut referenced);
            let dependent = u32::try_from(row).expect("a deck's derived layers fit a u32");
            for &name in &referenced {
                let dependency =
                    index_of(names, &by_name, name).ok_or(DerivedError::Undefined(name))?;
                edges.push((dependency, dependent));
                waiting_on[row] += 1;
            }
        }

        // CSR over the edges, so emitting a definition reaches its dependents in
        // one contiguous run instead of rescanning every edge.
        edges.sort_unstable();
        let dependents_start = csr_offsets(names.len(), &edges, |&(dependency, _)| dependency);

        // Kahn: a definition is emitted once nothing it references is still
        // waiting. An order rather than a depth counter, so a chain four
        // thousand definitions deep costs a queue and not the stack.
        let mut order: Vec<u32> = (0..count)
            .filter(|&row| waiting_on[row as usize] == 0)
            .collect();
        let mut head = 0usize;
        while head < order.len() {
            let ready = order[head] as usize;
            head += 1;
            let run = dependents_start[ready] as usize..dependents_start[ready + 1] as usize;
            for &(_, dependent) in &edges[run] {
                waiting_on[dependent as usize] -= 1;
                // Tens of definitions, so this is not a bulk loop and the branch
                // is not the kind `/branchless` triages. The taken side appends,
                // so the output index is data-dependent and the trip count is
                // not known until the walk finishes.
                if waiting_on[dependent as usize] == 0 {
                    order.push(dependent);
                }
            }
        }

        if order.len() != names.len() {
            // Fail closed, naming a definition that is on the cycle rather than
            // one merely downstream of it: the reported name is one a deck
            // author can actually break. `cycle_member` walks the second edge
            // index for it, built here because nothing on the accepting path
            // needs a dependent -> dependency direction.
            let member = cycle_member(&waiting_on, &edges);
            return Err(DerivedError::Recursive(names[member as usize]));
        }

        let name: Vec<StrId> = order.iter().map(|&row| names[row as usize]).collect();
        let expr: Vec<DerivedExpr> = order
            .iter()
            .map(|&row| exprs[row as usize].clone())
            .collect();
        let mut lookup: Vec<u32> = (0..count).collect();
        lookup.sort_unstable_by_key(|&row| name[row as usize]);

        debug_assert_eq!(name.len(), expr.len(), "the two columns stay parallel");
        debug_assert_eq!(lookup.len(), name.len(), "one lookup slot per definition");
        debug_assert!(
            lookup
                .windows(2)
                .all(|pair| name[pair[0] as usize] <= name[pair[1] as usize]),
            "the lookup column is what `get` binary-searches, so it is ascending by name"
        );
        Ok(Self {
            name,
            expr,
            lookup,
            ..Self::default()
        })
    }

    /// Evaluate every named layer against a store.
    ///
    /// **Transform.** Fills `self.result`, reusing the buffers a previous call
    /// grew rather than dropping them. Nothing below the entry allocates: the
    /// operand buffers every node writes come out of `self.scratch`, sized once
    /// here to the deepest definition in the deck.
    pub fn evaluate(&mut self, store: &gpurify_core::GeometryStore) -> Result<(), DerivedError> {
        debug_assert_eq!(
            self.name.len(),
            self.expr.len(),
            "`plan` left the two columns parallel"
        );
        let count = self.expr.len();

        // `resize_with` rather than `clear`: re-evaluating an evaluator that
        // already has results keeps every buffer it allocated, and each one is
        // cleared and refilled by the transform that writes it. This is the
        // "allocates once on first call" the doc comment above promises.
        if self.result.len() != count {
            self.result.resize_with(count, ValidatedLayer::default);
        }

        // One pool deep enough for every definition, never shrunk: a deck's
        // deepest expression is what sizes it, and a second `evaluate` finds it
        // already that deep with every buffer's capacity still on it.
        let deepest = self.expr.iter().map(scratch_slots).max().unwrap_or(0);
        if self.scratch.len() < deepest {
            self.scratch.resize_with(deepest, ValidatedLayer::default);
        }

        // Destructured, because a definition reads `result` behind it while
        // writing `result` ahead of it and takes `scratch` mutably at the same
        // time — three disjoint borrows the compiler will not take from `self`.
        let Self {
            name,
            expr,
            lookup,
            result,
            scratch,
        } = self;

        // Not a bulk loop — tens of derived layers per deck — and it returns on
        // the first deck error rather than accumulating, so the body carries an
        // early exit.
        for (row, node) in expr.iter().enumerate() {
            // The split is what lets a definition read the results of the
            // definitions `plan` placed before it while writing its own.
            let (evaluated, rest) = result.split_at_mut(row);
            let context = Context {
                store,
                names: &name[..],
                lookup: &lookup[..],
                evaluated,
            };
            eval(node, context, scratch, &mut rest[0])?;
        }

        debug_assert_eq!(
            self.result.len(),
            self.name.len(),
            "one result per named layer"
        );
        Ok(())
    }

    /// A previously evaluated named layer.
    ///
    /// The only way a rule reaches derived geometry, and deliberately the only
    /// way: everything a rule needs is a layer the deck named, so this borrows
    /// shared and every consumer can hold it at once. A rule needing an operand
    /// built from its own parameters — "shapes wider than W" — composes
    /// `core::boolean::*_into` into its own scratch instead. There is no
    /// evaluate-an-arbitrary-expression entry point, because one would need
    /// `&mut self` and would serialise every consumer behind this cache.
    pub fn get(&self, name: StrId) -> Option<&ValidatedLayer> {
        debug_assert_eq!(
            self.lookup.len(),
            self.name.len(),
            "one lookup slot per definition"
        );
        let row = index_of(&self.name, &self.lookup, name)?;
        // `get`, not an index: a name the deck defines has no result until
        // `evaluate` has run, and "not evaluated yet" is an absence like any
        // other rather than a panic.
        self.result.get(row as usize)
    }
}

/// What one expression node is evaluated against.
///
/// Four borrows threaded unchanged through every node, so they travel as one
/// parameter: the store the base layers live in, the name and lookup columns a
/// reference resolves through, and the definitions already evaluated by the
/// time this node is reached.
#[derive(Clone, Copy)]
struct Context<'a> {
    store: &'a GeometryStore,
    names: &'a [StrId],
    lookup: &'a [u32],
    evaluated: &'a [ValidatedLayer],
}

/// Evaluate one expression node into `out`.
///
/// **Transform, A-to-B.** Caller owns `out`, which every path below clears and
/// refills — including the bare-name path, so a definition that is only another
/// definition's name still owns its result rather than borrowing it.
///
/// `scratch` is the depth-indexed operand pool: this node takes the slots it
/// needs off the front and hands the remainder to its children, which is why
/// nothing here allocates. It is at least [`scratch_slots`] long for `expr`,
/// asserted on entry, and the split below panics rather than silently sharing a
/// buffer between two operands if it ever is not.
fn eval<'r>(
    expr: &DerivedExpr,
    context: Context<'r>,
    scratch: &'r mut [ValidatedLayer],
    out: &mut ValidatedLayer,
) -> Result<(), DerivedError> {
    debug_assert!(
        scratch.len() >= scratch_slots(expr),
        "the operand pool is shorter than this expression is deep"
    );
    match expr {
        DerivedExpr::Layer(LayerRef::Base(layer)) => {
            // Fail closed: a layer the store does not have is a typed error and
            // never an empty result. `polys_on_layer` would panic on it, which
            // is the same refusal spelled less usefully.
            if layer.idx() >= context.store.layer_count() {
                return Err(DerivedError::UnknownLayer);
            }
            validate_layer_into(context.store, *layer, out)?;
            Ok(())
        }
        DerivedExpr::Layer(LayerRef::Named(name)) => {
            let source = resolve(context, *name)?;
            // A union with nothing is the copy `ValidatedLayer` exposes no other
            // spelling of. Region-preserving, and it re-derives the same
            // canonical decomposition every other operator here produces.
            //
            // This is the one place a named reference is copied rather than
            // borrowed, and it is the top of a definition that is nothing but
            // another definition's name: the result belongs to this row's cache
            // slot, so it has to own its geometry. A named reference *inside* an
            // expression goes through [`operand`] and is borrowed.
            union_into(source, &ValidatedLayer::default(), out)?;
            Ok(())
        }
        DerivedExpr::Union(lhs, rhs) => combine(union_into, lhs, rhs, context, scratch, out),
        DerivedExpr::Intersection(lhs, rhs) => {
            combine(intersection_into, lhs, rhs, context, scratch, out)
        }
        DerivedExpr::Subtraction(lhs, rhs) => {
            combine(subtraction_into, lhs, rhs, context, scratch, out)
        }
        DerivedExpr::Offset(source, amount) => {
            debug_assert!(
                amount.raw().unsigned_abs() <= MAX_ABS_DBU.unsigned_abs(),
                "an offset is a coordinate distance and lives in the coordinate domain"
            );
            let (mine, rest) = scratch.split_at_mut(1);
            let grown = operand(source, context, rest, &mut mine[0])?;
            offset_into(grown, *amount, out)?;
            Ok(())
        }
        // `Inside` is `Intersection` under the name the deck spells, exactly as
        // the enum's doc comment permits: both keep the area of `operand` that
        // lies within the other operand and cut what straddles the edge.
        DerivedExpr::Inside { operand, region } => {
            combine(intersection_into, operand, region, context, scratch, out)
        }
        DerivedExpr::Outside {
            operand: subject,
            region,
            universe,
        } => {
            // `(operand and universe) minus region`. Clipping to the universe
            // first is what makes this the exact complement of `Inside` over the
            // extent the deck declared, and what truncates an operand reaching
            // outside it — the truncation the enum documents rather than errors
            // on.
            //
            // Two slots taken here, and the remainder handed to both the clip
            // and the region: the clip has finished with it by the time the
            // region starts, and neither result lives in it.
            let (mine, rest) = scratch.split_at_mut(2);
            let (clipped, excluded) = mine.split_at_mut(1);
            combine(
                intersection_into,
                subject,
                universe,
                context,
                rest,
                &mut clipped[0],
            )?;
            let removed = operand(region, context, rest, &mut excluded[0])?;
            subtraction_into(&clipped[0], removed, out)?;
            Ok(())
        }
    }
}

/// One operand of an operator, either borrowed or evaluated into `slot`.
///
/// **Transform, A-to-B**, with the A-is-already-a-B case taken as a borrow: a
/// named reference resolves to a layer the evaluator already holds, so it is
/// handed straight to the operator instead of being copied through a boolean.
/// Every other node is evaluated into the caller's `slot`, using `scratch` for
/// its own operands, and the borrow returned points there.
///
/// `slot` and `scratch` are separate parameters rather than one pool because
/// the returned borrow outlives the call while `scratch` does not: that is what
/// lets a binary node evaluate its second operand out of the same buffers the
/// first one just finished with.
fn operand<'r>(
    expr: &DerivedExpr,
    context: Context<'r>,
    scratch: &mut [ValidatedLayer],
    slot: &'r mut ValidatedLayer,
) -> Result<&'r ValidatedLayer, DerivedError> {
    match expr {
        DerivedExpr::Layer(LayerRef::Named(name)) => resolve(context, *name),
        node => {
            eval(node, context, scratch, slot)?;
            Ok(slot)
        }
    }
}

/// The already-evaluated layer a name refers to.
///
/// **Decision** — a name and the evaluator's columns in, a borrow of the result
/// out. `plan` put every dependency before the definition naming it, so the row
/// is filled by the time this is reached; refusing rather than indexing keeps a
/// broken order an error instead of a panic.
fn resolve(context: Context<'_>, name: StrId) -> Result<&ValidatedLayer, DerivedError> {
    let row =
        index_of(context.names, context.lookup, name).ok_or(DerivedError::Undefined(name))?;
    context
        .evaluated
        .get(row as usize)
        .ok_or(DerivedError::Undefined(name))
}

/// How many operand buffers evaluating an expression needs.
///
/// **Decision** — one expression in, the exact slot count [`eval`] will split
/// off it out. Counted rather than guessed, and counted against the splits in
/// `eval` itself: a binary node takes two, an `Offset` one, an `Outside` two
/// plus the two its inner clip takes, and every node's children share whatever
/// is left. So the answer is the *height* of the tree in slots, not the node
/// count — sibling subtrees hand the same buffers back and forth.
fn scratch_slots(expr: &DerivedExpr) -> usize {
    match expr {
        DerivedExpr::Layer(_) => 0,
        DerivedExpr::Union(lhs, rhs)
        | DerivedExpr::Intersection(lhs, rhs)
        | DerivedExpr::Subtraction(lhs, rhs) => 2 + scratch_slots(lhs).max(scratch_slots(rhs)),
        DerivedExpr::Offset(source, _) => 1 + scratch_slots(source),
        DerivedExpr::Inside { operand, region } => {
            2 + scratch_slots(operand).max(scratch_slots(region))
        }
        DerivedExpr::Outside {
            operand,
            region,
            universe,
        } => {
            let clip = 2 + scratch_slots(operand).max(scratch_slots(universe));
            2 + clip.max(scratch_slots(region))
        }
    }
}

/// Evaluate two operands and combine them with one of `core::boolean`'s three.
///
/// **Transform, A-to-B.** Two slots off the front of `scratch` hold whichever
/// operands have to be materialised; the remainder is handed to the left
/// operand and then, once that has returned, to the right one. Reusing it is
/// safe precisely because neither operand's result lives in it: each lives in
/// this node's own slot, or in the evaluator's results if it was a name.
fn combine<'r>(
    op: fn(&ValidatedLayer, &ValidatedLayer, &mut ValidatedLayer) -> Result<(), BooleanError>,
    lhs: &DerivedExpr,
    rhs: &DerivedExpr,
    context: Context<'r>,
    scratch: &'r mut [ValidatedLayer],
    out: &mut ValidatedLayer,
) -> Result<(), DerivedError> {
    let (mine, rest) = scratch.split_at_mut(2);
    let (left_slot, right_slot) = mine.split_at_mut(1);
    let left = operand(lhs, context, rest, &mut left_slot[0])?;
    let right = operand(rhs, context, rest, &mut right_slot[0])?;
    op(left, right, out)?;
    Ok(())
}

/// A definition that is genuinely on a cycle, from the residual state of an
/// ordering that stalled.
///
/// **Decision** — the undecremented in-degrees and the edge list in, the row of
/// a definition on a cycle out. Pure and table-testable.
///
/// The ordering emits a row exactly when its in-degree reaches zero, so a
/// non-zero one is the same statement as "never emitted", and a row is left
/// waiting only on dependencies that were never emitted either. A walk in the
/// dependent -> dependency direction therefore never leaves a finite set, so it
/// must arrive somewhere it has already been — and a row reachable from itself
/// along dependency edges is on a cycle rather than downstream of one. The
/// lowest waiting row starts the walk and the lowest waiting dependency steps
/// it, so the name reported is a function of the deck and not of the traversal.
///
/// The reverse index is built here rather than beside the forward one because
/// only this path reads it, and this path ends in a deck error.
fn cycle_member(waiting_on: &[u32], edges: &[(u32, u32)]) -> u32 {
    let rows = waiting_on.len();

    // CSR the other way round: dependent -> the dependencies it waits on.
    // `edges` is sorted, so each run comes out ascending by dependency.
    let deps_start = csr_offsets(rows, edges, |&(_, dependent)| dependent);
    let mut fill = deps_start.clone();
    let mut deps = vec![0u32; edges.len()];
    for &(dependency, dependent) in edges {
        deps[fill[dependent as usize] as usize] = dependency;
        fill[dependent as usize] += 1;
    }

    let mut walked = vec![false; rows];
    let mut row = waiting_on
        .iter()
        .position(|&waiting| waiting != 0)
        .expect("an ordering only stalls with a definition still waiting on one");
    while !walked[row] {
        walked[row] = true;
        let run = deps_start[row] as usize..deps_start[row + 1] as usize;
        row = deps[run]
            .iter()
            .copied()
            .find(|&dependency| waiting_on[dependency as usize] != 0)
            .expect("a waiting definition waits on a dependency that was never emitted")
            as usize;
    }

    debug_assert!(
        waiting_on[row] != 0,
        "the row walked back to was never emitted, so it is inside the stalled set"
    );
    debug_assert!(
        deps[deps_start[row] as usize..deps_start[row + 1] as usize]
            .iter()
            .any(|&dependency| waiting_on[dependency as usize] != 0),
        "a row on a cycle has a dependency on that same cycle"
    );
    u32::try_from(row).expect("a deck's derived layers fit a u32")
}

/// CSR offsets over one endpoint of the dependency edges.
///
/// **Decision** — a row count and an edge list in, the `rows + 1` offsets out.
/// The two walks want opposite directions: [`Evaluator::plan`] groups by
/// dependency to reach a definition's dependents, [`cycle_member`] groups by
/// dependent to walk back to a cycle. One counting pass spelled once, so the
/// coverage assertion cannot hold on one side and be forgotten on the other.
///
/// Not a bulk loop — a deck names tens of derived layers, and each references a
/// handful — and the counting pass is a scatter besides, so there is nothing
/// contiguous on the output side to widen.
fn csr_offsets(rows: usize, edges: &[(u32, u32)], group: fn(&(u32, u32)) -> u32) -> Vec<u32> {
    let mut start = vec![0u32; rows + 1];
    for edge in edges {
        start[group(edge) as usize + 1] += 1;
    }
    for row in 0..rows {
        start[row + 1] += start[row];
    }
    debug_assert_eq!(
        start[rows] as usize,
        edges.len(),
        "the offsets cover every edge"
    );
    start
}

/// Every derived name an expression references, at any depth and through every
/// operand every operator has.
///
/// **Decision** — one expression in, its dependency names appended to a
/// caller-owned buffer, so `plan` reuses one allocation across definitions.
/// Duplicates are kept: the in-degree they produce is matched by the edges they
/// produce, and deduplicating would leave a definition waiting forever.
fn referenced_names(expr: &DerivedExpr, out: &mut Vec<StrId>) {
    match expr {
        DerivedExpr::Layer(LayerRef::Named(name)) => out.push(*name),
        DerivedExpr::Layer(LayerRef::Base(_)) => {}
        DerivedExpr::Union(lhs, rhs)
        | DerivedExpr::Intersection(lhs, rhs)
        | DerivedExpr::Subtraction(lhs, rhs) => {
            referenced_names(lhs, out);
            referenced_names(rhs, out);
        }
        DerivedExpr::Offset(operand, _) => referenced_names(operand, out),
        DerivedExpr::Inside { operand, region } => {
            referenced_names(operand, out);
            referenced_names(region, out);
        }
        DerivedExpr::Outside {
            operand,
            region,
            universe,
        } => {
            referenced_names(operand, out);
            referenced_names(region, out);
            referenced_names(universe, out);
        }
    }
}

/// The row of `names` holding `name`, reached through a column of row indices
/// sorted by the name each one points at.
///
/// **Decision** — the one spelling of the lookup, so `get` and the evaluator's
/// name resolution cannot drift apart.
fn index_of(names: &[StrId], sorted: &[u32], name: StrId) -> Option<u32> {
    debug_assert_eq!(sorted.len(), names.len(), "one sorted slot per name");
    let slot = sorted
        .binary_search_by_key(&name, |&row| names[row as usize])
        .ok()?;
    Some(sorted[slot])
}

#[cfg(test)]
mod tests {
    //! The evaluation order `plan` produces, asserted where it is visible.
    //!
    //! `Evaluator` hands results out by name, never by position, so the order
    //! is on the private side of the interface and `tests/plan.rs` can only see
    //! whether a deck was accepted. That is the acceptance half. The ordering
    //! half is here, for the same reason the prefilter's adapter tests are unit
    //! tests: the property is real, is the point of the function, and is not
    //! observable from outside.

    use super::{DerivedError, DerivedExpr, Evaluator, LayerRef};
    use gpurify_core::LayerId;
    use gpurify_ingest::StrId;

    /// One definition, built so its identity survives into the stored
    /// expression: the base layer on the left spine is a tag, and the named
    /// references hang off it. Every definition has the same shape, so
    /// [`tag_of`] reads the tag back whatever the dependencies are.
    fn definition(tag: u16, dependencies: &[StrId]) -> DerivedExpr {
        let mut expr = DerivedExpr::Layer(LayerRef::Base(LayerId(tag)));
        for &dependency in dependencies {
            expr = DerivedExpr::Union(
                Box::new(expr),
                Box::new(DerivedExpr::Layer(LayerRef::Named(dependency))),
            );
        }
        expr
    }

    /// The tag [`definition`] wrote into an expression.
    fn tag_of(expr: &DerivedExpr) -> u16 {
        match expr {
            DerivedExpr::Layer(LayerRef::Base(LayerId(tag))) => *tag,
            DerivedExpr::Union(lhs, _) => tag_of(lhs),
            other => panic!("not an expression `definition` built: {other:?}"),
        }
    }

    /// Every derived name an expression references, at any depth and through
    /// every operand an operator has. Written out rather than asked of the
    /// crate, because asking the crate would make the test agree with whatever
    /// the crate does.
    fn dependencies_of(expr: &DerivedExpr, out: &mut Vec<StrId>) {
        match expr {
            DerivedExpr::Layer(LayerRef::Named(name)) => out.push(*name),
            DerivedExpr::Layer(LayerRef::Base(_)) => {}
            DerivedExpr::Union(lhs, rhs)
            | DerivedExpr::Intersection(lhs, rhs)
            | DerivedExpr::Subtraction(lhs, rhs) => {
                dependencies_of(lhs, out);
                dependencies_of(rhs, out);
            }
            DerivedExpr::Offset(operand, _) => dependencies_of(operand, out),
            DerivedExpr::Inside { operand, region } => {
                dependencies_of(operand, out);
                dependencies_of(region, out);
            }
            DerivedExpr::Outside {
                operand,
                region,
                universe,
            } => {
                dependencies_of(operand, out);
                dependencies_of(region, out);
                dependencies_of(universe, out);
            }
        }
    }

    /// A diamond whose only valid evaluation order is the exact reverse of both
    /// the order the definitions are written in and the numeric order of their
    /// names.
    ///
    /// `root` needs `left` and `right`, both of which need `leaf`. So `leaf`
    /// must come first and `root` last, while the input lists them
    /// `root, left, right, leaf` with ascending [`StrId`]. An implementation
    /// that preserved input order, or that sorted the names so `get` could
    /// binary-search them, produces a forward scan that evaluates `root`
    /// against results that do not exist yet.
    fn diamond() -> (Vec<StrId>, Vec<DerivedExpr>) {
        let (root, left, right, leaf) = (StrId(10), StrId(20), StrId(30), StrId(40));
        (
            vec![root, left, right, leaf],
            vec![
                definition(10, &[left, right]),
                definition(20, &[leaf]),
                definition(30, &[leaf]),
                definition(40, &[]),
            ],
        )
    }

    /// Oracle: law. A topological order is *defined* by one property — every
    /// dependency sits at a smaller index than the definition naming it — and
    /// that property holds for any legal order of any DAG. So it is checkable
    /// without asserting the particular permutation `plan` happens to pick,
    /// which would be a test of a choice rather than of a requirement.
    #[test]
    fn every_dependency_is_ordered_before_the_definition_that_names_it() {
        let (names, exprs) = diamond();
        let planned = Evaluator::plan(&names, &exprs).expect("a diamond is a DAG");

        let position = |name: StrId| {
            planned
                .name
                .iter()
                .position(|&ordered| ordered == name)
                .unwrap_or_else(|| panic!("{name:?} is missing from the evaluation order"))
        };

        let mut referenced = Vec::new();
        for (name, expr) in names.iter().zip(&exprs) {
            referenced.clear();
            dependencies_of(expr, &mut referenced);
            for &dependency in &referenced {
                assert!(
                    position(dependency) < position(*name),
                    "{dependency:?} is evaluated at index {} but {name:?} needs it at index {}",
                    position(dependency),
                    position(*name)
                );
            }
        }
    }

    /// Oracle: law. Ordering is a permutation, so it neither invents a
    /// definition nor loses one. Without this a `plan` that dropped the
    /// definitions it could not place would satisfy the ordering law above by
    /// emitting nothing at all.
    #[test]
    fn ordering_the_definitions_neither_adds_nor_drops_one() {
        let (names, exprs) = diamond();
        let planned = Evaluator::plan(&names, &exprs).expect("a diamond is a DAG");

        let mut ordered = planned.name.clone();
        ordered.sort_unstable();
        let mut given = names.clone();
        given.sort_unstable();
        assert_eq!(
            ordered, given,
            "the evaluation order is not a permutation of the names it was given"
        );
    }

    /// Oracle: law. Reordering moves names and expressions together or it moves
    /// them apart, and moving them apart is a silent wrong answer rather than
    /// an error: every name still resolves, every expression still evaluates,
    /// and every result belongs to a different layer than it claims. The tag on
    /// each definition is what makes that visible.
    #[test]
    fn reordering_keeps_each_expression_paired_with_its_own_name() {
        let (names, exprs) = diamond();
        let planned = Evaluator::plan(&names, &exprs).expect("a diamond is a DAG");

        assert_eq!(
            planned.name.len(),
            planned.expr.len(),
            "the name and expression columns must stay parallel"
        );
        for (index, name) in planned.name.iter().enumerate() {
            let original = names
                .iter()
                .position(|given| given == name)
                .expect("the order holds only names it was given");
            assert_eq!(
                tag_of(&planned.expr[index]),
                tag_of(&exprs[original]),
                "row {index} pairs {name:?} with another definition's expression"
            );
        }
    }

    /// Oracle: construct-from-answer. The cycle is written into the input, so
    /// the set of names on it is known before `plan` runs: `left` and `right`
    /// need each other, and `victim` needs `left` but is on no cycle at all.
    /// Breaking `victim` changes nothing, so reporting it sends a deck author
    /// to the wrong line.
    ///
    /// Here rather than in `tests/plan.rs` because the suite's cycle tests
    /// match `Recursive(_)` and this is a claim about the name inside it.
    #[test]
    fn the_reported_cycle_is_a_name_on_the_cycle_and_not_one_downstream_of_it() {
        let (victim, left, right) = (StrId(10), StrId(20), StrId(30));
        let names = vec![victim, left, right];
        let exprs = vec![
            definition(10, &[left]),
            definition(20, &[right]),
            definition(30, &[left]),
        ];

        let error = Evaluator::plan(&names, &exprs).expect_err("left and right need each other");
        let DerivedError::Recursive(reported) = error else {
            panic!("a mutual dependency is a cycle, got {error:?}");
        };
        assert!(
            reported == left || reported == right,
            "{reported:?} is not on the cycle; only {left:?} and {right:?} are, and \
             {victim:?} merely names one of them"
        );
    }
}
