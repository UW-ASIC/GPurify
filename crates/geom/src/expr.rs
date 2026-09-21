//! The derived-layer expression tree and its evaluator.

use crate::boolean::{intersection_into, offset_into, subtraction_into, union_into, BooleanError};
use crate::view::validate_layer_into;
use crate::StrId;
use crate::{Dbu, MAX_ABS_DBU};
use crate::{GeometryStore, LayerId, ValidatedLayer};

/// A reference to either a base layer or a named derived layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerRef {
    Base(LayerId),
    Named(StrId),
}

/// A derived-layer expression.
#[derive(Debug, Clone, PartialEq)]
pub enum DerivedExpr {
    Layer(LayerRef),
    Union(Box<DerivedExpr>, Box<DerivedExpr>),
    Intersection(Box<DerivedExpr>, Box<DerivedExpr>),
    /// `lhs` minus `rhs`. Non-commutative: swapping the operands is silently
    /// wrong rather than an error.
    Subtraction(Box<DerivedExpr>, Box<DerivedExpr>),
    /// Grow (positive) or shrink (negative) by an exact L-infinity kernel.
    Offset(Box<DerivedExpr>, Dbu),
    /// The area of `operand` inside `region` — area, not whole shapes, so a
    /// shape straddling the boundary is cut.
    Inside {
        operand: Box<DerivedExpr>,
        region: Box<DerivedExpr>,
    },
    /// The area of `operand` inside `universe` and **not** inside `region`.
    ///
    /// The universe must be explicit and finite; one that does not contain the
    /// operand truncates the result rather than erroring, since area outside
    /// the extent the deck declared was never claimed.
    Outside {
        operand: Box<DerivedExpr>,
        region: Box<DerivedExpr>,
        universe: Box<DerivedExpr>,
    },
}

/// Why a set of derived-layer definitions could not be ordered or evaluated.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DerivedError {
    #[error("derived layer {:?} is defined in terms of itself", .0)]
    Recursive(StrId),
    #[error("derived layer {:?} is referenced but not defined", .0)]
    Undefined(StrId),
    #[error("layer reference does not resolve to a layer in the deck")]
    UnknownLayer,
    #[error(transparent)]
    Boolean(#[from] crate::boolean::BooleanError),
    #[error(transparent)]
    Validity(#[from] crate::view::ValidityError),
}

/// Evaluates named derived layers once each and caches the results.
#[derive(Debug, Default)]
pub struct Evaluator {
    /// Names in evaluation order: every definition sits after the ones it
    /// references, so evaluation is one forward scan. Not sorted by name.
    name: Vec<StrId>,
    expr: Vec<DerivedExpr>,
    /// Indices into `name` sorted by the `StrId` each points at, which is what
    /// [`get`](Evaluator::get) binary-searches.
    lookup: Vec<u32>,
    /// Evaluated results, parallel to `name`.
    result: Vec<ValidatedLayer>,
    /// Operand buffers indexed by depth in the expression, not by node, so the
    /// live count is the height of the tree.
    scratch: Vec<ValidatedLayer>,
}

impl Evaluator {
    /// Order the deck's named expressions and reject cycles. `names[i]` names
    /// `exprs[i]`, and the two are reordered together.
    pub fn plan(names: &[StrId], exprs: &[DerivedExpr]) -> Result<Self, DerivedError> {
        debug_assert_eq!(
            names.len(),
            exprs.len(),
            "a name column and an expression column arrive parallel"
        );
        let count = u32::try_from(names.len()).expect("a deck's derived layers fit a u32");

        // The input order sorted by name, so a reference resolves while the
        // evaluation order is still being built.
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
        // waiting on. A reference no definition provides is refused rather than
        // dropped: an empty layer reads downstream as "nothing to check here".
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

        // `csr_offsets` requires the sort.
        edges.sort_unstable();
        let dependents_start = csr_offsets(names.len(), &edges, |&(dependency, _)| dependency);

        // Kahn, iterative: a deep chain cannot blow the stack.
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
                if waiting_on[dependent as usize] == 0 {
                    order.push(dependent);
                }
            }
        }

        if order.len() != names.len() {
            // Fail closed, naming a definition on the cycle rather than one
            // merely downstream: the reported name is one a deck author can
            // break.
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
    pub fn evaluate(&mut self, store: &crate::GeometryStore) -> Result<(), DerivedError> {
        debug_assert_eq!(
            self.name.len(),
            self.expr.len(),
            "`plan` left the two columns parallel"
        );
        let count = self.expr.len();

        if self.result.len() != count {
            self.result.resize_with(count, ValidatedLayer::default);
        }

        // One pool deep enough for every definition, so no node allocates.
        let deepest = self.expr.iter().map(scratch_slots).max().unwrap_or(0);
        if self.scratch.len() < deepest {
            self.scratch.resize_with(deepest, ValidatedLayer::default);
        }

        // Destructured: reading `result` behind the cursor while writing ahead
        // of it and holding `scratch` is three borrows `self` will not give.
        let Self {
            name,
            expr,
            lookup,
            result,
            scratch,
        } = self;

        for (row, node) in expr.iter().enumerate() {
            // The split lets a definition read the results before it.
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
    pub fn get(&self, name: StrId) -> Option<&ValidatedLayer> {
        debug_assert_eq!(
            self.lookup.len(),
            self.name.len(),
            "one lookup slot per definition"
        );
        let row = index_of(&self.name, &self.lookup, name)?;
        // A defined name has no result until `evaluate` has run.
        self.result.get(row as usize)
    }
}

/// What one expression node is evaluated against.
#[derive(Clone, Copy)]
struct Context<'a> {
    store: &'a GeometryStore,
    names: &'a [StrId],
    lookup: &'a [u32],
    evaluated: &'a [ValidatedLayer],
}

/// Evaluate one expression node into `out`.
///
/// `scratch` must be at least [`scratch_slots`] long for `expr`: a node splits
/// the slots it needs off the front and hands the remainder to its children.
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
            // never an empty result.
            if layer.idx() >= context.store.layer_count() {
                return Err(DerivedError::UnknownLayer);
            }
            validate_layer_into(context.store, *layer, out)?;
            Ok(())
        }
        DerivedExpr::Layer(LayerRef::Named(name)) => {
            let source = resolve(context, *name)?;
            // A union with nothing is the copy `ValidatedLayer` exposes no
            // other spelling of; this row's cache slot has to own its geometry.
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
        // `Inside` is `Intersection` under the name the deck spells: both keep
        // the area within the other operand and cut what straddles the edge.
        DerivedExpr::Inside { operand, region } => {
            combine(intersection_into, operand, region, context, scratch, out)
        }
        DerivedExpr::Outside {
            operand: subject,
            region,
            universe,
        } => {
            // `(operand and universe) minus region`. Clipping to the universe
            // first is what makes this the exact complement of `Inside` over
            // the extent the deck declared.
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
/// `slot` and `scratch` are separate parameters because the returned borrow
/// outlives the call while `scratch` does not.
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

/// The already-evaluated layer a name refers to, refused rather than indexed so
/// a broken evaluation order is an error and not a panic.
fn resolve(context: Context<'_>, name: StrId) -> Result<&ValidatedLayer, DerivedError> {
    let row = index_of(context.names, context.lookup, name).ok_or(DerivedError::Undefined(name))?;
    context
        .evaluated
        .get(row as usize)
        .ok_or(DerivedError::Undefined(name))
}

/// How many operand buffers evaluating an expression needs: the *height* of the
/// tree in slots, not the node count, since sibling subtrees share buffers.
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
/// The remainder of `scratch` is handed to both operands in turn; that is safe
/// only because neither operand's result lives in it.
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
/// A non-zero in-degree means "never emitted", and such a row waits only on
/// rows that were never emitted either, so walking dependent -> dependency must
/// revisit a row — which is on the cycle rather than downstream of it. Start and
/// step both take the lowest waiting row, so the name is a function of the deck.
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

/// CSR offsets over one endpoint of the dependency edges: `rows + 1` of them.
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

/// Every derived name an expression references, at any depth, appended to `out`.
///
/// Duplicates are kept: each one is matched by an edge, and deduplicating would
/// leave a definition waiting forever.
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

/// The row of `names` holding `name`, via a column of indices sorted by name.
fn index_of(names: &[StrId], sorted: &[u32], name: StrId) -> Option<u32> {
    debug_assert_eq!(sorted.len(), names.len(), "one sorted slot per name");
    let slot = sorted
        .binary_search_by_key(&name, |&row| names[row as usize])
        .ok()?;
    Some(sorted[slot])
}

#[cfg(test)]
mod tests {
    //! The evaluation order `plan` produces, which is not observable outside.

    use super::{DerivedError, DerivedExpr, Evaluator, LayerRef};
    use crate::LayerId;
    use crate::StrId;

    /// One definition, tagged by the base layer on its left spine.
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

    /// Every derived name an expression references, written out rather than
    /// asked of the crate under test.
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

    /// A diamond whose only valid order reverses both the input order and the
    /// numeric order of the names.
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

    /// Every dependency sits at a smaller index than the definition naming it,
    /// for any legal order of any DAG.
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

    /// Ordering is a permutation — a `plan` emitting nothing satisfies the
    /// ordering law above.
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

    /// Moving names and expressions apart is silently wrong rather than an
    /// error — everything still resolves, under the wrong layer.
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

    /// `left` and `right` need each other; `victim` names `left` but is on no
    /// cycle.
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
