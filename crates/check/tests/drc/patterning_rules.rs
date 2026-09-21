//! Multi-patterning: `color_into`, and the rule built on it.
//!
//! This is the only rule in the crate that can give up, and that is what the
//! tests here are about. Three outcomes exist because three things can happen —
//! a colouring was found, none exists, or the search ran out of budget — and
//! collapsing the third into either of the other two is the defect the module
//! was written to avoid. A checker reporting "colourable" after giving up is
//! worse than one reporting nothing.

use crate::common;

use common::{Env, Sink, A, RULE};
use gpurify_check::drc::rules::patterning::{
    check_multi_patterning, color_into, Coloring, MultiPatterningTable,
};
use gpurify_check::report::Severity;
use gpurify_testgen::{
    assert_clean, assert_rule_ran, dbu, layout_with_violation, Amount, Rng, ShapeKind,
    ViolationCase, ViolationShape,
};

// -------------------------------------------------------------- color_into

/// A graph that is `colours`-colourable by construction: every node is dealt a
/// colour up front and an edge is drawn only between nodes of different
/// colours, so the dealt assignment is a proper colouring and the search must
/// find one.
///
/// The edge set is a random subset rather than the complete multipartite graph,
/// so the instance is not the trivial one, and it is seeded so the corpus is the
/// same on every machine.
fn colourable_graph(seed: u64, node_count: u32, colours: u8) -> (Vec<u8>, Vec<(u32, u32)>) {
    let mut rng = Rng::new(seed);
    let assignment: Vec<u8> = (0..node_count)
        .map(|node| u8::try_from(node % u32::from(colours)).expect("colours is a u8"))
        .collect();

    let mut edges = Vec::new();
    for a in 0..node_count {
        for b in (a + 1)..node_count {
            if assignment[a as usize] != assignment[b as usize] && rng.unit() < 0.2 {
                edges.push((a, b));
            }
        }
    }
    rng.shuffle(&mut edges);
    (assignment, edges)
}

/// Assert a colouring is proper and within its palette.
fn assert_proper(colours: &[u8], edges: &[(u32, u32)], palette: u8) {
    for (node, &colour) in colours.iter().enumerate() {
        assert!(
            colour < palette,
            "node {node} was given colour {colour}, outside a palette of {palette}"
        );
    }
    for &(a, b) in edges {
        assert_ne!(
            colours[a as usize], colours[b as usize],
            "conflicting nodes {a} and {b} were given the same mask"
        );
    }
}

/// Oracle: construct-from-answer. The graph was built *from* a colouring, so one
/// exists and the search must return `Complete` with a full assignment. What is
/// asserted is not that it found the same colouring — any proper one is correct —
/// but that what came back is proper and within the palette, which is the whole
/// claim `Complete` makes.
#[test]
fn a_graph_built_from_a_colouring_is_coloured_completely_and_properly() {
    for (seed, nodes, palette) in [(1u64, 30u32, 3u8), (2, 48, 2), (3, 60, 4)] {
        let (_assignment, edges) = colourable_graph(seed, nodes, palette);
        let mut colours = Vec::new();
        let result = color_into(nodes, &edges, palette, &mut colours);

        assert_eq!(
            result,
            Coloring::Complete,
            "seed {seed}: a graph drawn from a {palette}-colouring must be {palette}-colourable"
        );
        assert_eq!(colours.len(), nodes as usize);
        assert_proper(&colours, &edges, palette);
    }
}

/// Oracle: construct-from-answer. A triangle needs three masks and cannot be
/// split across two, whatever search order is used — so this is *proved*
/// uncolourable rather than merely unsolved, and the buffer is left empty
/// because a partial colouring is not a result anyone can use.
#[test]
fn an_odd_cycle_is_proved_infeasible_and_leaves_no_partial_colouring_behind() {
    let triangle = [(0u32, 1u32), (1, 2), (0, 2)];

    // Pre-filled, so "left empty otherwise" is checked rather than assumed.
    let mut colours = vec![7, 7, 7];
    let result = color_into(3, &triangle, 2, &mut colours);

    assert!(
        matches!(result, Coloring::Infeasible { .. }),
        "a triangle over two masks is uncolourable, not merely unsearched: {result:?}"
    );
    assert!(
        colours.is_empty(),
        "a partial colouring left in the buffer invites a caller to read it"
    );

    // One more mask and the same graph is fine, which is what makes the
    // rejection above about the graph rather than about the search.
    let mut with_three = Vec::new();
    assert_eq!(
        color_into(3, &triangle, 3, &mut with_three),
        Coloring::Complete
    );
    assert_proper(&with_three, &triangle, 3);
}

/// Oracle: determinism. The reported node is specified as a function of the
/// graph, not of the path the search took through it, so two calls on the same
/// graph name the same node. A search reporting wherever it happened to stop
/// would pass the test above and fail this one.
#[test]
fn the_node_an_infeasible_graph_names_is_the_same_on_every_run() {
    let five_cycle = [(0u32, 1u32), (1, 2), (2, 3), (3, 4), (4, 0)];
    let mut first_out = Vec::new();
    let mut second_out = Vec::new();
    let first = color_into(5, &five_cycle, 2, &mut first_out);
    let second = color_into(5, &five_cycle, 2, &mut second_out);

    assert!(matches!(first, Coloring::Infeasible { .. }));
    assert_eq!(
        first, second,
        "the node named by an infeasible verdict is a function of the graph"
    );
}

/// Oracle: law. A graph containing a four-clique cannot be split across three
/// masks — four mutually conflicting shapes need four — so whatever the search
/// does with the three hundred nodes around it, the one answer it may never give
/// is `Complete`. Whether it proves infeasibility or exhausts its budget is a
/// question about the budget; that it never claims a colouring exists is the
/// property the layout depends on, and it holds either way.
///
/// The buffer must come back empty in both non-`Complete` cases, which is what
/// stops a caller reading a colouring out of a verdict that has none.
#[test]
fn a_graph_with_a_four_clique_is_never_reported_three_colourable() {
    let (_assignment, mut edges) = colourable_graph(11, 300, 3);
    // Nodes 0, 1, 2 already have three different dealt colours, so the clique is
    // completed by joining them to one another and to a fourth node.
    for clique in [(0u32, 1u32), (0, 2), (1, 2), (0, 3), (1, 3), (2, 3)] {
        edges.push(clique);
    }
    Rng::new(12).shuffle(&mut edges);

    let mut colours = vec![9; 300];
    let result = color_into(300, &edges, 3, &mut colours);

    assert_ne!(
        result,
        Coloring::Complete,
        "a four-clique admits no three-colouring, so no colouring may be claimed"
    );
    assert!(colours.is_empty());
}

// --------------------------------------------------- check_multi_patterning

/// Three squares, pairwise in conflict at a colour spacing of 71.
///
/// The two axis-aligned pairs are 50 apart; the diagonal pair is 50 apart on
/// both axes, so its exact separation is the square root of 5000 — under 71 and
/// over 70. That single unit of prune radius is what turns an L of three shapes
/// into an odd cycle, and narrowing it below the rule's own spacing is the
/// fail-open move this table's doc warns about.
fn odd_cycle_case() -> ViolationCase {
    layout_with_violation(
        ViolationShape {
            rule: RULE,
            severity: Severity::Error,
            kind: ShapeKind::OddCycle {
                layer: A,
                size: 100,
                gap: 50,
            },
        },
        (0, 0),
        Amount::Count(3),
        Amount::Count(2),
    )
}

fn patterning_table(colors: u8, color_spacing: i64) -> MultiPatterningTable {
    let mut table = MultiPatterningTable::default();
    table.rule.push(RULE);
    table.layer.push(A);
    table.colors.push(colors);
    table.color_spacing.push(dbu(color_spacing));
    table
}

/// Oracle: construct-from-answer. Three mutually conflicting shapes need three
/// masks and the process has two, so the layer cannot be manufactured. One
/// violation, not three: the defect is the cycle, and naming every member of a
/// thousand-shape component buries the fix.
///
/// The measurement and the point within the named shape are deliberately not
/// asserted. `check_multi_patterning` says a violation sits "at the shape named
/// by `Coloring::Infeasible`" and says nothing about which quantity it reports
/// or where on that shape it points, so an expected value for either would be
/// this test inventing a convention rather than reading one — the gap is
/// recorded in `docs/NEED_TESTING.md`. What *is* stated, and is asserted, is
/// that there is one row, that it names one shape rather than a conflicting
/// pair, and that the shape it names is one of the three in the cycle.
#[test]
fn an_uncolourable_layer_is_one_violation_naming_the_shape_that_could_not_be_placed() {
    let case = odd_cycle_case();
    let env = Env::default();
    let mut sink = Sink::default();

    check_multi_patterning(
        env.design(&case.store),
        &patterning_table(2, 71),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_eq!(
        sink.out.rule.len(),
        1,
        "the defect is the cycle, not each of its members"
    );
    assert_eq!(sink.out.rule[0], RULE);
    assert_eq!(sink.out.layer[0], A);
    assert_eq!(sink.out.severity[0], Severity::Error);
    assert_eq!(
        sink.out.shape_b[0], None,
        "an uncolourable layer names the one shape that could not be placed, not a pair"
    );

    let at = sink.out.at[0];
    let squares = [(-50, -50, 50, 50), (100, -50, 200, 50), (-50, 100, 50, 200)];
    assert!(
        squares.iter().any(|&(xlo, ylo, xhi, yhi)| at.x >= dbu(xlo)
            && at.x <= dbu(xhi)
            && at.y >= dbu(ylo)
            && at.y <= dbu(yhi)),
        "the violation is marked at {at:?}, which is on none of the three \
         conflicting shapes"
    );

    let run = assert_rule_ran(&sink.runs, RULE);
    assert_eq!(
        run.examined,
        u64::from(case.shapes),
        "examined counts shapes on the layer"
    );
    assert_eq!(run.violations, 1);
}

/// Oracle: construct-from-answer. The same three shapes with a third mask
/// available are colourable, and the rule says so having looked at all three.
#[test]
fn the_same_layer_with_a_third_mask_available_is_clean() {
    let case = odd_cycle_case();
    let env = Env::default();
    let mut sink = Sink::default();

    check_multi_patterning(
        env.design(&case.store),
        &patterning_table(3, 71),
        &mut sink.scratch,
        &mut sink.out,
        &mut sink.runs,
    );

    assert_clean(&sink.runs, &sink.out, RULE);
    assert_eq!(
        assert_rule_ran(&sink.runs, RULE).examined,
        u64::from(case.shapes)
    );
}

/// Oracle: construct-from-answer, and the boundary that decides the verdict. At
/// a colour spacing of 70 the diagonal pair is out of conflict — its separation
/// squared is 5000 and 70 squared is 4900 — so the conflict graph is a path and
/// two masks suffice. At 71 it is a triangle and they do not. One unit of prune
/// radius, two opposite verdicts, and the direction that loses the edge is the
/// one that makes an unmanufacturable layer look fine.
#[test]
fn one_unit_of_colour_spacing_separates_a_path_from_an_odd_cycle() {
    let case = odd_cycle_case();
    let env = Env::default();

    let mut inside = Sink::default();
    check_multi_patterning(
        env.design(&case.store),
        &patterning_table(2, 71),
        &mut inside.scratch,
        &mut inside.out,
        &mut inside.runs,
    );
    assert_eq!(inside.out.rule.len(), 1);

    let mut outside = Sink::default();
    check_multi_patterning(
        env.design(&case.store),
        &patterning_table(2, 70),
        &mut outside.scratch,
        &mut outside.out,
        &mut outside.runs,
    );
    assert_clean(&outside.runs, &outside.out, RULE);
    assert_eq!(
        assert_rule_ran(&outside.runs, RULE).examined,
        u64::from(case.shapes)
    );
}
