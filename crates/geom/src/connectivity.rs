//! Connected components over an edge list: union-find by rank with path halving.

/// The component a node belongs to: always the minimum node index in it, which
/// makes the labelling canonical regardless of edge order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ComponentLabel(pub u32);

/// Label every node with its component; `out` is cleared and refilled to
/// `node_count` rows. An edge naming a node `>= node_count` panics.
pub fn components_into(node_count: u32, edges: &[(u32, u32)], out: &mut Vec<ComponentLabel>) {
    let n = node_count as usize;
    // `rank` is a tree height, bounded by 64 under path halving.
    let mut parent: Vec<u32> = (0..node_count).collect();
    let mut rank: Vec<u8> = vec![0; n];

    for &(a, b) in edges {
        let ra = find(&mut parent, a);
        let rb = find(&mut parent, b);
        let joined = ra != rb;

        // Branchless union by rank; when `ra == rb` the store is a no-op and
        // `joined` suppresses the rank bump.
        let smaller = rank[ra as usize] < rank[rb as usize];
        let tie = rank[ra as usize] == rank[rb as usize];
        let mask = u32::from(smaller).wrapping_neg();
        let hi = (ra & !mask) | (rb & mask);
        let lo = (ra & mask) | (rb & !mask);
        parent[lo as usize] = hi;
        rank[hi as usize] += u8::from(tie & joined);
    }

    out.clear();
    out.reserve(n);

    // Ascending: the first node of a component reached is its minimum.
    let mut label: Vec<u32> = vec![u32::MAX; n];
    for i in 0..node_count {
        let root = find(&mut parent, i) as usize;
        label[root] = label[root].min(i);
        out.push(ComponentLabel(label[root]));
    }
}

/// Root of `node`, halving the path on the way.
fn find(parent: &mut [u32], node: u32) -> u32 {
    let mut x = node;
    while parent[x as usize] != x {
        let grand = parent[parent[x as usize] as usize];
        parent[x as usize] = grand;
        x = grand;
    }
    x
}
