//! Capacity limits for index construction and queries.

#[derive(Clone, Debug)]
pub struct HierarchyIndexOptions {
    pub max_depth: usize,
    pub max_expanded_visits_per_query: usize,
    pub max_array_instances: usize,
}

impl Default for HierarchyIndexOptions {
    fn default() -> Self {
        Self {
            max_depth: 1_024,
            max_expanded_visits_per_query: 10_000_000,
            max_array_instances: 10_000_000,
        }
    }
}
