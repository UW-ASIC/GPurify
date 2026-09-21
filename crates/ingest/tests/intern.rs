//! Interning: the laws `StrTable` and `PathTable` owe their callers.
//!
//! Both tables are lookup structures, so almost nothing about them has a closed
//! form. What they do have is a handful of properties that must hold for every
//! input, which is what the tests here are written against: idempotence,
//! `resolve` inverting `intern`, and a reverse lookup that finds a name however
//! the table was filled.

use gpurify_ingest::intern::{StrId, StrTable};
use gpurify_ingest::provenance::PathTable;
use gpurify_testgen::Rng;

/// Distinct names, seeded. The index prefix guarantees distinctness; the random
/// suffix is what stops the corpus being sorted on arrival, which would let a
/// broken sorted index pass.
fn distinct_names(count: usize, seed: u64) -> Vec<String> {
    let mut rng = Rng::new(seed);
    (0..count)
        .map(|i| format!("n{i}_{:x}", rng.next_u64()))
        .collect()
}

/// Oracle: law. Interning is idempotent and `resolve` inverts it — the two
/// properties `crate::intern`'s doc comment states outright. They hold for
/// every name, so arbitrary generated names are the right input rather than a
/// handful of chosen ones.
#[test]
fn interning_a_name_twice_gives_one_id_and_resolve_inverts_it() {
    let names = distinct_names(64, 7);
    let mut table = StrTable::default();

    let first: Vec<StrId> = names.iter().map(|n| table.intern(n)).collect();
    let second: Vec<StrId> = names.iter().map(|n| table.intern(n)).collect();

    assert_eq!(
        first, second,
        "interning a name a second time issued a different id"
    );
    assert_eq!(
        table.len(),
        names.len(),
        "the table grew on the second pass, so a duplicate was stored twice"
    );
    for (name, &id) in names.iter().zip(&first) {
        assert_eq!(
            table.resolve(id),
            name.as_str(),
            "{id:?} resolved to the wrong name"
        );
    }
}

/// Oracle: law. Two ids issued by one table are equal exactly when the names
/// were. That is the whole justification for comparing names as `u32`
/// downstream, and it is not implied by idempotence alone: a table that handed
/// out one id for everything would satisfy idempotence and fail this.
#[test]
fn distinct_names_get_distinct_ids() {
    let names = distinct_names(128, 13);
    let mut table = StrTable::default();
    let mut ids: Vec<u32> = names.iter().map(|n| table.intern(n).0).collect();
    let issued = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        ids.len(),
        issued,
        "two different names collided onto one id"
    );
}

/// Oracle: law. `get` finds every name that was interned, whatever order they
/// arrived in, and refuses every name that was not. The first half is the only
/// externally visible statement that the sorted index really is sorted: a
/// binary search over an index left in arrival order misses most of its
/// lookups. The second half is the fail-closed half — a consumer that must not
/// grow the table gets `None`, not a fresh id.
#[test]
fn get_finds_every_interned_name_in_any_arrival_order_and_refuses_the_rest() {
    let mut names = distinct_names(96, 21);
    Rng::new(4).shuffle(&mut names);

    let mut table = StrTable::default();
    for name in &names {
        table.intern(name);
    }

    let before = table.len();
    for name in &names {
        let found = table
            .get(name)
            .unwrap_or_else(|| panic!("{name} was interned but the reverse lookup missed it"));
        assert_eq!(table.resolve(found), name.as_str());
    }
    assert!(
        table.get("a name that was never interned").is_none(),
        "an unknown name resolved to an id, so a lookup can invent an entry"
    );
    assert_eq!(
        table.len(),
        before,
        "a `get` grew the table, which is exactly what it exists not to do"
    );
}

/// Oracle: law. The id a name receives depends on the order names arrived in,
/// but the *set* of ids does not, and neither does what any of them resolve to.
/// A table whose reverse lookup depended on arrival order would fail the second
/// assertion here while passing every single-order test.
#[test]
fn two_interning_orders_give_the_same_set_of_ids_and_the_same_names_back() {
    let names = distinct_names(48, 3);
    let mut shuffled: Vec<&String> = names.iter().collect();
    Rng::new(9).shuffle(&mut shuffled);

    let mut forward = StrTable::default();
    let mut forward_ids: Vec<u32> = names.iter().map(|n| forward.intern(n).0).collect();

    let mut reverse = StrTable::default();
    for name in &shuffled {
        reverse.intern(name);
    }
    let mut reverse_ids: Vec<u32> = names
        .iter()
        .map(|n| {
            reverse
                .get(n)
                .unwrap_or_else(|| panic!("{n} was interned into the second table but not found"))
                .0
        })
        .collect();

    forward_ids.sort_unstable();
    reverse_ids.sort_unstable();
    assert_eq!(
        forward_ids, reverse_ids,
        "the same set of names produced two different sets of ids"
    );
    assert_eq!(forward.len(), reverse.len());
    for name in &names {
        let id = reverse.get(name).expect("interned above");
        assert_eq!(reverse.resolve(id), name.as_str());
    }
}

/// Oracle: law. Capacity is not content. A table built with room for a thousand
/// names holds none of them, and behaves identically to a default one — which
/// is what stops `with_capacity` pre-filling the span column and shifting every
/// id by the reservation.
#[test]
fn with_capacity_reserves_space_without_interning_anything() {
    let mut reserved = StrTable::with_capacity(1024, 16_384);
    assert!(reserved.is_empty(), "a reserved table already held names");
    assert_eq!(reserved.len(), 0);

    let mut plain = StrTable::default();
    assert_eq!(reserved.intern("vdd"), plain.intern("vdd"));
    assert_eq!(reserved.intern("vss"), plain.intern("vss"));
    assert_eq!(reserved.len(), plain.len());
    assert!(!reserved.is_empty());
}

/// Oracle: construct-from-answer. `PathTable::ROOT` is documented as always
/// being id 0, which is a claim about the *first* id the table hands out: a
/// non-empty path interned into a fresh table must not take it. Every polygon
/// that came from no instance carries this id, so an implementation that let
/// the first real path land on zero would file all of them under a cell.
#[test]
fn the_root_path_is_reserved_for_the_empty_path() {
    let mut strings = StrTable::default();
    let cell = strings.intern("sram_bit");
    let mut paths = PathTable::default();

    let first = paths.intern(&[cell]);
    assert_ne!(
        first,
        PathTable::ROOT,
        "a non-empty path was issued the id reserved for the root"
    );
    assert_eq!(
        paths.intern(&[]),
        PathTable::ROOT,
        "the empty path is not id 0"
    );
    assert!(
        paths.get(PathTable::ROOT).is_empty(),
        "the root path has components"
    );
    assert_eq!(paths.get(first), [cell]);
}

/// Oracle: law. Paths are deduplicated — the reason they are referenced by id
/// at all — and `get` returns the components root first, in the order they were
/// interned. Reversing them would name the cell an instance sits in rather than
/// the instance itself, which reads plausibly in a report and is wrong.
#[test]
fn interning_a_path_twice_gives_one_id_and_preserves_component_order() {
    let mut strings = StrTable::default();
    let top = strings.intern("top");
    let bank = strings.intern("bank0");
    let bit = strings.intern("bit7");
    let mut paths = PathTable::default();

    let deep = paths.intern(&[top, bank, bit]);
    let shallow = paths.intern(&[top, bank]);
    assert_ne!(
        deep, shallow,
        "a prefix was deduplicated onto its extension"
    );
    assert_eq!(
        paths.intern(&[top, bank, bit]),
        deep,
        "the same path interned twice produced two ids"
    );
    assert_eq!(paths.get(deep), [top, bank, bit]);
    assert_eq!(paths.get(shallow), [top, bank]);
}
