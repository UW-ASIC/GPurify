//! Property runs: seeds derived from a name, committed regression seeds
//! replayed, and a failing input shrunk before it is reported.
//!
//! A property names itself, generates its input from a seeded [`Rng`], and
//! states what must hold. [`check`] runs it over [`seeds`] (fast, for the merge
//! gate) or many more (an `#[ignore]`d nightly twin), plus every seed in its
//! regression file, so a seed that once failed is replayed on every run. A
//! failure is shrunk to the smallest input that still fails, then reported
//! with its seed.
//!
//! There are no environment knobs: the count is the caller's argument, and a
//! seed to replay is a line in a file.

use crate::Rng;
use std::fmt::Debug;
use std::path::Path;

/// `count` seeds for the property `name`: the same seeds on every run, and
/// different properties get different seeds.
pub fn seeds(name: &str, count: u32) -> impl Iterator<Item = u64> {
    // FNV-1a of the name, so seeds depend on the property and nothing else.
    let base = name.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    (0..u64::from(count)).map(move |index| base.wrapping_add(index))
}

/// The seeds in a regression file: one decimal seed per line, `#` comments and
/// blank lines ignored. A missing file is no seeds.
///
/// # Panics
///
/// When the file exists but cannot be read, or a line is not a `u64`: a
/// regression that silently stops replaying is worse than a failing test.
pub fn regression_seeds(file: &Path) -> Vec<u64> {
    let Ok(text) = std::fs::read_to_string(file) else {
        assert!(!file.exists(), "{}: unreadable", file.display());
        return Vec::new();
    };
    text.lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.parse()
                .unwrap_or_else(|_| panic!("{}: {line:?} is not a seed", file.display()))
        })
        .collect()
}

/// Runs `property` on the input `generate` makes from each seed.
///
/// On the first failure the input is shrunk: `shrink` proposes smaller
/// candidates, and any candidate that still fails replaces the input, until
/// none does. The panic names the property, the seed, the shrunk input and
/// both failure messages, and says to add the seed to the regression file.
///
/// # Panics
///
/// When `property` fails for some seed: that is the test failing.
pub fn check<T: Debug>(
    name: &str,
    seeds: impl IntoIterator<Item = u64>,
    generate: impl Fn(&mut Rng) -> T,
    shrink: impl Fn(&T) -> Vec<T>,
    property: impl Fn(&T) -> Result<(), String>,
) {
    for seed in seeds {
        let input = generate(&mut Rng::new(seed));
        let Err(first) = property(&input) else {
            continue;
        };
        let (smallest, last) = shrunk(input, first.clone(), &shrink, &property);
        panic!(
            "{name}: seed {seed} fails: {first}\n  shrunk to {smallest:?}\n  which fails: \
             {last}\n  add {seed} to the property's regression seeds to replay it on every run"
        );
    }
}

/// The smallest failing input reachable by repeatedly taking a failing
/// candidate, and its failure message.
fn shrunk<T>(
    mut input: T,
    mut failure: String,
    shrink: &impl Fn(&T) -> Vec<T>,
    property: &impl Fn(&T) -> Result<(), String>,
) -> (T, String) {
    // Bounded: every accepted candidate is strictly smaller, by the shrinker's
    // contract, and the round count is capped for a shrinker that breaks it.
    for _ in 0..10_000 {
        let next = shrink(&input)
            .into_iter()
            .find_map(|candidate| property(&candidate).err().map(|why| (candidate, why)));
        match next {
            Some((smaller, why)) => {
                input = smaller;
                failure = why;
            }
            None => break,
        }
    }
    (input, failure)
}

/// Smaller versions of a layout of labelled rectangles `(layer, [xlo, ylo,
/// xhi, yhi])`: each with one rectangle dropped, then each with one rectangle
/// halved toward its lower-left corner, then each with one rectangle moved
/// halfway toward the origin. Every candidate is strictly smaller in rectangle
/// count, area or coordinate magnitude, so shrinking ends.
pub fn shrink_rects<L: Clone>(rects: &[(L, [i64; 4])]) -> Vec<Vec<(L, [i64; 4])>> {
    let mut out = Vec::new();
    for skip in 0..rects.len() {
        let mut fewer = rects.to_vec();
        fewer.remove(skip);
        out.push(fewer);
    }
    for (index, (layer, [xlo, ylo, xhi, yhi])) in rects.iter().enumerate() {
        let (w, h) = (xhi - xlo, yhi - ylo);
        if w > 1 || h > 1 {
            let mut halved = rects.to_vec();
            halved[index] = (
                layer.clone(),
                [*xlo, *ylo, xlo + (w / 2).max(1), ylo + (h / 2).max(1)],
            );
            out.push(halved);
        }
        let (dx, dy) = (xlo / 2, ylo / 2);
        if dx != 0 || dy != 0 {
            let mut moved = rects.to_vec();
            moved[index] = (layer.clone(), [xlo - dx, ylo - dy, xhi - dx, yhi - dy]);
            out.push(moved);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{check, seeds, shrink_rects};

    /// Oracle: a property that fails for any layout with a rectangle wider
    /// than 10 shrinks to one rectangle, of the smallest failing width.
    #[test]
    fn a_failure_shrinks_to_its_smallest_cause() {
        let result = std::panic::catch_unwind(|| {
            check(
                "wide",
                [7],
                |_| vec![(0u8, [0, 0, 5, 5]), (1, [100, 100, 180, 140])],
                |rects| shrink_rects(rects),
                |rects| {
                    if rects.iter().any(|(_, [xlo, _, xhi, _])| xhi - xlo > 10) {
                        Err("too wide".to_owned())
                    } else {
                        Ok(())
                    }
                },
            );
        });
        let message = *result
            .expect_err("the property fails")
            .downcast::<String>()
            .expect("a formatted panic");
        assert!(message.contains("seed 7"), "{message}");
        // One rectangle left, 11 wide (the first width over 10 that halving and
        // moving can reach is any width in 11..=20; the shrinker stops there).
        assert!(message.contains("shrunk to [(1, ["), "{message}");
    }

    /// The same name gives the same seeds; different names, different seeds.
    ///
    /// Oracle: law. `seeds` is documented as a function of the name: one name
    /// gives one stream, two names two, of the length asked for.
    #[test]
    fn seeds_depend_on_the_name_alone() {
        let a: Vec<u64> = seeds("a", 3).collect();
        assert_eq!(a, seeds("a", 3).collect::<Vec<_>>());
        assert_ne!(a, seeds("b", 3).collect::<Vec<_>>());
        assert_eq!(a.len(), 3);
    }
}
