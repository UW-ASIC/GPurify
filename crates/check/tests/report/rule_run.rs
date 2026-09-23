//! What "clean" is allowed to mean: an empty violation table comes from a rule
//! that ran, one that was skipped and one that refused alike; only the
//! [`RuleRun`] record tells them apart.

use gpurify_check::report::{Outcome, RuleRun, SkipReason, Violations};
use gpurify_ingest::StrId;
use gpurify_testgen::{assert_clean, assert_rule_ran};

const RULE: StrId = StrId(31);
const OTHER_RULE: StrId = StrId(32);

/// A rule that executed, looked at shapes, and found nothing.
fn ran_clean() -> RuleRun {
    RuleRun {
        rule: RULE,
        outcome: Outcome::Ran,
        examined: 4_096,
        violations: 0,
    }
}

/// Oracle: construct-from-answer. Four rules that found nothing for four
/// different reasons produce one indistinguishable violation table between
/// them, and four distinct run records. Both halves are asserted, because the
/// pair is the argument: if the tables differed the record would be redundant,
/// and if the records did not the ambiguity would survive.
///
/// The second half runs each record through the clean assertion against the
/// same empty table, so the claim is made against code rather than against the
/// derive: with the outcome as the only difference between the four, exactly
/// one of them may be judged clean.
#[test]
fn an_empty_violation_table_is_the_same_for_a_rule_that_ran_and_one_that_did_not() {
    let runs: Vec<RuleRun> = [
        Outcome::Ran,
        Outcome::Skipped(SkipReason::EmptyLayer),
        Outcome::Skipped(SkipReason::NoDesignIntent),
        Outcome::Refused,
    ]
    .into_iter()
    .map(|outcome| RuleRun {
        outcome,
        ..ran_clean()
    })
    .collect();

    for (i, left) in runs.iter().enumerate() {
        for right in &runs[i + 1..] {
            assert_ne!(left, right, "two outcomes share one run record");
        }
    }

    // The four differ in nothing but the outcome, and every one of them
    // contributed the same empty table. So the outcome is the whole of what
    // separates a clean result from the three that are not, and the clean
    // assertion has to read it: the first is accepted and the other three are
    // refused against a table none of them can be distinguished by.
    for (index, run) in runs.into_iter().enumerate() {
        let verdict =
            std::panic::catch_unwind(move || assert_clean(&[run], &Violations::default(), RULE));
        assert_eq!(
            verdict.is_ok(),
            index == 0,
            "{run:?} against an empty violation table was judged the wrong way"
        );
    }
}

/// Oracle: construct-from-answer. The clean assertion accepts exactly one of
/// the four records above, and the three it rejects are the three the old suite
/// accepted. Each rejection is checked, because a helper that cannot fail is
/// the defect being fixed rather than the fix.
#[test]
fn a_clean_assertion_accepts_only_a_rule_that_ran_and_examined_shapes() {
    assert_clean(&[ran_clean()], &Violations::default(), RULE);

    let rejected = [
        RuleRun {
            examined: 0,
            ..ran_clean()
        },
        RuleRun {
            outcome: Outcome::Skipped(SkipReason::EmptyLayer),
            ..ran_clean()
        },
        RuleRun {
            outcome: Outcome::Skipped(SkipReason::NoDesignIntent),
            ..ran_clean()
        },
        RuleRun {
            outcome: Outcome::Refused,
            ..ran_clean()
        },
        RuleRun {
            violations: 1,
            ..ran_clean()
        },
    ];
    for run in rejected {
        let verdict = std::panic::catch_unwind(move || {
            assert_clean(&[run], &Violations::default(), RULE);
        });
        assert!(
            verdict.is_err(),
            "{run:?} was accepted as clean against an empty violation table"
        );
    }
}

/// Oracle: construct-from-answer. A rule with no record at all is the exact
/// shape of "the dispatcher never reached it", and it is indistinguishable from
/// a clean run by the violation table alone. It must be rejected, and so must a
/// record that names a different rule.
#[test]
fn a_rule_with_no_run_record_is_not_clean() {
    let no_records = std::panic::catch_unwind(|| {
        assert_clean(&[], &Violations::default(), RULE);
    });
    assert!(
        no_records.is_err(),
        "a rule the dispatcher never reached was accepted as clean"
    );

    let wrong_rule = std::panic::catch_unwind(|| {
        assert_clean(&[ran_clean()], &Violations::default(), OTHER_RULE);
    });
    assert!(
        wrong_rule.is_err(),
        "another rule's run record was accepted as evidence for this one"
    );
}

/// Oracle: construct-from-answer. One rule, one row. Two records for the same
/// rule means a rule ran twice or two rules share an id, and either way no
/// assertion about that rule can be attributed — so the helper refuses rather
/// than picking the first.
#[test]
fn a_rule_recorded_twice_cannot_be_asserted_on() {
    let duplicated = std::panic::catch_unwind(|| {
        let _ = assert_rule_ran(&[ran_clean(), ran_clean()], RULE);
    });
    assert!(
        duplicated.is_err(),
        "two run records for one rule were accepted as one"
    );

    // One record among several rules is fine, and is the ordinary case.
    let among_others = assert_rule_ran(
        &[
            RuleRun {
                rule: OTHER_RULE,
                ..ran_clean()
            },
            ran_clean(),
        ],
        RULE,
    );
    assert_eq!(among_others, ran_clean());
}
