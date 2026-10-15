//! `gpurify compare <reference> <candidate> [--spec <compare.json>]`: two
//! parasitic netlists, SPEF or DSPF, from any two tools, compared net by net
//! with nets linked by name (PEX-009; [`gpurify_extract::foreign`] reads
//! them, [`gpurify_extract::compare`] measures them). The spec, JSON,
//! states the tolerance a qualification passes at, `{"tolerance": 5}` in
//! percent; without one it is 5 %.

use gpurify_extract::compare::{compare, Errors, Metric};
use gpurify_extract::foreign::{read_dspf, read_spef, Read};
use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

/// Rows whose reference and candidate are both under these are noise to a
/// qualification and not compared: 0.01 fF, 0.01 Ω, 0.01 fs.
const FLOOR: f64 = 0.01;

/// The compare spec: what a qualification passes at. An unknown key is an
/// error, so a misspelled one never leaves the default in force.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    /// Percent, zero or more: a row passes within this much of the
    /// reference.
    tolerance: f64,
}

/// The tolerance, percent, a spec file states.
fn tolerance(path: &str) -> Result<f64, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let spec: Spec = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
    Some(spec.tolerance)
        .filter(|t| t.is_finite() && *t >= 0.0)
        .ok_or_else(|| format!("{path}: tolerance {} is not a percentage", spec.tolerance))
}

/// Reads one netlist, its dialect told by its first line (`*SPEF` or
/// `*|DSPF`), else by its extension.
fn read(path: &Path) -> Result<Read, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let first = text.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let read = if first.starts_with("*SPEF")
        || (!first.starts_with("*|") && ext.eq_ignore_ascii_case("spef"))
    {
        read_spef(&text)
    } else if first.starts_with("*|DSPF") || ext.eq_ignore_ascii_case("dspf") {
        read_dspf(&text)
    } else {
        return Err(format!(
            "{}: neither SPEF (*SPEF) nor DSPF (*|DSPF)",
            path.display()
        ));
    };
    read.map_err(|e| format!("{}: {e}", path.display()))
}

/// Runs `compare` on its arguments (after the subcommand) and prints the
/// report; exits 0 when every metric's every compared row is within the
/// tolerance and both files hold the same nets.
pub(super) fn main(argv: &[String]) -> ExitCode {
    match run(argv) {
        Ok((text, passed)) => {
            print!("{text}");
            if passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(why) => {
            eprintln!("error: {why}");
            ExitCode::FAILURE
        }
    }
}

/// The report and whether it passes.
pub(super) fn run(argv: &[String]) -> Result<(String, bool), String> {
    let mut files = Vec::new();
    let mut spec = None;
    let mut args = argv.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--spec" => spec = Some(args.next().ok_or("--spec wants a value")?),
            "--tolerance" => {
                return Err("--tolerance is no longer an option: the compare spec's \
                            `tolerance` field (--spec <file>) says it now"
                    .into())
            }
            other if other.starts_with('-') => return Err(format!("unknown option {other}")),
            file => files.push(file),
        }
    }
    let [reference, candidate] = files[..] else {
        return Err("compare takes two parasitic netlists: compare <reference> <candidate>".into());
    };
    let tolerance = spec.map_or(Ok(5.0), |path| tolerance(path))?;
    let (a, b) = (read(Path::new(reference))?, read(Path::new(candidate))?);
    let mut names: Vec<String> = a.names.iter().chain(&b.names).cloned().collect();
    names.sort_unstable();
    names.dedup();
    let result = compare(&a.on_names(&names), &b.on_names(&names));

    let mut out = String::new();
    let _ = writeln!(out, "reference {reference}\ncandidate {candidate}");
    let both = names.len() - result.only_reference.len() - result.only_candidate.len();
    let _ = writeln!(
        out,
        "nets: {both} in both, {} in the reference only, {} in the candidate only",
        result.only_reference.len(),
        result.only_candidate.len()
    );
    for (side, nets) in [
        ("reference", &result.only_reference),
        ("candidate", &result.only_candidate),
    ] {
        for net in nets {
            let _ = writeln!(out, "  only in the {side}: {}", names[net.0 as usize]);
        }
    }
    let _ = writeln!(
        out,
        "tolerance {tolerance}%, rows under {FLOOR} in both not compared\n\
         metric            unit  rows  within  worst%      mean%     rms%      worst row"
    );
    let fraction = tolerance / 100.0;
    let mut passed = result.only_reference.is_empty() && result.only_candidate.is_empty();
    let net = |id: gpurify_check::topology::NetId| names[id.0 as usize].clone();
    let mut row = |label: &str, unit: &str, errors: Errors, at: Option<String>| {
        passed &= errors.within == errors.count;
        let _ = writeln!(
            out,
            "{label:<17} {unit:<5} {:>4}  {:>6}  {:>+9.3}  {:>8.3}  {:>8.3}  {}",
            errors.count,
            errors.within,
            100.0 * errors.worst,
            100.0 * errors.mean,
            100.0 * errors.rms,
            at.unwrap_or_else(|| "-".into())
        );
    };
    let per_net = |m: &Metric<gpurify_check::topology::NetId>| {
        let e = m.errors(fraction, FLOOR);
        (e, e.worst_row.map(|r| net(m.key[r])))
    };
    for (label, unit, metric) in [
        ("total_cap", "fF", &result.total_cap),
        ("ground_cap", "fF", &result.ground_cap),
        ("pin_to_pin_res", "ohm", &result.resistance),
        ("elmore_delay", "fs", &result.delay),
    ] {
        let (e, at) = per_net(metric);
        row(label, unit, e, at);
    }
    let e = result.coupling.errors(fraction, FLOOR);
    let at = e.worst_row.map(|r| {
        let (x, y) = result.coupling.key[r];
        format!("{}/{}", net(x), net(y))
    });
    row("coupling_cap", "fF", e, at);
    let _ = writeln!(out, "{}", if passed { "pass" } else { "fail" });
    Ok((out, passed))
}

#[cfg(test)]
mod tests {
    use super::run;

    /// Oracle: hand-derived: the candidate's ground cap on `b` is 10 %
    /// over the reference's (0.33 against 0.3 fF), so at the default 5 %
    /// one row of two fails and the run fails; at a spec's 20 % every row
    /// is within and it passes; a net in one file only fails it whatever
    /// the tolerance. The flag that used to say it is refused.
    #[test]
    fn a_ground_cap_ten_percent_off_fails_at_five_and_passes_at_twenty() {
        let dir = gpurify_testgen::oracle::scratch("compare");
        let spef = |b_cap: &str, extra: &str| {
            format!(
                "*SPEF \"IEEE 1481-2009\"\n*C_UNIT 1 FF\n*R_UNIT 1 OHM\n\n\
                 *D_NET a 1.0\n*CONN\n*P a I\n*CAP\n1 a:1 1.0\n*RES\n1 a a:1 10\n*END\n\n\
                 *D_NET b {b_cap}\n*CONN\n*P b I\n*CAP\n1 b:1 {b_cap}\n*RES\n1 b b:1 20\n*END\n{extra}"
            )
        };
        let write = |name: &str, text: String| {
            let path = dir.join(name);
            std::fs::write(&path, text).expect("writable");
            path.display().to_string()
        };
        let reference = write("r.spef", spef("0.3", ""));
        let candidate = write("c.spef", spef("0.33", ""));
        let extra = write(
            "x.spef",
            spef(
                "0.3",
                "\n*D_NET c 0.5\n*CONN\n*P c I\n*CAP\n1 c:1 0.5\n*END\n",
            ),
        );
        let args = |list: &[&str]| list.iter().map(ToString::to_string).collect::<Vec<_>>();
        let (text, passed) = run(&args(&[&reference, &candidate])).expect("runs");
        assert!(!passed, "{text}");
        let ground: Vec<&str> = text
            .lines()
            .find(|l| l.starts_with("ground_cap"))
            .expect("a ground row")
            .split_whitespace()
            .collect();
        assert_eq!(
            ground[..5],
            ["ground_cap", "fF", "2", "1", "+10.000"],
            "{text}"
        );
        let twenty = write("20.json", r#"{"tolerance": 20}"#.to_owned());
        let (_, passed) = run(&args(&[&reference, &candidate, "--spec", &twenty])).expect("runs");
        assert!(passed);
        let fifty = write("50.json", r#"{"tolerance": 50}"#.to_owned());
        let (text, passed) = run(&args(&[&reference, &extra, "--spec", &fifty])).expect("runs");
        assert!(
            !passed && text.contains("only in the candidate: c"),
            "{text}"
        );
        assert!(run(&args(&[&reference])).is_err());
        let typo = write("typo.json", r#"{"tolerence": 20}"#.to_owned());
        assert!(run(&args(&[&reference, &candidate, "--spec", &typo])).is_err());
        assert_eq!(
            run(&args(&[&reference, &candidate, "--tolerance", "20%"])).err(),
            Some(
                "--tolerance is no longer an option: the compare spec's `tolerance` field \
                 (--spec <file>) says it now"
                    .to_owned()
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
