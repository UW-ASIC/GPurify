//! The foundry-deck cross-check (testing-plan L6, ledger F2): each shipped
//! deck in `pdks/` against the foundry's own `KLayout` deck, on the foundry's
//! own test structures and standard cells.
//!
//! Oracle, per rule of the deck's ledger (`docs/xcheck/<deck>.tsv`):
//! - a foundry test structure says what it is: a fail structure must be
//!   flagged by the rule and a pass structure must not (gf180mcu draws its
//!   pass and fail boxes on 2/222 and 3/222, IHP its PASS and FAIL halves);
//!   sky130 ships no such structures, so its `test_violators.gds` is held
//!   to what the foundry deck finds there;
//! - a standard cell from the foundry's library is clean under every rule.
//!
//! Both `GPurify`, with the shipped deck, and the foundry's `KLayout` deck are
//! held to that, region by region. A ledger row marked `agrees` must hold
//! everywhere it was compared; `differs` must show its difference, which
//! its note explains. Every rule of the deck and every check the foundry
//! deck reported must have a row, so neither side gains a rule unledgered.
//!
//! The inputs are the repositories `pdks.tsv` pins, checked out under
//! `~/.cache/gpurify/foundry/<name>-<commit>` (the `oracles` job in
//! `.github/workflows/nightly.yml` fetches them); a missing one fails the
//! test. Run in the oracle shell:
//! `nix develop .#oracles --command cargo test --test foundry -- --ignored --test-threads=1`.

use gpurify::check::report::{Outcome, Violations};
use gpurify::engine::pipeline::{load, Inputs};
use gpurify::geom::Grid;
use gpurify_ingest::deck::parse_deck;
use gpurify_ingest::StrTable;
use gpurify_testgen::oracle;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The `KLayout` helper: reads structures, sheets cells, reads reports.
const HELPER: &str = include_str!("xcheck.rb");
/// The pinned foundry repositories: name, URL, commit, sparse-checkout paths.
const PINS: &str = include_str!("pdks.tsv");
/// One foundry deck run on one layout; the largest sheet takes minutes.
const LIMIT: Duration = Duration::from_secs(3600);

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The checkout of pinned repository `name`.
///
/// # Panics
///
/// When it is not there: a comparison that did not run must not pass.
fn checkout(name: &str) -> PathBuf {
    let row = PINS
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split('\t').collect::<Vec<_>>())
        .find(|f| f[0] == name)
        .unwrap_or_else(|| panic!("tests/foundry/pdks.tsv pins no {name}"));
    let home = std::env::var_os("HOME").expect("HOME is set");
    let dir = Path::new(&home)
        .join(".cache/gpurify/foundry")
        .join(format!("{name}-{}", row[2]));
    assert!(
        dir.is_dir(),
        "{} is missing: check out {} at {} with the sparse paths `{}` of \
         tests/foundry/pdks.tsv, as the `oracles` job of .github/workflows/nightly.yml does",
        dir.display(),
        row[1],
        row[2],
        row[3]
    );
    dir
}

/// A file inside a checkout, which must exist.
fn need(dir: &Path, rel: &str) -> PathBuf {
    let path = dir.join(rel);
    assert!(
        path.exists(),
        "the foundry checkout lacks {}",
        path.display()
    );
    path
}

/// Every file under `dir` with extension `ext`, sorted.
fn files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap_or_else(|e| panic!("{}: {e}", d.display())) {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == ext) {
                out.push(path);
            }
        }
    }
    out.sort();
    assert!(!out.is_empty(), "no .{ext} file under {}", dir.display());
    out
}

/// One foundry `KLayout` deck run: the script and its `-rd` switches; the
/// harness adds `input` (the layout) and `report`, which every deck reads.
#[derive(Clone)]
struct Run {
    script: PathBuf,
    switches: Vec<(String, String)>,
}

/// One layout both tools check.
struct Layout {
    /// For messages: the file the structures came from, or the library.
    name: String,
    /// The layout, or (`cells`) the sheet the helper writes.
    gds: PathBuf,
    /// How the helper finds its structures (`gf`, `ihp`, `pass`, `fail`,
    /// `whole`), or `cells` for a sheet of standard cells.
    style: &'static str,
    /// The structure's rule, for the `pass` and `fail` styles.
    label: String,
    /// The standard-cell GDS files, for `cells`.
    cells: Vec<PathBuf>,
    runs: Vec<Run>,
}

/// A rectangle in database units, closed.
#[derive(Clone, Copy, Debug)]
struct Rect([i64; 4]);

impl Rect {
    fn touches(&self, o: &Rect) -> bool {
        self.0[0] <= o.0[2] && o.0[0] <= self.0[2] && self.0[1] <= o.0[3] && o.0[1] <= self.0[3]
    }
    fn holds(&self, (x, y): (i64, i64)) -> bool {
        self.0[0] <= x && x <= self.0[2] && self.0[1] <= y && y <= self.0[3]
    }
}

fn rect(f: &[&str]) -> Rect {
    Rect(std::array::from_fn(|i| {
        f[i].parse().expect("an integer coordinate")
    }))
}

/// A structure: `pass`, `fail`, `cell` (clean under every rule) or
/// `foundry` (whatever the foundry deck finds there).
struct Region {
    kind: String,
    /// The rule ids the structure tests, as its text names them.
    labels: Vec<String>,
    at: Rect,
    /// It holds a polygon `GPurify` refuses (see `xcheck.rb`).
    odd: bool,
}

/// What the helper found in a layout.
#[derive(Default)]
struct Prepared {
    pairs: Vec<(u16, u16)>,
    regions: Vec<Region>,
}

/// A text naming several rules, as IHP writes them: `Act.a/b` is `Act.a`
/// and `Act.b`, `Cnt.g/1/2` is `Cnt.g`, `Cnt.g1` and `Cnt.g2`.
fn labels(text: &str) -> Vec<String> {
    let mut parts = text.split('/');
    let first = parts.next().expect("split yields one part");
    let Some(dot) = first.rfind('.') else {
        return vec![text.to_owned()];
    };
    let (base, suffix) = first.split_at(dot + 1);
    let letters = suffix.trim_end_matches(|c: char| c.is_ascii_digit());
    let mut out = vec![first.to_owned()];
    for p in parts {
        if p.starts_with(|c: char| c.is_ascii_digit()) {
            out.push(format!("{base}{letters}{p}"));
        } else {
            out.push(format!("{base}{p}"));
        }
    }
    out
}

fn klayout(dir: &Path, args: &[String]) {
    let mut all = vec!["-b".to_owned()];
    all.extend_from_slice(args);
    let refs: Vec<&str> = all.iter().map(String::as_str).collect();
    oracle::run(&oracle::tool("klayout"), &refs, dir, LIMIT);
}

fn rd(k: &str, v: impl AsRef<std::ffi::OsStr>) -> [String; 2] {
    [
        "-rd".to_owned(),
        format!("{k}={}", Path::new(v.as_ref()).display()),
    ]
}

fn prepare(layout: &Layout, dir: &Path) -> Prepared {
    let helper = dir.join("xcheck.rb");
    std::fs::write(&helper, HELPER).expect("the scratch dir is writable");
    let out = dir.join("prepared.tsv");
    let mut args = vec!["-r".to_owned(), helper.display().to_string()];
    args.extend(rd("mode", "prepare"));
    args.extend(rd("out", &out));
    args.extend(rd("gds", &layout.gds));
    args.extend(rd("style", layout.style));
    args.extend(rd("label", &layout.label));
    args.extend(rd("manhattan", dir.join("manhattan.gds")));
    if layout.style == "cells" {
        let list = dir.join("cells.txt");
        let names: Vec<String> = layout
            .cells
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        std::fs::write(&list, names.join("\n")).expect("writable");
        args.extend(rd("cells", &list));
    }
    klayout(dir, &args);
    let text = std::fs::read_to_string(&out).expect("the helper wrote its output");
    let mut prepared = Prepared::default();
    let mut odd = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f[0] {
            "layer" => prepared
                .pairs
                .push((f[1].parse().expect("u16"), f[2].parse().expect("u16"))),
            "region" => prepared.regions.push(Region {
                kind: f[1].to_owned(),
                labels: if layout.style == "ihp" {
                    labels(f[2])
                } else {
                    vec![f[2].to_owned()]
                },
                at: rect(&f[3..7]),
                odd: false,
            }),
            "odd" => odd.push(rect(&f[1..5])),
            other => panic!("unexpected helper line {other}"),
        }
    }
    for r in &mut prepared.regions {
        r.odd = odd.iter().any(|a| a.touches(&r.at));
    }
    assert!(
        !prepared.regions.is_empty(),
        "{}: no structure found",
        layout.name
    );
    prepared
}

/// What the foundry deck reported: every category it ran, and the boxes it
/// marked under each.
#[derive(Default)]
struct Foundry {
    categories: BTreeSet<String>,
    markers: BTreeMap<String, Vec<Rect>>,
}

fn foundry(layout: &Layout, gds: &Path, dir: &Path) -> Foundry {
    let mut reports = Vec::new();
    for (i, run) in layout.runs.iter().enumerate() {
        let report = dir.join(format!("foundry{i}.lyrdb"));
        let mut args = vec!["-r".to_owned(), run.script.display().to_string()];
        args.extend(rd("input", gds));
        args.extend(rd("report", &report));
        for (k, v) in &run.switches {
            args.extend(rd(k, v));
        }
        klayout(dir, &args);
        assert!(
            report.exists(),
            "{}: no report from {}",
            layout.name,
            run.script.display()
        );
        reports.push(report.display().to_string());
    }
    let out = dir.join("markers.tsv");
    let mut args = vec!["-r".to_owned(), dir.join("xcheck.rb").display().to_string()];
    args.extend(rd("mode", "markers"));
    args.extend(rd("out", &out));
    args.extend(rd("gds", gds));
    args.extend(rd("rdbs", reports.join(",")));
    klayout(dir, &args);
    let mut found = Foundry::default();
    for line in std::fs::read_to_string(&out).expect("markers").lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f[0] {
            "category" => {
                found.categories.insert(f[1].to_owned());
            }
            "marker" => found
                .markers
                .entry(f[1].to_owned())
                .or_default()
                .push(rect(&f[2..6])),
            other => panic!("unexpected helper line {other}"),
        }
    }
    found
}

/// What `GPurify` reported per rule: whether it ran, and where it flagged.
/// `Refused` marks a rule refused on the layout as drawn, whose flags come
/// from the copy without odd polygons.
type Ours = BTreeMap<String, (Outcome, Vec<(i64, i64)>)>;

/// The shipped deck on `gds`, every stream pair it does not declare
/// ignored, DRC rules only.
fn ours(deck: &str, gds: &Path, pairs: &[(u16, u16)], dir: &Path) -> Result<Ours, String> {
    let mut strings = StrTable::default();
    let parsed = parse_deck(deck, Grid::new(1000).expect("1 nm"), &mut strings)
        .expect("the shipped deck parses");
    let mut text = deck.to_owned();
    for &(l, d) in pairs {
        if parsed.layers.of_stream(l, d).is_none() && !parsed.layers.is_ignored(l, d) {
            writeln!(text, "ignore gds({l}, {d})").expect("a String");
        }
    }
    let path = dir.join("ours.deck");
    std::fs::write(&path, text).expect("writable");
    let loaded = load(&Inputs {
        layout: gds.to_path_buf(),
        deck: path,
        reference: Vec::new(),
        intent: None,
        ..Inputs::default()
    })
    .map_err(|e| format!("GPurify refused the layout: {e}"))?;
    let rules = &loaded.deck.drc;
    let (mut out, mut runs) = (Violations::default(), Vec::new());
    rules.run(&loaded.store, &mut out, &mut runs);
    let name = |id| loaded.strings.resolve(id).to_owned();
    let mut found: Ours = runs
        .iter()
        .map(|r| (name(r.rule), (r.outcome, Vec::new())))
        .collect();
    for i in 0..out.len() {
        if let Some((_, at)) = found.get_mut(&name(out.rule[i])) {
            at.push((out.at[i].x.raw(), out.at[i].y.raw()));
        }
    }
    Ok(found)
}

/// One row of a deck's ledger.
struct Row {
    ours: Vec<String>,
    foundry: Vec<String>,
    checks: Vec<String>,
    status: String,
    line: usize,
}

const STATUSES: &[&str] = &[
    "agrees",
    "differs",
    "ours_missing",
    "theirs_missing",
    "not_comparable",
];

fn ledger(path: &str) -> Vec<Row> {
    let text = std::fs::read_to_string(repo().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
    let list = |s: &str| -> Vec<String> {
        if s == "-" {
            Vec::new()
        } else {
            s.split_whitespace().map(str::to_owned).collect()
        }
    };
    let rows: Vec<Row> = text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.starts_with('#') && !l.trim().is_empty())
        .skip(1)
        .map(|(i, l)| {
            let f: Vec<&str> = l.split('\t').collect();
            assert!(f.len() == 5, "{path}:{}: five columns", i + 1);
            assert!(
                STATUSES.contains(&f[3]),
                "{path}:{}: status {}",
                i + 1,
                f[3]
            );
            Row {
                ours: list(f[0]),
                foundry: list(f[1]),
                checks: list(f[2]),
                status: f[3].to_owned(),
                line: i + 1,
            }
        })
        .collect();
    for r in &rows {
        let at = format!("{path}:{}", r.line);
        match r.status.as_str() {
            "ours_missing" => assert!(r.ours.is_empty() && !r.checks.is_empty(), "{at}"),
            "theirs_missing" => assert!(!r.ours.is_empty() && r.checks.is_empty(), "{at}"),
            _ => assert!(!r.ours.is_empty() && !r.checks.is_empty(), "{at}"),
        }
    }
    rows
}

/// Per ledger row: regions compared, and each disagreement.
#[derive(Default)]
struct Tally {
    compared: usize,
    flagged: usize,
    differences: Vec<String>,
}

fn compare(
    rows: &[Row],
    layout: &Layout,
    prepared: &Prepared,
    kl: &Foundry,
    us: &Ours,
    tallies: &mut [Tally],
) {
    for region in &prepared.regions {
        let labelled = matches!(region.kind.as_str(), "pass" | "fail");
        for (row, tally) in rows.iter().zip(tallies.iter_mut()) {
            if !matches!(row.status.as_str(), "agrees" | "differs") {
                continue;
            }
            if labelled && !row.foundry.iter().any(|f| region.labels.contains(f)) {
                continue;
            }
            // Only where the foundry deck ran the check (a unit run holds one
            // table; a sheet of cells is no die for density).
            if !row.checks.iter().any(|c| kl.categories.contains(c)) {
                continue;
            }
            let refused = row
                .ours
                .iter()
                .filter_map(|id| us.get(id))
                .any(|(o, _)| *o == Outcome::Refused);
            if refused && region.odd {
                continue;
            }
            // Where each side flagged inside the region, for the message.
            let theirs: Option<String> = row.checks.iter().find_map(|c| {
                let m = kl.markers.get(c)?.iter().find(|b| b.touches(&region.at))?;
                Some(format!("{c} {:?}", m.0))
            });
            let mine: Option<String> = row.ours.iter().find_map(|id| {
                let p = us.get(id)?.1.iter().find(|&&p| region.at.holds(p))?;
                Some(format!("{id} at {p:?}"))
            });
            let expected = match region.kind.as_str() {
                "fail" => true,
                "pass" | "cell" => false,
                _ => theirs.is_some(),
            };
            tally.compared += 1;
            tally.flagged += usize::from(mine.is_some() || theirs.is_some());
            let what = |flag: Option<&String>| match flag {
                Some(at) => format!("flags ({at})"),
                None => "misses".to_owned(),
            };
            let at = format!(
                "{} {} {} {:?}",
                layout.name,
                region.kind,
                region.labels.join("/"),
                region.at.0
            );
            if theirs.is_some() != expected {
                tally
                    .differences
                    .push(format!("foundry deck {}: {at}", what(theirs.as_ref())));
            }
            if mine.is_some() != expected {
                tally
                    .differences
                    .push(format!("GPurify {}: {at}", what(mine.as_ref())));
            }
        }
    }
}

/// The ways `ledger_path` fails to give every rule of `deck_path` exactly one
/// row, or names a rule the deck lacks; empty when it covers the deck.
fn ledger_gaps(deck_path: &str, ledger_path: &str) -> Vec<String> {
    let deck = std::fs::read_to_string(repo().join(deck_path)).expect("the shipped deck");
    let rows = ledger(ledger_path);
    let mut strings = StrTable::default();
    let parsed = parse_deck(&deck, Grid::new(1000).expect("1 nm"), &mut strings).expect("parses");
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for r in &rows {
        for id in &r.ours {
            *seen.entry(id.clone()).or_default() += 1;
        }
    }
    let mut problems = Vec::new();
    for spec in &parsed.rules.spec {
        let id = strings.resolve(spec.id);
        match seen.remove(id) {
            Some(1) => {}
            Some(n) => problems.push(format!("rule {id} is in {n} ledger rows")),
            None => problems.push(format!("rule {id} has no ledger row")),
        }
    }
    problems.extend(
        seen.keys()
            .map(|id| format!("ledger names {id}, which the deck lacks")),
    );
    problems
}

/// Runs both tools on every layout of a deck and holds the ledger to them.
fn cross_check(deck_path: &str, ledger_path: &str, layouts: &[Layout]) {
    let deck = std::fs::read_to_string(repo().join(deck_path)).expect("the shipped deck");
    let rows = ledger(ledger_path);

    // Every rule of the deck has exactly one row.
    let mut problems = ledger_gaps(deck_path, ledger_path);

    let mut tallies: Vec<Tally> = rows.iter().map(|_| Tally::default()).collect();
    let mut categories = BTreeSet::new();
    for (i, layout) in layouts.iter().enumerate() {
        let dir = oracle::scratch(&format!("foundry-{i}"));
        let prepared = prepare(layout, &dir);
        let kl = foundry(layout, &layout.gds, &dir);
        categories.extend(kl.categories.iter().cloned());
        // GPurify refuses a whole layout whose odd polygon feeds a derived
        // layer (finding N-f2-3), and a rule whose layer holds one. Those read
        // the copy without the structures holding odd polygons, and the
        // structures are not compared for them.
        let clean = dir.join("manhattan.gds");
        let us = match ours(&deck, &layout.gds, &prepared.pairs, &dir) {
            Ok(mut us) => {
                if us.values().any(|r| r.0 == Outcome::Refused) {
                    match ours(&deck, &clean, &prepared.pairs, &dir) {
                        Ok(again) => {
                            for (id, r) in &mut us {
                                if r.0 == Outcome::Refused {
                                    *r = again[id].clone();
                                    r.0 = Outcome::Refused;
                                }
                            }
                        }
                        Err(why) => {
                            problems.push(format!("{} without odd polygons: {why}", layout.name));
                        }
                    }
                }
                us
            }
            Err(_) => match ours(&deck, &clean, &prepared.pairs, &dir) {
                Ok(mut us) => {
                    for r in us.values_mut() {
                        r.0 = Outcome::Refused;
                    }
                    us
                }
                Err(why) => {
                    problems.push(format!("{} without odd polygons: {why}", layout.name));
                    continue;
                }
            },
        };
        compare(&rows, layout, &prepared, &kl, &us, &mut tallies);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Every check the foundry deck ran has a row.
    let ledgered: BTreeSet<&String> = rows.iter().flat_map(|r| &r.checks).collect();
    problems.extend(
        categories
            .iter()
            .filter(|c| !ledgered.contains(c))
            .map(|c| format!("foundry check {c} has no ledger row")),
    );

    println!("{ledger_path}: {} rows", rows.len());
    for (row, t) in rows.iter().zip(&tallies) {
        let name = format!("{ledger_path}:{} {}", row.line, row.ours.join(" "));
        if !matches!(row.status.as_str(), "agrees" | "differs") {
            continue;
        }
        println!(
            "  {name:<48} {:<8} compared {:>4} flagged {:>4} differ {:>4}",
            row.status,
            t.compared,
            t.flagged,
            t.differences.len()
        );
        for d in t.differences.iter().take(12) {
            println!("      {d}");
        }
        match (row.status.as_str(), t.compared, t.differences.len()) {
            (_, 0, _) => problems.push(format!("{name}: compared nowhere")),
            ("agrees", _, n) if n > 0 => problems.push(format!(
                "{name}: marked agrees, {n} differences, first {}",
                t.differences[0]
            )),
            ("differs", _, 0) => problems.push(format!("{name}: marked differs, but agrees")),
            _ => {}
        }
    }
    assert!(
        problems.is_empty(),
        "{} problems:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

fn switches(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|&(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// Oracle: GF's `fd_pv` unit structures (pass boxes on 2/222 clean, fail
/// boxes on 3/222 flagged) and the mcu7t5v0 cells (clean), against which
/// `GPurify` and `fd_pv`'s `gf180mcu.drc` are both held, row by row of
/// `docs/xcheck/gf180mcu.tsv` (a differential against the foundry deck).
#[test]
#[ignore = "release tier: needs the foundry PDKs and klayout (nix develop .#oracles)"]
fn foundry_deck_gf180mcu() {
    let pv = checkout("gf180mcu_fd_pv");
    let script = need(&pv, "klayout/drc/gf180mcu.drc");
    // The shipped deck's stack: 6 metals, 9 kA MetalTop, MIM option B.
    let run = |deck: &str| Run {
        script: script.clone(),
        switches: switches(&[("variant", "E"), ("run_mode", "flat"), ("decks", deck)]),
    };
    // Unit structures of other stacks are not run: variant A (metaltop_30k,
    // mim_a), F (antenna-2) and C, whose top metal and MIM bottom plate are
    // drawn on Metal5's 81/0 (metaltop, mim_b). Nor are tables whose rows
    // are all ours_missing or ERC (antenna-1).
    let other = [
        "metaltop_30k",
        "mim_a",
        "antenna-2",
        "metaltop",
        "mim_b",
        "antenna-1",
        "ldnmos",
        "ldpmos",
        "efuse",
        "otp_mk",
        "ymtp_mk",
        "sram_3p3",
        "sram_5p0",
        "mcell",
        "dummy_exclude",
        "drc_bjt",
        "lvs_bjt",
        "density-MT30_7_pass",
        "density-MT30_7_fail",
    ];
    let mut layouts: Vec<Layout> = files(&need(&pv, "klayout/drc/testing/unit"), "gds")
        .into_iter()
        .filter_map(|gds| {
            let stem = gds.file_stem()?.to_str()?.to_owned();
            if other.contains(&stem.as_str()) {
                return None;
            }
            let table = stem.split('-').next()?.to_owned();
            let (style, label) = match stem.strip_prefix("density-") {
                Some(rest) => {
                    let (rule, verdict) = rest.rsplit_once('_')?;
                    (
                        if verdict == "pass" { "pass" } else { "fail" },
                        rule.replace('_', "."),
                    )
                }
                None => ("gf", String::new()),
            };
            Some(Layout {
                name: stem,
                gds,
                style,
                label,
                cells: Vec::new(),
                runs: vec![run(&table)],
            })
        })
        .collect();
    let sc = checkout("gf180mcu_fd_sc_mcu7t5v0");
    let cells = files(&need(&sc, "cells"), "gds");
    layouts.push(Layout {
        name: "gf180mcu_fd_sc_mcu7t5v0".to_owned(),
        gds: oracle::scratch("foundry-sheet").join("gf180mcu_fd_sc_mcu7t5v0.gds"),
        style: "cells",
        label: String::new(),
        cells,
        // A sheet of cells is no die: density is compared on its own units.
        runs: vec![run("all,-density")],
    });
    cross_check("pdks/gf180mcu.deck", "docs/xcheck/gf180mcu.tsv", &layouts);
}

/// Oracle: IHP's unit cells (each rule's PASS half clean, FAIL half
/// flagged) and the `sg13g2_stdcell` cells (clean), against which `GPurify` and
/// IHP's `ihp-sg13g2.drc` and `sg13g2_maximal.drc` are both held, row by row
/// of `docs/xcheck/ihp_sg13g2.tsv` (a differential against the foundry deck).
#[test]
#[ignore = "release tier: needs the foundry PDKs and klayout (nix develop .#oracles)"]
fn foundry_deck_ihp_sg13g2() {
    let pdk = checkout("ihp_open_pdk");
    let drc = need(&pdk, "ihp-sg13g2/libs.tech/klayout/tech/drc");
    let json = need(
        &pdk,
        "ihp-sg13g2/libs.tech/klayout/python/sg13g2_pycell_lib/sg13g2_tech_mod.json",
    );
    let log = oracle::scratch("foundry-ihp-log").join("drc.log");
    let common = |extra: &[(&str, &str)]| {
        let mut s = switches(&[("run_mode", "flat")]);
        s.push(("drc_json".to_owned(), json.display().to_string()));
        s.push(("log".to_owned(), log.display().to_string()));
        s.extend(switches(extra));
        s
    };
    // Table mode, as IHP's run_drc.py runs one table; then the residual
    // rules of sg13g2_maximal.drc, which hold the rest of the manual.
    let table = |t: &str| Run {
        script: need(&drc, "ihp-sg13g2.drc"),
        switches: common(&[
            ("tables", t),
            ("no_feol", "true"),
            ("no_beol", "true"),
            ("no_forbidden", "true"),
            ("no_pin", "true"),
            ("no_offgrid", if t == "offgrid" { "false" } else { "true" }),
            ("no_angle", if t == "angle" { "false" } else { "true" }),
        ]),
    };
    let deck = |name: &str| Run {
        script: need(&drc, &format!("rule_decks/{name}.drc")),
        switches: common(&[]),
    };
    // Structures of tables the shipped deck has no rule for, or that are ERC
    // (antenna), are not run; nor metalslits and pad, whose rule texts run
    // along a row instead of down the PASS/FAIL columns.
    let other = [
        "antenna",
        "copperpillar",
        "solderbump",
        "schottkydiode",
        "npnsubstratetie",
        "metalslits",
        "pad",
    ];
    let mut layouts: Vec<Layout> = files(&need(&drc, "testing/testcases/unit"), "gds")
        .into_iter()
        .filter_map(|gds| {
            let stem = gds.file_stem()?.to_str()?.to_owned();
            if other.contains(&stem.as_str()) {
                return None;
            }
            // IHP's density structures stack one top cell per rule at the
            // origin, for a run per cell; their rows are not compared.
            if stem.starts_with("density_") {
                return None;
            }
            let t = match stem.as_str() {
                "metal2" | "metal3" | "metal4" | "metal5" => "metaln",
                "via2" | "via3" | "via4" => "vian",
                s => s,
            };
            Some(Layout {
                name: stem.clone(),
                gds,
                style: "ihp",
                label: String::new(),
                cells: Vec::new(),
                runs: vec![table(t), deck("sg13g2_maximal")],
            })
        })
        .collect();
    let lib = need(
        &pdk,
        "ihp-sg13g2/libs.ref/sg13g2_stdcell/gds/sg13g2_stdcell.gds",
    );
    layouts.push(Layout {
        name: "sg13g2_stdcell".to_owned(),
        gds: oracle::scratch("foundry-sheet").join("sg13g2_stdcell.gds"),
        style: "cells",
        label: String::new(),
        cells: vec![lib],
        runs: vec![
            Run {
                script: need(&drc, "ihp-sg13g2.drc"),
                switches: common(&[("tables", "main")]),
            },
            deck("sg13g2_maximal"),
            deck("antenna"),
        ],
    });
    cross_check(
        "pdks/ihp_sg13g2.deck",
        "docs/xcheck/ihp_sg13g2.tsv",
        &layouts,
    );
}

/// Oracle: a differential against the foundry's `sky130A_mr.drc` on
/// `test_violators.gds` (held to the foundry deck's findings), and the
/// `sky130_fd_sc_hd` cells (clean), row by row of `docs/xcheck/sky130.tsv`.
#[test]
#[ignore = "release tier: needs the foundry PDKs and klayout (nix develop .#oracles)"]
fn foundry_deck_sky130() {
    let kl = checkout("sky130_klayout_pdk");
    let run = Run {
        script: need(&kl, "tech/sky130/drc/sky130A_mr.drc"),
        // One thread: the deck runs deep with `threads(4)` unless `$thr` says
        // otherwise, and KLayout 0.30.8 so once hung in its `li` boolean
        // (sky130A_mr.drc:1067, killed at the limit) and once aborted writing
        // the report (`free(): invalid pointer`) on inputs other runs passed.
        switches: switches(&[
            ("feol", "true"),
            ("beol", "true"),
            ("offgrid", "true"),
            ("thr", "1"),
        ]),
    };
    let violators = need(&checkout("open_pdks"), "sky130/klayout/test_violators.gds");
    let hd = checkout("sky130_fd_sc_hd");
    let layouts = [
        Layout {
            name: "test_violators".to_owned(),
            gds: violators,
            style: "whole",
            label: String::new(),
            cells: Vec::new(),
            runs: vec![run.clone()],
        },
        Layout {
            name: "sky130_fd_sc_hd".to_owned(),
            gds: oracle::scratch("foundry-sheet").join("sky130_fd_sc_hd.gds"),
            style: "cells",
            label: String::new(),
            cells: files(&need(&hd, "cells"), "gds"),
            runs: vec![run],
        },
    ];
    cross_check("pdks/sky130.deck", "docs/xcheck/sky130.tsv", &layouts);
}

/// Every rule of each shipped deck has exactly one ledger row, and no row
/// names a rule the deck lacks, so a deck change that skips its ledger fails
/// here rather than only in the release tier (a rule added after F2 once
/// reached the base with no row).
///
/// Oracle: the ledgers' own contract (`docs/xcheck/*.tsv`, header), checked
/// against the parsed decks.
#[test]
fn every_deck_rule_has_one_ledger_row() {
    for (deck, ledger) in [
        ("pdks/sky130.deck", "docs/xcheck/sky130.tsv"),
        ("pdks/gf180mcu.deck", "docs/xcheck/gf180mcu.tsv"),
        ("pdks/ihp_sg13g2.deck", "docs/xcheck/ihp_sg13g2.tsv"),
    ] {
        let gaps = ledger_gaps(deck, ledger);
        assert!(gaps.is_empty(), "{ledger}:\n{}", gaps.join("\n"));
    }
}

/// Oracle: the texts as IHP's unit cells draw them on 63/0 (`activ.gds`
/// `Act.a/b`, `gatpoly.gds` `Gat.a/a1`, `cont.gds` `Cnt.g/1/2`, `nwell.gds`
/// `NW.f1.digibnd`, `forbidden.gds` `BasPoly`) and the rule ids IHP's deck
/// reports for them.
#[test]
fn a_compound_rule_text_names_each_rule() {
    assert_eq!(labels("Act.a/b"), ["Act.a", "Act.b"]);
    assert_eq!(labels("Gat.a/a1"), ["Gat.a", "Gat.a1"]);
    assert_eq!(labels("Cnt.g/1/2"), ["Cnt.g", "Cnt.g1", "Cnt.g2"]);
    assert_eq!(labels("NW.f1.digibnd"), ["NW.f1.digibnd"]);
    assert_eq!(labels("BasPoly"), ["BasPoly"]);
}
