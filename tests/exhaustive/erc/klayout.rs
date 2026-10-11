//! Antenna ratios against `KLayout`'s `antenna_check` (testing-plan §4 L6,
//! ledger O1), net by net and gate by gate, on X4's antenna fixtures and on
//! seeded boards ([`super::antenna_board`]).
//!
//! **What `KLayout` is given.** The fixture's GDS, and for every antenna row
//! and every collector of it one netter run: `clear_connections`, then the
//! connectivity standing when that collector is etched, then
//! `antenna_check(gate, collector, limit)` with a text layer. The stage is
//! the row's [`Stack`]'s: the conductors up to the collector's (a cut's is
//! its lower conductor's) and every via between two of them, each conductor
//! joined to itself; a cut collector joins only the conductors of its vias
//! that stand. The gate layer joins the conductor it is drawn on, poly (the
//! MIM capacitor's met2): `GPurify` finds it from the deck
//! (`erc::rules::antenna`), `KLayout` must be told. A sidewall row reads
//! `perimeter_only(collector, thickness)`, and a row's diode is
//! `antenna_check`'s one-element diode spec: a net with diode area is
//! skipped.
//!
//! **What is read back.** `antenna_check` writes one text per net it flags,
//! `agate: …, ametal: …, ratio: …`, at a vertex of that net's collector
//! shapes; the netter's `probe_net` there names the net, and every gate shape
//! is probed for its net too. So each gate gets `KLayout`'s net and ratio at
//! each collector's stage, read off `KLayout`'s own extraction.
//!
//! **Oracle.** `KLayout`'s antenna rule (`LayoutToNetlist::antenna_check`):
//! the merged collector area (or perimeter times thickness) on a net over the
//! merged gate area on it, a net flagged when that exceeds the limit by more
//! than 1e-10, a net with any area on a plain diode layer skipped. A row with
//! one collector is that check itself. A cumulative row (several
//! collectors) has no `KLayout` function: it is the sum, gate by gate, of
//! `antenna_check`'s ratio at each collector's stage (threshold 0), flagged
//! above the limit by more than 1e-10 as `antenna_check` flags, which is how
//! `KLayout`'s own test suite builds a cumulative check from per-stage ratios
//! (`drcSimpleTests_144`) and LEF/DEF 5.8 Appendix C's CAR.
//!
//! **Compared.** Per row that `GPurify` ran: every net (cumulative: every
//! group of gates on one net at every stage) `KLayout` flags must carry
//! exactly one `GPurify` violation at one of its gates, measuring the same
//! ratio to 1e-9 relative (`KLayout` prints twelve digits; both sides divide
//! exact areas), and every `GPurify` violation must sit on such a net.
//!
//! **Not compared**, each counted: a row `GPurify` refused; an
//! `antenna_electrical` row with a credit or a bonus (`KLayout`'s diode spec
//! credits per µm² of diode, never a constant, and `GPurify` refuses a credit
//! per area); a cumulative row with a diode (its skip is `GPurify`'s, at the
//! row's last stage; `KLayout` defines none).

use super::antenna_board::{self, contains, Board, Findings};
use super::{Rect, ERC};
use crate::harness::{self, Fixture};
use gpurify::check::erc::rules::antenna::{AntennaMeasure, Stack};
use gpurify::check::erc::RuleSet;
use gpurify::check::report::{Measurement, Outcome};
use gpurify::geom::LayerId;
use gpurify_ingest::deck::{Deck, DerivedOp};
use gpurify_ingest::StrTable;
use gpurify_testgen::oracle;
use serde_json::Value as Json;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Seeded boards per run.
const BOARDS: u64 = 300;

/// Fixtures per `KLayout` process.
const BATCH: usize = 40;

/// How long one `KLayout` batch may run; it takes seconds.
const LIMIT: Duration = Duration::from_mins(10);

/// `antenna_check`'s margin: a ratio flags only above `limit + EPSILON`
/// (`db::epsilon`, `dbLayoutToNetlist.cc`).
const EPSILON: f64 = 1e-10;

/// Two ratios agree to this, relative.
const RELATIVE: f64 = 1e-9;

/// The helpers every batch script starts with.
const PRELUDE: &str = r#"require "json"
def put(h) ; $out.puts(JSON.generate(h)) ; end
# antenna_check's text for each net it flags, with the net under it, and every
# gate shape with its net.
def measured(row, col, gate, metal, values, l2n)
  values.data.each do |t|
    n = l2n.probe_net(metal.data, RBA::Point::new(t.x, t.y))
    put({ m: [row, col], text: t.string, net: n ? n.cluster_id : -1 })
  end
  gate.data.each do |p|
    n = l2n.probe_net(gate.data, p.each_point_hull.first)
    b = p.bbox
    put({ g: [row, col], box: [b.left, b.bottom, b.right, b.top], net: n ? n.cluster_id : -1 })
  end
end
"#;

/// One antenna row as `KLayout` runs it.
struct Row {
    id: String,
    gate: LayerId,
    /// Deduplicated: each collector, its measure and its etch stage.
    collectors: Vec<(LayerId, AntennaMeasure, usize)>,
    /// `antenna`'s diode: the row leaves a net with diode area to another.
    diode: Option<LayerId>,
    limit: f64,
}

/// One fixture: the rows `KLayout` mirrors, the Ruby that runs them, and what
/// `GPurify` reported.
struct Job {
    name: String,
    rows: Vec<Row>,
    /// Rows not mirrored, with why.
    skipped: Vec<(String, &'static str)>,
    ruby: String,
    /// Per rule id: its outcome and `(ratio, at)` per violation.
    gpurify: BTreeMap<String, (Outcome, Findings)>,
}

/// The etch stage of `layer` (an index into `stack.conductors`): a
/// conductor's own place, a cut's lower conductor's. `Stack::standing`.
fn standing(stack: &Stack, layer: LayerId) -> Option<usize> {
    let pos = |l: LayerId| stack.conductors.iter().position(|&c| c == l);
    pos(layer).or_else(|| {
        stack
            .vias
            .iter()
            .filter(|v| v.0 == layer)
            .filter_map(|&(_, a, b)| Some(pos(a)?.min(pos(b)?)))
            .max()
    })
}

/// One antenna row as the deck states it: id, gate, collectors with their
/// measures, diode, limit.
type Stated = (
    String,
    LayerId,
    Vec<(LayerId, AntennaMeasure)>,
    Option<LayerId>,
    f64,
);

/// The antenna rows of `deck` that `KLayout` mirrors, the rest with why, and
/// the deck's stack.
fn rows(deck: &Deck, strings: &StrTable) -> (Vec<Row>, Vec<(String, &'static str)>, Stack) {
    let mut rules = RuleSet::from_deck(deck, strings).expect("an antenna fixture's deck builds");
    let name = |id| strings.resolve(id).to_owned();
    let mut stated: Vec<Stated> = Vec::new();
    let mut skipped = Vec::new();
    let a = &rules.antenna;
    for r in 0..a.head.len() {
        let span = a.collector_start[r] as usize..a.collector_start[r + 1] as usize;
        stated.push((
            name(a.head.rule[r]),
            a.gate[r],
            a.collector[span.clone()]
                .iter()
                .copied()
                .zip(a.collector_measure[span].iter().copied())
                .collect(),
            a.diode[r],
            a.max_ratio[r],
        ));
    }
    let e = &rules.antenna_electrical;
    for r in 0..e.head.len() {
        let id = name(e.head.rule[r]);
        if e.diode_credit[r] != 0.0 || e.diode_bonus[r] != 0.0 {
            skipped.push((id, "a diode credit or bonus"));
            continue;
        }
        let span = e.collector_start[r] as usize..e.collector_start[r + 1] as usize;
        // No credit: `ratio − 0 − 0` for every gate, diode or not.
        stated.push((
            id,
            e.gate[r],
            e.collector[span]
                .iter()
                .map(|&l| (l, AntennaMeasure::Area))
                .collect(),
            None,
            e.max_ratio[r],
        ));
    }
    let stack = std::mem::take(&mut rules.antenna.stack);
    let stack = if stack.conductors.is_empty() {
        std::mem::take(&mut rules.antenna_electrical.stack)
    } else {
        stack
    };
    let mut out = Vec::new();
    for (id, gate, collectors, diode, limit) in stated {
        let mut unique: Vec<(LayerId, AntennaMeasure)> = Vec::new();
        for (layer, measure) in collectors {
            if !unique.iter().any(|c| c.0 == layer) {
                unique.push((layer, measure));
            }
        }
        if unique.len() > 1 && diode.is_some() {
            skipped.push((id, "a cumulative row with a diode"));
            continue;
        }
        let top = unique
            .iter()
            .filter_map(|c| standing(&stack, c.0))
            .max()
            .expect("an antenna fixture's collectors stand in its stack");
        let collectors = unique
            .into_iter()
            .map(|(layer, measure)| (layer, measure, standing(&stack, layer).unwrap_or(top)))
            .collect();
        out.push(Row {
            id,
            gate,
            collectors,
            diode,
            limit,
        });
    }
    (out, skipped, stack)
}

/// Ruby variable of a layer.
fn var(layer: LayerId) -> String {
    format!("l{}", layer.0)
}

/// Defines `layer` (and first its operands) as `KLayout` layer variables.
fn define(deck: &Deck, layer: LayerId, done: &mut Vec<LayerId>, out: &mut String) {
    if done.contains(&layer) {
        return;
    }
    let operands = deck.layers.operands(layer).to_vec();
    for &o in &operands {
        define(deck, o, done, out);
    }
    let join = |sep: &str| {
        operands
            .iter()
            .map(|&o| var(o))
            .collect::<Vec<_>>()
            .join(sep)
    };
    let expr = match deck.layers.op(layer) {
        None => {
            let (gds, datatype) = deck.layers.stream_of(layer);
            format!("input({gds}, {datatype})")
        }
        Some(DerivedOp::And) => join(" & "),
        Some(DerivedOp::Or) => join(" | "),
        Some(DerivedOp::Not) => join(" - "),
        Some(op) => panic!("an antenna fixture derives a layer by {op:?}, which is not translated"),
    };
    let _ = writeln!(out, "  {} = {expr}", var(layer));
    done.push(layer);
}

/// The conductor a gate layer is drawn on: met2 under a MIM capacitor, poly
/// under every other gate (X4's decks).
fn gate_conductor(deck: &Deck, strings: &StrTable, gate: LayerId) -> LayerId {
    let named = if strings.resolve(deck.layers.name(gate)) == "mim" {
        "met2"
    } else {
        "poly"
    };
    deck.layers
        .id(strings, named)
        .expect("an antenna deck draws poly and met2")
}

/// The Ruby that runs one fixture's rows, writing to `out`.
fn ruby(
    deck: &Deck,
    strings: &StrTable,
    rows: &[Row],
    stack: &Stack,
    gds: &Path,
    out: &Path,
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "begin");
    let _ = writeln!(
        s,
        "  $out = File.open({:?}, \"w\")",
        out.display().to_string()
    );
    let _ = writeln!(s, "  source({:?})", gds.display().to_string());
    let mut done = Vec::new();
    for row in rows {
        define(deck, row.gate, &mut done, &mut s);
        define(
            deck,
            gate_conductor(deck, strings, row.gate),
            &mut done,
            &mut s,
        );
        for &(c, ..) in &row.collectors {
            define(deck, c, &mut done, &mut s);
        }
        if let Some(d) = row.diode {
            define(deck, d, &mut done, &mut s);
        }
    }
    for &c in &stack.conductors {
        define(deck, c, &mut done, &mut s);
    }
    for &(cut, ..) in &stack.vias {
        define(deck, cut, &mut done, &mut s);
    }
    for (r, row) in rows.iter().enumerate() {
        let on = gate_conductor(deck, strings, row.gate);
        let single = row.collectors.len() == 1;
        for (c, &(collector, measure, stage)) in row.collectors.iter().enumerate() {
            let standing = &stack.conductors[..=stage];
            assert!(
                standing.contains(&on),
                "{}: the gate's conductor is not etched when {} is",
                row.id,
                c
            );
            let _ = writeln!(s, "  clear_connections");
            for &cond in standing {
                let _ = writeln!(s, "  connect({0}, {0})", var(cond));
            }
            for &(cut, a, b) in &stack.vias {
                let (sa, sb) = (standing.contains(&a), standing.contains(&b));
                if (sa && sb) || cut == collector {
                    for (x, stands) in [(a, sa), (b, sb)] {
                        if stands {
                            let _ = writeln!(s, "  connect({}, {})", var(x), var(cut));
                        }
                    }
                }
            }
            let _ = writeln!(s, "  connect({}, {})", var(row.gate), var(on));
            let metal = match measure {
                AntennaMeasure::Area => var(collector),
                AntennaMeasure::Sidewall { thickness } => {
                    #[allow(clippy::cast_precision_loss, reason = "a thickness in nm")]
                    let um = thickness.raw() as f64 / 1000.0;
                    format!("perimeter_only({}, {um})", var(collector))
                }
            };
            let threshold = if single { row.limit } else { 0.0 };
            let diode = match (single, row.diode) {
                (true, Some(d)) => format!(", {}", var(d)),
                _ => String::new(),
            };
            let _ = writeln!(s, "  v = labels");
            let _ = writeln!(
                s,
                "  antenna_check({}, {metal}, {threshold:?}{diode}, v)",
                var(row.gate)
            );
            let _ = writeln!(
                s,
                "  measured({r}, {c}, {}, {}, v, l2n_data)",
                var(row.gate),
                var(collector)
            );
        }
    }
    let _ = writeln!(
        s,
        "rescue => e\n  put({{ error: e.message + \" at \" + e.backtrace.first.to_s }})\nensure\n  $out.close\nend"
    );
    s
}

/// A fixture run through `GPurify`, its GDS written to `dir` as `<i>.gds`
/// and its rows translated to read it and write `<i>.jsonl`.
fn job(fixture: &Fixture, dir: &Path, i: usize) -> Job {
    let (gds, deck, strings) =
        harness::written(fixture).unwrap_or_else(|why| panic!("{}: {why}", fixture.name));
    let ran = harness::run(fixture).unwrap_or_else(|why| panic!("{}: {why}", fixture.name));
    let (rows, skipped, stack) = rows(&deck, &strings);
    let path = dir.join(format!("{i}.gds"));
    std::fs::write(&path, &gds).expect("the scratch directory is writable");
    let ruby = ruby(
        &deck,
        &strings,
        &rows,
        &stack,
        &path,
        &dir.join(format!("{i}.jsonl")),
    );
    let mut gpurify: BTreeMap<String, (Outcome, Findings)> = ran
        .rows
        .iter()
        .map(|(id, outcome)| (id.clone(), (*outcome, Vec::new())))
        .collect();
    for (id, measured, at) in &ran.findings {
        if let (Some(entry), Measurement::Ratio(r)) = (gpurify.get_mut(id), measured) {
            entry.1.push((*r, *at));
        }
    }
    Job {
        name: fixture.name.clone(),
        rows,
        skipped,
        ruby,
        gpurify,
    }
}

/// What `KLayout` wrote for one fixture.
#[derive(Default)]
struct Measured {
    /// Per `(row, collector)`: the ratio of each net `antenna_check` flagged.
    ratio: BTreeMap<(usize, usize), BTreeMap<i64, f64>>,
    /// Per `(row, collector)`: every gate shape's box and net.
    gates: BTreeMap<(usize, usize), Vec<(Rect, i64)>>,
    errors: Vec<String>,
}

/// The `ratio` of an `antenna_check` text: `agate: …, ametal: …, ratio: …`.
fn ratio_of(text: &str) -> Option<f64> {
    text.split(", ")
        .find_map(|part| part.strip_prefix("ratio: "))
        .and_then(|v| v.trim().parse().ok())
}

impl Measured {
    fn parse(text: &str) -> Self {
        let mut out = Measured::default();
        let pair = |j: &Json| -> Option<(usize, usize)> {
            let a = j.get(0)?.as_u64()?;
            let b = j.get(1)?.as_u64()?;
            Some((usize::try_from(a).ok()?, usize::try_from(b).ok()?))
        };
        for line in text.lines() {
            let Ok(j) = serde_json::from_str::<Json>(line) else {
                out.errors.push(format!("not JSON: {line}"));
                continue;
            };
            if let Some(e) = j.get("error") {
                out.errors.push(e.to_string());
            } else if let Some(key) = j.get("m").and_then(pair) {
                let net = j["net"].as_i64().unwrap_or(-1);
                match j["text"].as_str().and_then(ratio_of) {
                    Some(r) => {
                        out.ratio.entry(key).or_default().insert(net, r);
                    }
                    None => out.errors.push(format!("no ratio in {line}")),
                }
            } else if let Some(key) = j.get("g").and_then(pair) {
                let b: Vec<i64> = j["box"]
                    .as_array()
                    .map(|a| a.iter().filter_map(Json::as_i64).collect())
                    .unwrap_or_default();
                if b.len() == 4 {
                    let net = j["net"].as_i64().unwrap_or(-1);
                    out.gates
                        .entry(key)
                        .or_default()
                        .push(((b[0], b[1], b[2], b[3]), net));
                } else {
                    out.errors.push(format!("no box in {line}"));
                }
            } else {
                out.errors.push(format!("unexpected: {line}"));
            }
        }
        out
    }
}

/// What the comparisons found.
#[derive(Default)]
struct Tally {
    fixtures: usize,
    /// Rows compared.
    rows: usize,
    /// Flagged nets (groups) both tools agree on.
    agreed: usize,
    /// Rows not mirrored, per reason.
    skipped: BTreeMap<&'static str, usize>,
    /// Rows `GPurify` did not run.
    not_run: usize,
    broken: Vec<String>,
}

fn close(a: f64, b: f64) -> bool {
    (a - b).abs() <= RELATIVE * a.abs().max(b.abs()).max(1e-12)
}

/// Compares one fixture's rows, gate group by gate group.
fn compare(job: &Job, m: &Measured, tally: &mut Tally) {
    tally.fixtures += 1;
    for (_, why) in &job.skipped {
        *tally.skipped.entry(*why).or_default() += 1;
    }
    if !m.errors.is_empty() {
        tally
            .broken
            .push(format!("{}: KLayout: {}", job.name, m.errors.join("; ")));
        return;
    }
    for (r, row) in job.rows.iter().enumerate() {
        let at = |what: String| format!("{} {}: {what}", job.name, row.id);
        let Some((outcome, findings)) = job.gpurify.get(&row.id) else {
            tally.broken.push(at("GPurify has no such row".to_owned()));
            continue;
        };
        if *outcome != Outcome::Ran {
            tally.not_run += 1;
            continue;
        }
        tally.rows += 1;
        // Per gate shape: its net at each collector's stage, and its ratio.
        let shapes = m.gates.get(&(r, 0)).cloned().unwrap_or_default();
        let mut groups: BTreeMap<Vec<i64>, (Vec<Rect>, f64, bool)> = BTreeMap::new();
        let mut unplaced = false;
        for &(bbox, _) in &shapes {
            let mut key = Vec::new();
            let (mut value, mut flagged) = (0.0, false);
            for c in 0..row.collectors.len() {
                let net = m
                    .gates
                    .get(&(r, c))
                    .and_then(|g| g.iter().find(|s| s.0 == bbox))
                    .map_or(-1, |s| s.1);
                unplaced |= net < 0;
                key.push(net);
                if let Some(&v) = m.ratio.get(&(r, c)).and_then(|n| n.get(&net)) {
                    value += v;
                    flagged = true;
                }
            }
            if row.collectors.len() > 1 {
                flagged = value > row.limit + EPSILON;
            }
            let entry = groups.entry(key).or_insert((Vec::new(), value, flagged));
            entry.0.push(bbox);
        }
        if unplaced {
            tally
                .broken
                .push(at("KLayout put a gate shape on no net".to_owned()));
            continue;
        }
        let keys: Vec<&Vec<i64>> = groups.keys().collect();
        let mut hits = vec![0usize; keys.len()];
        for &(value, point) in findings {
            let owners: Vec<usize> = (0..keys.len())
                .filter(|&k| groups[keys[k]].0.iter().any(|&b| contains(b, point)))
                .collect();
            let &[k] = owners.as_slice() else {
                tally.broken.push(at(format!(
                    "GPurify flags {value} at {point:?}, on {} of KLayout's gate groups",
                    owners.len()
                )));
                continue;
            };
            let (_, theirs, flagged) = &groups[keys[k]];
            let (theirs, flagged) = (*theirs, *flagged);
            if !flagged {
                tally.broken.push(at(format!(
                    "GPurify flags {value} at {point:?}; KLayout's ratio there is {theirs}, \
                     not above {}",
                    row.limit
                )));
            } else if !close(value, theirs) {
                tally.broken.push(at(format!(
                    "at {point:?} GPurify measures {value}, KLayout {theirs}"
                )));
            }
            hits[k] += 1;
        }
        for (k, key) in keys.iter().enumerate() {
            let (gates, theirs, flagged) = &groups[*key];
            match (*flagged, hits[k]) {
                (true, 1) => tally.agreed += 1,
                (true, n) => tally.broken.push(at(format!(
                    "KLayout flags the gates {gates:?} at {theirs}; GPurify reports them {n} times"
                ))),
                (false, _) => {}
            }
        }
    }
}

/// Runs `fixtures` through `GPurify` and one `KLayout` process and compares
/// each.
fn batch(klayout: &Path, fixtures: &[Fixture]) -> Tally {
    let dir = oracle::scratch("klayout-antenna");
    let jobs: Vec<Job> = fixtures
        .iter()
        .enumerate()
        .map(|(i, f)| job(f, &dir, i))
        .collect();
    let mut script = String::from(PRELUDE);
    for job in &jobs {
        let _ = writeln!(script, "# {}\n{}", job.name, job.ruby);
    }
    std::fs::write(dir.join("batch.drc"), &script).expect("the scratch directory is writable");
    oracle::run(klayout, &["-b", "-r", "batch.drc"], &dir, LIMIT);
    let mut tally = Tally::default();
    for (i, job) in jobs.iter().enumerate() {
        let text = std::fs::read_to_string(dir.join(format!("{i}.jsonl"))).unwrap_or_default();
        let m = if text.is_empty() {
            Measured {
                errors: vec!["no output".to_owned()],
                ..Measured::default()
            }
        } else {
            Measured::parse(&text)
        };
        compare(job, &m, &mut tally);
    }
    if tally.broken.is_empty() {
        let _ = std::fs::remove_dir_all(&dir);
    } else {
        tally.broken.push(super::kept(&dir));
    }
    tally
}

/// Every fixture through `GPurify` and `KLayout`, [`BATCH`] per process on
/// [`oracle::MAX_RUNNING`] threads; fails listing every disagreement.
fn compare_all(fixtures: &[Fixture]) -> Tally {
    let klayout = oracle::tool("klayout");
    let chunks: Vec<&[Fixture]> = fixtures.chunks(BATCH).collect();
    let next = AtomicUsize::new(0);
    let total = Mutex::new(Tally::default());
    std::thread::scope(|scope| {
        for _ in 0..oracle::MAX_RUNNING {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(chunk) = chunks.get(i) else {
                    break;
                };
                let found = batch(&klayout, chunk);
                let mut total = total.lock().expect("not poisoned");
                total.fixtures += found.fixtures;
                total.rows += found.rows;
                total.agreed += found.agreed;
                total.not_run += found.not_run;
                for (why, n) in found.skipped {
                    *total.skipped.entry(why).or_default() += n;
                }
                total.broken.extend(found.broken);
            });
        }
    });
    let total = total.into_inner().expect("not poisoned");
    println!(
        "klayout antenna: {} fixtures, {} rows compared, {} flagged nets agree, \
         {} rows GPurify did not run, not mirrored {:?}, {} broken",
        total.fixtures,
        total.rows,
        total.agreed,
        total.not_run,
        total.skipped,
        total.broken.len()
    );
    assert!(
        total.broken.is_empty(),
        "{} disagreements (first 60):\n{}",
        total.broken.len(),
        total.broken[..total.broken.len().min(60)].join("\n")
    );
    total
}

/// A seeded board as a fixture: every row of the board deck.
pub(super) fn board_fixture(seed: u64) -> Fixture {
    Fixture::new(
        &format!("erc/antenna_board/{seed}"),
        &["ERC-A1", "ERC-A2", "ERC-A3", "ERC-A4", "ERC-A8"],
        &antenna_board::deck(),
        ERC,
    )
    .layout(Board::random(seed).layout())
}

/// X4's antenna fixtures (LEF/DEF Figure C-20 at every limit, the sidewall
/// shapes, the derived gate, oxide classes, the MIM victim, the F29 and F72
/// cases, IHP Figure 7.1, the diode rows) and 300 seeded boards: every net
/// `antenna_check` flags, and every gate group of a cumulative row, carries
/// one `GPurify` violation with the same ratio, and nothing else does.
///
/// Oracle: differential against `KLayout`'s `antenna_check` (module docs).
/// The nightly `oracles` job runs it.
#[test]
#[ignore = "release tier: needs klayout (nix develop .#oracles)"]
fn klayout_antenna_differential_on_the_x4_fixtures_and_random_boards() {
    let mut fixtures = [
        super::antenna_lef(),
        super::antenna_sidewall(),
        super::antenna_variants(),
        super::antenna_electrical(),
    ]
    .concat();
    fixtures.extend((0..BOARDS).map(board_fixture));
    let total = compare_all(&fixtures);
    assert_eq!(total.fixtures, fixtures.len(), "every fixture ran");
    assert!(
        total.rows > 4000 && total.agreed > 3000,
        "too few comparisons: {} rows, {} flagged nets",
        total.rows,
        total.agreed
    );
}
