//! The `KLayout` mirror deck (L6, ledger F1): every DRC rule `GPurify` runs,
//! translated into a `KLayout` DRC script and run on the same GDS, rule by
//! rule, on the corpus and on a sample of the exhaustive DRC fixtures.
//!
//! The translation and each kind's verdict (exact, approximate with its
//! bracket, or not mirrored) are `docs/klayout-mirror.md`'s. A disagreement
//! fails the test unless a documented implementation difference explains it
//! (testing-plan F88).
//!
//! `KLayout` runs only in the oracle shell, so the comparisons are the release
//! tier: `nix develop .#oracles --command cargo test --test klayout -- --ignored`.
//! The merge tier checks that every deck the repository ships translates.
//! [`xor`] holds `gpurify xor` to `KLayout`'s XOR the same way.

mod compare;
mod lefdef;
mod translate;
mod xor;

#[path = "../common/lefdef_gen.rs"]
mod lefdef_gen;

#[path = "../exhaustive/bitmap.rs"]
mod bitmap;
#[path = "../exhaustive/drc_dimension.rs"]
mod drc_dimension;
#[path = "../exhaustive/drc_overlay.rs"]
mod drc_overlay;
#[path = "../common/gen_fixtures.rs"]
mod gen_fixtures;
#[path = "../exhaustive/harness.rs"]
mod harness;

use compare::{Finding, Klayout, Outcome};
use gpurify::check::report::{Measurement, Outcome as Ran};
use gpurify::engine::pipeline::{extract, load, Inputs, Loaded};
use gpurify::engine::run::{run_checks, Checks, Outputs, RunOptions};
use gpurify::geom::{Grid, PolyId};
use gpurify_ingest::deck::parse_deck;
use gpurify_ingest::StrTable;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use translate::{translate, Mirror, Verdict, PRELUDE};

/// One layout, its deck's mirror, and what `GPurify` reported.
struct Job {
    name: String,
    gds: PathBuf,
    ruby: String,
    mirrors: Vec<Mirror>,
    /// Per rule id: its outcome and findings.
    gpurify: BTreeMap<String, (Ran, Vec<Finding>)>,
}

fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// An empty directory for one run's files, so nothing a previous run wrote
/// can be read as this run's output.
fn scratch(tag: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("klayout-mirror")
        .join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the target temp dir is writable");
    dir
}

/// `GPurify`'s report, per rule, with each finding's shapes as vertices.
fn reported(loaded: &Loaded, outputs: &Outputs) -> BTreeMap<String, (Ran, Vec<Finding>)> {
    let name = |id| loaded.strings.resolve(id).to_owned();
    let mut out: BTreeMap<String, (Ran, Vec<Finding>)> = outputs
        .runs
        .iter()
        .map(|run| (name(run.rule), (run.outcome, Vec::new())))
        .collect();
    let v = &outputs.violations;
    let verts = |row: PolyId| {
        (row.0 != u32::MAX).then(|| {
            let (xs, ys) = loaded.store.poly_verts(row);
            xs.iter().zip(ys).map(|(x, y)| (x.raw(), y.raw())).collect()
        })
    };
    for i in 0..v.len() {
        #[allow(clippy::cast_precision_loss, reason = "test magnitudes fit an f64")]
        let measured = match v.measured[i] {
            Measurement::Length(d) => d.raw() as f64,
            Measurement::Area(a) => a.raw() as f64,
            Measurement::Ratio(r) => r,
            Measurement::Count(c) => f64::from(c),
            other => panic!("a DRC finding measures {other:?}"),
        };
        let finding = Finding {
            at: (v.at[i].x.raw(), v.at[i].y.raw()),
            measured,
            a: verts(v.shape_a[i]),
            b: v.shape_b[i].and_then(verts),
        };
        if let Some((_, findings)) = out.get_mut(&name(v.rule[i])) {
            findings.push(finding);
        }
    }
    out
}

fn drc() -> Checks {
    Checks {
        drc: true,
        ..harness::NONE
    }
}

/// Every corpus DRC cell, on `params.deck`.
fn corpus_jobs() -> Vec<Job> {
    let root = gen_fixtures::fixtures();
    let deck_path = root.join("params.deck");
    let text = std::fs::read_to_string(&deck_path).expect("the corpus deck");
    let mut strings = StrTable::default();
    let deck = parse_deck(&text, Grid::new(1000).expect("1 nm"), &mut strings)
        .expect("the corpus deck parses");
    let script = translate(&deck, &strings).expect("the corpus deck translates");
    let mut ids: Vec<PathBuf> = std::fs::read_dir(root.join("drc"))
        .expect("the corpus is generated")
        .map(|e| e.expect("a directory entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "gds"))
        .collect();
    ids.sort();
    ids.into_iter()
        .filter_map(|gds| {
            let inputs = Inputs {
                layout: gds.clone(),
                deck: deck_path.clone(),
                reference: Vec::new(),
                intent: None,
                lef: Vec::new(),
            };
            // A cell the reader refuses has no DRC report to compare.
            let loaded = load(&inputs).ok()?;
            let extracted = extract(&loaded).ok()?;
            let options = RunOptions {
                checks: drc(),
                lvs: gpurify::check::lvs::CompareOptions::default(),
                quasistatic_nets: Vec::new(),
            };
            let (outputs, _) = run_checks(&loaded, &extracted, &options).ok()?;
            Some(Job {
                name: format!(
                    "corpus/{}",
                    gds.file_stem().expect("a name").to_string_lossy()
                ),
                gpurify: reported(&loaded, &outputs),
                gds,
                ruby: script.ruby.clone(),
                mirrors: script.mirrors.clone(),
            })
        })
        .collect()
}

/// Threads that run `GPurify`, and `KLayout` processes, at once: the machine
/// is shared with other builds, and each `KLayout` holds its own interpreter.
fn workers() -> usize {
    std::thread::available_parallelism()
        .map_or(4, usize::from)
        .min(4)
}

/// Layouts per round: run through both tools, compared, then dropped, so a
/// long list never holds every script and report at once.
const ROUND: usize = 1000;

/// Each fixture run through `GPurify`, its layout written as GDS for `KLayout`.
/// A fixture whose inputs are refused on purpose has no report to compare and
/// is left out.
fn jobs_of(fixtures: &[harness::Fixture], tag: &str) -> Vec<Job> {
    let dir = scratch(&format!("{tag}-gds"));
    let per = fixtures.len().div_ceil(workers()).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = fixtures
            .chunks(per)
            .enumerate()
            .map(|(c, chunk)| {
                let dir = &dir;
                scope.spawn(move || {
                    chunk
                        .iter()
                        .enumerate()
                        .filter_map(|(i, fixture)| {
                            let (bytes, deck, strings) = harness::written(fixture).ok()?;
                            let ran = harness::run(fixture).ok()?;
                            let script =
                                translate(&deck, &strings).expect("a fixture deck translates");
                            let gds = dir.join(format!("{}.gds", c * per + i));
                            std::fs::write(&gds, bytes).expect("writable");
                            Some(Job {
                                name: fixture.name.clone(),
                                gds,
                                ruby: script.ruby,
                                mirrors: script.mirrors,
                                gpurify: reported(&ran.loaded, &ran.outputs),
                            })
                        })
                        .collect::<Vec<Job>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("building a job does not panic"))
            .collect()
    })
}

/// Runs every job's mirror, a batch of jobs per `KLayout` process, and returns
/// what each wrote.
fn run_klayout(jobs: &[Job], tag: &str) -> Vec<Klayout> {
    let found = Command::new("klayout").arg("-v").output();
    assert!(
        found.is_ok_and(|o| o.status.success()),
        "klayout is not on PATH: run this test inside `nix develop .#oracles`"
    );
    let dir = scratch(tag);
    let per = jobs.len().div_ceil(workers()).max(1);
    std::thread::scope(|scope| {
        for (b, batch) in jobs.chunks(per).enumerate() {
            let dir = &dir;
            scope.spawn(move || {
                let mut script = String::from(PRELUDE);
                for (i, job) in batch.iter().enumerate() {
                    let out = dir.join(format!("{}.jsonl", b * per + i));
                    write!(
                        script,
                        "# {name}\nbegin\n  $out = File.open({o:?}, \"w\")\n  src = source({g:?}).global_transform(magnify(2))\n{body}rescue => e\n  put({{ error: e.message + \" at \" + e.backtrace.first.to_s }})\nensure\n  $out.close\nend\n",
                        name = job.name,
                        o = out.display().to_string(),
                        g = job.gds.display().to_string(),
                        body = job.ruby
                    )
                    .expect("a String");
                }
                let path = dir.join(format!("batch{b}.drc"));
                std::fs::write(&path, script).expect("writable");
                let run = Command::new("klayout")
                    .args(["-b", "-r"])
                    .arg(&path)
                    .output()
                    .expect("klayout runs");
                assert!(
                    run.status.success(),
                    "{}: {}",
                    path.display(),
                    String::from_utf8_lossy(&run.stderr)
                );
            });
        }
    });
    (0..jobs.len())
        .map(
            |i| match std::fs::read_to_string(dir.join(format!("{i}.jsonl"))) {
                Ok(text) => Klayout::parse(&text),
                Err(why) => Klayout {
                    errors: vec![format!("no output: {why}")],
                    ..Klayout::default()
                },
            },
        )
        .collect()
}

/// Per kind: agree, of which something was found, explained by a documented
/// difference, not compared, `GPurify` skipped, not mirrored, disagree.
type Table = BTreeMap<&'static str, [usize; 7]>;

/// What the rounds of one differential add up to.
#[derive(Default)]
struct Tally {
    table: Table,
    known: Vec<String>,
    failures: Vec<String>,
    layouts: usize,
}

/// Compares every round of jobs, prints a table per kind, and fails on a
/// disagreement.
fn differential(tag: &str, rounds: impl Iterator<Item = Vec<Job>>) {
    let mut tally = Tally::default();
    for jobs in rounds {
        compare_round(&jobs, tag, &mut tally);
    }
    let Tally {
        table,
        known,
        mut failures,
        layouts,
    } = tally;
    assert!(layouts > 0, "{tag}: no layout to compare");
    println!("{tag}: {layouts} layouts");
    println!(
        "{:<24} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6}",
        "kind", "agree", "found", "known", "class", "skip", "none", "differ"
    );
    for (kind, row) in &table {
        println!(
            "{kind:<24} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6} {:>6}",
            row[0], row[1], row[2], row[3], row[4], row[5], row[6]
        );
    }
    for line in &known {
        println!("{line}");
    }
    let found: usize = table.values().map(|r| r[1] + r[6]).sum();
    assert!(found > 0, "{tag}: no rule found anything on either side");
    failures.sort();
    assert!(
        failures.is_empty(),
        "{tag}: {} disagreements:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// One round: `KLayout` on every job, then each rule compared into `tally`.
fn compare_round(jobs: &[Job], tag: &str, tally: &mut Tally) {
    tally.layouts += jobs.len();
    let results = run_klayout(jobs, tag);
    for (job, kl) in jobs.iter().zip(&results) {
        if !kl.errors.is_empty() {
            tally
                .failures
                .push(format!("{}: KLayout: {}", job.name, kl.errors.join("; ")));
            continue;
        }
        for m in &job.mirrors {
            let row = tally.table.entry(m.kind).or_default();
            let Some((outcome, findings)) = job.gpurify.get(&m.id) else {
                tally
                    .failures
                    .push(format!("{} {}: no GPurify row", job.name, m.id));
                continue;
            };
            if let Verdict::None(_) = m.verdict {
                row[5] += 1;
                continue;
            }
            if *outcome != Ran::Ran {
                row[4] += 1;
                continue;
            }
            let at = || format!("{} {} ({})", job.name, m.id, m.kind);
            match compare::compare(m, kl, findings) {
                Outcome::Agree(found) => {
                    row[0] += 1;
                    row[1] += usize::from(found);
                }
                Outcome::Known(finding, why) => {
                    row[2] += 1;
                    tally.known.push(format!("{finding}: {}: {why}", at()));
                }
                Outcome::NotCompared => row[3] += 1,
                Outcome::Disagree(why) => {
                    row[6] += 1;
                    tally.failures.push(format!("{}: {why}", at()));
                }
            }
        }
    }
}

/// A deck with a rule of most kinds on three layers, limits on the scale of
/// [`random_fixtures`]'s rectangles.
const RANDOM_DECK: &str = "grid 1nm
layer met1 = gds(68, 20)
layer met2 = gds(69, 20)
layer via1 = gds(68, 44)
layer both = met1 and met2
layer grown = met1.sized(20nm)
layer big = met1.with_area(>= 50000nm2)
layer narrow = met1.with_width(< 150nm)
layer touched = met1.interacting(met2)
layer cut = met1 not met2
layer edge = met1.edges() not met2.edges()
layer seam = met1.edges() and met2.edges()
layer inner = met1.edges().inside_part(met2)
connect conductors [met1, met2]
connect touch_within_layer
connect via via1 [met1, met2]
rule w width(met1) >= 100nm
rule mw width(met1) <= 400nm
rule el edge_length(met1) >= 60nm
rule n notch(met1) >= 100nm
rule s space(met1) >= 100nm
rule sd space(met1, met2) >= 80nm
rule eol eol_space(met1; eol_width: 120nm) >= 150nm
rule prl prl_space(met1; prl: 300nm) >= 150nm
rule cc corner_space(met1) >= 150nm
rule ws wide_space(met1; width: 300nm) >= 200nm
rule aws wide_space(met1; width: 300nm, attached: 100nm) >= 200nm
rule a area(met1) >= 30000nm2
rule ha hole_area(met1) >= 30000nm2
rule ch cheesing(met1) <= 200000nm2
rule d density(met1; window: 500nm, step: 250nm) >= 0.3
rule gd global_density(met1) <= 0.5
rule enc enclosure(via1, met1) >= 30nm
rule asym enclosure(via1, met1, opposite) >= 40nm
rule ext extension(met2, met1) >= 50nm
rule ov overlap(met1, met2) >= 60nm
rule rv redundant_via(via1; within: 200nm) >= 2
rule vas via_array_space(via1; array: 2) >= 100nm
rule c2c space(via1, center) >= 100nm
rule adj adjacent_space(via1; cuts: 2, within: 150nm) >= 100nm
rule adjc adjacent_space(via1, center; cuts: 1, within: 120nm) >= 110nm
rule mc contains(met1, via1) >= 1
rule mi inside(via1, met1)
rule cs size(via1) == 50nm x 50nm
rule f forbidden(met2.with_area(< 20000nm2))
rule bw width(grown) >= 150nm
rule bs space(big) >= 150nm
rule bn notch(narrow) >= 80nm
rule ba area(both) >= 10000nm2
rule ts space(touched, cut) >= 50nm
rule fe forbidden(seam)
rule fi forbidden(inner)
rule el2 length(edge) >= 80nm
rule es space(edge) >= 50nm
rule ee enclosure(edge, met2) >= 30nm
rule sn space(met1; nets: same) >= 120nm
rule dn space(met1; nets: different) >= 120nm
rule tab space_table(met1; prl: [0nm, 200nm], width: [0nm, 200nm], space: [[100nm, 120nm], [140nm, 160nm]])
rule tw two_width_table(met1; width: [0nm, 200nm], prl: [none, 100nm], space: [[100nm, 120nm], [120nm, 160nm]])
rule tip tip_space_table(met1; length: [0nm, 60nm, 200nm], space: [[150nm, 150nm, 120nm], [150nm, 130nm, 120nm], [120nm, 120nm, 100nm]])
rule fs forbidden_space(met1; min: 100nm, max: 150nm, prl: 100nm)
rule ccs corner_space(met1; corner_to_corner: false, except_eol: none) >= 150nm
rule tap tap_distance(met1, via1) <= 300nm
rule og off_grid(; pitch: 20nm)
rule ang angle(; allowed: [0deg, 90deg])
";

/// Random rectangles on [`RANDOM_DECK`]'s layers, on a 10 nm lattice so
/// shapes often touch, abut and align, from fixed seeds.
fn random_fixtures(count: u64) -> Vec<harness::Fixture> {
    (0..count)
        .map(|seed| {
            let mut rng = gpurify_testgen::Rng::new(seed);
            let mut layout = harness::Layout::default();
            for (layer, n, size) in [("met1", 8, 60), ("met2", 3, 40), ("via1", 5, 8)] {
                for _ in 0..rng.range(1, n) {
                    let (x, y) = (rng.range(0, 160) * 10, rng.range(0, 160) * 10);
                    let (w, h) = (rng.range(1, size) * 10, rng.range(1, size) * 10);
                    layout = layout.rect(layer, x, y, x + w, y + h);
                }
            }
            harness::Fixture::new(&format!("random/{seed}"), &[], RANDOM_DECK, drc()).layout(layout)
        })
        .collect()
}

/// A deck of the kinds that measure 45-degree shapes (H12), and the derived
/// layers that feed them. `sized` and `with_width` are left out: on a 45-degree
/// edge `sized` is the Minkowski sum with the square (`docs/deck.md`), which
/// `KLayout`'s normal shift is not, a documented difference.
const OCTILINEAR_DECK: &str = "grid 1nm
layer met1 = gds(68, 20)
layer met2 = gds(69, 20)
layer via1 = gds(68, 44)
layer both = met1 and met2
layer cut = met1 not met2
layer all = met1 or met2
connect conductors [met1, met2]
connect touch_within_layer
rule w width(met1) >= 100nm
rule el edge_length(met1) >= 60nm
rule n notch(met1) >= 100nm
rule s space(met1) >= 100nm
rule sd space(met1, met2) >= 80nm
rule a area(met1) >= 30000nm2
rule ha hole_area(met1) >= 30000nm2
rule f forbidden(met2.with_area(< 20000nm2))
rule ba area(both) >= 10000nm2
rule cn notch(cut) >= 100nm
rule as space(all) >= 100nm
rule ang angle(; allowed: [0deg, 45deg, 90deg, 135deg])
rule en enclosure(met2, met1) >= 50nm
rule enn enclosure(met2, met1, noncoincident) >= 50nm
rule ev enclosure(via1, met1) >= 30nm
rule evn enclosure(via1, met1, noncoincident) >= 30nm
rule eo enclosure(via1, met1, opposite) >= 30nm
rule ea enclosure(via1, met1, adjacent) >= 30nm
rule mi inside(met2, met1)
rule miv inside(via1, met1)
rule mc contains(met1, via1) >= 1
";

/// The bounding box of a ring, `(xlo, ylo, xhi, yhi)`.
fn ring_box(ring: &[(i64, i64)]) -> (i64, i64, i64, i64) {
    let xs = ring.iter().map(|p| p.0);
    let ys = ring.iter().map(|p| p.1);
    (
        xs.clone().min().expect("a ring"),
        ys.clone().min().expect("a ring"),
        xs.max().expect("a ring"),
        ys.max().expect("a ring"),
    )
}

/// One random 45-degree shape on a 10 nm lattice: a rectangle with chamfered
/// corners (an octagon when all four are cut), or a bar at 45 degrees whose
/// ends are cut by a step, so no corner is acute.
fn octilinear_shape(rng: &mut gpurify_testgen::Rng, size: i64) -> Vec<(i64, i64)> {
    let (x, y) = (rng.range(0, 150) * 10, rng.range(0, 150) * 10);
    if rng.range(0, 2) == 0 {
        let (w, h) = (rng.range(2, size) * 10, rng.range(2, size) * 10);
        let most = w.min(h) / 20;
        let c: Vec<i64> = (0..4).map(|_| rng.range(0, most + 1) * 10).collect();
        let mut ring = vec![
            (x + c[0], y),
            (x + w - c[1], y),
            (x + w, y + c[1]),
            (x + w, y + h - c[2]),
            (x + w - c[2], y + h),
            (x + c[3], y + h),
            (x, y + h - c[3]),
            (x, y + c[0]),
        ];
        ring.dedup();
        while ring.len() > 1 && ring.first() == ring.last() {
            ring.pop();
        }
        return ring;
    }
    // A bar between the lines y = x + c and y = x + c + d, `len` long in x.
    let (d, len) = (rng.range(1, size / 2) * 20, rng.range(2, size) * 10);
    let s = d / 2;
    let bar = [
        (0, 0),
        (len, len),
        (len, len + d - s),
        (len - s, len + d - s),
        (-s, d - s),
        (-s, 0),
    ];
    // Rising, or mirrored in x (and re-wound) to fall.
    if rng.range(0, 2) == 0 {
        bar.iter().map(|&(bx, by)| (x + bx, y + by)).collect()
    } else {
        bar.iter().rev().map(|&(bx, by)| (x - bx, y + by)).collect()
    }
}

/// Random 45-degree and rectilinear shapes on [`OCTILINEAR_DECK`]'s layers.
/// On a 10 nm lattice every crossing of two 45-degree edges falls on a 5 nm
/// point, on the 1 nm grid, so no vertex is snapped and the comparison is of
/// the measures alone.
fn octilinear_fixtures(count: u64) -> Vec<harness::Fixture> {
    (0..count)
        .map(|seed| {
            let mut rng = gpurify_testgen::Rng::new(seed ^ 0x45_45);
            let mut layout = harness::Layout::default();
            let mut boxes = Vec::new();
            for (layer, n, size) in [("met1", 7, 40), ("met2", 3, 30)] {
                for _ in 0..rng.range(1, n) {
                    let ring = octilinear_shape(&mut rng, size);
                    if layer == "met1" {
                        boxes.push(ring_box(&ring));
                    }
                    layout = layout.polygon(layer, &ring);
                }
            }
            // A square cut in some met1 shapes' boxes, mostly hosted, some
            // past a chamfer; its own stream so the shapes above are as
            // before. Cuts never meet: an enclosure reads each drawn cut on
            // its own (`docs/deck.md`), the mirror's `enclosed` their merge.
            let mut cuts = gpurify_testgen::Rng::new(seed ^ 0xc0_7c);
            let mut placed: Vec<(i64, i64, i64)> = Vec::new();
            for (x0, y0, x1, y1) in boxes {
                if cuts.range(0, 3) == 0 {
                    continue;
                }
                let side = cuts.range(2, 7) * 10;
                if x1 - x0 <= side || y1 - y0 <= side {
                    continue;
                }
                let x = x0 + cuts.range(0, (x1 - x0 - side) / 10 + 1) * 10;
                let y = y0 + cuts.range(0, (y1 - y0 - side) / 10 + 1) * 10;
                let apart = |&(px, py, ps): &(i64, i64, i64)| {
                    x > px + ps || px > x + side || y > py + ps || py > y + side
                };
                if !placed.iter().all(apart) {
                    continue;
                }
                placed.push((x, y, side));
                layout = layout.polygon(
                    "via1",
                    &[(x, y), (x + side, y), (x + side, y + side), (x, y + side)],
                );
            }
            harness::Fixture::new(&format!("octilinear/{seed}"), &[], OCTILINEAR_DECK, drc())
                .layout(layout)
        })
        .collect()
}

/// DRC-038, DRC-037, DRC-002: the kinds that measure 45-degree shapes against
/// `KLayout`'s same checks.
///
/// Oracle: differential against `KLayout`, through the mirror deck, on 1500
/// random layouts of chamfered rectangles, octagons and 45-degree bars, each
/// rule compared as its verdict states.
#[test]
#[ignore = "release tier: needs klayout (nix develop .#oracles)"]
fn random_octilinear_layouts_agree_with_the_klayout_mirror() {
    let fixtures = octilinear_fixtures(1500);
    differential(
        "octilinear",
        fixtures
            .chunks(ROUND)
            .map(|round| jobs_of(round, "octilinear")),
    );
}

/// The octilinear differential's layouts are valid and every rule of its deck
/// runs on them in `GPurify`, so the release-tier comparison compares rather
/// than counting refusals.
///
/// Oracle: the H12 scope (`docs/deck.md`, "45-degree geometry"): each kind in
/// [`OCTILINEAR_DECK`] measures 45-degree shapes, so none records `Refused`.
#[test]
fn the_octilinear_differential_layouts_run_every_rule() {
    let jobs = jobs_of(&octilinear_fixtures(40), "octilinear-merge");
    assert_eq!(jobs.len(), 40, "every layout loads and runs");
    for job in &jobs {
        for (id, (outcome, _)) in &job.gpurify {
            assert_ne!(*outcome, Ran::Refused, "{} {id}", job.name);
        }
    }
}

/// Oracle: differential against `KLayout`, through the mirror deck
/// `docs/klayout-mirror.md` documents, compared per rule as that rule's verdict
/// (EXACT or APPROX) states, on 3000 random layouts.
#[test]
#[ignore = "release tier: needs klayout (nix develop .#oracles)"]
fn random_layouts_agree_with_the_klayout_mirror() {
    let fixtures = random_fixtures(3000);
    differential(
        "random",
        fixtures.chunks(ROUND).map(|round| jobs_of(round, "random")),
    );
}

/// Oracle: differential against `KLayout`, through the mirror deck
/// `docs/klayout-mirror.md` documents, compared per rule as that rule's verdict
/// (EXACT or APPROX) states, on every corpus cell.
#[test]
#[ignore = "release tier: needs klayout (nix develop .#oracles)"]
fn every_corpus_cell_agrees_with_the_klayout_mirror() {
    differential("corpus", std::iter::once(corpus_jobs()));
}

/// Oracle: differential against `KLayout`, through the mirror deck
/// `docs/klayout-mirror.md` documents, compared per rule as that rule's verdict
/// (EXACT or APPROX) states, on every merge-depth DRC fixture under its
/// symmetries and translations.
#[test]
#[ignore = "release tier: needs klayout (nix develop .#oracles)"]
fn the_exhaustive_drc_fixtures_agree_with_the_klayout_mirror() {
    // Every DRC fixture of the merge depth: each layout under its symmetries
    // and translations.
    let depth = harness::Depth::Merge;
    let fixtures = [
        drc_dimension::fixtures(depth),
        drc_overlay::fixtures(depth),
        bitmap::fixtures(depth),
    ]
    .concat();
    differential(
        "fixtures",
        fixtures
            .chunks(ROUND)
            .map(|round| jobs_of(round, "fixtures")),
    );
}

/// Every deck the repository ships translates, and each DRC rule is either
/// mirrored or named as not mirrored with its reason.
///
/// Oracle: law. The Ruby script and the verdict table describe one translation:
/// a rule appears in the script exactly when its verdict is not `None`, for
/// every shipped deck.
#[test]
fn every_shipped_deck_translates() {
    let mut decks: Vec<PathBuf> = std::fs::read_dir(repo().join("pdks"))
        .expect("pdks/")
        .map(|e| e.expect("an entry").path())
        .filter(|p| p.extension().is_some_and(|e| e == "deck"))
        .collect();
    decks.push(repo().join("tests/fixtures/params.deck"));
    for path in decks {
        let text = std::fs::read_to_string(&path).expect("readable");
        let mut strings = StrTable::default();
        let deck = parse_deck(&text, Grid::new(1000).expect("1 nm"), &mut strings)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let script =
            translate(&deck, &strings).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        for m in &script.mirrors {
            let mirrored = script.ruby.contains(&format!("'{}'", m.id));
            assert_eq!(
                mirrored,
                !matches!(m.verdict, Verdict::None(_)),
                "{}: {} ({})",
                path.display(),
                m.id,
                m.kind
            );
        }
    }
}

/// A deck of the kinds that measure shapes at any angle (DRC-116), and the
/// booleans that feed them. `sized` and `with_width` are left out as in
/// [`OCTILINEAR_DECK`]; so are opposite and adjacent enclosure, which refuse
/// such edges, and `angle`, whose allowed list a skew edge breaks by design.
const ANYANGLE_DECK: &str = "grid 1nm
layer met1 = gds(68, 20)
layer met2 = gds(69, 20)
layer via1 = gds(68, 44)
layer both = met1 and met2
layer cut = met1 not met2
layer all = met1 or met2
connect conductors [met1, met2]
connect touch_within_layer
rule w width(met1) >= 100nm
rule el edge_length(met1) >= 60nm
rule n notch(met1) >= 100nm
rule s space(met1) >= 100nm
rule sd space(met1, met2) >= 80nm
rule a area(met1) >= 30000nm2
rule ha hole_area(cut) >= 30000nm2
rule cw width(cut) >= 60nm
rule f forbidden(met2.with_area(< 20000nm2))
rule ba area(both) >= 10000nm2
rule cn notch(cut) >= 100nm
rule as space(all) >= 100nm
rule en enclosure(met2, met1) >= 50nm
rule enn enclosure(met2, met1, noncoincident) >= 50nm
rule ev enclosure(via1, met1) >= 30nm
rule evn enclosure(via1, met1, noncoincident) >= 30nm
rule mi inside(met2, met1)
rule miv inside(via1, met1)
rule mc contains(met1, via1) >= 1
";

/// Even-odd: whether the grid point `p` is strictly inside `ring` (on an
/// edge is not).
fn strictly_inside(ring: &[(i64, i64)], p: (i64, i64)) -> bool {
    let n = ring.len();
    let mut odd = false;
    for i in 0..n {
        let (a, b) = (ring[i], ring[(i + 1) % n]);
        let side = (b.0 - a.0) * (p.1 - a.1) - (b.1 - a.1) * (p.0 - a.0);
        let within = (a.0.min(b.0)..=a.0.max(b.0)).contains(&p.0)
            && (a.1.min(b.1)..=a.1.max(b.1)).contains(&p.1);
        if side == 0 && within {
            return false;
        }
        if (a.1 > p.1) != (b.1 > p.1) && (side > 0) == (b.1 > a.1) {
            odd = !odd;
        }
    }
    odd
}

/// Whether two closed segments share a point.
fn segments_meet(p: ((i64, i64), (i64, i64)), q: ((i64, i64), (i64, i64))) -> bool {
    let cross = |o: (i64, i64), a: (i64, i64), b: (i64, i64)| {
        ((a.0 - o.0) * (b.1 - o.1) - (a.1 - o.1) * (b.0 - o.0)).signum()
    };
    let on = |s: ((i64, i64), (i64, i64)), r: (i64, i64)| {
        r.0 >= s.0 .0.min(s.1 .0)
            && r.0 <= s.0 .0.max(s.1 .0)
            && r.1 >= s.0 .1.min(s.1 .1)
            && r.1 <= s.0 .1.max(s.1 .1)
    };
    let (d1, d2) = (cross(q.0, q.1, p.0), cross(q.0, q.1, p.1));
    let (d3, d4) = (cross(p.0, p.1, q.0), cross(p.0, p.1, q.1));
    (d1 * d2 < 0 && d3 * d4 < 0)
        || (d1 == 0 && on(q, p.0))
        || (d2 == 0 && on(q, p.1))
        || (d3 == 0 && on(p, q.0))
        || (d4 == 0 && on(p, q.1))
}

/// Whether `inner` lies strictly inside `outer`: every vertex inside and no
/// two edges meeting.
fn strictly_within(inner: &[(i64, i64)], outer: &[(i64, i64)]) -> bool {
    let edges = |r: &[(i64, i64)]| -> Vec<((i64, i64), (i64, i64))> {
        (0..r.len()).map(|i| (r[i], r[(i + 1) % r.len()])).collect()
    };
    inner.iter().all(|&p| strictly_inside(outer, p))
        && edges(inner)
            .iter()
            .all(|&e| edges(outer).iter().all(|&f| !segments_meet(e, f)))
}

/// A star-shaped polygon at any angle round `(cx, cy)` on a 10 nm lattice:
/// 3 to 8 vertices at distinct angles round the centre, up to `reach` from
/// it, counter-clockwise.
fn star(rng: &mut gpurify_testgen::Rng, (cx, cy): (i64, i64), reach: i64) -> Vec<(i64, i64)> {
    loop {
        let n = rng.range(3, 9);
        let mut pts: Vec<(i64, i64)> = (0..n)
            .map(|_| {
                (
                    cx + rng.range(-reach, reach + 1) * 10,
                    cy + rng.range(-reach, reach + 1) * 10,
                )
            })
            .filter(|&p| p != (cx, cy))
            .collect();
        let half = |(x, y): (i64, i64)| y < cy || (y == cy && x < cx);
        let turn = |p: (i64, i64), q: (i64, i64)| (p.0 - cx) * (q.1 - cy) - (p.1 - cy) * (q.0 - cx);
        pts.sort_by(|&p, &q| half(p).cmp(&half(q)).then_with(|| 0.cmp(&turn(p, q))));
        let k = pts.len();
        let distinct = pts
            .windows(2)
            .all(|w| !(turn(w[0], w[1]) == 0 && half(w[0]) == half(w[1])));
        if k >= 3 && distinct && (0..k).all(|i| turn(pts[i], pts[(i + 1) % k]) > 0) {
            return pts;
        }
    }
}

/// Random shapes at any angle on [`ANYANGLE_DECK`]'s layers, on a 10 nm
/// lattice. No two edges cross between grid points, so nothing is rounded
/// and the comparison is of the measures alone: each met1 star sits in its
/// own 600 nm cell (neighbours come close, never overlap), and each met2
/// star and via1 square lies strictly inside a met1 star (a shrunk copy, kept
/// only when it is inside) or alone in an empty cell.
fn anyangle_fixtures(count: u64) -> Vec<harness::Fixture> {
    (0..count)
        .map(|seed| {
            let mut rng = gpurify_testgen::Rng::new(seed ^ 0xa1_1a);
            let mut layout = harness::Layout::default();
            for cell in 0..9i64 {
                let (ox, oy) = ((cell % 3) * 600, (cell / 3) * 600);
                // The centre at least `reach` lattice steps inside the cell.
                let reach = rng.range(3, 30);
                let free = 60 - 2 * reach;
                let centre = |rng: &mut gpurify_testgen::Rng| {
                    (
                        ox + (reach + rng.range(0, free.max(0) + 1)) * 10,
                        oy + (reach + rng.range(0, free.max(0) + 1)) * 10,
                    )
                };
                match rng.range(0, 6) {
                    0 => {}
                    1 => {
                        let c = centre(&mut rng);
                        layout = layout.polygon("met2", &star(&mut rng, c, reach));
                    }
                    _ => {
                        let c = centre(&mut rng);
                        let outer = star(&mut rng, c, reach);
                        layout = layout.polygon("met1", &outer);
                        if rng.range(0, 2) == 0 {
                            // Shrunk about the centre, which every star sees whole.
                            let k = rng.range(2, 8);
                            let inner: Vec<(i64, i64)> = outer
                                .iter()
                                .map(|&(x, y)| {
                                    (
                                        c.0 + ((x - c.0) * k / 10).div_euclid(10) * 10,
                                        c.1 + ((y - c.1) * k / 10).div_euclid(10) * 10,
                                    )
                                })
                                .collect();
                            let mut inner = inner;
                            inner.dedup();
                            while inner.len() > 1 && inner.first() == inner.last() {
                                inner.pop();
                            }
                            // Still a star round `c`: each turn round it under 180
                            // degrees and positive, so the ring is simple.
                            let k = inner.len();
                            let star_round_c = k >= 3
                                && (0..k).all(|i| {
                                    let (p, q) = (inner[i], inner[(i + 1) % k]);
                                    (p.0 - c.0) * (q.1 - c.1) - (p.1 - c.1) * (q.0 - c.0) > 0
                                });
                            if star_round_c && strictly_within(&inner, &outer) {
                                layout = layout.polygon("met2", &inner);
                            }
                        }
                        if rng.range(0, 2) == 0 {
                            let side = rng.range(2, 6) * 10;
                            let (x, y) = (c.0 + rng.range(-3, 3) * 10, c.1 + rng.range(-3, 3) * 10);
                            let square =
                                [(x, y), (x + side, y), (x + side, y + side), (x, y + side)];
                            if strictly_within(&square, &outer) {
                                layout = layout.polygon("via1", &square);
                            }
                        }
                    }
                }
            }
            harness::Fixture::new(&format!("anyangle/{seed}"), &[], ANYANGLE_DECK, drc())
                .layout(layout)
        })
        .collect()
}

/// DRC-116: the kinds that measure shapes at any angle against `KLayout`'s
/// same checks.
///
/// Oracle: differential against `KLayout`, through the mirror deck, on 1500
/// random layouts of star-shaped polygons at any angle (`docs/klayout-mirror.md`
/// a9), each rule compared as its verdict states.
#[test]
#[ignore = "release tier: needs klayout (nix develop .#oracles)"]
fn random_anyangle_layouts_agree_with_the_klayout_mirror() {
    let fixtures = anyangle_fixtures(1500);
    differential(
        "anyangle",
        fixtures
            .chunks(ROUND)
            .map(|round| jobs_of(round, "anyangle")),
    );
}

/// The any-angle differential's layouts are valid, hold edges at angles
/// other than multiples of 45 degrees, and every rule of its deck runs on
/// them in `GPurify`, so the release-tier comparison compares rather than
/// counting refusals.
///
/// Oracle: the DRC-116 scope (`docs/deck.md`, "Geometry at any angle"):
/// each kind in [`ANYANGLE_DECK`] measures such shapes, so none records
/// `Refused`.
#[test]
fn the_anyangle_differential_layouts_run_every_rule() {
    let jobs = jobs_of(&anyangle_fixtures(40), "anyangle-merge");
    assert_eq!(jobs.len(), 40, "every layout loads and runs");
    for job in &jobs {
        for (id, (outcome, _)) in &job.gpurify {
            assert_ne!(*outcome, Ran::Refused, "{} {id}", job.name);
        }
    }
}
