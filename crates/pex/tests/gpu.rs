//! The device adapter, and `docs/GPU.md` contract item 5.
//!
//! **Every test here runs.** None is `#[ignore]`d, and that is the point: the
//! old tree's GPU-vs-CPU equality tests were nearly all ignored, so nothing
//! proved the two paths agreed and the `f32` downgrade shipped unmeasured on a
//! signoff path.
//!
//! Each test has two branches and takes exactly one of them:
//!
//!  - **no device** — asserts the *fallback* was taken, which is the whole
//!    fail-closed contract. A machine with no Vulkan loader must run the
//!    reference adapter and say so, not quietly produce nothing.
//!  - **a device** — asserts agreement with `CpuMatVec` within the documented
//!    tolerance.
//!
//! Which branch a run takes is printed, so a green result cannot be read as
//! "the device path was exercised" when it was not.

mod common;

use common::{extracted, grid, uniform_stack};
use gpurify_pex::quasistatic::gpu::{Device, GpuMatVec};
use gpurify_pex::quasistatic::matvec::{select, Backend, CpuMatVec, MatVec};
use gpurify_pex::quasistatic::mesh::{build_into, Mesh, MeshOptions};
use gpurify_testgen::{dbu, Rng};

/// The relative tolerance an `f32` matvec is held to against the `f64`
/// reference.
///
/// `f32` carries about seven significant decimal digits, and the fold is over
/// `n` terms, so the worst case grows with `√n` for uncorrelated rounding. `2e-5`
/// is that bound with room, at the panel counts these fixtures produce — and it
/// is a *tolerance*, deliberately, because the two paths cannot agree
/// bit-for-bit: the host folds in `f64` and the device in `f32`. That difference
/// is what `Backend` exists to attribute.
const F32_TOLERANCE: f64 = 2e-5;

/// One charge in `[-0.5, 0.5)`.
///
/// Structure rather than a constant: a constant charge vector is reproduced by
/// any operator whose rows sum alike, so it passes against a kernel reading the
/// wrong column. The top 53 bits of the generator go into the mantissa, which is
/// the usual construction and is exact.
fn unit(rng: &mut Rng) -> f64 {
    #[expect(clippy::cast_precision_loss, reason = "53 bits is exactly an f64 mantissa")]
    let raw = (rng.next_u64() >> 11) as f64 / (1_u64 << 53) as f64;
    raw - 0.5
}

/// A mesh of `conductors` plates, meshed finely enough to make a real matrix.
///
/// Built through the real `mesh_nets_into` rather than by hand, so the panel
/// table the device sees is the one a solve would hand it — including the
/// spatial sort, which is what makes panel order canonical and therefore makes
/// the two adapters' inputs identical.
fn plates(seed: u64, conductors: u32) -> Mesh {
    let case = extracted(seed, 6 * conductors, conductors);
    let mut mesh = Mesh::default();
    build_into(
        case.store(),
        &case.nets,
        &case.selected,
        &uniform_stack(3, 1.0, 0.25),
        MeshOptions {
            max_edge: dbu(400),
            proximity_refine: dbu(0),
            max_panels: 1 << 16,
        },
        grid(),
        &mut mesh,
    )
    .expect("the scale corpus meshes");
    mesh
}

/// Oracle: the contract. Probing is not itself a failure, and the two answers a
/// caller has to tell apart are the two the return type gives it: `Ok(None)` is
/// "no GPU here", `Err` is "a GPU is here and this is why it did not run".
///
/// A probe that returned `Err` for an absent device would make every headless
/// CI run look like a broken machine; one that returned `Ok(None)` for a
/// *rejected* device would hide a real GPU behind a silent fallback. Both
/// directions are wrong and the split is the whole of the signature.
#[test]
fn probing_for_a_device_distinguishes_absence_from_rejection() {
    match Device::find() {
        Ok(None) => println!("no device: the host adapter is the answer"),
        Ok(Some(device)) => {
            assert!(
                device.crossover() > 0,
                "a crossover of zero selects the device at every size including \
                 the empty problem, which is the fail-open reading of the \
                 sentinel that docs/GPU.md contract item 6 forbids"
            );
            println!("device present, crossover {}", device.crossover());
        }
        Err(why) => println!("a device is present and was rejected: {why}"),
    }
}

/// Oracle: differential, against the reference adapter — `docs/GPU.md` contract
/// item 5, and the test the old tree had and `#[ignore]`d.
///
/// The two adapters compute the same operator, one in `f64` and one in `f32`, so
/// they must agree to within [`F32_TOLERANCE`] on every element. Compared
/// element by element rather than on a norm: a norm hides a single wrong entry
/// among thousands of right ones, and a single wrong entry is a wrong
/// capacitance.
///
/// The no-device branch asserts the fallback instead, which is the same claim
/// stated where there is nothing to compare against.
#[test]
fn the_device_matvec_agrees_with_the_host_within_the_f32_tolerance() {
    let mesh = plates(31, 3);
    let host = CpuMatVec::build(&mesh);
    let n = host.dim();
    assert!(n > 0, "the fixture meshed to nothing");

    let Some(device) = Device::find().expect("probing is not a failure") else {
        assert_eq!(
            select(n, None),
            Backend::Cpu,
            "with no device the host adapter runs at every size"
        );
        println!("no device: fallback asserted over {n} panels");
        return;
    };

    let gpu = GpuMatVec::upload(&device, &mesh).expect("the mesh uploads");
    assert_eq!(gpu.dim(), n, "the two adapters see the same problem");
    assert_eq!(gpu.backend(), Backend::GpuF32, "the adapter names itself");

    // A charge vector with structure rather than a constant: a constant vector
    // is reproduced by any operator whose rows sum alike, and would pass against
    // a kernel that read the wrong column.
    let mut rng = Rng::new(0xC0FF_EE01);
    let x: Vec<f64> = (0..n).map(|_| unit(&mut rng)).collect();

    let mut want = vec![0.0; n];
    let mut got = vec![0.0; n];
    host.apply(&x, &mut want);
    gpu.apply(&x, &mut got);

    let scale = want.iter().fold(0.0_f64, |peak, v| peak.max(v.abs()));
    assert!(scale > 0.0, "the reference produced an all-zero potential");
    for i in 0..n {
        let error = (got[i] - want[i]).abs() / scale;
        assert!(
            error <= F32_TOLERANCE,
            "panel {i}: device {got:?} against host {want:?}, relative error \
             {error} past {F32_TOLERANCE}",
            got = got[i],
            want = want[i]
        );
    }
    println!("device agreed with the host over {n} panels");
}

/// Oracle: law — the operator is linear, so scaling the charge scales the
/// potential exactly. True of the device path whatever its precision, and it
/// fails against a kernel that has picked up a constant term or is reading a
/// stale buffer from the previous call.
///
/// That second failure is the one this is really for: `apply` replays a
/// pre-recorded command buffer, so a missing write-visibility barrier would show
/// up as "the second call returned the first call's answer", which this catches
/// and a single-call equality test does not.
#[test]
fn the_device_matvec_is_linear_in_the_charge_vector() {
    let mesh = plates(47, 2);
    let n = mesh.panel.len();
    assert!(n > 0, "the fixture meshed to nothing");

    let Some(device) = Device::find().expect("probing is not a failure") else {
        assert_eq!(select(n, None), Backend::Cpu, "the fallback is the host");
        println!("no device: fallback asserted over {n} panels");
        return;
    };
    let gpu = GpuMatVec::upload(&device, &mesh).expect("the mesh uploads");

    let mut rng = Rng::new(0x5EED_5EED);
    let x: Vec<f64> = (0..n).map(|_| unit(&mut rng)).collect();
    let tripled: Vec<f64> = x.iter().map(|v| 3.0 * v).collect();

    let mut once = vec![0.0; n];
    let mut thrice = vec![0.0; n];
    gpu.apply(&x, &mut once);
    gpu.apply(&tripled, &mut thrice);

    let scale = once.iter().fold(0.0_f64, |peak, v| peak.max(v.abs()));
    assert!(scale > 0.0, "the device produced an all-zero potential");
    for i in 0..n {
        let error = (thrice[i] - 3.0 * once[i]).abs() / (3.0 * scale);
        assert!(
            error <= F32_TOLERANCE,
            "panel {i}: three times the charge gave {} where 3 x {} was due",
            thrice[i],
            once[i]
        );
    }
}

/// Oracle: the contract. `upload` allocates every buffer the solve will use and
/// records the one dispatch it replays, so a second `apply` on the same adapter
/// must be the same answer — contract item 1, asked as a behaviour rather than
/// as a claim about the code.
///
/// Byte-identical, not within a tolerance: the same adapter over the same input
/// runs the same fixed-order fold on the same device, so anything but equality
/// is state leaking between calls.
#[test]
fn a_second_apply_on_one_upload_is_the_same_answer_to_the_bit() {
    let mesh = plates(53, 2);
    let n = mesh.panel.len();

    let Some(device) = Device::find().expect("probing is not a failure") else {
        assert_eq!(select(n, None), Backend::Cpu, "the fallback is the host");
        return;
    };
    let gpu = GpuMatVec::upload(&device, &mesh).expect("the mesh uploads");

    let mut rng = Rng::new(0x1234_5678);
    let x: Vec<f64> = (0..n).map(|_| unit(&mut rng)).collect();
    let mut first = vec![0.0; n];
    let mut second = vec![0.0; n];
    gpu.apply(&x, &mut first);
    gpu.apply(&x, &mut second);

    assert_eq!(
        first.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
        second.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
        "two applies of one upload disagree, so something is carrying over"
    );
}

/// Oracle: construct-from-answer. An empty mesh has no dispatch to record and no
/// buffer to allocate, and a device is never selected for one anyway — `select`
/// compares against a crossover that is positive by construction. Refusing is
/// the fail-closed answer; returning an adapter whose buffers were never
/// allocated is not.
#[test]
fn an_empty_mesh_is_refused_rather_than_uploaded() {
    let Some(device) = Device::find().expect("probing is not a failure") else {
        return;
    };
    let empty = Mesh::default();
    assert!(
        GpuMatVec::upload(&device, &empty).is_err(),
        "an empty mesh has nothing to upload and must not yield an adapter"
    );
}

// ------------------------------------------------------------------ crossover

/// A synthetic mesh of exactly `n` panels on a cube lattice.
///
/// Geometry a *timing* measurement can control the size of. The kernel is
/// `O(n²)` in the panel count and reads the same five numbers per panel whatever
/// the layout, so cost is a function of `n` alone — which is why the crossover
/// can be measured on a lattice and applied to a real mesh. Correctness is
/// asserted on real meshed geometry above; this is only for the clock.
fn lattice(n: usize) -> Mesh {
    use gpurify_pex::quasistatic::mesh::Panel;

    // Integer cube root by search, not `cbrt().ceil()`: the float round trip is
    // three lossy casts to compute a number under a hundred, and getting it one
    // low would stack panels on top of each other.
    let mut side = 1_usize;
    while side * side * side < n {
        side += 1;
    }
    let mut panel = Vec::with_capacity(n);
    for index in 0..n {
        let (x, y, z) = (index % side, (index / side) % side, index / (side * side));
        // Micrometre-scale spacing, which is the scale a real mesh works at —
        // the kernel divides by a radical of these, so the exponent range
        // matters to an `f32` path even though the panel count does not.
        let step = |axis: usize| f64::from(u32::try_from(axis).expect("a lattice index")) * 1e-6;
        panel.push(Panel {
            centre: [step(x), step(y), step(z)],
            normal: [0.0, 0.0, 1.0],
            area: 1e-13,
            conductor: 0,
        });
    }
    Mesh {
        conductor_start: vec![0, u32::try_from(n).expect("a panel count is a u32")],
        conductor_net: vec![gpurify_topology::NetId(0)],
        epsilon: vec![3.9; n],
        panel,
    }
}

/// Wall time for `runs` matvecs, after one untimed warm-up.
fn time_applies(op: &dyn MatVec, runs: u32) -> std::time::Duration {
    let n = op.dim();
    let x = vec![1.0_f64; n];
    let mut y = vec![0.0_f64; n];
    op.apply(&x, &mut y);

    let start = std::time::Instant::now();
    for _ in 0..runs {
        op.apply(&x, &mut y);
    }
    start.elapsed()
}

/// Oracle: measurement — `docs/GPU.md` contract item 6, which is the one item
/// that cannot be met by reading the code.
///
/// Prints the host and device times at a sweep of panel counts and the crossover
/// they imply, so the constant in `gpu.rs` can be checked against a number
/// rather than against an argument.
///
/// **It does not gate**, which is this workspace's rule for anything with a
/// clock in it: a duration never fails a build. What it *does* assert is the
/// direction the contract turns on — that the selection is automatic and that a
/// crossover of zero is never reported — and on a machine with no device it
/// asserts the fallback instead, so the test runs either way and is never
/// `#[ignore]`d.
#[test]
fn the_crossover_is_measured_rather_than_assumed() {
    // Straddles the crossover and stops. The full sweep to 8192 is in
    // `MEASURED_CROSSOVER`'s own doc comment, run deliberately with `--release`;
    // repeating it inside every `cargo test -p gpurify-pex` put thirteen minutes
    // into a package that otherwise takes fifteen seconds, because the *host*
    // side of an O(n^2) kernel at 8192 panels is 183 ms per apply. A test that
    // slow stops being run, which is how the old tree's GPU tests ended up
    // `#[ignore]`d.
    const SIZES: [usize; 4] = [64, 128, 256, 512];

    let Some(device) = Device::find().expect("probing is not a failure") else {
        assert_eq!(
            select(usize::MAX, None),
            Backend::Cpu,
            "no device is present, so no size selects one"
        );
        println!("no device: nothing to measure, fallback asserted");
        return;
    };

    println!("panels     host us    device us   winner");
    let mut first_win = None;
    for n in SIZES {
        let mesh = lattice(n);
        let host = CpuMatVec::build(&mesh);
        let gpu = GpuMatVec::upload(&device, &mesh).expect("the lattice uploads");
        // Fewer repeats as the problem grows, because the kernel is O(n^2);
        // floored at three so the fastest row is still an average, and capped so
        // the slowest is still an average of the same shape.
        let runs = u32::try_from(4_096 / n.max(1)).unwrap_or(3).clamp(3, 64);

        let host_us = time_applies(&host, runs).as_secs_f64() * 1e6 / f64::from(runs);
        let gpu_us = time_applies(&gpu, runs).as_secs_f64() * 1e6 / f64::from(runs);
        let winner = if gpu_us < host_us { "device" } else { "host" };
        println!("{n:>6}  {host_us:>10.1}  {gpu_us:>10.1}   {winner}");
        if gpu_us < host_us && first_win.is_none() {
            first_win = Some(n);
        }
    }

    match first_win {
        Some(n) => println!(
            "measured crossover on this part: {n} panels (gpu.rs carries {})",
            device.crossover()
        ),
        None => println!(
            "the device did not win at any size up to {}; the crossover in \
             gpu.rs is above this sweep",
            SIZES[SIZES.len() - 1]
        ),
    }

    assert!(
        device.crossover() > 0,
        "a crossover of zero selects the device at every size, which is the \
         fail-open reading docs/GPU.md contract item 6 forbids"
    );
}
