//! Device-region capacitance (PEX-011) through a whole PEX run.

use gpurify::engine::pipeline::Inputs;
use gpurify::engine::run::{run, Checks, RunOptions};
use gpurify_check::topology::device::{DeviceMeasure, DeviceParam, TerminalRole};
use gpurify_extract::Parasitic;

/// The inverter's coupling, summed, with the params deck plus `extra`.
fn coupling_and_widths(extra: &str) -> (f64, Vec<(f64, bool)>) {
    let fixtures = crate::gen_fixtures::fixtures();
    let deck = std::fs::read_to_string(fixtures.join("params.deck")).expect("the params deck");
    let dir = gpurify_testgen::oracle::scratch("device-region");
    let path = dir.join("params.deck");
    std::fs::write(&path, format!("{deck}\n{extra}\n")).expect("writable");
    let inputs = Inputs {
        layout: fixtures.join("lvs/LVS_CLEAN_MATCH.gds"),
        deck: path,
        ..Inputs::default()
    };
    let options = RunOptions {
        checks: Checks {
            pex: true,
            ..Checks::default()
        },
        ..RunOptions::default()
    };
    let (loaded, extracted, outputs, _) = run(&inputs, &options).expect("the inverter runs");
    let network = outputs.parasitics.expect("PEX ran");
    let coupling = network
        .value
        .iter()
        .map(|v| match v {
            Parasitic::CouplingCap(q) => q.raw(),
            _ => 0.0,
        })
        .sum();
    // Each nfet's width in µm, and whether its source and drain are both
    // off its gate's net.
    let devices = &extracted.devices;
    let nfet = loaded.strings.get("nfet_01v8").expect("a model");
    let widths = (0..devices.kind.len())
        .filter(|&d| devices.model[d] == nfet)
        .map(|d| {
            let params = &devices.param
                [devices.param_start[d] as usize..devices.param_start[d + 1] as usize];
            let w = params
                .iter()
                .find_map(|&(p, m)| match (p, m) {
                    (DeviceParam::Width, DeviceMeasure::Length(w)) => Some(w.raw()),
                    _ => None,
                })
                .expect("a measured width");
            let terms = devices.terminal_start[d] as usize..devices.terminal_start[d + 1] as usize;
            let net = |role| {
                terms
                    .clone()
                    .find(|&t| devices.terminal_role[t] == role)
                    .map(|t| devices.terminal_net[t])
            };
            let apart = net(TerminalRole::Source) != net(TerminalRole::Gate)
                && net(TerminalRole::Drain) != net(TerminalRole::Gate);
            #[expect(clippy::cast_precision_loss, reason = "a small length")]
            let um = w as f64 / loaded.grid.dbu_per_um() as f64;
            (um, apart)
        })
        .collect();
    (coupling, widths)
}

/// Proves catalog PEX-011.
///
/// A `pex_device` line adds, per nfet, `(gate_contact + gate_diffusion) ·
/// W` between its gate and each of its source and drain, and nothing to the
/// pfet it does not name.
///
/// Oracle: the deck's definition (crate docs of
/// `gpurify_extract::device_region`): with 0.3 and 0.2 aF/µm, each nfet
/// side is `0.5 aF/µm · W`; the run without the line is the reference, so
/// the difference is exactly `Σ 2 · 0.5 · W / 1000` fF over the nfets
/// (metamorphic: only the stated model's devices gain).
#[test]
fn a_pex_device_line_adds_gate_to_contact_and_diffusion_capacitance() {
    let (base, widths) = coupling_and_widths("");
    let (with, _) = coupling_and_widths(
        "pex_device \"nfet_01v8\" gate_contact_cap 0.3aF/um gate_diffusion_cap 0.2aF/um",
    );
    assert!(!widths.is_empty() && widths.iter().all(|&(_, apart)| apart));
    let want: f64 = widths.iter().map(|&(w, _)| 2.0 * 0.5 * w / 1000.0).sum();
    assert!(want > 0.0);
    assert!(
        ((with - base) - want).abs() < 1e-12,
        "{with} - {base} against {want}"
    );
}
