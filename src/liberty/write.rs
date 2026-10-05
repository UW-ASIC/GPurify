//! The Liberty model of one macro at one corner, and its two writers: the
//! `.lib` and the Verilog blackbox.
//!
//! Units throughout: ns, pF, V, mA, nW, and pJ (pF·V²) for internal energy.
//! Output is a function of the model alone: no clock, no hash order.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::liberty::spec::{ArcKind, Characterization, CornerSpec, Direction, PinSpec, Role};
use crate::liberty::Accuracy;

/// One `.lib` file's content.
#[derive(Debug, Clone)]
pub struct Library {
    pub name: String,
    pub corner: CornerSpec,
    pub thresholds: Characterization,
    pub accuracy: Accuracy,
    pub tool_version: &'static str,
    pub cell: Cell,
}

#[derive(Debug, Clone)]
pub struct Cell {
    pub name: String,
    pub area_um2: f64,
    /// Mean of the per-state leakage, nW.
    pub leakage_nw: Option<f64>,
    /// `(when, nW)`; `when` is empty for a state with no digital pins.
    pub leakage_states: Vec<(String, f64)>,
    /// In spec order, supplies included.
    pub pins: Vec<Pin>,
}

#[derive(Debug, Clone)]
pub struct Pin {
    pub spec: PinSpec,
    /// `(rise, fall)`, pF.
    pub capacitance: Option<(f64, f64)>,
    pub max_transition_ns: Option<f64>,
    pub max_capacitance_pf: Option<f64>,
    pub timing: Vec<Timing>,
    pub power: Vec<InternalPower>,
}

impl Pin {
    pub fn bare(spec: PinSpec) -> Self {
        Self {
            spec,
            capacitance: None,
            max_transition_ns: None,
            max_capacitance_pf: None,
            timing: Vec::new(),
            power: Vec::new(),
        }
    }
}

/// One `timing ()` group.
#[derive(Debug, Clone)]
pub struct Timing {
    pub related: String,
    pub kind: ArcKind,
    pub sense: Option<&'static str>,
    pub tables: Vec<NamedTable>,
}

/// One `internal_power ()` group on an output.
#[derive(Debug, Clone)]
pub struct InternalPower {
    pub related: String,
    pub rise: Option<Table>,
    pub fall: Option<Table>,
}

/// A table under its Liberty group name (`cell_rise`, `ocv_sigma_cell_rise`, ...).
#[derive(Debug, Clone)]
pub struct NamedTable {
    pub group: String,
    /// `sigma_type` of an LVF table.
    pub sigma: Option<&'static str>,
    pub table: Table,
}

/// Row-major over `index_1` × `index_2`; `index_2` empty for a 1-D table.
#[derive(Debug, Clone, PartialEq)]
pub struct Table {
    pub index_1: Vec<f64>,
    pub index_2: Vec<f64>,
    pub values: Vec<f64>,
}

/// What a template's axes mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Axes {
    Delay,
    Constraint,
    Power,
}

impl Axes {
    const fn variables(self) -> (&'static str, &'static str) {
        match self {
            Self::Delay | Self::Power => ("input_net_transition", "total_output_net_capacitance"),
            Self::Constraint => ("related_pin_transition", "constrained_pin_transition"),
        }
    }

    const fn keyword(self) -> &'static str {
        match self {
            Self::Power => "power_lut_template",
            Self::Delay | Self::Constraint => "lu_table_template",
        }
    }

    const fn prefix(self) -> &'static str {
        match self {
            Self::Delay => "delay",
            Self::Constraint => "constraint",
            Self::Power => "energy",
        }
    }
}

/// A template is named by its axes and shape; each table restates its indices.
fn template_name(axes: Axes, table: &Table) -> String {
    format!(
        "{}_{}x{}",
        axes.prefix(),
        table.index_1.len(),
        table.index_2.len().max(1)
    )
}

fn timing_axes(kind: ArcKind) -> Axes {
    if kind.is_constraint() {
        Axes::Constraint
    } else {
        Axes::Delay
    }
}

/// Liberty number: fixed point where that keeps ten significant-ish digits,
/// scientific below. Never `NaN`: the characterizer refuses those upstream.
fn num(value: f64, out: &mut String) {
    debug_assert!(value.is_finite(), "a non-finite number reached the writer");
    if value == 0.0 {
        out.push('0');
    } else if value.abs() >= 1e-3 {
        let _ = write!(out, "{value:.10}");
    } else {
        let _ = write!(out, "{value:.9e}");
    }
}

fn list(values: &[f64], out: &mut String) {
    out.push('"');
    for (i, &v) in values.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        num(v, out);
    }
    out.push('"');
}

fn attr(out: &mut String, indent: usize, key: &str, value: impl std::fmt::Display) {
    let _ = writeln!(out, "{:indent$}{key} : {value};", "");
}

fn attr_num(out: &mut String, indent: usize, key: &str, value: f64) {
    let _ = write!(out, "{:indent$}{key} : ", "");
    num(value, out);
    out.push_str(";\n");
}

fn table(
    out: &mut String,
    indent: usize,
    group: &str,
    template: &str,
    sigma: Option<&str>,
    t: &Table,
) {
    let pad = indent + 4;
    let _ = writeln!(out, "{:indent$}{group} (\"{template}\") {{", "");
    if let Some(sigma) = sigma {
        attr(out, pad, "sigma_type", format!("\"{sigma}\""));
    }
    let _ = write!(out, "{:pad$}index_1(", "");
    list(&t.index_1, out);
    out.push_str(");\n");
    if !t.index_2.is_empty() {
        let _ = write!(out, "{:pad$}index_2(", "");
        list(&t.index_2, out);
        out.push_str(");\n");
    }
    let row = t.index_2.len().max(1);
    let _ = write!(out, "{:pad$}values(", "");
    for (i, chunk) in t.values.chunks(row).enumerate() {
        if i > 0 {
            let _ = write!(out, ", \\\n{:w$}", "", w = pad + 7);
        }
        list(chunk, out);
    }
    out.push_str(");\n");
    let _ = writeln!(out, "{:indent$}}}", "");
}

/// Write the `.lib`.
pub fn write_liberty(lib: &Library, out: &mut String) {
    let corner = &lib.corner;
    let th = &lib.thresholds;
    let _ = writeln!(
        out,
        "/* {} written by gpurify {}: accuracy {} ({}). */",
        lib.cell.name,
        lib.tool_version,
        lib.accuracy.name(),
        lib.accuracy.describe()
    );
    let _ = writeln!(out, "library (\"{}\") {{", lib.name);
    out.push_str("    technology (\"cmos\");\n");
    attr(out, 4, "delay_model", "table_lookup");
    attr(out, 4, "time_unit", "\"1ns\"");
    attr(out, 4, "voltage_unit", "\"1V\"");
    attr(out, 4, "current_unit", "\"1mA\"");
    attr(out, 4, "leakage_power_unit", "\"1nW\"");
    attr(out, 4, "pulling_resistance_unit", "\"1kohm\"");
    let _ = writeln!(out, "    capacitive_load_unit(1, \"pf\");");
    let nominal = lib
        .cell
        .pins
        .iter()
        .filter(|pin| pin.spec.role == Role::Power)
        .filter_map(|pin| corner.supplies.get(&pin.spec.name).copied())
        .fold(0.0_f64, f64::max);
    attr_num(out, 4, "nom_process", corner.process);
    attr_num(out, 4, "nom_temperature", corner.temperature);
    attr_num(out, 4, "nom_voltage", nominal);
    for (name, volts) in &corner.supplies {
        let _ = write!(out, "    voltage_map(\"{name}\", ");
        num(*volts, out);
        out.push_str(");\n");
    }
    let _ = writeln!(out, "    operating_conditions (\"{}\") {{", corner.name);
    attr_num(out, 8, "process", corner.process);
    attr_num(out, 8, "temperature", corner.temperature);
    attr_num(out, 8, "voltage", nominal);
    out.push_str("    }\n");
    attr(
        out,
        4,
        "default_operating_conditions",
        format!("\"{}\"", corner.name),
    );
    for edge in ["rise", "fall"] {
        attr_num(
            out,
            4,
            &format!("input_threshold_pct_{edge}"),
            th.input_threshold_pct,
        );
        attr_num(
            out,
            4,
            &format!("output_threshold_pct_{edge}"),
            th.output_threshold_pct,
        );
        attr_num(
            out,
            4,
            &format!("slew_lower_threshold_pct_{edge}"),
            th.slew_lower_pct,
        );
        attr_num(
            out,
            4,
            &format!("slew_upper_threshold_pct_{edge}"),
            th.slew_upper_pct,
        );
    }
    attr_num(out, 4, "slew_derate_from_library", 1.0);
    attr_num(out, 4, "default_cell_leakage_power", 0.0);
    attr_num(out, 4, "default_inout_pin_cap", 0.0);
    attr_num(out, 4, "default_input_pin_cap", 0.0);
    attr_num(out, 4, "default_output_pin_cap", 0.0);
    attr_num(out, 4, "default_fanout_load", 1.0);

    let mut templates: BTreeSet<(Axes, String, usize, usize)> = BTreeSet::new();
    for pin in &lib.cell.pins {
        for timing in &pin.timing {
            for named in &timing.tables {
                let axes = timing_axes(timing.kind);
                let t = &named.table;
                templates.insert((
                    axes,
                    template_name(axes, t),
                    t.index_1.len(),
                    t.index_2.len(),
                ));
            }
        }
        for power in &pin.power {
            for t in power.rise.iter().chain(&power.fall) {
                templates.insert((
                    Axes::Power,
                    template_name(Axes::Power, t),
                    t.index_1.len(),
                    t.index_2.len(),
                ));
            }
        }
    }
    for (axes, name, n1, n2) in &templates {
        let (v1, v2) = axes.variables();
        let _ = writeln!(out, "    {} (\"{name}\") {{", axes.keyword());
        attr(out, 8, "variable_1", v1);
        let dummy = |n: usize| {
            (1..=n)
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        if *n2 > 0 {
            attr(out, 8, "variable_2", v2);
        }
        let _ = writeln!(out, "        index_1(\"{}\");", dummy(*n1));
        if *n2 > 0 {
            let _ = writeln!(out, "        index_2(\"{}\");", dummy(*n2));
        }
        out.push_str("    }\n");
    }

    write_cell(&lib.cell, out);
    out.push_str("}\n");
}

fn write_cell(cell: &Cell, out: &mut String) {
    let _ = writeln!(out, "    cell (\"{}\") {{", cell.name);
    attr_num(out, 8, "area", cell.area_um2);
    attr(out, 8, "is_macro_cell", "true");
    attr(out, 8, "dont_touch", "true");
    attr(out, 8, "dont_use", "true");
    if let Some(leakage) = cell.leakage_nw {
        attr_num(out, 8, "cell_leakage_power", leakage);
    }
    for (when, nw) in &cell.leakage_states {
        out.push_str("        leakage_power () {\n");
        attr_num(out, 12, "value", *nw);
        if !when.is_empty() {
            attr(out, 12, "when", format!("\"{when}\""));
        }
        out.push_str("        }\n");
    }
    for pin in cell.pins.iter().filter(|pin| pin.spec.role.is_supply()) {
        let pg_type = match pin.spec.role {
            Role::Power => "primary_power",
            Role::Ground => "primary_ground",
            Role::Nwell => "nwell",
            _ => "pwell",
        };
        let _ = writeln!(out, "        pg_pin (\"{}\") {{", pin.spec.name);
        attr(out, 12, "pg_type", pg_type);
        attr(out, 12, "voltage_name", format!("\"{}\"", pin.spec.name));
        if matches!(pin.spec.role, Role::Nwell | Role::Pwell) {
            attr(out, 12, "physical_connection", "\"device_layer\"");
        }
        out.push_str("        }\n");
    }
    for pin in cell.pins.iter().filter(|pin| !pin.spec.role.is_supply()) {
        write_pin(pin, out);
    }
    out.push_str("    }\n");
}

/// A signal pin's Liberty direction.
pub fn direction(spec: &PinSpec) -> Direction {
    match spec.role {
        Role::Input | Role::Clock => Direction::Input,
        Role::Output => Direction::Output,
        _ => spec.direction.unwrap_or(Direction::Inout),
    }
}

fn write_pin(pin: &Pin, out: &mut String) {
    let spec = &pin.spec;
    let _ = writeln!(out, "        pin (\"{}\") {{", spec.name);
    attr(out, 12, "direction", direction(spec).liberty());
    if let Some(power) = &spec.power {
        attr(out, 12, "related_power_pin", format!("\"{power}\""));
    }
    if let Some(ground) = &spec.ground {
        attr(out, 12, "related_ground_pin", format!("\"{ground}\""));
    }
    match spec.role {
        Role::Clock => attr(out, 12, "clock", "true"),
        Role::Input => attr(out, 12, "clock", "false"),
        // Not read by OpenSTA, which leaves an arc-less pin unconstrained
        // anyway; read by tools that implement the attribute.
        Role::Analog => attr(out, 12, "is_analog", "true"),
        _ => {}
    }
    if let Some((rise, fall)) = pin.capacitance {
        attr_num(out, 12, "capacitance", 0.5 * (rise + fall));
        attr_num(out, 12, "rise_capacitance", rise);
        attr_num(out, 12, "fall_capacitance", fall);
    }
    if let Some(function) = &spec.function {
        attr(out, 12, "function", format!("\"{function}\""));
    }
    if let Some(t) = pin.max_transition_ns {
        attr_num(out, 12, "max_transition", t);
    }
    if let Some(c) = pin.max_capacitance_pf {
        attr_num(out, 12, "max_capacitance", c);
    }
    for timing in &pin.timing {
        out.push_str("            timing () {\n");
        attr(out, 16, "related_pin", format!("\"{}\"", timing.related));
        attr(out, 16, "timing_type", timing.kind.liberty());
        if let Some(sense) = timing.sense {
            attr(out, 16, "timing_sense", sense);
        }
        let axes = timing_axes(timing.kind);
        for named in &timing.tables {
            let name = template_name(axes, &named.table);
            table(out, 16, &named.group, &name, named.sigma, &named.table);
        }
        out.push_str("            }\n");
    }
    for power in &pin.power {
        out.push_str("            internal_power () {\n");
        attr(out, 16, "related_pin", format!("\"{}\"", power.related));
        for (group, t) in [("rise_power", &power.rise), ("fall_power", &power.fall)] {
            if let Some(t) = t {
                let name = template_name(Axes::Power, t);
                table(out, 16, group, &name, None, t);
            }
        }
        out.push_str("            }\n");
    }
    out.push_str("        }\n");
}

/// Write the `(* blackbox *)` Verilog module, ports in spec order, supplies
/// behind `USE_POWER_PINS` as the OpenLane/LibreLane flow expects.
pub fn write_blackbox(cell: &str, pins: &[PinSpec], tool_version: &str, out: &mut String) {
    let _ = writeln!(
        out,
        "// {cell} blackbox, written by gpurify {tool_version}."
    );
    out.push_str("(* blackbox *)\n");
    let _ = writeln!(out, "module {cell} (");
    let supplies: Vec<&PinSpec> = pins.iter().filter(|p| p.role.is_supply()).collect();
    let signals: Vec<&PinSpec> = pins.iter().filter(|p| !p.role.is_supply()).collect();
    if !supplies.is_empty() {
        out.push_str("`ifdef USE_POWER_PINS\n");
        for pin in &supplies {
            let _ = writeln!(out, "    inout {},", pin.name);
        }
        out.push_str("`endif\n");
    }
    for (i, pin) in signals.iter().enumerate() {
        let comma = if i + 1 < signals.len() { "," } else { "" };
        let _ = writeln!(out, "    {} {}{comma}", direction(pin).liberty(), pin.name);
    }
    out.push_str(");\nendmodule\n");
}

#[cfg(test)]
mod tests {
    use super::{num, write_blackbox, Table};
    use crate::liberty::spec::{PinSpec, Role};

    #[test]
    fn numbers_keep_their_digits_at_every_scale() {
        for (value, text) in [
            (0.0, "0"),
            (1.5, "1.5000000000"),
            (0.002_302, "0.0023020000"),
            (1.25e-5, "1.250000000e-5"),
            (-0.002, "-0.0020000000"),
        ] {
            let mut out = String::new();
            num(value, &mut out);
            assert_eq!(out, text);
        }
    }

    /// A trailing comma after the last port is a Verilog syntax error, and an
    /// empty signal list after the power block is the case that would make one.
    #[test]
    fn the_blackbox_has_no_trailing_comma() {
        let pin = |name: &str, role| PinSpec {
            name: name.to_owned(),
            role,
            power: None,
            ground: None,
            direction: None,
            bias: None,
            function: None,
        };
        let mut out = String::new();
        write_blackbox(
            "m",
            &[
                pin("vdd", Role::Power),
                pin("a", Role::Input),
                pin("y", Role::Output),
            ],
            "t",
            &mut out,
        );
        assert!(
            out.contains("    inout vdd,\n`endif\n    input a,\n    output y\n);"),
            "{out}"
        );
        let _ = Table {
            index_1: vec![],
            index_2: vec![],
            values: vec![],
        };
    }
}
