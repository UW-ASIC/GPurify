//! Every check kind the deck language spells, as data: one row per kind (and
//! per comparison, where the comparison picks the engine kind). A new engine
//! kind is one row here.

/// What a value measures, and so which units it accepts. Each dimension
/// converts to the one unit the engine stores it in.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Dim {
    /// Grid-checked, stored as grid units.
    Length,
    /// Checked against the square of the grid, stored as square grid units.
    Area,
    /// mV.
    Voltage,
    /// uA.
    Current,
    /// A/m.
    CurrentPerWidth,
    /// ohm.
    Resistance,
    /// K.
    Temperature,
    /// eV.
    Energy,
    /// h.
    Time,
    /// aF/um2 (PEX only).
    CapPerArea,
    /// aF/um (PEX only).
    CapPerLength,
    /// 0..=1, written bare or as `%`.
    Fraction,
    /// deg, a whole number.
    Angle,
    /// A bare number.
    Scalar,
    /// A bare unsigned integer.
    Count,
    /// `true` or `false`.
    Bool,
    /// A declared layer.
    Layer,
    /// `a x b`, two lengths; the second goes to the named engine param.
    LengthPair(&'static str),
    /// `[0deg, 90deg]`; one engine param per element, in degrees.
    AngleList,
    /// `["model", ..]`, device model names; one engine param per element.
    Models,
    /// `(name: value, ..)`, a nested set of params.
    Group(&'static [Param]),
}

/// Units, the dimension each belongs to, and the power of ten to the engine unit.
/// `C` is not here: it is an offset, handled where temperatures are read.
pub(crate) const UNITS: &[(&str, Dim, i32)] = &[
    ("nm", Dim::Length, 0),
    ("um", Dim::Length, 3),
    ("mm", Dim::Length, 6),
    ("nm2", Dim::Area, 0),
    ("um2", Dim::Area, 6),
    ("mm2", Dim::Area, 12),
    ("mV", Dim::Voltage, 0),
    ("V", Dim::Voltage, 3),
    ("nA", Dim::Current, -3),
    ("uA", Dim::Current, 0),
    ("mA", Dim::Current, 3),
    ("A", Dim::Current, 6),
    ("uA/um", Dim::CurrentPerWidth, 0),
    ("mA/um", Dim::CurrentPerWidth, 3),
    ("A/m", Dim::CurrentPerWidth, 0),
    ("mohm", Dim::Resistance, -3),
    ("ohm", Dim::Resistance, 0),
    ("kohm", Dim::Resistance, 3),
    ("Mohm", Dim::Resistance, 6),
    ("K", Dim::Temperature, 0),
    ("eV", Dim::Energy, 0),
    ("h", Dim::Time, 0),
    ("aF/um2", Dim::CapPerArea, 0),
    ("fF/um2", Dim::CapPerArea, 3),
    ("aF/um", Dim::CapPerLength, 0),
    ("fF/um", Dim::CapPerLength, 3),
    ("%", Dim::Fraction, -2),
    ("deg", Dim::Angle, 0),
];

/// One named argument: the deck's name, the engine's, and what it accepts.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Param {
    pub name: &'static str,
    pub engine: &'static str,
    pub dim: Dim,
    /// `none` is legal and leaves the engine param absent.
    pub none: bool,
}

/// The comparison a kind is written with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cmp {
    /// No comparison: every value is a named argument.
    Absent,
    /// `>=`, a minimum.
    Ge,
    /// `<=`, a maximum.
    Le,
    /// `==`, an exact value.
    Eq,
}

/// One row of the kind table.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Kind {
    /// The deck's name, `width` in `width(met1) >= 140nm`.
    pub name: &'static str,
    /// A bare word among the layer arguments that selects this row (`opposite`).
    pub modifier: Option<&'static str>,
    pub cmp: Cmp,
    /// The engine kind name `check` matches on.
    pub engine: &'static str,
    /// Engine layer slot `i` takes deck layer argument `layers[i]`.
    pub layers: &'static [u8],
    /// Further layer arguments follow the fixed ones.
    pub more: bool,
    /// The engine param the comparison value fills.
    pub limit: Option<Param>,
    pub params: &'static [Param],
    /// Engine flag params the row implies.
    pub fixed: &'static [(&'static str, bool)],
    /// Accepts `warning` after the rule id.
    pub warns: bool,
}

const fn p(name: &'static str, engine: &'static str, dim: Dim) -> Param {
    Param {
        name,
        engine,
        dim,
        none: false,
    }
}

const fn opt(name: &'static str, engine: &'static str, dim: Dim) -> Param {
    Param {
        name,
        engine,
        dim,
        none: true,
    }
}

/// A DRC row: one comparison, no `warning`.
const fn drc(
    name: &'static str,
    cmp: Cmp,
    engine: &'static str,
    layers: &'static [u8],
    limit: Option<Param>,
    params: &'static [Param],
) -> Kind {
    Kind {
        name,
        modifier: None,
        cmp,
        engine,
        layers,
        more: false,
        limit,
        params,
        fixed: &[],
        warns: false,
    }
}

/// An ERC row: named arguments only, `warning` allowed.
const fn erc(
    name: &'static str,
    layers: &'static [u8],
    more: bool,
    params: &'static [Param],
) -> Kind {
    Kind {
        name,
        modifier: None,
        cmp: Cmp::Absent,
        engine: name,
        layers,
        more,
        limit: None,
        params,
        fixed: &[],
        warns: true,
    }
}

const LIMIT: Option<Param> = Some(p("", "limit", Dim::Length));
const AREA: Option<Param> = Some(p("", "limit", Dim::Area));
const DENSITY: &[Param] = &[
    p("window", "window", Dim::Length),
    p("step", "step", Dim::Length),
];
const DENSITY_LIMIT: Option<Param> = Some(p("", "limit", Dim::Fraction));
const CMP_MODEL: &[Param] = &[
    p("target", "cmp_target_density", Dim::Fraction),
    p("thickness", "cmp_nominal_thickness", Dim::Length),
    p("sensitivity", "cmp_thickness_sensitivity", Dim::Length),
    p("max_delta", "cmp_max_abs_thickness_delta", Dim::Length),
];

pub(crate) const KINDS: &[Kind] = &[
    // DRC.
    drc("width", Cmp::Ge, "min_width", &[0], LIMIT, &[]),
    drc("width", Cmp::Le, "max_width", &[0], LIMIT, &[]),
    drc("edge_length", Cmp::Ge, "min_edge_length", &[0], LIMIT, &[]),
    drc("notch", Cmp::Ge, "notch", &[0], LIMIT, &[]),
    drc("space", Cmp::Ge, "min_spacing", &[0], LIMIT, &[]),
    drc("space", Cmp::Ge, "min_spacing_diff", &[0, 1], LIMIT, &[]),
    drc(
        "eol_space",
        Cmp::Ge,
        "eol_spacing",
        &[0],
        LIMIT,
        &[p("eol_width", "eol_width", Dim::Length)],
    ),
    drc(
        "prl_space",
        Cmp::Ge,
        "prl_spacing",
        &[0],
        LIMIT,
        &[p("prl", "prl_threshold", Dim::Length)],
    ),
    drc(
        "corner_space",
        Cmp::Ge,
        "corner_to_corner",
        &[0],
        LIMIT,
        &[],
    ),
    drc(
        "wide_space",
        Cmp::Ge,
        "wide_dependent_spacing",
        &[0],
        LIMIT,
        &[p("width", "width_threshold", Dim::Length)],
    ),
    drc("area", Cmp::Ge, "min_area", &[0], AREA, &[]),
    drc("hole_area", Cmp::Ge, "min_enclosed_area", &[0], AREA, &[]),
    drc(
        "cheesing",
        Cmp::Le,
        "cheesing",
        &[0],
        Some(p("", "max_unslotted", Dim::Area)),
        &[],
    ),
    Kind {
        fixed: &[("maximum", false)],
        ..drc("density", Cmp::Ge, "density", &[0], DENSITY_LIMIT, DENSITY)
    },
    Kind {
        fixed: &[("maximum", true)],
        ..drc("density", Cmp::Le, "density", &[0], DENSITY_LIMIT, DENSITY)
    },
    // The engine takes the outer layer first; the deck writes `enclosure(inner, outer)`.
    drc("enclosure", Cmp::Ge, "min_enclosure", &[1, 0], LIMIT, &[]),
    Kind {
        modifier: Some("opposite"),
        ..drc(
            "enclosure",
            Cmp::Ge,
            "asymmetric_enclosure",
            &[1, 0],
            Some(p("", "min_one_side", Dim::Length)),
            &[],
        )
    },
    drc("extension", Cmp::Ge, "min_extension", &[0, 1], LIMIT, &[]),
    drc("overlap", Cmp::Ge, "overlap", &[0, 1], LIMIT, &[]),
    drc(
        "tap_distance",
        Cmp::Le,
        "max_distance_to_tap",
        &[0, 1],
        LIMIT,
        &[],
    ),
    drc(
        "off_grid",
        Cmp::Absent,
        "off_grid",
        &[],
        None,
        &[p("pitch", "pitch", Dim::Length)],
    ),
    drc(
        "angle",
        Cmp::Absent,
        "angle",
        &[],
        None,
        &[p("allowed", "angle", Dim::AngleList)],
    ),
    drc(
        "redundant_via",
        Cmp::Ge,
        "redundant_via",
        &[0],
        Some(p("", "min_count", Dim::Count)),
        &[p("within", "within", Dim::Length)],
    ),
    drc(
        "via_array_space",
        Cmp::Ge,
        "via_array_spacing",
        &[0],
        LIMIT,
        &[p("array", "array_threshold", Dim::Count)],
    ),
    drc(
        "patterning",
        Cmp::Ge,
        "multi_patterning",
        &[0],
        Some(p("", "color_spacing", Dim::Length)),
        &[p("colors", "colors", Dim::Count)],
    ),
    // ERC.
    erc(
        "antenna",
        &[0, 1],
        true,
        &[
            p("max_ratio", "max_ratio", Dim::Scalar),
            opt("sidewall", "sidewall_thickness", Dim::Length),
        ],
    ),
    erc(
        "antenna_electrical",
        &[0, 1],
        true,
        &[
            p("max_ratio", "max_ratio", Dim::Scalar),
            opt("diode", "diode_layer", Dim::Layer),
            p("diode_credit", "diode_credit", Dim::Scalar),
            p("diode_bonus", "diode_bonus", Dim::Scalar),
        ],
    ),
    erc(
        "density_cmp",
        &[0],
        false,
        &[
            p("window", "window_x", Dim::LengthPair("window_y")),
            p("step", "step_x", Dim::LengthPair("step_y")),
            opt("min", "min_density", Dim::Fraction),
            opt("max", "max_density", Dim::Fraction),
            opt("max_delta", "max_neighbour_delta", Dim::Fraction),
            p("partial_windows", "include_partial_windows", Dim::Bool),
            opt("cmp", "", Dim::Group(CMP_MODEL)),
        ],
    ),
    erc(
        "electromigration",
        &[0],
        true,
        &[
            p("max_density", "max_density", Dim::CurrentPerWidth),
            p("max_current_per_cut", "max_current_per_cut", Dim::Current),
            p("blech_limit", "blech_limit", Dim::Current),
            p(
                "reference_temperature",
                "reference_temperature",
                Dim::Temperature,
            ),
            p("activation_energy", "activation_energy_ev", Dim::Energy),
            p("current_exponent", "current_exponent", Dim::Scalar),
        ],
    ),
    erc(
        "em_current_density",
        &[0],
        true,
        &[
            p("max_density", "max_density", Dim::CurrentPerWidth),
            p("max_current_per_cut", "max_current_per_cut", Dim::Current),
        ],
    ),
    erc(
        "esd_latchup",
        &[0, 1],
        false,
        &[
            p("min_guard_ring_width", "min_guard_ring_width", Dim::Length),
            p("max_tap_distance", "max_tap_distance", Dim::Length),
            p("clamps", "clamp", Dim::Models),
        ],
    ),
    erc(
        "esd_topological",
        &[0],
        false,
        &[p("clamps", "clamp", Dim::Models)],
    ),
    erc("floating_gate", &[], false, &[]),
    erc("floating_well", &[0, 1], false, &[]),
    erc(
        "hv_domain",
        &[],
        false,
        &[
            p("max_delta", "max_domain_delta", Dim::Voltage),
            opt("isolation", "isolation", Dim::Layer),
        ],
    ),
    erc("ir_drop", &[], false, &[]),
    erc(
        "missing_tie",
        &[0, 1],
        false,
        &[p("max_distance", "max_distance", Dim::Length)],
    ),
    erc(
        "multiple_drivers",
        &[],
        false,
        &[p("max", "max_drivers", Dim::Count)],
    ),
    erc(
        "p2p_resistance",
        &[],
        false,
        &[p("max", "max_resistance", Dim::Resistance)],
    ),
    erc(
        "reliability",
        &[],
        false,
        &[
            p("required_lifetime", "required_lifetime_hours", Dim::Time),
            p("reference_lifetime", "reference_lifetime_hours", Dim::Time),
            p("reference_stress", "reference_stress", Dim::Voltage),
            p("stress_exponent", "stress_exponent", Dim::Scalar),
            p(
                "reference_temperature",
                "reference_temperature",
                Dim::Temperature,
            ),
            p("activation_energy", "activation_energy_ev", Dim::Energy),
            p("max_abs_voltage", "max_abs_voltage", Dim::Voltage),
            p("duty_cycle", "duty_cycle", Dim::Fraction),
        ],
    ),
    erc("soft_connection", &[0], true, &[]),
    erc("supply_short", &[0, 1], false, &[]),
    erc("tie_high_low", &[], false, &[]),
    erc("unconnected_pin", &[0], true, &[]),
    erc(
        "gate_oxide",
        &[],
        false,
        &[
            p("models", "model", Dim::Models),
            p("max", "max_voltage", Dim::Voltage),
        ],
    ),
    erc(
        "drain_source",
        &[],
        false,
        &[
            p("models", "model", Dim::Models),
            p("max", "max_voltage", Dim::Voltage),
        ],
    ),
    erc(
        "well_bias",
        &[],
        false,
        &[
            opt("pmos", "pmos", Dim::Models),
            opt("nmos", "nmos", Dim::Models),
        ],
    ),
    erc(
        "missing_level_shifter",
        &[],
        false,
        &[opt("shifters", "shifter", Dim::Models)],
    ),
    erc("domain_crossing", &[], false, &[]),
];

/// The six PEX keys, each required once per `pex` statement.
pub(crate) const PEX: [(&str, Dim); 6] = [
    ("thickness", Dim::Length),
    ("height", Dim::Length),
    ("sheet", Dim::Resistance),
    ("dielectric", Dim::Scalar),
    ("area_cap", Dim::CapPerArea),
    ("fringe_cap", Dim::CapPerLength),
];
