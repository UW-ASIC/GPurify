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
    /// W/(m·K), written `W/mK`.
    ThermalConductivity,
    /// h.
    Time,
    /// V/um, an electric field (numerically mV/nm).
    Field,
    /// aF/um2 (PEX only).
    CapPerArea,
    /// aF/um (PEX only).
    CapPerLength,
    /// 1/K, a first-order temperature coefficient (PEX only).
    PerKelvin,
    /// 1/K², a second-order temperature coefficient (PEX only).
    PerKelvin2,
    /// aF (an LVS tolerance on a capacitance).
    Capacitance,
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
    /// `same` or `different`; `same` is the engine flag.
    Nets,
    /// `[a, b, ..]`, lengths; one engine param per element.
    LengthList,
    /// `[a, b, ..]`, voltages; one engine param per element, in mV.
    VoltageList,
    /// `[[a, b, ..], ..]`, rows of lengths; one engine param per cell, row by row.
    LengthRows,
    /// `[a x b, ..]`, pairs of lengths; per pair, the first to the param's
    /// engine name and the second to the named one.
    LengthPairList(&'static str),
    /// One of the listed bare words; the engine param is its index, a count.
    Word(&'static [&'static str]),
    /// `[(area, n), ..]`, a piecewise-linear table (LEF's `PWL`) with areas
    /// rising strictly; per point, the area goes to the param's engine name
    /// and the number to the named one.
    AreaTable(&'static str),
    /// `[none, a, ..]`, lengths or `none`; one engine param per element, a
    /// length or, for `none`, the flag `false`.
    OptLengthList,
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
    ("W/mK", Dim::ThermalConductivity, 0),
    ("h", Dim::Time, 0),
    ("V/um", Dim::Field, 0),
    ("V/nm", Dim::Field, 3),
    ("MV/cm", Dim::Field, 2),
    ("aF/um2", Dim::CapPerArea, 0),
    ("fF/um2", Dim::CapPerArea, 3),
    ("aF/um", Dim::CapPerLength, 0),
    ("fF/um", Dim::CapPerLength, 3),
    ("/K", Dim::PerKelvin, 0),
    ("/K2", Dim::PerKelvin2, 0),
    ("aF", Dim::Capacitance, 0),
    ("fF", Dim::Capacitance, 3),
    ("pF", Dim::Capacitance, 6),
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

/// A DRC row: one comparison.
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
    }
}

/// An ERC row: named arguments only.
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
    }
}

const LIMIT: Option<Param> = Some(p("", "limit", Dim::Length));
const AREA: Option<Param> = Some(p("", "limit", Dim::Area));
const DENSITY: &[Param] = &[
    p("window", "window", Dim::Length),
    p("step", "step", Dim::Length),
];
const DENSITY_LIMIT: Option<Param> = Some(p("", "limit", Dim::Fraction));
const COUNT: Option<Param> = Some(p("", "limit", Dim::Count));
/// MINSTEP's corner kinds, in the order of the engine's index.
const STEP_CORNERS: &[&str] = &["outside", "inside", "step"];
/// A voltage-dependent spacing table: the step voltages and the spacing from
/// each one up.
const VOLTAGE_SPACE: &[Param] = &[
    p("voltage", "voltage", Dim::VoltageList),
    p("space", "space", Dim::LengthList),
];
/// A narrow-line current band: a metal line at most `width` wide may carry
/// `current` (IHP SG13G2 §2.15's IMAX beside JMAX).
const EM_NARROW: &[Param] = &[
    p("width", "narrow_width", Dim::Length),
    p("current", "narrow_current", Dim::Current),
];
/// `esd_path`'s parameters, the same with a source layer or without.
const ESD_PATH: &[Param] = &[
    opt("clamps", "clamp", Dim::Models),
    p("current", "current", Dim::Current),
    p("clamp_resistance", "clamp_resistance", Dim::Resistance),
    opt("max_resistance", "max_resistance", Dim::Resistance),
    opt("clamp_it2", "clamp_it2", Dim::CurrentPerWidth),
    opt("max_density", "max_density", Dim::CurrentPerWidth),
    opt("max_current_per_cut", "max_current_per_cut", Dim::Current),
    opt("max_voltage", "max_voltage", Dim::Voltage),
];
/// An enclosure's wire band: the wire widths the rule holds.
const WIRE_WIDTH: &[Param] = &[p("width", "wire_width", Dim::Length)];
const WIRE_BELOW: &[Param] = &[p("below", "wire_below", Dim::Length)];
const WIRE: &[Param] = &[
    p("width", "wire_width", Dim::Length),
    p("below", "wire_below", Dim::Length),
];

/// `enclosure(inner, outer, opposite) >= len` with `params`.
const fn opposite(params: &'static [Param]) -> Kind {
    Kind {
        modifier: Some("opposite"),
        ..drc(
            "enclosure",
            Cmp::Ge,
            "asymmetric_enclosure",
            &[1, 0],
            Some(p("", "min_one_side", Dim::Length)),
            params,
        )
    }
}
const ADJACENT: &[Param] = &[
    p("cuts", "adjacent", Dim::Count),
    p("within", "within", Dim::Length),
];
/// LEF `PARALLELEDGE parSpace WITHIN parWithin [TWOEDGES]`.
const EOL_PARALLEL: &[Param] = &[
    p("space", "par_space", Dim::Length),
    p("within", "par_within", Dim::Length),
    p("two_edges", "two_edges", Dim::Bool),
];
const CMP_MODEL: &[Param] = &[
    p("target", "cmp_target_density", Dim::Fraction),
    p("sensitivity", "cmp_thickness_sensitivity", Dim::Length),
    p("max_delta", "cmp_max_abs_thickness_delta", Dim::Length),
];

pub(crate) const KINDS: &[Kind] = &[
    // DRC.
    drc("width", Cmp::Ge, "min_width", &[0], LIMIT, &[]),
    drc("width", Cmp::Le, "max_width", &[0], LIMIT, &[]),
    // Exact cut size, `size(licon) == 170nm x 170nm`: every merged figure is
    // exactly that rectangle, either way round.
    drc(
        "size",
        Cmp::Eq,
        "cut_size",
        &[0],
        Some(p("", "width", Dim::LengthPair("height"))),
        &[],
    ),
    drc("edge_length", Cmp::Ge, "min_edge_length", &[0], LIMIT, &[]),
    // LEF MINSTEP's variants: more than `max_edges` short edges in a row, or a
    // run of short edges at an outside corner, an inside corner or a step,
    // with LENGTHSUM's allowance (`length_sum: none` for none).
    drc(
        "min_step",
        Cmp::Ge,
        "min_step",
        &[0],
        LIMIT,
        &[p("max_edges", "max_edges", Dim::Count)],
    ),
    drc(
        "min_step",
        Cmp::Ge,
        "min_step",
        &[0],
        LIMIT,
        &[
            p("corner", "corner", Dim::Word(STEP_CORNERS)),
            opt("length_sum", "length_sum", Dim::Length),
        ],
    ),
    // A set of legal widths, `width(L; allowed: [350nm, 690nm])` (sky130
    // rpm.1b-1f): each merged figure's narrowest width is one of them.
    drc(
        "width",
        Cmp::Absent,
        "allowed_width",
        &[0],
        None,
        &[p("allowed", "width", Dim::LengthList)],
    ),
    // A protrusion narrower than the limit from a wire at least `wide` wide
    // (LEF `PROTRUSIONWIDTH width1 LENGTH 0 WIDTH width2`).
    drc(
        "protrusion_width",
        Cmp::Ge,
        "protrusion_width",
        &[0],
        LIMIT,
        &[p("wide", "wide", Dim::Length)],
    ),
    drc("notch", Cmp::Ge, "notch", &[0], LIMIT, &[]),
    drc("space", Cmp::Ge, "min_spacing", &[0], LIMIT, &[]),
    drc("space", Cmp::Ge, "min_spacing_diff", &[0, 1], LIMIT, &[]),
    // Facing edges only, KLayout's `projection` metric:
    // `space(lvtn, sd, projection) >= 235nm` (sky130 lvtn.3b).
    Kind {
        modifier: Some("projection"),
        ..drc("space", Cmp::Ge, "projection_spacing", &[0, 1], LIMIT, &[])
    },
    drc(
        "eol_space",
        Cmp::Ge,
        "eol_spacing",
        &[0],
        LIMIT,
        &[p("eol_width", "eol_width", Dim::Length)],
    ),
    // LEF `SPACING ENDOFLINE`: a keep-out reaching `within` past the end's
    // sides, optionally only beside parallel edges, with its own space
    // between two ends (`LEF58_SPACING ENDOFLINE ... ENDTOEND`).
    drc(
        "eol_space",
        Cmp::Ge,
        "eol_within_spacing",
        &[0],
        LIMIT,
        &[
            p("eol_width", "eol_width", Dim::Length),
            p("within", "eol_within", Dim::Length),
            opt("parallel", "", Dim::Group(EOL_PARALLEL)),
            opt("end_to_end", "end_to_end", Dim::Length),
        ],
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
    // `LEF58_CORNERSPACING CONVEXCORNER`: the larger axis gap between facing
    // convex corners (or Euclidean, `CORNERTOCORNER`), ends of line exempt
    // with `EXCEPTEOL`.
    drc(
        "corner_space",
        Cmp::Ge,
        "convex_corner_spacing",
        &[0],
        LIMIT,
        &[
            p("corner_to_corner", "corner_to_corner", Dim::Bool),
            opt("except_eol", "except_eol", Dim::Length),
        ],
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
    // Windows tile the die: a second layer names the die boundary
    // (`density(met1, prBoundary; ..)`), else the whole layout's extent.
    Kind {
        fixed: &[("maximum", false)],
        more: true,
        ..drc("density", Cmp::Ge, "density", &[0], DENSITY_LIMIT, DENSITY)
    },
    Kind {
        fixed: &[("maximum", true)],
        more: true,
        ..drc("density", Cmp::Le, "density", &[0], DENSITY_LIMIT, DENSITY)
    },
    Kind {
        fixed: &[("maximum", false)],
        more: true,
        ..drc(
            "global_density",
            Cmp::Ge,
            "global_density",
            &[0],
            DENSITY_LIMIT,
            &[],
        )
    },
    Kind {
        fixed: &[("maximum", true)],
        more: true,
        ..drc(
            "global_density",
            Cmp::Le,
            "global_density",
            &[0],
            DENSITY_LIMIT,
            &[],
        )
    },
    // Coverage of a layer inside each shape of a region layer (sky130 vpp.5a
    // "max pattern density of met3 over capacitor", vpp.11).
    Kind {
        fixed: &[("maximum", false)],
        ..drc(
            "region_density",
            Cmp::Ge,
            "region_density",
            &[0, 1],
            DENSITY_LIMIT,
            &[],
        )
    },
    Kind {
        fixed: &[("maximum", true)],
        ..drc(
            "region_density",
            Cmp::Le,
            "region_density",
            &[0, 1],
            DENSITY_LIMIT,
            &[],
        )
    },
    // The number of merged shapes on the layer in the whole layout, a minimum
    // or a maximum (IHP npn13G2.bR; one seal ring per chip).
    Kind {
        fixed: &[("maximum", false)],
        ..drc("count", Cmp::Ge, "count", &[0], COUNT, &[])
    },
    Kind {
        fixed: &[("maximum", true)],
        ..drc("count", Cmp::Le, "count", &[0], COUNT, &[])
    },
    // Several legal cut sizes, `size(via; allowed: [150nm x 150nm, 230nm x
    // 230nm])` (sky130 via.1b, LEF58_CUTCLASS): each merged figure is one of
    // them, either way round.
    drc(
        "size",
        Cmp::Absent,
        "cut_class",
        &[0],
        None,
        &[p("allowed", "width", Dim::LengthPairList("height"))],
    ),
    // The area a layer covers in the whole layout (IHP MIM.gR).
    drc("total_area", Cmp::Le, "total_area", &[0], AREA, &[]),
    // A shape's bounding box, its longer side over its shorter (sky130 capm.6).
    drc(
        "aspect_ratio",
        Cmp::Le,
        "aspect_ratio",
        &[0],
        Some(p("", "limit", Dim::Scalar)),
        &[],
    ),
    // Short-circuit critical area for a square defect of half-side `radius`:
    // `critical_area(met1; radius: 100nm) <= 50um2`.
    drc(
        "critical_area",
        Cmp::Le,
        "critical_area",
        &[0],
        AREA,
        &[p("radius", "radius", Dim::Length)],
    ),
    // Two masks' coverage balanced per window, an optional third layer the
    // die: `density_balance(m1_c1, m1_c2; window: 10um, step: 5um) >= 0.8`.
    Kind {
        more: true,
        ..drc(
            "density_balance",
            Cmp::Ge,
            "density_balance",
            &[0, 1],
            DENSITY_LIMIT,
            DENSITY,
        )
    },
    // The engine takes the outer layer first; the deck writes `enclosure(inner, outer)`.
    // A wire band (`width:`, `below:`, LEF `ENCLOSURE ... WIDTH`) is one more
    // row per combination, the plain row first: a row knowing every given
    // name wins, the first on a tie.
    drc("enclosure", Cmp::Ge, "min_enclosure", &[1, 0], LIMIT, &[]),
    drc(
        "enclosure",
        Cmp::Ge,
        "min_enclosure",
        &[1, 0],
        LIMIT,
        WIRE_WIDTH,
    ),
    drc(
        "enclosure",
        Cmp::Ge,
        "min_enclosure",
        &[1, 0],
        LIMIT,
        WIRE_BELOW,
    ),
    drc("enclosure", Cmp::Ge, "min_enclosure", &[1, 0], LIMIT, WIRE),
    // Coincident edges exempt, `enclosure(lvtn, nwell, noncoincident)`
    // (sky130 lvtn.10).
    Kind {
        modifier: Some("noncoincident"),
        ..drc(
            "enclosure",
            Cmp::Ge,
            "noncoincident_enclosure",
            &[1, 0],
            LIMIT,
            &[],
        )
    },
    // The inner spans its host along one axis: `full_width(V1, M2)` (ASAP7
    // V1.M2.AUX.2).
    drc("full_width", Cmp::Absent, "full_width", &[1, 0], None, &[]),
    // A maximum enclosure, `enclosure(licon, npc) <= 95nm` (sky130 npc.5).
    drc("enclosure", Cmp::Le, "max_enclosure", &[1, 0], LIMIT, &[]),
    opposite(&[]),
    opposite(WIRE_WIDTH),
    opposite(WIRE_BELOW),
    opposite(WIRE),
    Kind {
        modifier: Some("adjacent"),
        ..drc(
            "enclosure",
            Cmp::Ge,
            "adjacent_enclosure",
            &[1, 0],
            Some(p("", "min_one_side", Dim::Length)),
            &[],
        )
    },
    drc("extension", Cmp::Ge, "min_extension", &[0, 1], LIMIT, &[]),
    // A gate's shape: `bend(poly, diff)` (poly turning on diff, sky130
    // poly.11) and `covers_corner(poly, diff)` (poly over an inner corner of
    // diff, poly.10).
    Kind {
        fixed: &[("of_reference", false)],
        ..drc("bend", Cmp::Absent, "gate_corner", &[0, 1], None, &[])
    },
    Kind {
        fixed: &[("of_reference", true)],
        ..drc(
            "covers_corner",
            Cmp::Absent,
            "gate_corner",
            &[0, 1],
            None,
            &[],
        )
    },
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
    // One layer's edges: `angle(diff; allowed: [0deg, 90deg])` (sky130 x.2).
    drc(
        "angle",
        Cmp::Absent,
        "angle",
        &[0],
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
    // LEF MINIMUMCUT on the wide layer, the via's far metal third:
    // `min_cuts(via1, met2, met1; width: 1um) >= 2` is MINIMUMCUT 2 WIDTH 1.0
    // FROMBELOW on met2.
    drc(
        "min_cuts",
        Cmp::Ge,
        "minimum_cut",
        &[0, 1, 2],
        Some(p("", "min_count", Dim::Count)),
        &[p("width", "width", Dim::Length)],
    ),
    drc(
        "min_cuts",
        Cmp::Ge,
        "minimum_cut",
        &[0, 1, 2],
        Some(p("", "min_count", Dim::Count)),
        &[
            p("width", "width", Dim::Length),
            p("within", "within", Dim::Length),
        ],
    ),
    // LEF MAXVIASTACK over the cut layers listed, bottom to top:
    // `via_stack(via1, via2, via3) <= 2`.
    Kind {
        more: true,
        ..drc(
            "via_stack",
            Cmp::Le,
            "via_stack",
            &[0],
            Some(p("", "max_height", Dim::Count)),
            &[],
        )
    },
    drc(
        "via_array_space",
        Cmp::Ge,
        "via_array_spacing",
        &[0],
        LIMIT,
        &[p("array", "array_threshold", Dim::Count)],
    ),
    // LEF cut-layer SPACING: `space(via1, center)` is CENTERTOCENTER, and
    // `adjacent_space(via1; cuts: 3, within: 250nm)` ADJACENTCUTS 3 WITHIN.
    Kind {
        modifier: Some("center"),
        fixed: &[("center", true)],
        ..drc("space", Cmp::Ge, "cut_spacing", &[0], LIMIT, &[])
    },
    Kind {
        fixed: &[("center", false)],
        ..drc(
            "adjacent_space",
            Cmp::Ge,
            "cut_spacing",
            &[0],
            LIMIT,
            ADJACENT,
        )
    },
    Kind {
        modifier: Some("center"),
        fixed: &[("center", true)],
        ..drc(
            "adjacent_space",
            Cmp::Ge,
            "cut_spacing",
            &[0],
            LIMIT,
            ADJACENT,
        )
    },
    // LEF58_SPACINGTABLE on a cut layer, by cut class: `short`/`long` are the
    // classes' sizes, `space` two rows and columns per class (END, SIDE).
    drc(
        "cut_class_space",
        Cmp::Absent,
        "cut_class_spacing",
        &[0],
        None,
        &[
            p("short", "class_short", Dim::LengthList),
            p("long", "class_long", Dim::LengthList),
            p("space", "space", Dim::LengthRows),
        ],
    ),
    drc(
        "patterning",
        Cmp::Ge,
        "multi_patterning",
        &[0],
        Some(p("", "color_spacing", Dim::Length)),
        &[p("colors", "colors", Dim::Count)],
    ),
    // A corner whose angle inside its shape is under the limit (IHP 3.1
    // "acute angles <87 degree"); with no layer, every drawn layer.
    drc(
        "interior_angle",
        Cmp::Ge,
        "min_interior_angle",
        &[],
        Some(p("", "limit", Dim::Angle)),
        &[],
    ),
    drc(
        "interior_angle",
        Cmp::Ge,
        "min_interior_angle",
        &[0],
        Some(p("", "limit", Dim::Angle)),
        &[],
    ),
    // A drawn polygon that crosses itself or encloses no area (IHP 3.1
    // "self-intersecting polygons must be avoided"); with no layer, every
    // drawn layer.
    drc("valid", Cmp::Absent, "polygon_validity", &[], None, &[]),
    drc("valid", Cmp::Absent, "polygon_validity", &[0], None, &[]),
    // Pre-coloured shapes, one anchor layer per mask after the patterned one:
    // `patterning(met1, met1_mask1, met1_mask2; colors: 2) >= 50nm`.
    Kind {
        more: true,
        ..drc(
            "patterning",
            Cmp::Ge,
            "anchored_patterning",
            &[0, 1],
            Some(p("", "color_spacing", Dim::Length)),
            &[p("colors", "colors", Dim::Count)],
        )
    },
    // Every shape (or edge) of the layer is a violation: `forbidden(licon and poly and diff)`.
    drc("forbidden", Cmp::Absent, "forbidden", &[0], None, &[]),
    // Each outer shape holds at least `count` inner shapes entirely: `contains(tap, licon) >= 1`.
    drc(
        "contains",
        Cmp::Ge,
        "must_contain",
        &[0, 1],
        Some(p("", "min_count", Dim::Count)),
        &[],
    ),
    // At most `count` (sky130 rpm.1g "only 1 licon is allowed in ..."), or
    // exactly `count`.
    drc(
        "contains",
        Cmp::Le,
        "must_contain",
        &[0, 1],
        Some(p("", "max_count", Dim::Count)),
        &[],
    ),
    drc(
        "contains",
        Cmp::Eq,
        "must_contain",
        &[0, 1],
        Some(p("", "count", Dim::Count)),
        &[],
    ),
    // Every inner shape lies entirely inside the outer layer: `inside(poly_licon, npc)`.
    drc("inside", Cmp::Absent, "must_be_inside", &[0, 1], None, &[]),
    // Spacing between shapes on the same net, or on different nets (gf180 NW.2a/2b),
    // on one layer or between two (sky130 nwell.7).
    drc(
        "space",
        Cmp::Ge,
        "net_spacing",
        &[0],
        LIMIT,
        &[p("nets", "same_net", Dim::Nets)],
    ),
    drc(
        "space",
        Cmp::Ge,
        "net_spacing",
        &[0, 1],
        LIMIT,
        &[p("nets", "same_net", Dim::Nets)],
    ),
    // Spacing by width and parallel run length, a LEF `SPACINGTABLE`.
    drc(
        "space_table",
        Cmp::Absent,
        "spacing_table",
        &[0],
        None,
        &[
            p("prl", "prl", Dim::LengthList),
            p("width", "width", Dim::LengthList),
            p("space", "space", Dim::LengthRows),
        ],
    ),
    // Wide spacing measured from the wide part and what is attached to it
    // within `attached` (sky130 m1.3a).
    drc(
        "wide_space",
        Cmp::Ge,
        "attached_wide_spacing",
        &[0],
        LIMIT,
        &[
            p("width", "width_threshold", Dim::Length),
            p("attached", "attached", Dim::Length),
        ],
    ),
    // Space between facing edges by the length class of each (ASAP7 M1.S.1
    // to M1.S.5): a square, symmetric table of cells, one row and column per
    // class threshold.
    drc(
        "tip_space_table",
        Cmp::Absent,
        "tip_spacing_table",
        &[0],
        None,
        &[
            p("length", "length", Dim::LengthList),
            p("space", "space", Dim::LengthRows),
        ],
    ),
    // Spacing by the widths of both shapes and, per width, a run: LEF
    // `SPACINGTABLE TWOWIDTHS {WIDTH width [PRL runLength] {spacing}...}`.
    drc(
        "two_width_table",
        Cmp::Absent,
        "two_width_spacing_table",
        &[0],
        None,
        &[
            p("width", "width", Dim::LengthList),
            p("prl", "prl", Dim::OptLengthList),
            p("space", "space", Dim::LengthRows),
        ],
    ),
    // Every span (chord) of a shape is a legal length: one of the list, or at
    // least its last (`LEF58_SPANLENGTHTABLE`).
    drc(
        "span_length",
        Cmp::Absent,
        "span_length",
        &[0],
        None,
        &[
            p("x", "x_spans", Dim::LengthList),
            p("y", "y_spans", Dim::LengthList),
        ],
    ),
    // The exact centre-to-centre pitch of neighbouring rectangles along one
    // axis (ASAP7 FIN.S.1, GATE.S.1): `pitch(fin, vertical) == 27nm`.
    Kind {
        modifier: Some("vertical"),
        fixed: &[("vertical", true)],
        ..drc("pitch", Cmp::Eq, "exact_pitch", &[0], LIMIT, &[])
    },
    Kind {
        modifier: Some("horizontal"),
        fixed: &[("vertical", false)],
        ..drc("pitch", Cmp::Eq, "exact_pitch", &[0], LIMIT, &[])
    },
    // Another shape inside the keep-out box of an end of line
    // (`LEF58_EOLKEEPOUT eolWidth EXTENSION backward side forward`).
    drc(
        "eol_keep_out",
        Cmp::Absent,
        "eol_keep_out",
        &[0],
        None,
        &[
            p("eol_width", "eol_width", Dim::Length),
            p("backward", "backward", Dim::Length),
            p("side", "side", Dim::Length),
            p("forward", "forward", Dim::Length),
        ],
    ),
    // Another cut inside a cut class's keep-out zones (`LEF58_KEEPOUTZONE
    // CUTCLASS c1 [TO c2] ENDEXTENSION .. SIDEEXTENSION ..`).
    drc(
        "keep_out_zone",
        Cmp::Absent,
        "keep_out_zone",
        &[0],
        None,
        &[
            p("class", "short", Dim::LengthPair("long")),
            opt("to", "to_short", Dim::LengthPair("to_long")),
            p("end_side", "end_side", Dim::Length),
            p("end_forward", "end_forward", Dim::Length),
            p("side_side", "side_side", Dim::Length),
            p("side_forward", "side_forward", Dim::Length),
        ],
    ),
    // A gap in a forbidden range between facing edges that run alongside
    // (`LEF58_TWOWIRESFORBIDDENSPACING`).
    drc(
        "forbidden_space",
        Cmp::Absent,
        "forbidden_spacing",
        &[0],
        None,
        &[
            p("min", "min", Dim::Length),
            p("max", "max", Dim::Length),
            p("prl", "prl", Dim::Length),
        ],
    ),
    // Edge layers.
    drc("length", Cmp::Ge, "edge_min_length", &[0], LIMIT, &[]),
    drc("space", Cmp::Ge, "edge_spacing", &[0], LIMIT, &[]),
    drc("space", Cmp::Ge, "edge_spacing", &[0, 1], LIMIT, &[]),
    drc("enclosure", Cmp::Ge, "edge_enclosure", &[0, 1], LIMIT, &[]),
    // Edges facing each other across their shapes' material (back to back), as
    // a channel's length and width (sky130 poly.1b, difftap.2) or a width in
    // one direction (ASAP7 M4.W.1 on `met4.edges().horizontal()`).
    drc("width", Cmp::Ge, "edge_width", &[0], LIMIT, &[]),
    // Edges whose outer sides face each other (face to face): a spacing in one
    // direction (ASAP7 M4.S.2 on `met4.edges().vertical()`).
    drc(
        "facing_space",
        Cmp::Ge,
        "edge_facing_space",
        &[0],
        LIMIT,
        &[],
    ),
    // ERC.
    erc(
        "antenna",
        &[0, 1],
        true,
        &[
            p("max_ratio", "max_ratio", Dim::Scalar),
            opt("sidewall", "sidewall_thickness", Dim::Length),
            opt("diode", "diode_layer", Dim::Layer),
        ],
    ),
    erc(
        "antenna_electrical",
        &[0, 1],
        true,
        &[
            p("max_ratio", "max_ratio", Dim::Scalar),
            opt("sidewall", "sidewall_thickness", Dim::Length),
            p("cut_factor", "cut_factor", Dim::Scalar),
            opt("diode", "diode_layer", Dim::Layer),
            p("diode_credit", "diode_credit", Dim::Scalar),
            p("diode_bonus", "diode_bonus", Dim::Scalar),
            p("area_minus_diode", "area_minus_diode", Dim::Scalar),
            p("gate_plus_diode", "gate_plus_diode", Dim::Scalar),
            opt(
                "diode_reduce",
                "diode_reduce_area",
                Dim::AreaTable("diode_reduce"),
            ),
            opt(
                "diode_max_ratio",
                "diode_max_ratio_area",
                Dim::AreaTable("diode_max_ratio"),
            ),
            opt("exempt", "exempt_layer", Dim::Layer),
        ],
    ),
    erc(
        "conditional_tie",
        &[0, 1, 2, 3],
        false,
        &[
            p("within", "within", Dim::Length),
            p("spacing", "spacing", Dim::LengthList),
            p("max_distance", "max_distance", Dim::LengthList),
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
            opt("narrow", "", Dim::Group(EM_NARROW)),
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
        "esd_cross_domain",
        &[],
        false,
        &[
            p("diodes", "diode", Dim::Models),
            opt("local", "local", Dim::Models),
        ],
    ),
    erc(
        "esd_exposed",
        &[0],
        false,
        &[
            p("clamps", "clamp", Dim::Models),
            opt("resistors", "resistor", Dim::Models),
            opt("rated", "rated", Dim::Models),
        ],
    ),
    erc(
        "esd_ground_coupling",
        &[],
        false,
        &[p("diodes", "diode", Dim::Models)],
    ),
    erc(
        "esd_parasitic",
        &[0, 1],
        false,
        &[p("min_spacing", "min_spacing", Dim::Length)],
    ),
    erc("esd_path", &[0], false, ESD_PATH),
    // The current enters at a second layer's polygons: a guard ring under an
    // injection stress (JESD78).
    erc("esd_path", &[0, 1], false, ESD_PATH),
    erc(
        "esd_topological",
        &[0],
        false,
        &[p("clamps", "clamp", Dim::Models)],
    ),
    erc(
        "floating_gate",
        &[],
        false,
        &[p("labels_are_ports", "labels_are_ports", Dim::Bool)],
    ),
    erc("floating_well", &[0, 1], false, &[]),
    erc("fanout", &[], false, &[p("max", "max_gates", Dim::Count)]),
    erc(
        "forward_diode",
        &[0],
        false,
        &[p("models", "model", Dim::Models)],
    ),
    erc(
        "guard_ring",
        &[0, 1],
        false,
        &[
            opt("max_space", "max_space", Dim::Length),
            opt("min_width", "min_width", Dim::Length),
            opt("pad", "pad", Dim::Layer),
            opt("near", "near", Dim::Layer),
            opt("within", "within", Dim::Length),
        ],
    ),
    erc(
        "guard_ring_bias",
        &[0],
        false,
        &[p("power", "power", Dim::Bool)],
    ),
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
    erc("dynamic_ir_drop", &[], false, &[]),
    erc(
        "em_thermal",
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
            p(
                "thermal_conductivity",
                "thermal_conductivity",
                Dim::ThermalConductivity,
            ),
            p("spreading", "heat_spreading", Dim::Scalar),
            p("sigma", "sigma", Dim::Scalar),
            p("limit_failure", "limit_failure", Dim::Fraction),
            p("max_failure", "max_failure", Dim::Fraction),
        ],
    ),
    erc(
        "latchup_victim",
        &[0, 1, 2],
        false,
        &[
            p("within", "within", Dim::Length),
            p("max_distance", "max_distance", Dim::Length),
            opt("pad", "pad", Dim::Layer),
        ],
    ),
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
    erc("supply_short", &[0, 1, 2], false, &[]),
    erc(
        "tie_area",
        &[0, 1, 2],
        false,
        &[p("min_ratio", "min_ratio", Dim::Fraction)],
    ),
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
    // A high-voltage figure of a conductor lies inside its tag (sky130 hv.X.1,
    // hv.X.4, hvnwell.11); a net holds no tagged and untagged figure at once
    // (hvnwell.10).
    erc(
        "hv_tag",
        &[0, 1],
        false,
        &[p("voltage", "voltage", Dim::Voltage)],
    ),
    erc("mixed_tag", &[0, 1], false, &[]),
    // In the intent's power states: a gate left floating (ERC-F8), and a
    // powered transistor with a floating gate, not an isolation cell (ERC-F7).
    erc("undriven_gate", &[], false, &[]),
    erc(
        "missing_isolation",
        &[],
        false,
        &[opt("isolation", "isolation", Dim::Models)],
    ),
    // The field across the dielectric between two nets' shapes (JEP159A,
    // IC Validator): lateral on one layer, through the stack between two.
    erc(
        "dielectric_field",
        &[0],
        false,
        &[p("max_field", "max_field", Dim::Field)],
    ),
    erc(
        "dielectric_field",
        &[0, 1],
        false,
        &[p("max_field", "max_field", Dim::Field)],
    ),
    // Spacing that grows with the worst-case voltage between two nets
    // (LEF58_VOLTAGESPACING, sky130 hvnwell.8): one layer, or two.
    Kind {
        engine: "voltage_spacing",
        ..erc("voltage_space", &[0], false, VOLTAGE_SPACE)
    },
    Kind {
        engine: "voltage_spacing",
        ..erc("voltage_space", &[0, 1], false, VOLTAGE_SPACE)
    },
];

/// The PEX keys, each given at most once per `pex` statement, and every one
/// but the [`OPTIONAL_PEX_KEYS`] required.
pub(crate) const PEX: [(&str, Dim); 8] = [
    ("thickness", Dim::Length),
    ("height", Dim::Length),
    ("sheet", Dim::Resistance),
    ("dielectric", Dim::Scalar),
    ("area_cap", Dim::CapPerArea),
    ("fringe_cap", Dim::CapPerLength),
    ("tc1", Dim::PerKelvin),
    ("tc2", Dim::PerKelvin2),
];

/// The [`PEX`] keys a row may leave out: a dielectric the process does not
/// state (stated, it must be positive, testing-plan F74), and the temperature
/// coefficients, which a row gives together and exactly when the deck states
/// a `temperature`.
pub(crate) const OPTIONAL_PEX_KEYS: [&str; 3] = ["dielectric", "tc1", "tc2"];

/// Engine kinds whose layer arguments may be edge layers, and what each engine
/// layer slot takes: `Some(true)` edges, `Some(false)` polygons, `None` either.
/// Every other kind refuses an edge layer when the deck is read. A kind named
/// `edge_*` takes only edges, so a polygon argument picks its polygon twin.
pub(crate) const EDGE_KINDS: &[(&str, &[Option<bool>])] = &[
    ("forbidden", &[None]),
    ("edge_min_length", &[Some(true)]),
    ("edge_spacing", &[Some(true), Some(true)]),
    ("edge_enclosure", &[Some(true), Some(false)]),
    ("edge_width", &[Some(true)]),
    ("edge_facing_space", &[Some(true)]),
];
