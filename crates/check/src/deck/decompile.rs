//! A compiled deck back to names: every typed rule as the row the parser
//! would read it into, so the deck can be printed or overridden.

use super::CompiledDeck;
use crate::drc::ruleset::DfmCheck;
use crate::drc::{Rule, StepKind, StepNeighbour, WireBand};
use crate::erc::rules::antenna::AntennaMeasure;
use crate::report::LimitSense;
use crate::report::Severity;
use gpurify_geom::{Dbu, LayerId, Qty, StrId, StrTable};
use gpurify_ingest::deck::{CornerSource, DeckSource, LvsSrc, ParamSource, ParamValue, RuleSource};
use std::collections::HashMap;

/// One rule's row as it is filed, in engine names.
struct Row {
    kind: &'static str,
    layers: Vec<LayerId>,
    params: Vec<(&'static str, ParamSource)>,
}

impl Row {
    fn new(kind: &'static str, layers: &[LayerId]) -> Self {
        Self {
            kind,
            layers: layers.to_vec(),
            params: Vec::new(),
        }
    }

    fn value(mut self, name: &'static str, value: ParamValue) -> Self {
        self.params.push((name, ParamSource::Value(value)));
        self
    }

    fn length(self, name: &'static str, value: gpurify_geom::Dbu) -> Self {
        self.value(name, ParamValue::Length(value))
    }

    fn number(self, name: &'static str, value: f64) -> Self {
        self.value(name, ParamValue::Ratio(value))
    }
}

/// A row's sidewall thickness: the measure of any collector that has one
/// (a cut collects by area whatever the row states).
fn sidewall(measures: &[AntennaMeasure]) -> Option<gpurify_geom::Dbu> {
    measures.iter().find_map(|measure| match *measure {
        AntennaMeasure::Sidewall { thickness } => Some(thickness),
        AntennaMeasure::Area => None,
    })
}

impl CompiledDeck {
    /// The deck as names, in the form the parser reads text into: what
    /// [`lower`](gpurify_ingest::deck::lower) and
    /// [`CompiledDeck::from_deck`] turn back into an equal deck in the same
    /// `strings`. Rules come in deck order ([`CompiledDeck::provenance`]),
    /// and every value as the rule holds it, so a list the parser would read
    /// twice, or an angle written as 180 degrees, comes back as the rule
    /// stores it.
    pub fn source(&self, strings: &StrTable) -> DeckSource {
        let mut source = DeckSource::from_tables(
            &self.layers,
            &self.connectivity,
            &self.devices,
            &self.stack,
            self.temperature.map(gpurify_geom::Qty::raw),
            strings,
        );
        source.lvs = LvsSrc::from_controls(&self.lvs, &source.devices, strings);
        // The default type with no threshold is what a deck without the
        // statement lowers to.
        source.corners = self
            .corners
            .iter()
            .flat_map(|corner| {
                corner.stated.iter().map(|&(layer, values)| CornerSource {
                    corner: strings.resolve(corner.name).to_owned(),
                    layer: strings.resolve(self.layers.name(layer)).to_owned(),
                    values,
                })
            })
            .collect();
        source.stages = self
            .stages
            .name
            .iter()
            .enumerate()
            .map(|(at, &name)| {
                let ids = (self.stages.of_rule.iter())
                    .filter(|&&(_, stage)| usize::from(stage) == at)
                    .map(|&(id, _)| strings.resolve(id).to_owned())
                    .collect();
                (strings.resolve(name).to_owned(), ids)
            })
            .collect();
        source.waivers = (self.waivers.iter())
            .map(|&(rule, layer)| {
                (
                    strings.resolve(rule).to_owned(),
                    strings.resolve(self.layers.name(layer)).to_owned(),
                )
            })
            .collect();
        source.extraction = (self.extraction != gpurify_ingest::deck::Extraction::default())
            .then_some(self.extraction);
        source.pex_models = self.pex_models.clone();
        source.edits = self.edits.clone();
        let name = |layer: LayerId| strings.resolve(self.layers.name(layer)).to_owned();
        // The sheets as written, at the nominal temperature, with their
        // coefficients, rather than at the operating one with none.
        if let Some(law) = &self.temperature_law {
            source.temperature = Some((law.operating_k, law.nominal_k));
            for &(layer, sheet, tc) in &law.rows {
                let layer = name(layer);
                if let Some((_, row)) = source.pex.iter_mut().find(|(on, _)| *on == layer) {
                    row.sheet_res_ohm_sq = sheet;
                    row.tc = Some(tc);
                }
            }
        }
        let mut rows: HashMap<StrId, Row> = HashMap::new();
        for &(id, rule) in &self.drc.rules {
            let mut row = self.drc_row(rule);
            if self.drc.warnings.contains(&id) {
                row = row.value("warning", ParamValue::Flag(true));
            }
            rows.insert(id, row);
        }
        self.erc_rows(strings, &mut rows);
        let mut order: Vec<StrId> = self
            .provenance
            .iter()
            .map(|&(id, _)| id)
            .filter(|id| rows.contains_key(id))
            .collect();
        // A rule no provenance lists (a deck edited by hand) follows, DRC
        // first.
        for (id, _) in self.rules() {
            if !order.contains(&id) {
                order.push(id);
            }
        }
        source.rules = order
            .into_iter()
            .filter_map(|id| {
                let row = rows.remove(&id)?;
                Some(RuleSource {
                    id: strings.resolve(id).to_owned(),
                    kind: row.kind,
                    layers: row.layers.into_iter().map(name).collect(),
                    params: row
                        .params
                        .into_iter()
                        .map(|(param, value)| {
                            let value = match value {
                                ParamSource::Value(ParamValue::Layer(layer)) => {
                                    ParamSource::Layer(name(layer))
                                }
                                ParamSource::Value(ParamValue::Model(model)) => {
                                    ParamSource::Model(strings.resolve(model).to_owned())
                                }
                                other => other,
                            };
                            (param, value)
                        })
                        .collect(),
                })
            })
            .collect();
        source
    }

    /// A DRC rule's row, in the parameter names `drc::RuleSet::from_deck`
    /// reads.
    fn drc_row(&self, rule: Rule) -> Row {
        let one = |layer| Row::new(rule.kind(), &[layer]);
        let two = |a, b| Row::new(rule.kind(), &[a, b]);
        let bounded = |layer, boundary: Option<LayerId>| {
            let mut layers = vec![layer];
            layers.extend(boundary);
            Row::new(rule.kind(), &layers)
        };
        // An enclosure's wire band, `wire_width` only when it bounds.
        let band = |mut row: Row, wire: crate::drc::WireBand| {
            if wire.from.raw() > 0 {
                row = row.length("wire_width", wire.from);
            }
            if let Some(below) = wire.below {
                row = row.length("wire_below", below);
            }
            if let Some(extra) = wire.extra_cut {
                row = row
                    .length("extra_cut_within", extra.within)
                    .value("extra_cut_other", ParamValue::Layer(extra.other))
                    .value("extra_cut_only", ParamValue::Flag(extra.only));
            }
            if let Some(least) = wire.length.0 {
                row = row.length("length_from", least);
            }
            if let Some(short) = wire.length.1 {
                row = row.length("length_below", short);
            }
            row
        };
        match rule {
            Rule::MinWidth { layer, limit }
            | Rule::MaxWidth { layer, limit }
            | Rule::MinEdgeLength { layer, limit }
            | Rule::Notch { layer, limit }
            | Rule::MinSpacing { layer, limit }
            | Rule::CornerToCorner { layer, limit }
            | Rule::EdgeMinLength { layer, limit }
            | Rule::EdgeWidth { layer, limit } => one(layer).length("limit", limit),
            Rule::CutSize {
                layer,
                width,
                height,
            } => one(layer).length("width", width).length("height", height),
            Rule::MinSpacingDiff { a, b, limit }
            | Rule::ProjectionSpacing { a, b, limit }
            | Rule::Overlap { a, b, limit } => two(a, b).length("limit", limit),
            Rule::EolSpacing {
                layer,
                eol_width,
                limit,
            } => one(layer)
                .length("eol_width", eol_width)
                .length("limit", limit),
            Rule::PrlSpacing {
                layer,
                prl_threshold,
                limit,
            } => one(layer)
                .length("prl_threshold", prl_threshold)
                .length("limit", limit),
            Rule::WideDependentSpacing {
                layer,
                width_threshold,
                limit,
            } => one(layer)
                .length("width_threshold", width_threshold)
                .length("limit", limit),
            Rule::MinArea { layer, limit } | Rule::MinEnclosedArea { layer, limit } => {
                one(layer).value("limit", ParamValue::Area(limit))
            }
            Rule::Cheesing {
                layer,
                max_unslotted,
            } => one(layer).value("max_unslotted", ParamValue::Area(max_unslotted)),
            Rule::Density {
                layer,
                boundary,
                window,
                step,
                limit,
                sense,
            } => bounded(layer, boundary)
                .length("window", window)
                .length("step", step)
                .number("limit", limit)
                .value(
                    "maximum",
                    ParamValue::Flag(sense == crate::report::LimitSense::Maximum),
                ),
            Rule::GlobalDensity {
                layer,
                boundary,
                limit,
                sense,
            } => bounded(layer, boundary).number("limit", limit).value(
                "maximum",
                ParamValue::Flag(sense == crate::report::LimitSense::Maximum),
            ),
            Rule::MinEnclosure {
                outer,
                inner,
                limit,
                wire,
            } => band(two(outer, inner).length("limit", limit), wire),
            Rule::NoncoincidentEnclosure {
                outer,
                inner,
                limit,
            }
            | Rule::MaxEnclosure {
                outer,
                inner,
                limit,
            } => two(outer, inner).length("limit", limit),
            Rule::FullWidth { outer, inner } => two(outer, inner),
            Rule::AsymmetricEnclosure {
                outer,
                inner,
                min_one_side,
                wire,
            } => band(two(outer, inner).length("min_one_side", min_one_side), wire),
            Rule::AdjacentEnclosure {
                outer,
                inner,
                min_one_side,
            } => two(outer, inner).length("min_one_side", min_one_side),
            Rule::MinExtension {
                layer,
                reference,
                limit,
            } => two(layer, reference).length("limit", limit),
            Rule::GateCorner {
                layer,
                reference,
                of_reference,
            } => two(layer, reference).value("of_reference", ParamValue::Flag(of_reference)),
            Rule::MaxDistanceToTap { well, tap, limit } => two(well, tap).length("limit", limit),
            Rule::OffGrid { pitch } => Row::new(rule.kind(), &[]).length("pitch", pitch),
            Rule::Angle { layer, allowed } => {
                let layers: Vec<LayerId> = layer.into_iter().collect();
                let mut row = Row::new(rule.kind(), &layers);
                for bit in 0..4u32 {
                    if allowed & (1 << bit) != 0 {
                        row = row.value("angle", ParamValue::Count(45 * bit));
                    }
                }
                row
            }
            Rule::RedundantVia {
                layer,
                min_count,
                within,
            } => one(layer)
                .value("min_count", ParamValue::Count(min_count.into()))
                .length("within", within),
            Rule::MinimumCut {
                cut,
                wide,
                other,
                width,
                thin,
                within,
                min_count,
            } => {
                let mut row = Row::new(rule.kind(), &[cut, wide, other]).length("width", width);
                if let Some((length, distance)) = thin {
                    row = row.length("length", length).length("distance", distance);
                }
                if let Some(within) = within {
                    row = row.length("within", within);
                }
                row.value("min_count", ParamValue::Count(min_count.into()))
            }
            Rule::MetalWidthVia {
                cut,
                below,
                above,
                below_band,
                above_band,
                width,
                height,
            } => {
                // A band's upper bound is one past the widest width it holds.
                let max = |band: WireBand| {
                    band.below
                        .map_or(band.from, |below| below - Dbu::new_unchecked(1))
                };
                Row::new(rule.kind(), &[cut, below, above])
                    .length("below_min", below_band.from)
                    .length("below_max", max(below_band))
                    .length("above_min", above_band.from)
                    .length("above_max", max(above_band))
                    .length("cut_width", width)
                    .length("cut_height", height)
            }
            Rule::StackSpacing {
                a,
                b,
                metal,
                same_only,
                limit,
            } => Row::new(rule.kind(), &[a, b, metal])
                .value("same_net", ParamValue::Flag(same_only))
                .length("limit", limit),
            Rule::MaxCutSpacing { cut, others, limit } => {
                let layers: Vec<LayerId> = std::iter::once(cut).chain(others).collect();
                Row::new(rule.kind(), &layers).length("limit", limit)
            }
            Rule::ViaStack {
                stack,
                single,
                max_height,
            } => Row::new(
                rule.kind(),
                self.drc
                    .stacks
                    .get(stack as usize)
                    .map_or(&[], Vec::as_slice),
            )
            .value("max_height", ParamValue::Count(max_height.into()))
            .value("single", ParamValue::Flag(single)),
            Rule::CutSpacing {
                layer,
                center,
                adjacent,
                within,
                limit,
            } => {
                let mut row = one(layer).value("center", ParamValue::Flag(center));
                if adjacent != 0 {
                    row = row
                        .value("adjacent", ParamValue::Count(adjacent.into()))
                        .length("within", within);
                }
                row.length("limit", limit)
            }
            Rule::CutClassSpacing { layer, table } => {
                let mut row = one(layer);
                if let Some(table) = self.drc.cut_tables.get(table as usize) {
                    for (param, cells) in [
                        ("class_short", &table.short),
                        ("class_long", &table.long),
                        ("space", &table.space),
                    ] {
                        for &cell in cells {
                            row = row.length(param, cell);
                        }
                    }
                }
                row
            }
            Rule::ViaArraySpacing {
                layer,
                array_threshold,
                limit,
            } => one(layer)
                .value("array_threshold", ParamValue::Count(array_threshold.into()))
                .length("limit", limit),
            Rule::MultiPatterning {
                layer,
                colors,
                color_spacing,
            } => one(layer)
                .value("colors", ParamValue::Count(colors.into()))
                .length("color_spacing", color_spacing),
            Rule::AnchoredPatterning {
                layer,
                anchors,
                colors,
                color_spacing,
            } => {
                let mut layers = vec![layer];
                layers.extend(anchors.into_iter().flatten());
                Row::new(rule.kind(), &layers)
                    .value("colors", ParamValue::Count(colors.into()))
                    .length("color_spacing", color_spacing)
            }
            Rule::MeanCriticalArea {
                layer,
                sizes,
                limit,
            } => {
                let mut row = one(layer);
                if let Some(sizes) = self.drc.defect_sizes.get(sizes as usize) {
                    for &radius in &sizes.radius {
                        row = row.length("radii", radius);
                    }
                    for &weight in &sizes.weight {
                        row = row.number("weights", weight);
                    }
                }
                row.value("limit", ParamValue::Area(limit))
            }
            Rule::CriticalArea {
                layer,
                radius,
                limit,
            } => one(layer)
                .length("radius", radius)
                .value("limit", ParamValue::Area(limit)),
            Rule::ViaRedundancy {
                cut,
                lower,
                upper,
                pitch,
                space,
                limit,
            } => Row::new(rule.kind(), &[cut, lower, upper])
                .length("pitch", pitch)
                .length("space", space)
                .number("limit", limit),
            Rule::DfmScore {
                check,
                layer,
                outer,
                required,
                recommended,
                rate,
                limit,
            } => {
                let mut layers = vec![layer];
                layers.extend(outer);
                let check = match check {
                    DfmCheck::Space => 0,
                    DfmCheck::Width => 1,
                    DfmCheck::Enclosure => 2,
                };
                Row::new(rule.kind(), &layers)
                    .value("check", ParamValue::Count(check))
                    .length("required", required)
                    .length("recommended", recommended)
                    .number("rate", rate)
                    .number("limit", limit)
            }
            Rule::PatternMatch { layer, pattern } => {
                let mut row = one(layer);
                if let Some(pattern) = self.drc.patterns.get(pattern as usize) {
                    row = row
                        .length("window_w", pattern.window.0)
                        .length("window_h", pattern.window.1);
                    for (xs, ys, boxes) in [
                        ("shape_x", "shape_y", &pattern.shapes),
                        ("ignore_x", "ignore_y", &pattern.ignore),
                    ] {
                        for b in boxes {
                            row = row.length(xs, b.xlo).length(xs, b.xhi);
                            row = row.length(ys, b.ylo).length(ys, b.yhi);
                        }
                    }
                }
                row
            }
            Rule::CutAreaChange {
                pre,
                post,
                lower,
                upper,
                bands,
            } => {
                let mut row = Row::new(rule.kind(), &[pre, post, lower, upper]);
                if let Some(bands) = self.drc.cut_area_bands.get(bands as usize) {
                    for &cuts in &bands.cuts {
                        row = row.value("cuts", ParamValue::Count(cuts));
                    }
                    for &change in &bands.change {
                        row = row.value("change", ParamValue::Area(change));
                    }
                }
                row
            }
            Rule::CoverDensity {
                layer,
                cover,
                boundary,
                window,
                step,
                bands,
            } => {
                let mut layers = vec![layer, cover];
                layers.extend(boundary);
                let mut row = Row::new(rule.kind(), &layers)
                    .length("window", window)
                    .length("step", step);
                if let Some(bands) = self.drc.cover_bands.get(bands as usize) {
                    for &cover in &bands.cover {
                        row = row.number("cover", cover);
                    }
                    for &density in &bands.density {
                        row = row.number("density", density);
                    }
                    row = row.value("inclusive", ParamValue::Flag(bands.inclusive));
                }
                row
            }
            Rule::DensityBalance {
                a,
                b,
                boundary,
                window,
                step,
                limit,
            } => {
                let mut layers = vec![a, b];
                layers.extend(boundary);
                Row::new(rule.kind(), &layers)
                    .length("window", window)
                    .length("step", step)
                    .number("limit", limit)
            }
            Rule::Forbidden { layer } => one(layer),
            // `==` as `count`, else the bound stated.
            Rule::MustContain {
                outer,
                inner,
                min_count,
                max_count,
            } => match (min_count, max_count) {
                (min, max) if min == max => {
                    two(outer, inner).value("count", ParamValue::Count(min))
                }
                (min, u32::MAX) => two(outer, inner).value("min_count", ParamValue::Count(min)),
                (0, max) => two(outer, inner).value("max_count", ParamValue::Count(max)),
                (min, max) => two(outer, inner)
                    .value("min_count", ParamValue::Count(min))
                    .value("max_count", ParamValue::Count(max)),
            },
            Rule::MustBeInside { inner, outer } => two(inner, outer),
            Rule::NetSpacing {
                layer,
                other,
                same_net,
                limit,
            } => bounded(layer, other)
                .value("same_net", ParamValue::Flag(same_net))
                .length("limit", limit),
            Rule::SpacingTable { layer, table } => {
                let mut row = one(layer);
                if let Some(table) = self.drc.tables.get(table as usize) {
                    for (param, cells) in [
                        ("prl", &table.prl),
                        ("width", &table.width),
                        ("space", &table.space),
                    ] {
                        for &cell in cells {
                            row = row.length(param, cell);
                        }
                    }
                }
                row
            }
            Rule::AttachedWideSpacing {
                layer,
                width_threshold,
                attached,
                limit,
            } => one(layer)
                .length("width_threshold", width_threshold)
                .length("attached", attached)
                .length("limit", limit),
            Rule::EdgeSpacing { a, b, limit } => {
                let mut layers = vec![a];
                layers.extend(b);
                Row::new(rule.kind(), &layers).length("limit", limit)
            }
            Rule::EdgeEnclosure {
                edges,
                outer,
                limit,
            } => two(edges, outer).length("limit", limit),
            Rule::Count {
                layer,
                limit,
                sense,
            } => one(layer)
                .value("limit", ParamValue::Count(limit))
                .value("maximum", ParamValue::Flag(sense == LimitSense::Maximum)),
            Rule::AspectRatio { layer, limit } => one(layer).number("limit", limit),
            Rule::TotalArea { layer, limit } => one(layer).value("limit", ParamValue::Area(limit)),
            Rule::CutClass { layer, classes } => {
                let mut row = one(layer);
                for &(short, long) in self.drc.classes.get(classes as usize).into_iter().flatten() {
                    row = row.length("width", short).length("height", long);
                }
                row
            }
            Rule::EdgeFacingSpace { layer, limit, prl } => {
                let row = one(layer).length("limit", limit);
                if prl.raw() > 0 {
                    row.length("prl", prl)
                } else {
                    row
                }
            }
            Rule::RegionDensity {
                layer,
                region,
                limit,
                sense,
            } => two(layer, region)
                .number("limit", limit)
                .value("maximum", ParamValue::Flag(sense == LimitSense::Maximum)),
            Rule::AllowedWidth {
                layer,
                widths,
                open_last,
            } => {
                let mut row = one(layer);
                for &width in self.drc.widths.get(widths as usize).into_iter().flatten() {
                    row = row.length("width", width);
                }
                if open_last {
                    row = row.value("open_last", ParamValue::Flag(true));
                }
                row
            }
            Rule::MinInteriorAngle { layer, limit } => {
                let layers: Vec<LayerId> = layer.into_iter().collect();
                Row::new(rule.kind(), &layers).number("limit", limit)
            }
            Rule::PolygonValidity { layer } => {
                let layers: Vec<LayerId> = layer.into_iter().collect();
                Row::new(rule.kind(), &layers)
            }
            Rule::MinStep {
                layer,
                limit,
                kind,
                length_sum,
            } => {
                let (name, value) = match kind {
                    StepKind::MaxEdges(most) => ("max_edges", u32::from(most)),
                    StepKind::OutsideCorner => ("corner", 0),
                    StepKind::InsideCorner => ("corner", 1),
                    StepKind::Step => ("corner", 2),
                };
                let mut row = one(layer)
                    .length("limit", limit)
                    .value(name, ParamValue::Count(value));
                if let Some(sum) = length_sum {
                    row = row.length("length_sum", sum);
                }
                row
            }
            Rule::MinStepAdjacent {
                layer,
                limit,
                neighbour,
            } => {
                let row = one(layer).length("limit", limit);
                match neighbour {
                    StepNeighbour::Adjacent {
                        length,
                        eol,
                        except_rectangle,
                    } => {
                        let mut row = row.length("adjacent", length);
                        if let Some(eol) = eol {
                            row = row.length("adjacent_eol", eol);
                        }
                        row.value("except_rectangle", ParamValue::Flag(except_rectangle))
                    }
                    StepNeighbour::BetweenEol(eol) => row.length("between_eol", eol),
                }
            }
            Rule::TipSpacingTable { layer, table } => {
                let mut row = one(layer);
                if let Some(table) = self.drc.class_tables.get(table as usize) {
                    for &class in &table.class {
                        row = row.length("length", class);
                    }
                    for &cell in &table.space {
                        row = row.length("space", cell);
                    }
                }
                row
            }
            Rule::TwoWidthSpacingTable { layer, table } => {
                let mut row = one(layer);
                if let Some(table) = self.drc.class_tables.get(table as usize) {
                    for &width in &table.class {
                        row = row.length("width", width);
                    }
                    for &run in &table.prl {
                        row = match run {
                            Some(run) => row.length("prl", run),
                            None => row.value("prl", ParamValue::Flag(false)),
                        };
                    }
                    for &cell in &table.space {
                        row = row.length("space", cell);
                    }
                }
                row
            }
            Rule::SpanLength { layer, table } => {
                let mut row = one(layer);
                if let Some(table) = self.drc.span_tables.get(table as usize) {
                    for &span in &table.x {
                        row = row.length("x_spans", span);
                    }
                    for &span in &table.y {
                        row = row.length("y_spans", span);
                    }
                    for (param, except) in
                        [("x_except", table.x_except), ("y_except", table.y_except)]
                    {
                        if let Some(except) = except {
                            row = row.length(param, except);
                        }
                    }
                }
                row
            }
            Rule::ForbiddenSpacing {
                layer,
                min,
                max,
                prl,
            } => one(layer)
                .length("min", min)
                .length("max", max)
                .length("prl", prl),
            Rule::EolWithinSpacing {
                layer,
                eol_width,
                within,
                parallel,
                end_to_end,
                limit,
                lef58,
            } => {
                let mut row = one(layer)
                    .length("eol_width", eol_width)
                    .length("eol_within", within);
                if let Some(parallel) = parallel {
                    row = row
                        .length("par_space", parallel.space)
                        .length("par_within", parallel.within)
                        .value("two_edges", ParamValue::Flag(parallel.two_edges));
                }
                if let Some(space) = end_to_end {
                    row = row.length("end_to_end", space);
                }
                if let Some(side) = lef58.side_length {
                    row = row
                        .length("side_length", side.length)
                        .value("side_length_maximum", ParamValue::Flag(side.maximum))
                        .value("side_length_two_sides", ParamValue::Flag(side.two_sides));
                }
                if let Some(width) = lef58.opposite_width {
                    row = row.length("opposite_width", width);
                }
                if lef58.subtract_eol_width || lef58.parallel_min_length.is_some() {
                    row = row.value(
                        "par_subtract_eol_width",
                        ParamValue::Flag(lef58.subtract_eol_width),
                    );
                    if let Some(min) = lef58.parallel_min_length {
                        row = row.length("par_min_length", min);
                    }
                }
                if let Some((space, prl)) = lef58.end_prl {
                    row = row.length("end_prl_space", space).length("end_prl", prl);
                }
                if let Some((space, horizontal)) = lef58.wrong_dir {
                    row = row
                        .length("wrong_dir_space", space)
                        .value("wrong_dir_horizontal", ParamValue::Flag(horizontal));
                }
                if let Some(extension) = lef58.extension {
                    row = row.length("eol_extension", extension);
                }
                if let Some(cut) = lef58.enclose_cut {
                    row = row
                        .value("enclose_cut_layer", ParamValue::Layer(cut.cut))
                        .length("enclose_cut_within", cut.within)
                        .length("enclose_cut_space", cut.space)
                        .value("enclose_cut_all", ParamValue::Flag(cut.all));
                }
                row.length("limit", limit)
            }
            Rule::Origin { layer } => one(layer),
            Rule::ProtrusionWidth { layer, wide, limit } => {
                one(layer).length("wide", wide).length("limit", limit)
            }
            Rule::KeepOutZone {
                layer,
                class,
                to,
                end,
                side,
            } => {
                let mut row = one(layer).length("short", class.0).length("long", class.1);
                if let Some((short, long)) = to {
                    row = row.length("to_short", short).length("to_long", long);
                }
                row.length("end_side", end.0)
                    .length("end_forward", end.1)
                    .length("side_side", side.0)
                    .length("side_forward", side.1)
            }
            Rule::EolKeepOut {
                layer,
                eol_width,
                backward,
                side,
                forward,
            } => one(layer)
                .length("eol_width", eol_width)
                .length("backward", backward)
                .length("side", side)
                .length("forward", forward),
            Rule::ConvexCornerSpacing {
                layer,
                corner_to_corner,
                except_eol,
                limit,
            } => {
                let mut row =
                    one(layer).value("corner_to_corner", ParamValue::Flag(corner_to_corner));
                if let Some(width) = except_eol {
                    row = row.length("except_eol", width);
                }
                row.length("limit", limit)
            }
            Rule::ExactPitch {
                layer,
                vertical,
                pitch,
            } => one(layer)
                .value("vertical", ParamValue::Flag(vertical))
                .length("limit", pitch),
        }
    }

    /// Every ERC row, in the parameter names `erc::RuleSet::from_deck` reads.
    #[allow(clippy::too_many_lines, reason = "one arm per table")]
    fn erc_rows(&self, strings: &StrTable, rows: &mut HashMap<StrId, Row>) {
        let erc = &self.erc;
        let span = |start: &[u32], row: usize| start[row] as usize..start[row + 1] as usize;
        let model = |id: StrId| ParamSource::Model(strings.resolve(id).to_owned());
        let mut file = |head: &crate::erc::ruleset::RuleHead, row: usize, mut filed: Row| {
            if head.severity[row] == Severity::Warning {
                filed = filed.value("warning", ParamValue::Flag(true));
            }
            rows.insert(head.rule[row], filed);
        };
        let t = &erc.antenna;
        for r in 0..t.head.len() {
            let collectors = span(&t.collector_start, r);
            let mut layers = vec![t.gate[r]];
            layers.extend_from_slice(&t.collector[collectors.clone()]);
            let mut row = Row::new("antenna", &layers).number("max_ratio", t.max_ratio[r]);
            if let Some(thickness) = sidewall(&t.collector_measure[collectors]) {
                row = row.length("sidewall_thickness", thickness);
            }
            if let Some(diode) = t.diode[r] {
                row = row.value("diode_layer", ParamValue::Layer(diode));
            }
            file(&t.head, r, row);
        }
        let t = &erc.antenna_electrical;
        for r in 0..t.head.len() {
            let collectors = span(&t.collector_start, r);
            let mut layers = vec![t.gate[r]];
            layers.extend_from_slice(&t.collector[collectors.clone()]);
            let mut row =
                Row::new("antenna_electrical", &layers).number("max_ratio", t.max_ratio[r]);
            if let Some(thickness) = sidewall(&t.collector_measure[collectors]) {
                row = row.length("sidewall_thickness", thickness);
            }
            row = row.number("cut_factor", t.cut_factor[r]);
            if let Some(diode) = t.diode[r] {
                row = row.value("diode_layer", ParamValue::Layer(diode));
            }
            row = row
                .number("diode_credit", t.diode_credit[r])
                .number("diode_bonus", t.diode_bonus[r])
                .number("area_minus_diode", t.area_minus_diode[r])
                .number("gate_plus_diode", t.gate_plus_diode[r]);
            for (area, value, table) in [
                ("diode_reduce_area", "diode_reduce", &t.diode_reduce[r]),
                (
                    "diode_max_ratio_area",
                    "diode_max_ratio",
                    &t.diode_max_ratio[r],
                ),
            ] {
                for &(at, of) in table {
                    row = row.value(area, ParamValue::Area(at)).number(value, of);
                }
            }
            if let Some(exempt) = t.exempt[r] {
                row = row.value("exempt_layer", ParamValue::Layer(exempt));
            }
            file(&t.head, r, row);
        }
        let t = &erc.density_cmp;
        for r in 0..t.head.len() {
            let mut row = Row::new("density_cmp", &[t.layer[r]])
                .length("window_x", t.window[r].0)
                .length("window_y", t.window[r].1)
                .length("step_x", t.step[r].0)
                .length("step_y", t.step[r].1);
            for (param, bound) in [
                ("min_density", t.min_density[r]),
                ("max_density", t.max_density[r]),
                ("max_neighbour_delta", t.max_neighbour_delta[r]),
            ] {
                if let Some(bound) = bound {
                    row = row.number(param, bound);
                }
            }
            row = row.value(
                "include_partial_windows",
                ParamValue::Flag(t.include_partial_windows[r]),
            );
            if let Some(cmp) = t.cmp[r] {
                row = row
                    .number("cmp_target_density", cmp.target_density)
                    .length("cmp_thickness_sensitivity", cmp.thickness_sensitivity)
                    .length("cmp_max_abs_thickness_delta", cmp.max_abs_thickness_delta);
            }
            file(&t.head, r, row);
        }
        for r in 0..erc.domain_crossing.head.len() {
            file(
                &erc.domain_crossing.head,
                r,
                Row::new("domain_crossing", &[]),
            );
        }
        for (kind, t) in [
            ("drain_source", &erc.drain_source),
            ("gate_oxide", &erc.gate_oxide),
        ] {
            for r in 0..t.head.len() {
                let mut row = Row::new(kind, &[]);
                for &id in &t.model[span(&t.model_start, r)] {
                    row.params.push(("model", model(id)));
                }
                file(
                    &t.head,
                    r,
                    row.number("max_voltage", t.max_voltage[r].raw()),
                );
            }
        }
        let t = &erc.electromigration;
        for r in 0..t.head.len() {
            let layers = span(&t.layer_start, r);
            let first = layers.start;
            let row = Row::new("electromigration", &t.layer[layers])
                .number("max_density", t.max_density[first].raw())
                .number("max_current_per_cut", t.max_current_per_cut[first].raw())
                .number("blech_limit", t.blech_limit[first].raw())
                .number("reference_temperature", t.reference_temperature[r].raw())
                .number("activation_energy_ev", t.activation_energy_ev[r])
                .number("current_exponent", t.current_exponent[r]);
            file(&t.head, r, row);
        }
        for (kind, t) in [("em_rms", &erc.em_rms), ("em_peak", &erc.em_peak)] {
            for r in 0..t.head.len() {
                let mut row = Row::new(kind, &t.layer[span(&t.layer_start, r)])
                    .number("max_current_per_cut", t.max_current_per_cut[r].raw());
                for &f in &t.frequency[span(&t.frequency_start, r)] {
                    row = row.number("frequency", f);
                }
                for &w in &t.width[span(&t.width_start, r)] {
                    row = row.length("width", w);
                }
                for d in &t.density[span(&t.density_start, r)] {
                    row = row.number("density", d.raw());
                }
                file(&t.head, r, row);
            }
        }
        let t = &erc.em_current_density;
        for r in 0..t.head.len() {
            let layers = span(&t.layer_start, r);
            let first = layers.start;
            let mut row = Row::new("em_current_density", &t.layer[layers])
                .number("max_density", t.max_density[first].raw())
                .number("max_current_per_cut", t.max_current_per_cut[first].raw());
            if let Some((width, current)) = t.narrow[first] {
                row = row
                    .length("narrow_width", width)
                    .number("narrow_current", current.raw());
            }
            file(&t.head, r, row);
        }
        let t = &erc.esd_latchup;
        for r in 0..t.head.len() {
            let mut row = Row::new("esd_latchup", &[t.pad[r], t.guard_ring[r]])
                .length("min_guard_ring_width", t.min_guard_ring_width[r])
                .length("max_tap_distance", t.max_tap_distance[r]);
            for &id in &t.clamp[span(&t.clamp_start, r)] {
                row.params.push(("clamp", model(id)));
            }
            file(&t.head, r, row);
        }
        let t = &erc.esd_topological;
        for r in 0..t.head.len() {
            let mut row = Row::new("esd_topological", &[t.pad[r]]);
            for &id in &t.clamp[span(&t.clamp_start, r)] {
                row.params.push(("clamp", model(id)));
            }
            file(&t.head, r, row);
        }
        let t = &erc.conditional_tie;
        for r in 0..t.head.len() {
            let mut row = Row::new(
                "conditional_tie",
                &[t.region[r], t.tap[r], t.well[r], t.other[r]],
            )
            .length("within", t.within[r]);
            for &value in &t.spacing[span(&t.spacing_start, r)] {
                row = row.length("spacing", value);
            }
            for &value in &t.max_distance[span(&t.max_distance_start, r)] {
                row = row.length("max_distance", value);
            }
            file(&t.head, r, row);
        }
        let t = &erc.esd_cross_domain;
        for r in 0..t.head.len() {
            let mut row = Row::new("esd_cross_domain", &[]);
            for &id in &t.diode[span(&t.diode_start, r)] {
                row.params.push(("diode", model(id)));
            }
            for &id in &t.local[span(&t.local_start, r)] {
                row.params.push(("local", model(id)));
            }
            for &id in &t.resistor[span(&t.resistor_start, r)] {
                row.params.push(("resistor", model(id)));
            }
            for (name, value) in [
                ("min_series", t.min_series[r]),
                ("max_ground_resistance", t.max_ground_resistance[r]),
                ("coupling_resistance", t.coupling_resistance[r]),
            ] {
                if let Some(value) = value {
                    row = row.number(name, value.raw());
                }
            }
            file(&t.head, r, row);
        }
        let t = &erc.esd_exposed;
        for r in 0..t.head.len() {
            let mut row = Row::new("esd_exposed", &[t.pad[r]]);
            for &id in &t.clamp[span(&t.clamp_start, r)] {
                row.params.push(("clamp", model(id)));
            }
            for &id in &t.resistor[span(&t.resistor_start, r)] {
                row.params.push(("resistor", model(id)));
            }
            for &id in &t.rated[span(&t.rated_start, r)] {
                row.params.push(("rated", model(id)));
            }
            if let Some(min) = t.min_series[r] {
                row = row.number("min_series", min.raw());
            }
            file(&t.head, r, row);
        }
        let t = &erc.esd_ground_coupling;
        for r in 0..t.head.len() {
            let mut row = Row::new("esd_ground_coupling", &[]);
            for &id in &t.diode[span(&t.diode_start, r)] {
                row.params.push(("diode", model(id)));
            }
            file(&t.head, r, row);
        }
        let t = &erc.esd_parasitic;
        for r in 0..t.head.len() {
            let row = Row::new("esd_parasitic", &[t.pad[r], t.diffusion[r]])
                .length("min_spacing", t.min_spacing[r]);
            file(&t.head, r, row);
        }
        let t = &erc.esd_path;
        for r in 0..t.head.len() {
            let layers: Vec<LayerId> = if t.source[r] == t.pad[r] {
                vec![t.pad[r]]
            } else {
                vec![t.pad[r], t.source[r]]
            };
            let mut row = Row::new("esd_path", &layers)
                .number("current", t.current[r].raw())
                .number("clamp_resistance", t.clamp_resistance[r].raw());
            for &id in &t.clamp[span(&t.clamp_start, r)] {
                row.params.push(("clamp", model(id)));
            }
            let limits = [
                ("max_resistance", t.max_resistance[r].map(Qty::raw)),
                ("clamp_it2", t.clamp_it2[r].map(Qty::raw)),
                ("max_density", t.max_density[r].map(Qty::raw)),
                (
                    "max_current_per_cut",
                    t.max_current_per_cut[r].map(Qty::raw),
                ),
                ("max_voltage", t.max_voltage[r].map(Qty::raw)),
            ];
            for (name, limit) in limits {
                if let Some(value) = limit {
                    row = row.number(name, value);
                }
            }
            if let Some(width) = t.min_width[r] {
                row = row.length("min_width", width);
            }
            if let Some(held) = t.clamp_voltage[r] {
                row = row.number("clamp_voltage", held.raw());
            }
            file(&t.head, r, row);
        }
        let t = &erc.esd_pin_pair;
        for r in 0..t.head.len() {
            let mut row = Row::new("esd_pin_pair", &[t.pad[r]])
                .number("current", t.current[r].raw())
                .number("clamp_resistance", t.clamp_resistance[r].raw())
                .number("max_resistance", t.max_resistance[r].raw());
            for &id in &t.clamp[span(&t.clamp_start, r)] {
                row.params.push(("clamp", model(id)));
            }
            file(&t.head, r, row);
        }
        let t = &erc.esd_clamp_resistance;
        for r in 0..t.head.len() {
            let mut row = Row::new("esd_clamp_resistance", &[t.pad[r]])
                .number("max_resistance", t.max_resistance[r].raw());
            for &id in &t.clamp[span(&t.clamp_start, r)] {
                row.params.push(("clamp", model(id)));
            }
            file(&t.head, r, row);
        }
        let t = &erc.forward_diode;
        for r in 0..t.head.len() {
            let mut row = Row::new("forward_diode", &[t.marker[r]]);
            for &id in &t.model[span(&t.model_start, r)] {
                row.params.push(("model", model(id)));
            }
            file(&t.head, r, row);
        }
        let t = &erc.guard_ring;
        for r in 0..t.head.len() {
            let mut row = Row::new("guard_ring", &[t.target[r], t.ring[r]]);
            if let Some(space) = t.max_space[r] {
                row = row.length("max_space", space);
            }
            if let Some(width) = t.min_width[r] {
                row = row.length("min_width", width);
            }
            if let Some(pad) = t.pad[r] {
                row = row.value("pad", ParamValue::Layer(pad));
            }
            if let Some((near, within)) = t.near[r] {
                row = row
                    .value("near", ParamValue::Layer(near))
                    .length("within", within);
            }
            if let Some(clear) = t.clear[r] {
                row = row.value("clear", ParamValue::Layer(clear));
            }
            file(&t.head, r, row);
        }
        let t = &erc.guard_ring_bias;
        for r in 0..t.head.len() {
            let row = Row::new("guard_ring_bias", &[t.ring[r]])
                .value("power", ParamValue::Flag(t.power[r]));
            file(&t.head, r, row);
        }
        let t = &erc.latchup_victim;
        for r in 0..t.head.len() {
            let mut row = Row::new("latchup_victim", &[t.aggressor[r], t.region[r], t.tap[r]])
                .length("within", t.within[r])
                .length("max_distance", t.max_distance[r]);
            if let Some(pad) = t.pad[r] {
                row = row.value("pad", ParamValue::Layer(pad));
            }
            if let Some((bias, above)) = t.bias[r] {
                row = row
                    .value("bias", ParamValue::Layer(bias))
                    .value("forward", ParamValue::Count(u32::from(!above)));
            }
            file(&t.head, r, row);
        }
        let t = &erc.tie_area;
        for r in 0..t.head.len() {
            let row = Row::new("tie_area", &[t.region[r], t.contact[r], t.channel[r]])
                .number("min_ratio", t.min_ratio[r]);
            file(&t.head, r, row);
        }
        let t = &erc.floating_gate;
        for r in 0..t.head.len() {
            let row = Row::new("floating_gate", &[])
                .value("labels_are_ports", ParamValue::Flag(t.labels_are_ports[r]));
            file(&t.head, r, row);
        }
        let t = &erc.floating_well;
        for r in 0..t.head.len() {
            file(
                &t.head,
                r,
                Row::new("floating_well", &[t.well[r], t.tap[r]]),
            );
        }
        let t = &erc.hv_domain;
        for r in 0..t.head.len() {
            let mut row =
                Row::new("hv_domain", &[]).number("max_domain_delta", t.max_domain_delta[r].raw());
            if let Some(isolation) = t.isolation[r] {
                row = row.value("isolation", ParamValue::Layer(isolation));
            }
            file(&t.head, r, row);
        }
        for r in 0..erc.ir_drop.head.len() {
            file(&erc.ir_drop.head, r, Row::new("ir_drop", &[]));
        }
        for r in 0..erc.dynamic_ir_drop.head.len() {
            file(
                &erc.dynamic_ir_drop.head,
                r,
                Row::new("dynamic_ir_drop", &[]),
            );
        }
        let t = &erc.em_thermal;
        for r in 0..t.head.len() {
            let layers = span(&t.layer_start, r);
            let first = layers.start;
            let row = Row::new("em_thermal", &t.layer[layers])
                .number("max_density", t.max_density[first].raw())
                .number("max_current_per_cut", t.max_current_per_cut[first].raw())
                .number("blech_limit", t.blech_limit[first].raw())
                .number("reference_temperature", t.reference_temperature[r].raw())
                .number("activation_energy_ev", t.activation_energy_ev[r])
                .number("current_exponent", t.current_exponent[r])
                .number("thermal_conductivity", t.thermal_conductivity[r])
                .number("heat_spreading", t.heat_spreading[r])
                .number("sigma", t.sigma[r])
                .number("limit_failure", t.limit_failure[r])
                .number("max_failure", t.max_failure[r]);
            file(&t.head, r, row);
        }
        let t = &erc.missing_level_shifter;
        for r in 0..t.head.len() {
            let mut row = Row::new("missing_level_shifter", &[]);
            for &id in &t.shifter[span(&t.shifter_start, r)] {
                row.params.push(("shifter", model(id)));
            }
            file(&t.head, r, row);
        }
        let t = &erc.missing_tie;
        for r in 0..t.head.len() {
            let row = Row::new("missing_tie", &[t.region[r], t.tap[r]])
                .length("max_distance", t.max_distance[r]);
            file(&t.head, r, row);
        }
        let t = &erc.multiple_drivers;
        for r in 0..t.head.len() {
            let row = Row::new("multiple_drivers", &[])
                .value("max_drivers", ParamValue::Count(t.max_drivers[r]));
            file(&t.head, r, row);
        }
        let t = &erc.p2p_resistance;
        for r in 0..t.head.len() {
            let row =
                Row::new("p2p_resistance", &[]).number("max_resistance", t.max_resistance[r].raw());
            file(&t.head, r, row);
        }
        let t = &erc.reliability;
        for r in 0..t.head.len() {
            let row = Row::new("reliability", &[])
                .number("required_lifetime_hours", t.required_lifetime_hours[r])
                .number("reference_lifetime_hours", t.reference_lifetime_hours[r])
                .number("reference_stress", t.reference_stress[r].raw())
                .number("stress_exponent", t.stress_exponent[r])
                .number("reference_temperature", t.reference_temperature[r].raw())
                .number("activation_energy_ev", t.activation_energy_ev[r])
                .number("max_abs_voltage", t.max_abs_voltage[r].raw())
                .number("duty_cycle", t.duty_cycle[r]);
            file(&t.head, r, row);
        }
        let t = &erc.soft_connection;
        for r in 0..t.head.len() {
            let row = Row::new("soft_connection", &t.soft[span(&t.soft_start, r)]);
            file(&t.head, r, row);
        }
        let t = &erc.supply_short;
        for r in 0..t.head.len() {
            let mut layers = vec![t.tap_a[r], t.tap_b[r]];
            layers.extend(t.within[r]);
            file(&t.head, r, Row::new("supply_short", &layers));
        }
        for r in 0..erc.tie_high_low.head.len() {
            file(&erc.tie_high_low.head, r, Row::new("tie_high_low", &[]));
        }
        let t = &erc.unconnected_pin;
        for r in 0..t.head.len() {
            let row = Row::new("unconnected_pin", &t.layer[span(&t.layer_start, r)]);
            file(&t.head, r, row);
        }
        let t = &erc.voltage_spacing;
        for r in 0..t.head.len() {
            let mut layers = vec![t.layer[r]];
            layers.extend(t.other[r]);
            let mut row = Row::new("voltage_spacing", &layers);
            for at in span(&t.step_start, r) {
                row = row.number("voltage", t.voltage[at].raw());
            }
            for at in span(&t.step_start, r) {
                row = row.length("space", t.space[at]);
            }
            file(&t.head, r, row);
        }
        let t = &erc.dielectric_field;
        for r in 0..t.head.len() {
            let mut layers = vec![t.layer[r]];
            layers.extend(t.other[r]);
            let row = Row::new("dielectric_field", &layers).number("max_field", t.max_field[r]);
            file(&t.head, r, row);
        }
        let t = &erc.hv_tag;
        for r in 0..t.head.len() {
            let row =
                Row::new("hv_tag", &[t.layer[r], t.tag[r]]).number("voltage", t.voltage[r].raw());
            file(&t.head, r, row);
        }
        let t = &erc.mixed_tag;
        for r in 0..t.head.len() {
            file(&t.head, r, Row::new("mixed_tag", &[t.layer[r], t.tag[r]]));
        }
        let t = &erc.fanout;
        for r in 0..t.head.len() {
            let row = Row::new("fanout", &[]).value("max_gates", ParamValue::Count(t.max_gates[r]));
            file(&t.head, r, row);
        }
        let t = &erc.supply_path;
        for r in 0..t.head.len() {
            let row = Row::new("supply_path", &[]).value("both", ParamValue::Flag(t.both[r]));
            file(&t.head, r, row);
        }
        let t = &erc.power_switch;
        for r in 0..t.head.len() {
            let mut row = Row::new("power_switch", &[]);
            for &id in &t.model[span(&t.model_start, r)] {
                row.params.push(("model", model(id)));
            }
            file(&t.head, r, row);
        }
        let t = &erc.matching;
        for r in 0..t.head.len() {
            let row = Row::new("matching", &[t.group[r]]).length("tolerance", t.tolerance[r]);
            file(&t.head, r, row);
        }
        for r in 0..erc.floating_supply.head.len() {
            file(
                &erc.floating_supply.head,
                r,
                Row::new("floating_supply", &[]),
            );
        }
        for r in 0..erc.combinational_loop.head.len() {
            file(
                &erc.combinational_loop.head,
                r,
                Row::new("combinational_loop", &[]),
            );
        }
        let t = &erc.gate_path;
        for r in 0..t.head.len() {
            let row = Row::new("gate_path", &[])
                .value("ground", ParamValue::Flag(t.ground[r]))
                .value("max_devices", ParamValue::Count(t.max_devices[r]));
            file(&t.head, r, row);
        }
        for r in 0..erc.undriven_gate.head.len() {
            file(&erc.undriven_gate.head, r, Row::new("undriven_gate", &[]));
        }
        let t = &erc.missing_isolation;
        for r in 0..t.head.len() {
            let mut row = Row::new("missing_isolation", &[]);
            for &id in &t.isolation[span(&t.isolation_start, r)] {
                row.params.push(("isolation", model(id)));
            }
            file(&t.head, r, row);
        }
        let t = &erc.well_bias;
        for r in 0..t.head.len() {
            let mut row = Row::new("well_bias", &[]);
            for &id in &t.pmos[span(&t.pmos_start, r)] {
                row.params.push(("pmos", model(id)));
            }
            for &id in &t.nmos[span(&t.nmos_start, r)] {
                row.params.push(("nmos", model(id)));
            }
            file(&t.head, r, row);
        }
    }
}
