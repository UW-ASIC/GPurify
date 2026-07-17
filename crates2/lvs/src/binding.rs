//! Parameter evaluation and hierarchy-preserving binding from the SPICE/CDL AST.

use super::netlist::*;
use super::production::*;
use super::types::{DeviceFlavor, DeviceKind, TwoTerminalKind};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingErrorKind {
    Unsupported,
    Evaluation,
    Duplicate,
    Unresolved,
    HierarchyCycle,
    Arity,
    InvalidProperty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingError {
    pub kind: BindingErrorKind,
    pub span: SourceSpan,
    pub hierarchy_path: HierarchyPath,
    pub message: String,
}

impl BindingError {
    fn new(
        kind: BindingErrorKind,
        span: SourceSpan,
        hierarchy_path: HierarchyPath,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            span,
            hierarchy_path,
            message: message.into(),
        }
    }
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{} [{}]: {}",
            self.span.source, self.span.line, self.span.column, self.hierarchy_path, self.message
        )
    }
}

impl std::error::Error for BindingError {}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParameterEnvironment {
    pub values: BTreeMap<String, f64>,
}

impl ParameterEnvironment {
    pub fn get(&self, name: &str) -> Option<f64> {
        self.values.get(&name.to_ascii_lowercase()).copied()
    }
}

#[derive(Debug, Clone, PartialEq)]
enum ExprToken {
    Number(f64),
    Identifier(String),
    Plus,
    Minus,
    Star,
    Slash,
    Caret,
    LParen,
    RParen,
    End,
}

fn expression_text(raw: &str) -> Result<&str, String> {
    let text = raw.trim();
    if text.starts_with('{') && text.ends_with('}') && text.len() >= 2 {
        Ok(text[1..text.len() - 1].trim())
    } else if (text.starts_with('"') && text.ends_with('"'))
        || (text.starts_with('\'') && text.ends_with('\''))
    {
        Err("string-valued expressions are not numeric".into())
    } else {
        Ok(text)
    }
}

fn lex_expression(raw: &str) -> Result<Vec<ExprToken>, String> {
    let text = expression_text(raw)?;
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let simple = match bytes[index] {
            b'+' => Some(ExprToken::Plus),
            b'-' => Some(ExprToken::Minus),
            b'*' => Some(ExprToken::Star),
            b'/' => Some(ExprToken::Slash),
            b'^' => Some(ExprToken::Caret),
            b'(' => Some(ExprToken::LParen),
            b')' => Some(ExprToken::RParen),
            _ => None,
        };
        if let Some(token) = simple {
            tokens.push(token);
            index += 1;
            continue;
        }
        if bytes[index].is_ascii_digit() || bytes[index] == b'.' {
            let start = index;
            let mut saw_exponent = false;
            index += 1;
            while index < bytes.len() {
                let byte = bytes[index];
                if byte.is_ascii_digit() || byte == b'.' {
                    index += 1;
                } else if matches!(byte, b'e' | b'E') && !saw_exponent {
                    saw_exponent = true;
                    index += 1;
                    if index < bytes.len() && matches!(bytes[index], b'+' | b'-') {
                        index += 1;
                    }
                } else if byte.is_ascii_alphabetic() {
                    index += 1;
                    while index < bytes.len() && bytes[index].is_ascii_alphabetic() {
                        index += 1;
                    }
                    break;
                } else {
                    break;
                }
            }
            let literal = &text[start..index];
            let number = parse_engineering_number(literal)?
                .ok_or_else(|| format!("invalid numeric literal '{literal}'"))?;
            tokens.push(ExprToken::Number(number.value));
            continue;
        }
        if bytes[index].is_ascii_alphabetic() || matches!(bytes[index], b'_' | b'\\' | b'$') {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || matches!(
                        bytes[index],
                        b'_' | b'$' | b'.' | b'!' | b'[' | b']' | b'<' | b'>'
                    ))
            {
                index += 1;
            }
            tokens.push(ExprToken::Identifier(text[start..index].to_string()));
            continue;
        }
        return Err(format!(
            "unsupported character '{}' in numeric expression",
            bytes[index] as char
        ));
    }
    tokens.push(ExprToken::End);
    Ok(tokens)
}

struct ExpressionParser<'a, F> {
    tokens: &'a [ExprToken],
    index: usize,
    resolve: F,
}

impl<F> ExpressionParser<'_, F>
where
    F: FnMut(&str) -> Result<f64, String>,
{
    fn peek(&self) -> &ExprToken {
        &self.tokens[self.index]
    }

    fn take(&mut self) -> ExprToken {
        let token = self.tokens[self.index].clone();
        self.index += 1;
        token
    }

    fn parse(mut self) -> Result<f64, String> {
        let value = self.sum()?;
        if self.peek() != &ExprToken::End {
            return Err(format!(
                "unexpected token {:?} after expression",
                self.peek()
            ));
        }
        if !value.is_finite() {
            return Err("expression evaluated to a non-finite value".into());
        }
        Ok(value)
    }

    fn sum(&mut self) -> Result<f64, String> {
        let mut value = self.product()?;
        loop {
            match self.peek() {
                ExprToken::Plus => {
                    self.take();
                    value += self.product()?;
                }
                ExprToken::Minus => {
                    self.take();
                    value -= self.product()?;
                }
                _ => break,
            }
        }
        Ok(value)
    }

    fn product(&mut self) -> Result<f64, String> {
        let mut value = self.power()?;
        loop {
            match self.peek() {
                ExprToken::Star => {
                    self.take();
                    value *= self.power()?;
                }
                ExprToken::Slash => {
                    self.take();
                    let divisor = self.power()?;
                    if divisor == 0.0 {
                        return Err("division by zero".into());
                    }
                    value /= divisor;
                }
                _ => break,
            }
        }
        Ok(value)
    }

    fn power(&mut self) -> Result<f64, String> {
        let base = self.unary()?;
        if self.peek() == &ExprToken::Caret {
            self.take();
            let exponent = self.power()?;
            let value = base.powf(exponent);
            if !value.is_finite() {
                return Err("power operation produced a non-finite value".into());
            }
            Ok(value)
        } else {
            Ok(base)
        }
    }

    fn unary(&mut self) -> Result<f64, String> {
        match self.peek() {
            ExprToken::Plus => {
                self.take();
                self.unary()
            }
            ExprToken::Minus => {
                self.take();
                Ok(-self.unary()?)
            }
            _ => self.primary(),
        }
    }

    fn primary(&mut self) -> Result<f64, String> {
        match self.take() {
            ExprToken::Number(value) => Ok(value),
            ExprToken::Identifier(name) => {
                if self.peek() == &ExprToken::LParen {
                    return Err(format!(
                        "function call '{name}(...)' is outside the supported expression subset"
                    ));
                }
                (self.resolve)(&name)
            }
            ExprToken::LParen => {
                let value = self.sum()?;
                if self.take() != ExprToken::RParen {
                    return Err("missing ')' in expression".into());
                }
                Ok(value)
            }
            token => Err(format!(
                "expected number, parameter, or '(', found {token:?}"
            )),
        }
    }
}

fn evaluate_raw<F>(raw: &str, resolve: F) -> Result<f64, String>
where
    F: FnMut(&str) -> Result<f64, String>,
{
    let tokens = lex_expression(raw)?;
    ExpressionParser {
        tokens: &tokens,
        index: 0,
        resolve,
    }
    .parse()
}

/// Evaluate one expression against an already-resolved environment.
pub fn evaluate_parameter_expression(
    expression: &ParameterExpr,
    environment: &ParameterEnvironment,
    hierarchy_path: &HierarchyPath,
) -> Result<f64, BindingError> {
    evaluate_raw(&expression.raw, |name| {
        environment
            .get(name)
            .ok_or_else(|| format!("unresolved parameter '{name}'"))
    })
    .map_err(|message| {
        BindingError::new(
            BindingErrorKind::Evaluation,
            expression.span.clone(),
            hierarchy_path.clone(),
            message,
        )
    })
}

struct ScopeEvaluator<'a> {
    definitions: BTreeMap<String, &'a ParameterDecl>,
    parent: &'a ParameterEnvironment,
    values: BTreeMap<String, f64>,
    active: Vec<String>,
    hierarchy_path: &'a HierarchyPath,
}

impl ScopeEvaluator<'_> {
    fn resolve(&mut self, name: &str) -> Result<f64, BindingError> {
        let key = name.to_ascii_lowercase();
        if let Some(value) = self.values.get(&key) {
            return Ok(*value);
        }
        let Some(definition) = self.definitions.get(&key).copied() else {
            return self.parent.get(&key).ok_or_else(|| {
                BindingError::new(
                    BindingErrorKind::Unresolved,
                    SourceSpan {
                        source: "<parameter>".into(),
                        line: 1,
                        column: 1,
                        end_column: 1,
                    },
                    self.hierarchy_path.clone(),
                    format!("unresolved parameter '{name}'"),
                )
            });
        };
        if self.active.contains(&key) {
            let mut cycle = self.active.clone();
            cycle.push(key.clone());
            return Err(BindingError::new(
                BindingErrorKind::Evaluation,
                definition.span.clone(),
                self.hierarchy_path.clone(),
                format!("parameter cycle: {}", cycle.join(" -> ")),
            ));
        }
        self.active.push(key.clone());
        let value = evaluate_raw(&definition.value.raw, |identifier| {
            self.resolve(identifier).map_err(|error| error.to_string())
        })
        .map_err(|message| {
            BindingError::new(
                BindingErrorKind::Evaluation,
                definition.value.span.clone(),
                self.hierarchy_path.clone(),
                message,
            )
        })?;
        self.active.pop();
        if !value.is_finite() {
            return Err(BindingError::new(
                BindingErrorKind::Evaluation,
                definition.value.span.clone(),
                self.hierarchy_path.clone(),
                format!("parameter '{}' evaluated non-finite", definition.name),
            ));
        }
        self.values.insert(key, value);
        Ok(value)
    }
}

fn evaluate_scope(
    declarations: &[ParameterDecl],
    parent: &ParameterEnvironment,
    overrides: &BTreeMap<String, f64>,
    hierarchy_path: &HierarchyPath,
) -> Result<ParameterEnvironment, BindingError> {
    let mut definitions = BTreeMap::new();
    for declaration in declarations {
        let key = declaration.name.to_ascii_lowercase();
        if definitions.insert(key, declaration).is_some() {
            return Err(BindingError::new(
                BindingErrorKind::Duplicate,
                declaration.span.clone(),
                hierarchy_path.clone(),
                format!("duplicate parameter '{}'", declaration.name),
            ));
        }
    }
    for name in overrides.keys() {
        if !definitions.contains_key(&name.to_ascii_lowercase()) {
            return Err(BindingError::new(
                BindingErrorKind::Unresolved,
                declarations
                    .first()
                    .map(|declaration| declaration.span.clone())
                    .unwrap_or(SourceSpan {
                        source: "<override>".into(),
                        line: 1,
                        column: 1,
                        end_column: 1,
                    }),
                hierarchy_path.clone(),
                format!("override targets undeclared parameter '{name}'"),
            ));
        }
    }
    let mut evaluator = ScopeEvaluator {
        definitions,
        parent,
        values: overrides
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), *value))
            .collect(),
        active: Vec::new(),
        hierarchy_path,
    };
    let names: Vec<String> = evaluator.definitions.keys().cloned().collect();
    for name in names {
        evaluator.resolve(&name)?;
    }
    let mut values = parent.values.clone();
    values.extend(evaluator.values);
    Ok(ParameterEnvironment { values })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredModel {
    pub kind: DeviceKind,
    pub flavor: DeviceFlavor,
    pub device_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlackBoxSpec {
    pub name: String,
    pub ports: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReferenceBindingOptions {
    pub top: String,
    pub unsuffixed_length_nm: Option<f64>,
    pub configured_models: BTreeMap<String, ConfiguredModel>,
    pub model_aliases: BTreeMap<String, String>,
    pub black_boxes: BTreeMap<String, BlackBoxSpec>,
    pub equated_cells: BTreeMap<String, String>,
    pub property_tolerances: BTreeMap<String, NumericTolerance>,
}

impl ReferenceBindingOptions {
    pub fn new(top: impl Into<String>) -> Self {
        Self {
            top: top.into(),
            unsuffixed_length_nm: None,
            configured_models: BTreeMap::new(),
            model_aliases: BTreeMap::new(),
            black_boxes: BTreeMap::new(),
            equated_cells: BTreeMap::new(),
            property_tolerances: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BoundReferenceInstance {
    pub stable_id: String,
    pub target_cell: String,
    pub port_bindings: Vec<(String, String)>,
    pub parameters: ParameterEnvironment,
    pub hierarchy_path: HierarchyPath,
    pub black_box: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BoundReferenceCell {
    pub specialization: String,
    pub source_cell: String,
    pub ports: Vec<String>,
    pub parameters: ParameterEnvironment,
    pub netlist: DetailedRefNetlist,
    pub instances: Vec<BoundReferenceInstance>,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BoundReferenceHierarchy {
    pub top_cell: String,
    pub cells: BTreeMap<String, BoundReferenceCell>,
    pub globals: BTreeSet<String>,
    pub source_units: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Primitive {
    Mos(DeviceKind),
    Bjt(DeviceKind),
    Diode,
    Resistor,
    Capacitor,
}

#[derive(Debug, Clone)]
struct ResolvedModel {
    canonical_name: String,
    primitive: Primitive,
    flavor: DeviceFlavor,
    device_class: Option<String>,
    parameters: Vec<ParameterDecl>,
}

fn stable_hash(text: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn collect_units<'a>(ast: &'a NetlistAst, units: &mut Vec<&'a NetlistAst>) {
    units.push(ast);
    for child in &ast.included_units {
        collect_units(child, units);
    }
}

struct Binder<'a> {
    options: &'a ReferenceBindingOptions,
    subcircuits: BTreeMap<String, Subcircuit>,
    models: BTreeMap<String, ModelDecl>,
    globals: BTreeSet<String>,
    top_environment: ParameterEnvironment,
    source_units: BTreeSet<String>,
    cells: BTreeMap<String, BoundReferenceCell>,
    cache: BTreeMap<(String, String), String>,
    active_cells: Vec<String>,
}

impl Binder<'_> {
    fn resolve_model(
        &self,
        name: &str,
        span: &SourceSpan,
        path: &HierarchyPath,
    ) -> Result<ResolvedModel, BindingError> {
        let mut current = name.to_ascii_lowercase();
        let mut visited = Vec::new();
        let mut parameters = Vec::new();
        // ponytail: depth cap prevents runaway alias chains; 10 is plenty
        const MAX_ALIAS_DEPTH: usize = 10;
        loop {
            if visited.contains(&current) {
                visited.push(current.clone());
                return Err(BindingError::new(
                    BindingErrorKind::Unresolved,
                    span.clone(),
                    path.clone(),
                    format!("model alias cycle: {}", visited.join(" -> ")),
                ));
            }
            if visited.len() >= MAX_ALIAS_DEPTH {
                return Err(BindingError::new(
                    BindingErrorKind::Unresolved,
                    span.clone(),
                    path.clone(),
                    format!(
                        "model alias chain exceeds max depth ({MAX_ALIAS_DEPTH}): {}",
                        visited.join(" -> ")
                    ),
                ));
            }
            visited.push(current.clone());
            if let Some(configured) =
                self.options
                    .configured_models
                    .iter()
                    .find_map(|(model, binding)| {
                        model.eq_ignore_ascii_case(&current).then_some(binding)
                    })
            {
                let primitive = match configured.kind {
                    DeviceKind::Nmos | DeviceKind::Pmos => Primitive::Mos(configured.kind.clone()),
                    DeviceKind::Npn | DeviceKind::Pnp => Primitive::Bjt(configured.kind.clone()),
                };
                return Ok(ResolvedModel {
                    canonical_name: current,
                    primitive,
                    flavor: configured.flavor,
                    device_class: configured.device_class.clone(),
                    parameters,
                });
            }
            if let Some(alias) = self
                .options
                .model_aliases
                .iter()
                .find_map(|(alias, target)| alias.eq_ignore_ascii_case(&current).then_some(target))
            {
                current = alias.to_ascii_lowercase();
                continue;
            }
            let Some(model) = self.models.get(&current) else {
                return Err(BindingError::new(
                    BindingErrorKind::Unresolved,
                    span.clone(),
                    path.clone(),
                    format!("unresolved model '{name}'"),
                ));
            };
            let mut inherited_parameters = model.parameters.clone();
            inherited_parameters.extend(parameters);
            parameters = inherited_parameters;
            let primitive = match &model.primitive {
                ModelPrimitive::Nmos => Primitive::Mos(DeviceKind::Nmos),
                ModelPrimitive::Pmos => Primitive::Mos(DeviceKind::Pmos),
                ModelPrimitive::Npn => Primitive::Bjt(DeviceKind::Npn),
                ModelPrimitive::Pnp => Primitive::Bjt(DeviceKind::Pnp),
                ModelPrimitive::Diode => Primitive::Diode,
                ModelPrimitive::Resistor => Primitive::Resistor,
                ModelPrimitive::Capacitor => Primitive::Capacitor,
                ModelPrimitive::Alias(alias) => {
                    current = alias.to_ascii_lowercase();
                    continue;
                }
            };
            return Ok(ResolvedModel {
                canonical_name: model.name.to_ascii_lowercase(),
                primitive,
                flavor: DeviceFlavor::Standard,
                device_class: None,
                parameters,
            });
        }
    }

    fn tolerance(&self, property: &str) -> NumericTolerance {
        self.options
            .property_tolerances
            .iter()
            .find_map(|(name, tolerance)| name.eq_ignore_ascii_case(property).then_some(*tolerance))
            .unwrap_or(NumericTolerance::EXACT)
    }

    fn property(
        &self,
        name: &str,
        value: f64,
        unit: PropertyUnit,
    ) -> Result<TypedProperty, String> {
        if !value.is_finite() {
            return Err(format!("property '{name}' is non-finite"));
        }
        Ok(TypedProperty {
            value,
            unit,
            tolerance: self.tolerance(name),
            model_revision: None,
        })
    }

    fn ensure_net(netlist: &mut DetailedRefNetlist, name: &str, path: &HierarchyPath) {
        netlist.nets.entry(name.to_string()).or_insert(NetIdentity {
            id: name.to_string(),
            labels: BTreeSet::new(),
            ports: BTreeMap::new(),
            globals: BTreeSet::new(),
            hierarchy_path: path.clone(),
        });
    }

    fn evaluate_instance_parameters(
        &self,
        instance: &NetlistInstance,
        environment: &ParameterEnvironment,
        path: &HierarchyPath,
    ) -> Result<BTreeMap<String, f64>, BindingError> {
        let mut values = BTreeMap::new();
        for parameter in &instance.named_parameters {
            let value = evaluate_parameter_expression(&parameter.value, environment, path)?;
            values.insert(parameter.name.to_ascii_lowercase(), value);
        }
        Ok(values)
    }

    fn expression_property(
        &self,
        parameter: &ParameterDecl,
        environment: &ParameterEnvironment,
        path: &HierarchyPath,
        unit: PropertyUnit,
    ) -> Result<TypedProperty, BindingError> {
        let mut value = evaluate_parameter_expression(&parameter.value, environment, path)?;
        if matches!(
            unit,
            PropertyUnit::Nanometer | PropertyUnit::SquareNanometer
        ) {
            let power = if unit == PropertyUnit::SquareNanometer {
                2
            } else {
                1
            };
            value = if parameter
                .value
                .numeric
                .is_some_and(|number| number.suffix.is_none())
            {
                let Some(scale) = self.options.unsuffixed_length_nm else {
                    return Err(BindingError::new(
                        BindingErrorKind::InvalidProperty,
                        parameter.value.span.clone(),
                        path.clone(),
                        format!(
                            "unsuffixed length '{}' has no configured nanometer scale",
                            parameter.name
                        ),
                    ));
                };
                if !scale.is_finite() || scale <= 0.0 {
                    return Err(BindingError::new(
                        BindingErrorKind::InvalidProperty,
                        parameter.value.span.clone(),
                        path.clone(),
                        "unsuffixed_length_nm must be finite and positive",
                    ));
                }
                value * scale.powi(power)
            } else {
                value * 1.0e9_f64.powi(power)
            };
        }
        self.property(&parameter.name.to_ascii_uppercase(), value, unit)
            .map_err(|message| {
                BindingError::new(
                    BindingErrorKind::InvalidProperty,
                    parameter.value.span.clone(),
                    path.clone(),
                    message,
                )
            })
    }

    fn append_model_properties(
        &self,
        model: &ResolvedModel,
        environment: &ParameterEnvironment,
        path: &HierarchyPath,
        properties: &mut BTreeMap<String, TypedProperty>,
    ) -> Result<(), BindingError> {
        for parameter in &model.parameters {
            let value = evaluate_parameter_expression(&parameter.value, environment, path)?;
            let name = format!("MODEL.{}", parameter.name.to_ascii_uppercase());
            properties.insert(
                name.clone(),
                self.property(&name, value, PropertyUnit::Dimensionless)
                    .map_err(|message| {
                        BindingError::new(
                            BindingErrorKind::InvalidProperty,
                            parameter.value.span.clone(),
                            path.clone(),
                            message,
                        )
                    })?,
            );
        }
        Ok(())
    }

    fn bind_cell(
        &mut self,
        source_name: &str,
        environment: ParameterEnvironment,
        path: HierarchyPath,
    ) -> Result<String, BindingError> {
        let canonical_source = source_name.to_ascii_lowercase();
        if self.active_cells.contains(&canonical_source) {
            let mut cycle = self.active_cells.clone();
            cycle.push(canonical_source.clone());
            let span = self
                .subcircuits
                .get(&canonical_source)
                .map(|cell| cell.span.clone())
                .unwrap_or(SourceSpan {
                    source: "<hierarchy>".into(),
                    line: 1,
                    column: 1,
                    end_column: 1,
                });
            return Err(BindingError::new(
                BindingErrorKind::HierarchyCycle,
                span,
                path,
                format!("subcircuit recursion: {}", cycle.join(" -> ")),
            ));
        }
        let environment_signature = environment
            .values
            .iter()
            .map(|(name, value)| format!("{name}={:016x}", value.to_bits()))
            .collect::<Vec<_>>()
            .join(";");
        if let Some(specialization) = self
            .cache
            .get(&(canonical_source.clone(), environment_signature.clone()))
        {
            return Ok(specialization.clone());
        }
        let Some(cell) = self.subcircuits.get(&canonical_source).cloned() else {
            return Err(BindingError::new(
                BindingErrorKind::Unresolved,
                SourceSpan {
                    source: "<hierarchy>".into(),
                    line: 1,
                    column: 1,
                    end_column: 1,
                },
                path,
                format!("unresolved subcircuit '{source_name}'"),
            ));
        };
        let specialization = format!("{}${}", cell.name, stable_hash(&environment_signature));
        self.cache.insert(
            (canonical_source.clone(), environment_signature),
            specialization.clone(),
        );
        self.active_cells.push(canonical_source.clone());

        let mut netlist = DetailedRefNetlist::empty(&specialization);
        for port in &cell.ports {
            Self::ensure_net(&mut netlist, port, &path);
            netlist
                .nets
                .get_mut(port)
                .unwrap()
                .ports
                .insert(port.clone(), PortDirection::Unknown);
        }
        for global in &self.globals {
            Self::ensure_net(&mut netlist, global, &path);
            netlist
                .nets
                .get_mut(global)
                .unwrap()
                .globals
                .insert(global.clone());
        }
        let mut bound_instances = Vec::new();

        for instance in &cell.instances {
            let instance_path = path.child(&instance.name);
            for net in &instance.nets {
                Self::ensure_net(&mut netlist, net, &instance_path);
            }
            match instance.kind {
                InstanceKind::Subcircuit => {
                    let raw_target = instance.target.as_deref().expect("X target parsed");
                    let target = self
                        .options
                        .equated_cells
                        .iter()
                        .find_map(|(from, to)| {
                            from.eq_ignore_ascii_case(raw_target).then_some(to.as_str())
                        })
                        .unwrap_or(raw_target)
                        .to_string();
                    let overrides =
                        self.evaluate_instance_parameters(instance, &environment, &instance_path)?;
                    if let Some(black_box) =
                        self.options
                            .black_boxes
                            .iter()
                            .find_map(|(name, black_box)| {
                                name.eq_ignore_ascii_case(&target).then_some(black_box)
                            })
                    {
                        if black_box.ports.len() != instance.nets.len() {
                            return Err(BindingError::new(
                                BindingErrorKind::Arity,
                                instance.span.clone(),
                                instance_path,
                                format!(
                                    "black box '{}' expects {} ports, instance has {} nets",
                                    black_box.name,
                                    black_box.ports.len(),
                                    instance.nets.len()
                                ),
                            ));
                        }
                        bound_instances.push(BoundReferenceInstance {
                            stable_id: instance.name.clone(),
                            target_cell: black_box.name.clone(),
                            port_bindings: black_box
                                .ports
                                .iter()
                                .cloned()
                                .zip(instance.nets.iter().cloned())
                                .collect(),
                            parameters: ParameterEnvironment { values: overrides },
                            hierarchy_path: instance_path,
                            black_box: true,
                        });
                        continue;
                    }
                    let Some(target_cell) = self.subcircuits.get(&target.to_ascii_lowercase())
                    else {
                        return Err(BindingError::new(
                            BindingErrorKind::Unresolved,
                            instance.span.clone(),
                            instance_path,
                            format!("unresolved subcircuit '{target}'"),
                        ));
                    };
                    if target_cell.ports.len() != instance.nets.len() {
                        return Err(BindingError::new(
                            BindingErrorKind::Arity,
                            instance.span.clone(),
                            instance_path,
                            format!(
                                "subcircuit '{}' expects {} ports, instance has {} nets",
                                target_cell.name,
                                target_cell.ports.len(),
                                instance.nets.len()
                            ),
                        ));
                    }
                    let target_ports = target_cell.ports.clone();
                    let target_parameters = target_cell.parameters.clone();
                    let target_environment = evaluate_scope(
                        &target_parameters,
                        &self.top_environment,
                        &overrides,
                        &instance_path,
                    )?;
                    let target_specialization =
                        self.bind_cell(&target, target_environment.clone(), instance_path.clone())?;
                    bound_instances.push(BoundReferenceInstance {
                        stable_id: instance.name.clone(),
                        target_cell: target_specialization,
                        port_bindings: target_ports
                            .into_iter()
                            .zip(instance.nets.iter().cloned())
                            .collect(),
                        parameters: target_environment,
                        hierarchy_path: instance_path,
                        black_box: false,
                    });
                }
                InstanceKind::Mos => {
                    let model = self.resolve_model(
                        instance.model.as_deref().expect("MOS model"),
                        &instance.span,
                        &instance_path,
                    )?;
                    let Primitive::Mos(kind) = &model.primitive else {
                        return Err(BindingError::new(
                            BindingErrorKind::InvalidProperty,
                            instance.span.clone(),
                            instance_path,
                            format!("model '{}' is not a MOS model", model.canonical_name),
                        ));
                    };
                    let parameters: BTreeMap<String, &ParameterDecl> = instance
                        .named_parameters
                        .iter()
                        .map(|parameter| (parameter.name.to_ascii_lowercase(), parameter))
                        .collect();
                    let mut properties = BTreeMap::new();
                    for required in ["w", "l"] {
                        let Some(parameter) = parameters.get(required) else {
                            return Err(BindingError::new(
                                BindingErrorKind::InvalidProperty,
                                instance.span.clone(),
                                instance_path,
                                format!("MOS instance requires {required}"),
                            ));
                        };
                        properties.insert(
                            required.to_ascii_uppercase(),
                            self.expression_property(
                                parameter,
                                &environment,
                                &instance_path,
                                PropertyUnit::Nanometer,
                            )?,
                        );
                    }
                    for count in ["nf", "m"] {
                        let property = if let Some(parameter) = parameters.get(count) {
                            self.expression_property(
                                parameter,
                                &environment,
                                &instance_path,
                                PropertyUnit::Count,
                            )?
                        } else {
                            self.property(&count.to_ascii_uppercase(), 1.0, PropertyUnit::Count)
                                .map_err(|message| {
                                    BindingError::new(
                                        BindingErrorKind::InvalidProperty,
                                        instance.span.clone(),
                                        instance_path.clone(),
                                        message,
                                    )
                                })?
                        };
                        if property.value <= 0.0 || (count == "nf" && property.value.fract() != 0.0)
                        {
                            return Err(BindingError::new(
                                BindingErrorKind::InvalidProperty,
                                instance.span.clone(),
                                instance_path,
                                format!(
                                    "{count} must be positive{}",
                                    if count == "nf" { " integer" } else { "" }
                                ),
                            ));
                        }
                        properties.insert(count.to_ascii_uppercase(), property);
                    }
                    for area in ["ad", "as", "pd", "ps"] {
                        if let Some(parameter) = parameters.get(area) {
                            let unit = if area.starts_with('a') {
                                PropertyUnit::SquareNanometer
                            } else {
                                PropertyUnit::Nanometer
                            };
                            properties.insert(
                                area.to_ascii_uppercase(),
                                self.expression_property(
                                    parameter,
                                    &environment,
                                    &instance_path,
                                    unit,
                                )?,
                            );
                        }
                    }
                    for (name, parameter) in &parameters {
                        if matches!(
                            name.as_str(),
                            "w" | "l" | "nf" | "m" | "ad" | "as" | "pd" | "ps"
                        ) {
                            continue;
                        }
                        properties.insert(
                            name.to_ascii_uppercase(),
                            self.expression_property(
                                parameter,
                                &environment,
                                &instance_path,
                                PropertyUnit::Dimensionless,
                            )?,
                        );
                    }
                    self.append_model_properties(
                        &model,
                        &environment,
                        &instance_path,
                        &mut properties,
                    )?;
                    netlist.mos_devices.push(MosDeviceRecord {
                        identity: DeviceIdentity {
                            stable_id: instance.name.clone(),
                            hierarchy_path: instance_path,
                            model: Some(model.canonical_name),
                            device_class: model.device_class,
                            flavor: model.flavor,
                        },
                        kind: kind.clone(),
                        drain: instance.nets[0].clone(),
                        gate: instance.nets[1].clone(),
                        source: instance.nets[2].clone(),
                        body: TerminalConnection::Connected(instance.nets[3].clone()),
                        well: None,
                        substrate: None,
                        properties,
                    });
                }
                InstanceKind::Resistor | InstanceKind::Capacitor | InstanceKind::Diode => {
                    let (kind, value_name, unit, expected_model) = match instance.kind {
                        InstanceKind::Resistor => (
                            TwoTerminalKind::Resistor,
                            "R",
                            PropertyUnit::Ohm,
                            Some(Primitive::Resistor),
                        ),
                        InstanceKind::Capacitor => (
                            TwoTerminalKind::Capacitor,
                            "C",
                            PropertyUnit::Farad,
                            Some(Primitive::Capacitor),
                        ),
                        InstanceKind::Diode => (
                            TwoTerminalKind::Diode,
                            "AREA",
                            PropertyUnit::Dimensionless,
                            Some(Primitive::Diode),
                        ),
                        _ => unreachable!(),
                    };
                    let model = if let Some(model_name) = instance.model.as_deref() {
                        let model =
                            self.resolve_model(model_name, &instance.span, &instance_path)?;
                        if Some(model.primitive.clone()) != expected_model {
                            return Err(BindingError::new(
                                BindingErrorKind::InvalidProperty,
                                instance.span.clone(),
                                instance_path,
                                format!("model '{}' has the wrong primitive", model.canonical_name),
                            ));
                        }
                        Some(model)
                    } else {
                        None
                    };
                    let mut properties = BTreeMap::new();
                    if let Some(value) = instance.positional_parameters.first() {
                        let numeric =
                            evaluate_parameter_expression(value, &environment, &instance_path)?;
                        properties.insert(
                            value_name.into(),
                            self.property(value_name, numeric, unit)
                                .map_err(|message| {
                                    BindingError::new(
                                        BindingErrorKind::InvalidProperty,
                                        value.span.clone(),
                                        instance_path.clone(),
                                        message,
                                    )
                                })?,
                        );
                    }
                    for (index, value) in instance.positional_parameters.iter().enumerate().skip(1)
                    {
                        let numeric =
                            evaluate_parameter_expression(value, &environment, &instance_path)?;
                        let name = format!("P{index}");
                        properties.insert(
                            name.clone(),
                            self.property(&name, numeric, PropertyUnit::Dimensionless)
                                .map_err(|message| {
                                    BindingError::new(
                                        BindingErrorKind::InvalidProperty,
                                        value.span.clone(),
                                        instance_path.clone(),
                                        message,
                                    )
                                })?,
                        );
                    }
                    for parameter in &instance.named_parameters {
                        let numeric = evaluate_parameter_expression(
                            &parameter.value,
                            &environment,
                            &instance_path,
                        )?;
                        properties.insert(
                            parameter.name.to_ascii_uppercase(),
                            self.property(
                                &parameter.name.to_ascii_uppercase(),
                                numeric,
                                PropertyUnit::Dimensionless,
                            )
                            .map_err(|message| {
                                BindingError::new(
                                    BindingErrorKind::InvalidProperty,
                                    parameter.value.span.clone(),
                                    instance_path.clone(),
                                    message,
                                )
                            })?,
                        );
                    }
                    if let Some(model) = &model {
                        self.append_model_properties(
                            model,
                            &environment,
                            &instance_path,
                            &mut properties,
                        )?;
                    }
                    netlist.two_terminal_devices.push(TwoTerminalRecord {
                        identity: DeviceIdentity {
                            stable_id: instance.name.clone(),
                            hierarchy_path: instance_path,
                            model: model.as_ref().map(|model| model.canonical_name.clone()),
                            device_class: model
                                .as_ref()
                                .and_then(|model| model.device_class.clone()),
                            flavor: DeviceFlavor::Standard,
                        },
                        kind,
                        terminal_a: instance.nets[0].clone(),
                        terminal_b: instance.nets[1].clone(),
                        properties,
                    });
                }
                InstanceKind::Bjt => {
                    let model = self.resolve_model(
                        instance.model.as_deref().expect("BJT model"),
                        &instance.span,
                        &instance_path,
                    )?;
                    let Primitive::Bjt(kind) = &model.primitive else {
                        return Err(BindingError::new(
                            BindingErrorKind::InvalidProperty,
                            instance.span.clone(),
                            instance_path,
                            format!("model '{}' is not a BJT model", model.canonical_name),
                        ));
                    };
                    let mut properties = BTreeMap::new();
                    for parameter in &instance.named_parameters {
                        properties.insert(
                            parameter.name.to_ascii_uppercase(),
                            self.expression_property(
                                parameter,
                                &environment,
                                &instance_path,
                                PropertyUnit::Dimensionless,
                            )?,
                        );
                    }
                    self.append_model_properties(
                        &model,
                        &environment,
                        &instance_path,
                        &mut properties,
                    )?;
                    netlist.bjt_devices.push(BjtDeviceRecord {
                        identity: DeviceIdentity {
                            stable_id: instance.name.clone(),
                            hierarchy_path: instance_path,
                            model: Some(model.canonical_name),
                            device_class: model.device_class,
                            flavor: model.flavor,
                        },
                        kind: kind.clone(),
                        collector: instance.nets[0].clone(),
                        base: instance.nets[1].clone(),
                        emitter: instance.nets[2].clone(),
                        substrate: None,
                        properties,
                    });
                }
            }
        }

        let signature_text = format!(
            "{}|{:?}|{:?}|{:?}",
            specialization, netlist.mos_devices, netlist.two_terminal_devices, bound_instances
        );
        let signature = stable_hash(&signature_text);
        self.cells.insert(
            specialization.clone(),
            BoundReferenceCell {
                specialization: specialization.clone(),
                source_cell: cell.name,
                ports: cell.ports,
                parameters: environment,
                netlist,
                instances: bound_instances,
                signature,
            },
        );
        self.active_cells.pop();
        Ok(specialization)
    }
}

/// Bind a resolved parser AST into a specialization-preserving reference
/// hierarchy. X instances remain explicit; no flattening occurs here.
pub fn bind_reference_hierarchy(
    ast: &NetlistAst,
    options: &ReferenceBindingOptions,
) -> Result<BoundReferenceHierarchy, BindingError> {
    let mut units = Vec::new();
    collect_units(ast, &mut units);
    let root_path = HierarchyPath::root(&options.top);
    let mut subcircuits = BTreeMap::new();
    let mut models = BTreeMap::new();
    let mut globals = BTreeSet::new();
    let mut source_units = BTreeSet::new();
    let mut top_parameters = Vec::new();
    for unit in units {
        source_units.insert(unit.source.clone());
        for include in &unit.includes {
            if include.resolved_source.is_none() {
                return Err(BindingError::new(
                    BindingErrorKind::Unresolved,
                    include.span.clone(),
                    root_path,
                    format!("include '{}' was not resolved", include.requested),
                ));
            }
        }
        if !unit.top_level_instances.is_empty() {
            return Err(BindingError::new(
                BindingErrorKind::Unsupported,
                unit.top_level_instances[0].span.clone(),
                root_path,
                "top-level instances outside the selected .subckt are unsupported",
            ));
        }
        top_parameters.extend(unit.parameters.iter().cloned());
        globals.extend(unit.globals.iter().cloned());
        for subcircuit in &unit.subcircuits {
            let key = subcircuit.name.to_ascii_lowercase();
            if subcircuits.insert(key, subcircuit.clone()).is_some() {
                return Err(BindingError::new(
                    BindingErrorKind::Duplicate,
                    subcircuit.span.clone(),
                    root_path,
                    format!("duplicate subcircuit '{}'", subcircuit.name),
                ));
            }
        }
        for model in &unit.models {
            let key = model.name.to_ascii_lowercase();
            if models.insert(key, model.clone()).is_some() {
                return Err(BindingError::new(
                    BindingErrorKind::Duplicate,
                    model.span.clone(),
                    root_path,
                    format!("duplicate model '{}'", model.name),
                ));
            }
        }
    }
    let empty = ParameterEnvironment::default();
    let top_environment = evaluate_scope(&top_parameters, &empty, &BTreeMap::new(), &root_path)?;
    let top_key = options.top.to_ascii_lowercase();
    let Some(top_subcircuit) = subcircuits.get(&top_key) else {
        return Err(BindingError::new(
            BindingErrorKind::Unresolved,
            SourceSpan {
                source: ast.source.clone(),
                line: 1,
                column: 1,
                end_column: 1,
            },
            root_path,
            format!("selected top '{}' was not found", options.top),
        ));
    };
    let top_parameters = top_subcircuit.parameters.clone();
    let top_cell_environment = evaluate_scope(
        &top_parameters,
        &top_environment,
        &BTreeMap::new(),
        &root_path,
    )?;
    let mut binder = Binder {
        options,
        subcircuits,
        models,
        globals: globals.clone(),
        top_environment,
        source_units: source_units.clone(),
        cells: BTreeMap::new(),
        cache: BTreeMap::new(),
        active_cells: Vec::new(),
    };
    let top_cell = binder.bind_cell(&options.top, top_cell_environment, root_path)?;
    Ok(BoundReferenceHierarchy {
        top_cell,
        cells: binder.cells,
        globals,
        source_units: binder.source_units,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> NetlistAst {
        parse_netlist("binding.sp", source).unwrap()
    }

    #[test]
    fn expression_evaluator_handles_precedence_suffixes_and_power() {
        let expression = ParameterExpr {
            raw: "{base + 2u * (3 + 1)^2}".into(),
            numeric: None,
            span: SourceSpan {
                source: "expr.sp".into(),
                line: 7,
                column: 5,
                end_column: 30,
            },
        };
        let environment = ParameterEnvironment {
            values: BTreeMap::from([("base".into(), 1.0e-6)]),
        };
        let value =
            evaluate_parameter_expression(&expression, &environment, &HierarchyPath::root("top"))
                .unwrap();
        assert!((value - 33.0e-6).abs() < 1.0e-18);

        for raw in ["{missing + 1}", "{1 / 0}", "{sqrt(4)}"] {
            let expression = ParameterExpr {
                raw: raw.into(),
                numeric: None,
                span: expression.span.clone(),
            };
            let error = evaluate_parameter_expression(
                &expression,
                &environment,
                &HierarchyPath::root("top"),
            )
            .unwrap_err();
            assert_eq!(error.span.line, 7);
        }
    }

    #[test]
    fn model_alias_and_parameterized_hierarchy_bind_without_flattening() {
        let ast = parse(
            r#"
                .param scale=2
                .global VSS
                .model nch nmos level=1
                .model fast nch vth=0.4
                .subckt leaf d g s b params: width=1u fingers=1
                M0 d g s b fast w={width*scale} l=100n nf=fingers m=2 ad=1p ps=2u
                .ends leaf
                .subckt top d0 g0 s0 b0 d1 g1 s1 b1
                X0 d0 g0 s0 b0 leaf width=500n fingers=2
                X1 d1 g1 s1 b1 leaf width=1u fingers=4
                .ends top
            "#,
        );
        assert_eq!(ast.models.len(), 2);
        assert!(matches!(ast.models[1].primitive, ModelPrimitive::Alias(_)));
        let hierarchy =
            bind_reference_hierarchy(&ast, &ReferenceBindingOptions::new("top")).unwrap();
        assert_eq!(
            hierarchy.cells.len(),
            3,
            "top plus two parameter specializations"
        );
        let top = &hierarchy.cells[&hierarchy.top_cell];
        assert_eq!(top.instances.len(), 2);
        assert_ne!(top.instances[0].target_cell, top.instances[1].target_cell);
        assert_eq!(top.instances[0].port_bindings[0], ("d".into(), "d0".into()));
        assert!(
            top.netlist.mos_devices.is_empty(),
            "X instances stay hierarchical"
        );

        let first_leaf = &hierarchy.cells[&top.instances[0].target_cell];
        let mos = &first_leaf.netlist.mos_devices[0];
        assert_eq!(mos.kind, DeviceKind::Nmos);
        assert_eq!(mos.body.connected().map(String::as_str), Some("b"));
        assert!((mos.properties["W"].value - 1000.0).abs() < 1.0e-9);
        assert!((mos.properties["L"].value - 100.0).abs() < 1.0e-9);
        assert_eq!(mos.properties["NF"].value, 2.0);
        assert_eq!(mos.properties["M"].value, 2.0);
        assert!((mos.properties["AD"].value - 1.0e6).abs() < 1.0e-6);
        assert!((mos.properties["PS"].value - 2000.0).abs() < 1.0e-9);
        assert_eq!(mos.properties["MODEL.LEVEL"].value, 1.0);
        assert_eq!(mos.properties["MODEL.VTH"].value, 0.4);
        assert!(first_leaf.netlist.nets["VSS"].globals.contains("VSS"));
    }

    #[test]
    fn parameter_cycles_unknown_overrides_and_unsuffixed_lengths_fail_closed() {
        let cycle = parse(".param a={b+1} b={a+1}\n.subckt top x\n.ends top\n");
        let error =
            bind_reference_hierarchy(&cycle, &ReferenceBindingOptions::new("top")).unwrap_err();
        assert_eq!(error.kind, BindingErrorKind::Evaluation);
        assert!(error.message.contains("parameter cycle"));

        let unknown_override = parse(
            ".subckt leaf x params: p=1\n.ends leaf\n.subckt top x\nX0 x leaf q=2\n.ends top\n",
        );
        let error =
            bind_reference_hierarchy(&unknown_override, &ReferenceBindingOptions::new("top"))
                .unwrap_err();
        assert_eq!(error.kind, BindingErrorKind::Unresolved);
        assert!(error.message.contains("undeclared parameter 'q'"));

        let unsuffixed =
            parse(".model nch nmos\n.subckt top d g s b\nM0 d g s b nch w=1000 l=100\n.ends top\n");
        let error = bind_reference_hierarchy(&unsuffixed, &ReferenceBindingOptions::new("top"))
            .unwrap_err();
        assert_eq!(error.kind, BindingErrorKind::InvalidProperty);
        assert!(error.message.contains("unsuffixed length"));
    }

    #[test]
    fn wrong_model_primitive_and_hierarchy_arity_have_located_errors() {
        let wrong_model = parse(
            ".model diode_model diode\n.subckt top d g s b\nM0 d g s b diode_model w=1u l=100n\n.ends top\n",
        );
        let error = bind_reference_hierarchy(&wrong_model, &ReferenceBindingOptions::new("top"))
            .unwrap_err();
        assert_eq!(error.kind, BindingErrorKind::InvalidProperty);
        assert!(error.message.contains("not a MOS"));

        let arity =
            parse(".subckt leaf a b\nR0 a b 1k\n.ends leaf\n.subckt top a\nX0 a leaf\n.ends top\n");
        let error =
            bind_reference_hierarchy(&arity, &ReferenceBindingOptions::new("top")).unwrap_err();
        assert_eq!(error.kind, BindingErrorKind::Arity);
        assert!(error.span.line > 0);
        assert!(error.hierarchy_path.to_string().contains("X0"));
    }

    #[test]
    fn recursion_and_unresolved_includes_are_errors() {
        let recursive = parse(".subckt top a\nX0 a top\n.ends top\n");
        let error =
            bind_reference_hierarchy(&recursive, &ReferenceBindingOptions::new("top")).unwrap_err();
        assert_eq!(error.kind, BindingErrorKind::HierarchyCycle);
        assert!(error.message.contains("top -> top"));

        let unresolved_include = parse_netlist(
            "root.sp",
            ".include \"missing.sp\"\n.subckt top a\n.ends top\n",
        )
        .unwrap();
        let error =
            bind_reference_hierarchy(&unresolved_include, &ReferenceBindingOptions::new("top"))
                .unwrap_err();
        assert_eq!(error.kind, BindingErrorKind::Unresolved);
        assert!(error.message.contains("was not resolved"));
    }

    #[test]
    fn black_boxes_and_equated_cells_keep_explicit_port_maps() {
        let ast = parse(
            ".subckt leaf a b\nR0 a b 1k\n.ends leaf\n.subckt top x y\nX0 x y alias\nX1 x y macro gain=2\n.ends top\n",
        );
        let mut options = ReferenceBindingOptions::new("top");
        options.equated_cells.insert("alias".into(), "leaf".into());
        options.black_boxes.insert(
            "macro".into(),
            BlackBoxSpec {
                name: "macro".into(),
                ports: vec!["in".into(), "out".into()],
            },
        );
        let hierarchy = bind_reference_hierarchy(&ast, &options).unwrap();
        let top = &hierarchy.cells[&hierarchy.top_cell];
        assert_eq!(top.instances.len(), 2);
        assert!(!top.instances[0].black_box);
        assert!(top.instances[1].black_box);
        assert_eq!(
            top.instances[1].port_bindings,
            [("in".into(), "x".into()), ("out".into(), "y".into())]
        );
        assert_eq!(top.instances[1].parameters.get("gain"), Some(2.0));
    }
}
