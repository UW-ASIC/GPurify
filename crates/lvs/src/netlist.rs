//! Fail-closed SPICE/CDL reference-netlist parser.
//!
//! This module intentionally implements a declared subset instead of guessing at
//! dialect-specific syntax.  Parsing preserves hierarchy and properties in an AST;
//! conversion to the older flat [`RefNetlist`] is a separate, explicitly lossy-
//! forbidden operation.

use super::{DeviceFlavor, DeviceKind, RefBjt, RefDevice, RefNetlist, RefTwoTerminal};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Physical source range for a token or declaration.  Lines and columns are
/// one-based and always refer to the original physical line, including `+`
/// continuation lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSpan {
    pub source: String,
    pub line: usize,
    pub column: usize,
    pub end_column: usize,
}

impl SourceSpan {
    pub(crate) fn synthetic(source: &str) -> Self {
        Self {
            source: source.to_string(),
            line: 1,
            column: 1,
            end_column: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetlistErrorKind {
    Lexical,
    Syntax,
    DuplicateDefinition,
    NonFiniteNumber,
    IncludeResolution,
    IncludeCycle,
    UnresolvedReference,
}

/// Parser/include diagnostic with stable source coordinates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetlistError {
    pub kind: NetlistErrorKind,
    pub span: SourceSpan,
    pub message: String,
}

impl NetlistError {
    pub(crate) fn new(
        kind: NetlistErrorKind,
        span: SourceSpan,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            span,
            message: message.into(),
        }
    }
}

impl fmt::Display for NetlistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}: {}",
            self.span.source, self.span.line, self.span.column, self.message
        )
    }
}

impl std::error::Error for NetlistError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineeringSuffix {
    Tera,
    Giga,
    Mega,
    Kilo,
    Milli,
    Micro,
    Nano,
    Pico,
    Femto,
    Mil,
}

impl EngineeringSuffix {
    fn multiplier(self) -> f64 {
        match self {
            Self::Tera => 1.0e12,
            Self::Giga => 1.0e9,
            Self::Mega => 1.0e6,
            Self::Kilo => 1.0e3,
            Self::Milli => 1.0e-3,
            Self::Micro => 1.0e-6,
            Self::Nano => 1.0e-9,
            Self::Pico => 1.0e-12,
            Self::Femto => 1.0e-15,
            Self::Mil => 25.4e-6,
        }
    }
}

/// A numeric literal after applying its SPICE engineering suffix.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EngineeringNumber {
    pub value: f64,
    pub suffix: Option<EngineeringSuffix>,
}

/// Parse one standalone engineering-number literal.  `Ok(None)` means the text
/// is an identifier/expression rather than a number.  Numeric-looking text with
/// an unsupported suffix is an error, never an identifier fallback.
pub fn parse_engineering_number(raw: &str) -> Result<Option<EngineeringNumber>, String> {
    let text = raw.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let lower = text.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "nan" | "+nan" | "-nan" | "inf" | "+inf" | "-inf" | "infinity" | "+infinity" | "-infinity"
    ) {
        return Err(format!("non-finite numeric literal '{text}'"));
    }

    let bytes = text.as_bytes();
    let mut i = 0usize;
    if matches!(bytes.first(), Some(b'+') | Some(b'-')) {
        i += 1;
    }
    let mut digits = 0usize;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        digits += 1;
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            digits += 1;
            i += 1;
        }
    }
    if digits == 0 {
        return Ok(None);
    }
    if i < bytes.len() && matches!(bytes[i], b'e' | b'E') {
        i += 1;
        if i < bytes.len() && matches!(bytes[i], b'+' | b'-') {
            i += 1;
        }
        let exponent_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == exponent_start {
            return Err(format!("malformed exponent in numeric literal '{text}'"));
        }
    }

    let base_text = &text[..i];
    let suffix_text = &text[i..];
    if !suffix_text.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(format!("malformed numeric literal '{text}'"));
    }
    let suffix = match suffix_text.to_ascii_uppercase().as_str() {
        "" => None,
        "T" => Some(EngineeringSuffix::Tera),
        "G" => Some(EngineeringSuffix::Giga),
        "MEG" => Some(EngineeringSuffix::Mega),
        "K" => Some(EngineeringSuffix::Kilo),
        // SPICE is case-insensitive: M is milli.  Mega is only MEG.
        "M" => Some(EngineeringSuffix::Milli),
        "U" => Some(EngineeringSuffix::Micro),
        "N" => Some(EngineeringSuffix::Nano),
        "P" => Some(EngineeringSuffix::Pico),
        "F" => Some(EngineeringSuffix::Femto),
        "MIL" => Some(EngineeringSuffix::Mil),
        other => {
            return Err(format!(
                "unsupported engineering suffix '{other}' in '{text}'"
            ))
        }
    };
    let base: f64 = base_text
        .parse()
        .map_err(|_| format!("malformed numeric literal '{text}'"))?;
    let value = base * suffix.map_or(1.0, EngineeringSuffix::multiplier);
    if !value.is_finite() {
        return Err(format!("non-finite numeric literal '{text}'"));
    }
    Ok(Some(EngineeringNumber { value, suffix }))
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParameterExpr {
    /// Original token text, including braces or quotes when present.
    pub raw: String,
    /// Typed value for a standalone numeric literal; expressions remain `None`.
    pub numeric: Option<EngineeringNumber>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParameterDecl {
    pub name: String,
    pub value: ParameterExpr,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelPrimitive {
    Nmos,
    Pmos,
    Npn,
    Pnp,
    Diode,
    Resistor,
    Capacitor,
    /// Deterministic alias to another declared/configured model.
    Alias(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelDecl {
    pub name: String,
    pub primitive: ModelPrimitive,
    pub parameters: Vec<ParameterDecl>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstanceKind {
    Mos,
    Resistor,
    Capacitor,
    Diode,
    Bjt,
    Subcircuit,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetlistInstance {
    pub name: String,
    pub kind: InstanceKind,
    pub nets: Vec<String>,
    /// Device model for M/R/C/D/Q, when the declared grammar has one.
    pub model: Option<String>,
    /// Referenced subcircuit for X instances.
    pub target: Option<String>,
    /// Ordered value/area/etc. expressions after fixed terminals and model.
    pub positional_parameters: Vec<ParameterExpr>,
    pub named_parameters: Vec<ParameterDecl>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Subcircuit {
    pub name: String,
    pub ports: Vec<String>,
    pub parameters: Vec<ParameterDecl>,
    pub instances: Vec<NetlistInstance>,
    pub span: SourceSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeDecl {
    pub requested: String,
    pub resolved_source: Option<String>,
    pub span: SourceSpan,
}

/// One source unit.  Resolved includes are retained recursively rather than
/// flattened, preserving provenance and hierarchy.
#[derive(Debug, Clone, PartialEq)]
pub struct NetlistAst {
    pub source: String,
    pub globals: Vec<String>,
    pub parameters: Vec<ParameterDecl>,
    pub models: Vec<ModelDecl>,
    pub top_level_instances: Vec<NetlistInstance>,
    pub subcircuits: Vec<Subcircuit>,
    pub includes: Vec<IncludeDecl>,
    pub included_units: Vec<NetlistAst>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInclude {
    /// Stable identity used for diagnostics and cycle detection.
    pub source_name: String,
    pub contents: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TokenKind {
    Atom(String),
    Equals,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token {
    pub kind: TokenKind,
    pub span: SourceSpan,
}

impl Token {
    #[must_use]
    pub fn atom(&self) -> Option<&str> {
        match &self.kind {
            TokenKind::Atom(value) => Some(value),
            TokenKind::Equals => None,
        }
    }
}

#[derive(Debug)]
struct LogicalLine {
    tokens: Vec<Token>,
}

pub(crate) fn span(source: &str, line: usize, start: usize, end: usize) -> SourceSpan {
    SourceSpan {
        source: source.to_string(),
        line,
        column: start + 1,
        end_column: end + 1,
    }
}

fn lex_segment(
    source: &str,
    line_number: usize,
    line: &str,
    start: usize,
) -> Result<Vec<Token>, NetlistError> {
    if !line.is_ascii() {
        let column = line
            .as_bytes()
            .iter()
            .position(|byte| !byte.is_ascii())
            .unwrap_or(start);
        return Err(NetlistError::new(
            NetlistErrorKind::Lexical,
            span(source, line_number, column, column + 1),
            "non-ASCII source text is outside the declared SPICE/CDL subset",
        ));
    }
    let bytes = line.as_bytes();
    let mut tokens = Vec::new();
    let mut i = start;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || matches!(bytes[i], b';' | b'$') {
            break;
        }
        if bytes[i] == b'=' {
            tokens.push(Token {
                kind: TokenKind::Equals,
                span: span(source, line_number, i, i + 1),
            });
            i += 1;
            continue;
        }

        let token_start = i;
        if matches!(bytes[i], b'\'' | b'"') {
            let quote = bytes[i];
            i += 1;
            let mut escaped = false;
            let mut closed = false;
            while i < bytes.len() {
                let byte = bytes[i];
                i += 1;
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == quote {
                    closed = true;
                    break;
                }
            }
            if !closed {
                return Err(NetlistError::new(
                    NetlistErrorKind::Lexical,
                    span(source, line_number, token_start, bytes.len()),
                    "unterminated quoted token",
                ));
            }
        } else if bytes[i] == b'{' {
            let mut depth = 0usize;
            let mut quote: Option<u8> = None;
            let mut escaped = false;
            while i < bytes.len() {
                let byte = bytes[i];
                i += 1;
                if let Some(active_quote) = quote {
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == active_quote {
                        quote = None;
                    }
                    continue;
                }
                match byte {
                    b'\'' | b'"' => quote = Some(byte),
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if depth != 0 || quote.is_some() {
                return Err(NetlistError::new(
                    NetlistErrorKind::Lexical,
                    span(source, line_number, token_start, bytes.len()),
                    "unterminated braced expression",
                ));
            }
        } else {
            while i < bytes.len()
                && !bytes[i].is_ascii_whitespace()
                && bytes[i] != b'='
                && !matches!(bytes[i], b'{' | b'\'' | b'"')
            {
                i += 1;
            }
        }

        if i == token_start {
            return Err(NetlistError::new(
                NetlistErrorKind::Lexical,
                span(source, line_number, i, i + 1),
                "unsupported token boundary",
            ));
        }
        tokens.push(Token {
            kind: TokenKind::Atom(line[token_start..i].to_string()),
            span: span(source, line_number, token_start, i),
        });
    }
    Ok(tokens)
}

fn lex_logical_lines(source: &str, input: &str) -> Result<Vec<LogicalLine>, NetlistError> {
    let mut result = Vec::new();
    let mut current: Option<LogicalLine> = None;
    for (line_index, raw_line) in input.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        let first = line
            .as_bytes()
            .iter()
            .position(|byte| !byte.is_ascii_whitespace());
        let Some(first) = first else { continue };
        if line.as_bytes()[first] == b'*' {
            continue;
        }
        if line.as_bytes()[first] == b'+' {
            let Some(logical) = current.as_mut() else {
                return Err(NetlistError::new(
                    NetlistErrorKind::Syntax,
                    span(source, line_number, first, first + 1),
                    "continuation line has no preceding logical line",
                ));
            };
            logical
                .tokens
                .extend(lex_segment(source, line_number, line, first + 1)?);
        } else {
            if let Some(previous) = current.take() {
                result.push(previous);
            }
            current = Some(LogicalLine {
                tokens: lex_segment(source, line_number, line, first)?,
            });
        }
    }
    if let Some(previous) = current {
        result.push(previous);
    }
    Ok(result)
}

pub(crate) fn syntax(token: &Token, message: impl Into<String>) -> NetlistError {
    NetlistError::new(NetlistErrorKind::Syntax, token.span.clone(), message)
}

pub(crate) fn atom(token: &Token, description: &str) -> Result<String, NetlistError> {
    token
        .atom()
        .map(str::to_string)
        .ok_or_else(|| syntax(token, format!("expected {description}, found '='")))
}

fn is_params_marker(text: &str) -> bool {
    text.eq_ignore_ascii_case("params:") || text.eq_ignore_ascii_case("param:")
}

pub(crate) fn canonical(text: &str) -> String {
    text.to_ascii_lowercase()
}

fn strip_group(raw: &str) -> Option<&str> {
    let bytes = raw.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'{' && bytes[bytes.len() - 1] == b'}' {
        Some(raw[1..raw.len() - 1].trim())
    } else {
        None
    }
}

pub(crate) fn parameter_expr(token: &Token) -> Result<ParameterExpr, NetlistError> {
    let raw = atom(token, "parameter expression")?;
    let numeric_result = if (raw.starts_with('"') && raw.ends_with('"'))
        || (raw.starts_with('\'') && raw.ends_with('\''))
    {
        Ok(None)
    } else if let Some(inner) = strip_group(&raw) {
        match parse_engineering_number(inner) {
            Ok(value) => Ok(value),
            Err(error) => {
                // Operators inside braces make this a preserved expression.  A
                // numeric-looking atom with only an unknown suffix remains an error.
                let has_operator = inner
                    .bytes()
                    .any(|byte| matches!(byte, b'+' | b'-' | b'*' | b'/' | b'(' | b')'));
                if has_operator {
                    Ok(None)
                } else {
                    Err(error)
                }
            }
        }
    } else {
        parse_engineering_number(&raw)
    };
    let numeric = numeric_result.map_err(|message| {
        let kind = if message.contains("non-finite") {
            NetlistErrorKind::NonFiniteNumber
        } else {
            NetlistErrorKind::Syntax
        };
        NetlistError::new(kind, token.span.clone(), message)
    })?;
    Ok(ParameterExpr {
        raw,
        numeric,
        span: token.span.clone(),
    })
}

fn parse_assignments(tokens: &[Token], start: usize) -> Result<Vec<ParameterDecl>, NetlistError> {
    let mut parameters = Vec::new();
    let mut names = HashSet::new();
    let mut i = start;
    while i < tokens.len() {
        if tokens[i].atom().is_some_and(is_params_marker) {
            i += 1;
            continue;
        }
        let name = atom(&tokens[i], "parameter name")?;
        if i + 2 >= tokens.len() || tokens[i + 1].kind != TokenKind::Equals {
            return Err(syntax(
                &tokens[i],
                format!("parameter '{name}' must use name=value syntax"),
            ));
        }
        let key = canonical(&name);
        if !names.insert(key) {
            return Err(NetlistError::new(
                NetlistErrorKind::DuplicateDefinition,
                tokens[i].span.clone(),
                format!("duplicate parameter '{name}'"),
            ));
        }
        let value = parameter_expr(&tokens[i + 2])?;
        parameters.push(ParameterDecl {
            name,
            value,
            span: tokens[i].span.clone(),
        });
        i += 3;
    }
    Ok(parameters)
}

fn parse_named_tail(tokens: &[Token]) -> Result<(Vec<Token>, Vec<ParameterDecl>), NetlistError> {
    let mut positional = Vec::new();
    let mut named = Vec::new();
    let mut names = HashSet::new();
    let mut named_mode = false;
    let mut i = 0usize;
    while i < tokens.len() {
        if tokens[i].atom().is_some_and(is_params_marker) {
            named_mode = true;
            i += 1;
            continue;
        }
        let is_assignment = i + 1 < tokens.len() && tokens[i + 1].kind == TokenKind::Equals;
        if is_assignment {
            named_mode = true;
            if i + 2 >= tokens.len() {
                return Err(syntax(&tokens[i], "missing value after '='"));
            }
            let name = atom(&tokens[i], "parameter name")?;
            if !names.insert(canonical(&name)) {
                return Err(NetlistError::new(
                    NetlistErrorKind::DuplicateDefinition,
                    tokens[i].span.clone(),
                    format!("duplicate instance parameter '{name}'"),
                ));
            }
            named.push(ParameterDecl {
                name,
                value: parameter_expr(&tokens[i + 2])?,
                span: tokens[i].span.clone(),
            });
            i += 3;
        } else {
            if named_mode {
                return Err(syntax(
                    &tokens[i],
                    "positional argument follows named parameters; brace multi-token expressions",
                ));
            }
            positional.push(tokens[i].clone());
            i += 1;
        }
    }
    Ok((positional, named))
}

fn instance_prefix(name: &str) -> Option<char> {
    name.trim_start_matches('\\')
        .chars()
        .next()
        .map(|ch| ch.to_ascii_uppercase())
}

fn parse_instance(tokens: &[Token]) -> Result<NetlistInstance, NetlistError> {
    if tokens.is_empty() {
        unreachable!("empty logical lines are filtered")
    }
    let name = atom(&tokens[0], "instance name")?;
    let prefix = instance_prefix(&name).ok_or_else(|| syntax(&tokens[0], "empty instance name"))?;
    let (positional, named_parameters) = parse_named_tail(&tokens[1..])?;
    let positionals = |from: usize| -> Result<Vec<ParameterExpr>, NetlistError> {
        positional[from..].iter().map(parameter_expr).collect()
    };
    let strings = |range: std::ops::Range<usize>| -> Result<Vec<String>, NetlistError> {
        positional[range]
            .iter()
            .map(|token| atom(token, "net name"))
            .collect()
    };

    let (kind, nets, model, target, positional_parameters) = match prefix {
        'M' => {
            if positional.len() != 5 {
                return Err(syntax(
                    &tokens[0],
                    format!(
                        "MOS instance requires drain gate source body model (got {} positional fields)",
                        positional.len()
                    ),
                ));
            }
            (
                InstanceKind::Mos,
                strings(0..4)?,
                Some(atom(&positional[4], "MOS model")?),
                None,
                Vec::new(),
            )
        }
        'R' | 'C' => {
            if !(2..=4).contains(&positional.len()) {
                return Err(syntax(
                    &tokens[0],
                    format!(
                        "{} instance requires two nets, optional model, and one value",
                        if prefix == 'R' {
                            "resistor"
                        } else {
                            "capacitor"
                        }
                    ),
                ));
            }
            let (model, value) = match positional.len() {
                2 => {
                    let value_name = if prefix == 'R' { "r" } else { "c" };
                    let long_name = if prefix == 'R' {
                        "resistance"
                    } else {
                        "capacitance"
                    };
                    if !named_parameters.iter().any(|parameter| {
                        parameter.name.eq_ignore_ascii_case(value_name)
                            || parameter.name.eq_ignore_ascii_case(long_name)
                    }) {
                        return Err(syntax(
                            &tokens[0],
                            format!(
                                "{} instance with no positional value requires {}=<value>",
                                if prefix == 'R' {
                                    "resistor"
                                } else {
                                    "capacitor"
                                },
                                value_name
                            ),
                        ));
                    }
                    (None, Vec::new())
                }
                3 => (None, vec![parameter_expr(&positional[2])?]),
                4 => {
                    let model = atom(&positional[2], "device model")?;
                    if parameter_expr(&positional[2])?.numeric.is_some() {
                        return Err(syntax(
                            &positional[2],
                            "modeled R/C grammar is '<model> <value>'; numeric model is invalid",
                        ));
                    }
                    (Some(model), vec![parameter_expr(&positional[3])?])
                }
                _ => unreachable!(),
            };
            (
                if prefix == 'R' {
                    InstanceKind::Resistor
                } else {
                    InstanceKind::Capacitor
                },
                strings(0..2)?,
                model,
                None,
                value,
            )
        }
        'D' => {
            if positional.len() < 3 {
                return Err(syntax(
                    &tokens[0],
                    "diode instance requires anode cathode model",
                ));
            }
            (
                InstanceKind::Diode,
                strings(0..2)?,
                Some(atom(&positional[2], "diode model")?),
                None,
                positionals(3)?,
            )
        }
        'Q' => {
            if positional.len() != 4 {
                return Err(syntax(
                    &tokens[0],
                    "declared BJT subset requires collector base emitter model; substrate and positional area forms are unsupported",
                ));
            }
            (
                InstanceKind::Bjt,
                strings(0..3)?,
                Some(atom(&positional[3], "BJT model")?),
                None,
                Vec::new(),
            )
        }
        'X' => {
            if positional.len() < 2 {
                return Err(syntax(
                    &tokens[0],
                    "subcircuit instance requires at least one net and a target subcircuit",
                ));
            }
            let target_index = positional.len() - 1;
            (
                InstanceKind::Subcircuit,
                strings(0..target_index)?,
                None,
                Some(atom(&positional[target_index], "subcircuit target")?),
                Vec::new(),
            )
        }
        other => {
            return Err(NetlistError::new(
                NetlistErrorKind::Syntax,
                tokens[0].span.clone(),
                format!("unsupported or unknown instance prefix '{other}' in '{name}'"),
            ));
        }
    };
    if nets.iter().any(|net| net.is_empty()) {
        return Err(syntax(&tokens[0], "empty net name"));
    }
    Ok(NetlistInstance {
        name,
        kind,
        nets,
        model,
        target,
        positional_parameters,
        named_parameters,
        span: tokens[0].span.clone(),
    })
}

fn parse_subckt_header(tokens: &[Token]) -> Result<Subcircuit, NetlistError> {
    if tokens.len() < 2 {
        return Err(syntax(&tokens[0], ".subckt requires a name"));
    }
    let name = atom(&tokens[1], "subcircuit name")?;
    let mut ports = Vec::new();
    let mut parameters = Vec::new();
    let mut port_names = HashSet::new();
    let mut parameter_names = HashSet::new();
    let mut parameter_mode = false;
    let mut i = 2usize;
    while i < tokens.len() {
        if tokens[i].atom().is_some_and(is_params_marker) {
            parameter_mode = true;
            i += 1;
            continue;
        }
        let assignment = i + 1 < tokens.len() && tokens[i + 1].kind == TokenKind::Equals;
        if assignment {
            parameter_mode = true;
            if i + 2 >= tokens.len() {
                return Err(syntax(&tokens[i], "missing subcircuit parameter value"));
            }
            let parameter_name = atom(&tokens[i], "subcircuit parameter name")?;
            if !parameter_names.insert(canonical(&parameter_name)) {
                return Err(NetlistError::new(
                    NetlistErrorKind::DuplicateDefinition,
                    tokens[i].span.clone(),
                    format!("duplicate subcircuit parameter '{parameter_name}'"),
                ));
            }
            parameters.push(ParameterDecl {
                name: parameter_name,
                value: parameter_expr(&tokens[i + 2])?,
                span: tokens[i].span.clone(),
            });
            i += 3;
        } else {
            if parameter_mode {
                return Err(syntax(&tokens[i], "port follows subcircuit parameters"));
            }
            let port = atom(&tokens[i], "port name")?;
            if !port_names.insert(canonical(&port)) {
                return Err(NetlistError::new(
                    NetlistErrorKind::DuplicateDefinition,
                    tokens[i].span.clone(),
                    format!("duplicate subcircuit port '{port}'"),
                ));
            }
            ports.push(port);
            i += 1;
        }
    }
    Ok(Subcircuit {
        name,
        ports,
        parameters,
        instances: Vec::new(),
        span: tokens[0].span.clone(),
    })
}

fn unquote_path(token: &Token) -> Result<String, NetlistError> {
    let raw = atom(token, "include path")?;
    let bytes = raw.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\''))
    {
        let mut result = String::new();
        let mut escaped = false;
        for ch in raw[1..raw.len() - 1].chars() {
            if escaped {
                result.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else {
                result.push(ch);
            }
        }
        if escaped {
            return Err(syntax(token, "dangling escape in include path"));
        }
        Ok(result)
    } else {
        Ok(raw)
    }
}

/// Parse one source without resolving includes.  Include declarations remain in
/// the AST and no filesystem access occurs.
pub fn parse_netlist(source_name: &str, input: &str) -> Result<NetlistAst, NetlistError> {
    let lines = lex_logical_lines(source_name, input)?;
    let mut ast = NetlistAst {
        source: source_name.to_string(),
        globals: Vec::new(),
        parameters: Vec::new(),
        models: Vec::new(),
        top_level_instances: Vec::new(),
        subcircuits: Vec::new(),
        includes: Vec::new(),
        included_units: Vec::new(),
    };
    let mut current_subcircuit: Option<Subcircuit> = None;
    let mut subcircuit_names = HashSet::new();
    let mut top_instance_names = HashSet::new();
    let mut global_names = HashSet::new();
    let mut top_parameter_names = HashSet::new();
    let mut model_names = HashSet::new();
    let mut saw_end = false;
    let mut lib_section_stack: Vec<String> = Vec::new();

    for logical in lines {
        if logical.tokens.is_empty() {
            continue;
        }
        if saw_end {
            return Err(syntax(&logical.tokens[0], "content follows .end directive"));
        }
        // Inside a .lib section definition, only process .lib/.endl directives
        // to track nesting; skip everything else.
        if !lib_section_stack.is_empty() {
            let first = logical.tokens[0].atom().unwrap_or("");
            match first.to_ascii_lowercase().as_str() {
                ".lib" => {
                    if logical.tokens.len() == 2 {
                        let section = atom(&logical.tokens[1], "lib section name")?;
                        lib_section_stack.push(section);
                    }
                    // .lib file section inside a skipped block: ignore
                    continue;
                }
                ".endl" => {
                    lib_section_stack.pop();
                    continue;
                }
                _ => continue,
            }
        }
        let first = atom(&logical.tokens[0], "directive or instance name")?;
        if first.starts_with('.') {
            match first.to_ascii_lowercase().as_str() {
                ".subckt" => {
                    if current_subcircuit.is_some() {
                        return Err(syntax(
                            &logical.tokens[0],
                            "nested .subckt definitions are unsupported",
                        ));
                    }
                    let subcircuit = parse_subckt_header(&logical.tokens)?;
                    if !subcircuit_names.insert(canonical(&subcircuit.name)) {
                        return Err(NetlistError::new(
                            NetlistErrorKind::DuplicateDefinition,
                            subcircuit.span.clone(),
                            format!("duplicate subcircuit '{}'", subcircuit.name),
                        ));
                    }
                    current_subcircuit = Some(subcircuit);
                }
                ".ends" => {
                    let Some(subcircuit) = current_subcircuit.take() else {
                        return Err(syntax(&logical.tokens[0], ".ends without open .subckt"));
                    };
                    if logical.tokens.len() > 2 {
                        return Err(syntax(&logical.tokens[2], "extra field after .ends"));
                    }
                    if let Some(end_name) = logical.tokens.get(1) {
                        let end_name = atom(end_name, "subcircuit name")?;
                        if !end_name.eq_ignore_ascii_case(&subcircuit.name) {
                            return Err(syntax(
                                &logical.tokens[1],
                                format!(
                                    ".ends name '{end_name}' does not match .subckt '{}'",
                                    subcircuit.name
                                ),
                            ));
                        }
                    }
                    ast.subcircuits.push(subcircuit);
                }
                ".global" => {
                    if logical.tokens.len() < 2 {
                        return Err(syntax(
                            &logical.tokens[0],
                            ".global requires at least one net",
                        ));
                    }
                    for token in &logical.tokens[1..] {
                        let global = atom(token, "global net")?;
                        if !global_names.insert(canonical(&global)) {
                            return Err(NetlistError::new(
                                NetlistErrorKind::DuplicateDefinition,
                                token.span.clone(),
                                format!("duplicate global net '{global}'"),
                            ));
                        }
                        ast.globals.push(global);
                    }
                }
                ".param" => {
                    if logical.tokens.len() < 4 {
                        return Err(syntax(&logical.tokens[0], ".param requires name=value"));
                    }
                    let parameters = parse_assignments(&logical.tokens, 1)?;
                    if let Some(subcircuit) = current_subcircuit.as_mut() {
                        let mut existing: HashSet<String> = subcircuit
                            .parameters
                            .iter()
                            .map(|parameter| canonical(&parameter.name))
                            .collect();
                        for parameter in parameters {
                            if !existing.insert(canonical(&parameter.name)) {
                                return Err(NetlistError::new(
                                    NetlistErrorKind::DuplicateDefinition,
                                    parameter.span.clone(),
                                    format!("duplicate subcircuit parameter '{}'", parameter.name),
                                ));
                            }
                            subcircuit.parameters.push(parameter);
                        }
                    } else {
                        for parameter in parameters {
                            if !top_parameter_names.insert(canonical(&parameter.name)) {
                                return Err(NetlistError::new(
                                    NetlistErrorKind::DuplicateDefinition,
                                    parameter.span.clone(),
                                    format!("duplicate top-level parameter '{}'", parameter.name),
                                ));
                            }
                            ast.parameters.push(parameter);
                        }
                    }
                }
                ".model" => {
                    if current_subcircuit.is_some() {
                        return Err(syntax(
                            &logical.tokens[0],
                            ".model inside .subckt is outside the declared subset",
                        ));
                    }
                    if logical.tokens.len() < 3 {
                        return Err(syntax(
                            &logical.tokens[0],
                            ".model requires a model name and primitive/alias",
                        ));
                    }
                    let name = atom(&logical.tokens[1], "model name")?;
                    if !model_names.insert(canonical(&name)) {
                        return Err(NetlistError::new(
                            NetlistErrorKind::DuplicateDefinition,
                            logical.tokens[1].span.clone(),
                            format!("duplicate model '{name}'"),
                        ));
                    }
                    let primitive_name = atom(&logical.tokens[2], "model primitive or alias")?;
                    let primitive = match primitive_name.to_ascii_lowercase().as_str() {
                        "nmos" => ModelPrimitive::Nmos,
                        "pmos" => ModelPrimitive::Pmos,
                        "npn" => ModelPrimitive::Npn,
                        "pnp" => ModelPrimitive::Pnp,
                        "d" | "diode" => ModelPrimitive::Diode,
                        "r" | "res" | "resistor" => ModelPrimitive::Resistor,
                        "c" | "cap" | "capacitor" => ModelPrimitive::Capacitor,
                        _ => ModelPrimitive::Alias(primitive_name),
                    };
                    let parameters = if logical.tokens.len() == 3 {
                        Vec::new()
                    } else {
                        parse_assignments(&logical.tokens, 3)?
                    };
                    ast.models.push(ModelDecl {
                        name,
                        primitive,
                        parameters,
                        span: logical.tokens[0].span.clone(),
                    });
                }
                ".lib" => {
                    // ponytail: .lib as include-with-section is stored but not
                    // resolved here (resolver callback handles it). Section
                    // definitions (.lib <section> ... .endl) are skipped for now;
                    // the only form we consume is the two-token include form.
                    if current_subcircuit.is_some() {
                        return Err(syntax(
                            &logical.tokens[0],
                            ".lib inside .subckt is outside the declared subset",
                        ));
                    }
                    match logical.tokens.len() {
                        // .lib <section_name> — begin section definition block
                        2 => {
                            let section = atom(&logical.tokens[1], "lib section name")?;
                            lib_section_stack.push(section);
                        }
                        // .lib <filename> <section> — conditional include
                        3 => {
                            let requested = unquote_path(&logical.tokens[1])?;
                            if requested.is_empty() {
                                return Err(syntax(&logical.tokens[1], "lib path is empty"));
                            }
                            let section = atom(&logical.tokens[2], "lib section")?;
                            ast.includes.push(IncludeDecl {
                                requested: format!("{requested}@{section}"),
                                resolved_source: None,
                                span: logical.tokens[0].span.clone(),
                            });
                        }
                        _ => {
                            return Err(syntax(
                                &logical.tokens[0],
                                ".lib requires 1 (section) or 2 (file section) arguments",
                            ));
                        }
                    }
                }
                ".endl" => {
                    if lib_section_stack.is_empty() {
                        return Err(syntax(
                            &logical.tokens[0],
                            ".endl without matching .lib section",
                        ));
                    }
                    lib_section_stack.pop();
                }
                ".include" => {
                    if current_subcircuit.is_some() {
                        return Err(syntax(
                            &logical.tokens[0],
                            ".include inside .subckt is outside the declared subset",
                        ));
                    }
                    if logical.tokens.len() != 2 {
                        return Err(syntax(
                            &logical.tokens[0],
                            ".include requires exactly one quoted or unquoted path",
                        ));
                    }
                    let requested = unquote_path(&logical.tokens[1])?;
                    if requested.is_empty() {
                        return Err(syntax(&logical.tokens[1], "include path is empty"));
                    }
                    ast.includes.push(IncludeDecl {
                        requested,
                        resolved_source: None,
                        span: logical.tokens[0].span.clone(),
                    });
                }
                ".end" => {
                    if current_subcircuit.is_some() {
                        return Err(syntax(&logical.tokens[0], ".end before matching .ends"));
                    }
                    if logical.tokens.len() != 1 {
                        return Err(syntax(&logical.tokens[1], "extra field after .end"));
                    }
                    saw_end = true;
                }
                directive => {
                    return Err(syntax(
                        &logical.tokens[0],
                        format!("unsupported directive '{directive}'"),
                    ));
                }
            }
        } else {
            let instance = parse_instance(&logical.tokens)?;
            if let Some(subcircuit) = current_subcircuit.as_mut() {
                if subcircuit
                    .instances
                    .iter()
                    .any(|other| other.name.eq_ignore_ascii_case(&instance.name))
                {
                    return Err(NetlistError::new(
                        NetlistErrorKind::DuplicateDefinition,
                        instance.span.clone(),
                        format!("duplicate instance '{}'", instance.name),
                    ));
                }
                subcircuit.instances.push(instance);
            } else {
                if !top_instance_names.insert(canonical(&instance.name)) {
                    return Err(NetlistError::new(
                        NetlistErrorKind::DuplicateDefinition,
                        instance.span.clone(),
                        format!("duplicate top-level instance '{}'", instance.name),
                    ));
                }
                ast.top_level_instances.push(instance);
            }
        }
    }
    if let Some(subcircuit) = current_subcircuit {
        return Err(NetlistError::new(
            NetlistErrorKind::Syntax,
            subcircuit.span,
            format!("subcircuit '{}' has no matching .ends", subcircuit.name),
        ));
    }
    Ok(ast)
}

/// Expand bus ranges in port names: `data[3:0]` becomes
/// `["data[3]", "data[2]", "data[1]", "data[0]"]`.
/// Supports both `[high:low]` and `<high:low>` notations.
/// If no bus notation is found, returns `vec![port.to_string()]`.
pub fn expand_bus_range(port: &str) -> Vec<String> {
    let (open, close) = if let Some(pos) = port.find('[') {
        if port[pos..].contains(':') && port.ends_with(']') {
            (pos, ']')
        } else {
            return vec![port.to_string()];
        }
    } else if let Some(pos) = port.find('<') {
        if port[pos..].contains(':') && port.ends_with('>') {
            (pos, '>')
        } else {
            return vec![port.to_string()];
        }
    } else {
        return vec![port.to_string()];
    };
    let base = &port[..open];
    let inner = &port[open + 1..port.len() - 1];
    let Some((high_s, low_s)) = inner.split_once(':') else {
        return vec![port.to_string()];
    };
    let (Ok(high), Ok(low)) = (high_s.trim().parse::<i32>(), low_s.trim().parse::<i32>()) else {
        return vec![port.to_string()];
    };
    let open_ch = port.as_bytes()[open] as char;
    if high >= low {
        (low..=high)
            .rev()
            .map(|i| format!("{base}{open_ch}{i}{close}"))
            .collect()
    } else {
        (high..=low)
            .map(|i| format!("{base}{open_ch}{i}{close}"))
            .collect()
    }
}

fn collect_subcircuits<'a>(ast: &'a NetlistAst, output: &mut Vec<&'a Subcircuit>) {
    output.extend(ast.subcircuits.iter());
    for child in &ast.included_units {
        collect_subcircuits(child, output);
    }
}

fn validate_resolved_hierarchy(ast: &NetlistAst) -> Result<(), NetlistError> {
    let mut subcircuits = Vec::new();
    collect_subcircuits(ast, &mut subcircuits);
    let mut definitions: HashMap<String, &Subcircuit> = HashMap::new();
    for subcircuit in &subcircuits {
        let key = canonical(&subcircuit.name);
        if let Some(previous) = definitions.insert(key, subcircuit) {
            return Err(NetlistError::new(
                NetlistErrorKind::DuplicateDefinition,
                subcircuit.span.clone(),
                format!(
                    "duplicate subcircuit '{}' across sources (first declared at {}:{}:{})",
                    subcircuit.name, previous.span.source, previous.span.line, previous.span.column
                ),
            ));
        }
    }
    fn validate_instances(
        instances: &[NetlistInstance],
        definitions: &HashMap<String, &Subcircuit>,
    ) -> Result<(), NetlistError> {
        for instance in instances {
            if instance.kind == InstanceKind::Subcircuit {
                let target = instance.target.as_deref().expect("X target parsed");
                if !definitions.contains_key(&canonical(target)) {
                    return Err(NetlistError::new(
                        NetlistErrorKind::UnresolvedReference,
                        instance.span.clone(),
                        format!(
                            "instance '{}' references undefined subcircuit '{target}'",
                            instance.name
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
    for subcircuit in subcircuits {
        validate_instances(&subcircuit.instances, &definitions)?;
    }
    fn validate_unit_top_levels(
        ast: &NetlistAst,
        definitions: &HashMap<String, &Subcircuit>,
    ) -> Result<(), NetlistError> {
        validate_instances(&ast.top_level_instances, definitions)?;
        for child in &ast.included_units {
            validate_unit_top_levels(child, definitions)?;
        }
        Ok(())
    }
    validate_unit_top_levels(ast, &definitions)
}

fn resolve_unit<F>(
    source_name: &str,
    input: &str,
    resolver: &mut F,
    stack: &mut Vec<String>,
) -> Result<NetlistAst, NetlistError>
where
    F: FnMut(&str, &str) -> Result<ResolvedInclude, String>,
{
    let mut ast = parse_netlist(source_name, input)?;
    for index in 0..ast.includes.len() {
        let requested = ast.includes[index].requested.clone();
        let include_span = ast.includes[index].span.clone();
        let resolved = resolver(source_name, &requested).map_err(|message| {
            NetlistError::new(
                NetlistErrorKind::IncludeResolution,
                include_span.clone(),
                format!("failed to resolve include '{requested}': {message}"),
            )
        })?;
        if resolved.source_name.trim().is_empty() {
            return Err(NetlistError::new(
                NetlistErrorKind::IncludeResolution,
                include_span,
                format!("resolver returned an empty source identity for '{requested}'"),
            ));
        }
        if let Some(cycle_start) = stack
            .iter()
            .position(|source| source == &resolved.source_name)
        {
            let mut cycle = stack[cycle_start..].to_vec();
            cycle.push(resolved.source_name.clone());
            return Err(NetlistError::new(
                NetlistErrorKind::IncludeCycle,
                include_span,
                format!("include cycle: {}", cycle.join(" -> ")),
            ));
        }
        ast.includes[index].resolved_source = Some(resolved.source_name.clone());
        stack.push(resolved.source_name.clone());
        let child = resolve_unit(&resolved.source_name, &resolved.contents, resolver, stack)?;
        stack.pop();
        ast.included_units.push(child);
    }
    Ok(ast)
}

/// Parse a source and recursively resolve `.include` declarations through a
/// caller-owned callback.  The parser never opens files itself.  The callback's
/// stable `source_name` identity is used to detect include cycles.
pub fn parse_netlist_with_includes<F>(
    source_name: &str,
    input: &str,
    mut resolver: F,
) -> Result<NetlistAst, NetlistError>
where
    F: FnMut(&str, &str) -> Result<ResolvedInclude, String>,
{
    let mut stack = vec![source_name.to_string()];
    let ast = resolve_unit(source_name, input, &mut resolver, &mut stack)?;
    validate_resolved_hierarchy(&ast)?;
    Ok(ast)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MosModelBinding {
    pub kind: DeviceKind,
    pub flavor: DeviceFlavor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BjtModelBinding {
    pub kind: DeviceKind,
}

/// Explicit semantic bindings needed to convert a leaf AST to the legacy flat
/// reference type.  Model inference is intentionally forbidden.
#[derive(Debug, Clone, Default)]
pub struct RefConversionOptions {
    pub mos_models: HashMap<String, MosModelBinding>,
    pub bjt_models: HashMap<String, BjtModelBinding>,
    /// Nanometers represented by an unsuffixed W/L value.  `None` rejects
    /// unsuffixed dimensions instead of guessing the source netlist's unit.
    pub unsuffixed_length_nm: Option<f64>,
}

impl RefConversionOptions {
    pub fn add_mos_model(
        &mut self,
        name: impl Into<String>,
        kind: DeviceKind,
        flavor: DeviceFlavor,
    ) {
        self.mos_models
            .insert(canonical(&name.into()), MosModelBinding { kind, flavor });
    }

    pub fn add_bjt_model(&mut self, name: impl Into<String>, kind: DeviceKind) {
        self.bjt_models
            .insert(canonical(&name.into()), BjtModelBinding { kind });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefConversionErrorKind {
    TopNotFound,
    Unsupported,
    InvalidModelBinding,
    InvalidDimension,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefConversionError {
    pub kind: RefConversionErrorKind,
    pub span: SourceSpan,
    pub message: String,
}

impl RefConversionError {
    fn new(kind: RefConversionErrorKind, span: SourceSpan, message: impl Into<String>) -> Self {
        Self {
            kind,
            span,
            message: message.into(),
        }
    }

    fn unsupported(instance: &NetlistInstance, message: impl Into<String>) -> Self {
        Self::new(
            RefConversionErrorKind::Unsupported,
            instance.span.clone(),
            format!("instance '{}': {}", instance.name, message.into()),
        )
    }
}

impl fmt::Display for RefConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}: {}",
            self.span.source, self.span.line, self.span.column, self.message
        )
    }
}

impl std::error::Error for RefConversionError {}

fn find_subcircuit<'a>(ast: &'a NetlistAst, name: &str) -> Option<&'a Subcircuit> {
    ast.subcircuits
        .iter()
        .find(|subcircuit| subcircuit.name.eq_ignore_ascii_case(name))
        .or_else(|| {
            ast.included_units
                .iter()
                .find_map(|child| find_subcircuit(child, name))
        })
}

fn collect_globals(ast: &NetlistAst, globals: &mut Vec<String>) {
    globals.extend(ast.globals.iter().cloned());
    for child in &ast.included_units {
        collect_globals(child, globals);
    }
}

fn named_parameter<'a>(instance: &'a NetlistInstance, name: &str) -> Option<&'a ParameterDecl> {
    instance
        .named_parameters
        .iter()
        .find(|parameter| parameter.name.eq_ignore_ascii_case(name))
}

fn mos_binding<'a>(options: &'a RefConversionOptions, model: &str) -> Option<&'a MosModelBinding> {
    options.mos_models.get(&canonical(model)).or_else(|| {
        options
            .mos_models
            .iter()
            .find_map(|(name, binding)| name.eq_ignore_ascii_case(model).then_some(binding))
    })
}

fn bjt_binding<'a>(options: &'a RefConversionOptions, model: &str) -> Option<&'a BjtModelBinding> {
    options.bjt_models.get(&canonical(model)).or_else(|| {
        options
            .bjt_models
            .iter()
            .find_map(|(name, binding)| name.eq_ignore_ascii_case(model).then_some(binding))
    })
}

fn dimension_nm(
    parameter: &ParameterDecl,
    options: &RefConversionOptions,
) -> Result<i32, RefConversionError> {
    let Some(numeric) = parameter.value.numeric else {
        return Err(RefConversionError::new(
            RefConversionErrorKind::Unsupported,
            parameter.value.span.clone(),
            format!(
                "parameter '{}' is an expression; RefNetlist requires a resolved W/L value",
                parameter.name
            ),
        ));
    };
    let nm = if numeric.suffix.is_some() {
        numeric.value * 1.0e9
    } else {
        let Some(scale) = options.unsuffixed_length_nm else {
            return Err(RefConversionError::new(
                RefConversionErrorKind::Unsupported,
                parameter.value.span.clone(),
                format!(
                    "unsuffixed parameter '{}' has no declared length unit",
                    parameter.name
                ),
            ));
        };
        if !scale.is_finite() || scale <= 0.0 {
            return Err(RefConversionError::new(
                RefConversionErrorKind::InvalidDimension,
                parameter.value.span.clone(),
                "unsuffixed_length_nm must be finite and positive",
            ));
        }
        numeric.value * scale
    };
    if !nm.is_finite() || nm <= 0.0 || nm > f64::from(i32::MAX) {
        return Err(RefConversionError::new(
            RefConversionErrorKind::InvalidDimension,
            parameter.value.span.clone(),
            format!(
                "parameter '{}' resolves to invalid dimension {nm} nm",
                parameter.name
            ),
        ));
    }
    let rounded = nm.round();
    let tolerance = 1.0e-9_f64.max(rounded.abs() * 1.0e-12);
    if (nm - rounded).abs() > tolerance {
        return Err(RefConversionError::new(
            RefConversionErrorKind::InvalidDimension,
            parameter.value.span.clone(),
            format!(
                "parameter '{}' resolves to non-integral database dimension {nm} nm",
                parameter.name
            ),
        ));
    }
    Ok(rounded as i32)
}

/// Convert one explicitly selected flat/leaf subcircuit to the legacy
/// [`RefNetlist`].  Hierarchy, four-terminal body distinctions, unbound models,
/// unresolved properties, and R/C/D values/models are errors rather than being
/// discarded.
pub fn leaf_subcircuit_to_ref_netlist(
    ast: &NetlistAst,
    top: &str,
    options: &RefConversionOptions,
) -> Result<RefNetlist, RefConversionError> {
    let subcircuit = find_subcircuit(ast, top).ok_or_else(|| {
        RefConversionError::new(
            RefConversionErrorKind::TopNotFound,
            SourceSpan::synthetic(&ast.source),
            format!("selected top subcircuit '{top}' was not found"),
        )
    })?;
    if !subcircuit.parameters.is_empty() {
        return Err(RefConversionError::new(
            RefConversionErrorKind::Unsupported,
            subcircuit.span.clone(),
            format!(
                "selected subcircuit '{}' has formal/local parameters that RefNetlist cannot preserve",
                subcircuit.name
            ),
        ));
    }

    let mut devices = Vec::new();
    let mut ref_bjt = Vec::new();
    let ref_two_terminal: Vec<RefTwoTerminal> = Vec::new();
    for instance in &subcircuit.instances {
        match instance.kind {
            InstanceKind::Subcircuit => {
                return Err(RefConversionError::unsupported(
                    instance,
                    "hierarchical X instance cannot be flattened by this conversion API",
                ));
            }
            InstanceKind::Mos => {
                let model = instance.model.as_deref().expect("MOS model parsed");
                let Some(binding) = mos_binding(options, model) else {
                    return Err(RefConversionError::new(
                        RefConversionErrorKind::InvalidModelBinding,
                        instance.span.clone(),
                        format!(
                            "instance '{}': MOS model '{model}' has no explicit binding",
                            instance.name
                        ),
                    ));
                };
                if !matches!(binding.kind, DeviceKind::Nmos | DeviceKind::Pmos) {
                    return Err(RefConversionError::new(
                        RefConversionErrorKind::InvalidModelBinding,
                        instance.span.clone(),
                        format!(
                            "MOS model '{model}' is bound to non-MOS kind {:?}",
                            binding.kind
                        ),
                    ));
                }
                if !instance.nets[3].eq_ignore_ascii_case(&instance.nets[2]) {
                    return Err(RefConversionError::unsupported(
                        instance,
                        format!(
                            "body net '{}' differs from source '{}'; RefDevice has no body terminal",
                            instance.nets[3], instance.nets[2]
                        ),
                    ));
                }
                let width = named_parameter(instance, "w").ok_or_else(|| {
                    RefConversionError::unsupported(instance, "missing required W parameter")
                })?;
                let length = named_parameter(instance, "l").ok_or_else(|| {
                    RefConversionError::unsupported(instance, "missing required L parameter")
                })?;
                for parameter in &instance.named_parameters {
                    if !parameter.name.eq_ignore_ascii_case("w")
                        && !parameter.name.eq_ignore_ascii_case("l")
                    {
                        return Err(RefConversionError::unsupported(
                            instance,
                            format!(
                                "property '{}' cannot be represented by RefDevice",
                                parameter.name
                            ),
                        ));
                    }
                }
                devices.push(RefDevice {
                    kind: binding.kind.clone(),
                    // SPICE MOS order is D G S B.
                    drain: instance.nets[0].clone(),
                    gate: instance.nets[1].clone(),
                    source: instance.nets[2].clone(),
                    w: dimension_nm(width, options)?,
                    l: dimension_nm(length, options)?,
                    flavor: binding.flavor,
                    body: None,
                    ad: None,
                    as_: None,
                    pd: None,
                    ps: None,
                });
            }
            InstanceKind::Bjt => {
                let model = instance.model.as_deref().expect("BJT model parsed");
                let Some(binding) = bjt_binding(options, model) else {
                    return Err(RefConversionError::new(
                        RefConversionErrorKind::InvalidModelBinding,
                        instance.span.clone(),
                        format!(
                            "instance '{}': BJT model '{model}' has no explicit binding",
                            instance.name
                        ),
                    ));
                };
                if !matches!(binding.kind, DeviceKind::Npn | DeviceKind::Pnp) {
                    return Err(RefConversionError::new(
                        RefConversionErrorKind::InvalidModelBinding,
                        instance.span.clone(),
                        format!(
                            "BJT model '{model}' is bound to non-BJT kind {:?}",
                            binding.kind
                        ),
                    ));
                }
                if !instance.named_parameters.is_empty()
                    || !instance.positional_parameters.is_empty()
                {
                    return Err(RefConversionError::unsupported(
                        instance,
                        "BJT properties cannot be represented by RefBjt",
                    ));
                }
                ref_bjt.push(RefBjt {
                    kind: binding.kind.clone(),
                    name: instance.name.clone(),
                    collector: instance.nets[0].clone(),
                    base: instance.nets[1].clone(),
                    emitter: instance.nets[2].clone(),
                });
            }
            InstanceKind::Resistor | InstanceKind::Capacitor | InstanceKind::Diode => {
                let device = match instance.kind {
                    InstanceKind::Resistor => "resistor",
                    InstanceKind::Capacitor => "capacitor",
                    InstanceKind::Diode => "diode",
                    _ => unreachable!(),
                };
                return Err(RefConversionError::unsupported(
                    instance,
                    format!(
                        "{device} value/model properties cannot be represented by RefTwoTerminal"
                    ),
                ));
            }
        }
    }

    let mut net_seeds = HashMap::new();
    for port in &subcircuit.ports {
        net_seeds.insert(port.clone(), port.clone());
    }
    let mut globals = Vec::new();
    collect_globals(ast, &mut globals);
    for global in globals {
        net_seeds.insert(global.clone(), global);
    }
    Ok(RefNetlist {
        devices,
        net_seeds,
        ref_two_terminal,
        ref_bjt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subcircuit<'a>(ast: &'a NetlistAst, name: &str) -> &'a Subcircuit {
        find_subcircuit(ast, name).expect("subcircuit")
    }

    #[test]
    fn continuation_comments_case_and_physical_spans() {
        let ast = parse_netlist(
            "continuation.sp",
            r#"
                * full-line comment
                .SuBcKt inv in out vss
                M1 out in vss vss nch
                + W={base + 1u} L=180n ; unambiguous inline comment
                .param label="hello world" $ another inline comment
                .EnDs INV
                .END
            "#,
        )
        .unwrap();
        let inv = subcircuit(&ast, "INV");
        assert_eq!(inv.instances.len(), 1);
        assert_eq!(inv.instances[0].named_parameters.len(), 2);
        assert_eq!(
            inv.instances[0].named_parameters[0].value.raw,
            "{base + 1u}"
        );
        assert!(inv.instances[0].named_parameters[0].value.numeric.is_none());
        assert_eq!(inv.instances[0].named_parameters[0].span.line, 5);
        assert!(inv.instances[0].named_parameters[0].span.column > 1);
        assert_eq!(inv.parameters[0].value.raw, "\"hello world\"");
    }

    #[test]
    fn hierarchy_buses_escaped_identifiers_globals_and_parameters() {
        let ast = parse_netlist(
            "hier.cdl",
            r#"
                .global VDD! VSS!
                .param scale=2
                .subckt leaf data[3] data<2> \escaped_net params: drive={scale * 2}
                Rleaf data[3] \escaped_net 1k
                .ends leaf
                .subckt mid bus[3] bus<2> odd$name
                Xleaf bus[3] bus<2> odd$name leaf drive=3
                .ends mid
                .subckt top bus[3] bus<2> odd$name
                X0 bus[3] bus<2> odd$name mid drive=4
                .ends top
            "#,
        )
        .unwrap();
        assert_eq!(ast.globals, ["VDD!", "VSS!"]);
        assert_eq!(ast.parameters[0].name, "scale");
        let leaf = subcircuit(&ast, "leaf");
        assert_eq!(leaf.ports, ["data[3]", "data<2>", "\\escaped_net"]);
        assert_eq!(leaf.parameters[0].value.raw, "{scale * 2}");
        let top = subcircuit(&ast, "top");
        assert_eq!(top.instances[0].kind, InstanceKind::Subcircuit);
        assert_eq!(top.instances[0].target.as_deref(), Some("mid"));
        assert_eq!(top.instances[0].nets[2], "odd$name");
        assert_eq!(
            subcircuit(&ast, "mid").instances[0].target.as_deref(),
            Some("leaf")
        );
    }

    #[test]
    fn parses_every_declared_instance_prefix() {
        let ast = parse_netlist(
            "devices.sp",
            r#"
                .subckt child a b
                R0 a b 1k
                .ends child
                .subckt all d g s b x y z
                M0 d g s b nch w=1u l=100n
                R1 x y rpoly 2k tc1=1m
                C1 x y 3p
                D1 x y dio 2 area=3
                Q1 x y z npnmod
                X1 x y child gain=2
                R2 x y r=4k
                C2 x y capacitance={base_c * 2}
                .ends all
            "#,
        )
        .unwrap();
        let kinds: Vec<InstanceKind> = subcircuit(&ast, "all")
            .instances
            .iter()
            .map(|instance| instance.kind)
            .collect();
        assert_eq!(
            kinds,
            [
                InstanceKind::Mos,
                InstanceKind::Resistor,
                InstanceKind::Capacitor,
                InstanceKind::Diode,
                InstanceKind::Bjt,
                InstanceKind::Subcircuit,
                InstanceKind::Resistor,
                InstanceKind::Capacitor,
            ]
        );
        let resistor = &subcircuit(&ast, "all").instances[1];
        assert_eq!(resistor.model.as_deref(), Some("rpoly"));
        assert_eq!(
            resistor.positional_parameters[0].numeric.unwrap().value,
            2000.0
        );
        assert!(subcircuit(&ast, "all").instances[6]
            .positional_parameters
            .is_empty());
    }

    #[test]
    fn engineering_suffixes_distinguish_milli_and_mega() {
        let milli = parse_engineering_number("1M").unwrap().unwrap();
        let mega = parse_engineering_number("1meg").unwrap().unwrap();
        assert_eq!(milli.suffix, Some(EngineeringSuffix::Milli));
        assert_eq!(milli.value, 1.0e-3);
        assert_eq!(mega.suffix, Some(EngineeringSuffix::Mega));
        assert_eq!(mega.value, 1.0e6);
        assert!(
            (parse_engineering_number("2.5u").unwrap().unwrap().value - 2.5e-6).abs() < 1.0e-20
        );
        assert_eq!(
            parse_engineering_number("4e-3").unwrap().unwrap().value,
            4e-3
        );
        assert!(parse_engineering_number("1ma").is_err());
        assert!(parse_engineering_number("1e999").is_err());
        assert!(parse_engineering_number("width").unwrap().is_none());
    }

    #[test]
    fn include_resolver_preserves_units_and_resolves_hierarchy() {
        let ast = parse_netlist_with_includes(
            "root.sp",
            ".include \"cells/leaf.sp\"\n.subckt top a b\nX0 a b leaf\n.ends top\n",
            |including, requested| {
                assert_eq!(including, "root.sp");
                assert_eq!(requested, "cells/leaf.sp");
                Ok(ResolvedInclude {
                    source_name: "resolved/leaf.sp".into(),
                    contents: ".subckt leaf a b\nR0 a b 1k\n.ends leaf\n".into(),
                })
            },
        )
        .unwrap();
        assert_eq!(
            ast.includes[0].resolved_source.as_deref(),
            Some("resolved/leaf.sp")
        );
        assert_eq!(ast.included_units.len(), 1);
        assert_eq!(subcircuit(&ast, "leaf").span.source, "resolved/leaf.sp");
    }

    #[test]
    fn include_cycle_and_unresolved_x_are_errors() {
        let cycle = parse_netlist_with_includes("a.sp", ".include \"b.sp\"\n", |including, _| {
            if including == "a.sp" {
                Ok(ResolvedInclude {
                    source_name: "b.sp".into(),
                    contents: ".include \"a.sp\"\n".into(),
                })
            } else {
                Ok(ResolvedInclude {
                    source_name: "a.sp".into(),
                    contents: String::new(),
                })
            }
        })
        .unwrap_err();
        assert_eq!(cycle.kind, NetlistErrorKind::IncludeCycle);
        assert!(cycle.message.contains("a.sp -> b.sp -> a.sp"));

        let unresolved = parse_netlist_with_includes(
            "top.sp",
            ".subckt top a b\nX0 a b missing\n.ends top\n",
            |_, _| unreachable!(),
        )
        .unwrap_err();
        assert_eq!(unresolved.kind, NetlistErrorKind::UnresolvedReference);

        let duplicate_across_include = parse_netlist_with_includes(
            "root.sp",
            ".include \"child.sp\"\n.subckt same a\n.ends same\n",
            |_, _| {
                Ok(ResolvedInclude {
                    source_name: "child.sp".into(),
                    contents: ".subckt SAME b\n.ends SAME\n".into(),
                })
            },
        )
        .unwrap_err();
        assert_eq!(
            duplicate_across_include.kind,
            NetlistErrorKind::DuplicateDefinition
        );
    }

    #[test]
    fn duplicates_mismatched_ends_and_unknown_prefix_fail_closed() {
        let duplicate =
            parse_netlist("dup.sp", ".subckt a x y\nR0 x y 1k\nr0 x y 2k\n.ends a\n").unwrap_err();
        assert_eq!(duplicate.kind, NetlistErrorKind::DuplicateDefinition);
        assert_eq!(duplicate.span.line, 3);

        let duplicate_subcircuit = parse_netlist(
            "dup_subckt.sp",
            ".subckt Cell x\n.ends Cell\n.subckt cell y\n.ends cell\n",
        )
        .unwrap_err();
        assert_eq!(
            duplicate_subcircuit.kind,
            NetlistErrorKind::DuplicateDefinition
        );

        let mismatch = parse_netlist("ends.sp", ".subckt a x\n.ends b\n").unwrap_err();
        assert!(mismatch.message.contains("does not match"));

        let unknown = parse_netlist("unknown.sp", "V0 a b 1\n").unwrap_err();
        assert!(unknown.message.contains("unknown instance prefix"));

        let nonfinite = parse_netlist("nan.sp", ".param bad=1e999\n").unwrap_err();
        assert_eq!(nonfinite.kind, NetlistErrorKind::NonFiniteNumber);
        assert_eq!(
            parse_netlist("nan.sp", ".param bad=NaN\n")
                .unwrap_err()
                .kind,
            NetlistErrorKind::NonFiniteNumber
        );
    }

    #[test]
    fn malformed_arities_and_lexical_inputs_are_rejected() {
        for source in [
            ".subckt a x\nM0 x x x model w=1u l=1u\n.ends a\n",
            ".subckt a x\nR0 x\n.ends a\n",
            ".subckt a x\nC0 x x\n.ends a\n",
            ".subckt a x\nD0 x x\n.ends a\n",
            ".subckt a x\nQ0 x x model\n.ends a\n",
            ".subckt a x\nX0 child\n.ends a\n",
            "+ orphan\n",
            ".include \"unterminated\n",
            ".include '\\'\n",
            ".include \"\"\n",
            ".subckt a x\n",
        ] {
            assert!(
                parse_netlist("bad.sp", source).is_err(),
                "accepted: {source}"
            );
        }
    }

    fn conversion_options() -> RefConversionOptions {
        let mut options = RefConversionOptions::default();
        options.add_mos_model("nch_lvt", DeviceKind::Nmos, DeviceFlavor::Lvt);
        options.add_bjt_model("qnpn", DeviceKind::Npn);
        options
    }

    #[test]
    fn leaf_conversion_preserves_mos_dimensions_flavor_bjt_and_seeds() {
        let ast = parse_netlist(
            "leaf.sp",
            r#"
                .global VSS
                .subckt leaf in out VSS
                M0 out in VSS VSS nch_lvt w=1u l=180n
                Q0 out in VSS qnpn
                .ends leaf
            "#,
        )
        .unwrap();
        let reference =
            leaf_subcircuit_to_ref_netlist(&ast, "LEAF", &conversion_options()).unwrap();
        assert_eq!(reference.devices.len(), 1);
        assert_eq!(reference.devices[0].kind, DeviceKind::Nmos);
        assert_eq!(reference.devices[0].flavor, DeviceFlavor::Lvt);
        assert_eq!(
            (reference.devices[0].w, reference.devices[0].l),
            (1000, 180)
        );
        assert_eq!(reference.ref_bjt.len(), 1);
        assert_eq!(reference.ref_bjt[0].kind, DeviceKind::Npn);
        assert_eq!(
            reference.net_seeds.get("in").map(String::as_str),
            Some("in")
        );
        assert_eq!(
            reference.net_seeds.get("VSS").map(String::as_str),
            Some("VSS")
        );
    }

    #[test]
    fn leaf_conversion_rejects_information_refnetlist_cannot_represent() {
        let cases = [
            (
                ".subckt leaf d g s b\nM0 d g s b nch_lvt w=1u l=180n\n.ends leaf\n",
                "body net",
            ),
            (
                ".subckt leaf a b\nR0 a b 1k\n.ends leaf\n",
                "cannot be represented",
            ),
            (
                ".subckt child a b\nR0 a b 1k\n.ends child\n.subckt leaf a b\nX0 a b child\n.ends leaf\n",
                "hierarchical X",
            ),
            (
                ".subckt leaf d g s\nM0 d g s s nch_lvt w={width} l=180n\n.ends leaf\n",
                "expression",
            ),
        ];
        for (source, expected) in cases {
            let ast = parse_netlist("loss.sp", source).unwrap();
            let error =
                leaf_subcircuit_to_ref_netlist(&ast, "leaf", &conversion_options()).unwrap_err();
            assert_eq!(error.kind, RefConversionErrorKind::Unsupported);
            assert!(error.message.contains(expected), "{}", error.message);
        }
        let ast = parse_netlist("missing.sp", ".subckt leaf a\n.ends leaf\n").unwrap();
        assert_eq!(
            leaf_subcircuit_to_ref_netlist(&ast, "nope", &conversion_options())
                .unwrap_err()
                .kind,
            RefConversionErrorKind::TopNotFound
        );
    }

    #[test]
    fn lib_section_definition_lines_are_skipped() {
        let ast = parse_netlist(
            "lib.sp",
            r#"
                .lib tt
                .model nch_tt nmos level=49
                .endl tt
                .subckt top a b
                M0 a b b b nch w=1u l=100n
                .ends top
            "#,
        )
        .unwrap();
        // The .model inside .lib section should have been skipped
        assert!(
            ast.models.is_empty(),
            "model inside .lib section must be skipped"
        );
        assert_eq!(ast.subcircuits.len(), 1);
    }

    #[test]
    fn lib_include_form_records_file_at_section() {
        let ast = parse_netlist(
            "top.sp",
            ".lib \"models.lib\" tt\n.subckt top a\n.ends top\n",
        )
        .unwrap();
        assert_eq!(ast.includes.len(), 1);
        assert_eq!(ast.includes[0].requested, "models.lib@tt");
    }

    #[test]
    fn lib_endl_mismatch_is_error() {
        assert!(parse_netlist("bad.sp", ".endl oops\n").is_err());
    }

    #[test]
    fn expand_bus_range_square_brackets() {
        assert_eq!(
            expand_bus_range("data[3:0]"),
            vec!["data[3]", "data[2]", "data[1]", "data[0]"]
        );
    }

    #[test]
    fn expand_bus_range_angle_brackets() {
        assert_eq!(
            expand_bus_range("addr<1:3>"),
            vec!["addr<1>", "addr<2>", "addr<3>"]
        );
    }

    #[test]
    fn expand_bus_range_no_bus() {
        assert_eq!(expand_bus_range("clk"), vec!["clk"]);
        assert_eq!(expand_bus_range("data[3]"), vec!["data[3]"]);
    }

    #[test]
    fn expand_bus_range_single_bit() {
        assert_eq!(expand_bus_range("x[5:5]"), vec!["x[5]"]);
    }
}
