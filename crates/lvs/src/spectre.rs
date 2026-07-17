//! Spectre netlist dialect parser.
//!
//! Produces the same [`NetlistAst`] as the SPICE parser so downstream
//! binding works unchanged.
//!
//! ponytail: intentional subset — no `inline subckt`, no `alter`, no
//! `library` multi-section in one parse, no `ahdl_include`.  Add when
//! a real netlist needs them.

use super::netlist::{
    atom, canonical, parameter_expr, span, syntax, IncludeDecl, InstanceKind, ModelDecl,
    ModelPrimitive, NetlistAst, NetlistError, NetlistErrorKind, NetlistInstance, ParameterDecl,
    SourceSpan, Subcircuit, Token, TokenKind,
};
use std::collections::HashSet;

/// Parse a Spectre-dialect netlist into the shared AST.
pub fn parse_spectre(source: &str, input: &str) -> Result<NetlistAst, NetlistError> {
    let lines = spectre_logical_lines(source, input)?;
    let mut ast = NetlistAst {
        source: source.to_string(),
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
    let mut model_names = HashSet::new();
    let mut section_depth: usize = 0;

    for line in &lines {
        if line.tokens.is_empty() {
            continue;
        }
        // Inside section/endsection blocks, only track nesting.
        if section_depth > 0 {
            let first = line.tokens[0].atom().unwrap_or("");
            match first {
                "section" => section_depth += 1,
                "endsection" => section_depth -= 1,
                _ => {}
            }
            continue;
        }
        let first = line.tokens[0].atom().unwrap_or("");
        match first {
            "subckt" => {
                if current_subcircuit.is_some() {
                    return Err(syntax(
                        &line.tokens[0],
                        "nested subckt definitions are unsupported",
                    ));
                }
                let sub = parse_spectre_subckt_header(&line.tokens)?;
                if !subcircuit_names.insert(canonical(&sub.name)) {
                    return Err(NetlistError::new(
                        NetlistErrorKind::DuplicateDefinition,
                        sub.span.clone(),
                        format!("duplicate subcircuit '{}'", sub.name),
                    ));
                }
                current_subcircuit = Some(sub);
            }
            "ends" => {
                let Some(sub) = current_subcircuit.take() else {
                    return Err(syntax(&line.tokens[0], "ends without open subckt"));
                };
                if let Some(end_tok) = line.tokens.get(1) {
                    let end_name = atom(end_tok, "subcircuit name")?;
                    if !end_name.eq_ignore_ascii_case(&sub.name) {
                        return Err(syntax(
                            end_tok,
                            format!(
                                "ends name '{end_name}' does not match subckt '{}'",
                                sub.name
                            ),
                        ));
                    }
                }
                ast.subcircuits.push(sub);
            }
            "parameters" => {
                let params = parse_spectre_parameters(&line.tokens, 1)?;
                if let Some(sub) = current_subcircuit.as_mut() {
                    sub.parameters.extend(params);
                } else {
                    ast.parameters.extend(params);
                }
            }
            "global" => {
                for tok in &line.tokens[1..] {
                    let g = atom(tok, "global net")?;
                    ast.globals.push(g);
                }
            }
            "model" => {
                let mdl = parse_spectre_model(&line.tokens)?;
                if !model_names.insert(canonical(&mdl.name)) {
                    return Err(NetlistError::new(
                        NetlistErrorKind::DuplicateDefinition,
                        mdl.span.clone(),
                        format!("duplicate model '{}'", mdl.name),
                    ));
                }
                ast.models.push(mdl);
            }
            "include" => {
                if line.tokens.len() < 2 {
                    return Err(syntax(&line.tokens[0], "include requires a path"));
                }
                let requested = unquote_spectre(&line.tokens[1])?;
                if requested.is_empty() {
                    return Err(syntax(&line.tokens[1], "include path is empty"));
                }
                // ponytail: optional section= arg on include stored as file@section
                // tokenizer splits section=tt into [section, =, tt]
                let path = if line.tokens.len() >= 4 {
                    let key = atom(&line.tokens[2], "section key")?;
                    if key == "section"
                        && matches!(line.tokens[3].kind, TokenKind::Equals)
                        && line.tokens.len() >= 5
                    {
                        let sect = atom(&line.tokens[4], "section name")?;
                        format!("{requested}@{sect}")
                    } else {
                        requested
                    }
                } else {
                    requested
                };
                ast.includes.push(IncludeDecl {
                    requested: path,
                    resolved_source: None,
                    span: line.tokens[0].span.clone(),
                });
            }
            "section" => {
                section_depth += 1;
            }
            "endsection" => {
                return Err(syntax(
                    &line.tokens[0],
                    "endsection without matching section",
                ));
            }
            "simulator" | "simulatorOptions" | "saveOptions" | "save" | "ic" | "nodeset" => {
                // ponytail: simulator directives — skip silently
                continue;
            }
            _ => {
                // Instance line: name (ports) model params...
                if let Some(sub) = current_subcircuit.as_mut() {
                    let inst = parse_spectre_instance(&line.tokens)?;
                    if sub
                        .instances
                        .iter()
                        .any(|o| o.name.eq_ignore_ascii_case(&inst.name))
                    {
                        return Err(NetlistError::new(
                            NetlistErrorKind::DuplicateDefinition,
                            inst.span.clone(),
                            format!("duplicate instance '{}'", inst.name),
                        ));
                    }
                    sub.instances.push(inst);
                } else {
                    let inst = parse_spectre_instance(&line.tokens)?;
                    if !top_instance_names.insert(canonical(&inst.name)) {
                        return Err(NetlistError::new(
                            NetlistErrorKind::DuplicateDefinition,
                            inst.span.clone(),
                            format!("duplicate top-level instance '{}'", inst.name),
                        ));
                    }
                    ast.top_level_instances.push(inst);
                }
            }
        }
    }
    if current_subcircuit.is_some() {
        return Err(NetlistError::new(
            NetlistErrorKind::Syntax,
            SourceSpan::synthetic(source),
            "subckt has no matching ends",
        ));
    }
    if section_depth > 0 {
        return Err(NetlistError::new(
            NetlistErrorKind::Syntax,
            SourceSpan::synthetic(source),
            "section has no matching endsection",
        ));
    }
    Ok(ast)
}

// ---------------------------------------------------------------------------
// Lexer: Spectre tokenization
// ---------------------------------------------------------------------------

struct SpectreLine {
    tokens: Vec<Token>,
}

fn spectre_logical_lines(source: &str, input: &str) -> Result<Vec<SpectreLine>, NetlistError> {
    let mut result = Vec::new();
    let mut lines_iter = input.lines().enumerate().peekable();
    while let Some((line_index, raw_line)) = lines_iter.next() {
        let line_number = line_index + 1;
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        // Strip // comments
        let content = if let Some(pos) = line.find("//") {
            &line[..pos]
        } else {
            line
        };
        let trimmed = content.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Handle backslash continuation
        let mut full = trimmed.to_string();
        while full.ends_with('\\') {
            full.truncate(full.len() - 1);
            if let Some((_, next)) = lines_iter.next() {
                let next = next.strip_suffix('\r').unwrap_or(next);
                let next = if let Some(p) = next.find("//") {
                    &next[..p]
                } else {
                    next
                };
                full.push(' ');
                full.push_str(next.trim());
            } else {
                break;
            }
        }
        let tokens = lex_spectre_line(source, line_number, &full)?;
        if !tokens.is_empty() {
            result.push(SpectreLine { tokens });
        }
    }
    Ok(result)
}

fn lex_spectre_line(
    source: &str,
    line_number: usize,
    line: &str,
) -> Result<Vec<Token>, NetlistError> {
    let bytes = line.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        // skip whitespace
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        // parentheses become their own atoms
        if bytes[i] == b'(' || bytes[i] == b')' {
            tokens.push(Token {
                kind: TokenKind::Atom(String::from(bytes[i] as char)),
                span: span(source, line_number, i, i + 1),
            });
            i += 1;
            continue;
        }
        if bytes[i] == b'=' {
            tokens.push(Token {
                kind: TokenKind::Equals,
                span: span(source, line_number, i, i + 1),
            });
            i += 1;
            continue;
        }
        // quoted string
        if bytes[i] == b'"' {
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            if i < bytes.len() {
                i += 1; // consume closing quote
            }
            tokens.push(Token {
                kind: TokenKind::Atom(line[start..i].to_string()),
                span: span(source, line_number, start, i),
            });
            continue;
        }
        // regular token
        let start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'('
            && bytes[i] != b')'
        {
            i += 1;
        }
        if i > start {
            tokens.push(Token {
                kind: TokenKind::Atom(line[start..i].to_string()),
                span: span(source, line_number, start, i),
            });
        }
    }
    Ok(tokens)
}

// ---------------------------------------------------------------------------
// Spectre construct parsers
// ---------------------------------------------------------------------------

fn parse_spectre_subckt_header(tokens: &[Token]) -> Result<Subcircuit, NetlistError> {
    // subckt name (ports...) [parameters ...]
    if tokens.len() < 2 {
        return Err(syntax(&tokens[0], "subckt requires a name"));
    }
    let name = atom(&tokens[1], "subcircuit name")?;
    let mut ports = Vec::new();
    let mut i = 2usize;
    // optional parenthesized port list
    if i < tokens.len() && tokens[i].atom() == Some("(") {
        i += 1; // skip (
        while i < tokens.len() {
            let tok = atom(&tokens[i], "port or )")?;
            i += 1;
            if tok == ")" {
                break;
            }
            ports.push(tok);
        }
    }
    // remaining tokens before any "parameters" keyword are also ports (non-paren form)
    // but if we see "parameters" we switch to param mode
    let mut parameters = Vec::new();
    while i < tokens.len() {
        let tok_str = tokens[i].atom().unwrap_or("");
        if tok_str.eq_ignore_ascii_case("parameters") {
            i += 1;
            parameters = parse_spectre_parameters(tokens, i)?;
            break;
        }
        // non-paren port (rare but legal)
        if i + 1 < tokens.len() && tokens[i + 1].kind == TokenKind::Equals {
            // this is param=value
            parameters = parse_spectre_parameters(tokens, i)?;
            break;
        }
        ports.push(atom(&tokens[i], "port name")?);
        i += 1;
    }
    Ok(Subcircuit {
        name,
        ports,
        parameters,
        instances: Vec::new(),
        span: tokens[0].span.clone(),
    })
}

fn parse_spectre_parameters(
    tokens: &[Token],
    start: usize,
) -> Result<Vec<ParameterDecl>, NetlistError> {
    let mut params = Vec::new();
    let mut i = start;
    while i < tokens.len() {
        let name_str = tokens[i].atom().unwrap_or("");
        if name_str.eq_ignore_ascii_case("parameters") {
            i += 1;
            continue;
        }
        if i + 2 < tokens.len() && tokens[i + 1].kind == TokenKind::Equals {
            let name = atom(&tokens[i], "parameter name")?;
            let value = parameter_expr(&tokens[i + 2])?;
            params.push(ParameterDecl {
                name,
                value,
                span: tokens[i].span.clone(),
            });
            i += 3;
        } else {
            // Not a param assignment — stop
            break;
        }
    }
    Ok(params)
}

fn parse_spectre_model(tokens: &[Token]) -> Result<ModelDecl, NetlistError> {
    // model name type (params...)
    if tokens.len() < 3 {
        return Err(syntax(&tokens[0], "model requires name and type"));
    }
    let name = atom(&tokens[1], "model name")?;
    let prim_name = atom(&tokens[2], "model primitive")?;
    let primitive = match prim_name.to_ascii_lowercase().as_str() {
        "nmos" => ModelPrimitive::Nmos,
        "pmos" => ModelPrimitive::Pmos,
        "npn" => ModelPrimitive::Npn,
        "pnp" => ModelPrimitive::Pnp,
        "diode" | "d" => ModelPrimitive::Diode,
        "resistor" | "res" | "r" => ModelPrimitive::Resistor,
        "capacitor" | "cap" | "c" => ModelPrimitive::Capacitor,
        _ => ModelPrimitive::Alias(prim_name),
    };
    // Parse optional params — may be in parens or not
    let mut param_start = 3;
    if param_start < tokens.len() && tokens[param_start].atom() == Some("(") {
        param_start += 1;
    }
    let parameters = parse_spectre_parameters(tokens, param_start)?;
    Ok(ModelDecl {
        name,
        primitive,
        parameters,
        span: tokens[0].span.clone(),
    })
}

fn parse_spectre_instance(tokens: &[Token]) -> Result<NetlistInstance, NetlistError> {
    // name (ports...) model_or_subckt param=value ...
    if tokens.is_empty() {
        unreachable!();
    }
    let name = atom(&tokens[0], "instance name")?;
    let mut i = 1usize;
    let mut nets = Vec::new();
    // Port list in parens
    if i < tokens.len() && tokens[i].atom() == Some("(") {
        i += 1;
        while i < tokens.len() {
            let tok = atom(&tokens[i], "net or )")?;
            i += 1;
            if tok == ")" {
                break;
            }
            nets.push(tok);
        }
    }
    // Next non-param token is the model/subcircuit name
    if i >= tokens.len() {
        return Err(syntax(
            &tokens[0],
            format!("instance '{name}' missing model or subcircuit"),
        ));
    }
    // Check if this token is a name=value (no model specified)
    let model_or_target = if i + 1 < tokens.len() && tokens[i + 1].kind == TokenKind::Equals {
        // no model token — this is a bare instance with only params
        None
    } else {
        let m = atom(&tokens[i], "model/subcircuit")?;
        i += 1;
        Some(m)
    };
    // Remaining are named parameters
    let named_parameters = parse_spectre_parameters(tokens, i)?;

    // Determine kind from port count + model conventions
    let model_or_target = model_or_target.unwrap_or_default();
    let (kind, model, target) = classify_spectre_instance(&name, &model_or_target, nets.len());

    Ok(NetlistInstance {
        name,
        kind,
        nets,
        model,
        target,
        positional_parameters: Vec::new(),
        named_parameters,
        span: tokens[0].span.clone(),
    })
}

/// Classify a Spectre instance into the shared InstanceKind.
/// ponytail: heuristic — 4 ports = MOS, 3 = BJT, 2 = R/C/D, else subcircuit.
/// This matches typical Spectre usage; override via model declarations.
fn classify_spectre_instance(
    _name: &str,
    model: &str,
    port_count: usize,
) -> (InstanceKind, Option<String>, Option<String>) {
    let lower = model.to_ascii_lowercase();
    // Known primitive prefixes
    if lower.starts_with("nmos")
        || lower.starts_with("pmos")
        || lower.starts_with("nch")
        || lower.starts_with("pch")
    {
        return (InstanceKind::Mos, Some(model.to_string()), None);
    }
    if lower.starts_with("npn") || lower.starts_with("pnp") {
        return (InstanceKind::Bjt, Some(model.to_string()), None);
    }
    // Fall back to port count
    match port_count {
        4 => (InstanceKind::Mos, Some(model.to_string()), None),
        3 => (InstanceKind::Bjt, Some(model.to_string()), None),
        2 => {
            // Could be R, C, D, or subcircuit — default to subcircuit and let
            // model binding sort it out.
            (InstanceKind::Subcircuit, None, Some(model.to_string()))
        }
        _ => (InstanceKind::Subcircuit, None, Some(model.to_string())),
    }
}

fn unquote_spectre(token: &Token) -> Result<String, NetlistError> {
    let raw = atom(token, "path")?;
    if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
        Ok(raw[1..raw.len() - 1].to_string())
    } else {
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_spectre_subcircuit() {
        let ast = parse_spectre(
            "inv.scs",
            r#"
                // Inverter
                subckt inv (in out vdd vss)
                  parameters wp=1u wn=0.5u
                  mp (out in vdd vdd) pmos w=wp l=0.18u
                  mn (out in vss vss) nmos w=wn l=0.18u
                ends inv
            "#,
        )
        .unwrap();
        assert_eq!(ast.subcircuits.len(), 1);
        let inv = &ast.subcircuits[0];
        assert_eq!(inv.name, "inv");
        assert_eq!(inv.ports, ["in", "out", "vdd", "vss"]);
        assert_eq!(inv.parameters.len(), 2);
        assert_eq!(inv.instances.len(), 2);
        assert_eq!(inv.instances[0].kind, InstanceKind::Mos);
        assert_eq!(inv.instances[0].model.as_deref(), Some("pmos"));
        assert_eq!(inv.instances[0].nets, ["out", "in", "vdd", "vdd"]);
        assert_eq!(inv.instances[1].model.as_deref(), Some("nmos"));
    }

    #[test]
    fn spectre_include_and_section() {
        let ast = parse_spectre(
            "top.scs",
            r#"
                include "mylib.scs"
                include "corners.scs" section=tt

                section slow
                  // corner content skipped
                endsection
            "#,
        )
        .unwrap();
        assert_eq!(ast.includes.len(), 2);
        assert_eq!(ast.includes[0].requested, "mylib.scs");
        assert_eq!(ast.includes[1].requested, "corners.scs@tt");
    }

    #[test]
    fn spectre_model_and_global() {
        let ast = parse_spectre(
            "models.scs",
            r#"
                global 0 vdd!
                model mymos nmos (tox=9n vth0=0.4)
                model alias_model mymos
            "#,
        )
        .unwrap();
        assert_eq!(ast.globals, ["0", "vdd!"]);
        assert_eq!(ast.models.len(), 2);
        assert_eq!(ast.models[0].name, "mymos");
        assert!(matches!(ast.models[0].primitive, ModelPrimitive::Nmos));
        assert_eq!(ast.models[1].name, "alias_model");
        assert!(matches!(
            ast.models[1].primitive,
            ModelPrimitive::Alias(ref s) if s == "mymos"
        ));
    }

    #[test]
    fn spectre_comment_stripping() {
        let ast = parse_spectre(
            "cmt.scs",
            "// full line comment\nsubckt a (x)\n// inner comment\nends a\n",
        )
        .unwrap();
        assert_eq!(ast.subcircuits.len(), 1);
        assert_eq!(ast.subcircuits[0].ports, ["x"]);
    }

    #[test]
    fn spectre_continuation_line() {
        let ast = parse_spectre("cont.scs", "subckt big (a b \\\nc d)\nends big\n").unwrap();
        assert_eq!(ast.subcircuits[0].ports, ["a", "b", "c", "d"]);
    }

    #[test]
    fn spectre_rejects_mismatched_ends() {
        assert!(parse_spectre("bad.scs", "subckt a (x)\nends b\n").is_err());
    }

    #[test]
    fn spectre_rejects_dangling_subckt() {
        assert!(parse_spectre("bad.scs", "subckt a (x)\n").is_err());
    }
}
