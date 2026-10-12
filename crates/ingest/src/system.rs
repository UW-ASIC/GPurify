//! The system description: which dies make up a multi-die assembly (2.5D,
//! 3D, chiplets on an interposer), where each one sits, which of their faces
//! are bonded to each other, and which face meets the package.
//!
//! It is the configuration Calibre 3DSTACK reads from its rule deck, as the
//! product's public fact sheet lists it (Siemens, *Calibre 3DSTACK*, fact
//! sheet 82850-D2, 2022): the list of dies, each die's position and
//! orientation, and the interface geometry, whose text labels name the pins.
//! Everything else stays where it already lives: each die's layout, deck and
//! design intent are its own files, and the pin-level connectivity is the
//! system netlist, a SPICE or Spectre reference whose top subcircuit places
//! one instance per die.
//!
//! Read like the design intent: JSON, every key checked, every path relative
//! to the file. Nothing partial is returned.

use std::path::{Path, PathBuf};

/// Why a system description was rejected.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SystemFileError {
    /// Not JSON of the schema (an unknown key, a wrong type), or a value the
    /// schema refuses: no die, a die named twice or not at all, a rotation
    /// that is not a quarter turn, an origin that is not a number, a face
    /// naming an unlisted die, a bond between a die and itself, or an `esd`
    /// section that names no clamp, has no package face, or names system
    /// pins without system clamps (or the reverse).
    #[error("malformed system description: {0}")]
    Malformed(String),
    /// The file could not be read.
    #[error("io: {0}")]
    Io(String),
}

/// A parsed system description; [`parse_system`] gives the schema.
#[derive(Debug, Clone, PartialEq)]
pub struct System {
    /// Every die, in file order. A die's index here is how the rest of the
    /// description refers to it.
    pub dies: Vec<DieSpec>,
    /// Bonded face pairs: the two faces of each, on two different dies.
    pub bonds: Vec<[Face; 2]>,
    /// Per bond, in [`System::bonds`]' order, the alignment it is held to.
    pub bond_limits: Vec<BondLimits>,
    /// The face that meets the package substrate: its bumps are the
    /// component's external pins.
    pub package: Option<Face>,
    /// The ESD checks to run, if any.
    pub esd: Option<EsdSpec>,
}

/// One die of the assembly.
#[derive(Debug, Clone, PartialEq)]
pub struct DieSpec {
    /// The die's name: the system netlist's instance of it has this name. A
    /// die no instance names is interconnect only (an interposer, a
    /// redistribution layer).
    pub name: String,
    /// The die's GDSII layout.
    pub layout: PathBuf,
    /// The die's process deck.
    pub deck: PathBuf,
    /// The die's design intent: its supplies, by its own labels.
    pub intent: Option<PathBuf>,
    /// Where the die's origin lands in the assembly, in nanometres. Converted
    /// onto the die's grid exactly, or refused.
    pub origin_nm: [f64; 2],
    /// Counter-clockwise quarter turns, `0` to `3`.
    pub quarter_turns: u8,
    /// Whether the die is reflected in its x axis (`y` to `-y`) before it is
    /// turned: a die flipped face down.
    pub mirror: bool,
}

/// One face of a die: a layer of its deck whose shapes are its bumps,
/// through-silicon-via landings or bond pads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Face {
    /// The die, an index into [`System::dies`].
    pub die: usize,
    /// The deck layer's name.
    pub layer: String,
}

/// What a bond's bumps are held to across the two dies, each left out when
/// the file states none: a foundry's or packager's assembly rules, which
/// no public source states.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct BondLimits {
    /// The largest offset, centre to centre, between two bonded bumps, in
    /// nanometres; 0 or more.
    pub max_offset_nm: Option<f64>,
    /// The least gap between a bump and a bump of the facing die it does
    /// not bond, in nanometres; 0 or more.
    pub min_space_nm: Option<f64>,
}

/// The ESD checks: which device models protect a pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsdSpec {
    /// Models of the ESD protection devices and rail clamps, for the
    /// die-to-die and package checks. At least one.
    pub clamps: Vec<String>,
    /// Models rated for system-level stress (IEC 61000-4-2), for the system
    /// pins. Empty exactly when `system_pins` is.
    pub system_clamps: Vec<String>,
    /// The package pins exposed to system-level ESD (a connector's pins), by
    /// the label on their package bump.
    pub system_pins: Vec<String>,
}

/// The file's wire shape. `deny_unknown_fields` throughout: a typo'd key
/// would silently drop a die's placement or a check.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemWire {
    dies: Vec<DieWire>,
    #[serde(default)]
    bonds: Vec<BondWire>,
    package: Option<FaceWire>,
    esd: Option<EsdWire>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DieWire {
    name: String,
    layout: String,
    deck: String,
    intent: Option<String>,
    #[serde(default)]
    origin_nm: [f64; 2],
    #[serde(default)]
    rotate: u32,
    #[serde(default)]
    mirror: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BondWire {
    a: FaceWire,
    b: FaceWire,
    max_offset_nm: Option<f64>,
    min_space_nm: Option<f64>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FaceWire {
    die: String,
    layer: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EsdWire {
    clamps: Vec<String>,
    #[serde(default)]
    system_clamps: Vec<String>,
    #[serde(default)]
    system_pins: Vec<String>,
}

fn malformed<T>(why: String) -> Result<T, SystemFileError> {
    Err(SystemFileError::Malformed(why))
}

/// Parses and validates a system description; relative paths are taken
/// from `base`, the directory the file is in.
///
/// # Schema
///
/// ```json
/// {
///   "dies": [{ "name": "<instance>", "layout": "<gds>", "deck": "<deck>",
///              "intent": "<json>", "origin_nm": [<x>, <y>],
///              "rotate": 0|90|180|270, "mirror": false }],
///   "bonds": [{ "a": { "die": "<name>", "layer": "<deck layer>" },
///               "b": { "die": "<name>", "layer": "<deck layer>" },
///               "max_offset_nm": <nm>, "min_space_nm": <nm> }],
///   "package": { "die": "<name>", "layer": "<deck layer>" },
///   "esd": { "clamps": ["<model>"], "system_clamps": ["<model>"],
///            "system_pins": ["<label>"] }
/// }
/// ```
///
/// `dies` is required and not empty; in a die, `intent`, `origin_nm` (`[0,
/// 0]`), `rotate` (`0`) and `mirror` (`false`) may be left out. A die is
/// placed by reflecting it in its x axis when `mirror`, then turning it
/// counter-clockwise by `rotate` degrees, then moving its origin to
/// `origin_nm`: a GDSII reference's order. `bonds`, `package` and `esd` may be
/// left out, and so may a bond's `max_offset_nm` and `min_space_nm`, which
/// must be numbers of 0 or more.
///
/// # Errors
///
/// [`SystemFileError::Malformed`], naming what is wrong.
pub fn parse_system(source: &str, base: &Path) -> Result<System, SystemFileError> {
    let wire: SystemWire =
        serde_json::from_str(source).map_err(|e| SystemFileError::Malformed(e.to_string()))?;
    if wire.dies.is_empty() {
        return malformed("a system needs at least one die".to_owned());
    }
    let mut dies = Vec::with_capacity(wire.dies.len());
    for die in wire.dies {
        if die.name.is_empty() {
            return malformed("a die has an empty name".to_owned());
        }
        if dies.iter().any(|seen: &DieSpec| seen.name == die.name) {
            return malformed(format!("die {} is listed twice", die.name));
        }
        if die.rotate % 90 != 0 || die.rotate >= 360 {
            return malformed(format!(
                "die {}: rotate is {}, not 0, 90, 180 or 270",
                die.name, die.rotate
            ));
        }
        if !die.origin_nm.iter().all(|v| v.is_finite()) {
            return malformed(format!("die {}: origin_nm is not a number", die.name));
        }
        dies.push(DieSpec {
            layout: base.join(&die.layout),
            deck: base.join(&die.deck),
            intent: die.intent.map(|intent| base.join(intent)),
            origin_nm: die.origin_nm,
            quarter_turns: u8::try_from(die.rotate / 90).expect("below four, checked above"),
            mirror: die.mirror,
            name: die.name,
        });
    }
    let face = |wire: FaceWire| match dies.iter().position(|die| die.name == wire.die) {
        Some(die) => Ok(Face {
            die,
            layer: wire.layer,
        }),
        None => malformed(format!(
            "a face names die {}, which the system does not list",
            wire.die
        )),
    };
    let mut bonds = Vec::with_capacity(wire.bonds.len());
    let mut bond_limits = Vec::with_capacity(wire.bonds.len());
    for bond in wire.bonds {
        for (name, value) in [
            ("max_offset_nm", bond.max_offset_nm),
            ("min_space_nm", bond.min_space_nm),
        ] {
            if value.is_some_and(|v| !(v.is_finite() && v >= 0.0)) {
                return malformed(format!("a bond's {name} is not a number of 0 or more"));
            }
        }
        bond_limits.push(BondLimits {
            max_offset_nm: bond.max_offset_nm,
            min_space_nm: bond.min_space_nm,
        });
        let pair = [face(bond.a)?, face(bond.b)?];
        if pair[0].die == pair[1].die {
            return malformed(format!(
                "a bond joins die {} to itself",
                dies[pair[0].die].name
            ));
        }
        bonds.push(pair);
    }
    let package = wire.package.map(face).transpose()?;
    let esd = match wire.esd {
        None => None,
        Some(esd) => {
            if esd.clamps.is_empty() {
                return malformed("esd names no clamp model".to_owned());
            }
            if package.is_none() {
                return malformed(
                    "esd checks the package pins, so the system needs a package face".to_owned(),
                );
            }
            if esd.system_pins.is_empty() != esd.system_clamps.is_empty() {
                return malformed(
                    "esd: system pins need system clamps, and system clamps need system pins"
                        .to_owned(),
                );
            }
            Some(EsdSpec {
                clamps: esd.clamps,
                system_clamps: esd.system_clamps,
                system_pins: esd.system_pins,
            })
        }
    };
    Ok(System {
        dies,
        bond_limits,
        bonds,
        package,
        esd,
    })
}

/// Reads a system description from a file; see [`parse_system`]. Paths in it
/// are relative to the file's directory.
///
/// # Errors
///
/// [`SystemFileError::Io`] naming the path when it cannot be read, else as
/// [`parse_system`].
pub fn read_system(path: &Path) -> Result<System, SystemFileError> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| SystemFileError::Io(format!("{}: {e}", path.display())))?;
    parse_system(&source, path.parent().unwrap_or(Path::new("")))
}

#[cfg(test)]
mod tests {
    use super::{parse_system, Face};
    use std::path::Path;

    /// Oracle: construct-from-answer against the schema in `parse_system`'s
    /// rustdoc: every value reads back as written, paths joined to the base,
    /// `rotate: 270` is three quarter turns, and left-out keys take the
    /// documented defaults.
    #[test]
    fn a_full_description_reads_back_as_written() {
        let system = parse_system(
            r#"{
              "dies": [
                { "name": "Xint", "layout": "int.gds", "deck": "int.deck" },
                { "name": "Xcpu", "layout": "/abs/cpu.gds", "deck": "cpu.deck",
                  "intent": "cpu.json", "origin_nm": [1500, -20],
                  "rotate": 270, "mirror": true }
              ],
              "bonds": [{ "a": { "die": "Xint", "layer": "ubump" },
                          "b": { "die": "Xcpu", "layer": "bump" } }],
              "package": { "die": "Xint", "layer": "c4" },
              "esd": { "clamps": ["dio"], "system_clamps": ["scr"],
                       "system_pins": ["usb_dp"] }
            }"#,
            Path::new("/work"),
        )
        .expect("a legal description");
        let (int, cpu) = (&system.dies[0], &system.dies[1]);
        assert_eq!(int.layout, Path::new("/work/int.gds"));
        assert_eq!(cpu.layout, Path::new("/abs/cpu.gds"));
        assert_eq!(cpu.intent.as_deref(), Some(Path::new("/work/cpu.json")));
        assert_eq!(int.intent, None);
        assert_eq!(
            (int.origin_nm, int.quarter_turns, int.mirror),
            ([0.0, 0.0], 0, false)
        );
        assert_eq!(
            (cpu.origin_nm, cpu.quarter_turns, cpu.mirror),
            ([1500.0, -20.0], 3, true)
        );
        let face = |die, layer: &str| Face {
            die,
            layer: layer.to_owned(),
        };
        assert_eq!(system.bonds, [[face(0, "ubump"), face(1, "bump")]]);
        assert_eq!(system.package, Some(face(0, "c4")));
        let esd = system.esd.expect("esd");
        assert_eq!(
            (esd.clamps, esd.system_clamps, esd.system_pins),
            (
                vec!["dio".to_owned()],
                vec!["scr".to_owned()],
                vec!["usb_dp".to_owned()]
            )
        );
    }

    /// Oracle: the refusals `SystemFileError::Malformed` documents, one
    /// description breaking each, and each message names the rule broken.
    #[test]
    fn every_malformed_description_is_refused_with_its_reason() {
        let die = |name: &str, extra: &str| {
            format!(r#"{{ "name": "{name}", "layout": "l.gds", "deck": "d.deck"{extra} }}"#)
        };
        let two = format!("{}, {}", die("A", ""), die("B", ""));
        let cases = [
            (r#"{ "dies": [] }"#.to_owned(), "at least one die"),
            (format!(r#"{{ "dies": [{}] }}"#, die("", "")), "empty name"),
            (
                format!(r#"{{ "dies": [{}, {}] }}"#, die("A", ""), die("A", "")),
                "listed twice",
            ),
            (
                format!(r#"{{ "dies": [{}] }}"#, die("A", r#", "rotate": 45"#)),
                "not 0, 90, 180 or 270",
            ),
            (
                format!(r#"{{ "dies": [{}] }}"#, die("A", r#", "rotate": 360"#)),
                "not 0, 90, 180 or 270",
            ),
            (
                format!(r#"{{ "dies": [{}] }}"#, die("A", r#", "flip": true"#)),
                "unknown field",
            ),
            (
                format!(
                    r#"{{ "dies": [{two}], "bonds": [{{ "a": {{ "die": "A", "layer": "b" }},
                        "b": {{ "die": "C", "layer": "b" }} }}] }}"#
                ),
                "does not list",
            ),
            (
                format!(
                    r#"{{ "dies": [{two}], "bonds": [{{ "a": {{ "die": "A", "layer": "b" }},
                        "b": {{ "die": "A", "layer": "c" }} }}] }}"#
                ),
                "to itself",
            ),
            (
                format!(r#"{{ "dies": [{two}], "esd": {{ "clamps": ["d"] }} }}"#),
                "needs a package face",
            ),
            (
                format!(
                    r#"{{ "dies": [{two}], "package": {{ "die": "A", "layer": "c4" }},
                        "esd": {{ "clamps": [] }} }}"#
                ),
                "no clamp model",
            ),
            (
                format!(
                    r#"{{ "dies": [{two}], "package": {{ "die": "A", "layer": "c4" }},
                        "esd": {{ "clamps": ["d"], "system_pins": ["p"] }} }}"#
                ),
                "system pins need system clamps",
            ),
        ];
        for (source, reason) in cases {
            let error = parse_system(&source, Path::new(""))
                .expect_err(&source)
                .to_string();
            assert!(error.contains(reason), "{source}: {error}");
        }
    }
}
