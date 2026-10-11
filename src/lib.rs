//! Physical verification for integrated circuits: DRC, LVS, ERC and PEX, in one
//! tool and one library.
//!
//! Most verifiers say how many violations they found. `GPurify` also says how much
//! of the chip it looked at: every rule reports whether it ran and how many
//! shapes it examined, and a run that could not check everything it was asked to
//! does not pass. The same inputs always give the same bytes.
//!
//! # Running it
//!
//! From the command line, with a GDSII layout and a process deck:
//!
//! ```sh
//! gpurify drc my_layout.gds --deck my_process.deck
//! gpurify lvs my_layout.gds --deck my_process.deck --reference my_cell.spice
//! gpurify all my_layout.gds --deck my_process.deck --intent intent.json --format json
//! ```
//!
//! From Rust, the same run is [`engine::run::run`]:
//!
//! ```no_run
//! use gpurify::engine::run::run;
//! use gpurify::engine::{Checks, Inputs, RunOptions};
//!
//! let inputs = Inputs {
//!     layout: "my_layout.gds".into(),
//!     deck: "pdks/sky130.deck".into(),
//!     ..Inputs::default()
//! };
//! let options = RunOptions {
//!     checks: Checks::ALL,
//!     lvs: Default::default(),          // LVS tolerances and merge settings
//!     quasistatic_nets: vec![],         // nets to field-solve instead of closed forms
//! };
//! let (loaded, _extracted, outputs, summary) = run(&inputs, &options)?;
//! for rule in &outputs.runs {
//!     let name = loaded.strings.resolve(rule.rule);
//!     println!("{name}: {:?}, examined {}", rule.outcome, rule.examined);
//! }
//! assert!(summary.passed(), "{} violations", summary.violations);
//! # Ok::<(), gpurify::engine::EngineError>(())
//! ```
//!
//! # How a run goes
//!
//! 1. **Load** ([`engine::pipeline::load`]). The GDSII layout is read and
//!    flattened onto the grid its `UNITS` record states
//!    ([`ingest::layout`]). The deck is compiled ([`deck::compile`]): parsed,
//!    every limit converted to that grid exactly or refused ([`ingest::deck`]),
//!    and every rule typed and held to what its kind can hold. The reference netlist and
//!    design intent are read if given ([`ingest::netlist`], [`ingest::intent`]).
//! 2. **Extract** ([`engine::pipeline::extract`]). Nets are traced through the
//!    deck's conductors and vias, devices are recognised from their marker
//!    layers, and text labels name the nets ([`check::topology`]).
//! 3. **Check** ([`engine::run::run_checks`]). Design rules
//!    ([`check::drc`]), electrical rules ([`check::erc`]), layout against
//!    schematic ([`check::lvs`]) and parasitic extraction ([`extract`]), each
//!    once, in that order.
//! 4. **Report** ([`export`]). Text or JSON for the checks, SPEF or DSPF for the
//!    parasitics, all byte-deterministic.
//!
//! `lib` is the odd one out: it checks nothing, and writes a hard macro's
//! Liberty timing model per corner from the extracted layout ([`liberty`]).
//! `xor` compares two layouts layer by layer instead of checking one
//! ([`engine::xor`]).
//!
//! The four decks in `pdks/` are compiled into the library as [`pdks`], so a
//! consumer reads the deck the checker is tested with instead of a copy.
//! A deck can also be built or overridden in Rust ([`deck::DeckBuilder`]),
//! with rules of its own written as Rust functions ([`deck::CustomRule`]),
//! and shipped in a binary of its own ([`cli::main_with`]).
//!
//! # Where every rule is defined
//!
//! The [rule reference](check#rule-reference) lists every rule kind a deck can
//! name: its spelling, the Rust item that checks it, and the
//! [check catalog](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv)
//! rows it covers. The catalog is the list of everything a signoff verifier is
//! expected to check, and
//! [check-sources.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md)
//! cites the foundry manual, standard or tool that defines each check. What
//! `GPurify` does not check yet is in
//! [limitations.md](https://github.com/UW-ASIC/GPurify/blob/main/docs/limitations.md);
//! do not tape out on its verdict alone.
//!
//! The user guides: [running it](https://github.com/UW-ASIC/GPurify/blob/main/docs/usage.md),
//! [writing a deck](https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md),
//! [Liberty for a macro](https://github.com/UW-ASIC/GPurify/blob/main/docs/liberty.md).
//!
//! # The crates
//!
//! This crate re-exports the others, so one dependency reaches everything.
//!
//! | Crate | Re-exported as | Holds |
//! |---|---|---|
//! | `gpurify-geom` | [`geom`] | Database units, the geometry store, exact integer booleans, widths, spatial index, connectivity |
//! | `gpurify-ingest` | [`ingest`] | The readers: GDSII, the deck language, SPICE/CDL and Spectre netlists, design intent |
//! | `gpurify-check` | [`check`] | Extraction of nets and devices, and the DRC, ERC and LVS engines |
//! | `gpurify-extract` | [`extract`] | Parasitic R, C and L: closed forms, and a field solver for chosen nets |
//!
//! A consumer that only probes geometry can depend on `gpurify-geom` alone.

pub use gpurify_check as check;
pub use gpurify_check::deck;
pub mod cli;
pub use gpurify_geom as geom;
pub mod engine;
pub mod export;
pub mod liberty;
pub mod pdks;
pub use gpurify_extract as extract;
pub use gpurify_ingest as ingest;
