//! The forty-four rule tables and their transforms, grouped by what they need.
//!
//! Each ERC kind is one table type, one row per deck rule of that kind, and one
//! `check_*` function that runs every row. [`RuleSet`](crate::erc::RuleSet)
//! holds one table per kind. A table type's doc defines its kind: what it
//! flags, its deck spelling, the [check catalog] rows it covers and who defines
//! them. Its `check_*` function's doc says what a run reports.
//!
//! | Module | Kinds | Reads |
//! |---|---|---|
//! | [`topology`] | `floating_gate`, `floating_well`, `multiple_drivers`, `unconnected_pin`, `fanout` | nets, devices, geometry; `multiple_drivers` also the intent |
//! | [`supply`] | `supply_short`, `soft_connection`, `missing_tie`, `tie_high_low`, `esd_topological`, `mixed_tag` | nets, devices, geometry; `tie_high_low` and `esd_topological` also the intent |
//! | [`antenna`] | `antenna`, `antenna_electrical`, `density_cmp` | geometry, the deck's connectivity, the die box |
//! | [`electrical`] | `p2p_resistance`, `ir_drop`, `dynamic_ir_drop`, `em_current_density`, `electromigration`, `em_thermal` | per-net resistor networks, the solved supply grid; `em_thermal` also the deck's layer heights |
//! | [`reliability`] | `reliability`, `hv_domain`, `esd_latchup` | the solved supply grid, propagated voltages, the intent |
//! | [`esd`] | `esd_path`, `esd_ground_coupling`, `esd_cross_domain`, `esd_parasitic`, `esd_exposed` | nets, devices, the deck's stack and connectivity, propagated voltages, the intent |
//! | [`latchup`] | `guard_ring_bias`, `tie_area`, `guard_ring`, `forward_diode`, `conditional_tie`, `latchup_victim` | geometry, nets; `guard_ring_bias` the intent, `forward_diode` propagated voltages too |
//! | [`domain`] | `gate_oxide`, `drain_source`, `well_bias`, `missing_level_shifter`, `domain_crossing`, `voltage_spacing`, `dielectric_field`, `hv_tag`, `undriven_gate`, `missing_isolation` | propagated voltages, the intent; `voltage_spacing`, `dielectric_field` and `hv_tag` also geometry; `undriven_gate` and `missing_isolation` also each power state's |
//!
//! # Tables
//!
//! Every table is a struct of arrays. `head` has one entry per deck row, and
//! every other per-row column has `head.len()` entries. A list parameter
//! (layers, models) is CSR: row `i` owns `column[start[i] .. start[i + 1]]`,
//! so `start` has `head.len() + 1` entries once a row exists, starts at 0 and
//! never decreases. A per-layer limit column runs parallel to its layer column.
//! [`RuleSet::from_deck`](crate::erc::RuleSet::from_deck) keeps these
//! invariants. A table built by hand that breaks them makes its `check_*`
//! function panic on an out-of-bounds index.
//!
//! Units are the engine's, whatever unit the deck was written in: lengths and
//! areas in database units of the layout ([`Dbu`](gpurify_geom::Dbu)),
//! voltages in mV, currents in µA, current per width in A/m (equal to µA/µm),
//! resistance in Ω, temperature in K, activation energy in eV, lifetimes in
//! hours, and densities and duty cycles as fractions in `0.0 ..= 1.0`.
//!
//! # Outcomes
//!
//! Each `check_*` function appends its violations to `out` and records exactly
//! one [`RuleRun`](crate::report::RuleRun) per row:
//! [`Ran`](crate::report::Outcome::Ran) with the count of what it examined
//! (each function says what it counts),
//! [`Skipped`](crate::report::Outcome::Skipped) when the kind needs design
//! intent and none usable was given
//! ([`IntentMap::is_usable`](crate::erc::facts::IntentMap::is_usable)), or
//! [`Refused`](crate::report::Outcome::Refused) when an input is outside what
//! the rule represents exactly. A limit is strict: a value exactly at it
//! passes.
//!
//! # Sources
//!
//! A table's "Catalog" line names the rows of the [check catalog] it covers,
//! and "Defined by" the documents behind them, by the tags of
//! [check-sources.md]. The deck spellings are in [deck.md], and what a
//! partial row misses is in [limitations.md].
//!
//! [check catalog]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-catalog.tsv
//! [check-sources.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/check-sources.md
//! [deck.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/deck.md#electrical-rules
//! [limitations.md]: https://github.com/UW-ASIC/GPurify/blob/main/docs/limitations.md

pub mod antenna;
pub mod domain;
pub mod electrical;
pub mod esd;
pub mod latchup;
pub mod reliability;
pub mod supply;
pub mod topology;
