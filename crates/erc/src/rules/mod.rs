//! The nineteen rule tables and their transforms, grouped by what they need.
//!
//! Five files, and the split across them is the one that matters:
//!
//! | Module | Kinds | Needs |
//! |---|---|---|
//! | [`topology`] | floating gate, floating well, multiple drivers, unconnected pin | nets and devices |
//! | [`supply`] | supply short, soft connection, missing tie, tie high/low, ESD topological | nets, devices, marker geometry |
//! | [`antenna`] | antenna, cumulative antenna, density/CMP | geometry and deck limits |
//! | [`electrical`] | point-to-point resistance, IR drop, EM current density, electromigration | a solved resistive network |
//! | [`reliability`] | reliability, HV domain, ESD/latch-up | design intent, and mostly a solve too |
//!
//! The first three groups always run. In [`electrical`], only point-to-point
//! resistance always runs — its inputs are geometry and sheet resistance, both
//! of which the process supplies. The other three, and all of
//! [`reliability`], are gated on design intent.
//!
//! # What every transform in here looks like
//!
//! ```text
//! pub fn check_<kind>(.., table: &<Kind>Table, out: &mut Violations, runs: &mut Vec<RuleRun>)
//! ```
//!
//! One uniform pass over one table. Caller owns every output buffer, nothing
//! allocates per row, and each row ends by calling `record_run` — so
//! "every configured rule produced exactly one [`RuleRun`]" holds by
//! construction rather than by review.
//!
//! [`RuleRun`]: gpurify_report::RuleRun

pub mod antenna;
pub mod electrical;
pub mod reliability;
pub mod supply;
pub mod topology;
