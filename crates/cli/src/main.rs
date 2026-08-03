//! `gpurify` — the command line.
//!
//! Deliberately shallow. Argument parsing, formatting and an exit code; every
//! decision about what a run does belongs to `engine`, so a library consumer
//! gets exactly the run the command line gets.
//!
//! There is one binary rather than four. The flags that matter — deck, layout,
//! output format — are shared by every check, and four binaries would mean four
//! copies of them drifting apart, with no natural home for a combined signoff
//! run.
//!
//! `clap` lives here and only here, so nothing that links `gpurify-engine` as a
//! library pays for an argument parser.

// Definition-Phase; see CLAUDE.md
#![allow(unused_variables, dead_code)]

mod args;
mod format;

/// Exit code is part of the interface: a script gates on it.
///
/// `0` only when every selected check ran and passed. A **skipped** check is
/// not a pass and does not exit `0` — that is the false-clean failure in the
/// one place it would do the most damage, since a CI job reads nothing but this
/// number.
fn main() -> std::process::ExitCode {
    todo!()
}
