//! `gpurify` — parse the command line, run, render, exit `0` only on a pass
//! ([`gpurify::cli`]).

fn main() -> std::process::ExitCode {
    gpurify::cli::main_with(&[])
}
