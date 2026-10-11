//! The independent tools the differential tests run against (testing-plan
//! §4 L6): Netgen, `FastCap`, `FastHenry` and ngspice, all provided by
//! `nix develop .#oracles`.
//!
//! A differential test that cannot find its tool panics, naming the shell
//! that provides it: a comparison that did not run must never read as one
//! that passed. Every run goes through [`run`], which lets at most
//! [`MAX_RUNNING`] tool processes live at once in the whole test binary and
//! kills each one it started before returning or panicking.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Tool processes alive at once, across every thread of the binary. One
/// Netgen batch holds about 6 MB per comparison it has run, and the machine
/// is shared (testing-plan §4 L6).
pub const MAX_RUNNING: usize = 2;

/// Free slots of [`MAX_RUNNING`], and the wait for one.
static SLOTS: (Mutex<usize>, Condvar) = (Mutex::new(MAX_RUNNING), Condvar::new());

/// The executable `name` from `PATH`.
///
/// # Panics
///
/// When no directory on `PATH` holds a file of that name.
pub fn tool(name: &str) -> PathBuf {
    std::env::var_os("PATH")
        .iter()
        .flat_map(std::env::split_paths)
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
        .unwrap_or_else(|| {
            panic!("{name} is not on PATH: run this test inside `nix develop .#oracles`")
        })
}

/// A new, empty directory for one comparison's input and output files, under
/// the system temporary directory and named after `tag`. Nothing removes it:
/// a caller removes it once the comparison holds, and a failure leaves it for
/// a reader.
///
/// # Panics
///
/// When the directory cannot be created.
pub fn scratch(tag: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let serial = NEXT.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "gpurify-oracle-{tag}-{}-{serial}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|why| panic!("cannot create {}: {why}", dir.display()));
    dir
}

/// A slot of [`MAX_RUNNING`] and the child holding it: dropping it, on
/// return or on a panic, kills the child if it still runs, reaps it, and
/// frees the slot.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let (free, freed) = &SLOTS;
        *free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        freed.notify_one();
    }
}

/// Runs `tool` with `args` in `dir`, once one of [`MAX_RUNNING`] slots is
/// free, and returns its standard output. Its two output streams go to
/// `stdout.txt` and `stderr.txt` in `dir`.
///
/// # Panics
///
/// When it cannot be started, runs past `limit` (it is killed first), or
/// exits unsuccessfully; the message carries both of its output streams.
pub fn run(tool: &Path, args: &[&str], dir: &Path, limit: Duration) -> String {
    let (free, freed) = &SLOTS;
    {
        let mut slots = free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *slots == 0 {
            slots = freed
                .wait(slots)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *slots -= 1;
    }
    let stream = |name: &str| {
        File::create(dir.join(name)).unwrap_or_else(|why| panic!("{}: {why}", dir.display()))
    };
    let spawned = Command::new(tool)
        .args(args)
        .current_dir(dir)
        .stdout(stream("stdout.txt"))
        .stderr(stream("stderr.txt"))
        .spawn();
    let mut child = match spawned {
        Ok(child) => Running(child),
        Err(why) => {
            *free
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
            freed.notify_one();
            panic!("cannot start {}: {why}", tool.display());
        }
    };
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("the child can be polled") {
            break Some(status);
        }
        if start.elapsed() > limit {
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    drop(child);
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
    let stdout = read("stdout.txt");
    let shown = || format!("{stdout}\n{}", read("stderr.txt"));
    match status {
        None => panic!(
            "{} {args:?} in {} ran past {limit:?} and was killed:\n{}",
            tool.display(),
            dir.display(),
            shown()
        ),
        Some(status) if !status.success() => panic!(
            "{} {args:?} in {} failed ({status}):\n{}",
            tool.display(),
            dir.display(),
            shown()
        ),
        Some(_) => stdout,
    }
}
