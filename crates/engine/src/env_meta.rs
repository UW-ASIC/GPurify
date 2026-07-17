//! Environment metadata capture for qualification and benchmark provenance.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentMeta {
    pub crate_version: String,
    pub git_commit: String,
    pub git_dirty: bool,
    pub rust_version: String,
    pub target: String,
    pub cpu_model: String,
    pub cpu_cores: usize,
    pub ram_bytes: u64,
    pub gpu_model: Option<String>,
    pub gpu_driver: Option<String>,
}

pub fn capture() -> EnvironmentMeta {
    EnvironmentMeta {
        crate_version: env!("CARGO_PKG_VERSION").into(),
        git_commit: git_commit(),
        git_dirty: git_dirty(),
        rust_version: rustc_version(),
        target: std::env::consts::ARCH.into(),
        cpu_model: cpu_model(),
        cpu_cores: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        ram_bytes: ram_bytes(),
        gpu_model: gpu_model(),
        gpu_driver: gpu_driver(),
    }
}

fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn git_dirty() -> bool {
    std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

fn rustc_version() -> String {
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_default()
}

#[cfg(not(target_os = "linux"))]
fn cpu_model() -> String {
    String::new()
}

#[cfg(target_os = "linux")]
fn ram_bytes() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .map(|kb| kb * 1024)
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn ram_bytes() -> u64 {
    0
}

fn gpu_model() -> Option<String> {
    std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=name", "--format=csv,noheader"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn gpu_driver() -> Option<String> {
    std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=driver_version", "--format=csv,noheader"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_basic_fields() {
        let m = capture();
        assert!(!m.rust_version.is_empty());
        assert!(m.cpu_cores > 0);
        assert!(!m.crate_version.is_empty());
    }
}
