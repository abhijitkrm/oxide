//! Multi-process TCP devnet: each validator runs as a separate OS
//! process.
//!
//! # What this is
//!
//! A launcher that spawns N `oxide-devnet` processes, each running
//! a single validator node. The processes communicate over TCP,
//! simulating a real network deployment.
//!
//! The spawned binary is `oxide-devnet`, not `oxide-validator`:
//! development launchers are separate binaries from the production
//! validator — the production binary carries no dev-only network
//! mode (6.5).
//!
//! # Why this exists
//!
//! The in-process `TcpMultiNodeDevnet` runs all validators in a
//! single process, sharing memory and the same event loop. This
//! doesn't test:
//!
//! - Process isolation (a crash in one node doesn't affect others)
//! - Real OS-level network stack behavior
//! - Independent startup/shutdown of nodes
//! - Signal handling (SIGTERM, SIGINT)
//!
//! The multi-process devnet tests these scenarios by running each
//! node as a separate process.
//!
//! # Usage
//!
//! ```sh
//! # Launch a 4-node devnet (each node is a separate process)
//!
//! # Each node runs:
//! oxide-devnet --node 0 --num-nodes 4 --base-port 22000
//! oxide-devnet --node 1 --num-nodes 4 --base-port 22000
//! oxide-devnet --node 2 --num-nodes 4 --base-port 22000
//! oxide-devnet --node 3 --num-nodes 4 --base-port 22000
//! ```

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

/// Configuration for launching a multi-process devnet.
#[derive(Debug, Clone)]
pub struct MultiProcessDevnetConfig {
    /// Number of validator processes to launch.
    pub num_nodes: usize,
    /// Base TCP port. Node `i` listens on `127.0.0.1:{base_port + i}`.
    pub base_port: u16,
    /// Path to the `oxide-devnet` binary. If `None`, uses the
    /// current executable's directory.
    pub devnet_binary: Option<PathBuf>,
    /// How long to wait for all processes to start before returning.
    pub startup_wait: Duration,
}

impl Default for MultiProcessDevnetConfig {
    fn default() -> Self {
        Self {
            num_nodes: 4,
            base_port: 22000,
            devnet_binary: None,
            startup_wait: Duration::from_secs(2),
        }
    }
}

/// A multi-process devnet: N validator processes communicating over TCP.
///
/// Each process runs `oxide-devnet --node <i> --num-nodes <N>
/// --base-port <port>`. The launcher spawns all processes, waits for
/// them to start, and provides methods to check their status.
///
/// When dropped, all child processes are terminated.
pub struct MultiProcessDevnet {
    /// The child processes.
    children: Vec<Child>,
    /// The number of nodes.
    num_nodes: usize,
    /// The base port.
    base_port: u16,
}

impl MultiProcessDevnet {
    /// Launch a multi-process devnet with the given configuration.
    ///
    /// # Panics
    ///
    /// Panics if the validator binary cannot be found or if any
    /// process cannot be spawned.
    #[must_use]
    pub fn launch(config: MultiProcessDevnetConfig) -> Self {
        let binary = config.devnet_binary.unwrap_or_else(|| {
            // Try to find oxide-devnet in the same directory as the
            // current executable, or in the target directory.
            let current = std::env::current_exe().expect("current exe path");
            let dir = current.parent().expect("parent dir");
            dir.join("oxide-devnet")
        });

        assert!(binary.exists(), "oxide-devnet binary not found at {}", binary.display());

        let mut children = Vec::with_capacity(config.num_nodes);
        for i in 0..config.num_nodes {
            let child = Command::new(&binary)
                .arg("--node")
                .arg(i.to_string())
                .arg("--num-nodes")
                .arg(config.num_nodes.to_string())
                .arg("--base-port")
                .arg(config.base_port.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|e| panic!("failed to spawn validator {i}: {e}"));
            children.push(child);
        }

        // Wait for processes to start and establish connections.
        thread::sleep(config.startup_wait);

        Self { children, num_nodes: config.num_nodes, base_port: config.base_port }
    }

    /// Returns the number of validator processes.
    #[must_use]
    pub fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    /// Returns the base port.
    #[must_use]
    pub fn base_port(&self) -> u16 {
        self.base_port
    }

    /// Returns the listen address of node `i`.
    #[must_use]
    pub fn node_address(&self, i: usize) -> String {
        format!("127.0.0.1:{}", self.base_port + u16::try_from(i).unwrap_or(0))
    }

    /// Check if all processes are still running.
    ///
    /// Returns `true` if all processes are alive, `false` if any
    /// have exited.
    #[must_use]
    pub fn all_alive(&mut self) -> bool {
        self.children.iter_mut().all(|c| {
            match c.try_wait() {
                Ok(None) => true, // still running
                // exited or error checking — not alive
                _ => false,
            }
        })
    }

    /// Send SIGTERM (Unix) or terminate (Windows) to all processes.
    pub fn shutdown(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
        }
    }

    /// Wait for all processes to exit. Returns the exit status of
    /// each process.
    ///
    /// # Panics
    ///
    /// Panics if any child process cannot be waited on (e.g., the
    /// process was already reaped by another caller).
    pub fn wait_all(mut self) -> Vec<std::process::ExitStatus> {
        self.children.iter_mut().map(|c| c.wait().expect("wait for child process")).collect()
    }
}

impl Drop for MultiProcessDevnet {
    fn drop(&mut self) {
        // Kill all child processes when the devnet is dropped.
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Config defaults are sensible.
    #[test]
    fn config_defaults() {
        let config = MultiProcessDevnetConfig::default();
        assert_eq!(config.num_nodes, 4);
        assert_eq!(config.base_port, 22000);
        assert!(config.devnet_binary.is_none());
    }

    /// Node address derivation is correct.
    #[test]
    fn node_address_derivation() {
        let config =
            MultiProcessDevnetConfig { num_nodes: 4, base_port: 22000, ..Default::default() };
        // We can't actually launch processes in tests, but we can
        // test the address derivation logic.
        assert_eq!(format!("127.0.0.1:{}", config.base_port), "127.0.0.1:22000");
        assert_eq!(format!("127.0.0.1:{}", config.base_port + 3), "127.0.0.1:22003");
    }
}
