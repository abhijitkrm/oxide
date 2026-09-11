//! Benchmark: node assembly + smoke test.
//!
//! Measures the cost of assembling a full Oxide node (executor +
//! modules + consensus engine) and running a single-tx smoke test.
//! This is the cold-start path that `oxide-validator` and
//! `oxide-fullnode` execute on startup.
//!
//! Gate: assembly < 10 ms (release). The assembly is a one-time cost
//! at node startup; it should not dominate block production.
//!
//! `missing_docs` is allowed for this bench crate only: the criterion
//! entry-point macros generate undocumented functions, and benches are
//! not part of the public API.

#![allow(missing_docs)]

use criterion::{Criterion, criterion_group, criterion_main};
use node::{ConsensusConfig, Node, NodeConfig};

fn bench_node_assembly(c: &mut Criterion) {
    c.bench_function("node_assembly/sequencer", |b| {
        b.iter(|| {
            let config = NodeConfig {
                consensus: ConsensusConfig::Sequencer,
                max_mempool_entries: 10_000,
                ..NodeConfig::default()
            };
            let _node = Node::assemble(&config);
        });
    });

    c.bench_function("node_assembly/oxidebft", |b| {
        b.iter(|| {
            let config = NodeConfig {
                consensus: ConsensusConfig::OxideBft,
                max_mempool_entries: 10_000,
                ..NodeConfig::default()
            };
            let _node = Node::assemble(&config);
        });
    });
}

fn bench_node_smoke_test(c: &mut Criterion) {
    c.bench_function("node_smoke_test/sequencer", |b| {
        b.iter(|| {
            let config = NodeConfig {
                consensus: ConsensusConfig::Sequencer,
                max_mempool_entries: 10_000,
                ..NodeConfig::default()
            };
            let mut node = Node::assemble(&config);

            // Submit a bank transfer tx.
            let to = primitives::Address([2u8; 20]);
            let module_payload = bank::msg::transfer(to, 100);
            let tx = build_tx(framework::module_id::BANK, &module_payload);
            node.engine().submit_tx(tx);
            node.engine().run_until_idle();
        });
    });
}

fn build_tx(module_id: u8, module_payload: &[u8]) -> types::TxBytes {
    let sender = primitives::Address([0u8; 20]);
    let nonce = 0u64;
    let fee = 100u64;
    let mut bytes = Vec::with_capacity(36 + 1 + module_payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(module_id);
    bytes.extend_from_slice(module_payload);
    types::TxBytes::new(bytes)
}

criterion_group!(benches, bench_node_assembly, bench_node_smoke_test);
criterion_main!(benches);
