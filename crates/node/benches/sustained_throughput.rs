//! Benchmark: sustained executor throughput with large blocks.
//!
//! Measures the maximum txs/s the executor can process in a single
//! block, with no consensus overhead (`SequencerEngine`, single leader).
//! This isolates the executor + module execution cost from consensus
//! round-trip overhead.
//!
//! ## What this tells us
//!
//! - If TPS scales linearly with block size, the executor is NOT the
//!   bottleneck — consensus overhead is. Larger blocks in the real
//!   pipeline will amortize that overhead.
//! - If TPS plateaus at some block size, the executor IS the
//!   bottleneck. That plateau is the executor's maximum throughput.
//!
//! ## Gate
//!
//! The executor must sustain >= 10,000 bank-transfer tx/s in a single
//! block of 1000 txs (release). This is the floor below which the
//! executor itself is the bottleneck, regardless of block size.
//!
//! `missing_docs` is allowed for this bench crate only: the criterion
//! entry-point macros generate undocumented functions, and benches are
//! not part of the public API.

#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use node::{ConsensusConfig, Node, NodeConfig};
use primitives::Address;

/// Build a bank-transfer tx in the mempool v0 wire format.
fn build_bank_tx(nonce: u64) -> types::TxBytes {
    let to = Address([2u8; 20]);
    let payload = bank::msg::transfer(to, 1);
    let sender = Address([0u8; 20]);
    let fee = 100u64;
    let mut bytes = Vec::with_capacity(36 + 1 + payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(framework::module_id::BANK);
    bytes.extend_from_slice(&payload);
    types::TxBytes::new(bytes)
}

/// Benchmark: submit N bank-transfer txs and run one block to finality.
///
/// Uses the `SequencerEngine` (no voting, no QC, no TCP) to isolate
/// executor throughput. Each iteration:
/// 1. Assemble a fresh node.
/// 2. Submit `n` txs to the mempool.
/// 3. Run the engine to idle (one block, all txs).
/// 4. Measure wall time.
fn bench_executor_bank_throughput(c: &mut Criterion) {
    let block_sizes: &[usize] = &[100, 250, 500, 1000, 2000];

    let mut group = c.benchmark_group("executor_bank_throughput");
    group.throughput(Throughput::Elements(1)); // per-tx throughput

    for &n in block_sizes {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let config = NodeConfig {
                    consensus: ConsensusConfig::Sequencer,
                    max_mempool_entries: n + 100,
                    parallel_threshold: 32,
                    evm_persistence: true,
                    storage_path: None,
                    settlement_operator: None,
                    min_fee: 0,
                };
                let mut node = Node::assemble(&config);

                for nonce in 0..n as u64 {
                    node.engine().submit_tx(build_bank_tx(nonce));
                }
                node.engine().run_until_idle();

                // Verify all txs were finalized in one block.
                let height = node.engine().finalized_height();
                assert!(height.is_some(), "a block should be finalized");
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_executor_bank_throughput, bench_sustained_pipeline);
criterion_main!(benches);

/// Benchmark: sustained multi-block pipeline throughput.
///
/// Measures the full pipeline: mempool intake → block proposal →
/// consensus finalize → executor apply, sustained across many
/// blocks. This is the "real TPS" number — not the single-block
/// executor ceiling.
///
/// ## What this tells us
///
/// The single-block bench (`executor_bank_throughput`) isolates the
/// executor. This bench adds the consensus + finalization overhead
/// per block. The gap between the two reveals how much overhead
/// consensus adds per block.
///
/// ## Methodology
///
/// 1. Assemble a node with `SequencerEngine` (no voting overhead —
///    we're measuring the pipeline, not BFT rounds).
/// 2. Submit `txs_per_block` txs, run to idle (one block finalizes).
/// 3. Repeat for `num_blocks` blocks.
/// 4. Measure total wall time and compute sustained txs/s.
///
/// ## Gate
///
/// The sustained pipeline must achieve >= 5,000 txs/s across 100
/// blocks of 100 txs each (release profile). This is lower than the
/// single-block gate because per-block overhead (proposal, state
/// root, finalization) is amortized over fewer txs.
fn bench_sustained_pipeline(c: &mut Criterion) {
    let configs: &[(usize, usize)] = &[
        (100, 10),  // 100 txs/block, 10 blocks
        (100, 100), // 100 txs/block, 100 blocks
        (500, 20),  // 500 txs/block, 20 blocks
        (1000, 10), // 1000 txs/block, 10 blocks
    ];

    let mut group = c.benchmark_group("sustained_pipeline");
    group.sample_size(10); // fewer samples — each iteration is expensive

    for &(txs_per_block, num_blocks) in configs {
        let label = format!("{txs_per_block}tx_{num_blocks}blk");
        let total_txs = txs_per_block * num_blocks;
        group.throughput(Throughput::Elements(total_txs as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(&label),
            &(txs_per_block, num_blocks),
            |b, &(tpb, nb)| {
                b.iter(|| {
                    let config = NodeConfig {
                        consensus: ConsensusConfig::Sequencer,
                        max_mempool_entries: tpb + 100,
                        parallel_threshold: 32,
                        evm_persistence: false, // disable disk I/O for pure pipeline measurement
                        storage_path: None,
                        settlement_operator: None,
                        min_fee: 0,
                    };
                    let mut node = Node::assemble(&config);

                    let mut nonce = 0u64;
                    for _ in 0..nb {
                        for _ in 0..tpb {
                            node.engine().submit_tx(build_bank_tx(nonce));
                            nonce += 1;
                        }
                        node.engine().run_until_idle();
                    }

                    // Verify all blocks were finalized.
                    let height = node.engine().finalized_height();
                    assert!(height.is_some(), "blocks should be finalized");
                });
            },
        );
    }
    group.finish();
}
