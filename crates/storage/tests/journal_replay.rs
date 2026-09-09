//! Phase 1 acceptance gate: journal replay reproduces state root
//! bit-exact (plan.md §13).
//!
//! This test writes finalized blocks to the journal, replays them,
//! re-executes through the real executor + core/bank/staking modules,
//! and verifies the state root after replay matches the state root
//! from the original execution — byte for byte.
//!
//! The flow:
//! 1. Build an executor with core/bank/staking modules.
//! 2. Finalize N blocks (each with bank-transfer txs).
//! 3. After each block, record the state root and append the encoded
//!    `FinalizedBlock` to the journal.
//! 4. Sync the journal.
//! 5. Replay the journal: decode each record as a `FinalizedBlock`.
//! 6. Build a fresh executor (same modules) and replay each block
//!    through `finalize_block`.
//! 7. After each block, verify the state root matches the original.

use std::sync::Arc;

use codec::{Decode, Encode, Reader};
use executor::Executor;
use ports::AppInterface;
use primitives::{Address, Height};
use storage::replay;
use storage::{JournalConfig, JournalWriter};
use types::FinalizedBlock;

/// Construct a bank-transfer tx: sender 0x00..00 sends `amount`
/// tokens to recipient 0x02..02. The nonce makes each tx unique.
fn bank_tx(nonce: u64, amount: u64) -> types::TxBytes {
    let sender = Address([0u8; 20]);
    let to = Address([2u8; 20]);
    let fee = 100u64;
    let module_payload = bank::msg::transfer(to, amount);
    let mut bytes = Vec::with_capacity(36 + 1 + module_payload.len());
    bytes.extend_from_slice(&sender.0);
    bytes.extend_from_slice(&nonce.to_le_bytes());
    bytes.extend_from_slice(&fee.to_le_bytes());
    bytes.push(framework::module_id::BANK);
    bytes.extend_from_slice(&module_payload);
    types::TxBytes::new(bytes)
}

/// Build an executor with core/bank/staking modules (same as the
/// devnet multi-node runner).
fn build_executor() -> Arc<Executor> {
    let mut executor = Executor::new(10_000);
    executor.register_module(Arc::new(oxide_core::CoreModule::new()));
    executor.register_module(Arc::new(bank::BankModule::new()));
    executor.register_module(Arc::new(staking::StakingModule::new()));
    Arc::new(executor)
}

/// Encode a `FinalizedBlock` to bytes (for journal append).
fn encode_block(block: &FinalizedBlock) -> Vec<u8> {
    let mut buf = Vec::new();
    block.encode(&mut buf);
    buf
}

/// Decode a `FinalizedBlock` from journal record bytes.
fn decode_block(payload: &[u8]) -> FinalizedBlock {
    let mut reader = Reader::new(payload);
    FinalizedBlock::decode(&mut reader).expect("decoded FinalizedBlock must be valid")
}

/// The core acceptance test: write N blocks to the journal, replay
/// them, and verify the state root matches bit-exact after each
/// block.
#[test]
fn journal_replay_reproduces_state_root_bit_exact() {
    let dir = std::env::temp_dir().join(format!(
        "oxide-journal-replay-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);

    // --- Phase 1: execute blocks and write to journal ---
    let executor = build_executor();
    let mut writer = JournalWriter::create(&dir, JournalConfig::default())
        .expect("journal create should succeed");

    let n_blocks = 10usize;
    let mut original_roots = Vec::with_capacity(n_blocks);

    for h in 0..n_blocks {
        // Build a block with 3 bank-transfer txs.
        let txs: Vec<types::TxBytes> =
            (0..3).map(|i| bank_tx(u64::try_from(h * 10 + i).unwrap(), 1)).collect();
        let block = FinalizedBlock { height: Height::new(u64::try_from(h).unwrap()), txs };

        // Execute the block (produces and records the state root).
        executor.finalize_block(&block);
        let root = executor.attest_state(block.height).root;
        original_roots.push(root);

        // Append the encoded block to the journal.
        let payload = encode_block(&block);
        writer.append(&payload).expect("journal append should succeed");
    }
    writer.sync().expect("journal sync should succeed");

    // --- Phase 2: replay the journal and re-execute ---
    let replayed = replay(&dir).expect("journal replay should succeed");
    assert!(replayed.truncated_at.is_none(), "journal must be fully intact");
    assert_eq!(replayed.records.len(), n_blocks, "replay must return all {n_blocks} records");

    let replayed_executor = build_executor();
    for (i, record) in replayed.records.iter().enumerate() {
        let block = decode_block(&record.payload);
        assert_eq!(
            block.height,
            Height::new(u64::try_from(i).unwrap()),
            "replayed block {i} must have the correct height"
        );

        // Re-execute the block through the fresh executor.
        replayed_executor.finalize_block(&block);
        let replayed_root = replayed_executor.attest_state(block.height).root;

        // The acceptance gate: state root must match bit-exact.
        assert_eq!(
            replayed_root, original_roots[i],
            "state root mismatch at height {i}: original {:?}, replayed {:?}",
            original_roots[i], replayed_root
        );
    }

    // Clean up.
    let _ = std::fs::remove_dir_all(&dir);
}

/// Replay must handle an empty journal gracefully (fresh-node
/// bootstrap path).
#[test]
fn journal_replay_empty_directory() {
    let dir = std::env::temp_dir().join(format!(
        "oxide-journal-empty-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);

    let replayed = replay(&dir).expect("empty directory should not error");
    assert!(replayed.records.is_empty(), "empty journal has no records");
    assert!(replayed.truncated_at.is_none(), "empty journal is not truncated");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Replay must handle a missing directory gracefully (fresh-node
/// bootstrap path — the journal doesn't exist yet).
#[test]
fn journal_replay_missing_directory() {
    let dir = std::env::temp_dir().join(format!(
        "oxide-journal-missing-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    // Don't create the directory.
    let replayed = replay(&dir).expect("missing directory should not error");
    assert!(replayed.records.is_empty(), "missing journal has no records");
}

/// Replay must detect a torn tail and report `truncated_at` while
/// preserving all complete records before the tear.
#[test]
fn journal_replay_torn_tail_preserves_prefix() {
    let dir = std::env::temp_dir().join(format!(
        "oxide-journal-torn-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);

    let mut writer = JournalWriter::create(&dir, JournalConfig::default())
        .expect("journal create should succeed");

    // Write 5 complete blocks.
    for h in 0..5u64 {
        let block = FinalizedBlock { height: Height::new(h), txs: vec![bank_tx(h, 1)] };
        let payload = encode_block(&block);
        writer.append(&payload).expect("journal append should succeed");
    }
    writer.sync().expect("journal sync should succeed");

    // Corrupt the last record: truncate the segment file to cut the
    // last record's payload short (torn tail).
    let segment_path = dir.join("segment-0.log");
    let content = std::fs::read(&segment_path).expect("segment should be readable");
    // Truncate to cut the last record's payload (remove last 10 bytes).
    let truncated_len = content.len() - 10;
    std::fs::write(&segment_path, &content[..truncated_len])
        .expect("truncated write should succeed");

    let replayed = replay(&dir).expect("replay should succeed");
    // The first 4 records are complete; the 5th is torn.
    assert_eq!(replayed.records.len(), 4, "4 complete records before the torn tail");
    assert!(replayed.truncated_at.is_some(), "torn tail must be reported");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Replay must detect a bad CRC and report `truncated_at` while
/// preserving all complete records before the corruption.
#[test]
fn journal_replay_bad_crc_preserves_prefix() {
    let dir = std::env::temp_dir().join(format!(
        "oxide-journal-crc-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);

    let mut writer = JournalWriter::create(&dir, JournalConfig::default())
        .expect("journal create should succeed");

    // Write 3 complete blocks.
    for h in 0..3u64 {
        let block = FinalizedBlock { height: Height::new(h), txs: vec![bank_tx(h, 1)] };
        let payload = encode_block(&block);
        writer.append(&payload).expect("journal append should succeed");
    }
    writer.sync().expect("journal sync should succeed");

    // Corrupt the 2nd record's CRC (flip a byte in the CRC field).
    let segment_path = dir.join("segment-0.log");
    let mut content = std::fs::read(&segment_path).expect("segment should be readable");
    // The first record: [len 4][crc 4][payload N]. Find the 2nd record's
    // CRC by skipping the first record entirely.
    let first_len = u32::from_le_bytes([content[8], content[9], content[10], content[11]]) as usize;
    let first_record_end = 8 + 8 + first_len; // magic(8) + len(4) + crc(4) + payload
    // The 2nd record's CRC starts at first_record_end + 4 (after its len).
    let crc_offset = first_record_end + 4;
    content[crc_offset] ^= 0xFF; // flip a byte in the CRC
    std::fs::write(&segment_path, &content).expect("corrupted write should succeed");

    let replayed = replay(&dir).expect("replay should succeed");
    // The first record is complete; the 2nd has a bad CRC.
    assert_eq!(replayed.records.len(), 1, "1 complete record before the bad CRC");
    assert!(replayed.truncated_at.is_some(), "bad CRC must be reported");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Replay across multiple segments: write enough blocks to rotate
/// the segment, then replay and verify all records are recovered.
#[test]
fn journal_replay_multiple_segments() {
    let dir = std::env::temp_dir().join(format!(
        "oxide-journal-multi-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);

    // Use a tiny segment size to force rotation.
    let config = JournalConfig { max_segment_bytes: 1024 };
    let mut writer = JournalWriter::create(&dir, config).expect("journal create should succeed");

    // Write 20 blocks (each ~60 bytes, so rotation happens ~every 17 blocks
    // with the 1024-byte segment limit).
    for h in 0..20u64 {
        let block = FinalizedBlock { height: Height::new(h), txs: vec![bank_tx(h, 1)] };
        let payload = encode_block(&block);
        writer.append(&payload).expect("journal append should succeed");
    }
    writer.sync().expect("journal sync should succeed");

    let replayed = replay(&dir).expect("replay should succeed");
    assert!(replayed.truncated_at.is_none(), "journal must be fully intact");
    assert_eq!(replayed.records.len(), 20, "all 20 records across segments must be recovered");

    // Verify each replayed block decodes correctly.
    let executor = build_executor();
    for (i, record) in replayed.records.iter().enumerate() {
        let block = decode_block(&record.payload);
        assert_eq!(block.height, Height::new(u64::try_from(i).unwrap()));
        executor.finalize_block(&block);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Determinism: two identical write sequences produce identical
/// state roots after replay.
#[test]
fn journal_replay_deterministic_state_roots() {
    // Run 1: write and execute.
    let dir1 = std::env::temp_dir().join(format!(
        "oxide-journal-det1-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir1);

    let exec1 = build_executor();
    let mut writer1 = JournalWriter::create(&dir1, JournalConfig::default())
        .expect("journal create should succeed");

    for h in 0..5u64 {
        let block = FinalizedBlock { height: Height::new(h), txs: vec![bank_tx(h, h + 1)] };
        exec1.finalize_block(&block);
        writer1.append(&encode_block(&block)).expect("append should succeed");
    }
    writer1.sync().expect("sync should succeed");
    let roots1: Vec<_> = (0..5).map(|h| exec1.attest_state(Height::new(h)).root).collect();

    // Run 2: write and execute (identical sequence).
    let dir2 = std::env::temp_dir().join(format!(
        "oxide-journal-det2-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir2);

    let exec2 = build_executor();
    let mut writer2 = JournalWriter::create(&dir2, JournalConfig::default())
        .expect("journal create should succeed");

    for h in 0..5u64 {
        let block = FinalizedBlock { height: Height::new(h), txs: vec![bank_tx(h, h + 1)] };
        exec2.finalize_block(&block);
        writer2.append(&encode_block(&block)).expect("append should succeed");
    }
    writer2.sync().expect("sync should succeed");
    let roots2: Vec<_> = (0..5).map(|h| exec2.attest_state(Height::new(h)).root).collect();

    // The two runs must produce identical state roots.
    assert_eq!(roots1, roots2, "identical write sequences must produce identical state roots");

    // Now replay run 1's journal into a fresh executor and verify.
    let replayed = replay(&dir1).expect("replay should succeed");
    let exec3 = build_executor();
    for record in &replayed.records {
        let block = decode_block(&record.payload);
        exec3.finalize_block(&block);
    }
    let roots3: Vec<_> = (0..5).map(|h| exec3.attest_state(Height::new(h)).root).collect();
    assert_eq!(roots1, roots3, "replayed state roots must match original");

    let _ = std::fs::remove_dir_all(&dir1);
    let _ = std::fs::remove_dir_all(&dir2);
}
