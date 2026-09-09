//! EVM transaction receipts — the execution record for each tx.
//!
//! A receipt captures the outcome of a single EVM transaction:
//! status (success/revert), gas used, logs, and (for contract
//! creation) the created address. Receipts are the basis for:
//! - `eth_getTransactionReceipt` RPC.
//! - Block-level receipts root (MPT over receipts).
//! - Logs bloom filter for efficient log queries.
//!
//! # Reference
//!
//! - Ethereum Yellow Paper §4.3.1: the transaction receipt.
//! - EIP-658: receipt status (1 = success, 0 = failure).
//! - reth: `reth-revm` captures `ExecutionResult` into a `Receipt`
//!   type with the same fields.
//!
//! # Bloom filter
//!
//! The logs bloom is a 2048-bit bloom filter over all log addresses
//! and topics in the receipt. It enables `eth_getLogs` to skip
//! blocks whose bloom doesn't match the filter without scanning
//! every log. The bloom is constructed by:
//! - For each log: hash the address and each topic with keccak256.
//! - For each hash, set 3 bits (at positions derived from the first
//!   6 bytes of the hash: 3 pairs of (low, high) 11-bit indices).
//! - OR all bits together into the 2048-bit bloom.

use alloy_primitives::{Address, B256, Log};
use revm::context::result::ExecutionResult;

/// A 2048-bit bloom filter for log indexing.
///
/// Stored as 256 bytes (2048 bits). Used by `eth_getLogs` to
/// efficiently skip blocks that can't contain matching logs.
pub type Bloom = [u8; 256];

/// An EVM transaction receipt.
///
/// Captures the outcome of a single EVM transaction execution.
/// This is the data returned by `eth_getTransactionReceipt` and
/// committed in the block's receipts trie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// The transaction's status: `true` = success, `false` = revert.
    /// EIP-658: replaces the pre-658 "post-transaction state root".
    pub status: bool,
    /// Gas used by this transaction (after refunds, per EIP-3529).
    pub gas_used: u64,
    /// Logs emitted during execution. Empty if the tx reverted.
    pub logs: Vec<Log>,
    /// The 2048-bit bloom filter over `logs`. Used for log indexing.
    pub bloom: Bloom,
    /// The address of the contract created by this tx, if any.
    /// `None` for calls; `Some(addr)` for successful CREATE/CREATE2.
    pub contract_address: Option<Address>,
}

impl Receipt {
    /// Build a receipt from a revm `ExecutionResult`.
    ///
    /// This is the bridge between revm's execution outcome and
    /// Oxide's receipt type. It extracts:
    /// - Status (success/revert/halt → false).
    /// - Gas used (`tx_gas_used`).
    /// - Logs (copied from the execution result).
    /// - Contract address (for successful CREATE).
    /// - Bloom filter (computed from logs).
    ///
    /// # Arguments
    ///
    /// - `result`: the revm execution result.
    #[must_use]
    pub fn from_execution_result(result: &ExecutionResult) -> Self {
        let status = result.is_success();
        let gas_used = result.tx_gas_used();
        let contract_address = result.created_address();

        let logs: Vec<Log> = result.logs().to_vec();
        let bloom = bloom_from_logs(&logs);

        Self { status, gas_used, logs, bloom, contract_address }
    }

    /// The cumulative gas used across all receipts in a block.
    ///
    /// This is the sum of `gas_used` for all receipts up to and
    /// including this one. Used in `eth_getBlockReceipts`.
    #[must_use]
    pub fn cumulative_gas(receipts: &[Receipt]) -> Vec<u64> {
        let mut cumulative = 0u64;
        receipts
            .iter()
            .map(|r| {
                cumulative = cumulative.saturating_add(r.gas_used);
                cumulative
            })
            .collect()
    }
}

/// Compute the 2048-bit bloom filter from a list of logs.
///
/// For each log, we hash the address and each topic with keccak256.
/// For each hash, we extract 3 bit-pairs (9-bit indices into the
/// 2048-bit bloom) and set the corresponding bits.
///
/// Reference: Ethereum Yellow Paper Appendix D, `BLOOM` function.
#[must_use]
pub fn bloom_from_logs(logs: &[Log]) -> Bloom {
    let mut bloom = [0u8; 256];

    for log in logs {
        bloom_add(&mut bloom, log.address.as_slice());
        for topic in log.topics() {
            bloom_add(&mut bloom, topic.as_slice());
        }
    }

    bloom
}

/// Add a keccak-256 hash to the bloom filter.
///
/// Sets 3 bits in the 2048-bit bloom at positions derived from the
/// first 6 bytes of the hash. Each pair of bytes gives a 11-bit
/// index (0..=2047) into the bloom.
fn bloom_add(bloom: &mut Bloom, data: &[u8]) {
    let hash = alloy_primitives::keccak256(data);
    let hash_bytes = hash.as_slice();

    // 3 bit-pairs: (byte[0], byte[1]), (byte[2], byte[3]), (byte[4], byte[5]).
    // Each pair → 11-bit index: (high << 3) | (low >> 5).
    for i in 0..3 {
        let high = hash_bytes[i * 2] as usize;
        let low = hash_bytes[i * 2 + 1] as usize;
        let bit_index = ((high & 0x07) << 8) | low;
        let bit_index = bit_index & 0x7FF; // 11 bits → 0..=2047

        // Set bit `bit_index` in the 2048-bit bloom.
        let byte_index = bit_index / 8;
        let bit_in_byte = bit_index % 8;
        bloom[byte_index] |= 1 << bit_in_byte;
    }
}

/// Check if a bloom filter might contain a log matching the given
/// address and topics.
///
/// Returns `true` if the bloom *might* contain a matching log
/// (false positives possible). Returns `false` if the bloom
/// definitely does not contain a matching log (no false negatives).
///
/// This is the basis for `eth_getLogs` block-level filtering.
#[must_use]
pub fn bloom_contains(bloom: &Bloom, address: &[u8; 20], topics: &[B256]) -> bool {
    // Check the address.
    if !bloom_check(bloom, address) {
        return false;
    }
    // Check each topic.
    for topic in topics {
        if !bloom_check(bloom, topic.as_slice()) {
            return false;
        }
    }
    true
}

/// Check if a single entry is in the bloom.
fn bloom_check(bloom: &Bloom, data: &[u8]) -> bool {
    let hash = alloy_primitives::keccak256(data);
    let hash_bytes = hash.as_slice();

    for i in 0..3 {
        let high = hash_bytes[i * 2] as usize;
        let low = hash_bytes[i * 2 + 1] as usize;
        let bit_index = ((high & 0x07) << 8) | low;
        let bit_index = bit_index & 0x7FF;

        let byte_index = bit_index / 8;
        let bit_in_byte = bit_index % 8;
        if (bloom[byte_index] & (1 << bit_in_byte)) == 0 {
            return false;
        }
    }
    true
}

/// Compute the receipts root for a block.
///
/// The receipts root is a Merkle-Patricia Trie over the receipts,
/// keyed by transaction index, with RLP-encoded receipt values.
/// This matches Ethereum's `receiptsRoot` in the block header.
///
/// # Arguments
///
/// - `receipts`: the receipts for all transactions in the block,
///   in transaction-index order.
///
/// # Returns
///
/// The 32-byte receipts root. For zero receipts, returns `EMPTY_ROOT`.
///
/// # Panics
///
/// Panics if a receipt's RLP encoding exceeds 255 bytes for the list
/// header (impossible for valid receipts with ≤4 topics and ≤256
/// bytes of log data per log).
#[must_use]
pub fn receipts_root(receipts: &[Receipt]) -> B256 {
    if receipts.is_empty() {
        return alloy_trie::EMPTY_ROOT_HASH;
    }

    // Pre-compute cumulative gas for each receipt index.
    let cumulative_gases = Receipt::cumulative_gas(receipts);

    // Each receipt is RLP-encoded as:
    // [status_byte, cumulative_gas_used, bloom, logs]
    // For the trie, the key is the transaction index (RLP-encoded).
    // We use alloy-trie's `ordered_trie_root_with_encoder` which
    // handles the index keying.
    alloy_trie::root::ordered_trie_root_with_encoder(receipts, |receipt, buf| {
        use alloy_rlp::Encodable;
        // RLP-encode the receipt as a list:
        // [status, cumulative_gas, bloom, logs]
        // This matches Ethereum's pre-EIP-2718 receipt encoding.
        // Typed transactions (EIP-2718) prefix the receipt with the
        // tx type byte; we'll add that when we support typed tx
        // receipts in a follow-up.
        let status_byte: u8 = u8::from(receipt.status);

        // Find this receipt's index to get its cumulative gas.
        let idx = receipts.iter().position(|r| std::ptr::eq(r, receipt)).unwrap_or(0);
        let cumulative = cumulative_gases[idx];

        // Encode the logs as an RLP list into a temporary buffer.
        let mut logs_rlp = Vec::new();
        alloy_rlp::encode_list(&receipt.logs, &mut logs_rlp);

        // Compute the RLP list body length:
        // status (1 byte) + cumulative (variable) + bloom (256) + logs (variable)
        let cumulative_len = alloy_rlp::Encodable::length(&cumulative);
        let list_len = 1 + cumulative_len + 256 + logs_rlp.len();

        // RLP list header.
        if list_len < 56 {
            let suffix = u8::try_from(list_len).expect("list_len < 56");
            buf.push(0xc0 + suffix);
        } else {
            // Long list: 0xf7 + length_of_length bytes.
            let len_bytes = list_len.to_be_bytes();
            let leading_zeros = len_bytes.iter().take_while(|&&b| b == 0).count();
            let trimmed = &len_bytes[leading_zeros..];
            let suffix = u8::try_from(trimmed.len()).expect("len bytes <= 8");
            buf.push(0xf7 + suffix);
            buf.extend_from_slice(trimmed);
        }

        status_byte.encode(buf);
        cumulative.encode(buf);
        buf.extend_from_slice(&receipt.bloom);
        buf.extend_from_slice(&logs_rlp);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, Bytes, Log, LogData};

    /// A receipt with no logs should have an all-zero bloom.
    #[test]
    fn empty_logs_produce_zero_bloom() {
        let receipt = Receipt {
            status: true,
            gas_used: 21_000,
            logs: vec![],
            bloom: [0u8; 256],
            contract_address: None,
        };
        let bloom = bloom_from_logs(&receipt.logs);
        assert!(bloom.iter().all(|&b| b == 0));
    }

    /// A log with an address should set bits in the bloom.
    #[test]
    fn log_sets_bloom_bits() {
        let log = Log {
            address: Address::from_slice(&[0x42; 20]),
            data: LogData::new(vec![], Bytes::new()).unwrap(),
        };
        let bloom = bloom_from_logs(&[log]);
        // At least one bit must be set.
        assert!(bloom.iter().any(|&b| b != 0));
    }

    /// A bloom that contains a log address should return true for
    /// `bloom_contains`.
    #[test]
    fn bloom_contains_returns_true_for_present_address() {
        let addr_bytes = [0x42u8; 20];
        let log = Log {
            address: Address::from(addr_bytes),
            data: LogData::new(vec![], Bytes::new()).unwrap(),
        };
        let bloom = bloom_from_logs(&[log]);
        assert!(bloom_contains(&bloom, &addr_bytes, &[]));
    }

    /// A bloom that doesn't contain an address should return false.
    #[test]
    fn bloom_contains_returns_false_for_absent_address() {
        let addr_bytes = [0x42u8; 20];
        let log = Log {
            address: Address::from(addr_bytes),
            data: LogData::new(vec![], Bytes::new()).unwrap(),
        };
        let bloom = bloom_from_logs(&[log]);
        let absent_addr = [0x99u8; 20];
        // Very likely false (bloom has false positives but this is
        // a different address with high probability of not matching).
        assert!(!bloom_contains(&bloom, &absent_addr, &[]));
    }

    /// Cumulative gas should be the running sum.
    #[test]
    fn cumulative_gas_is_running_sum() {
        let receipts = vec![
            Receipt {
                status: true,
                gas_used: 21_000,
                logs: vec![],
                bloom: [0u8; 256],
                contract_address: None,
            },
            Receipt {
                status: true,
                gas_used: 30_000,
                logs: vec![],
                bloom: [0u8; 256],
                contract_address: None,
            },
            Receipt {
                status: false,
                gas_used: 50_000,
                logs: vec![],
                bloom: [0u8; 256],
                contract_address: None,
            },
        ];
        let cumulative = Receipt::cumulative_gas(&receipts);
        assert_eq!(cumulative, vec![21_000, 51_000, 101_000]);
    }

    /// A log with a topic should set bits for both address and topic.
    #[test]
    fn log_with_topic_sets_bloom_bits() {
        let topic = B256::from_slice(&[0xAA; 32]);
        let log = Log {
            address: Address::from_slice(&[0x42; 20]),
            data: LogData::new(vec![topic], Bytes::new()).unwrap(),
        };
        let bloom = bloom_from_logs(&[log]);
        assert!(bloom.iter().any(|&b| b != 0));
        // The bloom should contain the topic.
        assert!(bloom_contains(&bloom, &[0x42; 20], &[topic]));
    }

    /// Empty receipts should produce the empty root.
    #[test]
    fn empty_receipts_produce_empty_root() {
        let root = receipts_root(&[]);
        assert_eq!(root, alloy_trie::EMPTY_ROOT_HASH);
    }

    /// Non-empty receipts should produce a non-empty root.
    #[test]
    fn non_empty_receipts_produce_non_empty_root() {
        let receipts = vec![Receipt {
            status: true,
            gas_used: 21_000,
            logs: vec![],
            bloom: [0u8; 256],
            contract_address: None,
        }];
        let root = receipts_root(&receipts);
        assert_ne!(root, alloy_trie::EMPTY_ROOT_HASH);
    }
}
