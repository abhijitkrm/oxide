//! EVM state persistence — serialization between revm's `CacheDB` and
//! Oxide's `StorageBackend`.
//!
//! # Key scheme
//!
//! Each EVM account (balance, nonce, code, storage) is stored as a
//! single value under a 32-byte key:
//!
//! ```text
//! key = [0x01][address: 20B][0x00: 11B]   (32 bytes total)
//! ```
//!
//! The `0x01` namespace prefix lets `range([0x01])` enumerate all
//! EVM accounts in one scan — used by `load_from_storage` on
//! construction. A single value per account avoids the 32-byte key
//! length limit (address 20B + slot 32B = 52B doesn't fit in 32B).
//!
//! Two more namespaces hold the RPC-serving window:
//!
//! - `0x02` — sealed `ExecutedBlock` records (`eth_getBlockBy*`,
//!   receipts, logs, `debug_trace*`), keyed by height so `range`
//!   returns them in order. The tx/hash indexes are rebuilt on
//!   load, not persisted.
//! - `0x03` — per-height undo blobs for the versioned-state window
//!   (`versioned.rs`), so historical reads survive restart.
//!
//! Both windows are pruned by the same retention capacity; eviction
//! emits `Delete` ops in the same `apply_batch` as the new records,
//! so durable storage never outlives the in-memory window.
//!
//! # Value format
//!
//! ```text
//! [balance:  32B big-endian U256]
//! [nonce:     8B big-endian u64]
//! [code_hash: 32B]
//! [code_len:  4B big-endian u32]
//! [code:      code_len bytes]
//! [n_slots:   4B big-endian u32]
//! [slot_0:    32B][value_0: 32B]
//! ...
//! [slot_N:    32B][value_N: 32B]
//! ```
//!
//! All fields are fixed-width big-endian for deterministic
//! serialization (two validators with the same state must produce
//! byte-identical values — consensus requirement).

use primitives::{Address, Hash};

use crate::history::{ExecutedBlock, StoredTx};
use crate::receipts::Receipt;
use crate::trace::CallFrame;
use crate::tx::TxAuthorization;
use crate::versioned::{BlockUndo, UndoAccount};

/// Namespace prefix for EVM account keys.
pub(crate) const NS_ACCOUNT: u8 = 0x01;

/// Namespace prefix for sealed `ExecutedBlock` records.
///
/// Key format: `[0x02][height: 8B big-endian][0x00: 23B]` — 32
/// bytes, height-major so `range([0x02])` returns blocks in
/// ascending order. The `hash_index`/`tx_index` maps are *not*
/// persisted; they are rebuilt from the records on load.
pub(crate) const NS_BLOCK: u8 = 0x02;

/// Namespace prefix for per-height undo blobs.
///
/// Key format: `[0x03][height: 8B big-endian][0x00: 23B]`. The
/// value holds every `(address, pre-block account)` pair captured
/// during that height — restoring them rebuilds the versioned
/// index so historical reads survive restart. Every executed
/// height writes a blob (possibly empty) so the retention floor
/// is preserved exactly.
pub(crate) const NS_UNDO: u8 = 0x03;

/// Namespace prefix for module metadata — the schema version the
/// stored state was written at. Read on load so `migrate` knows
/// what it's migrating *from*; rewritten on flush so the stored
/// version always matches the binary that last wrote state.
pub(crate) const NS_META: u8 = 0x04;

/// The fixed key for the stored schema version:
/// `[0x04][0x00: 31B]` — a single slot, value is `u32 LE`.
/// Absent on backends written before versioning = v1.
pub(crate) fn state_version_key() -> Hash {
    let mut key = [0u8; Hash::LEN];
    key[0] = NS_META;
    Hash(key)
}

/// Build the 32-byte storage key for an EVM account.
///
/// Format: `[0x01][address: 20B][0x00: 11B]` = 32 bytes.
pub(crate) fn account_key(addr: &Address) -> Hash {
    let mut key = [0u8; Hash::LEN];
    key[0] = NS_ACCOUNT;
    key[1..21].copy_from_slice(&addr.0);
    // Bytes 21..32 are zero-padded (unused space in the 32-byte key).
    Hash(key)
}

/// The namespace prefix for `range` queries that enumerate all
/// EVM accounts.
pub(crate) fn account_prefix() -> [u8; 1] {
    [NS_ACCOUNT]
}

/// Extract the 20-byte address from a 32-byte account key.
///
/// Returns `None` if the key doesn't have the `0x01` namespace
/// prefix (defensive — should never happen for keys written by
/// `account_key`).
pub(crate) fn key_to_address(key: &Hash) -> Option<Address> {
    if key.0[0] != NS_ACCOUNT {
        return None;
    }
    let mut addr = [0u8; Address::LEN];
    addr.copy_from_slice(&key.0[1..21]);
    Some(Address(addr))
}

/// Serialize an EVM account into a flat byte vector.
///
/// See the module docs for the value format.
pub(crate) fn serialize_account(
    balance: revm::primitives::U256,
    nonce: u64,
    code_hash: revm::primitives::B256,
    code: &[u8],
    storage: &[(revm::primitives::U256, revm::primitives::U256)],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(76 + code.len() + storage.len() * 64);
    out.extend_from_slice(&balance.to_be_bytes::<32>());
    out.extend_from_slice(&nonce.to_be_bytes());
    out.extend_from_slice(code_hash.as_slice());
    out.extend_from_slice(&(u32::try_from(code.len()).unwrap_or(u32::MAX)).to_be_bytes());
    out.extend_from_slice(code);
    out.extend_from_slice(&(u32::try_from(storage.len()).unwrap_or(u32::MAX)).to_be_bytes());
    for (slot, value) in storage {
        out.extend_from_slice(&slot.to_be_bytes::<32>());
        out.extend_from_slice(&value.to_be_bytes::<32>());
    }
    out
}

/// Deserialize an EVM account from a byte slice.
///
/// Returns `None` if the data is malformed (too short, truncated
/// code or storage). The caller treats `None` as "skip this entry"
/// during `load_from_storage` — a corrupted entry is a storage bug,
/// not a consensus fault.
pub(crate) struct DeserializedAccount {
    pub balance: revm::primitives::U256,
    pub nonce: u64,
    pub code_hash: revm::primitives::B256,
    pub code: Vec<u8>,
    pub storage: Vec<(revm::primitives::U256, revm::primitives::U256)>,
}

pub(crate) fn deserialize_account(data: &[u8]) -> Option<DeserializedAccount> {
    if data.len() < 76 {
        return None;
    }
    let balance = revm::primitives::U256::from_be_bytes(<[u8; 32]>::try_from(&data[0..32]).ok()?);
    let nonce = u64::from_be_bytes(data[32..40].try_into().ok()?);
    let code_hash = revm::primitives::B256::from_slice(&data[40..72]);
    let code_len = u32::from_be_bytes(data[72..76].try_into().ok()?) as usize;
    if data.len() < 76 + code_len + 4 {
        return None;
    }
    let code = data[76..76 + code_len].to_vec();
    let n_slots_offset = 76 + code_len;
    let n_slots =
        u32::from_be_bytes(data[n_slots_offset..n_slots_offset + 4].try_into().ok()?) as usize;
    let storage_offset = n_slots_offset + 4;
    if data.len() < storage_offset + n_slots * 64 {
        return None;
    }
    let mut storage = Vec::with_capacity(n_slots);
    let mut off = storage_offset;
    for _ in 0..n_slots {
        let slot =
            revm::primitives::U256::from_be_bytes(<[u8; 32]>::try_from(&data[off..off + 32]).ok()?);
        let value = revm::primitives::U256::from_be_bytes(
            <[u8; 32]>::try_from(&data[off + 32..off + 64]).ok()?,
        );
        storage.push((slot, value));
        off += 64;
    }
    Some(DeserializedAccount { balance, nonce, code_hash, code, storage })
}

/// Deserialize an EVM account with snapshot-strictness — the checks
/// [`deserialize_account`] skips because a local storage corruption
/// is a skip-and-continue bug, but a *snapshot* is consensus state:
/// bytes that don't decode to exactly the encoder's output must be
/// rejected, not papered over.
///
/// Additional invariants over the lenient decoder:
///
/// - **Exact length**: no trailing bytes after the last slot pair.
/// - **Sorted, unique storage slots**: `account_flush_ops` sorts
///   slots ascending; any other order (or a duplicate) is not the
///   encoder's output.
/// - **`code_hash` binds the code bytes**: the MPT commits the hash,
///   not the code — a snapshot whose code doesn't match its hash
///   would install bytecode that diverges from the committed root
///   while verifying clean. Empty code must carry `KECCAK_EMPTY`
///   (the EOA convention); non-empty code must hash to `code_hash`.
pub(crate) fn deserialize_account_strict(data: &[u8]) -> Option<DeserializedAccount> {
    let account = deserialize_account(data)?;
    // Recompute the expected total length: 76 header bytes + code +
    // 4 count bytes + 64 bytes per slot. Trailing bytes are rejected.
    let expected = 76 + account.code.len() + 4 + account.storage.len() * 64;
    if data.len() != expected {
        return None;
    }
    // Slots are written in ascending order — enforce it so a
    // reordered or duplicated slot can't alias into the trie.
    if account.storage.windows(2).any(|w| w[0].0 >= w[1].0) {
        return None;
    }
    // The encoder never emits a zero value — Ethereum's
    // sparse-storage rule makes zero and absent identical, so a
    // zero entry is by definition not the encoder's output.
    if account.storage.iter().any(|(_, value)| value.is_zero()) {
        return None;
    }
    if account.code.is_empty() {
        if account.code_hash != crate::trie::KECCAK_EMPTY {
            return None;
        }
    } else if account.code_hash != alloy_primitives::keccak256(&account.code) {
        return None;
    }
    Some(account)
}

/// Build the 32-byte storage key for a sealed block record.
///
/// Format: `[0x02][height: 8B BE][0x00: 23B]` — height-major so a
/// `range([0x02])` scan returns blocks in ascending height order.
pub(crate) fn block_key(height: u64) -> Hash {
    let mut key = [0u8; Hash::LEN];
    key[0] = NS_BLOCK;
    key[1..9].copy_from_slice(&height.to_be_bytes());
    Hash(key)
}

/// Build the 32-byte storage key for a height's undo blob.
///
/// Format: `[0x03][height: 8B BE][0x00: 23B]`.
pub(crate) fn undo_key(height: u64) -> Hash {
    let mut key = [0u8; Hash::LEN];
    key[0] = NS_UNDO;
    key[1..9].copy_from_slice(&height.to_be_bytes());
    Hash(key)
}

/// The namespace prefix for `range` queries that enumerate all
/// sealed block records.
pub(crate) fn block_prefix() -> [u8; 1] {
    [NS_BLOCK]
}

/// The namespace prefix for `range` queries that enumerate all
/// undo blobs.
pub(crate) fn undo_prefix() -> [u8; 1] {
    [NS_UNDO]
}

/// Extract the block height from a `0x02`/`0x03` namespaced key.
pub(crate) fn key_to_height(key: &Hash) -> Option<u64> {
    if key.0[0] != NS_BLOCK && key.0[0] != NS_UNDO {
        return None;
    }
    Some(u64::from_be_bytes(key.0[1..9].try_into().ok()?))
}

use super::{Arc, CacheDB, EmptyDB, EvmModule, Module, alloy_primitives_address, fee, persist};

// ── Cursor reader ───────────────────────────────────────────────
//
// The account codec above hand-rolls offsets because the layout is
// flat. Block records nest (tx → logs → frames), so a cursor keeps
// the decode arithmetic auditable: every field goes through `take`,
// which bounds-checks once.

/// Bounds-checked cursor over a byte slice. All reads are
/// big-endian; any overrun returns `None` and the caller treats the
/// record as malformed (storage bug — skip the entry).
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Consume `n` bytes, or `None` if fewer remain.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.data.len() - self.pos < n {
            return None;
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn bool(&mut self) -> Option<bool> {
        Some(self.u8()? != 0)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    fn u128(&mut self) -> Option<u128> {
        Some(u128::from_be_bytes(self.take(16)?.try_into().ok()?))
    }

    fn u256(&mut self) -> Option<revm::primitives::U256> {
        Some(revm::primitives::U256::from_be_bytes(<[u8; 32]>::try_from(self.take(32)?).ok()?))
    }

    fn b256(&mut self) -> Option<revm::primitives::B256> {
        Some(revm::primitives::B256::from_slice(self.take(32)?))
    }

    fn address(&mut self) -> Option<revm::primitives::Address> {
        Some(revm::primitives::Address::from_slice(self.take(20)?))
    }

    /// `u32`-length-prefixed byte vector.
    fn bytes(&mut self) -> Option<Vec<u8>> {
        let len = self.u32()? as usize;
        Some(self.take(len)?.to_vec())
    }

    /// `u32`-length-prefixed UTF-8 string.
    fn string(&mut self) -> Option<String> {
        String::from_utf8(self.bytes()?).ok()
    }

    /// `true` when the cursor is exactly consumed — callers check
    /// this so trailing garbage marks the record malformed.
    fn at_end(&self) -> bool {
        self.pos == self.data.len()
    }
}

/// Emit helpers — every field is fixed-width big-endian or
/// `u32`-length-prefixed, matching the account format above.
fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

fn put_bool(out: &mut Vec<u8>, v: bool) {
    out.push(u8::from(v));
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u128(out: &mut Vec<u8>, v: u128) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u256(out: &mut Vec<u8>, v: revm::primitives::U256) {
    out.extend_from_slice(&v.to_be_bytes::<32>());
}

fn put_b256(out: &mut Vec<u8>, v: revm::primitives::B256) {
    out.extend_from_slice(v.as_slice());
}

fn put_address(out: &mut Vec<u8>, v: revm::primitives::Address) {
    out.extend_from_slice(v.as_slice());
}

fn put_bytes(out: &mut Vec<u8>, v: &[u8]) {
    put_u32(out, u32::try_from(v.len()).unwrap_or(u32::MAX));
    out.extend_from_slice(v);
}

fn put_string(out: &mut Vec<u8>, v: &str) {
    put_bytes(out, v.as_bytes());
}

/// Option flag + value pattern: `0` = absent, `1` = present
/// followed by `inner` bytes.
fn put_opt<T>(out: &mut Vec<u8>, v: Option<&T>, mut inner: impl FnMut(&mut Vec<u8>, &T)) {
    match v {
        None => put_u8(out, 0),
        Some(val) => {
            put_u8(out, 1);
            inner(out, val);
        }
    }
}

/// Decode a flag-prefixed optional field. The return is
/// `Option<Option<T>>` by necessity: the outer `Option` signals
/// malformation (`None` aborts the record), the inner is the
/// field's own optionality.
#[allow(clippy::option_option)]
fn read_opt<'a, T>(
    r: &mut Reader<'a>,
    inner: impl FnOnce(&mut Reader<'a>) -> Option<T>,
) -> Option<Option<T>> {
    match r.u8()? {
        0 => Some(None),
        _ => Some(inner(r)),
    }
}

// ── ExecutedBlock codec ─────────────────────────────────────────
//
// Layout (all big-endian):
//
// ```text
// hash(32) parent(32) number(8) timestamp(8) gas_used(8)
// gas_limit(8) base_fee(8) coinbase(20) bloom(256) tx_root(32)
// receipts_root(32) state_root(32)
// n_txs(4) then per StoredTx:
//   hash(32) tx_index(4) from(20) to_flag(1) [to(20)] nonce(8)
//   gas_limit(8) gas_price(16) max_priority(16) value(32)
//   input(u32+bytes) tx_type(1)
//   n_auths(4) then per TxAuthorization:
//     chain_id(32) address(20) nonce(8) recid(1) r(32) s(32)
//   v(32) r(32) s(32)
// n_receipts(4) then per Receipt:
//   tx_type(1) status(1) gas_used(8) contract_flag(1) [contract(20)]
//   bloom(256) n_logs(4) then per log:
//     address(20) n_topics(1) topics(32 each) data(u32+bytes)
// n_traces(4) then per Option<CallFrame>:
//   present(1) then per CallFrame (recursive):
//     kind(1) from(20) to_flag(1) [to(20)] value(32)
//     gas_limit(8) gas_used(8) input(u32+bytes) output(u32+bytes)
//     error_flag(1) [u32+utf8] rr_flag(1) [u32+utf8]
//     n_calls(4) children…
// ```

/// Serialize a sealed block record into the `0x02` value format.
pub(crate) fn serialize_block(block: &ExecutedBlock) -> Vec<u8> {
    let mut out = Vec::new();
    put_b256(&mut out, block.hash);
    put_b256(&mut out, block.parent_hash);
    put_u64(&mut out, block.number);
    put_u64(&mut out, block.timestamp);
    put_u64(&mut out, block.gas_used);
    put_u64(&mut out, block.gas_limit);
    put_u64(&mut out, block.base_fee);
    put_address(&mut out, block.coinbase);
    out.extend_from_slice(&block.bloom);
    put_b256(&mut out, block.tx_root);
    put_b256(&mut out, block.receipts_root);
    put_b256(&mut out, block.state_root);

    put_u32(&mut out, u32::try_from(block.txs.len()).unwrap_or(u32::MAX));
    for tx in &block.txs {
        serialize_stored_tx(&mut out, tx);
    }
    put_u32(&mut out, u32::try_from(block.receipts.len()).unwrap_or(u32::MAX));
    for receipt in &block.receipts {
        serialize_receipt(&mut out, receipt);
    }
    put_u32(&mut out, u32::try_from(block.traces.len()).unwrap_or(u32::MAX));
    for trace in &block.traces {
        put_opt(&mut out, trace.as_ref(), serialize_frame);
    }
    out
}

fn serialize_stored_tx(out: &mut Vec<u8>, tx: &StoredTx) {
    put_b256(out, tx.hash);
    put_u32(out, tx.tx_index);
    put_address(out, tx.from);
    put_opt(out, tx.to.as_ref(), |o, a| put_address(o, *a));
    put_u64(out, tx.nonce);
    put_u64(out, tx.gas_limit);
    put_u128(out, tx.gas_price);
    put_u128(out, tx.max_priority_fee_per_gas);
    put_u256(out, tx.value);
    put_bytes(out, &tx.input);
    put_u8(out, tx.tx_type);
    put_u32(out, u32::try_from(tx.authorization_list.len()).unwrap_or(u32::MAX));
    for auth in &tx.authorization_list {
        put_u256(out, auth.chain_id);
        put_address(out, auth.address);
        put_u64(out, auth.nonce);
        put_u8(out, auth.sig.recid.as_u8());
        put_u256(out, auth.sig.r);
        put_u256(out, auth.sig.s);
    }
    put_u256(out, tx.v);
    put_u256(out, tx.r);
    put_u256(out, tx.s);
}

fn serialize_receipt(out: &mut Vec<u8>, receipt: &Receipt) {
    put_u8(out, receipt.tx_type);
    put_bool(out, receipt.status);
    put_u64(out, receipt.gas_used);
    put_opt(out, receipt.contract_address.as_ref(), |o, a| put_address(o, *a));
    out.extend_from_slice(&receipt.bloom);
    put_u32(out, u32::try_from(receipt.logs.len()).unwrap_or(u32::MAX));
    for log in &receipt.logs {
        put_address(out, log.address);
        let topics = log.topics();
        // Topics are capped at 4 by the EVM; a u8 count is enough.
        put_u8(out, u8::try_from(topics.len()).unwrap_or(u8::MAX));
        for t in topics {
            put_b256(out, *t);
        }
        put_bytes(out, &log.data.data);
    }
}

/// geth callTracer `type` strings ↔ single-byte tags: CALL=0,
/// CALLCODE=1, DELEGATECALL=2, STATICCALL=3, CREATE=4, CREATE2=5,
/// CUSTOMCREATE=6.
fn frame_kind_tag(kind: &str) -> u8 {
    match kind {
        "CALLCODE" => 1,
        "DELEGATECALL" => 2,
        "STATICCALL" => 3,
        "CREATE" => 4,
        "CREATE2" => 5,
        "CUSTOMCREATE" => 6,
        // "CALL" and unknown kinds → 0. Unknowns shouldn't exist (the
        // recorder only emits the set above); tag them as CALL so the
        // record stays deserializable — a bad tag is worse than a
        // wrong label.
        _ => 0,
    }
}

fn frame_kind_str(tag: u8) -> Option<&'static str> {
    Some(match tag {
        0 => "CALL",
        1 => "CALLCODE",
        2 => "DELEGATECALL",
        3 => "STATICCALL",
        4 => "CREATE",
        5 => "CREATE2",
        6 => "CUSTOMCREATE",
        _ => return None,
    })
}

fn serialize_frame(out: &mut Vec<u8>, f: &CallFrame) {
    put_u8(out, frame_kind_tag(f.kind));
    put_address(out, f.from);
    put_opt(out, f.to.as_ref(), |o, a| put_address(o, *a));
    put_u256(out, f.value);
    put_u64(out, f.gas_limit);
    put_u64(out, f.gas_used);
    put_bytes(out, &f.input);
    put_bytes(out, &f.output);
    put_opt(out, f.error.as_ref(), |o, s| put_string(o, s));
    put_opt(out, f.revert_reason.as_ref(), |o, s| put_string(o, s));
    put_u32(out, u32::try_from(f.calls.len()).unwrap_or(u32::MAX));
    for child in &f.calls {
        serialize_frame(out, child);
    }
}

/// Deserialize an `ExecutedBlock` — inverse of [`serialize_block`].
///
/// `None` on any malformation: truncated fields, trailing garbage,
/// or mismatched vector lengths. The record's internal counts are
/// trusted for lengths but every read is bounds-checked.
pub(crate) fn deserialize_block(data: &[u8]) -> Option<ExecutedBlock> {
    let mut r = Reader::new(data);
    let hash = r.b256()?;
    let parent_hash = r.b256()?;
    let number = r.u64()?;
    let timestamp = r.u64()?;
    let gas_used = r.u64()?;
    let gas_limit = r.u64()?;
    let base_fee = r.u64()?;
    let coinbase = r.address()?;
    let bloom: [u8; 256] = r.take(256)?.try_into().ok()?;
    let tx_root = r.b256()?;
    let receipts_root = r.b256()?;
    let state_root = r.b256()?;

    let n_txs = r.u32()? as usize;
    let mut txs = Vec::with_capacity(n_txs);
    for _ in 0..n_txs {
        txs.push(deserialize_stored_tx(&mut r)?);
    }
    let n_receipts = r.u32()? as usize;
    let mut receipts = Vec::with_capacity(n_receipts);
    for _ in 0..n_receipts {
        receipts.push(deserialize_receipt(&mut r)?);
    }
    let n_traces = r.u32()? as usize;
    let mut traces = Vec::with_capacity(n_traces);
    for _ in 0..n_traces {
        traces.push(read_opt(&mut r, deserialize_frame)?);
    }
    if !r.at_end() {
        return None;
    }
    Some(ExecutedBlock {
        hash,
        parent_hash,
        number,
        timestamp,
        gas_used,
        gas_limit,
        base_fee,
        coinbase,
        bloom,
        tx_root,
        receipts_root,
        state_root,
        txs,
        receipts,
        traces,
    })
}

fn deserialize_stored_tx(r: &mut Reader<'_>) -> Option<StoredTx> {
    let hash = r.b256()?;
    let tx_index = r.u32()?;
    let from = r.address()?;
    let to = read_opt(r, Reader::address)?;
    let nonce = r.u64()?;
    let gas_limit = r.u64()?;
    let gas_price = r.u128()?;
    let max_priority_fee_per_gas = r.u128()?;
    let value = r.u256()?;
    let input = r.bytes()?;
    let tx_type = r.u8()?;
    let n_auths = r.u32()? as usize;
    let mut authorization_list = Vec::with_capacity(n_auths);
    for _ in 0..n_auths {
        let chain_id = r.u256()?;
        let address = r.address()?;
        let nonce = r.u64()?;
        let recid = crypto::secp::RecoveryId::try_from_u8(r.u8()?).ok()?;
        let sig_r = r.u256()?;
        let sig_s = r.u256()?;
        authorization_list.push(TxAuthorization {
            chain_id,
            address,
            nonce,
            sig: crate::tx::TxSignature { r: sig_r, s: sig_s, recid },
        });
    }
    let v = r.u256()?;
    let sig_r = r.u256()?;
    let sig_s = r.u256()?;
    Some(StoredTx {
        hash,
        tx_index,
        from,
        to,
        nonce,
        gas_limit,
        gas_price,
        max_priority_fee_per_gas,
        value,
        input,
        tx_type,
        authorization_list,
        v,
        r: sig_r,
        s: sig_s,
    })
}

fn deserialize_receipt(r: &mut Reader<'_>) -> Option<Receipt> {
    let tx_type = r.u8()?;
    let status = r.bool()?;
    let gas_used = r.u64()?;
    let contract_address = read_opt(r, Reader::address)?;
    let bloom: [u8; 256] = r.take(256)?.try_into().ok()?;
    let n_logs = r.u32()? as usize;
    let mut logs = Vec::with_capacity(n_logs);
    for _ in 0..n_logs {
        let address = r.address()?;
        let n_topics = r.u8()? as usize;
        let mut topics = Vec::with_capacity(n_topics);
        for _ in 0..n_topics {
            topics.push(r.b256()?);
        }
        let data = r.bytes()?;
        logs.push(revm::primitives::Log::new_unchecked(
            address,
            topics,
            revm::primitives::Bytes::from(data),
        ));
    }
    Some(Receipt { tx_type, status, gas_used, logs, bloom, contract_address })
}

fn deserialize_frame(r: &mut Reader<'_>) -> Option<CallFrame> {
    let kind = frame_kind_str(r.u8()?)?;
    let from = r.address()?;
    let to = read_opt(r, Reader::address)?;
    let value = r.u256()?;
    let gas_limit = r.u64()?;
    let gas_used = r.u64()?;
    let input = r.bytes()?;
    let output = r.bytes()?;
    let error = read_opt(r, Reader::string)?;
    let revert_reason = read_opt(r, Reader::string)?;
    let n_calls = r.u32()? as usize;
    let mut calls = Vec::with_capacity(n_calls);
    for _ in 0..n_calls {
        calls.push(deserialize_frame(r)?);
    }
    Some(CallFrame {
        kind,
        from,
        to,
        value,
        gas_limit,
        gas_used,
        input: revm::primitives::Bytes::from(input),
        output: revm::primitives::Bytes::from(output),
        error,
        revert_reason,
        calls,
    })
}

// ── BlockUndo codec ─────────────────────────────────────────────
//
// Layout:
//
// ```text
// n_accounts(4) then per entry:
//   address(20) exists(1)
//   if exists: balance(32) nonce(8) code_hash(32)
//              n_slots(4) then per slot: key(32) value(32)
// ```
//
// `exists = 0` encodes "the account did not exist before this
// block" — the `Option<UndoAccount>` in the in-memory map. Storage
// is sorted by key for deterministic bytes.

/// Serialize one height's undo accumulator into the `0x03` format.
pub(crate) fn serialize_undo(undo: &BlockUndo) -> Vec<u8> {
    let mut out = Vec::new();
    put_u32(&mut out, u32::try_from(undo.accounts.len()).unwrap_or(u32::MAX));
    // Sort by address for deterministic bytes — `HashMap` order is
    // random and consensus requires byte-identical values.
    let mut entries: Vec<(&revm::primitives::Address, &Option<UndoAccount>)> =
        undo.accounts.iter().collect();
    entries.sort_by_key(|(a, _)| **a);
    for (addr, entry) in entries {
        put_address(&mut out, *addr);
        match entry {
            None => put_u8(&mut out, 0),
            Some(ua) => {
                put_u8(&mut out, 1);
                put_u256(&mut out, ua.info.balance);
                put_u64(&mut out, ua.info.nonce);
                put_b256(&mut out, ua.info.code_hash);
                put_u32(&mut out, u32::try_from(ua.storage.len()).unwrap_or(u32::MAX));
                let mut slots: Vec<(&revm::primitives::U256, &revm::primitives::U256)> =
                    ua.storage.iter().collect();
                slots.sort_by_key(|(k, _)| **k);
                for (k, v) in slots {
                    put_u256(&mut out, *k);
                    put_u256(&mut out, *v);
                }
            }
        }
    }
    out
}

/// Deserialize a `BlockUndo` — inverse of [`serialize_undo`].
pub(crate) fn deserialize_undo(data: &[u8]) -> Option<BlockUndo> {
    let mut r = Reader::new(data);
    let n = r.u32()? as usize;
    let mut undo = BlockUndo::default();
    for _ in 0..n {
        let addr = r.address()?;
        let exists = r.u8()? != 0;
        let entry = if exists {
            let balance = r.u256()?;
            let nonce = r.u64()?;
            let code_hash = r.b256()?;
            let n_slots = r.u32()? as usize;
            let mut storage = revm::primitives::map::HashMap::with_capacity_and_hasher(
                n_slots,
                std::collections::hash_map::RandomState::default(),
            );
            for _ in 0..n_slots {
                let k = r.u256()?;
                let v = r.u256()?;
                storage.insert(k, v);
            }
            Some(UndoAccount {
                info: revm::database::state::AccountInfo {
                    balance,
                    nonce,
                    code_hash,
                    account_id: None,
                    code: None,
                },
                storage,
            })
        } else {
            None
        };
        undo.accounts.insert(addr, entry);
    }
    if !r.at_end() {
        return None;
    }
    Some(undo)
}

// ── Module↔storage orchestration ────────────────────────────
// `impl EvmModule` lives here so flush and load sit beside the
// key scheme they serialize through — the write schema and the
// read schema can never drift apart.
impl EvmModule {
    /// Strictly parse a snapshot's entries, returning the staged
    /// account set keyed by address.
    ///
    /// Enforces, before any state is touched:
    ///
    /// - `Snapshot.entries` sorted ascending with no duplicate keys
    ///   (the `Snapshot` contract — verified, not assumed).
    /// - `0x01` account keys in canonical form
    ///   (`[0x01][addr:20][0x00:11]` — the zero padding matters: a
    ///   key with non-zero tail bytes would alias the same address
    ///   under a second encoding) and values that satisfy
    ///   [`persist::deserialize_account_strict`].
    /// - `0x02` block records / `0x03` undo blobs: canonical key
    ///   padding and a fully-parsing value (RPC-window data — not
    ///   committed to the trie, but malformed records must not be
    ///   installed).
    /// - `0x04`: exactly the schema-version slot with a 4-byte value.
    /// - Any other namespace byte is rejected outright.
    pub(crate) fn parse_snapshot_entries(
        snapshot: &storage::Snapshot,
    ) -> Result<
        std::collections::BTreeMap<Address, persist::DeserializedAccount>,
        storage::SnapshotError,
    > {
        if snapshot.entries.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(storage::SnapshotError::Malformed);
        }
        let mut accounts = std::collections::BTreeMap::new();
        for (key, value) in &snapshot.entries {
            match key.0[0] {
                persist::NS_ACCOUNT => {
                    if key.0[21..].iter().any(|b| *b != 0) {
                        return Err(storage::SnapshotError::Malformed);
                    }
                    let addr =
                        persist::key_to_address(key).ok_or(storage::SnapshotError::Malformed)?;
                    let acct = persist::deserialize_account_strict(value)
                        .ok_or(storage::SnapshotError::Malformed)?;
                    if accounts.insert(addr, acct).is_some() {
                        return Err(storage::SnapshotError::Malformed);
                    }
                }
                persist::NS_BLOCK => {
                    if key.0[9..].iter().any(|b| *b != 0)
                        || persist::key_to_height(key).is_none()
                        || persist::deserialize_block(value).is_none()
                    {
                        return Err(storage::SnapshotError::Malformed);
                    }
                }
                persist::NS_UNDO => {
                    if key.0[9..].iter().any(|b| *b != 0)
                        || persist::key_to_height(key).is_none()
                        || persist::deserialize_undo(value).is_none()
                    {
                        return Err(storage::SnapshotError::Malformed);
                    }
                }
                persist::NS_META => {
                    if *key != persist::state_version_key() || value.len() != 4 {
                        return Err(storage::SnapshotError::Malformed);
                    }
                }
                _ => return Err(storage::SnapshotError::Malformed),
            }
        }
        Ok(accounts)
    }

    /// Flush the current `CacheDB` state to the `StorageBackend`.
    ///
    /// Phase D: incremental flush. Only accounts touched in the
    /// current block are flushed. This is O(touched) instead of
    /// O(N) — a major improvement for large states where each
    /// block modifies only a few accounts.
    ///
    /// If no accounts were touched (e.g., empty block), this is a
    /// no-op.
    ///
    /// # Self-destructed accounts
    ///
    /// Accounts that became `NotExisting` (self-destructed) or were
    /// removed from the cache emit a `Delete` op so the storage
    /// backend removes the stale entry. Without this, a
    /// self-destructed account would reappear on reload.
    ///
    /// # Deterministic serialization
    ///
    /// Storage slots are sorted by slot key before serialization so
    /// the persisted blob is byte-identical across all validators
    /// with the same logical state. Without this, `HashMap`
    /// iteration order would make the raw `StorageBackend` value
    /// non-deterministic.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    pub(crate) fn flush_to_storage(
        &self,
        backend: &mut (dyn storage::StorageBackend + Send),
    ) -> Result<(), storage::ApplyError> {
        let ops = self.account_flush_ops();
        self.flush_pending(backend, ops)
    }

    /// Attempt `apply_batch` over `pending_flush + extra` as ONE
    /// batch — a failed earlier flush retries inside the next one,
    /// so no account update, sealed-block record, or undo blob is
    /// ever dropped on a transient storage failure.
    ///
    /// On `Ok`: the buffer clears, the error latch resets, and the
    /// batch is synced (the per-block durability point — `Ok` from
    /// `apply_batch` is "written", `sync` is "durable"). On `Err`:
    /// the ops stay in `pending_flush` and the error is latched into
    /// `storage_error` — the in-memory state remains correct, but
    /// callers can observe degraded persistence via
    /// [`Self::storage_error`].
    pub(crate) fn flush_pending(
        &self,
        backend: &mut (dyn storage::StorageBackend + Send),
        extra: Vec<storage::Op>,
    ) -> Result<(), storage::ApplyError> {
        let mut pending = framework::lock_state(&self.pending_flush);
        pending.extend(extra);
        if pending.is_empty() {
            return Ok(());
        }
        match backend.apply_batch(&pending) {
            Ok(()) => {
                pending.clear();
                drop(pending);
                // Per-block durability point: `apply_batch` is
                // "written", `sync` is "durable". A sync failure is
                // latched but not buffered — the ops ARE written, and
                // the next successful sync covers them (same file).
                if let Err(e) = backend.sync() {
                    *framework::lock_state(&self.storage_error) = Some(e.clone());
                    return Err(e);
                }
                *framework::lock_state(&self.storage_error) = None;
                Ok(())
            }
            Err(e) => {
                drop(pending);
                *framework::lock_state(&self.storage_error) = Some(e.clone());
                Err(e)
            }
        }
    }

    /// Build the account write ops for the block's `touched` set —
    /// the pure form of [`flush_to_storage`], split out so
    /// `end_block` can commit accounts, the sealed history record,
    /// and the undo blob in one `apply_batch` (a crash must never
    /// leave state ahead of history, or a restarted node would serve
    /// newer state under an older height label).
    pub(crate) fn account_flush_ops(&self) -> Vec<storage::Op> {
        let db = framework::lock_state(&self.db);
        let touched = framework::lock_state(&self.touched);

        let mut ops = Vec::with_capacity(touched.len());
        for evm_addr in touched.iter() {
            let oxide_addr = Address(evm_addr.0.into());
            let key = persist::account_key(&oxide_addr);

            // Handle self-destructed / removed accounts: emit a
            // Delete op so the stale entry is removed from storage.
            // Without this, a self-destructed account reappears on
            // reload because the old persisted value is still there.
            // `serialize_committed_account` returns `None` for both
            // cases (missing entry or `NotExisting` tombstone) —
            // exactly the accounts absent from committed state.
            match Self::serialize_committed_account(evm_addr, &db) {
                Some(value) => ops.push(storage::Op::Set { key, value }),
                None => ops.push(storage::Op::Delete { key }),
            }
        }
        // The schema version rides every flush batch: one extra op
        // per block keeps the `0x04` meta slot in lockstep with the
        // binary that last wrote state — a downgraded binary's
        // `state_version` would rewrite it honestly instead of
        // inheriting a newer label it can't interpret.
        ops.push(storage::Op::Set {
            key: persist::state_version_key(),
            value: self.state_version().to_le_bytes().to_vec(),
        });
        ops
    }

    /// Serialize one committed cache account into its canonical
    /// value blob — the single encoding shared by the incremental
    /// flush ([`Self::account_flush_ops`]) and the snapshot export
    /// ([`Module::export_state`]). Keeping both on one serializer is
    /// the audit-3.2 invariant: the bytes that reach durable storage
    /// and the bytes a snapshot carries can never drift apart.
    ///
    /// Returns `None` when the address is absent from committed
    /// state — no cache entry, or an `AccountState::NotExisting`
    /// tombstone (self-destructed this block, or a `basic()` miss
    /// revm cached). Tombstones are not part of the state trie, so
    /// they must never serialize as live accounts.
    ///
    /// The blob layout is `persist::serialize_account`'s: balance,
    /// nonce, `code_hash`, code bytes, then storage slots sorted
    /// ascending by slot key. `DbAccount.storage` is a `U256Map`
    /// (hash map) — sorting makes the blob deterministic across
    /// validators with the same logical state.
    pub(crate) fn serialize_committed_account(
        evm_addr: &revm::primitives::Address,
        db: &CacheDB<EmptyDB>,
    ) -> Option<Vec<u8>> {
        let account = db.cache.accounts.get(evm_addr)?;
        if account.account_state == revm::database::AccountState::NotExisting {
            return None;
        }
        let code_bytes: Vec<u8> = if account.info.code_hash == revm::primitives::KECCAK_EMPTY {
            Vec::new()
        } else {
            // `original_byte_slice`, not `bytes_slice`: once revm has
            // analyzed a contract (first execution) `bytes_slice`
            // returns the padded buffer, whose keccak no longer
            // matches the committed `code_hash` — persisting it
            // would reinstall divergent bytecode on restart
            // (`extcodesize`/`extcodecopy` observe the padding).
            match &account.info.code {
                Some(bc) => bc.original_byte_slice().to_vec(),
                // A balance/nonce-touched contract may never have
                // loaded bytecode into `info.code` (e.g. a contract
                // coinbase receiving fees — `basic()` doesn't
                // populate `code`). Fall back to the contracts map:
                // writing `code_len=0` under a real `code_hash`
                // would silently strip the contract's code on
                // reload/snapshot.
                None => db
                    .cache
                    .contracts
                    .get(&account.info.code_hash)
                    .map_or_else(Vec::new, |bc| bc.original_byte_slice().to_vec()),
            }
        };
        // Sparse-storage invariant: zero-valued slots are absent in
        // Ethereum state — the committed map is swept at commit
        // (`commit_state` in lib.rs), and the filter here is the
        // belt to that suspenders: a zero in a persisted blob or a
        // snapshot would resurrect a slot the MPT cannot encode.
        let mut storage_slots: Vec<(revm::primitives::U256, revm::primitives::U256)> = account
            .storage
            .iter()
            .filter(|(_, val)| !val.is_zero())
            .map(|(slot, val)| (*slot, *val))
            .collect();
        storage_slots.sort_by_key(|a| a.0);
        Some(persist::serialize_account(
            account.info.balance,
            account.info.nonce,
            account.info.code_hash,
            &code_bytes,
            &storage_slots,
        ))
    }

    /// Load EVM state from the `StorageBackend` into the `CacheDB`.
    ///
    /// Reads all account entries (namespace prefix `0x01`) and
    /// populates the cache with balances, nonces, code, and storage.
    /// Called from `with_storage` on construction.
    ///
    /// # Panics
    ///
    /// Panics if the DB mutex is poisoned.
    pub(crate) fn load_from_storage(&self, backend: &mut (dyn storage::StorageBackend + Send)) {
        let entries = backend.range(&persist::account_prefix());
        // Only the *account* section is skipped on an empty range —
        // block history, the undo window, stale-record cleanup, and
        // the schema-version check still run: a backend can hold
        // sealed blocks (empty blocks write no accounts) or only a
        // version marker, and skipping their restore would silently
        // drop durable state that exists.
        if !entries.is_empty() {
            let mut db_guard = framework::lock_state(&self.db);
            let db = Arc::make_mut(&mut *db_guard);
            for (key, value) in &entries {
                let Some(oxide_addr) = persist::key_to_address(key) else { continue };
                let Some(account) = persist::deserialize_account(value) else {
                    continue;
                };
                let evm_addr = alloy_primitives_address(oxide_addr.0);

                // Insert account info into the cache.
                let info = revm::database::state::AccountInfo {
                    balance: account.balance,
                    nonce: account.nonce,
                    code_hash: account.code_hash,
                    account_id: None,
                    // revm's `Bytecode::default()` contains a STOP opcode,
                    // which makes `is_empty()` return false and triggers
                    // EIP-3607 `RejectCallerWithCode`. Use `new_raw` with
                    // empty bytes to create a truly empty bytecode.
                    code: if account.code.is_empty() {
                        Some(revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::new()))
                    } else {
                        Some(revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::from_iter(
                            account.code.iter().copied(),
                        )))
                    },
                };
                db.cache.accounts.insert(
                    evm_addr,
                    revm::database::DbAccount {
                        info,
                        // `None` = account exists in cache but EVM hasn't
                        // interacted with it in this block. This is correct
                        // for loaded state — revm will read storage from
                        // the `DbAccount.storage` field. `StorageCleared`
                        // would incorrectly zero out the storage.
                        account_state: revm::database::AccountState::None,
                        // Drop zero-valued slots on the way in —
                        // blobs written before the sparse-storage
                        // invariant may carry them; the committed
                        // map must hold only nonzero entries.
                        storage: account
                            .storage
                            .into_iter()
                            .filter(|(_, value)| !value.is_zero())
                            .collect(),
                    },
                );
                // HIGH fix: also populate `cache.contracts` (the code
                // hash → Bytecode map). revm looks up contract code by
                // hash via `cache.contracts`, not via the account's
                // `info.code` field. Without this, after a storage
                // reload, the EVM can't find contract code by hash —
                // calling a reloaded contract would behave as if it
                // has no code (a silent no-op call).
                if !account.code.is_empty() {
                    db.cache.contracts.insert(
                        account.code_hash,
                        revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::from_iter(
                            account.code.iter().copied(),
                        )),
                    );
                }
            }
            drop(db_guard);
        }

        // Restore the sealed-block history (`0x02` records) and the
        // undo window (`0x03` blobs) so historical state reads, log
        // queries, receipts, and `debug_trace*` survive restart.
        // Both scans come back height-ascending (the key layout is
        // height-major); `restore_block`/`push` rebuild the in-memory
        // indexes as they insert.
        let mut stale: Vec<Hash> = Vec::new();
        let floor = {
            let mut history = framework::lock_state(&self.history);
            for (_key, value) in backend.range(&persist::block_prefix()) {
                let Some(block) = persist::deserialize_block(&value) else {
                    continue; // Malformed record — a storage bug, skip it.
                };
                for evicted in history.restore_block(block) {
                    // Restored-then-evicted records are stale on disk
                    // (the configured window shrank since the records
                    // were written). Delete them below.
                    stale.push(persist::block_key(evicted));
                }
            }
            history.blocks_floor()
        };

        // Rehydrate the EIP-1559 fee state from the newest sealed
        // block. `end_block_ctx` evolves the fee as
        // `BaseFeeState::new(block.base_fee, block.gas_limit)
        //   .update(block.gas_used)`
        // — replaying that transition on the last sealed record
        // reproduces the exact in-memory state a crash dropped, so
        // the next block charges the same base fee it would have
        // without the restart. A fresh backend (no sealed blocks)
        // keeps the constructor seed, matching a cold start.
        {
            let history = framework::lock_state(&self.history);
            if let Some(last) = history.latest().and_then(|h| history.block(h)) {
                let mut fee_state = fee::BaseFeeState::new(last.base_fee, last.gas_limit);
                fee_state.update(last.gas_used);
                *framework::lock_state(&self.fee_state) = fee_state;
            }
        }

        {
            let mut versioned = framework::lock_state(&self.versioned);
            for (key, value) in backend.range(&persist::undo_prefix()) {
                let Some(height) = persist::key_to_height(&key) else { continue };
                if floor.is_some_and(|f| height < f) {
                    stale.push(key); // Below the restored window.
                    continue;
                }
                let Some(undo) = persist::deserialize_undo(&value) else { continue };
                versioned.push(height, undo);
            }
        }

        // One cleanup batch for stale records discovered during
        // restore (over-capacity or below-floor entries). Routed
        // through the pending buffer: a failure latches into
        // `storage_error` and retries inside the next block's flush
        // — the records are housekeeping, so a delayed cleanup is
        // harmless, but a silently dropped write is not.
        if !stale.is_empty() {
            let ops: Vec<storage::Op> =
                stale.into_iter().map(|key| storage::Op::Delete { key }).collect();
            let _ = self.flush_pending(backend, ops);
        }

        // Schema version check: the backend records the layout
        // version it was last written at (`0x04` meta namespace,
        // absent = v1 pre-versioning). Older than this binary's
        // declared `state_version` → run `migrate` on the freshly
        // loaded state and persist the new version. A failed
        // migration leaves the stored version untouched — the next
        // restart retries it.
        let stored_version = backend
            .get(&persist::state_version_key())
            .and_then(|v| <[u8; 4]>::try_from(v.as_slice()).ok().map(u32::from_le_bytes))
            .unwrap_or(1);
        if stored_version < self.state_version()
            && let Ok(new_version) = self.migrate(stored_version)
        {
            // Schema-version write through the pending buffer — a
            // failure latches and retries rather than leaving the
            // recorded version silently behind the migrated state.
            let _ = self.flush_pending(
                backend,
                vec![storage::Op::Set {
                    key: persist::state_version_key(),
                    value: new_version.to_le_bytes().to_vec(),
                }],
            );
        }
    }
}
