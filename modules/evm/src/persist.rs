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
const NS_ACCOUNT: u8 = 0x01;

/// Namespace prefix for sealed `ExecutedBlock` records.
///
/// Key format: `[0x02][height: 8B big-endian][0x00: 23B]` — 32
/// bytes, height-major so `range([0x02])` returns blocks in
/// ascending order. The `hash_index`/`tx_index` maps are *not*
/// persisted; they are rebuilt from the records on load.
const NS_BLOCK: u8 = 0x02;

/// Namespace prefix for per-height undo blobs.
///
/// Key format: `[0x03][height: 8B big-endian][0x00: 23B]`. The
/// value holds every `(address, pre-block account)` pair captured
/// during that height — restoring them rebuilds the versioned
/// index so historical reads survive restart. Every executed
/// height writes a blob (possibly empty) so the retention floor
/// is preserved exactly.
const NS_UNDO: u8 = 0x03;

/// Namespace prefix for module metadata — the schema version the
/// stored state was written at. Read on load so `migrate` knows
/// what it's migrating *from*; rewritten on flush so the stored
/// version always matches the binary that last wrote state.
const NS_META: u8 = 0x04;

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
