//! Signed EVM transaction types (Phase A).
//!
//! This module implements the four Ethereum transaction types:
//! Legacy (pre-EIP-155 and EIP-155), EIP-2930 (access lists),
//! EIP-1559 (base fee + priority fee), and EIP-7702 (set-code
//! transactions carrying an authorization list). Each type is
//! RLP-encoded per the Ethereum spec and carries a secp256k1
//! signature for sender recovery.
//!
//! # Reference
//!
//! - EIP-155: Simple replay attack protection (chain ID in v).
//! - EIP-2930: Optional access lists with type prefix `0x01`.
//! - EIP-1559: Fee market change with type prefix `0x02`.
//! - EIP-7702: Set EOA account code with type prefix `0x04`.
//!
//! reth is the canonical reference for encoding/decoding behavior.
//!
//! # RLP encoding rules
//!
//! - `U256` values (nonce, gas, value) are encoded as big-endian byte
//!   strings with leading zeros stripped (Ethereum convention).
//! - `Address` is 20 bytes.
//! - `TxKind::Create` is encoded as an empty string (0x80).
//! - `TxKind::Call(addr)` is encoded as 20 bytes.
//! - Legacy: `rlp([nonce, gas_price, gas_limit, to, value, data, v, r, s])`.
//! - EIP-2930: `0x01 || rlp([chain_id, nonce, gas_price, gas_limit, to,
//!   value, data, access_list, y_parity, r, s])`.
//! - EIP-1559: `0x02 || rlp([chain_id, nonce, max_priority_fee, max_fee,
//!   gas_limit, to, value, data, access_list, y_parity, r, s])`.
//! - EIP-7702: `0x04 || rlp([chain_id, nonce, max_priority_fee, max_fee,
//!   gas_limit, destination, value, data, access_list,
//!   authorization_list, y_parity, r, s])`, where `destination` is a
//!   mandatory 20-byte address (7702 forbids contract creation) and
//!   `authorization_list` is `[[chain_id, address, nonce, y_parity, r,
//!   s], ...]`.

use alloy_rlp::{BufMut, Decodable, Encodable, Header};
use crypto::secp::{self, RecoveryId};
use revm::primitives::{Address, Bytes, U256};

// ── RLP helpers for U256 ─────────────────────────────────────────────

/// Encode a `U256` as an RLP byte string (big-endian, leading zeros
/// stripped). This is the Ethereum convention for all integer fields
/// in transaction RLP.
fn encode_u256(val: &U256, out: &mut dyn BufMut) {
    let bytes = val.to_be_bytes::<32>();
    // Strip leading zeros.
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(32);
    let trimmed = &bytes[start..];
    // RLP encoding for byte strings:
    // - 0 bytes → 0x80
    // - 1 byte < 0x80 → just the byte itself (no header)
    // - 1 byte >= 0x80 → 0x81 + byte
    // - 2-55 bytes → 0x80+len + bytes
    if trimmed.is_empty() {
        out.put_u8(0x80);
    } else if trimmed.len() == 1 && trimmed[0] < 0x80 {
        out.put_u8(trimmed[0]);
    } else {
        Header { list: false, payload_length: trimmed.len() }.encode(out);
        out.put_slice(trimmed);
    }
}

/// Length of a `U256` in RLP encoding (header + big-endian bytes
/// without leading zeros).
fn u256_length(val: &U256) -> usize {
    let bytes = val.to_be_bytes::<32>();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(32);
    let trimmed_len = 32 - start;
    // RLP length:
    // - 0 bytes or 1 byte < 0x80 → 1 (0x80 or the byte itself)
    // - 1 byte >= 0x80 → 2 (0x81 + byte)
    // - 2-55 bytes → 1 + trimmed_len
    if trimmed_len == 0 || (trimmed_len == 1 && bytes[31] < 0x80) {
        1
    } else {
        Header { list: false, payload_length: trimmed_len }.length() + trimmed_len
    }
}

/// Decode a `U256` from an RLP byte string.
fn decode_u256(buf: &mut &[u8]) -> alloy_rlp::Result<U256> {
    let header = Header::decode(buf)?;
    if header.list {
        return Err(alloy_rlp::Error::UnexpectedList);
    }
    let payload_len = header.payload_length;
    if buf.len() < payload_len {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    let data = &buf[..payload_len];
    *buf = &buf[payload_len..];
    // Pad with leading zeros to 32 bytes.
    let mut arr = [0u8; 32];
    if data.len() > 32 {
        return Err(alloy_rlp::Error::Overflow);
    }
    arr[32 - data.len()..].copy_from_slice(data);
    Ok(U256::from_be_bytes(arr))
}

// ── TxKind ───────────────────────────────────────────────────────────

/// The `to` field of a transaction: a call to an existing address or
/// a contract creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxKind {
    /// Create a new contract (the `to` field is empty in RLP).
    Create,
    /// Call an existing contract at `address`.
    Call(Address),
}

impl Encodable for TxKind {
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            Self::Create => {
                // Empty string: 0x80
                Header { list: false, payload_length: 0 }.encode(out);
            }
            Self::Call(addr) => {
                addr.encode(out);
            }
        }
    }
    fn length(&self) -> usize {
        match self {
            Self::Create => 1, // 0x80
            Self::Call(addr) => addr.length(),
        }
    }
}

impl Decodable for TxKind {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // Peek at the first byte. If it's 0x80 (empty string), it's Create.
        // Otherwise it's a 20-byte address.
        if buf.is_empty() {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        if buf[0] == 0x80 {
            *buf = &buf[1..];
            return Ok(Self::Create);
        }
        let addr = Address::decode(buf)?;
        Ok(Self::Call(addr))
    }
}

// ── AccessList ───────────────────────────────────────────────────────

/// A single access list entry: an address and the storage keys the
/// transaction will access (for gas pre-payment per EIP-2930).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessListItem {
    /// The contract address.
    pub address: Address,
    /// Storage slots the tx will read or write.
    pub storage_keys: Vec<revm::primitives::B256>,
}

/// An EIP-2930 access list: a list of (address, `storage_keys`) pairs.
pub type AccessList = Vec<AccessListItem>;

/// Encode an access list as RLP. Each item is `[address, [storage_keys...]]`.
fn encode_access_list(list: &AccessList, out: &mut dyn BufMut) {
    let items_len: usize = list
        .iter()
        .map(|item| {
            let addr_len = item.address.length();
            let keys_len: usize =
                item.storage_keys.iter().map(alloy_rlp::Encodable::length).sum::<usize>();
            let keys_list_len = Header { list: true, payload_length: keys_len }.length() + keys_len;
            let inner_list_len = addr_len + keys_list_len;
            Header { list: true, payload_length: inner_list_len }.length() + inner_list_len
        })
        .sum();
    Header { list: true, payload_length: items_len }.encode(out);
    for item in list {
        let addr_len = item.address.length();
        let keys_len: usize =
            item.storage_keys.iter().map(alloy_rlp::Encodable::length).sum::<usize>();
        let keys_list_len = Header { list: true, payload_length: keys_len }.length() + keys_len;
        let inner_list_len = addr_len + keys_list_len;
        Header { list: true, payload_length: inner_list_len }.encode(out);
        item.address.encode(out);
        // Storage keys are a list of 32-byte hashes.
        Header { list: true, payload_length: keys_len }.encode(out);
        for key in &item.storage_keys {
            key.encode(out);
        }
    }
}

/// Length of an access list in RLP encoding.
fn access_list_length(list: &AccessList) -> usize {
    let items_len: usize = list
        .iter()
        .map(|item| {
            let addr_len = item.address.length();
            let keys_len: usize =
                item.storage_keys.iter().map(alloy_rlp::Encodable::length).sum::<usize>();
            // The storage keys are a list: header + keys.
            let keys_list_len = Header { list: true, payload_length: keys_len }.length() + keys_len;
            // The item is a list: [address, [keys...]].
            let inner_list_len = addr_len + keys_list_len;
            Header { list: true, payload_length: inner_list_len }.length() + inner_list_len
        })
        .sum();
    Header { list: true, payload_length: items_len }.length() + items_len
}

/// Decode an access list from RLP.
fn decode_access_list(buf: &mut &[u8]) -> alloy_rlp::Result<AccessList> {
    let header = Header::decode(buf)?;
    if !header.list {
        return Err(alloy_rlp::Error::UnexpectedString);
    }
    let payload_len = header.payload_length;
    if buf.len() < payload_len {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    // Create a sub-slice for decoding items. We advance `buf` past
    // the entire payload at the end.
    let mut remaining = &buf[..payload_len];
    let mut items = Vec::new();
    while !remaining.is_empty() {
        let item_header = Header::decode(&mut remaining)?;
        if !item_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let item_payload = item_header.payload_length;
        if remaining.len() < item_payload {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        let mut item_buf = &remaining[..item_payload];
        let address = Address::decode(&mut item_buf)?;
        // Storage keys list.
        let keys_header = Header::decode(&mut item_buf)?;
        if !keys_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let keys_payload = keys_header.payload_length;
        if item_buf.len() < keys_payload {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        let mut keys_buf = &item_buf[..keys_payload];
        let mut storage_keys = Vec::new();
        while !keys_buf.is_empty() {
            storage_keys.push(revm::primitives::B256::decode(&mut keys_buf)?);
        }
        items.push(AccessListItem { address, storage_keys });
        remaining = &remaining[item_payload..];
    }
    *buf = &buf[payload_len..];
    Ok(items)
}

// ── EIP-7702 authorization ───────────────────────────────────────────

/// The EIP-7702 "MAGIC" byte that prefixes the authorization signing
/// payload, domain-separating authority signatures from transaction
/// signatures (`keccak256(0x05 || rlp([chain_id, address, nonce]))`).
const EIP7702_MAGIC: u8 = 0x05;

/// A signed EIP-7702 authorization tuple.
///
/// On the wire each entry is `rlp([chain_id, address, nonce, y_parity,
/// r, s])`. The `sig` field carries the authority's signature over
/// `0x05 || rlp([chain_id, address, nonce])`; the recovered signer is
/// the *authority* whose account gets delegated to `address`.
///
/// Per EIP-7702, `chain_id == 0` authorizes on any chain (the
/// signature is chain-agnostic); a non-zero chain ID binds the
/// authorization to that chain only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxAuthorization {
    /// The chain the authorization is valid on (0 = any chain).
    pub chain_id: U256,
    /// The delegation target — the authority's account code becomes
    /// `0xef0100 || address` while the authorization is in effect.
    pub address: Address,
    /// The authority's nonce at signing time. The authorization is
    /// invalid once the authority's nonce advances past this value.
    pub nonce: u64,
    /// The authority's secp256k1 signature (`y_parity`, `r`, `s`).
    pub sig: TxSignature,
}

impl TxAuthorization {
    /// The EIP-7702 authorization signing hash:
    /// `keccak256(0x05 || rlp([chain_id, address, nonce]))`.
    ///
    /// The 0x05 domain byte ensures an authorization signature can
    /// never be reinterpreted as a transaction signature and vice
    /// versa.
    #[must_use]
    pub fn signing_hash(chain_id: U256, address: Address, nonce: u64) -> [u8; 32] {
        let payload_len =
            u256_length(&chain_id) + address.length() + u256_length(&U256::from(nonce));
        let mut buf = Vec::with_capacity(1 + payload_len + 8);
        buf.push(EIP7702_MAGIC);
        Header { list: true, payload_length: payload_len }.encode(&mut buf);
        encode_u256(&chain_id, &mut buf);
        address.encode(&mut buf);
        encode_u256(&U256::from(nonce), &mut buf);
        crypto::secp::keccak256(&buf)
    }

    /// Sign an authorization tuple, producing the signed entry for a
    /// type-4 transaction's `authorization_list`.
    ///
    /// # Errors
    ///
    /// Returns [`secp::SecpError`] if the private key is invalid.
    pub fn sign(
        chain_id: U256,
        address: Address,
        nonce: u64,
        privkey: &[u8],
    ) -> Result<Self, secp::SecpError> {
        let hash = Self::signing_hash(chain_id, address, nonce);
        let sig = secp::sign(privkey, &hash)?;
        Ok(Self { chain_id, address, nonce, sig: sig_to_txsig(&sig) })
    }

    /// Recover the *authority* — the EOA whose account this
    /// authorization delegates.
    ///
    /// # Errors
    ///
    /// Returns [`secp::SecpError`] if the signature is invalid.
    pub fn recover_authority(&self) -> Result<Address, secp::SecpError> {
        let hash = Self::signing_hash(self.chain_id, self.address, self.nonce);
        let r = self.sig.r.to_be_bytes::<32>();
        let s = self.sig.s.to_be_bytes::<32>();
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&r);
        sig_bytes[32..].copy_from_slice(&s);
        let recovered = secp::recover_sender(&hash, &sig_bytes, self.sig.recid.as_u8())?;
        Ok(Address::from(recovered.0))
    }
}

/// Encode one authorization tuple: `rlp([chain_id, address, nonce,
/// y_parity, r, s])`.
fn encode_authorization(auth: &TxAuthorization, out: &mut dyn BufMut) {
    let payload_len = u256_length(&auth.chain_id)
        + auth.address.length()
        + u256_length(&U256::from(auth.nonce))
        + u256_length(&U256::from(auth.sig.recid.as_u8()))
        + u256_length(&auth.sig.r)
        + u256_length(&auth.sig.s);
    Header { list: true, payload_length: payload_len }.encode(out);
    encode_u256(&auth.chain_id, out);
    auth.address.encode(out);
    encode_u256(&U256::from(auth.nonce), out);
    encode_u256(&U256::from(auth.sig.recid.as_u8()), out);
    encode_u256(&auth.sig.r, out);
    encode_u256(&auth.sig.s, out);
}

/// Length of one encoded authorization tuple.
fn authorization_length(auth: &TxAuthorization) -> usize {
    let payload_len = u256_length(&auth.chain_id)
        + auth.address.length()
        + u256_length(&U256::from(auth.nonce))
        + u256_length(&U256::from(auth.sig.recid.as_u8()))
        + u256_length(&auth.sig.r)
        + u256_length(&auth.sig.s);
    Header { list: true, payload_length: payload_len }.length() + payload_len
}

/// Encode an authorization list: `rlp([[chain_id, address, nonce,
/// y_parity, r, s], ...])`.
fn encode_authorization_list(list: &[TxAuthorization], out: &mut dyn BufMut) {
    let payload_len: usize = list.iter().map(authorization_length).sum();
    Header { list: true, payload_length: payload_len }.encode(out);
    for auth in list {
        encode_authorization(auth, out);
    }
}

/// Length of an encoded authorization list.
fn authorization_list_length(list: &[TxAuthorization]) -> usize {
    let payload_len: usize = list.iter().map(authorization_length).sum();
    Header { list: true, payload_length: payload_len }.length() + payload_len
}

/// Decode an authorization list from RLP.
///
/// The payload is decoded inside a bounded sub-slice so a malformed
/// inner tuple cannot consume bytes belonging to subsequent
/// transaction fields.
fn decode_authorization_list(buf: &mut &[u8]) -> alloy_rlp::Result<Vec<TxAuthorization>> {
    let header = Header::decode(buf)?;
    if !header.list {
        return Err(alloy_rlp::Error::UnexpectedString);
    }
    let payload_len = header.payload_length;
    if buf.len() < payload_len {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    let mut remaining = &buf[..payload_len];
    let mut list = Vec::new();
    while !remaining.is_empty() {
        let item_header = Header::decode(&mut remaining)?;
        if !item_header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let item_payload = item_header.payload_length;
        if remaining.len() < item_payload {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        let mut item_buf = &remaining[..item_payload];
        let chain_id = decode_u256(&mut item_buf)?;
        let address = Address::decode(&mut item_buf)?;
        let nonce = u256_to_u64(decode_u256(&mut item_buf)?)?;
        let recid = SignedTx::decode_recid(&mut item_buf)?;
        let r = decode_u256(&mut item_buf)?;
        let s = decode_u256(&mut item_buf)?;
        if !item_buf.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        list.push(TxAuthorization { chain_id, address, nonce, sig: TxSignature { r, s, recid } });
        remaining = &remaining[item_payload..];
    }
    *buf = &buf[payload_len..];
    Ok(list)
}

// ── Signature ────────────────────────────────────────────────────────

/// An ECDSA signature: `r`, `s`, and a recovery ID (`y_parity`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxSignature {
    /// The `r` component of the signature (32 bytes).
    pub r: U256,
    /// The `s` component of the signature (32 bytes).
    pub s: U256,
    /// The recovery ID (0 or 1 for standard Ethereum signatures).
    /// For legacy txs, this is extracted from the `v` value.
    pub recid: RecoveryId,
}

// ── Unsigned tx fields ───────────────────────────────────────────────

/// Fields shared by all transaction types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxFields {
    /// The sender's nonce (account nonce).
    pub nonce: u64,
    /// The gas limit for the transaction.
    pub gas_limit: u64,
    /// The destination: call or create.
    pub to: TxKind,
    /// The value to transfer (in wei).
    pub value: U256,
    /// The calldata / init code.
    pub data: Bytes,
    /// The chain ID (EIP-155).
    pub chain_id: u64,
}

/// Legacy transaction: `gas_price` is the exact fee per gas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxLegacy {
    /// Shared fields.
    pub fields: TxFields,
    /// The gas price (wei per gas unit).
    pub gas_price: U256,
}

/// EIP-2930 transaction: legacy gas pricing + access list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEip2930 {
    /// Shared fields.
    pub fields: TxFields,
    /// The gas price (wei per gas unit).
    pub gas_price: U256,
    /// The access list (EIP-2930).
    pub access_list: AccessList,
}

/// EIP-1559 transaction: base fee + priority fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEip1559 {
    /// Shared fields.
    pub fields: TxFields,
    /// The maximum priority fee per gas (tip, in wei).
    pub max_priority_fee_per_gas: U256,
    /// The maximum total fee per gas (tip + base fee, in wei).
    pub max_fee_per_gas: U256,
    /// The access list (EIP-2930).
    pub access_list: AccessList,
}

/// EIP-7702 "set code" transaction: EIP-1559 fee fields plus an
/// authorization list of signed delegation tuples.
///
/// The destination is a mandatory call target — EIP-7702 forbids
/// contract creation, so `fields.to` is always [`TxKind::Call`]
/// (enforced at decode time).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxEip7702 {
    /// Shared fields (`to` is always `Call` per EIP-7702).
    pub fields: TxFields,
    /// The maximum priority fee per gas (tip, in wei).
    pub max_priority_fee_per_gas: U256,
    /// The maximum total fee per gas (tip + base fee, in wei).
    pub max_fee_per_gas: U256,
    /// The access list (EIP-2930).
    pub access_list: AccessList,
    /// The signed authorization list (EIP-7702). Non-empty per spec;
    /// enforced at decode time.
    pub authorization_list: Vec<TxAuthorization>,
}

// ── SignedTx ─────────────────────────────────────────────────────────

/// A signed EVM transaction. The type prefix byte determines the
/// variant: no prefix (or >= 0xc0) = Legacy, 0x01 = EIP-2930,
/// 0x02 = EIP-1559, 0x04 = EIP-7702.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedTx {
    /// Legacy transaction (pre-EIP-155 or EIP-155).
    Legacy(TxLegacy, TxSignature),
    /// EIP-2930 transaction (access lists).
    Eip2930(TxEip2930, TxSignature),
    /// EIP-1559 transaction (base fee + priority fee).
    Eip1559(TxEip1559, TxSignature),
    /// EIP-7702 transaction (set-code / delegation authorization).
    Eip7702(TxEip7702, TxSignature),
}

/// Type prefix bytes for typed transactions (EIP-2718).
///
/// `0x03` (EIP-4844 blob transactions) is intentionally unassigned:
/// blob txs require beacon-side blob data Oxide does not carry, so
/// a `0x03` prefix still falls through to the legacy decoder and fails
/// there — a deterministic rejection either way.
const TX_TYPE_EIP2930: u8 = 0x01;
const TX_TYPE_EIP1559: u8 = 0x02;
const TX_TYPE_EIP7702: u8 = 0x04;

impl SignedTx {
    /// Sign a legacy transaction with the given private key and return
    /// the signed transaction.
    ///
    /// This is the primary signing entry point for tests and the future
    /// RPC layer. The private key must be 32 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`secp::SecpError`] if the private key is invalid or
    /// signing fails.
    pub fn sign_legacy(tx: TxLegacy, privkey: &[u8]) -> Result<Self, secp::SecpError> {
        let dummy_sig = TxSignature { r: U256::ZERO, s: U256::ZERO, recid: RecoveryId::new(0) };
        let temp = Self::Legacy(tx.clone(), dummy_sig);
        let signing_hash = temp.signing_hash();
        let sig = secp::sign(privkey, &signing_hash)?;
        Ok(Self::Legacy(tx, sig_to_txsig(&sig)))
    }

    /// Sign an EIP-1559 transaction with the given private key and return
    /// the signed transaction.
    ///
    /// # Errors
    ///
    /// Returns [`secp::SecpError`] if the private key is invalid or
    /// signing fails.
    pub fn sign_eip1559(tx: TxEip1559, privkey: &[u8]) -> Result<Self, secp::SecpError> {
        let dummy_sig = TxSignature { r: U256::ZERO, s: U256::ZERO, recid: RecoveryId::new(0) };
        let temp = Self::Eip1559(tx.clone(), dummy_sig);
        let signing_hash = temp.signing_hash();
        let sig = secp::sign(privkey, &signing_hash)?;
        Ok(Self::Eip1559(tx, sig_to_txsig(&sig)))
    }

    /// Sign an EIP-7702 transaction with the given private key and
    /// return the signed transaction.
    ///
    /// # Errors
    ///
    /// Returns [`secp::SecpError`] if the private key is invalid or
    /// signing fails.
    pub fn sign_eip7702(tx: TxEip7702, privkey: &[u8]) -> Result<Self, secp::SecpError> {
        let dummy_sig = TxSignature { r: U256::ZERO, s: U256::ZERO, recid: RecoveryId::new(0) };
        let temp = Self::Eip7702(tx.clone(), dummy_sig);
        let signing_hash = temp.signing_hash();
        let sig = secp::sign(privkey, &signing_hash)?;
        Ok(Self::Eip7702(tx, sig_to_txsig(&sig)))
    }

    /// Decode a signed transaction from raw RLP bytes.
    ///
    /// This is THE canonical decoder at every trust boundary — the
    /// RPC layer (`eth_sendRawTransaction`), mempool admission, and
    /// block execution all route through it, so a byte string one
    /// path accepts can never be rejected by another.
    ///
    /// Exact-consumption semantics: the decode must consume the
    /// entire input — trailing garbage is an error, not ignored.
    /// Combined with the per-decoder list-payload bounds (fields
    /// can't bleed past the declared RLP list length, and unconsumed
    /// declared payload is an error), this makes the accepted byte
    /// string the canonical encoding of the transaction: one tx, one
    /// byte string, one `keccak256` hash — deduplication, tx hashes,
    /// and history indexing can't disagree about identity.
    ///
    /// Prefer this over [`alloy_rlp::Decodable::decode`], which
    /// advances a `&mut &[u8]` cursor and silently tolerates a
    /// non-empty remainder.
    ///
    /// # Errors
    ///
    /// Returns [`alloy_rlp::Error`] if the bytes are not a valid
    /// RLP-encoded signed transaction (legacy, EIP-2930, EIP-1559,
    /// or EIP-7702), or if valid RLP is followed by trailing bytes.
    pub fn decode_raw(raw: &[u8]) -> alloy_rlp::Result<Self> {
        let mut cursor = raw;
        let decoded = <Self as alloy_rlp::Decodable>::decode(&mut cursor)?;
        // Reject trailing bytes — a well-formed transaction has no
        // extra data after the RLP payload. This prevents a class of
        // malleability where a client appends junk that is silently
        // ignored, producing a different hash than the canonical
        // encoding.
        if !cursor.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        Ok(decoded)
    }

    /// Encode the signed transaction to a byte vector (RLP).
    #[must_use]
    pub fn encode_to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        alloy_rlp::Encodable::encode(self, &mut buf);
        buf
    }

    /// The chain ID of the transaction.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        match self {
            Self::Legacy(tx, _) => tx.fields.chain_id,
            Self::Eip2930(tx, _) => tx.fields.chain_id,
            Self::Eip1559(tx, _) => tx.fields.chain_id,
            Self::Eip7702(tx, _) => tx.fields.chain_id,
        }
    }

    /// The EIP-2718 transaction type byte: `0` for legacy (implicit,
    /// not prefixed on the wire), `1` for EIP-2930, `2` for EIP-1559,
    /// `4` for EIP-7702.
    /// Used by the receipts root to prefix typed receipts per
    /// EIP-2718 (a typed tx's receipt is `type_byte || rlp(...)`).
    #[must_use]
    pub const fn tx_type(&self) -> u8 {
        match self {
            Self::Legacy(_, _) => 0,
            Self::Eip2930(_, _) => TX_TYPE_EIP2930,
            Self::Eip1559(_, _) => TX_TYPE_EIP1559,
            Self::Eip7702(_, _) => TX_TYPE_EIP7702,
        }
    }

    /// The nonce of the transaction.
    #[must_use]
    pub fn nonce(&self) -> u64 {
        match self {
            Self::Legacy(tx, _) => tx.fields.nonce,
            Self::Eip2930(tx, _) => tx.fields.nonce,
            Self::Eip1559(tx, _) => tx.fields.nonce,
            Self::Eip7702(tx, _) => tx.fields.nonce,
        }
    }

    /// The gas limit of the transaction.
    #[must_use]
    pub fn gas_limit(&self) -> u64 {
        match self {
            Self::Legacy(tx, _) => tx.fields.gas_limit,
            Self::Eip2930(tx, _) => tx.fields.gas_limit,
            Self::Eip1559(tx, _) => tx.fields.gas_limit,
            Self::Eip7702(tx, _) => tx.fields.gas_limit,
        }
    }

    /// The destination (call or create).
    #[must_use]
    pub fn to(&self) -> TxKind {
        match self {
            Self::Legacy(tx, _) => tx.fields.to,
            Self::Eip2930(tx, _) => tx.fields.to,
            Self::Eip1559(tx, _) => tx.fields.to,
            Self::Eip7702(tx, _) => tx.fields.to,
        }
    }

    /// The value to transfer (in wei).
    #[must_use]
    pub fn value(&self) -> U256 {
        match self {
            Self::Legacy(tx, _) => tx.fields.value,
            Self::Eip2930(tx, _) => tx.fields.value,
            Self::Eip1559(tx, _) => tx.fields.value,
            Self::Eip7702(tx, _) => tx.fields.value,
        }
    }

    /// The calldata / init code.
    #[must_use]
    pub fn data(&self) -> &Bytes {
        match self {
            Self::Legacy(tx, _) => &tx.fields.data,
            Self::Eip2930(tx, _) => &tx.fields.data,
            Self::Eip1559(tx, _) => &tx.fields.data,
            Self::Eip7702(tx, _) => &tx.fields.data,
        }
    }

    /// The maximum fee per gas the sender is willing to pay (in wei).
    /// For legacy txs, this is the gas price. For EIP-1559, it's the
    /// max fee per gas.
    #[must_use]
    pub fn max_fee_per_gas(&self) -> U256 {
        match self {
            Self::Legacy(tx, _) => tx.gas_price,
            Self::Eip2930(tx, _) => tx.gas_price,
            Self::Eip1559(tx, _) => tx.max_fee_per_gas,
            Self::Eip7702(tx, _) => tx.max_fee_per_gas,
        }
    }

    /// The priority fee per gas (tip, in wei). For legacy and EIP-2930
    /// txs, the entire fee goes to the miner (no base fee concept).
    #[must_use]
    pub fn max_priority_fee_per_gas(&self) -> U256 {
        match self {
            Self::Legacy(tx, _) => tx.gas_price,
            Self::Eip2930(tx, _) => tx.gas_price,
            Self::Eip1559(tx, _) => tx.max_priority_fee_per_gas,
            Self::Eip7702(tx, _) => tx.max_priority_fee_per_gas,
        }
    }

    /// The access list (empty for legacy txs).
    #[must_use]
    pub fn access_list(&self) -> &AccessList {
        match self {
            Self::Legacy(_, _) => &EMPTY_ACCESS_LIST_VEC,
            Self::Eip2930(tx, _) => &tx.access_list,
            Self::Eip1559(tx, _) => &tx.access_list,
            Self::Eip7702(tx, _) => &tx.access_list,
        }
    }

    /// The EIP-7702 authorization list (empty for all other types).
    #[must_use]
    pub fn authorization_list(&self) -> &[TxAuthorization] {
        match self {
            Self::Eip7702(tx, _) => &tx.authorization_list,
            _ => &[],
        }
    }

    /// Compute the keccak256 hash of the signed transaction. This is
    /// the transaction hash used in Ethereum.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        let encoded = self.encode_to_vec();
        crypto::secp::keccak256(&encoded)
    }

    /// Recover the sender's Ethereum address from the signature.
    ///
    /// This is the core of EVM transaction authentication. The EVM
    /// module calls this inside `handle()` to establish the true
    /// sender, never trusting the envelope.
    ///
    /// # Errors
    ///
    /// Returns [`secp::SecpError`] if the signature is invalid or
    /// recovery fails.
    pub fn recover_sender(&self) -> Result<primitives::Address, secp::SecpError> {
        let signing_hash = self.signing_hash();
        let sig_bytes = self.signature_bytes();
        let recid = self.recid();
        let recovered = secp::recover_sender(&signing_hash, &sig_bytes, recid)?;
        Ok(primitives::Address(recovered.0))
    }

    /// Encode the signed transaction to a byte vector.
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        buf
    }

    /// The signing hash: keccak256 of the RLP-encoded unsigned tx
    /// (without the signature). This is what the signer signs.
    pub fn signing_hash(&self) -> [u8; 32] {
        let encoded = self.encode_unsigned();
        crypto::secp::keccak256(&encoded)
    }

    /// Encode the unsigned transaction (for signing hash computation).
    fn encode_unsigned(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::Legacy(tx, _) => {
                // rlp([nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0])
                let payload_len = u256_length(&U256::from(tx.fields.nonce))
                    + u256_length(&tx.gas_price)
                    + u256_length(&U256::from(tx.fields.gas_limit))
                    + tx.fields.to.length()
                    + u256_length(&tx.fields.value)
                    + tx.fields.data.length()
                    + u256_length(&U256::from(tx.fields.chain_id))
                    + u256_length(&U256::ZERO) // 0
                    + u256_length(&U256::ZERO); // 0
                Header { list: true, payload_length: payload_len }.encode(&mut buf);
                encode_u256(&U256::from(tx.fields.nonce), &mut buf);
                encode_u256(&tx.gas_price, &mut buf);
                encode_u256(&U256::from(tx.fields.gas_limit), &mut buf);
                tx.fields.to.encode(&mut buf);
                encode_u256(&tx.fields.value, &mut buf);
                tx.fields.data.encode(&mut buf);
                encode_u256(&U256::from(tx.fields.chain_id), &mut buf);
                encode_u256(&U256::ZERO, &mut buf);
                encode_u256(&U256::ZERO, &mut buf);
            }
            Self::Eip2930(tx, _) => {
                buf.push(TX_TYPE_EIP2930);
                let payload_len = u256_length(&U256::from(tx.fields.chain_id))
                    + u256_length(&U256::from(tx.fields.nonce))
                    + u256_length(&tx.gas_price)
                    + u256_length(&U256::from(tx.fields.gas_limit))
                    + tx.fields.to.length()
                    + u256_length(&tx.fields.value)
                    + tx.fields.data.length()
                    + access_list_length(&tx.access_list);
                Header { list: true, payload_length: payload_len }.encode(&mut buf);
                encode_u256(&U256::from(tx.fields.chain_id), &mut buf);
                encode_u256(&U256::from(tx.fields.nonce), &mut buf);
                encode_u256(&tx.gas_price, &mut buf);
                encode_u256(&U256::from(tx.fields.gas_limit), &mut buf);
                tx.fields.to.encode(&mut buf);
                encode_u256(&tx.fields.value, &mut buf);
                tx.fields.data.encode(&mut buf);
                encode_access_list(&tx.access_list, &mut buf);
            }
            Self::Eip1559(tx, _) => {
                buf.push(TX_TYPE_EIP1559);
                let payload_len = u256_length(&U256::from(tx.fields.chain_id))
                    + u256_length(&U256::from(tx.fields.nonce))
                    + u256_length(&tx.max_priority_fee_per_gas)
                    + u256_length(&tx.max_fee_per_gas)
                    + u256_length(&U256::from(tx.fields.gas_limit))
                    + tx.fields.to.length()
                    + u256_length(&tx.fields.value)
                    + tx.fields.data.length()
                    + access_list_length(&tx.access_list);
                Header { list: true, payload_length: payload_len }.encode(&mut buf);
                encode_u256(&U256::from(tx.fields.chain_id), &mut buf);
                encode_u256(&U256::from(tx.fields.nonce), &mut buf);
                encode_u256(&tx.max_priority_fee_per_gas, &mut buf);
                encode_u256(&tx.max_fee_per_gas, &mut buf);
                encode_u256(&U256::from(tx.fields.gas_limit), &mut buf);
                tx.fields.to.encode(&mut buf);
                encode_u256(&tx.fields.value, &mut buf);
                tx.fields.data.encode(&mut buf);
                encode_access_list(&tx.access_list, &mut buf);
            }
            Self::Eip7702(tx, _) => {
                buf.push(TX_TYPE_EIP7702);
                let payload_len = u256_length(&U256::from(tx.fields.chain_id))
                    + u256_length(&U256::from(tx.fields.nonce))
                    + u256_length(&tx.max_priority_fee_per_gas)
                    + u256_length(&tx.max_fee_per_gas)
                    + u256_length(&U256::from(tx.fields.gas_limit))
                    + tx.fields.to.length()
                    + u256_length(&tx.fields.value)
                    + tx.fields.data.length()
                    + access_list_length(&tx.access_list)
                    + authorization_list_length(&tx.authorization_list);
                Header { list: true, payload_length: payload_len }.encode(&mut buf);
                encode_u256(&U256::from(tx.fields.chain_id), &mut buf);
                encode_u256(&U256::from(tx.fields.nonce), &mut buf);
                encode_u256(&tx.max_priority_fee_per_gas, &mut buf);
                encode_u256(&tx.max_fee_per_gas, &mut buf);
                encode_u256(&U256::from(tx.fields.gas_limit), &mut buf);
                tx.fields.to.encode(&mut buf);
                encode_u256(&tx.fields.value, &mut buf);
                tx.fields.data.encode(&mut buf);
                encode_access_list(&tx.access_list, &mut buf);
                encode_authorization_list(&tx.authorization_list, &mut buf);
            }
        }
        buf
    }

    /// The 64-byte compact signature (r ‖ s).
    fn signature_bytes(&self) -> [u8; 64] {
        let sig = match self {
            Self::Legacy(_, s)
            | Self::Eip2930(_, s)
            | Self::Eip1559(_, s)
            | Self::Eip7702(_, s) => s,
        };
        let r_bytes = sig.r.to_be_bytes::<32>();
        let s_bytes = sig.s.to_be_bytes::<32>();
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&r_bytes);
        out[32..].copy_from_slice(&s_bytes);
        out
    }

    /// The recovery ID (0 or 1).
    fn recid(&self) -> u8 {
        match self {
            Self::Legacy(_, s)
            | Self::Eip2930(_, s)
            | Self::Eip1559(_, s)
            | Self::Eip7702(_, s) => s.recid.as_u8(),
        }
    }
}

/// A static empty access list for legacy transactions.
static EMPTY_ACCESS_LIST_VEC: AccessList = AccessList::new();

/// Convert a `secp::RecoverableSignature` to a `TxSignature`.
fn sig_to_txsig(sig: &secp::RecoverableSignature) -> TxSignature {
    TxSignature {
        r: U256::from_be_bytes({
            let a: [u8; 32] = sig.sig[..32].try_into().expect("sig is 64 bytes");
            a
        }),
        s: U256::from_be_bytes({
            let a: [u8; 32] = sig.sig[32..].try_into().expect("sig is 64 bytes");
            a
        }),
        recid: sig.recid,
    }
}

impl Encodable for SignedTx {
    fn encode(&self, out: &mut dyn BufMut) {
        match self {
            Self::Legacy(tx, sig) => {
                // Legacy: rlp([nonce, gas_price, gas_limit, to, value, data, v, r, s])
                // v = 35 + 2*chain_id + recid (EIP-155) or 27 + recid (pre-EIP-155).
                let v = if tx.fields.chain_id > 0 {
                    U256::from(35 + 2 * tx.fields.chain_id + u64::from(sig.recid.as_u8()))
                } else {
                    U256::from(27 + u64::from(sig.recid.as_u8()))
                };
                let payload_len = u256_length(&U256::from(tx.fields.nonce))
                    + u256_length(&tx.gas_price)
                    + u256_length(&U256::from(tx.fields.gas_limit))
                    + tx.fields.to.length()
                    + u256_length(&tx.fields.value)
                    + tx.fields.data.length()
                    + u256_length(&v)
                    + u256_length(&sig.r)
                    + u256_length(&sig.s);
                Header { list: true, payload_length: payload_len }.encode(out);
                encode_u256(&U256::from(tx.fields.nonce), out);
                encode_u256(&tx.gas_price, out);
                encode_u256(&U256::from(tx.fields.gas_limit), out);
                tx.fields.to.encode(out);
                encode_u256(&tx.fields.value, out);
                tx.fields.data.encode(out);
                encode_u256(&v, out);
                encode_u256(&sig.r, out);
                encode_u256(&sig.s, out);
            }
            Self::Eip2930(tx, sig) => {
                out.put_u8(TX_TYPE_EIP2930);
                let payload_len = u256_length(&U256::from(tx.fields.chain_id))
                    + u256_length(&U256::from(tx.fields.nonce))
                    + u256_length(&tx.gas_price)
                    + u256_length(&U256::from(tx.fields.gas_limit))
                    + tx.fields.to.length()
                    + u256_length(&tx.fields.value)
                    + tx.fields.data.length()
                    + access_list_length(&tx.access_list)
                    + u256_length(&U256::from(sig.recid.as_u8())) // y_parity
                    + u256_length(&sig.r)
                    + u256_length(&sig.s);
                Header { list: true, payload_length: payload_len }.encode(out);
                encode_u256(&U256::from(tx.fields.chain_id), out);
                encode_u256(&U256::from(tx.fields.nonce), out);
                encode_u256(&tx.gas_price, out);
                encode_u256(&U256::from(tx.fields.gas_limit), out);
                tx.fields.to.encode(out);
                encode_u256(&tx.fields.value, out);
                tx.fields.data.encode(out);
                encode_access_list(&tx.access_list, out);
                // y_parity: encode as an integer (0 or 1).
                encode_u256(&U256::from(sig.recid.as_u8()), out);
                encode_u256(&sig.r, out);
                encode_u256(&sig.s, out);
            }
            Self::Eip1559(tx, sig) => {
                out.put_u8(TX_TYPE_EIP1559);
                let payload_len = u256_length(&U256::from(tx.fields.chain_id))
                    + u256_length(&U256::from(tx.fields.nonce))
                    + u256_length(&tx.max_priority_fee_per_gas)
                    + u256_length(&tx.max_fee_per_gas)
                    + u256_length(&U256::from(tx.fields.gas_limit))
                    + tx.fields.to.length()
                    + u256_length(&tx.fields.value)
                    + tx.fields.data.length()
                    + access_list_length(&tx.access_list)
                    + u256_length(&U256::from(sig.recid.as_u8())) // y_parity
                    + u256_length(&sig.r)
                    + u256_length(&sig.s);
                Header { list: true, payload_length: payload_len }.encode(out);
                encode_u256(&U256::from(tx.fields.chain_id), out);
                encode_u256(&U256::from(tx.fields.nonce), out);
                encode_u256(&tx.max_priority_fee_per_gas, out);
                encode_u256(&tx.max_fee_per_gas, out);
                encode_u256(&U256::from(tx.fields.gas_limit), out);
                tx.fields.to.encode(out);
                encode_u256(&tx.fields.value, out);
                tx.fields.data.encode(out);
                encode_access_list(&tx.access_list, out);
                // y_parity: encode as an integer (0 or 1).
                encode_u256(&U256::from(sig.recid.as_u8()), out);
                encode_u256(&sig.r, out);
                encode_u256(&sig.s, out);
            }
            Self::Eip7702(tx, sig) => Self::encode_eip7702(tx, sig, out),
        }
    }
}

impl SignedTx {
    /// Encode a signed EIP-7702 transaction:
    /// `0x04 || rlp([chain_id, nonce, max_priority_fee, max_fee,
    /// gas_limit, destination, value, data, access_list,
    /// authorization_list, y_parity, r, s])`.
    fn encode_eip7702(tx: &TxEip7702, sig: &TxSignature, out: &mut dyn BufMut) {
        out.put_u8(TX_TYPE_EIP7702);
        let payload_len = u256_length(&U256::from(tx.fields.chain_id))
            + u256_length(&U256::from(tx.fields.nonce))
            + u256_length(&tx.max_priority_fee_per_gas)
            + u256_length(&tx.max_fee_per_gas)
            + u256_length(&U256::from(tx.fields.gas_limit))
            + tx.fields.to.length()
            + u256_length(&tx.fields.value)
            + tx.fields.data.length()
            + access_list_length(&tx.access_list)
            + authorization_list_length(&tx.authorization_list)
            + u256_length(&U256::from(sig.recid.as_u8())) // y_parity
            + u256_length(&sig.r)
            + u256_length(&sig.s);
        Header { list: true, payload_length: payload_len }.encode(out);
        encode_u256(&U256::from(tx.fields.chain_id), out);
        encode_u256(&U256::from(tx.fields.nonce), out);
        encode_u256(&tx.max_priority_fee_per_gas, out);
        encode_u256(&tx.max_fee_per_gas, out);
        encode_u256(&U256::from(tx.fields.gas_limit), out);
        tx.fields.to.encode(out);
        encode_u256(&tx.fields.value, out);
        tx.fields.data.encode(out);
        encode_access_list(&tx.access_list, out);
        encode_authorization_list(&tx.authorization_list, out);
        encode_u256(&U256::from(sig.recid.as_u8()), out);
        encode_u256(&sig.r, out);
        encode_u256(&sig.s, out);
    }
}

impl Decodable for SignedTx {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        if buf.is_empty() {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        // Check the first byte for typed transaction prefix.
        // Legacy txs start with 0xc0+ (RLP list header).
        let first_byte = buf[0];
        if first_byte == TX_TYPE_EIP2930 {
            Self::decode_eip2930(buf)
        } else if first_byte == TX_TYPE_EIP1559 {
            Self::decode_eip1559(buf)
        } else if first_byte == TX_TYPE_EIP7702 {
            Self::decode_eip7702(buf)
        } else {
            Self::decode_legacy(buf)
        }
    }
}

/// Fuzz fix: safely convert U256 to u64, returning an RLP error on
/// overflow instead of panicking. `U256::to::<u64>()` panics if the
/// value doesn't fit in u64.
fn u256_to_u64(v: U256) -> alloy_rlp::Result<u64> {
    u64::try_from(v).map_err(|_| alloy_rlp::Error::Custom("u256 overflow u64"))
}

impl SignedTx {
    /// Decode a `y_parity` value (0 or 1) from RLP-encoded U256.
    fn decode_recid(buf: &mut &[u8]) -> alloy_rlp::Result<secp::RecoveryId> {
        let yp = decode_u256(buf)?;
        let yp_u64 = u256_to_u64(yp)?;
        secp::RecoveryId::try_from_u8(
            u8::try_from(yp_u64).map_err(|_| alloy_rlp::Error::Custom("invalid y_parity"))?,
        )
        .map_err(|_| alloy_rlp::Error::Custom("invalid recovery id"))
    }

    /// Decode an EIP-2930 typed transaction.
    fn decode_eip2930(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        *buf = &buf[1..];
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let payload_len = header.payload_length;
        if buf.len() < payload_len {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        // Bound every field decode to the declared list payload —
        // a field can't bleed past the list's own length, and any
        // payload byte the fields don't consume is a decode error.
        // Without this bound, noncanonical encodings (a padded list
        // header, or a header shorter than the fields) decode to the
        // same transaction as the canonical form — two byte strings,
        // one tx, disagreeing hashes.
        let mut payload = &buf[..payload_len];
        let chain_id = decode_u256(&mut payload)?;
        let nonce = decode_u256(&mut payload)?;
        let gas_price = decode_u256(&mut payload)?;
        let gas_limit = decode_u256(&mut payload)?;
        let to = TxKind::decode(&mut payload)?;
        let value = decode_u256(&mut payload)?;
        let data = Bytes::decode(&mut payload)?;
        let access_list = decode_access_list(&mut payload)?;
        let recid = Self::decode_recid(&mut payload)?;
        let r = decode_u256(&mut payload)?;
        let s = decode_u256(&mut payload)?;
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        *buf = &buf[payload_len..];
        Ok(Self::Eip2930(
            TxEip2930 {
                fields: TxFields {
                    nonce: u256_to_u64(nonce)?,
                    gas_limit: u256_to_u64(gas_limit)?,
                    to,
                    value,
                    data,
                    chain_id: u256_to_u64(chain_id)?,
                },
                gas_price,
                access_list,
            },
            TxSignature { r, s, recid },
        ))
    }

    /// Decode an EIP-1559 typed transaction.
    fn decode_eip1559(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        *buf = &buf[1..];
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let payload_len = header.payload_length;
        if buf.len() < payload_len {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        // Same payload bound as `decode_eip2930`: fields can't bleed
        // past the declared list length, and unconsumed payload is
        // an error — one canonical byte string per transaction.
        let mut payload = &buf[..payload_len];
        let chain_id = decode_u256(&mut payload)?;
        let nonce = decode_u256(&mut payload)?;
        let max_priority_fee = decode_u256(&mut payload)?;
        let max_fee = decode_u256(&mut payload)?;
        let gas_limit = decode_u256(&mut payload)?;
        let to = TxKind::decode(&mut payload)?;
        let value = decode_u256(&mut payload)?;
        let data = Bytes::decode(&mut payload)?;
        let access_list = decode_access_list(&mut payload)?;
        let recid = Self::decode_recid(&mut payload)?;
        let r = decode_u256(&mut payload)?;
        let s = decode_u256(&mut payload)?;
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        *buf = &buf[payload_len..];
        Ok(Self::Eip1559(
            TxEip1559 {
                fields: TxFields {
                    nonce: u256_to_u64(nonce)?,
                    gas_limit: u256_to_u64(gas_limit)?,
                    to,
                    value,
                    data,
                    chain_id: u256_to_u64(chain_id)?,
                },
                max_priority_fee_per_gas: max_priority_fee,
                max_fee_per_gas: max_fee,
                access_list,
            },
            TxSignature { r, s, recid },
        ))
    }

    /// Decode an EIP-7702 typed transaction.
    ///
    /// Two spec-level constraints are enforced at decode time so a
    /// malformed type-4 payload never reaches execution:
    /// - `destination` is a mandatory 20-byte address — EIP-7702
    ///   forbids contract creation, so a `Create` (empty `to`) is a
    ///   decode error.
    /// - `authorization_list` must be non-empty — a type-4 tx with no
    ///   authorizations is invalid per the spec and rejected by
    ///   geth/reth alike.
    fn decode_eip7702(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        *buf = &buf[1..];
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let payload_len = header.payload_length;
        if buf.len() < payload_len {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        // Same payload bound as the other typed decoders: one
        // canonical byte string per transaction.
        let mut payload = &buf[..payload_len];
        let chain_id = decode_u256(&mut payload)?;
        let nonce = decode_u256(&mut payload)?;
        let max_priority_fee = decode_u256(&mut payload)?;
        let max_fee = decode_u256(&mut payload)?;
        let gas_limit = decode_u256(&mut payload)?;
        // EIP-7702: `to` is a mandatory address, not TxKind — an
        // empty-string `to` (Create) fails Address::decode.
        let to = Address::decode(&mut payload)?;
        let value = decode_u256(&mut payload)?;
        let data = Bytes::decode(&mut payload)?;
        let access_list = decode_access_list(&mut payload)?;
        let authorization_list = decode_authorization_list(&mut payload)?;
        if authorization_list.is_empty() {
            return Err(alloy_rlp::Error::Custom("empty authorization list"));
        }
        let recid = Self::decode_recid(&mut payload)?;
        let r = decode_u256(&mut payload)?;
        let s = decode_u256(&mut payload)?;
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        *buf = &buf[payload_len..];
        Ok(Self::Eip7702(
            TxEip7702 {
                fields: TxFields {
                    nonce: u256_to_u64(nonce)?,
                    gas_limit: u256_to_u64(gas_limit)?,
                    to: TxKind::Call(to),
                    value,
                    data,
                    chain_id: u256_to_u64(chain_id)?,
                },
                max_priority_fee_per_gas: max_priority_fee,
                max_fee_per_gas: max_fee,
                access_list,
                authorization_list,
            },
            TxSignature { r, s, recid },
        ))
    }

    /// Decode a legacy (pre-EIP-155 or EIP-155) transaction.
    fn decode_legacy(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        let payload_len = header.payload_length;
        if buf.len() < payload_len {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        // Same payload bound as the typed decoders: fields can't
        // bleed past the declared list length and unconsumed payload
        // is an error — one canonical byte string per transaction.
        let mut payload = &buf[..payload_len];
        let nonce = decode_u256(&mut payload)?;
        let gas_price = decode_u256(&mut payload)?;
        let gas_limit = decode_u256(&mut payload)?;
        let to = TxKind::decode(&mut payload)?;
        let value = decode_u256(&mut payload)?;
        let data = Bytes::decode(&mut payload)?;
        let v = decode_u256(&mut payload)?;
        let r = decode_u256(&mut payload)?;
        let s = decode_u256(&mut payload)?;
        if !payload.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        *buf = &buf[payload_len..];
        // Decode v: pre-EIP-155 (27/28) or EIP-155 (35 + 2*chain_id + recid).
        // Fuzz fix: U256::to::<u64>() panics if the value doesn't fit
        // in u64. Use the safe helper.
        let v_u64: u64 = u256_to_u64(v)?;
        let (chain_id, recid) = if v_u64 == 27 || v_u64 == 28 {
            (0, v_u64 - 27)
        } else if v_u64 >= 35 {
            let recid = (v_u64 - 35) % 2;
            let chain_id = (v_u64 - 35 - recid) / 2;
            (chain_id, recid)
        } else {
            return Err(alloy_rlp::Error::Custom("invalid v value"));
        };
        let recid = secp::RecoveryId::try_from_u8(
            u8::try_from(recid).map_err(|_| alloy_rlp::Error::Custom("invalid recid"))?,
        )
        .map_err(|_| alloy_rlp::Error::Custom("invalid recovery id"))?;
        Ok(Self::Legacy(
            TxLegacy {
                fields: TxFields {
                    nonce: u256_to_u64(nonce)?,
                    gas_limit: u256_to_u64(gas_limit)?,
                    to,
                    value,
                    data,
                    chain_id,
                },
                gas_price,
            },
            TxSignature { r, s, recid },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::secp;

    /// Create a test signer with a fixed private key.
    fn make_signer() -> ([u8; 32], primitives::Address) {
        secp::generate_keypair_for_test()
    }

    /// Sign a legacy `TxLegacy` and return the `SignedTx`.
    fn sign_legacy(privkey: &[u8], tx: TxLegacy) -> SignedTx {
        let dummy_sig = TxSignature { r: U256::ZERO, s: U256::ZERO, recid: RecoveryId::new(0) };
        let temp = SignedTx::Legacy(tx.clone(), dummy_sig);
        let signing_hash = temp.signing_hash();
        let sig = secp::sign(privkey, &signing_hash).expect("sign must succeed");
        SignedTx::Legacy(tx, sig_to_txsig(&sig))
    }

    /// Sign an EIP-1559 `TxEip1559` and return the `SignedTx`.
    fn sign_1559(privkey: &[u8], tx: TxEip1559) -> SignedTx {
        let dummy_sig = TxSignature { r: U256::ZERO, s: U256::ZERO, recid: RecoveryId::new(0) };
        let temp = SignedTx::Eip1559(tx.clone(), dummy_sig);
        let signing_hash = temp.signing_hash();
        let sig = secp::sign(privkey, &signing_hash).expect("sign must succeed");
        SignedTx::Eip1559(tx, sig_to_txsig(&sig))
    }

    #[test]
    fn legacy_tx_round_trip_and_recover() {
        let (privkey, expected_addr) = make_signer();
        let to = TxKind::Call(Address::from([0x42; 20]));
        let signed = sign_legacy(
            &privkey,
            TxLegacy {
                fields: TxFields {
                    nonce: 0,
                    gas_limit: 21000,
                    to,
                    value: U256::from(1000),
                    data: Bytes::new(),
                    chain_id: 1,
                },
                gas_price: U256::from(1_000_000_000),
            },
        );
        // Recover sender.
        let recovered = signed.recover_sender().expect("recover must succeed");
        assert_eq!(recovered, expected_addr, "recovered address must match");
        // RLP round-trip.
        let mut encoded = Vec::new();
        signed.encode(&mut encoded);
        let mut buf = encoded.as_slice();
        let decoded = SignedTx::decode(&mut buf).expect("decode must succeed");
        assert_eq!(decoded, signed, "decoded tx must match original");
        // Recover from decoded.
        let recovered2 = decoded.recover_sender().expect("recover from decoded must succeed");
        assert_eq!(recovered2, expected_addr);
    }

    #[test]
    fn eip1559_tx_round_trip_and_recover() {
        let (privkey, expected_addr) = make_signer();
        let to = TxKind::Call(Address::from([0x42; 20]));
        let signed = sign_1559(
            &privkey,
            TxEip1559 {
                fields: TxFields {
                    nonce: 0,
                    gas_limit: 21000,
                    to,
                    value: U256::from(1000),
                    data: Bytes::new(),
                    chain_id: 1,
                },
                max_priority_fee_per_gas: U256::from(1_000_000_000),
                max_fee_per_gas: U256::from(2_000_000_000),
                access_list: Vec::new(),
            },
        );
        let recovered = signed.recover_sender().expect("recover must succeed");
        assert_eq!(recovered, expected_addr);
        let mut encoded = Vec::new();
        signed.encode(&mut encoded);
        assert_eq!(encoded[0], TX_TYPE_EIP1559, "EIP-1559 tx must start with 0x02");
        let mut buf = encoded.as_slice();
        let decoded = SignedTx::decode(&mut buf).expect("decode must succeed");
        assert_eq!(decoded, signed);
        let recovered2 = decoded.recover_sender().expect("recover from decoded must succeed");
        assert_eq!(recovered2, expected_addr);
    }

    #[test]
    fn legacy_contract_creation_round_trip() {
        let (privkey, expected_addr) = make_signer();
        let to = TxKind::Create;
        let signed = sign_legacy(
            &privkey,
            TxLegacy {
                fields: TxFields {
                    nonce: 0,
                    gas_limit: 500_000,
                    to,
                    value: U256::ZERO,
                    data: Bytes::from(vec![0x60, 0x80, 0x60, 0x40, 0x52]),
                    chain_id: 1,
                },
                gas_price: U256::from(1_000_000_000),
            },
        );
        let recovered = signed.recover_sender().expect("recover must succeed");
        assert_eq!(recovered, expected_addr);
        let mut encoded = Vec::new();
        signed.encode(&mut encoded);
        let mut buf = encoded.as_slice();
        let decoded = SignedTx::decode(&mut buf).expect("decode must succeed");
        assert_eq!(decoded, signed);
        assert!(matches!(decoded.to(), TxKind::Create));
    }

    #[test]
    fn eip1559_contract_creation_round_trip() {
        let (privkey, expected_addr) = make_signer();
        let to = TxKind::Create;
        let signed = sign_1559(
            &privkey,
            TxEip1559 {
                fields: TxFields {
                    nonce: 0,
                    gas_limit: 500_000,
                    to,
                    value: U256::ZERO,
                    data: Bytes::from(vec![0x60, 0x80, 0x60, 0x40, 0x52]),
                    chain_id: 1,
                },
                max_priority_fee_per_gas: U256::from(1_000_000_000),
                max_fee_per_gas: U256::from(2_000_000_000),
                access_list: Vec::new(),
            },
        );
        let recovered = signed.recover_sender().expect("recover must succeed");
        assert_eq!(recovered, expected_addr);
        let mut encoded = Vec::new();
        signed.encode(&mut encoded);
        let mut buf = encoded.as_slice();
        let decoded = SignedTx::decode(&mut buf).expect("decode must succeed");
        assert_eq!(decoded, signed);
        assert!(matches!(decoded.to(), TxKind::Create));
    }

    #[test]
    fn tx_hash_is_deterministic() {
        let (privkey, _) = make_signer();
        let to = TxKind::Call(Address::from([0x42; 20]));
        let signed = sign_legacy(
            &privkey,
            TxLegacy {
                fields: TxFields {
                    nonce: 0,
                    gas_limit: 21000,
                    to,
                    value: U256::from(1000),
                    data: Bytes::new(),
                    chain_id: 1,
                },
                gas_price: U256::from(1_000_000_000),
            },
        );
        let hash1 = signed.hash();
        let hash2 = signed.hash();
        assert_eq!(hash1, hash2, "tx hash must be deterministic");
    }

    #[test]
    fn different_txs_have_different_hashes() {
        let (privkey, _) = make_signer();
        let to = TxKind::Call(Address::from([0x42; 20]));
        let tx1 = sign_legacy(
            &privkey,
            TxLegacy {
                fields: TxFields {
                    nonce: 0,
                    gas_limit: 21000,
                    to,
                    value: U256::from(1000),
                    data: Bytes::new(),
                    chain_id: 1,
                },
                gas_price: U256::from(1_000_000_000),
            },
        );
        let tx2 = sign_legacy(
            &privkey,
            TxLegacy {
                fields: TxFields {
                    nonce: 1,
                    gas_limit: 21000,
                    to,
                    value: U256::from(1000),
                    data: Bytes::new(),
                    chain_id: 1,
                },
                gas_price: U256::from(1_000_000_000),
            },
        );
        assert_ne!(tx1.hash(), tx2.hash(), "different nonces must have different hashes");
    }

    #[test]
    fn chain_id_enforced_in_legacy_v() {
        let (privkey, _) = make_signer();
        let to = TxKind::Call(Address::from([0x42; 20]));
        let signed = sign_legacy(
            &privkey,
            TxLegacy {
                fields: TxFields {
                    nonce: 0,
                    gas_limit: 21000,
                    to,
                    value: U256::from(1000),
                    data: Bytes::new(),
                    chain_id: 1,
                },
                gas_price: U256::from(1_000_000_000),
            },
        );
        assert_eq!(signed.chain_id(), 1, "chain ID must be 1");
        // Encode and decode to verify v encodes chain_id correctly.
        let mut encoded = Vec::new();
        signed.encode(&mut encoded);
        let mut buf = encoded.as_slice();
        let decoded = SignedTx::decode(&mut buf).expect("decode must succeed");
        assert_eq!(decoded.chain_id(), 1, "decoded chain ID must be 1");
    }

    #[test]
    fn access_list_round_trip() {
        let (privkey, expected_addr) = make_signer();
        let to = TxKind::Call(Address::from([0x42; 20]));
        let access_list = vec![AccessListItem {
            address: Address::from([0xab; 20]),
            storage_keys: vec![
                revm::primitives::B256::from([0x01; 32]),
                revm::primitives::B256::from([0x02; 32]),
            ],
        }];
        let tx = TxEip1559 {
            fields: TxFields {
                nonce: 0,
                gas_limit: 21000,
                to,
                value: U256::ZERO,
                data: Bytes::new(),
                chain_id: 1,
            },
            max_priority_fee_per_gas: U256::from(1_000_000_000),
            max_fee_per_gas: U256::from(2_000_000_000),
            access_list,
        };
        let dummy_sig = TxSignature { r: U256::ZERO, s: U256::ZERO, recid: RecoveryId::new(0) };
        let temp = SignedTx::Eip1559(tx.clone(), dummy_sig);
        let signing_hash = temp.signing_hash();
        let sig = secp::sign(&privkey, &signing_hash).expect("sign must succeed");
        let signed = SignedTx::Eip1559(
            tx,
            TxSignature {
                r: U256::from_be_bytes({
                    let a: [u8; 32] = sig.sig[..32].try_into().unwrap();
                    a
                }),
                s: U256::from_be_bytes({
                    let a: [u8; 32] = sig.sig[32..].try_into().unwrap();
                    a
                }),
                recid: sig.recid,
            },
        );
        let recovered = signed.recover_sender().expect("recover must succeed");
        assert_eq!(recovered, expected_addr);
        let mut encoded = Vec::new();
        signed.encode(&mut encoded);
        let mut buf = encoded.as_slice();
        let decoded = SignedTx::decode(&mut buf).expect("decode must succeed");
        assert_eq!(decoded, signed);
        assert_eq!(decoded.access_list().len(), 1, "access list must have 1 item");
        assert_eq!(decoded.access_list()[0].storage_keys.len(), 2, "must have 2 storage keys");
    }

    #[test]
    fn tx_kind_create_encodes_as_empty_string() {
        let mut buf = Vec::new();
        TxKind::Create.encode(&mut buf);
        assert_eq!(buf, vec![0x80], "Create must encode as 0x80 (empty string)");
        let mut slice = buf.as_slice();
        let decoded = TxKind::decode(&mut slice).expect("decode must succeed");
        assert!(matches!(decoded, TxKind::Create));
    }

    #[test]
    fn tx_kind_call_encodes_as_address() {
        let addr = Address::from([0x42; 20]);
        let mut buf = Vec::new();
        TxKind::Call(addr).encode(&mut buf);
        // 20 bytes with a 0x14 prefix (single-byte length).
        assert_eq!(buf[0], 0x94, "Call must encode with 0x94 prefix (0x80+20 bytes)");
        let mut slice = buf.as_slice();
        let decoded = TxKind::decode(&mut slice).expect("decode must succeed");
        assert!(matches!(decoded, TxKind::Call(a) if a == addr));
    }

    #[test]
    fn eip7702_tx_round_trip_and_recover() {
        let (privkey, expected_addr) = make_signer();
        let (auth_privkey, expected_authority) = make_signer();
        let delegate = Address::from([0x77; 20]);
        let auth = TxAuthorization::sign(U256::from(1), delegate, 0, &auth_privkey)
            .expect("auth sign must succeed");
        // The authority recovered from the tuple is the signing EOA.
        assert_eq!(
            auth.recover_authority().expect("authority recovery"),
            Address::from(expected_authority.0)
        );
        let signed = SignedTx::sign_eip7702(
            TxEip7702 {
                fields: TxFields {
                    nonce: 0,
                    gas_limit: 100_000,
                    to: TxKind::Call(Address::from([0x42; 20])),
                    value: U256::ZERO,
                    data: Bytes::new(),
                    chain_id: 1,
                },
                max_priority_fee_per_gas: U256::from(1_000_000_000),
                max_fee_per_gas: U256::from(2_000_000_000),
                access_list: Vec::new(),
                authorization_list: vec![auth],
            },
            &privkey,
        )
        .expect("7702 sign must succeed");
        assert_eq!(signed.tx_type(), TX_TYPE_EIP7702);
        let recovered = signed.recover_sender().expect("recover must succeed");
        assert_eq!(recovered, expected_addr);
        let mut encoded = Vec::new();
        signed.encode(&mut encoded);
        assert_eq!(encoded[0], TX_TYPE_EIP7702, "EIP-7702 tx must start with 0x04");
        let mut buf = encoded.as_slice();
        let decoded = SignedTx::decode(&mut buf).expect("decode must succeed");
        assert_eq!(decoded, signed);
        assert_eq!(decoded.authorization_list().len(), 1);
        assert_eq!(decoded.authorization_list()[0].address, delegate);
        // The decoded authorization still recovers the same authority.
        assert_eq!(
            decoded.authorization_list()[0]
                .recover_authority()
                .expect("authority recovery after decode"),
            Address::from(expected_authority.0)
        );
    }

    #[test]
    fn eip7702_rejects_create_and_empty_auth_list() {
        // `to` = empty string (Create) must fail Address::decode.
        // Build the RLP manually: 0x04 || rlp([..., 0x80, ...]).
        let mut inner = Vec::new();
        encode_u256(&U256::from(1), &mut inner); // chain_id
        encode_u256(&U256::ZERO, &mut inner); // nonce
        encode_u256(&U256::from(1), &mut inner); // max_priority
        encode_u256(&U256::from(1), &mut inner); // max_fee
        encode_u256(&U256::from(21000), &mut inner); // gas
        Header { list: false, payload_length: 0 }.encode(&mut inner); // to = ""
        encode_u256(&U256::ZERO, &mut inner); // value
        Header { list: false, payload_length: 0 }.encode(&mut inner); // data = ""
        Header { list: true, payload_length: 0 }.encode(&mut inner); // acl = []
        // One valid authorization so only the `to` check can fail.
        let (auth_privkey, _) = make_signer();
        let auth =
            TxAuthorization::sign(U256::from(1), Address::from([0x77; 20]), 0, &auth_privkey)
                .expect("auth sign");
        encode_authorization_list(&[auth], &mut inner);
        encode_u256(&U256::ZERO, &mut inner); // y_parity
        encode_u256(&U256::from(1), &mut inner); // r
        encode_u256(&U256::from(1), &mut inner); // s
        let mut raw = vec![TX_TYPE_EIP7702];
        Header { list: true, payload_length: inner.len() }.encode(&mut raw);
        raw.extend_from_slice(&inner);
        assert!(
            SignedTx::decode_raw(&raw).is_err(),
            "type-4 tx with Create destination must be rejected"
        );

        // Empty authorization list must be rejected.
        let mut inner2 = Vec::new();
        encode_u256(&U256::from(1), &mut inner2);
        encode_u256(&U256::ZERO, &mut inner2);
        encode_u256(&U256::from(1), &mut inner2);
        encode_u256(&U256::from(1), &mut inner2);
        encode_u256(&U256::from(21000), &mut inner2);
        Address::from([0x42; 20]).encode(&mut inner2);
        encode_u256(&U256::ZERO, &mut inner2);
        Header { list: false, payload_length: 0 }.encode(&mut inner2);
        Header { list: true, payload_length: 0 }.encode(&mut inner2); // acl
        Header { list: true, payload_length: 0 }.encode(&mut inner2); // auths = []
        encode_u256(&U256::ZERO, &mut inner2);
        encode_u256(&U256::from(1), &mut inner2);
        encode_u256(&U256::from(1), &mut inner2);
        let mut raw2 = vec![TX_TYPE_EIP7702];
        Header { list: true, payload_length: inner2.len() }.encode(&mut raw2);
        raw2.extend_from_slice(&inner2);
        assert!(
            SignedTx::decode_raw(&raw2).is_err(),
            "type-4 tx with empty authorization list must be rejected"
        );
    }

    /// A signed EIP-1559 test tx plus the offset of its RLP list
    /// header in the encoding (`1` — after the type byte).
    fn signed_1559_bytes() -> Vec<u8> {
        let (privkey, _) = make_signer();
        let tx = TxEip1559 {
            fields: TxFields {
                nonce: 0,
                gas_limit: 21_000,
                to: TxKind::Call(Address::from([0x42; 20])),
                value: U256::ZERO,
                data: Bytes::new(),
                chain_id: 1,
            },
            max_priority_fee_per_gas: U256::from(1_000_000_000),
            max_fee_per_gas: U256::from(2_000_000_000),
            access_list: Vec::new(),
        };
        SignedTx::sign_eip1559(tx, &privkey).expect("sign").encode_to_bytes()
    }

    /// Split `type || header || payload` into (declared payload
    /// length, payload bytes). `hdr_offset` is 1 for typed txs, 0
    /// for legacy (no type byte).
    fn split_encoding(raw: &[u8], hdr_offset: usize) -> (usize, &[u8]) {
        let mut hdr_buf = &raw[hdr_offset..];
        let header = Header::decode(&mut hdr_buf).expect("list header");
        let payload = &raw[raw.len() - header.payload_length..];
        (header.payload_length, payload)
    }

    /// The 1.5 regression: an RLP list header that declares MORE
    /// payload than the fields consume must fail to decode —
    /// previously fields were read from the outer buffer, so the
    /// overstated bytes became a silently-tolerated cursor
    /// remainder on the executor path while RPC's `decode_raw`
    /// trailing check rejected the same bytes. Two byte strings
    /// decoded to the same tx, and only one route rejected them.
    #[test]
    fn decode_rejects_overstated_list_payload() {
        let raw = signed_1559_bytes();
        let (payload_len, payload) = split_encoding(&raw, 1);

        // Forge: declare 2 extra payload bytes, append 2 junk bytes.
        let mut forged = vec![raw[0]];
        Header { list: true, payload_length: payload_len + 2 }.encode(&mut forged);
        forged.extend_from_slice(payload);
        forged.extend_from_slice(&[0xde, 0xad]);

        assert!(
            SignedTx::decode_raw(&forged).is_err(),
            "an overstated list payload must fail — the declared \
             bytes the fields don't consume are noncanonical"
        );
        // The raw `Decodable` entry point must agree — execution and
        // RPC can no longer disagree about the same bytes.
        let mut cur: &[u8] = &forged;
        assert!(
            <SignedTx as alloy_rlp::Decodable>::decode(&mut cur).is_err(),
            "the streaming decoder must bound fields to the declared payload too"
        );
    }

    /// A list header declaring LESS payload than the fields consume
    /// must fail — previously the fields just bled past the declared
    /// boundary into whatever followed.
    #[test]
    fn decode_rejects_underestated_list_payload() {
        let raw = signed_1559_bytes();
        let (payload_len, payload) = split_encoding(&raw, 1);

        let mut forged = vec![raw[0]];
        Header { list: true, payload_length: payload_len - 4 }.encode(&mut forged);
        forged.extend_from_slice(payload);

        assert!(
            SignedTx::decode_raw(&forged).is_err(),
            "an understated list payload must fail — fields can't \
             bleed past the declared boundary"
        );
    }

    /// Legacy transactions carry no type byte — the same payload
    /// bound applies to their top-level list.
    #[test]
    fn decode_legacy_rejects_overstated_list_payload() {
        let (privkey, _) = make_signer();
        let tx = TxLegacy {
            fields: TxFields {
                nonce: 0,
                gas_limit: 21_000,
                to: TxKind::Call(Address::from([0x42; 20])),
                value: U256::ZERO,
                data: Bytes::new(),
                chain_id: 1,
            },
            gas_price: U256::from(1_000_000_000),
        };
        let raw = sign_legacy(&privkey, tx).encode_to_bytes();
        let (payload_len, payload) = split_encoding(&raw, 0);

        let mut forged = Vec::new();
        Header { list: true, payload_length: payload_len + 2 }.encode(&mut forged);
        forged.extend_from_slice(payload);
        forged.extend_from_slice(&[0xde, 0xad]);

        assert!(SignedTx::decode_raw(&forged).is_err(), "legacy overstated list payload must fail");
        let mut cur: &[u8] = &forged;
        assert!(<SignedTx as alloy_rlp::Decodable>::decode(&mut cur).is_err());
    }

    /// Sanity: the canonical encodings still round-trip — the bounds
    /// reject noncanonical bytes, not valid transactions.
    #[test]
    fn decode_accepts_canonical_encodings() {
        let raw = signed_1559_bytes();
        SignedTx::decode_raw(&raw).expect("canonical 1559 tx must decode");
        let (privkey, _) = make_signer();
        let legacy = sign_legacy(
            &privkey,
            TxLegacy {
                fields: TxFields {
                    nonce: 0,
                    gas_limit: 21_000,
                    to: TxKind::Create,
                    value: U256::ZERO,
                    data: Bytes::new(),
                    chain_id: 1,
                },
                gas_price: U256::from(1_000_000_000),
            },
        );
        SignedTx::decode_raw(&legacy.encode_to_bytes()).expect("canonical legacy tx must decode");
    }
}
