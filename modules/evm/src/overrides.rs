//! Per-call state overrides — geth's `stateOverride` semantics for
//! `eth_call`/`eth_estimateGas`.
//!
//! geth's call APIs accept a third argument mapping
//! `address → {balance?, nonce?, code?, state?, stateDiff?}` that
//! replaces account fields (or storage) for the duration of one
//! simulation — the standard trick for "what would this call do if
//! the account had code/funds/this slot set". The overrides must
//! never touch the authoritative store: they are applied by
//! [`OverrideView`], a read-only [`DatabaseRef`] wrapper that
//! answers overridden fields from a side table and delegates
//! everything else.
//!
//! # Field semantics (geth `OverrideAccount` parity)
//!
//! - `balance`, `nonce` — replace the field outright.
//! - `code` — replace the account code; `code_hash` is recomputed
//!   as `keccak(code)` and the blob is registered in
//!   `extra_code` so `code_by_hash` resolves it.
//! - `state` — **replace** the account's whole storage map:
//!   unlisted slots read as zero even if the base state has a
//!   value.
//! - `stateDiff` — **merge**: listed slots override, unlisted
//!   slots delegate to base state.
//! - `state` and `stateDiff` together are rejected by the RPC
//!   parser (geth returns "both state and stateDiff given").
//!
//! An overridden account that does not exist in base state still
//! reads as existing (zero-filled then field-replaced) — geth
//! creates the account implicitly.

use std::collections::BTreeMap;

use revm::bytecode::Bytecode;
use revm::database::DatabaseRef;
use revm::database::state::AccountInfo;
use revm::primitives::{Address, B256, U256};

/// One account's override entry — every field optional, absent
/// fields delegate to base state.
#[derive(Debug, Clone, Default)]
pub struct AccountOverride {
    /// Balance replacement (wei).
    pub balance: Option<U256>,
    /// Nonce replacement.
    pub nonce: Option<u64>,
    /// Code replacement — the account behaves as a contract.
    /// Raw initcode/runtime bytes; [`OverrideView`] wraps them in
    /// `Bytecode` and registers the `keccak` so `code_by_hash`
    /// resolves.
    pub code: Option<Vec<u8>>,
    /// Full storage replacement (`state`). Mutually exclusive
    /// with [`state_diff`](Self::state_diff).
    pub state: Option<BTreeMap<U256, U256>>,
    /// Per-slot storage merge (`stateDiff`).
    pub state_diff: Option<BTreeMap<U256, U256>>,
}

/// `address → override` for one simulation. `BTreeMap` keeps the
/// type deterministic (address-ordered) for free.
pub type StateOverrides = BTreeMap<Address, AccountOverride>;

/// A [`DatabaseRef`] that answers overridden account/storage/code
/// reads from a [`StateOverrides`] table and delegates everything
/// else. Purely read-only — simulation writes land in the
/// `CacheDB` layered on top, so neither the wrapped store nor the
/// override table is ever mutated.
pub(crate) struct OverrideView<'a, D> {
    /// The base state view (live `CacheDB` via `SharedCacheDB`,
    /// or a `versioned::StateView` for historical calls).
    inner: D,
    /// The parsed override table.
    overrides: &'a StateOverrides,
    /// `keccak(code) → bytecode` for every `code` override —
    /// `basic_ref` returns the hash; `code_by_hash_ref` must be
    /// able to resolve it.
    extra_code: BTreeMap<B256, Bytecode>,
}

impl<'a, D> OverrideView<'a, D> {
    /// Wrap `inner` with `overrides`. Precomputes the `extra_code`
    /// index once so `code_by_hash_ref` is a map lookup.
    pub(crate) fn new(inner: D, overrides: &'a StateOverrides) -> Self {
        let extra_code = overrides
            .values()
            .filter_map(|o| o.code.as_ref())
            .map(|raw| {
                let code = Bytecode::new_raw(raw.clone().into());
                (code.hash_slow(), code)
            })
            .collect();
        Self { inner, overrides, extra_code }
    }
}

impl<D: DatabaseRef> DatabaseRef for OverrideView<'_, D> {
    type Error = D::Error;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let base = self.inner.basic_ref(address)?;
        let Some(ovr) = self.overrides.get(&address) else { return Ok(base) };
        // An override on a missing account creates it implicitly
        // (geth semantics) — start from a zeroed AccountInfo.
        let mut info = base.unwrap_or_default();
        if let Some(balance) = ovr.balance {
            info.balance = balance;
        }
        if let Some(nonce) = ovr.nonce {
            info.nonce = nonce;
        }
        if let Some(raw) = &ovr.code {
            let code = Bytecode::new_raw(raw.clone().into());
            info.code_hash = code.hash_slow();
            info.code = Some(code);
        }
        Ok(Some(info))
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if let Some(code) = self.extra_code.get(&code_hash) {
            return Ok(code.clone());
        }
        self.inner.code_by_hash_ref(code_hash)
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let Some(ovr) = self.overrides.get(&address) else {
            return self.inner.storage_ref(address, index);
        };
        // `state` replaces the whole map: unlisted slots are zero.
        if let Some(state) = &ovr.state {
            return Ok(state.get(&index).copied().unwrap_or_default());
        }
        if let Some(v) = ovr.state_diff.as_ref().and_then(|d| d.get(&index)) {
            return Ok(*v);
        }
        self.inner.storage_ref(address, index)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash_ref(number)
    }
}
