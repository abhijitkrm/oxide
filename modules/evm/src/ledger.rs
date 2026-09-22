//! The EVM account store as the chain's single balance ledger.
//!
//! `framework::Balances` is implemented on [`EvmModule`] by mutating
//! `CacheDB` account balances directly — the same store EVM execution
//! reads and writes — so native module settlement (staking bonds,
//! exchange fills, perps margin, envelope fees) and EVM state always
//! observe one money supply. There is no second ledger.
//!
//! Two mutation paths exist and must never be mixed:
//!
//! - **Out-of-transaction** — this impl: native-tx `handle` calls,
//!   the executor's `charge_fee`, and `end_block` bookkeeping. Each
//!   write captures the account's pre-state into `block_undo` (the
//!   mechanism block replay and historical reads use) and marks the
//!   account `touched` so `state_root` and `flush_to_storage` see
//!   the change.
//! - **In-transaction** — [`crate::precompiles::JournalBalances`]:
//!   mutations go through revm's own journal so a reverting frame
//!   undoes them automatically. Writing the cache directly mid-frame
//!   would race with — and be clobbered by — revm's journaled
//!   `result.state` on commit.

use std::sync::Arc;

use executor::ExecError;
use framework::{Balances, WEI_PER_UNIT};
use primitives::Address;
use revm::primitives::U256;

use crate::{EvmModule, alloy_primitives_address};

/// Convert `u64` base units to wei — always exact (`u64::MAX` units
/// is ~1.8×10²⁸ wei, far inside `U256`).
fn units_to_wei(units: u64) -> U256 {
    U256::from(units) * U256::from(WEI_PER_UNIT)
}

/// Convert wei to base units, rounding down the sub-unit remainder
/// and saturating at `u64::MAX`.
///
/// The floor is deliberate: wei dust below one base unit (left by
/// wei-granularity EVM operations like gas refunds) is real value on
/// the ledger but too small for the `u64` module API to express. It
/// stays on the account, visible to EVM operations, and simply does
/// not participate in base-unit settlement.
fn wei_to_units(wei: U256) -> u64 {
    (wei / U256::from(WEI_PER_UNIT)).saturating_to::<u64>()
}

fn insufficient(addr: &Address, have: U256, want: U256) -> ExecError {
    ExecError::ModuleRejected(format!("ledger: {addr:?} has {have} wei, needs {want} wei"))
}

impl EvmModule {
    /// Set `evm_addr`'s balance to `next` wei with full block
    /// bookkeeping: undo capture (pre-state), `AccountState::Touched`,
    /// `KECCAK_EMPTY` normalization, and `touched` marking — identical
    /// to how committed EVM execution results merge into the cache
    /// (see the transfer fast-path in `execute`).
    ///
    /// Callers hold the `db` lock; `block_undo` and `touched` are
    /// taken inside in db → undo → touched order, matching every
    /// other site (`begin_block`, `genesis_insert_account`), so lock
    /// ordering is uniform and deadlock-free.
    fn set_balance(&self, evm_addr: revm::primitives::Address, next: U256) {
        let mut db_guard = framework::lock_state(&self.db);
        let db = Arc::make_mut(&mut *db_guard);
        framework::lock_state(&self.block_undo).capture(evm_addr, db.cache.accounts.get(&evm_addr));
        let account =
            db.cache.accounts.entry(evm_addr).or_insert_with(|| revm::database::DbAccount {
                info: revm::database::state::AccountInfo {
                    balance: U256::ZERO,
                    nonce: 0,
                    code_hash: revm::primitives::KECCAK_EMPTY,
                    account_id: None,
                    code: Some(revm::bytecode::Bytecode::new_raw(revm::primitives::Bytes::new())),
                },
                account_state: revm::database::AccountState::Touched,
                storage: revm::primitives::HashMap::default(),
            });
        account.info.balance = next;
        if account.info.code_hash == revm::primitives::B256::ZERO {
            // `B256::ZERO` is the uninitialized sentinel; the trie
            // expects `KECCAK_EMPTY` for codeless accounts — the same
            // normalization the execute path applies.
            account.info.code_hash = revm::primitives::KECCAK_EMPTY;
        }
        account.account_state = revm::database::AccountState::Touched;
        drop(db_guard);
        framework::lock_state(&self.touched).insert(evm_addr);
    }

    /// Current balance of `evm_addr` in wei — `ZERO` for accounts
    /// absent from the cache (never-funded, or loaded lazily from an
    /// empty backend: either way the spendable balance is zero).
    fn balance_wei(&self, evm_addr: revm::primitives::Address) -> U256 {
        let db = framework::lock_state(&self.db);
        db.cache.accounts.get(&evm_addr).map_or(U256::ZERO, |a| a.info.balance)
    }
}

impl Balances for EvmModule {
    fn balance(&self, addr: &Address) -> u64 {
        wei_to_units(self.balance_wei(alloy_primitives_address(addr.0)))
    }

    fn debit(&self, addr: &Address, amount: u64) -> Result<(), ExecError> {
        let wei = units_to_wei(amount);
        if wei.is_zero() {
            return Ok(());
        }
        let evm_addr = alloy_primitives_address(addr.0);
        let current = self.balance_wei(evm_addr);
        let next = current.checked_sub(wei).ok_or_else(|| insufficient(addr, current, wei))?;
        self.set_balance(evm_addr, next);
        Ok(())
    }

    fn credit(&self, addr: &Address, amount: u64) -> Result<(), ExecError> {
        let wei = units_to_wei(amount);
        if wei.is_zero() {
            return Ok(());
        }
        let evm_addr = alloy_primitives_address(addr.0);
        let current = self.balance_wei(evm_addr);
        let next = current.checked_add(wei).ok_or_else(|| {
            ExecError::ModuleRejected(format!("ledger: {addr:?} balance overflows U256"))
        })?;
        self.set_balance(evm_addr, next);
        Ok(())
    }

    fn transfer(&self, from: &Address, to: &Address, amount: u64) -> Result<(), ExecError> {
        let wei = units_to_wei(amount);
        if wei.is_zero() {
            return Ok(());
        }
        let from_addr = alloy_primitives_address(from.0);
        let to_addr = alloy_primitives_address(to.0);
        if from_addr == to_addr {
            // A self-transfer only has to prove solvency; writing
            // `bal - wei` then `bal + wei` to the same entry would
            // race with itself.
            let bal = self.balance_wei(from_addr);
            return if bal >= wei { Ok(()) } else { Err(insufficient(from, bal, wei)) };
        }
        // Check both sides before writing either — all-or-nothing.
        let from_bal = self.balance_wei(from_addr);
        let new_from =
            from_bal.checked_sub(wei).ok_or_else(|| insufficient(from, from_bal, wei))?;
        let to_bal = self.balance_wei(to_addr);
        let new_to = to_bal.checked_add(wei).ok_or_else(|| {
            ExecError::ModuleRejected(format!("ledger: {to:?} balance overflows U256"))
        })?;
        self.set_balance(from_addr, new_from);
        self.set_balance(to_addr, new_to);
        Ok(())
    }

    fn mint(&self, addr: &Address, amount: u64) {
        let wei = units_to_wei(amount);
        if wei.is_zero() {
            return;
        }
        let evm_addr = alloy_primitives_address(addr.0);
        let current = self.balance_wei(evm_addr);
        // `mint` is infallible (block rewards must not fail); a U256
        // balance cannot overflow by adding ≤ 1.8×10²⁸ anyway — the
        // saturating op is belt-and-suspenders, not a reachable path.
        self.set_balance(evm_addr, current.saturating_add(wei));
    }
}
