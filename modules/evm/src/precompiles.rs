//! EVM precompiles that bridge to native Oxide modules (plan.md §13, Phase 2).
//!
//! ## What this module is
//!
//! Implements EVM precompiles that call into native Oxide modules
//! (bank, staking, trading). This lets EVM smart contracts invoke
//! native chain functionality — e.g., a Uniswap deployment can call
//! the native bank module to transfer tokens, or a perps protocol
//! can call the native trading module to place orders.
//!
//! ## Why native precompiles
//!
//! Oxide's architecture (plan.md §2) has two execution tracks:
//! native modules (bank, staking, trading) and EVM. Native precompiles
//! bridge them: EVM contracts call native functionality via precompile
//! addresses, getting the performance and safety of the native
//! implementation without re-implementing it in Solidity.
//!
//! ## Precompile addresses
//!
//! Oxide reserves precompile addresses in the range
//! `0x0000_0000_0000_0000_0000_0000_0000_0000_OOXX` where `OO` is the
//! module ID and `XX` is the operation ID. This avoids collision with
//! Ethereum's standard precompiles (addresses 0x01–0x0A).
//!
//! Current precompiles:
//! - `0x0B_01` (bank, transfer): transfer native tokens between accounts.
//! - `0x0B_02` (bank, balance): query an account's native balance.
//! - `0x0C_01` (staking, delegate): delegate to a validator.

use primitives::Address;

/// A precompile call result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileResult {
    /// The output bytes returned to the EVM caller.
    pub output: Vec<u8>,
    /// The gas consumed by the precompile.
    pub gas_used: u64,
    /// Whether the precompile succeeded.
    pub success: bool,
}

impl PrecompileResult {
    /// A successful precompile call with the given output and gas.
    #[must_use]
    pub fn success(output: Vec<u8>, gas_used: u64) -> Self {
        Self { output, gas_used, success: true }
    }

    /// A failed precompile call (revert) with the given gas consumed.
    #[must_use]
    pub fn revert(gas_used: u64) -> Self {
        Self { output: Vec::new(), gas_used, success: false }
    }
}

/// The precompile address for a (`module_id`, `op_id`) pair.
///
/// Oxide precompiles live at addresses of the form
/// `0x0000...0000_OOXX` where `OO` is the module ID and `XX` is the
/// operation ID. This keeps them separate from Ethereum's standard
/// precompiles (0x01–0x0A).
#[must_use]
pub fn precompile_address(module_id: u8, op_id: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[18] = module_id;
    bytes[19] = op_id;
    Address(bytes)
}

/// Decode a precompile address into (`module_id`, `op_id`).
///
/// Returns `None` if the address is not a valid Oxide precompile
/// address (i.e., not in the `0x0000...OOXX` format).
#[must_use]
pub fn decode_precompile_address(addr: &Address) -> Option<(u8, u8)> {
    let bytes = addr.as_bytes();
    // The first 18 bytes must be zero.
    if bytes[..18].iter().any(|&b| b != 0) {
        return None;
    }
    // Module ID 0 is reserved (no precompile there).
    let module_id = bytes[18];
    if module_id == 0 {
        return None;
    }
    Some((module_id, bytes[19]))
}

/// Check if an address is an Oxide precompile address.
#[must_use]
pub fn is_precompile(addr: &Address) -> bool {
    decode_precompile_address(addr).is_some()
}

/// The bank transfer precompile (module `0x0B`, op `0x01`).
///
/// Input: `[to: 20B][amount: 32B]` (EVM ABI: address + uint256).
/// Output: empty on success.
/// Gas: `21_000` (same as a standard ETH transfer).
pub const BANK_TRANSFER: (u8, u8) = (0x0B, 0x01);

/// The bank balance precompile (module `0x0B`, op `0x02`).
///
/// Input: `[addr: 20B]`.
/// Output: `[balance: 32B]` (uint256).
/// Gas: `1_000` (a cold read).
pub const BANK_BALANCE: (u8, u8) = (0x0B, 0x02);

/// The staking delegate precompile (module `0x0C`, op `0x01`).
///
/// Input: `[validator: 20B][amount: 32B]`.
/// Output: empty on success.
/// Gas: `50_000` (a staking operation).
pub const STAKING_DELEGATE: (u8, u8) = (0x0C, 0x01);

/// Execute a precompile call.
///
/// Given a precompile address and input data, dispatch to the
/// appropriate native module handler. This is a stub implementation
/// that validates the input format and returns a success result —
/// the actual native module integration happens when the executor
/// wires precompiles into the EVM call path.
///
/// # Arguments
///
/// - `addr`: The precompile address (must be a valid Oxide precompile).
/// - `input`: The call data from the EVM.
/// - `gas_limit`: The gas limit for the precompile.
///
/// # Returns
///
/// A `PrecompileResult` with the output, gas used, and success flag.
///
/// # Panics
///
/// This function does not panic.
#[must_use]
pub fn execute_precompile(addr: &Address, input: &[u8], gas_limit: u64) -> PrecompileResult {
    let Some((module_id, op_id)) = decode_precompile_address(addr) else {
        return PrecompileResult::revert(0);
    };

    match (module_id, op_id) {
        BANK_TRANSFER => execute_bank_transfer(input, gas_limit),
        BANK_BALANCE => execute_bank_balance(input, gas_limit),
        STAKING_DELEGATE => execute_staking_delegate(input, gas_limit),
        _ => PrecompileResult::revert(0),
    }
}

/// Execute the bank transfer precompile.
///
/// Input: `[to: 20B][amount: 32B]`.
/// Gas: `21_000` (same as a standard ETH transfer).
fn execute_bank_transfer(input: &[u8], gas_limit: u64) -> PrecompileResult {
    const GAS_COST: u64 = 21_000;
    if gas_limit < GAS_COST {
        return PrecompileResult::revert(0);
    }
    // Input: 20-byte address + 32-byte amount = 52 bytes.
    if input.len() != 52 {
        return PrecompileResult::revert(GAS_COST);
    }
    // Validate the address (non-zero).
    let to = &input[..20];
    if to.iter().all(|&b| b == 0) {
        return PrecompileResult::revert(GAS_COST);
    }
    // Success — the actual transfer happens in the executor.
    PrecompileResult::success(Vec::new(), GAS_COST)
}

/// Execute the bank balance precompile.
///
/// Input: `[addr: 20B]`.
/// Output: `[balance: 32B]`.
/// Gas: `1_000`.
fn execute_bank_balance(input: &[u8], gas_limit: u64) -> PrecompileResult {
    const GAS_COST: u64 = 1_000;
    if gas_limit < GAS_COST {
        return PrecompileResult::revert(0);
    }
    if input.len() != 20 {
        return PrecompileResult::revert(GAS_COST);
    }
    // Return a zero balance (stub — the actual balance comes from
    // the native bank module via the executor).
    let mut output = vec![0u8; 32];
    output[31] = 0;
    PrecompileResult::success(output, GAS_COST)
}

/// Execute the staking delegate precompile.
///
/// Input: `[validator: 20B][amount: 32B]`.
/// Gas: `50_000`.
fn execute_staking_delegate(input: &[u8], gas_limit: u64) -> PrecompileResult {
    const GAS_COST: u64 = 50_000;
    if gas_limit < GAS_COST {
        return PrecompileResult::revert(0);
    }
    // Input: 20-byte validator + 32-byte amount = 52 bytes.
    if input.len() != 52 {
        return PrecompileResult::revert(GAS_COST);
    }
    // Validate the validator address (non-zero).
    let validator = &input[..20];
    if validator.iter().all(|&b| b == 0) {
        return PrecompileResult::revert(GAS_COST);
    }
    // Success — the actual delegation happens in the executor.
    PrecompileResult::success(Vec::new(), GAS_COST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precompile_address_encoding() {
        let addr = precompile_address(0x0B, 0x01);
        let bytes = addr.as_bytes();
        assert_eq!(bytes[..18], [0u8; 18]);
        assert_eq!(bytes[18], 0x0B);
        assert_eq!(bytes[19], 0x01);
    }

    #[test]
    fn decode_valid_precompile_address() {
        let addr = precompile_address(0x0B, 0x02);
        let decoded = decode_precompile_address(&addr);
        assert_eq!(decoded, Some((0x0B, 0x02)));
    }

    #[test]
    fn decode_rejects_non_precompile_address() {
        // A regular address (non-zero in first 18 bytes) is not a precompile.
        let addr = Address([0x42; 20]);
        assert!(decode_precompile_address(&addr).is_none());
    }

    #[test]
    fn decode_rejects_module_zero() {
        // Module ID 0 is reserved.
        let mut bytes = [0u8; 20];
        bytes[19] = 0x01;
        let addr = Address(bytes);
        assert!(decode_precompile_address(&addr).is_none());
    }

    #[test]
    fn is_precompile_checks() {
        assert!(is_precompile(&precompile_address(0x0B, 0x01)));
        assert!(!is_precompile(&Address([0x42; 20])));
    }

    #[test]
    fn bank_transfer_success() {
        let addr = precompile_address(0x0B, 0x01);
        let mut input = vec![0u8; 52];
        input[0] = 0x42; // non-zero "to" address
        let result = execute_precompile(&addr, &input, 100_000);
        assert!(result.success);
        assert_eq!(result.gas_used, 21_000);
        assert!(result.output.is_empty());
    }

    #[test]
    fn bank_transfer_rejects_zero_recipient() {
        let addr = precompile_address(0x0B, 0x01);
        let input = vec![0u8; 52]; // all-zero "to" address
        let result = execute_precompile(&addr, &input, 100_000);
        assert!(!result.success);
        assert_eq!(result.gas_used, 21_000);
    }

    #[test]
    fn bank_transfer_rejects_wrong_input_length() {
        let addr = precompile_address(0x0B, 0x01);
        let input = vec![0u8; 40]; // wrong length
        let result = execute_precompile(&addr, &input, 100_000);
        assert!(!result.success);
    }

    #[test]
    fn bank_transfer_reverts_on_insufficient_gas() {
        let addr = precompile_address(0x0B, 0x01);
        let mut input = vec![0u8; 52];
        input[0] = 0x42;
        let result = execute_precompile(&addr, &input, 20_000); // < 21_000
        assert!(!result.success);
        assert_eq!(result.gas_used, 0);
    }

    #[test]
    fn bank_balance_returns_32_bytes() {
        let addr = precompile_address(0x0B, 0x02);
        let input = vec![0x42; 20];
        let result = execute_precompile(&addr, &input, 10_000);
        assert!(result.success);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.gas_used, 1_000);
    }

    #[test]
    fn staking_delegate_success() {
        let addr = precompile_address(0x0C, 0x01);
        let mut input = vec![0u8; 52];
        input[0] = 0x42; // non-zero validator
        let result = execute_precompile(&addr, &input, 100_000);
        assert!(result.success);
        assert_eq!(result.gas_used, 50_000);
    }

    #[test]
    fn staking_delegate_rejects_zero_validator() {
        let addr = precompile_address(0x0C, 0x01);
        let input = vec![0u8; 52];
        let result = execute_precompile(&addr, &input, 100_000);
        assert!(!result.success);
    }

    #[test]
    fn unknown_precompile_reverts() {
        let addr = precompile_address(0xFF, 0xFF);
        let result = execute_precompile(&addr, &[], 100_000);
        assert!(!result.success);
    }

    #[test]
    fn non_precompile_address_reverts() {
        let addr = Address([0x42; 20]);
        let result = execute_precompile(&addr, &[], 100_000);
        assert!(!result.success);
    }
}
