//! EVM chain specification — fork schedule, chain ID, and gas parameters.
//!
//! A `ChainSpec` defines the EVM's configuration: the chain ID (for
//! EIP-155 replay protection), the hardfork schedule (which EVM
//! rules are active at each block), and gas parameters (block gas
//! limit, base fee).
//!
//! # Reference
//!
//! - Ethereum Yellow Paper §4.3.4: the chain specification.
//! - reth: `reth-chainspec` crate defines `ChainSpec` with fork
//!   activations, chain ID, and genesis alloc.
//! - EIP-155: chain ID in the signature for replay protection.
//!
//! # Design
//!
//! Oxide uses a simplified chain spec compared to reth's full
//! `ChainSpec`. We support:
//! - A fixed chain ID.
//! - A single active hardfork spec (no fork schedule transitions
//!   yet — Phase C uses a fixed `SpecId`).
//! - A block gas limit and base fee.
//!
//! Fork schedule transitions (e.g., "Paris at block N, Shanghai at
//! block N+M") will be added when the chain needs multi-fork
//! support. For now, a single spec is sufficient for devnet and
//! conformance testing.

use revm::primitives::hardfork::SpecId;

/// The EVM chain specification.
///
/// Encapsulates all configuration that determines EVM behavior:
/// chain ID, hardfork spec, gas limits, and base fee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSpec {
    /// The EIP-155 chain ID. Used for replay protection in signed
    /// transactions. Oxide devnet uses 1 (Ethereum mainnet ID) for
    /// conformance; production chains use a unique ID.
    pub chain_id: u64,
    /// The active EVM hardfork spec. Determines opcode availability,
    /// gas costs, and precompile set. `SpecId::PRAGUE` is the
    /// latest stable mainnet spec in revm 42.
    pub spec: SpecId,
    /// The block gas limit. Maximum total gas across all txs in a
    /// block. Ethereum mainnet uses 30M; Oxide uses the same.
    pub block_gas_limit: u64,
    /// The initial EIP-1559 base fee (wei per gas). The base fee
    /// adjusts per-block based on gas usage; this is the starting
    /// value. Ethereum mainnet uses ~1 gwei; Oxide devnet uses 7
    /// gwei.
    pub base_fee: u64,
}

impl ChainSpec {
    /// Create a chain spec for Oxide devnet.
    ///
    /// Devnet uses:
    /// - Chain ID 1 (Ethereum mainnet ID, for conformance).
    /// - Prague spec (latest stable).
    /// - 30M block gas limit.
    /// - 7 gwei base fee.
    #[must_use]
    pub fn devnet() -> Self {
        Self {
            chain_id: 1,
            spec: SpecId::PRAGUE,
            block_gas_limit: 30_000_000,
            base_fee: 7_000_000_000,
        }
    }

    /// Create a chain spec with a custom chain ID.
    ///
    /// For production chains that need a unique chain ID (not
    /// mainnet's ID 1).
    #[must_use]
    pub fn with_chain_id(chain_id: u64) -> Self {
        Self {
            chain_id,
            spec: SpecId::PRAGUE,
            block_gas_limit: 30_000_000,
            base_fee: 7_000_000_000,
        }
    }
}

impl Default for ChainSpec {
    fn default() -> Self {
        Self::devnet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_uses_mainnet_chain_id() {
        let spec = ChainSpec::devnet();
        assert_eq!(spec.chain_id, 1, "devnet uses chain ID 1 for conformance");
    }

    #[test]
    fn devnet_uses_prague_spec() {
        let spec = ChainSpec::devnet();
        assert_eq!(spec.spec, SpecId::PRAGUE);
    }

    #[test]
    fn devnet_uses_30m_gas_limit() {
        let spec = ChainSpec::devnet();
        assert_eq!(spec.block_gas_limit, 30_000_000);
    }

    #[test]
    fn devnet_uses_7_gwei_base_fee() {
        let spec = ChainSpec::devnet();
        assert_eq!(spec.base_fee, 7_000_000_000);
    }

    #[test]
    fn with_chain_id_preserves_other_params() {
        let spec = ChainSpec::with_chain_id(42);
        assert_eq!(spec.chain_id, 42);
        assert_eq!(spec.spec, SpecId::PRAGUE);
        assert_eq!(spec.block_gas_limit, 30_000_000);
    }

    #[test]
    fn default_matches_devnet() {
        let default = ChainSpec::default();
        let devnet = ChainSpec::devnet();
        assert_eq!(default, devnet);
    }
}
