//! oxide-matcher — the off-chain matching server binary.
//!
//! Assembles a single-node Oxide devnet (executor + exchange
//! modules on the EVM ledger), creates a matching server with funded accounts, wires
//! the batch settler to the executor's mempool, and starts all four
//! order-entry protocol servers (binary TCP, JSON-RPC, FIX, WebSocket).
//!
//! The matching server runs off-chain: it accepts orders, matches them
//! in-memory, and periodically submits batch settlement transactions
//! to the consensus mempool. Validators verify the batches without
//! re-matching.
//!
//! # Usage
//!
//! ```sh
//! # Start the matching server with defaults
//! oxide-matcher
//!
//! # Custom ports and 10k funded accounts
//! oxide-matcher --accounts 10000 --tcp-port 36000 --jsonrpc-port 36001 \
//!   --fix-port 36002 --ws-port 36003
//!
//! # With a specific batch settlement interval (50ms)
//! oxide-matcher --batch-interval 50
//! ```

#![allow(clippy::cast_precision_loss)]

use std::env;
use std::sync::Arc;
use std::time::Duration;

use matcher::MatchingServer;
use matcher::server::{ServerConfig, TxConfirmer, TxSubmitter, run_server_multi, run_server_ring};
use node::{ConsensusConfig, Node, NodeConfig};
use ports::AppInterface;
use types::{MempoolAck, TxBytes};

/// Adapter that submits settlement transactions into the executor's
/// mempool via the `matcher::server::TxSubmitter` trait — and reads
/// their FINALIZED outcomes back via `TxConfirmer`. Mempool
/// acceptance is only admission; the settler treats a batch as
/// settled only when `tx_outcome` proves the block executed it.
struct ExecutorTxSubmitter {
    executor: Arc<executor::Executor>,
}

impl TxSubmitter for ExecutorTxSubmitter {
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
        match self.executor.ingest_tx(tx) {
            MempoolAck::Accepted => Ok(()),
            MempoolAck::Rejected { reason } => Err(reason),
        }
    }
}

impl TxConfirmer for ExecutorTxSubmitter {
    fn tx_outcome(&self, tx_hash: &primitives::Hash) -> Option<executor::TxOutcome> {
        self.executor.tx_outcome(tx_hash)
    }

    fn executed_nonce(&self, sender: &primitives::Address) -> u64 {
        self.executor.executed_nonce_of(sender)
    }
}

/// Default number of funded accounts.
const DEFAULT_ACCOUNTS: usize = 10_000;

/// Default initial balance per account (1T quote units).
const DEFAULT_BALANCE: u64 = 1_000_000_000_000;

/// Default number of markets for multi-market mode.
const DEFAULT_MARKETS: usize = 128;

/// Default balance shard count.
const DEFAULT_ACCOUNTS_CAP: usize = 1_000_000;

/// CLI configuration parsed from command-line flags.
struct CliConfig {
    accounts: usize,
    tcp_port: u16,
    jsonrpc_port: u16,
    fix_port: u16,
    ws_port: u16,
    batch_interval: u64,
    mode: String,
    markets: usize,
    accounts_cap: usize,
    chain_id: u64,
    nonce_state: Option<std::path::PathBuf>,
    settlement_key: Option<[u8; 32]>,
    settlement_outbox: Option<std::path::PathBuf>,
}

/// Parse CLI flags into a `CliConfig`.
fn parse_cli() -> CliConfig {
    CliConfig {
        accounts: parse_flag("--accounts", DEFAULT_ACCOUNTS),
        tcp_port: parse_flag("--tcp-port", 36000u16),
        jsonrpc_port: parse_flag("--jsonrpc-port", 36001u16),
        fix_port: parse_flag("--fix-port", 36002u16),
        ws_port: parse_flag("--ws-port", 36003u16),
        batch_interval: parse_flag("--batch-interval", 100u64),
        mode: parse_flag("--mode", "multi".to_string()),
        markets: parse_flag("--markets", DEFAULT_MARKETS),
        accounts_cap: parse_flag("--accounts-cap", DEFAULT_ACCOUNTS_CAP),
        // Signature domain: signatures produced under another chain
        // ID must not verify here. Default = the devnet chain ID;
        // production passes the real chain ID.
        chain_id: parse_flag("--chain-id", matcher::protocol::CHAIN_ID),
        // Durable replay-gate checkpoint — without it, every restart
        // lets any captured signed request replay once.
        nonce_state: parse_flag_opt::<String>("--nonce-state").map(std::path::PathBuf::from),
        // The settlement operator's secp256k1 secret (64 hex chars).
        // When set, batch envelopes are signed and the sender is the
        // key-derived address — which is also wired as the exchange's
        // settlement operator. Without it envelopes are unsigned
        // (devnet only — `UnsignedTxPolicy::Allow`).
        settlement_key: parse_flag_opt::<String>("--settlement-key").map(|hex| parse_key_hex(&hex)),
        // Durable settlement-lane checkpoint — without it, a restart
        // forgets an in-flight batch (fills drained, outcome unknown).
        settlement_outbox: parse_flag_opt::<String>("--settlement-outbox")
            .map(std::path::PathBuf::from),
    }
}

/// Parse a 64-character hex string into a 32-byte secret key.
///
/// # Panics
///
/// Panics on malformed input — a bad operator key is a startup
/// misconfiguration, not a runtime condition.
fn parse_key_hex(hex: &str) -> [u8; 32] {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    assert_eq!(hex.len(), 64, "--settlement-key must be 32 bytes (64 hex chars)");
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("--settlement-key must be hex");
    }
    key
}

/// Build a `ServerConfig` from the CLI port settings.
fn build_server_config(cli: &CliConfig) -> ServerConfig {
    ServerConfig {
        binary_tcp_port: cli.tcp_port,
        jsonrpc_port: cli.jsonrpc_port,
        fix_port: cli.fix_port,
        websocket_port: cli.ws_port,
        batch_interval_ms: cli.batch_interval,
        chain_id: cli.chain_id,
        nonce_state_path: cli.nonce_state.clone(),
        settlement_key: cli.settlement_key,
        settlement_outbox: cli.settlement_outbox.clone(),
    }
}

/// Fund `n` accounts in a sharded balance cache, each with `DEFAULT_BALANCE`.
fn fund_sharded(balances: &matcher::AtomicBalanceCache, n: usize) {
    for i in 0..u32::try_from(n).unwrap_or(u32::MAX) {
        let mut addr = [0u8; 20];
        addr[..4].copy_from_slice(&i.to_le_bytes());
        balances.set(&primitives::Address(addr), DEFAULT_BALANCE);
    }
}

/// Fund `n` accounts in a single-market `MatchingServer`.
fn fund_server(server: &mut MatchingServer, n: usize) {
    for i in 0..u32::try_from(n).unwrap_or(u32::MAX) {
        let mut addr = [0u8; 20];
        addr[..4].copy_from_slice(&i.to_le_bytes());
        server.fund_account(&primitives::Address(addr), DEFAULT_BALANCE);
    }
}

/// Build N identical market configs (one per market for multi-market mode).
fn build_market_configs(n: usize) -> Vec<trading::MarketConfig> {
    (0..u8::try_from(n).unwrap_or(u8::MAX))
        .map(|m| trading::MarketConfig {
            market_id: u16::from(m),
            tick_size: 1_000_000,
            lot_size: 1_000,
            min_price: 1_000_000_000,
            max_price: 2_000_000_000,
            max_resting: 1 << 16,
        })
        .collect()
}

/// A single-market config (for ring/mutex modes).
fn single_market_config() -> trading::MarketConfig {
    trading::MarketConfig {
        market_id: 0,
        tick_size: 1_000_000,
        lot_size: 1_000,
        min_price: 1_000_000_000,
        max_price: 2_000_000_000,
        max_resting: 1 << 16,
    }
}

fn main() {
    let cli = parse_cli();
    println!("oxide-matcher: starting matching server");
    println!("  mode:            {}", cli.mode);
    println!("  accounts:        {}", cli.accounts);
    println!("  balance/account: {DEFAULT_BALANCE}");
    if cli.mode == "multi" {
        println!("  markets:         {}", cli.markets);
        println!("  balance capacity: {}", cli.accounts_cap);
    }
    println!("  binary TCP:      127.0.0.1:{}", cli.tcp_port);
    println!("  JSON-RPC:        127.0.0.1:{}", cli.jsonrpc_port);
    println!("  FIX 4.4:         127.0.0.1:{}", cli.fix_port);
    println!("  WebSocket:       127.0.0.1:{}", cli.ws_port);
    println!("  batch interval:  {}ms", cli.batch_interval);
    println!("  chain ID:        {}", cli.chain_id);
    if let Some(p) = &cli.nonce_state {
        println!("  nonce state:     {}", p.display());
    } else {
        println!("  nonce state:     memory-only (restart replays possible)");
    }
    if let Some(p) = &cli.settlement_outbox {
        println!("  settlement outbox: {}", p.display());
    }

    // The settlement operator: with `--settlement-key` the sender is
    // the key-derived secp256k1 address and envelopes are signed —
    // the node then runs the default `Reject` policy. Without a key
    // the devnet default is the well-known zero address and the
    // envelopes stay unsigned, so the node opts out explicitly.
    let sender = match &cli.settlement_key {
        Some(key) => crypto::secp::signable_pubkey_address(key)
            .expect("--settlement-key must be a valid secp256k1 secret"),
        None => primitives::Address([0u8; 20]),
    };
    println!("  settlement operator: {sender:?}");

    // Assemble the Oxide node (single-node devnet with executor +
    // modules). The exchange's settlement gate MUST name the same
    // operator the settler signs/sends as — left disabled, every
    // batch would be rejected at execution while the settler kept
    // counting submissions as settled.
    let node_config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 100_000,
        settlement_operator: Some(sender),
        // Signed envelopes are enforced iff the settler has a key to
        // sign with — an unsigned devnet settler is the only reason
        // to admit unsigned txs.
        require_signed_txs: cli.settlement_key.is_some(),
        ..NodeConfig::default()
    };
    let mut node = Node::assemble(&node_config);
    println!("oxide-matcher: devnet assembled (executor + exchange + perps on the EVM ledger)");

    // One executor handle serves both settlement roles: submitting
    // envelopes into the mempool and reading their finalized
    // execution outcomes back. The second is what turns "accepted"
    // into "settled".
    let link = Arc::new(ExecutorTxSubmitter { executor: node.app_handle() });
    let submitter: Arc<dyn TxSubmitter> = Arc::clone(&link) as Arc<dyn TxSubmitter>;
    let confirmer: Arc<dyn TxConfirmer> = link;
    let config = build_server_config(&cli);

    println!("oxide-matcher: starting protocol servers + batch settler...");
    println!("oxide-matcher: ready to accept orders");

    let runtime =
        tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("tokio runtime");

    std::thread::spawn(move || {
        loop {
            node.engine().run_until_idle();
            std::thread::sleep(Duration::from_millis(10));
        }
    });

    match cli.mode.as_str() {
        "multi" => {
            println!(
                "oxide-matcher: funding {} accounts across {} markets...",
                cli.accounts, cli.markets
            );
            let balances = Arc::new(matcher::AtomicBalanceCache::new(cli.accounts_cap));
            fund_sharded(&balances, cli.accounts);
            println!("oxide-matcher: funded {} accounts with {DEFAULT_BALANCE} each", cli.accounts);
            let configs = build_market_configs(cli.markets);
            println!("oxide-matcher: spawning {} market worker threads...", configs.len());
            runtime.block_on(run_server_multi(
                configs, balances, submitter, confirmer, config, sender,
            ));
        }
        "ring" => {
            println!("oxide-matcher: funding {} accounts (single-market ring)...", cli.accounts);
            let mut server = MatchingServer::new(single_market_config(), cli.accounts);
            server.set_chain_id(cli.chain_id);
            if let Some(p) = &cli.nonce_state {
                server.set_nonce_store(p.clone());
            }
            fund_server(&mut server, cli.accounts);
            println!("oxide-matcher: funded {} accounts with {DEFAULT_BALANCE} each", cli.accounts);
            runtime.block_on(run_server_ring(server, submitter, confirmer, config, sender));
        }
        "mutex" => {
            println!("oxide-matcher: funding {} accounts (single-market mutex)...", cli.accounts);
            let mut server = MatchingServer::new(single_market_config(), cli.accounts);
            server.set_chain_id(cli.chain_id);
            if let Some(p) = &cli.nonce_state {
                server.set_nonce_store(p.clone());
            }
            fund_server(&mut server, cli.accounts);
            println!("oxide-matcher: funded {} accounts with {DEFAULT_BALANCE} each", cli.accounts);
            let shared = Arc::new(matcher::SharedMatcher::new(server));
            runtime.block_on(matcher::server::run_server(
                shared, submitter, confirmer, config, sender,
            ));
        }
        _ => {
            eprintln!("oxide-matcher: unknown mode '{}' (use multi, ring, or mutex)", cli.mode);
            std::process::exit(1);
        }
    }
}

/// Parse a CLI flag of the form `--name value`. Returns the default
/// if the flag is not present.
fn parse_flag<T: std::str::FromStr>(name: &str, default: T) -> T {
    let args: Vec<String> = env::args().collect();
    for (i, arg) in args.iter().enumerate() {
        if arg == name {
            if let Some(val) = args.get(i + 1) {
                if let Ok(parsed) = val.parse() {
                    return parsed;
                }
            }
        }
    }
    default
}

/// Parse an optional CLI flag of the form `--name value`. Returns
/// `None` if the flag is absent or its value fails to parse.
fn parse_flag_opt<T: std::str::FromStr>(name: &str) -> Option<T> {
    let args: Vec<String> = env::args().collect();
    for (i, arg) in args.iter().enumerate() {
        if arg == name {
            return args.get(i + 1).and_then(|v| v.parse().ok());
        }
    }
    None
}
