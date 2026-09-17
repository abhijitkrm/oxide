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
use matcher::server::{ServerConfig, TxSubmitter, run_server_multi, run_server_ring};
use node::{ConsensusConfig, Node, NodeConfig};
use ports::AppInterface;
use types::{MempoolAck, TxBytes};

/// Adapter that submits settlement transactions into the executor's
/// mempool via the `matcher::server::TxSubmitter` trait.
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

/// Default number of funded accounts.
const DEFAULT_ACCOUNTS: usize = 10_000;

/// Default initial balance per account (1T quote units).
const DEFAULT_BALANCE: u64 = 1_000_000_000_000;

/// Default number of markets for multi-market mode.
const DEFAULT_MARKETS: usize = 128;

/// Default balance shard count.
const DEFAULT_SHARDS: usize = 64;

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
    shards: usize,
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
        shards: parse_flag("--shards", DEFAULT_SHARDS),
    }
}

/// Build a `ServerConfig` from the CLI port settings.
fn build_server_config(cli: &CliConfig) -> ServerConfig {
    ServerConfig {
        binary_tcp_port: cli.tcp_port,
        jsonrpc_port: cli.jsonrpc_port,
        fix_port: cli.fix_port,
        websocket_port: cli.ws_port,
        batch_interval_ms: cli.batch_interval,
    }
}

/// Fund `n` accounts in a sharded balance cache, each with `DEFAULT_BALANCE`.
fn fund_sharded(balances: &matcher::ShardedBalanceCache, n: usize) {
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
        println!("  balance shards:  {}", cli.shards);
    }
    println!("  binary TCP:      127.0.0.1:{}", cli.tcp_port);
    println!("  JSON-RPC:        127.0.0.1:{}", cli.jsonrpc_port);
    println!("  FIX 4.4:         127.0.0.1:{}", cli.fix_port);
    println!("  WebSocket:       127.0.0.1:{}", cli.ws_port);
    println!("  batch interval:  {}ms", cli.batch_interval);

    // Assemble the Oxide node (single-node devnet with executor + modules).
    let node_config = NodeConfig {
        consensus: ConsensusConfig::Sequencer,
        max_mempool_entries: 100_000,
        ..NodeConfig::default()
    };
    let mut node = Node::assemble(&node_config);
    println!("oxide-matcher: devnet assembled (executor + exchange + perps on the EVM ledger)");

    let submitter: Arc<dyn TxSubmitter> =
        Arc::new(ExecutorTxSubmitter { executor: node.app_handle() });
    let sender = primitives::Address([0u8; 20]);
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
            let balances = Arc::new(matcher::ShardedBalanceCache::new(cli.shards));
            fund_sharded(&balances, cli.accounts);
            println!("oxide-matcher: funded {} accounts with {DEFAULT_BALANCE} each", cli.accounts);
            let configs = build_market_configs(cli.markets);
            println!("oxide-matcher: spawning {} market worker threads...", configs.len());
            runtime.block_on(run_server_multi(configs, balances, submitter, config, sender));
        }
        "ring" => {
            println!("oxide-matcher: funding {} accounts (single-market ring)...", cli.accounts);
            let mut server = MatchingServer::new(single_market_config(), cli.accounts);
            fund_server(&mut server, cli.accounts);
            println!("oxide-matcher: funded {} accounts with {DEFAULT_BALANCE} each", cli.accounts);
            runtime.block_on(run_server_ring(server, submitter, config, sender));
        }
        "mutex" => {
            println!("oxide-matcher: funding {} accounts (single-market mutex)...", cli.accounts);
            let mut server = MatchingServer::new(single_market_config(), cli.accounts);
            fund_server(&mut server, cli.accounts);
            println!("oxide-matcher: funded {} accounts with {DEFAULT_BALANCE} each", cli.accounts);
            let shared = Arc::new(matcher::SharedMatcher::new(server));
            runtime.block_on(matcher::server::run_server(shared, submitter, config, sender));
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
