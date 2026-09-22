//! JSON-RPC endpoint handlers.
//!
//! Split from `lib.rs` around the read-surface invariant: every
//! `eth_*`/`net_*`/`web3_*`/`txpool_*`/`debug_*` method here is a
//! leaf handler — it reads module state, formats a response, and
//! can never mutate chain state. The dispatcher in `lib.rs` is
//! the only caller; keeping all handlers in one file makes the
//! served surface auditable against the spec in a single read.

use super::{
    B256, FILTER_TIMEOUT, FilterEntry, FilterKind, LogFilter, MAX_FEE_HISTORY_BLOCKS, MAX_FILTERS,
    MAX_LOG_RESULTS, Ordering, PENDING_RING_CAP, RpcError, RpcServer, SubscriptionType,
    TopicMatcher, TxBytes, TxpoolProvider, Value, WsConn, block_json, block_reward_percentiles,
    call_error, call_frame_json, hex_decode, hex_quantity_u128, json, keccak256, log_json,
    parse_address, parse_b256, parse_call_object, parse_eth_address, parse_filter_id,
    parse_state_overrides, parse_trace_options, parse_u64, parse_u256, pooled_tx_json,
    receipt_json, state_error, tx_json, txpool_content_json, txpool_inspect_summary,
};

impl RpcServer {
    // ---- Ethereum RPC methods ----

    /// `eth_chainId` — returns the chain ID as a hex string.
    pub(crate) fn eth_chain_id(&self) -> Value {
        json!(format!("0x{:x}", self.chain_id))
    }

    /// `eth_blockNumber` — returns the current block height as a hex
    /// string.
    pub(crate) fn eth_block_number(&self) -> Value {
        json!(format!("0x{:x}", self.block_height()))
    }

    /// `eth_gasPrice` — the oracle-suggested gas price: latest
    /// sealed block's base fee plus the sampled priority tip —
    /// geth's `SuggestGasPrice` = `suggestTip + head.BaseFee`.
    /// Without an attached EVM (stateless serving) the configured
    /// base fee is the honest fallback.
    pub(crate) fn eth_gas_price(&self) -> Value {
        let price = self.evm.as_deref().map_or(u128::from(self.base_fee), |evm| {
            u128::from(evm.latest_base_fee()).saturating_add(evm.suggest_gas_tip())
        });
        json!(format!("0x{price:x}"))
    }

    /// `net_version` — returns the network ID as a decimal string.
    pub(crate) fn net_version(&self) -> Value {
        json!(self.chain_id.to_string())
    }

    /// `web3_clientVersion` — returns the client version string.
    pub(crate) fn web3_client_version(&self) -> Value {
        json!(self.client_version)
    }

    /// `eth_getBalance` — returns an account's balance as a hex
    /// string in wei.
    ///
    /// Params: `[address: String, block: String?]`
    ///
    /// Heights within the retained undo window are served from the
    /// versioned overlay; older tags return geth's "missing trie
    /// node" error.
    pub(crate) fn eth_get_balance(&self, params: &[Value]) -> Result<Value, RpcError> {
        let addr = parse_address(params.first())?;
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(1))?;
        evm.balance_at(&addr, h).map(hex_quantity_u128).map_err(state_error)
    }

    /// `eth_getTransactionCount` — returns an account's nonce as a
    /// hex string.
    ///
    /// Params: `[address: String, block: String?]`
    pub(crate) fn eth_get_transaction_count(&self, params: &[Value]) -> Result<Value, RpcError> {
        let addr = parse_address(params.first())?;
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(1))?;
        evm.nonce_at(&addr, h).map(|n| json!(format!("0x{n:x}"))).map_err(state_error)
    }

    /// `eth_subscribe` — creates a WebSocket subscription.
    ///
    /// Params: `[subscriptionType: String, options?: Object]`
    ///
    /// Returns the subscription ID as a hex string. Over HTTP the
    /// method errors with `"notifications not supported"` — the
    /// geth behaviour, since there is no push channel.
    ///
    /// For `logs` subscriptions, `options` is an `eth_getLogs`-shaped
    /// filter object (`address`, `topics`); block-range fields are
    /// accepted but ignored — pushes only cover newly finalized
    /// blocks.
    pub(crate) fn eth_subscribe(
        &self,
        params: &[Value],
        conn: Option<&WsConn>,
    ) -> Result<Value, RpcError> {
        let Some(conn) = conn else {
            return Err(RpcError {
                code: -32_000,
                message: "notifications not supported".to_string(),
                data: None,
            });
        };
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing subscription type"));
        }
        let type_str = params[0]
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("subscription type must be a string"))?;
        let kind = SubscriptionType::parse(type_str).ok_or_else(|| {
            RpcError::invalid_params(&format!("unknown subscription type: {type_str}"))
        })?;
        let filter = match (kind.clone(), params.get(1)) {
            (SubscriptionType::Logs, Some(obj)) => Some(self.parse_log_filter(obj)?),
            (SubscriptionType::Logs, None) => Some(LogFilter::default()),
            _ => None,
        };
        Ok(json!(self.subscriptions.register(kind, filter, conn.conn_id, conn.sink.clone())))
    }

    /// `eth_unsubscribe` — cancels a WebSocket subscription.
    ///
    /// Params: `[subscriptionId: String]`
    ///
    /// Returns `true` if the subscription existed, `false` for
    /// unknown IDs (geth semantics — not an error).
    pub(crate) fn eth_unsubscribe(&self, params: &[Value]) -> Result<Value, RpcError> {
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing subscription ID"));
        }
        let id = params[0]
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("subscription ID must be a string"))?;
        Ok(json!(self.subscriptions.unregister(id)))
    }

    // ---- Pollable filters (`eth_newFilter` family) ----

    /// Register a pollable filter and return its hex ID. Reaps any
    /// expired filters first so the map can't grow on
    /// register-and-abandon clients.
    ///
    /// # Errors
    ///
    /// `-32000 "filter limit reached"` once [`MAX_FILTERS`] live
    /// filters are registered — the `filter-cap` guard.
    pub(crate) fn register_filter(&self, kind: FilterKind) -> Result<String, RpcError> {
        let mut filters = primitives::sync::lock_state(&self.filters);
        let now = std::time::Instant::now();
        filters.retain(|_, e| now.duration_since(e.last_poll) < FILTER_TIMEOUT);
        if filters.len() >= MAX_FILTERS {
            return Err(RpcError {
                code: -32000,
                message: format!("filter limit reached (max {MAX_FILTERS})"),
                data: None,
            });
        }
        let id = format!("0x{:x}", self.next_filter_id.fetch_add(1, Ordering::Relaxed));
        filters.insert(id.clone(), FilterEntry { kind, last_poll: now });
        Ok(id)
    }

    /// `eth_newFilter` — create a pollable log filter.
    ///
    /// Params: `[filter: Object]` — the same `eth_getLogs` shape.
    /// `eth_getFilterChanges` then returns matching logs in
    /// `(last_served, latest]` per poll (geth semantics).
    pub(crate) fn eth_new_filter(&self, params: &[Value]) -> Result<Value, RpcError> {
        let obj = params.first().ok_or_else(|| RpcError::invalid_params("missing filter"))?;
        let filter = self.parse_log_filter(obj)?;
        self.require_evm()?;
        let latest = self.latest_sealed_height();
        Ok(json!(self.register_filter(FilterKind::Log { filter, last_served: latest })?))
    }

    /// `eth_newBlockFilter` — create a pollable block filter.
    /// Each `eth_getFilterChanges` poll returns the hashes of blocks
    /// finalized since the last poll.
    pub(crate) fn eth_new_block_filter(&self) -> Result<Value, RpcError> {
        self.require_evm()?;
        let latest = self.latest_sealed_height();
        Ok(json!(self.register_filter(FilterKind::Block { last_served: latest })?))
    }

    /// `eth_newPendingTransactionFilter` — create a pollable
    /// pending-tx filter. Each `eth_getFilterChanges` poll returns
    /// the hashes of txs that entered the mempool since the last
    /// poll.
    ///
    pub(crate) fn eth_new_pending_transaction_filter(&self) -> Result<Value, RpcError> {
        let next_seq = primitives::sync::lock_state(&self.pending_txs).next_seq;
        Ok(json!(self.register_filter(FilterKind::PendingTx { next_seq })?))
    }

    /// `eth_uninstallFilter` — drop a pollable filter. Returns
    /// `true` if it existed (geth returns `false` for unknown IDs).
    pub(crate) fn eth_uninstall_filter(&self, params: &[Value]) -> Result<Value, RpcError> {
        let id = parse_filter_id(params.first())?;
        let removed = primitives::sync::lock_state(&self.filters).remove(&id).is_some();
        Ok(json!(removed))
    }

    // ---- Transaction pool ----

    /// Require the txpool provider or return the unbacked-namespace
    /// error — an unbacked `txpool_*` that answers as if the pool
    /// were empty is worse than an error.
    pub(crate) fn require_txpool(&self) -> Result<&dyn TxpoolProvider, RpcError> {
        self.txpool.as_deref().ok_or_else(|| RpcError {
            code: -32_000,
            message: "txpool namespace not enabled on this node".to_string(),
            data: None,
        })
    }

    /// `txpool_status` — `{pending, queued}` counts of pooled
    /// transactions (hex-encoded, per geth).
    pub(crate) fn txpool_status(&self) -> Result<Value, RpcError> {
        let pool = self.require_txpool()?;
        let (mut pending, mut queued) = (0u64, 0u64);
        for item in pool.txpool_snapshot() {
            if item.pending {
                pending += 1;
            } else {
                queued += 1;
            }
        }
        Ok(json!({
            "pending": format!("0x{pending:x}"),
            "queued": format!("0x{queued:x}"),
        }))
    }

    /// `txpool_content` — `{pending: {addr: {nonce: tx}}, queued: …}`
    /// with full pending-transaction objects (geth shape: positional
    /// block fields are `null` for pooled txs).
    pub(crate) fn txpool_content(&self) -> Result<Value, RpcError> {
        let pool = self.require_txpool()?;
        Ok(txpool_content_json(&pool.txpool_snapshot(), None))
    }

    /// `txpool_contentFrom` — like `txpool_content` but restricted to
    /// one sender address (geth extension used by block explorers).
    pub(crate) fn txpool_content_from(&self, params: &[Value]) -> Result<Value, RpcError> {
        let pool = self.require_txpool()?;
        let addr = params
            .first()
            .and_then(Value::as_str)
            .and_then(|s| s.strip_prefix("0x").map(str::to_owned).or_else(|| Some(s.to_owned())))
            .and_then(|s| hex::decode(s).ok())
            .and_then(|b| <[u8; 20]>::try_from(b.as_slice()).ok())
            .map(primitives::Address)
            .ok_or_else(|| RpcError {
                code: -32_602,
                message: "invalid address parameter".to_string(),
                data: None,
            })?;
        Ok(txpool_content_json(&pool.txpool_snapshot(), Some(addr)))
    }

    /// `eth_pendingTransactions` — a flat array of the pool's
    /// *pending* (executable) transactions as full tx objects
    /// (`blockHash`/`blockNumber`/`transactionIndex` null — geth's
    /// shape for unmined txs). Queued txs behind nonce gaps are
    /// excluded, matching geth's pending-set definition.
    pub(crate) fn eth_pending_transactions(&self) -> Result<Value, RpcError> {
        let pool = self.require_txpool()?;
        let txs: Vec<Value> =
            pool.txpool_snapshot().iter().filter(|item| item.pending).map(pooled_tx_json).collect();
        Ok(json!(txs))
    }

    /// `txpool_inspect` — same grouping as `txpool_content` but each
    /// leaf is geth's summary string `"to: value wei + gas × price"`.
    pub(crate) fn txpool_inspect(&self) -> Result<Value, RpcError> {
        let pool = self.require_txpool()?;
        let mut pending = serde_json::Map::new();
        let mut queued = serde_json::Map::new();
        for item in pool.txpool_snapshot() {
            let addr = format!("0x{}", hex::encode(item.sender.0));
            let bucket = if item.pending { &mut pending } else { &mut queued };
            let entry = bucket.entry(addr).or_insert_with(|| json!({}));
            if let Some(m) = entry.as_object_mut() {
                m.insert(format!("0x{:x}", item.nonce), txpool_inspect_summary(&item));
            }
        }
        Ok(json!({ "pending": pending, "queued": queued }))
    }

    // ---- Debug / tracing ----

    /// `debug_traceTransaction` — the recorded call tree for a
    /// sealed transaction.
    ///
    /// Traces are captured at execution time (see `evm::trace`):
    /// there is no archive state to re-execute against, so this is a
    /// history lookup bounded by the same retention window as every
    /// other history query. A hash outside the window returns the
    /// geth-style "transaction not found" error; a missing trace
    /// (impossible for an executed tx) returns a server error rather
    /// than fabricated output.
    ///
    /// Options: `{"tracer": "callTracer"}` is the only supported
    /// tracer — the struct-logger (`{structLogs}`) output geth
    /// produces by default is not recorded (per-step tracing is too
    /// expensive to run on every committed tx). An absent `tracer`
    /// therefore returns the callTracer shape — a documented
    /// deviation from geth; a named-but-unsupported tracer is a
    /// `-32602` error rather than a silently wrong shape.
    pub(crate) fn debug_trace_transaction(&self, params: &[Value]) -> Result<Value, RpcError> {
        let hash = params
            .first()
            .map(parse_b256)
            .transpose()?
            .ok_or_else(|| RpcError::invalid_params("missing tx hash"))?;
        parse_trace_options(params.get(1))?;
        let evm = self.require_evm()?;
        let history = evm.history();
        let Some((height, tx_index)) = history.tx_location(&hash) else {
            return Err(RpcError {
                code: -32_000,
                message: "transaction not found (or evicted from the history window)".to_string(),
                data: None,
            });
        };
        let Some(block) = history.block(height) else {
            return Err(RpcError {
                code: -32_000,
                message: "block evicted from history window".to_string(),
                data: None,
            });
        };
        let idx = tx_index as usize;
        let Some(Some(frame)) = block.traces.get(idx) else {
            return Err(RpcError {
                code: -32_000,
                message: "no call trace recorded for this transaction".to_string(),
                data: None,
            });
        };
        // Root-frame `gas`/`gasUsed` are tx-level in geth's
        // callTracer (the recorder reports frame-scoped values —
        // patch with the tx gas limit and the receipt's total gas
        // used, which includes the intrinsic cost).
        let tx = &block.txs[idx];
        let receipt = &block.receipts[idx];
        Ok(call_frame_json(frame, Some((tx.gas_limit, receipt.gas_used))))
    }

    /// `debug_traceCall` — simulate a call against latest state and
    /// return its call tree. Always servable: it executes fresh
    /// rather than needing recorded history.
    pub(crate) fn debug_trace_call(&self, params: &[Value]) -> Result<Value, RpcError> {
        let mut req = parse_call_object(params.first().ok_or_else(|| RpcError {
            code: -32_602,
            message: "missing call object".to_string(),
            data: None,
        })?)?;
        // Optional block tag — historical heights within the
        // retained undo window are servable.
        let h = self.resolve_block_ref(params.get(1))?;
        let ovr = parse_trace_options(params.get(2))?;
        // Same gas-cap clamp as `eth_call` — an unbounded simulation
        // is a resource-exhaustion vector.
        if req.gas.is_some_and(|g| g > types::CHAIN_BLOCK_GAS_LIMIT) {
            req.gas = Some(types::CHAIN_BLOCK_GAS_LIMIT);
        }
        let evm = self.require_evm()?;
        let gas_cap = req.gas.unwrap_or(evm.block_gas_limit());
        // Revert/halt is a *trace result*, not an RPC error — geth
        // returns the call tree with the frame's `error` set.
        let (gas_used, frame) =
            evm.call_read_traced_with_overrides(&req, Some(h), &ovr).map_err(call_error)?;
        let Some(frame) = frame else {
            return Err(RpcError {
                code: -32_000,
                message: "call produced no trace".to_string(),
                data: None,
            });
        };
        Ok(call_frame_json(&frame, Some((gas_cap, gas_used))))
    }

    /// `debug_traceBlockByNumber` — per-tx call trees for a sealed
    /// block, `[{txHash, result}]` in block order (geth shape).
    pub(crate) fn debug_trace_block_by_number(&self, params: &[Value]) -> Result<Value, RpcError> {
        parse_trace_options(params.get(1))?;
        let height = self.resolve_block_ref(params.first())?;
        self.trace_block_at(height)
    }

    /// `debug_traceBlockByHash` — same body keyed by block hash.
    pub(crate) fn debug_trace_block_by_hash(&self, params: &[Value]) -> Result<Value, RpcError> {
        let hash = params
            .first()
            .map(parse_b256)
            .transpose()?
            .ok_or_else(|| RpcError::invalid_params("missing block hash"))?;
        parse_trace_options(params.get(1))?;
        let evm = self.require_evm()?;
        let history = evm.history();
        let Some(block) = history.block_by_hash(&hash) else {
            return Err(RpcError {
                code: -32_000,
                message: "block not found (or evicted from the history window)".to_string(),
                data: None,
            });
        };
        let number = block.number;
        drop(history);
        self.trace_block_at(number)
    }

    /// Shared per-block trace body for `debug_traceBlock*`.
    pub(crate) fn trace_block_at(&self, height: u64) -> Result<Value, RpcError> {
        let evm = self.require_evm()?;
        let history = evm.history();
        let Some(block) = history.block(height) else {
            return Err(RpcError {
                code: -32_000,
                message: "block not found (or evicted from the history window)".to_string(),
                data: None,
            });
        };
        let out: Vec<Value> = block
            .txs
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                let result = match block.traces.get(i) {
                    Some(Some(frame)) => {
                        call_frame_json(frame, Some((tx.gas_limit, block.receipts[i].gas_used)))
                    }
                    _ => Value::Null,
                };
                json!({ "txHash": format!("0x{:x}", tx.hash), "result": result })
            })
            .collect();
        Ok(Value::Array(out))
    }

    /// Fetch a filter by ID, refreshing its liveness timestamp.
    /// Expired or unknown IDs produce geth's `filter not found`
    /// error (-32000).
    pub(crate) fn take_filter(&self, id: &str) -> Result<FilterEntry, RpcError> {
        let mut filters = primitives::sync::lock_state(&self.filters);
        let not_found =
            || RpcError { code: -32_000, message: "filter not found".to_string(), data: None };
        let entry = filters.get_mut(id).ok_or_else(not_found)?;
        let now = std::time::Instant::now();
        if now.duration_since(entry.last_poll) >= FILTER_TIMEOUT {
            filters.remove(id);
            return Err(not_found());
        }
        entry.last_poll = now;
        // The caller mutates cursors through the entry; simplest
        // correct approach is to remove and let the caller re-insert
        // — but then a concurrent poll could see a missing filter.
        // Filters are per-client state and the lock is held for the
        // whole update, so take-and-reinsert under one lock hold is
        // equivalent; we take to keep ownership simple.
        Ok(filters.remove(id).expect("entry present"))
    }

    /// `eth_getFilterChanges` — poll a filter for new results.
    ///
    /// - Log filter → logs in `(last_served, latest]`
    /// - Block filter → block hashes in `(last_served, latest]`
    /// - `PendingTx` filter → mempool-arrival tx hashes since last poll
    pub(crate) fn eth_get_filter_changes(&self, params: &[Value]) -> Result<Value, RpcError> {
        let id = parse_filter_id(params.first())?;
        let mut entry = self.take_filter(&id)?;
        let latest = self.latest_sealed_height();
        let result = match &mut entry.kind {
            FilterKind::Log { filter, last_served } => {
                let changes = if latest > *last_served {
                    let delta = LogFilter {
                        from_block: *last_served + 1,
                        to_block: latest,
                        addresses: filter.addresses.clone(),
                        topics: filter.topics.clone(),
                        ..LogFilter::default()
                    };
                    let evm = self.require_evm()?;
                    let matches = evm.history().logs(&delta);
                    if matches.len() > MAX_LOG_RESULTS {
                        // Reinsert the filter before erroring so the
                        // poll cursor survives — the client can still
                        // narrow the filter via a new `eth_newFilter`.
                        *last_served = latest;
                        let result = Err(RpcError {
                            code: -32_005,
                            message: format!(
                                "query returned more than {MAX_LOG_RESULTS} results; \
                                 narrow the filter"
                            ),
                            data: None,
                        });
                        primitives::sync::lock_state(&self.filters).insert(id.clone(), entry);
                        return result;
                    }
                    matches.iter().map(log_json).collect()
                } else {
                    Vec::new()
                };
                *last_served = latest;
                Value::Array(changes)
            }
            FilterKind::Block { last_served } => {
                let mut hashes = Vec::new();
                if latest > *last_served {
                    let evm = self.require_evm()?;
                    let history = evm.history();
                    for h in (*last_served + 1)..=latest {
                        if let Some(block) = history.block(h) {
                            hashes.push(json!(format!("0x{:x}", block.hash)));
                        }
                    }
                }
                *last_served = latest;
                Value::Array(hashes)
            }
            FilterKind::PendingTx { next_seq } => {
                let ring = primitives::sync::lock_state(&self.pending_txs);
                let hashes: Vec<Value> = ring
                    .entries
                    .iter()
                    .filter(|(seq, _)| *seq >= *next_seq)
                    .map(|(_, hash)| json!(format!("0x{hash:x}")))
                    .collect();
                *next_seq = ring.next_seq;
                drop(ring);
                Value::Array(hashes)
            }
        };
        primitives::sync::lock_state(&self.filters).insert(id, entry);
        Ok(result)
    }

    /// `eth_getFilterLogs` — all logs matching a log filter's stored
    /// criteria (unlike `getFilterChanges`, this does not advance a
    /// cursor). Non-log filters and unknown IDs produce geth's
    /// `filter not found` error.
    pub(crate) fn eth_get_filter_logs(&self, params: &[Value]) -> Result<Value, RpcError> {
        let id = parse_filter_id(params.first())?;
        let entry = self.take_filter(&id)?;
        let not_found =
            || RpcError { code: -32_000, message: "filter not found".to_string(), data: None };
        let FilterKind::Log { filter, .. } = &entry.kind else {
            // Re-insert before erroring so a block/pending filter
            // survives an erroneous `getFilterLogs` call.
            primitives::sync::lock_state(&self.filters).insert(id, entry);
            return Err(not_found());
        };
        let evm = self.require_evm()?;
        let matches = evm.history().logs(filter);
        let result = if matches.len() > MAX_LOG_RESULTS {
            Err(RpcError {
                code: -32_005,
                message: format!(
                    "query returned more than {MAX_LOG_RESULTS} results; narrow the filter"
                ),
                data: None,
            })
        } else {
            Ok(Value::Array(matches.iter().map(log_json).collect()))
        };
        primitives::sync::lock_state(&self.filters).insert(id, entry);
        result
    }

    /// Record a transaction entering this node's mempool — feeds
    /// `newPendingTransactions` subscribers and pending-tx filters.
    /// `hash` is the Ethereum tx hash (keccak256 of the signed RLP),
    /// not the envelope hash.
    pub fn record_pending_tx(&self, hash: B256) {
        {
            let mut ring = primitives::sync::lock_state(&self.pending_txs);
            if ring.entries.len() >= PENDING_RING_CAP {
                ring.entries.pop_front();
            }
            let seq = ring.next_seq;
            ring.entries.push_back((seq, hash));
            ring.next_seq = seq.saturating_add(1);
        }
        self.subscriptions.publish_pending_tx(hash);
    }

    // ---- Phase E: extended RPC methods ----

    /// `net_listening` — returns `true` (Oxide is always listening).
    pub(crate) fn net_listening(&self) -> Value {
        let _ = self;
        json!(true)
    }

    /// `net_peerCount` — returns the peer count as hex. Phase E v0
    /// returns `0x0` (no P2P wired yet).
    pub(crate) fn net_peer_count(&self) -> Value {
        let _ = self;
        json!("0x0")
    }

    /// `web3_sha3` — returns keccak-256 of the input data.
    ///
    /// Params: `[data: String]` (hex-encoded data)
    pub(crate) fn web3_sha3(&self, params: &[Value]) -> Result<Value, RpcError> {
        let _ = self;
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing data"));
        }
        let data_hex = params[0]
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("data must be a hex string"))?;
        let data = hex_decode(data_hex)?;
        let hash = keccak256(&data);
        Ok(json!(format!("0x{}", hex::encode(hash))))
    }

    /// `eth_getCode` — returns the code at a given address.
    ///
    /// Params: `[address: String, block: String?]`
    pub(crate) fn eth_get_code(&self, params: &[Value]) -> Result<Value, RpcError> {
        let addr = parse_address(params.first())?;
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(1))?;
        evm.code_at(&addr, h).map(|c| json!(format!("0x{}", hex::encode(c)))).map_err(state_error)
    }

    /// `eth_getStorageAt` — returns the storage value at a given
    /// address and slot.
    ///
    /// Params: `[address: String, slot: String, block: String?]`
    pub(crate) fn eth_get_storage_at(&self, params: &[Value]) -> Result<Value, RpcError> {
        let addr = parse_address(params.first())?;
        let slot = parse_u256(
            params.get(1).ok_or_else(|| RpcError::invalid_params("missing storage slot"))?,
        )?;
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(2))?;
        let value = evm.storage_at_height(&addr, &slot, h).map_err(state_error)?;
        Ok(json!(format!("0x{value:064x}")))
    }

    /// `eth_getProof` — EIP-1186 account + storage Merkle proofs.
    ///
    /// Params: `[address: String, storageKeys: String[], block: String?]`
    ///
    /// The proof is rebuilt from the state at the requested height
    /// via `HashBuilder` + `ProofRetainer` — `O(state)` per call, a
    /// cold-path archive query. Heights below the retained window
    /// return geth's `missing trie node` error.
    pub(crate) fn eth_get_proof(&self, params: &[Value]) -> Result<Value, RpcError> {
        let addr = parse_address(params.first())?;
        let keys = params
            .get(1)
            .and_then(Value::as_array)
            .ok_or_else(|| RpcError::invalid_params("missing storage keys array"))?;
        let mut slots = Vec::with_capacity(keys.len());
        for k in keys {
            slots.push(parse_b256(k)?);
        }
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(2))?;
        let proof = evm.account_proof(&addr, &slots, h).map_err(call_error)?;
        Ok(json!({
            "address": format!("0x{}", hex::encode(proof.address.0)),
            "accountProof": proof
                .account_proof
                .iter()
                .map(|n| format!("0x{}", hex::encode(n)))
                .collect::<Vec<_>>(),
            "balance": format!("0x{:x}", proof.balance),
            "codeHash": format!("0x{}", hex::encode(proof.code_hash)),
            "nonce": format!("0x{:x}", proof.nonce),
            "storageHash": format!("0x{}", hex::encode(proof.storage_hash)),
            "storageProof": proof
                .storage_proofs
                .iter()
                .map(|sp| json!({
                    "key": format!("0x{}", hex::encode(sp.key)),
                    "value": format!("0x{:x}", sp.value),
                    "proof": sp
                        .proof
                        .iter()
                        .map(|n| format!("0x{}", hex::encode(n)))
                        .collect::<Vec<_>>(),
                }))
                .collect::<Vec<_>>(),
        }))
    }

    /// `eth_getBlockByNumber` — returns a block by number.
    ///
    /// Params: `[blockNumber: String|Object, fullTransactions: bool]`
    ///
    /// Serves the module's sealed-block history window; heights
    /// outside the window (evicted or future) return `null`.
    pub(crate) fn eth_get_block_by_number(&self, params: &[Value]) -> Result<Value, RpcError> {
        let evm = self.require_evm()?;
        let full = params.get(1).and_then(Value::as_bool).unwrap_or(false);
        let number = self.resolve_block_ref(params.first())?;
        let history = evm.history();
        Ok(match history.block(number) {
            Some(block) => block_json(block, full),
            None => Value::Null,
        })
    }

    /// `eth_getBlockByHash` — returns a block by hash.
    ///
    /// Params: `[blockHash: String, fullTransactions: bool]`
    pub(crate) fn eth_get_block_by_hash(&self, params: &[Value]) -> Result<Value, RpcError> {
        let hash = parse_b256(
            params.first().ok_or_else(|| RpcError::invalid_params("missing block hash"))?,
        )?;
        let evm = self.require_evm()?;
        let full = params.get(1).and_then(Value::as_bool).unwrap_or(false);
        let history = evm.history();
        Ok(match history.block_by_hash(&hash) {
            Some(block) => block_json(block, full),
            None => Value::Null,
        })
    }

    /// `eth_getBlockTransactionCountByNumber` — returns the number of
    /// transactions in a block.
    ///
    /// Params: `[blockNumber: String]`
    pub(crate) fn eth_get_block_tx_count_by_number(
        &self,
        params: &[Value],
    ) -> Result<Value, RpcError> {
        let evm = self.require_evm()?;
        let number = self.resolve_block_ref(params.first())?;
        let history = evm.history();
        Ok(match history.block(number) {
            Some(block) => json!(format!("0x{:x}", block.txs.len())),
            None => Value::Null,
        })
    }

    /// `eth_getBlockTransactionCountByHash` — returns the number of
    /// transactions in a block by hash.
    ///
    /// Params: `[blockHash: String]`
    pub(crate) fn eth_get_block_tx_count_by_hash(
        &self,
        params: &[Value],
    ) -> Result<Value, RpcError> {
        let hash = parse_b256(
            params.first().ok_or_else(|| RpcError::invalid_params("missing block hash"))?,
        )?;
        let evm = self.require_evm()?;
        let history = evm.history();
        Ok(match history.block_by_hash(&hash) {
            Some(block) => json!(format!("0x{:x}", block.txs.len())),
            None => Value::Null,
        })
    }

    /// `eth_getTransactionByHash` — returns a transaction by hash.
    ///
    /// Params: `[txHash: String]`
    pub(crate) fn eth_get_transaction_by_hash(&self, params: &[Value]) -> Result<Value, RpcError> {
        let hash =
            parse_b256(params.first().ok_or_else(|| RpcError::invalid_params("missing tx hash"))?)?;
        let evm = self.require_evm()?;
        let history = evm.history();
        Ok(match history.tx_location(&hash) {
            Some((height, index)) => history
                .block(height)
                .and_then(|b| b.txs.get(index as usize).map(|t| tx_json(t, b)))
                .unwrap_or(Value::Null),
            None => Value::Null,
        })
    }

    /// `eth_getTransactionByBlockNumberAndIndex` — returns a tx by
    /// block number and index.
    ///
    /// Params: `[blockNumber: String, index: String]`
    pub(crate) fn eth_get_transaction_by_block_and_index(
        &self,
        params: &[Value],
    ) -> Result<Value, RpcError> {
        let evm = self.require_evm()?;
        let number = self.resolve_block_ref(params.first())?;
        let index =
            parse_u64(params.get(1).ok_or_else(|| RpcError::invalid_params("missing tx index"))?)?;
        let history = evm.history();
        let i = usize::try_from(index).unwrap_or(usize::MAX);
        Ok(match history.block(number) {
            Some(block) => block.txs.get(i).map_or(Value::Null, |t| tx_json(t, block)),
            None => Value::Null,
        })
    }

    /// `eth_getTransactionByBlockHashAndIndex` — returns a tx by
    /// block hash and index.
    ///
    /// Params: `[blockHash: String, index: String]`
    pub(crate) fn eth_get_transaction_by_block_hash_and_index(
        &self,
        params: &[Value],
    ) -> Result<Value, RpcError> {
        let hash = parse_b256(
            params.first().ok_or_else(|| RpcError::invalid_params("missing block hash"))?,
        )?;
        let evm = self.require_evm()?;
        let index =
            parse_u64(params.get(1).ok_or_else(|| RpcError::invalid_params("missing tx index"))?)?;
        let history = evm.history();
        let i = usize::try_from(index).unwrap_or(usize::MAX);
        Ok(match history.block_by_hash(&hash) {
            Some(block) => block.txs.get(i).map_or(Value::Null, |t| tx_json(t, block)),
            None => Value::Null,
        })
    }

    /// `eth_getTransactionReceipt` — returns a transaction receipt.
    ///
    /// Params: `[txHash: String]`
    pub(crate) fn eth_get_transaction_receipt(&self, params: &[Value]) -> Result<Value, RpcError> {
        let hash =
            parse_b256(params.first().ok_or_else(|| RpcError::invalid_params("missing tx hash"))?)?;
        let evm = self.require_evm()?;
        let history = evm.history();
        Ok(match history.tx_location(&hash) {
            Some((height, index)) => history.block(height).map_or(Value::Null, |block| {
                let i = index as usize;
                match (block.txs.get(i), block.receipts.get(i)) {
                    (Some(tx), Some(receipt)) => {
                        let cumulative = evm::receipts::Receipt::cumulative_gas(&block.receipts);
                        let log_base: u32 = block.receipts[..i]
                            .iter()
                            .map(|r| u32::try_from(r.logs.len()).unwrap_or(u32::MAX))
                            .sum();
                        receipt_json(tx, receipt, block, cumulative[i], log_base)
                    }
                    _ => Value::Null,
                }
            }),
            None => Value::Null,
        })
    }

    /// `eth_sendRawTransaction` — submits a raw EVM transaction.
    ///
    /// Params: `[rawTx: String]` (hex-encoded RLP transaction)
    ///
    /// When a [`TxSubmitter`] is attached, the raw RLP bytes are decoded
    /// into an [`evm::tx::SignedTx`], the sender is recovered via
    /// secp256k1, and the transaction is wrapped in the Oxide envelope
    /// (`evm::wrap_evm_tx_envelope`) and pushed into the mempool. The
    /// returned hash is the keccak256 of the raw RLP — the canonical
    /// Ethereum transaction hash.
    ///
    /// When no submitter is attached, the hash is still computed and
    /// returned, but the transaction is not submitted (Phase 2 v0
    /// behaviour, retained for stateless unit tests).
    pub(crate) fn eth_send_raw_transaction(&self, params: &[Value]) -> Result<Value, RpcError> {
        let start = std::time::Instant::now();
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing raw transaction"));
        }
        let raw_hex = params[0]
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("raw tx must be a hex string"))?;
        let raw = hex_decode(raw_hex)?;
        // The canonical Ethereum tx hash is keccak256 of the raw RLP.
        let hash = keccak256(&raw);

        if let Some(submitter) = &self.tx_submitter {
            // Decode the raw RLP into a signed EVM transaction. This
            // validates the transaction's structure (legacy, EIP-2930,
            // or EIP-1559) and lets us recover the sender and extract
            // the nonce and fee needed for the Oxide envelope.
            let signed = evm::tx::SignedTx::decode_raw(&raw).map_err(|e| {
                RpcError::invalid_params(&format!("invalid raw transaction: {e:?}"))
            })?;
            // Recover the sender's Ethereum address from the
            // signature. This is the same recovery the EVM module
            // performs during execution; doing it here lets the
            // mempool order by sender nonce without re-decoding.
            let sender = signed
                .recover_sender()
                .map_err(|e| RpcError::invalid_params(&format!("invalid signature: {e:?}")))?;
            // The envelope fee is the max fee per gas (EIP-1559) or
            // the gas price (legacy/EIP-2930), truncated to u64. The
            // mempool uses this for fee-density ranking. Amounts that
            // do not fit in u64 are rejected — Ethereum gas prices
            // are always small in practice, but we guard against
            // malformed input.
            let fee_u256 = signed.max_fee_per_gas();
            let fee: u64 = u64::try_from(fee_u256)
                .map_err(|_| RpcError::invalid_params("fee exceeds u64 range"))?;
            let nonce = signed.nonce();
            // Wrap the raw RLP in the Oxide envelope and submit.
            let envelope = evm::wrap_evm_tx_envelope(&sender, nonce, fee, &raw);
            submitter
                .submit_tx(TxBytes::new(envelope))
                .map_err(|reason| RpcError::transaction_rejected(&reason))?;
            // Feed pending-tx subscribers/filters — the tx is now
            // in this node's mempool.
            self.record_pending_tx(B256::from(hash));
        }

        if let Some(recorder) = &self.recorder {
            recorder.record("rpc_send_raw_tx", start.elapsed());
        }

        Ok(json!(format!("0x{}", hex::encode(hash))))
    }

    /// `oxide_sendRawTransaction` — submits a raw *native* module
    /// transaction (non-EVM).
    ///
    /// Params: `[rawTx: String]` (hex-encoded signed v1 envelope:
    /// `[sender][nonce][fee][module_id|0x80][sig:65B][payload]`).
    ///
    /// The envelope is pushed into the mempool as-is — admission
    /// checks (EIP-712 signature verification, replay protection,
    /// module validation) run inside `ingest_tx`, so this method is
    /// a thin decode+submit. The returned hash is the domain-tagged
    /// BLAKE3 transaction hash the executor/mempool index by — not
    /// keccak256 of the raw bytes, since the envelope is not an
    /// Ethereum tx.
    pub(crate) fn oxide_send_raw_transaction(&self, params: &[Value]) -> Result<Value, RpcError> {
        if params.is_empty() {
            return Err(RpcError::invalid_params("missing raw transaction"));
        }
        let raw_hex = params[0]
            .as_str()
            .ok_or_else(|| RpcError::invalid_params("raw tx must be a hex string"))?;
        let raw = hex_decode(raw_hex)?;
        // The executor/mempool tx hash is BLAKE3 over the full
        // envelope under Domain::Transaction.
        let hash = crypto::hash::Hasher::hash_one(crypto::hash::Domain::Transaction, &raw);

        if let Some(submitter) = &self.tx_submitter {
            submitter
                .submit_tx(TxBytes::new(raw))
                .map_err(|reason| RpcError::transaction_rejected(&reason))?;
        }

        Ok(json!(format!("0x{}", hex::encode(hash.0))))
    }

    /// `eth_call` — executes a call without persisting state.
    ///
    /// Params: `[call: Object, block: String?]`
    ///
    /// Runs on the module's simulation env (nonce/block-gas-limit/
    /// base-fee checks disabled; balance and fee checks kept, as in
    /// geth's `DoCall`). Reverts surface as JSON-RPC error code 3
    /// with the revert data attached — the shape web3 libraries
    /// decode into `Error(string)` reasons.
    pub(crate) fn eth_call(&self, params: &[Value]) -> Result<Value, RpcError> {
        let call = params.first().ok_or_else(|| RpcError::invalid_params("missing call object"))?;
        let mut req = parse_call_object(call)?;
        // Gas cap: a request may ask for more gas than any real tx
        // can carry. geth clamps `msg.GasLimit` to `--rpc.gascap`
        // (50M default) rather than erroring; our equivalent ceiling
        // is the block gas limit — a simulation can never need more.
        if req.gas.is_some_and(|g| g > types::CHAIN_BLOCK_GAS_LIMIT) {
            req.gas = Some(types::CHAIN_BLOCK_GAS_LIMIT);
        }
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(1))?;
        let ovr = parse_state_overrides(params.get(2))?;
        match evm.call_read_with_overrides(&req, Some(h), &ovr) {
            Ok(outcome) => Ok(json!(format!("0x{}", hex::encode(outcome.output)))),
            Err(e) => Err(call_error(e)),
        }
    }

    /// `eth_estimateGas` — estimates gas for a call.
    ///
    /// Params: `[call: Object, block: String?]`
    ///
    /// Binary-searches the simulation env for the smallest succeeding
    /// gas limit (geth/reth semantics). A call that cannot succeed at
    /// the block gas limit surfaces the underlying revert/halt error.
    pub(crate) fn eth_estimate_gas(&self, params: &[Value]) -> Result<Value, RpcError> {
        let call = params.first().ok_or_else(|| RpcError::invalid_params("missing call object"))?;
        let req = parse_call_object(call)?;
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(1))?;
        let ovr = parse_state_overrides(params.get(2))?;
        match evm.estimate_call_gas_with_overrides(&req, Some(h), &ovr) {
            Ok(gas) => Ok(json!(format!("0x{gas:x}"))),
            Err(e) => Err(call_error(e)),
        }
    }

    /// `eth_createAccessList` — generate the access list a call
    /// would touch (`{accessList, gasUsed}`).
    ///
    /// Params: `[call: Object, block: String?]`. Same call-object
    /// semantics as `eth_call` including a caller-supplied
    /// `accessList` (kept verbatim in the result, per geth).
    /// `gasUsed` is measured with the provided list applied — geth
    /// does not re-run with the generated one. Gas is clamped to the
    /// block limit exactly like `eth_call` (`gas-cap`).
    pub(crate) fn eth_create_access_list(&self, params: &[Value]) -> Result<Value, RpcError> {
        let call = params.first().ok_or_else(|| RpcError::invalid_params("missing call object"))?;
        let mut req = parse_call_object(call)?;
        if req.gas.is_some_and(|g| g > types::CHAIN_BLOCK_GAS_LIMIT) {
            req.gas = Some(types::CHAIN_BLOCK_GAS_LIMIT);
        }
        let evm = self.require_evm()?;
        let h = self.resolve_block_ref(params.get(1))?;
        match evm.create_access_list_at(&req, h) {
            Ok((list, gas_used)) => Ok(json!({
                "accessList": list.iter().map(|item| json!({
                    "address": format!("0x{}", hex::encode(item.address.0)),
                    "storageKeys": item
                        .storage_keys
                        .iter()
                        .map(|k| format!("0x{}", hex::encode(k.0)))
                        .collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
                "gasUsed": format!("0x{gas_used:x}"),
            })),
            Err(e) => Err(call_error(e)),
        }
    }

    /// `eth_maxPriorityFeePerGas` — the oracle's suggested tip
    /// (p60 of recent-block inclusion tips, geth `GasPriceOracle`).
    /// Without an EVM there is no sample history — return the 1 gwei
    /// default geth falls back to.
    pub(crate) fn eth_max_priority_fee_per_gas(&self) -> Value {
        let tip = match self.evm.as_deref() {
            Some(evm) => evm.suggest_gas_tip(),
            None => 1_000_000_000,
        };
        json!(format!("0x{tip:x}"))
    }

    /// `eth_getBlockReceipts` — returns all receipts for a block.
    ///
    /// Params: `[block: String]`
    pub(crate) fn eth_get_block_receipts(&self, params: &[Value]) -> Result<Value, RpcError> {
        let evm = self.require_evm()?;
        let number = self.resolve_block_ref(params.first())?;
        let history = evm.history();
        Ok(match history.block(number) {
            Some(block) => {
                let cumulative = evm::receipts::Receipt::cumulative_gas(&block.receipts);
                let mut log_base = 0u32;
                Value::Array(
                    block
                        .txs
                        .iter()
                        .zip(block.receipts.iter())
                        .zip(cumulative.iter())
                        .map(|((tx, receipt), &cum)| {
                            let json = receipt_json(tx, receipt, block, cum, log_base);
                            log_base = log_base.saturating_add(
                                u32::try_from(receipt.logs.len()).unwrap_or(u32::MAX),
                            );
                            json
                        })
                        .collect(),
                )
            }
            None => Value::Null,
        })
    }

    /// `eth_getLogs` — returns logs matching a filter.
    ///
    /// Params: `[filter: Object]` with `fromBlock`, `toBlock`,
    /// `address` (string or array), `topics` (positional array of
    /// hash / hash-array / null), or `blockHash` (EIP-234
    /// single-block form).
    ///
    /// Bounds: the scan is limited to the retained history window
    /// and `MAX_LOG_RESULTS` entries — an unbounded request returns
    /// `-32005` rather than OOM-ing the node (geth applies the same
    /// resource-limit principle via `FilterQuery` caps).
    pub(crate) fn eth_get_logs(&self, params: &[Value]) -> Result<Value, RpcError> {
        let filter_obj =
            params.first().ok_or_else(|| RpcError::invalid_params("missing filter"))?;
        if !filter_obj.is_object() {
            return Err(RpcError::invalid_params("filter must be an object"));
        }
        let evm = self.require_evm()?;
        let filter = self.parse_log_filter(filter_obj)?;
        let history = evm.history();
        let matches = history.logs(&filter);
        if matches.len() > MAX_LOG_RESULTS {
            return Err(RpcError {
                code: -32_005,
                message: format!(
                    "query returned more than {MAX_LOG_RESULTS} results; narrow the filter"
                ),
                data: None,
            });
        }
        Ok(Value::Array(matches.iter().map(log_json).collect()))
    }

    /// `eth_feeHistory` — returns fee history.
    ///
    /// Params: `[blockCount: String, newestBlock: String, rewardPercentiles: Array?]`
    ///
    /// Serves per-block `baseFeePerGas`, `gasUsedRatio`, and (when
    /// percentiles are requested) per-block priority-fee percentiles
    /// over executed transactions — the same shape geth returns.
    pub(crate) fn eth_fee_history(&self, params: &[Value]) -> Result<Value, RpcError> {
        let count = parse_u64(
            params.first().ok_or_else(|| RpcError::invalid_params("missing blockCount"))?,
        )?;
        if count == 0 {
            return Err(RpcError::invalid_params("blockCount must be > 0"));
        }
        if count > MAX_FEE_HISTORY_BLOCKS {
            return Err(RpcError::invalid_params(&format!(
                "blockCount exceeds maximum {MAX_FEE_HISTORY_BLOCKS}"
            )));
        }
        let evm = self.require_evm()?;
        let newest = self.resolve_block_ref(params.get(1))?;
        let percentiles: Vec<f64> = params
            .get(2)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_f64).collect())
            .unwrap_or_default();
        let history = evm.history();
        let latest = history.latest().unwrap_or(0);
        let newest = newest.min(latest);
        // `+1` for the EIP-1559 next-block base fee geth appends.
        let oldest = newest.saturating_sub(count).saturating_add(1);
        // `count` ≤ MAX_FEE_HISTORY_BLOCKS (checked above) — always
        // fits usize even on 32-bit targets.
        let cap = usize::try_from(count).unwrap_or(0);
        let mut base_fees = Vec::with_capacity(cap + 1);
        let mut ratios = Vec::with_capacity(cap);
        let mut rewards: Vec<Vec<String>> = Vec::with_capacity(cap);
        for h in oldest..=newest {
            if let Some(block) = history.block(h) {
                base_fees.push(format!("0x{:x}", block.base_fee));
                #[allow(clippy::cast_precision_loss)]
                ratios.push(block.gas_used as f64 / block.gas_limit.max(1) as f64);
                if !percentiles.is_empty() {
                    rewards.push(block_reward_percentiles(block, &percentiles));
                }
            } else {
                base_fees.push("0x0".to_string());
                ratios.push(0.0);
                if !percentiles.is_empty() {
                    rewards.push(Vec::new());
                }
            }
        }
        // The next block's base fee: our base fee is configured
        // statically (no EIP-1559 adjustment), so it repeats.
        base_fees.push(format!("0x{:x}", self.base_fee));
        let mut out = json!({
            "oldestBlock": format!("0x{oldest:x}"),
            "baseFeePerGas": base_fees,
            "gasUsedRatio": ratios,
        });
        if !percentiles.is_empty() {
            out["reward"] = json!(rewards);
        }
        Ok(out)
    }

    /// `eth_mining` — returns whether the node is mining.
    pub(crate) fn eth_mining(&self) -> Value {
        let _ = self;
        json!(false)
    }

    /// `eth_syncing` — returns sync status.
    pub(crate) fn eth_syncing(&self) -> Value {
        let _ = self;
        json!(false)
    }

    /// `eth_protocolVersion` — returns the protocol version.
    pub(crate) fn eth_protocol_version(&self) -> Value {
        let _ = self;
        json!("0x41")
    }

    /// `eth_accounts` — returns the accounts the node manages.
    pub(crate) fn eth_accounts(&self) -> Value {
        let _ = self;
        json!([])
    }

    /// `eth_coinbase` — returns the coinbase address.
    pub(crate) fn eth_coinbase(&self) -> Value {
        let _ = self;
        json!("0x0000000000000000000000000000000000000000")
    }

    /// `eth_hashrate` — returns the hashrate.
    pub(crate) fn eth_hashrate(&self) -> Value {
        let _ = self;
        json!("0x0")
    }

    // ---- Helpers ----

    /// The attached EVM module, or an internal error when the node
    /// was built without one (stateless test harnesses).
    pub(crate) fn require_evm(&self) -> Result<&evm::EvmModule, RpcError> {
        self.evm.as_deref().ok_or_else(|| RpcError::internal_error("evm module unavailable"))
    }

    /// Resolve a block tag / number / EIP-1898 object to a concrete
    /// block height in the sealed history window.
    ///
    /// Tag semantics under instant-finality consensus:
    ///
    /// - `latest` — the most recently *sealed* block
    ///   (`history.latest()`; falls back to the executor-reported
    ///   height when no block has sealed yet).
    /// - `safe` / `finalized` — identical to `latest`: a committed
    ///   block is final, there is no unfinalized "latest".
    /// - `pending` — `latest` for lookups (no pending-block
    ///   simulation is implemented yet).
    /// - `earliest` — height 0.
    /// - `"0x…"` — a literal height; may resolve outside the
    ///   retained window (history queries then return `null`).
    /// - `{blockHash: "0x…"}` / `{blockNumber: "0x…"}` — EIP-1898
    ///   object form; an unknown hash is an error.
    pub(crate) fn resolve_block_ref(&self, tag: Option<&Value>) -> Result<u64, RpcError> {
        let latest = self.latest_sealed_height();
        match tag {
            None => Ok(latest),
            Some(Value::String(s)) => match s.as_str() {
                "latest" | "safe" | "finalized" | "pending" => Ok(latest),
                "earliest" => Ok(0),
                _ => {
                    let s = s.strip_prefix("0x").unwrap_or(s);
                    u64::from_str_radix(s, 16).map_err(|e| {
                        RpcError::invalid_params(&format!("invalid block number: {e}"))
                    })
                }
            },
            Some(Value::Object(obj)) => {
                if let Some(hash) = obj.get("blockHash") {
                    let hash = parse_b256(hash)?;
                    let evm = self.require_evm()?;
                    let history = evm.history();
                    return history
                        .block_by_hash(&hash)
                        .map(|b| b.number)
                        .ok_or_else(|| RpcError::invalid_params("unknown block hash"));
                }
                if let Some(number) = obj.get("blockNumber") {
                    return self.resolve_block_ref(Some(number));
                }
                Err(RpcError::invalid_params("invalid block object"))
            }
            Some(_) => Err(RpcError::invalid_params("block must be a tag, number, or object")),
        }
    }

    /// The height of the most recent sealed block — the height
    /// `"latest"` resolves to for state reads.
    ///
    /// The EVM module is authoritative: `history.latest()` when at
    /// least one block has sealed, else `current_height()` (the
    /// in-flight or genesis height). The RPC `block_height` counter
    /// is only the fallback when no EVM is attached — the two can
    /// diverge (the counter is set by the driver, while state reads
    /// must land inside the EVM's servable window).
    pub(crate) fn latest_sealed_height(&self) -> u64 {
        self.evm.as_deref().map_or_else(
            || self.block_height(),
            |evm| evm.history().latest().unwrap_or_else(|| evm.current_height()),
        )
    }

    /// Parse an `eth_getLogs`/`eth_newFilter` filter object into the
    /// module's [`LogFilter`].
    ///
    /// `fromBlock`/`toBlock` accept tags and hex numbers (default
    /// `latest`); `blockHash` (EIP-234) makes the range fields
    /// irrelevant. `address` accepts a string or array of strings;
    /// `topics` accepts `null`, a hash, or an array of hashes per
    /// position.
    pub(crate) fn parse_log_filter(&self, obj: &Value) -> Result<LogFilter, RpcError> {
        let mut filter = LogFilter {
            from_block: self.latest_sealed_height(),
            to_block: self.latest_sealed_height(),
            ..LogFilter::default()
        };
        let Some(map) = obj.as_object() else {
            return Err(RpcError::invalid_params("filter must be an object"));
        };
        if let Some(v) = map.get("blockHash") {
            filter.block_hash = Some(parse_b256(v)?);
        }
        if let Some(v) = map.get("fromBlock") {
            filter.from_block = self.resolve_block_ref(Some(v))?;
        }
        if let Some(v) = map.get("toBlock") {
            filter.to_block = self.resolve_block_ref(Some(v))?;
        }
        if filter.from_block > filter.to_block && filter.block_hash.is_none() {
            return Err(RpcError::invalid_params("fromBlock exceeds toBlock"));
        }
        match map.get("address") {
            None | Some(Value::Null) => {}
            Some(Value::String(_)) => {
                filter.addresses.push(parse_eth_address(map.get("address"))?);
            }
            Some(Value::Array(addrs)) => {
                for a in addrs {
                    filter.addresses.push(parse_eth_address(Some(a))?);
                }
            }
            Some(_) => {
                return Err(RpcError::invalid_params("address must be string or array"));
            }
        }
        if let Some(Value::Array(topics)) = map.get("topics") {
            for entry in topics {
                let matcher = match entry {
                    Value::Null => TopicMatcher::Any,
                    Value::String(_) => TopicMatcher::One(parse_b256(entry)?),
                    Value::Array(set) => TopicMatcher::AnyOf(
                        set.iter().map(parse_b256).collect::<Result<Vec<B256>, _>>()?,
                    ),
                    _ => {
                        return Err(RpcError::invalid_params(
                            "topics entries must be null, a hash, or an array",
                        ));
                    }
                };
                filter.topics.push(matcher);
            }
        }
        Ok(filter)
    }
}
