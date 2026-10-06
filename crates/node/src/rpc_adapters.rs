//! Adapters wiring [`executor::Executor`] to the `rpc` crate's
//! provider traits — executor → `TxSubmitter`/`TxpoolProvider`/
//! `SnapshotProvider` — shared by the validator and devnet binaries
//! so both build the identical RPC surface.
//!
//! The executor already implements [`ports::AppInterface`]; these
//! adapters translate its types into the `Result<(), String>` /
//! `TxpoolItem` shapes the RPC layer expects, keeping `rpc` free of
//! an executor dependency.

use std::sync::Arc;

use codec::Encode;
use ports::AppInterface;
use types::{MempoolAck, TxBytes};

/// Adapter that lets the RPC server submit transactions into the
/// executor's mempool via the `rpc::TxSubmitter` trait.
///
/// The executor already implements `AppInterface::ingest_tx`, which
/// validates, pre-verifies, and mempools a wrapped transaction. This
/// adapter translates the `MempoolAck` into the `Result<(), String>`
/// that the RPC layer expects, keeping the RPC crate free of a direct
/// dependency on the executor crate.
pub struct ExecutorTxSubmitter {
    /// The executor whose mempool receives submitted transactions.
    pub executor: Arc<executor::Executor>,
}

impl rpc::TxSubmitter for ExecutorTxSubmitter {
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
        match self.executor.ingest_tx(tx) {
            MempoolAck::Accepted => Ok(()),
            MempoolAck::Rejected { reason } => Err(reason),
        }
    }
}

/// `TxSubmitter` that additionally gossips accepted transactions to
/// all peers.
///
/// After the local mempool accepts a tx, the *envelope bytes* are
/// pushed onto a channel the consensus loop drains and broadcasts
/// as `MSG_TX` frames. Only locally submitted txs are gossiped —
/// received gossip is ingested but never re-broadcast, so in the
/// full-mesh validator topology each tx traverses exactly one hop
/// and no flood loop forms. The channel is bounded; a full channel
/// drops the gossip copy but never fails the local submission (the
/// originator's mempool still holds the tx, and the keep-alive path
/// ensures liveness for non-gossipped txs is unaffected — peers may
/// simply not see it until resubmission).
pub struct GossipingTxSubmitter {
    /// The mempool-submission adapter the gossip layer wraps.
    pub inner: ExecutorTxSubmitter,
    /// Bounded channel of envelope bytes the consensus loop drains
    /// and broadcasts as `MSG_TX` frames; a full channel drops the
    /// gossip copy but never fails the local submission.
    pub gossip: std::sync::mpsc::SyncSender<Vec<u8>>,
}

impl rpc::TxSubmitter for GossipingTxSubmitter {
    fn submit_tx(&self, tx: TxBytes) -> Result<(), String> {
        self.inner.submit_tx_ref(&tx)?;
        let _ = self.gossip.try_send(tx.as_bytes().to_vec());
        Ok(())
    }
}

impl ExecutorTxSubmitter {
    /// Submit without consuming `tx` — used by [`GossipingTxSubmitter`]
    /// to keep the bytes for the gossip frame.
    ///
    /// # Errors
    ///
    /// Returns the mempool's rejection reason if the executor
    /// declines the envelope.
    pub fn submit_tx_ref(&self, tx: &TxBytes) -> Result<(), String> {
        match self.executor.ingest_tx(TxBytes::new(tx.as_bytes().to_vec())) {
            MempoolAck::Accepted => Ok(()),
            MempoolAck::Rejected { reason } => Err(reason),
        }
    }
}

/// Adapter that lets the RPC server serve the `txpool_*` namespace
/// from the executor's mempool.
///
/// The executor's `txpool_snapshot` takes the mempool lock once and
/// clones the pooled envelopes — a cold-path read; the RPC layer
/// holds no lock across the snapshot and the block path is
/// unaffected. Keeping this an adapter (rather than having `rpc`
/// depend on `executor`) preserves the workspace's dependency
/// direction.
pub struct ExecutorTxpoolProvider {
    /// The executor whose mempool snapshot serves `txpool_*`.
    pub executor: Arc<executor::Executor>,
}

impl rpc::TxpoolProvider for ExecutorTxpoolProvider {
    fn txpool_snapshot(&self) -> Vec<rpc::TxpoolItem> {
        self.executor
            .txpool_snapshot()
            .into_iter()
            .map(|(sender, nonce, envelope, pending)| rpc::TxpoolItem {
                sender,
                nonce,
                envelope,
                pending,
            })
            .collect()
    }
}

/// Adapter that lets the RPC server export the executor's state
/// snapshot via the `rpc::SnapshotProvider` trait.
///
/// The executor's `export_snapshot` returns an `ExecutorSnapshot`;
/// this adapter codec-encodes it so the RPC layer can serve it as
/// hex bytes without a direct dependency on the executor crate's
/// internal types.
pub struct ExecutorSnapshotProvider {
    /// The executor whose state snapshot the RPC layer exports.
    pub executor: Arc<executor::Executor>,
}

impl rpc::SnapshotProvider for ExecutorSnapshotProvider {
    fn export_snapshot(&self) -> Result<Vec<u8>, String> {
        let snap = self.executor.export_snapshot();
        let mut buf = Vec::new();
        snap.encode(&mut buf);
        Ok(buf)
    }

    fn snapshot_meta(&self) -> Result<(u64, primitives::Hash, u32), String> {
        let snap = self.executor.export_snapshot();
        Ok((snap.height, snap.state_root, executor::SNAPSHOT_FORMAT_VERSION))
    }

    /// One export for blob + meta — `snapshot_meta` alone costs a
    /// full export here, so the default (export, then meta) paid two.
    fn export_with_meta(&self) -> Result<(Vec<u8>, rpc::SnapshotMeta), String> {
        let snap = self.executor.export_snapshot();
        let meta = (snap.height, snap.state_root, executor::SNAPSHOT_FORMAT_VERSION);
        let mut buf = Vec::new();
        snap.encode(&mut buf);
        Ok((buf, meta))
    }

    /// `export_snapshot` snapshots at `current_height` (after the
    /// execution lane drains), so an unchanged height means an
    /// identical export — the RPC cache can serve its copy.
    fn snapshot_height(&self) -> Option<u64> {
        Some(self.executor.current_height())
    }
}
