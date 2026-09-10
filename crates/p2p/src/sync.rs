//! State sync protocol — fast snapshot synchronization for new nodes.
//!
//! # What this is
//!
//! A chunked snapshot sync protocol that allows a new node to join
//! the network by downloading a state snapshot from existing peers,
//! rather than replaying the entire journal from genesis.
//!
//! # Why this exists
//!
//! Without state sync, a new node must replay every block from
//! genesis to reach the current state. As the chain grows, this
//! becomes impractical (hours to days). State sync reduces this to
//! minutes by transferring a point-in-time snapshot of the state.
//!
//! # Protocol
//!
//! 1. The client connects to a peer (via the transport layer).
//! 2. The client sends a [`SyncRequest`] with the desired height
//!    (or `0` for "latest").
//! 3. The server responds with a [`SyncResponse`] containing:
//!    - The snapshot height
//!    - The total number of chunks
//!    - The state root (for verification)
//! 4. The client requests each chunk by index.
//! 5. The server responds with [`ChunkResponse`] containing the
//!    chunk data.
//! 6. The client assembles all chunks into a complete snapshot,
//!    verifies the state root, and imports it into its storage
//!    backend.
//!
//! # Chunking
//!
//! Snapshots are chunked to avoid sending multi-GB snapshots in a
//! single message. Each chunk is at most `CHUNK_SIZE` bytes. The
//! client requests chunks sequentially (or in parallel in a future
//! optimization).
//!
//! # Verification
//!
//! After assembling all chunks, the client verifies:
//! 1. The snapshot is sorted (deterministic).
//! 2. The state root matches the expected root from the [`SyncResponse`].
//! 3. No duplicate keys.
//!
//! # Limitations (Phase 2)
//!
//! - No parallel chunk downloads (sequential only).
//! - No chunk verification via Merkle proofs (full chunk download).
//! - No peer selection (uses the first available peer).
//! - No resume from partial sync (restarts from chunk 0).

use ports::transport::{PeerId, TransportError};

/// The maximum size of a single chunk in bytes.
///
/// Chunks are at most 1 MiB to stay well within the transport's
/// 16 MiB max message size while leaving room for overhead.
pub const CHUNK_SIZE: usize = 1 << 20; // 1 MiB

/// The maximum number of chunks in a single snapshot.
///
/// This limits snapshots to 64 GiB (64K chunks × 1 MiB). If the
/// state exceeds this, the snapshot is rejected.
pub const MAX_CHUNKS: u32 = 65_536;

/// The maximum number of entries in a single chunk.
///
/// This caps the `Vec::with_capacity` call in `ChunkResponse::decode`
/// to prevent OOM from untrusted input.
const MAX_ENTRIES_PER_CHUNK: usize = 65_536;

/// The maximum key length in a chunk entry.
///
/// Keys are 32-byte hashes in the storage backend, but the sync
/// protocol allows variable-length keys for flexibility. This cap
/// prevents OOM from untrusted input.
const MAX_KEY_LEN: usize = 1024;

/// The maximum value length in a chunk entry.
///
/// Values can be large (contract bytecode, etc.), but this cap
/// prevents OOM from untrusted input. Set to `CHUNK_SIZE` since no
/// single value should exceed the chunk size.
const MAX_VAL_LEN: usize = CHUNK_SIZE;

/// A state sync request message.
///
/// Sent by the client to request snapshot metadata or a specific
/// chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncRequest {
    /// Request snapshot metadata for a given height.
    ///
    /// `height = 0` means "latest available."
    Metadata {
        /// The desired snapshot height, or 0 for latest.
        height: u64,
    },

    /// Request a specific chunk by index.
    Chunk {
        /// The snapshot height.
        height: u64,
        /// The chunk index.
        index: u32,
    },
}

/// A state sync response with snapshot metadata.
///
/// Sent by the server in response to a [`SyncRequest::Metadata`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResponse {
    /// The height of the snapshot.
    pub height: u64,
    /// The total number of chunks in the snapshot.
    pub num_chunks: u32,
    /// The state root at this height (for verification).
    pub state_root: [u8; 32],
    /// The total number of key-value entries in the snapshot.
    pub num_entries: u64,
}

/// A chunk response.
///
/// Sent by the server in response to a [`SyncRequest::Chunk`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkResponse {
    /// The height of the snapshot this chunk belongs to.
    pub height: u64,
    /// The chunk index.
    pub index: u32,
    /// The chunk data: a list of (key, value) pairs.
    pub entries: Vec<(Vec<u8>, Vec<u8>)>,
    /// `true` if this is the last chunk.
    pub is_last: bool,
}

/// Errors that can occur during state sync.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    /// The requested height is not available.
    #[error("snapshot at height {0} is not available")]
    HeightNotAvailable(u64),

    /// The requested chunk index is out of range.
    #[error("chunk index {0} is out of range (num_chunks = {1})")]
    ChunkOutOfRange(u32, u32),

    /// The snapshot is too large (exceeds `MAX_CHUNKS`).
    #[error("snapshot too large: {0} chunks (max = {1})")]
    SnapshotTooLarge(u32, u32),

    /// The assembled snapshot is malformed (unsorted or duplicate keys).
    #[error("assembled snapshot is malformed")]
    MalformedSnapshot,

    /// The state root doesn't match the expected root.
    #[error("state root mismatch: expected {expected:?}, got {actual:?}")]
    StateRootMismatch {
        /// The expected root from the [`SyncResponse`].
        expected: [u8; 32],
        /// The actual root computed from the assembled snapshot.
        actual: [u8; 32],
    },

    /// A transport error occurred.
    #[error("transport error: {0}")]
    Transport(String),

    /// The peer sent an invalid response.
    #[error("invalid response from peer")]
    InvalidResponse,
}

impl From<TransportError> for SyncError {
    fn from(e: TransportError) -> Self {
        Self::Transport(format!("{e:?}"))
    }
}

/// Encode a sync request to bytes.
///
/// Format: `[type: 1 byte][payload]`
///
/// - Metadata: `[0x01][height: 8 bytes LE]`
/// - Chunk: `[0x02][height: 8 bytes LE][index: 4 bytes BE]`
impl SyncRequest {
    /// The message type byte for `Metadata`.
    const TYPE_METADATA: u8 = 0x01;

    /// The message type byte for `Chunk`.
    const TYPE_CHUNK: u8 = 0x02;

    /// Serialize the request to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Metadata { height } => {
                let mut buf = Vec::with_capacity(9);
                buf.push(Self::TYPE_METADATA);
                buf.extend_from_slice(&height.to_le_bytes());
                buf
            }
            Self::Chunk { height, index } => {
                let mut buf = Vec::with_capacity(13);
                buf.push(Self::TYPE_CHUNK);
                buf.extend_from_slice(&height.to_le_bytes());
                buf.extend_from_slice(&index.to_be_bytes());
                buf
            }
        }
    }

    /// Deserialize a request from bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the bytes are malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        if bytes.is_empty() {
            return Err(SyncError::InvalidResponse);
        }
        match bytes[0] {
            Self::TYPE_METADATA => {
                if bytes.len() < 9 {
                    return Err(SyncError::InvalidResponse);
                }
                let height = u64::from_le_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]);
                Ok(Self::Metadata { height })
            }
            Self::TYPE_CHUNK => {
                if bytes.len() < 13 {
                    return Err(SyncError::InvalidResponse);
                }
                let height = u64::from_le_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]);
                let index = u32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
                Ok(Self::Chunk { height, index })
            }
            _ => Err(SyncError::InvalidResponse),
        }
    }
}

/// Encode a sync response (metadata) to bytes.
///
/// Format: `[height: 8 bytes LE][num_chunks: 4 bytes BE][state_root: 32 bytes][num_entries: 8 bytes LE]`
impl SyncResponse {
    /// Serialize the response to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(52);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.num_chunks.to_be_bytes());
        buf.extend_from_slice(&self.state_root);
        buf.extend_from_slice(&self.num_entries.to_le_bytes());
        buf
    }

    /// Deserialize a response from bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the bytes are malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        if bytes.len() < 52 {
            return Err(SyncError::InvalidResponse);
        }
        let height = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let num_chunks = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let mut state_root = [0u8; 32];
        state_root.copy_from_slice(&bytes[12..44]);
        let num_entries = u64::from_le_bytes([
            bytes[44], bytes[45], bytes[46], bytes[47], bytes[48], bytes[49], bytes[50], bytes[51],
        ]);
        Ok(Self { height, num_chunks, state_root, num_entries })
    }
}

/// Encode a chunk response to bytes.
///
/// Format:
/// `[height: 8 bytes LE][index: 4 bytes BE][is_last: 1 byte][entry_count: 4 bytes BE]`
/// followed by each entry:
/// `[key_len: 4 bytes BE][key][val_len: 4 bytes BE][val]`
impl ChunkResponse {
    /// Serialize the chunk to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(17 + self.entries.len() * 64);
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.index.to_be_bytes());
        buf.push(u8::from(self.is_last));
        buf.extend_from_slice(
            &(u32::try_from(self.entries.len()).unwrap_or(u32::MAX)).to_be_bytes(),
        );
        for (key, val) in &self.entries {
            buf.extend_from_slice(&(u32::try_from(key.len()).unwrap_or(u32::MAX)).to_be_bytes());
            buf.extend_from_slice(key);
            buf.extend_from_slice(&(u32::try_from(val.len()).unwrap_or(u32::MAX)).to_be_bytes());
            buf.extend_from_slice(val);
        }
        buf
    }

    /// Deserialize a chunk from bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the bytes are malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self, SyncError> {
        if bytes.len() < 17 {
            return Err(SyncError::InvalidResponse);
        }
        let height = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let index = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let is_last = bytes[12] != 0;
        let entry_count = u32::from_be_bytes([bytes[13], bytes[14], bytes[15], bytes[16]]) as usize;
        // Cap entry_count to prevent OOM from untrusted input. Each
        // entry needs at least 8 bytes (4-byte key_len + 4-byte
        // val_len), so the remaining bytes can hold at most
        // (bytes.len() - 17) / 8 entries. Cap to both a hard maximum
        // and the byte-budget-derived maximum.
        let remaining = bytes.len().saturating_sub(17);
        let max_entries = remaining / 8; // minimum entry overhead
        let capped_count = entry_count.min(MAX_ENTRIES_PER_CHUNK).min(max_entries);
        let mut pos = 17;
        let mut entries = Vec::with_capacity(capped_count);
        for _ in 0..entry_count {
            if pos + 4 > bytes.len() {
                return Err(SyncError::InvalidResponse);
            }
            let key_len =
                u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                    as usize;
            // Cap key_len to prevent OOM from untrusted input.
            if key_len > MAX_KEY_LEN {
                return Err(SyncError::InvalidResponse);
            }
            pos += 4;
            if pos + key_len > bytes.len() {
                return Err(SyncError::InvalidResponse);
            }
            let key = bytes[pos..pos + key_len].to_vec();
            pos += key_len;
            if pos + 4 > bytes.len() {
                return Err(SyncError::InvalidResponse);
            }
            let val_len =
                u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                    as usize;
            // Cap val_len to prevent OOM from untrusted input.
            if val_len > MAX_VAL_LEN {
                return Err(SyncError::InvalidResponse);
            }
            pos += 4;
            if pos + val_len > bytes.len() {
                return Err(SyncError::InvalidResponse);
            }
            let val = bytes[pos..pos + val_len].to_vec();
            pos += val_len;
            entries.push((key, val));
        }
        Ok(Self { height, index, entries, is_last })
    }
}

/// Chunk a sorted list of (key, value) entries into chunks of at
/// most `CHUNK_SIZE` bytes.
///
/// A key-value entry in a snapshot.
pub type Entry = (Vec<u8>, Vec<u8>);

/// A chunk of entries.
pub type Chunk = Vec<Entry>;

/// # Errors
///
/// Returns `Err` if the number of chunks exceeds `MAX_CHUNKS`.
pub fn chunk_entries(entries: &[Entry]) -> Result<Vec<Chunk>, SyncError> {
    let mut chunks = Vec::new();
    let mut current_chunk = Vec::new();
    let mut current_size = 0usize;
    for (key, val) in entries {
        let entry_size = 8 + key.len() + val.len(); // 4 bytes key_len + key + 4 bytes val_len + val
        if current_size + entry_size > CHUNK_SIZE && !current_chunk.is_empty() {
            chunks.push(std::mem::take(&mut current_chunk));
            current_size = 0;
        }
        current_chunk.push((key.clone(), val.clone()));
        current_size += entry_size;
    }
    if !current_chunk.is_empty() {
        chunks.push(current_chunk);
    }
    if chunks.len() > MAX_CHUNKS as usize {
        let num_chunks = u32::try_from(chunks.len()).unwrap_or(u32::MAX);
        return Err(SyncError::SnapshotTooLarge(num_chunks, MAX_CHUNKS));
    }
    Ok(chunks)
}

/// Assemble chunks into a sorted snapshot.
///
/// # Errors
///
/// Returns `Err` if the assembled snapshot is malformed (unsorted
/// or duplicate keys).
pub fn assemble_chunks(chunks: &[Chunk]) -> Result<Vec<Entry>, SyncError> {
    let mut all_entries = Vec::new();
    for chunk in chunks {
        all_entries.extend(chunk.iter().cloned());
    }
    // Verify sorted and no duplicates.
    for i in 1..all_entries.len() {
        if all_entries[i].0 <= all_entries[i - 1].0 {
            return Err(SyncError::MalformedSnapshot);
        }
    }
    Ok(all_entries)
}

/// Compute a simple state root from sorted (key, value) entries.
///
/// This is a simple Merkle root: hash each (key, value) pair, then
/// hash the concatenation of all hashes. Not a full Merkle tree —
/// that's the storage layer's job. This is a quick integrity check
/// for the sync protocol.
#[must_use]
pub fn compute_state_root(entries: &[(Vec<u8>, Vec<u8>)]) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    for (key, val) in entries {
        key.hash(&mut hasher);
        val.hash(&mut hasher);
    }
    let hash = hasher.finish();
    let mut root = [0u8; 32];
    root[..8].copy_from_slice(&hash.to_le_bytes());
    root
}

/// A snapshot server: serves snapshot chunks to syncing peers.
///
/// The server holds a pre-chunked snapshot and responds to chunk
/// requests. It's designed to be used by a validator or full node
/// that has a complete state and wants to serve it to new nodes.
pub struct SnapshotServer {
    /// The snapshot height.
    height: u64,
    /// The pre-chunked snapshot entries.
    chunks: Vec<Vec<(Vec<u8>, Vec<u8>)>>,
    /// The state root.
    state_root: [u8; 32],
    /// The total number of entries.
    num_entries: u64,
}

impl SnapshotServer {
    /// Create a snapshot server from sorted (key, value) entries.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the entries are too large (exceeds `MAX_CHUNKS`).
    pub fn new(height: u64, entries: Vec<(Vec<u8>, Vec<u8>)>) -> Result<Self, SyncError> {
        let state_root = compute_state_root(&entries);
        let num_entries = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        let chunks = chunk_entries(&entries)?;
        Ok(Self { height, chunks, state_root, num_entries })
    }

    /// Returns the snapshot metadata.
    #[must_use]
    pub fn metadata(&self) -> SyncResponse {
        SyncResponse {
            height: self.height,
            num_chunks: u32::try_from(self.chunks.len()).unwrap_or(u32::MAX),
            state_root: self.state_root,
            num_entries: self.num_entries,
        }
    }

    /// Returns a specific chunk.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the chunk index is out of range.
    pub fn chunk(&self, index: u32) -> Result<ChunkResponse, SyncError> {
        let num_chunks = u32::try_from(self.chunks.len()).unwrap_or(u32::MAX);
        let idx = usize::try_from(index)
            .map_err(|_| SyncError::ChunkOutOfRange(index, num_chunks))?;
        if idx >= self.chunks.len() {
            return Err(SyncError::ChunkOutOfRange(index, num_chunks));
        }
        Ok(ChunkResponse {
            height: self.height,
            index,
            entries: self.chunks[idx].clone(),
            is_last: idx == self.chunks.len() - 1,
        })
    }

    /// Returns the number of chunks.
    #[must_use]
    pub fn num_chunks(&self) -> u32 {
        u32::try_from(self.chunks.len()).unwrap_or(u32::MAX)
    }
}

/// A snapshot client: downloads and assembles a snapshot from a peer.
///
/// The client requests metadata, then downloads each chunk
/// sequentially, assembles them, and verifies the state root.
pub struct SnapshotClient {
    /// The peer to sync from.
    peer: PeerId,
    /// The snapshot metadata (set after the first request).
    metadata: Option<SyncResponse>,
    /// Downloaded chunks.
    chunks: Vec<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl SnapshotClient {
    /// Create a new snapshot client for a given peer.
    #[must_use]
    pub fn new(peer: PeerId) -> Self {
        Self { peer, metadata: None, chunks: Vec::new() }
    }

    /// Returns the peer ID.
    #[must_use]
    pub fn peer(&self) -> &PeerId {
        &self.peer
    }

    /// Returns the snapshot metadata, if available.
    #[must_use]
    pub fn metadata(&self) -> Option<&SyncResponse> {
        self.metadata.as_ref()
    }

    /// Store metadata received from the server.
    pub fn set_metadata(&mut self, response: SyncResponse) {
        let num_chunks = response.num_chunks as usize;
        self.metadata = Some(response);
        self.chunks.clear();
        self.chunks.resize_with(num_chunks, Vec::new);
    }

    /// Store a chunk received from the server.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the chunk index is out of range or the
    /// height doesn't match the metadata.
    pub fn add_chunk(&mut self, chunk: ChunkResponse) -> Result<(), SyncError> {
        let metadata = self.metadata.as_ref().ok_or(SyncError::InvalidResponse)?;
        if chunk.height != metadata.height {
            return Err(SyncError::InvalidResponse);
        }
        let idx = usize::try_from(chunk.index)
            .map_err(|_| SyncError::ChunkOutOfRange(chunk.index, metadata.num_chunks))?;
        if idx >= self.chunks.len() {
            return Err(SyncError::ChunkOutOfRange(chunk.index, metadata.num_chunks));
        }
        self.chunks[idx] = chunk.entries;
        Ok(())
    }

    /// Returns `true` if all chunks have been downloaded.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.metadata.is_some() && self.chunks.iter().all(|c| !c.is_empty())
    }

    /// Assemble the downloaded chunks into a complete snapshot.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the snapshot is incomplete, malformed, or
    /// the state root doesn't match.
    pub fn assemble(&self) -> Result<Vec<Entry>, SyncError> {
        let metadata = self.metadata.as_ref().ok_or(SyncError::InvalidResponse)?;
        if !self.is_complete() {
            return Err(SyncError::InvalidResponse);
        }
        let entries = assemble_chunks(&self.chunks)?;
        let root = compute_state_root(&entries);
        if root != metadata.state_root {
            return Err(SyncError::StateRootMismatch {
                expected: metadata.state_root,
                actual: root,
            });
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_request_metadata_round_trip() {
        let req = SyncRequest::Metadata { height: 42 };
        let encoded = req.encode();
        let decoded = SyncRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn sync_request_chunk_round_trip() {
        let req = SyncRequest::Chunk { height: 42, index: 5 };
        let encoded = req.encode();
        let decoded = SyncRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn sync_response_round_trip() {
        let resp =
            SyncResponse { height: 100, num_chunks: 10, state_root: [0xAB; 32], num_entries: 5000 };
        let encoded = resp.encode();
        let decoded = SyncResponse::decode(&encoded).unwrap();
        assert_eq!(decoded, resp);
    }

    #[test]
    fn chunk_response_round_trip() {
        let chunk = ChunkResponse {
            height: 100,
            index: 3,
            entries: vec![
                (vec![0x01, 0x02], vec![0x03, 0x04, 0x05]),
                (vec![0x06], vec![0x07, 0x08]),
            ],
            is_last: false,
        };
        let encoded = chunk.encode();
        let decoded = ChunkResponse::decode(&encoded).unwrap();
        assert_eq!(decoded, chunk);
    }

    #[test]
    fn chunk_response_last_round_trip() {
        let chunk = ChunkResponse {
            height: 100,
            index: 9,
            entries: vec![(vec![0xFF], vec![0x00])],
            is_last: true,
        };
        let encoded = chunk.encode();
        let decoded = ChunkResponse::decode(&encoded).unwrap();
        assert_eq!(decoded, chunk);
    }

    #[test]
    fn chunk_entries_small() {
        let entries = vec![(vec![0x01], vec![0x02]), (vec![0x03], vec![0x04])];
        let chunks = chunk_entries(&entries).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], entries);
    }

    #[test]
    fn chunk_entries_large() {
        // Create entries that exceed CHUNK_SIZE to force multiple chunks.
        let big_val = vec![0xFF; CHUNK_SIZE / 2 + 1];
        let entries = vec![
            (vec![0x01], big_val.clone()),
            (vec![0x02], big_val.clone()),
            (vec![0x03], big_val),
        ];
        let chunks = chunk_entries(&entries).unwrap();
        assert!(chunks.len() >= 3);
        // Each chunk should have exactly one entry (they're too big to combine).
        for chunk in &chunks {
            assert_eq!(chunk.len(), 1);
        }
    }

    #[test]
    fn assemble_chunks_valid() {
        let chunks = vec![
            vec![(vec![0x01], vec![0x02]), (vec![0x03], vec![0x04])],
            vec![(vec![0x05], vec![0x06])],
        ];
        let assembled = assemble_chunks(&chunks).unwrap();
        assert_eq!(assembled.len(), 3);
        assert_eq!(assembled[0].0, vec![0x01]);
        assert_eq!(assembled[2].0, vec![0x05]);
    }

    #[test]
    fn assemble_chunks_unsorted_fails() {
        let chunks = vec![vec![(vec![0x03], vec![0x04]), (vec![0x01], vec![0x02])]];
        assert_eq!(assemble_chunks(&chunks), Err(SyncError::MalformedSnapshot));
    }

    #[test]
    fn assemble_chunks_duplicate_fails() {
        let chunks = vec![vec![(vec![0x01], vec![0x02]), (vec![0x01], vec![0x03])]];
        assert_eq!(assemble_chunks(&chunks), Err(SyncError::MalformedSnapshot));
    }

    #[test]
    fn snapshot_server_metadata_and_chunks() {
        let entries =
            vec![(vec![0x01], vec![0x02]), (vec![0x03], vec![0x04]), (vec![0x05], vec![0x06])];
        let server = SnapshotServer::new(42, entries).unwrap();
        let metadata = server.metadata();
        assert_eq!(metadata.height, 42);
        assert_eq!(metadata.num_chunks, 1);
        assert_eq!(metadata.num_entries, 3);

        let chunk = server.chunk(0).unwrap();
        assert_eq!(chunk.height, 42);
        assert_eq!(chunk.index, 0);
        assert!(chunk.is_last);
        assert_eq!(chunk.entries.len(), 3);
    }

    #[test]
    fn snapshot_server_chunk_out_of_range() {
        let entries = vec![(vec![0x01], vec![0x02])];
        let server = SnapshotServer::new(42, entries).unwrap();
        assert_eq!(server.chunk(1), Err(SyncError::ChunkOutOfRange(1, 1)));
    }

    #[test]
    fn snapshot_client_full_sync() {
        let entries =
            vec![(vec![0x01], vec![0x02]), (vec![0x03], vec![0x04]), (vec![0x05], vec![0x06])];
        let server = SnapshotServer::new(42, entries.clone()).unwrap();
        let metadata = server.metadata();
        let num_chunks = metadata.num_chunks;

        let mut client = SnapshotClient::new(vec![0u8]);
        client.set_metadata(metadata);

        assert!(!client.is_complete());
        for i in 0..num_chunks {
            let chunk = server.chunk(i).unwrap();
            client.add_chunk(chunk).unwrap();
        }
        assert!(client.is_complete());

        let assembled = client.assemble().unwrap();
        assert_eq!(assembled, entries);
    }

    #[test]
    fn snapshot_client_state_root_mismatch() {
        let entries = vec![(vec![0x01], vec![0x02]), (vec![0x03], vec![0x04])];
        let server = SnapshotServer::new(42, entries).unwrap();
        let mut metadata = server.metadata();
        // Corrupt the state root.
        metadata.state_root[0] ^= 0xFF;

        let mut client = SnapshotClient::new(vec![0u8]);
        client.set_metadata(metadata);

        let chunk = server.chunk(0).unwrap();
        client.add_chunk(chunk).unwrap();

        let result = client.assemble();
        assert!(matches!(result, Err(SyncError::StateRootMismatch { .. })));
    }

    #[test]
    fn snapshot_client_wrong_height() {
        let entries = vec![(vec![0x01], vec![0x02])];
        let server = SnapshotServer::new(42, entries).unwrap();
        let metadata = server.metadata();

        let mut client = SnapshotClient::new(vec![0u8]);
        client.set_metadata(metadata);

        // Try to add a chunk with wrong height.
        let bad_chunk = ChunkResponse {
            height: 99, // wrong
            index: 0,
            entries: vec![(vec![0x01], vec![0x02])],
            is_last: true,
        };
        assert_eq!(client.add_chunk(bad_chunk), Err(SyncError::InvalidResponse));
    }

    #[test]
    fn decode_empty_request_fails() {
        assert_eq!(SyncRequest::decode(&[]), Err(SyncError::InvalidResponse));
    }

    #[test]
    fn decode_truncated_metadata_fails() {
        // Type byte + only 4 bytes of height (need 8).
        let bytes = vec![0x01, 0x2A, 0x00, 0x00, 0x00];
        assert_eq!(SyncRequest::decode(&bytes), Err(SyncError::InvalidResponse));
    }

    #[test]
    fn decode_truncated_chunk_response_fails() {
        let bytes = vec![0x00; 10]; // Need at least 17 bytes.
        assert_eq!(ChunkResponse::decode(&bytes), Err(SyncError::InvalidResponse));
    }

    #[test]
    fn compute_state_root_deterministic() {
        let entries = vec![(vec![0x01], vec![0x02]), (vec![0x03], vec![0x04])];
        let root1 = compute_state_root(&entries);
        let root2 = compute_state_root(&entries);
        assert_eq!(root1, root2);
    }

    #[test]
    fn compute_state_root_sensitive() {
        let entries_a = vec![(vec![0x01], vec![0x02])];
        let entries_b = vec![(vec![0x01], vec![0x03])];
        assert_ne!(compute_state_root(&entries_a), compute_state_root(&entries_b));
    }
}
