//! Authenticated journal: integrates the journal (durability) with the
//! MMR (authentication).
//!
//! The M1 audit finding: the journal and MMR were separate. Every
//! journal record should contribute to the authenticated log root,
//! and replay should verify against the MMR root. Without this,
//! a corrupted or tampered journal record could go undetected if
//! the CRC check is bypassed (e.g., by replacing the segment file).
//!
//! # Design
//!
//! `AuthenticatedJournal` wraps a `JournalWriter` and an `Mmr`:
//! - `append(payload)` writes the payload to the journal and pushes
//!   `hash_leaf(payload)` to the MMR. The MMR root commits the
//!   entire log.
//! - `root()` returns the current MMR root.
//! - `replay_verified(dir, expected_root)` replays the journal,
//!   reconstructs the MMR from the replayed records, and verifies
//!   the root matches `expected_root`. A mismatch means the journal
//!   was tampered with.
//!
//! # Invariants
//!
//! - Every journal record contributes exactly one MMR leaf.
//! - The MMR root is deterministic: replaying the same journal
//!   always produces the same root.
//! - A tampered journal (modified record, inserted record, deleted
//!   record) produces a different root and is rejected.

use std::path::Path;

use crate::journal::{JournalConfig, JournalWriter, Replay, replay};
use crate::mmr::{Mmr, hash_leaf};

/// An authenticated journal: the journal (durability) plus the MMR
/// (authentication). Every `append` writes to both; the MMR root
/// commits the entire log.
pub struct AuthenticatedJournal {
    writer: JournalWriter,
    mmr: Mmr,
}

/// The result of authenticated replay.
#[derive(Debug)]
pub struct AuthenticatedReplay {
    /// The replay result (records, `truncated_at`).
    pub replay: Replay,
    /// The MMR root reconstructed from the replayed records.
    pub root: primitives::Hash,
    /// Whether the reconstructed root matches the expected root.
    pub root_matches: bool,
}

impl AuthenticatedJournal {
    /// Create a new authenticated journal in `dir`.
    ///
    /// # Errors
    /// Returns `JournalError` if the journal cannot be created.
    pub fn create(dir: &Path, config: JournalConfig) -> Result<Self, crate::journal::JournalError> {
        Ok(Self { writer: JournalWriter::create(dir, config)?, mmr: Mmr::new() })
    }

    /// Append a payload to the journal and push its hash to the MMR.
    ///
    /// # Errors
    /// Returns `JournalError` if the payload is too large or the
    /// journal cannot be written.
    pub fn append(
        &mut self,
        payload: &[u8],
    ) -> Result<crate::journal::Location, crate::journal::JournalError> {
        let location = self.writer.append(payload)?;
        self.mmr.push(hash_leaf(payload));
        Ok(location)
    }

    /// Flush the journal buffer to the OS.
    ///
    /// # Errors
    /// Returns `JournalError::Io` on write failure.
    pub fn flush(&mut self) -> Result<(), crate::journal::JournalError> {
        self.writer.flush()
    }

    /// Flush and sync the journal (durability point).
    ///
    /// # Errors
    /// Returns `JournalError::Io` on write or sync failure.
    pub fn sync(&mut self) -> Result<(), crate::journal::JournalError> {
        self.writer.sync()
    }

    /// The current MMR root — commits the entire log.
    pub fn root(&self) -> primitives::Hash {
        self.mmr.root()
    }

    /// The number of leaves (records) in the MMR.
    pub fn leaf_count(&self) -> u64 {
        self.mmr.leaf_count()
    }
}

/// Replay a journal directory and reconstruct the MMR root from
/// the replayed records. If `expected_root` is provided, verify
/// the reconstructed root matches.
///
/// # Errors
/// Returns `JournalError` only for true IO failures.
pub fn replay_verified(
    dir: &Path,
    expected_root: Option<primitives::Hash>,
) -> Result<AuthenticatedReplay, crate::journal::JournalError> {
    let replay = replay(dir)?;
    let mut mmr = Mmr::new();
    for record in &replay.records {
        mmr.push(hash_leaf(&record.payload));
    }
    let root = mmr.root();
    let root_matches = match expected_root {
        Some(expected) => root == expected,
        None => true,
    };
    Ok(AuthenticatedReplay { replay, root, root_matches })
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::Hash;
    use std::io::Write as _;

    /// A temp dir helper that cleans up on drop.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "oxide-auth-journal-{}-{}",
                name,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn authenticated_journal_root_is_deterministic() {
        let dir = TempDir::new("deterministic");
        let config = JournalConfig::default();
        let mut aj = AuthenticatedJournal::create(&dir.0, config).unwrap();
        aj.append(b"hello").unwrap();
        aj.append(b"world").unwrap();
        aj.sync().unwrap();
        let root1 = aj.root();

        // Replay and reconstruct.
        let result = replay_verified(&dir.0, Some(root1)).unwrap();
        assert!(result.root_matches, "reconstructed root must match");
        assert_eq!(result.root, root1);
        assert_eq!(result.replay.records.len(), 2);
    }

    #[test]
    fn tampered_journal_detected() {
        let dir = TempDir::new("tampered");
        let config = JournalConfig::default();
        let mut aj = AuthenticatedJournal::create(&dir.0, config).unwrap();
        aj.append(b"record1").unwrap();
        aj.append(b"record2").unwrap();
        aj.append(b"record3").unwrap();
        aj.sync().unwrap();
        let original_root = aj.root();

        // Tamper: append a record directly to the segment file
        // (bypassing the MMR). This simulates an attacker inserting
        // a record after the journal was written.
        let segment_path = dir.0.join("segment-0.log");
        let mut file = std::fs::OpenOptions::new().append(true).open(&segment_path).unwrap();
        // Write a valid-framed record that the journal will accept
        // during replay but the MMR won't know about.
        let tampered_payload = b"tampered";
        let len = u32::try_from(tampered_payload.len()).unwrap();
        let crc = crate::journal::crc32(tampered_payload);
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&crc.to_le_bytes());
        buf.extend_from_slice(tampered_payload);
        file.write_all(&buf).unwrap();
        file.sync_all().unwrap();

        // Replay: the journal will accept the tampered record (valid
        // CRC), but the reconstructed MMR root will differ from the
        // original root because the MMR has an extra leaf.
        let result = replay_verified(&dir.0, Some(original_root)).unwrap();
        assert!(!result.root_matches, "tampered journal must produce a different root");
        assert_eq!(result.replay.records.len(), 4, "journal accepted the tampered record");
        assert_ne!(result.root, original_root, "roots must differ");
    }

    #[test]
    fn empty_journal_has_zero_root() {
        let dir = TempDir::new("empty");
        let result = replay_verified(&dir.0, None).unwrap();
        // An empty MMR has a zero root (all-zeros hash).
        assert_eq!(result.root, Hash::ZERO, "empty journal root must be zero");
        assert_eq!(result.replay.records.len(), 0);
    }

    #[test]
    fn root_changes_after_each_append() {
        let dir = TempDir::new("changes");
        let config = JournalConfig::default();
        let mut aj = AuthenticatedJournal::create(&dir.0, config).unwrap();
        let root0 = aj.root();
        aj.append(b"a").unwrap();
        let root1 = aj.root();
        aj.append(b"b").unwrap();
        let root2 = aj.root();
        assert_ne!(root0, root1, "root must change after append");
        assert_ne!(root1, root2, "root must change after append");
    }
}
