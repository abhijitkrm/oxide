//! Encrypted keystore for secret key files.
//!
//! The chain's binaries load long-lived secrets (BLS consensus keys,
//! secp256k1 settlement/signer keys) from files. Storing those as raw
//! hex means a single filesystem read — a leaked backup, a mis-scoped
//! volume mount, a stray `cat` in a runbook — yields the key itself.
//! The keystore wraps the 32-byte secret in a passphrase-encrypted
//! blob so the file alone is useless:
//!
//! ```text
//! "OXKEY" | version u8 | kind u8 | kdf_iters u32be |
//! salt[16] | nonce[12] | ciphertext[32] || gcm_tag[16]      = 87 B
//! ```
//!
//! - **KDF:** PBKDF2-HMAC-SHA256 at [`KDF_ITERATIONS`] — the OWASP
//!   2023 recommendation for this primitive. Argon2id would resist
//!   GPU cracking better via memory-hardness, but no argon2
//!   implementation is in the dependency tree; `aws-lc-rs` (already
//!   the TLS provider) ships a FIPS-validated PBKDF2, so this file
//!   adds zero new dependencies to the lockfile.
//! - **AEAD:** AES-256-GCM via `aws_lc_rs::aead::RandomizedNonceKey`
//!   — a fresh random 96-bit nonce per seal, so nonce reuse is
//!   structurally impossible. The header (magic through salt) is
//!   bound as AAD, so a tampered `kind`/`iters`/`salt` fails the
//!   tag rather than producing a misparsed key.
//! - **Passphrase source:** the `OXIDE_KEY_PASSPHRASE` environment
//!   variable — never a CLI flag (argv is world-readable in `ps`).
//!
//! `aws-lc-rs` requires the passphrase be at least 14 bytes
//! ([`MIN_PASSPHRASE_LEN`]); shorter inputs fail before any crypto
//! runs rather than producing a weakly-protected file.
//!
//! Feature-gated behind `keystore` (`dep:aws-lc-rs`): consumers that
//! never touch key files — sim, fuzz, in-process harnesses — keep a
//! pure-Rust dependency graph.

use aws_lc_rs::aead::{AES_256_GCM, Aad, Nonce, RandomizedNonceKey};
use aws_lc_rs::pbkdf2;

/// File magic — `is_keystore` sniffs this so key-file loaders can
/// accept either raw secrets or keystores without a separate flag.
pub const MAGIC: &[u8; 5] = b"OXKEY";

/// Current format version. Bump on any layout change; `open` rejects
/// unknown versions rather than misparsing them.
pub const VERSION: u8 = 1;

/// PBKDF2-HMAC-SHA256 iteration count.
///
/// Unit: iterations. Origin: OWASP Password Storage Cheat Sheet
/// (2023) recommendation of 600,000 for PBKDF2-HMAC-SHA256. At ~0.5µs
/// per SHA-256 compression this costs ~200–300 ms per unlock on a
/// modern core — invisible on a cold key load, meaningful to a
/// brute-force loop. Raising it slows unlock linearly.
pub const KDF_ITERATIONS: u32 = 600_000;

/// Minimum passphrase length in bytes.
///
/// Unit: bytes. Origin: `aws-lc-rs` rejects PBKDF2 secrets shorter
/// than 14 bytes — the bound doubles as a sane passphrase floor
/// (below this, offline cracking is cheap regardless of KDF).
pub const MIN_PASSPHRASE_LEN: usize = 14;

/// PBKDF2 salt length — 16 bytes (128-bit), the standard bound.
const SALT_LEN: usize = 16;

/// AES-256-GCM nonce length — 96 bits, generated per seal.
const NONCE_LEN: usize = 12;

/// Environment variable the loaders read for the unlock passphrase.
pub const PASSPHRASE_ENV: &str = "OXIDE_KEY_PASSPHRASE";

/// Which key type a keystore wraps — recorded so a loader can refuse
/// a valid decryption of the *wrong* kind of key (a secp256k1 blob
/// fed to `--bls-key-file` fails loudly instead of booting with a
/// meaningless scalar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// BLS12-381 consensus signing secret.
    Bls = 1,
    /// secp256k1 secret (settlement operator, signer, account keys).
    Secp256k1 = 2,
    /// A raw 32-byte symmetric secret with no public-key derivation —
    /// shared-link keys (remote signer), API tokens, anything whose
    /// security is possession alone rather than a keypair. Distinct
    /// kind so a `generic` blob fed to `--bls-key-file` still fails
    /// the kind check instead of silently seeding a consensus key.
    Generic = 3,
}

impl KeyKind {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Bls),
            2 => Some(Self::Secp256k1),
            3 => Some(Self::Generic),
            _ => None,
        }
    }
}

/// Why a keystore operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeystoreError {
    /// Bytes do not start with [`MAGIC`] — not a keystore file.
    NotKeystore,
    /// [`VERSION`] mismatch — a newer (or corrupted) format.
    UnsupportedVersion(u8),
    /// File ends inside the fixed-layout header or payload.
    Truncated,
    /// Unknown `kind` byte — not a key kind this build knows.
    UnknownKind(u8),
    /// Passphrase shorter than [`MIN_PASSPHRASE_LEN`].
    PassphraseTooShort,
    /// [`PASSPHRASE_ENV`] is unset or empty — an encrypted file was
    /// given but nothing to decrypt it with.
    NoPassphrase,
    /// Structurally valid magic/length but a nonsense field (e.g.
    /// zero KDF iterations) — the file was not produced by `seal`.
    Malformed,
    /// Decryption failed — wrong passphrase or tampered bytes. The
    /// AEAD tag cannot distinguish the two, and neither should we.
    DecryptFailed,
    /// The crypto backend rejected an operation (RNG failure, etc.).
    Crypto,
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotKeystore => write!(f, "not an OXKEY keystore file"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported keystore version {v}"),
            Self::Truncated => write!(f, "keystore file truncated"),
            Self::UnknownKind(k) => write!(f, "unknown keystore key kind {k}"),
            Self::PassphraseTooShort => {
                write!(f, "passphrase must be at least {MIN_PASSPHRASE_LEN} bytes")
            }
            Self::NoPassphrase => {
                write!(f, "encrypted keystore requires the {PASSPHRASE_ENV} environment variable")
            }
            Self::Malformed => write!(f, "keystore header is malformed"),
            Self::DecryptFailed => {
                write!(f, "keystore decryption failed — wrong passphrase or corrupted file")
            }
            Self::Crypto => write!(f, "keystore crypto backend failure"),
        }
    }
}

impl std::error::Error for KeystoreError {}

/// Header layout: magic(5) + version(1) + kind(1) + iters(4) +
/// salt(16) — the nonce and ciphertext||tag follow.
const HEADER_LEN: usize = 5 + 1 + 1 + 4 + SALT_LEN;
/// Secret payload: 32-byte secret + 16-byte GCM tag.
const SEALED_SECRET_LEN: usize = 32 + 16;
/// Total file size for the current layout.
pub const KEYSTORE_LEN: usize = HEADER_LEN + NONCE_LEN + SEALED_SECRET_LEN;

/// True if `bytes` starts with the keystore magic — the loader's
/// sniff for "decrypt this" vs "parse as raw key".
#[must_use]
pub fn is_keystore(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// Encrypt `secret` into a keystore blob under `passphrase`.
///
/// A fresh CSPRNG salt and nonce make every seal unique — encrypting
/// the same key twice yields different files, so a keystore cannot be
/// correlated by content.
///
/// # Errors
///
/// [`KeystoreError::PassphraseTooShort`] for passphrases under
/// [`MIN_PASSPHRASE_LEN`]; [`KeystoreError::Crypto`] if the OS RNG or
/// AEAD backend fails.
pub fn seal(kind: KeyKind, secret: &[u8; 32], passphrase: &str) -> Result<Vec<u8>, KeystoreError> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(KeystoreError::PassphraseTooShort);
    }
    let mut salt = [0u8; SALT_LEN];
    crate::fill_random(&mut salt);

    let mut out = Vec::with_capacity(KEYSTORE_LEN);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(kind as u8);
    out.extend_from_slice(&KDF_ITERATIONS.to_be_bytes());
    out.extend_from_slice(&salt);

    let mut body = Vec::with_capacity(SEALED_SECRET_LEN);
    body.extend_from_slice(secret);
    let nonce = seal_with(&derive_key(&salt, passphrase), &out, &mut body)?;

    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decrypt a keystore blob, returning the kind and the secret.
///
/// # Errors
///
/// Every malformed or unauthentic input maps to a precise
/// [`KeystoreError`]; in particular a wrong passphrase is
/// indistinguishable from corruption ([`KeystoreError::DecryptFailed`])
/// — the GCM tag is the only oracle.
///
/// # Panics
///
/// Never in practice: the fixed-offset field slices are guarded by
/// the upfront length check, so the `expect`s are unreachable.
pub fn open(bytes: &[u8], passphrase: &str) -> Result<(KeyKind, [u8; 32]), KeystoreError> {
    if !is_keystore(bytes) {
        return Err(KeystoreError::NotKeystore);
    }
    if bytes.len() < HEADER_LEN + NONCE_LEN {
        return Err(KeystoreError::Truncated);
    }
    if bytes[5] != VERSION {
        return Err(KeystoreError::UnsupportedVersion(bytes[5]));
    }
    let kind = KeyKind::from_byte(bytes[6]).ok_or(KeystoreError::UnknownKind(bytes[6]))?;
    let iters = u32::from_be_bytes(bytes[7..11].try_into().expect("4-byte iters field"));
    let iters = std::num::NonZeroU32::new(iters).ok_or(KeystoreError::Malformed)?;
    let salt: &[u8; SALT_LEN] = bytes[11..11 + SALT_LEN].try_into().expect("salt field");
    let nonce_off = HEADER_LEN;
    let nonce = Nonce::try_assume_unique_for_key(&bytes[nonce_off..nonce_off + NONCE_LEN])
        .map_err(|_| KeystoreError::Malformed)?;
    let mut body = bytes[nonce_off + NONCE_LEN..].to_vec();
    if body.len() != SEALED_SECRET_LEN {
        return Err(KeystoreError::Truncated);
    }
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(KeystoreError::PassphraseTooShort);
    }

    // The header (magic..salt) is the AAD: the tag proves kind, iters
    // and salt are the values the sealer committed to.
    let header = &bytes[..nonce_off];
    let mut key = [0u8; 32];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iters, salt, passphrase.as_bytes(), &mut key);
    let cipher = RandomizedNonceKey::new(&AES_256_GCM, &key).map_err(|_| KeystoreError::Crypto)?;
    cipher
        .open_in_place(nonce, Aad::from(header), &mut body)
        .map_err(|_| KeystoreError::DecryptFailed)?;
    let secret: [u8; 32] = body[..32].try_into().expect("32-byte secret payload");
    Ok((kind, secret))
}

/// Read the unlock passphrase from [`PASSPHRASE_ENV`].
///
/// # Errors
///
/// [`KeystoreError::NoPassphrase`] when the variable is unset or
/// empty — callers surface the message verbatim so the operator sees
/// exactly what is missing.
pub fn passphrase_from_env() -> Result<String, KeystoreError> {
    match std::env::var(PASSPHRASE_ENV) {
        Ok(p) if !p.is_empty() => Ok(p),
        _ => Err(KeystoreError::NoPassphrase),
    }
}

/// Derive the 32-byte AEAD key from salt+passphrase at the standard
/// iteration count.
fn derive_key(salt: &[u8; SALT_LEN], passphrase: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        std::num::NonZeroU32::new(KDF_ITERATIONS).expect("nonzero iters"),
        salt,
        passphrase.as_bytes(),
        &mut key,
    );
    key
}

/// AES-256-GCM seal over `secret` with a random nonce; `header` is
/// bound as AAD. Returns the nonce the sealer chose.
fn seal_with(
    key: &[u8; 32],
    header: &[u8],
    body: &mut Vec<u8>,
) -> Result<[u8; NONCE_LEN], KeystoreError> {
    let cipher = RandomizedNonceKey::new(&AES_256_GCM, key).map_err(|_| KeystoreError::Crypto)?;
    let nonce = cipher
        .seal_in_place_append_tag(Aad::from(header), body)
        .map_err(|_| KeystoreError::Crypto)?;
    Ok(*nonce.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery staple";

    fn secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[24..].copy_from_slice(&42u64.to_be_bytes());
        s
    }

    /// Seal → open round-trips the secret and the declared kind.
    #[test]
    fn keystore_roundtrip() {
        let blob = seal(KeyKind::Bls, &secret(), PASS).expect("seal");
        assert_eq!(blob.len(), KEYSTORE_LEN);
        assert!(is_keystore(&blob));
        let (kind, key) = open(&blob, PASS).expect("open");
        assert_eq!(kind, KeyKind::Bls);
        assert_eq!(key, secret());
    }

    /// Two seals of the same secret differ — salt and nonce are
    /// CSPRNG-fresh, so a keystore is not a fingerprint of its key.
    #[test]
    fn seals_are_nondeterministic() {
        let a = seal(KeyKind::Secp256k1, &secret(), PASS).expect("a");
        let b = seal(KeyKind::Secp256k1, &secret(), PASS).expect("b");
        assert_ne!(a, b);
    }

    /// A wrong passphrase fails the GCM tag — never a wrong key.
    #[test]
    fn wrong_passphrase_fails() {
        let blob = seal(KeyKind::Bls, &secret(), PASS).expect("seal");
        assert_eq!(open(&blob, "wrong horse battery staple"), Err(KeystoreError::DecryptFailed));
    }

    /// Truncated, version-shifted, and kind-corrupted files all fail
    /// before or at the AEAD check — never silently misparsed.
    #[test]
    fn malformed_files_fail() {
        let blob = seal(KeyKind::Bls, &secret(), PASS).expect("seal");
        assert_eq!(open(&blob[..20], PASS), Err(KeystoreError::Truncated));
        let mut bad = blob.clone();
        bad[5] = 99;
        assert_eq!(open(&bad, PASS), Err(KeystoreError::UnsupportedVersion(99)));
        let mut bad = blob.clone();
        bad[6] = 77;
        assert_eq!(open(&bad, PASS), Err(KeystoreError::UnknownKind(77)));
        // Flipping a salt byte must fail the tag, not decrypt garbage.
        let mut bad = blob.clone();
        bad[11] ^= 1;
        assert_eq!(open(&bad, PASS), Err(KeystoreError::DecryptFailed));
        // And a raw key is not a keystore.
        assert_eq!(open(&secret(), PASS), Err(KeystoreError::NotKeystore));
    }

    /// Short passphrases are refused before any crypto.
    #[test]
    fn short_passphrase_refused() {
        assert_eq!(seal(KeyKind::Bls, &secret(), "short"), Err(KeystoreError::PassphraseTooShort));
    }
}
