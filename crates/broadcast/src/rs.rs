//! Reed-Solomon erasure coding over GF(256).
//!
//! Splits data into `k` data shards, computes `m` parity shards
//! using a Vandermonde encoding matrix, and reconstructs from any
//! `k` of the `n = k + m` total shards.
//!
//! # Algorithm
//!
//! The encoding matrix is a Vandermonde matrix `V` of size `n × k`,
//! where `V[i][j] = i^j` in GF(256). The top `k × k` submatrix is
//! the identity (systematic code), so the first `k` shards are the
//! original data. The bottom `m × k` submatrix produces the parity
//! shards.
//!
//! Reconstruction: given any `k` shards (with their indices), form a
//! `k × k` matrix from the corresponding rows of the Vandermonde
//! matrix, invert it, and multiply by the shard values. This is
//! Gaussian elimination over GF(256).
//!
//! # Determinism
//!
//! The encoding matrix depends only on `k` and `m` (compile-time
//! parameters at the call site). The same input always produces the
//! same shards, and the same shards always reconstruct the same data.

use crate::gf256::Gf256;

/// A Reed-Solomon code over GF(256) with `k` data shards and `m`
/// parity shards. Total shards `n = k + m`. Can reconstruct from any
/// `k` of the `n` shards.
pub struct ReedSolomon {
    /// The field arithmetic.
    field: Gf256,
    /// Number of data shards (must reconstruct from >= k).
    k: usize,
    /// Number of parity shards.
    m: usize,
    /// The encoding matrix: `n × k` Vandermonde matrix in systematic
    /// form (top k rows = identity, bottom m rows = parity).
    /// Stored row-major: `matrix[i * k + j]`.
    matrix: Vec<u8>,
}

impl ReedSolomon {
    /// Construct a Reed-Solomon code with `k` data shards and `m`
    /// parity shards.
    ///
    /// # Panics
    ///
    /// Panics if `k == 0`, `m == 0`, or `k + m > 255` (GF(256) has
    /// only 256 elements, so the Vandermonde matrix needs distinct
    /// evaluation points).
    #[must_use]
    pub fn new(k: usize, m: usize) -> Self {
        assert!(k > 0, "k must be > 0");
        assert!(m > 0, "m must be > 0");
        assert!(k + m <= 255, "k + m must be <= 255 for GF(256)");

        let field = Gf256::new();
        let n = k + m;

        // Build the Vandermonde matrix: V[i][j] = i^j in GF(256).
        // Evaluation points are 0, 1, 2, ..., n-1.
        let mut matrix = vec![0u8; n * k];
        for i in 0..n {
            for j in 0..k {
                matrix[i * k + j] = field.pow(
                    u8::try_from(i).expect("i < n <= 255"),
                    u32::try_from(j).expect("j < k <= 255"),
                );
            }
        }

        // Convert to systematic form: multiply by the inverse of the
        // top k×k submatrix so the first k rows become the identity.
        // This makes the first k shards the original data.
        let top = &matrix[..k * k];
        let inv_top = invert_matrix(&field, top, k)
            .expect("Vandermonde top k×k submatrix is always invertible for distinct points");

        // Multiply the full matrix by inv_top: systematic = V * inv_top.
        let mut systematic = vec![0u8; n * k];
        for i in 0..n {
            for j in 0..k {
                let mut sum = 0u8;
                for l in 0..k {
                    sum = field.add(sum, field.mul(matrix[i * k + l], inv_top[l * k + j]));
                }
                systematic[i * k + j] = sum;
            }
        }

        // Verify the top k rows are the identity (sanity check).
        for i in 0..k {
            for j in 0..k {
                let expected = u8::from(i == j);
                assert_eq!(
                    systematic[i * k + j],
                    expected,
                    "systematic form: top k×k must be identity"
                );
            }
        }

        Self { field, k, m, matrix: systematic }
    }

    /// The number of data shards.
    #[allow(dead_code)]
    #[must_use]
    pub fn k(&self) -> usize {
        self.k
    }

    /// The number of parity shards.
    #[allow(dead_code)]
    #[must_use]
    pub fn m(&self) -> usize {
        self.m
    }

    /// The total number of shards (data + parity).
    #[must_use]
    pub fn n(&self) -> usize {
        self.k + self.m
    }

    /// Encode `data` into `n` shards. Each shard is `shard_size`
    /// bytes. The first `k` shards are the original data (systematic
    /// code); the remaining `m` shards are parity.
    ///
    /// # Panics
    ///
    /// Panics if `data.len()` is not exactly `k * shard_size`.
    #[must_use]
    pub fn encode(&self, data: &[u8], shard_size: usize) -> Vec<Vec<u8>> {
        assert_eq!(data.len(), self.k * shard_size, "data must be k * shard_size bytes");
        let n = self.n();
        let mut shards = vec![vec![0u8; shard_size]; n];

        // Copy data shards (systematic: first k shards = data).
        for i in 0..self.k {
            shards[i].copy_from_slice(&data[i * shard_size..(i + 1) * shard_size]);
        }

        // Compute parity shards: for each parity row p (row k..n),
        // shard_p[col] = sum(matrix[p][j] * shard_j[col]) for j in 0..k.
        // We copy data shard values out first to avoid borrowing conflicts
        // between the immutable data shard reads and mutable parity writes.
        let data_shards: Vec<Vec<u8>> = shards[..self.k].to_vec();
        for (p, parity_shard) in shards.iter_mut().enumerate().skip(self.k) {
            for col in 0..shard_size {
                let mut sum = 0u8;
                for (j, data_shard) in data_shards.iter().enumerate() {
                    let coef = self.matrix[p * self.k + j];
                    sum = self.field.add(sum, self.field.mul(coef, data_shard[col]));
                }
                parity_shard[col] = sum;
            }
        }

        shards
    }

    /// Reconstruct the original data from any `k` shards.
    ///
    /// `shards` is a vector of `(index, shard_data)` pairs. The
    /// index is the shard's position in the original encoding (0..n).
    /// At least `k` shards must be provided.
    ///
    /// # Errors
    ///
    /// Returns `None` if fewer than `k` shards are provided.
    #[must_use]
    pub fn reconstruct(&self, shards: &[(usize, Vec<u8>)], shard_size: usize) -> Option<Vec<u8>> {
        if shards.len() < self.k {
            return None;
        }

        // Take exactly k shards (the first k provided).
        let available = &shards[..self.k];
        let shard_size = if shard_size == 0 {
            available.first().map_or(0, |(_, s)| s.len())
        } else {
            shard_size
        };

        // Build the k×k submatrix from the encoding matrix rows
        // corresponding to the available shard indices.
        let mut submatrix = vec![0u8; self.k * self.k];
        for (row, &(idx, _)) in available.iter().enumerate() {
            for col in 0..self.k {
                submatrix[row * self.k + col] = self.matrix[idx * self.k + col];
            }
        }

        // Invert the submatrix.
        let inv = invert_matrix(&self.field, &submatrix, self.k)?;

        // Multiply inv × available_shards to get the original data shards.
        let mut data = vec![0u8; self.k * shard_size];
        for i in 0..self.k {
            for col in 0..shard_size {
                let mut sum = 0u8;
                for (row, (_, shard)) in available.iter().enumerate() {
                    sum = self.field.add(sum, self.field.mul(inv[i * self.k + row], shard[col]));
                }
                data[i * shard_size + col] = sum;
            }
        }

        Some(data)
    }
}

/// Invert a `k × k` matrix over GF(256) using Gaussian elimination.
///
/// Returns `None` if the matrix is singular (not invertible).
fn invert_matrix(field: &Gf256, matrix: &[u8], k: usize) -> Option<Vec<u8>> {
    // Build the augmented matrix [matrix | identity].
    let mut aug = vec![0u8; k * k * 2];
    for i in 0..k {
        for j in 0..k {
            aug[i * 2 * k + j] = matrix[i * k + j];
        }
        aug[i * 2 * k + k + i] = 1; // identity on the right
    }

    // Forward elimination with partial pivoting.
    for col in 0..k {
        // Find a pivot row with non-zero entry in this column.
        let mut pivot = None;
        for row in col..k {
            if aug[row * 2 * k + col] != 0 {
                pivot = Some(row);
                break;
            }
        }
        let pivot = pivot?;

        // Swap rows if needed.
        if pivot != col {
            let (row_a, row_b) = aug.split_at_mut(pivot * 2 * k);
            row_a[col * 2 * k..(col + 1) * 2 * k].swap_with_slice(&mut row_b[..2 * k]);
        }

        // Scale the pivot row so the diagonal element is 1.
        let diag = aug[col * 2 * k + col];
        let inv_diag = field.inv(diag);
        for j in 0..2 * k {
            aug[col * 2 * k + j] = field.mul(aug[col * 2 * k + j], inv_diag);
        }

        // Eliminate all other rows.
        for row in 0..k {
            if row == col {
                continue;
            }
            let factor = aug[row * 2 * k + col];
            if factor == 0 {
                continue;
            }
            for j in 0..2 * k {
                let val = field.mul(factor, aug[col * 2 * k + j]);
                aug[row * 2 * k + j] = field.sub(aug[row * 2 * k + j], val);
            }
        }
    }

    // Extract the inverse from the right half of the augmented matrix.
    let mut inv = vec![0u8; k * k];
    for i in 0..k {
        for j in 0..k {
            inv[i * k + j] = aug[i * 2 * k + k + j];
        }
    }
    Some(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_reconstruct_all_data_shards() {
        let rs = ReedSolomon::new(4, 2);
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let shards = rs.encode(&data, 2);
        assert_eq!(shards.len(), 6);

        // Reconstruct from all 4 data shards.
        let available: Vec<(usize, Vec<u8>)> = (0..4).map(|i| (i, shards[i].clone())).collect();
        let recovered = rs.reconstruct(&available, 2).expect("reconstruct");
        assert_eq!(recovered, data);
    }

    #[test]
    fn encode_reconstruct_with_missing_data_shards() {
        let rs = ReedSolomon::new(4, 2);
        let data = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let shards = rs.encode(&data, 2);

        // Lose shard 0 and shard 2 (data shards), keep 1, 3, 4, 5 (2 data + 2 parity).
        let available = vec![
            (1, shards[1].clone()),
            (3, shards[3].clone()),
            (4, shards[4].clone()),
            (5, shards[5].clone()),
        ];
        let recovered = rs.reconstruct(&available, 2).expect("reconstruct");
        assert_eq!(recovered, data);
    }

    #[test]
    fn encode_reconstruct_with_only_parity_shards() {
        let rs = ReedSolomon::new(4, 2);
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];
        let shards = rs.encode(&data, 2);

        // Lose all data shards, keep only parity (shards 4 and 5).
        // Need k=4 shards but only have 2 parity — not enough.
        let available = vec![(4, shards[4].clone()), (5, shards[5].clone())];
        assert!(rs.reconstruct(&available, 2).is_none(), "2 < k=4 shards must fail");
    }

    #[test]
    fn encode_reconstruct_mixed_loss() {
        let rs = ReedSolomon::new(3, 2);
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let shards = rs.encode(&data, 2);

        // Lose shard 1 (data) and shard 4 (parity), keep 0, 2, 3.
        let available =
            vec![(0, shards[0].clone()), (2, shards[2].clone()), (3, shards[3].clone())];
        let recovered = rs.reconstruct(&available, 2).expect("reconstruct");
        assert_eq!(recovered, data);
    }

    #[test]
    fn systematic_first_shards_are_data() {
        let rs = ReedSolomon::new(4, 2);
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let shards = rs.encode(&data, 2);
        // First k=4 shards must equal the original data.
        for i in 0..4 {
            assert_eq!(shards[i], &data[i * 2..(i + 1) * 2], "systematic shard {i} must be data");
        }
    }

    #[test]
    fn reconstruct_too_few_shards_fails() {
        let rs = ReedSolomon::new(4, 2);
        let data = vec![0u8; 8];
        let shards = rs.encode(&data, 2);
        let available = vec![(0, shards[0].clone())];
        assert!(rs.reconstruct(&available, 2).is_none());
    }

    #[test]
    fn large_shard_reconstruction() {
        let rs = ReedSolomon::new(4, 2);
        let shard_size = 1024;
        let data: Vec<u8> = (0..4 * shard_size).map(|i| u8::try_from(i % 256).unwrap()).collect();
        let shards = rs.encode(&data, shard_size);

        // Lose shards 0 and 3, keep 1, 2, 4, 5.
        let available = vec![
            (1, shards[1].clone()),
            (2, shards[2].clone()),
            (4, shards[4].clone()),
            (5, shards[5].clone()),
        ];
        let recovered = rs.reconstruct(&available, shard_size).expect("reconstruct");
        assert_eq!(recovered, data);
    }

    #[test]
    fn n_eq_7_f_eq_2_reconstruction() {
        // n=7, f=2: k=5 data shards, m=2 parity. BFT standard.
        let rs = ReedSolomon::new(5, 2);
        let shard_size = 64;
        let data: Vec<u8> =
            (0..5 * shard_size).map(|i| u8::try_from(i % 256).unwrap().wrapping_mul(7)).collect();
        let shards = rs.encode(&data, shard_size);

        // Lose 2 shards (any 2 of the 7), reconstruct from remaining 5.
        let available: Vec<(usize, Vec<u8>)> =
            [2, 3, 4, 5, 6].iter().map(|&i| (i, shards[i].clone())).collect();
        let recovered = rs.reconstruct(&available, shard_size).expect("reconstruct");
        assert_eq!(recovered, data);
    }
}
