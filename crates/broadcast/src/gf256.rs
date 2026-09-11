//! GF(256) arithmetic — Galois field with 2^8 elements.
//!
//! Uses the AES irreducible polynomial `0x11B` (x^8 + x^4 + x^3 + x + 1),
//! the same field as AES Galois/Counter Mode. Multiplication uses
//! log/exp tables for O(1) lookup after a one-time table build.
//!
//! # Determinism
//!
//! The tables are built at construction time from the generator
//! `0x03` (a primitive element of GF(256) under the AES polynomial).
//! The same field parameters always produce the same tables, so
//! encoding and decoding are fully deterministic.

/// The lower 8 bits of the AES irreducible polynomial (0x11B),
/// used for modular reduction after a left shift: x^8 = x^4 + x^3 + x + 1.
const AES_REDUCE: u8 = 0x1B;

/// A primitive element (generator) of GF(256) under the AES polynomial.
/// `0x03` is the standard generator used by AES and most RS implementations.
const GENERATOR: u8 = 0x03;

/// GF(256) field arithmetic with precomputed log/exp tables.
///
/// The field has 256 elements (0..255). Addition is XOR. Multiplication
/// uses log/exp tables: `a * b = exp[log[a] + log[b]]`, with `log[0]`
/// undefined (handled by a zero-check).
pub struct Gf256 {
    /// Exponent table: `exp[i] = GENERATOR^i`. 512 entries (double-sized
    /// with period 255 to avoid modular reduction in mul/div).
    exp: [u8; 512],
    /// Logarithm table: `log[exp[i]] = i`. `log[0]` is unused (0 has
    /// no logarithm); callers must check for zero before lookup.
    log: [u8; 256],
}

impl Gf256 {
    /// Construct the field with precomputed log/exp tables.
    ///
    /// # Panics
    ///
    /// Never panics — the generator and polynomial are compile-time
    /// constants known to produce a valid field.
    #[must_use]
    pub fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];

        // Build exp table: exp[i] = GENERATOR^i in GF(256).
        // The multiplicative group of GF(256) has order 255, so
        // GENERATOR^255 = 1 for any non-zero element (Lagrange).
        let mut x: u8 = 1;
        for (i, exp_slot) in exp.iter_mut().enumerate().take(256) {
            *exp_slot = x;
            // Set log[x] = i. Skip i=255 because GENERATOR^255 = 1
            // would overwrite log[1] = 0 with 255.
            if i < 255 {
                log[x as usize] = u8::try_from(i).expect("i < 256");
            }
            x = gf_mul_raw(x, GENERATOR);
        }

        // Extend exp table with period 255 (not 256!) so that
        // exp[i + 255] = exp[i] for all i. This allows mul/div to
        // index directly without modular reduction.
        for i in 0..257 {
            exp[i + 255] = exp[i];
        }

        Self { exp, log }
    }

    /// Add two field elements (XOR in GF(2^8)).
    ///
    /// `self` is unused because addition is a pure field operation
    /// (no table lookup needed), but the method is kept on the
    /// struct for API consistency with `mul` and `div`.
    #[expect(clippy::unused_self)]
    #[must_use]
    pub fn add(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// Subtract two field elements (same as add in GF(2^8)).
    ///
    /// `self` is unused because subtraction equals addition in
    /// characteristic-2 fields (XOR is its own inverse).
    #[expect(clippy::unused_self)]
    #[must_use]
    pub fn sub(&self, a: u8, b: u8) -> u8 {
        a ^ b
    }

    /// Multiply two field elements using log/exp tables.
    ///
    /// Returns 0 if either operand is 0 (0 has no logarithm).
    #[must_use]
    pub fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        // exp[log[a] + log[b]] — the double-sized exp table (period 255)
        // avoids the need for modular reduction.
        self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
    }

    /// Divide two field elements. Returns 0 if `b` is 0 (undefined,
    /// but we return 0 rather than panicking for robustness in RS
    /// matrix inversion).
    #[cfg(test)]
    #[allow(clippy::unused_self)]
    #[must_use]
    pub fn div(&self, a: u8, b: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        if b == 0 {
            return 0; // Undefined — caller must ensure b != 0.
        }
        // exp[log[a] - log[b] + 255] — the +255 prevents underflow,
        // and the period-255 exp table gives the correct result.
        let log_a = self.log[a as usize] as usize;
        let log_b = self.log[b as usize] as usize;
        self.exp[log_a + 255 - log_b]
    }

    /// Compute the inverse of a non-zero element.
    ///
    /// Returns 0 if `a` is 0 (undefined, but 0 is its own inverse
    /// under XOR addition, so this is consistent).
    #[must_use]
    pub fn inv(&self, a: u8) -> u8 {
        if a == 0 {
            return 0;
        }
        // exp[255 - log[a]] = a^(-1)
        self.exp[255 - self.log[a as usize] as usize]
    }

    /// Raise `a` to the power `n` in GF(256).
    #[must_use]
    pub fn pow(&self, a: u8, n: u32) -> u8 {
        if a == 0 {
            return u8::from(n == 0);
        }
        // exp[(log[a] * n) mod 255]
        let log_a = u32::from(self.log[a as usize]);
        self.exp[((log_a * n) % 255) as usize]
    }
}

/// Raw GF(256) multiplication without tables — used only during
/// table construction. Implements the standard "Russian peasant"
/// algorithm with AES polynomial reduction.
fn gf_mul_raw(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let carry = a & 0x80;
        a = a.wrapping_shl(1);
        if carry != 0 {
            a ^= AES_REDUCE;
        }
        b >>= 1;
    }
    result
}

impl Default for Gf256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_is_xor() {
        let gf = Gf256::new();
        assert_eq!(gf.add(0x53, 0xCA), 0x99);
        assert_eq!(gf.add(0, 0), 0);
        assert_eq!(gf.add(0xFF, 0xFF), 0);
    }

    #[test]
    fn sub_is_xor() {
        let gf = Gf256::new();
        assert_eq!(gf.sub(0x99, 0xCA), 0x53);
    }

    #[test]
    fn mul_zero_returns_zero() {
        let gf = Gf256::new();
        assert_eq!(gf.mul(0, 0x53), 0);
        assert_eq!(gf.mul(0x53, 0), 0);
    }

    #[test]
    fn mul_one_returns_operand() {
        let gf = Gf256::new();
        assert_eq!(gf.mul(0x53, 1), 0x53);
    }

    #[test]
    fn mul_aes_test_vector() {
        // Known AES MixColumns test vector: 0x57 * 0x83 = 0xC1.
        let gf = Gf256::new();
        assert_eq!(gf.mul(0x57, 0x83), 0xC1);
    }

    #[test]
    fn mul_is_commutative() {
        let gf = Gf256::new();
        for a in [0x01, 0x53, 0xCA, 0xFF] {
            for b in [0x02, 0x53, 0xCA, 0xFF] {
                assert_eq!(gf.mul(a, b), gf.mul(b, a), "mul not commutative for {a}, {b}");
            }
        }
    }

    #[test]
    fn mul_is_associative() {
        let gf = Gf256::new();
        for a in [0x01, 0x53, 0xCA] {
            for b in [0x02, 0x53, 0xFF] {
                for c in [0x03, 0xCA, 0x80] {
                    let left = gf.mul(gf.mul(a, b), c);
                    let right = gf.mul(a, gf.mul(b, c));
                    assert_eq!(left, right, "mul not associative for {a},{b},{c}");
                }
            }
        }
    }

    #[test]
    fn div_inverts_mul() {
        let gf = Gf256::new();
        for a in [0x01, 0x53, 0xCA, 0xFF] {
            for b in [0x01, 0x53, 0xCA, 0xFF] {
                let product = gf.mul(a, b);
                assert_eq!(gf.div(product, b), a, "div doesn't invert mul for a={a}, b={b}");
            }
        }
    }

    #[test]
    fn inv_inverts_element() {
        let gf = Gf256::new();
        for a in [0x01, 0x53, 0xCA, 0xFF] {
            let inv = gf.inv(a);
            assert_eq!(gf.mul(a, inv), 1, "inv doesn't produce 1 for {a}");
        }
    }

    #[test]
    fn pow_computes_powers() {
        let gf = Gf256::new();
        assert_eq!(gf.pow(2, 0), 1);
        assert_eq!(gf.pow(2, 1), 2);
        assert_eq!(gf.pow(0x03, 255), 1); // generator^255 = 1 (Fermat)
    }

    #[test]
    fn distributive() {
        let gf = Gf256::new();
        for a in [0x01, 0x53] {
            for b in [0x02, 0xCA] {
                for c in [0x03, 0xFF] {
                    let left = gf.mul(a, gf.add(b, c));
                    let right = gf.add(gf.mul(a, b), gf.mul(a, c));
                    assert_eq!(left, right, "not distributive for {a},{b},{c}");
                }
            }
        }
    }

    #[test]
    fn generator_is_primitive() {
        // 3 is a primitive element: 3^255 = 1, and 3^k != 1 for k < 255.
        let gf = Gf256::new();
        assert_eq!(gf.pow(0x03, 255), 1, "3^255 must be 1 (Lagrange)");
        // Check that the order is exactly 255 (not a proper divisor).
        for &k in &[1u32, 3, 5, 15, 17, 51, 85] {
            assert_ne!(gf.pow(0x03, k), 1, "3^{k} must not be 1 (3 is primitive)");
        }
    }
}
