//! Foundational types shared by every layer of the Oxide blockchain.
//!
//! ## What this crate is
//!
//! The smallest vocabulary of the chain: content-addressing hashes
//! ([`Hash`]), account identities ([`Address`]), consensus identifiers
//! ([`Height`], [`View`], [`Epoch`]), wall-clock markers
//! ([`TimestampMs`]), and the deterministic fixed-point numbers
//! ([`Price`], [`Qty`]) that all trading arithmetic is built on.
//!
//! ## Why it exists
//!
//! Every subsystem — consensus, storage, execution, the matching engine —
//! must agree on byte-for-byte representations of these values, because
//! identical bytes are a *consensus requirement*: two validators that
//! encode the same block differently will compute different state roots
//! and fork. Centralizing the types here makes accidental divergence
//! impossible.
//!
//! ## Invariants
//!
//! - **std-only, forever** (see the crate `Cargo.toml` policy note):
//!   these types appear on every hot path and must not drag in dependency
//!   trees.
//! - **No floats in state.** All quantized value is fixed-point over
//!   `u64`/`u128`; floating point is non-associative across hardware and
//!   would break cross-validator determinism (the `performance-first`
//!   skill, §"Fixed-point only").
//! - Newtypes are used deliberately: passing a bare `u64` that is
//!   "sometimes a height, sometimes a view" is how consensus bugs are born.

use std::fmt;

/// A 32-byte digest used for content addressing throughout the chain
/// (block IDs, transaction Merkle leaves, state roots, signatures).
///
/// Oxide hashes with BLAKE3 (see `oxide-crypto`); this type is the
/// transport form so that hashing-algorithm choice stays swappable
/// without touching every struct.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash(pub [u8; Hash::LEN]);

impl Hash {
    /// Length in bytes.
    pub const LEN: usize = 32;

    /// The all-zero digest, used as a genesis placeholder ("no parent").
    ///
    /// Genesis is the only block permitted to carry it as a parent link;
    /// `oxide-consensus` rejects it anywhere else (docs/oxidebft-spec.md
    /// §"block structure").
    pub const ZERO: Hash = Hash([0u8; Hash::LEN]);

    /// Build a hash from exactly 32 bytes, failing otherwise.
    ///
    /// # Errors
    /// [`WrongSliceLength`] if `bytes.len() != 32`. Returning an error
    /// (rather than truncating) is mandatory: silent truncation would let
    /// a short attacker-controlled slice masquerade as a block ID.
    pub fn from_slice(bytes: &[u8]) -> Result<Hash, WrongSliceLength> {
        let fixed: [u8; Hash::LEN] = bytes
            .try_into()
            .map_err(|_| WrongSliceLength { expected: Hash::LEN, got: bytes.len() })?;
        Ok(Hash(fixed))
    }

    /// Constant bytes view (for codecs and signers).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A slice did not have the exact length a fixed-width type requires.
///
/// Carrying `expected`/`got` lets callers produce actionable error
/// messages at trust boundaries (gateway, p2p ingress) instead of a bare
/// "bad length".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrongSliceLength {
    /// Length the type requires.
    pub expected: usize,
    /// Length the input actually had.
    pub got: usize,
}

impl fmt::Display for WrongSliceLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "slice length {} != required {}", self.got, self.expected)
    }
}

impl std::error::Error for WrongSliceLength {}

/// Render `bytes` as lowercase hex, at most `precision` characters
/// (`None` = all). Shared by [`Hash`] and [`Address`]; truncation is the
/// documented contract behind `Debug`'s short form.
fn hex_limited(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    let max_chars = f.precision().unwrap_or(bytes.len() * 2);
    let visible_bytes = (max_chars / 2).min(bytes.len());
    for &byte in &bytes[..visible_bytes] {
        write!(f, "{byte:02x}")?;
    }
    // Odd precision (e.g. `.5`) shows one final nibble rather than
    // dropping it silently — a truncated digest must never look complete.
    if max_chars % 2 == 1 && visible_bytes < bytes.len() {
        write!(f, "{:x}", bytes[visible_bytes] >> 4)?;
    }
    Ok(())
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex_limited(f, &self.0)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Truncated in debug (logs stay readable); full form via Display.
        write!(f, "Hash({self:.12}…)")
    }
}

/// A 20-byte account identifier, byte-compatible with EVM addresses
/// (`H160`).
///
/// Oxide unifies native accounts and EVM accounts into one address space
/// (README.md → "Plug-and-play"): a native (ed25519) user and a `MetaMask`
/// user are both addressed by 20 bytes, which is what lets the EVM module
/// read and write native-module state without a bridge.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; Address::LEN]);

impl Address {
    /// Length in bytes.
    pub const LEN: usize = 20;

    /// The zero address. In the EVM it conventionally means "burn /
    /// no specific recipient"; Oxide keeps that convention so existing
    /// tooling behaves identically.
    pub const ZERO: Address = Address([0u8; Address::LEN]);

    /// Build an address from exactly 20 bytes.
    ///
    /// # Errors
    /// [`WrongSliceLength`] if `bytes.len() != 20`.
    pub fn from_slice(bytes: &[u8]) -> Result<Address, WrongSliceLength> {
        let fixed: [u8; Address::LEN] = bytes
            .try_into()
            .map_err(|_| WrongSliceLength { expected: Address::LEN, got: bytes.len() })?;
        Ok(Address(fixed))
    }

    /// Constant bytes view (for codecs and storage keys).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Prefixed lowercase hex to match `eth_*` tooling byte-for-byte;
        // changing this format breaks every downstream parser.
        write!(f, "0x")?;
        hex_limited(f, &self.0)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({self:.10}…)")
    }
}

/// A fixed-width byte type usable with the generic codec impls in
/// `oxide-codec`.
///
/// Implemented by [`Hash`] and [`Address`]. `oxide-codec` implements its
/// `Encode`/`Decode` traits generically over this bound, so adding a new
/// fixed-width type here automatically makes it wire-capable without
/// touching the codec crate.
pub trait Fixed: Copy {
    /// Exact serialized width in bytes.
    const LEN: usize;

    /// Parse from exactly [`Fixed::LEN`] bytes.
    ///
    /// # Errors
    /// [`WrongSliceLength`] when the slice length differs.
    fn from_fixed(bytes: &[u8]) -> Result<Self, WrongSliceLength>;

    /// Serialize as bytes.
    fn as_fixed(&self) -> &[u8];
}

impl Fixed for Hash {
    const LEN: usize = Hash::LEN;

    fn from_fixed(bytes: &[u8]) -> Result<Self, WrongSliceLength> {
        Hash::from_slice(bytes)
    }

    fn as_fixed(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Fixed for Address {
    const LEN: usize = Address::LEN;

    fn from_fixed(bytes: &[u8]) -> Result<Self, WrongSliceLength> {
        Address::from_slice(bytes)
    }

    fn as_fixed(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A strongly-typed `u64` counter whose meaning differs per consensus
/// context.
///
/// One generic type instead of three near-identical newtypes keeps this
/// file small; the *semantic* safety comes from the type parameter being
/// explicit at every use site (`Id<Height>` and `Id<View>` never mix).
#[derive(Clone, Copy)]
pub struct Id<T: IdSpace>(
    /// Raw counter value.
    pub u64,
    /// Keeps the space parameter invariant so `Id<A>` and `Id<B>` are
    /// distinct, incompatible types. Zero-sized; no runtime cost.
    std::marker::PhantomData<T>,
);

// Comparison/hashing are implemented manually (not derived) because a
// derive would add `T: PartialEq`-style bounds on the *marker* type —
// wrong: the identity of an `Id` is its raw counter alone, so two ids
// compare and hash by `self.0` regardless of their space parameter.
impl<T: IdSpace> PartialEq for Id<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: IdSpace> Eq for Id<T> {}

impl<T: IdSpace> PartialOrd for Id<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: IdSpace> Ord for Id<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

// Fully qualified to avoid colliding with this crate's own `Hash` struct.
impl<T: IdSpace> std::hash::Hash for Id<T> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.0);
    }
}

impl<T: IdSpace> Default for Id<T> {
    fn default() -> Self {
        // Every counter-space starts at zero (see Id::ZERO).
        Id::new(0)
    }
}

/// Marker for which counter-space an [`Id`] lives in.
pub trait IdSpace: Copy {
    /// Lowercase name used in `Display` (logs, error messages).
    const NAME: &'static str;
}

/// Block height: 0 = genesis, strictly increasing, never reused.
///
/// Invariant (docs/oxidebft-spec.md §"views"): the finalized height is
/// the *only* ordering the execution lane trusts; a height has at most
/// one finalized block, ever.
#[derive(Clone, Copy)]
pub struct HeightSpace;
impl IdSpace for HeightSpace {
    const NAME: &'static str = "height";
}

/// Consensus view: a leader round within an epoch. Views advance on
/// timeout or commit; multiple views may map to one height during
/// faults, and one view never maps to two heights in the same replica.
#[derive(Clone, Copy)]
pub struct ViewSpace;
impl IdSpace for ViewSpace {
    const NAME: &'static str = "view";
}

/// Staking epoch: a bounded span of heights over which the validator set
/// is constant. Epoch rotation is two-phase (old set commits the
/// transition block, new set takes over) per the plan's epoch design.
#[derive(Clone, Copy)]
pub struct EpochSpace;
impl IdSpace for EpochSpace {
    const NAME: &'static str = "epoch";
}

/// Block height (see [`HeightSpace`]).
pub type Height = Id<HeightSpace>;
/// Consensus view (see [`ViewSpace`]).
pub type View = Id<ViewSpace>;
/// Staking epoch (see [`EpochSpace`]).
pub type Epoch = Id<EpochSpace>;

impl<T: IdSpace> Id<T> {
    /// Construct from a raw counter value.
    pub const fn new(value: u64) -> Self {
        // PhantomData is zero-sized; this is as cheap as the raw u64.
        Id(value, std::marker::PhantomData)
    }

    /// Raw counter value.
    pub const fn value(self) -> u64 {
        self.0
    }

    /// The first valid value of this space (all spaces start at 0).
    pub const ZERO: Id<T> = Id::new(0);

    /// The maximum representable value. Used as a saturation target
    /// by `checked_next` callers that prefer a stuck counter over a
    /// silent wrap to 0 (a wrap would corrupt consensus state).
    pub const MAX: Id<T> = Id::new(u64::MAX);

    /// Next value in the space; consensus uses this heavily
    /// (`view.next()` on timeout) and it must stay `const`-cheap.
    ///
    /// **Overflow semantics:** `next()` wraps on `u64::MAX` (matches
    /// the `const fn` arithmetic contract). Consensus callers that
    /// must never wrap use [`checked_next`](Self::checked_next) or
    /// [`saturating_next`](Self::saturating_next) instead.
    ///
    /// `#[must_use]`: computing `next()` and discarding it is always a
    /// bug — the caller meant to advance something.
    #[must_use]
    pub const fn next(self) -> Self {
        // Wrapping is intentional for the cheap path: callers that
        // care use `checked_next`. Documented at the call sites.
        Id::new(self.0.wrapping_add(1))
    }

    /// Checked successor: `None` if `self == MAX` (would overflow).
    /// Use in consensus-critical paths where a wrap to 0 would
    /// corrupt state (height/view advancement from untrusted input).
    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        if self.0 == u64::MAX { None } else { Some(Id::new(self.0 + 1)) }
    }

    /// Saturating successor: `MAX` if `self == MAX`. Use when the
    /// caller prefers a stuck counter (dead chain) over a silent
    /// wrap to 0 (corrupted chain). The chain is already dead at
    /// `u64::MAX` height/view — saturation just makes it explicit.
    #[must_use]
    pub const fn saturating_next(self) -> Self {
        if self.0 == u64::MAX { self } else { Id::new(self.0 + 1) }
    }

    /// Previous value, if any (genesis has none).
    #[must_use]
    pub const fn prev(self) -> Option<Self> {
        if self.0 == 0 { None } else { Some(Id::new(self.0 - 1)) }
    }
}

impl<T: IdSpace> fmt::Display for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // e.g. "height 42" — the space name in logs is what lets an
        // on-call engineer tell a stuck-view incident from a stuck-height
        // one at a glance.
        write!(f, "{} {}", T::NAME, self.0)
    }
}

impl<T: IdSpace> fmt::Debug for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Same text as Display (logs and panic messages should agree);
        // the derive would print `Id(42, PhantomData)` — pure noise.
        write!(f, "{} {}", T::NAME, self.0)
    }
}

/// Milliseconds since the Unix epoch, as stamped into block headers.
///
/// Invariant: timestamps are *advisory data* (ordering and monotonicity
/// are enforced by consensus, not by comparing clocks), so execution
/// logic must never branch on them. Anything time-dependent in state
/// (funding intervals, TIF expiries) uses *heights*, which are
/// deterministic across validators.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct TimestampMs(pub u64);

impl TimestampMs {
    /// Milliseconds in one second; for readable derived constants.
    pub const MILLIS_PER_SEC: u64 = 1_000;
}

impl fmt::Display for TimestampMs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

/// Deterministic fixed-point arithmetic for trading state.
///
/// ## Why fixed-point (from first principles)
///
/// IEEE-754 floats are non-associative (`(a+b)+c != a+(b+c)` depending on
/// rounding and hardware) and cannot exactly represent `0.1`-style
/// decimals. A matching engine whose balance math depends on rounding
/// mode would let two validators disagree about whether an account is
/// solvent — an instant, catastrophic fork. Integers with a fixed scale
/// are exact, totally ordered, and hardware-independent.
///
/// ## Representation
///
/// Value = `raw / 10^SCALE`, stored as `u64`. Prices use 8 decimals
/// (matches common crypto-venue tick precision, e.g. `1234.5678`);
/// quantities use 6 decimals (matches `0.278200`-style base sizes).
/// All intermediate products are computed in `u128` and narrowed back
/// with explicit, documented rounding — never silently.
///
/// ## Invariants
///
/// - Operations are **checked**: overflow and division by zero return
///   `Err`; a consensus input that trips them is invalid, not
///   wrap-around garbage.
/// - Rounding is **round-half-up** on division (ties resolve upward);
///   one mode, documented per-op, everywhere.
pub mod fixed {
    use std::fmt;

    /// Error returned by fixed-point arithmetic.
    ///
    /// Both variants signal *invalid input or configuration* (market
    /// bounds, fee parameters), not operational failure — callers reject
    /// the offending transaction/config rather than alerting operators.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum FixedError {
        /// The exact result does not fit the destination type.
        Overflow,
        /// A divisor was zero; market/fee configuration must prevent
        /// this from ever reaching arithmetic.
        DivisionByZero,
    }

    impl fmt::Display for FixedError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                FixedError::Overflow => write!(f, "fixed-point result overflows destination"),
                FixedError::DivisionByZero => write!(f, "fixed-point division by zero"),
            }
        }
    }

    impl std::error::Error for FixedError {}

    /// A scale-8 unsigned price, e.g. `Price(123_456_789) == 1.23456789`.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
    pub struct Price(pub u64);

    /// A scale-6 unsigned quantity, e.g. `Qty(2_500_000) == 2.5`.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
    pub struct Qty(pub u64);

    /// Price scale: value = raw / 1e8.
    pub const PRICE_SCALE: u64 = 100_000_000;
    /// Quantity scale: value = raw / 1e6.
    pub const QTY_SCALE: u64 = 1_000_000;

    /// One unit (scale multiple) of [`Price`]: `1.0` as a price.
    pub const PRICE_ONE: Price = Price(PRICE_SCALE);
    /// One unit (scale multiple) of [`Qty`]: `1.0` as a quantity.
    pub const QTY_ONE: Qty = Qty(QTY_SCALE);

    /// qty × price → notional, in natural scale-14 (6 + 8) `u128` units.
    ///
    /// Notional is kept in its natural scale rather than narrowed,
    /// because margin math (`maintenance = notional × mmr`) consumes it
    /// directly and premature rounding there would compound into
    /// solvency drift across a position's lifetime.
    ///
    /// # Errors
    /// Never overflows for `u64` inputs (`u64::MAX² < u128::MAX`); the
    /// `Result` keeps the API stable if scales ever widen.
    pub fn notional(qty: Qty, price: Price) -> u128 {
        // raw scales multiply exactly; no rounding occurs in multiplication.
        u128::from(qty.0) * u128::from(price.0)
    }

    /// Divide a scale-14 notional by a price, rounding **half-up**.
    ///
    /// Used to split fills (`notional / price → qty`). Ties round upward
    /// so a taker never receives *less* than their pro-rata share — the
    /// direction of every rounding choice is a fairness decision and is
    /// fixed here, once, for the whole codebase.
    ///
    /// # Errors
    /// [`FixedError::DivisionByZero`] if `p == 0` (invalid market
    /// config); [`FixedError::Overflow`] if the quotient exceeds the
    /// `u64` raw range.
    pub fn qty_from_notional_div_price(n: u128, p: Price) -> Result<Qty, FixedError> {
        let divisor = u128::from(p.0);
        if divisor == 0 {
            return Err(FixedError::DivisionByZero);
        }
        let quotient = n / divisor;
        let rem = n % divisor;
        let rounded = quotient + u128::from(rem * 2 >= divisor);
        u64::try_from(rounded).map(Qty).map_err(|_| FixedError::Overflow)
    }

    /// `a × b / divisor` for raw `u64` values, rounding **half-up**.
    ///
    /// The general workhorse for fee/rate math (e.g. `notional_raw ×
    /// fee_bps / 10_000`). Order matters: multiply first in `u128` so no
    /// precision is lost before the single, final rounding step.
    ///
    /// # Errors
    /// [`FixedError::DivisionByZero`] if `divisor == 0`;
    /// [`FixedError::Overflow`] if the quotient exceeds `u64`.
    pub fn mul_div_half_up(a: u64, b: u64, divisor: u64) -> Result<u64, FixedError> {
        let div = u128::from(divisor);
        if div == 0 {
            return Err(FixedError::DivisionByZero);
        }
        let product = u128::from(a) * u128::from(b);
        let quotient = product / div;
        let rem = product % div;
        let rounded = quotient + u128::from(rem * 2 >= div);
        u64::try_from(rounded).map_err(|_| FixedError::Overflow)
    }

    /// Checked subtraction on quantities; underflow is `None`.
    ///
    /// A negative fill remainder means a matching bug, so callers must
    /// handle `None` loudly rather than saturating to zero.
    #[must_use]
    pub fn qty_sub(a: Qty, b: Qty) -> Option<Qty> {
        a.0.checked_sub(b.0).map(Qty)
    }

    /// Checked addition on quantities; overflow is `None`.
    #[must_use]
    pub fn qty_add(a: Qty, b: Qty) -> Option<Qty> {
        a.0.checked_add(b.0).map(Qty)
    }
}

#[cfg(test)]
mod tests {
    use super::fixed::{self, FixedError, PRICE_ONE, Price, QTY_ONE, Qty};
    use super::{Address, Epoch, Hash, Height, View, WrongSliceLength};

    /// Hash/Address parse the right length and reject the wrong one.
    #[test]
    fn test_fixed_types_reject_wrong_length() {
        let bytes = [7u8; 32];
        assert_eq!(Hash::from_slice(&bytes).unwrap(), Hash(bytes));
        let err = Hash::from_slice(&bytes[..31]).unwrap_err();
        assert_eq!(
            err,
            WrongSliceLength { expected: 32, got: 31 },
            "short slices must fail loudly, never truncate"
        );
        assert_eq!(Address::from_slice(&[1u8; 20]).unwrap(), Address([1u8; 20]));
        assert!(Address::from_slice(&[1u8; 19]).is_err());
    }

    /// Display formats are stable wire/API surfaces (hex rules), and
    /// Debug's truncated form never looks like a full digest.
    ///
    /// Expected strings are built mechanically (`repeat`) rather than
    /// hand-typed: a previous hand-written expectation was off by one
    /// hex digit — exactly the class of bug this test exists to catch.
    #[test]
    fn test_display_formats_are_exact() {
        let mut raw = [0u8; 32];
        raw[..4].copy_from_slice(&[0x0a, 0xbc, 0xde, 0xf0]);
        let h = Hash(raw);
        // Full: "0a bc de f0" then 28 zero bytes → "0abcdef0" + 56 '0's.
        let zeros56 = "0".repeat(56);
        assert_eq!(h.to_string(), format!("0abcdef0{zeros56}"));
        // Debug truncation: precision 12 → 6 bytes → 12 hex chars + "…".
        let first12 = format!("0abcdef0{}", "0".repeat(4));
        assert_eq!(format!("{h:?}"), format!("Hash({first12}…)"));

        let a = Address([0xff; 20]);
        // Full: "0x" + 20 bytes → 40 'f's.
        let f40 = "f".repeat(40);
        assert_eq!(a.to_string(), format!("0x{f40}"));
        // Debug truncation: precision 10 → 5 bytes → "0x" + 10 'f's + "…".
        let f10 = "f".repeat(10);
        assert_eq!(format!("{a:?}"), format!("Address(0x{f10}…)"));

        // Id renders its space name — the log-readability contract.
        assert_eq!(Height::new(7).to_string(), "height 7");
        assert_eq!(View::new(9).to_string(), "view 9");
        assert_eq!(Epoch::new(2).to_string(), "epoch 2");
        assert_eq!(format!("{:?}", View::new(9)), "view 9");
    }

    /// next/prev arithmetic on Id is correct at the boundaries.
    #[test]
    fn test_id_next_prev_boundaries() {
        assert_eq!(Height::ZERO.next().value(), 1);
        assert!(Height::ZERO.prev().is_none(), "genesis has no parent");
        assert_eq!(Height::new(1).prev().unwrap(), Height::ZERO);
    }

    /// `checked_next` and `saturating_next` must not wrap at `u64::MAX`.
    /// Consensus uses these to prevent a byzantine height/view from
    /// corrupting state via integer overflow (C1 fix).
    #[test]
    fn test_id_checked_and_saturating_next_no_wrap() {
        assert!(Height::MAX.checked_next().is_none());
        assert_eq!(Height::MAX.saturating_next(), Height::MAX);
        assert_eq!(Height::new(5).checked_next(), Some(Height::new(6)));
        assert_eq!(Height::new(5).saturating_next(), Height::new(6));
        // View space shares the impl.
        assert!(View::MAX.checked_next().is_none());
        assert_eq!(View::MAX.saturating_next(), View::MAX);
    }

    /// Fixed-point: notional and split-back are exact inverses where the
    /// scales cancel, and rounding direction is half-up.
    #[test]
    fn test_fixed_point_notional_round_trip() {
        // 2.5 qty (scale 6) × 1.25 price (scale 8) = 3.125 notional
        // (scale 14) = 312_500_000_000_000 raw — exactly representable.
        let n = fixed::notional(Qty(2_500_000), Price(125_000_000));
        assert_eq!(n, 312_500_000_000_000u128);
        // splitting back: 3.125 / 1.25 = 2.5 exactly
        let q = fixed::qty_from_notional_div_price(n, Price(125_000_000)).unwrap();
        assert_eq!(q, Qty(2_500_000));
    }

    /// Rounding is half-up and documented behavior — ties go upward.
    #[test]
    fn test_rounding_is_half_up() {
        // 1.5 → 2; 0.5 → 1; 2.5 → 3 (ties up), 1.4 → 1; 2.6 → 3.
        assert_eq!(fixed::mul_div_half_up(3, 1, 2).unwrap(), 2);
        assert_eq!(fixed::mul_div_half_up(1, 1, 2).unwrap(), 1);
        assert_eq!(fixed::mul_div_half_up(5, 1, 2).unwrap(), 3);
        assert_eq!(fixed::mul_div_half_up(7, 1, 5).unwrap(), 1);
        assert_eq!(fixed::mul_div_half_up(13, 1, 5).unwrap(), 3);
    }

    /// Fee math workhorse: bps-based fee on a raw value.
    #[test]
    fn test_fee_bps_math() {
        // 10 bps of 1_000_000 = 1_000.
        assert_eq!(fixed::mul_div_half_up(1_000_000, 10, 10_000).unwrap(), 1_000);
    }

    /// Division by zero and overflow are loud errors, never silent zeros.
    #[test]
    fn test_fixed_errors_are_loud() {
        assert_eq!(fixed::mul_div_half_up(1, 1, 0).unwrap_err(), FixedError::DivisionByZero);
        assert_eq!(
            fixed::qty_from_notional_div_price(1, Price(0)).unwrap_err(),
            FixedError::DivisionByZero
        );
        assert_eq!(
            fixed::mul_div_half_up(u64::MAX, u64::MAX, 1).unwrap_err(),
            FixedError::Overflow
        );
    }

    /// Checked add/sub on Qty never wrap silently.
    #[test]
    fn test_qty_checked_ops() {
        assert_eq!(fixed::qty_add(Qty(u64::MAX), Qty(1)), None);
        assert_eq!(fixed::qty_sub(Qty(0), Qty(1)), None);
        assert_eq!(fixed::qty_sub(Qty(5), Qty(3)).unwrap(), Qty(2));
    }

    /// Ordering on Id is the raw ordering — relied on by consensus
    /// ("highest QC wins") and by the MMR's lexicographic key linking.
    #[test]
    fn test_id_ordering_follows_raw() {
        assert!(View::new(3) > View::new(2));
        assert!(Epoch::new(10) < Epoch::new(11));
    }

    /// One-constants have their documented scale.
    #[test]
    fn test_one_constants() {
        assert_eq!(PRICE_ONE.0, 100_000_000);
        assert_eq!(QTY_ONE.0, 1_000_000);
    }
}
