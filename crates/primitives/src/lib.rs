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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Hash(pub [u8; Hash::LEN]);

/// Hand-written (not derived) so the digest reaches the hasher as ONE
/// 32-byte `write` (hft-audit-2 S-6).
///
/// `#[derive(Hash)]` on a `[u8; 32]` field goes through the slice impl,
/// which first writes a `usize` length prefix and then the bytes — two
/// `write` calls. For [`digest_map::DigestHasher`] that was five
/// dependent multiply steps (prefix + four 8-byte chunks) instead of
/// four; for `SipHash` an extra 8 bytes compressed per lookup.
///
/// Dropping the prefix is sound because the type is fixed-width: the
/// prefix exists to keep variable-length slices prefix-free inside
/// composite keys, and 32 bytes are always 32 bytes. All 32 bytes are
/// still written — truncating to an 8-byte prefix would let anyone who
/// can name arbitrary `Hash` values (a peer citing a block ID it never
/// produced) build unbounded collision chains even in keyed `SipHash`
/// maps. Consistency with `Eq` (derived, byte-wise) holds because the
/// hash input is exactly the compared bytes.
impl std::hash::Hash for Hash {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}

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
        div_half_up(n, p.0).map(Qty)
    }

    /// `n / d` rounded half-up into `u64` — the single rounding step
    /// shared by [`mul_div_half_up`] and [`qty_from_notional_div_price`].
    ///
    /// Exactly one division per call (hft-audit-2 S-8): the remainder
    /// is recovered as `n − q·d` (a multiply and a subtract) instead of
    /// a second `%`, which for `u128` would be a second `__umodti3`
    /// libcall whenever LLVM fails to pair it with the `/`. (Rust 1.98
    /// does pair them today — this makes the single division a property
    /// of the source rather than of an optimizer pass.)
    ///
    /// A `u64` fast arm (hardware `div r64` when the numerator fits)
    /// was measured and rejected: on Zen 2 it was *slower* (6.4 → 10.2
    /// ns) than `__udivti3`, whose small-operand path drops to a 32-bit
    /// `div` for realistic fee operands.
    ///
    /// Rounding is `rem ≥ d − rem` ⇔ `2·rem ≥ d`, written without the
    /// doubling so it cannot overflow.
    ///
    /// Budget (`benches/fixed.rs`, `x86_64` EPYC 7232P):
    /// `fixed/mul_div_half_up` ≈ 6.2 ns, `fixed/mul_div_half_up_wide`
    /// (128-bit numerator) ≈ 11.8 ns.
    #[inline]
    fn div_half_up(n: u128, d: u64) -> Result<u64, FixedError> {
        if d == 0 {
            return Err(FixedError::DivisionByZero);
        }
        let d128 = u128::from(d);
        let q = n / d128;
        // rem < d ≤ u64::MAX, so it always fits.
        let rem = u64::try_from(n - q * d128).map_err(|_| FixedError::Overflow)?;
        let rounded = q + u128::from(rem >= d - rem);
        u64::try_from(rounded).map_err(|_| FixedError::Overflow)
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
        div_half_up(u128::from(a) * u128::from(b), divisor)
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

    /// `PartialEq` against `u64` so assertions and literal
    /// comparisons (`assert_eq!(bal, 20_000)`) stay readable — the
    /// same convention [`SignedQty`] uses for `i64` literals.
    /// Deliberately NOT `PartialOrd`: ordering a typed quantity
    /// against an untyped raw would hide the denomination bridge
    /// (`free < Qty(amount)` should be written, not `free < amount`).
    impl PartialEq<u64> for Qty {
        fn eq(&self, other: &u64) -> bool {
            self.0 == *other
        }
    }
    impl PartialEq<Qty> for u64 {
        fn eq(&self, other: &Qty) -> bool {
            *self == other.0
        }
    }

    /// A scale-6 **signed** quantity — the unit of positions and fill
    /// deltas, where the sign carries direction (positive = long /
    /// bought, negative = short / sold).
    ///
    /// Same scale as [`Qty`] but a distinct type so a signed exposure
    /// can never silently pass as an unsigned order quantity, or the
    /// reverse — the audit's "signed position quantity" unit
    /// (docs/audit001.md §9.B). Arithmetic saturates rather than
    /// wrapping: a position exceeding `i64::MAX` needs ~9.2e18 lots
    /// against `u64`-bounded margin, unreachable for funded accounts,
    /// and saturation keeps a mid-liquidation overflow from becoming a
    /// consensus halt (the deliberate clamp documented in
    /// `perps::accounting::adjust_position`).
    ///
    /// `PartialEq`/`PartialOrd` against `i64` are implemented so
    /// literal comparisons (`pos.size == 0`, `size > 0`) stay readable;
    /// the confusion the type exists to prevent — signed exposure vs
    /// unsigned [`Qty`], [`Price`], or balance units — is enforced at
    /// the type boundary and unaffected by literal ergonomics.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
    pub struct SignedQty(pub i64);

    impl SignedQty {
        /// The flat/zero position — no exposure in either direction.
        pub const ZERO: Self = Self(0);

        /// Signed magnitude of an unsigned fill [`Qty`], saturating at
        /// `i64::MAX`. Market configs bound order quantity far below
        /// the `i64` range, so the clamp is a bound proof rather than a
        /// reachable path — and when it does fire it applies equally to
        /// both sides of a fill, keeping the net position change zero.
        #[must_use]
        pub fn saturating_from_qty(qty: Qty) -> Self {
            Self(i64::try_from(qty.0).unwrap_or(i64::MAX))
        }

        /// The magnitude as an unsigned [`Qty`] — same scale, direction
        /// dropped. Returning the typed quantity (not a bare `u64`)
        /// keeps magnitude math inside the unit lattice; callers that
        /// genuinely need the raw value take `.0` at the boundary.
        #[must_use]
        pub const fn abs_qty(self) -> Qty {
            // `i64::MIN`'s magnitude is 2^63 — still inside `u64`.
            Qty(self.0.unsigned_abs())
        }

        /// Raw `i64` for the wire/storage boundary — codecs stay
        /// `put_i64`/`get_i64`; the type disciplines in-memory use.
        #[must_use]
        pub const fn get(self) -> i64 {
            self.0
        }

        /// `self` is a long (positive) exposure.
        #[must_use]
        pub const fn is_long(self) -> bool {
            self.0 > 0
        }

        /// `self` is a short (negative) exposure.
        #[must_use]
        pub const fn is_short(self) -> bool {
            self.0 < 0
        }

        /// `self` is zero — no position.
        #[must_use]
        pub const fn is_flat(self) -> bool {
            self.0 == 0
        }

        /// `self` and `other` point in strictly opposite directions —
        /// the position-closing predicate: a delta opposing a live
        /// position realizes `PnL` on the closed portion. A flat side
        /// never opposes (zero has no direction to oppose).
        #[must_use]
        pub const fn opposes(self, other: Self) -> bool {
            (self.is_long() && other.is_short()) || (self.is_short() && other.is_long())
        }

        /// `delta` adds exposure in `self`'s direction — the
        /// entry-price update predicate: a flat position takes the
        /// fill's price outright, a same-side delta volume-weights the
        /// entry, and an opposing delta realizes `PnL` instead.
        #[must_use]
        pub const fn extends(self, delta: Self) -> bool {
            self.is_flat() || self.0.signum() == delta.0.signum()
        }

        /// `−1`/`0`/`+1` direction of the exposure. Kept for the
        /// sign-flip predicate ("the position changed direction"),
        /// where comparing directions — including flat — is the
        /// semantic, not long/short classification.
        #[must_use]
        pub fn signum(self) -> i64 {
            self.0.signum()
        }
    }

    /// Negation saturates (`-i64::MIN` clamps to `i64::MAX`) — the
    /// bound is unreachable for margin-bounded positions, and a wrap
    /// would silently flip a liquidation's direction.
    impl std::ops::Neg for SignedQty {
        type Output = Self;
        fn neg(self) -> Self {
            Self(self.0.saturating_neg())
        }
    }

    /// Position arithmetic saturates — see the type-level comment for
    /// why the bound is unreachable and why wrapping would be worse
    /// than clamping.
    impl std::ops::Add for SignedQty {
        type Output = Self;
        fn add(self, rhs: Self) -> Self {
            Self(self.0.saturating_add(rhs.0))
        }
    }

    impl std::ops::AddAssign for SignedQty {
        fn add_assign(&mut self, rhs: Self) {
            self.0 = self.0.saturating_add(rhs.0);
        }
    }

    impl std::ops::Sub for SignedQty {
        type Output = Self;
        fn sub(self, rhs: Self) -> Self {
            Self(self.0.saturating_sub(rhs.0))
        }
    }

    impl std::ops::SubAssign for SignedQty {
        fn sub_assign(&mut self, rhs: Self) {
            self.0 = self.0.saturating_sub(rhs.0);
        }
    }

    /// Widening into `i128` for notional/`PnL` math — always exact.
    impl From<SignedQty> for i128 {
        fn from(q: SignedQty) -> Self {
            Self::from(q.0)
        }
    }

    /// Literal comparisons stay ergonomic (`pos.size == 0`); see the
    /// type-level comment for why same-unit `i64` literals are safe
    /// while cross-unit mixing remains impossible.
    impl PartialEq<i64> for SignedQty {
        fn eq(&self, other: &i64) -> bool {
            self.0 == *other
        }
    }

    impl PartialEq<SignedQty> for i64 {
        fn eq(&self, other: &SignedQty) -> bool {
            *self == other.0
        }
    }

    impl PartialOrd<i64> for SignedQty {
        fn partial_cmp(&self, other: &i64) -> Option<std::cmp::Ordering> {
            self.0.partial_cmp(other)
        }
    }

    impl PartialOrd<SignedQty> for i64 {
        fn partial_cmp(&self, other: &SignedQty) -> Option<std::cmp::Ordering> {
            self.partial_cmp(&other.0)
        }
    }
}

/// Synchronization policy helpers — the project's poisoned-mutex
/// contract (audit 9.D).
///
/// `Mutex::lock` returns `Err(PoisonError)` when another thread
/// panicked while holding the guard. Recovering the guard
/// (`PoisonError::into_inner`) is only sound when every value the
/// mutex protects is *independently consistent* — e.g. a map where
/// each key's entry is written by a single infallible assignment.
/// State-machine mutexes do not meet that bar:
///
/// - `Inner`-style mutexes guard many fields updated across one
///   handler; a panic mid-handler can leave the fields torn.
/// - Field-per-mutex state (staking, oracle, executor's
///   mempool/finalized/outcomes) is no better: invariants span
///   several mutexes, so a panic while holding any of them tears
///   the section.
/// - `KVStore`-style maps are per-key, but a panic mid-*batch* can
///   leave a multi-key write half-applied.
///
/// In all those cases the torn state is financial or
/// consensus-relevant: continuing risks producing a divergent
/// result that looks valid. Halting is the only safe response — a
/// validator restarts and reconstructs from durable state. These
/// accessors therefore panic on poison instead of recovering the
/// guard, and are the required accessors for shared state mutexes.
///
/// Recovery remains legitimate — with the per-key/per-entry
/// invariant documented at the type — for structures like the
/// matcher's sparse balance overflow (each account word is
/// independently meaningful and every op touches it atomically).
pub mod sync {
    /// Lock a mutex guarding shared state, panicking if poisoned.
    ///
    /// # Panics
    ///
    /// Panics naming the invariant if the mutex is poisoned — a
    /// panic occurred while a thread held the guard, so the guarded
    /// state may be torn.
    pub fn lock_state<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|_| {
            panic!(
                "state mutex poisoned: a holder panicked mid-mutation; \
                 the guarded state may be torn — halting rather than \
                 recovering a possibly-inconsistent guard"
            )
        })
    }

    /// Read-lock an `RwLock` guarding shared state — same poison
    /// policy as [`lock_state`].
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned.
    pub fn read_state<T>(m: &std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
        m.read().unwrap_or_else(|_| {
            panic!(
                "state lock poisoned: a writer panicked mid-mutation; \
                 the guarded state may be torn — halting rather than recovering"
            )
        })
    }

    /// Write-lock an `RwLock` guarding shared state — same poison
    /// policy as [`lock_state`].
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned.
    pub fn write_state<T>(m: &std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
        m.write().unwrap_or_else(|_| {
            panic!(
                "state lock poisoned: a writer panicked mid-mutation; \
                 the guarded state may be torn — halting rather than recovering"
            )
        })
    }

    /// Consume a mutex guarding shared state — same poison policy
    /// as [`lock_state`].
    ///
    /// # Panics
    ///
    /// Panics if the mutex is poisoned.
    pub fn into_inner_state<T>(m: std::sync::Mutex<T>) -> T {
        m.into_inner().unwrap_or_else(|_| {
            panic!(
                "state mutex poisoned: a holder panicked mid-mutation; \
                 the guarded state may be torn — halting rather than recovering"
            )
        })
    }
}

/// IEEE CRC-32 (reflected, poly `0xEDB88320`, init/xorout
/// `0xFFFF_FFFF`) — the checksum framing the storage journal and the
/// consensus WAL. Both on-disk formats pin this exact variant, so
/// the output must never change.
///
/// Slice-by-8: eight 256-entry tables (8 KiB, built at compile time)
/// fold eight input bytes per step, with no `unsafe` and no
/// dependency. Measured on Apple M1, 16 MiB input, release build:
/// ~1.9 GB/s vs ~0.4 GB/s for the previous one-table byte loop (and
/// for the WAL's former bitwise loop, which LLVM optimizes to the
/// same speed) — ~4.7×. The journal checksums whole block batches
/// on the commit path, so throughput there is commit latency.
///
/// On `x86_64` hosts with PCLMULQDQ + SSE4.1 (every x86 server CPU since
/// 2010), inputs of at least [`crc32::CLMUL_MIN_LEN`] bytes take a
/// carry-less-multiply folding path instead (hft-audit-2 S-3): four
/// 128-bit lanes folded 64 bytes per step, then a Barrett reduction to
/// 32 bits — the Intel "Fast CRC Computation Using PCLMULQDQ" scheme
/// (Gopal et al., 2009) as implemented in zlib/Linux/`crc32fast`. The
/// feature check is `is_x86_feature_detected!` (one cached atomic load);
/// hosts without it, and other architectures, keep slice-by-8. Both
/// paths produce bit-identical output (pinned by tests) — the on-disk
/// formats depend on it.
pub mod crc32 {
    /// Shortest input routed to the PCLMULQDQ path. The folding loop
    /// needs 64 bytes to seed its four lanes plus the 128→32-bit
    /// reduction tail; below ~128 bytes that fixed cost is not repaid
    /// against slice-by-8 (the threshold zlib and `crc32fast` use).
    pub const CLMUL_MIN_LEN: usize = 128;

    /// CRC-32 of `data`.
    #[must_use]
    pub fn checksum(data: &[u8]) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            if data.len() >= CLMUL_MIN_LEN
                && std::arch::is_x86_feature_detected!("pclmulqdq")
                && std::arch::is_x86_feature_detected!("sse4.1")
            {
                #[allow(unsafe_code)]
                // SAFETY: `clmul::update` is a `#[target_feature(enable =
                // "pclmulqdq,sse4.1")]` function; calling it is sound iff
                // the running CPU supports both features, which the two
                // `is_x86_feature_detected!` checks above just proved.
                // The function body itself is safe code (no raw-pointer
                // loads) — the feature contract is the only invariant.
                let crc = unsafe { clmul::update(0xFFFF_FFFF, data) };
                return !crc;
            }
        }
        !software_update(0xFFFF_FFFF, data)
    }

    /// The portable slice-by-8 path: advances the raw (pre-xorout) CRC
    /// register `crc` over `data`. `checksum` = `!software_update(!0,
    /// data)`; the PCLMULQDQ path also uses it for its sub-16-byte tail.
    #[must_use]
    pub fn software_update(mut crc: u32, data: &[u8]) -> u32 {
        let (chunks, rest) = data.as_chunks::<8>();
        for c in chunks {
            let lo = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) ^ crc;
            let hi = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
            crc = TABLES[7][(lo & 0xFF) as usize]
                ^ TABLES[6][((lo >> 8) & 0xFF) as usize]
                ^ TABLES[5][((lo >> 16) & 0xFF) as usize]
                ^ TABLES[4][(lo >> 24) as usize]
                ^ TABLES[3][(hi & 0xFF) as usize]
                ^ TABLES[2][((hi >> 8) & 0xFF) as usize]
                ^ TABLES[1][((hi >> 16) & 0xFF) as usize]
                ^ TABLES[0][(hi >> 24) as usize];
        }
        for &byte in rest {
            crc = (crc >> 8) ^ TABLES[0][((crc ^ u32::from(byte)) & 0xFF) as usize];
        }
        crc
    }

    /// PCLMULQDQ folding for the reflected IEEE polynomial.
    ///
    /// Constants are `x^k mod P(x)` values in the bit-reflected domain
    /// (Gopal et al. §"Folding"; identical to zlib's `crc32_simd` and
    /// Linux `crc32-pclmul_asm.S`): `K1/K2` fold a lane 512 bits
    /// forward (4-lane loop), `K3/K4` fold 128 bits (1-lane loop and
    /// lane merge), `K5` reduces 96→64 bits, and `P_X`/`U_PRIME` are the
    /// polynomial and its Barrett constant `floor(x^64 / P(x))`, both
    /// reflected. Changing any of them changes every on-disk checksum.
    #[cfg(target_arch = "x86_64")]
    mod clmul {
        use std::arch::x86_64::{
            __m128i, _mm_and_si128, _mm_clmulepi64_si128, _mm_cvtsi32_si128, _mm_extract_epi32,
            _mm_set_epi32, _mm_set_epi64x, _mm_srli_si128, _mm_xor_si128,
        };

        const K1: i64 = 0x1_5444_2bd4;
        const K2: i64 = 0x1_c6e4_1596;
        const K3: i64 = 0x1_7519_97d0;
        const K4: i64 = 0x0_ccaa_009e;
        const K5: i64 = 0x1_63cd_6124;
        const P_X: i64 = 0x1_DB71_0641;
        const U_PRIME: i64 = 0x1_F701_1641;

        /// Advance the raw CRC register `crc` over `data`
        /// (`data.len() >= 64`; [`super::CLMUL_MIN_LEN`] guarantees it).
        ///
        /// Safe code throughout — 16-byte loads go through
        /// `u64::from_le_bytes` + `_mm_set_epi64x` (which LLVM lowers to
        /// one `movdqu`), so the only obligation on callers is the
        /// target-feature contract stated at the `checksum` call site.
        #[target_feature(enable = "pclmulqdq,sse4.1")]
        #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
        // Justification: the casts reinterpret bit patterns between the
        // u32/u64 CRC domain and the signed lane types the intrinsics
        // take — no arithmetic meaning is attached to the sign.
        pub(super) fn update(crc: u32, data: &[u8]) -> u32 {
            debug_assert!(data.len() >= 64);
            let (blocks, tail) = data.as_chunks::<16>();
            let (seed, rest) = blocks.split_at(4.min(blocks.len()));
            if seed.len() < 4 {
                return super::software_update(crc, data);
            }

            // Seed four lanes with the first 64 bytes; fold the running
            // register into the lowest 32 bits of lane 3 (the CRC is
            // linear, so pre-xoring the state into the first bytes is
            // exactly "continue from `crc`").
            let mut x3 = _mm_xor_si128(load(&seed[0]), _mm_cvtsi32_si128(crc as i32));
            let mut x2 = load(&seed[1]);
            let mut x1 = load(&seed[2]);
            let mut x0 = load(&seed[3]);

            // Fold 64 bytes per step while four full blocks remain.
            let k1k2 = _mm_set_epi64x(K2, K1);
            let (quads, singles) = rest.as_chunks::<4>();
            for q in quads {
                x3 = fold(x3, load(&q[0]), k1k2);
                x2 = fold(x2, load(&q[1]), k1k2);
                x1 = fold(x1, load(&q[2]), k1k2);
                x0 = fold(x0, load(&q[3]), k1k2);
            }

            // Merge the four lanes, then fold any leftover 16-byte blocks.
            let k3k4 = _mm_set_epi64x(K4, K3);
            let mut x = fold(x3, x2, k3k4);
            x = fold(x, x1, k3k4);
            x = fold(x, x0, k3k4);
            for b in singles {
                x = fold(x, load(b), k3k4);
            }

            // 128 → 64 bits.
            let low32 = _mm_set_epi32(0, 0, 0, !0);
            let x = _mm_xor_si128(_mm_clmulepi64_si128::<0x10>(x, k3k4), _mm_srli_si128::<8>(x));
            let x = _mm_xor_si128(
                _mm_clmulepi64_si128::<0x00>(_mm_and_si128(x, low32), _mm_set_epi64x(0, K5)),
                _mm_srli_si128::<4>(x),
            );

            // Barrett reduction 64 → 32 bits (bit-reflected variant: the
            // result is the upper half of the low 64-bit word).
            let pu = _mm_set_epi64x(U_PRIME, P_X);
            let t1 = _mm_clmulepi64_si128::<0x10>(_mm_and_si128(x, low32), pu);
            let t2 = _mm_clmulepi64_si128::<0x00>(_mm_and_si128(t1, low32), pu);
            let crc = _mm_extract_epi32::<1>(_mm_xor_si128(x, t2)) as u32;

            super::software_update(crc, tail)
        }

        /// `a·k_lo ⊕ a·k_hi ⊕ b` — fold lane `a` forward onto block `b`.
        #[inline]
        #[target_feature(enable = "pclmulqdq,sse4.1")]
        fn fold(a: __m128i, b: __m128i, keys: __m128i) -> __m128i {
            let lo = _mm_clmulepi64_si128::<0x00>(a, keys);
            let hi = _mm_clmulepi64_si128::<0x11>(a, keys);
            _mm_xor_si128(_mm_xor_si128(b, lo), hi)
        }

        /// Unaligned 16-byte little-endian load without raw pointers.
        #[inline]
        #[target_feature(enable = "pclmulqdq,sse4.1")]
        #[allow(clippy::cast_possible_wrap)]
        fn load(block: &[u8; 16]) -> __m128i {
            let (lo, hi) = block.as_chunks::<8>().0.split_at(1);
            _mm_set_epi64x(u64::from_le_bytes(hi[0]) as i64, u64::from_le_bytes(lo[0]) as i64)
        }
    }

    /// `TABLES[0]` is the classic byte table; `TABLES[k][i]` is the
    /// CRC contribution of byte `i` followed by `k` zero bytes.
    const TABLES: [[u32; 256]; 8] = build_tables();

    #[allow(clippy::cast_possible_truncation)]
    // Justification: `i` is bounded by the literal 256, which fits
    // usize on every target (`usize::from(u32)` does not exist and
    // `try_from` is not const).
    const fn build_tables() -> [[u32; 256]; 8] {
        let mut t = [[0u32; 256]; 8];
        let mut i = 0u32;
        while i < 256 {
            let mut c = i;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
                k += 1;
            }
            t[0][i as usize] = c;
            i += 1;
        }
        let mut s = 1;
        while s < 8 {
            let mut i = 0;
            while i < 256 {
                let prev = t[s - 1][i];
                t[s][i] = (prev >> 8) ^ t[0][(prev & 0xFF) as usize];
                i += 1;
            }
            s += 1;
        }
        t
    }

    #[cfg(test)]
    mod tests {
        use super::checksum;

        /// Bitwise reference — the definition the tables must match.
        fn reference(data: &[u8]) -> u32 {
            let mut crc = 0xFFFF_FFFF_u32;
            for &b in data {
                crc ^= u32::from(b);
                for _ in 0..8 {
                    crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
                }
            }
            !crc
        }

        #[test]
        fn known_answers() {
            assert_eq!(checksum(b"123456789"), 0xCBF4_3926);
            assert_eq!(checksum(b""), 0);
            assert_eq!(!super::software_update(!0, b"123456789"), 0xCBF4_3926);
            // Through the PCLMULQDQ path too (≥ CLMUL_MIN_LEN bytes):
            // the check string repeated, against the bitwise definition.
            let long: Vec<u8> = b"123456789".iter().copied().cycle().take(1000).collect();
            assert_eq!(checksum(&long), reference(&long));
        }

        /// hft-audit-2 S-3: the dispatching `checksum` (PCLMULQDQ on
        /// capable x86 hosts) must equal the software slice-by-8 path
        /// at every length across the `CLMUL_MIN_LEN` boundary, the
        /// 64-byte fold stride and the 16-byte tail, at every alignment
        /// in a 16-byte window — and the bitwise definition on large
        /// inputs. The on-disk journal/WAL formats depend on it.
        #[test]
        fn clmul_path_matches_software_at_all_lengths_and_alignments() {
            let data: Vec<u8> =
                (0u32..8192).map(|i| i.wrapping_mul(2_246_822_519).to_le_bytes()[3]).collect();
            for start in 0..16 {
                for len in 0..1100 {
                    let s = &data[start..start + len];
                    let sw = !super::software_update(!0, s);
                    assert_eq!(checksum(s), sw, "start {start} len {len}");
                }
            }
            for len in [4095, 4096, 4097, 8192 - 16] {
                let s = &data[..len];
                assert_eq!(checksum(s), reference(s), "len {len}");
            }
        }

        /// Randomised equality over many (offset, length, content)
        /// triples from a fixed-seed splitmix64 stream — deterministic
        /// (testing-standards: no ambient randomness) yet covering
        /// content patterns the structured sweep above does not.
        #[test]
        fn clmul_path_matches_software_on_pseudorandom_inputs() {
            let mut state = 0x0123_4567_89AB_CDEF_u64;
            let mut next = || {
                state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            };
            let mut buf = vec![0u8; 70_000];
            for b in buf.chunks_mut(8) {
                let w = next().to_le_bytes();
                b.copy_from_slice(&w[..b.len()]);
            }
            for _ in 0..400 {
                let start = usize::try_from(next() % 64).unwrap();
                let len = usize::try_from(next() % 65_000).unwrap();
                let s = &buf[start..start + len];
                assert_eq!(checksum(s), !super::software_update(!0, s), "start {start} len {len}");
            }
        }

        /// The PCLMULQDQ kernel itself, called directly with arbitrary
        /// starting registers, matches the software path — so the
        /// equality tests above are not comparing software with itself
        /// on a capable host. Skips (passes) on hosts without the
        /// features.
        #[cfg(target_arch = "x86_64")]
        #[test]
        fn clmul_update_matches_software_directly() {
            if !(std::arch::is_x86_feature_detected!("pclmulqdq")
                && std::arch::is_x86_feature_detected!("sse4.1"))
            {
                return;
            }
            let data: Vec<u8> =
                (0u32..5000).map(|i| i.wrapping_mul(7).wrapping_add(3).to_le_bytes()[0]).collect();
            for len in 64..600 {
                for init in [0xFFFF_FFFF_u32, 0, 0x1234_5678] {
                    #[allow(unsafe_code)]
                    // SAFETY: both required CPU features were detected above.
                    let hw = unsafe { super::clmul::update(init, &data[..len]) };
                    assert_eq!(hw, super::software_update(init, &data[..len]), "len {len}");
                }
            }
        }

        #[test]
        fn matches_reference_across_lengths_and_alignments() {
            let data: Vec<u8> =
                (0u32..4096).map(|i| i.wrapping_mul(2_654_435_761).to_le_bytes()[2]).collect();
            for start in 0..9 {
                for len in (0..300).chain([1023, 4000]) {
                    let end = (start + len).min(data.len());
                    assert_eq!(checksum(&data[start..end]), reference(&data[start..end]));
                }
            }
        }
    }
}

/// Process-wide actor supervision: a registry of named threads so a
/// silent death is a *visible* death, plus the panic hook that turns
/// a critical actor's panic into a process abort.
///
/// ## Why it exists
///
/// `panic = "unwind"` (workspace release profile) means a panicking
/// actor kills only its own thread — the process keeps running,
/// looking healthy while a consensus pump, exec lane, or accept loop
/// is gone. A validator that cannot observe its own dead actors
/// cannot be restarted by a supervisor (`systemd`, Kubernetes) that
/// keys on process exit or a health endpoint.
///
/// ## Model
///
/// - [`register`] names an actor and whether it is *critical* —
///   i.e. the node cannot do its job without it (exec lane, accept
///   loop, consensus driver).
/// - [`spawn_supervised`] is the standard spawn for supervised
///   threads: it registers the actor, names the OS thread (so the
///   panic hook can map thread → actor), and marks the actor
///   [`ActorState::Exited`] when the body returns.
/// - [`install_panic_hook`] wraps the default hook: every panic is
///   counted, registered actors are marked [`ActorState::Panicked`],
///   and a panic on a *critical* actor's thread aborts the process
///   so the supervisor restarts it — fail-fast beats half-alive.
///   A *clean return* never aborts: graceful shutdown exits actors
///   legitimately; the registry still reports them dead for
///   `/health`.
/// - [`unhealthy_critical`] / [`actors`] feed the health surface;
///   [`panics_total`] feeds metrics.
///
/// Tokio tasks are *not* covered by the thread registry — a task
/// panic unwinds into its `JoinHandle`, and the thread name is the
/// runtime worker's. Binaries monitor task `JoinHandle`s and report
/// through [`mark_exited`]/[`mark_panicked`].
pub mod supervision {
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Lifecycle state of a registered actor.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ActorState {
        /// Registered; the actor has not reported an exit.
        Alive,
        /// The actor's body returned — dead, but not by panic.
        /// Legitimate during shutdown, a failure otherwise.
        Exited,
        /// The actor panicked.
        Panicked,
    }

    struct ActorEntry {
        /// Whether the process cannot do its job without this actor.
        /// A panic on a critical actor's thread aborts the process.
        critical: bool,
        state: ActorState,
    }

    static REGISTRY: OnceLock<Mutex<BTreeMap<String, ActorEntry>>> = OnceLock::new();
    /// Process-wide panic counter, bumped by the installed hook and
    /// by [`mark_panicked`]. Exported as `oxide_actor_panics_total`.
    static PANICS: AtomicU64 = AtomicU64::new(0);

    fn registry() -> &'static Mutex<BTreeMap<String, ActorEntry>> {
        REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
    }

    /// Lock the registry, *recovering* from poison.
    ///
    /// Every caller of this module may run inside the panic hook —
    /// re-panicking there aborts unconditionally. A torn registry
    /// entry is strictly better than losing the panic report, so
    /// poison is recovered here (unlike [`sync::lock_state`](
    /// crate::sync::lock_state), which guards consensus state).
    fn lock_registry() -> MutexGuard<'static, BTreeMap<String, ActorEntry>> {
        registry().lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register `name` as a supervised actor.
    ///
    /// Re-registering revives a dead entry — correct for respawned
    /// actors — and refreshes its criticality.
    pub fn register(name: &str, critical: bool) {
        lock_registry().insert(name.to_string(), ActorEntry { critical, state: ActorState::Alive });
    }

    /// Record that `name`'s body returned (clean exit, closed
    /// channel, finished loop). Never aborts — shutdown exits
    /// actors legitimately — but `unhealthy_critical` reports it.
    pub fn mark_exited(name: &str) {
        if let Some(e) = lock_registry().get_mut(name) {
            e.state = ActorState::Exited;
        }
    }

    /// Record that `name` panicked. Also bumps [`panics_total`].
    /// Called by the panic hook (via thread-name lookup) and by
    /// task monitors observing a `JoinError`.
    pub fn mark_panicked(name: &str) {
        PANICS.fetch_add(1, Ordering::Relaxed);
        if let Some(e) = lock_registry().get_mut(name) {
            e.state = ActorState::Panicked;
        }
    }

    /// Total panics observed since hook install / first report.
    pub fn panics_total() -> u64 {
        PANICS.load(Ordering::Relaxed)
    }

    /// Names of critical actors that are no longer alive — the
    /// fail-closed input for `/health`: any entry here means the
    /// node is degraded and the health probe must say so.
    pub fn unhealthy_critical() -> Vec<String> {
        lock_registry()
            .iter()
            .filter(|(_, e)| e.critical && e.state != ActorState::Alive)
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// Snapshot of every registered actor: `(name, critical, state)`.
    /// Diagnostics only — `/health` uses [`unhealthy_critical`].
    pub fn actors() -> Vec<(String, bool, ActorState)> {
        lock_registry().iter().map(|(n, e)| (n.clone(), e.critical, e.state)).collect()
    }

    /// Install the process panic hook: keep the default output,
    /// count the panic, mark the panicking actor (matched by OS
    /// thread name, which [`spawn_supervised`] sets), and **abort
    /// the process when a critical actor's thread panics** — a
    /// validator that cannot execute or accept peers is worse than
    /// down, because it still signs (or withholds) on stale state.
    ///
    /// Idempotent per process; binaries call it first in `main`.
    /// Unregistered/unknown threads are counted but never abort —
    /// a panicking per-peer reader is a logged event, not a fatal
    /// one.
    pub fn install_panic_hook() {
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            default(info);
            PANICS.fetch_add(1, Ordering::Relaxed);
            let thread = std::thread::current();
            let name = thread.name().unwrap_or("<unnamed>");
            let critical = {
                let mut reg = lock_registry();
                match reg.get_mut(name) {
                    Some(e) => {
                        e.state = ActorState::Panicked;
                        e.critical
                    }
                    None => false,
                }
            };
            if critical {
                eprintln!(
                    "critical actor '{name}' panicked — aborting so the \
                     supervisor restarts a coherent process"
                );
                std::process::abort();
            }
        }));
    }

    /// Spawn a supervised thread: registers `name`, names the OS
    /// thread (so the panic hook maps panic → actor), runs `f`, and
    /// marks the actor [`ActorState::Exited`] when it returns.
    ///
    /// # Errors
    ///
    /// Propagates [`std::io::Error`] from [`std::thread::Builder::spawn`]
    /// (e.g. `EAGAIN` thread exhaustion) — callers decide whether the
    /// failed spawn is fatal.
    pub fn spawn_supervised<F>(
        name: &str,
        critical: bool,
        f: F,
    ) -> std::io::Result<std::thread::JoinHandle<()>>
    where
        F: FnOnce() + Send + 'static,
    {
        register(name, critical);
        let actor = name.to_string();
        std::thread::Builder::new().name(actor.clone()).spawn(move || {
            f();
            mark_exited(&actor);
        })
    }

    /// [`spawn_supervised`] + optional core pinning (hft-audit
    /// F-02): when `core` is `Some`, the actor's first action is
    /// `pin::pin_current_thread` — a failed pin logs once and the
    /// actor runs unpinned (locality is a performance property,
    /// never a correctness one; startup validation in the config
    /// layer is the fail-fast gate for bad topology).
    ///
    /// # Errors
    ///
    /// Same contract as [`spawn_supervised`].
    pub fn spawn_supervised_pinned<F>(
        name: &str,
        critical: bool,
        core: Option<u32>,
        f: F,
    ) -> std::io::Result<std::thread::JoinHandle<()>>
    where
        F: FnOnce() + Send + 'static,
    {
        let actor = name.to_string();
        spawn_supervised(name, critical, move || {
            if let Some(c) = core
                && let Err(e) = crate::pin::pin_current_thread(c)
            {
                eprintln!("{actor}: pin to core {c} failed: {e} — running unpinned");
            }
            f();
        })
    }
}

/// Thread pinning and NUMA surface (hft-audit F-02).
///
/// Why this module is std-only: `primitives` is on every hot path
/// and bound to the standard library — so pinning goes through
/// `taskset(1)` (util-linux, present on every real distro) against
/// the calling thread's `/proc/thread-self` TID instead of linking
/// `libc::sched_setaffinity`. A subprocess per pin is a few hundred
/// µs and runs exactly once per actor thread at startup — cold
/// path by definition, so no syscall-wrapper `unsafe` enters the
/// crate.
///
/// A host without `taskset` gets a clear `NotFound` error and every
/// caller continues unpinned — pinning is a locality property, never
/// a correctness one. (`sched_setaffinity` via `libc` would remove the
/// subprocess, but `libc` is not a dependency of this crate and the
/// std-only rule outranks a once-per-thread startup cost.)
///
/// SMT awareness (hft-audit-2 S-7): `online_cpus` counts *logical*
/// CPUs, so two actors can be "validly" pinned to the two hyperthreads
/// of one physical core and silently run at half speed.
/// [`pin::thread_siblings`] reads the sysfs sibling list and
/// [`pin::smt_pin_report`] turns a set of pins into errors (two actors
/// on one physical core) and warnings (a pinned core's sibling is
/// neither pinned nor isolated) for config validation to surface.
///
/// Non-Linux targets compile to no-ops: the config surface stays
/// portable and the caller logs the skipped pin.
pub mod pin {
    /// Pin the calling thread to logical CPU `core` (Linux).
    ///
    /// Spawns `taskset -pc <core> <tid>` — the `-p` form applies the
    /// mask to the *thread* whose TID `pid` names (taskset operates
    /// on threads, not just processes). `Ok(())` on success; `Err`
    /// carries stderr (missing `taskset`, invalid core) for the
    /// caller to log — a failed pin degrades locality, never
    /// correctness, so callers continue unpinned.
    ///
    /// # Errors
    ///
    /// `std::io::Error` if the thread id cannot be read, `taskset`
    /// is absent, or the affinity set is rejected (offline core,
    /// cgroup `cpuset` restriction).
    #[cfg(target_os = "linux")]
    pub fn pin_current_thread(core: u32) -> std::io::Result<()> {
        let target = std::fs::read_link("/proc/thread-self")?;
        let tid = target
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.parse::<u32>().ok())
            .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "could not parse /proc/thread-self tid",
            )
        })?;
        let out = match std::process::Command::new("taskset")
            .args(["-pc", &core.to_string(), &tid.to_string()])
            .output()
        {
            Ok(out) => out,
            // A missing binary is an environment gap (minimal container
            // images ship without util-linux), not a topology error —
            // say exactly that so the operator's log line is actionable.
            // The caller still continues unpinned (hft-audit-2 S-7).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "taskset(1) not found on PATH (install util-linux); \
                         cannot pin thread {tid} to core {core}"
                    ),
                ));
            }
            Err(e) => return Err(e),
        };
        if out.status.success() {
            return Ok(());
        }
        Err(std::io::Error::other(format!(
            "taskset -pc {core} {tid} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }

    /// Non-Linux no-op — see the module doc.
    ///
    /// # Errors
    ///
    /// Never: always `Ok(())`. The `Result` mirrors the Linux
    /// signature so call sites stay platform-blind.
    #[cfg(not(target_os = "linux"))]
    pub fn pin_current_thread(_core: u32) -> std::io::Result<()> {
        Ok(())
    }

    /// Logical CPUs this process may run on (the `sched_getaffinity`
    /// mask, not the machine total — cgroup/affinity restrictions
    /// count, which is exactly the set a pin must target). Linux
    /// reads `/sys/devices/system/cpu/online` (`"0-3,8-11"`); other
    /// platforms fall back to `available_parallelism`.
    #[cfg(target_os = "linux")]
    pub fn online_cpus() -> u32 {
        let mut count = std::fs::read_to_string("/sys/devices/system/cpu/online")
            .map_or(0, |s| u32::try_from(parse_cpu_list(&s).len()).unwrap_or(u32::MAX));
        if count == 0 {
            // `usize`→`u32` saturates: a host past 4 billion logical
            // CPUs reads as u32::MAX — an absurdity ceiling a pin
            // validator compares against, not a correctness value.
            count = std::thread::available_parallelism()
                .map_or(1, |n| u32::try_from(n.get()).unwrap_or(u32::MAX));
        }
        count
    }

    /// `available_parallelism` on non-Linux — the doc above applies.
    #[cfg(not(target_os = "linux"))]
    pub fn online_cpus() -> u32 {
        // `usize`→`u32` saturates — see the Linux arm.
        std::thread::available_parallelism()
            .map_or(1, |n| u32::try_from(n.get()).unwrap_or(u32::MAX))
    }

    /// Parse a Linux CPU-list string (`"0-3,8-11"`, `"0,8"`, `"5"`) —
    /// the format of `/sys/devices/system/cpu/{online,isolated}` and
    /// `topology/thread_siblings_list` — into ascending CPU ids.
    /// Malformed fragments are skipped (sysfs is trusted but a partial
    /// read must not panic); a range wider than [`MAX_CPU_LIST_SPAN`]
    /// is ignored rather than allocated.
    #[must_use]
    pub fn parse_cpu_list(s: &str) -> Vec<u32> {
        let mut out = Vec::new();
        for part in s.trim().split(',').map(str::trim).filter(|p| !p.is_empty()) {
            if let Some((lo, hi)) = part.split_once('-') {
                if let (Ok(lo), Ok(hi)) = (lo.parse::<u32>(), hi.parse::<u32>())
                    && lo <= hi
                    && hi - lo < MAX_CPU_LIST_SPAN
                {
                    out.extend(lo..=hi);
                }
            } else if let Ok(c) = part.parse::<u32>() {
                out.push(c);
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Widest single `lo-hi` range [`parse_cpu_list`] will expand.
    /// 65 536 logical CPUs is far beyond any shipping host (Linux's
    /// `NR_CPUS` max is 8192); the cap only stops a corrupt sysfs read
    /// from allocating gigabytes on a cold startup path.
    pub const MAX_CPU_LIST_SPAN: u32 = 1 << 16;

    /// SMT siblings of logical CPU `core`, including `core` itself
    /// (Linux: `/sys/devices/system/cpu/cpuN/topology/
    /// thread_siblings_list`). Two siblings share one physical core's
    /// L1/L2 and execution ports, so two hot actors pinned to siblings
    /// run at roughly half speed each — the silent 2× the audit warns
    /// about (hft-audit-2 S-7). Returns `[core]` when the topology is
    /// unreadable (non-Linux, offline core, sandboxed sysfs) — "no
    /// known siblings", never an error.
    #[must_use]
    pub fn thread_siblings(core: u32) -> Vec<u32> {
        #[cfg(target_os = "linux")]
        {
            let path = format!("/sys/devices/system/cpu/cpu{core}/topology/thread_siblings_list");
            if let Ok(s) = std::fs::read_to_string(path) {
                let list = parse_cpu_list(&s);
                if list.contains(&core) {
                    return list;
                }
            }
        }
        vec![core]
    }

    /// CPUs isolated from the general scheduler (`isolcpus=` /
    /// `/sys/devices/system/cpu/isolated`); empty when none or off
    /// Linux.
    #[must_use]
    pub fn isolated_cpus() -> Vec<u32> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(s) = std::fs::read_to_string("/sys/devices/system/cpu/isolated") {
                return parse_cpu_list(&s);
            }
        }
        Vec::new()
    }

    /// Outcome of [`smt_pin_report`]: hard misconfigurations and
    /// advisory findings, as operator-readable strings.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub struct SmtReport {
        /// Two pinned actors share one physical core (same logical CPU
        /// or SMT siblings). Config validation should reject these.
        pub errors: Vec<String>,
        /// A pinned actor's SMT sibling is neither pinned by us nor
        /// isolated, so arbitrary threads can land on the other half
        /// of its core. Worth a startup warning, not a refusal.
        pub warnings: Vec<String>,
    }

    /// Check a set of `(setting name, logical CPU)` pins against live
    /// SMT topology ([`thread_siblings`], [`isolated_cpus`]).
    ///
    /// Cold path: config validation at startup.
    #[must_use]
    pub fn smt_pin_report(pins: &[(&str, u32)]) -> SmtReport {
        smt_pin_report_with(pins, thread_siblings, &isolated_cpus())
    }

    /// [`smt_pin_report`] with injected topology — the testable core
    /// (testing-standards: no ambient system state in unit tests).
    #[must_use]
    pub fn smt_pin_report_with(
        pins: &[(&str, u32)],
        siblings: impl Fn(u32) -> Vec<u32>,
        isolated: &[u32],
    ) -> SmtReport {
        let mut report = SmtReport::default();
        for (i, &(name_a, core_a)) in pins.iter().enumerate() {
            let sibs = siblings(core_a);
            for &(name_b, core_b) in &pins[i + 1..] {
                if core_a == core_b {
                    report
                        .errors
                        .push(format!("{name_a} and {name_b} are both pinned to CPU {core_a}"));
                } else if sibs.contains(&core_b) {
                    report.errors.push(format!(
                        "{name_a} (CPU {core_a}) and {name_b} (CPU {core_b}) are SMT \
                         siblings of one physical core — each would run at ~half speed"
                    ));
                }
            }
            for &sib in sibs.iter().filter(|&&c| c != core_a) {
                let pinned_by_us = pins.iter().any(|&(_, c)| c == sib);
                if !pinned_by_us && !isolated.contains(&sib) {
                    report.warnings.push(format!(
                        "{name_a} (CPU {core_a}): SMT sibling CPU {sib} is not isolated — \
                         other threads can share this physical core (isolcpus={sib} or \
                         disable SMT)"
                    ));
                }
            }
        }
        report
    }

    /// Whether NUMA node `node` exists (Linux sysfs); always `true`
    /// elsewhere — the field is informational off Linux.
    #[cfg(target_os = "linux")]
    pub fn numa_node_present(node: u32) -> bool {
        std::path::Path::new(&format!("/sys/devices/system/node/node{node}")).is_dir()
    }

    /// Non-Linux: no sysfs to check — accept (the no-op surface is
    /// documented on the module).
    #[cfg(not(target_os = "linux"))]
    pub fn numa_node_present(_node: u32) -> bool {
        true
    }
}

#[cfg(test)]
mod pin_tests {
    use super::pin::{parse_cpu_list, smt_pin_report_with, thread_siblings};

    #[test]
    fn test_parse_cpu_list_handles_ranges_singles_and_garbage() {
        assert_eq!(parse_cpu_list("0-3,8-11\n"), vec![0, 1, 2, 3, 8, 9, 10, 11]);
        assert_eq!(parse_cpu_list("0,8"), vec![0, 8]);
        assert_eq!(parse_cpu_list("5"), vec![5]);
        assert_eq!(parse_cpu_list(""), Vec::<u32>::new());
        assert_eq!(parse_cpu_list("x,3-1,2,2,0-"), vec![2], "malformed parts skipped");
        assert_eq!(parse_cpu_list("0-4294967295"), Vec::<u32>::new(), "absurd span ignored");
    }

    /// Topology of the audit box: 8 cores × 2 threads, siblings N and N+8.
    fn epyc_siblings(c: u32) -> Vec<u32> {
        let base = c % 8;
        vec![base, base + 8]
    }

    #[test]
    fn test_smt_report_rejects_two_actors_on_one_physical_core() {
        let r = smt_pin_report_with(
            &[("consensus_core", 2), ("exec_lane_core", 10)],
            epyc_siblings,
            &[],
        );
        assert_eq!(r.errors.len(), 1, "{r:?}");
        assert!(r.errors[0].contains("SMT"));
        assert!(r.warnings.is_empty(), "siblings pinned by us are not 'unisolated': {r:?}");

        let same = smt_pin_report_with(&[("a", 3), ("b", 3)], epyc_siblings, &[]);
        assert_eq!(same.errors.len(), 1);
    }

    #[test]
    fn test_smt_report_warns_on_unisolated_sibling_only() {
        let r = smt_pin_report_with(
            &[("consensus_core", 2), ("exec_lane_core", 4)],
            epyc_siblings,
            &[],
        );
        assert!(r.errors.is_empty(), "distinct physical cores: {r:?}");
        assert_eq!(r.warnings.len(), 2, "{r:?}");

        let isolated = smt_pin_report_with(
            &[("consensus_core", 2), ("exec_lane_core", 4)],
            epyc_siblings,
            &[10, 12],
        );
        assert_eq!(isolated, super::pin::SmtReport::default());
    }

    #[test]
    fn test_thread_siblings_always_contains_the_core() {
        // Live sysfs (or the fallback): never empty, always includes
        // the queried CPU — callers rely on that invariant.
        assert!(thread_siblings(0).contains(&0));
        assert_eq!(thread_siblings(u32::MAX - 1), vec![u32::MAX - 1]);
    }
}

/// Map types for keys that are ALREADY cryptographic digests
/// (hft-audit F-25).
///
/// `Hash` keys are BLAKE3-256 digests — uniformly distributed by
/// construction. Running them through `HashMap`'s default `SipHash`
/// re-derives uniformity the key already has: ~25–30 ns per lookup,
/// twice per tx on the executor's preverify path and once per OCC
/// read/write probe — pure waste. [`DigestHasher`] folds the key's
/// 8-byte words through a multiply-mix chain (four steps for a
/// 32-byte digest, a few ns), which is all a uniform key needs.
///
/// **This hasher is NOT DoS-resistant by itself** — the property
/// doing the work is that the keys are cryptographic digests, so an
/// attacker cannot steer collisions without breaking the underlying
/// hash. Never use it on attacker-chosen non-digest keys (IDs,
/// strings, addresses that aren't hash-derived).
///
/// ```rust
/// use primitives::digest_map::DigestMap;
/// let mut m: DigestMap<u64> = DigestMap::default();
/// m.insert(primitives::Hash::ZERO, 7);
/// assert_eq!(m.get(&primitives::Hash::ZERO), Some(&7));
/// ```
pub mod digest_map {
    use std::hash::{BuildHasherDefault, Hasher};

    /// `Hasher` for digest-typed keys: folds every written 8-byte
    /// word through a Fibonacci multiply (`0x9E37…` spreads entropy
    /// into the high bits hashbrown uses for SIMD tag matching, and
    /// the low bits it uses for bucket index). Every byte of every
    /// write is folded (not just a prefix), so the hasher stays
    /// correct for structured keys such as the executor's
    /// zero-padded `OccKey`s, not only for uniform digests.
    ///
    /// A 32-byte [`crate::Hash`] reaches this hasher as one `write`
    /// (its hand-written `Hash` impl skips the slice length prefix —
    /// hft-audit-2 S-6), i.e. four 8-byte loads folded by four
    /// multiplies, with no length-prefix step and no zero-pad copy.
    #[derive(Default)]
    pub struct DigestHasher(u64);

    impl Hasher for DigestHasher {
        #[inline]
        fn finish(&self) -> u64 {
            self.0
        }

        #[inline]
        fn write(&mut self, bytes: &[u8]) {
            // Whole words straight from the slice; only a ragged tail
            // (never present for 32-byte digests) pays the zero-pad copy.
            let (words, tail) = bytes.as_chunks::<8>();
            for word in words {
                self.mix(u64::from_le_bytes(*word));
            }
            if !tail.is_empty() {
                let mut b = [0u8; 8];
                b[..tail.len()].copy_from_slice(tail);
                self.mix(u64::from_le_bytes(b));
            }
        }

        #[inline]
        fn write_u64(&mut self, n: u64) {
            self.mix(n);
        }
    }

    impl DigestHasher {
        /// One fold step: add the word, then multiply by the Fibonacci
        /// hashing constant — a full-width odd multiplier, the standard
        /// avalanche step. `write_u64(n)` and `write(&n.to_le_bytes())`
        /// fold identically, so callers may use either form.
        #[inline]
        fn mix(&mut self, word: u64) {
            self.0 = self.0.wrapping_add(word).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
    }

    /// `BuildHasher` alias for [`DigestHasher`] — zero-sized,
    /// constructible without state.
    pub type DigestBuildHasher = BuildHasherDefault<DigestHasher>;

    /// A `HashMap` keyed by [`crate::Hash`] with [`DigestBuildHasher`]
    /// — drop-in replacement for `HashMap<Hash, V>` on digest-keyed
    /// tables.
    pub type DigestMap<V> = std::collections::HashMap<crate::Hash, V, DigestBuildHasher>;

    /// A `HashSet` of [`crate::Hash`] with [`DigestBuildHasher`].
    pub type DigestSet = std::collections::HashSet<crate::Hash, DigestBuildHasher>;
}

#[cfg(test)]
mod tests {
    use super::fixed::{self, FixedError, PRICE_ONE, Price, QTY_ONE, Qty};
    use super::{Address, Epoch, Hash, Height, View, WrongSliceLength};

    /// hft-audit-2 S-6: a `Hash` key reaches `DigestHasher` as one
    /// 32-byte write — exactly four fold steps, no length-prefix step —
    /// and every byte participates (a digest differing only in its last
    /// byte must not collide by construction).
    #[test]
    fn test_hash_key_is_one_write_of_all_32_bytes() {
        use super::digest_map::DigestHasher;
        use std::hash::{Hash as _, Hasher as _};

        let mut raw = [0u8; 32];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap().wrapping_mul(37).wrapping_add(11);
        }
        let h = Hash(raw);

        let mut via_impl = DigestHasher::default();
        h.hash(&mut via_impl);
        let mut via_write = DigestHasher::default();
        via_write.write(&raw);
        assert_eq!(via_impl.finish(), via_write.finish(), "Hash::hash must be one plain write");

        // Manual four-step fold — what the hasher documents.
        let mut acc = 0u64;
        for w in raw.as_chunks::<8>().0 {
            let word = u64::from_le_bytes(*w);
            acc = acc.wrapping_add(word).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        }
        assert_eq!(via_impl.finish(), acc, "exactly four fold steps, no length prefix");

        let mut tweaked = raw;
        tweaked[31] ^= 1;
        let mut other = DigestHasher::default();
        Hash(tweaked).hash(&mut other);
        assert_ne!(via_impl.finish(), other.finish(), "the last byte must be hashed too");

        // write_u64 and write(le bytes) fold identically.
        let mut a = DigestHasher::default();
        a.write_u64(0xDEAD_BEEF_0123_4567);
        let mut b = DigestHasher::default();
        b.write(&0xDEAD_BEEF_0123_4567u64.to_le_bytes());
        assert_eq!(a.finish(), b.finish());
    }

    /// Hash/Eq consistency for `Hash` under the default (`SipHash`)
    /// hasher: equal digests hash equal, and a `HashMap` keyed by
    /// `Hash` still finds every key.
    #[test]
    fn test_hash_impl_consistent_with_eq_in_std_map() {
        let mut m = std::collections::HashMap::new();
        for i in 0u8..=255 {
            let mut raw = [0u8; 32];
            raw[31] = i;
            raw[0] = i.wrapping_mul(3);
            m.insert(Hash(raw), i);
        }
        assert_eq!(m.len(), 256);
        for i in 0u8..=255 {
            let mut raw = [0u8; 32];
            raw[31] = i;
            raw[0] = i.wrapping_mul(3);
            assert_eq!(m.get(&Hash(raw)), Some(&i));
        }
    }

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

    /// hft-audit-2 S-8: the single-division implementation (u64 fast
    /// arm + u128 arm, remainder as `n − q·d`) equals the original
    /// two-division formula on boundary values and a fixed-seed
    /// pseudorandom sweep spanning both arms, including exact halves.
    #[test]
    fn test_mul_div_half_up_matches_two_division_reference() {
        fn reference(lhs: u64, rhs: u64, divisor: u64) -> Result<u64, FixedError> {
            let div = u128::from(divisor);
            if div == 0 {
                return Err(FixedError::DivisionByZero);
            }
            let prod = u128::from(lhs) * u128::from(rhs);
            let rounded = prod / div + u128::from((prod % div) * 2 >= div);
            u64::try_from(rounded).map_err(|_| FixedError::Overflow)
        }
        let edges =
            [0u64, 1, 2, 3, 5, 9_999, 10_000, 100_000_000, u64::MAX / 2, u64::MAX - 1, u64::MAX];
        for &a in &edges {
            for &b in &edges {
                for &d in &edges {
                    assert_eq!(fixed::mul_div_half_up(a, b, d), reference(a, b, d), "{a}*{b}/{d}");
                }
            }
        }
        let mut x = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for i in 0..20_000u32 {
            // Vary magnitudes so both the u64 and u128 arms are hit.
            let a = next() >> (next() % 64);
            let b = next() >> (next() % 64);
            let d = (next() >> (next() % 64)).max(u64::from(i % 3));
            assert_eq!(fixed::mul_div_half_up(a, b, d), reference(a, b, d), "{a}*{b}/{d}");
        }
        // Exact halves round up in both arms.
        assert_eq!(fixed::mul_div_half_up(5, 1, 10).unwrap(), 1);
        assert_eq!(fixed::mul_div_half_up(1 << 63, 3, 1 << 2).unwrap(), (3u64 << 61));
        let half_wide = u128::from(u64::MAX) * 2 - 1; // odd numerator > u64::MAX
        assert_eq!(fixed::qty_from_notional_div_price(half_wide, Price(2)).unwrap(), Qty(u64::MAX));
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

    /// Supervision: registered actors report their lifecycle through
    /// the registry — exit marks dead, panics mark panicked (via
    /// `mark_panicked`, the same entrypoint the hook and task
    /// monitors call), and only *critical* dead actors report
    /// unhealthy.
    #[test]
    fn supervision_tracks_lifecycle() {
        use super::supervision::*;
        // Unique names — the registry is process-global and tests
        // run in parallel threads.
        register("t-crit", true);
        register("t-aux", false);
        assert!(unhealthy_critical().is_empty());

        mark_exited("t-crit");
        assert_eq!(unhealthy_critical(), vec!["t-crit".to_string()]);

        // A dead non-critical actor degrades but does not fail health.
        mark_panicked("t-aux");
        assert_eq!(unhealthy_critical(), vec!["t-crit".to_string()]);
        assert!(
            actors().iter().any(|(n, c, s)| n == "t-aux"
                && !c
                && *s == super::supervision::ActorState::Panicked)
        );

        // Respawn revives the entry.
        register("t-crit", true);
        assert!(unhealthy_critical().is_empty());
    }

    /// `spawn_supervised` names the OS thread after the actor (the
    /// panic hook's thread→actor mapping) and marks the actor
    /// `Exited` when the body returns.
    #[test]
    fn supervision_spawn_marks_exit() {
        use super::supervision::*;
        let (probe_tx, probe_rx) = std::sync::mpsc::channel();
        let handle = spawn_supervised("t-spawn", false, move || {
            probe_tx
                .send(std::thread::current().name().unwrap_or("?").to_string())
                .expect("probe channel");
        })
        .expect("spawn");
        handle.join().expect("supervised thread");
        assert_eq!(probe_rx.recv().expect("name probe"), "t-spawn");
        assert!(
            actors()
                .iter()
                .any(|(n, _, s)| n == "t-spawn" && *s == super::supervision::ActorState::Exited)
        );
    }
}
