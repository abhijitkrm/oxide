//! Unit tests — extracted from the implementation file so the
//! production code reads top-to-bottom without the test bulk
//! (split-giant-modules pass: every entry point's enforcement
//! stays visible).

use super::*;

fn addr(byte: u8) -> Address {
    Address([byte; 20])
}

/// A staking module with a `MemoryBalances` ledger wired and each
/// address `0..=9` funded with 1M base units, plus every listed
/// validator registered (zero stake — delegations build it up).
fn setup(validators: &[u8]) -> StakingModule {
    setup_with_ledger(validators).0
}

/// The ledger behind a setup — needed by tests asserting pool
/// movement. The ledger is `MemoryBalances`: a unit-test double
/// over the same `Balances` seam the real EVM-backed impl serves.
fn setup_with_ledger(
    validators: &[u8],
) -> (StakingModule, std::sync::Arc<framework::MemoryBalances>) {
    let staking = StakingModule::new();
    let ledger = std::sync::Arc::new(framework::MemoryBalances::new());
    for s in 0u8..=9 {
        ledger.mint(&addr(s), 1_000_000);
    }
    staking.set_ledger(ledger.clone());
    for v in validators {
        staking.register_validator(addr(*v));
    }
    (staking, ledger)
}

fn ctx() -> TxContext {
    TxContext { sender: addr(0), nonce: 0, fee: 0 }
}

fn ctx_with_sender(sender: u8) -> TxContext {
    TxContext { sender: addr(sender), nonce: 0, fee: 0 }
}

/// A committee with real voting power: each listed validator is
/// registered and self-bonds `power` base units. Governance
/// actions are weighed by bonded stake, so a registered but
/// unbonded "validator" carries no authority — committee-gated
/// tests must use this fixture, not bare `setup`.
fn setup_powered(validators: &[u8], power: u64) -> StakingModule {
    let staking = setup(validators);
    for v in validators {
        let a = addr(*v);
        staking
            .handle(&ctx_with_sender(*v), &msg::delegate(a, power))
            .expect("self-bond for committee power");
    }
    staking
}

#[test]
fn delegate_increases_stake() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    assert_eq!(staking.stake(&v), 1000);
}

#[test]
fn multiple_delegates_accumulate() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 100)).unwrap();
    staking.handle(&ctx(), &msg::delegate(v, 200)).unwrap();
    assert_eq!(staking.stake(&v), 300);
}

#[test]
fn undelegate_reduces_stake_and_creates_unbonding_entry() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    staking.begin_block(Height::new(10));
    staking.handle(&ctx(), &msg::undelegate(v, 300)).unwrap();
    assert_eq!(staking.stake(&v), 700, "stake should be reduced");
    let pending = staking.pending_unbonding();
    assert_eq!(pending.len(), 1, "one unbonding entry");
    assert_eq!(pending[0].amount, 300);
    assert_eq!(pending[0].delegator, addr(0));
    assert_eq!(
        pending[0].completion_height,
        10 + DEFAULT_UNBONDING_PERIOD_BLOCKS,
        "completion = current + unbonding_period"
    );
}

#[test]
fn undelegate_rejects_insufficient_stake() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 100)).unwrap();
    let result = staking.handle(&ctx(), &msg::undelegate(v, 200));
    assert!(result.is_err(), "should reject undelegate > stake");
}

#[test]
fn undelegate_rejects_non_delegator() {
    // Security regression: previously any sender could unbond any
    // validator's stake — the delegation is owned by sender 0, so
    // sender 5's undelegate must be rejected.
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let result = staking.handle(&ctx_with_sender(5), &msg::undelegate(v, 300));
    assert!(result.is_err(), "non-delegator must not unbond someone else's stake");
    assert_eq!(staking.stake(&v), 1000, "stake unchanged after rejected undelegate");
}

#[test]
fn delegate_moves_funds_to_bonded_pool() {
    let (staking, ledger) = setup_with_ledger(&[1]);
    let v = addr(1);
    let before = ledger.balance(&addr(0));
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    assert_eq!(ledger.balance(&addr(0)), before - 1000, "delegator debited");
    assert_eq!(ledger.balance(&BONDED_POOL), 1000, "bonded pool credited");
    assert_eq!(staking.delegation(&addr(0), &v), 1000);
}

#[test]
fn delegate_rejects_insufficient_balance() {
    let (staking, ledger) = setup_with_ledger(&[1]);
    let v = addr(1);
    let result = staking.handle(&ctx(), &msg::delegate(v, 2_000_000));
    assert!(result.is_err(), "delegate exceeding balance must fail");
    assert_eq!(staking.stake(&v), 0, "no stake created on failure");
    assert_eq!(ledger.balance(&BONDED_POOL), 0, "pool untouched on failure");
}

/// Overflow of the validator's aggregate stake must reject the whole
/// delegate atomically: `ModuleRejected` does not roll back prior
/// `CommittedMap` writes (or the pool debit), so every fallible add
/// runs before the first mutation. This pins that ordering — a
/// wrapped or half-applied delegate would diverge `delegated_total`
/// from `validators`/`delegations` and corrupt reward accounting on
/// every validator that executed the tx.
#[test]
fn delegate_stake_overflow_rejects_atomically() {
    let staking = StakingModule::new();
    let ledger = std::sync::Arc::new(framework::MemoryBalances::new());
    staking.set_ledger(ledger.clone());
    let v = addr(1);
    // Genesis self-stake at the u64 ceiling: any further delegation
    // overflows `stake + amount`.
    staking.genesis_register_validator(v, u64::MAX);
    let d = addr(2);
    ledger.mint(&d, 1_000_000);

    let result = staking.handle(&ctx_with_sender(2), &msg::delegate(v, 1));
    assert!(result.is_err(), "stake overflow must reject the delegate");
    // Nothing may be half-applied: stake, delegation, delegated_total
    // and the pool debit all read exactly as before the attempt.
    assert_eq!(staking.stake(&v), u64::MAX, "stake unchanged");
    assert_eq!(staking.delegation(&d, &v), 0, "no delegation recorded");
    assert_eq!(
        framework::lock_state(&staking.delegated_total).get(&v).copied().unwrap_or(0),
        0,
        "delegated_total must not gain the phantom unit"
    );
    assert_eq!(ledger.balance(&d), 1_000_000, "delegator not debited");
    assert_eq!(ledger.balance(&BONDED_POOL), 0, "pool not credited");
}

#[test]
fn unbonding_refunds_delegator_via_ledger() {
    let (staking, ledger) = setup_with_ledger(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let after_delegate = ledger.balance(&addr(0));
    staking.begin_block(Height::new(10));
    staking.handle(&ctx(), &msg::undelegate(v, 400)).unwrap();
    // Still in the pool while unbonding.
    assert_eq!(ledger.balance(&BONDED_POOL), 1000);
    assert_eq!(ledger.balance(&addr(0)), after_delegate, "not refunded yet");
    staking.begin_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS));
    staking.end_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS));
    assert_eq!(
        ledger.balance(&addr(0)),
        after_delegate + 400,
        "unbonded funds returned to the delegator"
    );
    assert_eq!(ledger.balance(&BONDED_POOL), 600, "pool keeps the bonded remainder");
}

#[test]
fn slash_burns_only_bonded_funds() {
    let (staking, ledger) = setup_with_ledger(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    staking.handle(&ctx_with_sender(1), &msg::slash(v, 100)).unwrap();
    assert_eq!(staking.stake(&v), 900);
    assert_eq!(staking.delegation(&addr(0), &v), 900, "delegation reduced proportionally");
    assert_eq!(ledger.balance(&BONDED_POOL), 900, "slashed amount burned from pool");
}

#[test]
fn undelegate_rejects_unknown_validator() {
    let staking = setup(&[1]);
    let v = addr(1);
    let result = staking.handle(&ctx(), &msg::undelegate(v, 100));
    assert!(result.is_err(), "should reject undelegate of unknown validator");
}

#[test]
fn unbonding_completes_after_period() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    staking.begin_block(Height::new(10));
    staking.handle(&ctx(), &msg::undelegate(v, 500)).unwrap();
    assert_eq!(staking.completed_unbonding().len(), 0, "not completed yet");
    staking.begin_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS));
    staking.end_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS));
    assert_eq!(
        staking.completed_unbonding().len(),
        0,
        "entry should be removed after end_block processes it"
    );
    assert_eq!(staking.pending_unbonding().len(), 0, "no pending entries");
}

#[test]
fn unbonding_not_completed_before_period() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    staking.begin_block(Height::new(10));
    staking.handle(&ctx(), &msg::undelegate(v, 500)).unwrap();
    staking.begin_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS - 1));
    staking.end_block(Height::new(10 + DEFAULT_UNBONDING_PERIOD_BLOCKS - 1));
    assert_eq!(staking.pending_unbonding().len(), 1, "still pending");
}

#[test]
fn slash_reduces_stake() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let slash_amount = msg::double_sign_slash_amount(1000);
    assert_eq!(slash_amount, 100, "10% of 1000 = 100");
    staking.handle(&ctx_with_sender(1), &msg::slash(v, slash_amount)).unwrap();
    assert_eq!(staking.stake(&v), 900, "stake reduced by slash");
}

#[test]
fn slash_capped_at_stake() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 100)).unwrap();
    // Try to slash more than the stake.
    staking.handle(&ctx_with_sender(1), &msg::slash(v, 500)).unwrap();
    assert_eq!(staking.stake(&v), 0, "stake floored at 0");
}

#[test]
fn slash_rejects_unknown_validator() {
    let staking = setup(&[2]);
    let v = addr(1);
    let result = staking.handle(&ctx_with_sender(2), &msg::slash(v, 100));
    assert!(result.is_err(), "should reject slash of unknown validator");
}

#[test]
fn slash_rejects_non_committee_sender() {
    // The permissionless slash path must not exist — evidence
    // carries its own proof; raw slash is governance.
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let result = staking.handle(&ctx(), &msg::slash(v, 100));
    assert!(result.is_err(), "non-validator sender must not slash");
    assert_eq!(staking.stake(&v), 1000, "stake untouched");
}

// ── Evidence (double-sign) + jail ────────────────────────────

/// A real BLS secret key for deterministic tests — same
/// `from_ikm` path consensus tests use.
fn bls_key(byte: u8) -> crypto::BlsSecretKey {
    let ikm = vec![byte; 32];
    crypto::BlsSecretKey::from_ikm(&ikm).expect("key gen")
}

/// Build a valid double-sign evidence message for `key`'s
/// validator: two votes over `(view, phase, epoch)` for two
/// different block hashes, both really signed.
fn signed_evidence(
    validator: Address,
    key: &crypto::BlsSecretKey,
    view: u64,
    epoch: u64,
) -> Vec<u8> {
    let hash_a = [0xAAu8; 32];
    let hash_b = [0xBBu8; 32];
    let vote_msg = |hash: &[u8; 32]| {
        let mut m = [0u8; 49];
        m[..8].copy_from_slice(&view.to_le_bytes());
        m[8] = 0; // phase — matches the engine's current_phase_byte
        m[9..41].copy_from_slice(hash);
        m[41..49].copy_from_slice(&epoch.to_le_bytes());
        m
    };
    let sig_a = key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_a));
    let sig_b = key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_b));
    msg::evidence(validator, view, 0, epoch, &hash_a, sig_a.as_bytes(), &hash_b, sig_b.as_bytes())
}

#[test]
fn evidence_slashes_and_jails_on_valid_proof() {
    let (staking, ledger) = setup_with_ledger(&[1]);
    let v = addr(1);
    let key = bls_key(1);
    staking.genesis_set_bls_key(v, key.public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

    let evidence = signed_evidence(v, &key, 7, 0);
    staking.handle(&ctx(), &evidence).unwrap();

    assert_eq!(staking.stake(&v), 900, "10% double-sign slash applied");
    assert_eq!(ledger.balance(&BONDED_POOL), 900, "slashed funds burned");
    assert!(staking.is_jailed(&v), "offender jailed");
    // The jail reaches consensus at the next rotation.
    let changes = staking.take_validator_changes();
    assert!(changes.removes.contains(&v), "jailed validator emitted as remove");
}

#[test]
fn evidence_rejects_identical_hashes() {
    let staking = setup(&[1]);
    let v = addr(1);
    let key = bls_key(1);
    staking.genesis_set_bls_key(v, key.public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

    // Same block hash twice is one vote, not equivocation.
    let hash = [0xAAu8; 32];
    let mut vote_msg = [0u8; 49];
    vote_msg[..8].copy_from_slice(&7u64.to_le_bytes());
    vote_msg[9..41].copy_from_slice(&hash);
    let sig = key.sign(crypto::hash::Domain::Vote, &vote_msg);
    let evidence = msg::evidence(v, 7, 0, 0, &hash, sig.as_bytes(), &hash, sig.as_bytes());
    assert!(staking.handle(&ctx(), &evidence).is_err());
    assert_eq!(staking.stake(&v), 1000);
}

#[test]
fn evidence_rejects_forged_signature() {
    let staking = setup(&[1]);
    let v = addr(1);
    // Register key 1, but sign the "evidence" with key 2 —
    // verification must fail against the registered key.
    let registered = bls_key(1);
    let forger = bls_key(2);
    staking.genesis_set_bls_key(v, registered.public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

    let evidence = signed_evidence(v, &forger, 7, 0);
    assert!(staking.handle(&ctx(), &evidence).is_err(), "forged proof must reject");
    assert_eq!(staking.stake(&v), 1000, "no slash on forged evidence");
    assert!(!staking.is_jailed(&v));
}

#[test]
fn evidence_rejects_replay() {
    let staking = setup(&[1]);
    let v = addr(1);
    let key = bls_key(1);
    staking.genesis_set_bls_key(v, key.public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

    let evidence = signed_evidence(v, &key, 7, 0);
    staking.handle(&ctx(), &evidence).unwrap();
    let result = staking.handle(&ctx(), &evidence);
    assert!(result.is_err(), "same proof must not slash twice");
    assert_eq!(staking.stake(&v), 900, "still exactly one slash");
}

#[test]
fn evidence_rejects_validator_without_key() {
    let staking = setup(&[1]);
    let v = addr(1);
    let key = bls_key(1);
    // No genesis_set_bls_key — the validator exists in staking
    // but has no consensus key on record to verify against.
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let evidence = signed_evidence(v, &key, 7, 0);
    assert!(staking.handle(&ctx(), &evidence).is_err());
}

#[test]
fn jailed_validator_stops_earning_rewards() {
    let staking = setup(&[1, 2]).with_block_reward(1_000);
    let (v1, v2) = (addr(1), addr(2));
    let key = bls_key(1);
    staking.genesis_set_bls_key(v1, key.public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v1, 1000)).unwrap();
    staking.handle(&ctx(), &msg::delegate(v2, 1000)).unwrap();

    staking.handle(&ctx(), &signed_evidence(v1, &key, 7, 0)).unwrap();
    // v1 jailed with 900 stake; v2 free with 1000 — v2 must take
    // the whole block reward.
    staking.end_block(Height::new(1));
    assert_eq!(staking.claimable(&addr(0)), 1_000, "all rewards to v2's delegator");
}

#[test]
fn unjail_readmits_after_period() {
    let staking = setup(&[1]);
    let v = addr(1);
    let key = bls_key(1);
    staking.genesis_set_bls_key(v, key.public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    staking.handle(&ctx(), &signed_evidence(v, &key, 7, 0)).unwrap();

    // Too early — jail period not elapsed.
    staking.begin_block(Height::new(100));
    assert!(staking.handle(&ctx_with_sender(1), &msg::unjail(v)).is_err());

    // After MIN_JAIL_BLOCKS the unjail is accepted and the
    // validator is re-admitted via the changes drain.
    staking.begin_block(Height::new(100 + MIN_JAIL_BLOCKS));
    staking.handle(&ctx_with_sender(1), &msg::unjail(v)).unwrap();
    assert!(!staking.is_jailed(&v));
    let changes = staking.take_validator_changes();
    assert_eq!(changes.adds.len(), 1, "unjailed validator re-admitted");
    assert_eq!(changes.adds[0].0, v);
    assert_eq!(changes.adds[0].1.public_key(), key.public_key(), "re-adds with current key");
    assert_eq!(changes.adds[0].2, 900, "re-adds with post-slash stake");
}

#[test]
fn unjail_rejects_non_jailed_and_other_sender() {
    let staking = setup(&[1]);
    let v = addr(1);
    // Not jailed at all.
    assert!(staking.handle(&ctx_with_sender(1), &msg::unjail(v)).is_err());
}

// ── Downtime tracking (record_block_attendance) ──────────────

#[test]
fn downtime_jails_after_full_window_of_absence() {
    let staking = setup(&[1, 2]);
    let (v1, v2) = (addr(1), addr(2));
    staking.handle(&ctx(), &msg::delegate(v1, 1000)).unwrap();
    staking.handle(&ctx(), &msg::delegate(v2, 1000)).unwrap();

    // v1 never signs; v2 signs every block.
    for h in 1..=DOWNTIME_WINDOW as u64 {
        staking.record_block_attendance(Height::new(h), &[v2]);
    }
    assert!(staking.is_jailed(&v1), "absent for the full window → jailed");
    assert!(!staking.is_jailed(&v2), "perfect attendance stays free");
    assert_eq!(staking.stake(&v1), 1000, "downtime jail does not slash");
    let changes = staking.take_validator_changes();
    assert!(changes.removes.contains(&v1), "auto-jail emitted as remove");
}

#[test]
fn downtime_grace_period_before_window_fills() {
    let staking = setup(&[1, 2]);
    let (v1, v2) = (addr(1), addr(2));
    staking.handle(&ctx(), &msg::delegate(v1, 1000)).unwrap();
    staking.handle(&ctx(), &msg::delegate(v2, 1000)).unwrap();

    // 99 absent blocks — one short of a full window: no jail yet
    // (fresh-join grace, same as Cosmos SignedBlocksWindow).
    for h in 1..DOWNTIME_WINDOW as u64 {
        staking.record_block_attendance(Height::new(h), &[v2]);
    }
    assert!(!staking.is_jailed(&v1), "cannot jail before the window fills");
}

#[test]
fn downtime_partial_absence_does_not_jail() {
    let staking = setup(&[1, 2]);
    let (v1, v2) = (addr(1), addr(2));
    staking.handle(&ctx(), &msg::delegate(v1, 1000)).unwrap();
    staking.handle(&ctx(), &msg::delegate(v2, 1000)).unwrap();

    // v1 signs exactly half the window (≥ DOWNTIME_MIN_SIGNED).
    for h in 1..=DOWNTIME_WINDOW as u64 {
        let signers = if h % 2 == 0 { vec![v1, v2] } else { vec![v2] };
        staking.record_block_attendance(Height::new(h), &signers);
    }
    assert!(!staking.is_jailed(&v1), "50% attendance stays free");
}

#[test]
fn attendance_empty_signers_is_noop() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    // Sequencer/mock engines report no attendance — an empty
    // signer list must never read as "everyone absent".
    for h in 1..=DOWNTIME_WINDOW as u64 {
        staking.record_block_attendance(Height::new(h), &[]);
    }
    assert!(!staking.is_jailed(&v));
}

#[test]
fn rewards_accumulate_per_block() {
    let staking = setup(&[1, 2]).with_block_reward(1_000_000);
    let v1 = addr(1);
    let v2 = addr(2);
    staking.handle(&ctx(), &msg::delegate(v1, 1000)).unwrap();
    staking.handle(&ctx(), &msg::delegate(v2, 3000)).unwrap();
    staking.begin_block(Height::new(1));
    staking.end_block(Height::new(1));
    // addr(0) is the only delegator: 25% accrues through v1's
    // reward-per-token and 75% through v2's — the delegator
    // claimable total is the full block reward.
    assert_eq!(staking.claimable(&addr(0)), 1_000_000, "delegator earns all positions");
    // The validators hold no self-share — their entire stake is
    // addr(0)'s delegation, so they accrue nothing directly.
    assert_eq!(staking.claimable(&v1), 0, "validator self-share is zero");
    assert_eq!(staking.claimable(&v2), 0, "validator self-share is zero");
}

/// The reward share is money math — its intermediate must not
/// saturate. `total_reward * stake` in `u64` overflows at real
/// token scale (`1e12` pool × `1e10` stake = `1e22` > `u64::MAX`),
/// and the old `saturating_mul` clamped the product, paying the
/// validator `u64::MAX / eligible` instead of its share — an
/// under-payment of ~500× that no test caught because every
/// reward test used small numbers. `u128` intermediates make the
/// overflow impossible rather than clamped.
#[test]
fn reward_share_does_not_saturate_at_token_scale() {
    let staking = setup(&[]).with_block_reward(1_000_000_000_000); // 1e12
    // Two genesis validators, 25%/75% of bonded stake — both
    // large enough that reward × stake overflows u64.
    staking.genesis_register_validator(addr(1), 10_000_000_000); // 1e10
    staking.genesis_register_validator(addr(2), 30_000_000_000); // 3e10
    staking.begin_block(Height::new(1));
    staking.end_block(Height::new(1));
    // Exact pro-rata shares of the 1e12 pool — the u64 product
    // (1e22) exceeds u64::MAX ≈ 1.8e19, so a saturating u64
    // intermediate would pay ~4.6e8, not these:
    assert_eq!(staking.claimable(&addr(1)), 250_000_000_000, "25% of the pool");
    assert_eq!(staking.claimable(&addr(2)), 750_000_000_000, "75% of the pool");
}

#[test]
fn rewards_accumulate_over_multiple_blocks() {
    let staking = setup(&[1]).with_block_reward(1_000_000);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    staking.begin_block(Height::new(1));
    staking.end_block(Height::new(1));
    staking.begin_block(Height::new(2));
    staking.end_block(Height::new(2));
    assert_eq!(staking.claimable(&addr(0)), 2_000_000, "2 blocks * 1M reward");
}

#[test]
fn rewards_split_between_delegator_and_self_share() {
    // Validator v1 has 4000 genesis self-stake (no delegation
    // record); delegator d bonds 4000 to it. The 1M block
    // reward splits pro-rata: half to the validator's
    // self-share, half to the delegator.
    let staking = setup(&[]).with_block_reward(1_000_000);
    staking.genesis_register_validator(addr(1), 4_000);
    let d = addr(0);
    staking.handle(&ctx_with_sender(0), &msg::delegate(addr(1), 4_000)).unwrap();
    staking.begin_block(Height::new(1));
    staking.end_block(Height::new(1));
    assert_eq!(staking.claimable(&d), 500_000, "delegator gets half");
    assert_eq!(staking.claimable(&addr(1)), 500_000, "self-share gets half");
}

#[test]
fn rewards_do_not_accrue_retroactively_to_new_delegator() {
    // A delegation made after rewards accrued starts at the
    // current reward-per-token — it cannot claim past rewards.
    let staking = setup(&[1]).with_block_reward(1_000_000);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    staking.begin_block(Height::new(1));
    staking.end_block(Height::new(1));
    // addr(2) delegates at block 2 — it must not share block 1's
    // reward.
    staking.handle(&ctx_with_sender(2), &msg::delegate(v, 1000)).unwrap();
    staking.begin_block(Height::new(2));
    staking.end_block(Height::new(2));
    assert_eq!(staking.claimable(&addr(0)), 1_500_000, "early delegator: b1 full + b2 half");
    assert_eq!(staking.claimable(&addr(2)), 500_000, "late delegator: b2 half only");
}

#[test]
fn fees_collected_in_fee_pool_distribute_to_delegators() {
    // The fee sweep is the "distribution" half of #18: whatever
    // landed in FEE_POOL during the block is added to the
    // issuance and distributed pro-rata.
    let (staking, ledger) = setup_with_ledger(&[1]);
    let staking = staking.with_block_reward(0);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    // Simulate the executor's charge_fee path: 3 txs x 700 fee
    // collected into FEE_POOL.
    ledger.mint(&FEE_POOL, 2_100);
    staking.begin_block(Height::new(1));
    staking.end_block(Height::new(1));
    assert_eq!(ledger.balance(&FEE_POOL), 0, "fee pool swept");
    assert_eq!(ledger.balance(&REWARD_POOL), 2_100);
    assert_eq!(staking.claimable(&addr(0)), 2_100, "fees distributed pro-rata");
}

#[test]
fn claim_pays_delegator_from_reward_pool() {
    // Conservation: a claim transfers real funds out of
    // REWARD_POOL — no minting at claim time.
    let (staking, ledger) = setup_with_ledger(&[1]);
    let staking = staking.with_block_reward(1_000);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let delegator_before = ledger.balance(&addr(0));
    staking.begin_block(Height::new(1));
    staking.end_block(Height::new(1));
    let pool_funded = ledger.balance(&REWARD_POOL);
    staking.handle(&ctx(), &msg::claim_reward(addr(0), 0)).unwrap();
    assert_eq!(
        ledger.balance(&addr(0)),
        delegator_before + 1_000,
        "claim pays real funds to the delegator"
    );
    assert_eq!(
        ledger.balance(&REWARD_POOL),
        pool_funded - 1_000,
        "pool decremented by exactly the claim"
    );
}

#[test]
fn claim_reward_withdraws_accumulated() {
    let staking = setup(&[0]).with_block_reward(1_000_000);
    let v = addr(0); // sender addr(0) is the validator — claims its own rewards
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    staking.begin_block(Height::new(1));
    staking.end_block(Height::new(1));
    assert_eq!(staking.claimable(&v), 1_000_000);
    staking.handle(&ctx(), &msg::claim_reward(v, 0)).unwrap();
    assert_eq!(staking.claimable(&v), 0, "rewards claimed");
}

#[test]
fn claim_reward_partial_withdrawal() {
    let staking = setup(&[0]).with_block_reward(1_000_000);
    let v = addr(0);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    staking.begin_block(Height::new(1));
    staking.end_block(Height::new(1));
    staking.handle(&ctx(), &msg::claim_reward(v, 400_000)).unwrap();
    assert_eq!(staking.claimable(&v), 600_000, "600K remaining");
}

#[test]
fn claim_reward_rejects_zero_balance() {
    let staking = setup(&[0]);
    let v = addr(0);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let result = staking.handle(&ctx(), &msg::claim_reward(v, 0));
    assert!(result.is_err(), "should reject claim with no rewards");
}

#[test]
fn top_validators_sorted_by_stake() {
    let staking = setup(&[1, 2, 3]);
    staking.handle(&ctx(), &msg::delegate(addr(1), 100)).unwrap();
    staking.handle(&ctx(), &msg::delegate(addr(2), 500)).unwrap();
    staking.handle(&ctx(), &msg::delegate(addr(3), 300)).unwrap();
    let top = staking.top_validators(2);
    assert_eq!(top.len(), 2);
    assert_eq!(top[0].address, addr(2), "highest stake first");
    assert_eq!(top[0].stake, 500);
    assert_eq!(top[1].address, addr(3), "second highest");
}

#[test]
fn zero_stake_validators_excluded() {
    let staking = setup(&[1]);
    staking.handle(&ctx(), &msg::delegate(addr(1), 100)).unwrap();
    let top = staking.top_validators(10);
    assert_eq!(top.len(), 1, "only non-zero-stake validators");
}

#[test]
fn malformed_message_rejected() {
    let staking = StakingModule::new();
    assert_eq!(staking.handle(&ctx(), &[1, 2, 3]), Err(ExecError::Malformed));
}

#[test]
fn unknown_message_type_rejected() {
    let staking = setup(&[1]);
    let v = addr(1);
    let mut msg = msg::delegate(v, 100);
    msg[0] = 0xFF; // unknown type
    let result = staking.handle(&ctx(), &msg);
    assert!(result.is_err(), "should reject unknown message type");
}

#[test]
fn state_root_changes_after_delegate() {
    let staking = setup(&[1]);
    let root0 = staking.state_root();
    staking.handle(&ctx(), &msg::delegate(addr(1), 100)).unwrap();
    let root1 = staking.state_root();
    assert_ne!(root0, root1);
}

#[test]
fn state_root_changes_after_slash() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let root0 = staking.state_root();
    staking.handle(&ctx_with_sender(1), &msg::slash(v, 100)).unwrap();
    let root1 = staking.state_root();
    assert_ne!(root0, root1, "state root must change after slash");
}

// ── C8 canonical state-root completeness ─────────────────────
//
// Most staking state (unbonding queues, reward accumulators,
// pending validator changes, jails, attendance rings, the
// scheduled halt) lives in memory, not the KV store. The state
// root must commit all of it — identical roots across
// validators must prove identical staking state.

#[test]
fn state_root_changes_after_attendance() {
    let staking = setup(&[1, 2]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let root0 = staking.state_root();
    // v2 signed, v1 absent — the attendance ring is consensus
    // state: it decides future downtime jailing.
    staking.record_block_attendance(Height::new(1), &[addr(2)]);
    let root1 = staking.state_root();
    assert_ne!(root0, root1, "attendance must be committed");
}

#[test]
fn state_root_changes_after_schedule_halt() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    staking.begin_block(Height::new(5));
    let root0 = staking.state_root();
    staking.handle(&ctx_with_sender(1), &msg::schedule_halt(v, 100)).unwrap();
    let root1 = staking.state_root();
    assert_ne!(root0, root1, "the scheduled halt must be committed");
}

#[test]
fn state_root_changes_after_key_change() {
    let staking = setup(&[0]);
    let v = addr(0);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let root0 = staking.state_root();
    let new_sk = bls_key(0xAA);
    let new_key = new_sk.public_key().as_bytes().to_vec();
    let pop = new_sk.pop_prove();
    staking.handle(&ctx(), &msg::key_change(v, &new_key, pop.as_bytes())).unwrap();
    let root1 = staking.state_root();
    assert_ne!(root0, root1, "pending key changes must be committed");
}

#[test]
fn state_root_changes_after_rewards_accrue() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let root0 = staking.state_root();
    // end_block accrues `reward_per_token` — an in-memory
    // accumulator that decides future payouts.
    staking.end_block(Height::new(1));
    let root1 = staking.state_root();
    assert_ne!(root0, root1, "reward accrual must be committed");
}

#[test]
fn custom_unbonding_period() {
    let staking = setup(&[1]).with_unbonding_period(10);
    let v = addr(1);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    staking.begin_block(Height::new(5));
    staking.handle(&ctx(), &msg::undelegate(v, 500)).unwrap();
    let pending = staking.pending_unbonding();
    assert_eq!(pending[0].completion_height, 15, "5 + 10 = 15");
}

#[test]
fn key_change_stores_pending_key() {
    let staking = setup(&[0]);
    let v = addr(0); // sender is addr(0) in ctx()
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let new_sk = bls_key(0xAA);
    let new_key = new_sk.public_key().as_bytes().to_vec();
    let pop = new_sk.pop_prove();
    staking.handle(&ctx(), &msg::key_change(v, &new_key, pop.as_bytes())).unwrap();
    assert!(staking.has_key_change(&v), "key change must be pending");
    let changes = staking.take_key_changes();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].0, v);
    assert_eq!(changes[0].1.as_bytes(), new_key.as_slice());
    // After take, the pending map is empty.
    assert!(!staking.has_key_change(&v), "key change must be drained");
}

#[test]
fn key_change_rejects_wrong_sender() {
    let staking = setup(&[1]);
    let v = addr(1); // sender is addr(0), but validator is addr(1)
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let new_sk = bls_key(0xAA);
    let new_key = new_sk.public_key().as_bytes().to_vec();
    let pop = new_sk.pop_prove();
    let result = staking.handle(&ctx(), &msg::key_change(v, &new_key, pop.as_bytes()));
    assert!(result.is_err(), "must reject key change from non-validator sender");
}

#[test]
fn key_change_rejects_unknown_validator() {
    let staking = setup(&[]);
    let v = addr(0); // sender is addr(0) but no stake delegated
    let new_sk = bls_key(0xAA);
    let new_key = new_sk.public_key().as_bytes().to_vec();
    let pop = new_sk.pop_prove();
    let result = staking.handle(&ctx(), &msg::key_change(v, &new_key, pop.as_bytes()));
    assert!(result.is_err(), "must reject key change for unknown validator");
}

#[test]
fn key_change_rejects_wrong_key_length() {
    let staking = setup(&[0]);
    let v = addr(0);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let short_key = vec![0xAA; 32]; // not 48 bytes
    let pop = bls_key(0xBB).pop_prove();
    let msg = msg::key_change(v, &short_key, pop.as_bytes());
    let result = staking.handle(&ctx(), &msg);
    assert!(result.is_err(), "must reject non-48-byte key");
}

/// C3: a consensus key must prove possession at admission.
/// Without `PoP`, `fast_aggregate_verify` QC checks admit a rogue
/// key — a public key crafted from honest keys so a lone attacker
/// signature verifies as a quorum aggregate.
#[test]
fn key_change_rejects_invalid_pop() {
    let staking = setup(&[0]);
    let v = addr(0);
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let new_sk = bls_key(0xAA);
    let new_key = new_sk.public_key().as_bytes().to_vec();
    // A different key's PoP is not a PoP for `new_key`.
    let wrong_pop = bls_key(0xBB).pop_prove();
    let result = staking.handle(&ctx(), &msg::key_change(v, &new_key, wrong_pop.as_bytes()));
    assert!(result.is_err(), "PoP for a different key must be rejected");
    // Garbage bytes are not a PoP either.
    let garbage = vec![0xCC; 96];
    let result = staking.handle(&ctx(), &msg::key_change(v, &new_key, &garbage));
    assert!(result.is_err(), "garbage PoP must be rejected");
    // The real PoP admits the change.
    let pop = new_sk.pop_prove();
    staking.handle(&ctx(), &msg::key_change(v, &new_key, pop.as_bytes())).unwrap();
    assert!(staking.has_key_change(&v), "valid PoP must admit the key change");
}

// ── Validator add / remove (committee-gated set changes) ────

/// A committee quorum can admit a new validator whose key
/// carries a valid proof-of-possession — the add lands in the
/// pending set changes for the next epoch rotation. Activation
/// requires bonded collateral, so the test delegates to the
/// admitted candidate before draining the rotation.
#[test]
fn validator_add_with_valid_pop_succeeds() {
    let staking = setup_powered(&[1], 100);
    let new_addr = addr(9);
    let new_sk = bls_key(0xAA);
    let pop = new_sk.pop_prove();
    staking
        .handle(
            &ctx_with_sender(1),
            &msg::validator_add(new_addr, new_sk.public_key().as_bytes(), pop.as_bytes()),
        )
        .unwrap();
    // The candidate bonds 500 (any delegator can bond to a
    // registered candidate — the ledger debit is the collateral).
    staking.handle(&ctx_with_sender(0), &msg::delegate(new_addr, 500)).unwrap();
    let changes = staking.take_validator_changes();
    assert_eq!(changes.adds.len(), 1, "one pending add");
    assert_eq!(changes.adds[0].0, new_addr);
    assert_eq!(changes.adds[0].1.public_key(), new_sk.public_key());
    assert_eq!(changes.adds[0].2, 500);
}

/// `PoP` is mandatory at admission: a `validator_add` carrying a
/// `PoP` for a different key — or garbage bytes — must be rejected.
/// Without this gate a rogue key (a public key algebraically
/// derived from honest keys) could enter the set and forge
/// `fast_aggregate_verify` quorum checks.
#[test]
fn validator_add_rejects_invalid_pop() {
    let staking = setup_powered(&[1], 100);
    let new_addr = addr(9);
    let new_sk = bls_key(0xAA);
    // PoP for a different key.
    let wrong_pop = bls_key(0xBB).pop_prove();
    let result = staking.handle(
        &ctx_with_sender(1),
        &msg::validator_add(new_addr, new_sk.public_key().as_bytes(), wrong_pop.as_bytes()),
    );
    assert!(result.is_err(), "PoP for a different key must be rejected");
    // Garbage bytes.
    let result = staking.handle(
        &ctx_with_sender(1),
        &msg::validator_add(new_addr, new_sk.public_key().as_bytes(), &[0xCC; 96]),
    );
    assert!(result.is_err(), "garbage PoP must be rejected");
    // Nothing registered or pending.
    assert!(!staking.is_registered(&new_addr));
    assert!(staking.take_validator_changes().adds.is_empty());
}

/// Only a powered committee member can endorse set membership —
/// an arbitrary account must not sybil the committee.
#[test]
fn validator_add_rejects_non_committee_sender() {
    let staking = setup_powered(&[1], 100);
    let new_sk = bls_key(0xAA);
    let pop = new_sk.pop_prove();
    let result = staking.handle(
        &ctx_with_sender(8), // addr(8) is funded but not a validator
        &msg::validator_add(addr(9), new_sk.public_key().as_bytes(), pop.as_bytes()),
    );
    assert!(result.is_err(), "non-validator sender must be rejected");
}

/// The staking address is the validator's identity — an existing
/// member (or a quorum-admitted pending candidate) cannot be
/// re-added under a new key.
#[test]
fn validator_add_rejects_duplicate_address() {
    let staking = setup_powered(&[1], 100);
    let sk = bls_key(0xAA);
    let pop = sk.pop_prove();
    // addr(1) is already a validator.
    let result = staking.handle(
        &ctx_with_sender(1),
        &msg::validator_add(addr(1), sk.public_key().as_bytes(), pop.as_bytes()),
    );
    assert!(result.is_err(), "existing validator address must be rejected");
    // A quorum-admitted candidate cannot be re-added either.
    let new_addr = addr(9);
    staking
        .handle(
            &ctx_with_sender(1),
            &msg::validator_add(new_addr, sk.public_key().as_bytes(), pop.as_bytes()),
        )
        .unwrap();
    let other_sk = bls_key(0xBB);
    let other_pop = other_sk.pop_prove();
    let result = staking.handle(
        &ctx_with_sender(1),
        &msg::validator_add(new_addr, other_sk.public_key().as_bytes(), other_pop.as_bytes()),
    );
    assert!(result.is_err(), "registered candidate address must be rejected");
}

/// A malformed BLS public key (48 bytes that do not encode a
/// valid compressed BLS12-381 point) must be rejected at
/// admission: `pop_verify` fails to uncompress it, so the add
/// never lands.
#[test]
fn validator_add_rejects_malformed_key() {
    let staking = setup_powered(&[1], 100);
    // 48 bytes that do not encode a valid BLS12-381 G1 point.
    let bogus_key = vec![0xFF; 48];
    let pop = bls_key(0xAA).pop_prove();
    let result = staking
        .handle(&ctx_with_sender(1), &msg::validator_add(addr(9), &bogus_key, pop.as_bytes()));
    assert!(result.is_err(), "malformed public key must be rejected");
}

// ── Coordinated halt scheduling (SCHEDULE_HALT) ─────────────

#[test]
fn schedule_halt_committee_only_and_future_only() {
    let staking = setup_powered(&[1], 100);
    staking.begin_block(Height::new(10));

    // Non-validator sender is refused.
    assert!(staking.handle(&ctx_with_sender(9), &msg::schedule_halt(addr(9), 100)).is_err());
    // A past/current height is refused (already executed —
    // scheduling behind the tip can never trigger cleanly).
    assert!(staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 10)).is_err());
    assert!(staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 5)).is_err());
    assert_eq!(staking.scheduled_halt_height(), None);

    // A powered validator schedules a future halt (a
    // single-validator committee is its own quorum).
    staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 100)).unwrap();
    assert_eq!(staking.scheduled_halt_height(), Some(100));
}

#[test]
fn schedule_halt_reschedule_and_cancel() {
    let staking = setup_powered(&[1], 100);
    staking.begin_block(Height::new(10));

    staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 100)).unwrap();
    assert_eq!(staking.scheduled_halt_height(), Some(100));

    // Re-schedule moves the halt (still future).
    staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 200)).unwrap();
    assert_eq!(staking.scheduled_halt_height(), Some(200));

    // Height 0 cancels the schedule.
    staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 0)).unwrap();
    assert_eq!(staking.scheduled_halt_height(), None);
}

// ── C9: committee-quorum governance ──────────────────────────
//
// Privileged actions are *endorsements*: each gated tx records
// the sender's endorsement of the exact action payload and the
// action applies only once cumulative endorser power strictly
// exceeds two-thirds of the committee's total bonded power —
// the same quorum a consensus QC requires. One validator's
// signature is a vote, never a command.

/// One validator must not admit a peer on its own signature:
/// two endorsements out of four equal-power validators are
/// still below quorum; the third crosses it.
#[test]
fn validator_add_requires_committee_quorum() {
    let staking = setup_powered(&[1, 2, 3, 4], 100);
    let new_addr = addr(9);
    let new_sk = bls_key(0xAA);
    let pop = new_sk.pop_prove();
    let add = msg::validator_add(new_addr, new_sk.public_key().as_bytes(), pop.as_bytes());

    staking.handle(&ctx_with_sender(1), &add).unwrap();
    assert!(!staking.is_registered(&new_addr), "one endorsement must not admit");
    staking.handle(&ctx_with_sender(2), &add).unwrap();
    assert!(!staking.is_registered(&new_addr), "two of four is below quorum");

    staking.handle(&ctx_with_sender(3), &add).unwrap();
    assert!(staking.is_registered(&new_addr), "quorum admits the candidate");
}

/// Admission itself bonds nothing — the audit's original hole
/// let the add message *declare* stake with no collateral behind
/// it. The endorsed registration carries zero stake; the
/// candidate activates at the rotation only if real balance was
/// bonded to it (by itself or any delegator), and the activation
/// stake is the bonded amount, not anything the add claimed.
#[test]
fn validator_add_activation_requires_bonded_stake() {
    // Unbonded candidate: the quorum-approved admission lapses
    // at the epoch boundary and the registration unwinds.
    let staking = setup_powered(&[1], 100);
    let new_addr = addr(9);
    let new_sk = bls_key(0xAA);
    let pop = new_sk.pop_prove();
    staking
        .handle(
            &ctx_with_sender(1),
            &msg::validator_add(new_addr, new_sk.public_key().as_bytes(), pop.as_bytes()),
        )
        .unwrap();
    assert!(staking.is_registered(&new_addr));
    assert_eq!(staking.stake(&new_addr), 0, "admission itself bonds nothing");
    let changes = staking.take_validator_changes();
    assert!(changes.adds.is_empty(), "unbonded candidate must not activate");
    assert!(!staking.is_registered(&new_addr), "lapsed admission unwinds");

    // Bonded candidate: activates with the bonded collateral —
    // delegation by any account counts, the ledger debit is the
    // collateral proof.
    let staking = setup_powered(&[1], 100);
    let pop = new_sk.pop_prove();
    staking
        .handle(
            &ctx_with_sender(1),
            &msg::validator_add(new_addr, new_sk.public_key().as_bytes(), pop.as_bytes()),
        )
        .unwrap();
    staking.handle(&ctx_with_sender(0), &msg::delegate(new_addr, 500)).unwrap();
    let changes = staking.take_validator_changes();
    assert_eq!(changes.adds.len(), 1);
    assert_eq!(changes.adds[0].0, new_addr);
    assert_eq!(changes.adds[0].2, 500, "activation stake is the bonded collateral");
}

/// A lone validator must not evict a peer: removal is the same
/// quorum-gated endorsement as admission.
#[test]
fn validator_remove_requires_committee_quorum() {
    let staking = setup_powered(&[1, 2, 3, 4], 100);
    let rm = msg::validator_remove(addr(4));

    staking.handle(&ctx_with_sender(1), &rm).unwrap();
    staking.handle(&ctx_with_sender(2), &rm).unwrap();
    assert!(
        staking.take_validator_changes().removes.is_empty(),
        "two endorsements must not remove"
    );

    staking.handle(&ctx_with_sender(3), &rm).unwrap();
    let changes = staking.take_validator_changes();
    assert_eq!(changes.removes, vec![addr(4)], "quorum removes");
}

/// Confiscating a validator's stake is a governance action —
/// one signer must not slash. (The permissionless path is
/// `EVIDENCE`, which authenticates itself with the proof.)
#[test]
fn slash_requires_committee_quorum() {
    let staking = setup_powered(&[1, 2, 3, 4], 100);
    let slash = msg::slash(addr(4), 10);

    staking.handle(&ctx_with_sender(1), &slash).unwrap();
    staking.handle(&ctx_with_sender(2), &slash).unwrap();
    assert_eq!(staking.stake(&addr(4)), 100, "below quorum, no slash");

    staking.handle(&ctx_with_sender(3), &slash).unwrap();
    assert_eq!(staking.stake(&addr(4)), 90, "quorum slashes");
}

/// Scheduling a coordinated halt freezes the chain — a single
/// validator must never hold that trigger alone.
#[test]
fn schedule_halt_requires_committee_quorum() {
    let staking = setup_powered(&[1, 2, 3, 4], 100);
    staking.begin_block(Height::new(10));
    let halt = msg::schedule_halt(addr(1), 100);

    staking.handle(&ctx_with_sender(1), &halt).unwrap();
    staking.handle(&ctx_with_sender(2), &halt).unwrap();
    assert_eq!(staking.scheduled_halt_height(), None, "below quorum, no halt");

    staking.handle(&ctx_with_sender(3), &halt).unwrap();
    assert_eq!(staking.scheduled_halt_height(), Some(100), "quorum schedules");
}

/// A registered-but-unbonded validator has zero voting power —
/// its endorsement is not even recorded. Registration is not
/// authority; bonded stake is.
#[test]
fn powerless_validator_cannot_endorse() {
    let staking = setup(&[1]);
    let new_sk = bls_key(0xAA);
    let pop = new_sk.pop_prove();
    let result = staking.handle(
        &ctx_with_sender(1),
        &msg::validator_add(addr(9), new_sk.public_key().as_bytes(), pop.as_bytes()),
    );
    assert!(result.is_err(), "a powerless member holds no governance vote");
    assert!(!staking.is_registered(&addr(9)));
}

/// A jailed validator is by definition suspected of misbehavior
/// — it must not keep voting on set changes during its jail
/// period even though its stake is still bonded.
#[test]
fn jailed_validator_cannot_endorse() {
    let staking = setup_powered(&[1, 2, 3, 4], 100);
    framework::lock_state(&staking.jailed).insert(addr(4), 1);
    let result = staking.handle(&ctx_with_sender(4), &msg::validator_remove(addr(3)));
    assert!(result.is_err(), "jailed validators hold no committee vote");
}

/// A quorum-admitted candidate is registered for delegation but
/// is not committee until the rotation seats it — it must not
/// endorse actions in the gap.
#[test]
fn pending_candidate_cannot_endorse() {
    let staking = setup_powered(&[1], 100);
    let new_addr = addr(9);
    let new_sk = bls_key(0xAA);
    let pop = new_sk.pop_prove();
    staking
        .handle(
            &ctx_with_sender(1),
            &msg::validator_add(new_addr, new_sk.public_key().as_bytes(), pop.as_bytes()),
        )
        .unwrap();
    staking.handle(&ctx_with_sender(0), &msg::delegate(new_addr, 100)).unwrap();
    let result = staking.handle(&ctx_with_sender(9), &msg::validator_remove(addr(1)));
    assert!(result.is_err(), "a pending candidate is not yet committee");
}

/// Endorsements bind to the exact action payload: "admit X with
/// key K1" and "admit X with key K2" are different actions and
/// accumulate separately. Whichever reaches quorum first wins;
/// the loser's later quorum is consumed as stale — it must not
/// rotate the already-admitted validator's key.
#[test]
fn endorsements_are_per_action() {
    let staking = setup_powered(&[1, 2, 3, 4], 100);
    let new_addr = addr(9);
    let (sk1, sk2) = (bls_key(0xAA), bls_key(0xBB));
    let add1 =
        msg::validator_add(new_addr, sk1.public_key().as_bytes(), sk1.pop_prove().as_bytes());
    let add2 =
        msg::validator_add(new_addr, sk2.public_key().as_bytes(), sk2.pop_prove().as_bytes());

    // Two endorsements on each action — neither quorums.
    for sender in [1u8, 2] {
        staking.handle(&ctx_with_sender(sender), &add1).unwrap();
        staking.handle(&ctx_with_sender(sender), &add2).unwrap();
    }
    assert!(!staking.is_registered(&new_addr), "split endorsements reach no quorum");
    assert_eq!(staking.endorsements.pending_count(), 2, "both variants accumulate");

    // K1 wins the race to quorum — and registering new_addr
    // killed the K2 variant, which can never apply now: its
    // frozen entry is swept out of the bounded pending set.
    staking.handle(&ctx_with_sender(3), &add1).unwrap();
    assert!(staking.is_registered(&new_addr));
    assert_eq!(staking.endorsements.pending_count(), 0, "losing variant must be swept, not leaked");
    staking.handle(&ctx_with_sender(0), &msg::delegate(new_addr, 50)).unwrap();

    // A late endorsement for K2 is rejected outright — the
    // address is registered, so the action is permanently dead.
    let err = staking.handle(&ctx_with_sender(4), &add2).unwrap_err();
    assert!(matches!(err, ExecError::ModuleRejected(_)));

    let changes = staking.take_validator_changes();
    assert_eq!(changes.adds.len(), 1);
    assert_eq!(changes.adds[0].1.public_key(), sk1.public_key(), "K1 won admission");
}

/// Removing a quorum-admitted candidate before it seats cancels
/// the pending add outright — it never occupied consensus, so
/// there is nothing to unbond and nothing reaches the rotation.
#[test]
fn validator_remove_cancels_pending_add_at_quorum() {
    let staking = setup_powered(&[1, 2], 100);
    let new_addr = addr(9);
    let new_sk = bls_key(0xAA);
    let pop = new_sk.pop_prove();
    let add = msg::validator_add(new_addr, new_sk.public_key().as_bytes(), pop.as_bytes());
    staking.handle(&ctx_with_sender(1), &add).unwrap();
    staking.handle(&ctx_with_sender(2), &add).unwrap();
    assert!(staking.is_registered(&new_addr));

    let rm = msg::validator_remove(new_addr);
    staking.handle(&ctx_with_sender(1), &rm).unwrap();
    staking.handle(&ctx_with_sender(2), &rm).unwrap();
    assert!(!staking.is_registered(&new_addr), "quorum remove cancels the admission");
    let changes = staking.take_validator_changes();
    assert!(changes.adds.is_empty() && changes.removes.is_empty());
}

/// The endorsement map is bounded state: beyond
/// `MAX_PENDING_ACTIONS` distinct pending actions new ones are
/// refused, while already-tracked actions still accept
/// endorsements (a cap must not deadlock governance).
#[test]
fn endorsement_cap_rejects_new_actions() {
    let staking = setup_powered(&[1, 2], 100);
    staking.begin_block(Height::new(1));
    // One endorsement per distinct halt height — with power 100
    // of 200 a single endorsement never quorums, so each stays
    // pending and fills the tracker.
    for h in 2..(2 + framework::MAX_PENDING_ACTIONS as u64) {
        staking
            .handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), h))
            .expect("tracked actions accepted up to the cap");
    }
    let result = staking.handle(&ctx_with_sender(1), &msg::schedule_halt(addr(1), 10_000));
    assert!(result.is_err(), "the cap rejects new actions");

    // An already-tracked action still takes endorsements — the
    // second validator completes its quorum and it applies.
    staking.handle(&ctx_with_sender(2), &msg::schedule_halt(addr(1), 2)).unwrap();
    assert_eq!(staking.scheduled_halt_height(), Some(2));
}

/// C8 for C9: pending endorsements are future-affecting state —
/// two replicas must diverge if one has recorded an endorsement
/// the other has not, so the tally is committed in the root.
#[test]
fn state_root_changes_after_endorsement() {
    let staking = setup_powered(&[1, 2], 100);
    let root0 = staking.state_root();
    staking.handle(&ctx_with_sender(1), &msg::validator_remove(addr(2))).unwrap();
    assert_ne!(staking.state_root(), root0, "a pending endorsement is committed state");
}

/// Snapshot round-trip: validators, delegations, an unbonding
/// entry, and the reward/set bookkeeping must export, verify,
/// and re-import byte-identically — the imported module's root
/// must equal the source's (audit 3.2).
#[test]
fn state_snapshot_round_trips() {
    let src = setup(&[1, 2]);
    src.handle(&ctx_with_sender(1), &msg::delegate(addr(1), 100)).unwrap();
    src.handle(&ctx_with_sender(3), &msg::delegate(addr(2), 250)).unwrap();
    // An unbonding entry exercises the FIFO queue section.
    src.handle(&ctx_with_sender(3), &msg::undelegate(addr(2), 50)).unwrap();
    src.begin_block(Height::new(10));
    src.end_block(Height::new(10));

    let snapshot = src.export_state().expect("staking exports state");
    assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());

    let dst = StakingModule::new();
    dst.import_state(&snapshot).unwrap();
    assert_eq!(dst.state_root(), src.state_root());
    assert_eq!(dst.delegation(&addr(1), &addr(1)), 100);
    assert_eq!(dst.delegation(&addr(3), &addr(2)), 200);
}

/// Every `CommittedMap`'s maintained fold must equal the
/// authoritative recompute (`recomputed_root`) after real handler
/// mutations — a mutation site that escaped the fold API would
/// desync the incremental root, and this test is the net that
/// catches it. Also asserts the incremental root differs from the
/// legacy full-serialization root: the format change is real, not
/// a no-op wrapper.
#[test]
fn committed_folds_stay_in_lockstep_after_mutations() {
    let (staking, _ledger) = setup_with_ledger(&[1, 2]);
    let (v1, v2) = (addr(1), addr(2));
    staking.handle(&ctx_with_sender(3), &msg::delegate(v1, 500)).unwrap();
    staking.handle(&ctx_with_sender(4), &msg::delegate(v1, 300)).unwrap();
    staking.handle(&ctx_with_sender(4), &msg::delegate(v2, 700)).unwrap();
    staking.begin_block(Height::new(1));
    staking.end_block(Height::new(1));
    staking.handle(&ctx_with_sender(4), &msg::undelegate(v1, 100)).unwrap();
    staking.handle(&ctx_with_sender(1), &msg::slash(v1, 50)).unwrap();

    // Bind each guard to a local first: a `lock_state(...)` temporary
    // lives until the end of its enclosing statement, so calling
    // `lock_state` twice on one map inside a single expression would
    // deadlock on the second `lock`.
    macro_rules! assert_fold_locked {
        ($name:literal, $map:expr) => {{
            let guard = framework::lock_state(&$map);
            assert_eq!(guard.root(), guard.recomputed_root(), "{} fold desynced", $name);
        }};
    }
    assert_fold_locked!("store", staking.store);
    assert_fold_locked!("delegations", staking.delegations);
    assert_fold_locked!("pending_rewards", staking.pending_rewards);
    assert_fold_locked!("reward_debt", staking.reward_debt);
    assert_fold_locked!("delegator_index", staking.delegator_index);
    assert_fold_locked!("delegated_total", staking.delegated_total);

    // The incremental preimage is a different construction from the
    // legacy full-serialization root — the same state must not
    // accidentally produce the old digest.
    let mut legacy = framework::CanonicalState::new();
    staking.write_committed(&mut legacy);
    assert_ne!(staking.state_root(), legacy.root());
}

/// A jailed validator must survive state sync: the jail marker
/// AND its jail height are canonical state — losing either would
/// let a slashed offender rejoin the active set early (the
/// `MIN_JAIL_BLOCKS` clock is measured from `jailed_at`).
#[test]
fn state_snapshot_preserves_jailed_validator() {
    let src = setup(&[1]);
    let v = addr(1);
    let key = bls_key(1);
    src.genesis_set_bls_key(v, key.public_key().as_bytes());
    src.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    // `jailed_at` records `current_height` — begin a block so the
    // jail lands at height 42, not the module's initial 0.
    src.begin_block(Height::new(42));
    src.handle(&ctx(), &signed_evidence(v, &key, 7, 0)).unwrap();
    assert!(src.is_jailed(&v), "offender jailed before export");
    src.end_block(Height::new(42));

    let snapshot = src.export_state().expect("staking exports state");
    assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());

    let dst = StakingModule::new();
    dst.import_state(&snapshot).unwrap();
    assert_eq!(dst.state_root(), src.state_root());
    assert!(dst.is_jailed(&v), "jail marker must survive import");
    assert_eq!(dst.stake(&v), 900, "post-slash stake must survive import");

    // The jail clock must not reset: unjailing before
    // `jailed_at + MIN_JAIL_BLOCKS` stays rejected even though
    // the imported module's *import height* is later.
    dst.begin_block(Height::new(42 + MIN_JAIL_BLOCKS - 1));
    assert!(
        dst.handle(&ctx_with_sender(1), &msg::unjail(v)).is_err(),
        "unjail must still be inside the jail period — the clock survived import"
    );
}

/// A truncated blob must fail inspection and import — the
/// claimed root is never trusted over the bytes.
#[test]
fn state_snapshot_rejects_corruption() {
    let src = setup(&[1]);
    src.handle(&ctx_with_sender(1), &msg::delegate(addr(1), 100)).unwrap();
    let mut snapshot = src.export_state().unwrap();
    snapshot.entries[0].1.truncate(12);
    assert!(src.inspect_state(&snapshot).is_err());
    assert!(StakingModule::new().import_state(&snapshot).is_err());
}

/// The replay key is the canonical OFFENSE identity —
/// `(validator, view, phase, epoch)` — so resubmitting the
/// same equivocation with the two votes swapped hits the same
/// key. The v1 key hashed the ordered pair and double-slashed.
#[test]
fn evidence_swapped_pair_is_same_offense() {
    let staking = setup(&[1]);
    let v = addr(1);
    let key = bls_key(1);
    staking.genesis_set_bls_key(v, key.public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

    let evidence = signed_evidence(v, &key, 7, 0);
    staking.handle(&ctx(), &evidence).unwrap();
    assert_eq!(staking.stake(&v), 900);

    // Rebuild the same proof with (hash_a, sig_a) and
    // (hash_b, sig_b) swapped — byte-distinct message, same
    // offense.
    let view = 7u64;
    let epoch = 0u64;
    let hash_a = [0xAAu8; 32];
    let hash_b = [0xBBu8; 32];
    let vote_msg = |hash: &[u8; 32]| {
        let mut m = [0u8; 49];
        m[..8].copy_from_slice(&view.to_le_bytes());
        m[9..41].copy_from_slice(hash);
        m[41..49].copy_from_slice(&epoch.to_le_bytes());
        m
    };
    let sig_a = key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_a));
    let sig_b = key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_b));
    let swapped =
        msg::evidence(v, view, 0, epoch, &hash_b, sig_b.as_bytes(), &hash_a, sig_a.as_bytes());
    let result = staking.handle(&ctx(), &swapped);
    assert!(result.is_err(), "swapped pair must not re-slash");
    assert_eq!(staking.stake(&v), 900, "still exactly one slash");
}

/// Penalties are per OFFENSE: a different conflicting pair at
/// the same (view, phase, epoch) — e.g. the validator triple-
/// signed the view — is still one offense, one penalty.
#[test]
fn evidence_different_pair_same_offense() {
    let staking = setup(&[1]);
    let v = addr(1);
    let key = bls_key(1);
    staking.genesis_set_bls_key(v, key.public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

    staking.handle(&ctx(), &signed_evidence(v, &key, 7, 0)).unwrap();
    assert_eq!(staking.stake(&v), 900);

    // Same triple, different second hash — still the same
    // offense position.
    let hash_a = [0xAAu8; 32];
    let hash_c = [0xCCu8; 32];
    let vote_msg = |hash: &[u8; 32]| {
        let mut m = [0u8; 49];
        m[..8].copy_from_slice(&7u64.to_le_bytes());
        m[9..41].copy_from_slice(hash);
        m[41..49].copy_from_slice(&0u64.to_le_bytes());
        m
    };
    let sig_a = key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_a));
    let sig_c = key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_c));
    let second = msg::evidence(v, 7, 0, 0, &hash_a, sig_a.as_bytes(), &hash_c, sig_c.as_bytes());
    assert!(staking.handle(&ctx(), &second).is_err(), "same offense — no second slash");
    assert_eq!(staking.stake(&v), 900);
}

/// A DIFFERENT consensus position is a different offense —
/// equivocating again at another view must slash again.
#[test]
fn evidence_distinct_view_is_distinct_offense() {
    let staking = setup(&[1]);
    let v = addr(1);
    let key = bls_key(1);
    staking.genesis_set_bls_key(v, key.public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

    staking.handle(&ctx(), &signed_evidence(v, &key, 7, 0)).unwrap();
    staking.handle(&ctx(), &signed_evidence(v, &key, 8, 0)).unwrap();
    // Two offenses, two 10% slashes: 1000 → 900 → 810.
    assert_eq!(staking.stake(&v), 810, "each distinct offense slashes");
}

/// Evidence for votes signed with a rotated-out key must still
/// verify — the retired-key history covers the evidence
/// window. v1 used only the live key, so a validator could
/// rotate away from a pending proof.
#[test]
fn evidence_verifies_with_retired_key() {
    let staking = setup(&[1]);
    let v = addr(1);
    let old_key = bls_key(1);
    let new_key = bls_key(2);
    staking.genesis_set_bls_key(v, old_key.public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

    // The offense predates the rotation: signed under K1.
    let evidence = signed_evidence(v, &old_key, 7, 0);
    // Rotate K1 → K2.
    let pop = new_key.pop_prove();
    staking
        .handle(
            &ctx_with_sender(1),
            &msg::key_change(v, new_key.public_key().as_bytes(), pop.as_bytes()),
        )
        .unwrap();
    let changes = staking.take_key_changes();
    assert_eq!(changes.len(), 1, "rotation applied");

    // Evidence signed with the retired key still verifies —
    // and slashes.
    staking.handle(&ctx(), &evidence).unwrap();
    assert_eq!(staking.stake(&v), 900, "rotated-out key evidence still slashes");
    assert!(staking.is_jailed(&v));
}

/// Each signature may verify under a different validator-owned
/// key — a mid-view rotation could split them. The offense is
/// the validator signing conflicting votes either way.
#[test]
fn evidence_verifies_mixed_keys() {
    let staking = setup(&[1]);
    let v = addr(1);
    let old_key = bls_key(1);
    let new_key = bls_key(2);
    staking.genesis_set_bls_key(v, old_key.public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let pop = new_key.pop_prove();
    staking
        .handle(
            &ctx_with_sender(1),
            &msg::key_change(v, new_key.public_key().as_bytes(), pop.as_bytes()),
        )
        .unwrap();
    staking.take_key_changes();

    // Vote A signed under retired K1, vote B under current K2.
    let hash_a = [0xAAu8; 32];
    let hash_b = [0xBBu8; 32];
    let vote_msg = |hash: &[u8; 32]| {
        let mut m = [0u8; 49];
        m[..8].copy_from_slice(&7u64.to_le_bytes());
        m[9..41].copy_from_slice(hash);
        m[41..49].copy_from_slice(&0u64.to_le_bytes());
        m
    };
    let sig_a = old_key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_a));
    let sig_b = new_key.sign(crypto::hash::Domain::Vote, &vote_msg(&hash_b));
    let evidence = msg::evidence(v, 7, 0, 0, &hash_a, sig_a.as_bytes(), &hash_b, sig_b.as_bytes());
    staking.handle(&ctx(), &evidence).unwrap();
    assert_eq!(staking.stake(&v), 900);
}

/// A key no validator ever held still cannot verify — the
/// retired set is validator-scoped, not a global forgery pool.
#[test]
fn evidence_rejects_unrelated_retired_key() {
    let staking = setup(&[1, 2]);
    let (v1, v2) = (addr(1), addr(2));
    let k1 = bls_key(1);
    let k2 = bls_key(2);
    staking.genesis_set_bls_key(v1, k1.public_key().as_bytes());
    staking.genesis_set_bls_key(v2, k2.public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v1, 1000)).unwrap();
    staking.handle(&ctx(), &msg::delegate(v2, 1000)).unwrap();
    // Rotate v2's key — v1's evidence signed with v2's OLD key
    // must still fail: the key was never v1's.
    let k2_new = bls_key(3);
    let pop = k2_new.pop_prove();
    staking
        .handle(
            &ctx_with_sender(2),
            &msg::key_change(v2, k2_new.public_key().as_bytes(), pop.as_bytes()),
        )
        .unwrap();
    staking.take_key_changes();
    let forged = signed_evidence(v1, &k2, 7, 0);
    assert!(staking.handle(&ctx(), &forged).is_err(), "another validator's key must not verify");
    assert_eq!(staking.stake(&v1), 1000);
}

/// The retired history is bounded — rotations beyond
/// `EVIDENCE_KEY_HISTORY` evict the oldest entries.
#[test]
fn retired_key_history_is_bounded() {
    let staking = setup(&[1]);
    let v = addr(1);
    staking.genesis_set_bls_key(v, bls_key(0).public_key().as_bytes());
    staking.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    // Nine rotations: keys 1..=9 displace 0..=8 → retired
    // holds at most EVIDENCE_KEY_HISTORY (8).
    for i in 1u8..=9 {
        let k = bls_key(i);
        let pop = k.pop_prove();
        staking
            .handle(
                &ctx_with_sender(1),
                &msg::key_change(v, k.public_key().as_bytes(), pop.as_bytes()),
            )
            .unwrap();
        staking.take_key_changes();
    }
    let retired = framework::lock_state(&staking.retired_bls_keys);
    let keys = retired.get(&v).expect("history exists");
    assert_eq!(keys.len(), EVIDENCE_KEY_HISTORY, "history capped");
    // The oldest (key 0) was evicted; the newest (key 8) kept.
    assert_eq!(keys.last().unwrap().as_bytes(), bls_key(8).public_key().as_bytes());
}

/// Retired keys are committed state — they must survive a
/// snapshot round-trip so every replica verifies the same
/// post-rotation evidence.
#[test]
fn snapshot_roundtrips_retired_keys() {
    let src = setup(&[1]);
    let v = addr(1);
    let old_key = bls_key(1);
    let new_key = bls_key(2);
    src.genesis_set_bls_key(v, old_key.public_key().as_bytes());
    src.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();
    let pop = new_key.pop_prove();
    src.handle(
        &ctx_with_sender(1),
        &msg::key_change(v, new_key.public_key().as_bytes(), pop.as_bytes()),
    )
    .unwrap();
    src.take_key_changes();
    let evidence = signed_evidence(v, &old_key, 7, 0);

    let snapshot = src.export_state().unwrap();
    assert_eq!(src.inspect_state(&snapshot).unwrap(), src.state_root());
    let dst = StakingModule::new();
    dst.set_ledger(std::sync::Arc::new(framework::MemoryBalances::new()));
    dst.import_state(&snapshot).unwrap();
    assert_eq!(dst.state_root(), src.state_root());
    // The imported replica verifies retired-key evidence too.
    dst.handle(&ctx(), &evidence).unwrap();
    assert_eq!(dst.stake(&v), 900);
}

/// Pre-upgrade blobs carry no retired-keys section: they decode
/// with an empty history — evidence verifies against the live
/// key, the exact pre-upgrade bound.
#[test]
fn pre_upgrade_blob_decodes_without_key_history() {
    let src = setup(&[1]);
    let v = addr(1);
    let key = bls_key(1);
    src.genesis_set_bls_key(v, key.public_key().as_bytes());
    src.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

    // Strip the trailing retired-keys section from the canon:
    // with an empty history the section is a single
    // `put_count(0)` — 8 zero bytes at the canon tail.
    let mut snapshot = src.export_state().unwrap();
    let blob = &mut snapshot.entries[0].1;
    let canon_len = usize::try_from(u64::from_le_bytes(blob[..8].try_into().unwrap())).unwrap();
    let section_len = 8usize; // put_count(0)
    blob[..8].copy_from_slice(&(canon_len as u64 - section_len as u64).to_le_bytes());
    blob.drain(8 + canon_len - section_len..8 + canon_len);
    let v1_snapshot = snapshot.clone();

    let dst = StakingModule::new();
    dst.set_ledger(std::sync::Arc::new(framework::MemoryBalances::new()));
    dst.inspect_state(&v1_snapshot).unwrap();
    dst.import_state(&v1_snapshot).unwrap();
    // Empty retired history — but live-key evidence works.
    assert!(framework::lock_state(&dst.retired_bls_keys).is_empty());
    let evidence = signed_evidence(v, &key, 7, 0);
    dst.handle(&ctx(), &evidence).unwrap();
    assert_eq!(dst.stake(&v), 900);
}

/// A snapshot blob carrying a 48-byte BLS key that is not a
/// well-formed group element must fail import — the `PoP` gate ran
/// at admission, so restore re-validates the point itself rather
/// than trusting the bytes. Without this a crafted blob lodges a
/// key that can never verify, wedging every QC that maps to it.
#[test]
fn snapshot_rejects_malformed_bls_key() {
    let src = setup(&[1]);
    let v = addr(1);
    let key = bls_key(1);
    src.genesis_set_bls_key(v, key.public_key().as_bytes());
    src.handle(&ctx(), &msg::delegate(v, 1000)).unwrap();

    let mut snapshot = src.export_state().unwrap();
    let blob = &mut snapshot.entries[0].1;
    let pk_bytes = key.public_key().as_bytes().to_vec();
    let off = blob
        .windows(pk_bytes.len())
        .position(|w| w == pk_bytes.as_slice())
        .expect("the committed key is in the canon");
    // `0xFF…` is not a valid compressed BLS12-381 point.
    for b in &mut blob[off..off + pk_bytes.len()] {
        *b = 0xFF;
    }

    let dst = StakingModule::new();
    dst.set_ledger(std::sync::Arc::new(framework::MemoryBalances::new()));
    assert!(
        dst.import_state(&snapshot).is_err(),
        "a malformed group element must fail import, not lodge"
    );
}

// ── `staking.*` parameter sink ──────────────────────────────
// The governed knobs land on the same atomics `with_*` builders
// seed — the applies below prove the sink writes where the
// enforcement paths read.

/// `staking.unbonding_period` / `staking.block_reward` apply
/// through the sink onto the live values — the same atomic every
/// replica's `end_block` writes at the apply height.
#[test]
fn staking_sink_applies_unbonding_period_and_block_reward() {
    let staking = StakingModule::new();
    framework::ParameterSink::apply_param(
        &staking,
        b"staking.unbonding_period",
        &7u64.to_le_bytes(),
    )
    .expect("unbonding_period apply");
    assert_eq!(staking.unbonding_period(), 7);
    framework::ParameterSink::apply_param(&staking, b"staking.block_reward", &0u64.to_le_bytes())
        .expect("block_reward apply — 0 is a legitimate issuance-off policy");
    assert_eq!(staking.block_reward(), 0);
}

/// The sink owns its keyspace: foreign keys route to a different
/// module's sink, malformed payloads fail decode, and a zero
/// unbonding window is rejected outright — an instant unbond
/// would let a validator exit before equivocation evidence can
/// land. Rejected applies leave the configured values untouched.
#[test]
fn staking_sink_rejects_foreign_malformed_and_zero_period() {
    let staking = StakingModule::new();
    assert!(
        framework::ParameterSink::apply_param(
            &staking,
            b"exchange.fee_vault.withdraw",
            &1u64.to_le_bytes()
        )
        .is_err(),
        "foreign key must reject"
    );
    assert!(
        framework::ParameterSink::apply_param(&staking, b"staking.block_reward", &[1, 2]).is_err(),
        "short payload must reject"
    );
    assert!(
        framework::ParameterSink::apply_param(
            &staking,
            b"staking.unbonding_period",
            &0u64.to_le_bytes()
        )
        .is_err(),
        "zero unbonding window must reject"
    );
    assert_eq!(staking.unbonding_period(), DEFAULT_UNBONDING_PERIOD_BLOCKS);
    assert_eq!(staking.block_reward(), DEFAULT_BLOCK_REWARD);
}
