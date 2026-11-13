//! The EVM-style lane (`docs/lanes-spec.md` §6): account-range
//! sharding of value transfers with cross-lane credits.
//!
//! Accounts partition by id range across `N` lanes; a transfer runs in
//! the lane that owns its *sender*. When the receiver lives elsewhere,
//! the sender is debited at once and a [`Credit`] goes to the lane's
//! outbox; the receiving lane applies credits in `(from_lane, idx)`
//! order, at most once.
//!
//! **Conservation:** `sum(balances) + sum(in-flight credits)` over all
//! lanes is constant. [`total_supply`] computes it and the tests assert
//! it after every step.
//!
//! Scope: value transfers only. Cross-lane contract calls that need a
//! synchronous result are out of scope for this prototype (spec §6).
//! Balances are `u128` and amounts `u64`, so a credit can never
//! overflow and conservation never depends on saturation.

/// A transfer submitted to the sender's lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transfer {
    /// Sender account (must belong to the processing lane).
    pub from: u64,
    /// Receiver account (any lane).
    pub to: u64,
    /// Amount, smallest unit.
    pub amount: u64,
}

/// A credit travelling between lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Credit {
    /// Lane that debited the sender.
    pub from_lane: u16,
    /// Index on the `(from_lane, receiver's lane)` channel, from 0 and
    /// contiguous. Per channel, not per source: a destination sees only
    /// its own channel's credits, so a source-wide counter would look
    /// like gaps.
    pub idx: u64,
    /// Receiver account.
    pub to: u64,
    /// Amount.
    pub amount: u64,
}

/// Maps accounts to lanes by contiguous id ranges.
#[derive(Debug, Clone, Copy)]
pub struct AccountRange {
    /// Number of lanes (at least 1).
    pub lanes: u16,
    /// Accounts per lane (at least 1).
    pub per_lane: u64,
}

impl AccountRange {
    /// Lane owning `account`; ids past the last range belong to the last lane.
    #[must_use]
    pub fn lane_of(&self, account: u64) -> u16 {
        let l = account / self.per_lane.max(1);
        l.min(u64::from(self.lanes.max(1)) - 1) as u16
    }
}

/// Why a delivery was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliverError {
    /// A message index was skipped; redelivery must start at `expected`.
    Gap {
        /// The next index the lane needs from that source.
        expected: u64,
    },
    /// The credit's receiver is not owned by this lane (misrouted).
    Misrouted,
}

/// One account-range lane.
pub struct EvmLane {
    id: u16,
    range: AccountRange,
    base: u64,
    balances: Vec<u128>,
    /// Next outgoing message index, per destination lane.
    next_out: Vec<u64>,
    /// Per-source next expected incoming index.
    next_in: Vec<u64>,
    outbox: Vec<Credit>,
    /// Transfers rejected for insufficient funds or wrong lane.
    pub rejected: u64,
}

impl EvmLane {
    /// Create lane `id` with every owned account funded with `initial`.
    #[must_use]
    pub fn new(id: u16, range: AccountRange, initial: u128) -> Self {
        let base = u64::from(id) * range.per_lane;
        // The last lane also owns the tail past the nominal ranges only
        // if the caller sizes `per_lane` to cover it; the prototype uses
        // exact ranges, so each lane owns exactly `per_lane` accounts.
        Self {
            id,
            range,
            base,
            balances: vec![initial; range.per_lane as usize],
            next_out: vec![0; usize::from(range.lanes)],
            next_in: vec![0; usize::from(range.lanes)],
            outbox: Vec::new(),
            rejected: 0,
        }
    }

    fn slot(&self, account: u64) -> Option<usize> {
        let i = account.checked_sub(self.base)?;
        (i < self.balances.len() as u64 && self.range.lane_of(account) == self.id)
            .then_some(i as usize)
    }

    /// Balance of an owned account.
    #[must_use]
    pub fn balance(&self, account: u64) -> Option<u128> {
        self.slot(account).map(|i| self.balances[i])
    }

    /// Apply transfers in order. Insufficient funds or a sender this lane
    /// does not own rejects the transfer with no state change.
    pub fn apply_transfers(&mut self, txs: &[Transfer]) {
        for t in txs {
            let Some(si) = self.slot(t.from) else {
                self.rejected += 1;
                continue;
            };
            let amt = u128::from(t.amount);
            if self.balances[si] < amt {
                self.rejected += 1;
                continue;
            }
            self.balances[si] -= amt;
            if let Some(ri) = self.slot(t.to) {
                self.balances[ri] += amt;
            } else {
                let dest = usize::from(self.range.lane_of(t.to));
                self.outbox.push(Credit {
                    from_lane: self.id,
                    idx: self.next_out[dest],
                    to: t.to,
                    amount: t.amount,
                });
                self.next_out[dest] += 1;
            }
        }
    }

    /// Take the pending outgoing credits, in index order.
    pub fn drain_outbox(&mut self) -> Vec<Credit> {
        std::mem::take(&mut self.outbox)
    }

    /// Take the pending credits grouped by destination lane (index =
    /// lane), each group in index order. What a parallel runner uses so
    /// every source buckets its own traffic.
    pub fn drain_by_dest(&mut self) -> Vec<Vec<Credit>> {
        let mut out = vec![Vec::new(); usize::from(self.range.lanes)];
        for c in std::mem::take(&mut self.outbox) {
            out[usize::from(self.range.lane_of(c.to))].push(c);
        }
        out
    }

    /// Sum of this lane's pending outgoing credits.
    #[must_use]
    pub fn in_flight(&self) -> u128 {
        self.outbox.iter().map(|c| u128::from(c.amount)).sum()
    }

    /// Sum of this lane's balances.
    #[must_use]
    pub fn balance_sum(&self) -> u128 {
        self.balances.iter().sum()
    }

    /// Apply incoming credits. Duplicates (index already applied) are
    /// ignored (at-most-once); a gap stops delivery and reports where
    /// to resume; a misrouted credit stops delivery. Credits already
    /// applied before the error stay applied.
    ///
    /// # Errors
    ///
    /// [`DeliverError`] on a gap or a misrouted credit.
    pub fn deliver(&mut self, msgs: &[Credit]) -> Result<(), DeliverError> {
        for m in msgs {
            let Some(next) = self.next_in.get_mut(usize::from(m.from_lane)) else {
                return Err(DeliverError::Misrouted);
            };
            if m.idx < *next {
                continue; // duplicate
            }
            if m.idx > *next {
                return Err(DeliverError::Gap { expected: *next });
            }
            let Some(i) = self.slot(m.to) else {
                return Err(DeliverError::Misrouted);
            };
            self.balances[i] += u128::from(m.amount);
            self.next_in[usize::from(m.from_lane)] += 1;
        }
        Ok(())
    }
}

/// Conserved total over all lanes: balances plus in-flight credits.
#[must_use]
pub fn total_supply(lanes: &[EvmLane]) -> u128 {
    lanes.iter().map(|l| l.balance_sum() + l.in_flight()).sum()
}

/// Run one round: every lane applies its transfers, then outboxes are
/// delivered to the owning lanes in `(source lane, idx)` order.
///
/// # Panics
///
/// Panics if delivery fails, which cannot happen when lanes only ever
/// exchange their own drained outboxes in order.
pub fn round(lanes: &mut [EvmLane], inputs: &[Vec<Transfer>], range: AccountRange) {
    for (l, txs) in lanes.iter_mut().zip(inputs) {
        l.apply_transfers(txs);
    }
    let mut per_dest: Vec<Vec<Credit>> = vec![Vec::new(); lanes.len()];
    for l in lanes.iter_mut() {
        for c in l.drain_outbox() {
            per_dest[usize::from(range.lane_of(c.to))].push(c);
        }
    }
    for (l, msgs) in lanes.iter_mut().zip(&per_dest) {
        l.deliver(msgs).expect("in-order delivery of drained outboxes");
    }
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;

    const LANES: u16 = 4;
    const PER: u64 = 64;

    fn setup() -> (Vec<EvmLane>, AccountRange) {
        let r = AccountRange { lanes: LANES, per_lane: PER };
        ((0..LANES).map(|i| EvmLane::new(i, r, 1_000)).collect(), r)
    }

    fn rng(x: &mut u64) -> u64 {
        *x ^= *x << 13;
        *x ^= *x >> 7;
        *x ^= *x << 17;
        *x
    }

    fn txs_for(lane: u16, n: usize, x: &mut u64) -> Vec<Transfer> {
        let total = u64::from(LANES) * PER;
        (0..n)
            .map(|_| Transfer {
                from: u64::from(lane) * PER + rng(x) % PER,
                to: rng(x) % total,
                amount: rng(x) % 300,
            })
            .collect()
    }

    /// Property: no step changes the conserved total, whether or not
    /// the credits have been delivered yet.
    #[test]
    fn conservation_holds_after_every_step() {
        for seed in 1..40u64 {
            let (mut lanes, r) = setup();
            let want = total_supply(&lanes);
            let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
            for _ in 0..20 {
                let inputs: Vec<Vec<Transfer>> =
                    (0..LANES).map(|l| txs_for(l, 50, &mut x)).collect();
                for (i, t) in inputs.iter().enumerate() {
                    lanes[i].apply_transfers(t);
                    // Outboxes are still inside the lanes: counted as in flight.
                    assert_eq!(total_supply(&lanes), want, "mid-round, seed {seed}");
                }
                let mut per_dest: Vec<Vec<Credit>> = vec![Vec::new(); lanes.len()];
                for l in &mut lanes {
                    for c in l.drain_outbox() {
                        per_dest[usize::from(r.lane_of(c.to))].push(c);
                    }
                }
                // Drained credits are in flight outside any lane: count them.
                let flying: u128 = per_dest.iter().flatten().map(|c| u128::from(c.amount)).sum();
                let bal: u128 = lanes.iter().map(EvmLane::balance_sum).sum();
                assert_eq!(bal + flying, want, "in transit, seed {seed}");
                for (l, m) in lanes.iter_mut().zip(&per_dest) {
                    l.deliver(m).expect("deliver");
                }
                assert_eq!(total_supply(&lanes), want, "after delivery, seed {seed}");
            }
        }
    }

    #[test]
    fn duplicates_are_ignored_and_gaps_reported() {
        let (mut lanes, _) = setup();
        lanes[0].apply_transfers(&[
            Transfer { from: 0, to: PER, amount: 10 },
            Transfer { from: 1, to: PER + 1, amount: 20 },
        ]);
        let msgs = lanes[0].drain_outbox();
        assert_eq!(msgs.len(), 2);
        // Gap: deliver idx 1 first.
        assert_eq!(lanes[1].deliver(&msgs[1..]), Err(DeliverError::Gap { expected: 0 }));
        lanes[1].deliver(&msgs).expect("in order");
        let after = lanes[1].balance(PER).expect("owned");
        lanes[1].deliver(&msgs).expect("duplicates are ignored");
        assert_eq!(lanes[1].balance(PER), Some(after), "at most once");
        assert_eq!(after, 1_010);
    }

    #[test]
    fn rejects_overdraft_and_foreign_sender_without_state_change() {
        let (mut lanes, _) = setup();
        let before = total_supply(&lanes);
        lanes[0].apply_transfers(&[
            Transfer { from: 0, to: 1, amount: 5_000 }, // overdraft
            Transfer { from: PER, to: 1, amount: 1 },   // not this lane's sender
        ]);
        assert_eq!(lanes[0].rejected, 2);
        assert_eq!(lanes[0].balance(0), Some(1_000));
        assert_eq!(total_supply(&lanes), before);
        assert!(lanes[0].drain_outbox().is_empty());
    }

    #[test]
    fn misrouted_credit_is_refused() {
        let (mut lanes, _) = setup();
        let c = Credit { from_lane: 0, idx: 0, to: 2 * PER, amount: 1 };
        assert_eq!(lanes[1].deliver(&[c]), Err(DeliverError::Misrouted));
    }

    /// Differential: N lanes with cross-lane credits end with exactly
    /// the balances of one big lane processing the same transfers in
    /// the same global order, as long as no transfer depends on an
    /// undelivered credit (senders are funded enough that none do).
    #[test]
    fn lanes_match_a_single_lane_oracle() {
        let r = AccountRange { lanes: LANES, per_lane: PER };
        let one = AccountRange { lanes: 1, per_lane: PER * u64::from(LANES) };
        let mut lanes: Vec<EvmLane> = (0..LANES).map(|i| EvmLane::new(i, r, 1_000_000)).collect();
        let mut oracle = [EvmLane::new(0, one, 1_000_000)];
        let mut x = 99u64;
        for _ in 0..30 {
            let inputs: Vec<Vec<Transfer>> = (0..LANES).map(|l| txs_for(l, 40, &mut x)).collect();
            round(&mut lanes, &inputs, r);
            let flat: Vec<Transfer> = inputs.concat();
            oracle[0].apply_transfers(&flat);
        }
        for acct in 0..u64::from(LANES) * PER {
            let got = lanes[usize::from(r.lane_of(acct))].balance(acct);
            assert_eq!(got, oracle[0].balance(acct), "account {acct}");
        }
    }
}
