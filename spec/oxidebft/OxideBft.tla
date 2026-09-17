------------------------------ MODULE OxideBft ------------------------------
(***************************************************************************)
(* TLA+ model of oxideBFT — the pipelined two-chain HotStuff-family          *)
(* consensus engine implemented in crates/consensus/src/engine.rs.           *)
(*                                                                           *)
(* The model is a FAITHFUL abstraction of the engine's safety-relevant       *)
(* rules, not generic HotStuff:                                              *)
(*                                                                           *)
(*  * Vote rule (engine.rs `vote()`): a validator votes in view v only if    *)
(*    it has not voted in any view >= v (`last_voted_view`), the stamped     *)
(*    height is exactly the claimed parent's height + 1 (HEIGHT CONTINUITY — *)
(*    the fix for the forged-height exploit: proposer-stamped heights are    *)
(*    otherwise arbitrary, letting a Byzantine leader commit a block at an   *)
(*    unreached height and wedge honest voters' per-height locks), it has    *)
(*    not voted for a different block at the same stamped height             *)
(*    (`voted_at_height`) — unless the proposal carries a valid TC for the   *)
(*    immediately preceding view (LOCK RELEASE — a timed-out view produced   *)
(*    no QC, so re-voting the same height cannot create conflicting          *)
(*    commits) — and the proposal's claimed parent equals the validator's    *)
(*    current highQC block while the attached justify QC has view >= its     *)
(*    own (`tail-fork resistance`). A Byzantine proposal may carry a         *)
(*    justify QC for a DIFFERENT block than its claimed parent — voters      *)
(*    see both fields, so both are modeled independently.                    *)
(*  * Commit rule (engine.rs `deliver_qc()`): a validator tracks `pending`,  *)
(*    the block of the most recently ADOPTED QC. Adopting QC(x) commits      *)
(*    justifyBlock(x) iff that block equals pending — i.e. two consecutively *)
(*    adopted QCs linked by a justify edge commit the inner block. Stamped   *)
(*    height, not chain depth, keys the finalized map. Committing prunes     *)
(*    the voter's per-height locks at-or-below the committed height          *)
(*    (`voted_at_height.retain(h > committed)`).                             *)
(*  * View sync (pacemaker.rs): a TC needs a quorum of timeout signatures;   *)
(*    receiving TC(v) with v >= current view jumps the validator to v+1.     *)
(*    Honest validators sign only their current view; Byzantine ones sign    *)
(*    any view. QC adoption past current view also jumps the view forward    *)
(*    (QC catch-up in `deliver_qc`).                                          *)
(*  * Quorums abstract cryptography: a QC exists iff >= Quorum votes exist   *)
(*    for a block at its own view; honest validators never double-vote a     *)
(*    view, Byzantine validators sign anything.                              *)
(*                                                                           *)
(* What is deliberately NOT modeled: epochs/rotation (single epoch),         *)
(* proposer signatures (leader(v) is the only possible proposer at v —       *)
(* the engine rejects others), stake-weighted leader selection (the cfg      *)
(* fixes equal-stake round-robin `view % N`), execution/exec_certs, and      *)
(* real-time timeouts.                                                       *)
(***************************************************************************)

EXTENDS Integers, FiniteSets, TLC

CONSTANTS
    N,              \* validator count; engine tolerates f = (N-1)/3
    Quorum,         \* QC/TC threshold = 2f+1
    Byzantine,      \* subset of Validators that may deviate arbitrarily
    MaxView,        \* view bound (model-checking finitization)
    MaxHeight,      \* stamped-height bound
    MaxVariants,    \* max proposals per view (equivocation bound)
    IndividualVotes, \* TRUE: enable per-vote actions (full fidelity);
                    \*  FALSE: quorum votes only (fast bug-hunt mode)
    FreeAdvance     \* TRUE: honest validators may advance views without
                    \*  evidence (the driver's advance_view); FALSE for
                    \*  evidence-only view movement (QC/TC jumps)

ASSUME N \in Nat /\ N >= 4
ASSUME Quorum \in Nat /\ Quorum <= N
ASSUME Byzantine \subseteq (0..(N-1))
ASSUME Cardinality(Byzantine) <= (N - 1) \div 3
ASSUME MaxView \in Nat /\ MaxHeight \in Nat /\ MaxVariants \in Nat

Validators == 0..(N-1)
Honest    == Validators \ Byzantine
Views     == 0..MaxView
Heights   == 0..MaxHeight

Leader(v) == v % N          \* equal-stake round robin (validator.rs:283)

(***************************************************************************)
(* Blocks are records:                                                       *)
(*   view    — the view the proposal claims                                  *)
(*   height  — STAMPED height; free choice for Byzantine leaders,            *)
(*             justify.height+1 for honest ones                              *)
(*   prev    — the claimed parent block (the vote rule binds this to the     *)
(*             voter's highQC block)                                         *)
(*   justify — the block the attached QC actually notarizes (the commit      *)
(*             rule follows justify edges, not prev edges)                   *)
(*   tcView  — the view of the embedded timeout certificate (-1 = none).     *)
(*             The leader embeds the TC that justified its entry into the    *)
(*             proposal's view; voters use it to release a same-height       *)
(*             vote lock left over from the timed-out view.                  *)
(* `Genesis` is the implicit genesis anchor: height -1 so the first block   *)
(* stamps height 0 (matching the engine's `last_committed` anchor rule).     *)
(***************************************************************************)

Genesis == [view |-> -1, height |-> -1, prev |-> -1, justify |-> -1, tcView |-> -1]
NoVal   == [view |-> -2, height |-> -2, prev |-> -2, justify |-> -2, tcView |-> -2]

VARIABLES
    proposals,      \* set of proposed blocks (Genesis not included)
    castVotes,      \* SUBSET (Validators \X proposals): all votes ever cast
    timeoutSigs,    \* SUBSET (Validators \X Views): timeout sigs ever cast
    view,           \* view[i] — validator i's current view
    highQC,         \* highQC[i] — block of i's highest adopted QC
    pending,        \* pending[i] — block of i's most recently adopted QC
    votedView,      \* votedView[i] — highest view i voted in (-1 = none)
    votedAt,        \* votedAt[i] — partial function Heights -> proposals
    stored,         \* stored[i] — blocks i holds (engine `blocks` map:
                    \*   own proposals + blocks i voted for). pending
                    \*   and commits are gated on membership — a QC
                    \*   alone cannot make an unseen block pending.
    committed       \* committed[i] — set of blocks i has committed

vars == <<proposals, castVotes, timeoutSigs, view, highQC, pending,
          votedView, votedAt, stored, committed>>

---------------------------------------------------------------------------
(* Derived predicates *)

VoteCount(b) == Cardinality({i \in Validators : <<i, b>> \in castVotes})

Notarized(b) == b = Genesis \/ VoteCount(b) >= Quorum
HasQC(b)     == b # Genesis /\ VoteCount(b) >= Quorum

TCExists(v) == Cardinality({i \in Validators : <<i, v>> \in timeoutSigs}) >= Quorum

\* Number of proposals already made for view v (equivocation bound).
PropCount(v) == Cardinality({b \in proposals : b.view = v})

\* Safe per-height-lock lookup: NoVal when i has no vote recorded at h.
VotedAt(i, h) == IF h \in DOMAIN votedAt[i] THEN votedAt[i][h] ELSE NoVal

\* The TC options an honest leader can embed at view v: either nothing
\* (view reached via QC progress), or a TC for v-1 that actually exists
\* (the quorum of timeout signatures was collected). Over-approximates
\* the engine's `last_tc` bookkeeping — checking a superset of
\* attachable evidence is conservative for safety.
TCOptions(v) == {-1} \cup {t \in Views : TCExists(t) /\ t + 1 = v}

\* The largest stamped height in a set of blocks — used by the commit
\* rule to prune per-height locks below the newly committed tip.
MaxHeightOf(S) ==
    CHOOSE h \in {x.height : x \in S} : \A y \in S : y.height <= h

(* The commit walk (engine `deliver_qc`): adopting QC(b) commits b's  *)
(* justify target AND every stored, uncommitted ancestor reachable    *)
(* via justify edges. A single-link "pending" check can skip a link   *)
(* when QC adoption races block storage — the InvNoGap shape TLC      *)
(* found — so the rule is recursive. The walk stops at Genesis, at a  *)
(* block the validator never stored (prefix-closed storage ⇒ that    *)
(* ancestor is unreachable, matching the engine's blocks.get gate),   *)
(* or at an already-committed height.                                 *)

RECURSIVE CommitChain(_, _)
CommitChain(i, b) ==
    IF b = Genesis
       \/ b \notin stored[i]
       \/ b.height \in {x.height : x \in committed[i]}
    THEN {}
    ELSE {b} \cup CommitChain(i, b.justify)

\* Whether the proposal's embedded TC releases a conflicting
\* per-height vote lock (engine.rs `proposal_tc_releases_lock`): the
\* TC must be the exact successor evidence for the proposal's view
\* (tcView + 1 = b.view) and be backed by a real quorum of timeout
\* signatures. The locked vote's view is always < b.view (enforced by
\* `votedView[i] < b.view`), so tcView = b.view - 1 automatically
\* covers it.
TCReleases(b) == b.tcView >= 0 /\ b.tcView = b.view - 1 /\ TCExists(b.tcView)

\* The committed anchor for a voter with no adopted QC: the engine
\* uses `last_committed` (post-rotation the chain continues), which
\* the model instantiates as Genesis — a node that has committed has
\* always adopted a QC first, so highQC = Genesis implies the anchor
\* is genesis.
Anchor(i) == Genesis

---------------------------------------------------------------------------
(* Initial state *)

Init ==
    /\ proposals   = {}
    /\ castVotes   = {}
    /\ timeoutSigs = {}
    /\ view        = [i \in Validators |-> 0]
    /\ highQC      = [i \in Validators |-> Genesis]
    /\ pending     = [i \in Validators |-> NoVal]
    /\ votedView   = [i \in Validators |-> -1]
    /\ votedAt     = [i \in Validators |-> <<>>]   \* empty function
    /\ stored      = [i \in Validators |-> {}]
    /\ committed   = [i \in Validators |-> {}]

---------------------------------------------------------------------------
(* Actions *)

\* Honest leader proposes at its current view: parent = own highQC
\* block (or the committed anchor when highQC = Genesis), height =
\* parent.height + 1 (height continuity — the stamp is DERIVED, not
\* chosen), justify = parent. The TC attached is the one that
\* justified entry into this view, when it exists.
HonestPropose(i) ==
    LET v == view[i]
        p == IF highQC[i] = Genesis THEN Anchor(i) ELSE highQC[i]
    IN  /\ i \in Honest
        /\ Leader(v) = i
        /\ v <= MaxView
        /\ p.height + 1 <= MaxHeight
        \* Engine: `propose` idles when the highQC block's header is
        \* not in `blocks` — a QC can be adopted before its block
        \* arrives, and an honest leader cannot stamp a valid height
        \* for a parent it has not seen.
        /\ p = Genesis \/ p \in stored[i]
        /\ \E tcv \in TCOptions(v) :
            LET nb == [view |-> v, height |-> p.height + 1, prev |-> p,
                       justify |-> p, tcView |-> tcv]
            IN  /\ nb \notin proposals
                /\ proposals' = proposals \cup {nb}
                /\ stored' = [stored EXCEPT ![i] = @ \cup {nb}]
        /\ UNCHANGED <<castVotes, timeoutSigs, view, highQC, pending,
                        votedView, votedAt, committed>>

\* Byzantine leader proposes an arbitrary block at view v: any notarized
\* claimed parent, any notarized justify target — INCLUDING a different
\* block than prev (crafted prev/justify divergence was the InvNoGap
\* counterexample; the fix makes honest voters reject it, so such
\* proposals can still be emitted here but can never be notarized) —
\* any stamped height (arbitrary stamps are still allowed — the FIX is
\* that voters now reject non-continuous ones), and any existing TC as
\* embedded evidence. Multiple variants per view model equivocation.
ByzPropose(i) ==
    /\ i \in Byzantine
    /\ \E v \in Views :
        /\ Leader(v) = i
        /\ PropCount(v) < MaxVariants
        /\ \E p \in proposals \cup {Genesis}, j \in proposals \cup {Genesis},
             h \in Heights, tcv \in ({-1} \cup {t \in Views : TCExists(t)}) :
              /\ Notarized(p) /\ Notarized(j)
              /\ LET nb == [view |-> v, height |-> h, prev |-> p, justify |-> j,
                            tcView |-> tcv]
                 IN  /\ nb \notin proposals
                    /\ proposals' = proposals \cup {nb}
    /\ UNCHANGED <<castVotes, timeoutSigs, view, highQC, pending,
                    votedView, votedAt, stored, committed>>

\* Honest vote — the full engine predicate (engine.rs vote()):
\*   b.view = view[i]                       (wrong-view proposals ignored)
\*   votedView[i] < b.view                  (one vote per view, monotonic)
\*   b.height = b.prev.height + 1           (HEIGHT CONTINUITY — the fix)
\*   votedAt[i][b.height] undefined or = b  (per-height lock) OR the
\*       proposal's TC is valid successor evidence for this view
\*       (lock release — recovers a timed-out split view)
\*   b.prev = b.justify                     (structural rule: a block
\*       extends exactly the block its embedded QC certifies — the
\*       commit rule walks justify edges, so decoupling prev from
\*       justify forks the stored chain from the committed chain)
\*   b.prev \in stored[i]                   (engine: `blocks.get` in
\*       the height-continuity check — storage is prefix-closed)
\*   highQC[i] # Genesis => b.prev = highQC[i] /\ b.justify.view >=
\*       highQC[i].view                     (tail-fork resistance)
\*   highQC[i] = Genesis  => b.prev = Genesis (committed anchor rule)
HonestVote(i, b) ==
    /\ IndividualVotes
    /\ i \in Honest
    /\ b \in proposals
    /\ b.view = view[i]
    /\ votedView[i] < b.view
    /\ b.height = b.prev.height + 1
    /\ b.prev = b.justify
    /\ b.prev \in stored[i] \/ b.prev = Genesis
    /\ \/ VotedAt(i, b.height) \in {NoVal, b}
       \/ TCReleases(b)
    /\ \/ (highQC[i] = Genesis /\ b.prev = Genesis)
       \/ (/\ highQC[i] # Genesis
           /\ b.prev = highQC[i]
           /\ b.justify # Genesis
           /\ b.justify.view >= highQC[i].view)
    /\ castVotes' = castVotes \cup {<<i, b>>}
    /\ votedView' = [votedView EXCEPT ![i] = b.view]
    /\ votedAt'   = [votedAt EXCEPT ![i] =
                        [h \in (DOMAIN votedAt[i]) \cup {b.height} |->
                            IF h = b.height THEN b ELSE votedAt[i][h]]]
    /\ stored'    = [stored EXCEPT ![i] = @ \cup {b}]
    /\ UNCHANGED <<proposals, timeoutSigs, view, highQC, pending, committed>>

\* Byzantine vote: sign anything, any view, as often as it likes.
ByzVote(i) ==
    /\ IndividualVotes
    /\ i \in Byzantine
    /\ \E b \in proposals : castVotes' = castVotes \cup {<<i, b>>}
    /\ UNCHANGED <<proposals, timeoutSigs, view, highQC, pending,
                    votedView, votedAt, stored, committed>>

\* Atomic quorum vote — a model-checking compression: an entire quorum
\* casts votes for b in one step. Each honest member must satisfy the
\* full vote predicate at THIS state; Byzantine members vote freely.
\* This is stricter than reality (a real voter's eligibility can lapse
\* between casting its vote and the QC completing) so the individual
\* HonestVote/ByzVote actions are kept as well — the union is a
\* superset of real behaviors, and this action provides the short
\* executions TLC needs to reach deep states.
HonestVoteOK(i, b) ==
    /\ b.view = view[i]
    /\ votedView[i] < b.view
    /\ b.height = b.prev.height + 1
    /\ b.prev = b.justify
    /\ b.prev \in stored[i] \/ b.prev = Genesis
    /\ \/ VotedAt(i, b.height) \in {NoVal, b}
       \/ TCReleases(b)
    /\ \/ (highQC[i] = Genesis /\ b.prev = Genesis)
       \/ (/\ highQC[i] # Genesis
           /\ b.prev = highQC[i]
           /\ b.justify # Genesis
           /\ b.justify.view >= highQC[i].view)

QuorumVote(b) ==
    /\ b \in proposals
    /\ ~HasQC(b)
    /\ \E Q \in SUBSET Validators :
        /\ Cardinality(Q) >= Quorum
        /\ \A i \in Q \cap Honest : HonestVoteOK(i, b)
        /\ castVotes' = castVotes \cup (Q \X {b})
        /\ votedView' = [i \in Validators |->
                            IF i \in Q \cap Honest THEN b.view ELSE votedView[i]]
        /\ votedAt'   = [i \in Validators |->
                            IF i \in Q \cap Honest
                            THEN [h \in (DOMAIN votedAt[i]) \cup {b.height} |->
                                     IF h = b.height THEN b ELSE votedAt[i][h]]
                            ELSE votedAt[i]]
        /\ stored'    = [i \in Validators |->
                            IF i \in Q \cap Honest THEN stored[i] \cup {b}
                            ELSE stored[i]]
        /\ UNCHANGED <<proposals, timeoutSigs, view, highQC, pending, committed>>

\* Adopt QC(b): engine `deliver_qc` — requires b.view > highQC[i].view
\* (monotonic, else StaleQc), sets highQC := b, catch-up jumps the view
\* to b.view + 1, and runs the two-chain commit: adopting QC(b) makes
\* b's justify target committable (child QC + embedded parent QC), so
\* the whole stored, uncommitted justify chain beneath it commits
\* (CommitChain). Committing prunes per-height locks <= the highest
\* newly committed height. Commit and pending are gated on
\* `b \in stored[i]` — the engine can only inspect justify edges of a
\* block whose header it holds; a QC for an unseen block updates
\* highQC/view but touches neither.
AdoptQC(i, b) ==
    /\ i \in Honest
    /\ HasQC(b)
    /\ b.view > highQC[i].view
    /\ highQC' = [highQC EXCEPT ![i] = b]
    /\ view'   = [view EXCEPT ![i] = IF b.view + 1 > @ THEN b.view + 1 ELSE @]
    /\ IF b \in stored[i]
       THEN /\ LET nc == CommitChain(i, b.justify)
               IN  /\ committed' = [committed EXCEPT ![i] = @ \cup nc]
                   /\ votedAt' = [votedAt EXCEPT ![i] =
                        IF nc = {}
                        THEN @
                        ELSE [h \in {x \in DOMAIN @ : x > MaxHeightOf(nc)} |->
                                @[h]]]
            /\ pending' = [pending EXCEPT ![i] = b]
       ELSE UNCHANGED <<committed, votedAt, pending>>
    /\ UNCHANGED <<proposals, castVotes, timeoutSigs, votedView, stored>>

\* Local timeout: honest validator signs its CURRENT view only.
HonestTimeout(i) ==
    /\ i \in Honest
    /\ view[i] <= MaxView
    /\ timeoutSigs' = timeoutSigs \cup {<<i, view[i]>>}
    /\ UNCHANGED <<proposals, castVotes, view, highQC, pending,
                    votedView, votedAt, stored, committed>>

\* Byzantine timeout: sign any view.
ByzTimeout(i) ==
    /\ i \in Byzantine
    /\ \E v \in Views : timeoutSigs' = timeoutSigs \cup {<<i, v>>}
    /\ UNCHANGED <<proposals, castVotes, view, highQC, pending,
                    votedView, votedAt, stored, committed>>

\* Deliver TC(v): accepted iff v >= view[i] (stale TCs rejected); the
\* pacemaker syncs to v then advances to v+1.
DeliverTC(i, v) ==
    /\ i \in Honest
    /\ TCExists(v)
    /\ v >= view[i]
    /\ view' = [view EXCEPT ![i] = v + 1]
    /\ UNCHANGED <<proposals, castVotes, timeoutSigs, highQC, pending,
                    votedView, votedAt, stored, committed>>

\* Happy-path advance (the driver calls advance_view after each completed
\* round — same effect as a TC for the current view).
AdvanceView(i) ==
    /\ FreeAdvance
    /\ i \in Honest
    /\ view[i] < MaxView
    /\ view' = [view EXCEPT ![i] = @ + 1]
    /\ UNCHANGED <<proposals, castVotes, timeoutSigs, highQC, pending,
                    votedView, votedAt, stored, committed>>

Next ==
    \/ \E i \in Validators : HonestPropose(i)
    \/ \E i \in Validators : ByzPropose(i)
    \/ \E i \in Validators, b \in proposals : HonestVote(i, b)
    \/ \E i \in Validators : ByzVote(i)
    \/ \E b \in proposals : QuorumVote(b)
    \/ \E i \in Validators, b \in proposals : AdoptQC(i, b)
    \/ \E i \in Validators : HonestTimeout(i)
    \/ \E i \in Validators : ByzTimeout(i)
    \/ \E i \in Validators, v \in Views : DeliverTC(i, v)
    \/ \E i \in Validators : AdvanceView(i)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

---------------------------------------------------------------------------
(* Justify-edge ancestry. Chains are finite and acyclic by construction:   *)
(* a block's justify target must be notarized when the block is proposed,  *)
(* so justify always points to an older-created block.                     *)

RECURSIVE IsAncestor(_, _)
IsAncestor(a, b) ==
    IF a = b THEN TRUE
    ELSE IF b = Genesis \/ b.justify = Genesis
         THEN a = Genesis
         ELSE IsAncestor(a, b.justify)

---------------------------------------------------------------------------
(* Invariants                                                              *)

\* THE safety property: the finalized map is keyed by stamped height — a
\* violation means two honest validators finalized different blocks at
\* the same height (a user-visible fork).
InvHeightConflict ==
    \A i, j \in Honest :
        \A b1 \in committed[i], b2 \in committed[j] :
            b1.height = b2.height => b1 = b2

\* Stronger chain-compatibility: every pair of committed blocks is
\* justify-comparable — all committed history lies on one chain.
InvSingleChain ==
    \A i, j \in Honest :
        \A b1 \in committed[i], b2 \in committed[j] :
            IsAncestor(b1, b2) \/ IsAncestor(b2, b1)

\* The invariant the forged-height bug violated: committed heights
\* per validator form a contiguous prefix starting at 0 — no block
\* may be finalized at a height the chain has not filled. Since all
\* committed heights are distinct (InvHeightConflict), the condition
\* "every committed height < the number committed" is exactly "the
\* committed set is {0..k-1} for some k".
InvNoGap ==
    \A i \in Honest :
        \A b \in committed[i] :
            b.height < Cardinality(committed[i])

\* Mechanism sanity: honest validators never cast two votes in one view.
InvOneVotePerView ==
    \A i \in Honest :
        \A b1, b2 \in proposals :
            (<<i, b1>> \in castVotes /\ <<i, b2>> \in castVotes /\
             b1.view = b2.view) => b1 = b2

\* At most one block is notarized per view — quorum intersection plus
\* one-vote-per-view, checked independently because Byzantine votes count
\* toward quorum.
InvQCUniqueness ==
    \A b1, b2 \in proposals :
        (b1.view = b2.view /\ HasQC(b1) /\ HasQC(b2)) => b1 = b2

\* Type sanity.
InvType ==
    /\ view \in [Validators -> 0..(MaxView+1)]
    /\ \A i \in Validators : committed[i] \subseteq proposals

===========================================================================
