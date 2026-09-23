------------------------- MODULE ExternalEffectFencing ------------------------
EXTENDS Integers
CONSTANTS Workers
ASSUME Workers # {}
VARIABLES leader, pending, effectCount, finalized
vars == <<leader, pending, effectCount, finalized>>
Init == /\ leader = "none" /\ pending = {}
        /\ effectCount = 0 /\ finalized = FALSE
Elect(w) == /\ w \in Workers /\ leader = "none" /\ leader' = w
            /\ UNCHANGED <<pending, effectCount, finalized>>
Lose(w) == /\ leader = w /\ leader' = "none"
           /\ UNCHANGED <<pending, effectCount, finalized>>
Prepare(w) == /\ leader = w /\ pending' = pending \cup {w}
              /\ UNCHANGED <<leader, effectCount, finalized>>
\* Destination idempotency is keyed by immutable batch ID. A stale worker may
\* retry after lease loss; the destination records only one effect.
Submit(w) == /\ w \in pending
             /\ effectCount' = IF effectCount = 0 THEN 1 ELSE effectCount
             /\ pending' = pending \ {w}
             /\ UNCHANGED <<leader, finalized>>
Reconcile == /\ effectCount = 1 /\ finalized' = TRUE
             /\ UNCHANGED <<leader, pending, effectCount>>
Next == (\E w \in Workers : Elect(w) \/ Lose(w) \/ Prepare(w) \/ Submit(w))
        \/ Reconcile \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars
FinalitySound == finalized => effectCount = 1
DestinationAtMostOnce == effectCount <= 1
=============================================================================
