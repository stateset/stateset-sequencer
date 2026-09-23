---------------------------- MODULE CacheReorgSafety ---------------------------
EXTENDS Integers, Sequences
CONSTANTS Roots, MaxReads
ASSUME /\ Roots # {} /\ MaxReads \in Nat \ {0}
VARIABLES root, anchored, cachedRoot, cachedAnchored, responses
vars == <<root, anchored, cachedRoot, cachedAnchored, responses>>
Init == /\ root \in Roots /\ anchored = FALSE
        /\ cachedRoot = root /\ cachedAnchored = FALSE
        /\ responses = <<>>
Anchor == /\ ~anchored /\ anchored' = TRUE
          /\ UNCHANGED <<root, cachedRoot, cachedAnchored, responses>>
Reorg == /\ anchored /\ anchored' = FALSE
         /\ UNCHANGED <<root, cachedRoot, cachedAnchored, responses>>
Refresh == /\ cachedRoot' = root /\ cachedAnchored' = anchored
           /\ UNCHANGED <<root, anchored, responses>>
Read(indexMatches, proofRoot) ==
  /\ indexMatches \in BOOLEAN /\ proofRoot \in Roots
  /\ Len(responses) < MaxReads
  /\ responses' = Append(responses,
       [root |-> root, anchored |-> anchored,
        proofAccepted |-> (indexMatches /\ proofRoot = root),
        proofRoot |-> proofRoot, indexMatches |-> indexMatches])
  /\ UNCHANGED <<root, anchored, cachedRoot, cachedAnchored>>
Next == Anchor \/ Reorg \/ Refresh
        \/ (\E i \in BOOLEAN, r \in Roots : Read(i, r))
        \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars
ProofSound == \A i \in 1..Len(responses) :
  responses[i].proofAccepted =>
    (responses[i].proofRoot = responses[i].root /\ responses[i].indexMatches)
=============================================================================
