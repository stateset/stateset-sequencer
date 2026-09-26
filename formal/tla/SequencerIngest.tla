-------------------------- MODULE SequencerIngest --------------------------
EXTENDS FiniteSets, Integers, Sequences, TLC

CONSTANTS Streams, Events, MaxSeq
Batches == {<<e>> : e \in Events} \cup
           {<<e, f>> : e \in Events, f \in Events}
\* The accepted members retain request order. Validation, replay, or version
\* checks may discard either member of a two-event request.
AcceptedFrom(request) ==
  IF Len(request) = 1
  THEN {<<>>, request}
  ELSE {<<>>, <<request[1]>>, <<request[2]>>, request}
ASSUME /\ Streams # {}
       /\ Events # {}
       /\ MaxSeq \in Nat

VARIABLES log, head
vars == <<log, head>>

SeqSet(xs) == {xs[i] : i \in 1..Len(xs)}
Committed == UNION {SeqSet(log[s]) : s \in Streams}

Init == /\ log = [s \in Streams |-> <<>>]
        /\ head = [s \in Streams |-> 0]

\* A PostgreSQL transaction holds the stream counter lock, accepts the
\* eligible members of a request, then atomically commits log and counter.
\* Capacity is charged to accepted members, not every submitted candidate.
Commit(s, request, accepted) ==
  /\ s \in Streams
  /\ request \in Batches
  /\ accepted \in AcceptedFrom(request)
  /\ Len(accepted) > 0
  /\ Cardinality(SeqSet(accepted)) = Len(accepted)
  /\ SeqSet(accepted) \cap Committed = {}
  /\ head[s] + Len(accepted) <= MaxSeq
  /\ log' = [log EXCEPT ![s] = @ \o accepted]
  /\ head' = [head EXCEPT ![s] = @ + Len(accepted)]

\* Rejection, replay, and rollback have no committed effect.
NoCommit == UNCHANGED vars
Next == (\E s \in Streams : \E request \in Batches :
           \E accepted \in AcceptedFrom(request) : Commit(s, request, accepted))
        \/ NoCommit
Spec == Init /\ [][Next]_vars

TypeOK == /\ log \in [Streams -> Seq(Events)]
          /\ head \in [Streams -> Nat]
HeadMatches == \A s \in Streams : head[s] = Len(log[s])
Bounded == \A s \in Streams : head[s] <= MaxSeq
NoDuplicateIds ==
  /\ \A s \in Streams : Cardinality(SeqSet(log[s])) = Len(log[s])
  /\ \A s, t \in Streams : s # t => SeqSet(log[s]) \cap SeqSet(log[t]) = {}

=============================================================================
