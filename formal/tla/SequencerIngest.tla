-------------------------- MODULE SequencerIngest --------------------------
EXTENDS FiniteSets, Integers, Sequences, TLC

CONSTANTS Streams, Events, MaxSeq
Batches == {<<e>> : e \in Events} \cup
           {<<e, f>> : e \in Events, f \in Events}
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
\* Batches are the finite, configured outcomes after validation/rejection.
Commit(s, batch) ==
  /\ s \in Streams
  /\ batch \in Batches
  /\ Len(batch) > 0
  /\ Cardinality(SeqSet(batch)) = Len(batch)
  /\ SeqSet(batch) \cap Committed = {}
  /\ head[s] + Len(batch) <= MaxSeq
  /\ log' = [log EXCEPT ![s] = @ \o batch]
  /\ head' = [head EXCEPT ![s] = @ + Len(batch)]

\* Rejection, replay, and rollback have no committed effect.
NoCommit == UNCHANGED vars
Next == (\E s \in Streams, batch \in Batches : Commit(s, batch)) \/ NoCommit
Spec == Init /\ [][Next]_vars

TypeOK == /\ log \in [Streams -> Seq(Events)]
          /\ head \in [Streams -> Nat]
HeadMatches == \A s \in Streams : head[s] = Len(log[s])
Bounded == \A s \in Streams : head[s] <= MaxSeq
NoDuplicateIds ==
  /\ \A s \in Streams : Cardinality(SeqSet(log[s])) = Len(log[s])
  /\ \A s, t \in Streams : s # t => SeqSet(log[s]) \cap SeqSet(log[t]) = {}

=============================================================================
