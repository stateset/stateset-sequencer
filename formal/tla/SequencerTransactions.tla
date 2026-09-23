----------------------- MODULE SequencerTransactions -----------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Writers, Streams, Events, MaxSeq, NoWriter
ASSUME /\ Writers # {}
       /\ Streams # {}
       /\ Events # {}
       /\ NoWriter \notin Writers
       /\ MaxSeq \in Nat

VARIABLES log, head, owner, phase, target, request, staged
vars == <<log, head, owner, phase, target, request, staged>>

SeqSet(xs) == {xs[i] : i \in 1..Len(xs)}
Committed == UNION {SeqSet(log[s]) : s \in Streams}

Init ==
  /\ log = [s \in Streams |-> <<>>]
  /\ head = [s \in Streams |-> 0]
  /\ owner = [s \in Streams |-> NoWriter]
  /\ phase = [w \in Writers |-> "idle"]
  /\ target \in [Writers -> Streams]
  /\ request \in [Writers -> Events]
  /\ staged = [w \in Writers |-> <<>>]

Start(w, s, e) ==
  /\ w \in Writers /\ s \in Streams /\ e \in Events
  /\ phase[w] = "idle"
  /\ phase' = [phase EXCEPT ![w] = "ready"]
  /\ target' = [target EXCEPT ![w] = s]
  /\ request' = [request EXCEPT ![w] = e]
  /\ UNCHANGED <<log, head, owner, staged>>

Lock(w) ==
  /\ w \in Writers
  /\ phase[w] = "ready"
  /\ owner[target[w]] = NoWriter
  /\ owner' = [owner EXCEPT ![target[w]] = w]
  /\ phase' = [phase EXCEPT ![w] = "locked"]
  /\ UNCHANGED <<log, head, target, request, staged>>

Accept(w) ==
  /\ w \in Writers
  /\ phase[w] = "locked"
  /\ owner[target[w]] = w
  /\ request[w] \notin Committed
  /\ head[target[w]] < MaxSeq
  /\ staged' = [staged EXCEPT ![w] = <<request[w]>>]
  /\ phase' = [phase EXCEPT ![w] = "done"]
  /\ UNCHANGED <<log, head, owner, target, request>>

\* Validation failure, duplicate event, or version conflict.
Reject(w) ==
  /\ w \in Writers
  /\ phase[w] = "locked"
  /\ owner[target[w]] = w
  /\ phase' = [phase EXCEPT ![w] = "done"]
  /\ UNCHANGED <<log, head, owner, target, request, staged>>

Commit(w) ==
  /\ w \in Writers
  /\ phase[w] = "done"
  /\ owner[target[w]] = w
  /\ SeqSet(staged[w]) \cap Committed = {}
  /\ head[target[w]] + Len(staged[w]) <= MaxSeq
  /\ log' = [log EXCEPT ![target[w]] = @ \o staged[w]]
  /\ head' = [head EXCEPT ![target[w]] = @ + Len(staged[w])]
  /\ owner' = [owner EXCEPT ![target[w]] = NoWriter]
  /\ phase' = [phase EXCEPT ![w] = "idle"]
  /\ staged' = [staged EXCEPT ![w] = <<>>]
  /\ UNCHANGED <<target, request>>

\* A failed transaction discards its staged insert and releases its lock.
Abort(w) ==
  /\ w \in Writers
  /\ phase[w] \in {"ready", "locked", "done"}
  /\ owner' = IF phase[w] = "ready" THEN owner
               ELSE [owner EXCEPT ![target[w]] = NoWriter]
  /\ phase' = [phase EXCEPT ![w] = "idle"]
  /\ staged' = [staged EXCEPT ![w] = <<>>]
  /\ UNCHANGED <<log, head, target, request>>

Next ==
  \/ \E w \in Writers, s \in Streams, e \in Events : Start(w, s, e)
  \/ \E w \in Writers : Lock(w) \/ Accept(w) \/ Reject(w) \/ Commit(w) \/ Abort(w)
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ log \in [Streams -> Seq(Events)]
  /\ head \in [Streams -> Nat]
  /\ owner \in [Streams -> (Writers \cup {NoWriter})]
  /\ phase \in [Writers -> {"idle", "ready", "locked", "done"}]
  /\ target \in [Writers -> Streams]
  /\ request \in [Writers -> Events]
  /\ staged \in [Writers -> Seq(Events)]

HeadMatches == \A s \in Streams : head[s] = Len(log[s])
Bounded == \A s \in Streams : head[s] <= MaxSeq
NoDuplicateIds ==
  /\ \A s \in Streams : Cardinality(SeqSet(log[s])) = Len(log[s])
  /\ \A s, t \in Streams : s # t => SeqSet(log[s]) \cap SeqSet(log[t]) = {}
LockExclusive ==
  \A w \in Writers : phase[w] \in {"locked", "done"} => owner[target[w]] = w

=============================================================================
