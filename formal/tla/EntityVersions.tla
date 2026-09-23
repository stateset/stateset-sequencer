-------------------------- MODULE EntityVersions ---------------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Writers, Streams, Entities, MaxSeq, NoWriter
ASSUME /\ Writers # {} /\ Streams # {} /\ Entities # {}
       /\ NoWriter \notin Writers /\ MaxSeq \in Nat

VARIABLES log, head, version, owner, phase, target, entity, expected, last
vars == <<log, head, version, owner, phase, target, entity, expected, last>>

CountOf(xs, e) == Cardinality({i \in 1..Len(xs) : xs[i] = e})

Init ==
  /\ log = [s \in Streams |-> <<>>]
  /\ head = [s \in Streams |-> 0]
  /\ version = [s \in Streams |-> [e \in Entities |-> 0]]
  /\ owner = [s \in Streams |-> NoWriter]
  /\ phase = [w \in Writers |-> "idle"]
  /\ target = [w \in Writers |-> CHOOSE s \in Streams : TRUE]
  /\ entity = [w \in Writers |-> CHOOSE e \in Entities : TRUE]
  /\ expected = [w \in Writers |-> 0]
  /\ last = [kind |-> "idle", expected |-> 0, actual |-> 0, sequence |-> 0]

Start(w, s, e, base) ==
  /\ w \in Writers /\ s \in Streams /\ e \in Entities
  /\ base \in 0..MaxSeq
  /\ phase[w] = "idle"
  /\ phase' = [phase EXCEPT ![w] = "ready"]
  /\ target' = [target EXCEPT ![w] = s]
  /\ entity' = [entity EXCEPT ![w] = e]
  /\ expected' = [expected EXCEPT ![w] = base]
  /\ UNCHANGED <<log, head, version, owner, last>>

Lock(w) ==
  /\ w \in Writers /\ phase[w] = "ready"
  /\ owner[target[w]] = NoWriter
  /\ owner' = [owner EXCEPT ![target[w]] = w]
  /\ phase' = [phase EXCEPT ![w] = "locked"]
  /\ UNCHANGED <<log, head, version, target, entity, expected, last>>

\* The version comparison, insert, version bump, and counter bump commit
\* together under the per-stream lock.
Apply(w) ==
  /\ w \in Writers /\ phase[w] = "locked"
  /\ owner[target[w]] = w
  /\ expected[w] = version[target[w]][entity[w]]
  /\ head[target[w]] < MaxSeq
  /\ log' = [log EXCEPT ![target[w]] = Append(@, entity[w])]
  /\ head' = [head EXCEPT ![target[w]] = @ + 1]
  /\ version' = [version EXCEPT ![target[w]][entity[w]] = @ + 1]
  /\ owner' = [owner EXCEPT ![target[w]] = NoWriter]
  /\ phase' = [phase EXCEPT ![w] = "idle"]
  /\ last' = [kind |-> "accepted", expected |-> expected[w],
              actual |-> version[target[w]][entity[w]],
              sequence |-> head[target[w]] + 1]
  /\ UNCHANGED <<target, entity, expected>>

Conflict(w) ==
  /\ w \in Writers /\ phase[w] = "locked"
  /\ owner[target[w]] = w
  /\ expected[w] # version[target[w]][entity[w]]
  /\ owner' = [owner EXCEPT ![target[w]] = NoWriter]
  /\ phase' = [phase EXCEPT ![w] = "idle"]
  /\ last' = [kind |-> "conflict", expected |-> expected[w],
              actual |-> version[target[w]][entity[w]], sequence |-> 0]
  /\ UNCHANGED <<log, head, version, target, entity, expected>>

Abort(w) ==
  /\ w \in Writers /\ phase[w] \in {"ready", "locked"}
  /\ owner' = IF phase[w] = "ready" THEN owner
               ELSE [owner EXCEPT ![target[w]] = NoWriter]
  /\ phase' = [phase EXCEPT ![w] = "idle"]
  /\ last' = [kind |-> "aborted", expected |-> expected[w],
              actual |-> 0, sequence |-> 0]
  /\ UNCHANGED <<log, head, version, target, entity, expected>>

Next ==
  \/ \E w \in Writers, s \in Streams, e \in Entities,
         base \in 0..MaxSeq : Start(w, s, e, base)
  \/ \E w \in Writers : Lock(w) \/ Apply(w) \/ Conflict(w) \/ Abort(w)
  \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ log \in [Streams -> Seq(Entities)]
  /\ head \in [Streams -> 0..MaxSeq]
  /\ version \in [Streams -> [Entities -> 0..MaxSeq]]
  /\ owner \in [Streams -> Writers \cup {NoWriter}]
  /\ phase \in [Writers -> {"idle", "ready", "locked"}]
  /\ target \in [Writers -> Streams]
  /\ entity \in [Writers -> Entities]
  /\ expected \in [Writers -> 0..MaxSeq]

HeadMatches == \A s \in Streams : head[s] = Len(log[s])
VersionsMatch == \A s \in Streams : \A e \in Entities :
  version[s][e] = CountOf(log[s], e)
LockExclusive == \A w \in Writers : phase[w] = "locked" =>
  owner[target[w]] = w
OutcomeSound ==
  /\ (last.kind = "conflict" =>
        last.expected # last.actual /\ last.sequence = 0)
  /\ (last.kind = "accepted" =>
        last.expected = last.actual /\ last.sequence > 0)

=============================================================================
