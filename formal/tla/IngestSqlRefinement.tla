------------------------ MODULE IngestSqlRefinement ------------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Writers, Streams, Events, MaxSeq, NoWriter, NoEvent
ASSUME /\ Writers # {} /\ Streams # {} /\ Events # {}
       /\ NoWriter \notin Writers /\ NoEvent \notin Events
       /\ MaxSeq \in Nat

VARIABLES committedLog, committedHead, owner, phase, target, request,
          reserved, staged
vars == <<committedLog, committedHead, owner, phase, target, request,
          reserved, staged>>

Ids(xs) == {xs[i] : i \in 1..Len(xs)}
CommittedIds == UNION {Ids(committedLog[s]) : s \in Streams}

Init ==
  /\ committedLog = [s \in Streams |-> <<>>]
  /\ committedHead = [s \in Streams |-> 0]
  /\ owner = [s \in Streams |-> NoWriter]
  /\ phase = [w \in Writers |-> "idle"]
  /\ target \in [Writers -> Streams]
  /\ request \in [Writers -> Events]
  /\ reserved = [w \in Writers |-> FALSE]
  /\ staged = [w \in Writers |-> NoEvent]

\* A SELECT before the conflicting transaction commits can see no event.
Lookup(w, s, e) ==
  /\ w \in Writers /\ s \in Streams /\ e \in Events
  /\ phase[w] = "idle"
  /\ e \notin CommittedIds
  /\ phase' = [phase EXCEPT ![w] = "looked"]
  /\ target' = [target EXCEPT ![w] = s]
  /\ request' = [request EXCEPT ![w] = e]
  /\ UNCHANGED <<committedLog, committedHead, owner, reserved, staged>>

Reserve(w) ==
  /\ w \in Writers /\ phase[w] = "looked"
  /\ reserved' = [reserved EXCEPT ![w] = TRUE]
  /\ phase' = [phase EXCEPT ![w] = "reserved"]
  /\ UNCHANGED <<committedLog, committedHead, owner, target, request, staged>>

Lock(w) ==
  /\ w \in Writers /\ phase[w] = "reserved"
  /\ owner[target[w]] = NoWriter
  /\ owner' = [owner EXCEPT ![target[w]] = w]
  /\ phase' = [phase EXCEPT ![w] = "locked"]
  /\ UNCHANGED <<committedLog, committedHead, target, request, reserved, staged>>

Insert(w) ==
  /\ w \in Writers /\ phase[w] = "locked"
  /\ owner[target[w]] = w
  /\ request[w] \notin CommittedIds
  /\ committedHead[target[w]] < MaxSeq
  /\ staged' = [staged EXCEPT ![w] = request[w]]
  /\ phase' = [phase EXCEPT ![w] = "inserted"]
  /\ UNCHANGED <<committedLog, committedHead, owner, target, request, reserved>>

\* ON CONFLICT DO NOTHING may observe a concurrent unique-key winner after
\* the earlier lookup. A failed insert releases the provisional reservation.
Conflict(w) ==
  /\ w \in Writers /\ phase[w] = "locked"
  /\ owner[target[w]] = w
  /\ request[w] \in CommittedIds
  /\ reserved' = [reserved EXCEPT ![w] = FALSE]
  /\ owner' = [owner EXCEPT ![target[w]] = NoWriter]
  /\ phase' = [phase EXCEPT ![w] = "idle"]
  /\ UNCHANGED <<committedLog, committedHead, target, request, staged>>

\* The SQL transaction makes its event row and counter update visible together.
Commit(w) ==
  /\ w \in Writers /\ phase[w] = "inserted"
  /\ owner[target[w]] = w
  /\ staged[w] \notin CommittedIds
  /\ committedHead[target[w]] < MaxSeq
  /\ committedLog' = [committedLog EXCEPT ![target[w]] = Append(@, staged[w])]
  /\ committedHead' = [committedHead EXCEPT ![target[w]] = @ + 1]
  /\ owner' = [owner EXCEPT ![target[w]] = NoWriter]
  /\ phase' = [phase EXCEPT ![w] = "idle"]
  /\ reserved' = [reserved EXCEPT ![w] = FALSE]
  /\ staged' = [staged EXCEPT ![w] = NoEvent]
  /\ UNCHANGED <<target, request>>

Abort(w) ==
  /\ w \in Writers /\ phase[w] \in {"looked", "reserved", "locked", "inserted"}
  /\ owner' = IF phase[w] \in {"locked", "inserted"}
               THEN [owner EXCEPT ![target[w]] = NoWriter] ELSE owner
  /\ phase' = [phase EXCEPT ![w] = "idle"]
  /\ reserved' = [reserved EXCEPT ![w] = FALSE]
  /\ staged' = [staged EXCEPT ![w] = NoEvent]
  /\ UNCHANGED <<committedLog, committedHead, target, request>>

Next ==
  \/ \E w \in Writers, s \in Streams, e \in Events : Lookup(w, s, e)
  \/ \E w \in Writers :
       Reserve(w) \/ Lock(w) \/ Insert(w) \/ Conflict(w) \/ Commit(w) \/ Abort(w)
  \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

Abstract == INSTANCE SequencerIngest
  WITH Streams <- Streams, Events <- Events, MaxSeq <- MaxSeq,
       log <- committedLog, head <- committedHead
RefinesIngest == Abstract!Spec

TypeOK ==
  /\ committedLog \in [Streams -> Seq(Events)]
  /\ committedHead \in [Streams -> 0..MaxSeq]
  /\ owner \in [Streams -> Writers \cup {NoWriter}]
  /\ phase \in [Writers -> {"idle", "looked", "reserved", "locked", "inserted"}]
  /\ target \in [Writers -> Streams]
  /\ request \in [Writers -> Events]
  /\ reserved \in [Writers -> BOOLEAN]
  /\ staged \in [Writers -> Events \cup {NoEvent}]
LockSound == \A w \in Writers :
  phase[w] \in {"locked", "inserted"} => owner[target[w]] = w
StagingSound == \A w \in Writers :
  phase[w] = "inserted" => staged[w] = request[w]

=============================================================================
