---------------------- MODULE CommandReservationRace -----------------------
EXTENDS FiniteSets

CONSTANTS Streams, NoStream
ASSUME /\ Cardinality(Streams) = 2
       /\ NoStream \notin Streams

\* Both streams submit the same globally unique event ID and the same
\* command ID. Each stream's command reservation is scoped to that stream.
VARIABLES eventOwner, reserved, phase
vars == <<eventOwner, reserved, phase>>

Init ==
  /\ eventOwner = NoStream
  /\ reserved = [s \in Streams |-> FALSE]
  /\ phase = [s \in Streams |-> "idle"]

\* Each ingest first sees the event ID as missing.
Begin(s) ==
  /\ s \in Streams /\ phase[s] = "idle"
  /\ eventOwner = NoStream
  /\ phase' = [phase EXCEPT ![s] = "looked"]
  /\ UNCHANGED <<eventOwner, reserved>>

Reserve(s) ==
  /\ s \in Streams /\ phase[s] = "looked"
  /\ reserved' = [reserved EXCEPT ![s] = TRUE]
  /\ phase' = [phase EXCEPT ![s] = "reserved"]
  /\ UNCHANGED eventOwner

Commit(s) ==
  /\ s \in Streams /\ phase[s] = "reserved"
  /\ eventOwner = NoStream
  /\ eventOwner' = s
  /\ phase' = [phase EXCEPT ![s] = "done"]
  /\ UNCHANGED reserved

\* The loser may see the same command ID on the winner's event. It must
\* compare the stream as well before deciding whether to keep its row.
Duplicate(s) ==
  /\ s \in Streams /\ phase[s] = "reserved"
  /\ eventOwner \in Streams \ {s}
  /\ reserved' = [reserved EXCEPT ![s] = FALSE]
  /\ phase' = [phase EXCEPT ![s] = "done"]
  /\ UNCHANGED eventOwner

Abort(s) ==
  /\ s \in Streams /\ phase[s] \in {"looked", "reserved"}
  /\ reserved' = [reserved EXCEPT ![s] = FALSE]
  /\ phase' = [phase EXCEPT ![s] = "done"]
  /\ UNCHANGED eventOwner

Next == (\E s \in Streams :
  Begin(s) \/ Reserve(s) \/ Commit(s) \/ Duplicate(s) \/ Abort(s))
  \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ eventOwner \in Streams \cup {NoStream}
  /\ reserved \in [Streams -> BOOLEAN]
  /\ phase \in [Streams -> {"idle", "looked", "reserved", "done"}]
NoOrphanReservation == \A s \in Streams :
  reserved[s] => (phase[s] = "reserved" \/ eventOwner = s)
OnlyWinnerKeepsCommittedCommand == \A s \in Streams :
  phase[s] = "done" /\ reserved[s] => eventOwner = s

=============================================================================
