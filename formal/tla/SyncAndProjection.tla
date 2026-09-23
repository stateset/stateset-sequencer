-------------------------- MODULE SyncAndProjection ------------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Events
ASSUME /\ Events # {} /\ IsFiniteSet(Events)

VARIABLES outbox, remote, ackSequence, cursor, projected, checkpoint
vars == <<outbox, remote, ackSequence, cursor, projected, checkpoint>>

Ids(xs) == {xs[i] : i \in 1..Len(xs)}
Position(e) == CHOOSE i \in 1..Len(remote) : remote[i] = e

Init ==
  /\ outbox = [e \in Events |-> "queued"]
  /\ remote = <<>>
  /\ ackSequence = [e \in Events |-> 0]
  /\ cursor = 0
  /\ projected = {}
  /\ checkpoint = 0

Push(e) ==
  /\ e \in Events /\ outbox[e] = "queued"
  /\ outbox' = [outbox EXCEPT ![e] = "sent"]
  /\ UNCHANGED <<remote, ackSequence, cursor, projected, checkpoint>>

\* A retry may deliver the same event again; remote event ID dedupe prevents
\* a second append. The outbox remains durable across a process restart.
Accept(e) ==
  /\ e \in Events /\ outbox[e] = "sent"
  /\ e \notin Ids(remote)
  /\ remote' = Append(remote, e)
  /\ UNCHANGED <<outbox, ackSequence, cursor, projected, checkpoint>>

Ack(e) ==
  /\ e \in Events /\ outbox[e] = "sent"
  /\ e \in Ids(remote)
  /\ outbox' = [outbox EXCEPT ![e] = "acked"]
  /\ ackSequence' = [ackSequence EXCEPT ![e] = Position(e)]
  /\ UNCHANGED <<remote, cursor, projected, checkpoint>>

Prune(e) ==
  /\ e \in Events /\ outbox[e] = "acked"
  /\ outbox' = [outbox EXCEPT ![e] = "pruned"]
  /\ UNCHANGED <<remote, ackSequence, cursor, projected, checkpoint>>

AdvanceCursor(n) ==
  /\ n \in 0..Len(remote)
  /\ cursor' = IF n > cursor THEN n ELSE cursor
  /\ UNCHANGED <<outbox, remote, ackSequence, projected, checkpoint>>

\* Applying a document and its checkpoint in one projection transaction.
Project ==
  /\ checkpoint < Len(remote)
  /\ projected' = projected \cup {remote[checkpoint + 1]}
  /\ checkpoint' = checkpoint + 1
  /\ UNCHANGED <<outbox, remote, ackSequence, cursor>>

Next ==
  \/ \E e \in Events : Push(e) \/ Accept(e) \/ Ack(e) \/ Prune(e)
  \/ \E n \in 0..Len(remote) : AdvanceCursor(n)
  \/ Project
  \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ outbox \in [Events -> {"queued", "sent", "acked", "pruned"}]
  /\ remote \in Seq(Events)
  /\ ackSequence \in [Events -> 0..Cardinality(Events)]
  /\ cursor \in 0..Cardinality(Events)
  /\ projected \subseteq Events
  /\ checkpoint \in 0..Cardinality(Events)
RemoteUnique == Cardinality(Ids(remote)) = Len(remote)
AckSound == \A e \in Events :
  outbox[e] \in {"acked", "pruned"} =>
    e \in Ids(remote) /\ ackSequence[e] = Position(e)
PruneSound == \A e \in Events : outbox[e] = "pruned" => ackSequence[e] > 0
CursorBounded == cursor <= Len(remote)
ProjectionPrefix ==
  /\ checkpoint <= Len(remote)
  /\ projected = {remote[i] : i \in 1..checkpoint}

=============================================================================
