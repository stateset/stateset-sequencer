---------------------------- MODULE CrashRecovery ---------------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Events, NoEvent
ASSUME /\ IsFiniteSet(Events) /\ Events # {} /\ NoEvent \notin Events

VARIABLES ledger, receipts, outbox, draft, projected, checkpoint,
          projectionDraft, workerUp
vars == <<ledger, receipts, outbox, draft, projected, checkpoint,
          projectionDraft, workerUp>>

Ids(xs) == {xs[i] : i \in 1..Len(xs)}
Init ==
  /\ ledger = <<>> /\ receipts = {} /\ outbox = [e \in Events |-> "absent"]
  /\ draft = NoEvent /\ projected = {} /\ checkpoint = 0
  /\ projectionDraft = NoEvent /\ workerUp = TRUE

BeginIngest(e) ==
  /\ workerUp /\ draft = NoEvent /\ e \in Events /\ e \notin receipts
  /\ draft' = e
  /\ UNCHANGED <<ledger, receipts, outbox, projected, checkpoint,
                 projectionDraft, workerUp>>
\* The ledger insert, receipt, and outbox row commit in one transaction.
CommitIngest ==
  /\ workerUp /\ draft # NoEvent
  /\ ledger' = Append(ledger, draft)
  /\ receipts' = receipts \cup {draft}
  /\ outbox' = [outbox EXCEPT ![draft] = "queued"]
  /\ draft' = NoEvent
  /\ UNCHANGED <<projected, checkpoint, projectionDraft, workerUp>>
Send(e) ==
  /\ workerUp /\ e \in receipts /\ outbox[e] = "queued"
  /\ outbox' = [outbox EXCEPT ![e] = "sent"]
  /\ UNCHANGED <<ledger, receipts, draft, projected, checkpoint,
                 projectionDraft, workerUp>>
Ack(e) ==
  /\ workerUp /\ e \in receipts /\ outbox[e] = "sent"
  /\ outbox' = [outbox EXCEPT ![e] = "acked"]
  /\ UNCHANGED <<ledger, receipts, draft, projected, checkpoint,
                 projectionDraft, workerUp>>
BeginProjection ==
  /\ workerUp /\ projectionDraft = NoEvent /\ checkpoint < Len(ledger)
  /\ projectionDraft' = ledger[checkpoint + 1]
  /\ UNCHANGED <<ledger, receipts, outbox, draft, projected,
                 checkpoint, workerUp>>
\* Documents and checkpoint commit atomically. A crash before this step
\* rolls both back; after this step a retry skips the committed prefix.
CommitProjection ==
  /\ workerUp /\ projectionDraft # NoEvent
  /\ projectionDraft = ledger[checkpoint + 1]
  /\ projected' = projected \cup {projectionDraft}
  /\ checkpoint' = checkpoint + 1
  /\ projectionDraft' = NoEvent
  /\ UNCHANGED <<ledger, receipts, outbox, draft, workerUp>>
Crash ==
  /\ workerUp
  /\ workerUp' = FALSE /\ draft' = NoEvent /\ projectionDraft' = NoEvent
  /\ UNCHANGED <<ledger, receipts, outbox, projected, checkpoint>>
Restart ==
  /\ ~workerUp
  /\ workerUp' = TRUE
  /\ UNCHANGED <<ledger, receipts, outbox, draft, projected,
                 checkpoint, projectionDraft>>

Next ==
  \/ \E e \in Events : BeginIngest(e) \/ Send(e) \/ Ack(e)
  \/ CommitIngest \/ BeginProjection \/ CommitProjection
  \/ Crash \/ Restart \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ ledger \in Seq(Events) /\ receipts \subseteq Events
  /\ outbox \in [Events -> {"absent", "queued", "sent", "acked"}]
  /\ draft \in Events \cup {NoEvent}
  /\ projectionDraft \in Events \cup {NoEvent}
  /\ projected \subseteq Events /\ checkpoint \in 0..Cardinality(Events)
  /\ workerUp \in BOOLEAN
ReceiptAtomic == receipts = Ids(ledger)
NoDuplicate == Cardinality(Ids(ledger)) = Len(ledger)
OutboxDurable == \A e \in Events : (outbox[e] # "absent") <=> e \in receipts
ProjectionPrefix == projected = {ledger[i] : i \in 1..checkpoint}

=============================================================================
