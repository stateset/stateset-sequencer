---------------------- MODULE WalPointInTimeRecovery ----------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Events, Receipts, MaxEntries
ASSUME /\ IsFiniteSet(Events) /\ Events # {}
       /\ IsFiniteSet(Receipts) /\ Receipts # {}
       /\ MaxEntries \in Nat

Entries == [event : Events, receipt : Receipts]
EventIds(xs) == {xs[i].event : i \in 1..Len(xs)}
ReceiptIds(xs) == {xs[i].receipt : i \in 1..Len(xs)}
Prefix(xs, count) == SubSeq(xs, 1, count)

VARIABLES wal, archived, base, backedUp, target, targetSet,
          recovered, restoring, promoted
vars == <<wal, archived, base, backedUp, target, targetSet,
          recovered, restoring, promoted>>

Init ==
  /\ wal = <<>> /\ archived = <<>> /\ base = <<>>
  /\ backedUp = FALSE /\ target = 0 /\ targetSet = FALSE
  /\ recovered = <<>> /\ restoring = FALSE /\ promoted = FALSE

\* One committed PostgreSQL transaction writes an event and its receipt.
\* The WAL entry represents their atomic durable database state.
Commit(entry) ==
  /\ entry \in Entries
  /\ Len(wal) < MaxEntries
  /\ entry.event \notin EventIds(wal)
  /\ entry.receipt \notin ReceiptIds(wal)
  /\ wal' = Append(wal, entry)
  /\ UNCHANGED <<archived, base, backedUp, target, targetSet,
                 recovered, restoring, promoted>>

\* A physical backup captures a consistent prefix of committed WAL entries.
TakeBase ==
  /\ ~backedUp
  /\ base' = wal /\ backedUp' = TRUE
  /\ UNCHANGED <<wal, archived, target, targetSet,
                 recovered, restoring, promoted>>

\* The named recovery target follows the last acknowledged commit to retain.
ChooseTarget ==
  /\ backedUp /\ ~targetSet
  /\ target' = Len(wal) /\ targetSet' = TRUE
  /\ UNCHANGED <<wal, archived, base, backedUp,
                 recovered, restoring, promoted>>

\* Archiving may lag behind commits but publishes only complete WAL records,
\* in order and without changing their bytes.
ArchiveNext ==
  /\ Len(archived) < Len(wal)
  /\ archived' = Append(archived, wal[Len(archived) + 1])
  /\ UNCHANGED <<wal, base, backedUp, target, targetSet,
                 recovered, restoring, promoted>>

\* Recovery cannot start until the archive covers the chosen target.
StartRestore ==
  /\ targetSet /\ ~restoring
  /\ Len(archived) >= target
  /\ recovered' = base /\ restoring' = TRUE
  /\ UNCHANGED <<wal, archived, base, backedUp, target, targetSet, promoted>>

ReplayNext ==
  /\ restoring /\ ~promoted
  /\ Len(recovered) < target
  /\ recovered' = Append(recovered, archived[Len(recovered) + 1])
  /\ UNCHANGED <<wal, archived, base, backedUp, target,
                 targetSet, restoring, promoted>>

Promote ==
  /\ restoring /\ ~promoted /\ Len(recovered) = target
  /\ promoted' = TRUE
  /\ UNCHANGED <<wal, archived, base, backedUp, target,
                 targetSet, recovered, restoring>>

Next ==
  \/ \E entry \in Entries : Commit(entry)
  \/ TakeBase \/ ChooseTarget \/ ArchiveNext
  \/ StartRestore \/ ReplayNext \/ Promote
  \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ wal \in Seq(Entries) /\ archived \in Seq(Entries)
  /\ base \in Seq(Entries) /\ recovered \in Seq(Entries)
  /\ backedUp \in BOOLEAN /\ targetSet \in BOOLEAN
  /\ restoring \in BOOLEAN /\ promoted \in BOOLEAN
  /\ target \in 0..MaxEntries
UniqueCommitted ==
  /\ Cardinality(EventIds(wal)) = Len(wal)
  /\ Cardinality(ReceiptIds(wal)) = Len(wal)
ArchivePrefix == archived = Prefix(wal, Len(archived))
BasePrefix == backedUp => base = Prefix(wal, Len(base))
TargetAfterBase == targetSet => Len(base) <= target
RecoveryPrefix == restoring =>
  /\ recovered = Prefix(wal, Len(recovered))
  /\ Len(recovered) <= target
\* Includes receipt bytes because each entry contains the receipt as well as
\* the event. In particular, later commits cannot appear in the restored DB.
PromotedExactTarget == promoted => recovered = Prefix(wal, target)
PostTargetExcluded == promoted =>
  EventIds(recovered) \cap EventIds(SubSeq(wal, target + 1, Len(wal))) = {}

=============================================================================
