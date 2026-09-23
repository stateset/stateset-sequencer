------------------------- MODULE MigrationPreservation ----------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Events
ASSUME /\ IsFiniteSet(Events) /\ Events # {}

RootOf == [e \in Events |->
  IF e = CHOOSE first \in Events : TRUE THEN 11 ELSE 22]

VARIABLES version, phase, ledger, receipts, roots,
          oldLedger, oldReceipts, oldRoots
vars == <<version, phase, ledger, receipts, roots,
          oldLedger, oldReceipts, oldRoots>>

Ids(xs) == {xs[i] : i \in 1..Len(xs)}
Prefix(xs, ys) ==
  Len(xs) <= Len(ys) /\ \A i \in 1..Len(xs) : xs[i] = ys[i]

Init ==
  /\ version = 1 /\ phase = "idle"
  /\ ledger = <<>> /\ receipts = {} /\ roots = <<>>
  /\ oldLedger = <<>> /\ oldReceipts = {} /\ oldRoots = <<>>

AppendEvent(e) ==
  /\ phase = "idle" /\ e \in Events /\ e \notin receipts
  /\ ledger' = Append(ledger, e)
  /\ receipts' = receipts \cup {e}
  /\ roots' = Append(roots, RootOf[e])
  /\ UNCHANGED <<version, phase, oldLedger, oldReceipts, oldRoots>>

StartUpgrade ==
  /\ version = 1 /\ phase = "idle"
  /\ phase' = "migrating"
  /\ oldLedger' = ledger /\ oldReceipts' = receipts /\ oldRoots' = roots
  /\ UNCHANGED <<version, ledger, receipts, roots>>
\* Migration DDL and data changes commit atomically. A process crash before
\* commit leaves the old schema and ledger intact.
CrashUpgrade ==
  /\ phase = "migrating"
  /\ phase' = "idle"
  /\ UNCHANGED <<version, ledger, receipts, roots,
                 oldLedger, oldReceipts, oldRoots>>
CommitUpgrade ==
  /\ phase = "migrating"
  /\ version' = 2 /\ phase' = "idle"
  /\ UNCHANGED <<ledger, receipts, roots,
                 oldLedger, oldReceipts, oldRoots>>

Next ==
  \/ \E e \in Events : AppendEvent(e)
  \/ StartUpgrade \/ CrashUpgrade \/ CommitUpgrade \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ version \in {1, 2} /\ phase \in {"idle", "migrating"}
  /\ ledger \in Seq(Events) /\ receipts \subseteq Events
  /\ roots \in Seq({RootOf[e] : e \in Events})
  /\ oldLedger \in Seq(Events) /\ oldReceipts \subseteq Events
  /\ oldRoots \in Seq({RootOf[e] : e \in Events})
ReceiptIntegrity == receipts = Ids(ledger)
RootIntegrity ==
  Len(roots) = Len(ledger) /\
  \A i \in 1..Len(ledger) : roots[i] = RootOf[ledger[i]]
UpgradePreservesOld == version = 2 =>
  Prefix(oldLedger, ledger) /\ oldReceipts \subseteq receipts /\
  Prefix(oldRoots, roots)

=============================================================================
