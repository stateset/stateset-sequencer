-------------------------- MODULE ChainReconciliation -----------------------
EXTENDS FiniteSets, Integers

CONSTANTS GoodRoot, BadRoot, NoRoot, TxIds, NoTx,
          MaxHeight, Confirmations
ASSUME /\ GoodRoot # BadRoot /\ GoodRoot # NoRoot /\ BadRoot # NoRoot
       /\ NoTx \notin TxIds /\ Cardinality(TxIds) = 2
       /\ MaxHeight \in Nat \ {0}
       /\ Confirmations \in 1..MaxHeight

VARIABLES height, chainRoot, chainTx, inclusion,
          candidateTx, observedTx, observedInclusion, localStatus
vars == <<height, chainRoot, chainTx, inclusion,
          candidateTx, observedTx, observedInclusion, localStatus>>

Init ==
  /\ height = 0 /\ chainRoot = NoRoot /\ chainTx = NoTx /\ inclusion = 0
  /\ candidateTx = NoTx /\ observedTx = NoTx
  /\ observedInclusion = 0 /\ localStatus = "unanchored"

Submit(t) ==
  /\ t \in TxIds /\ localStatus = "unanchored" /\ chainRoot = NoRoot
  /\ candidateTx' = t /\ localStatus' = "submitted"
  /\ UNCHANGED <<height, chainRoot, chainTx, inclusion,
                 observedTx, observedInclusion>>
Replace(t) ==
  /\ t \in TxIds /\ t # candidateTx
  /\ localStatus = "submitted" /\ chainRoot = NoRoot
  /\ candidateTx' = t
  /\ UNCHANGED <<height, chainRoot, chainTx, inclusion,
                 observedTx, observedInclusion, localStatus>>
Mine ==
  /\ localStatus = "submitted" /\ chainRoot = NoRoot
  /\ chainRoot' = GoodRoot /\ chainTx' = candidateTx
  /\ inclusion' = height
  /\ UNCHANGED <<height, candidateTx, observedTx,
                 observedInclusion, localStatus>>
\* A wrong-root batch with the same ID must never be accepted as local success.
ConflictingBatch(t) ==
  /\ t \in TxIds /\ chainRoot = NoRoot /\ localStatus # "finalized"
  /\ chainRoot' = BadRoot /\ chainTx' = t /\ inclusion' = height
  /\ UNCHANGED <<height, candidateTx, observedTx,
                 observedInclusion, localStatus>>
Observe ==
  /\ chainRoot = GoodRoot /\ chainTx # NoTx
  /\ localStatus # "finalized"
  /\ observedTx' = chainTx /\ observedInclusion' = inclusion
  /\ localStatus' = "pending"
  /\ UNCHANGED <<height, chainRoot, chainTx, inclusion, candidateTx>>
Reorg ==
  /\ chainRoot # NoRoot /\ localStatus # "finalized"
  /\ chainRoot' = NoRoot /\ chainTx' = NoTx /\ inclusion' = 0
  /\ UNCHANGED <<height, candidateTx, observedTx,
                 observedInclusion, localStatus>>
ReconcileMissing ==
  /\ chainRoot = NoRoot /\ localStatus \in {"submitted", "pending"}
  /\ observedTx' = NoTx /\ observedInclusion' = 0
  /\ candidateTx' = NoTx /\ localStatus' = "unanchored"
  /\ UNCHANGED <<height, chainRoot, chainTx, inclusion>>
Crash ==
  /\ localStatus # "finalized" /\ localStatus # "unanchored"
  /\ observedTx' = NoTx /\ observedInclusion' = 0
  /\ candidateTx' = NoTx /\ localStatus' = "unanchored"
  /\ UNCHANGED <<height, chainRoot, chainTx, inclusion>>
Advance ==
  /\ height < MaxHeight
  /\ height' = height + 1
  /\ UNCHANGED <<chainRoot, chainTx, inclusion, candidateTx,
                 observedTx, observedInclusion, localStatus>>
Finalize ==
  /\ localStatus = "pending" /\ chainRoot = GoodRoot
  /\ observedTx = chainTx /\ observedInclusion = inclusion
  /\ height - inclusion + 1 >= Confirmations
  /\ localStatus' = "finalized"
  /\ UNCHANGED <<height, chainRoot, chainTx, inclusion,
                 candidateTx, observedTx, observedInclusion>>

Next ==
  \/ \E t \in TxIds : Submit(t) \/ Replace(t) \/ ConflictingBatch(t)
  \/ Mine \/ Observe \/ Reorg \/ ReconcileMissing
  \/ Crash \/ Advance \/ Finalize \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ height \in 0..MaxHeight
  /\ chainRoot \in {NoRoot, GoodRoot, BadRoot}
  /\ chainTx \in TxIds \cup {NoTx}
  /\ inclusion \in 0..MaxHeight
  /\ candidateTx \in TxIds \cup {NoTx}
  /\ observedTx \in TxIds \cup {NoTx}
  /\ observedInclusion \in 0..MaxHeight
  /\ localStatus \in {"unanchored", "submitted", "pending", "finalized"}
FinalitySound == localStatus = "finalized" =>
  /\ chainRoot = GoodRoot /\ chainTx = observedTx
  /\ inclusion = observedInclusion
  /\ height - inclusion + 1 >= Confirmations
WrongRootNeverFinal == chainRoot = BadRoot => localStatus # "finalized"

=============================================================================
