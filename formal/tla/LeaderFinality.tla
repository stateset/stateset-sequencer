---------------------------- MODULE LeaderFinality --------------------------
EXTENDS FiniteSets, Integers

CONSTANTS Nodes, NoNode, MaxHeight, Confirmations, MaxAttempts
ASSUME /\ Cardinality(Nodes) = 2 /\ NoNode \notin Nodes
       /\ MaxHeight \in Nat \ {0}
       /\ Confirmations \in 1..MaxHeight
       /\ MaxAttempts \in Nat \ {0}

VARIABLES lockOwner, running, inFlight, chainHeight, included, inclusionHeight,
          localStatus, submissionAttempts
vars == <<lockOwner, running, inFlight, chainHeight, included, inclusionHeight,
          localStatus, submissionAttempts>>

Init ==
  /\ lockOwner = NoNode
  /\ running = {}
  /\ inFlight = {}
  /\ chainHeight = 0
  /\ included = FALSE
  /\ inclusionHeight = 0
  /\ localStatus = "unanchored"
  /\ submissionAttempts = 0

Acquire(n) ==
  /\ n \in Nodes /\ lockOwner = NoNode
  /\ lockOwner' = n
  /\ UNCHANGED <<running, inFlight, chainHeight, included, inclusionHeight,
                 localStatus, submissionAttempts>>
Start(n) ==
  /\ n \in Nodes /\ lockOwner = n
  /\ running' = running \cup {n}
  /\ UNCHANGED <<lockOwner, inFlight, chainHeight, included, inclusionHeight,
                 localStatus, submissionAttempts>>

\* Lease loss can leave an old task briefly running. The contract's batch ID
\* makes duplicate submissions harmless to the on-chain commitment state.
LoseLease(n) ==
  /\ n \in Nodes /\ lockOwner = n
  /\ lockOwner' = NoNode
  /\ UNCHANGED <<running, inFlight, chainHeight, included, inclusionHeight,
                 localStatus, submissionAttempts>>
Stop(n) ==
  /\ n \in running
  /\ running' = running \ {n}
  /\ UNCHANGED <<lockOwner, inFlight, chainHeight, included, inclusionHeight,
                 localStatus, submissionAttempts>>

BeginSubmit(n) ==
  /\ n \in running /\ localStatus = "unanchored"
  /\ n \notin inFlight
  /\ submissionAttempts + Cardinality(inFlight) < MaxAttempts
  /\ inFlight' = inFlight \cup {n}
  /\ UNCHANGED <<lockOwner, running, chainHeight, included,
                 inclusionHeight, localStatus, submissionAttempts>>

\* Two workers can start an RPC before either observes the other's result.
\* A duplicate completion counts as an external attempt but cannot create a
\* second contract commitment for the same batch ID.
FinishSubmit(n) ==
  /\ n \in inFlight
  /\ inFlight' = inFlight \ {n}
  /\ submissionAttempts' = submissionAttempts + 1
  /\ included' = IF localStatus = "unanchored" THEN TRUE ELSE included
  /\ inclusionHeight' =
       IF localStatus = "unanchored" THEN chainHeight ELSE inclusionHeight
  /\ localStatus' = IF localStatus = "unanchored" THEN "pending" ELSE localStatus
  /\ UNCHANGED <<lockOwner, running, chainHeight>>

AdvanceBlock ==
  /\ chainHeight < MaxHeight
  /\ chainHeight' = chainHeight + 1
  /\ UNCHANGED <<lockOwner, running, inFlight, included, inclusionHeight,
                 localStatus, submissionAttempts>>

\* The confirmation count is based on chain height after inclusion, not
\* elapsed wall-clock time since commitment creation.
Confirm ==
  /\ localStatus = "pending" /\ included
  /\ chainHeight - inclusionHeight + 1 >= Confirmations
  /\ localStatus' = "finalized"
  /\ UNCHANGED <<lockOwner, running, inFlight, chainHeight, included,
                 inclusionHeight, submissionAttempts>>

\* Reorgs within the configured confirmation window return the commitment
\* to the unanchored pool. Deeper reorgs are outside this model's assumption.
Reorg ==
  /\ localStatus = "pending"
  /\ included' = FALSE
  /\ inclusionHeight' = 0
  /\ localStatus' = "unanchored"
  /\ UNCHANGED <<lockOwner, running, inFlight, chainHeight, submissionAttempts>>

Next ==
  \/ \E n \in Nodes : Acquire(n) \/ Start(n) \/ LoseLease(n)
                    \/ Stop(n) \/ BeginSubmit(n) \/ FinishSubmit(n)
  \/ AdvanceBlock \/ Confirm \/ Reorg \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ lockOwner \in Nodes \cup {NoNode}
  /\ running \subseteq Nodes
  /\ inFlight \subseteq Nodes
  /\ chainHeight \in 0..MaxHeight
  /\ inclusionHeight \in 0..MaxHeight
  /\ localStatus \in {"unanchored", "pending", "finalized"}
  /\ submissionAttempts \in 0..MaxAttempts
  /\ submissionAttempts + Cardinality(inFlight) <= MaxAttempts
PendingSound == localStatus = "pending" => included
FinalitySound == localStatus = "finalized" =>
  included /\ chainHeight - inclusionHeight + 1 >= Confirmations

=============================================================================
