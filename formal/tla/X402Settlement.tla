--------------------------- MODULE X402Settlement --------------------------
EXTENDS FiniteSets, Integers

CONSTANTS Intents, Nonces, Payers, Payer, Assets, Asset, Amount, NoIntent
FirstPayer == CHOOSE payer \in Payers : TRUE
SecondPayer == CHOOSE payer \in Payers \ {FirstPayer} : TRUE
PayerModel == [i \in Intents |->
  IF i = (CHOOSE first \in Intents : TRUE) THEN FirstPayer ELSE SecondPayer]
AmountModel == [i \in Intents |->
  IF i = (CHOOSE first \in Intents : TRUE) THEN 2 ELSE 1]
FirstAsset == CHOOSE asset \in Assets : TRUE
SecondAsset == CHOOSE asset \in Assets \ {FirstAsset} : TRUE
AssetModel == [i \in Intents |->
  IF i = (CHOOSE first \in Intents : TRUE) THEN FirstAsset ELSE SecondAsset]
ASSUME /\ Intents # {} /\ IsFiniteSet(Intents)
       /\ Nonces # {} /\ IsFiniteSet(Nonces)
       /\ Cardinality(Payers) = 2
       /\ Payer \in [Intents -> Payers]
       /\ Cardinality(Assets) = 2
       /\ Asset \in [Intents -> Assets]
       /\ Amount \in [Intents -> Nat \ {0}]
       /\ NoIntent \notin Intents

VARIABLES status, nonceOf, nonceOwner, batchSet, batchStatus, recordedTotal
vars == <<status, nonceOf, nonceOwner, batchSet, batchStatus, recordedTotal>>

RECURSIVE SumAsset(_, _)
SumAsset(items, asset) ==
  IF items = {} THEN 0
  ELSE LET i == CHOOSE x \in items : TRUE
       IN (IF Asset[i] = asset THEN Amount[i] ELSE 0) +
          SumAsset(items \ {i}, asset)

Init ==
  /\ status = [i \in Intents |-> "pending"]
  /\ nonceOf = [i \in Intents |-> NoIntent]
  /\ nonceOwner = [payer \in Payers |-> [n \in Nonces |-> NoIntent]]
  /\ batchSet = {}
  /\ batchStatus = "pending"
  /\ recordedTotal = [asset \in Assets |-> 0]

Validate(i, n) ==
  /\ i \in Intents /\ n \in Nonces
  /\ status[i] = "pending" /\ nonceOwner[Payer[i]][n] = NoIntent
  /\ status' = [status EXCEPT ![i] = "sequenced"]
  /\ nonceOf' = [nonceOf EXCEPT ![i] = n]
  /\ nonceOwner' = [nonceOwner EXCEPT ![Payer[i]][n] = i]
  /\ UNCHANGED <<batchSet, batchStatus, recordedTotal>>

AddToBatch(i) ==
  /\ i \in Intents /\ status[i] = "sequenced"
  /\ batchStatus = "pending"
  /\ status' = [status EXCEPT ![i] = "batched"]
  /\ batchSet' = batchSet \cup {i}
  /\ UNCHANGED <<nonceOf, nonceOwner, batchStatus, recordedTotal>>

Commit ==
  /\ batchStatus = "pending" /\ batchSet # {}
  /\ batchStatus' = "committed"
  /\ recordedTotal' = [asset \in Assets |-> SumAsset(batchSet, asset)]
  /\ UNCHANGED <<status, nonceOf, nonceOwner, batchSet>>

Submit ==
  /\ batchStatus = "committed"
  /\ batchStatus' = "submitted"
  /\ UNCHANGED <<status, nonceOf, nonceOwner, batchSet, recordedTotal>>

\* The chain returns a subset of failed intents. Settlement of the batch and
\* all intent outcomes is one durable transaction. A retry is a stutter.
Settle(failed) ==
  /\ batchStatus \in {"committed", "submitted"}
  /\ failed \subseteq batchSet
  /\ status' = [i \in Intents |->
       IF i \in batchSet THEN IF i \in failed THEN "failed" ELSE "settled"
       ELSE status[i]]
  /\ batchStatus' = "settled"
  /\ UNCHANGED <<nonceOf, nonceOwner, batchSet, recordedTotal>>

Next ==
  \/ \E i \in Intents, n \in Nonces : Validate(i, n)
  \/ \E i \in Intents : AddToBatch(i)
  \/ Commit \/ Submit
  \/ \E failed \in SUBSET batchSet : Settle(failed)
  \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ status \in [Intents -> {"pending", "sequenced", "batched", "settled", "failed"}]
  /\ nonceOf \in [Intents -> Nonces \cup {NoIntent}]
  /\ nonceOwner \in [Payers -> [Nonces -> Intents \cup {NoIntent}]]
  /\ batchSet \subseteq Intents
  /\ batchStatus \in {"pending", "committed", "submitted", "settled"}
  /\ recordedTotal \in [Assets -> Nat]
NonceSound == \A i \in Intents :
  status[i] # "pending" => nonceOwner[Payer[i]][nonceOf[i]] = i
BatchSound == \A i \in Intents :
  i \in batchSet => status[i] \in {"batched", "settled", "failed"}
TotalFrozen == batchStatus # "pending" =>
  \A asset \in Assets : recordedTotal[asset] = SumAsset(batchSet, asset)
SettlementAccounted == batchStatus = "settled" =>
  /\ {i \in Intents : status[i] \in {"settled", "failed"}} = batchSet
  /\ \A asset \in Assets :
       SumAsset({i \in Intents : status[i] = "settled"}, asset) +
       SumAsset({i \in Intents : status[i] = "failed"}, asset) =
         recordedTotal[asset]

=============================================================================
