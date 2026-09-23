--------------------------- MODULE AuditTransactions --------------------------
EXTENDS Integers, Sequences
CONSTANTS Actions, MaxEffects
ASSUME /\ Actions # {} /\ MaxEffects \in Nat \ {0}
VARIABLES effects, audit, pending, checkpoint
vars == <<effects, audit, pending, checkpoint>>
Init == /\ effects = <<>> /\ audit = <<>>
        /\ pending = "none" /\ checkpoint = 0
Begin(a) == /\ a \in Actions /\ pending = "none"
            /\ Len(effects) < MaxEffects /\ pending' = a
            /\ UNCHANGED <<effects, audit, checkpoint>>
\* Database trigger inserts the audit record in the same transaction.
Commit == /\ pending # "none"
          /\ effects' = Append(effects, pending)
          /\ audit' = Append(audit, [seq |-> Len(audit) + 1, action |-> pending])
          /\ pending' = "none" /\ UNCHANGED checkpoint
Crash == /\ pending # "none" /\ pending' = "none"
         /\ UNCHANGED <<effects, audit, checkpoint>>
Checkpoint == /\ checkpoint < Len(audit)
              /\ checkpoint' = Len(audit)
              /\ UNCHANGED <<effects, audit, pending>>
Next == (\E a \in Actions : Begin(a)) \/ Commit \/ Crash
        \/ Checkpoint \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars
Complete == Len(effects) = Len(audit)
Ordered == \A i \in 1..Len(audit) :
  audit[i].seq = i /\ audit[i].action = effects[i]
CheckpointSound == checkpoint <= Len(audit)
=============================================================================
