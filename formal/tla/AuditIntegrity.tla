----------------------------- MODULE AuditIntegrity ---------------------------
EXTENDS Integers, Sequences

CONSTANTS Actions, MaxEntries, Genesis
ASSUME /\ Actions # {} /\ MaxEntries \in Nat \ {0}
       /\ Genesis \notin Actions
VARIABLES effects, audit
vars == <<effects, audit>>

Init == /\ effects = <<>> /\ audit = <<>>
\* The atomic action is the intended transaction boundary for a privileged
\* effect and its audit entry. Hash is abstract and collision-free here.
Commit(action) ==
  /\ action \in Actions /\ Len(effects) < MaxEntries
  /\ effects' = Append(effects, action)
  /\ audit' = Append(audit,
       [sequence |-> Len(audit) + 1, action |-> action,
        previous |-> IF Len(audit) = 0 THEN Genesis ELSE audit[Len(audit)]])
Next == (\E action \in Actions : Commit(action)) \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars
Complete == Len(effects) = Len(audit)
Ordered == \A i \in 1..Len(audit) :
  /\ audit[i].sequence = i
  /\ audit[i].action = effects[i]
  /\ audit[i].previous = (IF i = 1 THEN Genesis ELSE audit[i - 1])
=============================================================================
