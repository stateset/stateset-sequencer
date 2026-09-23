-------------------------- MODULE AtRestKeyRotation ---------------------------
EXTENDS FiniteSets, Integers, Sequences
CONSTANTS Keys, MaxWrites
ASSUME /\ IsFiniteSet(Keys) /\ Keys # {} /\ MaxWrites \in Nat \ {0}
VARIABLES current, available, ciphertexts
vars == <<current, available, ciphertexts>>
Init == /\ current \in Keys /\ available = {current}
        /\ ciphertexts = <<>>
Rotate(k) == /\ k \in Keys /\ k # current
             /\ current' = k /\ available' = available \cup {k}
             /\ UNCHANGED ciphertexts
Write == /\ Len(ciphertexts) < MaxWrites
         /\ ciphertexts' = Append(ciphertexts, current)
         /\ UNCHANGED <<current, available>>
\* Retirement requires re-encryption of every row using the old key.
Retire(k) == /\ k \in available /\ k # current
             /\ \A i \in 1..Len(ciphertexts) : ciphertexts[i] # k
             /\ available' = available \ {k}
             /\ UNCHANGED <<current, ciphertexts>>
Next == (\E k \in Keys : Rotate(k) \/ Retire(k))
        \/ Write \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars
CurrentPresent == current \in available
AllReadable == \A i \in 1..Len(ciphertexts) : ciphertexts[i] \in available
=============================================================================
