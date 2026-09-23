----------------------------- MODULE StarkAdmission ---------------------------
EXTENDS Integers, Sequences

CONSTANTS Events, Policies, MaxProofs
ASSUME /\ Events # {} /\ Policies # {} /\ MaxProofs \in Nat \ {0}
VARIABLES admitted
vars == <<admitted>>
Init == admitted = <<>>
\* Verification covers the canonical event or batch inputs, policy hash,
\* witness commitment, and proof bytes. Payload binding can be unverified
\* only under an explicit operator opt-in for compliance proofs or an
\* unrecoverable batch payload; this is visible as an attested-only result.
Submit(e, p, canonical, binding, override, verified) ==
  /\ e \in Events /\ p \in Policies
  /\ canonical \in BOOLEAN /\ binding \in BOOLEAN
  /\ override \in BOOLEAN /\ verified \in BOOLEAN
  /\ Len(admitted) < MaxProofs
  /\ IF canonical /\ (binding \/ override) /\ verified
       THEN admitted' = Append(admitted,
          [event |-> e, policy |-> p, canonical |-> canonical,
           binding |-> binding, override |-> override,
           verified |-> verified])
       ELSE UNCHANGED admitted
Next == \E e \in Events, p \in Policies,
           c \in BOOLEAN, b \in BOOLEAN, o \in BOOLEAN, v \in BOOLEAN :
             Submit(e, p, c, b, o, v)
        \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars
AdmissionSound == \A i \in 1..Len(admitted) :
  admitted[i].canonical /\ admitted[i].verified
    /\ (admitted[i].binding \/ admitted[i].override)
=============================================================================
