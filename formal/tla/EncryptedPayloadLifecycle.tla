----------------------- MODULE EncryptedPayloadLifecycle ----------------------
EXTENDS Integers, FiniteSets, Sequences

CONSTANTS Keys, Contexts, MaxPayloads
ASSUME /\ IsFiniteSet(Keys) /\ Keys # {} /\ Contexts # {}
       /\ MaxPayloads \in Nat \ {0}
VARIABLES active, payloads, reads
vars == <<active, payloads, reads>>

Init == /\ active = Keys /\ payloads = <<>> /\ reads = <<>>
Revoke(k) == /\ k \in active /\ active' = active \ {k}
             /\ UNCHANGED <<payloads, reads>>
Encrypt(recipients, context) ==
  /\ recipients \subseteq active /\ recipients # {}
  /\ context \in Contexts /\ Len(payloads) < MaxPayloads
  /\ payloads' = Append(payloads,
        [recipients |-> recipients, context |-> context])
  /\ UNCHANGED <<active, reads>>
\* Historical ciphertext remains readable by a holder of a formerly active
\* private key. Revocation only excludes the key from new wraps.
Decrypt(i, k, context) ==
  /\ i \in 1..Len(payloads) /\ k \in payloads[i].recipients
  /\ context = payloads[i].context /\ Len(reads) < MaxPayloads
  /\ reads' = Append(reads,
       [index |-> i, key |-> k, context |-> context,
        recipients |-> payloads[i].recipients,
        boundContext |-> payloads[i].context])
  /\ UNCHANGED <<active, payloads>>
Next == (\E k \in Keys : Revoke(k))
        \/ (\E r \in SUBSET Keys, c \in Contexts : Encrypt(r, c))
        \/ (\E i \in 1..Len(payloads), k \in Keys, c \in Contexts : Decrypt(i, k, c))
        \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars
WrapSound == \A i \in 1..Len(payloads) : payloads[i].recipients \subseteq Keys
ReadSound == \A i \in 1..Len(reads) :
  /\ reads[i].key \in reads[i].recipients
  /\ reads[i].context = reads[i].boundContext
=============================================================================
