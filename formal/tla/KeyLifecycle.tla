----------------------------- MODULE KeyLifecycle ---------------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Keys, Schemes, MaxTime, MaxAccepts, NoScheme
ASSUME /\ IsFiniteSet(Keys) /\ IsFiniteSet(Schemes)
       /\ Keys # {} /\ NoScheme \notin Schemes
       /\ MaxTime \in Nat \ {0} /\ MaxAccepts \in Nat \ {0}

VARIABLES status, cache, keyScheme, validFrom, validTo, clock, accepted
vars == <<status, cache, keyScheme, validFrom, validTo, clock, accepted>>

Init ==
  /\ status = [k \in Keys |-> "absent"]
  /\ cache = [k \in Keys |-> "absent"]
  /\ keyScheme = [k \in Keys |-> NoScheme]
  /\ validFrom = [k \in Keys |-> 0]
  /\ validTo = [k \in Keys |-> MaxTime]
  /\ clock = 0 /\ accepted = <<>>

Register(k, scheme, from, until) ==
  /\ k \in Keys /\ scheme \in Schemes /\ status[k] = "absent"
  /\ from \in 0..MaxTime /\ until \in from..MaxTime
  /\ status' = [status EXCEPT ![k] = "active"]
  /\ keyScheme' = [keyScheme EXCEPT ![k] = scheme]
  /\ validFrom' = [validFrom EXCEPT ![k] = from]
  /\ validTo' = [validTo EXCEPT ![k] = until]
  /\ UNCHANGED <<cache, clock, accepted>>
Revoke(k) ==
  /\ k \in Keys /\ status[k] = "active"
  /\ status' = [status EXCEPT ![k] = "revoked"]
  /\ UNCHANGED <<cache, keyScheme, validFrom, validTo, clock, accepted>>
Expire(k) ==
  /\ k \in Keys /\ status[k] = "active" /\ clock > validTo[k]
  /\ status' = [status EXCEPT ![k] = "expired"]
  /\ UNCHANGED <<cache, keyScheme, validFrom, validTo, clock, accepted>>
RefreshCache(k) ==
  /\ k \in Keys
  /\ cache' = [cache EXCEPT ![k] = status[k]]
  /\ UNCHANGED <<status, keyScheme, validFrom, validTo, clock, accepted>>
Tick ==
  /\ clock < MaxTime
  /\ clock' = clock + 1
  /\ UNCHANGED <<status, cache, keyScheme, validFrom, validTo, accepted>>

\* Cache can be stale. Signature acceptance reads authoritative lifecycle
\* state and binds the requested key ID to its registered signature scheme.
Verify(k, scheme) ==
  /\ k \in Keys /\ scheme \in Schemes /\ Len(accepted) < MaxAccepts
  /\ status[k] = "active" /\ validFrom[k] <= clock /\ clock <= validTo[k]
  /\ keyScheme[k] = scheme
  /\ accepted' = Append(accepted, [key |-> k, scheme |-> scheme,
                                   at |-> clock, statusAtRead |-> status[k],
                                   registeredScheme |-> keyScheme[k],
                                   start |-> validFrom[k], end |-> validTo[k]])
  /\ UNCHANGED <<status, cache, keyScheme, validFrom, validTo, clock>>

Next ==
  \/ \E k \in Keys, scheme \in Schemes, from \in 0..MaxTime :
       \E until \in from..MaxTime : Register(k, scheme, from, until)
  \/ \E k \in Keys : Revoke(k) \/ Expire(k) \/ RefreshCache(k)
  \/ \E k \in Keys, scheme \in Schemes : Verify(k, scheme)
  \/ Tick \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ status \in [Keys -> {"absent", "active", "revoked", "expired"}]
  /\ cache \in [Keys -> {"absent", "active", "revoked", "expired"}]
  /\ keyScheme \in [Keys -> Schemes \cup {NoScheme}]
  /\ validFrom \in [Keys -> 0..MaxTime]
  /\ validTo \in [Keys -> 0..MaxTime]
  /\ clock \in 0..MaxTime
  /\ accepted \in Seq([key : Keys, scheme : Schemes, at : 0..MaxTime,
                      statusAtRead : {"active"}, registeredScheme : Schemes,
                      start : 0..MaxTime, end : 0..MaxTime])
AcceptedSound == \A i \in 1..Len(accepted) :
  /\ accepted[i].statusAtRead = "active"
  /\ accepted[i].scheme = accepted[i].registeredScheme
  /\ accepted[i].start <= accepted[i].at
  /\ accepted[i].at <= accepted[i].end
RevokedStaysRegistered == \A k \in Keys :
  status[k] = "revoked" => keyScheme[k] # NoScheme

=============================================================================
