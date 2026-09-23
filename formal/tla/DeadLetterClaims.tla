--------------------------- MODULE DeadLetterClaims ----------------------------
EXTENDS Integers
CONSTANTS Tokens, MaxRetries, MaxTime
ASSUME /\ Tokens # {} /\ MaxRetries \in Nat \ {0}
       /\ MaxTime \in Nat \ {0}
VARIABLES status, token, attempts, clock, claimedAt, applied
vars == <<status, token, attempts, clock, claimedAt, applied>>
Init == /\ status = "pending" /\ token = "none"
        /\ attempts = 0 /\ clock = 0 /\ claimedAt = 0 /\ applied = 0
Claim(t) ==
  /\ t \in Tokens /\ t # token /\ attempts < MaxRetries
  /\ (status = "pending" \/ (status = "retrying" /\ claimedAt < clock))
  /\ status' = "retrying" /\ token' = t /\ claimedAt' = clock
  /\ UNCHANGED <<attempts, clock, applied>>
Resolve(t) == /\ status = "retrying" /\ token = t
              /\ status' = "resolved" /\ token' = "none"
              /\ applied' = applied + 1
              /\ UNCHANGED <<attempts, clock, claimedAt>>
Fail(t) == /\ status = "retrying" /\ token = t
           /\ attempts' = attempts + 1
           /\ status' = IF attempts' = MaxRetries THEN "failed" ELSE "pending"
           /\ token' = "none" /\ UNCHANGED <<clock, claimedAt, applied>>
Tick == /\ clock < MaxTime /\ clock' = clock + 1
        /\ UNCHANGED <<status, token, attempts, claimedAt, applied>>
Next == (\E t \in Tokens : Claim(t) \/ Resolve(t) \/ Fail(t))
        \/ Tick \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars
AtMostOnce == applied <= 1
ResolvedApplied == status = "resolved" => applied = 1
NoLiveTerminal == status \in {"resolved", "failed"} => token = "none"
=============================================================================
