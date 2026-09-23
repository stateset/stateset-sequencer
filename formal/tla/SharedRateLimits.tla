--------------------------- MODULE SharedRateLimits --------------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Keys, Limit, Capacity, MaxTicks, MaxDecisions
ASSUME /\ IsFiniteSet(Keys) /\ Keys # {}
       /\ Limit \in Nat \ {0} /\ Capacity \in Nat \ {0}
       /\ MaxTicks \in Nat \ {0} /\ MaxDecisions \in Nat \ {0}

VARIABLES used, epoch, now, decisions
vars == <<used, epoch, now, decisions>>

Init == /\ used = [k \in Keys |-> 0]
        /\ epoch = [k \in Keys |-> 0]
        /\ now = 0 /\ decisions = <<>>

\* One action is the row-locked PostgreSQL function call. A caller cannot
\* observe an intermediate increment, even when several replicas race.
Take(k) ==
  /\ k \in Keys /\ Len(decisions) < MaxDecisions
  /\ LET current == IF epoch[k] = now THEN used[k] ELSE 0
         active == {j \in Keys : epoch[j] = now /\ used[j] > 0}
     IN /\ IF current < Limit /\ (current > 0 \/ Cardinality(active) < Capacity)
               THEN /\ used' = [used EXCEPT ![k] = current + 1]
                    /\ epoch' = [epoch EXCEPT ![k] = now]
                    /\ decisions' = Append(decisions,
                         [key |-> k, epoch |-> now, ordinal |-> current + 1])
               ELSE /\ UNCHANGED <<used, epoch, decisions>>
        /\ UNCHANGED now

Tick == /\ now < MaxTicks /\ now' = now + 1
        /\ UNCHANGED <<used, epoch, decisions>>
Next == (\E k \in Keys : Take(k)) \/ Tick \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK == /\ used \in [Keys -> 0..Limit]
          /\ epoch \in [Keys -> 0..MaxTicks]
          /\ now \in 0..MaxTicks
NoOverAdmission == \A i \in 1..Len(decisions) : decisions[i].ordinal <= Limit
BoundedActiveKeys == Cardinality({k \in Keys : epoch[k] = now /\ used[k] > 0}) <= Capacity
=============================================================================
