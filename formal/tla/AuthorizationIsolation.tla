------------------------ MODULE AuthorizationIsolation ----------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Principals, Tenants, Stores, Bootstrap, NoTenant,
          MaxRequests, MaxPolicyChanges
ASSUME /\ IsFiniteSet(Principals) /\ IsFiniteSet(Tenants) /\ IsFiniteSet(Stores)
       /\ Bootstrap \in Principals /\ NoTenant \notin Tenants
       /\ Tenants # {} /\ Stores # {}
       /\ MaxRequests \in Nat \ {0}
       /\ MaxPolicyChanges \in Nat \ {0}

TenantOf == [p \in Principals |->
  IF p = Bootstrap THEN NoTenant ELSE CHOOSE t \in Tenants : TRUE]
InitialStores == [p \in Principals |->
  IF p = Bootstrap THEN {} ELSE {CHOOSE s \in Stores : TRUE}]
InitialRights == [p \in Principals |->
  IF p = Bootstrap THEN {"read", "write", "admin"} ELSE {"read", "write"}]

VARIABLES stores, rights, audit, effects, policyChanges
vars == <<stores, rights, audit, effects, policyChanges>>

Init ==
  /\ stores = InitialStores
  /\ rights = InitialRights
  /\ audit = <<>>
  /\ effects = {}
  /\ policyChanges = 0

BootstrapAccess(p) == p = Bootstrap /\ TenantOf[p] = NoTenant /\ "admin" \in rights[p]
CanAccess(p, t, s, operation) ==
  /\ operation \in rights[p]
  /\ (BootstrapAccess(p) \/ (TenantOf[p] = t /\ s \in stores[p]))

Request(p, t, s, operation) ==
  /\ p \in Principals /\ t \in Tenants /\ s \in Stores
  /\ operation \in {"read", "write", "admin"}
  /\ Len(audit) < MaxRequests
  /\ audit' = Append(audit, [principal |-> p, tenant |-> t,
                             store |-> s, operation |-> operation,
                             allowed |-> CanAccess(p, t, s, operation),
                             scoped |-> BootstrapAccess(p) \/
                               (TenantOf[p] = t /\ s \in stores[p])])
  /\ effects' = IF CanAccess(p, t, s, operation)
                THEN effects \cup {Len(audit) + 1} ELSE effects
  /\ UNCHANGED <<stores, rights, policyChanges>>

\* A principal may narrow its own policy. Only the bootstrap administrator
\* can widen another principal's permissions or store scope.
AttenuateRight(p, operation) ==
  /\ p \in Principals /\ operation \in rights[p]
  /\ policyChanges < MaxPolicyChanges
  /\ rights' = [rights EXCEPT ![p] = @ \ {operation}]
  /\ policyChanges' = policyChanges + 1
  /\ UNCHANGED <<stores, audit, effects>>
AttenuateStore(p, s) ==
  /\ p \in Principals /\ s \in stores[p]
  /\ policyChanges < MaxPolicyChanges
  /\ stores' = [stores EXCEPT ![p] = @ \ {s}]
  /\ policyChanges' = policyChanges + 1
  /\ UNCHANGED <<rights, audit, effects>>
AdminGrantRight(p, operation) ==
  /\ p \in Principals /\ operation \in {"read", "write", "admin"}
  /\ BootstrapAccess(Bootstrap)
  /\ policyChanges < MaxPolicyChanges
  /\ rights' = [rights EXCEPT ![p] = @ \cup {operation}]
  /\ policyChanges' = policyChanges + 1
  /\ UNCHANGED <<stores, audit, effects>>
AdminGrantStore(p, s) ==
  /\ p \in Principals /\ s \in Stores
  /\ BootstrapAccess(Bootstrap)
  /\ policyChanges < MaxPolicyChanges
  /\ stores' = [stores EXCEPT ![p] = @ \cup {s}]
  /\ policyChanges' = policyChanges + 1
  /\ UNCHANGED <<rights, audit, effects>>

Next ==
  \/ \E p \in Principals, t \in Tenants, s \in Stores,
       op \in {"read", "write", "admin"} : Request(p, t, s, op)
  \/ \E p \in Principals, op \in {"read", "write", "admin"} :
       AttenuateRight(p, op) \/ AdminGrantRight(p, op)
  \/ \E p \in Principals, s \in Stores :
       AttenuateStore(p, s) \/ AdminGrantStore(p, s)
  \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ stores \in [Principals -> SUBSET Stores]
  /\ rights \in [Principals -> SUBSET {"read", "write", "admin"}]
  /\ audit \in Seq([principal : Principals, tenant : Tenants,
                    store : Stores, operation : {"read", "write", "admin"},
                    allowed : BOOLEAN, scoped : BOOLEAN])
  /\ effects \subseteq 1..Len(audit)
  /\ policyChanges \in 0..MaxPolicyChanges
EffectsAuthorized == \A i \in effects : audit[i].allowed /\ audit[i].scoped
DeniedHasNoEffect == \A i \in 1..Len(audit) : ~audit[i].allowed => i \notin effects

=============================================================================
