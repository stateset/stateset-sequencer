------------------------------ MODULE SchemaPolicy ----------------------------
EXTENDS Integers, Sequences

CONSTANTS MaxEvents
ASSUME MaxEvents \in Nat \ {0}
VARIABLES schema, policy, mode, accepted
vars == <<schema, policy, mode, accepted>>

Init == /\ schema = "absent" /\ policy = "enabled"
        /\ mode = "required" /\ accepted = <<>>
Register == /\ schema = "absent" /\ schema' = "active"
            /\ UNCHANGED <<policy, mode, accepted>>
Deprecate == /\ schema = "active" /\ schema' = "deprecated"
             /\ UNCHANGED <<policy, mode, accepted>>
Archive == /\ schema \in {"active", "deprecated"} /\ schema' = "archived"
           /\ UNCHANGED <<policy, mode, accepted>>
SetPolicy(p) == /\ p \in {"enabled", "disabled"} /\ policy' = p
                /\ UNCHANGED <<schema, mode, accepted>>
SetMode(m) == /\ m \in {"disabled", "warn", "enforce", "required"}
              /\ mode' = m /\ UNCHANGED <<schema, policy, accepted>>
\* A schema is usable only while active. Disabled policy means no restriction;
\* enabled policy is checked against the authoritative policy row.
Ingest(valid, permitted) ==
  /\ valid \in BOOLEAN /\ permitted \in BOOLEAN
  /\ Len(accepted) < MaxEvents
  /\ (policy = "disabled" \/ permitted)
  /\ (mode \in {"disabled", "warn"}
      \/ (schema = "active" /\ valid)
      \/ (mode = "enforce" /\ schema # "active"))
  /\ accepted' = Append(accepted,
       [status |-> schema, policy |-> policy, mode |-> mode,
        valid |-> valid, permitted |-> permitted])
  /\ UNCHANGED <<schema, policy, mode>>
Next == Register \/ Deprecate \/ Archive
        \/ (\E p \in {"enabled", "disabled"} : SetPolicy(p))
        \/ (\E m \in {"disabled", "warn", "enforce", "required"} : SetMode(m))
        \/ (\E v \in BOOLEAN, p \in BOOLEAN : Ingest(v, p))
Spec == Init /\ [][Next]_vars
PolicySound == \A i \in 1..Len(accepted) :
  accepted[i].policy = "enabled" => accepted[i].permitted
SchemaSound == \A i \in 1..Len(accepted) :
  accepted[i].mode = "required" =>
    (accepted[i].status = "active" /\ accepted[i].valid)
EnforceSound == \A i \in 1..Len(accepted) :
  accepted[i].mode = "enforce" /\ accepted[i].status = "active"
    => accepted[i].valid
=============================================================================
