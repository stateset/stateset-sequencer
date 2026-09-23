-------------------------- MODULE ProofJobLifecycle ---------------------------
EXTENDS Integers
CONSTANTS Workers, MaxFailures
ASSUME /\ Workers # {} /\ MaxFailures \in Nat \ {0}
VARIABLES proof, job, failures, working
vars == <<proof, job, failures, working>>
Init == /\ proof = FALSE /\ job = "none"
        /\ failures = 0 /\ working = {}
\* Candidate queries can race; only the unique proof insert is decisive.
Start(w) == /\ w \in Workers /\ ~proof /\ job \in {"none", "retryable"}
            /\ working' = working \cup {w}
            /\ UNCHANGED <<proof, job, failures>>
Submit(w) == /\ w \in working /\ ~proof
             /\ proof' = TRUE /\ job' = "proved"
             /\ working' = working \ {w} /\ UNCHANGED failures
Fail(w) == /\ w \in working
           /\ working' = working \ {w}
           /\ IF proof THEN UNCHANGED <<proof, job, failures>>
              ELSE /\ failures' = failures + 1
                   /\ failures < MaxFailures
                   /\ job' = IF failures' = MaxFailures THEN "failed" ELSE "retryable"
                   /\ UNCHANGED proof
Crash(w) == /\ w \in working /\ working' = working \ {w}
            /\ UNCHANGED <<proof, job, failures>>
Next == (\E w \in Workers : Start(w) \/ Submit(w) \/ Fail(w) \/ Crash(w))
        \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars
ProofHasOutcome == proof => job = "proved"
TerminalStable == proof => failures <= MaxFailures
=============================================================================
