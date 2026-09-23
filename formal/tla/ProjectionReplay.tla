-------------------------- MODULE ProjectionReplay ---------------------------
EXTENDS Integers, Sequences
CONSTANTS E1, E2, E3
Events == <<E1, E2, E3>>
VARIABLES checkpoint, document, working, active
vars == <<checkpoint, document, working, active>>
Init == /\ checkpoint = 0 /\ document = <<>>
        /\ working = <<>> /\ active = FALSE
Begin == /\ ~active /\ active' = TRUE /\ working' = document
         /\ UNCHANGED <<checkpoint, document>>
Apply == /\ active /\ Len(working) < Len(Events)
         /\ working' = Append(working, Events[Len(working) + 1])
         /\ UNCHANGED <<checkpoint, document, active>>
Commit == /\ active /\ checkpoint' = Len(working)
          /\ document' = working /\ active' = FALSE
          /\ UNCHANGED working
Crash == /\ active /\ active' = FALSE /\ working' = document
         /\ UNCHANGED <<checkpoint, document>>
Next == Begin \/ Apply \/ Commit \/ Crash
Spec == Init /\ [][Next]_vars
CommittedPrefix == /\ checkpoint \in 0..Len(Events)
                   /\ document = SubSeq(Events, 1, checkpoint)
WorkingPrefix == working = SubSeq(Events, 1, Len(working))
=============================================================================
