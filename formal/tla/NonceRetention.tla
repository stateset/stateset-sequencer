--------------------------- MODULE NonceRetention ----------------------------
EXTENDS Integers
CONSTANTS MaxValidity, ClockSkew, Retention, MaxTime
ASSUME /\ MaxValidity \in Nat \ {0}
       /\ ClockSkew \in Nat
       /\ Retention \in Nat
       /\ Retention >= MaxValidity + 2 * ClockSkew
       /\ MaxTime > Retention
VARIABLES now, expires, tracked, replayAccepted
vars == <<now, expires, tracked, replayAccepted>>
\* An admitting node can be ahead of database time by ClockSkew.
Init == /\ now = 0 /\ expires \in 0..(MaxValidity + ClockSkew)
        /\ tracked = TRUE /\ replayAccepted = FALSE
Tick == /\ now < MaxTime /\ now' = now + 1
        /\ UNCHANGED <<expires, tracked, replayAccepted>>
Cleanup == /\ tracked /\ now > Retention /\ tracked' = FALSE
           /\ UNCHANGED <<now, expires, replayAccepted>>
\* A replaying node can be behind database time by ClockSkew.
Replay == /\ now - ClockSkew <= expires /\ ~tracked
          /\ replayAccepted' = TRUE
          /\ UNCHANGED <<now, expires, tracked>>
Next == Tick \/ Cleanup \/ Replay
Spec == Init /\ [][Next]_vars
NoLiveReplay == ~replayAccepted
CleanupAfterExpiry == ~tracked => now - ClockSkew > expires
=============================================================================
