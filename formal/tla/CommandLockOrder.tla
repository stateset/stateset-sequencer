------------------------- MODULE CommandLockOrder --------------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Writers, NoWriter
ASSUME /\ Cardinality(Writers) = 2
       /\ NoWriter \notin Writers

Commands == 1..2
Request(w) == <<1, 2>>

VARIABLES owner, phase, nextIndex
vars == <<owner, phase, nextIndex>>

Init ==
  /\ owner = [c \in Commands |-> NoWriter]
  /\ phase = [w \in Writers |-> "idle"]
  /\ nextIndex = [w \in Writers |-> 1]

Start(w) ==
  /\ w \in Writers /\ phase[w] = "idle"
  /\ phase' = [phase EXCEPT ![w] = "reserving"]
  /\ nextIndex' = [nextIndex EXCEPT ![w] = 1]
  /\ UNCHANGED owner

\* A successful INSERT holds the command row lock until the transaction ends.
Acquire(w) ==
  /\ w \in Writers /\ phase[w] = "reserving"
  /\ nextIndex[w] <= Len(Request(w))
  /\ owner[Request(w)[nextIndex[w]]] = NoWriter
  /\ owner' = [owner EXCEPT ![Request(w)[nextIndex[w]]] = w]
  /\ nextIndex' = [nextIndex EXCEPT ![w] = @ + 1]
  /\ UNCHANGED phase

Finish(w) ==
  /\ w \in Writers /\ phase[w] = "reserving"
  /\ nextIndex[w] > Len(Request(w))
  /\ owner' = [c \in Commands |-> IF owner[c] = w THEN NoWriter ELSE owner[c]]
  /\ phase' = [phase EXCEPT ![w] = "idle"]
  /\ nextIndex' = [nextIndex EXCEPT ![w] = 1]

Next == (\E w \in Writers : Start(w) \/ Acquire(w) \/ Finish(w))
        \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

WaitingFor(w) ==
  IF phase[w] = "reserving" /\ nextIndex[w] <= Len(Request(w))
  THEN owner[Request(w)[nextIndex[w]]]
  ELSE NoWriter

TypeOK ==
  /\ owner \in [Commands -> Writers \cup {NoWriter}]
  /\ phase \in [Writers -> {"idle", "reserving"}]
  /\ nextIndex \in [Writers -> 1..3]
LockOrder == \A w \in Writers : \A c \in Commands :
  owner[c] = w => c < nextIndex[w]
NoWaitCycle == \A a, b \in Writers : a # b =>
  ~(WaitingFor(a) = b /\ WaitingFor(b) = a)
SomeProgressEnabled ==
  (\E w \in Writers : phase[w] = "reserving") =>
    (\E w \in Writers :
      phase[w] = "reserving" /\
      (nextIndex[w] > Len(Request(w)) \/ WaitingFor(w) = NoWriter))

=============================================================================
