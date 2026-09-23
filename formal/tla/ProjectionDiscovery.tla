------------------------ MODULE ProjectionDiscovery -------------------------
EXTENDS Integers, Sequences, FiniteSets
CONSTANTS S1, S2, S3
Order == <<S1, S2, S3>>
Streams == {S1, S2, S3}
ASSUME Cardinality(Streams) = 3
VARIABLES cursor, active, seen
vars == <<cursor, active, seen>>
Init == /\ cursor = 1 /\ active = {} /\ seen = {}
Discover ==
  /\ active = {}
  /\ active' = {Order[cursor]}
  /\ seen' = seen \cup {Order[cursor]}
  /\ cursor' = IF cursor = Len(Order) THEN 1 ELSE cursor + 1
Finish == /\ active # {} /\ active' = {}
          /\ UNCHANGED <<cursor, seen>>
Next == Discover \/ Finish
Spec == Init /\ [][Next]_vars /\ WF_vars(Discover) /\ WF_vars(Finish)
TypeOK == /\ cursor \in 1..Len(Order)
          /\ active \subseteq Streams
          /\ seen \subseteq Streams
          /\ Cardinality(active) <= 1
NoLostStartedStream == active \subseteq seen
EventuallyDiscovered == <> (seen = Streams)
=============================================================================
