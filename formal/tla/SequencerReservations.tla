----------------------- MODULE SequencerReservations -----------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Streams, Counts, MaxSeq
ASSUME /\ Streams # {}
       /\ Counts \subseteq Nat \ {0}
       /\ MaxSeq \in Nat

VARIABLES head, allocations, stored
vars == <<head, allocations, stored>>

Interval(entry) == entry.start..entry.finish
Allocated(s) == UNION {Interval(allocations[s][i]) : i \in 1..Len(allocations[s])}
Ingested(s) == UNION {
  IF allocations[s][i].kind = "ingest" THEN Interval(allocations[s][i]) ELSE {}
    : i \in 1..Len(allocations[s])
}

Init ==
  /\ head = [s \in Streams |-> 0]
  /\ allocations = [s \in Streams |-> <<>>]
  /\ stored = [s \in Streams |-> {}]

\* Both paths advance the same counter atomically. Only ingest stores events.
Allocate(s, count, kind) ==
  /\ s \in Streams
  /\ count \in Counts
  /\ kind \in {"reserve", "ingest"}
  /\ head[s] + count <= MaxSeq
  /\ LET entry == [start |-> head[s] + 1,
                   finish |-> head[s] + count,
                   kind |-> kind]
     IN allocations' = [allocations EXCEPT ![s] = Append(@, entry)]
  /\ stored' = IF kind = "ingest"
               THEN [stored EXCEPT ![s] = @ \cup ((head[s] + 1)..(head[s] + count))]
               ELSE stored
  /\ head' = [head EXCEPT ![s] = @ + count]

Next == (\E s \in Streams, count \in Counts, kind \in {"reserve", "ingest"} :
  Allocate(s, count, kind)) \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ head \in [Streams -> 0..MaxSeq]
  /\ allocations \in [Streams -> Seq([start : Nat, finish : Nat,
                                      kind : {"reserve", "ingest"}])]
  /\ stored \in [Streams -> SUBSET (1..MaxSeq)]
HeadCovered == \A s \in Streams : Allocated(s) = 1..head[s]
StoredExact == \A s \in Streams : stored[s] = Ingested(s)
RangesDisjoint ==
  \A s \in Streams :
    \A i, j \in 1..Len(allocations[s]) :
      i < j => Interval(allocations[s][i]) \cap Interval(allocations[s][j]) = {}
NonEmptyRanges ==
  \A s \in Streams : \A i \in 1..Len(allocations[s]) :
    allocations[s][i].start <= allocations[s][i].finish

=============================================================================
