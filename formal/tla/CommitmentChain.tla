--------------------------- MODULE CommitmentChain -------------------------
EXTENDS Integers, Sequences

CONSTANTS MaxSeq, Genesis
ASSUME MaxSeq \in Nat \ {0}

VARIABLES commitments, lastEnd, lastRoot
vars == <<commitments, lastEnd, lastRoot>>

Init ==
  /\ commitments = <<>>
  /\ lastEnd = 0
  /\ lastRoot = Genesis

\* A tuple stands in for the domain-separated state-root hash. Its fields
\* remain visible to TLC; cryptographic collision resistance is out of scope.
NewRoot(prev, start, finish) == <<prev, start, finish>>

Commit(finish) ==
  /\ finish \in (lastEnd + 1)..MaxSeq
  /\ LET start == lastEnd + 1
         entry == [start |-> start, finish |-> finish,
                   prev |-> lastRoot,
                   root |-> NewRoot(lastRoot, start, finish)]
     IN commitments' = Append(commitments, entry)
  /\ lastEnd' = finish
  /\ lastRoot' = NewRoot(lastRoot, lastEnd + 1, finish)

\* Returning an existing range is idempotent; it creates no second entry.
Retry(start, finish) ==
  /\ \E i \in 1..Len(commitments) :
       commitments[i].start = start /\ commitments[i].finish = finish
  /\ UNCHANGED vars

Next == (\E finish \in 1..MaxSeq : Commit(finish))
        \/ (\E start, finish \in 1..MaxSeq : Retry(start, finish))
        \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

RangeChain == \A i \in 1..Len(commitments) :
  /\ commitments[i].start =
       IF i = 1 THEN 1 ELSE commitments[i - 1].finish + 1
  /\ commitments[i].start <= commitments[i].finish
  /\ commitments[i].finish <= MaxSeq
RootChain == \A i \in 1..Len(commitments) :
  /\ commitments[i].prev =
       IF i = 1 THEN Genesis ELSE commitments[i - 1].root
  /\ commitments[i].root = NewRoot(commitments[i].prev,
                                    commitments[i].start,
                                    commitments[i].finish)
HeadMatches ==
  /\ lastEnd = IF Len(commitments) = 0 THEN 0
                ELSE commitments[Len(commitments)].finish
  /\ lastRoot = IF Len(commitments) = 0 THEN Genesis
                 ELSE commitments[Len(commitments)].root

=============================================================================
