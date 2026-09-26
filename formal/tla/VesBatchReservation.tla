------------------------ MODULE VesBatchReservation ------------------------
EXTENDS FiniteSets, Integers, Sequences

CONSTANTS Events, Commands, MaxSeq
ASSUME /\ IsFiniteSet(Events) /\ Events # {}
       /\ IsFiniteSet(Commands) /\ Commands # {}
       /\ MaxSeq \in Nat

Inputs == [event : Events, command : Commands, base : 0..MaxSeq]
Requests == {<<input>> : input \in Inputs} \cup
            {<<first, second>> : first \in Inputs, second \in Inputs}
EventIds(xs) == {xs[i].event : i \in 1..Len(xs)}
CommandIds(xs) == {xs[i].command : i \in 1..Len(xs)}
AcceptedFrom(request) ==
  IF Len(request) = 1
  THEN {<<>>, request}
  ELSE {<<>>, <<request[1]>>, <<request[2]>>, request}

VARIABLES log, commands, receipts, head, version, phase, request, claimed, working, index,
          lastStart, lastAccepted, lastRejected
vars == <<log, commands, receipts, head, version, phase, request, claimed, working, index,
          lastStart, lastAccepted, lastRejected>>

Init ==
  /\ log = <<>> /\ commands = {} /\ receipts = {}
  /\ head = 0 /\ version = 0
  /\ phase = "idle" /\ request = <<>> /\ claimed = {}
  /\ working = <<>> /\ index = 1
  /\ lastStart = 0 /\ lastAccepted = <<>> /\ lastRejected = {}

\* The request has already passed signature/policy validation and contains
\* fresh event IDs and distinct command IDs. With one writer, acquiring every
\* command reservation before the counter lock can be represented atomically.
Begin(batch) ==
  /\ phase = "idle" /\ batch \in Requests
  /\ Cardinality(EventIds(batch)) = Len(batch)
  /\ Cardinality(CommandIds(batch)) = Len(batch)
  /\ EventIds(batch) \cap EventIds(log) = {}
  /\ CommandIds(batch) \cap CommandIds(log) = {}
  /\ request' = batch /\ claimed' = CommandIds(batch)
  /\ working' = <<>> /\ index' = 1 /\ phase' = "processing"
  /\ UNCHANGED <<log, commands, receipts, head, version,
                 lastStart, lastAccepted, lastRejected>>

\* A matching base version stages an event. Its command remains claimed until
\* the whole SQL transaction commits. A committed head is not changed yet.
Accept ==
  /\ phase = "processing" /\ index <= Len(request)
  /\ request[index].base = version + Len(working)
  /\ head + Len(working) < MaxSeq
  /\ working' = Append(working, request[index])
  /\ index' = index + 1
  /\ UNCHANGED <<log, commands, receipts, head, version, phase, request, claimed,
                 lastStart, lastAccepted, lastRejected>>

\* A version conflict removes the provisional command reservation even if
\* another member of the same batch has already been staged successfully.
RejectVersion ==
  /\ phase = "processing" /\ index <= Len(request)
  /\ request[index].base # version + Len(working)
  /\ claimed' = claimed \ {request[index].command}
  /\ index' = index + 1
  /\ UNCHANGED <<log, commands, receipts, head, version, phase, request, working,
                 lastStart, lastAccepted, lastRejected>>

\* A matching member with no remaining BIGINT slot aborts the entire batch.
Overflow ==
  /\ phase = "processing" /\ index <= Len(request)
  /\ request[index].base = version + Len(working)
  /\ head + Len(working) = MaxSeq
  /\ phase' = "idle" /\ request' = <<>> /\ claimed' = {}
  /\ working' = <<>> /\ index' = 1
  /\ lastStart' = head /\ lastAccepted' = <<>> /\ lastRejected' = {}
  /\ UNCHANGED <<log, commands, receipts, head, version>>

\* Event rows, receipt rows, version bumps, counter, and surviving command
\* reservations become visible at this transaction boundary only.
Commit ==
  /\ phase = "processing" /\ index > Len(request)
  /\ log' = log \o working
  /\ commands' = commands \cup CommandIds(working)
  /\ receipts' = receipts \cup EventIds(working)
  /\ head' = head + Len(working)
  /\ version' = version + Len(working)
  /\ lastStart' = head /\ lastAccepted' = working
  /\ lastRejected' = CommandIds(request) \ CommandIds(working)
  /\ phase' = "idle" /\ request' = <<>> /\ claimed' = {}
  /\ working' = <<>> /\ index' = 1

Abort ==
  /\ phase = "processing"
  /\ phase' = "idle" /\ request' = <<>> /\ claimed' = {}
  /\ working' = <<>> /\ index' = 1
  /\ lastStart' = head /\ lastAccepted' = <<>> /\ lastRejected' = {}
  /\ UNCHANGED <<log, commands, receipts, head, version>>

Next ==
  \/ \E batch \in Requests : Begin(batch)
  \/ Accept \/ RejectVersion \/ Overflow \/ Commit \/ Abort
  \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ log \in Seq(Inputs) /\ working \in Seq(Inputs)
  /\ request \in Seq(Inputs) /\ lastAccepted \in Seq(Inputs)
  /\ commands \subseteq Commands /\ receipts \subseteq Events
  /\ head \in 0..MaxSeq /\ version \in 0..MaxSeq
  /\ phase \in {"idle", "processing"}
  /\ claimed \subseteq Commands /\ lastRejected \subseteq Commands
  /\ index \in 1..3 /\ lastStart \in 0..MaxSeq
HeadAndVersionMatch == head = Len(log) /\ version = Len(log)
CommittedRowsMatch == commands = CommandIds(log) /\ receipts = EventIds(log)
UniqueCommitted ==
  /\ Cardinality(EventIds(log)) = Len(log)
  /\ Cardinality(CommandIds(log)) = Len(log)
WorkingInOrder == phase = "processing" => working \in AcceptedFrom(request)
ClaimsExact == phase = "processing" =>
  claimed = CommandIds(working) \cup CommandIds(SubSeq(request, index, Len(request)))
ClaimsUncommitted == claimed \cap CommandIds(log) = {}
IdleHasNoClaims == phase = "idle" => claimed = {} /\ working = <<>>
CapacityBound == head + Len(working) <= MaxSeq
ReplyMatchesCommit ==
  /\ lastStart <= head
  /\ lastAccepted = SubSeq(log, lastStart + 1, Len(log))
  /\ head = lastStart + Len(lastAccepted)
RejectedCommandsFree == lastRejected \cap CommandIds(log) = {}

=============================================================================
