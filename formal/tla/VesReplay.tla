----------------------------- MODULE VesReplay -----------------------------
EXTENDS FiniteSets, Integers

CONSTANTS Streams, Events, Bodies, Commands, MaxSeq,
          NoStream, NoBody, NoCommand, NoEvent
ASSUME /\ Streams # {} /\ Events # {} /\ Bodies # {}
       /\ NoStream \notin Streams /\ NoBody \notin Bodies
       /\ NoCommand \notin Commands /\ NoEvent \notin Events
       /\ MaxSeq \in Nat

VARIABLES savedStream, savedBody, savedCommand, savedSeq, receiptSeq,
          commandOwner, head, last
vars == <<savedStream, savedBody, savedCommand, savedSeq, receiptSeq,
          commandOwner, head, last>>

Stored(s) == {e \in Events : savedStream[e] = s}

Init ==
  /\ savedStream = [e \in Events |-> NoStream]
  /\ savedBody = [e \in Events |-> NoBody]
  /\ savedCommand = [e \in Events |-> NoCommand]
  /\ savedSeq = [e \in Events |-> 0]
  /\ receiptSeq = [e \in Events |-> 0]
  /\ commandOwner = [s \in Streams |-> [c \in Commands |-> NoEvent]]
  /\ head = [s \in Streams |-> 0]
  /\ last = [kind |-> "idle", stream |-> NoStream,
             event |-> NoEvent, body |-> NoBody,
             command |-> NoCommand, sequence |-> 0]

Fresh(s, e, c) ==
  /\ savedStream[e] = NoStream
  /\ IF c = NoCommand THEN TRUE ELSE commandOwner[s][c] = NoEvent
  /\ head[s] < MaxSeq

Exact(s, e, b, c) ==
  /\ savedStream[e] = s
  /\ savedBody[e] = b
  /\ savedCommand[e] = c
  /\ receiptSeq[e] > 0

\* The event, command reservation, receipt, and counter commit atomically.
Accept(s, e, b, c) ==
  /\ s \in Streams /\ e \in Events /\ b \in Bodies
  /\ c \in Commands \cup {NoCommand}
  /\ Fresh(s, e, c)
  /\ savedStream' = [savedStream EXCEPT ![e] = s]
  /\ savedBody' = [savedBody EXCEPT ![e] = b]
  /\ savedCommand' = [savedCommand EXCEPT ![e] = c]
  /\ savedSeq' = [savedSeq EXCEPT ![e] = head[s] + 1]
  /\ receiptSeq' = [receiptSeq EXCEPT ![e] = head[s] + 1]
  /\ commandOwner' = IF c = NoCommand THEN commandOwner
                      ELSE [commandOwner EXCEPT ![s][c] = e]
  /\ head' = [head EXCEPT ![s] = @ + 1]
  /\ last' = [kind |-> "accepted", stream |-> s, event |-> e,
              body |-> b, command |-> c, sequence |-> head[s] + 1]

\* Exact replay returns the original receipt, with no new sequence number.
Replay(s, e, b, c) ==
  /\ s \in Streams /\ e \in Events /\ b \in Bodies
  /\ c \in Commands \cup {NoCommand}
  /\ Exact(s, e, b, c)
  /\ last' = [kind |-> "replayed", stream |-> s, event |-> e,
              body |-> b, command |-> c, sequence |-> receiptSeq[e]]
  /\ UNCHANGED <<savedStream, savedBody, savedCommand, savedSeq,
                 receiptSeq, commandOwner, head>>

\* A changed event ID or reused command ID receives no receipt.
Reject(s, e, b, c) ==
  /\ s \in Streams /\ e \in Events /\ b \in Bodies
  /\ c \in Commands \cup {NoCommand}
  /\ ~Fresh(s, e, c)
  /\ ~Exact(s, e, b, c)
  /\ last' = [kind |-> "rejected", stream |-> s, event |-> e,
              body |-> b, command |-> c, sequence |-> 0]
  /\ UNCHANGED <<savedStream, savedBody, savedCommand, savedSeq,
                 receiptSeq, commandOwner, head>>

Next ==
  (\E s \in Streams, e \in Events, b \in Bodies,
       c \in Commands \cup {NoCommand} :
       Accept(s, e, b, c) \/ Replay(s, e, b, c) \/ Reject(s, e, b, c))
  \/ UNCHANGED vars
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ savedStream \in [Events -> Streams \cup {NoStream}]
  /\ savedBody \in [Events -> Bodies \cup {NoBody}]
  /\ savedCommand \in [Events -> Commands \cup {NoCommand}]
  /\ savedSeq \in [Events -> 0..MaxSeq]
  /\ receiptSeq \in [Events -> 0..MaxSeq]
  /\ commandOwner \in [Streams -> [Commands -> Events \cup {NoEvent}]]
  /\ head \in [Streams -> 0..MaxSeq]

ReceiptAtomicity == \A e \in Events :
  (savedStream[e] = NoStream) <=> (receiptSeq[e] = 0)
ReceiptMatches == \A e \in Events : receiptSeq[e] = savedSeq[e]
HeadMatches == \A s \in Streams : head[s] = Cardinality(Stored(s))
UniqueSequences == \A s \in Streams : \A e, f \in Stored(s) :
  savedSeq[e] = savedSeq[f] => e = f
NoSequenceGaps == \A s \in Streams :
  {savedSeq[e] : e \in Stored(s)} = 1..head[s]
CommandUnique == \A s \in Streams : \A e \in Stored(s) :
  IF savedCommand[e] = NoCommand THEN TRUE
  ELSE commandOwner[s][savedCommand[e]] = e
CommandOwnerSound == \A s \in Streams : \A c \in Commands :
  IF commandOwner[s][c] = NoEvent THEN TRUE
  ELSE /\ savedStream[commandOwner[s][c]] = s
       /\ savedCommand[commandOwner[s][c]] = c
ReplySound ==
  IF last.kind \in {"accepted", "replayed"}
  THEN /\ savedStream[last.event] = last.stream
       /\ savedBody[last.event] = last.body
       /\ savedCommand[last.event] = last.command
       /\ receiptSeq[last.event] = last.sequence
  ELSE last.sequence = 0

=============================================================================
