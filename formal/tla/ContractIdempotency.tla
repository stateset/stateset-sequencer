------------------------- MODULE ContractIdempotency -------------------------
EXTENDS Integers
CONSTANTS Workers, BatchFields
ASSUME /\ Workers # {} /\ BatchFields # {}
VARIABLES stored, accepted, localRecorded, localFields, mismatchRejected
vars == <<stored, accepted, localRecorded, localFields, mismatchRejected>>
Init == /\ stored = "none" /\ accepted = 0 /\ localRecorded = FALSE
        /\ localFields = "none" /\ mismatchRejected = FALSE
Submit(w, fields) ==
  /\ w \in Workers /\ fields \in BatchFields
  /\ IF stored = "none"
        THEN /\ stored' = fields /\ accepted' = 1
        ELSE /\ stored' = stored /\ accepted' = accepted
  /\ mismatchRejected' = (mismatchRejected \/ (stored # "none" /\ fields # stored))
  /\ UNCHANGED <<localRecorded, localFields>>
Record(fields) == /\ fields \in BatchFields /\ stored = fields
                  /\ localRecorded' = TRUE /\ localFields' = fields
                  /\ UNCHANGED <<stored, accepted, mismatchRejected>>
LoseLocal == /\ localRecorded /\ localRecorded' = FALSE
             /\ localFields' = "none"
             /\ UNCHANGED <<stored, accepted, mismatchRejected>>
Next == (\E w \in Workers, f \in BatchFields : Submit(w, f))
        \/ (\E f \in BatchFields : Record(f)) \/ LoseLocal
Spec == Init /\ [][Next]_vars
AtMostOneEffect == accepted <= 1
RecordedFieldsMatch == localRecorded => localFields = stored
=============================================================================
