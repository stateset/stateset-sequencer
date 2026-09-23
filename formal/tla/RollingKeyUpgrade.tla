------------------------- MODULE RollingKeyUpgrade ---------------------------
EXTENDS FiniteSets
CONSTANTS Nodes
ASSUME Cardinality(Nodes) = 2
VARIABLES newReaders, newWriters, oldReaders, ciphertextKeys, oldKeyRetired
vars == <<newReaders, newWriters, oldReaders, ciphertextKeys, oldKeyRetired>>
Init == /\ newReaders = {} /\ newWriters = {} /\ oldReaders = Nodes
        /\ ciphertextKeys = {"old"} /\ oldKeyRetired = FALSE
InstallReader(n) == /\ n \in Nodes \ newReaders
                    /\ newReaders' = newReaders \cup {n}
                    /\ UNCHANGED <<newWriters, oldReaders, ciphertextKeys, oldKeyRetired>>
Promote(n) == /\ n \in Nodes \ newWriters
              /\ newReaders = Nodes
              /\ newWriters' = newWriters \cup {n}
              /\ UNCHANGED <<newReaders, oldReaders, ciphertextKeys, oldKeyRetired>>
Write(n) == /\ n \in Nodes
            /\ ciphertextKeys' = ciphertextKeys \cup
                  {IF n \in newWriters THEN "new" ELSE "old"}
            /\ UNCHANGED <<newReaders, newWriters, oldReaders, oldKeyRetired>>
Reencrypt == /\ newWriters = Nodes
             /\ ciphertextKeys' = {"new"}
             /\ UNCHANGED <<newReaders, newWriters, oldReaders, oldKeyRetired>>
Retire == /\ newWriters = Nodes
          /\ "old" \notin ciphertextKeys
          /\ oldReaders' = {} /\ oldKeyRetired' = TRUE
          /\ UNCHANGED <<newReaders, newWriters, ciphertextKeys>>
Next == (\E n \in Nodes : InstallReader(n) \/ Promote(n) \/ Write(n))
        \/ Reencrypt \/ Retire
Spec == Init /\ [][Next]_vars
AllReadable == oldKeyRetired => "old" \notin ciphertextKeys
NoOldWriterAfterRetirement == oldKeyRetired => newWriters = Nodes
EveryNodeCanRead == \A n \in Nodes :
  /\ ("old" \in ciphertextKeys => n \in oldReaders)
  /\ ("new" \in ciphertextKeys => n \in newReaders)
=============================================================================
