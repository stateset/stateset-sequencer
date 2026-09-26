/-!
For any WAL length and any event/receipt record type, a consistent physical
base prefix plus complete archived WAL through a chosen target reconstructs
exactly that target prefix. This is a proof about lists of committed records;
PostgreSQL backup consistency and archive completeness remain assumptions.
-/

namespace WalRecovery

theorem replay_exact {Record : Type} (wal archive base : List Record)
    (baseLength archiveLength target : Nat)
    (basePrefix : base = wal.take baseLength)
    (archivePrefix : archive = wal.take archiveLength)
    (baseBeforeTarget : baseLength ≤ target)
    (archiveCoversTarget : target ≤ archiveLength) :
    base ++ (archive.drop baseLength).take (target - baseLength) =
      wal.take target := by
  subst base
  subst archive
  have baseIsTargetPrefix : wal.take baseLength = (wal.take target).take baseLength := by
    rw [List.take_take]
    simp [Nat.min_eq_left baseBeforeTarget]
  have replayIsTargetSuffix :
      ((wal.take archiveLength).drop baseLength).take (target - baseLength) =
        (wal.take target).drop baseLength := by
    rw [List.take_drop, Nat.add_sub_of_le baseBeforeTarget, List.take_take]
    simp [Nat.min_eq_left archiveCoversTarget]
  rw [baseIsTargetPrefix, replayIsTargetSuffix]
  exact List.take_append_drop baseLength (wal.take target)

end WalRecovery
