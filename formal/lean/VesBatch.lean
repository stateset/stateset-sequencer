/-!
An arbitrary-length abstraction of one VES batch for one entity. Inputs have
already passed signature, policy, event-ID, and command-ID checks. The scan
matches the implementation's per-event base-version decision after the stream
counter lock. PostgreSQL atomicity is represented by applying `commit` once
after the entire scan, or by leaving the state unchanged on rollback.

These theorems establish properties of the transition rule; they do not prove
that the Rust and SQL code implement it.
-/

namespace VesBatch

structure Input (Event Command : Type) where
  eventId : Event
  commandId : Command
  baseVersion : Nat

structure Scan (Event Command : Type) where
  accepted : List (Input Event Command)
  rejected : List (Input Event Command)
  nextVersion : Nat

def step {Event Command : Type} (scan : Scan Event Command)
    (input : Input Event Command) : Scan Event Command :=
  if input.baseVersion = scan.nextVersion then
    { scan with accepted := scan.accepted ++ [input], nextVersion := scan.nextVersion + 1 }
  else
    { scan with rejected := scan.rejected ++ [input] }

def run {Event Command : Type} (startVersion : Nat)
    (inputs : List (Input Event Command)) : Scan Event Command :=
  inputs.foldl step { accepted := [], rejected := [], nextVersion := startVersion }

def ScanCorrect {Event Command : Type} (startVersion : Nat)
    (scan : Scan Event Command) : Prop :=
  scan.nextVersion = startVersion + scan.accepted.length

theorem step_preserves_count {Event Command : Type} (startVersion : Nat)
    (scan : Scan Event Command) (input : Input Event Command)
    (correct : ScanCorrect startVersion scan) :
    ScanCorrect startVersion (step scan input) := by
  unfold ScanCorrect at correct ⊢
  by_cases hmatch : input.baseVersion = scan.nextVersion
  · simp [step, hmatch, correct, Nat.add_assoc]
  · simpa [step, hmatch] using correct

theorem fold_preserves_count {Event Command : Type} (startVersion : Nat)
    (inputs : List (Input Event Command)) (scan : Scan Event Command)
    (correct : ScanCorrect startVersion scan) :
    ScanCorrect startVersion (inputs.foldl step scan) := by
  induction inputs generalizing scan with
  | nil => simpa using correct
  | cons input rest ih =>
      simpa only [List.foldl_cons] using
        ih (step scan input) (step_preserves_count startVersion scan input correct)

theorem run_advances_by_accepted {Event Command : Type} (startVersion : Nat)
    (inputs : List (Input Event Command)) :
    (run startVersion inputs).nextVersion =
      startVersion + (run startVersion inputs).accepted.length := by
  exact fold_preserves_count startVersion inputs
    { accepted := [], rejected := [], nextVersion := startVersion } (by simp [ScanCorrect])

theorem step_accounts_for_input {Event Command : Type}
    (scan : Scan Event Command) (input : Input Event Command) :
    (step scan input).accepted.length + (step scan input).rejected.length =
      scan.accepted.length + scan.rejected.length + 1 := by
  by_cases hmatch : input.baseVersion = scan.nextVersion
  · simp [step, hmatch, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]
  · simp [step, hmatch, Nat.add_assoc, Nat.add_comm, Nat.add_left_comm]

theorem fold_accounts_for_inputs {Event Command : Type}
    (inputs : List (Input Event Command)) (scan : Scan Event Command) :
    (inputs.foldl step scan).accepted.length +
      (inputs.foldl step scan).rejected.length =
      scan.accepted.length + scan.rejected.length + inputs.length := by
  induction inputs generalizing scan with
  | nil => simp
  | cons input rest ih =>
      simp only [List.foldl_cons, List.length_cons]
      rw [ih (step scan input), step_accounts_for_input]
      omega

theorem run_accounts_for_inputs {Event Command : Type} (startVersion : Nat)
    (inputs : List (Input Event Command)) :
    (run startVersion inputs).accepted.length +
      (run startVersion inputs).rejected.length = inputs.length := by
  simpa [run] using fold_accounts_for_inputs inputs
    { accepted := [], rejected := [], nextVersion := startVersion }

theorem step_preserves_inputs {Event Command : Type}
    (scan : Scan Event Command) (input : Input Event Command) :
    List.Perm ((step scan input).accepted ++ (step scan input).rejected)
      ((scan.accepted ++ scan.rejected) ++ [input]) := by
  by_cases hmatch : input.baseVersion = scan.nextVersion
  · have reordered :
        List.Perm (scan.accepted ++ ([input] ++ scan.rejected))
          (scan.accepted ++ (scan.rejected ++ [input])) :=
      (List.perm_append_comm : List.Perm ([input] ++ scan.rejected)
        (scan.rejected ++ [input])).append_left scan.accepted
    simpa [step, hmatch, List.append_assoc] using reordered
  · simp [step, hmatch, List.append_assoc]

theorem fold_preserves_inputs {Event Command : Type}
    (inputs : List (Input Event Command)) (scan : Scan Event Command) :
    List.Perm
      ((inputs.foldl step scan).accepted ++ (inputs.foldl step scan).rejected)
      ((scan.accepted ++ scan.rejected) ++ inputs) := by
  induction inputs generalizing scan with
  | nil => simp
  | cons input rest ih =>
      simp only [List.foldl_cons]
      have prior := (step_preserves_inputs scan input).append_right rest
      exact (ih (step scan input)).trans (by
        simpa [List.append_assoc] using prior)

/-- Every original input appears exactly once in the accepted or rejected list. -/
theorem run_partitions_inputs {Event Command : Type} (startVersion : Nat)
    (inputs : List (Input Event Command)) :
    List.Perm ((run startVersion inputs).accepted ++
      (run startVersion inputs).rejected) inputs := by
  simpa [run] using fold_preserves_inputs inputs
    { accepted := [], rejected := [], nextVersion := startVersion }

structure State (Event Command : Type) where
  log : List (Input Event Command)
  commands : List Command
  receipts : List Event
  head : Nat
  version : Nat

def Valid {Event Command : Type} (state : State Event Command) : Prop :=
  state.head = state.log.length ∧
  state.version = state.log.length ∧
  state.commands = state.log.map Input.commandId ∧
  state.receipts = state.log.map Input.eventId

def commit {Event Command : Type} (state : State Event Command)
    (scan : Scan Event Command) : State Event Command :=
  { log := state.log ++ scan.accepted
    commands := state.commands ++ scan.accepted.map Input.commandId
    receipts := state.receipts ++ scan.accepted.map Input.eventId
    head := state.head + scan.accepted.length
    version := scan.nextVersion }

theorem commit_preserves_valid {Event Command : Type}
    (state : State Event Command) (inputs : List (Input Event Command))
    (valid : Valid state) :
    Valid (commit state (run state.version inputs)) := by
  rcases valid with ⟨head, version, commands, receipts⟩
  constructor
  · simp [commit, head]
  constructor
  · simp [commit, run_advances_by_accepted, version]
  constructor
  · simp [commit, commands]
  · simp [commit, receipts]

def abort {Event Command : Type} (state : State Event Command) : State Event Command := state

theorem abort_preserves_state {Event Command : Type} (state : State Event Command) :
    abort state = state := rfl

end VesBatch
