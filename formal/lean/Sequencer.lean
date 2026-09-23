import ReceiptEncoding

/-!
An abstract committed stream for the PostgreSQL ingest paths. A successful
insert appends one fresh event at the next sequence number. Rejection and
transaction rollback leave the committed state unchanged. This proves the
transition rule, not that the Rust and SQL implement it.
-/

namespace Sequencer

structure State (Event : Type) where
  events : List Event
  head : Nat

def Valid {Event : Type} (s : State Event) : Prop :=
  s.head = s.events.length ∧ s.events.Nodup

def accept {Event : Type} (s : State Event) (event : Event) : State Event :=
  { events := s.events ++ [event], head := s.head + 1 }

def reject {Event : Type} (s : State Event) : State Event := s

theorem initial_valid {Event : Type} : Valid (State.mk ([] : List Event) 0) := by
  simp [Valid]

theorem accept_valid {Event : Type} [DecidableEq Event]
    (s : State Event) (event : Event)
    (h : Valid s) (fresh : event ∉ s.events) : Valid (accept s event) := by
  rcases h with ⟨hhead, hnodup⟩
  constructor
  · simp [accept, hhead]
  · change (s.events ++ [event]).Nodup
    apply (List.pairwise_append).2
    refine ⟨hnodup, by simp, ?_⟩
    intro x hx y hy
    simp only [List.mem_singleton] at hy
    subst y
    intro heq
    apply fresh
    exact heq ▸ hx

/-- A committed batch is the list of successfully inserted event IDs. -/
def acceptBatch {Event : Type} (s : State Event) (batch : List Event) : State Event :=
  { events := s.events ++ batch, head := s.head + batch.length }

theorem acceptBatch_valid {Event : Type} [DecidableEq Event]
    (s : State Event) (batch : List Event)
    (h : Valid s) (distinct : batch.Nodup)
    (fresh : ∀ event ∈ batch, event ∉ s.events) :
    Valid (acceptBatch s batch) := by
  rcases h with ⟨hhead, hnodup⟩
  constructor
  · simp [acceptBatch, hhead]
  · change (s.events ++ batch).Nodup
    apply (List.pairwise_append).2
    refine ⟨hnodup, distinct, ?_⟩
    intro x hx y hy heq
    exact (fresh y hy) (heq ▸ hx)

theorem accepted_batch_size {Event : Type} (s : State Event) (batch : List Event) :
    (acceptBatch s batch).head = s.head + batch.length := rfl

theorem reject_valid {Event : Type} (s : State Event)
    (h : Valid s) : Valid (reject s) := h

theorem rollback_valid {Event : Type} (s : State Event)
    (h : Valid s) : Valid s := h

theorem accepted_sequence {Event : Type} (s : State Event) (event : Event) :
    (accept s event).head = s.head + 1 := rfl

theorem accept_within_limit {Event : Type} (s : State Event)
    (event : Event) (limit : Nat) (capacity : s.head < limit) :
    (accept s event).head ≤ limit := by
  simpa [accept] using Nat.succ_le_of_lt capacity

theorem rejected_sequence {Event : Type} (s : State Event) :
    (reject s).head = s.head := rfl

inductive Step {Event : Type} : State Event → State Event → Prop where
  | accepted (s : State Event) (event : Event) (fresh : event ∉ s.events) :
      Step s (accept s event)
  | acceptedBatch (s : State Event) (batch : List Event)
      (distinct : batch.Nodup) (fresh : ∀ event ∈ batch, event ∉ s.events) :
      Step s (acceptBatch s batch)
  | unchanged (s : State Event) : Step s s

inductive Reaches {Event : Type} : State Event → State Event → Prop where
  | refl (s : State Event) : Reaches s s
  | next {start middle finish : State Event} :
      Reaches start middle → Step middle finish → Reaches start finish

theorem step_valid {Event : Type} [DecidableEq Event]
    {before after : State Event} (h : Valid before)
    (step : Step before after) : Valid after := by
  cases step with
  | accepted event fresh => exact accept_valid before event h fresh
  | acceptedBatch batch distinct fresh =>
      exact acceptBatch_valid before batch h distinct fresh
  | unchanged => exact h

theorem all_commits_valid {Event : Type} [DecidableEq Event]
    {start finish : State Event} (h : Valid start)
    (trace : Reaches start finish) : Valid finish := by
  induction trace with
  | refl => exact h
  | next prior step ih => exact step_valid ih step

/-- A collection of streams with globally unique event IDs. -/
structure World (Stream Event : Type) where
  events : Stream → List Event
  head : Stream → Nat

def emptyWorld (Stream Event : Type) : World Stream Event :=
  { events := fun _ => [], head := fun _ => 0 }

def WorldValid {Stream Event : Type} (world : World Stream Event) : Prop :=
  (∀ stream, Valid (State.mk (world.events stream) (world.head stream))) ∧
  (∀ stream other event, stream ≠ other →
    event ∈ world.events stream → event ∉ world.events other)

theorem emptyWorld_valid (Stream Event : Type) : WorldValid (emptyWorld Stream Event) := by
  constructor
  · intro stream
    exact initial_valid
  · intro stream other event _ present
    simp [emptyWorld] at present

def commitBatch {Stream Event : Type} [DecidableEq Stream]
    (world : World Stream Event) (target : Stream) (batch : List Event) :
    World Stream Event :=
  { events := fun stream =>
      if stream = target then world.events stream ++ batch else world.events stream
    head := fun stream =>
      if stream = target then world.head stream + batch.length else world.head stream }

theorem commitBatch_valid {Stream Event : Type}
    [DecidableEq Stream] [DecidableEq Event]
    (world : World Stream Event) (target : Stream) (batch : List Event)
    (valid : WorldValid world) (distinct : batch.Nodup)
    (fresh : ∀ stream event, event ∈ batch → event ∉ world.events stream) :
    WorldValid (commitBatch world target batch) := by
  rcases valid with ⟨hlocal, hglobal⟩
  constructor
  · intro stream
    by_cases h : stream = target
    · subst stream
      simpa [commitBatch, acceptBatch] using
        (acceptBatch_valid (State.mk (world.events target) (world.head target))
          batch (hlocal target) distinct (fresh target))
    · simpa [commitBatch, h] using hlocal stream
  · intro stream other event different present
    by_cases hs : stream = target
    · subst stream
      have ho : other ≠ target := Ne.symm different
      simp only [commitBatch, if_pos rfl] at present
      simp only [commitBatch, if_neg ho]
      rcases List.mem_append.mp present with old | added
      · exact hglobal target other event different old
      · exact fresh other event added
    · by_cases ho : other = target
      · subst other
        simp only [commitBatch, if_neg hs] at present
        simp only [commitBatch, if_pos rfl]
        intro inTarget
        rcases List.mem_append.mp inTarget with old | added
        · exact hglobal stream target event different present old
        · exact (fresh stream event added) present
      · have presentOld : event ∈ world.events stream := by
          simpa [commitBatch, hs] using present
        simpa [commitBatch, ho] using
          (hglobal stream other event different presentOld)

inductive WorldStep {Stream Event : Type} [DecidableEq Stream] :
    World Stream Event → World Stream Event → Prop where
  | committed (world : World Stream Event) (target : Stream) (batch : List Event)
      (distinct : batch.Nodup)
      (fresh : ∀ stream event, event ∈ batch → event ∉ world.events stream) :
      WorldStep world (commitBatch world target batch)
  | unchanged (world : World Stream Event) : WorldStep world world

inductive WorldReaches {Stream Event : Type} [DecidableEq Stream] :
    World Stream Event → World Stream Event → Prop where
  | refl (world : World Stream Event) : WorldReaches world world
  | next {start middle finish : World Stream Event} :
      WorldReaches start middle → WorldStep middle finish → WorldReaches start finish

theorem all_world_commits_valid {Stream Event : Type}
    [DecidableEq Stream] [DecidableEq Event]
    {start finish : World Stream Event} (valid : WorldValid start)
    (history : WorldReaches start finish) : WorldValid finish := by
  induction history with
  | refl => exact valid
  | next prior step ih =>
      cases step with
      | committed target batch distinct fresh =>
          exact commitBatch_valid _ target batch ih distinct fresh
      | unchanged => exact ih

theorem from_empty_world_valid {Stream Event : Type}
    [DecidableEq Stream] [DecidableEq Event]
    {finish : World Stream Event}
    (history : WorldReaches (emptyWorld Stream Event) finish) :
    WorldValid finish :=
  all_world_commits_valid (emptyWorld_valid Stream Event) history

/-- The counter reservation API returns inclusive sequence ranges. -/
structure Range where
  start : Nat
  finish : Nat

def allocate (head count : Nat) : Range :=
  { start := head + 1, finish := head + count }

theorem allocation_nonempty (head count : Nat) (positive : 0 < count) :
    (allocate head count).start ≤ (allocate head count).finish := by
  simp [allocate]
  exact Nat.succ_le_of_lt positive

theorem consecutive_allocations_disjoint (head firstCount secondCount : Nat) :
    (allocate head firstCount).finish <
      (allocate (head + firstCount) secondCount).start := by
  simp [allocate]

/-- A stream with a version counter for each entity. -/
structure EntityState (Entity : Type) where
  events : List Entity
  head : Nat
  versions : Entity → Nat

def EntityValid {Entity : Type} [DecidableEq Entity]
    (s : EntityState Entity) : Prop :=
  s.head = s.events.length ∧
    ∀ entity, s.versions entity = s.events.countP (fun x => decide (x = entity))

def commitEntity {Entity : Type} [DecidableEq Entity]
    (s : EntityState Entity) (entity : Entity) : EntityState Entity :=
  { events := s.events ++ [entity]
    head := s.head + 1
    versions := fun e => if e = entity then s.versions e + 1 else s.versions e }

theorem entity_commit_valid {Entity : Type} [DecidableEq Entity]
    (s : EntityState Entity) (entity : Entity) (h : EntityValid s) :
    EntityValid (commitEntity s entity) := by
  rcases h with ⟨hhead, hversions⟩
  constructor
  · simp [commitEntity, hhead]
  · intro e
    by_cases he : e = entity
    · subst e
      simp [commitEntity, hversions entity]
    · simp [commitEntity, he, Ne.symm he, hversions e]

/-- If each writer acquires command keys in increasing order, two writers
    cannot wait on a key held by the other at the same time. -/
theorem no_two_writer_command_lock_cycle
    (heldA nextA heldB nextB : Nat)
    (orderedA : heldA < nextA) (orderedB : heldB < nextB)
    (aWaitsOnB : nextA = heldB) (bWaitsOnA : nextB = heldA) : False := by
  have ab : heldA < heldB := by simpa [aWaitsOnB] using orderedA
  have ba : heldB < heldA := by simpa [bWaitsOnA] using orderedB
  exact (Nat.lt_asymm ab ba)

end Sequencer

namespace Merkle

/-- An abstract binary Merkle tree. Hashing is an opaque node-combining
    function; the theorem does not assume collision resistance. -/
inductive Tree (Hash : Type) where
  | leaf : Hash → Tree Hash
  | node : Tree Hash → Tree Hash → Tree Hash

def root {Hash : Type} (combine : Hash → Hash → Hash) : Tree Hash → Hash
  | .leaf value => value
  | .node left right => combine (root combine left) (root combine right)

structure Sibling (Hash : Type) where
  hash : Hash
  onRight : Bool

def verify {Hash : Type} (combine : Hash → Hash → Hash)
    (leaf : Hash) (path : List (Sibling Hash)) : Hash :=
  path.foldl (fun current step =>
    if step.onRight then combine current step.hash else combine step.hash current) leaf

inductive InclusionPath {Hash : Type} (combine : Hash → Hash → Hash) :
    Tree Hash → Hash → List (Sibling Hash) → Prop where
  | leaf (value : Hash) : InclusionPath combine (.leaf value) value []
  | left {l r value path} (child : InclusionPath combine l value path) :
      InclusionPath combine (.node l r) value
        (path ++ [{ hash := root combine r, onRight := true }])
  | right {l r value path} (child : InclusionPath combine r value path) :
      InclusionPath combine (.node l r) value
        (path ++ [{ hash := root combine l, onRight := false }])

theorem inclusion_sound {Hash : Type} (combine : Hash → Hash → Hash)
    {tree : Tree Hash} {leaf : Hash} {path : List (Sibling Hash)}
    (included : InclusionPath combine tree leaf path) :
    verify combine leaf path = root combine tree := by
  induction included with
  | leaf => rfl
  | left child ih =>
      simp [verify] at ih
      simp [verify, List.foldl_append, root, ih]
  | right child ih =>
      simp [verify] at ih
      simp [verify, List.foldl_append, root, ih]

end Merkle

namespace Signing

/-- Abstract form of V2's presence byte followed by fixed-width value bytes.
    The optional command ID and base version use this shape independently. -/
def encodeOptional (value : Option Nat) : List Nat :=
  match value with
  | none => [0]
  | some n => [1, n]

theorem encodeOptional_injective (left right : Option Nat)
    (equal : encodeOptional left = encodeOptional right) : left = right := by
  cases left <;> cases right <;> simp [encodeOptional] at equal ⊢
  exact equal

end Signing

namespace Payments

/-- A settled batch partitions its authorized amount between successful and
    failed intents, regardless of the order or number of intents. -/
theorem settlement_partitions_total {Intent : Type}
    (amount : Intent → Nat) (failed : Intent → Bool) (batch : List Intent) :
    ((batch.filter failed).map amount).sum +
      ((batch.filter (fun intent => !failed intent)).map amount).sum =
      (batch.map amount).sum := by
  induction batch with
  | nil => simp
  | cons intent rest ih =>
      by_cases h : failed intent = true
      · simp [h, ih, Nat.add_assoc, Nat.add_left_comm, Nat.add_comm]
      · have hf : failed intent = false := Bool.eq_false_iff.mpr h
        simp [hf, ih, Nat.add_assoc, Nat.add_left_comm, Nat.add_comm]

theorem settlement_partitions_each_asset {Intent Asset : Type}
    [DecidableEq Asset] (amount : Intent → Nat) (asset : Intent → Asset)
    (chosen : Asset) (failed : Intent → Bool) (batch : List Intent) :
    ((batch.filter failed).map (fun intent =>
      if asset intent = chosen then amount intent else 0)).sum +
    ((batch.filter (fun intent => !failed intent)).map (fun intent =>
      if asset intent = chosen then amount intent else 0)).sum =
    (batch.map (fun intent =>
      if asset intent = chosen then amount intent else 0)).sum :=
  settlement_partitions_total
    (fun intent => if asset intent = chosen then amount intent else 0) failed batch

end Payments

namespace SharedAdmission

/-- One serialized database admission either consumes one available slot or
    leaves the current window unchanged. -/
def take (limit used : Nat) : Nat :=
  if used < limit then used + 1 else used

theorem take_respects_limit (limit used : Nat) (before : used ≤ limit) :
    take limit used ≤ limit := by
  unfold take
  split
  · simpa using Nat.succ_le_of_lt ‹used < limit›
  · exact before

theorem fold_takes_respects_limit (limit used : Nat) (requests : List Unit)
    (before : used ≤ limit) :
    requests.foldl (fun current _ => take limit current) used ≤ limit := by
  induction requests generalizing used with
  | nil => simpa using before
  | cons _ rest ih =>
      simp only [List.foldl_cons]
      exact ih _ (take_respects_limit limit used before)

theorem repeated_takes_respect_limit (limit : Nat) (requests : List Unit) :
    requests.foldl (fun used _ => take limit used) 0 ≤ limit :=
  fold_takes_respects_limit limit 0 requests (Nat.zero_le _)

end SharedAdmission

namespace AuditTrail

structure Entry (Action Hash : Type) where
  sequence : Nat
  action : Action
  previous : Hash
  hash : Hash

def append {Action Hash : Type} (hash : Hash → Action → Hash)
    (genesis : Hash) (entries : List (Entry Action Hash)) (action : Action) :
    List (Entry Action Hash) :=
  let previous := (entries.getLast?).map (·.hash) |>.getD genesis
  entries ++ [{ sequence := entries.length + 1, action := action,
                previous := previous, hash := hash previous action }]

/-- Appending one audited effect preserves a one-to-one count of effects and
    audit records, for arbitrary existing log lengths. -/
theorem append_preserves_complete {Action Hash : Type}
    (hash : Hash → Action → Hash) (genesis : Hash)
    (effects : List Action) (entries : List (Entry Action Hash))
    (action : Action) (complete : effects.length = entries.length) :
    (effects ++ [action]).length = (append hash genesis entries action).length := by
  simp [append, complete]

theorem append_sequence {Action Hash : Type}
    (hash : Hash → Action → Hash) (genesis : Hash)
    (entries : List (Entry Action Hash)) (action : Action) :
    ((append hash genesis entries action).getLast?).map (·.sequence) =
      some (entries.length + 1) := by
  simp [append]

end AuditTrail

namespace KeyRotation

def Readable (available ciphertextKeys : List Nat) : Prop :=
  ∀ key ∈ ciphertextKeys, key ∈ available

/-- An old key can be removed only after no stored ciphertext needs it. -/
theorem retire_unused_preserves_readability
    (available ciphertextKeys : List Nat) (oldKey : Nat)
    (readable : Readable available ciphertextKeys)
    (unused : ∀ key ∈ ciphertextKeys, key ≠ oldKey) :
    Readable (available.filter (· ≠ oldKey)) ciphertextKeys := by
  intro key inCiphertexts
  have inAvailable := readable key inCiphertexts
  have notOld := unused key inCiphertexts
  simp [List.mem_filter, inAvailable, notOld]

end KeyRotation

namespace Destination

def submit (effects : Nat) : Nat :=
  if effects = 0 then 1 else effects

/-- A destination keyed by batch ID records at most one effect across any
    sequence of submissions by current or stale leaders. -/
theorem submit_preserves_single_effect (effects : Nat) (bound : effects ≤ 1) :
    submit effects ≤ 1 := by
  by_cases empty : effects = 0
  · simp [submit, empty]
  · simpa [submit, empty] using bound

theorem fold_submits_preserves_single_effect (attempts : List Unit)
    (effects : Nat) (bound : effects ≤ 1) :
    attempts.foldl (fun current _ => submit current) effects ≤ 1 := by
  induction attempts generalizing effects with
  | nil => simpa using bound
  | cons _ rest ih =>
      simp only [List.foldl_cons]
      exact ih _ (submit_preserves_single_effect effects bound)

theorem repeated_submits_preserve_single_effect (attempts : List Unit) :
    attempts.foldl (fun effects _ => submit effects) 0 ≤ 1 :=
  fold_submits_preserves_single_effect attempts 0 (Nat.zero_le _)

end Destination
