/-!
Fixed-width receipt preimages bind each field before hashing. This proves the
byte layout is unambiguous when UUIDs are 16 bytes, sequence numbers are eight
bytes, and the signing hash is 32 bytes. SHA-256 collision resistance and the
Rust implementation are separate assumptions checked by executable vectors.
-/

namespace ReceiptEncoding

def preimage (domain tenant store event sequence signingHash : List UInt8) : List UInt8 :=
  domain ++ (tenant ++ (store ++ (event ++ (sequence ++ signingHash))))

theorem preimage_fields_injective
    (domain tenant₁ tenant₂ store₁ store₂ event₁ event₂
     sequence₁ sequence₂ hash₁ hash₂ : List UInt8)
    (tenantLength₁ : tenant₁.length = 16) (tenantLength₂ : tenant₂.length = 16)
    (storeLength₁ : store₁.length = 16) (storeLength₂ : store₂.length = 16)
    (eventLength₁ : event₁.length = 16) (eventLength₂ : event₂.length = 16)
    (sequenceLength₁ : sequence₁.length = 8) (sequenceLength₂ : sequence₂.length = 8)
    (same : preimage domain tenant₁ store₁ event₁ sequence₁ hash₁ =
            preimage domain tenant₂ store₂ event₂ sequence₂ hash₂) :
    tenant₁ = tenant₂ ∧ store₁ = store₂ ∧ event₁ = event₂ ∧
    sequence₁ = sequence₂ ∧ hash₁ = hash₂ := by
  unfold preimage at same
  have tail := List.append_inj_right same rfl
  obtain ⟨ht, tail⟩ := List.append_inj tail (tenantLength₁.trans tenantLength₂.symm)
  obtain ⟨hs, tail⟩ := List.append_inj tail (storeLength₁.trans storeLength₂.symm)
  obtain ⟨he, tail⟩ := List.append_inj tail (eventLength₁.trans eventLength₂.symm)
  obtain ⟨hq, hh⟩ := List.append_inj tail (sequenceLength₁.trans sequenceLength₂.symm)
  exact ⟨ht, hs, he, hq, hh⟩

end ReceiptEncoding
