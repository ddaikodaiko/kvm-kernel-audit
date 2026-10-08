# VERIFIED against pinned v6.1.74 — shadow-MMU rmap UAF (CVE-2026-46113 + CVE-2026-53359)

**Status:** CONFIRMED present in source. **Date:** 2026-10-08.
**Method:** read-only inspection of the pinned stable tag `v6.1.74`
(`git fetch stable refs/tags/v6.1.74`) + diff against the two upstream fix commits.
No code executed, no PoC. This is corroboration of a **public, already-patched** bug
class on our exact kvmCTF target. See `RELATED-PUBLIC-DISCLOSURES-v6.1.74.md` for the
disclosure/provenance context.

---

## Bottom line

On stock **v6.1.74**, `kvm_mmu_get_child_sp()` reuses the child shadow page linked at a
SPTE if it is merely **present and not large** — it checks **neither the GFN nor the
role**. That is the *fully-unguarded* form: v6.1.74 is exposed to **both** disclosed
shadow-paging UAFs at once, because *both* fixes are later additions to this one `if`.

**Exact site — `arch/x86/kvm/mmu/mmu.c:2256-2257` @ v6.1.74:**

```c
static struct kvm_mmu_page *kvm_mmu_get_child_sp(struct kvm_vcpu *vcpu,
                         u64 *sptep, gfn_t gfn,
                         bool direct, unsigned int access)
{
    union kvm_mmu_page_role role;

    if (is_shadow_present_pte(*sptep) && !is_large_pte(*sptep))   // <-- no gfn, no role
        return ERR_PTR(-EEXIST);

    role = kvm_mmu_child_role(sptep, direct, access);
    return kvm_mmu_get_shadow_page(vcpu, gfn, role);
}
```

### How the two fixes layer on top of this exact line

1. **CVE-2026-46113** — `0cb2af2ea66a` (Sean Christopherson, 2026-04-15) adds the **GFN**
   guard:
   ```c
   if (is_shadow_present_pte(*sptep) && !is_large_pte(*sptep) &&
       spte_to_child_sp(*sptep) && spte_to_child_sp(*sptep)->gfn == gfn)
   ```
   Its pre-fix hunk is **byte-identical** to v6.1.74:2256 → v6.1.74 lacks this guard.
2. **CVE-2026-53359 "Januscape"** — `81ccda30b4e8` (Paolo Bonzini, 2026-06-12) adds the
   **role** guard on top:
   ```c
       spte_to_child_sp(*sptep)->gfn == gfn &&
       spte_to_child_sp(*sptep)->role.word == role.word)
   ```
   v6.1.74 lacks this too.

Both are `Fixes: 2032a93d66fa` ("Don't allocate gfns page for direct mmu pages",
2010-08-01) — the bug class is ~16 years old and was live on the kvmCTF host.

---

## Root cause (why the stale rmap entry survives the free)

The shadow MMU derives a direct page's GFN as `sp->gfn + index`
(`kvm_mmu_page_get_gfn`, **mmu.c:701**; direct branch returns `sp->gfn + index`, indirect
branch reads `sp->shadowed_translation[index]`, **mmu.c:707**). `rmap_remove`
(**mmu.c:1051**) computes the GFN the same way (**mmu.c:1060**) to find and unlink the
rmap entry when a shadow page is zapped.

The invariant that keeps this safe: *the shadow page linked at a SPTE must shadow the
GFN/role the walk expects.* v6.1.74's reuse check does not enforce it, so a guest that
mutates a PDE between VM-entries can make KVM:

- **46113 path:** install a leaf SPTE + rmap entry under a GFN **outside**
  `[sp->gfn, sp->gfn+511]`. On zap, `rmap_remove` scans only that range and misses it.
- **53359 path:** reuse a `direct=1` (huge-split) SP where a `direct=0` (indirect) SP is
  needed; the GFN can be made to match but the role differs, so `kvm_mmu_page_get_gfn`
  takes the `sp->gfn+index` branch instead of `shadowed_translation[]`, again computing
  the wrong GFN and missing the rmap entry on removal.

Either way: memslot deletion frees the `kvm_mmu_page`, the **rmap entry survives**, and
the next rmap walk (dirty logging, MMU-notifier invalidation e.g. `MADV_DONTNEED`)
dereferences an `sptep` inside the freed page → **use-after-free**.

(The accomplice primitive on the kvmCTF escape — emulated memory-dest `VMREAD` flipping a
nested EPT12 leaf RAM→MMIO so a later write-fault installs an MMIO SPTE over a present
SPTE — is the "modify the mapping from outside the guest" trigger; cf. also
`aad885e77496` "Drop/zap existing present SPTE even when creating an MMIO SPTE".)

---

## Supporting file:line confirmations on v6.1.74

| Element | Location (v6.1.74) | Note |
|---|---|---|
| Vulnerable reuse `if` | `mmu.c:2256` | `present && !large` only — no gfn, no role |
| `kvm_mmu_get_child_sp` | `mmu.c:2250` | caller: `FNAME(fetch)` via `paging_tmpl.h` |
| `kvm_mmu_page_get_gfn` | `mmu.c:701` | direct → `sp->gfn+index`; indirect → `shadowed_translation[]` (707) |
| `rmap_remove` | `mmu.c:1051` | uses `kvm_mmu_page_get_gfn` at `:1060` to locate the entry |
| `drop_large_spte` / `__link_shadow_page` | `mmu.c:1159` / `2326`, call at `2340` | pre-fix "present ⇒ must be large" assumption |
| role-match check present? | `mmu.c:2067` (find_shadow_page), `4386`, `5461` | these are the *new-page* lookup / root checks — **not** the child-reuse early-return, which stays unguarded |

Fixes confirmed **absent** from v6.1.74 (no `->role.word == role.word` nor
`->gfn == gfn` on the child-reuse early-return path).

---

## What this means for us

- **Not submittable to kvmCTF.** Both CVEs are public and patched upstream (Apr/Jun 2026);
  kvmCTF requires an unreported 0-day reproducible on mainline. This is a *post-mortem
  verification*, not a finding we can claim.
- **It validates the audit's instinct and fixes its blind spot.** Our V1 map aimed at the
  TDP-MMU (retry/RCU timing). The real bugs were in the **shadow/indirect MMU rmap
  bookkeeping** — a logic bug, not a race, reachable without winning a timing window. The
  shadow-rmap sub-vector is now the top re-audit target (see
  `RELATED-PUBLIC-DISCLOSURES-v6.1.74.md` §3).
- **Template for the next hunt.** The reusable invariant to grep for across sibling paths:
  *every shadow-page reuse keyed on an SPTE must match `gfn` AND `role.word`; every path
  that frees an SP must prove its rmap-removal GFN computation matches the GFN used at
  install.* Any place that violates either is the shape of the next bug.

## Reference artifacts (this repo)

- `refs/CVE-2026-46113_0cb2af2ea66a_gfn.patch` — the GFN fix (full commit + message)
- `refs/CVE-2026-53359_81ccda30b4e8_role.patch` — the Januscape role fix (full commit)
- `refs/vuln-site_kvm_mmu_get_child_sp_v6.1.74.c` — the unguarded function as shipped on v6.1.74

## Disclosure hygiene

Everything here is public and patched; no embargo, no exploit, no weaponization. A *new*
bug confirmed later must still follow `security-research/kvmctf/rules.md` (report to
`security@kernel.org`, coordinate with Google, 90-day cap).
