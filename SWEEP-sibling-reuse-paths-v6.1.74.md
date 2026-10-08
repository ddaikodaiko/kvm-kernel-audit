# Sweep — sibling shadow-page reuse / rmap-GFN paths on v6.1.74

**Status:** complete, read-only. **Date:** 2026-10-08.
Follow-up to `VERIFIED-shadow-rmap-UAF-on-v6.1.74.md`: does any *other* reuse site on
v6.1.74 share the same unguarded shape (reuse an SP keyed on an SPTE without matching
both `gfn` and `role.word`, or compute an rmap GFN that can diverge from install)?

## Result: the hole is confined to the shadow/indirect MMU child-reuse path. TDP MMU is structurally immune.

### Consumers of the vulnerable `kvm_mmu_get_child_sp` (both reached from `FNAME(fetch)`)
`arch/x86/kvm/mmu/paging_tmpl.h`:
- **:654** non-leaf walk, `direct=false` — the CVE-2026-53359 (role) scenario: reuse a
  `direct=1` split SP where `direct=0` is needed. No role check before the `-EEXIST`
  "reuse" short-circuit.
- **:709** leaf-ward walk, `direct=true` — the CVE-2026-46113 (gfn) scenario. Guarded
  *only* by `validate_direct_spte()` immediately before it.

### `validate_direct_spte` (mmu.c:2358) is a **partial** guard, not a fix
It reuses the linked child via `to_shadow_page(*sptep & SPTE_BASE_ADDR_MASK)` and only
re-checks **`child->role.access == direct_access`**. If `access` matches it returns and
lets the stale SP stand — it never compares `gfn` nor `role.word`. So the exact
CVE condition (gfn/role diverges while access coincides) slips straight through. This is
consistent with the root cause, not an additional bug.

### TDP MMU — not exposed (negative result, by design)
`tdp_mmu_init_child_sp` (tdp_mmu.c:215) builds every child fresh:
`role = parent_sp->role; role.level--;` then `tdp_mmu_init_sp(child_sp, iter->sptep,
iter->gfn, role)` (tdp_mmu.c:226) — the SP is keyed to the **iterator's own gfn and a
parent-derived role** at install, never reused from a pre-existing present SPTE on a
gfn-only match. Present→present transitions go through the atomic
`tdp_mmu_set_spte_atomic` + `handle_changed_spte` bookkeeping, and rmaps are not used by
the TDP MMU at all. The CVE class therefore cannot occur here.

## Takeaways
1. **No new unpatched sibling found on v6.1.74.** The two public CVEs + the
   `validate_direct_spte` access-only partial guard fully account for the exposed surface
   in the child-reuse path.
2. **The bug class is shadow-paging-only.** On the kvmCTF host the attacker *must* drive
   nested/shadow paging (as the public escape does via nested EPT + emulated VMREAD) —
   pure TDP-MMU (EPT-on-EPT with no shadowing) does not reach it. This sharpens the
   `lab/` fuzz scope: exercise the **shadow/indirect** MMU (nested guest, or
   `ept=0`/legacy paging) rather than the default TDP path.
3. **Reusable invariant for the next hunt (unchanged, now with negative coverage):**
   *any reuse of a shadow page keyed on an SPTE must match `gfn` AND `role.word`; any
   path that frees an SP must prove its rmap-removal GFN computation
   (`kvm_mmu_page_get_gfn`, mmu.c:701) matches the GFN used at install.* v6.1.74 violates
   this only at `kvm_mmu_get_child_sp` (mmu.c:2256); every other SP-reuse/zap site swept
   either re-keys correctly (TDP) or is a bookkeeping consumer, not a reuse decision.
