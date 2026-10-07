# White-box security audit plan — Linux KVM, guest→host isolation (target: LTS v6.1.74)

**Scope.** Defensive, static (passive) audit of the KVM subsystem for guest-to-host
escape classes, aligned with the kvmCTF target (`v6.1.74`, Intel VMX, `CONFIG_KASAN`
optional). This document is an **audit methodology + code-reading map**, not an exploit.
Every item below is phrased as "where to look / what invariant must hold / how to
verify it in the source." No weaponization, no PoC.

**Primary trees to index**

| Area | Path (in-tree) |
|---|---|
| Arch-independent core, memslots, ioctl | `virt/kvm/kvm_main.c`, `include/linux/kvm_host.h` |
| x86 top-level vcpu/run/msr | `arch/x86/kvm/x86.c` |
| Shadow + TDP MMU | `arch/x86/kvm/mmu/mmu.c`, `mmu/tdp_mmu.c`, `mmu/paging_tmpl.h`, `mmu/spte.c` |
| VMX entry/exit | `arch/x86/kvm/vmx/vmx.c`, `vmx/vmenter.S`, `vmx/nested.c` |
| Instruction emulator | `arch/x86/kvm/emulate.c`, `arch/x86/kvm/kvm_emulate.h` |

> **Version note worth pinning first.** `KVM_SET_USER_MEMORY_REGION2` and `guest_memfd`
> are **not** in 6.1.74 (they land ~v6.8). On this target the relevant ioctl is
> `KVM_SET_USER_MEMORY_REGION`. Any audit note referencing `REGION2` must be mapped
> back to the 6.1.74 equivalents (`__kvm_set_memory_region`). Verify the exact code
> against the pinned tag before trusting any upstream writeup.

---

## Vector 1 — Memory corruption & the MMU (EPT/NPT, `mmu_lock`, mmu_notifiers)

### What makes this class dangerous
The MMU turns a guest physical address (GPA) into a host physical address (HPA). Any
window where a SPTE (shadow/EPT PTE) still points at a page that the host has
reclaimed, remapped, or freed is a direct UAF of host memory with
attacker-influenced contents — the strongest possible primitive.

### The core invariant to audit
A page fault that installs a SPTE must prove the host mapping it observed is *still
valid at install time*. KVM enforces this with the **mmu_notifier sequence counter**:

- `kvm->mmu_invalidate_seq`, `mmu_invalidate_in_progress`, and the range
  `[mmu_invalidate_range_start, mmu_invalidate_range_end)`.
- Fault path reads the seq **before** `gfn_to_pfn`, then under `mmu_lock` calls
  `mmu_invalidate_retry_hva()` (a.k.a. `mmu_notifier_retry_hva`) and **must bail** if
  the counter moved or the hva fell inside an in-flight invalidation.

### Functions to read, in order
1. `kvm_mmu_do_page_fault()` → `kvm_tdp_page_fault()` / `direct_page_fault()`
   (`arch/x86/kvm/mmu/mmu.c`). Trace where `fault->mmu_seq` is sampled.
2. `kvm_faultin_pfn()` / `__gfn_to_pfn_memslot()` — the point the pfn is obtained.
3. The commit point: `__direct_map()` (shadow) and `kvm_tdp_mmu_map()`
   (`mmu/tdp_mmu.c`). Confirm the retry check happens **after** acquiring `mmu_lock`
   and **before** the SPTE write.
4. `FNAME(fetch)` and `FNAME(walk_addr_generic)` in `mmu/paging_tmpl.h` for the
   shadow-paging / nested-guest walk (classic TOCTOU surface — cf. CVE-2022-1158,
   where a guest PTE was re-read after validation).
5. mmu_notifier side: `kvm_mmu_notifier_invalidate_range_start/end`,
   `kvm_unmap_gfn_range()`, `kvm_handle_hva_range()`.

### TDP-MMU–specific (lockless walks)
`tdp_mmu.c` walks page tables under `rcu_read_lock()` with the rwlock held only for
*read*. Audit:
- Every `tdp_mmu_set_spte_atomic()` / `handle_changed_spte()` for the
  "present→present with different pfn" transition (must flush + free old via
  RCU, never synchronously).
- `kvm_tdp_mmu_zap_*` vs concurrent `kvm_tdp_mmu_map` — iterator validity across
  `tdp_mmu_iter_cond_resched()` yields.
- `tdp_mmu_free_sp()` paths — confirm freeing is RCU-deferred so a concurrent lockless
  reader cannot touch a freed `struct kvm_mmu_page`.

### Memslot lifetime (the other UAF surface)
Memslots are RCU/SRCU-protected (`kvm->srcu`, `__kvm_memslots()`). A fault in flight
holds an SRCU read lock; a `KVM_SET_USER_MEMORY_REGION` delete swaps the memslot set.
Audit `kvm_set_memory_region` → `__kvm_set_memory_region` → `kvm_swap_active_memslots`
and confirm no raw pointer into an old slot survives the SRCU grace period in any
fault/emulation path.

### Step-by-step audit procedure (V1)
1. `git grep -n mmu_invalidate_seq arch/x86/kvm virt/kvm` — enumerate every read site.
2. For each SPTE-install site, assert ordering: *sample seq → get pfn → take mmu_lock
   → retry-check → write SPTE.* Flag any site that writes before the retry-check.
3. `git grep -n 'read_lock(&kvm->mmu_lock)'` vs `write_lock` — list which mutations run
   under the read lock and confirm each uses an atomic SPTE primitive.
4. Map every `kvm_mmu_page` free to an RCU callback; flag any synchronous `kmem_cache_free`.
5. With `CONFIG_KASAN=y`, these are exactly the sites that would surface as
   use-after-free / slab-out-of-bounds under stress — note them as dynamic-test targets.

---

## Vector 2 — Input validation at the ioctl / memory-region boundary

### Attack surface
Userspace-facing `KVM_*` ioctls that size, place, or type guest memory. On 6.1.74 the
money path is `KVM_SET_USER_MEMORY_REGION`. The invariant: no combination of
`guest_phys_addr`, `memory_size`, `userspace_addr`, `flags` may (a) integer-overflow a
gfn/npages computation, (b) create an HPA mapping outside the intended userspace VMA,
or (c) alias two slots.

### Functions to read
1. `kvm_vm_ioctl()` dispatch → `kvm_vm_ioctl_set_memory_region()` (`virt/kvm/kvm_main.c`).
2. `__kvm_set_memory_region()` — the validation core:
   - `check_memory_region_flags()` (reject unknown flag bits — audit the allowed mask).
   - alignment: `memory_size`/`guest_phys_addr` page-aligned; `userspace_addr` checks.
   - **overflow math:** `base_gfn = gpa >> PAGE_SHIFT`, `npages = size >> PAGE_SHIFT`,
     and any `base_gfn + npages` / `gpa + size` that can wrap `u64`/`gfn_t`.
   - `kvm_check_memslot_overlap()` for aliasing.
3. `kvm_arch_prepare_memory_region()` (x86) — arch extra checks.
4. Control-register ingress (guest-controlled but host-trusted): `kvm_set_cr0`,
   `kvm_set_cr4` + `kvm_valid_cr4`, `kvm_set_cr3`, `vmx_set_cr0/4`. Audit reserved-bit
   masks and CPUID-dependent feature gating.
5. Hypercall ingress: `kvm_emulate_hypercall()` (`arch/x86/kvm/x86.c`) — argument
   width, `nr` range, and per-hypercall bounds.

### VERIFIED against the pinned v6.1.74 tree
`__kvm_set_memory_region` is at `virt/kvm/kvm_main.c:1938`; `check_memory_region_flags`
at `:1545`; `kvm_check_memslot_overlap` at `:1917`. Confirmed check chain, in order:

1. `check_memory_region_flags` — **reject-unknown** flags mask
   (`KVM_MEM_LOG_DIRTY_PAGES` + `KVM_MEM_READONLY`). Unknown bit ⇒ `-EINVAL`. ✔
2. `as_id = mem->slot >> 16; id = (u16)mem->slot;` — deliberate truncation, then
   bounded by `as_id >= KVM_ADDRESS_SPACE_NUM || id >= KVM_MEM_SLOTS_NUM`.
   Note: `KVM_ADDRESS_SPACE_NUM` = **2 on x86** (SMM), overriding the generic `1`;
   `KVM_MEM_SLOTS_NUM = SHRT_MAX` (32767).
3. Page-alignment of `memory_size` and `guest_phys_addr` (`& (PAGE_SIZE-1)`).
4. Width guard `memory_size != (unsigned long)memory_size` (no-op on 64-bit; the
   audit's gfn-safety therefore *assumes* a 64-bit host — true for kvmCTF).
5. `userspace_addr` alignment + `untagged_addr()` equality (LAM/tagged-ptr defense)
   + `access_ok(userspace_addr, memory_size)`.
6. **Byte-range wrap guard:** `guest_phys_addr + memory_size < guest_phys_addr` ⇒
   `-EINVAL`. (The primary overflow defense.)
7. **Explicit npages cap (new detail):** `(memory_size >> PAGE_SHIFT) >
   KVM_MEM_MAX_NR_PAGES` ⇒ `-EINVAL`, where `KVM_MEM_MAX_NR_PAGES = (1UL<<31)-1`.
   This bounds `npages < 2^31`, so `base_gfn + npages` provably cannot wrap `u64`.
8. Only now: `base_gfn = gpa >> PAGE_SHIFT; npages = size >> PAGE_SHIFT;`.
9. **Global accumulator wrap guard (new detail):** on `KVM_MR_CREATE`,
   `(kvm->nr_memslot_pages + npages) < kvm->nr_memslot_pages` ⇒ `-EINVAL`
   (`nr_memslot_pages` is `unsigned long`).
10. `kvm_check_memslot_overlap(slots, id, base_gfn, base_gfn + npages)` — here the
    sum IS formed explicitly as the range `end`; it is safe precisely because of
    guards (6)+(7).

**Conclusion:** the validator itself is sound on this tree. There is no missing
`base_gfn + npages` guard — safety is established upstream at the byte level + the
`KVM_MEM_MAX_NR_PAGES` cap. So the audit energy belongs in the **consumers** of
`base_gfn`/`npages` (below), not in this function.

### Patterns to flag
- Any width-narrowing (`u64`→`int`/`unsigned`) on a size or index before a bounds check.
- `access_ok`/`copy_from_user` on a length derived from guest input without a prior cap.
- Reserved-bit masks hardcoded instead of derived from guest CPUID (feature smuggling).
- A flags mask that silently ignores unknown bits instead of `-EINVAL`.

### Step-by-step audit procedure (V2)
1. `git grep -n 'case KVM_' virt/kvm/kvm_main.c arch/x86/kvm/x86.c` — enumerate ioctls
   reachable from the VM/vcpu fd; classify each by whether it takes a size/addr.
2. For each, trace the argument from `copy_from_user` to first arithmetic use; prove a
   bound exists *before* the first `>>`, `+`, or cast.
3. Grep the tree for `>> PAGE_SHIFT` near a user-supplied size and check for pre-shift
   overflow guards.
4. Diff the 6.1.74 validation against later stable fixes:
   `git log v6.1.74..linux-6.1.y -- virt/kvm/kvm_main.c arch/x86/kvm/` and read every
   commit touching `__kvm_set_memory_region`/`check_memory_region_flags` — backported
   fixes are a map of real historical holes.

---

## Vector 3 — VM-Exit: state save/restore, register hygiene, speculative leakage

### Why it matters for guest→host
Immediately after `VMLAUNCH`/`VMRESUME` returns, the CPU is running host code but the
GPRs still hold whatever the asm restored. If host secrets remain in registers/buffers
when control returns to the guest, or if a speculative window lets the guest sample
host state, that is an info leak (read primitive) — and sloppy state restore can be
worse.

### Functions / asm to read
1. `vcpu_enter_guest()` → `vcpu_run()` (`arch/x86/kvm/x86.c`) — the pre/post-exit
   bookkeeping.
2. `vmx_vcpu_run()` and `vmx_vcpu_enter_exit()` (`vmx/vmx.c`) — host/guest MSR swap,
   CR2, debug regs, the call into asm.
3. `__vmx_vcpu_run` in `vmx/vmenter.S` — **GPR clear on exit** (every guest GPR must be
   zeroed/restored before returning to C so host values don't leak and guest values
   don't poison host speculation). This is the exact spot of the historical
   "clear registers on VM-exit" hardening.
4. Speculative-execution mitigations around the transition:
   - `vmx_spec_ctrl_restore_host()` / guest `MSR_IA32_SPEC_CTRL` handling.
   - `vmx_l1d_flush()` (L1TF), `mds_clear_cpu_buffers()` / `VERW` (MDS/TAA),
     IBPB on vmexit, retpoline/eIBRS gating in `vmenter.S`.
5. Async events on the exit edge: `kvm_check_nested_events()`, interrupt/NMI injection
   in `vmx_vcpu_run` prologue, and `handle_exit()` → `vmx_handle_exit()` dispatch.

### Patterns to flag
- A GPR or segment/debug register read after exit before it is re-sanitized.
- A mitigation (`VERW`, L1D flush, IBPB) gated on a feature flag whose "off" path leaves
  a buffer unscrubbed on a vulnerable microarchitecture.
- CR2/debug-reg restore ordering that lets a #DB or #PF observe transient host state.
- `xsave`/`xrstor` of FPU/AVX state where the guest state mask differs from what's
  restored for host.

### Step-by-step audit procedure (V3)
1. Read `vmenter.S` end-to-end; list every register written on the exit path and prove
   each is either host-restored or zeroed before `ret`.
2. For each speculative mitigation, find its `static_branch`/`cpu_feature` gate and
   enumerate the microarchitectures where the "disabled" path is reachable on the
   kvmCTF host CPU (Xeon Gold 5222, Cascade Lake).
3. Cross-check `vcpu_enter_guest()`'s ordering of `kvm_x86_ops` hooks against the
   comment contract (IRQs off window, preemption).
4. These are primarily **info-leak** (arbitrary/relative *read*) candidates — tag them
   accordingly for the tier model.

---

## Vector 4 — Instruction emulator (SGDT/SIDT/LGDT/LIDT, MSR r/w)

### Attack surface
KVM's software emulator (`emulate.c`) runs when hardware can't. Its opcode/state
machine is historically bug-dense: wrong operand width, writeback to the wrong
destination, descriptor-table handling, and privilege checks that don't match the CPU.

### Functions to read
1. `x86_emulate_insn()` and the opcode tables (`opcode`, `group`, `twobyte` arrays) in
   `emulate.c` — find the handlers for the system-descriptor insns.
2. Descriptor-table group: `em_sgdt`/`em_sidt` (store), `em_lgdt`/`em_lidt` (load, via
   `em_lgdt_lidt`), and `get_descriptor_table_ptr()` / `emulate_store_desc_ptr()`.
   Audit operand size (2+4 vs 2+8 bytes), CPL checks, and the memory writeback target.
3. Writeback engine: `writeback()` and `segmented_write()` — confirm the destination
   length/segment comes from decode, never from stale `ctxt` state.
4. MSR path: `em_rdmsr`/`em_wrmsr` → `kvm_set_msr`/`kvm_get_msr` →
   `__kvm_set_msr`/`kvm_set_msr_common`, `vmx_set_msr`/`vmx_get_msr`, and the filter
   `kvm_msr_allowed()` / `kvm_msr_user_space()`. Audit which MSRs are host-trusted and
   whether reserved bits are masked per CPUID.
5. `kvm_emulate_instruction()` entry and the `EMULTYPE_*` flags — when emulation is
   invoked and whether failure modes default to safe (`#UD`/exit) vs. silent.

### Patterns to flag
- An emulated insn whose CPL/mode check differs from the SDM (e.g. LGDT allowed outside
  CPL0).
- Operand-size selection that picks a wider write than the destination buffer.
- A `ctxt->dst`/`ctxt->src` reused across decode stages without reset.
- An MSR write that reaches hardware (`wrmsrl`) with guest-controlled value and
  insufficient reserved-bit/value validation.
- Emulator state (`ctxt->eip`, `_eip`, `ctxt->ops` callbacks) advanced on an error path.

### Step-by-step audit procedure (V4)
1. From the opcode tables, build the list of insns with a dedicated `em_*` handler;
   prioritize system/privileged ones.
2. For each descriptor-table handler, lay the operand-size and CPL logic next to the
   Intel SDM pseudocode and flag divergences.
3. For MSR writes, enumerate every MSR reaching real `wrmsr` and confirm a value/reserved
   validation + CPUID gate precedes it.
4. `git log v6.1.74..linux-6.1.y -- arch/x86/kvm/emulate.c` — every backported emulator
   fix is a labeled historical bug; map each to its root cause.

---

## Cross-cutting audit mechanics

- **Pin the exact tree.** Audit against the kvmCTF patch on top of `v6.1.74`, not
  mainline — behavior differs. (The patch ships in the kvmCTF bundle; see env setup.)
- **"Fixed-commit" method.** For every vector, the fastest signal is diffing
  `v6.1.74..linux-6.1.y` (and mainline) for the files above. A stream of stable
  backports *is* the list of real bugs found after this tag — read them as a checklist.
- **KASAN posture.** The relative-read/relative-write/DoS tiers map to KASAN violation
  classes. The static findings in V1 (UAF/OOB around SPTE + memslot lifetime) are the
  natural dynamic-test targets if a KASAN host is used.
- **Tier mapping of findings.** V1 → arbitrary/relative write (strongest). V2 →
  arbitrary write / unauthorized HPA mapping. V3 → arbitrary/relative read (info leak).
  V4 → RIP/state corruption → escalation or DoS.
- **Boundaries.** This plan stops at "find and understand the bug and its invariant."
  Any reproduction should target the authorized kvmCTF instance only, and reporting
  follows the two-stage process in `kvmctf/rules.md`.

## Suggested reading order (first pass)
1. `__kvm_set_memory_region` + `check_memory_region_flags` (V2 — smallest, highest ROI).
2. `kvm_mmu_do_page_fault` → `kvm_tdp_mmu_map` + the `mmu_invalidate_seq` retry (V1).
3. `vmenter.S` exit path + spec-ctrl restore (V3).
4. `emulate.c` descriptor-table + MSR handlers (V4).

---

## FINDINGS LOG

### V2 — CLOSED (no bug on v6.1.74). Date: 2026-10-07.
- **Validator** (`__kvm_set_memory_region`) is sound: reject-unknown flags, byte-wrap
  guard, explicit `npages` cap (`KVM_MEM_MAX_NR_PAGES = (1UL<<31)-1`), and global
  accumulator wrap guard. No missing `base_gfn+npages` check.
- **Cast scan** of `arch/x86/kvm/mmu/` + `virt/kvm/`: no narrowing of `gfn`/`npages`.
- **Translation helpers:** `__gfn_to_hva_memslot` (`kvm_host.h:1698`) clamps the offset
  with `array_index_nospec(offset, npages)` → out-of-range gfn collapses to 0, no wrap.
  Its sibling `__gfn_to_hva_many` (`kvm_main.c:2428`) computes `nr_pages` *unclamped*,
  but is defended by its caller's gate (below).
- **Caller-provenance sweep (the key invariant):** every consumer of
  `__gfn_to_hva_many` / `gfn_to_page_many_atomic` / `mark_page_dirty_in_slot`
  **co-derives `slot` and `gfn` from the same source**, or looks up the slot for that
  exact gfn immediately before use. The prefetch loop `direct_pte_prefetch_many`
  (`mmu.c:2876`) increments `gfn` against a once-fetched `slot`, but is bounded by
  `gfn_to_page_many_atomic`'s gate `if (entry < nr_pages) return 0;`
  (`kvm_main.c:2795`), so `gfn` provably stays in-slot.
- **INVARIANT (document & re-check on any future diff):** *In the memslot access
  paths, the slot passed to a consumer always contains the gfn passed alongside it; the
  only count-returning path (`gfn_to_page_many_atomic`) gates on `entry < nr_pages`
  before iterating.* A future change that fetches a slot once and then advances gfn past
  it without re-gating would break this and is the thing to watch for.

### V4 (emulate.c subset) — CLEAN. Date: 2026-10-07.
- **LGDT/LIDT (`em_lgdt_lidt`, emulate.c:3852):** operand-size per SDM — PROT64 sets
  `op_bytes=8` (10-byte operand) + non-canonical base `#GP`; legacy 2+4 / 24-bit mask
  in the store path. CPL enforced via the `Priv` table flag
  (`II(SrcMem | Priv, em_lgdt, lgdt)`, emulate.c:4460-4461) → generic check at
  emulate.c:5549. SGDT/SIDT (reg 0/1) correctly NOT `Priv`, UMIP-gated inline in
  `emulate_store_desc_ptr` (emulate.c:3824). No divergence.
- **em_wrmsr (emulate.c:3684):** thin shim — delegates to `set_msr_with_filter`; no
  inline reserved-bit/CPUID check (by design). CPL0 via `Priv`
  (`II(ImplicitOps | Priv, em_wrmsr, wrmsr)`, emulate.c:4772). *The real MSR
  reserved-bit/CPUID validation lives in `kvm_set_msr_common`/`vmx_set_msr`
  (x86.c / vmx/vmx.c), shared with the non-emulated WRMSR exit — that is the actual
  V4b target, NOT emulate.c.*
- **_eip / writeback on fault:** correct. Success commit `ctxt->eip = ctxt->_eip`
  (emulate.c:5762) sits BEFORE `done:` (5766); a faulting handler hits
  `if (rc != X86EMUL_CONTINUE) goto done;` (5704) and skips it. `writeback_registers`
  runs only `if (rc == X86EMUL_CONTINUE)` (5775). No RIP/GPR commit on fault.
- **Next MSR lead:** audit `kvm_set_msr_common` (x86.c) + `vmx_set_msr` (vmx/vmx.c) for
  which guest-writable MSRs reach a real `wrmsr` and whether reserved bits are masked
  per guest CPUID.

### V4b (MSR set path) — CLEAN. Date: 2026-10-07.
- **Guest-value → real `wrmsr` sites** are all defanged:
  - `PRED_CMD` (vmx.c:2225): CPUID + host-IBPB gated, `data & ~PRED_CMD_IBPB` rejected,
    and the `wrmsrl` writes the **constant** `PRED_CMD_IBPB`, not guest data.
  - `SPEC_CTRL` (vmx.c:2190): CPUID-gated (`guest_has_spec_ctrl_msr`), value validated
    by `kvm_spec_ctrl_test_value` (x86.c:13429 — a **hardware probe**, IRQ-off
    save/`wrmsrl_safe`/restore), stored in `vmx->spec_ctrl`; host value is restored on
    every VM-exit (`vmx_spec_ctrl_restore_host`, vmx.c:7100). Passthrough is safe.
  - `TSX_CTRL` (vmx.c:2218): capability-gated, fixed 2-bit mask
    (`TSX_CTRL_RTM_DISABLE|TSX_CTRL_CPUID_CLEAR` = the complete arch field); uret MSR,
    host value restored.
  - `KERNEL_GS_BASE` (vmx.c:1339): guest's own context reg, restored on exit.
  - LBR passthrough `wrmsrl(index, data)` (pmu_intel.c:326): `index` bounded by
    `intel_pmu_is_valid_lbr_msr` to SELECT/TOS/from/to/info ranges; guest-scoped LBR
    record MSRs only, IRQ-off, LBR-event-active only.
- **Reserved-bit validation is dynamic / CPUID-driven**, not hardcoded: `kvm_set_msr_common`
  gates on `guest_cpuid_has(...)` / `guest_pv_has(...)` and masks against per-vcpu
  capabilities (`kvm_guest_supported_xfd(vcpu)`, `kvm_caps.supported_xss`, `msr_ent.data`).
  Fixed masks appear only where the field is architecturally complete. **No feature
  smuggling found.**
- **Guest cannot force unsafe host speculation state:** host SPEC_CTRL/TSX restored on
  exit; PRED_CMD write is a constant barrier. No path lets the guest leave the host
  running with guest mitigation settings.

### AUDIT STATUS (static, v6.1.74): V2 CLEAN · V3 CLEAN (one post-tag VERW-placement delta) · V4 CLEAN · V4b CLEAN.
Pure static review of the logic/arithmetic/validation paths has not produced a
guest→host bug. Remaining classes (V1 MMU concurrency / V3 VM-exit races) are timing
bugs that static reading can only hypothesize — confirming requires the KASAN host +
dynamic stress/syzkaller on the kvmCTF lab instance.

### V1 — RACE-WINDOW MAP (static hypotheses, UNCONFIRMED). Date: 2026-10-07.
These are *where to aim the fuzzer*, not confirmed bugs. On v6.1.74 the protocols below
are intact; each entry states the window and exactly what would have to break.

#### H1 — the faultin→install retry window (`direct_page_fault`, mmu.c:4242)
Timeline (TDP fault):
- `mmu.c:4264` `mmu_seq = vcpu->kvm->mmu_invalidate_seq;` then `smp_rmb()` (4265) —
  sampled OUTSIDE the lock.
- `mmu.c:4268` `kvm_faultin_pfn()` — pfn obtained OUTSIDE the lock (window opens here).
- `mmu.c:4278-4281` `read_lock(&kvm->mmu_lock)` (TDP) / `write_lock` (shadow).
- `mmu.c:4282` `is_page_fault_stale()` → `mmu.c:4240` `mmu_invalidate_retry_hva()`
  (kvm_host.h:1917): returns 1 if `mmu_invalidate_in_progress && hva ∈
  [range_start,range_end)`, or if `mmu_invalidate_seq != mmu_seq`.
- `mmu.c:4286` `kvm_tdp_mmu_map()` — SPTE installed only if NOT stale.

Closure: the notifier increments `mmu_invalidate_in_progress` and sets the range in
`kvm_mmu_invalidate_begin` (kvm_main.c:736/744), invoked as the `on_lock` callback
(kvm_main.c:774) **while holding mmu_lock**; `mmu_invalidate_seq++` in invalidate_end
(kvm_main.c:820). Counters written under mmu_lock and read under mmu_lock (retry_hva
asserts `lockdep_assert_held`), so the lock serializes the racers: notifier-wins-lock ⇒
fault retries; fault-wins-lock ⇒ SPTE installed, notifier then zaps it. No stale SPTE
survives. **What would have to break:** an install path that skips
`is_page_fault_stale`, installs before the gate, a notifier update to
seq/range/in_progress outside mmu_lock, or a missing `smp_rmb` at 4265.

#### H2 — lockless iterators / atomic SPTE change (tdp_mmu.c)
- Atomic transition: `tdp_mmu_set_spte_atomic` (tdp_mmu.c:567) — `rcu_dereference` of
  sptep (570), `try_cmpxchg64` (588); a lost race returns `-EBUSY`, `old_spte` refreshed
  ⇒ caller retries. Bookkeeping in `__handle_changed_spte` (590).
- Deferred free: `handle_removed_pt` (tdp_mmu.c:353) ends in
  `call_rcu(&sp->rcu_head, tdp_mmu_free_sp_rcu_callback)` (tdp_mmu.c:433). Old page table
  freed only after an RCU grace period (callback tdp_mmu.c:79). A concurrent lockless
  reader under `rcu_read_lock` cannot touch freed memory.
- Synchronous-free exception: `tdp_mmu_free_sp(sp)` at tdp_mmu.c:1177 — reachable ONLY
  for an SP just allocated in `kvm_tdp_mmu_map` whose link cmpxchg lost; never visible to
  another thread, so synchronous free is safe there.
- Resched yield: `tdp_mmu_iter_cond_resched` (tdp_mmu.c:737) does `rcu_read_unlock()`
  (751) → `cond_resched_rwlock_*` → `rcu_read_lock()` (758) → `iter->yielded = true`
  (760). Guard: `tdp_mmu_set_spte_atomic` WARNs on `iter->yielded` (581), so a stale
  iterator cannot install an SPTE — the walker must re-step (fresh `rcu_dereference`).
  **What would have to break:** a raw sptep cached across a resched without the yielded
  re-walk; a synchronous free reachable by a concurrent reader; or a cmpxchg-success path
  skipping `__handle_changed_spte`.

**Net:** H1 and H2 are the two highest-value fuzz targets, but both protocols are sound
on this tree by inspection. A confirmable finding needs the KASAN host + stress.

### V3 — VM-exit register hygiene & speculative leakage (`vmenter.S`) — CLEAN on this tree; one post-tag hardening identified. Date: 2026-10-07.
Static read of `arch/x86/kvm/vmx/vmenter.S` (`__vmx_vcpu_run`; exit edge at `vmx_vmexit`).

**V3a — GPR clear-on-exit: COMPLETE.**
- Guest GPRs are spilled to the guest `regs` struct at `vmx_vmexit` (vmenter.S:163-186:
  RAX via stack `pop`:170, then RCX/RDX/RBX/RBP/RSI/RDI:171-176, R8-R15:178-185), then every
  GPR except RSP and RBX is zeroed at `.Lclear_regs` (vmenter.S:205-220).
- RBX exempt: holds the 0/1 return value (`xor %ebx,%ebx`:189 for VM-Exit; `mov $1`:264 for
  VM-Fail). RSP exempt: hardware-restored on VM-Exit. Matches the in-code rationale (:195-204).
- Clears use the 32-bit `xor %eNNd` form → zero-extends to wipe the full 64-bit register.
  Correct and idiomatic.
- **Threat-direction note (corrects a common misreading):** at `vmx_vmexit` the GPRs hold
  *guest* values, not host secrets. Host callee-saved regs (RBP/RBX/R12-R15) were stack-saved
  at entry (:47-58) and reloaded only at :245-255; host volatile regs held no secret across
  vmentry. So the clear defends against *guest→host speculative poisoning* (a guest value
  speculatively consumed by host code — incl. the "L1 cache miss while reloading" case the
  comment cites), NOT host-data leakage to the guest. No window exists where a GPR carries
  host data into the guest through this path.

**V3b — Spec-ctrl / RSB on the exit edge: PRESENT and correctly ordered.**
- RSB fill: `FILL_RETURN_BUFFER %_ASM_CX, RSB_CLEAR_LOOPS, X86_FEATURE_RSB_VMEXIT,
  X86_FEATURE_RSB_VMEXIT_LITE` (vmenter.S:234-235), before the first unbalanced RET (ordering
  contract at :222-232; eIBRS needs only a single retiring call).
- Host SPEC_CTRL restore: `call vmx_spec_ctrl_restore_host` (vmenter.S:240), after the RSB
  fill and before host-register restore + RET → guest IBRS/STIBP/SSBD cannot persist into host
  execution (matches the V4b finding on `vmx_spec_ctrl_restore_host`).
- Entry-side SPEC_CTRL write gated by `ALTERNATIVE ... X86_FEATURE_MSR_SPEC_CTRL` (:78) with
  the "no RET/indirect branch between here and vmentry" contract (:84-86) + serialization note
  (:100-103).

**V3c — What is NOT in `vmenter.S` on v6.1.74 (the key structural finding).**
- **VERW (MDS/TAA/MMIO buffer clear): absent from the asm.** On this tree the CPU-buffer clear
  is done in C in the caller (`vmx.c`, `mds_clear_cpu_buffers()` behind the `mds_user_clear`
  static branch) *before* the `__vmx_vcpu_run` call.
- **L1D flush (L1TF): absent from the asm** — `vmx_l1d_flush()` in `vmx.c` (`vmx_vcpu_run`),
  gated on `X86_FEATURE_FLUSH_L1D` / the l1tf mode.
- **IBPB: absent from the asm** — handled in the C entry path per the IBPB-on-switch policy.
- So "how does the asm run VERW/IBPB?" on 6.1.74 → *it does not*; only RSB-fill + SPEC_CTRL
  are in-asm, and buffer-clearing is a C-side, entry-edge mitigation.

**V3d — Post-tag hardening in `v6.1.74..linux-6.1.y` (fixed-commit method).**
- **`KVM/VMX: Move VERW closer to VMentry for MDS mitigation`** — upstream `43fb862de8f6`
  (Pawan Gupta), part of the "Delay VERW" series; backported to 6.1.y around **6.1.81**
  (early March 2024) alongside the **RFDS / CVE-2023-28746** mitigation (`RFDS_NO`/`RFDS_CLEAR`
  export). Adds `CLEAR_CPU_BUFFERS` **into `vmenter.S`** on the entry side (just before
  `vmresume`/`vmlaunch`) and removes the C-level `mds_clear_cpu_buffers()`.
  - **Root cause it closes:** with VERW in C before the asm, the register pushes / stack
    accesses between VERW and the actual vmentry re-populate the MDS-affected buffers with
    *host* data, which the guest can then sample via MDS. Moving VERW adjacent to vmentry
    shrinks that window to ~nothing.
  - **Relevance:** a genuine buffer-hygiene fix to the file under audit, made *after* v6.1.74.
    Stock-6.1.74 `vmenter.S` therefore has the wider pre-fix MDS window on MDS-affected parts.
    kvmCTF host = Cascade Lake (Xeon Gold 5222): **bundle-parity check** — if the kvmCTF patch
    was cut before ~6.1.81 the pre-fix window is present; after, it is closed. Info-leak
    (relative-read) class, not a logic bug.
  - **Cascade Lake qualifier (Xeon Gold 5222) — narrows the impact:** this part enumerates
    `MDS_NO` (in-silicon MDS fix), so the pre-6.1.81 VERW-placement window is **not** a live
    pure-MDS leak on the kvmCTF host. The VERW placement stays relevant here only for
    **TAA** (TSX Async Abort — only if TSX is enabled; otherwise TSX-off is the mitigation)
    and **RFDS** (only if the stepping enumerates RFDS-affected; RFDS is primarily an
    Atom-core issue, so likely N/A on this Xeon — confirm by enumeration). Net:
    defense-in-depth / info-leak (relative-read) tier, **not** a confirmed guest→host MDS
    leak on this silicon.
  - **ACTION (bundle parity):** confirm whether the applied kvmCTF patch includes
    `43fb862de8f6` (≥ ~6.1.81); record TSX-enabled state + RFDS enumeration for the
    Xeon Gold 5222 to decide whether the VERW-placement window is reachable at all.

**Net:** register hygiene (V3a) and the in-asm spec-ctrl/RSB edge (V3b) are sound on v6.1.74.
The one substantive delta vs. later 6.1.y is the VERW-placement hardening (V3d) — verify
bundle parity. No guest→host logic bug in `vmenter.S`.

---

# EXECUTIVE SUMMARY

**Engagement.** White-box, static (read-only) security audit of the Linux KVM subsystem
for guest→host isolation, pinned to the kvmCTF target **LTS v6.1.74** (Intel VMX). Source
obtained from `git.kernel.org` stable (tag verified: VERSION 6 / PATCHLEVEL 1 /
SUBLEVEL 74). No code was executed; findings are from reading the pinned tree.

**Bottom line.** No guest→host vulnerability was found by static review. Five areas were
audited to line-referenced depth; four are affirmatively clean, and the concurrency area
is mapped as two sound-but-fuzzable race windows. This is the expected result for a
heavily-fuzzed LTS tree and should be read as *coverage with evidence*, not absence of
effort.

| Vector | Area | Result | Key evidence |
|---|---|---|---|
| **V2** | memslot ioctl / arithmetic | **CLEAN** | `__kvm_set_memory_region` byte-wrap guard + `KVM_MEM_MAX_NR_PAGES` cap; all `gfn`/`npages` consumers co-derive (slot, gfn); prefetch bounded by `entry < nr_pages` gate (kvm_main.c:2795) |
| **V4** | instruction emulator | **CLEAN** | LGDT/LIDT operand-size + `Priv` CPL enforcement match SDM; `em_wrmsr` is a correct thin shim; RIP/GPR not committed on fault (emulate.c:5704/5762/5775) |
| **V4b** | MSR set path | **CLEAN** | guest→`wrmsr` sites defanged (constant IBPB / host-restore / bounded LBR index); reserved bits validated via guest CPUID + hardware probe, not hardcoded; no feature smuggling |
| **V1** | MMU concurrency (TDP) | **MAPPED (unconfirmed)** | H1 faultin→install retry serialized by `mmu_lock` (mmu.c:4264→4282); H2 atomic cmpxchg + RCU-deferred free + yielded-iterator guard (tdp_mmu.c:567/433/581) — both intact; see race-window map |
| **V3** | VM-exit / register hygiene / speculation (`vmenter.S`) | **CLEAN** (1 post-tag delta) | GPR clear-on-exit complete (vmenter.S:205-220, RSP/RBX exempt, defends guest→host poisoning); RSB fill + `vmx_spec_ctrl_restore_host` in-asm (:234-240); VERW/L1D/IBPB live in the C caller, not the asm. Post-6.1.74: VERW moved into `vmenter.S` (`43fb862de8f6`, ~6.1.81, RFDS/CVE-2023-28746) — verify bundle parity |

**What this deliverable is good for.** A defensive artifact: it documents, with exact
file:line references on v6.1.74, the invariants that keep each surface safe, so a future
maintainer or reviewer can re-check them against any backport or change. The V2 invariant
("every consumer co-derives slot and gfn; the one count path gates on `entry < nr_pages`")
and the H1/H2 "what would have to break" notes are the most reusable outputs.

**Limits & honest caveats.**
- Static review cannot confirm or refute timing bugs (V1/V3). H1/H2 are *hypotheses with
  coordinates*, not findings.
- Audit is against stock v6.1.74. The kvmCTF host runs a **patched** v6.1.74; exact parity
  requires applying the bundle patch (`storage.googleapis.com/kvmctf/latest.tar.gz`).
- V3 now has a dedicated static pass: register hygiene + in-asm spec-ctrl/RSB edge are CLEAN;
  VERW/L1D/IBPB live in the C caller on this tree. The one open item is bundle parity for the
  post-6.1.74 VERW-placement hardening (`43fb862de8f6`, ~6.1.81) — confirm against the applied
  kvmCTF patch. Full speculative-path confirmation on MDS-affected silicon still needs the lab.

**Recommended next step.** Stand up the dynamic lab (`lab/` — KASAN+KCOV kernel build
script and a syzkaller config scoped to the H1/H2 memslot/mmu-notifier surface) on a Linux
host with `/dev/kvm`, apply the kvmCTF patch, and fuzz. That is the only path to a
confirmable finding. Any confirmed bug must follow the two-stage disclosure in
`security-research/kvmctf/rules.md` (report to security@kernel.org, etc.).


