# Related public disclosures — KVM guest→host on LTS v6.1.74

**Purpose.** This note cross-references our static audit (`AUDIT_KVM_v6.1.74.md`)
against public, disclosed KVM guest→host vulnerabilities that land on the *same*
kvmCTF target (stock/patched LTS **v6.1.74**, Intel VMX). It is a defensive
corroboration + coverage-gap record, not an exploit. Every external claim is
sourced; where sources conflict the conflict is stated rather than resolved.

**Compiled:** 2026-10-08. **Audit cross-referenced:** `AUDIT_KVM_v6.1.74.md`
(static pass dated 2026-10-07).

---

## TL;DR

Two public guest→host disclosures hit v6.1.74, and **both live in the shadow MMU /
reverse-map (rmap) path** — not in the TDP-MMU concurrency windows (V1/H1/H2) or the
arithmetic/validation surfaces (V2/V4/V4b) that our static pass drove to depth. They
are a **17-year-old bug class** (present since 2010), fixed only in June 2026.

| CVE | Name | Fix commit | Class | Our audit's nearest vector |
|---|---|---|---|---|
| **CVE-2026-53359** | Januscape | `81ccda30b4e8` | Shadow-page reuse ignoring `role` → rmap accounting UAF | V1 (shadow UAF) — *not caught* |
| **CVE-2026-46113** | (kvmCTF escape) | `0cb2af2ea66a` | GFN-tracking gap: MMIO SPTE over present SPTE leaves stale rmap | V1 (shadow UAF) — *not caught* |

The honest conclusion: our static review concluded V1 was "sound but fuzzable" with the
lens aimed at the **TDP MMU** (`mmu_invalidate_seq` retry, lockless iterators, RCU-free).
The real-world bugs on this tree were in the **shadow/indirect MMU rmap bookkeeping**, a
surface our V1 map named (paging_tmpl.h, rmap lifetime) but did not drive to a finding.
This document records that gap so the audit's coverage claim stays honest.

---

## 1. CVE-2026-53359 — "Januscape"

**Disclosure.** Reported by Hyunwoo Kim (@v4bel) to `security@kernel.org` on
2026-06-12; mainline/stable fix early July; public write-up 2026-07-06. Used as a
0-day in Google kvmCTF. Public PoC panics the host (DoS) rather than demonstrating the
full escape; author states a working escape exists but is unreleased.

**Root cause (per the researcher's write-up).** `kvm_mmu_get_child_sp()` — the function
that follows a guest page table and obtains the lower-level child shadow page — decided
to **reuse** an existing child shadow page linked at the SPTE by comparing **only its
`gfn`**, ignoring the page's `role`. The `role` encodes whether the page shadows a guest
page table (indirect) or was **split** from a large page into 4 KiB pages (direct).
Confusing a direct-split page with an indirect page for the same gfn **breaks rmap
accounting**, which is what ultimately yields a use-after-free.

**Fix.** Commit `81ccda30b4e8` adds a `role.word` comparison to the reuse condition, so
the linked child page is reused only when **both `gfn` and `role` match**.

**Affected range.** Introduced `2032a93d66fa` (2010-08-01); fixed `81ccda30b4e8`
(June 2026). ~16 years latent. (Sources give both "merged June 16" and "June 19"; left
unresolved.)

**Companion.** Multiple sources state `81ccda30b4e8` alone is insufficient; the
GFN-tracking fix `0cb2af2ea66a` (CVE-2026-46113, below) must also be present. Verify both
commit IDs in the distro package changelog rather than trusting the `uname -r` version
string — backports carry them under renamed versions.

---

## 2. CVE-2026-46113 — the kvmCTF 6.1.74 escape (shadow-paging UAF)

**Disclosure.** Documented publicly in a kvmCTF write-up (pwn.ai) of an escape against a
bare-metal Google kvmCTF host running Linux **6.1.74 + KASAN**. The attacker runs a
Debian L1 guest hosting a **nested L2** guest; the primitive is driven through the
**nested shadow EPT (EPT02)**. Google attributed the submission to a shadow-paging UAF
fixed by `0cb2af2ea66a`.

**Root cause (per the linked patch + authors' analysis).** When a guest page table
changes between VM entries, KVM can reuse a **direct shadow page whose recorded GFN no
longer matches**. The new SPTE's **rmap entry is stored outside the range KVM later
searches when zapping** that shadow page, so the entry **survives after the shadow page
is freed** — a later rmap walk dereferences the stale pointer. The authors point at
`mmu_set_spte()`: it handles an MMIO / noslot PFN **before** the present SPTE, so the old
rmap entry is never removed.

**Exploitation primitive (as described).**
1. A memory-destination **VMREAD** emulated by KVM writes into the EPT12 leaf without
   triggering page-tracking cleanup — flipping a mapping from read-only RAM to MMIO.
2. A later write-fault installs an **MMIO SPTE over the existing present SPTE**, leaving
   the rmap entry behind.
3. **Root rotation + INVEPT** retire the shadow page, which is freed while the stale rmap
   pointer survives.
4. Allocation pressure + `VMFUNC` + touching aliases push the rmap past
   `RMAP_RECYCLE_THRESHOLD` (1000); KVM walks the stale pointer → **out-of-bounds read**
   that KASAN flags.
5. kvmCTF's patched KASAN report path sets the oracle flag; **hypercall #102** then
   returns the per-boot relative-read flag.

**Key identifiers.** `mmu_set_spte()`, `mark_mmio_spte()`, `mmu_spte_clear_track_bits()`,
`kvm_zap_all_rmap_sptes()`, `pte_list_add()`, `RMAP_RECYCLE_THRESHOLD`, `handle_vmread()`,
`kvm_write_guest_virt_system()`, fix commit `0cb2af2ea66a`.

**Caveat (from the source itself).** The authors' account is self-reported; they lacked a
host-side stack trace, so the CVE attribution rests on Google's label. They also report
the bounty was denied because a public patch appeared shortly before their service window.

---

## 3. Cross-reference to our static audit

| Our vector | Our verdict (2026-10-07) | Relation to the public bugs |
|---|---|---|
| **V1 — MMU concurrency (TDP)** | MAPPED, unconfirmed (H1 retry, H2 lockless/RCU) | **Different surface.** H1/H2 are TDP-MMU timing windows; both CVEs are **shadow/indirect MMU rmap-bookkeeping logic bugs**, triggerable without a race. Our V1 *named* rmap + `paging_tmpl.h` + shadow `__direct_map` as surfaces but did not pursue the role/gfn-tracking logic. |
| **V2 — memslot ioctl / arithmetic** | CLEAN | Unrelated. The bugs are not arithmetic/validation at the ioctl boundary. |
| **V3 — VM-exit / spec** | CLEAN (1 post-tag VERW delta) | Unrelated. |
| **V4 / V4b — emulator / MSR** | CLEAN | **Adjacent but not the bug.** CVE-2026-46113 is *triggered via* emulated `VMREAD` (`handle_vmread`) and the MMIO-SPTE install path, but the defect is in `mmu_set_spte()` rmap handling, not in emulator operand/CPL logic (what V4 checked). |

### Concrete coverage gap to add to the audit

Our V1 map should be extended with a **shadow-MMU rmap-lifetime sub-vector**, auditing:

1. **`kvm_mmu_get_child_sp()` / `kvm_mmu_find_shadow_page()`** — the child-page reuse
   decision. Invariant: a linked child SP is reused only when **both `gfn` and
   `role.word` match** (the Januscape fix). Flag any reuse keyed on gfn alone.
2. **`mmu_set_spte()` ordering** — whether an MMIO/noslot PFN is handled **before** an
   existing present SPTE's rmap entry is cleared (`mmu_spte_clear_track_bits` /
   `drop_spte`). The invariant: **no present→MMIO transition may leave an rmap entry that
   the later zap range won't cover** (the CVE-2026-46113 root cause).
3. **rmap zap coverage** — every path that frees a shadow page
   (`kvm_mmu_free_shadow_page` / `__kvm_mmu_prepare_zap_page`) must prove its
   `kvm_zap_all_rmap_sptes` / `pte_list_remove` covers **every** rmap entry the SP ever
   installed, including entries moved by a gfn change.
4. **Dynamic confirmation** — these are the exact sites that surface under KASAN on the
   nested-guest path; add `handle_vmread` + nested-EPT root-rotation/INVEPT churn to the
   `lab/` syzkaller scope, not just the H1/H2 memslot/notifier surface.

**Target-parity note.** Both fixes post-date stock v6.1.74. The kvmCTF host ran the bug
**live** (that is why these were valid 0-days there). Any re-run of our audit against the
applied kvmCTF bundle patch (`storage.googleapis.com/kvmctf/latest.tar.gz`) must check
whether `81ccda30b4e8` and `0cb2af2ea66a` are backported into that bundle before treating
the shadow-rmap surface as closed.

---

## 4. Disclosure hygiene

These CVEs are **already public and patched upstream**; nothing here is embargoed. This
document contains no exploit, PoC, or weaponization — only root-cause and code-location
cross-references usable for defensive re-audit. Any *new* bug we confirm must still follow
the two-stage disclosure in `security-research/kvmctf/rules.md`
(report to `security@kernel.org`, coordinate with Google, respect the 90-day cap).

---

## Sources

- kvmCTF 6.1.74 escape write-up (CVE-2026-46113): <https://pwn.ai/blog/kvmescape>
- Januscape write-up (V4bel): <https://github.com/V4bel/Januscape/blob/main/assets/write-up.md>
- Januscape repo: <https://github.com/V4bel/Januscape>
- TuxCare analysis (CVE-2026-53359): <https://tuxcare.com/blog/januscape-exposes-the-kvm-shadow-paging-bug-that-kept-coming-back/>
- Greenbone advisory: <https://www.greenbone.net/en/blog/cve-2026-53359-januscape-kvm-vulnerability/>
- Exploit-Intel (fix: "unexpected role"): <https://exploit-intel.com/vuln/CVE-2026-53359>
- The Hacker News coverage: <https://thehackernews.com/2026/07/16-year-old-linux-kvm-flaw-lets-guest.html>
- CIQ / Rocky Linux mitigation (both CVEs required): <https://kb.ciq.com/article/security-advisories/cve-januscape-mitigation>
- Google kvmCTF announcement: <https://security.googleblog.com/2024/06/virtual-escape-real-reward-introducing-google-kvmctf.html>
- Prior art — Project Zero "An EPYC escape": <https://projectzero.google/2021/06/an-epyc-escape-case-study-of-kvm.html>
- Context — CVE-2022-1158 (guest-PTE A/D cmpxchg): <https://access.redhat.com/security/cve/CVE-2022-1158>
