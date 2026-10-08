# Lab status — KVM MMU fuzz campaign (GCP Intel, Cascade Lake)

**Updated:** 2026-10-08 ~08:54 UTC. **State: OPERATIONAL — fuzzing.**

Clean, professional bring-up of the dynamic lab on the GCP Debian 12 Intel VM.
Supersedes the earlier half-built attempt (which boot-looped into emergency mode).

## Current campaign

| | |
|---|---|
| Host | GCP `kvm-fuzz-intel`, `n2-standard-8` (Cascade Lake, 8 vCPU / 32 GB), Debian 12, zone `us-east1-b` |
| Nested virt | enabled (`kvm_intel.nested=Y`, `/dev/kvm` present) — fuzz guests run hardware VMX |
| Target kernel | Linux **v6.1.74** + KASAN + KCOV + lockdep/PROVE_LOCKING + DEBUG_VM (reused from `~/kvm-kernel-audit/lab/linux-6.1.74-kasan`) |
| Fuzzer | syzkaller HEAD, built native with Go 1.26 (`~/syzkaller`) |
| Rootfs | fresh Debian bookworm image from syzkaller `create-image.sh` (glibc 2.36, matches target) |
| Config | `~/lab2/kvm-mmu.cfg` — scoped to KVM + mmap/madvise/mremap; 4 VMs × 2 vCPU, `sandbox:none`, cover+reproduce on |
| Web UI | `http://0.0.0.0:56741` on the VM (tunnel to view, see below) |
| Workdir | `~/lab2/workdir` (corpus, coverage, crashes) |
| Launcher | tmux session `kvmfuzz`; log at `~/lab2/manager.log` |

**First green (08:53 UTC):** corpus 123→381, coverage 10.8k→15.2k and climbing,
~59 exec/sec, candidates=0, **0 crashes** (expected this early). Host load avg ≈ 8
(fully utilised, healthy).

## Why this scope

The verified bug class on this exact target (`VERIFIED-shadow-rmap-UAF-on-v6.1.74.md`)
lives in the **shadow / indirect MMU rmap bookkeeping**, reached by driving nested /
shadow paging and exercising memslot churn + MMU-notifier invalidation (e.g.
`MADV_DONTNEED`). The config enables the `syz_kvm_*` pseudo-syscalls (which build nested
VMs and run guest code) plus `mmap`/`madvise`/`mremap`/memslot ioctls so the fuzzer can
reach that surface. KASAN is what turns a latent rmap UAF into a reported crash.

## Access the web UI (from a workstation)

```bash
gcloud compute ssh kvm-fuzz-intel --zone=us-east1-b -- -N -L 56741:127.0.0.1:56741
# then open http://127.0.0.1:56741
```

## Monitor

```bash
gcloud compute ssh kvm-fuzz-intel --zone=us-east1-b \
  --command='tail -f ~/lab2/manager.log'          # live rate/coverage/crashes
gcloud compute ssh kvm-fuzz-intel --zone=us-east1-b \
  --command='ls ~/lab2/workdir/crashes/'          # a dir per unique crash
```

A real hit = a dir under `workdir/crashes/` whose `description` is a `KASAN:` / `BUG:` /
`WARNING:` in an MMU symbol (`kvm_mmu_*`, `rmap_*`, `mmu_set_spte`, `__link_shadow_page`,
`kvm_mmu_get_child_sp`, `handle_changed_spte`, memslot / mmu-notifier). Triage against
`../AUDIT_KVM_v6.1.74.md`; confirm it is **not** CVE-2026-46113 / -53359 (both patched
upstream, so a stock-v6.1.74 hit there is known); a *novel* reproducible guest→host bug
is the only kvmCTF-submittable outcome and must follow `security-research/kvmctf/rules.md`.

## Persistence & the one caveat

- `~/relaunch-fuzz.sh` + an `@reboot` crontab entry relaunch the campaign in tmux on boot.
- **The instance is SPOT (preemptible) with `automaticRestart=False`.** If GCP preempts
  it, it STOPS and stays stopped — the campaign pauses until someone starts it again.
  Fine for a short window; for an unattended multi-day hunt make it durable (€300 credit
  ≈ 1 month of standard n2-standard-8 ≈ €0.39/hr):
  ```bash
  gcloud compute instances stop  kvm-fuzz-intel --zone=us-east1-b
  gcloud compute instances set-scheduling kvm-fuzz-intel --zone=us-east1-b \
      --provisioning-model=STANDARD --no-preemptible
  gcloud compute instances start kvm-fuzz-intel --zone=us-east1-b
  # @reboot cron relaunches the fuzzer automatically after start
  ```
  (This interrupts the current run briefly; the corpus in `workdir/` is preserved.)

## Honest note on expectations

Coverage-guided fuzzing of a heavily-reviewed LTS kernel is a *probabilistic, long*
effort — "0 crashes" for hours or days is the normal state, not a failure. The lab is set
up correctly to surface a bug if one is reachable; it does not guarantee one exists in
the covered surface. The €250k tier requires a full novel guest→host RCE — the realistic
near-term outcomes are a DoS/relative-read KASAN hit to triage, or clean coverage that
sharpens the static audit.
