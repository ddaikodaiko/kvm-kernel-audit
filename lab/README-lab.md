# kvmCTF v6.1.74 dynamic lab — scaffolding

Turns the static H1/H2 hypotheses from `../AUDIT_KVM_v6.1.74.md` into a running
coverage-guided fuzz lab. **Everything here runs on a Linux host, not the Windows audit
box.** Nothing has been executed — these are ready-to-run templates.

## Prerequisites (Linux host)
- A bare-metal or nested-virt Linux host where `/dev/kvm` is usable (the fuzz VMs run
  with `-enable-kvm`; the *target* KVM runs nested inside them).
- `build-essential libelf-dev libssl-dev bison flex bc`, Go (for syzkaller), QEMU.
- ~40 GB free for the kernel build + image + syzkaller workdir.
- syzkaller cloned and built: https://github.com/google/syzkaller
- A rootfs image + ssh key (syzkaller's `tools/create-image.sh` produces
  `bookworm.img` + `bookworm.id_rsa`).

## Step 1 — build the instrumented kernel
```bash
./build-kernel-kasan.sh            # full-clones v6.1.74, applies the KASAN/KCOV config, builds
# optional, exact kvmCTF parity (needs the gated bundle patch):
./build-kernel-kasan.sh --patch /path/to/kvmctf/kernel.patch
```
Outputs `vmlinux` (symbolization) and `arch/x86/boot/bzImage` (the VM kernel). The script
prints both paths. It enables, beyond plain KASAN: **KCOV** (syzkaller coverage),
**PREEMPT + PROVE_LOCKING** (fires the H2 `tdp_mmu_iter_cond_resched` yield and validates
the H1 `mmu_lock` ordering), **DEBUG_VM / FAILSLAB** (turns latent windows into oopses),
**DEBUG_INFO_DWARF4 + KALLSYMS_ALL** (symbols for `kernel_obj`).

## Step 2 — point the syz-manager config at your build
Edit `syzkaller-kvm-mmu.cfg`:
- `kernel_obj`  → the kernel source/build dir (has `vmlinux`).
- `vm.kernel`   → `.../arch/x86/boot/bzImage`.
- `image` / `sshkey` → your rootfs image + key.
- `syzkaller`   → your syzkaller checkout.
- `workdir`     → a scratch dir (corpus/crashes land here).

Boot flags in `vm.cmdline` are deliberate: `panic_on_warn=1` + `kasan.fault=panic` turn
the `WARN_ON_ONCE(iter->yielded)` guard (H2, tdp_mmu.c:581) and any KASAN hit into a
caught crash with a reproducer; `nokaslr` keeps reports stable.

## Step 3 — why this syscall set targets H1/H2
syzkaller fuzzes by mutating syscall sequences. The `enable_syscalls` list is scoped to
exactly the two windows we mapped — nothing else, so coverage concentrates there:

- **The KVM side (builds + runs a guest, drives faults):** `syz_kvm_setup_cpu$x86`
  (pseudo-syscall that stands up a vCPU + guest code), `ioctl$KVM_CREATE_VM/VCPU`,
  `ioctl$KVM_SET_USER_MEMORY_REGION` (create/move/**delete** memslots — the zap path for
  H2), `ioctl$KVM_RUN` (drives `direct_page_fault` → the H1 faultin→install window),
  dirty-log ioctls (exercise `kvm_clear_dirty_log_protect` + TDP dirty-bit SPTE churn).
- **The invalidation side (races the fault):** `mmap/munmap/mremap/mprotect` and
  especially `madvise(MADV_DONTNEED)` on the memory backing a memslot's `userspace_addr`
  fire `mmu_notifier_invalidate_range_start/end` — the H1 counter-party. `userfaultfd` +
  `UFFDIO_*` let the fuzzer stall and resume faults with precise timing, widening the
  race window between `mmu_seq` sampling (mmu.c:4264) and the under-lock retry
  (mmu.c:4282).

Run interleaved on 4 VMs × 4 procs, this is the configuration most likely to trip H1
(stale SPTE install) or H2 (use of a yielded iterator / premature free) if either window
is actually reachable on this tree.

> **Note on globs:** some syzkaller versions accept `"ioctl$KVM_*"` wildcards in
> `enable_syscalls`; this template lists names explicitly for portability. If your
> syzkaller supports globs, `"ioctl$KVM_*"` is a convenient superset. Confirm names
> against `sys/linux/dev_kvm.txt` in your checkout — descriptions evolve between versions.

## Step 4 — run
```bash
cd $syzkaller
./bin/syz-manager -config /home/researcher/kvm-audit/lab/syzkaller-kvm-mmu.cfg
```
Watch the web UI at `http://127.0.0.1:56741`. A crash in `kvm_tdp_mmu_map`,
`handle_changed_spte`, `__handle_changed_spte`, `tdp_mmu_set_spte_atomic`, or a KASAN
use-after-free in the memslot/mmu-notifier path is a hit on H1/H2 — triage the
reproducer against the invariants documented in `../AUDIT_KVM_v6.1.74.md`.

## Scope / ethics
For use only against your own lab build and the authorized kvmCTF instance, under the
reporting process in `security-research/kvmctf/rules.md`. This scaffolding finds and
characterizes bugs for disclosure; it is not a weaponized exploit.
