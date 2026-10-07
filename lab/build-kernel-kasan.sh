#!/usr/bin/env bash
# build-kernel-kasan.sh
# Build a KASAN-instrumented Linux v6.1.74 tuned to surface the V1 (MMU
# concurrency) race hypotheses H1/H2 under syzkaller.
#
# RUNS ON A LINUX HOST ONLY (needs gcc, make, /dev/kvm for the fuzz VMs).
# It CANNOT run on the Windows audit box, and the sparse KVM-only extract in
# ../linux-6.1.74 CANNOT be built — a kernel build needs the FULL tree. This
# script therefore does a full clone of v6.1.74 on the Linux host (where the
# NTFS reserved-name problem that blocked the Windows checkout does not exist).
#
# Why these options (vs a plain KASAN build):
#   KASAN               - catches the UAF/OOB that H1/H2 would produce.
#   KCOV                - REQUIRED by syzkaller for coverage-guided fuzzing.
#   PREEMPT + PROVE_LOCKING - makes cond_resched()/rwlock_needbreak() fire often
#                         (stresses the H2 tdp_mmu_iter_cond_resched yield) and
#                         validates the mmu_lock ordering H1 relies on.
#   DEBUG_VM/LIST, FAILSLAB - raise the odds a latent window becomes an oops.
#   DEBUG_INFO + KALLSYMS_ALL - symbolization for syz-manager (kernel_obj).
#
# Usage:
#   ./build-kernel-kasan.sh [SRC_DIR] [-j N] [--patch /path/to/kvmctf.patch]
#   SRC_DIR defaults to ./linux-6.1.74-kasan (full clone created if absent).
#   --patch applies the kvmCTF bundle patch for exact target parity (optional;
#           the bundle is the gated storage.googleapis.com/kvmctf download).

set -euo pipefail

SRC_DIR="${1:-$PWD/linux-6.1.74-kasan}"; [[ "${1:-}" == -* ]] && SRC_DIR="$PWD/linux-6.1.74-kasan"
JOBS="$(nproc)"
KTAG="v6.1.74"
KSTABLE_URL="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
PATCH=""

while [[ $# -gt 0 ]]; do case "$1" in
  -j) JOBS="$2"; shift 2 ;;
  --patch) PATCH="$2"; shift 2 ;;
  -*) echo "unknown: $1" >&2; exit 2 ;;
  *) shift ;;
esac; done

say(){ printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

command -v gcc  >/dev/null || { echo "need gcc (build-essential)"; exit 1; }
command -v flex >/dev/null || { echo "need flex/bison/libelf-dev/libssl-dev/bc"; exit 1; }

say "Source tree: $SRC_DIR  (tag $KTAG, jobs=$JOBS)"
if [[ ! -d "$SRC_DIR/.git" && ! -f "$SRC_DIR/Makefile" ]]; then
  git clone --depth 1 --branch "$KTAG" "$KSTABLE_URL" "$SRC_DIR"
fi
cd "$SRC_DIR"

if [[ -n "$PATCH" ]]; then
  say "Applying kvmCTF patch: $PATCH"
  git apply --index "$PATCH" || patch -p1 < "$PATCH"
fi

say "Base config (host-derived if available, else x86_64 defconfig)"
if [[ -f /boot/config-"$(uname -r)" ]]; then
  cp /boot/config-"$(uname -r)" .config && make olddefconfig
else
  make x86_64_defconfig
fi

say "Enabling KASAN / KCOV / debug / MMU-stress options"
scripts/config \
  -e KVM -e KVM_INTEL -e KVM_AMD \
  -e KASAN -e KASAN_INLINE -e KASAN_VMALLOC \
  -e KCOV -e KCOV_INSTRUMENT_ALL -e KCOV_ENABLE_COMPARISONS \
  -e DEBUG_KERNEL -e DEBUG_INFO_DWARF4 -e GDB_SCRIPTS \
  -e KALLSYMS -e KALLSYMS_ALL \
  -e PREEMPT -d PREEMPT_VOLUNTARY -d PREEMPT_NONE \
  -e PROVE_LOCKING -e LOCKDEP -e DEBUG_ATOMIC_SLEEP \
  -e DEBUG_VM -e DEBUG_LIST -e DEBUG_SPINLOCK \
  -e FAULT_INJECTION -e FAILSLAB -e FAULT_INJECTION_DEBUG_FS \
  -e CONFIGFS_FS -e SECURITYFS \
  -e DEBUG_FS \
  -e CMDLINE_BOOL \
  --set-val NR_CPUS 8
# syzkaller image talks over the network + ssh:
scripts/config -e NET -e INET -e E1000 -e VIRTIO -e VIRTIO_PCI -e VIRTIO_NET \
  -e 9P_FS -e NET_9P -e NET_9P_VIRTIO

make olddefconfig

say "Verifying the options that matter actually stuck"
for o in KASAN KCOV PREEMPT PROVE_LOCKING KVM_INTEL DEBUG_INFO_DWARF4; do
  grep -qE "^CONFIG_${o}=y" .config && echo "  [y] CONFIG_${o}" || echo "  [!] CONFIG_${o} NOT set"
done

say "Building bzImage + modules (-j$JOBS) — expect 15-40 min and ~25 GB"
make -j"$JOBS" bzImage modules

say "DONE"
echo "  vmlinux (kernel_obj / symbolization): $SRC_DIR/vmlinux"
echo "  bzImage (vm.kernel for syz-manager) : $SRC_DIR/arch/x86/boot/bzImage"
echo "  Point syzkaller-kvm-mmu.cfg 'kernel_obj' at $SRC_DIR and 'vm.kernel' at the bzImage."
