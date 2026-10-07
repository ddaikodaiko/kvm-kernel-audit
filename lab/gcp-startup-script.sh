#!/usr/bin/env bash
# gcp-startup-script.sh — self-provisioning fuzz lab for a GCP Debian 12 VM.
# Passed via `--metadata-from-file startup-script=…`; GCP runs it as root on boot.
# It installs everything, builds the KASAN kernel + syzkaller, makes a rootfs image,
# and launches syz-manager in a tmux session — unattended, no SSH babysitting.
# Idempotent: provisioning is guarded; on later boots it only (re)launches the fuzzer.
#
# Debian 12 host = GCC 12 / glibc 2.36 / OpenSSL-with-engine.h, so the toolchain
# blockers from RUNBOOK-bringup.md (#2,#3,#5) do not apply here.
set -euxo pipefail
exec > /var/log/kvm-lab-startup.log 2>&1   # progress: tail -f this on the VM

export DEBIAN_FRONTEND=noninteractive
LAB=/root/kvm-audit-lab
SRC="$LAB/linux-6.1.74-kasan"
SYZ="$LAB/syzkaller"
mkdir -p "$LAB"

if [[ ! -f "$LAB/.provisioned" ]]; then
  apt-get update -qq
  apt-get install -y build-essential flex bison libelf-dev libssl-dev bc git \
    curl ca-certificates qemu-system-x86 qemu-utils debootstrap tmux rsync kmod cpio

  # Go 1.26 (Debian's 1.19 is too old for syzkaller's go.mod; see RUNBOOK #1)
  if ! /usr/local/go/bin/go version 2>/dev/null | grep -q go1.26; then
    curl -sSL https://go.dev/dl/go1.26.0.linux-amd64.tar.gz | tar -C /usr/local -xz
  fi
  export PATH=/usr/local/go/bin:$PATH

  # syzkaller (host build; glibc matches the guest image → no executor mismatch)
  [[ -d "$SYZ" ]] || git clone --depth 1 https://github.com/google/syzkaller "$SYZ"
  ( cd "$SYZ" && GOTOOLCHAIN=local make -j"$(nproc)" TARGETOS=linux TARGETARCH=amd64 )

  # KASAN kernel, lean config from defconfig + the audit's MMU-stress options
  [[ -d "$SRC/.git" || -f "$SRC/Makefile" ]] || \
    git clone --depth 1 --branch v6.1.74 \
      https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git "$SRC"
  cd "$SRC"
  make x86_64_defconfig
  scripts/config \
    -e KVM -e KVM_INTEL -e KVM_AMD \
    -e KASAN -e KASAN_INLINE -e KASAN_VMALLOC \
    -e KCOV -e KCOV_INSTRUMENT_ALL -e KCOV_ENABLE_COMPARISONS \
    -e DEBUG_KERNEL -e DEBUG_INFO -e DEBUG_INFO_DWARF4 -e GDB_SCRIPTS \
    -e KALLSYMS -e KALLSYMS_ALL \
    -e PREEMPT -d PREEMPT_VOLUNTARY -d PREEMPT_NONE \
    -e PROVE_LOCKING -e LOCKDEP -e DEBUG_ATOMIC_SLEEP \
    -e DEBUG_VM -e DEBUG_LIST -e DEBUG_SPINLOCK \
    -e FAULT_INJECTION -e FAILSLAB -e FAULT_INJECTION_DEBUG_FS \
    -e CONFIGFS_FS -e SECURITYFS -e DEBUG_FS -e CMDLINE_BOOL \
    --set-val NR_CPUS 8 \
    -e NET -e INET -e E1000 -e VIRTIO -e VIRTIO_PCI -e VIRTIO_NET \
    -e 9P_FS -e NET_9P -e NET_9P_VIRTIO \
    -d MODULE_SIG -d MODULE_SIG_ALL -d MODULE_SIG_FORMAT \
    -d IMA -d IMA_APPRAISE_MODSIG -d INTEGRITY -d SYSTEM_DATA_VERIFICATION \
    -d SYSTEM_TRUSTED_KEYRING
  make olddefconfig
  make -j"$(nproc)" bzImage modules

  # rootfs image (debootstrap needs root — fine, we are root)
  mkdir -p "$LAB/image"
  cp "$SYZ/tools/create-image.sh" "$LAB/image/"
  ( cd "$LAB/image" && chmod +x create-image.sh && ./create-image.sh --distribution bookworm )

  # manager config (net.ifnames=0 fixes the 'can't ssh' NIC-naming trap — RUNBOOK #4)
  cat > "$LAB/syzkaller-kvm-mmu.cfg" <<EOF
{
  "target": "linux/amd64",
  "http": "127.0.0.1:56741",
  "workdir": "$SYZ/workdir-kvm-mmu",
  "kernel_obj": "$SRC",
  "image": "$LAB/image/bookworm.img",
  "sshkey": "$LAB/image/bookworm.id_rsa",
  "syzkaller": "$SYZ",
  "procs": 4,
  "type": "qemu",
  "reproduce": true,
  "cover": true,
  "vm": {
    "count": 4,
    "kernel": "$SRC/arch/x86/boot/bzImage",
    "cpu": 2,
    "mem": 2048,
    "qemu_args": "-enable-kvm -cpu host,migratable=off",
    "cmdline": "kasan.fault=panic kasan_multi_shot panic_on_warn=1 nokaslr net.ifnames=0 biosdevname=0"
  },
  "enable_syscalls": [
    "syz_kvm_setup_cpu\$x86", "openat\$kvm",
    "ioctl\$KVM_CREATE_VM", "ioctl\$KVM_CREATE_VCPU",
    "ioctl\$KVM_SET_USER_MEMORY_REGION", "ioctl\$KVM_RUN",
    "ioctl\$KVM_GET_DIRTY_LOG", "ioctl\$KVM_CLEAR_DIRTY_LOG",
    "ioctl\$KVM_SET_TSS_ADDR", "ioctl\$KVM_SET_IDENTITY_MAP_ADDR", "ioctl\$KVM_TRANSLATE",
    "mmap\$KVM_VCPU", "mmap", "munmap", "mremap", "madvise", "mprotect",
    "userfaultfd", "ioctl\$UFFDIO_REGISTER", "ioctl\$UFFDIO_COPY", "ioctl\$UFFDIO_UNREGISTER"
  ]
}
EOF
  mkdir -p "$SYZ/workdir-kvm-mmu"
  touch "$LAB/.provisioned"
fi

# (re)launch the fuzzer on every boot if not already running
export PATH=/usr/local/go/bin:$PATH
cd "$SYZ"
if ! tmux has-session -t kvmfuzz 2>/dev/null; then
  tmux new-session -d -s kvmfuzz \
    "./bin/syz-manager -config '$LAB/syzkaller-kvm-mmu.cfg' 2>&1 | tee '$LAB/syz-manager.log'"
fi
echo "kvm fuzz lab up: tmux session 'kvmfuzz', log at $LAB/syz-manager.log"
