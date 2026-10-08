#!/usr/bin/env bash
# setup-lab.sh — clean, professional syzkaller KVM fuzz lab on the GCP Debian 12 Intel VM.
# Idempotent. Reuses the already-built KASAN kernel; builds syzkaller; creates a
# fresh known-good rootfs (the old bookworm.img boots to emergency mode); writes a
# KVM-scoped syz-manager config; and leaves everything staged to launch.
set -euo pipefail

export PATH=/usr/local/go/bin:$PATH
export GOTOOLCHAIN=local
HOME_DIR="$HOME"
LAB="$HOME_DIR/lab2"                 # clean lab root
KDIR="$HOME_DIR/kvm-kernel-audit/lab/linux-6.1.74-kasan"
BZIMAGE="$KDIR/arch/x86/boot/bzImage"
VMLINUX="$KDIR/vmlinux"
SYZ="$HOME_DIR/syzkaller"
IMGDIR="$LAB/image"
WORKDIR="$LAB/workdir"

step(){ printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

step "Preflight: kernel artifacts must exist"
test -f "$BZIMAGE" || { echo "MISSING $BZIMAGE"; exit 1; }
test -f "$VMLINUX" || { echo "MISSING $VMLINUX"; exit 1; }
echo "bzImage: $(stat -c%s "$BZIMAGE") bytes ; vmlinux: $(stat -c%s "$VMLINUX") bytes"
go version

step "Install host deps (debootstrap, build tools)"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  debootstrap build-essential flex bison libelf-dev libssl-dev bc \
  qemu-system-x86 qemu-utils git ca-certificates >/dev/null
echo "deps ok"

mkdir -p "$LAB" "$IMGDIR" "$WORKDIR"

step "Clone + build syzkaller (native, Go $(go version | awk '{print $3}'))"
if [ ! -d "$SYZ/.git" ]; then
  git clone --depth 1 https://github.com/google/syzkaller "$SYZ"
fi
cd "$SYZ"
git config --global --add safe.directory "$SYZ" || true
make -s 2>&1 | tail -5
test -x "$SYZ/bin/syz-manager" || { echo "syz-manager build FAILED"; exit 1; }
echo "syzkaller built: $($SYZ/bin/syz-manager -help 2>&1 | head -1 || true)"

step "Create a fresh Debian bookworm rootfs (known-good; replaces the emergency-mode image)"
if [ ! -f "$IMGDIR/bookworm.img" ]; then
  cp "$SYZ/tools/create-image.sh" "$IMGDIR/create-image.sh"
  cd "$IMGDIR"
  # -d bookworm matches the kvmCTF guest userspace (glibc 2.36); default seek gives ~2GB.
  sudo --preserve-env=PATH ./create-image.sh -d bookworm 2>&1 | tail -8
fi
test -f "$IMGDIR/bookworm.img" || { echo "rootfs creation FAILED"; exit 1; }
test -f "$IMGDIR/bookworm.id_rsa" || { echo "ssh key MISSING"; exit 1; }
chmod 600 "$IMGDIR/bookworm.id_rsa"
echo "rootfs: $(stat -c%s "$IMGDIR/bookworm.img") bytes ; key ok"

step "Write KVM-scoped syz-manager config"
NPROC=$(nproc)
VMCOUNT=4                    # 4 guests x 2 vcpu on 8 vCPU host, leaves room for manager
cat > "$LAB/kvm-mmu.cfg" <<JSON
{
  "target": "linux/amd64",
  "http": "0.0.0.0:56741",
  "workdir": "$WORKDIR",
  "kernel_obj": "$KDIR",
  "image": "$IMGDIR/bookworm.img",
  "sshkey": "$IMGDIR/bookworm.id_rsa",
  "syzkaller": "$SYZ",
  "procs": 4,
  "sandbox": "none",
  "cover": true,
  "reproduce": true,
  "enable_syscalls": [
    "openat\$kvm",
    "ioctl\$KVM_*",
    "syz_kvm_setup_cpu\$*",
    "syz_kvm_*",
    "mmap",
    "munmap",
    "madvise",
    "mremap"
  ],
  "type": "qemu",
  "vm": {
    "count": $VMCOUNT,
    "cpu": 2,
    "mem": 2048,
    "kernel": "$BZIMAGE",
    "cmdline": "net.ifnames=0 biosdevname=0 nokaslr",
    "qemu_args": "-enable-kvm -cpu host,migratable=off -machine q35"
  }
}
JSON
echo "config written: $LAB/kvm-mmu.cfg"
"$SYZ/bin/syz-manager" -config "$LAB/kvm-mmu.cfg" -help >/dev/null 2>&1 || true

step "DONE — staging complete"
echo "launch with: tmux new -d -s kvmfuzz \"$SYZ/bin/syz-manager -config $LAB/kvm-mmu.cfg 2>&1 | tee -a $LAB/manager.log\""
echo "ui: http://127.0.0.1:56741 (tunnel)"
