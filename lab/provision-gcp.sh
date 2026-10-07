#!/usr/bin/env bash
# provision-gcp.sh
# Provision a GCP Intel Cascade Lake VM (Debian 12 host) as a syzkaller fuzz lab
# with kvmCTF v6.1.74 parity. Run ON THE VM after `gcloud compute scp`-ing it up
# alongside build-kernel-kasan.sh and syzkaller-kvm-mmu.cfg.
#
# Design:
#   * Host stays Debian 12 so nested /dev/kvm works natively (syzkaller needs it).
#   * The KASAN *kernel build* runs in a pinned debian:12 Podman container for
#     toolchain reproducibility (same gcc/binutils generation Google ships).
#   * Idempotent-ish: re-running skips clones/builds that already exist.
#
# Usage:  ./provision-gcp.sh           # full provision
#         SKIP_IMAGE=1 ./provision-gcp.sh   # skip rootfs image build
set -euo pipefail

WORKROOT="${WORKROOT:-$HOME/kvm-audit}"
LAB="$WORKROOT/lab"
SRC="$LAB/linux-6.1.74-kasan"
SYZ="$HOME/go/src/github.com/google/syzkaller"
IMG_DIR="$HOME/syzkaller-image"
DEB_IMAGE="debian:12"

say(){ printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

# ---- 0. sanity: nested virt must be visible ------------------------------
say "Checking nested virtualization"
if ! grep -qE '(vmx)' /proc/cpuinfo; then
  echo "FATAL: no vmx in /proc/cpuinfo — VM was not created with --enable-nested-virtualization" >&2
  exit 1
fi
[[ -e /dev/kvm ]] || { echo "FATAL: /dev/kvm missing"; exit 1; }
echo "  vmx present, /dev/kvm ok: $(lscpu | grep -i 'model name' | head -1)"

# ---- 1. host dependencies ------------------------------------------------
say "Installing host packages (Debian 12)"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  podman qemu-system-x86 qemu-utils debootstrap git golang-go \
  openssh-client build-essential flex bison libelf-dev libssl-dev bc rsync
sudo usermod -aG kvm "$USER" || true   # /dev/kvm access for this user

mkdir -p "$LAB" "$IMG_DIR"

# ---- 2. syzkaller (host build; Go auto-toolchain) ------------------------
say "Fetching + building syzkaller"
if [[ ! -d "$SYZ" ]]; then
  mkdir -p "$(dirname "$SYZ")"
  git clone --depth 1 https://github.com/google/syzkaller "$SYZ"
fi
( cd "$SYZ" && GOTOOLCHAIN=auto make -j"$(nproc)" TARGETOS=linux TARGETARCH=amd64 )

# ---- 3. rootfs image (Debian bookworm) + ssh key -------------------------
if [[ "${SKIP_IMAGE:-0}" != 1 && ! -f "$IMG_DIR/bookworm.img" ]]; then
  say "Creating syzkaller rootfs image (debootstrap bookworm)"
  ( cd "$IMG_DIR" && \
    cp "$SYZ/tools/create-image.sh" . && \
    chmod +x create-image.sh && \
    ./create-image.sh --distribution bookworm )
else
  echo "  rootfs image present or SKIP_IMAGE=1 — skipping"
fi

# ---- 4. KASAN kernel build INSIDE a pinned debian:12 container -----------
# Bind-mounts the source tree + build script; the container has the parity
# toolchain. /dev/kvm is NOT passed — this container only compiles.
say "Building KASAN kernel in $DEB_IMAGE container (toolchain parity)"
if [[ ! -f "$SRC/arch/x86/boot/bzImage" ]]; then
  podman run --rm \
    -v "$LAB":/lab:Z \
    -w /lab \
    "$DEB_IMAGE" \
    bash -euo pipefail -c '
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        build-essential flex bison libelf-dev libssl-dev bc git kmod cpio \
        gcc binutils make
      chmod +x build-kernel-kasan.sh
      ./build-kernel-kasan.sh /lab/linux-6.1.74-kasan -j'"$(nproc)"'
    '
else
  echo "  bzImage already built — skipping"
fi

# ---- 5. rewrite the syz config paths for this VM -------------------------
say "Rewriting syzkaller-kvm-mmu.cfg paths"
CFG="$LAB/syzkaller-kvm-mmu.cfg"
[[ -f "$CFG" ]] || cp "$HOME/syzkaller-kvm-mmu.cfg" "$CFG" 2>/dev/null || true
if [[ -f "$CFG" ]]; then
  sed -i \
    -e "s#\"workdir\":.*#\"workdir\": \"$LAB/workdir-kvm-mmu\",#" \
    -e "s#\"kernel_obj\":.*#\"kernel_obj\": \"$SRC\",#" \
    -e "s#\"syzkaller\":.*#\"syzkaller\": \"$SYZ\",#" \
    -e "s#\"image\":.*#\"image\": \"$IMG_DIR/bookworm.img\",#" \
    -e "s#\"sshkey\":.*#\"sshkey\": \"$IMG_DIR/bookworm.id_rsa\",#" \
    -e "s#\"kernel\":.*#\"kernel\": \"$SRC/arch/x86/boot/bzImage\",#" \
    "$CFG"
  mkdir -p "$LAB/workdir-kvm-mmu"
  echo "  patched $CFG"
fi

say "DONE — launch with:"
echo "  cd $SYZ && ./bin/syz-manager -config $CFG"
echo "  (reach the UI via SSH tunnel: -L 56741:127.0.0.1:56741 — never open it publicly)"
