#!/usr/bin/env bash
# setup-kvm-audit-env.sh
# Provision a Linux/WSL2 environment for a PASSIVE (static) KVM source audit
# aligned with the kvmCTF target (Linux LTS v6.1.74).
#
# Design goals:
#   * Safe + idempotent: re-running does not clobber or re-download.
#   * No silent downloads: large fetches (kernel source, kvmCTF bundle) require
#     an explicit flag. Default run only installs packages + indexes what exists.
#   * Static-audit focused: sets up cscope/ctags/clangd navigation. It does NOT
#     build the kernel by default (a full build needs ~20-30 GB + long CPU time).
#
# Tested target: Ubuntu 22.04/24.04 (native or WSL2).
#
# Usage:
#   ./setup-kvm-audit-env.sh                 # deps + index any source already present
#   ./setup-kvm-audit-env.sh --fetch-kernel  # ALSO git-clone linux-6.1.y @ v6.1.74 (~3-4 GB)
#   ./setup-kvm-audit-env.sh --fetch-bundle  # ALSO download the kvmCTF host bundle (size unknown)
#   ./setup-kvm-audit-env.sh --with-lab      # ALSO install qemu/debootstrap (run-lab extras)
#
# Combine flags freely. Review before running; it uses sudo for apt only.

set -euo pipefail

# ---- config ---------------------------------------------------------------
WORKROOT="${WORKROOT:-$HOME/kvm-audit}"
KSRC_DIR="$WORKROOT/linux-6.1.y"
KTAG="v6.1.74"
SR_DIR="$WORKROOT/security-research"
SR_URL="https://github.com/google/security-research.git"
KSTABLE_URL="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
BUNDLE_URL="https://storage.googleapis.com/kvmctf/latest.tar.gz"   # see kvmctf/rules.md
KVM_PATHS=(virt/kvm arch/x86/kvm include/linux/kvm_host.h)

FETCH_KERNEL=0; FETCH_BUNDLE=0; WITH_LAB=0
for a in "$@"; do case "$a" in
  --fetch-kernel) FETCH_KERNEL=1 ;;
  --fetch-bundle) FETCH_BUNDLE=1 ;;
  --with-lab)     WITH_LAB=1 ;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) echo "unknown arg: $a" >&2; exit 2 ;;
esac; done

say(){ printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok(){  printf '\033[1;32m[ok]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }

mkdir -p "$WORKROOT"

# ---- 1. virtualization capability check (informational for static audit) --
say "1/5  Virtualization capability check"
if grep -Eoq '(vmx|svm)' /proc/cpuinfo; then
  ext=$(grep -Eo '(vmx|svm)' /proc/cpuinfo | sort -u | tr '\n' ' ')
  ok "CPU virtualization extensions present: ${ext}"
else
  warn "No vmx/svm in /proc/cpuinfo. Under WSL2 this is normal; nested virt may be off."
  warn "Not required for a STATIC source audit — continuing."
fi
if [[ -e /dev/kvm ]]; then
  ok "/dev/kvm exists: $(ls -l /dev/kvm)"
  [[ -r /dev/kvm && -w /dev/kvm ]] && ok "/dev/kvm is r/w for you" \
     || warn "/dev/kvm not r/w for your user (add yourself to the 'kvm' group to run VMs)."
else
  warn "/dev/kvm absent. Fine for static audit; needed only to RUN guests."
fi

# ---- 2. system dependencies ----------------------------------------------
say "2/5  Installing audit toolchain (sudo apt)"
sudo apt-get update
# Static-analysis / navigation + the kernel's own build deps (so compile_commands
# can be generated later if you choose to).
PKGS=(build-essential libelf-dev libssl-dev bison flex bc \
      cscope universal-ctags clangd clang-tools clang-tidy \
      python3 python3-pip git ripgrep)
if [[ $WITH_LAB -eq 1 ]]; then
  PKGS+=(qemu-system-x86 qemu-utils debootstrap)   # run-lab extras (heavier)
  warn "--with-lab: adding qemu/debootstrap. Docker is NOT auto-installed (system/"
  warn "security change) — install it yourself if your lab needs it."
fi
sudo apt-get install -y "${PKGS[@]}"
ok "Installed: ${PKGS[*]}"

# ---- 3. security-research repo -------------------------------------------
say "3/5  google/security-research repo"
if [[ -d "$SR_DIR/.git" ]]; then
  ok "Already present at $SR_DIR (not re-cloning)."
else
  git clone --depth 1 "$SR_URL" "$SR_DIR"
  ok "Cloned to $SR_DIR"
fi
echo "    kvmCTF rules: $SR_DIR/kvmctf/rules.md"
echo "    kvmCTF PoCs:  $SR_DIR/pocs/linux/kvmctf/"

# ---- 4. kernel source (gated) --------------------------------------------
say "4/5  Kernel source ($KTAG)"
if [[ $FETCH_KERNEL -eq 1 ]]; then
  if [[ -d "$KSRC_DIR/.git" ]]; then
    ok "Kernel tree already at $KSRC_DIR"
  else
    warn "Cloning linux-stable at tag $KTAG (~3-4 GB). Ctrl-C now to abort."
    git clone --depth 1 --branch "$KTAG" "$KSTABLE_URL" "$KSRC_DIR"
    ok "Kernel source at $KSRC_DIR ($(git -C "$KSRC_DIR" describe --tags 2>/dev/null || echo "$KTAG"))"
  fi
else
  warn "Skipped kernel download (no --fetch-kernel). KVM dirs to index live under:"
  printf '         %s\n' "${KVM_PATHS[@]}"
fi

# ---- 4b. kvmCTF host bundle (gated) --------------------------------------
if [[ $FETCH_BUNDLE -eq 1 ]]; then
  say "4b   kvmCTF host bundle"
  dest="$WORKROOT/kvmctf-latest.tar.gz"
  if [[ -f "$dest" ]]; then
    ok "Bundle already downloaded: $dest"
  else
    warn "Downloading $BUNDLE_URL (size unknown; includes vmlinux images)."
    curl -fL --progress-bar -o "$dest" "$BUNDLE_URL"
    ok "Saved $dest ($(du -h "$dest" | cut -f1)). Contains the kvmCTF kernel patch,"
    ok ".config, exact gcc/binutils versions, vmlinux/bzImage/.ko, and the qemu cmd."
    warn "Apply the included patch onto $KTAG before auditing for exact behavior."
  fi
fi

# ---- 5. build the static-navigation index --------------------------------
say "5/5  Building code-navigation index (cscope + ctags, KVM subtree only)"
if [[ -d "$KSRC_DIR" ]]; then
  cd "$KSRC_DIR"
  : > cscope.files
  for p in "${KVM_PATHS[@]}"; do
    [[ -e "$p" ]] && find "$p" -type f \( -name '*.c' -o -name '*.h' -o -name '*.S' \) >> cscope.files
  done
  if [[ -s cscope.files ]]; then
    cscope -bq -i cscope.files
    ctags -L cscope.files -f tags
    ok "Indexed $(wc -l < cscope.files) KVM source files."
    ok "Navigate: 'cscope -d' here, or point clangd/your editor at $KSRC_DIR."
    echo "    Tip (needs a configured build, not done here):"
    echo "      make defconfig && make kvm/ && \\"
    echo "      python3 scripts/clang-tools/gen_compile_commands.py  # for clangd"
  else
    warn "No KVM paths found in $KSRC_DIR — is the tag correct?"
  fi
else
  warn "No kernel tree yet; re-run with --fetch-kernel to populate + index."
fi

# ---- summary --------------------------------------------------------------
say "DONE — environment summary"
printf '  workroot          : %s\n' "$WORKROOT"
printf '  security-research : %s\n' "$([[ -d $SR_DIR/.git ]] && echo present || echo MISSING)"
printf '  kernel %-10s : %s\n' "$KTAG" "$([[ -d $KSRC_DIR/.git ]] && echo present || echo 'not fetched (--fetch-kernel)')"
printf '  kvmCTF bundle     : %s\n' "$([[ -f $WORKROOT/kvmctf-latest.tar.gz ]] && echo downloaded || echo 'not fetched (--fetch-bundle)')"
printf '  qemu/debootstrap  : %s\n' "$([[ $WITH_LAB -eq 1 ]] && echo installed || echo 'skipped (--with-lab)')"
printf '  cscope/ctags idx  : %s\n' "$([[ -f $KSRC_DIR/cscope.out ]] && echo built || echo 'pending (needs kernel src)')"
echo
echo "Next: read $SR_DIR/kvmctf/rules.md, then start the audit from"
echo "AUDIT_KVM_v6.1.74.md (reading order at the bottom)."
