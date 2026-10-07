# Bring-up runbook — getting the fuzz lab to actually fuzz

Hard-won log of every blocker hit standing the lab up and the fix for each. The
common theme: a **bleeding-edge host** (Fedora 42: GCC 15, glibc 2.41, OpenSSL 3.2)
fighting an **old LTS target** (Linux 6.1.74, built/run against Debian 12 / glibc 2.36).
On a Debian 12 host end-to-end (i.e. the GCP Intel VM) almost none of this bites —
which is itself the argument for doing the real campaign there.

Status at first green: 2 VMs, `exec total` climbing at ~70/sec, corpus + coverage
growing, 0 crashes (expected early). Reaching that took clearing all seven below.

---

## 1. syzkaller won't build — `go.mod requires go >= 1.26.0`
- **Symptom:** `make` fails: `go 1.25.x` with `GOTOOLCHAIN=local`.
- **Cause:** syzkaller HEAD needs Go ≥ 1.26; host Go is older and pinned local.
- **Fix:** `GOTOOLCHAIN=auto` (lets Go fetch 1.26) — needs a bootstrap Go ≥ 1.21.
  On Debian 12 (Go 1.19, too old to auto-fetch) install Go 1.26 from the tarball
  instead: `curl -sSL https://go.dev/dl/go1.26.0.linux-amd64.tar.gz | tar -C /usr/local -xz`.

## 2. Kernel build — `openssl/engine.h: No such file`
- **Symptom:** `scripts/sign-file` / `certs/extract-cert` fail to compile.
- **Cause:** OpenSSL 3.2 (Fedora 42) removed the deprecated ENGINE headers; kernel
  6.1's host tools still `#include <openssl/engine.h>`.
- **Fix:** don't build module signing / cert tooling. Either disable it
  (`MODULE_SIG`, `IMA`, `INTEGRITY`, `SYSTEM_TRUSTED_KEYRING`) **or** build in a
  Debian 12 container whose OpenSSL still ships the header. The container also fixes #3.

## 3. Kernel build — `cannot use keyword 'false' as enumeration constant`
- **Symptom:** compile dies in `include/linux/stddef.h` (`'false' is a keyword with -std=c23`).
- **Cause:** GCC 15 defaults to C23, where `true`/`false`/`bool` are keywords; Linux
  6.1's `stddef.h` defines them as enum constants. **GCC 15 cannot build a 6.1 kernel.**
- **Fix:** build the kernel in a **Debian 12 (GCC 12) container** — the target's own
  toolchain generation. `podman run -v …:/lab debian:12 … make bzImage modules`.
  (Starting from `x86_64_defconfig` rather than the Fedora host config also keeps the
  build lean and drops the IMA/signing baggage of #2.)

## 4. Fuzzer — `can't ssh into the instance` (×N)
- **Symptom:** VMs boot (serial shows `graphical.target`) but syz-manager never connects;
  guest log shows `Failed to start networking.service`.
- **Cause:** systemd "predictable" names rename the NIC to `ens3`/`enp0s3`, but the
  syzkaller rootfs configures networking on `eth0` → no DHCP → no IP → no ssh.
- **Fix:** add `net.ifnames=0 biosdevname=0` to `vm.cmdline` (now baked into
  `syzkaller-kvm-mmu.cfg`). NIC comes up as `eth0`, matches the image, DHCP works.

## 5. Fuzzer — `lost connection to test machine`
- **Symptom:** SSH now works, but VMs die on the first program. Guest console:
  `/syz-executor: /lib/.../libc.so.6: version 'GLIBC_2.38' not found`.
- **Cause:** syz-executor was built on the host (new glibc) but runs **inside** the
  Debian 12 guest (glibc 2.36). Symbol-version mismatch → executor can't start.
- **Fix:** rebuild `syz-executor` in a Debian 12 container (`make executor`) so it links
  against glibc 2.36 — it builds `-static-pie`, so it then runs anywhere. On a Debian 12
  **host** (GCP) this never happens; the host-built executor already matches.

## 6. Fuzzer — `make executor` needs Go / git in the container
- **Symptom:** container `make executor` → `go: not found`, then
  `[FATAL] mismatching manager/executor git revisions … vs <empty>`.
- **Cause:** syzkaller's Makefile drives the build through a Go helper (`syz-make`), and
  bakes `GIT_REVISION` from `git` into both manager and executor; the manager refuses a
  mismatch. A container without Go/git produces an empty revision.
- **Fix:** install **Go 1.26 + git** in the build container. Same repo/commit → same
  revision as the host-built manager → they agree.

## 7. Don't starve the fuzzer
- A leftover `make -j` kernel build in a container pegged all cores and starved the
  fuzz VMs. Kill competing builds (`podman stop -a`) before/while fuzzing.

---

## The working launch (local AMD lab)
```bash
# one-time, in a Debian 12 container (fixes #1,#5,#6):
podman run --rm -v "$HOME/kvm-audit-lab/syzkaller":/syzkaller:Z -w /syzkaller debian:12 \
  bash -c 'apt-get update -qq && apt-get install -y build-essential curl ca-certificates git \
    && curl -sSL https://go.dev/dl/go1.26.0.linux-amd64.tar.gz | tar -C /usr/local -xz \
    && export PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local \
    && git config --global --add safe.directory /syzkaller && make executor'

# launch (persistent tmux):
cd ~/kvm-audit-lab && ./run-fuzz.sh
# UI (local): http://127.0.0.1:56741   |   attach: tmux attach -t kvmfuzz
```

## Reading the log — real signal vs noise
- `exec total=… (N/sec)` rising + `corpus`/`coverage` growing = fuzzing for real.
- `can't ssh` / `lost connection` = infra broken (see #4/#5), **not** kernel bugs.
- A real hit = a crash dir in `workdir-kvm-mmu/crashes/` whose `description` is a
  `KASAN:` / `BUG:` / `WARNING:` in the MMU path (`kvm_tdp_mmu_map`,
  `handle_changed_spte`, `tdp_mmu_set_spte_atomic`, memslot/mmu-notifier) — then triage
  against `../AUDIT_KVM_v6.1.74.md` and confirm on the Cascade Lake kvmCTF target.

## Why GCP Intel is cleaner (see `gcp-intel-lab.md`)
Debian 12 host = GCC 12, glibc 2.36, OpenSSL with `engine.h`: issues #2, #3, #5 vanish.
Plus Cascade Lake = real VMX parity with the kvmCTF target (this AMD box only exercises
the arch-independent MMU core).
