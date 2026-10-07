# Secondary fuzz lab on GCP — Intel Cascade Lake parity with kvmCTF

Goal: a second syzkaller lab on an **Intel Cascade Lake** host with **nested
virtualization**, matching the kvmCTF target microarchitecture (the local AMD box
only covers the arch-independent MMU core; this covers the Intel VMX surface too).

> Scope/ethics: for your own lab builds and the **authorized** kvmCTF instance only,
> under `security-research/kvmctf/rules.md`. Finds/characterizes bugs for disclosure.

---

## 1. Instance selection

| Need | Choice | Why |
|---|---|---|
| CPU parity | **N2** + `--min-cpu-platform="Intel Cascade Lake"` | N2 = Cascade Lake / Ice Lake. kvmCTF target is Cascade Lake. C3 is Sapphire Rapids (different μarch + mitigation set); N2D is AMD. |
| Nested virt | `--enable-nested-virtualization` | Required so the fuzz VMs boot with `-enable-kvm`; N2 (Intel Haswell+) supports it. |
| Region | `us-east1` (SC) or `us-east4` (N. Virginia) | N2 + Cascade Lake available; among the cheaper US regions. |
| Size | `n2-standard-16` (16 vCPU / 64 GB) — or `n2-standard-8` (8/32) to save | 4 syz VMs × 2 GB = 8 GB guest RAM, **KASAN roughly doubles the working set**, plus a parallel `make -j` kernel build. 64 GB is comfortable; 32 GB is the floor. |
| Disk | `pd-ssd` 150 GB (or Hyperdisk Balanced for tuned IOPS) | Kernel build ~25 GB + corpus/crashes + rootfs image. PD IOPS scale with size (~30/GB on pd-ssd); 150 GB ≈ 4.5k IOPS — enough for the build + corpus churn. |
| Cost lever | `--provisioning-model=SPOT` | Days-long campaigns: Spot is ~60-80% cheaper. Corpus/crashes live on the PD and survive a preemption; syz-manager resumes from `workdir`. Trade-off: it can be reclaimed mid-run. |

Rough on-demand cost (us-east1, changes over time — verify with `gcloud compute machine-types describe`): `n2-standard-16` ≈ $0.76/h, `n2-standard-8` ≈ $0.38/h. Spot is a fraction of that.

---

## 2. Create the VM

```bash
export PROJECT="$(gcloud config get-value project)"
export ZONE="us-east1-b"
export VM="kvm-fuzz-intel"

gcloud compute instances create "$VM" \
  --project="$PROJECT" \
  --zone="$ZONE" \
  --machine-type=n2-standard-16 \
  --min-cpu-platform="Intel Cascade Lake" \
  --enable-nested-virtualization \
  --image-family=debian-12 \
  --image-project=debian-cloud \
  --boot-disk-size=150GB \
  --boot-disk-type=pd-ssd \
  --metadata=enable-oslogin=TRUE \
  --provisioning-model=SPOT \
  --instance-termination-action=STOP
```

Drop `--provisioning-model/--instance-termination-action` for an on-demand (non-preemptible) VM. Keep `--no-address` off for now (you need egress to clone kernel/syzkaller); lock inbound down in §4 instead.

Verify nested virt once it's up:

```bash
gcloud compute ssh "$VM" --zone="$ZONE" --command='egrep -c "(vmx)" /proc/cpuinfo && ls -l /dev/kvm && lscpu | grep -i "model name"'
# expect: nonzero vmx count, /dev/kvm present, "... Cascade Lake" / "Xeon"
```

---

## 3. Provision (toolchain-parity build in a Debian 12 container)

Copy the provisioning script and the lab templates up, then run it:

```bash
gcloud compute scp --zone="$ZONE" \
  lab/provision-gcp.sh lab/build-kernel-kasan.sh lab/syzkaller-kvm-mmu.cfg \
  "$VM":~/ 
gcloud compute ssh "$VM" --zone="$ZONE" --command='chmod +x ~/provision-gcp.sh && ~/provision-gcp.sh'
```

`provision-gcp.sh` (see the file next to this one) does, on the host:
1. Installs host deps: `podman qemu-system-x86 qemu-utils debootstrap git golang openssh-client`.
2. Builds/fetches syzkaller (`GOTOOLCHAIN=auto`).
3. Creates the Debian bookworm rootfs image + ssh key via syzkaller's `tools/create-image.sh`.
4. Builds the **KASAN kernel inside a pinned `debian:12` Podman container** (toolchain parity), bind-mounting the source — the container runs `build-kernel-kasan.sh`.
5. Rewrites the paths in `syzkaller-kvm-mmu.cfg` to the VM's layout.

The kernel build runs in the container; **syzkaller runs on the host** (it needs `/dev/kvm`, which the container does not get).

---

## 4. Run — and do NOT expose the web UI

The config binds the manager UI to `127.0.0.1:56741`. **Never** open 56741 in a firewall
rule to `0.0.0.0/0` — it is an unauthenticated control panel. Reach it over an SSH tunnel:

```bash
# local terminal: forward the UI through SSH, then open http://localhost:56741
gcloud compute ssh "$VM" --zone="$ZONE" -- -N -L 56741:127.0.0.1:56741 &

# on the VM: launch the campaign (tmux so it survives disconnects)
gcloud compute ssh "$VM" --zone="$ZONE" --command='tmux new -d -s fuzz "cd ~/go/src/github.com/google/syzkaller && ./bin/syz-manager -config ~/syzkaller-kvm-mmu.cfg 2>&1 | tee ~/kvm-audit/lab/manager.log"'
```

A crash in `kvm_tdp_mmu_map`, `handle_changed_spte`, `tdp_mmu_set_spte_atomic`, or a KASAN
UAF in the memslot / mmu-notifier path = a hit on H1/H2. Triage the reproducer against the
invariants in `../AUDIT_KVM_v6.1.74.md`, then confirm it reproduces on the Cascade Lake
kvmCTF target before reporting.

## 5. Stop the meter

```bash
gcloud compute instances stop "$VM" --zone="$ZONE"    # keep the disk/corpus, stop billing compute
# or, when done for good:
gcloud compute instances delete "$VM" --zone="$ZONE"
```
