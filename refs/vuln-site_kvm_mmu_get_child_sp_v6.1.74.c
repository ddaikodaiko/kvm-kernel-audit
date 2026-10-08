// arch/x86/kvm/mmu/mmu.c @ v6.1.74 — lines 2250-2259

static struct kvm_mmu_page *kvm_mmu_get_child_sp(struct kvm_vcpu *vcpu,
						 u64 *sptep, gfn_t gfn,
						 bool direct, unsigned int access)
{
	union kvm_mmu_page_role role;

	if (is_shadow_present_pte(*sptep) && !is_large_pte(*sptep))
		return ERR_PTR(-EEXIST);

	role = kvm_mmu_child_role(sptep, direct, access);
