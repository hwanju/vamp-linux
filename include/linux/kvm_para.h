#ifndef __LINUX_KVM_PARA_H
#define __LINUX_KVM_PARA_H

/*
 * This header file provides a method for making a hypercall to the host
 * Architectures should define:
 * - kvm_hypercall0, kvm_hypercall1...
 * - kvm_arch_para_features
 * - kvm_para_available
 */

/* Return values for hypercalls */
#define KVM_ENOSYS		1000
#define KVM_EFAULT		EFAULT
#define KVM_E2BIG		E2BIG
#define KVM_EPERM		EPERM

#define KVM_HC_VAPIC_POLL_IRQ		1
#define KVM_HC_MMU_OP			2
#define KVM_HC_FEATURES			3
#define KVM_HC_PPC_MAP_MAGIC_PAGE	4

/*
 * hypercalls use architecture specific
 */
#include <asm/kvm_para.h>

#ifdef __KERNEL__

static inline int kvm_para_has_feature(unsigned int feature)
{
	if (kvm_arch_para_features() & (1UL << feature))
		return 1;
	return 0;
}

#ifdef CONFIG_KVM_VDI	/* guest-side */
DECLARE_PER_CPU(struct kvm_guest_task, guest_task);
static inline void kvm_para_set_task(int tgid, char *comm, unsigned long pgd)
{
	__get_cpu_var(guest_task).task_id = tgid;
	memcpy(&__get_cpu_var(guest_task).task_name, comm, 16);
	__get_cpu_var(guest_task).as_root = pgd;
}
static inline void kvm_para_set_taskname(char *comm)
{
	memcpy(&__get_cpu_var(guest_task).task_name, comm, 16);
}
static inline void kvm_para_set_debug(int idx, u32 val)
{
	if (idx >= 0 && idx < 5)
		__get_cpu_var(guest_task).debug[idx] = val;
}
static inline void kvm_para_set_debug64(int idx, u64 val)
{
	if (idx >= 0 && idx < 2)
		__get_cpu_var(guest_task).debug64[idx] = val;
}
#endif
#endif /* __KERNEL__ */
#endif /* __LINUX_KVM_PARA_H */

