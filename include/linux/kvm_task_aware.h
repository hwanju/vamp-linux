#ifndef __KVM_TASK_AWARE_H
#define __KVM_TASK_AWARE_H

#include <linux/kvm_host.h>

/* 
 * Guest task related
 */
#define MAX_GUEST_TASK_VCPU     8       /* FIXME: can have large value */

#define GUEST_THREAD_NOT_RUNNING	0
#define GUEST_THREAD_RUNNING	    2

/* 
 * Load tracking related
 */
extern unsigned int load_period_shift;
#define LOAD_EPOCH_TIME_IN_MSEC	 (1 << load_period_shift)
#define LOAD_EPOCH_TIME_IN_NSEC \
	(LOAD_EPOCH_TIME_IN_MSEC * NSEC_PER_MSEC)
#define load_idx(epoch_id)      \
	(unsigned int)((epoch_id) & (NR_LOAD_ENTRIES-1))
#define load_epoch_id(time_in_ns)       \
	((time_in_ns / NSEC_PER_MSEC) >> load_period_shift)
#define load_idx_by_time(time_in_ns)    (load_idx(load_epoch_id(time_in_ns)))
#define load_epoch_offset(time_in_ns)   (time_in_ns % LOAD_EPOCH_TIME_IN_NSEC)

#define LOAD_MONITOR_INPUT_BIT	  0

#define LOAD_MONITOR_PERIOID_EPOCH      (1<<(LOAD_ENTRIES_SHIFT-2))

/* VCPU states */
#define VCPU_BLOCKED    0
#define VCPU_WAITING    1 
#define VCPU_RUNNING    2

/* OS-aware */
#define has_system_task(kvm)    \
	(kvm->system_task_id != 0 && kvm->system_task_id != -1)
#define is_windows_os(kvm)	      has_system_task(kvm) /*FIXME: Linux */
#define is_unix_os(kvm)		 (!is_windows_os(kvm))
#define is_sync_ipi(kvm, vector)	(is_windows_os(kvm) && vector == 0xe1)
#define is_resched_ipi(kvm, vector)     (is_unix_os(kvm) && vector == 0xfd)

struct guest_thread_info {
	volatile long state;	    /* 0 = not running, 2 = running */
	int cpu;			/* physical cpu id hosting this vcpu */
	unsigned long long last_depart; /* for garbage collection */ 
	
	/* 
	 * load-related fields, see the comment of the same fields in kvm_vcpu 
	 */ 
	unsigned long long last_arrival;
	unsigned long long load_epoch_id;       
	unsigned long long cpu_loads[NR_LOAD_ENTRIES];
	unsigned long long cur_load_avg;
};

struct guest_task_struct {
	struct hlist_node link;
	unsigned long id;	/* host-side id (i.e. cr3) */
	int para_id;		/* guest-side id (i.e. tgid) by paravirt */
	/* aggregate guest thread load (in pct) 
	 * during pre-monitoring period */
	unsigned int pre_monitor_load;
	unsigned int flags;
	struct guest_thread_info threads[MAX_GUEST_TASK_VCPU];
};

void init_kvm_load_monitor(struct kvm *kvm);
void exit_kvm_load_monitor(struct kvm *kvm);
void start_load_monitor(struct kvm *kvm, unsigned long long now);
void init_task_aware_vcpu(struct kvm_vcpu *vcpu);
void destroy_task_aware_vcpu(struct kvm_vcpu *vcpu);
int init_task_aware_agent(void);
void destroy_task_aware_agent(void);
void track_guest_task(struct kvm_vcpu *vcpu, unsigned long guest_task_id);
void check_on_hlt(struct kvm_vcpu *vcpu);
#endif
