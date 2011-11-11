#ifndef __KVM_TASK_AWARE_H
#define __KVM_TASK_AWARE_H

#include <linux/kvm_host.h>

/* 
 * Guest task related
 */
#define MAX_GUEST_TASK_VCPU     8       /* FIXME: can have large value */

#define GUEST_THREAD_NOT_RUNNING        0
#define GUEST_THREAD_RUNNING            1

/* 
 * Load tracking related
 */
extern unsigned int load_period_shift;
#define LOAD_EPOCH_TIME_IN_MSEC         (1 << load_period_shift)
#define LOAD_EPOCH_TIME_IN_NSEC         (LOAD_EPOCH_TIME_IN_MSEC * NSEC_PER_MSEC)
#define load_idx(epoch_id)              (unsigned int)((epoch_id) & (NR_LOAD_ENTRIES-1))
#define load_epoch_id(time_in_ns)       ((time_in_ns / NSEC_PER_MSEC) >> load_period_shift)    /* TODO: find a convert function */
#define load_idx_by_time(time_in_ns)    (load_idx(load_epoch_id(time_in_ns)))
#define load_epoch_offset(time_in_ns)   (time_in_ns % LOAD_EPOCH_TIME_IN_NSEC)

#define LOAD_MONITOR_INPUT_BIT          0

#define LOAD_MONITOR_PERIOID_EPOCH      (1<<(LOAD_ENTRIES_SHIFT-2))

/* VCPU states */
#define VCPU_BLOCKED    0
#define VCPU_WAITING    1 
#define VCPU_RUNNING    2

/* VCPU flags */
#define VF_INTERACTIVE          0x00000001                      /* I have interactive workloads */
#define VF_BACKGROUND           0x00000002                      /* I have background workloads */
#define VF_INTERACTIVE_ON_RQ    (VF_INTERACTIVE | 0x100)        /* I'm on runq as an interactive vcpu (only for se's vcpu_flags) */

struct guest_thread_info {
        volatile long state;            /* 0 = not running, 1 = running */
        int cpu;                        /* physical cpu id hosting this vcpu */
        unsigned long long last_depart; /* for garbage collection */ 
        
        /* 
         * load-related fields, see the comment of the same fields in kvm_vcpu 
         */ 
        unsigned long long last_arrival;
        unsigned long long load_epoch_id;       
        unsigned long long cpu_loads[NR_LOAD_ENTRIES];
        unsigned int prev_cpu_load_avg;
};

struct guest_task_struct {
        struct hlist_node link;
        unsigned long id;
	unsigned int flags;
        struct guest_thread_info threads[MAX_GUEST_TASK_VCPU];
};

void init_kvm_load_monitor(struct kvm *kvm);
void exit_kvm_load_monitor(struct kvm *kvm);
void start_load_monitor(struct kvm *kvm, unsigned long long now, unsigned int duration_in_msec);
void init_task_aware_vcpu(struct kvm_vcpu *vcpu);
void destroy_task_aware_vcpu(struct kvm_vcpu *vcpu);
int init_task_aware_agent(void);
void destroy_task_aware_agent(void);
void track_guest_task(struct kvm_vcpu *vcpu, unsigned long guest_task_id);
#endif
