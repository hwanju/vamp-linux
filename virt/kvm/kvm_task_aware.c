#include <linux/sched.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/hash.h>
#include <trace/events/kvm.h>
#include <linux/kvm_task_aware.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <asm/apicdef.h>
#include "irq.h"
#include "ioapic.h"

int kvm_get_guest_task(struct kvm_vcpu *vcpu);
int kvm_set_slow_task(struct kvm *kvm);

#define set_guest_thread_state(guest_thread, state_value)     \
	set_mb(guest_thread->state, (state_value))

#define set_vcpu_state(vcpu, state_value)     \
	set_mb(vcpu->state, (state_value))

#define get_bg_vcpu_nice(vcpu)  \
	(sysctl_kvm_vamp <= 19 ? sysctl_kvm_vamp: \
	 vcpu->bg_exec_time * (sysctl_kvm_vamp - 19) / (vcpu->exec_time + 1))

#define KVM_TA_DEBUG

#ifdef KVM_TA_DEBUG
#define tadebug(args...) printk(KERN_DEBUG "kvm-ta debug: " args)
#else
#define tadebug(args...)
#endif

/* read-only: not updatable during runtime */
static unsigned int __read_mostly load_monitor_enabled = 1;
module_param(load_monitor_enabled, uint, S_IRUGO);      

/* virtual task that represents interrupt */
static struct guest_task_struct interrupt_virtual_task;
#define is_audio_task(gtask)	(gtask->audio_count > 10)	/*FIXME*/

/*
 * check_load_epoch() updates load_epoch_id and initializes 
 * cpu_loads[new_epoch_id], * when new load epoch begins at 
 * arrival time (entity would be vcpu or guest_thread).
 * NOTE: when cpu is idle, this check period could be 
 *       larger than epoch period. So, cpu_loads that are not 
 *       checked in the past have to be initialized! (See inner do-while loop)
 */
//static inline void check_load_epoch(struct kvm_vcpu *vcpu, 
void check_load_epoch(struct kvm_vcpu *vcpu, 
				struct guest_thread_info *guest_thread, 
				unsigned long long now)
{
	unsigned long long cur_load_epoch_id = load_epoch_id(now);

	/* following is for the first time a vcpu or guest thread firstly
	 * arrives, which means no departure (no accounting) hasn't happened.
	 * at the first arrival, load_epoch_id must be zero, so the difference
	 * from cur_load_epoch_id may be considerable. 
	 * To avoid excessive loop, load_epoch_id is set close to current one*/
	if (unlikely(cur_load_epoch_id - guest_thread->load_epoch_id >= 
				NR_LOAD_ENTRIES))
		guest_thread->load_epoch_id = 
			cur_load_epoch_id - NR_LOAD_ENTRIES + 1;
	if (unlikely(cur_load_epoch_id - vcpu->load_epoch_id >=
				NR_LOAD_ENTRIES))
		vcpu->load_epoch_id =
			cur_load_epoch_id - NR_LOAD_ENTRIES + 1;

	if (guest_thread->load_epoch_id < cur_load_epoch_id) {
		do {
			guest_thread->load_epoch_id++;
			guest_thread->cpu_loads[
				load_idx(guest_thread->load_epoch_id)] = 0;
		} while(guest_thread->load_epoch_id < cur_load_epoch_id);
	}
	if (unlikely(vcpu->load_epoch_id < cur_load_epoch_id)) {
		do {
			vcpu->load_epoch_id++;
			vcpu->cpu_loads[load_idx(vcpu->load_epoch_id)] = 0;
		} while(vcpu->load_epoch_id < cur_load_epoch_id);
	}
	/* At this time, invariant is vcpu->load_epoch_id == 
	 * guest_thread->load_epoch_id == cur_load_epoch_id */
}

/*
 * account_cpu_load() accounts cpu time for a guest thread and its vcpu 
 * as well when the guest thread is about to depart. 
 * Because the execution could span multiple epochs, 
 * this must correctly each part of execution time to a corresponding epoch.
 */
static inline void account_cpu_load(struct kvm_vcpu *vcpu, 
		struct guest_thread_info *guest_thread, 
		unsigned long long exec_time, unsigned long long now)
{
	unsigned long long i;
	unsigned long long cur_load_epoch_id = load_epoch_id(now);

	vcpu->exec_time += exec_time;
	if (likely(vcpu->cur_guest_task) && 
	    vcpu->cur_guest_task->flags & VF_BACKGROUND) 
		vcpu->bg_exec_time += exec_time;
	
	for (i = guest_thread->load_epoch_id; i < cur_load_epoch_id; i++) {
		unsigned long long account_time = LOAD_EPOCH_TIME_IN_NSEC;
		unsigned int idx = load_idx(i);

		if (i == guest_thread->load_epoch_id) { /* arrival epoch */
			account_time -= 
				load_epoch_offset(guest_thread->last_arrival);

			guest_thread->cpu_loads[idx] += account_time;
			vcpu->cpu_loads[idx] += account_time;
		}
		else {
			guest_thread->cpu_loads[idx] = account_time;
			vcpu->cpu_loads[idx] = account_time;
		}
		exec_time -= account_time;
	}
	/* current epoch is new, then initialize loads */
	if (guest_thread->load_epoch_id < cur_load_epoch_id) {  
		guest_thread->cpu_loads[load_idx(cur_load_epoch_id)] = 0;
		vcpu->cpu_loads[load_idx(cur_load_epoch_id)] = 0;
	}
	/* remaining exec time is accounted to the current load epoch */
	guest_thread->cpu_loads[load_idx(cur_load_epoch_id)] += exec_time;
	vcpu->cpu_loads[load_idx(cur_load_epoch_id)] += exec_time;

	guest_thread->load_epoch_id = cur_load_epoch_id;
	vcpu->load_epoch_id = cur_load_epoch_id;
	/* At this time, invariant is vcpu->load_epoch_id == 
	 * guest_thread->load_epoch_id == cur_load_epoch_id */
}

#define valid_vcpu_load(vcpu , timestamp)  \
	(vcpu->load_epoch_id >= load_epoch_id(timestamp) || \
	 vcpu->state == VCPU_RUNNING)

#define valid_gthread_load(gthread, timestamp)  \
	(gthread->load_epoch_id >= load_epoch_id(timestamp) || \
	 gthread->state == GUEST_THREAD_RUNNING)

static struct kmem_cache *guest_task_cache;
static __read_mostly struct preempt_ops acct_preempt_ops;

/* default load period */
#define DEFAULT_LOAD_PERIOD_MSEC	32      
/* maximum load period = 2^10 msec (about 1sec) */
#define MAX_LOAD_PERIOD_SHIFT	   10      
static unsigned int __read_mostly load_period_msec = DEFAULT_LOAD_PERIOD_MSEC;
module_param(load_period_msec, uint, S_IRUGO);    /* TODO: to be updatable */

unsigned int load_period_shift;

static inline struct guest_task_struct *alloc_guest_task(void)
{
	return kmem_cache_zalloc(guest_task_cache, GFP_ATOMIC);
}

static inline void free_guest_task(struct guest_task_struct *guest_task)
{
	kmem_cache_free(guest_task_cache, guest_task);
}

/*
 * Find guest task by id,
 * and should be called with holding guest_task_lock.
 */
static struct guest_task_struct *__find_guest_task(struct kvm *kvm, 
						unsigned long guest_task_id)
{
	struct guest_task_struct *iter_gtask, *guest_task = NULL;
	struct hlist_head *bucket;
	struct hlist_node *node;

	bucket = &kvm->guest_task_hash[hash_ptr((void *)guest_task_id, 
						GUEST_TASK_HASH_SHIFT)];
	hlist_for_each_entry(iter_gtask, node, bucket, link) {
		if (iter_gtask->id == guest_task_id) {  /* found */
			guest_task = iter_gtask;
			//tadebug("  %s: gtid=%08lx found\n", 
			//	      __func__, guest_task_id);
			break;
		}
	}
	return guest_task;
}

/*
 * Insert an allocated guest task into the hash table,
 * and should be called with holding guest_task_lock.
 */
static inline void __insert_to_guest_task_hash(struct kvm *kvm, 
					struct guest_task_struct *guest_task,
					unsigned long guest_task_id)
{
	struct hlist_head *bucket;

	bucket = &kvm->guest_task_hash[hash_ptr((void *)guest_task_id, 
						GUEST_TASK_HASH_SHIFT)];
	guest_task->id = guest_task_id;
	hlist_add_head(&guest_task->link, bucket);
}

/*
 * Find guest task by id and if not exist, allocate a new guest task.
 * This find & alloc is atomically done with the proctection of guest_task_lock.
 * The reason alloc function is protected is a task can have multiple threads.
 */
static struct guest_task_struct *find_and_alloc_guest_task(
				struct kvm *kvm, unsigned long guest_task_id) 
{
	struct guest_task_struct *guest_task;

	spin_lock(&kvm->guest_task_lock);
	guest_task = __find_guest_task(kvm, guest_task_id);
	if (!guest_task) {     /* not found */
		guest_task = alloc_guest_task();
		if (guest_task) 
			__insert_to_guest_task_hash(kvm, 
					guest_task, guest_task_id);
		//tadebug("  %s: gtid=%08lx (guest_task=%p) allocated\n", 
		//		      __func__, guest_task_id, guest_task);
	}
	spin_unlock(&kvm->guest_task_lock);
	return guest_task;
}

static inline struct guest_thread_info *get_cur_guest_thread(
						struct kvm_vcpu *vcpu)
{
	/* FIXME: possible race - should be handled with guest task deletion */
	if (unlikely(!vcpu->cur_guest_task))
		return NULL;
	return &vcpu->cur_guest_task->threads[vcpu->vcpu_id];
}

static inline unsigned long get_cur_guest_task_id(struct kvm_vcpu *vcpu)
{
	/* FIXME: possible race - should be handled with guest task deletion */
	if (unlikely(!vcpu->cur_guest_task))
		return 0;
	return vcpu->cur_guest_task->id;
}

/*
 * this function is called at hlt vmexit.
 * check the current gtask at hlt vmexit and if diverged, 
 * assume no system task in this vm.
 * e.g., Linux has an idle thread who doesn't need address space switching, 
 * whereas Windows has a separate system task
 */
#define is_system_task(kvm, gtask)   (kvm->system_task_id == gtask->id)
void check_on_hlt(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;

	/* cummulative run delay should be reset 
	 * since no longer cpu is needed */
	vcpu->prev_run_delay = vcpu->run_delay;

	/* if vcpu goes idle, prev task has no meaning of waker */
	vcpu->waker_guest_task = NULL;
	vcpu->remote_waker_guest_task = NULL;

	/* inspect whether the vm has a dedicated system task */
	if (!vcpu->cur_guest_task)
		return;

	if (kvm->system_task_id == 0)	   /* first set */
		kvm->system_task_id = vcpu->cur_guest_task->id;
	else if (kvm->system_task_id > 0 &&     /* if diverged */
		 kvm->system_task_id != vcpu->cur_guest_task->id)
		kvm->system_task_id = -1;       /* assume no system task */   
	trace_kvm_system_task(vcpu->vcpu_id, kvm->system_task_id, 
					vcpu->cur_guest_task->id);
}
EXPORT_SYMBOL_GPL(check_on_hlt);

static void init_load_monitor(void)
{
	int i;
	
	for (i = 1; i < MAX_LOAD_PERIOD_SHIFT; i++) {
		if ((1 << i) >= load_period_msec)
			break;
	}
	load_period_shift = i;
	load_period_msec  = LOAD_EPOCH_TIME_IN_MSEC;
	printk(KERN_INFO "kvm-ta: load period=%u ms (shift=%u)\n",
			LOAD_EPOCH_TIME_IN_MSEC, load_period_shift);
}

#define for_each_load_entry(i, _start_load_idx, _end_load_idx)      \
	for (i = _start_load_idx; i != _end_load_idx; i = load_idx(i + 1))
//#define get_ewma(_prev, _cur, _w)	((((_prev) * (10 - (_w)) + (_cur) * _w) + 5) / 10)
static unsigned int get_vcpu_load_avg(struct kvm_vcpu *vcpu, 
		unsigned int start_load_idx, unsigned int end_load_idx, 
		unsigned long long start_timestamp, int pre_monitor_period)
{
	int i, nr_epochs = 0;
	u64 cpu_load_avg = 0;
	unsigned int cur_load_idx = load_idx(vcpu->load_epoch_id);
	int running = vcpu->state == VCPU_RUNNING;
	int valid_load = vcpu->load_epoch_id >= load_epoch_id(start_timestamp);
	u64 load;

	for_each_load_entry(i, start_load_idx, end_load_idx) {
		if (valid_load) 
			load = vcpu->cpu_loads[i];
		else if (running)       /* if invalid, but running */
			/* add full epoch consumption not accounted yet */
			load = LOAD_EPOCH_TIME_IN_NSEC;
		else    /* invalid */
			load = 0;

		cpu_load_avg += load;
		nr_epochs++;
		trace_kvm_vcpu_load(vcpu->kvm->vm_id, vcpu->vcpu_id, 
				cur_load_idx, i, load);
		if (i == cur_load_idx)
			valid_load = 0;
	}

	/* fix pre_monitor_run_delay that might be 
	 * over-estimated by rough measurement */
	if (pre_monitor_period) {	
		/* currently, cpu_load_avg is total cpu
		 * idle time is the upper bound of wait time */
		u64 idle_time_ns = 
			(LOAD_EPOCH_TIME_IN_NSEC * nr_epochs) - cpu_load_avg;

		/* if roughly measured wait time is greater than idle time, 
		 * which is the upper bound, fix it */
		if (vcpu->pre_monitor_run_delay > idle_time_ns)
			vcpu->pre_monitor_run_delay = idle_time_ns;
	}

	cpu_load_avg = 
		(cpu_load_avg / nr_epochs) * 100 / LOAD_EPOCH_TIME_IN_NSEC;

	return (unsigned int)cpu_load_avg;
}

static inline unsigned long long get_potential_vcpu_load(
					struct kvm_vcpu *vcpu, 
					unsigned long long now, 
					int pre_monitor_period)
{
	/* consider wait time as potential load */
	if (pre_monitor_period)
		return (vcpu->pre_monitor_run_delay * 100) / 
			((NR_LOAD_ENTRIES-1) * LOAD_EPOCH_TIME_IN_NSEC);
	else 
		return (vcpu->cur_run_delay * 100) / 
			(now - vcpu->kvm->monitor_timestamp);
}

static unsigned int get_gthread_load_avg(struct kvm_vcpu *vcpu, 
			struct guest_task_struct *guest_task, 
			unsigned int start_load_idx, unsigned int end_load_idx,
			unsigned long long start_timestamp)
{
	struct guest_thread_info *guest_thread = 
		&guest_task->threads[vcpu->vcpu_id];
	int i, nr_epochs = 0;
	u64 cpu_load_avg = 0;
	unsigned int cur_load_idx = load_idx(guest_thread->load_epoch_id);
	int running = guest_thread->state == GUEST_THREAD_RUNNING;
	int valid_load = 
		guest_thread->load_epoch_id >= load_epoch_id(start_timestamp);
	u64 load;

	for_each_load_entry(i, start_load_idx, end_load_idx) {
		if (valid_load) 
			load = guest_thread->cpu_loads[i];
		else if (running)       /* if invalid, but running */
			/* add full epoch consumption not accounted yet */
			load = LOAD_EPOCH_TIME_IN_NSEC;
		else    /* invalid */
			load = 0;

		cpu_load_avg += load;
		nr_epochs++;
		trace_kvm_gthread_load(vcpu->kvm->vm_id, guest_task->id, 
				vcpu->vcpu_id, cur_load_idx, i, load);
		if (i == cur_load_idx)
			valid_load = 0;
	}
	return (cpu_load_avg / nr_epochs) * 100 / 
			LOAD_EPOCH_TIME_IN_NSEC;      /* in percentage (pct) */
}

static inline unsigned int get_potential_gthread_load(struct kvm_vcpu *vcpu, 
		struct guest_thread_info *guest_thread, 
		unsigned long long now, int pre_monitor_period)
{
	/* reflect run delay to gtask load in proportion to 
	 * gthread load of a vcpu. 
	 * potential load = run delay (%) x (thread load / vcpu load) */
	if (pre_monitor_period) 
		return (vcpu->pre_monitor_run_delay * guest_thread->cur_load_avg * 100) /
			(((NR_LOAD_ENTRIES-1) * LOAD_EPOCH_TIME_IN_NSEC) * (vcpu->cur_load_avg + 1));
	else
		return (vcpu->cur_run_delay * guest_thread->cur_load_avg * 100) / 
			((now - vcpu->kvm->monitor_timestamp) * (vcpu->cur_load_avg + 1));
}

#define DEFAULT_BG_LOAD_THRESH_PCT      60
static unsigned int bg_load_thresh_pct = DEFAULT_BG_LOAD_THRESH_PCT;
module_param(bg_load_thresh_pct, uint, 0644);

#define DEFAULT_MAX_INTERACTIVE_PHASE_MSEC      5000
static unsigned int max_interactive_phase_msec = 
					DEFAULT_MAX_INTERACTIVE_PHASE_MSEC;
module_param(max_interactive_phase_msec, uint, 0644);

#define DEFAULT_LOAD_MONITOR_WINDOW     30000000UL      /* 30ms */
static unsigned long load_monitor_window = DEFAULT_LOAD_MONITOR_WINDOW;
module_param(load_monitor_window, ulong, 0644);

static int load_prof_enabled = 0;
module_param(load_prof_enabled, int, 0644);

#define DEFAULT_LOAD_PROF_PERIOD_MSEC   120
static unsigned int load_prof_period_msec = DEFAULT_LOAD_PROF_PERIOD_MSEC;
module_param(load_prof_period_msec, uint, 0644);

/* main wrapper for adjusting vcpu's shares */
static void update_vcpu_shares(struct kvm_vcpu *vcpu, 
					struct task_struct *task)
{
	int bg_nice = get_bg_vcpu_nice(vcpu);

	if (unlikely(!vcpu->cur_guest_task))
		return;
	if (vcpu->cur_guest_task->flags & VF_BACKGROUND)
		trace_kvm_bg_vcpu(vcpu, bg_nice);
	adjust_vcpu_shares(task, vcpu->cur_guest_task->flags, bg_nice);
}

/* 
 * calculate cpu loads during pre-monitoring period 
 * that is prior to a user event.
 * now: the time (in ns) when a user input occurs
 * pre_monitor_duration: the duration (in ns) kept as previous load history 
 */
static void check_pre_monitor_period(struct kvm *kvm, unsigned long long now, 
		unsigned long long pre_monitor_duration)
{
	struct kvm_vcpu *vcpu = NULL;
	int vidx, bidx;
	/* an epoch after now is the beginning point of pre-monitoring period */
	unsigned int prev_start_load_idx = load_idx(load_epoch_id(now) + 1);
	unsigned int prev_end_load_idx = load_idx_by_time(now);
	/* timestamp of the beginning point of pre-monitoring period */
	unsigned long long pre_monitor_timestamp = now - pre_monitor_duration;
	unsigned int vm_load = 0;       /* for debugging */

	/* for paravirt */
	struct kvm_slow_task_info *sti = &kvm->arch.sti.stask_info;

	trace_kvm_load_check_entry(kvm->vm_id, NR_LOAD_ENTRIES, 
			load_period_msec, pre_monitor_timestamp, now);

	/* scan vcpu loads for pre-monitoring period */
	kvm->pre_monitor_load = 0;
	kvm_for_each_vcpu(vidx, vcpu, kvm) {
		/* reset previous run delay */
		vcpu->prev_run_delay = vcpu->run_delay; 

		if (!valid_vcpu_load(vcpu, pre_monitor_timestamp))
			continue;
		vcpu->cur_load_avg = 
			get_vcpu_load_avg(vcpu, prev_start_load_idx, 
				prev_end_load_idx, pre_monitor_timestamp, 1);
		/* accumulate effective vm load */
		kvm->pre_monitor_load += vcpu->cur_load_avg + 
					 get_potential_vcpu_load(vcpu, now, 1);
		vm_load += vcpu->cur_load_avg;  /* for debuggig */

		trace_kvm_vcpu_stat(kvm->vm_id, vcpu, 
				vcpu->pre_monitor_run_delay);
	}
	/* after scanning vcpu loads, make a decision 
	 * whether tasks are mixed (slow) or not (fast) */
	if (kvm->pre_monitor_load > bg_load_thresh_pct)	/* slow path */
		kvm->interactive_phase = MIXED_INTERACTIVE_PHASE;
	else	/* fast path */
		kvm->interactive_phase = NON_MIXED_INTERACTIVE_PHASE;

	/* scan gtask loads for pre-monitoring period */
	spin_lock(&kvm->guest_task_lock);
	sti->nr_tasks = 0;
	for (bidx = 0; bidx < GUEST_TASK_HASH_HEADS; bidx++) {
		struct guest_task_struct *iter_gtask;
		struct hlist_node *node;
		hlist_for_each_entry(iter_gtask, node, 
				&kvm->guest_task_hash[bidx], link) {
			int vcpu_id;
			int valid_load_task = 0;

			/* scan gthread load for each vcpu for 
			 * pre-monitoring period */
			iter_gtask->pre_monitor_load = 0;
			for (vcpu_id = 0; 
			     vcpu_id < MAX_GUEST_TASK_VCPU; vcpu_id++) {
				struct guest_thread_info *guest_thread = 
					&iter_gtask->threads[vcpu_id];
				struct kvm_vcpu *vcpu = kvm->vcpus[vcpu_id];

				/* we are interested in threads that have been 
				 * scheduled since load timer started */
				if (!vcpu || 
				    !valid_gthread_load(guest_thread, 
							pre_monitor_timestamp))
					continue;

				guest_thread->cur_load_avg = 
					get_gthread_load_avg(vcpu, 
							iter_gtask, 
							prev_start_load_idx, 
							prev_end_load_idx, 
							pre_monitor_timestamp);
				/* accumulate effective gtask load */
				iter_gtask->pre_monitor_load += 
					guest_thread->cur_load_avg + 
					get_potential_gthread_load(vcpu, 
							guest_thread, now, 1);
				valid_load_task = 1;
			}
			/* update gtask flags for background tasks */
			iter_gtask->flags = 0;
			if (kvm->interactive_phase == MIXED_INTERACTIVE_PHASE &&
			    iter_gtask->pre_monitor_load > 
							bg_load_thresh_pct &&
			    !is_system_task(kvm, iter_gtask) &&
			    !is_audio_task(iter_gtask)) {
				iter_gtask->flags |= VF_BACKGROUND;

				if (sti->nr_tasks < KVM_MAX_SLOW_TASKS) {
					sti->tasks[sti->nr_tasks].task_id = 
						iter_gtask->para_id;
					sti->tasks[sti->nr_tasks].load_pct =
						iter_gtask->pre_monitor_load;
					sti->nr_tasks++;
				}
			}
			
			if (valid_load_task)
				trace_kvm_gtask_stat(kvm, iter_gtask, 
						bg_load_thresh_pct,
						iter_gtask->pre_monitor_load);
		}
	}
	set_bit(KVM_REQ_SLOW_TASK, &kvm->requests);
	spin_unlock(&kvm->guest_task_lock);

	/* connect to scheduler core for notification of interactive phase */
	set_interactive_phase(&current->se, kvm->interactive_phase);

	/* promptly adjust vCPU shares if mixed workloads */
	if (kvm->interactive_phase == MIXED_INTERACTIVE_PHASE) {
		kvm_for_each_vcpu(vidx, vcpu, kvm) {
			struct task_struct *task = NULL;
			struct pid *pid;

			rcu_read_lock();
			pid = rcu_dereference(vcpu->pid);
			if (pid)
				task = get_pid_task(vcpu->pid, PIDTYPE_PID);
			rcu_read_unlock();
			if (!task || !vcpu->cur_guest_task)
				continue;

			update_vcpu_shares(vcpu, task);
			put_task_struct(task);
		}
	}
	trace_kvm_load_info(kvm, vm_load, kvm->pre_monitor_load, 0);
}

static void clear_gtask_flags(struct kvm *kvm)
{
	int bidx;
	spin_lock(&kvm->guest_task_lock);
	for (bidx = 0; bidx < GUEST_TASK_HASH_HEADS; bidx++) {
		struct guest_task_struct *iter_gtask;
		struct hlist_node *node;
		hlist_for_each_entry(iter_gtask, node, 
				&kvm->guest_task_hash[bidx], link)
			iter_gtask->flags = 0;
	}
	spin_unlock(&kvm->guest_task_lock);
}

static void finish_interactive_period(struct kvm *kvm)
{
	trace_kvm_load_check_exit(kvm->vm_id, 0, 0, 0, 0);
	kvm->interactive_phase = NORMAL_PHASE;
	clear_gtask_flags(kvm);

	kvm->arch.sti.stask_info.nr_tasks = 0;
	set_bit(KVM_REQ_SLOW_TASK, &kvm->requests);
}

#define in_interactive_phase(kvm, now)  \
	(now - kvm->user_input_timestamp < \
	 (max_interactive_phase_msec * NSEC_PER_MSEC))
static void load_timer_handler(unsigned long data)
{
	struct kvm *kvm = (struct kvm *)data;
	struct kvm_vcpu *vcpu = NULL;
	int vidx, bidx;
	unsigned long long now = sched_clock();

	unsigned int mon_start_load_idx = 
		load_idx_by_time(kvm->monitor_timestamp);
	/* excluding load idx of now */
	unsigned int mon_end_load_idx = load_idx_by_time(now);  

	unsigned int vm_load = 0;       /* for debugging */
	unsigned int eff_vm_load;
	unsigned int reactive_gtask_load;

	struct task_struct *task = NULL;
	struct pid *pid;

	BUG_ON(!kvm);

	if (!load_prof_enabled)
		goto finish_interactive_phase;

	trace_kvm_load_check_entry(kvm->vm_id, NR_LOAD_ENTRIES, 
			load_period_msec, kvm->monitor_timestamp, now);

	/* scan vcpu loads for monitoring period */
	eff_vm_load = 0;
	kvm_for_each_vcpu(vidx, vcpu, kvm) {
		vcpu->cur_run_delay = vcpu->run_delay - vcpu->prev_run_delay;
		/* reset previous run delay */
		vcpu->prev_run_delay = vcpu->run_delay; 

		/* we are interested in vcpus that have been scheduled 
		 * since load timer started */
		if (!valid_vcpu_load(vcpu, kvm->monitor_timestamp))
			continue;

		vcpu->cur_load_avg = get_vcpu_load_avg(vcpu, 
					mon_start_load_idx, mon_end_load_idx, 
					kvm->monitor_timestamp, 0);
		/* accumulate effective vm load */
		eff_vm_load += 
			vcpu->cur_load_avg + 
			get_potential_vcpu_load(vcpu, now, 0);
		vm_load += vcpu->cur_load_avg;  /* for debugging */

		trace_kvm_vcpu_stat(kvm->vm_id, vcpu, 
				vcpu->cur_run_delay);
	}

	/* scan gtask loads for monitoring period 
	 * Note that this scanning is required for only slow path, 
	 * but scanning always for analysis */
	reactive_gtask_load = 0;
	spin_lock(&kvm->guest_task_lock);
	for (bidx = 0; bidx < GUEST_TASK_HASH_HEADS; bidx++) {
		struct guest_task_struct *iter_gtask;
		struct hlist_node *node;
		hlist_for_each_entry(iter_gtask, node, 
				&kvm->guest_task_hash[bidx], link) {
			int vcpu_id;
			int valid_load_task = 0;
			unsigned int eff_gtask_load = 0;
			for (vcpu_id = 0; 
			     vcpu_id < MAX_GUEST_TASK_VCPU; vcpu_id++) {
				struct guest_thread_info *guest_thread = 
					&iter_gtask->threads[vcpu_id];
				struct kvm_vcpu *vcpu = kvm->vcpus[vcpu_id];
				/* we are interested in threads that have been 
				 * scheduled since load timer started */
				if (!vcpu || 
				    !valid_gthread_load(guest_thread, 
					    kvm->monitor_timestamp))
					continue;

				guest_thread->cur_load_avg = 
					get_gthread_load_avg(vcpu, 
						iter_gtask, 
						mon_start_load_idx, 
						mon_end_load_idx, 
						kvm->monitor_timestamp);
				/* accumulate effective gtask load */
				eff_gtask_load += 
					guest_thread->cur_load_avg + 
					get_potential_gthread_load(vcpu, 
							guest_thread, now, 0);
				valid_load_task = 1;
			}
			/* slow path & non-background task */
			if (kvm->interactive_phase == MIXED_INTERACTIVE_PHASE &&
			    !(iter_gtask->flags & VF_BACKGROUND)) {
				iter_gtask->flags = 0;
				 /* load increase by a user input */
				if (eff_gtask_load > 
				    iter_gtask->pre_monitor_load)
					reactive_gtask_load += (eff_gtask_load -
						iter_gtask->pre_monitor_load);
			}
			if (valid_load_task)
				trace_kvm_gtask_stat(kvm, iter_gtask,
							bg_load_thresh_pct,
							eff_gtask_load);
		}
	}
	spin_unlock(&kvm->guest_task_lock);
	trace_kvm_load_info(kvm, vm_load, eff_vm_load, reactive_gtask_load);

	/* determine whether interactive phase continues or not */
	if (load_prof_enabled && in_interactive_phase(kvm, now)) {
		kvm->monitor_timestamp = now;
		mod_timer(&kvm->load_timer, 
			  jiffies + msecs_to_jiffies(load_prof_period_msec));
		return;
	}

finish_interactive_phase:
	finish_interactive_period(kvm);

	/* connect to scheduler core for notification of 
	 * the end of interactive phase */
	rcu_read_lock();
	pid = rcu_dereference(kvm->vcpus[0]->pid);
	if (pid)
		task = get_pid_task(kvm->vcpus[0]->pid, PIDTYPE_PID);
	rcu_read_unlock();
	if (task) {
		set_interactive_phase(&task->se, NORMAL_PHASE);
		put_task_struct(task);
	}
}

static void guest_thread_arrive(struct kvm_vcpu *vcpu, 
				struct guest_thread_info *guest_thread, 
				unsigned long long now)
{
	kvm_get_guest_task(vcpu);
	vcpu->cur_guest_task->para_id = vcpu->arch.gt.gtask.task_id;
	
	guest_thread->cpu = vcpu->cpu;	/* FIXME: deprecated */
	guest_thread->last_arrival = now;
	check_load_epoch(vcpu, guest_thread, now);

	if (vcpu->kvm->interactive_phase == NORMAL_PHASE) {
		vcpu->cur_guest_task->flags = 0;
		vcpu->exec_time = vcpu->bg_exec_time = 0;
	}
	trace_kvm_gthread_switch_arrive(vcpu, 
			load_idx(guest_thread->load_epoch_id),
			guest_thread->cpu_loads[
				load_idx(guest_thread->load_epoch_id)],
			0);
	set_guest_thread_state(guest_thread, GUEST_THREAD_RUNNING);

	/* vcpu shadows the type of the currently running guest task */
	update_vcpu_shares(vcpu, current);
}

static void guest_thread_depart(struct kvm_vcpu *vcpu, 
		struct guest_thread_info *guest_thread, unsigned long long now)
{
	long long exec_time = 0;
	if (likely(guest_thread->last_arrival)) {
		exec_time = now - guest_thread->last_arrival;
		account_cpu_load(vcpu, guest_thread, exec_time, now);
	}
	guest_thread->last_depart = now;
	trace_kvm_gthread_switch_depart(vcpu, 
			load_idx(guest_thread->load_epoch_id),
			guest_thread->cpu_loads[
				load_idx(guest_thread->load_epoch_id)],
			exec_time);
	set_guest_thread_state(guest_thread, GUEST_THREAD_NOT_RUNNING);
}

/*
 * Tracking guest OS task switching,
 * called whenever a guest OS switches virtual address spaces (move-to-cr3)
 */
void track_guest_task(struct kvm_vcpu *vcpu, unsigned long guest_task_id) 
{
	struct guest_task_struct *guest_task;
	struct kvm *kvm = vcpu->kvm;
	struct guest_thread_info *prev, *next;
	unsigned long long now;

	if (!load_monitor_enabled)
		return;

	guest_task = find_and_alloc_guest_task(kvm, guest_task_id);
	if (!guest_task) {      /* not exist */
		printk(KERN_ERR "kvm-ta: error - find & alloc failed!\n");
		return;
	}
	now = sched_clock();
	/* FIXME: possible race - should be handled with guest task deletion */
	if (vcpu->cur_guest_task) {
		/* accounting for departing */
		prev = &vcpu->cur_guest_task->threads[vcpu->vcpu_id];
		guest_thread_depart(vcpu, prev, now);

		/* update (likely) waker guest task */
		if (vcpu->remote_waker_guest_task)
			vcpu->waker_guest_task = vcpu->remote_waker_guest_task;
		else if (vcpu->cur_guest_task != guest_task)
			vcpu->waker_guest_task = vcpu->cur_guest_task;

		/* check if bg->fg scheduling */
		if (vcpu->cur_guest_task->flags & VF_BACKGROUND &&
		    !(guest_task->flags & VF_BACKGROUND))
			current->se.statistics.nr_vcpu_bg2fg_switch++;
		current->se.statistics.nr_vcpu_task_switch++;
	}
	/* caching next guest thread as the current one */
	vcpu->cur_guest_task = guest_task;

	/* accounting for arriving */ 
	next = &guest_task->threads[vcpu->vcpu_id];
	guest_thread_arrive(vcpu, next, now);

	/* the reason yielding is carried out in track_guest_task() is
	 * we don't count the first gtask arrival right after vcpu arrival */
	if (vcpu->cur_guest_task->flags & VF_BACKGROUND)
		yield_from_boost(current);
}
EXPORT_SYMBOL_GPL(track_guest_task);

static inline struct kvm_vcpu *acct_preempt_notifier_to_vcpu(
					struct preempt_notifier *pn)
{
	return container_of(pn, struct kvm_vcpu, acct_preempt_notifier);
}

/*
 * always called when a vcpu arrives unlike kvm_preempt_notifer
 */
static void vcpu_arrive(struct preempt_notifier *pn, int cpu)
{
	struct kvm_vcpu *vcpu = acct_preempt_notifier_to_vcpu(pn);
	struct guest_thread_info *cur_guest_thread;
	unsigned long long now = sched_clock();

	if (test_and_clear_bit(KVM_REQ_SLOW_TASK, &vcpu->kvm->requests))
		kvm_set_slow_task(vcpu->kvm);

	/* run_delay (wait time) accounting */
	vcpu->run_delay = current->se.statistics.wait_sum;
	set_vcpu_state(vcpu, VCPU_RUNNING);

	/* recording for arrival */ 
	vcpu->last_arrival = now;
	cur_guest_thread = get_cur_guest_thread(vcpu);
	if (unlikely(!cur_guest_thread))
		return;
	trace_kvm_vcpu_switch_arrive(vcpu, current, vcpu->run_delay);
	guest_thread_arrive(vcpu, cur_guest_thread, now);
}

/*
 * always called when a vcpu departs unlike kvm_preempt_notifer
 */
static void vcpu_depart(struct preempt_notifier *pn, struct task_struct *next)
{
	struct kvm_vcpu *vcpu = acct_preempt_notifier_to_vcpu(pn);
	struct guest_thread_info *cur_guest_thread;
	unsigned long long now = sched_clock();

	/* vcpu state change for run_delay (wait time) accounting */
	if (likely(vcpu->state == VCPU_RUNNING) && !current->se.on_rq)
		set_vcpu_state(vcpu, VCPU_BLOCKED);     /* to be blocked */
	else
		set_vcpu_state(vcpu, VCPU_WAITING);     /* to wait */

	vcpu->last_depart = now;
	cur_guest_thread = get_cur_guest_thread(vcpu);
	if (unlikely(!cur_guest_thread))
		return;
	guest_thread_depart(vcpu, cur_guest_thread, now);
	trace_kvm_vcpu_switch_depart(vcpu, current, now - vcpu->last_arrival);

	while (vcpu->exec_time > load_monitor_window) {
		/* borrowed code from update_cfs_load */
		asm("" : "+rm" (vcpu->exec_time));
		vcpu->exec_time /= 2;
		vcpu->bg_exec_time /= 2;
	}
}

/*
 * called once a vcpu is created
 */
void init_task_aware_vcpu(struct kvm_vcpu *vcpu)
{
	if (!load_monitor_enabled)
		return;
	preempt_notifier_init(&vcpu->acct_preempt_notifier, &acct_preempt_ops);
	preempt_notifier_register(&vcpu->acct_preempt_notifier);
}
EXPORT_SYMBOL_GPL(init_task_aware_vcpu);

/*
 * called once a vcpu is destroyed
 */
void destroy_task_aware_vcpu(struct kvm_vcpu *vcpu)
{
	if (!load_monitor_enabled)
		return;
	preempt_notifier_unregister(&vcpu->acct_preempt_notifier);
}
EXPORT_SYMBOL_GPL(destroy_task_aware_vcpu);

/* by default: 500ms */
#define DOUBLE_CLICK_DELAY      (500 * NSEC_PER_MSEC)
void start_load_monitor(struct kvm *kvm, unsigned long long now)
{
	if (!load_monitor_enabled)
		return;
	
	if (!timer_pending(&kvm->load_timer) || 
	    (now - kvm->user_input_timestamp) > DOUBLE_CLICK_DELAY) {
		int vidx;
		struct kvm_vcpu *vcpu;
		unsigned long long pre_monitor_duration = 
			(LOAD_EPOCH_TIME_IN_NSEC * (NR_LOAD_ENTRIES - 1)) + 
							load_epoch_offset(now);
		unsigned long duration_jiffies =
			msecs_to_jiffies(load_prof_enabled ? 
				load_prof_period_msec : 
				max_interactive_phase_msec);

		del_timer_sync(&kvm->load_timer);
		if (kvm->interactive_phase)
			finish_interactive_period(kvm);

		kvm_for_each_vcpu(vidx, vcpu, kvm) {
			/* if last_arrival > t -> 
			 *   pre_monitor_run_delay = run_delay - prev_run_delay,
			 * else if vcpu is still waiting on rq 
			 *   pre_monitor_run_delay = pre_monitor_duration
			 * otherwize, 0
			 * where, t is the beginning of pre-monitoring duration
			 *	      (= now - first monitoring duration).
			 * Note that pre_monitor_run_delay might be 
			 * overestimated and finally fixed.
			 */
			if (vcpu->last_arrival > now - pre_monitor_duration)
				vcpu->pre_monitor_run_delay = 
					vcpu->run_delay - vcpu->prev_run_delay;
			else if (vcpu->state == VCPU_WAITING)
				vcpu->pre_monitor_run_delay = 
							pre_monitor_duration;
			else
				vcpu->pre_monitor_run_delay = 0;
		}
		kvm->user_input_timestamp = kvm->monitor_timestamp = now;
		check_pre_monitor_period(kvm, now, pre_monitor_duration);
		mod_timer(&kvm->load_timer, jiffies + duration_jiffies);
	}
}
EXPORT_SYMBOL_GPL(start_load_monitor);

void request_partial_boost(struct kvm_vcpu *src_vcpu, struct kvm_vcpu *vcpu)
{
	struct task_struct *task = NULL;
	struct pid *pid;

	if (!sysctl_kvm_partial_boost ||
	    vcpu->kvm->interactive_phase == NORMAL_PHASE)
		return;

	/* if source is NULL, unconditionally boosting */
	if (src_vcpu && 
	    (unlikely(!src_vcpu->cur_guest_task) ||
	    (src_vcpu->cur_guest_task->flags & VF_BACKGROUND &&
	    !current->se.boost_flag)))	/* return if bg && boost off */
		return;

	rcu_read_lock();
	pid = rcu_dereference(vcpu->pid);
	if (pid)
		task = get_pid_task(vcpu->pid, PIDTYPE_PID);
	rcu_read_unlock();

	if (!task)
		return;
	request_boost(task);
	put_task_struct(task);
}

#define KEYBOARD_LAPIC_VECTOR	0x31
#define AC97_LAPIC_VECTOR	0x3b	/* 0xb (irq) | 0x30 */
#define is_ac97_ioport(port)	(port >= 0xc800 && port <= 0xc8ff)
void check_lapic_irq(struct kvm_vcpu *src_vcpu, struct kvm_vcpu *vcpu,
						u32 vector, u32 ipi)
{
	if (ipi) {
		trace_kvm_ipi(src_vcpu, vcpu, vector);
		if (vector == RESCHEDULE_VECTOR) {
			if (src_vcpu->remote_waker_guest_task !=
			    &interrupt_virtual_task)
				vcpu->remote_waker_guest_task = 
					src_vcpu->cur_guest_task;
			else
				vcpu->remote_waker_guest_task = 
					&interrupt_virtual_task;

			request_partial_boost(src_vcpu, vcpu);
		}
	}
	else {	/* non-IPI: local APIC */
		vcpu->remote_waker_guest_task = &interrupt_virtual_task;

		if (vector == KEYBOARD_LAPIC_VECTOR)
			request_partial_boost(NULL, vcpu);
	}
}

/* VEC_POS & REG_POS are borrowed from arch/x86/kvm/lapic.c */
#define VEC_POS(v) ((v) & (32 - 1))
#define REG_POS(v) (((v) >> 5) << 4)
static inline int audio_interrupt_context(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	return test_bit(VEC_POS(AC97_LAPIC_VECTOR), 
		(apic->regs + APIC_ISR) + REG_POS(AC97_LAPIC_VECTOR));
}
void check_audio_access(struct kvm_vcpu *vcpu)
{
	struct guest_task_struct *audio_task;
	struct guest_task_struct *waker_task;
	unsigned long long now;
	//int min_idx = 0, min_counter = INT_MAX;
	//int i, hit = 0;

	if (!is_ac97_ioport(vcpu->arch.pio.port) ||
	    audio_interrupt_context(vcpu))
		return;

	trace_kvm_audio_access(vcpu, 0);

	now = sched_clock();
	if (vcpu->kvm->interactive_phase == NORMAL_PHASE)
		start_load_monitor(vcpu->kvm, now);

	/* update stat for waker task of audio-generating task */
	audio_task = vcpu->cur_guest_task;
	waker_task = vcpu->waker_guest_task;
	if (unlikely(!audio_task || !waker_task) ||
	    waker_task == &interrupt_virtual_task)
		return;

	audio_task->audio_count = 100;	/*FIXME*/
	waker_task->audio_count++;
#if 0

	/* decide hit or miss */
	for (i = 0; i < MAX_WAKER_TASKS; i++) {
		if (audio_task->waker_tasks[i] == waker_task) {
			hit = 1;	/* nothing to do anymore */
			break;
		}
		if (!audio_task->waker_tasks[i]) {	/* empty slot */
			min_idx = i;		/* put on the slot if missed */
			min_counter = 0;	/* do not update further */
		}
		else if (audio_task->waker_tasks[i]->audio_count < 
								min_counter) {
			min_idx = i;
			min_counter = audio_task->waker_tasks[i]->audio_count;
		}
	}
	if (!hit) {	/* if missed, evict and place the current waker */
		if (audio_task->waker_tasks[min_idx])	/* evict */
			audio_task->waker_tasks[min_idx]->audio_count = 0;
		audio_task->waker_tasks[min_idx] = waker_task;
	}
	trace_kvm_audio_access(vcpu, hit + 1);
#endif
}

/*
 * Each VM maintains a hash table to store guest_task_struct 
 * for every task tracked, called from kvm_create_vm().
 */
void init_kvm_load_monitor(struct kvm *kvm)
{
	int i;
	if (!load_monitor_enabled)
		return;
	/* guest task hash */
	for (i = 0; i < GUEST_TASK_HASH_HEADS; i++)
		INIT_HLIST_HEAD(&kvm->guest_task_hash[i]);
	spin_lock_init(&kvm->guest_task_lock);
	printk(KERN_INFO "kvm-ta: guest task hash initialized\n" );

	/* load monitor */
	init_timer(&kvm->load_timer);
	kvm->load_timer.function = load_timer_handler;
	kvm->load_timer.data     = (unsigned long)kvm;

	/* for tracing purpose (caller must be QEMU that hosts this VM */
	kvm->vm_id = current->pid;
}
EXPORT_SYMBOL_GPL(init_kvm_load_monitor);

/*
 * Destroy guest task hash when a VM is destroyed.
 * called from kvm_destroy_vm().
 */
void exit_kvm_load_monitor(struct kvm *kvm)
{
	int i;
	struct hlist_node *node, *tmp;
	struct guest_task_struct *guest_task;

	if (!load_monitor_enabled)
		return;
	spin_lock(&kvm->guest_task_lock);
	for (i = 0; i < GUEST_TASK_HASH_HEADS; i++) {
		hlist_for_each_entry_safe(guest_task, 
				node, tmp, &kvm->guest_task_hash[i], link) {
			hlist_del(&guest_task->link);
			free_guest_task(guest_task);
		}
	}
	spin_unlock(&kvm->guest_task_lock);
	printk(KERN_INFO "kvm-ta: guest task hash freed\n" );

	del_timer_sync(&kvm->load_timer);
}
EXPORT_SYMBOL_GPL(exit_kvm_load_monitor);

/*
 * System-wide initialization for task-aware agent (called from kvm_init()).
 * - Initialize slab cache for guest_task_struct.
 */
int init_task_aware_agent(void)
{
	if (!load_monitor_enabled)
		return -1;

	BUG_ON(guest_task_cache);
	guest_task_cache = kmem_cache_create("guest_task_struct", 
					sizeof(struct guest_task_struct), 
					__alignof__(struct guest_task_struct),
					0, NULL);
	if (!guest_task_cache)
		return -ENOMEM;
	printk(KERN_INFO "kvm-ta: creating slab for guest_task_struct\n" );

	acct_preempt_ops.sched_in = vcpu_arrive;
	acct_preempt_ops.sched_out = vcpu_depart;

	init_load_monitor();

	return 0;
}
EXPORT_SYMBOL_GPL(init_task_aware_agent);

/*
 * Terminate task-aware agent (called from kvm_exit()).
 * - Destroy slab cache for guest_task_struct.
 */
void destroy_task_aware_agent(void)
{
	if (!load_monitor_enabled)
		return;

	kmem_cache_destroy(guest_task_cache);
	printk(KERN_INFO "kvm-ta: destroying slab for guest_task_struct\n" );
}
EXPORT_SYMBOL_GPL(destroy_task_aware_agent);
