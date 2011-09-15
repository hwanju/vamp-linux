#include <linux/sched.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/hash.h>
#include <trace/events/kvm.h>
#include <linux/kvm_task_aware.h>
#include <linux/timer.h>

/* FIXME: mb must be required? */
#define set_guest_thread_state(guest_thread, state_value)     \
        set_mb(guest_thread->state, (state_value))

#define set_vcpu_state(vcpu, state_value)     \
        set_mb(vcpu->state, (state_value))

#define KVM_TA_DEBUG

#ifdef KVM_TA_DEBUG
#define tadebug(args...) printk(KERN_DEBUG "kvm-ta debug: " args)
#else
#define tadebug(args...)
#endif

/*
 * check_load_epoch() updates load_epoch_id and initializes cpu_loads[new_epoch_id],
 * when new load epoch begins at arrival time (entity would be vcpu or guest_thread).
 * NOTE: when cpu is idle, this check period could be larger than epoch period.
 *       So, cpu_loads that are not checked in the past have to be initialized! (See inner do-while loop)
 */
static inline void check_load_epoch(struct kvm_vcpu *vcpu, struct guest_thread_info *guest_thread, 
                                    unsigned long long now)
{
        unsigned long long cur_load_epoch_id = load_epoch_id(now);
        if (guest_thread->load_epoch_id < cur_load_epoch_id) {
                do {
                        guest_thread->load_epoch_id++;
                        guest_thread->cpu_loads[load_idx(guest_thread->load_epoch_id)] = 0;
                } while(guest_thread->load_epoch_id < cur_load_epoch_id);
        }
        if (unlikely(vcpu->load_epoch_id < cur_load_epoch_id)) {
                do {
                        vcpu->load_epoch_id++;
                        vcpu->cpu_loads[load_idx(vcpu->load_epoch_id)] = 0;
                } while(vcpu->load_epoch_id < cur_load_epoch_id);
        }
        /* At this time, invariant is vcpu->load_epoch_id == guest_thread->load_epoch_id == cur_load_epoch_id */
}

/*
 * account_cpu_load() accounts cpu time for a guest thread and its vcpu as well when the guest thread is
 * about to depart. Because the execution could span multiple epochs, this must correctly each part of
 * execution time to a corresponding epoch.
 */
static inline void account_cpu_load(struct kvm_vcpu *vcpu, struct guest_thread_info *guest_thread, 
                                    unsigned long long exec_time, unsigned long long now)
{
        unsigned long long i;
        unsigned long long cur_load_epoch_id = load_epoch_id(now);
        
        for (i = guest_thread->load_epoch_id; i < cur_load_epoch_id; i++) {
                unsigned long long account_time = LOAD_EPOCH_TIME_IN_NSEC;
                unsigned int idx = load_idx(i);

                if (i == guest_thread->load_epoch_id) {         /* arrival epoch */
                        account_time -= load_epoch_offset(guest_thread->last_arrival);

                        guest_thread->cpu_loads[idx] += account_time;
                        vcpu->cpu_loads[idx] += account_time;
                }
                else {
                        guest_thread->cpu_loads[idx] = account_time;
                        vcpu->cpu_loads[idx] = account_time;
                }
                exec_time -= account_time;
        }
        if (guest_thread->load_epoch_id < cur_load_epoch_id) {  /* current epoch is new, then initialize loads */
                guest_thread->cpu_loads[load_idx(cur_load_epoch_id)] = 0;
                vcpu->cpu_loads[load_idx(cur_load_epoch_id)] = 0;
        }
        /* remaining exec time is accounted to the current load epoch */
        guest_thread->cpu_loads[load_idx(cur_load_epoch_id)] += exec_time;
        vcpu->cpu_loads[load_idx(cur_load_epoch_id)] += exec_time;

        guest_thread->load_epoch_id = cur_load_epoch_id;
        vcpu->load_epoch_id = cur_load_epoch_id;
        /* At this time, invariant is vcpu->load_epoch_id == guest_thread->load_epoch_id == cur_load_epoch_id */
}

#define valid_load_entity(kvm, entity)  \
        (entity->load_epoch_id >= load_epoch_id(kvm->monitor_timestamp))

static struct kmem_cache *guest_task_cache;
static __read_mostly struct preempt_ops acct_preempt_ops;

#define DEFAULT_LOAD_PERIOD_MSEC        32      /* default load period */
#define MAX_LOAD_PERIOD_SHIFT           10      /* maximum load period = 2^10 msec (about 1sec) */
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
static inline struct guest_task_struct *__find_guest_task(struct kvm *kvm, 
                                                          unsigned long guest_task_id) 
{
        struct guest_task_struct *iter_guest_task, *guest_task = NULL;
        struct hlist_head *bucket;
        struct hlist_node *node;

        bucket = &kvm->guest_task_hash[hash_ptr((void *)guest_task_id, GUEST_TASK_HASH_SHIFT)];
        hlist_for_each_entry(iter_guest_task, node, bucket, link) {
                if (iter_guest_task->id == guest_task_id) {  /* found */
                        guest_task = iter_guest_task;
                        //tadebug("  %s: gtid=%08lx found\n", __func__, guest_task_id);
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

        bucket = &kvm->guest_task_hash[hash_ptr((void *)guest_task_id, GUEST_TASK_HASH_SHIFT)];
        guest_task->id = guest_task_id;
        hlist_add_head(&guest_task->link, bucket);
}

/*
 * Find guest task by id and if not exist, allocate a new guest task.
 * This find & alloc are atomically done with the proctection of guest_task_lock.
 * The reason alloc function is protected also is a guest task can have multiple threads.
 */
static inline struct guest_task_struct *find_and_alloc_guest_task(struct kvm *kvm, 
                                                                  unsigned long guest_task_id) 
{
        struct guest_task_struct *guest_task;

        spin_lock(&kvm->guest_task_lock);
        guest_task = __find_guest_task(kvm, guest_task_id);
        if (!guest_task) {     /* not found */
                guest_task = alloc_guest_task();
                if (guest_task) 
                        __insert_to_guest_task_hash(kvm, guest_task, guest_task_id);
                //tadebug("  %s: gtid=%08lx (guest_task=%p) allocated\n", __func__, guest_task_id, guest_task);
        }
        spin_unlock(&kvm->guest_task_lock);
        return guest_task;
}

static inline struct guest_thread_info *get_cur_guest_thread(struct kvm_vcpu *vcpu)
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

static inline void init_load_monitor(void)
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

static void load_timer_handler(unsigned long data)
{
        struct kvm *kvm = (struct kvm *)data;
        struct kvm_vcpu *vcpu;
        int i, vidx, bidx;
        unsigned long long now = sched_clock();
        unsigned long long run_delay;
        unsigned int start_load_idx = kvm->monitor_seqnum == 0 ? /* first */
                load_idx(load_epoch_id(now) + 1) : load_idx_by_time(kvm->monitor_timestamp);

        BUG_ON(!kvm);

#if 0   /* VLP disabled */
        spin_lock(&kvm->vlp_lock);
        trace_kvm_vlp_avg(kvm->vm_id, kvm->vlp_avg, kvm->vlp_period);
        spin_unlock(&kvm->vlp_lock);
#endif

        trace_kvm_load_check_entry(kvm->vm_id, NR_LOAD_ENTRIES, load_period_msec, kvm->monitor_timestamp, now);

#define for_each_load_entry(i, _start_load_idx, _curr_load_idx)      \
        for (i = _start_load_idx; i != _curr_load_idx; i = load_idx(i + 1))

        /* check vcpu load history */
        kvm_for_each_vcpu(vidx, vcpu, kvm) {
                run_delay = vcpu->prev_run_delay;
                vcpu->prev_run_delay = vcpu->run_delay;

                /* we are interested in vcpus that have been scheduled since load timer started */
                if (!valid_load_entity(kvm, vcpu))
                        continue;

                for_each_load_entry(i, start_load_idx, load_idx_by_time(now))
                        trace_kvm_vcpu_load(kvm->vm_id, vcpu->vcpu_id, 
                                        load_idx(vcpu->load_epoch_id), i, vcpu->cpu_loads[i]);
                run_delay = vcpu->run_delay - run_delay;
                trace_kvm_vcpu_run_delay(kvm->vm_id, vcpu->vcpu_id, run_delay);
        }

        /* check guest task load history */
        spin_lock(&kvm->guest_task_lock);
        for (bidx = 0; bidx < GUEST_TASK_HASH_HEADS; bidx++) {
                struct guest_task_struct *iter_guest_task;
                struct hlist_node *node;
                hlist_for_each_entry(iter_guest_task, node, &kvm->guest_task_hash[bidx], link) {
                        int vcpu_id;
                        for (vcpu_id = 0; vcpu_id < MAX_GUEST_TASK_VCPU; vcpu_id++) {
                                struct guest_thread_info *guest_thread = &iter_guest_task->threads[vcpu_id];
                                /* we are interested in threads that have been scheduled since load timer started */
                                if (!valid_load_entity(kvm, guest_thread))
                                        continue;
                                for_each_load_entry(i, start_load_idx, load_idx_by_time(now))
                                        trace_kvm_gthread_load(kvm->vm_id,
                                                        iter_guest_task->id, vcpu_id, 
                                                        load_idx(guest_thread->load_epoch_id), 
                                                        i, guest_thread->cpu_loads[i]);
                        }
                }
        }
        spin_unlock(&kvm->guest_task_lock);

        /* make a decision of vcpu placement policy */
        kvm_for_each_vcpu(vidx, vcpu, kvm) {
                /* FIXME: Test code */
                cpu_set(0, vcpu->cpus_to_run);
        }

        /****************TEST****************/
        kvm->monitor_seqnum++;
        if (kvm->monitor_seqnum < 20) {
                kvm->monitor_timestamp = now;
                mod_timer(&kvm->load_timer, jiffies + msecs_to_jiffies(240));
        }
        else {
                trace_kvm_load_check_exit(kvm->vm_id, 0, 0, 0, 0);
                kvm->monitor_seqnum = 0;
        }
        /************************************/
}

static inline void guest_thread_arrive(struct kvm_vcpu *vcpu, struct guest_thread_info *guest_thread, unsigned long long now)
{
        guest_thread->cpu = vcpu->cpu;
        guest_thread->last_arrival = now;
        check_load_epoch(vcpu, guest_thread, now);
        trace_kvm_gthread_switch_arrive(get_cur_guest_task_id(vcpu), 
                        vcpu->vcpu_id, load_idx(guest_thread->load_epoch_id),
                        guest_thread->cpu_loads[load_idx(guest_thread->load_epoch_id)]);
        set_guest_thread_state(guest_thread, GUEST_THREAD_RUNNING);
}

static inline void guest_thread_depart(struct kvm_vcpu *vcpu, struct guest_thread_info *guest_thread, unsigned long long now)
{
        long long exec_time;
        if (likely(guest_thread->last_arrival)) {
                exec_time = now - guest_thread->last_arrival;
                account_cpu_load(vcpu, guest_thread, exec_time, now);
        }
        guest_thread->last_depart = now;
        trace_kvm_gthread_switch_depart(get_cur_guest_task_id(vcpu), 
                        vcpu->vcpu_id, load_idx(guest_thread->load_epoch_id),
                        guest_thread->cpu_loads[load_idx(guest_thread->load_epoch_id)]);
        set_guest_thread_state(guest_thread, GUEST_THREAD_NOT_RUNNING);
}

/*
 * Tracking guest OS task switching. 
 * It is called whenever a guest OS switches virtual address spaces (move-to-cr3).
 */
void track_guest_task(struct kvm_vcpu *vcpu, unsigned long guest_task_id) 
{
        struct guest_task_struct *guest_task;
        struct kvm *kvm = vcpu->kvm;
        struct guest_thread_info *prev, *next;
        unsigned long long now;

        guest_task = find_and_alloc_guest_task(kvm, guest_task_id);
        if (!guest_task) {      /* not exist */
                printk(KERN_ERR "kvm-ta: error - guest_task_struct find & alloc failed!\n");
                return;
        }
        now = sched_clock();
        if (vcpu->cur_guest_task) {       /* FIXME: possible race - should be handled with guest task deletion */
                /* accounting for departing */
                prev = &vcpu->cur_guest_task->threads[vcpu->vcpu_id];             
                guest_thread_depart(vcpu, prev, now);
        }
        /* caching next guest thread as the current one */
        vcpu->cur_guest_task = guest_task;

        /* accounting for arriving */ 
        next = &guest_task->threads[vcpu->vcpu_id];
        guest_thread_arrive(vcpu, next, now);
}
EXPORT_SYMBOL_GPL(track_guest_task);

static inline struct kvm_vcpu *acct_preempt_notifier_to_vcpu(struct preempt_notifier *pn)
{
	return container_of(pn, struct kvm_vcpu, acct_preempt_notifier);
}

#if 0
static void start_vlp_monitor(struct kvm *kvm, unsigned long long now)
{
        spin_lock(&kvm->vlp_lock);
        kvm->vlp_avg = 0;
        kvm->vlp_period = 0;
        kvm->vlp_timestamp = now;
        spin_unlock(&kvm->vlp_lock);
}

static void account_vlp(struct kvm *kvm, unsigned long long now, int inc)
{
        u64 period = now - kvm->vlp_timestamp;
        
        /* account vlp only when vlp > 0 to exclude idle period */
        if (kvm->vlp > 0) {
                kvm->vlp_avg += (kvm->vlp * period);
                kvm->vlp_period += period;
        }

        /* adjust vlp */
        if (inc)
                kvm->vlp++;
        else if (likely(kvm->vlp > 0)) 
                kvm->vlp--;

        kvm->vlp_timestamp = now;

        trace_kvm_vlp(kvm->vm_id, kvm->vlp, kvm->vlp_avg, kvm->vlp_period);
}
#endif

/*
 * always called when a vcpu arrives unlike kvm_preempt_notifer
 */
static void vcpu_arrive(struct preempt_notifier *pn, int cpu)
{
	struct kvm_vcpu *vcpu = acct_preempt_notifier_to_vcpu(pn);
#if 0   /* VLP disabled */
        struct kvm *kvm = vcpu->kvm;
#endif
        struct guest_thread_info *cur_guest_thread;
        unsigned long long now = sched_clock();

        /* recording for arrival */ 
        vcpu->last_arrival = now;
        cur_guest_thread = get_cur_guest_thread(vcpu);
        if (unlikely(!cur_guest_thread))
                return;
        guest_thread_arrive(vcpu, cur_guest_thread, now);

        trace_kvm_vcpu_switch_arrive(vcpu->vcpu_id, load_idx(vcpu->load_epoch_id), 
                        vcpu->cpu_loads[load_idx(vcpu->load_epoch_id)], vcpu->state);

        if (vcpu->state == VCPU_WAITING)
                vcpu->run_delay += (now - vcpu->last_depart);
        set_vcpu_state(vcpu, VCPU_RUNNING);

#if 0   /* VLP disabled */
        /* vlp measure: check if this vcpu has been blocked */
        spin_lock(&kvm->vlp_lock);
        if (vcpu->state == VCPU_BLOCKED)
                account_vlp(kvm, now, 1);
        set_vcpu_state(vcpu, VCPU_RUNNING);
        spin_unlock(&kvm->vlp_lock);
#endif

#if 0
        /* vcpu migration if necessary */
        if (cpus_addr(vcpu->cpus_to_run)) {
                set_cpus_allowed_ptr(current, &vcpu->cpus_to_run);
                cpumask_clear(&vcpu->cpus_to_run);
        }
#endif
}

/*
 * always called when a vcpu departs unlike kvm_preempt_notifer
 */
static void vcpu_depart(struct preempt_notifier *pn, struct task_struct *next)
{
	struct kvm_vcpu *vcpu = acct_preempt_notifier_to_vcpu(pn);
#if 0   /* VLP disabled */
        struct kvm *kvm = vcpu->kvm;
#endif
        struct guest_thread_info *cur_guest_thread;
        unsigned long long now = sched_clock();

        vcpu->last_depart = now;
        cur_guest_thread = get_cur_guest_thread(vcpu);
        if (unlikely(!cur_guest_thread))
                return;
        guest_thread_depart(vcpu, cur_guest_thread, now);

        trace_kvm_vcpu_switch_depart(vcpu->vcpu_id, load_idx(vcpu->load_epoch_id), 
                        vcpu->cpu_loads[load_idx(vcpu->load_epoch_id)], vcpu->state);

        if (likely(vcpu->state == VCPU_RUNNING) && !current->se.on_rq)  /* to be blocked */
                set_vcpu_state(vcpu, VCPU_BLOCKED);
        else    /* to wait */
                set_vcpu_state(vcpu, VCPU_WAITING);

#if 0   /* VLP disabled */
        /* vlp measure: check if this vcpu will be blocked*/
        spin_lock(&kvm->vlp_lock);
        if (likely(vcpu->state == VCPU_RUNNING) && !current->se.on_rq) {       /* to be blocked */
                account_vlp(kvm, now, 0);
                set_vcpu_state(vcpu, VCPU_BLOCKED);
        }
        else    /* to wait */
                set_vcpu_state(vcpu, VCPU_WAITING);
        spin_unlock(&kvm->vlp_lock);
#endif
}

/*
 * called once a vcpu is created
 */
void init_task_aware_vcpu(struct kvm_vcpu *vcpu)
{
	preempt_notifier_init(&vcpu->acct_preempt_notifier, &acct_preempt_ops);
        preempt_notifier_register(&vcpu->acct_preempt_notifier);
}
EXPORT_SYMBOL_GPL(init_task_aware_vcpu);

/*
 * called once a vcpu is destroyed
 */
void destroy_task_aware_vcpu(struct kvm_vcpu *vcpu)
{
        preempt_notifier_unregister(&vcpu->acct_preempt_notifier);
}
EXPORT_SYMBOL_GPL(destroy_task_aware_vcpu);

void start_load_monitor(struct kvm *kvm, unsigned long long now, unsigned int duration_in_msec)
{
#if 0   /* VLP disabled */
        start_vlp_monitor(kvm, now);
#endif
        
        if (!timer_pending(&kvm->load_timer)) {
                int vidx;
                struct kvm_vcpu *vcpu;

                kvm_for_each_vcpu(vidx, vcpu, kvm)
                        vcpu->prev_run_delay = vcpu->run_delay;
                kvm->load_timer_start_time = now;
                kvm->monitor_timestamp = now;
                mod_timer(&kvm->load_timer, jiffies + msecs_to_jiffies(duration_in_msec));
        }
}
EXPORT_SYMBOL_GPL(start_load_monitor);

/*
 * Each VM maintains a hash table to store guest_task_struct for every task tracked.
 * called from kvm_create_vm().
 */
void init_kvm_load_monitor(struct kvm *kvm)
{
        int i;
        /* guest task hash */
        for (i = 0; i < GUEST_TASK_HASH_HEADS; i++)
                INIT_HLIST_HEAD(&kvm->guest_task_hash[i]);
        spin_lock_init(&kvm->guest_task_lock);
        printk(KERN_INFO "kvm-ta: guest task hash initialized\n" );

        /* load monitor */
        init_timer(&kvm->load_timer);
        kvm->load_timer.function = load_timer_handler;
        kvm->load_timer.data     = (unsigned long)kvm;

        /* VLP */
        spin_lock_init(&kvm->vlp_lock);

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

        spin_lock(&kvm->guest_task_lock);
        for (i = 0; i < GUEST_TASK_HASH_HEADS; i++) {
                hlist_for_each_entry_safe(guest_task, node, tmp, &kvm->guest_task_hash[i], link) {
                        hlist_del(&guest_task->link);
                        free_guest_task(guest_task);
                }
        }
        spin_unlock(&kvm->guest_task_lock);
        printk(KERN_INFO "kvm-ta: guest task hash freed\n" );

        del_timer_sync(&kvm->load_timer);
        spin_unlock_wait(&kvm->vlp_lock);
}
EXPORT_SYMBOL_GPL(exit_kvm_load_monitor);

/*
 * System-wide initialization for task-aware agent (called from kvm_init()).
 * - Initialize slab cache for guest_task_struct.
 */
int init_task_aware_agent(void)
{
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
        kmem_cache_destroy(guest_task_cache);
        printk(KERN_INFO "kvm-ta: destroying slab for guest_task_struct\n" );
}
EXPORT_SYMBOL_GPL(destroy_task_aware_agent);
