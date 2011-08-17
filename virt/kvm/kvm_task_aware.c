#include <linux/sched.h>
#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/hash.h>
#include <trace/events/kvm.h>
#include <linux/kvm_task_aware.h>

/* FIXME: mb must be required? */
#define set_guest_thread_state(guest_thread, state_value)     \
        set_mb(guest_thread->state, (state_value))

//#define KVM_TA_DEBUG

#ifdef KVM_TA_DEBUG
#define tadebug(args...) printk(KERN_DEBUG "kvm-ta debug: " args)
#else
#define tadebug(args...)
#endif

/*
 * check_load_epoch() updates load_epoch_id and initializes cpu_loads[new_epoch_id],
 * when new load epoch begins at arrival time (entity would be vcpu or guest_thread).
 */
#define check_load_epoch(entity, now)   \
        do {    \
                unsigned long long cur_load_epoch_id = load_epoch_id(now);      \
                if (unlikely(cur_load_epoch_id != entity->load_epoch_id)) {     \
                        entity->load_epoch_id = cur_load_epoch_id;              \
                        entity->cpu_loads[load_idx(cur_load_epoch_id)] = 0;     \
                        tadebug("\t-> epoch_id=%llu, idx=%u\n", cur_load_epoch_id, load_idx(cur_load_epoch_id));       \
                }       \
        } while(0)

#define account_cpu_load(entity, now, exec_time) \
        do {    \
                entity->cpu_loads[load_idx(entity->load_epoch_id)] += exec_time;        \
                tadebug("\t-> cpu_loads[%u]=%llu\n", load_idx(entity->load_epoch_id), entity->cpu_loads[load_idx(entity->load_epoch_id)]);       \
        } while(0)

static struct kmem_cache *guest_task_cache;
static __read_mostly struct preempt_ops acct_preempt_ops;

#define DEFAULT_LOAD_PERIOD_MSEC        64      /* default load period */
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
        printk(KERN_INFO "kvm-ta: load period=%u ms (shift=%u)\n",
                        1 << load_period_shift, load_period_shift);
}

static inline void guest_thread_arrive(struct kvm_vcpu *vcpu, struct guest_thread_info *guest_thread, unsigned long long now)
{
        guest_thread->cpu = vcpu->cpu;
        guest_thread->last_arrival = now;
        check_load_epoch(guest_thread, now);
        trace_kvm_guest_thread_switch_arrive(get_cur_guest_task_id(vcpu), 
                        vcpu->vcpu_id, load_idx(guest_thread->load_epoch_id),
                        guest_thread->cpu_loads[load_idx(guest_thread->load_epoch_id)]);
        tadebug("    %s: v%d now=%llu\n", __func__, vcpu->vcpu_id, now);
        set_guest_thread_state(guest_thread, GUEST_THREAD_RUNNING);
}

static inline void guest_thread_depart(struct kvm_vcpu *vcpu, struct guest_thread_info *guest_thread, unsigned long long now)
{
        long long delta;
        if (likely(guest_thread->last_arrival)) {
                delta = now - guest_thread->last_arrival;
                tadebug("     %s: v%d now=%llu delta=%llu \n", __func__, vcpu->vcpu_id, now, delta);
                account_cpu_load(guest_thread, now, delta);
        }
        guest_thread->last_depart = now;
        trace_kvm_guest_thread_switch_depart(get_cur_guest_task_id(vcpu), 
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

        tadebug("%s: pid=%d vcpu_id=%d gtid=%08lx\n", __func__, current->pid, vcpu->vcpu_id, guest_task_id);
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

/*
 * always called when a vcpu arrives unlike kvm_preempt_notifer
 */
static void vcpu_arrive(struct preempt_notifier *pn, int cpu)
{
	struct kvm_vcpu *vcpu = acct_preempt_notifier_to_vcpu(pn);
        struct guest_thread_info *cur_guest_thread;
        unsigned long long now = sched_clock();

        tadebug("%s: pid=%d, v%d, cur gtid=%08lx\n", __func__, 
                        current->pid, vcpu->vcpu_id, vcpu->cur_guest_task ? vcpu->cur_guest_task->id : 0);
        /* recording for arrival */ 
        vcpu->last_arrival = now;
        check_load_epoch(vcpu, now);
        trace_kvm_vcpu_switch_arrive(vcpu->vcpu_id, load_idx(vcpu->load_epoch_id), 
                        vcpu->cpu_loads[load_idx(vcpu->load_epoch_id)]);
        
        cur_guest_thread = get_cur_guest_thread(vcpu);
        if (unlikely(!cur_guest_thread))
                return;
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
        long long delta;

        tadebug("%s: pid=%d, v%d, cur gtid=%08lx\n", __func__, 
                        current->pid, vcpu->vcpu_id, vcpu->cur_guest_task ? vcpu->cur_guest_task->id : 0);
        /* accounting for cpu time for vcpu and its current thread */ 
        if (likely(vcpu->last_arrival)) {
                delta = now - vcpu->last_arrival;
                account_cpu_load(vcpu, now, delta);
        }
        vcpu->last_depart = now;
        trace_kvm_vcpu_switch_depart(vcpu->vcpu_id, load_idx(vcpu->load_epoch_id), 
                        vcpu->cpu_loads[load_idx(vcpu->load_epoch_id)]);

        cur_guest_thread = get_cur_guest_thread(vcpu);
        if (unlikely(!cur_guest_thread))
                return;
        guest_thread_depart(vcpu, cur_guest_thread, now);
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

/*
 * Each VM maintains a hash table to store guest_task_struct for every task tracked.
 * called from kvm_create_vm().
 */
void init_guest_task_hash(struct kvm *kvm)
{
        int i;
        for (i = 0; i < GUEST_TASK_HASH_HEADS; i++)
                INIT_HLIST_HEAD(&kvm->guest_task_hash[i]);
        spin_lock_init(&kvm->guest_task_lock);
        printk(KERN_INFO "kvm-ta: guest task hash initialized\n" );
}
EXPORT_SYMBOL_GPL(init_guest_task_hash);

/*
 * Destroy guest task hash when a VM is destroyed.
 * called from kvm_destroy_vm().
 */
void destroy_guest_task_hash(struct kvm *kvm)
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
}
EXPORT_SYMBOL_GPL(destroy_guest_task_hash);

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
