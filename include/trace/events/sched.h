#undef TRACE_SYSTEM
#define TRACE_SYSTEM sched

#if !defined(_TRACE_SCHED_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SCHED_H

#include <linux/sched.h>
#include <linux/tracepoint.h>

/*
 * Tracepoint for calling kthread_stop, performed to end a kthread:
 */
TRACE_EVENT(sched_kthread_stop,

	TP_PROTO(struct task_struct *t),

	TP_ARGS(t),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, t->comm, TASK_COMM_LEN);
		__entry->pid	= t->pid;
	),

	TP_printk("comm=%s pid=%d", __entry->comm, __entry->pid)
);

/*
 * Tracepoint for the return value of the kthread stopping:
 */
TRACE_EVENT(sched_kthread_stop_ret,

	TP_PROTO(int ret),

	TP_ARGS(ret),

	TP_STRUCT__entry(
		__field(	int,	ret	)
	),

	TP_fast_assign(
		__entry->ret	= ret;
	),

	TP_printk("ret=%d", __entry->ret)
);

/*
 * Tracepoint for waking up a task:
 */
DECLARE_EVENT_CLASS(sched_wakeup_template,

	TP_PROTO(struct task_struct *p, int success),

	TP_ARGS(p, success),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(	int,	prio			)
		__field(	int,	success			)
		__field(	int,	target_cpu		)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid		= p->pid;
		__entry->prio		= p->prio;
		__entry->success	= success;
		__entry->target_cpu	= task_cpu(p);
	),

	TP_printk("comm=%s pid=%d prio=%d success=%d target_cpu=%03d",
		  __entry->comm, __entry->pid, __entry->prio,
		  __entry->success, __entry->target_cpu)
);

DEFINE_EVENT(sched_wakeup_template, sched_wakeup,
	     TP_PROTO(struct task_struct *p, int success),
	     TP_ARGS(p, success));

/*
 * Tracepoint for waking up a new task:
 */
DEFINE_EVENT(sched_wakeup_template, sched_wakeup_new,
	     TP_PROTO(struct task_struct *p, int success),
	     TP_ARGS(p, success));

#ifdef CREATE_TRACE_POINTS
static inline long __trace_sched_switch_state(struct task_struct *p)
{
	long state = p->state;

#ifdef CONFIG_PREEMPT
	/*
	 * For all intents and purposes a preempted task is a running task.
	 */
	if (task_thread_info(p)->preempt_count & PREEMPT_ACTIVE)
		state = TASK_RUNNING;
#endif

	return state;
}
#endif

/*
 * Tracepoint for task switches, performed by the scheduler:
 */
TRACE_EVENT(sched_switch,

	TP_PROTO(struct task_struct *prev,
		 struct task_struct *next),

	TP_ARGS(prev, next),

	TP_STRUCT__entry(
		__array(	char,	prev_comm,	TASK_COMM_LEN	)
		__field(	pid_t,	prev_pid			)
		__field(	int,	prev_prio			)
		__field(	long,	prev_state			)
		__array(	char,	next_comm,	TASK_COMM_LEN	)
		__field(	pid_t,	next_pid			)
		__field(	int,	next_prio			)
	),

	TP_fast_assign(
		memcpy(__entry->next_comm, next->comm, TASK_COMM_LEN);
		__entry->prev_pid	= prev->pid;
		__entry->prev_prio	= prev->prio;
		__entry->prev_state	= __trace_sched_switch_state(prev);
		memcpy(__entry->prev_comm, prev->comm, TASK_COMM_LEN);
		__entry->next_pid	= next->pid;
		__entry->next_prio	= next->prio;
	),

	TP_printk("prev_comm=%s prev_pid=%d prev_prio=%d prev_state=%s ==> next_comm=%s next_pid=%d next_prio=%d",
		__entry->prev_comm, __entry->prev_pid, __entry->prev_prio,
		__entry->prev_state ?
		  __print_flags(__entry->prev_state, "|",
				{ 1, "S"} , { 2, "D" }, { 4, "T" }, { 8, "t" },
				{ 16, "Z" }, { 32, "X" }, { 64, "x" },
				{ 128, "W" }) : "R",
		__entry->next_comm, __entry->next_pid, __entry->next_prio)
);

/*
 * Tracepoint for a task being migrated:
 */
TRACE_EVENT(sched_migrate_task,

	TP_PROTO(struct task_struct *p, int dest_cpu),

	TP_ARGS(p, dest_cpu),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(	int,	prio			)
		__field(	int,	orig_cpu		)
		__field(	int,	dest_cpu		)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid		= p->pid;
		__entry->prio		= p->prio;
		__entry->orig_cpu	= task_cpu(p);
		__entry->dest_cpu	= dest_cpu;
	),

	TP_printk("comm=%s pid=%d prio=%d orig_cpu=%d dest_cpu=%d",
		  __entry->comm, __entry->pid, __entry->prio,
		  __entry->orig_cpu, __entry->dest_cpu)
);

DECLARE_EVENT_CLASS(sched_process_template,

	TP_PROTO(struct task_struct *p),

	TP_ARGS(p),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(	int,	prio			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->pid		= p->pid;
		__entry->prio		= p->prio;
	),

	TP_printk("comm=%s pid=%d prio=%d",
		  __entry->comm, __entry->pid, __entry->prio)
);

/*
 * Tracepoint for freeing a task:
 */
DEFINE_EVENT(sched_process_template, sched_process_free,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));
	     

/*
 * Tracepoint for a task exiting:
 */
DEFINE_EVENT(sched_process_template, sched_process_exit,
	     TP_PROTO(struct task_struct *p),
	     TP_ARGS(p));

/*
 * Tracepoint for waiting on task to unschedule:
 */
DEFINE_EVENT(sched_process_template, sched_wait_task,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

/*
 * Tracepoint for a waiting task:
 */
TRACE_EVENT(sched_process_wait,

	TP_PROTO(struct pid *pid),

	TP_ARGS(pid),

	TP_STRUCT__entry(
		__array(	char,	comm,	TASK_COMM_LEN	)
		__field(	pid_t,	pid			)
		__field(	int,	prio			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, current->comm, TASK_COMM_LEN);
		__entry->pid		= pid_nr(pid);
		__entry->prio		= current->prio;
	),

	TP_printk("comm=%s pid=%d prio=%d",
		  __entry->comm, __entry->pid, __entry->prio)
);

/*
 * Tracepoint for do_fork:
 */
TRACE_EVENT(sched_process_fork,

	TP_PROTO(struct task_struct *parent, struct task_struct *child),

	TP_ARGS(parent, child),

	TP_STRUCT__entry(
		__array(	char,	parent_comm,	TASK_COMM_LEN	)
		__field(	pid_t,	parent_pid			)
		__array(	char,	child_comm,	TASK_COMM_LEN	)
		__field(	pid_t,	child_pid			)
	),

	TP_fast_assign(
		memcpy(__entry->parent_comm, parent->comm, TASK_COMM_LEN);
		__entry->parent_pid	= parent->pid;
		memcpy(__entry->child_comm, child->comm, TASK_COMM_LEN);
		__entry->child_pid	= child->pid;
	),

	TP_printk("comm=%s pid=%d child_comm=%s child_pid=%d",
		__entry->parent_comm, __entry->parent_pid,
		__entry->child_comm, __entry->child_pid)
);

/*
 * XXX the below sched_stat tracepoints only apply to SCHED_OTHER/BATCH/IDLE
 *     adding sched_stat support to SCHED_FIFO/RR would be welcome.
 */
DECLARE_EVENT_CLASS(sched_stat_template,

	TP_PROTO(struct task_struct *tsk, u64 delay),

	TP_ARGS(tsk, delay),

	TP_STRUCT__entry(
		__array( char,	comm,	TASK_COMM_LEN	)
		__field( pid_t,	pid			)
		__field( u64,	delay			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, tsk->comm, TASK_COMM_LEN);
		__entry->pid	= tsk->pid;
		__entry->delay	= delay;
	)
	TP_perf_assign(
		__perf_count(delay);
	),

	TP_printk("comm=%s pid=%d delay=%Lu [ns]",
			__entry->comm, __entry->pid,
			(unsigned long long)__entry->delay)
);


/*
 * Tracepoint for accounting wait time (time the task is runnable
 * but not actually running due to scheduler contention).
 */
DEFINE_EVENT(sched_stat_template, sched_stat_wait,
	     TP_PROTO(struct task_struct *tsk, u64 delay),
	     TP_ARGS(tsk, delay));

/*
 * Tracepoint for accounting sleep time (time the task is not runnable,
 * including iowait, see below).
 */
DEFINE_EVENT(sched_stat_template, sched_stat_sleep,
	     TP_PROTO(struct task_struct *tsk, u64 delay),
	     TP_ARGS(tsk, delay));

/*
 * Tracepoint for accounting iowait time (time the task is not runnable
 * due to waiting on IO to complete).
 */
DEFINE_EVENT(sched_stat_template, sched_stat_iowait,
	     TP_PROTO(struct task_struct *tsk, u64 delay),
	     TP_ARGS(tsk, delay));

/*
 * Tracepoint for accounting runtime (time the task is executing
 * on a CPU).
 */
TRACE_EVENT(sched_stat_runtime,

	TP_PROTO(struct task_struct *tsk, u64 runtime, u64 vruntime),

	TP_ARGS(tsk, runtime, vruntime),

	TP_STRUCT__entry(
		__array( char,	comm,	TASK_COMM_LEN	)
		__field( pid_t,	pid			)
		__field( u64,	runtime			)
		__field( u64,	vruntime			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, tsk->comm, TASK_COMM_LEN);
		__entry->pid		= tsk->pid;
		__entry->runtime	= runtime;
		__entry->vruntime	= vruntime;
	)
	TP_perf_assign(
		__perf_count(runtime);
	),

	TP_printk("comm=%s pid=%d runtime=%Lu [ns] vruntime=%Lu [ns]",
			__entry->comm, __entry->pid,
			(unsigned long long)__entry->runtime,
			(unsigned long long)__entry->vruntime)
);

/*
 * Tracepoint for showing priority inheritance modifying a tasks
 * priority.
 */
TRACE_EVENT(sched_pi_setprio,

	TP_PROTO(struct task_struct *tsk, int newprio),

	TP_ARGS(tsk, newprio),

	TP_STRUCT__entry(
		__array( char,	comm,	TASK_COMM_LEN	)
		__field( pid_t,	pid			)
		__field( int,	oldprio			)
		__field( int,	newprio			)
	),

	TP_fast_assign(
		memcpy(__entry->comm, tsk->comm, TASK_COMM_LEN);
		__entry->pid		= tsk->pid;
		__entry->oldprio	= tsk->prio;
		__entry->newprio	= newprio;
	),

	TP_printk("comm=%s pid=%d oldprio=%d newprio=%d",
			__entry->comm, __entry->pid,
			__entry->oldprio, __entry->newprio)
);
#ifdef CONFIG_BALANCE_SCHED
TRACE_EVENT(sched_group_weight,

	TP_PROTO(unsigned int tgid, int pid, unsigned long weight, unsigned long group_weight, u64 vruntime, u64 group_vruntime),

	TP_ARGS(tgid, pid, weight, group_weight, vruntime, group_vruntime),

	TP_STRUCT__entry(
		__field( unsigned int,  tgid            )
		__field( int,           pid             )
		__field( unsigned long, weight          )
		__field( unsigned long, group_weight    )
		__field( u64,           vruntime        )
		__field( u64,           group_vruntime  )
	),

	TP_fast_assign(
		__entry->tgid           = tgid;
		__entry->pid            = pid;
		__entry->weight         = weight;
		__entry->group_weight   = group_weight;
		__entry->vruntime       = vruntime;
		__entry->group_vruntime = group_vruntime;
	),

	TP_printk("tgid=%d pid=%d weight=%lu group_weight=%lu vruntime=%llu group_vruntime=%llu",
                __entry->tgid, __entry->pid, __entry->weight, __entry->group_weight, __entry->vruntime, __entry->group_vruntime)
);
TRACE_EVENT(balsched_cpu_stat,
	TP_PROTO(int vm_id, int cpu, int load_imbalance, unsigned long nr_running_vcpus, int interactive_count),

	TP_ARGS(vm_id, cpu, load_imbalance, nr_running_vcpus, interactive_count),

	TP_STRUCT__entry(
		__field( int,           vm_id                   )
		__field( int,           cpu                     )
		__field( int,           load_imbalance          )
		__field( unsigned long, nr_running_vcpus        )
		__field( int,           interactive_count       )
	),

	TP_fast_assign(
		__entry->vm_id                  = vm_id;
		__entry->cpu                    = cpu;
		__entry->load_imbalance         = load_imbalance;
		__entry->nr_running_vcpus       = nr_running_vcpus;
		__entry->interactive_count      = interactive_count;
	),

	TP_printk("vm_id=%d cpu=%d load_imbalance=%d nr_running_vcpus=%lu interactive_count=%d",
                __entry->vm_id, __entry->cpu, __entry->load_imbalance, __entry->nr_running_vcpus, __entry->interactive_count)
);
TRACE_EVENT(balsched_affinity,
	TP_PROTO(int vm_id, int affinity_updated, unsigned long affinity_bit),

	TP_ARGS(vm_id, affinity_updated, affinity_bit),

	TP_STRUCT__entry(
		__field( int,           vm_id                   )
		__field( int,           affinity_updated        )
		__field( unsigned long, affinity_bit            )
	),

	TP_fast_assign(
		__entry->vm_id                  = vm_id;
		__entry->affinity_updated       = affinity_updated;
		__entry->affinity_bit           = affinity_bit;
	),

	TP_printk("vm_id=%d affinity_updated=%d affinity_bit=%02lx",
                __entry->vm_id, __entry->affinity_updated, __entry->affinity_bit)
);
TRACE_EVENT(balsched_cpu_load,
        TP_PROTO(int cpu, unsigned long weight, s64 expected_load, unsigned long cur_total_weight, s64 cpu_load, unsigned long weight_per_cpu),

        TP_ARGS(cpu, weight, expected_load, cur_total_weight, cpu_load, weight_per_cpu),

        TP_STRUCT__entry(
                __field( int,   cpu)
                __field( unsigned long, weight)
                __field( s64,   expected_load)
                __field( unsigned long, cur_total_weight)
                __field( s64,   cpu_load)
                __field( unsigned long, weight_per_cpu)
        ),

        TP_fast_assign(
                __entry->cpu    = cpu;
                __entry->weight = weight;
                __entry->expected_load  = expected_load;
                __entry->cur_total_weight       = cur_total_weight;
                __entry->cpu_load       = cpu_load;
                __entry->weight_per_cpu = weight_per_cpu;
        ),

        TP_printk("cpu=%d weight=%lu expected_load=%lld cur_total_weight=%lu cpu_load=%lld weight_per_cpu=%lu",
                       __entry->cpu, __entry->weight, __entry->expected_load, __entry->cur_total_weight, __entry->cpu_load, __entry->weight_per_cpu)
)
#endif
#ifdef CONFIG_KVM_VDI   /* hwandori-experimental */
TRACE_EVENT(sched_ipi_futex,

	TP_PROTO(struct task_struct *source_task, struct task_struct *target_task),

	TP_ARGS(source_task, target_task),

	TP_STRUCT__entry(
		__field( pid_t, source_pid              )
		__field( int,	source_type             )
		__field( pid_t,	target_pid              )
		__field( int,	target_type             )
	),

	TP_fast_assign(
		__entry->source_pid             = source_task->pid;
                __entry->source_type            = source_task->se.ipi_pending;
		__entry->target_pid             = target_task->pid;
                __entry->target_type            = target_task->se.ipi_pending;
	),

	TP_printk("source_pid=%d (type=%d) -> target_pid=%d (type=%d)",
                __entry->source_pid, __entry->source_type, __entry->target_pid, __entry->target_type)
);

TRACE_EVENT(sched_interactive_load,

	TP_PROTO(int cpu, int is_this_cpu, s64 load, int interactive_count),

	TP_ARGS(cpu, is_this_cpu, load, interactive_count),

	TP_STRUCT__entry(
		__field( int,   cpu                     )
		__field( int,	is_this_cpu             )
		__field( s64,	load                    )
		__field( int,	interactive_count       )
	),

	TP_fast_assign(
		__entry->cpu                    = cpu;
                __entry->is_this_cpu            = is_this_cpu;
		__entry->load                   = load;
                __entry->interactive_count      = interactive_count;
	),

	TP_printk("cpu=%d is_this_cpu=%d load=%lld interactive_count=%d",
                __entry->cpu, __entry->is_this_cpu, __entry->load, __entry->interactive_count)
);
#endif

#endif /* _TRACE_SCHED_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
