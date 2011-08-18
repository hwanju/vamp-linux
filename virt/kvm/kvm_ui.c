#include <linux/kvm_host.h>
#include <linux/module.h>
#include <trace/events/kvm.h>
#include <linux/kvm_task_aware.h>
#include <linux/kvm_ui.h>

#define get_event_type(arg)     (arg & 0xff)
#define get_event_info(arg)     ((arg >> 8) & 0xff)

int kvm_ui_event(struct kvm *kvm, uint32_t arg)
{
        int event_type = get_event_type(arg);
        int event_info = get_event_info(arg);
        unsigned long long now = sched_clock();

        trace_kvm_ui(event_type, event_info, load_idx_by_time(now));

        /* when an ui event is released, set the current timestamp into kvm */
        if (event_type == kvm_kbd_released || event_type == kvm_mouse_released)
                start_load_monitor(kvm, now, UI_MONITOR_MSEC);
        return 0;
}
EXPORT_SYMBOL_GPL(kvm_ui_event);
