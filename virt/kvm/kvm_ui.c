#include <linux/kvm_host.h>
#include <linux/module.h>
#include <trace/events/kvm.h>

//#define KVM_UI_DEBUG

#ifdef KVM_UI_DEBUG
#define uidebug(args...) printk(KERN_DEBUG "kvm-ui debug: " args)
#else
#define uidebug(args...)
#endif

#define get_event_type(arg)     (arg & 0xff)
#define get_event_info(arg)     ((arg >> 8) & 0xff)

int kvm_ui_event(struct kvm *kvm, uint32_t arg)
{
        int event_type = get_event_type(arg);
        int event_info = get_event_info(arg);
        uidebug("%s: pid=%d, event_type=%d, event_info=%d\n", __func__, current->pid, event_type, event_info);
        trace_kvm_ui(event_type, event_info);
        return 0;
}
EXPORT_SYMBOL_GPL(kvm_ui_event);
