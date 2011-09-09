#ifndef __KVM_UI_H
#define __KVM_UI_H

#include <linux/kvm.h>
#include <linux/kvm_host.h>

//#define NR_UI_LOAD_EPOCH        2
//#define UI_MONITOR_THRESHOLD    (NR_UI_LOAD_EPOCH * (1 << load_period_shift))
#define UI_MONITOR_MSEC         240      /* FIXME: temporal: 60ms (for monitoring) */

int kvm_ui_event(struct kvm *kvm, uint32_t event_type);
#endif
