#ifndef __KVM_UI_H
#define __KVM_UI_H

#include <linux/kvm.h>
#include <linux/kvm_host.h>

int kvm_ui_event(struct kvm *kvm, uint32_t event_type);
#endif
