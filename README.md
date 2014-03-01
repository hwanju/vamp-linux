Description
====
This is the Linux kernel that includes *vAMP hypervisor extension* based on KVM. The core of this extension is to improve the power (shares) of vCPUs that likely host interactive workloads for improving interactive performance of consolidated desktop VMs. This kernel also includes *paravirt* feature to support [user-level guest OS extension](https://github.com/virtualAMP/vamp-guest-extension), so it can also be used in a guest VM. For further information, please refer to our paper **"[Virtual Asymmetric Multiprocessor for Interactive Performance of Consolidated Destkops](http://vee2014.cs.technion.ac.il/papers/VEE14-final23.pdf)" (*[VEE 2014](http://vee2014.cs.technion.ac.il/)*)**.


Install
====
#### 1. Linux kernel

```
# make menuconfig
```
Enable **Virtualization ---> [*] Virtual desktop scheduling for KVM**. 

```
# make -j8
# make modules_install
# mkinitramfs -o /boot/initrd-3.0.0+ 3.0.0+
# make install
```

#### 2. QEMU

KVM requires QEMU, so you need to install qemu-kvm. For vAMP, a slightly modifed QEMU is needed. The source codes are [here](https://github.com/virtualAMP/vamp-qemu). The modification enables QEMU to notify KVM of triggered user inputs (currently mouse and keyboard) by using `ioctl`. You can simply add more hooks as you want like this. 

Before installing QEMU, you may need to install [SPICE](http://www.spice-space.org/). This is not mandatory, but without it you cannot use [SpicePlay](https://github.com/virtualAMP/spiceplay.git), which is a SPICE client that supports record/replay-based benchmarking. If you do not want SpicePlay-based benchmarking, skip this. For SPICE installation, refer to [here](https://github.com/virtualAMP/spiceplay.git).

```
# git clone https://github.com/virtualAMP/vamp-qemu.git
# cd vamp-qemu
# apt-get install zlib1g-dev libglib2.0-dev libpci-dev
# ./configure --enable-spice    # --enable-spice is not needed if you don't care SPICE
# make
# make install
``` 

Usage
====
#### 1. Cgroups
To use vAMP, the mandatory configuration is **[cgroups](https://www.kernel.org/doc/Documentation/cgroups/cgroups.txt)**, a container-based resource isolation functionality in Linux. Since the vAMP hypervisor extension assumes that all vCPUs that belongs to a single VM are contained in the same CPU cgroup. By leveraging this, the extension freely adjusts the shares of vCPUs without affecting other VM's CPU budgets. If this mandatory configuration is not set, vAMP would not work properly. You can use simply libvirt LXC, which automatically sets up cgroup upon VM start, or manually put VM's threads into a CPU cgroup as follows.

```
# mkdir /cpuctl
# mount -t cgroup -o cpu none /cpuctl
# mkdir /cpuctl/vm1
# echo ${QEMU_PID} > /cpuctl/vm1/cgroup.procs   # ${QEMU_PID} is PID of QEMU main process
```
This cgroup configuration, of course, should be done after VM instantiation. The VM instantiation can be done by several methods from using QEMU command to *[libvirt](http://libvirt.org)*, which is more recommended to automate trivial settings. This is beyond the scope of this document, so refer to the homepage of [libvirt](http://libvirt.org).

#### 2. Paramter setting
Without parameters set, vAMP is disabled by default. The parameters should be appropriately set after VM instantiation and cgroup setting. The followings are major parameters:

* `/proc/sys/kernel/kvm_vamp` is the nice value that is used for vAMP extension to apply to background vCPUs. Since shares decreases as nice value increases in Linux CFS and default vCPUs' nice values are zero, it should be positive in order to throttle the shares of background vCPUs. Simply it defines *weight ratio*, as shown in [paper](http://vee2014.cs.technion.ac.il/papers/VEE14-final23.pdf). For approximately 1:3 weight ratio of interactive and background vCPUs, this parameter is set to 5.   
* `/sys/module/kvm/parameters/bg_load_thresh_pct` is *background load threshold* in percentage, which is used to filter trivially loaded tasks. See Section 3.1.2 and 4.2 in the paper (50% is set in the evaluation).
* `/sys/module/kvm/parameters/max_interactive_phase_msec` is *maximum interactive phase* in millisecond, which is the time during which vAMP works to adjust vCPUs' shares. See section 3.1.2 and 4.2 in the paper (5000msec is set in the evaluation). 
* `/sys/module/kvm/parameters/remote_wakeup_track_mode` is the mode of remote wakeup tracking for identifying audio-generating tasks, as explained in Section 3.1.3 in the paper. This parameter is actually 4-bit representation to manipulate some functionality of the remote wake-up tracking for evaluation and debugging. Simply set 15 (i.e., 0xf) to enable all features. 

There are some other parameters in /sys/module/kvm/parameters, but they not as important as the above ones. You can browse the source codes to know the role of the parameters.

Misc
====
Note that the vAMP hypervisor extention is a research prototype, so the source code is for those who are interested in how the schemes introduced in the paper are implemented. So, if this doesn't work as you expect, you may look at how it works. The primary implementation is in `virt/kvm/kvm_task_aware.c` and generally you can see what is implemented beyond the baseline KVM by getting diff as follows.

```
# git diff 02f8c6aee8df3cd..c957ef8f9ddf23
```

To readily look at how it works, several tracepoints are placed in major code paths. Refer to `/sys/kernel/debug/tracing/events/kvm/` if you properly mount debugfs. Disabling by setting zero to /proc/sys/kernel/kvm_vamp, you can also simply track guest OS tasks by using tracepoints (e.g., kvm_gthread_switch) without being affected by vAMP. This tracking further may enables other people to devise other useful techniques leveraging task-awareness in the hypervisor. 

