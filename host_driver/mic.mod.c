#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x2ab9dba5, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x964b601a, __VMLINUX_SYMBOL_STR(kobject_put) },
	{ 0x2d3385d3, __VMLINUX_SYMBOL_STR(system_wq) },
	{ 0x19c3f856, __VMLINUX_SYMBOL_STR(kmem_cache_destroy) },
	{ 0x1fedf0f4, __VMLINUX_SYMBOL_STR(__request_region) },
	{ 0x98e34bd, __VMLINUX_SYMBOL_STR(cdev_del) },
	{ 0x23f40f61, __VMLINUX_SYMBOL_STR(device_remove_bin_file) },
	{ 0x8733c9e1, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xd2b09ce5, __VMLINUX_SYMBOL_STR(__kmalloc) },
	{ 0xee166bd7, __VMLINUX_SYMBOL_STR(cdev_init) },
	{ 0xf9a482f9, __VMLINUX_SYMBOL_STR(msleep) },
	{ 0xc897c382, __VMLINUX_SYMBOL_STR(sg_init_table) },
	{ 0x9b388444, __VMLINUX_SYMBOL_STR(get_zeroed_page) },
	{ 0x9c0dfed3, __VMLINUX_SYMBOL_STR(put_pid) },
	{ 0xe12fff09, __VMLINUX_SYMBOL_STR(up_read) },
	{ 0x4c4fef19, __VMLINUX_SYMBOL_STR(kernel_stack) },
	{ 0xe6da44a, __VMLINUX_SYMBOL_STR(set_normalized_timespec) },
	{ 0x15e3521b, __VMLINUX_SYMBOL_STR(generic_file_llseek) },
	{ 0x463e15d7, __VMLINUX_SYMBOL_STR(debugfs_create_dir) },
	{ 0xd6ee688f, __VMLINUX_SYMBOL_STR(vmalloc) },
	{ 0x1e0c2be4, __VMLINUX_SYMBOL_STR(ioremap_wc) },
	{ 0x349cba85, __VMLINUX_SYMBOL_STR(strchr) },
	{ 0x5e01d149, __VMLINUX_SYMBOL_STR(single_open) },
	{ 0x48efff5f, __VMLINUX_SYMBOL_STR(debugfs_create_u8) },
	{ 0xb6b46a7c, __VMLINUX_SYMBOL_STR(param_ops_int) },
	{ 0x69a358a6, __VMLINUX_SYMBOL_STR(iomem_resource) },
	{ 0xdf0f75c6, __VMLINUX_SYMBOL_STR(eventfd_signal) },
	{ 0x754d539c, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x43a53735, __VMLINUX_SYMBOL_STR(__alloc_workqueue_key) },
	{ 0x79aa04a2, __VMLINUX_SYMBOL_STR(get_random_bytes) },
	{ 0xf32f71a0, __VMLINUX_SYMBOL_STR(dma_set_mask) },
	{ 0x55b1bd11, __VMLINUX_SYMBOL_STR(single_release) },
	{ 0xb5dcab5b, __VMLINUX_SYMBOL_STR(remove_wait_queue) },
	{ 0xc715d9e0, __VMLINUX_SYMBOL_STR(boot_cpu_data) },
	{ 0x46608fa0, __VMLINUX_SYMBOL_STR(getnstimeofday) },
	{ 0xaf71098e, __VMLINUX_SYMBOL_STR(pci_disable_device) },
	{ 0xc75bded5, __VMLINUX_SYMBOL_STR(pci_disable_msix) },
	{ 0xb54533f7, __VMLINUX_SYMBOL_STR(usecs_to_jiffies) },
	{ 0x1b9bc2b, __VMLINUX_SYMBOL_STR(mmu_notifier_register) },
	{ 0x1a5f6a16, __VMLINUX_SYMBOL_STR(netif_carrier_on) },
	{ 0x1637ff0f, __VMLINUX_SYMBOL_STR(_raw_spin_lock_bh) },
	{ 0x6b06fdce, __VMLINUX_SYMBOL_STR(delayed_work_timer_fn) },
	{ 0x91831d70, __VMLINUX_SYMBOL_STR(seq_printf) },
	{ 0x5fbe341e, __VMLINUX_SYMBOL_STR(netif_carrier_off) },
	{ 0xd791cc7, __VMLINUX_SYMBOL_STR(remove_proc_entry) },
	{ 0xf087137d, __VMLINUX_SYMBOL_STR(__dynamic_pr_debug) },
	{ 0x3924302, __VMLINUX_SYMBOL_STR(device_destroy) },
	{ 0x38914c63, __VMLINUX_SYMBOL_STR(seq_write) },
	{ 0xb7495024, __VMLINUX_SYMBOL_STR(filp_close) },
	{ 0x3fec048f, __VMLINUX_SYMBOL_STR(sg_next) },
	{ 0x8486e57f, __VMLINUX_SYMBOL_STR(kernfs_put) },
	{ 0xeae3dfd6, __VMLINUX_SYMBOL_STR(__const_udelay) },
	{ 0x38c7a43f, __VMLINUX_SYMBOL_STR(tty_register_driver) },
	{ 0x33ba5cd4, __VMLINUX_SYMBOL_STR(param_ops_bool) },
	{ 0x593a99b, __VMLINUX_SYMBOL_STR(init_timer_key) },
	{ 0x797c8fa9, __VMLINUX_SYMBOL_STR(cancel_delayed_work_sync) },
	{ 0x1e12b70c, __VMLINUX_SYMBOL_STR(mutex_unlock) },
	{ 0xfd9e406d, __VMLINUX_SYMBOL_STR(vfs_fsync) },
	{ 0xe003d342, __VMLINUX_SYMBOL_STR(mmput) },
	{ 0x7485e15e, __VMLINUX_SYMBOL_STR(unregister_chrdev_region) },
	{ 0x999e8297, __VMLINUX_SYMBOL_STR(vfree) },
	{ 0xb308ee86, __VMLINUX_SYMBOL_STR(put_tty_driver) },
	{ 0x6f577053, __VMLINUX_SYMBOL_STR(debugfs_create_file) },
	{ 0x4629334c, __VMLINUX_SYMBOL_STR(__preempt_count) },
	{ 0x7a2af7b4, __VMLINUX_SYMBOL_STR(cpu_number) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0x1ec1089d, __VMLINUX_SYMBOL_STR(debugfs_remove_recursive) },
	{ 0xa692f01a, __VMLINUX_SYMBOL_STR(seq_read) },
	{ 0x63e08021, __VMLINUX_SYMBOL_STR(sysfs_remove_group) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0x9c417043, __VMLINUX_SYMBOL_STR(tty_set_operations) },
	{ 0x55b9699c, __VMLINUX_SYMBOL_STR(mutex_trylock) },
	{ 0xd03c245b, __VMLINUX_SYMBOL_STR(down_read) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0xf6246e10, __VMLINUX_SYMBOL_STR(down_write_trylock) },
	{ 0xc51bdc4f, __VMLINUX_SYMBOL_STR(simple_attr_read) },
	{ 0x733c3b54, __VMLINUX_SYMBOL_STR(kasprintf) },
	{ 0x190b5c8d, __VMLINUX_SYMBOL_STR(__netdev_alloc_skb) },
	{ 0xf432dd3d, __VMLINUX_SYMBOL_STR(__init_waitqueue_head) },
	{ 0xc671e369, __VMLINUX_SYMBOL_STR(_copy_to_user) },
	{ 0xffd5a395, __VMLINUX_SYMBOL_STR(default_wake_function) },
	{ 0xa3a1283, __VMLINUX_SYMBOL_STR(PDE_DATA) },
	{ 0xbf6ddb0, __VMLINUX_SYMBOL_STR(debugfs_create_u32) },
	{ 0x1f1824d8, __VMLINUX_SYMBOL_STR(pci_set_master) },
	{ 0x6ec9be76, __VMLINUX_SYMBOL_STR(vfs_read) },
	{ 0x50d1f870, __VMLINUX_SYMBOL_STR(pgprot_writecombine) },
	{ 0x559450f2, __VMLINUX_SYMBOL_STR(__f_setown) },
	{ 0xd5f2172f, __VMLINUX_SYMBOL_STR(del_timer_sync) },
	{ 0x60ea2d6, __VMLINUX_SYMBOL_STR(kstrtoull) },
	{ 0x4e29456a, __VMLINUX_SYMBOL_STR(vfs_readv) },
	{ 0xfb578fc5, __VMLINUX_SYMBOL_STR(memset) },
	{ 0x6fcb87a1, __VMLINUX_SYMBOL_STR(touch_softlockup_watchdog) },
	{ 0xf2af955a, __VMLINUX_SYMBOL_STR(proc_mkdir) },
	{ 0x7670eab2, __VMLINUX_SYMBOL_STR(pci_enable_msix) },
	{ 0xa8f98490, __VMLINUX_SYMBOL_STR(pci_restore_state) },
	{ 0x8f64aa4, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_irqrestore) },
	{ 0x8e663bd9, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x23beab60, __VMLINUX_SYMBOL_STR(__mutex_init) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0x20c55ae0, __VMLINUX_SYMBOL_STR(sscanf) },
	{ 0xd676438a, __VMLINUX_SYMBOL_STR(kthread_stop) },
	{ 0x3c3fce39, __VMLINUX_SYMBOL_STR(__local_bh_enable_ip) },
	{ 0xc1ed9a06, __VMLINUX_SYMBOL_STR(sysfs_create_group) },
	{ 0x449ad0a7, __VMLINUX_SYMBOL_STR(memcmp) },
	{ 0x31fd8f71, __VMLINUX_SYMBOL_STR(get_task_mm) },
	{ 0x560d8a9, __VMLINUX_SYMBOL_STR(mmu_notifier_unregister) },
	{ 0x637c3e8, __VMLINUX_SYMBOL_STR(tty_port_register_device) },
	{ 0x4c9d28b0, __VMLINUX_SYMBOL_STR(phys_base) },
	{ 0xa6624490, __VMLINUX_SYMBOL_STR(free_netdev) },
	{ 0xfaef0ed, __VMLINUX_SYMBOL_STR(__tasklet_schedule) },
	{ 0xa1c76e0a, __VMLINUX_SYMBOL_STR(_cond_resched) },
	{ 0x9166fada, __VMLINUX_SYMBOL_STR(strncpy) },
	{ 0x49dd2339, __VMLINUX_SYMBOL_STR(register_netdev) },
	{ 0xdcdc8b1c, __VMLINUX_SYMBOL_STR(fasync_helper) },
	{ 0x28492bea, __VMLINUX_SYMBOL_STR(netif_receive_skb) },
	{ 0x9cc4f70a, __VMLINUX_SYMBOL_STR(register_pm_notifier) },
	{ 0x5a921311, __VMLINUX_SYMBOL_STR(strncmp) },
	{ 0x92649420, __VMLINUX_SYMBOL_STR(tty_port_init) },
	{ 0x8ecd8731, __VMLINUX_SYMBOL_STR(kernfs_find_and_get_ns) },
	{ 0xcfdfb0c2, __VMLINUX_SYMBOL_STR(kmem_cache_free) },
	{ 0x1d21966b, __VMLINUX_SYMBOL_STR(tty_insert_flip_string_fixed_flag) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0x77f4cc43, __VMLINUX_SYMBOL_STR(mutex_lock) },
	{ 0x8c03d20c, __VMLINUX_SYMBOL_STR(destroy_workqueue) },
	{ 0xbb704422, __VMLINUX_SYMBOL_STR(device_create) },
	{ 0x9545af6d, __VMLINUX_SYMBOL_STR(tasklet_init) },
	{ 0xc2cdbf1, __VMLINUX_SYMBOL_STR(synchronize_sched) },
	{ 0x8834396c, __VMLINUX_SYMBOL_STR(mod_timer) },
	{ 0xbe2c0274, __VMLINUX_SYMBOL_STR(add_timer) },
	{ 0x8402da22, __VMLINUX_SYMBOL_STR(kill_pid) },
	{ 0x37a11ae5, __VMLINUX_SYMBOL_STR(simple_attr_release) },
	{ 0xd6b8e852, __VMLINUX_SYMBOL_STR(request_threaded_irq) },
	{ 0x86d8ac5c, __VMLINUX_SYMBOL_STR(up_write) },
	{ 0x38c8f5f, __VMLINUX_SYMBOL_STR(down_write) },
	{ 0xba846f53, __VMLINUX_SYMBOL_STR(fput) },
	{ 0x5babfabc, __VMLINUX_SYMBOL_STR(rtnl_link_unregister) },
	{ 0x42160169, __VMLINUX_SYMBOL_STR(flush_workqueue) },
	{ 0xa07ef116, __VMLINUX_SYMBOL_STR(device_create_file) },
	{ 0x83730f75, __VMLINUX_SYMBOL_STR(cdev_add) },
	{ 0xc6cbbc89, __VMLINUX_SYMBOL_STR(capable) },
	{ 0xb1c3a01a, __VMLINUX_SYMBOL_STR(oops_in_progress) },
	{ 0x49d26011, __VMLINUX_SYMBOL_STR(tty_unregister_device) },
	{ 0x10031e40, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0x78764f4e, __VMLINUX_SYMBOL_STR(pv_irq_ops) },
	{ 0x67b27ec1, __VMLINUX_SYMBOL_STR(tty_std_termios) },
	{ 0x42c8de35, __VMLINUX_SYMBOL_STR(ioremap_nocache) },
	{ 0x93fca811, __VMLINUX_SYMBOL_STR(__get_free_pages) },
	{ 0xba63339c, __VMLINUX_SYMBOL_STR(_raw_spin_unlock_bh) },
	{ 0xeeec26a7, __VMLINUX_SYMBOL_STR(queue_delayed_work_on) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x44b74989, __VMLINUX_SYMBOL_STR(get_user_pages) },
	{ 0x3bd1b1f6, __VMLINUX_SYMBOL_STR(msecs_to_jiffies) },
	{ 0x68c9f1f7, __VMLINUX_SYMBOL_STR(pci_reenable_device) },
	{ 0xd62c833f, __VMLINUX_SYMBOL_STR(schedule_timeout) },
	{ 0x1000e51, __VMLINUX_SYMBOL_STR(schedule) },
	{ 0x17673717, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0x43261dca, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irq) },
	{ 0xbff1063f, __VMLINUX_SYMBOL_STR(alloc_netdev_mqs) },
	{ 0x34aac631, __VMLINUX_SYMBOL_STR(eth_type_trans) },
	{ 0x75b28858, __VMLINUX_SYMBOL_STR(wake_up_process) },
	{ 0x2ba0349f, __VMLINUX_SYMBOL_STR(device_create_bin_file) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x7c61340c, __VMLINUX_SYMBOL_STR(__release_region) },
	{ 0x6a0750ca, __VMLINUX_SYMBOL_STR(pci_unregister_driver) },
	{ 0x3fc95f0a, __VMLINUX_SYMBOL_STR(ether_setup) },
	{ 0xa43a0a02, __VMLINUX_SYMBOL_STR(kernfs_notify) },
	{ 0x20705009, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xd52bf1ce, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0x9327f5ce, __VMLINUX_SYMBOL_STR(_raw_spin_lock_irqsave) },
	{ 0xb18735f8, __VMLINUX_SYMBOL_STR(vfs_writev) },
	{ 0x7635873, __VMLINUX_SYMBOL_STR(kmem_cache_create) },
	{ 0x88f4ad3, __VMLINUX_SYMBOL_STR(tty_unregister_driver) },
	{ 0xce46e140, __VMLINUX_SYMBOL_STR(ktime_get_ts) },
	{ 0x4302d0eb, __VMLINUX_SYMBOL_STR(free_pages) },
	{ 0xcf21d241, __VMLINUX_SYMBOL_STR(__wake_up) },
	{ 0xa1d73dcc, __VMLINUX_SYMBOL_STR(pci_set_power_state) },
	{ 0xd2026ca0, __VMLINUX_SYMBOL_STR(remove_proc_subtree) },
	{ 0x34f22f94, __VMLINUX_SYMBOL_STR(prepare_to_wait_event) },
	{ 0x43778b2e, __VMLINUX_SYMBOL_STR(__tty_alloc_driver) },
	{ 0x308992c, __VMLINUX_SYMBOL_STR(proc_create_data) },
	{ 0x4f68e5c9, __VMLINUX_SYMBOL_STR(do_gettimeofday) },
	{ 0x47e24f1d, __VMLINUX_SYMBOL_STR(eth_validate_addr) },
	{ 0x65bbbc78, __VMLINUX_SYMBOL_STR(schedule_hrtimeout_range) },
	{ 0x8c183cbe, __VMLINUX_SYMBOL_STR(iowrite16) },
	{ 0x5860aad4, __VMLINUX_SYMBOL_STR(add_wait_queue) },
	{ 0x349456e4, __VMLINUX_SYMBOL_STR(seq_lseek) },
	{ 0x68e05d57, __VMLINUX_SYMBOL_STR(getrawmonotonic) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xd3d199d8, __VMLINUX_SYMBOL_STR(remap_pfn_range) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xa5bed252, __VMLINUX_SYMBOL_STR(dma_supported) },
	{ 0xedc03953, __VMLINUX_SYMBOL_STR(iounmap) },
	{ 0x7681946c, __VMLINUX_SYMBOL_STR(unregister_pm_notifier) },
	{ 0xa4453079, __VMLINUX_SYMBOL_STR(rtnl_link_register) },
	{ 0x79ae72b6, __VMLINUX_SYMBOL_STR(__pci_register_driver) },
	{ 0xa8721b97, __VMLINUX_SYMBOL_STR(system_state) },
	{ 0xdc934606, __VMLINUX_SYMBOL_STR(put_page) },
	{ 0x4ca9669f, __VMLINUX_SYMBOL_STR(scnprintf) },
	{ 0x6d36dc13, __VMLINUX_SYMBOL_STR(class_destroy) },
	{ 0xc5534d64, __VMLINUX_SYMBOL_STR(ioread16) },
	{ 0xfa66f77c, __VMLINUX_SYMBOL_STR(finish_wait) },
	{ 0x7f71867d, __VMLINUX_SYMBOL_STR(tty_flip_buffer_push) },
	{ 0x222e7ce2, __VMLINUX_SYMBOL_STR(sysfs_streq) },
	{ 0x2e0d2f7f, __VMLINUX_SYMBOL_STR(queue_work_on) },
	{ 0x28318305, __VMLINUX_SYMBOL_STR(snprintf) },
	{ 0x45453d19, __VMLINUX_SYMBOL_STR(__netif_schedule) },
	{ 0x941f2aaa, __VMLINUX_SYMBOL_STR(eventfd_ctx_put) },
	{ 0xb0e602eb, __VMLINUX_SYMBOL_STR(memmove) },
	{ 0x264606c3, __VMLINUX_SYMBOL_STR(vmalloc_to_page) },
	{ 0x2283bb97, __VMLINUX_SYMBOL_STR(tty_wakeup) },
	{ 0x62cc8289, __VMLINUX_SYMBOL_STR(skb_put) },
	{ 0xfa9f96c, __VMLINUX_SYMBOL_STR(pci_enable_device) },
	{ 0xb5419b40, __VMLINUX_SYMBOL_STR(_copy_from_user) },
	{ 0x8d2e268b, __VMLINUX_SYMBOL_STR(param_ops_ulong) },
	{ 0x5268a83d, __VMLINUX_SYMBOL_STR(__class_create) },
	{ 0x7ea7cb42, __VMLINUX_SYMBOL_STR(simple_attr_open) },
	{ 0xa5407cad, __VMLINUX_SYMBOL_STR(dma_ops) },
	{ 0x29537c9e, __VMLINUX_SYMBOL_STR(alloc_chrdev_region) },
	{ 0x802f4ff0, __VMLINUX_SYMBOL_STR(simple_attr_write) },
	{ 0xf20dabd8, __VMLINUX_SYMBOL_STR(free_irq) },
	{ 0x90c0bfb8, __VMLINUX_SYMBOL_STR(pci_save_state) },
	{ 0xe914e41e, __VMLINUX_SYMBOL_STR(strcpy) },
	{ 0xe93f14b5, __VMLINUX_SYMBOL_STR(filp_open) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";
