#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif


static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0x92997ed8, "_printk" },
	{ 0xbcab6ee6, "sscanf" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x5e515be6, "ktime_get_ts64" },
	{ 0xef590492, "kmalloc_caches" },
	{ 0xeb310fd2, "kmalloc_trace" },
	{ 0xc88f67e8, "kthread_create_on_node" },
	{ 0x64c2eac1, "wake_up_process" },
	{ 0xfcca5424, "register_kprobe" },
	{ 0x37a086c5, "kthread_stop" },
	{ 0x37a0cba, "kfree" },
	{ 0xa19b956, "__stack_chk_fail" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x63026490, "unregister_kprobe" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0xfe8c61f0, "_raw_read_lock" },
	{ 0xdd4d55b6, "_raw_read_unlock" },
	{ 0xe68efe41, "_raw_write_lock" },
	{ 0x40235c98, "_raw_write_unlock" },
	{ 0xa648e561, "__ubsan_handle_shift_out_of_bounds" },
	{ 0xb3f7646e, "kthread_should_stop" },
	{ 0xd8b44db2, "param_ops_string" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x4ddb9e0e, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "64853FD8EB6607E28346FDC");
