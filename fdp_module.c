#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/nvme.h>
#include <linux/sched.h>
#include "fdp_module.h"

/*  */


/* get pid */
uint16_t nvme_get_fm_pid(uint64_t slba, uint16_t nblocks)
{
    struct nvme_fm_admin_node*     td    = td;     // Need to modify
    struct nvme_fm_circular_queue* sub_q = sub_q;  // Need to modify

    uint64_t chnk_id = slba * _FM_LBA_SZ / _FM_CHNK_SZ;
    uint16_t pid;

    if(slba == td->prev_lba)
        pid = td->prev_ruhid;

    else
    {
        pid = g_fm->fm_pids[chnk_id];
        nvme_fm_circular_push_chnk(sub_q, chnk_id);
    }

    td->prev_lba = slba + nblocks;
    td->prev_ruhid = pid;

    return pid;
}

/* define update */
void nvme_fm_pid_update(void)
{
    
}


/* define thread */
void* fm_update_thread(void*)
{
    while(!kthread_should_stop())
    {
        if(g_fm)
            nvme_fm_update(); 
            ssleep(1);
    }

    return NULL;
}

/* nvme_setup_cmd hooking */
static int handler_pre(struct kprobe* p, struct pt_regs* regs)
{
    struct nvme_command* cmd;
    uint16_t pid;
    
    cmd = (struct nvme_command*)regs->si;

    pid = nvme_get_fm_pid(cmd->slba, cmd->length);
    cmd->dspec = pid;

    return 0;
}

/* mudule init */
static int __init fdp_module_init(void)
{
    int ret, i;

    g_fm = kmalloc(sizeof(struct nvme_fm_attr), GFP_KERNEL);
    if(!g_fm)   return -ENOMEM;

    g_fm->num_chnk =  _FM_DEV_SZ/_FM_CHNK_SZ + 1;
    g_fm->chnks    = kmalloc(g_fm->num_chnk * sizeof(struct nvme_fm_chnk), GFP_KERNEL);
    if(!g_fm->chnks) return -ENOMEM;
    g_fm->fm_pids  = kmalloc(g_fm->num_chnk * sizeof(uint32_t), GFP_KERNEL);
    if(!g_fm->fm_pids) return -ENOMEM;

    g_sfr->decay_period = _SFR_DECAY_PERIOD * 1e9; // sec * 1e9

    for(uint64_t i = 0; i < g_fm->num_chnk; i++) 
    {
        g_fm->chnks[i].chnk_id    = i;
        g_fm->chnks[i].real_cnt   = 0;
        g_fm->chnks[i].access_cnt = 0;

        g_fm->chnks[i].access_time.tv_sec  = current_time.tv_sec;
        g_fm->chnks[i].access_time.tv_nsec = current_time.tv_nsec;
        
        g_fm->fm_pids[i] = 1;
    }

    g_fm->admin_q = kmalloc(sizeof(struct nvme_fm_admin_q));
    if(!g_fm->admin_q) return -ENOMEM;

    g_fm->admin_q->head = NULL;
    g_fm->admin_q->tail = NULL;

    update_thread = kthread_run(fm_update_thread, NULL, "fm_update_thread");
    if(IS_ERR(update_thread))
    {
        kfree(g_fm);
        return PTR_ERR(update_thread);
    }

    kp.symbol_name = "nvme_setup_rw"
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if(ret < 0)
    {
        printk(KERN_ERR "Failed to register kprobe: %d\n", ret);
        kthread_stop(update_thread);

        kfree(g_fm->chnks);
        kfree(g_fm->pids);
        kfree(g_fm);

        return ret;
    }

    printk(KERN_INFO "FDP Module loaded: update_thread and nvme_setup_rw hooking\n");


    return 0;
}

/* module exit */
static void __exit fdp_module_init(void)
{
    if(update_thread)
        kthread_stop(update_thread);

    unregister_kprobe(&kp);

    kfree(g_fm->chnks);
    kfree(g_fm->pids);
    kfree(g_fm);

    printk(KERN_INFO "FDP Module unloaded\n");
}

module_init(fdp_module_init);
module_exit(fdp_module_exit);
MODULE_LICENSE("GPL");