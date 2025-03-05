#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/nvme.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include "fdp_module.h"

/* TODO: To decision the decay time */
void nvme_fm_dp_decision(void)
{
    decay_period = dev_info.decay_period * 1e9; // sec * 1e9

    return;
}

/* Return interval (nsec) */
uint64_t nvme_time_diff(struct timespec t1, struct timespec t2) 
{
    return (t2.tv_nsec >= t1.tv_nsec) 
            ? (t2.tv_sec - t1.tv_sec) * 1e9 + (t2.tv_nsec - t1.tv_nsec)
            : (t2.tv_sec - t1.tv_sec - 1) * 1e9 + (1e9 + t2.tv_nsec - t1.tv_nsec);
}

/* For circular queue (lock-free) */ 
void nvme_fm_circular_push_chnk(struct nvme_fm_circular_queue* q, uint64_t chnk_id) 
{
    uint32_t rear, next_rear;
    // uint32_t f = 0; // to check overhead

    do 
    {
        rear = atomic_load(&q->rear);
        next_rear = (rear + 1) % _fm_QUEUE_SZ;

        // Queue is full -> busy wait
        if (next_rear == atomic_load(&q->front))    continue; // busy wait

    } while(!atomic_compare_exchange_weak(&q->rear, &rear, next_rear));

    q->queue[rear] = chnk_id;

    return;
}

/* For circular queue (lock-free) */ 
uint64_t nvme_fm_circular_pop_chnk(struct nvme_fm_circular_queue* q) 
{
    uint32_t front, new_front;

    do 
    {
        front = atomic_load(&q->front);

        // Queue is empty
        if (front == atomic_load(&q->rear))
            return _fm_DEAD_VALUE;
        
        new_front = (front + 1) % _fm_QUEUE_SZ;

    } while(!atomic_compare_exchange_weak(&q->front, &front, new_front));

    return q->queue[front];
}

/* Get pid */
uint16_t nvme_get_fm_pid(uint64_t slba, uint16_t length)
{
    struct nvme_fm_admin_node*     td    = td;     // Need to modify
    struct nvme_fm_circular_queue* sub_q = td->sub_q;  // Need to modify

    uint64_t chnk_id = slba * dev_info.lba_sz / dev_info.chnk_sz;
    uint16_t pid;

    if(slba == td->prev_lba)
        pid =  td->prev_ruhid;

    else
    {
        pid = fm_pids[chnk_id];
        nvme_fm_circular_push_chnk(sub_q, chnk_id);
    }

    td->prev_lba   = slba + length;
    td->prev_ruhid = pid;

    return pid;
}

#ifdef fm_STAT
/* For queue */
void nvme_fm_push_chnk(struct nvme_fm_queue* q, struct nvme_fm_chnk* chnk)
{
    struct nvme_fm_node* temp = (struct nvme_fm_node*)malloc(sizeof(struct nvme_fm_node));

    temp->chnk = chnk;
    temp->next = NULL;

    if(q->head == NULL && q->tail == NULL) 
    {
        q->head = temp;
        q->tail = temp;
        
        return;
    }

    q->tail->next = temp;
    q->tail       = temp;

    return;
}

/* For queue */
struct nvme_fm_chnk* nvme_fm_pop_chnk(struct nvme_fm_queue* q)
{
    if(q->head == NULL && q->tail == NULL)  return NULL; 

    struct nvme_fm_chnk* ret  = q->head->chnk;
    struct nvme_fm_node* temp = q->head;

    if(q->head == q->tail)
    {
        q->head = NULL;
        q->tail = NULL;

        free(temp);
        return ret;
    }

    q->head = q->head->next;

    free(temp);    
    return ret;
}
#endif

/* Update Placement IDs */
void nvme_fm_pid_update(void)
{
    struct timespec current_time;
    uint64_t        cur_id[_FM_UPDATE_BATCH_SZ];
    
    write_lock(&admin_q_lock);

    struct nvme_fm_admin_node* cur = admin_q->head;

    while(cur != NULL)
    {
        struct nvme_fm_circular_queue* cur_q = cur->sub_q;

        uint32_t valid_count = 0;
        
        for(uint32_t i = 0; i < _FM_UPDATE_BATCH_SZ; i++)
        {
            cur_id[i] = nvme_fm_circular_pop_chnk(cur_q);
            if(cur_id[i] >= num_chnk) break;

            valid_count += 1;
        }

        for(uint32_t i = 0; i < valid_count; i++)
        {
            uint64_t             id         =  cur_id[i];
            uint32_t*            cur_fm_pid = &(fm_pids[id]);
            struct nvme_fm_chnk* cur_chnk   = &(chnks[id]);
        
            clock_gettime(CLOCK_MONOTONIC, &current_time);

            cur_chnk->access_cnt += 1;
            cur_chnk->real_cnt   += 1;
            cur_chnk->interval   =  nvme_time_diff(cur_chnk->access_time, current_time);

            uint64_t interval       = cur_chnk->interval;
            uint32_t recency_weight = 1 << interval / decay_period;

            cur_chnk->access_cnt /= recency_weight;
            uint32_t access_cnt  =  cur_chnk->access_cnt;
            uint32_t ruh_id      =  1;

            // log2(access_cnt)
            if (access_cnt > 0 && ruh_id < dev_info.max_ruh) 
                while ((1U << ruh_id) <= access_cnt) ruh_id++;

            *cur_fm_pid = ruh_id;

            cur_chnk->access_time = current_time;

            // For stat
            #ifdef FM_STAT
            struct nvme_fm_chnk* stat_chnk = (struct nvme_fm_chnk*)malloc(sizeof(struct nvme_fm_chnk));

            stat_chnk->fm_pid     = *cur_fm_pid;
            stat_chnk->chnk_id    =  cur_chnk->chnk_id;
            stat_chnk->interval   =  cur_chnk->interval;
            stat_chnk->real_cnt   =  cur_chnk->real_cnt;
            stat_chnk->access_cnt =  cur_chnk->access_cnt;

            nvme_fm_push_chnk(cur->stat_q, stat_chnk);
            #endif
        }

        cur = cur->next;
    }

    write_unlock(&admin_q_lock);

    return;    
}

/* Init td */ // Need to modify
struct nvme_fm_admin_node* nvme_fm_td_init(void)
{
    struct nvme_fm_admin_node* ret = kmalloc(sizeof(struct nvme_fm_admin_node), GFP_KERNEL);
    if(!ret) return -ENOMEM;

    ret->sub_q        = kmalloc(sizeof(struct nvme_fm_circular_queue), GFP_KERNEL);
    if(!ret->sub_q) return -ENOMEM;

    ret->sub_q->front = 0;
    ret->sub_q->rear  = 0;

    ret->prev = NULL;
    ret->next = NULL;

    ret->prev_ruhid = 1;

    write_lock(&admin_q_lock);

    if(admin_q->tail) 
    {
        ret->prev           = admin_q->tail;
        admin_q->tail->next = ret;
    } 

    else 
        admin_q->head = ret;

    admin_q->tail = ret;

    write_unlock(&admin_q_lock);

    #ifdef FM_STAT
    ret->stat_q = kmalloc(sizeof(struct nvme_fm_queue), GFP_KERNEL);

    ret->stat_q->head = NULL;
    ret->stat_q->tail = NULL;
    #endif

    return ret;
}

/* Dispose td */
void nvme_fm_td_dispose(struct nvme_fm_admin_node* fm_td)
{
    struct nvme_fm_admin_node* cur_node = fm_td;
    
    write_lock(&admin_q_lock);
    if (cur_node->prev)
        cur_node->prev->next = cur_node->next;
    else
        g_fm->admin_q->head = cur_node->next;

    if (cur_node->next)
        cur_node->next->prev = cur_node->prev;
    else
        g_fm->admin_q->tail = cur_node->prev;

    write_unlock(&admin_q_lock);

    #ifdef fm_STAT
    nvme_fm_stat(cur_node->stat_q);
    kfree(cur_node->stat_q);
    #endif
    
    kfree(cur_node->sub_q);
    kfree(cur_node);

    return;
}

/* define thread */
void* fm_update_thread(void*)
{
    while(!kthread_should_stop())
    {
        if(chnks)
            nvme_fm_pid_update(); 
            // ssleep(1);
    }

    return NULL;
}

/* nvme_setup_cmd hooking */
static int handler_pre(struct kprobe* p, struct pt_regs* regs)
{
    struct nvme_command* cmd;
    uint16_t             pid;
    
    cmd = (struct nvme_command*)regs->si;
    pid = nvme_get_fm_pid(cmd->slba, cmd->length);

    cmd->dspec = pid;

    return 0;
}

/* Module init */
static char dev_info_str[100] = "";
module_param_string(dev_info, dev_info_str, sizeof(dev_info_str), 0644);
MODULE_PARM_DESC(dev_info, "Device info: tbytes:lba_sz:chnk_sz:max_ruh:decay_period");

static int __init fdp_module_init(void)
{
    int ret, i;

    printk(KERN_INFO "Module init: Received dev_info_str = %s\n", dev_info_str);
    ret = sscanf(dev_info_str, "%llu:%llu:%llu:%hu:%llu",
                 &dev_info.tbytes, &dev_info.lba_sz, &dev_info.chnk_sz,
                 &dev_info.max_ruh, &dev_info.decay_period);

    if (ret != 5) 
    {
        printk(KERN_ERR "Invalid dev_info format! Expected: tbytes:lba_sz:chnk_sz:max_ruh:decay_period\n");
        return -EINVAL;
    }

    printk(KERN_INFO "Device information:\n");
    printk(KERN_INFO "  tbytes       = %llu\n", dev_info.tbytes);
    printk(KERN_INFO "  lba_sz       = %llu\n", dev_info.lba_sz);
    printk(KERN_INFO "  chnk_sz      = %llu\n", dev_info.chnk_sz);
    printk(KERN_INFO "  max_ruh      = %hu\n", dev_info.max_ruh);
    printk(KERN_INFO "  decay_period = %llu\n", dev_info.decay_period);

    num_chnk = dev_info.tbytes/dev_info.chnk_sz + 1;
    chnks    = kmalloc(num_chnk * sizeof(struct nvme_fm_chnk), GFP_KERNEL);
    if(!chnks) return -ENOMEM;
    fm_pids  = kmalloc(num_chnk * sizeof(uint32_t), GFP_KERNEL);
    if(!fm_pids) return -ENOMEM;

    nvme_fm_dp_decision();

    for(uint64_t i = 0; i < num_chnk; i++) 
    {
        chnks[i].chnk_id    = i;
        chnks[i].real_cnt   = 0;
        chnks[i].access_cnt = 0;

        chnks[i].access_time.tv_sec  = current_time.tv_sec;
        chnks[i].access_time.tv_nsec = current_time.tv_nsec;

        fm_pids[i] = 1;
    }

    admin_q = kmalloc(sizeof(struct nvme_fm_admin_q), GFP_KERNEL);
    if(!admin_q) return -ENOMEM;

    admin_q->head = NULL;
    admin_q->tail = NULL;

    update_thread = kthread_run(fm_update_thread, NULL, "fm_update_thread");
    if(IS_ERR(update_thread))   return PTR_ERR(update_thread);

    kp.symbol_name = "nvme_setup_rw";
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if(ret < 0)
    {
        printk(KERN_ERR "Failed to register kprobe: %d\n", ret);
        kthread_stop(update_thread);

        kfree(chnks);
        kfree(fm_pids);

        return ret;
    }

    printk(KERN_INFO "FDP Module loaded: update_thread and nvme_setup_rw hooking\n");

    return 0;
}

/* Module exit */
static void __exit fdp_module_exit(void)
{
    if(update_thread)
        kthread_stop(update_thread);

    unregister_kprobe(&kp);

    kfree(chnks);
    kfree(fm_pids);

    printk(KERN_INFO "FDP Module unloaded\n");
}

module_init(fdp_module_init);
module_exit(fdp_module_exit);
MODULE_LICENSE("GPL");