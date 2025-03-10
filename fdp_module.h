#ifndef __FDP_MODULE_H__
#define __FDP_MODULE_H__

// #ifndef FM_STAT
// #define FM_STAT
// #endif

#ifndef FM_DEBUG
#define FM_DEBUG
#endif

#include <linux/module.h>      
#include <linux/kernel.h>      
#include <linux/init.h>        
#include <linux/moduleparam.h> 
#include <linux/sched.h>       
#include <linux/delay.h>       
#include <linux/kthread.h>     
#include <linux/rwlock.h>      
#include <linux/slab.h>        
#include <linux/kprobes.h>     
#include <linux/nvme.h>       
#include <linux/timekeeping.h>  
#include <linux/ktime.h>      
#include <linux/atomic.h>  

#ifdef FM_DEBUG
#include <linux/kobject.h>  
#include <linux/sysfs.h>  
#endif

/* Parameters */
#define _FM_WDSZ             4U             
// #define _FM_DEV_SZ           107373363200ULL // NVMeVirt (128GB)
// #define _FM_DEV_SZ           1000204886016ULL // Real device (1TB)  
// #define _FM_LBA_SZ           512ULL
// #define _FM_CHNK_SZ          (2*1024*1024ULL) // 2MiB
// #define _FM_MAX_RUH          15U              // 16 (0~15)
#define _FM_QUEUE_SZ         256U
#define _FM_DEAD_VALUE       0xDEAD       // magic number
// #define _FM_DECAY_PERIOD     10ULL            // sec
#define _FM_MAX_THREAD_NUM   8U
#define _FM_UPDATE_BATCH_SZ  1U

/* For use fm */ 
static struct nvme_fm_admin_q* admin_q       __attribute__((unused));
static struct nvme_dev_info    dev_info      __attribute__((unused));
static struct nvme_fm_chnk*    chnks         __attribute__((unused));
static struct task_struct*     update_thread __attribute__((unused));
static struct kprobe           kp            __attribute__((unused));
static uint16_t*               fm_pids       __attribute__((unused));
static uint64_t                decay_period  __attribute__((unused));
static uint64_t                num_chnk      __attribute__((unused));
static rwlock_t                admin_q_lock  __attribute__((unused));

struct nvme_dev_info
{
    uint64_t tbytes;       // bytes
    uint64_t lba_sz;       // bytes
    uint64_t chnk_sz;      // bytes
    uint16_t max_ruh;    
    uint64_t decay_period; // seconds
};

struct nvme_fm_chnk
{
    #ifdef FM_STAT
    uint32_t fm_pid;
    #endif

    uint64_t chnk_id;     // sLBA/chnk_size
    uint64_t interval;
    uint32_t real_cnt;
    uint32_t access_cnt;
    
    struct timespec64 access_time;
};

struct nvme_fm_circular_queue 
{
    uint64_t queue[_FM_QUEUE_SZ];

    atomic_t front;
    atomic_t rear;
};

struct nvme_fm_admin_node 
{
    struct nvme_fm_circular_queue* sub_q;

    uint64_t prev_lba;
    uint32_t prev_ruhid;

    struct nvme_fm_admin_node* prev;      
    struct nvme_fm_admin_node* next;    

    /* For stat */
    #ifdef FM_STAT
    struct nvme_fm_queue* stat_q;
    #endif
};

struct nvme_fm_admin_q 
{
    struct nvme_fm_admin_node* head;
    struct nvme_fm_admin_node* tail;
};

uint64_t nvme_time_diff(struct timespec64 t1, struct timespec64 t2);
uint64_t nvme_fm_circular_pop_chnk(struct nvme_fm_circular_queue* q);
void     nvme_fm_circular_push_chnk(struct nvme_fm_circular_queue* q, uint64_t chnk_id);

struct nvme_fm_admin_node* nvme_fm_td_init(void);
void                       nvme_fm_td_dispose(struct nvme_fm_admin_node* fm_td);

uint16_t nvme_get_fm_pid(uint64_t slba, uint16_t length);
void     nvme_fm_pid_update(void);
int      fm_update_thread(void* data);

static int  handler_pre(struct kprobe* p, struct pt_regs* regs);
static int  __init fdp_module_init(void);
static void __exit fdp_module_exit(void);

/* TODO: to decision the decay time */
void nvme_fm_dp_decision(void);

#ifdef FM_STAT

struct nvme_fm_node
{
    struct nvme_fm_chnk* chnk;
    struct nvme_fm_node* next;
};

struct nvme_fm_queue
{
    struct nvme_fm_node* head;
    struct nvme_fm_node* tail;
};

void                 nvme_fm_stat(struct nvme_fm_queue* stat_q);
struct nvme_fm_chnk* nvme_fm_pop_chnk(struct nvme_fm_queue* q);
void                 nvme_fm_push_chnk(struct nvme_fm_queue* q, struct nvme_fm_chnk* chnk);
#endif /* FM_STAT */

#ifdef FM_DEBUG
static struct kobject *fdp_kobj;  // sysfs 객체
static char fdp_debug_buf[256];   // 출력 버퍼
static DEFINE_SPINLOCK(fdp_debug_lock);  // 동기화용 spinlock
static ssize_t fdp_debug_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static void fdp_debug_log(const char *fmt, ...);
#endif

#endif /* __FDP_MODULE_H__*/
