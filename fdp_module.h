#ifndef __FDP_MODULE_H__
#define __FDP_MODULE_H__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/kprobes.h>     /* kprobe / kretprobe */
#include <linux/nvme.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/blk-mq.h>      /* blk_mq_rq_to_pdu */
#include <linux/bug.h>

#ifdef FM_DEBUG
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/spinlock.h>
#endif

/* =========================
 * Tunables / constants
 * =========================
 */
#define _FM_WDSZ             4U
#define _FM_QUEUE_SZ         256U
#define _FM_DEAD_VALUE       0xDEAD  /* magic number for empty pop */
#define _FM_MAX_THREAD_NUM   8U
#define _FM_UPDATE_BATCH_SZ  1U

/*
 * We assume the per-request driver-private area starts with a command
 * we can rewrite before submission. This mirrors the prior working approach
 * you used with nvme_setup_cmd().
 *
 * IMPORTANT:
 * If this ever mismatches the kernel's actual request layout, we may need
 * to adjust (e.g. via pahole to get struct layout / offset).
 */
struct nvme_req_pdu_head 
{
    struct nvme_command cmd;
};

/* =========================
 * FDP global state
 * =========================
 * These are module-scoped globals. We keep them 'static' in the .c, not here.
 * So here we only declare them 'extern'.
 */
struct nvme_dev_info 
{
    u64 tbytes;        /* bytes total */
    u64 lba_sz;        /* bytes per LBA */
    u64 chnk_sz;       /* bytes per "chunk" */
    u16 max_ruh;       /* #RUHs per RG */
    u64 decay_period;  /* seconds */
};

struct nvme_fm_chnk 
{
#ifdef FM_STAT
    u32 fm_pid;
#endif
    u64               chnk_id;      /* sLBA / chnk_size */
    u64               interval;     /* ns */
    u32               real_cnt;     /* raw access count */
    u32               access_cnt;   /* access count */
    struct timespec64 access_time;  /* last access time */
};

struct nvme_fm_circular_queue 
{
    u64      queue[_FM_QUEUE_SZ];
    atomic_t front;
    atomic_t rear;
};

struct nvme_fm_admin_node 
{
    struct nvme_fm_circular_queue *sub_q;

    u64 prev_lba;
    u32 prev_ruhid;

    struct nvme_fm_admin_node *prev;
    struct nvme_fm_admin_node *next;

#ifdef FM_STAT
    struct nvme_fm_queue *stat_q;
#endif
};

struct nvme_fm_admin_q 
{
    struct nvme_fm_admin_node *head;
    struct nvme_fm_admin_node *tail;
};

/* For update-thread statistics (optional) */
#ifdef FM_STAT
struct nvme_fm_node 
{
    struct nvme_fm_chnk *chnk;
    struct nvme_fm_node *next;
};

struct nvme_fm_queue 
{
    struct nvme_fm_node *head;
    struct nvme_fm_node *tail;
};
#endif /* FM_STAT */


/* =========================
 * Function prototypes
 * =========================
 */

/* time helpers */
u64  nvme_time_diff(struct timespec64 t1, struct timespec64 t2);

/* circular queue ops */
u64  nvme_fm_circular_pop_chnk(struct nvme_fm_circular_queue *q);
void nvme_fm_circular_push_chnk(struct nvme_fm_circular_queue *q, u64 chnk_id);

/* admin node lifecycle */
struct nvme_fm_admin_node *nvme_fm_td_init(void);
void                       nvme_fm_td_dispose(struct nvme_fm_admin_node *fm_td);

/* PID selection + update */
u16  nvme_get_fm_pid(u64 slba, u16 length);
void nvme_fm_pid_update(void);

/* background update thread */
int  fm_update_thread(void *data);

/* decay time decision */
void nvme_fm_dp_decision(void);

/* stats helpers if enabled */
#ifdef FM_STAT
void                 nvme_fm_stat(struct nvme_fm_queue *stat_q);
struct nvme_fm_chnk *nvme_fm_pop_chnk(struct nvme_fm_queue *q);
void                 nvme_fm_push_chnk(struct nvme_fm_queue *q,
                                       struct nvme_fm_chnk *chnk);
#endif /* FM_STAT */

#ifdef FM_DEBUG
/* sysfs debug exports */
ssize_t fdp_debug_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
void    fdp_debug_log(const char *fmt, ...);
#endif /* FM_DEBUG */

/* module init/exit */
static int  __init fdp_module_init(void);
static void __exit fdp_module_exit(void);

#endif /* __FDP_MODULE_H__ */
