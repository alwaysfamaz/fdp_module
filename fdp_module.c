#include "fdp_module.h"
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/blk_types.h>

/* -------------------------------------------------
 * Module parameters
 * -------------------------------------------------
 */

/* Which halfword in CDW13 to use for PID:
 *  true  => write PID in high 16 bits (NvmeVirt behavior)
 *  false => write PID in low 16 bits (FDP spec / real device)
 */
static bool dspec_hi16 = true;
module_param(dspec_hi16, bool, 0644);
MODULE_PARM_DESC(dspec_hi16,
    "Write DSPEC in CDW13: 1=high 16 bits (NvmeVirt), 0=low 16 bits (FDP spec)");

/* Device description string: tbytes:lba_sz:chnk_sz:max_ruh:decay_period */
static char dev_info_str[100] = "";
module_param_string(dev_info, dev_info_str, sizeof(dev_info_str), 0644);
MODULE_PARM_DESC(dev_info,
    "tbytes:lba_sz:chnk_sz:max_ruh:decay_period");

/* -------------------------------------------------
 * Global state (module scope)
 * -------------------------------------------------
 */
static struct nvme_fm_admin_q *admin_q;
static struct nvme_dev_info    dev_info;
static struct nvme_fm_chnk    *chnks;
static struct task_struct     *update_thread;
static struct kretprobe        krp;        /* kretprobe for nvme_setup_cmd */
static u16                    *fm_pids;
static u64                     decay_period; /* in ns */
static u64                     num_chnk;
static rwlock_t                admin_q_lock;

#ifdef FM_DEBUG
static struct kobject *fdp_kobj;
static char            fdp_debug_buf[256];
static DEFINE_SPINLOCK(fdp_debug_lock);
#endif

/* -------------------------------------------------
 * Helpers for NVMe command modification
 * -------------------------------------------------
 */

/* Set DTYPE=1 (Data Placement Directive) in RW command's CDW12[23:20].
 * Our nvme_rw_command has .control (__le16), but we treat CDW12 as 32 bits.
 */
static inline void nvme_rw_set_dtype_dp(struct nvme_rw_command *rw)
{
    u32 dw12 = le32_to_cpu(rw->control);   /* CDW12 */
    dw12 &= ~(0xFu << 20);                 /* clear [23:20] */
    dw12 |=  (0x1u << 20);                 /* DTYPE=1 => data placement */
    rw->control = cpu_to_le32(dw12);
}

/* Place PID into CDW13 (DSPEC).
 * We support two layouts:
 *   - Emulator (NvmeVirt): PID in the high 16 bits
 *   - "Spec": PID in the low 16 bits
 */
static inline void nvme_rw_set_dspec(struct nvme_rw_command *rw, u16 pid)
{
    u32 dsm = le32_to_cpu(rw->dsmgmt);  /* CDW13 */
    if (dspec_hi16) 
    {
        /* Emulator expects PID in bits [31:16] */
        dsm = (dsm & 0x0000FFFFu) | ((u32)pid << 16);
    } 
    else 
    {
        /* Spec-compliant: PID in bits [15:0] */
        dsm = (dsm & 0xFFFF0000u) | (pid & 0xFFFFu);
    }
    rw->dsmgmt = cpu_to_le32(dsm);
}

/* Decide decay_period in ns from dev_info.decay_period in seconds */
void nvme_fm_dp_decision(void)
{
    decay_period = dev_info.decay_period * 1000000000ULL; /* sec -> nsec */
}

/* timespec64 diff in ns */
u64 nvme_time_diff(struct timespec64 t1, struct timespec64 t2)
{
    /* t2 - t1 in ns, handling borrow on tv_nsec */
    if (t2.tv_nsec >= t1.tv_nsec)
        return (t2.tv_sec - t1.tv_sec) * 1000000000ULL
             + (t2.tv_nsec - t1.tv_nsec);
    else
        return (t2.tv_sec - t1.tv_sec - 1) * 1000000000ULL
             + (1000000000ULL + t2.tv_nsec - t1.tv_nsec);
}

/* -------------------------------------------------
 * Lock-free circular queue
 * -------------------------------------------------
 */
void nvme_fm_circular_push_chnk(struct nvme_fm_circular_queue *q, u64 chnk_id)
{
    u32 rear, next_rear;

    do 
    {
        rear = atomic_read(&q->rear);
        next_rear = (rear + 1) % _FM_QUEUE_SZ;
        /* queue full? spin */
        if (next_rear == atomic_read(&q->front)) 
        {
            cpu_relax();
            continue;
        }
    } while (atomic_cmpxchg(&q->rear, rear, next_rear) != rear);

    q->queue[rear] = chnk_id;
}

u64 nvme_fm_circular_pop_chnk(struct nvme_fm_circular_queue *q)
{
    u32 front, new_front;

    do 
    {
        front = atomic_read(&q->front);
        /* empty? */
        if (front == atomic_read(&q->rear))
            return _FM_DEAD_VALUE;
        new_front = (front + 1) % _FM_QUEUE_SZ;
    } while (atomic_cmpxchg(&q->front, front, new_front) != front);

    return q->queue[front];
}

/* -------------------------------------------------
 * Stats queue (optional)
 * -------------------------------------------------
 */
#ifdef FM_STAT
void nvme_fm_push_chnk(struct nvme_fm_queue *q, struct nvme_fm_chnk *chnk)
{
    struct nvme_fm_node *n = kmalloc(sizeof(*n), GFP_KERNEL);
    if (!n)
        return;
    n->chnk = chnk;
    n->next = NULL;

    if (!q->head) 
    {
        q->head = q->tail = n;
        return;
    }
    q->tail->next = n;
    q->tail = n;
}

struct nvme_fm_chnk *nvme_fm_pop_chnk(struct nvme_fm_queue *q)
{
    struct nvme_fm_node *t;
    struct nvme_fm_chnk *ret;

    if (!q->head)
        return NULL;

    t   = q->head;
    ret = t->chnk;

    q->head = t->next;
    if (!q->head)
        q->tail = NULL;

    kfree(t);
    return ret;
}
#endif /* FM_STAT */

/* -------------------------------------------------
 * PID selection logic
 * -------------------------------------------------
 */
u16 nvme_get_fm_pid(u64 slba, u16 length)
{
    struct nvme_fm_admin_node     *td;
    struct nvme_fm_circular_queue *sub_q;

    u64 chnk_id;
    u16 pid = 0;

    read_lock(&admin_q_lock);
    if (!admin_q || !(td = admin_q->head)) 
    {
        read_unlock(&admin_q_lock);
        return _FM_DEAD_VALUE;
    }

    sub_q   = td->sub_q;
    chnk_id = slba * dev_info.lba_sz / dev_info.chnk_sz;

    if (slba == td->prev_lba) 
    {
        /* sequential continuation => reuse RUH */
        pid = td->prev_ruhid;
    }  
    else 
    {
        /* first access to that chunk in a while */
        pid = fm_pids[chnk_id];
        nvme_fm_circular_push_chnk(sub_q, chnk_id);
    }
    read_unlock(&admin_q_lock);

    /* update prev_* under write lock */
    write_lock(&admin_q_lock);
    td->prev_lba   = slba + length;
    td->prev_ruhid = pid;
    write_unlock(&admin_q_lock);

    // pr_info("[FDP] Returning pid=%u for slba=%llu\n", pid, slba);
    return pid;
}

/* -------------------------------------------------
 * Periodic fm_pids update thread logic
 * -------------------------------------------------
 */
void nvme_fm_pid_update(void)
{
    struct timespec64 current_time;
    u64 cur_id[_FM_UPDATE_BATCH_SZ];
    struct nvme_fm_admin_node *cur;

    read_lock(&admin_q_lock);
    cur = admin_q ? admin_q->head : NULL;
    read_unlock(&admin_q_lock);

    while (cur != NULL) 
    {
        struct nvme_fm_circular_queue *cur_q = cur->sub_q;
        u32 valid = 0;

        /* gather up to _FM_UPDATE_BATCH_SZ chunk IDs */
        for (u32 i = 0; i < _FM_UPDATE_BATCH_SZ; i++) 
        {
            u64 id = nvme_fm_circular_pop_chnk(cur_q);
            if (id == _FM_DEAD_VALUE)
                break;
            if (id >= num_chnk)
                continue;
            cur_id[valid++] = id;
        }

        if (valid) 
        {
            write_lock(&admin_q_lock);
            for (u32 i = 0; i < valid; i++) 
            {
                u64 id = cur_id[i];
                u16 *cur_fm_pid          = &fm_pids[id];
                struct nvme_fm_chnk *cch = &chnks[id];

                ktime_get_ts64(&current_time);

                /* update stats */
                cch->real_cnt   += 1;
                cch->access_cnt += 1;
                cch->interval    = nvme_time_diff(cch->access_time, current_time);

                /* apply decay based on recency */
                if (likely(decay_period)) 
                {
                    u64 interval  = cch->interval;           /* ns since last */
                    u64 n         = interval / decay_period; /* steps elapsed */
                    u32 shift     = (u32)(n > 31 ? 31 : n);  /* clamp 0..31 */
                    u32 weight    = 1U << shift;             /* >=1 */

                    if (weight > 1)
                        cch->access_cnt /= weight;
                }

                /* choose RUH bin ~= log2(access_cnt) */
                {
                    u32 access_cnt = cch->access_cnt;
                    u32 ruh_id     = (access_cnt > 0)
                                   ? (31 - __builtin_clz(access_cnt))
                                   : 1;
                    *cur_fm_pid    = ruh_id;
                    // pr_info("[FDP] pid=%u, access_cnt=%u\n", *cur_fm_pid, access_cnt);
                }

                cch->access_time = current_time;

#ifdef FM_STAT
                {
                    struct nvme_fm_chnk *snap = kmalloc(sizeof(*snap), GFP_KERNEL);

                    if (snap) 
                    {
                        snap->chnk_id    = cch->chnk_id;
                        snap->interval   = cch->interval;
                        snap->real_cnt   = cch->real_cnt;
                        snap->access_cnt = cch->access_cnt;
                        snap->fm_pid     = *cur_fm_pid;
                        nvme_fm_push_chnk(cur->stat_q, snap);
                    }
                }
#endif
            }
            write_unlock(&admin_q_lock);
        }

        read_lock(&admin_q_lock);
        cur = cur->next;
        read_unlock(&admin_q_lock);
    }
}

/* -------------------------------------------------
 * Admin-thread node (per "stream") management
 * -------------------------------------------------
 */
struct nvme_fm_admin_node *nvme_fm_td_init(void)
{
    struct nvme_fm_admin_node *ret;

    ret = kmalloc(sizeof(*ret), GFP_KERNEL);
    if (!ret)
        return NULL;

    ret->sub_q = kmalloc(sizeof(struct nvme_fm_circular_queue), GFP_KERNEL);
    if (!ret->sub_q) 
    {
        kfree(ret);
        return NULL;
    }

    atomic_set(&ret->sub_q->front, 0);
    atomic_set(&ret->sub_q->rear,  0);

    ret->prev_ruhid = 1;
    ret->prev_lba   = 0;
    ret->prev       = NULL;
    ret->next       = NULL;

#ifdef FM_STAT
    ret->stat_q = kmalloc(sizeof(struct nvme_fm_queue), GFP_KERNEL);
    if (ret->stat_q) 
    {
        ret->stat_q->head = NULL;
        ret->stat_q->tail = NULL;
    }
#endif

    write_lock(&admin_q_lock);
    if (!admin_q) 
    {
        write_unlock(&admin_q_lock);
        kfree(ret->sub_q);
        kfree(ret);
        return NULL;
    }

    if (admin_q->tail) 
    {
        ret->prev = admin_q->tail;
        admin_q->tail->next = ret;
        admin_q->tail = ret;
    } 
    else 
    {
        admin_q->head = admin_q->tail = ret;
    }
    write_unlock(&admin_q_lock);

    return ret;
}

void nvme_fm_td_dispose(struct nvme_fm_admin_node *fm_td)
{
    struct nvme_fm_admin_node *node = fm_td;
    if (!node)
        return;

    write_lock(&admin_q_lock);
    if (node->prev)
        node->prev->next = node->next;
    else if (admin_q)
        admin_q->head = node->next;

    if (node->next)
        node->next->prev = node->prev;
    else if (admin_q)
        admin_q->tail = node->prev;
    write_unlock(&admin_q_lock);

#ifdef FM_STAT
    if (node->stat_q) 
    {
        nvme_fm_stat(node->stat_q);
        kfree(node->stat_q);
    }
#endif

    kfree(node->sub_q);
    kfree(node);
}

/* background updater thread */
int fm_update_thread(void *data)
{
    while (!kthread_should_stop()) 
    {
        if (chnks)
            nvme_fm_pid_update();
        msleep(1);
    }
    return 0;
}

/* -------------------------------------------------
 * kretprobe for nvme_setup_cmd(ns, req)
 * -------------------------------------------------
 *
 * nvme_setup_cmd(ns, req):
 *   x86_64: rdi = ns, rsi = req
 *   arm64 : x0  = ns, x1  = req
 *
 * We'll stash the request* at entry, and on return we
 * rewrite its nvme_command before it's actually issued.
 */

struct probe_ctx 
{
    struct request *req;
};

static inline struct request *get_req_from_regs(struct pt_regs *regs)
{
#if defined(CONFIG_X86_64)
    return (struct request *)regs->si;       /* 2nd arg */
#elif defined(CONFIG_ARM64)
    return (struct request *)regs->regs[1];  /* 2nd arg */
#else
# error "Add calling convention for your arch"
#endif
}

static int setup_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probe_ctx *ctx = (struct probe_ctx *)&ri->data;

#if defined(CONFIG_X86_64)
    void *arg0 = (void *)regs->di;
    void *arg1 = (void *)regs->si;
    ctx->req = (struct request *)arg1;

#elif defined(CONFIG_ARM64)
    void *arg0 = (void *)regs->regs[0];
    void *arg1 = (void *)regs->regs[1];
    ctx->req = (struct request *)arg1;
#else
# error "Add calling convention for your arch"
#endif

#ifdef FM_DEBUG
    pr_info("FDP setup_entry: nvme_setup_cmd(arg0=%p, arg1=%p) -> saved req=%p\n",
            arg0, arg1, ctx->req);
#endif /* FM_DEBUG */

    return 0;
}

static int setup_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probe_ctx *ctx = (struct probe_ctx *)&ri->data;
    struct request *req = ctx->req;
    void *pdu;
    int op;

    if (!req)
        return 0;

    op = req_op(req);

    if (op != REQ_OP_WRITE)
        return 0;

    pdu = blk_mq_rq_to_pdu(req);
    if (!pdu)
        return 0;

    {
        u8 *base = (u8 *)pdu;
        unsigned int off = 40;  /* <-- magic offset */

        struct nvme_command *cmd = (struct nvme_command *)(base + off);
        u8 opc = cmd->common.opcode;

        if (opc == nvme_cmd_write) 
        {
            struct nvme_rw_command *rw = &cmd->rw;

            u64 slba  = le64_to_cpu(rw->slba);
            u16 nlb0  = le16_to_cpu(rw->length); /* 0-based */
            u16 pid   = nvme_get_fm_pid(slba, (u16)(nlb0 + 1));

            /* DTYPE=1 (Data Placement) in CDW12 */
            nvme_rw_set_dtype_dp(rw);

            /* DSPEC <- pid (hi16 or lo16 depending on module param) */
            nvme_rw_set_dspec(rw, pid);

#ifdef FM_DEBUG
            {
                u32 cdw12 = le32_to_cpu(rw->control);
                u32 cdw13 = le32_to_cpu(rw->dsmgmt);
                pr_info("FDP inject: off=%u slba=%llu len=%u pid=%u cdw12=0x%08x cdw13=0x%08x hi16=%d\n",
                        off, slba, (unsigned)(nlb0 + 1), pid,
                        cdw12, cdw13, dspec_hi16);
            }
#endif /* FM_DEBUG */
        } 

        else 
        {
            pr_info("FDP warn: off=40 opcode=0x%x != nvme_cmd_write(0x%x)\n", opc, nvme_cmd_write);
        }
    }

    return 0;
}

/* -------------------------------------------------
 * FM_DEBUG sysfs support
 * -------------------------------------------------
 */
#ifdef FM_DEBUG
static struct kobj_attribute fdp_debug_attr =
    __ATTR(fdp_debug, 0444, fdp_debug_show, NULL);

ssize_t fdp_debug_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
    ssize_t ret;
    spin_lock(&fdp_debug_lock);
    ret = scnprintf(buf, sizeof(fdp_debug_buf), "%s\n", fdp_debug_buf);
    spin_unlock(&fdp_debug_lock);
    return ret;
}

void fdp_debug_log(const char *fmt, ...)
{
    va_list args;

    spin_lock(&fdp_debug_lock);
    va_start(args, fmt);
    vsnprintf(fdp_debug_buf, sizeof(fdp_debug_buf), fmt, args);
    va_end(args);
    spin_unlock(&fdp_debug_lock);
}
#endif /* FM_DEBUG */

/* -------------------------------------------------
 * Module init / exit
 * -------------------------------------------------
 */
static int __init fdp_module_init(void)
{
    int               ret;
    struct timespec64 now;

    pr_info("FDP: dev_info = %s\n", dev_info_str);

    ret = sscanf(dev_info_str, "%llu:%llu:%llu:%hu:%llu",
                 &dev_info.tbytes,
                 &dev_info.lba_sz,
                 &dev_info.chnk_sz,
                 &dev_info.max_ruh,
                 &dev_info.decay_period);
    
    if (ret != 5) 
    {
        pr_err("FDP: invalid dev_info. expected tbytes:lba_sz:chnk_sz:max_ruh:decay_period\n");
        return -EINVAL;
    }

    pr_info("FDP dev: tbytes=%llu lba_sz=%llu chnk_sz=%llu max_ruh=%hu decay=%llus\n",
            dev_info.tbytes, dev_info.lba_sz, dev_info.chnk_sz,
            dev_info.max_ruh, dev_info.decay_period);

    pr_info("FDP: DSPEC mode = %s (dspec_hi16=%d)\n",
            dspec_hi16 ? "HIGH16 (emulator)" : "LOW16 (spec)",
            dspec_hi16);

    rwlock_init(&admin_q_lock);

    num_chnk = dev_info.tbytes / dev_info.chnk_sz + 1;
    chnks    = kmalloc_array(num_chnk, sizeof(*chnks), GFP_KERNEL);
    if (!chnks)
        return -ENOMEM;

    fm_pids  = kmalloc_array(num_chnk, sizeof(*fm_pids), GFP_KERNEL);
    if (!fm_pids) 
    {
        kfree(chnks);
        return -ENOMEM;
    }

    nvme_fm_dp_decision();  /* set decay_period(ns) */

    ktime_get_ts64(&now);
    for (u64 i = 0; i < num_chnk; i++)
    {
        chnks[i].chnk_id      = i;
        chnks[i].real_cnt     = 0;
        chnks[i].access_cnt   = 0;
        chnks[i].access_time  = now;
        chnks[i].interval     = 0;
        fm_pids[i]            = 1;
    }

    admin_q = kmalloc(sizeof(*admin_q), GFP_KERNEL);
    if (!admin_q) 
    {
        kfree(fm_pids);
        kfree(chnks);
        return -ENOMEM;
    }
    admin_q->head = NULL;
    admin_q->tail = NULL;

    /* Start periodic updater thread */
    update_thread = kthread_run(fm_update_thread, NULL, "fm_update_thread");
    if (IS_ERR(update_thread)) 
    {
        ret = PTR_ERR(update_thread);
        kfree(admin_q);
        kfree(fm_pids);
        kfree(chnks);
        return ret;
    }

    /* Create one admin node for now */
    if (!nvme_fm_td_init()) 
    {
        kthread_stop(update_thread);
        kfree(admin_q);
        kfree(fm_pids);
        kfree(chnks);
        return -ENOMEM;
    }

    /* Register kretprobe on nvme_setup_cmd */
    memset(&krp, 0, sizeof(krp));
    krp.entry_handler  = setup_entry;
    krp.handler        = setup_ret;
    krp.data_size      = sizeof(struct probe_ctx);
    krp.maxactive      = 128;
    krp.kp.symbol_name = "nvme_setup_cmd";

    ret = register_kretprobe(&krp);
    if (ret < 0) 
    {
        pr_err("FDP: register_kretprobe(nvme_setup_cmd) failed: %d\n", ret);
        kthread_stop(update_thread);
        kfree(admin_q);
        kfree(fm_pids);
        kfree(chnks);
        return ret;
    }

    pr_info("FDP: kretprobe attached to nvme_setup_cmd\n");

#ifdef FM_DEBUG
    fdp_kobj = kobject_create_and_add("fdp_module", kernel_kobj);
    if (!fdp_kobj) 
    {
        unregister_kretprobe(&krp);
        kthread_stop(update_thread);
        kfree(admin_q);
        kfree(fm_pids);
        kfree(chnks);
        return -ENOMEM;
    }

    if (sysfs_create_file(fdp_kobj, &fdp_debug_attr.attr)) 
    {
        sysfs_remove_file(fdp_kobj, &fdp_debug_attr.attr);
        kobject_put(fdp_kobj);
        unregister_kretprobe(&krp);
        kthread_stop(update_thread);
        kfree(admin_q);
        kfree(fm_pids);
        kfree(chnks);
        return -ENOMEM;
    }
#endif

    pr_info("FDP Module loaded: kretprobe nvme_setup_cmd + updater thread\n");
    return 0;
}

static void __exit fdp_module_exit(void)
{
    if (update_thread)
        kthread_stop(update_thread);

    unregister_kretprobe(&krp);

#ifdef FM_DEBUG
    if (fdp_kobj) 
    {
        sysfs_remove_file(fdp_kobj, &fdp_debug_attr.attr);
        kobject_put(fdp_kobj);
    }
#endif

    kfree(chnks);
    kfree(fm_pids);
    kfree(admin_q);

    pr_info("FDP Module unloaded\n");
}

module_init(fdp_module_init);
module_exit(fdp_module_exit);

MODULE_LICENSE("GPL");
