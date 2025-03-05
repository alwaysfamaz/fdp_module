#include <stdatomic.h>

#include "spdk/nvme_sfr.h"
#include "nvme_internal.h"
#include "spdk/stdinc.h"
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/rwlock.h>
#include <linux/slab.h>
#include <linux/nvme.h>
#include <linux/sched.h>
#include "fdp_module.h"

// #define NDEBUG
#ifdef SFR_APPLY

/* Return interval (nsec) */
uint64_t nvme_time_diff(struct timespec t1, struct timespec t2) 
{
    return (t2.tv_nsec >= t1.tv_nsec) 
            ? (t2.tv_sec - t1.tv_sec) * 1e9 + (t2.tv_nsec - t1.tv_nsec)
            : (t2.tv_sec - t1.tv_sec - 1) * 1e9 + (1e9 + t2.tv_nsec - t1.tv_nsec);
}

#ifdef SFR_STAT
/* 
    Write log file [chnk_id,ruh_id,interval,access_cnt,real_cnt]
*/
void nvme_sfr_stat(struct nvme_sfr_queue* stat_q)
{
    FILE* log_fp;
    struct nvme_sfr_chnk* cur = NULL;

    log_fp = fopen("log_temp.csv", "a");
    fprintf(log_fp, "*** stat start ***\n");
    fprintf(log_fp, "chnk_id,ruh_id,interval,access_cnt,real_cnt\n");

    while ((cur = nvme_sfr_pop_chnk(stat_q)) != NULL)
    {
        if(cur->real_cnt < 2)
            fprintf(log_fp, "%lu,%u,,%u,%u\n", cur->chnk_id, cur->sfr_pid, cur->access_cnt, cur->real_cnt);
        else
            fprintf(log_fp, "%lu,%u,%lu,%u,%u\n", cur->chnk_id, cur->sfr_pid, cur->interval, cur->access_cnt, cur->real_cnt);

        free(cur);
    }
    fprintf(log_fp, "*** stat   end ***\n\n");
    
    fclose(log_fp);
    return;
};
#endif

/* SFR initiation */
void nvme_sfr_init(void)
{
    g_sfr = (struct nvme_sfr_attr*)malloc(sizeof(struct nvme_sfr_attr));

    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);

    g_sfr->num_chnk =  _SFR_DEV_SZ/_SFR_CHNK_SZ + 1;
    g_sfr->chnks    = (struct nvme_sfr_chnk*)malloc(g_sfr->num_chnk * sizeof(struct nvme_sfr_chnk));
    g_sfr->sfr_pids = (uint32_t*)malloc(g_sfr->num_chnk * sizeof(uint32_t));

    for(uint64_t i = 0; i < g_sfr->num_chnk; i++) 
    {
        g_sfr->chnks[i].chnk_id    = i;
        g_sfr->chnks[i].real_cnt   = 0;
        g_sfr->chnks[i].access_cnt = 0;

        g_sfr->chnks[i].access_time.tv_sec  = current_time.tv_sec;
        g_sfr->chnks[i].access_time.tv_nsec = current_time.tv_nsec;

        g_sfr->sfr_pids[i] = 1;
    }

    g_sfr->admin_q = (struct nvme_sfr_admin_q*)malloc(sizeof(struct nvme_sfr_admin_q));

    g_sfr->admin_q->head = NULL;
    g_sfr->admin_q->tail = NULL;

    pthread_mutex_init(&g_sfr->admin_q_mutex, NULL);

    g_sfr->decay_period = _SFR_DECAY_PERIOD * 1e9; // sec * 1e9

    pthread_create(&(g_sfr->update_thread), NULL, sfr_update_thread, NULL);

    g_sfr_initialized = 1;

    return;
}

/* SFR dispose */
void nvme_sfr_dispose(void)
{
    g_sfr->update_thread_running = 0;

    pthread_join(g_sfr->update_thread, NULL);
    pthread_mutex_destroy(&g_sfr->admin_q_mutex);

    for(struct nvme_sfr_admin_node* cur = g_sfr->admin_q->head; cur != NULL; cur = cur->next)
        free(cur->sub_q);

    free(g_sfr->admin_q);

    free(g_sfr->sfr_pids);
    free(g_sfr->chnks);

    free(g_sfr);

    g_sfr_initialized = 0;

    return;
}

/* For each thread */
struct nvme_sfr_admin_node* nvme_sfr_td_init(void)
{
    struct nvme_sfr_admin_node* ret = (struct nvme_sfr_admin_node*)malloc(sizeof(struct nvme_sfr_admin_node));

    ret->sub_q        = (struct nvme_sfr_circular_queue*)malloc(sizeof(struct nvme_sfr_circular_queue));
    ret->sub_q->front = 0;
    ret->sub_q->rear  = 0;

    ret->prev = NULL;
    ret->next = NULL;

    ret->prev_ruhid = 1;

    pthread_mutex_lock(&g_sfr->admin_q_mutex);

    if(g_sfr->admin_q->tail) 
    {
        ret->prev = g_sfr->admin_q->tail;
        g_sfr->admin_q->tail->next = ret;
    } 

    else 
        g_sfr->admin_q->head = ret;

    g_sfr->admin_q->tail = ret;

    #ifdef SFR_STAT
    ret->stat_q = (struct nvme_sfr_queue*)malloc(sizeof(struct nvme_sfr_queue));

    ret->stat_q->head = NULL;
    ret->stat_q->tail = NULL;
    #endif

    pthread_mutex_unlock(&g_sfr->admin_q_mutex);

    return ret;
}

/* For each thread */
void nvme_sfr_td_dispose(struct nvme_sfr_admin_node* sfr_td)
{
    struct nvme_sfr_admin_node* cur_node = sfr_td;
    
    pthread_mutex_lock(&g_sfr->admin_q_mutex);
    if (cur_node->prev)
        cur_node->prev->next = cur_node->next;
    else
        g_sfr->admin_q->head = cur_node->next;

    if (cur_node->next)
        cur_node->next->prev = cur_node->prev;
    else
        g_sfr->admin_q->tail = cur_node->prev;

    pthread_mutex_unlock(&g_sfr->admin_q_mutex);

    #ifdef SFR_STAT
    nvme_sfr_stat(cur_node->stat_q);
    free(cur_node->stat_q);
    #endif
    
    free(cur_node->sub_q);
    free(cur_node);

    return;
}

/* For circular queue (lock-free) */ 
void nvme_sfr_circular_push_chnk(struct nvme_sfr_circular_queue* q, uint64_t chnk_id) 
{
    uint32_t rear, next_rear;

    do 
    {
        rear = atomic_load(&q->rear);
        next_rear = (rear + 1) % _SFR_QUEUE_SZ;

        // Queue is full -> busy wait
        if (next_rear == atomic_load(&q->front))    continue; // busy wait

    } while(!atomic_compare_exchange_weak(&q->rear, &rear, next_rear));

    q->queue[rear] = chnk_id;

    return;
}

/* For circular queue (lock-free) */ 
uint64_t nvme_sfr_circular_pop_chnk(struct nvme_sfr_circular_queue* q) 
{
    uint32_t front, new_front;

    do 
    {
        front = atomic_load(&q->front);

        // Queue is empty
        if (front == atomic_load(&q->rear))
            return _SFR_DEAD_VALUE;
        
        new_front = (front + 1) % _SFR_QUEUE_SZ;

    } while(!atomic_compare_exchange_weak(&q->front, &front, new_front));

    return q->queue[front];
}

#ifdef SFR_STAT
/* For queue */
void nvme_sfr_push_chnk(struct nvme_sfr_queue* q, struct nvme_sfr_chnk* chnk)
{
    struct nvme_sfr_node* temp = (struct nvme_sfr_node*)malloc(sizeof(struct nvme_sfr_node));

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
struct nvme_sfr_chnk* nvme_sfr_pop_chnk(struct nvme_sfr_queue* q)
{
    if(q->head == NULL && q->tail == NULL)  return NULL; 

    struct nvme_sfr_chnk* ret  = q->head->chnk;
    struct nvme_sfr_node* temp = q->head;

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

/* Return sLBA's sfr_PID */
uint32_t nvme_sfr_get_sfr_pid(struct spdk_nvme_qpair* qpair, uint64_t slba, uint32_t lba_count)
{
    assert(g_sfr_initialized == 1);

    struct nvme_sfr_admin_node*     td    = qpair->sfr_td;
    struct nvme_sfr_circular_queue* sub_q = td->sub_q;

    uint64_t  chnk_id = slba * _SFR_LBA_SZ / _SFR_CHNK_SZ;

    uint32_t  sfr_pid;

    /* For seq write */
    if(slba == td->prev_lba)
        sfr_pid = td->prev_ruhid;

    /* For random write */
    else
    {
        sfr_pid = g_sfr->sfr_pids[chnk_id];
        nvme_sfr_circular_push_chnk(sub_q, chnk_id);
    }

    td->prev_lba   = slba + lba_count;
    td->prev_ruhid = sfr_pid;

    return sfr_pid;
}

/* sfr_PID update */
void nvme_sfr_update(void) // Circular
{
    struct timespec current_time;
    uint64_t        cur_id[_SFR_UPDATE_BATCH_SZ];
    
    pthread_mutex_lock(&g_sfr->admin_q_mutex);

    struct nvme_sfr_admin_node* cur = g_sfr->admin_q->head;

    while(cur != NULL)
    {
        struct nvme_sfr_circular_queue* cur_q = cur->sub_q;

        uint32_t valid_count = 0;
        
        for(uint32_t i = 0; i < _SFR_UPDATE_BATCH_SZ; i++)
        {
            cur_id[i] = nvme_sfr_circular_pop_chnk(cur_q);

            if(cur_id[i] >= g_sfr->num_chnk) break;

            valid_count += 1;
        }

        for(uint32_t i = 0; i < valid_count; i++)
        {
            uint64_t              id           =  cur_id[i];
            uint32_t*             cur_sfr_pid  = &(g_sfr->sfr_pids[id]);
            struct nvme_sfr_chnk* cur_chnk     = &(g_sfr->chnks[id]);
        
            clock_gettime(CLOCK_MONOTONIC, &current_time);

            cur_chnk->access_cnt += 1;
            cur_chnk->real_cnt   += 1;
            cur_chnk->interval   =  nvme_time_diff(cur_chnk->access_time, current_time);

            uint64_t interval       = cur_chnk->interval;
            uint32_t recency_weight = 1 << interval / g_sfr->decay_period;

            cur_chnk->access_cnt /= recency_weight;
            uint32_t access_cnt  =  cur_chnk->access_cnt;
            uint32_t ruh_id      =  1;

            // log2(access_cnt)
            if (access_cnt > 0 && ruh_id < _SFR_MAX_RUH) 
                while ((1U << ruh_id) <= access_cnt) ruh_id++;

            *cur_sfr_pid = ruh_id;

            cur_chnk->access_time = current_time;

            #ifdef SFR_STAT
            // for stat
            struct nvme_sfr_chnk* stat_chnk = (struct nvme_sfr_chnk*)malloc(sizeof(struct nvme_sfr_chnk));

            stat_chnk->sfr_pid    = *cur_sfr_pid;
            stat_chnk->chnk_id    =  cur_chnk->chnk_id;
            stat_chnk->interval   =  cur_chnk->interval;
            stat_chnk->real_cnt   =  cur_chnk->real_cnt;
            stat_chnk->access_cnt =  cur_chnk->access_cnt;

            nvme_sfr_push_chnk(cur->stat_q, stat_chnk);
            #endif
        }

        cur = cur->next;
    }

    pthread_mutex_unlock(&g_sfr->admin_q_mutex);
    return;
}

void* sfr_update_thread(void*)
{
    // while(g_sfr->update_thread_running)
    // {
    //     if(g_sfr)
    //         nvme_sfr_update(); 
    // }

    while(!kthread_should_stop())
    {
        if(g_sfr)
            nvme_sfr_update(); 
            ssleep(1);
    }

    return NULL;
}

static int __init fdp_module_init(void)
{
    task = kthread_run(sfr_update_thread, NULL, "sfr_update_thread");
    if(IS_ERR(task))
    {
        pr_err("Failed to create kernel thread\n");
        return PTR_ERR(task);
    }

    return 0;
}

static void __exit fdp_module_init(void)
{
    if(task)
        kthread_stop(task);
}

module_init(fdp_module_init);
module_exit(fdp_module_exit);
MODULE_LICENSE("GPL");

#endif /* SFR_APPLY */  