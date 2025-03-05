#ifndef __NVME_SFR_H__
#define __NVME_SFR_H__

// #ifndef SFR_APPLY
// #define SFR_APPLY
// #endif

#ifndef SFR_STAT
#define SFR_STAT
#endif

#include "../lib/nvme/nvme_internal.h"
#include <stdint.h>
#include <unistd.h>
#include <math.h>
#include <signal.h>
#include <pthread.h>

/* Parameters */
#define _SFR_WDSZ             4U             
// #define _SFR_DEV_SZ           107373363200ULL // NVMeVirt (128GB)
#define _SFR_DEV_SZ           1000204886016ULL // Real device (1TB)  
#define _SFR_LBA_SZ           512ULL
#define _SFR_CHNK_SZ          (2*1024*1024ULL) // 2MiB
#define _SFR_MAX_RUH          15U              // 16 (0~15)
#define _SFR_QUEUE_SZ         256U
#define _SFR_DEAD_VALUE       0xDEADBEEF       // magic number
#define _SFR_DECAY_PERIOD     10ULL            // sec
#define _SFR_MAX_THREAD_NUM   8U
#define _SFR_UPDATE_BATCH_SZ  1U

/* For use SFR */ 
static struct nvme_sfr_attr* g_sfr             __attribute__((unused));
static uint32_t              g_sfr_initialized __attribute__((unused));

struct nvme_sfr_attr
{
    uint64_t decay_period;

    struct nvme_sfr_chnk* chnks;
    uint32_t*             sfr_pids;

    uint32_t num_chnk;

    pthread_t update_thread;
    uint32_t  update_thread_running;

    struct nvme_sfr_admin_q* admin_q;
    pthread_mutex_t          admin_q_mutex;
};

struct nvme_sfr_chnk
{
    #ifdef SFR_STAT
    uint32_t sfr_pid;
    #endif

    uint64_t chnk_id;     // sLBA/chnk_size
    uint64_t interval;
    uint32_t real_cnt;
    uint32_t access_cnt;
    
    struct timespec access_time;
};

struct nvme_sfr_circular_queue 
{
    uint64_t queue[_SFR_QUEUE_SZ];

    uint32_t front;
    uint32_t rear;
};

struct nvme_sfr_admin_node 
{
    struct nvme_sfr_circular_queue* sub_q;

    uint64_t prev_lba;
    uint32_t prev_ruhid;

    struct nvme_sfr_admin_node* prev;      
    struct nvme_sfr_admin_node* next;    

    /* For stat */
    #ifdef SFR_STAT
    struct nvme_sfr_queue* stat_q;
    #endif
};

struct nvme_sfr_admin_q 
{
    struct nvme_sfr_admin_node* head;
    struct nvme_sfr_admin_node* tail;
};

uint32_t sfr_td_id_alloc(void);
void     sfr_td_id_release(uint32_t id);

void nvme_sfr_init(void);
void nvme_sfr_dispose(void);

struct nvme_sfr_admin_node* nvme_sfr_td_init(void);
void                        nvme_sfr_td_dispose(struct nvme_sfr_admin_node* sfr_td);

uint32_t nvme_sfr_get_sfr_pid(struct spdk_nvme_qpair* qpair, uint64_t slba, uint32_t lba_count);
void     nvme_sfr_update(void);
void*    sfr_update_thread(void*);

uint64_t nvme_sfr_circular_pop_chnk(struct nvme_sfr_circular_queue* q);
void     nvme_sfr_circular_push_chnk(struct nvme_sfr_circular_queue* q, uint64_t chnk_id);

uint64_t nvme_time_diff(struct timespec t1, struct timespec t2);

#ifdef SFR_STAT

struct nvme_sfr_node
{
    struct nvme_sfr_chnk* chnk;
    struct nvme_sfr_node* next;
};

struct nvme_sfr_queue
{
    struct nvme_sfr_node* head;
    struct nvme_sfr_node* tail;
};

void                  nvme_sfr_stat(struct nvme_sfr_queue* stat_q);
struct nvme_sfr_chnk* nvme_sfr_pop_chnk(struct nvme_sfr_queue* q);
void                  nvme_sfr_push_chnk(struct nvme_sfr_queue* q, struct nvme_sfr_chnk* chnk);

#endif

/* TODO: to decision the decay time
void     nvme_sfr_dp_decision(struct nvme_sfr_attr* sfr);
*/ 

#endif /* __NVME_SFR_H__ */
