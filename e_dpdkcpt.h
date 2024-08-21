/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _E_DPDKCPT_H
#define _E_DPDKCPT_H

#include <openssl/async.h>
#include <openssl/aes.h>
#include <rte_crypto.h>
#include <rte_version.h>

/*Note: MAX_ASYNC_JOBS(cn106xx,cn96xx, cn98xx) value is 36. So due to this min mbufs, sym/asym ops set as 36. Also AES-GCM requires two sessions per operation, so min sessions set as 72.*/
#define E_DPDKCPT_NUM_DEQUEUED_OPS		32
#define E_DPDKCPT_MAX_SESSIONS                  (INT_MAX/2)
#define E_DPDKCPT_DEFAULT_SESSIONS              (128 << 10)
#define E_DPDKCPT_MIN_SESSIONS                  72
#define E_DPDKCPT_MAX_MBUFS                     (INT_MAX/2)
#define E_DPDKCPT_DEFAULT_MBUFS                 4096
#define E_DPDKCPT_MIN_MBUFS                     36
#define E_DPDKCPT_MAX_SYM_OPS                   (INT_MAX/2)
#define E_DPDKCPT_DEFAULT_SYM_OPS               4096
#define E_DPDKCPT_MIN_SYM_OPS                   36
#define E_DPDKCPT_MAX_ASYM_OPS                  (INT_MAX/2)
#define E_DPDKCPT_DEFAULT_ASYM_OPS              1024
#define E_DPDKCPT_MIN_ASYM_OPS                  36
#define E_DPDKCPT_MAX_POOL_CACHE_SIZE           512
#define E_DPDKCPT_DEFAULT_POOL_CACHE_SIZE       512
#define E_DPDKCPT_MIN_POOL_CACHE_SIZE           0
#define E_DPDKCPT_MAX_ASYM_QP_DESC_COUNT        8192
#define E_DPDKCPT_DEFAULT_ASYM_QP_DESC_COUNT    512
#define E_DPDKCPT_MIN_ASYM_QP_DESC_COUNT        32
#define E_DPDKCPT_MAX_SYM_QP_DESC_COUNT         8192
#define E_DPDKCPT_DEFAULT_SYM_QP_DESC_COUNT     2048
#define E_DPDKCPT_MIN_SYM_QP_DESC_COUNT         32
#define E_DPDKCPT_AES_CBC_IV_LENGTH		16
#define E_DPDKCPT_AES_GCM_IV_LENGTH		12
#define E_DPDKCPT_CPOLY_IV_LEN                  12
#define E_DPDKCPT_AES_BLOCK_SIZE		16
#define E_DPDK_DIGEST_LEN			64
#define E_DPDKCPT_RTE_MBUF_CUSTOM_BUF_SIZE	(32 * 1024)
#define E_DPDKCPT_IV_OFFSET			\
	(sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op))
#define MIN(a, b)				((a) < (b) ? (a) : (b))
#define MAX(a, b)				((a) > (b) ? (a) : (b))
#define MAX_DEQUEUE_OPS				32
#define MAX_ENQUEUE_ATTEMPTS			20
#define RSA_SHIFT 0
#define EC_SHIFT 1
#define GCM_SHIFT 2
#define CBC_SHIFT 3
#define CPOLY_SHIFT 4
#define SHIFT_OSSL_BITS 8
#define ALG_MASK(alg) ((1<<alg##_SHIFT)<<SHIFT_OSSL_BITS)
#define SET_ENGINE_ALG_FLAGS(e, updated_flag)(ENGINE_set_flags(e, updated_flag))
#define IS_ALG_ENABLED(e, alg)(ENGINE_get_flags(e)&ALG_MASK(alg))
#define ASYM_ALG_SUPPORT_MASK (((1<<RSA_SHIFT)|(1<<EC_SHIFT)) << SHIFT_OSSL_BITS)
#define SYM_ALG_SUPPORT_MASK (((1<<GCM_SHIFT)|(1<<CBC_SHIFT)|(1<<CPOLY_SHIFT)) << SHIFT_OSSL_BITS)
#define ALL_ALG_SUPPORT_MASK (ASYM_ALG_SUPPORT_MASK | SYM_ALG_SUPPORT_MASK)
#define CHECK_LIMIT_AND_ASSIGN(value, max, min)((value>max)?max:((value<min)?min:value))
#define CACHE_FLUSH_THRESHOLD_MULTIPLIER 1.5
#define CACHESZ_LIMIT(n)((n>1)?((n/CACHE_FLUSH_THRESHOLD_MULTIPLIER)-1):0)
#define DPDKCPT_MAX_NUM_POOL 5
#define ASYM_OP_POOL_INDEX 0
#define ASYM_SESSION_POOL_INDEX 1
#define MBUF_POOL_INDEX 2
#define SYM_OP_POOL_INDEX 3
#define SYM_SESSION_POOL_INDEX 4
#define HW_OFFLOAD_PKT_SZ_THRESHOLD_MAX           16384
#define HW_OFFLOAD_PKT_SZ_THRESHOLD_DEFAULT       0
#define HW_OFFLOAD_PKT_SZ_THRESHOLD_MIN           0
#define DPDKCPT_CTRL_CMD_EAL_PARAMS               (ENGINE_CMD_BASE + 1)
#define DPDKCPT_CTRL_CMD_EAL_INIT                 (ENGINE_CMD_BASE + 2)
#define DPDKCPT_CTRL_CMD_EAL_PID_IN_FP            (ENGINE_CMD_BASE + 3)
#define DPDKCPT_CTRL_CMD_EAL_CORE_BY_CPU          (ENGINE_CMD_BASE + 4)
#define DPDKCPT_CTRL_CMD_EAL_CPTVF_BY_CPU         (ENGINE_CMD_BASE + 5)
#define DPDKCPT_CTRL_CMD_CRYPTO_DRIVER            (ENGINE_CMD_BASE + 6)
#define DPDKCPT_CTRL_CMD_CPTVF_QUEUES             (ENGINE_CMD_BASE + 7)
#define DPDKCPT_CTRL_CMD_ENGINE_ALG_SUPPORT       (ENGINE_CMD_BASE + 8)
#define DPDKCPT_CTRL_CMD_DPDK_QP_CONF_PARAMS      (ENGINE_CMD_BASE + 9)
#define DPDKCPT_CTRL_CMD_HW_OFFLOAD_THRESH_PKTSZ  (ENGINE_CMD_BASE + 10)
#define DPDKCPT_CTRL_CMD_ENG_LOG_LEVEL            (ENGINE_CMD_BASE + 11)
#define DPDKCPT_CTRL_CMD_ENG_LOG_FILE             (ENGINE_CMD_BASE + 12)
#define DPDKCPT_CTRL_CMD_POLL                     (ENGINE_CMD_BASE + 13)
#define DPDKCPT_GET_NUM_REQUESTS_IN_FLIGHT        (ENGINE_CMD_BASE + 14)

#define GET_NUM_ASYM_REQUESTS_IN_FLIGHT             1
#define GET_NUM_KDF_REQUESTS_IN_FLIGHT              2
#define GET_NUM_CIPHER_PIPELINE_REQUESTS_IN_FLIGHT  3
#define GET_NUM_ASYM_MB_ITEMS_IN_QUEUE              4
#define GET_NUM_KDF_MB_ITEMS_IN_QUEUE               5
#define GET_NUM_SYM_MB_ITEMS_IN_QUEUE               6

#define MAX_PIPE_JOBS 64

# define CPT_ATOMIC_INC(cpt_int)              \
	            (__sync_add_and_fetch(&(cpt_int), 1))

# define CPT_ATOMIC_DEC(cpt_int)              \
	            (__sync_sub_and_fetch(&(cpt_int), 1))
# define CPT_ATOMIC_INC_N(cpt_int, n)              \
	            (__sync_add_and_fetch(&(cpt_int), n))

# define CPT_ATOMIC_DEC_N(cpt_int, n)              \
	            (__sync_sub_and_fetch(&(cpt_int), n))

#define ARMv8_AES_set_encrypt_key aes_v8_set_encrypt_key
#define ARMv8_AES_encrypt aes_v8_encrypt
#define ARMv8_AES_set_decrypt_key aes_v8_set_decrypt_key
#define ARMv8_AES_decrypt aes_v8_decrypt

/* use the maximum iv length(GCM, CBC, CPOLY) so that GCM,CBC,CPOLY
 * can ack crypto operations for each other */
#define E_DPDKCPT_COP_METADATA_OFF                                    \
	(E_DPDKCPT_IV_OFFSET + MAX(E_DPDKCPT_CPOLY_IV_LEN,            \
	MAX(E_DPDKCPT_AES_CBC_IV_LENGTH, E_DPDKCPT_AES_GCM_IV_LENGTH)))

int ARMv8_AES_set_encrypt_key(const unsigned char *userKey, const int bits,
			      AES_KEY *key);
void ARMv8_AES_encrypt(const unsigned char *in, unsigned char *out,
		       const AES_KEY *key);
int ARMv8_AES_set_decrypt_key(const unsigned char *userKey, const int bits,
			      AES_KEY *key);
void ARMv8_AES_decrypt(const unsigned char *in, unsigned char *out,
		       const AES_KEY *key);

int engine_log(uint32_t level, const char *fmt, ...);

extern OSSL_ASYNC_FD zero_fd;

extern struct rte_mempool *mbuf_pool;
extern struct rte_mempool *crypto_sym_op_pool;
extern struct rte_mempool *sym_session_pool;
extern struct rte_mempool *sym_session_priv_pool;
extern struct rte_mempool *crypto_asym_op_pool;
extern struct rte_mempool *asym_session_pool;

void ENGINE_load_dpdkcpt(void);

typedef struct ossl_cry_op_status {
	int is_complete;
	int is_successful;
	int numpipes;
        ASYNC_WAIT_CTX *wctx_p;
} ossl_cry_op_status_t;

typedef struct async_pipe_job {
    ASYNC_WAIT_CTX *wctx_p;
    int counter;
} async_pipe_job_t;

enum engine_log_error {
	ENG_LOG_STDERR = 0,
	ENG_LOG_EMERG = 1,
	ENG_LOG_ERR = 2,
	ENG_LOG_INFO = 3
};

static inline int pause_async_job(void)
{
	ASYNC_JOB *job = ASYNC_get_current_job();
	if (job != NULL) {
		ASYNC_WAIT_CTX *wctx = ASYNC_get_wait_ctx(job);
		if (wctx != NULL) {
			size_t numfds = 0;
			ASYNC_WAIT_CTX_get_all_fds(wctx, NULL, &numfds);
			/* If wctx does not have an fd, then set it.
			 * This is needed for the speed test which select()s
			 * on fd
			 */
			if (numfds == 0)
				ASYNC_WAIT_CTX_set_wait_fd(wctx, NULL, zero_fd,
							   NULL, NULL);
		}
		ASYNC_pause_job();
	}
	return 0;
}

static inline void invoke_async_callback(ASYNC_WAIT_CTX *wctx_p)
{
    int (*callback)(void *arg);
    void *args;

    if(ASYNC_WAIT_CTX_get_callback(wctx_p, &callback, &args))
        (*callback)(args);
}

static inline void check_for_job_completion (ASYNC_WAIT_CTX *resumed_wctx, ASYNC_WAIT_CTX *wctx_p, int numpipes, uint8_t *job_qsz, async_pipe_job_t *pip_jobs)
{
    uint8_t job_index = 0, k = 0, wctx_found = 0;
    if ((*job_qsz == 0))
    {
        pip_jobs[0].wctx_p = wctx_p;
        pip_jobs[0].counter = 1;
	*job_qsz = 1;
        if (pip_jobs[0].counter == numpipes)
        {
            if ((resumed_wctx == NULL) || (resumed_wctx != pip_jobs[0].wctx_p))
                invoke_async_callback(pip_jobs[0].wctx_p);
	    (*job_qsz)--;
        }
    }
    else
    {
        for (job_index=0; job_index < *job_qsz; job_index++)
	{
            if (wctx_p == pip_jobs[job_index].wctx_p)
            {
                wctx_found = 1;
                pip_jobs[job_index].counter++;
                if (pip_jobs[job_index].counter == numpipes)
	        {
                    if ((resumed_wctx == NULL) || (resumed_wctx != pip_jobs[job_index].wctx_p))
                        invoke_async_callback(pip_jobs[job_index].wctx_p);
                    for (k = job_index; k < (*job_qsz - 1); k++)
	            {
                        pip_jobs[k].wctx_p = pip_jobs[k+1].wctx_p;
                        pip_jobs[k].counter = pip_jobs[k+1].counter;
                    }
                    (*job_qsz)--;
                }
            }
        }
        if (!wctx_found) {
            pip_jobs[*job_qsz].wctx_p = wctx_p;
            (*job_qsz)++;
        }
    }
}
#endif /* _E_DPDKCPT_H */
