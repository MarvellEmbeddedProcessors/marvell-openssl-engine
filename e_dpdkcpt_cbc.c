/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/async.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cryptodev.h>

#include "e_dpdkcpt.h"

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
#define E_DPDKCPT_AES128_CBC_KEY_LENGTH 16
#define E_DPDKCPT_AES256_CBC_KEY_LENGTH 32

#define ARMv8_AES_cbc_encrypt aes_v8_cbc_encrypt

extern int cpt_num_requests_in_flight;
extern int cpt_num_cipher_pipeline_requests_in_flight;

struct ossl_dpdk_ctx {
	uint8_t key[16];
	int keylen;
	uint8_t dev_id; /* cpt dev_id*/
	int iv_set;
	struct rte_crypto_sym_xform aead_xform;
	struct rte_cryptodev_sym_session *cry_session;
	struct rte_crypto_op *op;
	struct rte_mbuf *ibuf;
	struct rte_mbuf *obuf;
	/* Below members are for pipeline */
	uint8_t numpipes;
	uint8_t **input_buf;
	uint8_t **output_buf;
	long int *input_len;
	union {
		double align;
		AES_KEY ks;
	} ks;
	block128_f block;
	union {
		cbc128_f cbc;
		ctr128_f ctr;
	} stream;
	int hw_offload_pkt_sz_threshold;
};

static int dpdkcpt_aes_init_key_helper(EVP_CIPHER_CTX *ctx,
				       const unsigned char *key,
				       const unsigned char *iv, int enc,
				       int key_len);
static int dpdkcpt_aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
				  const unsigned char *in, size_t inl);
static int dpdkcpt_aes_cbc_cleanup(EVP_CIPHER_CTX *ctx);

static int dpdkcpt_aes128_init_key(EVP_CIPHER_CTX *ctx,
				   const unsigned char *key,
				   const unsigned char *iv, int enc);
static int dpdkcpt_aes256_init_key(EVP_CIPHER_CTX *ctx,
				   const unsigned char *key,
				   const unsigned char *iv, int enc);
static int dpdkcpt_aes128_cbc_ctrl(EVP_CIPHER_CTX *ctx,
					int type, int arg, void *ptr);
static int dpdkcpt_aes256_cbc_ctrl(EVP_CIPHER_CTX *ctx, int type,
					int arg, void *ptr);
int dpdkcpt_aes_cbc_ctrl_helper(EVP_CIPHER_CTX *ctx, int type,
					int arg, void *ptr);

const EVP_CIPHER *dpdkcpt_aes_128_cbc(void);
const EVP_CIPHER *dpdkcpt_aes_256_cbc(void);
void ARMv8_AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
			   size_t length, const AES_KEY *key,
			   unsigned char *ivec, const int enc);

EVP_CIPHER *_hidden_aes_128_cbc = NULL;
EVP_CIPHER *_hidden_aes_256_cbc = NULL;

extern int sym_dev_id[];
extern int sym_queues[];
extern uint16_t hw_offload_pktsz_thresh;

const EVP_CIPHER *dpdkcpt_aes_128_cbc(void)
{
	if (_hidden_aes_128_cbc == NULL &&
	    ((_hidden_aes_128_cbc = EVP_CIPHER_meth_new(
		      NID_aes_128_cbc, E_DPDKCPT_AES_BLOCK_SIZE /* block sz */,
		      E_DPDKCPT_AES128_CBC_KEY_LENGTH /* key len */)) == NULL ||
	     !EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc,
					    E_DPDKCPT_AES_CBC_IV_LENGTH) ||
	     !EVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc,
					EVP_CIPH_FLAG_DEFAULT_ASN1 |
					EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_PIPELINE) ||
	     !EVP_CIPHER_meth_set_init(_hidden_aes_128_cbc,
				       dpdkcpt_aes128_init_key) ||
	     !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc,
					    dpdkcpt_aes_cbc_cipher) ||
		 !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_cbc, dpdkcpt_aes128_cbc_ctrl) ||
		 !EVP_CIPHER_meth_set_cleanup(_hidden_aes_128_cbc,
					  dpdkcpt_aes_cbc_cleanup) ||
	     !EVP_CIPHER_meth_set_impl_ctx_size(
		     _hidden_aes_128_cbc, sizeof(struct ossl_dpdk_ctx)))) {
		EVP_CIPHER_meth_free(_hidden_aes_128_cbc);
		_hidden_aes_128_cbc = NULL;
	}
	return _hidden_aes_128_cbc;
}

const EVP_CIPHER *dpdkcpt_aes_256_cbc(void)
{
	if (_hidden_aes_256_cbc == NULL &&
	    ((_hidden_aes_256_cbc = EVP_CIPHER_meth_new(
		      NID_aes_256_cbc, E_DPDKCPT_AES_BLOCK_SIZE /* block sz */,
		      E_DPDKCPT_AES256_CBC_KEY_LENGTH /* key len */)) == NULL ||
	     !EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_cbc,
					    E_DPDKCPT_AES_CBC_IV_LENGTH) ||
	     !EVP_CIPHER_meth_set_flags(_hidden_aes_256_cbc,
					EVP_CIPH_FLAG_DEFAULT_ASN1 |
					EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_PIPELINE) ||
	     !EVP_CIPHER_meth_set_init(_hidden_aes_256_cbc,
				       dpdkcpt_aes256_init_key) ||
	     !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_cbc,
					    dpdkcpt_aes_cbc_cipher) ||
		 !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_cbc, dpdkcpt_aes256_cbc_ctrl) ||
		 !EVP_CIPHER_meth_set_cleanup(_hidden_aes_256_cbc,
					  dpdkcpt_aes_cbc_cleanup) ||
	     !EVP_CIPHER_meth_set_impl_ctx_size(
		     _hidden_aes_256_cbc, sizeof(struct ossl_dpdk_ctx)))) {
		EVP_CIPHER_meth_free(_hidden_aes_256_cbc);
		_hidden_aes_256_cbc = NULL;
	}
	return _hidden_aes_256_cbc;
}

/*
 * AES Implementation
 */

int dpdkcpt_aes_init_key_helper(EVP_CIPHER_CTX *ctx, const unsigned char *key,
				const unsigned char *iv, int enc, int key_len)
{
	struct ossl_dpdk_ctx *dpdk_ctx =
			(struct ossl_dpdk_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	int ret = 0;
    if(iv == NULL && key == NULL)
        return 1;

    dpdk_ctx->hw_offload_pkt_sz_threshold = hw_offload_pktsz_thresh;
    if(key != NULL) {
		struct rte_crypto_sym_xform cipher_xform = {
			.next = NULL,
			.type = RTE_CRYPTO_SYM_XFORM_CIPHER,
			.cipher = { .op = enc ? RTE_CRYPTO_CIPHER_OP_ENCRYPT :
						RTE_CRYPTO_CIPHER_OP_DECRYPT,
				    .algo = RTE_CRYPTO_CIPHER_AES_CBC,
				    .key = { .length = key_len },
				    .iv = { .offset = E_DPDKCPT_IV_OFFSET,
					    .length = E_DPDKCPT_AES_CBC_IV_LENGTH } }
		};

		cipher_xform.cipher.key.data = (const uint8_t *)key;

		unsigned int lcore = rte_lcore_id();
		if (lcore == LCORE_ID_ANY || sym_dev_id[lcore] == -1) {
			engine_log(ENG_LOG_ERR, "%s: Queues not available for lcore %d\n",
				__FUNCTION__, lcore);
			return 0;
		}
		dpdk_ctx->dev_id = sym_dev_id[lcore];

		/* Create crypto session and initialize it for the crypto device. */
		if (dpdk_ctx->cry_session == NULL) {
			dpdk_ctx->cry_session =
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
				(void *)rte_cryptodev_sym_session_create(dpdk_ctx->dev_id,
									&cipher_xform,
									sym_session_pool);
#else
				(void *)rte_cryptodev_sym_session_create(sym_session_pool);
#endif
			if (dpdk_ctx->cry_session == NULL) {
				engine_log(ENG_LOG_ERR, "Session could not be created\n");
				return 0;
			}

#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
			if (rte_cryptodev_sym_session_init(
				    dpdk_ctx->dev_id,
				    (struct rte_cryptodev_sym_session *)dpdk_ctx->cry_session,
				    &cipher_xform, sym_session_priv_pool) < 0) {
				engine_log(ENG_LOG_ERR, "Session could not be initialized "
						"for the crypto device\n");
				return 0;
			}
#endif
		}
		if (enc) {
			ret = ARMv8_AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
					&dpdk_ctx->ks.ks);
			dpdk_ctx->block = (block128_f) ARMv8_AES_encrypt;
			dpdk_ctx->stream.cbc = (cbc128_f) ARMv8_AES_cbc_encrypt;
		} else {
			ret = ARMv8_AES_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
					&dpdk_ctx->ks.ks);
			dpdk_ctx->block = (block128_f) ARMv8_AES_decrypt;
			dpdk_ctx->stream.cbc = (cbc128_f) ARMv8_AES_cbc_encrypt;
		}
		if (ret < 0) {
			engine_log(ENG_LOG_ERR, "Set encrypt/decrypt key failed!!!\n");
			return 0;
		}
    }

	dpdk_ctx->numpipes = 0;

	return 1;
}

int dpdkcpt_aes128_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			    const unsigned char *iv, int enc)
{
	return dpdkcpt_aes_init_key_helper(ctx, key, iv, enc,
					   E_DPDKCPT_AES128_CBC_KEY_LENGTH);
}

int dpdkcpt_aes256_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			    const unsigned char *iv, int enc)
{
	return dpdkcpt_aes_init_key_helper(ctx, key, iv, enc,
					   E_DPDKCPT_AES256_CBC_KEY_LENGTH);
}

int dpdkcpt_aes128_cbc_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
	int ret;

	ret = dpdkcpt_aes_cbc_ctrl_helper(ctx, type, arg, ptr);
	return ret;
}

int dpdkcpt_aes256_cbc_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
	int ret;

	ret = dpdkcpt_aes_cbc_ctrl_helper(ctx, type, arg, ptr);
	return ret;
}

int dpdkcpt_aes_cbc_ctrl_helper(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
{
	struct ossl_dpdk_ctx *dpdk_ctx =
		(struct ossl_dpdk_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);

	switch (type) {
	case EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS:
		dpdk_ctx->numpipes = arg;
		dpdk_ctx->output_buf = ptr;
		break;
	case EVP_CTRL_SET_PIPELINE_INPUT_BUFS:
		dpdk_ctx->numpipes = arg;
		dpdk_ctx->input_buf = ptr;
		break;
	case EVP_CTRL_SET_PIPELINE_INPUT_LENS:
		dpdk_ctx->numpipes = arg;
		dpdk_ctx->input_len = ptr;
		break;
	default:
		return 0;
	}
	return 1;
}
int dpdkcpt_aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			   const unsigned char *in, size_t inl)
{
	int i, j, k, numpipes, numalloc, ret;
	volatile uint16_t num_enqueued_ops, num_dequeued_ops;
	void *buf;
	uint8_t *iv_ptr;
	struct rte_mbuf *mbuf;
	ossl_cry_op_status_t current_job;
	struct rte_crypto_op **enq_op_ptr = NULL, *deq_op_ptr[E_DPDKCPT_NUM_DEQUEUED_OPS];
	ossl_cry_op_status_t **status_ptr = NULL, *new_st_ptr[E_DPDKCPT_NUM_DEQUEUED_OPS];
	unsigned char saved_iv[E_DPDKCPT_AES_CBC_IV_LENGTH];
	const unsigned char *next_iv;
	uint16_t datalen = (uint16_t)(inl - E_DPDKCPT_AES_CBC_IV_LENGTH);

	struct ossl_dpdk_ctx *dpdk_ctx =
		(struct ossl_dpdk_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	ASYNC_JOB *job = NULL;
	ASYNC_WAIT_CTX *wctx_local = NULL;
	async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];
	uint8_t pip_jb_qsz = 0;

	numpipes = dpdk_ctx->numpipes;
	/* Bydefault number of pipe is one */
	if (numpipes == 0) {
		numpipes = 1;
		dpdk_ctx->output_buf = &out;
		dpdk_ctx->input_buf = (uint8_t **)&in;
		dpdk_ctx->input_len = &inl;
	}
	if ((datalen < dpdk_ctx->hw_offload_pkt_sz_threshold) && (numpipes == 1)) {
		(*dpdk_ctx->stream.cbc) (in, out, inl, &dpdk_ctx->ks,
					EVP_CIPHER_CTX_iv_noconst(ctx),
					EVP_CIPHER_CTX_encrypting(ctx));
		dpdk_ctx->output_buf = NULL;
		dpdk_ctx->input_buf = NULL;
		dpdk_ctx->input_len = NULL;
		dpdk_ctx->numpipes = 0;
		return 1;
	}
	enq_op_ptr = OPENSSL_malloc(sizeof(struct rte_crypto_op *) * numpipes);
	status_ptr = OPENSSL_malloc(sizeof(ossl_cry_op_status_t *) * numpipes);
	if (unlikely(enq_op_ptr == NULL || status_ptr == NULL)) {
		engine_log(ENG_LOG_ERR, "OPENSSL_malloc failed\n");
		numalloc = 0;
		ret = -1;
		goto free_resources;
	}
	job = ASYNC_get_current_job();
	if (job != NULL)
		wctx_local = (ASYNC_WAIT_CTX *)ASYNC_get_wait_ctx(job);

	for (i = 0; i < numpipes; i++) {
		if (dpdk_ctx->input_len[i] < E_DPDKCPT_AES_CBC_IV_LENGTH) {
			engine_log (ENG_LOG_ERR, "Invalid input length\n");
			ret = 0;
			goto free_resources;
		}
		// For decrytion, save the last iv_len bytes of ciphertext as next IV.
		if (!EVP_CIPHER_CTX_encrypting(ctx)) {
			next_iv = dpdk_ctx->input_buf[i] +
						dpdk_ctx->input_len[i] - E_DPDKCPT_AES_CBC_IV_LENGTH;
			memcpy(saved_iv, next_iv, E_DPDKCPT_AES_CBC_IV_LENGTH);
		}
		enq_op_ptr[i] = rte_crypto_op_alloc(crypto_sym_op_pool,
				RTE_CRYPTO_OP_TYPE_SYMMETRIC);
		if (unlikely(enq_op_ptr[i] == NULL)) {
			engine_log(ENG_LOG_ERR, "Not enough crypto operations available\n");
			numalloc = i;
			ret = -1;
			goto free_resources;
		}
		/* Get a burst of mbufs */
		mbuf = rte_pktmbuf_alloc(mbuf_pool);
		if (unlikely(mbuf == NULL)) {
			engine_log(ENG_LOG_ERR, "Not enough mbufs available\n");
			/* roll back last crypto op */
			rte_mempool_put(crypto_sym_op_pool, enq_op_ptr[i]);
			numalloc = i;
			ret = -1;
			goto free_resources;
		}
		/* Get data buf pointer pointing to start of pkt */
		buf = rte_pktmbuf_mtod_offset(mbuf, char *, 0);
		memcpy(buf, dpdk_ctx->input_buf[i], dpdk_ctx->input_len[i]);

		enq_op_ptr[i]->sym->m_src = mbuf;
		enq_op_ptr[i]->sym->cipher.data.offset = 0;
		enq_op_ptr[i]->sym->cipher.data.length = dpdk_ctx->input_len[i];

		iv_ptr = rte_crypto_op_ctod_offset(enq_op_ptr[i], uint8_t *,
				E_DPDKCPT_IV_OFFSET);

		memcpy(iv_ptr, EVP_CIPHER_CTX_iv_noconst(ctx), E_DPDKCPT_AES_CBC_IV_LENGTH);
		status_ptr[i] = rte_crypto_op_ctod_offset(enq_op_ptr[i],
				ossl_cry_op_status_t *, E_DPDKCPT_COP_METADATA_OFF);
		status_ptr[i]->is_complete = 0;
		status_ptr[i]->is_successful = 0;
		status_ptr[i]->numpipes = numpipes;
		status_ptr[i]->wctx_p = wctx_local;

		rte_crypto_op_attach_sym_session(enq_op_ptr[i], dpdk_ctx->cry_session);
		mbuf = NULL;
	}

	/* Enqueue this crypto operation in the crypto device */
	for (k = 0, num_enqueued_ops = 0;
	    (num_enqueued_ops < numpipes && k < MAX_ENQUEUE_ATTEMPTS); k++) {
		num_enqueued_ops +=
			rte_cryptodev_enqueue_burst(
				dpdk_ctx->dev_id, sym_queues[rte_lcore_id()],
				&enq_op_ptr[num_enqueued_ops],
				numpipes - num_enqueued_ops);
	}
	if (unlikely(num_enqueued_ops < numpipes)) {
		engine_log(ENG_LOG_ERR, "Enqueue failed - too many attempts\n");
		numalloc = numpipes;
		ret = -1;
		goto free_resources;
	}
	CPT_ATOMIC_INC_N(cpt_num_cipher_pipeline_requests_in_flight, numpipes);
	CPT_ATOMIC_INC(cpt_num_requests_in_flight);
	pause_async_job();

	CPT_ATOMIC_DEC_N(cpt_num_cipher_pipeline_requests_in_flight, numpipes);
	CPT_ATOMIC_DEC(cpt_num_requests_in_flight);

	j = 0;
	while (status_ptr[0]->is_successful == 0) {
	    do {
		    num_dequeued_ops = rte_cryptodev_dequeue_burst(
					dpdk_ctx->dev_id, sym_queues[rte_lcore_id()],
					&deq_op_ptr[0],
					E_DPDKCPT_NUM_DEQUEUED_OPS);

		    for (i = 0; i < num_dequeued_ops; i++) {
		    	new_st_ptr[i] = rte_crypto_op_ctod_offset(deq_op_ptr[i],
		    		ossl_cry_op_status_t *, E_DPDKCPT_COP_METADATA_OFF);
		    	new_st_ptr[i]->is_complete = 1;
		    	/* Check if operation was processed successfully */
		    	if (deq_op_ptr[i]->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
                            engine_log(ENG_LOG_ERR, "Crypto (CBC) op status is not success (err:%d)\n",
                                        deq_op_ptr[i]->status);
		            new_st_ptr[i]->is_successful = 0;
		    	} else {
                            new_st_ptr[i]->is_successful = 1;
		            if(new_st_ptr[i]->wctx_p)
			        check_for_job_completion(status_ptr[0]->wctx_p, new_st_ptr[i]->wctx_p,
					    new_st_ptr[i]->numpipes, &pip_jb_qsz, &pip_jobs[0]);
		    	}
		    }
	    } while (pip_jb_qsz>0);
	}

	for (i = 0; i < numpipes; i++) {
		buf = rte_pktmbuf_mtod_offset(enq_op_ptr[i]->sym->m_src, char *, 0);
		memcpy(dpdk_ctx->output_buf[i], buf, dpdk_ctx->input_len[i]);
		// For encryption, copy last 16 bytes of ciphertext to IV
		if (EVP_CIPHER_CTX_encrypting(ctx))
		    next_iv = (dpdk_ctx->output_buf[i] + dpdk_ctx->input_len[i]
				   - E_DPDKCPT_AES_CBC_IV_LENGTH);
		else
		    next_iv = saved_iv;
		memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), next_iv, E_DPDKCPT_AES_CBC_IV_LENGTH);
		rte_pktmbuf_free(enq_op_ptr[i]->sym->m_src);
		enq_op_ptr[i]->sym->m_src = NULL;
	}
	rte_mempool_put_bulk(crypto_sym_op_pool, (void **)enq_op_ptr, numpipes);
	ret = 1;

free_resources:
	if (unlikely(ret < 0)) {
		for (i = 0; i < numalloc; i++) {
			rte_pktmbuf_free(enq_op_ptr[i]->sym->m_src);
			enq_op_ptr[i]->sym->m_src = NULL;
		}
		rte_mempool_put_bulk(crypto_sym_op_pool, (void **)enq_op_ptr, numalloc);
	}
	if (enq_op_ptr != NULL) {
		OPENSSL_free(enq_op_ptr);
		enq_op_ptr = NULL;
	}
	if (status_ptr != NULL) {
		OPENSSL_free(status_ptr);
		status_ptr = NULL;
	}
	dpdk_ctx->output_buf = NULL;
	dpdk_ctx->input_buf = NULL;
	dpdk_ctx->input_len = NULL;
	dpdk_ctx->numpipes = 0;

	return ret;
}

int dpdkcpt_aes_cbc_cleanup(EVP_CIPHER_CTX *ctx)
{
	int retval;
	struct ossl_dpdk_ctx *dpdk_ctx =
		(struct ossl_dpdk_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);

	if (dpdk_ctx->cry_session != NULL) {
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		retval = rte_cryptodev_sym_session_clear(
			dpdk_ctx->dev_id, (struct rte_cryptodev_sym_session *)
					dpdk_ctx->cry_session);
		if (retval < 0)
			engine_log(ENG_LOG_ERR, "FAILED to clear session. ret=%d\n",
				retval);
		retval = rte_cryptodev_sym_session_free(
			(struct rte_cryptodev_sym_session *)
				dpdk_ctx->cry_session);
#else
		retval = rte_cryptodev_sym_session_free(dpdk_ctx->dev_id,
			(struct rte_cryptodev_sym_session *)
				dpdk_ctx->cry_session);
#endif
		if (retval < 0)
			engine_log(ENG_LOG_ERR, "FAILED to free session. ret=%d\n",
				retval);
	}

	return 1;
}
