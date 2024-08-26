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
#if OPENSSL_API_LEVEL >= 30000
#include <crypto/modes.h>
#include <openssl/evp.h>
#else
#include <modes_local.h>
#include <evp_local.h>
#endif

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>

#include "e_dpdkcpt.h"

#define E_DPDKCPT_AEAD_DIGEST_LENGTH	16
#define E_DPDKCPT_AES128_GCM_KEY_LENGTH	16
#define E_DPDKCPT_AES256_GCM_KEY_LENGTH	32
#define E_DPDKCPT_AES_CTR_IV_LENGTH	16
#define SSL_MAX_PIPELINES   32
#define TLS_HDR_SIZE    13
#define ARMv8_AES_ctr32_encrypt_blocks aes_v8_ctr32_encrypt_blocks
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

#define E_DPDKCPT_GCM_FLAGS                                                    \
	(EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_DEFAULT_ASN1 |              \
	 EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER |                    \
	 EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_GCM_MODE)

#define CRYPTO_OP(c)                                                           \
	((c) ? RTE_CRYPTO_AEAD_OP_ENCRYPT : RTE_CRYPTO_AEAD_OP_DECRYPT)

#define AES_GCM_FLAGS  (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV \
						| EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_ALWAYS_CALL_INIT \
						| EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY \
						| EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_GCM_MODE \
						| EVP_CIPH_FLAG_PIPELINE | EVP_CIPH_CUSTOM_IV_LENGTH )

extern int sym_dev_id[];
extern int sym_queues[];
extern uint16_t hw_offload_pktsz_thresh;
extern int cpt_num_requests_in_flight;
extern int cpt_num_cipher_pipeline_requests_in_flight;

struct ossl_dpdk_ctx {
	union {
		double align;
		AES_KEY ks;
	} ks;
	uint8_t key[32];
	uint64_t iv[3];
	uint8_t *aad;
	uint8_t auth_tag[16];
	uint8_t keylen;
	uint8_t dev_id; /* cpt dev_id*/
	uint8_t key_set:1;
	uint8_t iv_set:1;
	uint8_t iv_gen:1;
	GCM128_CONTEXT gcm;
	int aad_len;
	int taglen;
	int ivlen;
	int tls_aad_len;
	ctr128_f ctr;
	int hw_offload_pkt_sz_threshold;
	struct rte_cryptodev_sym_session *aead_cry_session;
	struct rte_cryptodev_sym_session *cipher_cry_session;
	struct rte_crypto_op *op;
	struct rte_mbuf *ibuf;
	struct rte_mbuf *obuf;
	/* Below members are for pipeline */
	volatile int numpipes;
	uint8_t **input_buf;
	uint8_t **output_buf;
	long int *input_len;
	struct rte_crypto_op *ops[SSL_MAX_PIPELINES];
	struct rte_mbuf *ibufs[SSL_MAX_PIPELINES];
	uint32_t aad_cnt;
	char aad_pipe[SSL_MAX_PIPELINES][TLS_HDR_SIZE];
};
/* AES-GCM */
static int dpdkcpt_aes128_gcm_init_key(EVP_CIPHER_CTX *ctx,
				       const unsigned char *key,
				       const unsigned char *iv, int enc);
static int dpdkcpt_aes256_gcm_init_key(EVP_CIPHER_CTX *ctx,
				       const unsigned char *key,
				       const unsigned char *iv, int enc);

static int dpdkcpt_aes_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
				  const unsigned char *in, size_t inl);
static int dpdkcpt_aes_gcm_cleanup(EVP_CIPHER_CTX *ctx);
static int dpdkcpt_aes_gcm_init_key(EVP_CIPHER_CTX *ctx,
				    const unsigned char *key,
				    const unsigned char *iv, int enc,
				    int key_len);
static int dpdk_aes_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr);
static int create_crypto_operation_pl(struct ossl_dpdk_ctx *dpdk_ctx,
		const uint8_t *in, int len, int enc, uint8_t pipe_index);

const EVP_CIPHER *dpdkcpt_aes_128_gcm(void);
const EVP_CIPHER *dpdkcpt_aes_256_gcm(void);
void ARMv8_AES_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
		size_t len, const AES_KEY *key,
		const unsigned char ivec[16]);

EVP_CIPHER *_hidden_aes_128_gcm = NULL;
EVP_CIPHER *_hidden_aes_256_gcm = NULL;

const EVP_CIPHER *dpdkcpt_aes_128_gcm(void)
{
	if (_hidden_aes_128_gcm != NULL)
		return _hidden_aes_128_gcm;

	_hidden_aes_128_gcm = EVP_CIPHER_meth_new(NID_aes_128_gcm,
					1, E_DPDKCPT_AES128_GCM_KEY_LENGTH);

	if (!EVP_CIPHER_meth_set_iv_length (_hidden_aes_128_gcm,
						E_DPDKCPT_AES_GCM_IV_LENGTH) ||
		!EVP_CIPHER_meth_set_init(_hidden_aes_128_gcm,
				      dpdkcpt_aes128_gcm_init_key) ||
	    !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_gcm,
					   dpdkcpt_aes_gcm_cipher) ||
	    !EVP_CIPHER_meth_set_cleanup(_hidden_aes_128_gcm,
					 dpdkcpt_aes_gcm_cleanup) ||
	    !EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_gcm, dpdk_aes_gcm_ctrl) ||
		!EVP_CIPHER_meth_set_flags(_hidden_aes_128_gcm, AES_GCM_FLAGS) ||
	    !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_128_gcm,
					       sizeof(struct ossl_dpdk_ctx))) {
		EVP_CIPHER_meth_free(_hidden_aes_128_gcm);
		_hidden_aes_128_gcm = NULL;
	}
	return _hidden_aes_128_gcm;
}

const EVP_CIPHER *dpdkcpt_aes_256_gcm(void)
{
	if (_hidden_aes_256_gcm != NULL)
		return _hidden_aes_256_gcm;

	_hidden_aes_256_gcm = EVP_CIPHER_meth_new(NID_aes_256_gcm,
					1, E_DPDKCPT_AES256_GCM_KEY_LENGTH);

	if (!EVP_CIPHER_meth_set_iv_length (_hidden_aes_256_gcm,
						E_DPDKCPT_AES_GCM_IV_LENGTH) ||
		!EVP_CIPHER_meth_set_init(_hidden_aes_256_gcm,
				      dpdkcpt_aes256_gcm_init_key) ||
	    !EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_gcm,
					   dpdkcpt_aes_gcm_cipher) ||
	    !EVP_CIPHER_meth_set_cleanup(_hidden_aes_256_gcm,
					 dpdkcpt_aes_gcm_cleanup) ||
	    !EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_gcm, dpdk_aes_gcm_ctrl) ||
		!EVP_CIPHER_meth_set_flags(_hidden_aes_256_gcm, AES_GCM_FLAGS) ||
	    !EVP_CIPHER_meth_set_impl_ctx_size(_hidden_aes_256_gcm,
					       sizeof(struct ossl_dpdk_ctx))) {
		EVP_CIPHER_meth_free(_hidden_aes_256_gcm);
		_hidden_aes_256_gcm = NULL;
	}
	return _hidden_aes_256_gcm;
}

/*
 * Create AEAD Session for TLS
 */
static int create_aead_session(enum rte_crypto_aead_algorithm algo,
			       struct ossl_dpdk_ctx *dpdk_ctx, int enc,
			       int aad_len, uint8_t reconfigure)
{
	struct rte_crypto_sym_xform aead_xform;
	int retval;

	if (reconfigure) {
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		retval = rte_cryptodev_sym_session_free(dpdk_ctx->dev_id,
				(struct rte_cryptodev_sym_session *)
				dpdk_ctx->aead_cry_session);

#else
		retval = rte_cryptodev_sym_session_clear(
				dpdk_ctx->dev_id,
				(struct rte_cryptodev_sym_session *)
				dpdk_ctx->aead_cry_session);
#endif
		if (retval < 0)
			engine_log(ENG_LOG_ERR, "FAILED to free session\n");
	}
	/* Setup AEAD Parameters */
	aead_xform.type = RTE_CRYPTO_SYM_XFORM_AEAD;
	aead_xform.next = NULL;
	aead_xform.aead.algo = algo;
	aead_xform.aead.op = CRYPTO_OP(enc);
	aead_xform.aead.key.data = dpdk_ctx->key;
	aead_xform.aead.key.length = dpdk_ctx->keylen;
	aead_xform.aead.iv.offset = E_DPDKCPT_IV_OFFSET;
	aead_xform.aead.iv.length = E_DPDKCPT_AES_GCM_IV_LENGTH;
	aead_xform.aead.digest_length = E_DPDKCPT_AEAD_DIGEST_LENGTH;
	aead_xform.aead.aad_length = aad_len;

	/* Create Crypto session*/
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		dpdk_ctx->aead_cry_session =
			rte_cryptodev_sym_session_create(dpdk_ctx->dev_id,
							&aead_xform,
							sym_session_pool);
		if (dpdk_ctx->aead_cry_session == NULL) {
			engine_log(ENG_LOG_ERR, "Could not create session.\n");
			return -1;
		}
#else
		if (!reconfigure) {
			dpdk_ctx->aead_cry_session =
				rte_cryptodev_sym_session_create(sym_session_pool);
			if (dpdk_ctx->aead_cry_session == NULL) {
				engine_log(ENG_LOG_ERR, "Could not create session.\n");
				return -1;
			}
		}

		if (rte_cryptodev_sym_session_init(dpdk_ctx->dev_id,
						dpdk_ctx->aead_cry_session, &aead_xform,
						sym_session_priv_pool) < 0) {
			engine_log(ENG_LOG_ERR, "Session could not be initialized "
					"for the crypto device\n");
			return -1;
		}
#endif

	return 0;
}

/*
 * Create CIPHER Session for Crypto operation only
 */
static int create_cipher_session(
				enum rte_crypto_cipher_algorithm algo,
				struct ossl_dpdk_ctx *dpdk_ctx, int enc)
{
	struct rte_crypto_sym_xform cipher_xform = {
		.next = NULL,
		.type = RTE_CRYPTO_SYM_XFORM_CIPHER,
		.cipher = { .op = enc ? RTE_CRYPTO_CIPHER_OP_ENCRYPT :
					RTE_CRYPTO_CIPHER_OP_DECRYPT,
			    .algo = algo,
			    .key = { .length = dpdk_ctx->keylen },
			    .iv = { .offset = E_DPDKCPT_IV_OFFSET,
				    .length = E_DPDKCPT_AES_CTR_IV_LENGTH } }
	};
	cipher_xform.cipher.key.data = (uint8_t *)dpdk_ctx->key;

	/* Create crypto session and initialize it for the crypto device. */
	if (dpdk_ctx->cipher_cry_session == NULL) {
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		dpdk_ctx->cipher_cry_session =
			(void *)rte_cryptodev_sym_session_create(dpdk_ctx->dev_id,
								&cipher_xform,
								sym_session_pool);
#else
		dpdk_ctx->cipher_cry_session =
			(void *)rte_cryptodev_sym_session_create(sym_session_pool);
#endif

		if (dpdk_ctx->cipher_cry_session == NULL) {
			engine_log(ENG_LOG_ERR, "Session could not be created\n");
			return -1;
		}

#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		if (rte_cryptodev_sym_session_init(dpdk_ctx->dev_id,
					dpdk_ctx->cipher_cry_session,
					&cipher_xform,
					sym_session_priv_pool) < 0) {
			engine_log(ENG_LOG_ERR, "Session could not be initialized "
					"for the crypto device\n");
			return -1;
		}
#endif
	}

	return 0;
}

/*
 * Common crypto operation for both TLS and Crypto case
 */
static int create_crypto_operation(EVP_CIPHER_CTX *ctx,
				   struct ossl_dpdk_ctx *dpdk_ctx,
				   const uint8_t *in, int len, int enc)
{
	unsigned int aad_pad_len = 0, plaintext_pad_len = 0;

	/* Generate Crypto op data structure */
	dpdk_ctx->op = rte_crypto_op_alloc(crypto_sym_op_pool,
					   RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (dpdk_ctx->op == NULL)
		engine_log(ENG_LOG_ERR, "Failed to create crypto_op\n");

	struct rte_crypto_sym_op *sym_op = dpdk_ctx->op->sym;
	if (dpdk_ctx->tls_aad_len >= 0) {
		aad_pad_len = RTE_ALIGN_CEIL(dpdk_ctx->tls_aad_len, 16);
		sym_op->aead.aad.data = (uint8_t *)rte_pktmbuf_append(
			dpdk_ctx->ibuf, aad_pad_len);

		sym_op->aead.aad.phys_addr = rte_pktmbuf_iova(dpdk_ctx->ibuf);
		memcpy(sym_op->aead.aad.data, EVP_CIPHER_CTX_buf_noconst(ctx),
		       dpdk_ctx->tls_aad_len);
	} else if (dpdk_ctx->aad_len >= 0) {
		aad_pad_len = RTE_ALIGN_CEIL(dpdk_ctx->aad_len, 16);
		sym_op->aead.aad.data = (uint8_t *)rte_pktmbuf_append(
			dpdk_ctx->ibuf, aad_pad_len);

		sym_op->aead.aad.phys_addr = rte_pktmbuf_iova(dpdk_ctx->ibuf);
		memcpy(sym_op->aead.aad.data, dpdk_ctx->aad,
		       dpdk_ctx->aad_len);
	} else {
		dpdk_ctx->op->sym->cipher.data.offset = 0;
		dpdk_ctx->op->sym->cipher.data.length = len;
	}

	/* Append IV at the end of the crypto operation*/
	uint8_t *iv_ptr = rte_crypto_op_ctod_offset(dpdk_ctx->op, uint8_t *,
						    E_DPDKCPT_IV_OFFSET);
	if (iv_ptr == NULL)
		engine_log(ENG_LOG_ERR, "IV_PTR is null\n");

	rte_memcpy(iv_ptr, dpdk_ctx->iv, dpdk_ctx->ivlen);

	if (dpdk_ctx->tls_aad_len >= 0 || dpdk_ctx->aad_len >= 0) {
		uint8_t *plaintext, *ciphertext;

		/* Append plaintext/ciphertext */
		if (CRYPTO_OP(enc) == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
			plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
			plaintext = (uint8_t *)rte_pktmbuf_append(
				dpdk_ctx->ibuf, plaintext_pad_len);

			memcpy(plaintext, in, len);

			/* Append digest data */
			sym_op->aead.digest.data =
				(uint8_t *)rte_pktmbuf_append(
					dpdk_ctx->ibuf, EVP_GCM_TLS_TAG_LEN);
			memset(sym_op->aead.digest.data, 0,
			       EVP_GCM_TLS_TAG_LEN);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(
				dpdk_ctx->ibuf,
				plaintext_pad_len + aad_pad_len);

		} else {
			plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
			ciphertext = (uint8_t *)rte_pktmbuf_append(
				dpdk_ctx->ibuf, plaintext_pad_len);

			memcpy(ciphertext, in, len);

			/* Append digest data */
			sym_op->aead.digest.data =
				(uint8_t *)rte_pktmbuf_append(
					dpdk_ctx->ibuf, EVP_GCM_TLS_TAG_LEN);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(
				dpdk_ctx->ibuf,
				plaintext_pad_len + aad_pad_len);

			rte_memcpy(in + plaintext_pad_len + aad_pad_len, sym_op->aead.digest.data,
				   EVP_GCM_TLS_TAG_LEN);
		}
		sym_op->aead.data.length = len;
		sym_op->aead.data.offset = aad_pad_len;
	}

	return 0;
}

static int create_crypto_operation_pl(struct ossl_dpdk_ctx *dpdk_ctx,
		const uint8_t *in, int len, int enc, uint8_t pipe_index)
{
	unsigned int aad_pad_len = 0, plaintext_pad_len = 0;

	dpdk_ctx->ops[pipe_index] = rte_crypto_op_alloc(crypto_sym_op_pool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (unlikely(dpdk_ctx->ops[pipe_index] == NULL)) {
		engine_log(ENG_LOG_ERR, "Failed to create crypto_ops for pipe: %d\n", pipe_index);
		return -1;
	}
	struct rte_crypto_sym_op *sym_op = dpdk_ctx->ops[pipe_index]->sym;
	if (dpdk_ctx->tls_aad_len >= 0) {
		aad_pad_len = RTE_ALIGN_CEIL(dpdk_ctx->tls_aad_len, 16);
		sym_op->aead.aad.data = (uint8_t *)rte_pktmbuf_append(
				dpdk_ctx->ibufs[pipe_index], aad_pad_len);
		sym_op->aead.aad.phys_addr = rte_pktmbuf_iova(
				dpdk_ctx->ibufs[pipe_index]);
		memcpy(sym_op->aead.aad.data, dpdk_ctx->aad_pipe[pipe_index],
				dpdk_ctx->tls_aad_len);
	}
	/* Append IV at the end of the crypto operation*/
	uint8_t *iv_ptr = rte_crypto_op_ctod_offset(dpdk_ctx->ops[pipe_index],
			uint8_t *, E_DPDKCPT_IV_OFFSET);
	if (iv_ptr == NULL)
		engine_log(ENG_LOG_ERR, "IV_PTR is null\n");
	rte_memcpy(iv_ptr, dpdk_ctx->iv, dpdk_ctx->ivlen);
	if (dpdk_ctx->tls_aad_len >= 0 || dpdk_ctx->aad_len >= 0) {
		uint8_t *plaintext, *ciphertext;
		/* Append plaintext/ciphertext */
		if (CRYPTO_OP(enc) == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
			plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
			plaintext = (uint8_t *)rte_pktmbuf_append(
					dpdk_ctx->ibufs[pipe_index], plaintext_pad_len);
			memcpy(plaintext, in, len);
			/* Append digest data */
			sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
					dpdk_ctx->ibufs[pipe_index], EVP_GCM_TLS_TAG_LEN);
			memset(sym_op->aead.digest.data, 0, EVP_GCM_TLS_TAG_LEN);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(
					dpdk_ctx->ibufs[pipe_index], plaintext_pad_len + aad_pad_len);
		} else {
			plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
			ciphertext = (uint8_t *)rte_pktmbuf_append(
					dpdk_ctx->ibufs[pipe_index], plaintext_pad_len);
			memcpy(ciphertext, in, len);
			/* Append digest data */
			sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
					dpdk_ctx->ibufs[pipe_index], EVP_GCM_TLS_TAG_LEN);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(
					dpdk_ctx->ibufs[pipe_index], plaintext_pad_len + aad_pad_len);
			rte_memcpy(sym_op->aead.digest.data, in + len, EVP_GCM_TLS_TAG_LEN);
		}
		sym_op->aead.data.length = len;
		sym_op->aead.data.offset = aad_pad_len;
	}
	return 0;
}

int dpdkcpt_aes128_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
				const unsigned char *iv, int enc)
{
	return dpdkcpt_aes_gcm_init_key(ctx, key, iv, enc,
					E_DPDKCPT_AES128_GCM_KEY_LENGTH);
}

int dpdkcpt_aes256_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
				const unsigned char *iv, int enc)
{
	return dpdkcpt_aes_gcm_init_key(ctx, key, iv, enc,
					E_DPDKCPT_AES256_GCM_KEY_LENGTH);
}

int dpdkcpt_aes_gcm_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			     const unsigned char *iv, int enc, int key_len)
{
	if (iv == NULL && key == NULL)
		return 1;
	struct ossl_dpdk_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);

	unsigned int lcore = rte_lcore_id();
	if (lcore == LCORE_ID_ANY || sym_dev_id[lcore] == -1) {
		engine_log(ENG_LOG_ERR, "%s: Queues not available for lcore %d\n",
			__FUNCTION__, lcore);
		return 0;
	}
	dpdk_ctx->dev_id = sym_dev_id[lcore];

	if (key != NULL) {
		dpdk_ctx->keylen = key_len;
		memcpy(dpdk_ctx->key, key, key_len);
		dpdk_ctx->key_set = 1;

		ARMv8_AES_set_encrypt_key(key, key_len * 8, &dpdk_ctx->ks.ks);
		CRYPTO_gcm128_init(&dpdk_ctx->gcm, &dpdk_ctx->ks, (block128_f) ARMv8_AES_encrypt);
		dpdk_ctx->ctr = (ctr128_f) ARMv8_AES_ctr32_encrypt_blocks;
		int retval = create_aead_session(RTE_CRYPTO_AEAD_AES_GCM,
						dpdk_ctx, enc,
						EVP_AEAD_TLS1_AAD_LEN, 0);
		if (retval < 0) {
			engine_log(ENG_LOG_ERR, "AEAD Sesion creation failed.\n");
			return 0;
		}

		int ret = create_cipher_session(RTE_CRYPTO_CIPHER_AES_CTR,
						dpdk_ctx, enc);
		if (ret < 0) {
			engine_log(ENG_LOG_ERR, "Cipher Sesion creation failed.\n");
			return 0;
		}
		if (iv == NULL && dpdk_ctx->iv_set)
			iv = (const unsigned char*)&dpdk_ctx->iv;
		if (iv) {
			CRYPTO_gcm128_setiv(&dpdk_ctx->gcm, iv, dpdk_ctx->ivlen);
			memcpy(dpdk_ctx->iv, iv, dpdk_ctx->ivlen);
			dpdk_ctx->iv_set = 1;
		}
	} else {
		if (dpdk_ctx->key_set)
			CRYPTO_gcm128_setiv(&dpdk_ctx->gcm, iv, dpdk_ctx->ivlen);
		memcpy(dpdk_ctx->iv, iv, dpdk_ctx->ivlen);
		dpdk_ctx->iv_set = 1;
		dpdk_ctx->iv_gen = 0;
	}

	dpdk_ctx->numpipes = 0;
	return 1;
}

/*
 * GCM ctrl function
 */

int dpdk_aes_gcm_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
	struct ossl_dpdk_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(c);
	unsigned char *buf;

	switch (type) {
	case EVP_CTRL_INIT:
		memset(dpdk_ctx, 0, sizeof(struct ossl_dpdk_ctx));
		dpdk_ctx->key_set = 0;
		dpdk_ctx->iv_set = 0;
		dpdk_ctx->ivlen = E_DPDKCPT_AES_GCM_IV_LENGTH;
		memcpy(dpdk_ctx->iv, EVP_CIPHER_CTX_iv_noconst(c),
		       dpdk_ctx->ivlen);
		dpdk_ctx->taglen = -1;
		dpdk_ctx->aad_len = -1;
		dpdk_ctx->iv_gen = 0;
		dpdk_ctx->tls_aad_len = -1;
		dpdk_ctx->hw_offload_pkt_sz_threshold = hw_offload_pktsz_thresh;

		return 1;

	//! Below control cmd added in openssl-1.1.1g version
	#if OPENSSL_VERSION_NUMBER >= 0x1010107fL
	case EVP_CTRL_GET_IVLEN:
		*(int *)ptr = dpdk_ctx->ivlen;
		return 1;
	#endif

	case EVP_CTRL_AEAD_SET_IVLEN:
		if (arg <= 0)
			return 0;
		/* Allocate memory for IV if needed */
		if ((arg > EVP_MAX_IV_LENGTH) && (arg > dpdk_ctx->ivlen)) {
			if (dpdk_ctx->iv == NULL)
				return 0;
		}
		dpdk_ctx->ivlen = arg;
		return 1;

	case EVP_CTRL_GCM_SET_IV_FIXED:
		/* Special case: -1 length restores whole IV */
		if (arg == -1) {
			memcpy(dpdk_ctx->iv, ptr, dpdk_ctx->ivlen - arg);
			dpdk_ctx->iv_gen = 1;
			return 1;
		}
		/*
		 * Fixed field must be at least 4 bytes and invocation field
		 * at least 8.
		 */
		if ((arg < 4) || (dpdk_ctx->ivlen - arg) < 8)
			return 0;
		if (arg)
			memcpy((uint8_t *)dpdk_ctx->iv, ptr, arg);
		if (EVP_CIPHER_CTX_encrypting(c) &&
		    RAND_bytes((uint8_t *)&dpdk_ctx->iv[2],
			       dpdk_ctx->ivlen - arg) <= 0)
			return 0;
		dpdk_ctx->iv_gen = 1;
		return 1;

	case EVP_CTRL_GCM_IV_GEN:
		if (dpdk_ctx->iv_gen == 0 || dpdk_ctx->key_set == 0)
			return 0;
		memcpy((uint8_t *)dpdk_ctx->iv + dpdk_ctx->ivlen - arg,
		       &dpdk_ctx->iv[2], arg);
		if (arg <= 0 || arg > dpdk_ctx->ivlen)
			arg = dpdk_ctx->ivlen;
		memcpy(ptr, &dpdk_ctx->iv[2], arg);
		CRYPTO_gcm128_setiv(&dpdk_ctx->gcm,
				    (const uint8_t *)&dpdk_ctx->iv,
				    dpdk_ctx->ivlen);
		/*
		 * Invocation field will be at least 8 bytes in size and
		 * so no need to check wrap around or increment more than
		 * last 8 bytes.
		 */
		dpdk_ctx->iv[2]++;
		dpdk_ctx->iv_set = 1;
		return 1;

	case EVP_CTRL_GCM_SET_IV_INV:
		if (dpdk_ctx->iv_gen == 0 || dpdk_ctx->key_set == 0 ||
		    EVP_CIPHER_CTX_encrypting(c))
			return 0;
		memcpy((uint8_t *)dpdk_ctx->iv + dpdk_ctx->ivlen - arg, ptr,
		       arg);
		CRYPTO_gcm128_setiv(&dpdk_ctx->gcm,
				    (const uint8_t *)&dpdk_ctx->iv,
				    dpdk_ctx->ivlen);
		dpdk_ctx->iv_set = 1;
		return 1;

	case EVP_CTRL_AEAD_TLS1_AAD:
		/* Save the AAD for later use */
		if (arg != EVP_AEAD_TLS1_AAD_LEN)
			return 0;
		memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
		dpdk_ctx->tls_aad_len = arg;
		{
			unsigned int len =
				EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8 |
				EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];
			/* Correct length for explicit IV */
			if (len < EVP_GCM_TLS_EXPLICIT_IV_LEN)
				return 0;
			len -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
			/* If decrypting correct for tag too */
			if (!EVP_CIPHER_CTX_encrypting(c)) {
				if (len < EVP_GCM_TLS_TAG_LEN)
					return 0;
				len -= EVP_GCM_TLS_TAG_LEN;
			}
			EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = len >> 8;
			EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xff;
		}
		if (dpdk_ctx->aad_cnt < SSL_MAX_PIPELINES) {
			memcpy(dpdk_ctx->aad_pipe[dpdk_ctx->aad_cnt],
					EVP_CIPHER_CTX_buf_noconst(c), arg);
			dpdk_ctx->aad_cnt++;
		} else {
			engine_log(ENG_LOG_ERR, "In a single go, max. AAD count is 32\n");
			return 0;
		}

		/* Extra padding: tag appended to record */
		return EVP_GCM_TLS_TAG_LEN;

	case EVP_CTRL_AEAD_SET_TAG:
		if (arg <= 0 || arg > 16 || EVP_CIPHER_CTX_encrypting(c))
			return 0;
		buf = EVP_CIPHER_CTX_buf_noconst(c);
		memcpy(dpdk_ctx->auth_tag, ptr, arg);
		memcpy(buf, ptr, arg);
		dpdk_ctx->taglen = arg;
		return 1;

	case EVP_CTRL_AEAD_GET_TAG:
		if (arg <= 0 || arg > 16 || !EVP_CIPHER_CTX_encrypting(c) ||
		    dpdk_ctx->taglen < 0)
			return 0;
		memcpy(ptr, dpdk_ctx->auth_tag, arg);
		return 1;

	case EVP_CTRL_SET_PIPELINE_OUTPUT_BUFS:
		dpdk_ctx->numpipes = arg;
		dpdk_ctx->output_buf = ptr;
		return 1;

	case EVP_CTRL_SET_PIPELINE_INPUT_BUFS:
		dpdk_ctx->numpipes = arg;
		dpdk_ctx->input_buf = ptr;
		return 1;

	case EVP_CTRL_SET_PIPELINE_INPUT_LENS:
		dpdk_ctx->numpipes = arg;
		dpdk_ctx->input_len = ptr;
		return 1;

	default:
		return -1;
	}
}

/*
 *Pure crypto application (Cipher case only)
 */
static int crypto_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			     const unsigned char *in, size_t len)
{
	struct ossl_dpdk_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
	struct rte_mbuf *mbuf = NULL;

	int enc = EVP_CIPHER_CTX_encrypting(ctx);

	ossl_cry_op_status_t *status_curr_job;
	int rv = -1;
	/*
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     */
	/* AAD data is stored in dpdk_ctx->aad */

	/* Create crypto session and initialize it for the
     * crypto device.
     */
	int retval;

	dpdk_ctx->ibuf = rte_pktmbuf_alloc(mbuf_pool);

	if (dpdk_ctx->ibuf == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create a mbuf\n");
		return -1;
	}

	void *buf = rte_pktmbuf_append(dpdk_ctx->ibuf, len);
	if (buf == NULL) {
		engine_log(ENG_LOG_ERR, "Not enough room in the mbuf\n");
		return 0;
	}

	/* get databuf pointer pointing to start of pkt. */
	buf = rte_pktmbuf_mtod_offset(dpdk_ctx->ibuf, char *, 0);
	memcpy(buf, in, len);

	/* Create AEAD operation */
	retval = create_crypto_operation(ctx, dpdk_ctx, in, len, enc);
	if (retval < 0)
		return retval;

	rte_crypto_op_attach_sym_session(dpdk_ctx->op,
					 dpdk_ctx->cipher_cry_session);
	dpdk_ctx->op->sym->m_src = dpdk_ctx->ibuf;

	status_curr_job =
		rte_crypto_op_ctod_offset(dpdk_ctx->op, ossl_cry_op_status_t *,
					  E_DPDKCPT_COP_METADATA_OFF);

	status_curr_job->is_complete = 0;
	status_curr_job->is_successful = 0;

	/* Enqueue this crypto operation in the crypto device. */
	uint16_t num_enqueued_ops =
		rte_cryptodev_enqueue_burst(dpdk_ctx->dev_id,
				sym_queues[rte_lcore_id()], &dpdk_ctx->op, 1);

	if (num_enqueued_ops != 1) {
		engine_log(ENG_LOG_ERR, "Crypto operation enqueue failed\n");
		return 0;
	}

	uint16_t num_dequeued_ops;
	struct rte_crypto_op *dequeued_ops[E_DPDKCPT_NUM_DEQUEUED_OPS];

	while (!status_curr_job->is_complete) {
		pause_async_job();

		num_dequeued_ops =
			rte_cryptodev_dequeue_burst(dpdk_ctx->dev_id,
							sym_queues[rte_lcore_id()],
						    dequeued_ops,
						    E_DPDKCPT_NUM_DEQUEUED_OPS);

		for (int j = 0; j < num_dequeued_ops; j++) {
			ossl_cry_op_status_t *status_of_job;
			status_of_job = rte_crypto_op_ctod_offset(
				dequeued_ops[j], ossl_cry_op_status_t *,
				E_DPDKCPT_COP_METADATA_OFF);

			status_of_job->is_complete = 1;
			/* Check if operation was processed successfully */
			if (dequeued_ops[j]->status !=
			    RTE_CRYPTO_OP_STATUS_SUCCESS) {
		        engine_log(ENG_LOG_ERR, "Crypto (CTR) op status is not success (err:%d)\n",
				       dequeued_ops[j]->status);
				status_of_job->is_successful = 0;
			} else {
				status_of_job->is_successful = 1;
			}
		}
	}

	mbuf = dpdk_ctx->op->sym->m_src;

	if (!status_curr_job->is_successful) {
		rv = -1;
		goto err;
	}

	buf = rte_pktmbuf_mtod_offset(mbuf, char *,
				      dpdk_ctx->op->sym->cipher.data.offset);
	memcpy(out, buf, len);
	rv = len;

err:
	rte_mempool_put_bulk(crypto_sym_op_pool, (void **)&dpdk_ctx->op, 1);
	rte_pktmbuf_free(mbuf);
	dpdk_ctx->tls_aad_len = -1;
	return rv;
}

/*
 * Normal crypto application
 */
static int crypto_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			     const unsigned char *in, size_t len)
{
	struct ossl_dpdk_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
	struct rte_mbuf *mbuf = NULL;
	int ret;
	static uint8_t sw_encrypt = 0, sw_decrypt = 0;
	int enc = EVP_CIPHER_CTX_encrypting(ctx);

	if (in != NULL) {
		if (out == NULL) {
			if (CRYPTO_gcm128_aad(&dpdk_ctx->gcm, in, len))
				return -1;
			dpdk_ctx->aad =  rte_malloc(NULL, sizeof(uint8_t) * len, 0);
			if (!dpdk_ctx->aad)
			{
				engine_log(ENG_LOG_ERR, "AAD memory alloc failed\n");
				return -1;
			}
			memcpy(dpdk_ctx->aad, in, len);
			if ((size_t)dpdk_ctx->aad_len != len) {
				ret = create_aead_session(RTE_CRYPTO_AEAD_AES_GCM,
							dpdk_ctx, enc, len, 1);
				if (ret < 0) {
					engine_log(ENG_LOG_ERR, "Create aead session "
							"failed\n");
					return ret;
				}
				dpdk_ctx->aad_len = len;
			}
			return len;
		} else if (enc) {
			if (len < dpdk_ctx->hw_offload_pkt_sz_threshold) {
				if (CRYPTO_gcm128_encrypt_ctr32(&dpdk_ctx->gcm,
							in,
							out,
							len, dpdk_ctx->ctr)) {
					dpdk_ctx->tls_aad_len = -1;
					dpdk_ctx->aad_len = -1;
					return -1;
				}
				sw_encrypt = 1;
				return len;
			}
		} else {
			if (len < dpdk_ctx->hw_offload_pkt_sz_threshold) {
				if (CRYPTO_gcm128_decrypt_ctr32(&dpdk_ctx->gcm,
							in,
							out,
							len, dpdk_ctx->ctr)) {
					dpdk_ctx->tls_aad_len = -1;
					dpdk_ctx->aad_len = -1;
					return -1;
				}
				sw_decrypt = 1;
				return len;
			}
		}
	} else {
		if (!enc) {
			if (dpdk_ctx->taglen < 0)
				return -1;
			if (sw_decrypt) {
				ret = CRYPTO_gcm128_finish(&dpdk_ctx->gcm,
						EVP_CIPHER_CTX_buf_noconst(ctx),
						dpdk_ctx->taglen);
				if (ret != 0)
					return -1;
				sw_decrypt = 0;
			}
			memcpy(dpdk_ctx->auth_tag,
				EVP_CIPHER_CTX_buf_noconst(ctx), 16);
			dpdk_ctx->iv_set = 0;
			return 0;
		}
		if (sw_encrypt) {
			CRYPTO_gcm128_tag(&dpdk_ctx->gcm,
					  EVP_CIPHER_CTX_buf_noconst(ctx), 16);
			sw_encrypt = 0;
		}
		memcpy(dpdk_ctx->auth_tag, EVP_CIPHER_CTX_buf_noconst(ctx), 16);
		dpdk_ctx->taglen = 16;
		/* Don't reuse the IV */
		dpdk_ctx->iv_set = 0;
		return 0;
	}

	if (dpdk_ctx->aad_len == -1) {
		int ret = crypto_ctr_cipher(ctx, out, in, len);
		return ret;
	}
	ossl_cry_op_status_t *status_curr_job;
	int rv = -1;
	/*
     * Set IV from start of buffer or generate IV and write to start of
     * buffer.
     */
	/* AAD data is stored in dpdk_ctx->aad */

	/* Create crypto session and initialize it for the
     * crypto device.
     */
	int retval;

	dpdk_ctx->ibuf = rte_pktmbuf_alloc(mbuf_pool);

	if (dpdk_ctx->ibuf == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create a mbuf\n");
		return -1;
	}

	/* Create AEAD operation */
	retval = create_crypto_operation(ctx, dpdk_ctx, in, len, enc);
	if (retval < 0)
		return retval;
	rte_crypto_op_attach_sym_session(dpdk_ctx->op,
					 dpdk_ctx->aead_cry_session);

	dpdk_ctx->op->sym->m_src = dpdk_ctx->ibuf;

	status_curr_job =
		rte_crypto_op_ctod_offset(dpdk_ctx->op, ossl_cry_op_status_t *,
					  E_DPDKCPT_COP_METADATA_OFF);

	status_curr_job->is_complete = 0;
	status_curr_job->is_successful = 0;
	void *buf;
	/* Enqueue this crypto operation in the crypto device. */
	uint16_t num_enqueued_ops =
		rte_cryptodev_enqueue_burst(dpdk_ctx->dev_id,
				sym_queues[rte_lcore_id()], &dpdk_ctx->op, 1);

	if (num_enqueued_ops != 1) {
		engine_log(ENG_LOG_ERR, "Crypto operation enqueue failed\n");
		return 0;
	}

	uint16_t num_dequeued_ops;
	struct rte_crypto_op *dequeued_ops[E_DPDKCPT_NUM_DEQUEUED_OPS];

	while (!status_curr_job->is_complete) {
		pause_async_job();

		num_dequeued_ops =
			rte_cryptodev_dequeue_burst(dpdk_ctx->dev_id,
							sym_queues[rte_lcore_id()],
						    dequeued_ops,
						    E_DPDKCPT_NUM_DEQUEUED_OPS);

		for (int j = 0; j < num_dequeued_ops; j++) {
			ossl_cry_op_status_t *status_of_job;
			status_of_job = rte_crypto_op_ctod_offset(
				dequeued_ops[j], ossl_cry_op_status_t *,
				E_DPDKCPT_COP_METADATA_OFF);

			status_of_job->is_complete = 1;
			/* Check if operation was processed successfully */
			if (dequeued_ops[j]->status !=
			    RTE_CRYPTO_OP_STATUS_SUCCESS) {
		        engine_log(ENG_LOG_ERR, "Crypto (GCM) op status is not success (err:%d)\n",
				       dequeued_ops[j]->status);
				status_of_job->is_successful = 0;
			} else {
				status_of_job->is_successful = 1;
			}
		}
	}

	mbuf = dpdk_ctx->op->sym->m_src;

	if (!status_curr_job->is_successful) {
		rv = -1;
		goto err;
	}

	buf = rte_pktmbuf_mtod_offset(mbuf, char *,
				      dpdk_ctx->op->sym[0].aead.data.offset);
	memcpy(out, buf, len);
	rv = len;
	if (enc) {
		memcpy(EVP_CIPHER_CTX_buf_noconst(ctx),
		       dpdk_ctx->op->sym[0].aead.digest.data,
		       EVP_GCM_TLS_TAG_LEN);
		memcpy(dpdk_ctx->auth_tag,
		       dpdk_ctx->op->sym[0].aead.digest.data,
		       EVP_GCM_TLS_TAG_LEN);
	}
err:
	rte_mempool_put_bulk(crypto_sym_op_pool, (void **)&dpdk_ctx->op, 1);
	rte_pktmbuf_free(mbuf);
	dpdk_ctx->tls_aad_len = -1;
	dpdk_ctx->aad_len = -1;
	return rv;
}

/*
 * TLS application case
 */
static int aes_gcm_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
{
	struct rte_crypto_op *deq_op_ptr[E_DPDKCPT_NUM_DEQUEUED_OPS];
	volatile uint16_t num_enqueued_ops, num_dequeued_ops;
	ossl_cry_op_status_t **status_ptr = NULL;
	ossl_cry_op_status_t *new_st_ptr[E_DPDKCPT_NUM_DEQUEUED_OPS];
	ossl_cry_op_status_t current_job;
	uint8_t i, j, k, numpipes, numalloc;
	struct ossl_dpdk_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
	int enc = EVP_CIPHER_CTX_encrypting(ctx), ret;
	uint16_t datalen = (uint16_t)(len - EVP_GCM_TLS_EXPLICIT_IV_LEN - EVP_GCM_TLS_TAG_LEN);
	ASYNC_JOB *job = NULL;
	ASYNC_WAIT_CTX *wctx_local = NULL;
	async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];
	uint8_t pip_jb_qsz = 0;

	/* Encrypt/decrypt must be performed in place */
	if (out != in ||
			len < (EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN))
		return -1;
	numpipes = dpdk_ctx->numpipes;
	/* Bydefault number of pipe is one */
	if (numpipes == 0) {
		numpipes = 1;
		dpdk_ctx->input_buf = (uint8_t **)&in;
		dpdk_ctx->output_buf = &out;
		dpdk_ctx->input_len = &len;
	}

	if ((datalen < dpdk_ctx->hw_offload_pkt_sz_threshold) && (numpipes == 1)) {
		if (EVP_CIPHER_CTX_ctrl(
					ctx, enc ? EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
					EVP_GCM_TLS_EXPLICIT_IV_LEN, out) <= 0) {
			engine_log (ENG_LOG_ERR, "Failed to set IV from start of buffer\n");
			ret = -1;
			goto skip_free_buf;
		}
		if (CRYPTO_gcm128_aad(&dpdk_ctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx),
					dpdk_ctx->tls_aad_len)) {
			engine_log (ENG_LOG_ERR, "Set AAD failed!!!\n");
			ret = -1;
			goto skip_free_buf;
		}
		/* Fix buffer and length to point to payload */
		in += EVP_GCM_TLS_EXPLICIT_IV_LEN;
		out += EVP_GCM_TLS_EXPLICIT_IV_LEN;
		len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
		if (enc) {
			if (CRYPTO_gcm128_encrypt_ctr32(&dpdk_ctx->gcm,
						in,
						out,
						len, dpdk_ctx->ctr)) {
				engine_log (ENG_LOG_ERR, "ARM v8 Encrypt "
						"failed!!!\n");
				ret = -1;
				goto skip_free_buf;
			}
			out += len;
			/* Finally write tag */
			CRYPTO_gcm128_tag(&dpdk_ctx->gcm, out,
					EVP_GCM_TLS_TAG_LEN);
			ret = len + EVP_GCM_TLS_EXPLICIT_IV_LEN +
				EVP_GCM_TLS_TAG_LEN;
		} else {
			if (CRYPTO_gcm128_decrypt_ctr32(&dpdk_ctx->gcm,
						in,
						out,
						len, dpdk_ctx->ctr)) {
				engine_log (ENG_LOG_ERR, "ARM v8 Decrypt "
						"failed!!!\n");
				ret = -1;
				goto skip_free_buf;

			}/* Retrieve tag */
			CRYPTO_gcm128_tag(&dpdk_ctx->gcm, EVP_CIPHER_CTX_buf_noconst(ctx),
					EVP_GCM_TLS_TAG_LEN);
			/* If tag mismatch wipe buffer */
			if (CRYPTO_memcmp(EVP_CIPHER_CTX_buf_noconst(ctx), in + len,
						EVP_GCM_TLS_TAG_LEN)) {
				OPENSSL_cleanse(out, len);
				engine_log (ENG_LOG_ERR, "TAG mismatch "
						"found!!!\n");
				ret = -1;
				goto skip_free_buf;
			}
			ret = len;

		}
		goto skip_free_buf;
	}

	status_ptr = OPENSSL_malloc(sizeof(ossl_cry_op_status_t *) * numpipes);
	if (unlikely(status_ptr == NULL)) {
		engine_log(ENG_LOG_ERR, "OPENSSL_malloc failed\n");
		numalloc = 0;
		ret = -1;
		goto free_resources;
	}

	job = ASYNC_get_current_job();
	if (job != NULL)
		wctx_local = (ASYNC_WAIT_CTX *)ASYNC_get_wait_ctx(job);

	for (i = 0; i < numpipes; i++) {
		/* Set IV from start of buffer or generate IV and write to
		 * start of buffer. */
		if (EVP_CIPHER_CTX_ctrl(
					ctx, enc ? EVP_CTRL_GCM_IV_GEN : EVP_CTRL_GCM_SET_IV_INV,
					EVP_GCM_TLS_EXPLICIT_IV_LEN, dpdk_ctx->output_buf[i]) <= 0) {
			engine_log (ENG_LOG_ERR, "Failed to set IV from start of buffer\n");
		}
		dpdk_ctx->input_buf[i] += EVP_GCM_TLS_EXPLICIT_IV_LEN;
		if (numpipes == 0 || numpipes == 1) {
			dpdk_ctx->output_buf[i] += EVP_GCM_TLS_EXPLICIT_IV_LEN;
		}
		dpdk_ctx->input_len[i] -= EVP_GCM_TLS_EXPLICIT_IV_LEN + EVP_GCM_TLS_TAG_LEN;
				/* Get a burst of mbufs */
		dpdk_ctx->ibufs[i] = rte_pktmbuf_alloc(mbuf_pool);
		if (unlikely(dpdk_ctx->ibufs[i] == NULL)) {
			engine_log (ENG_LOG_ERR, "Not enough mbufs available\n");
			numalloc = i;
			ret = -1;
			goto free_resources;
		}
		/* Create crypto session and initialize it for the crypto device */
		ret = create_crypto_operation_pl(dpdk_ctx, dpdk_ctx->input_buf[i],
				dpdk_ctx->input_len[i], enc, i);
		if (unlikely(ret < 0)) {
			/* roll back last buf */
			rte_pktmbuf_free(dpdk_ctx->ibufs[i]);
			dpdk_ctx->ibufs[i] = NULL;
			numalloc = i;
			ret = -1;
			goto free_resources;
		}
		rte_crypto_op_attach_sym_session(dpdk_ctx->ops[i], dpdk_ctx->aead_cry_session);
		dpdk_ctx->ops[i]->sym->m_src = dpdk_ctx->ibufs[i];
		status_ptr[i] = rte_crypto_op_ctod_offset(dpdk_ctx->ops[i], ossl_cry_op_status_t *,
				E_DPDKCPT_COP_METADATA_OFF);
		status_ptr[i]->is_complete = 0;
		status_ptr[i]->is_successful = 0;
		status_ptr[i]->numpipes = numpipes;
		status_ptr[i]->wctx_p = wctx_local;
	}
	/* Enqueue this crypto operation in the crypto device. */
	for (k = 0, num_enqueued_ops = 0;
	    (num_enqueued_ops < numpipes && k < MAX_ENQUEUE_ATTEMPTS); k++) {
		num_enqueued_ops +=
			rte_cryptodev_enqueue_burst(
				dpdk_ctx->dev_id, sym_queues[rte_lcore_id()],
				&dpdk_ctx->ops[num_enqueued_ops],
				numpipes - num_enqueued_ops);
	}
	if (unlikely(num_enqueued_ops < numpipes)) {
		engine_log(ENG_LOG_ERR, "Enqueue failed - too many attempts\n");
		numalloc = numpipes;
		ret = -1;
		goto free_resources;
	}
	CPT_ATOMIC_INC_N(cpt_num_cipher_pipeline_requests_in_flight, numpipes);
	CPT_ATOMIC_INC_N(cpt_num_requests_in_flight, numpipes);
	pause_async_job();

	CPT_ATOMIC_DEC_N(cpt_num_cipher_pipeline_requests_in_flight, numpipes);
	CPT_ATOMIC_DEC_N(cpt_num_requests_in_flight, numpipes);

	while (status_ptr[0]->is_successful == 0) {
		do {
			num_dequeued_ops = rte_cryptodev_dequeue_burst(
					dpdk_ctx->dev_id, sym_queues[rte_lcore_id()],
					&deq_op_ptr[0],
					E_DPDKCPT_NUM_DEQUEUED_OPS);

			/* Check the status of dequeued operations */
			for (j = 0; j < num_dequeued_ops; j++) {
				new_st_ptr[j] = rte_crypto_op_ctod_offset(deq_op_ptr[j],
						ossl_cry_op_status_t *, E_DPDKCPT_COP_METADATA_OFF);
				new_st_ptr[j]->is_complete = 1;
				/* Check if operation was processed successfully */
				if (deq_op_ptr[j]->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
		            engine_log(ENG_LOG_ERR, "Crypto (GCM-TLS) op status is not success (err:%d)\n",
							deq_op_ptr[j]->status);
					new_st_ptr[j]->is_successful = 0;
				} else {
					new_st_ptr[j]->is_successful = 1;
					if(new_st_ptr[j]->wctx_p)
					    check_for_job_completion(status_ptr[0]->wctx_p,
							    new_st_ptr[j]->wctx_p, new_st_ptr[j]->numpipes,
							    &pip_jb_qsz, &pip_jobs[0]);
				}
			}
		} while(pip_jb_qsz>0);
	}

	for (i = 0; i < numpipes; i++) {
		void *buf = rte_pktmbuf_mtod_offset(dpdk_ctx->ops[i]->sym->m_src, char *,
				dpdk_ctx->ops[i]->sym[0].aead.data.offset);
		memcpy(dpdk_ctx->output_buf[i], buf, dpdk_ctx->input_len[i]);
		memcpy(dpdk_ctx->output_buf[i] + dpdk_ctx->input_len[i],
				dpdk_ctx->ops[i]->sym[0].aead.digest.data, EVP_GCM_TLS_TAG_LEN);
		rte_pktmbuf_free(dpdk_ctx->ops[i]->sym->m_src);
		dpdk_ctx->ops[i]->sym->m_src = NULL;
	}
	rte_mempool_put_bulk(crypto_sym_op_pool, (void **)dpdk_ctx->ops, numpipes);
	for (j = 0; j < numpipes; j++)
		dpdk_ctx->ops[j] = NULL;
	ret = 1;
free_resources:
	if (unlikely(ret < 0)) {
		for (i = 0; i < numalloc; i++) {
			rte_pktmbuf_free(dpdk_ctx->ops[i]->sym->m_src);
			dpdk_ctx->ops[i]->sym->m_src = NULL;
			rte_mempool_put(crypto_sym_op_pool, dpdk_ctx->ops[i]);
			dpdk_ctx->ops[i] = NULL;
		}
	}
	if (status_ptr != NULL) {
		OPENSSL_free(status_ptr);
		status_ptr = NULL;
	}
skip_free_buf:
	dpdk_ctx->input_buf = NULL;
	dpdk_ctx->input_len = NULL;
	dpdk_ctx->output_buf = NULL;
	dpdk_ctx->aad_cnt = 0;
	dpdk_ctx->numpipes = 0;
	dpdk_ctx->tls_aad_len = -1;
	dpdk_ctx->iv_set = 0;

	return ret;
}

int dpdkcpt_aes_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			   const unsigned char *in, size_t len)
{
	struct ossl_dpdk_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
	/* If not set up, return error */
	if (!dpdk_ctx->key_set)
		return -1;
	if (dpdk_ctx->tls_aad_len >= 0)
		return aes_gcm_tls_cipher(ctx, out, in, len);
	if (!dpdk_ctx->iv_set)
		return -1;
	int ret = crypto_gcm_cipher(ctx, out, in, len);
	if (ret < 0)
		return -1;
	return ret;
}

int dpdkcpt_aes_gcm_cleanup(EVP_CIPHER_CTX *ctx)
{
	int retval;
	struct ossl_dpdk_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
	if (dpdk_ctx == NULL)
		return 0;
	if (dpdk_ctx->aead_cry_session != NULL) {
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		retval = rte_cryptodev_sym_session_clear(
			dpdk_ctx->dev_id, (struct rte_cryptodev_sym_session *)
					dpdk_ctx->aead_cry_session);
		if (retval < 0)
			engine_log(ENG_LOG_ERR, "FAILED to clear session %d\n", retval);
		retval = rte_cryptodev_sym_session_free(
			(struct rte_cryptodev_sym_session *)
				dpdk_ctx->aead_cry_session);
#else
		retval = rte_cryptodev_sym_session_free(dpdk_ctx->dev_id,
			(struct rte_cryptodev_sym_session *)
				dpdk_ctx->aead_cry_session);
#endif
		if (retval < 0)
			engine_log(ENG_LOG_ERR, "FAILED to free session %d\n", retval);
	}
	if (dpdk_ctx->cipher_cry_session != NULL) {
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		retval = rte_cryptodev_sym_session_clear(
			dpdk_ctx->dev_id, (struct rte_cryptodev_sym_session *)
					dpdk_ctx->cipher_cry_session);
		retval = rte_cryptodev_sym_session_free(
			(struct rte_cryptodev_sym_session *)
				dpdk_ctx->cipher_cry_session);

#else
		retval = rte_cryptodev_sym_session_free(dpdk_ctx->dev_id,
			(struct rte_cryptodev_sym_session *)
				dpdk_ctx->cipher_cry_session);
#endif
		if (retval < 0)
			engine_log(ENG_LOG_ERR, "FAILED to free session %d\n", retval);
	}
	if (dpdk_ctx->aad)
	{
		rte_free(dpdk_ctx->aad);
		dpdk_ctx->aad = NULL;
	}

	return 1;
}
