/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <stdint.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/async.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <crypto/poly1305.h>
#include <crypto/chacha.h>
#if OPENSSL_API_LEVEL >= 30000
#include <openssl/evp.h>
#else
#include <evp_local.h>
#endif

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cryptodev.h>
#include "e_dpdkcpt.h"

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

#define E_DPDKCPT_CPOLY_KEY_LEN			32
#define E_DPDKCPT_CPOLY_BLOCK_SIZE		1
#define E_DPDKCPT_CPOLY_AEAD_AAD_LEN	12
#define E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN	16
#define SSL_MAX_PIPELINES   32
#define TLS_HDR_SIZE	13
#define NO_TLS_PAYLOAD_LENGTH ((size_t)-1)
#define POLY1305_ctx(actx)    ((POLY1305 *)(actx + 1))

#define CRYPTO_OP(c)	\
	((c) ? RTE_CRYPTO_AEAD_OP_ENCRYPT : RTE_CRYPTO_AEAD_OP_DECRYPT)

#define CPOLY_FLAGS  (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV \
					| EVP_CIPH_FLAG_CUSTOM_CIPHER \
					| EVP_CIPH_ALWAYS_CALL_INIT \
					| EVP_CIPH_CTRL_INIT \
					| EVP_CIPH_CUSTOM_COPY \
					| EVP_CIPH_FLAG_AEAD_CIPHER \
					| EVP_CIPH_FLAG_PIPELINE)

EVP_CIPHER *dpdkcpt_chacha20_poly1305;
static const unsigned char zero[2*CHACHA_BLK_SIZE] = { 0 };

typedef struct {
	union {
		double align;   /* this ensures even sizeof(EVP_CHACHA_KEY)%8==0 */
		unsigned int d[CHACHA_KEY_SIZE / 4];
	} key;
	unsigned int  counter[CHACHA_CTR_SIZE / 4];
	unsigned char buf[CHACHA_BLK_SIZE];
	unsigned int  partial_len;
} EVP_CHACHA_KEY;

typedef struct {
	EVP_CHACHA_KEY key;
	unsigned int nonce[12/4];
	unsigned char tag[POLY1305_BLOCK_SIZE];
	unsigned char tls_aad[POLY1305_BLOCK_SIZE];
	struct { uint64_t aad, text; } len;
	int aad, mac_inited, tag_len, nonce_len;
	size_t tls_payload_length;
} EVP_CHACHA_AEAD_CTX;

struct ossl_dpdk_cpoly_ctx {
	EVP_CHACHA_AEAD_CTX *actx;
	uint8_t key[32];
	int key_len;
	uint8_t iv[12];
	int iv_len;
	uint8_t auth_tag[16];
	int auth_taglen;
	uint8_t aad[16];
	int aad_len;
	/* Below two members for tls1_2 */
	uint8_t seq_num[SSL_MAX_PIPELINES][8];
	int tls_aad_len;
	uint8_t dev_id;
	struct rte_crypto_sym_xform aead_xform;
	struct rte_cryptodev_sym_session *cry_session;
	struct rte_crypto_op *op;
	struct rte_mbuf *ibuf;
	struct rte_mbuf *obuf;
	/* Below members are for pipeline */
	int numpipes;
	uint8_t **input_buf;
	uint8_t **output_buf;
	size_t *input_len;
	struct rte_crypto_op *ops[SSL_MAX_PIPELINES];
	struct rte_mbuf *ibufs[SSL_MAX_PIPELINES];
	uint32_t aad_cnt;
	char aad_pipe[SSL_MAX_PIPELINES][TLS_HDR_SIZE];
	int hw_offload_pkt_sz_threshold;
};

const EVP_CIPHER *EVP_dpdkcpt_chacha20_poly1305(void);
static int dpdkcpt_chacha20_poly1305_init_key(EVP_CIPHER_CTX *ctx,
		const unsigned char *ch, const unsigned char *uch, int val);
static int dpdkcpt_chacha20_poly1305_cleanup(EVP_CIPHER_CTX *ctx);
static int dpdkcpt_chacha20_poly1305_cipher(EVP_CIPHER_CTX *ctx, unsigned char *ch,
		const unsigned char *ch1, size_t ln);
static int dpdkcpt_chacha20_poly1305_ctrl(EVP_CIPHER_CTX *c, int type,
		int arg, void *ptr);
static int create_crypto_operation_pl(struct ossl_dpdk_cpoly_ctx *dpdk_ctx,
		const uint8_t *in, int len, int enc, uint8_t pipe_index);
static int dpdkcpt_chacha20_poly1305_crypto(EVP_CIPHER_CTX *ctx,
		unsigned char *out, const unsigned char *in, size_t len);
static int dpdkcpt_chacha20_poly1305_tls_cipher(EVP_CIPHER_CTX *ctx,
		unsigned char *out, const unsigned char *in, size_t len);

static int create_crypto_operation(EVP_CIPHER_CTX *ctx,
		const uint8_t *in, int len, int enc);

extern int sym_dev_id[];
extern int sym_queues[];
extern uint16_t hw_offload_pktsz_thresh;

extern int cpt_num_requests_in_flight;
extern int cpt_num_cipher_pipeline_requests_in_flight;

static int chacha_init_key(EVP_CIPHER_CTX *ctx,
			   const unsigned char user_key[CHACHA_KEY_SIZE],
			   const unsigned char iv[CHACHA_CTR_SIZE], int enc)
{
	struct ossl_dpdk_cpoly_ctx *dpdk_ctx =
		(struct ossl_dpdk_cpoly_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	EVP_CHACHA_AEAD_CTX *actx = dpdk_ctx->actx;
	EVP_CHACHA_KEY *key = (EVP_CHACHA_KEY*)&actx->key;

	unsigned int i;

	if (user_key)
		for (i = 0; i < CHACHA_KEY_SIZE; i+=4) {
			key->key.d[i/4] = CHACHA_U8TOU32(user_key+i);
		}

	if (iv)
		for (i = 0; i < CHACHA_CTR_SIZE; i+=4) {
			key->counter[i/4] = CHACHA_U8TOU32(iv+i);
		}

	key->partial_len = 0;

	return 1;
}

/*
 * Create AEAD Session
 */
static int create_cpoly_aead_session(struct ossl_dpdk_cpoly_ctx *dpdk_ctx, int enc,
					int aad_len, uint8_t reconfigure)
{
	int retval;

	if (reconfigure) {
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		retval = rte_cryptodev_sym_session_free(dpdk_ctx->dev_id,
			(struct rte_cryptodev_sym_session *)
				dpdk_ctx->cry_session);

#else
		retval = rte_cryptodev_sym_session_clear(
				dpdk_ctx->dev_id,
			(struct rte_cryptodev_sym_session *)dpdk_ctx->cry_session);
#endif
		if (retval < 0)
			engine_log(ENG_LOG_ERR, "FAILED to free session\n");
	}

	struct rte_crypto_sym_xform aead_xform = {
			.next = NULL,
			.type = RTE_CRYPTO_SYM_XFORM_AEAD,
			.aead = {
				.op = enc ? RTE_CRYPTO_AEAD_OP_ENCRYPT :
					RTE_CRYPTO_AEAD_OP_DECRYPT,
				.algo = RTE_CRYPTO_AEAD_CHACHA20_POLY1305,
				.key = {.length = E_DPDKCPT_CPOLY_KEY_LEN},
				.iv = { .offset = E_DPDKCPT_IV_OFFSET,
					.length = E_DPDKCPT_CPOLY_IV_LEN},
				.digest_length = E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN,
				.aad_length = aad_len
			},
	};
	aead_xform.aead.key.data = dpdk_ctx->key;
	aead_xform.aead.key.length = dpdk_ctx->key_len;

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	dpdk_ctx->cry_session =
		(void *)rte_cryptodev_sym_session_create(dpdk_ctx->dev_id,
							&aead_xform,
							sym_session_pool);
	if (dpdk_ctx->cry_session == NULL) {
		engine_log (ENG_LOG_ERR, "Session could not be created: %d\n", __LINE__);
		return 0;
	}
#else
	if (!reconfigure) {
		dpdk_ctx->cry_session =
			(void *)rte_cryptodev_sym_session_create(sym_session_pool);
		if (dpdk_ctx->cry_session == NULL) {
			engine_log (ENG_LOG_ERR, "Session could not be created: %d\n",
					__LINE__);
			return 0;
		}
	}

	if (rte_cryptodev_sym_session_init(dpdk_ctx->dev_id,
				(struct rte_cryptodev_sym_session *)
				dpdk_ctx->cry_session,
				&aead_xform, sym_session_priv_pool) < 0) {
		engine_log(ENG_LOG_ERR, "Session initialization failed\n");
		return 0;
	}
#endif
	return 1;

}
static int dpdkcpt_chacha20_poly1305_init_key(EVP_CIPHER_CTX *ctx,
		const unsigned char *key, const unsigned char *iv, int enc)
{
	if (iv == NULL && key == NULL)
		return 1;
	struct ossl_dpdk_cpoly_ctx *dpdk_ctx =
			(struct ossl_dpdk_cpoly_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);

	unsigned int lcore = rte_lcore_id();

	dpdk_ctx->actx->len.aad = 0;
	dpdk_ctx->actx->len.text = 0;
	dpdk_ctx->actx->aad = 0;
	dpdk_ctx->actx->mac_inited = 0;
	dpdk_ctx->actx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

	if (lcore == LCORE_ID_ANY || sym_dev_id[lcore] == -1) {
		engine_log(ENG_LOG_ERR, "%s: Queues not available for lcore %d\n",
			__FUNCTION__, lcore);
		return 0;
	}
	dpdk_ctx->dev_id = sym_dev_id[lcore];

	if (key != NULL) {

		dpdk_ctx->key_len = E_DPDKCPT_CPOLY_KEY_LEN;
		memcpy(dpdk_ctx->key, key, E_DPDKCPT_CPOLY_KEY_LEN);
		dpdk_ctx->auth_taglen = E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN;
		dpdk_ctx->aad_len = EVP_AEAD_TLS1_AAD_LEN;
		dpdk_ctx->numpipes = 0;
		int retval = create_cpoly_aead_session(
				dpdk_ctx, enc, dpdk_ctx->aad_len, 0);
		if (retval < 0) {
			engine_log(ENG_LOG_ERR, "AEAD Sesion creation failed.\n");
			return 0;
		}

	}
	if (iv != NULL) {
		memcpy (dpdk_ctx->iv, iv, E_DPDKCPT_CPOLY_IV_LEN);
		unsigned char temp[CHACHA_CTR_SIZE] = { 0 };

		/* pad on the left */
		if (dpdk_ctx->actx->nonce_len <= CHACHA_CTR_SIZE)
			memcpy(temp + CHACHA_CTR_SIZE - dpdk_ctx->actx->nonce_len, iv,
					dpdk_ctx->actx->nonce_len);

		chacha_init_key(ctx, key, temp, enc);

		dpdk_ctx->actx->nonce[0] = dpdk_ctx->actx->key.counter[1];
		dpdk_ctx->actx->nonce[1] = dpdk_ctx->actx->key.counter[2];
		dpdk_ctx->actx->nonce[2] = dpdk_ctx->actx->key.counter[3];

	} else {
		chacha_init_key(ctx, key, NULL, enc);
	}

	return 1;
}

static int dpdkcpt_chacha20_poly1305_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
	int i;
	struct ossl_dpdk_cpoly_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(c);
	int enc = EVP_CIPHER_CTX_encrypting(c);
	int ret = 0;

	switch (type) {
	case EVP_CTRL_INIT:
		memset(dpdk_ctx, 0, sizeof(struct ossl_dpdk_cpoly_ctx));
		dpdk_ctx->iv_len = EVP_CIPHER_CTX_iv_length(c);
		memcpy(dpdk_ctx->iv, EVP_CIPHER_CTX_iv_noconst(c), dpdk_ctx->iv_len);
		dpdk_ctx->auth_taglen = -1;
		dpdk_ctx->aad_len = -1;
		dpdk_ctx->tls_aad_len = -1;
		dpdk_ctx->hw_offload_pkt_sz_threshold = hw_offload_pktsz_thresh;
		if (dpdk_ctx->actx == NULL)
			dpdk_ctx->actx =
				OPENSSL_zalloc(sizeof(EVP_CHACHA_AEAD_CTX) +
						Poly1305_ctx_size());
		if (dpdk_ctx->actx == NULL) {
			engine_log(ENG_LOG_ERR, "EVP_F_CHACHA20_POLY1305_CTRL, "
					"EVP_R_INITIALIZATION_ERROR \n");
			return 0;
		}
		dpdk_ctx->actx->len.aad = 0;
		dpdk_ctx->actx->len.text = 0;
		dpdk_ctx->actx->aad = 0;
		dpdk_ctx->actx->mac_inited = 0;
		dpdk_ctx->actx->tag_len = 0;
		dpdk_ctx->actx->nonce_len = 12;
		dpdk_ctx->actx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
		memset(dpdk_ctx->actx->tls_aad, 0, POLY1305_BLOCK_SIZE);

		return 1;
	case EVP_CTRL_AEAD_SET_IVLEN:
		if (arg <= 0)
			return 0;
		if ((arg > EVP_MAX_IV_LENGTH) && (arg > dpdk_ctx->iv_len)) {
			if (dpdk_ctx->iv == NULL) {
				engine_log(ENG_LOG_INFO, "dpdk_ctx->iv is null\n");
				return 0;
			}
		}
		dpdk_ctx->iv_len = arg;
		dpdk_ctx->actx->nonce_len = arg;
		return 1;
	case EVP_CTRL_AEAD_SET_IV_FIXED:
		if (arg != 12)
			return 0;
		dpdk_ctx->actx->nonce[0] = dpdk_ctx->actx->key.counter[1]
			= CHACHA_U8TOU32((unsigned char *)ptr);
		dpdk_ctx->actx->nonce[1] = dpdk_ctx->actx->key.counter[2]
			= CHACHA_U8TOU32((unsigned char *)ptr+4);
		dpdk_ctx->actx->nonce[2] =dpdk_ctx->actx->key.counter[3]
			= CHACHA_U8TOU32((unsigned char *)ptr+8);
		return 1;

	case EVP_CTRL_AEAD_SET_TAG:
		if (arg <= 0 || arg > 16 || EVP_CIPHER_CTX_encrypting(c) || ptr == NULL)
			return 0;
		memcpy(dpdk_ctx->auth_tag, ptr, arg);
		memcpy(dpdk_ctx->actx->tag, ptr, arg);
		dpdk_ctx->auth_taglen = arg;
		dpdk_ctx->actx->tag_len = arg;
		return 1;
	case EVP_CTRL_AEAD_GET_TAG:
		if (arg <= 0 || arg > 16 || !EVP_CIPHER_CTX_encrypting(c) ||
				((dpdk_ctx->auth_taglen < 0) && (dpdk_ctx->actx->tag_len < 0)))
			return 0;
		memcpy(ptr, dpdk_ctx->auth_tag, arg);
		return 1;
	case EVP_CTRL_AEAD_TLS1_AAD:
		/* Save AAD for later use */
		if (arg != EVP_AEAD_TLS1_AAD_LEN)
			return 0;
		unsigned char *aad = ptr;

		memcpy(EVP_CIPHER_CTX_buf_noconst(c), ptr, arg);
		memcpy(dpdk_ctx->actx->tls_aad, ptr, EVP_AEAD_TLS1_AAD_LEN);
		aad = dpdk_ctx->actx->tls_aad;
		/* Save sequence number for IV update */
		for (i = 0; i < 8; i++) {
			dpdk_ctx->seq_num[dpdk_ctx->aad_cnt][i] =
							((uint8_t *)ptr)[i];
		}
		dpdk_ctx->tls_aad_len = arg;
		unsigned int len = EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] << 8 |
						EVP_CIPHER_CTX_buf_noconst(c)[arg - 1];
		if (!EVP_CIPHER_CTX_encrypting(c)) {
			if (len < E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN)
				return -1;
			len -= E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN;
			EVP_CIPHER_CTX_buf_noconst(c)[arg - 2] = (len >> 8) & 0xFF;
			EVP_CIPHER_CTX_buf_noconst(c)[arg - 1] = len & 0xFF;
			aad[arg - 2] = (len >> 8) & 0xFF;
			aad[arg - 1] = len & 0xFF;
		}
		dpdk_ctx->actx->tls_payload_length = len;
		if (dpdk_ctx->aad_cnt < SSL_MAX_PIPELINES) {
			memcpy(dpdk_ctx->aad_pipe[dpdk_ctx->aad_cnt],
				EVP_CIPHER_CTX_buf_noconst(c), arg);
			dpdk_ctx->aad_cnt++;
		}
		/*
		 * record sequence number is XORed with the IV as per RFC7905.
		 */
		dpdk_ctx->actx->key.counter[1] = dpdk_ctx->actx->nonce[0];
		dpdk_ctx->actx->key.counter[2] =
			dpdk_ctx->actx->nonce[1] ^ CHACHA_U8TOU32(aad);
		dpdk_ctx->actx->key.counter[3] =
			dpdk_ctx->actx->nonce[2] ^ CHACHA_U8TOU32(aad+4);
		dpdk_ctx->actx->mac_inited = 0;

		return E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN;
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
		engine_log(ENG_LOG_INFO, "Default value = %d\n", type);
		return -1;
	}
}

static int create_crypto_operation(
		EVP_CIPHER_CTX *ctx, const uint8_t *in, int len, int enc)
{

	unsigned int aad_pad_len = 16, plaintext_pad_len = 0;
	uint8_t *plaintext, *ciphertext, i, updated_iv[12];

	struct ossl_dpdk_cpoly_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
	/* Generate crypto op data structure */
	dpdk_ctx->op = rte_crypto_op_alloc(crypto_sym_op_pool,
			RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (dpdk_ctx->op == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create crypto_op : %d\n", __LINE__);
		return -1;
	}

	struct rte_crypto_sym_op *sym_op = dpdk_ctx->op->sym;
	sym_op->aead.aad.data = (uint8_t *)rte_pktmbuf_append(dpdk_ctx->ibuf,
		aad_pad_len);
	sym_op->aead.aad.phys_addr = rte_pktmbuf_iova(dpdk_ctx->ibuf);
	if (dpdk_ctx->tls_aad_len > 0) {
		memcpy(sym_op->aead.aad.data, EVP_CIPHER_CTX_buf_noconst(ctx),
			dpdk_ctx->tls_aad_len);
	} else {
		memcpy(sym_op->aead.aad.data, dpdk_ctx->aad, dpdk_ctx->aad_len);
	}

	/* Append IV at the end of the crypto operation */
	uint8_t *iv_ptr = rte_crypto_op_ctod_offset(dpdk_ctx->op, uint8_t *,
			E_DPDKCPT_IV_OFFSET);
	if (iv_ptr == NULL)
		engine_log(ENG_LOG_ERR, "IV_PTR is null: %d\n", __LINE__);
	/* XORing iv with sequence no: is not needed in TLS1.3 since it is
	 * already being done inside openssl */
	rte_memcpy(iv_ptr, dpdk_ctx->iv, dpdk_ctx->iv_len);

	if (CRYPTO_OP(enc) == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
		plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
		plaintext = (uint8_t *)rte_pktmbuf_append(dpdk_ctx->ibuf,
				plaintext_pad_len);
		memcpy(plaintext, in, len);

		/* Append digest data* */
		if (dpdk_ctx->tls_aad_len >= 0) {
			sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
				dpdk_ctx->ibuf, E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN);
			memset(sym_op->aead.digest.data, 0, E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(dpdk_ctx->ibuf,
				plaintext_pad_len + aad_pad_len);
		} else {
			sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
				dpdk_ctx->ibuf, dpdk_ctx->auth_taglen);
			memset(sym_op->aead.digest.data, 0, dpdk_ctx->auth_taglen);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(dpdk_ctx->ibuf,
				plaintext_pad_len + aad_pad_len);
		}
	} else {
		plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
		ciphertext = (uint8_t *)rte_pktmbuf_append(dpdk_ctx->ibuf,
				plaintext_pad_len);
		memcpy(ciphertext, in, len);
		/* Append digest data* */
		if (dpdk_ctx->tls_aad_len >= 0) {
			sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
				dpdk_ctx->ibuf, E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(dpdk_ctx->ibuf,
				plaintext_pad_len + aad_pad_len);
			rte_memcpy(sym_op->aead.digest.data, in+len,
				E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN);
		} else {
			sym_op->aead.digest.data = (uint8_t *)rte_pktmbuf_append(
				dpdk_ctx->ibuf, dpdk_ctx->auth_taglen);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(dpdk_ctx->ibuf,
				plaintext_pad_len + aad_pad_len);
			rte_memcpy(sym_op->aead.digest.data, dpdk_ctx->auth_tag,
				dpdk_ctx->auth_taglen);
		}
	}
	sym_op->aead.data.length = len;
	sym_op->aead.data.offset = aad_pad_len;

	return 0;
}

static int create_crypto_operation_pl(struct ossl_dpdk_cpoly_ctx *dpdk_ctx,
		const uint8_t *in, int len, int enc, uint8_t pipe_index)
{
	unsigned int aad_pad_len = 0, plaintext_pad_len = 0;
	uint8_t updated_iv[12];

	dpdk_ctx->ops[pipe_index] = rte_crypto_op_alloc(crypto_sym_op_pool,
					RTE_CRYPTO_OP_TYPE_SYMMETRIC);
	if (unlikely(dpdk_ctx->ops[pipe_index] == NULL)) {
		engine_log(ENG_LOG_ERR, "Failed to create crypto_ops for pipe: %d\n",
			pipe_index);
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
	if (dpdk_ctx->tls_aad_len > 0) {
		memcpy(updated_iv, dpdk_ctx->iv, dpdk_ctx->iv_len);
		/* Updating IV value by XORing with sequence number */
		for (uint8_t i = 0; i < 8; i++)
			updated_iv[i + 4] = dpdk_ctx->seq_num[pipe_index][i] ^
						dpdk_ctx->iv[i + 4];
		rte_memcpy(iv_ptr, updated_iv, dpdk_ctx->iv_len);
	} else {
		rte_memcpy(iv_ptr, dpdk_ctx->iv, dpdk_ctx->iv_len);
	}
	if (dpdk_ctx->tls_aad_len >= 0 || dpdk_ctx->aad_len >= 0) {
		uint8_t *plaintext, *ciphertext;
		/* Append plaintext/ciphertext */
		if (CRYPTO_OP(enc) == RTE_CRYPTO_AEAD_OP_ENCRYPT) {
			plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
			plaintext = (uint8_t *)rte_pktmbuf_append(
				dpdk_ctx->ibufs[pipe_index], plaintext_pad_len);
			memcpy(plaintext, in, len);
			/* Append digest data */
			sym_op->aead.digest.data =
					(uint8_t *)rte_pktmbuf_append(
					dpdk_ctx->ibufs[pipe_index],
					EVP_CHACHAPOLY_TLS_TAG_LEN);
			memset(sym_op->aead.digest.data, 0,
			       EVP_CHACHAPOLY_TLS_TAG_LEN);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(
					dpdk_ctx->ibufs[pipe_index],
					plaintext_pad_len + aad_pad_len);
		} else {
			plaintext_pad_len = RTE_ALIGN_CEIL(len, 16);
			ciphertext = (uint8_t *)rte_pktmbuf_append(
					dpdk_ctx->ibufs[pipe_index],
					plaintext_pad_len);
			memcpy(ciphertext, in, len);
			/* Append digest data */
			sym_op->aead.digest.data =
					(uint8_t *)rte_pktmbuf_append(
					dpdk_ctx->ibufs[pipe_index],
					EVP_CHACHAPOLY_TLS_TAG_LEN);
			sym_op->aead.digest.phys_addr = rte_pktmbuf_iova_offset(
					dpdk_ctx->ibufs[pipe_index],
					plaintext_pad_len + aad_pad_len);
			rte_memcpy(sym_op->aead.digest.data, in + len,
				   EVP_CHACHAPOLY_TLS_TAG_LEN);
		}
		sym_op->aead.data.length = len;
		sym_op->aead.data.offset = aad_pad_len;
	}

	return 0;
}

static int chacha_cipher(EVP_CIPHER_CTX * ctx, unsigned char *out,
			const unsigned char *inp, size_t len)
{
	struct ossl_dpdk_cpoly_ctx *dpdk_ctx =
		(struct ossl_dpdk_cpoly_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	EVP_CHACHA_KEY *key = (EVP_CHACHA_KEY*)(&dpdk_ctx->actx->key);
	unsigned int n, rem, ctr32;

	if ((n = key->partial_len)) {
		while (len && n < CHACHA_BLK_SIZE) {
			*out++ = *inp++ ^ key->buf[n++];
			len--;
		}
		key->partial_len = n;

		if (len == 0)
			return 1;

		if (n == CHACHA_BLK_SIZE) {
			key->partial_len = 0;
			key->counter[0]++;
			if (key->counter[0] == 0)
				key->counter[1]++;
		}
	}

	rem = (unsigned int)(len % CHACHA_BLK_SIZE);
	len -= rem;
	ctr32 = key->counter[0];
	while (len >= CHACHA_BLK_SIZE) {
		size_t blocks = len / CHACHA_BLK_SIZE;
		/*
		 * 1<<28 is just a not-so-small yet not-so-large number...
		 * Below condition is practically never met, but it has to
		 * be checked for code correctness.
		 */
		if (sizeof(size_t)>sizeof(unsigned int) && blocks>(1U<<28))
			blocks = (1U<<28);

		/*
		 * As ChaCha20_ctr32 operates on 32-bit counter, caller
		 * has to handle overflow. 'if' below detects the
		 * overflow, which is then handled by limiting the
		 * amount of blocks to the exact overflow point...
		 */
		ctr32 += (unsigned int)blocks;
		if (ctr32 < blocks) {
			blocks -= ctr32;
			ctr32 = 0;
		}
		blocks *= CHACHA_BLK_SIZE;
		ChaCha20_ctr32(out, inp, blocks, key->key.d, key->counter);
		len -= blocks;
		inp += blocks;
		out += blocks;

		key->counter[0] = ctr32;
		if (ctr32 == 0) key->counter[1]++;
	}

	if (rem) {
		memset(key->buf, 0, sizeof(key->buf));
		ChaCha20_ctr32(key->buf, key->buf, CHACHA_BLK_SIZE,
				key->key.d, key->counter);
		for (n = 0; n < rem; n++)
			out[n] = inp[n] ^ key->buf[n];
		key->partial_len = rem;
	}

	return 1;
}

static int dpdkcpt_chacha20_poly1305_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
{
	int ret;
	struct ossl_dpdk_cpoly_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);

	if (dpdk_ctx->tls_aad_len >= 0)
		ret = dpdkcpt_chacha20_poly1305_tls_cipher(ctx, out, in, len);
	else
		ret = dpdkcpt_chacha20_poly1305_crypto(ctx, out, in, len);

	if (ret < 0)
		return -1;
	return ret;
}

/* sw_chacha20_poly1305_tls_cipher API is invoked if protocol version is TLS1.2
 * and data(PT/CT) len is less than hw_offload_pkt_sz_threshold
 * This API will use Chachapoly ARMv8 implementation for doing the operation.
 */
static int sw_chacha20_poly1305_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
		const unsigned char *in, size_t len)
{
	struct ossl_dpdk_cpoly_ctx *dpdk_ctx =
		(struct ossl_dpdk_cpoly_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
	EVP_CHACHA_AEAD_CTX *actx = (EVP_CHACHA_AEAD_CTX *)dpdk_ctx->actx;
	size_t tail, tohash_len, buf_len, plen = actx->tls_payload_length;
	unsigned char *buf, *tohash, *ctr, storage[sizeof(zero) + 32];
	int enc = EVP_CIPHER_CTX_encrypting(ctx);

	if (len != plen + POLY1305_BLOCK_SIZE)
		return -1;

	buf = storage + ((0 - (size_t)storage) & 15);   /* align */
	ctr = buf + CHACHA_BLK_SIZE;
	tohash = buf + CHACHA_BLK_SIZE - POLY1305_BLOCK_SIZE;

	if (plen <= CHACHA_BLK_SIZE) {
		size_t i;

		actx->key.counter[0] = 0;
		ChaCha20_ctr32(buf, zero, (buf_len = 2 * CHACHA_BLK_SIZE),
				actx->key.key.d, actx->key.counter);
		Poly1305_Init(POLY1305_ctx(actx), buf);
		actx->key.partial_len = 0;
		memcpy(tohash, actx->tls_aad, POLY1305_BLOCK_SIZE);
		tohash_len = POLY1305_BLOCK_SIZE;
		actx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
		actx->len.text = plen;

		if (enc) {
			for (i = 0; i < plen; i++) {
				out[i] = ctr[i] ^= in[i];
			}
		} else {
			for (i = 0; i < plen; i++) {
				unsigned char c = in[i];
				out[i] = ctr[i] ^ c;
				ctr[i] = c;
			}
		}

		in += i;
		out += i;

		tail = (0 - i) & (POLY1305_BLOCK_SIZE - 1);
		memset(ctr + i, 0, tail);
		ctr += i + tail;
		tohash_len += i + tail;
	} else {
		actx->key.counter[0] = 0;
		ChaCha20_ctr32(buf, zero, (buf_len = CHACHA_BLK_SIZE),
				actx->key.key.d, actx->key.counter);
		Poly1305_Init(POLY1305_ctx(actx), buf);
		actx->key.counter[0] = 1;
		actx->key.partial_len = 0;
		Poly1305_Update(POLY1305_ctx(actx), actx->tls_aad, POLY1305_BLOCK_SIZE);
		tohash = ctr;
		tohash_len = 0;
		actx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
		actx->len.text = plen;

		if (enc) {
			ChaCha20_ctr32(out, in, plen, actx->key.key.d, actx->key.counter);
			Poly1305_Update(POLY1305_ctx(actx), out, plen);
		} else {
			Poly1305_Update(POLY1305_ctx(actx), in, plen);
			ChaCha20_ctr32(out, in, plen, actx->key.key.d, actx->key.counter);
		}

		in += plen;
		out += plen;
		tail = (0 - plen) & (POLY1305_BLOCK_SIZE - 1);
		Poly1305_Update(POLY1305_ctx(actx), zero, tail);
	}

	{
		const union {
			long one;
			char little;
		} is_endian = { 1 };

		if (is_endian.little) {
			memcpy(ctr, (unsigned char *)&actx->len, POLY1305_BLOCK_SIZE);
		} else {
			ctr[0]  = (unsigned char)(actx->len.aad);
			ctr[1]  = (unsigned char)(actx->len.aad>>8);
			ctr[2]  = (unsigned char)(actx->len.aad>>16);
			ctr[3]  = (unsigned char)(actx->len.aad>>24);
			ctr[4]  = (unsigned char)(actx->len.aad>>32);
			ctr[5]  = (unsigned char)(actx->len.aad>>40);
			ctr[6]  = (unsigned char)(actx->len.aad>>48);
			ctr[7]  = (unsigned char)(actx->len.aad>>56);

			ctr[8]  = (unsigned char)(actx->len.text);
			ctr[9]  = (unsigned char)(actx->len.text>>8);
			ctr[10] = (unsigned char)(actx->len.text>>16);
			ctr[11] = (unsigned char)(actx->len.text>>24);
			ctr[12] = (unsigned char)(actx->len.text>>32);
			ctr[13] = (unsigned char)(actx->len.text>>40);
			ctr[14] = (unsigned char)(actx->len.text>>48);
			ctr[15] = (unsigned char)(actx->len.text>>56);
		}
		tohash_len += POLY1305_BLOCK_SIZE;
	}

	Poly1305_Update(POLY1305_ctx(actx), tohash, tohash_len);
	OPENSSL_cleanse(buf, buf_len);
	Poly1305_Final(POLY1305_ctx(actx), enc ? actx->tag
			: tohash);

	actx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;

	if (enc) {
		memcpy(out, actx->tag, POLY1305_BLOCK_SIZE);
	} else {
		if (CRYPTO_memcmp(tohash, in, POLY1305_BLOCK_SIZE)) {
			memset(out - (len - POLY1305_BLOCK_SIZE), 0,
					len - POLY1305_BLOCK_SIZE);
			return -1;
		}
	}

	return len;
}


/* Below API added for TLS1_2 protocol
 *
 * AAD data is alway set via control function in case of TLS1_2
 * IV is updating by XOR'ing with sequence number
 * Here, len value is comming from SSL layer is equal to
 * (PT/CT length + AUTH tag len) for both encryption/decryption.*/

static int dpdkcpt_chacha20_poly1305_tls_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	int enc;
	ossl_cry_op_status_t **status_ptr = NULL;
        ossl_cry_op_status_t *new_st_ptr[E_DPDKCPT_NUM_DEQUEUED_OPS];
	ossl_cry_op_status_t current_job;
	uint16_t num_enqueued_ops, num_dequeued_ops;
	struct rte_crypto_op *deq_op_ptr[E_DPDKCPT_NUM_DEQUEUED_OPS];
	uint8_t i, j, numpipes, numalloc, k, ret = 0;
	struct ossl_dpdk_cpoly_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
	uint16_t datalen = (uint16_t)(len - EVP_CHACHAPOLY_TLS_TAG_LEN);
	ASYNC_JOB *job = NULL;
	ASYNC_WAIT_CTX *wctx_local = NULL;
	async_pipe_job_t pip_jobs[MAX_PIPE_JOBS];
	uint8_t pip_jb_qsz = 0;

	if ((in != out) || (len < EVP_CHACHAPOLY_TLS_TAG_LEN))
		return -1;
	numpipes = dpdk_ctx->numpipes;

	/* Bydefault number of pipe is one */
	if (numpipes == 0) {
		numpipes = 1;
		dpdk_ctx->input_len = malloc(sizeof(int));
		dpdk_ctx->input_len[0] = len;
		dpdk_ctx->output_buf = &out;
		/* As it's inplace */
		dpdk_ctx->input_buf = &out;
	}
	if ((datalen < dpdk_ctx->hw_offload_pkt_sz_threshold) && (numpipes == 1)) {
		ret = sw_chacha20_poly1305_tls_cipher(ctx, out, in, len);
		dpdk_ctx->numpipes = 0;
		dpdk_ctx->aad_cnt = 0;
		return ret;
	}
	enc = EVP_CIPHER_CTX_encrypting(ctx);
	status_ptr = malloc(sizeof(ossl_cry_op_status_t *) * numpipes);
	if (unlikely(status_ptr == NULL)) {
		engine_log(ENG_LOG_ERR, "Malloc failed\n");
		numalloc = 0;
		ret = -1;
		goto free_resources;
	}
	job = ASYNC_get_current_job();
	if (job != NULL)
		wctx_local = (ASYNC_WAIT_CTX *)ASYNC_get_wait_ctx(job);

	for (i = 0; i < numpipes; i++) {
		dpdk_ctx->input_len[i] -= EVP_CHACHAPOLY_TLS_TAG_LEN;
		/* Get a burst of mbufs */
		dpdk_ctx->ibufs[i] = rte_pktmbuf_alloc(mbuf_pool);
		if (unlikely(dpdk_ctx->ibufs[i] == NULL)) {
			engine_log(ENG_LOG_ERR, "Not enough mbufs available\n");
			numalloc = i;
			ret = -1;
			goto free_resources;
		}
		/* Create crypto session and initialize it for
		 * the crypto device
		 */
		ret = create_crypto_operation_pl(dpdk_ctx,
				dpdk_ctx->input_buf[i], dpdk_ctx->input_len[i],
				enc, i);
		if (unlikely(ret < 0)) {
			/* roll back last buf */
			rte_pktmbuf_free(dpdk_ctx->ibufs[i]);
			dpdk_ctx->ibufs[i] = NULL;
			numalloc = i;
			ret = -1;
			goto free_resources;
		}
		rte_crypto_op_attach_sym_session(dpdk_ctx->ops[i],
						 dpdk_ctx->cry_session);
		dpdk_ctx->ops[i]->sym->m_src = dpdk_ctx->ibufs[i];
		status_ptr[i] = rte_crypto_op_ctod_offset(dpdk_ctx->ops[i],
				ossl_cry_op_status_t *,
				E_DPDKCPT_COP_METADATA_OFF);
		status_ptr[i]->is_complete = 0;
		status_ptr[i]->is_successful = 0;
		status_ptr[i]->numpipes = numpipes;
		status_ptr[i]->wctx_p = wctx_local;
	}

	for (k=0, num_enqueued_ops=0;
	    ((num_enqueued_ops < numpipes) && (k < MAX_ENQUEUE_ATTEMPTS)); k++) {
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
	CPT_ATOMIC_INC(cpt_num_requests_in_flight);
	pause_async_job();

	CPT_ATOMIC_DEC_N(cpt_num_cipher_pipeline_requests_in_flight, numpipes);
	CPT_ATOMIC_DEC(cpt_num_requests_in_flight);

	while (status_ptr[0]->is_successful == 0) {
		do {
			num_dequeued_ops = rte_cryptodev_dequeue_burst(
					dpdk_ctx->dev_id, sym_queues[rte_lcore_id()],
					&deq_op_ptr[0], E_DPDKCPT_NUM_DEQUEUED_OPS);
			for (i = 0; i < num_dequeued_ops; i++) {
				new_st_ptr[i] = rte_crypto_op_ctod_offset(
						deq_op_ptr[i], ossl_cry_op_status_t *,
						E_DPDKCPT_COP_METADATA_OFF);
				new_st_ptr[i]->is_complete = 1;
				/* Check if operation was processed successfully  */
				if (deq_op_ptr[i]->status !=
						RTE_CRYPTO_OP_STATUS_SUCCESS) {
		            engine_log(ENG_LOG_ERR, "Crypto (CPOLY) op status is not success (err:%d)\n",
							deq_op_ptr[i]->status);
					new_st_ptr[i]->is_successful = 0;
				} else {
					new_st_ptr[i]->is_successful = 1;
					if(new_st_ptr[i]->wctx_p)
					    check_for_job_completion(status_ptr[0]->wctx_p,
							   new_st_ptr[i]->wctx_p, new_st_ptr[i]->numpipes,
							   &pip_jb_qsz, &pip_jobs[0]);
				}
			}
		} while(pip_jb_qsz>0);
	}

	for (i = 0; i < numpipes; i++) {
		void *buf = rte_pktmbuf_mtod_offset(
				dpdk_ctx->ops[i]->sym->m_src, char *,
				dpdk_ctx->ops[i]->sym[0].aead.data.offset);
		memcpy(dpdk_ctx->output_buf[i], buf, dpdk_ctx->input_len[i]);
		memcpy(dpdk_ctx->output_buf[i] + dpdk_ctx->input_len[i],
				dpdk_ctx->ops[i]->sym[0].aead.digest.data,
				EVP_CHACHAPOLY_TLS_TAG_LEN);
		rte_pktmbuf_free(dpdk_ctx->ops[i]->sym->m_src);
		dpdk_ctx->ops[i]->sym->m_src = NULL;
	}
	rte_mempool_put_bulk(crypto_sym_op_pool, (void **)dpdk_ctx->ops,
			     numpipes);
	for (int j = 0; j < numpipes; j++)
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
	dpdk_ctx->numpipes = 0;
	dpdk_ctx->aad_cnt = 0;
	if (status_ptr != NULL) {
		free(status_ptr);
		status_ptr = NULL;
	}

	return ret;
}

static inline void cpoly_mac_init(EVP_CHACHA_AEAD_CTX *actx)
{
	size_t plen = actx->tls_payload_length;

	actx->key.counter[0] = 0;
	ChaCha20_ctr32(actx->key.buf, zero, CHACHA_BLK_SIZE,
			actx->key.key.d, actx->key.counter);
	Poly1305_Init(POLY1305_ctx(actx), actx->key.buf);
	actx->key.counter[0] = 1;
	actx->key.partial_len = 0;
	actx->len.aad = actx->len.text = 0;
	actx->mac_inited = 1;
	if (plen != NO_TLS_PAYLOAD_LENGTH) {
		Poly1305_Update(POLY1305_ctx(actx), actx->tls_aad,
				EVP_AEAD_TLS1_AAD_LEN);
		actx->len.aad = EVP_AEAD_TLS1_AAD_LEN;
		actx->aad = 1;
	}
}

static int dpdkcpt_chacha20_poly1305_crypto(EVP_CIPHER_CTX *ctx, unsigned char *out,
	const unsigned char *in, size_t len)
{
	int retval, enc, rv = -1;
	struct rte_mbuf *mbuf = NULL;
	ossl_cry_op_status_t *status_ptr, *new_st_ptr;
	uint16_t num_enqueued_ops, num_dequeued_ops;
	struct rte_crypto_op *dequeued_ops[1];

	struct ossl_dpdk_cpoly_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
	EVP_CHACHA_AEAD_CTX *actx = dpdk_ctx->actx;
	size_t rem, plen = actx->tls_payload_length;
	static int sw_cpoly_encrypt = 0, sw_cpoly_decrypt = 0;

	enc = EVP_CIPHER_CTX_encrypting(ctx);

	if (in != NULL) {
		if (out == NULL) {
			if (!actx->mac_inited)
				cpoly_mac_init(actx);
			Poly1305_Update(POLY1305_ctx(actx), in, len);
			actx->len.aad += len;
			actx->aad = 1;

			memcpy(dpdk_ctx->aad, in, len);
			if (((size_t)dpdk_ctx->aad_len != len)) {
				int ret = create_cpoly_aead_session(dpdk_ctx,
								    enc, len, 1);
				if (ret < 0)
					return ret;
				dpdk_ctx->aad_len = len;
			}
			return len;
		} else {                                /* plain- or ciphertext */
			if (len < dpdk_ctx->hw_offload_pkt_sz_threshold) {

				if (!actx->mac_inited)
					cpoly_mac_init(actx);
				if (actx->aad) {                    /* wrap up aad */
					if ((rem = (size_t)actx->len.aad % POLY1305_BLOCK_SIZE))
						Poly1305_Update(POLY1305_ctx(actx), zero,
								POLY1305_BLOCK_SIZE - rem);
					actx->aad = 0;
				}

				actx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
				if (plen == NO_TLS_PAYLOAD_LENGTH)
					plen = len;
				else if (len != plen + POLY1305_BLOCK_SIZE)
					return -1;

				if (enc) {                 /* plaintext */
					chacha_cipher(ctx, out, in, plen);
					Poly1305_Update(POLY1305_ctx(actx), out, plen);
					in += plen;
					out += plen;
					actx->len.text += plen;
					sw_cpoly_encrypt = 1;
				} else {                            /* ciphertext */
					Poly1305_Update(POLY1305_ctx(actx), in, plen);
					chacha_cipher(ctx, out, in, plen);
					in += plen;
					out += plen;
					actx->len.text += plen;
					sw_cpoly_decrypt = 1;
				}
				return len;
			}
		}

	}
	if (((in == NULL) || (plen != len)) && (sw_cpoly_decrypt || sw_cpoly_encrypt)) {
		const union {
			long one;
			char little;
		} is_endian = { 1 };
		unsigned char temp[POLY1305_BLOCK_SIZE];

		if (actx->aad) {                        /* wrap up aad */
			if ((rem = (size_t)actx->len.aad % POLY1305_BLOCK_SIZE))
				Poly1305_Update(POLY1305_ctx(actx), zero,
						POLY1305_BLOCK_SIZE - rem);
			actx->aad = 0;
		}

		if ((rem = (size_t)actx->len.text % POLY1305_BLOCK_SIZE))
			Poly1305_Update(POLY1305_ctx(actx), zero,
					POLY1305_BLOCK_SIZE - rem);

		if (is_endian.little) {
			Poly1305_Update(POLY1305_ctx(actx),
					(unsigned char *)&actx->len, POLY1305_BLOCK_SIZE);
		} else {
			temp[0]  = (unsigned char)(actx->len.aad);
			temp[1]  = (unsigned char)(actx->len.aad>>8);
			temp[2]  = (unsigned char)(actx->len.aad>>16);
			temp[3]  = (unsigned char)(actx->len.aad>>24);
			temp[4]  = (unsigned char)(actx->len.aad>>32);
			temp[5]  = (unsigned char)(actx->len.aad>>40);
			temp[6]  = (unsigned char)(actx->len.aad>>48);
			temp[7]  = (unsigned char)(actx->len.aad>>56);
			temp[8]  = (unsigned char)(actx->len.text);
			temp[9]  = (unsigned char)(actx->len.text>>8);
			temp[10] = (unsigned char)(actx->len.text>>16);
			temp[11] = (unsigned char)(actx->len.text>>24);
			temp[12] = (unsigned char)(actx->len.text>>32);
			temp[13] = (unsigned char)(actx->len.text>>40);
			temp[14] = (unsigned char)(actx->len.text>>48);
			temp[15] = (unsigned char)(actx->len.text>>56);

			Poly1305_Update(POLY1305_ctx(actx), temp, POLY1305_BLOCK_SIZE);
		}
		Poly1305_Final(POLY1305_ctx(actx), enc ? actx->tag
				: temp);
		if (enc) {
			memcpy(dpdk_ctx->auth_tag, actx->tag, POLY1305_BLOCK_SIZE);
			sw_cpoly_encrypt = 0;
		} else {
			memcpy(dpdk_ctx->auth_tag, temp, POLY1305_BLOCK_SIZE);
			sw_cpoly_decrypt = 0;
		}
		actx->mac_inited = 0;

		if (in != NULL && len != plen) {        /* tls mode */
			if (enc) {
				memcpy(out, actx->tag, POLY1305_BLOCK_SIZE);
				memcpy(dpdk_ctx->auth_tag, actx->tag, POLY1305_BLOCK_SIZE);
				sw_cpoly_encrypt = 0;
			} else {
				if (CRYPTO_memcmp(temp, in, POLY1305_BLOCK_SIZE)) {
					memset(out - plen, 0, plen);
					return -1;
				}
				sw_cpoly_decrypt = 0;
			}
		} else if ((!enc) && sw_cpoly_decrypt) {
			if (CRYPTO_memcmp(temp, actx->tag, actx->tag_len))
				return -1;
			sw_cpoly_decrypt = 0;

		}
		return len;
	}
	if ((in == NULL)) {
		if ((!enc) && !sw_cpoly_decrypt) {
			if (dpdk_ctx->auth_taglen < 0)
				return -1;
			memcpy(dpdk_ctx->auth_tag, EVP_CIPHER_CTX_buf_noconst(ctx),
					E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN);
			return 0;
		}
		if ((enc) && (!sw_cpoly_encrypt)) {
			memcpy(dpdk_ctx->auth_tag, EVP_CIPHER_CTX_buf_noconst(ctx),
					E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN);
			dpdk_ctx->auth_taglen = E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN;
		}
		return 0;
	}

	dpdk_ctx->ibuf = rte_pktmbuf_alloc(mbuf_pool);
	if (dpdk_ctx->ibuf == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create a mbuf: %d\n", __LINE__);
		return -1;
	}

	/* Clear mbuf payload */
	memset(rte_pktmbuf_mtod(dpdk_ctx->ibuf, uint8_t *), 0,
			rte_pktmbuf_tailroom(dpdk_ctx->ibuf));

	/* Create AEAD operation */
	retval = create_crypto_operation(ctx, in, len, enc);
	if (retval < 0)
		return retval;

	rte_crypto_op_attach_sym_session(dpdk_ctx->op, dpdk_ctx->cry_session);
	dpdk_ctx->op->sym->m_src = dpdk_ctx->ibuf;

	status_ptr = rte_crypto_op_ctod_offset (dpdk_ctx->op,
			ossl_cry_op_status_t *, E_DPDKCPT_COP_METADATA_OFF);

	status_ptr->is_complete = 0;
	status_ptr->is_successful = 0;

	num_enqueued_ops =
		rte_cryptodev_enqueue_burst(dpdk_ctx->dev_id,
				sym_queues[rte_lcore_id()], &dpdk_ctx->op, 1);

	if (num_enqueued_ops < 1) {
		engine_log(ENG_LOG_ERR, "\nCrypto operation enqueue failed: %d\n", __LINE__);
		return 0;
	}


	while (!status_ptr->is_complete) {
		pause_async_job();

		num_dequeued_ops = rte_cryptodev_dequeue_burst(
			dpdk_ctx->dev_id, sym_queues[rte_lcore_id()], dequeued_ops, 1);

		if (num_dequeued_ops > 0) {
			new_st_ptr = rte_crypto_op_ctod_offset(
				dequeued_ops[0], ossl_cry_op_status_t *,
				E_DPDKCPT_COP_METADATA_OFF);

			new_st_ptr->is_complete = 1;
			if (dequeued_ops[0]->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
				engine_log(ENG_LOG_ERR, "Operation were not processed"
					"correctly err: %d", dequeued_ops[0]->status);
				new_st_ptr->is_successful = 0;
			} else {
				new_st_ptr->is_successful = 1;
			}
		}
	}
	mbuf = dpdk_ctx->op->sym->m_src;

	if (!status_ptr->is_successful) {
		rv = -1;
		engine_log(ENG_LOG_ERR, "Job not process\n");
		goto err;
	}

	void *buf = rte_pktmbuf_mtod_offset(mbuf, char *,
				dpdk_ctx->op->sym[0].aead.data.offset);

	memcpy(out, buf, len);
	if (enc == 1) {
		memcpy (EVP_CIPHER_CTX_buf_noconst(ctx),
			dpdk_ctx->op->sym[0].aead.digest.data,
			E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN);
		memcpy (dpdk_ctx->auth_tag, dpdk_ctx->op->sym[0].aead.digest.data,
			E_DPDKCPT_CPOLY_AEAD_DIGEST_LEN);
	}
	rv = len;

err:
	rte_mempool_put_bulk(crypto_sym_op_pool, (void **)&dpdk_ctx->op, 1);
	rte_pktmbuf_free(mbuf);

	return rv;
}

static int dpdkcpt_chacha20_poly1305_cleanup(EVP_CIPHER_CTX *ctx)
{
	int retval;
	struct ossl_dpdk_cpoly_ctx *dpdk_ctx = EVP_CIPHER_CTX_get_cipher_data(ctx);

	if (dpdk_ctx == NULL)
		return 0;
	if (dpdk_ctx->cry_session != NULL) {
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		retval = rte_cryptodev_sym_session_clear(dpdk_ctx->dev_id,
					(struct rte_cryptodev_sym_session *)
					dpdk_ctx->cry_session);
		if (retval < 0)
			engine_log(ENG_LOG_ERR, "FAILED to clear session, retval = %d\n",
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
			engine_log(ENG_LOG_ERR, "FAILED to free session\n");
	}
	if (dpdk_ctx->actx)
		OPENSSL_free(dpdk_ctx->actx);

	return 1;
}

const EVP_CIPHER *EVP_dpdkcpt_chacha20_poly1305(void)
{
	if (dpdkcpt_chacha20_poly1305 != NULL)
		return dpdkcpt_chacha20_poly1305;

	dpdkcpt_chacha20_poly1305 = EVP_CIPHER_meth_new(NID_chacha20_poly1305,
			E_DPDKCPT_CPOLY_BLOCK_SIZE, E_DPDKCPT_CPOLY_KEY_LEN);

	EVP_CIPHER_meth_set_iv_length (dpdkcpt_chacha20_poly1305,
			E_DPDKCPT_CPOLY_IV_LEN);
	EVP_CIPHER_meth_set_init (dpdkcpt_chacha20_poly1305,
			dpdkcpt_chacha20_poly1305_init_key);
	EVP_CIPHER_meth_set_do_cipher (dpdkcpt_chacha20_poly1305,
			dpdkcpt_chacha20_poly1305_cipher);
	EVP_CIPHER_meth_set_cleanup (dpdkcpt_chacha20_poly1305,
			dpdkcpt_chacha20_poly1305_cleanup);
	EVP_CIPHER_meth_set_ctrl(dpdkcpt_chacha20_poly1305,
			dpdkcpt_chacha20_poly1305_ctrl);
	EVP_CIPHER_meth_set_flags(dpdkcpt_chacha20_poly1305, CPOLY_FLAGS);
	EVP_CIPHER_meth_set_impl_ctx_size (dpdkcpt_chacha20_poly1305,
			sizeof(struct ossl_dpdk_cpoly_ctx));

	return dpdkcpt_chacha20_poly1305;
}
