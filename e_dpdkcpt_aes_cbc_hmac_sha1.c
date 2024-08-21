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

#include <rte_hexdump.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/async.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cryptodev.h>

#include "e_dpdkcpt.h"

#define E_DPDKCPT_AES128_CBC_KEY_LENGTH 16
#define E_DPDKCPT_AES256_CBC_KEY_LENGTH 32

/* Offset were the IV need to be copied */
#define E_DPDKCPT_AES_CBC_HMAC_SHA_IV_OFFSET    (sizeof(struct rte_crypto_op) + \
		sizeof(struct rte_crypto_sym_op) + 2 * \
		sizeof(struct rte_crypto_sym_xform))

/* Meta Data follows after the IV */
#define E_DPDKCPT_COP_METADATA_OFF_CBC_HMAC_SHA \
	(E_DPDKCPT_AES_CBC_HMAC_SHA_IV_OFFSET + E_DPDKCPT_AES_CBC_IV_LENGTH)

/* Invalid payload length */
#define E_DPDK_AES_SHA1_NO_PAYLOAD_LENGTH       ((size_t)-1)
#define SSL_MAX_PIPELINES	32

struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx {
	uint8_t key[E_DPDKCPT_AES256_CBC_KEY_LENGTH];
	uint8_t iv[E_DPDKCPT_AES_CBC_IV_LENGTH];
	int keylen;
	int enc;
	uint8_t dev_id; /*<cpt dev_id>*/
	struct rte_cryptodev_sym_session *cry_session;
	struct rte_crypto_op *op;
	struct rte_mbuf *ibuf;
	struct rte_mbuf *obuf;
	uint8_t tls_aad[SSL_MAX_PIPELINES][EVP_AEAD_TLS1_AAD_LEN];
	int tls_aad_len;
	unsigned int tls_ver;
	size_t payload_length;
	uint8_t hmac_key[SHA_DIGEST_LENGTH];
	int update_keys;

	/*Below members are for pipeline */
	uint8_t numpipes;
	uint32_t aad_cnt;
	uint8_t **input_buf;
	uint8_t **output_buf;
	long *input_len;
};

static int aes_cbc_hmac_sha1_setup_session(EVP_CIPHER_CTX *ctx);
static int dpdkcpt_aes_cbc_hmac_sha1_cipher(EVP_CIPHER_CTX *ctx,
		unsigned char *out, const unsigned char *in, size_t inl);
static int dpdkcpt_aes_cbc_hmac_sha1_cleanup(EVP_CIPHER_CTX *ctx);
static int dpdkcpt_aes_cbc_hmac_sha1_init_key(EVP_CIPHER_CTX *ctx,
		const unsigned char *key,
				const unsigned char *iv, int enc, int key_len);
static int dpdkcpt_aes128_cbc_hmac_sha1_init_key(EVP_CIPHER_CTX *ctx,
				const unsigned char *key,
				const unsigned char *iv, int enc);
static int dpdkcpt_aes256_cbc_hmac_sha1_init_key(EVP_CIPHER_CTX *ctx,
				const unsigned char *key,
				const unsigned char *iv, int enc);
static int dpdkcpt_aes_cbc_hmac_sha1_ctrl(EVP_CIPHER_CTX *ctx, int type,
							int arg, void *ptr);
const EVP_CIPHER *dpdkcpt_aes_128_cbc_hmac_sha1(void);
const EVP_CIPHER *dpdkcpt_aes_256_cbc_hmac_sha1(void);
EVP_CIPHER *_hidden_aes_128_cbc_hmac_sha1;
EVP_CIPHER *_hidden_aes_256_cbc_hmac_sha1;

extern int sym_dev_id[];
extern int sym_queues[];

static inline uint8_t *
pktmbuf_mtod_offset(struct rte_mbuf *mbuf, int offset)
{
	struct rte_mbuf *m;

	for (m = mbuf; (m != NULL) && (offset > m->data_len); m = m->next)
		offset -= m->data_len;

	if (m == NULL) {
		printf("pktmbuf_mtod_offset: offset out of buffer\n");
		return NULL;
	}
	return rte_pktmbuf_mtod_offset(m, uint8_t *, offset);
}

static inline rte_iova_t
pktmbuf_iova_offset(struct rte_mbuf *mbuf, int offset)
{
	struct rte_mbuf *m;

	for (m = mbuf; (m != NULL) && (offset > m->data_len); m = m->next)
		offset -= m->data_len;

	if (m == NULL) {
		printf("pktmbuf_iova_offset: offset out of buffer\n");
		return 0;
	}
	return rte_pktmbuf_iova_offset(m, offset);
}

const EVP_CIPHER *dpdkcpt_aes_128_cbc_hmac_sha1(void)
{
	if (_hidden_aes_128_cbc_hmac_sha1 == NULL) {
		_hidden_aes_128_cbc_hmac_sha1 = EVP_CIPHER_meth_new(
				NID_aes_128_cbc_hmac_sha1, E_DPDKCPT_AES_BLOCK_SIZE,
				E_DPDKCPT_AES128_CBC_KEY_LENGTH);
		if (_hidden_aes_128_cbc_hmac_sha1 != NULL) {
			if (!EVP_CIPHER_meth_set_iv_length(_hidden_aes_128_cbc_hmac_sha1,
						E_DPDKCPT_AES_CBC_IV_LENGTH) ||
				!EVP_CIPHER_meth_set_flags(_hidden_aes_128_cbc_hmac_sha1,
					  EVP_CIPH_CBC_MODE
					| EVP_CIPH_FLAG_DEFAULT_ASN1
					| EVP_CIPH_FLAG_AEAD_CIPHER
					| EVP_CIPH_FLAG_PIPELINE) ||
				!EVP_CIPHER_meth_set_init(_hidden_aes_128_cbc_hmac_sha1,
					dpdkcpt_aes128_cbc_hmac_sha1_init_key) ||
				!EVP_CIPHER_meth_set_do_cipher(_hidden_aes_128_cbc_hmac_sha1,
					dpdkcpt_aes_cbc_hmac_sha1_cipher) ||
				!EVP_CIPHER_meth_set_cleanup(_hidden_aes_128_cbc_hmac_sha1,
					dpdkcpt_aes_cbc_hmac_sha1_cleanup) ||
				!EVP_CIPHER_meth_set_ctrl(_hidden_aes_128_cbc_hmac_sha1,
					dpdkcpt_aes_cbc_hmac_sha1_ctrl) ||
				!EVP_CIPHER_meth_set_impl_ctx_size(
					_hidden_aes_128_cbc_hmac_sha1,
					sizeof(struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx))) {
					EVP_CIPHER_meth_free(_hidden_aes_128_cbc_hmac_sha1);
					_hidden_aes_128_cbc_hmac_sha1 = NULL;
				}
		}
	}

	return _hidden_aes_128_cbc_hmac_sha1;
}

const EVP_CIPHER *dpdkcpt_aes_256_cbc_hmac_sha1(void)
{
	if (_hidden_aes_256_cbc_hmac_sha1 == NULL) {
		_hidden_aes_256_cbc_hmac_sha1 = EVP_CIPHER_meth_new(
				NID_aes_256_cbc_hmac_sha1, E_DPDKCPT_AES_BLOCK_SIZE,
				E_DPDKCPT_AES256_CBC_KEY_LENGTH);
		if (_hidden_aes_256_cbc_hmac_sha1 != NULL) {
			if (!EVP_CIPHER_meth_set_iv_length(_hidden_aes_256_cbc_hmac_sha1,
					E_DPDKCPT_AES_CBC_IV_LENGTH) ||
				!EVP_CIPHER_meth_set_flags(_hidden_aes_256_cbc_hmac_sha1,
					  EVP_CIPH_CBC_MODE
					| EVP_CIPH_FLAG_DEFAULT_ASN1
					| EVP_CIPH_FLAG_AEAD_CIPHER
					| EVP_CIPH_FLAG_PIPELINE) ||
				!EVP_CIPHER_meth_set_init(_hidden_aes_256_cbc_hmac_sha1,
					dpdkcpt_aes256_cbc_hmac_sha1_init_key) ||
				!EVP_CIPHER_meth_set_do_cipher(_hidden_aes_256_cbc_hmac_sha1,
					dpdkcpt_aes_cbc_hmac_sha1_cipher) ||
				!EVP_CIPHER_meth_set_cleanup(_hidden_aes_256_cbc_hmac_sha1,
					dpdkcpt_aes_cbc_hmac_sha1_cleanup) ||
				!EVP_CIPHER_meth_set_ctrl(_hidden_aes_256_cbc_hmac_sha1,
					dpdkcpt_aes_cbc_hmac_sha1_ctrl) ||
				!EVP_CIPHER_meth_set_impl_ctx_size(
					_hidden_aes_256_cbc_hmac_sha1,
					sizeof(struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx))) {
					EVP_CIPHER_meth_free(_hidden_aes_256_cbc_hmac_sha1);
					_hidden_aes_256_cbc_hmac_sha1 = NULL;
				}
		}
	}

	return _hidden_aes_256_cbc_hmac_sha1;
}

/*
 * AES HMAC SHA Implementation
 */

int aes_cbc_hmac_sha1_setup_session(EVP_CIPHER_CTX *ctx)
{
	unsigned int lcore = rte_lcore_id();
	if (lcore == LCORE_ID_ANY || sym_dev_id[lcore] == -1) {
		engine_log(ENG_LOG_ERR, "%s: Queues not available for lcore %d\n",
			__FUNCTION__, lcore);
		return 0;
	}
	int dev_id = sym_dev_id[lcore];
	struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx *dpdk_ctx =
		(struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx *)
		EVP_CIPHER_CTX_get_cipher_data(ctx);

	struct rte_crypto_sym_xform cipher_xform = {
		.next = NULL,
		.type = RTE_CRYPTO_SYM_XFORM_CIPHER,
		.cipher = { .op = dpdk_ctx->enc ? RTE_CRYPTO_CIPHER_OP_ENCRYPT :
			RTE_CRYPTO_CIPHER_OP_DECRYPT,
			.algo = RTE_CRYPTO_CIPHER_AES_CBC,
			.key = { .length = dpdk_ctx->keylen },
			.iv = { .offset = E_DPDKCPT_AES_CBC_HMAC_SHA_IV_OFFSET,
				.length = E_DPDKCPT_AES_CBC_IV_LENGTH } }
	};

	struct rte_crypto_sym_xform auth_xform = {
		.next = NULL,
		.type = RTE_CRYPTO_SYM_XFORM_AUTH,
		.auth = { .op = dpdk_ctx->enc ? RTE_CRYPTO_AUTH_OP_GENERATE :
			 RTE_CRYPTO_AUTH_OP_VERIFY,
			.algo = RTE_CRYPTO_AUTH_SHA1_HMAC,
			.key = { .length = SHA_DIGEST_LENGTH},
			.digest_length = SHA_DIGEST_LENGTH}
	};

	struct rte_crypto_sym_xform *first_xform;

	if (dpdk_ctx->enc) {
		first_xform = &auth_xform;
		auth_xform.next = &cipher_xform;
	} else {
		first_xform = &cipher_xform;
		cipher_xform.next = &auth_xform;
	}

	auth_xform.auth.key.data = dpdk_ctx->hmac_key;
	cipher_xform.cipher.key.data = (const uint8_t *)dpdk_ctx->key;

	dpdk_ctx->dev_id = dev_id;
	/* Create crypto session and initialize it for the crypto device. */
	if (dpdk_ctx->cry_session == NULL) {
		dpdk_ctx->cry_session =
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
			(void *)rte_cryptodev_sym_session_create(dev_id,
								first_xform,
								sym_session_pool);
#else
			(void *)rte_cryptodev_sym_session_create(sym_session_pool);
#endif
		if (dpdk_ctx->cry_session == NULL) {
			engine_log(ENG_LOG_ERR, "Session could not be created\n");
			return 0;
		}

#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		if (rte_cryptodev_sym_session_init(dev_id,
					(struct rte_cryptodev_sym_session *)dpdk_ctx->cry_session,
					first_xform,
					sym_session_priv_pool) < 0) {
			engine_log(ENG_LOG_ERR, "Session could not be initialized for the crypto device\n");
			return 0;
		}
#endif
	}

	return 1;
}

int dpdkcpt_aes_cbc_hmac_sha1_init_key(EVP_CIPHER_CTX *ctx,
		const unsigned char *key, const unsigned char *iv,
		int enc, int key_len)
{
	struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx *dpdk_ctx =
		(struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx *)
		EVP_CIPHER_CTX_get_cipher_data(ctx);

	if (iv != NULL)
		memcpy(dpdk_ctx->iv, iv, E_DPDKCPT_AES_CBC_IV_LENGTH);

	if (key != NULL) {
		memcpy(dpdk_ctx->key, key, key_len);

	    dpdk_ctx->keylen = key_len;
	    dpdk_ctx->enc = enc;
	    dpdk_ctx->update_keys = 1;
	    dpdk_ctx->numpipes = 0;
	    dpdk_ctx->payload_length = E_DPDK_AES_SHA1_NO_PAYLOAD_LENGTH;
    }

	return 1;
}

int dpdkcpt_aes128_cbc_hmac_sha1_init_key(EVP_CIPHER_CTX *ctx,
		const unsigned char *key, const unsigned char *iv, int enc)
{
	return dpdkcpt_aes_cbc_hmac_sha1_init_key(ctx, key, iv, enc,
					E_DPDKCPT_AES128_CBC_KEY_LENGTH);
}

int dpdkcpt_aes256_cbc_hmac_sha1_init_key(EVP_CIPHER_CTX *ctx,
		const unsigned char *key, const unsigned char *iv, int enc)
{
	return dpdkcpt_aes_cbc_hmac_sha1_init_key(ctx, key, iv, enc,
					E_DPDKCPT_AES256_CBC_KEY_LENGTH);
}

int dpdkcpt_aes_cbc_hmac_sha1_ctrl(EVP_CIPHER_CTX *ctx, int type,
									int arg, void *ptr)
{
	struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx *dpdk_ctx =
		(struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx *)
		EVP_CIPHER_CTX_get_cipher_data(ctx);

	if (dpdk_ctx == NULL)
		return 0;

	switch (type) {
	case EVP_CTRL_AEAD_SET_MAC_KEY:
		{
			if (ptr != NULL)
				memcpy(dpdk_ctx->hmac_key, ptr, arg);

			return 1;
		}
	case EVP_CTRL_AEAD_TLS1_AAD:
		{
			unsigned char *p = ptr;
			unsigned int len;

			/* Save the AAD for later use */
			if (arg != EVP_AEAD_TLS1_AAD_LEN)
				return -1;

			len = p[arg - 2] << 8 | p[arg - 1];

			if (EVP_CIPHER_CTX_encrypting(ctx)) {
				dpdk_ctx->payload_length = len;
				dpdk_ctx->tls_ver =
					p[arg - 4] << 8 | p[arg - 3];
				if (dpdk_ctx->tls_ver >= TLS1_1_VERSION) {
					if (len < E_DPDKCPT_AES_BLOCK_SIZE)
						return 0;
					len -= E_DPDKCPT_AES_BLOCK_SIZE;
					p[arg - 2] = len >> 8;
					p[arg - 1] = len;
				}
				if (dpdk_ctx->aad_cnt < SSL_MAX_PIPELINES) {
					memcpy(dpdk_ctx->tls_aad
					       [dpdk_ctx->aad_cnt], ptr, arg);
					dpdk_ctx->aad_cnt++;
				}
				dpdk_ctx->tls_aad_len = arg;

				return (((len + SHA_DIGEST_LENGTH +
						E_DPDKCPT_AES_BLOCK_SIZE)
						& -E_DPDKCPT_AES_BLOCK_SIZE)
						- len);
			} else {
				memcpy(dpdk_ctx->tls_aad[dpdk_ctx->aad_cnt],
						ptr, arg);
				dpdk_ctx->aad_cnt++;
				dpdk_ctx->payload_length = arg;
				dpdk_ctx->tls_aad_len = arg;

				return SHA_DIGEST_LENGTH;
			}
		}

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

int dpdkcpt_aes_cbc_hmac_sha1_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			const unsigned char *in, size_t inl)
{
	struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx *dpdk_ctx =
		(struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx *)
		EVP_CIPHER_CTX_get_cipher_data(ctx);
	ossl_cry_op_status_t **status_ptr, **new_st_ptr;
	size_t plen = dpdk_ctx->payload_length, iv_len = 0, sha_data_off = 0,
			sha_data_len = 0;
	unsigned int pad_len = 0;
	AES_KEY aes_key;

	struct rte_crypto_op **enq_op_ptr, **deq_op_ptr;
	int numpipes = 1;

	numpipes = dpdk_ctx->numpipes;

	dpdk_ctx->payload_length = E_DPDK_AES_SHA1_NO_PAYLOAD_LENGTH;

	if (inl % E_DPDKCPT_AES_BLOCK_SIZE)
		return 0;

	/* Minimum packet size.
	 * E_DPDKCPT_AES_BLOCK_SIZE bytes explicit IV +
	 * SHA_DIGEST_LENGTH bytes HMAC +
	 * one byte data +
	 * padding
	 */
	if (inl < (3 * E_DPDKCPT_AES_BLOCK_SIZE))
		return 0;

	if (dpdk_ctx->update_keys) {
		aes_cbc_hmac_sha1_setup_session(ctx);
		dpdk_ctx->update_keys = 0;
	}
	/* Bydefault number of pipes is one */
	if (numpipes == 0) {
		numpipes = 1;
		dpdk_ctx->input_len = malloc(sizeof(int));
		dpdk_ctx->input_len[0] = inl;
		dpdk_ctx->output_buf = &out;
		/* As it's inplace */
		dpdk_ctx->input_buf = &out;
	}

	char *sha_data_buf[numpipes];
	void *buf_digest[numpipes];
	void *buf_pad_len[numpipes];
	char *buf[numpipes];
	uint16_t i, num_dequeued_ops, num_enqueued_ops;
	struct rte_mbuf *mbuf;
	uint8_t *iv_ptr;
	void *buf_ptr;

	enq_op_ptr = malloc(sizeof(struct rte_crypto_op *) * numpipes);
	deq_op_ptr = malloc(sizeof(struct rte_crypto_op *) * numpipes);
	status_ptr = malloc(sizeof(ossl_cry_op_status_t *) * numpipes);
	new_st_ptr = malloc(sizeof(ossl_cry_op_status_t *) * numpipes);

	for (i = 0; i < numpipes; i++) {

		enq_op_ptr[i] = rte_crypto_op_alloc(
		crypto_sym_op_pool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
		if (enq_op_ptr[i] == NULL) {
			engine_log(ENG_LOG_ERR, "Not enough crypto operations available\n");
			return 0;
		}
		/* Get a burst of mbufs */
		mbuf = rte_pktmbuf_alloc(mbuf_pool);
		if (mbuf == NULL) {
			engine_log(ENG_LOG_ERR, "Not enough crypto ops available\n");
			return 0;
		}

		if (EVP_CIPHER_CTX_encrypting(ctx)) {
			if (plen == E_DPDK_AES_SHA1_NO_PAYLOAD_LENGTH) {
				/* Even for speed test and other tests without
				 * payload follow tls proto
				 */
				plen = dpdk_ctx->input_len[i] -
						SHA_DIGEST_LENGTH -
						((dpdk_ctx->input_len[i] -
						SHA_DIGEST_LENGTH) %
						E_DPDKCPT_AES_BLOCK_SIZE);
				iv_len = E_DPDKCPT_AES_BLOCK_SIZE;
			} else if (dpdk_ctx->input_len[i] !=
					(long)((plen + SHA_DIGEST_LENGTH +
					E_DPDKCPT_AES_BLOCK_SIZE)
					& -E_DPDKCPT_AES_BLOCK_SIZE))
				return 0;
			else if (dpdk_ctx->tls_ver >= TLS1_1_VERSION)
				iv_len = E_DPDKCPT_AES_BLOCK_SIZE;

			sha_data_off += iv_len;

			/* First AES_BLOCK is encrypted using software
			 * as per current flexi crypto
			 */
			memset(&aes_key, 0, sizeof(AES_KEY));
			AES_set_encrypt_key(dpdk_ctx->key,
				dpdk_ctx->keylen*8,
				&aes_key);
			AES_cbc_encrypt(dpdk_ctx->input_buf[numpipes-1-i],
					dpdk_ctx->output_buf[numpipes-1-i],
					E_DPDKCPT_AES_BLOCK_SIZE, &aes_key,
					dpdk_ctx->iv, AES_ENCRYPT);
			memcpy(dpdk_ctx->iv, dpdk_ctx->output_buf[numpipes-1-i],
				E_DPDKCPT_AES_CBC_IV_LENGTH);

			/* reserve space for input digest */
			/* For TLS it is AAD + payload */
			sha_data_len = dpdk_ctx->tls_aad_len + plen -
					sha_data_off;
			sha_data_buf[i] = rte_pktmbuf_append(mbuf,
					sha_data_len);
			if (sha_data_buf[i] == NULL) {
				engine_log(ENG_LOG_ERR, "Not enough room in the mbuf\n");
				return 0;
			}
			memset(sha_data_buf[i], 0, sha_data_len);
			memcpy(sha_data_buf[i], dpdk_ctx->tls_aad[i],
				dpdk_ctx->tls_aad_len);
			memcpy((sha_data_buf[i]+dpdk_ctx->tls_aad_len),
				(in+sha_data_off), (plen-sha_data_off));

			/* reserve space for digest */
			buf_digest[i] = rte_pktmbuf_append(mbuf,
					SHA_DIGEST_LENGTH);
			memset(buf_digest[i], 0, SHA_DIGEST_LENGTH);

			/* reserve space for padding */
			pad_len = dpdk_ctx->input_len[i] - plen -
					SHA_DIGEST_LENGTH;
			buf_pad_len[i] = rte_pktmbuf_append(mbuf, pad_len);
			memset(buf_pad_len[i], (pad_len-1), pad_len);

			enq_op_ptr[i]->sym->m_src = mbuf;
			enq_op_ptr[i]->sym->cipher.data.offset =
					dpdk_ctx->tls_aad_len;
			enq_op_ptr[i]->sym->cipher.data.length = plen -
					sha_data_off + SHA_DIGEST_LENGTH +
					pad_len;
			enq_op_ptr[i]->sym->auth.digest.data =
				pktmbuf_mtod_offset(mbuf, sha_data_len);
			enq_op_ptr[i]->sym->auth.digest.phys_addr =
				pktmbuf_iova_offset(mbuf, sha_data_len);
			enq_op_ptr[i]->sym->auth.data.offset = 0;
			enq_op_ptr[i]->sym->auth.data.length = sha_data_len;

			dpdk_ctx->output_buf[i] += E_DPDKCPT_AES_BLOCK_SIZE;
			dpdk_ctx->input_len[i] -= E_DPDKCPT_AES_BLOCK_SIZE;

		} else {
			unsigned char pad_data[E_DPDKCPT_AES_BLOCK_SIZE];
			unsigned char pad_iv[E_DPDKCPT_AES_CBC_IV_LENGTH];
			unsigned int pad;
			size_t data_len;

			memcpy(pad_data, dpdk_ctx->output_buf[i] +
				dpdk_ctx->input_len[i]-E_DPDKCPT_AES_BLOCK_SIZE,
				E_DPDKCPT_AES_BLOCK_SIZE);
			memcpy(pad_iv, dpdk_ctx->output_buf[i]+
					dpdk_ctx->input_len[i]-
					(2*E_DPDKCPT_AES_BLOCK_SIZE),
					E_DPDKCPT_AES_CBC_IV_LENGTH);
			memset(&aes_key, 0, sizeof(AES_KEY));
			AES_set_decrypt_key(dpdk_ctx->key,
				dpdk_ctx->keylen*8, &aes_key);
			AES_cbc_encrypt(pad_data, pad_data,
				E_DPDKCPT_AES_BLOCK_SIZE, &aes_key,
				pad_iv, AES_DECRYPT);

			memcpy(dpdk_ctx->iv, dpdk_ctx->input_buf[i],
					E_DPDKCPT_AES_CBC_IV_LENGTH);

			dpdk_ctx->input_buf[i] += E_DPDKCPT_AES_BLOCK_SIZE;
			dpdk_ctx->input_len[i] -= E_DPDKCPT_AES_BLOCK_SIZE;

			pad = pad_data[E_DPDKCPT_AES_BLOCK_SIZE-1];
			data_len = dpdk_ctx->input_len[i] -
				(SHA_DIGEST_LENGTH + pad + 1);
			dpdk_ctx->tls_aad[i][dpdk_ctx->tls_aad_len - 2] =
					data_len >> 8;
			dpdk_ctx->tls_aad[i][dpdk_ctx->tls_aad_len - 1] =
			data_len;

			/* rte_pktmbuf_append returns the pointer to appended
			 * data.
			 */
			buf[i] = rte_pktmbuf_append(mbuf,
					(inl+dpdk_ctx->tls_aad_len));
			if (buf[i] == NULL) {
				engine_log(ENG_LOG_ERR, "Not enough room in the mbuf\n");
				return 0;
			}
			memcpy(buf[i], dpdk_ctx->tls_aad[i],
					dpdk_ctx->tls_aad_len);
			memcpy(buf[i]+dpdk_ctx->tls_aad_len,
					dpdk_ctx->input_buf[i],
					dpdk_ctx->input_len[i]);
			enq_op_ptr[i]->sym->m_src = mbuf;
			enq_op_ptr[i]->sym->cipher.data.offset =
					dpdk_ctx->tls_aad_len;
			enq_op_ptr[i]->sym->cipher.data.length =
					dpdk_ctx->input_len[i];
			enq_op_ptr[i]->sym->auth.digest.data =
					pktmbuf_mtod_offset(mbuf,
					(data_len + dpdk_ctx->tls_aad_len));
			enq_op_ptr[i]->sym->auth.digest.phys_addr =
					pktmbuf_iova_offset(mbuf, (data_len +
					dpdk_ctx->tls_aad_len));
			enq_op_ptr[i]->sym->auth.data.offset = 0;
			enq_op_ptr[i]->sym->auth.data.length =
			dpdk_ctx->tls_aad_len + data_len;
		}

		iv_ptr = rte_crypto_op_ctod_offset(enq_op_ptr[i], uint8_t *,
			E_DPDKCPT_AES_CBC_HMAC_SHA_IV_OFFSET);

		memcpy(iv_ptr, dpdk_ctx->iv, E_DPDKCPT_AES_CBC_IV_LENGTH);

		status_ptr[i] = rte_crypto_op_ctod_offset(
				enq_op_ptr[i], ossl_cry_op_status_t *,
				E_DPDKCPT_COP_METADATA_OFF_CBC_HMAC_SHA);

		status_ptr[i]->is_complete = 0;
		status_ptr[i]->is_successful = 0;

		rte_crypto_op_attach_sym_session(enq_op_ptr[i],
				dpdk_ctx->cry_session);

	}
	/* Enqueue this crypto operation in the crypto device. */
	num_enqueued_ops = rte_cryptodev_enqueue_burst(dpdk_ctx->dev_id,
			sym_queues[rte_lcore_id()], enq_op_ptr, numpipes);

	if (num_enqueued_ops < numpipes) {
		rte_mempool_put_bulk(crypto_sym_op_pool, (void **)enq_op_ptr,
					 numpipes);
		for (i = 0; i < numpipes; i++)
			rte_pktmbuf_free(enq_op_ptr[i]->sym->m_src);
		printf("\n %d Crypto operations enqueue failed.\n",
				(numpipes - num_enqueued_ops));
		return 0;
	}

	/*
	 * Assumption is that 1 operation is dequeued since only
	 * one operation is enqueued.
	 */
	num_dequeued_ops = 0;
	while (num_dequeued_ops != numpipes) {
		pause_async_job();
		num_dequeued_ops += rte_cryptodev_dequeue_burst(
				dpdk_ctx->dev_id, sym_queues[rte_lcore_id()],
				&deq_op_ptr[num_dequeued_ops], numpipes);
	}

	if (num_dequeued_ops == numpipes) {
		for (i = 0; i < numpipes; i++) {
			new_st_ptr[i] = rte_crypto_op_ctod_offset(deq_op_ptr[i],
					ossl_cry_op_status_t *,
					E_DPDKCPT_COP_METADATA_OFF_CBC_HMAC_SHA);
			new_st_ptr[i]->is_complete = 1;
			/* Check if operation was processed successfully */
			if (deq_op_ptr[i]->status !=
					RTE_CRYPTO_OP_STATUS_SUCCESS) {
				new_st_ptr[i]->is_successful = 0;
				printf("\nSome operations were not processed\n"
					"correctly err: %d, i = %d\n",
					deq_op_ptr[i]->status, i);
			} else {
				new_st_ptr[i]->is_successful = 1;
			}
		}
	}
	for (i = 0; i < numpipes; i++) {
		buf_ptr = rte_pktmbuf_mtod_offset(enq_op_ptr[i]->sym->m_src,
				char *, dpdk_ctx->tls_aad_len);
		memcpy(dpdk_ctx->output_buf[i], buf_ptr,
				dpdk_ctx->input_len[i]);
		rte_pktmbuf_free(enq_op_ptr[i]->sym->m_src);
		enq_op_ptr[i]->sym->m_src = NULL;
	}
	rte_mempool_put_bulk(crypto_sym_op_pool, (void **)enq_op_ptr, numpipes);

	dpdk_ctx->aad_cnt = 0;
	dpdk_ctx->numpipes = 0;

	free(enq_op_ptr);
	free(deq_op_ptr);
	free(new_st_ptr);
	free(status_ptr);

	enq_op_ptr = NULL;
	deq_op_ptr = NULL;
	new_st_ptr = NULL;
	status_ptr = NULL;

	return 1;
}

int dpdkcpt_aes_cbc_hmac_sha1_cleanup(EVP_CIPHER_CTX *ctx)
{
	int retval;
	int dev_id = sym_dev_id[rte_lcore_id()];
	struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx *dpdk_ctx =
		(struct e_dpdkcpt_aes_cbc_hmac_sha1_ctx *)
		EVP_CIPHER_CTX_get_cipher_data(ctx);

	if (dpdk_ctx->cry_session != NULL) {
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		retval = rte_cryptodev_sym_session_clear(
			dev_id, (struct rte_cryptodev_sym_session *)
					dpdk_ctx->cry_session);
		if (retval < 0)
			engine_log(ENG_LOG_ERR, "FAILED to clear session. ret=%d\n",
				retval);
		retval = rte_cryptodev_sym_session_free(
			(struct rte_cryptodev_sym_session *)
				dpdk_ctx->cry_session);
#else
		retval = rte_cryptodev_sym_session_free(dev_id,
			(struct rte_cryptodev_sym_session *)
				dpdk_ctx->cry_session);
#endif
		if (retval < 0)
			engine_log(ENG_LOG_ERR, "FAILED to free session. ret=%d\n",
				retval);
	}

	return 1;
}
