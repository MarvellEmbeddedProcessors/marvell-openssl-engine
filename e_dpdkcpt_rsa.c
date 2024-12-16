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
#include <openssl/crypto.h>
#include <openssl/bn.h>

#include <openssl/ssl.h>
#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_malloc.h>

#include "e_dpdkcpt.h"
#include "e_dpdkcpt_rsa.h"

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

RSA_METHOD * default_rsa_meth;
const struct rte_cryptodev_asymmetric_xform_capability *asym_rsa_xform_cap;

extern int asym_dev_id[];
extern int asym_queues[];

extern int cpt_num_requests_in_flight;
extern int cpt_num_asym_requests_in_flight;

static int setup_noncrt_priv_op_xform(struct rte_crypto_asym_xform *rsa_xform,
				      RSA *rsa)
{
	uint64_t total_size = 0;
	const BIGNUM *n;
	const BIGNUM *e;
	const BIGNUM *d;

	RSA_get0_key(rsa, &n, &e, &d);
	if ((n == NULL) || (e == NULL) || (d == NULL)) {
		engine_log(ENG_LOG_ERR, "One or more non crt method params(n/e/d) "
				"are NULL");
		return -1;
	}

        memset(rsa_xform, 0, sizeof(struct rte_crypto_asym_xform));
	rsa_xform->xform_type = RTE_CRYPTO_ASYM_XFORM_RSA;
	rsa_xform->rsa.key_type = RTE_RSA_KEY_TYPE_EXP;
	total_size = BN_num_bytes(n) + BN_num_bytes(e) + BN_num_bytes(d);

	rsa_xform->rsa.n.data = (uint8_t *)rte_malloc(NULL, total_size, 0);
	if (unlikely(rsa_xform->rsa.n.data == NULL)) {
		engine_log(ENG_LOG_ERR,	"func:%s:line %u FAILED: %s", __func__,
				__LINE__, "rte_malloc failure");
		return -1;
	}
	rsa_xform->rsa.n.length = BN_bn2bin(n, rsa_xform->rsa.n.data);

	rsa_xform->rsa.e.data =
		(uint8_t *)rsa_xform->rsa.n.data + rsa_xform->rsa.n.length;
	rsa_xform->rsa.e.length = BN_bn2bin(e, rsa_xform->rsa.e.data);
	rsa_xform->rsa.d.data = (uint8_t *)rsa_xform->rsa.e.data +
		rsa_xform->rsa.e.length;
	rsa_xform->rsa.d.length = BN_bn2bin(d, rsa_xform->rsa.d.data);
	return 0;
}

static void setup_crt_priv_op_xform(struct rte_crypto_asym_xform *rsa_xform,
				    RSA *rsa)
{
	uint64_t total_size = 0, crt_length = 0;
	const BIGNUM *dmp1;
	const BIGNUM *dmq1;
	const BIGNUM *iqmp;
	const BIGNUM *n;
	const BIGNUM *e;
	const BIGNUM *p;
	const BIGNUM *q;
	int ret = 0;

	RSA_get0_key(rsa, &n, &e, NULL);
	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

        memset(rsa_xform, 0, sizeof(struct rte_crypto_asym_xform));
	rsa_xform->xform_type = RTE_CRYPTO_ASYM_XFORM_RSA;
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	rsa_xform->rsa.key_type = RTE_RSA_KEY_TYPE_QT;
#else
	rsa_xform->rsa.key_type = RTE_RSA_KET_TYPE_QT;
#endif

	/* To avoid multiple malloc calls, doing it one time with total size of
	 * all parameters.
	 * Maximum length for a CRT parameter is BN_num_bytes(n)/2.
	 */
	total_size =
		BN_num_bytes(n) + BN_num_bytes(e) + 5 * (BN_num_bytes(n) / 2);
	crt_length = BN_num_bytes(n) / 2;

	rsa_xform->rsa.n.data = (uint8_t *)rte_malloc(NULL, total_size, 0);
	if (unlikely(rsa_xform->rsa.n.data == NULL)) {
		engine_log(ENG_LOG_ERR,	"func:%s:line %u FAILED: %s", __func__,
				__LINE__, "rte_malloc failure");
		return;
	}
	rsa_xform->rsa.n.length = BN_bn2bin(n, rsa_xform->rsa.n.data);

	rsa_xform->rsa.e.data =
		(uint8_t *)rsa_xform->rsa.n.data + rsa_xform->rsa.n.length;
	rsa_xform->rsa.e.length = BN_bn2bin(e, rsa_xform->rsa.e.data);

	rsa_xform->rsa.qt.p.data =
		(uint8_t *)rsa_xform->rsa.e.data + rsa_xform->rsa.e.length;
	rsa_xform->rsa.qt.p.length = BN_bn2bin(p, rsa_xform->rsa.qt.p.data);

	rsa_xform->rsa.qt.q.data = (uint8_t *)rsa_xform->rsa.qt.p.data +
				   rsa_xform->rsa.qt.p.length;
	rsa_xform->rsa.qt.q.length = BN_bn2bin(q, rsa_xform->rsa.qt.q.data);

	/* Microcode requires CRT parameters be prepadded with zeroes if length
	 * is lesser than modlength/2
	 */
	rsa_xform->rsa.qt.dP.data = (uint8_t *)rsa_xform->rsa.qt.q.data +
				    rsa_xform->rsa.qt.q.length;
	ret = BN_bn2bin(dmp1, rsa_xform->rsa.qt.dP.data + crt_length
		- BN_num_bytes(dmp1));
	if (ret == -1)
		fprintf(stderr, "Error: Conversion failed.\n");
	rsa_xform->rsa.qt.dP.length = crt_length;

	rsa_xform->rsa.qt.dQ.data = (uint8_t *)rsa_xform->rsa.qt.dP.data +
				    rsa_xform->rsa.qt.dP.length;
	ret = BN_bn2bin(dmq1, rsa_xform->rsa.qt.dQ.data + crt_length
		- BN_num_bytes(dmq1));
	if (ret == -1)
		fprintf(stderr, "Error: Conversion failed.\n");
	rsa_xform->rsa.qt.dQ.length = crt_length;

	rsa_xform->rsa.qt.qInv.data = (uint8_t *)rsa_xform->rsa.qt.dQ.data +
				      rsa_xform->rsa.qt.dQ.length;
	ret = BN_bn2bin(iqmp, rsa_xform->rsa.qt.qInv.data + crt_length
		- BN_num_bytes(iqmp));
	if (ret == -1)
		fprintf(stderr, "Error: Conversion failed.\n");
	rsa_xform->rsa.qt.qInv.length = crt_length;
}

static void setup_non_crt_pub_op_xform(struct rte_crypto_asym_xform *rsa_xform,
				       RSA *rsa)
{
	uint64_t total_size = 0;
	const BIGNUM *n;
	const BIGNUM *e;
	const BIGNUM *d;

	RSA_get0_key(rsa, &n, &e, &d);

        memset(rsa_xform, 0, sizeof(struct rte_crypto_asym_xform));
	rsa_xform->xform_type = RTE_CRYPTO_ASYM_XFORM_RSA;

	/* To avoid multiple malloc calls, doing it one time with total size of
	 * all parameters.
	 * Maximum length for a NON-CRT parameter is BN_num_bytes(d).
	 */
	if (d != NULL)
		total_size =
			BN_num_bytes(n) + BN_num_bytes(e) + BN_num_bytes(d);
	else
		total_size = BN_num_bytes(n) + BN_num_bytes(e);

	rsa_xform->rsa.n.data = (uint8_t *)rte_malloc(NULL, total_size, 0);
	if (unlikely(rsa_xform->rsa.n.data == NULL)) {
		engine_log(ENG_LOG_ERR,	"func:%s:line %u FAILED: %s", __func__,
				__LINE__, "rte_malloc failure");
		return;
	}
	rsa_xform->rsa.n.length = BN_bn2bin(n, rsa_xform->rsa.n.data);

	rsa_xform->rsa.e.data =
		(uint8_t *)rsa_xform->rsa.n.data + rsa_xform->rsa.n.length;
	rsa_xform->rsa.e.length = BN_bn2bin(e, rsa_xform->rsa.e.data);

	if (d != NULL) {
		rsa_xform->rsa.key_type = RTE_RSA_KEY_TYPE_EXP;
		rsa_xform->rsa.d.data = (uint8_t *)rsa_xform->rsa.e.data +
					rsa_xform->rsa.e.length;
		rsa_xform->rsa.d.length = BN_bn2bin(d, rsa_xform->rsa.d.data);
	} else {
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		rsa_xform->rsa.key_type = RTE_RSA_KEY_TYPE_QT;
#else
		rsa_xform->rsa.key_type = RTE_RSA_KET_TYPE_QT;
#endif
		rsa_xform->rsa.qt.p.data = NULL;
		rsa_xform->rsa.qt.p.length = 0;
	}
}

static void reset_xform(struct rte_crypto_asym_xform *rsa_xform)
{
	rte_free(rsa_xform->rsa.n.data);
}

static int asym_sess_create(struct rte_crypto_asym_xform *rsa_xform,
			    struct rte_cryptodev_asym_session **sess)
{
	unsigned int lcore = rte_lcore_id();
	if (lcore == LCORE_ID_ANY || asym_dev_id[lcore] == -1) {
		engine_log(ENG_LOG_ERR, "%s: Queues not available for lcore %d\n",
			__FUNCTION__, lcore);
		return -1;
	}
	uint8_t dev_id = asym_dev_id[lcore];
	int ret = 0;

	/* Create Asym Session */
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	ret = rte_cryptodev_asym_session_create(dev_id, rsa_xform,
						asym_session_pool,
						(void **)sess);
	if (unlikely(ret < 0)) {
		engine_log(ENG_LOG_ERR,	"line %u FAILED: %s", __LINE__,
			"Session creation failed");
		return -1;
	}
#else
	*sess = rte_cryptodev_asym_session_create(asym_session_pool);
	if (unlikely(sess == NULL)) {
		engine_log(ENG_LOG_ERR,	"line %u FAILED: %s", __LINE__,
			"Session creation failed");
		return -1;
	}

	ret = rte_cryptodev_asym_session_init(dev_id, *sess, rsa_xform,
					      asym_session_pool);
	if (unlikely(ret < 0)) {
		engine_log(ENG_LOG_ERR, "line %u FAILED: %s", __LINE__,
			"unable to config asym session");
		rte_cryptodev_asym_session_free(*sess);
		return -1;
	}
#endif
	return 1;
}

static void asym_sess_destroy(struct rte_cryptodev_asym_session *sess)
{
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	rte_cryptodev_asym_session_free(asym_dev_id[rte_lcore_id()], sess);
#else
	rte_cryptodev_asym_session_clear(asym_dev_id[rte_lcore_id()], sess);
	rte_cryptodev_asym_session_free(sess);
#endif
}

static int queue_ops(struct rte_crypto_op *cry_op)
{
	struct rte_crypto_op *result_op[MAX_DEQUEUE_OPS];
	unsigned int lcoreid = rte_lcore_id();
	uint8_t dev_id = asym_dev_id[lcoreid];
	int nb_ops = 0, qp_id = asym_queues[lcoreid];
	struct rte_crypto_asym_xform *rsa_xform = NULL;
	ASYNC_WAIT_CTX **wctx_p = NULL;
	uint32_t op_size = 0;

	op_size = __rte_crypto_op_get_priv_data_size(crypto_asym_op_pool);
	rsa_xform = __rte_crypto_op_get_priv_data(cry_op, op_size);
	wctx_p = (ASYNC_WAIT_CTX **) rsa_xform + 1;

	ASYNC_JOB *job = ASYNC_get_current_job();
	if (job != NULL && wctx_p != NULL)
		*wctx_p = ASYNC_get_wait_ctx(job);

	if (rte_cryptodev_enqueue_burst(dev_id, qp_id, &cry_op, 1) != 1) {
		engine_log(ENG_LOG_ERR, "Error in cryptodev enqueue\n");
		return -1;
	}

	CPT_ATOMIC_INC(cpt_num_asym_requests_in_flight);
	CPT_ATOMIC_INC(cpt_num_requests_in_flight);
	pause_async_job();

	while (cry_op->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED) {
		nb_ops = rte_cryptodev_dequeue_burst(dev_id, qp_id, result_op,
							 MAX_DEQUEUE_OPS);
		if (nb_ops == 0)
			ASYNC_pause_job();
	}

	CPT_ATOMIC_DEC(cpt_num_asym_requests_in_flight);
	CPT_ATOMIC_DEC(cpt_num_requests_in_flight);

	if (cry_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
		engine_log(ENG_LOG_ERR, "Crypto (RSA) op status is not success!\n");
		return -1;
	}
	return 1;
}

static int dpdk_rsa_check_modlen(RSA *rsa)
{
	int ret;
	uint64_t plen;
	const BIGNUM *n;

	RSA_get0_key(rsa, &n, NULL, NULL);
	plen = BN_num_bytes(n);

	ret = rte_cryptodev_asym_xform_capability_check_modlen(
			asym_rsa_xform_cap, plen);

	return ret;
}

static inline int is_crt_meth_possible (RSA *rsa)
{
	const BIGNUM *dmp1;
	const BIGNUM *dmq1;
	const BIGNUM *iqmp;
	const BIGNUM *p;
	const BIGNUM *q;

	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
	if (p == NULL || q == NULL || dmp1 == NULL || dmq1 == NULL ||
	    iqmp == NULL) {
		engine_log(ENG_LOG_ERR, "One or more CRT op params(p/q/dmp1/dmq1/iqmp)"
				" are NULL. Using non CRT method instead!!!\n");
		return 0;
	}
	return 1;
}

/*
 * RSA implementation
 */

/* Private encryption */
int dpdk_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
		      RSA *rsa, int padding)
{
	struct rte_cryptodev_asym_session *sess = NULL;
	struct rte_crypto_asym_xform *rsa_xform = NULL;
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *cry_op = NULL;
	uint32_t op_size = 0;
	int ret = 0, verify_func_ret = 0;
	int use_crt_method = 1;
	uint8_t *decrypt_msg = NULL;

	ret = dpdk_rsa_check_modlen(rsa);
	if (ret != 0 ||
	   (padding != RSA_NO_PADDING && padding !=  RSA_PKCS1_PADDING) ||
	   (RSA_get_version(rsa) == RSA_ASN1_VERSION_MULTI)) {
		RSA_set_method(rsa, default_rsa_meth);
		ret = RSA_meth_get_priv_enc(default_rsa_meth)(flen, from, to, rsa,
				padding);
		return ret;
	}
	if (!is_crt_meth_possible(rsa))
		use_crt_method = 0;

priv_enc_start:
	/* Generate Crypto op data structure */
	cry_op = rte_crypto_op_alloc(crypto_asym_op_pool,
				     RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (unlikely(cry_op == NULL)) {
		engine_log(ENG_LOG_ERR, "line %u FAILED: %s", __LINE__,
			"Failed to allocate asymmetric crypto "
			"operation struct");
		return -1;
	}

	op_size = __rte_crypto_op_get_priv_data_size(crypto_asym_op_pool);
	rsa_xform = __rte_crypto_op_get_priv_data(cry_op, op_size);

	/* Setup private xform operations */
	if (use_crt_method)
		setup_crt_priv_op_xform(rsa_xform, rsa);
	else {
		ret = setup_noncrt_priv_op_xform(rsa_xform, rsa);
		if (unlikely(ret < 0)) {
			reset_xform(rsa_xform);
			rte_crypto_op_free(cry_op);
			return -1;
		}
	}

#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
 	 if (padding == RSA_NO_PADDING)
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
  	else
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif

	/* Session Configuration */
	ret = asym_sess_create(rsa_xform, &sess);
	if (unlikely(ret < 0)) {
		reset_xform(rsa_xform);
		rte_crypto_op_free(cry_op);
		return -1;
	}

	/* attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(cry_op, sess);

	asym_op = cry_op->asym;
	asym_op->rsa.op_type = RTE_CRYPTO_ASYM_OP_SIGN;
	asym_op->rsa.message.data = from;
	asym_op->rsa.message.length = flen;
	asym_op->rsa.sign.length = flen;
	asym_op->rsa.sign.data = to;
	if (padding == RSA_NO_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_NONE;
#endif
	else if (padding == RSA_PKCS1_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif

	ret = RSA_size(rsa);

	/* Enqueue and Dequeue operations */
	if (unlikely(queue_ops(cry_op) < 0))
		ret = -1;
	asym_sess_destroy(sess);
	reset_xform(rsa_xform);
	rte_crypto_op_free(cry_op);

	if ((ret > 0) && (use_crt_method == 1)) {
		decrypt_msg = (uint8_t *)rte_malloc(NULL, ret, 0);
	        if (unlikely(decrypt_msg == NULL)) {
			engine_log(ENG_LOG_ERR,	"func:%s:line %u FAILED: %s", __func__,
				__LINE__, "rte_malloc failure");
			return -1;
		}

		verify_func_ret = dpdk_rsa_pub_dec(ret, to, decrypt_msg,
						   rsa, padding);
		if ((verify_func_ret < 0) ||
		    (memcmp(from, decrypt_msg, flen) != 0)) {
			use_crt_method = 0;
			goto priv_enc_start;
		}
		rte_free(decrypt_msg);
	}

	return ret;
}

/* Public decryption */
int dpdk_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to,
		     RSA *rsa, int padding)
{
	struct rte_crypto_asym_xform *rsa_xform = NULL;
	struct rte_cryptodev_asym_session *sess = NULL;
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *cry_op = NULL;
	uint32_t op_size = 0;
	int ret = 0;


	ret = dpdk_rsa_check_modlen(rsa);
	if (ret != 0 ||
	   (padding != RSA_NO_PADDING && padding !=  RSA_PKCS1_PADDING) ||
	   (RSA_get_version(rsa) == RSA_ASN1_VERSION_MULTI)) {
		RSA_set_method(rsa, default_rsa_meth);
		ret = RSA_meth_get_pub_dec(default_rsa_meth)(flen, from, to, rsa,
				padding);
		return ret;
	}

	/* Generate Crypto op data structure */
	cry_op = rte_crypto_op_alloc(crypto_asym_op_pool,
				     RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (unlikely(cry_op == NULL)) {
		engine_log(ENG_LOG_ERR, "line %u FAILED: %s", __LINE__,
			"Failed to allocate asymmetric crypto "
			"operation struct");
		return -1;
	}

	op_size = __rte_crypto_op_get_priv_data_size(crypto_asym_op_pool);
	rsa_xform = __rte_crypto_op_get_priv_data(cry_op, op_size);

	/* Setup public xform opertions */
	setup_non_crt_pub_op_xform(rsa_xform, rsa);

#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
  	if (padding == RSA_NO_PADDING)
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
  	else
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif

	/* Session Configuration */
	ret = asym_sess_create(rsa_xform, &sess);
	if (unlikely(ret < 0)) {
		reset_xform(rsa_xform);
		rte_crypto_op_free(cry_op);
		return -1;
	}

	/* Attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(cry_op, sess);

	asym_op = cry_op->asym;
	asym_op->rsa.op_type = RTE_CRYPTO_ASYM_OP_VERIFY;

	/* Octeon PMDs (otx2/cnxk) overwrite decrypted result in rsa.sign.data
	 * Note: Openssl PMD does not return decrypted result and it is not supported.
	 */
	if (to != from)
		memcpy(to, from, flen);
	asym_op->rsa.sign.data = to;
	asym_op->rsa.sign.length = flen;

	if (padding == RSA_NO_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_NONE;
#endif
	else if (padding == RSA_PKCS1_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif

	/* Enqueue and Dequeue operations */
	if (unlikely(queue_ops(cry_op) < 0))
		ret = -1;
	else
		ret = asym_op->rsa.sign.length;


	asym_sess_destroy(sess);
	reset_xform(rsa_xform);
	rte_crypto_op_free(cry_op);

	return ret;
}

/* public encryption*/
int dpdk_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to,
		     RSA *rsa, int padding)
{
	struct rte_crypto_asym_xform *rsa_xform = NULL;
	struct rte_cryptodev_asym_session *sess = NULL;
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *cry_op = NULL;
	uint32_t op_size = 0;
	int ret = 0;


	ret = dpdk_rsa_check_modlen(rsa);
	if (ret != 0 ||
	   (padding != RSA_NO_PADDING && padding !=  RSA_PKCS1_PADDING) ||
	   (RSA_get_version(rsa) == RSA_ASN1_VERSION_MULTI)) {
		RSA_set_method(rsa, default_rsa_meth);
		ret = RSA_meth_get_pub_enc(default_rsa_meth)(flen, from, to, rsa,
				padding);
		return ret;
	}

	/* Generate Crypto op data structure */
	cry_op = rte_crypto_op_alloc(crypto_asym_op_pool,
				     RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (unlikely(cry_op == NULL)) {
		engine_log(ENG_LOG_ERR, "line %u FAILED: %s", __LINE__,
			"Failed to allocate asymmetric crypto "
			"operation struct");
		return -1;
	}

	op_size = __rte_crypto_op_get_priv_data_size(crypto_asym_op_pool);
	rsa_xform = __rte_crypto_op_get_priv_data(cry_op, op_size);

	/* Setup public xform operations */
	setup_non_crt_pub_op_xform(rsa_xform, rsa);

#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
  	if (padding == RSA_NO_PADDING)
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
  	else
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif

	/* Session Configuration */
	ret = asym_sess_create(rsa_xform, &sess);
	if (unlikely(ret < 0)) {
		reset_xform(rsa_xform);
		rte_crypto_op_free(cry_op);
		return -1;
	}

	/* Attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(cry_op, sess);

	asym_op = cry_op->asym;
	asym_op->rsa.op_type = RTE_CRYPTO_ASYM_OP_ENCRYPT;

	asym_op->rsa.message.length = flen;
	asym_op->rsa.message.data = from;
	asym_op->rsa.cipher.length = 0;
	asym_op->rsa.cipher.data = to;
	if (padding == RSA_NO_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_NONE;
#endif
	else if (padding == RSA_PKCS1_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif

	ret = RSA_size(rsa);

	/* Enqueue and Dequeue operations */
	if (unlikely(queue_ops(cry_op) < 0))
		ret = -1;

	asym_sess_destroy(sess);
	reset_xform(rsa_xform);
	rte_crypto_op_free(cry_op);

	return ret;
}

/* Private decryption */
int dpdk_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to,
		      RSA *rsa, int padding)
{
	struct rte_crypto_asym_xform *rsa_xform = NULL;
	struct rte_cryptodev_asym_session *sess = NULL;
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *cry_op = NULL;
	uint32_t op_size = 0;
	int ret = 0;


	ret = dpdk_rsa_check_modlen(rsa);
	if (ret != 0 ||
	   (padding != RSA_NO_PADDING && padding !=  RSA_PKCS1_PADDING) ||
	   (RSA_get_version(rsa) == RSA_ASN1_VERSION_MULTI)) {
		RSA_set_method(rsa, default_rsa_meth);
		ret = RSA_meth_get_priv_dec(default_rsa_meth)(flen, from, to, rsa,
				padding);
		return ret;
	}

	/* Generate Crypto op data structure */
	cry_op = rte_crypto_op_alloc(crypto_asym_op_pool,
				     RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (unlikely(cry_op == NULL)) {
		engine_log(ENG_LOG_ERR, "line %u FAILED: %s", __LINE__,
			"Failed to allocate asymmetric crypto "
			"operation struct");
		return -1;
	}

	op_size = __rte_crypto_op_get_priv_data_size(crypto_asym_op_pool);
	rsa_xform = __rte_crypto_op_get_priv_data(cry_op, op_size);

	/* Setup priv xform opertions */
	setup_crt_priv_op_xform(rsa_xform, rsa);

#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
  	if (padding == RSA_NO_PADDING)
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
  	else
    		rsa_xform->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif

	/* Session Configuration */
	ret = asym_sess_create(rsa_xform, &sess);
	if (unlikely(ret < 0)) {
		reset_xform(rsa_xform);
		rte_crypto_op_free(cry_op);
		return -1;
	}

	/* Attach asymmetric crypto session to crypto operations */
	rte_crypto_op_attach_asym_session(cry_op, sess);

	asym_op = cry_op->asym;
	asym_op->rsa.op_type = RTE_CRYPTO_ASYM_OP_DECRYPT;

	asym_op->rsa.message.data = to;
	asym_op->rsa.message.length = 0;
	asym_op->rsa.cipher.data = from;
	asym_op->rsa.cipher.length = flen;
	if (padding == RSA_NO_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_NONE;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_NONE;
#endif
	else if (padding == RSA_PKCS1_PADDING)
#if RTE_VERSION >= RTE_VERSION_NUM(24, 11, 0, 0)
		;
#elif RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
		asym_op->rsa.padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#else
		asym_op->rsa.pad = RTE_CRYPTO_RSA_PADDING_PKCS1_5;
#endif
	/* Enqueue and Dequeue operations */
	if (unlikely(queue_ops(cry_op) < 0))
		ret = -1;
	else
		ret = asym_op->rsa.message.length;

	asym_sess_destroy(sess);
	reset_xform(rsa_xform);
	rte_crypto_op_free(cry_op);

	return ret;
}
