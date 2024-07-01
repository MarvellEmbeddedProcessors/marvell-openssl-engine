/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <openssl/async.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include <rte_crypto.h>
#include <rte_crypto_asym.h>
#include <rte_cryptodev.h>
#include <rte_hexdump.h>

#include "e_dpdkcpt.h"
#include "e_dpdkcpt_ecdsa.h"

#define MAX_DEQUEUE_OPS 32

extern int asym_dev_id[];
extern int asym_queues[];
extern OSSL_ASYNC_FD zero_fd;
extern struct rte_mempool *asym_session_pool;
extern struct rte_mempool *crypto_asym_op_pool;

extern int cpt_num_requests_in_flight;
extern int cpt_num_asym_requests_in_flight;

static int ecdsa_sess_create(struct rte_crypto_asym_xform *ecdsa_xform,
			     struct rte_cryptodev_asym_session **sess)
{
	unsigned int lcore = rte_lcore_id();
	if (lcore == LCORE_ID_ANY || asym_dev_id[lcore] == -1) {
		engine_log(ENG_LOG_ERR, "%s: Queues not available for lcore %d\n",
			__FUNCTION__, lcore);
		return 0;
	}
	int devid = asym_dev_id[lcore];
	int ret;

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	ret = rte_cryptodev_asym_session_create(devid, ecdsa_xform,
						asym_session_pool,
						(void **)sess);
	if (ret < 0) {
		engine_log(ENG_LOG_ERR, "Asym session create failed\n");
		return 0;
	}
#else
	*sess = rte_cryptodev_asym_session_create(asym_session_pool);
	if (*sess == NULL) {
		engine_log(ENG_LOG_ERR, "Asym session create failed\n");
		return 0;
	}

	ret = rte_cryptodev_asym_session_init(devid, *sess, ecdsa_xform,
					      asym_session_pool);

	if (ret < 0) {
		engine_log(ENG_LOG_ERR, "Asym session init failed\n");
		rte_cryptodev_asym_session_free(*sess);
		*sess = NULL;
		return 0;
	}
#endif
	return 1;
}

/**
 * @returns 1 on success, 0 on failure
 */
static int set_ec_point(struct rte_crypto_ec_point *p, const EC_GROUP *ecgroup,
			const EC_POINT *ecpoint)
{
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	int ret = 0;

	EC_POINT_get_affine_coordinates_GFp(ecgroup, ecpoint, x, y, NULL);

	if (bn_to_crypto_param(&p->x, x) && bn_to_crypto_param(&p->y, y)) {
		ret = 1; /* Success */
	} else {
		free_crypto_param(&p->x);
		free_crypto_param(&p->y);
	}

	BN_free(x);
	BN_free(y);

	return ret;
}

static inline void free_ec_point(struct rte_crypto_ec_point *p)
{
	if (p == NULL)
		return;

	free_crypto_param(&p->x);
	free_crypto_param(&p->y);
}

/**
 * Assumes that all the to-be-initialized pointers were set to NULL on function
 * call. i.e xform needs to have been memset/explicitly initialized to 0s
 *
 * @returns 1 on success, 0 on failure
 */
static int setup_ec_xform(struct rte_crypto_asym_xform *asym_xform,
			     const EC_GROUP *ecgroup, int type)
{
	int curve_name = EC_GROUP_get_curve_name(ecgroup);
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	enum rte_crypto_curve_id curve_id;
#else
	enum rte_crypto_ec_group curve_id;
#endif

	memset(asym_xform, 0, sizeof(*asym_xform));
	asym_xform->next = NULL;
	asym_xform->xform_type = type;

	switch (curve_name) {
	case NID_X9_62_prime192v1:
		curve_id = RTE_CRYPTO_EC_GROUP_SECP192R1;
		break;
	case NID_secp224r1:
		curve_id = RTE_CRYPTO_EC_GROUP_SECP224R1;
		break;
	case NID_X9_62_prime256v1:
		curve_id = RTE_CRYPTO_EC_GROUP_SECP256R1;
		break;
	case NID_secp384r1:
		curve_id = RTE_CRYPTO_EC_GROUP_SECP384R1;
		break;
	case NID_secp521r1:
		curve_id = RTE_CRYPTO_EC_GROUP_SECP521R1;
		break;
	default:
		/* Unsupported curve */
		return 0;
	}

	asym_xform->ec.curve_id = curve_id;
	return 1;
}

/**
 * Assumes that all the to-be-initialized pointers were set to NULL on function
 * call. i.e xform needs to have been memset/explicitly initialized to 0s
 *
 * @returns 1 on success, 0 on failure
 */
static inline int
setup_ecdsa_sign_xform(struct rte_crypto_asym_xform *asym_xform,
		       const EC_GROUP *ecgroup, const EC_KEY *eckey)
{
	(void) eckey;
	return setup_ec_xform(asym_xform, ecgroup, RTE_CRYPTO_ASYM_XFORM_ECDSA);
}

static int ecdh_sess_create(struct rte_crypto_asym_xform *ecdh_xform,
                             struct rte_cryptodev_asym_session **sess)
{
        unsigned int lcore = rte_lcore_id();
        if (lcore == LCORE_ID_ANY || asym_dev_id[lcore] == -1) {
            engine_log(ENG_LOG_ERR, "%s: Queues not available for lcore %d\n",
                __FUNCTION__, lcore);
            return 0;
        }
        int devid = asym_dev_id[lcore];
        int ret;

#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
        ret = rte_cryptodev_asym_session_create(devid, ecdh_xform,
						asym_session_pool,
						(void **)sess);
        if (ret < 0)
                return 0;
#else
        *sess = rte_cryptodev_asym_session_create(asym_session_pool);
	if (*sess == NULL)
		return 0;

        ret = rte_cryptodev_asym_session_init(devid, *sess, ecdh_xform,
                                              asym_session_pool);

        if (ret < 0) {
                engine_log(ENG_LOG_ERR, "Asym session init failed\n");
                rte_cryptodev_asym_session_free(*sess);
                *sess = NULL;
                return 0;
        }
#endif

        return 1;
}

/**
 * @returns 1 on success, 0 on auth failure, and -1 on error
 */
static int perform_crypto_op(struct rte_crypto_op *crypto_op)
{
	struct rte_crypto_op *result_ops[MAX_DEQUEUE_OPS];
	uint16_t nb_ops;
	unsigned int lcoreid = rte_lcore_id();
	uint8_t devid = asym_dev_id[lcoreid];
	int qp_id = asym_queues[lcoreid];
	ASYNC_WAIT_CTX **wctx_p = NULL;
	struct rte_crypto_asym_xform *asym_xform = NULL;

	if (rte_cryptodev_enqueue_burst(devid, qp_id, &crypto_op, 1) != 1) {
		engine_log(ENG_LOG_ERR, "Could not enqueue the crypto opeation\n");
		return -1;
	}

	asym_xform = __rte_crypto_op_get_priv_data(crypto_op,
                        sizeof(struct rte_crypto_asym_xform));
	wctx_p = (ASYNC_WAIT_CTX **) asym_xform + 1;

	ASYNC_JOB *job = ASYNC_get_current_job();
	if (job != NULL && wctx_p != NULL) {
		*wctx_p = ASYNC_get_wait_ctx(job);
	}

	CPT_ATOMIC_INC(cpt_num_asym_requests_in_flight);
	CPT_ATOMIC_INC(cpt_num_requests_in_flight);
	pause_async_job();

	while (crypto_op->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED) {
		nb_ops = rte_cryptodev_dequeue_burst(devid, qp_id, result_ops,
							 MAX_DEQUEUE_OPS);
		if (nb_ops == 0)
		   ASYNC_pause_job();
	}

	CPT_ATOMIC_DEC(cpt_num_asym_requests_in_flight);
	CPT_ATOMIC_DEC(cpt_num_requests_in_flight);

	if (crypto_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
		if (crypto_op->status == RTE_CRYPTO_OP_STATUS_AUTH_FAILED)
			return 0;
		else {
			engine_log(ENG_LOG_ERR,
				"Crypto (ECDSA) operation not success (err: %d)", crypto_op->status);
			return -1;
		}
	}

	return 1;
}

/**
 * @returns 1 on success, 0 on failure
 * Conforms to OpenSSL's ECDSA_sign semantics
 */
int ecdsa_sign(int type, const unsigned char *dgst, int dlen,
	       unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
	       const BIGNUM *r, EC_KEY *eckey)
{
	const int xform_size = sizeof(struct rte_crypto_asym_xform);
	struct rte_crypto_ecdsa_op_param *ecdsa_param = NULL;
	const EC_GROUP *ecgroup = EC_KEY_get0_group(eckey);
	struct rte_crypto_asym_xform *asym_xform = NULL;
	struct rte_cryptodev_asym_session *sess = NULL;
	const int max_rslen = PCURVES_MAX_PRIME_LEN;
	uint8_t devid = asym_dev_id[rte_lcore_id()];
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *crypto_op = NULL;
	unsigned char *dup_buf = NULL;
	int redo, rlen, slen, derlen;
	unsigned char *buf = NULL;
	ECDSA_SIG *sig_st = NULL;
	BIGNUM *k = BN_new();
	BIGNUM *rbn = NULL;
	BIGNUM *sbn = NULL;
	int ret = 0;
	(void)type;
	(void)kinv;
	(void)r;

	crypto_op = rte_crypto_op_alloc(crypto_asym_op_pool,
					RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (crypto_op == NULL)
		return 0;

	asym_xform = __rte_crypto_op_get_priv_data(crypto_op, xform_size);
	asym_op = &crypto_op->asym[0];
	ecdsa_param = &asym_op->ecdsa;

	if (!setup_ecdsa_sign_xform(asym_xform, ecgroup, eckey))
		goto err;

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 99)
	if (!bn_to_crypto_param(&ecdsa_param->pkey,
				EC_KEY_get0_private_key(eckey)))
#else
	if (!bn_to_crypto_param(&asym_xform->ec.pkey,
				EC_KEY_get0_private_key(eckey)))
#endif
		goto err;

	if (!ecdsa_sess_create(asym_xform, &sess))
		goto err;

	if (rte_crypto_op_attach_asym_session(crypto_op, sess) != 0)
		goto err;

	ecdsa_param->op_type = RTE_CRYPTO_ASYM_OP_SIGN;
	ecdsa_param->message.data = malloc(dlen);
	ecdsa_param->message.length = dlen;

	if (ecdsa_param->message.data == NULL)
		goto err;

	memcpy(ecdsa_param->message.data, dgst, dlen);
#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 99)
	if (!set_ec_point(&ecdsa_param->q, ecgroup,
			  EC_KEY_get0_public_key(eckey)))
#else
	if (!set_ec_point(&asym_xform->ec.q, ecgroup,
			  EC_KEY_get0_public_key(eckey)))
#endif
		goto err;

	ecdsa_param->r.data = malloc(max_rslen);
	ecdsa_param->s.data = malloc(max_rslen);
	ecdsa_param->r.length = max_rslen;
	ecdsa_param->s.length = max_rslen;

	if (ecdsa_param->r.data == NULL || ecdsa_param->s.data == NULL)
		goto err;

	do {
		redo = false;

		do {
			BN_rand_range(k, EC_GROUP_get0_order(ecgroup));
		} while (BN_is_zero(k));

		if (!bn_to_crypto_param(&ecdsa_param->k, k))
			goto err;

		if (perform_crypto_op(crypto_op) != 1)
			goto err;

		rlen = ecdsa_param->r.length;
		slen = ecdsa_param->s.length;

		rbn = BN_bin2bn(ecdsa_param->r.data, rlen, NULL);
		sbn = BN_bin2bn(ecdsa_param->s.data, slen, NULL);

		if (rbn == NULL || sbn == NULL) {
			BN_free(rbn);
			BN_free(sbn);
			goto err;
		}

		if (BN_is_zero(rbn) || BN_is_zero(sbn)) {
			redo = true;
			BN_free(rbn);
			BN_free(sbn);
			sbn = NULL;
			rbn = NULL;
			ecdsa_param->r.length = max_rslen;
			ecdsa_param->s.length = max_rslen;
		}
	} while (redo);

	sig_st = ECDSA_SIG_new();
	if (!ECDSA_SIG_set0(sig_st, rbn, sbn)) {
		BN_free(rbn);
		BN_free(sbn);
		goto err;
	}

	buf = malloc(PCURVES_MAX_DER_SIG_LEN);
	if (buf == NULL)
		goto err;

	dup_buf = buf;
	derlen = i2d_ECDSA_SIG(sig_st, &dup_buf);

	memcpy(sig, buf, derlen);
	*siglen = derlen;
	ret = 1;

err:
	if (sess != NULL) {
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		rte_cryptodev_asym_session_clear(devid, sess);
		rte_cryptodev_asym_session_free(sess);
#else
		rte_cryptodev_asym_session_free(devid, sess);
#endif
	}
	if (crypto_op != NULL)
		rte_crypto_op_free(crypto_op);

	ECDSA_SIG_free(sig_st);
	BN_free(k);
	free(buf);

	return ret;
}

static inline int
setup_ecdsa_verify_xform(struct rte_crypto_asym_xform *asym_xform,
			 const EC_GROUP *ecgroup)
{
	return setup_ec_xform(asym_xform, ecgroup, RTE_CRYPTO_ASYM_XFORM_ECDSA);
}

/**
 * @returns 1 on successful verification, 0 on verification failure, -1 on error
 */
int ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
		 const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
	const int xform_size = sizeof(struct rte_crypto_asym_xform);
	uint8_t devid = asym_dev_id[rte_lcore_id()];
	int ret = -1;

	struct rte_cryptodev_asym_session *sess = NULL;
	struct rte_crypto_asym_xform *asym_xform = NULL;
	struct rte_crypto_ecdsa_op_param *ecdsa_param = NULL;
	struct rte_crypto_asym_op *asym_op = NULL;
	struct rte_crypto_op *crypto_op = NULL;

	const EC_GROUP *ecgroup = EC_KEY_get0_group(eckey);
	const BIGNUM *rbn = NULL;
	const BIGNUM *sbn = NULL;
	ECDSA_SIG *sig_st = NULL;
	int rlen;
	int slen;
	(void)type;

	crypto_op = rte_crypto_op_alloc(crypto_asym_op_pool,
					RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
	if (crypto_op == NULL)
		return -1;

	asym_xform = __rte_crypto_op_get_priv_data(crypto_op, xform_size);

	if (asym_xform == NULL)
		return -1;

	if (!setup_ecdsa_verify_xform(asym_xform, ecgroup))
		goto err;

	if (!ecdsa_sess_create(asym_xform, &sess))
		goto err;

	if (rte_crypto_op_attach_asym_session(crypto_op, sess) != 0)
		goto err;

	asym_op = &crypto_op->asym[0];
	ecdsa_param = &asym_op->ecdsa;
	memset(&ecdsa_param->k, 0, sizeof(rte_crypto_param));
	;
	ecdsa_param->op_type = RTE_CRYPTO_ASYM_OP_VERIFY;
	ecdsa_param->message.data = malloc(dgst_len);
	ecdsa_param->message.length = dgst_len;

	if (ecdsa_param->message.data == NULL)
		goto err;

	memcpy(ecdsa_param->message.data, dgst, dgst_len);

#if RTE_VERSION < RTE_VERSION_NUM(23, 11, 0, 99)
	if (!set_ec_point(&ecdsa_param->q, ecgroup,
			  EC_KEY_get0_public_key(eckey)))
#else
	if (!set_ec_point(&asym_xform->ec.q, ecgroup,
			  EC_KEY_get0_public_key(eckey)))
#endif
		goto err;

	if (d2i_ECDSA_SIG(&sig_st, &sigbuf, sig_len) == NULL)
		goto err;

	ECDSA_SIG_get0(sig_st, &rbn, &sbn);

	rlen = BN_num_bytes(rbn);
	slen = BN_num_bytes(sbn);

	ecdsa_param->r.data = malloc(rlen);
	ecdsa_param->s.data = malloc(slen);
	ecdsa_param->r.length = rlen;
	ecdsa_param->s.length = slen;

	if (ecdsa_param->r.data == NULL || ecdsa_param->s.data == NULL)
		goto err;

	BN_bn2bin(rbn, ecdsa_param->r.data);
	BN_bn2bin(sbn, ecdsa_param->s.data);

	ret = perform_crypto_op(crypto_op);

err:
	if(sess != NULL) {
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		rte_cryptodev_asym_session_clear(devid, sess);
		rte_cryptodev_asym_session_free(sess);
#else
		rte_cryptodev_asym_session_free(devid, sess);
#endif
	}
	if ( crypto_op != NULL)
		rte_crypto_op_free(crypto_op);

	ECDSA_SIG_free(sig_st);

	return ret;
}

static int e_dpdkcpt_ec_point_mul(const EC_GROUP *group, void *rxbuf,
                                  void *rybuf, const BIGNUM *g_scalar,
                                  const EC_POINT *point)
{
        struct rte_crypto_asym_op *asym_op = NULL;
        struct rte_crypto_op *op = NULL;
        struct rte_cryptodev_asym_session *sess = NULL;
        struct rte_crypto_asym_xform *xform;
        BIGNUM *px = BN_new();
        BIGNUM *py = BN_new();
        BIGNUM *rx = BN_new();
        BIGNUM *ry = BN_new();
        int ret = -1;
        int devid = asym_dev_id[rte_lcore_id()];

        /* set up crypto op data structure */

        op = rte_crypto_op_alloc(crypto_asym_op_pool,
                        RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
        if (!op) {
                RTE_LOG(ERR, USER1,
                        "line %u FAILED: %s",
                        __LINE__, "Failed to allocate asymmetric crypto "
                        "operation struct");
                goto error_exit;
        }

        xform = __rte_crypto_op_get_priv_data(op,
                        sizeof(struct rte_crypto_asym_xform));

		if (!setup_ec_xform(xform, group, RTE_CRYPTO_ASYM_XFORM_ECPM))
			goto error_exit;

        if (!ecdh_sess_create(xform, &sess))
                goto error_exit;

         /* attach asymmetric crypto session to crypto operations */
         rte_crypto_op_attach_asym_session(op, sess);

        EC_POINT_get_affine_coordinates_GFp(group, point, px, py, NULL);
        asym_op = op->asym;
        bn_to_crypto_param(&asym_op->ecpm.p.x, px);
        bn_to_crypto_param(&asym_op->ecpm.p.y, py);
        bn_to_crypto_param(&asym_op->ecpm.scalar, g_scalar);

        asym_op->ecpm.r.x.data = rxbuf;
        asym_op->ecpm.r.y.data = rybuf;

        ret = perform_crypto_op(op);
	if (ret < 1) {
		ret = 0;
                RTE_LOG(ERR, USER1,
                        "%s: EC Point arithmetic failure: ret: %d",
			__func__, ret);
		goto error_exit;
	}

	ret = asym_op->ecpm.r.x.length;

        rte_crypto_op_free(op);
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
        rte_cryptodev_asym_session_clear(devid, sess);

        if (rte_cryptodev_asym_session_free(sess) != 0)
                engine_log(ENG_LOG_ERR, "Could not free the asym session properly\n");
#else
        if (rte_cryptodev_asym_session_free(devid, sess) != 0)
                engine_log(ENG_LOG_ERR, "Could not free the asym session properly\n");
#endif

error_exit:
        BN_free(ry);
        BN_free(rx);
        BN_free(py);
        BN_free(px);
        return ret;
}

int ecdh_keygen(EC_KEY *eckey)
{
     const EC_GROUP *group = EC_KEY_get0_group((const EC_KEY*)eckey);
     int ok = 0;
     const BIGNUM *const_priv_key = EC_KEY_get0_private_key(
                                                (const EC_KEY*)eckey);
     const EC_POINT *generator = EC_GROUP_get0_generator(group);
     const BIGNUM *order;
     BIGNUM *priv_key = NULL;
     EC_POINT *pub_key = NULL;
     void *rxbuf = NULL;
     void *rybuf = NULL;
     int prime_length;
     BIGNUM *rx, *ry;

     if (const_priv_key == NULL) {
         priv_key = BN_secure_new();
         if (priv_key == NULL)
             goto err;
     } else
         priv_key = BN_dup(const_priv_key);

     order = EC_GROUP_get0_order(group);
     if (order == NULL)
         goto err;

     do
         if (!BN_rand_range(priv_key, order))
             goto err;
     while (BN_is_zero(priv_key)) ;

     pub_key = EC_POINT_new(group);
     if (pub_key == NULL)
         goto err;

     rxbuf = OPENSSL_malloc(PCURVES_MAX_PRIME_LEN);
     rybuf = OPENSSL_malloc(PCURVES_MAX_PRIME_LEN);
     if (rxbuf == NULL || rybuf == NULL)
     	goto err;

     memset(rxbuf, 0, PCURVES_MAX_PRIME_LEN);
     memset(rybuf, 0, PCURVES_MAX_PRIME_LEN);

     if ((prime_length = e_dpdkcpt_ec_point_mul(group, rxbuf, rybuf,
         priv_key, generator)) == 0) {
         ECerr(EC_F_PKEY_EC_KEYGEN, EC_R_POINT_ARITHMETIC_FAILURE);
         goto err;
     }

     rx = BN_bin2bn(rxbuf, prime_length, NULL);
     ry = BN_bin2bn(rybuf, prime_length, NULL);
     EC_POINT_set_affine_coordinates_GFp(group, pub_key, rx, ry,
                        NULL);
     EC_KEY_set_private_key(eckey, priv_key);
     EC_KEY_set_public_key(eckey, pub_key);
     ok = 1;

  err:
     if (rybuf)
         OPENSSL_free(rybuf);
     if (rxbuf)
         OPENSSL_free(rxbuf);
     if (pub_key)
         EC_POINT_free(pub_key);
     if (priv_key)
         BN_free(priv_key);
     return ok;
}

int ecdh_compute_key(unsigned char **pout, size_t *poutlen,
                     const EC_POINT *pub_key, const EC_KEY *ecdh)
{
     BN_CTX *ctx;
     BIGNUM *x = NULL, *y = NULL;
     const BIGNUM *priv_key;
     const EC_GROUP *group;
     int ret = 0;
     size_t buflen;
     void *rxbuf = NULL;
     void *rybuf = NULL;

     if ((ctx = BN_CTX_new()) == NULL)
         goto err;

     BN_CTX_start(ctx);
     x = BN_CTX_get(ctx);
     y = BN_CTX_get(ctx);
     if (x == NULL || y == NULL) {
         ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
         goto err;
     }

     priv_key = EC_KEY_get0_private_key(ecdh);
     if (priv_key == NULL) {
         ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, EC_R_NO_PRIVATE_VALUE);
         goto err;
     }

     group = EC_KEY_get0_group(ecdh);
     if (EC_KEY_get_flags(ecdh) & EC_FLAG_COFACTOR_ECDH) {
         if (!EC_GROUP_get_cofactor(group, x, NULL) ||
             !BN_mul(x, x, priv_key, ctx)) {
             ECerr(EC_F_ECDH_SIMPLE_COMPUTE_KEY, ERR_R_MALLOC_FAILURE);
             goto err;
         }
         priv_key = x;
     }

     rxbuf = OPENSSL_malloc(PCURVES_MAX_PRIME_LEN);
     rybuf = OPENSSL_malloc(PCURVES_MAX_PRIME_LEN);
     if (rxbuf == NULL || rybuf == NULL)
     	goto err;

     memset(rxbuf, 0, PCURVES_MAX_PRIME_LEN);
     memset(rybuf, 0, PCURVES_MAX_PRIME_LEN);

     if ((buflen = e_dpdkcpt_ec_point_mul(group, rxbuf, rybuf,
     	priv_key, pub_key)) == 0) {
         ECerr(EC_F_ECDH_COMPUTE_KEY, EC_R_POINT_ARITHMETIC_FAILURE);
         goto err;
     }

     *pout = rxbuf;
     *poutlen = buflen;
     rxbuf = NULL;
     ret = 1;
err:
     if (rybuf)
         OPENSSL_free(rybuf);
     if (rxbuf)
         OPENSSL_free(rxbuf);
     if (ctx)
         BN_CTX_end(ctx);
     BN_CTX_free(ctx);
     return ret;
}
