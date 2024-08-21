/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _E_DPDKCPT_ECDSA_H
#define _E_DPDKCPT_ECDSA_H

#include <openssl/bn.h>
#include <openssl/ec.h>

#define PCURVES_MAX_PRIME_LEN		72 /* P521 curve */
#define PCURVES_MAX_DER_SIG_LEN		141

int ecdsa_sign(int type, const unsigned char *dgst, int dlen,
	       unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
	       const BIGNUM *r, EC_KEY *eckey);

int ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
		 const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);

int ecdh_keygen(EC_KEY *key);

int ecdh_compute_key(unsigned char **psec, size_t *pseclen,
		      const EC_POINT *pub_key, const EC_KEY *ecdh);

static inline void free_crypto_param(rte_crypto_param *p)
{
	free(p->data);
	p->data = NULL;
	p->length = 0;
	return;
}

static inline int bn_to_crypto_param(rte_crypto_param *cp, const BIGNUM *bn)
{
	cp->data = malloc(PCURVES_MAX_PRIME_LEN);
	if (!cp->data)
		return 0;

	cp->length = BN_num_bytes(bn);
	memset(cp->data, 0, PCURVES_MAX_PRIME_LEN);
	if (BN_bn2bin(bn, cp->data) <= 0) {
		free_crypto_param(cp);
		return 0;
	}

	return 1;
}

#endif
