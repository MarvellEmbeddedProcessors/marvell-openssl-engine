/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _E_DPDK_RSA_H
#define _E_DPDK_RSA_H

#define MBUF_TEST_SIZE 1024
extern RSA_METHOD * default_rsa_meth;
extern const struct rte_cryptodev_asymmetric_xform_capability *asym_rsa_xform_cap;

int dpdk_rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to,
		     RSA *rsa, int padding);
int dpdk_rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to,
		     RSA *rsa, int padding);
int dpdk_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
		      RSA *rsa, int padding);
int dpdk_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to,
		      RSA *rsa, int padding);
#endif /* _E_DPDKCPT_RSA_H */
