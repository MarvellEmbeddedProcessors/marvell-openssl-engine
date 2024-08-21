/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#define _GNU_SOURCE
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
#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cryptodev.h>

#include "e_dpdkcpt.h"
#include "e_dpdkcpt_rsa.h"
#include "e_dpdkcpt_malloc.h"
#include "e_dpdkcpt_ecdsa.h"

#ifdef OSSL_PMD
#include "e_openssl.h"
#elif defined CRYPTO_OCTEONTX2
#include "e_dpdkcpt_otx2.h"
#elif defined(CRYPTO_A80X0)
#include "e_dpdkcpt_a80x0.h"
#else
#include "e_openssl.h"
#endif

OSSL_ASYNC_FD zero_fd;

struct rte_mempool *mbuf_pool;
struct rte_mempool *crypto_sym_op_pool;
struct rte_mempool *sym_session_pool;
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
struct rte_mempool *sym_session_priv_pool;
#endif
struct rte_mempool *crypto_asym_op_pool;
struct rte_mempool *asym_session_pool;

/* Engine Id and Name */
static const char *engine_dpdkcpt_id = "dpdk_engine";
static const char *engine_dpdkcpt_name = "OpenSSL Engine v1.0 using DPDK";

static ENGINE_CMD_DEFN dpdkcpt_cmd_defns [] =
{
	{DPDKCPT_CTRL_CMD_EAL_PARAMS, "eal_params",
	 "Parameters for rte_eal_init()", ENGINE_CMD_FLAG_STRING},
	{DPDKCPT_CTRL_CMD_EAL_INIT, "eal_init",
	 "Perform rte_eal_init()", ENGINE_CMD_FLAG_STRING},
	{DPDKCPT_CTRL_CMD_EAL_PID_IN_FP, "eal_pid_in_fileprefix",
	 "Use PID in file-prefix for rte_eal_init()", ENGINE_CMD_FLAG_STRING},
	{DPDKCPT_CTRL_CMD_EAL_CORE_BY_CPU, "eal_core_by_cpu",
	 "Specify current corenum in rte_eal_init()", ENGINE_CMD_FLAG_STRING},
	{DPDKCPT_CTRL_CMD_EAL_CPTVF_BY_CPU, "eal_cptvf_by_cpu",
	 "Use current corenum to determine whitelisting of crypto VF BDF", ENGINE_CMD_FLAG_STRING},
	{DPDKCPT_CTRL_CMD_CRYPTO_DRIVER, "crypto_driver",
	 "DPDK crypto PMD to use", ENGINE_CMD_FLAG_STRING},
	{DPDKCPT_CTRL_CMD_CPTVF_QUEUES, "cptvf_queues",
	 "VF Queues to map for each lcore ", ENGINE_CMD_FLAG_STRING},
	{DPDKCPT_CTRL_CMD_ENGINE_ALG_SUPPORT, "engine_alg_support",
	 "Enable/disable asymmetric or symmetric support in openssl engine ", ENGINE_CMD_FLAG_STRING},
        {DPDKCPT_CTRL_CMD_DPDK_QP_CONF_PARAMS, "dpdk_qp_conf_params",
         "DPDK Mempool and qp descriptor count config params for Symmetric & Asymmetric operations", ENGINE_CMD_FLAG_STRING},
        {DPDKCPT_CTRL_CMD_HW_OFFLOAD_THRESH_PKTSZ, "hw_offload_pkt_sz_thresh",
         "Threshold pktsize value configured for HW offload", ENGINE_CMD_FLAG_NUMERIC},
        {DPDKCPT_CTRL_CMD_ENG_LOG_LEVEL, "engine_log_level",
         "DPDK Engine_level to use", ENGINE_CMD_FLAG_STRING},
        {DPDKCPT_CTRL_CMD_ENG_LOG_FILE, "engine_log_file",
         "DPDK Engine_logs to be dumped", ENGINE_CMD_FLAG_STRING},
        {DPDKCPT_CTRL_CMD_POLL, "POLL",
         "Poll the queues for running lcore", ENGINE_CMD_FLAG_NO_INPUT},
        {DPDKCPT_GET_NUM_REQUESTS_IN_FLIGHT, "GET_NUM_REQUESTS_IN_FLIGHT",
         "Get the number of in-flight requests", ENGINE_CMD_FLAG_NUMERIC}
};

#define DPDKCPT_MAX_EAL_PARAMS 64
#define DPDKCPT_MAX_EAL_ARGV 64

static char * dpdkcpt_eal_params[DPDKCPT_MAX_EAL_PARAMS];
static char * dpdkcpt_eal_argv[DPDKCPT_MAX_EAL_ARGV];
static int dpdkcpt_eal_params_cnt = 0;
static int dpdkcpt_eal_argc = 0;
static char * dpdkcpt_queue_conf = NULL;
static uint8_t disable_eal_init = 0;
static uint8_t engine_level = 0;
static FILE* log_fp = NULL;
static char * dpdkcpt_alg_params = NULL;
static uint16_t pool_cachesz[DPDKCPT_MAX_NUM_POOL];

int asym_queues[RTE_MAX_LCORE];
int sym_queues[RTE_MAX_LCORE];
int asym_dev_id[RTE_MAX_LCORE];
int sym_dev_id[RTE_MAX_LCORE];
unsigned int queues_per_vf[E_DPDKCPT_MAX_CPT_DEVICES] = {0};
uint32_t dpdkcpt_sessions = E_DPDKCPT_DEFAULT_SESSIONS;
uint32_t dpdkcpt_num_mbufs = E_DPDKCPT_DEFAULT_MBUFS;
uint32_t dpdkcpt_num_sym_ops = E_DPDKCPT_DEFAULT_SYM_OPS;
uint32_t dpdkcpt_num_asym_ops = E_DPDKCPT_DEFAULT_ASYM_OPS;
uint16_t dpdkcpt_pool_cache_size = E_DPDKCPT_DEFAULT_POOL_CACHE_SIZE;
uint16_t dpdkcpt_asym_qp_desc_count = E_DPDKCPT_DEFAULT_ASYM_QP_DESC_COUNT;
uint16_t dpdkcpt_sym_qp_desc_count = E_DPDKCPT_DEFAULT_SYM_QP_DESC_COUNT;
uint16_t hw_offload_pktsz_thresh = HW_OFFLOAD_PKT_SZ_THRESHOLD_DEFAULT;

int cpt_num_requests_in_flight = 0;
int cpt_num_asym_requests_in_flight = 0;
int cpt_num_kdf_requests_in_flight = 0;
int cpt_num_cipher_pipeline_requests_in_flight = 0;
/* Multi-buffer number of items in queue */
int cpt_num_asym_mb_items_in_queue = 0;
int cpt_num_kdf_mb_items_in_queue = 0;
int cpt_num_cipher_mb_items_in_queue = 0;

static inline void free_all_mempools(void);
static inline int process_dpdkcpt_queue_conf(char*);

/* RSA */
static RSA_METHOD *dpdk_rsa_method = NULL;
static EC_KEY_METHOD *dpdk_eckey_method = NULL;

/* Engine Lifetime functions */
static int dpdkcpt_destroy(ENGINE *e);
static int dpdkcpt_init(ENGINE *e);
static int dpdkcpt_ctrl(ENGINE *e, int cmd, long numval, void * ptrval, void (*cb) (void));
static int dpdkcpt_finish(ENGINE *e);

static int dpdkcpt_cap_ciphers(const int **nids, ENGINE *e);

/* Setup ciphers */
static int dpdkcpt_ciphers(ENGINE *, const EVP_CIPHER **, const int **, int);

static int dpdkcpt_cipher_nids[] = { NID_aes_128_cbc, NID_aes_256_cbc,
			NID_aes_128_gcm, NID_aes_256_gcm,
			NID_aes_128_cbc_hmac_sha1, NID_aes_256_cbc_hmac_sha1,
			NID_chacha20_poly1305, 0};

/* Device setup code */
static int config_sym_devs(int *sym_valid_dev, int sym_dev_count);
static int config_asym_devs(int *asym_valid_dev, int asym_dev_count);

static int dpdkcpt_poll(uint8_t dev_id, uint16_t qp_id);
static int dpdkcpt_sym_poll(uint8_t dev_id, uint16_t qp_id);

/* AES-GCM */
const EVP_CIPHER *dpdkcpt_aes_128_gcm(void);
const EVP_CIPHER *dpdkcpt_aes_256_gcm(void);

/* AES-CBC */
const EVP_CIPHER *dpdkcpt_aes_128_cbc(void);
const EVP_CIPHER *dpdkcpt_aes_256_cbc(void);

/* AES-CBC-HMAC-SHA1 */
const EVP_CIPHER *dpdkcpt_aes_128_cbc_hmac_sha1(void);
const EVP_CIPHER *dpdkcpt_aes_256_cbc_hmac_sha1(void);

/* CHACHA20-POLY1305 */
const EVP_CIPHER *EVP_dpdkcpt_chacha20_poly1305(void);

static const EC_KEY_METHOD *default_eckey_meth = NULL;

int (*ecdsa_sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
		     BIGNUM **rp) = NULL;
ECDSA_SIG *(*ecdsa_sign_sig)(const unsigned char *dgst, int dgst_len,
			  const BIGNUM *in_kinv, const BIGNUM *in_r,
			  EC_KEY *eckey) = NULL;
int (*ecdsa_verify_sig)(const unsigned char *dgst, int dgst_len,
		     const ECDSA_SIG *sig, EC_KEY *eckey) = NULL;

/* Engine logging API */
int engine_log(uint32_t level, const char *fmt, ...) {
     va_list args;
     va_start(args, fmt);

     if(engine_level >= level) {
         if(!log_fp)
             vfprintf(stderr, fmt, args);
         else
             vfprintf(log_fp, fmt, args);
     }
     va_end(args);
}

static int ec_key_set_group(EC_KEY *key, const EC_GROUP *grp)
{
       int nid = EC_GROUP_get_curve_name(grp);

       switch (nid) {
       case NID_X9_62_prime192v1:
       case NID_secp224r1:
       case NID_X9_62_prime256v1:
       case NID_secp384r1:
       case NID_secp521r1:
               break;
       default:
               /* Unsupported curve */
               return EC_KEY_set_method(key, default_eckey_meth);
       }

       return 1;
}

static inline void free_all_mempools(void)
{
	rte_mempool_free(mbuf_pool);
	rte_mempool_free(sym_session_pool);
	rte_mempool_free(crypto_sym_op_pool);
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
	rte_mempool_free(sym_session_priv_pool);
#endif
	rte_mempool_free(crypto_asym_op_pool);
	rte_mempool_free(asym_session_pool);

	mbuf_pool = NULL;
	sym_session_pool = NULL;
	crypto_sym_op_pool = NULL;
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
	sym_session_priv_pool = NULL;
#endif
	crypto_asym_op_pool = NULL;
	asym_session_pool = NULL;

	return;
}

/*
* Parse core numbers from below format
* cptvf_queues = {{c1, c2, c2, c3...}, {c4, c4, c6, ...}, ...}
*/
static inline int process_dpdkcpt_queue_conf(char* queue_conf) {
	char * tok = NULL, *range_tok = NULL;
	int vf = -1;
	unsigned int parsing_done = 0, queue = 0;
	unsigned int lcore = 0, lcore_l = 0, lcore_h = 0;

	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		sym_dev_id[lcore] = asym_dev_id[lcore] = -1;
		sym_queues[lcore] = asym_queues[lcore] = -1;
	}
	tok = strpbrk(queue_conf, "{");
	if (tok == NULL || *tok == '\0') {
		engine_log(ENG_LOG_ERR, "%s: cptvf_queues: Invalid Format\n", __FUNCTION__);
		return -1;
	}
	tok = strpbrk(tok+1, "{");
	while (tok != NULL && *tok != '\0') {
		switch(*tok) {
			case '{':
			/* Start of one VF config */
			vf++;
			queue = 0;
			/* Only parse config for the devices available */
			if (vf >= sym_dev_count) {
				parsing_done = 1;
				break;
			}
			if (vf >= E_DPDKCPT_MAX_CPT_DEVICES) {
				engine_log(ENG_LOG_ERR,
					"%s: cptvf_queues: Too many VFs configured\n", __FUNCTION__);
				return -1;
			}
			/* Fall through */
			case ',':
			/* Expect core number after '{' and ',' */
			sscanf(tok+1, "%d", &lcore_l);
			if (lcore_l > RTE_MAX_LCORE) {
				engine_log(ENG_LOG_ERR, "%s: Core number exceeds RTE_MAX_LCORE\n", __FUNCTION__);
				return -1;
			}
			lcore_h = lcore_l;
			range_tok = strpbrk(tok+1, "-{},");
			/* If next token is -, the input is a lcore range of format %d-%d */
			if (range_tok != NULL && *range_tok == '-') {
				tok = range_tok;
				sscanf(tok+1, "%d", &lcore_h);
				if (lcore_h > RTE_MAX_LCORE) {
					engine_log(ENG_LOG_ERR, "%s: Core number exceeds RTE_MAX_LCORE\n", __FUNCTION__);
					return -1;
				}
			}
			for (lcore = lcore_l; lcore <= lcore_h; lcore++) {
				if (sym_queues[lcore] == -1) {
					sym_queues[lcore] = queue;
					sym_dev_id[lcore] = vf;
					/* Setup same queue for asym operation as well,
					* will be overwritten when second queue is configuered for same core */
					asym_queues[lcore] = queue;
					asym_dev_id[lcore] = vf;
					queues_per_vf[vf]++;
				} else if (asym_dev_id[lcore] == sym_dev_id[lcore] &&
								asym_queues[lcore] == sym_queues[lcore]){
					asym_queues[lcore] = queue;
					asym_dev_id[lcore] = vf;
					queues_per_vf[vf]++;
				} else {
					engine_log(ENG_LOG_ERR,
						"%s: cptvf_queues: maximum only 2 queues per core\n", __FUNCTION__);
					return -1;
				}
				queue++;
			}
			break;

			case '}':
			/* End of one VF config */
			dev_in_use++;
			tok = strpbrk(tok+1, "{},");
			if (tok != NULL && *tok == '}') {
				/* }} marks the end of complete config */
				parsing_done = 1;
			} else if (tok == NULL || *tok != ',') {
				engine_log(ENG_LOG_ERR, "%s: cptvf_queues: Invalid Format\n", __FUNCTION__);
				return -1;
			}
			break;
		}
		if (parsing_done) break;
		if (tok == NULL) {
			engine_log(ENG_LOG_ERR, "%s: cptvf_queues: Invalid Format\n", __FUNCTION__);
			return -1;
		}
		tok = strpbrk(tok+1, "{},");
	}

	return 0;
}

/*
 * OSSL_CONF_INIT: use openssl.cnf file for configuring engine.
 * When using conf file, register engine lifecycle functions and dpdkcpt_init will be called later while processing conf file.
 */
static int dpdkcpt_basic_bind(ENGINE *e)
{
#ifdef OSSL_CONF_INIT
	if (!ENGINE_set_id(e, engine_dpdkcpt_id) ||
	    !ENGINE_set_name(e, engine_dpdkcpt_name) ||
	    !ENGINE_set_destroy_function(e, dpdkcpt_destroy) ||
	    !ENGINE_set_init_function(e, dpdkcpt_init) ||
	    !ENGINE_set_cmd_defns(e, dpdkcpt_cmd_defns) ||
	    !ENGINE_set_ctrl_function(e, dpdkcpt_ctrl) ||
	    !ENGINE_set_finish_function(e, dpdkcpt_finish)) {
		return 0;
	}
#else
	SET_ENGINE_ALG_FLAGS(e, (ENGINE_get_flags(e)|ALL_ALG_SUPPORT_MASK));
	if (!dpdkcpt_init(e)) {
		return 0;
	}
#endif
	return 1;
}

static inline int dpdkcpt_plt_init(void)
{
	uint64_t feature_flags = 0;
	char idstr[10];
	int argc, idx = -1, ret = 0;
	char cpu[3] = {0};

	sprintf(idstr, "rte%d", getpid());
	sprintf(cpu, "%2d", sched_getcpu());

	/* Initialize EAL */
	if (!dpdkcpt_eal_argc) {
		engine_log(ENG_LOG_ERR, "No EAL arguments provided\n");
		return -1;
	}
	if (!disable_eal_init) {
		ret = rte_eal_init(dpdkcpt_eal_argc, dpdkcpt_eal_argv);
		if (ret < 0 && (rte_errno !=  EALREADY)) {
			engine_log(ENG_LOG_ERR, "Invalid EAL arguments\n");
			return -1;
		}
	}
	/* Get driver id */
	cdev_id = rte_cryptodev_driver_id_get(crypto_name);
	if (cdev_id == -1) {
		engine_log(ENG_LOG_ERR,
			"Could not load Crypto PMD "
			"%s, Check if it is enabled in rte_build_config.h\n",
			crypto_name);
		return -1;
	}

	/* Gets the number of attached crypto devices for particular driver */
	nb_devs = rte_cryptodev_devices_get(crypto_name, cptdevs,
				E_DPDKCPT_MAX_CPT_DEVICES);
	if (!nb_devs) {
		engine_log(ENG_LOG_ERR, "No crypto device found\n");
		return -1;
	}
	feature_flags = get_next_crypto_dev(&idx);
	while (1) {
		if ((feature_flags & RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO) &&
		    (sym_dev_count < E_DPDKCPT_MAX_CPT_SYM_DEVICES)) {
			sym_valid_dev[sym_dev_count++] = cptdevs[idx];
			feature_flags = get_next_crypto_dev(&idx);
			if (!feature_flags)
				break;
		}
	}

	return 0;
}

static int bind_dpdkcpt(ENGINE *e)
{
	struct rte_cryptodev_config conf;
	int lcoreid;
	int ret = 0;
	int i = 0, q = 0;

	if ((zero_fd = open("/dev/zero", 0)) < 0)
		return -1;

	if ((ENGINE_get_flags(e)&ALL_ALG_SUPPORT_MASK))
		engine_log(ENG_LOG_ERR, "CPT HW Offload Configured!!!\n");
#ifndef OSSL_CONF_INIT
	ret = dpdkcpt_hw_init();
#else
	ret = dpdkcpt_plt_init();
#endif
	if (ret < 0) {
		engine_log(ENG_LOG_ERR, "Failed in platform init\n");
		return 0;
	}

	if(dpdkcpt_queue_conf != NULL &&
			process_dpdkcpt_queue_conf(dpdkcpt_queue_conf) < 0) {
		engine_log(ENG_LOG_ERR, "Failed processing cptvf_queues config\n");
		return 0;
	}

	/* Setup default queues for lcore 0 when cptvf_queues not configured */
	if (sym_dev_count > 0 && dev_in_use == 0) {
		for (lcoreid = 0; lcoreid < RTE_MAX_LCORE; lcoreid++) {
			sym_dev_id[lcoreid] = asym_dev_id[lcoreid] = -1;
			sym_queues[lcoreid] = asym_queues[lcoreid] = -1;
		}
		lcoreid = 0;
		queues_per_vf[lcoreid] = 2;
		sym_dev_id[lcoreid] = 0;
		sym_queues[lcoreid] = 0;
		asym_dev_id[lcoreid] = 0;
		asym_queues[lcoreid] = 1;
		dev_in_use = 1;
	}
	sym_dev_count = asym_dev_count = dev_in_use = MIN(sym_dev_count, dev_in_use);

	for (i = 0; i < dev_in_use; i++) {
		conf.nb_queue_pairs = queues_per_vf[i];
		conf.socket_id = rte_socket_id();
		conf.ff_disable = 0;
		if (rte_cryptodev_configure(sym_valid_dev[i], &conf) < 0)
			goto err;
	}
	if (dev_in_use > 0) {
		ret = config_sym_devs(sym_valid_dev, sym_dev_count);
		if (ret < 0) {
			engine_log(ENG_LOG_ERR, "Something went wrong in sym config\n");
			return 0;
		}

		ret = config_asym_devs(sym_valid_dev, asym_dev_count);
		if (ret < 0) {
			engine_log(ENG_LOG_ERR,
				"Something went wrong in asym config\n");
			return 0;
		}

		for (i = 0; i < dev_in_use; i++) {
			if (rte_cryptodev_start(sym_valid_dev[i]) < 0)
				goto err;
		}

		if (IS_ALG_ENABLED(e, EC)) {
			/* EC KEY method */
			default_eckey_meth = EC_KEY_get_default_method();
			dpdk_eckey_method = EC_KEY_METHOD_new(default_eckey_meth);

			EC_KEY_METHOD_set_init(dpdk_eckey_method, NULL, NULL, NULL,
					ec_key_set_group, NULL, NULL);
			EC_KEY_METHOD_get_sign(default_eckey_meth, NULL,
					&ecdsa_sign_setup, &ecdsa_sign_sig);
			EC_KEY_METHOD_set_sign(dpdk_eckey_method, ecdsa_sign,
					ecdsa_sign_setup, ecdsa_sign_sig);
			EC_KEY_METHOD_get_verify(default_eckey_meth, NULL,
					&ecdsa_verify_sig);
			EC_KEY_METHOD_set_verify(dpdk_eckey_method, ecdsa_verify,
					ecdsa_verify_sig);
			EC_KEY_METHOD_set_keygen(dpdk_eckey_method, ecdh_keygen);
			EC_KEY_METHOD_set_compute_key(dpdk_eckey_method, ecdh_compute_key);

			if (!ENGINE_set_EC(e, dpdk_eckey_method)) {
				engine_log(ENG_LOG_ERR, "Setting EC method failed");
				goto err;
			}
		}
		if (IS_ALG_ENABLED(e, RSA)) {
			/* RSA method */
			default_rsa_meth = RSA_get_default_method();

			if ((dpdk_rsa_method = RSA_meth_new("DPDK RSA method", 0)) ==
					NULL ||
					RSA_meth_set_pub_dec(dpdk_rsa_method, dpdk_rsa_pub_dec) ==
					0 ||
					RSA_meth_set_priv_enc(dpdk_rsa_method, dpdk_rsa_priv_enc) ==
					0 ||
					RSA_meth_set_pub_enc(dpdk_rsa_method, dpdk_rsa_pub_enc) ==
					0 ||
					RSA_meth_set_priv_dec(dpdk_rsa_method, dpdk_rsa_priv_dec) ==
					0) {
				engine_log(ENG_LOG_ERR, "Setting RSA operations failed");
				goto err;
			}
			/* Set ENGINE for RSA */
			if (!ENGINE_set_RSA(e, dpdk_rsa_method)) {
				engine_log(ENG_LOG_ERR, "Setting RSA method failed");
				goto err;
			}
		}
	}

	engine_log(ENG_LOG_INFO, "DPDK Pool Params: sessions=%d, mbufs=%d, sym_ops=%d, asym_ops=%d, asym_desc_cnt=%d, sym_desc_cnt=%d\n", dpdkcpt_sessions, dpdkcpt_num_mbufs, dpdkcpt_num_sym_ops, dpdkcpt_num_asym_ops, dpdkcpt_asym_qp_desc_count, dpdkcpt_sym_qp_desc_count);
	engine_log(ENG_LOG_INFO, "DPDK Pool cachesz: asym op pool=%d, asym session pool=%d, mbuf pool=%d, sym op pool=%d, sym session pool=%d\n", pool_cachesz[ASYM_OP_POOL_INDEX], pool_cachesz[ASYM_SESSION_POOL_INDEX], pool_cachesz[MBUF_POOL_INDEX], pool_cachesz[SYM_OP_POOL_INDEX], pool_cachesz[SYM_SESSION_POOL_INDEX]);
	engine_log(ENG_LOG_INFO, "CPT DEVICES AND LCORE MAP:\n");
	engine_log(ENG_LOG_INFO, "==========================\n");
	for (lcoreid = 0; lcoreid < RTE_MAX_LCORE; lcoreid++) {
		if (sym_queues[lcoreid] != -1) {
			/* Till this point, sym_dev_id and asym_dev_id arrays
			 * contain VF index rather than actual VF id */
			sym_dev_id[lcoreid] = sym_valid_dev[sym_dev_id[lcoreid]];
			asym_dev_id[lcoreid] = sym_valid_dev[asym_dev_id[lcoreid]];
			if (IS_ALG_ENABLED(e, GCM) || IS_ALG_ENABLED(e, CBC) || (IS_ALG_ENABLED(e, CPOLY)))
			  engine_log(ENG_LOG_INFO, "lcoreid: %d, symid: %d sym_queue: %d\n",
				  lcoreid, sym_dev_id[lcoreid], sym_queues[lcoreid]);
			if (IS_ALG_ENABLED(e, RSA) || IS_ALG_ENABLED(e, EC))
			  engine_log(ENG_LOG_INFO, "lcoreid: %d, asymid: %d asym_queue: %d\n",
				  lcoreid, asym_dev_id[lcoreid], asym_queues[lcoreid]);
		}
	}
	engine_log(ENG_LOG_INFO, "==========================\n");

	if (!ENGINE_set_id(e, engine_dpdkcpt_id) ||
	    !ENGINE_set_name(e, engine_dpdkcpt_name) ||
	    !ENGINE_set_ciphers(e, dpdkcpt_ciphers) ||
	    !ENGINE_set_destroy_function(e, dpdkcpt_destroy) ||
	    !ENGINE_set_finish_function(e, dpdkcpt_finish)) {
		engine_log(ENG_LOG_ERR, "DPDKCPT Engine set failed");
		rte_mempool_free(mbuf_pool);
		rte_mempool_free(crypto_sym_op_pool);
		rte_mempool_free(sym_session_pool);
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
		rte_mempool_free(sym_session_priv_pool);
#endif
		goto err;
	}
	return 1;

err:
	free_all_mempools();
	return 0;
}

/* Configure one symmetric device */
static int config_sym_devs(int *sym_valid_dev, int sym_dev_count)
{
	struct rte_cryptodev_qp_conf qp_conf;
	uint8_t socket_id = rte_socket_id();
	unsigned int lcore;
	int session_size, calc_cachesz = 0;

	/* Configure the queue pair */
	qp_conf.nb_descriptors = dpdkcpt_sym_qp_desc_count;

	calc_cachesz = MIN(dpdkcpt_pool_cache_size, CACHESZ_LIMIT(dpdkcpt_num_mbufs*sym_dev_count));
	pool_cachesz[MBUF_POOL_INDEX] = calc_cachesz;
	/* Create the mbuf pool. */
	mbuf_pool = rte_pktmbuf_pool_create(
		"cpt_mbuf_pool", dpdkcpt_num_mbufs * sym_dev_count,
		calc_cachesz, 0,
		RTE_PKTMBUF_HEADROOM + E_DPDKCPT_RTE_MBUF_CUSTOM_BUF_SIZE +
		E_DPDK_DIGEST_LEN,
		socket_id);

	if (mbuf_pool == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create cpt_mbuf pool\n");
		goto err;
	}
	calc_cachesz = MIN(dpdkcpt_pool_cache_size, CACHESZ_LIMIT(dpdkcpt_num_sym_ops*sym_dev_count));
	pool_cachesz[SYM_OP_POOL_INDEX] = calc_cachesz;

	/* Create symmetric op pool */
	crypto_sym_op_pool = rte_crypto_op_pool_create(
		"crypto_sym_op_pool", RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		dpdkcpt_num_sym_ops * sym_dev_count, calc_cachesz,
		E_DPDKCPT_AES_CBC_IV_LENGTH + sizeof(ossl_cry_op_status_t),
		socket_id);
	if (crypto_sym_op_pool == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create crypto_sym_op pool\n");
		goto err;
	}

	/* Get private session data size. */
	session_size =
		rte_cryptodev_sym_get_private_session_size(sym_valid_dev[0]);

	/* Create session mempool for the session header, with one object
	 * per session.*/
	calc_cachesz = MIN(dpdkcpt_pool_cache_size,
				CACHESZ_LIMIT(dpdkcpt_sessions*sym_dev_count));
	pool_cachesz[SYM_SESSION_POOL_INDEX] = calc_cachesz;
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	sym_session_pool = rte_cryptodev_sym_session_pool_create(
			"session_pool", dpdkcpt_sessions * sym_dev_count,
			session_size, calc_cachesz, 0, socket_id);
#else
	sym_session_pool = rte_cryptodev_sym_session_pool_create(
			"session_pool", dpdkcpt_sessions * sym_dev_count, 0,
			calc_cachesz, 0, socket_id);
#endif
	if (sym_session_pool == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create session pool\n");
		goto err;
	}

#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
	/* Create private session mempool for the private session data,
	 * with one object per session.*/
	sym_session_priv_pool =
		rte_mempool_create("session_private_pool",
		dpdkcpt_sessions * sym_dev_count,
		session_size, calc_cachesz, 0,
		NULL, NULL, NULL, NULL, socket_id, 0);
	if (sym_session_priv_pool == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create session private pool\n");
		goto err;
	}

	qp_conf.mp_session_private = sym_session_priv_pool;
#endif
	qp_conf.mp_session = sym_session_pool;

	/* Multiple lcores sharing same queue is not supported
	 * Thus, sym_queues[lcore] has unique queues */
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		if (sym_queues[lcore] != -1) {
			if (rte_cryptodev_queue_pair_setup(sym_valid_dev[sym_dev_id[lcore]],
					sym_queues[lcore], &qp_conf, socket_id) < 0)
				goto err;
		}
	}
	return 1;

err:
	free_all_mempools();
	return -1;
}

/* Configure one asymmetric device */
static int config_asym_devs(int *asym_valid_dev, int asym_dev_count)
{
	struct rte_cryptodev_qp_conf asym_qp_conf;
	struct rte_cryptodev_asym_capability_idx idx;
	uint8_t socket_id = rte_socket_id();
	int asym_session_size, shared_queue, calc_cachesz = 0;
	unsigned int lcore;

	/* Configure queue pair*/
	asym_qp_conf.nb_descriptors = dpdkcpt_asym_qp_desc_count;

	/* Get asym dev capability */
	idx.type = RTE_CRYPTO_ASYM_XFORM_RSA;
	asym_rsa_xform_cap = rte_cryptodev_asym_capability_get(asym_valid_dev[0],
			&idx);
	calc_cachesz = MIN(dpdkcpt_pool_cache_size, CACHESZ_LIMIT(dpdkcpt_num_asym_ops*asym_dev_count));
	pool_cachesz[ASYM_OP_POOL_INDEX] = calc_cachesz;

	/* Create asymmetric op pool */
	crypto_asym_op_pool = rte_crypto_op_pool_create(
		"CRYPTO_ASYM_OP_POOL", RTE_CRYPTO_OP_TYPE_ASYMMETRIC,
		dpdkcpt_num_asym_ops * asym_dev_count, calc_cachesz,
		/* extra sizeof(void *) to store async job ctx. */
		sizeof(struct rte_crypto_asym_xform) + sizeof(void *),
		socket_id);
	if (crypto_asym_op_pool == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create crypto_asym_op pool\n");
		goto err;
	}

	asym_qp_conf.mp_session = asym_session_pool;
#if RTE_VERSION < RTE_VERSION_NUM(22, 11, 0, 99)
	asym_qp_conf.mp_session_private = asym_session_pool;
#endif

	/* Same queue can be shared for sym and asym operations
	 * Thus, skip queues that are already configured for sym */
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
		shared_queue = (asym_dev_id[lcore] == sym_dev_id[lcore] &&
				asym_queues[lcore] == sym_queues[lcore]);
		if (asym_queues[lcore] != -1 && !shared_queue) {
			if (rte_cryptodev_queue_pair_setup(sym_valid_dev[asym_dev_id[lcore]],
					asym_queues[lcore], &asym_qp_conf, socket_id) < 0)
				goto err;
		}
	}
	/* Get private session data size. */
	asym_session_size = RTE_MAX(
		rte_cryptodev_asym_get_private_session_size(asym_valid_dev[0]),
		rte_cryptodev_asym_get_header_session_size());

	/* Create session mempool, with two objects per session,
	 * one for the session header and another one for the
	 * private session data for the crypto device.*/
	calc_cachesz = MIN(dpdkcpt_pool_cache_size, CACHESZ_LIMIT(dpdkcpt_sessions * 2 * asym_dev_count));
	pool_cachesz[ASYM_SESSION_POOL_INDEX] = calc_cachesz;
#if RTE_VERSION >= RTE_VERSION_NUM(22, 11, 0, 99)
	asym_session_pool =
		rte_cryptodev_asym_session_pool_create("asym_session_pool",
				dpdkcpt_sessions * 2 * asym_dev_count,
				calc_cachesz, 0, socket_id);
#else
	asym_session_pool = rte_mempool_create("asym_session_pool",
			    dpdkcpt_sessions * 2 * asym_dev_count,
			    asym_session_size, calc_cachesz,
			    0, NULL, NULL, NULL, NULL, socket_id, 0);
#endif
	if (asym_session_pool == NULL) {
		engine_log(ENG_LOG_ERR, "Failed to create asym_session pool\n");
		goto err;
	}

	return 1;

err:
	free_all_mempools();
	return -1;
}

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
	if (id && (strcmp(id, engine_dpdkcpt_id) != 0))
		return 0;
	if (!dpdkcpt_basic_bind(e)) {
		engine_log(ENG_LOG_ERR, "Failed to set basic ENGINE_set_xxx properties\n");
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#endif

void ENGINE_load_dpdkcpt(void)
{
	ENGINE *e = ENGINE_new();
	if (e == NULL)
		return;
	if (!dpdkcpt_basic_bind(e)) {
		ENGINE_free(e);
		engine_log(ENG_LOG_ERR, "Failed to set basic ENGINE_set_xxx properties\n");
		return;
	}
	ENGINE_add(e);
	ENGINE_free(e);
	ERR_clear_error();
}

static int dpdkcpt_init(ENGINE *e)
{
	if (e == NULL) {
		engine_log(ENG_LOG_ERR, "Engine init filure\n");
		return 0;
	}
	if (!bind_dpdkcpt(e)) {
		return 0;
	}
#ifdef E_DPDK_MEM_FUNC
	CRYPTO_set_mem_functions(dpdkcpt_malloc, dpdkcpt_realloc, dpdkcpt_free);
#endif
	return 1;
}

static int dpdkcpt_finish(ENGINE *e)
{
	if (e == NULL) {
		engine_log(ENG_LOG_ERR, "Engine finish failure\n");
		return 0;
	}
	return 1;
}

static int dpdkcpt_ctrl(ENGINE *e, int cmd, long numval, void * ptrval, void (*cb) (void))
{
	char * sp = NULL, *alg = NULL, *value = NULL;
	int engine_flags = 0;
	uint32_t user_val = 0;
	if (e == NULL) {
		engine_log(ENG_LOG_ERR, "%s: Invalid Engine\n", __FUNCTION__);
		return 0;
	}
	switch(cmd) {
	case DPDKCPT_CTRL_CMD_EAL_PARAMS:
		engine_log(ENG_LOG_ERR, "eal params: '%s'\n", (char *)ptrval);

		/* This is freed implicitly on process exit */
		dpdkcpt_eal_params[dpdkcpt_eal_params_cnt] = OPENSSL_strdup(ptrval);
		dpdkcpt_eal_argv[dpdkcpt_eal_argc] =
			strtok_r(dpdkcpt_eal_params[dpdkcpt_eal_params_cnt], " ", &sp);
		while(dpdkcpt_eal_argv[dpdkcpt_eal_argc])
		{
			dpdkcpt_eal_argc++;
			dpdkcpt_eal_argv[dpdkcpt_eal_argc] = strtok_r(NULL, " ", &sp);
		}
		dpdkcpt_eal_params_cnt++;
		break;
	case DPDKCPT_CTRL_CMD_EAL_INIT:
		if (strcmp(ptrval, "no") == 0)
		{
			disable_eal_init = 1;
		}
		break;
	case DPDKCPT_CTRL_CMD_EAL_PID_IN_FP:
		if (strcmp(ptrval, "yes") == 0)
		{
			char idstr[50] = {0};
			snprintf(idstr, sizeof(idstr), "--file-prefix=e_dpdkcpt%d", getpid());
			engine_log(ENG_LOG_ERR, "eal params updated: '%s'\n", (char *)idstr);

			/* This is freed implicitly on process exit */
			dpdkcpt_eal_argv[dpdkcpt_eal_argc++] = OPENSSL_strdup(idstr);
			dpdkcpt_eal_argv[dpdkcpt_eal_argc] = NULL;
		}
		break;
	case DPDKCPT_CTRL_CMD_EAL_CORE_BY_CPU:
		if (strcmp(ptrval, "yes") == 0)
		{
			char cpu[15] = {0};
			snprintf(cpu, sizeof(cpu), "--lcores=0@%2d", sched_getcpu());
			engine_log(ENG_LOG_ERR, "eal params updated: '%s'\n", (char *)cpu);

			/* This is freed implicitly on process exit */
			dpdkcpt_eal_argv[dpdkcpt_eal_argc++] = OPENSSL_strdup(cpu);
			dpdkcpt_eal_argv[dpdkcpt_eal_argc] = NULL;
		}
		break;
	case DPDKCPT_CTRL_CMD_EAL_CPTVF_BY_CPU:
		{
		char cptvf[20] = {0};

		/*
		 * cptvf DBDF will be of the form DDDD:BB:dd.f.
		 * DDDD:BB: comes from ptrval
		 * dd.f comes from sched_getcpu()
		 * -w is depcrecated, use -a (allow) for PCI
		 */
		snprintf(cptvf, sizeof(cptvf), "-a%.8s%02d.%d", (char *)ptrval,
			((sched_getcpu() + 1) >> 3) & 0x7, (sched_getcpu() + 1) & 0x7);
		engine_log(ENG_LOG_ERR, "eal params updated: '%s'\n", (char *)cptvf);

		/* This is freed implicitly on process exit */
		dpdkcpt_eal_argv[dpdkcpt_eal_argc++] = OPENSSL_strdup(cptvf);
		dpdkcpt_eal_argv[dpdkcpt_eal_argc] = NULL;
		break;
		}
	case DPDKCPT_CTRL_CMD_CRYPTO_DRIVER:
		if (strncmp(ptrval, "crypto_openssl", 14) == 0)
		{
			char vdevstr[50] = {0};
			snprintf(vdevstr, sizeof(vdevstr),
						"--vdev=%s,max_nb_queue_pairs=64", (char *)ptrval);
			engine_log(ENG_LOG_ERR, "eal params updated: '%s'\n", (char *)vdevstr);

			/* This is freed implicitly on process exit */
			dpdkcpt_eal_argv[dpdkcpt_eal_argc++] = OPENSSL_strdup(vdevstr);
			dpdkcpt_eal_argv[dpdkcpt_eal_argc] = NULL;
		}
		crypto_name = OPENSSL_strdup(ptrval);
		break;
	case DPDKCPT_CTRL_CMD_CPTVF_QUEUES:
		dpdkcpt_queue_conf = OPENSSL_strdup(ptrval);
		break;
	case DPDKCPT_CTRL_CMD_ENG_LOG_LEVEL:
		if (strcmp(ptrval, "ENG_LOG_EMERG") == 0) {
			engine_level = 1;
		}
		else if (strcmp(ptrval, "ENG_LOG_ERR") == 0) {
			engine_level = 2;
		}
		else if (strcmp(ptrval, "ENG_LOG_INFO") == 0 ) {
			engine_level = 3;
		}
		break;
	case DPDKCPT_CTRL_CMD_ENG_LOG_FILE:
		log_fp = fopen(ptrval, "a");
			if(!log_fp) {
				engine_log(ENG_LOG_ERR, "Can't open file with Error Number", errno);
			}
		break;
	case DPDKCPT_CTRL_CMD_ENGINE_ALG_SUPPORT:
		engine_flags =  ENGINE_get_flags(e);
		dpdkcpt_alg_params =  OPENSSL_strdup(ptrval);
		alg = strtok_r(dpdkcpt_alg_params, ":", &sp);
		engine_log(ENG_LOG_ERR, "Enabled ");
		while (alg != NULL) {
			if (strcmp(alg, "NONE") == 0) {
				engine_log(ENG_LOG_ERR, "None of the operations ");
			} else if (strcmp(alg, "ALL") == 0) {
				engine_log(ENG_LOG_ERR, "Both Asymmetric and Symmetric Operations ");
				engine_flags|=ALL_ALG_SUPPORT_MASK;
			} else if (strcmp(alg, "ASYM") == 0) {
				engine_log(ENG_LOG_ERR, "Asymmetric Operations Only ");
				engine_flags|=ASYM_ALG_SUPPORT_MASK;
			} else if (strcmp(alg, "SYM") == 0) {
				engine_log(ENG_LOG_ERR, "Symmetric Operations Only ");
				engine_flags|=SYM_ALG_SUPPORT_MASK;
			} else if (strcmp(alg, "RSA") == 0) {
				engine_log(ENG_LOG_ERR, "RSA ");
				engine_flags|=ALG_MASK(RSA);
			} else if (strcmp(alg, "EC") == 0) {
				engine_log(ENG_LOG_ERR, "ECDSA ECDH ");
				engine_flags|=ALG_MASK(EC);
			} else if (strcmp(alg, "GCM") == 0) {
				engine_log(ENG_LOG_ERR, "AES-GCM ");
				engine_flags|=ALG_MASK(GCM);
			} else if (strcmp(alg, "CBC") == 0) {
				engine_log(ENG_LOG_ERR, "AES-CBC ");
				engine_flags|=ALG_MASK(CBC);
			} else if (strcmp(alg, "CPOLY") == 0) {
				engine_log(ENG_LOG_ERR, "CHACHA20-POLY1305 ");
				engine_flags|=ALG_MASK(CPOLY);
			} else {
				engine_log(ENG_LOG_ERR, "ALL operations since value configured is invalid ");
				engine_flags|=ALL_ALG_SUPPORT_MASK;
			}
			alg = strtok_r(NULL, ":", &sp);
		}
		//printf("in engine !!!\n");
		SET_ENGINE_ALG_FLAGS(e, engine_flags);
		break;
	case DPDKCPT_CTRL_CMD_DPDK_QP_CONF_PARAMS:
		if ((value = strstr(ptrval, "pool_cachesz=")) !=NULL) {
			dpdkcpt_pool_cache_size =
				atoi(value+strlen("pool_cachesz="));
			user_val = dpdkcpt_pool_cache_size;
			dpdkcpt_pool_cache_size =
				CHECK_LIMIT_AND_ASSIGN(dpdkcpt_pool_cache_size,
						E_DPDKCPT_MAX_POOL_CACHE_SIZE,
						E_DPDKCPT_MIN_POOL_CACHE_SIZE);
			if (user_val != dpdkcpt_pool_cache_size)
				engine_log(ENG_LOG_ERR, "Configured pool cachesz value "
						"is outside range limit. "
						"Setting value as %d\n",
						dpdkcpt_pool_cache_size);
		}
		if ((value = strstr(ptrval, "sessions=")) != NULL) {
			dpdkcpt_sessions = atoi(value+strlen("sessions="));
			user_val = dpdkcpt_sessions;
			dpdkcpt_sessions =
				CHECK_LIMIT_AND_ASSIGN(dpdkcpt_sessions,
							E_DPDKCPT_MAX_SESSIONS,
							E_DPDKCPT_MIN_SESSIONS);
			if (user_val != dpdkcpt_sessions)
				engine_log(ENG_LOG_ERR,"Configured sessions value is "
					       "outside range limit. Setting "
					       " value as %d\n",
					       dpdkcpt_sessions);
		}
		if ((value = strstr(ptrval, "mbufs=")) !=NULL) {
			dpdkcpt_num_mbufs = atoi(value+strlen("mbufs="));
			user_val = dpdkcpt_num_mbufs;
			dpdkcpt_num_mbufs =
				CHECK_LIMIT_AND_ASSIGN(dpdkcpt_num_mbufs,
							E_DPDKCPT_MAX_MBUFS,
							E_DPDKCPT_MIN_MBUFS);
			if (user_val != dpdkcpt_num_mbufs)
				engine_log(ENG_LOG_ERR, "Configured mbufs value is "
						"outside range limit. Setting"
						" value as %d\n",
						dpdkcpt_num_mbufs);
		}
		if ((value = strstr(ptrval, "sym_ops=")) !=NULL) {
			dpdkcpt_num_sym_ops = atoi(value+strlen("sym_ops="));
			user_val = dpdkcpt_num_sym_ops;
			dpdkcpt_num_sym_ops =
				CHECK_LIMIT_AND_ASSIGN(dpdkcpt_num_sym_ops,
						       E_DPDKCPT_MAX_SYM_OPS,
						       E_DPDKCPT_MIN_SYM_OPS);
			if (user_val != dpdkcpt_num_sym_ops)
				engine_log(ENG_LOG_ERR, "Configured sym_ops value is "
						"outside range limit. Setting "
						"value as %d\n",
						dpdkcpt_num_sym_ops);
		}
		if ((value = strstr(ptrval, "asym_ops=")) !=NULL) {
			dpdkcpt_num_asym_ops = atoi(value+strlen("asym_ops="));
			user_val = dpdkcpt_num_asym_ops;
			dpdkcpt_num_asym_ops =
				CHECK_LIMIT_AND_ASSIGN(dpdkcpt_num_asym_ops,
						       E_DPDKCPT_MAX_ASYM_OPS,
						       E_DPDKCPT_MIN_ASYM_OPS);
			if (user_val != dpdkcpt_num_asym_ops)
				engine_log(ENG_LOG_ERR, "Configured asym ops value is "
						"outside range limit. Setting"
						" value as %d\n",
						dpdkcpt_num_asym_ops);
		}
		if ((value = strstr(ptrval, "asym_desc_cnt=")) !=NULL) {
			dpdkcpt_asym_qp_desc_count =
				atoi(value+strlen("asym_desc_cnt="));
			user_val = dpdkcpt_asym_qp_desc_count;
			dpdkcpt_asym_qp_desc_count =
				CHECK_LIMIT_AND_ASSIGN(dpdkcpt_asym_qp_desc_count,
						E_DPDKCPT_MAX_ASYM_QP_DESC_COUNT,
						E_DPDKCPT_MIN_ASYM_QP_DESC_COUNT);
			if (user_val != dpdkcpt_asym_qp_desc_count)
				engine_log(ENG_LOG_ERR, "Configured asym qp desc count "
						"is outside range limit. "
						"Setting value as %d\n",
						dpdkcpt_asym_qp_desc_count);
		}
		if ((value = strstr(ptrval, " sym_desc_cnt=")) !=NULL) {
			dpdkcpt_sym_qp_desc_count =
				atoi(value+strlen(" sym_desc_cnt="));
			user_val = dpdkcpt_sym_qp_desc_count;
			dpdkcpt_sym_qp_desc_count =
				CHECK_LIMIT_AND_ASSIGN(dpdkcpt_sym_qp_desc_count,
						E_DPDKCPT_MAX_SYM_QP_DESC_COUNT,
						E_DPDKCPT_MIN_SYM_QP_DESC_COUNT);
			if (user_val != dpdkcpt_sym_qp_desc_count)
				engine_log(ENG_LOG_ERR, "Configured sym qp desc count "
						"is outside range limit. "
						"Setting value as %d\n",
						dpdkcpt_sym_qp_desc_count);
		}
		break;
	case DPDKCPT_CTRL_CMD_HW_OFFLOAD_THRESH_PKTSZ:
		hw_offload_pktsz_thresh = (int)numval;
		hw_offload_pktsz_thresh =
			CHECK_LIMIT_AND_ASSIGN(hw_offload_pktsz_thresh,
						HW_OFFLOAD_PKT_SZ_THRESHOLD_MAX,
						HW_OFFLOAD_PKT_SZ_THRESHOLD_MIN);
		engine_log(ENG_LOG_ERR, "HW Offload threshold pktsz: %d\n",
				hw_offload_pktsz_thresh);
		break;
	case DPDKCPT_CTRL_CMD_POLL:
		{
	        unsigned int lcoreid = rte_lcore_id();
		    dpdkcpt_poll(asym_dev_id[lcoreid], asym_queues[lcoreid]);
		    dpdkcpt_sym_poll(sym_dev_id[lcoreid], sym_queues[lcoreid]);
		    break;
        }
	case DPDKCPT_GET_NUM_REQUESTS_IN_FLIGHT:
		if (numval == GET_NUM_ASYM_REQUESTS_IN_FLIGHT) {
			*(int **)ptrval = &cpt_num_asym_requests_in_flight;
		} else if (numval == GET_NUM_KDF_REQUESTS_IN_FLIGHT) {
			*(int **)ptrval = &cpt_num_kdf_requests_in_flight;
		} else if (numval == GET_NUM_CIPHER_PIPELINE_REQUESTS_IN_FLIGHT) {
			*(int **)ptrval = &cpt_num_cipher_pipeline_requests_in_flight;
		} else if (numval == GET_NUM_ASYM_MB_ITEMS_IN_QUEUE) {
			*(int **)ptrval = &cpt_num_asym_mb_items_in_queue;
		} else if (numval == GET_NUM_KDF_MB_ITEMS_IN_QUEUE) {
			*(int **)ptrval = &cpt_num_kdf_mb_items_in_queue;
		} else if (numval == GET_NUM_SYM_MB_ITEMS_IN_QUEUE) {
			*(int **)ptrval = &cpt_num_cipher_mb_items_in_queue;
		} else
			engine_log(ENG_LOG_ERR, "Invalid GET_NUM_REQUESTS_IN_FLIGHT parameter\n");
        break;
	default:
		break;
	}
	return 1;
}

static int dpdkcpt_destroy(ENGINE *e)
{
	if (e == NULL) {
		engine_log(ENG_LOG_ERR, "Engine destroy failure\n");
		fclose(log_fp);
		return 0;
	}
	free_all_mempools();
	return 1;
}

static int dpdkcpt_cap_ciphers(const int **nids, ENGINE *e)
{
	int *cipher_nids, num, i = 0;
	struct rte_cryptodev_sym_capability_idx idx;
	struct rte_cryptodev_symmetric_capability *cap;

	num = (sizeof(dpdkcpt_cipher_nids) -1) /
			sizeof(dpdkcpt_cipher_nids[0]);
	cipher_nids = malloc(sizeof(int) * num);
	if (IS_ALG_ENABLED(e, CPOLY)) {
		idx.type = RTE_CRYPTO_SYM_XFORM_AEAD;
		idx.algo.aead = RTE_CRYPTO_AEAD_CHACHA20_POLY1305;

		cap = rte_cryptodev_sym_capability_get(0, &idx);
		if (cap != NULL) {
			cipher_nids[i++] = NID_chacha20_poly1305;
			cap = NULL;
		}
	}

	if (IS_ALG_ENABLED(e, GCM)) {
		idx.type = RTE_CRYPTO_SYM_XFORM_AEAD;
		idx.algo.aead = RTE_CRYPTO_AEAD_AES_GCM;
		cap = rte_cryptodev_sym_capability_get(0, &idx);
		if (cap != NULL) {
			cipher_nids[i++] = NID_aes_128_gcm;
			cipher_nids[i++] = NID_aes_256_gcm;
			cap = NULL;
		}
	}

	if (IS_ALG_ENABLED(e, CBC)) {
		idx.type = RTE_CRYPTO_SYM_XFORM_CIPHER;
		idx.algo.cipher = RTE_CRYPTO_CIPHER_AES_CBC;
		cap = rte_cryptodev_sym_capability_get(0, &idx);
		if (cap != NULL) {
			cipher_nids[i++] = NID_aes_128_cbc;
			cipher_nids[i++] = NID_aes_256_cbc;
			cap = NULL;

			idx.type = RTE_CRYPTO_SYM_XFORM_AUTH;
			idx.algo.cipher = RTE_CRYPTO_AUTH_SHA1_HMAC;
			cap = rte_cryptodev_sym_capability_get(0, &idx);
			if (cap != NULL) {
				cipher_nids[i++] = NID_aes_128_cbc_hmac_sha1;
				cipher_nids[i++] = NID_aes_256_cbc_hmac_sha1;
			}
		}
	}
	cipher_nids[i] = 0;
	*nids = cipher_nids;

	return i;
}

static int dpdkcpt_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
			   const int **nids, int nid)
{
	int ok = 1, num = 0;
	(void)e;

	if (cipher == NULL) {
		/* We are returning a list of supported nids */
		num = dpdkcpt_cap_ciphers(nids, e);
		return num;
	}

	/* We are being asked for a specific cipher */
	switch (nid) {
	case NID_aes_128_cbc:
		*cipher = dpdkcpt_aes_128_cbc();
		break;
	case NID_aes_256_cbc:
		*cipher = dpdkcpt_aes_256_cbc();
		break;
	case NID_aes_128_gcm:
		*cipher = dpdkcpt_aes_128_gcm();
		break;
	case NID_aes_256_gcm:
		*cipher = dpdkcpt_aes_256_gcm();
		break;
	case NID_aes_128_cbc_hmac_sha1:
		*cipher = dpdkcpt_aes_128_cbc_hmac_sha1();
		break;
	case NID_aes_256_cbc_hmac_sha1:
		*cipher = dpdkcpt_aes_256_cbc_hmac_sha1();
		break;
	case NID_chacha20_poly1305:
		*cipher = EVP_dpdkcpt_chacha20_poly1305();
		break;
	default:
		ok = 0;
		*cipher = NULL;
		break;
	}
	return ok;
}

static int dpdkcpt_poll(uint8_t dev_id, uint16_t qp_id)
{
	int (*callback)(void *arg);
        void *args;
	uint32_t op_size = __rte_crypto_op_get_priv_data_size(crypto_asym_op_pool);
	struct rte_crypto_asym_xform *rsa_xform = NULL;
	ASYNC_WAIT_CTX **wctx_p = NULL;
	struct rte_crypto_op *result_op[MAX_DEQUEUE_OPS];

	uint16_t nb_ops = rte_cryptodev_dequeue_burst(dev_id, qp_id, result_op,
							 MAX_DEQUEUE_OPS);

	for (uint16_t i = 0; i < nb_ops; i++) {
		struct rte_crypto_op *cry_op = result_op[i];
		rsa_xform = __rte_crypto_op_get_priv_data(cry_op, op_size);
		wctx_p = (ASYNC_WAIT_CTX **) rsa_xform + 1;
		if(ASYNC_WAIT_CTX_get_callback(*wctx_p, &callback, &args))
			(*callback)(args);
	}
}

static int dpdkcpt_sym_poll(uint8_t dev_id, uint16_t qp_id)
{
	int (*callback)(void *arg);
	void *args;
	ASYNC_WAIT_CTX *wctx_p = NULL;
	struct rte_crypto_op *result_op[MAX_DEQUEUE_OPS];
	ossl_cry_op_status_t *new_st_ptr[E_DPDKCPT_NUM_DEQUEUED_OPS];
	ossl_cry_op_status_t current_job;
	int i, j, k, ret = 0;
	uint16_t num_dequeued_ops = 0;
	async_pipe_job_t pipe_asyncjobs[MAX_PIPE_JOBS];
	uint8_t present = 0;
	uint8_t pipe_job_qsz = 0;

	j = 0;
	do {
		num_dequeued_ops = rte_cryptodev_dequeue_burst(
				dev_id, qp_id,
				&result_op[0],
				E_DPDKCPT_NUM_DEQUEUED_OPS);
		/* Check the status of dequeued operations */
		for (i = 0; i < num_dequeued_ops; i++) {
			new_st_ptr[i] = rte_crypto_op_ctod_offset(result_op[i],
					ossl_cry_op_status_t *, E_DPDKCPT_COP_METADATA_OFF);
			new_st_ptr[i]->is_complete = 1;

			/* Check if operation was processed successfully */
			if (result_op[i]->status != RTE_CRYPTO_OP_STATUS_SUCCESS)
				new_st_ptr[i]->is_successful = 0;
			else {
				new_st_ptr[i]->is_successful = 1;
				if(new_st_ptr[i]->wctx_p)
				    check_for_job_completion(NULL, new_st_ptr[i]->wctx_p,
						  new_st_ptr[i]->numpipes, &pipe_job_qsz,
						  &pipe_asyncjobs[0]);
			}
		}
	} while (pipe_job_qsz>0);
}
