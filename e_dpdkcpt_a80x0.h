/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#define E_DPDKCPT_NUM_ARGS		10
#define E_DPDKCPT_NUM_PER_BUS		8
#define E_DPDKCPT_MAX_CPT_SYM_DEVICES	48
#define E_DPDKCPT_MAX_CPT_ASYM_DEVICES	24

#define E_DPDKCPT_MAX_CPT_DEVICES	\
	(E_DPDKCPT_MAX_CPT_SYM_DEVICES + E_DPDKCPT_MAX_CPT_ASYM_DEVICES)

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

uint8_t cptdevs[E_DPDKCPT_MAX_CPT_DEVICES];
int sym_valid_dev[E_DPDKCPT_MAX_CPT_SYM_DEVICES];
int asym_valid_dev[E_DPDKCPT_MAX_CPT_ASYM_DEVICES];

int sym_dev_count = 0, asym_dev_count = 0;
int cdev_id, nb_devs;

const char *crypto_name = "crypto_mvsam";

static inline uint64_t get_next_crypto_dev(int *dev_id)
{
	struct rte_cryptodev_info info;

	while ((++(*dev_id)) < nb_devs) {
		rte_cryptodev_info_get(cptdevs[*dev_id], &info);
		/* Check if device belongs to respective driver,
		 * if not proceed with new device, though this
		 * shouldn't happen
		 */
		if (info.driver_id == cdev_id)
			return info.feature_flags;
	}
	return 0ULL;
}

static inline int dpdkcpt_hw_init(void)
{
	uint64_t feature_flags = 0;
	char idstr[10];
	int argc, idx = -1, ret = 0;

	sprintf(idstr, "rte%d", getpid());

	char *argv[E_DPDKCPT_NUM_ARGS] = {
		"DPDK",	"--file-prefix",
		idstr,	"--socket-mem=500", /* 500MB per process */
		"--vdev",	crypto_name,
		"-d",	"librte_mempool_ring.so",
		"-d",	"librte_pmd_mvsam_crypto.so"
	};

	argc = E_DPDKCPT_NUM_ARGS;
	/* Initialize EAL */
	ret = rte_eal_init(argc, (char **)argv);
	if (ret < 0 && (rte_errno !=  EALREADY)) {
		fprintf(stderr, "Invalid EAL arguments\n");
		return -1;
	}
	/* Get driver id */
	cdev_id = rte_cryptodev_driver_id_get(crypto_name);
	if (cdev_id == -1) {
		fprintf(stderr,
			"CPT PMD must be loaded. Check if "
			"%s is enabled.\n",
			"CONFIG_RTE_LIBRTE_PMD_MVSAM_CRYPTO");
		return -1;
	}

	/* Gets the number of attached crypto devices for particular driver */
	nb_devs = rte_cryptodev_devices_get(crypto_name, cptdevs,
				E_DPDKCPT_MAX_CPT_DEVICES);
	if (!nb_devs) {
		fprintf(stderr, "No crypto device found\n");
		return -1;
	}
	feature_flags = get_next_crypto_dev(&idx);
	while (1) {
		if (sym_dev_count < E_DPDKCPT_MAX_CPT_SYM_DEVICES) {
			sym_valid_dev[sym_dev_count++] = cptdevs[idx];
			feature_flags = get_next_crypto_dev(&idx);
			if (!feature_flags)
				break;
		}
		if ((feature_flags & RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO) &&
			(asym_dev_count < E_DPDKCPT_MAX_CPT_ASYM_DEVICES)) {
			asym_valid_dev[asym_dev_count++] = cptdevs[idx];
			feature_flags = get_next_crypto_dev(&idx);
			if (!feature_flags)
				break;
		}
	}

	return 0;
}
