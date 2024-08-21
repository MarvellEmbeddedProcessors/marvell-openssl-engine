/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <rte_common.h>
#include <rte_version.h>

#define E_DEV_DOMAIN			2
#define E_DPDKCPT_NUM_ARGS		10
#define E_DPDKCPT_NUM_CORES		24
#define E_DPDKCPT_NUM_PER_BUS		8
#define E_DPDKCPT_MAX_CPT_SYM_DEVICES	48
#define E_DPDKCPT_MAX_CPT_ASYM_DEVICES	24
#define E_DPDKCPT_MAX_CPT_DEVICES	\
	(E_DPDKCPT_MAX_CPT_SYM_DEVICES + E_DPDKCPT_MAX_CPT_ASYM_DEVICES)
#define DEF_DEV_BUS			"10"

#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"

uint8_t cptdevs[E_DPDKCPT_MAX_CPT_DEVICES];
int sym_valid_dev[E_DPDKCPT_MAX_CPT_SYM_DEVICES];
int asym_valid_dev[E_DPDKCPT_MAX_CPT_ASYM_DEVICES];

int sym_dev_count = 0, asym_dev_count = 0;
unsigned int dev_in_use = 0;
int cdev_id, nb_devs;

const char *crypto_name;

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
	char devstr[20], idstr[10];
	int argc, idx = -1, ret = 0;
	char cpu[5] = {0};
	int cpuquot, cpurem;
	char *bus = getenv("OTX2_BUS");

	sprintf(idstr, "rte%d", getpid());
	sprintf(cpu, "0@%2d", sched_getcpu());

	cpuquot = (unsigned short)(sched_getcpu() + 1) / E_DPDKCPT_NUM_PER_BUS;
	cpurem = (unsigned short)(sched_getcpu() + 1)  % E_DPDKCPT_NUM_PER_BUS;

	if (!bus) {
		fprintf(stderr, " OTX2 BUS slot not defined. Using default\n");
		bus = DEF_DEV_BUS;
	}

	crypto_name = getenv("CRYPTO_DRIVER");
	if (!crypto_name) {
		fprintf(stderr, " CRYPTO DRIVER name not defined. Using default (crypto_cn10k)\n");
		crypto_name = "crypto_cn10k";
	}

	/* Symmetric engine */
	sprintf(devstr, "%04d:%s:0%d.%d", E_DEV_DOMAIN, bus, cpuquot, cpurem);

	char *argv[E_DPDKCPT_NUM_ARGS] = {
		"DPDK",	"--file-prefix",
		idstr,	"--socket-mem=500", /* 500MB per process */
		"--lcores",	cpu,
#if RTE_VERSION >= RTE_VERSION_NUM(20, 11, 0, 0)
		"-a",	devstr,
#else
		"-w",	devstr,
#endif
		"-d",	"librte_mempool_ring.so"
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
			"CONFIG_RTE_LIBRTE_PMD_OCTEONTX2_CRYPTO");
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

