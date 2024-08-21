/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#include <stdint.h>

#include <rte_mbuf.h>

#include "e_dpdkcpt.h"
#include "e_dpdkcpt_malloc.h"

void *dpdkcpt_malloc(size_t len, const char *file, int line)
{
	struct rte_mbuf *mbuf_ptr = NULL;
	void *data_ptr = NULL;

	(void)file, (void)line;
	mbuf_ptr = rte_pktmbuf_alloc(mbuf_pool);
	if (mbuf_ptr == NULL) {
		engine_log(ENG_LOG_ERR,
			"Failed to create a mbuf\n File : %s Line : %d\n", file,
			line);
		return NULL;
	}
	data_ptr = rte_pktmbuf_append(mbuf_ptr, len + E_DPDK_DIGEST_LEN);
	if (data_ptr == NULL)
		return NULL;
	*((uint64_t *)data_ptr - 1) = 0xDEADBEEF;
	return data_ptr;
}

void *dpdkcpt_realloc(void *ptr, size_t len, const char *file, int line)
{
	struct rte_mbuf *mbuf_ptr = NULL;
	uint64_t *data_ptr = NULL;
	(void)file, (void)line;

	if (ptr == NULL)
		return dpdkcpt_malloc(len, file, line);

	if (len == 0) {
		dpdkcpt_free(ptr, file, line);
		return NULL;
	}
	data_ptr = (uint64_t *)ptr - 1;
	if (*data_ptr == 0xDEADBEEF) {
		mbuf_ptr =
			(struct rte_mbuf *)((char *)ptr - RTE_PKTMBUF_HEADROOM -
					    sizeof(struct rte_mbuf));
		if (mbuf_ptr == NULL) {
			engine_log(ENG_LOG_ERR, "Failed to get mbuf pointer\n");
			return NULL;
		}
		if (rte_pktmbuf_append(mbuf_ptr, len) == NULL)
			return NULL;
		/* get databuf pointer pointing to start of pkt. */
		return rte_pktmbuf_mtod(mbuf_ptr, void *);
	} else {
		data_ptr = realloc(ptr, len);
		return data_ptr;
	}
}

void dpdkcpt_free(void *ptr, const char *file, int line)
{
	struct rte_mbuf *mbuf_ptr = NULL;
	uint64_t *data_ptr = NULL;

	(void)file, (void)line;
	if (ptr != NULL) {
		data_ptr = (uint64_t *)ptr - 1;
		if (*data_ptr == 0xDEADBEEF) {
			mbuf_ptr = (struct rte_mbuf *)((char *)ptr -
						       RTE_PKTMBUF_HEADROOM -
						       sizeof(struct rte_mbuf));
			/* With the changes for TCP Zero copy, this buffer
			 * could be part of an mbuf chain, but not the head.
			 * So changing to segment free.
			 */
			rte_pktmbuf_free_seg(mbuf_ptr);
		} else {
			free(ptr);
		}
	}
}
