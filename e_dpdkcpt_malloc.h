/* SPDX-License-Identifier: Marvell-MIT
 * Copyright (c) 2024 Marvell.
 */

#ifndef _E_DPDKCPT_MALLOC_H
#define _E_DPDKCPT_MALLOC_H

/* define E_DPDK_MEM_FUNC to overload openssl's malloc, realloc, and free */
/* #define E_DPDK_MEM_FUNC */

/* Engine Memory Function */
void *dpdkcpt_malloc(size_t len, const char *file, int line);
void *dpdkcpt_realloc(void *ptr, size_t len, const char *file, int line);
void dpdkcpt_free(void *ptr, const char *file, int line);

#endif /* _E_DPDKCPT_MEMORY_H */
