/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * A simple MAC thread for one instance on the nRF91 port (CONFIG_TDMA_NRF_RUNNER).
 *
 * The thread owns one struct tdma_mac and its storage: it takes the port's
 * events (tdma_nrf_msg_get()), hands them to the MAC (tdma_nrf_dispatch()) and
 * calls tdma_tick() when the MAC wants it. Every call into the MAC, from any
 * thread, goes through tdma_nrf_runner_lock() / _unlock(); the callbacks
 * (deliver, events) run in the MAC thread with the lock held and must not
 * block. Sending from inside deliver (an echo) is allowed.
 */

#ifndef CAPPELLA_TDMA_NRF_RUNNER_H_
#define CAPPELLA_TDMA_NRF_RUNNER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tdma_mac.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tdma_nrf_runner_cfg {
	/* The MAC configuration; .mem is filled in by the runner. */
	struct tdma_cfg mac;
	/* Band (its group configures the PHY), carrier set and TX power. */
	uint8_t band;
	int8_t tx_power_dbm;
	int8_t tx_power_max_dbm; /* the build's ceiling */
	/* A complete SDU from src_rd_id (MAC thread, lock held). */
	void (*deliver)(uint32_t src_rd_id, const uint8_t *data, size_t len);
	/* Link security (NULL = off). */
	const struct tdma_sec_ops *sec;
	void *sec_ctx;
};

/* tdma_nrf_init(), configure, activate, and the MAC thread (idle until started). */
int tdma_nrf_runner_init(uint8_t band);
/* Stop a running MAC, set up a new one with cfg and start it (FT: beacon, PT: search). */
int tdma_nrf_runner_start(const struct tdma_nrf_runner_cfg *cfg);
void tdma_nrf_runner_stop(void);
bool tdma_nrf_runner_running(void);

void tdma_nrf_runner_lock(void);
void tdma_nrf_runner_unlock(void);
/* The instance (call into it only with the lock held). */
struct tdma_mac *tdma_nrf_runner_mac(void);
/* tdma_send() under the lock, then wake the MAC thread. */
int tdma_nrf_runner_send(uint32_t dst_rd_id, const uint8_t *data, size_t len, uint8_t prio);

/* MAC thread counters. */
struct tdma_nrf_runner_stats {
	uint32_t wakeups;
	uint32_t late_ticks; /* woke > 500 us after a commit was due */
	uint32_t late_max_us;
	uint64_t busy_ticks; /* time with the lock held (not counting quiet-window waits) */
};
void tdma_nrf_runner_get_stats(struct tdma_nrf_runner_stats *out);

#ifdef __cplusplus
}
#endif

#endif /* CAPPELLA_TDMA_NRF_RUNNER_H_ */
