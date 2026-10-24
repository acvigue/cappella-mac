/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* A simple MAC thread for one instance (see cappella/tdma_nrf_runner.h). */

#include <cappella/tdma_nrf.h>
#include <cappella/tdma_nrf_runner.h>

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

LOG_MODULE_DECLARE(tdma_nrf, CONFIG_TDMA_NRF_LOG_LEVEL);

#define CTL_KICK 0

static K_MUTEX_DEFINE(lock);
static struct tdma_mac mac;
static struct tdma_mac_store store;
static bool running;
static void (*deliver_cb)(uint32_t src, const uint8_t *data, size_t len);
static struct tdma_nrf_runner_stats rst;

static void port_deliver(void *ctx, uint32_t src_rd, const uint8_t *data, size_t len)
{
	ARG_UNUSED(ctx);
	if (deliver_cb) {
		deliver_cb(src_rd, data, len);
	}
}

void tdma_nrf_runner_lock(void)
{
	k_mutex_lock(&lock, K_FOREVER);
}

void tdma_nrf_runner_unlock(void)
{
	k_mutex_unlock(&lock);
}

struct tdma_mac *tdma_nrf_runner_mac(void)
{
	return &mac;
}

bool tdma_nrf_runner_running(void)
{
	return running;
}

static void kick(void)
{
	(void)tdma_nrf_post_ctl(CTL_KICK, 0, K_NO_WAIT);
}

int tdma_nrf_runner_start(const struct tdma_nrf_runner_cfg *cfg)
{
	const struct nrf_modem_dect_phy_band *b = tdma_nrf_band(cfg->band);
	struct tdma_cfg tc = cfg->mac;
	struct tdma_port p;
	int err;

	if (!tdma_nrf_activated()) {
		return -ENETDOWN;
	}
	if (!b) {
		LOG_ERR("band %u not supported by the modem", cfg->band);
		return -ENOTSUP;
	}
	if (tc.ch_min < b->min_carrier || tc.ch_max > b->max_carrier || tc.ch_max < tc.ch_min) {
		LOG_ERR("carriers %u-%u outside band %u (%u-%u)", tc.ch_min, tc.ch_max, cfg->band,
			b->min_carrier, b->max_carrier);
		return -ERANGE;
	}
	tdma_nrf_runner_lock();
	if (running) {
		tdma_stop(&mac);
		running = false;
	}
	tdma_nrf_unbind(0);
	err = tdma_nrf_band_group(b->band_group_index);
	if (err) {
		goto out;
	}
	tdma_nrf_set_network_id(tc.network_id);
	tdma_nrf_set_carriers(tc.ch_min, tc.ch_max, tc.ch_mask);
	tdma_nrf_set_tx_power(
		tdma_nrf_pwr_index(cfg->tx_power_dbm, cfg->band, cfg->tx_power_max_dbm));
	tdma_nrf_port_init(&p, 0);
	p.deliver = port_deliver;
	p.sec = cfg->sec;
	p.sec_ctx = cfg->sec_ctx;
	deliver_cb = cfg->deliver;
	tc.mem = tdma_mem_of(&store);
	tdma_nrf_new_session(0);
	err = tdma_init(&mac, &tc, &p);
	if (err) {
		LOG_ERR("tdma_init: %d", err);
		goto out;
	}
	tdma_nrf_bind(0, &mac, tc.role == TDMA_ROLE_FT);
	err = tdma_start(&mac);
	if (err) {
		LOG_ERR("tdma_start: %d", err);
		tdma_nrf_unbind(0);
		goto out;
	}
	running = true;
	LOG_INF("%s on band %u, carriers %u-%u, %d dBm", tc.role == TDMA_ROLE_FT ? "FT" : "PT",
		cfg->band, tc.ch_min, tc.ch_max, tdma_nrf_pwr_dbm(tdma_nrf_tx_power()));
out:
	tdma_nrf_runner_unlock();
	kick();
	return err;
}

void tdma_nrf_runner_stop(void)
{
	tdma_nrf_runner_lock();
	if (running) {
		tdma_stop(&mac);
		running = false;
	}
	tdma_nrf_runner_unlock();
	kick();
}

int tdma_nrf_runner_send(uint32_t dst_rd_id, const uint8_t *data, size_t len, uint8_t prio)
{
	int err;

	tdma_nrf_runner_lock();
	err = running ? tdma_send(&mac, dst_rd_id, data, len, prio) : -ENOTCONN;
	tdma_nrf_runner_unlock();
	if (err == 0) {
		kick();
	}
	return err;
}

void tdma_nrf_runner_get_stats(struct tdma_nrf_runner_stats *out)
{
	tdma_nrf_runner_lock();
	*out = rst;
	tdma_nrf_runner_unlock();
}

static void runner_fn(void *a, void *b, void *c)
{
	static struct tdma_nrf_msg msg;
	uint64_t next = UINT64_MAX;
	uint32_t drops = 0;

	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	for (;;) {
		k_timeout_t to = K_MSEC(1000);
		uint64_t now = tdma_nrf_now();

		if (next != UINT64_MAX) {
			if (next <= now) {
				to = K_NO_WAIT;
			} else if (next - now < TDMA_TICKS_PER_SEC) {
				to = tdma_nrf_until(next);
			}
		}
		int r = tdma_nrf_msg_get(&msg, to);
		uint64_t t_wake = tdma_nrf_now();

		tdma_nrf_note_wake(t_wake);
		tdma_nrf_runner_lock();
		uint64_t t0 = tdma_nrf_now(), q0 = tdma_nrf_get_stats()->quiet_ticks;

		if (r == 0 && msg.kind != TDMA_NRF_MSG_CTL) {
			tdma_nrf_dispatch(&msg);
		}
		if (tdma_nrf_get_stats()->q_drop != drops) {
			drops = tdma_nrf_get_stats()->q_drop;
			tdma_nrf_reap();
		}
		if (running) {
			uint64_t tn = tdma_nrf_now();

			if (next != UINT64_MAX && tn > next + TDMA_US_TO_TICKS(500)) {
				rst.late_ticks++;
				rst.late_max_us =
					MAX(rst.late_max_us, (uint32_t)TDMA_TICKS_TO_US(tn - next));
			}
			next = tdma_tick(&mac, tn);
		} else {
			next = UINT64_MAX;
		}
		rst.wakeups++;
		{
			uint64_t t1 = tdma_nrf_now(),
				 waited = tdma_nrf_get_stats()->quiet_ticks - q0;

			if (t1 > t0 + waited) {
				rst.busy_ticks += t1 - t0 - waited;
			}
		}
		tdma_nrf_runner_unlock();
		tdma_nrf_keepalive();
	}
}

K_THREAD_DEFINE(tdma_nrf_runner_thread, CONFIG_TDMA_NRF_RUNNER_STACK_SIZE, runner_fn, NULL, NULL,
		NULL, K_PRIO_COOP(CONFIG_TDMA_NRF_RUNNER_PRIO), 0, -1);

int tdma_nrf_runner_init(uint8_t band)
{
	const struct nrf_modem_dect_phy_band *b;
	int err = tdma_nrf_init(NULL);

	if (err) {
		return err;
	}
	b = tdma_nrf_band(band);
	err = tdma_nrf_configure(b ? b->band_group_index : 0);
	if (!err) {
		err = tdma_nrf_activate();
	}
	if (err) {
		return err;
	}
	k_thread_name_set(tdma_nrf_runner_thread, "tdma_mac");
	k_thread_start(tdma_nrf_runner_thread);
	return 0;
}
