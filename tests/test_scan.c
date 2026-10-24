/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * A root that listens for other clusters (tdma_ft_scan()) on the simulated
 * radio: two clusters on independent frame grids, one root listening on the
 * other's carrier while priority probes run in its own cluster.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sim.h"
#include "test.h"

#define MS(x) ((uint64_t)(x) * TDMA_FRAME_TICKS / 10u)
#define US(t) ((unsigned long long)TDMA_TICKS_TO_US(t))

static struct sim *s;
static int drv_stop;

/* The security cost model of an nRF9151 with the AES in the secure partition. */
static void sec_model_on(void)
{
	sim_sec_all = true;
	sim_grant_ahead = false;
	sim_sec_cost_us = 450;
	sim_sec_open_us = 250;
	sim_sec_busy_us = 450;
	sim_sec_stats_reset();
}

static void sec_model_off(void)
{
	sim_sec_all = false;
	sim_sec_cost_us = sim_sec_open_us = sim_sec_busy_us = 0;
}

static uint64_t until(bool (*cond)(void), uint64_t deadline)
{
	while (s->t < deadline) {
		sim_run_until(s, s->t + MS(5));
		if (cond()) {
			return s->t;
		}
	}
	return UINT64_MAX;
}

static void clean(const char *what)
{
	CHECK(sim_phy_errors(s) == 0, "%s: PHY rules broken %u times", what, sim_phy_errors(s));
	CHECK(sim_sec_st.nonce_reuse == 0, "%s: nonce reuse %llu", what,
	      (unsigned long long)sim_sec_st.nonce_reuse);
}

/*
 * Two clusters on independent grids: A (root, 1705) with PT B, C (root,
 * 1709) with PT D. A listens once per second (tdma_ft_scan) while 64 B
 * priority probes go A <-> B every 5-15 ms: C's beacon (route record and
 * the app bytes) is heard on 1709 at whatever offset its frame has, the PHY's
 * rules hold, B keeps its parent, nothing is lost, and the probes' p99 stays
 * where it was without the listens (the max may take one window, ~12 ms).
 */
#define FS_LAT_MAX 20000
static uint32_t fs_lat[2][FS_LAT_MAX];
static uint32_t fs_nlat[2];
static uint32_t fs_sent[2], fs_got[2];
static uint32_t fs_heard_c, fs_heard_app_ok, fs_done, fs_done_stopped, fs_on_1709, fs_heard_1709;
static uint16_t fs_last_ch;
static bool fs_on;

static void fs_deliver(struct sim *sm, int node, uint32_t src, const uint8_t *data, size_t len)
{
	uint64_t t0;
	int dir = node == 1 ? 0 : 1; /* 0: A -> B */

	(void)src;
	if (len < 9 || data[0] != 0x5c || (node != 0 && node != 1)) {
		return;
	}
	memcpy(&t0, &data[1], 8);
	fs_got[dir]++;
	if (fs_on && fs_nlat[dir] < FS_LAT_MAX) {
		fs_lat[dir][fs_nlat[dir]++] = (uint32_t)US(sm->t - t0);
	}
}

static void fs_evt(struct sim *sm, int node, const struct tdma_evt *e)
{
	(void)sm;
	if (node != 0) {
		return;
	}
	if (e->type == TDMA_EVT_FT_SCAN && e->rd_id == sim_rd_for_box(3)) {
		fs_heard_c++;
		fs_heard_app_ok += e->app_len == 3 && e->app[0] == 1 && e->app[1] == 7 &&
				   e->app[2] == 2 && e->route_len >= 2 && e->route[0] == 3;
	} else if (e->type == TDMA_EVT_FT_SCAN_DONE) {
		fs_done++;
		fs_heard_1709 += e->channel == 1709 && (e->value & 0xffff) > 0;
		fs_done_stopped += e->cause != TDMA_CAUSE_NONE;
	}
}

static void fs_probe(struct sim *sm, void *arg)
{
	int from = (int)(intptr_t)arg;
	uint8_t msg[64] = {0x5c};
	uint64_t t = sm->t;

	if (drv_stop) {
		return;
	}
	memcpy(&msg[1], &t, 8);
	if (sim_send(sm, from, sm->nodes[from ? 0 : 1].cfg.rd_id, msg, sizeof(msg), 1) == 0) {
		fs_sent[from]++;
	}
	sim_at(sm, sm->t + MS(5) + sim_rand(sm) % MS(10), fs_probe, arg);
}

static uint32_t fs_pct(uint32_t *v, uint32_t n, uint32_t pct)
{
	/* (insertion sort is fine at these sizes? no: qsort) */
	if (!n) {
		return 0;
	}
	for (uint32_t i = 1; i < n; i++) {
		uint32_t x = v[i], j = i;

		while (j && v[j - 1] > x) {
			v[j] = v[j - 1];
			j--;
		}
		v[j] = x;
	}
	return v[(uint64_t)(n - 1) * pct / 100u];
}

static uint64_t fs_every;

static void fs_scan_tick(struct sim *sm, void *arg)
{
	uint16_t ch = (uint16_t)(uintptr_t)arg;

	if (drv_stop || !fs_on) {
		return;
	}
	if (tdma_ft_scan(&sm->nodes[0].mac, ch, 0) == 0) {
		fs_last_ch = sm->nodes[0].mac.fs_ch;
		fs_on_1709 += fs_last_ch == 1709;
	}
	sim_at(sm, sm->t + fs_every, fs_scan_tick, arg);
}

static bool fs_both_assoc(void)
{
	return tdma_get_state(&s->nodes[1].mac) == TDMA_ST_ASSOCIATED &&
	       tdma_get_state(&s->nodes[3].mac) == TDMA_ST_ASSOCIATED;
}

void test_ft_scan(void)
{
	static const uint8_t app_c[3] = {1, 7, 2}, app_a[3] = {1, 0, 2};
	uint8_t rr_a[6] = {1, 1, 0, 0, 0, 0}, rr_c[6] = {3, 3, 0, 0, 0, 0};
	uint32_t p99_0[2], max_0[2], p99_1[2], max_1[2], skipped, scans, heard_rr, on_rr;
	const struct tdma_chan_info *ci;

	sec_model_on();
	s = sim_init(103);
	for (int k = 0; k < 2; k++) {
		int ft = sim_add_node(s, TDMA_ROLE_FT, (uint8_t)(1 + 2 * k), TDMA_PLAN_H,
				      (int64_t)(sim_rand(s) % (1ull << 40)),
				      (int32_t)(sim_rand(s) % 40001) - 20000);
		int pt = sim_add_node(s, TDMA_ROLE_PT, (uint8_t)(2 + 2 * k), TDMA_PLAN_H,
				      (int64_t)(sim_rand(s) % (1ull << 40)),
				      (int32_t)(sim_rand(s) % 40001) - 20000);

		s->nodes[ft].cfg.channel = k ? 1709 : 1705;
		s->nodes[ft].cfg.plan_auto = true;
		s->nodes[ft].cfg.ul_lead_trim = s->nodes[pt].cfg.ul_lead_trim =
			TDMA_US_TO_TICKS(300);
		s->nodes[ft].cfg.dl_lead_trim = s->nodes[pt].cfg.dl_lead_trim =
			TDMA_US_TO_TICKS(150);
		s->nodes[pt].cfg.channel = 0;
		s->nodes[pt].cfg.ft_rd_filter = s->nodes[ft].cfg.rd_id;
	}
	for (int i = 0; i < 4; i++) {
		sim_start(s, i);
	}
	drv_stop = 0;
	fs_on = false;
	memset(fs_nlat, 0, sizeof(fs_nlat));
	memset(fs_sent, 0, sizeof(fs_sent));
	memset(fs_got, 0, sizeof(fs_got));
	fs_heard_c = fs_heard_app_ok = fs_done = fs_done_stopped = fs_on_1709 = fs_heard_1709 = 0;
	s->on_deliver = fs_deliver;
	s->on_evt = fs_evt;
	CHECK(until(fs_both_assoc, MS(20000)) != UINT64_MAX, "two clusters up");
	tdma_set_route(&s->nodes[0].mac, rr_a, sizeof(rr_a));
	tdma_set_beacon_ext(&s->nodes[0].mac, app_a, sizeof(app_a));
	tdma_set_route(&s->nodes[2].mac, rr_c, sizeof(rr_c));
	tdma_set_beacon_ext(&s->nodes[2].mac, app_c, sizeof(app_c));
	sim_at(s, s->t + MS(1), fs_probe, (void *)(intptr_t)0);
	sim_at(s, s->t + MS(3), fs_probe, (void *)(intptr_t)1);
	/* 30 s without listens */
	sim_run_until(s, s->t + MS(1000));
	fs_on = true;
	sim_run_until(s, s->t + MS(30000));
	for (int d = 0; d < 2; d++) {
		max_0[d] = fs_pct(fs_lat[d], fs_nlat[d], 100);
		p99_0[d] = fs_pct(fs_lat[d], fs_nlat[d], 99);
		fs_nlat[d] = 0;
	}
	/* 60 s with a listen every 2.5 s, the MAC's round robin over the carriers */
	skipped = tdma_get_stats(&s->nodes[0].mac)->fs_skipped;
	fs_every = MS(2500);
	sim_at(s, s->t, fs_scan_tick, (void *)(uintptr_t)0);
	sim_run_until(s, s->t + MS(60000));
	for (int d = 0; d < 2; d++) {
		uint32_t over = 0;

		max_1[d] = fs_pct(fs_lat[d], fs_nlat[d], 100);
		p99_1[d] = fs_pct(fs_lat[d], fs_nlat[d], 99);
		for (uint32_t i = 0; i < fs_nlat[d]; i++) {
			over += fs_lat[d][i] > p99_0[d] + 1000;
		}
		printf("    %s: %u of %u probes over the p99 without listens + 1 ms\n",
		       d ? "B -> A" : "A -> B", over, fs_nlat[d]);
	}
	scans = tdma_get_stats(&s->nodes[0].mac)->fs_scans;
	skipped = tdma_get_stats(&s->nodes[0].mac)->fs_skipped - skipped;
	heard_rr = fs_heard_1709;
	on_rr = fs_on_1709;
	/* then 30 s of a listen per second on C's carrier */
	fs_on = false;
	sim_run_until(s, s->t + MS(2600));
	fs_on = true;
	fs_on_1709 = fs_heard_1709 = 0;
	fs_every = MS(1000);
	sim_at(s, s->t, fs_scan_tick, (void *)(uintptr_t)1709);
	sim_run_until(s, s->t + MS(30000));
	fs_on = false;
	drv_stop = 1;
	sim_run_until(s, s->t + MS(500));
	ci = &s->nodes[0].mac.chans[1709 - SIM_CH_MIN];
	printf("    round robin, one per 2.5 s: %u listens, 1709 %u times, C heard %u; A's slots "
	       "left out %u (%.1f per "
	       "listen), B's %u\n",
	       scans, on_rr, heard_rr, skipped, scans ? (double)skipped / scans : 0.0,
	       tdma_get_stats(&s->nodes[1].mac)->fs_quiet);
	printf("    one per second on 1709: %u, C heard %u; app bytes ok %u of %u; 1709 clusters "
	       "%u; not placed %u\n",
	       fs_on_1709, fs_heard_1709, fs_heard_app_ok, fs_heard_c, ci->clusters,
	       fs_done_stopped);
	printf("    probes A -> B p99 / max %u / %u us without, %u / %u us with; B -> A %u / %u, "
	       "%u / %u; "
	       "sent %u + %u, delivered %u + %u, retransmissions %u + %u\n",
	       p99_0[0], max_0[0], p99_1[0], max_1[0], p99_0[1], max_0[1], p99_1[1], max_1[1],
	       fs_sent[0], fs_sent[1], fs_got[0], fs_got[1], tdma_get_stats(&s->nodes[0].mac)->retx,
	       tdma_get_stats(&s->nodes[1].mac)->retx);
	CHECK(on_rr >= 2 && heard_rr == on_rr,
	      "round robin: C heard on every listen on 1709 (%u of %u)", heard_rr, on_rr);
	CHECK(fs_on_1709 >= 25 && fs_heard_1709 * 100u >= fs_on_1709 * 95u,
	      "on 1709: C heard in >= 95 %% of the listens (%u of %u)", fs_heard_1709, fs_on_1709);
	CHECK(fs_heard_app_ok == fs_heard_c && fs_heard_c > 0,
	      "route record and app bytes as C beacons them");
	CHECK(fs_done_stopped == 0, "every listen placed (%u not)", fs_done_stopped);
	CHECK(ci->clusters > 0, "1709 marked as taken (carrier choice)");
	CHECK(sim_count_evt(&s->nodes[1], TDMA_EVT_LOST, 0) == 0, "B kept A");
	CHECK(fs_got[0] == fs_sent[0] && fs_got[1] == fs_sent[1], "no probe lost");
	for (int d = 0; d < 2; d++) {
		CHECK(p99_1[d] <= p99_0[d] + 500,
		      "p99 %s within 0.5 ms of the run without listens (%u / %u us)",
		      d ? "B -> A" : "A -> B", p99_1[d], p99_0[d]);
		/* (a window with its margins is 59 ss, 12.3 ms; plan H's slots come every 5 ms) */
		CHECK(max_1[d] <= max_0[d] + 12300 + 5000,
		      "max %s at most one window and a slot period more (%u / %u us)",
		      d ? "B -> A" : "A -> B", max_1[d], max_0[d]);
	}
	s->on_deliver = NULL;
	s->on_evt = NULL;
	clean("ft scan");
	sec_model_off();
}
