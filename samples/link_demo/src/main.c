/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * cappella-mac link demo: two nRF91 DKs, one FT and one PT, on the TDMA MAC
 * over the DECT NR+ PHY.
 *
 *   link ft [carrier]       start as FT (0 / none: the quietest carrier of the set)
 *   link pt                 start as PT (search, associate with the first FT heard)
 *   link stop
 *   link status             MAC state, peer, counters
 *   link ping [n] [len]     round trips to the peer (it echoes)
 *   link tput <s> [len]     send to the peer as fast as the MAC takes it
 *   link rx                 what this board received (bytes, rate) since the last call
 *   link key <32 hex>|off   link security with the reference AES-CCM (both boards)
 *   link errlog [clear]     PHY op errors with the calls around them
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/drivers/hwinfo.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include <cappella/tdma_mac.h>
#include <cappella/tdma_nrf.h>
#include <cappella/tdma_nrf_runner.h>
#if defined(CONFIG_TDMA_SEC_REF)
#include <cappella/tdma_sec_ref.h>
#endif

LOG_MODULE_REGISTER(link_demo, LOG_LEVEL_INF);

/* Payload type byte of the demo's SDUs. */
#define T_PING 0x01
#define T_PONG 0x02
#define T_BULK 0x03

#define PING_LEN_MAX 1280

static uint32_t own_rd;
static uint32_t peer_rd; /* FT: the first child; PT: the parent */
static bool is_ft;

/* ping: the outstanding request, the RTT of the last answer */
static K_SEM_DEFINE(pong_sem, 0, 1);
static volatile uint16_t ping_seq;
static volatile uint64_t pong_at;

/* receive counters (MAC thread) */
static uint64_t rx_bytes, rx_sdus;
static int64_t rx_since;

#if defined(CONFIG_TDMA_SEC_REF)
static struct tdma_sec_ref sec;
static bool sec_on;

static uint32_t sec_random(void *ctx)
{
	ARG_UNUSED(ctx);
	return sys_rand32_get();
}
#endif

/* ---- MAC callbacks (MAC thread, runner lock held) ------------------------------ */

static void on_deliver(uint32_t src, const uint8_t *data, size_t len)
{
	rx_bytes += len;
	rx_sdus++;
	if (len < 3) {
		return;
	}
	if (data[0] == T_PING) {
		static uint8_t pong[PING_LEN_MAX];

		memcpy(pong, data, len);
		pong[0] = T_PONG;
		/* priority for a small echo; the lock is held: call the MAC directly */
		(void)tdma_send(tdma_nrf_runner_mac(), src, pong, len, len <= 64 ? 1 : 0);
	} else if (data[0] == T_PONG && sys_get_le16(&data[1]) == ping_seq) {
		pong_at = tdma_nrf_now();
		k_sem_give(&pong_sem);
	}
}

static void on_evt(const struct tdma_evt *e, void *user)
{
	ARG_UNUSED(user);
	switch (e->type) {
	case TDMA_EVT_FT_STARTED:
		LOG_INF("FT beaconing on carrier %u", e->channel);
		break;
	case TDMA_EVT_ASSOCIATED:
		peer_rd = e->rd_id;
		LOG_INF("associated with FT 0x%08x", e->rd_id);
		break;
	case TDMA_EVT_LOST:
		LOG_INF("lost FT 0x%08x (cause %d)", e->rd_id, e->cause);
		peer_rd = 0;
		break;
	case TDMA_EVT_CHILD_ADDED:
		LOG_INF("PT 0x%08x joined (position %u)", e->rd_id, e->pos);
		if (!peer_rd) {
			peer_rd = e->rd_id;
		}
		break;
	case TDMA_EVT_CHILD_REMOVED:
		LOG_INF("PT 0x%08x left (cause %d)", e->rd_id, e->cause);
		if (peer_rd == e->rd_id) {
			peer_rd = 0;
		}
		break;
	case TDMA_EVT_MOVE:
	case TDMA_EVT_CHANNEL:
		LOG_INF("carrier %u (cause %d)", e->channel, e->cause);
		break;
	default:
		break;
	}
}

/* ---- setup ---------------------------------------------------------------------- */

/* A radio device id from the chip's device id: never 0 or broadcast, short id != 0 / 0xffff. */
static uint32_t make_rd_id(void)
{
	uint8_t id[16];
	ssize_t n = hwinfo_get_device_id(id, sizeof(id));
	uint32_t h = 2166136261u;

	for (ssize_t i = 0; i < n; i++) {
		h = (h ^ id[i]) * 16777619u;
	}
	if (n <= 0) {
		h = sys_rand32_get();
	}
	h &= 0x7fffffffu;
	if ((h & 0xffffu) == 0 || (h & 0xffffu) == 0xffffu) {
		h ^= 0x1234u;
	}
	return h | 0x10000000u;
}

static int start(bool ft, uint16_t channel)
{
	struct tdma_nrf_runner_cfg c = {
		.mac =
			{
				.role = ft ? TDMA_ROLE_FT : TDMA_ROLE_PT,
				.rd_id = own_rd,
				.network_id = CONFIG_LINK_DEMO_NETWORK_ID,
				.box_id = (uint8_t)own_rd,
				.channel = ft ? channel : 0,
				.ch_min = CONFIG_LINK_DEMO_CH_MIN,
				.ch_max = CONFIG_LINK_DEMO_CH_MAX,
				.plan_id = CONFIG_LINK_DEMO_PLAN,
				.plan_auto = IS_ENABLED(CONFIG_LINK_DEMO_PLAN_AUTO),
				.plan_t2 = IS_ENABLED(CONFIG_LINK_DEMO_PLAN_AUTO),
				.evt_cb = on_evt,
			},
		.band = CONFIG_LINK_DEMO_BAND,
		.tx_power_dbm = CONFIG_LINK_DEMO_TX_POWER_DBM,
		.tx_power_max_dbm = 19,
		.deliver = on_deliver,
	};

#if defined(CONFIG_TDMA_SEC_REF)
	if (sec_on) {
		c.sec = &tdma_sec_ref_ops;
		c.sec_ctx = &sec;
		c.mac.sess_ctr = sys_rand32_get() | 1u;
	}
#endif
	is_ft = ft;
	peer_rd = 0;
	return tdma_nrf_runner_start(&c);
}

int main(void)
{
	int err;

	own_rd = make_rd_id();
	err = tdma_nrf_runner_init(CONFIG_LINK_DEMO_BAND);
	if (err) {
		LOG_ERR("PHY bring-up failed: %d", err);
		return 0;
	}
#if defined(CONFIG_TDMA_SEC_REF)
	tdma_sec_ref_init(&sec, sec_random, NULL);
#endif
	rx_since = k_uptime_get();
	LOG_INF("link demo: ready, rd id 0x%08x, network 0x%08x", own_rd,
		CONFIG_LINK_DEMO_NETWORK_ID);
	if (IS_ENABLED(CONFIG_LINK_DEMO_ROLE_FT)) {
		err = start(true, CONFIG_LINK_DEMO_CHANNEL);
	} else if (IS_ENABLED(CONFIG_LINK_DEMO_ROLE_PT)) {
		err = start(false, 0);
	}
	if (err) {
		LOG_ERR("start: %d", err);
	}
	return 0;
}

/* ---- shell ------------------------------------------------------------------------ */

static int cmd_ft(const struct shell *sh, size_t argc, char **argv)
{
	uint16_t ch = argc > 1 ? (uint16_t)strtoul(argv[1], NULL, 0) : CONFIG_LINK_DEMO_CHANNEL;
	int err = start(true, ch);

	if (err) {
		shell_error(sh, "start FT: %d", err);
	}
	return err;
}

static int cmd_pt(const struct shell *sh, size_t argc, char **argv)
{
	int err;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	err = start(false, 0);
	if (err) {
		shell_error(sh, "start PT: %d", err);
	}
	return err;
}

static int cmd_stop(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(sh);
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	tdma_nrf_runner_stop();
	peer_rd = 0;
	return 0;
}

static const char *state_str(enum tdma_state s)
{
	switch (s) {
	case TDMA_ST_IDLE:
		return "idle";
	case TDMA_ST_FT:
		return "FT";
	case TDMA_ST_FT_SCAN:
		return "FT, scanning carriers";
	case TDMA_ST_SEARCH:
		return "searching";
	case TDMA_ST_ASSOCIATING:
		return "associating";
	case TDMA_ST_ASSOCIATED:
		return "associated";
	default:
		return "?";
	}
}

static int cmd_status(const struct shell *sh, size_t argc, char **argv)
{
	struct tdma_mac *m = tdma_nrf_runner_mac();
	const struct tdma_nrf_stats *ps = tdma_nrf_get_stats();
	struct tdma_nrf_runner_stats rs;
	struct tdma_stats st;
	enum tdma_state s;
	const char *plan = "-";
	uint16_t ch;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	tdma_nrf_runner_lock();
	s = tdma_nrf_runner_running() ? tdma_get_state(m) : TDMA_ST_IDLE;
	st = *tdma_get_stats(m);
	ch = tdma_nrf_runner_running() ? tdma_channel(m) : 0;
	if (tdma_nrf_runner_running() && m->plan) {
		plan = m->plan->name;
	}
	tdma_nrf_runner_unlock();
	tdma_nrf_runner_get_stats(&rs);

	shell_print(sh, "rd 0x%08x, %s, carrier %u, plan %s, %d dBm, peer 0x%08x", own_rd,
		    state_str(s), ch, plan, tdma_nrf_pwr_dbm(tdma_nrf_tx_power()), peer_rd);
	shell_print(sh,
		    "beacons tx %u rx %u; PDUs tx %u rx %u, retx %u; SDUs tx %u (drop %u) rx %u",
		    st.beacons_tx, st.beacons_rx, st.pdus_tx, st.pdus_rx, st.retx, st.sdu_tx_ok,
		    st.sdu_tx_drop, st.sdu_rx);
	shell_print(sh, "long bursts tx %u rx %u, plan switches %u; late slots %u, bad rx %u",
		    st.flex_tx, st.flex_rx, st.plan_switches, st.late_slots, st.bad_rx);
	shell_print(sh,
		    "PHY op err %u (last 0x%x), refused tx %u rx %u, queue drops %u, LBT busy %u",
		    ps->op_err, ps->last_op_err, ps->tx_refused, ps->rx_refused, ps->q_drop,
		    ps->lbt_busy);
	shell_print(sh,
		    "last rx %d dBm, SNR %d.%02d dB; MAC thread wakeups %u, late %u (max %u us)",
		    ps->last_rssi, ps->last_snr / 4,
		    (ps->last_snr < 0 ? -ps->last_snr : ps->last_snr) % 4 * 25, rs.wakeups,
		    rs.late_ticks, rs.late_max_us);
	return 0;
}

static int cmd_ping(const struct shell *sh, size_t argc, char **argv)
{
	static uint8_t buf[PING_LEN_MAX];
	int n = argc > 1 ? atoi(argv[1]) : 10;
	size_t len = argc > 2 ? strtoul(argv[2], NULL, 0) : 32;
	uint32_t rtt[100], got = 0, sum = 0, mx = 0, mn = UINT32_MAX;

	if (!peer_rd) {
		shell_error(sh, "no peer yet");
		return -ENOTCONN;
	}
	n = CLAMP(n, 1, (int)ARRAY_SIZE(rtt));
	len = CLAMP(len, 3, sizeof(buf));
	memset(buf, 0x5a, len);
	for (int i = 0; i < n; i++) {
		uint64_t t0;
		int err;

		ping_seq++;
		buf[0] = T_PING;
		sys_put_le16(ping_seq, &buf[1]);
		k_sem_reset(&pong_sem);
		t0 = tdma_nrf_now();
		err = tdma_nrf_runner_send(peer_rd, buf, len, len <= 64 ? 1 : 0);
		if (err) {
			shell_error(sh, "send: %d", err);
			return err;
		}
		if (k_sem_take(&pong_sem, K_MSEC(500)) == 0) {
			uint32_t us = (uint32_t)TDMA_TICKS_TO_US(pong_at - t0);

			rtt[got++] = us;
			sum += us;
			mx = MAX(mx, us);
			mn = MIN(mn, us);
		}
		/* a random gap: a fixed interval locks to the 10 ms frame */
		k_msleep(20 + sys_rand32_get() % 20);
	}
	if (got) {
		shell_print(sh,
			    "%d x %u B: %u answered, RTT min %u.%03u avg %u.%03u max %u.%03u ms", n,
			    len, got, mn / 1000, mn % 1000, sum / got / 1000, sum / got % 1000,
			    mx / 1000, mx % 1000);
	} else {
		shell_print(sh, "%d x %u B: no answer", n, len);
	}
	return 0;
}

static int cmd_tput(const struct shell *sh, size_t argc, char **argv)
{
	static uint8_t buf[TDMA_MAX_SDU];
	int64_t secs = strtoul(argv[1], NULL, 0);
	size_t len = argc > 2 ? strtoul(argv[2], NULL, 0) : 1200;
	int64_t t0 = k_uptime_get(), end = t0 + 1000 * CLAMP(secs, 1, 600);
	uint64_t sent = 0;
	uint32_t full = 0;
	struct tdma_stats a, b;

	if (!peer_rd) {
		shell_error(sh, "no peer yet");
		return -ENOTCONN;
	}
	len = CLAMP(len, 3, sizeof(buf));
	memset(buf, 0xa5, len);
	buf[0] = T_BULK;
	tdma_nrf_runner_lock();
	a = *tdma_get_stats(tdma_nrf_runner_mac());
	tdma_nrf_runner_unlock();
	while (k_uptime_get() < end) {
		int err = tdma_nrf_runner_send(peer_rd, buf, len, 0);

		if (err == 0) {
			sent += len;
		} else if (err == -ENOBUFS) {
			full++;
			k_usleep(500); /* queue full: the MAC paces the sender */
		} else {
			shell_error(sh, "send: %d", err);
			break;
		}
	}
	k_msleep(200);
	tdma_nrf_runner_lock();
	b = *tdma_get_stats(tdma_nrf_runner_mac());
	tdma_nrf_runner_unlock();
	{
		int64_t ms = k_uptime_get() - t0;

		shell_print(
			sh,
			"queued %llu B in %lld ms: %llu kB/s offered; SDUs acked %u, dropped %u, "
			"retransmissions %u (queue full %u times)",
			(unsigned long long)sent, (long long)ms,
			(unsigned long long)(sent / (uint64_t)MAX(ms, 1)),
			b.sdu_tx_ok - a.sdu_tx_ok, b.sdu_tx_drop - a.sdu_tx_drop, b.retx - a.retx,
			full);
		shell_print(sh, "the receiver's 'link rx' gives the delivered rate");
	}
	return 0;
}

static int cmd_rx(const struct shell *sh, size_t argc, char **argv)
{
	uint64_t bytes, sdus;
	int64_t now = k_uptime_get(), ms;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);
	tdma_nrf_runner_lock();
	bytes = rx_bytes;
	sdus = rx_sdus;
	rx_bytes = rx_sdus = 0;
	ms = now - rx_since;
	rx_since = now;
	tdma_nrf_runner_unlock();
	shell_print(sh, "received %llu SDUs, %llu B in %lld ms: %llu kB/s",
		    (unsigned long long)sdus, (unsigned long long)bytes, (long long)ms,
		    (unsigned long long)(bytes / (uint64_t)MAX(ms, 1)));
	return 0;
}

#if defined(CONFIG_TDMA_SEC_REF)
static int hexval(char c)
{
	return c >= '0' && c <= '9'   ? c - '0'
	       : c >= 'a' && c <= 'f' ? c - 'a' + 10
	       : c >= 'A' && c <= 'F' ? c - 'A' + 10
				      : -1;
}

static int cmd_key(const struct shell *sh, size_t argc, char **argv)
{
	uint8_t k[16];

	ARG_UNUSED(argc);
	if (!strcmp(argv[1], "off")) {
		sec_on = false;
		tdma_sec_ref_set_key(&sec, 0, NULL);
		shell_print(sh, "link security off at the next start");
		return 0;
	}
	if (strlen(argv[1]) != 32) {
		shell_error(sh, "32 hex digits (a 128-bit network key)");
		return -EINVAL;
	}
	for (int i = 0; i < 16; i++) {
		int hi = hexval(argv[1][2 * i]), lo = hexval(argv[1][2 * i + 1]);

		if (hi < 0 || lo < 0) {
			shell_error(sh, "not hex");
			return -EINVAL;
		}
		k[i] = (uint8_t)(hi << 4 | lo);
	}
	tdma_sec_ref_set_key(&sec, 0, k);
	memset(k, 0, sizeof(k));
	sec_on = true;
	shell_print(sh, "link security on at the next start (link ft / link pt), key index 0");
	return 0;
}
#endif

static int cmd_errlog(const struct shell *sh, size_t argc, char **argv)
{
	ARG_UNUSED(argv);
	tdma_nrf_print_errlog(sh, argc > 1);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_link,
	SHELL_CMD_ARG(ft, NULL, "[carrier]: start as FT (0: quietest carrier)", cmd_ft, 1, 1),
	SHELL_CMD(pt, NULL, "start as PT", cmd_pt), SHELL_CMD(stop, NULL, "stop the MAC", cmd_stop),
	SHELL_CMD(status, NULL, "state and counters", cmd_status),
	SHELL_CMD_ARG(ping, NULL, "[n] [len]: round trips to the peer", cmd_ping, 1, 2),
	SHELL_CMD_ARG(tput, NULL, "<seconds> [len]: send to the peer at full rate", cmd_tput, 2, 1),
	SHELL_CMD(rx, NULL, "received bytes and rate since the last call", cmd_rx),
	IF_ENABLED(CONFIG_TDMA_SEC_REF, (SHELL_CMD_ARG(key, NULL,
		"<32 hex>|off: link security with the reference AES-CCM", cmd_key, 2, 0),))
			   SHELL_CMD_ARG(errlog, NULL, "[clear]: PHY op errors", cmd_errlog, 1, 1),
		   SHELL_SUBCMD_SET_END);
SHELL_CMD_REGISTER(link, &sub_link, "cappella-mac link demo", NULL);
