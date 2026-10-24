/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * nRF91 port of the MAC: struct tdma_port on Nordic's DECT NR+ PHY API
 * (nrf_modem_dect_phy, modem firmware mfw-nr+ 2.0.0; docs/phy-timing.md).
 *
 * What it does
 *   - the PHY event handler: PCC / PDC / COMPLETED / RSSI events become small
 *     messages in one queue (a PDC's payload is copied once into a slab
 *     block); nothing else runs in the handler
 *   - modem time: "now" = time of the last PHY event + kernel time since, so
 *     it lags the modem clock by the IPC latency (the safe direction)
 *   - the op table: MAC handles <-> PHY handles, for up to TDMA_NRF_INSTANCES
 *     MAC instances on one radio (a relay runs two), with a session number
 *     per instance so completions of ops from an older setup are dropped
 *   - the tdma_port ops: rx, rx_stop, tx (with LBT), rssi, scan, now; every op
 *     is checked against the configured carrier set, every TX uses the
 *     configured power index
 *   - the PHY quiet window: an op request is held back while it would reach
 *     the modem 0.65-0.2 ms before another op's start (the modem fails the
 *     accepted op with OP_TIMEOUT otherwise; docs/phy-timing.md)
 *   - PHY bring-up: modem library, init, band list, configure, activate,
 *     band-group changes
 *   - dispatch: queued messages -> tdma_on_rx / tdma_on_op_done /
 *     tdma_on_rssi / tdma_on_pcc of the instance that owns the op
 *   - counters and an op error log for diagnostics
 *
 * What it leaves to the application: the thread that owns the MAC instances
 * (it takes messages with tdma_nrf_msg_get(), hands them to
 * tdma_nrf_dispatch() and calls tdma_tick()), tdma_port.deliver / trace /
 * away / sec, and every policy. CONFIG_TDMA_NRF_RUNNER provides a simple
 * thread for one instance (tdma_nrf_runner.h).
 *
 * Context: tdma_nrf_dispatch(), tdma_nrf_reap() and the tdma_port ops run in
 * the MAC thread with the application's MAC lock held, like every other call
 * into the MAC instances.
 */

#ifndef CAPPELLA_TDMA_NRF_H_
#define CAPPELLA_TDMA_NRF_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/kernel.h>
#include <nrf_modem_dect_phy.h>

#include "tdma_mac.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TDMA_NRF_INSTANCES 2

/*
 * PHY handles with this bit set belong to the application (raw
 * nrf_modem_dect_phy ops of test tools): their events go to
 * tdma_nrf_hooks.test_evt first. Bits 0..28 are free for the application.
 */
#define TDMA_NRF_H_TEST (1u << 29)

enum tdma_nrf_msg_kind {
	TDMA_NRF_MSG_RX,   /* a packet: .handle, .stf, .hdr, .rssi, .snr, .data / .len */
	TDMA_NRF_MSG_DONE, /* an op completed: .handle, .err, .stf = event time */
	TDMA_NRF_MSG_CTL,  /* the application's own control message: .ctl, .arg */
	TDMA_NRF_MSG_RSSI, /* .n subslot maxima in .ss */
	TDMA_NRF_MSG_PCC,  /* a scan op heard a physical header: .rssi, .arg, .crc_ok */
};

#define TDMA_NRF_SS_MAX 24 /* subslots per RSSI message (one 5 ms report) */

struct tdma_nrf_msg {
	uint8_t kind;
	uint8_t ctl;
	bool crc_ok;
	int16_t rssi;
	int16_t snr; /* 0.25 dB */
	uint16_t len;
	uint32_t handle;
	int32_t err;
	uint32_t arg;
	uint64_t stf;
	union nrf_modem_dect_phy_hdr hdr;
	uint8_t *data; /* RX: a slab block, freed by tdma_nrf_dispatch() */
	uint32_t cyc;  /* RX: DWT cycle count when the event handler queued it */
	uint8_t n;
	int8_t ss[TDMA_NRF_SS_MAX];
};

/* Optional application hooks (any may be NULL). */
struct tdma_nrf_hooks {
	/* MAC thread: right before tdma_on_rx() / tdma_on_op_done() of instance inst. */
	void (*before_mac)(uint8_t inst);
	/* MAC thread: after tdma_on_rx() of instance inst returned. */
	void (*after_rx)(uint8_t inst);
	/* MAC thread: true = ignore bursts and headers of this transmitter (tests). */
	bool (*drop_tx)(uint16_t tx_short);
	/*
	 * Every PHY call (kind 1 rx, 2 tx, 3 rssi, 4 cancel, 5 scan) and every
	 * quiet-window wait, for a packet trace.
	 */
	void (*trace_call)(uint8_t kind, uint64_t start, uint32_t dur, uint16_t len);
	void (*trace_quiet)(uint64_t op_start, uint32_t wait_us);
	/* PHY event handler context: an event of a TDMA_NRF_H_TEST handle; true = consumed. */
	bool (*test_evt)(const struct nrf_modem_dect_phy_event *evt);
};

/* PHY-side counters (diagnostics). */
struct tdma_nrf_stats {
	uint32_t pcc_err, pdc_err, pdc_no_pcc, reject;
	uint32_t q_drop;    /* events lost to a full queue / slab */
	uint32_t pool_full; /* op table full */
	uint32_t tx_refused, rx_refused;
	uint32_t op_err;
	int32_t last_op_err;
	uint32_t op_reaped; /* ops whose completion never came */
	uint32_t lbt_busy;  /* TX ops dropped by the PHY's LBT */
	uint32_t rssi_evts, pcc_fwd;
	uint32_t err_long_tx, err_short_tx, err_rx;
	uint16_t err_slot[8]; /* failed ops by plan slot index (7: 7 and above) */
	uint32_t tx_call_max_us, tx_call_max_len, rx_call_max_us;
	uint32_t lead_min_us; /* smallest start - now at a TX call */
	/*
	 * start - now at the PHY call by op kind (FT short TX, PT short TX, long
	 * TX, RX, FT beacon TX) in 100 us steps from 400 us (0: < 500, 5: >= 900).
	 */
	uint32_t lead_hist[5][6];
	uint32_t build_hist[2][5]; /* FT DL / beacon TX: call - wakeup < 200, 400, 600, 800, more */
	uint32_t quiet_wait, quiet_tight, quiet_wait_max_us;
	uint64_t quiet_ticks; /* time spent waiting in the quiet window */
	uint32_t on_rx_max_us, rx_len_at_max;
	int16_t last_rssi;
	int16_t last_snr; /* 0.25 dB */
	uint32_t bursts_long, bursts_short;
	uint64_t pay_long, tbs_long, pay_short, tbs_short;
	/* RX path: long bursts (> 300 B) and bursts of instance 1, in DWT cycles */
	uint32_t rxl_n;
	uint64_t rxl_isr_cyc, rxl_wait_cyc, rxl_cyc;
	uint32_t rxc_n, rxc_max;
	uint64_t rxc_sum;
	/* how far "now" was behind an event's own time stamp */
	uint32_t tb_behind_max_us, tb_hist[4]; /* < 100, < 300, < 500, >= 500 us */
};

/* ---- bring-up ----------------------------------------------------------------- */

/*
 * Modem library, event handler, PHY init and the modem's band list. The PHY is
 * configured and activated with tdma_nrf_configure() / tdma_nrf_activate().
 */
int tdma_nrf_init(const struct tdma_nrf_hooks *hooks);
int tdma_nrf_configure(uint8_t band_group);
int tdma_nrf_activate(void);
/* Cancel every op, deactivate. */
int tdma_nrf_deactivate(void);
/* MAC stopped: move the PHY to another band group (deactivate, configure, activate). */
int tdma_nrf_band_group(uint8_t band_group);
bool tdma_nrf_activated(void);
uint8_t tdma_nrf_cur_group(void);

/* The modem's bands (empty until tdma_nrf_init()), one band's entry or NULL. */
size_t tdma_nrf_bands(const struct nrf_modem_dect_phy_band **bands);
const struct nrf_modem_dect_phy_band *tdma_nrf_band(uint8_t band);
/* Highest DECT power step <= min(dbm, the band's power class, ceiling_dbm): its index. */
uint8_t tdma_nrf_pwr_index(int dbm, uint8_t band, int ceiling_dbm);
int8_t tdma_nrf_pwr_dbm(uint8_t idx); /* ETSI TS 103 636-4 table 6.2.1-3b (idx > 15: 15) */
int8_t tdma_nrf_class_dbm(uint8_t power_class); /* TS 103 636-2 table 6.2.1-1 */

/* ---- radio settings used by every op ------------------------------------------ */

void tdma_nrf_set_network_id(uint32_t network_id);
uint32_t tdma_nrf_network_id(void);
/* Carriers lo..hi, bit i of mask = lo + i (0 = all); ops elsewhere are refused. */
void tdma_nrf_set_carriers(uint16_t lo, uint16_t hi, uint32_t mask);
void tdma_nrf_get_carriers(uint16_t *lo, uint16_t *hi, uint32_t *mask);
bool tdma_nrf_carrier_ok(uint16_t ch);
void tdma_nrf_set_tx_power(uint8_t pwr_idx);
uint8_t tdma_nrf_tx_power(void);
/* Quiet window [start - us, start - late_us) before every pending op (us <= late_us: off). */
void tdma_nrf_set_quiet(uint16_t us, uint16_t late_us);
void tdma_nrf_get_quiet(uint16_t *us, uint16_t *late_us);

/* ---- MAC instances --------------------------------------------------------------- */

/* now, rx, rx_stop, tx, rssi, scan and ctx for instance inst; the rest stays NULL. */
void tdma_nrf_port_init(struct tdma_port *port, uint8_t inst);
void *tdma_nrf_ctx(uint8_t inst);
uint8_t tdma_nrf_ctx_inst(const void *ctx);
/* Before tdma_init() of instance inst: ops committed until now are stale. */
void tdma_nrf_new_session(uint8_t inst);
/* After tdma_init(): events of instance inst's ops go to m (ft: its role, for counters). */
void tdma_nrf_bind(uint8_t inst, struct tdma_mac *m, bool ft);
void tdma_nrf_unbind(uint8_t inst);
int tdma_nrf_ops_in_flight(void);
int tdma_nrf_ops_in_flight_of(uint8_t inst);

/* ---- modem time --------------------------------------------------------------------- */

uint64_t tdma_nrf_now(void);
/* The kernel timeout (absolute) at which tdma_nrf_now() reaches mt. */
k_timeout_t tdma_nrf_until(uint64_t mt);
int64_t tdma_nrf_ms_since_event(void);
/* Ask the modem for its time when no event came for 500 ms (keeps "now" fresh). */
void tdma_nrf_keepalive(void);

/* ---- the event queue ------------------------------------------------------------------ */

int tdma_nrf_msg_get(struct tdma_nrf_msg *m, k_timeout_t timeout);
int tdma_nrf_msg_peek(struct tdma_nrf_msg *m);
uint32_t tdma_nrf_msg_pending(void);
/* Queue an application control message (TDMA_NRF_MSG_CTL) for the MAC thread. */
int tdma_nrf_post_ctl(uint8_t ctl, uint32_t arg, k_timeout_t timeout);
/* MAC thread, lock held: RX / DONE / RSSI / PCC to the owning instance; frees RX data. */
void tdma_nrf_dispatch(const struct tdma_nrf_msg *m);
/* MAC thread, lock held: complete ops whose event was lost (-ETIMEDOUT, 30 ms after their end). */
void tdma_nrf_reap(void);
/* The MAC thread woke at modem time mt (build-time counters). */
void tdma_nrf_note_wake(uint64_t mt);

/* ---- raw access for test tools ---------------------------------------------------------- */

/* RX params as the port builds them (scan: any network, RSSI reported). */
void tdma_nrf_fill_rx(struct nrf_modem_dect_phy_rx_params *p, uint32_t handle, uint64_t start,
		      uint32_t duration, uint16_t ch, bool scan);

/* ---- diagnostics ---------------------------------------------------------------------------- */

const struct tdma_nrf_stats *tdma_nrf_get_stats(void);
struct shell;
/* The op error log: recent failed ops with the PHY calls and ops around them. */
void tdma_nrf_print_errlog(const struct shell *sh, bool clear);

#ifdef __cplusplus
}
#endif

#endif /* CAPPELLA_TDMA_NRF_H_ */
