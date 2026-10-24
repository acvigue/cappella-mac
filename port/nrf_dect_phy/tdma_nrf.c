/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * nRF91 port of the MAC on nrf_modem_dect_phy (see cappella/tdma_nrf.h).
 *
 * Modem time: "now" = time of the last PHY event + kernel time since it was
 * received. That lags the real modem clock by the IPC latency (~40 us) plus
 * one kernel tick (30.5 us), which is the safe direction: the MAC commits ops
 * 1 ms before air and the PHY needs 465 us.
 */

#include <cappella/tdma_nrf.h>
#include <cappella/tdma_pdu.h>

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/util.h>

#include <modem/nrf_modem_lib.h>
#include <nrf_modem.h>
#include <nrf_modem_dect_phy.h>
#include <cmsis_core.h>

LOG_MODULE_REGISTER(tdma_nrf, CONFIG_TDMA_NRF_LOG_LEVEL);

static struct tdma_nrf_hooks hooks;
static struct tdma_nrf_stats st = {.lead_min_us = UINT32_MAX};

/* DWT cycles per microsecond (the nRF91's application core runs at 64 MHz). */
#define CYC_PER_US 64u

/* ---- radio limits: the modem's bands ------------------------------------------ */

/* ETSI TS 103 636-4 table 6.2.1-3b: transmit power index -> dBm. */
static const int8_t pwr_dbm[16] = {-40, -30, -20, -16, -12, -8, -4, 0,
				   4,   7,   10,  13,  16,  19, 21, 23};
/* TS 103 636-2 table 6.2.1-1: power class I..IV -> max dBm. */
static const int8_t class_dbm[5] = {23, 23, 21, 19, 10};

#define MAX_BANDS 8
static struct nrf_modem_dect_phy_band bands[MAX_BANDS];
static uint8_t n_bands; /* 0 = the modem did not report (yet) */

size_t tdma_nrf_bands(const struct nrf_modem_dect_phy_band **out)
{
	*out = bands;
	return n_bands;
}

const struct nrf_modem_dect_phy_band *tdma_nrf_band(uint8_t band)
{
	for (uint8_t i = 0; i < n_bands; i++) {
		if (bands[i].band_number == band) {
			return &bands[i];
		}
	}
	return NULL;
}

uint8_t tdma_nrf_pwr_index(int dbm, uint8_t band, int ceiling_dbm)
{
	const struct nrf_modem_dect_phy_band *b = tdma_nrf_band(band);
	int limit = MIN(dbm, ceiling_dbm);
	uint8_t idx = 0;

	if (b && b->power_class >= 1 && b->power_class <= 4) {
		limit = MIN(limit, class_dbm[b->power_class]);
	}
	for (uint8_t i = 0; i < ARRAY_SIZE(pwr_dbm); i++) {
		if (pwr_dbm[i] <= limit) {
			idx = i;
		}
	}
	return idx;
}

int8_t tdma_nrf_pwr_dbm(uint8_t idx)
{
	return pwr_dbm[MIN(idx, ARRAY_SIZE(pwr_dbm) - 1)];
}

int8_t tdma_nrf_class_dbm(uint8_t power_class)
{
	return power_class < ARRAY_SIZE(class_dbm) ? class_dbm[power_class] : 0;
}

/* ---- radio settings ------------------------------------------------------------ */

static uint16_t set_lo, set_hi;
static uint32_t set_mask;
static uint32_t network_id;
static uint8_t tx_pwr_idx;
static uint16_t quiet_us = CONFIG_TDMA_NRF_QUIET_US;
static uint16_t quiet_late_us = CONFIG_TDMA_NRF_QUIET_LATE_US;

void tdma_nrf_set_network_id(uint32_t id)
{
	network_id = id;
}

uint32_t tdma_nrf_network_id(void)
{
	return network_id;
}

void tdma_nrf_set_carriers(uint16_t lo, uint16_t hi, uint32_t mask)
{
	set_lo = lo;
	set_hi = hi;
	set_mask = mask ? mask : (hi >= lo ? (uint32_t)(BIT64(MIN(hi - lo + 1, 32)) - 1) : 0u);
}

void tdma_nrf_get_carriers(uint16_t *lo, uint16_t *hi, uint32_t *mask)
{
	*lo = set_lo;
	*hi = set_hi;
	*mask = set_mask;
}

bool tdma_nrf_carrier_ok(uint16_t ch)
{
	return ch >= set_lo && ch <= set_hi && ch - set_lo < 32 && (set_mask & BIT(ch - set_lo));
}

void tdma_nrf_set_tx_power(uint8_t idx)
{
	tx_pwr_idx = MIN(idx, ARRAY_SIZE(pwr_dbm) - 1);
}

uint8_t tdma_nrf_tx_power(void)
{
	return tx_pwr_idx;
}

void tdma_nrf_set_quiet(uint16_t us, uint16_t late_us)
{
	quiet_us = us;
	quiet_late_us = late_us;
}

void tdma_nrf_get_quiet(uint16_t *us, uint16_t *late_us)
{
	*us = quiet_us;
	*late_us = quiet_late_us;
}

/* ---- PHY op table (port handle <-> MAC handle) ------------------------------- */

struct port_op {
	bool used;
	uint8_t inst;
	uint32_t phy_handle;
	uint32_t mac_handle;
	uint32_t gen;
	uint16_t tx_len; /* 0 for RX */
	uint64_t start;
	bool lbt;
	uint16_t lead_us;  /* start - now at the PHY call */
	uint32_t dur;      /* RX duration / TX subslots (ticks) */
	uint32_t call_cyc; /* DWT at the PHY call */
};

/*
 * PHY handles of scan / RSSI-reporting RX ops carry this bit, so the event
 * handler (ISR context) knows to pass their PCCs and RSSI on without looking
 * at the op table.
 */
#define PH_SCAN BIT(30)
BUILD_ASSERT((PH_SCAN & TDMA_NRF_H_TEST) == 0, "handle bits");

static struct port_op port_ops[CONFIG_TDMA_NRF_OPS];
static uint32_t next_phy_handle = 1;
static struct tdma_mac *inst_mac[TDMA_NRF_INSTANCES];
static uint32_t inst_gen[TDMA_NRF_INSTANCES];
static bool inst_ft[TDMA_NRF_INSTANCES];
static uint8_t inst_id[TDMA_NRF_INSTANCES] = {0, 1};
static uint64_t wake_mt; /* modem time the MAC thread last woke */

void *tdma_nrf_ctx(uint8_t inst)
{
	return &inst_id[inst < TDMA_NRF_INSTANCES ? inst : 0];
}

uint8_t tdma_nrf_ctx_inst(const void *ctx)
{
	return ctx ? *(const uint8_t *)ctx : 0;
}

void tdma_nrf_new_session(uint8_t inst)
{
	inst_gen[inst]++;
}

void tdma_nrf_bind(uint8_t inst, struct tdma_mac *m, bool ft)
{
	inst_mac[inst] = m;
	inst_ft[inst] = ft;
}

void tdma_nrf_unbind(uint8_t inst)
{
	inst_mac[inst] = NULL;
}

void tdma_nrf_note_wake(uint64_t mt)
{
	wake_mt = mt;
}

static struct port_op *pop_new(uint8_t inst, uint32_t mac_handle, bool scan)
{
	for (int i = 0; i < CONFIG_TDMA_NRF_OPS; i++) {
		if (!port_ops[i].used) {
			port_ops[i] = (struct port_op){
				.used = true,
				.inst = inst,
				.phy_handle = next_phy_handle | (scan ? PH_SCAN : 0),
				.mac_handle = mac_handle,
				.gen = inst_gen[inst],
			};
			/* Never NRF_MODEM_DECT_PHY_HANDLE_CANCEL_ALL, never 0, below
			 * TDMA_NRF_H_TEST. */
			next_phy_handle = next_phy_handle >= 0x1fffffff ? 1 : next_phy_handle + 1;
			return &port_ops[i];
		}
	}
	return NULL;
}

static struct port_op *pop_by_phy(uint32_t phy_handle)
{
	for (int i = 0; i < CONFIG_TDMA_NRF_OPS; i++) {
		if (port_ops[i].used && port_ops[i].phy_handle == phy_handle) {
			return &port_ops[i];
		}
	}
	return NULL;
}

static struct port_op *pop_by_mac(uint8_t inst, uint32_t mac_handle)
{
	for (int i = 0; i < CONFIG_TDMA_NRF_OPS; i++) {
		if (port_ops[i].used && port_ops[i].inst == inst &&
		    port_ops[i].gen == inst_gen[inst] && port_ops[i].mac_handle == mac_handle) {
			return &port_ops[i];
		}
	}
	return NULL;
}

/* The MAC instance an op belongs to, NULL when the op is stale (an older setup). */
static struct tdma_mac *pop_mac(const struct port_op *op)
{
	return inst_mac[op->inst] && op->gen == inst_gen[op->inst] ? inst_mac[op->inst] : NULL;
}

int tdma_nrf_ops_in_flight(void)
{
	int n = 0;

	for (int i = 0; i < CONFIG_TDMA_NRF_OPS; i++) {
		n += port_ops[i].used;
	}
	return n;
}

int tdma_nrf_ops_in_flight_of(uint8_t inst)
{
	int n = 0;

	for (int i = 0; i < CONFIG_TDMA_NRF_OPS; i++) {
		n += port_ops[i].used && port_ops[i].inst == inst;
	}
	return n;
}

/* ---- op error log -------------------------------------------------------------- */

/*
 * The last failed ops with their lead at the PHY call, when the modem
 * reported them, and the PHY calls and completed ops around them (modem time
 * relative to the failed op's start).
 */
#define ERRLOG_N 8
static struct errlog {
	int32_t err;
	uint16_t len;
	uint8_t slot, use;
	uint16_t lead_us;
	int32_t evt_vs_start_us; /* completion event's modem time - op start */
	uint32_t frame;
} errlog[ERRLOG_N];
static uint32_t errlog_n;
/* the last completed ops (any result), for the error log's "what came before" */
#define OPHIST_N 8
static struct ophist {
	uint64_t start, done_mt;
	uint32_t dur;
	int32_t err;
	uint16_t len;
	bool tx;
} ophist[OPHIST_N];
static uint32_t ophist_n;
/* the last PHY calls (rx / tx / rssi / cancel / scan), for the error log */
#define CALLS_N 8
static struct callrec {
	uint64_t start, at; /* modem time of the call */
	uint32_t cyc, dur;
	uint16_t len;
	uint8_t kind; /* 1 rx, 2 tx, 3 rssi, 4 cancel, 5 scan */
} calls[CALLS_N];
static uint32_t calls_n;
#define ERR_CALLS 4
static struct errcall {
	int32_t call_rel_us, start_rel_us, end_rel_us;
	uint16_t len;
	uint8_t kind;
} errcalls[ERRLOG_N][ERR_CALLS];
#define ERR_PREV 2
static struct errprev {
	int32_t start_rel_us, end_rel_us, done_rel_us; /* vs the failed op's start */
	int32_t err;
	uint16_t len;
	bool tx;
} errprev[ERRLOG_N][ERR_PREV];
static uint32_t ok_rx_lead_hist[6], err_rx_lead_hist[6];
/*
 * Ops (not scans) by outcome against the latest other PHY call made before
 * their start: [ok/err][how long before the start: none in 1.6 ms, < 200,
 * < 400, < 600, < 800, < 1600 us] (the quiet window's evidence).
 */
static uint32_t op_vs_call[2][6];

/* Returns the stamp that identifies the call (port_op.call_cyc). */
static uint32_t call_note(uint8_t kind, uint64_t start, uint32_t dur, uint16_t len)
{
	uint32_t cyc = DWT->CYCCNT;

	calls[calls_n++ % CALLS_N] = (struct callrec){.start = start,
						      .cyc = cyc,
						      .at = tdma_nrf_now(),
						      .dur = dur,
						      .len = len,
						      .kind = kind};
	if (hooks.trace_call) {
		hooks.trace_call(kind, start, dur, len);
	}
	return cyc;
}

static void op_vs_call_note(uint64_t start, uint32_t phy_call_cyc, bool err)
{
	int b = 0;

	for (int k = 1; k <= CALLS_N; k++) {
		const struct callrec *c = &calls[(calls_n - k) % CALLS_N];

		if (c->cyc == phy_call_cyc || c->at > start) {
			continue; /* the op itself, or a call after its start */
		}
		uint32_t us = (uint32_t)TDMA_TICKS_TO_US(start - c->at);

		if (us < 1600 && c->at >= start - TDMA_US_TO_TICKS(1600)) {
			b = us < 200 ? 1 : us < 400 ? 2 : us < 600 ? 3 : us < 800 ? 4 : 5;
		}
		break;
	}
	op_vs_call[err][b]++;
}

/* ---- modem time ------------------------------------------------------------- */

static struct k_spinlock time_lock;
static uint64_t last_mt; /* modem time of the newest event */
static int64_t last_kt;  /* kernel ticks when it was received */

static void time_note(uint64_t mt)
{
	k_spinlock_key_t key;

	if (mt == 0) {
		return;
	}
	key = k_spin_lock(&time_lock);
	if (last_mt) {
		uint64_t est = last_mt + (uint64_t)(k_uptime_ticks() - last_kt) *
						 TDMA_TICKS_PER_SEC /
						 CONFIG_SYS_CLOCK_TICKS_PER_SEC;

		if (mt > est) {
			uint32_t us = (uint32_t)TDMA_TICKS_TO_US(mt - est);

			st.tb_behind_max_us = MAX(st.tb_behind_max_us, us);
			st.tb_hist[us < 100 ? 0 : us < 300 ? 1 : us < 500 ? 2 : 3]++;
		}
	}
	if (mt > last_mt) {
		last_mt = mt;
		last_kt = k_uptime_ticks();
	}
	k_spin_unlock(&time_lock, key);
}

uint64_t tdma_nrf_now(void)
{
	k_spinlock_key_t key = k_spin_lock(&time_lock);
	uint64_t mt = last_mt;
	int64_t kt = last_kt;

	k_spin_unlock(&time_lock, key);
	return mt + (uint64_t)(k_uptime_ticks() - kt) * TDMA_TICKS_PER_SEC /
			    CONFIG_SYS_CLOCK_TICKS_PER_SEC;
}

/*
 * The kernel tick at which tdma_nrf_now() reaches mt, as an absolute timeout:
 * a relative K_USEC() is rounded up to whole ticks and counted from the next
 * tick, so the MAC thread would wake up to two ticks (61 us) after its commit
 * was due.
 */
k_timeout_t tdma_nrf_until(uint64_t mt)
{
	k_spinlock_key_t key = k_spin_lock(&time_lock);
	uint64_t base = last_mt;
	int64_t kt = last_kt;

	k_spin_unlock(&time_lock, key);
	if (mt <= base) {
		return K_TIMEOUT_ABS_TICKS(kt);
	}
	return K_TIMEOUT_ABS_TICKS(kt + (int64_t)(((mt - base) * CONFIG_SYS_CLOCK_TICKS_PER_SEC +
						   TDMA_TICKS_PER_SEC - 1) /
						  TDMA_TICKS_PER_SEC));
}

int64_t tdma_nrf_ms_since_event(void)
{
	k_spinlock_key_t key = k_spin_lock(&time_lock);
	int64_t kt = last_kt;

	k_spin_unlock(&time_lock, key);
	return k_ticks_to_ms_floor64(k_uptime_ticks() - kt);
}

/* ---- PHY events -> the queue -------------------------------------------------- */

/*
 * Messages are small; received payloads (up to 700 B) are copied once, in
 * the event handler, into a block of rx_data. Copying whole packets through
 * the queue cost two large memcpy per event (even op-complete ones), which
 * with a size-optimised libc took hundreds of microseconds of ISR and MAC
 * thread time on the modem and made TX commits miss the PHY's lead time.
 */
K_MSGQ_DEFINE(tdma_nrf_q, sizeof(struct tdma_nrf_msg), CONFIG_TDMA_NRF_EVT_QUEUE, 4);
K_MEM_SLAB_DEFINE_STATIC(rx_data, TDMA_PKT_MAX, CONFIG_TDMA_NRF_EVT_QUEUE / 2, 4);

/* Synchronous PHY control (init/configure/activate/deactivate). */
static K_SEM_DEFINE(ctl_sem, 0, 1);
static volatile int ctl_err;
static atomic_t activated;
static uint8_t cur_group; /* band group the PHY is configured for */

/* PCC of a reception, matched with its PDC by transaction id. */
static struct {
	bool valid;
	uint64_t stf;
	union nrf_modem_dect_phy_hdr hdr;
	int16_t rssi;
	int16_t snr;
} pcc_tab[16];

static struct tdma_nrf_msg isr_msg; /* the event handler is not re-entered */

static void phy_post(struct tdma_nrf_msg *m)
{
	if (k_msgq_put(&tdma_nrf_q, m, K_NO_WAIT)) {
		st.q_drop++;
	}
}

static bool test_evt(uint32_t handle, const struct nrf_modem_dect_phy_event *evt)
{
	return (handle & TDMA_NRF_H_TEST) && hooks.test_evt && hooks.test_evt(evt);
}

static void phy_handler(const struct nrf_modem_dect_phy_event *evt)
{
	struct tdma_nrf_msg *m = &isr_msg;

	time_note(evt->time);

	switch (evt->id) {
	case NRF_MODEM_DECT_PHY_EVT_INIT:
		ctl_err = evt->init.err;
		k_sem_give(&ctl_sem);
		break;
	case NRF_MODEM_DECT_PHY_EVT_CONFIGURE:
		ctl_err = evt->configure.err;
		k_sem_give(&ctl_sem);
		break;
	case NRF_MODEM_DECT_PHY_EVT_ACTIVATE:
		ctl_err = evt->activate.err;
		k_sem_give(&ctl_sem);
		break;
	case NRF_MODEM_DECT_PHY_EVT_DEACTIVATE:
		ctl_err = evt->deactivate.err;
		k_sem_give(&ctl_sem);
		break;
	case NRF_MODEM_DECT_PHY_EVT_BANDS:
		ctl_err = evt->band_get.err;
		n_bands = 0;
		for (uint32_t i = 0; i < evt->band_get.band_count && n_bands < MAX_BANDS; i++) {
			bands[n_bands++] = evt->band_get.band[i];
		}
		k_sem_give(&ctl_sem);
		break;
	case NRF_MODEM_DECT_PHY_EVT_PCC: {
		const struct nrf_modem_dect_phy_pcc_event *p = &evt->pcc;
		int i = p->transaction_id & 15;

		if (test_evt(p->handle, evt)) {
			break;
		}
		pcc_tab[i].valid =
			p->header_status == NRF_MODEM_DECT_PHY_HDR_STATUS_VALID && p->phy_type == 1;
		pcc_tab[i].stf = p->stf_start_time;
		pcc_tab[i].hdr = p->hdr;
		pcc_tab[i].rssi = p->rssi_2 / 2;
		pcc_tab[i].snr = p->snr;
		if ((p->handle & PH_SCAN) &&
		    p->header_status == NRF_MODEM_DECT_PHY_HDR_STATUS_VALID) {
			/* type 1 and 2: short network id, then the transmitter id */
			m->kind = TDMA_NRF_MSG_PCC;
			m->handle = p->handle;
			m->rssi = p->rssi_2 / 2;
			m->crc_ok = p->phy_type == 1;
			m->arg = p->hdr.type_2[1] | (uint32_t)p->hdr.type_2[2] << 16 |
				 (uint32_t)p->hdr.type_2[3] << 8;
			phy_post(m);
			st.pcc_fwd++;
		}
		break;
	}
	case NRF_MODEM_DECT_PHY_EVT_RSSI: {
		/* RSSI-1 per symbol, 5 symbols per subslot: one max per subslot */
		const struct nrf_modem_dect_phy_rssi_event *r = &evt->rssi;
		int8_t mx = INT8_MIN;
		bool any = false;

		st.rssi_evts++;
		m->kind = TDMA_NRF_MSG_RSSI;
		m->handle = r->handle;
		m->n = 0;
		for (uint16_t k = 0; k < r->meas_len; k++) {
			int8_t v = r->meas[k];

			if (v != NRF_MODEM_DECT_PHY_RSSI_NOT_MEASURED) {
				mx = MAX(mx, v);
				any = true;
			}
			if (k % 5 == 4 || k + 1 == r->meas_len) {
				if (any) {
					m->ss[m->n++] = mx;
				}
				mx = INT8_MIN;
				any = false;
				if (m->n == TDMA_NRF_SS_MAX) {
					phy_post(m);
					m->n = 0;
				}
			}
		}
		if (m->n) {
			phy_post(m);
		}
		break;
	}
	case NRF_MODEM_DECT_PHY_EVT_PDC: {
		const struct nrf_modem_dect_phy_pdc_event *p = &evt->pdc;
		int i = p->transaction_id & 15;

		if (test_evt(p->handle, evt)) {
			pcc_tab[i].valid = false;
			break;
		}
		if (!pcc_tab[i].valid) {
			st.pdc_no_pcc++;
			break;
		}
		pcc_tab[i].valid = false;
		m->kind = TDMA_NRF_MSG_RX;
		m->handle = p->handle;
		m->stf = pcc_tab[i].stf;
		m->hdr = pcc_tab[i].hdr;
		m->rssi = pcc_tab[i].rssi;
		m->snr = pcc_tab[i].snr;
		m->crc_ok = true;
		if (k_mem_slab_alloc(&rx_data, (void **)&m->data, K_NO_WAIT)) {
			st.q_drop++;
			break;
		}
		m->len = MIN(p->len, TDMA_PKT_MAX);
		{
			uint32_t c0 = DWT->CYCCNT;

			memcpy(m->data, p->data, m->len);
			m->cyc = DWT->CYCCNT;
			if (m->len > 300) {
				st.rxl_isr_cyc += m->cyc - c0;
			}
		}
		if (k_msgq_put(&tdma_nrf_q, m, K_NO_WAIT)) {
			st.q_drop++;
			k_mem_slab_free(&rx_data, m->data);
		}
		break;
	}
	case NRF_MODEM_DECT_PHY_EVT_PCC_ERROR:
		st.pcc_err++;
		break;
	case NRF_MODEM_DECT_PHY_EVT_PDC_ERROR:
		if (test_evt(evt->pdc_crc_err.handle, evt)) {
			pcc_tab[evt->pdc_crc_err.transaction_id & 15].valid = false;
			break;
		}
		st.pdc_err++;
		pcc_tab[evt->pdc_crc_err.transaction_id & 15].valid = false;
		break;
	case NRF_MODEM_DECT_PHY_EVT_COMPLETED:
		if (test_evt(evt->op_complete.handle, evt)) {
			break;
		}
		m->kind = TDMA_NRF_MSG_DONE;
		m->handle = evt->op_complete.handle;
		m->err = evt->op_complete.err;
		m->stf = evt->time;
		phy_post(m);
		break;
	case NRF_MODEM_DECT_PHY_EVT_REJECT:
		st.reject++;
		break;
	default:
		break;
	}
}

int tdma_nrf_msg_get(struct tdma_nrf_msg *m, k_timeout_t timeout)
{
	return k_msgq_get(&tdma_nrf_q, m, timeout);
}

int tdma_nrf_msg_peek(struct tdma_nrf_msg *m)
{
	return k_msgq_peek(&tdma_nrf_q, m);
}

uint32_t tdma_nrf_msg_pending(void)
{
	return k_msgq_num_used_get(&tdma_nrf_q);
}

int tdma_nrf_post_ctl(uint8_t ctl, uint32_t arg, k_timeout_t timeout)
{
	struct tdma_nrf_msg m = {.kind = TDMA_NRF_MSG_CTL, .ctl = ctl, .arg = arg};

	if (k_msgq_put(&tdma_nrf_q, &m, timeout)) {
		st.q_drop++;
		return -ENOBUFS;
	}
	return 0;
}

/* ---- tdma_port ------------------------------------------------------------- */

static uint64_t port_now(void *ctx)
{
	ARG_UNUSED(ctx);
	return tdma_nrf_now();
}

void tdma_nrf_fill_rx(struct nrf_modem_dect_phy_rx_params *p, uint32_t handle, uint64_t start,
		      uint32_t dur, uint16_t ch, bool scan)
{
	memset(p, 0, sizeof(*p));
	p->start_time = start;
	p->handle = handle;
	p->network_id = network_id;
	p->mode = NRF_MODEM_DECT_PHY_RX_MODE_CONTINUOUS;
	p->rssi_interval = NRF_MODEM_DECT_PHY_RSSI_INTERVAL_OFF;
	p->link_id = NRF_MODEM_DECT_PHY_LINK_UNSPECIFIED;
	p->rssi_level = 0;
	p->carrier = ch;
	p->duration = dur;
	p->filter.short_network_id = network_id & 0xff;
	p->filter.is_short_network_id_used = 1;
	p->filter.receiver_identity = 0;
	if (scan) {
		/* every network, and RSSI-1 reported every 12 slots (and at the end) */
		p->filter.is_short_network_id_used = 0;
		p->rssi_interval = NRF_MODEM_DECT_PHY_RSSI_INTERVAL_12_SLOTS;
	}
}

static void lead_note(int kind, uint64_t start, uint64_t now)
{
	uint32_t us = start > now ? (uint32_t)TDMA_TICKS_TO_US(start - now) : 0;
	uint32_t b = us < 500 ? 0 : us >= 900 ? 5 : (us - 400) / 100;

	st.lead_hist[kind][b]++;
}

/*
 * Quiet window before every op (CONFIG_TDMA_NRF_QUIET_US / _LATE_US): the
 * modem fails an accepted op with OP_TIMEOUT (0x1005) when another op request
 * reaches it ~0.23-0.6 ms before that op's start (every failure seen had a
 * call 200-600 us before; none with a call < 200 or 800-1600 us before; the
 * modem reports the failure ~230 us before the start, so it sets the op up
 * then). A call that would land in [start - QUIET, start - LATE) of an op
 * already handed over waits until start - LATE, as long as its own op then
 * still has `need` ticks (the PHY lead + margin: the burst is built and sealed
 * already). Not later: a request the modem takes while the op runs delayed
 * that op's reception (idle DL probes +0.24 ms when held to the start, +0.05
 * ms to start - 200 us). MAC thread, MAC lock held; waits at most QUIET - LATE.
 */
static void quiet_wait(uint64_t start, uint32_t need)
{
	const uint64_t q = TDMA_US_TO_TICKS(quiet_us), late = TDMA_US_TO_TICKS(quiet_late_us);
	uint64_t now = tdma_nrf_now(), sp = UINT64_MAX;

	if (q <= late) {
		return;
	}
	for (int i = 0; i < CONFIG_TDMA_NRF_OPS; i++) {
		const struct port_op *o = &port_ops[i];

		/* (stale ops too: they are still queued in the modem) */
		if (o->used && o->start > now && o->start < sp) {
			sp = o->start;
		}
	}
	if (sp == UINT64_MAX || sp - now >= q || sp - now <= late) {
		return;
	}
	if (sp >= start || start < sp - late + need) {
		st.quiet_tight++;
		return;
	}
	st.quiet_wait++;
	st.quiet_wait_max_us =
		MAX(st.quiet_wait_max_us, (uint32_t)TDMA_TICKS_TO_US(sp - late - now));
	if (hooks.trace_quiet) {
		hooks.trace_quiet(sp, (uint32_t)TDMA_TICKS_TO_US(sp - late - now));
	}
	k_sleep(tdma_nrf_until(sp - late));
	{
		uint64_t t = tdma_nrf_now();

		st.quiet_ticks += t > now ? t - now : 0;
	}
}

#define QUIET_NEED_RX      (TDMA_PHY_LEAD_RX_TICKS + TDMA_US_TO_TICKS(150))
#define QUIET_NEED_TX      (TDMA_PHY_LEAD_TX_TICKS + TDMA_US_TO_TICKS(150))
#define QUIET_NEED_TX_LONG (QUIET_NEED_TX + TDMA_US_TO_TICKS(300)) /* > 300 B: the copy */

static int rx_op(uint8_t inst, uint32_t handle, uint64_t start, uint32_t duration, uint16_t ch,
		 bool scan)
{
	struct nrf_modem_dect_phy_rx_params p;
	struct port_op *op;
	int err;

	if (!tdma_nrf_carrier_ok(ch)) {
		return -EINVAL;
	}
	op = pop_new(inst, handle, scan);
	if (!op) {
		st.pool_full++;
		return -ENOMEM;
	}
	tdma_nrf_fill_rx(&p, op->phy_handle, start, duration, ch, scan);
	quiet_wait(start, QUIET_NEED_RX);
	{
		uint64_t t0 = tdma_nrf_now();

		lead_note(3, start, t0);
		op->start = start ? start : t0; /* (asap: from the call on, for the reaper) */
		op->dur = duration;
		op->lead_us = start > t0 ? (uint16_t)MIN(TDMA_TICKS_TO_US(start - t0), 65535) : 0;
		op->call_cyc = call_note(scan ? 5 : 1, start, duration, 0);
		err = nrf_modem_dect_phy_rx(&p);
		uint32_t us = (DWT->CYCCNT - op->call_cyc) / CYC_PER_US;

		st.rx_call_max_us = MAX(st.rx_call_max_us, us);
	}
	if (err) {
		op->used = false;
		st.rx_refused++;
		return -EIO;
	}
	return 0;
}

static int port_rx(void *ctx, uint32_t handle, uint64_t start, uint32_t duration, uint16_t ch)
{
	return rx_op(tdma_nrf_ctx_inst(ctx), handle, start, duration, ch, false);
}

static int port_scan(void *ctx, uint32_t handle, uint64_t start, uint32_t duration, uint16_t ch)
{
	return rx_op(tdma_nrf_ctx_inst(ctx), handle, start, duration, ch, true);
}

static int port_rssi(void *ctx, uint32_t handle, uint64_t start, uint32_t duration, uint16_t ch)
{
	struct port_op *op;
	int err;

	if (!tdma_nrf_carrier_ok(ch)) {
		return -EINVAL;
	}
	op = pop_new(tdma_nrf_ctx_inst(ctx), handle, true);
	if (!op) {
		st.pool_full++;
		return -ENOMEM;
	}
	struct nrf_modem_dect_phy_rssi_params p = {
		.start_time = start,
		.handle = op->phy_handle,
		.carrier = ch,
		.duration = DIV_ROUND_UP(duration, TDMA_SUBSLOT_TICKS), /* in subslots */
		.reporting_interval = NRF_MODEM_DECT_PHY_RSSI_INTERVAL_12_SLOTS,
	};

	quiet_wait(start, QUIET_NEED_RX);
	op->start = start;
	op->dur = duration;
	op->call_cyc = call_note(3, start, duration, 0);
	err = nrf_modem_dect_phy_rssi(&p);
	if (err) {
		op->used = false;
		st.rx_refused++;
		return -EIO;
	}
	return 0;
}

static int port_rx_stop(void *ctx, uint32_t handle)
{
	struct port_op *op = pop_by_mac(tdma_nrf_ctx_inst(ctx), handle);

	if (!op) {
		return -ENOENT;
	}
	(void)call_note(4, op->start, 0, 0);
	return nrf_modem_dect_phy_cancel(op->phy_handle) ? -EIO : 0;
}

static int port_tx(void *ctx, uint32_t handle, uint64_t start, uint16_t ch, const uint8_t *phy_hdr,
		   size_t hdr_len, const uint8_t *payload, size_t len, uint8_t subslots,
		   uint8_t mcs, uint32_t lbt_ticks, int8_t lbt_dbm)
{
	union nrf_modem_dect_phy_hdr h;
	struct tdma_phy_hdr th;
	struct port_op *op;
	uint8_t pwr = tx_pwr_idx;
	uint8_t inst = tdma_nrf_ctx_inst(ctx);
	const struct tdma_mac *im = inst_mac[inst];
	uint64_t ref_start = im ? im->ref_start : 0;
	bool ft_role = inst_ft[inst];
	int err;

	if (!tdma_nrf_carrier_ok(ch) || tdma_phy_hdr_decode(phy_hdr, hdr_len, &th) ||
	    subslots == 0 || subslots > 16 || len > tdma_tbs(mcs, subslots) ||
	    (lbt_ticks && (lbt_ticks < NRF_MODEM_DECT_LBT_PERIOD_MIN ||
			   lbt_ticks > NRF_MODEM_DECT_LBT_PERIOD_MAX))) {
		return -EINVAL;
	}

	memset(&h, 0, sizeof(h));
	h.hdr_type_2.packet_length = subslots - 1;
	h.hdr_type_2.packet_length_type = 0; /* subslots */
	h.hdr_type_2.header_format = 1;
	h.hdr_type_2.short_network_id = th.short_nwid;
	h.hdr_type_2.transmitter_id_hi = th.tx_short >> 8;
	h.hdr_type_2.transmitter_id_lo = th.tx_short & 0xff;
	h.hdr_type_2.df_mcs = mcs;
	h.hdr_type_2.transmit_power = pwr;
	h.hdr_type_2.receiver_id_hi = th.rx_short >> 8;
	h.hdr_type_2.receiver_id_lo = th.rx_short & 0xff;
	h.hdr_type_2.num_spatial_streams = 0;

	op = pop_new(inst, handle, false);
	if (!op) {
		st.pool_full++;
		return -ENOMEM;
	}
	struct nrf_modem_dect_phy_tx_params p = {
		.start_time = start,
		.handle = op->phy_handle,
		.network_id = network_id,
		.phy_type = 1,
		.lbt_rssi_threshold_max = lbt_ticks ? lbt_dbm : 0,
		.carrier = ch,
		.lbt_period = lbt_ticks,
		.phy_header = &h,
		.bs_cqi = NRF_MODEM_DECT_PHY_BS_CQI_NOT_USED,
		.data = (uint8_t *)payload,
		.data_size = len,
	};

	if (!lbt_ticks) {
		quiet_wait(start, len > 300 ? QUIET_NEED_TX_LONG : QUIET_NEED_TX);
	}
	{
		uint64_t t0 = tdma_nrf_now();
		bool beacon = (start - ref_start) % TDMA_FRAME_TICKS < TDMA_SUBSLOT_TICKS;

		op->tx_len = (uint16_t)len;
		op->start = start;
		op->lead_us = start > t0 ? (uint16_t)MIN(TDMA_TICKS_TO_US(start - t0), 65535) : 0;
		op->lbt = lbt_ticks != 0;
		op->dur = (uint32_t)subslots * TDMA_SUBSLOT_TICKS;
		st.lead_min_us = MIN(st.lead_min_us,
				     start > t0 ? (uint32_t)TDMA_TICKS_TO_US(start - t0) : 0);
		if (ft_role && subslots < TDMA_LRX_MIN_SS) {
			uint32_t us = t0 > wake_mt ? (uint32_t)TDMA_TICKS_TO_US(t0 - wake_mt) : 0;

			st.build_hist[beacon][us < 200   ? 0
					      : us < 400 ? 1
					      : us < 600 ? 2
					      : us < 800 ? 3
							 : 4]++;
		}
		lead_note(subslots >= TDMA_LRX_MIN_SS ? 2
			  : !ft_role                  ? 1
			  : beacon                    ? 4
						      : 0,
			  start, t0);
		op->call_cyc =
			call_note(2, start, (uint32_t)subslots * TDMA_SUBSLOT_TICKS, (uint16_t)len);
		err = nrf_modem_dect_phy_tx(&p);
		uint64_t t1 = tdma_nrf_now();

		if (t1 > t0 && (uint32_t)TDMA_TICKS_TO_US(t1 - t0) > st.tx_call_max_us) {
			st.tx_call_max_us = (uint32_t)TDMA_TICKS_TO_US(t1 - t0);
			st.tx_call_max_len = len;
		}
	}
	if (err) {
		op->used = false;
		st.tx_refused++;
		return -EIO;
	}
	if (subslots >= 4) {
		st.bursts_long++;
		st.pay_long += len;
		st.tbs_long += tdma_tbs(mcs, subslots);
	} else {
		st.bursts_short++;
		st.pay_short += len;
		st.tbs_short += tdma_tbs(mcs, subslots);
	}
	return 0;
}

void tdma_nrf_port_init(struct tdma_port *p, uint8_t inst)
{
	memset(p, 0, sizeof(*p));
	p->ctx = tdma_nrf_ctx(inst);
	p->now = port_now;
	p->rx = port_rx;
	p->rx_stop = port_rx_stop;
	p->tx = port_tx;
	p->rssi = port_rssi;
	p->scan = port_scan;
}

/* Received PCC header (ETSI type 2) -> the MAC's packed stand-in. */
static void hdr_to_mac(const union nrf_modem_dect_phy_hdr *h, uint8_t out[TDMA_PHY_HDR_LEN])
{
	struct tdma_phy_hdr th = {
		.subslots = h->hdr_type_2.packet_length + 1,
		.short_nwid = h->hdr_type_2.short_network_id,
		.tx_short = (uint16_t)(h->hdr_type_2.transmitter_id_hi << 8 |
				       h->hdr_type_2.transmitter_id_lo),
		.rx_short = (uint16_t)(h->hdr_type_2.receiver_id_hi << 8 |
				       h->hdr_type_2.receiver_id_lo),
		.tx_power = h->hdr_type_2.transmit_power,
		.mcs = h->hdr_type_2.df_mcs,
	};

	tdma_phy_hdr_encode(&th, out, TDMA_PHY_HDR_LEN);
}

/* ---- dispatch: queued events -> the MAC instances ------------------------------- */

static int32_t rel_us(uint64_t t, uint64_t ref)
{
	return (int32_t)(((int64_t)t - (int64_t)ref) * 1000000 / TDMA_TICKS_PER_SEC);
}

static void errlog_note(const struct port_op *op, const struct tdma_nrf_msg *m, int err,
			struct tdma_mac *im, uint32_t mac_handle)
{
	uint32_t ei = errlog_n % ERRLOG_N;
	struct errlog *e = &errlog[errlog_n++ % ERRLOG_N];

	/* the last calls made, oldest first; times vs the failed op's start */
	for (int k = 0; k < ERR_CALLS; k++) {
		const struct callrec *c = &calls[(calls_n - ERR_CALLS + k) % CALLS_N];

		errcalls[ei][k] = (struct errcall){
			.call_rel_us = rel_us(c->at, op->start),
			.start_rel_us = rel_us(c->start, op->start),
			.end_rel_us = rel_us(c->start + c->dur, op->start),
			.len = c->len,
			.kind = c->kind,
		};
	}
	for (int k = 0; k < ERR_PREV; k++) {
		const struct ophist *h = &ophist[(ophist_n - 1 - k) % OPHIST_N];

		errprev[ei][k] = (struct errprev){
			.start_rel_us = rel_us(h->start, op->start),
			.end_rel_us = rel_us(h->start + h->dur, op->start),
			.done_rel_us = rel_us(h->done_mt, op->start),
			.err = h->err,
			.len = h->len,
			.tx = h->tx,
		};
		if (ophist_n <= (uint32_t)k + 1) {
			break;
		}
	}
	*e = (struct errlog){
		.err = err,
		.len = op->tx_len,
		.lead_us = op->lead_us,
		.evt_vs_start_us =
			(int32_t)((int64_t)(m->stf - op->start) * 1000000 / TDMA_TICKS_PER_SEC),
		.slot = 0xff,
	};
	if (im) {
		uint8_t sl, us;
		uint32_t fr;
		uint16_t och;

		if (tdma_op_info(im, mac_handle, &sl, &us, &fr, &och) == 0) {
			e->slot = sl | (op->inst ? 0x80 : 0);
			e->use = us;
			e->frame = fr;
		}
	}
}

static void dispatch_rx(const struct tdma_nrf_msg *m)
{
	struct port_op *op = pop_by_phy(m->handle);
	struct tdma_mac *im = op ? pop_mac(op) : NULL;
	uint8_t hdr[TDMA_PHY_HDR_LEN];

	if (!im) {
		k_mem_slab_free(&rx_data, m->data);
		return;
	}
	if (hooks.before_mac) {
		hooks.before_mac(op->inst);
	}
	hdr_to_mac(&m->hdr, hdr);
	if (hooks.drop_tx) {
		struct tdma_phy_hdr ph;

		if (tdma_phy_hdr_decode(hdr, sizeof(hdr), &ph) == 0 && hooks.drop_tx(ph.tx_short)) {
			k_mem_slab_free(&rx_data, m->data);
			return;
		}
	}
	st.last_rssi = m->rssi;
	st.last_snr = m->snr;
	{
		uint64_t t0 = tdma_nrf_now();
		uint32_t c0 = DWT->CYCCNT;

		tdma_on_rx(im, op->mac_handle, m->stf, m->rssi, m->snr, hdr, sizeof(hdr), m->data,
			   m->len, m->crc_ok);
		uint64_t t1 = tdma_nrf_now();

		if (op->inst) {
			uint32_t w = c0 - m->cyc;

			st.rxc_n++;
			st.rxc_sum += w;
			st.rxc_max = MAX(st.rxc_max, w);
		}
		if (m->len > 300) {
			st.rxl_n++;
			st.rxl_wait_cyc += c0 - m->cyc;
			st.rxl_cyc += DWT->CYCCNT - c0;
		}
		if (t1 > t0 && (uint32_t)TDMA_TICKS_TO_US(t1 - t0) > st.on_rx_max_us) {
			st.on_rx_max_us = (uint32_t)TDMA_TICKS_TO_US(t1 - t0);
			st.rx_len_at_max = m->len;
		}
	}
	k_mem_slab_free(&rx_data, m->data);
	if (hooks.after_rx) {
		hooks.after_rx(op->inst);
	}
}

static void dispatch_done(const struct tdma_nrf_msg *m)
{
	struct port_op *op = pop_by_phy(m->handle);
	uint32_t mac_handle;
	struct tdma_mac *im;
	bool op_was_tx;
	uint16_t op_len;
	uint8_t op_inst;
	int err;

	if (!op) {
		return;
	}
	mac_handle = op->mac_handle;
	im = pop_mac(op);
	op_inst = op->inst;
	op_was_tx = op->tx_len > 0;
	op_len = op->tx_len;
	op->used = false;
	err = m->err;
	if (!(op->phy_handle & PH_SCAN)) {
		uint16_t l = op->lead_us;
		uint32_t b = l < 500 ? 0 : l >= 900 ? 5 : (l - 400) / 100;
		bool bad = err && err != NRF_MODEM_DECT_PHY_ERR_OP_CANCELED &&
			   err != NRF_MODEM_DECT_PHY_ERR_LBT_CHANNEL_BUSY;

		if (!op_was_tx) {
			(bad ? err_rx_lead_hist : ok_rx_lead_hist)[b]++;
		}
		op_vs_call_note(op->start, op->call_cyc, bad);
	}
	if (err && err != NRF_MODEM_DECT_PHY_ERR_OP_CANCELED &&
	    err != NRF_MODEM_DECT_PHY_ERR_LBT_CHANNEL_BUSY) {
		errlog_note(op, m, err, im, mac_handle);
	}
	ophist[ophist_n++ % OPHIST_N] = (struct ophist){
		.start = op->start,
		.done_mt = m->stf,
		.dur = op->dur,
		.err = err,
		.len = op->tx_len,
		.tx = op_was_tx,
	};
	if (err == NRF_MODEM_DECT_PHY_ERR_OP_CANCELED) {
		err = 0; /* rx_stop of a not yet started op */
	}
	if (err == NRF_MODEM_DECT_PHY_ERR_LBT_CHANNEL_BUSY && op_was_tx) {
		st.lbt_busy++;
		err = TDMA_ERR_LBT_BUSY; /* the MAC backs off; not a failure */
	} else if (err) {
		st.op_err++;
		st.last_op_err = err;
		if (!op_was_tx) {
			st.err_rx++;
		} else if (op_len > 300) {
			st.err_long_tx++;
		} else {
			st.err_short_tx++;
		}
	}
	if (im) {
		uint8_t sl, us;
		uint32_t fr;
		uint16_t och;

		if (err && err != TDMA_ERR_LBT_BUSY &&
		    tdma_op_info(im, mac_handle, &sl, &us, &fr, &och) == 0) {
			st.err_slot[sl < 7 ? sl : 7]++;
			if (st.op_err <= 30) {
				LOG_WRN("op err 0x%x: [%u] %s slot %u (use %u) frame %u carrier "
					"%u, "
					"%u B",
					err, op_inst, op_was_tx ? "TX" : "RX", sl, us, fr, och,
					op_len);
			}
		}
		if (hooks.before_mac) {
			hooks.before_mac(op_inst);
		}
		tdma_on_op_done(im, mac_handle, err);
	}
}

void tdma_nrf_dispatch(const struct tdma_nrf_msg *m)
{
	struct port_op *op;
	struct tdma_mac *im;

	switch (m->kind) {
	case TDMA_NRF_MSG_RX:
		dispatch_rx(m);
		break;
	case TDMA_NRF_MSG_DONE:
		dispatch_done(m);
		break;
	case TDMA_NRF_MSG_RSSI:
		op = pop_by_phy(m->handle);
		if (op && (im = pop_mac(op))) {
			tdma_on_rssi(im, op->mac_handle, m->ss, m->n);
		}
		break;
	case TDMA_NRF_MSG_PCC:
		op = pop_by_phy(m->handle);
		if (op && (im = pop_mac(op)) &&
		    !(hooks.drop_tx && hooks.drop_tx((uint16_t)(m->arg >> 8)))) {
			tdma_on_pcc(im, op->mac_handle, m->rssi, (uint8_t)m->arg,
				    (uint16_t)(m->arg >> 8), m->crc_ok);
		}
		break;
	default:
		break;
	}
}

/*
 * An op whose completion never came (its event was dropped: the event queue
 * overflows when a flash write stalls the CPU) would stay "in flight" in the
 * MAC forever: a PT never searches again (it waits for its ops to drain), a
 * relay's search is refused by the arbiter. 30 ms after its end it is
 * completed with -ETIMEDOUT.
 */
void tdma_nrf_reap(void)
{
	uint64_t now = tdma_nrf_now();

	for (int i = 0; i < CONFIG_TDMA_NRF_OPS; i++) {
		struct port_op *op = &port_ops[i];
		struct tdma_mac *im;

		if (!op->used || op->start + op->dur + TDMA_US_TO_TICKS(30000) > now) {
			continue;
		}
		im = pop_mac(op);
		op->used = false;
		st.op_reaped++;
		if (im) {
			tdma_on_op_done(im, op->mac_handle, -ETIMEDOUT);
		}
	}
}

/* ---- PHY bring-up -------------------------------------------------------------- */

static int phy_wait(const char *what)
{
	if (k_sem_take(&ctl_sem, K_SECONDS(10))) {
		LOG_ERR("DECT PHY %s: timeout", what);
		return -ETIMEDOUT;
	}
	if (ctl_err) {
		LOG_ERR("DECT PHY %s: err 0x%x", what, ctl_err);
		return -EIO;
	}
	return 0;
}

int tdma_nrf_configure(uint8_t group)
{
	struct nrf_modem_dect_phy_config_params cp = {
		.band_group_index = group, /* 0: ~1.9 GHz bands, 1: ~900 MHz (band 4) */
		.harq_rx_process_count = 4,
		.harq_rx_expiry_time_us = 5000000,
	};
	int err;

	k_sem_reset(&ctl_sem);
	err = nrf_modem_dect_phy_configure(&cp);
	if (!err) {
		err = phy_wait("configure");
	}
	if (!err) {
		cur_group = group;
	}
	return err;
}

int tdma_nrf_activate(void)
{
	int err;

	k_sem_reset(&ctl_sem);
	err = nrf_modem_dect_phy_activate(NRF_MODEM_DECT_PHY_RADIO_MODE_LOW_LATENCY);
	if (!err) {
		err = phy_wait("activate");
	}
	if (err) {
		return err;
	}
	atomic_set(&activated, 1);
	nrf_modem_dect_phy_time_get();
	return 0;
}

int tdma_nrf_deactivate(void)
{
	int err;

	nrf_modem_dect_phy_cancel(NRF_MODEM_DECT_PHY_HANDLE_CANCEL_ALL);
	k_sleep(K_MSEC(20));
	k_sem_reset(&ctl_sem);
	err = nrf_modem_dect_phy_deactivate();
	if (!err) {
		err = phy_wait("deactivate");
	}
	atomic_set(&activated, 0);
	return err;
}

int tdma_nrf_band_group(uint8_t group)
{
	int err;

	if (group == cur_group) {
		return 0;
	}
	LOG_INF("PHY band group %u -> %u", cur_group, group);
	err = tdma_nrf_deactivate();
	if (!err) {
		err = tdma_nrf_configure(group);
	}
	if (!err) {
		err = tdma_nrf_activate();
	}
	if (err) {
		LOG_ERR("band group change failed: %d", err);
	}
	return err;
}

bool tdma_nrf_activated(void)
{
	return atomic_get(&activated) != 0;
}

uint8_t tdma_nrf_cur_group(void)
{
	return cur_group;
}

void tdma_nrf_keepalive(void)
{
	if (atomic_get(&activated) && tdma_nrf_ms_since_event() > 500) {
		nrf_modem_dect_phy_time_get();
	}
}

int tdma_nrf_init(const struct tdma_nrf_hooks *h)
{
	int err;

	if (h) {
		hooks = *h;
	}
	/* DWT cycle counter for the RX path counters */
	DCB->DEMCR |= DCB_DEMCR_TRCENA_Msk;
	DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

	err = nrf_modem_lib_init();
	if (err) {
		LOG_ERR("nrf_modem_lib_init failed: %d", err);
		return err;
	}
	err = nrf_modem_dect_phy_event_handler_set(phy_handler);
	if (err) {
		return err;
	}
	k_sem_reset(&ctl_sem);
	err = nrf_modem_dect_phy_init();
	if (!err) {
		err = phy_wait("init");
	}
	if (err) {
		return err;
	}
	/* what the modem supports: bands, carrier ranges, power classes (before activation) */
	k_sem_reset(&ctl_sem);
	err = nrf_modem_dect_phy_band_get();
	if (!err) {
		err = phy_wait("band list");
	}
	if (err) {
		LOG_WRN("DECT PHY band list: %d; radio settings cannot be checked", err);
	}
	for (uint8_t i = 0; i < n_bands; i++) {
		LOG_INF("modem band %u: carriers %u-%u, group %u, power class %u (%d dBm), rx gain "
			"%d",
			bands[i].band_number, bands[i].min_carrier, bands[i].max_carrier,
			bands[i].band_group_index, bands[i].power_class,
			tdma_nrf_class_dbm(bands[i].power_class), bands[i].rx_gain);
	}
	return 0;
}

/* ---- diagnostics ------------------------------------------------------------------ */

const struct tdma_nrf_stats *tdma_nrf_get_stats(void)
{
	return &st;
}

#if defined(CONFIG_SHELL)
void tdma_nrf_print_errlog(const struct shell *sh, bool clear)
{
	uint32_t n = errlog_n;

	shell_print(
		sh,
		"RX lead at call (us) ok : <500 %u, -600 %u, -700 %u, -800 %u, -900 %u, more %u",
		ok_rx_lead_hist[0], ok_rx_lead_hist[1], ok_rx_lead_hist[2], ok_rx_lead_hist[3],
		ok_rx_lead_hist[4], ok_rx_lead_hist[5]);
	shell_print(
		sh,
		"RX lead at call (us) err: <500 %u, -600 %u, -700 %u, -800 %u, -900 %u, more %u",
		err_rx_lead_hist[0], err_rx_lead_hist[1], err_rx_lead_hist[2], err_rx_lead_hist[3],
		err_rx_lead_hist[4], err_rx_lead_hist[5]);
	for (int k = 0; k < 2; k++) {
		shell_print(sh,
			    "ops %s by the last other call before the start: none %u, <200 us %u, "
			    "<400 %u, <600 %u, <800 %u, <1600 %u",
			    k ? "err" : "ok ", op_vs_call[k][0], op_vs_call[k][1], op_vs_call[k][2],
			    op_vs_call[k][3], op_vs_call[k][4], op_vs_call[k][5]);
	}
	shell_print(sh, "rx() call max %u us; %u op errors logged (last %d)", st.rx_call_max_us, n,
		    MIN(n, ERRLOG_N));
	for (uint32_t i = n > ERRLOG_N ? n - ERRLOG_N : 0; i < n; i++) {
		const struct errlog *e = &errlog[i % ERRLOG_N];

		shell_print(sh,
			    "  err 0x%x %s %u B slot %u use %u frame %u: lead %u us at the call, "
			    "reported %d us after the start (%d after the call)",
			    e->err, e->len ? "TX" : "RX", e->len, e->slot, e->use, e->frame,
			    e->lead_us, e->evt_vs_start_us,
			    e->evt_vs_start_us + (int32_t)e->lead_us);
		for (int k = 0; k < ERR_CALLS; k++) {
			static const char *const kn[6] = {"?",    "rx",     "tx",
							  "rssi", "cancel", "scan"};
			const struct errcall *q = &errcalls[i % ERRLOG_N][k];

			shell_print(sh, "     call %s %u B at %d: start %d end %d", kn[q->kind % 6],
				    q->len, q->call_rel_us, q->start_rel_us, q->end_rel_us);
		}
		for (int k = 0; k < ERR_PREV; k++) {
			const struct errprev *q = &errprev[i % ERRLOG_N][k];

			shell_print(sh, "     prev %d: %s %u B start %d end %d done %d us err 0x%x",
				    k, q->tx ? "TX" : "RX", q->len, q->start_rel_us, q->end_rel_us,
				    q->done_rel_us, q->err);
		}
	}
	if (clear) {
		errlog_n = 0;
		memset(ok_rx_lead_hist, 0, sizeof(ok_rx_lead_hist));
		memset(err_rx_lead_hist, 0, sizeof(err_rx_lead_hist));
		st.rx_call_max_us = 0;
		memset(op_vs_call, 0, sizeof(op_vs_call));
	}
}
#endif
