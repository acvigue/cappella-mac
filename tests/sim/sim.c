/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* Discrete-event simulator: virtual clock, fake PHYs, shared air. */

#include "sim.h"
#include <cappella/tdma_sec_ref_crypto.h>
#include <cappella/tdma_pdu.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum ev_type {
	EV_LBT,
	EV_TX_END,
	EV_RX_DELIVER,
	EV_RSSI,
	EV_OP_DONE,
	EV_APP,
	EV_TICK,
};

struct ev {
	uint64_t t;
	uint64_t seq;
	uint8_t type;
	uint8_t node;
	uint8_t crc;
	uint8_t w;  /* MAC instance of the node (struct sim_op.which) */
	int8_t snr; /* RX_DELIVER: effective SNR */
	uint32_t a; /* handle / air index */
	uint32_t b; /* generation */
	sim_fn fn;
	void *arg;
};

#define SIM_PKT_MAX 704 /* MCS 4, 8 subslots */

struct air {
	bool used;
	bool cancelled;
	int node;
	uint16_t ch;
	uint8_t mcs;
	uint8_t subslots;
	uint64_t t_start; /* on air, including TX jitter */
	uint64_t t_end;
	uint64_t lbt_t0; /* LBT window [lbt_t0, t_start); 0 = no LBT */
	int8_t lbt_dbm;
	uint32_t handle;
	uint8_t hdr[TDMA_PHY_HDR_LEN];
	uint8_t pl[SIM_PKT_MAX]; /* zero padded to the TBS like the modem does */
	size_t len;              /* = TBS */
};

/* Measured PHY behaviour (docs/phy-timing.md). */
#define LEAD_TX     TDMA_US_TO_TICKS(465)
#define LEAD_RX     TDMA_US_TO_TICKS(390)
#define RX_PRE_MIN  TDMA_US_TO_TICKS(1)        /* RX window must open >= 1 us before the STF */
#define RX_DONE_LAT TDMA_US_TO_TICKS(250)      /* RX op_done after the window (after any PDC) */
#define JITTER      20                         /* +-20 ticks TX start jitter */
#define RSSI_CHUNK  (24u * TDMA_SUBSLOT_TICKS) /* RSSI reported per 12 slots (5 ms) */

/* Minimum idle between two ops of one radio, from the nominal end of the first. */
static uint64_t op_gap(bool first_tx, bool second_tx)
{
	if (first_tx) {
		return second_tx ? TDMA_US_TO_TICKS(285) : TDMA_US_TO_TICKS(245);
	}
	return second_tx ? TDMA_US_TO_TICKS(225) : TDMA_US_TO_TICKS(240);
}

/* PDC event after the end of a burst: 110-240 us, growing with size and MCS. */
uint64_t sim_pdc_ticks(uint8_t subslots, uint8_t mcs)
{
	unsigned int us = 110 + 30u * subslots + 15u * mcs;

	return TDMA_US_TO_TICKS(us > 240 ? 240 : us);
}

static struct sim the_sim;
static struct ev heap[SIM_MAX_EVENTS];
static size_t heap_n;
static uint64_t ev_seq;
static struct air air[SIM_MAX_AIR];

/* ---- event heap ------------------------------------------------------------- */

static bool ev_less(const struct ev *x, const struct ev *y)
{
	if (x->t != y->t) {
		return x->t < y->t;
	}
	if (x->type != y->type) {
		return x->type < y->type;
	}
	return x->seq < y->seq;
}

static void push(struct ev e)
{
	size_t i;

	if (heap_n >= SIM_MAX_EVENTS) {
		fprintf(stderr, "sim: event heap full\n");
		abort();
	}
	e.seq = ev_seq++;
	i = heap_n++;
	heap[i] = e;
	while (i > 0) {
		size_t p = (i - 1) / 2;

		if (!ev_less(&heap[i], &heap[p])) {
			break;
		}
		struct ev tmp = heap[i];

		heap[i] = heap[p];
		heap[p] = tmp;
		i = p;
	}
}

static struct ev pop(void)
{
	struct ev top = heap[0];
	size_t i = 0;

	heap[0] = heap[--heap_n];
	for (;;) {
		size_t l = 2 * i + 1, r = l + 1, m = i;

		if (l < heap_n && ev_less(&heap[l], &heap[m])) {
			m = l;
		}
		if (r < heap_n && ev_less(&heap[r], &heap[m])) {
			m = r;
		}
		if (m == i) {
			break;
		}
		struct ev tmp = heap[i];

		heap[i] = heap[m];
		heap[m] = tmp;
		i = m;
	}
	return top;
}

/* ---- clocks ------------------------------------------------------------------- */

/*
 * 128-bit products that cannot overflow (< 2^95). UBSan's overflow check of an
 * __int128 multiply needs compiler-rt's __muloti4, which clang does not link
 * with libgcc (Linux): not checked here.
 */
#if defined(__clang__)
#define NO_I128_OVF_CHECK __attribute__((no_sanitize("signed-integer-overflow")))
#else
#define NO_I128_OVF_CHECK
#endif

NO_I128_OVF_CHECK uint64_t sim_local(const struct sim_node *n, uint64_t t)
{
	__int128 v = (__int128)t * (1000000000 + n->ppb) / 1000000000;

	return (uint64_t)(v + n->offset);
}

/* Smallest true time whose local time is >= l. */
NO_I128_OVF_CHECK static uint64_t sim_true(const struct sim_node *n, uint64_t l)
{
	__int128 d = (__int128)l - n->offset;
	__int128 den = 1000000000 + n->ppb;
	uint64_t t;

	if (d <= 0) {
		return 0;
	}
	t = (uint64_t)((d * 1000000000 + den - 1) / den);
	while (t > 0 && sim_local(n, t - 1) >= l) {
		t--;
	}
	while (sim_local(n, t) < l) {
		t++;
	}
	return t;
}

uint64_t sim_rand(struct sim *s)
{
	/* xorshift64* */
	uint64_t x = s->rng;

	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	s->rng = x;
	return x * 0x2545F4914F6CDD1Dull;
}

/* ---- identities: network id and rd ids from a site number and a node number ---------- */

static uint32_t site_hash(void)
{
	return SIM_SITE_ID * 2654435761u;
}

uint32_t sim_network_id(void)
{
	uint32_t id = site_hash() ^ 0xa5a5a5a5u;

	if ((id & 0xff) == 0) {
		id |= 0x01;
	}
	if ((id & 0xffffff00) == 0) {
		id |= 0x0100;
	}
	return id;
}

uint32_t sim_rd_for_box(uint8_t box)
{
	return 0x10000000u | ((site_hash() & 0xffffu) << 8) | box;
}

/* ---- RSSI / interferers --------------------------------------------------------------- */

int sim_add_interferer(struct sim *s, uint16_t ch, int8_t dbm, uint64_t t_from, uint64_t t_to,
		       uint64_t period, uint64_t on)
{
	for (int i = 0; i < SIM_MAX_INTF; i++) {
		if (!s->intf[i].used) {
			s->intf[i] = (struct sim_intf){true, ch, dbm, t_from, t_to, period, on};
			return i;
		}
	}
	abort();
}

static bool intf_on(const struct sim_intf *f, uint64_t t0, uint64_t t1)
{
	uint64_t k;

	if (!f->used || t1 <= f->t_from || t0 >= f->t_to) {
		return false;
	}
	if (!f->period) {
		return true;
	}
	k = t0 > f->t_from ? (t0 - f->t_from) / f->period : 0;
	for (;; k++) {
		uint64_t b0 = f->t_from + k * f->period, b1 = b0 + f->on;

		if (b0 >= t1 || b0 >= f->t_to) {
			return false;
		}
		if (b1 > t0) {
			return true;
		}
	}
}

static int ch_dist(uint16_t a, uint16_t b)
{
	return a > b ? a - b : b - a;
}

/* Interferer level on ch (same carrier only: what hurts a packet). */
static int intf_level(const struct sim *s, uint16_t ch, uint64_t t0, uint64_t t1)
{
	int v = -128;

	for (int i = 0; i < SIM_MAX_INTF; i++) {
		const struct sim_intf *f = &s->intf[i];

		if (f->used && f->ch == ch && intf_on(f, t0, t1) && f->dbm > v) {
			v = f->dbm;
		}
	}
	return v;
}

int8_t sim_rssi_at(struct sim *s, int node, uint16_t ch, uint64_t t0, uint64_t t1)
{
	int v = SIM_NOISE_DBM;

	for (int i = 0; i < SIM_MAX_INTF; i++) {
		const struct sim_intf *f = &s->intf[i];
		int d;

		if (!f->used || ch_dist(f->ch, ch) > 1 || !intf_on(f, t0, t1)) {
			continue;
		}
		d = f->dbm - (f->ch != ch ? 6 : 0);
		v = d > v ? d : v;
	}
	for (int i = 0; i < SIM_MAX_AIR; i++) {
		const struct air *a = &air[i];
		int d;

		if (!a->used || a->cancelled || a->node == node || ch_dist(a->ch, ch) > 1 ||
		    a->t_start >= t1 || a->t_end <= t0) {
			continue;
		}
		d = SIM_RX_DBM - (a->ch != ch ? 6 : 0);
		v = d > v ? d : v;
	}
	return (int8_t)v;
}

/* ---- fake PHY ------------------------------------------------------------------- */

static void resched(struct sim_node *n);
static void relay_step(struct sim_node *n);

static struct sim_node *inst_node(void *ctx)
{
	return ((struct sim_inst *)ctx)->n;
}

static uint8_t inst_which(void *ctx)
{
	return ((struct sim_inst *)ctx)->which;
}

static struct tdma_mac *macof(struct sim_node *n, uint8_t which)
{
	return which ? &n->rmac : &n->mac;
}

static uint64_t port_now(void *ctx)
{
	struct sim_node *n = inst_node(ctx);

	return sim_local(n, n->sim->t);
}

/* A relay's radio arbiter (tdma_relay_away()). */
static int port_away(void *ctx, uint64_t start, uint32_t dur)
{
	struct sim_node *n = inst_node(ctx);

	return tdma_relay_away(&n->relay, macof(n, inst_which(ctx)), start, dur);
}

static struct sim_op *op_alloc(struct sim_node *n)
{
	for (int i = 0; i < SIM_NODE_OPS; i++) {
		if (!n->ops[i].used) {
			return &n->ops[i];
		}
	}
	return NULL;
}

static struct sim_op *op_by_handle(struct sim_node *n, uint8_t which, uint32_t h)
{
	for (int i = 0; i < SIM_NODE_OPS; i++) {
		if (n->ops[i].used && n->ops[i].handle == h && n->ops[i].which == which) {
			return &n->ops[i];
		}
	}
	return NULL;
}

static const int8_t snr_need[5] = {1, 4, 7, 10, 13};

static int phy_err(struct sim_node *n, const char *what, int err)
{
	n->phy_errors++;
	if (n->phy_errors <= 5) {
		fprintf(stderr, "  sim: node %d PHY error at t=%llu: %s\n", n->id,
			(unsigned long long)n->sim->t, what);
	}
	return err;
}

/* Validate and place an op on the node's timeline (lead, gaps, horizon). */
static int place_op(struct sim_node *n, uint64_t start_l, uint64_t dur_l, bool asap, bool is_tx,
		    uint16_t ch, struct sim_op **out)
{
	struct sim *s = n->sim;
	uint64_t now_l = sim_local(n, s->t);
	uint64_t ts, te;
	struct sim_op *op;

	if (!n->alive) {
		return -EIO;
	}
	if (asap) {
		ts = s->t;
		start_l = now_l;
	} else {
		/* a TX's seal ran on the commit path just before: it ate into the lead */
		if (start_l < now_l + (is_tx ? LEAD_TX + n->sec.debt : LEAD_RX)) {
			if (getenv("SIM_LEAD_DBG")) {
				fprintf(stderr,
					"  sim: node %d plan %s slot %u pos %d: lead %lld us, seal "
					"debt %llu us, dur %llu ss\n",
					n->id, n->mac.plan ? n->mac.plan->name : "-",
					n->mac.cur_slot, n->mac.my_pos,
					(long long)TDMA_TICKS_TO_US(start_l - now_l),
					(unsigned long long)TDMA_TICKS_TO_US(n->sec.debt),
					(unsigned long long)(dur_l / TDMA_SUBSLOT_TICKS));
				fprintf(stderr,
					"    state %d, last rx from node %u (%u ss), busy_until - "
					"now %lld us, op start - last rx end %lld us\n",
					(int)n->mac.state, n->dbg_last_rx_info >> 8,
					n->dbg_last_rx_info & 0xff,
					(long long)TDMA_TICKS_TO_US(
						(int64_t)(n->busy_until - s->t)),
					(long long)TDMA_TICKS_TO_US((int64_t)(sim_true(n, start_l) -
									      n->dbg_last_rx_end)));
			}
			return phy_err(n,
				       is_tx ? "TX inside the 465 us lead"
					     : "RX inside the 390 us lead",
				       -ETIME);
		}
		if (start_l > now_l + 2 * TDMA_FRAME_TICKS) {
			return phy_err(n, "op more than 2 frames ahead", -EINVAL);
		}
		ts = sim_true(n, start_l);
	}
	te = sim_true(n, start_l + dur_l);
	for (int i = 0; i < SIM_NODE_OPS; i++) {
		struct sim_op *o = &n->ops[i];

		if (!o->used) {
			continue;
		}
		/* retuning to another carrier: measured +10 us at most */
		uint64_t rt = o->ch != ch ? TDMA_US_TO_TICKS(TDMA_RETUNE_EXTRA_US) : 0;

		if (o->t_end <= ts) {
			if (ts - o->t_end < op_gap(o->is_tx, is_tx) + rt) {
				return phy_err(n, "too close after the previous op", -EBUSY);
			}
		} else if (te <= o->t_start) {
			if (o->t_start - te < op_gap(is_tx, o->is_tx) + rt) {
				return phy_err(n, "too close before the next op", -EBUSY);
			}
		} else {
			return phy_err(n, "overlapping ops", -EBUSY);
		}
	}
	op = op_alloc(n);
	if (!op) {
		return phy_err(n, "too many ops", -ENOMEM);
	}
	memset(op, 0, sizeof(*op));
	op->used = true;
	op->is_tx = is_tx;
	op->gen = ++n->gen;
	op->t_start = ts;
	op->t_end = te;
	op->ch = ch;
	*out = op;
	return 0;
}

static int rx_like(void *ctx, uint32_t handle, uint64_t start, uint32_t dur, uint16_t ch,
		   uint8_t kind)
{
	struct sim_node *n = inst_node(ctx);
	struct sim_op *op;
	int err = place_op(n, start, dur, start == 0, false, ch, &op);

	if (err) {
		return err;
	}
	op->which = inst_which(ctx);
	op->handle = handle;
	op->ch = ch;
	op->kind = kind;
	if (kind == SIM_OP_RSSI || kind == SIM_OP_SCAN) {
		uint64_t t = op->t_start + RSSI_CHUNK;

		op->meas_next = op->t_start;
		push((struct ev){.t = t < op->t_end ? t : op->t_end,
				 .type = EV_RSSI,
				 .node = (uint8_t)n->id,
				 .a = handle,
				 .b = op->gen,
				 .w = op->which});
	}
	push((struct ev){.t = op->t_end + RX_DONE_LAT,
			 .type = EV_OP_DONE,
			 .node = (uint8_t)n->id,
			 .a = handle,
			 .b = op->gen,
			 .w = op->which});
	return 0;
}

static int port_rx(void *ctx, uint32_t handle, uint64_t start, uint32_t dur, uint16_t ch)
{
	return rx_like(ctx, handle, start, dur, ch, SIM_OP_RX);
}

static int port_rssi(void *ctx, uint32_t handle, uint64_t start, uint32_t dur, uint16_t ch)
{
	return rx_like(ctx, handle, start, dur, ch, SIM_OP_RSSI);
}

static int port_scan(void *ctx, uint32_t handle, uint64_t start, uint32_t dur, uint16_t ch)
{
	return rx_like(ctx, handle, start, dur, ch, SIM_OP_SCAN);
}

/* RSSI chunk of an RSSI / scan op: highest level per subslot, like the modem's events. */
static void rssi_chunk(struct sim *s, const struct ev *e)
{
	struct sim_node *n = &s->nodes[e->node];
	struct sim_op *op = op_by_handle(n, e->w, e->a);
	int8_t ss[64];
	size_t k = 0;
	uint64_t t0, t1;

	if (!n->alive || !op || op->gen != e->b) {
		return;
	}
	t0 = op->meas_next;
	t1 = s->t < op->t_end ? s->t : op->t_end;
	for (uint64_t t = t0; t + TDMA_SUBSLOT_TICKS <= t1 + 1 && k < sizeof(ss);
	     t += TDMA_SUBSLOT_TICKS) {
		ss[k++] = sim_rssi_at(s, n->id, op->ch, t, t + TDMA_SUBSLOT_TICKS);
	}
	op->meas_next = t1;
	if (k) {
		tdma_on_rssi(macof(n, op->which), op->handle, ss, k);
		resched(n);
	}
	if (t1 < op->t_end) {
		uint64_t t = t1 + RSSI_CHUNK;

		push((struct ev){.t = t < op->t_end ? t : op->t_end,
				 .type = EV_RSSI,
				 .node = e->node,
				 .a = e->a,
				 .b = e->b,
				 .w = e->w});
	}
}

static int port_rx_stop(void *ctx, uint32_t handle)
{
	struct sim_node *n = inst_node(ctx);
	struct sim_op *op = op_by_handle(n, inst_which(ctx), handle);

	if (!op || op->is_tx) {
		return -ENOENT;
	}
	if (op->t_end > n->sim->t) {
		op->t_end = n->sim->t > op->t_start ? n->sim->t : op->t_start;
	}
	op->gen = ++n->gen; /* the scheduled op_done is stale now */
	push((struct ev){.t = n->sim->t,
			 .type = EV_OP_DONE,
			 .node = (uint8_t)n->id,
			 .a = handle,
			 .b = op->gen,
			 .w = op->which});
	return 0;
}

static int air_alloc(struct sim *s)
{
	for (int i = 0; i < SIM_MAX_AIR; i++) {
		if (!air[i].used || air[i].t_end + 2 * TDMA_FRAME_TICKS < s->t) {
			return i;
		}
	}
	return -1;
}

static int port_tx(void *ctx, uint32_t handle, uint64_t start, uint16_t ch, const uint8_t *hdr,
		   size_t hdr_len, const uint8_t *pl, size_t len, uint8_t subslots, uint8_t mcs,
		   uint32_t lbt, int8_t lbt_dbm)
{
	struct sim_node *n = inst_node(ctx);
	struct sim *s = n->sim;
	struct sim_op *op;
	size_t tbs = tdma_tbs(mcs, subslots);
	int ai, err;
	int64_t jit;

	if (hdr_len != TDMA_PHY_HDR_LEN || tbs == 0 || tbs > SIM_PKT_MAX) {
		return phy_err(n, "bad tx parameters", -EINVAL);
	}
	if (len > tbs) {
		/* the modem would silently truncate: a MAC sizing bug */
		return phy_err(n, "payload larger than the transport block", -EMSGSIZE);
	}
	if (start == 0) {
		return phy_err(n, "unscheduled tx", -EINVAL);
	}
	if (lbt && (lbt < 2 * 2880u || lbt > 110 * 2880u)) {
		return phy_err(n, "LBT period outside 2..110 symbols", -EINVAL);
	}
	/* the LBT window is part of the op (lead, gaps) */
	err = place_op(n, start - lbt, (uint64_t)subslots * TDMA_SUBSLOT_TICKS + lbt, false, true,
		       ch, &op);
	n->sec.debt = 0;
	if (err) {
		return err;
	}
	if (n->tx_fail_ppm && sim_rand(s) % 1000000u < n->tx_fail_ppm) {
		/*  an accepted TX the modem fails: nothing on air, OP_TIMEOUT */
		op->handle = handle;
		op->which = inst_which(ctx);
		op->ch = ch;
		op->kind = SIM_OP_TX;
		op->err = 0x1005;
		n->tx_failed++;
		push((struct ev){.t = op->t_end,
				 .type = EV_OP_DONE,
				 .node = (uint8_t)n->id,
				 .a = handle,
				 .b = op->gen,
				 .w = op->which});
		return 0;
	}
	ai = air_alloc(s);
	if (ai < 0) {
		fprintf(stderr, "sim: air table full\n");
		abort();
	}
	op->handle = handle;
	op->which = inst_which(ctx);
	op->ch = ch;
	jit = (int64_t)(sim_rand(s) % (2 * JITTER + 1)) - JITTER;
	{
		uint64_t ts = lbt ? sim_true(n, start) : op->t_start;

		air[ai] = (struct air){.used = true,
				       .node = n->id,
				       .ch = ch,
				       .mcs = mcs,
				       .subslots = subslots,
				       .t_start = (uint64_t)((int64_t)ts + jit),
				       .t_end = (uint64_t)((int64_t)op->t_end + jit),
				       .len = tbs,
				       .lbt_t0 = lbt ? op->t_start : 0,
				       .lbt_dbm = lbt_dbm,
				       .handle = handle};
		if (lbt) {
			push((struct ev){.t = ts,
					 .type = EV_LBT,
					 .node = (uint8_t)n->id,
					 .a = (uint32_t)ai,
					 .b = op->gen,
					 .w = op->which});
		}
	}
	op->kind = SIM_OP_TX;
	memcpy(air[ai].hdr, hdr, hdr_len);
	memcpy(air[ai].pl, pl, len); /* rest stays zero: the PHY's padding */
	s->st.tx++;
	if (s->on_air) {
		s->on_air(s, n->id, air[ai].t_start, ch, hdr, pl, len, subslots, mcs);
	}
	if (s->on_tamper) {
		s->on_tamper(s, n->id, air[ai].hdr, air[ai].pl, tbs);
	}
	push((struct ev){
		.t = air[ai].t_end, .type = EV_TX_END, .node = (uint8_t)n->id, .a = (uint32_t)ai});
	push((struct ev){.t = op->t_end,
			 .type = EV_OP_DONE,
			 .node = (uint8_t)n->id,
			 .a = handle,
			 .b = op->gen,
			 .w = op->which});
	return 0;
}

static void port_deliver(void *ctx, uint32_t src, const uint8_t *data, size_t len)
{
	struct sim_node *n = inst_node(ctx);

	if (n->sim->on_deliver) {
		n->sim->on_deliver(n->sim, n->id, src, data, len);
	}
}

static void evt_cb(const struct tdma_evt *e, void *user)
{
	struct sim_node *n = inst_node(user);

	if (inst_which(user)) {
		if (n->rn_evts < SIM_MAX_EVT_LOG) {
			n->revts[n->rn_evts] = *e;
			n->revt_t[n->rn_evts] = n->sim->t;
			n->rn_evts++;
		}
		return;
	}
	if (n->n_evts < SIM_MAX_EVT_LOG) {
		n->evts[n->n_evts] = *e;
		n->evt_t[n->n_evts] = n->sim->t;
		n->n_evts++;
	}
	if (n->sim->on_evt) {
		n->sim->on_evt(n->sim, n->id, e);
	}
}

/* ---- air ------------------------------------------------------------------------- */

/*
 * A received long burst keeps the modem busy after its end: on the DKs a TX
 * 4 ss after a received 7 ss burst failed (0x1005) ~4 % of the time, an RX
 * ~16 %, a TX 3 ss after an 8 ss one 1 in 3. Model: the next op starts >= 5 ss
 * after any received burst of LRX_MIN_SS or more, else a PHY contract
 * violation (an RX op is checked when it receives a packet). An RX op that
 * receives another long packet (a FLEX train) may start 2 ss after it: 0
 * failures in 1000 trains of 3 x 8 ss on the DKs (`tdma train rxops`).
 */
#define LRX_MIN_SS TDMA_LRX_MIN_SS

static void tx_end(struct sim *s, int ai)
{
	struct air *a = &air[ai];
	bool collided = false;

	if (a->cancelled) {
		return;
	}
	if (a->node >= 0) {
		struct sim_node *tn = &s->nodes[a->node];

		if (tn->lrx_end && tn->lrx_end <= a->t_start &&
		    a->t_start - tn->lrx_end < (uint64_t)TDMA_LRX_TO_TX_SS * TDMA_SUBSLOT_TICKS -
						       TDMA_SUBSLOT_TICKS / 4) {
			phy_err(tn, "TX < 5 ss after the end of a received long burst", -EBUSY);
		}
	}
	for (int i = 0; i < SIM_MAX_AIR; i++) {
		struct air *b = &air[i];

		if (i != ai && b->used && !b->cancelled && b->ch == a->ch && b->node != a->node &&
		    b->t_start < a->t_end && a->t_start < b->t_end) {
			collided = true;
			break;
		}
	}
	for (int j = 0; j < s->n_nodes; j++) {
		struct sim_node *n = &s->nodes[j];

		if (j == a->node || !n->alive) {
			continue;
		}
		for (int k = 0; k < SIM_NODE_OPS; k++) {
			struct sim_op *op = &n->ops[k];

			if (!op->used || op->is_tx || op->kind == SIM_OP_RSSI || op->ch != a->ch ||
			    op->t_start + RX_PRE_MIN > a->t_start || op->t_end < a->t_end) {
				continue;
			}
			bool crc = true;
			int il = intf_level(s, a->ch, a->t_start, a->t_end);
			int snr = a->node >= 0 ? s->snr_db[a->node][j]
					       : SIM_SNR_DEFAULT; /* injected */
			bool by_intf = il > -128 && SIM_RX_DBM - il < snr;

			snr = by_intf ? SIM_RX_DBM - il : snr;
			if (collided) {
				s->st.collisions++;
				crc = false;
			} else if (snr < snr_need[a->mcs > 4 ? 4 : a->mcs]) {
				if (by_intf) {
					s->st.lost_intf++;
				} else {
					s->st.lost_snr++;
				}
				break;
			} else if (a->node >= 0 && s->loss_ppm[a->node][j] &&
				   sim_rand(s) % 1000000u < s->loss_ppm[a->node][j]) {
				s->st.lost++;
				break;
			}
			/* another long packet (a train) is received 2 ss later (`tdma train rxops`)
			 */
			if (n->lrx_end && op->t_start >= n->lrx_end &&
			    op->t_start - n->lrx_end < (uint64_t)(a->subslots >= LRX_MIN_SS
									  ? TDMA_MIN_OP_GAP_SS
									  : TDMA_LRX_TO_TX_SS) *
								       TDMA_SUBSLOT_TICKS -
							       TDMA_SUBSLOT_TICKS / 4) {
				phy_err(n, "RX < 5 ss after the end of a received long burst",
					-EBUSY);
			}
			if (a->subslots >= LRX_MIN_SS && a->t_end > n->lrx_end) {
				n->lrx_end = a->t_end;
			}
			push((struct ev){.t = a->t_end + sim_pdc_ticks(a->subslots, a->mcs),
					 .type = EV_RX_DELIVER,
					 .w = op->which,
					 .node = (uint8_t)j,
					 .a = (uint32_t)ai,
					 .b = op->handle,
					 .crc = crc,
					 .snr = (int8_t)(snr > 127 ? 127 : snr)});
			break;
		}
	}
}

static void rx_deliver(struct sim *s, const struct ev *e)
{
	struct sim_node *n = &s->nodes[e->node];
	struct air *a = &air[e->a];

	if (!n->alive || !op_by_handle(n, e->w, e->b)) {
		return;
	}
	if (e->crc) {
		struct sim_op *op = op_by_handle(n, e->w, e->b);
		struct tdma_phy_hdr h;

		s->st.delivered++;
		if (op->kind == SIM_OP_SCAN &&
		    tdma_phy_hdr_decode(a->hdr, TDMA_PHY_HDR_LEN, &h) == 0) {
			tdma_on_pcc(macof(n, e->w), e->b, SIM_RX_DBM, h.short_nwid, h.tx_short, 1);
		}
	}
	n->dbg_last_rx_end = a->t_end;
	n->dbg_last_rx_info = (uint32_t)a->node << 8 | a->subslots;
	if (e->w) {
		tdma_relay_sync(&n->relay);
	}
	tdma_on_rx(macof(n, e->w), e->b, sim_local(n, a->t_start), SIM_RX_DBM,
		   (int16_t)(e->snr * 4), a->hdr, TDMA_PHY_HDR_LEN, a->pl, a->len, e->crc);
	if (n->sec.busy_add) {
		/* the PHY event comes ~150 us after the packet; then the MAC verifies it */
		uint64_t b = s->t + TDMA_US_TO_TICKS(150);

		n->busy_until = (n->busy_until > b ? n->busy_until : b) + n->sec.busy_add;
		n->sec.busy_add = 0;
	}
	resched(n);
}

/* ---- node control -------------------------------------------------------------------- */

static void resched(struct sim_node *n)
{
	uint64_t w, t;

	if (!n->alive) {
		return;
	}
	relay_step(n);
	w = tdma_next_wakeup(&n->mac);
	if (n->relay_on && tdma_relay_running(&n->relay)) {
		uint64_t r = tdma_next_wakeup(&n->rmac);

		w = r < w ? r : w;
	}
	if (w == UINT64_MAX) {
		n->tick_at = UINT64_MAX;
		return;
	}
	t = sim_true(n, w);
	if (t < n->sim->t) {
		t = n->sim->t;
	}
	if (t < n->busy_until && !n->relay_on) {
		/*
		 * The MAC thread is busy verifying a burst. A relay's MAC thread
		 * commits first (app: tick before a received burst whose processing
		 * would make a commit late): the other instance's rx_clear() knows
		 * nothing of what this one receives.
		 */
		t = n->busy_until;
	}
	if (t == n->tick_at) {
		return;
	}
	n->tick_at = t;
	push((struct ev){.t = t, .type = EV_TICK, .node = (uint8_t)n->id, .b = ++n->tick_gen});
}

static void nr_clear(void);

struct sim *sim_init(uint64_t seed)
{
	nr_clear(); /* nonces are per simulation (keys and rd ids repeat across runs) */
	memset(&the_sim, 0, sizeof(the_sim));
	memset(air, 0, sizeof(air));
	heap_n = 0;
	ev_seq = 0;
	the_sim.rng = seed ? seed : 1;
	memset(the_sim.snr_db, SIM_SNR_DEFAULT, sizeof(the_sim.snr_db));
	return &the_sim;
}

int sim_add_node(struct sim *s, enum tdma_role role, uint8_t box, uint8_t plan_id, int64_t offset,
		 int32_t ppb)
{
	int i = s->n_nodes++;
	struct sim_node *n = &s->nodes[i];

	memset(n, 0, sizeof(*n));
	n->sim = s;
	n->id = i;
	n->offset = offset;
	n->ppb = ppb;
	n->tick_at = UINT64_MAX;
	n->cfg = (struct tdma_cfg){
		.role = role,
		.rd_id = sim_rd_for_box(box),
		.network_id = sim_network_id(),
		.box_id = box,
		.channel = SIM_CHANNEL,
		.ch_min = SIM_CH_MIN,
		.ch_max = SIM_CH_MAX,
		.mcs = 0, /* plan default */
		.plan_id = plan_id,
		.seed = (uint32_t)sim_rand(s) | 1u,
		.evt_cb = evt_cb,
		.evt_user = &n->inst[0],
	};
	n->inst[0] = (struct sim_inst){n, 0};
	n->inst[1] = (struct sim_inst){n, 1};
	if (sim_sec_all) {
		sim_sec_on(s, i, sim_sec_default_key);
		n->cfg.grant_ahead = sim_grant_ahead;
		n->sec.cost_base = TDMA_US_TO_TICKS(sim_sec_cost_us);
		n->sec.hints = sim_sec_cost_us != 0;
		n->sec.open_typ_base = TDMA_US_TO_TICKS(sim_sec_open_us);
		n->sec.open_busy = TDMA_US_TO_TICKS(sim_sec_busy_us);
	}
	return i;
}

static void sec_ops_init(struct sim_node *n);

static void node_boot(struct sim_node *n)
{
	struct tdma_port port = {
		.ctx = &n->inst[0],
		.now = port_now,
		.rx = port_rx,
		.rx_stop = port_rx_stop,
		.tx = port_tx,
		.deliver = port_deliver,
		.rssi = port_rssi,
		.scan = port_scan,
	};

	n->alive = true;
	if (n->sec.on) {
		sec_ops_init(n);
		port.sec = &n->sec.ops;
		port.sec_ctx = n;
		n->cfg.sess_ctr = ++n->sec.sess_ctr; /* the app persists it per FT start */
		n->cfg.sec_devkey = n->sec.devkey;
		memset(n->sec.sess, 0, sizeof(n->sec.sess));
		n->sec.debt = 0;
		n->sec.busy_add = 0;
	}
	n->busy_until = 0;
	n->inst[0] = (struct sim_inst){n, 0};
	n->inst[1] = (struct sim_inst){n, 1};
	if (n->relay_on) {
		struct tdma_mem all = tdma_mem_of(&n->store), pt;

		/* a relay: peer 0 for the parent, the last two peers for the child cluster */
		if (tdma_mem_split(&all, &pt, &n->rmem, 2, 3)) {
			abort();
		}
		n->cfg.mem = pt;
		n->cfg.relay = !n->relay_hold;
		port.away = port_away;
		memset(&n->rmac, 0, sizeof(n->rmac));
		tdma_relay_init(&n->relay, &n->mac, &n->rmac);
	} else if (!n->cfg.mem.peers) {
		n->cfg.mem = tdma_mem_of(&n->store);
	}
	if (tdma_init(&n->mac, &n->cfg, &port) || tdma_start(&n->mac)) {
		fprintf(stderr, "sim: node %d failed to start\n", n->id);
		abort();
	}
	resched(n);
}

void sim_start(struct sim *s, int node)
{
	node_boot(&s->nodes[node]);
}

void sim_kill(struct sim *s, int node)
{
	struct sim_node *n = &s->nodes[node];

	n->alive = false;
	n->tick_gen++;
	n->tick_at = UINT64_MAX;
	for (int i = 0; i < SIM_NODE_OPS; i++) {
		n->ops[i].used = false;
	}
	n->gen += SIM_NODE_OPS; /* invalidate pending op_done events */
	for (int i = 0; i < SIM_MAX_AIR; i++) {
		if (air[i].used && air[i].node == node && air[i].t_end > s->t) {
			air[i].cancelled = true;
		}
	}
}

void sim_revive(struct sim *s, int node)
{
	sim_kill(s, node);
	/* a reboot also gives a fresh backoff seed */
	s->nodes[node].cfg.seed = (uint32_t)sim_rand(s) | 1u;
	node_boot(&s->nodes[node]);
}

void sim_at(struct sim *s, uint64_t t, sim_fn fn, void *arg)
{
	push((struct ev){.t = t < s->t ? s->t : t, .type = EV_APP, .fn = fn, .arg = arg});
}

int sim_send(struct sim *s, int node, uint32_t dst, const uint8_t *data, size_t len, uint8_t prio)
{
	struct sim_node *n = &s->nodes[node];
	int err;

	if (!n->alive) {
		return -EIO;
	}
	err = n->relay_on && tdma_relay_running(&n->relay) && tdma_link_mtu(&n->rmac, dst)
		      ? tdma_send(&n->rmac, dst, data, len, prio)
		      : tdma_send(&n->mac, dst, data, len, prio);
	resched(n);
	return err;
}

void sim_relay_on(struct sim *s, int node, uint16_t ch)
{
	s->nodes[node].relay_on = true;
	s->nodes[node].relay_ch = ch;
}

struct tdma_mac *sim_relay_mac(struct sim_node *n)
{
	return n->relay_on ? &n->rmac : NULL;
}

void sim_relay_want(struct sim *s, int node, bool on)
{
	struct sim_node *n = &s->nodes[node];

	n->relay_hold = !on;
	if (n->alive) {
		tdma_pt_set_relay(&n->mac, on);
		relay_step(n);
		resched(n);
	}
}

/*
 * A relay's control, after everything that may change the up instance: the
 * child cluster starts once up is associated on a plan R1 fits (on relay_ch,
 * plan HG, the parent's grid), and stops when up has left its parent.
 */
static void relay_step(struct sim_node *n)
{
	if (!n->relay_on) {
		return;
	}
	if (tdma_relay_running(&n->relay)) {
		if (n->relay_hold ||
		    (!n->relay_keep && tdma_get_state(&n->mac) != TDMA_ST_ASSOCIATED)) {
			tdma_stop(&n->rmac);
			n->relay_stops++;
		} else {
			tdma_relay_sync(&n->relay);
			tdma_relay_plan_step(&n->relay);
		}
		return;
	}
	if (n->relay_hold || !tdma_relay_ready(&n->relay) || n->rmac.n_ops) {
		return;
	}
	struct tdma_port port = n->mac.port;
	uint8_t depth = 0;

	tdma_tree(&n->mac, &depth, NULL);
	port.ctx = &n->inst[1];
	n->rcfg = n->cfg;
	n->rcfg.role = TDMA_ROLE_FT;
	n->rcfg.plan_id = tdma_relay_child_plan(&n->relay);
	n->rcfg.channel = n->relay_ch;
	n->rcfg.relay = true;
	n->rcfg.depth = (uint8_t)(depth + 1u);
	n->rcfg.ft_rd_filter = 0;
	n->rcfg.mem = n->rmem;
	n->rcfg.plan_auto = false;
	n->rcfg.evt_user = &n->inst[1];
	if (n->sec.on) {
		n->rcfg.sess_ctr = ++n->sec.sess_ctr; /* every FT start: a new session counter */
	}
	if (tdma_init(&n->rmac, &n->rcfg, &port)) {
		fprintf(stderr, "sim: node %d: relay init failed\n", n->id);
		abort();
	}
	tdma_relay_sync(&n->relay);
	if (tdma_start(&n->rmac)) {
		fprintf(stderr, "sim: node %d: relay start failed\n", n->id);
		abort();
	}
	n->relay_starts++;
}

void sim_set_loss_all(struct sim *s, uint32_t ppm)
{
	for (int i = 0; i < SIM_MAX_NODES; i++) {
		for (int j = 0; j < SIM_MAX_NODES; j++) {
			s->loss_ppm[i][j] = i == j ? 0 : ppm;
		}
	}
}

void sim_set_snr(struct sim *s, int a, int b, int8_t db)
{
	s->snr_db[a][b] = db;
	s->snr_db[b][a] = db;
}

void sim_run_until(struct sim *s, uint64_t t_end)
{
	while (heap_n && heap[0].t <= t_end) {
		struct ev e = pop();
		struct sim_node *n = &s->nodes[e.node];
		struct sim_op *op;

		s->t = e.t;
		switch (e.type) {
		case EV_LBT: {
			struct air *a = &air[e.a];

			op = op_by_handle(n, e.w, a->handle);
			if (!n->alive || !op || op->gen != e.b || a->cancelled) {
				break;
			}
			if (sim_rssi_at(s, a->node, a->ch, a->lbt_t0, a->t_start) >= a->lbt_dbm) {
				a->cancelled = true;
				op->err = TDMA_ERR_LBT_BUSY;
				s->st.lbt_busy++;
			}
			break;
		}
		case EV_RSSI:
			rssi_chunk(s, &e);
			break;
		case EV_TX_END:
			tx_end(s, (int)e.a);
			break;
		case EV_RX_DELIVER:
			rx_deliver(s, &e);
			break;
		case EV_OP_DONE:
			op = op_by_handle(n, e.w, e.a);
			if (!n->alive || !op || op->gen != e.b) {
				break;
			}
			op->used = false;
			if (e.w) {
				tdma_relay_sync(&n->relay);
			}
			tdma_on_op_done(macof(n, e.w), e.a, op->err);
			resched(n);
			break;
		case EV_TICK:
			if (!n->alive || e.b != n->tick_gen) {
				break;
			}
			n->tick_at = UINT64_MAX;
			tdma_tick(&n->mac, sim_local(n, s->t));
			relay_step(n);
			if (n->relay_on && tdma_relay_running(&n->relay)) {
				tdma_tick(&n->rmac, sim_local(n, s->t));
			}
			resched(n);
			break;
		case EV_APP:
			e.fn(s, e.arg);
			break;
		}
	}
	if (s->t < t_end) {
		s->t = t_end;
	}
}

uint32_t sim_phy_errors(const struct sim *s)
{
	uint32_t n = 0;

	for (int i = 0; i < s->n_nodes; i++) {
		n += s->nodes[i].phy_errors;
	}
	return n;
}

const struct tdma_evt *sim_find_evt(const struct sim_node *n, enum tdma_evt_type type,
				    uint64_t t_from, uint64_t *t_out)
{
	for (int i = 0; i < n->n_evts; i++) {
		if (n->evts[i].type == type && n->evt_t[i] >= t_from) {
			if (t_out) {
				*t_out = n->evt_t[i];
			}
			return &n->evts[i];
		}
	}
	return NULL;
}

const struct tdma_evt *sim_find_revt(const struct sim_node *n, enum tdma_evt_type type,
				     uint64_t t_from, uint64_t *t_out)
{
	for (int i = 0; i < n->rn_evts; i++) {
		if (n->revts[i].type == type && n->revt_t[i] >= t_from) {
			if (t_out) {
				*t_out = n->revt_t[i];
			}
			return &n->revts[i];
		}
	}
	return NULL;
}

int sim_count_revt(const struct sim_node *n, enum tdma_evt_type type, uint64_t t_from)
{
	int c = 0;

	for (int i = 0; i < n->rn_evts; i++) {
		c += n->revts[i].type == type && n->revt_t[i] >= t_from;
	}
	return c;
}

int sim_count_evt(const struct sim_node *n, enum tdma_evt_type type, uint64_t t_from)
{
	int c = 0;

	for (int i = 0; i < n->n_evts; i++) {
		c += n->evts[i].type == type && n->evt_t[i] >= t_from;
	}
	return c;
}

/* ---- security: reference crypto behind tdma_sec_ops, nonce-reuse checker ----------------------
 */

bool sim_sec_all;
bool sim_grant_ahead;
uint32_t sim_sec_cost_us;
uint32_t sim_sec_open_us, sim_sec_busy_us;
/* "cm-sim-key-00001": a made-up key for the simulation */
const uint8_t sim_sec_default_key[16] = {0x63, 0x6d, 0x2d, 0x73, 0x69, 0x6d, 0x2d, 0x6b,
					 0x65, 0x79, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x31};
struct sim_sec_stats sim_sec_st;

#define NR_BITS 21
static uint64_t nr_tab[1u << NR_BITS]; /* fingerprints of (key, nonce); 0 = empty */
static uint64_t nr_used;

static void nr_clear(void)
{
	if (nr_used) {
		memset(nr_tab, 0, sizeof(nr_tab));
		nr_used = 0;
	}
}

void sim_sec_stats_reset(void)
{
	memset(&sim_sec_st, 0, sizeof(sim_sec_st));
	nr_clear();
}

static uint64_t fnv(const uint8_t *p, size_t n, uint64_t h)
{
	for (size_t i = 0; i < n; i++) {
		h = (h ^ p[i]) * 0x100000001b3ull;
	}
	return h;
}

/* Every seal: a (key, nonce) pair seen before is a reuse (no HARQ resends exist yet). */
static void nr_note(const uint8_t key[16], const uint8_t nonce[TDMA_SEC_NONCE_LEN])
{
	uint64_t h = fnv(nonce, TDMA_SEC_NONCE_LEN, fnv(key, 16, 0xcbf29ce484222325ull)) | 1u;
	uint32_t i = (uint32_t)(h >> 7) & ((1u << NR_BITS) - 1);

	if (nr_used > (3u << NR_BITS) / 4) {
		return; /* table full: stop checking rather than report garbage */
	}
	while (nr_tab[i]) {
		if (nr_tab[i] == h) {
			sim_sec_st.nonce_reuse++;
			return;
		}
		i = (i + 1) & ((1u << NR_BITS) - 1);
	}
	nr_tab[i] = h;
	nr_used++;
}

static void be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static int ss_derive(void *ctx, uint8_t idx, uint32_t nwid, uint32_t ft, uint32_t ctr, uint32_t rnd,
		     uint32_t *handle)
{
	struct sim_node *n = ctx;
	uint8_t c[16];

	if (idx > 3 || !n->sec.have[idx]) {
		return TDMA_ERR_NOKEY;
	}
	for (uint32_t i = 0; i < sizeof(n->sec.sess) / sizeof(n->sec.sess[0]); i++) {
		if (!n->sec.sess[i].used) {
			be32(c, nwid);
			be32(c + 4, ft);
			be32(c + 8, ctr);
			be32(c + 12, rnd);
			tdma_ref_kdf(n->sec.key[idx], "CMs1", c, sizeof(c), n->sec.sess[i].key, 16);
			n->sec.sess[i].used = true;
			*handle = i + 1;
			return 0;
		}
	}
	return -ENOMEM;
}

static void ss_release(void *ctx, uint32_t handle)
{
	struct sim_node *n = ctx;

	if (handle && handle <= sizeof(n->sec.sess) / sizeof(n->sec.sess[0])) {
		n->sec.sess[handle - 1].used = false;
	}
}

static const uint8_t *ss_key(struct sim_node *n, uint32_t handle)
{
	if (!handle || handle > sizeof(n->sec.sess) / sizeof(n->sec.sess[0]) ||
	    !n->sec.sess[handle - 1].used) {
		fprintf(stderr, "sim: node %d: bad session handle %u\n", n->id, handle);
		abort();
	}
	return n->sec.sess[handle - 1].key;
}

static int ss_seal(void *ctx, uint32_t handle, const uint8_t nonce[TDMA_SEC_NONCE_LEN],
		   const uint8_t *aad, size_t aad_len, uint8_t *body, size_t len, uint8_t *mic)
{
	struct sim_node *n = ctx;
	const uint8_t *k = ss_key(n, handle);

	nr_note(k, nonce);
	memcpy(n->sec.last_nonce, nonce, TDMA_SEC_NONCE_LEN);
	tdma_ref_ccm_seal(k, nonce, TDMA_SEC_NONCE_LEN, aad, aad_len, body, len, mic,
			  TDMA_SEC_MIC_LEN);
	sim_sec_st.seals++;
	if (n->sec.cost_base || n->sec.cost_per16) {
		n->sec.debt += n->sec.cost_base + n->sec.cost_per16 * ((len + aad_len + 15) / 16);
	}
	return 0;
}

static int ss_open(void *ctx, uint32_t handle, const uint8_t nonce[TDMA_SEC_NONCE_LEN],
		   const uint8_t *aad, size_t aad_len, uint8_t *body, size_t len,
		   const uint8_t *mic)
{
	struct sim_node *n = ctx;

	sim_sec_st.opens++;
	n->sec.busy_add += n->sec.open_busy;
	if (tdma_ref_ccm_open(ss_key(n, handle), nonce, TDMA_SEC_NONCE_LEN, aad, aad_len, body, len,
			      mic, TDMA_SEC_MIC_LEN)) {
		sim_sec_st.open_fail++;
		return -EBADMSG;
	}
	memcpy(n->sec.ok_nonce[n->sec.n_ok++ % 64], nonce, TDMA_SEC_NONCE_LEN);
	return 0;
}

static int ss_key_state(void *ctx, uint8_t *active, uint8_t *next)
{
	struct sim_node *n = ctx;

	*active = n->sec.have[n->sec.active] ? n->sec.active : TDMA_SEC_NO_KEY;
	*next = n->sec.next;
	return 0;
}

static uint32_t ss_random(void *ctx)
{
	struct sim_node *n = ctx;

	return (uint32_t)sim_rand(n->sim);
}

static void sec_ops_init(struct sim_node *n)
{
	n->sec.ops = (struct tdma_sec_ops){
		.derive = ss_derive,
		.release = ss_release,
		.seal = ss_seal,
		.open = ss_open,
		.key_state = ss_key_state,
		.random = ss_random,
		.seal_ticks_base = n->sec.hints ? n->sec.cost_base : 0,
		.seal_ticks_per16 = n->sec.hints ? n->sec.cost_per16 : 0,
		.open_ticks_base = n->sec.hints ? n->sec.open_typ_base : 0,
		.open_ticks_per16 = n->sec.hints ? n->sec.open_typ_per16 : 0,
	};
}

void sim_sec_on(struct sim *s, int node, const uint8_t key[16])
{
	struct sim_node *n = &s->nodes[node];

	n->sec.on = true;
	memcpy(n->sec.key[0], key, 16);
	n->sec.have[0] = true;
	n->sec.active = 0;
	n->sec.next = TDMA_SEC_NO_KEY;
}

void sim_sec_key(struct sim *s, int node, uint8_t idx, const uint8_t *key)
{
	struct sim_node *n = &s->nodes[node];

	n->sec.have[idx & 3] = key != NULL;
	if (key) {
		memcpy(n->sec.key[idx & 3], key, 16);
	}
}

void sim_sec_state(struct sim *s, int node, uint8_t active, uint8_t next)
{
	s->nodes[node].sec.active = active;
	s->nodes[node].sec.next = next;
}

void sim_inject(struct sim *s, uint64_t t, uint16_t ch, const uint8_t hdr[TDMA_PHY_HDR_LEN],
		const uint8_t *pl, size_t len, uint8_t subslots, uint8_t mcs)
{
	size_t tbs = tdma_tbs(mcs, subslots);
	int ai = air_alloc(s);

	if (ai < 0 || tbs == 0 || len > tbs) {
		fprintf(stderr, "sim_inject: bad packet\n");
		abort();
	}
	air[ai] = (struct air){.used = true,
			       .node = -1,
			       .ch = ch,
			       .mcs = mcs,
			       .subslots = subslots,
			       .t_start = t,
			       .t_end = t + (uint64_t)subslots * TDMA_SUBSLOT_TICKS,
			       .len = tbs};
	memcpy(air[ai].hdr, hdr, TDMA_PHY_HDR_LEN);
	memcpy(air[ai].pl, pl, len);
	push((struct ev){.t = air[ai].t_end, .type = EV_TX_END, .a = (uint32_t)ai});
}

bool sim_sec_opened(const struct sim_node *n, const uint8_t nonce[TDMA_SEC_NONCE_LEN])
{
	for (uint32_t i = 0; i < 64 && i < n->sec.n_ok; i++) {
		if (!memcmp(n->sec.ok_nonce[i], nonce, TDMA_SEC_NONCE_LEN)) {
			return true;
		}
	}
	return false;
}

uint64_t sim_true_of(const struct sim_node *n, uint64_t local)
{
	return sim_true(n, local);
}
