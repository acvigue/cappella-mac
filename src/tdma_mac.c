/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * TDMA MAC core: frame timing, the just-in-time slot scheduler and the FT /
 * PT state machines. The per-peer data path (ARQ, queues, reassembly) lives
 * in tdma_link.c, the wire format in tdma_pdu.c.
 *
 * Scheduling model: the MAC walks the plan slot by slot. Each slot's op is
 * decided and handed to the PHY at slot start - TDMA_COMMIT_LEAD_TICKS, so
 * data queued up to that moment still makes the slot and only a handful of
 * ops are ever in flight.
 *
 * Ops per device (docs/phy-timing.md):
 *   FT: one TX per DL burst (beacon + records for every PT, broadcast), one
 *       continuous RX over each run of UL/contention slots.
 *   PT: one RX per DL burst it follows, one TX in its own UL slot (or in a
 *       contention opportunity while associating).
 * The plan validator guarantees >= 2 idle subslots between any of these.
 *
 * Hybrid plans (H, H4) add FLEX regions: each one carries at most one long
 * burst, DL to one PT or UL from one PT, sized to the queue (DL) or to the
 * PT's last status record (UL) at that link's MCS. The FT decides when it
 * commits the DL burst before the region and announces it there in a grant
 * record; PTs report their queue in a status record in every UL burst. The
 * guaranteed slots never move, so their latency bound holds under any bulk
 * load.
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "tdma_internal.h"

/* TDMA_ERR_LBT_BUSY is -EBUSY without pulling errno.h into the public header. */
typedef char tdma_lbt_err_check[(TDMA_ERR_LBT_BUSY == -EBUSY) ? 1 : -1];

#define USE_SEARCH    0xff
#define USE_SCAN      0xfe /* FT channel selection: RX any network + RSSI */
#define USE_MEAS      0xfd /* FT monitor: RSSI only */
#define USE_PROBE     0xfc /* PT: one listen for another cluster's DL burst (tdma_pt_probe) */
#define USE_FTSCAN    0xfb /* FT: one listen for other clusters' beacons (tdma_ft_scan) */
/*
 * a listen's margins to our own ops: the PHY's gap before it
 * (after our beacon burst), and after it the long-burst rule (a burst heard
 * at its end keeps the modem busy for TDMA_LRX_TO_TX_SS).
 */
#define FS_GAP_BEFORE ((uint64_t)TDMA_MIN_OP_GAP_SS * TDMA_SUBSLOT_TICKS)
#define FS_GAP_AFTER  ((uint64_t)TDMA_LRX_TO_TX_SS * TDMA_SUBSLOT_TICKS)
#define CFGV(m, f, d) ((m)->cfg.f ? (m)->cfg.f : (d))

/* ---- small helpers ---------------------------------------------------------- */

static uint32_t rng_next(struct tdma_mac *m)
{
	/* xorshift32: deterministic, enough for backoff and nonces */
	uint32_t x = m->rng;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	m->rng = x;
	return x;
}

static void emit_full(struct tdma_mac *m, enum tdma_evt_type type, uint32_t rd, uint32_t nwid,
		      enum tdma_cause cause, uint8_t pos, int16_t rssi, uint16_t ch)
{
	struct tdma_evt e = {
		.type = type,
		.rd_id = rd,
		.network_id = nwid,
		.cause = cause,
		.rssi = rssi,
		.pos = pos,
		.channel = ch,
	};

	if (m->cfg.evt_cb) {
		m->cfg.evt_cb(&e, m->cfg.evt_user);
	}
}

static void emit(struct tdma_mac *m, enum tdma_evt_type type, uint32_t rd, enum tdma_cause cause,
		 uint8_t pos, int16_t rssi)
{
	emit_full(m, type, rd, m->cfg.network_id, cause, pos, rssi, m->chan);
}

static int beacon_of_pkt(const uint8_t *pkt, size_t len, struct tdma_beacon *b);
static uint32_t mon_period(const struct tdma_mac *m);
/* link security (section "link security" below) */
static int sec_seal(struct tdma_mac *m, uint8_t si, uint32_t frame, const struct tdma_phy_hdr *h,
		    size_t *len);
static uint32_t sec_lead(const struct tdma_mac *m, const struct tdma_slot *s);
static bool sec_hints(const struct tdma_mac *m);
static uint32_t sec_open_cost(const struct tdma_mac *m);
static bool sec_hints_calc(const struct tdma_mac *m);
static uint32_t sec_open_cost_calc(const struct tdma_mac *m);
static uint32_t sec_lead_calc(const struct tdma_mac *m, const struct tdma_slot *s);
static uint32_t rx_clear_max(const struct tdma_mac *m);
static uint8_t flex_i(const struct tdma_mac *m, uint8_t si);
static const struct tdma_lead_cache *lc(const struct tdma_mac *cm);
static uint32_t burst_air(const struct tdma_slot *s);
static void sec_tick(struct tdma_mac *m, uint32_t frame);
static void sec_reset(struct tdma_mac *m, bool keep_cache);
static int sec_ft_start(struct tdma_mac *m);
static void sec_ft_beacon(struct tdma_mac *m, uint32_t frame, struct tdma_beacon *b);
static void sec_ft_poll(struct tdma_mac *m, uint32_t frame);
static bool sec_denied(const struct tdma_mac *m, uint32_t rd);
static int clear_beacon(const struct tdma_mac *m, const uint8_t *pkt, size_t len,
			struct tdma_beacon *b);
static bool is_pt(const struct tdma_mac *m);
static bool ft_active_peer(const struct tdma_peer *p, uint32_t frame);
static void plan_apply(struct tdma_mac *m, const struct tdma_plan *p);
static size_t dl_pdu_cap(const struct tdma_plan *plan, uint8_t mcs, bool sec);
static size_t ul_pdu_cap(const struct tdma_plan *plan, uint8_t mcs, bool sec);
static uint8_t flex_len_for(const struct tdma_mac *m, uint8_t mcs, uint8_t maxn, size_t need);
static uint32_t lead_trim(const struct tdma_mac *m, const struct tdma_slot *s);
static bool ft_relay_child(const struct tdma_mac *m);
static void emit_pos_move(struct tdma_mac *m, uint32_t rd, uint8_t from, uint8_t to);
static bool fs_covers(const struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start);

/*
 * How much earlier rx_clear can commit a TX slot than its own lead says:
 * back over a verify window and a whole received burst (the longest slot of
 * the plan, a FLEX region); the sim's multi-PT bulk tests saw spurious
 * retransmissions with less.
 */
static uint32_t rx_clear_max_calc(const struct tdma_mac *m)
{
	uint32_t mx = 0;

	if (!sec_hints_calc(m) || !m->plan) {
		return 0;
	}
	for (uint8_t i = 0; i < m->plan->n_slots; i++) {
		uint32_t a = burst_air(&m->plan->slots[i]);

		mx = a > mx ? a : mx;
	}
	return mx + TDMA_RX_PROC_TICKS + 2 * sec_open_cost_calc(m);
}

static struct link_params link_params(const struct tdma_mac *m)
{
	struct link_params p = {
		.max_tx = CFGV(m, arq_max_tx, TDMA_DEF_ARQ_MAX_TX),
		.lifetime = CFGV(m, tx_lifetime_ticks, TDMA_DEF_TX_LIFETIME_TICKS),
		/*
		 * a peer burst built after it saw ours: FLEX bursts are frozen
		 * earlier; with a cost model the peer's commit is earlier by its
		 * seal time, and it follows our burst only after the window in
		 * which it verifies it (rx_clear), else it comes before our end
		 */
		.ack_turnaround =
			(m->flex_plan ? TDMA_FLEX_COMMIT_LEAD_TICKS : TDMA_COMMIT_LEAD_TICKS) +
			TDMA_RX_PROC_TICKS + 3 * sec_open_cost(m) + rx_clear_max(m),
	};

	return p;
}

struct deliver_ctx {
	struct tdma_mac *m;
	uint32_t src;
	struct tdma_peer *p;
};

static void deliver(void *ctx, const uint8_t *data, size_t len);

/*
 * With every own burst of peer p's link: SDUs held for in-order delivery are
 * given up waiting for an older one after the sender's lifetime (+ 2 RTOs).
 */
static void peer_rx_poll(struct tdma_mac *m, struct tdma_peer *p)
{
	struct deliver_ctx dc = {m, p->rd_id, p};
	uint32_t hold =
		CFGV(m, tx_lifetime_ticks, TDMA_DEF_TX_LIFETIME_TICKS) + 2u * TDMA_ARQ_RTO_TICKS;

	link_rx_poll(&p->link, m->ras, m->n_ras, (uint8_t)(p - m->peers + 1),
		     m->port.now(m->port.ctx), hold, deliver, &dc, &m->stats);
}

/* Reset peer i's link and free its reassembly buffers. */
static void peer_link_reset(struct tdma_mac *m, uint8_t i)
{
	link_reset(&m->peers[i].link);
	ras_release(m->ras, m->n_ras, (uint8_t)(i + 1u));
}

/* port.trace of the data PDU at pdu (no-op for other PDUs or without a trace hook). */
static void trace_pdu(const struct tdma_mac *m, uint8_t ev, uint32_t peer, const uint8_t *pdu,
		      size_t len, uint64_t air)
{
	struct tdma_data d;

	if (!m->port.trace || tdma_pdu_type(pdu, len) != TDMA_PDU_DATA ||
	    tdma_data_decode(pdu, len, &d)) {
		return;
	}
	m->port.trace(m->port.ctx, ev, peer, d.seq, d.frag ? (uint8_t)(d.frag_off / 16u) : 0,
		      d.frag ? (uint8_t)((d.frag_total + 15u) / 16u) : 1, d.len, air);
}

static uint8_t popcount32(uint32_t x)
{
	uint8_t n = 0;

	for (; x; x &= x - 1) {
		n++;
	}
	return n;
}

/*
 * Hopping: frame f is on base + (the (f mod n)-th entry of a permutation of
 * mask's bits), a new permutation for every cycle of n frames, drawn with a
 * PRNG keyed by seed and cycle. Every carrier comes once per cycle, so a PT
 * that listens on one carrier for n + 1 frames hears a beacon.
 */
static uint16_t carrier_for(struct tdma_mac *m, uint16_t base, uint32_t mask, uint32_t seed,
			    uint32_t frame)
{
	uint8_t n = popcount32(mask);
	uint32_t cycle, x;

	if (n == 0) {
		return base;
	}
	cycle = frame / n;
	if (!m->hop_cached || m->hop_cycle != cycle || m->hop_key != (mask ^ seed) ||
	    m->hop_n != n) {
		uint8_t k = 0;

		for (uint8_t i = 0; i < 32; i++) {
			if (mask & (1u << i)) {
				m->hop_perm[k++] = i;
			}
		}
		x = (seed ^ (cycle * 2654435761u)) | 1u;
		for (uint8_t i = (uint8_t)(n - 1); i > 0; i--) {
			uint8_t j, t;

			x ^= x << 13;
			x ^= x >> 17;
			x ^= x << 5;
			j = (uint8_t)(x % (uint32_t)(i + 1));
			t = m->hop_perm[i];
			m->hop_perm[i] = m->hop_perm[j];
			m->hop_perm[j] = t;
		}
		m->hop_cycle = cycle;
		m->hop_key = mask ^ seed;
		m->hop_n = n;
		m->hop_cached = true;
	}
	return (uint16_t)(base + m->hop_perm[frame % n]);
}

/* Carrier of the ops of frame (a pending move takes effect at its frame). */
static uint16_t op_ch(struct tdma_mac *m, uint32_t frame)
{
	if (m->move_valid && (int32_t)(frame - m->move_frame) >= 0) {
		return m->move_mask ? carrier_for(m, m->hop_base, m->move_mask, m->hop_seed, frame)
				    : m->move_ch;
	}
	return m->hop_mask ? carrier_for(m, m->hop_base, m->hop_mask, m->hop_seed, frame) : m->chan;
}

static bool is_dl(const struct tdma_slot *s)
{
	return s->use == TDMA_SLOT_BEACON || s->use == TDMA_SLOT_DL;
}

static bool is_ul(const struct tdma_slot *s)
{
	return s->use == TDMA_SLOT_UL || s->use == TDMA_SLOT_CONTENTION;
}

static bool is_flex(const struct tdma_slot *s)
{
	return s->use == TDMA_SLOT_FLEX;
}

static bool is_dl(const struct tdma_slot *s);

/*
 * Whether an UL long burst in FLEX slot fj may use the early extent
 * (subslot - ul_early, up to ul_len): always when granted a DL period ahead;
 * granted just in time only when the PT still decodes the grant before it must
 * commit the burst (TDMA_GRANT_DECODE_TICKS after the announcing DL burst).
 */
static bool flex_ul_early_ok(const struct tdma_plan *pl, uint8_t fj, bool ahead)
{
	const struct tdma_slot *fs = &pl->slots[fj];
	int k = (int)fj - 1;

	if (ahead) {
		return true;
	}
	while (k >= 0 && !is_dl(&pl->slots[k])) {
		k--;
	}
	return k >= 0 &&
	       (int64_t)(fs->subslot - fs->ul_early - pl->slots[k].subslot - pl->slots[k].len) *
			       TDMA_SUBSLOT_TICKS >=
		       (int64_t)(TDMA_FLEX_COMMIT_LEAD_TICKS + TDMA_RX_PROC_TICKS +
				 TDMA_GRANT_DECODE_TICKS);
}

/* Subslots an UL long burst of FLEX slot fj starts before the region. */
static uint8_t flex_early(const struct tdma_plan *pl, uint8_t fj, bool ul, bool ahead)
{
	return ul && flex_ul_early_ok(pl, fj, ahead) ? pl->slots[fj].ul_early : 0;
}

/* Longest long burst of FLEX slot fj in one direction. */
static uint8_t flex_max_len(const struct tdma_plan *pl, uint8_t fj, bool ul, bool ahead)
{
	const struct tdma_slot *s = &pl->slots[fj];

	return ul && s->ul_len && flex_ul_early_ok(pl, fj, ahead) ? s->ul_len : s->len;
}

/*
 * TDMA_PLAN_F_OPEN: in every TDMA_OPEN_EVERY-th frame the plan's last
 * UL slot (its only PT's second one) is a contention slot.
 */
static bool open_slot(const struct tdma_plan *pl, const struct tdma_slot *s, uint32_t frame)
{
	return (pl->flags & TDMA_PLAN_F_OPEN) && s == &pl->slots[pl->n_slots - 1] &&
	       s->use == TDMA_SLOT_UL && frame % TDMA_OPEN_EVERY == 0u;
}

static bool is_pt(const struct tdma_mac *m)
{
	return m->cfg.role == TDMA_ROLE_PT;
}

static uint64_t slot_start(const struct tdma_mac *m, uint32_t frame, const struct tdma_slot *s)
{
	int64_t df = (int32_t)(frame - m->ref_frame);

	return m->ref_start + (uint64_t)(df * (int64_t)TDMA_FRAME_TICKS) +
	       (uint64_t)s->subslot * TDMA_SUBSLOT_TICKS;
}

/* A packet fills its whole burst (its GI is inside); no extra guard needed. */
static uint32_t burst_air(const struct tdma_slot *s)
{
	return s->len * TDMA_SUBSLOT_TICKS;
}

/* Per-packet overhead: security header + MIC, or the old MIC reserve when security is off. */
static size_t ovh_of(bool sec)
{
	return sec ? TDMA_SEC_OVERHEAD : TDMA_MIC_RESERVE;
}

static size_t ovh(const struct tdma_mac *m)
{
	return ovh_of(m->sec.on);
}

/* Usable PHY payload (records) of a burst of len subslots. */
static size_t len_cap_o(uint8_t mcs, uint8_t len, size_t o)
{
	size_t tbs = tdma_tbs(mcs, len);

	tbs = tbs > TDMA_PKT_MAX ? TDMA_PKT_MAX : tbs;
	return tbs > o ? tbs - o : 0;
}

#define len_cap(m, mcs, len) len_cap_o(mcs, len, ovh(m))

/* Usable PHY payload of a burst at the MCS in use. */
static size_t burst_cap_o(uint8_t mcs, const struct tdma_slot *s, size_t o)
{
	return len_cap_o(mcs, s->len, o);
}

#define burst_cap(m, mcs, s) burst_cap_o(mcs, s, ovh(m))

size_t tdma_payload_cap(const struct tdma_mac *m, size_t tbs)
{
	tbs = tbs > TDMA_PKT_MAX ? TDMA_PKT_MAX : tbs;
	return tbs > ovh(m) ? tbs - ovh(m) : 0;
}

/* Index into m->flex of FLEX slot si (FLEX slots before it). */
static uint8_t flex_idx(const struct tdma_plan *plan, uint8_t si)
{
	uint8_t n = 0;

	for (uint8_t i = 0; i < si; i++) {
		n += is_flex(&plan->slots[i]);
	}
	return n;
}

/* The FLEX slot announced by DL slot si (the next FLEX before the next DL), or -1. */
static int flex_after(const struct tdma_plan *plan, uint8_t si)
{
	for (uint8_t j = (uint8_t)(si + 1); j < plan->n_slots && !is_dl(&plan->slots[j]); j++) {
		if (is_flex(&plan->slots[j])) {
			return j;
		}
	}
	return -1;
}

/* The FLEX region continuing the train of FLEX slot fj (the next slot, if FLEX), or -1. */
static int flex_next_in_train(const struct tdma_plan *plan, int fj)
{
	return fj >= 0 && fj + 1 < plan->n_slots && is_flex(&plan->slots[fj + 1]) ? fj + 1 : -1;
}

/*
 * Grant-ahead: the FLEX slot granted in DL slot si (the one after the next DL
 * burst), -1 if none; *wrap = 1 when it is in the next frame.
 */
static int flex_ahead(const struct tdma_plan *plan, uint8_t si, uint32_t *wrap)
{
	uint8_t nd = 0;

	*wrap = 1;
	for (uint8_t j = (uint8_t)(si + 1); j < plan->n_slots; j++) {
		if (is_dl(&plan->slots[j])) {
			nd = j;
			*wrap = 0;
			break;
		}
	}
	return flex_after(plan, nd);
}

/* How deep the links' queues are under the plan in use (link_set_cap()). */
static uint8_t q_depth(const struct tdma_mac *m)
{
	return !m->train_plan                           ? TDMA_QD_STD
	       : (m->plan->flags & TDMA_PLAN_F_PATTERN) ? TDMA_QD_FRAME
							: TDMA_QD_TRAIN;
}

static void flex_clear(struct tdma_mac *m)
{
	memset(m->flex, 0, sizeof(m->flex));
}

/* Plan T2: FLEX regions come as one pattern per frame (TDMA_PLAN_F_PATTERN). */
static bool pat_plan(const struct tdma_plan *p)
{
	return p && (p->flags & TDMA_PLAN_F_PATTERN);
}

/* The pattern of frame `frame` (when it runs the plan in use). */
static const struct tdma_t2 *t2_of(const struct tdma_mac *m, uint32_t frame)
{
	const struct tdma_t2 *t = &m->t2[frame & 1u];

	return t->valid && t->frame == frame && t->plan == m->plan->id ? t : NULL;
}

static uint8_t pat_stat_i(uint8_t plan_id)
{
	return plan_id == TDMA_PLAN_T2D ? 1 : 0;
}

static uint8_t flex_i(const struct tdma_mac *m, uint8_t si);

/*
 * Pattern plans: the air length of what this node receives in FLEX slot si of
 * frame f (0: nothing), the region's length while the frame's pattern is not
 * known.
 */
static uint8_t t2_rx_len(const struct tdma_mac *m, uint8_t si, uint32_t f)
{
	const struct tdma_t2 *t = t2_of(m, f);
	int8_t b;

	if (!t) {
		return m->plan->slots[si].len;
	}
	if (is_pt(m) && t->pos != (uint8_t)m->my_pos) {
		return 0;
	}
	b = tdma_pat_burst(m->plan, t->pat, flex_i(m, si));
	if (is_pt(m) ? b <= 0 : b >= 0) {
		return 0;
	}
	return (uint8_t)(b < 0 ? -b : b);
}

/*
 * SNR average in 1/16 dB: falls fast (1/2 per sample), rises slowly (1/8),
 * so a fading link drops its MCS within a burst or two and a good one does
 * not climb on a lucky sample. The first sample sets it.
 */
static void snr_avg(int16_t *avg_q4, uint8_t *n, int16_t snr_q2)
{
	int32_t x = (int32_t)snr_q2 * 4;

	if (*n == 0) {
		*avg_q4 = (int16_t)x;
	} else {
		*avg_q4 = (int16_t)(*avg_q4 + (x - *avg_q4) / (x < *avg_q4 ? 2 : 8));
	}
	if (*n < 255) {
		(*n)++;
	}
}

/*
 * Beacon record (security extension included when on, an announced switch
 * not). Plans of the hybrid format (the ones mesh builds run) keep room for
 * the tree extension and a full route record ; the small DL bursts
 * of plans A / B / 1x10 carry a route record only where it fits.
 */
static size_t beacon_rec_len(const struct tdma_plan *plan, bool sec)
{
	/*
	 * and the mesh layer's app bytes (TDMA_BEXT_APP, at most 2 + 6):
	 * a relay's route record with its path and the app bytes would not fit the
	 * route record's room alone, and the burst's grant record (a train's three
	 * entries) is built last, from what is left.
	 */
	return TDMA_REC_HDR_LEN + TDMA_BEACON_FIXED_LEN +
	       (size_t)plan->n_positions * TDMA_BEACON_ENTRY_LEN + (sec ? TDMA_BEACON_SEC_LEN : 0) +
	       (tdma_plan_has_flex(plan) ? TDMA_BEACON_TREE_LEN + TDMA_BEACON_ROUTE_HDR_LEN +
						   TDMA_ROUTE_MAX + 2u + TDMA_BEXT_APP_MAX
					 : 0);
}

/* Largest PDU every DL burst can carry next to the beacon. */
static size_t dl_pdu_cap(const struct tdma_plan *plan, uint8_t mcs, bool sec)
{
	size_t cap = TDMA_PDU_MAX;

	for (uint8_t i = 0; i < plan->n_slots; i++) {
		const struct tdma_slot *s = &plan->slots[i];
		size_t c = burst_cap_o(mcs, s, ovh_of(sec));

		if (!is_dl(s)) {
			continue;
		}
		c -= s->use == TDMA_SLOT_BEACON ? beacon_rec_len(plan, sec) : 0;
		c -= tdma_plan_has_flex(plan) ? TDMA_GRANT_REC_LEN : 0;
		c = c > TDMA_REC_HDR_LEN ? c - TDMA_REC_HDR_LEN : 0;
		cap = c < cap ? c : cap;
	}
	return cap;
}

/* Largest PDU every UL / contention burst carries. */
static size_t ul_pdu_cap(const struct tdma_plan *plan, uint8_t mcs, bool sec)
{
	size_t cap = TDMA_PDU_MAX;

	if (pat_plan(plan)) {
		/* no guaranteed UL slot: the smallest UL burst of a pattern (2 ss, as plan H's) */
		static const struct tdma_slot ul2 = {0, 2, TDMA_SLOT_UL, 0, 0, 0};
		size_t c = burst_cap_o(mcs, &ul2, ovh_of(sec));

		c -= TDMA_STATUS_REC_LEN + TDMA_REC_HDR_LEN;
		return c < cap ? c : cap;
	}

	for (uint8_t i = 0; i < plan->n_slots; i++) {
		const struct tdma_slot *s = &plan->slots[i];
		size_t c = burst_cap_o(mcs, s, ovh_of(sec));

		if (!is_ul(s)) {
			continue;
		}
		c -= tdma_plan_has_flex(plan) ? TDMA_STATUS_REC_LEN : 0;
		c = c > TDMA_REC_HDR_LEN ? c - TDMA_REC_HDR_LEN : 0;
		cap = c < cap ? c : cap;
	}
	return cap;
}

/* Can this plan run at this MCS (beacon, an assoc request and a fragment fit)? */
static bool plan_mcs_ok(const struct tdma_plan *plan, uint8_t mcs, bool sec)
{
	size_t need = TDMA_DATA_HDR_LEN + TDMA_FRAG_HDR_LEN + 8;

	return mcs <= 4 && dl_pdu_cap(plan, mcs, sec) >= need &&
	       ul_pdu_cap(plan, mcs, sec) >= need && ul_pdu_cap(plan, mcs, sec) >= TDMA_ASSOC_LEN;
}

/* ---- PHY ops ------------------------------------------------------------------ */

static struct tdma_op *op_find(struct tdma_mac *m, uint32_t handle)
{
	for (int i = 0; i < TDMA_MAX_OPS; i++) {
		if (m->ops[i].used && m->ops[i].handle == handle) {
			return &m->ops[i];
		}
	}
	return NULL;
}

static struct tdma_op *op_new(struct tdma_mac *m)
{
	for (int i = 0; i < TDMA_MAX_OPS; i++) {
		if (!m->ops[i].used) {
			memset(&m->ops[i], 0, sizeof(m->ops[i]));
			m->next_handle = m->next_handle + 1 ? m->next_handle + 1 : 1;
			m->ops[i].handle = m->next_handle;
			return &m->ops[i];
		}
	}
	m->stats.port_errors++;
	return NULL;
}

static void op_commit(struct tdma_mac *m, struct tdma_op *op)
{
	op->used = true;
	op->plan = m->plan;
	m->n_ops++;
	if (m->n_ops > m->stats.ops_hwm) {
		m->stats.ops_hwm = m->n_ops;
	}
}

/* RX window from the nominal start of slot first to the end of slot last. */
static struct tdma_op *rx_slots(struct tdma_mac *m, uint8_t first, uint8_t last, uint32_t frame,
				uint64_t start)
{
	const struct tdma_slot *a = &m->plan->slots[first];
	const struct tdma_slot *b = &m->plan->slots[last];
	uint32_t dur = (uint32_t)(b->subslot + b->len - a->subslot) * TDMA_SUBSLOT_TICKS +
		       2 * TDMA_RX_MARGIN_TICKS;
	struct tdma_op *op = op_new(m);

	if (!op) {
		return NULL;
	}
	op->ch = op_ch(m, frame);
	if (m->port.rx(m->port.ctx, op->handle, start - TDMA_RX_MARGIN_TICKS, dur, op->ch)) {
		m->stats.port_errors++;
		return NULL;
	}
	op->use = a->use;
	op->slot = first;
	op->slot_end = last;
	op->frame = frame;
	op->start = start;
	op_commit(m, op);
	return op;
}

/* RX window for a long burst of f->len subslots in FLEX slot si. */
static struct tdma_op *rx_flex(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start,
			       const struct tdma_flex *f)
{
	struct tdma_op *op = op_new(m);

	if (!op) {
		return NULL;
	}
	op->ch = op_ch(m, frame);
	/*
	 * FT monitor: a speculative UL region is usually empty. Received with
	 * RSSI (the port's scan op), it measures the own channel for free; it
	 * counts only if nobody transmitted in it.
	 */
	/*
	 * Only as often as the monitor needs it (half a period): every RSSI
	 * report is an IPC event, and 200 of them a second made the modem take
	 * TX ops late on the DK.
	 */
	op->mon = !is_pt(m) && f->ul && f->spec && m->port.scan && mon_period(m) &&
		  (int32_t)(frame - m->mon_last) >= (int32_t)(mon_period(m) / 2) &&
		  !ft_relay_child(m);
	if (op->mon) {
		m->mon_last =
			frame; /* a reception in it voids the measurement; try again next region */
	}
	if ((op->mon ? m->port.scan : m->port.rx)(
		    m->port.ctx, op->handle, start - TDMA_RX_MARGIN_TICKS,
		    (uint32_t)f->len * TDMA_SUBSLOT_TICKS + 2 * TDMA_RX_MARGIN_TICKS, op->ch)) {
		m->stats.port_errors++;
		return NULL;
	}
	op->use = TDMA_SLOT_FLEX;
	op->slot = si;
	op->slot_end = si;
	op->frame = frame;
	op->start = start;
	op->flex = *f;
	op_commit(m, op);
	return op;
}

/* One packet of subslots at mcs from m->pkt_buf; lbt_ticks > 0: listen before talk. */
static int tx_burst_lbt(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start,
			uint32_t dst_rd, size_t len, uint8_t subslots, uint8_t mcs,
			uint32_t lbt_ticks)
{
	const struct tdma_slot *s = &m->plan->slots[si];
	struct tdma_phy_hdr h = {
		.subslots = subslots,
		.short_nwid = (uint8_t)m->cfg.network_id,
		.tx_short = tdma_short_rd(m->cfg.rd_id),
		.rx_short =
			dst_rd == TDMA_RD_BROADCAST ? TDMA_SHORT_BROADCAST : tdma_short_rd(dst_rd),
		.mcs = mcs,
	};
	struct tdma_op *op = op_new(m);

	if (!op) {
		return -ENOMEM;
	}
	tdma_phy_hdr_encode(&h, m->hdr_buf, sizeof(m->hdr_buf));
	if (m->sec.on && sec_seal(m, si, frame, &h, &len)) {
		/* never sent unsealed */
		m->stats.sec_seal_err++;
		return -EIO;
	}
	op->ch = op_ch(m, frame);
	if (m->port.tx(m->port.ctx, op->handle, start, op->ch, m->hdr_buf, TDMA_PHY_HDR_LEN,
		       m->pkt_buf, len, subslots, mcs, lbt_ticks,
		       (int8_t)CFGV(m, rssi_busy_dbm, TDMA_DEF_RSSI_BUSY_DBM))) {
		m->stats.port_errors++;
		return -EIO;
	}
	op->lbt = lbt_ticks > 0;
	op->use = s->use;
	op->slot = si;
	op->slot_end = si;
	op->is_tx = true;
	op->frame = frame;
	op->start = start;
	op_commit(m, op);
	return 0;
}

static int tx_burst(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start, uint32_t dst_rd,
		    size_t len, uint8_t subslots, uint8_t mcs)
{
	return tx_burst_lbt(m, si, frame, start, dst_rd, len, subslots, mcs, 0);
}

static int tx_slot(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start, uint32_t dst_rd,
		   size_t len)
{
	return tx_burst(m, si, frame, start, dst_rd, len, m->plan->slots[si].len, m->mcs);
}

/*
 * Records for one peer into m->pkt_buf from *off, up to cap: the first PDU
 * with ack mode `mode`, then data PDUs while they fit. Returns PDUs added.
 */
static int build_records(struct tdma_mac *m, struct tdma_link *l, uint64_t start, uint64_t end,
			 int mode, uint8_t addr, size_t *off, size_t cap)
{
	struct link_params lp = link_params(m);
	uint64_t now = m->port.now(m->port.ctx);
	int added = 0;

	peer_rx_poll(m, (struct tdma_peer *)(uintptr_t)((const uint8_t *)l -
							offsetof(struct tdma_peer, link)));
	for (;;) {
		/* long bursts: one PDU may take all the room (a fragment cut to fit) */
		size_t room = tdma_rec_room_long(cap, *off);
		size_t at = *off;
		int n;

		if (room < TDMA_ACK_LEN) {
			break;
		}
		n = link_build(l, &lp, now, start, end, mode,
			       m->pkt_buf + at + TDMA_REC_LONG_HDR_LEN, room, &m->stats);
		if (n <= 0) {
			break;
		}
		tdma_rec_close_long(m->pkt_buf, off, addr, (size_t)n);
		trace_pdu(m, TDMA_TRACE_TX, is_pt(m) ? m->parent_rd : 0,
			  m->pkt_buf + *off - (size_t)n, (size_t)n, start);
		added++;
		if (m->pkt_buf[*off - (size_t)n] != TDMA_PDU_DATA) {
			break; /* an ack-only PDU ends it */
		}
		mode = LB_DATA;
	}
	return added;
}

/* PT: status record (queue after this burst, DL quality) at *off; room was reserved. */
static void pt_status_rec(struct tdma_mac *m, size_t *off, size_t cap)
{
	size_t q = link_pending_bytes(&m->peers[0].link);
	struct tdma_status st = {
		.flags = (uint8_t)((m->cfg.relay ? TDMA_STF_RELAY : 0) |
				   (m->hgx_ok ? TDMA_STF_HGX : 0)),
		.queued = (uint16_t)(q > 0xffff ? 0xffff : q),
		.snr = m->dl_snr_valid ? (int8_t)(m->dl_snr_q4 / 16) : (int8_t)TDMA_SNR_UNKNOWN,
		.rssi = m->dl_rssi,
	};
	int n = tdma_status_encode(&st, m->pkt_buf + *off + TDMA_REC_HDR_LEN,
				   tdma_rec_room(cap, *off));

	if (n > 0) {
		tdma_rec_close(m->pkt_buf, off, (uint8_t)m->my_pos, (size_t)n);
	}
}

static void stop_rx_ops(struct tdma_mac *m)
{
	for (int i = 0; i < TDMA_MAX_OPS; i++) {
		if (m->ops[i].used && !m->ops[i].is_tx) {
			m->port.rx_stop(m->port.ctx, m->ops[i].handle);
		}
	}
}

/* ---- channel access: table, selection, scan, LBT, monitor, hopping --------------------- */

/* Channel 0: the FT chooses (and changes) the carrier, PTs search all of them. */
static bool ch_auto(const struct tdma_mac *m)
{
	return m->cfg.channel == 0;
}

static uint8_t ch_count(const struct tdma_mac *m)
{
	return (uint8_t)(m->cfg.ch_max - m->cfg.ch_min + 1);
}

/* Carriers of the table we may use (cfg ch_mask; a fixed channel is always usable). */
static uint32_t ch_usable_mask(const struct tdma_mac *m)
{
	uint32_t all = ch_count(m) >= 32 ? 0xffffffffu : ((1u << ch_count(m)) - 1u);

	if (!ch_auto(m)) {
		return 1u << (m->cfg.channel - m->cfg.ch_min);
	}
	return m->cfg.ch_mask ? (m->cfg.ch_mask & all) : all;
}

static bool ch_usable(const struct tdma_mac *m, uint16_t ch)
{
	return ch >= m->cfg.ch_min && ch <= m->cfg.ch_max &&
	       (ch_usable_mask(m) & (1u << (ch - m->cfg.ch_min)));
}

static struct tdma_chan_info *ch_info(struct tdma_mac *m, uint16_t ch)
{
	if (ch < m->cfg.ch_min || ch > m->cfg.ch_max) {
		return NULL;
	}
	return &m->chans[ch - m->cfg.ch_min];
}

/* Is ch one the cluster operates on (the carrier, or a member of the hop set)? */
static bool ch_in_use(const struct tdma_mac *m, uint16_t ch)
{
	if (m->hop_mask) {
		return ch >= m->hop_base && ch < m->hop_base + 32 &&
		       (m->hop_mask & (1u << (ch - m->hop_base)));
	}
	return ch == m->chan;
}

static uint32_t lbt_ticks(const struct tdma_mac *m)
{
	return m->cfg.lbt_ticks == TDMA_OFF ? 0 : CFGV(m, lbt_ticks, TDMA_DEF_LBT_TICKS);
}

static uint32_t rach_lbt_ticks(const struct tdma_mac *m)
{
	return m->cfg.rach_lbt_ticks == TDMA_OFF ? 0
						 : CFGV(m, rach_lbt_ticks, TDMA_DEF_RACH_LBT_TICKS);
}

static uint32_t mon_period(const struct tdma_mac *m)
{
	return m->cfg.mon_period == TDMA_OFF || !m->port.rssi
		       ? 0
		       : CFGV(m, mon_period, TDMA_DEF_MON_PERIOD_FRAMES);
}

/* FT: does the beacon of frame go out with LBT (first beacon on a channel)? */
static bool lbt_beacon(const struct tdma_mac *m, uint32_t frame)
{
	return m->cfg.role == TDMA_ROLE_FT && lbt_ticks(m) &&
	       (m->lbt_pending || (m->move_valid && m->move_frame == frame));
}

/*
 * Count measured subslots into a table entry ("free" / "possible" / "busy",
 * TS 103 636-4 5.1.2). Old counts are halved once the entry gets large, so a
 * background entry follows the channel. The monitor window counts (w_*) are
 * kept beside. Returns the busy subslots.
 */
static uint32_t ch_account(struct tdma_mac *m, struct tdma_chan_info *c, const int8_t *ss, size_t n,
			   uint32_t frame)
{
	const int8_t fr = (int8_t)CFGV(m, rssi_free_dbm, TDMA_DEF_RSSI_FREE_DBM);
	const int8_t bz = (int8_t)CFGV(m, rssi_busy_dbm, TDMA_DEF_RSSI_BUSY_DBM);
	uint32_t busy = 0, poss = 0, free_ = 0;
	int8_t mx = -128;

	if (n > 1000u) {
		n = 1000u;
	}
	for (size_t i = 0; i < n; i++) {
		int8_t v = ss[i];

		if (v > bz) {
			busy++;
		} else if (v > fr) {
			poss++;
		} else {
			free_++;
		}
		mx = v > mx ? v : mx;
	}
	if (!c->valid || c->n_ss == 0) {
		c->max_dbm = -128;
	}
	while (c->n_ss + n > 2000u) {
		c->n_ss /= 2;
		c->n_free /= 2;
		c->n_poss /= 2;
		c->n_busy /= 2;
		c->max_dbm = -128; /* the recent measurement sets it again */
	}
	c->valid = true;
	c->n_ss = (uint16_t)(c->n_ss + n);
	c->n_free = (uint16_t)(c->n_free + free_);
	c->n_poss = (uint16_t)(c->n_poss + poss);
	c->n_busy = (uint16_t)(c->n_busy + busy);
	c->max_dbm = mx > c->max_dbm ? mx : c->max_dbm;
	c->frame = frame;
	if (c->w_ss < 60000u) {
		if (c->w_ss == 0) {
			c->w_max = -128;
		}
		c->w_ss = (uint16_t)(c->w_ss + n);
		c->w_busy = (uint16_t)(c->w_busy + busy);
		c->w_max = mx > c->w_max ? mx : c->w_max;
	}
	return busy;
}

static bool ch_adjacent_cluster(const struct tdma_mac *m, uint16_t ch)
{
	for (int d = -1; d <= 1; d += 2) {
		int x = (int)ch + d;

		if (x >= m->cfg.ch_min && x <= m->cfg.ch_max &&
		    m->chans[x - m->cfg.ch_min].clusters) {
			return true;
		}
	}
	return false;
}

static bool ch_suitable(const struct tdma_mac *m, const struct tdma_chan_info *c)
{
	uint32_t ok = (uint32_t)c->n_free + c->n_poss;

	return c->n_ss &&
	       ok * 100u >= (uint32_t)CFGV(m, suitable_pct, TDMA_DEF_SUITABLE_PCT) * c->n_ss;
}

/*
 * Ordering key, lower is better. TS 103 636-4 5.1.2 (all subslots free first,
 * then fewest busy, then fewest possible), with Nordic's extra rule that a
 * channel where another cluster was heard comes last, and an unsuitable one
 * (< SCAN_SUITABLE free or possible) after every suitable one. A neighbour
 * carrier with a cluster (adjacent carriers overlap) is next to last among
 * equals; the quietest wins a tie.
 */
static bool ch_avoided(const struct tdma_mac *m, uint16_t ch)
{
	for (int i = 0; i < 4; i++) {
		uint16_t a = m->avoid_ch[i];

		if (a && (ch > a ? ch - a : a - ch) <= 1) {
			return true;
		}
	}
	return false;
}

void tdma_ft_set_avoid(struct tdma_mac *m, const uint16_t *ch, size_t n)
{
	for (size_t i = 0; i < 4; i++) {
		m->avoid_ch[i] = i < n ? ch[i] : 0;
	}
}

static uint64_t ch_key(const struct tdma_mac *m, const struct tdma_chan_info *c)
{
	uint64_t busy = (uint64_t)c->n_busy * 1000u / c->n_ss;
	uint64_t poss = (uint64_t)c->n_poss * 1000u / c->n_ss;

	return ((uint64_t)(c->clusters != 0 || ch_avoided(m, c->ch)) << 40) |
	       ((uint64_t)!ch_suitable(m, c) << 39) |
	       ((uint64_t)(c->n_busy + c->n_poss != 0) << 38) |
	       ((uint64_t)ch_adjacent_cluster(m, c->ch) << 37) | (busy << 24) | (poss << 12) |
	       (uint64_t)(c->max_dbm + 128);
}

uint16_t tdma_chan_best(const struct tdma_mac *m, uint16_t except)
{
	const struct tdma_chan_info *best = NULL, *pref = NULL;
	uint64_t best_key = UINT64_MAX;

	for (uint8_t i = 0; i < ch_count(m); i++) {
		const struct tdma_chan_info *c = &m->chans[i];

		if (!c->valid || !c->n_ss || c->ch == except || !ch_usable(m, c->ch)) {
			continue;
		}
		if (c->ch == m->cfg.pref_channel) {
			pref = c;
		}
		if (ch_key(m, c) < best_key) {
			best_key = ch_key(m, c);
			best = c;
		}
	}
	/* The preferred carrier when it is good enough: no cluster on or next to
	 * it, nothing busy, SCAN_SUITABLE free/possible. PTs that remember it find
	 * the cluster faster.
	 */
	if (pref && !pref->clusters && !pref->n_busy && ch_suitable(m, pref) &&
	    !ch_adjacent_cluster(m, pref->ch)) {
		return pref->ch;
	}
	return best ? best->ch : 0;
}

/* A carrier good enough for the hop set: suitable, no cluster, busy below the monitor threshold. */
static bool ch_hop_ok(const struct tdma_mac *m, const struct tdma_chan_info *c)
{
	return c->valid && c->n_ss && !c->clusters && ch_suitable(m, c) &&
	       (uint32_t)c->n_busy * 100u <
		       (uint32_t)CFGV(m, mon_busy_pct, TDMA_DEF_MON_BUSY_PCT) * c->n_ss;
}

/* FT scan: next usable carrier index from scan_i; false when done. */
static bool scan_next(struct tdma_mac *m)
{
	while (m->scan_i < ch_count(m) && !ch_usable(m, (uint16_t)(m->cfg.ch_min + m->scan_i))) {
		m->scan_i++;
	}
	return m->scan_i < ch_count(m);
}

static void ft_win_reset(struct tdma_mac *m, uint32_t frame)
{
	m->win_start = frame;
	for (uint8_t i = 0; i < ch_count(m); i++) {
		m->chans[i].w_ss = m->chans[i].w_busy = 0;
		m->chans[i].w_max = -128;
	}
}

static void ft_begin(struct tdma_mac *m, uint64_t now)
{
	uint32_t f0 = m->cfg.start_frame;

	m->ref_start = now + 2 * TDMA_COMMIT_LEAD_TICKS + TDMA_FRAME_TICKS;
	m->ref_frame = f0;
	if (m->cfg.relay && m->follow_valid) {
		/* a relay's cluster: the parent's grid and frame numbers, from the first whole
		 * frame */
		uint64_t first = now + 2 * TDMA_COMMIT_LEAD_TICKS;

		m->ref_start = m->follow_start;
		m->ref_frame = m->follow_frame;
		f0 = m->follow_frame;
		while (slot_start(m, f0, &m->plan->slots[0]) < first) {
			f0++;
		}
		while (slot_start(m, f0 - 1u, &m->plan->slots[0]) >= first) {
			f0--;
		}
	}
	m->cur_frame = f0;
	m->cur_slot = 0;
	m->state = TDMA_ST_FT;
	m->lbt_pending = lbt_ticks(m) != 0;
	m->fs_valid = m->fs_placed = false;
	m->fs_handle = 0;
	m->lbt_fail = 0;
	m->lbt_retry_frame = f0;
	m->mon_last = f0;
	m->bg_last = f0;
	m->move_hold = f0;
	m->sec.sess_start = f0;
	ft_win_reset(m, f0);
	if (!m->lbt_pending) {
		m->ft_started = true;
		emit(m, TDMA_EVT_FT_STARTED, m->cfg.rd_id, TDMA_CAUSE_NONE, 0, 0);
	}
}

static void ft_scan_kick(struct tdma_mac *m, uint64_t now)
{
	uint16_t ch;
	uint32_t frames = ch_auto(m) ? CFGV(m, scan_frames, TDMA_DEF_SCAN_FRAMES)
				     : CFGV(m, fixed_scan_frames, TDMA_DEF_FIXED_SCAN_FRAMES);
	struct tdma_chan_info *c;
	struct tdma_op *op;

	if (m->state != TDMA_ST_FT_SCAN || m->search_handle || m->n_ops || !scan_next(m)) {
		return;
	}
	ch = (uint16_t)(m->cfg.ch_min + m->scan_i);
	c = ch_info(m, ch);
	*c = (struct tdma_chan_info){.ch = ch, .w_max = -128};
	if (m->port.away && m->port.away(m->port.ctx, 0, frames * TDMA_FRAME_TICKS)) {
		m->stats.relay_away++;
		m->retry_at = now + TDMA_FRAME_TICKS;
		return;
	}
	op = op_new(m);
	if (op && m->port.scan(m->port.ctx, op->handle, 0, frames * TDMA_FRAME_TICKS, ch) == 0) {
		op->use = USE_SCAN;
		op->ch = ch;
		op_commit(m, op);
		m->search_handle = op->handle;
		m->search_ch = ch;
		m->retry_at = UINT64_MAX;
		m->stats.scans++;
	} else {
		if (op) {
			m->stats.port_errors++;
		}
		m->retry_at = now + TDMA_FRAME_TICKS;
	}
}

static void ft_scan_done(struct tdma_mac *m, uint64_t now)
{
	uint16_t ch = ch_auto(m) ? tdma_chan_best(m, 0) : m->cfg.channel;
	uint32_t hop = 0;

	m->chan = ch ? ch : m->chan;
	m->hop_mask = 0;
	m->hop_base = m->cfg.ch_min;
	if (ch_auto(m) && m->cfg.hop) {
		for (uint8_t i = 0; i < ch_count(m); i++) {
			if (ch_usable(m, m->chans[i].ch) && ch_hop_ok(m, &m->chans[i])) {
				hop |= 1u << i;
			}
		}
		if (popcount32(hop) >= 2) {
			m->hop_mask = hop;
			do {
				m->hop_seed = rng_next(m) ^ m->cfg.network_id;
			} while (m->hop_seed == 0);
			m->hop_cached = false;
			m->chan = carrier_for(m, m->hop_base, hop, m->hop_seed, 0);
		}
	}
	emit(m, TDMA_EVT_CHANNEL_SELECTED, m->cfg.rd_id, TDMA_CAUSE_NONE, 0, 0);
	ft_begin(m, now);
}

/* FT scan op: a packet of ours (any network); an FT's beacon is reported. */
static void ft_scan_rx(struct tdma_mac *m, const struct tdma_op *op, const uint8_t *pkt, size_t len,
		       int16_t rssi)
{
	struct tdma_chan_info *c = ch_info(m, op->ch);
	struct tdma_beacon b;

	/* informational only: a secured beacon's cleartext part is read without verifying */
	if (!c || clear_beacon(m, pkt, len, &b) || b.ft_rd_id == m->cfg.rd_id) {
		return;
	}
	if (c->cluster_rd != b.ft_rd_id || c->cluster_nwid != b.network_id) {
		c->cluster_rd = b.ft_rd_id;
		c->cluster_nwid = b.network_id;
		emit_full(m, TDMA_EVT_SCAN_CLUSTER, b.ft_rd_id, b.network_id, TDMA_CAUSE_NONE, 0,
			  rssi, op->ch);
	}
}

/* FT, before an LBT beacon in frame + 1: does an op of ours ending at end break its quiet? */
static bool ft_quiet(const struct tdma_mac *m, uint32_t frame, uint64_t end, uint32_t gap_ss)
{
	uint32_t lbt = lbt_ticks(m);

	if (!lbt || !m->move_valid || m->move_frame != frame + 1) {
		return false;
	}
	return end + (uint64_t)gap_ss * TDMA_SUBSLOT_TICKS + lbt >
	       slot_start(m, frame + 1, &m->plan->slots[0]);
}

/* FT monitor: is a measurement due (idle: the region would go unused / speculative)? */
/*
 * FT: a relay child is associated. Its child cluster transmits in the O
 * blocks, where this FT's FLEX regions lie, on a carrier nearby: on the
 * bench a cluster 2 carriers away measured up to -69 dBm (busy) in them and
 * moved the parent away. With a relay child the own carrier is measured only
 * in empty DL bursts (E blocks), not in idle FLEX regions.
 */
static bool ft_relay_child(const struct tdma_mac *m)
{
	for (uint8_t i = 0; m->cfg.role == TDMA_ROLE_FT && m->plan && i < m->plan->n_positions;
	     i++) {
		if (m->peers[i].rd_id && m->peers[i].relay) {
			return true;
		}
	}
	return false;
}

static bool ft_mon_due(const struct tdma_mac *m, uint32_t frame, bool idle)
{
	uint32_t period = mon_period(m);
	int32_t d = (int32_t)(frame - m->mon_last);

	if (!period || m->lbt_pending) {
		return false;
	}
	return d >= (int32_t)period || (idle && d >= (int32_t)(period / 2));
}

/*
 * FT monitor: carrier of the next measurement in frame: the frame's own
 * carrier; every Nth one a usable carrier the cluster does not use
 * (background scan, the next candidate for a move or for the hop set).
 */
static uint16_t ft_meas_ch(struct tdma_mac *m, uint32_t frame)
{
	uint8_t n = ch_count(m);

	m->mon_seq++;
	if (ch_auto(m) && n > 1 && m->mon_seq % TDMA_MON_BG_EVERY == 0) {
		for (uint8_t k = 1; k <= n; k++) {
			uint8_t i = (uint8_t)((m->bg_rr + k) % n);
			uint16_t ch = (uint16_t)(m->cfg.ch_min + i);

			if (ch_usable(m, ch) && !ch_in_use(m, ch) &&
			    !(m->move_valid && ch == m->move_ch)) {
				m->bg_rr = i;
				return ch;
			}
		}
	}
	return op_ch(m, frame);
}

/* FT: a usable carrier the cluster does not use (round robin), 0 if none. */
static uint16_t ft_bg_ch(struct tdma_mac *m)
{
	uint8_t n = ch_count(m);

	if (!ch_auto(m)) {
		return 0;
	}
	for (uint8_t k = 1; k <= n; k++) {
		uint8_t i = (uint8_t)((m->bg_rr + k) % n);
		uint16_t ch = (uint16_t)(m->cfg.ch_min + i);

		if (ch_usable(m, ch) && !ch_in_use(m, ch) && !(m->move_valid && ch == m->move_ch)) {
			m->bg_rr = i;
			return ch;
		}
	}
	return 0;
}

/* FT: RSSI op over len subslots from start (an idle region of our own frame). */
static void meas_op(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start, uint8_t len,
		    uint16_t ch)
{
	struct tdma_op *op;

	if (ch_in_use(m, ch)) {
		m->mon_last = frame;
	}
	if (!m->port.rssi || !(op = op_new(m))) {
		return;
	}
	if (m->port.rssi(m->port.ctx, op->handle, start, (uint32_t)len * TDMA_SUBSLOT_TICKS, ch)) {
		m->stats.port_errors++;
		return;
	}
	op->use = USE_MEAS;
	op->slot = si;
	op->slot_end = si;
	op->frame = frame;
	op->start = start;
	op->ch = ch;
	op_commit(m, op);
	if (ch_in_use(m, ch)) {
		m->stats.meas++;
	} else {
		m->stats.meas_bg++;
	}
}

/*
 * Subslots a window must have measured on a carrier before it counts: 7, or
 * the FLEX region's length when that is shorter (a background measurement
 * takes one region).
 */
static uint16_t meas_min_ss(const struct tdma_mac *m)
{
	uint16_t n = 7;

	for (uint8_t i = 0; m->plan && i < m->plan->n_slots; i++) {
		if (is_flex(&m->plan->slots[i]) && m->plan->slots[i].len < n) {
			n = m->plan->slots[i].len;
		}
	}
	return n;
}

static bool ch_loaded(const struct tdma_mac *m, const struct tdma_chan_info *c, uint16_t min_ss)
{
	return c->w_ss >= min_ss &&
	       (uint32_t)c->w_busy * 100u >=
		       (uint32_t)CFGV(m, mon_busy_pct, TDMA_DEF_MON_BUSY_PCT) * c->w_ss;
}

/*
 * FT, hopping: drop hop-set carriers that were busy in this window (keeping
 * at least 2, the worst go first), take back dropped ones a background
 * measurement found quiet two windows after they were dropped. Announced
 * like a move. Returns true if a change was announced.
 */
static bool ft_hop_eval(struct tdma_mac *m, uint32_t frame)
{
	uint32_t mask = m->hop_mask, window = CFGV(m, mon_window, TDMA_DEF_MON_WINDOW_FRAMES);
	bool changed = false;

	for (;;) {
		int worst = -1;
		uint32_t worst_pm = 0;

		if (popcount32(mask) <= 2) {
			break;
		}
		for (uint8_t i = 0; i < 32; i++) {
			struct tdma_chan_info *c = ch_info(m, (uint16_t)(m->hop_base + i));
			uint32_t pm;

			if (!(mask & (1u << i)) || !c || !ch_loaded(m, c, meas_min_ss(m))) {
				continue;
			}
			pm = (uint32_t)c->w_busy * 1000u / c->w_ss;
			if (worst < 0 || pm > worst_pm) {
				worst = i;
				worst_pm = pm;
			}
		}
		if (worst < 0) {
			break;
		}
		mask &= ~(1u << worst);
		m->hop_dropped_frame[worst] = frame;
		m->chans[m->hop_base + worst - m->cfg.ch_min].quiet_win = 0;
		m->stats.hop_drops++;
		m->stats.move_busy_pct = (uint8_t)(worst_pm / 10u);
		changed = true;
	}
	for (uint8_t i = 0; i < 32 && i < ch_count(m); i++) {
		struct tdma_chan_info *c = &m->chans[i];
		uint16_t ch = (uint16_t)(m->cfg.ch_min + i);

		if ((mask & (1u << (ch - m->hop_base))) || !ch_usable(m, ch)) {
			continue;
		}
		/*
		 * Back in only after 3 windows in a row measured without a busy
		 * subslot (a duty-cycled interferer can look quiet in one 7-subslot
		 * sample), and not within 2 windows of being dropped.
		 */
		if (c->w_ss >= meas_min_ss(m)) {
			c->quiet_win =
				c->w_busy || c->clusters
					? 0
					: (uint8_t)(c->quiet_win < 255 ? c->quiet_win + 1 : 255);
		}
		if (c->quiet_win < 3 || (int32_t)(frame - m->hop_dropped_frame[ch - m->hop_base]) <
						(int32_t)(2u * window)) {
			continue;
		}
		mask |= 1u << (ch - m->hop_base);
		m->stats.hop_adds++;
		changed = true;
	}
	if (changed && mask != m->hop_mask) {
		return tdma_ft_set_hop(m, mask, TDMA_CAUSE_INTERFERENCE) == 0;
	}
	return false;
}

/*
 * FT: end of a monitor window. Single carrier: move when it was busy in at
 * least mon_busy_pct of the measured subslots, or when every PT reports an
 * SNR below mon_snr_bad_db while the channel is not quiet (above the "free"
 * level somewhere in the window): interference at the PTs, not distance.
 * Hopping: per carrier of the hop set (ft_hop_eval).
 */
static void ft_mon_eval(struct tdma_mac *m, uint32_t frame)
{
	const int8_t bad = m->cfg.mon_snr_bad_db ? m->cfg.mon_snr_bad_db : TDMA_DEF_MON_SNR_BAD_DB;
	const struct tdma_chan_info *c = ch_info(m, m->chan);
	uint32_t pct = 0;
	unsigned int n_act = 0, n_bad = 0;
	enum tdma_cause cause = TDMA_CAUSE_NONE;

	if ((int32_t)(frame - m->win_start) <
	    (int32_t)CFGV(m, mon_window, TDMA_DEF_MON_WINDOW_FRAMES)) {
		return;
	}
	if (m->hop_mask) {
		uint32_t ss = 0, busy = 0;
		int8_t mx = -128;

		for (uint8_t i = 0; i < 32; i++) {
			const struct tdma_chan_info *h = ch_info(m, (uint16_t)(m->hop_base + i));

			if ((m->hop_mask & (1u << i)) && h) {
				ss += h->w_ss;
				busy += h->w_busy;
				mx = h->w_ss && h->w_max > mx ? h->w_max : mx;
			}
		}
		m->stats.mon_busy_pct = (uint8_t)(ss ? busy * 100u / ss : 0);
		m->stats.mon_max_dbm = mx;
		if (!m->move_valid && (int32_t)(frame - m->move_hold) >= 0) {
			ft_hop_eval(m, frame);
		}
		ft_win_reset(m, frame);
		return;
	}
	if (c && c->w_ss) {
		pct = (uint32_t)c->w_busy * 100u / c->w_ss;
	}
	m->stats.mon_busy_pct = (uint8_t)pct;
	m->stats.mon_max_dbm = c && c->w_ss ? c->w_max : -128;
	for (uint8_t i = 0; i < m->plan->n_positions; i++) {
		const struct tdma_peer *p = &m->peers[i];
		int snr;

		if (!ft_active_peer(p, frame)) {
			continue;
		}
		if (p->n_dl_snr >= 4) {
			snr = p->dl_snr_q4 / 16;
		} else if (p->n_ul_snr >= 4) {
			snr = p->ul_snr_q4 / 16;
		} else {
			continue;
		}
		n_act++;
		n_bad += snr < bad;
	}
	if (c && ch_loaded(m, c, 20)) {
		cause = TDMA_CAUSE_INTERFERENCE;
	} else if (bad != TDMA_SNR_OFF && n_act && n_bad == n_act && c && c->w_ss &&
		   c->w_max > (int8_t)CFGV(m, rssi_free_dbm, TDMA_DEF_RSSI_FREE_DBM)) {
		cause = TDMA_CAUSE_POOR_SNR;
	}
	ft_win_reset(m, frame);
	if (cause != TDMA_CAUSE_NONE && ch_auto(m) && !m->move_valid &&
	    (int32_t)(frame - m->move_hold) >= 0) {
		/* the own entry reflects the window: the move goes elsewhere */
		if (tdma_ft_move(m, 0, cause) == 0) {
			m->stats.move_busy_pct = (uint8_t)pct;
		}
	}
}

/* FT / PT: the frame of a pending move has come: every op from here on is on the new carrier(s). */
static void apply_move(struct tdma_mac *m, uint32_t frame)
{
	m->chan = m->move_mask ? carrier_for(m, m->hop_base, m->move_mask, m->hop_seed, frame)
			       : m->move_ch;
	m->hop_mask = m->move_mask;
	m->move_valid = false;
	m->stats.moves++;
	if (!is_pt(m)) {
		/* LBT on the new carrier; a hop-set change keeps hopping without it */
		m->lbt_pending = lbt_ticks(m) != 0 && !m->hop_mask;
		m->lbt_fail = 0;
		m->lbt_retry_frame = frame;
		m->move_hold = frame + 2u * CFGV(m, mon_window, TDMA_DEF_MON_WINDOW_FRAMES);
		ft_win_reset(m, frame);
	}
	emit_full(m, TDMA_EVT_CHANNEL, m->cfg.rd_id, m->cfg.network_id, m->move_cause, 0, 0,
		  m->hop_mask ? 0 : m->chan);
}

/* PT: every carrier of a mask (relative to base) is one we may use. */
static bool pt_mask_ok(const struct tdma_mac *m, uint16_t base, uint32_t mask)
{
	for (uint8_t i = 0; i < 32; i++) {
		if ((mask & (1u << i)) && !ch_info((struct tdma_mac *)m, (uint16_t)(base + i))) {
			return false;
		}
	}
	return true;
}

/* PT: a beacon's hop set (or none) is what the cluster uses now. */
static void pt_hop_note(struct tdma_mac *m, const struct tdma_beacon *b, uint16_t rx_ch)
{
	if ((b->flags & TDMA_F_HOP) && pt_mask_ok(m, b->hop_base, b->hop_mask)) {
		if (m->hop_mask != b->hop_mask || m->hop_seed != b->hop_seed ||
		    m->hop_base != b->hop_base) {
			m->hop_cached = false;
		}
		m->hop_base = b->hop_base;
		m->hop_mask = b->hop_mask;
		m->hop_seed = b->hop_seed;
	} else {
		m->hop_mask = 0;
		m->chan = rx_ch;
	}
}

/* PT: a beacon announces a move. */
static void pt_move_note(struct tdma_mac *m, const struct tdma_beacon *b)
{
	if (!(b->flags & TDMA_F_MOVE) || !ch_info(m, b->move_ch) ||
	    (int32_t)(b->move_frame - b->frame) <= 0 ||
	    (b->move_mask && !pt_mask_ok(m, m->hop_base, b->move_mask)) ||
	    (!b->move_mask && !m->hop_mask && b->move_ch == m->chan)) {
		return;
	}
	if (m->move_valid && m->move_ch == b->move_ch && m->move_frame == b->move_frame &&
	    m->move_mask == b->move_mask) {
		return;
	}
	m->move_valid = true;
	m->move_ch = b->move_ch;
	m->move_mask = b->move_mask;
	m->move_frame = b->move_frame;
	m->move_cause = TDMA_CAUSE_NONE;
	emit_full(m, TDMA_EVT_MOVE, b->ft_rd_id, m->cfg.network_id, TDMA_CAUSE_NONE, 0, 0,
		  b->move_mask ? 0 : b->move_ch);
}

/* FT: a beacon sent with LBT completed. */
static void ft_lbt_done(struct tdma_mac *m, const struct tdma_op *op, int err)
{
	if (err == TDMA_ERR_LBT_BUSY) {
		m->stats.lbt_busy++;
		emit_full(m, TDMA_EVT_LBT_BUSY, m->cfg.rd_id, m->cfg.network_id, TDMA_CAUSE_NONE, 0,
			  0, op->ch);
		m->lbt_pending = true;
		if (++m->lbt_fail >= CFGV(m, lbt_max_fail, TDMA_DEF_LBT_MAX_FAIL) && ch_auto(m) &&
		    !m->hop_mask && op->ch == m->chan) {
			struct tdma_chan_info *c = ch_info(m, m->chan);
			uint16_t nc;

			if (c) { /* what LBT saw: busy */
				c->valid = true;
				c->n_ss = c->n_ss ? c->n_ss : 1;
				c->n_busy = c->n_ss;
				c->n_free = c->n_poss = 0;
			}
			nc = tdma_chan_best(m, m->chan);
			if (nc) {
				/* PTs that followed us lose sync and search every carrier */
				m->chan = nc;
				m->stats.moves += m->ft_started;
				emit(m, TDMA_EVT_CHANNEL, m->cfg.rd_id, TDMA_CAUSE_LBT, 0, 0);
			}
			m->lbt_fail = 0;
		}
		/* hopping: the retry is on another carrier anyway */
		m->lbt_retry_frame = op->frame + 1 + rng_next(m) % 3;
		return;
	}
	if (err == 0 && m->lbt_pending) {
		m->lbt_pending = false;
		m->lbt_fail = 0;
		m->stats.lbt_ok++;
		if (!m->ft_started) {
			m->ft_started = true;
			emit_full(m, TDMA_EVT_FT_STARTED, m->cfg.rd_id, m->cfg.network_id,
				  TDMA_CAUSE_NONE, 0, 0, op->ch);
		}
	}
}

/* ---- PT ----------------------------------------------------------------------- */

static void search_kick(struct tdma_mac *m, uint64_t now)
{
	struct tdma_op *op;
	uint16_t ch = ch_auto(m) ? m->search_ch : m->cfg.channel;
	uint32_t dur = ch_auto(m) ? CFGV(m, search_dwell_ticks, TDMA_DEF_SEARCH_DWELL_TICKS)
				  : TDMA_SEARCH_RX_TICKS;
	bool fast = m->fast_ch && now < m->fast_until && ch_info(m, m->fast_ch);

	/* hopping FTs visit every carrier once per (set size) frames */
	if (ch_auto(m) && m->cfg.hop && !m->cfg.search_dwell_ticks) {
		uint32_t d = (popcount32(ch_usable_mask(m)) + 1u) * TDMA_FRAME_TICKS +
			     3u * TDMA_SUBSLOT_TICKS;

		dur = d > dur ? d : dur;
	}
	if (!ch_usable(m, ch)) {
		ch = m->search_ch = m->cfg.ch_min;
		while (!ch_usable(m, ch) && ch < m->cfg.ch_max) {
			ch = ++m->search_ch;
		}
	}
	if (fast) {
		/* a known parent's carrier: one beacon period and a bit, again until found */
		ch = m->fast_ch;
		dur = TDMA_FRAME_TICKS + 4u * TDMA_SUBSLOT_TICKS;
	}

	if (m->state != TDMA_ST_SEARCH || m->search_handle || m->n_ops) {
		return; /* wait for the slot ops of the old sync to drain */
	}
	if (m->port.away && m->port.away(m->port.ctx, 0, dur)) {
		/* (the child cluster's ops drain first, or it has its frames between searches) */
		m->stats.relay_away++;
		m->retry_at = now + 2u * TDMA_SUBSLOT_TICKS;
		return;
	}
	op = op_new(m);
	if (op && m->port.rx(m->port.ctx, op->handle, 0, dur, ch) == 0) {
		op->use = USE_SEARCH;
		op->ch = ch;
		op_commit(m, op);
		m->search_handle = op->handle;
		m->retry_at = UINT64_MAX;
		m->stats.fast_searches += fast;
	} else {
		if (op) {
			m->stats.port_errors++;
		}
		m->retry_at = now + TDMA_FRAME_TICKS;
	}
}

static void pt_enter_search(struct tdma_mac *m)
{
	m->state = TDMA_ST_SEARCH;
	m->parent_rd = 0;
	m->my_pos = -1;
	m->assoc_waiting = false;
	m->peers[0].rd_id = 0;
	peer_link_reset(m, 0);
	flex_clear(m);
	memset(m->t2, 0, sizeof(m->t2));
	m->dl_snr_valid = false;
	m->move_valid = false;
	m->retime_valid = false;
	m->pm_valid = false;
	m->probe_valid = false;
	m->probe_handle = 0;
	m->q_valid = false;
	m->hop_mask = 0;
	m->search_ch = m->chan;
	if (m->sec.on) {
		sec_reset(m, true);
	}
	stop_rx_ops(m);
	search_kick(m, m->port.now(m->port.ctx));
}

/* Leave the FT we followed; tells the upper layer in its own terms. */
static void pt_lose(struct tdma_mac *m, enum tdma_cause cause)
{
	uint32_t parent = m->parent_rd;
	enum tdma_state was = m->state;

	pt_enter_search(m);
	if (was == TDMA_ST_ASSOCIATED) {
		emit(m, TDMA_EVT_LOST, parent, cause, 0, 0);
	} else if (was == TDMA_ST_ASSOCIATING) {
		emit(m, TDMA_EVT_ASSOC_FAILED, parent, cause, 0, 0);
	}
}

/* Contention opportunities per frame: contention slots + UL slots we may use. */
static uint32_t pt_opportunities(const struct tdma_mac *m)
{
	uint32_t n = 0;

	for (uint8_t i = 0; i < m->plan->n_slots; i++) {
		const struct tdma_slot *s = &m->plan->slots[i];

		if (s->use == TDMA_SLOT_CONTENTION ||
		    (s->use == TDMA_SLOT_UL && (m->free_mask & (1u << s->pos)))) {
			n++;
		}
	}
	return n ? n : 1;
}

static void pt_new_backoff(struct tdma_mac *m)
{
	bool fast = m->fast_ch && m->port.now(m->port.ctx) < m->fast_until;
	uint32_t window =
		(uint32_t)(fast ? TDMA_FAST_BACKOFF_FRAMES
				: CFGV(m, assoc_backoff_frames, TDMA_DEF_ASSOC_BACKOFF_FRAMES)) *
		pt_opportunities(m);

	m->backoff = (uint16_t)(rng_next(m) % window);
	if ((m->plan->flags & TDMA_PLAN_F_OPEN) && !m->free_mask) {
		m->backoff =
			(uint16_t)(rng_next(m) % 2u); /* HGX: one open frame in TDMA_OPEN_EVERY */
	}
}

/* Positions we may contend in: free ones, and our own stale entry after a reboot. */
static void pt_table(struct tdma_mac *m, const struct tdma_beacon *b)
{
	uint16_t me = tdma_short_rd(m->cfg.rd_id);

	m->free_mask = 0;
	for (uint8_t i = 0; i < b->n; i++) {
		if (b->e[i].short_id == 0 || b->e[i].short_id == me) {
			m->free_mask |= (uint16_t)(1u << i);
		}
	}
	m->parent_full = m->free_mask == 0;
	if (m->parent_full) {
		const struct tdma_plan *p = tdma_plan_get(b->plan_id);

		m->parent_full = !p || !(p->flags & TDMA_PLAN_F_OPEN); /* (asks in an open frame) */
	}
}

/* Skip slots of the current frame that are too close to commit now. */
static void skip_near_slots(struct tdma_mac *m)
{
	uint64_t now = m->port.now(m->port.ctx);

	/*
	 * A slot we may transmit in also needs its seal time (sec_lead), and the
	 * burst we synced on is still to be verified (rx_clear()'s window): right
	 * after the sync a PT's association request in the first free UL slot
	 * after that was sealed into the PHY's lead (sim: T4 with 3 PTs and the
	 * hardware cost model; the request is refused, the PT tries again later).
	 */
	uint64_t verify = sec_hints(m) ? TDMA_RX_PROC_TICKS + 2u * (uint64_t)sec_open_cost(m) : 0;

	while (slot_start(m, m->cur_frame, &m->plan->slots[m->cur_slot]) <
	       now + TDMA_PHY_LEAD_TX_TICKS + TDMA_RX_MARGIN_TICKS + verify +
		       sec_lead(m, &m->plan->slots[m->cur_slot])) {
		if (++m->cur_slot >= m->plan->n_slots) {
			m->cur_slot = 0;
			m->cur_frame++;
		}
	}
}

/* PT: a beacon announces a timing shift of the cluster (TDMA_F_RETIME,). */
static void pt_retime_note(struct tdma_mac *m, const struct tdma_beacon *b)
{
	if (!(b->flags & TDMA_F_RETIME) || (int32_t)(b->retime_frame - b->frame) <= 0) {
		return;
	}
	m->retime_valid = true;
	m->retime_frame = b->retime_frame;
	m->retime_delta = b->retime_delta;
}

static void pt_sync(struct tdma_mac *m, const struct tdma_beacon *b, const struct tdma_plan *plan,
		    uint64_t rx_start, uint16_t ch)
{
	m->chan = ch;
	m->move_valid = false;
	pt_hop_note(m, b, ch);
	pt_move_note(m, b);
	m->plan = plan;
	m->mcs = b->mcs;
	m->parent_rd = b->ft_rd_id;
	m->ref_start = rx_start; /* the beacon burst starts subslot 0 of its frame */
	m->ref_frame = b->frame;
	m->cur_frame = b->frame;
	m->cur_slot = 1;
	m->tree_depth = b->depth;
	m->tree_grid = b->grid_ss;
	m->parent_route_len = b->route_len;
	memcpy(m->parent_route, b->route, b->route_len);
	m->last_beacon_frame = b->frame;
	m->last_ft_frame = b->frame;
	pt_retime_note(m, b);
	m->state = TDMA_ST_ASSOCIATING;
	m->my_pos = -1;
	m->assoc_attempts = 0;
	m->assoc_waiting = false;
	m->flex_plan = tdma_plan_has_flex(plan);
	m->train_plan = tdma_plan_has_train(plan);
	m->psw_valid = false;
	flex_clear(m);
	memset(m->t2, 0, sizeof(m->t2));
	pt_table(m, b);
	do {
		m->nonce = (uint8_t)rng_next(m);
	} while (m->nonce == 0);
	pt_new_backoff(m);
	skip_near_slots(m);
	if (m->search_handle) {
		m->port.rx_stop(m->port.ctx, m->search_handle);
	}
}

/*
 * PT: the FT may switch to plan p: our position (if we have one) exists in
 * it. Plans of other sizes keep the positions' indices (plan_multi: H <-> H4).
 */
static bool pt_plan_ok(const struct tdma_mac *m, const struct tdma_plan *p)
{
	return m->state != TDMA_ST_ASSOCIATED || (m->my_pos >= 0 && m->my_pos < p->n_positions);
}

static void pt_beacon(struct tdma_mac *m, struct tdma_op *op, const struct tdma_beacon *b,
		      uint64_t rx_start, int16_t rssi)
{
	uint16_t me = tdma_short_rd(m->cfg.rd_id);

	if (b->ft_rd_id != m->parent_rd) {
		return; /* someone else's FT on our channel */
	}
	m->stats.beacons_rx++;
	/* Resync on every beacon. A changed frame counter (FT restarted
	 * without us noticing) just renumbers our frames.
	 */
	m->cur_frame += b->frame - op->frame;
	m->ref_start = rx_start;
	m->ref_frame = b->frame;
	m->last_beacon_frame = b->frame;
	m->last_ft_frame = b->frame;
	m->tree_depth = b->depth;
	m->tree_grid = b->grid_ss;
	m->parent_route_len = b->route_len;
	memcpy(m->parent_route, b->route, b->route_len);

	if (b->plan_id != m->plan->id && b->mcs == m->mcs && tdma_plan_get(b->plan_id) &&
	    pt_plan_ok(m, tdma_plan_get(b->plan_id))) {
		/*
		 * The FT switched plans (we missed or were late for the
		 * announcement). Ops of this frame committed under the old plan
		 * before this beacon was decoded match the new one only for a
		 * compatible plan; else the rest of the frame is skipped.
		 */
		bool compat = tdma_plan_compatible(m->plan, tdma_plan_get(b->plan_id));

		m->stats.plan_unannounced++;
		plan_apply(m, tdma_plan_get(b->plan_id));
		if (!compat && m->cur_frame == b->frame) {
			m->cur_slot = 0;
			m->cur_frame++;
		}
	}
	if (b->plan_id != m->plan->id || b->n != m->plan->n_positions || b->mcs != m->mcs) {
		pt_lose(m, TDMA_CAUSE_PLAN_CHANGED);
		return;
	}
	if (b->plan_next && tdma_plan_get((uint8_t)(b->plan_next - 1u)) &&
	    pt_plan_ok(m, tdma_plan_get((uint8_t)(b->plan_next - 1u)))) {
		m->psw_valid = true;
		m->psw_plan = (uint8_t)(b->plan_next - 1u);
		m->psw_frame = b->frame + b->plan_in;
	}
	if (b->flags & TDMA_F_CLOSING) {
		pt_lose(m, TDMA_CAUSE_FT_CLOSED);
		return;
	}
	pt_hop_note(m, b, op->ch);
	pt_move_note(m, b);
	pt_retime_note(m, b);
	if (b->q_valid && (int32_t)(b->q_frame - b->frame) >= 0 &&
	    (int32_t)(b->q_frame - b->frame) <= 2) {
		/* the FT listens elsewhere then */
		m->q_valid = true;
		m->q_frame = b->q_frame;
		m->q_ss = b->q_ss;
		m->q_len = b->q_len;
	}
	if (m->state == TDMA_ST_ASSOCIATED) {
		const struct tdma_beacon_entry *e = &b->e[m->my_pos];

		if (b->pm_valid && b->pm_from == (uint8_t)m->my_pos && b->pm_to < b->n &&
		    (int32_t)(b->pm_frame - b->frame) > 0) {
			/* position compaction: ours from pm_frame on */
			m->pm_valid = true;
			m->pm_from = b->pm_from;
			m->pm_to = b->pm_to;
			m->pm_frame = b->pm_frame;
		} else if (b->pm_valid && b->pm_swap && b->pm_to == (uint8_t)m->my_pos &&
			   b->pm_from < b->n && (int32_t)(b->pm_frame - b->frame) > 0) {
			/* the other PT of a swap */
			m->pm_valid = true;
			m->pm_from = b->pm_to;
			m->pm_to = b->pm_from;
			m->pm_frame = b->pm_frame;
		}
		if (e->short_id != me || e->nonce != m->nonce) {
			/* moved without us hearing the announcement: follow, else we were released
			 */
			for (uint8_t i = 0; i < b->n; i++) {
				if (b->e[i].short_id == me && b->e[i].nonce == m->nonce) {
					uint8_t from = (uint8_t)m->my_pos;

					m->my_pos = (int8_t)i;
					m->pm_valid = false;
					emit_pos_move(m, m->cfg.rd_id, from, i);
					return;
				}
			}
			pt_lose(m, TDMA_CAUSE_RELEASED);
		}
		return;
	}
	/* Associating: our entry with our nonce means the FT took our request. */
	for (uint8_t i = 0; i < b->n; i++) {
		if (b->e[i].short_id == me && b->e[i].nonce == m->nonce) {
			m->state = TDMA_ST_ASSOCIATED;
			m->my_pos = (int8_t)i;
			m->assoc_waiting = false;
			m->peers[0].rd_id = m->parent_rd;
			peer_link_reset(m, 0);
			link_set_cap(&m->peers[0].link, ul_pdu_cap(m->plan, m->mcs, m->sec.on),
				     m->flex_plan, q_depth(m));
			emit(m, TDMA_EVT_ASSOCIATED, m->parent_rd, TDMA_CAUSE_NONE, i, rssi);
			return;
		}
	}
	pt_table(m, b);
	if (m->parent_full && !m->assoc_waiting) {
		pt_lose(m, TDMA_CAUSE_FULL);
	}
}

/* First record of a beacon burst. */
static int beacon_of_pkt(const uint8_t *pkt, size_t len, struct tdma_beacon *b)
{
	size_t off = 0, plen;
	const uint8_t *pdu;
	uint8_t addr;

	if (tdma_rec_next(pkt, len, &off, &addr, &pdu, &plen) != 1 || addr != TDMA_ADDR_ALL) {
		return -EINVAL;
	}
	return tdma_beacon_decode(pdu, plen, b);
}

static void pt_rx_search(struct tdma_mac *m, const struct tdma_op *op, const struct tdma_phy_hdr *h,
			 const uint8_t *pkt, size_t len, uint64_t rx_start, int16_t rssi,
			 int16_t snr_q2)
{
	struct tdma_beacon b;
	const struct tdma_plan *plan;

	if (m->state != TDMA_ST_SEARCH || h->rx_short != TDMA_SHORT_BROADCAST ||
	    beacon_of_pkt(pkt, len, &b) || b.network_id != m->cfg.network_id ||
	    tdma_short_rd(b.ft_rd_id) != h->tx_short) {
		return; /* DL bursts without a beacon are not a sync point */
	}
	if (m->cfg.evt_cb) {
		/*
		 * .value: the cluster's tree depth (0 = a root) | grid offset << 8 |
		 * FULL << 16 | positions in use << 20; the route record, SNR and the
		 * FT's transmit power for the mesh layer's link cost.
		 */
		uint32_t used = 0;

		for (uint8_t i = 0; i < b.n; i++) {
			used += b.e[i].short_id != 0;
		}
		struct tdma_evt e = {.type = TDMA_EVT_BEACON,
				     .rd_id = b.ft_rd_id,
				     .network_id = m->cfg.network_id,
				     .rssi = rssi,
				     .channel = op->ch,
				     .value = b.depth | (uint32_t)b.grid_ss << 8 |
					      ((b.flags & TDMA_F_FULL) ? 1u << 16 : 0) | used << 20,
				     .snr_q2 = snr_q2,
				     .tx_power = h->tx_power,
				     .route_len = b.route_len,
				     .route = b.route};

		m->cfg.evt_cb(&e, m->cfg.evt_user);
	}
	if (m->cfg.ft_rd_filter && b.ft_rd_id != m->cfg.ft_rd_filter) {
		return;
	}
	plan = tdma_plan_get(b.plan_id);
	if (!plan || plan->n_positions != b.n || !plan_mcs_ok(plan, b.mcs, m->sec.on)) {
		return;
	}
	m->stats.beacons_rx++;
	pt_sync(m, &b, plan, rx_start, op->ch);
	emit(m, TDMA_EVT_SYNCED, b.ft_rd_id, TDMA_CAUSE_NONE, 0, rssi);
	if (m->parent_full) {
		pt_lose(m, TDMA_CAUSE_FULL);
	}
}

static void pt_contend(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start)
{
	struct tdma_assoc_req r = {
		.flags = m->cfg.relay ? TDMA_AF_RELAY : 0,
		.pt_rd_id = m->cfg.rd_id,
		.ft_rd_id = m->parent_rd,
		.box_id = m->cfg.box_id,
		.nonce = m->nonce,
	};
	size_t off = 0;
	int n;

	if (m->assoc_waiting || m->parent_full) {
		return;
	}
	if (m->backoff) {
		m->backoff--;
		return;
	}
	n = tdma_assoc_encode(&r, m->pkt_buf + TDMA_REC_HDR_LEN,
			      tdma_rec_room(burst_cap(m, m->mcs, &m->plan->slots[si]), 0));
	if (n <= 0) {
		return;
	}
	tdma_rec_close(m->pkt_buf, &off, TDMA_ADDR_ALL, (size_t)n);
	/* random access: listen before talk (TS 103 636-4 5.3.1) */
	if (tx_burst_lbt(m, si, frame, start, m->parent_rd, off, m->plan->slots[si].len, m->mcs,
			 rach_lbt_ticks(m)) == 0) {
		m->assoc_waiting = true;
		m->assoc_sent_frame = frame;
		m->stats.assoc_tx++;
	}
}

/* PT: our grant for FLEX slot si of this frame, if any: send or receive the long burst. */
static void pt_flex(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start)
{
	struct tdma_flex *f = &m->flex[flex_i(m, si)];
	size_t off = 0, cap;
	struct tdma_flex g = *f;

	if (!f->valid || f->frame != frame || f->slot != si) {
		return;
	}
	f->valid = false;
	if (!g.ul) {
		rx_flex(m, si, frame, start, &g);
		return;
	}
	if ((g.spec || g.ahead) && !link_has_pending(&m->peers[0].link)) {
		return; /* offered, but nothing to send */
	}
	cap = len_cap(m, g.mcs, g.len);
	start -= (uint64_t)g.early * TDMA_SUBSLOT_TICKS; /* UL bursts may start before the region */
	build_records(m, &m->peers[0].link, start, start + (uint64_t)g.len * TDMA_SUBSLOT_TICKS,
		      LB_AUTO, (uint8_t)m->my_pos, &off, cap - TDMA_STATUS_REC_LEN);
	pt_status_rec(m, &off, cap);
	if (tx_burst(m, si, frame, start, m->parent_rd, off, g.len, g.mcs) == 0) {
		m->stats.flex_tx++;
		m->stats.flex_tx_early += g.early_commit;
	}
}

/*
 * PT, plan T2: what the frame's pattern gives us in FLEX slot si. DL: listen.
 * UL: the first UL burst of the frame always goes out (acks and the queue
 * report), sized to what is queued; later ones only with data, and full
 * length after a long one (2 ss after a received long burst the FT takes only
 * another long one).
 */
static void pt_t2(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start)
{
	struct tdma_t2 *t = &m->t2[frame & 1u];
	struct tdma_link *l = &m->peers[0].link;
	uint8_t fi = flex_i(m, si), full, len;
	bool first = true;
	size_t off = 0, cap;
	int8_t b;

	if (!t2_of(m, frame) || t->pos != (uint8_t)m->my_pos) {
		return;
	}
	b = tdma_pat_burst(m->plan, t->pat, fi);
	if (b > 0) {
		struct tdma_flex g = {.valid = true,
				      .slot = si,
				      .pos = t->pos,
				      .len = tdma_max_burst(t->mcs_dl, (uint8_t)b),
				      .mcs = t->mcs_dl,
				      .frame = frame};

		rx_flex(m, si, frame, start, &g);
		return;
	}
	if (b == 0) {
		return;
	}
	for (uint8_t k = 0; k < fi; k++) {
		first &= tdma_pat_burst(m->plan, t->pat, k) >= 0;
	}
	if (!first && !link_has_pending(l)) {
		return;
	}
	full = tdma_max_burst(t->mcs_ul, (uint8_t)-b);
	if (full < 2) {
		return;
	}
	if (t->ul_long || link_bulk_ready(l) + TDMA_STATUS_REC_LEN >= len_cap(m, t->mcs_ul, full)) {
		len = full;
	} else {
		len = flex_len_for(m, t->mcs_ul, full, link_pending_bytes(l) + TDMA_STATUS_REC_LEN);
	}
	cap = len_cap(m, t->mcs_ul, len);
	build_records(m, l, start, start + (uint64_t)len * TDMA_SUBSLOT_TICKS, LB_AUTO,
		      (uint8_t)m->my_pos, &off, cap - TDMA_STATUS_REC_LEN);
	pt_status_rec(m, &off, cap);
	if (tx_burst(m, si, frame, start, m->parent_rd, off, len, t->mcs_ul) == 0) {
		m->stats.flex_tx++;
		t->ul_long |= len >= TDMA_LRX_MIN_SS;
	}
}

/*
 * PT, at a beacon slot of frame: sync lost? After beacon_miss_max frames
 * without a beacon, unless (link security on) verified bursts from the FT
 * still come, up to TDMA_BEACON_MISS_DL_FACTOR x beacon_miss_max frames.
 */
static bool pt_sync_gone(struct tdma_mac *m, uint32_t frame)
{
	int32_t max = (int32_t)CFGV(m, beacon_miss_max, TDMA_DEF_BEACON_MISS_MAX);
	int32_t nb = (int32_t)(frame - m->last_beacon_frame);

	if (nb <= max) {
		return false;
	}
	if (!m->sec.on || m->state != TDMA_ST_ASSOCIATED || nb > TDMA_BEACON_MISS_DL_FACTOR * max ||
	    (int32_t)(frame - m->last_ft_frame) > max) {
		return true;
	}
	m->stats.beacon_bridged++;
	return false;
}

/* ---- PT: backup probes  ------------------------------------------------ */

#define PROBE_SS     3 /* a DL burst of plan H / HG */
#define PROBE_FRAMES 4 /* frames to place it in */

static void probe_end(struct tdma_mac *m, bool heard, int16_t rssi, int16_t snr_q2)
{
	struct tdma_evt e = {.type = TDMA_EVT_PROBE,
			     .rd_id = m->probe_rd,
			     .network_id = m->cfg.network_id,
			     .value = heard,
			     .rssi = rssi,
			     .snr_q2 = snr_q2,
			     .channel = m->probe_ch};

	m->probe_valid = false;
	m->probe_handle = 0;
	m->stats.probes++;
	m->stats.probes_heard += heard;
	if (m->cfg.evt_cb) {
		m->cfg.evt_cb(&e, m->cfg.evt_user);
	}
}

/* Is subslot s of our frame within [a - gap, b + gap) of an own op? (mod the frame) */
static bool ss_near(unsigned int s, unsigned int len, unsigned int a, unsigned int b)
{
	for (int w = -1; w <= 1; w++) {
		int x = (int)s + w * (int)TDMA_SUBSLOTS_PER_FRAME;

		if (x < (int)b + TDMA_MIN_OP_GAP_SS && x + (int)len + TDMA_MIN_OP_GAP_SS > (int)a) {
			return true;
		}
	}
	return false;
}

/*
 * Where a probe at subslot ss fits: 1 in place of our own DL burst there (a
 * sibling cluster on the same grid: its beacon burst, the one always sent,
 * comes with ours), 2 where we have nothing within the PHY's gap, 0 nowhere.
 */
static int probe_fit(const struct tdma_mac *m, uint8_t ss)
{
	bool replace = false;

	for (uint8_t i = 0; i < m->plan->n_slots; i++) {
		const struct tdma_slot *s = &m->plan->slots[i];
		bool ours = is_dl(s) || (s->use == TDMA_SLOT_UL && s->pos == m->my_pos) ||
			    (is_flex(s) && m->flex_plan);

		if (is_dl(s) && s->subslot == ss) {
			replace = true;
			continue;
		}
		if (ours && ss_near(ss, PROBE_SS, s->subslot, (unsigned int)s->subslot + s->len)) {
			return replace ? 1 : 0;
		}
	}
	return replace ? 1 : 2;
}

int tdma_pt_probe(struct tdma_mac *m, uint32_t rd_id, uint16_t ch, uint8_t at_ss)
{
	if (m->state != TDMA_ST_ASSOCIATED || m->probe_valid || !rd_id || !ch ||
	    at_ss >= TDMA_SUBSLOTS_PER_FRAME || !probe_fit(m, at_ss)) {
		return -EBUSY;
	}
	m->probe_valid = true;
	m->probe_heard = false;
	m->probe_rd = rd_id;
	m->probe_ch = ch;
	m->probe_ss = at_ss;
	m->probe_handle = 0;
	m->probe_until = m->cur_frame + PROBE_FRAMES;
	return 0;
}

static void probe_rx(struct tdma_mac *m, uint64_t start, uint32_t frame)
{
	struct tdma_op *op = op_new(m);
	uint32_t dur = PROBE_SS * TDMA_SUBSLOT_TICKS + 2 * TDMA_RX_MARGIN_TICKS;

	if (!op) {
		return;
	}
	if (m->port.away && m->port.away(m->port.ctx, start - TDMA_RX_MARGIN_TICKS, dur)) {
		probe_end(m, false, 0, 0); /* a relay: its cluster has the radio then */
		return;
	}
	if (m->port.rx(m->port.ctx, op->handle, start - TDMA_RX_MARGIN_TICKS, dur, m->probe_ch)) {
		m->stats.port_errors++;
		probe_end(m, false, 0, 0);
		return;
	}
	op->use = USE_PROBE;
	op->ch = m->probe_ch;
	op->start = start;
	op->frame = frame;
	op_commit(m, op);
	m->probe_handle = op->handle;
}

/* tdma_tick(), PT: a probe where we have nothing, once it is up to 2 ms ahead. */
static void probe_tick(struct tdma_mac *m, uint64_t now)
{
	uint64_t t;

	if (!m->probe_valid || m->probe_handle) {
		return;
	}
	if (m->state != TDMA_ST_ASSOCIATED || (int32_t)(m->cur_frame - m->probe_until) > 0) {
		probe_end(m, false, 0, 0);
		return;
	}
	if (probe_fit(m, m->probe_ss) != 2) {
		return; /* (in place of our DL burst: pt_commit()) */
	}
	t = slot_start(m, m->cur_frame, &m->plan->slots[0]) -
	    (uint64_t)m->plan->slots[0].subslot * TDMA_SUBSLOT_TICKS +
	    (uint64_t)m->probe_ss * TDMA_SUBSLOT_TICKS;
	while (t < now + TDMA_PHY_LEAD_RX_TICKS + TDMA_RX_MARGIN_TICKS + TDMA_US_TO_TICKS(100)) {
		t += TDMA_FRAME_TICKS;
	}
	if (t - now <= TDMA_US_TO_TICKS(4000)) {
		probe_rx(m, t, m->cur_frame); /* (out of order with the slots before it: the PHY
						 takes that) */
	}
}

static void pt_commit(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start)
{
	const struct tdma_slot *s = &m->plan->slots[si];
	size_t off = 0, cap;

	switch (s->use) {
	case TDMA_SLOT_BEACON:
		if (pt_sync_gone(m, frame)) {
			pt_lose(m, TDMA_CAUSE_SYNC_LOST);
			return;
		}
		if (m->state == TDMA_ST_ASSOCIATING && m->assoc_waiting &&
		    (int32_t)(frame - m->assoc_sent_frame) >
			    (int32_t)CFGV(m, assoc_wait_frames, TDMA_DEF_ASSOC_WAIT_FRAMES)) {
			m->assoc_waiting = false;
			if (++m->assoc_attempts >=
			    CFGV(m, assoc_max_attempts, TDMA_DEF_ASSOC_MAX_ATTEMPTS)) {
				pt_lose(m, TDMA_CAUSE_NO_RESPONSE);
				return;
			}
			pt_new_backoff(m);
		}
		if (m->state == TDMA_ST_ASSOCIATED && m->probe_valid && !m->probe_handle &&
		    s->subslot == m->probe_ss && probe_fit(m, m->probe_ss) == 1) {
			probe_rx(m, start, frame); /* one beacon of ours missed now and then */
			break;
		}
		rx_slots(m, si, si, frame, start);
		break;
	case TDMA_SLOT_DL:
		if (m->state == TDMA_ST_ASSOCIATED && m->probe_valid && !m->probe_handle &&
		    s->subslot == m->probe_ss && probe_fit(m, m->probe_ss) == 1) {
			probe_rx(m, start, frame); /* a sibling cluster's DL burst instead of ours
						      (ARQ resends) */
			break;
		}
		if (m->state == TDMA_ST_ASSOCIATED) {
			rx_slots(m, si, si, frame, start);
		}
		break;
	case TDMA_SLOT_UL:
		if (m->state == TDMA_ST_ASSOCIATING &&
		    ((m->free_mask & (1u << s->pos)) || open_slot(m->plan, s, frame))) {
			pt_contend(m, si, frame, start);
			break;
		}
		if (m->state != TDMA_ST_ASSOCIATED || s->pos != m->my_pos ||
		    open_slot(m->plan, s, frame)) {
			break;
		}
		/* Always send: the FT counts our bursts for liveness and
		 * every burst carries our acks (and, in hybrid plans, our queue).
		 */
		cap = burst_cap(m, m->mcs, s);
		build_records(m, &m->peers[0].link, start, start + burst_air(s), LB_ACK,
			      (uint8_t)m->my_pos, &off,
			      cap - (m->flex_plan ? TDMA_STATUS_REC_LEN : 0));
		if (m->flex_plan) {
			pt_status_rec(m, &off, cap);
		}
		if (off > 0) {
			tx_slot(m, si, frame, start, m->parent_rd, off);
		}
		break;
	case TDMA_SLOT_CONTENTION:
		if (m->state == TDMA_ST_ASSOCIATING) {
			pt_contend(m, si, frame, start);
		}
		break;
	case TDMA_SLOT_FLEX:
		if (m->state == TDMA_ST_ASSOCIATED) {
			(pat_plan(m->plan) ? pt_t2 : pt_flex)(m, si, frame, start);
		}
		break;
	}
}

/* ---- FT ----------------------------------------------------------------------- */

static void ft_release(struct tdma_mac *m, uint8_t pos, enum tdma_cause cause)
{
	struct tdma_peer *p = &m->peers[pos];
	uint32_t rd = p->rd_id;

	p->rd_id = 0;
	p->nonce = 0;
	p->relay = false;
	p->hgx_ok = false;
	if (m->pm_valid && m->pm_from == pos) {
		m->pm_valid = false; /* (its move) */
	}
	peer_link_reset(m, (uint8_t)(p - m->peers));
	m->roster_ver++;
	emit(m, TDMA_EVT_CHILD_REMOVED, rd, cause, pos, 0);
}

/* TDMA_EVT_POS_MOVE: rd moved from position `from` to `to`. */
static void emit_pos_move(struct tdma_mac *m, uint32_t rd, uint8_t from, uint8_t to)
{
	struct tdma_evt e = {.type = TDMA_EVT_POS_MOVE,
			     .rd_id = rd,
			     .network_id = m->cfg.network_id,
			     .pos = to,
			     .value = from,
			     .channel = m->chan};

	m->stats.pos_moves++;
	if (m->cfg.evt_cb) {
		m->cfg.evt_cb(&e, m->cfg.evt_user);
	}
}

static void mem_swap(void *x, void *y, size_t n)
{
	uint8_t *a = x, *b = y;

	while (n--) {
		uint8_t t = *a;

		*a++ = *b;
		*b++ = t;
	}
}

static uint8_t pos_swapped(uint8_t p, uint8_t a, uint8_t b)
{
	return p == a ? b : p == b ? a : p;
}

/*
 * FT, position compaction : positions a and b trade what they hold
 * (the peers with their queues and queue memory, reassembly buffers, FLEX
 * decisions, the UL runs in flight). A PT keeps its association, ARQ state
 * and queued SDUs; at the same frame it uses its new position (announced:
 * TDMA_BEXT_PMOVE).
 */
static void ft_pos_swap(struct tdma_mac *m, uint8_t a, uint8_t b)
{
	struct tdma_link *lt, *lf;

	mem_swap(&m->peers[a], &m->peers[b], sizeof(m->peers[0]));
	/*
	 * The queue memory went along with the peers; the lower positions have the
	 * deep queues (TDMA_TXQ_N_BIG): a PT that moved down from a small one gets
	 * the deep memory of its new position (its queue copied over), the free
	 * position the small one. Without it a compacted PT kept the shallow
	 * queue: DL bulk 246 -> 120 kB/s on the DKs.
	 */
	lt = &m->peers[b].link;
	lf = &m->peers[a].link;
	if (!m->peers[a].rd_id && lf->n_chunks > lt->n_chunks) {
		uint8_t (*small)[TDMA_TXQ_CHUNK] = lt->chunk;
		uint8_t ns = lt->n_chunks;

		link_regrow(lt, lf->chunk, lf->n_chunks);
		link_attach(lf, small, ns);
		link_reset(lf);
	}
	for (uint8_t i = 0; i < m->n_ras; i++) {
		if (m->ras[i].owner == a + 1u || m->ras[i].owner == b + 1u) {
			m->ras[i].owner =
				(uint8_t)(pos_swapped((uint8_t)(m->ras[i].owner - 1u), a, b) + 1u);
		}
	}
	for (uint8_t i = 0; i < TDMA_FLEX_SLOTS; i++) {
		m->flex[i].pos = pos_swapped(m->flex[i].pos, a, b);
	}
	for (uint8_t i = 0; i < 2; i++) {
		m->t2[i].pos = pos_swapped(m->t2[i].pos, a, b);
	}
	mem_swap(&m->flow_frame[2u * a], &m->flow_frame[2u * b], 2u * sizeof(m->flow_frame[0]));
	for (int i = 0; i < TDMA_MAX_OPS; i++) {
		struct tdma_op *op = &m->ops[i];
		uint32_t ga = (op->got >> a) & 1u, gb = (op->got >> b) & 1u;

		if (!op->used) {
			continue;
		}
		mem_swap(&op->owners[a], &op->owners[b], sizeof(op->owners[0]));
		op->got = (op->got & ~((1u << a) | (1u << b))) | (ga << b) | (gb << a);
		op->flex.pos = pos_swapped(op->flex.pos, a, b);
	}
}

/*
 * FT, plan auto: a relay child (or a lone PT) sits above the base plan's
 * positions while one of them is free (it joined when they were taken):
 * plan H (the relay's R1 layout) cannot be used. It moves down, announced
 * TDMA_PLAN_ANNOUNCE_FRAMES ahead.
 */
static bool ft_pos_compact(struct tdma_mac *m, uint32_t frame, uint8_t npos)
{
	int from = -1, to = -1;

	for (uint8_t i = 0; i < m->plan->n_positions; i++) {
		if (m->peers[i].rd_id && i >= npos) {
			from = i; /* the highest */
		} else if (!m->peers[i].rd_id && i < npos && to < 0) {
			to = i; /* the lowest free */
		}
	}
	if (from < 0 || to < 0) {
		return false;
	}
	m->pm_valid = true;
	m->pm_swap = false;
	m->pm_from = (uint8_t)from;
	m->pm_to = (uint8_t)to;
	m->pm_frame = frame + TDMA_PLAN_ANNOUNCE_FRAMES;
	return true;
}

static void pos_move_announce(struct tdma_mac *m, uint32_t frame, uint8_t from, uint8_t to,
			      bool swap)
{
	m->pm_valid = true;
	m->pm_swap = swap;
	m->pm_from = from;
	m->pm_to = to;
	m->pm_frame = frame + TDMA_PLAN_ANNOUNCE_FRAMES;
}

/*
 * FT of a relay's child cluster (plan HG), one child: under a root (depth 1)
 * it takes position 1, whether it relays too or not: its UL slot (20 / 44)
 * is 3 ss later than position 0's, 14 ss before ours (17 from position 0: 2
 * hops up p99 10.9 -> 9.4 ms on the DKs). A child that relays needs it
 * anyway (TDMA_RELAY_OFFSET_SS: its own cluster's blocks would cut into
 * position 0's UL slot; tdma_relay_plan_check()). Deeper, a lone child takes
 * position 0: 13 ss before our UL slot (position 1: 10, which a forwarded SDU
 * misses on the DKs). position 0 too while the relay heads for
 * plan HGX (one position).
 *
 * A root on plan H / T : a relay child whose cluster could run HGX
 * (TDMA_STF_HGX) takes position 1 (UL 8 / 32: HGX gives it 12 ss up, 15 down);
 * one that cannot, position 0 (HG: 17 / 14 ss up there, 20 / 17 in 1). The
 * other PT swaps with it (TDMA_BEXT_PMOVE with the swap bit).
 */
static void ft_pos_prefer(struct tdma_mac *m, uint32_t frame)
{
	if (m->pm_valid || m->psw_valid || m->retime_valid || m->move_valid) {
		return;
	}
	if (!m->cfg.relay) {
		const struct tdma_peer *p0 = &m->peers[0], *p1 = &m->peers[1];
		bool w0 = p0->rd_id && p0->relay && p0->hgx_ok,
		     w1 = p1->rd_id && p1->relay && p1->hgx_ok;

		if ((m->plan->id != TDMA_PLAN_H && m->plan->id != TDMA_PLAN_T) ||
		    (p0->rd_id && !p0->announced) || (p1->rd_id && !p1->announced)) {
			return;
		}
		if (w0 && !w1) {
			pos_move_announce(m, frame, 0, 1, p1->rd_id != 0);
		} else if (p1->rd_id && p1->relay && !p1->hgx_ok && !(p0->rd_id && p0->relay)) {
			pos_move_announce(m, frame, 1, 0, p0->rd_id != 0);
		}
		return;
	}
	if (m->plan->id != TDMA_PLAN_HG) {
		return;
	}
	uint8_t want = m->cfg.depth <= 1u && !m->hgx_want ? 1u : 0u, from = (uint8_t)(1u - want);

	if (!m->peers[from].rd_id || m->peers[want].rd_id) {
		return;
	}
	pos_move_announce(m, frame, from, want, false);
}

/* Both roles, at the commit of slot 0 of pm_frame: the announced move takes effect. */
static void pos_move_apply(struct tdma_mac *m)
{
	uint8_t a = m->pm_from, b = m->pm_to;

	m->pm_valid = false;
	if (m->state == TDMA_ST_FT) {
		bool swap = m->pm_swap && m->peers[b].rd_id;

		if (a >= m->plan->n_positions || b >= m->plan->n_positions || !m->peers[a].rd_id ||
		    (m->peers[b].rd_id && !m->pm_swap)) {
			return;
		}
		ft_pos_swap(m, a, b);
		m->roster_ver++;
		emit_pos_move(m, m->peers[b].rd_id, a, b);
		if (swap) {
			emit_pos_move(m, m->peers[a].rd_id, b, a);
		}
	} else if (m->state == TDMA_ST_ASSOCIATED && m->my_pos == (int8_t)a &&
		   b < m->plan->n_positions) {
		m->my_pos = (int8_t)b;
		emit_pos_move(m, m->cfg.rd_id, a, b);
	}
}

static void ft_assign(struct tdma_mac *m, uint8_t pos, const struct tdma_assoc_req *r)
{
	struct tdma_peer *p = &m->peers[pos];

	p->rd_id = r->pt_rd_id;
	p->nonce = r->nonce;
	p->announced = false;
	p->ul_miss = 0;
	p->ul_missed_last = false;
	p->bsr = 0;
	p->reply_hint = false;
	p->bsr_t = 0;
	memset(p->glog, 0, sizeof(p->glog));
	p->n_ul_snr = p->n_dl_snr = 0;
	p->mcs_ul = p->mcs_dl = m->mcs;
	p->flex_fail = 0;
	p->assoc_frame = m->cur_frame;
	p->reassoc_fast = 0;
	p->sec_fail = 0;
	p->relay = (r->flags & TDMA_AF_RELAY) != 0;
	peer_link_reset(m, (uint8_t)(p - m->peers));
	link_set_cap(&p->link, dl_pdu_cap(m->plan, m->mcs, m->sec.on), m->flex_plan, q_depth(m));
	m->roster_ver++;
}

/* FT: the PT's queue, less what we granted after the burst that reported it. */
static size_t ft_ul_need(const struct tdma_peer *p)
{
	size_t b = p->bsr;

	for (int i = 0; i < TDMA_GRANT_LOG; i++) {
		if (p->glog[i].cap && p->glog[i].start > p->bsr_t) {
			b -= b < p->glog[i].cap ? b : p->glog[i].cap;
		}
	}
	return b;
}

static bool ft_active_peer(const struct tdma_peer *p, uint32_t frame)
{
	return p->rd_id && p->announced && (int32_t)(frame - p->dl_from_frame) >= 0;
}

static bool ft_active(const struct tdma_mac *m, const struct tdma_peer *p, uint32_t frame)
{
	(void)m;
	return ft_active_peer(p, frame);
}

/* FT: may p get a FLEX region (long burst) of this frame? Not a relay: it is in its own cluster
 * then. */
static bool ft_flex_ok(const struct tdma_mac *m, const struct tdma_peer *p, uint32_t frame)
{
	return ft_active(m, p, frame) && !p->relay;
}

static bool ft_any_active(struct tdma_mac *m, uint32_t frame)
{
	for (uint8_t i = 0; i < m->plan->n_positions; i++) {
		if (ft_active(m, &m->peers[i], frame)) {
			return true;
		}
	}
	return false;
}

/* FT: does any flow have data for a FLEX region (else it would go out speculatively)? */
static bool ft_flex_demand(struct tdma_mac *m, uint32_t frame)
{
	for (uint8_t i = 0; i < m->plan->n_positions; i++) {
		struct tdma_peer *p = &m->peers[i];

		if (ft_active(m, p, frame) && (ft_ul_need(p) || link_pending_bytes(&p->link))) {
			return true;
		}
	}
	return false;
}

/* Shortest burst (>= 2 ss, <= maxn) whose payload holds need bytes; maxn if none does. */
static uint8_t flex_len_for(const struct tdma_mac *m, uint8_t mcs, uint8_t maxn, size_t need)
{
	for (uint8_t n = 2; n < maxn; n++) {
		if (len_cap(m, mcs, n) >= need) {
			return n;
		}
	}
	return maxn;
}

/*
 * FT: who gets FLEX slot fj of this frame. Round robin over the flows (DL to
 * PT k, UL from PT k) that have data waiting, so every busy flow gets the
 * same share of long bursts; with nobody waiting, a speculative UL grant to
 * the next PT (it sends only if something arrived meanwhile). Fills e.
 */
static bool ft_flex_decide(struct tdma_mac *m, uint32_t frame, uint8_t fj, bool ahead,
			   struct tdma_grant_entry *e)
{
	const struct tdma_slot *fs = &m->plan->slots[fj];
	const uint8_t npos = m->plan->n_positions;
	const uint8_t nflow = (uint8_t)(2 * npos);
	struct tdma_flex *f = &m->flex[flex_i(m, fj)];
	int pick = -1;
	bool spec = false;
	size_t need = 0;

	if (fs_covers(m, fj, frame, slot_start(m, frame, fs))) {
		return false; /* our listen for other trees has the radio then */
	}

	/*
	 * A train plan gives a frame's train to one flow: by demand, the flow
	 * with the most waiting times the frames since it had one (strict
	 * alternation gave a flow that needed a third of the frames every
	 * other one, and the saturated one the rest: UL 107 + DL 60 kB/s on
	 * the DKs). Saturated flows still alternate (same queue, the one served
	 * last waited least).
	 */
	uint64_t best = 0;

	for (uint8_t k = 0; k < nflow && (pick < 0 || m->train_plan); k++) {
		uint8_t fl = (uint8_t)((m->flex_rr + k) % nflow);
		struct tdma_peer *p = &m->peers[fl / 2];
		size_t nd;

		if (!ft_flex_ok(m, p, frame)) {
			continue;
		}
		nd = (fl & 1) ? ft_ul_need(p) : link_pending_bytes(&p->link);
		if (nd && m->train_plan) {
			uint32_t w = frame - m->flow_frame[fl];
			uint64_t sc = (uint64_t)nd * (w > 64u ? 64u : w ? w : 1u);

			if (sc > best) {
				best = sc;
				pick = fl;
				need = nd;
			}
		} else if (nd) {
			pick = fl;
			need = nd;
		}
	}
	if (pick >= 0) {
		m->flex_rr = (uint8_t)((pick + 1) % nflow);
		m->flow_frame[pick] = frame;
	}
	/*
	 * Nobody waiting. A PT whose SDU was just delivered probably gets an
	 * answer (ping, TCP ack, CoAP): offer the region as DL to it, sent only
	 * if the answer is queued by the time the region is committed. That
	 * decision falls before the long UL burst that completed the request
	 * has even ended, so without the hint the answer waits a whole period.
	 * Otherwise a speculative UL grant, round robin.
	 */
	for (uint8_t k = 0; k < npos && pick < 0; k++) {
		uint8_t pos = (uint8_t)((m->spec_rr + k) % npos);
		struct tdma_peer *p = &m->peers[pos];

		if (ft_flex_ok(m, p, frame) && p->reply_hint) {
			p->reply_hint = false;
			pick = 2 * pos;
			spec = true;
			m->spec_rr = (uint8_t)((pos + 1) % npos);
		}
	}
	for (uint8_t k = 0; k < npos && pick < 0; k++) {
		uint8_t pos = (uint8_t)((m->spec_rr + k) % npos);

		if (ft_flex_ok(m, &m->peers[pos], frame)) {
			pick = 2 * pos + 1;
			spec = true;
			m->spec_rr = (uint8_t)((pos + 1) % npos);
		}
	}
	f->valid = false;
	if (pick < 0) {
		return false;
	}
	struct tdma_peer *p = &m->peers[pick / 2];
	bool ul = pick & 1;
	uint8_t mcs = ul ? p->mcs_ul : p->mcs_dl;
	uint8_t maxn = tdma_max_burst(mcs, flex_max_len(m->plan, fj, ul, ahead));
	uint8_t len;

	if (maxn < 2) {
		return false;
	}
	/*
	 * A train's first region (8 ss): a PT knows a just-in-time grant ~1 ms
	 * before it must commit the burst, and a burst of small SDUs takes too
	 * long to build (on the DKs 0x1000 on ~30 % of them): plan H's 6 ss
	 * until the PT sends bulk SDUs.
	 */
	if (m->train_plan && ul && !p->ul_bulk && maxn > TDMA_TRAIN_SMALL_UL_SS) {
		maxn = TDMA_TRAIN_SMALL_UL_SS;
	}
	len = spec ? maxn : flex_len_for(m, mcs, maxn, need + (ul ? TDMA_STATUS_REC_LEN : 0));
	*f = (struct tdma_flex){.valid = true,
				.ul = ul,
				.spec = spec,
				.slot = fj,
				.pos = (uint8_t)(pick / 2),
				.len = len,
				.mcs = mcs,
				.early = flex_early(m->plan, fj, ul, ahead),
				.ahead = ahead && ul,
				.frame = frame,
				.rd = p->rd_id};
	*e = (struct tdma_grant_entry){
		.pos = f->pos,
		.flags = (uint8_t)((ul ? TDMA_GRANT_F_UL : 0) | (spec ? TDMA_GRANT_F_SPEC : 0)),
		.start = (uint8_t)(fs->subslot - f->early),
		.len = len,
		.mcs = mcs};
	if (ul) {
		size_t c = len_cap(m, mcs, len);

		c = c > TDMA_STATUS_REC_LEN ? c - TDMA_STATUS_REC_LEN : 0;
		/* this burst finishes a bulk SDU: its answer may be bulk too */
		if (!spec && need > link_mtu(&p->link) && c >= need) {
			p->reply_hint = true;
		}
		/* the burst's real start: a status it carries is stamped with it */
		p->glog[p->glog_i] = (struct tdma_grant_log){
			slot_start(m, frame, fs) - (uint64_t)f->early * TDMA_SUBSLOT_TICKS,
			(uint16_t)c};
		p->glog_i = (uint8_t)((p->glog_i + 1) % TDMA_GRANT_LOG);
	}
	if (spec) {
		m->stats.grants_spec++;
	} else if (ul) {
		m->stats.grants_ul++;
	} else {
		m->stats.grants_dl++;
	}
	return true;
}

/*
 * FT: FLEX slot fk continues the train whose first granted region is lj (this
 * frame): the same PT, the same direction, while that flow is in bulk. A
 * speculative UL train stays speculative (the PT sends only if it has
 * something by then). Fills e.
 */
static bool ft_train_follow(struct tdma_mac *m, uint32_t frame, uint8_t lj, uint8_t fk,
			    struct tdma_grant_entry *e)
{
	const struct tdma_flex *ld = &m->flex[flex_i(m, lj)];
	struct tdma_flex *f = &m->flex[flex_i(m, fk)];
	const struct tdma_slot *fs = &m->plan->slots[fk];
	struct tdma_peer *p = &m->peers[ld->pos];
	uint8_t len;

	if (!ld->valid || ld->meas || ld->frame != frame || (ld->spec && !ld->ul) ||
	    !ft_active(m, p, frame) || p->rd_id != ld->rd ||
	    fs_covers(m, fk, frame, slot_start(m, frame, fs))) {
		return false;
	}
	/*
	 * Trains are for bulk SDUs (long fragments); a flood of small SDUs gets
	 * the first region only (a long burst of them takes long to build, and
	 * the ARQ window holds fewer of them than a train carries). A flow in
	 * bulk gets the whole train at full length even when what it reported
	 * (UL) or has queued (DL) now is less: the acks of the last train come
	 * after this decision and free queue room its sender refills before
	 * these regions are built (a DL burst with nothing to send stays off
	 * air). Full length also because 2 ss after a long burst a receiver
	 * takes only another long one (a short one needs TDMA_LRX_TO_TX_SS).
	 */
	if (!ld->spec && !(ld->ul ? p->ul_bulk : link_frag_busy(&p->link))) {
		return false;
	}
	len = tdma_max_burst(ld->mcs, fs->len);
	if (len < TDMA_LRX_MIN_SS) {
		return false;
	}
	*f = (struct tdma_flex){.valid = true,
				.ul = ld->ul,
				.spec = ld->spec,
				.slot = fk,
				.pos = ld->pos,
				.len = len,
				.mcs = ld->mcs,
				.frame = frame,
				.rd = p->rd_id};
	*e = (struct tdma_grant_entry){.pos = f->pos,
				       .flags = (uint8_t)((ld->ul ? TDMA_GRANT_F_UL : 0) |
							  (ld->spec ? TDMA_GRANT_F_SPEC : 0)),
				       .start = fs->subslot,
				       .len = len,
				       .mcs = ld->mcs};
	if (ld->ul) {
		size_t c = len_cap(m, ld->mcs, len);

		c = c > TDMA_STATUS_REC_LEN ? c - TDMA_STATUS_REC_LEN : 0;
		p->glog[p->glog_i] = (struct tdma_grant_log){slot_start(m, frame, fs), (uint16_t)c};
		p->glog_i = (uint8_t)((p->glog_i + 1) % TDMA_GRANT_LOG);
	}
	if (ld->spec) {
		m->stats.grants_spec++;
	} else if (ld->ul) {
		m->stats.grants_ul++;
	} else {
		m->stats.grants_dl++;
	}
	return true;
}

/*
 * FT, after FLEX slot fj of this frame went to a demanded UL burst of PT k:
 * when k is the only one with bulk waiting and still has more than that burst
 * takes, give it FLEX slot fa (the one after the next DL burst, frame ff) now,
 * one DL period ahead. Knowing it that early the PT commits the burst before
 * it receives the DL burst in front of it, so it may use the early extent
 * (plan H: 7 instead of 6 ss); it sends only if it has data then.
 */
static bool ft_ul_ahead(struct tdma_mac *m, uint32_t frame, uint8_t fj, uint8_t fa, uint32_t ff,
			struct tdma_grant_entry *e)
{
	const struct tdma_flex *fj_g = &m->flex[flex_i(m, fj)];
	struct tdma_flex *f = &m->flex[flex_i(m, fa)];
	const struct tdma_slot *fs = &m->plan->slots[fa];
	struct tdma_peer *p;
	size_t need, c;
	uint8_t len, mcs;

	/*
	 * Not with plan BQ in use: in the H frames after BQ -> H under UL bulk
	 * about 1 transition in 10 had the FT's next DL burst fail (0x1005, with
	 * >= 600 us of lead left at the PHY call) and lose the grant in it;
	 * without UL grants ahead 0 in 120 transitions (cause not found). Bulk
	 * goes to T2 there, and UL in H measured the same without them.
	 */
	if (m->cfg.grant_ahead || m->train_plan || m->cfg.plan_bq ||
	    (m->psw_valid && (int32_t)(ff - m->psw_frame) >= 0) || !fj_g->valid || fj_g->meas ||
	    !fj_g->ul || fj_g->spec || fj_g->frame != frame || m->lbt_pending ||
	    (f->valid && (f->frame == ff || f->meas)) ||
	    ft_quiet(m, ff, slot_start(m, ff, fs) + burst_air(fs), TDMA_FLEX_TO_DL_SS)) {
		return false;
	}
	p = &m->peers[fj_g->pos];
	need = ft_ul_need(p); /* after the grant of fj */
	if (!ft_active(m, p, frame) || !p->ul_bulk || need < link_mtu(&p->link)) {
		return false;
	}
	for (uint8_t i = 0; i < m->plan->n_positions; i++) {
		const struct tdma_peer *q = &m->peers[i];

		/* DL to anyone beyond what a guaranteed burst takes, or another PT's UL */
		if (ft_active(m, q, frame) && (link_pending_bytes(&q->link) > q->link.pdu_cap ||
					       (i != fj_g->pos && ft_ul_need(q)))) {
			return false;
		}
	}
	mcs = p->mcs_ul;
	len = tdma_max_burst(mcs, flex_max_len(m->plan, fa, true, true));
	if (len < 2) {
		return false;
	}
	len = flex_len_for(m, mcs, len, need + TDMA_STATUS_REC_LEN);
	*f = (struct tdma_flex){.valid = true,
				.ul = true,
				.ahead = true,
				.slot = fa,
				.pos = fj_g->pos,
				.len = len,
				.mcs = mcs,
				.early = flex_early(m->plan, fa, true, true),
				.frame = ff,
				.rd = p->rd_id};
	*e = (struct tdma_grant_entry){.pos = f->pos,
				       .flags = TDMA_GRANT_F_UL | TDMA_GRANT_F_AHEAD,
				       .start = (uint8_t)(fs->subslot - f->early),
				       .len = len,
				       .mcs = mcs};
	c = len_cap(m, mcs, len);
	c = c > TDMA_STATUS_REC_LEN ? c - TDMA_STATUS_REC_LEN : 0;
	p->glog[p->glog_i] = (struct tdma_grant_log){
		slot_start(m, ff, fs) - (uint64_t)f->early * TDMA_SUBSLOT_TICKS, (uint16_t)c};
	p->glog_i = (uint8_t)((p->glog_i + 1) % TDMA_GRANT_LOG);
	m->stats.grants_ul++;
	m->stats.grants_ahead++;
	return true;
}

/*
 * FT, pattern plans: the pattern of frame f (plan np), decided with the beacon
 * of the frame before. One PT (round robin over those with demand, else the
 * next active one: its UL bursts then go out only with data, the first one
 * for its acks and queue report); in T2 the pattern whose DL share of the
 * frame comes closest to the PT's share of what waits (DL queue against its
 * last queue report). Fills the two grant entries (DL, UL MCS).
 */
static const uint16_t t2_share[] = {
	/* DL bytes per 1024 of the pattern (MCS 4, the beacon burst not counted) */
	[TDMA_T2_U4] = 0,
	[TDMA_T2_D1U3] = 166,
	[TDMA_T2_D2U2] = 452,
	[TDMA_T2_D3U1] = 738,
};

static bool ft_t2_decide(struct tdma_mac *m, const struct tdma_plan *np, uint32_t f,
			 struct tdma_grant_entry *e)
{
	const uint8_t npos = m->plan->n_positions;
	struct tdma_t2 *t = &m->t2[f & 1u];
	int pick = -1, any = -1;
	size_t dl, ul;
	uint8_t pat = 0;

	t->valid = false;
	for (uint8_t k = 0; k < npos && pick < 0; k++) {
		uint8_t i = (uint8_t)((m->t2_rr + k) % npos);
		struct tdma_peer *p = &m->peers[i];

		if (!ft_flex_ok(m, p, f - 1u)) {
			continue;
		}
		any = any < 0 ? i : any;
		if (link_pending_bytes(&p->link) || p->bsr || p->ul_bulk) {
			pick = i;
		}
	}
	pick = pick < 0 ? any : pick;
	if (pick < 0) {
		return false;
	}
	m->t2_rr = (uint8_t)((pick + 1) % npos);
	struct tdma_peer *p = &m->peers[pick];

	dl = link_pending_bytes(&p->link);
	ul = p->bsr;
	if (np->id == TDMA_PLAN_T2 && dl) {
		uint32_t want = ul || p->ul_bulk ? (uint32_t)((uint64_t)dl * 1024u / (dl + ul + 1u))
						 : 1024u;
		uint32_t best = UINT32_MAX;

		for (uint8_t k = 0; k < np->n_pat && k < sizeof(t2_share) / sizeof(t2_share[0]);
		     k++) {
			uint32_t d = want > t2_share[k] ? want - t2_share[k] : t2_share[k] - want;

			if (d < best) {
				best = d;
				pat = k;
			}
		}
	}
	*t = (struct tdma_t2){.valid = true,
			      .frame = f,
			      .plan = np->id,
			      .pat = pat,
			      .pos = (uint8_t)pick,
			      .mcs_dl = p->mcs_dl,
			      .mcs_ul = p->mcs_ul,
			      .rd = p->rd_id};
	e[0] = (struct tdma_grant_entry){.pos = (uint8_t)pick,
					 .flags = TDMA_GRANT_F_NEXT,
					 .start = pat,
					 .len = (uint8_t)(np->id + 1u),
					 .mcs = p->mcs_dl};
	e[1] = e[0];
	e[1].flags |= TDMA_GRANT_F_UL;
	e[1].mcs = p->mcs_ul;
	m->stats.pat_frames[pat_stat_i(np->id)][pat]++;
	return true;
}

static void ft_assoc(struct tdma_mac *m, const struct tdma_assoc_req *r, int16_t rssi)
{
	int free_pos = -1;

	if (r->ft_rd_id != m->cfg.rd_id) {
		return;
	}
	if (sec_denied(m, r->pt_rd_id)) {
		m->stats.sec_denied++;
		return;
	}
	m->stats.assoc_tx++;
	for (uint8_t i = 0; i < m->plan->n_positions; i++) {
		struct tdma_peer *p = &m->peers[i];

		/* short ids are what the beacon lists: they must stay unique */
		if (p->rd_id && tdma_short_rd(p->rd_id) == tdma_short_rd(r->pt_rd_id)) {
			if (p->rd_id == r->pt_rd_id && p->nonce == r->nonce) {
				return; /* a retry of a request we already granted */
			}
			/* New session from a known PT (it rebooted or lost
			 * sync): its sequence numbers start over. Twice within
			 * a second: two radios with one rd id (a provisioning
			 * error that also makes them reuse nonces): alarm.
			 */
			bool fast = p->rd_id == r->pt_rd_id &&
				    (int32_t)(m->cur_frame - p->assoc_frame) < 100;
			uint8_t nfast = fast ? (uint8_t)(p->reassoc_fast + 1) : 0;

			ft_release(m, i, TDMA_CAUSE_REASSOC);
			ft_assign(m, i, r);
			p->reassoc_fast = nfast;
			if (nfast >= 2) {
				p->reassoc_fast = 0;
				m->stats.sec_alarms++;
				emit_full(m, TDMA_EVT_SEC_ALARM, r->pt_rd_id, m->cfg.network_id,
					  TDMA_CAUSE_DUP_ID, i, rssi, m->chan);
			}
			emit(m, TDMA_EVT_CHILD_ADDED, r->pt_rd_id, TDMA_CAUSE_NONE, i, rssi);
			return;
		}
		if (free_pos < 0 && p->rd_id == 0 && !(m->pm_valid && m->pm_to == i)) {
			free_pos = i; /* (not one a PT is about to move to) */
		}
	}
	if (free_pos < 0) {
		if (m->plan->flags & TDMA_PLAN_F_OPEN) {
			/* asked in an open frame; the relay makes room (HG) */
			m->room_wanted = true;
			m->stats.room_asks++;
		}
		return; /* full; the beacon says so */
	}
	ft_assign(m, (uint8_t)free_pos, r);
	emit(m, TDMA_EVT_CHILD_ADDED, r->pt_rd_id, TDMA_CAUSE_NONE, (uint8_t)free_pos, rssi);
}

static void ft_plan_announce(struct tdma_mac *m, uint32_t frame, uint8_t plan_id, uint8_t in)
{
	m->psw_valid = true;
	m->psw_plan = plan_id;
	m->psw_frame = frame + in;
	m->psw_cnt = 0;
}

/*
 * FT: does p's traffic need long bursts (plan H's FLEX regions)? A
 * fragmented SDU to send, or more waiting than two guaranteed PDUs, either
 * way (UL from its last queue report).
 */
static bool ft_wants_flex(const struct tdma_peer *p)
{
	size_t c = p->link.pdu_cap;

	return link_bulk_ready(&p->link) || link_frag_busy(&p->link) ||
	       link_pending_bytes(&p->link) > 2u * c || p->bsr > 2u * c;
}

/*
 * FT, once per frame (beacon), cfg.plan_auto: the bulk plans while PTs move
 * bulk SDUs (a fragmented SDU in flight with a long burst's worth or more
 * waiting, DL, or full UL long bursts with a backlog): T2 while one PT is
 * active (it has the whole frame), T2D for DL only, T with more PTs. Without
 * bulk the configured plan (H), and with cfg.plan_bq plan BQ (guaranteed
 * slots every 2.5 ms, no long bursts) once nothing needed a long burst for
 * TDMA_BQ_QUIET_FRAMES; back to H on the first frame that does. A change is
 * announced after TDMA_PLAN_UP_FRAMES frames in a row that ask for the same
 * other plan (TDMA_PLAN_DOWN_FRAMES back to the configured one, 1 to and
 * from BQ), never sooner than TDMA_PLAN_DWELL_FRAMES after the last switch
 * (TDMA_BQ_DWELL_FRAMES out of BQ). T2 has no UL slot a new PT could contend
 * in: with a position free, the FT leaves it for T after TDMA_T2_MAX_FRAMES.
 */
/* FT, once per frame: the demand EWMA of every PT (TDMA_PLAN_DOWN_BYTES). */
static void ft_demand_tick(struct tdma_mac *m)
{
	for (uint8_t i = 0; i < m->n_peers; i++) {
		struct tdma_peer *p = &m->peers[i];

		for (int d = 0; d < 2; d++) {
			int64_t x = (int64_t)p->dem_acc[d] * 16 - (int64_t)p->dem_q4[d];

			p->dem_q4[d] = (uint32_t)((int64_t)p->dem_q4[d] + x / 16);
			p->dem_acc[d] = 0;
		}
	}
}

static uint32_t peer_demand(const struct tdma_peer *p)
{
	return (p->dem_q4[0] + p->dem_q4[1]) / 16u;
}

static void ft_plan_auto(struct tdma_mac *m, uint32_t frame)
{
	const struct tdma_plan *base = tdma_plan_get(m->base_plan);
	const struct tdma_plan *bulk = tdma_plan_get(TDMA_PLAN_T);
	const struct tdma_plan *t2 = tdma_plan_get(TDMA_PLAN_T2);
	const struct tdma_plan *t2d = tdma_plan_get(TDMA_PLAN_T2D);
	const struct tdma_plan *bq = tdma_plan_get(TDMA_PLAN_BQ);
	const struct tdma_plan *multi = m->cfg.plan_multi ? tdma_plan_get(m->cfg.plan_multi) : NULL;
	const struct tdma_plan *mbulk = multi ? tdma_plan_get(TDMA_PLAN_T4) : NULL;
	const struct tdma_plan *want;
	uint8_t n = 0, act = 0, dl_only = 0, n_assoc = 0, top = 0;
	bool free_pos = false, flex = false, ul_dem = false;
	unsigned int need, dwell;
	uint32_t dmax = 0;

	ft_demand_tick(m);
	if (multi && (!base || multi->mcs != base->mcs || multi->n_positions <= base->n_positions ||
		      multi->n_positions > m->n_peers)) {
		multi = mbulk = NULL;
	}
	if (mbulk && (mbulk->n_positions != multi->n_positions || mbulk->mcs != multi->mcs)) {
		mbulk = NULL;
	}
	if (!m->cfg.plan_auto || m->psw_valid || m->move_valid || m->lbt_pending || m->pm_valid ||
	    !base ||
	    (m->plan != base && m->plan != bulk && m->plan != t2 && m->plan != t2d &&
	     m->plan != bq && (!multi || m->plan != multi) && (!mbulk || m->plan != mbulk))) {
		return;
	}
	bool relay = false;

	for (uint8_t i = 0; i < m->n_peers; i++) {
		if (m->peers[i].rd_id) {
			n_assoc++;
			top = (uint8_t)(i + 1u);
			relay |= m->peers[i].relay;
		}
	}
	if (top > base->n_positions && n_assoc <= base->n_positions && (relay || n_assoc < 2) &&
	    ft_pos_compact(m, frame, base->n_positions)) {
		return; /* the plan after the move */
	}
	/*
	 * A relay child keeps its slots in the E blocks (docs/mac-design.md "Relays"
	 * 2.9): H and T only. Not T2 / T2D (no slots for it), not BQ (DL bursts
	 * in its O blocks), not H4 / T4 (no relay layout for their positions yet;
	 * the cluster stays at 2 PTs) unless PTs sit in positions only those
	 * have.
	 */
	if (relay) {
		t2 = t2d = bq = NULL;
		if (top <= base->n_positions) {
			multi = mbulk = NULL;
		}
	}
	if (multi && (n_assoc >= 2 || top > base->n_positions)) {
		/*
		 * Several PTs: the plan with room for more, at once (with 2 PTs plan
		 * H is full, a third could not join). H's bulk and idle plans are
		 * for one PT only (T2 / T2D give the others no UL slot); this family
		 * is H4 and, under bulk, T4 (a train, every PT keeps its UL slot).
		 */
		if (m->plan != multi && m->plan != mbulk) {
			m->psw_from_t2 = m->plan == t2 || m->plan == t2d;
			ft_plan_announce(m, frame, multi->id, TDMA_PLAN_ANNOUNCE_FRAMES);
			m->stats.plan_multi++;
			return;
		}
		base = multi;
		bulk = mbulk;
		t2 = t2d = bq = NULL;
	}
	if (bulk && (bulk->n_positions != base->n_positions || bulk->mcs != base->mcs)) {
		bulk = NULL;
	}
	if (!m->cfg.plan_t2 || !t2 || t2->n_positions != base->n_positions ||
	    t2->mcs != base->mcs) {
		t2 = t2d = NULL;
	}
	if (t2d && (t2d->n_positions != base->n_positions || t2d->mcs != base->mcs)) {
		t2d = NULL;
	}
	if (!m->cfg.plan_bq || !bq || bq->n_positions != base->n_positions ||
	    bq->mcs != base->mcs || base->id != TDMA_PLAN_H) {
		bq = NULL;
	}
	for (uint8_t i = 0; i < m->plan->n_positions; i++) {
		struct tdma_peer *p = &m->peers[i];
		bool dlb, ulb;

		free_pos |= !p->rd_id;
		if (!ft_active(m, p, frame) || p->relay) {
			continue; /* (a relay never gets long bursts: its bulk asks for no bulk
				     plan) */
		}
		act++;
		dmax = peer_demand(p) > dmax ? peer_demand(p) : dmax;
		ul_dem |= p->dem_q4[1] / 16u >= TDMA_T2D_UL_BYTES || p->bsr >= TDMA_PKT_MAX;
		dlb = link_frag_busy(&p->link) && link_pending_bytes(&p->link) >= TDMA_PKT_MAX;
		ulb = p->ul_bulk && (p->ul_full || ft_ul_need(p) >= TDMA_PKT_MAX);
		n = (uint8_t)(n + (dlb || ulb));
		dl_only = (uint8_t)(dl_only + (dlb && !ulb && p->bsr < TDMA_PKT_MAX));
		flex |= ft_wants_flex(p);
	}
	m->bq_quiet =
		n || flex ? 0 : (uint16_t)(m->bq_quiet < 0xffffu ? m->bq_quiet + 1u : m->bq_quiet);
	if (n) {
		want = act == 1 && t2 ? (dl_only && !ul_dem && t2d ? t2d : t2) : bulk ? bulk : base;
	} else if (bq && (m->bq_quiet >= TDMA_BQ_QUIET_FRAMES || (m->plan == bq && !flex))) {
		want = bq;
	} else {
		want = base;
	}
	if ((want == t2 || want == t2d) && free_pos && bulk &&
	    (((m->plan == t2 || m->plan == t2d) &&
	      (int32_t)(frame - m->plan_since) >= TDMA_T2_MAX_FRAMES) ||
	     (m->plan == bulk && m->psw_from_t2 &&
	      (int32_t)(frame - m->plan_since) < 2 * TDMA_PLAN_DWELL_FRAMES))) {
		want = bulk; /* a while in T: UL slots for association requests */
	}
	/*
	 * Hysteresis: a bulk plan stays while its PT's demand would load H's long
	 * bursts (T2D becomes T2 when the UL needs more than T2D's one UL slot);
	 * then it goes to H (not straight to BQ: BQ follows H when quiet).
	 */
	if (want && (want == base || want == bq) && m->plan != base && m->plan != bq) {
		if (dmax >= TDMA_PLAN_DOWN_BYTES) {
			want = m->plan == t2d && t2 && ul_dem ? t2 : m->plan;
			m->stats.plan_held++;
		} else {
			want = base;
		}
	}
	if (!want || want == m->plan) {
		m->psw_cnt = 0;
		return;
	}
	if (want->id != m->psw_want) {
		m->psw_want = want->id;
		m->psw_cnt = 0;
	}
	m->psw_cnt++;
	need = want == bq || m->plan == bq                    ? 1u
	       : want == base                                 ? TDMA_PLAN_DOWN_FRAMES
	       : m->plan == base && dmax < TDMA_PLAN_UP_BYTES ? TDMA_PLAN_UP_SLOW_FRAMES
							      : TDMA_PLAN_UP_FRAMES;
	dwell = m->plan == bq ? TDMA_BQ_DWELL_FRAMES : TDMA_PLAN_DWELL_FRAMES;
	if (m->psw_cnt >= need && (int32_t)(frame - m->plan_since) >= (int32_t)dwell) {
		m->psw_from_t2 = m->plan == t2 || m->plan == t2d;
		/* out of BQ at once: what waits needs long bursts (a PT that misses it skips a
		 * frame) */
		ft_plan_announce(m, frame, want->id,
				 m->plan == bq ? TDMA_BQ_ANNOUNCE_FRAMES
					       : TDMA_PLAN_ANNOUNCE_FRAMES);
	}
}

/* FT: every associated PT has a position in plan p (positions keep their index). */
static bool plan_fits_peers(const struct tdma_mac *m, const struct tdma_plan *p)
{
	for (uint8_t i = p->n_positions; i < m->n_peers; i++) {
		if (m->peers[i].rd_id) {
			return false;
		}
	}
	return true;
}

int tdma_ft_set_plan(struct tdma_mac *m, int plan_id)
{
	const struct tdma_plan *p;

	if (m->state != TDMA_ST_FT || !m->plan) {
		return -EINVAL;
	}
	if (plan_id < 0) {
		m->cfg.plan_auto = true;
		return 0;
	}
	p = tdma_plan_get((uint8_t)plan_id);
	if (!p || p->n_positions > m->n_peers || !plan_fits_peers(m, p) || p->mcs != m->plan->mcs ||
	    plan_id > 14 || tdma_plan_validate(p)) {
		return -EINVAL;
	}
	for (uint8_t i = 0; i < p->n_positions; i++) {
		/* a relay child keeps the slots of its layout (plan auto never leaves them either)
		 */
		if (m->peers[i].rd_id && m->peers[i].relay &&
		    tdma_relay_plan_check(p, i, tdma_plan_get(TDMA_PLAN_HG), NULL)) {
			return -EINVAL;
		}
	}
	m->cfg.plan_auto = false;
	if (p != m->plan) {
		ft_plan_announce(m, m->cur_frame, (uint8_t)plan_id, TDMA_PLAN_ANNOUNCE_FRAMES);
	}
	return 0;
}

/* One DL burst: the beacon (in the beacon slot), then PDUs for every PT. */
static void ft_dl(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start)
{
	const struct tdma_slot *s = &m->plan->slots[si];
	const uint8_t npos = m->plan->n_positions;
	size_t cap = burst_cap(m, m->mcs, s), off = 0;
	struct link_params lp = link_params(m);
	uint64_t now = m->port.now(m->port.ctx);
	bool beacon = s->use == TDMA_SLOT_BEACON;

	if (beacon) {
		ft_plan_auto(
			m, frame); /* first: a switch next frame changes what this beacon carries */
		ft_pos_prefer(m, frame);
	}
	bool pat = pat_plan(m->plan);
	int fj = pat ? -1 : flex_after(m->plan, si);
	uint32_t fa_wrap = 0;
	int fa = m->flex_plan && !pat ? flex_ahead(m->plan, si, &fa_wrap) : -1;
	size_t gres = (m->cfg.grant_ahead ? fa : fj) >= 0 ? TDMA_GRANT_REC_LEN : 0;
	/* plan T2 next frame (also the first one after a switch): its pattern goes in this beacon
	 */
	const struct tdma_plan *np = m->psw_valid && (int32_t)(frame + 1u - m->psw_frame) >= 0
					     ? tdma_plan_get(m->psw_plan)
					     : m->plan;
	bool t2_next = beacon && pat_plan(np);
	bool fj_new = false, fa_new = false; /* decided in this burst */
	int n;

	uint32_t train_new = 0; /* FLEX indices of train regions decided in this burst */

	if (!m->cfg.grant_ahead && fj >= 0 && fa >= 0 && !m->train_plan) {
		gres += TDMA_GRANT_ENTRY_LEN; /* room for an UL grant one period ahead */
	}
	for (int fk = m->cfg.grant_ahead ? -1 : flex_next_in_train(m->plan, fj); fk >= 0;
	     fk = flex_next_in_train(m->plan, fk)) {
		gres += TDMA_GRANT_ENTRY_LEN; /* the rest of a train */
	}
	if (t2_next) {
		gres += TDMA_GRANT_REC_LEN + TDMA_GRANT_ENTRY_LEN;
	}

	if (!beacon && ft_quiet(m, frame, start + burst_air(s), TDMA_MIN_OP_GAP_SS)) {
		return;
	}
	if (beacon) {
		struct tdma_beacon b = {
			.network_id = m->cfg.network_id,
			.ft_rd_id = m->cfg.rd_id,
			.frame = frame,
			.plan_id = m->plan->id,
			.mcs = m->mcs,
			.roster_ver = m->roster_ver,
			.n = npos,
			.flags = TDMA_F_FULL,
		};

		for (uint8_t i = 0; i < npos; i++) {
			b.e[i].short_id = tdma_short_rd(m->peers[i].rd_id);
			b.e[i].nonce = m->peers[i].nonce;
			if (!m->peers[i].rd_id) {
				b.flags &= ~TDMA_F_FULL;
			}
		}
		if (m->plan->flags & TDMA_PLAN_F_OPEN) {
			b.flags &= ~TDMA_F_FULL; /* HGX: a node may ask in an open frame */
		}
		if (m->hop_mask) {
			b.flags |= TDMA_F_HOP;
			b.hop_base = m->hop_base;
			b.hop_mask = m->hop_mask;
			b.hop_seed = m->hop_seed;
		}
		if (m->move_valid) {
			b.flags |= TDMA_F_MOVE;
			b.move_ch = m->move_ch;
			b.move_frame = m->move_frame;
			b.move_mask = m->move_mask;
		}
		if (m->psw_valid && (int32_t)(m->psw_frame - frame) > 0) {
			b.plan_next = (uint8_t)(m->psw_plan + 1u);
			b.plan_in = (uint8_t)(m->psw_frame - frame);
		}
		if (m->sec.on) {
			sec_ft_beacon(m, frame, &b);
		}
		if (m->retime_valid && (int32_t)(m->retime_frame - frame) > 0) {
			b.flags |= TDMA_F_RETIME;
			b.retime_frame = m->retime_frame;
			b.retime_delta = m->retime_delta;
		}
		if (m->cfg.relay || m->route_len) {
			b.flags |= TDMA_F_TREE;
			tdma_tree(m, &b.depth, &b.grid_ss);
			b.route_len = m->route_len;
			memcpy(b.route, m->route, m->route_len);
			b.app_len = m->route_len ? m->app_len : 0;
			memcpy(b.app, m->app, b.app_len);
		}
		if (m->fs_placed && (int32_t)(m->fs_frame - frame) >= 0) {
			/* our listen elsewhere, with its margins: PTs keep their bursts out of it
			 */
			uint64_t f0 = slot_start(m, m->fs_frame, &m->plan->slots[0]) -
				      (uint64_t)m->plan->slots[0].subslot * TDMA_SUBSLOT_TICKS;
			uint64_t qa = m->fs_start - FS_GAP_BEFORE, qb = m->fs_end + FS_GAP_AFTER;

			if (!(b.flags & TDMA_F_TREE)) {
				b.flags |= TDMA_F_TREE;
				tdma_tree(m, &b.depth, &b.grid_ss);
			}
			b.q_valid = qa >= f0;
			b.q_frame = m->fs_frame;
			b.q_ss = (uint8_t)((qa - f0) / TDMA_SUBSLOT_TICKS);
			b.q_len =
				(uint8_t)((qb - f0 + TDMA_SUBSLOT_TICKS - 1u) / TDMA_SUBSLOT_TICKS -
					  b.q_ss);
		}
		if (m->pm_valid && (int32_t)(m->pm_frame - frame) > 0) {
			/* a position move: announced, and the new position listed as taken */
			if (!(b.flags & TDMA_F_TREE)) {
				b.flags |= TDMA_F_TREE;
				tdma_tree(m, &b.depth, &b.grid_ss);
			}
			b.pm_valid = true;
			b.pm_swap = m->pm_swap;
			b.pm_from = m->pm_from;
			b.pm_to = m->pm_to;
			b.pm_frame = m->pm_frame;
			if (m->pm_to < npos && m->pm_from < npos && !m->pm_swap) {
				b.e[m->pm_to] = b.e[m->pm_from];
			}
		}
		n = tdma_beacon_encode(&b, m->pkt_buf + TDMA_REC_HDR_LEN, tdma_rec_room(cap, off));
		if (n == -ENOBUFS && b.route_len) {
			/* a small DL burst: the beacon without the route record */
			b.route_len = 0;
			b.app_len = 0;
			if (!m->cfg.relay && !b.pm_valid && !b.q_valid) {
				b.flags &= (uint8_t)~TDMA_F_TREE;
			}
			n = tdma_beacon_encode(&b, m->pkt_buf + TDMA_REC_HDR_LEN,
					       tdma_rec_room(cap, off));
		}
		if (n <= 0) {
			return;
		}
		tdma_rec_close(m->pkt_buf, &off, TDMA_ADDR_ALL, (size_t)n);
	}
	for (uint8_t i = 0; i < npos; i++) {
		if (ft_active(m, &m->peers[i], frame)) {
			peer_rx_poll(m, &m->peers[i]);
		}
	}
	/* Round robin over the PTs so one busy PT cannot starve the others
	 * of burst space: priority PDUs of every PT first (small packets; the
	 * net layer marks what fits one PDU), then one PDU each (acks), then
	 * more data while it fits. Room for the grant record stays free.
	 */
	/* a long DL burst (T2D's beacon burst) carries long records: a fragment may take it all */
	const bool lrec = s->len >= TDMA_LRX_MIN_SS;
	const size_t rh = lrec ? TDMA_REC_LONG_HDR_LEN : TDMA_REC_HDR_LEN;

	for (int pass = -1; pass < TDMA_ARQ_WINDOW_WIDE; pass++) {
		bool more = false;

		for (uint8_t k = 0; k < npos; k++) {
			uint8_t i = (uint8_t)((m->dl_rr + k) % npos);
			struct tdma_peer *p = &m->peers[i];
			size_t room = lrec ? tdma_rec_room_long(cap - gres, off)
					   : tdma_rec_room(cap - gres, off);

			if (!ft_active(m, p, frame) || room < TDMA_ACK_LEN) {
				continue;
			}
			/*
			 * Fragments are cut to the room they get: in the first
			 * passes a PT gets at most a guaranteed-burst PDU, and
			 * the PTs after it keep room for an ack-only record.
			 */
			if (pass <= 0) {
				size_t keep = 0;

				for (uint8_t j = (uint8_t)(k + 1u); pass == 0 && j < npos; j++) {
					const struct tdma_peer *q =
						&m->peers[(m->dl_rr + j) % npos];

					if (ft_active(m, q, frame) && q->link.ack_dirty) {
						keep += TDMA_REC_HDR_LEN + TDMA_ACK_LEN + 1u;
					}
				}
				room = room > p->link.pdu_cap ? p->link.pdu_cap : room;
				if (room >= TDMA_ACK_LEN + 1u + keep) {
					room -= keep;
				}
			}
			/* An ack-only PDU after a missed UL lets the PT judge (and
			 * resend) what it sent without waiting for its RTO.
			 */
			n = link_build(&p->link, &lp, now, start, start + burst_air(s),
				       pass < 0 ? LB_PRIO
				       : pass   ? LB_DATA
						: (p->ul_missed_last ? LB_ACK : LB_AUTO),
				       m->pkt_buf + off + rh, room, &m->stats);
			if (n > 0) {
				if (lrec) {
					tdma_rec_close_long(m->pkt_buf, &off, i, (size_t)n);
				} else {
					tdma_rec_close(m->pkt_buf, &off, i, (size_t)n);
				}
				trace_pdu(m, TDMA_TRACE_TX, p->rd_id, m->pkt_buf + off - (size_t)n,
					  (size_t)n, start);
				more |= m->pkt_buf[off - (size_t)n] == TDMA_PDU_DATA;
			}
			/* held back for the acks of the others: try again next pass */
			more |= pass == 0 && link_has_pending(&p->link);
		}
		if (!more && pass >= 0) {
			break;
		}
	}
	m->dl_rr = (uint8_t)((m->dl_rr + 1) % npos);
	if (t2_next) {
		struct tdma_grant g = {.n = 2};

		if (m->lbt_pending || !ft_t2_decide(m, np, frame + 1u, g.e) ||
		    (n = tdma_grant_encode(&g, m->pkt_buf + off + TDMA_REC_HDR_LEN,
					   tdma_rec_room(cap, off))) <= 0) {
			m->t2[(frame + 1u) & 1u].valid = false;
		} else {
			tdma_rec_close(m->pkt_buf, &off, TDMA_ADDR_ALL, (size_t)n);
		}
	}
	if (fj >= 0 && !m->cfg.grant_ahead) {
		struct tdma_grant g = {0};
		const struct tdma_slot *fs = &m->plan->slots[fj];
		struct tdma_flex *fx = &m->flex[flex_i(m, (uint8_t)fj)];
		uint64_t fend = slot_start(m, frame, fs) + burst_air(fs);

		if (ft_quiet(m, frame, fend, TDMA_FLEX_TO_DL_SS)) {
			fx->valid = false; /* keep it quiet before the LBT of the next beacon */
		} else if (fx->valid && fx->ahead && fx->frame == frame) {
			/* given to a long burst one DL period ago */
		} else if (mon_period(m) && !m->lbt_pending &&
			   (int32_t)(frame - m->bg_last) >= (int32_t)(4u * mon_period(m)) &&
			   !ft_flex_demand(m, frame) && (fx->ch = ft_bg_ch(m)) != 0) {
			/*
			 * Background: every 4 periods a region nobody needs measures
			 * a carrier we do not use (move target, carriers dropped
			 * from the hop set).
			 */
			*fx = (struct tdma_flex){.valid = true,
						 .meas = true,
						 .slot = (uint8_t)fj,
						 .len = fs->len,
						 .frame = frame,
						 .ch = fx->ch};
			m->bg_last = frame;
		} else if (!ft_relay_child(m) &&
			   ft_mon_due(m, frame,
				      !ft_any_active(m, frame) ||
					      (!m->port.scan && !ft_flex_demand(m, frame)))) {
			/*
			 * Monitor: this region stays free of our traffic and the
			 * FT measures the channel in it. Taken after half a period
			 * when no PT could use it, else only when a whole period
			 * went by without a free measurement (speculative UL
			 * regions nobody sent in, DL bursts with nothing to send).
			 */
			*fx = (struct tdma_flex){.valid = true,
						 .meas = true,
						 .slot = (uint8_t)fj,
						 .len = fs->len,
						 .frame = frame,
						 .ch = ft_meas_ch(m, frame)};
			m->mon_last = frame;
		} else if (ft_flex_decide(m, frame, (uint8_t)fj, false, &g.e[0])) {
			g.n = 1;
			fj_new = true;
		}
		/* the rest of the train: the PT and direction of its first granted region */
		int lj = fj_new ? fj : -1;

		for (int fk = flex_next_in_train(m->plan, fj); fk >= 0 && g.n < TDMA_MAX_GRANTS;
		     fk = flex_next_in_train(m->plan, fk)) {
			const struct tdma_slot *ks = &m->plan->slots[fk];
			bool ok;

			m->flex[flex_i(m, (uint8_t)fk)].valid = false;
			if (ft_quiet(m, frame, slot_start(m, frame, ks) + burst_air(ks),
				     TDMA_FLEX_TO_DL_SS)) {
				continue;
			}
			ok = lj >= 0 ? ft_train_follow(m, frame, (uint8_t)lj, (uint8_t)fk,
						       &g.e[g.n])
				     : ft_flex_decide(m, frame, (uint8_t)fk, false, &g.e[g.n]);
			if (!ok) {
				continue;
			}
			if (lj < 0) {
				lj = fk;
			}
			train_new |= 1u << flex_i(m, (uint8_t)fk);
			g.n++;
		}
		if (fa >= 0 && g.n < TDMA_MAX_GRANTS &&
		    ft_ul_ahead(m, frame, (uint8_t)fj, (uint8_t)fa, frame + fa_wrap, &g.e[g.n])) {
			g.n++;
			fa_new = true;
		}
		if (g.n) {
			n = tdma_grant_encode(&g, m->pkt_buf + off + TDMA_REC_HDR_LEN,
					      tdma_rec_room(cap, off));
			if (n > 0) {
				tdma_rec_close(m->pkt_buf, &off, TDMA_ADDR_ALL, (size_t)n);
			} else {
				fj_new = fa_new = false;
				for (uint8_t fi = 0; fi < TDMA_FLEX_SLOTS; fi++) {
					if (train_new & (1u << fi)) {
						m->flex[fi].valid = false;
					}
				}
				train_new = 0;
				if (g.e[0].flags & TDMA_GRANT_F_AHEAD) {
					m->flex[flex_i(m, (uint8_t)fa)].valid = false;
				} else {
					m->flex[flex_i(m, (uint8_t)fj)].valid = false;
					if (g.n > 1) {
						m->flex[flex_i(m, (uint8_t)fa)].valid = false;
					}
				}
			}
		}
	}
	if (fa >= 0 && m->cfg.grant_ahead) {
		/* grant-ahead: decide the FLEX region after the next DL burst now */
		struct tdma_grant g = {0};
		const struct tdma_slot *fs = &m->plan->slots[fa];
		uint32_t ff = frame + fa_wrap;
		struct tdma_flex *fx = &m->flex[flex_i(m, (uint8_t)fa)];

		if (ft_quiet(m, ff, slot_start(m, ff, fs) + burst_air(fs), TDMA_FLEX_TO_DL_SS) ||
		    m->lbt_pending || (m->psw_valid && (int32_t)(ff - m->psw_frame) >= 0)) {
			fx->valid = false;
		} else if (ft_flex_decide(m, ff, (uint8_t)fa, true, &g.e[0])) {
			g.n = 1;
			g.e[0].flags |= TDMA_GRANT_F_AHEAD;
			n = tdma_grant_encode(&g, m->pkt_buf + off + TDMA_REC_HDR_LEN,
					      tdma_rec_room(cap, off));
			if (n > 0) {
				tdma_rec_close(m->pkt_buf, &off, TDMA_ADDR_ALL, (size_t)n);
			} else {
				fx->valid = false;
			}
		}
	}
	if (off == 0 && !beacon && ft_mon_due(m, frame, true)) {
		/* nothing to send in this DL burst: measure the channel instead */
		meas_op(m, si, frame, start, s->len, ft_meas_ch(m, frame));
		return;
	}
	if (off == 0 || tx_burst_lbt(m, si, frame, start, TDMA_RD_BROADCAST, off, s->len, m->mcs,
				     beacon && lbt_beacon(m, frame) ? lbt_ticks(m) : 0)) {
		/* the grant never went out: nobody uses the region */
		int gj = m->cfg.grant_ahead ? fa : fj;

		if (gj >= 0 && !m->flex[flex_i(m, (uint8_t)gj)].meas &&
		    (m->cfg.grant_ahead || fj_new)) {
			m->flex[flex_i(m, (uint8_t)gj)].valid = false;
		}
		if (fa_new) {
			m->flex[flex_i(m, (uint8_t)fa)].valid = false;
		}
		for (uint8_t fi = 0; fi < TDMA_FLEX_SLOTS; fi++) {
			if (train_new & (1u << fi)) {
				m->flex[fi].valid = false;
			}
		}
		if (t2_next) {
			m->t2[(frame + 1u) & 1u].valid = false;
		}
		return;
	}
	m->stats.dl_bursts_tx++;
	if (beacon) {
		m->stats.beacons_tx++;
		/*
		 * Key / session switch wanted? Polled after the beacon went to the
		 * PHY: deriving the next session key can take a millisecond or more
		 * (a secure partition) and must not make this beacon late; the next one announces.
		 */
		if (m->sec.on) {
			sec_ft_poll(m, frame + 1u);
		}
		/* PTs learn their position from this beacon and listen from
		 * the next frame on.
		 */
		for (uint8_t i = 0; i < npos; i++) {
			if (m->peers[i].rd_id && !m->peers[i].announced) {
				m->peers[i].announced = true;
				m->peers[i].dl_from_frame = frame + 1;
			}
		}
	}
}

/* One continuous RX over the run of UL / contention slots starting at si. */
static void ft_ul_run(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start)
{
	uint8_t last = si;
	struct tdma_op *op;

	if (si > 0 && is_ul(&m->plan->slots[si - 1])) {
		return; /* inside a run that already has its RX op */
	}
	while (last + 1 < m->plan->n_slots && is_ul(&m->plan->slots[last + 1])) {
		last++;
	}
	if (ft_quiet(m, frame,
		     slot_start(m, frame, &m->plan->slots[last]) + burst_air(&m->plan->slots[last]),
		     TDMA_MIN_OP_GAP_SS)) {
		return;
	}
	op = rx_slots(m, si, last, frame, start);
	if (!op) {
		return;
	}
	for (uint8_t i = si; i <= last; i++) {
		const struct tdma_slot *s = &m->plan->slots[i];
		struct tdma_peer *p = &m->peers[s->pos];

		if (s->use == TDMA_SLOT_UL && p->rd_id && p->announced &&
		    !open_slot(m->plan, s, frame)) {
			op->owners[s->pos] = p->rd_id;
		}
	}
}

/* FT: carry out our decision for FLEX slot si: the long DL burst, or listen for the PT's. */
static void ft_flex(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start)
{
	struct tdma_flex *f = &m->flex[flex_i(m, si)];
	struct tdma_flex g = *f;
	struct tdma_peer *p = &m->peers[f->pos];
	size_t off = 0;

	if (f->valid && f->meas && f->frame == frame && f->slot == si) {
		f->valid = false;
		meas_op(m, si, frame, start, g.len, g.ch);
		return;
	}
	if (!f->valid || f->meas || f->frame != frame || f->slot != si || p->rd_id != f->rd) {
		return;
	}
	f->valid = false;
	if (g.ul) {
		struct tdma_op *op =
			rx_flex(m, si, frame, start - (uint64_t)g.early * TDMA_SUBSLOT_TICKS, &g);

		if (op) {
			op->owners[g.pos] = g.rd;
		}
		return;
	}
	build_records(m, &p->link, start, start + (uint64_t)g.len * TDMA_SUBSLOT_TICKS, LB_AUTO,
		      g.pos, &off, len_cap(m, g.mcs, g.len));
	if (off > 0 && tx_burst(m, si, frame, start, g.rd, off, g.len, g.mcs) == 0) {
		m->stats.flex_tx++;
	}
}

/* FT, plan T2: the frame's pattern in FLEX slot si: our DL burst (with data), or listen. */
static void ft_t2(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start)
{
	const struct tdma_t2 *t = t2_of(m, frame);
	struct tdma_peer *p;
	size_t off = 0;
	int8_t b;

	if (!t || (p = &m->peers[t->pos])->rd_id != t->rd ||
	    ft_quiet(m, frame, start + burst_air(&m->plan->slots[si]), TDMA_FLEX_TO_DL_SS)) {
		return;
	}
	b = tdma_pat_burst(m->plan, t->pat, flex_i(m, si));
	if (b < 0) {
		struct tdma_flex g = {.valid = true,
				      .ul = true,
				      .spec = true,
				      .slot = si,
				      .pos = t->pos,
				      .len = tdma_max_burst(t->mcs_ul, (uint8_t)-b),
				      .mcs = t->mcs_ul,
				      .frame = frame,
				      .rd = t->rd};
		struct tdma_op *op = rx_flex(m, si, frame, start, &g);

		if (op) {
			op->owners[t->pos] = t->rd;
		}
		return;
	}
	if (b == 0 || !link_has_pending(&p->link)) {
		return;
	}
	b = (int8_t)tdma_max_burst(t->mcs_dl, (uint8_t)b);
	build_records(m, &p->link, start, start + (uint64_t)b * TDMA_SUBSLOT_TICKS, LB_AUTO, t->pos,
		      &off, len_cap(m, t->mcs_dl, (uint8_t)b));
	if (off > 0 && tx_burst(m, si, frame, start, t->rd, off, (uint8_t)b, t->mcs_dl) == 0) {
		m->stats.flex_tx++;
	}
}

static void ft_commit(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start)
{
	const struct tdma_slot *s = &m->plan->slots[si];

	if (m->lbt_pending) {
		/* first beacon on this channel: nothing else until its LBT passed */
		if (s->use == TDMA_SLOT_BEACON && (int32_t)(frame - m->lbt_retry_frame) >= 0) {
			ft_dl(m, si, frame, start);
		}
		return;
	}
	if (is_dl(s)) {
		ft_dl(m, si, frame, start);
	} else if (is_flex(s)) {
		(pat_plan(m->plan) ? ft_t2 : ft_flex)(m, si, frame, start);
	} else {
		ft_ul_run(m, si, frame, start);
	}
}

/* ---- scheduler ------------------------------------------------------------------ */

static bool scheduling(const struct tdma_mac *m)
{
	return m->state == TDMA_ST_FT || m->state == TDMA_ST_ASSOCIATING ||
	       m->state == TDMA_ST_ASSOCIATED;
}

static uint32_t rx_clear(const struct tdma_mac *m, const struct tdma_slot *s, uint32_t frame,
			 uint32_t lead);

/*
 * PT: its UL burst in FLEX slot s of frame was granted a DL period ahead. It
 * is committed like a FLEX region after a grant-ahead (the full seal time
 * earlier, and before a burst received just before it, rx_clear()), and the
 * burst starts ul_early before the region.
 */
static bool pt_ul_ahead(const struct tdma_mac *m, const struct tdma_slot *s, uint32_t frame)
{
	const struct tdma_flex *g;
	uint8_t si = (uint8_t)(s - m->plan->slots);

	if (!is_pt(m) || !is_flex(s)) {
		return false;
	}
	g = &m->flex[flex_i(m, si)];
	return g->valid && g->ul && g->early_commit && g->frame == frame && g->slot == si;
}

static bool relay_no_flex(const struct tdma_mac *m);

/*
 * A relay's up instance commits its parent-side DL / beacon RX ops before its
 * child cluster's UL run starts: an RX op committed at the usual 1 ms lead (a
 * PHY call of ~0.2-0.3 ms, the child's PDC event held behind it) delayed the
 * child's burst until the relay's next commit was due (+5 ms per relay
 * hop; plan HG with the UL run first in its block: 1.1 ms average
 * wait on the DKs with the old 7 ss). Under a root the run starts 12 ss
 * before our DL bursts. Under another relay's cluster (plan HG, our UL slots
 * before our DL bursts) the run ends 12 ss before them: committed 9 ss ahead
 * (after the run's bursts are handled, before our UL slots would be committed
 * early with it, and outside their quiet window). TDMA_RELAY_RX_LEAD_TICKS.
 */
static uint32_t relay_rx_lead(const struct tdma_mac *m, const struct tdma_slot *s, uint32_t lead)
{
	uint32_t want;

	if (!is_pt(m) && m->cfg.relay && s->use == TDMA_SLOT_UL && m->plan->id == TDMA_PLAN_HGX) {
		/*
		 * the child's UL (root 20 / 44) comes after our own DL burst
		 * (15 / 39), the parent's DL (24 / 0) after it: the usual lead, its call
		 * after our DL burst's start (at 1.6 ms it fell in that burst's quiet
		 * window: held 0.4 ms, the parent's DL burst waited behind it).
		 */
		return lead;
	}
	if (!is_pt(m) && m->cfg.relay && s->use == TDMA_SLOT_UL) {
		/*
		 * a relay's child cluster commits its UL runs before the
		 * parent's DL burst before them comes in (~1.05 ms after its start,
		 * opened in ~0.6 ms): committed at the usual 1 ms they waited behind
		 * it and reached the PHY ~0.45 ms ahead (0x1000 on the DKs).
		 */
		return lead < TDMA_RELAY_CHILD_RX_LEAD_TICKS ? TDMA_RELAY_CHILD_RX_LEAD_TICKS
							     : lead;
	}
	if (!relay_no_flex(m) || (s->use != TDMA_SLOT_DL && s->use != TDMA_SLOT_BEACON)) {
		return lead;
	}
	/*
	 * under a root with our child cluster on HGX the parent's DL (24 / 0)
	 * comes 9 ss after our child DL burst (15 / 39): committed 8.5 ss ahead, after
	 * that burst's start (12.5 put the call in its quiet window).
	 */
	want = m->child_hgx ? 8u * TDMA_SUBSLOT_TICKS + TDMA_SUBSLOT_TICKS / 2u
			    : TDMA_RELAY_RX_LEAD_TICKS(m->plan);
	return lead < want ? want : lead;
}

/*
 * An FT beacon burst that goes to the PHY with the FLEX lead: one after LBT,
 * or the long one of a pattern plan (T2D: 7 ss, ~600 B of beacon, pattern and
 * DL data; plan 1x10's 8 ss beacon stays: its lead would cut into the UL run).
 * T2D's long beacon burst, built and sealed at the short
 * lead (~0.5 ms of build, open DL records and seal), reached the PHY 0.46-0.66
 * ms ahead and the modem failed it with 0x1005 (FT op errors 15-27 per
 * single-PT test run, ARQ resends: probes under DL bulk
 * p99 up to 42 ms).
 */
static bool long_beacon(const struct tdma_mac *m, const struct tdma_slot *s, uint32_t frame)
{
	return s->use == TDMA_SLOT_BEACON &&
	       (lbt_beacon(m, frame) ||
		(!is_pt(m) && pat_plan(m->plan) && s->len >= TDMA_LRX_MIN_SS));
}

/* How long before its start a slot's op goes to the PHY (an LBT beacon: like FLEX). */
static uint32_t slot_lead(const struct tdma_mac *m, const struct tdma_slot *s, uint32_t frame)
{
	uint32_t lead = (is_flex(s) || long_beacon(m, s, frame)
				 ? TDMA_FLEX_COMMIT_LEAD_TICKS
				 : TDMA_COMMIT_LEAD_TICKS - lead_trim(m, s)) +
			sec_lead(m, s);

	if (pt_ul_ahead(m, s, frame)) {
		lead += lc(m)->flex_cut + (uint32_t)s->ul_early * TDMA_SUBSLOT_TICKS;
	}
	return relay_rx_lead(m, s, rx_clear(m, s, frame, lead));
}

static uint64_t slot_due(const struct tdma_mac *m, uint32_t frame, uint8_t si)
{
	const struct tdma_slot *s = &m->plan->slots[si];
	uint64_t start = slot_start(m, frame, s);
	uint32_t lead = slot_lead(m, s, frame);

	return start > lead ? start - lead : 0;
}

/*
 * When the next slot is due. With a seal cost model the leads differ per
 * slot (a TX slot is committed earlier by its seal time), so a later slot
 * can be due before the current one: then the current one is committed
 * early (harmless) to keep the order.
 */
static uint64_t next_commit_calc(const struct tdma_mac *m)
{
	uint64_t due = slot_due(m, m->cur_frame, m->cur_slot);

	if (sec_hints(m)) {
		uint32_t f = m->cur_frame;
		uint8_t si = m->cur_slot;

		for (uint8_t k = 1; k < m->plan->n_slots; k++) {
			if (++si >= m->plan->n_slots) {
				si = 0;
				f++;
			}
			uint64_t d = slot_due(m, f, si);

			due = d < due ? d : due;
		}
	}
	return due;
}

typedef char tdma_lead_in_fx_check[TDMA_FLEX_SLOTS <= 8 ? 1 : -1];
typedef char tdma_lead_in_op_check[TDMA_MAX_OPS <= 8 ? 1 : -1];

/*
 * A relay's up instance (a PT that announced TDMA_AF_RELAY / TDMA_STF_RELAY):
 * its parent grants it no FLEX burst, so a FLEX region without a known grant
 * holds nothing for it (and its child cluster has the radio there). Without
 * this, rx_clear() kept a relay's commits out of the time it would verify a
 * whole FLEX region it never receives: plan H position 0 committed its UL at
 * 29 and the DL RX at 24 together at 3.95 ms, right when its child's UL burst
 * (root-ss 17-18) ended, so the child's SDU waited for that ~1 ms tick and
 * missed the UL slot it was meant for (+5 ms per relay hop,).
 */
static bool relay_no_flex(const struct tdma_mac *m)
{
	return is_pt(m) && m->cfg.relay && !pat_plan(m->plan);
}

/*
 * The inputs of the leads of frames f and f + 1 besides the lead cache, in a
 * comparable form: rx_end_rel() of every FLEX region of frames f - 1 .. f + 1.
 */
static void lead_inputs(const struct tdma_mac *m, const struct tdma_lead_cache *c, uint32_t f,
			struct tdma_lead_in *in)
{
	memset(in, 0, sizeof(*in));
	in->lbt_pending = m->lbt_pending;
	in->child_hgx = m->child_hgx;
	in->move_valid = m->move_valid;
	in->move_frame = m->move_frame;
	for (uint8_t fi = 0; fi < c->n_flex; fi++) {
		uint8_t pi = c->fslot[fi];
		const struct tdma_flex *g = &m->flex[fi];

		for (uint32_t r = 0; r < 3; r++) {
			uint32_t fr = f - 1u + r;
			uint8_t len = m->plan->slots[pi].len;

			if (pat_plan(m->plan)) {
				len = t2_rx_len(m, pi, fr);
			} else if (g->valid && g->frame == fr && g->slot == pi) {
				len = (uint8_t)(g->len -
						g->early); /* air end, from the region start */
				if (c->pt && g->ul && g->early_commit) {
					in->ul_ahead[r] |= (uint8_t)(1u << fi);
				}
			} else if (relay_no_flex(m)) {
				len = 0;
			}
			in->flex_len[r][fi] = len;
		}
	}
	for (int i = 0; i < TDMA_MAX_OPS; i++) {
		const struct tdma_op *op = &m->ops[i];
		uint32_t r = op->frame - (f - 1u);

		/* ops override the grant (the last one wins, as in rx_end_rel()) */
		if (op->used && !op->is_tx && op->use == TDMA_SLOT_FLEX && r < 3 &&
		    op->plan == m->plan && op->slot < TDMA_LC_SLOTS &&
		    is_flex(&m->plan->slots[op->slot])) {
			in->flex_len[r][c->fidx[op->slot]] =
				(uint8_t)(op->flex.len - op->flex.early);
		}
	}
}

static uint32_t slot_lead_in0(const struct tdma_mac *m, const struct tdma_lead_cache *c,
			      const struct tdma_lead_in *in, uint32_t f_in, uint8_t si,
			      uint32_t frame);

/* slot_lead() of slot si of frame f (f or f + 1 of the snapshot `in` was taken for). */
static uint32_t slot_lead_in(const struct tdma_mac *m, const struct tdma_lead_cache *c,
			     const struct tdma_lead_in *in, uint32_t f_in, uint8_t si,
			     uint32_t frame)
{
	return relay_rx_lead(m, &m->plan->slots[si], slot_lead_in0(m, c, in, f_in, si, frame));
}

static uint32_t slot_lead_in0(const struct tdma_mac *m, const struct tdma_lead_cache *c,
			      const struct tdma_lead_in *in, uint32_t f_in, uint8_t si,
			      uint32_t frame)
{
	const struct tdma_plan *pl = m->plan;
	const struct tdma_slot *s = &pl->slots[si];
	uint8_t n = pl->n_slots;
	uint32_t lead =
		(is_flex(s) || long_beacon(m, s, frame) ? TDMA_FLEX_COMMIT_LEAD_TICKS
							: TDMA_COMMIT_LEAD_TICKS - c->trim[si]) +
		c->slead[si];
	int64_t start = (int64_t)s->subslot * TDMA_SUBSLOT_TICKS;
	int64_t w = TDMA_RX_PROC_TICKS + 2 * (int64_t)c->open_cost;
	bool ahead = is_flex(s) && (in->ul_ahead[frame - (f_in - 1u)] & (1u << c->fidx[si]));

	if (ahead) {
		lead += c->flex_cut + (uint32_t)s->ul_early * TDMA_SUBSLOT_TICKS;
	}
	/* rx_clear() */
	if (!c->hints || (is_flex(s) && !m->cfg.grant_ahead && !ahead && !pat_plan(pl))) {
		return lead;
	}
	for (uint8_t k = 1; k < n; k++) {
		uint8_t pi = (uint8_t)((si + n - k) % n);
		const struct tdma_slot *p = &pl->slots[pi];
		bool prev = pi > si;
		uint32_t len =
			is_flex(p)
				? in->flex_len[frame - (prev ? 1u : 0u) - (f_in - 1u)][c->fidx[pi]]
				: p->len;
		int64_t end = (int64_t)p->subslot * TDMA_SUBSLOT_TICKS +
			      (int64_t)len * TDMA_SUBSLOT_TICKS -
			      (prev ? (int64_t)TDMA_FRAME_TICKS : 0);
		int64_t d = start - end;

		if (d - w > (int64_t)lead) {
			break;
		}
		if (!(is_flex(p) || (c->pt ? is_dl(p) : is_ul(p))) || d <= 0 ||
		    (is_flex(p) && !len)) {
			continue;
		}
		if ((int64_t)lead >= d) {
			uint32_t seal =
				c->slead[si]; /* = sec_lead(): the seal before p's end (rx_clear) */

			if (seal && (int64_t)lead < d + (int64_t)seal &&
			    lead - seal < TDMA_PHY_LEAD_TX_TICKS + TDMA_RX_PROC_TICKS) {
				lead = (uint32_t)d + seal + TDMA_RX_MARGIN_TICKS;
			}
			continue;
		}
		lead = (uint32_t)d + TDMA_RX_MARGIN_TICKS;
	}
	return lead;
}

/*
 * When the next slot is due (as next_commit_calc()). The MAC thread asks on
 * every wakeup (1-2 kHz on the modem), and the lead of a slot looks back over
 * the slots before it, so leads are kept until the frame being scheduled or
 * something they depend on changes; each is computed when first needed.
 */
static uint64_t next_commit(const struct tdma_mac *cm)
{
	struct tdma_mac *m = (struct tdma_mac *)(uintptr_t)cm; /* the memo is logically mutable */
	struct tdma_lead_memo *lm = &m->lmemo;
	const struct tdma_plan *pl = m->plan;
	uint8_t n = pl->n_slots, si = m->cur_slot;
	uint32_t f0 = m->cur_frame, f = f0;
	struct tdma_lead_in in;
	const struct tdma_lead_cache *c;
	uint64_t due = UINT64_MAX;
	uint64_t fstart = slot_start(m, f0, &pl->slots[0]);

	if (!sec_hints(m) || n > TDMA_LC_SLOTS) {
		return next_commit_calc(m);
	}
	c = lc(m);
	lead_inputs(m, c, f0, &in);
	if (!lm->valid || lm->frame != f0 || lm->lc_gen != c->gen ||
	    memcmp(&lm->in, &in, sizeof(in))) {
		lm->in = in;
		lm->frame = f0;
		lm->lc_gen = c->gen;
		lm->have[0] = lm->have[1] = 0;
		lm->valid = true;
	}
	for (uint8_t k = 0; k < n; k++) {
		uint8_t row = (uint8_t)(f - f0);
		uint64_t start = fstart + (uint64_t)row * TDMA_FRAME_TICKS +
				 (uint64_t)(pl->slots[si].subslot - pl->slots[0].subslot) *
					 TDMA_SUBSLOT_TICKS;
		uint64_t d;

		if (!(lm->have[row] & (1u << si))) {
			lm->lead[row][si] = slot_lead_in(m, c, &in, f0, si, f);
			lm->have[row] |= 1u << si;
		}
		d = start > lm->lead[row][si] ? start - lm->lead[row][si] : 0;
		due = d < due ? d : due;
		if (++si >= n) {
			si = 0;
			f++;
		}
	}
#if defined(TDMA_CHECK_LEAD_MEMO)
	/* host tests: the memo must give exactly what the full evaluation gives */
	if (due != next_commit_calc(m)) {
		__builtin_trap();
	}
#endif
	return due;
}

/*
 * Switch to plan p (compatible with the one in use) now: FT at the frame it
 * announced, PT there too or at once when a beacon names another plan. Ops
 * already committed keep their plan (op->plan); grants are dropped (a frame of
 * the new plan is granted in its own beacon); every link takes the queue
 * depth and tag window of the new plan.
 */
static void plan_apply(struct tdma_mac *m, const struct tdma_plan *p)
{
	m->psw_valid = false;
	if (!p || p == m->plan) {
		return;
	}
	m->plan = p;
	m->flex_plan = tdma_plan_has_flex(p);
	m->train_plan = tdma_plan_has_train(p);
	m->plan_since = m->cur_frame;
	m->psw_cnt = 0;
	flex_clear(m);
	if (m->cur_slot >= p->n_slots) {
		m->cur_slot = 0;
		m->cur_frame++;
	}
	if (is_pt(m)) {
		if (m->state == TDMA_ST_ASSOCIATED) {
			link_set_cap(&m->peers[0].link, ul_pdu_cap(p, m->mcs, m->sec.on),
				     m->flex_plan, q_depth(m));
		}
	} else {
		for (uint8_t i = 0; i < p->n_positions; i++) {
			if (m->peers[i].rd_id) {
				link_set_cap(&m->peers[i].link, dl_pdu_cap(p, m->mcs, m->sec.on),
					     m->flex_plan, q_depth(m));
			}
		}
	}
	m->stats.psw_log[m->stats.plan_switches % 8u] = m->cur_frame << 4 | p->id;
	m->stats.plan_switches++;
}

static void advance(struct tdma_mac *m)
{
	if (++m->cur_slot >= m->plan->n_slots) {
		m->cur_slot = 0;
		m->cur_frame++;
	}
}

/* An announced plan switch takes effect before the first slot of its frame is committed. */
static void plan_due(struct tdma_mac *m)
{
	if (m->psw_valid && m->cur_slot == 0 && (int32_t)(m->cur_frame - m->psw_frame) >= 0) {
		plan_apply(m, tdma_plan_get(m->psw_plan));
	}
}

static bool slot_used(const struct tdma_mac *m, uint8_t si, uint32_t frame);

/*
 * The latest time the next commits may start and still reach the PHY in time:
 * per slot the MAC has an op for, its start minus `tx_need` (a burst we send:
 * build, seal, PHY call, PHY lead) or `rx_need` (a receive op); the earliest
 * over the next frame's slots (they are committed in order). The port asks it
 * before it lets a received burst go ahead of a commit that is due by its
 * nominal lead (a relay: the burst may carry what that commit should send).
 */
uint64_t tdma_next_latest(const struct tdma_mac *m, uint32_t tx_need, uint32_t rx_need)
{
	uint64_t latest = UINT64_MAX;
	uint32_t f = m->cur_frame;
	uint8_t si = m->cur_slot;

	uint64_t dl_extra = TDMA_US_TO_TICKS(150);

	if (!scheduling(m)) {
		return UINT64_MAX;
	}
	if (!is_pt(m)) {
		/*
		 * a DL burst that fills with fragments takes ~0.15 ms more to
		 * build, and a ~200 B burst wants ~0.6 ms at the PHY (0x1005 at 0.53 on
		 * the DKs: the depth-2 relay of a three-hop chain under DL bulk)
		 */
		for (uint8_t i = 0; i < m->plan->n_positions; i++) {
			if (m->peers[i].rd_id && link_pending_bytes(&m->peers[i].link) > 200u) {
				dl_extra = TDMA_US_TO_TICKS(300);
				break;
			}
		}
	}
	for (uint8_t k = 0; k < m->plan->n_slots; k++) {
		const struct tdma_slot *s = &m->plan->slots[si];

		if (slot_used(m, si, f)) {
			bool tx = is_pt(m) ? (s->use == TDMA_SLOT_UL ||
					      s->use == TDMA_SLOT_CONTENTION || is_flex(s))
					   : (is_dl(s) || is_flex(s));
			/* an FT's DL / beacon burst: + 150 us (bigger, its records take longer to
			 * build) */
			uint64_t st = slot_start(m, f, s),
				 need = !tx ? rx_need : tx_need + (is_pt(m) ? 0u : dl_extra);

			uint64_t l = st > need ? st - need : 0;

			latest = l < latest ? l : latest;
		}
		if (++si >= m->plan->n_slots) {
			si = 0;
			f++;
		}
	}
	return latest;
}

uint64_t tdma_next_wakeup(const struct tdma_mac *m)
{
	if (scheduling(m)) {
		return next_commit(m);
	}
	if ((m->state == TDMA_ST_SEARCH || m->state == TDMA_ST_FT_SCAN) && !m->search_handle &&
	    !m->n_ops) {
		return m->retry_at;
	}
	return UINT64_MAX;
}

/*
 * Would slot si of frame (starting at start) give an op, and is the radio
 * someone else's then (port.away, a relay's other instance)? The op's extent:
 * the burst, an FT's whole UL run, a FLEX region with its early UL extent, an
 * LBT window before the beacon or an association request.
 */
/*
 * Would slot si of frame give an op of ours? PT: the beacon, DL bursts once
 * associated, its own UL slot or a contention opportunity, a FLEX region
 * granted to it; FT: every slot but FLEX regions it gave nobody and UL slots
 * inside a run (the run's RX op belongs to its first slot).
 */
static bool slot_used(const struct tdma_mac *m, uint8_t si, uint32_t frame)
{
	const struct tdma_plan *pl = m->plan;
	const struct tdma_slot *s = &pl->slots[si];

	if (is_pt(m)) {
		bool assoc = m->state == TDMA_ST_ASSOCIATED;
		bool open = open_slot(pl, s, frame);
		bool contend =
			m->state == TDMA_ST_ASSOCIATING &&
			(s->use == TDMA_SLOT_CONTENTION ||
			 (s->use == TDMA_SLOT_UL && ((m->free_mask & (1u << s->pos)) || open)));

		if ((s->use == TDMA_SLOT_DL && !assoc) ||
		    (s->use == TDMA_SLOT_UL && !contend &&
		     !(assoc && s->pos == m->my_pos && !open)) ||
		    (s->use == TDMA_SLOT_CONTENTION && !contend)) {
			return false;
		}
		if (is_flex(s)) {
			const struct tdma_flex *g = &m->flex[flex_i(m, si)];

			return assoc &&
			       (pat_plan(pl) || (g->valid && g->frame == frame && g->slot == si));
		}
		return true;
	}
	if (is_flex(s) && !pat_plan(pl)) {
		const struct tdma_flex *f = &m->flex[flex_i(m, si)];

		return f->valid && f->frame == frame && f->slot == si;
	}
	return !(is_ul(s) && si > 0 && is_ul(&pl->slots[si - 1]));
}

/* The radio time [*a, *e) slot si of frame (starting at start) would take, RX margins included. */
static void slot_extent(const struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start,
			uint64_t *a_out, uint64_t *e_out)
{
	const struct tdma_plan *pl = m->plan;
	const struct tdma_slot *s = &pl->slots[si];
	uint64_t a = start, e = start + burst_air(s);

	if (is_pt(m)) {
		bool contend = m->state == TDMA_ST_ASSOCIATING &&
			       (s->use == TDMA_SLOT_CONTENTION ||
				(s->use == TDMA_SLOT_UL && (m->free_mask & (1u << s->pos))));

		if (contend && rach_lbt_ticks(m)) {
			a -= rach_lbt_ticks(m);
		}
	} else {
		if (is_ul(s)) {
			uint8_t last = si;

			while (last + 1 < pl->n_slots && is_ul(&pl->slots[last + 1])) {
				last++;
			}
			e = slot_start(m, frame, &pl->slots[last]) + burst_air(&pl->slots[last]);
		}
		if (s->use == TDMA_SLOT_BEACON && lbt_beacon(m, frame)) {
			a -= lbt_ticks(m);
		}
	}
	if (is_flex(s)) {
		a -= (uint64_t)s->ul_early * TDMA_SUBSLOT_TICKS;
		if (start + (uint64_t)(s->ul_len > s->len ? s->ul_len : s->len) *
				    TDMA_SUBSLOT_TICKS >
		    e) {
			e = start + (uint64_t)(s->ul_len > s->len ? s->ul_len : s->len) *
					    TDMA_SUBSLOT_TICKS;
		}
	}
	*a_out = a - TDMA_RX_MARGIN_TICKS;
	*e_out = e + TDMA_RX_MARGIN_TICKS;
}

static bool slot_away(const struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start)
{
	uint64_t a, e;

	if (!slot_used(m, si, frame)) {
		return false;
	}
	slot_extent(m, si, frame, start, &a, &e);
	return m->port.away(m->port.ctx, a, (uint32_t)(e - a)) != 0;
}

/* ---- FT: listens for other trees (tdma_ft_scan()) ------------------------ */

/* A carrier of the channel set (also with a fixed channel: listening is not using it). */
static bool ch_in_set(const struct tdma_mac *m, uint16_t ch)
{
	return ch >= m->cfg.ch_min && ch <= m->cfg.ch_max && ch - m->cfg.ch_min < 32 &&
	       (!m->cfg.ch_mask || (m->cfg.ch_mask & (1u << (ch - m->cfg.ch_min))));
}

static void fs_end(struct tdma_mac *m, enum tdma_cause cause)
{
	struct tdma_evt e = {.type = TDMA_EVT_FT_SCAN_DONE,
			     .rd_id = m->cfg.rd_id,
			     .network_id = m->cfg.network_id,
			     .cause = cause,
			     .channel = m->fs_ch,
			     .value = m->fs_heard | (uint32_t)m->fs_pcc << 16};
	struct tdma_chan_info *c = ch_info(m, m->fs_ch);

	if (cause == TDMA_CAUSE_NONE) {
		m->stats.fs_scans++;
		if (c) {
			/* who operates there now (what the start scan counted goes stale) */
			c->clusters = (uint8_t)(m->fs_pcc > 255u ? 255u : m->fs_pcc);
		}
	}
	m->fs_valid = m->fs_placed = false;
	m->fs_handle = 0;
	if (m->cfg.evt_cb) {
		m->cfg.evt_cb(&e, m->cfg.evt_user);
	}
}

int tdma_ft_scan(struct tdma_mac *m, uint16_t ch, uint8_t flags)
{
	if (m->state != TDMA_ST_FT || m->cfg.role != TDMA_ROLE_FT || m->cfg.relay || m->fs_valid ||
	    !m->port.scan || m->lbt_pending || m->move_valid || m->retime_valid ||
	    (!(flags & TDMA_FS_ANY_PLAN) && (m->train_plan || pat_plan(m->plan)))) {
		return -EBUSY;
	}
	if (ch && !ch_in_set(m, ch)) {
		return -EINVAL;
	}
	for (uint8_t k = 1, n = ch_count(m); !ch && k <= n; k++) {
		uint8_t i = (uint8_t)((m->fs_rr + k) % n);
		uint16_t c = (uint16_t)(m->cfg.ch_min + i);

		if (ch_in_set(m, c)) {
			ch = c;
			m->fs_rr = i;
		}
	}
	if (!ch) {
		return -EBUSY;
	}
	m->fs_valid = true;
	m->fs_placed = false;
	m->fs_ch = ch;
	m->fs_handle = 0;
	m->fs_heard = m->fs_pcc = 0;
	m->fs_until = m->cur_frame + TDMA_FT_SCAN_FRAMES;
	return 0;
}

/*
 * At the beacon of frame: the window goes after the next frame's beacon
 * burst (decided a frame ahead, so no FLEX region is granted into it).
 */
static void fs_place(struct tdma_mac *m, uint32_t frame)
{
	const struct tdma_plan *pl = m->plan;
	uint32_t f = frame + 1u;
	uint64_t a, e;

	if (m->lbt_pending || m->move_valid || m->retime_valid || m->psw_valid || m->pm_valid ||
	    pl->slots[0].use != TDMA_SLOT_BEACON) {
		return; /* (an announcement in flight: the next beacon) */
	}
	slot_extent(m, 0, f, slot_start(m, f, &pl->slots[0]), &a, &e);
	m->fs_frame = f;
	m->fs_start = e + FS_GAP_BEFORE;
	m->fs_end = m->fs_start + TDMA_FT_SCAN_TICKS;
	m->fs_placed = true;
}

/* Does the window take the radio time of slot si of frame? */
static bool fs_covers(const struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start)
{
	uint64_t a, e;

	if (!m->fs_placed) {
		return false;
	}
	slot_extent(m, si, frame, start, &a, &e);
	return a < m->fs_end + FS_GAP_AFTER && e + FS_GAP_BEFORE > m->fs_start;
}

/*
 * PT: would slot si of frame fall in the FT's announced listen? The FT's view
 * of the slot (an UL run from its first slot to its last, a FLEX region with
 * its UL extent), so we leave out exactly what it leaves out. The beacon RX
 * stays (sync bookkeeping).
 */
static bool pt_quiet(struct tdma_mac *m, uint8_t si, uint32_t frame, uint64_t start)
{
	const struct tdma_plan *pl = m->plan;
	const struct tdma_slot *s = &pl->slots[si];
	uint64_t f0, qa, qb, a, e;
	uint8_t first = si;

	if (!m->q_valid) {
		return false;
	}
	if ((int32_t)(frame - m->q_frame) > 2) {
		m->q_valid = false;
		return false;
	}
	if (s->use == TDMA_SLOT_BEACON || !slot_used(m, si, frame)) {
		return false;
	}
	f0 = slot_start(m, m->q_frame, &pl->slots[0]) -
	     (uint64_t)pl->slots[0].subslot * TDMA_SUBSLOT_TICKS;
	qa = f0 + (uint64_t)m->q_ss * TDMA_SUBSLOT_TICKS;
	qb = qa + (uint64_t)m->q_len * TDMA_SUBSLOT_TICKS;
	if (s->use == TDMA_SLOT_UL) {
		uint8_t last = si;

		while (first > 0 && pl->slots[first - 1].use == TDMA_SLOT_UL) {
			first--;
		}
		while (last + 1 < pl->n_slots && pl->slots[last + 1].use == TDMA_SLOT_UL) {
			last++;
		}
		a = start - (uint64_t)(s->subslot - pl->slots[first].subslot) * TDMA_SUBSLOT_TICKS -
		    TDMA_RX_MARGIN_TICKS;
		e = start +
		    (uint64_t)(pl->slots[last].subslot + pl->slots[last].len - s->subslot) *
			    TDMA_SUBSLOT_TICKS +
		    TDMA_RX_MARGIN_TICKS;
	} else {
		slot_extent(m, si, frame, start, &a, &e);
	}
	if (a < qb && e > qa) {
		m->stats.fs_quiet++;
		return true;
	}
	return false;
}

/* The listen itself, once our beacon burst before it is committed (in order with it). */
static void fs_commit(struct tdma_mac *m, uint64_t now)
{
	struct tdma_op *op;

	if (!m->fs_placed || m->fs_handle || m->fs_start > now + 2u * TDMA_FRAME_TICKS) {
		return;
	}
	if (now + TDMA_PHY_LEAD_RX_TICKS + 2u * TDMA_RX_MARGIN_TICKS >= m->fs_start ||
	    !(op = op_new(m))) {
		fs_end(m, TDMA_CAUSE_STOPPED);
		return;
	}
	if (m->port.scan(m->port.ctx, op->handle, m->fs_start - TDMA_RX_MARGIN_TICKS,
			 (uint32_t)(m->fs_end - m->fs_start) + 2u * TDMA_RX_MARGIN_TICKS,
			 m->fs_ch)) {
		m->stats.port_errors++;
		fs_end(m, TDMA_CAUSE_STOPPED);
		return;
	}
	op->use = USE_FTSCAN;
	op->ch = m->fs_ch;
	op->start = m->fs_start;
	op->frame = m->fs_frame;
	op_commit(m, op);
	m->fs_handle = op->handle;
}

/* tdma_tick(), FT: a listen that could not be placed / committed in time goes. */
static void fs_tick(struct tdma_mac *m, uint64_t now)
{
	if (!m->fs_valid) {
		return;
	}
	if (m->state != TDMA_ST_FT) {
		if (!m->fs_handle) {
			fs_end(m, TDMA_CAUSE_STOPPED);
		}
		return;
	}
	if ((!m->fs_placed && (int32_t)(m->cur_frame - m->fs_until) > 0) ||
	    (m->fs_placed && !m->fs_handle && now + TDMA_PHY_LEAD_RX_TICKS >= m->fs_start)) {
		fs_end(m, TDMA_CAUSE_STOPPED);
	}
}

/* A packet the listen received: a beacon (cleartext part, not verified) is reported. */
static void fs_rx(struct tdma_mac *m, const uint8_t *phy_hdr, size_t hdr_len, const uint8_t *pkt,
		  size_t len, int16_t rssi, int16_t snr_q2)
{
	struct tdma_phy_hdr h;
	struct tdma_beacon b;
	struct tdma_chan_info *c = ch_info(m, m->fs_ch);
	uint32_t used = 0;

	if (tdma_phy_hdr_decode(phy_hdr, hdr_len, &h) || h.rx_short != TDMA_SHORT_BROADCAST ||
	    clear_beacon(m, pkt, len, &b) || b.ft_rd_id == m->cfg.rd_id ||
	    tdma_short_rd(b.ft_rd_id) != h.tx_short) {
		return;
	}
	m->fs_heard++;
	m->stats.fs_beacons++;
	if (c) {
		c->cluster_rd = b.ft_rd_id;
		c->cluster_nwid = b.network_id;
	}
	for (uint8_t i = 0; i < b.n; i++) {
		used += b.e[i].short_id != 0;
	}
	if (m->cfg.evt_cb) {
		struct tdma_evt e = {.type = TDMA_EVT_FT_SCAN,
				     .rd_id = b.ft_rd_id,
				     .network_id = b.network_id,
				     .rssi = rssi,
				     .channel = m->fs_ch,
				     .value = b.depth | (uint32_t)b.grid_ss << 8 |
					      ((b.flags & TDMA_F_FULL) ? 1u << 16 : 0) | used << 20,
				     .snr_q2 = snr_q2,
				     .tx_power = h.tx_power,
				     .route_len = b.route_len,
				     .route = b.route,
				     .app_len = b.app_len,
				     .app = b.app};

		m->cfg.evt_cb(&e, m->cfg.evt_user);
	}
}

uint64_t tdma_tick(struct tdma_mac *m, uint64_t now)
{
	if (m->state == TDMA_ST_SEARCH) {
		search_kick(m, now);
	}
	if (m->state == TDMA_ST_FT_SCAN) {
		ft_scan_kick(m, now);
	}
	bool first = true;
	uint64_t nc = 0;
	bool nc_valid = false;

	if (is_pt(m)) {
		probe_tick(m, now);
	} else {
		fs_tick(m, now);
	}
	while (scheduling(m)) {
		plan_due(m);
		uint8_t si = m->cur_slot;
		const struct tdma_slot *s = &m->plan->slots[si];
		uint64_t start = slot_start(m, m->cur_frame, s);
		uint32_t frame = m->cur_frame;

		/*
		 * A commit can take long (sealing, deriving a session key in a secure partition):
		 * judge the next slot against the time now, not the time the tick
		 * started, so a slot that became too close is skipped instead of
		 * reaching the PHY late.
		 */
		if (!first) {
			uint64_t t = m->port.now(m->port.ctx);

			now = t > now ? t : now;
		}
		first = false;

		nc = next_commit(m);
		if (nc > now) {
			nc_valid =
				true; /* = tdma_next_wakeup(): nothing changes before the return */
			break;
		}
		if ((int64_t)(now - start) > 2 * (int64_t)TDMA_FRAME_TICKS) {
			/* The MAC stalled: jump to the current frame instead
			 * of walking every missed slot.
			 */
			uint32_t behind = (uint32_t)((now - start) / TDMA_FRAME_TICKS);

			m->stats.late_slots += behind * m->plan->n_slots;
			m->cur_frame += behind;
			continue;
		}
		if (m->retime_valid && si == 0 && (int32_t)(frame - m->retime_frame) >= 0) {
			/* this frame and the ones after it start retime_delta later */
			m->ref_start += m->retime_delta;
			m->retime_valid = false;
			m->stats.retimes++;
			emit(m, TDMA_EVT_RETIME, m->cfg.rd_id, TDMA_CAUSE_NONE, 0, 0);
			continue;
		}
		if (m->pm_valid && si == 0 && (int32_t)(frame - m->pm_frame) >= 0) {
			pos_move_apply(m);
		}
		/* Too close for the PHY (RX windows open RX_MARGIN early, LBT before the beacon).
		 */
		if ((int64_t)(start - TDMA_RX_MARGIN_TICKS - now -
			      (s->use == TDMA_SLOT_BEACON && lbt_beacon(m, frame) ? lbt_ticks(m)
										  : 0)) <
		    (int64_t)TDMA_PHY_LEAD_TX_TICKS) {
			/*
			 * (a slot that gives us no op is not late: another PT's UL slot
			 * right after sync, a FLEX region nobody granted us)
			 */
			if (slot_used(m, si, frame) &&
			    !(is_pt(m) && s->use == TDMA_SLOT_UL && s->pos != m->my_pos)) {
				m->stats.late_slots++;
			}
			/* Still run the PT beacon bookkeeping (sync loss). */
			if (is_pt(m) && s->use == TDMA_SLOT_BEACON && pt_sync_gone(m, frame)) {
				pt_lose(m, TDMA_CAUSE_SYNC_LOST);
				break;
			}
			advance(m);
			continue;
		}
		if (m->move_valid && (int32_t)(frame - m->move_frame) >= 0) {
			apply_move(m, frame);
		}
		if (m->sec.on) {
			sec_tick(m, frame);
		}
		/* our root's listen for other trees has the radio then (PT: the FT's). */
		if (is_pt(m) && m->state == TDMA_ST_ASSOCIATED && pt_quiet(m, si, frame, start)) {
			advance(m);
			continue;
		}
		if (!is_pt(m) && fs_covers(m, si, frame, start)) {
			m->stats.fs_skipped += slot_used(m, si, frame);
			advance(m);
			fs_commit(m, now);
			continue;
		}
		/* A relay: the radio is the other instance's then (tdma_relay_away()). */
		if (m->port.away && slot_away(m, si, frame, start)) {
			m->stats.relay_away++;
			advance(m);
			if (is_pt(m) && s->use == TDMA_SLOT_BEACON && pt_sync_gone(m, frame)) {
				pt_lose(m, TDMA_CAUSE_SYNC_LOST);
				break;
			}
			continue;
		}
		/* Advance first: a commit may resync or leave the schedule. */
		advance(m);
		if (is_pt(m)) {
			pt_commit(m, si, frame, start);
		} else {
			if (m->fs_valid && !m->fs_placed && s->use == TDMA_SLOT_BEACON) {
				fs_place(m, frame);
			}
			ft_commit(m, si, frame, start);
			if (m->fs_placed && frame == m->fs_frame) {
				fs_commit(m, now);
			}
		}
	}
	return nc_valid ? nc : tdma_next_wakeup(m);
}

/* ---- link security (docs/mac-design.md "Link security") ----------------------------- */

/*
 * Packet: sec_hdr (2) | [cleartext record] | body (CCM ciphertext) | MIC.
 * Nonce: tx long rd id | FT frame | start subslot | 0 0 0 0 (13 bytes, BE),
 * never sent. AAD: the PHY header fields | sec_hdr | cleartext record. Keys:
 * one per FT session (port derives it from the network key, key index,
 * network id, FT rd id, session counter and random); sessions switch at an
 * announced frame (key rotation, counter rollover).
 */

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static void emit_sec(struct tdma_mac *m, enum tdma_evt_type type, uint32_t rd,
		     enum tdma_cause cause, uint32_t value, uint32_t frame)
{
	struct tdma_evt e = {
		.type = type,
		.rd_id = rd,
		.network_id = m->cfg.network_id,
		.cause = cause,
		.channel = m->chan,
		.value = value,
		.frame = frame,
	};

	if (m->cfg.evt_cb) {
		m->cfg.evt_cb(&e, m->cfg.evt_user);
	}
}

static bool sec_hints_calc(const struct tdma_mac *m)
{
	return m->sec.on && (m->port.sec->seal_ticks_base || m->port.sec->seal_ticks_per16);
}

static uint32_t sec_cost(const struct tdma_mac *m, size_t bytes)
{
	return m->port.sec->seal_ticks_base +
	       m->port.sec->seal_ticks_per16 * (uint32_t)((bytes + 15u) / 16u);
}

/* Extra commit lead of a slot this node may transmit in: its seal time. */
static uint32_t sec_lead_calc(const struct tdma_mac *m, const struct tdma_slot *s)
{
	bool tx;
	size_t bytes;
	uint32_t cost;

	if (!sec_hints_calc(m)) {
		return 0;
	}
	tx = is_flex(s) || (is_pt(m) ? is_ul(s) : is_dl(s));
	/*
	 * (an associated PT sends in its own position's UL slots only: another
	 * position's slot due a seal time early woke a relay's MAC thread with
	 * nothing to commit, right when its child's UL burst was to be opened)
	 */
	if (!tx || (is_pt(m) && s->use == TDMA_SLOT_UL && m->state == TDMA_ST_ASSOCIATED &&
		    m->my_pos >= 0 && s->pos != m->my_pos)) {
		return 0;
	}
	bytes = is_flex(s) ? TDMA_PKT_MAX : tdma_tbs(m->mcs, s->len);
	cost = sec_cost(m, bytes > TDMA_PKT_MAX ? TDMA_PKT_MAX : bytes);
	/*
	 * A FLEX region is committed TDMA_FLEX_EXTRA_LEAD_TICKS earlier anyway; on
	 * a PT that counts toward its seal time: more would move its commit
	 * before the grant that decides it has been received and break the plan.
	 * The FT decided the region when it built the DL burst before it, so it
	 * commits it the full seal time earlier: on the modem the FT's long DL
	 * bursts otherwise reached the PHY late (0x1000) under bulk, the seal
	 * having eaten the margin that the extra lead was there for.
	 */
	if (is_flex(s) && !m->cfg.grant_ahead && is_pt(m) && !pat_plan(m->plan)) {
		cost = cost > TDMA_FLEX_EXTRA_LEAD_TICKS ? cost - TDMA_FLEX_EXTRA_LEAD_TICKS : 0;
	}
	return cost;
}

static uint32_t sec_open_cost_calc(const struct tdma_mac *m)
{
	return sec_hints_calc(m) ? sec_cost(m, TDMA_PKT_MAX) : 0;
}

/*
 * The lead-model constants of the plan in use, recomputed when an input
 * changed (plan, MCS, role, grant-ahead, security, the cost model, which
 * 'mm sec cost' may change at run time). The cache is logically mutable.
 */
static const struct tdma_lead_cache *lc(const struct tdma_mac *cm)
{
	struct tdma_mac *m = (struct tdma_mac *)(uintptr_t)cm;
	struct tdma_lead_cache *c = &m->lc;
	const struct tdma_sec_ops *o = m->port.sec;
	uint32_t sb = o ? o->seal_ticks_base : 0, sp = o ? o->seal_ticks_per16 : 0;
	uint32_t ob = o ? o->open_ticks_base : 0, op = o ? o->open_ticks_per16 : 0;

	int8_t pos = is_pt(m) && m->state == TDMA_ST_ASSOCIATED ? m->my_pos : -1;

	if (c->valid && c->plan == m->plan && c->sec == o && c->mcs == m->mcs &&
	    c->pt == is_pt(m) && c->ahead == m->cfg.grant_ahead && c->on == m->sec.on &&
	    c->relay == m->cfg.relay && c->sb == sb && c->sp == sp && c->ob == ob && c->op == op &&
	    c->pos == pos && c->ul_trim == m->cfg.ul_lead_trim &&
	    c->dl_trim == m->cfg.dl_lead_trim) {
		return c;
	}
	c->pos = pos;
	c->ul_trim = m->cfg.ul_lead_trim;
	c->dl_trim = m->cfg.dl_lead_trim;
	c->plan = m->plan;
	c->sec = o;
	c->sb = sb;
	c->sp = sp;
	c->ob = ob;
	c->op = op;
	c->mcs = m->mcs;
	c->pt = is_pt(m);
	c->ahead = m->cfg.grant_ahead;
	c->on = m->sec.on;
	c->relay = m->cfg.relay;
	c->hints = sec_hints_calc(m);
	c->open_cost = sec_open_cost_calc(m);
	c->clear_max = rx_clear_max_calc(m);
	c->n_flex = 0;
	c->flex_cut = 0;
	if (c->hints && is_pt(m) && !m->cfg.grant_ahead && !pat_plan(m->plan)) {
		uint32_t cost = sec_cost(m, TDMA_PKT_MAX);

		c->flex_cut = cost < TDMA_FLEX_EXTRA_LEAD_TICKS ? cost : TDMA_FLEX_EXTRA_LEAD_TICKS;
	}
	for (uint8_t i = 0; m->plan && i < m->plan->n_slots && i < TDMA_LC_SLOTS; i++) {
		const struct tdma_slot *si_ = &m->plan->slots[i];

		c->fidx[i] = flex_idx(m->plan, i);
		c->slead[i] = sec_lead_calc(m, si_);
		/*
		 * Short TX slots with a measured build + seal cost below the lead
		 * (cfg): the PT's own UL slot (not a contention slot: LBT), the
		 * FT's DL bursts but the beacon.
		 */
		if (pos >= 0 && si_->use == TDMA_SLOT_UL && si_->pos == pos) {
			/*
			 * (a relay: half, Its MAC thread also serves the child
			 * cluster, and its UL right after the parent's DL burst reached
			 * the PHY only 516-547 us ahead at times: 0x1005 on the DKs)
			 */
			c->trim[i] = m->cfg.relay ? c->ul_trim / 2u : c->ul_trim;
		} else if (!is_pt(m) && si_->use == TDMA_SLOT_DL) {
			c->trim[i] = c->dl_trim;
		} else {
			c->trim[i] = 0;
		}
		if (c->trim[i] > TDMA_COMMIT_LEAD_TICKS / 2) {
			c->trim[i] = TDMA_COMMIT_LEAD_TICKS / 2;
		}
		if (is_flex(&m->plan->slots[i]) && c->n_flex < TDMA_FLEX_SLOTS) {
			c->fslot[c->n_flex++] = i;
		}
	}
	c->valid = true;
	c->gen++;
	return c;
}

static bool sec_hints(const struct tdma_mac *m)
{
	return lc(m)->hints;
}

/* What the commit lead of a short TX slot may be shorter than TDMA_COMMIT_LEAD_TICKS. */
static uint32_t lead_trim(const struct tdma_mac *m, const struct tdma_slot *s)
{
	size_t i = (size_t)(s - m->plan->slots);

	return i < m->plan->n_slots && i < TDMA_LC_SLOTS ? lc(m)->trim[i] : 0;
}

static uint32_t sec_open_cost(const struct tdma_mac *m)
{
	return lc(m)->open_cost;
}

static uint32_t rx_clear_max(const struct tdma_mac *m)
{
	return lc(m)->clear_max;
}

static uint32_t sec_lead(const struct tdma_mac *m, const struct tdma_slot *s)
{
	const struct tdma_lead_cache *c = lc(m);
	size_t i = (size_t)(s - m->plan->slots);

	return i < m->plan->n_slots && i < TDMA_LC_SLOTS ? c->slead[i] : sec_lead_calc(m, s);
}

/* Index into m->flex of FLEX slot si of the plan in use. */
static uint8_t flex_i(const struct tdma_mac *m, uint8_t si)
{
	return si < TDMA_LC_SLOTS ? lc(m)->fidx[si] : flex_idx(m->plan, si);
}

/* A burst this node may receive in slot p (and then open). */
static bool may_rx(const struct tdma_mac *m, const struct tdma_slot *p)
{
	return is_flex(p) || (is_pt(m) ? is_dl(p) : is_ul(p));
}

/* Air end of what may be received in slot pi of frame f: a FLEX burst as granted, if known. */
static int64_t rx_end_rel(const struct tdma_mac *m, uint8_t pi, uint32_t f)
{
	const struct tdma_slot *p = &m->plan->slots[pi];
	uint32_t len = p->len;

	if (is_flex(p)) {
		const struct tdma_flex *g = &m->flex[flex_i(m, pi)];

		if (pat_plan(m->plan)) {
			len = t2_rx_len(m, pi, f);
		} else if (g->valid && g->frame == f && g->slot == pi) {
			len = (uint32_t)(g->len - g->early);
		} else if (relay_no_flex(m)) {
			len = 0;
		}
		for (int i = 0; i < TDMA_MAX_OPS; i++) {
			const struct tdma_op *op = &m->ops[i];

			if (op->used && !op->is_tx && op->use == TDMA_SLOT_FLEX && op->slot == pi &&
			    op->frame == f && op->plan == m->plan) {
				len = (uint32_t)(op->flex.len - op->flex.early);
			}
		}
	}
	return (int64_t)p->subslot * TDMA_SUBSLOT_TICKS + (int64_t)len * TDMA_SUBSLOT_TICKS;
}

/*
 * With a cost model, a received burst occupies the MAC for about
 * TDMA_RX_PROC_TICKS + 2 x the open cost after it ends (the PHY event, the
 * open, then its PDUs). A commit that falls into that window waits for it and
 * goes out late, so it is moved before the end of that burst instead (plan H:
 * a PT's UL slot, or its DL / beacon RX op, after a long DL burst; a granted
 * FLEX burst may end well before its region). Not for a FLEX region granted
 * in the burst right before it (no grant_ahead): its commit must follow that
 * burst.
 */
static uint32_t rx_clear(const struct tdma_mac *m, const struct tdma_slot *s, uint32_t frame,
			 uint32_t lead)
{
	const struct tdma_plan *pl = m->plan;
	uint8_t si = (uint8_t)(s - pl->slots), n = pl->n_slots;
	int64_t start = (int64_t)s->subslot * TDMA_SUBSLOT_TICKS;
	int64_t w = TDMA_RX_PROC_TICKS + 2 * (int64_t)sec_open_cost(m);

	if (!sec_hints(m) ||
	    (is_flex(s) && !m->cfg.grant_ahead && !pat_plan(pl) && !pt_ul_ahead(m, s, frame))) {
		return lead;
	}
	for (uint8_t k = 1; k < n; k++) {
		uint8_t pi = (uint8_t)((si + n - k) % n);
		const struct tdma_slot *p = &pl->slots[pi];
		bool prev = pi > si; /* in the frame before */
		int64_t end = rx_end_rel(m, pi, prev ? frame - 1 : frame) -
			      (prev ? (int64_t)TDMA_FRAME_TICKS : 0);
		int64_t d = start - end; /* p's end -> our start */

		if (d - w > (int64_t)lead) {
			break; /* p and everything before it is done before our commit */
		}
		if (!may_rx(m, p) || d <= 0 ||
		    (is_flex(p) && end == (int64_t)p->subslot * TDMA_SUBSLOT_TICKS -
						   (prev ? (int64_t)TDMA_FRAME_TICKS : 0))) {
			continue; /* (a pattern region we do not receive in) */
		}
		if ((int64_t)lead >= d) {
			/*
			 * Our commit is before p ends, but its seal runs into p's RX
			 * event; with only a trimmed lead left after the seal, the
			 * event's handling made the PHY call late (DKs: a PT in
			 * position 1 of T4 / H4, its UL slot 5 ss after the beacon
			 * burst, 0x1000 for ~0.6 % of its bursts under UL bulk). Then
			 * the seal goes before p's end.
			 */
			uint32_t seal = sec_lead(m, s);

			if (seal && (int64_t)lead < d + (int64_t)seal &&
			    lead - seal < TDMA_PHY_LEAD_TX_TICKS + TDMA_RX_PROC_TICKS) {
				lead = (uint32_t)d + seal + TDMA_RX_MARGIN_TICKS;
			}
			continue;
		}
		lead = (uint32_t)d + TDMA_RX_MARGIN_TICKS; /* commit just before p ends */
	}
	return lead;
}

/* Typical open time of a burst of n bytes (the seal model when no open model is given). */
static uint32_t open_typ(const struct tdma_mac *m, size_t bytes)
{
	const struct tdma_sec_ops *o = m->port.sec;

	if (!o->open_ticks_base && !o->open_ticks_per16) {
		return sec_cost(m, bytes);
	}
	return o->open_ticks_base + o->open_ticks_per16 * (uint32_t)((bytes + 15u) / 16u);
}

/*
 * FT, hybrid plans: whether a PT can verify the DL burst with the grant and
 * still commit the FLEX region right after it (by the cost model); if not,
 * FLEX regions are granted one DL period ahead.
 */
static bool sec_need_ahead(const struct tdma_mac *m)
{
	const struct tdma_plan *pl = m->plan;

	if (!sec_hints(m) || !m->flex_plan) {
		return false;
	}
	for (uint8_t f = 0; f < pl->n_slots; f++) {
		const struct tdma_slot *fs = &pl->slots[f];
		int64_t lead, end, win;
		int8_t g = -1;

		if (!is_flex(fs)) {
			continue;
		}
		for (int8_t j = (int8_t)f - 1; j >= 0; j--) {
			if (is_dl(&pl->slots[j])) {
				g = j;
				break;
			}
		}
		if (g < 0) {
			return true;
		}
		lead = TDMA_FLEX_COMMIT_LEAD_TICKS;
		if (sec_cost(m, TDMA_PKT_MAX) > TDMA_FLEX_EXTRA_LEAD_TICKS) {
			lead += sec_cost(m, TDMA_PKT_MAX) - TDMA_FLEX_EXTRA_LEAD_TICKS;
		}
		end = (int64_t)pl->slots[g].subslot * TDMA_SUBSLOT_TICKS + burst_air(&pl->slots[g]);
		win = (int64_t)fs->subslot * TDMA_SUBSLOT_TICKS - lead - end - TDMA_RX_PROC_TICKS;
		if ((int64_t)open_typ(m, tdma_tbs(m->mcs, pl->slots[g].len)) > win) {
			return true;
		}
	}
	return false;
}

static void sess_drop(struct tdma_mac *m, int8_t i)
{
	struct tdma_sec_sess *ss;

	if (i < 0) {
		return;
	}
	ss = &m->sec.sess[i];
	if (ss->valid) {
		m->port.sec->release(m->port.sec_ctx, ss->handle);
	}
	memset(ss, 0, sizeof(*ss));
	if (m->sec.cur == i) {
		m->sec.cur = -1;
	}
	if (m->sec.next == i) {
		m->sec.next = -1;
	}
	if (m->sec.prev == i) {
		m->sec.prev = -1;
	}
}

/* keep_cache: only forget which session is current (PT lost its FT). */
static void sec_reset(struct tdma_mac *m, bool keep_cache)
{
	if (!keep_cache) {
		for (int8_t i = 0; i < TDMA_SEC_SESS; i++) {
			sess_drop(m, i);
		}
	}
	m->sec.cur = m->sec.next = m->sec.prev = -1;
	m->sec.beacon_fail = 0;
}

static int8_t sess_find(const struct tdma_mac *m, uint8_t idx, uint32_t ft, uint32_t ctr,
			uint32_t rnd)
{
	for (int8_t i = 0; i < TDMA_SEC_SESS; i++) {
		const struct tdma_sec_sess *ss = &m->sec.sess[i];

		if (ss->valid && ss->idx == idx && ss->ft == ft && ss->ctr == ctr &&
		    ss->rnd == rnd) {
			return i;
		}
	}
	return -1;
}

/* Find or derive a session; *err = TDMA_ERR_NOKEY etc. when it cannot be derived. */
static int8_t sess_get(struct tdma_mac *m, uint8_t idx, uint32_t ft, uint32_t ctr, uint32_t rnd,
		       int *err)
{
	int8_t i = sess_find(m, idx, ft, ctr, rnd), victim = -1;
	uint32_t h = 0;
	int r;

	*err = 0;
	if (i >= 0) {
		m->sec.sess[i].used = ++m->sec.stamp;
		return i;
	}
	for (int8_t k = 0; k < TDMA_SEC_SESS; k++) {
		if (k == m->sec.cur || k == m->sec.next || k == m->sec.prev) {
			continue;
		}
		if (!m->sec.sess[k].valid) {
			victim = k;
			break;
		}
		if (victim < 0 || m->sec.sess[k].used < m->sec.sess[victim].used) {
			victim = k;
		}
	}
	if (victim < 0) {
		*err = -ENOMEM;
		return -1;
	}
	r = m->port.sec->derive(m->port.sec_ctx, idx, m->cfg.network_id, ft, ctr, rnd, &h);
	if (r || h == 0) {
		*err = r ? r : -EIO;
		m->stats.sec_no_key += r == TDMA_ERR_NOKEY;
		return -1;
	}
	sess_drop(m, victim);
	m->sec.sess[victim] = (struct tdma_sec_sess){.valid = true,
						     .idx = idx,
						     .ft = ft,
						     .ctr = ctr,
						     .rnd = rnd,
						     .handle = h,
						     .used = ++m->sec.stamp};
	m->stats.sec_derive++;
	return victim;
}

/* Session of the bursts of a frame: the announced one from its frame, the old one before. */
static int8_t sess_for_frame(const struct tdma_mac *m, uint32_t frame)
{
	if (m->sec.next >= 0 && (int32_t)(frame - m->sec.next_frame) >= 0) {
		return m->sec.next;
	}
	if (m->sec.prev >= 0 && (int32_t)(frame - m->sec.prev_switch) < 0) {
		return m->sec.prev;
	}
	return m->sec.cur;
}

static void sec_nonce(uint8_t n[TDMA_SEC_NONCE_LEN], uint32_t tx_rd, uint32_t frame, uint8_t ss)
{
	memset(n, 0, TDMA_SEC_NONCE_LEN);
	put_be32(n, tx_rd);
	put_be32(n + 4, frame);
	n[8] = ss;
}

/* AAD into m->sec.aad: PHY header fields, then sec_hdr + cleartext record from pkt. */
static size_t sec_aad(struct tdma_mac *m, const struct tdma_phy_hdr *h, const uint8_t *pkt,
		      size_t clear)
{
	uint8_t *a = m->sec.aad;

	a[0] = h->short_nwid;
	a[1] = (uint8_t)(h->tx_short >> 8);
	a[2] = (uint8_t)h->tx_short;
	a[3] = (uint8_t)(h->rx_short >> 8);
	a[4] = (uint8_t)h->rx_short;
	a[5] = h->subslots;
	a[6] = h->mcs;
	memcpy(a + 7, pkt, TDMA_SEC_HDR_LEN + clear);
	return 7 + TDMA_SEC_HDR_LEN + clear;
}

/* Is the first record of a plaintext packet one that goes in clear (beacon, association request)?
 */
static size_t clear_len(const uint8_t *pkt, size_t len)
{
	if (len < TDMA_REC_HDR_LEN + 2 || pkt[0] == 0 || pkt[1] != TDMA_ADDR_ALL ||
	    (size_t)pkt[0] + TDMA_REC_HDR_LEN > len) {
		return 0;
	}
	return pkt[2] == TDMA_PDU_BEACON || pkt[2] == TDMA_PDU_ASSOC_REQ
		       ? (size_t)pkt[0] + TDMA_REC_HDR_LEN
		       : 0;
}

/*
 * Seal m->pkt_buf[0..*len) (plaintext records) in place for the burst of
 * slot si in frame: the records move up by the header, the MIC follows.
 */
static int sec_seal(struct tdma_mac *m, uint8_t si, uint32_t frame, const struct tdma_phy_hdr *h,
		    size_t *len)
{
	int8_t i = sess_for_frame(m, frame);
	uint8_t *p = m->pkt_buf;
	size_t n = *len, clear = clear_len(p, n);
	uint8_t nonce[TDMA_SEC_NONCE_LEN];
	struct tdma_sec_hdr sh;
	size_t aad_len;

	if (i < 0) {
		return TDMA_ERR_NOKEY;
	}
	if (n - clear > TDMA_SEC_BODY_MAX || n + TDMA_SEC_OVERHEAD > sizeof(m->pkt_buf)) {
		return -EMSGSIZE;
	}
	memmove(p + TDMA_SEC_HDR_LEN, p, n);
	sh = (struct tdma_sec_hdr){.ver = TDMA_SEC_VERSION,
				   .key_idx = m->sec.sess[i].idx,
				   .clear = clear != 0,
				   .body_len = (uint16_t)(n - clear)};
	tdma_sec_hdr_encode(&sh, p);
	sec_nonce(nonce, m->cfg.rd_id, frame, m->plan->slots[si].subslot);
	aad_len = sec_aad(m, h, p, clear);
	if (m->port.sec->seal(m->port.sec_ctx, m->sec.sess[i].handle, nonce, m->sec.aad, aad_len,
			      p + TDMA_SEC_HDR_LEN + clear, n - clear, p + TDMA_SEC_HDR_LEN + n)) {
		return -EIO;
	}
	*len = n + TDMA_SEC_OVERHEAD;
	m->stats.sec_sealed++;
	return 0;
}

/* The beacon in the cleartext part of a packet (secured or, with security off, plain). */
static int clear_beacon(const struct tdma_mac *m, const uint8_t *pkt, size_t len,
			struct tdma_beacon *b)
{
	struct tdma_sec_hdr sh;

	if (!m->sec.on) {
		return beacon_of_pkt(pkt, len, b);
	}
	if (len < TDMA_SEC_OVERHEAD || tdma_sec_hdr_decode(pkt, &sh) || !sh.clear) {
		return -EINVAL;
	}
	return beacon_of_pkt(pkt + TDMA_SEC_HDR_LEN, len - TDMA_SEC_HDR_LEN, b);
}

/* MIC failure bookkeeping: counters, per-peer counts, the once-a-second alarm. */
static void sec_fail(struct tdma_mac *m, const struct tdma_phy_hdr *h, struct tdma_peer *p)
{
	uint64_t now = m->port.now(m->port.ctx);

	m->stats.sec_mic_fail++;
	m->sec.last_short = h->tx_short;
	if (p && p->sec_fail < 0xffff) {
		p->sec_fail++;
	}
	if (now - m->sec.win_t >= TDMA_TICKS_PER_SEC) {
		m->sec.win_t = now;
		m->sec.win_fail = 0;
		m->sec.win_alarmed = false;
	}
	if (++m->sec.win_fail >= CFGV(m, sec_alarm_fails, TDMA_DEF_SEC_ALARM_FAILS) &&
	    !m->sec.win_alarmed) {
		m->sec.win_alarmed = true;
		m->stats.sec_alarms++;
		emit_sec(m, TDMA_EVT_SEC_ALARM, h->tx_short, TDMA_CAUSE_NONE, m->sec.win_fail, 0);
	}
}

/* PT: what we accepted from an FT this boot (session counter, last frame); -1 = nothing. */
static int seen_find(struct tdma_mac *m, uint32_t ft, bool add)
{
	for (int i = 0; i < 4; i++) {
		if (m->sec.seen[i].ft == ft) {
			return i;
		}
	}
	if (!add) {
		return -1;
	}
	m->sec.seen_rr = (uint8_t)((m->sec.seen_rr + 1) % 4);
	m->sec.seen[m->sec.seen_rr].ft = ft;
	m->sec.seen[m->sec.seen_rr].ctr = 0;
	m->sec.seen[m->sec.seen_rr].frame = 0;
	return m->sec.seen_rr;
}

/* PT: session of a beacon (before verifying it); -1 with *err when not usable. */
static int8_t beacon_sess(struct tdma_mac *m, const struct tdma_beacon *b, int *err)
{
	int seen;

	*err = -EINVAL;
	if (!(b->flags & TDMA_F_BSEC)) {
		m->stats.sec_bad_hdr++;
		return -1;
	}
	if (!(b->sflags & TDMA_SF_DEVKEY) != !m->cfg.sec_devkey) {
		m->stats.sec_devkey++; /* dev and real networks never join */
		return -1;
	}
	seen = seen_find(m, b->ft_rd_id, false);
	if (seen >= 0 && b->sess_ctr < m->sec.seen[seen].ctr) {
		m->stats.sec_stale++; /* an older session of that FT: replayed */
		return -1;
	}
	return sess_get(m, b->key_idx, b->ft_rd_id, b->sess_ctr, b->sess_rand, err);
}

/*
 * PT: a verified beacon. Freshness (docs/mac-design.md "Link security"): the session
 * counter never goes back; within the current session the frame only goes
 * up and (once synced) stays within 2 of the predicted one. A higher session
 * counter is a genuine FT restart or switch (only the key holder can make
 * one) and is followed. Returns false when the beacon must be ignored.
 */
static bool beacon_fresh(struct tdma_mac *m, const struct tdma_op *op, const struct tdma_beacon *b,
			 int8_t si)
{
	int k = seen_find(m, b->ft_rd_id, true);
	uint32_t *seen = &m->sec.seen[k].ctr, *last = &m->sec.seen[k].frame;
	bool same = m->sec.cur == si;

	if (b->sess_ctr < *seen ||
	    /* the same session: frames only go up (a replay, even while searching) */
	    (b->sess_ctr == *seen && *seen && (int32_t)(b->frame - *last) <= 0)) {
		m->stats.sec_stale++;
		return false;
	}
	if (op->use == TDMA_SLOT_BEACON && same &&
	    ((int32_t)(b->frame - m->last_beacon_frame) <= 0 ||
	     (int32_t)(b->frame - op->frame) > 2 || (int32_t)(op->frame - b->frame) > 2)) {
		m->stats.sec_stale++;
		return false;
	}
	*seen = b->sess_ctr;
	*last = b->frame;
	return true;
}

/* PT: follow the verified beacon's session and its announced switch. */
static void beacon_adopt(struct tdma_mac *m, const struct tdma_beacon *b, int8_t si)
{
	int8_t old = m->sec.cur;

	if (m->sec.cur != si) {
		if (m->sec.next == si) {
			m->sec.next =
				-1; /* the switch we were told about (beacon of the switch frame) */
		}
		if (m->sec.prev == si) {
			m->sec.prev = -1;
		}
		m->sec.cur = si;
		if (old < 0 || m->sec.sess[old].idx != m->sec.sess[si].idx) {
			m->stats.sec_switches += old >= 0;
			emit_sec(m, TDMA_EVT_KEY_SWITCH, b->ft_rd_id, TDMA_CAUSE_NONE,
				 m->sec.sess[si].idx, b->frame);
		}
	}
	if ((b->sflags & TDMA_SF_NEXT) && (int32_t)(b->next_frame - b->frame) > 0) {
		uint8_t nidx = (uint8_t)((b->sflags >> TDMA_SF_NEXT_IDX_SHIFT) & 3u);
		int err;

		if (m->sec.next >= 0) {
			const struct tdma_sec_sess *n = &m->sec.sess[m->sec.next];

			if (n->idx == nidx && n->ctr == b->next_ctr && n->rnd == b->next_rand &&
			    m->sec.next_frame == b->next_frame) {
				return; /* already known */
			}
		}
		int8_t ni = sess_get(m, nidx, b->ft_rd_id, b->next_ctr, b->next_rand, &err);

		if (ni >= 0) {
			m->sec.next = ni;
			m->sec.next_frame = b->next_frame;
			emit_sec(m, TDMA_EVT_KEY_ANNOUNCE, b->ft_rd_id, TDMA_CAUSE_NONE, nidx,
				 b->next_frame);
		}
		/* TDMA_ERR_NOKEY: we lack the next key; from the switch on, beacons fail ->
		 * LOST(KEY) */
	}
}

/*
 * Verify and decrypt a received burst; on success *pl / *len are the
 * plaintext records (cleartext record first). Nothing of a burst is used
 * before this returns 0.
 */
static void pt_lose(struct tdma_mac *m, enum tdma_cause cause);
static int ft_slot_of(const struct tdma_mac *m, const struct tdma_op *op, uint64_t rx_start);

static int sec_rx(struct tdma_mac *m, struct tdma_op *op, const struct tdma_phy_hdr *h,
		  const uint8_t **pl, size_t *len, uint64_t rx_start)
{
	const uint8_t *in = *pl;
	size_t n = *len, clear = 0;
	struct tdma_sec_hdr sh;
	struct tdma_beacon b;
	bool have_b = false, pt_beacon_slot = false;
	uint32_t tx_rd = 0, frame = op->frame;
	uint8_t subslot = 0;
	int8_t si = -1;
	struct tdma_peer *peer = NULL;
	uint8_t nonce[TDMA_SEC_NONCE_LEN];
	size_t aad_len;
	int err = 0;

	if (n < TDMA_SEC_OVERHEAD || tdma_sec_hdr_decode(in, &sh)) {
		m->stats.sec_bad_hdr++;
		return -EINVAL;
	}
	if (sh.clear) {
		clear = (size_t)in[TDMA_SEC_HDR_LEN] + TDMA_REC_HDR_LEN;
		if (in[TDMA_SEC_HDR_LEN] == 0) {
			m->stats.sec_bad_hdr++;
			return -EINVAL;
		}
	}
	if (TDMA_SEC_HDR_LEN + clear + sh.body_len + TDMA_SEC_MIC_LEN > n) {
		m->stats.sec_bad_hdr++;
		return -EINVAL;
	}
	if (clear && in[TDMA_SEC_HDR_LEN + 1] == TDMA_ADDR_ALL &&
	    tdma_beacon_decode(in + TDMA_SEC_HDR_LEN + TDMA_REC_HDR_LEN, clear - TDMA_REC_HDR_LEN,
			       &b) == 0) {
		have_b = true;
	}

	/* who sent it, in which frame and subslot, under which session */
	if (op->use == USE_SEARCH) {
		const struct tdma_plan *plan;

		if (!have_b || b.network_id != m->cfg.network_id ||
		    h->rx_short != TDMA_SHORT_BROADCAST ||
		    tdma_short_rd(b.ft_rd_id) != h->tx_short ||
		    !(plan = tdma_plan_get(b.plan_id))) {
			return -EINVAL; /* not a beacon of ours: ignored, as without security */
		}
		tx_rd = b.ft_rd_id;
		frame = b.frame;
		subslot = plan->slots[0].subslot;
		si = beacon_sess(m, &b, &err);
	} else if (is_pt(m)) {
		tx_rd = m->parent_rd;
		subslot = op->plan->slots[op->slot].subslot;
		pt_beacon_slot = op->use == TDMA_SLOT_BEACON;
		if (pt_beacon_slot) {
			if (!have_b || b.ft_rd_id != m->parent_rd) {
				return -EINVAL; /* someone else's FT on our channel */
			}
			frame = b.frame;
			si = beacon_sess(m, &b, &err);
		} else if (h->tx_short != tdma_short_rd(m->parent_rd)) {
			/*
			 * another cluster's burst in our DL slot (a three-hop chain:
			 * the depth-2 child's UL on our parent's carrier) is not a MIC
			 * failure of our FT's: ignored like a beacon of someone else's FT.
			 */
			m->stats.sec_foreign++;
			return -EINVAL;
		} else {
			si = sess_for_frame(m, frame);
		}
	} else if (op->use == TDMA_SLOT_FLEX) {
		tx_rd = op->owners[op->flex.pos];
		subslot = op->plan->slots[op->slot].subslot;
		peer = &m->peers[op->flex.pos];
		si = sess_for_frame(m, frame);
	} else {
		int slot = ft_slot_of(m, op, rx_start);
		const struct tdma_slot *s;
		struct tdma_assoc_req req;

		if (slot < 0) {
			m->stats.bad_rx++;
			return -EINVAL;
		}
		s = &op->plan->slots[slot];
		subslot = s->subslot;
		if (clear && in[TDMA_SEC_HDR_LEN + 2] == TDMA_PDU_ASSOC_REQ &&
		    tdma_assoc_decode(in + TDMA_SEC_HDR_LEN + TDMA_REC_HDR_LEN,
				      clear - TDMA_REC_HDR_LEN, &req) == 0 &&
		    tdma_short_rd(req.pt_rd_id) == h->tx_short) {
			tx_rd = req.pt_rd_id;
		} else if (s->use == TDMA_SLOT_UL && op->owners[s->pos] &&
			   tdma_short_rd(op->owners[s->pos]) == h->tx_short) {
			tx_rd = op->owners[s->pos];
			peer = &m->peers[s->pos];
		} else if (s->use == TDMA_SLOT_UL && op->owners[s->pos]) {
			m->stats.sec_foreign++; /* another cluster's burst in that PT's UL slot */
			return -EINVAL;
		} else {
			m->stats.bad_rx++;
			return -EINVAL;
		}
		si = sess_for_frame(m, frame);
	}
	if (si < 0) {
		if (pt_beacon_slot && err == TDMA_ERR_NOKEY &&
		    ++m->sec.beacon_fail >= CFGV(m, sec_beacon_fail, TDMA_DEF_SEC_BEACON_FAIL)) {
			pt_lose(m, TDMA_CAUSE_KEY);
		}
		if (si < 0 && err == 0) {
			m->stats.sec_no_key++;
		}
		return TDMA_ERR_NOKEY;
	}
	if (sh.key_idx != m->sec.sess[si].idx) {
		m->stats.sec_no_key++;
		return TDMA_ERR_NOKEY;
	}

	memcpy(m->rx_buf, in, TDMA_SEC_HDR_LEN + clear + sh.body_len + TDMA_SEC_MIC_LEN);
	sec_nonce(nonce, tx_rd, frame, subslot);
	aad_len = sec_aad(m, h, m->rx_buf, clear);
	err = m->port.sec->open(m->port.sec_ctx, m->sec.sess[si].handle, nonce, m->sec.aad, aad_len,
				m->rx_buf + TDMA_SEC_HDR_LEN + clear, sh.body_len,
				m->rx_buf + TDMA_SEC_HDR_LEN + clear + sh.body_len);
	if (err && !is_pt(m) && m->sec.prev >= 0 && si != m->sec.prev &&
	    (int32_t)(frame - m->sec.prev_until) < 0 &&
	    m->sec.sess[m->sec.prev].idx == sh.key_idx) {
		/* FT, just after a switch: a PT that missed it still seals with the old key */
		memcpy(m->rx_buf, in, TDMA_SEC_HDR_LEN + clear + sh.body_len + TDMA_SEC_MIC_LEN);
		err = m->port.sec->open(m->port.sec_ctx, m->sec.sess[m->sec.prev].handle, nonce,
					m->sec.aad, aad_len, m->rx_buf + TDMA_SEC_HDR_LEN + clear,
					sh.body_len,
					m->rx_buf + TDMA_SEC_HDR_LEN + clear + sh.body_len);
	}
	if (err) {
		if (clear && in[TDMA_SEC_HDR_LEN + 2] == TDMA_PDU_ASSOC_REQ) {
			m->stats.sec_assoc_reject++;
		}
		sec_fail(m, h, peer);
		if (pt_beacon_slot &&
		    ++m->sec.beacon_fail >= CFGV(m, sec_beacon_fail, TDMA_DEF_SEC_BEACON_FAIL)) {
			pt_lose(m, TDMA_CAUSE_KEY);
		}
		return -EBADMSG;
	}
	if (have_b && (op->use == USE_SEARCH || pt_beacon_slot)) {
		if (!beacon_fresh(m, op, &b, si)) {
			return -EINVAL;
		}
		m->sec.beacon_fail = 0;
		beacon_adopt(m, &b, si);
	}
	m->stats.sec_opened++;
	*pl = m->rx_buf + TDMA_SEC_HDR_LEN;
	*len = clear + sh.body_len;
	return 0;
}

/* FT: start of the network: our first session on the active key. */
static int sec_ft_start(struct tdma_mac *m)
{
	uint8_t act = 0, nxt = TDMA_SEC_NO_KEY;
	int8_t i;
	int err;

	sec_reset(m, false);
	if (m->port.sec->key_state(m->port.sec_ctx, &act, &nxt) || act > 3) {
		return TDMA_ERR_NOKEY;
	}
	i = sess_get(m, act, m->cfg.rd_id, m->cfg.sess_ctr ? m->cfg.sess_ctr : 1,
		     m->port.sec->random(m->port.sec_ctx), &err);
	if (i < 0) {
		return err ? err : TDMA_ERR_NOKEY;
	}
	m->sec.cur = i;
	m->sec.sess_start = m->cfg.start_frame;
	emit_sec(m, TDMA_EVT_KEY_SWITCH, m->cfg.rd_id, TDMA_CAUSE_NONE, act, m->cfg.start_frame);
	return 0;
}

/*
 * FT, per beacon: start an announced switch when the platform wants another
 * key index, or the session is about to use up its frame counter space.
 */
static void sec_ft_poll(struct tdma_mac *m, uint32_t frame)
{
	const struct tdma_sec_sess *c;
	uint8_t act = TDMA_SEC_NO_KEY, nxt = TDMA_SEC_NO_KEY, want;
	uint32_t ann = CFGV(m, sec_announce_frames, TDMA_DEF_SEC_ANNOUNCE_FRAMES);
	uint32_t life = CFGV(m, sec_session_frames, TDMA_DEF_SEC_SESSION_FRAMES);
	bool rollover;
	int8_t i;
	int err;

	if (m->sec.cur < 0 || m->sec.next >= 0 || m->sec.prev >= 0) {
		return;
	}
	c = &m->sec.sess[m->sec.cur];
	if (m->port.sec->key_state(m->port.sec_ctx, &act, &nxt)) {
		return;
	}
	want = nxt <= 3 && nxt != c->idx ? nxt : act <= 3 ? act : c->idx;
	rollover = frame - m->sec.sess_start + ann + 2u >= life;
	if (want == c->idx && !rollover) {
		return;
	}
	i = sess_get(m, want, m->cfg.rd_id, c->ctr + 1u, m->port.sec->random(m->port.sec_ctx),
		     &err);
	if (i < 0) {
		return;
	}
	m->sec.next = i;
	m->sec.next_frame = frame + ann;
	emit_sec(m, TDMA_EVT_KEY_ANNOUNCE, m->cfg.rd_id, TDMA_CAUSE_NONE, want, m->sec.next_frame);
}

/* FT: the security extension of the beacon of frame. */
static void sec_ft_beacon(struct tdma_mac *m, uint32_t frame, struct tdma_beacon *b)
{
	int8_t i = sess_for_frame(m, frame);

	if (i < 0) {
		return;
	}
	b->flags |= TDMA_F_BSEC;
	b->sess_ctr = m->sec.sess[i].ctr;
	b->sess_rand = m->sec.sess[i].rnd;
	b->key_idx = m->sec.sess[i].idx;
	b->sflags = m->cfg.sec_devkey ? TDMA_SF_DEVKEY : 0;
	if (m->sec.next >= 0 && i != m->sec.next) {
		const struct tdma_sec_sess *n = &m->sec.sess[m->sec.next];

		b->sflags |= (uint8_t)(TDMA_SF_NEXT | (n->idx << TDMA_SF_NEXT_IDX_SHIFT));
		b->next_frame = m->sec.next_frame;
		b->next_ctr = n->ctr;
		b->next_rand = n->rnd;
	}
}

/* Both roles, at the commit of each slot: switch sessions at the announced frame. */
static void sec_tick(struct tdma_mac *m, uint32_t frame)
{
	if (m->sec.prev >= 0 && (int32_t)(frame - m->sec.prev_until) >= 0 && m->sec.next < 0) {
		sess_drop(m, m->sec.prev);
	}
	if (m->sec.next >= 0 && (int32_t)(frame - m->sec.next_frame) >= 0) {
		int8_t old = m->sec.cur;
		uint8_t idx = m->sec.sess[m->sec.next].idx;
		bool new_idx = old < 0 || m->sec.sess[old].idx != idx;

		if (m->sec.prev >= 0 && m->sec.prev != old) {
			sess_drop(m, m->sec.prev);
		}
		m->sec.prev = old;
		m->sec.prev_switch = m->sec.next_frame;
		m->sec.prev_until =
			m->sec.next_frame + 10u; /* FT: UL under the old key a little longer */
		m->sec.cur = m->sec.next;
		m->sec.next = -1;
		m->sec.sess_start = m->sec.next_frame;
		m->stats.sec_switches++;
		if (new_idx || !is_pt(m)) {
			emit_sec(m, TDMA_EVT_KEY_SWITCH, is_pt(m) ? m->parent_rd : m->cfg.rd_id,
				 TDMA_CAUSE_NONE, idx, frame);
		}
	}
}

static bool sec_denied(const struct tdma_mac *m, uint32_t rd)
{
	for (uint8_t i = 0; i < m->sec.n_deny; i++) {
		if (m->sec.deny[i] == rd) {
			return true;
		}
	}
	return false;
}

/* ---- platform -> MAC --------------------------------------------------------------- */

static void deliver(void *ctx, const uint8_t *data, size_t len)
{
	struct deliver_ctx *d = ctx;

	if (d->m->state == TDMA_ST_FT && len > link_mtu(&d->p->link)) {
		d->p->reply_hint = true; /* a bulk SDU: its answer may be bulk too */
	}
	if (d->m->state == TDMA_ST_FT) {
		d->p->dem_acc[1] += (uint32_t)len;
	}
	d->m->port.deliver(d->m->port.ctx, d->src, data, len);
}

/* Data or ack-only from a peer in its own burst. Returns false if malformed. */
static bool link_rx(struct tdma_mac *m, struct tdma_peer *p, const uint8_t *pdu, size_t len,
		    uint64_t rx_start)
{
	struct link_params lp = link_params(m);
	struct deliver_ctx dc = {m, p->rd_id, p};
	struct tdma_data d;
	struct tdma_ack a;

	switch (tdma_pdu_type(pdu, len)) {
	case TDMA_PDU_DATA:
		if (tdma_data_decode(pdu, len, &d)) {
			return false;
		}
		link_rx_ack(&p->link, &lp, &d.ack, rx_start, &m->stats);
		trace_pdu(m, TDMA_TRACE_RX, p->rd_id, pdu, len, rx_start);
		link_rx_data(&p->link, m->ras, m->n_ras, (uint8_t)(p - m->peers + 1), &d, rx_start,
			     deliver, &dc, &m->stats);
		return true;
	case TDMA_PDU_ACK:
		if (tdma_ack_decode(pdu, len, &a)) {
			return false;
		}
		link_rx_ack(&p->link, &lp, &a, rx_start, &m->stats);
		return true;
	default:
		return false;
	}
}

/* PT: keep the grants for our position (for FLEX regions later in this frame). */
static bool pt_grant(struct tdma_mac *m, const struct tdma_op *op, const uint8_t *pdu, size_t len)
{
	struct tdma_grant g;

	if (tdma_grant_decode(pdu, len, &g)) {
		return false;
	}
	for (uint8_t i = 0; i < g.n; i++) {
		const struct tdma_grant_entry *e = &g.e[i];

		uint32_t gframe = op->frame;
		uint8_t from = (uint8_t)(op->slot + 1);

		if (e->flags & TDMA_GRANT_F_NEXT) {
			/* pattern plans: the pattern of the next frame (plan id + 1 in len) */
			struct tdma_t2 *t = &m->t2[(op->frame + 1u) & 1u];
			const struct tdma_plan *np = tdma_plan_get((uint8_t)(e->len - 1u));

			if (!pat_plan(np) || e->start >= np->n_pat) {
				return false;
			}
			if (!t->valid || t->frame != op->frame + 1u) {
				*t = (struct tdma_t2){.valid = true,
						      .frame = op->frame + 1u,
						      .plan = np->id,
						      .pat = e->start,
						      .pos = e->pos,
						      .mcs_dl = e->mcs,
						      .mcs_ul = e->mcs};
				if (e->pos == (uint8_t)m->my_pos) {
					m->stats.pat_frames[pat_stat_i(np->id)][e->start]++;
				}
			}
			if (e->flags & TDMA_GRANT_F_UL) {
				t->mcs_ul = e->mcs;
			} else {
				t->mcs_dl = e->mcs;
			}
			continue;
		}
		if (e->pos != (uint8_t)m->my_pos) {
			continue;
		}
		if (e->flags & TDMA_GRANT_F_AHEAD) {
			/* the FLEX region after the next DL burst */
			uint32_t wrap = 0;
			int fa = flex_ahead(m->plan, op->slot, &wrap);

			if (fa < 0) {
				continue;
			}
			gframe += wrap;
			from = (uint8_t)fa;
		}
		for (uint8_t j = from; j < m->plan->n_slots; j++) {
			const struct tdma_slot *fs = &m->plan->slots[j];

			bool ul = (e->flags & TDMA_GRANT_F_UL) != 0;
			bool ahead = (e->flags & TDMA_GRANT_F_AHEAD) != 0;

			if (!is_flex(fs) ||
			    fs->subslot - flex_early(m->plan, j, ul, ahead) != e->start) {
				continue;
			}
			if (e->len > flex_max_len(m->plan, j, ul, ahead) ||
			    len_cap(m, e->mcs, e->len) <= TDMA_STATUS_REC_LEN) {
				return false;
			}
			struct tdma_flex *f = &m->flex[flex_i(m, j)];

			*f = (struct tdma_flex){
				.valid = true,
				.ul = ul,
				.spec = (e->flags & TDMA_GRANT_F_SPEC) != 0,
				.slot = j,
				.pos = e->pos,
				.len = e->len,
				.mcs = e->mcs,
				.early = flex_early(m->plan, j, ul, ahead),
				.ahead = ahead && ul,
				.frame = gframe,
			};
			/*
			 * An early burst is committed before the DL burst in front of
			 * it, i.e. without the acks that one brings: worth it when
			 * bulk fragments fill it anyway. Else send it late, in the
			 * region's own extent (the FT listens from the early start).
			 */
			if (f->ahead && f->early) {
				if (m->cfg.grant_ahead || link_bulk_ready(&m->peers[0].link) >=
								  len_cap(m, e->mcs, e->len)) {
					f->early_commit = true;
				} else {
					f->early = 0;
					f->len = e->len < fs->len ? e->len : fs->len;
				}
			}
			break;
		}
	}
	return true;
}

/* Records of a DL burst addressed to our position, and grants. */
static bool pt_dl_records(struct tdma_mac *m, const struct tdma_op *op, const uint8_t *pkt,
			  size_t len, uint64_t rx_start)
{
	size_t off = 0, plen;
	const uint8_t *pdu;
	uint8_t addr;
	int r;

	while ((r = tdma_rec_next(pkt, len, &off, &addr, &pdu, &plen)) == 1) {
		if (m->state != TDMA_ST_ASSOCIATED) {
			continue;
		}
		if (addr == TDMA_ADDR_ALL) {
			if (tdma_pdu_type(pdu, plen) == TDMA_PDU_GRANT && m->flex_plan &&
			    op->use != TDMA_SLOT_FLEX && !pt_grant(m, op, pdu, plen)) {
				return false;
			}
			continue; /* the beacon */
		}
		if (addr != (uint8_t)m->my_pos) {
			continue; /* another PT's PDU */
		}
		if (!link_rx(m, &m->peers[0], pdu, plen, rx_start)) {
			return false;
		}
	}
	return r == 0;
}

/*
 * PT: a verified (link security) burst from the FT in a slot other than the
 * beacon's: the FT is there (pt_sync_gone()). A DL slot's burst starts at the
 * slot like the beacon at subslot 0, so it also corrects the frame timing
 * when beacons are missed (a few us of clock drift per 100 ms).
 */
static void pt_ft_burst(struct tdma_mac *m, const struct tdma_op *op, uint64_t rx_start)
{
	const struct tdma_slot *s;
	uint64_t want;
	int64_t d;

	if ((int32_t)(op->frame - m->last_ft_frame) > 0) {
		m->last_ft_frame = op->frame;
	}
	if (op->use != TDMA_SLOT_DL || op->plan != m->plan || op->slot >= m->plan->n_slots ||
	    (int32_t)(op->frame - m->last_beacon_frame) <= 1) {
		return;
	}
	s = &m->plan->slots[op->slot];
	want = slot_start(m, op->frame, s);
	d = (int64_t)(rx_start - want);
	if (d > -(int64_t)TDMA_US_TO_TICKS(30) && d < (int64_t)TDMA_US_TO_TICKS(30)) {
		m->ref_start = (uint64_t)((int64_t)m->ref_start + d);
		m->stats.dl_resync++;
	}
}

static void pt_rx(struct tdma_mac *m, struct tdma_op *op, const struct tdma_phy_hdr *h,
		  const uint8_t *pkt, size_t len, uint64_t rx_start, int16_t rssi, int16_t snr_q2)
{
	struct tdma_beacon b;
	uint16_t want_rx =
		op->use == TDMA_SLOT_FLEX ? tdma_short_rd(m->cfg.rd_id) : TDMA_SHORT_BROADCAST;

	if (h->tx_short != tdma_short_rd(m->parent_rd) || h->rx_short != want_rx) {
		m->stats.bad_rx++;
		return;
	}
	{
		uint8_t n = m->dl_snr_valid ? 1 : 0;

		snr_avg(&m->dl_snr_q4, &n, snr_q2);
		m->dl_snr_valid = true;
		m->dl_rssi = (int8_t)(rssi < -128 ? -128 : rssi > 127 ? 127 : rssi);
	}
	if (op->use == TDMA_SLOT_FLEX) {
		m->stats.flex_rx++;
	}
	if (op->use == TDMA_SLOT_BEACON) {
		if (beacon_of_pkt(pkt, len, &b) || b.network_id != m->cfg.network_id) {
			m->stats.bad_rx++;
			return;
		}
		m->parent_tx_power = h->tx_power;
		pt_beacon(m, op, &b, rx_start, rssi);
		if (!scheduling(m)) {
			return;
		}
	}
	if (!pt_dl_records(m, op, pkt, len, rx_start)) {
		m->stats.bad_rx++;
		return;
	}
	if (m->sec.on && op->use != TDMA_SLOT_BEACON && m->state == TDMA_ST_ASSOCIATED) {
		pt_ft_burst(m, op, rx_start);
	}
}

/* FT: an UL burst from p was received with this SNR: per-link UL MCS. */
static void ft_ul_quality(struct tdma_mac *m, struct tdma_peer *p, int16_t snr_q2)
{
	uint8_t old = p->mcs_ul;

	snr_avg(&p->ul_snr_q4, &p->n_ul_snr, snr_q2);
	if (p->n_ul_snr >= 4) {
		p->mcs_ul = tdma_mcs_select(p->mcs_ul, (int16_t)(p->ul_snr_q4 / 4), 4);
	}
	m->stats.mcs_changes += p->mcs_ul != old;
}

/* FT: a status record from p (in a burst starting at rx_start). */
static void ft_status(struct tdma_mac *m, struct tdma_peer *p, const struct tdma_status *st,
		      uint64_t rx_start)
{
	uint8_t old = p->mcs_dl;

	/* a PT that starts / stops its child cluster (tdma_pt_set_relay) */
	p->relay = (st->flags & TDMA_STF_RELAY) != 0;
	p->hgx_ok = p->relay && (st->flags & TDMA_STF_HGX) != 0;
	if (rx_start >= p->bsr_t) {
		p->bsr = st->queued;
		p->bsr_t = rx_start;
		if (st->queued < TDMA_PKT_MAX) {
			p->ul_full = false; /* its backlog is gone (plan_auto) */
		}
	}
	p->dl_rssi = st->rssi;
	if (st->snr != TDMA_SNR_UNKNOWN) {
		snr_avg(&p->dl_snr_q4, &p->n_dl_snr, (int16_t)(st->snr * 4));
		if (p->n_dl_snr >= 4) {
			p->mcs_dl = tdma_mcs_select(p->mcs_dl, (int16_t)(p->dl_snr_q4 / 4), 4);
		}
	}
	m->stats.mcs_changes += p->mcs_dl != old;
}

/* FT: the records of an UL burst from position pos. False if malformed. */
static bool ft_ul_records(struct tdma_mac *m, struct tdma_peer *p, uint8_t pos, const uint8_t *pkt,
			  size_t len, uint64_t rx_start)
{
	size_t off = 0, plen;
	const uint8_t *pdu;
	uint8_t addr;
	int r;

	while ((r = tdma_rec_next(pkt, len, &off, &addr, &pdu, &plen)) == 1) {
		struct tdma_status st;

		if (addr != pos) {
			return false;
		}
		if (tdma_pdu_type(pdu, plen) == TDMA_PDU_STATUS) {
			if (tdma_status_decode(pdu, plen, &st)) {
				return false;
			}
			ft_status(m, p, &st, rx_start);
		} else if (!link_rx(m, p, pdu, plen, rx_start)) {
			return false;
		}
	}
	return r == 0;
}

/* FT: the long burst of an UL grant. */
static void ft_rx_flex(struct tdma_mac *m, struct tdma_op *op, const struct tdma_phy_hdr *h,
		       const uint8_t *pkt, size_t len, uint64_t rx_start, int16_t snr_q2)
{
	uint8_t pos = op->flex.pos;
	struct tdma_peer *p = &m->peers[pos];
	uint64_t want = op->start;

	if (!op->flex.ul || !op->owners[pos] || p->rd_id != op->owners[pos] ||
	    h->tx_short != tdma_short_rd(p->rd_id) || h->rx_short != tdma_short_rd(m->cfg.rd_id) ||
	    rx_start + TDMA_SUBSLOT_TICKS / 2 < want ||
	    rx_start >=
		    want + (uint64_t)op->flex.early * TDMA_SUBSLOT_TICKS + TDMA_SUBSLOT_TICKS / 2 ||
	    !ft_ul_records(m, p, pos, pkt, len, rx_start)) {
		m->stats.bad_rx++;
		return;
	}
	op->got |= 1u << pos;
	m->stats.flex_rx++;
	p->flex_fail = 0;
	/* bulk SDUs (a fragment longer than a short record): worth an UL grant a period ahead */
	p->ul_bulk = false;
	{
		size_t off = 0, plen;
		const uint8_t *pdu;
		uint8_t addr;

		while (tdma_rec_next(pkt, len, &off, &addr, &pdu, &plen) == 1) {
			p->ul_bulk |= plen > TDMA_REC_SHORT_MAX &&
				      tdma_pdu_type(pdu, plen) == TDMA_PDU_DATA;
		}
		/* ... filled the burst it sent and has a backlog left: the PT is in bulk */
		p->ul_full = p->ul_bulk && p->bsr >= TDMA_PKT_MAX &&
			     off + TDMA_PKT_MAX / 8u >= len_cap(m, h->mcs, h->subslots);
	}
	ft_ul_quality(m, p, snr_q2);
}

/* Which slot of an FT UL run a packet starting at rx_start belongs to. */
static int ft_slot_of(const struct tdma_mac *m, const struct tdma_op *op, uint64_t rx_start)
{
	for (uint8_t i = op->slot; i <= op->slot_end; i++) {
		uint64_t st = slot_start(m, op->frame, &op->plan->slots[i]);

		if (rx_start + TDMA_SUBSLOT_TICKS / 2 >= st &&
		    rx_start < st + TDMA_SUBSLOT_TICKS / 2) {
			return i;
		}
	}
	return -1;
}

static void ft_rx(struct tdma_mac *m, struct tdma_op *op, const struct tdma_phy_hdr *h,
		  const uint8_t *pkt, size_t len, uint64_t rx_start, int16_t rssi, int16_t snr_q2)
{
	int si = ft_slot_of(m, op, rx_start);
	const struct tdma_slot *s;
	size_t off = 0, plen;
	const uint8_t *pdu;
	uint8_t addr;
	int r;

	if (si < 0 || h->rx_short != tdma_short_rd(m->cfg.rd_id)) {
		m->stats.bad_rx++;
		return;
	}
	s = &op->plan->slots[si];
	while ((r = tdma_rec_next(pkt, len, &off, &addr, &pdu, &plen)) == 1) {
		struct tdma_assoc_req req;

		if (tdma_pdu_type(pdu, plen) == TDMA_PDU_ASSOC_REQ) {
			struct tdma_peer *p = &m->peers[s->pos];

			/* contention slot, a free UL slot, or the PT's own old one */
			if (addr != TDMA_ADDR_ALL || tdma_assoc_decode(pdu, plen, &req) ||
			    tdma_short_rd(req.pt_rd_id) != h->tx_short ||
			    (s->use == TDMA_SLOT_UL && p->rd_id &&
			     !open_slot(op->plan, s, op->frame) &&
			     tdma_short_rd(p->rd_id) != h->tx_short)) {
				m->stats.bad_rx++;
				return;
			}
			ft_assoc(m, &req, rssi);
			continue;
		}
		if (s->use != TDMA_SLOT_UL || addr != s->pos) {
			m->stats.bad_rx++;
			return;
		}
		struct tdma_peer *p = &m->peers[s->pos];
		struct tdma_status st;

		if (!op->owners[s->pos] || p->rd_id != op->owners[s->pos] ||
		    h->tx_short != tdma_short_rd(p->rd_id)) {
			m->stats.bad_rx++;
			return;
		}
		if (tdma_pdu_type(pdu, plen) == TDMA_PDU_STATUS) {
			if (tdma_status_decode(pdu, plen, &st)) {
				m->stats.bad_rx++;
				return;
			}
			ft_status(m, p, &st, rx_start);
		} else if (!link_rx(m, p, pdu, plen, rx_start)) {
			m->stats.bad_rx++;
			return;
		}
		if (!(op->got & (1u << s->pos))) {
			p->ul_rssi = (int8_t)(rssi < -128 ? -128 : rssi > 127 ? 127 : rssi);
			ft_ul_quality(m, p, snr_q2);
		}
		op->got |= 1u << s->pos;
		p->ul_miss = 0;
		p->ul_missed_last = false;
	}
	if (r < 0) {
		m->stats.bad_rx++;
	}
}

void tdma_on_rx(struct tdma_mac *m, uint32_t handle, uint64_t rx_start_time, int16_t rssi,
		int16_t snr_q2, const uint8_t *phy_hdr, size_t hdr_len, const uint8_t *payload,
		size_t len, bool crc_ok)
{
	struct tdma_op *op = op_find(m, handle);
	struct tdma_phy_hdr h;

	if (!op || op->is_tx || m->state == TDMA_ST_IDLE) {
		return;
	}
	if (op->use == USE_MEAS) {
		return;
	}
	if (op->use == USE_PROBE) {
		/* the backup's cluster: a burst its FT sent (the PHY header is enough: alive, how
		 * loud) */
		if (crc_ok && m->probe_valid && !m->probe_heard &&
		    tdma_phy_hdr_decode(phy_hdr, hdr_len, &h) == 0 &&
		    h.short_nwid == (uint8_t)m->cfg.network_id &&
		    h.tx_short == tdma_short_rd(m->probe_rd)) {
			m->probe_heard = true;
			m->probe_rssi = rssi;
			m->probe_snr = snr_q2;
		}
		return;
	}
	if (op->use == USE_SCAN) {
		if (crc_ok && payload && m->state == TDMA_ST_FT_SCAN) {
			ft_scan_rx(m, op, payload, len, rssi);
		}
		return;
	}
	if (op->use == USE_FTSCAN) {
		if (crc_ok && payload && m->fs_handle == op->handle) {
			fs_rx(m, phy_hdr, hdr_len, payload, len, rssi, snr_q2);
		}
		return;
	}
	if (!crc_ok || !payload || tdma_phy_hdr_decode(phy_hdr, hdr_len, &h) ||
	    h.short_nwid != (uint8_t)m->cfg.network_id) {
		m->stats.bad_rx++;
		return;
	}
	if (op->use != USE_SEARCH && !scheduling(m)) {
		return; /* a leftover slot op after we lost sync */
	}
	if (m->sec.on && sec_rx(m, op, &h, &payload, &len, rx_start_time)) {
		return;
	}
	if (op->use == USE_SEARCH) {
		pt_rx_search(m, op, &h, payload, len, rx_start_time, rssi, snr_q2);
	} else if (!scheduling(m)) {
		return; /* a leftover slot op after we lost sync */
	} else if (is_pt(m)) {
		pt_rx(m, op, &h, payload, len, rx_start_time, rssi, snr_q2);
	} else if (op->use == TDMA_SLOT_FLEX) {
		ft_rx_flex(m, op, &h, payload, len, rx_start_time, snr_q2);
	} else {
		ft_rx(m, op, &h, payload, len, rx_start_time, rssi, snr_q2);
	}
}

/* FT: an UL run ended; count missed bursts of the PTs that owned slots in it. */
static void ft_ul_done(struct tdma_mac *m, const struct tdma_op *op)
{
	for (uint8_t i = 0; i < m->plan->n_positions; i++) {
		struct tdma_peer *p = &m->peers[i];

		if (!op->owners[i] || (op->got & (1u << i)) || p->rd_id != op->owners[i]) {
			continue;
		}
		p->ul_missed_last = true;
		if (++p->ul_miss >= CFGV(m, ul_miss_max, TDMA_DEF_UL_MISS_MAX)) {
			ft_release(m, i, TDMA_CAUSE_UL_TIMEOUT);
		}
	}
}

void tdma_on_op_done(struct tdma_mac *m, uint32_t handle, int err)
{
	struct tdma_op *op = op_find(m, handle);

	if (!op) {
		return;
	}
	if (err && !(op->lbt && err == TDMA_ERR_LBT_BUSY)) {
		m->stats.port_errors++;
	}
	if (err && op->is_tx && scheduling(m)) {
		/* a failed burst's PDUs go again in our next one */
		for (uint8_t i = 0; i < (is_pt(m) ? 1u : m->plan->n_positions); i++) {
			if (m->peers[i].rd_id) {
				link_tx_failed(&m->peers[i].link, op->start);
			}
		}
	}
	if (op->use == USE_SEARCH) {
		m->search_handle = 0;
		if (ch_auto(m) && m->state == TDMA_ST_SEARCH) {
			for (uint8_t k = 0; k < ch_count(m); k++) {
				m->search_ch = m->search_ch >= m->cfg.ch_max
						       ? m->cfg.ch_min
						       : (uint16_t)(m->search_ch + 1);
				if (ch_usable(m, m->search_ch)) {
					break;
				}
			}
		}
	} else if (op->use == USE_SCAN) {
		m->search_handle = 0;
		m->scan_i++;
	} else if (op->use == USE_PROBE) {
		if (m->probe_valid && m->probe_handle == op->handle) {
			probe_end(m, m->probe_heard, m->probe_rssi, m->probe_snr);
		}
	} else if (op->use == USE_FTSCAN) {
		if (m->fs_valid && m->fs_handle == op->handle) {
			fs_end(m, err ? TDMA_CAUSE_STOPPED : TDMA_CAUSE_NONE);
		}
	} else if (op->use == USE_MEAS) {
		if (m->state == TDMA_ST_FT) {
			ft_mon_eval(m, op->frame);
		}
	} else if (op->is_tx && op->lbt) {
		if (m->state == TDMA_ST_FT) {
			ft_lbt_done(m, op, err);
		} else if (err == TDMA_ERR_LBT_BUSY && m->state == TDMA_ST_ASSOCIATING) {
			/* association request not sent: the channel was busy; back off again */
			m->stats.lbt_busy++;
			m->assoc_waiting = false;
			pt_new_backoff(m);
		}
	} else if (m->state == TDMA_ST_FT && !op->is_tx && op->use == TDMA_SLOT_FLEX && op->mon &&
		   !op->got && !op->heard && op->m_ss && ch_in_use(m, op->ch)) {
		/* an empty speculative UL region: a measurement of the own channel */
		struct tdma_chan_info *c = ch_info(m, op->ch);

		if (c) {
			int8_t v[32] = {0};
			uint16_t n = op->m_ss > 32 ? 32 : op->m_ss;
			uint16_t busy = op->m_busy > n ? n : op->m_busy;
			const int8_t fr = (int8_t)CFGV(m, rssi_free_dbm, TDMA_DEF_RSSI_FREE_DBM);

			/* a subslot list with the same busy count and maximum, the rest "free" */
			for (uint16_t i = 0; i < n; i++) {
				v[i] = i < busy || i + 1 == n
					       ? op->m_max
					       : (int8_t)(fr < op->m_max ? fr : op->m_max);
			}
			ch_account(m, c, v, n, op->frame);
		}
		m->mon_last = op->frame;
		m->stats.meas++;
		ft_mon_eval(m, op->frame);
	} else if (m->state == TDMA_ST_FT && !op->is_tx && op->use == TDMA_SLOT_FLEX) {
		/* a demanded UL burst that never came (the PT's grant was lost, or the burst) */
		struct tdma_peer *p = &m->peers[op->flex.pos];

		if (op->flex.ahead && !op->got) {
			m->stats.flex_ahead_empty++;
		}
		if (!op->flex.spec && !op->flex.ahead && !op->got &&
		    p->rd_id == op->owners[op->flex.pos]) {
			m->stats.flex_miss++;
			/* twice in a row at this MCS: one step down until the SNR says otherwise */
			if (++p->flex_fail >= 2 && p->mcs_ul > 0 && p->mcs_ul == op->flex.mcs) {
				p->mcs_ul--;
				p->flex_fail = 0;
				m->stats.mcs_changes++;
			}
		}
	} else if (m->state == TDMA_ST_FT && !op->is_tx && is_ul(&op->plan->slots[op->slot])) {
		ft_ul_done(m, op);
	}
	op->used = false;
	m->n_ops--;
	if (m->state == TDMA_ST_SEARCH) {
		search_kick(m, m->port.now(m->port.ctx));
	}
	if (m->state == TDMA_ST_FT_SCAN && !m->search_handle && !m->n_ops) {
		if (!scan_next(m)) {
			ft_scan_done(m, m->port.now(m->port.ctx));
		} else {
			ft_scan_kick(m, m->port.now(m->port.ctx));
		}
	}
}

void tdma_on_rssi(struct tdma_mac *m, uint32_t handle, const int8_t *ss_max, size_t n)
{
	struct tdma_op *op = op_find(m, handle);
	struct tdma_chan_info *c;

	if (op && op->mon && ss_max) {
		const int8_t bz = (int8_t)CFGV(m, rssi_busy_dbm, TDMA_DEF_RSSI_BUSY_DBM);

		for (size_t i = 0; i < n && op->m_ss < 0xffff; i++) {
			op->m_ss++;
			op->m_busy = (uint16_t)(op->m_busy + (ss_max[i] > bz));
			op->m_max =
				(op->m_ss == 1 || ss_max[i] > op->m_max) ? ss_max[i] : op->m_max;
		}
		return;
	}
	if (!op || (op->use != USE_SCAN && op->use != USE_MEAS && op->use != USE_FTSCAN) ||
	    !ss_max || !n || !(c = ch_info(m, op->ch))) {
		return;
	}
	ch_account(m, c, ss_max, n, op->frame);
}

void tdma_on_pcc(struct tdma_mac *m, uint32_t handle, int16_t rssi, uint8_t short_nwid,
		 uint16_t tx_short, uint8_t hdr_type)
{
	struct tdma_op *op = op_find(m, handle);
	struct tdma_chan_info *c;

	(void)hdr_type;
	if (op && op->mon) {
		op->heard = true;
		return;
	}
	if (op && op->use == USE_FTSCAN) {
		if (m->fs_handle == op->handle && m->fs_pcc < 0xffff) {
			m->fs_pcc++; /* any radio on that carrier (another site's too) */
		}
		return;
	}
	if (!op || op->use != USE_SCAN || !(c = ch_info(m, op->ch))) {
		return;
	}
	/* Any other radio's physical header: someone operates on this carrier. */
	if (c->clusters < 255) {
		c->clusters++;
	}
	if (c->clusters == 1 && !c->cluster_rd && m->state == TDMA_ST_FT_SCAN) {
		/*
		 * Another network's payload may not decode (scrambling), its header
		 * does: report short network id + transmitter short id until a
		 * beacon of ours gives the long ones.
		 */
		c->cluster_rd = tx_short;
		c->cluster_nwid = short_nwid;
		emit_full(m, TDMA_EVT_SCAN_CLUSTER, tx_short, short_nwid, TDMA_CAUSE_NONE, 0, rssi,
			  op->ch);
	}
	if (c->clusters == 1 || rssi > c->cluster_dbm) {
		c->cluster_dbm = (int8_t)(rssi < -128 ? -128 : rssi > 127 ? 127 : rssi);
	}
}

/* ---- API ---------------------------------------------------------------------------- */

int tdma_init(struct tdma_mac *m, const struct tdma_cfg *cfg, const struct tdma_port *port)
{
	if (!m || !cfg || !port || !port->now || !port->rx || !port->rx_stop || !port->tx ||
	    !port->deliver) {
		return -EINVAL;
	}
	if (cfg->rd_id == 0 || cfg->rd_id == TDMA_RD_BROADCAST || cfg->network_id == 0 ||
	    tdma_short_rd(cfg->rd_id) == TDMA_SHORT_BROADCAST || tdma_short_rd(cfg->rd_id) == 0) {
		return -EINVAL;
	}
	if (cfg->ch_min
		    ? (cfg->ch_max < cfg->ch_min || cfg->ch_max - cfg->ch_min >= TDMA_CH_TABLE ||
		       (cfg->channel && (cfg->channel < cfg->ch_min || cfg->channel > cfg->ch_max)))
		    : cfg->channel == 0) {
		return -EINVAL;
	}
	if (cfg->role == TDMA_ROLE_FT) {
		const struct tdma_plan *plan = tdma_plan_get(cfg->plan_id);

		if (tdma_plan_validate(plan) ||
		    !plan_mcs_ok(plan, cfg->mcs ? cfg->mcs : plan->mcs, port->sec != NULL)) {
			return -EINVAL;
		}
	}
	if (cfg->role == TDMA_ROLE_FT && cfg->relay &&
	    (!cfg->channel || !cfg->depth || cfg->depth >= TDMA_MAX_DEPTH)) {
		return -EINVAL; /* a relay's cluster: a fixed carrier (the relay picks it),
				   depth 1.. */
	}
	if (!cfg->mem.peers || !cfg->mem.n_peers || cfg->mem.n_peers > TDMA_MAX_POSITIONS ||
	    !cfg->mem.qmem || !cfg->mem.ras || !cfg->mem.n_ras ||
	    cfg->mem.n_chunks < tdma_mem_chunks(cfg->mem.n_peers, cfg->mem.n_big) ||
	    (cfg->role == TDMA_ROLE_FT &&
	     tdma_plan_get(cfg->plan_id)->n_positions > cfg->mem.n_peers)) {
		return -EINVAL;
	}
	if (port->sec && (!port->sec->derive || !port->sec->release || !port->sec->seal ||
			  !port->sec->open || !port->sec->key_state || !port->sec->random)) {
		return -EINVAL;
	}
	memset(m, 0, sizeof(*m));
	m->peers = cfg->mem.peers;
	m->n_peers = cfg->mem.n_peers;
	m->ras = cfg->mem.ras;
	m->n_ras = cfg->mem.n_ras;
	memset(m->peers, 0, (size_t)m->n_peers * sizeof(m->peers[0]));
	memset(m->ras, 0, (size_t)m->n_ras * sizeof(m->ras[0]));
	for (unsigned int i = 0, c = 0; i < m->n_peers; i++) {
		uint8_t n =
			(uint8_t)(i < cfg->mem.n_big ? TDMA_TXQ_ALL_CHUNKS : TDMA_TXQ_SMALL_CHUNKS);

		link_attach(&m->peers[i].link, &cfg->mem.qmem[c], n);
		c += n;
	}
	m->cfg = *cfg;
	m->port = *port;
	if (m->cfg.role == TDMA_ROLE_FT && m->cfg.relay) {
		m->cfg.plan_auto = false; /* the child plan is derived from the parent's (HG) */
		m->cfg.plan_multi = 0;
	}
	m->sec.on = port->sec != NULL;
	m->sec.cur = m->sec.next = m->sec.prev = -1;
	m->rng = cfg->seed ? cfg->seed : (cfg->rd_id * 2654435761u) | 1u;
	m->my_pos = -1;
	m->retry_at = UINT64_MAX;
	m->state = TDMA_ST_IDLE;
	if (!m->cfg.ch_min) {
		m->cfg.ch_min = m->cfg.ch_max = m->cfg.channel;
	}
	m->hop_base = m->cfg.ch_min;
	for (uint8_t i = 0; i < ch_count(m); i++) {
		m->chans[i].ch = (uint16_t)(m->cfg.ch_min + i);
	}
	if (m->cfg.channel) {
		m->chan = m->cfg.channel;
	} else if (ch_info(m, m->cfg.pref_channel)) {
		m->chan = m->cfg.pref_channel;
	} else {
		m->chan = m->cfg.ch_min;
	}
	m->search_ch = m->chan;
	return 0;
}

int tdma_start(struct tdma_mac *m)
{
	uint64_t now = m->port.now(m->port.ctx);

	if (m->state != TDMA_ST_IDLE) {
		return -EALREADY;
	}
	for (int i = 0; i < m->n_peers; i++) {
		m->peers[i].rd_id = 0;
		peer_link_reset(m, (uint8_t)i);
	}
	m->move_valid = false;
	m->lbt_pending = false;
	m->ft_started = false;
	m->pm_valid = false;
	m->hop_mask = 0;
	if (m->cfg.role == TDMA_ROLE_FT && m->sec.on) {
		int err = sec_ft_start(m);

		if (err) {
			return err; /* no network key: an FT without one cannot beacon */
		}
	}
	m->psw_valid = false;
	m->psw_cnt = 0;
	m->plan_since = 0;
	if (m->cfg.role == TDMA_ROLE_FT) {
		m->plan = tdma_plan_get(m->cfg.plan_id);
		m->base_plan = m->cfg.plan_id;
		m->mcs = m->cfg.mcs ? m->cfg.mcs : m->plan->mcs;
		m->flex_plan = tdma_plan_has_flex(m->plan);
		m->train_plan = tdma_plan_has_train(m->plan);
		flex_clear(m);
		memset(m->t2, 0, sizeof(m->t2));
		if (sec_need_ahead(m)) {
			m->cfg.grant_ahead = true; /* by the cost model (tdma_cfg.grant_ahead) */
		}
		if (m->cfg.relay) {
			/* a relay's cluster: on the carrier the relay picked, on the parent's grid
			 */
			if (!m->follow_valid) {
				m->state = TDMA_ST_IDLE;
				return -EINVAL;
			}
			ft_begin(m, now);
		} else if (m->port.scan) {
			/* channel selection (TS 103 636-4 5.1.2), then LBT on the first beacon */
			m->state = TDMA_ST_FT_SCAN;
			m->scan_i = 0;
			m->search_handle = 0;
			ft_scan_kick(m, now);
		} else {
			ft_begin(m, now);
		}
	} else {
		m->state = TDMA_ST_SEARCH;
		m->search_ch = m->chan;
		search_kick(m, now);
	}
	return 0;
}

void tdma_stop(struct tdma_mac *m)
{
	enum tdma_state was = m->state;

	if (was == TDMA_ST_IDLE) {
		return;
	}
	m->state = TDMA_ST_IDLE;
	stop_rx_ops(m);
	if (was == TDMA_ST_FT) {
		for (uint8_t i = 0; i < m->plan->n_positions; i++) {
			if (m->peers[i].rd_id) {
				ft_release(m, i, TDMA_CAUSE_STOPPED);
			}
		}
	} else if (was == TDMA_ST_ASSOCIATED) {
		emit(m, TDMA_EVT_LOST, m->parent_rd, TDMA_CAUSE_STOPPED, 0, 0);
	} else if (was == TDMA_ST_ASSOCIATING) {
		emit(m, TDMA_EVT_ASSOC_FAILED, m->parent_rd, TDMA_CAUSE_STOPPED, 0, 0);
	}
	m->parent_rd = 0;
	m->my_pos = -1;
	m->move_valid = false;
	m->lbt_pending = false;
	m->search_handle = 0;
	if (m->sec.on) {
		sec_reset(m, false);
	}
	for (int i = 0; i < m->n_peers; i++) {
		m->peers[i].rd_id = 0;
		peer_link_reset(m, (uint8_t)i);
	}
	emit(m, TDMA_EVT_STOPPED, m->cfg.rd_id, TDMA_CAUSE_STOPPED, 0, 0);
}

static struct tdma_peer *peer_of(struct tdma_mac *m, uint32_t dst)
{
	if (m->state == TDMA_ST_ASSOCIATED) {
		return dst == m->parent_rd ? &m->peers[0] : NULL;
	}
	if (m->state != TDMA_ST_FT) {
		return NULL;
	}
	for (uint8_t i = 0; i < m->plan->n_positions; i++) {
		if (m->peers[i].rd_id && m->peers[i].rd_id == dst) {
			return &m->peers[i];
		}
	}
	return NULL;
}

int tdma_send(struct tdma_mac *m, uint32_t dst_rd_id, const uint8_t *data, size_t len, uint8_t prio)
{
	uint64_t now = m->port.now(m->port.ctx);
	struct tdma_peer *p;
	int ret = -ENOTCONN;

	if (!data || len == 0 || len > TDMA_MAX_SDU) {
		return -EMSGSIZE;
	}
	if (m->state == TDMA_ST_ASSOCIATED && dst_rd_id == TDMA_RD_BROADCAST) {
		dst_rd_id = m->parent_rd;
	}
	if (dst_rd_id != TDMA_RD_BROADCAST) {
		p = peer_of(m, dst_rd_id);
		ret = p ? link_enqueue(&p->link, data, len, prio, now) : -ENOTCONN;
		if (ret == 0 && m->state == TDMA_ST_FT) {
			p->dem_acc[0] += (uint32_t)len;
		}
		return ret;
	}
	if (m->state != TDMA_ST_FT) {
		return -ENOTCONN;
	}
	for (uint8_t i = 0; i < m->plan->n_positions; i++) {
		if (!m->peers[i].rd_id) {
			continue;
		}
		int err = link_enqueue(&m->peers[i].link, data, len, prio, now);

		if (err == 0) {
			m->peers[i].dem_acc[0] += (uint32_t)len;
		}
		/* Broadcast: report the first failure, but still try everyone. */
		if (ret == -ENOTCONN || (ret == 0 && err)) {
			ret = err;
		}
	}
	return ret;
}

bool tdma_send_room(struct tdma_mac *m, uint32_t dst_rd_id, size_t len, uint8_t prio)
{
	struct tdma_peer *p;

	if (m->state == TDMA_ST_ASSOCIATED && dst_rd_id == TDMA_RD_BROADCAST) {
		dst_rd_id = m->parent_rd;
	}
	p = peer_of(m, dst_rd_id);
	if (!p) {
		return true; /* tdma_send() fails at once, nothing to wait for */
	}
	if (link_room(&p->link, len, prio)) {
		return true;
	}
	if (!prio) {
		p->link.blocked = true;
	}
	return false;
}

int tdma_pt_set_target(struct tdma_mac *m, uint32_t ft_rd_id)
{
	if (m->cfg.role != TDMA_ROLE_PT) {
		return -EINVAL;
	}
	m->cfg.ft_rd_filter = ft_rd_id;
	if ((m->state == TDMA_ST_ASSOCIATING || m->state == TDMA_ST_ASSOCIATED) && ft_rd_id &&
	    ft_rd_id != m->parent_rd) {
		pt_lose(m, TDMA_CAUSE_STOPPED);
	}
	return 0;
}

int tdma_pt_set_target_ch(struct tdma_mac *m, uint32_t ft_rd_id, uint16_t ch, uint32_t for_ticks)
{
	int err = tdma_pt_set_target(m, ft_rd_id);

	if (err) {
		return err;
	}
	m->fast_ch = ch;
	m->fast_until = ch ? m->port.now(m->port.ctx) + for_ticks : 0;
	if (ch && m->state == TDMA_ST_SEARCH && m->search_handle && m->search_ch != ch) {
		/* the carrier sweep in progress: over to the known carrier now */
		m->port.rx_stop(m->port.ctx, m->search_handle);
	}
	return 0;
}

/*
 * a relay's child cluster switches plan (HG <-> HGX) at `frame`, its
 * frames starting `delta` ticks later from then on (TDMA_F_RETIME), both
 * announced in the beacons before it.
 */
int tdma_ft_relay_switch(struct tdma_mac *m, uint8_t plan_id, uint32_t frame, uint32_t delta)
{
	const struct tdma_plan *p = tdma_plan_get(plan_id);

	if (m->state != TDMA_ST_FT || !m->cfg.relay || !p || p == m->plan || m->psw_valid ||
	    m->retime_valid || m->pm_valid || !plan_fits_peers(m, p) ||
	    (int32_t)(frame - m->cur_frame) <= 1 || delta >= TDMA_FRAME_TICKS) {
		return -EINVAL;
	}
	m->psw_valid = true;
	m->psw_plan = plan_id;
	m->psw_frame = frame;
	m->psw_cnt = 0;
	m->retime_valid = delta != 0;
	m->retime_frame = frame;
	m->retime_delta = delta;
	return 0;
}

/* FT, announce that the PT at `from` moves to the free position `to`. */
int tdma_ft_pos_move(struct tdma_mac *m, uint8_t from, uint8_t to)
{
	if (m->state != TDMA_ST_FT || m->pm_valid || from >= m->plan->n_positions ||
	    to >= m->plan->n_positions || from == to || !m->peers[from].rd_id ||
	    m->peers[to].rd_id) {
		return -EINVAL;
	}
	pos_move_announce(m, m->cur_frame, from, to, false);
	return 0;
}

int tdma_ft_retime(struct tdma_mac *m, uint32_t frame, uint32_t delta)
{
	if (m->state != TDMA_ST_FT || delta >= TDMA_FRAME_TICKS ||
	    (int32_t)(frame - m->cur_frame) <= 1) {
		return -EINVAL;
	}
	if (m->retime_valid) {
		return m->retime_frame == frame && m->retime_delta == delta ? 0 : -EALREADY;
	}
	m->retime_valid = true;
	m->retime_frame = frame;
	m->retime_delta = delta;
	return 0;
}

bool tdma_retime_pending(const struct tdma_mac *m, uint32_t *frame, uint32_t *delta)
{
	if (!m->retime_valid) {
		return false;
	}
	if (frame) {
		*frame = m->retime_frame;
	}
	if (delta) {
		*delta = m->retime_delta;
	}
	return true;
}

void tdma_ft_set_depth(struct tdma_mac *m, uint8_t depth)
{
	if (m->cfg.role == TDMA_ROLE_FT && m->cfg.relay && depth <= TDMA_MAX_DEPTH) {
		m->cfg.depth = depth;
	}
}

enum tdma_state tdma_get_state(const struct tdma_mac *m)
{
	return m->state;
}

uint32_t tdma_parent(const struct tdma_mac *m)
{
	return m->state == TDMA_ST_ASSOCIATED ? m->parent_rd : 0;
}

size_t tdma_children(const struct tdma_mac *m, uint32_t *out, size_t max)
{
	size_t n = 0;

	if (m->state != TDMA_ST_FT) {
		return 0;
	}
	for (uint8_t i = 0; i < m->plan->n_positions && n < max; i++) {
		if (m->peers[i].rd_id) {
			out[n++] = m->peers[i].rd_id;
		}
	}
	return n;
}

size_t tdma_link_mtu(const struct tdma_mac *m, uint32_t dst_rd_id)
{
	struct tdma_peer *p = peer_of((struct tdma_mac *)m, dst_rd_id);

	return p ? link_mtu(&p->link) : 0;
}

uint8_t tdma_link_mcs(const struct tdma_mac *m, uint32_t child_rd_id, bool dl)
{
	struct tdma_peer *p;

	if (m->state != TDMA_ST_FT) {
		return 0xff;
	}
	p = peer_of((struct tdma_mac *)m, child_rd_id);
	return p ? (dl ? p->mcs_dl : p->mcs_ul) : 0xff;
}

const struct tdma_stats *tdma_get_stats(const struct tdma_mac *m)
{
	return &m->stats;
}

int tdma_ft_move(struct tdma_mac *m, uint16_t ch, enum tdma_cause cause)
{
	if (m->state != TDMA_ST_FT || m->lbt_pending) {
		return -EINVAL;
	}
	if (m->move_valid) {
		return -EALREADY;
	}
	if (ch == 0) {
		ch = tdma_chan_best(m, m->chan);
		if (ch == 0) {
			return -ENOENT;
		}
	}
	if (!ch_info(m, ch) || (!m->hop_mask && ch == m->chan)) {
		return -EINVAL;
	}
	m->move_valid = true;
	m->move_ch = ch;
	m->move_mask = 0;
	m->move_cause = cause;
	/* the beacon of cur_frame may still be uncommitted: it announces too */
	m->move_frame = m->cur_frame + 1u + CFGV(m, move_frames, TDMA_DEF_MOVE_FRAMES);
	emit_full(m, TDMA_EVT_MOVE, m->cfg.rd_id, m->cfg.network_id, cause, 0, 0, ch);
	return 0;
}

int tdma_ft_set_hop(struct tdma_mac *m, uint32_t mask, enum tdma_cause cause)
{
	if (m->state != TDMA_ST_FT || m->lbt_pending) {
		return -EINVAL;
	}
	if (m->move_valid) {
		return -EALREADY;
	}
	if (mask && (popcount32(mask) < 2 || !pt_mask_ok(m, m->cfg.ch_min, mask))) {
		return -EINVAL;
	}
	if (!m->hop_mask && !mask) {
		return -EINVAL;
	}
	if (mask && !m->hop_mask) {
		m->hop_base = m->cfg.ch_min;
		do {
			m->hop_seed = rng_next(m) ^ m->cfg.network_id;
		} while (m->hop_seed == 0);
	}
	m->move_valid = true;
	m->move_mask = mask;
	m->move_cause = cause;
	m->move_frame = m->cur_frame + 1u + CFGV(m, move_frames, TDMA_DEF_MOVE_FRAMES);
	/* stopping: stay on the carrier the move frame would have had */
	m->move_ch = mask ? m->chan
			  : carrier_for(m, m->hop_base, m->hop_mask, m->hop_seed, m->move_frame);
	emit_full(m, TDMA_EVT_MOVE, m->cfg.rd_id, m->cfg.network_id, cause, 0, 0,
		  mask ? 0 : m->move_ch);
	return 0;
}

int tdma_op_info(const struct tdma_mac *m, uint32_t handle, uint8_t *slot, uint8_t *use,
		 uint32_t *frame, uint16_t *ch)
{
	const struct tdma_op *op = op_find((struct tdma_mac *)m, handle);

	if (!op) {
		return -ENOENT;
	}
	*slot = op->slot;
	*use = op->use;
	*frame = op->frame;
	*ch = op->ch;
	return 0;
}

uint16_t tdma_channel(const struct tdma_mac *m)
{
	struct tdma_mac *mm = (struct tdma_mac *)m; /* only the hop cache changes */

	if (m->hop_mask && (m->state == TDMA_ST_FT || m->state == TDMA_ST_ASSOCIATING ||
			    m->state == TDMA_ST_ASSOCIATED)) {
		return carrier_for(mm, m->hop_base, m->hop_mask, m->hop_seed, m->cur_frame);
	}
	return m->chan;
}

uint32_t tdma_hop_mask(const struct tdma_mac *m)
{
	return m->hop_mask;
}

uint16_t tdma_hop_carrier(struct tdma_mac *m, uint32_t frame)
{
	return op_ch(m, frame);
}

const struct tdma_chan_info *tdma_chan_table(const struct tdma_mac *m, size_t *n)
{
	*n = ch_count(m);
	return m->chans;
}

/* (plan HG: a root's grid + TDMA_RELAY_ROOT_OFFSET_SS, then + TDMA_RELAY_OFFSET_SS per depth) */
uint8_t tdma_grid_of_depth(uint8_t depth)
{
	return depth ? (uint8_t)((TDMA_RELAY_ROOT_OFFSET_SS +
				  (uint32_t)(depth - 1u) * TDMA_RELAY_OFFSET_SS) %
				 TDMA_SUBSLOTS_PER_FRAME)
		     : 0;
}

void tdma_tree(const struct tdma_mac *m, uint8_t *depth, uint8_t *grid_ss)
{
	uint8_t d = 0, g = 0;

	if (is_pt(m)) {
		d = m->tree_depth;
		g = m->tree_grid;
	} else if (m->cfg.relay) {
		d = m->cfg.depth;
		g = m->plan && m->plan->id == TDMA_PLAN_HGX ? TDMA_RELAY_HGX_OFFSET_SS
							    : tdma_grid_of_depth(d);
	}
	if (depth) {
		*depth = d;
	}
	if (grid_ss) {
		*grid_ss = g;
	}
}

uint32_t tdma_lbt_pending(const struct tdma_mac *m)
{
	return m->state == TDMA_ST_FT && m->lbt_pending ? lbt_ticks(m) : 0;
}

int tdma_set_route(struct tdma_mac *m, const uint8_t *rr, size_t len)
{
	if (len > TDMA_ROUTE_MAX || (len && !rr)) {
		return -EINVAL;
	}
	if (len) {
		memcpy(m->route, rr, len);
	}
	m->route_len = (uint8_t)len;
	return 0;
}

int tdma_set_beacon_ext(struct tdma_mac *m, const uint8_t *app, size_t len)
{
	if (len > TDMA_BEXT_APP_MAX || (len && !app)) {
		return -EINVAL;
	}
	if (len) {
		memcpy(m->app, app, len);
	}
	m->app_len = (uint8_t)len;
	return 0;
}

size_t tdma_parent_route(const struct tdma_mac *m, uint8_t *out, size_t max)
{
	size_t n = m->parent_route_len;

	if (!is_pt(m) || (m->state != TDMA_ST_ASSOCIATED && m->state != TDMA_ST_ASSOCIATING)) {
		return 0;
	}
	n = n < max ? n : max;
	memcpy(out, m->parent_route, n);
	return n;
}

void tdma_pt_set_relay(struct tdma_mac *m, bool on)
{
	if (is_pt(m)) {
		m->cfg.relay = on;
	}
}

void tdma_link_hold(struct tdma_mac *m, uint32_t rd_id, bool on)
{
	if (m->state == TDMA_ST_ASSOCIATED && (!rd_id || rd_id == m->parent_rd)) {
		m->stats.hold_on += on && !m->peers[0].link.hold_tx;
		link_hold(&m->peers[0].link, on);
		return;
	}
	if (m->state != TDMA_ST_FT) {
		return;
	}
	for (uint8_t i = 0; i < m->plan->n_positions; i++) {
		struct tdma_peer *p = &m->peers[i];

		if (p->rd_id && (!rd_id || p->rd_id == rd_id)) {
			m->stats.hold_on += on && !p->link.hold_tx;
			link_hold(&p->link, on);
		}
	}
}

bool tdma_link_held(const struct tdma_mac *m, uint32_t rd_id)
{
	const struct tdma_peer *p = peer_of((struct tdma_mac *)m, rd_id);

	return p && p->link.peer_hold &&
	       (int64_t)(m->port.now(m->port.ctx) - p->link.peer_hold_t) < (int64_t)TDMA_HOLD_TICKS;
}

size_t tdma_link_pending(const struct tdma_mac *m, uint32_t dst_rd_id)
{
	const struct tdma_peer *p = peer_of((struct tdma_mac *)m, dst_rd_id);

	return p ? link_pending_bytes(&p->link) : 0;
}

bool tdma_child_is_relay(const struct tdma_mac *m, uint32_t rd_id)
{
	if (m->state != TDMA_ST_FT || !rd_id) {
		return false;
	}
	for (uint8_t i = 0; i < m->n_peers; i++) {
		if (m->peers[i].rd_id == rd_id) {
			return m->peers[i].relay;
		}
	}
	return false;
}

/* FT relay: a new security session in place (unannounced; PTs derive it from the next beacon). */
static void sec_ft_renew(struct tdma_mac *m)
{
	int8_t cur = m->sec.cur, i;
	int err;

	if (!m->sec.on || cur < 0) {
		return;
	}
	sess_drop(m, m->sec.next);
	sess_drop(m, m->sec.prev);
	i = sess_get(m, m->sec.sess[cur].idx, m->cfg.rd_id, m->sec.sess[cur].ctr + 1u,
		     m->port.sec->random(m->port.sec_ctx), &err);
	if (i < 0) {
		/* no key handle: stop sealing under the old session (nothing goes out) */
		sess_drop(m, cur);
		return;
	}
	sess_drop(m, cur);
	m->sec.cur = i;
	m->sec.sess_start = m->cur_frame;
	m->stats.sec_switches++;
	emit_sec(m, TDMA_EVT_KEY_SWITCH, m->cfg.rd_id, TDMA_CAUSE_NONE, m->sec.sess[i].idx,
		 m->cur_frame);
}

void tdma_ft_follow(struct tdma_mac *m, uint64_t start, uint32_t frame)
{
	if (m->cfg.role != TDMA_ROLE_FT || !m->cfg.relay) {
		return;
	}
	if (m->state == TDMA_ST_FT && m->follow_valid) {
		/* the frame the current numbering has at about `start` */
		int64_t dt = (int64_t)(start - m->ref_start);
		int64_t k = (dt + (dt >= 0 ? 1 : -1) * (int64_t)(TDMA_FRAME_TICKS / 2)) /
			    (int64_t)TDMA_FRAME_TICKS;
		int64_t err = dt - k * (int64_t)TDMA_FRAME_TICKS;
		uint32_t predicted = m->ref_frame + (uint32_t)k;

		if (err > (int64_t)TDMA_RELAY_TOL_TICKS || err < -(int64_t)TDMA_RELAY_TOL_TICKS) {
			m->stats.follow_jumps++;
		}
		if (predicted != frame) {
			/*
			 * The parent's counter jumped (a new root, a merge): frames are
			 * renumbered, and under the current key a (frame, subslot) could
			 * come again. A new session first.
			 */
			m->cur_frame += frame - predicted;
			m->stats.follow_renumber++;
			m->ref_start = start;
			m->ref_frame = frame;
			sec_ft_renew(m);
		}
	}
	m->follow_valid = true;
	m->follow_start = start;
	m->follow_frame = frame;
	if (m->state == TDMA_ST_FT) {
		m->ref_start = start;
		m->ref_frame = frame;
	}
}

int tdma_sec_info(const struct tdma_mac *m, struct tdma_sec_info *out)
{
	int8_t c = m->sec.cur, n = m->sec.next;

	memset(out, 0, sizeof(*out));
	out->on = m->sec.on;
	out->devkey = m->cfg.sec_devkey;
	out->key_idx = TDMA_SEC_NO_KEY;
	out->next_idx = TDMA_SEC_NO_KEY;
	out->n_deny = m->sec.n_deny;
	if (c >= 0) {
		out->key_idx = m->sec.sess[c].idx;
		out->ft_rd = m->sec.sess[c].ft;
		out->sess_ctr = m->sec.sess[c].ctr;
		out->sess_rand = m->sec.sess[c].rnd;
	}
	if (n >= 0) {
		out->switch_pending = true;
		out->next_idx = m->sec.sess[n].idx;
		out->next_frame = m->sec.next_frame;
		out->next_ctr = m->sec.sess[n].ctr;
	}
	return 0;
}

int tdma_sec_deny(struct tdma_mac *m, uint32_t rd_id, bool add)
{
	uint8_t i;

	for (i = 0; i < m->sec.n_deny && m->sec.deny[i] != rd_id; i++) {
	}
	if (!add) {
		if (i == m->sec.n_deny) {
			return -ENOENT;
		}
		m->sec.deny[i] = m->sec.deny[--m->sec.n_deny];
		return 0;
	}
	if (i == m->sec.n_deny) {
		if (m->sec.n_deny >= TDMA_DENY_MAX) {
			return -ENOSPC;
		}
		m->sec.deny[m->sec.n_deny++] = rd_id;
	}
	if (m->state == TDMA_ST_FT) {
		for (uint8_t k = 0; k < m->plan->n_positions; k++) {
			if (m->peers[k].rd_id == rd_id) {
				ft_release(m, k, TDMA_CAUSE_REVOKED);
			}
		}
	}
	return 0;
}

size_t tdma_sec_deny_list(const struct tdma_mac *m, uint32_t *out, size_t max)
{
	size_t n = m->sec.n_deny < max ? m->sec.n_deny : max;

	memcpy(out, m->sec.deny, n * sizeof(out[0]));
	return n;
}
