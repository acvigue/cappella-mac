/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* Multi-node simulation tests: association, latency, loss, failures, drift. */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "sim.h"
#include <cappella/tdma_pdu.h>
#include "test.h"

#define MS(x)     ((uint64_t)(x) * 69120u)
#define FRAMES(n) ((uint64_t)(n) * TDMA_FRAME_TICKS)
#define US(t)     ((unsigned long long)TDMA_TICKS_TO_US(t))
#define FT        0

static struct sim *s;
static int n_pts;

/*
 * Bytes the 64-byte SDUs of the latency / drift tests shrink by (sec_basic:
 * the security overhead, 2 B per burst + 10 B beacon extension, so the SDUs
 * still fit one burst next to the beacon and the plan bounds still apply).
 */
size_t test_sdu_shrink;
/*
 * Latency slack (ticks) the bound checks allow (sec_hw_model: the seal lead
 * for the guaranteed slots, one DL period more for grant-ahead long bursts).
 */
uint64_t test_slack_small, test_slack_bulk;

/* ---- network setup ----------------------------------------------------------------- */

/* Commit lead trims (us) every node of the next net_build() gets (cfg.ul / dl_lead_trim). */
static uint32_t test_ul_trim_us, test_dl_trim_us;

static void net_build(uint8_t plan, int pts, uint64_t seed, int32_t ft_ppb, const int32_t *pt_ppb)
{
	s = sim_init(seed);
	n_pts = pts;
	/* Arbitrary, very different modem clocks per node. */
	sim_add_node(s, TDMA_ROLE_FT, 1, plan, (int64_t)(sim_rand(s) % (1ull << 40)), ft_ppb);
	for (int i = 0; i < pts; i++) {
		sim_add_node(s, TDMA_ROLE_PT, (uint8_t)(2 + i), plan,
			     (int64_t)(sim_rand(s) % (1ull << 40)), pt_ppb ? pt_ppb[i] : 0);
	}
	for (int i = 0; i <= pts; i++) {
		s->nodes[i].cfg.ul_lead_trim = TDMA_US_TO_TICKS(test_ul_trim_us);
		s->nodes[i].cfg.dl_lead_trim = TDMA_US_TO_TICKS(test_dl_trim_us);
	}
}

static void net_start(void)
{
	for (int i = 0; i <= n_pts; i++) {
		sim_start(s, i);
	}
}

static uint32_t rd(int node)
{
	return s->nodes[node].cfg.rd_id;
}

static bool all_associated(void)
{
	for (int i = 1; i <= n_pts; i++) {
		if (!s->nodes[i].alive || tdma_get_state(&s->nodes[i].mac) != TDMA_ST_ASSOCIATED) {
			return false;
		}
	}
	return true;
}

/* Run until every PT is associated; returns that time or UINT64_MAX at deadline. */
static uint64_t wait_assoc(uint64_t deadline)
{
	while (s->t < deadline) {
		sim_run_until(s, s->t + TDMA_FRAME_TICKS / 4);
		if (all_associated()) {
			return s->t;
		}
	}
	return UINT64_MAX;
}

static void check_clean(void)
{
	uint32_t port_err = 0, late = 0;

	for (int i = 0; i < s->n_nodes; i++) {
		port_err += tdma_get_stats(&s->nodes[i].mac)->port_errors;
		late += tdma_get_stats(&s->nodes[i].mac)->late_slots;
	}
	CHECK(sim_phy_errors(s) == 0, "PHY contract violations: %u", sim_phy_errors(s));
	CHECK(port_err == 0, "port errors: %u", port_err);
	CHECK(late == 0, "late slots: %u", late);
}

/* ---- traffic ------------------------------------------------------------------------- */

#define MAX_FLOWS 32
#define MAX_IDS   16384
#define MSG_MAGIC 0x5aa5

struct flow {
	int src, dst;
	size_t len;
	uint64_t gap_min, gap_rand;
	uint32_t sent, next_id, send_err;
	uint8_t prio;
	bool saturate;    /* -ENOBUFS: try the same id again (saturated sender) */
	uint64_t t_stop;  /* stops sending here (0: traffic_stop) */
	uint64_t bytes;   /* delivered */
	uint32_t next_rx; /* id after the newest delivered */
};

static struct flow flows[MAX_FLOWS];
static int n_flows;
static uint8_t seen[MAX_FLOWS][MAX_IDS];
static uint64_t sent_at[MAX_FLOWS][MAX_IDS]; /* true time each id was queued */
static uint32_t lat[400000];
static uint8_t lat_dl[400000]; /* 1 = FT -> PT */
static uint8_t lat_flow[400000];
static size_t n_lat;
static uint32_t lat_tmp[400000];
static uint32_t dups, corrupt, misrouted, misordered;
static uint64_t traffic_stop;
static bool quiet; /* stress: no per-run output / summary rows */

static void traffic_reset(void)
{
	n_flows = 0;
	memset(flows, 0, sizeof(flows));
	memset(seen, 0, sizeof(seen));
	n_lat = 0;
	dups = corrupt = misrouted = misordered = 0;
}

static void flow_send(struct sim *sm, void *arg)
{
	struct flow *f = arg;
	uint8_t msg[TDMA_MAX_SDU];
	uint32_t id;
	int fi = (int)(f - flows);

	if (sm->t >= traffic_stop || (f->t_stop && sm->t >= f->t_stop) || f->next_id >= MAX_IDS) {
		return;
	}
	int dst = f->dst >= 0 ? f->dst : 1 + (int)(sim_rand(sm) % (uint64_t)n_pts);

	id = f->next_id++;
	msg[0] = MSG_MAGIC & 0xff;
	msg[1] = MSG_MAGIC >> 8;
	msg[2] = (uint8_t)fi;
	msg[3] = (uint8_t)dst;
	memcpy(&msg[4], &id, 4);
	memcpy(&msg[8], &sm->t, 8);
	for (size_t i = 16; i < f->len; i++) {
		msg[i] = (uint8_t)(id * 31 + i);
	}
	sent_at[fi][id] = sm->t;
	if (sim_send(sm, f->src, rd(dst), msg, f->len, f->prio) == 0) {
		f->sent++;
	} else if (f->saturate) {
		f->next_id--; /* queue full: offer it again at the next gap */
	} else {
		f->send_err++;
		seen[fi][id] = 0xff; /* never sent, never expected */
	}
	sim_at(sm, sm->t + f->gap_min + sim_rand(sm) % f->gap_rand, flow_send, f);
}

static void on_deliver(struct sim *sm, int node, uint32_t src, const uint8_t *data, size_t len)
{
	uint32_t id;
	uint64_t t0;
	struct flow *f;

	if (len < 16 || data[0] != (MSG_MAGIC & 0xff) || data[1] != (MSG_MAGIC >> 8) ||
	    data[2] >= n_flows) {
		corrupt++;
		return;
	}
	f = &flows[data[2]];
	memcpy(&id, &data[4], 4);
	memcpy(&t0, &data[8], 8);
	if (node != (f->dst >= 0 ? f->dst : data[3]) || src != rd(f->src) || id >= MAX_IDS) {
		misrouted++;
		return;
	}
	if (len != f->len) {
		corrupt++;
		return;
	}
	for (size_t i = 16; i < len; i++) {
		if (data[i] != (uint8_t)(id * 31 + i)) {
			corrupt++;
			return;
		}
	}
	if (seen[data[2]][id]++) {
		dups++;
		return;
	}
	f->bytes += len;
	if (id < f->next_rx) {
		misordered++; /* an older one after a newer one */
	} else {
		f->next_rx = id + 1;
	}
	if (getenv("LAT_DBG") && sm->t - t0 > MS(atoi(getenv("LAT_DBG")))) {
		printf("      late: flow %u id %u %llu us, sent at %llu us (frame %llu ss %llu)\n",
		       data[2], id, US(sm->t - t0), US(t0),
		       (unsigned long long)(t0 / TDMA_FRAME_TICKS),
		       (unsigned long long)(t0 % TDMA_FRAME_TICKS / TDMA_SUBSLOT_TICKS));
	}
	if (n_lat < sizeof(lat) / sizeof(lat[0])) {
		lat_flow[n_lat] = data[2];
		lat_dl[n_lat] = f->src == FT;
		lat[n_lat++] = (uint32_t)(sm->t - t0);
	}
}

static void add_flow(int src, int dst, size_t len, uint64_t gap_min, uint64_t gap_rand,
		     uint64_t t_start)
{
	struct flow *f = &flows[n_flows++];

	f->src = src;
	f->dst = dst;
	f->len = len;
	f->gap_min = gap_min;
	f->gap_rand = gap_rand;
	sim_at(s, t_start + sim_rand(s) % gap_rand, flow_send, f);
}

/* Both directions between the FT and every PT. */
static void add_flows_all(size_t len, uint64_t gap_min, uint64_t gap_rand, uint64_t t_start)
{
	for (int i = 1; i <= n_pts; i++) {
		add_flow(FT, i, len, gap_min, gap_rand, t_start);
		add_flow(i, FT, len, gap_min, gap_rand, t_start);
	}
}

static uint32_t total_sent(void)
{
	uint32_t n = 0;

	for (int i = 0; i < n_flows; i++) {
		n += flows[i].sent;
	}
	return n;
}

static uint32_t total_send_err(void)
{
	uint32_t n = 0;

	for (int i = 0; i < n_flows; i++) {
		n += flows[i].send_err;
	}
	return n;
}

static uint32_t total_sdu_drops(void)
{
	uint32_t n = 0;

	for (int i = 0; i < s->n_nodes; i++) {
		n += tdma_get_stats(&s->nodes[i].mac)->sdu_tx_drop;
	}
	return n;
}

static uint32_t total_stat_retx(void)
{
	uint32_t n = 0;

	for (int i = 0; i < s->n_nodes; i++) {
		n += tdma_get_stats(&s->nodes[i].mac)->retx;
	}
	return n;
}

static uint32_t sum_stat(size_t off)
{
	uint32_t n = 0;

	for (int i = 0; i < s->n_nodes; i++) {
		n += *(const uint32_t *)((const uint8_t *)tdma_get_stats(&s->nodes[i].mac) + off);
	}
	return n;
}

#define STAT(f) sum_stat(offsetof(struct tdma_stats, f))

static unsigned int queued_pdus(void)
{
	unsigned int n = 0;

	for (int i = 0; i < s->n_nodes; i++) {
		for (int k = 0; k < TDMA_MAX_POSITIONS; k++) {
			n += s->nodes[i].mac.peers[k].link.n_sdu;
		}
	}
	return n;
}

static int cmp_u32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

enum {
	DIR_DL = 1,
	DIR_UL = 2,
	DIR_ALL = 3
};

static void lat_report(const char *name, int dir, uint64_t bound, struct lat_row *out)
{
	struct lat_row r = {0};
	unsigned long long sum = 0;
	size_t le5 = 0, n = 0;

	for (size_t i = 0; i < n_lat; i++) {
		if (dir & (lat_dl[i] ? DIR_DL : DIR_UL)) {
			lat_tmp[n++] = lat[i];
		}
	}
	snprintf(r.name, sizeof(r.name), "%s", name);
	r.sent = 0;
	for (int i = 0; i < n_flows; i++) {
		if (dir & (flows[i].src == FT ? DIR_DL : DIR_UL)) {
			r.sent += flows[i].sent;
		}
	}
	r.delivered = (unsigned int)n;
	r.dropped = total_sdu_drops();
	r.dups = dups;
	r.bound = bound;
	if (n) {
		qsort(lat_tmp, n, sizeof(lat_tmp[0]), cmp_u32);
		for (size_t i = 0; i < n; i++) {
			sum += lat_tmp[i];
			le5 += lat_tmp[i] <= MS(5);
		}
		r.min = lat_tmp[0];
		r.max = lat_tmp[n - 1];
		r.avg = sum / n;
		r.p99 = lat_tmp[(n * 99) / 100 < n ? (n * 99) / 100 : n - 1];
		r.pct_5ms = 100.0 * (double)le5 / (double)n;
	}
	if (out) {
		*out = r;
	}
	if (quiet) {
		return;
	}
	printf("    %s: sent %u delivered %u dropped %u dups %u | min %llu us avg %llu us p99 %llu "
	       "us "
	       "max %llu us | bound %llu us | <=5 ms %.2f%%\n",
	       name, r.sent, r.delivered, r.dropped, r.dups, US(r.min), US(r.avg), US(r.p99),
	       US(r.max), US(bound), r.pct_5ms);
	lat_table_add(&r);
}

/*
 * Worst case one-way latency without loss or queueing: the frame arrives just
 * after a burst was committed, so it waits for the next burst (largest gap),
 * plus the commit lead, the burst's air time and the PDC latency.
 */
static uint64_t bound_dir(uint8_t plan_id, int dir)
{
	const struct tdma_plan *p = tdma_plan_get(plan_id);
	uint64_t worst = 0;

	for (uint8_t i = 0; i < p->n_slots; i++) {
		const struct tdma_slot *sl = &p->slots[i];
		bool dl = sl->use == TDMA_SLOT_BEACON || sl->use == TDMA_SLOT_DL;
		uint64_t gap, b;

		if ((dir == DIR_DL) != dl || sl->use == TDMA_SLOT_CONTENTION ||
		    sl->use == TDMA_SLOT_FLEX) {
			continue;
		}
		gap = tdma_plan_max_gap_ticks(p, sl->pos, dl ? TDMA_SLOT_DL : TDMA_SLOT_UL);
		b = gap + TDMA_COMMIT_LEAD_TICKS + (uint64_t)sl->len * TDMA_SUBSLOT_TICKS +
		    sim_pdc_ticks(sl->len, p->mcs) + 64; /* + TX jitter */
		/* trimmed leads: every UL slot, every DL burst but the beacon */
		b -= TDMA_US_TO_TICKS(dl ? (sl->use == TDMA_SLOT_DL ? test_dl_trim_us : 0)
					 : test_ul_trim_us);
		worst = b > worst ? b : worst;
	}
	return worst;
}

/* ---- 1/2: association ---------------------------------------------------------------- */

static void assoc_test(uint8_t plan, int pts, uint64_t seed, uint64_t deadline_frames)
{
	uint64_t t, t_sync_max = 0;
	uint32_t req = 0;

	net_build(plan, pts, seed, 0, NULL);
	net_start();
	t = wait_assoc(FRAMES(deadline_frames));
	CHECK(t != UINT64_MAX, "not all %d PTs associated within %llu frames", pts,
	      (unsigned long long)deadline_frames);
	for (int i = 1; i <= pts; i++) {
		uint64_t ts = 0;

		CHECK(sim_find_evt(&s->nodes[i], TDMA_EVT_SYNCED, 0, &ts) != NULL, "PT %d synced",
		      i);
		t_sync_max = ts > t_sync_max ? ts : t_sync_max;
		req += tdma_get_stats(&s->nodes[i].mac)->assoc_tx;
		CHECK(tdma_parent(&s->nodes[i].mac) == rd(FT), "PT %d parent", i);
	}
	{
		uint32_t kids[TDMA_MAX_POSITIONS];

		CHECK(tdma_children(&s->nodes[FT].mac, kids, TDMA_MAX_POSITIONS) == (size_t)pts,
		      "FT children");
		CHECK(sim_count_evt(&s->nodes[FT], TDMA_EVT_CHILD_ADDED, 0) == pts,
		      "CHILD_ADDED x%d (%d)", pts,
		      sim_count_evt(&s->nodes[FT], TDMA_EVT_CHILD_ADDED, 0));
	}
	if (quiet) {
		check_clean();
		return;
	}
	printf("    plan %s, %d PT(s): all synced by %.1f ms, all associated by %.1f ms "
	       "(%.1f frames); %u assoc requests, %u receptions lost to collisions\n",
	       tdma_plan_get(plan)->name, pts, (double)t_sync_max / 69120.0, (double)t / 69120.0,
	       (double)t / TDMA_FRAME_TICKS, req, s->st.collisions);
	check_clean();
}

void test_assoc_1pt(void)
{
	/* backoff < 8 frames of opportunities + first beacon + answer */
	for (uint64_t seed = 1; seed <= 20; seed++) {
		int before = test_failures;

		assoc_test(TDMA_PLAN_A, 1, seed, 15);
		if (test_failures != before) {
			printf("    (seed %llu)\n", (unsigned long long)seed);
			break;
		}
	}
	assoc_test(TDMA_PLAN_B, 1, 3, 15);
}

/* Default plan: 4 PTs fill it; a 5th is told the FT is full. */
void test_assoc_full(void)
{
	uint64_t t;

	assoc_test(TDMA_PLAN_A, 4, 7, 300);
	assoc_test(TDMA_PLAN_A, 4, 8, 300);
	assoc_test(TDMA_PLAN_B, 2, 9, 300);

	net_build(TDMA_PLAN_A, 4, 11, 0, NULL);
	net_start();
	CHECK(wait_assoc(FRAMES(300)) != UINT64_MAX, "4 PTs");
	t = s->t;
	sim_add_node(s, TDMA_ROLE_PT, 6, TDMA_PLAN_A, 12345, 0);
	sim_start(s, 5);
	sim_run_until(s, t + MS(100));
	{
		const struct tdma_evt *e =
			sim_find_evt(&s->nodes[5], TDMA_EVT_ASSOC_FAILED, t, NULL);

		CHECK(e && e->cause == TDMA_CAUSE_FULL, "5th PT: ASSOC_FAILED(FULL)");
		CHECK(tdma_get_stats(&s->nodes[5].mac)->assoc_tx == 0, "no request into a full FT");
	}
	printf("    5th PT on plan A: ASSOC_FAILED(FULL) without transmitting\n");
	check_clean();
}

void test_assoc_10pt(void)
{
	assoc_test(TDMA_PLAN_1X10, 10, 9, 300);
	assoc_test(TDMA_PLAN_1X10, 10, 10, 300);
}

/* ---- 3: latency without loss --------------------------------------------------------------- */

/*
 * UL: every PT sends to the FT at random times. DL: the FT sends to a random
 * PT at random times. Never two frames of one flow within one burst period:
 * this measures access latency, not queueing.
 */
static void latency_test(uint8_t plan, int pts, const char *name, bool require_5ms)
{
	const struct tdma_plan *p = tdma_plan_get(plan);
	uint64_t gap_ul = 0, gap_dl, t0, b_dl, b_ul;
	struct lat_row rd_, ru;
	char nm[48];

	net_build(plan, pts, 100 + plan, 0, NULL);
	s->on_deliver = on_deliver;
	traffic_reset();
	net_start();
	t0 = wait_assoc(FRAMES(300));
	CHECK(t0 != UINT64_MAX, "association");
	for (uint8_t i = 0; i < p->n_positions; i++) {
		uint64_t g = tdma_plan_max_gap_ticks(p, i, TDMA_SLOT_UL);

		gap_ul = g > gap_ul ? g : gap_ul;
	}
	gap_dl = tdma_plan_max_gap_ticks(p, 0, TDMA_SLOT_DL);
	b_dl = bound_dir(plan, DIR_DL);
	b_ul = bound_dir(plan, DIR_UL);
	traffic_stop = t0 + MS(10000);
	for (int i = 1; i <= pts; i++) {
		add_flow(i, FT, 64 - test_sdu_shrink, gap_ul, 3 * gap_ul, t0 + MS(50));
	}
	add_flow(FT, -1, 64 - test_sdu_shrink, gap_dl, 3 * gap_dl, t0 + MS(50));
	sim_run_until(s, traffic_stop + MS(300));

	snprintf(nm, sizeof(nm), "%s DL", name);
	lat_report(nm, DIR_DL, b_dl, &rd_);
	snprintf(nm, sizeof(nm), "%s UL", name);
	lat_report(nm, DIR_UL, b_ul, &ru);
	/* flows send every 1-3 gaps: > 1000 UL SDUs in 10 s up to a 5 ms gap, half at 10 ms (plan
	 * T) */
	CHECK(rd_.delivered == rd_.sent && ru.delivered == ru.sent &&
		      ru.sent > (gap_ul > 24u * TDMA_SUBSLOT_TICKS
					 ? (uint32_t)(1000u * 24u * TDMA_SUBSLOT_TICKS / gap_ul)
					 : 1000u),
	      "every frame delivered (DL %u/%u, UL %u/%u)", rd_.delivered, rd_.sent, ru.delivered,
	      ru.sent);
	CHECK(dups == 0 && corrupt == 0 && misrouted == 0, "dups %u corrupt %u misrouted %u", dups,
	      corrupt, misrouted);
	CHECK(rd_.max <= b_dl + test_slack_small, "DL max %llu us > bound %llu us", US(rd_.max),
	      US(b_dl + test_slack_small));
	CHECK(ru.max <= b_ul + test_slack_small, "UL max %llu us > bound %llu us", US(ru.max),
	      US(b_ul + test_slack_small));
	CHECK(total_stat_retx() == 0, "no retransmissions on a clean channel (%u)",
	      total_stat_retx());
	if (require_5ms) {
		CHECK(rd_.max <= MS(5) && ru.max <= MS(5), "max DL %llu / UL %llu us > 5 ms",
		      US(rd_.max), US(ru.max));
	} else if (rd_.max > MS(5) || ru.max > MS(5)) {
		printf("    NOTE: plan %s misses the 5 ms target by design: a burst every %llu us "
		       "plus %llu us commit lead + air + PDC\n",
		       p->name, US(gap_dl), US(TDMA_COMMIT_LEAD_TICKS));
	}
	check_clean();
}

/* All PTs get DL frames at random, independent times: they share DL bursts. */
static void dl_share_test(uint8_t plan, int pts, const char *name)
{
	const struct tdma_plan *p = tdma_plan_get(plan);
	uint64_t gap = tdma_plan_max_gap_ticks(p, 0, TDMA_SLOT_DL), t0;
	struct lat_row r;

	net_build(plan, pts, 200 + plan, 0, NULL);
	s->on_deliver = on_deliver;
	traffic_reset();
	net_start();
	t0 = wait_assoc(FRAMES(300));
	traffic_stop = t0 + MS(10000);
	for (int i = 1; i <= pts; i++) {
		add_flow(FT, i, 64, gap, 3 * gap, t0 + MS(50));
	}
	sim_run_until(s, traffic_stop + MS(300));
	lat_report(name, DIR_DL, 0, &r);
	CHECK(r.delivered == r.sent && dups == 0 && corrupt == 0, "all delivered (%u/%u)",
	      r.delivered, r.sent);
	check_clean();
}

void test_latency_a(void)
{
	latency_test(TDMA_PLAN_A, 4, "A, 4 PTs, 64 B", false);
	dl_share_test(TDMA_PLAN_A, 4, "A, DL to 4 PTs at once");
}

void test_latency_b(void)
{
	latency_test(TDMA_PLAN_B, 2, "B, 2 PTs, 64 B", true);
	dl_share_test(TDMA_PLAN_B, 2, "B, DL to 2 PTs at once");
}

void test_latency_1x10(void)
{
	latency_test(TDMA_PLAN_1X10, 10, "1x10, 10 PTs, 64 B", false);
}

/* ---- 4: 10 % loss ------------------------------------------------------------------------- */

static void lossy_traffic(const char *name, uint8_t plan, int pts, size_t len, uint64_t gap_min,
			  uint64_t gap_rand, uint64_t dur, uint64_t seed)
{
	struct lat_row r;
	uint64_t t0;
	uint32_t sent, drops, retx;

	net_build(plan, pts, seed, 0, NULL);
	s->on_deliver = on_deliver;
	traffic_reset();
	sim_set_loss_all(s, 100000); /* 10 % on every link, both directions, beacons too */
	net_start();
	t0 = wait_assoc(FRAMES(1000));
	CHECK(t0 != UINT64_MAX, "association under loss");
	traffic_stop = t0 + dur;
	add_flows_all(len, gap_min, gap_rand, t0 + MS(50));
	sim_run_until(s, traffic_stop + MS(500));
	/* drain: under overload the queues may still hold traffic */
	for (int k = 0; k < 100 && queued_pdus(); k++) {
		sim_run_until(s, s->t + MS(100));
	}
	CHECK(queued_pdus() == 0, "queues drained (%u PDUs left)", queued_pdus());

	lat_report(name, DIR_ALL, 0, &r);
	sent = total_sent();
	drops = total_sdu_drops();
	retx = total_stat_retx();
	CHECK(dups == 0 && corrupt == 0 && misrouted == 0, "dups %u corrupt %u misrouted %u", dups,
	      corrupt, misrouted);
	/* Everything not delivered must be accounted for as an ARQ drop. */
	CHECK(r.delivered + drops >= sent && r.delivered <= sent,
	      "delivered %u + dropped %u < sent %u", r.delivered, drops, sent);
	for (int i = 1; i <= pts; i++) {
		CHECK(sim_count_evt(&s->nodes[i], TDMA_EVT_LOST, t0) == 0, "PT %d lost its FT", i);
	}
	CHECK(sim_count_evt(&s->nodes[FT], TDMA_EVT_CHILD_REMOVED, t0) == 0, "FT dropped a child");
	if (!quiet) {
		uint32_t dr = 0, dl = 0;

		for (int i = 0; i < s->n_nodes; i++) {
			dr += tdma_get_stats(&s->nodes[i].mac)->drop_retries;
			dl += tdma_get_stats(&s->nodes[i].mac)->drop_lifetime;
		}
		printf("    %u retransmissions; %u SDUs given up (%u PDUs after %d tries, %u PDUs "
		       "past lifetime); %u send() refusals; air: %u lost, %u collided\n",
		       retx, drops, dr, TDMA_DEF_ARQ_MAX_TX, dl, total_send_err(), s->st.lost,
		       s->st.collisions);
	}
	check_clean();
}

void test_loss10(void)
{
	lossy_traffic("A, 4 PTs, 64 B, 10% loss", TDMA_PLAN_A, 4, 64, MS(5), MS(15), MS(20000), 41);
}

void test_frag(void)
{
	lossy_traffic("A, 2 PTs, 1280 B, 10% loss", TDMA_PLAN_A, 2, TDMA_MAX_SDU, MS(150), MS(100),
		      MS(20000), 43);
	CHECK(n_lat > 200, "fragmented SDUs delivered (%zu)", n_lat);
}

/* ---- 5: FT disappears and comes back ----------------------------------------------------------
 */

void test_ft_loss(void)
{
	const int miss = TDMA_DEF_BEACON_MISS_MAX;
	uint64_t t0, t1, t;

	net_build(TDMA_PLAN_A, 3, 55, 0, NULL);
	s->on_deliver = on_deliver;
	traffic_reset();
	net_start();
	CHECK(wait_assoc(FRAMES(300)) != UINT64_MAX, "association");
	sim_run_until(s, s->t + MS(200));

	t0 = s->t;
	sim_kill(s, FT);
	sim_run_until(s, t0 + FRAMES(miss + 5));
	for (int i = 1; i <= n_pts; i++) {
		const struct tdma_evt *e = sim_find_evt(&s->nodes[i], TDMA_EVT_LOST, t0, &t);

		CHECK(e && e->cause == TDMA_CAUSE_SYNC_LOST && e->rd_id == rd(FT),
		      "PT %d LOST(SYNC_LOST, FT)", i);
		if (e) {
			CHECK(t - t0 <= FRAMES(miss + 2), "PT %d noticed after %llu us", i,
			      US(t - t0));
			printf("    PT %d: sync lost %.1f ms (%.1f frames) after the FT went "
			       "silent\n",
			       i, (double)(t - t0) / 69120.0, (double)(t - t0) / TDMA_FRAME_TICKS);
		}
		CHECK(tdma_get_state(&s->nodes[i].mac) == TDMA_ST_SEARCH, "PT %d searching", i);
	}

	sim_run_until(s, t0 + MS(500));
	t1 = s->t;
	sim_revive(s, FT);
	t = wait_assoc(t1 + MS(3000));
	CHECK(t != UINT64_MAX, "PTs rejoined the restarted FT");
	if (t != UINT64_MAX) {
		printf("    all %d PTs re-associated %.1f ms after the FT restarted\n", n_pts,
		       (double)(t - t1) / 69120.0);
	}
	CHECK(sim_count_evt(&s->nodes[FT], TDMA_EVT_CHILD_ADDED, t1) == n_pts, "CHILD_ADDED again");

	/* and data flows again */
	traffic_stop = s->t + MS(500);
	add_flows_all(64, MS(5), MS(10), s->t);
	sim_run_until(s, traffic_stop + MS(200));
	/* with security a 64 B SDU takes 2 plan A UL bursts: these flows overload them */
	for (int k = 0; k < 20 && queued_pdus(); k++) {
		sim_run_until(s, s->t + MS(50));
	}
	CHECK(n_lat == total_sent() && n_lat > 50,
	      "data after rejoin (%zu/%u; SDU drops %u, retx %u, "
	      "dup %u, no reassembly buffer %u)",
	      n_lat, total_sent(), STAT(sdu_tx_drop), STAT(retx), STAT(dup_rx), STAT(ras_full));
	check_clean();
}

/* ---- 6: PT disappears -------------------------------------------------------------------------
 */

void test_pt_loss(void)
{
	const int ul_miss = TDMA_DEF_UL_MISS_MAX;
	uint64_t t0, t;
	const struct tdma_evt *e;

	net_build(TDMA_PLAN_A, 2, 66, 0, NULL);
	s->on_deliver = on_deliver;
	traffic_reset();
	net_start();
	CHECK(wait_assoc(FRAMES(300)) != UINT64_MAX, "association");
	sim_run_until(s, s->t + MS(100));

	t0 = s->t;
	sim_kill(s, 1);
	sim_run_until(s, t0 + MS(400));
	e = sim_find_evt(&s->nodes[FT], TDMA_EVT_CHILD_REMOVED, t0, &t);
	CHECK(e && e->rd_id == rd(1) && e->cause == TDMA_CAUSE_UL_TIMEOUT,
	      "CHILD_REMOVED(PT 1, UL_TIMEOUT)");
	if (e) {
		/* 2 UL bursts per frame in plan A */
		CHECK(t - t0 <= FRAMES(ul_miss / 2 + 2), "removed after %llu us", US(t - t0));
		printf("    FT freed PT 1's position %.1f ms after it went silent (%d missed UL "
		       "bursts)\n",
		       (double)(t - t0) / 69120.0, ul_miss);
	}
	CHECK(sim_count_evt(&s->nodes[FT], TDMA_EVT_CHILD_REMOVED, t0) == 1, "only PT 1 removed");
	CHECK(sim_count_evt(&s->nodes[2], TDMA_EVT_LOST, t0) == 0, "PT 2 unaffected");

	/* PT 1 comes back: gets a position again */
	t0 = s->t;
	sim_revive(s, 1);
	CHECK(wait_assoc(t0 + MS(2000)) != UINT64_MAX, "PT 1 rejoined");
	CHECK(sim_count_evt(&s->nodes[FT], TDMA_EVT_CHILD_ADDED, t0) == 1, "re-added");

	/* PT 2 reboots faster than the FT notices: new session (nonce), the FT
	 * must restart that child's sequence space or data would be lost.
	 */
	sim_run_until(s, s->t + MS(50));
	t0 = s->t;
	sim_revive(s, 2);
	CHECK(wait_assoc(t0 + MS(2000)) != UINT64_MAX, "PT 2 rejoined");
	e = sim_find_evt(&s->nodes[FT], TDMA_EVT_CHILD_REMOVED, t0, NULL);
	CHECK(e && e->rd_id == rd(2) && e->cause == TDMA_CAUSE_REASSOC, "REASSOC removal");
	CHECK(sim_count_evt(&s->nodes[FT], TDMA_EVT_CHILD_ADDED, t0) == 1, "re-added");
	traffic_stop = s->t + MS(500);
	add_flows_all(64, MS(5), MS(10), s->t);
	sim_run_until(s, traffic_stop + MS(200));
	/* with security a 64 B SDU takes 2 plan A UL bursts: these flows overload them */
	for (int k = 0; k < 20 && queued_pdus(); k++) {
		sim_run_until(s, s->t + MS(50));
	}
	CHECK(n_lat == total_sent() && n_lat > 50 && dups == 0, "data after reboot (%zu/%u)", n_lat,
	      total_sent());
	check_clean();
}

/* ---- 7: clock drift ------------------------------------------------------------------------ */

void test_drift(void)
{
	static const int32_t ppb[] = {-20000, 20000, -20000, 20000};
	uint64_t t0, b_ul = bound_dir(TDMA_PLAN_A, DIR_UL);
	struct lat_row r, rdl;

	net_build(TDMA_PLAN_A, 4, 77, 20000, ppb);
	s->on_deliver = on_deliver;
	traffic_reset();
	net_start();
	t0 = wait_assoc(FRAMES(300));
	CHECK(t0 != UINT64_MAX, "association");
	traffic_stop = t0 + MS(60000);
	add_flows_all(64 - test_sdu_shrink, MS(5), MS(100), t0 + MS(10));
	sim_run_until(s, traffic_stop + MS(300));

	lat_report("A, +-20 ppm, 60 s UL", DIR_UL, b_ul, &r);
	lat_report("A, +-20 ppm, 60 s DL", DIR_DL, 0, &rdl);
	for (int i = 1; i <= n_pts; i++) {
		const struct tdma_stats *st = tdma_get_stats(&s->nodes[i].mac);

		CHECK(sim_count_evt(&s->nodes[i], TDMA_EVT_LOST, t0) == 0, "PT %d lost sync", i);
		printf("    PT %d (%+d ppm vs FT %+d ppm): %u beacons received\n", i,
		       ppb[i - 1] / 1000, 20, st->beacons_rx);
	}
	CHECK(sim_count_evt(&s->nodes[FT], TDMA_EVT_CHILD_REMOVED, t0) == 0, "FT removed a child");
	CHECK(r.delivered == r.sent && rdl.delivered == rdl.sent && dups == 0 && corrupt == 0,
	      "all delivered (UL %u/%u DL %u/%u)", r.delivered, r.sent, rdl.delivered, rdl.sent);
	/* 40 ppm relative drift moves a 5 ms wait by 0.2 us: same bound. */
	CHECK(r.max <= b_ul, "UL max %llu us > %llu us", US(r.max), US(b_ul));
	check_clean();
}

/* ---- API behaviour ------------------------------------------------------------------------ */

static void noop_evt(const struct tdma_evt *e, void *u)
{
	(void)e;
	(void)u;
}

void test_api(void)
{
	uint8_t buf[TDMA_MAX_SDU + 1] = {0};
	struct tdma_mac *ft, *pt;
	struct tdma_cfg bad;
	struct tdma_port port = {0};
	static struct tdma_mac scratch;
	static struct tdma_mac_store scratch_store;
	int err, n;

	net_build(TDMA_PLAN_A, 1, 5, 0, NULL);
	net_start();
	ft = &s->nodes[FT].mac;
	pt = &s->nodes[1].mac;

	CHECK(tdma_send(pt, rd(FT), buf, 10, 0) == -ENOTCONN, "PT not associated");
	CHECK(tdma_send(ft, rd(1), buf, 10, 0) == -ENOTCONN, "unknown child");
	CHECK(tdma_start(ft) == -EALREADY, "double start");

	bad = s->nodes[FT].cfg;
	bad.rd_id = 0;
	CHECK(tdma_init(&scratch, &bad, &port) == -EINVAL, "port without callbacks");
	port = s->nodes[FT].mac.port;
	CHECK(tdma_init(&scratch, &bad, &port) == -EINVAL, "rd id 0");
	bad = s->nodes[FT].cfg;
	bad.plan_id = 77;
	CHECK(tdma_init(&scratch, &bad, &port) == -EINVAL, "unknown plan");
	bad = s->nodes[FT].cfg;
	bad.network_id = 0;
	CHECK(tdma_init(&scratch, &bad, &port) == -EINVAL, "network id 0");
	bad = s->nodes[FT].cfg;
	bad.mem = tdma_mem_of(&scratch_store);
	bad.mem.n_peers = 3; /* plan A has 4 positions */
	CHECK(tdma_init(&scratch, &bad, &port) == -EINVAL, "storage for fewer peers than the plan");
	bad.mem.n_peers = 4;
	bad.mem.n_chunks = (uint16_t)(tdma_mem_chunks(4, bad.mem.n_big) - 1);
	CHECK(tdma_init(&scratch, &bad, &port) == -EINVAL, "too little chunk memory");
	bad = s->nodes[FT].cfg;
	bad.mem = tdma_mem_of(&scratch_store);
	bad.evt_cb = noop_evt;
	CHECK(tdma_init(&scratch, &bad, &port) == 0, "valid cfg");

	/* scan only: beacons reported, no sync; then join that FT by rd id */
	tdma_pt_set_target(pt, TDMA_RD_BROADCAST);
	sim_run_until(s, FRAMES(10));
	CHECK(sim_count_evt(&s->nodes[1], TDMA_EVT_BEACON, 0) >= 5 &&
		      sim_count_evt(&s->nodes[1], TDMA_EVT_SYNCED, 0) == 0,
	      "scan only: %d beacons, %d syncs", sim_count_evt(&s->nodes[1], TDMA_EVT_BEACON, 0),
	      sim_count_evt(&s->nodes[1], TDMA_EVT_SYNCED, 0));
	CHECK(sim_find_evt(&s->nodes[1], TDMA_EVT_BEACON, 0, NULL)->rd_id == rd(FT), "scan rd");
	tdma_pt_set_target(pt, rd(FT) ^ 0x40); /* nobody */
	sim_run_until(s, FRAMES(20));
	CHECK(tdma_get_state(pt) == TDMA_ST_SEARCH, "other target: still searching");
	tdma_pt_set_target(pt, rd(FT));
	CHECK(wait_assoc(FRAMES(50)) != UINT64_MAX, "association");
	CHECK(tdma_pt_set_target(ft, 0) == -EINVAL, "FT has no target");
	CHECK(tdma_send(ft, rd(1), buf, TDMA_MAX_SDU + 1, 0) == -EMSGSIZE, "too big");
	CHECK(tdma_send(ft, rd(1), buf, 0, 0) == -EMSGSIZE, "empty");
	CHECK(tdma_send(pt, rd(1), buf, 10, 0) == -ENOTCONN, "PT to a non-parent");
	CHECK(tdma_send(ft, TDMA_RD_BROADCAST, buf, 10, 0) == 0, "FT broadcast");
	CHECK(tdma_send(pt, TDMA_RD_BROADCAST, buf, 10, 0) == 0, "PT broadcast -> parent");
	n = 0;
	while ((err = tdma_send(pt, rd(FT), buf, 64, 0)) == 0) {
		n++;
	}
	CHECK(err == -ENOBUFS && n == TDMA_TXQ_SDUS - 1, "queue full after %d (err %d)", n, err);
	CHECK(tdma_send(pt, rd(FT), buf, TDMA_MAX_SDU, 0) == -ENOBUFS, "no room for 1280 B");
	CHECK(tdma_link_mtu(pt, rd(FT)) == 64 && tdma_link_mtu(ft, rd(1)) == TDMA_SDU_PER_PDU_MAX &&
		      tdma_link_mtu(ft, 12345) == 0,
	      "link MTUs: PT %zu FT %zu", tdma_link_mtu(pt, rd(FT)), tdma_link_mtu(ft, rd(1)));

	/* stop: PT reports LOST(STOPPED) then STOPPED; the FT notices via UL timeout */
	uint64_t t0 = s->t;

	tdma_stop(pt);
	CHECK(sim_find_evt(&s->nodes[1], TDMA_EVT_LOST, t0, NULL) &&
		      sim_find_evt(&s->nodes[1], TDMA_EVT_LOST, t0, NULL)->cause ==
			      TDMA_CAUSE_STOPPED,
	      "LOST(STOPPED)");
	CHECK(sim_find_evt(&s->nodes[1], TDMA_EVT_STOPPED, t0, NULL), "STOPPED");
	CHECK(tdma_get_state(pt) == TDMA_ST_IDLE, "idle");
	sim_run_until(s, s->t + MS(300));
	CHECK(sim_count_evt(&s->nodes[FT], TDMA_EVT_CHILD_REMOVED, t0) == 1, "FT timed it out");
	tdma_stop(ft);
	CHECK(sim_find_evt(&s->nodes[FT], TDMA_EVT_STOPPED, t0, NULL), "FT STOPPED");
	sim_run_until(s, s->t + MS(50));
	CHECK(tdma_get_stats(ft)->ops_hwm <= 4 && tdma_get_stats(pt)->ops_hwm <= 4,
	      "ops in flight: FT %u PT %u", tdma_get_stats(ft)->ops_hwm,
	      tdma_get_stats(pt)->ops_hwm);
	printf("    ops in flight high-water mark: FT %u, PT %u\n", tdma_get_stats(ft)->ops_hwm,
	       tdma_get_stats(pt)->ops_hwm);
	check_clean();
}

/* ---- garbage on the air -----------------------------------------------------------------------
 */

static uint32_t injected;

static void inject(struct sim *sm, void *arg)
{
	struct sim_node *n;
	uint8_t hdr[TDMA_PHY_HDR_LEN], pl[TDMA_PKT_MAX];
	struct tdma_phy_hdr h;
	size_t len = sim_rand(sm) % (sizeof(pl) + 1);
	bool real_ids = sim_rand(sm) & 1;
	int k;

	(void)arg;
	n = &sm->nodes[sim_rand(sm) % (uint64_t)sm->n_nodes];
	if (sm->t < traffic_stop) {
		sim_at(sm, sm->t + MS(1) / 2, inject, NULL);
	}
	for (k = 0; k < SIM_NODE_OPS; k++) {
		if (n->ops[k].used && !n->ops[k].is_tx) {
			break;
		}
	}
	if (k == SIM_NODE_OPS) {
		return;
	}
	for (size_t i = 0; i < len; i++) {
		pl[i] = (uint8_t)sim_rand(sm);
	}
	for (size_t i = 0; i < sizeof(hdr); i++) {
		hdr[i] = (uint8_t)sim_rand(sm);
	}
	if (real_ids) {
		/* Plausible header from a real peer, but a malformed packet:
		 * the MAC must reject it without touching its state.
		 */
		int peer = n->id == FT ? 1 + (int)(sim_rand(sm) % (uint64_t)n_pts) : FT;
		uint8_t pos = n->id == FT ? (uint8_t)(peer - 1)
					  : (uint8_t)(n->mac.my_pos >= 0 ? n->mac.my_pos : 0);

		h = (struct tdma_phy_hdr){.subslots = 2,
					  .short_nwid = (uint8_t)sim_network_id(),
					  .tx_short = tdma_short_rd(rd(peer)),
					  .rx_short = n->id == FT ? tdma_short_rd(rd(FT))
								  : TDMA_SHORT_BROADCAST};
		tdma_phy_hdr_encode(&h, hdr, sizeof(hdr));
		len = len < 16 ? 16 : len;
		switch (sim_rand(sm) % 3) {
		case 0: /* record overruns the packet */
			pl[0] = (uint8_t)(len - 1);
			break;
		case 1: /* data PDU whose length field overruns its record */
			pl[0] = 12;
			pl[1] = pos;
			pl[2] = TDMA_PDU_DATA;
			pl[3] = 0;
			pl[7] = 200;
			pl[8] = 0;
			break;
		default: /* truncated beacon / ack / assoc record */
			pl[0] = 3;
			pl[1] = sim_rand(sm) & 1 ? TDMA_ADDR_ALL : pos;
			pl[2] = (uint8_t)(sim_rand(sm) % 4);
			pl[3] = 0;
			break;
		}
	}
	tdma_on_rx(&n->mac, n->ops[k].handle, sim_local(n, sm->t), -70, 80, hdr, sizeof(hdr), pl,
		   len, true);
	injected++;
}

void test_fuzz_rx(void)
{
	uint32_t bad = 0;
	uint64_t t0;

	net_build(TDMA_PLAN_A, 2, 99, 0, NULL);
	s->on_deliver = on_deliver;
	traffic_reset();
	net_start();
	t0 = wait_assoc(FRAMES(300));
	CHECK(t0 != UINT64_MAX, "association");
	traffic_stop = t0 + MS(5000);
	add_flows_all(64, MS(5), MS(10), t0);
	injected = 0;
	sim_at(s, t0, inject, NULL);
	sim_run_until(s, traffic_stop + MS(300));
	for (int i = 0; i < s->n_nodes; i++) {
		bad += tdma_get_stats(&s->nodes[i].mac)->bad_rx;
	}
	CHECK(n_lat == total_sent() && dups == 0 && corrupt == 0 && misrouted == 0,
	      "traffic intact: %zu/%u dups %u corrupt %u", n_lat, total_sent(), dups, corrupt);
	for (int i = 1; i <= n_pts; i++) {
		CHECK(sim_count_evt(&s->nodes[i], TDMA_EVT_LOST, t0) == 0, "PT %d lost", i);
	}
	CHECK(bad > injected / 2, "garbage counted as bad_rx (%u of %u)", bad, injected);
	printf("    %u garbage packets injected into live RX ops, %u counted as bad_rx (the rest "
	       "were ignored as foreign), link unaffected\n",
	       injected, bad);
	check_clean();
}

/* ---- seed sweep --------------------------------------------------------------------------------
 */

/* Many seeds of the contention and loss scenarios, to shake out rare orderings. */
void test_stress(void)
{
	int before = test_failures;
	uint64_t worst = 0;

	quiet = true;
	for (uint64_t seed = 1000; seed < 1100 && test_failures == before; seed++) {
		static const uint8_t plan[3] = {TDMA_PLAN_A, TDMA_PLAN_1X10, TDMA_PLAN_B};
		static const int pts[3] = {4, 10, 2};

		assoc_test(plan[seed % 3], pts[seed % 3], seed, 300);
		worst = s->t > worst ? s->t : worst;
	}
	printf("    100 contention runs (A/4, 1x10/10, B/2 PTs): slowest full association %.1f "
	       "ms\n",
	       (double)worst / 69120.0);
	for (uint64_t seed = 2000; seed < 2020 && test_failures == before; seed++) {
		lossy_traffic("stress A 10% loss", TDMA_PLAN_A, 4, (size_t)(16 + seed % 300),
			      MS(10), MS(20), MS(3000), seed);
	}
	printf("    20 lossy runs, 16-315 B SDUs: no duplicates, all losses accounted\n");
	for (uint64_t seed = 3000; seed < 3012 && test_failures == before; seed++) {
		lossy_traffic("stress H 10% loss", seed & 1 ? TDMA_PLAN_H : TDMA_PLAN_H4,
			      seed & 1 ? 2 : 4, (size_t)(16 + (seed * 97) % 1265), MS(20), MS(40),
			      MS(3000), seed);
	}
	printf("    12 lossy runs on H / H4, 16-1280 B SDUs: no duplicates, all losses "
	       "accounted\n");
	quiet = false;
	if (test_failures != before) {
		printf("    stress failed (see seed above)\n");
	}
}

/* ---- the fake PHY itself rejects what the real one rejects --------------------------------- */

void test_phy_model(void)
{
	struct tdma_port *p;
	uint8_t hdr[TDMA_PHY_HDR_LEN] = {0x21}, pl[200] = {0};
	uint64_t now, t;

	net_build(TDMA_PLAN_A, 1, 3, 0, NULL);
	sim_start(s, 1); /* PT: continuous search RX now */
	sim_run_until(s, MS(1));
	tdma_stop(&s->nodes[1].mac);
	sim_run_until(s, MS(2));
	p = &s->nodes[1].mac.port;
	now = p->now(p->ctx);

	CHECK(p->tx(p->ctx, 900, now + TDMA_US_TO_TICKS(455), 1, hdr, 10, pl, 10, 2, 3, 0, 0) ==
		      -ETIME,
	      "TX 455 us ahead rejected");
	CHECK(p->rx(p->ctx, 901, now + TDMA_US_TO_TICKS(385), 1000, 1) == -ETIME,
	      "RX 385 us ahead rejected");
	t = now + MS(2);
	CHECK(p->tx(p->ctx, 902, t, 1, hdr, 10, pl, 78, 2, 3, 0, 0) == -EMSGSIZE, "78 B > TBS 77");
	CHECK(p->tx(p->ctx, 903, t, 1, hdr, 10, pl, 77, 2, 3, 0, 0) == 0, "77 B at MCS 3, 2 ss");
	/* TX ends at t + 2 ss; TX->RX needs 245 us */
	CHECK(p->rx(p->ctx, 904, t + 2 * TDMA_SUBSLOT_TICKS + TDMA_US_TO_TICKS(240), 14400, 1) ==
		      -EBUSY,
	      "RX 240 us after TX rejected");
	CHECK(p->rx(p->ctx, 905, t + 2 * TDMA_SUBSLOT_TICKS + TDMA_US_TO_TICKS(250), 14400, 1) == 0,
	      "RX 250 us after TX accepted");
	CHECK(p->tx(p->ctx, 906, t - 2 * TDMA_SUBSLOT_TICKS - TDMA_US_TO_TICKS(280), 1, hdr, 10, pl,
		    10, 2, 3, 0, 0) == -EBUSY,
	      "TX 280 us before TX rejected");
	CHECK(p->tx(p->ctx, 907, now + 3 * TDMA_FRAME_TICKS, 1, hdr, 10, pl, 10, 2, 3, 0, 0) ==
		      -EINVAL,
	      "3 frames ahead rejected");
	/* LBT: the 2 ss window before the packet is part of the op (gap to the RX at 905) */
	CHECK(p->tx(p->ctx, 908, t + 6 * TDMA_SUBSLOT_TICKS, 1, hdr, 10, pl, 10, 2, 3,
		    2 * TDMA_SUBSLOT_TICKS, -71) == -EBUSY,
	      "TX whose LBT window starts 1 ss after an RX rejected");
	CHECK(p->tx(p->ctx, 909, t + 8 * TDMA_SUBSLOT_TICKS, 1, hdr, 10, pl, 10, 2, 3,
		    2 * TDMA_SUBSLOT_TICKS, -71) == 0,
	      "TX whose LBT window starts 2 ss after an RX accepted");
	CHECK(p->tx(p->ctx, 910, t + 16 * TDMA_SUBSLOT_TICKS, 1, hdr, 10, pl, 10, 2, 3, 2880,
		    -71) == -EINVAL,
	      "LBT of 1 symbol rejected");
	CHECK(sim_phy_errors(s) == 8, "8 violations counted (%u)", sim_phy_errors(s));
	printf("    fake PHY rejects: short lead (TX/RX), oversize payload, short gaps, far ahead, "
	       "LBT window inside a gap, LBT < 2 symbols\n");
}

/* ---- hybrid plans: grants, long bursts, fairness, floor under bulk, link MCS -------------------
 */

/* Latency of the samples whose flow index has bit set in mask. */
static void lat_report_flows(const char *name, uint32_t mask, uint64_t bound, struct lat_row *out)
{
	size_t n = 0;
	unsigned long long sum = 0;
	size_t le5 = 0;
	struct lat_row r = {0};

	for (size_t i = 0; i < n_lat; i++) {
		if (mask & (1u << lat_flow[i])) {
			lat_tmp[n++] = lat[i];
		}
	}
	snprintf(r.name, sizeof(r.name), "%s", name);
	for (int i = 0; i < n_flows; i++) {
		if (mask & (1u << i)) {
			r.sent += flows[i].sent;
		}
	}
	r.delivered = (unsigned int)n;
	r.dropped = total_sdu_drops();
	r.dups = dups;
	r.bound = bound;
	if (n) {
		qsort(lat_tmp, n, sizeof(lat_tmp[0]), cmp_u32);
		for (size_t i = 0; i < n; i++) {
			sum += lat_tmp[i];
			le5 += lat_tmp[i] <= MS(5);
		}
		r.min = lat_tmp[0];
		r.max = lat_tmp[n - 1];
		r.avg = sum / n;
		r.p99 = lat_tmp[(n * 99) / 100 < n ? (n * 99) / 100 : n - 1];
		r.pct_5ms = 100.0 * (double)le5 / (double)n;
	}
	*out = r;
	printf("    %s: sent %u delivered %u | min %llu us avg %llu us p99 %llu us max %llu us | "
	       "bound %llu us\n",
	       name, r.sent, r.delivered, US(r.min), US(r.avg), US(r.p99), US(r.max), US(bound));
	lat_table_add(&r);
}

static void flex_stats(void)
{
	printf("    grants: DL %u, UL %u (%u a period ahead), speculative %u; long bursts tx %u rx "
	       "%u, "
	       "missed %u; retx %u, dup rx %u, no reassembly buffer %u\n",
	       STAT(grants_dl), STAT(grants_ul), STAT(grants_ahead), STAT(grants_spec),
	       STAT(flex_tx), STAT(flex_rx), STAT(flex_miss), STAT(retx), STAT(dup_rx),
	       STAT(ras_full));
}

static void hybrid_net(uint8_t plan, int pts, uint64_t seed)
{
	/* a pattern plan (T2) has no UL slot to associate in: start in H, then switch */
	bool pat = (tdma_plan_get(plan)->flags & TDMA_PLAN_F_PATTERN) != 0;

	net_build(pat ? TDMA_PLAN_H : plan, pts, seed, 0, NULL);
	s->on_deliver = on_deliver;
	traffic_reset();
	net_start();
	CHECK(wait_assoc(FRAMES(300)) != UINT64_MAX, "association");
	if (pat) {
		CHECK(tdma_ft_set_plan(&s->nodes[0].mac, plan) == 0, "switch to plan %u", plan);
		sim_run_until(s, s->t + FRAMES(TDMA_PLAN_ANNOUNCE_FRAMES + 2));
		CHECK(s->nodes[0].mac.plan->id == plan && s->nodes[1].mac.plan->id == plan,
		      "plan %u in use", plan);
	}
}

void test_hybrid_plan(void)
{
	const struct tdma_plan *h = tdma_plan_get(TDMA_PLAN_H), *h4 = tdma_plan_get(TDMA_PLAN_H4);
	uint8_t buf[64];
	int n;

	CHECK(h && tdma_plan_validate(h) == 0 && tdma_plan_has_flex(h), "plan H valid");
	CHECK(h4 && tdma_plan_validate(h4) == 0, "plan H4 valid");
	const struct tdma_plan *tp = tdma_plan_get(TDMA_PLAN_T);

	CHECK(tp && tdma_plan_validate(tp) == 0 && tdma_plan_has_train(tp) &&
		      !tdma_plan_has_train(h),
	      "plan T valid, has a train; H has none");
	const struct tdma_plan *t4 = tdma_plan_get(TDMA_PLAN_T4);

	CHECK(t4 && tdma_plan_validate(t4) == 0 && tdma_plan_has_train(t4) && t4->n_positions == 4,
	      "plan T4 valid, 4 positions, has a train");
	CHECK(tdma_plan_max_gap_ticks(t4, 3, TDMA_SLOT_UL) == 48 * TDMA_SUBSLOT_TICKS,
	      "T4: guaranteed UL once per frame for every position");
	CHECK(tdma_plan_max_gap_ticks(tp, 1, TDMA_SLOT_UL) == 48 * TDMA_SUBSLOT_TICKS,
	      "T: guaranteed UL once per frame");
	CHECK(!tdma_plan_has_flex(tdma_plan_get(TDMA_PLAN_B)), "B has no flex");
	CHECK(tdma_plan_max_gap_ticks(h, 0, TDMA_SLOT_DL) == 24 * TDMA_SUBSLOT_TICKS &&
		      tdma_plan_max_gap_ticks(h, 1, TDMA_SLOT_UL) == 24 * TDMA_SUBSLOT_TICKS,
	      "H: guaranteed DL/UL every 5 ms");

	/* FLEX regions the validator must refuse */
	static const struct tdma_slot flex_close[] = {
		{0, 3, TDMA_SLOT_BEACON, 0}, {5, 2, TDMA_SLOT_UL, 0}, {8, 4, TDMA_SLOT_FLEX, 0}};
	static const struct tdma_slot flex_early[] = {
		{0, 3, TDMA_SLOT_BEACON, 0}, {5, 4, TDMA_SLOT_FLEX, 0}, {11, 2, TDMA_SLOT_UL, 0}};
	static const struct tdma_slot flex_ok[] = {
		{0, 3, TDMA_SLOT_BEACON, 0}, {5, 2, TDMA_SLOT_UL, 0}, {12, 10, TDMA_SLOT_FLEX, 0}};
	static const struct tdma_slot flex_dl_close[] = {{0, 3, TDMA_SLOT_BEACON, 0},
							 {5, 2, TDMA_SLOT_UL, 0},
							 {12, 10, TDMA_SLOT_FLEX, 0},
							 {25, 3, TDMA_SLOT_DL, 0}};
	static const struct tdma_slot flex_rx_close[] = {{0, 3, TDMA_SLOT_BEACON, 0},
							 {5, 2, TDMA_SLOT_UL, 0},
							 {9, 1, TDMA_SLOT_UL, 0},
							 {12, 10, TDMA_SLOT_FLEX, 0}};
	static const struct tdma_slot flex_wrap[] = {{0, 3, TDMA_SLOT_BEACON, 0},
						     {5, 2, TDMA_SLOT_UL, 0},
						     {9, 16, TDMA_SLOT_FLEX, 0},
						     {27, 2, TDMA_SLOT_FLEX, 0}};
	/* a DL long burst to the next DL TX: 3 ss; an UL long burst must end 5 ss before it */
	static const struct tdma_slot flex_ul_short[] = {{0, 3, TDMA_SLOT_BEACON, 0},
							 {5, 2, TDMA_SLOT_UL, 0},
							 {12, 8, TDMA_SLOT_FLEX, 0, 0, 7},
							 {25, 3, TDMA_SLOT_DL, 0}};
	static const struct tdma_slot flex_dl_rx4[] = {{0, 3, TDMA_SLOT_BEACON, 0},
						       {5, 2, TDMA_SLOT_UL, 0},
						       {12, 9, TDMA_SLOT_FLEX, 0, 0, 7},
						       {25, 3, TDMA_SLOT_DL, 0}};
	static const struct tdma_slot flex_ul_4[] = {{0, 3, TDMA_SLOT_BEACON, 0},
						     {5, 2, TDMA_SLOT_UL, 0},
						     {12, 10, TDMA_SLOT_FLEX, 0, 0, 9},
						     {25, 3, TDMA_SLOT_DL, 0}};
	static const struct tdma_slot flex_ul_early3[] = {{0, 3, TDMA_SLOT_BEACON, 0},
							  {5, 2, TDMA_SLOT_UL, 0},
							  {14, 8, TDMA_SLOT_FLEX, 0, 3, 7},
							  {25, 3, TDMA_SLOT_DL, 0}};
	/* trains: 2 ss between the regions, no early UL extent inside, one DL burst for them all */
	static const struct tdma_slot train_close[] = {{0, 3, TDMA_SLOT_BEACON, 0},
						       {5, 2, TDMA_SLOT_UL, 0},
						       {13, 8, TDMA_SLOT_FLEX, 0},
						       {22, 8, TDMA_SLOT_FLEX, 0}};
	static const struct tdma_slot train_ok[] = {{0, 3, TDMA_SLOT_BEACON, 0},
						    {5, 2, TDMA_SLOT_UL, 0},
						    {13, 8, TDMA_SLOT_FLEX, 0},
						    {23, 8, TDMA_SLOT_FLEX, 0}};
	static const struct tdma_slot train_early[] = {{0, 3, TDMA_SLOT_BEACON, 0},
						       {5, 2, TDMA_SLOT_UL, 0},
						       {13, 8, TDMA_SLOT_FLEX, 0},
						       {24, 7, TDMA_SLOT_FLEX, 0, 1, 8}};
	static const struct tdma_slot flex_no_dl[] = {{0, 3, TDMA_SLOT_BEACON, 0},
						      {5, 2, TDMA_SLOT_UL, 0},
						      {13, 6, TDMA_SLOT_FLEX, 0},
						      {24, 2, TDMA_SLOT_UL, 0},
						      {28, 6, TDMA_SLOT_FLEX, 0}};
	static const struct tdma_slot long_dl_ul[] = {{0, 8, TDMA_SLOT_BEACON, 0},
						      {10, 2, TDMA_SLOT_UL, 0}};
	struct tdma_plan p = {9, 1, 3, 4, flex_close, "x", 0};

	CHECK(tdma_plan_validate(&p) == -EINVAL, "FLEX 1 ss after an UL burst");
	p.slots = flex_early;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "FLEX before the PTs can know their grant");
	p.slots = flex_ok;
	CHECK(tdma_plan_validate(&p) == 0, "minimal hybrid plan");
	p.slots = flex_wrap;
	p.n_slots = 4;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "FLEX without a DL burst of its own");
	p.slots = flex_dl_close;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "DL 3 ss after an UL long burst (needs 5)");
	p.slots = flex_ul_short;
	CHECK(tdma_plan_validate(&p) == 0, "DL 5 ss after a DL long burst, 6 after an UL one");
	p.slots = flex_dl_rx4;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "PT's DL RX 4 ss after a DL long burst");
	p.slots = flex_ul_4;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "DL 4 ss after an UL long burst");
	p.slots = flex_ul_early3;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "UL long burst 3 ss before its region");
	p.slots = long_dl_ul;
	p.n_slots = 2;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "PT TX 2 ss after a received 8 ss DL burst");
	p.n_slots = 4;
	p.slots = flex_rx_close;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "FLEX 2 ss after the UL run (needs 3)");
	p.slots = train_ok;
	CHECK(tdma_plan_validate(&p) == 0, "train: 2 ss between two long bursts");
	p.slots = train_close;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "train: 1 ss between two long bursts");
	p.slots = train_early;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "train: early UL extent inside a train");
	p.slots = flex_no_dl;
	p.n_slots = 5;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "FLEX after an UL slot without its own DL burst");
	p.n_slots = 4;

	/* grant / status / wide ack codecs */
	struct tdma_grant g = {.n = 2,
			       .e = {{1, TDMA_GRANT_F_UL, 12, 8, 4},
				     {0, TDMA_GRANT_F_SPEC, 36, 10, 3}}},
			  g2;
	n = tdma_grant_encode(&g, buf, sizeof(buf));
	CHECK(n == TDMA_GRANT_FIXED_LEN + 2 * TDMA_GRANT_ENTRY_LEN &&
		      tdma_grant_decode(buf, (size_t)n, &g2) == 0 && g2.n == 2 &&
		      g2.e[0].pos == 1 && g2.e[0].flags == TDMA_GRANT_F_UL && g2.e[1].start == 36 &&
		      g2.e[1].len == 10 && g2.e[1].mcs == 3,
	      "grant round trip");
	CHECK(tdma_grant_decode(buf, (size_t)n - 1, &g2) == -EINVAL, "short grant");
	buf[TDMA_GRANT_FIXED_LEN + 3] = 9; /* 9 ss at MCS 4: above the largest transport block */
	CHECK(tdma_grant_decode(buf, (size_t)n, &g2) == -EINVAL, "grant beyond 700 B");
	struct tdma_status st = {.queued = 1234, .snr = -7, .rssi = -60}, st2;

	n = tdma_status_encode(&st, buf, sizeof(buf));
	CHECK(n == TDMA_STATUS_LEN && tdma_status_decode(buf, (size_t)n, &st2) == 0 &&
		      st2.queued == 1234 && st2.snr == -7 && st2.rssi == -60,
	      "status round trip");
	struct tdma_ack a = {true, 9, 0xa55a, true}, a2;

	n = tdma_ack_encode(&a, buf, sizeof(buf));
	CHECK(n == TDMA_ACK_LEN + 1 && tdma_ack_decode(buf, (size_t)n, &a2) == 0 && a2.wide &&
		      a2.ack_map == 0xa55a,
	      "wide ack");
	CHECK(tdma_ack_decode(buf, TDMA_ACK_LEN, &a2) == -EINVAL, "wide ack truncated");
	uint8_t pl[40] = {1, 2, 3};
	struct tdma_data d = {.seq = 4,
			      .ack = {true, 3, 0x8001, true},
			      .frag = true,
			      .frag_tag = 5,
			      .frag_off = 40,
			      .frag_total = 120,
			      .len = 40,
			      .payload = pl},
			 d2;

	n = tdma_data_encode(&d, buf, sizeof(buf));
	CHECK(n == TDMA_DATA_HDR_LEN + 1 + TDMA_FRAG_HDR_LEN + 40 &&
		      tdma_data_decode(buf, (size_t)n, &d2) == 0 && d2.ack.wide &&
		      d2.ack.ack_map == 0x8001 && d2.frag_off == 40 && d2.frag_total == 120 &&
		      memcmp(d2.payload, pl, 40) == 0,
	      "wide data round trip");

	/* MCS selection: thresholds 6/9/12/16 dB up, 3 dB hysteresis down, cap */
	CHECK(tdma_mcs_select(0, 22 * 4, 4) == 4 && tdma_mcs_select(4, 22 * 4, 3) == 3 &&
		      tdma_mcs_select(4, 14 * 4, 4) == 4 && tdma_mcs_select(4, 12 * 4, 4) == 3 &&
		      tdma_mcs_select(2, 10 * 4, 4) == 2 && tdma_mcs_select(3, 10 * 4, 4) == 3 &&
		      tdma_mcs_select(3, 8 * 4, 4) == 1 && tdma_mcs_select(1, 2 * 4, 4) == 0,
	      "MCS thresholds / hysteresis");
	{
		uint8_t m = 4, changes = 0;

		for (int i = 0; i < 1000; i++) { /* 15-17 dB noise around the MCS 4 threshold */
			uint8_t m2 = tdma_mcs_select(m, (int16_t)(60 + (i * 7919) % 9), 4);

			changes += m2 != m;
			m = m2;
		}
		CHECK(changes == 0 && m == 4, "no flapping at the threshold (%u)", changes);
	}
	printf("    plans H / H4 valid, flex validator, grant/status/wide codecs, MCS "
	       "hysteresis\n");
}

/*
 * Bulk SDUs every gap ms in one direction on plan H, one flow per PT; asserts
 * delivery and the given latency bounds (us).
 */
static void bulk_test(const char *name, uint8_t plan, int pts, bool dl, size_t len, uint64_t gap,
		      uint64_t max_us, uint64_t avg_us)
{
	struct lat_row r;
	uint64_t t0;

	hybrid_net(plan, pts, 300 + len + dl);
	t0 = s->t;
	traffic_stop = t0 + MS(10000);
	for (int i = 1; i <= pts; i++) {
		if (dl) {
			add_flow(FT, i, len, gap, gap, t0 + MS(20));
		} else {
			add_flow(i, FT, len, gap, gap, t0 + MS(20));
		}
	}
	sim_run_until(s, traffic_stop + MS(300));
	lat_report(name, dl ? DIR_DL : DIR_UL, MS(max_us) / 1000, &r);
	flex_stats();
	CHECK(r.delivered == r.sent && r.sent > 100 && dups == 0 && corrupt == 0 && misrouted == 0,
	      "all delivered (%u/%u) dups %u corrupt %u", r.delivered, r.sent, dups, corrupt);
	CHECK(STAT(retx) == 0, "no retransmissions on a clean channel (%u)", STAT(retx));
	CHECK(r.max <= MS(max_us) / 1000 + test_slack_bulk, "max %llu us > %llu us", US(r.max),
	      (unsigned long long)max_us);
	CHECK(r.avg <= MS(avg_us) / 1000 + test_slack_bulk, "avg %llu us > %llu us", US(r.avg),
	      (unsigned long long)avg_us);
	CHECK(STAT(flex_miss) == 0, "every demanded long burst arrived (%u)", STAT(flex_miss));
	check_clean();
}

void test_grant_ul(void)
{
	/* plan H's UL long bursts are 6 ss (503 B) since the 5 ss long-RX -> TX rule */
	bulk_test("H UL 1000 B, 1 PT", TDMA_PLAN_H, 1, false, 1000, MS(50), 18000, 15500);
	bulk_test("H UL 1280 B, 1 PT", TDMA_PLAN_H, 1, false, 1280, MS(50), 19500, 16000);
	bulk_test("H UL 1000 B, 2 PTs", TDMA_PLAN_H, 2, false, 1000, MS(50), 28000, 17500);
	bulk_test("H UL 1280 B, 2 PTs", TDMA_PLAN_H, 2, false, 1280, MS(50), 33000, 21000);
	bulk_test("H4 UL 1000 B, 4 PTs", TDMA_PLAN_H4, 4, false, 1000, MS(100), 50000, 32000);
}

void test_flex_dl(void)
{
	bulk_test("H DL 1000 B, 1 PT", TDMA_PLAN_H, 1, true, 1000, MS(50), 16500, 13500);
	bulk_test("H DL 1280 B, 1 PT", TDMA_PLAN_H, 1, true, 1280, MS(50), 18500, 15500);
	bulk_test("H DL 1000 B, 2 PTs", TDMA_PLAN_H, 2, true, 1000, MS(50), 27000, 15000);
	bulk_test("H DL 1280 B, 2 PTs", TDMA_PLAN_H, 2, true, 1280, MS(50), 31000, 17500);
}

/* Small traffic on plan H: the guaranteed bound, plus what the flex region adds. */
void test_hybrid_small(void)
{
	latency_test(TDMA_PLAN_H, 2, "H, 2 PTs, 64 B", false);
	latency_test(TDMA_PLAN_H4, 4, "H4, 4 PTs, 64 B", false);
	latency_test(TDMA_PLAN_T, 2, "T, 2 PTs, 64 B", false);
	latency_test(TDMA_PLAN_BQ, 2, "BQ, 2 PTs, 64 B", true);
	/* commit lead trims as a DK application would set them: UL bound -300 us */
	test_ul_trim_us = 300;
	test_dl_trim_us = 150;
	latency_test(TDMA_PLAN_BQ, 2, "BQ, trimmed leads, 64 B", true);
	latency_test(TDMA_PLAN_H, 2, "H, trimmed leads, 64 B", false);
	test_ul_trim_us = test_dl_trim_us = 0;
}

/* Bulk both ways with 10 % loss on every link: ARQ over the long bursts. */
void test_bulk_loss(void)
{
	struct lat_row r;
	uint32_t sent, drops;

	hybrid_net(TDMA_PLAN_H, 2, 51);
	sim_set_loss_all(s, 100000);
	traffic_stop = s->t + MS(20000);
	add_flows_all(1200, MS(40), MS(40), s->t + MS(20));
	sim_run_until(s, traffic_stop + MS(500));
	for (int k = 0; k < 100 && queued_pdus(); k++) {
		sim_run_until(s, s->t + MS(100));
	}
	CHECK(queued_pdus() == 0, "queues drained (%u)", queued_pdus());
	lat_report("H, 1200 B both ways, 10% loss", DIR_ALL, 0, &r);
	flex_stats();
	sent = total_sent();
	drops = total_sdu_drops();
	CHECK(dups == 0 && corrupt == 0 && misrouted == 0, "dups %u corrupt %u misrouted %u", dups,
	      corrupt, misrouted);
	CHECK(r.delivered + drops >= sent && r.delivered <= sent && r.delivered * 100 >= sent * 97,
	      "delivered %u + dropped %u of %u", r.delivered, drops, sent);
	CHECK(STAT(retx) > 0, "loss was repaired by ARQ (%u retransmissions)", STAT(retx));
	for (int i = 1; i <= n_pts; i++) {
		CHECK(sim_count_evt(&s->nodes[i], TDMA_EVT_LOST, 0) == 0, "PT %d lost", i);
	}
	CHECK(misordered == 0, "%u SDUs delivered out of order", misordered);
	check_clean();

	/*
	 * Saturated 1280 B both ways on 1 PT at 10 % loss: several fragmented SDUs
	 * in flight per link, cut to every burst size, resent shortened. Every SDU
	 * arrives once, intact and in order, or is counted as given up.
	 */
	hybrid_net(TDMA_PLAN_H, 1, 52);
	sim_set_loss_all(s, 100000);
	traffic_stop = s->t + MS(10000);
	add_flow(FT, 1, TDMA_MAX_SDU, MS(1) / 4, 1, s->t);
	flows[n_flows - 1].saturate = true;
	add_flow(1, FT, TDMA_MAX_SDU, MS(1) / 4, 1, s->t);
	flows[n_flows - 1].saturate = true;
	sim_run_until(s, traffic_stop + MS(500));
	for (int k = 0; k < 100 && queued_pdus(); k++) {
		sim_run_until(s, s->t + MS(100));
	}
	lat_report("H, 1 PT, 1280 B saturated both ways, 10% loss", DIR_ALL, 0, &r);
	flex_stats();
	sent = total_sent();
	drops = total_sdu_drops();
	CHECK(dups == 0 && corrupt == 0 && misrouted == 0 && misordered == 0,
	      "dups %u corrupt %u misrouted %u misordered %u", dups, corrupt, misrouted,
	      misordered);
	CHECK(r.delivered + drops >= sent && r.delivered <= sent && r.delivered * 100 >= sent * 95,
	      "delivered %u + dropped %u of %u", r.delivered, drops, sent);
	check_clean();
}

/* Jain's index and min/max over the flows selected by mask. */
static double jain_of(uint32_t mask, uint64_t *lo, uint64_t *hi)
{
	double sum = 0, sq = 0;
	int n = 0;

	*lo = UINT64_MAX;
	*hi = 0;
	for (int i = 0; i < n_flows; i++) {
		uint64_t b = flows[i].bytes;

		if (!(mask & (1u << i))) {
			continue;
		}
		*lo = b < *lo ? b : *lo;
		*hi = b > *hi ? b : *hi;
		sum += (double)b;
		sq += (double)b * (double)b;
		n++;
	}
	return sq > 0 ? sum * sum / ((double)n * sq) : 0;
}

/*
 * Every flow saturated: the PTs get the same share. Per direction, every flow
 * must get the same bytes (the guaranteed DL burst is shared by all PTs while
 * every PT has its own UL slot, so DL and UL flows differ by design).
 */
static void fair_test(uint8_t plan, int pts, const char *name)
{
	uint64_t lo, hi, lo2, hi2, t0;
	uint32_t dl = 0, ul = 0;
	double jd, ju, jp;

	hybrid_net(plan, pts, 60 + (uint64_t)pts);
	t0 = s->t;
	traffic_stop = t0 + MS(10000);
	add_flows_all(1000, MS(1), MS(1), t0); /* far above capacity: queues stay full */
	sim_run_until(s, traffic_stop);
	for (int i = 0; i < n_flows; i++) {
		if (flows[i].src == FT) {
			dl |= 1u << i;
		} else {
			ul |= 1u << i;
		}
	}
	jd = jain_of(dl, &lo, &hi);
	ju = jain_of(ul, &lo2, &hi2);
	{
		double sum = 0, sq = 0;

		for (int k = 0; k < pts; k++) {
			double b = (double)(flows[2 * k].bytes + flows[2 * k + 1].bytes);

			sum += b;
			sq += b * b;
		}
		jp = sum * sum / ((double)pts * sq);
	}
	printf("    %s: DL %llu..%llu kB/s per PT (Jain %.3f), UL %llu..%llu kB/s (Jain %.3f), "
	       "per-PT Jain %.3f\n",
	       name, (unsigned long long)(lo / 10000), (unsigned long long)(hi / 10000), jd,
	       (unsigned long long)(lo2 / 10000), (unsigned long long)(hi2 / 10000), ju, jp);
	flex_stats();
	CHECK(jd >= 0.98 && ju >= 0.98 && jp >= 0.98 && lo * 10 >= hi * 8 && lo2 * 10 >= hi2 * 8,
	      "unfair: DL %.3f UL %.3f PT %.3f", jd, ju, jp);
	CHECK(dups == 0 && corrupt == 0 && misrouted == 0, "dups %u corrupt %u", dups, corrupt);
	check_clean();
}

void test_fair(void)
{
	fair_test(TDMA_PLAN_H, 2, "H, 2 PTs saturated both ways");
	fair_test(TDMA_PLAN_H4, 4, "H4, 4 PTs saturated both ways");
	fair_test(TDMA_PLAN_T, 2, "T, 2 PTs saturated both ways");
}

/*
 * The latency floor survives bulk: every link saturated with 1000 B SDUs
 * while 64 B SDUs (prio, as the net layer sends packets that fit one PDU)
 * run both ways. They must stay within the guaranteed-slot bound.
 */
static void floor_test(uint8_t plan, int pts, const char *name)
{
	const struct tdma_plan *p = tdma_plan_get(plan);
	uint64_t gap = tdma_plan_max_gap_ticks(p, 0, TDMA_SLOT_DL), t0;
	uint64_t b = bound_dir(plan, DIR_DL) > bound_dir(plan, DIR_UL) ? bound_dir(plan, DIR_DL)
								       : bound_dir(plan, DIR_UL);
	uint32_t mask = 0;
	struct lat_row r;

	hybrid_net(plan, pts, 70 + (uint64_t)pts);
	t0 = s->t;
	traffic_stop = t0 + MS(10000);
	add_flows_all(1000, MS(2), MS(2), t0);
	/* as latency_test: one DL flow to a random PT, one UL flow per PT */
	mask |= 1u << n_flows;
	add_flow(FT, -1, 64, gap, 3 * gap, t0 + MS(50));
	flows[n_flows - 1].prio = 1;
	for (int i = 1; i <= pts; i++) {
		mask |= 1u << n_flows;
		add_flow(i, FT, 64, gap, 3 * gap, t0 + MS(50));
		flows[n_flows - 1].prio = 1;
	}
	sim_run_until(s, traffic_stop + MS(300));
	lat_report_flows(name, mask, b, &r);
	flex_stats();
	CHECK(r.delivered == r.sent && r.sent > 500, "small SDUs delivered (%u/%u)", r.delivered,
	      r.sent);
	CHECK(r.max <= b + test_slack_small, "small max %llu us > guaranteed bound %llu us",
	      US(r.max), US(b + test_slack_small));
	check_clean();
}

void test_floor_bulk(void)
{
	floor_test(TDMA_PLAN_H, 2, "H, 64 B under 1000 B bulk");
	floor_test(TDMA_PLAN_H4, 4, "H4, 64 B under 1000 B bulk");
	floor_test(TDMA_PLAN_T, 2, "T, 64 B under 1000 B bulk");
}

/*
 * Per-link MCS: network (guaranteed slots) at MCS 2; PT 1 has 25 dB, PT 2
 * 9 dB. Long bursts must go out at MCS 4 to PT 1 and stay at MCS 2 to PT 2
 * (MCS 3/4 would be lost there). Then PT 1's link drops to 11 dB: down to 2.
 */
void test_link_mcs(void)
{
	struct lat_row r;
	uint64_t t0;

	net_build(TDMA_PLAN_H, 2, 81, 0, NULL);
	s->nodes[FT].cfg.mcs = 2;
	sim_set_snr(s, FT, 1, 25);
	sim_set_snr(s, FT, 2, 9);
	s->on_deliver = on_deliver;
	traffic_reset();
	net_start();
	CHECK(wait_assoc(FRAMES(300)) != UINT64_MAX, "association");
	t0 = s->t;
	traffic_stop = t0 + MS(5000);
	add_flows_all(1000, MS(40), MS(20), t0 + MS(20));
	sim_run_until(s, t0 + MS(2500));
	{
		const struct tdma_mac *ft = &s->nodes[FT].mac;

		printf("    MCS DL/UL: PT 1 (25 dB) %u/%u, PT 2 (9 dB) %u/%u\n",
		       tdma_link_mcs(ft, rd(1), true), tdma_link_mcs(ft, rd(1), false),
		       tdma_link_mcs(ft, rd(2), true), tdma_link_mcs(ft, rd(2), false));
		CHECK(tdma_link_mcs(ft, rd(1), true) == 4 && tdma_link_mcs(ft, rd(1), false) == 4,
		      "PT 1 up to MCS 4");
		CHECK(tdma_link_mcs(ft, rd(2), true) == 2 && tdma_link_mcs(ft, rd(2), false) == 2,
		      "PT 2 stays at MCS 2");
	}
	sim_set_snr(s, FT, 1, 8);
	sim_run_until(s, traffic_stop + MS(500));
	for (int k = 0; k < 50 && queued_pdus(); k++) {
		sim_run_until(s, s->t + MS(100));
	}
	CHECK(tdma_link_mcs(&s->nodes[FT].mac, rd(1), true) <= 2 &&
		      tdma_link_mcs(&s->nodes[FT].mac, rd(1), false) <= 2,
	      "PT 1 down to MCS <= 2 at 8 dB (%u/%u)",
	      tdma_link_mcs(&s->nodes[FT].mac, rd(1), true),
	      tdma_link_mcs(&s->nodes[FT].mac, rd(1), false));
	printf("    PT 1 after 25 -> 8 dB: MCS DL/UL %u/%u\n",
	       tdma_link_mcs(&s->nodes[FT].mac, rd(1), true),
	       tdma_link_mcs(&s->nodes[FT].mac, rd(1), false));
	lat_report("H, per-link MCS, 1000 B", DIR_ALL, 0, &r);
	flex_stats();
	printf("    receptions lost to SNR < MCS need: %u (only around the 25 -> 8 dB step)\n",
	       s->st.lost_snr);
	CHECK(dups == 0 && corrupt == 0 && r.delivered + total_sdu_drops() >= r.sent,
	      "delivered %u of %u", r.delivered, r.sent);
	CHECK(total_sdu_drops() <= 2, "SDU drops %u", total_sdu_drops());
	check_clean();
}

/* ---- request / response (ping) over long bursts ---------------------------------------------- */

static uint32_t echo_n;
static uint64_t echo_sum, echo_max, echo_min;
static uint32_t echo_rtt[4096];

static void echo_deliver(struct sim *sm, int node, uint32_t src, const uint8_t *data, size_t len)
{
	uint64_t t0;

	if (node == FT) { /* echo it back, like an ICMPv6 echo reply */
		for (int i = 1; i < sm->n_nodes; i++) {
			if (sm->nodes[i].cfg.rd_id == src) {
				sim_send(sm, FT, src, data, len, 0);
			}
		}
		return;
	}
	memcpy(&t0, &data[8], 8);
	if (echo_n < 4096) {
		echo_rtt[echo_n] = (uint32_t)(sm->t - t0);
	}
	echo_n++;
	echo_sum += sm->t - t0;
	echo_max = sm->t - t0 > echo_max ? sm->t - t0 : echo_max;
	echo_min = sm->t - t0 < echo_min ? sm->t - t0 : echo_min;
}

static void echo_test(uint8_t plan, size_t len, uint64_t max_us, uint64_t med_us)
{
	char nm[48];
	struct lat_row r = {0};
	uint32_t n;

	hybrid_net(plan, 1, 900 + len);
	s->on_deliver = echo_deliver;
	echo_n = 0;
	echo_sum = echo_max = 0;
	echo_min = UINT64_MAX;
	traffic_stop = s->t + MS(5000);
	add_flow(1, FT, len, MS(100), MS(20), s->t + MS(20)); /* ping -i 100 */
	sim_run_until(s, traffic_stop + MS(300));
	n = echo_n < 4096 ? echo_n : 4096;
	qsort(echo_rtt, n, sizeof(echo_rtt[0]), cmp_u32);
	snprintf(nm, sizeof(nm), "%s RTT %zu B echo", tdma_plan_get(plan)->name, len);
	memcpy(r.name, nm, sizeof(r.name) - 1);
	r.name[sizeof(r.name) - 1] = 0;
	r.sent = flows[0].sent;
	r.delivered = echo_n;
	r.min = echo_min;
	r.avg = n ? echo_rtt[n / 2] : 0; /* median in the avg column */
	r.p99 = n ? echo_rtt[(n * 99) / 100] : 0;
	r.max = echo_max;
	lat_table_add(&r);
	printf("    %s: %u/%u, min %llu median %llu max %llu us\n", nm, echo_n, flows[0].sent,
	       US(echo_min), US(r.avg), US(echo_max));
	flex_stats();
	CHECK(echo_n == flows[0].sent && echo_n > 40, "all echoed (%u/%u)", echo_n, flows[0].sent);
	CHECK(r.max <= MS(max_us) / 1000 + 2 * test_slack_bulk &&
		      r.avg <= MS(med_us) / 1000 + 2 * test_slack_bulk,
	      "RTT median %llu max %llu us", US(r.avg), US(r.max));
	check_clean();
}

void test_echo(void)
{
	echo_test(TDMA_PLAN_H, 64, 15000, 10000);
	echo_test(TDMA_PLAN_H, 1000, 30000, 26000);
	echo_test(TDMA_PLAN_H, 1200, 40000, 30000);
	echo_test(TDMA_PLAN_B, 1000, 90000, 80000);
}

/* ---- throughput (saturated queues) ------------------------------------------------------------
 */

/*
 * Saturated throughput: the senders offer SDUs every 0.25 ms (far above
 * capacity, so the MAC queues stay full and -ENOBUFS paces them, like the
 * firmware's `tdma perf raw`). Bytes delivered between 1 s and 9 s of
 * traffic, per direction, in kB/s (1000 B/s); latency from acceptance by
 * tdma_send() to delivery. dirs: DIR_DL, DIR_UL or both.
 */
struct thr_res {
	unsigned int dl, ul; /* kB/s */
	unsigned int lb_eff; /* SDU bytes in long bursts, % of their TBS (no security) */
	unsigned int lb_hdr; /* ... % of the bytes sent in them (records + MIC reserve) */
	uint64_t avg, p99, max;
};

/* Long bursts (>= 5 ss) on air: transport block bytes, and SDU bytes in their data PDUs. */
static uint64_t thr_lb_tbs, thr_lb_sdu, thr_lb_used;
static bool thr_lb_on;

static void thr_on_air(struct sim *sm, int node, uint64_t t_start, uint16_t ch, const uint8_t *hdr,
		       const uint8_t *pl, size_t len, uint8_t subslots, uint8_t mcs)
{
	size_t off = 0, plen;
	const uint8_t *pdu;
	uint8_t addr;
	struct tdma_data d;

	(void)sm;
	(void)node;
	(void)t_start;
	(void)ch;
	(void)hdr;
	if (!thr_lb_on || subslots < 5) {
		return;
	}
	thr_lb_tbs += tdma_tbs(mcs, subslots);
	while (tdma_rec_next(pl, len, &off, &addr, &pdu, &plen) == 1) {
		if (tdma_pdu_type(pdu, plen) == TDMA_PDU_DATA &&
		    tdma_data_decode(pdu, plen, &d) == 0) {
			thr_lb_sdu += d.len;
		}
	}
	thr_lb_used += off + TDMA_MIC_RESERVE;
}

static void thr_run(const char *name, uint8_t plan, int pts, int dirs, size_t len,
		    struct thr_res *res)
{
	uint64_t t0, b_dl0 = 0, b_ul0 = 0, b_dl = 0, b_ul = 0;
	uint32_t ftx0, frx0, gdl0, gul0;
	struct lat_row r;
	char nm[48];

	hybrid_net(plan, pts, 4000 + len * 7 + (uint64_t)pts * 3 + (uint64_t)dirs);
	t0 = s->t;
	traffic_stop = t0 + MS(9000);
	for (int i = 1; i <= pts; i++) {
		if (dirs & DIR_DL) {
			add_flow(FT, i, len, MS(1) / 4, 1, t0);
			flows[n_flows - 1].saturate = true;
		}
		if (dirs & DIR_UL) {
			add_flow(i, FT, len, MS(1) / 4, 1, t0);
			flows[n_flows - 1].saturate = true;
		}
	}
	sim_run_until(s, t0 + MS(1000));
	for (int i = 0; i < n_flows; i++) {
		*(flows[i].src == FT ? &b_dl0 : &b_ul0) += flows[i].bytes;
	}
	ftx0 = STAT(flex_tx);
	frx0 = STAT(flex_rx);
	gdl0 = STAT(grants_dl);
	gul0 = STAT(grants_ul);
	n_lat = 0; /* latency of the steady state only */
	thr_lb_tbs = thr_lb_sdu = thr_lb_used = 0;
	thr_lb_on = !sim_sec_all; /* sealed bursts cannot be parsed here */
	s->on_air = thr_on_air;
	sim_run_until(s, traffic_stop);
	s->on_air = NULL;
	thr_lb_on = false;
	for (int i = 0; i < n_flows; i++) {
		*(flows[i].src == FT ? &b_dl : &b_ul) += flows[i].bytes;
	}
	res->dl = (unsigned int)((b_dl - b_dl0) / 8000);
	res->ul = (unsigned int)((b_ul - b_ul0) / 8000);
	snprintf(nm, sizeof(nm), "thr %s", name);
	quiet = true;
	lat_report(nm, DIR_ALL, 0, &r);
	quiet = false;
	lat_table_add(&r);
	res->avg = r.avg;
	res->p99 = r.p99;
	res->max = r.max;
	printf("    %-34s DL %4u kB/s  UL %4u kB/s  sum %4u kB/s | SDU latency avg %6llu p99 %6llu "
	       "max %6llu us | long bursts %u/8 s, retx %u",
	       name, res->dl, res->ul, res->dl + res->ul, US(r.avg), US(r.p99), US(r.max),
	       (STAT(flex_tx) - ftx0 + STAT(flex_rx) - frx0) / 2, STAT(retx));
	if (getenv("THR_GRANTS")) {
		printf(", grants DL %u UL %u", STAT(grants_dl) - gdl0, STAT(grants_ul) - gul0);
	}
	if (STAT(grants_ahead)) {
		printf(", %u UL grants a period ahead", STAT(grants_ahead));
	}
	if (thr_lb_tbs && thr_lb_used) {
		res->lb_eff = (unsigned int)(thr_lb_sdu * 100 / thr_lb_tbs);
		res->lb_hdr = (unsigned int)(thr_lb_sdu * 100 / thr_lb_used);
		printf(", long bursts: SDU bytes %u %% of TBS, %u %% of what was sent", res->lb_eff,
		       res->lb_hdr);
	}
	printf("\n");
	sim_run_until(s, traffic_stop + MS(500));
	CHECK(dups == 0 && corrupt == 0 && misrouted == 0, "%s: dups %u corrupt %u misrouted %u",
	      name, dups, corrupt, misrouted);
	CHECK(total_sdu_drops() == 0, "%s: %u SDUs dropped on a clean channel", name,
	      total_sdu_drops());
	check_clean();
}

static void thr_set(const char *tag)
{
	static const struct {
		const char *name;
		uint8_t plan;
		int pts, dirs;
		size_t len;
		unsigned int min_sum; /* kB/s: regression floor (about 80 % of the result) */
		unsigned int min_eff; /* SDU bytes in long bursts, % of TBS (without security) */
	} t[] = {
		{"H, 1 PT, UL, 1280 B", TDMA_PLAN_H, 1, DIR_UL, 1280, 100, 90},
		{"H, 1 PT, DL, 1280 B", TDMA_PLAN_H, 1, DIR_DL, 1280, 95, 90},
		{"H, 1 PT, both, 1280 B", TDMA_PLAN_H, 1, DIR_ALL, 1280, 115, 0},
		{"H, 1 PT, UL, 512 B", TDMA_PLAN_H, 1, DIR_UL, 512, 80, 0},
		{"H, 1 PT, DL, 512 B", TDMA_PLAN_H, 1, DIR_DL, 512, 52, 0},
		{"H, 1 PT, UL, 64 B", TDMA_PLAN_H, 1, DIR_UL, 64, 70, 0},
		{"H, 1 PT, DL, 64 B", TDMA_PLAN_H, 1, DIR_DL, 64, 53, 0},
		{"H, 2 PTs, both, 1280 B", TDMA_PLAN_H, 2, DIR_ALL, 1280, 130, 0},
		{"B, 1 PT, UL, 1280 B", TDMA_PLAN_B, 1, DIR_UL, 1280, 29, 0},
		{"H4, 1 PT, UL, 1280 B", TDMA_PLAN_H4, 1, DIR_UL, 1280, 45, 0},
		{"H4, 3 PTs, UL, 1280 B", TDMA_PLAN_H4, 3, DIR_UL, 1280, 60, 0},
		/* plan T4: DL 4 ss, 4 UL slots, a train of 7 + 7 + 5 ss (plan_multi under bulk) */
		{"T4, 1 PT, UL, 1280 B", TDMA_PLAN_T4, 1, DIR_UL, 1280, 120, 90},
		{"T4, 1 PT, DL, 1280 B", TDMA_PLAN_T4, 1, DIR_DL, 1280, 120, 90},
		{"T4, 3 PTs, UL, 1280 B", TDMA_PLAN_T4, 3, DIR_UL, 1280, 120, 0},
		{"T4, 3 PTs, both, 1280 B", TDMA_PLAN_T4, 3, DIR_ALL, 1280, 120, 0},
		/* plan T: a train of 3 x 8 ss per frame for bulk SDUs */
		{"T, 1 PT, UL, 1280 B", TDMA_PLAN_T, 1, DIR_UL, 1280, 160, 90},
		{"T, 1 PT, DL, 1280 B", TDMA_PLAN_T, 1, DIR_DL, 1280, 160, 90},
		{"T, 1 PT, both, 1280 B", TDMA_PLAN_T, 1, DIR_ALL, 1280, 170, 0},
		{"T, 1 PT, UL, 512 B", TDMA_PLAN_T, 1, DIR_UL, 512, 80, 0},
		{"T, 1 PT, DL, 512 B", TDMA_PLAN_T, 1, DIR_DL, 512, 100, 0},
		{"T, 1 PT, UL, 64 B", TDMA_PLAN_T, 1, DIR_UL, 64, 35, 0},
		{"T, 2 PTs, both, 1280 B", TDMA_PLAN_T, 2, DIR_ALL, 1280, 175, 0},
		/* plan T2: the whole frame for one PT, patterns of DL / UL long bursts */
		{"T2, 1 PT, UL, 1280 B", TDMA_PLAN_T2, 1, DIR_UL, 1280, 210, 90},
		{"T2, 1 PT, DL, 1280 B", TDMA_PLAN_T2, 1, DIR_DL, 1280, 150, 90},
		{"T2D, 1 PT, DL, 1280 B", TDMA_PLAN_T2D, 1, DIR_DL, 1280, 210, 90},
		{"T2D, 1 PT, DL, 512 B", TDMA_PLAN_T2D, 1, DIR_DL, 512, 100, 0},
		{"T2, 1 PT, both, 1280 B", TDMA_PLAN_T2, 1, DIR_ALL, 1280, 200, 0},
		{"T2, 1 PT, UL, 512 B", TDMA_PLAN_T2, 1, DIR_UL, 512, 80, 0},
		{"T2, 1 PT, DL, 512 B", TDMA_PLAN_T2, 1, DIR_DL, 512, 100, 0},
		{"T2, 1 PT, UL, 64 B", TDMA_PLAN_T2, 1, DIR_UL, 64, 35, 0},
		{"T2, 2 PTs, both, 1280 B", TDMA_PLAN_T2, 2, DIR_ALL, 1280, 175, 0},
	};

	printf("  -- %s\n", tag);
	for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		struct thr_res r = {0};

		thr_run(t[i].name, t[i].plan, t[i].pts, t[i].dirs, t[i].len, &r);
		CHECK(r.dl + r.ul >= t[i].min_sum, "%s: %u kB/s < floor %u", t[i].name, r.dl + r.ul,
		      t[i].min_sum);
		CHECK(sim_sec_all || r.lb_eff >= t[i].min_eff,
		      "%s: long bursts carry %u %% SDU bytes of their TBS < %u %%", t[i].name,
		      r.lb_eff, t[i].min_eff);
	}
}

void test_throughput(void)
{
	thr_set("no security");
	/* the hardware model of sec_hw_model (secure-partition seal / open costs, open busy time)
	 */
	sim_sec_all = true;
	sim_grant_ahead = false;
	sim_sec_cost_us = 450;
	sim_sec_open_us = 250;
	sim_sec_busy_us = 450;
	sim_sec_stats_reset();
	thr_set("security on, hardware cost model (450 us seals, 450 us opens)");
	CHECK(sim_sec_st.nonce_reuse == 0 && sim_sec_st.open_fail == 0,
	      "%llu nonce reuses, %llu MIC failures", (unsigned long long)sim_sec_st.nonce_reuse,
	      (unsigned long long)sim_sec_st.open_fail);
	sim_sec_all = false;
	sim_sec_cost_us = sim_sec_open_us = sim_sec_busy_us = 0;
}

/*
 * Lopsided two-way bulk, 1 PT: one direction saturated, the other 60 kB/s
 * (1200 B every 20 ms). The trains (T) and patterns (T2, T2D) follow the
 * demand: the paced direction gets what it sends, the saturated one the
 * rest (strict alternation gave it every other frame: ~105 kB/s).
 */
static void lop_run(uint8_t plan, int sat_dir, unsigned int min_sat)
{
	uint64_t t0, b0[2] = {0, 0}, b1[2] = {0, 0};
	const char *pn = tdma_plan_get(plan)->name;

	hybrid_net(plan, 1, 300 + plan + (uint64_t)sat_dir);
	t0 = s->t;
	traffic_stop = t0 + MS(9000);
	add_flow(FT, 1, 1200, sat_dir == DIR_DL ? MS(1) / 4 : MS(20), 1, t0);
	flows[0].saturate = sat_dir == DIR_DL;
	add_flow(1, FT, 1200, sat_dir == DIR_UL ? MS(1) / 4 : MS(20), 1, t0);
	flows[1].saturate = sat_dir == DIR_UL;
	sim_run_until(s, t0 + MS(1000));
	b0[0] = flows[0].bytes;
	b0[1] = flows[1].bytes;
	sim_run_until(s, traffic_stop);
	b1[0] = (flows[0].bytes - b0[0]) / 8000;
	b1[1] = (flows[1].bytes - b0[1]) / 8000;
	printf("    %-3s %s saturated, %s 60 kB/s: DL %llu kB/s, UL %llu kB/s\n", pn,
	       sat_dir == DIR_DL ? "DL" : "UL", sat_dir == DIR_DL ? "UL" : "DL",
	       (unsigned long long)b1[0], (unsigned long long)b1[1]);
	CHECK(b1[sat_dir == DIR_DL ? 1 : 0] >= 57 && b1[sat_dir == DIR_DL ? 0 : 1] >= min_sat,
	      "%s lopsided: DL %llu UL %llu kB/s", pn, (unsigned long long)b1[0],
	      (unsigned long long)b1[1]);
	sim_run_until(s, traffic_stop + MS(500));
	check_clean();
}

void test_lopsided(void)
{
	lop_run(TDMA_PLAN_T, DIR_UL, 130);
	lop_run(TDMA_PLAN_T, DIR_DL, 130);
	lop_run(TDMA_PLAN_T2, DIR_UL, 170);
	lop_run(TDMA_PLAN_T2, DIR_DL, 170);
}

/*
 * Plan switching (cfg.plan_auto, plan H <-> T): 64 B probes both ways all the
 * time; UL bulk, idle, DL bulk, idle, then 5 short UL bulk bursts. The FT
 * goes to T under bulk and back to H when idle, the PT follows without
 * re-associating; nothing lost, duplicated or late for the PHY.
 */
static uint64_t psw_bytes(void)
{
	uint64_t b = 0;

	for (int i = 0; i < n_flows; i++) {
		b += flows[i].len > 64 ? flows[i].bytes : 0;
	}
	return b;
}

static void psw_bulk(int src, int dst, uint64_t from, uint64_t to)
{
	add_flow(src, dst, 1280, MS(1) / 4, 1, from);
	flows[n_flows - 1].saturate = true;
	flows[n_flows - 1].t_stop = to;
}

void test_plan_switch(void)
{
	const struct tdma_mac *ft, *pt;
	uint64_t t0, b0;
	uint32_t mask = 0, sw_ft = 0;
	struct lat_row r;

	net_build(TDMA_PLAN_H, 1, 93, 0, NULL);
	s->nodes[0].cfg.plan_auto = true;
	s->on_deliver = on_deliver;
	traffic_reset();
	net_start();
	CHECK((t0 = wait_assoc(FRAMES(300))) != UINT64_MAX, "association");
	ft = &s->nodes[0].mac;
	pt = &s->nodes[1].mac;
	traffic_stop = t0 + MS(11000);
	mask = 3u;
	add_flow(FT, 1, 64, MS(20), MS(20), t0);
	flows[0].prio = 1;
	add_flow(1, FT, 64, MS(20), MS(20), t0);
	flows[1].prio = 1;
	psw_bulk(1, FT, t0 + MS(1000), t0 + MS(3000));
	psw_bulk(FT, 1, t0 + MS(4000), t0 + MS(6000));
	for (int k = 0; k < 5; k++) {
		psw_bulk(1, FT, t0 + MS(7000 + 700 * k), t0 + MS(7300 + 700 * k));
	}
	sim_run_until(s, t0 + MS(900));
	CHECK(ft->plan->id == TDMA_PLAN_H && pt->plan->id == TDMA_PLAN_H, "idle: H");
	sim_run_until(s, t0 + MS(2000));
	b0 = psw_bytes();
	CHECK(ft->plan->id == TDMA_PLAN_T && pt->plan->id == TDMA_PLAN_T,
	      "UL bulk: T (FT %s PT %s)", ft->plan->name, pt->plan->name);
	sim_run_until(s, t0 + MS(3000));
	printf("    UL bulk in T: %llu kB/s\n", (unsigned long long)((psw_bytes() - b0) / 1000));
	CHECK(psw_bytes() - b0 >= 150000, "UL bulk in T >= 150 kB/s");
	sim_run_until(s, t0 + MS(3800));
	CHECK(ft->plan->id == TDMA_PLAN_H && pt->plan->id == TDMA_PLAN_H, "idle again: H");
	sim_run_until(s, t0 + MS(5000));
	b0 = psw_bytes();
	CHECK(ft->plan->id == TDMA_PLAN_T && pt->plan->id == TDMA_PLAN_T, "DL bulk: T");
	sim_run_until(s, t0 + MS(6000));
	printf("    DL bulk in T: %llu kB/s\n", (unsigned long long)((psw_bytes() - b0) / 1000));
	CHECK(psw_bytes() - b0 >= 150000, "DL bulk in T >= 150 kB/s");
	sim_run_until(s, traffic_stop + MS(500));
	sw_ft = tdma_get_stats(ft)->plan_switches;
	printf("    plan switches FT %u PT %u, associations PT %u\n", sw_ft,
	       tdma_get_stats(pt)->plan_switches,
	       sim_count_evt(&s->nodes[1], TDMA_EVT_ASSOCIATED, 0));
	CHECK(sw_ft >= 6 && tdma_get_stats(pt)->plan_switches == sw_ft, "switches (FT %u PT %u)",
	      sw_ft, tdma_get_stats(pt)->plan_switches);
	CHECK(sim_count_evt(&s->nodes[1], TDMA_EVT_ASSOCIATED, 0) == 1, "never re-associated");
	lat_report_flows("plan switch: 64 B probes", mask, bound_dir(TDMA_PLAN_T, DIR_DL), &r);
	CHECK(r.delivered == r.sent && total_sdu_drops() == 0 && dups == 0 && corrupt == 0 &&
		      misrouted == 0,
	      "all delivered once (%u/%u, drops %u, dups %u)", r.delivered, r.sent,
	      total_sdu_drops(), dups);
	CHECK(r.max <= bound_dir(TDMA_PLAN_T, DIR_DL) + test_slack_small,
	      "probe max %llu us > plan T's bound", US(r.max));
	check_clean();
}

/*
 * Plan switching with the whole-frame plans (cfg.plan_t2): one PT, so UL bulk
 * goes to T2 (all-UL patterns), DL bulk to T2D, both ways to T2 (mixed
 * patterns), idle back to H. 64 B probes both ways all the time; nothing
 * lost, no re-association, probes within one frame + a long burst.
 */
static uint64_t t2_bound(void)
{
	return TDMA_FRAME_TICKS + TDMA_FLEX_COMMIT_LEAD_TICKS + 8u * TDMA_SUBSLOT_TICKS +
	       sim_pdc_ticks(8, 4) + 64;
}

void test_plan_switch_t2(void)
{
	const struct tdma_mac *ft, *pt;
	uint64_t t0, b0;
	struct lat_row r;
	uint32_t sw_ft;

	net_build(TDMA_PLAN_H, 1, 94, 0, NULL);
	s->nodes[0].cfg.plan_auto = true;
	s->nodes[0].cfg.plan_t2 = true;
	s->on_deliver = on_deliver;
	traffic_reset();
	net_start();
	CHECK((t0 = wait_assoc(FRAMES(300))) != UINT64_MAX, "association");
	ft = &s->nodes[0].mac;
	pt = &s->nodes[1].mac;
	traffic_stop = t0 + MS(10000);
	add_flow(FT, 1, 64, MS(20), MS(20), t0);
	flows[0].prio = 1;
	add_flow(1, FT, 64, MS(20), MS(20), t0);
	flows[1].prio = 1;
	psw_bulk(1, FT, t0 + MS(1000), t0 + MS(3000));
	psw_bulk(FT, 1, t0 + MS(4000), t0 + MS(6000));
	psw_bulk(1, FT, t0 + MS(7000), t0 + MS(9000));
	psw_bulk(FT, 1, t0 + MS(7000), t0 + MS(9000));
	sim_run_until(s, t0 + MS(900));
	CHECK(ft->plan->id == TDMA_PLAN_H && pt->plan->id == TDMA_PLAN_H, "idle: H");
	sim_run_until(s, t0 + MS(2000));
	b0 = psw_bytes();
	CHECK(ft->plan->id == TDMA_PLAN_T2 && pt->plan->id == TDMA_PLAN_T2,
	      "UL bulk: T2 (FT %s PT %s)", ft->plan->name, pt->plan->name);
	sim_run_until(s, t0 + MS(3000));
	printf("    UL bulk in T2: %llu kB/s\n", (unsigned long long)((psw_bytes() - b0) / 1000));
	CHECK(psw_bytes() - b0 >= 230000, "UL bulk in T2 >= 230 kB/s");
	sim_run_until(s, t0 + MS(3800));
	CHECK(ft->plan->id == TDMA_PLAN_H && pt->plan->id == TDMA_PLAN_H, "idle again: H");
	sim_run_until(s, t0 + MS(5000));
	b0 = psw_bytes();
	CHECK(ft->plan->id == TDMA_PLAN_T2D && pt->plan->id == TDMA_PLAN_T2D,
	      "DL bulk: T2D (FT %s PT %s)", ft->plan->name, pt->plan->name);
	sim_run_until(s, t0 + MS(6000));
	printf("    DL bulk in T2D: %llu kB/s\n", (unsigned long long)((psw_bytes() - b0) / 1000));
	CHECK(psw_bytes() - b0 >= 230000, "DL bulk in T2D >= 230 kB/s");
	sim_run_until(s, t0 + MS(8000));
	b0 = psw_bytes();
	CHECK(ft->plan->id == TDMA_PLAN_T2 && pt->plan->id == TDMA_PLAN_T2, "both ways: T2 (FT %s)",
	      ft->plan->name);
	sim_run_until(s, t0 + MS(9000));
	printf("    both ways in T2: %llu kB/s\n", (unsigned long long)((psw_bytes() - b0) / 1000));
	CHECK(psw_bytes() - b0 >= 220000, "both ways in T2 >= 220 kB/s");
	sim_run_until(s, traffic_stop + MS(500));
	CHECK(ft->plan->id == TDMA_PLAN_H, "idle at the end: H");
	sw_ft = tdma_get_stats(ft)->plan_switches;
	printf("    plan switches FT %u PT %u, associations PT %u, T2 patterns U4/D1U3/D2U2/D3U1 "
	       "%u/%u/%u/%u, T2D %u\n",
	       sw_ft, tdma_get_stats(pt)->plan_switches,
	       sim_count_evt(&s->nodes[1], TDMA_EVT_ASSOCIATED, 0),
	       tdma_get_stats(ft)->pat_frames[0][0], tdma_get_stats(ft)->pat_frames[0][1],
	       tdma_get_stats(ft)->pat_frames[0][2], tdma_get_stats(ft)->pat_frames[0][3],
	       tdma_get_stats(ft)->pat_frames[1][0]);
	CHECK(sw_ft >= 6 && tdma_get_stats(pt)->plan_switches == sw_ft, "switches (FT %u PT %u)",
	      sw_ft, tdma_get_stats(pt)->plan_switches);
	CHECK(sim_count_evt(&s->nodes[1], TDMA_EVT_ASSOCIATED, 0) == 1, "never re-associated");
	lat_report_flows("plan switch T2: 64 B probes", 3u, t2_bound(), &r);
	CHECK(r.delivered == r.sent && total_sdu_drops() == 0 && dups == 0 && corrupt == 0 &&
		      misrouted == 0,
	      "all delivered once (%u/%u, drops %u, dups %u)", r.delivered, r.sent,
	      total_sdu_drops(), dups);
	CHECK(r.max <= t2_bound() + test_slack_small, "probe max %llu us > T2's bound %llu us",
	      US(r.max), US(t2_bound()));
	check_clean();
}

/*
 * Plan BQ while idle (cfg.plan_bq): 64 B probes both ways all the time; idle
 * -> BQ, a 1000 B SDU each way -> H and back, UL bulk -> T2 -> H -> BQ, a
 * flood of 64 B SDUs -> H. Probes in BQ within BQ's bound, nothing lost, no
 * re-association.
 */
static uint32_t lost_between(uint64_t a, uint64_t b, uint32_t *sent);

void test_plan_switch_bq(void)
{
	const struct tdma_mac *ft, *pt;
	uint64_t t0, bq_max = 0;
	struct lat_row r;
	uint32_t sw_ft;

	net_build(TDMA_PLAN_H, 1, 95, 0, NULL);
	s->nodes[0].cfg.plan_auto = true;
	s->nodes[0].cfg.plan_t2 = true;
	s->nodes[0].cfg.plan_bq = true;
	s->on_deliver = on_deliver;
	traffic_reset();
	net_start();
	CHECK((t0 = wait_assoc(FRAMES(300))) != UINT64_MAX, "association");
	ft = &s->nodes[0].mac;
	pt = &s->nodes[1].mac;
	traffic_stop = t0 + MS(8000);
	add_flow(FT, 1, 64, MS(20), MS(20), t0);
	flows[0].prio = 1;
	add_flow(1, FT, 64, MS(20), MS(20), t0);
	flows[1].prio = 1;
	add_flow(FT, 1, 1000, MS(1000), 1, t0 + MS(1500));
	flows[2].t_stop = t0 + MS(1600);
	add_flow(1, FT, 1000, MS(1000), 1, t0 + MS(1500));
	flows[3].t_stop = t0 + MS(1600);
	psw_bulk(1, FT, t0 + MS(3000), t0 + MS(4000));
	add_flow(1, FT, 64, MS(1) / 2, MS(1) / 2, t0 + MS(6000)); /* ~128 kB/s of 64 B SDUs */
	flows[n_flows - 1].t_stop = t0 + MS(6500);
	sim_run_until(s, t0 + MS(1000));
	CHECK(ft->plan->id == TDMA_PLAN_BQ && pt->plan->id == TDMA_PLAN_BQ,
	      "idle: BQ (FT %s PT %s)", ft->plan->name, pt->plan->name);
	n_lat = 0;
	sim_run_until(s, t0 + MS(1490));
	lat_report_flows("BQ idle: 64 B probes", 3u, bound_dir(TDMA_PLAN_BQ, DIR_DL), &r);
	bq_max = r.max;
	CHECK(r.max <= bound_dir(TDMA_PLAN_BQ, DIR_DL) + test_slack_small,
	      "probes in BQ max %llu us > BQ's bound %llu us", US(r.max),
	      US(bound_dir(TDMA_PLAN_BQ, DIR_DL)));
	for (int k = 0; getenv("BQ_DBG") && k < 30; k++) {
		sim_run_until(s, t0 + MS(1490 + 5 * k));
		printf("      %d ms: FT %s psw %d -> %u at %u (cur %u), quiet %u, bsr %u\n",
		       1490 + 5 * k, ft->plan->name, ft->psw_valid, ft->psw_plan, ft->psw_frame,
		       ft->cur_frame, ft->bq_quiet, ft->peers[0].bsr);
	}
	sim_run_until(s, t0 + MS(1580));
	CHECK(ft->plan->id == TDMA_PLAN_H, "1000 B SDUs: H (FT %s)", ft->plan->name);
	sim_run_until(s, t0 + MS(2800));
	CHECK(ft->plan->id == TDMA_PLAN_BQ, "idle again: BQ (FT %s)", ft->plan->name);
	sim_run_until(s, t0 + MS(3500));
	CHECK(ft->plan->id == TDMA_PLAN_T2 && pt->plan->id == TDMA_PLAN_T2, "UL bulk: T2 (FT %s)",
	      ft->plan->name);
	sim_run_until(s, t0 + MS(5500));
	CHECK(ft->plan->id == TDMA_PLAN_BQ, "after bulk: BQ (FT %s)", ft->plan->name);
	sim_run_until(s, t0 + MS(6300));
	CHECK(ft->plan->id == TDMA_PLAN_H, "64 B flood: H (FT %s)", ft->plan->name);
	sim_run_until(s, traffic_stop + MS(500));
	CHECK(ft->plan->id == TDMA_PLAN_BQ, "idle at the end: BQ (FT %s)", ft->plan->name);
	sw_ft = tdma_get_stats(ft)->plan_switches;
	printf("    plan switches FT %u PT %u, associations PT %u, BQ probe max %llu us\n", sw_ft,
	       tdma_get_stats(pt)->plan_switches,
	       sim_count_evt(&s->nodes[1], TDMA_EVT_ASSOCIATED, 0), US(bq_max));
	CHECK(sw_ft >= 8 && tdma_get_stats(pt)->plan_switches == sw_ft, "switches (FT %u PT %u)",
	      sw_ft, tdma_get_stats(pt)->plan_switches);
	CHECK(sim_count_evt(&s->nodes[1], TDMA_EVT_ASSOCIATED, 0) == 1, "never re-associated");
	{
		uint32_t n = 0, lost = lost_between(0, UINT64_MAX, &n);

		CHECK(total_sdu_drops() == 0 && dups == 0 && corrupt == 0 && misrouted == 0 &&
			      lost == 0 && n == total_sent(),
		      "all delivered once (%u lost of %u, drops %u, dups %u)", lost, n,
		      total_sdu_drops(), dups);
	}
	check_clean();
}

/*
 * Paced bulk (cfg.plan_auto with T2 and BQ, 1 PT): a host-paced flow of
 * 1200 B SDUs at 75 kB/s DL, then 75 kB/s both ways, then 30 kB/s DL, with
 * 64 B probes both ways. Each settles on one plan (T2D, T2, H) instead of
 * flapping between H and a bulk plan (the backlog rule alone switched every
 * ~250 ms: backlog now and then, never for long); everything delivered.
 */
struct paced_case {
	const char *name;
	uint64_t dl_gap, ul_gap; /* 0: no flow that way */
	uint64_t ul_later;       /* the UL flow starts this much after the DL one */
	uint8_t plan;            /* where it settles */
	uint32_t min_kbps;
};

static void paced_run(const struct paced_case *c, uint64_t seed)
{
	const struct tdma_mac *ft, *pt;
	uint64_t t0, b0, b1;
	uint32_t sw0, sw1, held;

	net_build(TDMA_PLAN_H, 1, seed, 0, NULL);
	s->nodes[0].cfg.plan_auto = true;
	s->nodes[0].cfg.plan_t2 = true;
	s->nodes[0].cfg.plan_bq = true;
	s->on_deliver = on_deliver;
	traffic_reset();
	net_start();
	CHECK((t0 = wait_assoc(FRAMES(300))) != UINT64_MAX, "association");
	ft = &s->nodes[0].mac;
	pt = &s->nodes[1].mac;
	traffic_stop = t0 + MS(7000);
	add_flow(FT, 1, 64, MS(20), MS(20), t0);
	flows[0].prio = 1;
	add_flow(1, FT, 64, MS(20), MS(20), t0);
	flows[1].prio = 1;
	if (c->dl_gap) {
		add_flow(FT, 1, 1200, c->dl_gap, 1, t0 + MS(500));
	}
	if (c->ul_gap) {
		add_flow(1, FT, 1200, c->ul_gap, 1, t0 + MS(500) + c->ul_later);
	}
	sim_run_until(s, t0 + MS(2000) + c->ul_later);
	sw0 = tdma_get_stats(ft)->plan_switches;
	held = tdma_get_stats(ft)->plan_held;
	b0 = psw_bytes();
	sim_run_until(s, traffic_stop);
	sw1 = tdma_get_stats(ft)->plan_switches;
	b1 = (psw_bytes() - b0) / (5000 - c->ul_later / MS(1)); /* kB/s */
	printf("    %-30s settled in %s, %u switches after settling (%u total), %llu kB/s, held "
	       "%u frames\n",
	       c->name, ft->plan->name, sw1 - sw0, sw1, (unsigned long long)b1,
	       tdma_get_stats(ft)->plan_held - held);
	CHECK(sw1 - sw0 <= 1, "%s: %u plan switches after settling (flapping)", c->name, sw1 - sw0);
	CHECK(ft->plan->id == c->plan && pt->plan->id == c->plan, "%s: plan %s / %s, want %s",
	      c->name, ft->plan->name, pt->plan->name, tdma_plan_get(c->plan)->name);
	CHECK(b1 >= c->min_kbps, "%s: %llu kB/s", c->name, (unsigned long long)b1);
	sim_run_until(s, traffic_stop + MS(1500));
	CHECK(ft->plan->id == TDMA_PLAN_BQ, "%s: idle after: BQ (FT %s)", c->name, ft->plan->name);
	CHECK(sim_count_evt(&s->nodes[1], TDMA_EVT_ASSOCIATED, 0) == 1, "%s: never re-associated",
	      c->name);
	{
		uint32_t n = 0, lost = lost_between(0, UINT64_MAX, &n);

		CHECK(total_sdu_drops() == 0 && dups == 0 && corrupt == 0 && misrouted == 0 &&
			      lost == 0 && n == total_sent(),
		      "%s: all delivered once (%u lost of %u, drops %u, dups %u)", c->name, lost, n,
		      total_sdu_drops(), dups);
	}
	check_clean();
}

void test_plan_paced(void)
{
	static const struct paced_case cases[] = {
		{"75 kB/s DL", MS(16), 0, 0, TDMA_PLAN_T2D, 73},
		{"75 kB/s both ways", MS(16), MS(16), 0, TDMA_PLAN_T2, 146},
		{"75 kB/s DL, then UL too", MS(16), MS(16), MS(1500), TDMA_PLAN_T2, 146},
		{"30 kB/s DL", MS(40), 0, 0, TDMA_PLAN_H, 29},
	};

	for (unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		paced_run(&cases[i], 410 + i);
	}
}

/* ---- channel access: selection, LBT, interference monitoring, moves, PT search ----------------
 */

/* cfg channel 0 everywhere (FT chooses, PTs search every carrier), 1705 preferred. */
static void auto_net(uint8_t plan, int pts, uint64_t seed)
{
	net_build(plan, pts, seed, 0, NULL);
	for (int i = 0; i <= pts; i++) {
		s->nodes[i].cfg.channel = 0;
		s->nodes[i].cfg.pref_channel = SIM_CHANNEL;
	}
	s->on_deliver = on_deliver;
	traffic_reset();
}

/* An FT of another site (own network id and rd ids) beaconing on ch, no LBT. */
static int add_foreign_ft(uint16_t ch)
{
	int i = sim_add_node(s, TDMA_ROLE_FT, 1, TDMA_PLAN_A, (int64_t)(sim_rand(s) % (1ull << 40)),
			     0);

	s->nodes[i].cfg.network_id = 0x5a5a5a01u;
	s->nodes[i].cfg.rd_id = 0x20777701u;
	s->nodes[i].cfg.channel = ch;
	s->nodes[i].cfg.lbt_ticks = TDMA_OFF;
	return i;
}

static void print_chan_table(const struct tdma_mac *m)
{
	size_t n;
	const struct tdma_chan_info *t = tdma_chan_table(m, &n);

	printf("      ch    ss  free  poss  busy  max dBm  clusters\n");
	for (size_t i = 0; i < n; i++) {
		if (t[i].valid) {
			printf("      %u %5u %5u %5u %5u %8d %9u%s\n", t[i].ch, t[i].n_ss,
			       t[i].n_free, t[i].n_poss, t[i].n_busy, t[i].max_dbm, t[i].clusters,
			       t[i].ch == tdma_channel(m) ? "  <- in use" : "");
		}
	}
}

/* SDUs queued in [a, b) that never arrived (and were accepted by tdma_send). */
static uint32_t lost_between(uint64_t a, uint64_t b, uint32_t *sent)
{
	uint32_t lost = 0, n = 0;

	for (int f = 0; f < n_flows; f++) {
		for (uint32_t id = 0; id < flows[f].next_id; id++) {
			if (sent_at[f][id] < a || sent_at[f][id] >= b || seen[f][id] == 0xff) {
				continue;
			}
			n++;
			lost += seen[f][id] == 0;
		}
	}
	if (sent) {
		*sent = n;
	}
	return lost;
}

/* Worst latency of SDUs queued in [a, b) (delivered ones). */
static uint64_t max_lat_after(uint64_t a)
{
	uint64_t mx = 0;

	(void)a;
	for (size_t i = 0; i < n_lat; i++) {
		mx = lat[i] > mx ? lat[i] : mx;
	}
	return mx;
}

static int assoc_events_after(uint64_t t)
{
	int n = 0;

	for (int i = 1; i <= n_pts; i++) {
		n += sim_count_evt(&s->nodes[i], TDMA_EVT_ASSOCIATED, t) +
		     sim_count_evt(&s->nodes[i], TDMA_EVT_LOST, t);
	}
	return n;
}

void test_chan_select(void)
{
	uint64_t t, ts = 0;
	uint16_t ch;
	int f;
	const struct tdma_evt *e;

	/* Quiet band: the preferred carrier, after the 9-carrier scan and LBT. */
	auto_net(TDMA_PLAN_H, 1, 801);
	net_start();
	t = wait_assoc(MS(3000));
	CHECK(t != UINT64_MAX, "association on a quiet band");
	CHECK(tdma_channel(&s->nodes[FT].mac) == SIM_CHANNEL, "quiet band: preferred %u (got %u)",
	      SIM_CHANNEL, tdma_channel(&s->nodes[FT].mac));
	CHECK(sim_find_evt(&s->nodes[FT], TDMA_EVT_FT_STARTED, 0, &ts) != NULL, "FT_STARTED");
	CHECK(tdma_get_stats(&s->nodes[FT].mac)->scans == 9, "9 carriers scanned (%u)",
	      tdma_get_stats(&s->nodes[FT].mac)->scans);
	printf("    quiet band: FT on %u (preferred) after scan + LBT at %.1f ms, PT (searching "
	       "all "
	       "carriers) associated at %.1f ms\n",
	       tdma_channel(&s->nodes[FT].mac), (double)ts / 69120.0, (double)t / 69120.0);
	check_clean();

	/*
	 * 1705 (preferred) jammed at -60 dBm (so 1704 / 1706 see -66: busy), 1703
	 * "possible" (-80 dBm), another site's cluster on 1709 (1708 / 1710 next to
	 * it). Expected: 1707, the lowest all-free carrier with no cluster on or
	 * next to it. PTs search every carrier and find it.
	 */
	auto_net(TDMA_PLAN_H, 2, 802);
	sim_add_interferer(s, 1705, -60, 0, UINT64_MAX, 0, 0);
	sim_add_interferer(s, 1703, -80, 0, UINT64_MAX, 0, 0);
	f = add_foreign_ft(1709);
	sim_start(s, f);
	net_start();
	t = wait_assoc(MS(4000));
	ch = tdma_channel(&s->nodes[FT].mac);
	CHECK(t != UINT64_MAX, "association with interference");
	CHECK(ch == 1707, "chose %u, expected 1707", ch);
	/* first from its physical header (short ids), then from its decoded beacon */
	e = sim_find_evt(&s->nodes[FT], TDMA_EVT_SCAN_CLUSTER, 0, NULL);
	CHECK(e && e->rd_id == tdma_short_rd(s->nodes[f].cfg.rd_id) && e->channel == 1709 &&
		      e->network_id == (s->nodes[f].cfg.network_id & 0xff),
	      "foreign cluster reported on 1709 (header)");
	e = NULL;
	for (int i = 0; i < s->nodes[FT].n_evts; i++) {
		if (s->nodes[FT].evts[i].type == TDMA_EVT_SCAN_CLUSTER &&
		    s->nodes[FT].evts[i].rd_id == s->nodes[f].cfg.rd_id) {
			e = &s->nodes[FT].evts[i];
		}
	}
	CHECK(e && e->channel == 1709 && e->network_id == s->nodes[f].cfg.network_id,
	      "foreign cluster reported on 1709 (beacon)");
	for (int i = 1; i <= n_pts; i++) {
		CHECK(tdma_channel(&s->nodes[i].mac) == ch &&
			      tdma_parent(&s->nodes[i].mac) == rd(FT),
		      "PT %d on %u under our FT", i, tdma_channel(&s->nodes[i].mac));
	}
	printf("    jammed 1705, -80 dBm on 1703, foreign cluster on 1709: FT chose %u, PTs "
	       "associated at %.1f ms; scan table:\n",
	       ch, (double)t / 69120.0);
	print_chan_table(&s->nodes[FT].mac);
	/* and traffic works next to the foreign cluster */
	traffic_stop = s->t + MS(1000);
	add_flows_all(64, MS(5), MS(10), s->t);
	sim_run_until(s, traffic_stop + MS(200));
	CHECK(n_lat == total_sent() && n_lat > 100, "data (%zu/%u)", n_lat, total_sent());
	check_clean();
}

void test_lbt(void)
{
	uint64_t t, ts = 0;
	const struct tdma_evt *e;

	/* Fixed channel busy for 300 ms: no beacon goes out before it is free. */
	net_build(TDMA_PLAN_H, 1, 811, 0, NULL);
	s->on_deliver = on_deliver;
	traffic_reset();
	sim_add_interferer(s, SIM_CHANNEL, -60, 0, MS(300), 0, 0);
	net_start();
	t = wait_assoc(MS(2000));
	CHECK(t != UINT64_MAX, "association after the channel became free");
	CHECK(sim_find_evt(&s->nodes[FT], TDMA_EVT_FT_STARTED, 0, &ts) && ts >= MS(300),
	      "first beacon after the interferer stopped (%.1f ms)", (double)ts / 69120.0);
	CHECK(tdma_get_stats(&s->nodes[FT].mac)->lbt_busy > 10 &&
		      tdma_get_stats(&s->nodes[FT].mac)->beacons_rx == 0,
	      "LBT busy %u", tdma_get_stats(&s->nodes[FT].mac)->lbt_busy);
	CHECK(sim_count_evt(&s->nodes[1], TDMA_EVT_SYNCED, 0) >= 1 &&
		      sim_find_evt(&s->nodes[1], TDMA_EVT_SYNCED, 0, &t) && t > MS(300),
	      "PT synced only after the first real beacon");
	printf("    fixed channel busy 0-300 ms: %u beacons held back by LBT, first beacon at %.1f "
	       "ms\n",
	       tdma_get_stats(&s->nodes[FT].mac)->lbt_busy, (double)ts / 69120.0);
	check_clean();

	/* Auto: the chosen carrier gets jammed after its scan: LBT fails, the FT goes elsewhere. */
	auto_net(TDMA_PLAN_H, 1, 812);
	sim_add_interferer(s, SIM_CHANNEL, -60, MS(400), UINT64_MAX, 0, 0);
	net_start();
	t = wait_assoc(MS(4000));
	CHECK(t != UINT64_MAX, "association");
	e = sim_find_evt(&s->nodes[FT], TDMA_EVT_CHANNEL, 0, NULL);
	CHECK(e && e->cause == TDMA_CAUSE_LBT && e->channel != SIM_CHANNEL,
	      "LBT failures moved the FT off %u", SIM_CHANNEL);
	CHECK(tdma_get_stats(&s->nodes[FT].mac)->lbt_busy == TDMA_DEF_LBT_MAX_FAIL, "%u busy LBTs",
	      tdma_get_stats(&s->nodes[FT].mac)->lbt_busy);
	CHECK(tdma_channel(&s->nodes[1].mac) == tdma_channel(&s->nodes[FT].mac), "PT followed");
	printf("    auto, %u jammed after its scan: %u busy LBTs, FT on %u, PT associated at %.1f "
	       "ms\n",
	       SIM_CHANNEL, tdma_get_stats(&s->nodes[FT].mac)->lbt_busy,
	       tdma_channel(&s->nodes[FT].mac), (double)t / 69120.0);
	check_clean();

	/* Association requests (random access) wait for a free channel too. */
	CHECK(STAT(assoc_tx) >= 2, "requests sent and received");
}

/*
 * Mid-run interferer (40 % duty cycle, -60 dBm) on the FT's carrier while 64 B
 * flows run both ways and PT 1 sends 1000 B bulk: the FT's monitor sees the
 * channel busy, announces a move, PTs follow without re-associating.
 */
void test_chan_move(void)
{
	uint64_t t0, t_int, t_mv = 0, t_ch = 0;
	uint16_t ch0, ch1;
	uint32_t n_before, n_after, n_move, l_before, l_after, l_move;
	const struct tdma_evt *e;

	auto_net(TDMA_PLAN_H, 2, 821);
	net_start();
	t0 = wait_assoc(MS(4000));
	CHECK(t0 != UINT64_MAX, "association");
	ch0 = tdma_channel(&s->nodes[FT].mac);
	traffic_stop = t0 + MS(5000);
	add_flows_all(64, MS(5), MS(10), t0);
	add_flow(1, FT, 1000, MS(40), MS(20), t0);
	t_int = t0 + MS(1000);
	sim_add_interferer(s, ch0, -60, t_int, UINT64_MAX, MS(7), MS(28) / 10);
	sim_run_until(s, traffic_stop + MS(500));

	e = sim_find_evt(&s->nodes[FT], TDMA_EVT_MOVE, t_int, &t_mv);
	CHECK(e && e->cause == TDMA_CAUSE_INTERFERENCE, "move announced (interference)");
	sim_find_evt(&s->nodes[FT], TDMA_EVT_CHANNEL, t_int, &t_ch);
	ch1 = tdma_channel(&s->nodes[FT].mac);
	CHECK(ch1 != ch0 && ch1 != ch0 - 1 && ch1 != ch0 + 1, "FT moved %u -> %u", ch0, ch1);
	for (int i = 1; i <= n_pts; i++) {
		CHECK(tdma_channel(&s->nodes[i].mac) == ch1 &&
			      tdma_get_state(&s->nodes[i].mac) == TDMA_ST_ASSOCIATED,
		      "PT %d followed", i);
		CHECK(sim_count_evt(&s->nodes[i], TDMA_EVT_MOVE, t_int) == 1,
		      "PT %d heard the move", i);
	}
	CHECK(assoc_events_after(t0 + MS(1)) == 0, "no PT lost / re-associated (%d)",
	      assoc_events_after(t0 + MS(1)));
	CHECK(sim_count_evt(&s->nodes[FT], TDMA_EVT_CHILD_REMOVED, t0) == 0, "no child removed");
	/* until the switch the old carrier is still jammed; from the switch on nothing may be lost
	 */
	l_before = lost_between(t_int, t_mv, &n_before);
	l_move = lost_between(t_mv, t_ch, &n_move);
	l_after = lost_between(t_ch, traffic_stop, &n_after);
	CHECK(l_after == 0, "SDUs queued after the switch lost: %u", l_after);
	CHECK(dups == 0 && corrupt == 0 && misrouted == 0, "dups %u corrupt %u", dups, corrupt);
	printf("    interferer 40 %% / -60 dBm on %u from +1 s: busy %u %% in the window, move "
	       "announced %.0f ms later, on %u %.0f ms after that\n",
	       ch0, tdma_get_stats(&s->nodes[FT].mac)->move_busy_pct,
	       (double)(t_mv - t_int) / 69120.0, ch1, (double)(t_ch - t_mv) / 69120.0);
	printf("    SDUs lost (by time queued): jammed, before the announcement %u/%u, during the "
	       "announcement %u/%u, after the switch %u/%u; no re-association; FT measurements: "
	       "%u own, %u background\n",
	       l_before, n_before, l_move, n_move, l_after, n_after,
	       tdma_get_stats(&s->nodes[FT].mac)->meas, tdma_get_stats(&s->nodes[FT].mac)->meas_bg);
	check_clean();
}

/*
 * tdma_ft_move() on a clean band with traffic running (the `tdma move`
 * command): no SDU lost, latency during the move; then a PT that slept through
 * the announcement finds the FT on the new carrier by searching all of them,
 * and a jammer that kills the link outright: the FT moves, PTs re-associate.
 */
void test_move_cmd(void)
{
	uint64_t t0, t_mv = 0, t_ch = 0, t;
	uint16_t ch0, ch1;
	uint32_t n_mv, l_mv;
	struct lat_row r;

	auto_net(TDMA_PLAN_H, 2, 831);
	net_start();
	t0 = wait_assoc(MS(4000));
	CHECK(t0 != UINT64_MAX, "association");
	ch0 = tdma_channel(&s->nodes[FT].mac);
	traffic_stop = t0 + MS(2000);
	add_flows_all(64, MS(5), MS(10), t0);
	add_flow(FT, 2, 1000, MS(40), MS(20), t0);
	sim_run_until(s, t0 + MS(1000));
	CHECK(tdma_ft_move(&s->nodes[FT].mac, 1709, TDMA_CAUSE_CMD) == 0, "move accepted");
	CHECK(tdma_ft_move(&s->nodes[FT].mac, 1703, TDMA_CAUSE_CMD) == -EALREADY, "one at a time");
	sim_run_until(s, traffic_stop + MS(300));
	sim_find_evt(&s->nodes[FT], TDMA_EVT_MOVE, t0, &t_mv);
	sim_find_evt(&s->nodes[FT], TDMA_EVT_CHANNEL, t0, &t_ch);
	ch1 = tdma_channel(&s->nodes[FT].mac);
	CHECK(ch1 == 1709, "on 1709 (%u)", ch1);
	CHECK(assoc_events_after(t0 + MS(1)) == 0, "no re-association");
	l_mv = lost_between(t0, traffic_stop, &n_mv);
	CHECK(l_mv == 0 && dups == 0, "lost %u/%u dups %u", l_mv, n_mv, dups);
	lat_report("H, 64 B + 1000 B, move", DIR_ALL, 0, &r);
	printf("    tdma move %u -> %u: switch %.0f ms after the command, %u/%u SDUs lost, "
	       "max latency %.1f ms (64 B and 1000 B mixed)\n",
	       ch0, ch1, (double)(t_ch - t_mv) / 69120.0, l_mv, n_mv,
	       (double)max_lat_after(0) / 69120.0);
	check_clean();

	/* PT 2 asleep during the announcement: it searches every carrier and rejoins. */
	sim_kill(s, 2);
	CHECK(tdma_ft_move(&s->nodes[FT].mac, 1711, TDMA_CAUSE_CMD) == 0, "second move");
	sim_run_until(s, s->t + MS(300));
	t = s->t;
	sim_revive(s, 2);
	CHECK(wait_assoc(t + MS(2000)) != UINT64_MAX, "PT 2 found the FT on 1711");
	printf("    PT 2 slept through the move to 1711: searching all carriers, associated %.0f "
	       "ms "
	       "after boot\n",
	       (double)(s->t - t) / 69120.0);
	CHECK(tdma_channel(&s->nodes[2].mac) == 1711, "PT 2 on 1711");

	/* A jammer that kills the link (continuous, -50 dBm): PTs lose sync, the FT's
	 * monitor sees 100 % busy and moves without them, PTs search and re-associate.
	 */
	t = s->t;
	sim_add_interferer(s, 1711, -50, t, UINT64_MAX, 0, 0);
	t0 = wait_assoc(t + MS(200)); /* still associated? no: wait for loss first */
	sim_run_until(s, t + MS(4000));
	CHECK(tdma_channel(&s->nodes[FT].mac) != 1711 && all_associated(),
	      "FT moved off the jammed carrier and PTs rejoined (FT on %u)",
	      tdma_channel(&s->nodes[FT].mac));
	{
		const struct tdma_evt *e = sim_find_evt(&s->nodes[FT], TDMA_EVT_MOVE, t, &t_mv);
		uint64_t ta = 0;

		CHECK(e && e->cause == TDMA_CAUSE_INTERFERENCE, "monitor move");
		sim_find_evt(&s->nodes[1], TDMA_EVT_ASSOCIATED, t, &ta);
		printf("    link-killing jammer on 1711: FT move announced after %.0f ms, to %u; "
		       "PT 1 "
		       "re-associated %.0f ms after the jammer started\n",
		       (double)(t_mv - t) / 69120.0, tdma_channel(&s->nodes[FT].mac),
		       (double)(ta - t) / 69120.0);
	}
	(void)t0;
	check_clean();
}

/* ---- frequency hopping --------------------------------------------------------------------- */

#define HOP_MASK 0x155u /* 1703, 1705, 1707, 1709, 1711 */

static void hop_net(int pts, uint64_t seed)
{
	auto_net(TDMA_PLAN_H, pts, seed);
	for (int i = 0; i <= pts; i++) {
		s->nodes[i].cfg.hop = true;
		s->nodes[i].cfg.ch_mask = HOP_MASK;
	}
}

void test_hop(void)
{
	uint64_t t0, t_j, t_mv = 0, t_ch = 0, b_dl = bound_dir(TDMA_PLAN_H, DIR_DL),
			  b_ul = bound_dir(TDMA_PLAN_H, DIR_UL);
	uint32_t mask0, mask1, n_j, l_j, n_a, l_a;
	struct lat_row r, rd_, ru;
	struct tdma_mac *ft;
	uint16_t seen_ch[TDMA_CH_TABLE] = {0};

	/* the hop sequence: every carrier once per cycle of n frames */
	hop_net(2, 841);
	ft = &s->nodes[FT].mac;
	ft->hop_base = 1703;
	ft->hop_mask = HOP_MASK;
	ft->hop_seed = 0x12345678u;
	for (uint32_t f = 0; f < 5 * 40; f++) {
		uint16_t c = tdma_hop_carrier(ft, f);

		CHECK(c >= 1703 && c <= 1711 && (HOP_MASK & (1u << (c - 1703))), "carrier %u", c);
		seen_ch[c - 1703]++;
		if (f % 5 == 4) {
			for (int k = 0; k < 9; k++) {
				CHECK(seen_ch[k] == ((HOP_MASK >> k) & 1) * (f / 5 + 1),
				      "cycle %u: carrier %d x%u", f / 5, 1703 + k, seen_ch[k]);
			}
		}
	}

	/*
	 * Clean band, hopping over 5 carriers, 1703 jammed from the start (left
	 * out of the hop set by the scan). 64 B both ways: the guaranteed bounds
	 * hold while hopping.
	 */
	hop_net(2, 842);
	sim_add_interferer(s, 1703, -60, 0, UINT64_MAX, 0, 0);
	net_start();
	t0 = wait_assoc(MS(4000));
	CHECK(t0 != UINT64_MAX, "association while hopping");
	ft = &s->nodes[FT].mac;
	mask0 = tdma_hop_mask(ft);
	CHECK(mask0 == (HOP_MASK & ~1u), "hop set 0x%x (1703 left out)", mask0);
	for (int i = 1; i <= n_pts; i++) {
		CHECK(tdma_hop_mask(&s->nodes[i].mac) == mask0 &&
			      s->nodes[i].mac.hop_seed == ft->hop_seed,
		      "PT %d hops with the FT", i);
	}
	traffic_stop = t0 + MS(3000);
	add_flows_all(64, MS(5), MS(10), t0 + MS(10));
	sim_run_until(s, traffic_stop + MS(300));
	lat_report("H hopping 4 ch, 64 B DL", DIR_DL, b_dl, &rd_);
	lat_report("H hopping 4 ch, 64 B UL", DIR_UL, b_ul, &ru);
	CHECK(rd_.delivered == rd_.sent && ru.delivered == ru.sent && dups == 0, "all delivered");
	CHECK(rd_.max <= b_dl && ru.max <= b_ul, "bounds hold while hopping (DL %llu UL %llu us)",
	      US(rd_.max), US(ru.max));
	printf("    hopping over 0x%x (1703 jammed, left out): 64 B DL max %llu us (bound %llu), "
	       "UL "
	       "max %llu us (bound %llu), %u/%u delivered\n",
	       mask0, US(rd_.max), US(b_dl), US(ru.max), US(b_ul), rd_.delivered + ru.delivered,
	       rd_.sent + ru.sent);
	check_clean();

	/*
	 * Mid-run, 1707 gets jammed (continuous, -60 dBm): one frame in four is
	 * lost until the monitor drops 1707 from the hop set; ARQ recovers, no
	 * re-association, nothing lost after the change.
	 */
	traffic_reset();
	t0 = s->t;
	t_j = t0 + MS(500);
	traffic_stop = t0 + MS(4000);
	add_flows_all(64, MS(5), MS(10), t0);
	add_flow(1, FT, 1000, MS(40), MS(20), t0);
	sim_add_interferer(s, 1707, -60, t_j, UINT64_MAX, 0, 0);
	sim_run_until(s, traffic_stop + MS(300));
	mask1 = tdma_hop_mask(ft);
	CHECK(mask1 == (mask0 & ~(1u << 4)), "1707 dropped: 0x%x -> 0x%x", mask0, mask1);
	sim_find_evt(&s->nodes[FT], TDMA_EVT_MOVE, t_j, &t_mv);
	sim_find_evt(&s->nodes[FT], TDMA_EVT_CHANNEL, t_j, &t_ch);
	for (int i = 1; i <= n_pts; i++) {
		CHECK(tdma_hop_mask(&s->nodes[i].mac) == mask1, "PT %d follows the new hop set", i);
	}
	CHECK(assoc_events_after(t0) == 0, "no re-association");
	l_j = lost_between(t_j, t_ch, &n_j);
	l_a = lost_between(t_ch, traffic_stop, &n_a);
	CHECK(l_a == 0 && dups == 0 && corrupt == 0, "lost after the change %u", l_a);
	CHECK(l_j * 20 <= n_j, "loss while 1 of 4 carriers jammed <= 5 %% (%u/%u)", l_j, n_j);
	lat_report("H hop, 1707 jammed", DIR_ALL, 0, &r);
	printf("    1707 jammed at +0.5 s: dropped from the hop set %.0f ms later (0x%x -> 0x%x, "
	       "in effect %.0f ms after the announcement); SDUs lost while jammed %u/%u (ARQ), "
	       "after %u/%u; retx %u\n",
	       (double)(t_mv - t_j) / 69120.0, mask0, mask1, (double)(t_ch - t_mv) / 69120.0, l_j,
	       n_j, l_a, n_a, STAT(retx));
	check_clean();

	/*
	 * A duty-cycled interferer (40 %, period 7 ms) on 1709: dropped once, no
	 * flapping while it lasts (a quiet sample must not bring it back), and
	 * taken back after it stops (1707 too, its jammer stops as well).
	 */
	{
		int n_mv;
		uint64_t t1 = s->t, t_stop = t1 + MS(3000);
		uint32_t adds0 = tdma_get_stats(ft)->hop_adds;

		s->intf[1].t_to = t1; /* 1707's jammer stops */
		sim_add_interferer(s, 1709, -60, t1, t_stop, MS(7), MS(28) / 10);
		sim_run_until(s, t_stop);
		n_mv = sim_count_evt(&s->nodes[FT], TDMA_EVT_MOVE, t1);
		CHECK(!(tdma_hop_mask(ft) & (1u << 6)), "1709 out while jammed (0x%x)",
		      tdma_hop_mask(ft));
		CHECK(n_mv <= 2, "no flapping: %d hop-set changes while 1709 is jammed", n_mv);
		sim_run_until(s, t_stop + MS(4000));
		CHECK(tdma_hop_mask(ft) == mask0, "both back after the interferers stopped (0x%x)",
		      tdma_hop_mask(ft));
		CHECK(assoc_events_after(t0) == 0, "no re-association");
		printf("    40 %% duty interferer on 1709 for 3 s: %d hop-set change(s) while it "
		       "lasted, "
		       "hop set back to 0x%x after it stopped (%u carriers taken back)\n",
		       n_mv, tdma_hop_mask(ft), tdma_get_stats(ft)->hop_adds - adds0);
		check_clean();
	}
}

/*
 * Several PTs with plan auto (cfg.plan_multi = H4 on top of H, T, T2, T2D,
 * BQ): one PT runs the one-PT plans (UL bulk: T2); a second PT that starts
 * during that bulk joins within T2's limit (T every TDMA_T2_MAX_FRAMES for
 * association requests) and the FT goes to H4 at once, where a third joins;
 * the bulk goes on in T4 (every PT keeps its UL slot), every PT's probes keep
 * flowing both ways within T4's bound, then H4's when the bulk ends. Two PTs
 * leave: back to the one-PT plans.
 * Nothing lost, no re-association of the PTs that stay.
 */
static bool node_assoc(int i)
{
	return s->nodes[i].alive && tdma_get_state(&s->nodes[i].mac) == TDMA_ST_ASSOCIATED;
}

static uint64_t wait_node(int i, uint64_t deadline)
{
	while (s->t < deadline) {
		sim_run_until(s, s->t + TDMA_FRAME_TICKS / 4);
		if (node_assoc(i)) {
			return s->t;
		}
	}
	return UINT64_MAX;
}

void test_plan_multi(void)
{
	const struct tdma_mac *ft;
	uint64_t t0, tj, b0;
	struct lat_row r;
	uint32_t mask = 0;

	net_build(TDMA_PLAN_H, 3, 96, 0, NULL);
	s->nodes[0].cfg.plan_auto = true;
	s->nodes[0].cfg.plan_t2 = true;
	s->nodes[0].cfg.plan_bq = true;
	s->nodes[0].cfg.plan_multi = TDMA_PLAN_H4;
	s->on_deliver = on_deliver;
	traffic_reset();
	sim_start(s, 0);
	sim_start(s, 1);
	CHECK((t0 = wait_node(1, FRAMES(300))) != UINT64_MAX, "PT 1 association");
	ft = &s->nodes[0].mac;
	traffic_stop = t0 + MS(16000);
	add_flow(FT, 1, 64, MS(20), MS(20), t0);
	add_flow(1, FT, 64, MS(20), MS(20), t0);
	psw_bulk(1, FT, t0 + MS(1000), t0 + MS(9000));
	sim_run_until(s, t0 + MS(900));
	CHECK(ft->plan->id == TDMA_PLAN_BQ || ft->plan->id == TDMA_PLAN_H,
	      "one PT idle: BQ / H (%s)", ft->plan->name);
	sim_run_until(s, t0 + MS(2000));
	CHECK(ft->plan->id == TDMA_PLAN_T2, "one PT, UL bulk: T2 (%s)", ft->plan->name);
	sim_start(s, 2);
	CHECK((tj = wait_node(2, t0 + MS(9000))) != UINT64_MAX, "PT 2 joins during the bulk");
	printf("    PT 2 joined %llu ms after it started (T2 -> T for association requests)\n",
	       (unsigned long long)(US(tj - (t0 + MS(2000))) / 1000));
	CHECK(tj - (t0 + MS(2000)) <= MS(6000), "PT 2 joined within 6 s");
	sim_run_until(s, s->t + FRAMES(6));
	CHECK(ft->plan->id == TDMA_PLAN_H4 && s->nodes[1].mac.plan->id == TDMA_PLAN_H4 &&
		      s->nodes[2].mac.plan->id == TDMA_PLAN_H4,
	      "two PTs: H4 (FT %s)", ft->plan->name);
	add_flow(FT, 2, 64, MS(20), MS(20), s->t);
	add_flow(2, FT, 64, MS(20), MS(20), s->t);
	sim_start(s, 3);
	CHECK((tj = wait_node(3, s->t + MS(3000))) != UINT64_MAX, "PT 3 joins under H4");
	add_flow(FT, 3, 64, MS(20), MS(20), s->t);
	add_flow(3, FT, 64, MS(20), MS(20), s->t);
	for (int i = 0; i < n_flows; i++) {
		flows[i].prio = flows[i].len == 64;
		mask |= flows[i].len == 64 ? 1u << i : 0u;
	}
	sim_run_until(s,
		      s->t + MS(200)); /* a new child's DL starts with the beacon that lists it */
	tj = s->t;
	b0 = psw_bytes();
	n_lat = 0;
	sim_run_until(s, t0 + MS(9000));
	printf("    PT 1 UL bulk with 3 PTs (T4): %llu kB/s\n",
	       (unsigned long long)((psw_bytes() - b0) * 1000 /
				    (US(s->t - tj) ? US(s->t - tj) : 1)));
	lat_report_flows("T4, 3 PTs, one in UL bulk: 64 B probes", mask,
			 bound_dir(TDMA_PLAN_T4, DIR_DL), &r);
	for (int i = 0; getenv("MULTI_DBG") && i < n_flows; i++) {
		if (mask & (1u << i)) {
			struct lat_row q;
			char nm[40];

			snprintf(nm, sizeof(nm), "  flow %d %d->%d", i, flows[i].src, flows[i].dst);
			lat_report_flows(nm, 1u << i, 0, &q);
		}
	}
	/* T4's 4 ss DL burst carries the beacon, a grant and three 64 B SDUs */
	CHECK(r.max <= bound_dir(TDMA_PLAN_T4, DIR_DL) + test_slack_small,
	      "probe max %llu us > T4's bound %llu us", US(r.max),
	      US(bound_dir(TDMA_PLAN_T4, DIR_DL)));
	CHECK(ft->plan->id == TDMA_PLAN_T4, "3 PTs, one in bulk: T4 (%s)", ft->plan->name);
	CHECK(psw_bytes() - b0 >= (uint64_t)US(s->t - tj) * 120u / 1000u, "bulk in T4 >= 120 kB/s");
	/* the bulk ends at 9 s: H4, whose probes stay within H4's bound (+ a DL period: its
	 * 3 ss DL burst carries two 64 B SDUs, a third waits for the next one) */
	sim_run_until(s, t0 + MS(9300));
	CHECK(ft->plan->id == TDMA_PLAN_H4, "3 PTs idle: H4 (%s)", ft->plan->name);
	n_lat = 0;
	sim_run_until(s, t0 + MS(9990));
	lat_report_flows("H4, 3 PTs idle: 64 B probes", mask, bound_dir(TDMA_PLAN_H4, DIR_DL), &r);
	CHECK(r.p99 <= bound_dir(TDMA_PLAN_H4, DIR_DL) + test_slack_small &&
		      r.max <= bound_dir(TDMA_PLAN_H4, DIR_DL) + 29u * TDMA_SUBSLOT_TICKS +
				       test_slack_small,
	      "probe p99 %llu / max %llu us > H4's bound %llu us (+ a DL period)", US(r.p99),
	      US(r.max), US(bound_dir(TDMA_PLAN_H4, DIR_DL)));
	/* PTs 3 and 2 leave (their flows stop first) */
	flows[3].t_stop = flows[4].t_stop = flows[5].t_stop = flows[6].t_stop = t0 + MS(10000);
	sim_run_until(s, t0 + MS(10500));
	CHECK(tdma_get_stats(ft)->plan_switches > 0, "switches");
	sim_kill(s, 3);
	sim_kill(s, 2);
	sim_run_until(s, t0 + MS(13000));
	{
		uint32_t kids[TDMA_MAX_POSITIONS];
		size_t nk = tdma_children(ft, kids, TDMA_MAX_POSITIONS);

		CHECK(nk == 1, "one PT left (%zu)", nk);
	}
	CHECK(ft->plan->id == TDMA_PLAN_BQ || ft->plan->id == TDMA_PLAN_H,
	      "one PT again: BQ / H (%s)", ft->plan->name);
	sim_run_until(s, traffic_stop + MS(500));
	printf("    plan switches FT %u (to H4 %u), PT 1 %u; associations PT 1 %u\n",
	       tdma_get_stats(ft)->plan_switches, tdma_get_stats(ft)->plan_multi,
	       tdma_get_stats(&s->nodes[1].mac)->plan_switches,
	       sim_count_evt(&s->nodes[1], TDMA_EVT_ASSOCIATED, 0));
	CHECK(sim_count_evt(&s->nodes[1], TDMA_EVT_ASSOCIATED, 0) == 1, "PT 1 never re-associated");
	CHECK(tdma_get_stats(ft)->plan_multi == 1, "one switch to H4 (%u)",
	      tdma_get_stats(ft)->plan_multi);
	{
		uint32_t sent = 0, got = 0;

		for (int i = 0; i < n_flows; i++) {
			if (flows[i].len == 64) {
				sent += flows[i].sent;
				for (uint32_t k = 0; k < flows[i].next_id && k < MAX_IDS; k++) {
					got += seen[i][k] == 1;
				}
			}
		}
		printf("    64 B probes: %u sent, %u delivered\n", sent, got);
		for (int i = 0; getenv("MULTI_DBG") && i < n_flows; i++) {
			uint32_t g = 0, first_lost = UINT32_MAX;

			for (uint32_t k = 0; k < flows[i].next_id && k < MAX_IDS; k++) {
				g += seen[i][k] == 1;
				if (seen[i][k] != 1 && first_lost == UINT32_MAX) {
					first_lost = k;
				}
			}
			printf("      flow %d %d->%d len %zu sent %u got %u first lost id %u at "
			       "%llu ms\n",
			       i, flows[i].src, flows[i].dst, flows[i].len, flows[i].sent, g,
			       first_lost,
			       first_lost == UINT32_MAX
				       ? 0ull
				       : (unsigned long long)(US(sent_at[i][first_lost] - t0) /
							      1000));
		}
		CHECK(got == sent, "every probe delivered (%u/%u)", got, sent);
	}
	CHECK(dups == 0 && corrupt == 0 && misrouted == 0, "dups %u corrupt %u misrouted %u", dups,
	      corrupt, misrouted);
	check_clean();
}
