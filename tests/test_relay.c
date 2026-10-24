/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Relays (docs/mac-design.md "Relays"): plan HG, the merged op sequence, the
 * beacon tree extension, the storage split, and relay networks in the sim:
 * a chain (A <- B <- C, D a leaf of A), two children under a relay, relay
 * loss, a counter jump at the relay, depth 2 and the depth limit. Every run
 * has link security with the DK cost model (seal 450 us, open 250 us), so the
 * nonce-reuse checker sees both of a relay's keys, and the fake PHY checks the
 * relay's merged op sequence (one radio, both instances' ops).
 */

#include <errno.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>

#include "sim.h"
#include <cappella/tdma_pdu.h>
#include "test.h"

#define MS(x)     ((uint64_t)(x) * 69120u)
#define FRAMES(n) ((uint64_t)(n) * TDMA_FRAME_TICKS)
#define US(t)     ((unsigned long long)TDMA_TICKS_TO_US(t))

#define CH_A 1705
#define CH_B 1707
#define CH_R 1709

/* ---- units ------------------------------------------------------------------------- */

void test_relay_plan(void)
{
	const struct tdma_plan *hg = tdma_plan_get(TDMA_PLAN_HG);
	struct tdma_relay_check c = {
		.ul_trim = TDMA_US_TO_TICKS(300),
		.dl_trim = TDMA_US_TO_TICKS(150),
		.seal = TDMA_US_TO_TICKS(450),
		.quiet = TDMA_US_TO_TICKS(650),
		.late = TDMA_US_TO_TICKS(200),
	};
	/* DL bursts in the O blocks (H4, BQ, B), or no UL slots at all (T2, T2D) */
	static const uint8_t bad_parents[] = {TDMA_PLAN_H4, TDMA_PLAN_BQ, TDMA_PLAN_T2,
					      TDMA_PLAN_T2D, TDMA_PLAN_B};

	CHECK(hg && tdma_plan_validate(hg) == 0 && hg->n_positions == 2 && tdma_plan_has_flex(hg) &&
		      !tdma_plan_has_train(hg),
	      "plan HG: valid, 2 positions, hybrid format, no FLEX train");
	for (uint8_t pid = TDMA_PLAN_H; pid <= TDMA_PLAN_T; pid += TDMA_PLAN_T - TDMA_PLAN_H) {
		for (uint8_t pos = 0; pos < 2; pos++) {
			int r = tdma_relay_plan_check(tdma_plan_get(pid), pos, hg, &c);

			CHECK(r == 0, "R1: parent %s position %u", tdma_plan_get(pid)->name, pos);
			printf("    R1 parent %-2s pos %u: %u ops per frame, smallest gap %u ss, "
			       "%u PHY calls "
			       "per frame held by the quiet window\n",
			       tdma_plan_get(pid)->name, pos, c.n_ops, c.min_gap_ss, c.held_calls);
			CHECK(r || c.min_gap_ss >= TDMA_MIN_OP_GAP_SS, "gap");
		}
	}
	for (size_t i = 0; i < sizeof(bad_parents); i++) {
		const struct tdma_plan *p = tdma_plan_get(bad_parents[i]);

		for (uint8_t pos = 0; p && pos < p->n_positions; pos++) {
			CHECK(tdma_relay_plan_check(p, pos, hg, NULL) != 0,
			      "R1 must not fit parent %s position %u", p->name, pos);
		}
	}
	CHECK(tdma_relay_plan_check(tdma_plan_get(TDMA_PLAN_H), 2, hg, NULL) == -EINVAL,
	      "no such position");
	CHECK(tdma_relay_plan_check(tdma_plan_get(TDMA_PLAN_H), 0, tdma_plan_get(TDMA_PLAN_H),
				    NULL) != 0,
	      "a child plan with FLEX regions");

	/* beacon tree extension: after the security extension, with an announced switch */
	{
		struct tdma_beacon b = {.flags = TDMA_F_BSEC | TDMA_F_TREE,
					.network_id = 0x1234,
					.ft_rd_id = 0x10000102,
					.frame = 77,
					.plan_id = TDMA_PLAN_HG,
					.mcs = 4,
					.n = 2,
					.sess_ctr = 5,
					.sess_rand = 6,
					.sflags = TDMA_SF_NEXT,
					.next_frame = 99,
					.next_ctr = 6,
					.next_rand = 7,
					.depth = 2,
					.grid_ss = 24};
		struct tdma_beacon d;
		uint8_t buf[96];
		int n = tdma_beacon_encode(&b, buf, sizeof(buf));

		CHECK(n == TDMA_BEACON_FIXED_LEN + 2 * TDMA_BEACON_ENTRY_LEN + TDMA_BEACON_SEC_LEN +
				      TDMA_BEACON_SEC_NEXT_LEN + TDMA_BEACON_TREE_LEN,
		      "tree ext length %d", n);
		CHECK(n > 0 && tdma_beacon_decode(buf, (size_t)n, &d) == 0 && d.depth == 2 &&
			      d.grid_ss == 24 && d.next_rand == 7 && d.sess_ctr == 5,
		      "tree ext round trip");
		CHECK(n > 0 && tdma_beacon_decode(buf, (size_t)n - 1, &d) == -EINVAL,
		      "short tree ext");
		b.flags = 0;
		n = tdma_beacon_encode(&b, buf, sizeof(buf));
		CHECK(n > 0 && tdma_beacon_decode(buf, (size_t)n, &d) == 0 && d.depth == 0 &&
			      d.grid_ss == 0,
		      "no tree ext: a root's cluster");
		b.flags = TDMA_F_TREE;
		b.depth = 0;
		n = tdma_beacon_encode(&b, buf, sizeof(buf));
		CHECK(n > 0 && tdma_beacon_decode(buf, (size_t)n, &d) == -EINVAL,
		      "tree ext depth 0 off the root's grid");
		b.grid_ss = 0;
		n = tdma_beacon_encode(&b, buf, sizeof(buf));
		CHECK(n > 0 && tdma_beacon_decode(buf, (size_t)n, &d) == 0 && d.depth == 0 &&
			      d.route_len == 0,
		      "tree ext depth 0: a root's (with route record)");
		b.depth = TDMA_MAX_DEPTH + 1;
		b.grid_ss = 12;
		n = tdma_beacon_encode(&b, buf, sizeof(buf));
		CHECK(n > 0 && tdma_beacon_decode(buf, (size_t)n, &d) == -EINVAL,
		      "tree ext too deep");
	}

	/* the route record behind the tree extension (opaque bytes, fuzzed) */
	{
		struct tdma_beacon b = {.flags = TDMA_F_BSEC | TDMA_F_TREE | TDMA_F_HOP,
					.network_id = 0x1234,
					.ft_rd_id = 0x10000102,
					.frame = 77,
					.plan_id = TDMA_PLAN_H,
					.mcs = 4,
					.n = 2,
					.sess_ctr = 5,
					.hop_base = 1703,
					.hop_mask = 0x1f,
					.hop_seed = 9,
					.depth = 0,
					.grid_ss = 0,
					.route_len = TDMA_ROUTE_MAX};
		struct tdma_beacon d;
		uint8_t buf[128];
		uint32_t rnd = 12345;
		int n;

		for (int i = 0; i < TDMA_ROUTE_MAX; i++) {
			b.route[i] = (uint8_t)(0xa0 + i);
		}
		n = tdma_beacon_encode(&b, buf, sizeof(buf));
		CHECK(n == TDMA_BEACON_FIXED_LEN + 2 * TDMA_BEACON_ENTRY_LEN + TDMA_BEACON_HOP_LEN +
				      TDMA_BEACON_SEC_LEN + TDMA_BEACON_TREE_LEN +
				      TDMA_BEACON_ROUTE_HDR_LEN + TDMA_ROUTE_MAX,
		      "route record length %d", n);
		CHECK(n > 0 && tdma_beacon_decode(buf, (size_t)n, &d) == 0 &&
			      d.route_len == TDMA_ROUTE_MAX &&
			      !memcmp(d.route, b.route, TDMA_ROUTE_MAX) && d.hop_mask == 0x1f,
		      "route record round trip");
		CHECK(n > 0 && tdma_beacon_decode(buf, (size_t)n - 1, &d) == -EINVAL,
		      "truncated route record");
		/* a beacon with the two-byte tree extension only has no record */
		CHECK(n > 0 && tdma_beacon_decode(buf, (size_t)n - 1 - TDMA_ROUTE_MAX, &d) == 0 &&
			      d.route_len == 0,
		      "two-byte tree extension");
		b.route_len = TDMA_ROUTE_MAX + 1;
		CHECK(tdma_beacon_encode(&b, buf, sizeof(buf)) == -ENOBUFS,
		      "route record too long");
		b.route_len = 3;
		n = tdma_beacon_encode(&b, buf, sizeof(buf));
		CHECK(n > 0, "short route record");
		buf[n - 4] = TDMA_ROUTE_MAX + 1;
		CHECK(tdma_beacon_decode(buf, (size_t)n, &d) == -EINVAL,
		      "route length above the max");
		/* a position move after the route record (and after an empty one) */
		for (int rl = 0; rl <= 3; rl += 3) {
			b.route_len = (uint8_t)rl;
			b.pm_valid = true;
			b.pm_from = 2;
			b.pm_to = 1;
			b.pm_frame = 80;
			n = tdma_beacon_encode(&b, buf, sizeof(buf));
			CHECK(n > 0 && tdma_beacon_decode(buf, (size_t)n, &d) == 0 && d.pm_valid &&
				      d.pm_from == 2 && d.pm_to == 1 && d.pm_frame == 80 &&
				      d.route_len == rl && !memcmp(d.route, b.route, (size_t)rl),
			      "position move round trip (route %d B)", rl);
			/* what an older decoder sees: the route record, the rest ignored */
			CHECK(n > 0 &&
				      tdma_beacon_decode(buf, (size_t)n - 2u - TDMA_BEXT_PMOVE_LEN,
							 &d) == 0 &&
				      !d.pm_valid && d.route_len == rl,
			      "without the extension");
			buf[n - 2 - TDMA_BEXT_PMOVE_LEN] = 9; /* an unknown type: skipped */
			CHECK(tdma_beacon_decode(buf, (size_t)n, &d) == 0 && !d.pm_valid,
			      "unknown extension skipped");
		}
		b.pm_valid = false;
		/* fuzz: every truncation and random byte flips decode or fail cleanly, never
		 * overrun */
		b.route_len = TDMA_ROUTE_MAX;
		n = tdma_beacon_encode(&b, buf, sizeof(buf));
		for (int it = 0; it < 4000 && n > 0; it++) {
			uint8_t f[128];
			size_t fl = (size_t)n;

			memcpy(f, buf, (size_t)n);
			rnd = rnd * 1103515245u + 12345u;
			f[2 + (rnd >> 8) % ((size_t)n - 2)] ^= (uint8_t)(rnd >> 16);
			if (it & 1) {
				fl = (rnd >> 4) % ((size_t)n + 1);
			}
			if (tdma_beacon_decode(f, fl, &d) == 0) {
				CHECK(d.route_len <= TDMA_ROUTE_MAX && d.n <= TDMA_MAX_POSITIONS,
				      "fuzzed beacon in range");
			}
		}
	}

	/* storage split: the PT keeps peer 0 + its deep queue, the child cluster the last peers */
	{
		static struct tdma_mac_store st;
		struct tdma_mem all = tdma_mem_of(&st), pt, rl;

		CHECK(tdma_mem_split(&all, &pt, &rl, 2, 3) == 0, "split");
		CHECK(pt.n_peers == 1 && pt.peers == st.peers && pt.n_ras == TDMA_RAS_SLOTS - 3 &&
			      rl.n_peers == 2 && rl.peers == &st.peers[TDMA_MAX_POSITIONS - 2] &&
			      rl.n_ras == 3 && rl.ras == &st.ras[TDMA_RAS_SLOTS - 3] &&
			      rl.qmem + rl.n_chunks <= st.qmem + TDMA_TXQ_POOL_CHUNKS &&
			      pt.qmem + pt.n_chunks <= rl.qmem,
		      "split layout");
		CHECK(tdma_mem_split(&all, &pt, &rl, TDMA_MAX_POSITIONS, 3) == -EINVAL &&
			      tdma_mem_split(&all, &pt, &rl, 2, TDMA_RAS_SLOTS) == -EINVAL &&
			      tdma_mem_split(&all, &pt, &rl, 0, 3) == -EINVAL,
		      "impossible splits");
	}
}

/* ---- relay networks in the sim --------------------------------------------------------- */

static struct sim *s;

static uint32_t rd(int node)
{
	return s->nodes[node].cfg.rd_id;
}

/* A node: FT (ft_rd 0) or a PT pinned to the node `parent` (-1: none), relay: child carrier. */
static int add(enum tdma_role role, uint8_t box, int parent, uint16_t relay_ch)
{
	int i = sim_add_node(s, role, box, TDMA_PLAN_H, (int64_t)(sim_rand(s) % (1ull << 40)),
			     (int32_t)(sim_rand(s) % 80001) - 40000); /* +-40 ppm */
	struct sim_node *n = &s->nodes[i];

	n->cfg.ul_lead_trim = TDMA_US_TO_TICKS(300);
	n->cfg.dl_lead_trim = TDMA_US_TO_TICKS(150);
	if (role == TDMA_ROLE_FT) {
		n->cfg.channel = CH_A;
		n->cfg.plan_auto = true;
		n->cfg.plan_t2 = n->cfg.plan_bq = true;
		n->cfg.plan_multi = TDMA_PLAN_H4;
	} else {
		n->cfg.channel = 0; /* search every carrier */
		n->cfg.ft_rd_filter = parent >= 0 ? s->nodes[parent].cfg.rd_id : 0;
	}
	if (relay_ch) {
		sim_relay_on(s, i, relay_ch);
	}
	return i;
}

static void sec_model(bool on)
{
	sim_sec_all = on;
	sim_grant_ahead = false;
	sim_sec_cost_us = on ? 450 : 0;
	sim_sec_open_us = on ? 250 : 0;
	sim_sec_busy_us = on ? 450 : 0;
	if (on) {
		sim_sec_stats_reset();
	}
}

static bool assoc_to(int pt, int parent)
{
	const struct sim_node *n = &s->nodes[pt];

	return n->alive && tdma_get_state(&n->mac) == TDMA_ST_ASSOCIATED &&
	       tdma_parent(&n->mac) == rd(parent);
}

static uint64_t wait_until(bool (*cond)(void), uint64_t deadline)
{
	while (s->t < deadline) {
		sim_run_until(s, s->t + TDMA_FRAME_TICKS / 2);
		if (cond()) {
			return s->t;
		}
	}
	return UINT64_MAX;
}

static uint32_t sum_mac(size_t off, bool relay_too)
{
	uint32_t v = 0;

	for (int i = 0; i < s->n_nodes; i++) {
		v += *(const uint32_t *)((const uint8_t *)tdma_get_stats(&s->nodes[i].mac) + off);
		if (relay_too && s->nodes[i].relay_on && s->nodes[i].relay_starts) {
			v += *(const uint32_t *)((const uint8_t *)tdma_get_stats(
							 &s->nodes[i].rmac) +
						 off);
		}
	}
	return v;
}

#define MSTAT(f) sum_mac(offsetof(struct tdma_stats, f), true)

/* ---- traffic: probes and bulk between two nodes, latency per flow -------------------------- */

#define R_FLOWS 12
#define R_LAT   20000
#define R_MAGIC 0xa55a

struct rflow {
	const char *name;
	int src, dst;
	size_t len;
	uint64_t gap; /* 0: saturating bulk */
	uint64_t t_stop;
	uint32_t sent, got, dup, fwd_drop;
	int via;  /* -1, or the relay that forwards it (rdeliver) */
	int via2; /* -1, or a second relay after via (3 hops) */
	bool own; /* the source's own priority traffic (TDMA_PRIO_OWN) */
	uint64_t bytes;
	uint32_t n_lat;
	uint32_t lat[R_LAT];
	uint32_t seen[R_LAT / 32 + 1];
};

static struct rflow rf[R_FLOWS];
static int n_rf;

static void rflow_send(struct sim *sm, void *arg)
{
	struct rflow *f = arg;
	uint8_t msg[TDMA_MAX_SDU];
	int fi = (int)(f - rf);

	if (sm->t >= f->t_stop || f->sent >= R_LAT) {
		return;
	}
	memset(msg, 0, sizeof(msg));
	msg[0] = R_MAGIC & 0xff;
	msg[1] = R_MAGIC >> 8;
	msg[2] = (uint8_t)fi;
	memcpy(&msg[4], &f->sent, 4);
	memcpy(&msg[8], &sm->t, 8);
	if (sim_send(sm, f->src, rd(f->via >= 0 ? f->via : f->dst), msg, f->len,
		     f->gap && f->len <= 64 ? (f->own ? TDMA_PRIO_OWN : 1u) : 0u) == 0) {
		f->sent++;
		sim_at(sm, sm->t + (f->gap ? f->gap / 2 + sim_rand(sm) % f->gap : MS(1)),
		       rflow_send, f);
	} else {
		sim_at(sm, sm->t + MS(1), rflow_send, f); /* queue full (bulk) / not linked yet */
	}
}

/*
 * Store and forward at a relay (the app's mesh layer, mesh_fwd.c): a flow with
 * a `via` node is sent to it and passed on R_FWD_US after the delivery (the
 * DKs open the burst, deliver and forward in ~0.45 ms after its PDC event).
 */
#define R_FWD_US 450
#define R_FWDQ   64

static struct rfwd {
	int node, flow, to;
	size_t len;
	uint8_t msg[64];
} fq[R_FWDQ];
static unsigned int fq_n;

static void rfwd_send(struct sim *sm, void *arg)
{
	struct rfwd *q = arg;
	struct rflow *f = &rf[q->flow];

	if (sim_send(sm, q->node, rd(q->to), q->msg, q->len, 1) != 0) {
		f->fwd_drop++;
	}
}

static void rdeliver(struct sim *sm, int node, uint32_t src, const uint8_t *data, size_t len)
{
	struct rflow *f;
	uint32_t id;
	uint64_t t0;

	if (len < 16 || data[0] != (R_MAGIC & 0xff) || data[1] != (R_MAGIC >> 8) ||
	    data[2] >= n_rf) {
		return;
	}
	f = &rf[data[2]];
	if (len <= sizeof(fq[0].msg) && ((f->via >= 0 && node == f->via && src == rd(f->src)) ||
					 (f->via2 >= 0 && node == f->via2 && src == rd(f->via)))) {
		struct rfwd *q = &fq[fq_n++ % R_FWDQ];

		q->node = node;
		q->to = node == f->via && f->via2 >= 0 ? f->via2 : f->dst;
		q->flow = data[2];
		q->len = len;
		memcpy(q->msg, data, len);
		sim_at(sm, sm->t + TDMA_US_TO_TICKS(R_FWD_US), rfwd_send, q);
		return;
	}
	if (f->via >= 0 && src == rd(f->via2 >= 0 ? f->via2 : f->via)) {
		src = rd(f->src); /* forwarded: the relay's link delivered it */
	}
	memcpy(&id, &data[4], 4);
	memcpy(&t0, &data[8], 8);
	if (node != f->dst || src != rd(f->src) || id >= R_LAT) {
		return;
	}
	if (f->seen[id / 32] & (1u << (id % 32))) {
		f->dup++;
		return;
	}
	f->seen[id / 32] |= 1u << (id % 32);
	f->got++;
	f->bytes += len;
	f->lat[f->n_lat++] = (uint32_t)(sm->t - t0);
}

static struct rflow *rflow_add(const char *name, int src, int dst, size_t len, uint64_t gap,
			       uint64_t t0, uint64_t t1)
{
	struct rflow *f = &rf[n_rf++];

	memset(f, 0, sizeof(*f));
	f->name = name;
	f->src = src;
	f->dst = dst;
	f->len = len;
	f->gap = gap;
	f->t_stop = t1;
	f->via = -1;
	f->via2 = -1;
	sim_at(s, t0 + sim_rand(s) % MS(10), rflow_send, f);
	return f;
}

static int cmp32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return x < y ? -1 : x > y;
}

static uint64_t rflow_p99(struct rflow *f, uint64_t *avg, uint64_t *mx)
{
	uint64_t sum = 0;

	if (!f->n_lat) {
		*avg = *mx = 0;
		return 0;
	}
	qsort(f->lat, f->n_lat, sizeof(f->lat[0]), cmp32);
	for (uint32_t i = 0; i < f->n_lat; i++) {
		sum += f->lat[i];
	}
	*avg = sum / f->n_lat;
	*mx = f->lat[f->n_lat - 1];
	return f->lat[(f->n_lat * 99u) / 100u];
}

/* Latency row per probe flow; returns the worst p99 (ticks). */
static uint64_t probe_report(const char *set)
{
	uint64_t worst = 0;

	for (int i = 0; i < n_rf; i++) {
		struct rflow *f = &rf[i];
		uint64_t avg, mx, p99;

		if (!f->gap) {
			continue;
		}
		p99 = rflow_p99(f, &avg, &mx);
		worst = p99 > worst ? p99 : worst;
		printf("    %-10s %-8s %5u sent %5u got %2u dup   avg %5llu  p99 %5llu  max %5llu "
		       "us\n",
		       set, f->name, f->sent, f->got, f->dup, US(avg), US(p99), US(mx));
		{
			struct lat_row r = {.sent = f->sent,
					    .delivered = f->got,
					    .dups = f->dup,
					    .avg = avg,
					    .p99 = p99,
					    .max = mx,
					    .bound = TDMA_US_TO_TICKS(6900)};

			snprintf(r.name, sizeof(r.name), "%s %s", set, f->name);
			r.min = f->n_lat ? f->lat[0] : 0;
			lat_table_add(&r);
		}
	}
	return worst;
}

static void check_relay_clean(const char *what)
{
	uint32_t pe = MSTAT(port_errors), late = MSTAT(late_slots);

	CHECK(sim_phy_errors(s) == 0, "%s: PHY contract violations (merged op sequences): %u", what,
	      sim_phy_errors(s));
	CHECK(pe == 0, "%s: port errors %u", what, pe);
	CHECK(late == 0, "%s: late slots %u", what, late);
	CHECK(sim_sec_st.nonce_reuse == 0, "%s: nonce reuse %llu", what,
	      (unsigned long long)sim_sec_st.nonce_reuse);
}

/* chain: A (root FT) <- B (relay) <- C, D a leaf of A */
enum {
	NA,
	NB,
	NC,
	ND
};

static bool chain_up(void)
{
	return assoc_to(NB, NA) && assoc_to(NC, NB) && assoc_to(ND, NA);
}

static void chain_build(uint64_t seed)
{
	s = sim_init(seed);
	s->on_deliver = rdeliver;
	n_rf = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 2, NA, CH_B);
	add(TDMA_ROLE_PT, 3, NB, 0);
	add(TDMA_ROLE_PT, 4, NA, 0);
	for (int i = 0; i < s->n_nodes; i++) {
		sim_start(s, i);
	}
}

void test_relay_chain(void)
{
	struct sim_node *b;
	uint64_t t_up, t0;
	struct rflow *bulk[4];
	uint32_t a_flex_b;

	sec_model(true);
	chain_build(11);
	t_up = wait_until(chain_up, MS(20000));
	CHECK(t_up != UINT64_MAX, "chain associated");
	b = &s->nodes[NB];
	printf("    associated after %llu ms: B relay on %u (A on %u), C under B, D under A\n",
	       US(t_up) / 1000, tdma_channel(&b->rmac), tdma_channel(&s->nodes[NA].mac));
	CHECK(tdma_get_state(&b->rmac) == TDMA_ST_FT && tdma_channel(&b->rmac) == CH_B &&
		      tdma_channel(&s->nodes[NA].mac) == CH_A,
	      "B's child cluster on its own carrier");
	{
		uint8_t d = 9, g = 9;

		tdma_tree(&s->nodes[NC].mac, &d, &g);
		/* (B's cluster on HG or HGX, the latter once B is in position 1) */
		CHECK(d == 1 && g == tdma_relay_offset_ss(s->nodes[NA].mac.plan, b->rmac.plan),
		      "C sees depth %u grid %u", d, g);
		tdma_tree(&s->nodes[ND].mac, &d, &g);
		CHECK(d == 0 && g == 0, "D sees the root's cluster");
	}
	{
		const struct tdma_mac *a = &s->nodes[NA].mac;
		bool flag = false;

		for (uint8_t i = 0; i < a->plan->n_positions; i++) {
			flag |= a->peers[i].rd_id == rd(NB) && a->peers[i].relay;
		}
		CHECK(flag, "A knows B is a relay");
	}
	/* 64 B probes on every link at once, both ways, 10 s */
	t0 = s->t + MS(200);
	rflow_add("A->B", NA, NB, 64, MS(20), t0, t0 + MS(10000));
	rflow_add("B->A", NB, NA, 64, MS(20), t0, t0 + MS(10000));
	rflow_add("B->C", NB, NC, 64, MS(20), t0, t0 + MS(10000));
	rflow_add("C->B", NC, NB, 64, MS(20), t0, t0 + MS(10000));
	rflow_add("A->D", NA, ND, 64, MS(20), t0, t0 + MS(10000));
	rflow_add("D->A", ND, NA, 64, MS(20), t0, t0 + MS(10000));
	sim_run_until(s, t0 + MS(10300));
	{
		uint64_t worst = probe_report("chain");

		CHECK(worst <= TDMA_US_TO_TICKS(7000 + 450),
		      "per-link p99 %llu us (H bound + seal)", US(worst));
	}
	for (int i = 0; i < n_rf; i++) {
		CHECK(rf[i].got == rf[i].sent && rf[i].dup == 0, "%s: %u of %u, %u dup", rf[i].name,
		      rf[i].got, rf[i].sent, rf[i].dup);
	}
	check_relay_clean("probes");

	/* bulk on the relay links, one at a time, 3 s each: throughput per relay link */
	a_flex_b = tdma_get_stats(&b->mac)->flex_rx + tdma_get_stats(&b->mac)->flex_tx;
	static const struct {
		const char *name;
		int src, dst;
	} bl[] = {{"B->A", NB, NA}, {"A->B", NA, NB}, {"C->B", NC, NB}, {"B->C", NB, NC}};

	for (int k = 0; k < 4; k++) {
		uint64_t t1 = s->t + MS(100);

		bulk[k] = rflow_add(bl[k].name, bl[k].src, bl[k].dst, 1000, 0, t1, t1 + MS(3000));
		sim_run_until(s, t1 + MS(3300));
		printf("    bulk %-5s 1000 B SDUs: %5.1f kB/s (%u of %u)\n", bl[k].name,
		       (double)bulk[k]->bytes / 3000.0, bulk[k]->got, bulk[k]->sent);
	}
	/* R1 targets [est]: ~20 kB/s up (2 ss UL), ~39 kB/s down (3 ss DL) per relay link */
	CHECK(bulk[0]->bytes >= 15000u * 3 && bulk[2]->bytes >= 15000u * 3,
	      "relay links UL: B->A %llu, C->B %llu B in 3 s", (unsigned long long)bulk[0]->bytes,
	      (unsigned long long)bulk[2]->bytes);
	CHECK(bulk[1]->bytes >= 28000u * 3 && bulk[3]->bytes >= 28000u * 3,
	      "relay links DL: A->B %llu, B->C %llu B in 3 s", (unsigned long long)bulk[1]->bytes,
	      (unsigned long long)bulk[3]->bytes);
	CHECK(tdma_get_stats(&b->mac)->flex_rx + tdma_get_stats(&b->mac)->flex_tx == a_flex_b &&
		      a_flex_b == 0,
	      "no long bursts to / from the relay");
	/* A's plan under bulk to its relay: H or T, never T2 / T2D / BQ / H4 */
	{
		const struct tdma_stats *as = tdma_get_stats(&s->nodes[NA].mac);
		bool ok = as->plan_multi == 0;

		for (int k = 0; k < 2; k++) {
			for (int p = 0; p < TDMA_PAT_MAX; p++) {
				ok &= as->pat_frames[k][p] == 0;
			}
		}
		for (uint32_t k = 0; k < 8 && k < as->plan_switches; k++) {
			uint8_t id = (uint8_t)(as->psw_log[k] & 15u);

			ok &= id == TDMA_PLAN_H || id == TDMA_PLAN_T;
		}
		CHECK(ok, "A's plans with a relay child: H / T only (%u switches)",
		      as->plan_switches);
	}
	printf("    B: %u slots given to the other instance (up %u / down %u refused ops), %u "
	       "first "
	       "beacon(s) after LBT\n",
	       tdma_get_stats(&b->mac)->relay_away + tdma_get_stats(&b->rmac)->relay_away,
	       b->relay.away_up, b->relay.away_down, tdma_get_stats(&b->rmac)->lbt_ok);
	check_relay_clean("bulk");
	sec_model(false);
}

/*
 * Pipelining at a relay (Part A): SDUs from C forwarded by B to
 * A (and back) 0.45 ms after B got them. With the relay's commits as on the
 * DKs (no FLEX region it is never granted in rx_clear(), its parent-side DL RX
 * committed before its child's burst ends), C's UL burst at root-ss 17-18 / 41-42
 * makes B's next UL (29 / 5): 2 hops up within ~10 ms. Down, B's child DL burst
 * after A's DL is committed before the forwarded SDU is there (+5 ms; not solved yet).
 */
static bool b_c_up(void)
{
	return assoc_to(NB, NA) && assoc_to(NC, NB);
}

static bool b_c_hgx(void)
{
	return b_c_up() && s->nodes[NB].mac.my_pos == 1 &&
	       s->nodes[NB].rmac.plan->id == TDMA_PLAN_HGX && s->nodes[NC].mac.my_pos == 0 &&
	       s->nodes[NC].mac.plan->id == TDMA_PLAN_HGX && !s->nodes[NB].rmac.retime_valid &&
	       !s->nodes[NC].mac.retime_valid;
}

static bool chain_b_back(void)
{
	return assoc_to(NB, NA) && assoc_to(NC, NB) && s->nodes[NB].mac.my_pos >= 0 &&
	       !s->nodes[NB].rmac.retime_valid;
}

void test_relay_pipe(void)
{
	struct rflow *up, *dn;
	uint64_t avg, mx, p99u, p99d;

	sec_model(true);
	/*
	 * A <- B <- C only. B (one child that does not relay) moves to
	 * position 1 of A's cluster (UL 8 / 32) and its cluster to plan HGX (C in
	 * position 0): C's UL 20 / 44 -> B's UL 32 / 8, A's DL 0 / 24 -> B's child
	 * DL 15 / 39 (was 15 -> 29 and 0 -> 19 on HG).
	 */
	s = sim_init(13);
	s->on_deliver = rdeliver;
	n_rf = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 2, NA, CH_B);
	add(TDMA_ROLE_PT, 3, NB, 0);
	for (int i = 0; i < s->n_nodes; i++) {
		sim_start(s, i);
	}
	CHECK(wait_until(b_c_up, MS(20000)) != UINT64_MAX, "chain associated");
	CHECK(wait_until(b_c_hgx, s->t + MS(3000)) != UINT64_MAX,
	      "B in position %d, its cluster on %s, C in position %d", s->nodes[NB].mac.my_pos,
	      s->nodes[NB].rmac.plan->name, s->nodes[NC].mac.my_pos);
	{
		uint64_t t0 = s->t + MS(200);

		up = rflow_add("C->B->A", NC, NA, 64, MS(20), t0, t0 + MS(20000));
		up->via = NB;
		dn = rflow_add("A->B->C", NA, NC, 64, MS(20), t0, t0 + MS(20000));
		dn->via = NB;
		sim_run_until(s, t0 + MS(20300));
	}
	p99u = rflow_p99(up, &avg, &mx);

	printf("    2 hops up   C->B->A: %u of %u, avg %llu p99 %llu max %llu us\n", up->got,
	       up->sent, US(avg), US(p99u), US(mx));
	p99d = rflow_p99(dn, &avg, &mx);
	printf("    2 hops down A->B->C: %u of %u, avg %llu p99 %llu max %llu us\n", dn->got,
	       dn->sent, US(avg), US(p99d), US(mx));
	CHECK(up->got == up->sent && dn->got == dn->sent && !up->dup && !dn->dup,
	      "relayed probes all delivered once (%u/%u, %u/%u)", up->got, up->sent, dn->got,
	      dn->sent);
	/*
	 * one 1-hop worst case (C's UL wait + its burst) + the relay term. With
	 * plan HG's UL run first: up ~3.5 ms (C's UL 12-16 -> B's
	 * UL 29, was 2.5), down ~4 ms (A's DL 0 -> B's child DL 19 in the same
	 * frame; it missed 12 and waited for 36: 7.5). a lone
	 * child takes position 1 (UL 15 -> 29: 2.9 ms up). up 12 ss
	 * (2.5 ms), down 15 ss (3.1 ms).
	 */
	CHECK(p99u <= TDMA_US_TO_TICKS(9500),
	      "2 hops up p99 %llu us <= 9.5 ms (pipelined at the relay)", US(p99u));
	CHECK(p99d <= TDMA_US_TO_TICKS(10600),
	      "2 hops down p99 %llu us <= 10.6 ms (pipelined at the relay)", US(p99d));
	{
		uint8_t d = 0, g = 0;

		tdma_tree(&s->nodes[NC].mac, &d, &g);
		CHECK(d == 1 && g == TDMA_RELAY_HGX_OFFSET_SS, "C sees depth %u grid %u", d, g);
	}
	CHECK(s->nodes[NB].relay.to_hgx == 1 && s->nodes[NB].relay.to_hg == 0 &&
		      tdma_get_stats(&s->nodes[NC].mac)->retimes == 1,
	      "one switch to HGX (%u, %u back), C shifted once (%u)", s->nodes[NB].relay.to_hgx,
	      s->nodes[NB].relay.to_hg, tdma_get_stats(&s->nodes[NC].mac)->retimes);
	check_relay_clean("pipe");
	sec_model(false);
}

/*
 * the tree (A root; B relay with leaf C; D a leaf of A) and every
 * way in and out of plan HGX. B moves to position 1 of A's cluster (D swaps to
 * 0), its cluster to HGX; a second box X asks to join B in an open frame ->
 * HG, X joins; X gone -> HGX again after the hold; C starts relaying -> HG and
 * B back in position 0; C stops -> HGX in position 1. C and D never lose their
 * parents, C's probes go on.
 */
enum {
	HA,
	HB,
	HC,
	HD,
	HX
};

static bool hgx_tree(void)
{
	const struct sim_node *b = &s->nodes[HB];

	return assoc_to(HB, HA) && assoc_to(HC, HB) && assoc_to(HD, HA) && b->mac.my_pos == 1 &&
	       b->rmac.plan->id == TDMA_PLAN_HGX && s->nodes[HC].mac.my_pos == 0 &&
	       s->nodes[HC].mac.plan->id == TDMA_PLAN_HGX && !b->rmac.retime_valid &&
	       !s->nodes[HC].mac.retime_valid && s->nodes[HD].mac.my_pos == 0;
}

static bool hgx_two(void)
{
	return assoc_to(HX, HB) && assoc_to(HC, HB) && s->nodes[HB].rmac.plan->id == TDMA_PLAN_HG;
}

static bool hgx_c_relays(void)
{
	return s->nodes[HB].rmac.plan->id == TDMA_PLAN_HG && s->nodes[HB].mac.my_pos == 0 &&
	       tdma_get_state(&s->nodes[HC].rmac) == TDMA_ST_FT && assoc_to(HC, HB);
}

void test_relay_hgx(void)
{
	struct rflow *up, *dn;
	uint64_t avg, mx, p99u, p99d, t;
	int c_lost, d_lost;

	sec_model(true);
	s = sim_init(41);
	s->on_deliver = rdeliver;
	n_rf = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 2, HA, CH_B);
	add(TDMA_ROLE_PT, 3, HB, 1711);
	add(TDMA_ROLE_PT, 4, HA, 0);
	add(TDMA_ROLE_PT, 5, HB, 0);
	s->nodes[HC].relay_hold = true; /* relay capable, not wanted yet */
	for (int i = 0; i < HX; i++) {
		sim_start(s, i);
	}
	t = wait_until(hgx_tree, MS(30000));
	if (getenv("HGX_DBG")) {
		const struct tdma_mac *a = &s->nodes[HA].mac;

		for (int i = 0; i < 2; i++) {
			fprintf(stderr,
				"DBG A pos %d rd %x relay %d hgx %d ann %d; plan %s pm %d\n", i,
				a->peers[i].rd_id, a->peers[i].relay, a->peers[i].hgx_ok,
				a->peers[i].announced, a->plan->name, a->pm_valid);
		}
		fprintf(stderr, "DBG B up hgx_ok %d pos %d; dn plan %s want %d kids %x %x\n",
			s->nodes[HB].mac.hgx_ok, s->nodes[HB].mac.my_pos,
			s->nodes[HB].rmac.plan->name, s->nodes[HB].rmac.hgx_want,
			s->nodes[HB].rmac.peers[0].rd_id, s->nodes[HB].rmac.peers[1].rd_id);
	}
	CHECK(t != UINT64_MAX, "B in position %d of A (D %d), its cluster %s, C in %d",
	      s->nodes[HB].mac.my_pos, s->nodes[HD].mac.my_pos, s->nodes[HB].rmac.plan->name,
	      s->nodes[HC].mac.my_pos);
	{
		uint64_t t0 = s->t + MS(200);

		up = rflow_add("C->B->A", HC, HA, 64, MS(20), t0, t0 + MS(10000));
		up->via = HB;
		dn = rflow_add("A->B->C", HA, HC, 64, MS(20), t0, t0 + MS(10000));
		dn->via = HB;
		sim_run_until(s, t0 + MS(10300));
	}
	p99u = rflow_p99(up, &avg, &mx);
	printf("    HGX: 2 hops up %llu, down ", US(p99u));
	p99d = rflow_p99(dn, &avg, &mx);
	printf("%llu us p99 (D swapped to position 0)\n", US(p99d));
	CHECK(p99u <= TDMA_US_TO_TICKS(9500) && p99d <= TDMA_US_TO_TICKS(10600), "HGX latency");
	CHECK(up->got == up->sent && dn->got == dn->sent, "all delivered");

	/* a second box asks to join B: HG, it joins */
	{
		uint64_t t1 = s->t;

		up = rflow_add("C->B", HC, HB, 64, MS(20), t1, t1 + MS(70000));
		sim_start(s, HX);
		t = wait_until(hgx_two, t1 + MS(15000));
		CHECK(t != UINT64_MAX, "X joined B (B's cluster %s, %u open-frame asks)",
		      s->nodes[HB].rmac.plan->name, tdma_get_stats(&s->nodes[HB].rmac)->room_asks);
		printf("    X joined B %llu ms after its start (open-frame asks %u)\n",
		       US(t - t1) / 1000, tdma_get_stats(&s->nodes[HB].rmac)->room_asks);
		sim_run_until(s, s->t + MS(2000));
		sim_kill(s, HX);
		/* X gone: HGX again after the hold (30 s) */
		t = wait_until(hgx_tree, s->t + MS(40000));
		CHECK(t != UINT64_MAX, "HGX again after X left (%s)", s->nodes[HB].rmac.plan->name);
		CHECK(t > t1 + MS(30000), "not before the hold");
		sim_run_until(s, t1 + MS(70300));
		CHECK(up->got + 3 >= up->sent, "C->B through it all: %u of %u", up->got, up->sent);
	}
	/* C starts relaying: HG, B in position 0; stops: HGX in position 1 */
	sim_relay_want(s, HC, true);
	t = wait_until(hgx_c_relays, s->t + MS(10000));
	CHECK(t != UINT64_MAX, "C relays: B's cluster %s, B in position %d",
	      s->nodes[HB].rmac.plan->name, s->nodes[HB].mac.my_pos);
	sim_run_until(s, s->t + MS(2000));
	sim_relay_want(s, HC, false);
	t = wait_until(hgx_tree, s->t + MS(10000));
	CHECK(t != UINT64_MAX, "C stopped relaying: HGX again (%s, B in %d)",
	      s->nodes[HB].rmac.plan->name, s->nodes[HB].mac.my_pos);
	c_lost = sim_count_evt(&s->nodes[HC], TDMA_EVT_LOST, 0);
	d_lost = sim_count_evt(&s->nodes[HD], TDMA_EVT_LOST, 0);
	printf("    switches: to HGX %u, to HG %u; C lost its parent %d times, D %d\n",
	       s->nodes[HB].relay.to_hgx, s->nodes[HB].relay.to_hg, c_lost, d_lost);
	CHECK(c_lost == 0 && d_lost == 0, "C and D kept their parents");
	CHECK(s->nodes[HB].relay.to_hgx == 3 && s->nodes[HB].relay.to_hg == 2, "3 + 2 switches");
	check_relay_clean("hgx");
	sec_model(false);
}

/*
 * a leaf under an HGX relay loses it. A; B relay (leaf C, HGX in
 * position 1), D relay without children (HG, position 0: an empty cluster
 * stays on HG). B dies: C goes to D on its carrier (the mesh's fast reroute),
 * D now has one leaf child: A moves it to the free position 1 and D's cluster
 * goes to HGX; C's probes to A come through D.
 */
static uint64_t hr_lost_t, hr_assoc_t;

static void hr_kill_b(struct sim *sm, void *arg)
{
	(void)arg;
	sim_kill(sm, HB);
}

static bool hr_up(void)
{
	return assoc_to(HB, HA) && assoc_to(HC, HB) && assoc_to(HD, HA) &&
	       s->nodes[HB].rmac.plan->id == TDMA_PLAN_HGX && s->nodes[HB].mac.my_pos == 1 &&
	       tdma_get_state(&s->nodes[HD].rmac) == TDMA_ST_FT &&
	       s->nodes[HD].rmac.plan->id == TDMA_PLAN_HG;
}

static bool hr_after(void)
{
	return assoc_to(HC, HD) && s->nodes[HD].mac.my_pos == 1 &&
	       s->nodes[HD].rmac.plan->id == TDMA_PLAN_HGX && !s->nodes[HD].rmac.retime_valid &&
	       s->nodes[HC].mac.plan->id == TDMA_PLAN_HGX;
}

static void hr_watch(struct sim *sm, void *arg)
{
	struct sim_node *c = &sm->nodes[HC];

	(void)arg;
	if (!hr_lost_t && tdma_get_state(&c->mac) != TDMA_ST_ASSOCIATED) {
		hr_lost_t = sm->t;
		c->cfg.ft_rd_filter = rd(HD);
		tdma_pt_set_target_ch(&c->mac, rd(HD), tdma_channel(&sm->nodes[HD].rmac), MS(500));
	}
	if (hr_lost_t && !hr_assoc_t && assoc_to(HC, HD)) {
		hr_assoc_t = sm->t;
	}
	if (!hr_assoc_t) {
		sim_at(sm, sm->t + MS(1), hr_watch, NULL);
	}
}

void test_relay_hgx_reroute(void)
{
	struct rflow *up;
	uint64_t t, t_kill;

	sec_model(true);
	s = sim_init(43);
	s->on_deliver = rdeliver;
	n_rf = 0;
	hr_lost_t = hr_assoc_t = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 2, HA, CH_B);
	add(TDMA_ROLE_PT, 3, HB, 0);
	add(TDMA_ROLE_PT, 4, HA, 1709);
	for (int i = 0; i < 4; i++) {
		sim_start(s, i);
	}
	t = wait_until(hr_up, MS(30000));
	CHECK(t != UINT64_MAX, "B (HGX, position %d) with C, D (%s) empty", s->nodes[HB].mac.my_pos,
	      s->nodes[HD].rmac.plan->name);
	t_kill = s->t + MS(200);
	up = rflow_add("C->D", HC, HD, 64, MS(20), t_kill + MS(300), t_kill + MS(6000));
	sim_at(s, t_kill, hr_kill_b, NULL);
	sim_at(s, t_kill, hr_watch, NULL);
	t = wait_until(hr_after, t_kill + MS(6000));
	printf("    B killed: C under D %llu ms after the kill, D in position %d, its cluster %s "
	       "%llu ms "
	       "after the kill\n",
	       hr_assoc_t ? US(hr_assoc_t - t_kill) / 1000 : 0, s->nodes[HD].mac.my_pos,
	       s->nodes[HD].rmac.plan->name, t != UINT64_MAX ? US(t - t_kill) / 1000 : 0);
	CHECK(hr_assoc_t && hr_assoc_t - t_kill < MS(500), "C rerouted to D");
	CHECK(t != UINT64_MAX, "D in position 1 on HGX");
	(void)up;
	sim_run_until(s, t_kill + MS(6300));
	{
		uint32_t late = 0;

		for (uint32_t i = 0; i < up->n_lat; i++) {
			late += up->lat[i] > TDMA_US_TO_TICKS(9500);
		}
		printf("    C->D %u of %u from 0.3 s after the kill (%u over 9.5 ms)\n", up->got,
		       up->sent, late);
		CHECK(up->sent > 200 && up->got + 2 >= up->sent, "C->D went on");
	}
	sec_model(false);
}

/*
 * EF abuse at a relay. C sends priority SDUs every `gap` through B,
 * B its own every 20 ms; the modem may fail some of B's TX bursts (on the DKs
 * B's UL bursts cut from a child's forwarded bulk failed now and then). B's own
 * go ahead of forwarded priority not sent yet (TDMA_PRIO_OWN), and a failed
 * burst's PDUs go again in B's next burst (link_tx_failed()), not after the
 * parent's next DL burst shows them missing (+10 ms: p99 18.4 ms on the DKs).
 */
static uint64_t ef_abuse_run(uint64_t gap, bool own, uint32_t fail_ppm, uint32_t *gotc,
			     uint32_t *sentc)
{
	struct rflow *fb, *fc;
	uint64_t avg, mx;

	s = sim_init(13);
	s->on_deliver = rdeliver;
	n_rf = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 2, NA, CH_B);
	add(TDMA_ROLE_PT, 3, NB, 0);
	for (int i = 0; i < s->n_nodes; i++) {
		sim_start(s, i);
	}
	CHECK(wait_until(b_c_hgx, MS(20000)) != UINT64_MAX, "A <- B <- C on HGX");
	s->nodes[NB].tx_fail_ppm = fail_ppm;
	{
		uint64_t t0 = s->t + MS(200);

		fc = rflow_add("C->B->A flood", NC, NA, 64, gap, t0, t0 + MS(10000));
		fc->via = NB;
		fb = rflow_add("B->A own", NB, NA, 64, MS(20), t0, t0 + MS(10000));
		fb->own = own;
		sim_run_until(s, t0 + MS(10500));
	}
	*gotc = fc->got;
	*sentc = fc->sent;
	return rflow_p99(fb, &avg, &mx);
}

void test_relay_ef_abuse(void)
{
	uint64_t fifo, own, fail, fail_own;
	uint32_t g[4], n[4], failed;

	sec_model(true);
	fail = ef_abuse_run(MS(16), false, 20000, &g[2], &n[2]);
	failed = s->nodes[NB].tx_failed;
	fail_own = ef_abuse_run(MS(8), true, 20000, &g[3], &n[3]);
	fifo = ef_abuse_run(MS(8), false, 0, &g[0], &n[0]);
	own = ef_abuse_run(MS(8), true, 0, &g[1], &n[1]);
	printf("    B's own EF p99 (C every 8 ms): FIFO %llu, own first %llu us; with 2 %% of B's "
	       "bursts "
	       "failed (%u): C every 16 ms %llu, every 8 ms + own first %llu us; C's flood %u/%u "
	       "%u/%u\n",
	       US(fifo), US(own), failed, US(fail), US(fail_own), g[0], n[0], g[1], n[1]);
	CHECK(failed > 20, "failures injected (%u)", failed);
	CHECK(own <= TDMA_US_TO_TICKS(8000) && own + TDMA_US_TO_TICKS(2000) < fifo,
	      "own first: %llu us (FIFO %llu us)", US(own), US(fifo));
	CHECK(fail <= TDMA_US_TO_TICKS(10500) && fail_own <= TDMA_US_TO_TICKS(12500),
	      "a failed burst costs one burst period (%llu / %llu us)", US(fail), US(fail_own));
	CHECK(g[0] == n[0] && g[1] == n[1] && g[2] + 2 >= n[2], "C's flood goes on");
	check_relay_clean("ef_abuse");
	sec_model(false);
}

/*
 * pipelining through two relays, A <- B <- C <- D (a three-hop chain).
 * The child at depth 1 sits in position 1 of B's cluster (UL 14 ss before
 * B's), the depth-2 cluster runs TDMA_RELAY_OFFSET_SS (14) after B's, its
 * child in position 0: C's child DL 14 ss after B's DL (12: +5 ms down at
 * depth 2), D's UL 13 ss before C's (was 15).
 */
static bool chain3_up(void)
{
	return assoc_to(NB, NA) && assoc_to(NC, NB) && assoc_to(ND, NC) &&
	       tdma_get_state(&s->nodes[NC].rmac) == TDMA_ST_FT && s->nodes[NC].mac.my_pos == 1 &&
	       s->nodes[ND].mac.my_pos == 0;
}

void test_relay_pipe3(void)
{
	struct rflow *up, *dn, *up2;
	uint64_t avg, mx, p99u, p99d, p99c;

	sec_model(true);
	s = sim_init(29);
	s->on_deliver = rdeliver;
	n_rf = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 2, NA, CH_B);
	add(TDMA_ROLE_PT, 3, NB, 1711);
	add(TDMA_ROLE_PT, 4, NC, 0);
	for (int i = 0; i < s->n_nodes; i++) {
		sim_start(s, i);
	}
	CHECK(wait_until(chain3_up, MS(30000)) != UINT64_MAX,
	      "chain A <- B <- C <- D, C in position %d of B, D in %d of C",
	      s->nodes[NC].mac.my_pos, s->nodes[ND].mac.my_pos);
	{
		uint8_t d = 0, g = 0;

		tdma_tree(&s->nodes[ND].mac, &d, &g);
		CHECK(d == 2 && g == tdma_grid_of_depth(2), "D: depth %u grid %u", d, g);
	}
	{
		uint64_t t0 = s->t + MS(200);

		up = rflow_add("D->C->B->A", ND, NA, 64, MS(20), t0, t0 + MS(20000));
		up->via = NC;
		up->via2 = NB;
		dn = rflow_add("A->B->C->D", NA, ND, 64, MS(20), t0, t0 + MS(20000));
		dn->via = NB;
		dn->via2 = NC;
		sim_run_until(s, t0 + MS(20300));
		/* (alone: one UL burst of C carries one 64 B SDU) */
		t0 = s->t + MS(100);
		up2 = rflow_add("C->B->A", NC, NA, 64, MS(20), t0, t0 + MS(20000));
		up2->via = NB;
		sim_run_until(s, t0 + MS(20300));
	}
	p99u = rflow_p99(up, &avg, &mx);
	printf("    3 hops up   D->C->B->A: %u of %u, avg %llu p99 %llu max %llu us\n", up->got,
	       up->sent, US(avg), US(p99u), US(mx));
	p99d = rflow_p99(dn, &avg, &mx);
	printf("    3 hops down A->B->C->D: %u of %u, avg %llu p99 %llu max %llu us\n", dn->got,
	       dn->sent, US(avg), US(p99d), US(mx));
	p99c = rflow_p99(up2, &avg, &mx);
	printf("    2 hops up   C->B->A:    %u of %u, avg %llu p99 %llu max %llu us\n", up2->got,
	       up2->sent, US(avg), US(p99c), US(mx));
	CHECK(up->got == up->sent && dn->got == dn->sent && up2->got == up2->sent && !up->dup &&
		      !dn->dup && !up2->dup,
	      "relayed probes all delivered once");
	/* one 1-hop worst case + the relay terms: up 13 + 14 ss, down 19 + 14 ss (pipelined) */
	CHECK(p99u <= TDMA_US_TO_TICKS(14000), "3 hops up p99 %llu us <= 14 ms", US(p99u));
	CHECK(p99d <= TDMA_US_TO_TICKS(15500), "3 hops down p99 %llu us <= 15.5 ms", US(p99d));
	CHECK(p99c <= TDMA_US_TO_TICKS(10000), "2 hops up from position 1 p99 %llu us <= 10 ms",
	      US(p99c));
	check_relay_clean("pipe3");
	sec_model(false);
}

/*
 * Backpressure (TDMA_F_HOLD): B holds its child C; C starts no new
 * bulk SDU towards B (its probes still go), then goes on when released; B
 * holds its parent A the same way for the downstream direction.
 */
static struct rflow *hold_f[4];

static void hold_set(struct sim *sm, void *arg)
{
	struct sim_node *b = &sm->nodes[NB];
	bool on = arg != NULL;

	tdma_link_hold(&b->rmac, rd(NC), on);
	tdma_link_hold(&b->mac, rd(NA), on);
}

void test_relay_hold(void)
{
	uint64_t t0, t1;
	uint32_t up0, dn0, up1, dn1, up2, dn2, pr0, pr1;

	sec_model(true);
	chain_build(17);
	CHECK(wait_until(chain_up, MS(20000)) != UINT64_MAX, "chain associated");
	t0 = s->t + MS(100);
	hold_f[0] = rflow_add("C->B bulk", NC, NB, 1000, 0, t0, t0 + MS(6000));
	hold_f[1] = rflow_add("A->B bulk", NA, NB, 1000, 0, t0, t0 + MS(6000));
	hold_f[2] = rflow_add("C->B probe", NC, NB, 64, MS(20), t0, t0 + MS(6000));
	t1 = t0 + MS(2000);
	sim_at(s, t1, hold_set, (void *)1);
	sim_at(s, t1 + MS(2000), hold_set, NULL);
	sim_run_until(s, t1);
	up0 = hold_f[0]->got;
	dn0 = hold_f[1]->got;
	pr0 = hold_f[2]->got;
	sim_run_until(s, t1 + MS(300)); /* what was under way when the hold came */
	up1 = hold_f[0]->got;
	dn1 = hold_f[1]->got;
	sim_run_until(s, t1 + MS(2000));
	up2 = hold_f[0]->got;
	dn2 = hold_f[1]->got;
	pr1 = hold_f[2]->got;
	sim_run_until(s, t0 + MS(6300));
	printf("    bulk SDUs: C->B %u in 2 s, %u held (+%u in the first 0.3 s), %u after the "
	       "release; "
	       "A->B %u, %u held (+%u), %u after; probes C->B %u while held\n",
	       up0, up2 - up1, up1 - up0, hold_f[0]->got - up2, dn0, dn2 - dn1, dn1 - dn0,
	       hold_f[1]->got - dn2, pr1 - pr0);
	CHECK(up2 == up1 && dn2 == dn1, "nothing new of bulk while held (C->B +%u, A->B +%u)",
	      up2 - up1, dn2 - dn1);
	CHECK(pr1 - pr0 >= 80, "priority goes on while held (%u probes)", pr1 - pr0);
	CHECK(hold_f[0]->got - up2 >= up0 / 2 && hold_f[1]->got - dn2 >= dn0 / 2,
	      "bulk goes on after the release");
	CHECK(tdma_get_stats(&s->nodes[NB].rmac)->hold_on >= 1 &&
		      tdma_get_stats(&s->nodes[NC].mac)->hold_waits > 0,
	      "hold counted (asked %u, waits %u)", tdma_get_stats(&s->nodes[NB].rmac)->hold_on,
	      tdma_get_stats(&s->nodes[NC].mac)->hold_waits);
	for (int i = 0; i < 3; i++) {
		CHECK(hold_f[i]->dup == 0, "%s: no duplicates", hold_f[i]->name);
	}
	check_relay_clean("hold");
	sec_model(false);
}

/*
 * MAC level: a relay's parent dies, the relay keeps its child cluster
 * and fast-associates to a warm backup on its known carrier (same grid: no
 * shift); its child never notices. A: root; B, D: relays under A; C: relay
 * under B (backup D) with child E.
 */
enum {
	RA,
	RB,
	RC,
	RD,
	RE
};
#define CH_D 1703
#define CH_C 1711

static uint64_t rr_lost_t, rr_assoc_t;

static bool rr_up(void)
{
	return assoc_to(RB, RA) && assoc_to(RD, RA) && assoc_to(RC, RB) && assoc_to(RE, RC) &&
	       tdma_get_state(&s->nodes[RD].rmac) == TDMA_ST_FT;
}

static void rr_kill_b(struct sim *sm, void *arg)
{
	(void)arg;
	sim_kill(sm, RB);
}

/* the mesh layer's part : parent lost -> keep the cluster, the backup on its carrier */
static void rr_watch(struct sim *sm, void *arg)
{
	struct sim_node *c = &sm->nodes[RC];

	(void)arg;
	if (!rr_lost_t && tdma_get_state(&c->mac) != TDMA_ST_ASSOCIATED) {
		rr_lost_t = sm->t;
		c->relay_keep = true;
		tdma_pt_set_target_ch(&c->mac, rd(RD), tdma_channel(&sm->nodes[RD].rmac), MS(500));
	}
	if (rr_lost_t && !rr_assoc_t && assoc_to(RC, RD)) {
		rr_assoc_t = sm->t;
	}
	if (!rr_assoc_t) {
		sim_at(sm, sm->t + MS(1), rr_watch, NULL);
	}
}

void test_relay_reroute(void)
{
	uint64_t t0, t_kill;
	int e_lost;
	struct rflow *fe, *fc;

	sec_model(true);
	s = sim_init(23);
	s->on_deliver = rdeliver;
	n_rf = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 2, RA, CH_B);
	add(TDMA_ROLE_PT, 3, RB, CH_C);
	add(TDMA_ROLE_PT, 4, RA, CH_D);
	add(TDMA_ROLE_PT, 5, RC, 0);
	for (int i = 0; i < s->n_nodes; i++) {
		sim_start(s, i);
	}
	CHECK(wait_until(rr_up, MS(30000)) != UINT64_MAX, "A; B, D under A; C under B; E under C");
	rr_lost_t = rr_assoc_t = 0;
	s->nodes[RC].relay_keep = true; /* the cluster outlives the parent */
	t0 = s->t + MS(100);
	fe = rflow_add("E->C", RE, RC, 64, MS(20), t0, t0 + MS(4000));
	fc = rflow_add("C->parent", RC, RB, 64, MS(20), t0, t0 + MS(1000));
	t_kill = t0 + MS(1000);
	sim_at(s, t_kill, rr_kill_b, NULL);
	sim_at(s, t_kill, rr_watch, NULL);
	sim_run_until(s, t_kill + MS(3200));
	e_lost = sim_count_evt(&s->nodes[RE], TDMA_EVT_LOST, t0);
	if (getenv("RR_DBG")) {
		for (int k = 0; k < 2; k++) {
			const struct sim_node *n = &s->nodes[k ? RE : RC];

			for (int i = 0; i < n->n_evts; i++) {
				if (n->evt_t[i] >= t_kill - MS(50)) {
					fprintf(stderr, "DBG %s +%lld ms evt %d rd %x cause %d\n",
						k ? "E" : "C",
						(long long)((int64_t)(n->evt_t[i] - t_kill) /
							    (int64_t)MS(1)),
						n->evts[i].type, n->evts[i].rd_id,
						n->evts[i].cause);
				}
			}
			for (int i = 0; !k && i < n->rn_evts; i++) {
				if (n->revt_t[i] >= t_kill - MS(50)) {
					fprintf(stderr,
						"DBG Crelay +%lld ms evt %d rd %x cause %d\n",
						(long long)((int64_t)(n->revt_t[i] - t_kill) /
							    (int64_t)MS(1)),
						n->revts[i].type, n->revts[i].rd_id,
						n->revts[i].cause);
				}
			}
		}
		fprintf(stderr, "DBG C relay away up %u down %u searches %u; rmac state %d\n",
			s->nodes[RC].relay.away_up, s->nodes[RC].relay.away_down,
			s->nodes[RC].relay.searches, s->nodes[RC].rmac.state);
	}
	printf("    B killed: C noticed after %llu ms, associated to D %llu ms after that (%llu ms "
	       "after the kill); C's cluster %s, E lost it %d times, E->C %u of %u; C searched %u "
	       "times on D's carrier\n",
	       rr_lost_t ? US(rr_lost_t - t_kill) / 1000 : 0,
	       rr_assoc_t && rr_lost_t ? US(rr_assoc_t - rr_lost_t) / 1000 : 0,
	       rr_assoc_t ? US(rr_assoc_t - t_kill) / 1000 : 0,
	       tdma_get_state(&s->nodes[RC].rmac) == TDMA_ST_FT ? "kept" : "stopped", e_lost,
	       fe->got, fe->sent, tdma_get_stats(&s->nodes[RC].mac)->fast_searches);
	CHECK(rr_assoc_t != 0 && rr_assoc_t - t_kill <= MS(500), "C on its backup D within 0.5 s");
	CHECK(e_lost == 0 && assoc_to(RE, RC), "E kept its parent C throughout");
	CHECK(fe->got + 2 >= fe->sent, "E->C went on (%u of %u)", fe->got, fe->sent);
	CHECK(tdma_get_stats(&s->nodes[RC].rmac)->retimes == 0, "same grid: no shift");
	(void)fc;
	check_relay_clean("reroute");
	sec_model(false);
}

/*
 * MAC level: an island and its merge. A dies: relay B keeps its
 * child cluster (C stays); A comes back on a new grid, B finds it, joins and
 * re-aligns its cluster with an announced shift (TDMA_F_RETIME): C moves with
 * it and keeps its position, no nonce repeats, no PHY rule broken.
 */
static void kill_a(struct sim *sm, void *arg)
{
	(void)arg;
	sim_kill(sm, NA);
}

static void revive_a(struct sim *sm, void *arg)
{
	(void)arg;
	sim_revive(sm, NA);
}

static void island_keep(struct sim *sm, void *arg)
{
	struct sim_node *b = &sm->nodes[NB];

	(void)arg;
	b->relay_keep = true;
	if (tdma_get_state(&b->mac) == TDMA_ST_SEARCH) {
		/* the island looks for its old parent on its carrier */
		tdma_pt_set_target_ch(&b->mac, rd(NA), CH_A, MS(20000));
	} else {
		sim_at(sm, sm->t + MS(5), island_keep, NULL);
	}
}

void test_relay_retime(void)
{
	uint64_t t0, t_back;
	struct rflow *fcb;
	int c_lost;
	uint32_t c_retimes, b_retimes;

	sec_model(true);
	s = sim_init(29);
	s->on_deliver = rdeliver;
	n_rf = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 2, NA, CH_B);
	add(TDMA_ROLE_PT, 3, NB, 0);
	for (int i = 0; i < s->n_nodes; i++) {
		sim_start(s, i);
	}
	CHECK(wait_until(b_c_up, MS(20000)) != UINT64_MAX, "A <- B <- C");
	CHECK(wait_until(b_c_hgx, s->t + MS(3000)) != UINT64_MAX, "B's cluster on HGX");
	s->nodes[NB].relay_keep = true;
	t0 = s->t + MS(100);
	c_retimes = tdma_get_stats(&s->nodes[NC].mac)->retimes;
	b_retimes = tdma_get_stats(&s->nodes[NB].rmac)->retimes;
	fcb = rflow_add("C->B", NC, NB, 64, MS(20), t0, t0 + MS(8000));
	sim_at(s, t0 + MS(500), kill_a, NULL);
	sim_at(s, t0 + MS(500), island_keep, NULL);
	/* a reboot: its frames come at another phase (3.7 ms off the old grid) */
	sim_at(s, t0 + MS(2500) + TDMA_US_TO_TICKS(3700), revive_a, NULL);
	sim_run_until(s, t0 + MS(2499));
	CHECK(!assoc_to(NB, NA) && tdma_get_state(&s->nodes[NB].rmac) == TDMA_ST_FT,
	      "an island: B without a parent, its cluster on");
	t_back = wait_until(chain_b_back, t0 + MS(8000));
	sim_run_until(s, t0 + MS(8300));
	c_lost = sim_count_evt(&s->nodes[NC], TDMA_EVT_LOST, t0);
	c_retimes = tdma_get_stats(&s->nodes[NC].mac)->retimes - c_retimes;
	b_retimes = tdma_get_stats(&s->nodes[NB].rmac)->retimes - b_retimes;
	printf("    A gone 2 s: B kept its cluster (C lost it %d times, C->B %u of %u); A back on "
	       "a "
	       "new grid: B under A again %llu ms after A's restart, shifts applied: B's cluster "
	       "%u, "
	       "C %u (B announced %u)\n",
	       c_lost, fcb->got, fcb->sent,
	       t_back != UINT64_MAX ? US(t_back - t0 - MS(2500)) / 1000 : 0, b_retimes, c_retimes,
	       s->nodes[NB].relay.retimes);
	CHECK(t_back != UINT64_MAX, "B joined A again");
	CHECK(c_lost == 0 && assoc_to(NC, NB), "C kept B throughout");
	CHECK(b_retimes == 1 && c_retimes == 1, "one announced shift, applied by B and C");
	CHECK(fcb->got + 5 >= fcb->sent, "C->B went on (%u of %u)", fcb->got, fcb->sent);
	{
		uint8_t g = 0xff;

		tdma_tree(&s->nodes[NC].mac, NULL, &g);
		CHECK(g == tdma_relay_offset_ss(s->nodes[NA].mac.plan, s->nodes[NB].rmac.plan),
		      "C on the root's grid again (grid %u ss)", g);
	}
	check_relay_clean("retime");
	sec_model(false);
}

/* two children under a relay, a leaf beside it: the layout of docs/mac-design.md "Relays" */
void test_relay_two(void)
{
	enum {
		A,
		X,
		B,
		C,
		D
	};
	uint64_t t0;

	sec_model(true);
	s = sim_init(21);
	s->on_deliver = rdeliver;
	n_rf = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 5, A, 0);
	add(TDMA_ROLE_PT, 2, A, CH_B);
	add(TDMA_ROLE_PT, 3, B, 0);
	add(TDMA_ROLE_PT, 4, B, 0);
	for (int i = 0; i < s->n_nodes; i++) {
		sim_start(s, i);
	}
	for (int k = 0;
	     k < 400 && !(assoc_to(X, A) && assoc_to(B, A) && assoc_to(C, B) && assoc_to(D, B));
	     k++) {
		sim_run_until(s, s->t + MS(50));
	}
	CHECK(assoc_to(X, A) && assoc_to(B, A) && assoc_to(C, B) && assoc_to(D, B),
	      "X, B under A; C, D under B");
	t0 = s->t + MS(200);
	rflow_add("A->X", A, X, 64, MS(20), t0, t0 + MS(8000));
	rflow_add("X->A", X, A, 64, MS(20), t0, t0 + MS(8000));
	rflow_add("A->B", A, B, 64, MS(20), t0, t0 + MS(8000));
	rflow_add("B->A", B, A, 64, MS(20), t0, t0 + MS(8000));
	rflow_add("B->C", B, C, 64, MS(20), t0, t0 + MS(8000));
	rflow_add("C->B", C, B, 64, MS(20), t0, t0 + MS(8000));
	rflow_add("B->D", B, D, 64, MS(20), t0, t0 + MS(8000));
	rflow_add("D->B", D, B, 64, MS(20), t0, t0 + MS(8000));
	/* and bulk from A to its leaf X: A's FLEX regions run while B is in its own cluster */
	struct rflow *bx = rflow_add("A->X bulk", A, X, 1000, 0, t0, t0 + MS(8000));

	sim_run_until(s, t0 + MS(8300));
	(void)probe_report("two");
	/*
	 * B's cluster: H's bound. A's links: A runs plan T under its leaf's bulk
	 * (the relay keeps T's first-half slots, 10 ms cadence): T's bound.
	 */
	for (int i = 0; i < n_rf; i++) {
		uint64_t avg, mx, p99 = rflow_p99(&rf[i], &avg, &mx);
		bool a_link = rf[i].src == A || rf[i].dst == A;

		CHECK(!rf[i].gap || p99 <= TDMA_US_TO_TICKS(a_link ? 12500 + 450 : 7000 + 450),
		      "%s p99 %llu us", rf[i].name, US(p99));
	}
	printf("    A->X bulk beside the relay: %.1f kB/s\n", (double)bx->bytes / 8000.0);
	CHECK(bx->bytes > 100000u * 8, "leaf bulk uses A's long bursts: %llu B",
	      (unsigned long long)bx->bytes);
	for (int i = 0; i < n_rf; i++) {
		CHECK(rf[i].gap == 0 || (rf[i].got == rf[i].sent && rf[i].dup == 0), "%s: %u of %u",
		      rf[i].name, rf[i].got, rf[i].sent);
	}
	{
		struct tdma_mac *r = &s->nodes[B].rmac;
		uint32_t kids[4];

		CHECK(tdma_children(r, kids, 4) == 2, "B's cluster has two children (full)");
	}
	check_relay_clean("two");
	sec_model(false);
}

/* relay loss: C notices, searches; the relay comes back and C rejoins */
static void kill_b(struct sim *sm, void *arg)
{
	(void)arg;
	sim_kill(sm, NB);
}

static void revive_b(struct sim *sm, void *arg)
{
	(void)arg;
	sim_revive(sm, NB);
}

void test_relay_loss(void)
{
	uint64_t t_kill, t_lost = 0, t_back;
	const struct tdma_evt *e;

	sec_model(true);
	chain_build(31);
	CHECK(wait_until(chain_up, MS(20000)) != UINT64_MAX, "chain associated");
	t_kill = s->t + MS(500);
	sim_at(s, t_kill, kill_b, NULL);
	sim_run_until(s, t_kill + MS(2000));
	e = sim_find_evt(&s->nodes[NC], TDMA_EVT_LOST, t_kill, &t_lost);
	CHECK(e != NULL, "C notices the relay is gone");
	if (e) {
		printf("    relay killed: C lost it after %llu ms (%s), searching\n",
		       US(t_lost - t_kill) / 1000,
		       e->cause == TDMA_CAUSE_SYNC_LOST ? "sync lost" : "other");
		CHECK(t_lost - t_kill <= MS(400), "C's detection %llu ms",
		      US(t_lost - t_kill) / 1000);
	}
	CHECK(tdma_get_state(&s->nodes[NC].mac) == TDMA_ST_SEARCH,
	      "C searches (no reroute without a backup)");
	CHECK(assoc_to(ND, NA), "D unaffected");
	sim_at(s, s->t, revive_b, NULL);
	t_back = wait_until(chain_up, s->t + MS(20000));
	CHECK(t_back != UINT64_MAX, "B back, C rejoined");
	if (t_back != UINT64_MAX) {
		printf("    relay back: chain whole again after %llu ms\n",
		       US(t_back - t_kill - MS(2000)) / 1000);
	}
	sim_run_until(s, s->t + MS(1000));
	check_relay_clean("loss");
	sec_model(false);
}

/* the parent's frame counter jumps under the relay: new child session, no nonce reuse */
static void jump(struct sim *sm, void *arg)
{
	struct sim_node *b = &sm->nodes[NB];

	(void)arg;
	/* as if B re-synced into a tree with another frame counter */
	tdma_ft_follow(&b->rmac,
		       b->mac.ref_start + (uint64_t)TDMA_RELAY_ROOT_OFFSET_SS * TDMA_SUBSLOT_TICKS,
		       b->mac.ref_frame + 1000u);
}

void test_relay_renumber(void)
{
	uint64_t t0;
	uint32_t sw0;

	sec_model(true);
	chain_build(41);
	CHECK(wait_until(chain_up, MS(20000)) != UINT64_MAX, "chain associated");
	t0 = s->t + MS(200);
	rflow_add("B->C", NB, NC, 64, MS(10), t0, t0 + MS(3000));
	rflow_add("C->B", NC, NB, 64, MS(10), t0, t0 + MS(3000));
	sw0 = tdma_get_stats(&s->nodes[NB].rmac)->sec_switches;
	sim_at(s, t0 + MS(1000), jump, NULL);
	sim_run_until(s, t0 + MS(3500));
	printf("    counter jump: %u renumberings, %u new sessions at B's cluster; C %s; B->C "
	       "%u/%u, "
	       "C->B %u/%u\n",
	       tdma_get_stats(&s->nodes[NB].rmac)->follow_renumber,
	       tdma_get_stats(&s->nodes[NB].rmac)->sec_switches - sw0,
	       assoc_to(NC, NB) ? "still associated" : "re-associated or lost", rf[0].got,
	       rf[0].sent, rf[1].got, rf[1].sent);
	CHECK(tdma_get_stats(&s->nodes[NB].rmac)->follow_renumber >= 1 &&
		      tdma_get_stats(&s->nodes[NB].rmac)->sec_switches > sw0,
	      "renumbered with a new session");
	CHECK(sim_sec_st.nonce_reuse == 0, "nonce reuse %llu",
	      (unsigned long long)sim_sec_st.nonce_reuse);
	CHECK(sim_phy_errors(s) == 0, "PHY violations %u", sim_phy_errors(s));
	CHECK(wait_until(chain_up, s->t + MS(10000)) != UINT64_MAX, "chain whole again");
	sec_model(false);
}

/* depth 2: A <- B <- R <- C; a box at the depth limit does not start a cluster */
void test_relay_depth(void)
{
	enum {
		A,
		B,
		R,
		C,
		E
	};
	uint64_t t0;

	sec_model(true);
	s = sim_init(51);
	s->on_deliver = rdeliver;
	n_rf = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 2, A, CH_B);
	add(TDMA_ROLE_PT, 3, B, CH_R);
	add(TDMA_ROLE_PT, 4, R, 1711); /* depth 3: must never run a cluster */
	add(TDMA_ROLE_PT, 6, C, 0);
	for (int i = 0; i < s->n_nodes; i++) {
		sim_start(s, i);
	}
	for (int k = 0; k < 600 && !(assoc_to(B, A) && assoc_to(R, B) && assoc_to(C, R)); k++) {
		sim_run_until(s, s->t + MS(50));
	}
	CHECK(assoc_to(B, A) && assoc_to(R, B) && assoc_to(C, R), "A <- B <- R <- C");
	{
		uint8_t d = 0, g = 0;

		tdma_tree(&s->nodes[C].mac, &d, &g);
		CHECK(d == 2 && g == TDMA_RELAY_ROOT_OFFSET_SS + TDMA_RELAY_OFFSET_SS,
		      "C: depth %u, grid %u", d, g);
	}
	t0 = s->t + MS(200);
	rflow_add("B->R", B, R, 64, MS(20), t0, t0 + MS(5000));
	rflow_add("R->B", R, B, 64, MS(20), t0, t0 + MS(5000));
	rflow_add("R->C", R, C, 64, MS(20), t0, t0 + MS(5000));
	rflow_add("C->R", C, R, 64, MS(20), t0, t0 + MS(5000));
	sim_run_until(s, t0 + MS(5300));
	{
		uint64_t worst = probe_report("depth2");

		CHECK(worst <= TDMA_US_TO_TICKS(7000 + 450), "per-link p99 %llu us", US(worst));
	}
	CHECK(s->nodes[C].relay_starts == 0 &&
		      tdma_get_state(&s->nodes[E].mac) != TDMA_ST_ASSOCIATED,
	      "no cluster below depth %u (C started %u, E %s)", TDMA_MAX_DEPTH,
	      s->nodes[C].relay_starts,
	      tdma_get_state(&s->nodes[E].mac) == TDMA_ST_ASSOCIATED ? "joined" : "not joined");
	check_relay_clean("depth2");
	sec_model(false);
}

/*
 * a relay that starts and stops at run time (tdma_pt_set_relay(), the
 * status record flag), and the route record of every cluster's beacons.
 */
static bool b_relay_at_a(void)
{
	return tdma_child_is_relay(&s->nodes[NA].mac, rd(NB));
}

static bool c_under_b(void)
{
	return assoc_to(NC, NB);
}

static bool b_plain_at_a(void)
{
	return assoc_to(NB, NA) && !tdma_child_is_relay(&s->nodes[NA].mac, rd(NB)) &&
	       !tdma_relay_running(&s->nodes[NB].relay);
}

void test_relay_dynamic(void)
{
	static const uint8_t rr_a[] = {1, 1, 0, 0, 7, 0}; /* sink 1, rank 1, cost 0, depth 0 */
	struct sim_node *b;
	struct rflow *bulk;
	uint8_t got[TDMA_ROUTE_MAX];
	uint64_t t, t0;
	uint32_t flex0;

	sec_model(true);
	s = sim_init(61);
	s->on_deliver = rdeliver;
	n_rf = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 2, NA, CH_B);
	add(TDMA_ROLE_PT, 3, NB, 0);
	s->nodes[NB].relay_hold = true; /* relay capable, no child cluster at first */
	for (int i = 0; i < 2; i++) {
		sim_start(s, i);
	}
	CHECK(tdma_set_route(&s->nodes[NA].mac, rr_a, sizeof(rr_a)) == 0, "root's route record");
	CHECK(tdma_set_route(&s->nodes[NA].mac, rr_a, TDMA_ROUTE_MAX + 1) == -EINVAL, "too long");
	sim_start(s, NC);
	t = wait_until(b_plain_at_a, MS(20000));
	CHECK(t != UINT64_MAX, "B a plain PT of A");
	CHECK(tdma_parent_route(&s->nodes[NB].mac, got, sizeof(got)) == sizeof(rr_a) &&
		      !memcmp(got, rr_a, sizeof(rr_a)),
	      "B has the root's route record from its beacons");
	b = &s->nodes[NB];
	/* a plain PT gets long bursts */
	t0 = s->t + MS(100);
	bulk = rflow_add("B->A", NB, NA, 1000, 0, t0, t0 + MS(2000));
	sim_run_until(s, t0 + MS(2300));
	flex0 = tdma_get_stats(&b->mac)->flex_tx;
	printf("    B plain: bulk B->A %.1f kB/s, %u long bursts\n", (double)bulk->bytes / 2000.0,
	       flex0);
	CHECK(flex0 > 0, "plain PT: long bursts");
	CHECK(!assoc_to(NC, NB), "C has nothing to join yet");
	/* B starts relaying: A learns it from the status records, C joins B's cluster */
	t0 = s->t;
	sim_relay_want(s, NB, true);
	t = wait_until(b_relay_at_a, t0 + MS(2000));
	CHECK(t != UINT64_MAX, "A marks B a relay");
	if (t != UINT64_MAX) {
		printf("    relay on: A knows after %llu ms\n", US(t - t0) / 1000);
	}
	t = wait_until(c_under_b, t0 + MS(20000));
	CHECK(t != UINT64_MAX, "C joined B's cluster");
	if (t != UINT64_MAX) {
		uint8_t d = 9;

		printf("    relay on: C under B %llu ms after the switch\n", US(t - t0) / 1000);
		tdma_tree(&s->nodes[NC].mac, &d, NULL);
		CHECK(d == 1, "C at depth %u", d);
	}
	flex0 = tdma_get_stats(&b->mac)->flex_tx + tdma_get_stats(&b->mac)->flex_rx;
	t0 = s->t + MS(100);
	bulk = rflow_add("B->A relay", NB, NA, 1000, 0, t0, t0 + MS(2000));
	sim_run_until(s, t0 + MS(2300));
	printf("    B relay: bulk B->A %.1f kB/s\n", (double)bulk->bytes / 2000.0);
	CHECK(tdma_get_stats(&b->mac)->flex_tx + tdma_get_stats(&b->mac)->flex_rx <= flex0 + 2,
	      "relay: no long bursts (%u)",
	      tdma_get_stats(&b->mac)->flex_tx + tdma_get_stats(&b->mac)->flex_rx - flex0);
	/* and off again: the cluster stops, A gives B its long bursts back */
	t0 = s->t;
	sim_relay_want(s, NB, false);
	t = wait_until(b_plain_at_a, t0 + MS(2000));
	CHECK(t != UINT64_MAX, "B a plain PT again");
	if (t != UINT64_MAX) {
		printf("    relay off: A knows after %llu ms\n", US(t - t0) / 1000);
	}
	sim_run_until(s, s->t + MS(500));
	CHECK(!assoc_to(NC, NB), "C lost B's cluster");
	check_relay_clean("dynamic");
	sec_model(false);
}

/*
 * Position compaction : B joined A third (position 2 of H4) and
 * wants to relay; a relay needs position 0 / 1 of plan H. The leaf in
 * position 0 leaves: A moves B down (announced, TDMA_BEXT_PMOVE), B keeps its
 * association and queues, A switches to H, B's child cluster forms and C
 * joins it. Probes A <-> B every 20 ms the whole time.
 */
enum {
	PA,
	PX,
	PD,
	PB,
	PC
};

static bool pc_x_d_up(void)
{
	return assoc_to(PX, PA) && assoc_to(PD, PA);
}

static bool pc_b_up(void)
{
	return assoc_to(PB, PA);
}

static bool pc_x_gone(void)
{
	uint32_t kids[TDMA_MAX_POSITIONS];

	return tdma_children(&s->nodes[PA].mac, kids, TDMA_MAX_POSITIONS) == 2;
}

static bool pc_relayed(void)
{
	return assoc_to(PC, PB) && s->nodes[PB].relay_on && tdma_relay_running(&s->nodes[PB].relay);
}

void test_pos_compact(void)
{
	struct rflow *ab, *ba;
	uint64_t t_want, t_rel;
	int lost_b;
	int8_t pos0;

	sec_model(true);
	s = sim_init(29);
	s->on_deliver = rdeliver;
	n_rf = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 5, PA, 0);
	add(TDMA_ROLE_PT, 4, PA, 0);
	add(TDMA_ROLE_PT, 2, PA, CH_B);
	add(TDMA_ROLE_PT, 3, PB, 0);
	s->nodes[PB].relay_hold = true; /* relay capable, not wanted yet */
	sim_start(s, PA);
	sim_start(s, PX);
	sim_start(s, PD);
	CHECK(wait_until(pc_x_d_up, MS(20000)) != UINT64_MAX, "X and D under A");
	sim_start(s, PB);
	CHECK(wait_until(pc_b_up, s->t + MS(20000)) != UINT64_MAX, "B under A");
	pos0 = s->nodes[PB].mac.my_pos;
	CHECK(pos0 == 2 && s->nodes[PA].mac.plan->id == TDMA_PLAN_H4, "B in position %d of plan %u",
	      pos0, s->nodes[PA].mac.plan->id);
	{
		uint64_t t0 = s->t + MS(100);

		ab = rflow_add("A->B", PA, PB, 64, MS(20), t0, t0 + MS(15000));
		ba = rflow_add("B->A", PB, PA, 64, MS(20), t0, t0 + MS(15000));
	}
	sim_run_until(s, s->t + MS(1000));
	sim_kill(s, PX);
	CHECK(wait_until(pc_x_gone, s->t + MS(5000)) != UINT64_MAX, "A released X");
	t_want = s->t;
	sim_relay_want(s, PB, true);
	{
		uint64_t t_end = s->t + MS(3000);

		while (s->t < t_end && !tdma_relay_running(&s->nodes[PB].relay)) {
			sim_run_until(s, s->t + TDMA_FRAME_TICKS / 2);
		}
	}
	printf("    B: position %d -> %d (%u move at A, %u at B), A on plan %s, relay cluster %s "
	       "%llu ms after "
	       "it was wanted\n",
	       pos0, s->nodes[PB].mac.my_pos, tdma_get_stats(&s->nodes[PA].mac)->pos_moves,
	       tdma_get_stats(&s->nodes[PB].mac)->pos_moves, s->nodes[PA].mac.plan->name,
	       tdma_relay_running(&s->nodes[PB].relay) ? "running" : "NOT running",
	       US(s->t - t_want) / 1000);
	CHECK(s->nodes[PB].mac.my_pos < 2 && tdma_get_stats(&s->nodes[PA].mac)->pos_moves == 1 &&
		      tdma_get_stats(&s->nodes[PB].mac)->pos_moves == 1,
	      "B moved down once, announced (A %u, B %u)",
	      tdma_get_stats(&s->nodes[PA].mac)->pos_moves,
	      tdma_get_stats(&s->nodes[PB].mac)->pos_moves);
	CHECK(s->nodes[PA].mac.plan->id == TDMA_PLAN_H, "A on plan H");
	{
		const struct tdma_link *l = &s->nodes[PA].mac.peers[s->nodes[PB].mac.my_pos].link;

		/* the deep queue memory of its new position (TDMA_TXQ_N_BIG), its queue copied over
		 */
		CHECK(l->n_chunks == TDMA_TXQ_ALL_CHUNKS &&
			      s->nodes[PA].mac.peers[2].link.n_chunks < TDMA_TXQ_ALL_CHUNKS,
		      "B's DL queue at A: %u chunks (position 2's: %u)", l->n_chunks,
		      s->nodes[PA].mac.peers[2].link.n_chunks);
	}
	CHECK(tdma_relay_running(&s->nodes[PB].relay), "B's child cluster runs");
	sim_start(s, PC);
	t_rel = wait_until(pc_relayed, s->t + MS(20000));
	CHECK(t_rel != UINT64_MAX, "C joined B's cluster");
	sim_run_until(s, ab->t_stop + MS(500));
	lost_b = sim_count_evt(&s->nodes[PB], TDMA_EVT_LOST, 0);
	printf("    probes A->B %u of %u, B->A %u of %u (dup %u / %u); B lost A %d times\n",
	       ab->got, ab->sent, ba->got, ba->sent, ab->dup, ba->dup, lost_b);
	CHECK(lost_b == 0, "B kept its association (lost %d)", lost_b);
	CHECK(ab->got == ab->sent && ba->got == ba->sent && !ab->dup && !ba->dup,
	      "every probe once across the move");
	check_relay_clean("pos_compact");
	sec_model(false);
}

/*
 * Backup probes : C (under relay B) listens now and then for its
 * backups: relay D's cluster (a sibling: the same grid, in place of C's own
 * DL burst at 24) and the root A (A's DL burst at C's subslot 29, where C has
 * nothing). Heard while D lives, not after it died; C's traffic never lost.
 */
enum {
	BA,
	BB,
	BC,
	BD
};

static int bp_heard[2], bp_tries[2], bp_after_kill_heard, bp_after_kill;
static uint64_t bp_kill_t;

static bool bp_up(void)
{
	return assoc_to(BB, BA) && assoc_to(BD, BA) && assoc_to(BC, BB) &&
	       tdma_relay_running(&s->nodes[BB].relay) && tdma_relay_running(&s->nodes[BD].relay);
}

static void bp_evt(struct sim *sm, int node, const struct tdma_evt *e)
{
	(void)sm;
	if (node != BC || e->type != TDMA_EVT_PROBE) {
		return;
	}
	int k = e->rd_id == rd(BD) ? 0 : 1;

	if (k == 0 && bp_kill_t && s->t > bp_kill_t) {
		bp_after_kill++;
		bp_after_kill_heard += (int)e->value;
		return;
	}
	bp_tries[k]++;
	bp_heard[k] += (int)e->value;
}

static void bp_probe(struct sim *sm, void *arg)
{
	struct sim_node *c = &sm->nodes[BC];
	uint8_t g_own = c->mac.tree_grid;
	int k = (int)(intptr_t)arg;

	if (k == 0) {
		/* D's beacon burst: a sibling, the same grid as ours (in place of our beacon) */
		(void)tdma_pt_probe(&c->mac, rd(BD), tdma_channel(&sm->nodes[BD].rmac),
				    (uint8_t)((tdma_grid_of_depth(1) + 48u - g_own) % 48u));
	} else {
		(void)tdma_pt_probe(&c->mac, rd(BA), tdma_channel(&sm->nodes[BA].mac),
				    (uint8_t)((48u - g_own) % 48u)); /* its beacon burst */
	}
	sim_at(sm, sm->t + MS(150), bp_probe, (void *)(intptr_t)(1 - k));
}

void test_backup_probe(void)
{
	struct rflow *ac, *ca;

	sec_model(true);
	s = sim_init(37);
	s->on_deliver = rdeliver;
	s->on_evt = bp_evt;
	n_rf = 0;
	memset(bp_heard, 0, sizeof(bp_heard));
	memset(bp_tries, 0, sizeof(bp_tries));
	bp_after_kill = bp_after_kill_heard = 0;
	bp_kill_t = 0;
	add(TDMA_ROLE_FT, 1, -1, 0);
	add(TDMA_ROLE_PT, 2, BA, CH_B);
	add(TDMA_ROLE_PT, 3, BB, 0);
	add(TDMA_ROLE_PT, 4, BA, 1709);
	for (int i = 0; i < s->n_nodes; i++) {
		sim_start(s, i);
	}
	/*
	 * B stays on HG here (the sibling probe needs D's beacon burst
	 * in place of ours: on the same grid; C under an HGX relay cannot probe an
	 * HG sibling at all, its UL slot sits on that beacon: hgx_tree checks it)
	 */
	s->nodes[BB].relay.hgx_hold_until = UINT64_MAX;
	CHECK(wait_until(bp_up, MS(30000)) != UINT64_MAX, "diamond: A; B, D relays; C under B");
	{
		uint64_t t0 = s->t + MS(100);

		ac = rflow_add("A->C", BA, BC, 64, MS(20), t0, t0 + MS(10000));
		ac->via = BB;
		ca = rflow_add("C->A", BC, BA, 64, MS(20), t0, t0 + MS(10000));
		ca->via = BB;
		sim_at(s, t0, bp_probe, (void *)(intptr_t)0);
		sim_run_until(s, t0 + MS(5000));
		bp_kill_t = s->t;
		sim_kill(s, BD);
		sim_run_until(s, t0 + MS(10500));
	}
	printf("    C's probes: D (sibling, in place of C's beacon) heard %d of %d, root A (C's "
	       "subslot 29) %d of %d; "
	       "after D died %d of %d; probes A->C %u/%u, C->A %u/%u; C stats %u / %u heard\n",
	       bp_heard[0], bp_tries[0], bp_heard[1], bp_tries[1], bp_after_kill_heard,
	       bp_after_kill, ac->got, ac->sent, ca->got, ca->sent,
	       tdma_get_stats(&s->nodes[BC].mac)->probes,
	       tdma_get_stats(&s->nodes[BC].mac)->probes_heard);
	CHECK(bp_tries[0] >= 10 && bp_heard[0] * 10 >= bp_tries[0] * 9, "D heard (%d of %d)",
	      bp_heard[0], bp_tries[0]);
	CHECK(bp_tries[1] >= 10 && bp_heard[1] * 10 >= bp_tries[1] * 9, "A heard (%d of %d)",
	      bp_heard[1], bp_tries[1]);
	CHECK(bp_after_kill >= 5 && bp_after_kill_heard == 0, "D not heard once dead (%d of %d)",
	      bp_after_kill_heard, bp_after_kill);
	CHECK(ac->got == ac->sent && ca->got == ca->sent, "C's traffic all delivered");
	check_relay_clean("backup_probe");
	s->on_evt = NULL;
	sec_model(false);
}
