/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Link security tests (docs/mac-design.md "Link security"): vectors, every network test
 * again with security on, and the attacks: wrong key, rogue FT, forged acks,
 * replay, tampering, FT restart / role switch with a global nonce-reuse
 * check, counter wrap, rekey under load, duplicate box id, the seal timing
 * model, a secured fuzzer, dev-key separation and the deny list.
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <cappella/tdma_sec_ref_crypto.h>
#include "sim.h"
#include <cappella/tdma_pdu.h>
#include "test.h"

#define MS(x)     ((uint64_t)(x) * 69120u)
#define FRAMES(n) ((uint64_t)(n) * TDMA_FRAME_TICKS)

static struct sim *s;

static const uint8_t K1[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			       0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0x01};
static const uint8_t K2[16] = {0xa5, 0x5a, 0xa5, 0x5a, 0x01, 0x02, 0x03, 0x04,
			       0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};

/* ---- helpers ------------------------------------------------------------------------------------
 */

static int hexb(const char *h, uint8_t *out)
{
	int n = 0;

	while (h[0] && h[1]) {
		unsigned int v;

		sscanf(h, "%2x", &v);
		out[n++] = (uint8_t)v;
		h += 2;
	}
	return n;
}

static int add(enum tdma_role role, uint8_t box, uint8_t plan, const uint8_t *key)
{
	int i = sim_add_node(s, role, box, plan, (int64_t)(sim_rand(s) % (1ull << 40)), 0);

	if (key) {
		sim_sec_on(s, i, key);
	}
	return i;
}

static uint32_t rd(int node)
{
	return s->nodes[node].cfg.rd_id;
}

static const struct tdma_stats *st(int node)
{
	return tdma_get_stats(&s->nodes[node].mac);
}

static bool associated(int node)
{
	return s->nodes[node].alive && tdma_get_state(&s->nodes[node].mac) == TDMA_ST_ASSOCIATED;
}

/* Run until every listed PT is associated (or the deadline); returns the time or UINT64_MAX. */
static uint64_t wait_nodes(const int *pts, int n, uint64_t deadline)
{
	while (s->t < deadline) {
		bool all = true;

		sim_run_until(s, s->t + TDMA_FRAME_TICKS / 4);
		for (int i = 0; i < n; i++) {
			all &= associated(pts[i]);
		}
		if (all) {
			return s->t;
		}
	}
	return UINT64_MAX;
}

/* Key switches go to the "app": the switched-to index becomes active, nothing pending. */
static void sec_evt(struct sim *sm, int node, const struct tdma_evt *e)
{
	if (e->type == TDMA_EVT_KEY_SWITCH) {
		sim_sec_state(sm, node, (uint8_t)e->value, TDMA_SEC_NO_KEY);
	}
}

static void net_init(uint64_t seed)
{
	s = sim_init(seed);
	s->on_evt = sec_evt;
}

/* ---- traffic: numbered, self-checking SDUs ----------------------------------------------------
 */

#define TF_MAX   16
#define TF_IDS   8192
#define TF_MAGIC 0xc3

struct tflow {
	int src, dst;
	size_t len;
	uint64_t gap;
	uint32_t sent, got, bad, dup;
	uint8_t seen[TF_IDS];
};

static struct tflow tf[TF_MAX];
static int ntf;
static uint64_t tf_stop;
static uint32_t tf_bad_any;

static void tf_reset(void)
{
	memset(tf, 0, sizeof(tf));
	ntf = 0;
	tf_bad_any = 0;
	tf_stop = UINT64_MAX;
}

static void tf_send(struct sim *sm, void *arg)
{
	struct tflow *f = arg;
	uint8_t msg[TDMA_MAX_SDU];
	uint32_t id = f->sent;

	if (sm->t >= tf_stop || id >= TF_IDS) {
		return;
	}
	if (sm->nodes[f->src].alive) {
		msg[0] = TF_MAGIC;
		msg[1] = (uint8_t)(f - tf);
		memcpy(&msg[2], &id, 4);
		for (size_t i = 6; i < f->len; i++) {
			msg[i] = (uint8_t)(id * 13 + i);
		}
		if (sim_send(sm, f->src, sm->nodes[f->dst].cfg.rd_id, msg, f->len, 0) == 0) {
			f->sent++;
		}
	}
	sim_at(sm, sm->t + f->gap / 2 + sim_rand(sm) % f->gap, tf_send, f);
}

static void tf_deliver(struct sim *sm, int node, uint32_t src, const uint8_t *d, size_t len)
{
	struct tflow *f;
	uint32_t id;

	(void)sm;
	if (len < 6 || d[0] != TF_MAGIC || d[1] >= ntf) {
		tf_bad_any++;
		return;
	}
	f = &tf[d[1]];
	memcpy(&id, &d[2], 4);
	if (node != f->dst || src != rd(f->src) || len != f->len || id >= TF_IDS) {
		f->bad++;
		return;
	}
	for (size_t i = 6; i < len; i++) {
		if (d[i] != (uint8_t)(id * 13 + i)) {
			f->bad++;
			return;
		}
	}
	if (f->seen[id]++) {
		f->dup++;
		return;
	}
	f->got++;
}

static struct tflow *tf_add(int src, int dst, size_t len, uint64_t gap, uint64_t t0)
{
	struct tflow *f = &tf[ntf++];

	f->src = src;
	f->dst = dst;
	f->len = len;
	f->gap = gap;
	s->on_deliver = tf_deliver;
	sim_at(s, t0 + sim_rand(s) % gap, tf_send, f);
	return f;
}

static void tf_check(const char *what, int skip_mask)
{
	for (int i = 0; i < ntf; i++) {
		struct tflow *f = &tf[i];

		if (skip_mask & (1 << i)) {
			continue;
		}
		CHECK(f->got == f->sent && !f->bad && !f->dup,
		      "%s: flow %d->%d: %u sent, %u delivered, %u bad, %u dup", what, f->src,
		      f->dst, f->sent, f->got, f->bad, f->dup);
	}
	CHECK(!tf_bad_any, "%s: %u foreign SDUs", what, tf_bad_any);
}

static uint32_t sum_stat(size_t off)
{
	uint32_t n = 0;

	for (int i = 0; i < s->n_nodes; i++) {
		n += *(const uint32_t *)((const uint8_t *)st(i) + off);
	}
	return n;
}

#define SUM(field) sum_stat(offsetof(struct tdma_stats, field))

/* ---- 1. vectors --------------------------------------------------------------------------------
 */

static uint8_t first_nonce[TDMA_SEC_NONCE_LEN];
static uint32_t first_frame;
static bool got_first;

static void nonce_probe(struct sim *sm, int node, uint64_t t, uint16_t ch, const uint8_t *hdr,
			const uint8_t *pl, size_t len, uint8_t subslots, uint8_t mcs)
{
	struct tdma_sec_hdr sh;
	struct tdma_beacon b;

	(void)t;
	(void)ch;
	(void)hdr;
	(void)subslots;
	(void)mcs;
	if (got_first || node != 0 || len < 4 || tdma_sec_hdr_decode(pl, &sh) || !sh.clear ||
	    tdma_beacon_decode(pl + 4, pl[2], &b)) {
		return;
	}
	memcpy(first_nonce, sm->nodes[0].sec.last_nonce, sizeof(first_nonce));
	first_frame = b.frame;
	got_first = true;
}

void test_sec_vectors(void)
{
	uint8_t k[16], p[64], c[64], t[16], n[16], a[16], out[64];
	int pl, al, nl;

	/* FIPS-197 C.1 */
	hexb("000102030405060708090a0b0c0d0e0f", k);
	hexb("00112233445566778899aabbccddeeff", p);
	tdma_ref_aes128(k, p, out);
	hexb("69c4e0d86a7b0430d8cdb78070b4c55a", c);
	CHECK(!memcmp(out, c, 16), "AES-128 FIPS-197");

	/* RFC 4493 */
	hexb("2b7e151628aed2a6abf7158809cf4f3c", k);
	tdma_ref_cmac(k, p, 0, out);
	hexb("bb1d6929e95937287fa37d129b756746", c);
	CHECK(!memcmp(out, c, 16), "CMAC empty");
	pl = hexb(
		"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
		p);
	tdma_ref_cmac(k, p, 16, out);
	hexb("070a16b46b4d4144f79bdd9dd04a287c", c);
	CHECK(!memcmp(out, c, 16), "CMAC 16");
	tdma_ref_cmac(k, p, (size_t)pl, out);
	hexb("dfa66747de9ae63030ca32611497c827", c);
	CHECK(!memcmp(out, c, 16), "CMAC 40");

	/* RFC 3610 packet vector #1: 13-byte nonce, 8-byte tag */
	hexb("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf", k);
	nl = hexb("00000003020100a0a1a2a3a4a5", n);
	al = hexb("0001020304050607", a);
	pl = hexb("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e", p);
	memcpy(out, p, (size_t)pl);
	tdma_ref_ccm_seal(k, n, (size_t)nl, a, (size_t)al, out, (size_t)pl, t, 8);
	hexb("588c979a61c663d2f066d0c2c0f989806d5f6b61dac384", c);
	CHECK(!memcmp(out, c, (size_t)pl), "CCM RFC 3610 #1 ciphertext");
	hexb("17e8d12cfdf926e0", c);
	CHECK(!memcmp(t, c, 8), "CCM RFC 3610 #1 tag");
	CHECK(tdma_ref_ccm_open(k, n, (size_t)nl, a, (size_t)al, out, (size_t)pl, t, 8) == 0 &&
		      !memcmp(out, p, (size_t)pl),
	      "CCM RFC 3610 #1 decrypt");
	out[3] ^= 1;
	CHECK(tdma_ref_ccm_open(k, n, (size_t)nl, a, (size_t)al, out, (size_t)pl, t, 8) != 0,
	      "CCM tamper detected");

	/* SP 800-38C example 1: 7-byte nonce, 4-byte tag */
	hexb("404142434445464748494a4b4c4d4e4f", k);
	nl = hexb("10111213141516", n);
	al = hexb("0001020304050607", a);
	pl = hexb("20212223", p);
	memcpy(out, p, 4);
	tdma_ref_ccm_seal(k, n, (size_t)nl, a, (size_t)al, out, 4, t, 4);
	hexb("7162015b4dac255d", c);
	CHECK(!memcmp(out, c, 4) && !memcmp(t, c + 4, 4), "CCM SP 800-38C ex. 1 (4-byte tag)");

	/*
	 * SP 800-108r1 counter-mode CMAC KDF with the K0 block (PSA layout); golden values
	 * from an independent implementation (OpenSSL CMAC), made-up key and context
	 */
	for (int i = 0; i < 16; i++) {
		k[i] = (uint8_t)i;
	}
	hexb("5a11000110000a0100000005deadbeef", a);
	tdma_ref_kdf(k, "CMs1", a, 16, out, 16);
	hexb("1430480245db59b0f4e81120492c7971", c);
	CHECK(!memcmp(out, c, 16), "KDF session key");
	tdma_ref_kdf(k, "CMkc", NULL, 0, out, 16);
	hexb("7019728c8f807184225a50ac56946cb6", c);
	CHECK(!memcmp(out, c, 16), "KDF key check value");
	tdma_ref_kdf(k, "CMni", NULL, 0, out, 32);
	hexb("8d1f581a420e6359ef342fa118429eb833b547e51b2cef500676fca43742b11e", c);
	CHECK(!memcmp(out, c, 32), "KDF 32 bytes");

	/* security header */
	{
		struct tdma_sec_hdr h = {.ver = 1, .key_idx = 2, .clear = true, .body_len = 1234},
				    h2;
		uint8_t b[2];

		tdma_sec_hdr_encode(&h, b);
		CHECK(b[0] == 0x6c && b[1] == 0xd2, "sec_hdr bits %02x %02x", b[0], b[1]);
		CHECK(tdma_sec_hdr_decode(b, &h2) == 0 && h2.key_idx == 2 && h2.clear &&
			      h2.body_len == 1234,
		      "sec_hdr round trip");
		b[0] &= 0x3f;
		CHECK(tdma_sec_hdr_decode(b, &h2) == -EINVAL, "sec_hdr version 0 rejected");
	}

	/* beacon security extension */
	{
		struct tdma_beacon b = {.flags = TDMA_F_BSEC,
					.network_id = 0x5a110001,
					.ft_rd_id = 0x10000a01,
					.frame = 77,
					.n = 2,
					.mcs = 4,
					.sess_ctr = 9,
					.sess_rand = 0xdeadbeef,
					.key_idx = 1,
					.sflags = TDMA_SF_DEVKEY | TDMA_SF_NEXT |
						  (2 << TDMA_SF_NEXT_IDX_SHIFT),
					.next_frame = 177,
					.next_ctr = 10,
					.next_rand = 0x12345678};
		struct tdma_beacon b2;
		uint8_t buf[128];
		int len = tdma_beacon_encode(&b, buf, sizeof(buf));

		CHECK(len == TDMA_BEACON_FIXED_LEN + 2 * TDMA_BEACON_ENTRY_LEN +
				      TDMA_BEACON_SEC_LEN + TDMA_BEACON_SEC_NEXT_LEN,
		      "sec beacon length %d", len);
		CHECK(tdma_beacon_decode(buf, (size_t)len, &b2) == 0 && b2.sess_ctr == 9 &&
			      b2.sess_rand == 0xdeadbeef && b2.key_idx == 1 &&
			      b2.sflags == b.sflags && b2.next_frame == 177 && b2.next_ctr == 10 &&
			      b2.next_rand == 0x12345678,
		      "sec beacon round trip");
		CHECK(tdma_beacon_decode(buf, (size_t)len - 1, &b2) == -EINVAL, "truncated next");
		CHECK(tdma_beacon_decode(buf, (size_t)len - TDMA_BEACON_SEC_NEXT_LEN - 1, &b2) ==
			      -EINVAL,
		      "truncated extension");
	}

	/* nonce layout on the air: FT rd id | frame | start subslot | 0 */
	net_init(5);
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_A, K1);
	got_first = false;
	s->on_air = nonce_probe;
	sim_start(s, 0);
	sim_start(s, 1);
	sim_run_until(s, MS(500));
	CHECK(got_first, "no beacon seen");
	{
		uint8_t want[TDMA_SEC_NONCE_LEN] = {0};

		want[0] = (uint8_t)(rd(0) >> 24);
		want[1] = (uint8_t)(rd(0) >> 16);
		want[2] = (uint8_t)(rd(0) >> 8);
		want[3] = (uint8_t)rd(0);
		want[4] = (uint8_t)(first_frame >> 24);
		want[5] = (uint8_t)(first_frame >> 16);
		want[6] = (uint8_t)(first_frame >> 8);
		want[7] = (uint8_t)first_frame;
		CHECK(!memcmp(first_nonce, want, sizeof(want)), "beacon nonce layout");
	}
	CHECK(associated(1), "secured association");
}

/* ---- 2. every network test with security on ----------------------------------------------------
 */

void test_sec_basic(void)
{
	static const struct {
		const char *name;
		void (*fn)(void);
		bool restarts; /* MIC failures are expected (stale sessions after an FT restart) */
	} t[] = {
		{"assoc_full", test_assoc_full, false},
		{"latency_a", test_latency_a, false},
		{"latency_b", test_latency_b, false},
		{"latency_1x10", test_latency_1x10, false},
		{"loss10", test_loss10, false},
		{"frag", test_frag, false},
		{"drift", test_drift, false},
		{"ft_loss", test_ft_loss, true},
		{"pt_loss", test_pt_loss, true},
		{"hybrid_small", test_hybrid_small, false},
		{"grant_ul", test_grant_ul, false},
		{"flex_dl", test_flex_dl, false},
		{"bulk_loss", test_bulk_loss, false},
		{"link_mcs", test_link_mcs, false},
		{"echo", test_echo, false},
		{"chan_move", test_chan_move, false},
		{"move_cmd", test_move_cmd, false},
		{"hop", test_hop, false},
	};

	sim_sec_all = true;
	test_sdu_shrink = TDMA_SEC_OVERHEAD - TDMA_MIC_RESERVE + TDMA_BEACON_SEC_LEN;
	for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		int before = test_failures;

		sim_sec_stats_reset();
		printf("  -- %s with security on\n", t[i].name);
		t[i].fn();
		printf("     %llu bursts sealed, %llu opened, %llu MIC failures, %llu nonce "
		       "reuses\n",
		       (unsigned long long)sim_sec_st.seals, (unsigned long long)sim_sec_st.opens,
		       (unsigned long long)sim_sec_st.open_fail,
		       (unsigned long long)sim_sec_st.nonce_reuse);
		CHECK(sim_sec_st.seals > 100, "%s: nothing sealed", t[i].name);
		CHECK(sim_sec_st.nonce_reuse == 0, "%s: nonce reuse", t[i].name);
		CHECK(t[i].restarts || sim_sec_st.open_fail == 0, "%s: %llu MIC failures",
		      t[i].name, (unsigned long long)sim_sec_st.open_fail);
		if (test_failures != before) {
			printf("     ^ %s failed with security on\n", t[i].name);
		}
	}
	sim_sec_all = false;
	test_sdu_shrink = 0;
}

/*
 * The hardware model (nRF9151 with the AES-CCM in a secure partition, as
 * measured on the DK): a seal is reported as 450 us (the firmware's lead; ~230 us
 * typical, ~580 us worst case), a typical open as 250 us, and each opened
 * burst keeps the MAC busy for 450 us (open + PDUs) after its PHY event,
 * delaying commits as the meta-IRQ MAC thread does. The FT then grants long
 * bursts in the DL burst right before them (no grant_ahead), and the MAC
 * keeps commits out of the verify windows (rx_clear). The hybrid tests again
 * under that model.
 */
void test_sec_hw_model(void)
{
	static const struct {
		const char *name;
		void (*fn)(void);
	} t[] = {
		{"hybrid_small", test_hybrid_small},
		{"grant_ul", test_grant_ul},
		{"flex_dl", test_flex_dl},
		{"bulk_loss", test_bulk_loss},
		{"fair", test_fair},
		{"floor_bulk", test_floor_bulk},
		{"echo", test_echo},
	};

	sim_sec_all = true;
	sim_grant_ahead = false;
	sim_sec_cost_us = 450;
	sim_sec_open_us = 250;
	sim_sec_busy_us = 450;
	test_sdu_shrink = TDMA_SEC_OVERHEAD - TDMA_MIC_RESERVE + TDMA_BEACON_SEC_LEN;
	/*
	 * allowed: the seal lead on every TX, plus a commit moved before the end
	 * of a burst received just before (rx_clear: up to a FLEX region); bulk
	 * with 4 PTs on plan H4 averages ~2.8 ms over its plain bound (it was
	 * allowed a whole DL period with grant_ahead before).
	 */
	test_slack_small = TDMA_US_TO_TICKS(450 + 1500);
	test_slack_bulk = TDMA_US_TO_TICKS(450 + 3000);
	for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		int before = test_failures;

		sim_sec_stats_reset();
		printf("  -- %s, security on, 450 us seals, 450 us opens\n", t[i].name);
		t[i].fn();
		CHECK(sim_sec_st.nonce_reuse == 0 && sim_sec_st.open_fail == 0,
		      "%s: %llu nonce reuses, %llu MIC failures", t[i].name,
		      (unsigned long long)sim_sec_st.nonce_reuse,
		      (unsigned long long)sim_sec_st.open_fail);
		if (test_failures != before) {
			printf("     ^ %s failed under the hardware model\n", t[i].name);
		}
	}
	sim_sec_all = false;
	sim_sec_cost_us = sim_sec_open_us = sim_sec_busy_us = 0;
	test_sdu_shrink = 0;
	test_slack_small = test_slack_bulk = 0;
}

/* ---- 3. wrong key -------------------------------------------------------------------------------
 */

void test_sec_wrong_key(void)
{
	int pts[1] = {1};

	net_init(11);
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 3, TDMA_PLAN_A, K2); /* another network key */
	for (int i = 0; i < 3; i++) {
		sim_start(s, i);
	}
	CHECK(wait_nodes(pts, 1, MS(3000)) != UINT64_MAX, "the right key associates");
	sim_run_until(s, MS(5000));
	CHECK(!associated(2), "wrong key associated");
	CHECK(sim_count_evt(&s->nodes[2], TDMA_EVT_SYNCED, 0) == 0, "wrong key synced");
	CHECK(sim_count_evt(&s->nodes[2], TDMA_EVT_BEACON, 0) == 0, "wrong key reported a beacon");
	CHECK(st(2)->assoc_tx == 0, "wrong key sent %u association requests", st(2)->assoc_tx);
	CHECK(st(2)->sec_mic_fail > 100, "wrong key: %u beacons failed", st(2)->sec_mic_fail);
	CHECK(st(0)->sec_opened > 0 && st(0)->assoc_tx == 1, "FT took one association");
	printf("    PT with another key: %u beacons failed the MIC, 0 synced, 0 sent\n",
	       st(2)->sec_mic_fail);
}

/* ---- 4. rogue FT --------------------------------------------------------------------------------
 */

void test_sec_rogue_ft(void)
{
	int pts[1] = {1};
	uint64_t t;

	net_init(12);
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_FT, 9, TDMA_PLAN_A, K2); /* right network id, no key */
	for (int i = 0; i < 3; i++) {
		s->nodes[i].cfg.channel =
			0; /* the real FT avoids the rogue's carrier, PTs search all */
	}
	sim_start(s, 2);
	sim_start(s, 1);
	sim_run_until(s, MS(2000));
	CHECK(!associated(1) && sim_count_evt(&s->nodes[1], TDMA_EVT_SYNCED, 0) == 0,
	      "PT followed the rogue FT");
	CHECK(st(1)->sec_mic_fail > 5, "rogue beacons: %u MIC failures", st(1)->sec_mic_fail);
	sim_start(s, 0);
	t = wait_nodes(pts, 1, MS(8000));
	CHECK(t != UINT64_MAX, "PT found the real FT next to the rogue");
	if (t == UINT64_MAX) {
		printf("    FT state %d beacons %u lbt ok %u busy %u; PT state %d mic %u opened %u "
		       "stale %u "
		       "nokey %u bad %u synced %d beacons_rx %u\n",
		       tdma_get_state(&s->nodes[0].mac), st(0)->beacons_tx, st(0)->lbt_ok,
		       st(0)->lbt_busy, tdma_get_state(&s->nodes[1].mac), st(1)->sec_mic_fail,
		       st(1)->sec_opened, st(1)->sec_stale, st(1)->sec_no_key, st(1)->sec_bad_hdr,
		       sim_count_evt(&s->nodes[1], TDMA_EVT_SYNCED, 0), st(1)->beacons_rx);
	}
	CHECK(tdma_parent(&s->nodes[1].mac) == rd(0), "parent 0x%08x",
	      tdma_parent(&s->nodes[1].mac));
	for (int i = 0; i < s->nodes[1].n_evts; i++) {
		const struct tdma_evt *e = &s->nodes[1].evts[i];

		CHECK(!((e->type == TDMA_EVT_SYNCED || e->type == TDMA_EVT_BEACON) &&
			e->rd_id == rd(2)),
		      "PT acted on a rogue beacon (event %d)", e->type);
	}
	printf("    rogue FT ignored (%u MIC failures); real FT joined %.0f ms after it started\n",
	       st(1)->sec_mic_fail, (double)(t - MS(2000)) / 69120.0);
}

/* ---- 5. forged acks, forged association ---------------------------------------------------------
 */

static int fa_pos;
static uint8_t fa_box =
	2; /* the transmitter the injected bursts claim (sec_foreign: another one) */
static uint32_t fa_injected;
static uint64_t fa_stop;
static bool fa_sec;

/* local start of slot si in FT frame f */
static uint64_t ft_slot_true(int ft, uint32_t f, uint8_t si)
{
	const struct tdma_mac *m = &s->nodes[ft].mac;
	uint64_t l = m->ref_start +
		     (uint64_t)((int64_t)(int32_t)(f - m->ref_frame) * (int64_t)TDMA_FRAME_TICKS) +
		     (uint64_t)m->plan->slots[si].subslot * TDMA_SUBSLOT_TICKS;

	return sim_true_of(&s->nodes[ft], l);
}

static uint32_t ft_next_frame(int ft)
{
	const struct tdma_mac *m = &s->nodes[ft].mac;
	uint64_t l = sim_local(&s->nodes[ft], s->t);

	return m->ref_frame + (uint32_t)((l - m->ref_start) / TDMA_FRAME_TICKS) + 1;
}

/* A packet the way an attacker without the key builds it: records, a fake header and MIC. */
static size_t forge(uint8_t *pkt, const uint8_t *rec, size_t rec_len, bool clear)
{
	size_t n = 0;

	if (fa_sec) {
		struct tdma_sec_hdr sh = {.ver = 1,
					  .key_idx = 0,
					  .clear = clear,
					  .body_len = (uint16_t)(clear ? 0 : rec_len)};

		tdma_sec_hdr_encode(&sh, pkt);
		n = 2;
	}
	memcpy(pkt + n, rec, rec_len);
	n += rec_len;
	if (fa_sec) {
		for (int i = 0; i < TDMA_SEC_MIC_LEN; i++) {
			pkt[n++] = (uint8_t)sim_rand(s);
		}
	}
	return n;
}

static void fa_inject(struct sim *sm, void *arg)
{
	const struct tdma_mac *m = &sm->nodes[0].mac;
	uint32_t f = ft_next_frame(0);
	uint8_t rec[16], pkt[64], hdr[TDMA_PHY_HDR_LEN];
	const struct tdma_link *l = &m->peers[fa_pos].link;
	struct tdma_ack a = {.valid = true,
			     .ack = (uint8_t)(l->next_seq - 1),
			     .ack_map = 0xffff,
			     .wide = l->wide};
	int n;

	(void)arg;
	if (sm->t >= fa_stop) {
		return;
	}
	for (uint8_t si = 0; si < m->plan->n_slots; si++) {
		const struct tdma_slot *sl = &m->plan->slots[si];
		struct tdma_phy_hdr h = {.subslots = sl->len,
					 .short_nwid = (uint8_t)sim_network_id(),
					 .tx_short = tdma_short_rd(sim_rd_for_box(fa_box)),
					 .rx_short = tdma_short_rd(rd(0)),
					 .mcs = m->mcs};

		if (sl->use != TDMA_SLOT_UL || sl->pos != fa_pos) {
			continue;
		}
		n = tdma_ack_encode(&a, rec + 2, sizeof(rec) - 2);
		rec[0] = (uint8_t)n;
		rec[1] = (uint8_t)fa_pos;
		tdma_phy_hdr_encode(&h, hdr, sizeof(hdr));
		sim_inject(sm, ft_slot_true(0, f, si), SIM_CHANNEL, hdr, pkt,
			   forge(pkt, rec, (size_t)n + 2, false), sl->len, m->mcs);
		fa_injected++;
	}
	sim_at(sm, sm->t + TDMA_FRAME_TICKS, fa_inject, NULL);
}

static void fa_ft_send(struct sim *sm, void *arg)
{
	uint8_t d[40] = {1, 2, 3};

	(void)arg;
	if (sm->t >= fa_stop) {
		return;
	}
	sim_send(sm, 0, rd(1), d, sizeof(d), 0);
	sim_at(sm, sm->t + MS(10), fa_ft_send, NULL);
}

static void forged_ack_run(bool sec, uint32_t *ok, bool *released)
{
	int pts[1] = {1};
	uint64_t t0;

	net_init(13);
	fa_sec = sec;
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_A, sec ? K1 : NULL);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_A, sec ? K1 : NULL);
	sim_start(s, 0);
	sim_start(s, 1);
	t0 = wait_nodes(pts, 1, MS(3000));
	CHECK(t0 != UINT64_MAX, "association");
	for (fa_pos = 0;
	     fa_pos < TDMA_MAX_POSITIONS && s->nodes[0].mac.peers[fa_pos].rd_id != rd(1);
	     fa_pos++) {
	}
	sim_run_until(s, t0 + MS(100));
	sim_kill(s, 1); /* the PT is gone; the attacker answers in its slot */
	fa_injected = 0;
	fa_stop = s->t + MS(2000);
	sim_at(s, s->t, fa_ft_send, NULL);
	sim_at(s, s->t, fa_inject, NULL);
	sim_run_until(s, fa_stop);
	*ok = st(0)->sdu_tx_ok;
	*released = sim_count_evt(&s->nodes[0], TDMA_EVT_CHILD_REMOVED, 0) > 0;
	sim_run_until(s, fa_stop + MS(300));
}

/*
 * a burst of another transmitter (another cluster on our
 * carrier, a three-hop chain: the depth-2 child's UL in the relay's DL slots) in a PT's
 * slot is not that PT's MIC failure: ignored and counted apart, no alarm.
 */
void test_sec_foreign(void)
{
	uint32_t ok;
	bool rel;

	fa_box = 9;
	forged_ack_run(true, &ok, &rel);
	fa_box = 2;
	printf("    %u bursts of box 9 in the dead PT's UL slot: MIC failures %u, foreign %u, "
	       "alarms %u\n",
	       fa_injected, st(0)->sec_mic_fail, st(0)->sec_foreign, st(0)->sec_alarms);
	CHECK(st(0)->sec_mic_fail == 0 && st(0)->sec_alarms == 0, "counted as MIC failures: %u",
	      st(0)->sec_mic_fail);
	CHECK(st(0)->sec_foreign > 10, "foreign %u", st(0)->sec_foreign);
	CHECK(ok == 0 && rel, "nothing believed, the dead PT released");
}

void test_sec_forged_ack(void)
{
	uint32_t ok_plain, ok_sec;
	bool rel_plain, rel_sec;
	uint32_t fails, rej;

	forged_ack_run(false, &ok_plain, &rel_plain);
	printf("    without security: %u forged acks injected, FT counted %u SDUs as delivered to "
	       "a "
	       "dead PT, released it: %s\n",
	       fa_injected, ok_plain, rel_plain ? "yes" : "no");
	CHECK(ok_plain > 50 && !rel_plain, "the attack works without security (control)");

	forged_ack_run(true, &ok_sec, &rel_sec);
	fails = st(0)->sec_mic_fail;
	printf("    with security: %u forged acks injected, %u failed the MIC, %u SDUs counted as "
	       "delivered, released: %s\n",
	       fa_injected, fails, ok_sec, rel_sec ? "yes" : "no");
	CHECK(ok_sec == 0, "forged acks believed: %u", ok_sec);
	CHECK(rel_sec, "dead PT kept alive by forged bursts");
	CHECK(fails > 10, "MIC failures %u", fails);
	CHECK(st(0)->sec_alarms > 0, "no alarm");

	/* forged association request (sealed-looking, wrong MIC) in a free UL slot */
	{
		const struct tdma_mac *m = &s->nodes[0].mac;
		struct tdma_assoc_req r = {
			.pt_rd_id = sim_rd_for_box(7), .ft_rd_id = rd(0), .box_id = 7, .nonce = 5};
		uint8_t rec[20], pkt[64], hdr[TDMA_PHY_HDR_LEN];
		int n = tdma_assoc_encode(&r, rec + 2, sizeof(rec) - 2);
		int k = 0;

		rec[0] = (uint8_t)n;
		rec[1] = TDMA_ADDR_ALL;
		for (uint32_t f = ft_next_frame(0); k < 20; f++) {
			for (uint8_t si = 0; si < m->plan->n_slots; si++) {
				const struct tdma_slot *sl = &m->plan->slots[si];
				struct tdma_phy_hdr h = {.subslots = sl->len,
							 .short_nwid = (uint8_t)sim_network_id(),
							 .tx_short = tdma_short_rd(r.pt_rd_id),
							 .rx_short = tdma_short_rd(rd(0)),
							 .mcs = m->mcs};

				if (sl->use != TDMA_SLOT_UL) {
					continue;
				}
				tdma_phy_hdr_encode(&h, hdr, sizeof(hdr));
				sim_inject(s, ft_slot_true(0, f, si), SIM_CHANNEL, hdr, pkt,
					   forge(pkt, rec, (size_t)n + 2, true), sl->len, m->mcs);
				k++;
				break;
			}
		}
		rej = st(0)->sec_assoc_reject;
		sim_run_until(s, s->t + FRAMES(30));
		CHECK(st(0)->sec_assoc_reject >= rej + 15, "forged associations rejected: %u",
		      st(0)->sec_assoc_reject - rej);
		CHECK(tdma_children(&s->nodes[0].mac, (uint32_t[4]){0}, 4) == 0,
		      "forged association accepted");
		printf("    20 forged association requests: %u rejected by the MIC, no child "
		       "added\n",
		       st(0)->sec_assoc_reject - rej);
	}
}

/* ---- 6. replay ----------------------------------------------------------------------------------
 */

#define REC_MAX 2048

struct rec_pkt {
	int node;
	uint64_t t;
	uint16_t ch;
	uint8_t hdr[TDMA_PHY_HDR_LEN];
	uint8_t pl[TDMA_PKT_MAX];
	size_t len;
	uint8_t subslots, mcs;
};

static struct rec_pkt recs[REC_MAX];
static int n_recs;
static bool recording;

static void recorder(struct sim *sm, int node, uint64_t t, uint16_t ch, const uint8_t *hdr,
		     const uint8_t *pl, size_t len, uint8_t subslots, uint8_t mcs)
{
	(void)sm;
	if (!recording || n_recs >= REC_MAX) {
		return;
	}
	recs[n_recs] = (struct rec_pkt){
		.node = node, .t = t, .ch = ch, .len = len, .subslots = subslots, .mcs = mcs};
	memcpy(recs[n_recs].hdr, hdr, TDMA_PHY_HDR_LEN);
	memcpy(recs[n_recs].pl, pl, len);
	n_recs++;
}

/* Replay node's recorded packets, shifted by whole frames so they land in the same slots later. */
static int replay(int node, uint64_t from, uint64_t shift_frames)
{
	int k = 0;

	for (int i = 0; i < n_recs; i++) {
		const struct rec_pkt *r = &recs[i];

		if (r->node != node || r->t < from) {
			continue;
		}
		sim_inject(s, r->t + FRAMES(shift_frames), r->ch, r->hdr, r->pl, r->len,
			   r->subslots, r->mcs);
		k++;
	}
	return k;
}

void test_sec_replay(void)
{
	int pts[2] = {1, 2};
	uint64_t t0, t1, t2, tl;
	uint32_t rx_before, f0, stale0;
	int k;

	net_init(14);
	tf_reset();
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 3, TDMA_PLAN_A, K1);
	s->on_air = recorder;
	n_recs = 0;
	for (int i = 0; i < 3; i++) {
		sim_start(s, i);
	}
	t0 = wait_nodes(pts, 2, MS(3000));
	CHECK(t0 != UINT64_MAX, "association");
	tf_add(1, 0, 40, MS(20), t0);
	tf_add(0, 1, 40, MS(20), t0);
	tf_add(2, 0, 40, MS(20), t0);
	tf_stop = t0 + MS(1000);
	recording = true;
	sim_run_until(s, t0 + MS(1000));
	recording = false;

	/* (a) PT 1 dies; its recorded UL bursts are replayed in its slot */
	sim_kill(s, 1);
	t1 = s->t;
	rx_before = tf[0].got;
	f0 = st(0)->sec_mic_fail;
	k = replay(1, t0 + MS(500), (t1 - (t0 + MS(500))) / TDMA_FRAME_TICKS + 2);
	sim_run_until(s, t1 + MS(800));
	CHECK(tf[0].got == rx_before, "replayed SDUs delivered: %u", tf[0].got - rx_before);
	/* until the FT releases the silent PT (20 missed UL bursts) they reach the MIC check */
	CHECK(st(0)->sec_mic_fail - f0 >= 10, "replays not refused: %u of %d",
	      st(0)->sec_mic_fail - f0, k);
	CHECK(sim_find_evt(&s->nodes[0], TDMA_EVT_CHILD_REMOVED, t1, NULL) != NULL,
	      "replays kept the dead PT alive");
	printf("    (a) %d UL bursts replayed 0.5 s later: %u MIC failures, 0 SDUs, dead PT "
	       "released\n",
	       k, st(0)->sec_mic_fail - f0);

	/* (b) the FT dies; its beacons are replayed: PT 2 must not stay on the dead timeline */
	sim_kill(s, 0);
	t2 = s->t;
	stale0 = st(2)->sec_stale;
	k = replay(0, t0, (t2 - t0) / TDMA_FRAME_TICKS + 2);
	sim_run_until(s, t2 + MS(1000));
	CHECK(sim_find_evt(&s->nodes[2], TDMA_EVT_LOST, t2, &tl) != NULL, "PT stayed on replays");
	CHECK(sim_count_evt(&s->nodes[2], TDMA_EVT_SYNCED, t2) == 0, "PT re-synced to replays");
	CHECK(st(2)->sec_stale > stale0, "stale beacons not counted");
	printf("    (b) %d FT bursts replayed after the FT died: PT lost sync after %.0f ms, %u "
	       "stale "
	       "beacons refused, never re-synced\n",
	       k, (double)(tl - t2) / 69120.0, st(2)->sec_stale - stale0);

	/* (c) the FT comes back (new session) while old-session beacons keep coming */
	sim_revive(s, 0);
	k = replay(0, t0, (s->t - t0) / TDMA_FRAME_TICKS + 2);
	CHECK(wait_nodes(&pts[1], 1, s->t + MS(6000)) != UINT64_MAX,
	      "PT did not find the restarted FT among replays");
	CHECK(tdma_parent(&s->nodes[2].mac) == rd(0), "wrong parent");
	printf("    (c) FT restarted with %d old bursts replayed meanwhile: PT on the new "
	       "session\n",
	       k);
}

/* ---- 7. tampering
 * -------------------------------------------------------------------------------- */

static int tp_target; /* node whose next packet gets a bit flip */
static int tp_bit;    /* payload bit; < 0: header bit -tp_bit - 1 */
static bool tp_armed;
static uint8_t tp_nonce[TDMA_SEC_NONCE_LEN];
static size_t tp_used;
static bool tp_done;
static uint8_t tp_want; /* only packets whose first record (after the header) is ... 0 = any */

static void tamper(struct sim *sm, int node, uint8_t *hdr, uint8_t *pl, size_t tbs)
{
	struct tdma_sec_hdr sh;

	if (!tp_armed || node != tp_target || tdma_sec_hdr_decode(pl, &sh)) {
		return;
	}
	if (tp_want && !(sh.clear && pl[4] == TDMA_PDU_BEACON)) {
		return;
	}
	tp_used = TDMA_SEC_HDR_LEN + (sh.clear ? pl[2] + 2u : 0u) + sh.body_len + TDMA_SEC_MIC_LEN;
	memcpy(tp_nonce, sm->nodes[node].sec.last_nonce, sizeof(tp_nonce));
	if (tp_bit >= 0) {
		if ((size_t)tp_bit / 8 >= tbs) {
			return;
		}
		pl[tp_bit / 8] ^= (uint8_t)(1u << (tp_bit % 8));
	} else {
		hdr[(-tp_bit - 1) / 8] ^= (uint8_t)(1u << ((-tp_bit - 1) % 8));
	}
	tp_armed = false;
	tp_done = true;
}

/* Flip bits of node tx's packets one at a time; returns (rejected, accepted, padding accepted). */
static void tamper_sweep(int tx, int rx, bool beacon, bool header, int *rej, int *acc, int *pad_ok,
			 int *pad_n)
{
	int nbits = header ? 7 * 8 : 8 * 160;

	*rej = *acc = *pad_ok = *pad_n = 0;
	tp_target = tx;
	tp_want = beacon;
	for (int b = 0; b < nbits; b++) {
		/* padding: only a sample */
		tp_bit = header ? -(b + 1) : b;
		tp_armed = true;
		tp_done = false;
		while (!tp_done) {
			sim_run_until(s, s->t + TDMA_FRAME_TICKS / 2);
		}
		sim_run_until(s, s->t + FRAMES(2));
		bool ok = sim_sec_opened(&s->nodes[rx], tp_nonce);

		if (header) {
			/*
			 * byte 4: bits 4-7 TX power (informational), bit 3 unused:
			 * neither is decoded, so neither is authenticated
			 */
			if (b / 8 == 4 && b % 8 >= 3) {
				*pad_n += 1;
				*pad_ok += ok;
			} else if (ok) {
				*acc += 1;
				printf("    header bit %d accepted\n", b);
			} else {
				*rej += 1;
			}
		} else if ((size_t)b / 8 >= tp_used) {
			*pad_n += 1;
			*pad_ok += ok;
			if (b / 8 >= (int)tp_used + 2) {
				break; /* a few padding bytes are enough */
			}
		} else if (ok) {
			*acc += 1;
			printf("    payload bit %d (of %zu bytes) accepted\n", b, tp_used);
		} else {
			*rej += 1;
		}
		sim_run_until(s,
			      s->t + FRAMES(1)); /* a good burst in between (PT beacon counter) */
	}
}

void test_sec_tamper(void)
{
	int pts[1] = {1};
	int rej, acc, pad_ok, pad_n;
	uint64_t t0;

	net_init(15);
	tf_reset();
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_A, K1);
	sim_start(s, 0);
	sim_start(s, 1);
	t0 = wait_nodes(pts, 1, MS(3000));
	CHECK(t0 != UINT64_MAX, "association");
	s->on_tamper = tamper;
	tf_add(1, 0, 24, MS(5), t0);
	tf_add(0, 1, 24, MS(5), t0);

	tamper_sweep(1, 0, false, false, &rej, &acc, &pad_ok, &pad_n);
	printf("    PT UL bursts: %d payload bits flipped and rejected, %d accepted; padding %d/%d "
	       "accepted\n",
	       rej, acc, pad_ok, pad_n);
	CHECK(acc == 0 && rej > 100, "UL payload tamper: %d accepted", acc);
	CHECK(pad_ok == pad_n, "padding flips must not matter (%d/%d)", pad_ok, pad_n);

	tamper_sweep(0, 1, true, false, &rej, &acc, &pad_ok, &pad_n);
	printf("    FT beacon bursts: %d bits (clear beacon, body, MIC) rejected, %d accepted; "
	       "padding %d/%d\n",
	       rej, acc, pad_ok, pad_n);
	CHECK(acc == 0 && rej > 300, "beacon burst tamper: %d accepted", acc);

	tamper_sweep(1, 0, false, true, &rej, &acc, &pad_ok, &pad_n);
	printf("    PHY header: %d bits rejected, %d accepted; TX power + unused bits %d/%d "
	       "accepted "
	       "(not decoded, not authenticated)\n",
	       rej, acc, pad_ok, pad_n);
	CHECK(acc == 0, "header tamper: %d accepted", acc);
	s->on_tamper = NULL;
	CHECK(associated(1), "PT lost its FT during the sweep");
}

/* ---- 8. FT restart, role switch: global nonce-reuse check --------------------------------------
 */

static void revive_cb(struct sim *sm, void *arg)
{
	sim_revive(sm, (int)(intptr_t)arg);
}

static void swap_cb(struct sim *sm, void *arg)
{
	(void)arg;
	/* box 2 becomes the FT, the old FT (box 1) comes back as a PT a little later */
	sim_kill(sm, 0);
	sm->nodes[1].cfg.role = TDMA_ROLE_FT;
	sim_revive(sm, 1);
	sm->nodes[0].cfg.role = TDMA_ROLE_PT;
}

void test_sec_ft_restart(void)
{
	int pts[2] = {1, 2}, pts2[2] = {0, 2};

	sim_sec_stats_reset();
	net_init(16);
	tf_reset();
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 3, TDMA_PLAN_A, K1);
	for (int i = 0; i < 3; i++) {
		sim_start(s, i);
	}
	CHECK(wait_nodes(pts, 2, MS(3000)) != UINT64_MAX, "association");
	tf_add(1, 0, 60, MS(10), s->t);
	tf_add(0, 2, 60, MS(10), s->t);
	sim_at(s, MS(3000), revive_cb, (void *)0);
	sim_at(s, MS(7000), revive_cb, (void *)0);
	sim_run_until(s, MS(11000));
	CHECK(wait_nodes(pts, 2, MS(14000)) != UINT64_MAX, "re-association after FT restarts");
	tf_stop = s->t;
	sim_at(s, s->t + MS(100), swap_cb, NULL);
	sim_at(s, s->t + MS(1100), revive_cb, (void *)0);
	sim_run_until(s, s->t + MS(1200));
	CHECK(wait_nodes(pts2, 2, s->t + MS(8000)) != UINT64_MAX,
	      "association after the role switch");
	CHECK(tdma_parent(&s->nodes[0].mac) == rd(1), "old FT under the new one");
	printf("    2 FT restarts + role switch: %llu bursts sealed, %llu nonce reuses, sessions "
	       "derived %u\n",
	       (unsigned long long)sim_sec_st.seals, (unsigned long long)sim_sec_st.nonce_reuse,
	       SUM(sec_derive));
	CHECK(sim_sec_st.nonce_reuse == 0, "nonce reuse across sessions");
}

/* ---- 9. counter wrap ---------------------------------------------------------------------------
 */

void test_sec_counter_wrap(void)
{
	int pts[2] = {1, 2};
	uint64_t t0;

	sim_sec_stats_reset();
	net_init(17);
	tf_reset();
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_H, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_H, K1);
	add(TDMA_ROLE_PT, 3, TDMA_PLAN_H, K1);
	/* start 300 frames before the 32-bit frame counter wraps; sessions of 250 frames */
	s->nodes[0].cfg.start_frame = 0xffffffffu - 300u;
	s->nodes[0].cfg.sec_session_frames = 250;
	s->nodes[0].cfg.sec_announce_frames = 50;
	for (int i = 0; i < 3; i++) {
		sim_start(s, i);
	}
	t0 = wait_nodes(pts, 2, MS(2000));
	CHECK(t0 != UINT64_MAX, "association");
	for (int i = 1; i <= 2; i++) {
		tf_add(0, i, 300, MS(15), t0);
		tf_add(i, 0, 300, MS(15), t0);
	}
	tf_stop = t0 + MS(6000);
	sim_run_until(s, tf_stop + MS(500));
	tf_check("wrap", 0);
	CHECK(st(0)->sec_switches >= 2, "session rollovers: %u", st(0)->sec_switches);
	CHECK(s->nodes[0].mac.cur_frame < 1000, "frame counter did not wrap (%u)",
	      s->nodes[0].mac.cur_frame);
	CHECK(sim_count_evt(&s->nodes[1], TDMA_EVT_LOST, 0) == 0 &&
		      sim_count_evt(&s->nodes[2], TDMA_EVT_LOST, 0) == 0,
	      "a PT lost its FT across the wrap / rollover");
	CHECK(sim_sec_st.nonce_reuse == 0, "nonce reuse");
	CHECK(SUM(sdu_tx_drop) == 0, "SDUs dropped: %u", SUM(sdu_tx_drop));
	printf("    frame counter wrapped (now %u), %u session rollovers, %u SDUs, 0 lost, 0 nonce "
	       "reuse\n",
	       s->nodes[0].mac.cur_frame, st(0)->sec_switches, SUM(sdu_rx));
}

/* ---- 10. rekey under load -----------------------------------------------------------------------
 */

static void rekey_cb(struct sim *sm, void *arg)
{
	(void)arg;
	sim_sec_state(sm, 0, 0, 1); /* "mm key activate 1" on the FT */
}

static void rekey_run(bool missing, uint64_t seed)
{
	int pts[3] = {1, 2, 3};
	uint64_t t0, ts;

	sim_sec_stats_reset();
	net_init(seed);
	tf_reset();
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_H4, K1);
	for (int i = 0; i < 3; i++) {
		add(TDMA_ROLE_PT, (uint8_t)(2 + i), TDMA_PLAN_H4, K1);
	}
	for (int i = 0; i < 4; i++) {
		if (!(missing && i == 3)) {
			sim_sec_key(s, i, 1, K2); /* the new bundle (epoch + 1) reached the box */
		}
		sim_start(s, i);
	}
	t0 = wait_nodes(pts, 3, MS(3000));
	CHECK(t0 != UINT64_MAX, "association");
	for (int i = 1; i <= 3; i++) {
		tf_add(0, i, (size_t)(40 + 300 * (i - 1)), MS(12), t0);
		tf_add(i, 0, (size_t)(40 + 300 * (i - 1)), MS(12), t0);
	}
	tf_stop = t0 + MS(4000);
	sim_at(s, t0 + MS(1500), rekey_cb, NULL);
	sim_run_until(s, tf_stop + MS(500));
	CHECK(sim_find_evt(&s->nodes[0], TDMA_EVT_KEY_ANNOUNCE, t0, NULL) != NULL,
	      "no announcement");
	CHECK(sim_find_evt(&s->nodes[0], TDMA_EVT_KEY_SWITCH, t0, &ts) != NULL,
	      "FT did not switch");
	CHECK(s->nodes[0].mac.sec.cur >= 0 &&
		      s->nodes[0].mac.sec.sess[s->nodes[0].mac.sec.cur].idx == 1,
	      "FT not on key 1");
	CHECK(sim_sec_st.nonce_reuse == 0, "nonce reuse");
	if (!missing) {
		tf_check("rekey", 0);
		for (int i = 1; i <= 3; i++) {
			CHECK(sim_count_evt(&s->nodes[i], TDMA_EVT_LOST, 0) == 0, "PT %d lost", i);
			CHECK(sim_find_evt(&s->nodes[i], TDMA_EVT_KEY_SWITCH, t0, NULL) != NULL,
			      "PT %d did not switch", i);
		}
		CHECK(SUM(sdu_tx_drop) == 0, "SDUs dropped: %u", SUM(sdu_tx_drop));
		printf("    key 0 -> 1 under bidirectional load (3 PTs, 40-640 B): switch %.0f ms "
		       "after "
		       "the request, %u SDUs, 0 lost, 0 dropped\n",
		       (double)(ts - t0 - MS(1500)) / 69120.0, SUM(sdu_rx));
	} else {
		const struct tdma_evt *e = sim_find_evt(&s->nodes[3], TDMA_EVT_LOST, t0, NULL);

		CHECK(e && e->cause == TDMA_CAUSE_KEY, "PT without key 1: LOST cause %d",
		      e ? (int)e->cause : -1);
		CHECK(!associated(3), "PT without the new key still associated");
		for (int i = 1; i <= 2; i++) {
			CHECK(sim_count_evt(&s->nodes[i], TDMA_EVT_LOST, 0) == 0, "PT %d lost", i);
		}
		tf_check("rekey, one PT without the key", (1 << 4) | (1 << 5));
		printf("    PT without key 1: LOST(KEY); the other two: 0 lost\n");
	}
}

void test_sec_rekey(void)
{
	rekey_run(false, 18);
	rekey_run(true, 19);
}

/* ---- 11. duplicate box id
 * ------------------------------------------------------------------------ */

void test_sec_dup_id(void)
{
	sim_sec_stats_reset();
	net_init(20);
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_A, K1); /* provisioned with the same box id */
	for (int i = 0; i < 3; i++) {
		sim_start(s, i);
	}
	sim_run_until(s, MS(8000));
	{
		const struct tdma_evt *e = NULL;

		for (int i = 0; i < s->nodes[0].n_evts; i++) {
			if (s->nodes[0].evts[i].type == TDMA_EVT_SEC_ALARM &&
			    s->nodes[0].evts[i].cause == TDMA_CAUSE_DUP_ID) {
				e = &s->nodes[0].evts[i];
			}
		}
		CHECK(e && e->rd_id == rd(1), "FT did not alarm on the duplicate rd id");
	}
	printf("    two radios with box id 2: FT alarms (duplicate rd id), %llu nonce reuses "
	       "flagged by the checker\n",
	       (unsigned long long)sim_sec_st.nonce_reuse);
	CHECK(sim_sec_st.nonce_reuse > 0, "the checker must see the reuse");
}

/* ---- 13. timing model
 * ---------------------------------------------------------------------------- */

static uint32_t timing_run(bool hints, uint32_t *delivered, uint32_t *sent)
{
	int pts[2] = {1, 2};
	uint64_t t0;

	net_init(21);
	tf_reset();
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_1X10, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_1X10, K1);
	add(TDMA_ROLE_PT, 3, TDMA_PLAN_1X10, K1);
	for (int i = 0; i < 3; i++) {
		/* 120 cycles/byte at 64 MHz (software CCM): 30 us per 16 B + 50 us */
		s->nodes[i].sec.cost_per16 = TDMA_US_TO_TICKS(30);
		s->nodes[i].sec.cost_base = TDMA_US_TO_TICKS(50);
		s->nodes[i].sec.hints = hints;
		sim_start(s, i);
	}
	t0 = wait_nodes(pts, 2, MS(3000));
	CHECK(t0 != UINT64_MAX, "association");
	tf_add(0, 1, 1200, MS(20), t0);
	tf_add(0, 2, 1200, MS(20), t0);
	tf_stop = t0 + MS(3000);
	sim_run_until(s, tf_stop + MS(1000));
	*delivered = tf[0].got + tf[1].got;
	*sent = tf[0].sent + tf[1].sent;
	return sim_phy_errors(s) + SUM(late_slots) + SUM(port_errors);
}

void test_sec_timing(void)
{
	uint32_t d0, s0, d1, s1;
	uint32_t e0 = timing_run(false, &d0, &s0);
	uint32_t e1 = timing_run(true, &d1, &s1);

	printf("    1x10, full 463 B DL bursts, seal model 50 us + 30 us / 16 B (~920 us):\n"
	       "      1 ms commit lead: %u PHY lead violations / late / port errors, %u/%u SDUs\n"
	       "      per-slot lead (+seal time): %u, %u/%u SDUs\n",
	       e0, d0, s0, e1, d1, s1);
	CHECK(e0 > 0, "the model should break the fixed lead");
	CHECK(e1 == 0 && d1 == s1, "per-slot lead: %u errors, %u/%u", e1, d1, s1);
}

/*
 * Verify windows (docs/mac-design.md "Link security"): every opened burst keeps the
 * MAC busy for 450 us after its PHY event, as on the DK (meta-IRQ MAC thread,
 * open in the secure partition, then the PDUs), and ticks wait for it. Plan H with bulk both
 * ways and small packets. Without a cost model the waits make commits late;
 * with the firmware's (seal 450 us, typical open 250 us) the MAC keeps
 * commits out of those windows. The FT's grant-ahead choice follows the
 * typical open cost: with 250 us a PT verifies the DL burst with the grant in
 * time, with the seal model's 450 us it could not.
 */
static uint32_t busy_run(bool hints, uint32_t open_us, bool *ahead, uint32_t *delivered,
			 uint32_t *sent)
{
	int pts[1] = {1};
	uint64_t t0;

	net_init(31);
	tf_reset();
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_H, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_H, K1);
	for (int i = 0; i < 2; i++) {
		s->nodes[i].sec.cost_base = TDMA_US_TO_TICKS(450);
		s->nodes[i].sec.open_typ_base = TDMA_US_TO_TICKS(open_us);
		s->nodes[i].sec.open_busy = TDMA_US_TO_TICKS(450);
		s->nodes[i].sec.hints = hints;
		if (!hints) {
			s->nodes[i].sec.cost_base = 0; /* no lead, no debt: only the busy MAC */
		}
		sim_start(s, i);
	}
	*ahead = s->nodes[0].mac.cfg.grant_ahead;
	t0 = wait_nodes(pts, 1, MS(3000));
	CHECK(t0 != UINT64_MAX, "association");
	tf_add(0, 1, 1000, MS(30), t0);
	tf_add(1, 0, 1000, MS(30), t0);
	tf_add(0, 1, 40, MS(20), t0);
	tf_add(1, 0, 40, MS(20), t0);
	tf_stop = t0 + MS(3000);
	sim_run_until(s, tf_stop + MS(1000));
	*delivered = *sent = 0;
	for (int i = 0; i < ntf; i++) {
		*delivered += tf[i].got;
		*sent += tf[i].sent;
	}
	return sim_phy_errors(s) + SUM(late_slots) + SUM(port_errors);
}

void test_sec_rx_busy(void)
{
	uint32_t d0, s0, d1, s1, d2, s2;
	bool a0, a1, a2;
	uint32_t e0 = busy_run(false, 0, &a0, &d0, &s0);
	uint32_t e1 = busy_run(true, 250, &a1, &d1, &s1);
	uint32_t e2 = busy_run(true, 0, &a2, &d2, &s2);

	printf("    plan H, 1000 B + 40 B both ways, 450 us of MAC time per opened burst:\n"
	       "      no cost model: %u PHY / late / port errors, %u/%u SDUs\n"
	       "      seal 450 us, open 250 us: %u errors, %u/%u SDUs, grant ahead %s\n"
	       "      seal 450 us, open = seal: %u errors, %u/%u SDUs, grant ahead %s\n",
	       e0, d0, s0, e1, d1, s1, a1 ? "on" : "off", e2, d2, s2, a2 ? "on" : "off");
	CHECK(e0 > 0, "the busy MAC should make commits late without a cost model");
	CHECK(e1 == 0 && d1 == s1, "with the cost model: %u errors, %u/%u", e1, d1, s1);
	CHECK(!a1, "a 250 us open fits plan H's grant window: no grant ahead");
	CHECK(e2 == 0 && d2 == s2, "open = seal: %u errors, %u/%u", e2, d2, s2);
	CHECK(a2, "a 450 us open does not fit: grant ahead");
}

/* ---- 14. secured fuzz
 * ---------------------------------------------------------------------------- */

static uint32_t fz_n;
static uint64_t fz_stop;

static void fz_inject(struct sim *sm, void *arg)
{
	int node = (int)(sim_rand(sm) % 3);
	struct sim_node *n = &sm->nodes[node];
	uint8_t hdr[TDMA_PHY_HDR_LEN], pl[TDMA_PKT_MAX];
	size_t len = 4 + sim_rand(sm) % 200;
	struct tdma_phy_hdr h;
	int k;

	(void)arg;
	if (sm->t >= fz_stop) {
		return;
	}
	sim_at(sm, sm->t + 1000 + sim_rand(sm) % 5000, fz_inject, NULL);
	for (k = 0; k < SIM_NODE_OPS; k++) {
		if (n->ops[k].used && !n->ops[k].is_tx && n->ops[k].kind == SIM_OP_RX) {
			break;
		}
	}
	if (k == SIM_NODE_OPS) {
		return;
	}
	for (size_t i = 0; i < len; i++) {
		pl[i] = (uint8_t)sim_rand(sm);
	}
	{
		struct tdma_sec_hdr sh = {.ver = (uint8_t)(sim_rand(sm) % 8 ? 1 : sim_rand(sm) % 4),
					  .key_idx = (uint8_t)(sim_rand(sm) % 4),
					  .clear = sim_rand(sm) & 1,
					  .body_len = (uint16_t)(sim_rand(sm) % 3
									 ? sim_rand(sm) % (len + 8)
									 : sim_rand(sm) % 2048)};

		tdma_sec_hdr_encode(&sh, pl);
		if (sh.clear && sim_rand(sm) % 2) {
			pl[2] = (uint8_t)(sim_rand(sm) % len);
			pl[3] = TDMA_ADDR_ALL;
			pl[4] = (uint8_t)(sim_rand(sm) % 6);
			pl[5] = 0;
		}
	}
	{
		int peer = node == 0 ? 1 + (int)(sim_rand(sm) % 2) : 0;

		h = (struct tdma_phy_hdr){.subslots = 2,
					  .short_nwid = (uint8_t)sim_network_id(),
					  .tx_short = tdma_short_rd(sm->nodes[peer].cfg.rd_id),
					  .rx_short =
						  node == 0 ? tdma_short_rd(sm->nodes[0].cfg.rd_id)
							    : TDMA_SHORT_BROADCAST,
					  .mcs = 3};
	}
	tdma_phy_hdr_encode(&h, hdr, sizeof(hdr));
	tdma_on_rx(&n->mac, n->ops[k].handle, sim_local(n, sm->t), -70, 80, hdr, sizeof(hdr), pl,
		   len, true);
	fz_n++;
}

void test_sec_fuzz(void)
{
	int pts[2] = {1, 2};
	uint64_t t0;

	net_init(22);
	tf_reset();
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 3, TDMA_PLAN_A, K1);
	for (int i = 0; i < 3; i++) {
		sim_start(s, i);
	}
	t0 = wait_nodes(pts, 2, MS(3000));
	CHECK(t0 != UINT64_MAX, "association");
	for (int i = 1; i <= 2; i++) {
		tf_add(0, i, 80, MS(10), t0);
		tf_add(i, 0, 80, MS(10), t0);
	}
	tf_stop = fz_stop = t0 + MS(10000);
	fz_n = 0;
	sim_at(s, t0, fz_inject, NULL);
	sim_run_until(s, tf_stop + MS(500));
	tf_check("secured fuzz", 0);
	for (int i = 1; i <= 2; i++) {
		CHECK(sim_count_evt(&s->nodes[i], TDMA_EVT_LOST, t0) == 0, "PT %d lost", i);
	}
	printf("    %u garbage packets with (mostly) valid security headers into live RX ops: %u "
	       "bad "
	       "headers, %u MIC failures, %u no-key, traffic intact\n",
	       fz_n, SUM(sec_bad_hdr), SUM(sec_mic_fail), SUM(sec_no_key));
	CHECK(SUM(sec_bad_hdr) + SUM(sec_mic_fail) + SUM(sec_no_key) + SUM(bad_rx) > fz_n / 3,
	      "garbage not counted");
}

/* ---- dev key / real key separation, deny list ---------------------------------------------------
 */

void test_sec_devkey(void)
{
	int pts[1] = {1};

	net_init(23);
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_A, K1);
	s->nodes[0].sec.devkey = true; /* same key bytes, but the FT runs the dev key */
	sim_start(s, 0);
	sim_start(s, 1);
	sim_run_until(s, MS(3000));
	CHECK(!associated(1) && st(1)->sec_devkey > 50, "real-key PT joined a dev-key FT (%u)",
	      st(1)->sec_devkey);
	printf("    real-key PT: %u dev-key beacons refused in 3 s, never synced\n",
	       st(1)->sec_devkey);
	s->nodes[1].sec.devkey = true;
	sim_revive(s, 1);
	CHECK(wait_nodes(pts, 1, s->t + MS(3000)) != UINT64_MAX, "dev-key PT joins the dev-key FT");
	printf("    the same PT with the dev-key flag joins\n");
}

void test_sec_deny(void)
{
	int pts[2] = {1, 2};
	uint64_t t;
	const struct tdma_evt *e;

	net_init(24);
	add(TDMA_ROLE_FT, 1, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 2, TDMA_PLAN_A, K1);
	add(TDMA_ROLE_PT, 3, TDMA_PLAN_A, K1);
	for (int i = 0; i < 3; i++) {
		sim_start(s, i);
	}
	CHECK(wait_nodes(pts, 2, MS(3000)) != UINT64_MAX, "association");
	t = s->t;
	CHECK(tdma_sec_deny(&s->nodes[0].mac, rd(2), true) == 0, "deny add");
	e = sim_find_evt(&s->nodes[0], TDMA_EVT_CHILD_REMOVED, t, NULL);
	CHECK(e && e->rd_id == rd(2) && e->cause == TDMA_CAUSE_REVOKED, "denied child not removed");
	sim_run_until(s, t + MS(3000));
	CHECK(!associated(2) && associated(1), "deny list: PT 3 %d, PT 2 %d", associated(2),
	      associated(1));
	CHECK(st(0)->sec_denied > 0, "no request refused");
	printf("    denied PT removed (REVOKED), %u association requests refused in 3 s; the other "
	       "PT unaffected\n",
	       st(0)->sec_denied);
	CHECK(tdma_sec_deny(&s->nodes[0].mac, rd(2), false) == 0, "deny del");
	CHECK(wait_nodes(pts, 2, s->t + MS(5000)) != UINT64_MAX, "PT back after deny del");
}

/*
 * Beacons missed while DL data still comes (the PT's beacon RX ops failing,
 * docs/mac-design.md "Quiet window"): with link security a PT keeps sync on
 * verified DL bursts (and corrects its frame timing from the DL-slot ones)
 * up to TDMA_BEACON_MISS_DL_FACTOR x beacon_miss_max frames without a
 * beacon; longer, or without security, it loses sync as before. The FT's
 * beacons are hidden from the PT (another network id in the PHY header) for
 * n frames; the clocks are 40 ppm apart.
 */
static uint64_t bm_from, bm_to;
static int bm_hide, bm_hidden;

static void bm_air(struct sim *sm, int node, uint64_t t, uint16_t ch, const uint8_t *hdr,
		   const uint8_t *pl, size_t len, uint8_t subslots, uint8_t mcs)
{
	const struct tdma_mac *m = &sm->nodes[0].mac;
	uint64_t l, ph;

	(void)ch;
	(void)hdr;
	(void)pl;
	(void)len;
	(void)subslots;
	(void)mcs;
	bm_hide = 0;
	if (node != 0 || t < bm_from || t >= bm_to) {
		return;
	}
	l = sim_local(&sm->nodes[0], t);
	ph = (l - m->ref_start) % TDMA_FRAME_TICKS;
	bm_hide = ph < TDMA_SUBSLOT_TICKS / 2 || ph > TDMA_FRAME_TICKS - TDMA_SUBSLOT_TICKS / 2;
}

static void bm_tamper(struct sim *sm, int node, uint8_t *hdr, uint8_t *pl, size_t tbs)
{
	(void)sm;
	(void)pl;
	(void)tbs;
	if (node == 0 && bm_hide) {
		hdr[1] ^= 0x5a; /* the short network id: not ours, dropped before anything else */
		bm_hidden++;
	}
}

static void beacon_miss_run(bool sec, uint32_t frames, bool keep)
{
	int ft, pt;
	uint64_t t0;
	int assoc0;

	net_init(1500 + frames + sec);
	ft = sim_add_node(s, TDMA_ROLE_FT, 1, TDMA_PLAN_H, (int64_t)(sim_rand(s) % (1ull << 40)),
			  20000);
	pt = sim_add_node(s, TDMA_ROLE_PT, 2, TDMA_PLAN_H, (int64_t)(sim_rand(s) % (1ull << 40)),
			  -20000);
	if (sec) {
		sim_sec_on(s, ft, K1);
		sim_sec_on(s, pt, K1);
	}
	sim_start(s, ft);
	sim_start(s, pt);
	CHECK((t0 = wait_nodes(&pt, 1, MS(5000))) != UINT64_MAX, "association");
	tf_reset();
	tf_add(ft, pt, 200, MS(4), t0);
	tf_add(pt, ft, 64, MS(20), t0);
	bm_hidden = 0;
	bm_from = t0 + MS(1000);
	bm_to = bm_from + (uint64_t)frames * TDMA_FRAME_TICKS;
	s->on_air = bm_air;
	s->on_tamper = bm_tamper;
	assoc0 = sim_count_evt(&s->nodes[pt], TDMA_EVT_ASSOCIATED, 0);
	tf_stop = t0 + MS(3000);
	sim_run_until(s, t0 + MS(4000));
	printf("    security %s, %u frames without beacons (%d hidden): %s; bridged %u beacon "
	       "slots, "
	       "%u timing corrections, lost %d, PHY errors %u\n",
	       sec ? "on" : "off", frames, bm_hidden,
	       sim_count_evt(&s->nodes[pt], TDMA_EVT_LOST, 0) ? "sync lost" : "kept sync",
	       st(pt)->beacon_bridged, st(pt)->dl_resync,
	       sim_count_evt(&s->nodes[pt], TDMA_EVT_LOST, 0), s->nodes[pt].phy_errors);
	CHECK(bm_hidden >= (int)frames - 1, "%d beacons hidden of %u", bm_hidden, frames);
	if (keep) {
		CHECK(sim_count_evt(&s->nodes[pt], TDMA_EVT_LOST, 0) == 0 &&
			      sim_count_evt(&s->nodes[pt], TDMA_EVT_ASSOCIATED, 0) == assoc0,
		      "kept sync over %u frames without beacons", frames);
		CHECK(st(pt)->beacon_bridged > 0 && st(pt)->dl_resync > 0, "bridged %u, resync %u",
		      st(pt)->beacon_bridged, st(pt)->dl_resync);
		tf_check("beacons missed", 0);
	} else {
		CHECK(sim_count_evt(&s->nodes[pt], TDMA_EVT_LOST, 0) == 1, "sync lost (%u frames)",
		      frames);
		CHECK(associated(pt), "associated again after the beacons came back");
	}
	s->on_air = NULL;
	s->on_tamper = NULL;
}

void test_sec_beacon_miss(void)
{
	beacon_miss_run(true, 25, true);
	beacon_miss_run(true, 50, false);
	beacon_miss_run(false, 15, false);
}
