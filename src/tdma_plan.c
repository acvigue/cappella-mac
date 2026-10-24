/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Slot plans and PHY sizing. A plan is a table, not code: the scheduler walks
 * it in subslot order every frame. The layouts follow
 * docs/phy-timing.md "Recommendations": one combined FT DL burst per
 * opportunity, the UL bursts of all PTs back to back (1 subslot apart) inside
 * one FT RX, and >= 2 idle subslots between any two ops of one device.
 */

#include <errno.h>

#include <cappella/tdma_mac.h>

#define BCN(ss, n)       {(ss), (n), TDMA_SLOT_BEACON, 0, 0, 0}
#define DL(ss, n)        {(ss), (n), TDMA_SLOT_DL, 0, 0, 0}
#define UL(ss, p)        {(ss), 2, TDMA_SLOT_UL, (p), 0, 0}
#define CT(ss)           {(ss), 2, TDMA_SLOT_CONTENTION, 0, 0, 0}
#define FX(ss, n)        {(ss), (n), TDMA_SLOT_FLEX, 0, 0, 0}
/* FLEX region: DL long bursts at ss for n, UL long bursts e subslots earlier for up to u */
#define FXU(ss, n, e, u) {(ss), (n), TDMA_SLOT_FLEX, 0, (e), (u)}

/*
 * Plan A: two 5 ms half-frames. 0-3 DL (4 ss, 209 B at MCS 3), 4-5 idle,
 * UL0..UL3 at 6/9/12/15, contention 18-19, 20-23 idle (FT RX -> TX).
 */
#define HALF_A(o) UL((o) + 6, 0), UL((o) + 9, 1), UL((o) + 12, 2), UL((o) + 15, 3), CT((o) + 18)

static const struct tdma_slot slots_a[] = {
	BCN(0, 4),
	HALF_A(0),
	DL(24, 4),
	HALF_A(24),
};

/*
 * Plan B: four 2.5 ms quarter-frames. 0-1 DL (2 ss, 117 B at MCS 4), 2-3 idle,
 * UL0 4-5, UL1 7-8, 9-11 idle. No room for a contention slot: the UL slot of a
 * free position is the contention opportunity (with both taken nobody could
 * join anyway).
 */
#define QUARTER_B(o) UL((o) + 4, 0), UL((o) + 7, 1)

static const struct tdma_slot slots_b[] = {
	BCN(0, 2), QUARTER_B(0),  DL(12, 2), QUARTER_B(12),
	DL(24, 2), QUARTER_B(24), DL(36, 2), QUARTER_B(36),
};

/*
 * One opportunity per frame: 8 ss DL (463 B at MCS 3), 10 UL slots, 2 contention.
 * UL0 starts 5 ss after the DL burst (a received long burst, TDMA_LRX_TO_TX_SS).
 */
static const struct tdma_slot slots_1x10[] = {
	BCN(0, 8), UL(13, 0), UL(16, 1), UL(19, 2), UL(22, 3), UL(25, 4),
	UL(28, 5), UL(31, 6), UL(34, 7), UL(37, 8), UL(40, 9), CT(43),
};

/*
 * Plan H (hybrid): two 5 ms half-frames. 0-2 DL (3 ss, 217 B at MCS 4: beacon,
 * grant and a 64 B packet for both PTs), 3-4 idle, UL0 5-6, UL1 8-9, then one
 * long burst per half-frame, 13-18 (6 ss, 503 B at MCS 4): 3 ss after the FT's
 * UL-run RX, and 5 ss from its end to the receiver's next op
 * (TDMA_LRX_TO_TX_SS: the FT's DL TX after an UL one, the PT's DL RX after a
 * DL one). An UL burst granted a DL period ahead (a PT with a backlog) starts a
 * subslot earlier: 12-18 (7 ss, 604 B, RX -> RX 2 ss after the UL run); granted
 * just in time it cannot, the PT knows the grant only ~1 ms before it would
 * have to commit. The guaranteed slots are plan A's cadence for 2 PTs; the flex
 * region is given per half-frame to whoever has the most pressing bulk (grant
 * record in the DL burst right before it).
 */
#define HALF_H(o) UL((o) + 5, 0), UL((o) + 8, 1), FXU((o) + 13, 6, 1, 7)

static const struct tdma_slot slots_h[] = {
	BCN(0, 3),
	HALF_H(0),
	DL(24, 3),
	HALF_H(24),
};

/*
 * Plan H4: 4 PTs. Two guaranteed blocks per frame (DL 3 ss, UL at +5/+8/+11/+14)
 * at 0 and 19, then FLEX: DL 38-42 (5 ss, 407 B at MCS 4) or UL 37-42 (6 ss,
 * 503 B), both 5 ss before the beacon. DL and UL come every 19 / 29 ss (max 6 ms).
 */
#define BLK_H4(o) UL((o) + 5, 0), UL((o) + 8, 1), UL((o) + 11, 2), UL((o) + 14, 3)

static const struct tdma_slot slots_h4[] = {
	BCN(0, 3), BLK_H4(0), DL(19, 3), BLK_H4(19), FXU(38, 5, 1, 6),
};

/*
 * Plan T (bulk, one train per frame): plan H's first half (0-2 DL, UL0 5-6,
 * UL1 8-9), then a train of three 8 ss long bursts (700 B at MCS 4) 2 ss
 * apart, 13-20, 23-30, 33-40, all for one PT in one direction, announced by
 * the DL burst at 0. On the DKs a long TX goes out 290 us after the end of
 * the one before, and a long packet is received 2 ss after another one, in
 * one RX op or in two (`tdma train`, docs/phy-timing.md). 41-47: the
 * 5 ss a received long burst needs before the receiver's next op, and the
 * beacon. 3 x 700 B per 10 ms one way; the guaranteed slots come once per
 * frame (small packets wait up to ~12 ms, or ride the train going their
 * way). The positions are plan H's, so a cluster can switch between H and T.
 */
static const struct tdma_slot slots_t[] = {
	BCN(0, 3), UL(5, 0), UL(8, 1), FX(13, 8), FX(23, 8), FX(33, 8),
};

/*
 * Plan T4 (bulk with 2-4 PTs, plan_multi): H4's block with a 4 ss DL burst
 * (0-3, 311 B: beacon, grant and three 64 B SDUs; with 3 ss the third PT's
 * small packet waited a frame), UL 6/9/12/15, then a train of 7 + 7 + 5 ss
 * (604 + 604 + 407 B at MCS 4), 20-26, 29-35, 38-42, for one PT in one
 * direction, announced by the DL burst at 0: 3 ss after the FT's UL-run RX
 * (TDMA_RX_TO_FLEX_SS), 2 ss apart, 5 ss before the beacon (a received long
 * burst). Every burst of the train is long: after a received long burst only
 * another long one may follow 2 ss later. Every PT keeps its UL slot once per
 * frame (no starvation, association requests in free positions); small
 * packets wait up to a frame unless they ride the train. 4 positions, as H4.
 */
static const struct tdma_slot slots_t4[] = {
	BCN(0, 4), UL(6, 0), UL(9, 1), UL(12, 2), UL(15, 3), FX(20, 7), FX(29, 7), FX(38, 5),
};

/*
 * Plan BQ (idle / small packets, 2 PTs): plan H's guaranteed block (DL 0-2,
 * UL0 5-6, UL1 8-9) every 2.5 ms instead of every 5 ms, no FLEX region. The
 * format of the hybrid plans (status records, 16-bit acks, grant room in the
 * DL bursts, the same PDU sizes), so a cluster switches between BQ and H
 * (which starts with the same three slots) without changing its links: the
 * FT runs BQ while nothing needs a long burst (docs/mac-design.md, "Plan BQ").
 */
#define QUARTER_BQ(o) DL((o), 3), UL((o) + 5, 0), UL((o) + 8, 1)

static const struct tdma_slot slots_bq[] = {
	BCN(0, 3), UL(5, 0), UL(8, 1), QUARTER_BQ(12), QUARTER_BQ(24), QUARTER_BQ(36),
};

/*
 * Plan HG (a relay's child cluster, layout R1 of docs/mac-design.md "Relays"):
 * plan H's guaranteed slots and no FLEX region, in the hybrid format (status
 * records, 16-bit acks, H's PDU sizes).  (downstream pipelining):
 * in each of its two 12-subslot blocks the UL slots come first and the DL
 * burst last (block 17-28: UL0 17-18, UL1 20-21, DL 24-26; block 41-52: UL0
 * 41-42, UL1 44-45, the beacon burst 0-2), so what the parent's DL burst
 * brought goes on in the child DL burst of the same block pair (16 ss later
 * under a root, was 9: +5 ms per hop) and what a child sent goes up in the
 * relay's next UL slot (both child positions). The child frame starts
 * TDMA_RELAY_ROOT_OFFSET_SS after a root's frame (TDMA_RELAY_OFFSET_SS after
 * another relay cluster's), so its blocks are the parent's O blocks: the relay
 * is in its parent's cluster in the E blocks, in its own in the O blocks
 * (tdma_relay_plan_check()).
 */
static const struct tdma_slot slots_hg[] = {
	BCN(0, 3), UL(17, 0), UL(20, 1), DL(24, 3), UL(41, 0), UL(44, 1),
};

/*
 * Plan HGX : a relay's child cluster with one child while the relay
 * sits in position 1 of a root's plan H / T / BQ (UL 8 / 32). DL first: the
 * beacon burst 0-2 and DL 24-26, the child's UL 5-6 / 29-30; the frame starts
 * TDMA_RELAY_HGX_OFFSET_SS (15) after the root's. Root subslots: the child DL
 * at 15 / 39 (15 after the root's DL: what it brought goes on in the same
 * block), the child UL at 20 / 44 (12 before the relay's UL at 32 / 8). The
 * relay: RX 0-2, TX 8-9, TX 15-17, RX 20-21, RX 24-26, TX 32-33, TX 39-41,
 * RX 44-45, 2 ss or more apart; its blocks are the root's O blocks (origin
 * TDMA_RELAY_HGX_ORIGIN_SS = root 12). HG gives the same relay 20 / 17 ss up
 * and 19 down; a second child does not fit (TDMA_PLAN_F_OPEN: it asks in the
 * open frames, the relay goes to HG).
 */
static const struct tdma_slot slots_hgx[] = {
	BCN(0, 3),
	UL(5, 0),
	DL(24, 3),
	UL(29, 0),
};

/*
 * Plan T2 (bulk, one PT, the whole frame): the beacon (0-2, also the DL slot
 * of every PT: acks and small SDUs), then four 8 ss regions 2 ss apart. The
 * beacon of the frame before gives them to one PT as a pattern: all UL (4 x
 * 700 B) or DL first and UL after. 5-12, 15-22, 25-32, 35-42 end 5 ss before
 * the next beacon (a received long burst, FT or PT). A DL burst right before
 * an UL one ends 5 ss before it (the PT's TX after a received long burst), so
 * it is 5 ss. The frame has no guaranteed UL slot: the FT uses T2 only while
 * one PT is active (docs/mac-design.md, "Plans T2, T2D").
 */
static const struct tdma_slot slots_t2[] = {
	BCN(0, 3), FX(5, 8), FX(15, 8), FX(25, 8), FX(35, 8),
};

static const int8_t pat_t2[][TDMA_PAT_REGIONS] = {
	[TDMA_T2_U4] = {-8, -8, -8, -8, 0},
	[TDMA_T2_D1U3] = {5, -8, -8, -8, 0},
	[TDMA_T2_D2U2] = {8, 5, -8, -8, 0},
	[TDMA_T2_D3U1] = {8, 8, 5, -8, 0},
};

/*
 * Plan T2D (bulk DL, one PT): DL needs an UL burst per frame for the acks,
 * and a PT receives a short burst only 5 ss after a long one, but a long one
 * 2 ss after it. So the beacon burst is long too (0-6, 604 B: the beacon and
 * DL data), then DL 9-16, 19-26, 29-36 and the PT's UL 42-43 (5 ss after the
 * last long burst it received). 4 ss from that UL burst to the FT's long
 * beacon burst: with 3 ss (and an 8 ss beacon burst at 0-7) ~3 % of the
 * beacon bursts failed on the DKs (0x1005). 604 + 3 x 700 B DL per frame; T2
 * with all DL would end its DL bursts 5 ss before the beacon (a short
 * packet) and needs the UL burst too.
 */
static const struct tdma_slot slots_t2d[] = {
	BCN(0, 7), FX(9, 8), FX(19, 8), FX(29, 8), FX(42, 2),
};

static const int8_t pat_t2d[][TDMA_PAT_REGIONS] = {
	[TDMA_T2D_D3U] = {8, 8, 8, -2, 0},
};

int8_t tdma_pat_burst(const struct tdma_plan *plan, uint8_t pattern, uint8_t fi)
{
	return plan && plan->pat && pattern < plan->n_pat && fi < TDMA_PAT_REGIONS
		       ? plan->pat[pattern][fi]
		       : 0;
}

#define N(a) ((uint8_t)(sizeof(a) / sizeof((a)[0])))

static const struct tdma_plan plans[] = {
	{TDMA_PLAN_A, 4, N(slots_a), 3, slots_a, "A", 0, NULL, 0},
	{TDMA_PLAN_1X10, 10, N(slots_1x10), 3, slots_1x10, "1x10", 0, NULL, 0},
	{TDMA_PLAN_B, 2, N(slots_b), 4, slots_b, "B", 0, NULL, 0},
	{TDMA_PLAN_H, 2, N(slots_h), 4, slots_h, "H", 0, NULL, 0},
	{TDMA_PLAN_H4, 4, N(slots_h4), 4, slots_h4, "H4", 0, NULL, 0},
	{TDMA_PLAN_T, 2, N(slots_t), 4, slots_t, "T", 0, NULL, 0},
	{TDMA_PLAN_T2, 2, N(slots_t2), 4, slots_t2, "T2", TDMA_PLAN_F_PATTERN, pat_t2, N(pat_t2)},
	{TDMA_PLAN_BQ, 2, N(slots_bq), 4, slots_bq, "BQ", TDMA_PLAN_F_HYBRID, NULL, 0},
	{TDMA_PLAN_T2D, 2, N(slots_t2d), 4, slots_t2d, "T2D", TDMA_PLAN_F_PATTERN, pat_t2d,
	 N(pat_t2d)},
	{TDMA_PLAN_T4, 4, N(slots_t4), 4, slots_t4, "T4", 0, NULL, 0},
	{TDMA_PLAN_HG, 2, N(slots_hg), 4, slots_hg, "HG", TDMA_PLAN_F_HYBRID, NULL, 0},
	{TDMA_PLAN_HGX, 1, N(slots_hgx), 4, slots_hgx, "HGX", TDMA_PLAN_F_HYBRID | TDMA_PLAN_F_OPEN,
	 NULL, 0},
};

const struct tdma_plan *tdma_plan_get(uint8_t id)
{
	for (size_t i = 0; i < sizeof(plans) / sizeof(plans[0]); i++) {
		if (plans[i].id == id && plans[i].n_positions <= TDMA_MAX_POSITIONS) {
			return &plans[i];
		}
	}
	return NULL;
}

/*
 * Transport block sizes in bytes, physical header type 2, 1..16 subslots
 * (Nordic's table, ETSI TS 103 636-3 5.3; 1..4 ss measured on air). 0: above
 * the modem's largest transport block, 5600 bits.
 */
static const uint16_t tbs_table[5][TDMA_MAX_BURST_SS] = {
	{0, 17, 33, 50, 67, 83, 99, 115, 133, 149, 165, 181, 197, 213, 233, 249},
	{4, 37, 69, 103, 137, 169, 201, 233, 263, 295, 327, 359, 391, 423, 463, 495},
	{7, 57, 107, 157, 205, 253, 295, 343, 399, 447, 495, 540, 596, 644, 692, 0},
	{11, 77, 141, 209, 271, 335, 399, 463, 532, 596, 660, 0, 0, 0, 0, 0},
	{18, 117, 217, 311, 407, 503, 604, 700, 0, 0, 0, 0, 0, 0, 0, 0},
};

uint16_t tdma_tbs(uint8_t mcs, uint8_t subslots)
{
	if (mcs > 4 || subslots == 0 || subslots > TDMA_MAX_BURST_SS) {
		return 0;
	}
	return tbs_table[mcs][subslots - 1];
}

uint8_t tdma_max_burst(uint8_t mcs, uint8_t max_ss)
{
	uint8_t best = 0;

	for (uint8_t n = 1; n <= max_ss && n <= TDMA_MAX_BURST_SS; n++) {
		uint16_t t = tdma_tbs(mcs, n);

		if (t && t <= TDMA_PKT_MAX) {
			best = n;
		}
	}
	return best;
}

bool tdma_plan_has_train(const struct tdma_plan *plan)
{
	for (uint8_t i = 1; plan && i < plan->n_slots; i++) {
		if (plan->slots[i].use == TDMA_SLOT_FLEX &&
		    plan->slots[i - 1].use == TDMA_SLOT_FLEX) {
			return true;
		}
	}
	return false;
}

bool tdma_plan_compatible(const struct tdma_plan *a, const struct tdma_plan *b)
{
	if (!a || !b || a->n_positions != b->n_positions || a->mcs != b->mcs) {
		return false;
	}
	for (uint8_t i = 0; i < a->n_slots && i < b->n_slots; i++) {
		const struct tdma_slot *x = &a->slots[i], *y = &b->slots[i];

		if (x->use != y->use || x->subslot != y->subslot) {
			return false;
		}
		if (x->use == TDMA_SLOT_FLEX) {
			return true;
		}
		if (x->len != y->len || x->pos != y->pos) {
			return false;
		}
	}
	return false;
}

bool tdma_plan_has_flex(const struct tdma_plan *plan)
{
	if (plan && (plan->flags & TDMA_PLAN_F_HYBRID)) {
		return true;
	}
	for (uint8_t i = 0; plan && i < plan->n_slots; i++) {
		if (plan->slots[i].use == TDMA_SLOT_FLEX) {
			return true;
		}
	}
	return false;
}

/* SNR (dB) a link needs before it moves up to MCS m: about 3 dB above the 10 % BLER point. */
static const int8_t mcs_up_db[5] = {-128, 6, 9, 12, 16};

uint8_t tdma_mcs_select(uint8_t cur, int16_t snr_q2, uint8_t max)
{
	uint8_t target = 0;

	max = max > 4 ? 4 : max;
	cur = cur > max ? max : cur;
	for (uint8_t m = 1; m <= max; m++) {
		if (snr_q2 >= mcs_up_db[m] * 4) {
			target = m;
		}
	}
	if (target >= cur) {
		return target;
	}
	/* hysteresis: keep cur until the SNR is clearly below its threshold */
	return snr_q2 < mcs_up_db[cur] * 4 - TDMA_MCS_HYST_Q2 ? target : cur;
}

static bool is_dl(const struct tdma_slot *s)
{
	return s->use == TDMA_SLOT_BEACON || s->use == TDMA_SLOT_DL;
}

static bool is_ul(const struct tdma_slot *s)
{
	return s->use == TDMA_SLOT_UL || s->use == TDMA_SLOT_CONTENTION;
}

/* Longest UL long burst of a FLEX region. */
static unsigned int flex_ul_len(const struct tdma_slot *s)
{
	return s->ul_len ? s->ul_len : s->len;
}

/* Idle subslots going forward (cyclically) from subslot a to subslot b. */
static unsigned int fwd(unsigned int a, unsigned int b)
{
	return (b + TDMA_SUBSLOTS_PER_FRAME - a) % TDMA_SUBSLOTS_PER_FRAME;
}

/* Two ops of one radio on different carriers (hopping) need <= this; the plans' gap rule must cover
 * it. */
typedef char tdma_retune_gap_check[(TDMA_MIN_OP_GAP_SS * TDMA_SUBSLOT_TICKS >=
				    TDMA_US_TO_TICKS(TDMA_PHY_GAP_MAX_US + TDMA_RETUNE_EXTRA_US))
					   ? 1
					   : -1];

/*
 * One device's ops in a frame, in order: [s, e) in subslots, TX or RX, long
 * (TDMA_LRX_MIN_SS or more). Checks every op against the next (cyclic, the
 * next frame's first op 48 ss later): TDMA_MIN_OP_GAP_SS; on the FT an RX
 * before a long TX TDMA_RX_TO_FLEX_SS (measured after the UL run); a received
 * long burst TDMA_LRX_TO_TX_SS before anything but the RX of another long
 * burst.
 */
struct tl_op {
	uint8_t s, e;
	bool tx, lng;
};

static int tl_check(const struct tl_op *o, unsigned int n, bool ft)
{
	for (unsigned int i = 0; i < n && n > 1; i++) {
		const struct tl_op *a = &o[i], *b = &o[(i + 1) % n];
		unsigned int bs = b->s + (i + 1 == n ? TDMA_SUBSLOTS_PER_FRAME : 0u);
		unsigned int need = TDMA_MIN_OP_GAP_SS;

		if (bs < a->e) {
			return -EINVAL;
		}
		if (ft && !a->tx && b->tx && b->lng && need < TDMA_RX_TO_FLEX_SS) {
			need = TDMA_RX_TO_FLEX_SS;
		}
		if (!a->tx && a->lng && (b->tx || !b->lng)) {
			need = TDMA_LRX_TO_TX_SS;
		}
		if (bs - a->e < need) {
			return -EINVAL;
		}
	}
	return 0;
}

/*
 * A pattern plan: beacon (FT TX, PT RX) and FLEX regions only; every
 * pattern's bursts inside their regions, DL before UL, and the FT's and the
 * PT's op sequence within the PHY's gaps. An UL burst after the first one of
 * a frame is full length or not sent (2 ss after a received long burst the
 * FT takes only another long one); a DL burst is full length.
 */
static int validate_patterns(const struct tdma_plan *plan)
{
	struct tl_op ft[TDMA_PAT_REGIONS + 1], pt[TDMA_PAT_REGIONS + 1];
	uint8_t nfx = 0, fs[TDMA_PAT_REGIONS];

	if (plan->slots[0].use != TDMA_SLOT_BEACON || plan->slots[0].subslot != 0 || !plan->pat ||
	    plan->n_pat == 0 || plan->n_pat > TDMA_PAT_MAX) {
		return -EINVAL;
	}
	for (uint8_t i = 1; i < plan->n_slots; i++) {
		const struct tdma_slot *s = &plan->slots[i];

		if (s->use != TDMA_SLOT_FLEX || nfx >= TDMA_PAT_REGIONS || s->ul_early ||
		    s->ul_len || s->subslot < plan->slots[i - 1].subslot + plan->slots[i - 1].len ||
		    s->subslot + s->len > TDMA_SUBSLOTS_PER_FRAME) {
			return -EINVAL;
		}
		fs[nfx++] = i;
	}
	for (uint8_t p = 0; p < plan->n_pat; p++) {
		unsigned int n = 1;
		bool ul_seen = false;
		bool bl = plan->slots[0].len >= TDMA_LRX_MIN_SS;

		ft[0] = (struct tl_op){0, plan->slots[0].len, true, bl};
		pt[0] = (struct tl_op){0, plan->slots[0].len, false, bl};
		for (uint8_t k = nfx; k < TDMA_PAT_REGIONS; k++) {
			if (plan->pat[p][k]) {
				return -EINVAL; /* a burst without a region */
			}
		}
		for (uint8_t k = 0; k < nfx; k++) {
			const struct tdma_slot *s = &plan->slots[fs[k]];
			int8_t b = plan->pat[p][k];
			uint8_t len = (uint8_t)(b < 0 ? -b : b);

			if (!b) {
				continue;
			}
			if (len > s->len || len < 2 || (b > 0 && ul_seen)) {
				return -EINVAL;
			}
			ul_seen |= b < 0;
			ft[n] = (struct tl_op){s->subslot, (uint8_t)(s->subslot + len), b > 0,
					       len >= TDMA_LRX_MIN_SS};
			pt[n] = (struct tl_op){s->subslot, (uint8_t)(s->subslot + len), b < 0,
					       len >= TDMA_LRX_MIN_SS};
			n++;
		}
		if (!ul_seen || tl_check(ft, n, true) || tl_check(pt, n, false)) {
			return -EINVAL; /* the PT needs an UL burst per frame (acks) */
		}
	}
	return 0;
}

int tdma_plan_validate(const struct tdma_plan *plan)
{
	unsigned int end = 0, n_beacon = 0;
	uint32_t has_ul = 0;
	/* FT op list: DL bursts and UL runs as [start, end) */
	uint8_t op_s[TDMA_SUBSLOTS_PER_FRAME], op_e[TDMA_SUBSLOTS_PER_FRAME];
	unsigned int n_ops = 0;

	if (!plan || plan->n_slots == 0 || plan->n_positions == 0 ||
	    plan->n_positions > TDMA_MAX_POSITIONS || plan->n_slots > TDMA_SUBSLOTS_PER_FRAME) {
		return -EINVAL;
	}
	if (plan->slots[0].use != TDMA_SLOT_BEACON || plan->slots[0].subslot != 0) {
		return -EINVAL;
	}
	if (plan->flags & TDMA_PLAN_F_PATTERN) {
		return tdma_tbs(plan->mcs, plan->slots[0].len) <
				       TDMA_REC_HDR_LEN + TDMA_BEACON_FIXED_LEN +
					       plan->n_positions * TDMA_BEACON_ENTRY_LEN +
					       TDMA_MIC_RESERVE + TDMA_GRANT_REC_LEN +
					       TDMA_GRANT_ENTRY_LEN
			       ? -EINVAL
			       : validate_patterns(plan);
	}
	bool flex = tdma_plan_has_flex(plan);
	unsigned int n_flex = 0;

	for (uint8_t i = 0; i < plan->n_slots; i++) {
		const struct tdma_slot *s = &plan->slots[i];
		bool run_cont = i > 0 && is_ul(s) && is_ul(&plan->slots[i - 1]);

		if (s->len == 0 || s->subslot < end ||
		    s->subslot + s->len > TDMA_SUBSLOTS_PER_FRAME || s->use > TDMA_SLOT_FLEX ||
		    s->len > TDMA_MAX_BURST_SS) {
			return -EINVAL;
		}
		if (is_dl(s) && tdma_tbs(plan->mcs, s->len) <
					TDMA_REC_HDR_LEN + TDMA_BEACON_FIXED_LEN +
						plan->n_positions * TDMA_BEACON_ENTRY_LEN +
						TDMA_MIC_RESERVE +
						(flex ? TDMA_GRANT_REC_LEN : 0)) {
			return -EINVAL; /* the beacon (+ grant) must fit any DL burst */
		}
		if (s->use == TDMA_SLOT_FLEX) {
			/* announced in the DL burst before it, in the same frame */
			if (++n_flex > TDMA_FLEX_SLOTS || i == 0 || s->len < 2) {
				return -EINVAL;
			}
			int k = i - 1;
			/*
			 * A FLEX region right after another one continues its train:
			 * same DL burst, same PT and direction, so 2 ss between them
			 * are enough (long TX -> TX, received long -> RX). No early
			 * UL extent inside a train.
			 */
			bool cont = plan->slots[k].use == TDMA_SLOT_FLEX;

			if (cont && (s->ul_early || s->ul_len || plan->slots[k].ul_len ||
				     s->subslot < end + TDMA_MIN_OP_GAP_SS)) {
				return -EINVAL;
			}
			while (k > 0 && !is_dl(&plan->slots[k])) {
				if (plan->slots[k].use == TDMA_SLOT_FLEX &&
				    plan->slots[k + 1].use != TDMA_SLOT_FLEX) {
					return -EINVAL; /* no DL burst of its own */
				}
				k--;
			}
			/* the PTs must have decoded the grant before they commit the region */
			if ((uint32_t)(s->subslot - plan->slots[k].subslot - plan->slots[k].len) *
				    TDMA_SUBSLOT_TICKS <
			    TDMA_FLEX_COMMIT_LEAD_TICKS + TDMA_RX_PROC_TICKS) {
				return -EINVAL;
			}
			/*
			 * An UL long burst starts up to ul_early before the region: its
			 * PT commits it on the region's lead, which must still leave a
			 * normal commit lead; RX -> RX after the op before it.
			 */
			unsigned int ue = s->ul_early, ul = flex_ul_len(s);

			if (ue > TDMA_FLEX_UL_EARLY_MAX || ue > s->subslot || ul < 2 ||
			    TDMA_FLEX_COMMIT_LEAD_TICKS <
				    ue * TDMA_SUBSLOT_TICKS + TDMA_COMMIT_LEAD_TICKS ||
			    s->subslot - ue < end + TDMA_MIN_OP_GAP_SS) {
				return -EINVAL;
			}
			/* FT: RX of the UL run -> long TX (measured) */
			if (is_ul(&plan->slots[i - 1]) &&
			    s->subslot - plan->slots[i - 1].subslot - plan->slots[i - 1].len <
				    TDMA_RX_TO_FLEX_SS) {
				return -EINVAL;
			}
			/* FT: long DL TX -> next DL TX; received long UL burst -> next DL TX */
			for (uint8_t j = (uint8_t)(i + 1); j <= plan->n_slots; j++) {
				const struct tdma_slot *d = &plan->slots[j % plan->n_slots];

				if (is_dl(d)) {
					/* the DL extent may carry an UL burst too (granted just in
					 * time) */
					if (fwd((s->subslot + s->len) % TDMA_SUBSLOTS_PER_FRAME,
						d->subslot) < TDMA_LRX_TO_TX_SS ||
					    fwd((s->subslot - ue + ul) % TDMA_SUBSLOTS_PER_FRAME,
						d->subslot) < TDMA_LRX_TO_TX_SS) {
						return -EINVAL;
					}
					break;
				}
			}
			/* PT: received long DL burst -> its next op (TX or RX) */
			for (uint8_t j = 0; j < plan->n_slots; j++) {
				const struct tdma_slot *u = &plan->slots[j];

				if ((is_ul(u) || is_dl(u)) &&
				    fwd((s->subslot + s->len) % TDMA_SUBSLOTS_PER_FRAME,
					u->subslot) < TDMA_LRX_TO_TX_SS) {
					return -EINVAL;
				}
			}
		}
		/* PT: a received long DL burst -> its next op (TX or RX) */
		if (is_dl(s) && s->len >= TDMA_LRX_MIN_SS) {
			for (uint8_t j = 0; j < plan->n_slots; j++) {
				const struct tdma_slot *u = &plan->slots[j];

				if (j != i && (is_ul(u) || is_dl(u) || u->use == TDMA_SLOT_FLEX) &&
				    fwd((s->subslot + s->len) % TDMA_SUBSLOTS_PER_FRAME,
					u->subslot) < TDMA_LRX_TO_TX_SS) {
					return -EINVAL;
				}
			}
		}
		n_beacon += s->use == TDMA_SLOT_BEACON;
		if (s->use == TDMA_SLOT_UL) {
			if (s->pos >= plan->n_positions) {
				return -EINVAL;
			}
			has_ul |= 1u << s->pos;
		}
		if (run_cont) {
			/* next UL burst in the same FT RX: other transmitter */
			if (s->subslot - end < TDMA_UL_GUARD_SS) {
				return -EINVAL;
			}
			op_e[n_ops - 1] = (uint8_t)(s->subslot + s->len);
		} else {
			op_s[n_ops] = s->subslot;
			op_e[n_ops] = (uint8_t)(s->subslot + s->len);
			n_ops++;
		}
		end = s->subslot + s->len;
	}
	if (n_beacon != 1 || has_ul != (1u << plan->n_positions) - 1) {
		return -EINVAL;
	}
	/* the scheduler commits in table order: commit times must not go backwards */
	for (uint8_t i = 1; i < plan->n_slots; i++) {
		const struct tdma_slot *a = &plan->slots[i - 1], *b = &plan->slots[i];
		uint64_t ca = (uint64_t)a->subslot * TDMA_SUBSLOT_TICKS +
			      TDMA_FLEX_COMMIT_LEAD_TICKS -
			      (a->use == TDMA_SLOT_FLEX ? TDMA_FLEX_COMMIT_LEAD_TICKS
							: TDMA_COMMIT_LEAD_TICKS);
		uint64_t cb = (uint64_t)b->subslot * TDMA_SUBSLOT_TICKS +
			      TDMA_FLEX_COMMIT_LEAD_TICKS -
			      (b->use == TDMA_SLOT_FLEX ? TDMA_FLEX_COMMIT_LEAD_TICKS
							: TDMA_COMMIT_LEAD_TICKS);

		if (cb < ca) {
			return -EINVAL;
		}
	}
	/* FT: consecutive own ops (cyclic) */
	for (unsigned int i = 0; i < n_ops; i++) {
		unsigned int j = (i + 1) % n_ops;

		if (n_ops > 1 &&
		    fwd(op_e[i] % TDMA_SUBSLOTS_PER_FRAME, op_s[j]) < TDMA_MIN_OP_GAP_SS) {
			return -EINVAL;
		}
	}
	/*
	 * PT: every UL/contention TX against every DL RX, both directions. A
	 * FLEX region can be TX or RX for any PT: it must keep the gap to every
	 * other slot.
	 */
	for (uint8_t i = 0; i < plan->n_slots; i++) {
		const struct tdma_slot *u = &plan->slots[i];

		if (is_dl(u)) {
			continue;
		}
		for (uint8_t k = 0; k < plan->n_slots; k++) {
			const struct tdma_slot *d = &plan->slots[k];

			if (k == i ||
			    (!is_dl(d) && u->use != TDMA_SLOT_FLEX && d->use != TDMA_SLOT_FLEX)) {
				continue;
			}
			/* both extents of a FLEX region (DL and UL long burst) */
			for (unsigned int xu = 0; xu < (u->use == TDMA_SLOT_FLEX ? 2u : 1u); xu++) {
				for (unsigned int xd = 0; xd < (d->use == TDMA_SLOT_FLEX ? 2u : 1u);
				     xd++) {
					unsigned int us = u->subslot - (xu ? u->ul_early : 0);
					unsigned int ue = us + (xu ? flex_ul_len(u) : u->len);
					unsigned int ds = d->subslot - (xd ? d->ul_early : 0);
					unsigned int de = ds + (xd ? flex_ul_len(d) : d->len);

					if (fwd(de % TDMA_SUBSLOTS_PER_FRAME, us) <
						    TDMA_MIN_OP_GAP_SS ||
					    fwd(ue % TDMA_SUBSLOTS_PER_FRAME, ds) <
						    TDMA_MIN_OP_GAP_SS) {
						return -EINVAL;
					}
				}
			}
		}
	}
	return 0;
}

uint32_t tdma_plan_max_gap_ticks(const struct tdma_plan *plan, uint8_t pos, uint8_t use)
{
	int first = -1, prev = -1;
	unsigned int gap, max = 0;

	for (uint8_t i = 0; i < plan->n_slots; i++) {
		const struct tdma_slot *s = &plan->slots[i];
		bool match = use == TDMA_SLOT_UL
				     ? (s->use == TDMA_SLOT_UL && s->pos == pos)
				     : (use == s->use || (use != TDMA_SLOT_CONTENTION && is_dl(s)));

		if (!match) {
			continue;
		}
		if (prev >= 0) {
			gap = s->subslot - prev;
			max = gap > max ? gap : max;
		} else {
			first = s->subslot;
		}
		prev = s->subslot;
	}
	if (first < 0) {
		return 0;
	}
	gap = TDMA_SUBSLOTS_PER_FRAME - prev + first;
	max = gap > max ? gap : max;
	return max * TDMA_SUBSLOT_TICKS;
}

/* ---- relays: the merged op sequence ------------------------------------------- */

#define RL_OPS 24

struct rl_op {
	uint8_t s, e; /* subslots of the parent's frame, e may pass 48 */
	bool tx, lng, down;
};

static unsigned int rl_add(struct rl_op *o, unsigned int n, unsigned int s, unsigned int len,
			   bool tx, bool down)
{
	if (n < RL_OPS) {
		o[n] = (struct rl_op){(uint8_t)s, (uint8_t)(s + len), tx, len >= TDMA_LRX_MIN_SS,
				      down};
		n++;
	}
	return n;
}

/*
 * Is [s, e) (subslots of the parent's frame, s < 48) inside one block of the
 * instance's parity (E: up, O: down)? The parent plan's blocks start at
 * `origin` (0 for a root's plan, TDMA_RELAY_BLOCK_ORIGIN_SS for HG).
 */
static bool rl_in_blocks(const struct rl_op *o, unsigned int origin)
{
	unsigned int s = (o->s + TDMA_SUBSLOTS_PER_FRAME - origin) % TDMA_SUBSLOTS_PER_FRAME;
	unsigned int b = s / TDMA_RELAY_BLOCK_SS;

	return (b & 1u) == (o->down ? 1u : 0u) &&
	       s + (o->e - o->s) <= (b + 1u) * TDMA_RELAY_BLOCK_SS;
}

uint8_t tdma_relay_offset_ss(const struct tdma_plan *parent, const struct tdma_plan *child)
{
	if (child && child->id == TDMA_PLAN_HGX) {
		return TDMA_RELAY_HGX_OFFSET_SS;
	}
	return parent && parent->id == TDMA_PLAN_HG ? TDMA_RELAY_OFFSET_SS
						    : TDMA_RELAY_ROOT_OFFSET_SS;
}

uint8_t tdma_relay_origin_ss(const struct tdma_plan *child)
{
	return child && child->id == TDMA_PLAN_HGX ? TDMA_RELAY_HGX_ORIGIN_SS
						   : TDMA_RELAY_BLOCK_ORIGIN_SS;
}

int tdma_relay_plan_check(const struct tdma_plan *pp, uint8_t pos, const struct tdma_plan *cp,
			  struct tdma_relay_check *out)
{
	struct rl_op o[RL_OPS];
	struct tl_op t[RL_OPS];
	unsigned int n = 0, min_gap = 0xff, held = 0;
	const unsigned int off = tdma_relay_offset_ss(pp, cp);
	const unsigned int origin = pp && (pp->id == TDMA_PLAN_HG || pp->id == TDMA_PLAN_HGX)
					    ? tdma_relay_origin_ss(pp)
					    : 0u;

	if (!pp || !cp || pos >= pp->n_positions || (pp->flags & TDMA_PLAN_F_PATTERN) ||
	    tdma_plan_validate(pp) || tdma_plan_validate(cp) ||
	    (cp->id == TDMA_PLAN_HGX && (pp->id == TDMA_PLAN_HG || pp->id == TDMA_PLAN_HGX)) ||
	    pp->id == TDMA_PLAN_HGX) {
		return -EINVAL; /* HGX only under a root; nothing relays under HGX */
	}
	/* the relay as a PT of the parent: every DL burst, its own UL slot (never a FLEX region) */
	for (uint8_t i = 0; i < pp->n_slots; i++) {
		const struct tdma_slot *s = &pp->slots[i];

		if (is_dl(s)) {
			n = rl_add(o, n, s->subslot, s->len, false, false);
		} else if (s->use == TDMA_SLOT_UL && s->pos == pos) {
			n = rl_add(o, n, s->subslot, s->len, true, false);
		}
	}
	/* the relay as the child's FT: its DL bursts and one RX per UL run, tdma_relay_offset_ss()
	 * later */
	for (uint8_t i = 0; i < cp->n_slots; i++) {
		const struct tdma_slot *s = &cp->slots[i];
		unsigned int st = (s->subslot + off) % TDMA_SUBSLOTS_PER_FRAME;

		if (s->use == TDMA_SLOT_FLEX) {
			return -EINVAL; /* the child plan of R1 has none */
		}
		if (is_dl(s)) {
			n = rl_add(o, n, st, s->len, true, true);
		} else if (is_ul(s)) {
			uint8_t last = i;

			if (i > 0 && is_ul(&cp->slots[i - 1])) {
				continue;
			}
			while (last + 1 < cp->n_slots && is_ul(&cp->slots[last + 1])) {
				last++;
			}
			n = rl_add(o, n, st,
				   cp->slots[last].subslot + cp->slots[last].len - s->subslot,
				   false, true);
			o[n - 1].lng = false; /* one RX window over short UL bursts */
		}
	}
	/* in start order */
	for (unsigned int i = 1; i < n; i++) {
		for (unsigned int k = i; k > 0 && o[k].s < o[k - 1].s; k--) {
			struct rl_op x = o[k];

			o[k] = o[k - 1];
			o[k - 1] = x;
		}
	}
	for (unsigned int i = 0; i < n; i++) {
		const struct rl_op *a = &o[i], *b = &o[(i + 1) % n];
		unsigned int bs = b->s + (i + 1 == n ? TDMA_SUBSLOTS_PER_FRAME : 0u);

		if (!rl_in_blocks(a, origin) || bs < a->e) {
			return -EINVAL;
		}
		min_gap = bs - a->e < min_gap ? bs - a->e : min_gap;
		t[i] = (struct tl_op){a->s, a->e, a->tx, a->lng};
	}
	if (n < 2 || tl_check(t, n, true)) {
		return -EINVAL;
	}
	/* call-time check: op k's PHY call in op j's quiet window */
	for (unsigned int k = 0; out && out->quiet > out->late && k < n; k++) {
		const struct rl_op *a = &o[k];
		/*
		 * the beacon burst (child subslot 0) has no trim; UL TX of the PT ul_trim; DL TX
		 * dl_trim; the parent's DL RX before the child's UL run (tdma_mac.c
		 * relay_rx_lead())
		 */
		bool beacon = a->down && a->s == off;
		uint32_t lead = !a->tx ? (a->down ? TDMA_RELAY_CHILD_RX_LEAD_TICKS
						  : TDMA_RELAY_RX_LEAD_TICKS(pp))
				       : TDMA_COMMIT_LEAD_TICKS + out->seal -
						 (beacon    ? 0
						  : a->down ? out->dl_trim
							    : out->ul_trim);
		int64_t call = (int64_t)a->s * TDMA_SUBSLOT_TICKS - (int64_t)lead;

		for (unsigned int j = 0; j < n; j++) {
			for (int w = -1; w <= 1; w++) {
				int64_t sj = (int64_t)o[j].s * TDMA_SUBSLOT_TICKS +
					     (int64_t)w * TDMA_FRAME_TICKS;

				if (j != k && call >= sj - (int64_t)out->quiet &&
				    call < sj - (int64_t)out->late) {
					held++;
				}
			}
		}
	}
	if (out) {
		out->n_ops = (uint8_t)n;
		out->min_gap_ss = (uint8_t)min_gap;
		out->held_calls = (uint8_t)held;
	}
	return 0;
}
