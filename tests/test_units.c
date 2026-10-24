/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* Unit tests: PDU codec, plans, the per-peer link (ARQ) in isolation. */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../src/tdma_internal.h"
#include <cappella/tdma_pdu.h>
#include "test.h"

/* ---- PDU codec ----------------------------------------------------------------- */

void test_pdu(void)
{
	uint8_t buf[TDMA_PKT_MAX + 32];
	int n;

	/* physical header */
	struct tdma_phy_hdr h = {.subslots = 2,
				 .short_nwid = 0x5a,
				 .tx_short = 0x3402,
				 .rx_short = 0xffff,
				 .tx_power = 7,
				 .mcs = 2};
	struct tdma_phy_hdr h2;

	n = tdma_phy_hdr_encode(&h, buf, sizeof(buf));
	CHECK(n == TDMA_PHY_HDR_LEN, "n=%d", n);
	CHECK(tdma_phy_hdr_decode(buf, (size_t)n, &h2) == 0, "decode");
	CHECK(h2.subslots == 2 && h2.short_nwid == 0x5a && h2.tx_short == 0x3402 &&
		      h2.rx_short == 0xffff && h2.tx_power == 7 && h2.mcs == 2,
	      "phy hdr round trip");
	CHECK(tdma_phy_hdr_decode(buf, 9, &h2) == -EINVAL, "short phy hdr");
	CHECK(tdma_phy_hdr_decode(buf, 11, &h2) == -EINVAL, "long phy hdr");
	buf[0] = 0x10;
	CHECK(tdma_phy_hdr_decode(buf, 10, &h2) == -ENOTSUP, "foreign header format");
	h.subslots = 0;
	CHECK(tdma_phy_hdr_encode(&h, buf, sizeof(buf)) < 0, "0 subslots");

	/* beacon */
	struct tdma_beacon b = {.flags = TDMA_F_FULL,
				.network_id = 0xdeadbe01,
				.ft_rd_id = 0x10123401,
				.frame = 0x01020304,
				.plan_id = 1,
				.mcs = 3,
				.roster_ver = 9,
				.n = TDMA_MAX_POSITIONS};
	struct tdma_beacon b2;

	for (int i = 0; i < TDMA_MAX_POSITIONS; i++) {
		b.e[i].short_id = i % 3 ? (uint16_t)(0x3400u + (uint32_t)i) : 0;
		b.e[i].nonce = (uint8_t)(i * 17);
	}
	n = tdma_beacon_encode(&b, buf, TDMA_PKT_MAX);
	CHECK(n == TDMA_BEACON_FIXED_LEN + TDMA_MAX_POSITIONS * TDMA_BEACON_ENTRY_LEN, "len %d", n);
	CHECK(n <= 255, "beacon fits a record");
	CHECK(tdma_beacon_decode(buf, (size_t)n, &b2) == 0, "decode");
	CHECK(b2.flags == b.flags && b2.frame == b.frame && b2.mcs == 3 && b2.plan_id == 1 &&
		      b2.roster_ver == 9 && b2.e[4].short_id == b.e[4].short_id &&
		      b2.e[4].nonce == b.e[4].nonce && b2.e[3].short_id == 0,
	      "beacon round trip");
	CHECK(tdma_beacon_decode(buf, (size_t)n - 1, &b2) == -EINVAL, "truncated table");
	CHECK(tdma_beacon_decode(buf, 17, &b2) == -EINVAL, "truncated fixed part");
	CHECK(tdma_beacon_decode(buf, (size_t)n + 7, &b2) == 0, "PHY padding accepted");
	buf[17] = TDMA_MAX_POSITIONS + 1;
	CHECK(tdma_beacon_decode(buf, sizeof(buf), &b2) == -EMSGSIZE, "too many entries");
	buf[17] = TDMA_MAX_POSITIONS;
	buf[15] = 9;
	CHECK(tdma_beacon_decode(buf, (size_t)n, &b2) == -EINVAL, "bad MCS");
	buf[15] = 3;
	buf[1] |= TDMA_F_SEC;
	CHECK(tdma_beacon_decode(buf, (size_t)n, &b2) < 0, "secured PDU rejected in v0");
	buf[1] &= ~TDMA_F_SEC;
	buf[0] = 7;
	CHECK(tdma_beacon_decode(buf, (size_t)n, &b2) < 0, "unknown type");
	CHECK(tdma_pdu_type(buf, (size_t)n) == -EINVAL, "unknown type");
	b.n = TDMA_MAX_POSITIONS + 1;
	CHECK(tdma_beacon_encode(&b, buf, sizeof(buf)) == -ENOBUFS, "encode too many");
	b.n = 2;
	CHECK(tdma_beacon_encode(&b, buf, 20) == -ENOBUFS, "encode into small buffer");
	/* channel move announcement */
	b.flags = TDMA_F_MOVE;
	b.move_ch = 1709;
	b.move_frame = 0x01020310;
	n = tdma_beacon_encode(&b, buf, TDMA_PKT_MAX);
	CHECK(n == TDMA_BEACON_FIXED_LEN + 2 * TDMA_BEACON_ENTRY_LEN + TDMA_BEACON_MOVE_LEN,
	      "move len %d", n);
	CHECK(tdma_beacon_decode(buf, (size_t)n, &b2) == 0 && b2.move_ch == 1709 &&
		      b2.move_frame == 0x01020310 && (b2.flags & TDMA_F_MOVE),
	      "move round trip");
	CHECK(tdma_beacon_decode(buf, (size_t)n - 1, &b2) == -EINVAL, "truncated move");
	b.move_ch = 0;
	n = tdma_beacon_encode(&b, buf, TDMA_PKT_MAX);
	CHECK(tdma_beacon_decode(buf, (size_t)n, &b2) == -EINVAL, "move to channel 0 rejected");

	/* data, unfragmented */
	uint8_t pl[TDMA_MAX_SDU];

	for (size_t i = 0; i < sizeof(pl); i++) {
		pl[i] = (uint8_t)(i * 7 + 3);
	}
	struct tdma_data d = {.seq = 200, .ack = {true, 17, 0xa5}, .len = 64, .payload = pl};
	struct tdma_data d2;

	n = tdma_data_encode(&d, buf, TDMA_PDU_MAX);
	CHECK(n == TDMA_DATA_HDR_LEN + 64, "n=%d", n);
	CHECK(tdma_data_decode(buf, (size_t)n, &d2) == 0, "decode");
	CHECK(d2.seq == 200 && d2.ack.valid && d2.ack.ack == 17 && d2.ack.ack_map == 0xa5 &&
		      d2.len == 64 && !d2.frag && memcmp(d2.payload, pl, 64) == 0,
	      "data round trip");
	CHECK(tdma_data_decode(buf, (size_t)n - 1, &d2) == -EINVAL, "payload truncated");
	CHECK(tdma_data_decode(buf, 6, &d2) == -EINVAL, "header truncated");
	d.len = TDMA_SDU_PER_PDU_MAX + 1;
	CHECK(tdma_data_encode(&d, buf, TDMA_PDU_MAX) == -ENOBUFS, "oversized data");
	buf[5] = 0xff;
	buf[6] = 0xff;
	CHECK(tdma_data_decode(buf, sizeof(buf), &d2) < 0, "len field beyond buffer");

	/* data, fragment */
	d = (struct tdma_data){.seq = 3,
			       .frag = true,
			       .frag_tag = 9,
			       .frag_off = 2 * 60,
			       .frag_total = 1000,
			       .len = 100,
			       .payload = pl};
	n = tdma_data_encode(&d, buf, TDMA_PDU_MAX);
	CHECK(n == 112, "fragment PDU: %d", n);
	CHECK(tdma_data_decode(buf, (size_t)n, &d2) == 0 && d2.frag && d2.frag_tag == 9 &&
		      d2.len == 100 && d2.frag_total == 1000 && d2.frag_off == d.frag_off &&
		      !d2.ack.valid,
	      "fragment round trip");
	buf[8] = 121; /* off 121: not on a TDMA_FRAG_ALIGN unit */
	CHECK(tdma_data_decode(buf, (size_t)n, &d2) == -EMSGSIZE, "unaligned fragment offset");
	buf[8] = 120;
	buf[10] = 200; /* SDU 200 B: off + len beyond it */
	buf[11] = 0;
	CHECK(tdma_data_decode(buf, (size_t)n, &d2) == -EMSGSIZE, "fragment beyond its SDU");
	buf[10] = 0xff;
	buf[11] = 0x7f; /* SDU longer than the reassembly buffer */
	CHECK(tdma_data_decode(buf, (size_t)n, &d2) == -EMSGSIZE, "SDU length beyond TDMA_MAX_SDU");
	buf[10] = 220; /* ends the SDU */
	buf[11] = 0;
	CHECK(tdma_data_decode(buf, (size_t)n, &d2) == 0, "last fragment");
	buf[5] = 99; /* 99 B: an unaligned length is only allowed at the end */
	buf[10] = 219;
	CHECK(tdma_data_decode(buf, (size_t)n, &d2) == 0, "last fragment, unaligned end");
	buf[10] = 230;
	CHECK(tdma_data_decode(buf, (size_t)n, &d2) == -EMSGSIZE, "unaligned middle fragment");
	buf[5] = 100;
	CHECK(tdma_data_decode(buf, 10, &d2) == -EINVAL, "frag header truncated");

	/* ack */
	struct tdma_ack a = {true, 250, 0x81}, a2;

	n = tdma_ack_encode(&a, buf, sizeof(buf));
	CHECK(n == TDMA_ACK_LEN && tdma_ack_decode(buf, (size_t)n, &a2) == 0 && a2.valid &&
		      a2.ack == 250 && a2.ack_map == 0x81,
	      "ack round trip");
	CHECK(tdma_ack_decode(buf, 3, &a2) == -EINVAL, "short ack");
	a.valid = false;
	tdma_ack_encode(&a, buf, sizeof(buf));
	CHECK(tdma_ack_decode(buf, TDMA_ACK_LEN, &a2) == 0 && !a2.valid, "invalid ack");
	CHECK(tdma_ack_encode(&a, buf, 3) == -ENOBUFS, "ack small buffer");

	/* association request */
	struct tdma_assoc_req r = {.pt_rd_id = 0x10123405,
				   .ft_rd_id = 0x10123401,
				   .box_id = 5,
				   .nonce = 0x42},
			      r2;

	n = tdma_assoc_encode(&r, buf, sizeof(buf));
	CHECK(n == TDMA_ASSOC_LEN && tdma_assoc_decode(buf, (size_t)n, &r2) == 0 &&
		      r2.pt_rd_id == r.pt_rd_id && r2.ft_rd_id == r.ft_rd_id && r2.box_id == 5 &&
		      r2.nonce == 0x42,
	      "assoc round trip");
	CHECK(tdma_assoc_decode(buf, (size_t)n - 1, &r2) == -EINVAL, "short assoc");
	buf[11] = 0;
	CHECK(tdma_assoc_decode(buf, (size_t)n, &r2) == -EINVAL, "nonce 0");
	buf[11] = 1;
	memset(&buf[2], 0, 4);
	CHECK(tdma_assoc_decode(buf, (size_t)n, &r2) == -EINVAL, "rd id 0");

	CHECK(tdma_pdu_type(NULL, 4) == -EINVAL && tdma_pdu_type(buf, 1) == -EINVAL, "short type");

	/* records: build two, pad with zeros like the PHY, walk them */
	{
		uint8_t pkt[77] = {0};
		size_t off = 0, plen, room;
		const uint8_t *pdu;
		uint8_t addr;

		room = tdma_rec_room(sizeof(pkt), off);
		CHECK(room == 75, "room %zu", room);
		n = tdma_ack_encode(&a, pkt + off + TDMA_REC_HDR_LEN, room);
		tdma_rec_close(pkt, &off, 2, (size_t)n);
		n = tdma_assoc_encode(&r, pkt + off + TDMA_REC_HDR_LEN,
				      tdma_rec_room(sizeof(pkt), off));
		tdma_rec_close(pkt, &off, TDMA_ADDR_ALL, (size_t)n);
		off = 0;
		CHECK(tdma_rec_next(pkt, sizeof(pkt), &off, &addr, &pdu, &plen) == 1 && addr == 2 &&
			      plen == TDMA_ACK_LEN && pdu[0] == TDMA_PDU_ACK,
		      "record 1");
		CHECK(tdma_rec_next(pkt, sizeof(pkt), &off, &addr, &pdu, &plen) == 1 &&
			      addr == TDMA_ADDR_ALL && plen == TDMA_ASSOC_LEN,
		      "record 2");
		CHECK(tdma_rec_next(pkt, sizeof(pkt), &off, &addr, &pdu, &plen) == 0,
		      "padding ends");
		off = 0;
		pkt[0] = 76; /* overruns the 77-byte packet */
		CHECK(tdma_rec_next(pkt, sizeof(pkt), &off, &addr, &pdu, &plen) == -EINVAL,
		      "overrun");
		CHECK(tdma_rec_next(pkt, 1, &off, &addr, &pdu, &plen) == -EINVAL, "header only");
		CHECK(tdma_rec_room(3, 2) == 0 && tdma_rec_room(1000, 0) == TDMA_REC_SHORT_MAX,
		      "room limits");
	}
	/* long records (> 254 B): 4-byte header; a short PDU in a long slot moves down */
	{
		uint8_t pkt[700] = {0};
		size_t off = 0, plen, room;
		const uint8_t *pdu;
		uint8_t addr;

		room = tdma_rec_room_long(sizeof(pkt), off);
		CHECK(room == 696 && tdma_rec_room_long(258, 0) == 254 &&
			      tdma_rec_room_long(259, 0) == 255,
		      "long room %zu", room);
		d = (struct tdma_data){.seq = 1,
				       .frag = true,
				       .frag_tag = 3,
				       .frag_off = 0,
				       .frag_total = 1280,
				       .len = 600,
				       .payload = pl};
		n = tdma_data_encode(&d, pkt + off + TDMA_REC_LONG_HDR_LEN, room);
		tdma_rec_close_long(pkt, &off, 1, (size_t)n);
		CHECK(off == (size_t)(TDMA_REC_LONG_HDR_LEN + n) && pkt[0] == TDMA_REC_LONG,
		      "long record");
		n = tdma_ack_encode(&a, pkt + off + TDMA_REC_LONG_HDR_LEN,
				    tdma_rec_room_long(sizeof(pkt), off));
		tdma_rec_close_long(pkt, &off, 2, (size_t)n);
		off = 0;
		CHECK(tdma_rec_next(pkt, sizeof(pkt), &off, &addr, &pdu, &plen) == 1 && addr == 1 &&
			      plen == (size_t)(TDMA_DATA_HDR_LEN + TDMA_FRAG_HDR_LEN + 600) &&
			      tdma_data_decode(pdu, plen, &d2) == 0 && d2.len == 600 &&
			      memcmp(d2.payload, pl, 600) == 0,
		      "long record walked");
		CHECK(tdma_rec_next(pkt, sizeof(pkt), &off, &addr, &pdu, &plen) == 1 && addr == 2 &&
			      plen == TDMA_ACK_LEN && pdu[0] == TDMA_PDU_ACK,
		      "short record after it");
		CHECK(tdma_rec_next(pkt, sizeof(pkt), &off, &addr, &pdu, &plen) == 0, "end");
		off = 0;
		pkt[2] = 100; /* a long header must carry > 254 */
		pkt[3] = 0;
		CHECK(tdma_rec_next(pkt, sizeof(pkt), &off, &addr, &pdu, &plen) == -EINVAL,
		      "long header with a short length");
		pkt[2] = 0xff;
		pkt[3] = 0x02; /* 767: beyond the packet */
		CHECK(tdma_rec_next(pkt, sizeof(pkt), &off, &addr, &pdu, &plen) == -EINVAL,
		      "long record overrun");
		CHECK(tdma_rec_next(pkt, 3, &off, &addr, &pdu, &plen) == -EINVAL,
		      "long header cut");
	}
}

/* Every decoder on random bytes: must not crash or read out of bounds (ASan). */
void test_pdu_fuzz(void)
{
	uint32_t x = 12345;
	unsigned int ok = 0;

	for (int iter = 0; iter < 200000; iter++) {
		size_t len;
		uint8_t *buf;

		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		len = x % (TDMA_PKT_MAX + 8);
		buf = malloc(len ? len : 1); /* exact size so ASan sees overreads */
		for (size_t i = 0; i < len; i++) {
			x ^= x << 13;
			x ^= x >> 17;
			x ^= x << 5;
			buf[i] = (uint8_t)x;
		}
		if (len) {
			buf[0] &= 3; /* mostly valid types to get deep into the decoders */
		}
		struct tdma_beacon b;
		struct tdma_data d;
		struct tdma_ack a;
		struct tdma_assoc_req r;
		struct tdma_phy_hdr h;

		ok += tdma_beacon_decode(buf, len, &b) == 0;
		if (tdma_data_decode(buf, len, &d) == 0) {
			ok++;
			CHECK(d.payload + d.len <= buf + len, "payload inside buffer");
		}
		ok += tdma_ack_decode(buf, len, &a) == 0;
		ok += tdma_assoc_decode(buf, len, &r) == 0;
		ok += tdma_phy_hdr_decode(buf, len, &h) == 0;
		{
			size_t off = 0, plen, tot = 0;
			const uint8_t *pdu;
			uint8_t addr;

			while (tdma_rec_next(buf, len, &off, &addr, &pdu, &plen) == 1) {
				tot += plen;
				CHECK(pdu + plen <= buf + len, "record inside buffer");
			}
			(void)tot;
		}
		free(buf);
	}
	printf("    200000 random buffers, %u decoded as valid, no crash\n", ok);
}

/* ---- plans ------------------------------------------------------------------------- */

void test_plan(void)
{
	static const struct {
		uint8_t id;
		uint8_t n;
		uint32_t dl_gap, ul_gap;
	} want[] = {
		{TDMA_PLAN_A, 4, 24 * TDMA_SUBSLOT_TICKS, 24 * TDMA_SUBSLOT_TICKS},
		{TDMA_PLAN_1X10, 10, 48 * TDMA_SUBSLOT_TICKS, 48 * TDMA_SUBSLOT_TICKS},
		{TDMA_PLAN_B, 2, 12 * TDMA_SUBSLOT_TICKS, 12 * TDMA_SUBSLOT_TICKS},
	};

	for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
		const struct tdma_plan *p = tdma_plan_get(want[i].id);

		CHECK(p != NULL, "plan %u", want[i].id);
		if (!p) {
			continue;
		}
		CHECK(tdma_plan_validate(p) == 0, "plan %s valid", p->name);
		CHECK(p->n_positions == want[i].n, "plan %s positions", p->name);
		CHECK(tdma_plan_max_gap_ticks(p, 0, TDMA_SLOT_DL) == want[i].dl_gap,
		      "plan %s DL gap", p->name);
		for (uint8_t pos = 0; pos < p->n_positions; pos++) {
			CHECK(tdma_plan_max_gap_ticks(p, pos, TDMA_SLOT_UL) == want[i].ul_gap,
			      "plan %s pos %u UL gap", p->name, pos);
		}
		printf("    plan %-4s: %2u slots, %2u positions, MCS %u, DL burst %u B, UL burst "
		       "%u B, "
		       "DL/UL every %llu us\n",
		       p->name, p->n_slots, p->n_positions, p->mcs,
		       tdma_tbs(p->mcs, p->slots[0].len), tdma_tbs(p->mcs, 2),
		       (unsigned long long)TDMA_TICKS_TO_US(want[i].dl_gap));
	}
	CHECK(tdma_plan_get(99) == NULL, "unknown plan");
	CHECK(tdma_tbs(2, 2) == 57 && tdma_tbs(3, 2) == 77 && tdma_tbs(4, 2) == 117 &&
		      tdma_tbs(2, 4) == 157 && tdma_tbs(3, 4) == 209 && tdma_tbs(4, 4) == 311 &&
		      tdma_tbs(5, 2) == 0 && tdma_tbs(4, 9) == 0 && tdma_tbs(4, 8) == 700 &&
		      tdma_tbs(3, 11) == 660 && tdma_tbs(3, 12) == 0 && tdma_tbs(1, 16) == 495 &&
		      tdma_tbs(2, 17) == 0,
	      "TBS table (5600-bit cap)");
	CHECK(tdma_max_burst(4, 10) == 8 && tdma_max_burst(3, 10) == 10 &&
		      tdma_max_burst(4, 4) == 4 && tdma_max_burst(2, 16) == 15,
	      "longest bursts");

	/* the v0 spec layout: DL k at 2-3 directly followed by UL k at 4-5 */
	static const struct tdma_slot v0_spec[] = {{0, 2, TDMA_SLOT_BEACON, 0},
						   {2, 2, TDMA_SLOT_DL, 0},
						   {4, 2, TDMA_SLOT_UL, 0},
						   {22, 2, TDMA_SLOT_CONTENTION, 0}};
	static const struct tdma_slot no_beacon[] = {{2, 2, TDMA_SLOT_DL, 0}};
	static const struct tdma_slot overlap[] = {
		{0, 4, TDMA_SLOT_BEACON, 0}, {6, 2, TDMA_SLOT_UL, 0}, {7, 2, TDMA_SLOT_UL, 0}};
	static const struct tdma_slot no_ul_guard[] = {
		{0, 4, TDMA_SLOT_BEACON, 0}, {6, 2, TDMA_SLOT_UL, 0}, {8, 2, TDMA_SLOT_UL, 1}};
	static const struct tdma_slot rx_tx_tight[] = {{0, 4, TDMA_SLOT_BEACON, 0},
						       {6, 2, TDMA_SLOT_UL, 0},
						       {47, 1, TDMA_SLOT_CONTENTION, 0}};
	static const struct tdma_slot ok_2[] = {
		{0, 4, TDMA_SLOT_BEACON, 0}, {6, 2, TDMA_SLOT_UL, 0}, {9, 2, TDMA_SLOT_UL, 1}};
	static const struct tdma_slot bad_pos[] = {{0, 4, TDMA_SLOT_BEACON, 0},
						   {6, 2, TDMA_SLOT_UL, 2}};
	struct tdma_plan p = {9, 1, 4, 3, v0_spec, "x", 0};

	CHECK(tdma_plan_validate(&p) == -EINVAL, "v0 spec plan: DL->UL gap 0 rejected");
	p.slots = no_beacon;
	p.n_slots = 1;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "no beacon");
	p.slots = overlap;
	p.n_slots = 3;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "overlap");
	p.slots = no_ul_guard;
	p.n_positions = 2;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "UL bursts without a guard subslot");
	p.slots = rx_tx_tight;
	p.n_positions = 1;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "UL run ends right before the next beacon");
	p.slots = ok_2;
	p.n_positions = 2;
	CHECK(tdma_plan_validate(&p) == 0, "minimal valid plan");
	p.n_positions = 3;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "position without UL slot");
	p.slots = bad_pos;
	p.n_slots = 2;
	p.n_positions = 2;
	CHECK(tdma_plan_validate(&p) == -EINVAL, "position out of range");
	static const struct tdma_slot small_dl[] = {
		{0, 2, TDMA_SLOT_BEACON, 0}, {4, 2, TDMA_SLOT_UL, 0}, {7, 2, TDMA_SLOT_UL, 1}};

	p.slots = small_dl;
	p.n_slots = 3;
	CHECK(tdma_plan_validate(&p) == 0, "2 ss beacon at MCS 3");
	p.mcs = 0; /* 2 ss at MCS 0 = 17 B: no room for the beacon */
	CHECK(tdma_plan_validate(&p) == -EINVAL, "beacon does not fit the DL burst");
	CHECK(tdma_plan_validate(NULL) == -EINVAL, "NULL");

	CHECK(TDMA_US_TO_TICKS(10000) == TDMA_FRAME_TICKS, "10 ms = frame");
	CHECK(TDMA_TICKS_TO_US(TDMA_SUBSLOT_TICKS) == 208, "subslot us");
}

/* ---- link (ARQ) without a radio ---------------------------------------------------------- */

static struct tdma_link la, lb;
static uint8_t qmem_a[TDMA_TXQ_ALL_CHUNKS][TDMA_TXQ_CHUNK],
	qmem_b[TDMA_TXQ_ALL_CHUNKS][TDMA_TXQ_CHUNK];
static struct tdma_ras rpool[TDMA_RAS_PER_LINK + 1];

/* a 2 ss UL burst at MCS 3: 77 B - MIC - record header */
#define CAP      (77 - TDMA_MIC_RESERVE - TDMA_REC_HDR_LEN)
#define PER_FRAG ((CAP - TDMA_DATA_HDR_LEN - TDMA_FRAG_HDR_LEN) / TDMA_FRAG_ALIGN * TDMA_FRAG_ALIGN)
static uint8_t got[TDMA_MAX_SDU];
static size_t got_len;
static int got_n;

static void cap_deliver(void *ctx, const uint8_t *data, size_t len)
{
	(void)ctx;
	memcpy(got, data, len);
	got_len = len;
	got_n++;
}

static uint8_t hop_max_tx = 3;

/* Hand one PDU from link `from` (built for a burst at t with room cap) to link `to`. */
static int hop_cap(struct tdma_link *from, struct tdma_link *to, uint64_t t, bool lose,
		   struct tdma_stats *st, size_t cap, link_deliver_fn dlv)
{
	struct link_params lp = {hop_max_tx, 1000000000u,
				 TDMA_COMMIT_LEAD_TICKS + TDMA_RX_PROC_TICKS};
	uint8_t buf[TDMA_PKT_MAX];
	struct tdma_data d;
	struct tdma_ack a;
	int n = link_build(from, &lp, t, t, t + 28800, true, buf, cap, st);

	CHECK(n <= (int)cap, "PDU %d > room %zu", n, cap);
	if (n <= 0 || lose) {
		return n;
	}
	if (tdma_pdu_type(buf, (size_t)n) == TDMA_PDU_DATA) {
		CHECK(tdma_data_decode(buf, (size_t)n, &d) == 0, "decode");
		link_rx_ack(to, &lp, &d.ack, t, st);
		link_rx_data(to, rpool, sizeof(rpool) / sizeof(rpool[0]), from == &la ? 2 : 1, &d,
			     t, dlv, NULL, st);
	} else {
		CHECK(tdma_ack_decode(buf, (size_t)n, &a) == 0, "decode");
		link_rx_ack(to, &lp, &a, t, st);
	}
	return n;
}

static int hop(struct tdma_link *from, struct tdma_link *to, uint64_t t, bool lose,
	       struct tdma_stats *st)
{
	return hop_cap(from, to, t, lose, st, CAP, cap_deliver);
}

static void links_reset(size_t cap, bool wide)
{
	link_attach(&la, qmem_a, TDMA_TXQ_ALL_CHUNKS);
	link_attach(&lb, qmem_b, TDMA_TXQ_ALL_CHUNKS);
	link_reset(&la);
	link_reset(&lb);
	link_set_cap(&la, cap, wide, false);
	link_set_cap(&lb, cap, wide, false);
	memset(rpool, 0, sizeof(rpool));
}

static const struct tdma_txsdu *qa(uint8_t i)
{
	return &la.sdu[la.order[i]];
}

/* random traffic: SDU content is a function of (id, byte), id in the first 2 bytes */
static uint8_t rnd_pat(unsigned int id, size_t i)
{
	return (uint8_t)(id * 131u + i * 7u + (i >> 8));
}

static unsigned int rnd_ok, rnd_bad, rnd_seen[64];

static void rnd_deliver(void *ctx, const uint8_t *data, size_t len)
{
	unsigned int id;

	(void)ctx;
	if (len < 4) {
		rnd_bad++;
		return;
	}
	id = data[0] | (unsigned int)data[1] << 8;
	if (id >= 64 || len != 4u + (id * 397u) % (TDMA_MAX_SDU - 3u)) {
		rnd_bad++;
		return;
	}
	for (size_t i = 4; i < len; i++) {
		if (data[i] != rnd_pat(id, i)) {
			rnd_bad++;
			return;
		}
	}
	rnd_seen[id]++;
	rnd_ok++;
}

void test_link(void)
{
	struct tdma_stats st = {0};
	uint8_t sdu[TDMA_MAX_SDU];
	uint64_t t = 1000000;
	const uint64_t half = TDMA_FRAME_TICKS / 2;

	for (size_t i = 0; i < sizeof(sdu); i++) {
		sdu[i] = (uint8_t)(i ^ (i >> 8));
	}
	links_reset(CAP, false);

	/* in-order exchange, A -> B, B acks in its bursts */
	for (int i = 0; i < 5; i++) {
		CHECK(link_enqueue(&la, sdu, 64, 0, t) == 0, "enqueue");
	}
	got_n = 0;
	for (int i = 0; i < 12; i++, t += half) {
		hop(&la, &lb, t, false, &st);
		hop(&lb, &la, t + 2 * TDMA_SUBSLOT_TICKS, false, &st);
	}
	CHECK(got_n == 5 && st.sdu_tx_ok == 5 && !link_has_pending(&la) && la.n_sdu == 0,
	      "5 delivered + acked (%d, %u)", got_n, st.sdu_tx_ok);
	CHECK(st.retx == 0 && st.dup_rx == 0, "no retx/dups on a clean link (%u %u)", st.retx,
	      st.dup_rx);

	/* window: at most TDMA_ARQ_WINDOW PDUs in flight without acks */
	memset(&st, 0, sizeof(st));
	for (int i = 0; i < 20; i++) {
		link_enqueue(&la, sdu, 10, 0, t);
	}
	/* bursts close together: no RTO, nothing judged */
	for (int i = 0; i < 12; i++, t += 1000) {
		hop(&la, &lb, t, true, &st);
	}
	CHECK(st.pdus_tx - st.retx == TDMA_ARQ_WINDOW, "window limits new PDUs to %d (%u)",
	      TDMA_ARQ_WINDOW, st.pdus_tx - st.retx);
	links_reset(CAP, false);

	/* loss + retransmission + duplicate filter */
	memset(&st, 0, sizeof(st));
	got_n = 0;
	link_enqueue(&la, sdu, 40, 0, t);
	hop(&la, &lb, t, true, &st); /* lost */
	t += half;
	hop(&lb, &la, t, false, &st); /* B's burst well after: judges it lost */
	t += half;
	hop(&la, &lb, t, false, &st); /* retransmission arrives */
	CHECK(got_n == 1 && st.retx == 1, "retransmitted once (%d %u)", got_n, st.retx);
	/* B's ack is lost; A resends; B must drop the duplicate */
	t += half;
	hop(&lb, &la, t, true, &st);
	t += 2 * TDMA_FRAME_TICKS + 1; /* RTO fallback */
	hop(&la, &lb, t, false, &st);
	CHECK(got_n == 1 && st.dup_rx == 1, "duplicate suppressed (%d %u)", got_n, st.dup_rx);
	t += half;
	hop(&lb, &la, t, false, &st);
	CHECK(!link_has_pending(&la) && la.n_sdu == 0, "acked at last");

	/* max tries -> drop */
	memset(&st, 0, sizeof(st));
	link_enqueue(&la, sdu, 40, 0, t);
	for (int i = 0; i < 6; i++) {
		t += half;
		hop(&la, &lb, t, true, &st);
		t += half;
		hop(&lb, &la, t, false, &st);
	}
	CHECK(st.drop_retries == 1 && st.pdus_tx == 3 && st.sdu_tx_drop == 1 &&
		      !link_has_pending(&la) && la.n_sdu == 0,
	      "dropped after 3 tries (%u %u)", st.drop_retries, st.pdus_tx);

	/* fragmentation: 1280 bytes, every fifth burst lost */
	memset(&st, 0, sizeof(st));
	got_n = 0;
	links_reset(CAP, false);
	CHECK(link_enqueue(&la, sdu, TDMA_MAX_SDU, 0, t) == 0, "enqueue max SDU");
	for (int i = 0; i < 80 && la.n_sdu; i++) {
		t += half;
		hop(&la, &lb, t, (i % 5) == 0 && i < 30, &st);
		t += 2 * TDMA_SUBSLOT_TICKS;
		hop(&lb, &la, t, false, &st);
	}
	CHECK(got_n == 1 && got_len == TDMA_MAX_SDU && memcmp(got, sdu, TDMA_MAX_SDU) == 0,
	      "1280-byte SDU reassembled (%d, %zu)", got_n, got_len);
	CHECK(st.sdu_tx_ok == 1, "counted once (%u) tx %u retx %u drop %u/%u rx %u dup %u",
	      st.sdu_tx_ok, st.pdus_tx, st.retx, st.drop_retries, st.drop_lifetime, st.pdus_rx,
	      st.dup_rx);

	/* fragments are cut to the room of the burst: a long burst takes one big one */
	memset(&st, 0, sizeof(st));
	got_n = 0;
	links_reset(CAP, true);
	CHECK(link_enqueue(&la, sdu, TDMA_MAX_SDU, 0, t) == 0, "enqueue max SDU (wide)");
	{
		int n = hop_cap(&la, &lb, t, false, &st, 590, cap_deliver);

		CHECK(n >= 590 - (TDMA_FRAG_ALIGN - 1) && n <= 590,
		      "fragment fills a 590 B room: %d", n);
		n = hop_cap(&la, &lb, t + 1, false, &st, 590, cap_deliver);
		CHECK(n >= 590 - (TDMA_FRAG_ALIGN - 1), "second one too: %d", n);
		n = hop_cap(&la, &lb, t + 2, false, &st, 590, cap_deliver);
		CHECK(got_n == 1 && got_len == TDMA_MAX_SDU &&
			      memcmp(got, sdu, TDMA_MAX_SDU) == 0 &&
			      n == TDMA_MAX_SDU -
					      2 * ((590 - (int)(TDMA_DATA_HDR_LEN + 1 +
								TDMA_FRAG_HDR_LEN)) /
						   TDMA_FRAG_ALIGN * TDMA_FRAG_ALIGN) +
					      (int)(TDMA_DATA_HDR_LEN + 1 + TDMA_FRAG_HDR_LEN),
		      "1280 B in three PDUs (last %d)", n);
	}
	/* a lost big fragment is resent in small bursts: shortened, the rest with a new seq */
	memset(&st, 0, sizeof(st));
	got_n = 0;
	links_reset(CAP, true);
	link_enqueue(&la, sdu, 700, 0, t);
	hop_cap(&la, &lb, t, true, &st, 590, cap_deliver); /* big fragment lost */
	t += half;
	hop(&lb, &la, t, false, &st); /* judged lost */
	for (int i = 0; i < 40 && la.n_sdu; i++) {
		t += half;
		hop(&la, &lb, t, false, &st);
		t += 2 * TDMA_SUBSLOT_TICKS;
		hop(&lb, &la, t, false, &st);
	}
	CHECK(got_n == 1 && got_len == 700 && memcmp(got, sdu, 700) == 0 && st.sdu_tx_ok == 1 &&
		      st.retx >= 1 && st.drop_retries == 0,
	      "700 B SDU resent in small bursts (%d, retx %u)", got_n, st.retx);
	/* ... and when the lost one actually arrived (only the ack was lost): no second delivery */
	memset(&st, 0, sizeof(st));
	got_n = 0;
	link_enqueue(&la, sdu, 700, 0, t);
	t += half;
	hop_cap(&la, &lb, t, false, &st, 590, cap_deliver); /* arrives */
	t += half;
	hop(&lb, &la, t, true, &st);                            /* ack lost */
	hop_cap(&la, &lb, t + 1, false, &st, 590, cap_deliver); /* the rest; completes the SDU */
	CHECK(got_n == 1, "delivered once");
	t += 2 * TDMA_FRAME_TICKS + 1; /* RTO: the first part goes again, in small bursts */
	for (int i = 0; i < 40 && la.n_sdu; i++) {
		hop(&la, &lb, t, false, &st);
		t += 2 * TDMA_SUBSLOT_TICKS;
		hop(&lb, &la, t, false, &st);
		t += half;
	}
	CHECK(got_n == 1 && st.sdu_tx_ok == 1 && la.n_sdu == 0,
	      "resent parts of a delivered SDU are dropped (%d)", got_n);

	/* lifetime */
	memset(&st, 0, sizeof(st));
	links_reset(CAP, false);
	link_enqueue(&la, sdu, 30, 0, t);
	{
		struct link_params lp = {3, 1000, 0};
		uint8_t buf[TDMA_PDU_MAX];

		/* queued long ago: no lifetime before the first transmission */
		link_build(&la, &lp, t + 5000, t + 5000, t + 6000, false, buf, sizeof(buf), &st);
		CHECK(st.pdus_tx == 1 && st.drop_lifetime == 0, "sent despite queue age");
		link_build(&la, &lp, t + 6001, t + 6001, t + 7000, false, buf, sizeof(buf), &st);
	}
	CHECK(st.drop_lifetime == 1 && !link_has_pending(&la) && la.n_sdu == 0, "lifetime drop");

	/* priority goes ahead of normal traffic not started yet */
	links_reset(CAP, false);
	link_enqueue(&la, sdu, 200, 0, t);
	link_enqueue(&la, sdu, 10, 0, t);
	link_enqueue(&la, sdu, 11, 1, t);
	CHECK(la.n_sdu == 3 && qa(0)->len == 11 && qa(0)->prio && qa(1)->len == 200,
	      "prio first while nothing sent");
	links_reset(CAP, false);
	link_enqueue(&la, sdu, 200, 0, t);
	{
		struct link_params lp = {3, 1000000000u, 0};
		uint8_t buf[TDMA_PDU_MAX];

		link_build(&la, &lp, t, t, t + 1, false, buf, CAP, &st); /* first fragment sent */
	}
	link_enqueue(&la, sdu, 10, 0, t);
	link_enqueue(&la, sdu, 11, 1, t);
	/* an unfragmented one also ahead of the rest of a started SDU ... */
	CHECK(qa(0)->len == 11 && qa(1)->len == 200, "prio passes the rest of a started SDU");
	link_enqueue(&la, sdu, 12, 1, t);
	CHECK(qa(1)->len == 12, "prio keeps FIFO order among prio SDUs");
	/* ... a fragmented one only ahead of what has not started */
	link_enqueue(&la, sdu, 150, 1, t);
	CHECK(qa(2)->len == 200 && qa(3)->len == 150 && qa(4)->len == 10,
	      "fragmented prio SDU after the started fragmented SDU");

	/* enqueue limits */
	links_reset(CAP, false);
	CHECK(link_enqueue(&la, sdu, TDMA_MAX_SDU + 1, 0, t) == -EMSGSIZE, "too big");
	CHECK(link_mtu(&la) == CAP - TDMA_DATA_HDR_LEN, "mtu");
	CHECK(link_enqueue(&la, sdu, 0, 0, t) == -EMSGSIZE, "empty");
	int k = 0;

	while (link_enqueue(&la, sdu, TDMA_MAX_SDU, 0, t) == 0) {
		k++;
	}
	CHECK(k == TDMA_TXQ_STD_CHUNKS / ((TDMA_MAX_SDU + TDMA_TXQ_CHUNK - 1) / TDMA_TXQ_CHUNK),
	      "queue holds %d max SDUs", k);
	/* a sender that found the queue full has more: the queue report says so */
	CHECK(link_pending_bytes(&la) >= (size_t)(k + 1) * TDMA_MAX_SDU,
	      "blocked sender reported (%zu)", link_pending_bytes(&la));
	/* a small priority SDU still finds room behind the full bulk queue; bulk does not */
	CHECK(!link_room(&la, TDMA_MAX_SDU, 0) && link_room(&la, 64, 1), "prio reserve");
	CHECK(link_enqueue(&la, sdu, 64, 1, t) == 0 && link_enqueue(&la, sdu, 60, 1, t) == 0,
	      "small prio SDUs behind a full bulk queue");
	CHECK(link_enqueue(&la, sdu, 64, 0, t) == -ENOBUFS && la.blocked, "bulk still full");
	CHECK(link_pending_bytes(&la) >= (size_t)(k + 1) * TDMA_MAX_SDU, "still reported blocked");
	memset(&st, 0, sizeof(st));
	for (int i = 0; i < 80 && la.n_sdu >= k; i++) {
		t += half;
		hop(&la, &lb, t, false, &st);
		t += 2 * TDMA_SUBSLOT_TICKS;
		hop(&lb, &la, t, false, &st);
	}
	CHECK(la.n_sdu == k - 1 && la.n_prio == 0 && link_room(&la, TDMA_MAX_SDU, 0),
	      "prio SDUs and one bulk SDU acked: room for a max SDU (%u SDUs)", la.n_sdu);
	CHECK(la.n_sdu == k - 1 && link_pending_bytes(&la) < (size_t)k * TDMA_MAX_SDU,
	      "room again: no longer reported (%zu)", link_pending_bytes(&la));
	links_reset(CAP, false);
	for (k = 0; link_enqueue(&la, sdu, 8, 0, t) == 0; k++) {
	}
	CHECK(k == (TDMA_TXQ_SDUS < TDMA_TXQ_STD_CHUNKS ? TDMA_TXQ_SDUS : TDMA_TXQ_STD_CHUNKS),
	      "queue holds %d small SDUs", k);
	/* a link whose bursts are too small for 32 fragments of a max SDU */
	links_reset(TDMA_DATA_HDR_LEN + TDMA_FRAG_HDR_LEN + 20, false);
	CHECK(link_enqueue(&la, sdu, TDMA_MAX_SDU, 0, t) == -EMSGSIZE, "too many fragments");
	CHECK(link_enqueue(&la, sdu, 30, 0, t) == 0, "small SDU on a small link");

	/*
	 * Random: SDUs of every length both ways, bursts of random room (guaranteed and
	 * long), 10 % loss each way, acks in every burst. Everything arrives exactly once
	 * and intact (lifetime and tries are unlimited here).
	 */
	memset(&st, 0, sizeof(st));
	memset(rnd_seen, 0, sizeof(rnd_seen));
	rnd_ok = rnd_bad = 0;
	links_reset(CAP, true);
	{
		uint32_t x = 777;
		unsigned int next_id = 0;
		hop_max_tx = 255;
		for (int i = 0; i < 4000 && (next_id < 64 || la.n_sdu); i++) {
			size_t room;

			x = x * 1103515245u + 12345u;
			if (next_id < 64 && (x >> 16) % 3 == 0) {
				uint8_t b[TDMA_MAX_SDU];
				size_t len = 4u + (next_id * 397u) % (TDMA_MAX_SDU - 3u);

				b[0] = (uint8_t)next_id;
				b[1] = (uint8_t)(next_id >> 8);
				b[2] = b[3] = 0;
				for (size_t j = 4; j < len; j++) {
					b[j] = rnd_pat(next_id, j);
				}
				if (link_enqueue(&la, b, len, (x >> 20) % 4 == 0, t) == 0) {
					next_id++;
				}
			}
			x = x * 1103515245u + 12345u;
			room = (x >> 16) % 2 ? CAP : 100 + (x >> 18) % 600;
			t += half / 2;
			x = x * 1103515245u + 12345u;
			hop_cap(&la, &lb, t, (x >> 16) % 10 == 0, &st, room, rnd_deliver);
			t += 4 * TDMA_SUBSLOT_TICKS;
			x = x * 1103515245u + 12345u;
			hop_cap(&lb, &la, t, (x >> 16) % 10 == 0, &st, CAP, rnd_deliver);
		}
		unsigned int once = 0;

		for (unsigned int id = 0; id < 64; id++) {
			once += rnd_seen[id] == 1;
		}
		hop_max_tx = 3;
		CHECK(next_id == 64 && rnd_ok == 64 && once == 64 && rnd_bad == 0,
		      "random cuts, 10 %% loss: %u/%u SDUs once, %u bad (retx %u, drops %u/%u, "
		      "no buffer %u)",
		      once, next_id, rnd_bad, st.retx, st.drop_retries, st.drop_lifetime,
		      st.ras_full);
	}
}

/*
 * random
 * traffic both ways with loss, short lifetimes, retries, holds, priority and
 * bulk, burst sizes from ack-only to long; every link operation checks that
 * the free list and the SDUs' chunk chains partition the chunks
 * (TDMA_CHECK_LEAD_MEMO: link_check()).
 */
void test_link_fuzz(void)
{
	struct tdma_stats st;
	uint64_t t = 1000000;
	uint32_t x = 0x9e3779b9u, sent = 0, okb = 0;
	uint8_t sdu[TDMA_MAX_SDU];

	memset(&st, 0, sizeof(st));
	for (int round = 0; round < 6; round++) {
		bool wide = round & 1;

		links_reset(round < 3 ? CAP : 400, wide);
		for (int it = 0; it < 40000; it++) {
			uint32_t r;
			struct link_params lp;
			uint8_t buf[TDMA_PKT_MAX];
			struct tdma_link *from = (it & 1) ? &la : &lb, *to = (it & 1) ? &lb : &la;
			size_t cap;
			int n;

			x ^= x << 13;
			x ^= x >> 17;
			x ^= x << 5;
			r = x;
			if (r % 3 == 0) {
				size_t len = 1 + r / 7 % (r % 11 == 0 ? TDMA_MAX_SDU : 300);

				memset(sdu, (int)(it & 0xff), len);
				sent += link_enqueue(from, sdu, len, (uint8_t)(r % 5 == 0), t) == 0;
			}
			if (r % 97 == 0) {
				link_hold(from, !from->hold_tx);
			}
			lp = (struct link_params){(uint8_t)(1 + r % 4),
						  (uint32_t)(r % 2 ? 6 : 40) * 691200u,
						  TDMA_COMMIT_LEAD_TICKS};
			cap = r % 13 == 0 ? TDMA_ACK_LEN + 1 : r % 4 == 0 ? 400 : CAP;
			n = link_build(from, &lp, t, t, t + 28800, (int)(r % 4), buf, cap, &st);
			if (n > 0 && (r >> 8) % 10 >= 3) { /* 30 % lost */
				struct tdma_data d;
				struct tdma_ack a;

				if (tdma_pdu_type(buf, (size_t)n) == TDMA_PDU_DATA &&
				    tdma_data_decode(buf, (size_t)n, &d) == 0) {
					link_rx_ack(to, &lp, &d.ack, t, &st);
					link_rx_data(to, rpool, sizeof(rpool) / sizeof(rpool[0]),
						     from == &la ? 2 : 1, &d, t, cap_deliver, NULL,
						     &st);
					okb += d.len;
				} else if (tdma_ack_decode(buf, (size_t)n, &a) == 0) {
					link_rx_ack(to, &lp, &a, t, &st);
				}
			}
			t += 14400u * (1 + r % 24);
		}
	}
	printf("    %u SDUs queued, %u B delivered, %u PDU drops (lifetime %u, retries %u), %u "
	       "retx, %u hold waits\n",
	       sent, okb, st.drop_lifetime + st.drop_retries, st.drop_lifetime, st.drop_retries,
	       st.retx, st.hold_waits);
	CHECK(sent > 1000 && okb > 0, "traffic went");
}

/*
 * priority
 * SDUs may take queue entries bulk leaves free, so with 23 bulk + 5 priority
 * SDUs all 28 entries were in use while the bulk count (23 < 24) still let a
 * bulk SDU in: link_enqueue() wrote it past sdu[] into order[], and later
 * removals released chunks twice (a cycle in the free list).
 */
void test_link_slots(void)
{
	uint8_t sdu[64];
	int n_bulk = 0, n_prio = 0, err;

	memset(sdu, 0x5a, sizeof(sdu));
	links_reset(CAP, false);
	for (int i = 0; i < TDMA_TXQ_SDUS - 1; i++) {
		n_bulk += link_enqueue(&la, sdu, sizeof(sdu), 0, 0) == 0;
	}
	for (int i = 0; i < TDMA_TXQ_PRIO_SDUS + 1; i++) {
		n_prio += link_enqueue(&la, sdu, 16, 1, 0) == 0;
	}
	CHECK(n_bulk == TDMA_TXQ_SDUS - 1 && n_prio == TDMA_TXQ_PRIO_SDUS + 1,
	      "queued %d bulk + %d priority", n_bulk, n_prio);
	CHECK(la.n_sdu == TDMA_TXQ_ALL_SDUS, "every entry in use (%u)", la.n_sdu);
	err = link_enqueue(&la, sdu, sizeof(sdu), 0, 0);
	CHECK(err == -ENOBUFS, "a bulk SDU with every entry in use is refused (%d)", err);
	CHECK(!link_room(&la, sizeof(sdu), 0) && !link_room(&la, 16, 1),
	      "no room reported either way");
	err = link_enqueue(&la, sdu, 16, 1, 0);
	CHECK(err == -ENOBUFS, "a priority SDU too (%d)", err);
	CHECK(!la.corrupt && la.n_sdu == TDMA_TXQ_ALL_SDUS, "the queue intact");
	printf("    %d bulk + %d priority SDUs: all %d entries used, the next bulk / priority SDU "
	       "refused\n",
	       n_bulk, n_prio, TDMA_TXQ_ALL_SDUS);
}
