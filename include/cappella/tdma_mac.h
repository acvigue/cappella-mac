/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * cappella-mac TDMA MAC for DECT NR+ on the Nordic DECT PHY firmware.
 * Design: docs/mac-design.md (including its "Decisions" section); PHY numbers:
 * docs/phy-timing.md.
 *
 * Pure C99, no heap, no floating point, no OS. One instance per radio; the
 * caller owns the (static) struct tdma_mac. All entry points must be called
 * from one context (the MAC thread on the modem, the event loop on the host):
 *
 *   tdma_on_rx()       a packet was received by one of our RX ops
 *   tdma_on_op_done()  an rx/tx op finished (or was stopped / failed)
 *   tdma_tick()        time passed; returns when it wants to be called next
 *   tdma_send()        queue an SDU for a peer
 *
 * Air structure (measured constraints): per opportunity the FT sends ONE DL
 * burst (beacon + DL PDUs for every PT, broadcast) and receives all UL bursts
 * with ONE continuous RX op. Any two ops of one device are >= 2 subslots
 * apart. Each op is handed to the PHY just in time (TDMA_COMMIT_LEAD_TICKS
 * before it starts), so only a few ops are ever in flight.
 */

#ifndef TDMA_MAC_H_
#define TDMA_MAC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tdma_port.h"

/* ---- compile-time sizing / tuning (override with -D or Kconfig) ---------- */

/* Zephyr: the Kconfig values arrive through the auto-included autoconf.h. */
#if defined(CONFIG_TDMA_MAC_MAX_POSITIONS) && !defined(TDMA_MAX_POSITIONS)
#define TDMA_MAX_POSITIONS CONFIG_TDMA_MAC_MAX_POSITIONS
#endif
#if defined(CONFIG_TDMA_MAC_TXQ_PDUS) && !defined(TDMA_TXQ_PDUS)
#define TDMA_TXQ_PDUS CONFIG_TDMA_MAC_TXQ_PDUS
#endif
#if defined(CONFIG_TDMA_MAC_TXQ_BYTES) && !defined(TDMA_TXQ_BYTES)
#define TDMA_TXQ_BYTES CONFIG_TDMA_MAC_TXQ_BYTES
#endif
#if defined(CONFIG_TDMA_MAC_TXQ_SDUS) && !defined(TDMA_TXQ_SDUS)
#define TDMA_TXQ_SDUS CONFIG_TDMA_MAC_TXQ_SDUS
#endif
#if defined(CONFIG_TDMA_MAC_TXQ_PRIO_BYTES) && !defined(TDMA_TXQ_PRIO_BYTES)
#define TDMA_TXQ_PRIO_BYTES CONFIG_TDMA_MAC_TXQ_PRIO_BYTES
#endif
#if defined(CONFIG_TDMA_MAC_RAS_SLOTS) && !defined(TDMA_RAS_SLOTS)
#define TDMA_RAS_SLOTS CONFIG_TDMA_MAC_RAS_SLOTS
#endif
#if defined(CONFIG_TDMA_MAC_TX_SDU_INFLIGHT) && !defined(TDMA_TX_SDU_INFLIGHT)
#define TDMA_TX_SDU_INFLIGHT CONFIG_TDMA_MAC_TX_SDU_INFLIGHT
#endif
#if defined(CONFIG_TDMA_MAC_PDU_MAX) && !defined(TDMA_PDU_MAX)
#define TDMA_PDU_MAX CONFIG_TDMA_MAC_PDU_MAX
#endif
#if defined(CONFIG_TDMA_MAC_MAX_SDU) && !defined(TDMA_MAX_SDU)
#define TDMA_MAX_SDU CONFIG_TDMA_MAC_MAX_SDU
#endif
#if defined(CONFIG_TDMA_MAC_COMMIT_LEAD_US) && !defined(TDMA_COMMIT_LEAD_TICKS)
#define TDMA_COMMIT_LEAD_TICKS TDMA_US_TO_TICKS(CONFIG_TDMA_MAC_COMMIT_LEAD_US)
#endif

/* Positions (PT slots) per FT; the largest plan used must fit. */
#ifndef TDMA_MAX_POSITIONS
#define TDMA_MAX_POSITIONS 10
#endif
/*
 * Per peer TX queue: SDU bytes in TDMA_TXQ_CHUNK-byte chunks (TDMA_TXQ_BYTES
 * in all), up to TDMA_TXQ_SDUS SDUs, and TDMA_TXQ_PDUS PDU descriptors (data
 * PDUs in flight, and parts of SDUs waiting to be sent again). Fragments are
 * cut from the queued SDU when a burst is built, to fit the room left in it.
 */
#ifndef TDMA_TXQ_PDUS
#define TDMA_TXQ_PDUS 20
#endif
#ifndef TDMA_TXQ_BYTES
#define TDMA_TXQ_BYTES 7680
#endif
/*
 * Plans without FLEX trains use only this much of it (two max-size SDUs:
 * 2560 B with 1280-byte SDUs): a deeper queue gives them no throughput, only
 * queueing delay. A train plan (plan T) sends ~2 KB per frame and gets the
 * acks of a train in the next frame or the one after: four max-size SDUs
 * (5120 B). The whole-frame plans (T2, T2D, ~2.7 KB per frame) all of it:
 * with 5120 B the DKs' sender refilled the queue too late for full long
 * bursts (91 % of the TBS used, 236 kB/s; 7680 B: 99 %, 259 kB/s).
 */
#define TDMA_SDU_CHUNK_BYTES ((TDMA_MAX_SDU + 63) / 64 * 64)
#ifndef TDMA_TXQ_STD_BYTES
#define TDMA_TXQ_STD_BYTES (2 * TDMA_SDU_CHUNK_BYTES)
#endif
#ifndef TDMA_TXQ_TRAIN_BYTES
#define TDMA_TXQ_TRAIN_BYTES (4 * TDMA_SDU_CHUNK_BYTES)
#endif
#ifndef TDMA_TXQ_SDUS
#define TDMA_TXQ_SDUS 24
#endif
#define TDMA_TXQ_CHUNK  64
#define TDMA_TXQ_CHUNKS (TDMA_TXQ_BYTES / TDMA_TXQ_CHUNK)
#define TDMA_TXQ_STD_CHUNKS                                                                        \
	(TDMA_TXQ_STD_BYTES < TDMA_TXQ_BYTES ? TDMA_TXQ_STD_BYTES / TDMA_TXQ_CHUNK                 \
					     : TDMA_TXQ_CHUNKS)
#define TDMA_TXQ_TRAIN_CHUNKS                                                                      \
	(TDMA_TXQ_TRAIN_BYTES < TDMA_TXQ_BYTES ? TDMA_TXQ_TRAIN_BYTES / TDMA_TXQ_CHUNK             \
					       : TDMA_TXQ_CHUNKS)
/*
 * On top of that, room only priority SDUs (the ones that fit one PDU) may
 * take: a small packet never waits for a bulk SDU to be acked (bulk keeps
 * exactly TDMA_TXQ_BYTES / TDMA_TXQ_SDUS, so the queue report and grants
 * do not change).
 */
#ifndef TDMA_TXQ_PRIO_BYTES
#define TDMA_TXQ_PRIO_BYTES 256
#endif
#define TDMA_TXQ_PRIO_CHUNKS (TDMA_TXQ_PRIO_BYTES / TDMA_TXQ_CHUNK)
#define TDMA_TXQ_PRIO_SDUS   4
#define TDMA_TXQ_ALL_CHUNKS  (TDMA_TXQ_CHUNKS + TDMA_TXQ_PRIO_CHUNKS)
#define TDMA_TXQ_ALL_SDUS    (TDMA_TXQ_SDUS + TDMA_TXQ_PRIO_SDUS)
/*
 * Chunk memory: the links of the first TDMA_TXQ_BIG_LINKS peers get all of
 * TDMA_TXQ_BYTES, the others only what plans without trains use (STD + prio).
 * The deep queues are for the train / whole-frame plans (T, T2, T2D), which
 * have 2 positions: an FT runs them only with its PTs in positions 0 and 1,
 * and a PT's link to its FT is peer 0. Positions 2 and up only exist in plans
 * for more PTs (H4, A, 1x10), all with STD queues. Saves ~5 KB per position
 * above 2 (a 4-position MAC: 52.6 -> 42.4 KB).
 */
#ifndef TDMA_TXQ_BIG_LINKS
#define TDMA_TXQ_BIG_LINKS 2
#endif
#define TDMA_TXQ_SMALL_CHUNKS                                                                      \
	(TDMA_TXQ_STD_CHUNKS + TDMA_TXQ_PRIO_CHUNKS < TDMA_TXQ_ALL_CHUNKS                          \
		 ? TDMA_TXQ_STD_CHUNKS + TDMA_TXQ_PRIO_CHUNKS                                      \
		 : TDMA_TXQ_ALL_CHUNKS)
#define TDMA_TXQ_N_BIG                                                                             \
	(TDMA_MAX_POSITIONS < TDMA_TXQ_BIG_LINKS ? TDMA_MAX_POSITIONS : TDMA_TXQ_BIG_LINKS)
#define TDMA_TXQ_POOL_CHUNKS                                                                       \
	(TDMA_TXQ_N_BIG * TDMA_TXQ_ALL_CHUNKS +                                                    \
	 (TDMA_MAX_POSITIONS - TDMA_TXQ_N_BIG) * TDMA_TXQ_SMALL_CHUNKS)
/*
 * Reassembly buffers (TDMA_MAX_SDU each), shared by all peers; one peer
 * holds at most TDMA_RAS_PER_LINK. A sender has at most TDMA_TX_SDU_INFLIGHT
 * fragmented SDUs started and not yet acked.
 */
#ifndef TDMA_RAS_SLOTS
#define TDMA_RAS_SLOTS (TDMA_MAX_POSITIONS + 1)
#endif
#ifndef TDMA_TX_SDU_INFLIGHT
#define TDMA_TX_SDU_INFLIGHT 2
#endif
/*
 * ... and on the links of a train plan (both ends know the plan from the
 * beacon): a train frame carries 2.1-2.8 KB one way and its acks come a frame
 * later, so 4  held 512 B SDUs back (sim, plan T: UL 102 -> 197
 * kB/s with 6).
 */
#define TDMA_TX_SDU_INFLIGHT_TRAIN 6
#define TDMA_RAS_PER_LINK          6
/* Fragments are cut at multiples of this (the reassembly map's unit). */
#define TDMA_FRAG_ALIGN            4
/* A fragment carries at least this much (or the rest of its SDU). */
#define TDMA_FRAG_MIN              16
/*
 * Largest single PDU (data header + SDU bytes) a link ever builds; each link
 * further limits it to what its bursts carry. 113 = 2 ss at MCS 4 minus MIC.
 */
#ifndef TDMA_PDU_MAX
#define TDMA_PDU_MAX 113
#endif
/*
 * Largest PHY payload the MAC builds or accepts. The modem's largest transport
 * block is 5600 bits = 700 B (MCS 4 / 8 ss, MCS 3 / 11 ss, MCS 2 / 15 ss; Nordic's
 * TBS table, ETSI TS 103 636-3 5.3), so a long burst never carries more.
 */
#ifndef TDMA_PKT_MAX
#define TDMA_PKT_MAX 700
#endif
/* Largest SDU tdma_send() takes (fragmented over bursts). */
#ifndef TDMA_MAX_SDU
#define TDMA_MAX_SDU 1280
#endif
/* Bytes kept free in every packet when security is off (the old MIC reserve). */
#ifndef TDMA_MIC_RESERVE
#define TDMA_MIC_RESERVE 4
#endif
/*
 * Link security (docs/mac-design.md "Link security"): one AES-128-CCM MIC per
 * PHY packet, 4, 6 or 8 bytes, behind a 2-byte security header.
 */
#if defined(CONFIG_TDMA_MAC_SEC_MIC_LEN) && !defined(TDMA_SEC_MIC_LEN)
#define TDMA_SEC_MIC_LEN CONFIG_TDMA_MAC_SEC_MIC_LEN
#endif
#ifndef TDMA_SEC_MIC_LEN
#define TDMA_SEC_MIC_LEN 4
#endif
#if TDMA_SEC_MIC_LEN != 4 && TDMA_SEC_MIC_LEN != 6 && TDMA_SEC_MIC_LEN != 8
#error "TDMA_SEC_MIC_LEN must be 4, 6 or 8"
#endif
#define TDMA_SEC_HDR_LEN  2
#define TDMA_SEC_OVERHEAD (TDMA_SEC_HDR_LEN + TDMA_SEC_MIC_LEN)
#define TDMA_SEC_VERSION  1
/* FT deny list entries (rd ids refused at association). */
#ifndef TDMA_DENY_MAX
#define TDMA_DENY_MAX 16
#endif
/* Session keys a node keeps (current, announced next, previous, PT search cache). */
#define TDMA_SEC_SESS        6
/*
 * Selective-repeat window, PDUs. Links of plain plans use 8 (8-bit ack bitmap,
 * the v0 format); links of hybrid plans 16 (16-bit bitmap, TDMA_F_WIDE), so a
 * long burst can carry up to 16 fragments before the first ack comes back.
 */
#define TDMA_ARQ_WINDOW      8
#define TDMA_ARQ_WINDOW_WIDE 16
/* In-flight PHY ops tracked. */
#ifndef TDMA_MAX_OPS
#define TDMA_MAX_OPS 8
#endif

/* ---- air timing (ETSI TS 103 636, mu = 1) ------------------------------- */

#define TDMA_TICKS_PER_SEC      69120000u
#define TDMA_FRAME_TICKS        691200u /* 10 ms */
#define TDMA_SUBSLOT_TICKS      14400u  /* 208.33 us */
#define TDMA_SUBSLOTS_PER_FRAME 48u

#define TDMA_US_TO_TICKS(us) ((uint32_t)(((uint64_t)(us) * 6912u) / 100u))
#define TDMA_TICKS_TO_US(t)  ((uint64_t)(t) * 100u / 6912u)

/*
 * Measured on nRF9151 / mfw-nr+ 2.0.0 (docs/phy-timing.md):
 * an op must reach the modem >= 465 us (TX) / 390 us (RX) before it starts,
 * and "now" on the modem side is an extrapolation, so ops are committed 1 ms
 * ahead. The commit lead is also where a slot's payload is frozen.
 */
#define TDMA_PHY_LEAD_TX_TICKS TDMA_US_TO_TICKS(465)
#define TDMA_PHY_LEAD_RX_TICKS TDMA_US_TO_TICKS(390)
#ifndef TDMA_COMMIT_LEAD_TICKS
#define TDMA_COMMIT_LEAD_TICKS TDMA_US_TO_TICKS(1000)
#endif
/* Minimum idle between two ops of one device, in plan subslots (225-285 us). */
#define TDMA_MIN_OP_GAP_SS        2
/*
 * Ops on different carriers (hopping, background measurements, moves): the
 * PHY needed at most 10 us more idle than on one carrier (two DKs,
 *, 1703->1704 and 1705->1711; RX->TX 240 vs 230 us, TX->RX 250,
 * RX->RX 240, TX->TX 290 us either way). TDMA_MIN_OP_GAP_SS covers it;
 * tdma_plan_validate() checks that it still does.
 */
#define TDMA_PHY_GAP_MAX_US       290
#define TDMA_RETUNE_EXTRA_US      10
/* Minimum idle between UL bursts of different PTs inside one FT RX (4 DKs: 3 PTs, every slot used,
 * 0 errors). */
#define TDMA_UL_GUARD_SS          1
/*
 * Measured with long bursts on two DKs: the FT's TX failed
 * with 0x1005 when it started 2 ss after its UL-run RX and carried 700 B,
 * and (1 in 3) when a short TX started 3 ss after the end of a received
 * 8-subslot burst. Hybrid plans keep 3 ss from an UL run to a FLEX region
 * and 4 ss from a FLEX region to the next DL burst.
 */
#define TDMA_RX_TO_FLEX_SS        3
#define TDMA_FLEX_TO_DL_SS        4
/*
 * Received long burst -> the receiver's next op (plan H on the
 * DKs): 4 ss after a received 7 ss / 604 B burst the FT's short DL TX failed
 * with 0x1005 for ~4 % of the bursts under UL bulk, and the PT's DL RX after
 * a full DL long burst for ~16 %; 5 ss is the rule now. A FLEX region has two
 * extents: [subslot, +len) for a DL long burst or an UL one granted just in
 * time, and [subslot - ul_early, +ul_len) for an UL long burst granted a DL
 * period ahead (the PT commits it before it receives the DL burst in front);
 * each must end TDMA_LRX_TO_TX_SS before the receiver's next op.
 */
#define TDMA_LRX_TO_TX_SS         5
#define TDMA_LRX_MIN_SS           5 /* a burst this long counts as long */
/* An UL long burst starts at most this early: its PT commits it on the region's lead. */
#define TDMA_FLEX_UL_EARLY_MAX    2
/*
 * Plan switching (cfg.plan_auto): to the bulk plan after this many frames in
 * a row with one PT in bulk (a fragmented SDU in flight and >= TDMA_PKT_MAX
 * waiting, either way), back after this many without, at the earliest
 * TDMA_PLAN_DWELL_FRAMES after the last switch; announced in this many beacons.
 */
#define TDMA_PLAN_UP_FRAMES       5
#define TDMA_PLAN_DOWN_FRAMES     3
#define TDMA_PLAN_DWELL_FRAMES    20
#define TDMA_PLAN_ANNOUNCE_FRAMES 3
/*
 * Demand (cfg.plan_auto): per PT the SDU bytes queued to it (DL) and delivered
 * from it (UL) per frame, smoothed over ~16 frames (EWMA, 1/16 per frame). A
 * bulk plan (T, T2, T2D) goes back to the configured one only while the
 * busiest PT's demand is below TDMA_PLAN_DOWN_BYTES; the configured plan goes
 * to a bulk plan after TDMA_PLAN_UP_FRAMES frames of bulk with a demand of at
 * least TDMA_PLAN_UP_BYTES, after TDMA_PLAN_UP_SLOW_FRAMES below it. T2D
 * (one 2 ss UL slot per frame, ~117 B) only while the PT's UL demand is below
 * TDMA_T2D_UL_BYTES and its queue report below TDMA_PKT_MAX (also when the
 * plan is held: a held T2D becomes T2). A host-paced 75 kB/s flow (backlog now and then, never
 * for long) flapped H <-> T2 every ~250 ms on the backlog rule alone.
 */
#define TDMA_PLAN_DOWN_BYTES      450 /* per frame (45 kB/s): ~45 % of plan H's two long bursts */
#define TDMA_PLAN_UP_BYTES        250
#define TDMA_PLAN_UP_SLOW_FRAMES  15
#define TDMA_T2D_UL_BYTES         60
/* T2 has no UL slot to contend in: with a position free the FT leaves it for T this often */
#define TDMA_T2_MAX_FRAMES        500
/* plan BQ: after this many frames without a need for long bursts; at least this long in it */
#define TDMA_BQ_QUIET_FRAMES      20
#define TDMA_BQ_DWELL_FRAMES      2
#define TDMA_BQ_ANNOUNCE_FRAMES   1 /* a switch out of BQ: the next frame */
/* Train plans: an UL long burst of a PT that sends no bulk SDUs is at most this long. */
#define TDMA_TRAIN_SMALL_UL_SS    6
/*
 * A PT knows a grant this long after the end of the DL burst that carries it
 * (PDC event, open, records: ~0.8 ms on the DK with security). An UL burst
 * granted just in time may start early only when its commit still follows
 * that; one granted a DL period ahead always may.
 */
#define TDMA_GRANT_DECODE_TICKS   TDMA_US_TO_TICKS(600)
/*
 * FLEX bursts are committed this much earlier than other slots: handing a
 * 700 B payload to the modem took up to ~280 us on the DK (a 17 B one
 * ~120 us), on top of the 465 us TX lead.
 */
#ifndef TDMA_FLEX_EXTRA_LEAD_TICKS
#define TDMA_FLEX_EXTRA_LEAD_TICKS TDMA_US_TO_TICKS(500)
#endif
#define TDMA_FLEX_COMMIT_LEAD_TICKS (TDMA_COMMIT_LEAD_TICKS + TDMA_FLEX_EXTRA_LEAD_TICKS)
/* RX windows open this much before / close this much after the packet (>= 1 us works). */
#ifndef TDMA_RX_MARGIN_TICKS
#define TDMA_RX_MARGIN_TICKS TDMA_US_TO_TICKS(10)
#endif
/* Packet end -> PDU through the peer's MAC (PDC event 110-240 us measured). */
#ifndef TDMA_RX_PROC_TICKS
#define TDMA_RX_PROC_TICKS TDMA_US_TO_TICKS(250)
#endif
/* Search RX op length (continuous; deliberately not a frame multiple). */
#ifndef TDMA_SEARCH_RX_TICKS
#define TDMA_SEARCH_RX_TICKS (100u * TDMA_FRAME_TICKS + 3u * TDMA_SUBSLOT_TICKS)
#endif

/* ---- channel selection, LBT, interference monitoring (docs/mac-design.md) ---- */

/* One OFDM symbol at mu = 1 (41.67 us); the PHY's LBT works in symbols. */
#define TDMA_SYMBOL_TICKS 2880u
/* Carriers in the channel table / hop set (band 4 has 29: 524-552). */
#define TDMA_CH_TABLE     32
/* tdma_on_op_done() err of a TX whose LBT found the channel busy. */
#define TDMA_ERR_LBT_BUSY (-16) /* -EBUSY */
/* cfg value that switches a feature off (lbt_ticks, rach_lbt_ticks, mon_period). */
#define TDMA_OFF          0xffffffffu

/*
 * ETSI TS 103 636-4 V1.5.1, 5.1.2 and table 7.2-1 (band 9): a subslot is
 * "free" if max(RSSI-1) <= RSSI_THRESHOLD_MIN (-85 dBm), "busy" above
 * RSSI_THRESHOLD_MAX (-52 dBm - max TX power = -62 dBm at 10 dBm; Nordic's MAC
 * uses -71), "possible" between. SCAN_MEAS_DURATION is 24 slots (1 frame) per
 * channel, SCAN_SUITABLE 75 %.
 */
#define TDMA_DEF_RSSI_FREE_DBM      (-85)
#define TDMA_DEF_RSSI_BUSY_DBM      (-71)
#define TDMA_DEF_SUITABLE_PCT       75
#define TDMA_DEF_SCAN_FRAMES        10 /* auto channel: frames per carrier (beacons of slow FTs) */
#define TDMA_DEF_FIXED_SCAN_FRAMES  1  /* fixed channel: one SCAN_MEAS_DURATION */
/*
 * LBT before the first beacon on a channel (start, move): the PHY measures
 * this long right before the beacon (nrf_modem_dect_phy_tx lbt_period, 2..110
 * symbols). The spec's MINIMUM_LBT_PERIOD (random access) is STF + GI; we use
 * 2 subslots for the cluster start.
 */
#define TDMA_DEF_LBT_TICKS          (2u * TDMA_SUBSLOT_TICKS)
/* LBT of association requests (random access): 2 symbols >= STF + GI. */
#define TDMA_DEF_RACH_LBT_TICKS     (2u * TDMA_SYMBOL_TICKS)
#define TDMA_DEF_LBT_MAX_FAIL       4 /* busy LBTs in a row before another channel (auto) */
/* FT: RSSI measurement of an idle region of its own frame at least this often. */
#define TDMA_DEF_MON_PERIOD_FRAMES  10
/* Loaded-channel decision over this many frames (0.5 s); no automatic move for 2 windows after one.
 */
#define TDMA_DEF_MON_WINDOW_FRAMES  50
#define TDMA_DEF_MON_BUSY_PCT       25 /* busy subslots in a window -> move */
#define TDMA_DEF_MON_SNR_BAD_DB     6  /* every PT below this (and the channel not quiet) -> move */
#define TDMA_DEF_MOVE_FRAMES        10 /* a move is announced in this many beacons */
/* Every Nth monitor measurement goes to another carrier (background scan). */
#define TDMA_MON_BG_EVERY           4
/* PT search with channel 0: listen this long per carrier (> 1 beacon period). */
#define TDMA_DEF_SEARCH_DWELL_TICKS (3u * TDMA_FRAME_TICKS + 3u * TDMA_SUBSLOT_TICKS)

/* Runtime defaults (struct tdma_cfg field = 0 picks these). */
#define TDMA_DEF_BEACON_MISS_MAX      10 /* frames -> PT sync lost */
/*
 * With link security a PT that misses beacons but still receives verified DL
 * bursts from its FT (in DL slots: they also correct its frame timing) keeps
 * sync up to this many times beacon_miss_max frames without a beacon; it
 * loses sync beacon_miss_max frames after the last verified burst.
 */
#define TDMA_BEACON_MISS_DL_FACTOR    3
#define TDMA_DEF_UL_MISS_MAX          20 /* UL bursts -> FT frees the position */
#define TDMA_DEF_ARQ_MAX_TX           3  /* transmissions per PDU */
/* ARQ gives a PDU up this long after its first transmission (100 ms). */
#define TDMA_DEF_TX_LIFETIME_TICKS    (10u * TDMA_FRAME_TICKS)
#define TDMA_DEF_ASSOC_BACKOFF_FRAMES 8 /* random backoff 0..7 frames */
#define TDMA_DEF_ASSOC_WAIT_FRAMES    3 /* beacons to wait for our entry */
#define TDMA_DEF_ASSOC_MAX_ATTEMPTS   16

/* ARQ fallback retransmit timer when no peer burst judged a PDU. */
#define TDMA_ARQ_RTO_TICKS (2u * TDMA_FRAME_TICKS)
/* A peer's TDMA_F_HOLD lapses this long after the last PDU that carried it. */
#define TDMA_HOLD_TICKS    (4u * TDMA_FRAME_TICKS)

#define TDMA_RD_BROADCAST    0xffffffffu
#define TDMA_SHORT_BROADCAST 0xffffu

/* ---- PDU sizes (codec in tdma_pdu.h) ------------------------------------ */

#define TDMA_PHY_HDR_LEN      10
#define TDMA_REC_HDR_LEN      2 /* len + addr in front of every PDU in a packet */
#define TDMA_DATA_HDR_LEN     7 /* + 1 with a 16-bit ack bitmap (TDMA_F_WIDE) */
#define TDMA_FRAG_HDR_LEN     5
#define TDMA_ACK_LEN          4 /* + 1 with TDMA_F_WIDE */
#define TDMA_GRANT_FIXED_LEN  3
#define TDMA_GRANT_ENTRY_LEN  5
#define TDMA_MAX_GRANTS       4 /* entries per grant PDU */
#define TDMA_STATUS_LEN       6
/* A grant record (one entry) in a DL burst / a status record in an UL burst. */
#define TDMA_GRANT_REC_LEN    (TDMA_REC_HDR_LEN + TDMA_GRANT_FIXED_LEN + TDMA_GRANT_ENTRY_LEN)
#define TDMA_STATUS_REC_LEN   (TDMA_REC_HDR_LEN + TDMA_STATUS_LEN)
/* Longest burst (physical header packet_length, 4 bit, in subslots). */
#define TDMA_MAX_BURST_SS     16
#define TDMA_ASSOC_LEN        12
#define TDMA_BEACON_FIXED_LEN 18
#define TDMA_BEACON_ENTRY_LEN 3
/* An SDU must fit this many fragments of the link's guaranteed-burst size. */
#define TDMA_MAX_FRAGS        32

#define TDMA_SDU_PER_PDU_MAX (TDMA_PDU_MAX - TDMA_DATA_HDR_LEN)

/* Beacon security extension (TDMA_F_BSEC): ctr, rand, key idx, flags [+ next switch]. */
#define TDMA_BEACON_SEC_LEN          10
#define TDMA_BEACON_SEC_NEXT_LEN     12
/* Default frames a key / session switch is announced in beacons before it happens. */
#define TDMA_DEF_SEC_ANNOUNCE_FRAMES 100
/* A session is replaced (announced like a key switch) after this many frames. */
#define TDMA_DEF_SEC_SESSION_FRAMES  (0xffffffffu - 0xffffu)
/* PT: beacons in a row that fail to verify (or need a key it lacks) -> LOST(KEY). */
#define TDMA_DEF_SEC_BEACON_FAIL     5
/* MIC failures within one second -> TDMA_EVT_SEC_ALARM (once per second). */
#define TDMA_DEF_SEC_ALARM_FAILS     10

#if TDMA_PDU_MAX + TDMA_REC_HDR_LEN + TDMA_SEC_OVERHEAD > TDMA_PKT_MAX
#error "TDMA_PDU_MAX does not fit TDMA_PKT_MAX"
#endif
#if TDMA_PDU_MAX > 255
#error "a PDU record length is one byte"
#endif
#if TDMA_MAX_POSITIONS > 16
#error "position masks are 16 bit"
#endif
#if TDMA_TXQ_PDUS > 255 || TDMA_TXQ_ALL_SDUS > 255
#error "TX queue entries are indexed with uint8_t"
#endif
#if TDMA_TXQ_ALL_CHUNKS > 254 || TDMA_TXQ_CHUNK * TDMA_TXQ_CHUNKS < TDMA_MAX_SDU
#error "TDMA_TXQ_BYTES + TDMA_TXQ_PRIO_BYTES: 1 SDU .. 254 chunks"
#endif
#if TDMA_TX_SDU_INFLIGHT_TRAIN > TDMA_RAS_PER_LINK
#error "TDMA_TX_SDU_INFLIGHT_TRAIN: 1 .. TDMA_RAS_PER_LINK"
#endif
#if TDMA_TX_SDU_INFLIGHT < 1 || TDMA_TX_SDU_INFLIGHT > TDMA_RAS_PER_LINK
#error "TDMA_TX_SDU_INFLIGHT: 1 .. TDMA_RAS_PER_LINK"
#endif

/* ---- plans --------------------------------------------------------------- */

enum tdma_slot_use {
	TDMA_SLOT_BEACON,     /* FT DL burst that also carries the beacon (one per frame) */
	TDMA_SLOT_DL,         /* FT DL burst: PDUs for every PT, broadcast */
	TDMA_SLOT_UL,         /* PT at .pos -> FT; free position = contention */
	TDMA_SLOT_CONTENTION, /* PT -> FT association requests */
	/*
	 * On-demand region: per opportunity the FT gives it (in the grant record
	 * of the DL burst before it) to one long burst, DL to one PT or UL from
	 * one PT, of up to .len subslots at that link's MCS. Never overlaps a
	 * guaranteed slot; unused when nobody needs it.
	 */
	TDMA_SLOT_FLEX,
};

#define TDMA_PAT_REGIONS 5 /* FLEX regions a pattern plan may have */

struct tdma_slot {
	uint8_t subslot; /* first subslot within the frame, 0..47 */
	uint8_t len;     /* subslots (FLEX: of a DL long burst) */
	uint8_t use;     /* enum tdma_slot_use */
	uint8_t pos;     /* position for UL */
	/* FLEX: an UL long burst starts ul_early subslots before .subslot, up to ul_len (0 = len)
	 */
	uint8_t ul_early;
	uint8_t ul_len;
};

struct tdma_plan {
	uint8_t id; /* carried in the beacon */
	uint8_t n_positions;
	uint8_t n_slots;
	uint8_t mcs;                   /* default MCS (DL burst size is chosen for it) */
	const struct tdma_slot *slots; /* sorted by subslot, slots[0] = beacon */
	const char *name;
	uint8_t flags; /* TDMA_PLAN_F_* */
	/* TDMA_PLAN_F_PATTERN: per pattern and FLEX region, see tdma_pat_burst() */
	const int8_t (*pat)[TDMA_PAT_REGIONS];
	uint8_t n_pat;
};

/*
 * The FLEX regions are not granted one by one: per frame, the beacon of the
 * frame before gives them all to one PT as one of the plan's patterns
 * (direction and length per region; plans T2, T2D). The plan has no
 * guaranteed UL slots: tdma_plan_validate() checks every pattern instead.
 */
#define TDMA_PLAN_F_PATTERN 0x01
/* No FLEX region, but the hybrid plans' format (status records, wide acks, grant room) */
#define TDMA_PLAN_F_HYBRID  0x02
/*
 * HGX: every TDMA_OPEN_EVERY-th frame the last UL slot (position 0's second
 * one) is a contention slot instead (the plan's only position is taken, a
 * second node asks there; the relay then goes to HG), and the beacon never
 * says FULL.
 */
#define TDMA_PLAN_F_OPEN    0x04
#define TDMA_OPEN_EVERY     128u

#define TDMA_PLAN_A    0  /* default: 5 ms half-frames, 4 PTs (~7 ms worst case) */
#define TDMA_PLAN_1X10 1  /* one opportunity per frame, 10 PTs */
#define TDMA_PLAN_B    2  /* 2.5 ms quarter-frames, 2 PTs (<= 5 ms worst case) */
#define TDMA_PLAN_H    3  /* hybrid: 5 ms half-frames, 2 PTs + 10 ss flex region */
#define TDMA_PLAN_H4   4  /* hybrid: 5 ms half-frames, 4 PTs + 4 ss flex region */
#define TDMA_PLAN_T    5  /* bulk: plan H's first half, then a train of 3 x 8 ss long bursts */
#define TDMA_PLAN_T2   6  /* bulk, one PT: beacon, 4 x 8 ss in patterns of DL / UL (no UL slots) */
#define TDMA_PLAN_T2D  7  /* bulk DL, one PT: a 7 ss beacon burst, 3 x 8 ss DL, 2 ss UL */
#define TDMA_PLAN_BQ   8  /* idle: plan H's guaranteed block every 2.5 ms, 2 PTs, no FLEX */
#define TDMA_PLAN_T4   9  /* bulk, 4 PTs: DL 4 ss, 4 UL slots, then a train of 7 + 7 + 5 ss */
#define TDMA_PLAN_HG   10 /* a relay's child cluster: plan H's guaranteed slots, no FLEX (R1) */
#define TDMA_PLAN_HGX                                                                              \
	11 /* a relay's child cluster, one child, relay in the root's position 1: DL first */

/*
 * Relays (docs/mac-design.md "Relays"). A relay is a PT in
 * its parent's cluster (MAC instance "up") and the FT of a child cluster
 * ("down", plan HG). Every cluster's frame is aligned to the root's: a
 * child frame starts TDMA_RELAY_OFFSET_SS after its parent cluster's frame,
 * with the parent's frame number. Seen from the up instance's frame, the
 * radio is up's in the E blocks [0, 12) and [24, 36) and down's in the O
 * blocks [12, 24) and [36, 48) (tdma_relay_away()). Tree depth: the root's
 * cluster is depth 0, a node joined to a depth-d cluster has depth d + 1, at
 * most TDMA_MAX_DEPTH; only a node below that depth starts a child cluster.
 */
#define TDMA_RELAY_OFFSET_SS           14
/*
 * plan HG puts the DL burst last in its block (UL 17-21, DL 24-26):
 * under a root's cluster (DL 0-2 at the start of its blocks) the child frame
 * starts 19 ss later, so the child's blocks are the root frame's O blocks and
 * its DL bursts come 16 ss after the root's. Under another relay's cluster
 * (an HG frame) the offset is TDMA_RELAY_OFFSET_SS. An HG frame's blocks
 * start at its subslot TDMA_RELAY_BLOCK_ORIGIN_SS. 14 under
 * an HG frame (was 12): the depth-2 relay's child DL comes 14 ss after its
 * parent's DL (12 left it 0.1 ms to open that burst and seal its own: +5 ms
 * per hop down), its child's UL (position 0) 13 ss before its own UL (in
 * position 1 of its parent: the depth-2 blocks would cut into position 0's UL
 * slot, tdma_relay_plan_check() refuses it).
 */
#define TDMA_RELAY_ROOT_OFFSET_SS      19
#define TDMA_RELAY_BLOCK_ORIGIN_SS     17
/*
 * plan HGX (one child, the relay in position 1 of a root's plan H /
 * T / BQ) starts 15 ss after the root's frame: its DL burst (beacon) 15 ss
 * after the root's DL, its child's UL (root 20 / 44) 12 ss before the relay's
 * UL (32 / 8). Its blocks start at its subslot 45 (= root 12).
 */
#define TDMA_RELAY_HGX_OFFSET_SS       15
#define TDMA_RELAY_HGX_ORIGIN_SS       45
/*
 * A relay's parent-side DL RX commit lead (ticks): under a root 12.5 ss, before
 * its child's UL run and its child beacon's commit (at 12 ss both commits came
 * due together and the beacon burst reached the PHY late: 0x1000 / 0x1005);
 * under another relay's cluster 9 ss (was 11), after its
 * child's UL run (it ends 12 ss before) and before its own UL slot's quiet
 * window, without committing that UL slot early with it.
 */
#define TDMA_RELAY_CHILD_RX_LEAD_TICKS TDMA_US_TO_TICKS(1600)
#define TDMA_RELAY_RX_LEAD_TICKS(parent)                                                           \
	((parent) && (parent)->id == TDMA_PLAN_HG                                                  \
		 ? 9u * TDMA_SUBSLOT_TICKS                                                         \
		 : 12u * TDMA_SUBSLOT_TICKS + TDMA_SUBSLOT_TICKS / 2u)
#define TDMA_RELAY_BLOCK_SS 12
#define TDMA_MAX_DEPTH      3
/*
 * the route record a cluster's beacons carry for the mesh layer
 * (tdma_set_route(), opaque to the MAC; docs/mac-design.md "Relays").
 */
#ifndef TDMA_ROUTE_MAX
#define TDMA_ROUTE_MAX 12
#endif
/* the mesh layer's opaque beacon bytes (TDMA_BEXT_APP, tdma_set_beacon_ext()) */
#define TDMA_BEXT_APP_MAX    6
/* An arbiter window may be overrun by this much (RX margins, timing jitter). */
#define TDMA_RELAY_TOL_TICKS TDMA_US_TO_TICKS(40)

/*
 * Patterns: what FLEX region fi of a frame carries for the PT it is given to,
 * > 0: a DL burst of that many subslots, < 0: an UL burst of up to -n
 * subslots, 0: nothing. DL first, then UL (a direction change costs a
 * shorter DL burst: 5 ss from a received long burst to the PT's TX).
 */
#define TDMA_PAT_MAX 4 /* patterns per plan */
#define TDMA_T2_U4   0 /* T2: UL 8 8 8 8 */
#define TDMA_T2_D1U3 1 /* T2: DL 5, UL 8 8 8 */
#define TDMA_T2_D2U2 2 /* T2: DL 8 5, UL 8 8 */
#define TDMA_T2_D3U1 3 /* T2: DL 8 8 5, UL 8 */
#define TDMA_T2D_D3U 0 /* T2D: DL 8 8 8 (after the 7 ss beacon burst), UL 2 */
int8_t tdma_pat_burst(const struct tdma_plan *plan, uint8_t pattern, uint8_t fi);

const struct tdma_plan *tdma_plan_get(uint8_t id);
/*
 * 0 when the table is usable on the radio: sorted, inside the frame, beacon
 * first, every position has a UL slot, >= TDMA_MIN_OP_GAP_SS idle between
 * any two ops of the FT (DL bursts, the UL RX run) and of any PT (DL RX, its
 * UL / contention TX), >= TDMA_UL_GUARD_SS between UL bursts.
 */
int tdma_plan_validate(const struct tdma_plan *plan);
/* Worst-case gap between consecutive DL bursts (pos ignored) or UL bursts of pos. */
uint32_t tdma_plan_max_gap_ticks(const struct tdma_plan *plan, uint8_t pos, uint8_t use);
/* PHY payload bytes of one packet (physical header type 2), 0 if unsupported. */
uint16_t tdma_tbs(uint8_t mcs, uint8_t subslots);
/* Longest burst <= max_ss with a supported TBS at mcs that fits TDMA_PKT_MAX; 0 if none. */
uint8_t tdma_max_burst(uint8_t mcs, uint8_t max_ss);
/* Does the plan have FLEX regions (grants, status records), or their format (BQ)? */
bool tdma_plan_has_flex(const struct tdma_plan *plan);
/*
 * Whether the plan has FLEX trains: FLEX regions right after a FLEX region
 * (no DL burst between), announced by the same DL burst and given to the
 * same PT in the same direction as the first, 2 ss apart (TX -> TX and RX ->
 * RX of long packets, measured: docs/phy-timing.md).
 */
bool tdma_plan_has_train(const struct tdma_plan *plan);
/*
 * Whether a cluster can switch between plans a and b without re-associating:
 * the same positions and MCS, and the same slots up to the first FLEX region,
 * which starts at the same subslot (what a PT commits before it has decoded
 * the frame's beacon is the same in both).
 */
bool tdma_plan_compatible(const struct tdma_plan *a, const struct tdma_plan *b);

/*
 * Per-link MCS from the receive SNR (0.25 dB units, as the modem reports it):
 * highest MCS whose threshold the SNR clears, with hysteresis (drop only
 * TDMA_MCS_HYST_Q2 below the current MCS's threshold), capped at max.
 */
#define TDMA_MCS_HYST_Q2 12 /* 3 dB */
uint8_t tdma_mcs_select(uint8_t cur, int16_t snr_q2, uint8_t max);

/* ---- events -------------------------------------------------------------- */

enum tdma_evt_type {
	TDMA_EVT_FT_STARTED,    /* FT: beaconing (-> DECT_LINK_EVT_CLUSTER_CREATED) */
	TDMA_EVT_BEACON,        /* PT searching: beacon of our network (-> SCAN_RESULT) */
	TDMA_EVT_SYNCED,        /* PT: following .rd_id's frame timing */
	TDMA_EVT_ASSOCIATED,    /* PT: parent .rd_id gave us a position (-> JOINED) */
	TDMA_EVT_ASSOC_FAILED,  /* PT: gave up on .rd_id, .cause (-> JOIN_FAILED) */
	TDMA_EVT_LOST,          /* PT: parent .rd_id gone, .cause (-> UNJOINED) */
	TDMA_EVT_CHILD_ADDED,   /* FT: .rd_id at .pos (-> CHILD_ADDED) */
	TDMA_EVT_CHILD_REMOVED, /* FT: .rd_id, .cause (-> CHILD_REMOVED) */
	TDMA_EVT_STOPPED,       /* tdma_stop() finished (-> NETWORK_REMOVED / DEACTIVATED) */
	TDMA_EVT_SCAN_CLUSTER,  /* FT scan: beacon of another FT (.rd_id, .network_id, .channel) */
	TDMA_EVT_CHANNEL_SELECTED, /* FT scan done: beaconing on .channel after LBT */
	TDMA_EVT_LBT_BUSY,         /* FT: first beacon on .channel deferred, channel busy */
	TDMA_EVT_MOVE,             /* FT: announced / PT: heard a move to .channel, .cause */
	TDMA_EVT_CHANNEL,          /* FT / PT: now operating on .channel, .cause */
	/* security */
	TDMA_EVT_KEY_SWITCH, /* FT / PT: links now use key index .value (session switch at a frame)
			      */
	TDMA_EVT_KEY_ANNOUNCE, /* FT: announced / PT: heard a switch to key index .value at frame
				  .frame */
	TDMA_EVT_SEC_ALARM, /* .value MIC failures within a second; .rd_id = last short id seen, or
			       a duplicate rd */
	TDMA_EVT_RETIME,    /* FT / PT: the cluster's frames shifted (TDMA_F_RETIME) */
	TDMA_EVT_POS_MOVE,  /* FT / PT: .rd_id moved from position .value to .pos (compaction) */
	TDMA_EVT_PROBE,     /* PT: tdma_pt_probe() of .rd_id on .channel: .value 1 heard (.rssi,
			       .snr_q2), 0 not */
	/*
	 * FT (tdma_ft_scan()): a beacon heard on .channel (any network,
	 * .network_id): FT .rd_id, .value as TDMA_EVT_BEACON's, .route / .app as
	 * it beacons them (cleartext: not verified, information only)
	 */
	TDMA_EVT_FT_SCAN,
	TDMA_EVT_FT_SCAN_DONE, /* FT: the listen on .channel ended: .value beacons heard | other
				  PCCs << 16; .cause STOPPED: not placed */
};

enum tdma_cause {
	TDMA_CAUSE_NONE,
	TDMA_CAUSE_SYNC_LOST,    /* PT: beacon_miss_max beacons missed */
	TDMA_CAUSE_RELEASED,     /* PT: FT no longer lists us */
	TDMA_CAUSE_FT_CLOSED,    /* PT: FT beacons with the CLOSING flag */
	TDMA_CAUSE_PLAN_CHANGED, /* PT: FT switched plans */
	TDMA_CAUSE_UL_TIMEOUT,   /* FT: ul_miss_max UL bursts missed */
	TDMA_CAUSE_REASSOC,      /* FT: child re-associated (new session) */
	TDMA_CAUSE_STOPPED,      /* local tdma_stop() / new target */
	TDMA_CAUSE_FULL,         /* PT: FT has no free position */
	TDMA_CAUSE_NO_RESPONSE,  /* PT: assoc_max_attempts requests unanswered */
	TDMA_CAUSE_INTERFERENCE, /* FT: own channel measured busy (monitor) */
	TDMA_CAUSE_POOR_SNR,     /* FT: every PT reports poor SNR on a non-quiet channel */
	TDMA_CAUSE_CMD,          /* tdma_ft_move() by the user */
	TDMA_CAUSE_LBT,          /* FT: LBT kept failing on the channel */
	TDMA_CAUSE_KEY,          /* PT: the FT's beacons do not verify / use a key we lack */
	TDMA_CAUSE_REVOKED,      /* FT: rd id on the deny list */
	TDMA_CAUSE_DUP_ID,       /* FT alarm: one rd id associating from two radios */
};

struct tdma_evt {
	enum tdma_evt_type type;
	uint32_t rd_id;
	uint32_t network_id;
	enum tdma_cause cause;
	int16_t rssi;
	uint8_t pos;
	uint16_t channel;
	uint32_t value; /* security events: key index / failure count */
	uint32_t frame; /* KEY_ANNOUNCE: switch frame */
	/* BEACON: link quality and the route record (valid during the callback only) */
	int16_t snr_q2;
	uint8_t tx_power; /* the FT's physical header transmit power index */
	uint8_t route_len;
	const uint8_t *route;
	/* FT_SCAN: the beacon's TDMA_BEXT_APP bytes (valid during the callback only) */
	uint8_t app_len;
	const uint8_t *app;
};

typedef void (*tdma_evt_cb_t)(const struct tdma_evt *evt, void *user);

/* ---- configuration --------------------------------------------------------- */

enum tdma_role {
	TDMA_ROLE_FT,
	TDMA_ROLE_PT,
};

struct tdma_peer;
struct tdma_ras;

/*
 * Storage of an instance's peers (links, TX queues) and reassembly buffers,
 * owned by the caller (tdma_cfg.mem). An FT uses peers[pos] for position pos,
 * so a plan needs n_peers >= its positions; a PT uses peers[0] only. The first
 * n_big peers get TDMA_TXQ_ALL_CHUNKS of qmem each (the deep queues of the
 * train / whole-frame plans), the others TDMA_TXQ_SMALL_CHUNKS: qmem holds
 * tdma_mem_chunks(n_peers, n_big) chunks. struct tdma_mac_store is the full
 * set (TDMA_MAX_POSITIONS peers); a relay's two instances share one
 * (tdma_mem_split(), docs/mac-design.md "Relays").
 */
struct tdma_mem {
	struct tdma_peer *peers;
	uint8_t n_peers;
	uint8_t n_big;
	uint8_t (*qmem)[TDMA_TXQ_CHUNK];
	uint16_t n_chunks;
	struct tdma_ras *ras;
	uint8_t n_ras;
};

struct tdma_cfg {
	enum tdma_role role;
	uint32_t rd_id;      /* long radio device id of this node */
	uint32_t network_id; /* network id; low byte = short network id */
	uint8_t box_id;
	/*
	 * Carrier. FT: 0 = choose by RSSI scan over ch_min..ch_max (and move
	 * away from interference), else this one only. PT: 0 = search every
	 * carrier in ch_min..ch_max, else this one.
	 */
	uint16_t channel;
	uint16_t ch_min, ch_max;
	/* carriers of ch_min..ch_max that may be used (bit i = ch_min + i); 0 = all */
	uint32_t ch_mask;
	uint16_t pref_channel; /* channel 0: taken when suitable (0 = none) */
	/*
	 * Frequency hopping (channel 0 only): the FT hops every frame over the
	 * carriers of ch_mask its scan found usable (a per-cycle permutation
	 * seeded from network id + FT session, announced in every beacon);
	 * PTs search each carrier for (set size + 1) frames.
	 */
	bool hop;
	/*
	 * FT, hybrid plans: grant each FLEX region in the DL burst one DL
	 * period before it (TDMA_GRANT_F_AHEAD) instead of the one right before.
	 * Costs a DL period of bulk latency; needed when verifying the DL burst
	 * and sealing the long burst take longer than the plan leaves between
	 * them (link security in a secure partition, docs/mac-design.md "Link security"). An FT
	 * also turns it on by itself when the cost model of tdma_sec_ops says so.
	 */
	bool grant_ahead;
	uint8_t mcs;     /* FT: 0 = plan default; PTs use the MCS the beacon announces */
	uint8_t plan_id; /* FT: TDMA_PLAN_*; PT learns it from the beacon */
	/*
	 * FT: switch between plan_id and the bulk plan TDMA_PLAN_T by demand
	 * (one PT in sustained bulk -> T, idle -> back), announced in the
	 * beacons; PTs follow without re-associating (the plans must be
	 * tdma_plan_compatible()).
	 */
	bool plan_auto;
	/* FT, plan_auto: T2 (whole-frame trains) for a single active PT */
	bool plan_t2;
	/* FT, plan_auto with plan H: BQ (H's guaranteed slots every 2.5 ms) while idle */
	bool plan_bq;
	/*
	 * FT, plan_auto: a plan with more positions (H4) while 2 or more PTs are
	 * associated, so that one more can join (with 2 PTs plan H is full);
	 * the configured plan and its bulk / idle plans again once one PT (in
	 * one of its positions) is left. 0 = none.
	 */
	uint8_t plan_multi;
	/*
	 * Ticks the commit lead of short TX slots is cut by (at most half of
	 * TDMA_COMMIT_LEAD_TICKS): a PT's own UL slot, an FT's DL bursts but the
	 * beacon (whose build is the longest). From measured build + seal
	 * times; every tick is one-way latency.
	 */
	uint32_t ul_lead_trim, dl_lead_trim;
	/* PT: FT to sync to. 0 = first FT of our network; TDMA_RD_BROADCAST =
	 * none (scan only: just TDMA_EVT_BEACON per beacon heard).
	 */
	uint32_t ft_rd_filter;
	uint32_t seed; /* backoff PRNG seed; 0 = derive from rd_id */

	tdma_evt_cb_t evt_cb;
	void *evt_user;

	/* 0 = TDMA_DEF_* */
	uint16_t beacon_miss_max;
	uint16_t ul_miss_max;
	uint8_t arq_max_tx;
	uint32_t tx_lifetime_ticks;
	uint8_t assoc_backoff_frames;
	uint8_t assoc_wait_frames;
	uint8_t assoc_max_attempts;

	/* channel selection / LBT / monitoring; 0 = TDMA_DEF_*, TDMA_OFF = off */
	uint8_t scan_frames;       /* auto: frames per carrier */
	uint8_t fixed_scan_frames; /* fixed channel: frames scanned before the first beacon */
	int8_t rssi_free_dbm;
	int8_t rssi_busy_dbm;
	uint8_t suitable_pct;
	uint32_t lbt_ticks;      /* first beacon on a channel */
	uint32_t rach_lbt_ticks; /* PT association requests */
	uint8_t lbt_max_fail;
	uint32_t mon_period; /* frames */
	uint16_t mon_window; /* frames */
	uint8_t mon_busy_pct;
	int8_t mon_snr_bad_db; /* TDMA_SNR_OFF = no SNR trigger */
	uint8_t move_frames;
	uint32_t search_dwell_ticks;

	/* link security (only with port->sec; 0 = TDMA_DEF_*) */
	uint32_t sess_ctr; /* FT: session counter of this start (persisted by the app; 0 -> 1) */
	bool sec_devkey;   /* running on the insecure dev key: beacons say so, PTs must match */
	uint16_t sec_announce_frames;
	uint32_t sec_session_frames;
	uint8_t sec_beacon_fail;
	uint16_t sec_alarm_fails;
	uint32_t start_frame; /* FT: number of the first frame (tests: counter wrap) */

	/*
	 * Relays. PT: ask the parent for a relay position (TDMA_AF_RELAY: no
	 * FLEX grants, no plan without slots for us). FT: this is a relay's
	 * child cluster on plan HG: no channel scan (cfg.channel is fixed), the
	 * frame timing comes from tdma_ft_follow(), the beacons carry the tree
	 * extension (depth, grid offset).
	 */
	bool relay;
	uint8_t depth; /* FT relay: depth of the cluster (= the relay's own, 1..) */

	/* peer / queue / reassembly storage (required) */
	struct tdma_mem mem;
};

#define TDMA_SNR_OFF (-128)

/* One carrier as last measured (scan or background measurement). */
struct tdma_chan_info {
	uint16_t ch;
	bool valid;
	uint16_t n_ss; /* measured subslots (halved when large, so recent counts more) */
	uint16_t n_free, n_poss, n_busy;
	int8_t max_dbm;        /* highest subslot RSSI-1 */
	uint16_t w_ss, w_busy; /* FT monitor: current window */
	int8_t w_max;
	uint8_t quiet_win; /* FT, hopping: windows in a row it was measured without a busy subslot
			    */
	uint8_t clusters;  /* PCCs of other radios heard while scanning it (saturating) */
	int8_t cluster_dbm;
	uint32_t cluster_rd; /* last beacon of ours-format heard there */
	uint32_t cluster_nwid;
	uint32_t frame; /* FT frame of the last update */
};

struct tdma_stats {
	uint32_t beacons_tx;
	uint32_t beacons_rx;
	uint32_t dl_bursts_tx; /* FT DL bursts incl. beacon bursts */
	uint32_t pdus_tx;      /* data PDUs incl. retransmissions */
	uint32_t pdus_rx;      /* new data PDUs */
	uint32_t acks_tx;      /* ack-only PDUs */
	uint32_t retx;
	uint32_t dup_rx;
	uint32_t drop_retries;  /* PDUs given up after arq_max_tx */
	uint32_t drop_lifetime; /* PDUs still unacked tx_lifetime after first TX */
	uint32_t sdu_tx_ok;     /* SDUs whose every PDU was acked */
	uint32_t sdu_tx_drop;   /* SDUs lost to a PDU drop */
	uint32_t sdu_rx;        /* SDUs delivered */
	uint32_t ras_full;      /* fragments not taken: no reassembly buffer free (resent) */
	uint32_t bad_rx;        /* malformed / CRC / wrong ids */
	uint32_t late_slots;    /* slots skipped because the MAC ran late */
	uint32_t port_errors;   /* rx/tx ops the platform refused or failed */
	uint32_t assoc_tx;      /* association requests sent (PT) / received (FT) */
	uint32_t ops_hwm;       /* most ops in flight at once */
	/* hybrid plans */
	uint32_t grants_dl;        /* FT: flex regions given to a DL burst */
	uint32_t grants_ul;        /* FT: flex regions given to a PT on its demand */
	uint32_t grants_spec;      /* FT: flex regions given to a PT speculatively */
	uint32_t grants_ahead;     /* of grants_ul: given a DL period ahead (early UL burst) */
	uint32_t flex_tx;          /* long bursts sent */
	uint32_t flex_rx;          /* long bursts received */
	uint32_t flex_miss;        /* FT: demanded UL grant with nothing received */
	uint32_t flex_ahead_empty; /* FT: an UL region granted a period ahead stayed empty */
	uint32_t flex_tx_early;    /* PT: UL long bursts sent early (granted a period ahead) */
	uint32_t mcs_changes;      /* FT: per-link MCS changes */
	/* channel access */
	uint32_t scans;         /* carriers scanned (FT channel selection) */
	uint32_t lbt_ok;        /* first beacons sent after a free LBT */
	uint32_t lbt_busy;      /* TXs dropped by LBT (beacon or association request) */
	uint32_t meas;          /* FT: own-channel monitor measurements */
	uint32_t meas_bg;       /* FT: background measurements of other carriers */
	uint32_t moves;         /* channel changes (FT: announced, PT: followed) */
	uint32_t plan_switches; /* plan changes without re-association (FT: made, PT: followed) */
	uint32_t plan_held;     /* FT: frames a bulk plan was kept for its demand (plan_auto) */
	uint32_t plan_multi;    /* FT: switches to cfg.plan_multi (several PTs) */
	uint32_t plan_unannounced; /* PT: switches learnt from the beacon of the new plan's frame */
	uint32_t beacon_bridged;   /* PT: beacon slots past beacon_miss_max kept by verified DL */
	uint32_t dl_resync;        /* PT: timing corrections from verified DL-slot bursts */
	uint32_t psw_log[8];       /* the last switches: frame << 4 | new plan (debug) */
	/* plans T2, T2D: frames per pattern (FT: given, PT: heard) */
	uint32_t pat_frames[2][TDMA_PAT_MAX];
	uint8_t mon_busy_pct;  /* FT: busy subslots in the last finished window */
	int8_t mon_max_dbm;    /* FT: highest subslot RSSI in that window */
	uint8_t move_busy_pct; /* FT: busy % of the window that triggered the last automatic move */
	uint32_t hop_drops;    /* FT: carriers dropped from the hop set (interference) */
	uint32_t hop_adds;     /* FT: carriers taken back */
	/* link security */
	uint32_t sec_sealed;   /* bursts sealed */
	uint32_t sec_opened;   /* bursts that verified */
	uint32_t sec_mic_fail; /* bursts dropped: MIC did not verify */
	uint32_t sec_foreign;  /* bursts of another transmitter in a slot of ours (not verified) */
	uint32_t sec_bad_hdr;  /* bursts dropped: no / malformed security header */
	uint32_t sec_no_key;   /* bursts / beacons under a key index we do not hold */
	uint32_t sec_stale;    /* verified beacons refused as replayed / old session */
	uint32_t sec_devkey;   /* beacons refused: dev-key flag differs from ours */
	uint32_t sec_seal_err; /* bursts not sent: seal failed (never sent in clear) */
	uint32_t sec_derive;   /* session keys derived */
	uint32_t sec_denied;   /* FT: association requests refused by the deny list */
	uint32_t sec_assoc_reject; /* FT: association requests that did not verify */
	uint32_t sec_switches;     /* key / session switches done */
	uint32_t sec_alarms;       /* TDMA_EVT_SEC_ALARM emitted */
	/* relays */
	uint32_t relay_away; /* slots not committed: the radio was the other instance's (port.away)
			      */
	uint32_t follow_jumps;    /* FT relay: frame timing corrections > TDMA_RELAY_TOL_TICKS */
	uint32_t follow_renumber; /* FT relay: the parent's frame counter jumped (new session) */
	/* backpressure (TDMA_F_HOLD, tdma_link_hold()) */
	uint32_t hold_on;    /* links we asked to hold (off -> on) */
	uint32_t hold_waits; /* bursts that started no new bulk SDU: the peer held */
	/* */
	uint32_t retimes;   /* timing shifts applied (TDMA_F_RETIME) */
	uint32_t pos_moves; /* FT: PTs moved to another position; PT: moves followed */
	uint32_t room_asks; /* FT on HGX: association requests in an open frame */
	uint32_t probes,
		probes_heard; /* PT: tdma_pt_probe() listens done / that heard the cluster */
	uint32_t
		queue_resets; /* links reset: their queue memory was inconsistent (should stay 0) */
	uint32_t fast_searches; /* PT: searches on a known carrier (tdma_pt_set_target_ch) */
	/*  (FT, tdma_ft_scan()) */
	uint32_t fs_scans;   /* listens done */
	uint32_t fs_beacons; /* beacons heard in them (any network) */
	uint32_t fs_skipped; /* own slots left out for them (ops not committed) */
	uint32_t
		fs_quiet; /* PT: slots left out while the FT listened elsewhere (TDMA_BEXT_QUIET) */
};

/* ---- instance state (treat as private) ------------------------------------ */

enum tdma_state {
	TDMA_ST_IDLE,
	TDMA_ST_FT,          /* FT running */
	TDMA_ST_FT_SCAN,     /* FT: scanning carriers before the first beacon */
	TDMA_ST_SEARCH,      /* PT: continuous RX for a beacon */
	TDMA_ST_ASSOCIATING, /* PT: synced, asking for a position */
	TDMA_ST_ASSOCIATED,  /* PT: has a position */
};

enum tdma_txe_state {
	TDMA_TXE_FREE,
	TDMA_TXE_UNSENT, /* part of an SDU cut off a retransmission: sent with a new seq */
	TDMA_TXE_INFLIGHT,
};

/* One data PDU in flight (bytes [off, off + len) of an SDU), or a part waiting to be resent. */
struct tdma_txe {
	uint8_t state;
	uint8_t seq;
	uint8_t tries;
	bool need_retx;
	bool frag;
	uint8_t sdu; /* index into tdma_link.sdu[] */
	uint16_t off;
	uint16_t len;
	uint64_t first_tx; /* start of its bytes' first transmission; lifetime runs from here */
	uint64_t tx_start;
	uint64_t tx_end;
};

/* One queued SDU; its bytes live in the link's chunks (first_chunk, chunk_next[]). */
struct tdma_txsdu {
	bool used;
	bool prio;
	bool own;  /* prio TDMA_PRIO_OWN: ahead of other priority SDUs not started yet */
	bool frag; /* goes out in fragments (decided when the first one is cut) */
	bool started;
	uint8_t tag;
	uint8_t first_chunk;
	uint16_t len;
	uint16_t next;  /* bytes [0, next) went into a PDU at least once */
	uint16_t acked; /* bytes acked */
};

/* A reassembly buffer (shared by the peers of a MAC instance). */
struct tdma_ras {
	uint8_t owner; /* peer index + 1, 0 = free */
	uint8_t tag;
	uint16_t total;
	uint16_t have; /* TDMA_FRAG_ALIGN units received */
	bool complete; /* held until the SDUs before it are delivered or given up */
	uint64_t touched;
	uint32_t map[(TDMA_MAX_SDU / TDMA_FRAG_ALIGN + 31) / 32];
	uint8_t buf[TDMA_MAX_SDU];
};

/* Per-peer link: TX queue + ARQ sender, RX duplicate filter (reassembly: struct tdma_ras). */
struct tdma_link {
	struct tdma_txsdu sdu[TDMA_TXQ_ALL_SDUS];
	uint8_t order[TDMA_TXQ_ALL_SDUS]; /* queue order of sdu[] indices (priority first) */
	uint8_t n_sdu;
	uint8_t n_prio; /* priority SDUs queued, and the chunks they hold */
	uint8_t prio_chunks;
	struct tdma_txe pdu[TDMA_TXQ_PDUS];
	uint8_t free_head; /* free chunks: a list through chunk_next[] */
	uint8_t n_free;
	uint8_t n_chunks; /* chunks of this link (TDMA_TXQ_ALL / _SMALL_CHUNKS) */
	uint8_t chunk_next[TDMA_TXQ_ALL_CHUNKS];
	uint8_t (*chunk)[TDMA_TXQ_CHUNK]; /* n_chunks of struct tdma_mac's qmem, set by tdma_init */
	uint64_t exp_now;                 /* link_build() expired the queue at this time */
	bool exp_valid;
	bool blocked; /* the last enqueue found the queue full: more is waiting outside */
	uint8_t next_seq;
	uint8_t next_tag;
	uint8_t pdu_cap;     /* largest PDU this link's bursts always carry */
	bool wide;           /* 16-bit ack bitmap, window TDMA_ARQ_WINDOW_WIDE (hybrid plans) */
	uint8_t bulk_chunks; /* chunks normal SDUs may hold (TDMA_TXQ_STD_CHUNKS, all on trains) */
	uint8_t bulk_want;   /* what link_set_cap() asked for (bulk_chunks: within n_chunks) */
	uint8_t inflight;    /* fragmented SDUs in flight (TDMA_TX_SDU_INFLIGHT[_TRAIN]) */
	uint8_t rx_inflight; /* the peer's tag window as a receiver (the largest it may use) */

	bool rx_valid;
	uint8_t rx_hi;       /* highest seq received */
	uint32_t rx_map;     /* bit i: seq rx_hi-1-i received (16 bits go on air) */
	uint8_t ack_dirty;   /* bursts that should still carry our ack */
	uint8_t done_tag[4]; /* tags of the last fragmented SDUs delivered (late fragments) */
	uint8_t done_n, done_i;
	bool rx_tag_valid;
	uint8_t rx_tag_hi;   /* newest fragmented SDU tag seen from the peer */
	uint8_t rx_tag_next; /* oldest tag not delivered: fragmented SDUs go up in tag order */
	/* backpressure (TDMA_F_HOLD): we ask the peer to hold; the peer asked us (when last) */
	bool hold_tx;
	bool peer_hold;
	uint64_t peer_hold_t;
	bool corrupt; /* its chunk lists were found inconsistent: reset at the next use */
};

/* FT: an UL grant, remembered so a later-arriving older status is not counted twice. */
struct tdma_grant_log {
	uint64_t start;
	uint16_t cap;
};

#define TDMA_GRANT_LOG 6

struct tdma_peer {
	uint32_t rd_id; /* 0 = position free */
	uint8_t nonce;  /* association session id from the PT */
	bool announced; /* FT: a beacon listing it went out */
	uint32_t dl_from_frame;
	uint16_t ul_miss;
	bool ul_missed_last;
	/* FT, hybrid plans: the PT's last reported queue and our grants since */
	uint16_t bsr;
	uint64_t bsr_t; /* start of the burst that carried it */
	struct tdma_grant_log glog[TDMA_GRANT_LOG];
	uint8_t glog_i;
	/* FT: per-link MCS for long bursts (UL from our SNR, DL from the PT's report) */
	int16_t ul_snr_q4; /* EWMA, 1/16 dB */
	int16_t dl_snr_q4;
	uint8_t n_ul_snr, n_dl_snr;
	int8_t ul_rssi; /* FT: dBm of its last guaranteed UL burst */
	int8_t dl_rssi; /* FT: dBm of our bursts at the PT (its last status record) */
	uint8_t mcs_ul, mcs_dl;
	uint8_t flex_fail;
	bool reply_hint; /* FT: an SDU from it was just delivered; a reply may follow */
	bool ul_bulk;    /* FT: its last UL long burst carried a long fragment (bulk SDUs) */
	bool ul_full;    /* FT: ... and was full (plan_auto: the PT is in bulk) */
	/* FT, plan_auto: SDU bytes this frame and their EWMA (bytes per frame x 16), DL / UL */
	uint32_t dem_acc[2];
	uint32_t dem_q4[2];
	uint32_t assoc_frame; /* FT: frame of the (re)association */
	uint8_t reassoc_fast; /* FT: re-associations soon after the previous one (duplicate rd id)
			       */
	uint16_t sec_fail;    /* FT: MIC failures of bursts in this PT's slots */
	bool relay;  /* FT: the PT runs a child cluster (TDMA_AF_RELAY): no FLEX, keep its slots */
	bool hgx_ok; /* FT: that child cluster could run HGX: the relay wants position 1
			(TDMA_STF_HGX) */
	struct tdma_link link;
};

/* A security session: key index + (FT, counter, random), and the platform's key handle. */
struct tdma_sec_sess {
	bool valid;
	uint8_t idx;
	uint32_t ft, ctr, rnd;
	uint32_t handle;
	uint32_t used; /* LRU stamp (PT cache) */
};

struct tdma_sec_state {
	bool on;
	int8_t cur, next, prev; /* indices into sess[], -1 = none */
	uint32_t next_frame;    /* next becomes current from this frame */
	uint32_t prev_switch;   /* prev is the session of frames before this one */
	uint32_t prev_until;    /* FT: prev still opens UL of frames before this (grace) */
	uint32_t sess_start;    /* FT: first frame of the current session */
	uint32_t stamp;
	struct tdma_sec_sess sess[TDMA_SEC_SESS];
	/* PT: highest session counter seen per FT this boot (beacon freshness) */
	struct {
		uint32_t ft, ctr, frame; /* frame: last beacon accepted in session ctr */
	} seen[4];
	uint8_t seen_rr;
	uint8_t beacon_fail; /* PT: beacons in a row that did not verify */
	uint64_t win_t;      /* alarm window start (ticks) */
	uint16_t win_fail;
	bool win_alarmed;
	uint16_t last_short; /* tx short id of the last burst that failed */
	uint32_t deny[TDMA_DENY_MAX];
	uint8_t n_deny;
	uint8_t aad[TDMA_PHY_HDR_LEN + TDMA_SEC_HDR_LEN + 255 + TDMA_REC_HDR_LEN];
};

/* A long burst in a FLEX region: FT's decision, or a grant a PT received. */
struct tdma_flex {
	bool valid;
	bool ul;      /* PT -> FT */
	bool spec;    /* given without demand: the PT sends only if it has data */
	uint8_t slot; /* plan index of the FLEX slot */
	uint8_t pos;
	uint8_t len; /* subslots */
	uint8_t mcs;
	uint8_t early; /* UL: subslots before the region's start (slot ul_early) */
	bool ahead;    /* UL, granted one DL period ahead (a busy PT): sent only if there is data */
	bool early_commit; /* PT: committed before the DL burst in front (uses the early extent) */
	uint32_t frame;
	uint32_t rd; /* FT: the PT it was given to */
	bool meas;   /* FT: kept free for an RSSI measurement on .ch */
	uint16_t ch;
};

#define TDMA_FLEX_SLOTS 5
typedef char tdma_pat_regions_check[TDMA_FLEX_SLOTS >= TDMA_PAT_REGIONS ? 1 : -1];

struct tdma_op {
	bool used;
	const struct tdma_plan *plan; /* the plan its slot indices refer to (a switch may come) */
	uint8_t use;                  /* enum tdma_slot_use of the first slot, or 0xff = search */
	uint8_t slot;                 /* plan index of the first slot */
	uint8_t slot_end;             /* FT UL run: plan index of the last slot */
	bool is_tx;
	uint32_t handle;
	uint32_t frame;
	uint32_t got;                        /* FT UL run: positions heard; PT: DL received */
	uint32_t owners[TDMA_MAX_POSITIONS]; /* FT UL run: rd per position when committed */
	uint64_t start;                      /* nominal start of the first slot */
	struct tdma_flex flex;               /* FLEX ops: the long burst */
	uint16_t ch;                         /* carrier */
	bool lbt;                            /* TX with listen before talk */
	/* FT: speculative UL region received with RSSI (port scan op): a free
	 * measurement of the own channel when nobody transmitted in it */
	bool mon;
	bool heard;
	uint16_t m_ss, m_busy;
	int8_t m_max;
};

#define TDMA_LC_SLOTS 32

/*
 * Constants of the commit-lead model for the plan in use (tdma_mac.c, lc()),
 * recomputed whenever one of the inputs it was computed from changes: the
 * MAC thread evaluates the lead of every slot on every wakeup.
 */
struct tdma_lead_cache {
	bool valid;
	const struct tdma_plan *plan;
	const struct tdma_sec_ops *sec;
	uint32_t sb, sp, ob, op; /* the cost model it was computed with */
	uint8_t mcs;
	bool pt, ahead, on;
	bool relay; /* cfg.relay (a relay PT's DL RX leads, no FLEX) */
	bool hints;
	uint32_t open_cost, clear_max;
	uint8_t fidx[TDMA_LC_SLOTS];    /* flex index of each slot */
	uint8_t fslot[TDMA_FLEX_SLOTS]; /* slot of each flex index */
	uint8_t n_flex;
	uint32_t slead[TDMA_LC_SLOTS]; /* sec_lead() of each slot */
	uint32_t flex_cut;             /* PT: what sec_lead() takes off a FLEX region's seal lead */
	int8_t pos;                    /* PT: own position (-1: not associated) */
	uint32_t ul_trim, dl_trim;     /* cfg.ul_lead_trim / dl_lead_trim it was computed with */
	uint32_t trim[TDMA_LC_SLOTS];  /* what each slot's commit lead is cut by (lead_trim()) */
	uint32_t gen;                  /* bumped on every recomputation */
};

/*
 * Everything besides the lead cache that the commit leads of frames F and
 * F + 1 depend on (F = the frame being scheduled): the LBT state of the
 * beacon, and the air length of what may be received in each FLEX region of
 * frames F - 1 .. F + 1 (a granted burst may be shorter than its region).
 */
struct tdma_lead_in {
	bool lbt_pending, move_valid;
	bool child_hgx; /* (relay_rx_lead()) */
	uint32_t move_frame;
	uint8_t flex_len[3][TDMA_FLEX_SLOTS]; /* [frame - (F - 1)][flex index] */
	uint8_t ul_ahead[3]; /* PT: bit fi: its UL burst in FLEX fi was granted a period ahead */
};

/*
 * Commit leads of the slots of frames F (row 0) and F + 1 (row 1) for
 * next_commit(); bit i of have[row] = lead[row][i] computed. Cleared when
 * F or an input changes.
 */
struct tdma_lead_memo {
	bool valid;
	uint32_t frame;
	uint32_t lc_gen;
	struct tdma_lead_in in;
	uint32_t have[2];
	uint32_t lead[2][TDMA_LC_SLOTS];
};

struct tdma_mac {
	struct tdma_cfg cfg;
	struct tdma_port port;
	const struct tdma_plan *plan;
	enum tdma_state state;
	uint32_t rng;
	uint8_t mcs; /* in use (FT: cfg or plan, PT: from the beacon) */

	/* frame timing: frame ref_frame starts at ref_start (own clock) */
	uint64_t ref_start;
	uint32_t ref_frame;
	/* next slot to commit */
	uint32_t cur_frame;
	uint8_t cur_slot;

	struct tdma_op ops[TDMA_MAX_OPS];
	uint8_t n_ops;
	uint32_t next_handle;
	uint32_t search_handle; /* 0 = no search op */
	uint64_t retry_at;      /* search RX could not be started: try again */

	/* FT */
	uint8_t roster_ver;
	uint8_t dl_rr;   /* round robin start for DL burst filling */
	uint8_t flex_rr; /* round robin over flows (DL k, UL k) for FLEX regions */
	/* FT, train plans: the last frame flow (DL k, UL k) had a train */
	uint32_t flow_frame[2 * TDMA_MAX_POSITIONS];
	uint8_t spec_rr; /* round robin for speculative UL grants */
	bool flex_plan;  /* plan has FLEX regions */
	bool train_plan; /* ... and FLEX trains (back-to-back regions, one DL burst) */
	/* plan switch (FT: announced, PT: heard) to psw_plan at frame psw_frame */
	bool psw_valid;
	uint8_t psw_plan;
	uint32_t psw_frame;
	uint8_t base_plan;   /* FT: cfg.plan_id, where plan_auto returns to */
	uint32_t plan_since; /* frame the plan in use started */
	uint16_t psw_cnt;    /* FT, plan_auto: frames in a row that ask for a switch */
	uint8_t psw_want;    /* ... to this plan */
	uint16_t bq_quiet;   /* FT, plan_auto: frames in a row nothing needed a long burst */
	bool psw_from_t2;    /* FT: the last switch left T2 */
	/* FT: decisions, PT: received grants (by FLEX slot) */
	struct tdma_flex flex[TDMA_FLEX_SLOTS];
	/*
	 * Plan T2: the pattern of frame f in t2[f & 1] (FT: decided, PT: heard in
	 * the beacon of frame f - 1). Kept across plan switches: the pattern of
	 * the first T2 frame comes with the beacon before it.
	 */
	struct tdma_t2 {
		bool valid;
		uint32_t frame;
		uint8_t plan; /* the pattern plan it is for */
		uint8_t pat;  /* TDMA_T2_* / TDMA_T2D_* */
		uint8_t pos;
		uint8_t mcs_dl, mcs_ul;
		uint32_t rd;  /* FT: the PT it was given to */
		bool ul_long; /* this frame: an UL burst of TDMA_LRX_MIN_SS or more went out (PT) */
	} t2[2];
	uint8_t t2_rr; /* FT: round robin over PTs with demand */

	/* PT */
	uint32_t parent_rd;
	int8_t my_pos;
	uint8_t nonce;
	uint32_t last_beacon_frame;
	uint32_t last_ft_frame; /* PT: frame of the last verified burst from the FT (any slot) */
	uint16_t backoff;       /* contention opportunities to skip */
	uint32_t assoc_sent_frame;
	bool assoc_waiting;
	uint8_t assoc_attempts;
	bool parent_full;
	uint16_t free_mask; /* PT: free positions in the last beacon (contention) */
	int16_t dl_snr_q4;  /* PT: EWMA SNR of the parent's bursts, 1/16 dB */
	bool dl_snr_valid;
	int8_t dl_rssi;
	uint8_t tree_depth; /* PT: depth of the parent's cluster (beacon tree extension; 0 = root)
			     */
	uint8_t tree_grid;  /* PT: its frame's offset from the root's frame, subslots */
	/* FT: the route record its beacons carry; PT: the one of the parent's last beacon */
	uint8_t route_len;
	uint8_t route[TDMA_ROUTE_MAX];
	uint8_t parent_route_len;
	uint8_t parent_route[TDMA_ROUTE_MAX];
	uint8_t parent_tx_power; /* PT: transmit power index in the parent's last beacon header */
	/* FT relay: frame f starts at follow_start + (f - follow_frame) frames (tdma_ft_follow) */
	bool follow_valid;
	uint64_t follow_start;
	uint32_t follow_frame;
	/* a timing shift (FT: announced, TDMA_F_RETIME; PT: heard), from retime_frame on */
	bool retime_valid;
	uint32_t retime_frame;
	uint32_t retime_delta;
	/* position compaction : the PT at pm_from goes to pm_to from frame pm_frame on */
	bool pm_valid;
	bool pm_swap; /* the PT at pm_to moves to pm_from at the same frame */
	/* */
	bool hgx_ok; /* PT (a relay's up instance): our child cluster could run HGX (TDMA_STF_HGX)
		      */
	bool child_hgx; /* PT (a relay's up instance): our child cluster runs HGX (DL RX leads) */
	bool hgx_want;  /* FT (a relay's child cluster): HGX is wanted (a lone child: position 0) */
	bool room_wanted; /* FT on HGX: a node asked to join in an open frame (the relay goes to HG)
			   */
	uint8_t pm_from, pm_to;
	uint32_t pm_frame;
	/* PT, search only fast_ch (a known parent's carrier) until fast_until */
	uint16_t fast_ch;
	uint64_t fast_until;
	/* PT : one listen for another cluster's DL burst (tdma_pt_probe()) */
	bool probe_valid;
	bool probe_heard;
	uint8_t probe_ss;
	uint16_t probe_ch;
	uint32_t probe_rd;
	uint32_t probe_until; /* frame: give up when not placed by then */
	uint32_t probe_handle;
	int16_t probe_rssi, probe_snr;
	/* FT : the beacons' TDMA_BEXT_APP bytes (tdma_set_beacon_ext()) */
	uint8_t app_len;
	uint8_t app[TDMA_BEXT_APP_MAX];
	/*
	 * FT (tdma_ft_scan()): one listen on fs_ch in [fs_start,
	 * fs_end) instead of our own ops there (placed: fs_frame's beacon burst
	 * known; committed: fs_handle)
	 */
	bool fs_valid;
	bool fs_placed;
	uint16_t fs_ch;
	uint8_t fs_rr;
	uint32_t fs_frame;
	uint64_t fs_start, fs_end;
	uint32_t fs_handle;
	uint16_t fs_heard, fs_pcc;
	uint32_t fs_until; /* frame: give up when not placed by then */
	/* PT : the FT is away from q_ss of q_frame for q_len subslots (TDMA_BEXT_QUIET) */
	bool q_valid;
	uint32_t q_frame;
	uint8_t q_ss, q_len;

	/* channel */
	uint16_t chan;      /* carrier in use (FT: chosen; PT: where the FT was found) */
	uint16_t search_ch; /* PT search / FT scan: carrier of the current op */
	uint8_t scan_i;     /* FT scan: carriers done */
	bool move_valid;    /* a move to move_ch / move_mask at frame move_frame is pending */
	uint16_t move_ch;
	uint32_t move_mask;
	uint32_t move_frame;
	/* hopping: hop_mask != 0 -> frame f is on cfg.ch_min + hop_perm[f % hop_n] of cycle f /
	 * hop_n */
	uint16_t hop_base;
	uint32_t hop_mask;
	uint32_t hop_seed;
	uint32_t hop_cycle; /* cycle the permutation below is for */
	uint32_t hop_key;   /* mask ^ seed it was computed with */
	bool hop_cached;
	uint8_t hop_n;
	uint8_t hop_perm[TDMA_CH_TABLE];
	uint32_t hop_dropped_frame[TDMA_CH_TABLE];
	enum tdma_cause move_cause;
	uint16_t avoid_ch[4]; /* FT: carriers (and neighbours) of clusters in our time blocks
				 (tdma_ft_set_avoid) */
	uint32_t move_hold;   /* FT: no automatic move before this frame */
	bool ft_started;      /* FT: FT_STARTED emitted */
	bool lbt_pending;     /* FT: the next beacon goes out with LBT, nothing else until then */
	uint8_t lbt_fail;
	uint32_t lbt_retry_frame;
	uint32_t mon_last; /* FT: frame of the last measurement */
	uint32_t mon_seq;
	uint32_t bg_last; /* FT: frame of the last background measurement */
	uint8_t bg_rr;
	uint32_t win_start; /* FT: monitor window (counts per carrier in chans[].w_*) */
	struct tdma_chan_info chans[TDMA_CH_TABLE];

	/* FT: peers[pos]; PT: peers[0] = parent (cfg.mem) */
	struct tdma_peer *peers;
	uint8_t n_peers;
	struct tdma_ras *ras;
	uint8_t n_ras;

	struct tdma_sec_state sec;

	struct tdma_stats stats;
	struct tdma_lead_cache lc;
	struct tdma_lead_memo lmemo;
	uint8_t hdr_buf[TDMA_PHY_HDR_LEN];
	uint8_t pkt_buf[TDMA_PKT_MAX];
	uint8_t rx_buf[TDMA_PKT_MAX]; /* security: a received burst decrypted in place */
};

/* All the storage one instance can use (TDMA_MAX_POSITIONS peers). */
struct tdma_mac_store {
	struct tdma_peer peers[TDMA_MAX_POSITIONS];
	uint8_t qmem[TDMA_TXQ_POOL_CHUNKS][TDMA_TXQ_CHUNK];
	struct tdma_ras ras[TDMA_RAS_SLOTS];
};

/* Chunks of qmem n peers need, the first n_big of them with the deep queues. */
static inline uint16_t tdma_mem_chunks(uint8_t n, uint8_t n_big)
{
	return (uint16_t)((n_big < n ? n_big : n) * TDMA_TXQ_ALL_CHUNKS +
			  (n_big < n ? n - n_big : 0) * TDMA_TXQ_SMALL_CHUNKS);
}

/* The whole store for one instance (the layout tdma_init() used before tdma_mem). */
static inline struct tdma_mem tdma_mem_of(struct tdma_mac_store *s)
{
	struct tdma_mem m = {
		.peers = s->peers,
		.n_peers = TDMA_MAX_POSITIONS,
		.n_big = TDMA_TXQ_N_BIG,
		.qmem = s->qmem,
		.n_chunks = TDMA_TXQ_POOL_CHUNKS,
		.ras = s->ras,
		.n_ras = TDMA_RAS_SLOTS,
	};

	return m;
}

/* ---- API ------------------------------------------------------------------- */

int tdma_init(struct tdma_mac *m, const struct tdma_cfg *cfg, const struct tdma_port *port);
/* FT: start beaconing. PT: start searching. */
int tdma_start(struct tdma_mac *m);
/* Stop scheduling, stop RX ops, flush queues; emits LOST/CHILD_REMOVED + STOPPED. */
void tdma_stop(struct tdma_mac *m);

/* rssi in dBm, snr_q2 in 0.25 dB (nrf_modem_dect_phy PCC "snr"). */
void tdma_on_rx(struct tdma_mac *m, uint32_t handle, uint64_t rx_start_time, int16_t rssi,
		int16_t snr_q2, const uint8_t *phy_hdr, size_t hdr_len, const uint8_t *payload,
		size_t len, bool crc_ok);
void tdma_on_op_done(struct tdma_mac *m, uint32_t handle, int err);
/* Commit due slots; returns the modem time it next needs to be called at. */
uint64_t tdma_tick(struct tdma_mac *m, uint64_t now);
uint64_t tdma_next_wakeup(const struct tdma_mac *m);
/* The latest the next commits may start (start - tx_need / rx_need per slot with an op). */
uint64_t tdma_next_latest(const struct tdma_mac *m, uint32_t tx_need, uint32_t rx_need);

/*
 * Queue an SDU. dst: a child rd id (FT), the parent rd id (PT), or
 * TDMA_RD_BROADCAST (FT: a copy to every child; PT: to the parent).
 * prio > 0 jumps ahead of queued, not yet sent normal traffic; TDMA_PRIO_OWN
 * (a relay's own priority traffic) also ahead of other priority SDUs not sent
 * yet (forwarded ones: a child's EF cannot take every one of our UL bursts).
 * -EMSGSIZE above TDMA_MAX_SDU (or more fragments than the link allows),
 * -ENOTCONN not associated / unknown dst, -ENOBUFS queue full (nothing queued).
 */
#define TDMA_PRIO_OWN 2
int tdma_send(struct tdma_mac *m, uint32_t dst_rd_id, const uint8_t *data, size_t len,
	      uint8_t prio);
/*
 * Would tdma_send() to this unicast dst find queue room for len bytes now?
 * For a sender that waits for room without holding its own locks. A bulk
 * (prio 0) sender that finds none is counted as waiting in the queue report,
 * as after an -ENOBUFS.
 */
bool tdma_send_room(struct tdma_mac *m, uint32_t dst_rd_id, size_t len, uint8_t prio);

/*
 * PT: change ft_rd_filter at runtime (scan only -> TDMA_RD_BROADCAST, join
 * one FT -> its rd). Applies to the next sync from search; a
 * current sync/association to another FT is left (as LOST/ASSOC_FAILED with
 * TDMA_CAUSE_STOPPED) so the PT searches for the new target.
 */
int tdma_pt_set_target(struct tdma_mac *m, uint32_t ft_rd_id);
/*
 * fast reroute: as tdma_pt_set_target(), and the search stays on
 * carrier ch (a warm backup's, known from the tree) for for_ticks, with a
 * short association backoff (TDMA_FAST_BACKOFF_FRAMES).
 */
int tdma_pt_set_target_ch(struct tdma_mac *m, uint32_t ft_rd_id, uint16_t ch, uint32_t for_ticks);
#define TDMA_FAST_BACKOFF_FRAMES 3
/*
 * FT (a relay's child cluster): shift the cluster's frames by delta
 * ticks ([0, frame)) from frame on, announced in every beacon until then
 * (TDMA_F_RETIME); PTs shift with it and keep their positions. -EINVAL if
 * frame is not ahead or delta out of range; -EALREADY if one is pending.
 */
int tdma_ft_retime(struct tdma_mac *m, uint32_t frame, uint32_t delta);
/* A shift announced (FT) or heard (PT) and not applied yet. */
bool tdma_retime_pending(const struct tdma_mac *m, uint32_t *frame, uint32_t *delta);
/* FT relay: the tree depth its beacons give (an island root: 0; after a merge: the new one). */
void tdma_ft_set_depth(struct tdma_mac *m, uint8_t depth);

/*
 * Channel access inputs from the port (only for ops of its rssi()/scan()):
 * ss_max[i] = highest RSSI-1 (dBm, > 0 = saturated) of the i-th measured
 * subslot; pcc = a valid physical header of any radio (hdr_type 0 = type 1,
 * 1 = type 2) heard by a scan op.
 */
void tdma_on_rssi(struct tdma_mac *m, uint32_t handle, const int8_t *ss_max, size_t n);
void tdma_on_pcc(struct tdma_mac *m, uint32_t handle, int16_t rssi, uint8_t short_nwid,
		 uint16_t tx_short, uint8_t hdr_type);

/*
 * FT: move the cluster to ch (0 = the best other carrier in the table),
 * announced in the next move_frames beacons; PTs follow without
 * re-associating. Ends hopping. -ENOENT no other usable carrier, -EINVAL
 * bad ch / not FT, -EALREADY a move is pending.
 */
int tdma_ft_move(struct tdma_mac *m, uint16_t ch, enum tdma_cause cause);
/*
 * FT: hop over mask (bit i = ch_min + i, >= 2 carriers; 0 = stop hopping and
 * stay on the carrier of the move frame), announced like a move.
 */
int tdma_ft_set_hop(struct tdma_mac *m, uint32_t mask, enum tdma_cause cause);
/*
 * FT: carriers other clusters use in our time blocks (mesh: the roster's
 * relay clusters of our depth's parity), up to 4; carrier choices and moves
 * rank them and their neighbours with the carriers another cluster was heard
 * on (a root's monitor never hears them: they run when it does).
 */
void tdma_ft_set_avoid(struct tdma_mac *m, const uint16_t *ch, size_t n);
/* a relay's child cluster: plan switch + frame shift at `frame` (tdma_relay_plan_step()). */
int tdma_ft_relay_switch(struct tdma_mac *m, uint8_t plan_id, uint32_t frame, uint32_t delta);
/* FT, the PT at `from` moves to the free position `to` (announced). */
int tdma_ft_pos_move(struct tdma_mac *m, uint8_t from, uint8_t to);
/*
 * FT: plan in use. plan_id >= 0: switch to that plan (announced in
 * TDMA_PLAN_ANNOUNCE_FRAMES beacons; it must be tdma_plan_compatible() with
 * the one in use) and stop switching by demand; < 0: switch by demand
 * (cfg.plan_auto) again. -EINVAL: not an FT, unknown or incompatible plan.
 */
int tdma_ft_set_plan(struct tdma_mac *m, int plan_id);
/* Debug: what an op in flight is (plan slot, enum tdma_slot_use or 0xfd-0xff, frame, carrier). */
int tdma_op_info(const struct tdma_mac *m, uint32_t handle, uint8_t *slot, uint8_t *use,
		 uint32_t *frame, uint16_t *ch);
/* Carrier in use (hopping: of the frame being scheduled; 0 = none yet). */
uint16_t tdma_channel(const struct tdma_mac *m);
/* Hop set in use (0 = no hopping). */
uint32_t tdma_hop_mask(const struct tdma_mac *m);
/* Carrier of frame `frame` for a hop set (exposed for tests / the shell). */
uint16_t tdma_hop_carrier(struct tdma_mac *m, uint32_t frame);
/* The channel table (n entries, ch_min..ch_max). */
const struct tdma_chan_info *tdma_chan_table(const struct tdma_mac *m, size_t *n);
/* Best carrier by the selection rules, excluding `except` (0 = none); 0 if none usable. */
uint16_t tdma_chan_best(const struct tdma_mac *m, uint16_t except);

static inline size_t tdma_max_sdu(void)
{
	return TDMA_MAX_SDU;
}

enum tdma_state tdma_get_state(const struct tdma_mac *m);
uint32_t tdma_parent(const struct tdma_mac *m);
/* FT: fills out[] with child rd ids, returns the count. */
size_t tdma_children(const struct tdma_mac *m, uint32_t *out, size_t max);
const struct tdma_stats *tdma_get_stats(const struct tdma_mac *m);
/* SDU bytes one PDU of the link to dst carries (0 = no such link): above it, fragments. */
size_t tdma_link_mtu(const struct tdma_mac *m, uint32_t dst_rd_id);
/* FT: MCS used for long bursts to (dl) / from (!dl) a child; 0xff = no such child. */
uint8_t tdma_link_mcs(const struct tdma_mac *m, uint32_t child_rd_id, bool dl);

/* ---- relays (docs/mac-design.md "Relays") -------------------------- */

/*
 * FT relay (cfg.relay): frame `frame` starts at modem time `start` (the up
 * instance's frame + tdma_relay_offset_ss(), tdma_relay_sync()). Before
 * tdma_start() it gives the first frame's timing; while running it keeps the
 * cluster on the grid. A frame number that does not continue the current
 * numbering (the parent's counter jumped) starts a new security session, so
 * (key, nonce) never repeats.
 */
void tdma_ft_follow(struct tdma_mac *m, uint64_t start, uint32_t frame);
/* Depth and grid offset (subslots) of the cluster this instance runs (FT) or is in (PT). */
void tdma_tree(const struct tdma_mac *m, uint8_t *depth, uint8_t *grid_ss);
/* FT: the LBT window (ticks) the next beacon goes out with; 0 = no first beacon pending. */
uint32_t tdma_lbt_pending(const struct tdma_mac *m);

/*
 * . FT: the route record its beacons carry from the next one on (len
 * 0 = none; a root's cluster then sends no tree extension), -EINVAL above
 * TDMA_ROUTE_MAX. PT: the record of the parent's last beacon (0 = none).
 */
int tdma_set_route(struct tdma_mac *m, const uint8_t *rr, size_t len);
/*
 * FT: len bytes of the mesh layer's (TDMA_BEXT_APP, opaque) its
 * beacons carry behind the route record from the next one on (0: none);
 * -EINVAL above TDMA_BEXT_APP_MAX.
 */
int tdma_set_beacon_ext(struct tdma_mac *m, const uint8_t *app, size_t len);
/*
 * FT (a tree's root): listen once on carrier ch for a beacon
 * period and a bit (TDMA_FT_SCAN_TICKS: a beacon burst of any cluster, at any
 * offset from our frame), in place of our own ops in that time: from just
 * after one of our beacon bursts over the next one (PTs miss one beacon, the
 * DL / UL slots it covers go again by ARQ; no FLEX region is granted into
 * it). ch 0: the MAC picks the next carrier of the channel set (round robin,
 * our own included: with our PTs quiet, a cluster of another tree that took
 * our carrier is heard there too). The listen also measures the carrier (RSSI, the channel table)
 * and counts the other radios' physical headers there (`clusters`: carrier choice and moves keep
 * off it). TDMA_EVT_FT_SCAN per beacon heard, TDMA_EVT_FT_SCAN_DONE at the end. -EBUSY: not a
 * running FT, a listen pending, our first beacon's LBT, a move or re-alignment announced, a bulk
 * plan; -EINVAL: ch not in the channel set.
 */
#define TDMA_FT_SCAN_TICKS  (TDMA_FRAME_TICKS + 4u * TDMA_SUBSLOT_TICKS)
#define TDMA_FT_SCAN_FRAMES 4u /* frames to place it in */
/* flags: also while a bulk plan runs (T, T2, T2D: else -EBUSY, the bulk keeps its frames) */
#define TDMA_FS_ANY_PLAN    0x01
int tdma_ft_scan(struct tdma_mac *m, uint16_t ch, uint8_t flags);
size_t tdma_parent_route(const struct tdma_mac *m, uint8_t *out, size_t max);
/*
 * PT: run (or stop running) a child cluster. The parent learns it from the
 * next status record (TDMA_STF_RELAY) and treats the PT as a relay child from
 * then on (no FLEX, no plan without its slots), as for TDMA_AF_RELAY at
 * association; a later association asks with the flag.
 */
void tdma_pt_set_relay(struct tdma_mac *m, bool on);
/*
 * PT (backup probes): listen once on carrier ch for a DL burst of
 * FT rd_id (a warm backup: another cluster of our tree, on the site grid)
 * that starts at subslot at_ss of our frame, within the next frames. The
 * listen replaces our own DL / beacon burst there when one starts at the same
 * subslot (a sibling cluster: the same grid; its beacon burst is the one that
 * is always sent, so at_ss 0), else it goes in when we have nothing within 2
 * subslots of it. TDMA_EVT_PROBE tells the result. -EBUSY: not associated, a
 * probe pending, a relay (two instances), or no room for it.
 */
int tdma_pt_probe(struct tdma_mac *m, uint32_t rd_id, uint16_t ch, uint8_t at_ss);
/* Bytes queued for dst and not yet sent (PDU records waiting; 0 = none / no such link). */
size_t tdma_link_pending(const struct tdma_mac *m, uint32_t dst_rd_id);
/*
 * Backpressure, hop by hop : ask the peer rd_id (0: every
 * link) to start no new non-priority SDUs towards us (TDMA_F_HOLD on every
 * PDU we send it, an ack-only PDU in each of our bursts if nothing else goes),
 * or release it. A hold the peer stops refreshing lapses after
 * TDMA_HOLD_TICKS. Priority SDUs and SDUs already started are not held.
 */
void tdma_link_hold(struct tdma_mac *m, uint32_t rd_id, bool on);
/* The peer holds our bulk towards it. */
bool tdma_link_held(const struct tdma_mac *m, uint32_t rd_id);
/* FT: a child is a relay (TDMA_AF_RELAY / TDMA_STF_RELAY). */
bool tdma_child_is_relay(const struct tdma_mac *m, uint32_t rd_id);

/*
 * The radio arbiter of a relay (tdma_relay.c): one radio, two instances. Both
 * ports' away() call tdma_relay_away(); the platform calls tdma_relay_sync()
 * before it hands the down instance anything (event or tick), starts down
 * (cfg.relay, plan HG, tdma_ft_follow() first) once tdma_relay_ready(), and
 * stops it when up leaves its parent.
 */
struct tdma_relay {
	struct tdma_mac *up, *down;
	uint32_t away_up, away_down; /* refused ops, per instance */
	/*
	 * up searches while the child cluster runs on (a parent lost:
	 * a warm backup, an island looking for a tree). A search op takes the
	 * radio once down's committed ops are done; down then pauses for it and
	 * gets TDMA_RELAY_SEARCH_GAP frames before the next one.
	 */
	bool search_req;
	uint64_t search_req_t; /* when up last asked (a request it does not renew lapses) */
	uint32_t search_lapsed;
	uint8_t search_gap; /* frames between two searches (0: TDMA_RELAY_SEARCH_GAP) */
	uint64_t search_busy_until, search_hold_until;
	uint32_t searches; /* search ops given the radio while down ran */
	uint32_t retimes;  /* re-alignments started (a new parent's grid, TDMA_F_RETIME) */
	/* child plan HGX <-> HG (tdma_relay_plan_step()) */
	uint32_t to_hgx, to_hg;  /* switches started */
	uint64_t hgx_hold_until; /* no HGX before (a second node asked to join) */
	uint64_t up_since;       /* up associated since (0: not now) */
};

/* Frames down runs between two of up's search ops; frames a re-alignment is announced ahead. */
#define TDMA_RELAY_SEARCH_GAP   5u
#define TDMA_RELAY_RETIME_AHEAD 5u

void tdma_relay_init(struct tdma_relay *r, struct tdma_mac *up, struct tdma_mac *down);
int tdma_relay_away(struct tdma_relay *r, const struct tdma_mac *who, uint64_t start, uint32_t dur);
/* up is associated on a parent plan the child plan fits around (tdma_relay_plan_check). */
bool tdma_relay_ready(const struct tdma_relay *r);
/* down is running (FT) or starting. */
bool tdma_relay_running(const struct tdma_relay *r);
void tdma_relay_sync(struct tdma_relay *r);
/*
 * the child plan. HGX while up sits in position 1 of a root's plan
 * the layout fits (H, T) and the child cluster has exactly one child, one that
 * does not relay; HG otherwise. tdma_relay_child_plan(): the plan to start the child
 * cluster with. tdma_relay_plan_step() (after tdma_relay_sync()): switches
 * between them, announced TDMA_RELAY_RETIME_AHEAD frames ahead with the 4 ss
 * shift of the child frame (TDMA_F_RETIME) at the same frame; a lone child
 * first moves to position 0. A node asking to join in an HGX open frame keeps
 * the cluster on HG for TDMA_RELAY_HGX_HOLD_TICKS.
 */
uint8_t tdma_relay_child_plan(const struct tdma_relay *r);
void tdma_relay_plan_step(struct tdma_relay *r);
#define TDMA_RELAY_HGX_HOLD_TICKS  (30ull * TDMA_TICKS_PER_SEC)
/* after up (re)associates: time for the root to move it to position 1 before HGX is left */
#define TDMA_RELAY_HGX_GRACE_TICKS (TDMA_TICKS_PER_SEC / 2u)
/*
 * Split one instance's worth of storage between a relay's PT (peer 0 with its
 * deep queue, the reassembly buffers but relay_ras) and its child cluster
 * (the last relay_peers peers, short queues, relay_ras buffers). -EINVAL if
 * all cannot be split that way.
 */
int tdma_mem_split(const struct tdma_mem *all, struct tdma_mem *pt, struct tdma_mem *relay,
		   uint8_t relay_peers, uint8_t relay_ras);

/*
 * The relay's merged op sequence for (parent plan, its position there, child
 * plan at tdma_relay_offset_ss(parent)), cyclic over the frame: every gap rule of
 * tdma_plan_validate() (2 ss, RX -> long TX 3 ss, 5 ss after a received long
 * burst), the parent's ops in E blocks and the child's in O blocks. The
 * call-time check counts PHY calls that land in another op's quiet window
 * [start - quiet_us, start - late_us) when every op is committed its lead
 * ahead (RX: commit lead; TX: commit lead - trim + seal; the port then holds
 * them, docs/mac-design.md "PHY quiet window"). 0 = usable.
 */
struct tdma_relay_check {
	uint32_t ul_trim, dl_trim, seal; /* ticks (inputs) */
	uint32_t quiet, late;            /* ticks (inputs; 0, 0 = no call-time check) */
	uint8_t n_ops;
	uint8_t min_gap_ss;
	uint8_t held_calls; /* per frame */
};
int tdma_relay_plan_check(const struct tdma_plan *parent, uint8_t pos,
			  const struct tdma_plan *child, struct tdma_relay_check *out);
/*
 * Where a relay's child frame starts in its parent cluster's frame (subslots):
 * by the parent's plan and the child plan (HG or HGX; NULL: HG).
 */
uint8_t tdma_relay_offset_ss(const struct tdma_plan *parent, const struct tdma_plan *child);
/* Where a child plan's (HG / HGX) relay blocks start in its frame (subslots). */
uint8_t tdma_relay_origin_ss(const struct tdma_plan *child);
/* Frame offset (subslots) from the root's frame of a cluster at depth d (plan HG below the root).
 */
uint8_t tdma_grid_of_depth(uint8_t depth);

/* ---- link security (docs/mac-design.md "Link security") ------------------------------------- */

struct tdma_sec_info {
	bool on;
	bool devkey;
	uint8_t key_idx; /* index of the current session, TDMA_SEC_NO_KEY = none */
	uint32_t ft_rd, sess_ctr, sess_rand;
	bool switch_pending;
	uint8_t next_idx;
	uint32_t next_frame;
	uint32_t next_ctr;
	uint8_t n_deny;
};

int tdma_sec_info(const struct tdma_mac *m, struct tdma_sec_info *out);
/*
 * FT deny list (works with security off too): association requests from rd
 * are refused, a current child with it is released (TDMA_CAUSE_REVOKED).
 * -ENOSPC list full, -ENOENT (del) not listed.
 */
int tdma_sec_deny(struct tdma_mac *m, uint32_t rd_id, bool add);
size_t tdma_sec_deny_list(const struct tdma_mac *m, uint32_t *out, size_t max);
/* Payload bytes a burst of TBS tbs carries with this instance's overhead. */
size_t tdma_payload_cap(const struct tdma_mac *m, size_t tbs);

/* Short (16 bit) rd id used in the physical header and the beacon table. */
static inline uint16_t tdma_short_rd(uint32_t rd_id)
{
	return (uint16_t)(rd_id & 0xffffu);
}

#endif /* TDMA_MAC_H_ */
