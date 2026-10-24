/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* Internal interfaces between the MAC core and the per-peer link (ARQ). */

#ifndef TDMA_INTERNAL_H_
#define TDMA_INTERNAL_H_

#include <cappella/tdma_mac.h>
#include <cappella/tdma_pdu.h>

struct link_params {
	uint8_t max_tx;
	uint32_t lifetime;
	/* A peer burst starting this long after our PDU ended reflects it. */
	uint32_t ack_turnaround;
};

typedef void (*link_deliver_fn)(void *ctx, const uint8_t *data, size_t len);

/* Give a link its chunk memory (n chunks, <= TDMA_TXQ_ALL_CHUNKS); before link_reset(). */
void link_attach(struct tdma_link *l, uint8_t (*mem)[TDMA_TXQ_CHUNK], uint8_t n);
void link_reset(struct tdma_link *l);
/*
 * Largest PDU this link's bursts always have room for (fragment size follows);
 * wide: 16-bit ack bitmap and window TDMA_ARQ_WINDOW_WIDE (hybrid plans);
 * train: the deeper queue and TDMA_TX_SDU_INFLIGHT_TRAIN (plans with FLEX trains).
 */
/* depth: TDMA_QD_STD (2560 B queued), TDMA_QD_TRAIN (plan T), TDMA_QD_FRAME (whole-frame plans) */
#define TDMA_QD_STD   0
#define TDMA_QD_TRAIN 1
#define TDMA_QD_FRAME 2
void link_set_cap(struct tdma_link *l, size_t pdu_cap, bool wide, uint8_t depth);
/* Move l's queue into a larger, empty memory region of n chunks (position compaction). */
void link_regrow(struct tdma_link *l, uint8_t (*mem)[TDMA_TXQ_CHUNK], uint8_t n);
/* SDU bytes in one unfragmented PDU of this link. */
size_t link_mtu(const struct tdma_link *l);
/* Queue one SDU (cut into PDUs as bursts are built). 0 or -ENOBUFS / -EMSGSIZE. */
int link_enqueue(struct tdma_link *l, const uint8_t *data, size_t len, uint8_t prio, uint64_t now);
/* Would link_enqueue() find room for an SDU of len bytes (no size checks)? */
bool link_room(const struct tdma_link *l, size_t len, uint8_t prio);
bool link_has_pending(const struct tdma_link *l);
/*
 * Fragment bytes the next burst could carry without new acks: the rest of the
 * fragmented SDUs started, and of the next one if the tag window lets it start.
 */
size_t link_bulk_ready(const struct tdma_link *l);
/* A fragmented SDU is in flight (started, not all acked): the sender is in bulk. */
bool link_frag_busy(const struct tdma_link *l);
/* Record bytes (record + PDU headers + payload) of everything waiting to be sent. */
size_t link_pending_bytes(const struct tdma_link *l);
void link_tx_failed(struct tdma_link *l, uint64_t start);

/* Ask the peer to hold (TDMA_F_HOLD on every PDU to it while on) or release it. */
void link_hold(struct tdma_link *l, bool on);

/* link_build() ack modes (0/1 keep the old bool meaning). */
#define LB_AUTO 0 /* ack-only PDU when acks are still owed */
#define LB_ACK  1 /* always at least an ack-only PDU */
#define LB_DATA 2 /* data PDUs only */
#define LB_PRIO 3 /* priority data PDUs only (new or retransmitted) */

/*
 * Build the PDU for an own burst [start, end). Data (a retransmission first,
 * else a new PDU if the window allows), else an ack-only PDU (mode), else
 * nothing. Returns the PDU length, 0 for "send nothing". Called repeatedly
 * for one burst, it returns the next PDU each time.
 */
int link_build(struct tdma_link *l, const struct link_params *p, uint64_t now, uint64_t start,
	       uint64_t end, int mode, uint8_t *buf, size_t cap, struct tdma_stats *st);
/* Apply the peer's ack state carried by a burst that started at rx_start. */
void link_rx_ack(struct tdma_link *l, const struct link_params *p, const struct tdma_ack *a,
		 uint64_t rx_start, struct tdma_stats *st);
/*
 * Duplicate filter + reassembly in the shared buffers pool[n_pool] (owner =
 * peer index + 1); complete SDUs go to deliver(). A fragment that finds no
 * buffer is not taken (and not acked).
 */
void link_rx_data(struct tdma_link *l, struct tdma_ras *pool, size_t n_pool, uint8_t owner,
		  const struct tdma_data *d, uint64_t now, link_deliver_fn deliver, void *ctx,
		  struct tdma_stats *st);
/*
 * Deliver SDUs held (for in-order delivery) longer than hold for an older one
 * that never came. Called with every own burst of the link.
 */
void link_rx_poll(struct tdma_link *l, struct tdma_ras *pool, size_t n_pool, uint8_t owner,
		  uint64_t now, uint32_t hold, link_deliver_fn deliver, void *ctx,
		  struct tdma_stats *st);
/* Free the reassembly buffers of owner (its link was reset). */
void ras_release(struct tdma_ras *pool, size_t n, uint8_t owner);

#endif /* TDMA_INTERNAL_H_ */
