/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Per-peer link: TX queue, selective-repeat ARQ, duplicate filter and
 * byte-range reassembly.
 *
 * SDUs are queued whole (their bytes in fixed-size chunks). A data PDU is cut
 * from an SDU when a burst is built, as large as the room left in that burst
 * (at TDMA_FRAG_ALIGN boundaries), so a long burst carries one big fragment
 * instead of several guaranteed-burst-sized ones. Every PDU in flight has a
 * descriptor (SDU, byte range, seq). A lost PDU is resent with its seq; when
 * the burst at hand is too small for it, the PDU is shortened to fit and the
 * cut-off rest becomes a new PDU (new seq) later. The receiver reassembles by
 * byte range, so any cut works, and a byte range that arrives twice (an ack
 * that was lost, then a shortened resend) is harmless.
 *
 * Every burst we send carries our receive state (highest seq + bitmap), so
 * the peer's next burst acks ours. Because ops are committed a lead time
 * ahead, the burst right after ours usually cannot ack it yet; a window of
 * PDUs keeps the link busy meanwhile and a PDU counts as lost only when a peer
 * burst that started late enough to have seen it does not ack it (or, as a
 * fallback, after TDMA_ARQ_RTO_TICKS).
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>

#include "tdma_internal.h"

#define CHUNK           TDMA_TXQ_CHUNK
#define NO_CHUNK        0xffu
/* A reassembly buffer nobody touched for this long is free for others. */
#define RAS_STALE_TICKS (20u * TDMA_FRAME_TICKS)

static void chunks_init(struct tdma_link *l);
static void link_recover(struct tdma_link *l, struct tdma_stats *st);

#if defined(TDMA_CHECK_LEAD_MEMO)
static void link_check(const struct tdma_link *l);
#define LINK_CHECK(l) link_check(l)
#else
#define LINK_CHECK(l)                                                                              \
	do {                                                                                       \
	} while (0)
#endif

/* Bulk chunks a link may hold: want, within its own chunks minus the priority room. */
static uint8_t bulk_cap(const struct tdma_link *l, unsigned int want)
{
	unsigned int n = l->n_chunks > TDMA_TXQ_PRIO_CHUNKS
				 ? (unsigned int)l->n_chunks - TDMA_TXQ_PRIO_CHUNKS
				 : 0u;

	return (uint8_t)(want < n ? want : n);
}

void link_attach(struct tdma_link *l, uint8_t (*mem)[TDMA_TXQ_CHUNK], uint8_t n)
{
	l->chunk = mem;
	l->n_chunks = n < TDMA_TXQ_ALL_CHUNKS ? n : (uint8_t)TDMA_TXQ_ALL_CHUNKS;
	l->bulk_chunks = 0;
}

void link_reset(struct tdma_link *l)
{
	memset(l->sdu, 0, sizeof(l->sdu));
	memset(l->pdu, 0, sizeof(l->pdu));
	l->n_sdu = 0;
	l->n_prio = 0;
	l->prio_chunks = 0;
	chunks_init(l);
	l->next_seq = 0;
	l->next_tag = 0;
	l->rx_valid = false;
	l->rx_hi = 0;
	l->rx_map = 0;
	l->ack_dirty = 0;
	l->done_n = 0;
	l->done_i = 0;
	l->rx_tag_valid = false;
	l->exp_valid = false;
	l->blocked = false;
	l->hold_tx = false;
	l->peer_hold = false;
	l->corrupt = false;
	if (!l->bulk_chunks) {
		l->bulk_want = (uint8_t)TDMA_TXQ_STD_CHUNKS;
		l->bulk_chunks = bulk_cap(l, TDMA_TXQ_STD_CHUNKS);
		l->inflight = TDMA_TX_SDU_INFLIGHT;
	}
	l->rx_inflight = l->inflight;
	LINK_CHECK(l);
}

static size_t data_hdr(const struct tdma_link *l)
{
	return TDMA_DATA_HDR_LEN + (l->wide ? 1u : 0u);
}

static size_t pdu_hdr(const struct tdma_link *l, bool frag)
{
	return data_hdr(l) + (frag ? TDMA_FRAG_HDR_LEN : 0u);
}

/* ---- chunk store ------------------------------------------------------------------ */

/* Free chunks form a list through chunk_next[] (free_head, n_free of them). */
static void chunks_init(struct tdma_link *l)
{
	for (unsigned int i = 0; i < l->n_chunks; i++) {
		l->chunk_next[i] = (uint8_t)(i + 1u < l->n_chunks ? i + 1u : NO_CHUNK);
	}
	l->free_head = l->n_chunks ? 0 : NO_CHUNK;
	l->n_free = l->n_chunks;
}

/* Chain n free chunks; returns the first, or NO_CHUNK. */
static uint8_t chunks_alloc(struct tdma_link *l, unsigned int n)
{
	uint8_t first = l->free_head, last = first;

	if (n == 0 || l->n_free < n) {
		return NO_CHUNK;
	}
	for (unsigned int k = 1; k < n; k++) {
		last = l->chunk_next[last];
		if (last >= l->n_chunks) {
			l->corrupt = true; /* (shorter than n_free says) */
			return NO_CHUNK;
		}
	}
	l->free_head = l->chunk_next[last];
	l->chunk_next[last] = NO_CHUNK;
	l->n_free = (uint8_t)(l->n_free - n);
	return first;
}

static void chunks_release(struct tdma_link *l, uint8_t c)
{
	uint8_t tail = c;
	unsigned int k = 1;

	if (c == NO_CHUNK || c >= l->n_chunks) {
		return;
	}
	while (l->chunk_next[tail] != NO_CHUNK && l->chunk_next[tail] < l->n_chunks) {
		tail = l->chunk_next[tail];
		if (++k > l->n_chunks) {
			/*
			 * A cycle (seen once on hardware in a long soak: a bulk SDU written past
			 * sdu[] into order[], link_room(); fixed). A safety net: the
			 * link is reset at its next build (link_recover(), counted in
			 * queue_resets) instead of spinning here.
			 */
			l->corrupt = true;
			return;
		}
	}
	l->chunk_next[tail] = l->free_head;
	l->free_head = c;
	l->n_free = (uint8_t)(l->n_free + k);
}

#if defined(TDMA_CHECK_LEAD_MEMO)
/* host tests: the free list and the SDUs' chains partition the chunks exactly */
static void link_check(const struct tdma_link *l)
{
	uint8_t owner[TDMA_TXQ_ALL_CHUNKS];
	unsigned int n = 0;

	memset(owner, 0, sizeof(owner));
	for (uint8_t c = l->free_head; c != NO_CHUNK; c = l->chunk_next[c]) {
		if (c >= l->n_chunks || owner[c] || ++n > l->n_chunks) {
			__builtin_trap();
		}
		owner[c] = 1;
	}
	if (n != l->n_free) {
		__builtin_trap();
	}
	{
		unsigned int used = 0;
		uint32_t seen = 0;

		for (int i = 0; i < TDMA_TXQ_ALL_SDUS; i++) {
			used += l->sdu[i].used;
		}
		if (used != l->n_sdu || l->n_sdu > TDMA_TXQ_ALL_SDUS) {
			__builtin_trap(); /* the queue order and the SDU slots disagree */
		}
		for (uint8_t i = 0; i < l->n_sdu; i++) {
			if (l->order[i] >= TDMA_TXQ_ALL_SDUS || !l->sdu[l->order[i]].used ||
			    (seen & (1u << l->order[i]))) {
				__builtin_trap();
			}
			seen |= 1u << l->order[i];
		}
	}
	for (int i = 0; i < TDMA_TXQ_ALL_SDUS; i++) {
		if (!l->sdu[i].used) {
			continue;
		}
		for (uint8_t c = l->sdu[i].first_chunk; c != NO_CHUNK; c = l->chunk_next[c]) {
			if (c >= l->n_chunks || owner[c]) {
				__builtin_trap();
			}
			owner[c] = (uint8_t)(2 + i);
		}
	}
}
#endif

/* Bytes [off, off + n) of SDU s into dst (from, or to with to_sdu, the chunks). */
static void sdu_bytes(struct tdma_link *l, const struct tdma_txsdu *s, size_t off, uint8_t *dst,
		      const uint8_t *src, size_t n)
{
	uint8_t c = s->first_chunk;

	for (size_t k = off / CHUNK; k > 0 && c != NO_CHUNK; k--) {
		c = l->chunk_next[c];
	}
	off %= CHUNK;
	while (n && c != NO_CHUNK) {
		size_t m = CHUNK - off < n ? CHUNK - off : n;

		if (src) {
			memcpy(&l->chunk[c][off], src, m);
			src += m;
		} else {
			memcpy(dst, &l->chunk[c][off], m);
			dst += m;
		}
		n -= m;
		off = 0;
		c = l->chunk_next[c];
	}
}

/* ---- queue ------------------------------------------------------------------------ */

static unsigned int window(const struct tdma_link *l)
{
	return l->wide ? TDMA_ARQ_WINDOW_WIDE : TDMA_ARQ_WINDOW;
}

/* Chunks normal (bulk) SDUs may still take: l->bulk_chunks minus what they hold. */
static unsigned int bulk_room(const struct tdma_link *l)
{
	unsigned int used = l->n_chunks - l->n_free - l->prio_chunks;

	return used >= l->bulk_chunks ? 0u : l->bulk_chunks - used;
}

/*
 * Window for normal traffic. Wide (hybrid) links keep the last 2 places for
 * priority PDUs, so a small packet never waits for bulk acks.
 */
#define PRIO_RESERVE 2

static unsigned int window_for(const struct tdma_link *l, bool prio)
{
	return prio || !l->wide ? window(l) : window(l) - PRIO_RESERVE;
}

void link_set_cap(struct tdma_link *l, size_t pdu_cap, bool wide, uint8_t depth)
{
	bool train = depth != TDMA_QD_STD;

	l->pdu_cap = (uint8_t)(pdu_cap < TDMA_PDU_MAX ? pdu_cap : TDMA_PDU_MAX);
	l->wide = wide;
	l->bulk_want = (uint8_t)(depth == TDMA_QD_FRAME ? TDMA_TXQ_CHUNKS
				 : train                ? TDMA_TXQ_TRAIN_CHUNKS
							: TDMA_TXQ_STD_CHUNKS);
	l->bulk_chunks = bulk_cap(l, l->bulk_want);
	l->inflight = train ? TDMA_TX_SDU_INFLIGHT_TRAIN : TDMA_TX_SDU_INFLIGHT;
	/*
	 * As a receiver, the largest window the peer may still use: after a
	 * switch from a train plan its older SDUs are still in flight, and a
	 * PT may follow a switch to one a frame late.
	 */
	l->rx_inflight = wide && l->rx_inflight < TDMA_TX_SDU_INFLIGHT_TRAIN
				 ? (uint8_t)TDMA_TX_SDU_INFLIGHT_TRAIN
			 : l->rx_inflight < l->inflight ? l->inflight
							: l->rx_inflight;
}

/*
 * l's queue moves into a larger memory
 * region (n >= its chunks; the region holds nothing else): its chunks keep
 * their indices, the new ones join the free list, the bulk depth follows.
 */
void link_regrow(struct tdma_link *l, uint8_t (*mem)[TDMA_TXQ_CHUNK], uint8_t n)
{
	uint8_t old = l->n_chunks;

	if (n > TDMA_TXQ_ALL_CHUNKS) {
		n = (uint8_t)TDMA_TXQ_ALL_CHUNKS;
	}
	if (n <= old) {
		return;
	}
	memcpy(mem, l->chunk, (size_t)old * TDMA_TXQ_CHUNK);
	l->chunk = mem;
	for (unsigned int i = old; i < n; i++) {
		l->chunk_next[i] = (uint8_t)(i + 1u < n ? i + 1u : l->free_head);
	}
	l->free_head = old;
	l->n_free = (uint8_t)(l->n_free + (n - old));
	l->n_chunks = n;
	l->bulk_chunks = bulk_cap(l, l->bulk_want ? l->bulk_want : TDMA_TXQ_STD_CHUNKS);
	LINK_CHECK(l);
}

size_t link_mtu(const struct tdma_link *l)
{
	return l->pdu_cap > data_hdr(l) ? l->pdu_cap - data_hdr(l) : 0;
}

/* Fragment payload that always fits the link's guaranteed bursts. */
static size_t guaranteed_frag(const struct tdma_link *l)
{
	size_t one = link_mtu(l);

	return one > TDMA_FRAG_HDR_LEN
		       ? (one - TDMA_FRAG_HDR_LEN) / TDMA_FRAG_ALIGN * TDMA_FRAG_ALIGN
		       : 0;
}

bool link_has_pending(const struct tdma_link *l)
{
	for (uint8_t i = 0; i < l->n_sdu; i++) {
		const struct tdma_txsdu *s = &l->sdu[l->order[i]];

		if (s->next < s->len) {
			return true;
		}
	}
	for (int i = 0; i < TDMA_TXQ_PDUS; i++) {
		const struct tdma_txe *e = &l->pdu[i];

		if (e->state == TDMA_TXE_UNSENT ||
		    (e->state == TDMA_TXE_INFLIGHT && e->need_retx)) {
			return true;
		}
	}
	return false;
}

static bool tag_window_ok(const struct tdma_link *l);

size_t link_bulk_ready(const struct tdma_link *l)
{
	size_t n = 0;
	bool next = tag_window_ok(l);

	for (uint8_t i = 0; i < l->n_sdu; i++) {
		const struct tdma_txsdu *s = &l->sdu[l->order[i]];

		if (!s->frag || s->next >= s->len) {
			continue;
		}
		if (s->started) {
			n += (size_t)(s->len - s->next);
			/* a big SDU's later fragments: acks of its earlier ones do not hold them
			 * back */
			n += s->len > 2u * TDMA_PKT_MAX / 3u ? TDMA_PKT_MAX : 0u;
		} else if (next) {
			n += s->len;
			next = false;
		}
	}
	return n;
}

bool link_frag_busy(const struct tdma_link *l)
{
	for (uint8_t i = 0; i < l->n_sdu; i++) {
		const struct tdma_txsdu *s = &l->sdu[l->order[i]];

		if (s->frag && s->started && s->acked < s->len) {
			return true;
		}
	}
	return false;
}

size_t link_pending_bytes(const struct tdma_link *l)
{
	size_t n = 0;

	for (uint8_t i = 0; i < l->n_sdu; i++) {
		const struct tdma_txsdu *s = &l->sdu[l->order[i]];
		size_t rem = (size_t)(s->len - s->next);

		if (!rem) {
			continue;
		}
		/* what cutting it will add: one PDU per ~500 B (a long burst's room) */
		n += rem + (TDMA_REC_LONG_HDR_LEN + pdu_hdr(l, s->frag)) * (1u + rem / 500u);
	}
	for (int i = 0; i < TDMA_TXQ_PDUS; i++) {
		const struct tdma_txe *e = &l->pdu[i];

		if (e->state == TDMA_TXE_UNSENT ||
		    (e->state == TDMA_TXE_INFLIGHT && e->need_retx)) {
			n += TDMA_REC_HDR_LEN + pdu_hdr(l, e->frag) + e->len;
		}
	}
	/*
	 * A sender waiting for queue room (dect0 waits, perf retries) has more:
	 * say so, or the FT sizes the next long burst to what is queued here.
	 */
	if (l->blocked && n &&
	    (l->n_sdu - l->n_prio >= TDMA_TXQ_SDUS ||
	     bulk_room(l) < (TDMA_MAX_SDU + CHUNK - 1) / CHUNK)) {
		n += TDMA_MAX_SDU; /* (only while the queue is still full: the flag is not cleared)
				    */
	}
	return n;
}

static unsigned int chunks_of(size_t len)
{
	return (unsigned int)((len + CHUNK - 1) / CHUNK);
}

bool link_room(const struct tdma_link *l, size_t len, uint8_t prio)
{
	unsigned int need = chunks_of(len), nfree = l->n_free;

	if (l->n_sdu >= TDMA_TXQ_ALL_SDUS || nfree < need) {
		return false;
	}
	/*
	 * Bulk: TDMA_TXQ_SDUS entries of its own. Priority SDUs may also take
	 * entries bulk leaves free, so both counts matter: 23 bulk + 5 priority
	 * SDUs filled all 28 entries and a 24th bulk SDU went past the end of
	 * sdu[] into order[] (a chunk free-list hang seen in a long soak).
	 */
	return prio || (l->n_sdu - l->n_prio < TDMA_TXQ_SDUS && bulk_room(l) >= need);
}

int link_enqueue(struct tdma_link *l, const uint8_t *data, size_t len, uint8_t prio, uint64_t now)
{
	size_t one = link_mtu(l), gf = guaranteed_frag(l);
	unsigned int need = chunks_of(len);
	uint8_t pos = l->n_sdu, si = 0;
	struct tdma_txsdu *s;

	(void)now;
	LINK_CHECK(l);
	if (len == 0 || len > TDMA_MAX_SDU || gf < TDMA_FRAG_MIN) {
		return -EMSGSIZE;
	}
	if (len > one && (len + gf - 1) / gf > TDMA_MAX_FRAGS) {
		return -EMSGSIZE; /* this link's bursts are too small for it */
	}
	if (!link_room(l, len, prio)) {
		if (!prio) {
			l->blocked = true;
		}
		return -ENOBUFS;
	}
	if (!prio) {
		l->blocked = false;
	} else {
		l->n_prio++;
		l->prio_chunks += (uint8_t)need;
	}
	while (si < TDMA_TXQ_ALL_SDUS && l->sdu[si].used) {
		si++;
	}
	if (si == TDMA_TXQ_ALL_SDUS) {
		/* n_sdu and the entries disagree: the queue is reset at the next build */
		l->corrupt = true;
		if (prio) {
			l->n_prio--;
			l->prio_chunks -= (uint8_t)need;
		}
		return -ENOBUFS;
	}
	s = &l->sdu[si];
	*s = (struct tdma_txsdu){.used = true,
				 .prio = prio != 0,
				 .own = prio == TDMA_PRIO_OWN,
				 .frag = len > one,
				 .len = (uint16_t)len};
	s->first_chunk = chunks_alloc(l, need);
	if (s->first_chunk == NO_CHUNK) {
		s->used = false;
		if (prio) {
			l->n_prio--;
			l->prio_chunks -= (uint8_t)need;
		}
		return -ENOBUFS; /* (corrupt: reset and counted at the next build) */
	}
	sdu_bytes(l, s, 0, NULL, data, len);
	if (prio) {
		/*
		 * Behind earlier priority traffic, ahead of normal traffic not
		 * started yet; an unfragmented one also ahead of the rest of a
		 * started normal SDU (it bypasses reassembly).
		 */
		for (pos = 0; pos < l->n_sdu; pos++) {
			const struct tdma_txsdu *o = &l->sdu[l->order[pos]];

			if (!o->prio && (!o->started || !s->frag)) {
				break;
			}
			/* (our own ahead of forwarded priority not started) */
			if (s->own && o->prio && !o->own && !o->started) {
				break;
			}
		}
	}
	memmove(&l->order[pos + 1], &l->order[pos], (size_t)(l->n_sdu - pos));
	l->order[pos] = si;
	l->n_sdu++;
	LINK_CHECK(l);
	return 0;
}

/*
 * the burst that started at `start` failed at the PHY (op error):
 * what it carried goes again in our next burst, not after the peer's next one
 * shows it missing (a relay's own EF under load: +13.7 ms -> +5 ms).
 */
void link_tx_failed(struct tdma_link *l, uint64_t start)
{
	for (int i = 0; i < TDMA_TXQ_PDUS; i++) {
		struct tdma_txe *e = &l->pdu[i];

		if (e->state == TDMA_TXE_INFLIGHT && e->tx_start == start) {
			e->need_retx = true;
		}
	}
}

/* Remove SDU si and every PDU descriptor of it. Returns the descriptors removed. */
static unsigned int sdu_remove(struct tdma_link *l, uint8_t si)
{
	unsigned int n = 0;

#if defined(TDMA_CHECK_LEAD_MEMO)
	if (!l->sdu[si].used) {
		__builtin_trap(); /* removed twice: its chunks would be freed twice */
	}
#endif
	for (int i = 0; i < TDMA_TXQ_PDUS; i++) {
		if (l->pdu[i].state != TDMA_TXE_FREE && l->pdu[i].sdu == si) {
			l->pdu[i].state = TDMA_TXE_FREE;
			n++;
		}
	}
	for (uint8_t i = 0; i < l->n_sdu; i++) {
		if (l->order[i] == si) {
			memmove(&l->order[i], &l->order[i + 1], (size_t)(l->n_sdu - i - 1));
			l->n_sdu--;
			break;
		}
	}
	chunks_release(l, l->sdu[si].first_chunk);
	if (l->sdu[si].prio) {
		l->n_prio--;
		l->prio_chunks -= (uint8_t)chunks_of(l->sdu[si].len);
	}
	l->sdu[si].used = false;
	LINK_CHECK(l);
	return n;
}

static unsigned int drop_sdu(struct tdma_link *l, uint8_t si, struct tdma_stats *st)
{
	unsigned int n = sdu_remove(l, si);

	st->sdu_tx_drop++;
	return n ? n : 1;
}

/* Descriptor e was acked: count its bytes, the SDU when it is complete. */
static void acked(struct tdma_link *l, struct tdma_txe *e, struct tdma_stats *st)
{
	struct tdma_txsdu *s = &l->sdu[e->sdu];

	e->state = TDMA_TXE_FREE;
	s->acked = (uint16_t)(s->acked + e->len);
	if (s->acked >= s->len) {
		st->sdu_tx_ok++;
		sdu_remove(l, e->sdu);
	}
}

static void fill_ack(const struct tdma_link *l, struct tdma_ack *a)
{
	a->valid = l->rx_valid;
	a->wide = l->wide;
	a->ack = l->rx_hi;
	a->ack_map = (uint16_t)(l->wide ? l->rx_map & 0xffffu : l->rx_map & 0xffu);
	a->hold = l->hold_tx;
}

/* The peer asked us to hold new non-priority SDUs (refreshed by every PDU it sends us). */
static bool peer_held(const struct tdma_link *l, uint64_t now)
{
	return l->peer_hold && (int64_t)(now - l->peer_hold_t) < (int64_t)TDMA_HOLD_TICKS;
}

void link_hold(struct tdma_link *l, bool on)
{
	if (l->hold_tx != on) {
		l->hold_tx = on;
		l->ack_dirty = 2; /* tell the peer in our next bursts, also when it is released */
	}
}

static struct tdma_txe *pdu_alloc(struct tdma_link *l)
{
	for (int i = 0; i < TDMA_TXQ_PDUS; i++) {
		if (l->pdu[i].state == TDMA_TXE_FREE) {
			return &l->pdu[i];
		}
	}
	return NULL;
}

/*
 * Whether the next fragmented SDU (tag next_tag) may start: the fragmented
 * SDUs started and not finished must all be younger than l->inflight
 * (TDMA_TX_SDU_INFLIGHT, on train plans TDMA_TX_SDU_INFLIGHT_TRAIN) tags
 * before it. The receiver relies on that: a buffer whose tag is that far
 * behind the newest tag it has seen belongs to an SDU that was delivered or
 * given up.
 */
static bool tag_window_ok(const struct tdma_link *l)
{
	for (uint8_t i = 0; i < l->n_sdu; i++) {
		const struct tdma_txsdu *s = &l->sdu[l->order[i]];

		if (s->frag && s->started && (uint8_t)(l->next_tag - s->tag) >= l->inflight) {
			return false;
		}
	}
	return true;
}

/*
 * How much of a fragment of rem bytes fits room (payload bytes): all of it, or
 * a TDMA_FRAG_ALIGN multiple of at least TDMA_FRAG_MIN. 0: it does not fit.
 */
static size_t frag_fit(size_t room, size_t rem)
{
	size_t n;

	if (room >= rem) {
		return rem;
	}
	n = room / TDMA_FRAG_ALIGN * TDMA_FRAG_ALIGN;
	return n >= TDMA_FRAG_MIN ? n : 0;
}

/*
 * Shorten descriptor e to n bytes; the rest goes into a new UNSENT descriptor.
 * False when no descriptor is free.
 */
static bool pdu_split(struct tdma_link *l, struct tdma_txe *e, size_t n)
{
	struct tdma_txe *r = pdu_alloc(l);

	if (!r) {
		return false;
	}
	*r = (struct tdma_txe){.state = TDMA_TXE_UNSENT,
			       .tries = e->tries,
			       .frag = true,
			       .sdu = e->sdu,
			       .off = (uint16_t)(e->off + n),
			       .len = (uint16_t)(e->len - n),
			       .first_tx = e->first_tx};
	e->len = (uint16_t)n;
	return true;
}

/* Encode descriptor e (its SDU bytes) as a data PDU into buf. */
static int pdu_encode(struct tdma_link *l, const struct tdma_txe *e, uint8_t *buf, size_t cap)
{
	const struct tdma_txsdu *s = &l->sdu[e->sdu];
	struct tdma_data d = {
		.seq = e->seq,
		.frag = e->frag,
		.frag_tag = s->tag,
		.frag_off = e->off,
		.frag_total = s->len,
		.len = e->len,
		.payload = NULL,
	};
	int n;

	fill_ack(l, &d.ack);
	n = tdma_data_encode(&d, buf, cap);
	if (n > 0) {
		sdu_bytes(l, s, e->off, buf + (size_t)n - e->len, NULL, e->len);
	}
	return n;
}

static int link_build0(struct tdma_link *l, const struct link_params *p, uint64_t now,
		       uint64_t start, uint64_t end, int mode, uint8_t *buf, size_t cap,
		       struct tdma_stats *st);

/* A link whose queue memory was found inconsistent starts over (its queued SDUs are lost). */
static void link_recover(struct tdma_link *l, struct tdma_stats *st)
{
	if (l->corrupt) {
		link_reset(l);
		l->corrupt = false;
		if (st) {
			st->queue_resets++;
		}
	}
}

int link_build(struct tdma_link *l, const struct link_params *p, uint64_t now, uint64_t start,
	       uint64_t end, int mode, uint8_t *buf, size_t cap, struct tdma_stats *st)
{
	int n;

	LINK_CHECK(l);
	link_recover(l, st);
	n = link_build0(l, p, now, start, end, mode, buf, cap, st);
	link_recover(l, st);

	LINK_CHECK(l);
	return n;
}

static int link_build0(struct tdma_link *l, const struct link_params *p, uint64_t now,
		       uint64_t start, uint64_t end, int mode, uint8_t *buf, size_t cap,
		       struct tdma_stats *st)
{
	struct tdma_txe *pick = NULL, *unsent = NULL;
	unsigned int inflight = 0, oldest_d = 0;
	bool retx = false;

	/*
	 * Expire (once per burst: every PDU of one burst is built with the same
	 * now): RTO; lifetime for everything sent; max_tx for PDUs due again.
	 * Lifetime runs from a PDU's first transmission, not from enqueue: a
	 * 1280-byte SDU needs 22 UL bursts on plan A before its last fragment
	 * even goes out. A part cut off a resend keeps its parent's.
	 */
	if (!l->exp_valid || now != l->exp_now) {
		l->exp_valid = true;
		l->exp_now = now;
		for (int i = 0; i < TDMA_TXQ_PDUS; i++) {
			struct tdma_txe *e = &l->pdu[i];

			if (e->state == TDMA_TXE_FREE) {
				continue;
			}
			if (e->state == TDMA_TXE_INFLIGHT && !e->need_retx &&
			    (int64_t)(now - e->tx_start) >= (int64_t)TDMA_ARQ_RTO_TICKS) {
				e->need_retx = true;
			}
			if (e->tries && (int64_t)(now - e->first_tx) > (int64_t)p->lifetime) {
				st->drop_lifetime += drop_sdu(l, e->sdu, st);
			} else if (e->state == TDMA_TXE_INFLIGHT && e->need_retx &&
				   e->tries >= p->max_tx) {
				st->drop_retries += drop_sdu(l, e->sdu, st);
			}
		}
	}

	/* one pass: window state, the oldest lost PDU, a part waiting with no seq */
	for (int i = 0; i < TDMA_TXQ_PDUS; i++) {
		struct tdma_txe *e = &l->pdu[i];
		unsigned int d;

		if (e->state == TDMA_TXE_UNSENT) {
			if (!unsent && (mode != LB_PRIO || l->sdu[e->sdu].prio)) {
				unsent = e;
			}
			continue;
		}
		if (e->state != TDMA_TXE_INFLIGHT) {
			continue;
		}
		inflight++;
		d = (uint8_t)(l->next_seq - e->seq);
		oldest_d = d > oldest_d ? d : oldest_d;
		if (e->need_retx && (mode != LB_PRIO || l->sdu[e->sdu].prio) &&
		    (!pick || d > (uint8_t)(l->next_seq - pick->seq))) {
			pick = e;
		}
	}
	if (pick) {
		size_t h = pdu_hdr(l, pick->frag);

		if (h + pick->len > cap) {
			/* too big for this burst: an unfragmented one waits for room */
			size_t n = pick->frag && cap > h ? frag_fit(cap - h, pick->len) : 0;

			if (!n || !pdu_split(l, pick, n)) {
				pick = NULL;
			}
		}
		retx = pick != NULL;
	}
	if (!pick && unsent) {
		/* a part cut off a resend: new seq, so the window applies */
		bool prio = l->sdu[unsent->sdu].prio;
		size_t h = pdu_hdr(l, true);
		size_t n = cap > h ? frag_fit(cap - h, unsent->len) : 0;

		if (inflight < window_for(l, prio) && oldest_d < window_for(l, prio) && n &&
		    (n == unsent->len || pdu_split(l, unsent, n))) {
			pick = unsent;
		}
	}
	if (!pick) {
		/* new bytes: queue order, no overtaking */
		for (uint8_t i = 0; i < l->n_sdu; i++) {
			uint8_t si = l->order[i];
			struct tdma_txsdu *s = &l->sdu[si];
			size_t rem = (size_t)(s->len - s->next), h = pdu_hdr(l, s->frag), n;
			struct tdma_txe *e;

			if (!rem) {
				continue; /* all of it in flight: the next SDU may start */
			}
			if ((mode == LB_PRIO && !s->prio) || inflight >= window_for(l, s->prio) ||
			    oldest_d >= window_for(l, s->prio)) {
				break;
			}
			if (!s->prio && !s->started && peer_held(l, now)) {
				st->hold_waits++;
				break; /* the peer holds: nothing new of bulk (priority went first)
					*/
			}
			if (s->frag && !s->started && !tag_window_ok(l)) {
				break; /* the receiver reassembles that many at a time */
			}
			n = !s->frag ? (h + rem <= cap ? rem : 0)
				     : (cap > h ? frag_fit(cap - h, rem) : 0);
			e = n ? pdu_alloc(l) : NULL;
			if (!e) {
				break; /* a shared DL burst may not have room left for it */
			}
			if (!s->started) {
				s->started = true;
				if (s->frag) {
					s->tag = l->next_tag++;
				}
			}
			*e = (struct tdma_txe){.state = TDMA_TXE_UNSENT,
					       .frag = s->frag,
					       .sdu = si,
					       .off = s->next,
					       .len = (uint16_t)n};
			s->next = (uint16_t)(s->next + n);
			pick = e;
			break;
		}
	}

	if (pick) {
		int n;

		if (pick->state == TDMA_TXE_UNSENT) {
			pick->seq = l->next_seq++;
			pick->state = TDMA_TXE_INFLIGHT;
		}
		n = pdu_encode(l, pick, buf, cap);
		if (n < 0) {
			return n;
		}
		if (retx) {
			st->retx++;
		}
		if (pick->tries++ == 0) {
			pick->first_tx = start;
		}
		pick->need_retx = false;
		pick->tx_start = start;
		pick->tx_end = end;
		if (l->ack_dirty) {
			l->ack_dirty--;
		}
		st->pdus_tx++;
		return n;
	}
	if ((mode == LB_ACK || (mode == LB_AUTO && (l->ack_dirty || l->hold_tx))) &&
	    cap >= (size_t)(TDMA_ACK_LEN + l->wide)) {
		struct tdma_ack a;

		fill_ack(l, &a);
		if (l->ack_dirty) {
			l->ack_dirty--;
		}
		st->acks_tx++;
		return tdma_ack_encode(&a, buf, cap);
	}
	return 0;
}

static bool is_acked(const struct tdma_ack *a, uint8_t seq)
{
	uint8_t d = (uint8_t)(a->ack - seq);

	if (!a->valid) {
		return false;
	}
	if (d == 0) {
		return true;
	}
	return d <= (a->wide ? 16 : 8) && (a->ack_map & (1u << (d - 1)));
}

void link_rx_ack(struct tdma_link *l, const struct link_params *p, const struct tdma_ack *a,
		 uint64_t rx_start, struct tdma_stats *st)
{
	LINK_CHECK(l);
	l->peer_hold = a->hold;
	if (a->hold) {
		l->peer_hold_t = rx_start;
	}
	for (int i = 0; i < TDMA_TXQ_PDUS; i++) {
		struct tdma_txe *e = &l->pdu[i];

		if (e->state != TDMA_TXE_INFLIGHT) {
			continue;
		}
		if (is_acked(a, e->seq)) {
			acked(l, e, st);
		} else if (e->tx_end + p->ack_turnaround <= rx_start) {
			/* The peer built this burst after it must have seen
			 * ours: it did not get it. Resend in our next burst.
			 */
			e->need_retx = true;
		}
	}
	LINK_CHECK(l);
}

/* ---- receive ------------------------------------------------------------------------ */

/* Whether seq is new (not received yet, nor too old to tell). */
static bool rx_is_new(const struct tdma_link *l, uint8_t seq)
{
	int8_t d;
	unsigned int bit;

	if (!l->rx_valid) {
		return true;
	}
	d = (int8_t)(seq - l->rx_hi);
	if (d > 0) {
		return true;
	}
	if (d == 0) {
		return false;
	}
	bit = (unsigned int)(-d) - 1;
	return bit < 32 && !(l->rx_map & (1u << bit));
}

/* Record seq as received (rx_is_new() said so). */
static void rx_mark(struct tdma_link *l, uint8_t seq)
{
	int8_t d;

	if (!l->rx_valid) {
		l->rx_valid = true;
		l->rx_hi = seq;
		l->rx_map = 0;
		return;
	}
	d = (int8_t)(seq - l->rx_hi);
	if (d > 0) {
		l->rx_map = d >= 32 ? 0 : (l->rx_map << d) | (1u << (d - 1));
		l->rx_hi = seq;
	} else if (d < 0) {
		l->rx_map |= 1u << ((unsigned int)(-d) - 1);
	}
}

void ras_release(struct tdma_ras *pool, size_t n, uint8_t owner)
{
	for (size_t i = 0; i < n; i++) {
		if (pool[i].owner == owner) {
			pool[i].owner = 0;
		}
	}
}

/*
 * The reassembly buffer of (owner, tag, total), or a new one: a free buffer,
 * else the owner's least recently used when it already holds
 * TDMA_RAS_PER_LINK (its sender never has that many in flight, so that SDU was
 * given up), else one nobody touched for RAS_STALE_TICKS. NULL: none free.
 */
static struct tdma_ras *ras_get(struct tdma_ras *pool, size_t n, uint8_t owner, uint8_t tag,
				uint16_t total, uint64_t now)
{
	struct tdma_ras *free_r = NULL, *own_lru = NULL, *stale = NULL;
	unsigned int own = 0;

	for (size_t i = 0; i < n; i++) {
		struct tdma_ras *r = &pool[i];

		if (!r->owner) {
			free_r = free_r ? free_r : r;
			continue;
		}
		if (r->owner == owner) {
			if (r->tag == tag && r->total == total) {
				return r;
			}
			own++;
			if (!r->complete && (!own_lru || r->touched < own_lru->touched)) {
				own_lru = r;
			}
		} else if ((int64_t)(now - r->touched) > (int64_t)RAS_STALE_TICKS &&
			   (!stale || r->touched < stale->touched)) {
			stale = r;
		}
	}
	struct tdma_ras *r = own >= TDMA_RAS_PER_LINK ? own_lru : free_r ? free_r : stale;

	if (r) {
		r->owner = owner;
		r->tag = tag;
		r->total = total;
		r->have = 0;
		r->complete = false;
		memset(r->map, 0, sizeof(r->map));
	}
	return r;
}

static struct tdma_ras *ras_find(struct tdma_ras *pool, size_t n, uint8_t owner, uint8_t tag)
{
	for (size_t i = 0; i < n; i++) {
		if (pool[i].owner == owner && pool[i].tag == tag) {
			return &pool[i];
		}
	}
	return NULL;
}

/* Hand a complete SDU up and free its buffer. */
static void ras_deliver(struct tdma_link *l, struct tdma_ras *r, link_deliver_fn deliver, void *ctx,
			struct tdma_stats *st)
{
	r->owner = 0;
	l->done_tag[l->done_i] = r->tag;
	l->done_i = (uint8_t)((l->done_i + 1u) % sizeof(l->done_tag));
	l->done_n = l->done_n < sizeof(l->done_tag) ? (uint8_t)(l->done_n + 1u) : l->done_n;
	st->sdu_rx++;
	deliver(ctx, r->buf, r->total);
}

/*
 * In tag order: deliver the complete SDUs from rx_tag_next on. A tag that fell
 * out of the peer's tag window (l->rx_inflight behind the newest) was
 * delivered or given up by the sender: skip it (and free a partial buffer).
 */
static void ras_flush(struct tdma_link *l, struct tdma_ras *pool, size_t n, uint8_t owner,
		      link_deliver_fn deliver, void *ctx, struct tdma_stats *st)
{
	for (;;) {
		struct tdma_ras *r = ras_find(pool, n, owner, l->rx_tag_next);
		bool dead = (uint8_t)(l->rx_tag_hi - l->rx_tag_next) >= l->rx_inflight &&
			    (int8_t)(l->rx_tag_hi - l->rx_tag_next) > 0;

		if (r && r->complete) {
			ras_deliver(l, r, deliver, ctx, st);
		} else if (dead) {
			if (r) {
				r->owner = 0;
			}
		} else {
			break;
		}
		l->rx_tag_next++;
	}
}

void link_rx_poll(struct tdma_link *l, struct tdma_ras *pool, size_t n_pool, uint8_t owner,
		  uint64_t now, uint32_t hold, link_deliver_fn deliver, void *ctx,
		  struct tdma_stats *st)
{
	for (size_t i = 0; i < n_pool; i++) {
		struct tdma_ras *r = &pool[i];

		/*
		 * Held this long for an older SDU: the peer gave that one up (its
		 * lifetime ran out) and sent no newer one that would tell us so.
		 */
		if (r->owner == owner && r->complete &&
		    (int64_t)(now - r->touched) > (int64_t)hold && l->rx_tag_valid &&
		    (int8_t)(r->tag - l->rx_tag_next) > 0) {
			l->rx_tag_next = r->tag;
			ras_flush(l, pool, n_pool, owner, deliver, ctx, st);
		}
	}
}

/* Forget delivered tags that fell out of the peer's tag window. */
static void done_expire(struct tdma_link *l)
{
	uint8_t k = 0;

	for (uint8_t i = 0; i < l->done_n; i++) {
		uint8_t t = l->done_tag[(l->done_i + sizeof(l->done_tag) - l->done_n + i) %
					sizeof(l->done_tag)];

		if ((uint8_t)(l->rx_tag_hi - t) < l->rx_inflight) {
			l->done_tag[k++] = t; /* oldest first */
		}
	}
	l->done_n = k;
	l->done_i = (uint8_t)(k % sizeof(l->done_tag));
}

static unsigned int popcount32(uint32_t x)
{
	x = x - ((x >> 1) & 0x55555555u);
	x = (x & 0x33333333u) + ((x >> 2) & 0x33333333u);
	return (((x + (x >> 4)) & 0x0f0f0f0fu) * 0x01010101u) >> 24;
}

/*
 * Mark units [a, b) received; returns how many were new. A word of the map at
 * a time (a 700 B fragment is 175 units: bit by bit that was ~27 us of the
 * FT's MAC thread per received long burst on the modem).
 */
static unsigned int ras_mark(struct tdma_ras *r, unsigned int a, unsigned int b)
{
	unsigned int n = 0;

	while (a < b) {
		unsigned int w = a / 32, lo = a % 32;
		unsigned int hi = (b - w * 32u) < 32u ? (b - w * 32u) : 32u; /* exclusive */
		uint32_t mask = (hi == 32u ? ~0u : ((1u << hi) - 1u)) & ~((1u << lo) - 1u);

		n += popcount32(mask & ~r->map[w]);
		r->map[w] |= mask;
		a = w * 32u + hi;
	}
	return n;
}

void link_rx_data(struct tdma_link *l, struct tdma_ras *pool, size_t n_pool, uint8_t owner,
		  const struct tdma_data *d, uint64_t now, link_deliver_fn deliver, void *ctx,
		  struct tdma_stats *st)
{
	struct tdma_ras *r;
	unsigned int units;

	/* Ack in the next two bursts even for duplicates: our previous ack
	 * evidently did not make it.
	 */
	l->ack_dirty = 2;
	if (!rx_is_new(l, d->seq)) {
		st->dup_rx++;
		return;
	}
	if (!d->frag) {
		rx_mark(l, d->seq);
		st->pdus_rx++;
		st->sdu_rx++;
		deliver(ctx, d->payload, d->len);
		return;
	}
	/* the peer's tag window (tag_window_ok()): older buffers and delivered tags are dead */
	if (!l->rx_tag_valid) {
		l->rx_tag_valid = true;
		l->rx_tag_hi = l->rx_tag_next = d->frag_tag;
	} else if ((int8_t)(d->frag_tag - l->rx_tag_hi) > 0) {
		l->rx_tag_hi = d->frag_tag;
		ras_flush(l, pool, n_pool, owner, deliver, ctx, st);
		done_expire(l);
	} else if ((uint8_t)(l->rx_tag_hi - d->frag_tag) >= l->rx_inflight) {
		/* an old tag: a resend of a part of an SDU done with */
		rx_mark(l, d->seq);
		st->pdus_rx++;
		return;
	}
	for (uint8_t i = 0; i < l->done_n; i++) {
		if (l->done_tag[i] == d->frag_tag) {
			/* a resent part of an SDU delivered already */
			rx_mark(l, d->seq);
			st->pdus_rx++;
			return;
		}
	}
	r = ras_get(pool, n_pool, owner, d->frag_tag, d->frag_total, now);
	if (!r) {
		/* not taken (no ack): the sender resends it, maybe a buffer is free then */
		st->ras_full++;
		return;
	}
	rx_mark(l, d->seq);
	st->pdus_rx++;
	r->touched = now;
	if (r->complete) {
		return; /* held for the SDUs before it; this part came twice */
	}
	/* tdma_data_decode() bounded off + len by frag_total <= TDMA_MAX_SDU, and the alignment */
	memcpy(&r->buf[d->frag_off], d->payload, d->len);
	r->have = (uint16_t)(r->have + ras_mark(r, d->frag_off / TDMA_FRAG_ALIGN,
						(d->frag_off + d->len + TDMA_FRAG_ALIGN - 1u) /
							TDMA_FRAG_ALIGN));
	units = (r->total + TDMA_FRAG_ALIGN - 1u) / TDMA_FRAG_ALIGN;
	if (r->have < units) {
		return;
	}
	r->complete = true;
	if ((int8_t)(r->tag - l->rx_tag_next) < 0) {
		ras_deliver(l, r, deliver, ctx,
			    st); /* older than where in-order delivery started */
		return;
	}
	ras_flush(l, pool, n_pool, owner, deliver, ctx, st);
}
