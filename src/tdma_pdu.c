/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * PDU codec. Everything that comes off the air goes through a decoder here
 * first, so every length and range check lives in this file.
 */

#include <errno.h>
#include <string.h>

#include <cappella/tdma_pdu.h>

static void put_le16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void put_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static uint16_t get_le16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t get_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

/* ---- physical header (our packed stand-in for ETSI type 2) ---------------- */

/*
 * byte 0    : 0x20 marker (format 2) | packet length - 1 (4 bit)
 * byte 1    : short network id
 * byte 2-3  : transmitter short id (BE)
 * byte 4    : tx power (4 bit) << 4 | mcs (3 bit)
 * byte 5-6  : receiver short id (BE)
 * byte 7-9  : reserved (streams, DF redundancy, HARQ feedback): 0
 */
#define PHY_HDR_MARKER 0x20

int tdma_phy_hdr_encode(const struct tdma_phy_hdr *h, uint8_t *buf, size_t cap)
{
	if (cap < TDMA_PHY_HDR_LEN || h->subslots == 0 || h->subslots > 16) {
		return -ENOBUFS;
	}
	memset(buf, 0, TDMA_PHY_HDR_LEN);
	buf[0] = PHY_HDR_MARKER | ((h->subslots - 1) & 0x0f);
	buf[1] = h->short_nwid;
	buf[2] = (uint8_t)(h->tx_short >> 8);
	buf[3] = (uint8_t)h->tx_short;
	buf[4] = (uint8_t)(((h->tx_power & 0x0f) << 4) | (h->mcs & 0x07));
	buf[5] = (uint8_t)(h->rx_short >> 8);
	buf[6] = (uint8_t)h->rx_short;
	return TDMA_PHY_HDR_LEN;
}

int tdma_phy_hdr_decode(const uint8_t *buf, size_t len, struct tdma_phy_hdr *h)
{
	if (!buf || len != TDMA_PHY_HDR_LEN) {
		return -EINVAL;
	}
	if ((buf[0] & 0xf0) != PHY_HDR_MARKER) {
		return -ENOTSUP;
	}
	h->subslots = (buf[0] & 0x0f) + 1;
	h->short_nwid = buf[1];
	h->tx_short = (uint16_t)((buf[2] << 8) | buf[3]);
	h->tx_power = buf[4] >> 4;
	h->mcs = buf[4] & 0x07;
	h->rx_short = (uint16_t)((buf[5] << 8) | buf[6]);
	return 0;
}

/* ---- security header ------------------------------------------------------ */

void tdma_sec_hdr_encode(const struct tdma_sec_hdr *h, uint8_t out[2])
{
	uint16_t v = (uint16_t)(((h->ver & 3u) << 14) | ((h->key_idx & 3u) << 12) |
				((h->clear ? 1u : 0u) << 11) | (h->body_len & 0x7ffu));

	out[0] = (uint8_t)(v >> 8);
	out[1] = (uint8_t)v;
}

int tdma_sec_hdr_decode(const uint8_t in[2], struct tdma_sec_hdr *h)
{
	uint16_t v = (uint16_t)((in[0] << 8) | in[1]);

	h->ver = (uint8_t)(v >> 14);
	h->key_idx = (uint8_t)((v >> 12) & 3u);
	h->clear = (v >> 11) & 1u;
	h->body_len = v & 0x7ffu;
	return h->ver == TDMA_SEC_VERSION ? 0 : -EINVAL;
}

/* ---- common --------------------------------------------------------------- */

int tdma_pdu_type(const uint8_t *buf, size_t len)
{
	if (!buf || len < 2) {
		return -EINVAL;
	}
	if (buf[1] & TDMA_F_SEC) {
		return -ENOTSUP; /* v0 has no security; never accept "secured" PDUs */
	}
	if (buf[0] > TDMA_PDU_STATUS) {
		return -EINVAL;
	}
	return buf[0];
}

/* ---- records ---------------------------------------------------------------- */

int tdma_rec_next(const uint8_t *pkt, size_t len, size_t *off, uint8_t *addr, const uint8_t **pdu,
		  size_t *pdu_len)
{
	size_t o = *off;
	size_t n;

	if (o >= len || pkt[o] == 0) {
		return 0; /* end, or the PHY's zero padding */
	}
	n = pkt[o];
	if (n == TDMA_REC_LONG) {
		size_t h = TDMA_REC_LONG_HDR_LEN;

		if (o + h > len) {
			return -EINVAL;
		}
		n = get_le16(&pkt[o + 2]);
		if (n <= TDMA_REC_SHORT_MAX || o + h + n > len) {
			return -EINVAL;
		}
		*addr = pkt[o + 1];
		*pdu = &pkt[o + h];
		*pdu_len = n;
		*off = o + h + n;
		return 1;
	}
	if (o + TDMA_REC_HDR_LEN + n > len) {
		return -EINVAL;
	}
	*addr = pkt[o + 1];
	*pdu = &pkt[o + TDMA_REC_HDR_LEN];
	*pdu_len = n;
	*off = o + TDMA_REC_HDR_LEN + n;
	return 1;
}

size_t tdma_rec_room(size_t cap, size_t off)
{
	size_t room = off + TDMA_REC_HDR_LEN < cap ? cap - off - TDMA_REC_HDR_LEN : 0;

	return room > TDMA_REC_SHORT_MAX ? TDMA_REC_SHORT_MAX : room;
}

size_t tdma_rec_room_long(size_t cap, size_t off)
{
	size_t room = off + TDMA_REC_LONG_HDR_LEN < cap ? cap - off - TDMA_REC_LONG_HDR_LEN : 0;
	size_t s = tdma_rec_room(cap, off);

	return room > s ? room : s;
}

void tdma_rec_close_long(uint8_t *pkt, size_t *off, uint8_t addr, size_t pdu_len)
{
	if (pdu_len > TDMA_REC_SHORT_MAX) {
		pkt[*off] = TDMA_REC_LONG;
		pkt[*off + 1] = addr;
		put_le16(&pkt[*off + 2], (uint16_t)pdu_len);
		*off += TDMA_REC_LONG_HDR_LEN + pdu_len;
		return;
	}
	memmove(&pkt[*off + TDMA_REC_HDR_LEN], &pkt[*off + TDMA_REC_LONG_HDR_LEN], pdu_len);
	tdma_rec_close(pkt, off, addr, pdu_len);
}

void tdma_rec_close(uint8_t *pkt, size_t *off, uint8_t addr, size_t pdu_len)
{
	pkt[*off] = (uint8_t)pdu_len;
	pkt[*off + 1] = addr;
	*off += TDMA_REC_HDR_LEN + pdu_len;
}

/* ---- beacon --------------------------------------------------------------- */

/*
 * type, flags, network id, FT rd id, frame (LE32 each), plan, mcs, roster
 * version, n, n x (short id LE16, nonce)
 */
int tdma_beacon_encode(const struct tdma_beacon *b, uint8_t *buf, size_t cap)
{
	size_t len =
		TDMA_BEACON_FIXED_LEN + (size_t)b->n * TDMA_BEACON_ENTRY_LEN +
		((b->flags & TDMA_F_HOP) ? TDMA_BEACON_HOP_LEN : 0) +
		((b->flags & TDMA_F_MOVE) ? TDMA_BEACON_MOVE_LEN : 0) +
		((b->flags & TDMA_F_BSEC) ? TDMA_BEACON_SEC_LEN : 0) +
		((b->flags & TDMA_F_BSEC) && (b->sflags & TDMA_SF_NEXT) ? TDMA_BEACON_SEC_NEXT_LEN
									: 0) +
		((b->flags & TDMA_F_RETIME) ? TDMA_BEACON_RETIME_LEN : 0) +
		((b->flags & TDMA_F_TREE) ? TDMA_BEACON_TREE_LEN : 0) +
		((b->flags & TDMA_F_TREE) && (b->route_len || b->pm_valid || b->q_valid)
			 ? TDMA_BEACON_ROUTE_HDR_LEN + b->route_len
			 : 0) +
		((b->flags & TDMA_F_TREE) && b->q_valid ? 2u + TDMA_BEXT_QUIET_LEN : 0) +
		((b->flags & TDMA_F_TREE) && b->pm_valid ? 2u + TDMA_BEXT_PMOVE_LEN : 0) +
		((b->flags & TDMA_F_TREE) && b->route_len && b->app_len ? 2u + b->app_len : 0);
	uint8_t *p = buf;

	if (b->n > TDMA_MAX_POSITIONS || b->route_len > TDMA_ROUTE_MAX ||
	    b->app_len > TDMA_BEXT_APP_MAX || len > cap) {
		return -ENOBUFS;
	}
	*p++ = TDMA_PDU_BEACON;
	*p++ = b->flags & ~TDMA_F_SEC;
	put_le32(p, b->network_id);
	p += 4;
	put_le32(p, b->ft_rd_id);
	p += 4;
	put_le32(p, b->frame);
	p += 4;
	if (b->plan_id > 15 || b->mcs > 15 || b->plan_next > 15 || b->plan_in > 15) {
		return -EINVAL;
	}
	*p++ = (uint8_t)(b->plan_id | (b->plan_in ? b->plan_next << 4 : 0));
	*p++ = (uint8_t)(b->mcs | (b->plan_next ? b->plan_in << 4 : 0));
	*p++ = b->roster_ver;
	*p++ = b->n;
	for (uint8_t i = 0; i < b->n; i++) {
		put_le16(p, b->e[i].short_id);
		p[2] = b->e[i].nonce;
		p += TDMA_BEACON_ENTRY_LEN;
	}
	if (b->flags & TDMA_F_HOP) {
		put_le16(p, b->hop_base);
		put_le32(p + 2, b->hop_mask);
		put_le32(p + 6, b->hop_seed);
		p += TDMA_BEACON_HOP_LEN;
	}
	if (b->flags & TDMA_F_MOVE) {
		put_le16(p, b->move_ch);
		put_le32(p + 2, b->move_frame);
		put_le32(p + 6, b->move_mask);
		p += TDMA_BEACON_MOVE_LEN;
	}
	if (b->flags & TDMA_F_BSEC) {
		put_le32(p, b->sess_ctr);
		put_le32(p + 4, b->sess_rand);
		p[8] = b->key_idx;
		p[9] = b->sflags;
		p += TDMA_BEACON_SEC_LEN;
		if (b->sflags & TDMA_SF_NEXT) {
			put_le32(p, b->next_frame);
			put_le32(p + 4, b->next_ctr);
			put_le32(p + 8, b->next_rand);
			p += TDMA_BEACON_SEC_NEXT_LEN;
		}
	}
	if (b->flags & TDMA_F_RETIME) {
		if (b->retime_delta >= TDMA_FRAME_TICKS) {
			return -EINVAL;
		}
		put_le32(p, b->retime_frame);
		put_le32(p + 4, b->retime_delta);
		p += TDMA_BEACON_RETIME_LEN;
	}
	if (b->flags & TDMA_F_TREE) {
		if (b->grid_ss >= TDMA_SUBSLOTS_PER_FRAME) {
			return -EINVAL;
		}
		p[0] = b->depth;
		p[1] = b->grid_ss;
		if (b->route_len || b->pm_valid || b->q_valid) {
			p[2] = b->route_len;
			memcpy(&p[3], b->route, b->route_len);
		}
		if (b->pm_valid) {
			uint8_t *x = &p[3 + b->route_len];

			if (b->pm_from >= TDMA_MAX_POSITIONS || b->pm_to >= TDMA_MAX_POSITIONS ||
			    b->pm_from == b->pm_to) {
				return -EINVAL;
			}
			x[0] = TDMA_BEXT_PMOVE;
			x[1] = TDMA_BEXT_PMOVE_LEN;
			x[2] = b->pm_from;
			x[3] = (uint8_t)(b->pm_to | (b->pm_swap ? 0x80u : 0u));
			put_le32(&x[4], b->pm_frame);
		}
		{
			uint8_t *x = &p[3 + b->route_len +
					(b->pm_valid ? 2u + TDMA_BEXT_PMOVE_LEN : 0u)];

			if (b->route_len && b->app_len) {
				x[0] = TDMA_BEXT_APP;
				x[1] = b->app_len;
				memcpy(&x[2], b->app, b->app_len);
				x += 2u + b->app_len;
			}
			if (b->q_valid) {
				x[0] = TDMA_BEXT_QUIET;
				x[1] = TDMA_BEXT_QUIET_LEN;
				put_le32(&x[2], b->q_frame);
				x[6] = b->q_ss;
				x[7] = b->q_len;
			}
		}
	}
	return (int)len;
}

int tdma_beacon_decode(const uint8_t *buf, size_t len, struct tdma_beacon *b)
{
	const uint8_t *p;

	if (tdma_pdu_type(buf, len) != TDMA_PDU_BEACON || len < TDMA_BEACON_FIXED_LEN) {
		return -EINVAL;
	}
	b->flags = buf[1];
	b->network_id = get_le32(&buf[2]);
	b->ft_rd_id = get_le32(&buf[6]);
	b->frame = get_le32(&buf[10]);
	b->plan_id = buf[14] & 0x0f;
	b->plan_next = buf[14] >> 4;
	b->mcs = buf[15] & 0x0f;
	b->plan_in = buf[15] >> 4;
	if (!b->plan_next || !b->plan_in) {
		b->plan_next = b->plan_in = 0;
	}
	b->roster_ver = buf[16];
	b->n = buf[17];
	if (b->n > TDMA_MAX_POSITIONS) {
		return -EMSGSIZE;
	}
	if (len < TDMA_BEACON_FIXED_LEN + (size_t)b->n * TDMA_BEACON_ENTRY_LEN) {
		return -EINVAL;
	}
	if (b->ft_rd_id == 0 || b->ft_rd_id == TDMA_RD_BROADCAST || b->mcs > 7) {
		return -EINVAL;
	}
	p = &buf[TDMA_BEACON_FIXED_LEN];
	for (uint8_t i = 0; i < b->n; i++) {
		b->e[i].short_id = get_le16(p);
		b->e[i].nonce = p[2];
		p += TDMA_BEACON_ENTRY_LEN;
	}
	b->hop_base = 0;
	b->hop_mask = 0;
	b->hop_seed = 0;
	b->move_ch = 0;
	b->move_frame = 0;
	b->move_mask = 0;
	b->sess_ctr = b->sess_rand = 0;
	b->key_idx = 0;
	b->sflags = 0;
	b->next_frame = b->next_ctr = b->next_rand = 0;
	b->depth = b->grid_ss = 0;
	b->route_len = 0;
	b->pm_valid = false;
	b->pm_swap = false;
	b->pm_from = b->pm_to = 0;
	b->pm_frame = 0;
	b->app_len = 0;
	b->q_valid = false;
	b->q_frame = 0;
	b->q_ss = b->q_len = 0;
	if (b->flags & TDMA_F_HOP) {
		if (len < (size_t)(p - buf) + TDMA_BEACON_HOP_LEN) {
			return -EINVAL;
		}
		b->hop_base = get_le16(p);
		b->hop_mask = get_le32(p + 2);
		b->hop_seed = get_le32(p + 6);
		p += TDMA_BEACON_HOP_LEN;
		if (b->hop_base == 0 || (b->hop_mask & (b->hop_mask - 1)) == 0) {
			return -EINVAL; /* a hop set has >= 2 carriers */
		}
	}
	if (b->flags & TDMA_F_MOVE) {
		if (len < (size_t)(p - buf) + TDMA_BEACON_MOVE_LEN) {
			return -EINVAL;
		}
		b->move_ch = get_le16(p);
		b->move_frame = get_le32(p + 2);
		b->move_mask = get_le32(p + 6);
		p += TDMA_BEACON_MOVE_LEN;
		if (b->move_ch == 0 || (b->move_mask && (b->move_mask & (b->move_mask - 1)) == 0)) {
			return -EINVAL;
		}
	}
	if (b->flags & TDMA_F_BSEC) {
		if (len < (size_t)(p - buf) + TDMA_BEACON_SEC_LEN) {
			return -EINVAL;
		}
		b->sess_ctr = get_le32(p);
		b->sess_rand = get_le32(p + 4);
		b->key_idx = p[8];
		b->sflags = p[9];
		p += TDMA_BEACON_SEC_LEN;
		if (b->key_idx > 3) {
			return -EINVAL;
		}
		if (b->sflags & TDMA_SF_NEXT) {
			if (len < (size_t)(p - buf) + TDMA_BEACON_SEC_NEXT_LEN) {
				return -EINVAL;
			}
			b->next_frame = get_le32(p);
			b->next_ctr = get_le32(p + 4);
			b->next_rand = get_le32(p + 8);
			p += TDMA_BEACON_SEC_NEXT_LEN;
		}
	}
	b->retime_frame = b->retime_delta = 0;
	if (b->flags & TDMA_F_RETIME) {
		if (len < (size_t)(p - buf) + TDMA_BEACON_RETIME_LEN) {
			return -EINVAL;
		}
		b->retime_frame = get_le32(p);
		b->retime_delta = get_le32(p + 4);
		p += TDMA_BEACON_RETIME_LEN;
		if (b->retime_delta >= TDMA_FRAME_TICKS) {
			return -EINVAL;
		}
	}
	if (b->flags & TDMA_F_TREE) {
		if (len < (size_t)(p - buf) + TDMA_BEACON_TREE_LEN) {
			return -EINVAL;
		}
		b->depth = p[0];
		b->grid_ss = p[1];
		p += TDMA_BEACON_TREE_LEN;
		/* depth 0 is a root's cluster (route record only): on the root's own grid */
		if (b->depth > TDMA_MAX_DEPTH || b->grid_ss >= TDMA_SUBSLOTS_PER_FRAME ||
		    (b->depth == 0 && b->grid_ss != 0)) {
			return -EINVAL;
		}
		if (len > (size_t)(p - buf)) {
			size_t rl = p[0];

			if (rl > TDMA_ROUTE_MAX ||
			    len < (size_t)(p - buf) + TDMA_BEACON_ROUTE_HDR_LEN + rl) {
				return -EINVAL;
			}
			b->route_len = (uint8_t)rl;
			memcpy(b->route, p + 1, rl);
			p += TDMA_BEACON_ROUTE_HDR_LEN + rl;
			/* extensions ; unknown types are skipped */
			while (len >= (size_t)(p - buf) + 2u &&
			       len >= (size_t)(p - buf) + 2u + p[1]) {
				if (p[0] == TDMA_BEXT_PMOVE && p[1] == TDMA_BEXT_PMOVE_LEN &&
				    p[2] < TDMA_MAX_POSITIONS &&
				    (p[3] & 0x7fu) < TDMA_MAX_POSITIONS && p[2] != (p[3] & 0x7fu)) {
					b->pm_valid = true;
					b->pm_swap = (p[3] & 0x80u) != 0;
					b->pm_from = p[2];
					b->pm_to = (uint8_t)(p[3] & 0x7fu);
					b->pm_frame = get_le32(&p[4]);
				} else if (p[0] == TDMA_BEXT_APP && p[1] >= 1u &&
					   p[1] <= TDMA_BEXT_APP_MAX) {
					b->app_len = p[1];
					memcpy(b->app, &p[2], p[1]);
				} else if (p[0] == TDMA_BEXT_QUIET && p[1] == TDMA_BEXT_QUIET_LEN &&
					   p[7]) {
					b->q_valid = true;
					b->q_frame = get_le32(&p[2]);
					b->q_ss = p[6];
					b->q_len = p[7];
				}
				p += 2u + p[1];
			}
		}
	}
	return 0;
}

/* ---- data ------------------------------------------------------------------- */

/*
 * type, flags, seq, ack, ack_map (u8, or LE16 with TDMA_F_WIDE), len (LE16)
 * [FRAG: tag, off (LE16), SDU length (LE16)]
 * payload[len]
 */
int tdma_data_encode(const struct tdma_data *d, uint8_t *buf, size_t cap)
{
	size_t w = d->ack.wide ? 1 : 0;
	size_t hdr = TDMA_DATA_HDR_LEN + w + (d->frag ? TDMA_FRAG_HDR_LEN : 0);
	uint8_t flags = d->flags &
			~(TDMA_F_SEC | TDMA_F_ACK_VALID | TDMA_F_FRAG | TDMA_F_WIDE | TDMA_F_HOLD);
	uint16_t map = d->ack.valid ? d->ack.ack_map : 0;

	if (hdr + d->len > cap) {
		return -ENOBUFS;
	}
	if (d->ack.hold) {
		flags |= TDMA_F_HOLD;
	}
	if (d->ack.valid) {
		flags |= TDMA_F_ACK_VALID;
	}
	if (d->frag) {
		flags |= TDMA_F_FRAG;
	}
	if (w) {
		flags |= TDMA_F_WIDE;
	}
	buf[0] = TDMA_PDU_DATA;
	buf[1] = flags;
	buf[2] = d->seq;
	buf[3] = d->ack.valid ? d->ack.ack : 0;
	buf[4] = (uint8_t)map;
	if (w) {
		buf[5] = (uint8_t)(map >> 8);
	}
	put_le16(&buf[5 + w], d->len);
	if (d->frag) {
		buf[7 + w] = d->frag_tag;
		put_le16(&buf[8 + w], d->frag_off);
		put_le16(&buf[10 + w], d->frag_total);
	}
	if (d->len && d->payload) { /* NULL: the caller fills the payload in */
		memcpy(&buf[hdr], d->payload, d->len);
	}
	return (int)(hdr + d->len);
}

int tdma_data_decode(const uint8_t *buf, size_t len, struct tdma_data *d)
{
	size_t w, hdr;

	if (tdma_pdu_type(buf, len) != TDMA_PDU_DATA || len < TDMA_DATA_HDR_LEN) {
		return -EINVAL;
	}
	w = (buf[1] & TDMA_F_WIDE) ? 1 : 0;
	hdr = TDMA_DATA_HDR_LEN + w;
	if (len < hdr) {
		return -EINVAL;
	}
	d->flags = buf[1];
	d->seq = buf[2];
	d->ack.valid = (buf[1] & TDMA_F_ACK_VALID) != 0;
	d->ack.hold = (buf[1] & TDMA_F_HOLD) != 0;
	d->ack.wide = w != 0;
	d->ack.ack = buf[3];
	d->ack.ack_map = (uint16_t)(buf[4] | (w ? buf[5] << 8 : 0));
	d->len = get_le16(&buf[5 + w]);
	d->frag = (buf[1] & TDMA_F_FRAG) != 0;
	d->frag_tag = 0;
	d->frag_off = d->frag_total = 0;
	if (d->frag) {
		hdr += TDMA_FRAG_HDR_LEN;
		if (len < hdr) {
			return -EINVAL;
		}
		d->frag_tag = buf[7 + w];
		d->frag_off = get_le16(&buf[8 + w]);
		d->frag_total = get_le16(&buf[10 + w]);
		/* the reassembly map counts TDMA_FRAG_ALIGN units: cuts sit on them */
		if (d->len == 0 || d->frag_total > TDMA_MAX_SDU ||
		    (uint32_t)d->frag_off + d->len > d->frag_total ||
		    d->frag_off % TDMA_FRAG_ALIGN ||
		    (d->frag_off + d->len != d->frag_total && d->len % TDMA_FRAG_ALIGN)) {
			return -EMSGSIZE;
		}
	}
	if (hdr + d->len > len) {
		return -EINVAL;
	}
	if (d->len > TDMA_MAX_SDU) {
		return -EMSGSIZE;
	}
	d->payload = &buf[hdr];
	return 0;
}

/* ---- ack-only ------------------------------------------------------------------ */

/* type, flags, ack, ack_map (u8, or LE16 with TDMA_F_WIDE) */
int tdma_ack_encode(const struct tdma_ack *a, uint8_t *buf, size_t cap)
{
	size_t n = TDMA_ACK_LEN + (a->wide ? 1 : 0);
	uint16_t map = a->valid ? a->ack_map : 0;

	if (cap < n) {
		return -ENOBUFS;
	}
	buf[0] = TDMA_PDU_ACK;
	buf[1] = (uint8_t)((a->valid ? TDMA_F_ACK_VALID : 0) | (a->wide ? TDMA_F_WIDE : 0) |
			   (a->hold ? TDMA_F_HOLD : 0));
	buf[2] = a->valid ? a->ack : 0;
	buf[3] = (uint8_t)map;
	if (a->wide) {
		buf[4] = (uint8_t)(map >> 8);
	}
	return (int)n;
}

int tdma_ack_decode(const uint8_t *buf, size_t len, struct tdma_ack *a)
{
	if (tdma_pdu_type(buf, len) != TDMA_PDU_ACK || len < TDMA_ACK_LEN) {
		return -EINVAL;
	}
	a->wide = (buf[1] & TDMA_F_WIDE) != 0;
	if (a->wide && len < TDMA_ACK_LEN + 1) {
		return -EINVAL;
	}
	a->valid = (buf[1] & TDMA_F_ACK_VALID) != 0;
	a->hold = (buf[1] & TDMA_F_HOLD) != 0;
	a->ack = buf[2];
	a->ack_map = (uint16_t)(buf[3] | (a->wide ? buf[4] << 8 : 0));
	return 0;
}

/* ---- association request -------------------------------------------------------- */

int tdma_assoc_encode(const struct tdma_assoc_req *r, uint8_t *buf, size_t cap)
{
	if (cap < TDMA_ASSOC_LEN) {
		return -ENOBUFS;
	}
	buf[0] = TDMA_PDU_ASSOC_REQ;
	buf[1] = r->flags & ~TDMA_F_SEC;
	put_le32(&buf[2], r->pt_rd_id);
	put_le32(&buf[6], r->ft_rd_id);
	buf[10] = r->box_id;
	buf[11] = r->nonce;
	return TDMA_ASSOC_LEN;
}

int tdma_assoc_decode(const uint8_t *buf, size_t len, struct tdma_assoc_req *r)
{
	if (tdma_pdu_type(buf, len) != TDMA_PDU_ASSOC_REQ || len < TDMA_ASSOC_LEN) {
		return -EINVAL;
	}
	r->flags = buf[1];
	r->pt_rd_id = get_le32(&buf[2]);
	r->ft_rd_id = get_le32(&buf[6]);
	r->box_id = buf[10];
	r->nonce = buf[11];
	if (r->pt_rd_id == 0 || r->pt_rd_id == TDMA_RD_BROADCAST || r->nonce == 0) {
		return -EINVAL;
	}
	return 0;
}

/* ---- grant (FT -> all) ------------------------------------------------------------ */

/* type, flags, n, n x (pos, flags, start subslot, len subslots, mcs) */
int tdma_grant_encode(const struct tdma_grant *g, uint8_t *buf, size_t cap)
{
	size_t len = TDMA_GRANT_FIXED_LEN + (size_t)g->n * TDMA_GRANT_ENTRY_LEN;
	uint8_t *p = buf + TDMA_GRANT_FIXED_LEN;

	if (g->n > TDMA_MAX_GRANTS || len > cap) {
		return -ENOBUFS;
	}
	buf[0] = TDMA_PDU_GRANT;
	buf[1] = g->flags & ~TDMA_F_SEC;
	buf[2] = g->n;
	for (uint8_t i = 0; i < g->n; i++, p += TDMA_GRANT_ENTRY_LEN) {
		p[0] = g->e[i].pos;
		p[1] = g->e[i].flags;
		p[2] = g->e[i].start;
		p[3] = g->e[i].len;
		p[4] = g->e[i].mcs;
	}
	return (int)len;
}

int tdma_grant_decode(const uint8_t *buf, size_t len, struct tdma_grant *g)
{
	const uint8_t *p = buf + TDMA_GRANT_FIXED_LEN;

	if (tdma_pdu_type(buf, len) != TDMA_PDU_GRANT || len < TDMA_GRANT_FIXED_LEN) {
		return -EINVAL;
	}
	g->flags = buf[1];
	g->n = buf[2];
	if (g->n > TDMA_MAX_GRANTS) {
		return -EMSGSIZE;
	}
	if (len < TDMA_GRANT_FIXED_LEN + (size_t)g->n * TDMA_GRANT_ENTRY_LEN) {
		return -EINVAL;
	}
	for (uint8_t i = 0; i < g->n; i++, p += TDMA_GRANT_ENTRY_LEN) {
		g->e[i].pos = p[0];
		g->e[i].flags = p[1];
		g->e[i].start = p[2];
		g->e[i].len = p[3];
		g->e[i].mcs = p[4];
		if (p[2] >= TDMA_SUBSLOTS_PER_FRAME || p[3] == 0 || p[3] > TDMA_MAX_BURST_SS ||
		    p[2] + p[3] > TDMA_SUBSLOTS_PER_FRAME || p[4] > 4 ||
		    tdma_tbs(p[4], p[3]) == 0) {
			return -EINVAL;
		}
	}
	return 0;
}

/* ---- status (PT -> FT) ------------------------------------------------------------ */

/* type, flags, queued (LE16), snr (dB, s8), rssi (dBm, s8) */
int tdma_status_encode(const struct tdma_status *st, uint8_t *buf, size_t cap)
{
	if (cap < TDMA_STATUS_LEN) {
		return -ENOBUFS;
	}
	buf[0] = TDMA_PDU_STATUS;
	buf[1] = st->flags & ~TDMA_F_SEC;
	put_le16(&buf[2], st->queued);
	buf[4] = (uint8_t)st->snr;
	buf[5] = (uint8_t)st->rssi;
	return TDMA_STATUS_LEN;
}

int tdma_status_decode(const uint8_t *buf, size_t len, struct tdma_status *st)
{
	if (tdma_pdu_type(buf, len) != TDMA_PDU_STATUS || len < TDMA_STATUS_LEN) {
		return -EINVAL;
	}
	st->flags = buf[1];
	st->queued = get_le16(&buf[2]);
	st->snr = (int8_t)buf[4];
	st->rssi = (int8_t)buf[5];
	return 0;
}
