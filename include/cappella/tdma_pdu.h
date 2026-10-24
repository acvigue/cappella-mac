/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * TDMA MAC PDU codec (v0 format, docs/mac-design.md "PDUs" + "Decisions").
 *
 * A PHY payload is a sequence of records: u8 len, u8 addr, PDU[len]; a len of
 * 0 (the PHY's zero padding up to the transport block size) ends it. addr is
 * the PT position a DL PDU is for, the sender's position for UL, or
 * TDMA_ADDR_ALL (beacon, association request).
 *
 * Multi-byte PDU fields are little endian; the 10-byte physical header is our
 * own packed stand-in for ETSI type 2 and big endian like the real one.
 * Decoders check every length and return -EINVAL / -EMSGSIZE / -ENOTSUP;
 * encoders return the encoded length or -ENOBUFS.
 */

#ifndef TDMA_PDU_H_
#define TDMA_PDU_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tdma_mac.h"

enum tdma_pdu_type {
	TDMA_PDU_BEACON = 0,
	TDMA_PDU_DATA = 1,
	TDMA_PDU_ASSOC_REQ = 2,
	TDMA_PDU_ACK = 3,
	TDMA_PDU_GRANT = 4,  /* FT -> all: who uses the next FLEX region(s) */
	TDMA_PDU_STATUS = 5, /* PT -> FT: queued bytes + DL link quality */
};

/* flags byte (byte 1 of every PDU) */
#define TDMA_F_SEC                0x01 /* reserved: AES-CCM + 4-byte MIC; v0 rejects it */
#define TDMA_F_ACK_VALID          0x02 /* data/ack: ack + ack_map fields are meaningful */
#define TDMA_F_FRAG               0x04 /* data: fragment header follows */
#define TDMA_F_CLOSING            0x08 /* beacon: FT is shutting the network down */
#define TDMA_F_FULL               0x10 /* beacon: no free position */
#define TDMA_F_WIDE               0x20 /* data/ack: 16-bit ack bitmap (one more header byte) */
/*
 * data/ack: the sender asks the receiver to start no new non-priority SDUs
 * towards it for now (hop-by-hop backpressure: a relay whose forwarding queue
 * holds enough from this neighbour). Bit 3 is CLOSING in a beacon only.
 */
#define TDMA_F_HOLD               0x08
#define TDMA_F_MOVE               0x40 /* beacon: the cluster moves (channel LE16, frame LE32, mask LE32) */
#define TDMA_F_HOP                0x80 /* beacon: the cluster hops (base LE16, mask LE32, seed LE32) */
/*
 * beacon: security extension follows (session ctr LE32, rand LE32, key idx,
 * sflags [, next: frame LE32, ctr LE32, rand LE32]). Bit 1 is a data / ack
 * flag elsewhere; a beacon never had it.
 */
#define TDMA_F_BSEC               0x02
/*
 * beacon: tree extension follows the others (depth, grid offset in subslots):
 * the cluster of a relay (docs/mac-design.md "Relays"). Bit 2 is the
 * data FRAG flag elsewhere; a beacon never had it.
 */
#define TDMA_F_TREE               0x04
#define TDMA_BEACON_TREE_LEN      2
/*
 * beacon: the cluster's frames shift: from frame retime_frame on
 * they start retime_delta ticks later ([0, frame), LE32 each), before the
 * tree extension. A relay re-aligning its cluster to a new parent's grid
 * (merge, a parent of another depth) announces it; its children shift with it
 * and keep their positions. Bit 5 is the data / ack WIDE flag elsewhere; a
 * beacon never had it.
 */
#define TDMA_F_RETIME             0x20
#define TDMA_BEACON_RETIME_LEN    8
/*
 * the tree extension may go on with a route record for the mesh
 * layer (opaque to the MAC): u8 length, then that many bytes (at most
 * TDMA_ROUTE_MAX). A root's cluster sends the extension with depth 0 and grid
 * 0 when it has a route record. Beacons with the two-byte extension only decode with no record.
 */
#define TDMA_BEACON_ROUTE_HDR_LEN 1
/*
 * after the route record (its length byte then present, 0 for
 * none) the tree extension may go on with extensions: type, length, data.
 * Decoders skip types they do not know (older ones stop at the route).
 * TDMA_BEXT_PMOVE: the PT at position `from` moves to `to` from frame on
 * (from, to, frame LE32): position compaction, the PT keeps its association.
 */
#define TDMA_BEXT_PMOVE           1
#define TDMA_BEXT_PMOVE_LEN       6
/*
 * TDMA_BEXT_APP carries 1..TDMA_BEXT_APP_MAX bytes of the mesh
 * layer's own (opaque to the MAC, tdma_set_beacon_ext()): the tree summary
 * a root scanning for other trees of its site compares with its own.
 */
#define TDMA_BEXT_APP             2 /* (TDMA_BEXT_APP_MAX: tdma_mac.h) */
/*
 * TDMA_BEXT_QUIET: the FT listens elsewhere (tdma_ft_scan())
 * from subslot `ss` of frame `frame` for `len` subslots (frame LE32, ss,
 * len): its PTs send nothing that would fall in it (their data goes in the
 * next slot after it instead of into a burst nobody hears).
 */
#define TDMA_BEXT_QUIET           3
#define TDMA_BEXT_QUIET_LEN       6
/* association request flags */
#define TDMA_AF_RELAY             0x04 /* the PT runs a child cluster: keep its slots, no FLEX */
/* status record flags: the PT runs (or is about to start) a child cluster (tdma_pt_set_relay) */
#define TDMA_STF_RELAY            0x04
/* status record flags : the PT's child cluster could run plan HGX: it wants position 1 */
#define TDMA_STF_HGX              0x10

/* beacon security extension sflags */
#define TDMA_SF_DEVKEY         0x01 /* running on the insecure dev key */
#define TDMA_SF_NEXT           0x02 /* a session / key switch is announced */
#define TDMA_SF_NEXT_IDX_SHIFT 4    /* bits 4-5: key index of the next session */

/*
 * Security header (2 bytes, big endian) in front of every secured packet:
 * b15-14 version (01), b13-12 key index, b11 C (the first record is
 * cleartext: beacon or association request), b10-0 body length.
 */
struct tdma_sec_hdr {
	uint8_t ver;
	uint8_t key_idx;
	bool clear;
	uint16_t body_len;
};

#define TDMA_SEC_BODY_MAX 2047

#define TDMA_BEACON_MOVE_LEN 10
#define TDMA_BEACON_HOP_LEN  10

struct tdma_phy_hdr {
	uint8_t subslots;   /* packet length, 1..16 */
	uint8_t short_nwid; /* low byte of the network id */
	uint16_t tx_short;
	uint16_t rx_short; /* TDMA_SHORT_BROADCAST for beacons */
	uint8_t tx_power;  /* 4 bit, informational */
	uint8_t mcs;       /* 3 bit */
};

#define TDMA_ADDR_ALL 0xff

/* Position table entry: short rd id (unique within a site), 0 = free. */
struct tdma_beacon_entry {
	uint16_t short_id;
	uint8_t nonce;
};

struct tdma_beacon {
	uint8_t flags;
	uint32_t network_id;
	uint32_t ft_rd_id;
	uint32_t frame;
	uint8_t plan_id; /* (on air: low nibble; high nibble plan_next) */
	uint8_t mcs;     /* what PTs use for their UL (on air: low nibble; high nibble plan_in) */
	/* a plan switch: plan_next - 1 from frame + plan_in on (plan_next 0: none) */
	uint8_t plan_next;
	uint8_t plan_in;
	uint8_t roster_ver;
	uint8_t n;
	struct tdma_beacon_entry e[TDMA_MAX_POSITIONS];
	/* TDMA_F_HOP: frame f is on hop_base + the permutation of hop_mask's bits (hop_seed) */
	uint16_t hop_base;
	uint32_t hop_mask;
	uint32_t hop_seed;
	/* TDMA_F_MOVE: from frame move_frame on, carrier move_ch (move_mask != 0: hop over it) */
	uint16_t move_ch;
	uint32_t move_frame;
	uint32_t move_mask;
	/* TDMA_F_BSEC: the FT's security session (and an announced switch) */
	uint32_t sess_ctr;
	uint32_t sess_rand;
	uint8_t key_idx;
	uint8_t sflags; /* TDMA_SF_* */
	uint32_t next_frame;
	uint32_t next_ctr;
	uint32_t next_rand;
	/* TDMA_F_RETIME: frames from retime_frame on start retime_delta ticks later */
	uint32_t retime_frame;
	uint32_t retime_delta;
	/* TDMA_F_TREE: depth of the cluster (its FT's hops from the root), frame offset from the
	 * root's */
	uint8_t depth;
	uint8_t grid_ss;
	/* TDMA_F_TREE: the mesh layer's route record (0 bytes: none) */
	uint8_t route_len;
	uint8_t route[TDMA_ROUTE_MAX];
	/* TDMA_BEXT_PMOVE (with TDMA_F_TREE): the PT at pm_from moves to pm_to from pm_frame on */
	bool pm_valid;
	bool pm_swap; /* (bit 7 of `to` on air) the PT at pm_to moves to pm_from at the same frame
		       */
	uint8_t pm_from, pm_to;
	uint32_t pm_frame;
	/* TDMA_BEXT_APP (with TDMA_F_TREE and a route record): the mesh layer's bytes (0: none) */
	uint8_t app_len;
	uint8_t app[TDMA_BEXT_APP_MAX];
	/* TDMA_BEXT_QUIET (with TDMA_F_TREE): the FT is away from q_ss of q_frame for q_len
	 * subslots */
	bool q_valid;
	uint32_t q_frame;
	uint8_t q_ss, q_len;
};

struct tdma_ack {
	bool valid;
	uint8_t ack;      /* highest seq received */
	uint16_t ack_map; /* bit i: ack-1-i received (8 bits unless wide) */
	bool wide;        /* encoded / decoded with a 16-bit bitmap */
	bool hold;        /* TDMA_F_HOLD in the PDU carrying it */
};

struct tdma_data {
	uint8_t flags;
	uint8_t seq;
	struct tdma_ack ack;
	bool frag;
	uint8_t frag_tag;
	uint16_t frag_off;   /* byte offset in the SDU (a multiple of TDMA_FRAG_ALIGN) */
	uint16_t frag_total; /* SDU length */
	uint16_t len;
	const uint8_t *payload; /* points into the decoded buffer */
};

struct tdma_assoc_req {
	uint8_t flags;
	uint32_t pt_rd_id;
	uint32_t ft_rd_id;
	uint8_t box_id;
	uint8_t nonce; /* session id echoed in the beacon (v0: "capabilities" byte) */
};

#define TDMA_GRANT_F_UL    0x01 /* PT -> FT (else FT -> PT) */
#define TDMA_GRANT_F_SPEC  0x02 /* speculative: send only if there is data */
/*
 * For the FLEX region after the NEXT DL burst (one DL period ahead), not the
 * one right after this burst: the receiver then has a whole period to verify
 * the burst and prepare (cfg grant_ahead, used with link security).
 */
#define TDMA_GRANT_F_AHEAD 0x04
/*
 * Pattern plans: the pattern of the NEXT frame's FLEX regions (start = the
 * pattern, len = the plan id + 1): one entry with the DL MCS, one with
 * TDMA_GRANT_F_UL and the UL MCS.
 */
#define TDMA_GRANT_F_NEXT  0x08

struct tdma_grant_entry {
	uint8_t pos;   /* PT position */
	uint8_t flags; /* TDMA_GRANT_F_* */
	uint8_t start; /* first subslot, within the frame of the carrying burst */
	uint8_t len;   /* subslots, 1..TDMA_MAX_BURST_SS */
	uint8_t mcs;
};

struct tdma_grant {
	uint8_t flags;
	uint8_t n;
	struct tdma_grant_entry e[TDMA_MAX_GRANTS];
};

#define TDMA_SNR_UNKNOWN (-128)

struct tdma_status {
	uint8_t flags;
	uint16_t queued; /* bytes of PDU records still waiting to go (saturating) */
	int8_t snr;      /* dB, of the parent's bursts; TDMA_SNR_UNKNOWN if none yet */
	int8_t rssi;     /* dBm */
};

/*
 * Next record of a packet at *off. Returns 1 with addr/pdu/pdu_len set, 0 at
 * the end (padding), -EINVAL if a record overruns the packet.
 */
int tdma_rec_next(const uint8_t *pkt, size_t len, size_t *off, uint8_t *addr, const uint8_t **pdu,
		  size_t *pdu_len);
/* Room for one more PDU after *off (TDMA_REC_HDR_LEN already subtracted), 0 if none. */
size_t tdma_rec_room(size_t cap, size_t off);
/* Close a record whose PDU was encoded at pkt + off + TDMA_REC_HDR_LEN. */
void tdma_rec_close(uint8_t *pkt, size_t *off, uint8_t addr, size_t pdu_len);
/*
 * Long records: a PDU of more than TDMA_REC_SHORT_MAX bytes goes behind a
 * 4-byte header (0xff, addr, length LE16). tdma_rec_room_long() is the room
 * for one PDU after *off counting that (or the short header when the long
 * one does not pay off); encode the PDU at pkt + off + TDMA_REC_LONG_HDR_LEN
 * and close it with tdma_rec_close_long(), which moves a short one down.
 */
#define TDMA_REC_SHORT_MAX    254
#define TDMA_REC_LONG         0xff
#define TDMA_REC_LONG_HDR_LEN 4
size_t tdma_rec_room_long(size_t cap, size_t off);
void tdma_rec_close_long(uint8_t *pkt, size_t *off, uint8_t addr, size_t pdu_len);

void tdma_sec_hdr_encode(const struct tdma_sec_hdr *h, uint8_t out[2]);
/* -EINVAL unknown version */
int tdma_sec_hdr_decode(const uint8_t in[2], struct tdma_sec_hdr *h);

int tdma_phy_hdr_encode(const struct tdma_phy_hdr *h, uint8_t *buf, size_t cap);
int tdma_phy_hdr_decode(const uint8_t *buf, size_t len, struct tdma_phy_hdr *h);

/* PDU type of a buffer, or negative errno when it is too short / unknown. */
int tdma_pdu_type(const uint8_t *buf, size_t len);

int tdma_beacon_encode(const struct tdma_beacon *b, uint8_t *buf, size_t cap);
int tdma_beacon_decode(const uint8_t *buf, size_t len, struct tdma_beacon *b);

int tdma_data_encode(const struct tdma_data *d, uint8_t *buf, size_t cap);
int tdma_data_decode(const uint8_t *buf, size_t len, struct tdma_data *d);

int tdma_ack_encode(const struct tdma_ack *a, uint8_t *buf, size_t cap);
int tdma_ack_decode(const uint8_t *buf, size_t len, struct tdma_ack *a);

int tdma_assoc_encode(const struct tdma_assoc_req *r, uint8_t *buf, size_t cap);
int tdma_assoc_decode(const uint8_t *buf, size_t len, struct tdma_assoc_req *r);

int tdma_grant_encode(const struct tdma_grant *g, uint8_t *buf, size_t cap);
int tdma_grant_decode(const uint8_t *buf, size_t len, struct tdma_grant *g);

int tdma_status_encode(const struct tdma_status *st, uint8_t *buf, size_t cap);
int tdma_status_decode(const uint8_t *buf, size_t len, struct tdma_status *st);

#endif /* TDMA_PDU_H_ */
