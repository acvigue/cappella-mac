/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Deterministic multi-node simulation for the TDMA MAC.
 *
 * - one global true clock (ticks); every node has its own modem clock
 *   local = offset + true * (1 + ppb / 1e9)
 * - a fake PHY per node implementing tdma_port.h with the behaviour measured
 *   in docs/phy-timing.md: lead TX 465 us / RX 390 us, idle between
 *   ops of one radio TX->TX 285, TX->RX 245, RX->TX 225, RX->RX 240 us, RX
 *   window open >= 1 us before the packet, exact transport block sizes
 *   (zero padding; longer payloads rejected as a MAC bug; at most 700 B), PDC
 *   latency 110-240 us, +-0.29 us TX jitter, ops at most two frames ahead
 * - per-link SNR: reported with every packet; a packet whose MCS needs more
 *   SNR than the link has is lost (MCS 0..4 need 1/4/7/10/13 dB)
 * - a shared air: a TX reaches every live node whose RX op on the same
 *   channel covers the whole packet; overlapping TXs on a channel collide
 *   (both lost, delivered with crc_ok = false); per-link loss probability
 *   from a seeded PRNG
 * - RSSI-1: every packet arrives at SIM_RX_DBM, the noise floor is
 *   SIM_NOISE_DBM, interferers (sim_add_interferer) add noise on a carrier,
 *   possibly duty-cycled; the neighbour carriers (+-1, they overlap in band 9)
 *   see any of it 6 dB lower. An interferer also lowers the SNR of packets on
 *   its carrier (SIR = SIM_RX_DBM - interferer). RSSI ops / scan ops report the
 *   highest level per subslot in 5 ms chunks, like the modem
 * - LBT on TX: the window before the packet counts as part of the op (lead,
 *   gaps); if RSSI-1 in it reaches the threshold the packet is not sent and the
 *   op completes with TDMA_ERR_LBT_BUSY
 */

#ifndef SIM_H_
#define SIM_H_

#include <stdbool.h>
#include <stdint.h>

#include <cappella/tdma_mac.h>

#define SIM_MAX_NODES   16
#define SIM_NODE_OPS    16
#define SIM_MAX_AIR     512
#define SIM_MAX_EVENTS  16384
#define SIM_MAX_EVT_LOG 512

#define SIM_SITE_ID   0x00001234u
#define SIM_CHANNEL   1705
#define SIM_CH_MIN    1703
#define SIM_CH_MAX    1711
#define SIM_NOISE_DBM (-100)
#define SIM_RX_DBM    (-60)
#define SIM_MAX_INTF  8

enum sim_op_kind {
	SIM_OP_RX,
	SIM_OP_TX,
	SIM_OP_RSSI,
	SIM_OP_SCAN,
};

/* Noise on carrier ch at dbm in [t_from, t_to); period 0 = continuous, else on for `on` per period.
 */
struct sim_intf {
	bool used;
	uint16_t ch;
	int8_t dbm;
	uint64_t t_from, t_to, period, on;
};

struct sim;

struct sim_op {
	bool used;
	bool is_tx;
	uint32_t handle;
	uint32_t gen;
	uint64_t t_start;
	uint64_t t_end;
	uint16_t ch;
	uint8_t kind;       /* enum sim_op_kind */
	uint8_t which;      /* the node's MAC instance: 0 mac, 1 rmac (a relay's child cluster) */
	int err;            /* reported with op_done (LBT busy) */
	uint64_t meas_next; /* RSSI / scan: start of the next unreported chunk */
};

/*
 * Link security of a node (sim_sec_*): keys by index, what the FT's
 * key_state reports, the persisted FT session counter, a seal cost model.
 * The ops use the reference AES / CCM / KDF of port/sec_ref (tdma_sec_ref_crypto.h).
 */
struct sim_sec_node {
	bool on;
	bool devkey;
	uint8_t key[4][16];
	bool have[4];
	uint8_t active, next;           /* key_state */
	uint32_t sess_ctr;              /* persisted by the "app": +1 per FT start */
	uint32_t cost_base, cost_per16; /* modelled seal time (ticks); 0 = free */
	bool hints;                     /* report the cost model to the MAC (per-slot lead) */
	uint64_t debt;                  /* seal time spent before the current TX call */
	uint32_t open_typ_base, open_typ_per16; /* typical open time reported to the MAC */
	uint32_t open_busy; /* MAC time an opened burst takes (ticks); 0 = free */
	uint64_t busy_add;  /* open time spent in the current RX event */
	struct {
		bool used;
		uint8_t key[16];
	} sess[2 * TDMA_SEC_SESS + 2]; /* a relay's two instances */
	struct tdma_sec_ops ops;
	uint8_t last_nonce[TDMA_SEC_NONCE_LEN];
	uint8_t ok_nonce[64][TDMA_SEC_NONCE_LEN]; /* nonces of the last bursts that verified */
	uint32_t n_ok;
};

struct sim_node;

/* A port context: one MAC instance of a node. */
struct sim_inst {
	struct sim_node *n;
	uint8_t which;
};

struct sim_node {
	uint32_t tx_fail_ppm, tx_failed; /* TX ops the modem fails (sim) */
	uint64_t dbg_last_rx_end;        /* debug: air end of the last burst delivered */
	uint32_t dbg_last_rx_info;       /* debug: its transmitter << 8 | subslots */
	struct sim *sim;
	int id;
	bool alive;
	struct tdma_mac mac;
	struct tdma_cfg cfg;
	struct tdma_mac_store store; /* cfg.mem unless a test sets its own */
	int64_t offset;
	int32_t ppb;
	struct sim_op ops[SIM_NODE_OPS];
	uint32_t gen;
	uint32_t tick_gen;
	uint64_t tick_at;    /* true time of the pending tick, UINT64_MAX = none */
	uint64_t busy_until; /* true time: the MAC thread is still verifying a burst */
	uint64_t lrx_end;    /* true time: end of the last long burst it received */
	uint32_t phy_errors;
	int n_evts;
	struct tdma_evt evts[SIM_MAX_EVT_LOG];
	uint64_t evt_t[SIM_MAX_EVT_LOG];
	struct sim_sec_node sec;
	/*
	 * Relay (sim_relay_on): mac is the up instance (PT, cfg.relay), rmac the
	 * child cluster's FT (plan HG) on relay_ch, started once mac is
	 * associated (tdma_relay_ready), stopped when it is not. One radio:
	 * both instances' ops share ops[] (the PHY's gap rules see the merged
	 * sequence) behind tdma_relay_away().
	 */
	struct sim_inst inst[2];
	bool relay_on;
	bool relay_hold; /* relay capable, child cluster held off ('relay auto') */
	bool relay_keep; /* the child cluster runs on while mac has no parent */
	uint16_t relay_ch;
	struct tdma_mac rmac;
	struct tdma_cfg rcfg;
	struct tdma_relay relay;
	struct tdma_mem rmem;
	uint32_t relay_starts, relay_stops;
	int rn_evts;
	struct tdma_evt revts[SIM_MAX_EVT_LOG];
	uint64_t revt_t[SIM_MAX_EVT_LOG];
};

typedef void (*sim_fn)(struct sim *s, void *arg);

struct sim_stats {
	uint32_t tx;
	uint32_t delivered;
	uint32_t collisions; /* receptions destroyed by overlap */
	uint32_t lost;       /* receptions dropped by link loss */
	uint32_t lost_snr;   /* receptions dropped: SNR too low for the MCS */
	uint32_t lost_intf;  /* receptions dropped: interferer (SIR too low for the MCS) */
	uint32_t lbt_busy;   /* TXs not sent: LBT found the channel busy */
};

/* SNR (dB) a packet needs at MCS 0..4 in the model (about the 10 % BLER points). */
#define SIM_SNR_DEFAULT 22

struct sim {
	uint64_t t;
	uint64_t rng;
	int n_nodes;
	struct sim_node nodes[SIM_MAX_NODES];
	uint32_t loss_ppm[SIM_MAX_NODES][SIM_MAX_NODES];
	int8_t snr_db[SIM_MAX_NODES][SIM_MAX_NODES]; /* link SNR, reported with every packet */
	struct sim_stats st;
	struct sim_intf intf[SIM_MAX_INTF];
	void (*on_deliver)(struct sim *s, int node, uint32_t src, const uint8_t *data, size_t len);
	void (*on_evt)(struct sim *s, int node, const struct tdma_evt *e);
	/* every packet put on air by a node (after sealing) */
	void (*on_air)(struct sim *s, int node, uint64_t t_start, uint16_t ch, const uint8_t *hdr,
		       const uint8_t *pl, size_t len, uint8_t subslots, uint8_t mcs);
	/* may change a node's packet on air (header and the TBS-sized payload) */
	void (*on_tamper)(struct sim *s, int node, uint8_t *hdr, uint8_t *pl, size_t tbs);
	void *user;
};

/* The one simulation instance (reset by sim_init). */
struct sim *sim_init(uint64_t seed);

uint32_t sim_rd_for_box(uint8_t box);
uint32_t sim_network_id(void);

/* Adds a node (not started). plan_id is used by FTs only. */
int sim_add_node(struct sim *s, enum tdma_role role, uint8_t box, uint8_t plan_id, int64_t offset,
		 int32_t ppb);
void sim_start(struct sim *s, int node);
void sim_kill(struct sim *s, int node);
/* Kill + fresh tdma_init/tdma_start (power cycle). */
void sim_revive(struct sim *s, int node);

void sim_at(struct sim *s, uint64_t t, sim_fn fn, void *arg);
void sim_run_until(struct sim *s, uint64_t t);

/* Queue an SDU at the instance that has a link to dst (a relay: its parent or a child). */
int sim_send(struct sim *s, int node, uint32_t dst, const uint8_t *data, size_t len, uint8_t prio);
/*
 * Make a PT node a relay (before sim_start): it asks for a relay position and
 * runs a child cluster on ch once associated.
 */
void sim_relay_on(struct sim *s, int node, uint16_t ch);
/* The node's child-cluster instance (NULL: not a relay). */
struct tdma_mac *sim_relay_mac(struct sim_node *n);
/*
 * A relay node's child cluster held off (on = false: it stops, the PT tells
 * its parent through the status record) or allowed again (relays
 * start and stop at run time, tdma_pt_set_relay()).
 */
void sim_relay_want(struct sim *s, int node, bool on);
void sim_set_loss_all(struct sim *s, uint32_t ppm);
/* Both directions between nodes a and b. */
void sim_set_snr(struct sim *s, int a, int b, int8_t db);

/* Interferer on ch (see struct sim_intf); returns its index. */
int sim_add_interferer(struct sim *s, uint16_t ch, int8_t dbm, uint64_t t_from, uint64_t t_to,
		       uint64_t period, uint64_t on);
/* Highest RSSI-1 node sees on ch in [t0, t1) (true time), its own TXs excluded. */
int8_t sim_rssi_at(struct sim *s, int node, uint16_t ch, uint64_t t0, uint64_t t1);

/* ---- security ---- */

/* sim_add_node enables security on every new node with sim_sec_default_key (sec_basic). */
extern bool sim_sec_all;
extern const uint8_t sim_sec_default_key[16];
/* With sim_sec_all: grant-ahead FTs and a flat seal cost (us, 0 = free) reported as hint. */
extern bool sim_grant_ahead;
extern uint32_t sim_sec_cost_us;
/*
 * With sim_sec_all: the typical open time reported to the MAC (us, 0 = the
 * seal model) and the MAC time an opened burst really takes (us, 0 = free):
 * ticks wait until the MAC thread is done, as on the DK.
 */
extern uint32_t sim_sec_open_us, sim_sec_busy_us;

/* Security on, key index 0 = key, active 0 (before sim_start). */
void sim_sec_on(struct sim *s, int node, const uint8_t key[16]);
/* Install (key) or remove (NULL) a key index. */
void sim_sec_key(struct sim *s, int node, uint8_t idx, const uint8_t *key);
/* key_state the node reports (next = TDMA_SEC_NO_KEY: no switch wanted). */
void sim_sec_state(struct sim *s, int node, uint8_t active, uint8_t next);

/* Global counters (across sim_init) and the nonce-reuse checker. */
struct sim_sec_stats {
	uint64_t seals, opens, open_fail;
	uint64_t nonce_reuse; /* (key, nonce) used for a second seal */
};
extern struct sim_sec_stats sim_sec_st;
void sim_sec_stats_reset(void);

/* A packet on air from nobody (attacker): true time t, carrier ch. */
void sim_inject(struct sim *s, uint64_t t, uint16_t ch, const uint8_t hdr[TDMA_PHY_HDR_LEN],
		const uint8_t *pl, size_t len, uint8_t subslots, uint8_t mcs);

/* Did node verify a burst with this nonce recently (last 64)? */
bool sim_sec_opened(const struct sim_node *n, const uint8_t nonce[TDMA_SEC_NONCE_LEN]);

uint64_t sim_local(const struct sim_node *n, uint64_t t);
/* True time of a node's local (modem clock) time. */
uint64_t sim_true_of(const struct sim_node *n, uint64_t local);
uint64_t sim_rand(struct sim *s);
uint32_t sim_phy_errors(const struct sim *s);
/* Modelled PDC latency (packet end -> tdma_on_rx) for a burst. */
uint64_t sim_pdc_ticks(uint8_t subslots, uint8_t mcs);

/* First logged event of type for node at or after t_from; NULL if none. */
const struct tdma_evt *sim_find_evt(const struct sim_node *n, enum tdma_evt_type type,
				    uint64_t t_from, uint64_t *t_out);
int sim_count_evt(const struct sim_node *n, enum tdma_evt_type type, uint64_t t_from);
/* The same for a relay's child-cluster instance. */
const struct tdma_evt *sim_find_revt(const struct sim_node *n, enum tdma_evt_type type,
				     uint64_t t_from, uint64_t *t_out);
int sim_count_revt(const struct sim_node *n, enum tdma_evt_type type, uint64_t t_from);

#endif /* SIM_H_ */
