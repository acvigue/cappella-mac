/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * What the TDMA MAC needs from the platform (docs/mac-design.md).
 *
 * Every call is non-blocking. Times are absolute modem ticks (69.12 MHz) of
 * the node's own modem clock. The MAC is instance based (struct tdma_mac) so
 * the host simulation can run many nodes in one process; on the modem there
 * is exactly one instance and ctx is unused or points at the driver state.
 *
 * Completion of every accepted rx/tx op is reported back through
 * tdma_on_op_done(); received packets through tdma_on_rx(), always before the
 * op_done of the RX op that received them (nrf_modem_dect_phy does the same:
 * PDC/PCC events precede op_complete).
 */

#ifndef TDMA_PORT_H_
#define TDMA_PORT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Link security (docs/mac-design.md "Link security"): the MAC builds the nonce, the AAD and the
 * packet layout; the platform does the crypto behind opaque key handles, so
 * the library stays crypto-agnostic (a hardware AES or a secure partition on
 * the device, the reference AES of tdma_sec_ref.h in the host tests). A NULL struct tdma_port.sec
 * means security off.
 *
 * All calls come from the MAC context and must not block for long: seal is
 * on the TX commit path (inside the commit lead), open on the RX path.
 */
#define TDMA_SEC_NONCE_LEN 13
#define TDMA_SEC_NO_KEY    0xffu /* key_state: no such index */
/* derive(): the key index is not installed (Zephyr's -ENOKEY; not in every libc). */
#define TDMA_ERR_NOKEY     (-126)

struct tdma_sec_ops {
	/*
	 * Session key for (key_idx, network, FT, session counter, session
	 * random) -> *handle (!= 0). FT: its own session; PT: any FT session it
	 * hears. TDMA_ERR_NOKEY when key_idx is not installed.
	 */
	int (*derive)(void *ctx, uint8_t key_idx, uint32_t network_id, uint32_t ft_rd,
		      uint32_t sess_ctr, uint32_t sess_rand, uint32_t *handle);
	void (*release)(void *ctx, uint32_t handle);
	/* AES-128-CCM, body encrypted in place, mic = TDMA_SEC_MIC_LEN bytes. */
	int (*seal)(void *ctx, uint32_t handle, const uint8_t nonce[TDMA_SEC_NONCE_LEN],
		    const uint8_t *aad, size_t aad_len, uint8_t *body, size_t len, uint8_t *mic);
	/* 0 ok (body decrypted in place), -EBADMSG on a MIC failure (body undefined). */
	int (*open)(void *ctx, uint32_t handle, const uint8_t nonce[TDMA_SEC_NONCE_LEN],
		    const uint8_t *aad, size_t aad_len, uint8_t *body, size_t len,
		    const uint8_t *mic);
	/*
	 * FT: the key index to run on (*active) and one to switch to with an
	 * announced switch (*next, TDMA_SEC_NO_KEY = none). Polled once per
	 * beacon.
	 */
	int (*key_state)(void *ctx, uint8_t *active, uint8_t *next);
	/* A random 32-bit value (session random). */
	uint32_t (*random)(void *ctx);
	/*
	 * Optional cost model for the commit lead (0 = none): sealing a burst
	 * of n payload bytes takes about base + per16 * ceil(n / 16) ticks;
	 * TX slots are then committed that much earlier. Opening costs the
	 * same and lengthens the ARQ turnaround; a commit is kept out of the
	 * time in which the MAC verifies a burst it just received.
	 */
	uint32_t seal_ticks_base;
	uint32_t seal_ticks_per16;
	/*
	 * Optional typical open cost, same form (0, 0 = the seal model): an FT
	 * of a hybrid plan grants long bursts one DL period ahead
	 * (tdma_cfg.grant_ahead) when a PT cannot verify the DL burst with the
	 * grant in the time the plan leaves before the long burst.
	 */
	uint32_t open_ticks_base;
	uint32_t open_ticks_per16;
};

struct tdma_port {
	void *ctx;

	/* Current modem time in ticks. */
	uint64_t (*now)(void *ctx);

	/*
	 * Receive on channel from start for duration ticks. start == 0 means
	 * "as soon as possible" (used only for the continuous search RX).
	 * Returns 0 when the op was accepted, negative errno otherwise.
	 */
	int (*rx)(void *ctx, uint32_t handle, uint64_t start, uint32_t duration_ticks,
		  uint16_t channel);

	/*
	 * Stop an RX op early (nrf_modem_dect_phy_rx_stop). The op_done for
	 * the handle still follows. Not in the v0 spec; needed to leave the
	 * continuous search RX the moment a beacon is heard.
	 */
	int (*rx_stop)(void *ctx, uint32_t handle);

	/*
	 * Transmit one packet at start. subslots is the packet length
	 * (physical header packet_length = subslots - 1, length type subslots);
	 * the packet fills the whole burst. len never exceeds the transport
	 * block size for (mcs, subslots): the MAC sizes its PDUs (tdma_tbs())
	 * because the modem silently pads / truncates to the TBS.
	 *
	 * lbt_ticks > 0: listen before talk. The channel must measure below
	 * lbt_dbm (RSSI-1) for the lbt_ticks right before start, else the
	 * packet is not sent and the op completes with TDMA_ERR_LBT_BUSY
	 * (nrf_modem_dect_phy_tx lbt_period / lbt_rssi_threshold_max). The LBT
	 * window counts as part of the op for the PHY's gap and lead rules.
	 */
	int (*tx)(void *ctx, uint32_t handle, uint64_t start, uint16_t channel,
		  const uint8_t *phy_hdr, size_t hdr_len, const uint8_t *payload, size_t len,
		  uint8_t subslots, uint8_t mcs, uint32_t lbt_ticks, int8_t lbt_dbm);

	/*
	 * Optional (NULL: no channel selection scan / interference monitoring).
	 *
	 * rssi: RSSI-1 measurement on channel from start for duration ticks
	 * (nrf_modem_dect_phy_rssi). Results go to tdma_on_rssi() (any number of
	 * calls, before the op's tdma_on_op_done()).
	 *
	 * scan: receive on channel from start (0 = as soon as possible) for
	 * duration ticks with no network filter, measuring RSSI-1 at the same
	 * time (nrf_modem_dect_phy_rx with rssi_interval). Every valid PCC goes
	 * to tdma_on_pcc(), every decoded packet of ours (type 2 header) to
	 * tdma_on_rx(), the RSSI to tdma_on_rssi().
	 */
	int (*rssi)(void *ctx, uint32_t handle, uint64_t start, uint32_t duration_ticks,
		    uint16_t channel);
	int (*scan)(void *ctx, uint32_t handle, uint64_t start, uint32_t duration_ticks,
		    uint16_t channel);

	/* A complete SDU from src_rd_id, to IP. data is only valid during the call. */
	void (*deliver)(void *ctx, uint32_t src_rd_id, const uint8_t *data, size_t len);

	/* Link security (NULL = off; every existing behaviour unchanged). */
	const struct tdma_sec_ops *sec;
	void *sec_ctx;

	/*
	 * Optional debug trace of data PDUs (NULL = off), for timing one packet
	 * through the MAC: TDMA_TRACE_TX when a data PDU is put into an own
	 * burst (called at commit time, air_start = the burst's start), and
	 * TDMA_TRACE_RX when one arrives (air_start = the burst's start as
	 * received). seq, frag_idx / frag_cnt (1 = not fragmented) and len are
	 * the PDU's.
	 */
	void (*trace)(void *ctx, uint8_t ev, uint32_t peer_rd, uint8_t seq, uint8_t frag_idx,
		      uint8_t frag_cnt, uint16_t len, uint64_t air_start);

	/*
	 * Optional (NULL: the radio is always ours). A relay runs two MAC
	 * instances on one radio (tdma_relay.c): nonzero when the op this
	 * instance wants on [start, start + dur) (start 0: as soon as possible,
	 * a search / scan op) is outside its windows. The slot is then skipped
	 * before anything is built or sealed (tdma_stats.relay_away).
	 */
	int (*away)(void *ctx, uint64_t start, uint32_t dur);
};

#define TDMA_TRACE_TX 1
#define TDMA_TRACE_RX 2

#endif /* TDMA_PORT_H_ */
