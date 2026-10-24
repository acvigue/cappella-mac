/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Reference link-security backend: struct tdma_sec_ops in portable C on the
 * reference AES-128-CCM of tdma_sec_ref_crypto.h, with keys in RAM.
 *
 * For the host simulation, for bring-up and as a template. It is slow (a
 * byte-oriented AES, key schedule per block), not constant time and keeps
 * keys in plain memory: production firmware should implement tdma_sec_ops
 * on a hardware AES and a protected key store, and keep the same session
 * key derivation if it must interoperate with this one.
 *
 * Session key of (key index, network id, FT rd id, session counter, session
 * random): NIST SP 800-108 counter-mode CMAC KDF of the network key with label
 * TDMA_SEC_REF_LABEL and context BE32(network) BE32(FT) BE32(counter)
 * BE32(random).
 */

#ifndef CAPPELLA_TDMA_SEC_REF_H_
#define CAPPELLA_TDMA_SEC_REF_H_

#include <stdbool.h>
#include <stdint.h>

#include "tdma_port.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TDMA_SEC_REF_KEYS     4
#define TDMA_SEC_REF_SESSIONS 8
#define TDMA_SEC_REF_LABEL    "CMs1"

struct tdma_sec_ref {
	uint8_t key[TDMA_SEC_REF_KEYS][16];
	bool have[TDMA_SEC_REF_KEYS];
	uint8_t active; /* key index in use */
	uint8_t next;   /* key index to switch to, TDMA_SEC_NO_KEY = none */
	struct {
		bool used;
		uint8_t key[16];
	} sess[TDMA_SEC_REF_SESSIONS];
	uint32_t (*random)(void *ctx);
	void *random_ctx;
};

/* No keys, active index 0, no switch pending. random() must not be NULL. */
void tdma_sec_ref_init(struct tdma_sec_ref *s, uint32_t (*random)(void *ctx), void *random_ctx);
/* Install (key != NULL) or remove the 16-byte network key of index idx (0..3). */
int tdma_sec_ref_set_key(struct tdma_sec_ref *s, uint8_t idx, const uint8_t *key);
/* The key index an FT runs on and the one it announces a switch to. */
void tdma_sec_ref_set_state(struct tdma_sec_ref *s, uint8_t active, uint8_t next);

/* The ops; tdma_port.sec_ctx must point at a struct tdma_sec_ref. No cost model. */
extern const struct tdma_sec_ops tdma_sec_ref_ops;

#ifdef __cplusplus
}
#endif

#endif /* CAPPELLA_TDMA_SEC_REF_H_ */
