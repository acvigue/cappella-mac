/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* Reference link-security backend (see cappella/tdma_sec_ref.h). */

#include <cappella/tdma_sec_ref.h>
#include <cappella/tdma_sec_ref_crypto.h>
#include <cappella/tdma_mac.h>

#include <errno.h>
#include <string.h>

void tdma_sec_ref_init(struct tdma_sec_ref *s, uint32_t (*random)(void *ctx), void *random_ctx)
{
	memset(s, 0, sizeof(*s));
	s->next = TDMA_SEC_NO_KEY;
	s->random = random;
	s->random_ctx = random_ctx;
}

int tdma_sec_ref_set_key(struct tdma_sec_ref *s, uint8_t idx, const uint8_t *key)
{
	if (idx >= TDMA_SEC_REF_KEYS) {
		return -EINVAL;
	}
	s->have[idx] = key != NULL;
	if (key) {
		memcpy(s->key[idx], key, 16);
	} else {
		memset(s->key[idx], 0, 16);
	}
	return 0;
}

void tdma_sec_ref_set_state(struct tdma_sec_ref *s, uint8_t active, uint8_t next)
{
	s->active = active;
	s->next = next;
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static int ref_derive(void *ctx, uint8_t key_idx, uint32_t network_id, uint32_t ft_rd,
		      uint32_t sess_ctr, uint32_t sess_rand, uint32_t *handle)
{
	struct tdma_sec_ref *s = ctx;
	uint8_t c[16];

	if (key_idx >= TDMA_SEC_REF_KEYS || !s->have[key_idx]) {
		return TDMA_ERR_NOKEY;
	}
	for (uint32_t i = 0; i < TDMA_SEC_REF_SESSIONS; i++) {
		if (!s->sess[i].used) {
			put_be32(c, network_id);
			put_be32(c + 4, ft_rd);
			put_be32(c + 8, sess_ctr);
			put_be32(c + 12, sess_rand);
			tdma_ref_kdf(s->key[key_idx], TDMA_SEC_REF_LABEL, c, sizeof(c),
				     s->sess[i].key, 16);
			s->sess[i].used = true;
			*handle = i + 1u;
			return 0;
		}
	}
	return -ENOMEM;
}

static const uint8_t *sess_key(struct tdma_sec_ref *s, uint32_t handle)
{
	if (handle == 0 || handle > TDMA_SEC_REF_SESSIONS || !s->sess[handle - 1u].used) {
		return NULL;
	}
	return s->sess[handle - 1u].key;
}

static void ref_release(void *ctx, uint32_t handle)
{
	struct tdma_sec_ref *s = ctx;

	if (sess_key(s, handle)) {
		memset(&s->sess[handle - 1u], 0, sizeof(s->sess[0]));
	}
}

static int ref_seal(void *ctx, uint32_t handle, const uint8_t nonce[TDMA_SEC_NONCE_LEN],
		    const uint8_t *aad, size_t aad_len, uint8_t *body, size_t len, uint8_t *mic)
{
	const uint8_t *k = sess_key(ctx, handle);

	if (!k) {
		return -EINVAL;
	}
	tdma_ref_ccm_seal(k, nonce, TDMA_SEC_NONCE_LEN, aad, aad_len, body, len, mic,
			  TDMA_SEC_MIC_LEN);
	return 0;
}

static int ref_open(void *ctx, uint32_t handle, const uint8_t nonce[TDMA_SEC_NONCE_LEN],
		    const uint8_t *aad, size_t aad_len, uint8_t *body, size_t len,
		    const uint8_t *mic)
{
	const uint8_t *k = sess_key(ctx, handle);

	if (!k) {
		return -EINVAL;
	}
	return tdma_ref_ccm_open(k, nonce, TDMA_SEC_NONCE_LEN, aad, aad_len, body, len, mic,
				 TDMA_SEC_MIC_LEN)
		       ? -EBADMSG
		       : 0;
}

static int ref_key_state(void *ctx, uint8_t *active, uint8_t *next)
{
	const struct tdma_sec_ref *s = ctx;

	*active = s->active < TDMA_SEC_REF_KEYS && s->have[s->active] ? s->active : TDMA_SEC_NO_KEY;
	*next = s->next;
	return 0;
}

static uint32_t ref_random(void *ctx)
{
	struct tdma_sec_ref *s = ctx;

	return s->random(s->random_ctx);
}

const struct tdma_sec_ops tdma_sec_ref_ops = {
	.derive = ref_derive,
	.release = ref_release,
	.seal = ref_seal,
	.open = ref_open,
	.key_state = ref_key_state,
	.random = ref_random,
};
