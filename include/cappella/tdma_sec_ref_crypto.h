/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Reference AES-128 / CMAC / CCM / SP 800-108 counter-mode KDF in portable C.
 *
 * For the host simulation and as a starting point on targets without an AES
 * engine: small and slow, NOT constant time, no key protection. Production
 * firmware should put tdma_sec_ops in front of a hardware AES / a secure
 * key store instead. The KDF follows NIST SP 800-108r1 counter mode with
 * CMAC as PRF and the K0 block (the PSA_ALG_SP800_108_COUNTER_CMAC layout).
 */

#ifndef CAPPELLA_TDMA_SEC_REF_CRYPTO_H_
#define CAPPELLA_TDMA_SEC_REF_CRYPTO_H_

#include <stddef.h>
#include <stdint.h>

void tdma_ref_aes128(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
void tdma_ref_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t mac[16]);

/*
 * CCM (RFC 3610 / SP 800-38C) with a nonce of 7..13 bytes and an M-byte tag
 * (4..16, even). Encrypts / decrypts in place; tdma_ref_ccm_open() returns 0 or -1 on
 * a tag mismatch.
 */
void tdma_ref_ccm_seal(const uint8_t key[16], const uint8_t *nonce, size_t nlen, const uint8_t *aad,
		       size_t alen, uint8_t *data, size_t len, uint8_t *tag, size_t m);
int tdma_ref_ccm_open(const uint8_t key[16], const uint8_t *nonce, size_t nlen, const uint8_t *aad,
		      size_t alen, uint8_t *data, size_t len, const uint8_t *tag, size_t m);

/*
 * K0 = CMAC(K, label || 0x00 || ctx || [8*olen]_32);
 * T(i) = CMAC(K, [i]_32 || label || 0x00 || ctx || [8*olen]_32 || K0), i = 1..
 */
void tdma_ref_kdf(const uint8_t key[16], const char *label, const uint8_t *ctx, size_t ctx_len,
		  uint8_t *out, size_t olen);

#endif /* CAPPELLA_TDMA_SEC_REF_CRYPTO_H_ */
