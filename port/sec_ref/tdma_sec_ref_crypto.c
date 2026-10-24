/*
 * SPDX-License-Identifier: MPL-2.0
 * Copyright (c) 2026 The cappella-mac authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

/* Reference crypto (see cappella/tdma_sec_ref_crypto.h). */

#include <cappella/tdma_sec_ref_crypto.h>

#include <string.h>

static const uint8_t sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
	0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4,
	0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71,
	0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
	0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6,
	0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
	0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45,
	0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44,
	0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a,
	0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
	0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
	0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25,
	0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
	0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1,
	0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
	0x16,
};

static uint8_t xt(uint8_t x)
{
	return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

void tdma_ref_aes128(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
	uint8_t rk[176], s[16], t[16];
	uint8_t rcon = 1;

	memcpy(rk, key, 16);
	for (int i = 16; i < 176; i += 4) {
		uint8_t w[4] = {rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1]};

		if (i % 16 == 0) {
			uint8_t x = w[0];

			w[0] = (uint8_t)(sbox[w[1]] ^ rcon);
			w[1] = sbox[w[2]];
			w[2] = sbox[w[3]];
			w[3] = sbox[x];
			rcon = xt(rcon);
		}
		for (int j = 0; j < 4; j++) {
			rk[i + j] = (uint8_t)(rk[i - 16 + j] ^ w[j]);
		}
	}
	for (int i = 0; i < 16; i++) {
		s[i] = (uint8_t)(in[i] ^ rk[i]);
	}
	for (int r = 1; r <= 10; r++) {
		for (int i = 0; i < 16; i++) {
			t[i] = sbox[s[(i + 4 * (i % 4)) % 16]]; /* SubBytes + ShiftRows */
		}
		for (int c = 0; c < 4 && r < 10; c++) {
			uint8_t *a = &t[4 * c];
			uint8_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3],
				x = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);

			a[0] = (uint8_t)(a0 ^ x ^ xt((uint8_t)(a0 ^ a1)));
			a[1] = (uint8_t)(a1 ^ x ^ xt((uint8_t)(a1 ^ a2)));
			a[2] = (uint8_t)(a2 ^ x ^ xt((uint8_t)(a2 ^ a3)));
			a[3] = (uint8_t)(a3 ^ x ^ xt((uint8_t)(a3 ^ a0)));
		}
		for (int i = 0; i < 16; i++) {
			s[i] = (uint8_t)(t[i] ^ rk[16 * r + i]);
		}
	}
	memcpy(out, s, 16);
}

static void dbl(uint8_t b[16])
{
	uint8_t c = b[0] & 0x80;

	for (int i = 0; i < 15; i++) {
		b[i] = (uint8_t)((b[i] << 1) | (b[i + 1] >> 7));
	}
	b[15] = (uint8_t)((b[15] << 1) ^ (c ? 0x87 : 0));
}

void tdma_ref_cmac(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t mac[16])
{
	uint8_t k1[16] = {0}, k2[16], x[16] = {0}, last[16] = {0};
	size_t n = len ? (len + 15) / 16 : 1;

	tdma_ref_aes128(key, k1, k1);
	dbl(k1);
	memcpy(k2, k1, 16);
	dbl(k2);
	for (size_t b = 0; b + 1 < n; b++) {
		for (int i = 0; i < 16; i++) {
			x[i] ^= msg[16 * b + i];
		}
		tdma_ref_aes128(key, x, x);
	}
	{
		size_t rem = len - 16 * (n - 1);

		if (rem) {
			memcpy(last, msg + 16 * (n - 1), rem);
		}
		if (rem == 16) {
			for (int i = 0; i < 16; i++) {
				last[i] ^= k1[i];
			}
		} else {
			last[rem] = 0x80;
			for (int i = 0; i < 16; i++) {
				last[i] ^= k2[i];
			}
		}
	}
	for (int i = 0; i < 16; i++) {
		x[i] ^= last[i];
	}
	tdma_ref_aes128(key, x, mac);
}

/* CBC-MAC of B0 | aad | data (unencrypted), and the CTR keystream applied to data. */
static void ccm_mac(const uint8_t key[16], const uint8_t *nonce, size_t nlen, const uint8_t *aad,
		    size_t alen, const uint8_t *data, size_t len, size_t m, uint8_t x[16])
{
	size_t L = 15 - nlen;
	uint8_t b[16];

	memset(b, 0, 16);
	b[0] = (uint8_t)((alen ? 0x40 : 0) | (((m - 2) / 2) << 3) | (L - 1));
	memcpy(b + 1, nonce, nlen);
	for (size_t i = 0; i < L; i++) {
		b[15 - i] = (uint8_t)(len >> (8 * i));
	}
	tdma_ref_aes128(key, b, x);
	if (alen) {
		uint8_t blk[16];
		size_t pos;

		memset(blk, 0, 16);
		blk[0] = (uint8_t)(alen >> 8);
		blk[1] = (uint8_t)alen;
		pos = 2;
		for (size_t i = 0; i < alen; i++) {
			blk[pos++] = aad[i];
			if (pos == 16) {
				for (int k = 0; k < 16; k++) {
					x[k] ^= blk[k];
				}
				tdma_ref_aes128(key, x, x);
				memset(blk, 0, 16);
				pos = 0;
			}
		}
		if (pos) {
			for (int k = 0; k < 16; k++) {
				x[k] ^= blk[k];
			}
			tdma_ref_aes128(key, x, x);
		}
	}
	for (size_t i = 0; i < len; i += 16) {
		for (size_t k = 0; k < 16 && i + k < len; k++) {
			x[k] ^= data[i + k];
		}
		tdma_ref_aes128(key, x, x);
	}
}

static void ccm_ctr(const uint8_t key[16], const uint8_t *nonce, size_t nlen, uint32_t i,
		    uint8_t s[16])
{
	uint8_t a[16];
	size_t L = 15 - nlen;

	memset(a, 0, 16);
	a[0] = (uint8_t)(L - 1);
	memcpy(a + 1, nonce, nlen);
	for (size_t k = 0; k < L && k < 4; k++) {
		a[15 - k] = (uint8_t)(i >> (8 * k));
	}
	tdma_ref_aes128(key, a, s);
}

void tdma_ref_ccm_seal(const uint8_t key[16], const uint8_t *nonce, size_t nlen, const uint8_t *aad,
		       size_t alen, uint8_t *data, size_t len, uint8_t *tag, size_t m)
{
	uint8_t x[16], s[16];

	ccm_mac(key, nonce, nlen, aad, alen, data, len, m, x);
	for (size_t i = 0; i < len; i += 16) {
		ccm_ctr(key, nonce, nlen, (uint32_t)(i / 16 + 1), s);
		for (size_t k = 0; k < 16 && i + k < len; k++) {
			data[i + k] ^= s[k];
		}
	}
	ccm_ctr(key, nonce, nlen, 0, s);
	for (size_t k = 0; k < m; k++) {
		tag[k] = (uint8_t)(x[k] ^ s[k]);
	}
}

int tdma_ref_ccm_open(const uint8_t key[16], const uint8_t *nonce, size_t nlen, const uint8_t *aad,
		      size_t alen, uint8_t *data, size_t len, const uint8_t *tag, size_t m)
{
	uint8_t x[16], s[16], d = 0;

	for (size_t i = 0; i < len; i += 16) {
		ccm_ctr(key, nonce, nlen, (uint32_t)(i / 16 + 1), s);
		for (size_t k = 0; k < 16 && i + k < len; k++) {
			data[i + k] ^= s[k];
		}
	}
	ccm_mac(key, nonce, nlen, aad, alen, data, len, m, x);
	ccm_ctr(key, nonce, nlen, 0, s);
	for (size_t k = 0; k < m; k++) {
		d |= (uint8_t)(tag[k] ^ x[k] ^ s[k]);
	}
	return d ? -1 : 0;
}

static void be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

void tdma_ref_kdf(const uint8_t key[16], const char *label, const uint8_t *ctx, size_t ctx_len,
		  uint8_t *out, size_t olen)
{
	uint8_t fixed[256], msg[300], k0[16], t[16];
	size_t llen = strlen(label), flen = 0;

	if (llen + 1 + ctx_len + 4 > sizeof(fixed)) {
		memset(out, 0, olen); /* label + context too long: no key */
		return;
	}
	memcpy(fixed, label, llen);
	flen = llen;
	fixed[flen++] = 0;
	if (ctx_len) {
		memcpy(fixed + flen, ctx, ctx_len);
	}
	flen += ctx_len;
	be32(fixed + flen, (uint32_t)(olen * 8));
	flen += 4;
	tdma_ref_cmac(key, fixed, flen, k0);
	for (uint32_t i = 1; olen; i++) {
		size_t n = olen < 16 ? olen : 16;

		be32(msg, i);
		memcpy(msg + 4, fixed, flen);
		memcpy(msg + 4 + flen, k0, 16);
		tdma_ref_cmac(key, msg, 4 + flen + 16, t);
		memcpy(out, t, n);
		out += n;
		olen -= n;
	}
}
