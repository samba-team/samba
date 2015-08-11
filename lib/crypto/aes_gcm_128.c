/*
   AES-GCM-128

   Copyright (C) Stefan Metzmacher 2014

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "../lib/crypto/crypto.h"
#include "lib/util/byteorder.h"

static inline void aes_gcm_128_inc32(uint8_t inout[AES_BLOCK_SIZE])
{
	uint32_t v;

	v = RIVAL(inout, AES_BLOCK_SIZE - 4);
	v += 1;
	RSIVAL(inout, AES_BLOCK_SIZE - 4, v);
}

static inline void aes_gcm_128_mul(const uint8_t x[AES_BLOCK_SIZE],
				   const uint8_t y[AES_BLOCK_SIZE],
				   uint8_t v[AES_BLOCK_SIZE],
				   uint8_t z[AES_BLOCK_SIZE])
{
	uint8_t i;
	/* 11100001 || 0^120 */
	static const uint8_t r[AES_BLOCK_SIZE] = {
		0xE1, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	};

	memset(z, 0, AES_BLOCK_SIZE);
	memcpy(v, y, AES_BLOCK_SIZE);

	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		uint8_t mask;
		for (mask = 0x80; mask != 0 ; mask >>= 1) {
			uint8_t v_lsb = v[AES_BLOCK_SIZE-1] & 1;
			if (x[i] & mask) {
				aes_block_xor(z, v, z);
			}

			aes_block_rshift(v, v);
			if (v_lsb != 0) {
				aes_block_xor(v, r, v);
			}
		}
	}
}

static inline void aes_gcm_128_ghash_block(struct aes_gcm_128_context *ctx,
					   const uint8_t in[AES_BLOCK_SIZE])
{
	aes_block_xor(ctx->Y, in, ctx->y.block);
	aes_gcm_128_mul(ctx->y.block, ctx->H, ctx->v.block, ctx->Y);
}

void aes_gcm_128_init(struct aes_gcm_128_context *ctx,
		      const uint8_t K[AES_BLOCK_SIZE],
		      const uint8_t IV[AES_GCM_128_IV_SIZE])
{
	ZERO_STRUCTP(ctx);

	AES_set_encrypt_key(K, 128, &ctx->aes_key);

	/*
	 * Step 1: generate H (ctx->Y is the zero block here)
	 */
	AES_encrypt(ctx->Y, ctx->H, &ctx->aes_key);

	/*
	 * Step 2: generate J0
	 */
	memcpy(ctx->J0, IV, AES_GCM_128_IV_SIZE);
	aes_gcm_128_inc32(ctx->J0);

	/*
	 * We need to prepare CB with J0.
	 */
	memcpy(ctx->CB, ctx->J0, AES_BLOCK_SIZE);
	ctx->c.ofs = AES_BLOCK_SIZE;
}

static inline void aes_gcm_128_update_tmp(struct aes_gcm_128_context *ctx,
					  struct aes_gcm_128_tmp *tmp,
					  const uint8_t *v, size_t v_len)
{
	tmp->total += v_len;

	if (tmp->ofs > 0) {
		size_t copy = MIN(AES_BLOCK_SIZE - tmp->ofs, v_len);

		memcpy(tmp->block + tmp->ofs, v, copy);
		tmp->ofs += copy;
		v += copy;
		v_len -= copy;
	}

	if (tmp->ofs == AES_BLOCK_SIZE) {
		aes_gcm_128_ghash_block(ctx, tmp->block);
		tmp->ofs = 0;
	}

	while (v_len >= AES_BLOCK_SIZE) {
		aes_gcm_128_ghash_block(ctx, v);
		v += AES_BLOCK_SIZE;
		v_len -= AES_BLOCK_SIZE;
	}

	if (v_len == 0) {
		return;
	}

	ZERO_STRUCT(tmp->block);
	memcpy(tmp->block, v, v_len);
	tmp->ofs = v_len;
}

void aes_gcm_128_updateA(struct aes_gcm_128_context *ctx,
			 const uint8_t *a, size_t a_len)
{
	aes_gcm_128_update_tmp(ctx, &ctx->A, a, a_len);
}

void aes_gcm_128_updateC(struct aes_gcm_128_context *ctx,
			 const uint8_t *c, size_t c_len)
{
	if (ctx->A.ofs > 0) {
		aes_gcm_128_ghash_block(ctx, ctx->A.block);
		ctx->A.ofs = 0;
	}

	aes_gcm_128_update_tmp(ctx, &ctx->C, c, c_len);
}

static inline void aes_gcm_128_crypt_tmp(struct aes_gcm_128_context *ctx,
					 struct aes_gcm_128_tmp *tmp,
					 uint8_t *m, size_t m_len)
{
	tmp->total += m_len;

	while (m_len > 0) {
		if (tmp->ofs == AES_BLOCK_SIZE) {
			aes_gcm_128_inc32(ctx->CB);
			AES_encrypt(ctx->CB, tmp->block, &ctx->aes_key);
			tmp->ofs = 0;
		}

		if (likely(tmp->ofs == 0 && m_len >= AES_BLOCK_SIZE)) {
			aes_block_xor(m, tmp->block, m);
			m += AES_BLOCK_SIZE;
			m_len -= AES_BLOCK_SIZE;
			aes_gcm_128_inc32(ctx->CB);
			AES_encrypt(ctx->CB, tmp->block, &ctx->aes_key);
			continue;
		}

		m[0] ^= tmp->block[tmp->ofs];
		m += 1;
		m_len -= 1;
		tmp->ofs += 1;
	}
}

void aes_gcm_128_crypt(struct aes_gcm_128_context *ctx,
		       uint8_t *m, size_t m_len)
{
	aes_gcm_128_crypt_tmp(ctx, &ctx->c, m, m_len);
}

void aes_gcm_128_digest(struct aes_gcm_128_context *ctx,
			uint8_t T[AES_BLOCK_SIZE])
{
	if (ctx->A.ofs > 0) {
		aes_gcm_128_ghash_block(ctx, ctx->A.block);
		ctx->A.ofs = 0;
	}

	if (ctx->C.ofs > 0) {
		aes_gcm_128_ghash_block(ctx, ctx->C.block);
		ctx->C.ofs = 0;
	}

	RSBVAL(ctx->AC, 0, ctx->A.total * 8);
	RSBVAL(ctx->AC, 8, ctx->C.total * 8);
	aes_gcm_128_ghash_block(ctx, ctx->AC);

	AES_encrypt(ctx->J0, ctx->c.block, &ctx->aes_key);
	aes_block_xor(ctx->c.block, ctx->Y, T);

	ZERO_STRUCTP(ctx);
}
