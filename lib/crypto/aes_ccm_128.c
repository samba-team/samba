/*
   AES-CCM-128 (rfc 3610)

   Copyright (C) Stefan Metzmacher 2012

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
#include "lib/crypto/aes.h"
#include "lib/crypto/aes_ccm_128.h"
#include "lib/util/byteorder.h"

#define M_ ((AES_CCM_128_M - 2) / 2)
#define L_ (AES_CCM_128_L - 1)

void aes_ccm_128_init(struct aes_ccm_128_context *ctx,
		      const uint8_t K[AES_BLOCK_SIZE],
		      const uint8_t N[AES_CCM_128_NONCE_SIZE],
		      size_t a_total, size_t m_total)
{
	ZERO_STRUCTP(ctx);

	AES_set_encrypt_key(K, 128, &ctx->aes_key);
	memcpy(ctx->nonce, N, AES_CCM_128_NONCE_SIZE);
	ctx->a_remain = a_total;
	ctx->m_remain = m_total;

	/*
	 * prepare B_0
	 */
	ctx->B_i[0]  = L_;
	ctx->B_i[0] += 8 * M_;
	if (a_total > 0) {
		ctx->B_i[0] += 64;
	}
	memcpy(&ctx->B_i[1], ctx->nonce, AES_CCM_128_NONCE_SIZE);
	RSIVAL(ctx->B_i, (AES_BLOCK_SIZE - AES_CCM_128_L), m_total);

	/*
	 * prepare X_1
	 */
	AES_encrypt(ctx->B_i, ctx->X_i, &ctx->aes_key);

	/*
	 * prepare B_1
	 */
	ZERO_STRUCT(ctx->B_i);
	if (a_total >= UINT32_MAX) {
		RSSVAL(ctx->B_i, 0, 0xFFFF);
		RSBVAL(ctx->B_i, 2, (uint64_t)a_total);
		ctx->B_i_ofs = 10;
	} else if (a_total >= 0xFF00) {
		RSSVAL(ctx->B_i, 0, 0xFFFE);
		RSIVAL(ctx->B_i, 2, a_total);
		ctx->B_i_ofs = 6;
	} else if (a_total > 0) {
		RSSVAL(ctx->B_i, 0, a_total);
		ctx->B_i_ofs = 2;
	}

	/*
	 * prepare A_i
	 */
	ctx->A_i[0]  = L_;
	memcpy(&ctx->A_i[1], ctx->nonce, AES_CCM_128_NONCE_SIZE);

	ctx->S_i_ofs = AES_BLOCK_SIZE;
}

void aes_ccm_128_update(struct aes_ccm_128_context *ctx,
			const uint8_t *v, size_t v_len)
{
	size_t *remain;

	if (v_len == 0) {
		return;
	}

	if (ctx->a_remain > 0) {
		remain = &ctx->a_remain;
	} else {
		remain = &ctx->m_remain;
	}

	if (unlikely(v_len > *remain)) {
		abort();
	}

	if (ctx->B_i_ofs > 0) {
		size_t n = MIN(AES_BLOCK_SIZE - ctx->B_i_ofs, v_len);

		memcpy(&ctx->B_i[ctx->B_i_ofs], v, n);
		v += n;
		v_len -= n;
		ctx->B_i_ofs += n;
		*remain -= n;
	}

	if ((ctx->B_i_ofs == AES_BLOCK_SIZE) || (*remain == 0)) {
		aes_block_xor(ctx->X_i, ctx->B_i, ctx->B_i);
		AES_encrypt(ctx->B_i, ctx->X_i, &ctx->aes_key);
		ctx->B_i_ofs = 0;
	}

	while (v_len >= AES_BLOCK_SIZE) {
		aes_block_xor(ctx->X_i, v, ctx->B_i);
		AES_encrypt(ctx->B_i, ctx->X_i, &ctx->aes_key);
		v += AES_BLOCK_SIZE;
		v_len -= AES_BLOCK_SIZE;
		*remain -= AES_BLOCK_SIZE;
	}

	if (v_len > 0) {
		ZERO_STRUCT(ctx->B_i);
		memcpy(ctx->B_i, v, v_len);
		ctx->B_i_ofs += v_len;
		*remain -= v_len;
		v = NULL;
		v_len = 0;
	}

	if (*remain > 0) {
		return;
	}

	if (ctx->B_i_ofs > 0) {
		aes_block_xor(ctx->X_i, ctx->B_i, ctx->B_i);
		AES_encrypt(ctx->B_i, ctx->X_i, &ctx->aes_key);
		ctx->B_i_ofs = 0;
	}
}

static inline void aes_ccm_128_S_i(struct aes_ccm_128_context *ctx,
				   uint8_t S_i[AES_BLOCK_SIZE],
				   size_t i)
{
	RSIVAL(ctx->A_i, (AES_BLOCK_SIZE - AES_CCM_128_L), i);
	AES_encrypt(ctx->A_i, S_i, &ctx->aes_key);
}

void aes_ccm_128_crypt(struct aes_ccm_128_context *ctx,
		       uint8_t *m, size_t m_len)
{
	while (m_len > 0) {
		if (ctx->S_i_ofs == AES_BLOCK_SIZE) {
			ctx->S_i_ctr += 1;
			aes_ccm_128_S_i(ctx, ctx->S_i, ctx->S_i_ctr);
			ctx->S_i_ofs = 0;
		}

		if (likely(ctx->S_i_ofs == 0 && m_len >= AES_BLOCK_SIZE)) {
			aes_block_xor(m, ctx->S_i, m);
			m += AES_BLOCK_SIZE;
			m_len -= AES_BLOCK_SIZE;
			ctx->S_i_ctr += 1;
			aes_ccm_128_S_i(ctx, ctx->S_i, ctx->S_i_ctr);
			continue;
		}

		m[0] ^= ctx->S_i[ctx->S_i_ofs];
		m += 1;
		m_len -= 1;
		ctx->S_i_ofs += 1;
	}
}

void aes_ccm_128_digest(struct aes_ccm_128_context *ctx,
			uint8_t digest[AES_BLOCK_SIZE])
{
	if (unlikely(ctx->a_remain != 0)) {
		abort();
	}
	if (unlikely(ctx->m_remain != 0)) {
		abort();
	}

	/* prepare S_0 */
	aes_ccm_128_S_i(ctx, ctx->S_i, 0);

	/*
	 * note X_i is T here
	 */
	aes_block_xor(ctx->X_i, ctx->S_i, digest);

	ZERO_STRUCTP(ctx);
}
