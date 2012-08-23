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
#include "../lib/crypto/crypto.h"
#include "lib/util/byteorder.h"

#define M_ ((AES_CCM_128_M - 2) / 2)
#define L_ (AES_CCM_128_L - 1)

static inline void aes_ccm_128_xor(const uint8_t in1[AES_BLOCK_SIZE],
				   const uint8_t in2[AES_BLOCK_SIZE],
				   uint8_t out[AES_BLOCK_SIZE])
{
	uint8_t i;

	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		out[i] = in1[i] ^ in2[i];
	}
}

void aes_ccm_128_init(struct aes_ccm_128_context *ctx,
		      const uint8_t K[AES_BLOCK_SIZE],
		      const uint8_t N[AES_CCM_128_NONCE_SIZE],
		      size_t a_total, size_t m_total)
{
	uint8_t B_0[AES_BLOCK_SIZE];

	ZERO_STRUCTP(ctx);

	AES_set_encrypt_key(K, 128, &ctx->aes_key);
	memcpy(ctx->nonce, N, AES_CCM_128_NONCE_SIZE);
	ctx->a_remain = a_total;
	ctx->m_remain = m_total;

	/*
	 * prepare B_0
	 */
	B_0[0]  = L_;
	B_0[0] += 8 * M_;
	if (a_total > 0) {
		B_0[0] += 64;
	}
	memcpy(&B_0[1], ctx->nonce, AES_CCM_128_NONCE_SIZE);
	RSIVAL(B_0, (AES_BLOCK_SIZE - AES_CCM_128_L), m_total);

	/*
	 * prepare X_1
	 */
	AES_encrypt(B_0, ctx->X_i, &ctx->aes_key);

	/*
	 * prepare B_1
	 */
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

	ctx->S_i_ofs = AES_BLOCK_SIZE;
}

void aes_ccm_128_update(struct aes_ccm_128_context *ctx,
			const uint8_t *v, size_t v_len)
{
	size_t *remain;

	if (ctx->a_remain > 0) {
		remain = &ctx->a_remain;
	} else {
		remain = &ctx->m_remain;
	}

	while (v_len > 0) {
		size_t n = MIN(AES_BLOCK_SIZE - ctx->B_i_ofs, v_len);
		bool more = true;

		memcpy(&ctx->B_i[ctx->B_i_ofs], v, n);
		v += n;
		v_len -= n;
		ctx->B_i_ofs += n;
		*remain -= n;

		if (ctx->B_i_ofs == AES_BLOCK_SIZE) {
			more = false;
		} else if (*remain == 0) {
			more = false;
		}

		if (more) {
			continue;
		}

		aes_ccm_128_xor(ctx->X_i, ctx->B_i, ctx->B_i);
		AES_encrypt(ctx->B_i, ctx->X_i, &ctx->aes_key);

		ZERO_STRUCT(ctx->B_i);
		ctx->B_i_ofs = 0;
	}
}

static void aes_ccm_128_S_i(struct aes_ccm_128_context *ctx,
			    uint8_t S_i[AES_BLOCK_SIZE],
			    size_t i)
{
	uint8_t A_i[AES_BLOCK_SIZE];

	A_i[0]  = L_;
	memcpy(&A_i[1], ctx->nonce, AES_CCM_128_NONCE_SIZE);
	RSIVAL(A_i, (AES_BLOCK_SIZE - AES_CCM_128_L), i);

	AES_encrypt(A_i, S_i, &ctx->aes_key);
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

		m[0] ^= ctx->S_i[ctx->S_i_ofs];
		m += 1;
		m_len -= 1;
		ctx->S_i_ofs += 1;
	}
}

void aes_ccm_128_digest(struct aes_ccm_128_context *ctx,
			uint8_t digest[AES_BLOCK_SIZE])
{
	uint8_t S_0[AES_BLOCK_SIZE];

	aes_ccm_128_S_i(ctx, S_0, 0);

	/*
	 * note X_i is T here
	 */
	aes_ccm_128_xor(ctx->X_i, S_0, digest);

	ZERO_STRUCT(S_0);
	ZERO_STRUCTP(ctx);
}
