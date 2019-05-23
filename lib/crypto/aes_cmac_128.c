/*
   AES-CMAC-128 (rfc 4493)
   Copyright (C) Stefan Metzmacher 2012
   Copyright (C) Jeremy Allison 2012
   Copyright (C) Michael Adam 2012

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
#include "lib/crypto/aes_cmac_128.h"

static const uint8_t const_Zero[] = {
	0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00
};

static const uint8_t const_Rb[] = {
	0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x87
};

#define _MSB(x) (((x)[0] & 0x80)?1:0)

void aes_cmac_128_init(struct aes_cmac_128_context *ctx,
		       const uint8_t K[AES_BLOCK_SIZE])
{
	ZERO_STRUCTP(ctx);

	AES_set_encrypt_key(K, 128, &ctx->aes_key);

	/* step 1 - generate subkeys k1 and k2 */

	AES_encrypt(const_Zero, ctx->L, &ctx->aes_key);

	if (_MSB(ctx->L) == 0) {
		aes_block_lshift(ctx->L, ctx->K1);
	} else {
		aes_block_lshift(ctx->L, ctx->tmp);
		aes_block_xor(ctx->tmp, const_Rb, ctx->K1);
	}

	if (_MSB(ctx->K1) == 0) {
		aes_block_lshift(ctx->K1, ctx->K2);
	} else {
		aes_block_lshift(ctx->K1, ctx->tmp);
		aes_block_xor(ctx->tmp, const_Rb, ctx->K2);
	}
}

void aes_cmac_128_update(struct aes_cmac_128_context *ctx,
			 const uint8_t *msg, size_t msg_len)
{
	/*
	 * check if we expand the block
	 */
	if (ctx->last_len < AES_BLOCK_SIZE) {
		size_t len = MIN(AES_BLOCK_SIZE - ctx->last_len, msg_len);

		if (len > 0) {
			memcpy(&ctx->last[ctx->last_len], msg, len);
			msg += len;
			msg_len -= len;
			ctx->last_len += len;
		}
	}

	if (msg_len == 0) {
		/* if it is still the last block, we are done */
		return;
	}

	/*
	 * now checksum everything but the last block
	 */
	aes_block_xor(ctx->X, ctx->last, ctx->Y);
	AES_encrypt(ctx->Y, ctx->X, &ctx->aes_key);

	while (msg_len > AES_BLOCK_SIZE) {
		aes_block_xor(ctx->X, msg, ctx->Y);
		AES_encrypt(ctx->Y, ctx->X, &ctx->aes_key);
		msg += AES_BLOCK_SIZE;
		msg_len -= AES_BLOCK_SIZE;
	}

	/*
	 * copy the last block, it will be processed in
	 * aes_cmac_128_final().
	 */
	ZERO_STRUCT(ctx->last);
	memcpy(ctx->last, msg, msg_len);
	ctx->last_len = msg_len;
}

void aes_cmac_128_final(struct aes_cmac_128_context *ctx,
			uint8_t T[AES_BLOCK_SIZE])
{
	if (ctx->last_len < AES_BLOCK_SIZE) {
		ctx->last[ctx->last_len] = 0x80;
		aes_block_xor(ctx->last, ctx->K2, ctx->tmp);
	} else {
		aes_block_xor(ctx->last, ctx->K1, ctx->tmp);
	}

	aes_block_xor(ctx->tmp, ctx->X, ctx->Y);
	AES_encrypt(ctx->Y, T, &ctx->aes_key);

	ZERO_STRUCTP(ctx);
}
