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
#include "../lib/crypto/crypto.h"

static const uint8_t const_Zero[] = {
	0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00
};

static const uint8_t const_Rb[] = {
	0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x87
};

#define _MSB(x) (((x)[0] & 0x80)?1:0)

static inline void aes_cmac_128_left_shift_1(const uint8_t in[AES_BLOCK_SIZE],
					     uint8_t out[AES_BLOCK_SIZE])
{
	uint8_t overflow = 0;
	int8_t i;

	for (i = AES_BLOCK_SIZE - 1; i >= 0; i--) {
		out[i] = in[i] << 1;

		out[i] |= overflow;

		overflow = _MSB(&in[i]);
	}
}

static inline void aes_cmac_128_xor(const uint8_t in1[AES_BLOCK_SIZE],
				    const uint8_t in2[AES_BLOCK_SIZE],
				    uint8_t out[AES_BLOCK_SIZE])
{
	uint8_t i;

	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		out[i] = in1[i] ^ in2[i];
	}
}

void aes_cmac_128_init(struct aes_cmac_128_context *ctx,
		       const uint8_t K[AES_BLOCK_SIZE])
{
	uint8_t L[AES_BLOCK_SIZE];

	ZERO_STRUCTP(ctx);

	AES_set_encrypt_key(K, 128, &ctx->aes_key);

	/* step 1 - generate subkeys k1 and k2 */

	AES_encrypt(const_Zero, L, &ctx->aes_key);

	if (_MSB(L) == 0) {
		aes_cmac_128_left_shift_1(L, ctx->K1);
	} else {
		uint8_t tmp_block[AES_BLOCK_SIZE];

		aes_cmac_128_left_shift_1(L, tmp_block);
		aes_cmac_128_xor(tmp_block, const_Rb, ctx->K1);
		ZERO_STRUCT(tmp_block);
	}

	if (_MSB(ctx->K1) == 0) {
		aes_cmac_128_left_shift_1(ctx->K1, ctx->K2);
	} else {
		uint8_t tmp_block[AES_BLOCK_SIZE];

		aes_cmac_128_left_shift_1(ctx->K1, tmp_block);
		aes_cmac_128_xor(tmp_block, const_Rb, ctx->K2);
		ZERO_STRUCT(tmp_block);
	}

	ZERO_STRUCT(L);
}

void aes_cmac_128_update(struct aes_cmac_128_context *ctx,
			 const uint8_t *_msg, size_t _msg_len)
{
	uint8_t tmp_block[AES_BLOCK_SIZE];
	uint8_t Y[AES_BLOCK_SIZE];
	const uint8_t *msg = _msg;
	size_t msg_len = _msg_len;

	/*
	 * copy the remembered last block
	 */
	ZERO_STRUCT(tmp_block);
	if (ctx->last_len) {
		memcpy(tmp_block, ctx->last, ctx->last_len);
	}

	/*
	 * check if we expand the block
	 */
	if (ctx->last_len < AES_BLOCK_SIZE) {
		size_t len = MIN(AES_BLOCK_SIZE - ctx->last_len, msg_len);

		memcpy(&tmp_block[ctx->last_len], msg, len);
		memcpy(ctx->last, tmp_block, AES_BLOCK_SIZE);
		msg += len;
		msg_len -= len;
		ctx->last_len += len;
	}

	if (msg_len == 0) {
		/* if it is still the last block, we are done */
		ZERO_STRUCT(tmp_block);
		return;
	}

	/*
	 * It is not the last block anymore
	 */
	ZERO_STRUCT(ctx->last);
	ctx->last_len = 0;

	/*
	 * now checksum everything but the last block
	 */
	aes_cmac_128_xor(ctx->X, tmp_block, Y);
	AES_encrypt(Y, ctx->X, &ctx->aes_key);

	while (msg_len > AES_BLOCK_SIZE) {
		memcpy(tmp_block, msg, AES_BLOCK_SIZE);
		msg += AES_BLOCK_SIZE;
		msg_len -= AES_BLOCK_SIZE;

		aes_cmac_128_xor(ctx->X, tmp_block, Y);
		AES_encrypt(Y, ctx->X, &ctx->aes_key);
	}

	/*
	 * copy the last block, it will be processed in
	 * aes_cmac_128_final().
	 */
	memcpy(ctx->last, msg, msg_len);
	ctx->last_len = msg_len;

	ZERO_STRUCT(tmp_block);
	ZERO_STRUCT(Y);
}

void aes_cmac_128_final(struct aes_cmac_128_context *ctx,
			uint8_t T[AES_BLOCK_SIZE])
{
	uint8_t tmp_block[AES_BLOCK_SIZE];
	uint8_t Y[AES_BLOCK_SIZE];

	if (ctx->last_len < AES_BLOCK_SIZE) {
		ctx->last[ctx->last_len] = 0x80;
		aes_cmac_128_xor(ctx->last, ctx->K2, tmp_block);
	} else {
		aes_cmac_128_xor(ctx->last, ctx->K1, tmp_block);
	}

	aes_cmac_128_xor(tmp_block, ctx->X, Y);
	AES_encrypt(Y, T, &ctx->aes_key);

	ZERO_STRUCT(tmp_block);
	ZERO_STRUCT(Y);
	ZERO_STRUCTP(ctx);
}
