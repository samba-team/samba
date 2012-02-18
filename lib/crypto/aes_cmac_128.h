/*
   AES-CMAC-128 (rfc 4493)
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

#ifndef LIB_CRYPTO_AES_CMAC_128_H
#define LIB_CRYPTO_AES_CMAC_128_H

struct aes_cmac_128_context {
	AES_KEY aes_key;

	uint8_t K1[AES_BLOCK_SIZE];
	uint8_t K2[AES_BLOCK_SIZE];

	uint8_t X[AES_BLOCK_SIZE];

	uint8_t last[AES_BLOCK_SIZE];
	size_t last_len;
};

void aes_cmac_128_init(struct aes_cmac_128_context *ctx,
		       const uint8_t K[AES_BLOCK_SIZE]);
void aes_cmac_128_update(struct aes_cmac_128_context *ctx,
			 const uint8_t *_msg, size_t _msg_len);
void aes_cmac_128_final(struct aes_cmac_128_context *ctx,
			uint8_t T[AES_BLOCK_SIZE]);

#endif /* LIB_CRYPTO_AES_CMAC_128_H */
