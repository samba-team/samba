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

#ifndef LIB_CRYPTO_AES_GCM_128_H
#define LIB_CRYPTO_AES_GCM_128_H

#define AES_GCM_128_IV_SIZE (12)

struct aes_gcm_128_context {
	AES_KEY aes_key;

	uint64_t __align;

	struct aes_gcm_128_tmp {
		size_t ofs;
		size_t total;
		uint8_t block[AES_BLOCK_SIZE];
	} A, C, c, v, y;

	uint8_t H[AES_BLOCK_SIZE];
	uint8_t J0[AES_BLOCK_SIZE];
	uint8_t CB[AES_BLOCK_SIZE];
	uint8_t Y[AES_BLOCK_SIZE];
	uint8_t AC[AES_BLOCK_SIZE];
};

void aes_gcm_128_init(struct aes_gcm_128_context *ctx,
		      const uint8_t K[AES_BLOCK_SIZE],
		      const uint8_t IV[AES_GCM_128_IV_SIZE]);
void aes_gcm_128_updateA(struct aes_gcm_128_context *ctx,
			 const uint8_t *a, size_t a_len);
void aes_gcm_128_updateC(struct aes_gcm_128_context *ctx,
			 const uint8_t *c, size_t c_len);
void aes_gcm_128_crypt(struct aes_gcm_128_context *ctx,
		       uint8_t *m, size_t m_len);
void aes_gcm_128_digest(struct aes_gcm_128_context *ctx,
			uint8_t T[AES_BLOCK_SIZE]);

#endif /* LIB_CRYPTO_AES_GCM_128_H */
