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

#ifndef LIB_CRYPTO_AES_CCM_128_H
#define LIB_CRYPTO_AES_CCM_128_H

#define AES_CCM_128_M 16
#define AES_CCM_128_L 4
#define AES_CCM_128_NONCE_SIZE (15 - AES_CCM_128_L)

struct aes_ccm_128_context {
	AES_KEY aes_key;
	uint8_t nonce[AES_CCM_128_NONCE_SIZE];

	size_t a_remain;
	size_t m_remain;

	uint8_t X_i[AES_BLOCK_SIZE];
	uint8_t B_i[AES_BLOCK_SIZE];
	size_t B_i_ofs;

	uint8_t S_i[AES_BLOCK_SIZE];
	size_t S_i_ofs;
	size_t S_i_ctr;
};

void aes_ccm_128_init(struct aes_ccm_128_context *ctx,
		      const uint8_t K[AES_BLOCK_SIZE],
		      const uint8_t N[AES_CCM_128_NONCE_SIZE],
		      size_t a_total, size_t m_total);
void aes_ccm_128_update(struct aes_ccm_128_context *ctx,
			const uint8_t *v, size_t v_len);
void aes_ccm_128_crypt(struct aes_ccm_128_context *ctx,
			 uint8_t *m, size_t m_len);
void aes_ccm_128_digest(struct aes_ccm_128_context *ctx,
			uint8_t digest[AES_BLOCK_SIZE]);

#endif /* LIB_CRYPTO_AES_CCM_128_H */
