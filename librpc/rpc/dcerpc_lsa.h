/*
 * Copyright (c) 2023      Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _DCERPC_LSA_H
#define _DCERPC_LSA_H

#include <util/discard.h>
#include "lib/util/data_blob.h"

#define LSA_AES256_ENC_KEY_STRING \
	"Microsoft LSAD encryption key AEAD-AES-256-CBC-HMAC-SHA512 16"
/* Including terminating null byte */
#define LSA_AES256_ENC_KEY_STRING_LEN sizeof(LSA_AES256_ENC_KEY_STRING)

#define LSA_AES256_MAC_KEY_STRING \
	 "Microsoft LSAD MAC key AEAD-AES-256-CBC-HMAC-SHA512 16"
/* Including terminating null byte */
#define LSA_AES256_MAC_KEY_STRING_LEN sizeof(LSA_AES256_MAC_KEY_STRING)

static const DATA_BLOB lsa_aes256_enc_key_salt = {
	.data = discard_const_p(uint8_t, LSA_AES256_ENC_KEY_STRING),
	.length = LSA_AES256_ENC_KEY_STRING_LEN,
};

static const DATA_BLOB lsa_aes256_mac_key_salt = {
	.data = discard_const_p(uint8_t, LSA_AES256_MAC_KEY_STRING),
	.length = LSA_AES256_MAC_KEY_STRING_LEN,
};

#endif /* _DCERPC_LSA_H */
