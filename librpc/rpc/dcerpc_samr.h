/*
 * Copyright (c) 2022      Andreas Schneider <asn@samba.org>
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

#ifndef _DCERPC_SAMR_H
#define _DCERPC_SAMR_H

#include <util/discard.h>
#include "lib/util/data_blob.h"

#define SAMR_AES256_ENC_KEY_STRING \
	"Microsoft SAM encryption key AEAD-AES-256-CBC-HMAC-SHA512 16"
#define SAMR_AES256_ENC_KEY_STRING_LEN 61 /* Including terminating null byte */

#define SAMR_AES256_MAC_KEY_STRING \
	 "Microsoft SAM MAC key AEAD-AES-256-CBC-HMAC-SHA512 16"
#define SAMR_AES256_MAC_KEY_STRING_LEN 54 /* Including terminating null byte */

static const DATA_BLOB samr_aes256_enc_key_salt = {
	.data = discard_const_p(uint8_t, SAMR_AES256_ENC_KEY_STRING),
	.length = SAMR_AES256_ENC_KEY_STRING_LEN,
};

static const DATA_BLOB samr_aes256_mac_key_salt = {
	.data = discard_const_p(uint8_t, SAMR_AES256_MAC_KEY_STRING),
	.length = SAMR_AES256_MAC_KEY_STRING_LEN,
};

#endif /* _DCERPC_SAMR_H */
