/*
   Unix SMB/CIFS implementation.
   Wrapper for gnutls hash and encryption functions

   Copyright (C) Stefan Metzmacher <metze@samba.org> 2007
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2009-2019
   Copyright (c) Andreas Schneider <asn@samba.org> 2019

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

/*
 * This (arcfour over data with a key combined from two imputs, one
 * the key another the confounder), is a common pattern in pre-AES
 * windows cryptography
 *
 * Some protocols put the confounder first, others second so both
 * parameters are named key_input here.
 *
 */

#include "includes.h"
#include "lib/util/data_blob.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "gnutls_helpers.h"
#include "lib/util/memory.h"

int samba_gnutls_arcfour_confounded_md5(const DATA_BLOB *key_input1,
					const DATA_BLOB *key_input2,
					DATA_BLOB *data,
					enum samba_gnutls_direction encrypt)
{
	int rc;
	gnutls_hash_hd_t hash_hnd = NULL;
	uint8_t confounded_key[16];
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t confounded_key_datum = {
		.data = confounded_key,
		.size = sizeof(confounded_key),
	};

	rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_MD5);
	if (rc < 0) {
		return rc;
	}
	rc = gnutls_hash(hash_hnd, key_input1->data, key_input1->length);
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		return rc;
	}
	rc = gnutls_hash(hash_hnd, key_input2->data, key_input2->length);
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		return rc;
	}

	gnutls_hash_deinit(hash_hnd, confounded_key);

	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_ARCFOUR_128,
				&confounded_key_datum,
				NULL);
	if (rc < 0) {
		return rc;
	}

	if (encrypt == SAMBA_GNUTLS_ENCRYPT) {
		rc = gnutls_cipher_encrypt(cipher_hnd,
					   data->data,
					   data->length);
	} else {
		rc = gnutls_cipher_decrypt(cipher_hnd,
					   data->data,
					   data->length);
	}
	gnutls_cipher_deinit(cipher_hnd);
	ZERO_ARRAY(confounded_key);

	return rc;
}
