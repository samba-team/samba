/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Guenther Deschner                  2008.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "../libcli/auth/libcli_auth.h"
#include "../lib/crypto/arcfour.h"
#include "rpc_client/init_samr.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

/*************************************************************************
 inits a samr_CryptPasswordEx structure
 *************************************************************************/

void init_samr_CryptPasswordEx(const char *pwd,
			       DATA_BLOB *session_key,
			       struct samr_CryptPasswordEx *pwd_buf)
{
	/* samr_CryptPasswordEx */

	uint8_t pwbuf[532];
	gnutls_hash_hd_t hash_hnd = NULL;
	uint8_t confounder[16];
	DATA_BLOB confounded_session_key = data_blob(NULL, 16);
	int rc;

	encode_pw_buffer(pwbuf, pwd, STR_UNICODE);

	generate_random_buffer((uint8_t *)confounder, 16);

	rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_MD5);
	if (rc < 0) {
		goto out;
	}

	rc = gnutls_hash(hash_hnd, confounder, 16);
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		goto out;
	}
	rc = gnutls_hash(hash_hnd, session_key->data, session_key->length);
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		goto out;
	}

	gnutls_hash_deinit(hash_hnd, confounded_session_key.data);

	arcfour_crypt_blob(pwbuf, 516, &confounded_session_key);
	ZERO_ARRAY_LEN(confounded_session_key.data,
		       confounded_session_key.length);
	data_blob_free(&confounded_session_key);

	memcpy(&pwbuf[516], confounder, 16);
	ZERO_ARRAY(confounder);

	memcpy(pwd_buf->data, pwbuf, sizeof(pwbuf));
	ZERO_ARRAY(pwbuf);
out:
	return;
}

/*************************************************************************
 inits a samr_CryptPassword structure
 *************************************************************************/

void init_samr_CryptPassword(const char *pwd,
			     DATA_BLOB *session_key,
			     struct samr_CryptPassword *pwd_buf)
{
	/* samr_CryptPassword */

	encode_pw_buffer(pwd_buf->data, pwd, STR_UNICODE);
	arcfour_crypt_blob(pwd_buf->data, 516, session_key);
}
