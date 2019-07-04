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

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

/*************************************************************************
 inits a samr_CryptPasswordEx structure
 *************************************************************************/

NTSTATUS init_samr_CryptPasswordEx(const char *pwd,
				   DATA_BLOB *session_key,
				   struct samr_CryptPasswordEx *pwd_buf)
{
	/* samr_CryptPasswordEx */

	uint8_t _confounder[16] = {0};
	DATA_BLOB confounder = data_blob_const(_confounder, 16);
	uint8_t pwbuf[532] = {0};
	DATA_BLOB encrypt_pwbuf = data_blob_const(pwbuf, 516);
	bool ok;
	int rc;

	ok = encode_pw_buffer(pwbuf, pwd, STR_UNICODE);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	generate_random_buffer(_confounder, sizeof(_confounder));

	rc = samba_gnutls_arcfour_confounded_md5(&confounder,
						 session_key,
						 &encrypt_pwbuf,
						 SAMBA_GNUTLS_ENCRYPT);
	if (rc < 0) {
		ZERO_ARRAY(_confounder);
		return gnutls_error_to_ntstatus(rc, NT_STATUS_ACCESS_DISABLED_BY_POLICY_OTHER);
	}

	memcpy(&pwbuf[516], confounder.data, confounder.length);
	ZERO_ARRAY(_confounder);

	memcpy(pwd_buf->data, pwbuf, sizeof(pwbuf));
	ZERO_ARRAY(pwbuf);

	return NT_STATUS_OK;
}

/*************************************************************************
 inits a samr_CryptPassword structure
 *************************************************************************/

NTSTATUS init_samr_CryptPassword(const char *pwd,
				 DATA_BLOB *session_key,
				 struct samr_CryptPassword *pwd_buf)
{
	/* samr_CryptPassword */
	bool ok;

	ok = encode_pw_buffer(pwd_buf->data, pwd, STR_UNICODE);
	if (!ok) {
		return NT_STATUS_INTERNAL_ERROR;
	}
	arcfour_crypt_blob(pwd_buf->data, 516, session_key);

	return NT_STATUS_OK;
}
