/*
   Unix SMB/CIFS implementation.

   Samba kpasswd implementation

   Copyright (c) 2005      Andrew Bartlett <abartlet@samba.org>
   Copyright (c) 2016      Andreas Schneider <asn@samba.org>

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

#include "includes.h"
#include "system/kerberos.h"
#include "kdc/kpasswd-helper.h"

bool kpasswd_make_error_reply(TALLOC_CTX *mem_ctx,
			      krb5_error_code error_code,
			      const char *error_string,
			      DATA_BLOB *error_data)
{
	bool ok;
	char *s;
	size_t slen;

	if (error_code == 0) {
		DBG_DEBUG("kpasswd reply - %s\n", error_string);
	} else {
		DBG_INFO("kpasswd reply - %s\n", error_string);
	}

	ok = push_utf8_talloc(mem_ctx, &s, error_string, &slen);
	if (!ok) {
		return false;
	}

	/*
	 * The string 's' has two terminating nul-bytes which are also
	 * reflected by 'slen'. Normally Kerberos doesn't expect that strings
	 * are nul-terminated, but Heimdal does!
	 */
#ifndef SAMBA4_USES_HEIMDAL
	if (slen < 2) {
		return false;
	}
	slen -= 2;
#endif
	if (2 + slen < slen) {
		return false;
	}
	error_data->length = 2 + slen;
	error_data->data = talloc_size(mem_ctx, error_data->length);
	if (error_data->data == NULL) {
		talloc_free(s);
		return false;
	}

	RSSVAL(error_data->data, 0, error_code);
	memcpy(error_data->data + 2, s, slen);

	talloc_free(s);

	return true;
}
