/*
 * Copyright (c) 2019      Andreas Schneider <asn@samba.org>
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

#ifndef _GNUTLS_HELPERS_H
#define _GNUTLS_HELPERS_H

#include "libcli/util/ntstatus.h"
#include "libcli/util/werror.h"

NTSTATUS _gnutls_error_to_ntstatus(int gnutls_rc,
				   NTSTATUS blocked_status,
				   const char *function,
				   const char *location);
#define gnutls_error_to_ntstatus(gnutls_rc, blocked_status) \
	_gnutls_error_to_ntstatus(gnutls_rc, blocked_status, \
				  __FUNCTION__, __location__)

WERROR _gnutls_error_to_werror(int gnutls_rc,
			       WERROR blocked_werr,
			       const char *function,
			       const char *location);
#define gnutls_error_to_werror(gnutls_rc, blocked_werr) \
	_gnutls_error_to_werror(gnutls_rc, blocked_werr, \
				__FUNCTION__, __location__)

enum samba_gnutls_direction {
	SAMBA_GNUTLS_ENCRYPT,
	SAMBA_GNUTLS_DECRYPT
};

int samba_gnutls_arcfour_confounded_md5(const DATA_BLOB *key_input1,
					const DATA_BLOB *key_input2,
					DATA_BLOB *data,
					enum samba_gnutls_direction encrypt);

#endif /* _GNUTLS_HELPERS_H */
