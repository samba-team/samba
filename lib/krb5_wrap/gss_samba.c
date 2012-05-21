/*
 *  Unix SMB/CIFS implementation.
 *
 *  Simple GSSAPI wrappers
 *
 *  Copyright (c) 2012      Andreas Schneider <asn@samba.org>
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
#include "gss_samba.h"

#ifdef HAVE_GSSAPI

#if !defined(HAVE_GSS_OID_EQUAL)
int smb_gss_oid_equal(const gss_OID first_oid, const gss_OID second_oid)
{
	if (first_oid == GSS_C_NO_OID || second_oid == GSS_C_NO_OID) {
		return 0;
	}

	if (first_oid == second_oid) {
		return 1;
	}

	if ((first_oid)->length != (second_oid)->length) {
		return 0;
	}

	if (memcmp((first_oid)->elements, (second_oid)->elements,
		   (first_oid)->length) == 0) {
		return 1;
	}

	return 0;
}
#endif /* !HAVE_GSS_OID_EQUAL */

#endif /* HAVE_GSSAPI */
