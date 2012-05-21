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

#ifndef _GSS_SAMBA_H
#define _GSS_SAMBA_H

#ifdef HAVE_GSSAPI

#include "system/gssapi.h"

#if defined(HAVE_GSS_OID_EQUAL)
#define smb_gss_oid_equal gss_oid_equal
#else
int smb_gss_oid_equal(const gss_OID first_oid, const gss_OID second_oid);
#endif /* HAVE_GSS_OID_EQUAL */

#endif /* HAVE_GSSAPI */
#endif /* _GSS_SAMBA_H */
