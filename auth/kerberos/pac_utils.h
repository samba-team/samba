/*
   Unix SMB/CIFS implementation.
   kerberos authorization data (PAC) utility library
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2011
   Copyright (C) Simo Sorce 2010-2012

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

#ifndef _PAC_UTILS_H
#define _PAC_UTILS_H

#ifdef HAVE_KRB5

#include "lib/krb5_wrap/krb5_samba.h"
#include "lib/krb5_wrap/gss_samba.h"

struct PAC_SIGNATURE_DATA;
struct PAC_DATA;
struct PAC_LOGON_INFO;

krb5_error_code check_pac_checksum(DATA_BLOB pac_data,
				   struct PAC_SIGNATURE_DATA *sig,
				   krb5_context context,
				   const krb5_keyblock *keyblock);

NTSTATUS kerberos_decode_pac(TALLOC_CTX *mem_ctx,
			     DATA_BLOB pac_data_blob,
			     krb5_context context,
			     const krb5_keyblock *krbtgt_keyblock,
			     const krb5_keyblock *service_keyblock,
			     krb5_const_principal client_principal,
			     time_t tgs_authtime,
			     struct PAC_DATA **pac_data_out);

NTSTATUS kerberos_pac_logon_info(TALLOC_CTX *mem_ctx,
				 DATA_BLOB blob,
				 krb5_context context,
				 const krb5_keyblock *krbtgt_keyblock,
				 const krb5_keyblock *service_keyblock,
				 krb5_const_principal client_principal,
				 time_t tgs_authtime,
				 struct PAC_LOGON_INFO **logon_info);

NTSTATUS gssapi_obtain_pac_blob(TALLOC_CTX *mem_ctx,
				gss_ctx_id_t gssapi_context,
				gss_name_t gss_client_name,
				DATA_BLOB *pac_data);
NTSTATUS gssapi_get_session_key(TALLOC_CTX *mem_ctx,
				gss_ctx_id_t gssapi_context,
				DATA_BLOB *session_key,
				uint32_t *keytype);

/* not the best place here, need to move to a more generic gssapi
 * wrapper later */
char *gssapi_error_string(TALLOC_CTX *mem_ctx,
			  OM_uint32 maj_stat, OM_uint32 min_stat,
			  const gss_OID mech);
#endif /* HAVE_KRB5 */
#endif /* _PAC_UTILS_H */
